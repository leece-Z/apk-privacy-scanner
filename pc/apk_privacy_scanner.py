#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android APK 隐私安全检测工具 (APK Privacy Scanner)
===================================================
功能：
1. 权限分析 — 检测敏感权限申请情况
2. SDK/追踪器分析 — 识别第三方SDK（分析、广告、推送等）
3. 网络行为分析 — 检测硬编码URL、API端点、域名
4. 组件暴露分析 — 检测导出的Activity/Service/Receiver
5. 签名信息 — 检查签名和证书
6. 综合风险评分 — 生成隐私风险等级

技术栈：Python + androguard + 内置正则匹配

用法：python apk_privacy_scanner.py <apk文件路径>
"""

import sys
import os
import re
import json
import hashlib
import logging
import io
from collections import defaultdict
from datetime import datetime

# 禁用 colorama 避免 Windows GBK 编码问题
os.environ['LOGURU_LEVEL'] = 'CRITICAL'
os.environ['NO_COLOR'] = '1'
logging.disable(logging.CRITICAL)

# 强制 stdout 使用 UTF-8
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except:
        pass

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    print("[!] 需要安装 androguard：pip install androguard")
    sys.exit(1)


# ============================================================
# 一、敏感权限定义库
# ============================================================

# 危险级权限（Android官方 dangerous permissions）
DANGEROUS_PERMISSIONS = {
    # 日历
    "READ_CALENDAR": "读取日历",
    "WRITE_CALENDAR": "修改日历",
    # 通话记录
    "READ_CALL_LOG": "读取通话记录",
    "WRITE_CALL_LOG": "修改通话记录",
    "PROCESS_OUTGOING_CALLS": "拦截呼出电话",
    # 摄像头
    "CAMERA": "使用摄像头",
    # 通讯录
    "READ_CONTACTS": "读取联系人",
    "WRITE_CONTACTS": "修改联系人",
    "GET_ACCOUNTS": "获取账户列表",
    # 位置
    "ACCESS_FINE_LOCATION": "精确定位（GPS）",
    "ACCESS_COARSE_LOCATION": "粗略定位（基站/WiFi）",
    "ACCESS_BACKGROUND_LOCATION": "后台定位",
    # 麦克风
    "RECORD_AUDIO": "录音",
    # 电话
    "READ_PHONE_STATE": "读取手机状态（IMEI/IMSI等）",
    "READ_PHONE_NUMBERS": "读取本机号码",
    "CALL_PHONE": "拨打电话",
    "ANSWER_PHONE_CALLS": "接听电话",
    "ADD_VOICEMAIL": "添加语音邮件",
    "USE_SIP": "使用SIP通话",
    # 传感器
    "BODY_SENSORS": "身体传感器",
    # 短信
    "SEND_SMS": "发送短信",
    "RECEIVE_SMS": "接收短信",
    "READ_SMS": "读取短信",
    "RECEIVE_WAP_PUSH": "接收WAP推送",
    "RECEIVE_MMS": "接收彩信",
    # 存储
    "READ_EXTERNAL_STORAGE": "读取外部存储",
    "WRITE_EXTERNAL_STORAGE": "写入外部存储",
    "READ_MEDIA_IMAGES": "读取图片",
    "READ_MEDIA_VIDEO": "读取视频",
    "READ_MEDIA_AUDIO": "读取音频",
    # Android 11+
    "MANAGE_EXTERNAL_STORAGE": "管理所有文件",
    # 其他敏感
    "SYSTEM_ALERT_WINDOW": "悬浮窗",
    "WRITE_SETTINGS": "修改系统设置",
    "BIND_ACCESSIBILITY_SERVICE": "无障碍服务",
    "REQUEST_INSTALL_PACKAGES": "安装应用",
    "PACKAGE_USAGE_STATS": "读取应用使用记录",
    "QUERY_ALL_PACKAGES": "查询所有已安装应用",
}

# 高危组合：一旦出现则严重警告
HIGH_RISK_PERMISSION_COMBOS = [
    {
        "name": "[HIGH] 间谍软件特征",
        "perms": ["RECORD_AUDIO", "CAMERA"],
        "desc": "同时申请录音+摄像头权限，可秘密录制音视频"
    },
    {
        "name": "[HIGH] 短信劫持特征",
        "perms": ["RECEIVE_SMS", "SEND_SMS", "READ_SMS"],
        "desc": "可拦截/读取/发送短信，可能窃取验证码"
    },
    {
        "name": "[HIGH] 通话监控特征",
        "perms": ["READ_CALL_LOG", "RECORD_AUDIO"],
        "desc": "可读取通话记录+录音，可能窃听通话"
    },
    {
        "name": "[HIGH] 完全监控特征",
        "perms": ["ACCESS_FINE_LOCATION", "READ_CONTACTS", "CAMERA"],
        "desc": "定位+联系人+摄像头，全方位隐私窃取"
    },
    {
        "name": "[MED] 安装应用风险",
        "perms": ["REQUEST_INSTALL_PACKAGES", "WRITE_EXTERNAL_STORAGE"],
        "desc": "可从外部存储安装应用（可能静默安装）"
    },
    {
        "name": "[MED] 无障碍监控",
        "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"],
        "desc": "无障碍服务+悬浮窗，可监控所有操作"
    },
]


# ============================================================
# 二、追踪器/第三方SDK签名库
# ============================================================

KNOWN_TRACKERS = {
    # Google 系
    "com.google.firebase": ("Firebase（Google分析/推送）", "[HIGH]"),
    "com.google.android.gms.ads": ("Google AdMob广告", "[MED]"),
    "com.google.android.gms.measurement": ("Google Analytics", "[HIGH]"),
    "com.google.android.gms.tagmanager": ("Google Tag Manager", "[MED]"),
    "com.google.firebase.crashlytics": ("Firebase Crashlytics（崩溃收集）", "[MED]"),
    "com.google.firebase.perf": ("Firebase Performance（性能监控）", "[LOW]"),
    
    # 广告/变现
    "com.facebook.ads": ("Facebook Audience Network广告", "[MED]"),
    "com.unity3d.ads": ("Unity Ads广告", "[MED]"),
    "com.applovin": ("AppLovin广告", "[MED]"),
    "com.ironsource": ("ironSource广告", "[MED]"),
    "com.vungle": ("Vungle广告", "[MED]"),
    "com.mopub": ("MoPub广告", "[MED]"),
    "com.chartboost": ("Chartboost广告", "[MED]"),
    "com.tapjoy": ("Tapjoy广告", "[MED]"),
    "com.inmobi": ("InMobi广告", "[MED]"),
    "com.mintegral": ("Mintegral广告", "[MED]"),
    "com.bytedance.pangle": ("穿山甲/Pangle广告（字节）", "[HIGH]"),
    "com.qq.e": ("腾讯优量汇广告", "[HIGH]"),
    "com.kwad": ("快手广告", "[MED]"),
    
    # 分析/统计
    "com.umeng": ("友盟统计（阿里）", "[HIGH]"),
    "com.baidu.mobstat": ("百度统计", "[HIGH]"),
    "com.tencent.bugly": ("腾讯Bugly", "[MED]"),
    "com.appsflyer": ("AppsFlyer归因分析", "[MED]"),
    "com.adjust": ("Adjust归因分析", "[MED]"),
    "com.branch": ("Branch深度链接", "[LOW]"),
    "com.amplitude": ("Amplitude分析", "[MED]"),
    "com.mixpanel": ("Mixpanel分析", "[MED]"),
    "com.flurry": ("Flurry分析（Yahoo）", "[MED]"),
    "com.localytics": ("Localytics分析", "[LOW]"),
    
    # 社交/IM
    "com.facebook": ("Facebook SDK", "[HIGH]"),
    "com.twitter": ("Twitter SDK", "[MED]"),
    "com.tencent.mm": ("微信SDK", "[LOW]"),
    "com.sina.weibo": ("微博SDK", "[LOW]"),
    
    # 推送
    "com.igexin": ("个推推送", "[MED]"),
    "com.xiaomi.mipush": ("小米推送", "[LOW]"),
    "com.huawei.hms.push": ("华为推送", "[LOW]"),
    "com.vivo.push": ("vivo推送", "[LOW]"),
    "com.oppo.push": ("OPPO推送", "[LOW]"),
    "com.heytap.msp": ("OPPO推送", "[LOW]"),
    "com.meizu.cloud.pushsdk": ("魅族推送", "[LOW]"),
    "com.jpush": ("极光推送", "[MED]"),
    "com.getui": ("个推", "[MED]"),
    
    # 支付
    "com.alipay": ("支付宝SDK", "[LOW]"),
    "com.tencent.mm.opensdk": ("微信支付SDK", "[LOW]"),
    "com.unionpay": ("银联支付SDK", "[LOW]"),
    "com.paypal": ("PayPal SDK", "[LOW]"),
    "com.stripe": ("Stripe支付", "[LOW]"),
    
    # 地图
    "com.amap": ("高德地图SDK", "[MED]"),
    "com.baidu.map": ("百度地图SDK", "[MED]"),
    "com.google.android.gms.maps": ("Google Maps SDK", "[MED]"),
    
    # 客服
    "im.crisp": ("Crisp在线客服", "[LOW]"),
    "com.tencent.qcloud": ("腾讯云通信", "[LOW]"),
    
    # 其他
    "com.squareup.okhttp": ("OkHttp网络库", "[--]"),
    "com.squareup.retrofit": ("Retrofit网络库", "[--]"),
    "com.squareup.picasso": ("Picasso图片加载", "[--]"),
    "com.bumptech.glide": ("Glide图片加载", "[--]"),
    "com.facebook.fresco": ("Fresco图片加载", "[--]"),
    "com.google.gson": ("Gson JSON库", "[--]"),
    "com.fasterxml": ("Jackson JSON库", "[--]"),
    "com.alibaba.fastjson": ("FastJSON库（阿里）", "[--]"),
    "org.apache": ("Apache通用库", "[--]"),
    "kotlin": ("Kotlin标准库", "[--]"),
    "androidx": ("AndroidX官方库", "[--]"),
    "com.google.android.material": ("Material Design库", "[--]"),
}

# 硬编码URL模式（可能泄露服务器信息）
URL_PATTERNS = [
    (r'https?://[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}[^\s"\'<>]*', "URL"),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "IP地址"),
]

# 常见隐私泄露API调用
SENSITIVE_API_PATTERNS = {
    "getDeviceId": "获取设备IMEI",
    "getSubscriberId": "获取IMSI",
    "getLine1Number": "获取本机号码",
    "getSimSerialNumber": "获取SIM卡序列号",
    "getMacAddress": "获取MAC地址",
    "getSSID": "获取WiFi SSID",
    "getBSSID": "获取WiFi BSSID",
    "getInstalledPackages": "获取已安装应用列表",
    "getRunningAppProcesses": "获取运行中进程",
    "getAccounts": "获取账户信息",
    "getLastKnownLocation": "获取位置信息",
    "requestLocationUpdates": "请求位置更新",
    "getCellLocation": "获取基站位置",
    "TelephonyManager": "电话管理（可获取IMEI/IMSI）",
    "WifiManager.getConnectionInfo": "获取WiFi连接信息",
}


# ============================================================
# 三、核心分析引擎
# ============================================================

class APKPrivacyScanner:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = None
        self.dex = None
        self.analysis = None
        self.risk_score = 0
        self.risk_items = []
        
    def load(self):
        """加载APK"""
        print(f"[*] 正在加载 APK: {os.path.basename(self.apk_path)}")
        self.apk, self.dexes, self.analysis = AnalyzeAPK(self.apk_path)
        print(f"[OK] 加载成功\n")
        return self
        
    def analyze_permissions(self):
        """分析权限"""
        print("=" * 60)
        print("【一、权限分析】")
        print("=" * 60)
        
        perms = self.apk.get_permissions()
        perm_names = []
        for p in perms:
            name = p.split(".")[-1] if "." in p else p
            perm_names.append(name)
        
        total = len(perm_names)
        dangerous = []
        normal = []
        
        for pn in perm_names:
            if pn in DANGEROUS_PERMISSIONS:
                dangerous.append((pn, DANGEROUS_PERMISSIONS[pn]))
                self.risk_score += 10
            else:
                normal.append(pn)
        
        print(f"  总权限数: {total}")
        print(f"  |- 危险权限: {len(dangerous)}")
        print(f"  - 普通权限: {len(normal)}")
        
        if dangerous:
            print(f"\n  [!] 危险权限详情:")
            for perm, desc in dangerous:
                print(f"    > {perm} — {desc}")
                self.risk_items.append(f"危险权限: {perm} ({desc})")
        else:
            print(f"\n  [OK] 未申请危险级权限")
        
        # 检测高危权限组合
        print(f"\n  [*] 高危权限组合检测:")
        found_combos = False
        for combo in HIGH_RISK_PERMISSION_COMBOS:
            matched = [p for p in combo["perms"] if p in perm_names]
            if len(matched) >= 2:
                found_combos = True
                print(f"    {combo['name']}: {combo['desc']}")
                print(f"      匹配权限: {', '.join(matched)}")
                self.risk_score += 30
                self.risk_items.append(combo['name'])
        
        if not found_combos:
            print(f"    [OK] 未发现高危权限组合")
        
        return perm_names
    
    def analyze_components(self):
        """分析导出的组件"""
        print("\n" + "=" * 60)
        print("【二、组件暴露分析】")
        print("=" * 60)
        
        exported = {}
        total_exported = 0
        
        # 用androguard官方API获取各组件
        for comp_type, getter in [
            ("Activity", self.apk.get_activities),
            ("Service", self.apk.get_services),
            ("Receiver", self.apk.get_receivers),
            ("Provider", self.apk.get_providers),
        ]:
            comp_list = []
            try:
                components = getter()
                if components:
                    for comp_name in components:
                        comp_list.append(comp_name.split(".")[-1])
            except Exception as e:
                pass
            exported[comp_type] = comp_list
            total_exported += len(comp_list)
        
        print(f"  声明的组件总数: {total_exported}")
        
        for comp_type, comp_list in exported.items():
            if comp_list:
                level = "[!]" if comp_type in ("Service", "Provider") else "  "
                print(f"  {level} {comp_type}: {len(comp_list)}个")
                if len(comp_list) <= 10:
                    for c in comp_list[:10]:
                        print(f"      - {c}")
                else:
                    for c in comp_list[:5]:
                        print(f"      - {c}")
                    print(f"      ... 还有 {len(comp_list)-5} 个")
        
        # 导出组件多意味着攻击面大
        if total_exported > 20:
            self.risk_score += 5
            self.risk_items.append(f"大量声明组件({total_exported}个)")
        
        return exported
    
    def analyze_trackers(self):
        """分析第三方SDK/追踪器"""
        print("\n" + "=" * 60)
        print("【三、第三方SDK/追踪器分析】")
        print("=" * 60)
        
        # 方法1: 从DEX类名匹配
        all_classes = set()
        for dex in self.dexes:
            for cls in dex.get_classes():
                name = str(cls.name).lower()
                all_classes.add(name)
        
        # 方法2: 从AndroidManifest XML中提取所有包引用
        try:
            manifest_xml = self.apk.get_android_manifest_xml()
            if manifest_xml:
                manifest_str = str(manifest_xml).lower()
                all_classes.add(manifest_str)  # 整个manifest当做一个大字符串搜索
        except:
            pass
        
        # 方法3: 从lib目录中的so文件名推断SDK
        try:
            lib_files = self.apk.get_files()
            for f in lib_files:
                if f.startswith('lib/') and f.endswith('.so'):
                    all_classes.add(f.lower())
        except:
            pass
        
        found_trackers = []
        # 用包名路径匹配
        for cls_path in all_classes:
            for tracker_key, (tracker_name, level) in KNOWN_TRACKERS.items():
                if tracker_key.lower() in cls_path:
                    found_trackers.append((tracker_key, tracker_name, level))
        
        # 去重
        seen = set()
        unique_trackers = []
        for t in found_trackers:
            if t[0] not in seen:
                seen.add(t[0])
                unique_trackers.append(t)
        
        # 分类统计
        high_risk = [t for t in unique_trackers if t[2] in ("[HIGH]",)]
        medium_risk = [t for t in unique_trackers if t[2] in ("[MED]",)]
        low_risk = [t for t in unique_trackers if t[2] in ("[LOW]",)]
        neutral = [t for t in unique_trackers if t[2] in ("[--]",)]
        
        print(f"  识别到的第三方SDK: {len(unique_trackers)}个")
        print(f"  |- [HIGH] 高风险: {len(high_risk)}")
        print(f"  |- [MED] 中风险: {len(medium_risk)}")
        print(f"  |- [LOW] 低风险: {len(low_risk)}")
        print(f"  - [--] 通用库: {len(neutral)}")
        
        if high_risk:
            print(f"\n  [HIGH] 高风险SDK:")
            for key, name, level in high_risk:
                print(f"    > {name}")
                self.risk_items.append(f"高风险SDK: {name}")
                self.risk_score += 20
        
        if medium_risk:
            print(f"\n  [MED] 中风险SDK:")
            for key, name, level in medium_risk:
                print(f"    > {name}")
                self.risk_score += 10
        
        if low_risk:
            print(f"\n  [LOW] 低风险SDK:")
            for key, name, level in low_risk:
                print(f"    > {name}")
                self.risk_score += 3
        
        if neutral:
            print(f"\n  [--] 通用库 ({len(neutral)}个，已省略详情)")
        
        return unique_trackers
    
    def analyze_network(self):
        """分析网络相关（URL/IP/域名）"""
        print("\n" + "=" * 60)
        print("【四、网络地址分析】")
        print("=" * 60)
        
        urls = set()
        ips = set()
        
        # 从DEX中搜索字符串
        for dex in self.dexes:
            for string in dex.get_strings():
                s = str(string)
                # URL
                for match in re.finditer(r'https?://[a-zA-Z0-9][-a-zA-Z0-9]*\.[^\s"\'<>\[\]]+', s):
                    url = match.group(0)
                    if len(url) < 200:
                        urls.add(url)
                # IP
                for match in re.finditer(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s):
                    ip = match.group(0)
                    # 过滤明显的非IP
                    parts = ip.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        # 排除常见非服务器IP
                        if ip not in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
                            ips.add(ip)
        
        # 提取域名
        domains = set()
        for url in urls:
            match = re.search(r'https?://([^/:\s]+)', url)
            if match:
                domains.add(match.group(1))
        
        print(f"  发现硬编码URL: {len(urls)}个")
        print(f"  发现IP地址: {len(ips)}个")
        print(f"  涉及域名: {len(domains)}个")
        
        if urls:
            print(f"\n  [URL] 关键URL/端点 (显示前20个):")
            for url in sorted(urls)[:20]:
                print(f"    > {url}")
        
        if ips:
            print(f"\n  [IP] IP地址 (显示前10个):")
            for ip in sorted(ips)[:10]:
                print(f"    > {ip}")
        
        # 检测可疑域名
        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.club']
        suspicious_domains = [d for d in domains if any(d.endswith(t) for t in suspicious_tlds)]
        if suspicious_domains:
            print(f"\n  [!] 可疑域名 (非主流顶级域):")
            for d in suspicious_domains:
                print(f"    > {d}")
                self.risk_items.append(f"可疑域名: {d}")
                self.risk_score += 15
        
        if len(domains) > 20:
            self.risk_items.append(f"大量硬编码域名({len(domains)}个)")
            self.risk_score += 5
        
        return {"urls": urls, "ips": ips, "domains": domains}
    
    def analyze_signature(self):
        """分析签名"""
        print("\n" + "=" * 60)
        print("【五、签名信息】")
        print("=" * 60)
        
        try:
            # 获取包名
            package = self.apk.get_package()
            print(f"  包名: {package}")
            
            # 获取证书
            certs = self.apk.get_certificates()
            if certs:
                for i, cert in enumerate(certs):
                    try:
                        cert_sha1 = cert.sha1_fingerprint.replace(" ", "")
                        subject = str(cert.subject)
                        issuer = str(cert.issuer)
                        print(f"\n  证书 {i+1}:")
                        print(f"    SHA1: {cert_sha1}")
                        print(f"    主题: {subject}")
                        print(f"    颁发者: {issuer}")
                        
                        # 检测是否为调试证书
                        if "Android Debug" in subject or "debug" in subject.lower():
                            print(f"    [!] 调试证书!")
                            self.risk_items.append("使用调试证书签名")
                            self.risk_score += 5
                        
                        # 检测自签名
                        if subject == issuer:
                            print(f"    [i] 自签名证书（常见于非Google Play分发）")
                    except Exception as e:
                        print(f"    证书 {i+1}: 解析失败 - {e}")
        except Exception as e:
            print(f"  签名解析失败: {e}")
    
    def analyze_sensitive_api(self):
        """分析敏感API调用"""
        print("\n" + "=" * 60)
        print("【六、敏感API调用检测】")
        print("=" * 60)
        
        found_apis = defaultdict(int)
        
        for dex in self.dexes:
            for cls in dex.get_classes():
                class_name = str(cls.name)
                try:
                    for method in cls.get_methods():
                        method_name = str(method.name)
                        full = f"{class_name}.{method_name}"
                        for pattern, desc in SENSITIVE_API_PATTERNS.items():
                            if pattern.lower() in full.lower():
                                found_apis[desc] += 1
                except:
                    pass
        
        if found_apis:
            print(f"  检测到以下敏感API调用:")
            for api, count in sorted(found_apis.items(), key=lambda x: -x[1]):
                print(f"    [!] {api}: 发现 {count} 处调用")
                self.risk_score += 5
                self.risk_items.append(f"敏感API: {api}")
        else:
            print(f"  [OK] 未检测到已知敏感API调用")
        
        return found_apis
    
    def calculate_risk_level(self):
        """计算综合风险等级"""
        print("\n" + "=" * 60)
        print("【七、综合风险评估】")
        print("=" * 60)
        
        if self.risk_score <= 10:
            level = "[OK] 低风险"
            advice = "该应用隐私风险较低，可放心使用"
        elif self.risk_score <= 30:
            level = "[LOW] 中等风险"
            advice = "存在一定隐私风险，建议谨慎授权"
        elif self.risk_score <= 60:
            level = "[MED] 较高风险"
            advice = "隐私风险较高，建议仔细审查权限后使用"
        else:
            level = "[HIGH] 高风险"
            advice = "严重隐私风险！建议避免使用或严格限制权限"
        
        print(f"  风险评分: {self.risk_score} / 100+")
        print(f"  风险等级: {level}")
        print(f"  建议: {advice}")
        
        if self.risk_items:
            print(f"\n  [*] 风险项汇总:")
            for item in self.risk_items:
                print(f"    > {item}")
        
        return {
            "score": self.risk_score,
            "level": level,
            "advice": advice,
            "items": self.risk_items
        }
    
    def run_full_analysis(self):
        """运行完整分析"""
        print("\n" + "[*]" * 30)
        print(f"  APK隐私安全扫描器 v1.0")
        print(f"  分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("[*]" * 30 + "\n")
        
        self.analyze_permissions()
        self.analyze_components()
        self.analyze_trackers()
        self.analyze_network()
        self.analyze_signature()
        self.analyze_sensitive_api()
        risk_result = self.calculate_risk_level()
        
        print("\n" + "=" * 60)
        print("  分析完成!")
        print("=" * 60)
        
        return risk_result


# ============================================================
# 四、主程序入口
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("用法: python apk_privacy_scanner.py <APK文件路径>")
        print("示例: python apk_privacy_scanner.py app.apk")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    
    if not os.path.exists(apk_path):
        print(f"[!] 文件不存在: {apk_path}")
        sys.exit(1)
    
    scanner = APKPrivacyScanner(apk_path)
    scanner.load()
    scanner.run_full_analysis()


if __name__ == "__main__":
    main()

