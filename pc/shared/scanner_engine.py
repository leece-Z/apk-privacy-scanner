#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK 隐私扫描共享引擎 (Shared Engine)
======================================
供 PC 端和 Android 端共用的核心分析逻辑。
依赖：androguard

用法：
    from scanner_engine import APKPrivacyScanner
    scanner = APKPrivacyScanner(apk_path, progress_callback)
    scanner.load()
    result = scanner.run_full()
"""

import re
import os
from collections import defaultdict
from datetime import datetime

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    raise ImportError("请安装 androguard：pip install androguard")


# ============================================================
# 一、敏感权限定义库
# ============================================================

DANGEROUS_PERMISSIONS = {
    "READ_CALENDAR": "读取日历",
    "WRITE_CALENDAR": "修改日历",
    "READ_CALL_LOG": "读取通话记录",
    "WRITE_CALL_LOG": "修改通话记录",
    "PROCESS_OUTGOING_CALLS": "拦截呼出电话",
    "CAMERA": "使用摄像头",
    "READ_CONTACTS": "读取联系人",
    "WRITE_CONTACTS": "修改联系人",
    "GET_ACCOUNTS": "获取账户列表",
    "ACCESS_FINE_LOCATION": "精确定位（GPS）",
    "ACCESS_COARSE_LOCATION": "粗略定位（基站/WiFi）",
    "ACCESS_BACKGROUND_LOCATION": "后台定位",
    "RECORD_AUDIO": "录音",
    "READ_PHONE_STATE": "读取手机状态（IMEI/IMSI等）",
    "READ_PHONE_NUMBERS": "读取本机号码",
    "CALL_PHONE": "拨打电话",
    "ANSWER_PHONE_CALLS": "接听电话",
    "ADD_VOICEMAIL": "添加语音邮件",
    "USE_SIP": "使用SIP通话",
    "BODY_SENSORS": "身体传感器",
    "SEND_SMS": "发送短信",
    "RECEIVE_SMS": "接收短信",
    "READ_SMS": "读取短信",
    "RECEIVE_WAP_PUSH": "接收WAP推送",
    "RECEIVE_MMS": "接收彩信",
    "READ_EXTERNAL_STORAGE": "读取外部存储",
    "WRITE_EXTERNAL_STORAGE": "写入外部存储",
    "READ_MEDIA_IMAGES": "读取图片",
    "READ_MEDIA_VIDEO": "读取视频",
    "READ_MEDIA_AUDIO": "读取音频",
    "MANAGE_EXTERNAL_STORAGE": "管理所有文件",
    "SYSTEM_ALERT_WINDOW": "悬浮窗",
    "WRITE_SETTINGS": "修改系统设置",
    "BIND_ACCESSIBILITY_SERVICE": "无障碍服务",
    "REQUEST_INSTALL_PACKAGES": "安装应用",
    "PACKAGE_USAGE_STATS": "读取应用使用记录",
    "QUERY_ALL_PACKAGES": "查询所有已安装应用",
}

HIGH_RISK_PERMISSION_COMBOS = [
    {"name": "间谍软件特征", "perms": ["RECORD_AUDIO", "CAMERA"],
     "desc": "同时申请录音+摄像头权限，可秘密录制音视频"},
    {"name": "短信劫持特征", "perms": ["RECEIVE_SMS", "SEND_SMS", "READ_SMS"],
     "desc": "可拦截/读取/发送短信，可能窃取验证码"},
    {"name": "通话监控特征", "perms": ["READ_CALL_LOG", "RECORD_AUDIO"],
     "desc": "可读取通话记录+录音，可能窃听通话"},
    {"name": "完全监控特征", "perms": ["ACCESS_FINE_LOCATION", "READ_CONTACTS", "CAMERA"],
     "desc": "定位+联系人+摄像头，全方位隐私窃取"},
    {"name": "安装应用风险", "perms": ["REQUEST_INSTALL_PACKAGES", "WRITE_EXTERNAL_STORAGE"],
     "desc": "可从外部存储安装应用（可能静默安装）"},
    {"name": "无障碍监控", "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"],
     "desc": "无障碍服务+悬浮窗，可监控所有操作"},
]

KNOWN_TRACKERS = {
    "com.google.firebase": ("Firebase（Google分析/推送）", "HIGH"),
    "com.google.android.gms.ads": ("Google AdMob广告", "MED"),
    "com.google.android.gms.measurement": ("Google Analytics", "HIGH"),
    "com.google.android.gms.tagmanager": ("Google Tag Manager", "MED"),
    "com.google.firebase.crashlytics": ("Firebase Crashlytics（崩溃收集）", "MED"),
    "com.google.firebase.perf": ("Firebase Performance（性能监控）", "LOW"),
    "com.facebook.ads": ("Facebook Audience Network广告", "MED"),
    "com.unity3d.ads": ("Unity Ads广告", "MED"),
    "com.applovin": ("AppLovin广告", "MED"),
    "com.ironsource": ("ironSource广告", "MED"),
    "com.vungle": ("Vungle广告", "MED"),
    "com.mopub": ("MoPub广告", "MED"),
    "com.chartboost": ("Chartboost广告", "MED"),
    "com.tapjoy": ("Tapjoy广告", "MED"),
    "com.inmobi": ("InMobi广告", "MED"),
    "com.mintegral": ("Mintegral广告", "MED"),
    "com.bytedance.pangle": ("穿山甲/Pangle广告（字节）", "HIGH"),
    "com.qq.e": ("腾讯优量汇广告", "HIGH"),
    "com.kwad": ("快手广告", "MED"),
    "com.umeng": ("友盟统计（阿里）", "HIGH"),
    "com.baidu.mobstat": ("百度统计", "HIGH"),
    "com.tencent.bugly": ("腾讯Bugly", "MED"),
    "com.appsflyer": ("AppsFlyer归因分析", "MED"),
    "com.adjust": ("Adjust归因分析", "MED"),
    "com.branch": ("Branch深度链接", "LOW"),
    "com.amplitude": ("Amplitude分析", "MED"),
    "com.mixpanel": ("Mixpanel分析", "MED"),
    "com.flurry": ("Flurry分析（Yahoo）", "MED"),
    "com.localytics": ("Localytics分析", "LOW"),
    "com.facebook": ("Facebook SDK", "HIGH"),
    "com.twitter": ("Twitter SDK", "MED"),
    "com.tencent.mm": ("微信SDK", "LOW"),
    "com.sina.weibo": ("微博SDK", "LOW"),
    "com.igexin": ("个推推送", "MED"),
    "com.xiaomi.mipush": ("小米推送", "LOW"),
    "com.huawei.hms.push": ("华为推送", "LOW"),
    "com.vivo.push": ("vivo推送", "LOW"),
    "com.oppo.push": ("OPPO推送", "LOW"),
    "com.heytap.msp": ("OPPO推送", "LOW"),
    "com.meizu.cloud.pushsdk": ("魅族推送", "LOW"),
    "com.jpush": ("极光推送", "MED"),
    "com.getui": ("个推", "MED"),
    "com.alipay": ("支付宝SDK", "LOW"),
    "com.tencent.mm.opensdk": ("微信支付SDK", "LOW"),
    "com.unionpay": ("银联支付SDK", "LOW"),
    "com.paypal": ("PayPal SDK", "LOW"),
    "com.stripe": ("Stripe支付", "LOW"),
    "com.amap": ("高德地图SDK", "MED"),
    "com.baidu.map": ("百度地图SDK", "MED"),
    "com.google.android.gms.maps": ("Google Maps SDK", "MED"),
    "im.crisp": ("Crisp在线客服", "LOW"),
    "com.tencent.qcloud": ("腾讯云通信", "LOW"),
    "com.squareup.okhttp": ("OkHttp网络库", "--"),
    "com.squareup.retrofit": ("Retrofit网络库", "--"),
    "com.squareup.picasso": ("Picasso图片加载", "--"),
    "com.bumptech.glide": ("Glide图片加载", "--"),
    "com.facebook.fresco": ("Fresco图片加载", "--"),
    "com.google.gson": ("Gson JSON库", "--"),
    "com.fasterxml": ("Jackson JSON库", "--"),
    "com.alibaba.fastjson": ("FastJSON库（阿里）", "--"),
    "org.apache": ("Apache通用库", "--"),
    "kotlin": ("Kotlin标准库", "--"),
    "androidx": ("AndroidX官方库", "--"),
    "com.google.android.material": ("Material Design库", "--"),
}

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
# 二、核心分析引擎
# ============================================================

class APKPrivacyScanner:
    """APK 隐私安全扫描器（共享引擎）"""

    def __init__(self, apk_path, progress_callback=None):
        self.apk_path = apk_path
        self.progress = progress_callback or (lambda msg, pct: None)
        self.apk = None
        self.dexes = None
        self.analysis = None
        self.risk_score = 0
        self.risk_items = []
        self.result_data = {}

    def load(self):
        """加载 APK 文件"""
        self.progress("正在加载 APK...", 5)
        self.apk, self.dexes, self.analysis = AnalyzeAPK(self.apk_path)
        self.progress("APK 加载成功", 10)

    def analyze_permissions(self):
        """分析权限"""
        self.progress("正在分析权限...", 15)
        perms = self.apk.get_permissions()
        perm_names = []
        for p in perms:
            name = p.split(".")[-1] if "." in p else p
            perm_names.append(name)

        dangerous = [(pn, DANGEROUS_PERMISSIONS[pn])
                      for pn in perm_names if pn in DANGEROUS_PERMISSIONS]
        normal = [pn for pn in perm_names if pn not in DANGEROUS_PERMISSIONS]

        for d in dangerous:
            self.risk_score += 10
            self.risk_items.append(f"危险权限: {d[0]} ({d[1]})")

        combos_found = []
        for combo in HIGH_RISK_PERMISSION_COMBOS:
            matched = [p for p in combo["perms"] if p in perm_names]
            if len(matched) >= 2:
                combos_found.append({
                    "name": combo["name"],
                    "desc": combo["desc"],
                    "matched": matched,
                })
                self.risk_score += 30
                self.risk_items.append(combo["name"])

        self.result_data["permissions"] = {
            "total": len(perm_names),
            "dangerous": dangerous,
            "normal": normal,
            "combos": combos_found,
        }
        self.progress("权限分析完成", 30)

    def analyze_components(self):
        """分析组件暴露"""
        self.progress("正在分析组件...", 35)
        exported = {}
        total = 0
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
            except Exception:
                pass
            exported[comp_type] = comp_list
            total += len(comp_list)

        if total > 20:
            self.risk_score += 5
            self.risk_items.append(f"大量声明组件({total}个)")

        self.result_data["components"] = {"exported": exported, "total": total}
        self.progress("组件分析完成", 45)

    def analyze_trackers(self):
        """分析第三方SDK"""
        self.progress("正在识别第三方SDK...", 50)
        all_classes = set()
        for dex in self.dexes:
            for cls in dex.get_classes():
                all_classes.add(str(cls.name).lower())

        try:
            manifest_xml = self.apk.get_android_manifest_xml()
            if manifest_xml is not None:
                all_classes.add(str(manifest_xml).lower())
        except Exception:
            pass

        try:
            for f in self.apk.get_files():
                if f.startswith('lib/') and f.endswith('.so'):
                    all_classes.add(f.lower())
        except Exception:
            pass

        found = set()
        for cls_path in all_classes:
            for tracker_key, (tracker_name, level) in KNOWN_TRACKERS.items():
                if tracker_key.lower() in cls_path:
                    found.add((tracker_key, tracker_name, level))

        high = [t for t in found if t[2] == "HIGH"]
        medium = [t for t in found if t[2] == "MED"]
        low = [t for t in found if t[2] == "LOW"]
        neutral = [t for t in found if t[2] == "--"]

        for _ in high:
            self.risk_score += 20
            self.risk_items.append(f"高风险SDK: {_[1]}")
        for _ in medium:
            self.risk_score += 10
        for _ in low:
            self.risk_score += 3

        self.result_data["trackers"] = {
            "high": high, "medium": medium, "low": low,
            "neutral": neutral, "total": len(found),
        }
        self.progress("SDK识别完成", 65)

    def analyze_network(self):
        """分析网络地址"""
        self.progress("正在分析网络地址...", 70)
        urls = set()
        ips = set()

        for dex in self.dexes:
            for string in dex.get_strings():
                s = str(string)
                for match in re.finditer(r'https?://[a-zA-Z0-9][-a-zA-Z0-9]*\.[^\s"\'<>\[\]]+', s):
                    url = match.group(0)
                    if len(url) < 200:
                        urls.add(url)
                for match in re.finditer(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s):
                    ip = match.group(0)
                    parts = ip.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        if ip not in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
                            ips.add(ip)

        domains = set()
        for url in urls:
            m = re.search(r'https?://([^/:\s]+)', url)
            if m:
                domains.add(m.group(1))

        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.club']
        suspicious_domains = [d for d in domains if any(d.endswith(t) for t in suspicious_tlds)]
        for d in suspicious_domains:
            self.risk_items.append(f"可疑域名: {d}")
            self.risk_score += 15

        if len(domains) > 20:
            self.risk_items.append(f"大量硬编码域名({len(domains)}个)")
            self.risk_score += 5

        self.result_data["network"] = {
            "urls": sorted(urls), "ips": sorted(ips), "domains": sorted(domains),
            "suspicious_domains": suspicious_domains,
            "url_count": len(urls), "ip_count": len(ips), "domain_count": len(domains),
        }
        self.progress("网络分析完成", 80)

    def analyze_signature(self):
        """分析签名"""
        self.progress("正在解析签名...", 85)
        sig_data = {}
        try:
            sig_data["package"] = self.apk.get_package()
            certs = self.apk.get_certificates()
            sig_data["certs"] = []
            if certs:
                for cert in certs:
                    try:
                        c = {
                            "sha1": cert.sha1_fingerprint.replace(" ", ""),
                            "subject": str(cert.subject),
                            "issuer": str(cert.issuer),
                        }
                        if "Android Debug" in c["subject"] or "debug" in c["subject"].lower():
                            c["debug"] = True
                            self.risk_items.append("使用调试证书签名")
                            self.risk_score += 5
                        if c["subject"] == c["issuer"]:
                            c["self_signed"] = True
                        sig_data["certs"].append(c)
                    except Exception:
                        pass
        except Exception as e:
            sig_data["error"] = str(e)

        self.result_data["signature"] = sig_data
        self.progress("签名解析完成", 90)

    def analyze_sensitive_api(self):
        """分析敏感API调用"""
        self.progress("正在检测敏感API...", 92)
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
                except Exception:
                    pass

        for api, count in found_apis.items():
            self.risk_score += 5
            self.risk_items.append(f"敏感API: {api}")

        self.result_data["sensitive_api"] = dict(found_apis)
        self.progress("敏感API检测完成", 98)

    def calculate_risk(self):
        """计算风险等级"""
        if self.risk_score <= 10:
            level, advice = "低风险", "该应用隐私风险较低，可放心使用"
        elif self.risk_score <= 30:
            level, advice = "中等风险", "存在一定隐私风险，建议谨慎授权"
        elif self.risk_score <= 60:
            level, advice = "较高风险", "隐私风险较高，建议仔细审查权限后使用"
        else:
            level, advice = "高风险", "严重隐私风险！建议避免使用或严格限制权限"

        self.result_data["risk"] = {
            "score": self.risk_score,
            "level": level,
            "advice": advice,
            "items": self.risk_items,
        }
        self.progress("分析完成", 100)

    def run_full(self):
        """运行完整分析"""
        self.load()
        self.analyze_permissions()
        self.analyze_components()
        self.analyze_trackers()
        self.analyze_network()
        self.analyze_signature()
        self.analyze_sensitive_api()
        self.calculate_risk()
        return self.result_data
