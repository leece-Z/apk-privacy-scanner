#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK 隐私安全扫描器 — GUI 版
双击运行 → 选择 APK → 分析 → 浏览器显示报告
支持 Windows / macOS
"""

import sys, os, re, io, json, hashlib, logging, tempfile, webbrowser, threading, time
from collections import defaultdict
from datetime import datetime

# ============================================================
# 环境初始化
# ============================================================
os.environ['LOGURU_LEVEL'] = 'CRITICAL'
os.environ['NO_COLOR'] = '1'
logging.disable(logging.CRITICAL)

if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except:
        pass

# 检查 androguard
try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    import subprocess
    print("正在安装 androguard，请稍候...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "androguard", "-q"])
    from androguard.misc import AnalyzeAPK
    print("androguard 安装完成！")

# ============================================================
# 数据定义（与核心引擎相同）
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
    {"name": "间谍软件特征", "perms": ["RECORD_AUDIO", "CAMERA"], "desc": "同时申请录音+摄像头权限，可秘密录制音视频"},
    {"name": "短信劫持特征", "perms": ["RECEIVE_SMS", "SEND_SMS", "READ_SMS"], "desc": "可拦截/读取/发送短信，可能窃取验证码"},
    {"name": "通话监控特征", "perms": ["READ_CALL_LOG", "RECORD_AUDIO"], "desc": "可读取通话记录+录音，可能窃听通话"},
    {"name": "完全监控特征", "perms": ["ACCESS_FINE_LOCATION", "READ_CONTACTS", "CAMERA"], "desc": "定位+联系人+摄像头，全方位隐私窃取"},
    {"name": "安装应用风险", "perms": ["REQUEST_INSTALL_PACKAGES", "WRITE_EXTERNAL_STORAGE"], "desc": "可从外部存储安装应用（可能静默安装）"},
    {"name": "无障碍监控", "perms": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"], "desc": "无障碍服务+悬浮窗，可监控所有操作"},
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
# 核心分析引擎
# ============================================================

class APKPrivacyScanner:
    def __init__(self, apk_path, progress_callback=None):
        self.apk_path = apk_path
        self.progress = progress_callback or (lambda msg, pct: None)
        self.apk = None
        self.dexes = None
        self.risk_score = 0
        self.risk_items = []
        self.result_data = {}

    def load(self):
        self.progress("正在加载 APK...", 5)
        self.apk, self.dexes, self.analysis = AnalyzeAPK(self.apk_path)
        self.progress("APK 加载成功", 10)

    def analyze_permissions(self):
        self.progress("正在分析权限...", 15)
        perms = self.apk.get_permissions()
        perm_names = []
        for p in perms:
            name = p.split(".")[-1] if "." in p else p
            perm_names.append(name)

        dangerous = [(pn, DANGEROUS_PERMISSIONS[pn]) for pn in perm_names if pn in DANGEROUS_PERMISSIONS]
        normal = [pn for pn in perm_names if pn not in DANGEROUS_PERMISSIONS]

        for _ in dangerous:
            self.risk_score += 10
            self.risk_items.append(f"危险权限: {_[0]} ({_[1]})")

        combos_found = []
        for combo in HIGH_RISK_PERMISSION_COMBOS:
            matched = [p for p in combo["perms"] if p in perm_names]
            if len(matched) >= 2:
                combos_found.append({"name": combo["name"], "desc": combo["desc"], "matched": matched})
                self.risk_score += 30
                self.risk_items.append(combo["name"])

        self.result_data["permissions"] = {
            "total": len(perm_names),
            "dangerous": dangerous,
            "normal": normal,
            "combos": combos_found,
        }
        self.progress("权限分析完成", 30)
        return perm_names

    def analyze_components(self):
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
            except:
                pass
            exported[comp_type] = comp_list
            total += len(comp_list)

        if total > 20:
            self.risk_score += 5
            self.risk_items.append(f"大量声明组件({total}个)")

        self.result_data["components"] = {"exported": exported, "total": total}
        self.progress("组件分析完成", 45)

    def analyze_trackers(self):
        self.progress("正在识别第三方SDK...", 50)
        all_classes = set()
        for dex in self.dexes:
            for cls in dex.get_classes():
                all_classes.add(str(cls.name).lower())

        try:
            manifest_xml = self.apk.get_android_manifest_xml()
            if manifest_xml is not None:
                all_classes.add(str(manifest_xml).lower())
        except:
            pass

        try:
            for f in self.apk.get_files():
                if f.startswith('lib/') and f.endswith('.so'):
                    all_classes.add(f.lower())
        except:
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

        self.result_data["trackers"] = {"high": high, "medium": medium, "low": low, "neutral": neutral, "total": len(found)}
        self.progress("SDK识别完成", 65)

    def analyze_network(self):
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
                    except:
                        pass
        except Exception as e:
            sig_data["error"] = str(e)

        self.result_data["signature"] = sig_data
        self.progress("签名解析完成", 90)

    def analyze_sensitive_api(self):
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
                except:
                    pass

        for api, count in found_apis.items():
            self.risk_score += 5
            self.risk_items.append(f"敏感API: {api}")

        self.result_data["sensitive_api"] = dict(found_apis)
        self.progress("敏感API检测完成", 98)

    def calculate_risk(self):
        if self.risk_score <= 10:
            level, advice = "低风险", "该应用隐私风险较低，可放心使用"
        elif self.risk_score <= 30:
            level, advice = "中等风险", "存在一定隐私风险，建议谨慎授权"
        elif self.risk_score <= 60:
            level, advice = "较高风险", "隐私风险较高，建议仔细审查权限后使用"
        else:
            level, advice = "高风险", "严重隐私风险！建议避免使用或严格限制权限"

        self.result_data["risk"] = {
            "score": self.risk_score, "level": level, "advice": advice, "items": self.risk_items,
        }
        self.progress("分析完成", 100)

    def run_full(self):
        self.load()
        self.analyze_permissions()
        self.analyze_components()
        self.analyze_trackers()
        self.analyze_network()
        self.analyze_signature()
        self.analyze_sensitive_api()
        self.calculate_risk()
        return self.result_data


# ============================================================
# HTML 报告生成
# ============================================================

def generate_html(apk_path, data):
    basename = os.path.basename(apk_path)
    risk = data["risk"]
    perms = data["permissions"]
    comps = data["components"]
    trackers = data["trackers"]
    network = data["network"]
    sig = data.get("signature", {})
    api = data.get("sensitive_api", {})

    level_colors = {"低风险": "#22c55e", "中等风险": "#f59e0b", "较高风险": "#f97316", "高风险": "#ef4444"}
    color = level_colors.get(risk["level"], "#6b7280")

    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    # 危险权限表格
    perm_rows = ""
    for p, desc in perms["dangerous"]:
        perm_rows += f"<tr><td>{esc(p)}</td><td>{esc(desc)}</td></tr>"

    # 权限组合
    combo_html = ""
    for c in perms["combos"]:
        combo_html += f"""<div class="risk-item"><strong>{esc(c['name'])}</strong>：{esc(c['desc'])}（匹配: {', '.join(c['matched'])}）</div>"""

    # 组件
    comp_html = ""
    for ct, clist in comps["exported"].items():
        if clist:
            comp_html += f"<div class='tag'>{ct}: {len(clist)}个</div>"

    # SDK
    sdk_html = ""
    for level, label, cls in [("HIGH", "高风险", "danger"), ("MED", "中风险", "warning"), ("LOW", "低风险", "info")]:
        for t in trackers.get({"HIGH": "high", "MED": "medium", "LOW": "low"}[level], []):
            sdk_html += f"<span class='badge badge-{cls}'>{t[1]}</span>"

    # URL
    url_html = ""
    for url in network["urls"][:20]:
        url_html += f"<div class='url-item'>{esc(url)}</div>"
    if len(network["urls"]) > 20:
        url_html += f"<div class='url-item'>... 还有 {len(network['urls']) - 20} 个</div>"

    # 可疑域名
    susp_html = ""
    for d in network["suspicious_domains"]:
        susp_html += f"<span class='badge badge-danger'>{esc(d)}</span>"

    # 敏感API
    api_html = ""
    for api_name, count in sorted(api.items(), key=lambda x: -x[1]):
        api_html += f"<tr><td>{esc(api_name)}</td><td>{count} 处调用</td></tr>"

    # 风险项
    risk_items_html = "".join(f"<li>{esc(item)}</li>" for item in risk["items"])

    # 签名
    sig_html = ""
    if sig.get("certs"):
        for i, c in enumerate(sig["certs"]):
            sig_html += f"""<div class='sig-card'>
                <div><strong>证书 {i+1}</strong></div>
                <div>SHA1: <code>{esc(c.get('sha1',''))}</code></div>
                <div>主题: {esc(c.get('subject',''))}</div>
                <div>颁发者: {esc(c.get('issuer',''))}</div>
                {"<div class='badge badge-danger'>调试证书</div>" if c.get('debug') else ""}
                {"<div class='badge badge-info'>自签名</div>" if c.get('self_signed') else ""}
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APK 隐私安全分析报告 — {esc(basename)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f5f9; color: #1e293b; line-height: 1.6; }}
.container {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
.header {{ background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: #fff; padding: 32px; border-radius: 16px; margin-bottom: 24px; }}
.header h1 {{ font-size: 24px; margin-bottom: 8px; }}
.header .subtitle {{ color: #94a3b8; font-size: 14px; }}
.score-box {{ display: flex; align-items: center; gap: 16px; margin-top: 16px; }}
.score-circle {{ width: 80px; height: 80px; border-radius: 50%; background: {color}; display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: bold; color: #fff; }}
.score-info {{ }}
.score-info .level {{ font-size: 20px; font-weight: bold; color: {color}; }}
.score-info .advice {{ color: #64748b; margin-top: 4px; }}
.card {{ background: #fff; border-radius: 12px; padding: 24px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.card h2 {{ font-size: 18px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }}
th {{ background: #f8fafc; font-weight: 600; font-size: 13px; color: #64748b; }}
.tag {{ display: inline-block; background: #e2e8f0; color: #334155; padding: 2px 10px; border-radius: 12px; font-size: 13px; margin: 2px; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 13px; margin: 2px; }}
.badge-danger {{ background: #fef2f2; color: #dc2626; }}
.badge-warning {{ background: #fffbeb; color: #d97706; }}
.badge-info {{ background: #eff6ff; color: #2563eb; }}
.risk-item {{ background: #fef2f2; border-left: 3px solid #ef4444; padding: 8px 12px; margin: 8px 0; border-radius: 0 8px 8px 0; font-size: 14px; }}
.url-item {{ font-family: monospace; font-size: 13px; padding: 4px 0; color: #334155; word-break: break-all; border-bottom: 1px solid #f1f5f9; }}
.sig-card {{ background: #f8fafc; border-radius: 8px; padding: 12px; margin: 8px 0; font-size: 13px; }}
.sig-card code {{ background: #e2e8f0; padding: 1px 4px; border-radius: 3px; font-size: 12px; word-break: break-all; }}
ul {{ padding-left: 20px; }}
li {{ margin: 4px 0; font-size: 14px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 16px; }}
.stat {{ background: #f8fafc; padding: 12px; border-radius: 8px; text-align: center; }}
.stat .num {{ font-size: 24px; font-weight: bold; color: #1e293b; }}
.stat .label {{ font-size: 12px; color: #64748b; }}
.footer {{ text-align: center; padding: 24px; color: #94a3b8; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>APK 隐私安全分析报告</h1>
    <div class="subtitle">{esc(basename)} | 分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    <div class="score-box">
        <div class="score-circle">{risk['score']}</div>
        <div class="score-info">
            <div class="level">{risk['level']}</div>
            <div class="advice">{esc(risk['advice'])}</div>
        </div>
    </div>
</div>

<div class="card">
    <h2>概览统计</h2>
    <div class="stats">
        <div class="stat"><div class="num">{len(perms['dangerous'])}</div><div class="label">危险权限</div></div>
        <div class="stat"><div class="num">{comps['total']}</div><div class="label">声明组件</div></div>
        <div class="stat"><div class="num">{trackers['total']}</div><div class="label">第三方SDK</div></div>
        <div class="stat"><div class="num">{network['url_count']}</div><div class="label">硬编码URL</div></div>
        <div class="stat"><div class="num">{network['domain_count']}</div><div class="label">涉及域名</div></div>
        <div class="stat"><div class="num">{len(api)}</div><div class="label">敏感API</div></div>
    </div>
</div>

<div class="card">
    <h2>权限分析 ({perms['total']}个权限，其中 {len(perms['dangerous'])} 个危险)</h2>
    {("<table><thead><tr><th>权限</th><th>说明</th></tr></thead><tbody>" + perm_rows + "</tbody></table>") if perm_rows else "<p>未申请危险权限</p>"}
    {combo_html}
</div>

<div class="card">
    <h2>组件暴露分析</h2>
    {comp_html}
</div>

<div class="card">
    <h2>第三方SDK ({trackers['total']}个)</h2>
    {sdk_html if sdk_html else "<p>未识别到已知第三方SDK</p>"}
</div>

<div class="card">
    <h2>网络地址分析</h2>
    <p style="margin-bottom:12px;color:#64748b">硬编码URL: {network['url_count']}个 | IP地址: {network['ip_count']}个 | 域名: {network['domain_count']}个</p>
    {url_html}
    {("<h3 style='margin-top:16px'>可疑域名</h3>" + susp_html) if susp_html else ""}
</div>

<div class="card">
    <h2>敏感API调用</h2>
    {("<table><thead><tr><th>API</th><th>检测结果</th></tr></thead><tbody>" + api_html + "</tbody></table>") if api_html else "<p>未检测到已知敏感API调用</p>"}
</div>

<div class="card">
    <h2>签名信息</h2>
    <p>包名: <code>{esc(sig.get('package','未知'))}</code></p>
    {sig_html if sig_html else "<p>签名解析失败</p>"}
</div>

<div class="card">
    <h2>风险项汇总</h2>
    <ul>{risk_items_html}</ul>
</div>

<div class="footer">
    APK Privacy Scanner v1.0 — Powered by Python + androguard
</div>

</div>
</body>
</html>"""
    return html


# ============================================================
# GUI 界面
# ============================================================

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


class ScannerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("APK 隐私安全扫描器")
        self.root.geometry("560x460")
        self.root.resizable(False, False)
        self.root.configure(bg="#f1f5f9")

        # 居中
        self.root.update_idletasks()
        w, h = 560, 460
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        self.apk_path = None
        self.build_ui()

    def build_ui(self):
        # 标题
        title = tk.Label(
            self.root, text="APK 隐私安全扫描器",
            font=("Microsoft YaHei", 18, "bold"), fg="#1e293b", bg="#f1f5f9"
        )
        title.pack(pady=(30, 4))

        subtitle = tk.Label(
            self.root, text="选择 APK 文件，一键分析隐私安全风险",
            font=("Microsoft YaHei", 11), fg="#64748b", bg="#f1f5f9"
        )
        subtitle.pack(pady=(0, 20))

        # 文件选择区
        file_frame = tk.Frame(self.root, bg="#ffffff", highlightbackground="#e2e8f0", highlightthickness=1, bd=0)
        file_frame.pack(fill="x", padx=40, pady=(0, 10))

        self.file_label = tk.Label(
            file_frame, text="  尚未选择 APK 文件",
            font=("Consolas", 10), fg="#94a3b8", bg="#ffffff",
            anchor="w", wraplength=420, justify="left"
        )
        self.file_label.pack(side="left", fill="x", expand=True, padx=(12, 8), pady=12)

        self.select_btn = tk.Button(
            file_frame, text="选择文件", command=self.select_file,
            bg="#3b82f6", fg="#ffffff", font=("Microsoft YaHei", 10),
            relief="flat", padx=16, pady=6, cursor="hand2",
            activebackground="#2563eb", activeforeground="#ffffff"
        )
        self.select_btn.pack(side="right", padx=(0, 8), pady=10)

        # 进度条
        self.progress = ttk.Progressbar(self.root, mode="determinate", length=480)
        self.progress.pack(pady=(10, 4), padx=40)

        self.status_label = tk.Label(
            self.root, text="等待选择文件...", font=("Microsoft YaHei", 9),
            fg="#94a3b8", bg="#f1f5f9"
        )
        self.status_label.pack()

        # 开始按钮
        self.start_btn = tk.Button(
            self.root, text="开始分析", command=self.start_scan,
            bg="#22c55e", fg="#ffffff", font=("Microsoft YaHei", 13, "bold"),
            relief="flat", padx=40, pady=10, cursor="hand2", state="disabled",
            activebackground="#16a34a", activeforeground="#ffffff"
        )
        self.start_btn.pack(pady=(20, 10))

        # 提示
        hint = tk.Label(
            self.root,
            text="提示：分析大型 APK 可能需要数十秒，请耐心等待",
            font=("Microsoft YaHei", 8), fg="#94a3b8", bg="#f1f5f9"
        )
        hint.pack()

    def select_file(self):
        path = filedialog.askopenfilename(
            title="选择 APK 文件",
            filetypes=[("APK 文件", "*.apk"), ("所有文件", "*.*")]
        )
        if path:
            self.apk_path = path
            basename = os.path.basename(path)
            self.file_label.config(text=f"  {basename}", fg="#1e293b")
            self.start_btn.config(state="normal", bg="#22c55e")
            self.status_label.config(text=f"已选择: {basename}")

    def update_progress(self, msg, pct):
        m, p = msg, pct
        self.root.after(0, lambda m=m, p=p: self._update_ui(m, p))

    def _update_ui(self, msg, pct):
        self.status_label.config(text=msg)
        self.progress["value"] = pct

    def start_scan(self):
        if not self.apk_path:
            messagebox.showwarning("提示", "请先选择 APK 文件")
            return

        self.start_btn.config(state="disabled", text="分析中...", bg="#94a3b8")
        self.select_btn.config(state="disabled")
        self.progress["value"] = 0
        self.status_label.config(text="正在初始化...")

        def run():
            try:
                scanner = APKPrivacyScanner(self.apk_path, self.update_progress)
                data = scanner.run_full()
                html = generate_html(self.apk_path, data)

                # 保存 HTML 并打开浏览器
                tmp = os.path.join(tempfile.gettempdir(), f"apk_report_{int(time.time())}.html")
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(html)

                path = tmp  # 固定变量，避免闭包问题
                self.root.after(0, lambda p=path: self._on_done(p))
            except Exception as e:
                err = str(e)
                self.root.after(0, lambda e=err: self._on_error(e))

        threading.Thread(target=run, daemon=True).start()

    def _on_done(self, html_path):
        self.status_label.config(text="分析完成！正在打开浏览器...", fg="#22c55e")
        self.progress["value"] = 100
        self.start_btn.config(state="normal", text="开始分析", bg="#22c55e")
        self.select_btn.config(state="normal")

        # 在子线程中打开浏览器，避免阻塞 GUI
        def open_browser():
            webbrowser.open(f"file:///{html_path}")
            # 浏览器打开后弹窗
            self.root.after(300, lambda: messagebox.showinfo("分析完成", "报告已生成并在浏览器中打开！"))
        threading.Thread(target=open_browser, daemon=True).start()

    def _on_error(self, err):
        self.status_label.config(text=f"错误: {err[:60]}", fg="#ef4444")
        self.start_btn.config(state="normal", text="开始分析", bg="#22c55e")
        self.select_btn.config(state="normal")
        messagebox.showerror("分析失败", f"发生错误：\n{err}")

    def run(self):
        self.root.mainloop()


# ============================================================
# 入口
# ============================================================

if __name__ == "__main__":
    # 如果传了 APK 路径作为参数，直接命令行模式
    if len(sys.argv) > 1 and sys.argv[1].endswith('.apk'):
        apk_path = sys.argv[1]
        if not os.path.exists(apk_path):
            print(f"文件不存在: {apk_path}")
            sys.exit(1)
        print(f"正在分析: {os.path.basename(apk_path)}")
        scanner = APKPrivacyScanner(apk_path)
        data = scanner.run_full()
        html = generate_html(apk_path, data)
        tmp = os.path.join(tempfile.gettempdir(), f"apk_report_{int(time.time())}.html")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(html)
        webbrowser.open(f"file:///{tmp}")
        print(f"报告已生成: {tmp}")
        print(f"风险评分: {data['risk']['score']} — {data['risk']['level']}")
    else:
        ScannerApp().run()
