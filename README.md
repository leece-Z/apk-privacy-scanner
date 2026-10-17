# APK Privacy Scanner — Android APK 隐私安全扫描器

<p align="center">
  <strong>🔍 静态分析 Android APK 文件，检测隐私和安全风险</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-PC%20%7C%20Android-green" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/Kotlin-2.0.21-blueviolet" alt="Kotlin">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

---

## 双端可用

本工具提供 **PC 桌面版** 和 **Android 手机版** 两种使用方式，共享相同的规则库和评分体系：

| | PC 桌面版 | Android 手机版 |
|---|---|---|
| **入口** | `pc/` 目录 | `android/` 目录 |
| **语言** | Python | Kotlin |
| **UI** | tkinter GUI | Jetpack Compose + Material3 |
| **APK 解析** | androguard 库 | 纯 Kotlin (ZipInputStream) |
| **报告格式** | HTML（浏览器自动打开） | Markdown（一键分享） |
| **依赖安装** | `pip install androguard` | 安装 APK 即用 |
| **适用场景** | 电脑端深度分析 | 手机上随时随地扫描 |

> 📱 Android 版详情请参阅 [`android/README.md`](android/README.md)

## 快速开始

### 🖥️ PC 桌面版

#### 安装依赖

```bash
pip install androguard
```

#### 运行

**Windows 用户**：双击 `pc/启动扫描器.bat` 或 `pc/run_scanner.bat`

**macOS 用户**：双击 `pc/启动扫描器.command`

**命令行用户**：

```bash
# v2.0 GUI 版（推荐）
python pc/apk_scanner_gui.py

# v1.0 命令行版
python pc/apk_privacy_scanner.py your-app.apk
```

#### 使用流程（v2.0 GUI 版）

1. 双击启动脚本 → 自动检查 Python 和依赖
2. 弹出窗口 → 点击「选择文件」选择 `.apk` 文件
3. 点击「开始分析」→ 进度条显示分析进度
4. 分析完成 → 自动在浏览器中打开精美的 HTML 报告

### 📱 Android 手机版

1. 安装 APK（见 [`android/README.md`](android/README.md) 构建方式）
2. 打开应用 → 点击「选择 APK 文件」
3. 在系统文件选择器中选取 APK
4. 等待扫描完成 → 查看风险评分和详细结果
5. 点击「分享报告」导出 Markdown 格式报告

---

## 功能

7 项自动化检测，覆盖 APK 隐私安全的核心维度：

| # | 模块 | 检测内容 |
|---|------|---------|
| 1 | **权限分析** | 敏感权限申请 + 高危权限组合检测（间谍软件/短信劫持/完全监控等） |
| 2 | **组件暴露分析** | 导出的 Activity/Service/Receiver/Provider（PC 端） |
| 3 | **SDK/追踪器分析** | 识别 Firebase/友盟/穿山甲/广告/分析等 60+ 种第三方 SDK |
| 4 | **网络地址分析** | 硬编码 URL/IP/域名，检测可疑域名 |
| 5 | **签名信息** | 证书 SHA1、签名者、是否调试证书（PC 端） |
| 6 | **敏感API检测** | 获取 IMEI/IMSI/位置/联系人等隐私 API 调用 |
| 7 | **综合风险评估** | 加权评分 + 风险等级（低/中/较高/高）+ 建议 |

### 示例输出

```
  风险评分: 15 / 100+
  风险等级: [LOW] 中等风险
  建议: 存在一定隐私风险，建议谨慎授权

  风险项汇总:
    > 大量硬编码域名(35个)
    > 敏感API: 获取WiFi BSSID
    > 敏感API: 获取WiFi SSID
```

## 项目结构

```
apk_analyse_test/
├── android/                     # 📱 Android 手机版 (Kotlin + Compose)
│   ├── app/                     # 主应用模块
│   │   └── src/main/java/       # Kotlin 源码
│   │       ├── scanner/         # 扫描引擎
│   │       ├── rules/           # 规则库
│   │       ├── model/           # 数据模型
│   │       ├── report/          # 报告生成
│   │       └── ui/              # Compose UI
│   └── README.md                # Android 版详细说明
│
├── pc/                          # 🖥️ PC 桌面版 (Python)
│   ├── apk_scanner_gui.py       # v2.0 GUI 版（推荐）
│   ├── apk_privacy_scanner.py   # v1.0 命令行版
│   ├── shared/
│   │   └── scanner_engine.py    # 共享扫描引擎
│   ├── 启动扫描器.bat            # Windows 启动脚本
│   ├── 启动扫描器.command        # macOS 启动脚本
│   └── run_scanner.bat          # 命令行启动脚本
│
└── docs/                        # 📄 发布文档与配图
```

## 技术架构

### PC 端

```
apk_scanner_gui.py / apk_privacy_scanner.py
│
├── androguard (APK 解析引擎)
│   ├── APK 解析 → AndroidManifest.xml / DEX / 资源
│   ├── 权限提取 → get_permissions()
│   ├── 组件提取 → get_activities() / get_services() 等
│   ├── 证书提取 → get_certificates()
│   └── DEX 分析 → 字符串提取 / 类名提取
│
├── 检测引擎（自建）
│   ├── 危险权限库（37+ 权限定义）
│   ├── 高危权限组合（6 种风险模式）
│   ├── SDK/追踪器库（60+ 第三方 SDK 签名）
│   ├── 敏感 API 模式（15 种隐私 API）
│   └── URL/IP 正则提取
│
└── 评分引擎
    ├── 加权评分（权限 10 分 / 组合 30 分 / SDK 3-20 分 / ...）
    ├── 风险等级（低 / 中 / 较高 / 高）
    └── 风险项汇总
```

### Android 端

```
ApkStaticScanner (ZipInputStream 解析)
│
├── DexStringExtractor     纯 Kotlin DEX 字符串提取
├── TrackerAnalyzer        SDK/追踪器规则匹配
├── SensitiveApiAnalyzer   敏感 API 规则匹配
├── NetworkAnalyzer        URL/域名/可疑域名提取
└── RiskScorer             多维度加权评分
```

## 风险评分规则

| 检测项 | 单次加分 |
|--------|---------|
| 危险权限 | +10 分 |
| 高危权限组合 | +30 分 |
| 高风险 SDK | +20 分 |
| 中风险 SDK | +10 分 |
| 低风险 SDK | +3 分 |
| 可疑域名 | +15 分 |
| 敏感 API 调用 | +5 分 |
| 调试证书 | +5 分 |
| 大量组件/域名 | +5 分 |

**风险等级：** ≤10 低风险 / ≤30 中等 / ≤60 较高 / \>60 高

## 识别 SDK 清单（部分）

| 类别 | SDK |
|------|-----|
| 广告 | Google AdMob、穿山甲/Pangle、优量汇、快手、Unity Ads、AppLovin、ironSource |
| 分析 | Firebase、友盟、百度统计、AppsFlyer、Adjust、Amplitude、Mixpanel |
| 社交 | Facebook SDK、Twitter SDK、微信 SDK、微博 SDK |
| 推送 | 个推、极光、小米/华为/OPPO/vivo 推送 |
| 支付 | 支付宝、微信支付、银联、PayPal、Stripe |
| 地图 | 高德、百度、Google Maps |

## 与业界工具对比

| 特性 | 本工具 | Exodus Privacy | PCAPdroid | MobSF |
|------|--------|---------------|-----------|-------|
| 运行环境 | PC + 手机 | 手机 App/网站 | Android 手机 | PC(Web) |
| APK 静态分析 | ✅ | ✅ | ❌ | ✅ |
| 实时流量监控 | ❌ | ❌ | ✅ | ❌ |
| 危险权限组合检测 | ✅ | ❌ | ❌ | ❌ |
| 敏感 API 检测 | ✅ | ❌ | ❌ | ✅ |
| SDK/追踪器识别 | ✅ (60+) | ✅ (300+) | ❌ | ✅ |
| 综合风险评分 | ✅ | ❌ | ❌ | ✅ |
| 中文本地化 | ✅ | 部分 | ✅ | 部分 |
| 安装复杂度 | 轻量 | 手机安装 | 手机安装 | 较重(Docker) |
| GUI 界面 | ✅ | ❌ | ✅ | ✅ |

## 隐私声明

- PC 端：完全本地分析，不上传任何数据
- Android 端：**零权限声明**，不申请网络、文件等任何权限，通过系统文件选择器 + Uri 授权读取 APK

## 致谢

本项目由 [CodeBuddy](https://www.codebuddy.ai) AI 辅助开发完成。

## License

MIT
