# APK Privacy Scanner Android

<p align="center">
  <strong>Android 手机端 APK 隐私安全静态扫描工具</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android%208.0%2B-green" alt="Platform">
  <img src="https://img.shields.io/badge/Kotlin-2.0.21-blueviolet" alt="Kotlin">
  <img src="https://img.shields.io/badge/Jetpack%20Compose-BOM%202024.12.01-blue" alt="Compose">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/Version-0.4.0-orange" alt="Version">
</p>

---

## 简介

APK Privacy Scanner 是一款 Android 原生应用，可以在手机上直接扫描任意 APK 安装包，检测其中的隐私安全风险。无需连接电脑，选择 APK 文件即可完成全面分析。

> 🖥️ 同系列 PC 桌面版（Python + androguard）请访问：[apk_privacy_scanner](https://github.com/leece-Z/VIBE_CODING/tree/main/apk_privacy_scanner)

## 功能特性

### 扫描入口

| 入口 | 说明 |
|------|------|
| **选择 APK 文件** | 通过系统文件选择器选取任意 APK 进行分析 |
| **已安装应用** | 浏览已安装应用列表，一键扫描目标应用 |

### 六大扫描引擎

| 引擎 | 说明 |
|------|------|
| **权限分析** | 检测 37 种 Android 危险权限声明（定位、录音、短信、摄像头等） |
| **目标应用权限详情** | 提取被扫描 APK 声明的危险权限，查询授权状态（仅已安装应用） |
| **权限组合分析** | 识别 6 种高危权限组合（间谍软件、短信劫持、通话监控等） |
| **SDK / 追踪器识别** | 60+ 规则覆盖国内外主流 SDK（Firebase、友盟、穿山甲、腾讯广告等） |
| **敏感 API 检测** | 15 种敏感 API 调用模式（IMEI、IMSI、位置、WiFi 信息等） |
| **网络行为分析** | 提取 URL / IP / 域名，识别可疑域名（.xyz、.top、.tk 等） |
| **综合风险评分** | 多维度加权评分，输出风险等级与安全建议 |

### 风险评分体系

| 分值范围 | 风险等级 | 建议 |
|----------|----------|------|
| 0 | 无风险 | 未发现明确风险项 |
| 1 - 10 | 低风险 | 该应用隐私风险较低 |
| 11 - 30 | 中等风险 | 存在一定隐私风险，建议谨慎授权 |
| 31 - 60 | 较高风险 | 隐私风险较高，建议仔细审查权限后使用 |
| 60+ | 高风险 | 严重隐私风险，建议避免使用或严格限制权限 |

### Markdown 报告

扫描完成后自动生成 9 章节 Markdown 格式报告，支持一键分享。

## 权限声明

本应用 **不声明任何 `uses-permission`**。

| 保证不会 | 说明 |
|----------|------|
| ❌ 申请全盘文件权限 | 仅通过系统文件选择器 + Uri 授权读取 |
| ❌ 申请网络权限 | 完全离线分析，不上传任何数据 |
| ❌ 上传 APK | 所有分析在本地完成 |
| ❌ 安装被扫描 APK | 只做静态扫描，不触发安装 |
| ❌ 执行 APK 内代码 | 纯静态字符串提取与规则匹配 |

## 技术架构

```
┌─────────────────────────────────────────┐
│              UI Layer                    │
│  Jetpack Compose + Material3            │
│  (选择APK/已安装 → 扫描中 → 结果展示)     │
├─────────────────────────────────────────┤
│            Scanner Engine                │
│  ApkStaticScanner (ZipInputStream)      │
│  ├── DexStringExtractor (纯Kotlin)      │
│  ├── AndroidManifestParser              │
│  ├── TrackerAnalyzer                    │
│  ├── SensitiveApiAnalyzer               │
│  ├── NetworkAnalyzer                    │
│  └── RiskScorer                         │
├─────────────────────────────────────────┤
│            Rules Layer                   │
│  PermissionRules (37种危险权限)           │
│  PermissionComboRules (6种高危组合)       │
│  TrackerRules (60+ SDK规则)             │
│  SensitiveApiRules (15种敏感API)         │
│  NetworkRules (可疑域名规则)             │
│  RiskScoreRules (评分阈值)               │
├─────────────────────────────────────────┤
│       Permission / File Layer            │
│  PermissionChecker (自身+目标权限查询)    │
│  InstalledAppsReader (已安装应用读取)     │
│  ApkFileMetadataReader (APK元数据)       │
├─────────────────────────────────────────┤
│            Report Layer                  │
│  MarkdownReportGenerator                │
└─────────────────────────────────────────┘
```

### 技术栈

- **语言**: Kotlin 2.0.21
- **UI**: Jetpack Compose (BOM 2024.12.01) + Material3
- **APK 解析**: 纯 Kotlin (ZipInputStream)，不依赖第三方分析库
- **最低支持**: Android 8.0 (API 26)
- **目标 SDK**: 35

## 项目结构

```
app/src/main/java/com/codebuddy/apkprivacyscanner/
├── MainActivity.kt              # 主入口
├── file/
│   ├── ApkFileMetadataReader.kt # APK 文件元数据读取
│   └── InstalledAppsReader.kt   # 已安装应用读取 (v1.1.0)
├── permission/
│   └── PermissionChecker.kt     # 权限检查（自身+目标应用，v1.2.0/1.2.2）
├── model/
│   ├── ApkFileUiState.kt        # 文件选择 UI 状态
│   ├── ApkScanResult.kt         # 扫描结果聚合
│   ├── AppPermissionDetail.kt   # 目标应用权限详情 (v1.2.1)
│   ├── InstalledAppInfo.kt      # 已安装应用数据模型 (v1.1.0)
│   ├── PermissionState.kt       # 权限状态数据模型 (v1.2.0)
│   ├── RiskItem.kt              # 风险项模型
│   ├── RiskLevel.kt             # 风险等级枚举
│   ├── RiskScoreResult.kt       # 风险评分结果
│   ├── TrackerFinding.kt        # 追踪器发现
│   ├── SensitiveApiFinding.kt   # 敏感API发现
│   ├── NetworkFinding.kt        # 网络发现
│   ├── ApkStructureSummary.kt   # APK结构摘要
│   └── DexStringSummary.kt      # DEX字符串摘要
├── rules/
│   ├── PermissionRules.kt       # 危险权限规则 (37项)
│   ├── PermissionComboRules.kt  # 高危权限组合 (6种)
│   ├── TrackerRules.kt          # 追踪器/SDK规则 (60+)
│   ├── SensitiveApiRules.kt     # 敏感API规则 (15种)
│   ├── NetworkRules.kt          # 网络规则
│   └── RiskScoreRules.kt        # 评分阈值
├── scanner/
│   ├── ApkStaticScanner.kt      # 静态扫描主入口
│   ├── AndroidManifestParser.kt  # Manifest 权限提取 (v1.2.1)
│   ├── ApkStructureScanner.kt   # APK结构扫描
│   ├── DexStringExtractor.kt    # DEX字符串提取
│   ├── TrackerAnalyzer.kt       # 追踪器分析器
│   ├── SensitiveApiAnalyzer.kt  # 敏感API分析器
│   ├── NetworkAnalyzer.kt       # 网络行为分析器
│   └── RiskScorer.kt            # 风险评分器
├── report/
│   └── MarkdownReportGenerator.kt # Markdown报告生成（9章节）
└── ui/
    ├── ScannerApp.kt            # 导航框架
    ├── components/
    │   └── ScannerComponents.kt  # 可复用UI组件
    ├── screens/
    │   └── ScannerScreens.kt    # 页面 (入口/扫描/结果)
    └── theme/
        ├── Color.kt             # 颜色定义
        ├── Theme.kt             # 主题配置
        └── Type.kt              # 字体排版
```

## 构建方式

### 环境要求

- Android Studio Hedgehog 或更高版本
- JDK 17
- Android SDK，compileSdk = 35

### 构建 Debug APK

```bash
./gradlew assembleDebug
```

输出路径：

```
app/build/outputs/apk/debug/app-debug.apk
```

### 构建 Release APK

```bash
./gradlew assembleRelease
```

## 使用方式

### 方式一：扫描 APK 文件

1. 安装并打开应用
2. 点击「选择 APK 文件」按钮
3. 在系统文件选择器中选取要扫描的 APK
4. 等待扫描完成（约 5-15 秒）
5. 查看风险评分和详细结果
6. 点击「分享报告」导出 Markdown 格式报告

### 方式二：扫描已安装应用

1. 打开应用进入首页
2. 点击「已安装应用」入口
3. 在应用列表中选择目标应用
4. 自动提取 APK 并扫描
5. 查看风险评分、权限声明与授权状态
6. 点击「分享报告」导出 Markdown 格式报告

## 当前限制

- DEX 字符串提取为模式匹配，非完整反编译
- 暂不支持 HTML 报告生成
- 暂无扫描历史记录
- 暂不支持报告保存为文件
- 文件扫描场景无法查询权限授权状态（无目标 packageName）

## 后续计划

| 版本 | 计划内容 |
|------|----------|
| v1.0.1 | MVP 收尾与稳定版归档 |
| v1.1.0 | 已安装 App 列表入口 ✅ (2026-06-14) |
| v1.1.1 | 已安装 App APK 扫描 ✅ (2026-06-14) |
| v1.2.0 | 权限申请与当前授权状态读取（扫描器自身） ✅ (2026-06-14) |
| v1.2.1 | 评分体系升级（Manifest 权限提取 + 结果展示） ✅ (2026-06-14) |
| v1.2.2 | 目标应用权限授权状态查询 ✅ (2026-06-14) |
| v1.3.0 | App 类型与权限合理性 |
| v2.0 | 权限变化监控 / 准实时提醒 |

## 免责声明

本工具基于静态规则进行隐私安全初筛，不等同完整安全审计结论。扫描结果仅供参考，不构成对任何应用的安全性保证。

## 致谢

本项目由 [CodeBuddy](https://www.codebuddy.ai) AI 辅助开发完成。

## License

MIT License
