package com.codebuddy.apkprivacyscanner.model

data class ApkScanResult(
    val structureSummary: ApkStructureSummary,
    val dexStringSummary: DexStringSummary,
    val trackerFindings: List<TrackerFinding> = emptyList(),
    val sensitiveApiFindings: List<SensitiveApiFinding> = emptyList(),
    val networkFinding: NetworkFinding = NetworkFinding(
        urls = emptyList(),
        ips = emptyList(),
        domains = emptyList(),
        suspiciousDomains = emptyList()
    ),
    val riskScoreResult: RiskScoreResult = RiskScoreResult(
        score = 0,
        level = RiskLevel.NONE,
        advice = RiskLevel.NONE.advice,
        items = emptyList()
    ),
    /** v1.2.1: 目标应用权限状态（声明+授权） */
    val appPermissions: List<AppPermissionDetail> = emptyList(),
    /**
     * 本次扫描的覆盖度总览（P1 证据模型）。
     * 默认 COMPLETE，与升级前行为一致；接入加固壳检测后可降级并列出未知项。
     */
    val coverage: ScanCoverage = ScanCoverage()
)
