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
    val appPermissions: List<AppPermissionDetail> = emptyList()
)
