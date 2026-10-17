package com.codebuddy.apkprivacyscanner.rules

object RiskScoreRules {
    const val dangerousPermissionScore = 10
    const val highRiskPermissionComboScore = 30
    const val highRiskTrackerScore = 20
    const val mediumRiskTrackerScore = 10
    const val lowRiskTrackerScore = 3
    const val suspiciousDomainScore = 15
    const val sensitiveApiScore = 5
    const val debugCertificateScore = 5
    const val largeStructureScore = 5

    const val lowRiskMax = 10
    const val mediumRiskMax = 30
    const val elevatedRiskMax = 60
}
