package com.codebuddy.apkprivacyscanner.model

data class TrackerFinding(
    val pattern: String,
    val displayName: String,
    val category: String,
    val riskLevel: RiskLevel,
    val score: Int,
    val evidence: String
)
