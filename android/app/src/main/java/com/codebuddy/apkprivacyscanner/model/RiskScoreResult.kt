package com.codebuddy.apkprivacyscanner.model

data class RiskScoreResult(
    val score: Int,
    val level: RiskLevel,
    val advice: String,
    val items: List<RiskItem>
)
