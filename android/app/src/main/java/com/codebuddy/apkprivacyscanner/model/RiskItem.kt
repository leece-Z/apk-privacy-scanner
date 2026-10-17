package com.codebuddy.apkprivacyscanner.model

enum class RiskItemType {
    Permission,
    PermissionCombo,
    Tracker,
    Network,
    SensitiveApi,
    Signature,
    Structure
}

data class RiskItem(
    val type: RiskItemType,
    val title: String,
    val description: String,
    val score: Int,
    val evidence: String? = null,
    val riskLevel: RiskLevel = RiskLevel.LOW
)
