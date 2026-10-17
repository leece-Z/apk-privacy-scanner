package com.codebuddy.apkprivacyscanner.model

enum class RiskLevel(
    val displayName: String,
    val advice: String
) {
    NONE("无风险", "未发现明确风险项"),
    LOW("低风险", "该应用隐私风险较低"),
    MEDIUM("中等风险", "存在一定隐私风险，建议谨慎授权"),
    ELEVATED("较高风险", "隐私风险较高，建议仔细审查权限后使用"),
    HIGH("高风险", "严重隐私风险，建议避免使用或严格限制权限")
}
