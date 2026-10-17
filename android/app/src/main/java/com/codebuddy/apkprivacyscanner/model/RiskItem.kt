package com.codebuddy.apkprivacyscanner.model

enum class RiskItemType(val displayName: String) {
    Permission("权限声明"),
    PermissionCombo("权限组合"),
    Tracker("追踪器 / SDK"),
    Network("网络行为"),
    SensitiveApi("敏感 API"),
    Signature("签名"),
    Structure("结构特征")
}

data class RiskItem(
    val type: RiskItemType,
    val title: String,
    val description: String,
    val score: Int,
    val evidence: String? = null,
    val riskLevel: RiskLevel = RiskLevel.LOW,
    /**
     * 证据置信度。
     *
     * 默认 INFERRED 而非 OBSERVED：现有全部规则命中（权限正则、字符串匹配）
     * 本质都是模式匹配，可能命中未调用或已废弃的代码。显式声明这一点，
     * 可以避免报告把「字符串池里存在」误读为「应用确实调用」。
     */
    val confidence: EvidenceConfidence = EvidenceConfidence.INFERRED,
    /** 证据来源位置，例如 AndroidManifest.xml、classes.dex 字符串池 */
    val evidenceSource: String? = null
) {
    /** 该结论是否需要人工复核 */
    val needsReview: Boolean
        get() = confidence != EvidenceConfidence.OBSERVED
}
