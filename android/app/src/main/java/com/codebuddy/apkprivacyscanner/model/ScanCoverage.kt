package com.codebuddy.apkprivacyscanner.model

/**
 * 扫描覆盖度等级。
 *
 * 核心目的：避免「什么都没扫到却输出低风险」这种假阴性。
 * 一旦目标被加固或存在未覆盖区域，报告必须显式降级并列出未知项。
 */
enum class CoverageLevel(
    val label: String,
    val badge: String,
    val rank: Int
) {
    /** 全量覆盖，结论可直接采信 */
    COMPLETE(label = "完整覆盖", badge = "完整", rank = 0),

    /** 存在未完全覆盖的区域，结论需谨慎采信 */
    LIMITED(label = "部分覆盖", badge = "部分", rank = 1),

    /** 关键区域完全无法读取，结论仅覆盖外壳 */
    BLOCKED(label = "受阻", badge = "受阻", rank = 2);

    /** 是否可以正常给出风险结论 */
    val isTrustworthy: Boolean get() = this == COMPLETE
}

/**
 * 单条未覆盖声明。用于在报告中显式列出「哪些地方没看到」。
 */
data class ScanUnknown(
    val area: String,
    val reason: String,
    val impact: String
)

/**
 * 本次扫描的覆盖度总览。
 *
 * 默认值为 COMPLETE / 无未知项，保证在检测能力尚未接入（P0 阶段）
 * 时报告行为与现状完全一致，不会产生误报式降级。
 */
data class ScanCoverage(
    val level: CoverageLevel = CoverageLevel.COMPLETE,
    val summary: String = "本次扫描覆盖 APK 的清单、DEX 字符串、Native 库清单与 assets 条目。",
    val packerName: String? = null,
    val unknowns: List<ScanUnknown> = emptyList(),
    val notes: List<String> = emptyList()
) {
    companion object {
        /** 尚未接入加固壳检测时的默认覆盖度 */
        fun default(): ScanCoverage = ScanCoverage()
    }
}