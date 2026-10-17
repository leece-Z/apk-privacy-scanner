package com.codebuddy.apkprivacyscanner.model

/**
 * 证据置信度分级。
 *
 * 设计意图：区分「看到的事实」与「由模式匹配推出的结论」与「没看到的部分」。
 * 隐私扫描的结论本质上大量来自字符串规则匹配，如果不标明证据等级，
 * 「字符串池里存在 getDeviceId」会被误读为「该应用调用了 getDeviceId」。
 */
enum class EvidenceConfidence(
    val label: String,
    val badge: String,
    val description: String,
    val rank: Int
) {
    /** 来自结构化声明或实际字节内容，可直接复核 */
    OBSERVED(
        label = "已确证",
        badge = "[确证]",
        description = "来自 APK 结构化声明或实际文件内容，可逐项复核",
        rank = 0
    ),

    /** 来自字符串/字节模式匹配，可能命中未调用或已废弃的代码 */
    INFERRED(
        label = "推定",
        badge = "[推定]",
        description = "来自字符串或字节模式匹配，可能命中未调用、已废弃或混淆代码",
        rank = 1
    ),

    /** 该区域未被覆盖，不能据此判断风险高低 */
    UNKNOWN(
        label = "未知",
        badge = "[未知]",
        description = "该区域未被本次扫描覆盖，不能据此判断风险高低",
        rank = 2
    );

    companion object {
        fun fromLabel(label: String?): EvidenceConfidence {
            return entries.firstOrNull { it.label == label } ?: INFERRED
        }
    }
}