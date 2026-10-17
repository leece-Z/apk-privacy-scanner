package com.codebuddy.apkprivacyscanner.report

import com.codebuddy.apkprivacyscanner.file.formatFileSize
import com.codebuddy.apkprivacyscanner.model.ApkFileUiState
import com.codebuddy.apkprivacyscanner.model.ApkScanResult
import com.codebuddy.apkprivacyscanner.model.AppPermissionDetail
import com.codebuddy.apkprivacyscanner.model.RiskItem

class MarkdownReportGenerator {
    fun generate(
        apk: ApkFileUiState,
        result: ApkScanResult
    ): String {
        return buildString {
            appendLine("# APK Privacy Scanner 静态扫描报告")
            appendLine()
            appendApkInfo(apk)
            appendRiskSummary(result)
            appendAppPermissions(result.appPermissions)
            appendRiskItems(result.riskScoreResult.items)
            appendRuleFindings(result)
            appendNetworkFindings(result)
            appendStructureSummary(result)
            appendDexSummary(result)
            appendDisclaimer()
        }
    }

    private fun StringBuilder.appendApkInfo(apk: ApkFileUiState) {
        appendLine("## 1. APK 文件信息")
        appendLine()
        appendLine("- 文件名：${apk.displayName}")
        appendLine("- 文件大小：${formatFileSize(apk.sizeBytes)}")
        appendLine("- MIME：${apk.mimeType ?: "未知"}")
        appendLine("- 是否识别为 APK：${if (apk.isApk) "是" else "否"}")
        appendLine()
    }

    private fun StringBuilder.appendRiskSummary(result: ApkScanResult) {
        val risk = result.riskScoreResult
        appendLine("## 2. 风险总览")
        appendLine()
        appendLine("- 风险评分：${risk.score} / 100+")
        appendLine("- 风险等级：${risk.level.displayName}")
        appendLine("- 风险建议：${risk.advice}")
        appendLine("- 风险项数量：${risk.items.size}")
        appendLine()
    }

    private fun StringBuilder.appendAppPermissions(permissions: List<AppPermissionDetail>) {
        if (permissions.isEmpty()) return

        appendLine("## 3. 目标应用权限")
        appendLine()
        val declaredCount = permissions.size
        val highRiskCount = permissions.count { it.riskLevel.displayName.contains("高") }
        appendLine("- 共声明 **$declaredCount** 个危险权限")
        if (highRiskCount > 0) {
            appendLine("- 其中 **$highRiskCount** 个为高风险/较高风险")
        }
        appendLine()

        appendLine("| 权限 | 说明 | 风险等级 | 加分 |")
        appendLine("|------|------|----------|------|")
        permissions.forEach { perm ->
            val grantedText = when (perm.isGranted) {
                true -> " ✓已授权"
                false -> " ✗未授权"
                null -> ""
            }
            appendLine("| ${perm.name.substringAfterLast('.')}$grantedText | ${perm.description} | ${perm.riskLevel.displayName} | +${perm.score} |")
        }
        appendLine()
    }

    private fun StringBuilder.appendRiskItems(items: List<RiskItem>) {
        appendLine("## 4. 风险项摘要")
        appendLine()
        if (items.isEmpty()) {
            appendLine("暂无风险项。")
            appendLine()
            return
        }

        items.groupBy { it.type }.forEach { (type, groupItems) ->
            appendLine("### ${type.name}（${groupItems.size}）")
            groupItems.take(MAX_ITEMS).forEach { item ->
                appendLine("- ${item.title}（+${item.score}）：${item.description}")
                item.evidence?.let { evidence ->
                    appendLine("  - 证据：${evidence.take(MAX_EVIDENCE_LENGTH)}")
                }
            }
            if (groupItems.size > MAX_ITEMS) {
                appendLine("- 还有 ${groupItems.size - MAX_ITEMS} 条未展示")
            }
            appendLine()
        }
    }

    private fun StringBuilder.appendRuleFindings(result: ApkScanResult) {
        appendLine("## 5. 规则命中")
        appendLine()
        appendLine("- Tracker / SDK 命中：${result.trackerFindings.size}")
        result.trackerFindings.take(MAX_ITEMS).forEach { finding ->
            appendLine("  - ${finding.displayName}：${finding.pattern}")
        }
        if (result.trackerFindings.size > MAX_ITEMS) {
            appendLine("  - 还有 ${result.trackerFindings.size - MAX_ITEMS} 条未展示")
        }
        appendLine()
        appendLine("- 敏感 API 命中：${result.sensitiveApiFindings.size}")
        result.sensitiveApiFindings.take(MAX_ITEMS).forEach { finding ->
            appendLine("  - ${finding.displayName}：${finding.pattern}")
        }
        if (result.sensitiveApiFindings.size > MAX_ITEMS) {
            appendLine("  - 还有 ${result.sensitiveApiFindings.size - MAX_ITEMS} 条未展示")
        }
        appendLine()
    }

    private fun StringBuilder.appendNetworkFindings(result: ApkScanResult) {
        val network = result.networkFinding
        appendLine("## 6. 网络线索")
        appendLine()
        appendLine("- URL 数量：${network.urlCount}")
        appendLine("- IP 数量：${network.ipCount}")
        appendLine("- 域名数量：${network.domainCount}")
        appendLine("- 可疑域名数量：${network.suspiciousDomains.size}")
        appendSampleList("URL 样例", network.urls)
        appendSampleList("IP 样例", network.ips)
        appendSampleList("域名样例", network.domains)
        appendSampleList("可疑域名", network.suspiciousDomains)
    }

    private fun StringBuilder.appendStructureSummary(result: ApkScanResult) {
        val structure = result.structureSummary
        appendLine("## 7. APK 结构概览")
        appendLine()
        appendLine("- ZIP entry 总数：${structure.totalEntries}")
        appendLine("- AndroidManifest.xml：${if (structure.hasManifest) "存在" else "未发现"}")
        appendLine("- DEX 文件数量：${structure.dexCount}")
        appendLine("- META-INF 文件数量：${structure.metaInfCount}")
        appendLine("- Native so 数量：${structure.nativeLibraryCount}")
        appendLine("- assets 条目数量：${structure.assetCount}")
        appendLine("- res 条目数量：${structure.resourceCount}")
        appendSampleList("entry 示例", structure.sampleEntries)
    }

    private fun StringBuilder.appendDexSummary(result: ApkScanResult) {
        val dex = result.dexStringSummary
        appendLine("## 8. DEX 字符串概览")
        appendLine()
        appendLine("- 扫描 DEX 文件数量：${dex.dexFileCount}")
        appendLine("- 提取字符串数量：${dex.totalStrings}")
        appendLine("- URL-like 样例数量：${dex.urlLikeSamples.size}")
        appendLine("- API-like 样例数量：${dex.apiLikeSamples.size}")
        appendLine("- Package-like 样例数量：${dex.packageLikeSamples.size}")
        appendSampleList("字符串样例", dex.stringSamples)
        appendSampleList("URL-like 样例", dex.urlLikeSamples)
        appendSampleList("API-like 样例", dex.apiLikeSamples)
        appendSampleList("Package-like 样例", dex.packageLikeSamples)
    }

    private fun StringBuilder.appendSampleList(title: String, items: List<String>) {
        appendLine()
        appendLine("### $title")
        if (items.isEmpty()) {
            appendLine("暂无。")
            appendLine()
            return
        }
        items.take(MAX_ITEMS).forEach { item ->
            appendLine("- ${item.take(MAX_EVIDENCE_LENGTH)}")
        }
        if (items.size > MAX_ITEMS) {
            appendLine("- 还有 ${items.size - MAX_ITEMS} 条未展示")
        }
        appendLine()
    }

    private fun StringBuilder.appendDisclaimer() {
        appendLine("## 9. 说明")
        appendLine()
        appendLine("本报告由 APK Privacy Scanner 基于静态规则生成，仅用于隐私安全初筛，不等同完整安全审计结论。")
        appendLine("工具不会上传 APK，不安装被扫描应用，也不执行 APK 内代码。")
        appendLine()
    }

    private companion object {
        const val MAX_ITEMS = 10
        const val MAX_EVIDENCE_LENGTH = 180
    }
}
