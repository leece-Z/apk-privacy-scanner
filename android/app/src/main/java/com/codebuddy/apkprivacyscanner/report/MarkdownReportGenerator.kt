package com.codebuddy.apkprivacyscanner.report

import com.codebuddy.apkprivacyscanner.file.formatFileSize
import com.codebuddy.apkprivacyscanner.model.ApkFileUiState
import com.codebuddy.apkprivacyscanner.model.ApkScanResult
import com.codebuddy.apkprivacyscanner.model.AppPermissionDetail
import com.codebuddy.apkprivacyscanner.model.EvidenceConfidence
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
            appendCoverage(result)
            appendRiskSummary(result)
            appendAppPermissions(result.appPermissions)
            appendRiskItemsByConfidence(result.riskScoreResult.items)
            appendRuleFindings(result)
            appendNetworkFindings(result)
            appendStructureSummary(result)
            appendDexSummary(result)
            appendUnknownsAndLimits(result)
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

    /**
     * 扫描可信度（P1 新增）。
     *
     * 放在最前面，让读者先知道「这份报告能信到什么程度」，
     * 再去看具体风险项。覆盖度不足时给出醒目的降级提示。
     */
    private fun StringBuilder.appendCoverage(result: ApkScanResult) {
        val coverage = result.coverage
        appendLine("## 2. 扫描可信度")
        appendLine()
        appendLine("- 覆盖度：**${coverage.level.label}**（${coverage.level.badge}）")
        appendLine("- 覆盖说明：${coverage.summary}")
        coverage.packerName?.let { packer ->
            appendLine("- 检测到加固壳：**$packer**")
        }
        if (!coverage.level.isTrustworthy) {
            appendLine()
            appendLine("> ⚠️ **本报告不完整**：以下结论仅覆盖已读取到的部分，未覆盖区域见第 10 章。")
            appendLine("> 未覆盖不等于无风险，请勿据此判定目标应用安全。")
        }
        coverage.notes.forEach { note ->
            appendLine("- $note")
        }
        appendLine()

        val items = result.riskScoreResult.items
        if (items.isNotEmpty()) {
            val observed = items.count { it.confidence == EvidenceConfidence.OBSERVED }
            val inferred = items.count { it.confidence == EvidenceConfidence.INFERRED }
            val unknown = items.count { it.confidence == EvidenceConfidence.UNKNOWN }
            appendLine("**证据构成（共 ${items.size} 项）**")
            appendLine()
            appendLine("| 置信度 | 数量 | 含义 |")
            appendLine("|--------|------|------|")
            appendLine("| ${EvidenceConfidence.OBSERVED.badge} 已确证 | $observed | 结构化声明或实际文件内容，可逐项复核 |")
            appendLine("| ${EvidenceConfidence.INFERRED.badge} 推定 | $inferred | 模式匹配所得，可能命中未调用或已废弃代码 |")
            appendLine("| ${EvidenceConfidence.UNKNOWN.badge} 未知 | $unknown | 该区域未被覆盖，不能据此判断 |")
            appendLine()
        }
    }

    private fun StringBuilder.appendRiskSummary(result: ApkScanResult) {
        val risk = result.riskScoreResult
        appendLine("## 3. 风险总览")
        appendLine()
        appendLine("- 风险评分：${risk.score} / 100+")
        appendLine("- 风险等级：${risk.level.displayName}")
        appendLine("- 风险建议：${risk.advice}")
        appendLine("- 风险项数量：${risk.items.size}")
        appendLine()
    }

    private fun StringBuilder.appendAppPermissions(permissions: List<AppPermissionDetail>) {
        if (permissions.isEmpty()) return

        appendLine("## 4. 目标应用权限")
        appendLine()
        val declaredCount = permissions.size
        val highRiskCount = permissions.count { it.riskLevel.displayName.contains("高") }
        appendLine("- 共声明 **$declaredCount** 个危险权限")
        if (highRiskCount > 0) {
            appendLine("- 其中 **$highRiskCount** 个为高风险/较高风险")
        }
        appendLine()
        appendLine("> 权限为清单声明事实，但下方风险评分基于名称匹配，[推定] 未必等于实际调用。")
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

    /**
     * 风险项摘要（P1 改造）：按证据置信度分层输出。
     *
     * 已确证在最前（可直接采信），推定居中（需复核），未知最后（不能用于判风险）。
     * 分层比平铺更能避免把「模式匹配命中」当成「确证事实」。
     */
    private fun StringBuilder.appendRiskItemsByConfidence(items: List<RiskItem>) {
        appendLine("## 5. 风险项摘要（按证据置信度分层）")
        appendLine()
        if (items.isEmpty()) {
            appendLine("暂无风险项。")
            appendLine()
            return
        }

        val grouped = items.groupBy { it.confidence }
            .toSortedMap(compareBy { it.rank })

        grouped.forEach { (confidence, groupItems) ->
            appendLine("### ${confidence.badge} ${confidence.label}（${groupItems.size} 项）")
            appendLine()
            appendLine("_${confidence.description}_")
            appendLine()

            groupItems.groupBy { it.type }.forEach { (type, typeItems) ->
                appendLine("**${type.displayName}**（${typeItems.size}）")
                appendLine()
                typeItems.take(MAX_ITEMS).forEach { item ->
                    appendLine("- ${item.title}（+${item.score}）")
                    appendLine("  - ${item.description}")
                    item.evidence?.let { evidence ->
                        appendLine("  - 证据：${evidence.take(MAX_EVIDENCE_LENGTH)}")
                    }
                    item.evidenceSource?.let { source ->
                        appendLine("  - 来源：$source")
                    }
                }
                if (typeItems.size > MAX_ITEMS) {
                    appendLine("- 还有 ${typeItems.size - MAX_ITEMS} 条未展示")
                }
                appendLine()
            }
        }
    }

    private fun StringBuilder.appendRuleFindings(result: ApkScanResult) {
        appendLine("## 6. 规则命中")
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
        appendLine("## 7. 网络线索")
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
        appendLine("## 8. APK 结构概览")
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
        appendLine("## 9. DEX 字符串概览")
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

    /**
     * 未知与限制（P1 新增）。
     *
     * 显式列出「哪些地方没看到」和「工具固有的技术边界」，
     * 避免读者把「未发现风险」误读为「确认不存在风险」。
     */
    private fun StringBuilder.appendUnknownsAndLimits(result: ApkScanResult) {
        appendLine("## 10. 未知与限制")
        appendLine()

        val unknowns = result.coverage.unknowns
        if (unknowns.isNotEmpty()) {
            appendLine("### 本次未覆盖的区域")
            appendLine()
            unknowns.forEach { unknown ->
                appendLine("- **${unknown.area}**")
                appendLine("  - 原因：${unknown.reason}")
                appendLine("  - 影响：${unknown.impact}")
            }
            appendLine()
        } else {
            appendLine("### 本次未覆盖的区域")
            appendLine()
            appendLine("- 无。目标结构完整解析，未发现明确未覆盖区域。")
            appendLine()
        }

        appendLine("### 工具固有限制")
        appendLine()
        appendLine("以下为当前实现的技术边界，任何一次扫描都受其限制：")
        appendLine()
        BUILT_IN_LIMITATIONS.forEach { limitation ->
            appendLine("- $limitation")
        }
        appendLine()
    }

    private fun StringBuilder.appendDisclaimer() {
        appendLine("## 11. 说明")
        appendLine()
        appendLine("本报告由 APK Privacy Scanner 基于静态规则生成，仅用于隐私安全初筛，不等同完整安全审计结论。")
        appendLine("工具不会上传 APK，不安装被扫描应用，也不执行 APK 内代码。")
        appendLine()
        appendLine("阅读提示：报告中标注 [确证] 的结论可直接采信；标注 [推定] 的结论来自模式匹配，建议复核；")
        appendLine("标注 [未知] 的区域表示本次未覆盖，不能据此判断风险高低。未覆盖不等于无风险。")
        appendLine()
    }

    private companion object {
        const val MAX_ITEMS = 10
        const val MAX_EVIDENCE_LENGTH = 180

        /**
         * 工具固有限制（P1 证据模型）。
         *
         * 这些是实现层面的客观边界，不是本次扫描的偶发情况。
         * 显式列出可避免读者把「未发现」误读为「确认不存在」。
         */
        val BUILT_IN_LIMITATIONS = listOf(
            "AndroidManifest.xml 采用明文正则提取权限，未解析 AXML 二进制结构：自定义权限、权限定义与权限申请无法区分，`android:exported`、`queries` 等组件属性未纳入分析。",
            "DEX 采用字节级可打印字符串提取，非结构化解析：字符串无法归属到具体类与方法，不能确认是否真的被调用，存在误报与漏报。",
            "字符串样本量有上限，超出部分不参与规则匹配，大量信息在提取阶段即被丢弃。",
            "Native (.so) 库仅记录文件名，不做解析：native 层可能存在的隐私收集能力未被覆盖。",
            "assets 条目仅记录路径，未扫描内容：放在 assets 中的配置、密钥、接口地址不会被发现。",
            "不校验 APK 签名与证书，无法据此判断应用是否被重打包或篡改。",
            "不做动态分析：目标应用的实际运行时行为（实际发起的请求、读取的数据）不在本报告范围内。"
        )
    }
}
