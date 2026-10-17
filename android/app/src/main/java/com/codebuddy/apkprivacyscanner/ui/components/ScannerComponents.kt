package com.codebuddy.apkprivacyscanner.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.codebuddy.apkprivacyscanner.file.formatFileSize
import com.codebuddy.apkprivacyscanner.model.ApkFileUiState
import com.codebuddy.apkprivacyscanner.model.ApkScanResult
import com.codebuddy.apkprivacyscanner.model.ApkStructureSummary
import com.codebuddy.apkprivacyscanner.model.DexStringSummary
import com.codebuddy.apkprivacyscanner.model.RiskItem
import com.codebuddy.apkprivacyscanner.model.RiskItemType
import com.codebuddy.apkprivacyscanner.model.RiskLevel
import com.codebuddy.apkprivacyscanner.model.RiskScoreResult

@Composable
fun HeaderSection() {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = "APK Privacy Scanner",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground
        )
        Text(
            text = "手机端 APK 隐私安全静态扫描工具",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AssistChip(onClick = { }, label = { Text("本地静态扫描") })
            AssistChip(onClick = { }, label = { Text("不上传 APK") })
            AssistChip(onClick = { }, label = { Text("规则初筛") })
        }
    }
}

@Composable
fun StatusCards(
    selectedApk: ApkFileUiState?,
    scanResult: ApkScanResult?
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        SummaryCard(
            title = "风险评分",
            value = scanResult?.riskScoreResult?.score?.toString() ?: "--",
            modifier = Modifier.weight(1f)
        )
        SummaryCard(
            title = "风险等级",
            value = scanResult?.riskScoreResult?.level?.displayName ?: selectedApk?.displayName ?: "待选择",
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
fun SummaryCard(
    title: String,
    value: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

@Composable
fun SelectedApkCard(apk: ApkFileUiState) {
    SectionCard(title = if (apk.isApk) "APK 文件" else "文件类型待确认") {
        MetadataLine(label = "文件名", value = apk.displayName)
        MetadataLine(label = "大小", value = formatFileSize(apk.sizeBytes))
        MetadataLine(label = "MIME", value = apk.mimeType ?: "未知")
    }
}

@Composable
fun StructureSummaryCard(summary: ApkStructureSummary) {
    SectionCard(title = "APK 结构概览") {
        MetadataLine(label = "总条目", value = summary.totalEntries.toString())
        MetadataLine(label = "Manifest", value = if (summary.hasManifest) "存在" else "未发现")
        MetadataLine(label = "DEX 文件", value = summary.dexCount.toString())
        MetadataLine(label = "META-INF", value = summary.metaInfCount.toString())
        MetadataLine(label = "Native so", value = summary.nativeLibraryCount.toString())
        MetadataLine(label = "assets", value = summary.assetCount.toString())
        MetadataLine(label = "res", value = summary.resourceCount.toString())
    }
}

@Composable
fun DexStringSummaryCard(summary: DexStringSummary) {
    SectionCard(title = "DEX 字符串概览") {
        MetadataLine(label = "扫描 DEX", value = summary.dexFileCount.toString())
        MetadataLine(label = "字符串数量", value = summary.totalStrings.toString())
        MetadataLine(label = "URL-like", value = summary.urlLikeSamples.size.toString())
        MetadataLine(label = "API-like", value = summary.apiLikeSamples.size.toString())
        MetadataLine(label = "Package-like", value = summary.packageLikeSamples.size.toString())
    }
}

@Composable
fun AnalysisSummaryCard(scanResult: ApkScanResult) {
    SectionCard(title = "规则命中概览") {
        MetadataLine(label = "Tracker 命中", value = scanResult.trackerFindings.size.toString())
        MetadataLine(label = "敏感 API 命中", value = scanResult.sensitiveApiFindings.size.toString())
        MetadataLine(label = "URL", value = scanResult.networkFinding.urlCount.toString())
        MetadataLine(label = "IP", value = scanResult.networkFinding.ipCount.toString())
        MetadataLine(label = "域名", value = scanResult.networkFinding.domainCount.toString())
        MetadataLine(label = "可疑域名", value = scanResult.networkFinding.suspiciousDomains.size.toString())
    }
}

@Composable
fun RiskScoreCard(result: RiskScoreResult) {
    val color = riskLevelColor(result.level)
    Card(
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.14f))
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "风险总览",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = result.advice,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                RiskLevelBadge(level = result.level, color = color)
            }
            MetadataLine(label = "风险评分", value = "${result.score} / 100+")
            MetadataLine(label = "风险等级", value = result.level.displayName)
            MetadataLine(label = "风险项", value = result.items.size.toString())
        }
    }
}

@Composable
private fun RiskLevelBadge(level: RiskLevel, color: Color) {
    Box(
        modifier = Modifier
            .clip(CircleShape)
            .background(color)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = level.displayName,
            style = MaterialTheme.typography.labelMedium,
            color = Color.White,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun RiskItemsGroupedCard(items: List<RiskItem>) {
    SectionCard(title = "风险项摘要") {
        if (items.isEmpty()) {
            EmptyText("暂无风险项")
        } else {
            items.groupBy { it.type }.forEach { (type, groupItems) ->
                RiskGroup(type = type, items = groupItems)
            }
        }
    }
}

@Composable
private fun RiskGroup(type: RiskItemType, items: List<RiskItem>) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            text = "${riskTypeTitle(type)}（${items.size}）",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold
        )
        items.take(MAX_GROUP_ITEMS).forEach { item ->
            Text(
                text = "${item.title}（+${item.score}）",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            item.evidence?.let { evidence ->
                Text(
                    text = evidence.take(MAX_EVIDENCE_LENGTH),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        if (items.size > MAX_GROUP_ITEMS) {
            Text(
                text = "还有 ${items.size - MAX_GROUP_ITEMS} 条未展示",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun ResultExplanationCard() {
    SectionCard(title = "结果说明") {
        Text(
            text = "URL-like / API-like / Package-like 是静态字符串线索；风险评分是基于当前规则的初筛结果，不等同完整安全审计结论。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun MetadataLine(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun EntrySampleCard(entries: List<String>) {
    SampleListCard(title = "条目示例", items = entries)
}

@Composable
fun SampleListCard(
    title: String,
    items: List<String>,
    maxItems: Int = MAX_SAMPLE_ITEMS
) {
    SectionCard(title = title) {
        if (items.isEmpty()) {
            EmptyText("暂无样例")
        } else {
            items.take(maxItems).forEach { item ->
                Text(
                    text = item.take(MAX_EVIDENCE_LENGTH),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (items.size > maxItems) {
                Text(
                    text = "还有 ${items.size - maxItems} 条未展示",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun StepTitle(
    index: String,
    title: String,
    subtitle: String
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primary),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = index,
                color = MaterialTheme.colorScheme.onPrimary,
                fontWeight = FontWeight.Bold
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun PrivacyNotice() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondary.copy(alpha = 0.10f))
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                text = "隐私边界",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "通过系统文件选择器读取用户主动选择的单个文件；不申请全盘文件权限、不上传 APK、不安装被扫描应用、不执行 APK 内代码。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun SectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            content()
        }
    }
}

@Composable
private fun EmptyText(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

private fun riskTypeTitle(type: RiskItemType): String {
    return when (type) {
        RiskItemType.Permission -> "权限风险"
        RiskItemType.PermissionCombo -> "权限组合"
        RiskItemType.Tracker -> "Tracker / SDK"
        RiskItemType.Network -> "网络线索"
        RiskItemType.SensitiveApi -> "敏感 API"
        RiskItemType.Signature -> "签名风险"
        RiskItemType.Structure -> "结构风险"
    }
}

private fun riskLevelColor(level: RiskLevel): Color {
    return when (level) {
        RiskLevel.NONE -> Color(0xFF64748B)
        RiskLevel.LOW -> Color(0xFF16A34A)
        RiskLevel.MEDIUM -> Color(0xFFF59E0B)
        RiskLevel.ELEVATED -> Color(0xFFEA580C)
        RiskLevel.HIGH -> Color(0xFFDC2626)
    }
}

private const val MAX_GROUP_ITEMS = 10
private const val MAX_SAMPLE_ITEMS = 10
private const val MAX_EVIDENCE_LENGTH = 140
