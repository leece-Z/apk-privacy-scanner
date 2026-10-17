package com.codebuddy.apkprivacyscanner.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.codebuddy.apkprivacyscanner.model.ApkFileUiState
import com.codebuddy.apkprivacyscanner.model.ApkScanResult
import com.codebuddy.apkprivacyscanner.model.AppPermissionDetail
import com.codebuddy.apkprivacyscanner.model.InstalledAppInfo
import com.codebuddy.apkprivacyscanner.model.PermissionState
import com.codebuddy.apkprivacyscanner.model.PermissionType
import com.codebuddy.apkprivacyscanner.model.RiskLevel
import com.codebuddy.apkprivacyscanner.ui.components.AnalysisSummaryCard
import com.codebuddy.apkprivacyscanner.ui.components.DexStringSummaryCard
import com.codebuddy.apkprivacyscanner.ui.components.EntrySampleCard
import com.codebuddy.apkprivacyscanner.ui.components.ResultExplanationCard
import com.codebuddy.apkprivacyscanner.ui.components.RiskItemsGroupedCard
import com.codebuddy.apkprivacyscanner.ui.components.RiskScoreCard
import com.codebuddy.apkprivacyscanner.ui.components.SampleListCard
import com.codebuddy.apkprivacyscanner.ui.components.SelectedApkCard
import com.codebuddy.apkprivacyscanner.ui.components.StepTitle
import com.codebuddy.apkprivacyscanner.ui.components.StructureSummaryCard

@Composable
fun HomeContent(
    selectedApk: ApkFileUiState?,
    scanResult: ApkScanResult?,
    errorMessage: String?,
    permissionStates: List<PermissionState> = emptyList(),
    onSelectApk: () -> Unit,
    onScanApk: () -> Unit,
    onPreviewResult: () -> Unit,
    onRequestPermission: (String) -> Unit = {},
    onOpenInstalledApps: () -> Unit = {}
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text(
                text = "选择 APK 后开始分析",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "本阶段会串联 APK 结构读取、DEX 字符串提取、规则匹配和初版风险评分。",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // v1.2.0: 权限状态概览
            PermissionStatusCard(
                states = permissionStates,
                onRequestPermission = onRequestPermission
            )

            // v1.1.0: 已安装应用列表入口
            OutlinedButton(
                modifier = Modifier.fillMaxWidth(),
                onClick = onOpenInstalledApps
            ) {
                Text("扫描已安装应用")
            }

            Button(
                modifier = Modifier.fillMaxWidth(),
                onClick = onSelectApk
            ) {
                Text("选择 APK 文件")
            }

            selectedApk?.let { apk ->
                SelectedApkCard(apk = apk)
            }

            scanResult?.let { result ->
                RiskScoreCard(result = result.riskScoreResult)
                AnalysisSummaryCard(scanResult = result)
            }

            errorMessage?.let { message ->
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Button(
                modifier = Modifier.fillMaxWidth(),
                enabled = selectedApk?.isApk == true,
                onClick = onScanApk
            ) {
                Text("开始基础扫描")
            }
            OutlinedButton(
                modifier = Modifier.fillMaxWidth(),
                enabled = scanResult != null,
                onClick = onPreviewResult
            ) {
                Text("查看扫描结果")
            }
        }
    }
}

@Composable
fun ScanningContent(
    selectedApk: ApkFileUiState?,
    progress: Float,
    progressMessage: String,
    elapsedSeconds: Int,
    onBack: () -> Unit,
    onShowResult: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            StepTitle(
                index = "01",
                title = "基础扫描引擎",
                subtitle = "正在串联 APK 读取、DEX 字符串提取、规则匹配和风险评分。"
            )
            selectedApk?.let { apk ->
                Text(
                    text = "待扫描文件：${apk.displayName}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // 实时进度条
            LinearProgressIndicator(
                progress = { progress.coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth()
            )

            // 进度信息
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = "${(progress * 100).toInt()}% — $progressMessage",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = "已耗时：${elapsedSeconds / 2}.${if (elapsedSeconds % 2 == 0) "0" else "5"}s",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(
                    modifier = Modifier.weight(1f),
                    onClick = onBack
                ) {
                    Text("返回首页")
                }
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = onShowResult
                ) {
                    Text("查看结果")
                }
            }
        }
    }
}

@Composable
fun ResultContent(
    selectedApk: ApkFileUiState?,
    scanResult: ApkScanResult?,
    onShareReport: () -> Unit,
    onBack: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            StepTitle(
                index = "02",
                title = "扫描结果",
                subtitle = "展示风险总览、命中摘要和静态线索。可分享 Markdown 报告文本。"
            )
            selectedApk?.let { apk -> SelectedApkCard(apk = apk) }
            scanResult?.let { result ->
                RiskScoreCard(result = result.riskScoreResult)
                // v1.2.1: 目标应用权限状态
                TargetAppPermissionCard(permissions = result.appPermissions)
                ResultExplanationCard()
                RiskItemsGroupedCard(items = result.riskScoreResult.items)
                AnalysisSummaryCard(scanResult = result)
                StructureSummaryCard(summary = result.structureSummary)
                DexStringSummaryCard(summary = result.dexStringSummary)
                SampleListCard(title = "Tracker / SDK 命中", items = result.trackerFindings.map { it.displayName })
                SampleListCard(title = "敏感 API 命中", items = result.sensitiveApiFindings.map { it.displayName })
                SampleListCard(title = "URL 样例", items = result.networkFinding.urls)
                SampleListCard(title = "IP 样例", items = result.networkFinding.ips)
                SampleListCard(title = "域名样例", items = result.networkFinding.domains)
                SampleListCard(title = "可疑域名", items = result.networkFinding.suspiciousDomains)
                EntrySampleCard(entries = result.structureSummary.sampleEntries)
                SampleListCard(title = "DEX 字符串样例", items = result.dexStringSummary.stringSamples)
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = onShareReport
                ) {
                    Text("分享 Markdown 报告")
                }
            } ?: Text(
                text = "尚未完成基础扫描，请先返回首页选择 APK 并点击扫描。",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedButton(
                modifier = Modifier.fillMaxWidth(),
                onClick = onBack
            ) {
                Text("返回首页")
            }
        }
    }
}

// ===== v1.1.0: 已安装 App 列表入口（分页 + 选中后扫码） =====

private const val PAGE_SIZE = 20

@Composable
fun InstalledAppsContent(
    apps: List<InstalledAppInfo>,
    currentPage: Int,
    selectedApp: InstalledAppInfo?,
    isLoading: Boolean,
    errorMessage: String?,
    permissionStates: List<PermissionState> = emptyList(),
    onSelectApp: (InstalledAppInfo) -> Unit,
    onScanApp: () -> Unit,
    onPageChange: (Int) -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRequestPermission: (String) -> Unit = {}
) {
    val totalPages = if (apps.isEmpty()) 1 else (apps.size + PAGE_SIZE - 1) / PAGE_SIZE
    val pageStart = currentPage * PAGE_SIZE
    val pageApps = apps.drop(pageStart).take(PAGE_SIZE)

    // v1.2.0: 查找 QUERY_ALL_PACKAGES 权限状态
    val queryPermission = permissionStates.find {
        it.permission == android.Manifest.permission.QUERY_ALL_PACKAGES
    }
    val hasQueryPermission = queryPermission?.isGranted == true

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text(
                text = "已安装应用列表",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "点击应用选中，再点击「开始基础扫描」进行隐私分析。",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            // v1.2.0: 权限不足引导卡片
            if (!hasQueryPermission && !isLoading) {
                PermissionGuideCard(
                    permission = queryPermission,
                    onRequestPermission = onRequestPermission,
                    onBack = onBack
                )
            }

            // 顶部操作按钮
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    modifier = Modifier.weight(1f),
                    onClick = onBack
                ) {
                    Text("返回首页")
                }
                OutlinedButton(
                    modifier = Modifier.weight(1f),
                    onClick = onRefresh,
                    enabled = !isLoading
                ) {
                    Text("刷新列表")
                }
            }

            // 加载中
            if (isLoading) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Text(
                    text = "正在读取已安装应用列表...",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // 错误信息
            errorMessage?.let { message ->
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            // 选中应用信息 + 扫描按钮
            selectedApp?.let { app ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text(
                            text = "已选中：${app.appName}",
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        Text(
                            text = "${app.packageName}${app.versionName?.let { " | v$it" } ?: ""}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                        )
                        Button(
                            modifier = Modifier.fillMaxWidth(),
                            onClick = onScanApp
                        ) {
                            Text("开始基础扫描")
                        }
                    }
                }
            }

            // 应用列表
            if (!isLoading && apps.isEmpty() && errorMessage == null) {
                Text(
                    text = "未读取到已安装应用，请检查权限设置。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            pageApps.forEach { app ->
                AppListItem(
                    app = app,
                    isSelected = selectedApp?.packageName == app.packageName,
                    onSelect = { onSelectApp(app) }
                )
            }

            // 分页控件
            if (totalPages > 1) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedButton(
                        onClick = { onPageChange(currentPage - 1) },
                        enabled = currentPage > 0
                    ) {
                        Text("上一页")
                    }
                    Text(
                        text = "第 ${currentPage + 1} / $totalPages 页",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedButton(
                        onClick = { onPageChange(currentPage + 1) },
                        enabled = currentPage < totalPages - 1
                    ) {
                        Text("下一页")
                    }
                }
            }

            // 底部提示
            Text(
                text = "共 ${apps.size} 个应用 | 每页 $PAGE_SIZE 个 | 当前第 ${currentPage + 1} 页",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// ===== v1.2.0: 权限状态卡片 =====

@Composable
fun PermissionStatusCard(
    states: List<PermissionState>,
    onRequestPermission: (String) -> Unit
) {
    if (states.isEmpty()) return

    val hasMissing = states.any { !it.isGranted && it.type == PermissionType.RUNTIME }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (hasMissing)
                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
            else
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(
                text = "应用权限状态",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )

            states.forEach { state ->
                PermissionItem(state = state, onAction = {
                    if (!state.isGranted && state.actionHint != null) {
                        onRequestPermission(state.permission)
                    }
                })
            }
        }
    }
}

@Composable
private fun PermissionItem(
    state: PermissionState,
    onAction: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        // 状态图标 + 名称 + 描述
        Row(
            modifier = Modifier.weight(1f),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val icon = if (state.isGranted) "✓" else "✗"
            val iconColor = if (state.isGranted)
                MaterialTheme.colorScheme.primary
            else
                MaterialTheme.colorScheme.error

            Text(
                text = icon,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = iconColor
            )
            Spacer(modifier = Modifier.width(8.dp))
            Column {
                Text(
                    text = state.displayName,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = state.description,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // 操作按钮
        if (!state.isGranted && state.actionHint != null) {
            val isRunnable = state.type == PermissionType.RUNTIME ||
                    state.type == PermissionType.SPECIAL
            if (isRunnable) {
                Spacer(modifier = Modifier.width(8.dp))
                OutlinedButton(
                    onClick = onAction,
                    contentPadding = ButtonDefaults.TextButtonContentPadding
                ) {
                    Text(
                        text = state.actionHint,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
        }
    }
}

// v1.2.0: 权限不足引导卡片（已安装应用页专用）
@Composable
private fun PermissionGuideCard(
    permission: PermissionState?,
    onRequestPermission: (String) -> Unit,
    onBack: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.4f)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "⚠ 需要权限授权",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Text(
                text = permission?.description ?: "需要「查询所有应用」权限才能读取已安装应用列表。",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Text(
                text = "请在系统设置 → 应用 → APK隐私扫描 → 权限中开启",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.7f)
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    modifier = Modifier.weight(1f),
                    onClick = onBack
                ) {
                    Text("返回首屏")
                }
                if (permission != null && !permission.isGranted) {
                    Button(
                        modifier = Modifier.weight(1f),
                        onClick = { onRequestPermission(permission.permission) }
                    ) {
                        Text("去授权")
                    }
                }
            }
        }
    }
}

// ===== v1.1.0 应用列表项组件 =====

@Composable
private fun AppListItem(
    app: InstalledAppInfo,
    isSelected: Boolean,
    onSelect: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected)
                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f)
            else
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        ),
        onClick = onSelect
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = app.appName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                app.versionName?.let { ver ->
                    Text(
                        text = "版本: $ver",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            if (isSelected) {
                Text(
                    text = "✓",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }
    }
}

// ===== v1.2.1: 目标应用权限状态卡片 =====

@Composable
private fun TargetAppPermissionCard(permissions: List<AppPermissionDetail>) {
    if (permissions.isEmpty()) return

    val declaredCount = permissions.count { it.isDeclared }
    val highRiskCount = permissions.count { it.riskLevel == RiskLevel.HIGH || it.riskLevel == RiskLevel.ELEVATED }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (highRiskCount > 0)
                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.15f)
            else
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // 标题行
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "目标应用权限",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "命中 $declaredCount 个危险权限",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (highRiskCount > 0)
                        MaterialTheme.colorScheme.error
                    else
                        MaterialTheme.colorScheme.primary
                )
            }

            // 权限列表
            permissions.forEach { perm ->
                TargetPermissionItem(perm)
            }
        }
    }
}

@Composable
private fun TargetPermissionItem(perm: AppPermissionDetail) {
    val riskColor = when (perm.riskLevel) {
        RiskLevel.HIGH, RiskLevel.ELEVATED -> MaterialTheme.colorScheme.error
        RiskLevel.MEDIUM -> MaterialTheme.colorScheme.error.copy(alpha = 0.7f)
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // 风险等级指示圆点
        Text(
            text = "●",
            style = MaterialTheme.typography.labelSmall,
            color = riskColor
        )

        // 权限信息
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = perm.displayName,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = perm.name.substringAfterLast('.'),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // 风险标签
        Text(
            text = perm.riskLevel.displayName,
            style = MaterialTheme.typography.labelSmall,
            color = riskColor,
            fontWeight = FontWeight.Bold
        )

        // 授权状态（仅已知时显示）
        perm.isGranted?.let { granted ->
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = if (granted) "✓ 已授权" else "✗ 未授权",
                style = MaterialTheme.typography.labelSmall,
                color = if (granted)
                    MaterialTheme.colorScheme.primary
                else
                    MaterialTheme.colorScheme.error,
                fontWeight = FontWeight.Medium
            )
        }

        // 加分
        Text(
            text = "+${perm.score}",
            style = MaterialTheme.typography.labelSmall,
            color = riskColor
        )
    }
}
