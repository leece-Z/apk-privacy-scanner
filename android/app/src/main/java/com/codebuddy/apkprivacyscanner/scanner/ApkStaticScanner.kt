package com.codebuddy.apkprivacyscanner.scanner

import android.content.Context
import android.net.Uri
import com.codebuddy.apkprivacyscanner.model.AppPermissionDetail
import com.codebuddy.apkprivacyscanner.model.ApkScanResult
import com.codebuddy.apkprivacyscanner.model.ApkStructureSummary
import com.codebuddy.apkprivacyscanner.model.NetworkFinding
import com.codebuddy.apkprivacyscanner.model.RiskItem
import com.codebuddy.apkprivacyscanner.model.RiskItemType
import com.codebuddy.apkprivacyscanner.model.RiskLevel
import com.codebuddy.apkprivacyscanner.permission.PermissionChecker
import com.codebuddy.apkprivacyscanner.rules.NetworkRules
import com.codebuddy.apkprivacyscanner.rules.PermissionRules
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.util.zip.ZipInputStream

class ApkStaticScanner(private val context: Context) {

    // ===== v1.0: 通过 Uri（系统文件选择器）扫描 =====
    fun scan(uri: Uri, onProgress: ((Float, String) -> Unit)? = null): ApkScanResult {
        onProgress?.invoke(0.05f, "正在打开 APK 文件...")
        val inputStream = context.contentResolver.openInputStream(uri)
            ?: error("无法打开用户选择的 APK 文件")
        return inputStream.use { scanFromInputStream(it, onProgress) }
    }

    // ===== v1.1.1: 通过文件路径直接扫描（已安装应用 sourceDir） =====
    // v1.2.2: 增加 packageName 参数，用于查询目标 App 的权限授权状态
    fun scanFromPath(
        apkPath: String,
        packageName: String? = null,
        onProgress: ((Float, String) -> Unit)? = null
    ): ApkScanResult {
        onProgress?.invoke(0.05f, "正在读取 APK 文件...")
        val file = File(apkPath)
        if (!file.exists() || !file.canRead()) {
            error("无法读取 APK 文件：$apkPath")
        }
        val inputStream = FileInputStream(file)
        return inputStream.use { scanFromInputStream(it, onProgress, packageName) }
    }

    // ===== 核心扫描逻辑（统一入口） =====
    private fun scanFromInputStream(
        inputStream: InputStream,
        onProgress: ((Float, String) -> Unit)?,
        packageName: String? = null  // v1.2.2: 用于查询目标 App 权限授权状态
    ): ApkScanResult {
        val dexFiles = mutableListOf<String>()
        val metaInfFiles = mutableListOf<String>()
        val nativeLibraries = mutableListOf<String>()
        val assetEntries = mutableListOf<String>()
        val resourceEntries = mutableListOf<String>()
        val sampleEntries = mutableListOf<String>()
        var totalEntries = 0
        var hasManifest = false
        var manifestBytes: ByteArray? = null

        val dexStringExtractor = DexStringExtractor()
        val dexAccumulator = dexStringExtractor.createAccumulator()

        onProgress?.invoke(0.10f, "正在解析 APK 结构...")

        ZipInputStream(inputStream.buffered()).use { zipStream ->
            while (true) {
                val entry = zipStream.nextEntry ?: break
                val name = entry.name
                totalEntries += 1

                if (sampleEntries.size < MAX_SAMPLE_ENTRIES) {
                    sampleEntries += name
                }

                when {
                    name == "AndroidManifest.xml" -> {
                        hasManifest = true
                        // v1.2.1: 保存 Manifest 内容用于权限提取
                        manifestBytes = zipStream.readBytes()
                    }
                    name.matches(DEX_FILE_REGEX) -> {
                        dexFiles += name
                        dexStringExtractor.consumeDexEntry(
                            dexFileName = name,
                            inputStream = zipStream,
                            accumulator = dexAccumulator
                        )
                    }
                    name.startsWith("META-INF/") -> metaInfFiles += name
                    name.startsWith("lib/") && name.endsWith(".so") -> nativeLibraries += name
                    name.startsWith("assets/") -> assetEntries += name
                    name.startsWith("res/") -> resourceEntries += name
                }

                zipStream.closeEntry()
            }
        }

        // v1.2.1: 从 Manifest 中提取权限声明
        val permissions = manifestBytes?.let { bytes ->
            AndroidManifestParser.extract(String(bytes, Charsets.ISO_8859_1))
        } ?: emptyList()

        val structureSummary = ApkStructureSummary(
            totalEntries = totalEntries,
            hasManifest = hasManifest,
            dexFiles = dexFiles,
            metaInfFiles = metaInfFiles,
            nativeLibraries = nativeLibraries,
            assetEntries = assetEntries,
            resourceEntries = resourceEntries,
            sampleEntries = sampleEntries,
            permissions = permissions
        )

        onProgress?.invoke(0.35f, "正在提取 DEX 字符串...")
        val dexStringSummary = dexStringExtractor.buildSummary(dexAccumulator)

        onProgress?.invoke(0.55f, "正在运行 Tracker/SDK 识别...")
        val stringsForAnalysis = buildList {
            addAll(dexStringSummary.stringSamples)
            addAll(dexStringSummary.urlLikeSamples)
            addAll(dexStringSummary.apiLikeSamples)
            addAll(dexStringSummary.packageLikeSamples)
        }
        val trackerFindings = TrackerAnalyzer().analyze(stringsForAnalysis)

        onProgress?.invoke(0.70f, "正在检测敏感 API 调用...")
        val sensitiveApiFindings = SensitiveApiAnalyzer().analyze(stringsForAnalysis)

        onProgress?.invoke(0.85f, "正在分析网络行为...")
        val networkFinding = NetworkAnalyzer().analyze(stringsForAnalysis)

        onProgress?.invoke(0.95f, "正在计算风险评分...")
        val riskScoreResult = RiskScorer().score(
            permissions = permissions,
            matchedTrackers = trackerFindings.map { it.evidence },
            matchedSensitiveApis = sensitiveApiFindings.map { it.evidence },
            extraItems = networkFinding.toRiskItems()
        )

        // v1.2.1/v1.2.2: 构建目标应用权限详情列表（含授权状态） */
        val appPermissions = buildAppPermissionDetails(permissions, packageName)

        onProgress?.invoke(1.0f, "扫描完成")
        return ApkScanResult(
            structureSummary = structureSummary,
            dexStringSummary = dexStringSummary,
            trackerFindings = trackerFindings,
            sensitiveApiFindings = sensitiveApiFindings,
            networkFinding = networkFinding,
            riskScoreResult = riskScoreResult,
            appPermissions = appPermissions
        )
    }

    private fun NetworkFinding.toRiskItems(): List<RiskItem> {
        val items = mutableListOf<RiskItem>()
        suspiciousDomains.forEach { domain ->
            items += RiskItem(
                type = RiskItemType.Network,
                title = "可疑域名：$domain",
                description = "域名命中可疑顶级域名列表",
                score = NetworkRules.suspiciousDomainScore,
                evidence = domain,
                riskLevel = RiskLevel.MEDIUM
            )
        }
        if (domainCount > LARGE_DOMAIN_THRESHOLD) {
            items += RiskItem(
                type = RiskItemType.Network,
                title = "大量硬编码域名",
                description = "检测到较多硬编码域名",
                score = NetworkRules.largeDomainCountScore,
                evidence = domainCount.toString(),
                riskLevel = RiskLevel.LOW
            )
        }
        return items
    }

    // v1.2.1/v1.2.2: 构建目标应用权限详情列表（含授权状态查询）
    private fun buildAppPermissionDetails(
        permissions: List<String>,
        packageName: String? = null
    ): List<AppPermissionDetail> {
        if (permissions.isEmpty()) return emptyList()

        val declaredShortNames = permissions.map { it.substringAfterLast('.') }.toSet()

        // 遍历所有危险权限规则，为声明的权限创建详情
        return PermissionRules.dangerousPermissions.mapNotNull { rule ->
            if (rule.name in declaredShortNames) {
                val fullPermissionName = "android.permission.${rule.name}"
                AppPermissionDetail(
                    name = fullPermissionName,
                    displayName = rule.description,
                    description = rule.description,
                    isDeclared = true,
                    riskLevel = rule.riskLevel,
                    score = rule.score,
                    // v1.2.2: 已知 packageName 时查询授权状态，否则为 null
                    isGranted = packageName?.let { pkg ->
                        PermissionChecker.checkTargetAppPermission(
                            context, pkg, fullPermissionName
                        )
                    }
                )
            } else {
                null
            }
        }
    }

    private companion object {
        const val MAX_SAMPLE_ENTRIES = 20
        const val LARGE_DOMAIN_THRESHOLD = 20
        val DEX_FILE_REGEX = Regex("classes(\\d*)\\.dex")
    }
}
