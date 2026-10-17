package com.codebuddy.apkprivacyscanner.ui

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.codebuddy.apkprivacyscanner.file.getInstalledApps
import com.codebuddy.apkprivacyscanner.file.readApkFileState
import com.codebuddy.apkprivacyscanner.model.ApkFileUiState
import com.codebuddy.apkprivacyscanner.model.ApkScanResult
import com.codebuddy.apkprivacyscanner.model.InstalledAppInfo
import com.codebuddy.apkprivacyscanner.model.PermissionState
import com.codebuddy.apkprivacyscanner.permission.PermissionChecker
import com.codebuddy.apkprivacyscanner.report.MarkdownReportGenerator
import com.codebuddy.apkprivacyscanner.scanner.ApkStaticScanner
import com.codebuddy.apkprivacyscanner.ui.components.HeaderSection
import com.codebuddy.apkprivacyscanner.ui.components.PrivacyNotice
import com.codebuddy.apkprivacyscanner.ui.components.StatusCards
import com.codebuddy.apkprivacyscanner.ui.screens.HomeContent
import com.codebuddy.apkprivacyscanner.ui.screens.InstalledAppsContent
import com.codebuddy.apkprivacyscanner.ui.screens.ResultContent
import com.codebuddy.apkprivacyscanner.ui.screens.ScanningContent
import com.codebuddy.apkprivacyscanner.ui.theme.ApkPrivacyScannerTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class ScreenState {
    Home,
    Scanning,
    Result,
    InstalledApps  // v1.1.0: 已安装 App 列表入口
}

@Composable
fun ScannerApp() {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val coroutineScope = rememberCoroutineScope()
    var screenState by remember { mutableStateOf(ScreenState.Home) }
    var selectedApk by remember { mutableStateOf<ApkFileUiState?>(null) }
    var scanResult by remember { mutableStateOf<ApkScanResult?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // v1.1.0: 已安装应用列表状态
    var installedApps by remember { mutableStateOf<List<InstalledAppInfo>>(emptyList()) }
    var isInstalledAppsLoading by remember { mutableStateOf(false) }
    var installedAppsPage by remember { mutableStateOf(0) }
    var selectedInstalledApp by remember { mutableStateOf<InstalledAppInfo?>(null) }

    // 扫描进度状态
    var scanProgress by remember { mutableStateOf(0f) }
    var scanProgressMessage by remember { mutableStateOf("") }
    var scanElapsedSeconds by remember { mutableStateOf(0) }

    // v1.2.0: 权限状态管理
    var permissionStates by remember {
        mutableStateOf(PermissionChecker.checkAll(appContext))
    }

    fun refreshPermissionStates() {
        permissionStates = PermissionChecker.checkAll(appContext)
    }

    // v1.2.0: 运行时权限请求 Launcher
    val runtimePermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        refreshPermissionStates()
    }

    // v1.2.0: 跳转系统设置（MANAGE_EXTERNAL_STORAGE 等特殊权限）
    val settingsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        refreshPermissionStates()
    }

    // v1.2.0: 请求指定权限（自动选择正确方式）
    fun requestPermission(permission: String) {
        when (permission) {
            Manifest.permission.MANAGE_EXTERNAL_STORAGE -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val intent = Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:${appContext.packageName}")
                    )
                    settingsLauncher.launch(intent)
                }
            }
            else -> {
                runtimePermissionLauncher.launch(permission)
            }
        }
    }

    val apkPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) {
            errorMessage = "未选择 APK 文件"
            return@rememberLauncherForActivityResult
        }

        runCatching {
            context.contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        }

        selectedApk = readApkFileState(context, uri)
        scanResult = null
        errorMessage = if (selectedApk?.isApk == true) {
            null
        } else {
            "已选择文件，但文件名或 MIME 类型未识别为 APK，请确认文件是否正确。"
        }
        screenState = ScreenState.Home
    }

    // 统一扫描启动（含进度计时器）
    fun startScanning(
        onScan: (onProgress: (Float, String) -> Unit) -> ApkScanResult,
        onFailureHome: Boolean
    ) {
        screenState = ScreenState.Scanning
        scanResult = null
        errorMessage = null
        scanProgress = 0f
        scanProgressMessage = "准备扫描..."
        scanElapsedSeconds = 0

        coroutineScope.launch {
            // 每 0.5s 更新一次计时器
            val tickerJob: Job = launch {
                while (isActive) {
                    delay(500L)
                    scanElapsedSeconds += 1
                }
            }

            val result = runCatching {
                withContext(Dispatchers.IO) {
                    onScan { progress, message ->
                        scanProgress = progress
                        scanProgressMessage = message
                    }
                }
            }

            tickerJob.cancel()

            result
                .onSuccess { summary ->
                    scanProgress = 1f
                    scanProgressMessage = "扫描完成"
                    scanResult = summary
                    errorMessage = null
                    screenState = ScreenState.Result
                }
                .onFailure { error ->
                    scanProgress = 0f
                    scanProgressMessage = ""
                    errorMessage = error.message ?: "扫描失败"
                    scanResult = null
                    screenState = if (onFailureHome) ScreenState.Home else ScreenState.InstalledApps
                }
        }
    }

    fun scanSelectedApk() {
        val apk = selectedApk ?: return
        if (!apk.isApk) {
            errorMessage = "请先选择有效的 APK 文件"
            return
        }

        startScanning(
            onScan = { onProgress ->
                ApkStaticScanner(appContext).scan(apk.uri, onProgress)
            },
            onFailureHome = true
        )
    }

    // v1.1.1: 扫描已安装应用的 APK
    fun scanInstalledApp() {
        val app = selectedInstalledApp ?: return

        selectedApk = ApkFileUiState(
            uri = Uri.EMPTY,
            displayName = "${app.appName}.apk",
            sizeBytes = null,
            mimeType = "application/vnd.android.package-archive",
            isApk = true
        )

        startScanning(
            onScan = { onProgress ->
                // v1.2.2: 传入 packageName 以查询目标 App 的权限授权状态
                ApkStaticScanner(appContext).scanFromPath(
                    apkPath = app.sourceDir,
                    packageName = app.packageName,
                    onProgress = onProgress
                )
            },
            onFailureHome = false
        )
    }

    // v1.1.0/v1.2.0: 加载已安装应用列表（含权限预检）
    fun loadInstalledApps() {
        isInstalledAppsLoading = true
        errorMessage = null
        selectedInstalledApp = null

        // v1.2.0: 权限预检
        refreshPermissionStates()
        if (PermissionChecker.hasMissingCritical(appContext)) {
            installedApps = emptyList()
            isInstalledAppsLoading = false
            errorMessage = "未获取「查询所有应用」权限，无法读取已安装应用列表。请在系统设置中授予后重试。"
            return
        }

        coroutineScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    getInstalledApps(appContext)
                }
            }

            result
                .onSuccess { apps ->
                    installedApps = apps
                    isInstalledAppsLoading = false
                    installedAppsPage = 0
                    if (apps.isEmpty()) {
                        errorMessage = "未能读取到已安装应用。请在系统设置中授予本应用「查询所有应用」权限后重试。"
                    }
                }
                .onFailure { error ->
                    installedApps = emptyList()
                    isInstalledAppsLoading = false
                    errorMessage = error.message ?: "读取已安装应用列表失败"
                }
        }
    }

    fun shareMarkdownReport() {
        val apk = selectedApk ?: return
        val result = scanResult ?: return
        val report = MarkdownReportGenerator().generate(apk = apk, result = result)
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "APK Privacy Scanner 扫描报告")
            putExtra(Intent.EXTRA_TEXT, report)
        }
        context.startActivity(
            Intent.createChooser(sendIntent, "分享 Markdown 报告")
        )
    }

    Scaffold { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            HeaderSection()
            StatusCards(
                selectedApk = selectedApk,
                scanResult = scanResult
            )

            when (screenState) {
                ScreenState.Home -> HomeContent(
                    selectedApk = selectedApk,
                    scanResult = scanResult,
                    errorMessage = errorMessage,
                    permissionStates = permissionStates,
                    onSelectApk = {
                        apkPickerLauncher.launch(
                            arrayOf(
                                "application/vnd.android.package-archive",
                                "application/octet-stream",
                                "application/zip",
                                "application/x-zip-compressed",
                                "*/*"
                            )
                        )
                    },
                    onScanApk = ::scanSelectedApk,
                    onPreviewResult = { screenState = ScreenState.Result },
                    onRequestPermission = ::requestPermission,
                    // v1.1.0: 跳转到已安装应用列表
                    onOpenInstalledApps = {
                        screenState = ScreenState.InstalledApps
                        selectedInstalledApp = null
                        if (installedApps.isEmpty()) {
                            loadInstalledApps()
                        }
                    }
                )

                ScreenState.Scanning -> ScanningContent(
                    selectedApk = selectedApk,
                    progress = scanProgress,
                    progressMessage = scanProgressMessage,
                    elapsedSeconds = scanElapsedSeconds,
                    onBack = { screenState = ScreenState.Home },
                    onShowResult = { screenState = ScreenState.Result }
                )

                ScreenState.Result -> ResultContent(
                    selectedApk = selectedApk,
                    scanResult = scanResult,
                    onShareReport = ::shareMarkdownReport,
                    onBack = { screenState = ScreenState.Home }
                )

                // v1.1.0: 已安装 App 列表页面（分页 + 选中后扫码 + v1.2.0 权限状态）
                ScreenState.InstalledApps -> InstalledAppsContent(
                    apps = installedApps,
                    currentPage = installedAppsPage,
                    selectedApp = selectedInstalledApp,
                    isLoading = isInstalledAppsLoading,
                    errorMessage = errorMessage,
                    permissionStates = permissionStates,
                    onSelectApp = { app ->
                        selectedInstalledApp = app
                    },
                    onScanApp = ::scanInstalledApp,
                    onPageChange = { page -> installedAppsPage = page },
                    onBack = {
                        screenState = ScreenState.Home
                        errorMessage = null
                        selectedInstalledApp = null
                    },
                    onRefresh = ::loadInstalledApps,
                    onRequestPermission = ::requestPermission
                )
            }

            PrivacyNotice()
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun ScannerAppPreview() {
    ApkPrivacyScannerTheme {
        ScannerApp()
    }
}
