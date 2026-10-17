package com.codebuddy.apkprivacyscanner.model

/**
 * 已安装应用信息模型
 * v1.1.0: 已安装 App 列表入口
 */
data class InstalledAppInfo(
    val packageName: String,
    val appName: String,
    val versionName: String?,
    /** APK 文件路径（sourceDir），用于 v1.1.1 直接扫描 */
    val sourceDir: String
)
