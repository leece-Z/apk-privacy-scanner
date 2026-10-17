package com.codebuddy.apkprivacyscanner.model

/**
 * 目标应用（被扫描 APK）的权限详情
 *
 * v1.2.1: 在扫描结果中展示被扫描软件的应用权限状态
 */
data class AppPermissionDetail(
    /** 完整权限名，如 "android.permission.CAMERA" */
    val name: String,
    /** 中文显示名（来自 PermissionRules），如 "使用摄像头" */
    val displayName: String,
    /** 中文说明（来自 PermissionRules） */
    val description: String,
    /** 是否在目标 APK 的 AndroidManifest 中声明 */
    val isDeclared: Boolean,
    /** 风险等级（来自 PermissionRules） */
    val riskLevel: RiskLevel,
    /** 风险加分（来自 PermissionRules） */
    val score: Int,
    /** 是否已授权（仅当扫描已安装 App 时可查，否则为 null） */
    val isGranted: Boolean? = null
)
