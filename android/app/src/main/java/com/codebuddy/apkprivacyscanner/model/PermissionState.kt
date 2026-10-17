package com.codebuddy.apkprivacyscanner.model

/**
 * 单个权限的授权状态快照
 * v1.2.0: 权限申请与当前授权状态读取
 */
data class PermissionState(
    /** 权限常量名（如 android.permission.QUERY_ALL_PACKAGES） */
    val permission: String,
    /** 人类可读的名称 */
    val displayName: String,
    /** 为什么需要此权限的简短说明 */
    val description: String,
    /** 当前授权状态：true=已授权，false=未授权 */
    val isGranted: Boolean,
    /** 权限类型：normal=声明即生效, runtime=需弹窗申请, special=需跳转系统设置 */
    val type: PermissionType,
    /** 用户需要采取的操作建议（为空表示无需操作） */
    val actionHint: String? = null
)

enum class PermissionType {
    /** 声明即生效（如 INTERNET、QUERY_ALL_PACKAGES 名义上） */
    NORMAL,
    /** 标准运行时权限，可通过 requestPermissions 申请 */
    RUNTIME,
    /** 特殊权限，必须跳转系统设置页手动开启（如 MANAGE_EXTERNAL_STORAGE） */
    SPECIAL
}
