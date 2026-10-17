package com.codebuddy.apkprivacyscanner.permission

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.core.content.ContextCompat
import com.codebuddy.apkprivacyscanner.model.PermissionState
import com.codebuddy.apkprivacyscanner.model.PermissionType

/**
 * 权限状态检查工具
 * v1.2.0: 权限申请与当前授权状态读取
 */
object PermissionChecker {

    /** 获取所有关注权限的当前授权状态 */
    fun checkAll(context: Context): List<PermissionState> {
        return buildList {
            // QUERY_ALL_PACKAGES：声明即生效的普通权限，但有些 ROM 需要额外开启
            add(
                PermissionState(
                    permission = Manifest.permission.QUERY_ALL_PACKAGES,
                    displayName = "查询所有应用",
                    description = "用于读取已安装应用列表，以便选择扫描目标",
                    isGranted = isQueryAllPackagesEffective(context),
                    type = PermissionType.NORMAL,
                    actionHint = if (!isQueryAllPackagesEffective(context)) {
                        "请在系统设置 → 应用 → APK隐私扫描 → 权限中开启"
                    } else null
                )
            )

            // READ_EXTERNAL_STORAGE：Android ≤12 运行时权限，Android 13+ 废弃
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) {
                add(
                    PermissionState(
                        permission = Manifest.permission.READ_EXTERNAL_STORAGE,
                        displayName = "读取外部存储",
                        description = "用于读取用户选择的 APK 文件",
                        isGranted = checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE),
                        type = PermissionType.RUNTIME,
                        actionHint = if (!checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE)) {
                            "点击授权"
                        } else null
                    )
                )
            } else {
                // Android 13+：通过 SAF 文件选择器读取，不需要存储权限
                add(
                    PermissionState(
                        permission = "android.permission.READ_MEDIA_IMAGES",
                        displayName = "读取媒体文件",
                        description = "Android 13+ 使用系统文件选择器，无需额外权限",
                        isGranted = true,
                        type = PermissionType.NORMAL,
                        actionHint = null
                    )
                )
            }

            // MANAGE_EXTERNAL_STORAGE：特殊权限，需跳系统设置（API 30+）
            add(
                PermissionState(
                    permission = Manifest.permission.MANAGE_EXTERNAL_STORAGE,
                    displayName = "管理所有文件",
                    description = "全文件访问权限（用于扫描任意位置的 APK 文件）",
                    isGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        Environment.isExternalStorageManager()
                    } else {
                        true // API < 30 默认有此权限
                    },
                    type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        PermissionType.SPECIAL
                    } else {
                        PermissionType.NORMAL
                    },
                    actionHint = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
                        !Environment.isExternalStorageManager()
                    ) {
                        "前往系统设置"
                    } else null
                )
            )
        }
    }

    /** 检查标准运行时权限是否已授权 */
    fun checkSelfPermission(context: Context, permission: String): Boolean {
        return ContextCompat.checkSelfPermission(context, permission) ==
                PackageManager.PERMISSION_GRANTED
    }

    /**
     * 检查 QUERY_ALL_PACKAGES 是否实际生效
     * 策略：尝试获取一个系统已知包的信息作为探针，若成功则权限有效
     */
    private fun isQueryAllPackagesEffective(context: Context): Boolean {
        return runCatching {
            val pm = context.packageManager
            // 尝试查询系统设置包作为探针
            pm.getPackageInfo("com.android.settings", 0)
            true
        }.getOrDefault(
            // 降级：尝试 getInstalledApplications
            runCatching {
                context.packageManager.getInstalledApplications(0)
                true
            }.getOrDefault(false)
        )
    }

    /** 是否有未授权的关键权限 */
    fun hasMissingCritical(context: Context): Boolean {
        return !isQueryAllPackagesEffective(context)
    }

    /**
     * 检查目标应用的某个权限是否已授权
     * v1.2.2: 支持查询目标 app 的权限授权状态
     *
     * @param context 上下文
     * @param packageName 目标应用包名
     * @param permission 完整权限名，如 "android.permission.CAMERA"
     * @return true 表示目标应用已获得该权限
     */
    fun checkTargetAppPermission(
        context: Context,
        packageName: String,
        permission: String
    ): Boolean {
        return runCatching {
            context.packageManager.checkPermission(permission, packageName) ==
                    PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
    }
}
