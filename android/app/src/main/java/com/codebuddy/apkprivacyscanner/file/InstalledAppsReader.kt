package com.codebuddy.apkprivacyscanner.file

import android.content.Context
import android.content.pm.PackageManager
import com.codebuddy.apkprivacyscanner.model.InstalledAppInfo
import com.codebuddy.apkprivacyscanner.permission.PermissionChecker

/**
 * 读取设备上已安装的应用列表
 * v1.1.0: 已安装 App 列表入口
 * v1.2.0: 增加权限预检分支，区分"权限不足"和"读取异常"
 */
fun getInstalledApps(context: Context): List<InstalledAppInfo> {
    val pm = context.packageManager

    return runCatching {
        pm.getInstalledPackages(0)
    }.getOrElse { e1 ->
        // v1.2.0: 区分权限不足 vs 其他错误
        if (!PermissionChecker.checkSelfPermission(context, android.Manifest.permission.QUERY_ALL_PACKAGES)) {
            // 降级：尝试通过 getInstalledApplications 获取
            return runCatching {
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
            }.getOrElse {
                return emptyList()
            }.map { appInfo ->
                val versionName = runCatching {
                    pm.getPackageInfo(appInfo.packageName, 0).versionName
                }.getOrNull()

                InstalledAppInfo(
                    packageName = appInfo.packageName,
                    appName = pm.getApplicationLabel(appInfo).toString(),
                    versionName = versionName,
                    sourceDir = appInfo.sourceDir
                )
            }
        }
        // 非权限原因导致的失败：仍尝试降级路径
        return runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }.getOrElse {
            return emptyList()
        }.map { appInfo ->
            val versionName = runCatching {
                pm.getPackageInfo(appInfo.packageName, 0).versionName
            }.getOrNull()

            InstalledAppInfo(
                packageName = appInfo.packageName,
                appName = pm.getApplicationLabel(appInfo).toString(),
                versionName = versionName,
                sourceDir = appInfo.sourceDir
            )
        }
    }.mapNotNull { pkgInfo ->
        val appInfo = pkgInfo.applicationInfo ?: return@mapNotNull null
        InstalledAppInfo(
            packageName = pkgInfo.packageName,
            appName = pm.getApplicationLabel(appInfo).toString(),
            versionName = pkgInfo.versionName,
            sourceDir = appInfo.sourceDir
        )
    }.sortedBy { it.appName.lowercase() }
}

