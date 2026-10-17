package com.codebuddy.apkprivacyscanner.rules

enum class SensitiveApiCategory {
    DEVICE_ID,
    SIM,
    LOCATION,
    WIFI,
    ACCOUNT,
    APP_LIST,
    PROCESS,
    TELEPHONY
}

data class SensitiveApiRule(
    val pattern: String,
    val displayName: String,
    val category: SensitiveApiCategory,
    val score: Int = 5
)

object SensitiveApiRules {
    val rules = listOf(
        SensitiveApiRule("getDeviceId", "获取设备IMEI", SensitiveApiCategory.DEVICE_ID),
        SensitiveApiRule("getSubscriberId", "获取IMSI", SensitiveApiCategory.SIM),
        SensitiveApiRule("getLine1Number", "获取本机号码", SensitiveApiCategory.SIM),
        SensitiveApiRule("getSimSerialNumber", "获取SIM卡序列号", SensitiveApiCategory.SIM),
        SensitiveApiRule("getMacAddress", "获取MAC地址", SensitiveApiCategory.WIFI),
        SensitiveApiRule("getSSID", "获取WiFi SSID", SensitiveApiCategory.WIFI),
        SensitiveApiRule("getBSSID", "获取WiFi BSSID", SensitiveApiCategory.WIFI),
        SensitiveApiRule("getInstalledPackages", "获取已安装应用列表", SensitiveApiCategory.APP_LIST),
        SensitiveApiRule("getRunningAppProcesses", "获取运行中进程", SensitiveApiCategory.PROCESS),
        SensitiveApiRule("getAccounts", "获取账户信息", SensitiveApiCategory.ACCOUNT),
        SensitiveApiRule("getLastKnownLocation", "获取位置信息", SensitiveApiCategory.LOCATION),
        SensitiveApiRule("requestLocationUpdates", "请求位置更新", SensitiveApiCategory.LOCATION),
        SensitiveApiRule("getCellLocation", "获取基站位置", SensitiveApiCategory.LOCATION),
        SensitiveApiRule("TelephonyManager", "电话管理（可获取IMEI/IMSI）", SensitiveApiCategory.TELEPHONY),
        SensitiveApiRule("WifiManager.getConnectionInfo", "获取WiFi连接信息", SensitiveApiCategory.WIFI)
    )
}
