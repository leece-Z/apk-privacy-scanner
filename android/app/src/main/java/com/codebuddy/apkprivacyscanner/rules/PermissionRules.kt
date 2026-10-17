package com.codebuddy.apkprivacyscanner.rules

import com.codebuddy.apkprivacyscanner.model.RiskLevel

data class PermissionRule(
    val name: String,
    val description: String,
    val riskLevel: RiskLevel = RiskLevel.HIGH,
    val score: Int = 10
)

object PermissionRules {
    val dangerousPermissions = listOf(
        PermissionRule("READ_CALENDAR", "读取日历"),
        PermissionRule("WRITE_CALENDAR", "修改日历"),
        PermissionRule("READ_CALL_LOG", "读取通话记录"),
        PermissionRule("WRITE_CALL_LOG", "修改通话记录"),
        PermissionRule("PROCESS_OUTGOING_CALLS", "拦截呼出电话"),
        PermissionRule("CAMERA", "使用摄像头"),
        PermissionRule("READ_CONTACTS", "读取联系人"),
        PermissionRule("WRITE_CONTACTS", "修改联系人"),
        PermissionRule("GET_ACCOUNTS", "获取账户列表"),
        PermissionRule("ACCESS_FINE_LOCATION", "精确定位（GPS）"),
        PermissionRule("ACCESS_COARSE_LOCATION", "粗略定位（基站/WiFi）"),
        PermissionRule("ACCESS_BACKGROUND_LOCATION", "后台定位"),
        PermissionRule("RECORD_AUDIO", "录音"),
        PermissionRule("READ_PHONE_STATE", "读取手机状态（IMEI/IMSI等）"),
        PermissionRule("READ_PHONE_NUMBERS", "读取本机号码"),
        PermissionRule("CALL_PHONE", "拨打电话"),
        PermissionRule("ANSWER_PHONE_CALLS", "接听电话"),
        PermissionRule("ADD_VOICEMAIL", "添加语音邮件"),
        PermissionRule("USE_SIP", "使用SIP通话"),
        PermissionRule("BODY_SENSORS", "身体传感器"),
        PermissionRule("SEND_SMS", "发送短信"),
        PermissionRule("RECEIVE_SMS", "接收短信"),
        PermissionRule("READ_SMS", "读取短信"),
        PermissionRule("RECEIVE_WAP_PUSH", "接收WAP推送"),
        PermissionRule("RECEIVE_MMS", "接收彩信"),
        PermissionRule("READ_EXTERNAL_STORAGE", "读取外部存储"),
        PermissionRule("WRITE_EXTERNAL_STORAGE", "写入外部存储"),
        PermissionRule("READ_MEDIA_IMAGES", "读取图片"),
        PermissionRule("READ_MEDIA_VIDEO", "读取视频"),
        PermissionRule("READ_MEDIA_AUDIO", "读取音频"),
        PermissionRule("MANAGE_EXTERNAL_STORAGE", "管理所有文件"),
        PermissionRule("SYSTEM_ALERT_WINDOW", "悬浮窗"),
        PermissionRule("WRITE_SETTINGS", "修改系统设置"),
        PermissionRule("BIND_ACCESSIBILITY_SERVICE", "无障碍服务"),
        PermissionRule("REQUEST_INSTALL_PACKAGES", "安装应用"),
        PermissionRule("PACKAGE_USAGE_STATS", "读取应用使用记录"),
        PermissionRule("QUERY_ALL_PACKAGES", "查询所有已安装应用")
    )

    val dangerousByName = dangerousPermissions.associateBy { it.name }
}
