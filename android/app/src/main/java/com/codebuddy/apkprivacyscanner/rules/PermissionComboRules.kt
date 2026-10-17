package com.codebuddy.apkprivacyscanner.rules

import com.codebuddy.apkprivacyscanner.model.RiskLevel

data class PermissionComboRule(
    val name: String,
    val permissions: List<String>,
    val description: String,
    val riskLevel: RiskLevel,
    val score: Int = 30
)

object PermissionComboRules {
    val combos = listOf(
        PermissionComboRule(
            name = "间谍软件特征",
            permissions = listOf("RECORD_AUDIO", "CAMERA"),
            description = "同时申请录音+摄像头权限，可秘密录制音视频",
            riskLevel = RiskLevel.HIGH
        ),
        PermissionComboRule(
            name = "短信劫持特征",
            permissions = listOf("RECEIVE_SMS", "SEND_SMS", "READ_SMS"),
            description = "可拦截/读取/发送短信，可能窃取验证码",
            riskLevel = RiskLevel.HIGH
        ),
        PermissionComboRule(
            name = "通话监控特征",
            permissions = listOf("READ_CALL_LOG", "RECORD_AUDIO"),
            description = "可读取通话记录+录音，可能窃听通话",
            riskLevel = RiskLevel.HIGH
        ),
        PermissionComboRule(
            name = "完全监控特征",
            permissions = listOf("ACCESS_FINE_LOCATION", "READ_CONTACTS", "CAMERA"),
            description = "定位+联系人+摄像头，全方位隐私窃取",
            riskLevel = RiskLevel.HIGH
        ),
        PermissionComboRule(
            name = "安装应用风险",
            permissions = listOf("REQUEST_INSTALL_PACKAGES", "WRITE_EXTERNAL_STORAGE"),
            description = "可从外部存储安装应用（可能静默安装）",
            riskLevel = RiskLevel.MEDIUM
        ),
        PermissionComboRule(
            name = "无障碍监控",
            permissions = listOf("BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"),
            description = "无障碍服务+悬浮窗，可监控所有操作",
            riskLevel = RiskLevel.MEDIUM
        )
    )
}
