package com.codebuddy.apkprivacyscanner.model

data class SensitiveApiFinding(
    val pattern: String,
    val displayName: String,
    val category: String,
    val score: Int,
    val evidence: String
)
