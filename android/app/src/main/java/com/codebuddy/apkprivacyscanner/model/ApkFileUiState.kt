package com.codebuddy.apkprivacyscanner.model

import android.net.Uri

data class ApkFileUiState(
    val uri: Uri,
    val displayName: String,
    val sizeBytes: Long?,
    val mimeType: String?,
    val isApk: Boolean
)
