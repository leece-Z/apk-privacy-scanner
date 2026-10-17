package com.codebuddy.apkprivacyscanner.file

import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.provider.OpenableColumns
import com.codebuddy.apkprivacyscanner.model.ApkFileUiState

fun readApkFileState(context: Context, uri: Uri): ApkFileUiState {
    val displayName = queryOpenableColumn(
        context = context,
        uri = uri,
        columnName = OpenableColumns.DISPLAY_NAME
    ) ?: uri.lastPathSegment ?: "未知文件"
    val sizeBytes = queryOpenableColumn(
        context = context,
        uri = uri,
        columnName = OpenableColumns.SIZE
    )?.toLongOrNull()
    val mimeType = context.contentResolver.getType(uri)
    val isApk = displayName.endsWith(".apk", ignoreCase = true) ||
        mimeType == "application/vnd.android.package-archive"

    return ApkFileUiState(
        uri = uri,
        displayName = displayName,
        sizeBytes = sizeBytes,
        mimeType = mimeType,
        isApk = isApk
    )
}

private fun queryOpenableColumn(
    context: Context,
    uri: Uri,
    columnName: String
): String? {
    val cursor: Cursor = context.contentResolver.query(
        uri,
        arrayOf(columnName),
        null,
        null,
        null
    ) ?: return null

    return cursor.use {
        if (!it.moveToFirst()) {
            null
        } else {
            val columnIndex = it.getColumnIndex(columnName)
            if (columnIndex == -1 || it.isNull(columnIndex)) {
                null
            } else {
                it.getString(columnIndex)
            }
        }
    }
}

fun formatFileSize(sizeBytes: Long?): String {
    if (sizeBytes == null || sizeBytes < 0L) {
        return "未知"
    }

    val kb = sizeBytes / 1024.0
    val mb = kb / 1024.0
    val gb = mb / 1024.0

    return when {
        gb >= 1.0 -> "%.2f GB".format(gb)
        mb >= 1.0 -> "%.2f MB".format(mb)
        kb >= 1.0 -> "%.2f KB".format(kb)
        else -> "$sizeBytes B"
    }
}
