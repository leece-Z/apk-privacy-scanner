package com.codebuddy.apkprivacyscanner.scanner

import java.io.InputStream

/**
 * 从 APK 中的 AndroidManifest.xml 提取权限声明
 *
 * Android APK 中的 Manifest 是二进制 XML（AXML），但权限字符串
 * "android.permission.xxx" 在二进制中仍以明文形式存在，
 * 故可用正则直接从字节流中提取，无需完整 XML 解析。
 */
object AndroidManifestParser {

    /** 匹配 android.permission.xxx 权限字符串 */
    private val PERMISSION_REGEX = Regex("android\\.permission\\.([A-Z_]+)")

    /** 权限名字符长度上限（过滤误匹配的长段落）*/
    private const val MAX_PERMISSION_NAME_LENGTH = 80

    /**
     * 从 AndroidManifest.xml 字节流中提取所有声明的权限
     *
     * @param inputStream AndroidManifest.xml 的输入流（APK ZIP entry）
     * @return 完整的权限常量名列表，如 ["android.permission.CAMERA", ...]
     */
    fun extract(inputStream: InputStream): List<String> {
        return inputStream.buffered().use { stream ->
            // 读取为字符串；二进制 Manifest 虽非纯文本，但权限名是ASCII可读的
            val content = String(stream.readBytes(), Charsets.ISO_8859_1)
            extract(content)
        }
    }

    /**
     * 从已读取的 Manifest 文本内容中提取权限
     */
    fun extract(content: String): List<String> {
        return PERMISSION_REGEX
            .findAll(content)
            .map { it.value }
            .filter { it.length <= MAX_PERMISSION_NAME_LENGTH }
            .distinct()
            .sorted()
            .toList()
    }

    /**
     * 将提取出的权限列表与危险权限规则匹配，返回命中列表
     */
    fun matchDangerous(permissions: List<String>): List<String> {
        // 提取权限短名集合（如 "CAMERA", "READ_CONTACTS"）
        val shortNames = permissions
            .map { it.substringAfterLast('.') }
            .toSet()

        // 只返回在 PermissionRules.dangerousByName 中定义的权限
        return permissions.filter { perm ->
            perm.substringAfterLast('.') in
                    com.codebuddy.apkprivacyscanner.rules.PermissionRules.dangerousByName
        }
    }
}
