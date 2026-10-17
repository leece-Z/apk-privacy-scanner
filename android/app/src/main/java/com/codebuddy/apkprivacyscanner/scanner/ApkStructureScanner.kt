package com.codebuddy.apkprivacyscanner.scanner

import android.content.Context
import android.net.Uri
import com.codebuddy.apkprivacyscanner.model.ApkStructureSummary
import java.util.zip.ZipInputStream

class ApkStructureScanner(private val context: Context) {
    fun scan(uri: Uri): ApkStructureSummary {
        val dexFiles = mutableListOf<String>()
        val metaInfFiles = mutableListOf<String>()
        val nativeLibraries = mutableListOf<String>()
        val assetEntries = mutableListOf<String>()
        val resourceEntries = mutableListOf<String>()
        val sampleEntries = mutableListOf<String>()
        var totalEntries = 0
        var hasManifest = false

        val inputStream = context.contentResolver.openInputStream(uri)
            ?: error("无法打开用户选择的 APK 文件")

        inputStream.use { rawStream ->
            ZipInputStream(rawStream.buffered()).use { zipStream ->
                while (true) {
                    val entry = zipStream.nextEntry ?: break
                    val name = entry.name
                    totalEntries += 1

                    if (sampleEntries.size < MAX_SAMPLE_ENTRIES) {
                        sampleEntries += name
                    }

                    when {
                        name == "AndroidManifest.xml" -> hasManifest = true
                        name.matches(DEX_FILE_REGEX) -> dexFiles += name
                        name.startsWith("META-INF/") -> metaInfFiles += name
                        name.startsWith("lib/") && name.endsWith(".so") -> nativeLibraries += name
                        name.startsWith("assets/") -> assetEntries += name
                        name.startsWith("res/") -> resourceEntries += name
                    }

                    zipStream.closeEntry()
                }
            }
        }

        return ApkStructureSummary(
            totalEntries = totalEntries,
            hasManifest = hasManifest,
            dexFiles = dexFiles,
            metaInfFiles = metaInfFiles,
            nativeLibraries = nativeLibraries,
            assetEntries = assetEntries,
            resourceEntries = resourceEntries,
            sampleEntries = sampleEntries
        )
    }

    private companion object {
        const val MAX_SAMPLE_ENTRIES = 20
        val DEX_FILE_REGEX = Regex("classes(\\d*)\\.dex")
    }
}
