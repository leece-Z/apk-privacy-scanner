package com.codebuddy.apkprivacyscanner.model

data class ApkStructureSummary(
    val totalEntries: Int,
    val hasManifest: Boolean,
    val dexFiles: List<String>,
    val metaInfFiles: List<String>,
    val nativeLibraries: List<String>,
    val assetEntries: List<String>,
    val resourceEntries: List<String>,
    val sampleEntries: List<String>,
    /** v1.2.1: 从 AndroidManifest.xml 中提取的权限声明 */
    val permissions: List<String> = emptyList()
) {
    val dexCount: Int = dexFiles.size
    val metaInfCount: Int = metaInfFiles.size
    val nativeLibraryCount: Int = nativeLibraries.size
    val assetCount: Int = assetEntries.size
    val resourceCount: Int = resourceEntries.size
}
