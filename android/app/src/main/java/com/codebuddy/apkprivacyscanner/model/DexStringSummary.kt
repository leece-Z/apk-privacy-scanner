package com.codebuddy.apkprivacyscanner.model

data class DexStringSummary(
    val dexFilesScanned: List<String>,
    val totalStrings: Int,
    val stringSamples: List<String>,
    val urlLikeSamples: List<String>,
    val apiLikeSamples: List<String>,
    val packageLikeSamples: List<String>
) {
    val dexFileCount: Int = dexFilesScanned.size
}
