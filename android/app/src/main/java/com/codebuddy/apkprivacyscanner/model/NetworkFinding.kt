package com.codebuddy.apkprivacyscanner.model

data class NetworkFinding(
    val urls: List<String>,
    val ips: List<String>,
    val domains: List<String>,
    val suspiciousDomains: List<String>
) {
    val urlCount: Int = urls.size
    val ipCount: Int = ips.size
    val domainCount: Int = domains.size
}
