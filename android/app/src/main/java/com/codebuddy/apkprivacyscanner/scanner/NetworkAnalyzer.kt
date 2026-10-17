package com.codebuddy.apkprivacyscanner.scanner

import com.codebuddy.apkprivacyscanner.model.NetworkFinding
import com.codebuddy.apkprivacyscanner.rules.NetworkRules

class NetworkAnalyzer {
    fun analyze(strings: Collection<String>): NetworkFinding {
        val urls = linkedSetOf<String>()
        val ips = linkedSetOf<String>()
        val domains = linkedSetOf<String>()

        strings.forEach { value ->
            NetworkRules.urlPattern.findAll(value).forEach { match ->
                val url = match.value.take(MAX_URL_LENGTH)
                urls += url
                extractDomain(url)?.let { domain -> domains += domain }
            }

            NetworkRules.ipPattern.findAll(value).forEach { match ->
                val ip = match.value
                if (isValidPublicLikeIp(ip)) {
                    ips += ip
                }
            }
        }

        val suspiciousDomains = domains.filter { domain ->
            NetworkRules.suspiciousTlds.any { tld -> domain.endsWith(tld, ignoreCase = true) }
        }

        return NetworkFinding(
            urls = urls.toList(),
            ips = ips.toList(),
            domains = domains.toList(),
            suspiciousDomains = suspiciousDomains
        )
    }

    private fun extractDomain(url: String): String? {
        val withoutScheme = url.substringAfter("://", missingDelimiterValue = "")
        if (withoutScheme.isBlank()) {
            return null
        }
        return withoutScheme
            .substringBefore('/')
            .substringBefore(':')
            .takeIf { it.isNotBlank() }
    }

    private fun isValidPublicLikeIp(ip: String): Boolean {
        val parts = ip.split('.')
        if (parts.size != 4) {
            return false
        }
        if (!parts.all { part -> part.toIntOrNull()?.let { it in 0..255 } == true }) {
            return false
        }
        return ip !in ignoredIps
    }

    private companion object {
        const val MAX_URL_LENGTH = 200
        val ignoredIps = setOf("0.0.0.0", "255.255.255.255", "127.0.0.1")
    }
}
