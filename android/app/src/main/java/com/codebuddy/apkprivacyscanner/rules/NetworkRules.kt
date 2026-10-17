package com.codebuddy.apkprivacyscanner.rules

object NetworkRules {
    val urlPattern = Regex("https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+")
    val ipPattern = Regex("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b")
    val suspiciousTlds = listOf(
        ".xyz",
        ".top",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".pw",
        ".cc",
        ".club"
    )

    const val suspiciousDomainScore = 15
    const val largeDomainCountScore = 5
}
