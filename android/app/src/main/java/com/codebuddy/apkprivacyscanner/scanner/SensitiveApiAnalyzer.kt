package com.codebuddy.apkprivacyscanner.scanner

import com.codebuddy.apkprivacyscanner.model.SensitiveApiFinding
import com.codebuddy.apkprivacyscanner.rules.SensitiveApiRules

class SensitiveApiAnalyzer {
    fun analyze(strings: Collection<String>): List<SensitiveApiFinding> {
        return strings.flatMap { value ->
            SensitiveApiRules.rules.filter { rule ->
                value.contains(rule.pattern, ignoreCase = true)
            }.map { rule ->
                SensitiveApiFinding(
                    pattern = rule.pattern,
                    displayName = rule.displayName,
                    category = rule.category.name,
                    score = rule.score,
                    evidence = value
                )
            }
        }.distinctBy { it.pattern to it.evidence }
    }
}
