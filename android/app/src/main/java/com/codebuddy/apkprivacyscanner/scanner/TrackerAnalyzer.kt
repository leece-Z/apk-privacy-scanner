package com.codebuddy.apkprivacyscanner.scanner

import com.codebuddy.apkprivacyscanner.model.TrackerFinding
import com.codebuddy.apkprivacyscanner.rules.TrackerRules

class TrackerAnalyzer {
    fun analyze(strings: Collection<String>): List<TrackerFinding> {
        return strings.flatMap { value ->
            TrackerRules.trackers.filter { rule ->
                value.contains(rule.pattern, ignoreCase = true)
            }.map { rule ->
                TrackerFinding(
                    pattern = rule.pattern,
                    displayName = rule.displayName,
                    category = rule.category.name,
                    riskLevel = rule.riskLevel,
                    score = rule.score,
                    evidence = value
                )
            }
        }.distinctBy { it.pattern to it.evidence }
    }
}
