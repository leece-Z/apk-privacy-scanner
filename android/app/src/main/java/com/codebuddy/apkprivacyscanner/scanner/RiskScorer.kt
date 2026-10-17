package com.codebuddy.apkprivacyscanner.scanner

import com.codebuddy.apkprivacyscanner.model.RiskItem
import com.codebuddy.apkprivacyscanner.model.RiskItemType
import com.codebuddy.apkprivacyscanner.model.RiskLevel
import com.codebuddy.apkprivacyscanner.model.RiskScoreResult
import com.codebuddy.apkprivacyscanner.rules.PermissionComboRules
import com.codebuddy.apkprivacyscanner.rules.PermissionRules
import com.codebuddy.apkprivacyscanner.rules.RiskScoreRules
import com.codebuddy.apkprivacyscanner.rules.SensitiveApiRules
import com.codebuddy.apkprivacyscanner.rules.TrackerRules

class RiskScorer {
    fun score(
        permissions: Collection<String> = emptyList(),
        matchedTrackers: Collection<String> = emptyList(),
        matchedSensitiveApis: Collection<String> = emptyList(),
        extraItems: List<RiskItem> = emptyList()
    ): RiskScoreResult {
        val items = mutableListOf<RiskItem>()
        items += scorePermissions(permissions)
        items += scorePermissionCombos(permissions)
        items += scoreTrackers(matchedTrackers)
        items += scoreSensitiveApis(matchedSensitiveApis)
        items += extraItems

        val totalScore = items.sumOf { it.score }
        val level = levelForScore(totalScore)

        return RiskScoreResult(
            score = totalScore,
            level = level,
            advice = level.advice,
            items = items
        )
    }

    private fun scorePermissions(permissions: Collection<String>): List<RiskItem> {
        val permissionNames = permissions.map { it.substringAfterLast('.') }.toSet()
        return permissionNames.mapNotNull { name ->
            PermissionRules.dangerousByName[name]?.let { rule ->
                RiskItem(
                    type = RiskItemType.Permission,
                    title = "危险权限：${rule.name}",
                    description = rule.description,
                    score = rule.score,
                    evidence = rule.name,
                    riskLevel = rule.riskLevel
                )
            }
        }
    }

    private fun scorePermissionCombos(permissions: Collection<String>): List<RiskItem> {
        val permissionNames = permissions.map { it.substringAfterLast('.') }.toSet()
        return PermissionComboRules.combos.mapNotNull { combo ->
            val matched = combo.permissions.filter { it in permissionNames }
            if (matched.size >= 2) {
                RiskItem(
                    type = RiskItemType.PermissionCombo,
                    title = combo.name,
                    description = combo.description,
                    score = combo.score,
                    evidence = matched.joinToString(),
                    riskLevel = combo.riskLevel
                )
            } else {
                null
            }
        }
    }

    private fun scoreTrackers(matchedTrackers: Collection<String>): List<RiskItem> {
        return matchedTrackers.flatMap { value ->
            TrackerRules.trackers.filter { rule ->
                value.contains(rule.pattern, ignoreCase = true)
            }.map { rule ->
                RiskItem(
                    type = RiskItemType.Tracker,
                    title = rule.displayName,
                    description = "匹配第三方 SDK / Tracker：${rule.pattern}",
                    score = rule.score,
                    evidence = value,
                    riskLevel = rule.riskLevel
                )
            }
        }.distinctBy { it.title to it.evidence }
    }

    private fun scoreSensitiveApis(matchedSensitiveApis: Collection<String>): List<RiskItem> {
        return matchedSensitiveApis.flatMap { value ->
            SensitiveApiRules.rules.filter { rule ->
                value.contains(rule.pattern, ignoreCase = true)
            }.map { rule ->
                RiskItem(
                    type = RiskItemType.SensitiveApi,
                    title = rule.displayName,
                    description = "匹配敏感 API：${rule.pattern}",
                    score = rule.score,
                    evidence = value,
                    riskLevel = RiskLevel.MEDIUM
                )
            }
        }.distinctBy { it.title to it.evidence }
    }

    private fun levelForScore(score: Int): RiskLevel {
        return when {
            score <= 0 -> RiskLevel.NONE
            score <= RiskScoreRules.lowRiskMax -> RiskLevel.LOW
            score <= RiskScoreRules.mediumRiskMax -> RiskLevel.MEDIUM
            score <= RiskScoreRules.elevatedRiskMax -> RiskLevel.ELEVATED
            else -> RiskLevel.HIGH
        }
    }
}
