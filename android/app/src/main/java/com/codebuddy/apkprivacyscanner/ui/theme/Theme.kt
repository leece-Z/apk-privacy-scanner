package com.codebuddy.apkprivacyscanner.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val LightColors = lightColorScheme(
    primary = AppPrimary,
    secondary = AppSecondary,
    background = AppBackground,
    surface = AppSurface,
    onPrimary = AppOnPrimary,
    onSecondary = AppOnSecondary,
    onBackground = AppOnBackground,
    onSurface = AppOnSurface,
    onSurfaceVariant = AppOnSurfaceVariant
)

private val DarkColors = darkColorScheme(
    primary = AppPrimaryDark,
    secondary = AppSecondaryDark,
    background = AppBackgroundDark,
    surface = AppSurfaceDark,
    onPrimary = AppOnPrimary,
    onSecondary = AppOnSecondary,
    onBackground = AppOnBackgroundDark,
    onSurface = AppOnSurfaceDark,
    onSurfaceVariant = AppOnSurfaceVariantDark
)

@Composable
fun ApkPrivacyScannerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColors else LightColors

    MaterialTheme(
        colorScheme = colorScheme,
        typography = AppTypography,
        content = content
    )
}
