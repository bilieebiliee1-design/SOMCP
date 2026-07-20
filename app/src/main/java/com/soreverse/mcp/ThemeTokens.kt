package com.soreverse.mcp

import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

internal object AppPalette {
    val blue = Color(0xFF0A84FF)
    val teal = Color(0xFF64D2FF)
    val indigo = Color(0xFF5E5CE6)
    val purple = Color(0xFFBF5AF2)
    val green = Color(0xFF30D158)
    val orange = Color(0xFFFF9F0A)
    val red = Color(0xFFFF453A)
    val mono = Color(0xFF8E8E93)

    fun accent(name: String, dark: Boolean): Color = when (name) {
        "teal" -> if (dark) Color(0xFF64D2FF) else Color(0xFF0891B2)
        "indigo" -> if (dark) Color(0xFF5E5CE6) else Color(0xFF4F46E5)
        "purple" -> if (dark) Color(0xFFBF5AF2) else Color(0xFF9333EA)
        "green" -> if (dark) Color(0xFF30D158) else Color(0xFF16A34A)
        "orange" -> if (dark) Color(0xFFFF9F0A) else Color(0xFFEA580C)
        "red" -> if (dark) Color(0xFFFF453A) else Color(0xFFDC2626)
        "mono" -> if (dark) Color(0xFFD1D1D6) else Color(0xFF3A3A3C)
        else -> if (dark) Color(0xFF0A84FF) else Color(0xFF007AFF)
    }
}

internal data class UiMetrics(
    val pagePad: androidx.compose.ui.unit.Dp,
    val sectionGap: androidx.compose.ui.unit.Dp,
    val rowPadV: androidx.compose.ui.unit.Dp,
    val cardRadius: androidx.compose.ui.unit.Dp,
    val controlRadius: androidx.compose.ui.unit.Dp,
)

internal fun uiMetrics(density: String, corner: String): UiMetrics {
    val pagePad = when (density) {
        "compact" -> 12.dp
        "spacious" -> 20.dp
        else -> 16.dp
    }
    val sectionGap = when (density) {
        "compact" -> 12.dp
        "spacious" -> 22.dp
        else -> 16.dp
    }
    val rowPadV = when (density) {
        "compact" -> 8.dp
        "spacious" -> 14.dp
        else -> 11.dp
    }
    val cardRadius = when (corner) {
        "small" -> 10.dp
        "large" -> 18.dp
        "xlarge" -> 24.dp
        else -> 14.dp
    }
    val controlRadius = when (corner) {
        "small" -> 8.dp
        "large" -> 14.dp
        "xlarge" -> 18.dp
        else -> 11.dp
    }
    return UiMetrics(pagePad, sectionGap, rowPadV, cardRadius, controlRadius)
}

internal fun textScaleFactor(textScale: String): Float = when (textScale) {
    "large" -> 1.08f
    "xlarge" -> 1.16f
    else -> 1f
}

internal fun TextStyle.scaledBy(scale: Float): TextStyle = copy(
    fontSize = (fontSize.value * scale).sp,
    lineHeight = (lineHeight.value * scale).sp,
)

internal fun scaledTypography(scale: Float): Typography {
    val base = Typography()
    return Typography(
        displayLarge = base.displayLarge.scaledBy(scale),
        displayMedium = base.displayMedium.scaledBy(scale),
        displaySmall = base.displaySmall.scaledBy(scale),
        headlineLarge = base.headlineLarge.scaledBy(scale),
        headlineMedium = base.headlineMedium.scaledBy(scale),
        headlineSmall = base.headlineSmall.scaledBy(scale),
        titleLarge = base.titleLarge.scaledBy(scale),
        titleMedium = base.titleMedium.scaledBy(scale),
        titleSmall = base.titleSmall.scaledBy(scale),
        bodyLarge = base.bodyLarge.scaledBy(scale),
        bodyMedium = base.bodyMedium.scaledBy(scale),
        bodySmall = base.bodySmall.scaledBy(scale),
        labelLarge = base.labelLarge.scaledBy(scale),
        labelMedium = base.labelMedium.scaledBy(scale),
        labelSmall = base.labelSmall.scaledBy(scale),
    )
}

internal fun appLightColors(accent: Color, highContrast: Boolean) = lightColorScheme(
    primary = accent,
    onPrimary = Color.White,
    primaryContainer = accent.copy(alpha = 0.12f),
    onPrimaryContainer = Color(0xFF0B1B33),
    secondary = Color(0xFFE8E8ED),
    onSecondary = Color(0xFF1C1C1E),
    secondaryContainer = Color(0xFFF2F2F7),
    onSecondaryContainer = Color(0xFF1C1C1E),
    tertiary = AppPalette.indigo,
    onTertiary = Color.White,
    background = Color(0xFFF2F2F7),
    onBackground = if (highContrast) Color(0xFF000000) else Color(0xFF1C1C1E),
    surface = Color(0xFFFFFFFF),
    onSurface = if (highContrast) Color(0xFF000000) else Color(0xFF1C1C1E),
    surfaceVariant = Color(0xFFE5E5EA),
    onSurfaceVariant = if (highContrast) Color(0xFF3A3A3C) else Color(0xFF636366),
    surfaceContainer = Color(0xFFFFFFFF),
    surfaceContainerHigh = Color(0xFFF7F7FA),
    surfaceContainerHighest = Color(0xFFE5E5EA),
    outline = if (highContrast) Color(0xFF8E8E93) else Color(0xFFC6C6C8),
    outlineVariant = Color(0xFFE5E5EA),
    error = Color(0xFFFF3B30),
    onError = Color.White,
    errorContainer = Color(0xFFFFECEA),
    onErrorContainer = Color(0xFF93000A),
)

internal fun appDarkColors(accent: Color, pureBlack: Boolean, highContrast: Boolean) = darkColorScheme(
    primary = accent,
    onPrimary = Color.White,
    primaryContainer = accent.copy(alpha = 0.18f),
    onPrimaryContainer = Color(0xFFE8F1FF),
    secondary = Color(0xFF2C2C2E),
    onSecondary = Color(0xFFF5F5F7),
    secondaryContainer = Color(0xFF3A3A3C),
    onSecondaryContainer = Color(0xFFF5F5F7),
    tertiary = Color(0xFF5E5CE6),
    onTertiary = Color.White,
    background = if (pureBlack) Color(0xFF000000) else Color(0xFF0B0B0D),
    onBackground = if (highContrast) Color(0xFFFFFFFF) else Color(0xFFF5F5F7),
    surface = if (pureBlack) Color(0xFF1C1C1E) else Color(0xFF161618),
    onSurface = if (highContrast) Color(0xFFFFFFFF) else Color(0xFFF5F5F7),
    surfaceVariant = Color(0xFF2C2C2E),
    onSurfaceVariant = if (highContrast) Color(0xFFD1D1D6) else Color(0xFF8E8E93),
    surfaceContainer = if (pureBlack) Color(0xFF1C1C1E) else Color(0xFF161618),
    surfaceContainerHigh = Color(0xFF2C2C2E),
    surfaceContainerHighest = Color(0xFF3A3A3C),
    outline = if (highContrast) Color(0xFFAEAEB2) else Color(0xFF3A3A3C),
    outlineVariant = Color(0xFF2C2C2E),
    error = Color(0xFFFF453A),
    onError = Color.White,
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

internal fun statusSuccess(dark: Boolean = false): Color = if (dark) Color(0xFF30D158) else Color(0xFF34C759)
internal fun statusError(dark: Boolean = false): Color = if (dark) Color(0xFFFF453A) else Color(0xFFFF3B30)
internal fun statusWarning(dark: Boolean = false): Color = if (dark) Color(0xFFFF9F0A) else Color(0xFFFF9500)

internal object AppleColors {
    val systemBlue = AppPalette.blue
    val systemBlueDark = AppPalette.blue
    val systemGreen = AppPalette.green
    val systemGreenDark = AppPalette.green
    val systemRed = AppPalette.red
    val systemRedDark = AppPalette.red
    val systemOrange = AppPalette.orange
    val systemOrangeDark = AppPalette.orange
    val systemIndigo = AppPalette.indigo
    val systemTeal = AppPalette.teal
    val systemPurple = AppPalette.purple
    object Light {
        val background = Color(0xFFF2F2F7)
        val secondaryBackground = Color(0xFFFFFFFF)
        val tertiaryBackground = Color(0xFFF2F2F7)
        val groupedBackground = Color(0xFFF2F2F7)
        val card = Color(0xFFFFFFFF)
        val fill = Color(0xFFE5E5EA)
        val fillSecondary = Color(0xFFF2F2F7)
        val separator = Color(0xFFC6C6C8)
        val label = Color(0xFF1C1C1E)
        val secondaryLabel = Color(0xFF636366)
        val tertiaryLabel = Color(0xFF8E8E93)
        val primary = AppPalette.blue
        val onPrimary = Color.White
        val success = AppPalette.green
        val error = AppPalette.red
        val warning = AppPalette.orange
        val glass = Color(0xFFFFFFFF)
        val glassStrong = Color(0xFFFFFFFF)
        val glassStroke = Color(0x33C6C6C8)
    }
    object Dark {
        val background = Color(0xFF000000)
        val secondaryBackground = Color(0xFF1C1C1E)
        val tertiaryBackground = Color(0xFF2C2C2E)
        val groupedBackground = Color(0xFF000000)
        val card = Color(0xFF1C1C1E)
        val fill = Color(0xFF3A3A3C)
        val fillSecondary = Color(0xFF2C2C2E)
        val separator = Color(0xFF38383A)
        val label = Color(0xFFF5F5F7)
        val secondaryLabel = Color(0xFF8E8E93)
        val tertiaryLabel = Color(0xFF636366)
        val primary = AppPalette.blue
        val onPrimary = Color.White
        val success = AppPalette.green
        val error = AppPalette.red
        val warning = AppPalette.orange
        val glass = Color(0xFF1C1C1E)
        val glassStrong = Color(0xFF1C1C1E)
        val glassStroke = Color(0x33FFFFFF)
    }
}

internal fun appleLightColors() = appLightColors(AppPalette.blue, false)
internal fun appleDarkColors() = appDarkColors(AppPalette.blue, true, false)
internal fun appleSuccess(dark: Boolean = false): Color = statusSuccess(dark)
internal fun appleError(dark: Boolean = false): Color = statusError(dark)
internal fun appleWarning(dark: Boolean = false): Color = statusWarning(dark)

internal val LocalUiMetrics = staticCompositionLocalOf {
    uiMetrics("comfortable", "medium")
}
internal val LocalReduceMotion = staticCompositionLocalOf { false }
