// The one design system of YEW (plan D-W-9, §5.2): Material 3, one accent for YED and one for
// YEC, large tabular numerals, cards, light and dark from day one, restrained motion.
import 'package:flutter/cupertino.dart' show CupertinoPageTransitionsBuilder;
import 'package:flutter/material.dart';

/// The YED accent (the Yellowback's yellow).
const Color yedAccent = Color(0xFFE6A800);

/// The YEC accent (a cool teal, so the two assets never read alike).
const Color yecAccent = Color(0xFF1D9A8A);

/// The one motion duration used where something confirms it happened (balance change,
/// send complete). Everything else is instant.
const Duration confirmMotion = Duration(milliseconds: 350);

/// The theme extension the screens read the two accents from.
@immutable
class YewColors extends ThemeExtension<YewColors> {
  const YewColors({
    required this.yed,
    required this.yec,
    required this.pending,
    required this.danger,
  });

  final Color yed;
  final Color yec;
  final Color pending;
  final Color danger;

  @override
  YewColors copyWith({Color? yed, Color? yec, Color? pending, Color? danger}) => YewColors(
    yed: yed ?? this.yed,
    yec: yec ?? this.yec,
    pending: pending ?? this.pending,
    danger: danger ?? this.danger,
  );

  @override
  YewColors lerp(YewColors? other, double t) {
    if (other == null) return this;
    return YewColors(
      yed: Color.lerp(yed, other.yed, t)!,
      yec: Color.lerp(yec, other.yec, t)!,
      pending: Color.lerp(pending, other.pending, t)!,
      danger: Color.lerp(danger, other.danger, t)!,
    );
  }
}

/// `Theme.of(context).extension<YewColors>()` with a fallback.
YewColors yewColors(BuildContext context) =>
    Theme.of(context).extension<YewColors>() ??
    const YewColors(yed: yedAccent, yec: yecAccent, pending: Colors.grey, danger: Colors.red);

/// Numerals: large, tabular (so a changing balance does not jitter).
const List<FontFeature> tabular = [FontFeature.tabularFigures()];

ThemeData buildTheme(Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final scheme = ColorScheme.fromSeed(
    seedColor: yedAccent,
    brightness: brightness,
    secondary: yecAccent,
    surface: dark ? const Color(0xFF121212) : const Color(0xFFFAFAF7),
  );
  final base = ThemeData(colorScheme: scheme, useMaterial3: true, brightness: brightness);
  final text = base.textTheme;
  return base.copyWith(
    scaffoldBackgroundColor: scheme.surface,
    textTheme: text.copyWith(
      displayLarge: text.displayLarge?.copyWith(fontWeight: FontWeight.w600, fontFeatures: tabular),
      displayMedium: text.displayMedium?.copyWith(fontWeight: FontWeight.w600, fontFeatures: tabular),
      headlineMedium: text.headlineMedium?.copyWith(fontWeight: FontWeight.w600, fontFeatures: tabular),
      titleLarge: text.titleLarge?.copyWith(fontWeight: FontWeight.w600),
      bodyMedium: text.bodyMedium?.copyWith(fontFeatures: tabular),
    ),
    cardTheme: CardThemeData(
      elevation: 0,
      color: dark ? const Color(0xFF1C1C1E) : Colors.white,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      margin: EdgeInsets.zero,
    ),
    appBarTheme: AppBarTheme(
      backgroundColor: scheme.surface,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      centerTitle: false,
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        minimumSize: const Size.fromHeight(52),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        minimumSize: const Size.fromHeight(52),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: BorderSide.none),
    ),
    snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
    pageTransitionsTheme: const PageTransitionsTheme(
      builders: {
        TargetPlatform.android: FadeForwardsPageTransitionsBuilder(),
        TargetPlatform.iOS: CupertinoPageTransitionsBuilder(),
      },
    ),
    extensions: [
      YewColors(
        yed: dark ? const Color(0xFFFFC53D) : yedAccent,
        yec: dark ? const Color(0xFF3FC1AF) : yecAccent,
        pending: dark ? const Color(0xFF9E9E9E) : const Color(0xFF757575),
        danger: scheme.error,
      ),
    ],
  );
}
