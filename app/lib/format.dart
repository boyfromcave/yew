// Amount rules on screen (plan §3.7 "What the user sees", W3 brief): YED is dollars with two
// decimals from cents; YEC has eight decimals from zat. Pure functions, no locale package.

const int zatPerYec = 100000000;

/// `$12.34` from cents (negative: `-$12.34`).
String formatYed(int cents) {
  final sign = cents < 0 ? '-' : '';
  final c = cents.abs();
  return '$sign\$${c ~/ 100}.${(c % 100).toString().padLeft(2, '0')}';
}

/// `+$12.34` / `-$12.34` for a history delta.
String formatYedDelta(int cents) => cents > 0 ? '+${formatYed(cents)}' : formatYed(cents);

/// `0.00021000` from zat, eight decimals, no unit.
String formatYec(int zat) {
  final sign = zat < 0 ? '-' : '';
  final z = zat.abs();
  return '$sign${z ~/ zatPerYec}.${(z % zatPerYec).toString().padLeft(8, '0')}';
}

/// `+0.50000000` / `-0.00101000` for a history delta.
String formatYecDelta(int zat) => zat > 0 ? '+${formatYec(zat)}' : formatYec(zat);

/// Cents from a dollar string (`12`, `12.3`, `12.34`, `$12.34`); null when malformed.
int? parseYedCents(String s) {
  final t = s.trim().replaceAll('\$', '').replaceAll(',', '');
  final m = RegExp(r'^(\d+)(?:\.(\d{1,2}))?$').firstMatch(t);
  if (m == null) return null;
  final whole = int.parse(m.group(1)!);
  final frac = (m.group(2) ?? '').padRight(2, '0');
  return whole * 100 + int.parse(frac);
}

/// Zat from a YEC string with up to eight decimals; null when malformed.
int? parseYecZat(String s) {
  final t = s.trim().replaceAll(',', '');
  final m = RegExp(r'^(\d+)(?:\.(\d{1,8}))?$').firstMatch(t);
  if (m == null) return null;
  final whole = int.parse(m.group(1)!);
  final frac = (m.group(2) ?? '').padRight(8, '0');
  return whole * zatPerYec + int.parse(frac);
}

/// The Home price line: `1 YED = $1.00 · mint price 0.52 YEC`, from `pMint` in micro-USD per
/// YEC (YEC per YED = 1e6 / pMint); undefined when the price is.
String formatPriceLine(int? microUsdPerYec) {
  if (microUsdPerYec == null || microUsdPerYec <= 0) return '1 YED = \$1.00 · mint price unavailable';
  final yecPerYed = 1000000 / microUsdPerYec;
  final shown = yecPerYed >= 100
      ? yecPerYed.toStringAsFixed(0)
      : yecPerYed >= 1
      ? yecPerYed.toStringAsFixed(2)
      : yecPerYed.toStringAsFixed(4);
  return '1 YED = \$1.00 · mint price $shown YEC';
}

/// `$0.52 per YEC` from micro-USD.
String formatUsdPerYec(int microUsd) {
  final whole = microUsd ~/ 1000000;
  final cents = (microUsd % 1000000) ~/ 10000;
  return '\$$whole.${cents.toString().padLeft(2, '0')} per YEC';
}

/// `ab12cd34…ef56` for a txid or an address.
String shorten(String s, {int head = 10, int tail = 6}) =>
    s.length <= head + tail + 1 ? s : '${s.substring(0, head)}…${s.substring(s.length - tail)}';
