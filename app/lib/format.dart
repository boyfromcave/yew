// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

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

/// `125 %`, `2.5 %`, `5 %` from basis points (the in-term promise's own form).
String formatBps(int bps) {
  var s = (bps / 100).toStringAsFixed(2);
  while (s.contains('.') && (s.endsWith('0') || s.endsWith('.'))) {
    s = s.substring(0, s.length - 1);
  }
  return '$s %';
}

/// `ab12cd34…ef56` for a txid or an address.
String shorten(String s, {int head = 10, int tail = 6}) =>
    s.length <= head + tail + 1 ? s : '${s.substring(0, head)}…${s.substring(s.length - tail)}';

/// `2026-10-06 14:05` (local time) from Unix seconds: a deadline height as a date (H-9.2). The
/// core estimates the date from the chain's 75-second target spacing; it is not a promise.
String formatDate(int unixSecs) {
  final d = DateTime.fromMillisecondsSinceEpoch(unixSecs * 1000).toLocal();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${d.year}-${two(d.month)}-${two(d.day)} ${two(d.hour)}:${two(d.minute)}';
}

/// `in about 3 days` / `about 5 hours ago` / `in under an hour`, relative to [now] (default:
/// the clock).
String formatRelative(int unixSecs, {DateTime? now}) {
  final at = DateTime.fromMillisecondsSinceEpoch(unixSecs * 1000);
  final d = at.difference(now ?? DateTime.now());
  final future = !d.isNegative;
  final a = d.abs();
  final String span;
  if (a.inDays >= 2) {
    span = '${a.inDays} days';
  } else if (a.inHours >= 2) {
    span = '${a.inHours} hours';
  } else if (a.inMinutes >= 60) {
    span = 'an hour';
  } else {
    return future ? 'in under an hour' : 'under an hour ago';
  }
  return future ? 'in about $span' : 'about $span ago';
}

/// `height 528 · 2026-10-06 14:05 (in about 3 days)`: a deadline as both.
String formatDeadline(int height, int unixSecs, {DateTime? now}) => 'height $height · ${formatDate(unixSecs)} (${formatRelative(unixSecs, now: now)})';
