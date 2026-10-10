// Amount rules on screen, translated from app/lib/format.dart: YED is dollars with two decimals
// from cents; YEC has eight decimals from zat. Amounts arrive as strings (u64); BigInt here.
export const ZAT_PER_YEC = 100000000n;

const big = (v: string | bigint | number): bigint => (typeof v === "bigint" ? v : BigInt(v || 0));

/** `$12.34` from cents (negative: `-$12.34`). */
export function formatYed(cents: string | bigint | number): string {
  const c = big(cents); const sign = c < 0n ? "-" : ""; const a = c < 0n ? -c : c;
  return `${sign}$${a / 100n}.${(a % 100n).toString().padStart(2, "0")}`;
}
export function formatYedDelta(cents: string | bigint | number): string {
  return big(cents) > 0n ? `+${formatYed(cents)}` : formatYed(cents);
}
/** `0.00021000` from zat, eight decimals, no unit. */
export function formatYec(zat: string | bigint | number): string {
  const z = big(zat); const sign = z < 0n ? "-" : ""; const a = z < 0n ? -z : z;
  return `${sign}${a / ZAT_PER_YEC}.${(a % ZAT_PER_YEC).toString().padStart(8, "0")}`;
}
export function formatYecDelta(zat: string | bigint | number): string {
  return big(zat) > 0n ? `+${formatYec(zat)}` : formatYec(zat);
}
/** Cents from a dollar string (`12`, `12.3`, `12.34`, `$12.34`); null when malformed. */
export function parseYedCents(s: string): bigint | null {
  const m = /^(\d+)(?:\.(\d{1,2}))?$/.exec(s.trim().replace(/\$/g, "").replace(/,/g, ""));
  if (!m) return null;
  return BigInt(m[1]) * 100n + BigInt((m[2] ?? "").padEnd(2, "0"));
}
/** Zat from a YEC string with up to eight decimals; null when malformed. */
export function parseYecZat(s: string): bigint | null {
  const m = /^(\d+)(?:\.(\d{1,8}))?$/.exec(s.trim().replace(/,/g, ""));
  if (!m) return null;
  return BigInt(m[1]) * ZAT_PER_YEC + BigInt((m[2] ?? "").padEnd(8, "0"));
}
/** The Home price line from the price in cents per YEC (YEC per YED = 100 / price). */
export function formatPriceLine(priceCents: string | bigint | number): string {
  const p = Number(big(priceCents));
  if (!(p > 0)) return "1 YED = $1.00 · mint price unavailable";
  const y = 100 / p;
  const shown = y >= 100 ? y.toFixed(0) : y >= 1 ? y.toFixed(2) : y.toFixed(4);
  return `1 YED = $1.00 · mint price ${shown} YEC`;
}
/** `ab12cd34…ef56` for a txid or an address. */
export function shorten(s: string, head = 10, tail = 6): string {
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}
/** Collateral ratio in percent from collateral zat and debt cents at a price in cents/YEC. */
export function ratioPct(collateralZat: string | bigint, cents: string | bigint, priceCents: string | bigint): number | null {
  const c = big(cents); const p = big(priceCents);
  if (c <= 0n || p <= 0n) return null;
  return Number((big(collateralZat) * p * 100n) / (ZAT_PER_YEC * c));
}
