import { describe, expect, it } from "vitest";
import { formatPriceLine, formatYec, formatYecDelta, formatYed, formatYedDelta, parseYecZat, parseYedCents, ratioPct, shorten } from "../src/format";

describe("format (translated from app/lib/format.dart)", () => {
  it("YED from cents", () => {
    expect(formatYed("1234")).toBe("$12.34"); expect(formatYed("-5")).toBe("-$0.05"); expect(formatYedDelta("250")).toBe("+$2.50");
  });
  it("YEC from zat", () => {
    expect(formatYec("21000")).toBe("0.00021000"); expect(formatYecDelta("-101000")).toBe("-0.00101000"); expect(formatYec("250000000")).toBe("2.50000000");
  });
  it("parses amounts", () => {
    expect(parseYedCents("$12.3")).toBe(1230n); expect(parseYedCents("12.345")).toBeNull(); expect(parseYecZat("0.5")).toBe(50000000n); expect(parseYecZat("x")).toBeNull();
  });
  it("price line and ratio", () => {
    expect(formatPriceLine("52")).toBe("1 YED = $1.00 · mint price 1.92 YEC"); expect(formatPriceLine("0")).toContain("unavailable");
    expect(ratioPct("200000000", "100", "52")).toBe(104); expect(shorten("a".repeat(40))).toBe("aaaaaaaaaa…aaaaaa");
  });
});
