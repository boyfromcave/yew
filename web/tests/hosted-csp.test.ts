// The hosted build's <meta> policy (hosted-csp.ts) and the testnet banner (src/prefixes.ts).
import { describe, expect, it } from "vitest";
import { hostedCsp } from "../hosted-csp";
import { networkBanner } from "../src/prefixes";
import index from "../index.html?raw";

const policy = (html: string) => /http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(html)![1];

describe("hosted build", () => {
  it("leaves index.html alone without VITE_DEFAULT_SERVER", () => {
    expect(hostedCsp(index, undefined)).toBe(index);
    expect(hostedCsp(index, "")).toBe(index);
  });
  it("connect-src becomes exactly 'self' and the server's origin, frame-ancestors (ignored in a <meta>) goes; nothing else changes", () => {
    const out = hostedCsp(index, "https://fastnet-lightwallet.ycash.team");
    const directives = policy(out).split("; ");
    expect(directives).toContain("connect-src 'self' https://fastnet-lightwallet.ycash.team");
    expect(policy(out)).not.toContain("download.z.cash");
    const rest = (d: string) => !d.startsWith("connect-src") && !d.startsWith("frame-ancestors");
    expect(policy(index)).toContain("frame-ancestors 'none'");
    expect(policy(out)).not.toContain("frame-ancestors");
    expect(directives.filter(rest)).toEqual(policy(index).split("; ").filter(rest));
    expect(out.replace(policy(out), "")).toBe(index.replace(policy(index), ""));
  });
  it("keeps a port, and refuses anything that is not a bare https origin", () => {
    expect(policy(hostedCsp(index, "https://lw.example.org:9443"))).toContain("connect-src 'self' https://lw.example.org:9443;");
    for (const bad of ["http://lw.example.org", "https://lw.example.org/path", "https://u:p@lw.example.org", "https://lw.example.org/?q=1", "lw.example.org"]) {
      expect(() => hostedCsp(index, bad)).toThrow();
    }
    expect(() => hostedCsp("<html></html>", "https://lw.example.org")).toThrow(/connect-src/);
  });
  it("a testnet build says its coins have no value; mainnet and regtest builds carry no banner", () => {
    expect(networkBanner("testnet")).toBe("Fast testnet: coins here have no value");
    expect(networkBanner("mainnet")).toBeNull();
    expect(networkBanner("regtest")).toBeNull();
  });
});
