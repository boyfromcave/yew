// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .
import { describe, expect, it } from "vitest";
import { TESTNET_DEFAULT_SERVER, defaultServerFor } from "../src/servers";
import html from "../index.html?raw";

describe("default server (beta3 item 17)", () => {
  const https = { protocol: "https:", hostname: "wallet.example", port: "" };
  const http = { protocol: "http:", hostname: "localhost", port: "5173" };
  it("a testnet build defaults to the fast testnet's server, over https", () => {
    expect(TESTNET_DEFAULT_SERVER).toBe("https://fastnet-lightwallet.ycash.team");
    expect(defaultServerFor("testnet", https, false)).toBe(TESTNET_DEFAULT_SERVER);
    expect(defaultServerFor("testnet", http, false)).toBe(TESTNET_DEFAULT_SERVER);
  });
  it("other networks keep the gateway's origin, none in the dev loop, the mock in mock mode", () => {
    expect(defaultServerFor("regtest", https, false)).toBe("https://wallet.example:443");
    expect(defaultServerFor("mainnet", http, false)).toBe("");
    expect(defaultServerFor("testnet", https, true)).toBe("http://localhost:8080");
  });
  it("the page's Content-Security-Policy lets it connect there", () => {
    const csp = /connect-src ([^;]+);/.exec(html)?.[1] ?? "";
    expect(csp.split(" ")).toContain(TESTNET_DEFAULT_SERVER);
  });
});
