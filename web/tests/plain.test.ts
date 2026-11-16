// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// The hosted fast-testnet acceptance run's flaws (beta3): a second tab, an unreachable or fixed server,
// the proving files' source and trust sentence, the network's prefixes, a passkey that never answers,
// the favicon.
import { describe, expect, it } from "vitest";
import { MOCK_SEED, MockCore } from "../src/mock";
import { OnboardingVm } from "../src/vm/onboarding";
import { SettingsVm } from "../src/vm/settings";
import type { Unlock, WalletMeta } from "../src/keystore";
import { PASSKEY_CANCELLED, cancelPasskey, passkeyRequest } from "../src/keystore";
import { OPEN_ELSEWHERE, hostedParamsText, hostedServerText, openElsewhere, unreachableServer } from "../src/plain";
import { trustParagraphs, trustParagraphsFor } from "../src/trust";
import { localize } from "../src/prefixes";
import index from "../index.html?raw";

const HOSTED = "https://fastnet-lightwallet.ycash.team";
const FAILED_FETCH = "network: rpc Unknown error: JS API error: TypeError: Failed to fetch";

describe("a second tab on the same wallet", () => {
  it("the storage refusal reads as one plain sentence, no internal text", () => {
    // verbatim from the acceptance run (s5-params-tabs.log)
    const raw = `store: private wallet store: Opfs { operation: "acquire sync access handle", message: "NoModificationAllowedError: Failed to execute 'createSyncAccessHandle' on 'FileSystemFileHandle': Access Handles cannot be created if there is another open Access Handle or Writable stream associated with the same file.", value: JsValue(NoModificationAllowedError: …) }`;
    expect(openElsewhere(raw)).toBe(true);
    expect(OPEN_ELSEWHERE).toBe("This wallet is open in another tab or window. Close it there, then reload.");
    for (const other of ["store: no wallet on this browser", FAILED_FETCH, "invalid: wrong passphrase or passkey"]) expect(openElsewhere(other)).toBe(false);
  });
});

describe("the server", () => {
  it("a failed fetch is a plain sentence naming the address; any other error stands", () => {
    expect(unreachableServer(FAILED_FETCH, "https://example.com:443")).toBe("Cannot reach the server at https://example.com:443. Check the address.");
    expect(unreachableServer("network: NetworkError when attempting to fetch resource.", "https://x:443")).toContain("Cannot reach");
    expect(unreachableServer("network: the server did not answer", "https://x:443")).toBe("network: the server did not answer");
  });
  it("onboarding: a server that cannot be reached is said plainly, without the transport's prefix", async () => {
    const core = Object.assign(new MockCore(), { latest_height: async () => { throw new Error(FAILED_FETCH); } });
    const vm = new OnboardingVm(core, { saveSeed: async () => {} }, "", "testnet");
    vm.startRestore(); vm.restore(MOCK_SEED, 100);
    await vm.checkServer("https://example.com");
    expect(vm.state.error).toBe("Cannot reach the server at https://example.com:443. Check the address.");
    expect(vm.state.error).not.toMatch(/rpc|JS API|TypeError/);
    expect(vm.state.serverFixed).toBe(false);
  });
  it("a hosted build checks only its own server, whatever is typed", async () => {
    const asked: string[] = [];
    const core = Object.assign(new MockCore(), { latest_height: async (url: string) => { asked.push(url); return 1200; } });
    const vm = new OnboardingVm(core, { saveSeed: async () => {} }, HOSTED, "testnet", true);
    expect(vm.state.serverFixed).toBe(true);
    vm.startRestore(); vm.restore(MOCK_SEED, 100);
    await vm.checkServer("https://example.com");
    expect(asked).toEqual([`${HOSTED}:443`]); expect(vm.state.serverUrl).toBe(`${HOSTED}:443`); expect(vm.state.tip).toBe(1200);
    expect(hostedServerText(HOSTED)).toBe(`This hosted wallet connects only to ${HOSTED}. To use another server, run the wallet yourself.`);
    // without a server to fix, nothing is fixed
    expect(new OnboardingVm(core, { saveSeed: async () => {} }, "", "testnet", true).state.serverFixed).toBe(false);
  });
});

describe("the proving files on a hosted build", () => {
  // the core's texts (core/src/sapling_params.rs fetch_refused_text, http_refused_text)
  const refused = "/sapling-params/sapling-spend.params: this browser could not download it (Failed to fetch). The host is unreachable or does not let web pages download from it (no CORS header). Enter a mirror that does under Source, in Settings.";
  const missing = "/sapling-params/sapling-spend.params: HTTP 404: this wallet's server does not provide this file. Private sending needs the two Sapling proving files (about 52 MB, fetched once). Ask the wallet's operator, or enter a mirror under Source, in Settings.";
  it("never sends the user to a mirror field the page does not have", () => {
    expect(hostedParamsText(refused)).not.toContain("mirror"); expect(hostedParamsText(refused)).toContain("Check your connection, then try again.");
    expect(hostedParamsText(missing)).not.toContain("mirror"); expect(hostedParamsText(missing)).toMatch(/Ask the wallet's operator\.$/);
  });
  it("the settings view-model fetches from the page's own site only, and maps the error", async () => {
    const sources: string[][] = [];
    const core = Object.assign(new MockCore(), { fetch_params: async (_f: unknown, s: string[] = []) => { sources.push(s); throw new Error(`params: ${refused}`); } });
    const vm = new SettingsVm(core, { forget: async () => {} }, "https://mirror.example/p/", "testnet", true);
    expect(vm.state.paramsSource).toBe("");
    await vm.fetchParams();
    expect(sources).toEqual([[]]); expect(vm.state.error).not.toContain("mirror");
    // a self-run build keeps the mirror and the core's advice
    const own = new SettingsVm(core, { forget: async () => {} }, "https://mirror.example/p/", "testnet");
    await own.fetchParams(); expect(sources[1]).toEqual(["https://mirror.example/p/"]); expect(own.state.error).toContain("mirror");
  });
  it("the trust statement says where this build's files come from, never ycashd's source", () => {
    const all = (ps: string[]) => ps.join(" ");
    expect(all(trustParagraphs)).not.toContain("ycashd uses");
    expect(all(trustParagraphsFor(false))).toContain("from this site or a mirror set in Settings, checked in this browser against fingerprints built into YEW");
    expect(all(trustParagraphsFor(true))).toContain("served by this site, downloaded once, checked in this browser against fingerprints built into YEW");
    expect(all(trustParagraphsFor(true))).not.toContain("mirror");
    expect(trustParagraphsFor(true)).toHaveLength(trustParagraphs.length);
  });
});

describe("the network's prefixes", () => {
  it("a testnet page shows testnet prefixes", () => {
    expect(localize("Private YEC (ys1…)", "testnet")).toBe("Private YEC (ytestsapling1…)");
    expect(localize("one of your public addresses (s1… or yb…)", "testnet")).toBe("one of your public addresses (sm… or yt…)");
    expect(localize("sqf… or sqs…", "testnet")).toBe("tqf… or tqs…");
    expect(localize("ybf…/ybs…", "testnet")).toBe("ytf…/yts…");
    expect(localize("s… address", "testnet")).toBe("s… address"); // any transparent address: right on every network
    expect(localize("s1… or yb…", "mainnet")).toBe("s1… or yb…");
    expect(localize("Private YEC (ys1…)", "regtest")).toBe("Private YEC (yregtestsapling1…)");
  });
  it("the trust statement is localized at render: its mainnet ys1… becomes the network's", () => {
    expect(localize(trustParagraphs[0], "testnet")).toContain("(ytestsapling1…)");
  });
});

describe("a passkey that never answers", () => {
  it("Cancel ends the request with a plain message", async () => {
    const p = passkeyRequest<string>(() => new Promise(() => {}));
    cancelPasskey();
    await expect(p).rejects.toThrow(PASSKEY_CANCELLED);
  });
  it("the browser's own cancel, a refusal or no answer read the same; other errors stand", async () => {
    await expect(passkeyRequest(async () => { throw new DOMException("x", "NotAllowedError"); })).rejects.toThrow(PASSKEY_CANCELLED);
    await expect(passkeyRequest(async () => { throw new DOMException("x", "AbortError"); })).rejects.toThrow(PASSKEY_CANCELLED);
    await expect(passkeyRequest(async () => null)).rejects.toThrow(PASSKEY_CANCELLED);
    await expect(passkeyRequest(async () => { throw new Error("passkey: this authenticator has no PRF; use a passphrase"); })).rejects.toThrow("no PRF");
    await expect(passkeyRequest(async () => "ok")).resolves.toBe("ok");
  });
  it("it times out on its own, and the signal is aborted for the browser", async () => {
    let signal: AbortSignal | undefined;
    await expect(passkeyRequest((s) => { signal = s; return new Promise(() => {}); }, 20)).rejects.toThrow(PASSKEY_CANCELLED);
    expect(signal?.aborted).toBe(true);
  });
  it("onboarding: Cancel returns to the choice between passkey and passphrase with the message", async () => {
    let reject: ((e: Error) => void) | undefined; let saved = false;
    const ks = {
      saveSeed: (_s: string, u: Unlock, _m: WalletMeta) => u.method === "prf" ? new Promise<void>((_, rej) => { reject = rej; }) : (saved = true, Promise.resolve()),
      cancelPasskey: () => reject?.(new Error(PASSKEY_CANCELLED)),
    };
    const vm = new OnboardingVm(new MockCore(), ks, "http://localhost:8080");
    vm.startRestore(); vm.restore(MOCK_SEED, 100); await vm.checkServer("http://localhost:8080"); vm.serverDone(); vm.acceptTrust(true); vm.trustDone();
    const done = vm.finish({ method: "prf" });
    await new Promise((r) => setTimeout(r, 0)); await new Promise((r) => setTimeout(r, 0));
    expect(vm.state.passkeyWaiting).toBe(true); expect(vm.state.busy).toBe(true);
    vm.cancelPasskey(); await done;
    expect(vm.state).toMatchObject({ step: "unlock", busy: false, passkeyWaiting: false, error: PASSKEY_CANCELLED });
    await vm.finish({ method: "passphrase", passphrase: "correct horse" });
    expect(vm.state.step).toBe("done"); expect(saved).toBe(true);
  });
});

describe("the favicon", () => {
  it("is a file of the bundle referenced from index.html, never a data: URL or inline", () => {
    const link = /<link rel="icon" type="image\/svg\+xml" href="([^"]+)" \/>/.exec(index);
    expect(link?.[1]).toBe("/src/favicon.svg");
    expect(index).not.toMatch(/href="data:/);
  });
});
