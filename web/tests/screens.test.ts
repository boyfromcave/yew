// The screens' view-models against MockCore: the flows of app/lib/screens translated, with the
// one rule that matters checked everywhere — nothing is broadcast except through confirm().
import { describe, expect, it } from "vitest";
import { MOCK_SEED, MockCore } from "../src/mock";
import { OnboardingVm } from "../src/vm/onboarding";
import { HomeVm } from "../src/vm/home";
import { SendVm } from "../src/vm/send";
import { ReceiveVm } from "../src/vm/receive";
import { HistoryVm } from "../src/vm/history";
import { SettingsVm } from "../src/vm/settings";
import { YellowbackVm } from "../src/vm/yellowback";
import type { Unlock, WalletMeta } from "../src/keystore";

class FakeKeystore {
  saved: { seed: string; unlock: Unlock; meta: WalletMeta } | null = null; forgotten = false;
  async saveSeed(seed: string, unlock: Unlock, meta: WalletMeta) { this.saved = { seed, unlock, meta }; }
  async forget() { this.forgotten = true; }
}
async function openWallet(core = new MockCore()) { await core.open(MOCK_SEED, 0, "http://localhost:8080"); return core; }

describe("onboarding", () => {
  it("creates: seed shown once, confirm step, server, trust, unlock → encrypted at rest, opened", async () => {
    const core = new MockCore(), ks = new FakeKeystore();
    const vm = new OnboardingVm(core, ks, "http://localhost:8080");
    await vm.create();
    expect(vm.state.step).toBe("seed"); expect(vm.state.seedWords.split(" ")).toHaveLength(12); expect(vm.state.birthday).toBe(1200);
    vm.written(); expect(vm.state.step).toBe("confirm");
    expect(vm.confirmWords(["wrong", "wrong", "wrong"])).toBe(false); expect(vm.state.error).toContain("not the words");
    const words = vm.state.seedWords.split(" ");
    expect(vm.confirmWords(vm.state.confirmIndexes.map((i) => words[i]))).toBe(true); expect(vm.state.step).toBe("server");
    await vm.checkServer("not a url"); expect(vm.state.error).toContain("invalid");
    await vm.checkServer("http://localhost:8080"); expect(vm.state.tip).toBe(1200);
    vm.serverDone(); expect(vm.state.step).toBe("trust");
    vm.trustDone(); expect(vm.state.step).toBe("trust"); vm.acceptTrust(true); vm.trustDone(); expect(vm.state.step).toBe("unlock");
    await vm.finish({ method: "passphrase", passphrase: "correct horse" });
    expect(vm.state.step).toBe("done"); expect(vm.state.seedWords).toBe(""); // the seed does not linger in the view-model
    expect(ks.saved?.seed).toBe(MOCK_SEED); expect(ks.saved?.meta.serverUrl).toBe("http://localhost:8080");
    expect((await core.status()).open).toBe(true);
  });
  it("restores: 12 or 24 words and a birthday", async () => {
    const vm = new OnboardingVm(new MockCore(), new FakeKeystore());
    vm.startRestore(); vm.restore("one two three", 5); expect(vm.state.error).toContain("12 or 24");
    vm.restore(MOCK_SEED, 100); expect(vm.state.step).toBe("server"); expect(vm.state.birthday).toBe(100);
  });
  it("shows the core's error text verbatim", async () => {
    const vm = new OnboardingVm(new MockCore({ failNetwork: true }), new FakeKeystore());
    await vm.checkServer("http://localhost:8080"); expect(vm.state.error).toBe("network: the server did not answer");
  });
});

describe("home", () => {
  it("balances and the progress callback", async () => {
    const core = await openWallet(); const vm = new HomeVm(core);
    await vm.attach(); await vm.load();
    expect(vm.state.balances?.yedCents).toBe("12500"); expect(vm.state.network).toBe("regtest");
    await vm.sync(); expect(vm.state.progress?.pct).toBe(100); expect(vm.state.syncing).toBe(false);
  });
});

describe("send", () => {
  it("YED: preview carries the node's verdict; confirm is the only broadcast", async () => {
    const core = await openWallet(); const vm = new SendVm(core, "yed");
    await vm.setTo("ye1Recipient000000000000000000000000"); vm.state.amount = "25.00";
    await vm.preview(); expect(vm.state.yed?.verdict).toContain("ok"); expect(core.broadcasts).toHaveLength(0);
    await vm.confirm(); expect(vm.state.txid).toHaveLength(64); expect(core.broadcasts).toHaveLength(1);
  });
  it("YED to a private address is refused before the core is asked", async () => {
    const vm = new SendVm(await openWallet(), "yed");
    await vm.setTo("ys1qprivaterecipient00000000000000000000"); vm.state.amount = "1";
    await vm.preview(); expect(vm.state.error).toContain("public address"); expect(vm.state.yed).toBeNull();
  });
  it("YEC: a memo only for ys1…, the reveal warning when private pays a public address", async () => {
    const core = await openWallet(); const vm = new SendVm(core, "yec");
    await vm.setTo("s1PublicRecipient0000000000000000000"); vm.state.amount = "0.5"; vm.state.memo = "hi";
    await vm.preview(); expect(vm.state.error).toContain("private (ys1…) recipient");
    vm.state.memo = ""; await vm.preview(); expect(vm.state.errorKind).toBe("params"); // privacy first: the proving files are needed
    await core.fetch_params(() => {}); await vm.preview(); expect(vm.state.yec?.revealsShielded).toBe(true); expect(vm.state.yec?.funding).toBe("private");
    await vm.setTo("ys1qprivaterecipient00000000000000000000"); vm.state.memo = "thanks"; vm.reset();
    await vm.preview(); expect(vm.state.yec?.revealsShielded).toBe(false); expect(vm.state.error).toBe("");
  });
  it("a gate refusal is shown with its kind", async () => {
    const vm = new SendVm(await openWallet(), "yed"); vm.state.yed = { previewId: "stale", inputs: 1, feeZat: "1", verdict: "" };
    await vm.confirm(); expect(vm.state.errorKind).toBe("gate"); expect(vm.state.txid).toBe("");
  });
  it("move: shield needs the params", async () => {
    const core = await openWallet(); const vm = new SendVm(core, "yec");
    await vm.movePreview("to_private", "1"); expect(vm.state.errorKind).toBe("params");
    await core.fetch_params(() => {}); await vm.movePreview("to_private", "1"); expect(vm.state.move?.fee).toBe("10000");
  });
});

describe("receive / history / settings", () => {
  it("three address kinds and a fresh private one", async () => {
    const vm = new ReceiveVm(await openWallet());
    await vm.show("shielded"); expect(vm.state.address.startsWith("ys1")).toBe(true);
    await vm.show("yed"); expect(vm.state.address.startsWith("ye")).toBe(true);
    await vm.show("transparent"); expect(vm.state.address.startsWith("s1")).toBe(true);
    const a = vm.state.address; await vm.fresh(); expect(vm.state.kind).toBe("shielded"); expect(vm.state.address).not.toBe(a);
  });
  it("history pages and memos", async () => {
    const vm = new HistoryVm(await openWallet()); await vm.load(0);
    expect(vm.state.rows).toHaveLength(4); expect(vm.state.rows[0].memo).toBe("thanks for lunch");
    await vm.more(); expect(vm.state.more).toBe(false);
  });
  it("params fetch with progress, export WIF, forget", async () => {
    const core = await openWallet(); const ks = new FakeKeystore(); const vm = new SettingsVm(core, ks);
    await vm.loadParams(); expect(vm.state.params?.present).toBe(false);
    const seen: number[] = []; vm.subscribe(() => { if (vm.state.fetching) seen.push(vm.state.fetching.bytesDone); });
    await vm.fetchParams(); expect(seen.length).toBeGreaterThan(0); expect(vm.state.params?.present).toBe(true); expect(vm.state.fetching).toBeNull();
    await vm.exportWif("nope"); expect(vm.state.error).toContain("invalid"); await vm.exportWif("s1MockTransparentAddress000000000000"); expect(vm.state.wif.startsWith("c")).toBe(true);
    await vm.forget(); expect(ks.forgotten).toBe(true); expect((await core.status()).open).toBe(false);
  });
});

describe("yellowback", () => {
  it("mint: estimate → start → confirm the carrier → finish opens a vault", async () => {
    const core = await openWallet(); const vm = new YellowbackVm(core);
    await vm.load(); expect(vm.state.vaults).toHaveLength(1);
    await vm.estimate("abc", 100); expect(vm.state.error).toContain("dollars");
    await vm.estimate("100", 100); expect(vm.state.estimate?.termClass).toBe("A"); expect(vm.state.estimate?.collateralZat).toBe("57692307692");
    await vm.mintStart(); expect(vm.state.mint?.mintId).toBeGreaterThan(0); expect(core.broadcasts).toHaveLength(0);
    await vm.mintConfirm(); expect(core.broadcasts).toHaveLength(1); expect(vm.state.mintStatus?.state).toBe("DONE"); expect(vm.state.mintStatus?.inProgress).toBe(false);
    await vm.load(); expect(vm.state.vaults).toHaveLength(2);
  });
  it("redeem: preview shows the burn and the return; confirm closes the vault", async () => {
    const core = await openWallet(); const vm = new YellowbackVm(core); await vm.load();
    const v = vm.state.vaults[0]; await vm.redeemPreview(v.vaultTxid);
    expect(vm.state.redeem?.burnCents).toBe(v.cents); expect(vm.state.redeem?.returnedZat).toBe(v.collateralZat);
    await vm.confirm(); expect(vm.state.txid).toHaveLength(64); expect(vm.state.vaults[0].open).toBe(false);
  });
  it("claimable: list, preview, confirm", async () => {
    const core = await openWallet(); const vm = new YellowbackVm(core);
    await vm.loadClaimable(); expect(vm.state.claimable).toHaveLength(1);
    await vm.claimPreview(vm.state.claimable[0].vaultTxid); expect(vm.state.claim?.claimantZat).toBe("119900000");
    await vm.confirm(); expect(core.broadcasts).toHaveLength(1);
  });
  it("busy: a second call while one is in progress rejects", async () => {
    const core = new MockCore({ delayMs: 20 }); await core.open(MOCK_SEED, 0, "http://x");
    const a = core.vaults(); await expect(core.balances()).rejects.toThrow("busy"); await a;
  });
});

describe("serialized core", () => {
  it("queues concurrent calls instead of surfacing busy", async () => {
    const { serialized } = await import("../src/core");
    const core = serialized(new MockCore({ delayMs: 20 })); await core.open(MOCK_SEED, 0, "http://x");
    const [a, b] = await Promise.all([core.vaults(), core.balances()]); expect(a).toHaveLength(1); expect(b.yedCents).toBe("12500");
  });
});
