// @vitest-environment jsdom
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// Receive (beta3, the hosted acceptance run): a tab change showed the previous tab's address for 3 to
// 15 s, Copy and QR live. Each test here is one half of the fix.
import { describe, expect, it } from "vitest";
import { MOCK_SEED, MockCore } from "../src/mock";
import type { AddressKind } from "../src/core";
import { ReceiveVm } from "../src/vm/receive";
import { renderReceive } from "../src/screens/receive";
import { addressMatchesKind, receiveKindOf } from "../src/prefixes";
import { SendVm } from "../src/vm/send";
import { YellowbackVm } from "../src/vm/yellowback";
import { renderVault } from "../src/screens/yellowback";
import { renderMove, renderSend } from "../src/screens/send";
import { SettingsVm } from "../src/vm/settings";

async function openWallet() { const c = new MockCore(); await c.open(MOCK_SEED, 0, "http://localhost:8080", "regtest"); return c; }

/** MockCore whose receive_address answers only when the test releases that kind (a core busy with a
 *  sync), and counts the calls. */
class SlowCore extends MockCore {
  calls = 0;
  private gates = new Map<AddressKind, () => void>();
  override async receive_address(kind: AddressKind) {
    this.calls++;
    if (this.gated) await new Promise<void>((r) => this.gates.set(kind, r));
    return super.receive_address(kind);
  }
  gated = true;
  release(kind: AddressKind) { this.gates.get(kind)?.(); }
}
async function slowWallet(gated = true) { const c = new SlowCore(); await c.open(MOCK_SEED, 0, "http://localhost:8080", "regtest"); c.gated = gated; return c; }
const tick = () => new Promise((r) => setTimeout(r, 0));
const regtest = () => "regtest" as const;

describe("receive: the address shown is always the current tab's", () => {
  it("a slow answer for the tab left behind is not shown under the next tab", async () => {
    const core = await slowWallet(); const vm = new ReceiveVm(core, regtest);
    const first = vm.show("shielded");
    expect(vm.state.loading).toBe(true); expect(vm.shown).toBe("");
    const second = vm.show("transparent");                     // the user switches while the first is on its way
    core.release("shielded"); await first;
    expect(vm.state.kind).toBe("transparent"); expect(vm.state.address).toBe(""); expect(vm.shown).toBe(""); expect(vm.state.loading).toBe(true);
    core.release("transparent"); await second;
    expect(vm.shown.startsWith("sm")).toBe(true);
    await vm.show("shielded"); expect(vm.shown.startsWith("yregtestsapling1")).toBe(true); // the late answer was kept for its own tab
  });

  it("Copy is off while loading: no address, no QR; a tab change clears the old one at once", async () => {
    const core = await slowWallet(); const vm = new ReceiveVm(core, regtest);
    const root = document.createElement("div"); const unsub = renderReceive(root, vm);
    const copyBtn = () => [...root.querySelectorAll("button")].find((b) => b.textContent === "Copy") as HTMLButtonElement;
    expect(copyBtn().disabled).toBe(true); expect(root.querySelector("code.addr")).toBeNull(); expect(root.querySelector(".qr")).toBeNull();
    expect(root.querySelector("[data-receive=loading]")).not.toBeNull();
    core.release("shielded"); await tick();
    expect(copyBtn().disabled).toBe(false); expect(root.querySelector("code.addr")?.textContent?.startsWith("yregtestsapling1")).toBe(true);
    expect(root.querySelector(".qr")).not.toBeNull();
    ([...root.querySelectorAll(".seg button")].find((b) => b.textContent === "Public (ECC)") as HTMLButtonElement).click();
    expect(copyBtn().disabled).toBe(true); expect(root.querySelector("code.addr")).toBeNull(); expect(root.querySelector(".qr")).toBeNull();
    core.release("transparent"); await tick();
    expect(root.querySelector("code.addr")?.textContent?.startsWith("sm")).toBe(true);
    unsub();
  });

  it("an address whose prefix is not the tab's is refused, not shown", async () => {
    const core = await slowWallet(false);
    core.receive_address = async () => "yregtestsapling1qmockshieldedaddress0000000000000000000000000000000000000000qq";
    const vm = new ReceiveVm(core, regtest);
    await vm.show("transparent");
    expect(vm.shown).toBe(""); expect(vm.state.address).toBe(""); expect(vm.state.error).toContain("not of this type"); expect(vm.state.error).toContain("sm…");
    const root = document.createElement("div"); const unsub = renderReceive(root, vm);
    await tick(); expect(root.querySelector("code.addr")).toBeNull(); expect(root.querySelector(".qr")).toBeNull(); unsub();
  });

  it("prime at unlock: every tab answers from the cache at once; after a sync only the rotating kinds are asked again", async () => {
    const core = await slowWallet(false); const vm = new ReceiveVm(core, regtest);
    await vm.prime(); expect(core.calls).toBe(5);
    for (const k of ["shielded", "transparent", "pq_falcon", "pq_slh", "yed"] as const) {
      const p = vm.show(k); expect(vm.state.loading).toBe(false); expect(addressMatchesKind(k, vm.shown, "regtest")).toBe(true); await p;
    }
    expect(core.calls).toBe(5);
    await vm.refreshRotating(); expect(core.calls).toBe(9);    // transparent, both post-quantum, YED; never the private one
    vm.clear(); expect(vm.state.address).toBe("");            // a closed wallet's addresses go with it
    void vm.show("yed"); expect(vm.state.loading).toBe(true); expect(core.calls).toBe(10);
  });

  it("an answer for a wallet closed meanwhile never lands", async () => {
    const core = await slowWallet(); const vm = new ReceiveVm(core, regtest);
    const p = vm.show("shielded"); vm.clear(); core.release("shielded"); await p;
    expect(vm.state.address).toBe(""); expect(vm.shown).toBe("");
  });

  it("prefixes: the longest match decides, so a testnet private address is never YED's yt…", () => {
    expect(receiveKindOf("ytestsapling1qqqq", "testnet")).toBe("shielded"); expect(receiveKindOf("ytAbc", "testnet")).toBe("yed");
    expect(receiveKindOf("ytfAbc", "testnet")).toBe("yed"); expect(receiveKindOf("smAbc", "testnet")).toBe("transparent");
    expect(receiveKindOf("tqfAbc", "testnet")).toBe("pq_falcon"); expect(receiveKindOf("tqsAbc", "testnet")).toBe("pq_slh");
    expect(receiveKindOf("s1Abc", "mainnet")).toBe("transparent"); expect(receiveKindOf("sqfAbc", "mainnet")).toBe("pq_falcon");
    expect(addressMatchesKind("transparent", "ys1qqq", "mainnet")).toBe(false); expect(addressMatchesKind("yed", "ytestsapling1qq", "testnet")).toBe(false);
    expect(receiveKindOf("zs1abc", "mainnet")).toBeNull();
  });
});

describe("the same race elsewhere: an answer for a selection the user left is never shown", () => {
  it("Send: a preview asked for before the asset changed is dropped; the card shows the preview's own recipient and amount", async () => {
    const core = new MockCore({ delayMs: 5 }); await core.open(MOCK_SEED, 0, "http://localhost:8080", "regtest");
    const vm = new SendVm(core, "yed");
    await vm.setTo("ye1Recipient000000000000000000000000"); vm.state.amount = "25.00";
    const p = vm.preview(); vm.setAsset("yec"); await p;
    expect(vm.state.yed).toBeNull(); expect(vm.previewId).toBe("");
    vm.setAsset("yed"); await vm.preview();
    expect(vm.state.yed?.to).toBe("ye1Recipient000000000000000000000000"); expect(vm.state.yed?.cents).toBe("2500");
  });
  it("Vault: a redeem preview of another vault is not shown on this vault's screen", async () => {
    const core = await openWallet(); const vm = new YellowbackVm(core); await vm.load();
    const mine = vm.state.vaults[0].vaultTxid;
    const other = "ab".repeat(32); vm.set({ vaults: [...vm.state.vaults, { ...vm.state.vaults[0], vaultTxid: other }] });
    await vm.redeemPreview(mine); expect(vm.redeemFor(mine)).not.toBeNull(); expect(vm.redeemFor(other)).toBeNull();
    const root = document.createElement("div"); const unsub = renderVault(root, vm, other);
    expect(root.textContent).toContain("Preview the redeem"); expect(root.textContent).not.toContain("Slide to redeem");
    // and one landing late, after the user moved to the other vault's screen, is not drawn there either
    await vm.redeemPreview(mine); expect(root.textContent).not.toContain("Slide to redeem"); unsub();
    const own = document.createElement("div"); const unsub2 = renderVault(own, vm, mine);
    expect(own.textContent).toContain("Slide to redeem"); unsub2();                  // on its own vault it is
  });
});

async function delayed(ms = 5) { const c = new MockCore({ delayMs: ms }); await c.open(MOCK_SEED, 0, "http://localhost:8080", "regtest"); return c; }
const YED_TO = "ye1Recipient000000000000000000000000";
const inputs = (root: HTMLElement) => [...root.querySelectorAll("input[type=text], textarea")] as HTMLInputElement[];
const button = (root: HTMLElement, text: string) => [...root.querySelectorAll("button")].find((b) => b.textContent === text) as HTMLButtonElement | undefined;

describe("review of the race fix: forms, confirm, stale errors, the exported key", () => {
  it("Send: the inputs are disabled while a preview is open and enabled again on Change, on an error and after a send", async () => {
    const core = await openWallet(); const vm = new SendVm(core, "yed");
    const root = document.createElement("div"); const unsub = renderSend(root, vm);
    await vm.setTo(YED_TO); vm.state.amount = "25.00"; vm.set({});
    expect(inputs(root).every((i) => !i.disabled)).toBe(true);
    await vm.preview(); expect(inputs(root).length).toBeGreaterThan(0); expect(inputs(root).every((i) => i.disabled)).toBe(true);
    button(root, "Change")!.click(); expect(inputs(root).every((i) => !i.disabled)).toBe(true);
    vm.state.amount = "abc"; await vm.preview(); expect(vm.state.error).toContain("dollars"); expect(inputs(root).every((i) => !i.disabled)).toBe(true);
    vm.state.amount = "25.00"; await vm.preview(); await vm.confirm(); expect(vm.state.txid).not.toBe("");
    vm.reset(); expect(inputs(root).every((i) => !i.disabled)).toBe(true);
    unsub();
  });

  it("Send: the card shows the preview's own recipient and amount, and confirm sends the previewed id, whatever the form says now", async () => {
    const core = await openWallet(); const vm = new SendVm(core, "yed");
    const root = document.createElement("div"); const unsub = renderSend(root, vm);
    await vm.setTo(YED_TO); vm.state.amount = "25.00"; await vm.preview();
    const id = vm.previewId; expect(id).not.toBe("");
    vm.state.to = "ye1Other00000000000000000000000000000"; vm.state.amount = "99.00"; vm.set({}); // the form changed underneath
    expect(root.textContent).toContain(YED_TO); expect(root.textContent).toContain("$25.00");
    expect(root.textContent).not.toContain("ye1Other"); expect(root.textContent).not.toContain("$99.00");
    await vm.confirm(); expect(core.broadcasts.at(-1)).toBe(id);
    unsub();
  });

  it("Send: the public-to-private note follows the preview's recipient, not the field", async () => {
    const core = await openWallet(); const vm = new SendVm(core, "yec");
    const z = "yregtestsapling1qmockrecipient000000000000000000000000000000000000000000qq";
    await vm.setTo(z); vm.state.amount = "0.5"; await vm.preview();
    expect(vm.state.yecToPrivate).toBe(true);
    vm.set({ toKind: "p2pkh" }); expect(vm.state.yecToPrivate).toBe(true);
  });

  it("Move: a preview for the direction left behind is dropped, and the amount is frozen while one shows", async () => {
    const core = await delayed(); const vm = new SendVm(core, "yec"); await core.fetch_params(() => {});
    const root = document.createElement("div"); const unsub = renderMove(root, vm);
    const p = vm.movePreview("to_private", "1"); button(root, "Private → public")!.click(); await p;
    expect(vm.state.move).toBeNull(); expect(root.textContent).not.toContain("Slide to move");
    await vm.movePreview("to_public", "1"); expect(vm.state.moveDirection).toBe("to_public");
    expect(root.textContent).toContain("Slide to move"); expect(inputs(root).every((i) => i.disabled)).toBe(true);
    button(root, "Public → private")!.click(); expect(root.textContent).not.toContain("Slide to move"); expect(inputs(root).every((i) => !i.disabled)).toBe(true);
    unsub();
  });

  it("a stale preview's ERROR is dropped like its answer (Send)", async () => {
    const core = await delayed(); const vm = new SendVm(core, "yed");
    await vm.setTo(YED_TO); vm.state.amount = "999999.00";       // more than the wallet holds: the core refuses
    const p = vm.preview(); vm.setAsset("yec"); await p;
    expect(vm.state.error).toBe(""); expect(vm.state.yed).toBeNull();
    vm.setAsset("yed"); await vm.preview(); expect(vm.state.error).toContain("insufficient"); // on its own selection it shows
  });

  it("Mint: an estimate (and its error) asked for before the funding source changed is dropped", async () => {
    const core = await delayed(); const vm = new YellowbackVm(core);
    let p = vm.estimate("100", 100); vm.setFrom("rqf1MockFalconAddress000000000000000000000000000000000"); await p;
    expect(vm.state.estimate).toBeNull();
    p = vm.estimate("100", -1 as number); await p; expect(vm.state.error).toContain("blocks"); // a check before any call still shows
    core.mint_estimate = () => new Promise((_, no) => setTimeout(() => no(new Error("network: the server did not answer")), 5));
    p = vm.estimate("100", 100); vm.reset(); await p; expect(vm.state.error).toBe(""); expect(vm.state.estimate).toBeNull();
  });

  it("Claim: a preview asked for before Cancel is dropped", async () => {
    const core = await delayed(); const vm = new YellowbackVm(core);
    await vm.loadClaimable(); const c = vm.state.claimable.find((x) => x.claimable)!;
    const p = vm.claimPreview(c.vaultTxid); vm.reset(); await p;
    expect(vm.state.claim).toBeNull(); expect(vm.previewId).toBe("");
    await vm.claimPreview(c.vaultTxid); expect(vm.state.claim?.item.vaultTxid).toBe(c.vaultTxid);
  });

  it("Settings: only the latest export's key is shown, with the address requested; Hide, lock and leaving clear it", async () => {
    const core = await delayed(); const vm = new SettingsVm(core, { forget: async () => {} });
    const a = "smMockTransparentAddress000000000000";
    let p = vm.exportWif(a); vm.clearWif(); await p;                // left (main.ts route calls clearWif) before the answer
    expect(vm.state.wif).toBe(""); expect(vm.state.wifFor).toBe("");
    p = vm.exportWif("nope"); vm.clearWif(); await p; expect(vm.state.error).toBe(""); // its error is stale too
    await vm.exportWif(a); expect(vm.state.wif.startsWith("c")).toBe(true); expect(vm.state.wifFor).toBe(a);
    vm.clearWif(); expect(vm.state.wif).toBe("");
    await vm.exportWif(a); expect(vm.state.wif).not.toBe(""); await vm.lock(); expect(vm.state.wif).toBe(""); expect(vm.state.wifFor).toBe("");
  });
});
