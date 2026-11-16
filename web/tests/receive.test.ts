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
