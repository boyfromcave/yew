// @vitest-environment jsdom
// Final-run D-2 and D-3: a claim in the browser is two steps like a mint (the carrier, then the CLAIM
// from mint_finish once the carrier is confirmed; app: claimable.dart → MintProgressScreen), the
// screen says which step was sent, a reload between the steps resumes, and the Claimable list offers
// only what the node judges claimable.
import { describe, expect, it } from "vitest";
import { MOCK_SEED, MockCore } from "../src/mock";
import { YellowbackVm, claimStage } from "../src/vm/yellowback";
import { renderClaimable, renderYellowback } from "../src/screens/yellowback";
import type { ClaimableItem } from "../src/core";

async function openWallet(core = new MockCore()) { await core.open(MOCK_SEED, 0, "http://localhost:8080", "regtest"); return core; }
const tick = () => new Promise((r) => setTimeout(r, 0));
async function settle(vm: YellowbackVm) { for (let i = 0; i < 20 && vm.state.busy; i++) await tick(); await tick(); }

describe("claim in the browser (final-run D-2)", () => {
  it("the claim's confirm sends the carrier only and keeps the row; the CLAIM follows once the carrier is confirmed", async () => {
    const core = await openWallet(); const vm = new YellowbackVm(core);
    await vm.loadClaimable(); const c = vm.state.claimable[0];
    await vm.claimPreview(c.vaultTxid); await vm.confirm();
    expect(vm.state.error).toBe("");
    expect(core.broadcasts).toHaveLength(1);                       // the carrier only
    expect(vm.state.mintId).not.toBeNull();                        // before the fix: dropped
    const carrier = vm.state.txid;
    expect(vm.state.mintStatus?.kind).toBe("claim"); expect(vm.state.mintStatus?.state).toBe("CARRIER_SENT");
    expect(vm.state.mintStatus?.carrierTxid).toBe(carrier);
    expect(claimStage(vm.state.mintStatus!)).toContain("Step 1 of 2 sent");
    expect(vm.state.pending.map((m) => m.mintId)).toEqual([vm.state.mintId]);
    // the carrier confirms: the next check stages the CLAIM, the slide sends it
    core.confirmCarriers(); await vm.mintFinish();
    expect(vm.state.mintStatus?.canFinish).toBe(true); expect(vm.state.step?.mintId).toBe(vm.state.mintId);
    expect(core.broadcasts).toHaveLength(1);
    await vm.mintStepConfirm();
    expect(core.broadcasts).toHaveLength(2);
    expect(vm.state.mintStatus?.state).toBe("MAIN_SENT"); expect(vm.state.txid).toBe(vm.state.mintStatus?.mainTxid);
    expect(vm.state.txid).not.toBe(carrier);
  });

  it("a reload between the two steps: the parked carrier is listed and resumes to the CLAIM", async () => {
    const core = await openWallet(); const first = new YellowbackVm(core);
    await first.loadClaimable(); await first.claimPreview(first.state.claimable[0].vaultTxid); await first.confirm();
    const id = first.state.mintId!;
    core.confirmCarriers();
    const vm = new YellowbackVm(core);                               // the page reloaded: a fresh view-model
    await vm.load();
    expect(vm.state.pending.map((m) => [m.mintId, m.kind, m.state])).toEqual([[id, "claim", "CARRIER_CONFIRMED"]]);
    await vm.resume(id);
    expect(vm.state.mintId).toBe(id); expect(vm.state.step?.mintId).toBe(id); expect(vm.state.mintStatus?.canFinish).toBe(true);
    await vm.mintStepConfirm();
    expect(core.broadcasts).toHaveLength(2); expect(vm.state.mintStatus?.state).toBe("MAIN_SENT");
  });

  it("a carrier whose window closed is shown as such and swept back, never as a sent claim", async () => {
    const core = await openWallet(); const vm = new YellowbackVm(core);
    await vm.loadClaimable(); await vm.claimPreview(vm.state.claimable[0].vaultTxid); await vm.confirm();
    core.confirmCarriers(true);
    const again = new YellowbackVm(core); await again.load();
    const row = again.state.pending[0]; expect(row.state).toBe("LAPSED"); expect(claimStage(row)).toContain("nothing was claimed");
    await again.resume(row.mintId); await again.mintSweep(); expect(again.state.step?.mintId).toBe(row.mintId);
    await again.mintStepConfirm(); expect(again.state.mintStatus?.state).toBe("SWEPT"); expect(core.broadcasts).toHaveLength(2);
  });

  it("the Claimable screen says the carrier was sent, then the claim (never \"Claim sent\" for the carrier)", async () => {
    const core = await openWallet(); const vm = new YellowbackVm(core);
    const root = document.createElement("div"); renderClaimable(root, vm); await settle(vm);
    await vm.claimPreview(vm.state.claimable[0].vaultTxid); await vm.confirm(); await settle(vm);
    expect(root.textContent).not.toContain("Claim sent");
    expect(root.textContent).toContain("Step 1 of 2 sent");
    expect(root.querySelector("[data-claim-state]")?.getAttribute("data-claim-state")).toBe("CARRIER_SENT");
    core.confirmCarriers(); await vm.mintFinish(); await settle(vm);
    expect(root.querySelector("input.slide")?.getAttribute("aria-label")).toBe("Slide to send the claim");
    await vm.mintStepConfirm(); await settle(vm);
    expect(root.textContent).toContain("Claim sent");
    expect(root.querySelector("[data-claim-state]")?.getAttribute("data-claim-state")).toBe("MAIN_SENT");
  });

  it("the Yellowback screen lists a parked claim with a way back into it", async () => {
    const core = await openWallet(); const first = new YellowbackVm(core);
    await first.loadClaimable(); await first.claimPreview(first.state.claimable[0].vaultTxid); await first.confirm();
    const vm = new YellowbackVm(core); const root = document.createElement("div");
    renderYellowback(root, vm, "10000"); await settle(vm);
    expect(root.querySelector("[data-pending]")?.textContent).toContain("Claim");
    expect(root.querySelector(`[data-resume="${first.state.mintId}"]`)).not.toBeNull();
  });
});

describe("the Claimable list follows the node's flag (final-run D-3)", () => {
  const notYet = (c: ClaimableItem): ClaimableItem => ({ ...c, vaultTxid: "f6".repeat(32), claimable: false, claimPath: "", claimantZat: "0", underwaterAtMicroUsd: "15000000" });

  it("a vault the node marks claimable:false is not offered, and is refused if picked", async () => {
    const core = await openWallet(); core.claimRows.push(notYet(core.claimRows[0]));
    const vm = new YellowbackVm(core); const root = document.createElement("div");
    renderClaimable(root, vm); await settle(vm);
    const now = root.querySelector('[data-claimable="now"]')!, later = root.querySelector('[data-claimable="later"]')!;
    expect(now.querySelectorAll("li")).toHaveLength(1); expect(now.textContent).toContain("claimable now");
    expect(later.querySelectorAll("li")).toHaveLength(1); expect(later.textContent).toContain("not claimable: above $15.0000");
    (later.querySelector("li") as HTMLElement).click(); await settle(vm);
    expect(vm.state.claim).toBeNull();                                // nothing to click through to
    await vm.claimPreview("f6".repeat(32));
    expect(vm.state.error).toContain("does not judge this vault claimable"); expect(vm.state.claim).toBeNull();
    expect(core.broadcasts).toHaveLength(0);
  });

  it("only unclaimable vaults: \"Nothing is claimable right now.\"", async () => {
    const core = await openWallet(); core.claimRows = [notYet(core.claimRows[0])];
    const vm = new YellowbackVm(core); const root = document.createElement("div");
    renderClaimable(root, vm); await settle(vm);
    expect(root.textContent).toContain("Nothing is claimable right now.");
    expect(root.querySelector('[data-claimable="now"]')).toBeNull();
  });
});

describe("the Claimable screen's first frame", () => {
  it("asks the node before it says nothing is claimable (the real-stack re-run read the empty first frame)", async () => {
    const core = await openWallet(); const vm = new YellowbackVm(core);
    const root = document.createElement("div"); renderClaimable(root, vm);
    expect(root.textContent).not.toContain("Nothing is claimable");
    expect(root.textContent).toContain("Asking the node");
    await settle(vm); expect(root.querySelector('[data-claimable="now"]')).not.toBeNull();
  });
});
