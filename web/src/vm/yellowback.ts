// Yellowback (yellowback.dart, mint.dart, mint_progress.dart, vault.dart, claimable.dart):
// YED held, the vaults, what is claimable; mint = availability → estimate → start (the carrier,
// staged) → confirm (funds it; answers the mintId) → finish (the MINT, staged) → confirm;
// redeem and claim = preview → confirm. Every broadcast is confirm(previewId) (W2: the real
// core stages the mint steps too, so one rule covers every broadcast).
import type { ClaimPreview, ClaimableItem, Core, MintAvailability, MintEstimate, MintStart, MintStatus, MintStep, RedeemPreview, Vault } from "../core";
import { kindOf, messageOf } from "../core";
import { parseYedCents } from "../format";
import { Vm } from "./base";

export interface YellowbackState {
  vaults: Vault[]; claimable: ClaimableItem[]; busy: boolean; error: string; errorKind: string;
  availability: MintAvailability | null; estimate: MintEstimate | null; mint: MintStart | null;
  /** After the carrier's confirm: the mint's id, then its row from mint_finish / mint_sweep. */
  mintId: number | null; mintStatus: MintStatus | null; step: MintStep | null;
  redeem: RedeemPreview | null; claim: ClaimPreview | null; txid: string;
}

export class YellowbackVm extends Vm<YellowbackState> {
  constructor(private core: Core) {
    super({ vaults: [], claimable: [], busy: false, error: "", errorKind: "", availability: null, estimate: null, mint: null, mintId: null, mintStatus: null, step: null, redeem: null, claim: null, txid: "" });
  }
  private async run(f: () => Promise<void>) {
    this.set({ busy: true, error: "", errorKind: "" });
    try { await f(); } catch (e) { this.set({ error: messageOf(e), errorKind: kindOf(e) }); } finally { this.set({ busy: false }); }
  }
  reset() { this.set({ estimate: null, mint: null, mintId: null, mintStatus: null, step: null, redeem: null, claim: null, txid: "", error: "", errorKind: "" }); }
  load() { return this.run(async () => this.set({ vaults: await this.core.vaults() })); }
  /** The node's mint gate (H-1/H-5): shown on the Mint screen; a halted mint is not estimated. */
  loadAvailability() { return this.run(async () => this.set({ availability: await this.core.mint_availability() })); }
  loadClaimable() { return this.run(async () => this.set({ claimable: await this.core.claimable() })); }

  estimate(amount: string, lockBlocks: number) {
    return this.run(async () => {
      const cents = parseYedCents(amount); if (cents === null || cents <= 0n) throw new Error("invalid: enter an amount in dollars, like 25.00");
      if (!Number.isInteger(lockBlocks) || lockBlocks <= 0) throw new Error("invalid: the lock is a number of blocks");
      this.set({ estimate: await this.core.mint_estimate(cents.toString(), lockBlocks), mint: null, mintId: null, mintStatus: null, step: null, txid: "" });
    });
  }
  /** Start: the carrier preview for the estimate the user saw. */
  mintStart() {
    return this.run(async () => {
      const e = this.state.estimate; if (!e) throw new Error("invalid: estimate first");
      this.set({ mint: await this.core.mint_start(e.cents, e.lockBlocks) });
    });
  }
  /** Confirm the carrier (funded and broadcast by the core; the mintId comes back), then stage the finish. */
  mintConfirm() {
    return this.run(async () => {
      const m = this.state.mint; if (!m) throw new Error("invalid: nothing to confirm");
      const r = await this.core.confirm(m.previewId);
      if (r.mintId === null) throw new Error("build: the core did not record the mint");
      this.set({ txid: r.txid, mintId: r.mintId });
      await this.stageFinish();
    });
  }
  /** Stage the MINT (mint_finish) — the core answers "build: …" until the carrier is confirmed. */
  private async stageFinish() {
    const id = this.state.mintId; if (id === null) return;
    const step = await this.core.mint_finish(id);
    this.set({ step, mintStatus: step.row });
  }
  mintFinish() { return this.run(() => this.stageFinish()); }
  /** Confirm the staged MINT (or sweep): the vault opens (or the carrier returns). */
  mintStepConfirm() {
    return this.run(async () => {
      const st = this.state.step; if (!st) throw new Error("invalid: nothing to confirm");
      const r = await this.core.confirm(st.previewId);
      const rows = await this.core.mints();
      this.set({ txid: r.txid, step: null, mintStatus: rows.find((m) => m.mintId === st.mintId) ?? st.row });
    });
  }
  mintSweep() { return this.run(async () => { const id = this.state.mintId; if (id === null) return; const step = await this.core.mint_sweep(id); this.set({ step, mintStatus: step.row }); }); }

  redeemPreview(vaultTxid: string) { return this.run(async () => this.set({ redeem: await this.core.redeem_preview(vaultTxid), claim: null, txid: "" })); }
  claimPreview(vaultTxid: string) { return this.run(async () => this.set({ claim: await this.core.claim_preview(vaultTxid), redeem: null, txid: "" })); }
  get previewId() { return this.state.redeem?.previewId ?? this.state.claim?.previewId ?? ""; }
  confirm() {
    return this.run(async () => {
      const id = this.previewId; if (!id) throw new Error("invalid: nothing to confirm");
      const r = await this.core.confirm(id);
      this.set({ txid: r.txid, redeem: null, claim: null });
      this.set({ vaults: await this.core.vaults() });
    });
  }
}
