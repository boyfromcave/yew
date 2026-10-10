// Yellowback (yellowback.dart, mint.dart, mint_progress.dart, vault.dart, claimable.dart):
// YED held, the vaults, what is claimable; mint = estimate → start (the carrier preview) →
// confirm → finish; redeem and claim = preview → confirm. Every broadcast is confirm(previewId).
import type { ClaimPreview, ClaimableItem, Core, MintEstimate, MintStart, MintStatus, RedeemPreview, Vault } from "../core";
import { kindOf, messageOf } from "../core";
import { parseYedCents } from "../format";
import { Vm } from "./base";

export interface YellowbackState {
  vaults: Vault[]; claimable: ClaimableItem[]; busy: boolean; error: string; errorKind: string;
  estimate: MintEstimate | null; mint: MintStart | null; mintStatus: MintStatus | null;
  redeem: RedeemPreview | null; claim: ClaimPreview | null; txid: string;
}

export class YellowbackVm extends Vm<YellowbackState> {
  constructor(private core: Core) {
    super({ vaults: [], claimable: [], busy: false, error: "", errorKind: "", estimate: null, mint: null, mintStatus: null, redeem: null, claim: null, txid: "" });
  }
  private async run(f: () => Promise<void>) {
    this.set({ busy: true, error: "", errorKind: "" });
    try { await f(); } catch (e) { this.set({ error: messageOf(e), errorKind: kindOf(e) }); } finally { this.set({ busy: false }); }
  }
  reset() { this.set({ estimate: null, mint: null, mintStatus: null, redeem: null, claim: null, txid: "", error: "", errorKind: "" }); }
  load() { return this.run(async () => this.set({ vaults: await this.core.vaults() })); }
  loadClaimable() { return this.run(async () => this.set({ claimable: await this.core.claimable() })); }

  estimate(amount: string, lockBlocks: number) {
    return this.run(async () => {
      const cents = parseYedCents(amount); if (cents === null || cents <= 0n) throw new Error("invalid: enter an amount in dollars, like 25.00");
      if (!Number.isInteger(lockBlocks) || lockBlocks <= 0) throw new Error("invalid: the lock is a number of blocks");
      this.set({ estimate: await this.core.mint_estimate(cents.toString(), lockBlocks), mint: null, mintStatus: null, txid: "" });
    });
  }
  /** Start: the carrier preview for the estimate the user saw. */
  mintStart() {
    return this.run(async () => {
      const e = this.state.estimate; if (!e) throw new Error("invalid: estimate first");
      this.set({ mint: await this.core.mint_start(e.cents, e.lockBlocks) });
    });
  }
  /** Confirm the carrier, then finish the mint (the MINT itself) when the core allows. */
  mintConfirm() {
    return this.run(async () => {
      const m = this.state.mint; if (!m) throw new Error("invalid: nothing to confirm");
      const r = await this.core.confirm(m.previewId);
      this.set({ txid: r.txid });
      this.set({ mintStatus: await this.core.mint_finish(m.mintId) });
    });
  }
  mintFinish() { return this.run(async () => { const m = this.state.mint; if (!m) return; this.set({ mintStatus: await this.core.mint_finish(m.mintId) }); }); }
  mintSweep() { return this.run(async () => { const m = this.state.mint; if (!m) return; this.set({ mintStatus: await this.core.mint_sweep(m.mintId) }); }); }

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
