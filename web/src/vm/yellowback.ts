// Yellowback (yellowback.dart, mint.dart, mint_progress.dart, vault.dart, claimable.dart):
// YED held, the vaults, what is claimable; mint = availability → estimate → start (the carrier,
// staged) → confirm (funds it; answers the mintId) → finish (the MINT, staged) → confirm;
// redeem and claim = preview → confirm. Every broadcast is confirm(previewId) (W2: the real
// core stages the mint steps too, so one rule covers every broadcast).
import type { ClaimPreview, ClaimableItem, Core, MintAvailability, MintEstimate, MintStart, MintStatus, MintStep, PqSource, RedeemPreview, Unavailable, Vault } from "../core";
import { kindOf, messageOf } from "../core";
import { parseYedCents } from "../format";
import { Vm } from "./base";

export interface YellowbackState {
  vaults: Vault[]; claimable: ClaimableItem[]; busy: boolean; error: string; errorKind: string;
  availability: MintAvailability | null; estimate: MintEstimate | null; mint: MintStart | null;
  /** After the carrier's confirm: the mint's id, then its row from mint_finish / mint_sweep. */
  mintId: number | null; mintStatus: MintStatus | null; step: MintStep | null;
  redeem: RedeemPreview | null; claim: ClaimPreview | null; txid: string;
  /** Review YEW-REVIEW-5 L4: the user pressed "Pay this fee" for the estimate's or the claim's unusual fee. */
  feeAccepted: boolean;
  /** Review YEW-REVIEW-5 M2: the finish's main fee rose above what the start accepted; the core's text and
   *  the new acknowledgement it needs back. */
  finishFee: { note: string; ack: string } | null;
  /** beta2 D-3: the mint's funding source ("" = the public balance, else one of `sources`' addresses). */
  from: string; sources: PqSource[]; unavailable: Unavailable[];
  /** The user pressed "Pay this fee" for the estimate's unusual carrier fee (its own confirmation). */
  carrierFeeAccepted: boolean;
  /** Final-run D-2: the two-step rows (mints and claims) still in flight or with a carrier to sweep, as
   *  the store keeps them: a reload between the carrier and the main step resumes from here. */
  pending: MintStatus[];
}

/** A two-step row the user still has to act on or wait for: in flight, or lapsed with its carrier to sweep. */
export function isPending(m: MintStatus): boolean { return m.inProgress || m.canSweep; }

/** Final-run D-2: where a claim stands, in words — its carrier sent, the CLAIM sent, or why it stopped. */
export function claimStage(m: MintStatus): string {
  switch (m.state) {
    case "CARRIER_SENT": return "Step 1 of 2 sent: the claim's carrier is waiting for its first confirmation; the claim itself is sent after it.";
    case "CARRIER_CONFIRMED": return m.canFinish ? "Step 1 of 2 confirmed: send the claim (step 2)." : "The carrier is confirmed, but the claim's window has closed.";
    case "MAIN_SENT": return "Claim sent (step 2 of 2): waiting for it to be mined.";
    case "DONE": return "Claimed: the claim is mined.";
    case "LAPSED": return "The claim was not sent in time and its window has closed: nothing was claimed. Sweep the carrier back.";
    case "SWEEP_SENT": return "The carrier is being swept back.";
    case "SWEPT": return "The carrier was swept back: nothing was claimed.";
    case "FAILED": return `The claim failed${m.note ? `: ${m.note}` : ""}.`;
    default: return m.state;
  }
}

/** The acknowledgement in a finish refusal (`unusual-fee: … accept-unusual-fee:<fee>:row:<id> …`). */
export function finishAck(message: string): { note: string; ack: string } | null {
  if (!message.startsWith("unusual-fee:")) return null;
  const m = /accept-unusual-fee:\d+:row:\d+/.exec(message); if (!m) return null;
  const cut = message.indexOf(" To pay it,");
  return { note: (cut < 0 ? message : message.slice(0, cut)).replace(/^unusual-fee: /, ""), ack: m[0] };
}

export class YellowbackVm extends Vm<YellowbackState> {
  constructor(private core: Core) {
    super({ vaults: [], claimable: [], busy: false, error: "", errorKind: "", availability: null, estimate: null, mint: null, mintId: null, mintStatus: null, step: null, redeem: null, claim: null, txid: "", feeAccepted: false, finishFee: null, from: "", sources: [], unavailable: [], carrierFeeAccepted: false, pending: [] });
  }
  private async run(f: () => Promise<void>) {
    this.set({ busy: true, error: "", errorKind: "" });
    try { await f(); } catch (e) { this.set({ error: messageOf(e), errorKind: kindOf(e) }); } finally { this.set({ busy: false }); }
  }
  reset() { this.set({ estimate: null, mint: null, mintId: null, mintStatus: null, step: null, redeem: null, claim: null, txid: "", error: "", errorKind: "", feeAccepted: false, finishFee: null, carrierFeeAccepted: false }); }
  /** The "Fund from" chooser: the post-quantum sources and the shapes this build cannot run. */
  async loadSources() {
    try {
      const [sources, unavailable] = await Promise.all([this.core.pq_sources(), this.core.unavailable_shapes()]);
      this.set({ sources, unavailable, from: sources.some((x) => x.address === this.state.from) ? this.state.from : "" });
    } catch (e) { this.set({ error: messageOf(e), errorKind: kindOf(e) }); }
  }
  setFrom(from: string) { this.set({ from, estimate: null, mint: null, error: "", errorKind: "", carrierFeeAccepted: false }); }
  unavailableReason(shape: Unavailable["shape"]): string | null { return this.state.unavailable.find((u) => u.shape === shape)?.reason ?? null; }
  acceptCarrierFee() { this.set({ carrierFeeAccepted: true }); }
  /** The user's own confirmation of the shown unusual fee (estimate, claim, or the finish's new fee). */
  acceptFee() { this.set({ feeAccepted: true }); }
  /** The acknowledgement confirm passes back: only after acceptFee(); an unaccepted flagged fee refuses here. */
  private ackFor(ack: string | null | undefined): string | undefined {
    if (!ack) return undefined;
    if (!this.state.feeAccepted) throw new Error("invalid: this fee is unusual; press \"Pay this fee\" first");
    return ack;
  }
  load() { return this.run(async () => { this.set({ vaults: await this.core.vaults() }); await this.loadPending(); }); }
  /** The two-step rows still to act on (final-run D-2: a reload between a claim's carrier and its CLAIM). */
  async loadPending() { this.set({ pending: (await this.core.mints()).filter(isPending) }); }
  /** Pick up a pending row (after a reload): its row, then the step it is ready for. */
  resume(mintId: number) {
    return this.run(async () => {
      const row = (await this.core.mints()).find((m) => m.mintId === mintId);
      if (!row) throw new Error(`invalid: no mint or claim with id ${mintId}`);
      this.set({ mintId, mintStatus: row, step: null, txid: row.carrierTxid, mint: null, estimate: null, claim: null, redeem: null, finishFee: null, feeAccepted: false });
      if (row.state === "CARRIER_SENT" || row.state === "CARRIER_CONFIRMED") await this.stageFinish();
    });
  }
  /** The node's mint gate (H-1/H-5): shown on the Mint screen; a halted mint is not estimated. */
  loadAvailability() { return this.run(async () => this.set({ availability: await this.core.mint_availability() })); }
  /** The gate again, quietly (after a sync): a failed read keeps the last answer; the sync's own error shows on Home. */
  private async refreshAvailability() {
    try { this.set({ availability: await this.core.mint_availability() }); } catch { /* keep the last answer */ }
  }
  loadClaimable() { return this.run(async () => { this.set({ claimable: await this.core.claimable() }); await this.loadPending(); }); }

  estimate(amount: string, lockBlocks: number) {
    return this.run(async () => {
      const cents = parseYedCents(amount); if (cents === null || cents <= 0n) throw new Error("invalid: enter an amount in dollars, like 25.00");
      if (!Number.isInteger(lockBlocks) || lockBlocks <= 0) throw new Error("invalid: the lock is a number of blocks");
      this.set({ estimate: await this.core.mint_estimate(cents.toString(), lockBlocks, this.state.from), mint: null, mintId: null, mintStatus: null, step: null, txid: "", feeAccepted: false, finishFee: null, carrierFeeAccepted: false });
    });
  }
  /** Start: the carrier preview for the estimate the user saw. */
  mintStart() {
    return this.run(async () => {
      const e = this.state.estimate; if (!e) throw new Error("invalid: estimate first");
      // the carrier fee's own confirmation goes with the start (the core refuses a flagged one without it)
      if (e.unusualCarrierFeeAck && !this.state.carrierFeeAccepted) throw new Error("invalid: the carrier fee is unusual; press \"Pay this fee\" first");
      // only the core's estimate id and the acknowledgement: the core starts from the estimate it keeps (the terms a
      // server answer may not differ from, audit G-2; the carrier fee the funding may not exceed and the source,
      // beta2 D-3; review YEW-REVIEW-10 L2)
      this.set({ mint: await this.core.mint_start(e.estimateId, { acceptUnusualCarrierFee: e.unusualCarrierFeeAck ?? null }) });
    });
  }
  /** Confirm the carrier (funded and broadcast by the core; the mintId comes back), then stage the finish. */
  mintConfirm() {
    return this.run(async () => {
      const m = this.state.mint; if (!m) throw new Error("invalid: nothing to confirm");
      const r = await this.core.confirm(m.previewId, this.ackFor(this.state.estimate?.unusualFeeAck));
      if (r.mintId == null) throw new Error("build: the core did not record the mint");
      this.set({ txid: r.txid, mintId: r.mintId });
      await this.stageFinish();
    });
  }
  /** Stage the MINT (mint_finish). The core advances a mint only from a sync, so one runs first; while the
   *  carrier is unconfirmed the core answers "build: …" — that is a wait, not an error: the row is shown
   *  with a note and the next sync (automatic) tries again. */
  private async stageFinish() {
    const id = this.state.mintId; if (id === null) return;
    try { await this.core.sync(); } catch { /* the sync's own error shows on Home */ }
    try {
      const step = await this.core.mint_finish(id);
      this.set({ step, mintStatus: step.row });
    } catch (e) {
      if (kindOf(e) !== "build") throw e;
      const rows = await this.core.mints();
      const row = rows.find((m) => m.mintId === id) ?? this.state.mintStatus;
      this.set({ step: null, mintStatus: row ? { ...row, note: row.note || "waiting for the carrier to confirm (checked at every sync)" } : null });
    }
  }
  mintFinish() { return this.run(() => this.stageFinish()); }
  /** After a sync (HomeVm.onSynced): a pending mint re-checks its carrier; a broadcast MINT refreshes its
   *  row (and the vaults) so the screen moves to "Minted" without a click. */
  onSynced() {
    if (this.state.busy) return;
    // the pending list (a claim or mint left between its steps) follows the chain (final-run D-2)
    void this.loadPending().catch(() => { /* keep the last list */ });
    // no mint in progress: the mint gate follows the chain, so a Mint screen opened while the price was
    // missing reads "Minting is open" after the sync that brings it, without a reload (real-stack run WEB-FIX)
    if (this.state.mintId === null) { if (this.state.availability) void this.refreshAvailability(); return; }
    const st = this.state.mintStatus;
    // a carrier still waiting: stage again so the row (and the slide) follow the sync, staged before or not
    if (st && st.inProgress && !st.canFinish && st.state !== "MAIN_SENT") { this.run(async () => {
      const id = this.state.mintId!; try { const step = await this.core.mint_finish(id); this.set({ step, mintStatus: step.row }); }
      catch (e) { if (kindOf(e) !== "build") throw e; }
    }); return; }
    if (st && !this.state.step) this.run(async () => {
      const rows = await this.core.mints(); const row = rows.find((m) => m.mintId === this.state.mintId);
      if (row) this.set({ mintStatus: row, vaults: await this.core.vaults() });
    });
  }
  /** Confirm the staged MINT (or sweep): the vault opens (or the carrier returns). */
  mintStepConfirm() {
    return this.run(async () => {
      const st = this.state.step; if (!st) throw new Error("invalid: nothing to confirm");
      let r;
      try { r = await this.core.confirm(st.previewId); }
      catch (e) {
        // the finish's fee rose above what the start accepted: nothing was sent; show the note and
        // ask (acceptFinishFee) instead of failing with the raw refusal
        const f = finishAck(messageOf(e));
        if (!f) throw e;
        this.set({ step: null, finishFee: f, feeAccepted: false });
        return;
      }
      const rows = await this.core.mints();
      this.set({ txid: r.txid, step: null, finishFee: null, mintStatus: rows.find((m) => m.mintId === st.mintId) ?? st.row });
    });
  }
  /** After acceptFee() on a finish refusal: stage the finish again and confirm it with the new acknowledgement. */
  acceptFinishFee() {
    return this.run(async () => {
      const f = this.state.finishFee, id = this.state.mintId; if (!f || id === null) throw new Error("invalid: nothing to confirm");
      const ack = this.ackFor(f.ack)!;
      const step = await this.core.mint_finish(id);
      const r = await this.core.confirm(step.previewId, ack);
      const rows = await this.core.mints();
      this.set({ txid: r.txid, step: null, finishFee: null, feeAccepted: false, mintStatus: rows.find((m) => m.mintId === id) ?? step.row });
    });
  }
  mintSweep() { return this.run(async () => { const id = this.state.mintId; if (id === null) return; const step = await this.core.mint_sweep(id); this.set({ step, mintStatus: step.row }); }); }

  redeemPreview(vaultTxid: string) { return this.run(async () => this.set({ redeem: await this.core.redeem_preview(vaultTxid), claim: null, txid: "" })); }
  claimPreview(vaultTxid: string) {
    return this.run(async () => {
      // final-run D-3: only a vault the node judges claimable at its tip (`claimable: true`)
      const row = this.state.claimable.find((c) => c.vaultTxid === vaultTxid);
      if (row && !row.claimable) throw new Error("invalid: The node does not judge this vault claimable now.");
      this.set({ claim: await this.core.claim_preview(vaultTxid), redeem: null, txid: "", feeAccepted: false });
    });
  }
  get previewId() { return this.state.redeem?.previewId ?? this.state.claim?.previewId ?? ""; }
  confirm() {
    return this.run(async () => {
      const id = this.previewId; if (!id) throw new Error("invalid: nothing to confirm");
      const claim = this.state.claim;
      const r = await this.core.confirm(id, this.ackFor(claim?.unusualFeeAck));
      if (claim) {
        // final-run D-2: a claim is two steps like a mint (app: claimable.dart → MintProgressScreen). The
        // confirm sent only the carrier and answered the row; the CLAIM goes out from mint_finish once the
        // carrier is confirmed. Keep the row: the screen shows the carrier as sent, never "Claim sent".
        if (r.mintId == null) throw new Error("build: the core did not record the claim");
        this.set({ txid: r.txid, mintId: r.mintId, mintStatus: null, step: null, claim: null, redeem: null, feeAccepted: false });
        await this.stageFinish();
        await this.loadPending();
        return;
      }
      this.set({ txid: r.txid, redeem: null, claim: null, feeAccepted: false });
      this.set({ vaults: await this.core.vaults() });
    });
  }
}
