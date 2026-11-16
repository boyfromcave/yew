// Send (send.dart): asset YED/YEC, address, amount, a message for ys1… recipients, preview
// (fee, where the YEC comes from, the reveal warning, the node's dry-run verdict for YED),
// slide-to-confirm → confirm(previewId), result. Every core error is shown verbatim.
// Sends between address types (beta2 D-8, as app/lib/screens/send.dart): a From chooser offers
// Automatic (private first, then public: ECC or private to s…/ys1…/sqf…/sqs…) and each of the
// wallet's post-quantum addresses (to s…/sqf…/sqs…); the shapes the browser build cannot run
// (post-quantum to ys1…, private to post-quantum) are named by the core (`unavailable_shapes`)
// and shown as one line instead of an option. A post-quantum preview shows the fee, the signed
// size and the signing time ("not measured" here), and a flagged fee its separate confirmation.
import type { Core, MoveDirection, PqSendPreview, PqSource, Unavailable, YecPreview, YedPreview } from "../core";
import { kindOf, messageOf } from "../core";
import { parseYecZat, parseYedCents } from "../format";
import { Vm } from "./base";
import { localize } from "../prefixes";

export type Asset = "yed" | "yec";
export interface SendState {
  asset: Asset; to: string; amount: string; memo: string; toKind: string; busy: boolean; error: string; errorKind: string;
  yec: YecPreview | null; yed: YedPreview | null; move: YecPreview | null; txid: string;
  /** The user pressed "Pay this fee" for the current preview's unusual fee (review YEW-REVIEW-5 L4). */
  feeAccepted: boolean;
  /** The YEC source: "" = automatic (private first, then public), else one of `sources`' addresses. */
  from: string;
  /** The wallet's post-quantum addresses holding plain YEC (the From chooser). */
  sources: PqSource[];
  /** The shapes this build cannot run, with the core's one-line reason. */
  unavailable: Unavailable[];
  pq: PqSendPreview | null;
  /** The `yec` preview's recipient is private (ys1…), from that preview's own address check. */
  yecToPrivate: boolean;
  /** The direction `move` was previewed for (the Move screen shows only a preview of its own direction). */
  moveDirection: MoveDirection | null;
}

/** Why a valid address of `kind` is not a destination for `asset` (app/lib/screens/send.dart
 *  `destinationMismatch`): the post-quantum forms are asset-bound (D-Q-20/D-Q-21). */
export function destinationMismatch(asset: Asset, kind: string): string | null {
  if (asset === "yec" && kind === "pq") return localize("This is a post-quantum YED address (ybf…/ybs…). To send YEC to the same wallet, ask for its sqf… or sqs… address.");
  if (asset === "yed" && kind === "pq_yec") return localize("This is a post-quantum YEC address (sqf…/sqs…): it receives YEC, not YED. Ask for a yb… address.");
  return null;
}

export class SendVm extends Vm<SendState> {
  /** Bumped by every change that makes an answer in flight stale (reset: the asset, the source, the
   *  direction, "Change"): a preview asked for before it is dropped, never shown (beta3). */
  private gen = 0;
  constructor(private core: Core, asset: Asset = "yed") {
    super({ asset, to: "", amount: "", memo: "", toKind: "", busy: false, error: "", errorKind: "", yec: null, yed: null, move: null, txid: "", feeAccepted: false, from: "", sources: [], unavailable: [], pq: null, moveDirection: null, yecToPrivate: false });
  }
  /** `g`: the generation a preview was asked for in; its error is dropped, like its answer, once the
   *  user has left that selection (beta3 review). A confirm passes none: its error always shows. */
  private async run(f: () => Promise<void>, g?: number) {
    this.set({ busy: true, error: "", errorKind: "" });
    try { await f(); } catch (e) { if (g === undefined || g === this.gen) this.set({ error: messageOf(e), errorKind: kindOf(e) }); } finally { this.set({ busy: false }); }
  }
  reset() { this.gen++; this.set({ yec: null, yed: null, move: null, moveDirection: null, pq: null, error: "", errorKind: "", txid: "", feeAccepted: false }); }
  setAsset(asset: Asset) { this.set({ asset }); this.reset(); }
  /** The From chooser's contents: the post-quantum sources and what this build cannot do. A source that
   *  dropped out of the list (spent, a refresh) falls back to Automatic (review YEW-REVIEW-3 L5). */
  async loadSources() {
    try {
      const [sources, unavailable] = await Promise.all([this.core.pq_sources(), this.core.unavailable_shapes()]);
      const from = sources.some((x) => x.address === this.state.from) ? this.state.from : "";
      this.set({ sources, unavailable, from });
    } catch (e) { this.set({ error: messageOf(e), errorKind: kindOf(e) }); }
  }
  setFrom(from: string) { this.set({ from }); this.reset(); }
  /** The core's reason a shape cannot run here, or null when it can. */
  unavailableReason(shape: Unavailable["shape"]): string | null { return this.state.unavailable.find((u) => u.shape === shape)?.reason ?? null; }
  /** The chosen post-quantum source cannot pay the current recipient in this build (ys1…): the reason, else null. */
  get blockedReason(): string | null {
    const s = this.state;
    if (s.asset !== "yec" || !s.from || s.toKind !== "sapling") return null;
    return this.unavailableReason("pq_to_private");
  }
  /** Records the recipient; re-renders only when its kind changes (a memo field appears for ys1…). */
  async setTo(to: string) {
    this.state.to = to;
    const k = to.trim() ? await this.core.validate_address(to.trim()).catch(() => ({ valid: false, kind: "" })) : { valid: false, kind: "" };
    // the recipient changed again while this one was checked: its answer is not the field's
    if (this.state.to !== to) return;
    const toKind = k.valid ? k.kind : "";
    // the message field exists only for a private recipient: when it goes, its text goes with it (a hidden
    // message the user cannot see or clear would refuse every later preview)
    if (toKind !== this.state.toKind) this.set(toKind === "sapling" ? { toKind } : { toKind, memo: "" });
  }
  get toPrivate() { return this.state.asset === "yec" && !this.state.from && this.state.toKind === "sapling"; }
  get memoBytes() { return new TextEncoder().encode(this.state.memo).length; }
  preview() {
    const g = this.gen;
    return this.run(async () => {
      const s = this.state; const to = s.to.trim();
      if (!to) throw new Error("invalid: enter an address");
      const check = await this.core.validate_address(to);
      // private-ness from this check of this address, never from an older field check
      const toPrivate = s.asset === "yec" && !s.from && check.valid && check.kind === "sapling";
      if (check.valid) { const wrong = destinationMismatch(s.asset, check.kind); if (wrong) throw new Error(`invalid: ${wrong}`); }
      if (s.asset === "yed") {
        if (check.kind === "sapling") throw new Error(localize("invalid: YED can only be sent to a public address (yb… or s…)."));
        const cents = parseYedCents(s.amount); if (cents === null || cents <= 0n) throw new Error("invalid: enter an amount in dollars, like 25.00");
        const yed = await this.core.send_yed_preview(to, cents.toString());
        if (g === this.gen) this.set({ yed, yec: null, feeAccepted: false });
      } else {
        const zat = parseYecZat(s.amount); if (zat === null || zat <= 0n) throw new Error("invalid: enter an amount in YEC, like 0.5");
        if (s.memo && !toPrivate) throw new Error("invalid: a message needs a private (ys1…) recipient");
        if (this.memoBytes > 512) throw new Error("invalid: the message is longer than 512 bytes");
        if (s.from) {
          // from a post-quantum address: the core plans and signs (build::pq_send); its refusals verbatim
          const blocked = check.kind === "sapling" ? this.unavailableReason("pq_to_private") : null;
          if (blocked) throw new Error(`unsupported: ${blocked}`);
          const pq = await this.core.pq_send_preview(s.from, to, zat.toString());
          if (g === this.gen) this.set({ pq, yec: null, yed: null, feeAccepted: false });
          return;
        }
        const yec = await this.core.send_yec_preview(to, zat.toString(), toPrivate && s.memo ? s.memo : undefined);
        if (g === this.gen) this.set({ yec, yed: null, yecToPrivate: check.valid && check.kind === "sapling" });
      }
    }, g);
  }
  /** Move YEC between the own private and public balances. */
  movePreview(direction: MoveDirection, amount: string) {
    const g = this.gen;
    return this.run(async () => {
      const zat = parseYecZat(amount); if (zat === null || zat <= 0n) throw new Error("invalid: enter an amount in YEC");
      const move = await this.core.move_preview(direction, zat.toString());
      // the direction changed meanwhile (reset): this preview moves the other way, so it is not shown
      if (g === this.gen) this.set({ move, moveDirection: direction });
    }, g);
  }
  get previewId(): string { const s = this.state; return s.yed?.previewId ?? s.pq?.previewId ?? s.yec?.previewId ?? s.move?.previewId ?? ""; }
  /** The flagged fee's note (null when the fee is usual). */
  get feeNote(): string | null { return this.state.yed?.feeNote ?? this.state.pq?.feeNote ?? null; }
  /** The flagged fee's acknowledgement the core needs back (null when the fee is usual). */
  get feeAck(): string | null { return this.state.yed?.unusualFeeAck ?? this.state.pq?.unusualFeeAck ?? null; }
  /** The user's own confirmation of an unusual fee (the separate step; the slider stays off until then). */
  acceptFee() { this.set({ feeAccepted: true }); }
  /** The one path that signs and broadcasts. An unusual fee's acknowledgement goes back only after
   *  acceptFee(); without it the core refuses and nothing is sent. */
  confirm() {
    return this.run(async () => {
      const id = this.previewId; if (!id) throw new Error("invalid: nothing to confirm");
      const ack = this.feeAck;
      if (ack && !this.state.feeAccepted) throw new Error("invalid: this fee is unusual; press \"Pay this fee\" first");
      const r = await this.core.confirm(id, ack ?? undefined);
      // a sent payment's form is done with: the next send starts empty (its message included)
      this.set({ txid: r.txid, yec: null, yed: null, move: null, moveDirection: null, pq: null, feeAccepted: false, to: "", toKind: "", amount: "", memo: "" });
    });
  }
}
