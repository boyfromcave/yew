// Send (send.dart): asset YED/YEC, address, amount, a message for ys1… recipients, preview
// (fee, where the YEC comes from, the reveal warning, the node's dry-run verdict for YED),
// slide-to-confirm → confirm(previewId), result. Every core error is shown verbatim.
import type { Core, MoveDirection, YecPreview, YedPreview } from "../core";
import { kindOf, messageOf } from "../core";
import { parseYecZat, parseYedCents } from "../format";
import { Vm } from "./base";

export type Asset = "yed" | "yec";
export interface SendState {
  asset: Asset; to: string; amount: string; memo: string; toKind: string; busy: boolean; error: string; errorKind: string;
  yec: YecPreview | null; yed: YedPreview | null; move: { previewId: string; fee: string } | null; txid: string;
}

export class SendVm extends Vm<SendState> {
  constructor(private core: Core, asset: Asset = "yed") {
    super({ asset, to: "", amount: "", memo: "", toKind: "", busy: false, error: "", errorKind: "", yec: null, yed: null, move: null, txid: "" });
  }
  private async run(f: () => Promise<void>) {
    this.set({ busy: true, error: "", errorKind: "" });
    try { await f(); } catch (e) { this.set({ error: messageOf(e), errorKind: kindOf(e) }); } finally { this.set({ busy: false }); }
  }
  reset() { this.set({ yec: null, yed: null, move: null, error: "", errorKind: "", txid: "" }); }
  setAsset(asset: Asset) { this.set({ asset }); this.reset(); }
  /** Records the recipient; re-renders only when its kind changes (a memo field appears for ys1…). */
  async setTo(to: string) {
    this.state.to = to;
    const k = to.trim() ? await this.core.validate_address(to.trim()).catch(() => ({ valid: false, kind: "" })) : { valid: false, kind: "" };
    const toKind = k.valid ? k.kind : "";
    if (toKind !== this.state.toKind) this.set({ toKind });
  }
  get toPrivate() { return this.state.toKind === "sapling"; }
  get memoBytes() { return new TextEncoder().encode(this.state.memo).length; }
  preview() {
    return this.run(async () => {
      const s = this.state; const to = s.to.trim();
      if (!to) throw new Error("invalid: enter an address");
      if (s.asset === "yed") {
        if (this.toPrivate) throw new Error("invalid: YED can only be sent to a public address (ye… or s…).");
        const cents = parseYedCents(s.amount); if (cents === null || cents <= 0n) throw new Error("invalid: enter an amount in dollars, like 25.00");
        this.set({ yed: await this.core.send_yed_preview(to, cents.toString()), yec: null });
      } else {
        const zat = parseYecZat(s.amount); if (zat === null || zat <= 0n) throw new Error("invalid: enter an amount in YEC, like 0.5");
        if (s.memo && !this.toPrivate) throw new Error("invalid: a message needs a private (ys1…) recipient");
        if (this.memoBytes > 512) throw new Error("invalid: the message is longer than 512 bytes");
        this.set({ yec: await this.core.send_yec_preview(to, zat.toString(), this.toPrivate && s.memo ? s.memo : undefined), yed: null });
      }
    });
  }
  /** Move YEC between the own private and public balances. */
  movePreview(direction: MoveDirection, amount: string) {
    return this.run(async () => {
      const zat = parseYecZat(amount); if (zat === null || zat <= 0n) throw new Error("invalid: enter an amount in YEC");
      this.set({ move: await this.core.move_preview(direction, zat.toString()) });
    });
  }
  get previewId(): string { const s = this.state; return s.yed?.previewId ?? s.yec?.previewId ?? s.move?.previewId ?? ""; }
  /** The one path that signs and broadcasts. */
  confirm() {
    return this.run(async () => {
      const id = this.previewId; if (!id) throw new Error("invalid: nothing to confirm");
      const r = await this.core.confirm(id);
      this.set({ txid: r.txid, yec: null, yed: null, move: null });
    });
  }
}
