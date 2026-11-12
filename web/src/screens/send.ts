import { mount } from "../dom";
import { clear, go, h } from "../dom";
import { formatSigning, formatYec, formatYed, shorten } from "../format";
import type { PqSendPreview } from "../core";
import { SendVm } from "../vm/send";
import { errorCard, feeLine, previewCard, resultCard, slideToConfirm, unusualFeeCard } from "../widgets";
import { localize } from "../prefixes";

export function renderSend(root: HTMLElement, vm: SendVm) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    if (s.txid) { mount(root, resultCard("Sent", s.txid, () => { vm.reset(); go("home"); })); return; }
    const to = h("input", { type: "text", value: s.to, autocomplete: "off", spellcheck: false, placeholder: localize(s.asset === "yed" ? "yb… address" : s.from ? "s…, sqf… or sqs… address" : "ys1… (private), s…, sqf… or sqs… address"), on: { change: () => vm.setTo(to.value) } });
    const amount = h("input", { type: "text", inputmode: "decimal", value: s.amount, placeholder: s.asset === "yed" ? "25.00" : "0.5", on: { input: () => (vm.state.amount = amount.value) } });
    const memo = h("textarea", { value: s.memo, placeholder: "Message to the recipient (private payments only)", on: { input: () => (vm.state.memo = memo.value) } });
    const seg = (a: "yed" | "yec", label: string) => h("button", { class: s.asset === a ? "on" : "", on: { click: () => vm.setAsset(a) } }, label);
    const previewing = s.yed || s.yec || s.pq;
    // beta2 D-8: the From chooser (YEC only), the post-quantum sources with their balances; a shape
    // this build cannot run is one line of text, never an option
    const fromSelect = h("select", { disabled: !!previewing, "aria-label": "From", on: { change: () => vm.setFrom(fromSelect.value) } },
      h("option", { value: "", selected: s.from === "" }, "Automatic: private first, then public"),
      s.sources.map((x) => h("option", { value: x.address, selected: s.from === x.address }, `Post-quantum ${x.schemeName} · ${shorten(x.address, 6, 4)} · ${formatYec(x.balanceZat)} YEC`)));
    const privateToPq = vm.unavailableReason("private_to_pq");
    mount(root, h("h2", null, "Send"), h("div", { class: "seg" }, seg("yed", "YED"), seg("yec", "YEC")),
      s.asset === "yec" ? [h("label", null, "From"), fromSelect,
        privateToPq ? h("p", { class: "small", "data-shape": "private_to_pq" }, localize(`Private → post-quantum (sqf…/sqs…): ${privateToPq}`)) : null] : null,
      h("label", null, "To"), to,
      vm.blockedReason ? h("p", { class: "warn", "data-shape": "pq_to_private" }, vm.blockedReason) : null, h("label", null, s.asset === "yed" ? "Amount, $" : "Amount, YEC"), amount,
      s.asset === "yec" && vm.toPrivate ? [h("label", null, `Message (${vm.memoBytes} / 512 bytes)`), memo] : null,
      errorCard(s.error, s.errorKind),
      !previewing ? h("div", { class: "actions" }, h("button", { disabled: s.busy || !!vm.blockedReason, on: { click: () => vm.preview() } }, s.busy ? "Asking the node…" : "Preview")) : null,
      s.yed ? [previewCard(`Send ${formatYed(BigInt(Math.round(Number(s.amount.replace(/[$,]/g, "")) * 100)))}`, [["To", s.to], ["Fee", feeLine(s.yed.feeZat)], ["YED inputs", String(s.yed.inputs)], ["Node verdict", s.yed.verdict]]),
        unusualFeeCard(s.yed.feeNote, s.feeAccepted, () => vm.acceptFee()),
        slideToConfirm("Slide to send", () => vm.confirm(), s.busy || (!!s.yed.unusualFeeAck && !s.feeAccepted)), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Change")] : null,
      s.yec ? [previewCard(`Send ${s.amount} YEC`, [["To", s.to], ...(s.yec.memo ? [["Message", s.yec.memo] as [string, string]] : []), ["Fee", feeLine(s.yec.fee)], ["Change", `${formatYec(s.yec.change)} YEC`], ["Paid from", s.yec.funding === "shielded" ? "your private balance" : "your public balance"]],
          s.yec.revealsShielded ? "This payment leaves your private balance for a public address: its amount will be visible on the chain."
            : s.yec.funding !== "shielded" && s.toKind === "sapling" ? publicToPrivateNote : undefined),
        s.yec.paramsNeeded ? h("p", { class: "small" }, "Proved in this browser at confirm (private spends take a while).") : null,
        slideToConfirm("Slide to send", () => vm.confirm(), s.busy), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Change")] : null,
      s.pq ? [pqPreviewCard(s.pq),
        unusualFeeCard(s.pq.feeNote, s.feeAccepted, () => vm.acceptFee()),
        slideToConfirm(`Slide to send ${formatYec(s.pq.amountZat)} YEC`, () => vm.confirm(), s.busy || (!!s.pq.unusualFeeAck && !s.feeAccepted)), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Change")] : null);
  };
  // the From chooser's balances change with every send and sync: read them again on every visit
  draw(); vm.loadSources(); return vm.subscribe(draw);
}

/** A private (ys1…) recipient paid from the public balance (WEB-REAL MEDIUM-4): what the chain shows. */
export const publicToPrivateNote = "Paid from your public balance: the amount and the public address it comes from are visible on the chain; the recipient's address and the message are not.";

/** A post-quantum send's preview (app/lib/widgets/preview_card.dart PqSendPreviewCard): the fee, the
 *  signed size and the signing time ("not measured" where the platform has no clock: the browser). */
export function pqPreviewCard(p: PqSendPreview): HTMLElement {
  const ms = p.signMillis;
  const signing = formatSigning(ms);
  const rows: [string, string][] = [["To", p.to], ["Amount", `${formatYec(p.amountZat)} YEC`]];
  if (p.amountBumped) rows.push(["", "Raised by 1 zat: exactly 0.0001 YEC would look like a YED token"]);
  rows.push(["From", p.fromPrivate ? "your private balance" : `post-quantum ${p.schemeName} · ${shorten(p.from, 6, 4)}`],
    ["Fee", feeLine(p.feeZat)], ["Size", `${p.sizeBytes} bytes · ${p.inputs} ${p.fromPrivate ? "note" : "input"}${p.inputs === 1 ? "" : "s"}`],
    [p.fromPrivate ? "Proving" : "Signing", signing]);
  if (BigInt(p.changeZat) > 0n) rows.push(["Change", p.fromPrivate ? `${formatYec(p.changeZat)} YEC back to your private balance` : `${formatYec(p.changeZat)} YEC back to the same address`]);
  rows.push(["Expires", `height ${p.expiryHeight}`]);
  return previewCard(`Send ${formatYec(p.amountZat)} YEC`, rows,
    p.fromPrivate ? "This payment leaves your private balance for a public address: its amount will be visible on the chain." : undefined);
}

/** Move YEC between the own private and public balances (home.dart "Move…"). */
export function renderMove(root: HTMLElement, vm: SendVm) {
  let direction: "to_private" | "to_public" = "to_private";
  const draw = () => {
    clear(root);
    const s = vm.state;
    if (s.txid) { mount(root, resultCard("Moved", s.txid, () => { vm.reset(); go("home"); })); return; }
    const amount = h("input", { type: "text", inputmode: "decimal", placeholder: "0.5", value: s.amount, on: { input: () => (vm.state.amount = amount.value) } });
    const seg = (d: typeof direction, label: string) => h("button", { class: direction === d ? "on" : "", on: { click: () => { direction = d; vm.reset(); } } }, label);
    mount(root, h("h2", null, "Move YEC"), h("div", { class: "seg" }, seg("to_private", "Public → private"), seg("to_public", "Private → public")),
      h("p", { class: "small" }, direction === "to_private" ? "Shield: public YEC becomes private. Needs the private sending files (Settings)." : "Unshield: private YEC becomes public; the amount is visible on the chain."),
      h("label", null, "Amount, YEC"), amount, errorCard(s.error, s.errorKind),
      !s.move ? h("div", { class: "actions" }, h("button", { disabled: s.busy, on: { click: () => vm.movePreview(direction, amount.value) } }, "Preview")) : null,
      s.move ? [previewCard(`Move ${s.amount} YEC`, [["Fee", feeLine(s.move.fee)], ["Change", `${formatYec(s.move.change)} YEC`], ["Paid from", s.move.funding === "shielded" ? "your private balance" : "your public balance"]]),
        slideToConfirm("Slide to move", () => vm.confirm(), s.busy)] : null);
  };
  draw(); return vm.subscribe(draw);
}
