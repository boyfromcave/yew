import { mount } from "../dom";
import { clear, go, h } from "../dom";
import { formatYec, formatYed } from "../format";
import { SendVm } from "../vm/send";
import { errorCard, feeLine, previewCard, resultCard, slideToConfirm } from "../widgets";

export function renderSend(root: HTMLElement, vm: SendVm) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    if (s.txid) { mount(root, resultCard("Sent", s.txid, () => { vm.reset(); go("home"); })); return; }
    const to = h("input", { type: "text", value: s.to, autocomplete: "off", spellcheck: false, placeholder: s.asset === "yed" ? "ye… or s1… address" : "ys1… (private), s1… or ye… address", on: { change: () => vm.setTo(to.value) } });
    const amount = h("input", { type: "text", inputmode: "decimal", value: s.amount, placeholder: s.asset === "yed" ? "25.00" : "0.5", on: { input: () => (vm.state.amount = amount.value) } });
    const memo = h("textarea", { value: s.memo, placeholder: "Message to the recipient (private payments only)", on: { input: () => (vm.state.memo = memo.value) } });
    const seg = (a: "yed" | "yec", label: string) => h("button", { class: s.asset === a ? "on" : "", on: { click: () => vm.setAsset(a) } }, label);
    const previewing = s.yed || s.yec;
    mount(root, h("h2", null, "Send"), h("div", { class: "seg" }, seg("yed", "YED"), seg("yec", "YEC")),
      h("label", null, "To"), to, h("label", null, s.asset === "yed" ? "Amount, $" : "Amount, YEC"), amount,
      s.asset === "yec" && vm.toPrivate ? [h("label", null, `Message (${vm.memoBytes} / 512 bytes)`), memo] : null,
      errorCard(s.error, s.errorKind),
      !previewing ? h("div", { class: "actions" }, h("button", { disabled: s.busy, on: { click: () => vm.preview() } }, s.busy ? "Asking the node…" : "Preview")) : null,
      s.yed ? [previewCard(`Send ${formatYed(BigInt(Math.round(Number(s.amount.replace(/[$,]/g, "")) * 100)))}`, [["To", s.to], ["Fee", feeLine(s.yed.feeZat)], ["YED inputs", String(s.yed.inputs)], ["Node verdict", s.yed.verdict]]),
        slideToConfirm("Slide to send", () => vm.confirm(), s.busy), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Change")] : null,
      s.yec ? [previewCard(`Send ${s.amount} YEC`, [["To", s.to], ["Fee", feeLine(s.yec.fee)], ["Change", `${formatYec(s.yec.change)} YEC`], ["Paid from", s.yec.funding === "private" ? "your private balance" : "your public balance"]],
          s.yec.revealsShielded ? "This payment leaves your private balance for a public address: its amount will be visible on the chain." : undefined),
        slideToConfirm("Slide to send", () => vm.confirm(), s.busy), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Change")] : null);
  };
  draw(); return vm.subscribe(draw);
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
      s.move ? [previewCard(`Move ${s.amount} YEC`, [["Fee", feeLine(s.move.fee)]]), slideToConfirm("Slide to move", () => vm.confirm(), s.busy)] : null);
  };
  draw(); return vm.subscribe(draw);
}
