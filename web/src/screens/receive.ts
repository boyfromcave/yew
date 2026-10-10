import { mount } from "../dom";
import { clear, copy, h } from "../dom";
import type { AddressKind } from "../core";
import { ReceiveVm } from "../vm/receive";
import { errorCard, qr } from "../widgets";

export function renderReceive(root: HTMLElement, vm: ReceiveVm) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    const seg = (k: AddressKind, label: string) => h("button", { class: s.kind === k ? "on" : "", on: { click: () => vm.show(k) } }, label);
    const cp = h("button", { class: "secondary", disabled: !s.address, on: { click: () => copy(s.address, cp) } }, "Copy");
    mount(root, h("h2", null, "Receive"), h("div", { class: "seg" }, seg("shielded", "Private"), seg("transparent", "Public"), seg("yed", "YED")),
      h("p", { class: "small" }, s.kind === "shielded" ? "Private YEC (ys1…): amounts and messages are hidden on the chain." : s.kind === "yed" ? "YED and the public YEC that pays its fees (ye…)." : "Public YEC (s1…): visible on the chain."),
      s.address ? qr(s.address) : null, s.address ? h("code", { class: "addr" }, s.address) : null, errorCard(s.error),
      h("div", { class: "actions" }, cp, s.kind === "shielded" ? h("button", { class: "secondary", on: { click: () => vm.fresh() } }, "New private address") : null));
  };
  draw(); if (!vm.state.address) vm.show(vm.state.kind); return vm.subscribe(draw);
}
