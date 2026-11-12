import { mount } from "../dom";
import { clear, copy, h } from "../dom";
import type { AddressKind } from "../core";
import { ReceiveVm } from "../vm/receive";
import { errorCard, qr } from "../widgets";
import { localize } from "../prefixes";

export function renderReceive(root: HTMLElement, vm: ReceiveVm) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    const seg = (k: AddressKind, label: string) => h("button", { class: s.kind === k ? "on" : "", on: { click: () => vm.show(k) } }, label);
    const cp = h("button", { class: "secondary", disabled: !s.address, on: { click: () => copy(s.address, cp) } }, "Copy");
    // beta2 D-8, D-9: the post-quantum plain-YEC forms, the scheme in the label and in the prefix
    const about: Record<AddressKind, string> = {
      shielded: "Private YEC (ys1…): amounts and messages are hidden on the chain.",
      transparent: "Public YEC (s…, ECC): visible on the chain.",
      pq_falcon: "Public YEC to a post-quantum key, scheme FN-DSA-512 (sqf…): plain YEC only, visible on the chain. Spending it carries a ~1.6 KB signature.",
      pq_slh: "Public YEC to a post-quantum key, scheme SLH-DSA-SHA2-128s (sqs…): plain YEC only, visible on the chain. Spending it carries a ~7.9 KB signature, so its fees are the largest.",
      yed: "YED and the public YEC that pays its fees (yb…).",
    };
    mount(root, h("h2", null, "Receive"), h("div", { class: "seg" }, seg("shielded", "Private"), seg("transparent", "Public (ECC)"), seg("pq_falcon", "PQ · FN-DSA-512"), seg("pq_slh", "PQ · SLH-DSA"), seg("yed", "YED")),
      h("p", { class: "small" }, localize(about[s.kind])),
      s.address ? qr(s.address) : null, s.address ? h("code", { class: "addr" }, s.address) : null, errorCard(s.error),
      h("div", { class: "actions" }, cp, s.kind === "shielded" ? h("button", { class: "secondary", on: { click: () => vm.fresh() } }, "New private address") : null));
  };
  draw(); if (!vm.state.address) vm.show(vm.state.kind); return vm.subscribe(draw);
}
