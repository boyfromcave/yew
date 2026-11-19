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
    // only the current tab's own, prefix-checked address is shown, copied or encoded (vm.shown); while it
    // is on its way the screen says so and Copy is off
    const addr = vm.shown;
    const cp = h("button", { class: "secondary", disabled: !addr, on: { click: () => { if (vm.shown) copy(vm.shown, cp); } } }, "Copy");
    // beta2 D-8, D-9: the post-quantum plain-YEC forms, the scheme in the label and in the prefix
    const about: Record<AddressKind, string> = {
      shielded: "Private YEC (ys1…): amounts and messages are hidden on the chain.",
      transparent: "Public YEC (s1…, ECC): visible on the chain.",
      pq_falcon: "Public YEC to a post-quantum key, scheme FN-DSA-512 (sqf…): plain YEC only, visible on the chain. Spending it carries a ~1.6 KB signature.",
      pq_slh: "Public YEC to a post-quantum key, scheme SLH-DSA-SHA2-128s (sqs…): plain YEC only, visible on the chain. Spending it carries a ~7.9 KB signature, so its fees are the largest.",
      yed: "YED and the public YEC that pays its fees (yb…).",
    };
    mount(root, h("h2", null, "Receive"), h("div", { class: "seg" }, seg("shielded", "Private"), seg("transparent", "Public (ECC)"), seg("pq_falcon", "PQ · FN-DSA-512"), seg("pq_slh", "PQ · SLH-DSA"), seg("yed", "YED")),
      h("p", { class: "small" }, localize(about[s.kind])),
      // beta4: a mining reward paid to a post-quantum address can only be shielded, at the exact amount
      s.kind === "pq_falcon" || s.kind === "pq_slh" ? h("p", { class: "small error", "data-receive": "pq-mining-warning" }, "Not for mining payouts: a mining reward paid here can only be moved by shielding it at the exact amount after 101 confirmations, which this web wallet cannot do yet. Pay mining rewards to a ycashd or yewd wallet address instead.") : null,
      addr ? qr(addr) : null, addr ? h("code", { class: "addr" }, addr) : null,
      s.loading ? h("p", { class: "small pending", "data-receive": "loading" }, "Getting this address…") : null, errorCard(s.error),
      h("div", { class: "actions" }, cp, s.kind === "shielded" ? h("button", { class: "secondary", on: { click: () => vm.fresh() } }, "New private address") : null));
  };
  // subscribed first: show() answers from the cache synchronously, and that change must draw
  const unsub = vm.subscribe(draw); void vm.show(vm.state.kind); return unsub;
}
