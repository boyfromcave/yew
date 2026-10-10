import { mount } from "../dom";
import { clear, copy, h } from "../dom";
import { formatYecDelta, formatYedDelta, shorten } from "../format";
import { HistoryVm } from "../vm/history";
import { errorCard, row } from "../widgets";

export function renderHistory(root: HTMLElement, vm: HistoryVm) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    if (s.open) {
      const r = s.open; const cp = h("button", { class: "secondary", on: { click: () => copy(r.txid, cp) } }, "Copy txid");
      mount(root, h("h2", null, r.kind), row("txid", r.txid), row("Height", r.pending ? "pending" : String(r.height)),
        BigInt(r.yedDelta) !== 0n ? row("YED", formatYedDelta(r.yedDelta)) : null, BigInt(r.yecDelta) !== 0n ? row("YEC", formatYecDelta(r.yecDelta)) : null,
        r.verdict ? row("Node verdict", r.verdict) : null, r.memo ? [h("p", { class: "small" }, "Message"), h("p", null, r.memo)] : null,
        h("div", { class: "actions" }, cp, h("button", { on: { click: () => vm.openRow(null) } }, "Back")));
      return;
    }
    mount(root, h("h2", null, "History"), errorCard(s.error),
      s.rows.length === 0 ? h("p", { class: "small" }, "No transactions yet.") : null,
      h("ul", { class: "list" }, s.rows.map((r) => h("li", { on: { click: () => vm.openRow(r) } },
        h("span", null, h("div", null, r.kind, r.memo ? " ✉" : ""), h("div", { class: `small ${r.pending ? "pending" : ""}` }, r.pending ? "pending" : `height ${r.height} · ${shorten(r.txid, 8, 4)}`)),
        h("span", null, BigInt(r.yedDelta) !== 0n ? h("div", { class: "yed" }, formatYedDelta(r.yedDelta)) : null, BigInt(r.yecDelta) !== 0n ? h("div", { class: "yec small" }, `${formatYecDelta(r.yecDelta)} YEC`) : null)))),
      s.more && s.rows.length ? h("div", { class: "actions" }, h("button", { class: "secondary", on: { click: () => vm.more() } }, "More")) : null);
  };
  draw(); vm.load(0); return vm.subscribe(draw);
}
