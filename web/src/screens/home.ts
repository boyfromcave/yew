import { mount } from "../dom";
import { clear, go, h } from "../dom";
import { formatPriceLine, formatYec, formatYed } from "../format";
import { HomeVm } from "../vm/home";
import { errorCard, progressBar } from "../widgets";

export function renderHome(root: HTMLElement, vm: HomeVm) {
  const draw = () => {
    clear(root);
    const s = vm.state; const b = s.balances;
    const p = s.progress;
    mount(root, 
      h("div", { class: "card" }, h("h3", null, "Yellowback"), h("div", { class: "big yed" }, b ? formatYed(b.yedCents) : "—"),
        b && BigInt(b.yedPendingCents) !== 0n ? h("div", { class: "small pending" }, `${formatYed(b.yedPendingCents)} pending`) : null,
        h("div", { class: "actions" }, h("button", { class: "secondary", on: { click: () => go("yellowback") } }, "Mint, vaults, claims"))),
      h("div", { class: "card" }, h("h3", null, "Ycash"),
        h("div", { class: "row" }, h("span", null, "Private"), h("span", { class: "yec" }, b ? `${formatYec(b.shieldedZat)} YEC` : "—")),
        b && b.shieldedSpendableZat !== b.shieldedZat ? h("div", { class: "small pending" }, `${formatYec(b.shieldedSpendableZat)} spendable now`) : null,
        h("div", { class: "row" }, h("span", null, "Public"), h("span", { class: "yec" }, b ? `${formatYec(b.yecZat)} YEC` : "—")),
        b && BigInt(b.yecPendingZat) !== 0n ? h("div", { class: "small pending" }, `${formatYec(b.yecPendingZat)} YEC pending`) : null,
        h("div", { class: "actions" }, h("button", { class: "secondary", on: { click: () => go("move") } }, "Move…"))),
      h("p", { class: "small" }, b ? formatPriceLine(b.priceCents ?? "0") : "", s.network ? ` · ${s.network}` : ""),
      p && (s.syncing || p.pct < 100) ? progressBar(p.pct, `${p.phase} · ${p.height} / ${p.tip}`) : null,
      errorCard(s.error),
      h("div", { class: "actions" },
        h("button", { on: { click: () => go("receive") } }, "Receive"),
        h("button", { on: { click: () => go("send") } }, "Send"),
        h("button", { class: "secondary", disabled: s.syncing, on: { click: () => vm.sync() } }, s.syncing ? "Syncing…" : "Sync")));
  };
  draw(); return vm.subscribe(draw);
}
