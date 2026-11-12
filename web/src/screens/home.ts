import { mount } from "../dom";
import { clear, go, h } from "../dom";
import { formatPriceLine, formatYec, formatYed } from "../format";
import { HomeVm } from "../vm/home";
import { errorCard, progressBar } from "../widgets";
import { localize } from "../prefixes";

/** WEB-REAL LOW-5: a balance that could not be computed is never shown as 0. */
export function termsRefusedText(why: string): string {
  return `The FN-DSA-512 and YED balances cannot be computed: this server's fee terms were refused (${why}). Use another server.`;
}

export function renderHome(root: HTMLElement, vm: HomeVm) {
  const draw = () => {
    clear(root);
    const s = vm.state; const b = s.balances;
    const p = s.progress;
    mount(root, 
      h("div", { class: "card" }, h("h3", null, "Yellowback"), h("div", { class: "big yed" }, b && !b.termsRefused ? formatYed(b.yedCents) : "—"),
        b && BigInt(b.yedPendingCents) !== 0n ? h("div", { class: "small pending" }, `${formatYed(b.yedPendingCents)} pending`) : null,
        h("div", { class: "actions" }, h("button", { class: "secondary", on: { click: () => go("yellowback") } }, "Mint, vaults, claims"))),
      h("div", { class: "card" }, h("h3", null, "Ycash"),
        h("div", { class: "row" }, h("span", null, "Private"), h("span", { class: "yec" }, b ? `${formatYec(b.shieldedZat)} YEC` : "—")),
        b && b.shieldedSpendableZat !== b.shieldedZat ? h("div", { class: "small pending" }, `${formatYec(b.shieldedSpendableZat)} spendable now`) : null,
        h("div", { class: "row" }, h("span", null, "Public (ECC)"), h("span", { class: "yec" }, b ? `${formatYec(b.yecZat)} YEC` : "—")),
        b && BigInt(b.yecPendingZat) !== 0n ? h("div", { class: "small pending" }, `${formatYec(b.yecPendingZat)} YEC pending`) : null,
        // beta2 D-8: balances by type; post-quantum YEC is spent only from its own address (Send → From)
        h("div", { class: "row" }, h("span", null, localize("PQ · SLH-DSA (sqs…)")), h("span", { class: "yec" }, b ? `${formatYec(b.pqSlhZat)} YEC` : "—")),
        h("div", { class: "row" }, h("span", null, localize("PQ · FN-DSA-512 (sqf…)")), h("span", { class: "yec" }, b && !b.termsRefused ? `${formatYec(b.pqFalconZat)} YEC` : "—")),
        // never in a spendable total: held outputs and YEC staged for a mint are listed on their own
        b && BigInt(b.stagedForMintZat) !== 0n ? h("div", { class: "small pending", "data-balance": "staged" }, `${formatYec(b.stagedForMintZat)} YEC staged for a mint in progress (not spendable until the mint finishes or lapses)`) : null,
        b && b.heldCount > 0 ? h("div", { class: "small pending", "data-balance": "held" }, `${b.heldCount} output${b.heldCount === 1 ? "" : "s"} held: in no balance and never spent as plain YEC (${b.heldCount === 1 ? "it may carry" : "they may carry"} YED, or the origin could not be verified)`) : null,
        h("div", { class: "actions" }, h("button", { class: "secondary", on: { click: () => go("move") } }, "Move…"))),
      h("p", { class: "small" }, b ? formatPriceLine(b.priceCents ?? "0") : "", s.network ? ` · ${s.network}` : ""),
      p && (s.syncing || p.pct < 100) ? progressBar(p.pct, `${p.phase} · ${p.height} / ${p.tip}`) : null,
      errorCard(s.error),
      b?.termsRefused ? errorCard(termsRefusedText(b.termsRefused)) : null,
      h("div", { class: "actions" },
        h("button", { on: { click: () => go("receive") } }, "Receive"),
        h("button", { on: { click: () => go("send") } }, "Send"),
        h("button", { class: "secondary", disabled: s.syncing, on: { click: () => vm.sync() } }, s.syncing ? "Syncing…" : "Sync")));
  };
  draw(); return vm.subscribe(draw);
}
