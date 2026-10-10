import { mount } from "../dom";
import { clear, go, h } from "../dom";
import { formatYec, formatYed, shorten } from "../format";
import { YellowbackVm } from "../vm/yellowback";
import { errorCard, feeLine, previewCard, resultCard, slideToConfirm } from "../widgets";

export function renderYellowback(root: HTMLElement, vm: YellowbackVm, yedCents: string) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    if (s.txid && !s.mint) { mount(root, resultCard("Sent", s.txid, () => { vm.reset(); draw(); })); return; }
    const vaults = s.vaults.filter((v) => v.open);
    mount(root, h("h2", null, "Yellowback"), h("div", { class: "card" }, h("h3", null, "YED you hold"), h("div", { class: "big yed" }, formatYed(yedCents)),
        h("div", { class: "actions" }, h("button", { on: { click: () => go("mint") } }, "Mint"), h("button", { class: "secondary", on: { click: () => go("claimable") } }, "Claimable"))),
      errorCard(s.error, s.errorKind),
      h("h3", null, "Your vaults"), vaults.length === 0 ? h("p", { class: "small" }, "No open vault. Mint YED to open one.") : null,
      h("ul", { class: "list" }, vaults.map((v) => h("li", { on: { click: () => go("vault", v.vaultTxid) } },
        h("span", null, h("div", null, `${formatYed(v.cents)} · ${formatYec(v.collateralZat)} YEC`), h("div", { class: "small" }, `class ${v.termClass} · ${v.status} · ${v.redeemable ? "redeemable now" : `redeem at height ${v.lockHeight} (${v.blocksToLock} blocks)`}`)),
        h("span", { class: "small" }, shorten(v.vaultTxid, 6, 4))))),
      s.vaults.length > vaults.length ? h("p", { class: "small" }, `${s.vaults.length - vaults.length} closed`) : null);
  };
  draw(); vm.load(); return vm.subscribe(draw);
}

export function renderMint(root: HTMLElement, vm: YellowbackVm) {
  const draw = () => {
    clear(root);
    const s = vm.state; const e = s.estimate;
    if (s.mintStatus && !s.mintStatus.inProgress) { mount(root, resultCard(s.mintStatus.state === "DONE" ? `Minted ${formatYed(s.mintStatus.cents)}` : s.mintStatus.state, s.mintStatus.vaultTxid || s.txid, () => { vm.reset(); go("yellowback"); })); return; }
    const amount = h("input", { type: "text", inputmode: "decimal", placeholder: "25.00", value: e ? (Number(e.cents) / 100).toFixed(2) : "" });
    const lock = h("input", { type: "number", min: 1, value: e ? String(e.lockBlocks) : "100" });
    mount(root, h("h2", null, "Mint YED"), h("p", { class: "small" }, "YED is minted against public YEC locked in a vault; redeem at any time after the lock, a liquidator may claim once the grace period after it has passed."),
      h("label", null, "Amount to mint, $"), amount, h("label", null, "Lock, in blocks"), lock, errorCard(s.error, s.errorKind),
      !e ? h("div", { class: "actions" }, h("button", { disabled: s.busy, on: { click: () => vm.estimate(amount.value, Number(lock.value)) } }, s.busy ? "Asking the node…" : "Estimate")) : null,
      e && !s.mint ? [previewCard(`Mint ${formatYed(e.cents)}`, [["Collateral to lock", `${formatYec(e.collateralZat)} YEC`], ["Term class", e.termClass], ["Redeem from height", String(e.lockHeight)], ["Claimable from height", String(e.claimHeight)], ["Enforcement fee", feeLine(e.feeZat)], ["Fee payee", e.payee || "none (FEE-0)"], ["Expires if not minted by", String(e.expiryHeight)]]),
        h("div", { class: "actions" }, h("button", { disabled: s.busy, on: { click: () => vm.mintStart() } }, s.busy ? "Preparing…" : "Start: fund the carrier"), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Change the amount"))] : null,
      e && s.mint && !s.txid ? [previewCard("Step 1 of 2: the carrier", [["Carrier funds", `${formatYec(e.collateralZat)} YEC + fees`], ["Then", "the MINT locks the vault"]]), slideToConfirm("Slide to fund the carrier", () => vm.mintConfirm(), s.busy)] : null,
      s.mint && s.txid && s.mintStatus?.inProgress ? [h("div", { class: "card" }, h("h3", null, "Step 2 of 2: waiting for the carrier"), h("p", { class: "small" }, `carrier ${shorten(s.txid)} · ${s.mintStatus.state}`),
        h("div", { class: "actions" }, h("button", { disabled: s.busy, on: { click: () => vm.mintFinish() } }, "Finish the mint"), s.mintStatus.canSweep ? h("button", { class: "secondary", on: { click: () => vm.mintSweep() } }, "Window closed: sweep the carrier") : null))] : null);
  };
  draw(); return vm.subscribe(draw);
}

export function renderVault(root: HTMLElement, vm: YellowbackVm, vaultTxid: string) {
  const draw = () => {
    clear(root);
    const s = vm.state; const v = s.vaults.find((x) => x.vaultTxid === vaultTxid);
    if (s.txid) { mount(root, resultCard("Vault redeemed", s.txid, () => { vm.reset(); go("yellowback"); })); return; }
    if (!v) { mount(root, h("h2", null, "Vault"), h("p", null, s.vaults.length ? "No such vault." : "Loading…")); return; }
    mount(root, h("h2", null, "Vault"), h("div", { class: "big yed" }, formatYed(v.cents)), h("p", { class: "yec" }, `minted against ${formatYec(v.collateralZat)} YEC`),
      h("p", { class: "small" }, `${v.status} · class ${v.termClass} · minted at ${v.mintHeight} · redeem from ${v.lockHeight} · claimable from ${v.claimHeight} · tip ${v.tip}`),
      v.tip >= v.claimHeight && v.open ? h("p", { class: "warn" }, "Past the claim height: a liquidator may claim this vault. Redeem it now.") : null,
      errorCard(s.error, s.errorKind),
      !s.redeem ? h("div", { class: "actions" }, h("button", { disabled: s.busy || !v.open, on: { click: () => vm.redeemPreview(v.vaultTxid) } }, s.busy ? "Preparing…" : "Preview the redeem"), !v.redeemable && v.open ? h("span", { class: "small pending" }, `Redeem unlocks at height ${v.lockHeight}.`) : null) : null,
      s.redeem ? [previewCard("Redeem", [["YED burned", formatYed(s.redeem.burnCents)], ["Collateral returned", `${formatYec(s.redeem.returnedZat)} YEC`], ["Enforcement fee", feeLine(s.redeem.feeZat)], ["Fee payee", s.redeem.payee || "none"]]),
        slideToConfirm("Slide to redeem", () => vm.confirm(), s.busy), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Cancel")] : null);
  };
  draw(); if (!vm.state.vaults.length) vm.load(); return vm.subscribe(draw);
}

export function renderClaimable(root: HTMLElement, vm: YellowbackVm) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    if (s.txid) { mount(root, resultCard("Claim sent", s.txid, () => { vm.reset(); go("yellowback"); })); return; }
    mount(root, h("h2", null, "Claimable vaults"), h("p", { class: "small" }, "Underwater vaults any YED holder may claim: burn the debt, receive the collateral less the fee and the owner's residual. The core refuses to sign if the server's numbers would burn more or pay less than shown."),
      errorCard(s.error, s.errorKind),
      !s.claim ? (s.claimable.length === 0 && !s.busy ? h("p", null, "Nothing is claimable right now.") : h("ul", { class: "list" }, s.claimable.map((c) => h("li", { on: { click: () => vm.claimPreview(c.vaultTxid) } },
        h("span", null, h("div", null, `${formatYed(c.cents)} debt · ${formatYec(c.collateralZat)} YEC`), h("div", { class: "small" }, `you keep about ${formatYec(c.claimantZat)} YEC · clause ${c.claimPath} · ${shorten(c.ownerAddress, 8, 4)}`)))))) : null,
      s.claim ? [previewCard("Claim", [["YED burned", formatYed(s.claim.burnCents)], ["You receive", `${formatYec(s.claim.claimantZat)} YEC`], ["Enforcement fee", feeLine(s.claim.feeZat)]]),
        slideToConfirm("Slide to claim", () => vm.confirm(), s.busy), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Cancel")] : null);
  };
  draw(); vm.loadClaimable(); return vm.subscribe(draw);
}
