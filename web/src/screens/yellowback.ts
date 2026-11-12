import { mount } from "../dom";
import { clear, go, h } from "../dom";
import { formatYec, formatYed, shorten } from "../format";
import type { Balances, MintStatus, Vault } from "../core";
import { YellowbackVm, claimStage } from "../vm/yellowback";
import { errorCard, feeLine, previewCard, resultCard, slideToConfirm, unusualFeeCard } from "../widgets";

/** The owner's redeem: open at any height after the mint (in-term claims, D-IT-15); before the term ends it
 *  pays the early-redeem fee, so the label says which of the two a redeem now would be. */
function redeemLabel(v: Vault): string {
  if (!v.open) return "closed";
  if (!v.redeemable) return `redeem opens at height ${v.mintHeight + v.blocksUntilRedeem} (${v.blocksUntilRedeem} blocks)`;
  if (v.earlyRedeem) return `redeemable · early-redemption fee ${formatYec(v.earlyRedeemFeeZat)} YEC until the term ends at height ${v.lockHeight} (${v.blocksUntilTermEnd} blocks)`;
  return "redeemable";
}

/** The claim risk, from the core's verdict — never from the height alone. A claim is valid only while the
 *  collateral is worth less than the threshold (125 %) × debt at the attested claim price (IT-2); past the
 *  term and grace the node's own judgement applies, which the core reports in the same flags. */
function claimNotice(v: Vault): HTMLElement | null {
  if (!v.open) return null;
  const pct = (v.claimThresholdBps / 100).toFixed(0);
  const price = (micro: string) => `$${(Number(micro) / 1e6).toFixed(4)}`;
  if (v.claimable || v.underwater) return h("p", { class: "warn" }, `Anyone may claim this vault now: at the attested claim price ${price(v.claimPriceMicroUsd)} its collateral is worth less than ${pct} % of the debt. Redeem it to keep what is left.`);
  if (v.nearThreshold) return h("p", { class: "warn" }, `Close to the claim threshold: a claim becomes valid if YEC falls to ${price(v.underwaterAtMicroUsd)} (${pct} % of the debt at the attested price, now ${price(v.claimPriceMicroUsd)}). Add nothing here — redeem, or watch the price.`);
  if (v.tip >= v.claimHeight) return h("p", { class: "small" }, `Past the term and its grace (height ${v.claimHeight}). No claim is valid against it now: the collateral covers more than ${pct} % of the debt at the attested price ${price(v.claimPriceMicroUsd)}; a claim would only become valid if YEC fell to ${price(v.underwaterAtMicroUsd)}.`);
  return null;
}

const usd = (micro: string) => `$${(Number(micro) / 1e6).toFixed(4)}`;

/** Final-run D-2: the mints and claims left between their two steps (a reload, a closed tab), each with
 *  where it stands and the way back into it. */
function pendingList(vm: YellowbackVm, rows: MintStatus[]): HTMLElement | null {
  if (!rows.length) return null;
  return h("div", { class: "card", "data-pending": "" }, h("h3", null, "In progress"),
    h("ul", { class: "list" }, rows.map((m) => h("li", null,
      h("span", null, h("div", null, `${m.kind === "claim" ? "Claim" : "Mint"} · ${formatYed(m.cents)}${m.kind === "claim" ? " debt" : ""} · ${m.state}`),
        h("div", { class: "small" }, `${m.kind === "claim" ? claimStage(m) : m.note || "the carrier is sent; the mint follows it"} · carrier ${shorten(m.carrierTxid, 6, 4)}`)),
      h("button", { class: "secondary", "data-resume": String(m.mintId), disabled: vm.state.busy, on: { click: () => { void vm.resume(m.mintId).then(() => go(m.kind === "claim" ? "claimable" : "mint")); } } }, "Continue")))));
}

export function renderYellowback(root: HTMLElement, vm: YellowbackVm, yedCents: string) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    if (s.txid && !s.mint && s.mintId === null) { mount(root, resultCard("Sent", s.txid, () => { vm.reset(); draw(); })); return; }
    const vaults = s.vaults.filter((v) => v.open);
    mount(root, h("h2", null, "Yellowback"), h("div", { class: "card" }, h("h3", null, "YED you hold"), h("div", { class: "big yed" }, yedCents ? formatYed(yedCents) : "—"),
        h("div", { class: "actions" }, h("button", { on: { click: () => go("mint") } }, "Mint"), h("button", { class: "secondary", on: { click: () => go("claimable") } }, "Claimable"))),
      errorCard(s.error, s.errorKind),
      pendingList(vm, s.pending),
      h("h3", null, "Your vaults"), vaults.length === 0 ? h("p", { class: "small" }, "No open vault. Mint YED to open one.") : null,
      h("ul", { class: "list" }, vaults.map((v) => h("li", { on: { click: () => go("vault", v.vaultTxid) } },
        h("span", null, h("div", null, `${formatYed(v.cents)} · ${formatYec(v.collateralZat)} YEC`), h("div", { class: "small" }, `class ${v.termClass} · ${v.status} · ${redeemLabel(v)}`)),
        h("span", { class: "small" }, shorten(v.vaultTxid, 6, 4))))),
      s.vaults.length > vaults.length ? h("p", { class: "small" }, `${s.vaults.length - vaults.length} closed`) : null);
  };
  draw(); vm.load(); return vm.subscribe(draw);
}

export function renderMint(root: HTMLElement, vm: YellowbackVm, balances: () => Balances | null = () => null) {
  const draw = () => {
    clear(root);
    const s = vm.state; const e = s.estimate; const a = s.availability;
    if (s.mintStatus?.kind === "claim") { mount(root, h("h2", null, "Mint YED"), h("p", null, "A claim is in progress."), h("div", { class: "actions" }, h("button", { on: { click: () => go("claimable") } }, "Go to the claim"), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Mint instead"))); return; }
    if (s.mintStatus && !s.mintStatus.inProgress) { mount(root, resultCard(s.mintStatus.state === "DONE" ? `Minted ${formatYed(s.mintStatus.cents)}` : s.mintStatus.state, s.mintStatus.vaultTxid || s.txid, () => { vm.reset(); go("yellowback"); })); return; }
    const amount = h("input", { type: "text", inputmode: "decimal", placeholder: "25.00", value: e ? (Number(e.cents) / 100).toFixed(2) : "" });
    const lock = h("input", { type: "number", min: 1, value: e ? String(e.lockBlocks) : "100" });
    const halted = a !== null && !a.allowed;
    // beta2 D-3: "Fund from" — the public balance or one of the wallet's post-quantum addresses, each
    // with its balance; funding from the private balance is the app's (one line says so)
    const b = balances();
    const fromSelect = h("select", { disabled: !!e, "aria-label": "Fund from", on: { change: () => vm.setFrom(fromSelect.value) } },
      h("option", { value: "", selected: s.from === "" }, `Public · ${b ? formatYec(BigInt(b.yecZat) + BigInt(b.yecReservedZat)) : "—"} YEC`),
      s.sources.map((x) => h("option", { value: x.address, selected: s.from === x.address }, `Post-quantum ${x.schemeName} · ${shorten(x.address, 6, 4)} · ${formatYec(x.balanceZat)} YEC`)));
    const fromPrivate = vm.unavailableReason("mint_from_private");
    const source = (from: string) => from ? `post-quantum · ${shorten(from, 6, 4)}` : "your public balance";
    mount(root, h("h2", null, "Mint YED"), h("p", { class: "small" }, "YED is minted against YEC locked in a vault; redeem at any time after the lock, a liquidator may claim once the grace period after it has passed."),
      a === null ? h("p", { class: "small" }, "Asking the node whether minting is open…") : h("p", { class: halted ? "warn" : "small" }, halted ? a.reason : `Minting is open · ${a.attestStatus}${a.mintableClasses.length ? ` · classes ${a.mintableClasses.join(", ")}` : ""}`),
      h("label", null, "Amount to mint, $"), amount, h("label", null, "Lock, in blocks"), lock,
      h("label", null, "Fund from"), fromSelect,
      fromPrivate ? h("p", { class: "small", "data-shape": "mint_from_private" }, `Private: ${fromPrivate}`) : null,
      errorCard(s.error, s.errorKind),
      !e ? h("div", { class: "actions" }, h("button", { disabled: s.busy || halted, on: { click: () => vm.estimate(amount.value, Number(lock.value)) } }, s.busy ? "Asking the node…" : "Estimate")) : null,
      e && !s.mint ? [previewCard(`Mint ${formatYed(e.cents)}`, [["Collateral to lock", `${formatYec(e.collateralZat)} YEC`], ["Term class", e.termClass], ["Redeem from height", String(e.lockHeight)], ["Claimable from height", String(e.claimHeight)], ["Enforcement fee", feeLine(e.feeZat)], ["Fee payee", e.payee || "none (FEE-0)"],
          ["Funded from", source(e.from)], ["Carrier fee", e.from ? `${feeLine(e.carrierFeeZat)} (priced on its signature size)` : feeLine(e.carrierFeeZat)], ["Network fees", `${feeLine(e.networkFeeZat)} (two transactions)`],
          [`Total from ${source(e.from)}`, `${formatYec(e.totalZat)} YEC`], ["Expires if not minted by", String(e.expiryHeight)]],
          e.affordable ? undefined : `${e.from ? "This post-quantum address" : "Your public balance"} (${formatYec(e.availableZat)} YEC) does not cover it.`),
        unusualFeeCard(e.carrierFeeNote, s.carrierFeeAccepted, () => vm.acceptCarrierFee()),
        h("div", { class: "actions" }, h("button", { disabled: s.busy || !e.affordable || (!!e.unusualCarrierFeeAck && !s.carrierFeeAccepted), on: { click: () => vm.mintStart() } }, s.busy ? "Preparing…" : "Start: fund the carrier"), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Change the amount"))] : null,
      e && s.mint && s.mintId === null ? [previewCard("Step 1 of 2: the carrier", [["Carrier funds", `${formatYec(e.collateralZat)} YEC + fees`], ["Then", "the MINT locks the vault"]]),
        unusualFeeCard(e.feeNote, s.feeAccepted, () => vm.acceptFee()),
        slideToConfirm("Slide to fund the carrier", () => vm.mintConfirm(), s.busy || (!!e.unusualFeeAck && !s.feeAccepted))] : null,
      s.finishFee ? [unusualFeeCard(s.finishFee.note, s.feeAccepted, () => vm.acceptFee()),
        s.feeAccepted ? slideToConfirm("Slide to mint at this fee", () => vm.acceptFinishFee(), s.busy) : null] : null,
      s.mintId !== null && s.mintStatus?.inProgress ? [h("div", { class: "card" }, h("h3", null, "Step 2 of 2: the mint"), h("p", { class: "small" }, `carrier ${shorten(s.mintStatus.carrierTxid || s.txid)} · ${s.mintStatus.state}${s.mintStatus.note ? ` · ${s.mintStatus.note}` : ""}`),
        s.step && s.mintStatus.canFinish ? slideToConfirm("Slide to mint", () => vm.mintStepConfirm(), s.busy) : null,
        h("div", { class: "actions" }, !s.mintStatus.canFinish ? h("button", { disabled: s.busy, on: { click: () => vm.mintFinish() } }, "Check the carrier") : null,
          s.mintStatus.canSweep ? h("button", { class: "secondary", on: { click: () => vm.mintSweep() } }, "Window closed: sweep the carrier") : null,
          s.step && s.mintStatus.canSweep && !s.mintStatus.canFinish ? slideToConfirm("Slide to sweep", () => vm.mintStepConfirm(), s.busy) : null))] : null);
  };
  draw(); if (!vm.state.availability) vm.loadAvailability(); if (!vm.state.unavailable.length) vm.loadSources(); return vm.subscribe(draw);
}

export function renderVault(root: HTMLElement, vm: YellowbackVm, vaultTxid: string) {
  const draw = () => {
    clear(root);
    const s = vm.state; const v = s.vaults.find((x) => x.vaultTxid === vaultTxid);
    if (s.txid) { mount(root, resultCard("Vault redeemed", s.txid, () => { vm.reset(); go("yellowback"); })); return; }
    if (!v) { mount(root, h("h2", null, "Vault"), h("p", null, s.vaults.length ? "No such vault." : "Loading…")); return; }
    mount(root, h("h2", null, "Vault"), h("div", { class: "big yed" }, formatYed(v.cents)), h("p", { class: "yec" }, `minted against ${formatYec(v.collateralZat)} YEC`),
      h("p", { class: "small" }, `${v.status} · class ${v.termClass} · minted at ${v.mintHeight} · term ends at ${v.lockHeight} · claimable from ${v.claimHeight} · tip ${v.tip}`),
      claimNotice(v),
      errorCard(s.error, s.errorKind),
      !s.redeem ? h("div", { class: "actions" }, h("button", { disabled: s.busy || !v.open, on: { click: () => vm.redeemPreview(v.vaultTxid) } }, s.busy ? "Preparing…" : "Preview the redeem"), v.open ? h("span", { class: "small pending" }, redeemLabel(v)) : null) : null,
      s.redeem ? [previewCard(s.redeem.kind === "early" ? "Redeem early" : "Redeem", [["YED burned", formatYed(s.redeem.burnCents)], ["Collateral returned", `${formatYec(s.redeem.collateralZat)} YEC`], ["Enforcement fee", feeLine(s.redeem.feeZat)], ["Fee payee", s.redeem.payee || "none"]],
          BigInt(s.redeem.earlyRedeemFeeZat || 0) > 0n ? `Before the lock: an early-redeem fee of ${formatYec(s.redeem.earlyRedeemFeeZat)} YEC is taken from the collateral.` : undefined),
        slideToConfirm("Slide to redeem", () => vm.confirm(), s.busy), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Cancel")] : null);
  };
  draw(); if (!vm.state.vaults.length) vm.load(); return vm.subscribe(draw);
}

/** Final-run D-2: a claim after its carrier — where it stands (carrier sent, claim sent, or why it stopped)
 *  and the step it is ready for: send the CLAIM once the carrier is confirmed, sweep the carrier back if
 *  the window closed. Never "Claim sent" before the CLAIM itself is. */
function claimProgress(vm: YellowbackVm, m: MintStatus | null): HTMLElement[] {
  const s = vm.state;
  if (!m) return [h("div", { class: "card", "data-claim-state": "CARRIER_SENT" }, h("h3", null, "Claim: step 1 of 2"), h("p", null, "The claim's carrier is sent; the claim itself follows once it is confirmed."), h("p", { class: "small" }, `carrier ${shorten(s.txid)}`))];
  const done = () => { vm.reset(); go("yellowback"); };
  if (m.state === "MAIN_SENT" || m.state === "DONE") return [resultCard(m.state === "DONE" ? "Claimed" : "Claim sent", m.mainTxid || s.txid, done), h("p", { class: "small", "data-claim-state": m.state }, `${claimStage(m)} Carrier ${shorten(m.carrierTxid)}.`)];
  if (!m.inProgress && !m.canSweep) return [h("div", { class: "card", "data-claim-state": m.state }, h("h3", null, "Claim stopped"), h("p", null, claimStage(m)), h("p", { class: "small" }, `carrier ${shorten(m.carrierTxid)}${m.sweepTxid ? ` · sweep ${shorten(m.sweepTxid)}` : ""}`), h("div", { class: "actions" }, h("button", { on: { click: done } }, "Done")))];
  return [h("div", { class: "card", "data-claim-state": m.state }, h("h3", null, m.canSweep ? "Claim: window closed" : m.state === "CARRIER_SENT" ? "Claim: step 1 of 2 sent" : "Claim: step 2 of 2"), h("p", null, claimStage(m)),
    h("p", { class: "small" }, `${formatYed(m.cents)} debt · carrier ${shorten(m.carrierTxid)}${m.note ? ` · ${m.note}` : ""}`),
    s.step && m.canFinish ? slideToConfirm("Slide to send the claim", () => vm.mintStepConfirm(), s.busy) : null,
    h("div", { class: "actions" }, !m.canFinish && !m.canSweep ? h("button", { disabled: s.busy, on: { click: () => vm.mintFinish() } }, s.busy ? "Checking…" : "Check the carrier") : null,
      m.canSweep && !s.step ? h("button", { class: "secondary", on: { click: () => vm.mintSweep() } }, "Sweep the carrier back") : null,
      s.step && m.canSweep ? slideToConfirm("Slide to sweep", () => vm.mintStepConfirm(), s.busy) : null))];
}

export function renderClaimable(root: HTMLElement, vm: YellowbackVm) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    // a claim under way: its row (kind "claim"), or the moment between the carrier's confirm and its row
    const row = s.mintStatus?.kind === "claim" ? s.mintStatus : null;
    const underway = row !== null || (s.mintId !== null && s.mintStatus === null && !s.mint && !!s.txid);
    if (underway) { mount(root, h("h2", null, "Claim"), errorCard(s.error, s.errorKind), claimProgress(vm, row)); return; }
    // final-run D-3: only what the node judges claimable at its tip can be claimed; the rest is listed apart
    const now = s.claimable.filter((c) => c.claimable), later = s.claimable.filter((c) => !c.claimable);
    mount(root, h("h2", null, "Claimable vaults"), h("p", { class: "small" }, "Underwater vaults any YED holder may claim: burn the debt, receive the collateral less the fee and the owner's residual. The core refuses to sign if the server's numbers would burn more or pay less than shown. A claim is two transactions, like a mint: its carrier, then the claim."),
      errorCard(s.error, s.errorKind),
      pendingList(vm, s.pending.filter((m) => m.kind === "claim")),
      !s.claim ? [now.length === 0 ? h("p", null, s.busy ? "Asking the node…" : "Nothing is claimable right now.") : h("ul", { class: "list", "data-claimable": "now" }, now.map((c) => h("li", { on: { click: () => vm.claimPreview(c.vaultTxid) } },
        h("span", null, h("div", null, `${formatYed(c.cents)} debt · ${formatYec(c.collateralZat)} YEC`), h("div", { class: "small" }, `claimable now${c.inTerm ? " (in term)" : ""} · you keep about ${formatYec(c.claimantZat)} YEC · clause ${c.claimPath} · ${shorten(c.ownerAddress, 8, 4)}`))))),
        later.length ? [h("h3", null, "Not claimable now"), h("ul", { class: "list", "data-claimable": "later" }, later.map((c) => h("li", { "aria-disabled": "true" },
          h("span", null, h("div", null, `${formatYed(c.cents)} debt · ${formatYec(c.collateralZat)} YEC`), h("div", { class: "small pending" }, `not claimable: above ${usd(c.underwaterAtMicroUsd)} · ${shorten(c.ownerAddress, 8, 4)}`)))))] : null] : null,
      s.claim ? [previewCard("Claim", [["YED burned (at most)", formatYed(s.claim.maxBurnCents)], ["You receive (at least)", `${formatYec(s.claim.minOutZat)} YEC`], ["Enforcement fee", feeLine(s.claim.item.feeZat)], ["Clause", s.claim.item.claimPath], ["Then", "the carrier is sent now; the claim itself once it is confirmed"]]),
        unusualFeeCard(s.claim.feeNote, s.feeAccepted, () => vm.acceptFee()),
        slideToConfirm("Slide to claim", () => vm.confirm(), s.busy || (!!s.claim.unusualFeeAck && !s.feeAccepted)), h("button", { class: "secondary", on: { click: () => vm.reset() } }, "Cancel")] : null);
  };
  // load first (busy at once), so the first frame never reads "Nothing is claimable" before the node answered
  void vm.loadClaimable(); draw(); return vm.subscribe(draw);
}
