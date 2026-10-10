// Shared widgets: the preview card (fee, verdict, reveal warning), slide-to-confirm (the one
// gesture that calls confirm()), the result, the error card, a QR, a progress bar.
import { h, copy } from "./dom";
import { formatYec, shorten } from "./format";
import qrcode from "qrcode-generator";

export function errorCard(text: string, kind = ""): HTMLElement | null {
  if (!text) return null;
  const hint = kind === "gate" ? "The node refused this transaction; nothing was sent." : kind === "network" ? "The server did not answer." : kind === "params" ? "Fetch the private sending files in Settings." : "";
  return h("div", { class: "card error", role: "alert" }, h("p", null, text), hint ? h("p", { class: "small" }, hint) : null);
}

export function row(k: string, v: string): HTMLElement { return h("div", { class: "row" }, h("span", { class: "k" }, k), h("span", { class: "v" }, v)); }

export function previewCard(title: string, rows: [string, string][], warning?: string): HTMLElement {
  return h("div", { class: "card preview" }, h("h3", null, title), rows.map(([k, v]) => row(k, v)), warning ? h("p", { class: "warn" }, warning) : null);
}

/** Slide to confirm: a range input dragged to the end fires `onConfirm` once, else snaps back. */
export function slideToConfirm(label: string, onConfirm: () => void, disabled = false): HTMLElement {
  const input = h("input", { type: "range", min: 0, max: 100, value: 0, class: "slide", disabled, "aria-label": label });
  let fired = false;
  const done = () => { if (!fired && Number(input.value) >= 100) { fired = true; input.disabled = true; onConfirm(); } else input.value = "0"; };
  input.addEventListener("change", done);
  input.addEventListener("pointerup", done);
  input.addEventListener("keyup", (e) => { if ((e as KeyboardEvent).key === "End" || (e as KeyboardEvent).key === "Enter") { input.value = "100"; done(); } });
  return h("div", { class: "slide-wrap" }, input, h("span", { class: "slide-label" }, label));
}

export function resultCard(title: string, txid: string, onDone: () => void): HTMLElement {
  const b = h("button", { class: "secondary", on: { click: () => copy(txid, b) } }, "Copy txid");
  return h("div", { class: "card result" }, h("h3", null, title), h("code", { class: "txid" }, shorten(txid, 16, 8)), h("div", { class: "actions" }, b, h("button", { on: { click: onDone } }, "Done")));
}

export function progressBar(pct: number, text: string): HTMLElement {
  const fill = h("div", { class: "fill" }); fill.style.width = `${Math.max(0, Math.min(100, pct))}%`;
  return h("div", { class: "progress", role: "progressbar", "aria-valuenow": Math.round(pct) }, h("div", { class: "bar" }, fill), h("span", { class: "small" }, text));
}

export function qr(text: string): HTMLElement {
  const q = qrcode(0, "M"); q.addData(text); q.make();
  const box = h("div", { class: "qr" }); box.innerHTML = q.createSvgTag({ scalable: true, margin: 2 });
  return box;
}

export function feeLine(zat: string) { return `${formatYec(zat)} YEC`; }
