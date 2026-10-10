import { mount } from "../dom";
import { clear, go, h } from "../dom";
import { SettingsVm } from "../vm/settings";
import { trustParagraphs, trustTitle } from "../trust";
import { errorCard, progressBar } from "../widgets";
import type { WalletMeta } from "../keystore";

export function renderSettings(root: HTMLElement, vm: SettingsVm, meta: WalletMeta | null, version: string, onLocked: () => void) {
  let showTrust = false;
  const draw = () => {
    clear(root);
    const s = vm.state;
    if (showTrust) { mount(root, h("h2", null, trustTitle), trustParagraphs.map((p) => h("p", { class: "trust" }, p)), h("button", { on: { click: () => { showTrust = false; draw(); } } }, "Back")); return; }
    const wifAddr = h("input", { type: "text", placeholder: "an own s1… or ye… address", spellcheck: false });
    const wifIn = h("input", { type: "password", placeholder: "WIF from YecWallet", autocomplete: "off" });
    const wifBday = h("input", { type: "number", min: 0, value: "0" });
    const mb = (s.params?.bytes ?? 0) / 1e6;
    mount(root, h("h2", null, "Settings"),
      h("div", { class: "card" }, h("h3", null, "Server"), h("p", null, meta ? `${meta.serverUrl} · ${meta.network} · birthday ${meta.birthday}` : "—"), h("p", { class: "small" }, "Set at onboarding; to change it, forget this wallet and restore with the phrase.")),
      h("div", { class: "card" }, h("h3", null, "Private sending files"),
        h("p", null, s.params === null ? "Checking…" : s.params.present ? `Ready (${mb.toFixed(1)} MB in the browser cache).` : "Not fetched. Needed before any private send or shield; 52 MB, fetched once from the standard source and kept only if the fingerprints built into YEW match."),
        s.fetching ? progressBar((100 * s.fetching.bytesDone) / Math.max(1, s.fetching.bytesTotal), `${s.fetching.name} · ${(s.fetching.bytesDone / 1e6).toFixed(1)} / ${(s.fetching.bytesTotal / 1e6).toFixed(1)} MB`) : null,
        s.params && !s.params.present && !s.fetching ? h("div", { class: "actions" }, h("button", { on: { click: () => vm.fetchParams() } }, "Fetch (52 MB)")) : null),
      h("div", { class: "card" }, h("h3", null, trustTitle), h("p", { class: "small" }, "The trust statement shown at setup."), h("button", { class: "secondary", on: { click: () => { showTrust = true; draw(); } } }, "Read")),
      h("div", { class: "card" }, h("h3", null, "Export private key"), h("p", { class: "small" }, "WIF for one public address (YecWallet, ycashd). Anyone with it can spend that address."), wifAddr,
        h("div", { class: "actions" }, h("button", { class: "secondary", on: { click: () => vm.exportWif(wifAddr.value) } }, "Export"), s.wif ? h("button", { class: "secondary", on: { click: () => vm.clearWif() } }, "Hide") : null),
        s.wif ? h("code", { class: "addr" }, s.wif) : null),
      h("div", { class: "card" }, h("h3", null, "Import private key"), h("p", { class: "small" }, "A WIF from YecWallet, outside the seed: the phrase will not restore it."), wifIn, h("label", null, "Birthday height"), wifBday,
        h("div", { class: "actions" }, h("button", { class: "secondary", on: { click: () => vm.importWif(wifIn.value, Number(wifBday.value)) } }, "Import"))),
      s.status ? h("p", { class: "small" }, s.status) : null, errorCard(s.error),
      h("div", { class: "card" }, h("h3", null, "About"), h("p", { class: "small" }, `yew-web-core ${version}`)),
      h("div", { class: "actions" },
        h("button", { class: "secondary", on: { click: async () => { await vm.lock(); onLocked(); } } }, "Lock"),
        h("button", { class: "danger", on: { click: async () => { if (confirm("Forget this wallet? The seed is removed from this browser. Without your written recovery phrase the YEC and YED are lost.")) { await vm.forget(); go("home"); location.reload(); } } } }, "Forget this wallet")));
  };
  draw(); vm.loadParams(); return vm.subscribe(draw);
}
