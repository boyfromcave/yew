import { mount } from "../dom";
import { clear, h } from "../dom";
import { OnboardingVm } from "../vm/onboarding";
import { trustParagraphs, trustTitle } from "../trust";
import { errorCard } from "../widgets";
import { prfAvailable } from "../keystore";

export function renderOnboarding(root: HTMLElement, vm: OnboardingVm) {
  const draw = () => {
    clear(root);
    const s = vm.state;
    const err = errorCard(s.error);
    const busy = s.busy;
    if (s.step === "start") mount(root, 
      h("h1", { class: "yed" }, "YEW"), h("p", null, "Your Electronic Wallet — for Ycash Yellowback (YED) and YEC, in this browser. Your keys never leave it."),
      err, h("div", { class: "actions" },
        h("button", { disabled: busy, on: { click: () => vm.create() } }, "Create a new wallet"),
        h("button", { class: "secondary", disabled: busy, on: { click: () => vm.startRestore() } }, "Restore from a recovery phrase")));
    else if (s.step === "seed") mount(root, 
      h("h2", null, "Your recovery phrase"), h("p", null, "Write these words down, in order, and keep them offline. They are shown once; they are the only way to restore this wallet."),
      h("ol", { class: "seed" }, s.seedWords.split(" ").map((w) => h("li", null, w))),
      h("div", { class: "actions" }, h("button", { on: { click: () => vm.written() } }, "I have written it down")));
    else if (s.step === "confirm") {
      const inputs = s.confirmIndexes.map((i) => h("input", { type: "text", autocomplete: "off", autocapitalize: "none", "aria-label": `word ${i + 1}`, placeholder: `word ${i + 1}` }));
      mount(root, h("h2", null, "Confirm your copy"), h("p", null, `Type words ${s.confirmIndexes.map((i) => i + 1).join(", ")} of your phrase.`),
        inputs.map((inp, k) => [h("label", null, `Word ${s.confirmIndexes[k] + 1}`), inp]), err,
        h("div", { class: "actions" }, h("button", { on: { click: () => vm.confirmWords(inputs.map((i) => i.value)) } }, "Continue"),
          h("button", { class: "secondary", on: { click: () => vm.set({ step: "seed", error: "" }) } }, "Show the phrase again")));
    } else if (s.step === "restore") {
      const words = h("textarea", { autocomplete: "off", autocapitalize: "none", spellcheck: false, placeholder: "12 or 24 words" });
      const bday = h("input", { type: "number", min: 0, value: "0" });
      mount(root, h("h2", null, "Recovery phrase"), h("p", null, "12 or 24 words. A Ywallet phrase restores the same address."), words,
        h("label", null, "Birthday height (the block the wallet was created around; 0 = scan everything)"), bday, err,
        h("div", { class: "actions" }, h("button", { on: { click: () => vm.restore(words.value, Number(bday.value)) } }, "Continue"),
          h("button", { class: "secondary", on: { click: () => vm.set({ step: "start", error: "" }) } }, "Back")));
    } else if (s.step === "server") {
      const url = h("input", { type: "url", value: s.serverUrl, placeholder: "https://host:port — no default: enter one you trust" });
      mount(root, h("h2", null, "Server"), h("p", null, "The light-client server this wallet trusts (the statement follows). On mainnet it must be https."), url, err,
        h("div", { class: "actions" }, h("button", { class: "secondary", disabled: busy, on: { click: () => vm.checkServer(url.value) } }, s.tip === null ? "Check server" : `Server ok · tip ${s.tip}`),
          h("button", { disabled: s.tip === null || busy, on: { click: () => vm.serverDone() } }, "Continue")));
    } else if (s.step === "trust") {
      const cb = h("input", { type: "checkbox", checked: s.trustAccepted, on: { change: () => vm.acceptTrust(cb.checked) } });
      mount(root, h("h2", null, trustTitle), trustParagraphs.map((p) => h("p", { class: "trust" }, p)),
        h("label", null, cb, " I understand what this wallet trusts"), h("div", { class: "actions" }, h("button", { disabled: !s.trustAccepted, on: { click: () => vm.trustDone() } }, "Continue")));
    } else if (s.step === "unlock") {
      const pass = h("input", { type: "password", autocomplete: "new-password", placeholder: "at least 8 characters" });
      const pass2 = h("input", { type: "password", autocomplete: "new-password", placeholder: "again" });
      const prf = prfAvailable();
      mount(root, h("h2", null, "Unlock"), h("p", null, "The phrase is encrypted in this browser. Choose what unlocks it."),
        prf ? h("div", { class: "card" }, h("h3", null, "Passkey (recommended)"), h("p", { class: "small" }, "The key is derived by your authenticator (WebAuthn PRF: Touch ID, Windows Hello, a security key); no passphrase to remember."),
          h("button", { disabled: busy, on: { click: () => vm.finish({ method: "prf" }) } }, s.restoring ? "Restore with a passkey" : "Create with a passkey")) : null,
        h("div", { class: "card" }, h("h3", null, "Passphrase"), h("p", { class: "small" }, "PBKDF2-SHA-256 (600 000 rounds) → AES-256-GCM. Forgetting it means restoring from the written phrase."),
          h("label", null, "Passphrase"), pass, h("label", null, "Repeat"), pass2,
          h("div", { class: "actions" }, h("button", { disabled: busy, on: { click: () => pass.value !== pass2.value ? vm.set({ error: "The passphrases differ." }) : vm.finish({ method: "passphrase", passphrase: pass.value }) } }, busy ? "Working…" : s.restoring ? "Restore wallet" : "Create wallet"))),
        err);
    }
  };
  draw(); return vm.subscribe(draw);
}

/** The returning-user unlock. */
export function renderUnlock(root: HTMLElement, method: "prf" | "passphrase", onUnlock: (u: { method: "prf" } | { method: "passphrase"; passphrase: string }) => Promise<void>, onForget: () => void) {
  clear(root);
  const pass = h("input", { type: "password", autocomplete: "current-password" });
  const err = h("div");
  const run = async (u: { method: "prf" } | { method: "passphrase"; passphrase: string }) => { clear(err); try { await onUnlock(u); } catch (e) { err.append(errorCard(e instanceof Error ? e.message : String(e))!); } };
  mount(root, h("h1", { class: "yed" }, "YEW"), h("h2", null, "Unlock"),
    method === "prf" ? h("button", { on: { click: () => run({ method: "prf" }) } }, "Unlock with your passkey")
      : [h("label", null, "Passphrase"), pass, h("div", { class: "actions" }, h("button", { on: { click: () => run({ method: "passphrase", passphrase: pass.value }) } }, "Unlock"))],
    err, h("p", { class: "small" }, h("a", { href: "#", on: { click: (e: Event) => { e.preventDefault(); if (confirm("Forget this wallet? Without your written recovery phrase the YEC and YED are lost.")) onForget(); } } }, "Forget this wallet")));
  pass.addEventListener("keyup", (e) => { if (e.key === "Enter") run({ method: "passphrase", passphrase: pass.value }); });
}
