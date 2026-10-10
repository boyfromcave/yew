// Onboarding (app/lib/screens/onboarding.dart, seed_backup.dart): create or restore → the seed
// shown once with a confirm step → server → trust statement → how to unlock (passkey PRF or
// passphrase) → the seed encrypted at rest and the wallet opened.
import type { Core } from "../core";
import { messageOf } from "../core";
import type { Unlock, WalletMeta } from "../keystore";
import { Vm } from "./base";

export type Step = "start" | "seed" | "confirm" | "restore" | "server" | "trust" | "unlock" | "done";
export interface OnboardingState {
  step: Step; restoring: boolean; seedWords: string; confirmIndexes: number[]; birthday: number;
  serverUrl: string; tip: number | null; trustAccepted: boolean; busy: boolean; error: string; network: string;
}
export interface Keystore { saveSeed(seed: string, unlock: Unlock, meta: WalletMeta): Promise<void> }

/** A new seed's birthday: the tip less a margin, so a payment made while the phrase is being
 *  written down is still scanned (W2). */
export const BIRTHDAY_MARGIN = 20;

/** `http(s)://host[:port]` → `http(s)://host:port` (the core wants a port; 443 / 80 implied). */
export function normalizeServer(url: string): string {
  const m = /^(https?):\/\/([^\s/:]+|\[[0-9a-fA-F:]+\])(?::(\d+))?\/?$/.exec(url.trim());
  if (!m) return url.trim();
  return `${m[1]}://${m[2]}:${m[3] ?? (m[1] === "https" ? "443" : "80")}`;
}

export class OnboardingVm extends Vm<OnboardingState> {
  constructor(private core: Core, private keystore: Keystore, private defaultServer = "", network = "regtest") {
    super({ step: "start", restoring: false, seedWords: "", confirmIndexes: [], birthday: 0, serverUrl: defaultServer, tip: null, trustAccepted: false, busy: false, error: "", network });
  }
  private async run(f: () => Promise<void>) {
    this.set({ busy: true, error: "" });
    try { await f(); } catch (e) { this.set({ error: messageOf(e) }); } finally { this.set({ busy: false }); }
  }
  /** Create: a fresh phrase, shown once. */
  create() {
    return this.run(async () => {
      const seedWords = await this.core.new_seed_words();
      const n = seedWords.split(" ").length;
      const picks = new Set<number>();
      while (picks.size < 3) picks.add(Math.floor(Math.random() * n));
      // The birthday is set at the server step (checkServer), when the tip is known.
      this.set({ seedWords, restoring: false, confirmIndexes: [...picks].sort((a, b) => a - b), birthday: 0, step: "seed" });
    });
  }
  written() { this.set({ step: "confirm", error: "" }); }
  /** The confirm step: the words at `confirmIndexes`, typed back. */
  confirmWords(typed: string[]): boolean {
    const words = this.state.seedWords.split(" ");
    const ok = this.state.confirmIndexes.every((i, k) => (typed[k] ?? "").trim().toLowerCase() === words[i]);
    if (!ok) { this.set({ error: "Those are not the words at those positions. Check your written copy." }); return false; }
    this.set({ step: "server", error: "" }); return true;
  }
  startRestore() { this.set({ step: "restore", restoring: true, error: "" }); }
  restore(words: string, birthday: number) {
    const w = words.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (w.length !== 12 && w.length !== 24) { this.set({ error: "A recovery phrase has 12 or 24 words." }); return; }
    if (!Number.isInteger(birthday) || birthday < 0) { this.set({ error: "The birthday is a block height (0 = scan everything)." }); return; }
    this.set({ seedWords: w.join(" "), birthday, step: "server", error: "" });
  }
  checkServer(serverUrl: string) {
    return this.run(async () => {
      const url = normalizeServer(serverUrl);
      if (!/^https?:\/\/[^\s/]+:\d+$/.test(url)) throw new Error("invalid: a server is http(s)://host:port");
      if (url.startsWith("http://") && !/localhost|127\.0\.0\.1|\.local/.test(url) && !import.meta.env?.DEV) throw new Error("invalid: a plain connection is for a local devnet only");
      const tip = await this.core.latest_height(url, this.state.network);
      // A seed made here starts BIRTHDAY_MARGIN blocks below the tip; a restore keeps its own.
      const birthday = this.state.restoring ? this.state.birthday : Math.max(1, tip - BIRTHDAY_MARGIN);
      this.set({ serverUrl: url, tip, birthday });
    });
  }
  serverDone() { if (this.state.tip !== null) this.set({ step: "trust", error: "" }); }
  acceptTrust(accepted: boolean) { this.set({ trustAccepted: accepted }); }
  trustDone() { if (this.state.trustAccepted) this.set({ step: "unlock", error: "" }); }
  /** Encrypt the seed at rest and open the wallet. Seed words never persist in `state` after. */
  finish(unlock: Unlock) {
    return this.run(async () => {
      const s = this.state;
      await this.keystore.saveSeed(s.seedWords, unlock, { birthday: s.birthday, serverUrl: s.serverUrl, network: s.network, createdAt: Date.now() });
      await this.core.open(s.seedWords, s.birthday, s.serverUrl, s.network);
      this.set({ step: "done", seedWords: "" });
    });
  }
}
