// Settings (settings.dart): the server, the trust statement, the proving files (status + fetch
// with progress), export WIF, import WIF, lock (close), forget.
import type { Core, ParamsProgress, ParamsStatus } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";
import type { WalletMeta } from "../keystore";
import { storeDirOf } from "../keystore";
import { hostedParamsText } from "../plain";
export interface SettingsState {
  params: ParamsStatus | null; fetching: ParamsProgress | null; wif: string; error: string; status: string;
  /** The address `wif` spends (shown with it: the key is never shown without the address it belongs to). */
  wifFor: string;
  /** Base URL (ending in `/`) the proving files are fetched from; "" = this page's own server, `/sapling-params/`. */
  paramsSource: string;
}
export interface Forgettable { forget(): Promise<void> }
export class SettingsVm extends Vm<SettingsState> {
  private wifSeq = 0;
  /** `hosted`: a hosted build, which fetches the proving files from its own site only (no mirror). */
  constructor(private core: Core, private keystore: Forgettable, paramsSource = "", private network = "regtest", private hosted = false) {
    super({ params: null, fetching: null, wif: "", wifFor: "", error: "", status: "", paramsSource: hosted ? "" : paramsSource });
  }
  private async run(f: () => Promise<void>) {
    this.set({ error: "", status: "" });
    try { await f(); } catch (e) { this.set({ error: this.hosted ? hostedParamsText(messageOf(e)) : messageOf(e) }); }
  }
  loadParams() { return this.run(async () => this.set({ params: await this.core.params_status() })); }
  fetchParams() {
    return this.run(async () => {
      const src = this.state.paramsSource.trim();
      try { await this.core.fetch_params((p) => this.set({ fetching: p }), src ? [src.endsWith("/") ? src : `${src}/`] : []); } finally { this.set({ fetching: null }); }
      this.set({ params: await this.core.params_status(), status: "Private sending files ready." });
    });
  }
  /** The previous key leaves the screen at once; only the answer to the latest export is shown (beta3). */
  exportWif(address: string) {
    const a = address.trim(), n = ++this.wifSeq;
    this.set({ wif: "", wifFor: "" });
    return this.run(async () => { const wif = await this.core.export_wif(a); if (n === this.wifSeq) this.set({ wif, wifFor: a }); });
  }
  clearWif() { this.wifSeq++; this.set({ wif: "", wifFor: "" }); }
  importWif(wif: string, birthday: number) { return this.run(async () => { await this.core.import_wif(wif.trim(), birthday); this.set({ status: "Key imported; sync to see its coins." }); }); }
  lock() { this.clearWif(); return this.run(() => this.core.close()); }
  /** Forget: the seed leaves the keystore first, then the core closes the wallet and deletes
   *  its store (`meta.storeDir`, else the network's default). */
  forget(meta: WalletMeta | null = null) {
    return this.run(async () => { await this.core.close().catch(() => {}); await this.keystore.forget(); await this.core.forget(storeDirOf(meta, this.network)); });
  }
}
