// Settings (settings.dart): the server, the trust statement, the proving files (status + fetch
// with progress), export WIF, import WIF, lock (close), forget.
import type { Core, ParamsProgress, ParamsStatus } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";
import type { WalletMeta } from "../keystore";
import { storeDirOf } from "../keystore";
export interface SettingsState {
  params: ParamsStatus | null; fetching: ParamsProgress | null; wif: string; error: string; status: string;
  /** Base URL (ending in `/`) the proving files are fetched from; "" = the standard source. */
  paramsSource: string;
}
export interface Forgettable { forget(): Promise<void> }
export class SettingsVm extends Vm<SettingsState> {
  constructor(private core: Core, private keystore: Forgettable, paramsSource = "", private network = "regtest") { super({ params: null, fetching: null, wif: "", error: "", status: "", paramsSource }); }
  private async run(f: () => Promise<void>) {
    this.set({ error: "", status: "" });
    try { await f(); } catch (e) { this.set({ error: messageOf(e) }); }
  }
  loadParams() { return this.run(async () => this.set({ params: await this.core.params_status() })); }
  fetchParams() {
    return this.run(async () => {
      const src = this.state.paramsSource.trim();
      try { await this.core.fetch_params((p) => this.set({ fetching: p }), src ? [src.endsWith("/") ? src : `${src}/`] : []); } finally { this.set({ fetching: null }); }
      this.set({ params: await this.core.params_status(), status: "Private sending files ready." });
    });
  }
  exportWif(address: string) { return this.run(async () => this.set({ wif: await this.core.export_wif(address.trim()) })); }
  clearWif() { this.set({ wif: "" }); }
  importWif(wif: string, birthday: number) { return this.run(async () => { await this.core.import_wif(wif.trim(), birthday); this.set({ status: "Key imported; sync to see its coins." }); }); }
  lock() { return this.run(() => this.core.close()); }
  /** Forget: the seed leaves the keystore first, then the core closes the wallet and deletes
   *  its store (`meta.storeDir`, else the network's default). */
  forget(meta: WalletMeta | null = null) {
    return this.run(async () => { await this.core.close().catch(() => {}); await this.keystore.forget(); await this.core.forget(storeDirOf(meta, this.network)); });
  }
}
