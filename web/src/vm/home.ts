// Home (home.dart): numbers first — YED, YEC public/private, price, sync progress from the
// core's callback (no polling), Receive / Send / Move.
import type { Balances, Core, ProgressEvent } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";

export interface HomeState { balances: Balances | null; progress: ProgressEvent | null; syncing: boolean; error: string; network: string }

export class HomeVm extends Vm<HomeState> {
  constructor(private core: Core) { super({ balances: null, progress: null, syncing: false, error: "", network: "" }); }
  async attach() {
    await this.core.set_progress_callback((e) => this.set({ progress: e }));
    this.set({ network: await this.core.network().catch(() => "") });
  }
  async load() {
    try { this.set({ balances: await this.core.balances(), error: "" }); } catch (e) { this.set({ error: messageOf(e) }); }
  }
  async sync() {
    if (this.state.syncing) return;
    this.set({ syncing: true, error: "" });
    try { await this.core.sync(); await this.load(); } catch (e) { this.set({ error: messageOf(e) }); } finally { this.set({ syncing: false }); }
  }
}
