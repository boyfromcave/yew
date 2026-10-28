// Home (home.dart): numbers first — YED, YEC public/private, price, sync progress from the
// core's callback (no polling), Receive / Send / Move.
import type { Balances, Core, ProgressEvent } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";

export interface HomeState { balances: Balances | null; progress: ProgressEvent | null; syncing: boolean; error: string; network: string }

export class HomeVm extends Vm<HomeState> {
  /** Called after every completed sync (manual or automatic): screens that show chain state refresh. */
  private synced: Array<() => void> = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  constructor(private core: Core) { super({ balances: null, progress: null, syncing: false, error: "", network: "" }); }
  onSynced(f: () => void) { this.synced.push(f); return () => { this.synced = this.synced.filter((g) => g !== f); }; }
  /** The wallet syncs by itself: every `everyMs` while the page is visible, and when it becomes visible
   *  again (regtest mines a block every few seconds; a two-step mint only advances on a sync). */
  autoSync(everyMs = 8000) {
    this.stopAutoSync();
    const tick = () => { if (typeof document === "undefined" || document.visibilityState === "visible") this.sync(); };
    this.timer = setInterval(tick, everyMs);
    if (typeof document !== "undefined") document.addEventListener("visibilitychange", tick);
  }
  stopAutoSync() { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
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
    try { await this.core.sync(); await this.load(); for (const f of this.synced) f(); } catch (e) { this.set({ error: messageOf(e) }); } finally { this.set({ syncing: false }); }
  }
}
