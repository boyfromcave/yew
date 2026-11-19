// Home (home.dart): numbers first — YED, YEC by type (private, public ECC, post-quantum by scheme;
// held and staged-for-mint apart, never in a total), price, sync progress from the
// core's callback (no polling), Receive / Send / Move.
import type { Balances, Core, MiningReward, MovePreview, ProgressEvent } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";

export interface HomeState { balances: Balances | null; progress: ProgressEvent | null; syncing: boolean; error: string; network: string;
  /** The last sync's note that post-quantum addresses were not looked up (empty when they were). */
  pqNote: string;
  /** beta4: the mining rewards (coinbase outputs), shown apart from every balance. */
  rewards: MiningReward[];
  /** The reward move being confirmed (its preview), and the result or refusal of the last one. */
  rewardPreview: MovePreview | null; rewardNote: string }

export class HomeVm extends Vm<HomeState> {
  /** Called after every completed sync (manual or automatic): screens that show chain state refresh. */
  private synced: Array<() => void> = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  constructor(private core: Core) { super({ balances: null, progress: null, syncing: false, error: "", network: "", pqNote: "", rewards: [], rewardPreview: null, rewardNote: "" }); }
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
    try { this.set({ rewards: await this.core.mining_rewards() }); } catch { this.set({ rewards: [] }); }
  }
  /** "Move to Sapling" for an address's mature mining rewards: the exact-amount preview, or the core's
   *  refusal (a post-quantum address: the recovery path). */
  async previewReward(address: string) {
    this.set({ rewardPreview: null, rewardNote: "" });
    try { this.set({ rewardPreview: await this.core.reward_move_preview(address) }); } catch (e) { this.set({ rewardNote: messageOf(e) }); }
  }
  async confirmReward() {
    const p = this.state.rewardPreview; if (!p) return;
    try { const r = await this.core.confirm(p.previewId); this.set({ rewardPreview: null, rewardNote: `Moved to your private balance: ${r.txid}` }); await this.load(); }
    catch (e) { this.set({ rewardPreview: null, rewardNote: messageOf(e) }); }
  }
  cancelReward() { this.set({ rewardPreview: null }); }
  async sync() {
    if (this.state.syncing) return;
    this.set({ syncing: true, error: "" });
    try { const r = await this.core.sync(); this.set({ pqNote: r.pq_unindexed ? (r.pq_note ?? "") : "" }); await this.load(); for (const f of this.synced) f(); } catch (e) { this.set({ error: messageOf(e) }); } finally { this.set({ syncing: false }); }
  }
}
