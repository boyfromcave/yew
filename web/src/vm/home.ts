// Home (home.dart): numbers first — YED, YEC by type (private, public ECC, post-quantum by scheme;
// held and staged-for-mint apart, never in a total), price, sync progress from the
// core's callback (no polling), Receive / Send / Move.
import type { Balances, Core, MiningReward, ParamsProgress, ProgressEvent, RewardPreview } from "../core";
import { kindOf, messageOf } from "../core";
import { Vm } from "./base";

export interface HomeState { balances: Balances | null; progress: ProgressEvent | null; syncing: boolean; error: string; network: string;
  /** The last sync's note that post-quantum addresses were not looked up (empty when they were). */
  pqNote: string;
  /** beta4: the mining rewards (coinbase outputs), shown apart from every balance. */
  rewards: MiningReward[];
  /** The reward move being confirmed (its preview), and the result or refusal of the last one. */
  rewardPreview: RewardPreview | null; rewardNote: string;
  /** The address whose move waits for the proving parameters (a post-quantum reward is proved at preview), and
   *  the download's progress while it runs. */
  rewardParamsFor: string; rewardFetching: ParamsProgress | null }

export class HomeVm extends Vm<HomeState> {
  /** Called after every completed sync (manual or automatic): screens that show chain state refresh. */
  private synced: Array<() => void> = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  /** `paramsSources`: where a reward move's proving files are fetched from (Settings' Source; none = the core's). */
  constructor(private core: Core, private paramsSources: () => string[] = () => []) { super({ balances: null, progress: null, syncing: false, error: "", network: "", pqNote: "", rewards: [], rewardPreview: null, rewardNote: "", rewardParamsFor: "", rewardFetching: null }); }
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
  /** "Move to Sapling" for an address's mature mining rewards: the exact-amount preview, or the core's refusal.
   *  A post-quantum reward is proved at preview: without the proving parameters the card offers their download. */
  async previewReward(address: string) {
    this.set({ rewardPreview: null, rewardNote: "", rewardParamsFor: "" });
    try { this.set({ rewardPreview: await this.core.reward_move_preview(address) }); }
    catch (e) { this.set({ rewardNote: messageOf(e), rewardParamsFor: kindOf(e) === "params" ? address : "" }); }
  }
  /** Download the proving parameters (52 MB, once; verified against their pins) and preview the move again. */
  async fetchParamsForReward() {
    const address = this.state.rewardParamsFor; if (!address) return;
    try { await this.core.fetch_params((p) => this.set({ rewardFetching: p }), this.paramsSources()); }
    catch (e) { this.set({ rewardFetching: null, rewardNote: messageOf(e) }); return; }
    this.set({ rewardFetching: null });
    await this.previewReward(address);
  }
  /** Confirm the previewed move. A flagged fee is shown on the card (its note), so pressing Move accepts it. */
  async confirmReward() {
    const p = this.state.rewardPreview; if (!p) return;
    const ack = "unusualFeeAck" in p ? p.unusualFeeAck ?? undefined : undefined;
    try { const r = await this.core.confirm(p.previewId, ack); this.set({ rewardPreview: null, rewardNote: `Moved to your private balance: ${r.txid}` }); await this.load(); }
    catch (e) { this.set({ rewardPreview: null, rewardNote: messageOf(e) }); }
  }
  cancelReward() { this.set({ rewardPreview: null }); }
  async sync() {
    if (this.state.syncing) return;
    this.set({ syncing: true, error: "" });
    try { const r = await this.core.sync(); this.set({ pqNote: r.pq_unindexed ? (r.pq_note ?? "") : "" }); await this.load(); for (const f of this.synced) f(); } catch (e) { this.set({ error: messageOf(e) }); } finally { this.set({ syncing: false }); }
  }
}
