// Home (home.dart): numbers first — YED, YEC by type (private, public ECC, post-quantum by scheme;
// held and staged-for-mint apart, never in a total), price, sync progress from the
// core's callback (no polling), Receive / Send / Move.
import type { Balances, Core, ProgressEvent } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";

export interface HomeState { balances: Balances | null; progress: ProgressEvent | null;
  /** A sync the user sees: one they asked for, the first after opening, or a background catch-up of
   *  several blocks. A background sync that finds little to do never sets it (beta4 list item 6). */
  syncing: boolean; error: string; network: string;
  /** The last sync's note that post-quantum addresses were not looked up (empty when they were). */
  pqNote: string;
  /** When the last sync completed (ms since the epoch), and the tip it reached: shown quietly. */
  lastSyncAt: number | null; tip: number | null }

/** How the wallet follows the chain by itself (beta4 list item 6). It asks the server for its tip
 *  (one `GetLatestBlock`) every `baseMs`, backing off by half again per quiet check up to `maxMs`,
 *  and runs the full sync only when the tip moved, a transaction of the wallet's is pending, or
 *  `fullEveryMs` passed since the last one (an incoming payment still in the mempool). A background
 *  sync is shown only when the tip moved by `catchUpBlocks` or more. */
export interface Pacing { baseMs: number; maxMs: number; fullEveryMs: number; catchUpBlocks: number }

/** The pace for a network: regtest mines a block every few seconds (the devnet suites wait on it);
 *  testnet and mainnet target one every 75 s, so a tip check every 20 to 60 s keeps the wallet
 *  within a block of the chain at a small fraction of a full sync's cost to the server. */
export function pacing(network: string): Pacing {
  return network === "regtest"
    ? { baseMs: 3000, maxMs: 8000, fullEveryMs: 30_000, catchUpBlocks: 10 }
    : { baseMs: 20_000, maxMs: 60_000, fullEveryMs: 300_000, catchUpBlocks: 10 };
}

/** A balance that is still settling: something of the wallet's waits for a block. */
export function hasPending(b: Balances | null): boolean {
  if (!b) return false;
  const nz = (s: string) => { try { return BigInt(s) !== 0n; } catch { return false; } };
  return nz(b.yecPendingZat) || nz(b.yedPendingCents) || nz(b.shieldedPendingZat) || nz(b.stagedForMintZat)
    || b.shieldedSpendableZat !== b.shieldedZat;
}

export class HomeVm extends Vm<HomeState> {
  /** Called after every completed sync (manual or automatic): screens that show chain state refresh. */
  private synced: Array<() => void> = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private onVisible: (() => void) | null = null;
  private probe: (() => Promise<number>) | null = null;
  /** Between autoSync and stopAutoSync. */
  private auto = false;
  private pace: Pacing = pacing("");
  private delay = 0;
  private lastFullAt = 0;
  /** The sync in flight, whoever started it: a second one waits for it instead. */
  private running: Promise<void> | null = null;
  /** The core's last progress event: shown only while a sync is visible. */
  private lastProgress: ProgressEvent | null = null;
  constructor(private core: Core) { super({ balances: null, progress: null, syncing: false, error: "", network: "", pqNote: "", lastSyncAt: null, tip: null }); }
  onSynced(f: () => void) { this.synced.push(f); return () => { this.synced = this.synced.filter((g) => g !== f); }; }
  /** The wallet syncs by itself while the page is visible, and checks at once when it becomes visible
   *  again. `probe` answers the server's tip cheaply (`Core.latest_height`); without it every check is
   *  a full sync, still in the background. `pace` overrides the network's pacing (tests). */
  autoSync(probe?: () => Promise<number>, pace?: Partial<Pacing>) {
    this.stopAutoSync();
    this.auto = true;
    this.probe = probe ?? null;
    this.pace = { ...pacing(this.state.network), ...pace };
    this.delay = this.pace.baseMs;
    this.lastFullAt = Date.now();
    this.schedule(this.delay);
    if (typeof document !== "undefined") {
      this.onVisible = () => { if (document.visibilityState === "visible") { this.delay = this.pace.baseMs; this.schedule(0); } };
      document.addEventListener("visibilitychange", this.onVisible);
    }
  }
  stopAutoSync() {
    this.auto = false;
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    if (this.onVisible && typeof document !== "undefined") document.removeEventListener("visibilitychange", this.onVisible);
    this.onVisible = null; this.probe = null;
  }
  private schedule(ms: number) {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => { this.timer = null; void this.tick(); }, ms);
  }
  /** One background check: the tip, then a full sync only when there is something to sync. */
  async tick() {
    if (typeof document !== "undefined" && document.visibilityState !== "visible") return; // resumes on visibilitychange
    let moved = true, behind = 0;
    if (this.probe) {
      try {
        const tip = await this.probe();
        moved = this.state.tip === null || tip !== this.state.tip;
        behind = this.state.tip === null ? 0 : tip - this.state.tip;
      } catch { moved = false; } // the sync below says what is wrong, at the backed-off pace
    }
    const pending = hasPending(this.state.balances);
    const due = moved || pending || Date.now() - this.lastFullAt >= this.pace.fullEveryMs || !this.probe;
    if (due && !this.running) await this.run(behind >= this.pace.catchUpBlocks);
    // the base pace while the chain moves or something of ours waits for a block, else back off
    this.delay = moved || pending ? this.pace.baseMs : Math.min(this.pace.maxMs, Math.round(this.delay * 1.5));
    if (this.auto) this.schedule(this.delay);
  }
  async attach() {
    await this.core.set_progress_callback((e) => { this.lastProgress = e; if (this.state.syncing) this.set({ progress: e }); });
    this.set({ network: await this.core.network().catch(() => "") });
  }
  async load() {
    try { this.set({ balances: await this.core.balances(), error: "" }); } catch (e) { this.set({ error: messageOf(e) }); }
  }
  /** A sync the user sees (the Sync button, the first after opening). A background sync already
   *  running is shown from here on and waited for. */
  async sync() {
    if (this.running) {
      if (!this.state.syncing) this.set({ syncing: true, progress: this.lastProgress });
      await this.running;
      return;
    }
    await this.run(true);
  }
  private async run(visible: boolean) {
    if (visible) this.set({ syncing: true, error: "" });
    const job = (async () => {
      try {
        const r = await this.core.sync();
        this.lastFullAt = Date.now();
        const balances = await this.core.balances();
        this.set({ balances, pqNote: r.pq_unindexed ? (r.pq_note ?? "") : "", tip: r.tip, lastSyncAt: Date.now(), error: "" });
        for (const f of this.synced) f();
      } catch (e) {
        const error = messageOf(e);
        if (error !== this.state.error) this.set({ error });
      }
    })();
    this.running = job;
    try { await job; } finally { this.running = null; if (this.state.syncing) this.set({ syncing: false }); }
  }
}
