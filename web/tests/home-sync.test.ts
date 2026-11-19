// beta4 list item 6: the web wallet syncs when there is something to sync, and a background sync
// that finds little to do changes nothing the user sees.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MOCK_SEED, MockCore } from "../src/mock";
import { HomeVm, hasPending, pacing } from "../src/vm/home";
import { syncedLine } from "../src/screens/home";

const PACE = { baseMs: 1000, maxMs: 4000, fullEveryMs: 1_000_000, catchUpBlocks: 10 };

/** A wallet opened and synced once (as main.ts does), with counters on the core's calls and a
 *  record of every `syncing` / `progress` / `error` the screen would have drawn. */
async function setup() {
  const core = new MockCore();
  await core.open(MOCK_SEED, 0, "http://localhost:8080", "regtest");
  const calls = { sync: 0, probe: 0 };
  const sync = core.sync.bind(core);
  core.sync = () => { calls.sync++; return sync(); };
  const probe = () => { calls.probe++; return core.latest_height("http://localhost:8080", "regtest"); };
  const vm = new HomeVm(core);
  await vm.attach(); await vm.load(); await vm.sync();
  calls.sync = 0;
  const seen = { syncing: [] as boolean[], progress: 0, errors: [] as string[] };
  vm.subscribe(() => { seen.syncing.push(vm.state.syncing); seen.errors.push(vm.state.error); });
  const progress = vm.state.progress;
  const progressed = () => vm.state.progress !== progress;
  return { core, vm, calls, probe, seen, progressed };
}

describe("home auto sync (beta4 item 6)", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("a quiet chain: only tip checks, backing off, and nothing on screen changes", async () => {
    const { vm, calls, probe, seen, progressed } = await setup();
    vm.autoSync(probe, PACE);
    await vi.advanceTimersByTimeAsync(20_000);
    vm.stopAutoSync();
    expect(calls.sync).toBe(0);
    // at 1 s, 2.5, 4.75, 8.125, then every 4 s: 6 checks in 20 s, not 20
    expect(calls.probe).toBe(6);
    expect(seen.syncing).toEqual([]);
    expect(progressed()).toBe(false);
  });

  it("a new block: one background sync, never shown as syncing; the quiet line moves", async () => {
    const { core, vm, calls, probe, seen, progressed } = await setup();
    const before = vm.state.tip;
    let ran = 0; vm.onSynced(() => ran++);
    vm.autoSync(probe, PACE);
    core.mine(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(calls.sync).toBe(1);
    expect(ran).toBe(1);
    expect(vm.state.tip).toBe(before! + 1);
    expect(seen.syncing.every((s) => !s)).toBe(true);
    expect(progressed()).toBe(false);
    // and no second sync while the chain stays put
    await vi.advanceTimersByTimeAsync(10_000);
    vm.stopAutoSync();
    expect(calls.sync).toBe(1);
  });

  it("a catch-up of many blocks is shown", async () => {
    const { core, vm, calls, probe, seen } = await setup();
    vm.autoSync(probe, PACE);
    core.mine(25);
    await vi.advanceTimersByTimeAsync(1000);
    vm.stopAutoSync();
    expect(calls.sync).toBe(1);
    expect(seen.syncing).toContain(true);
    expect(vm.state.syncing).toBe(false);
  });

  it("a pending transaction of the wallet's syncs at every check until it settles", async () => {
    const { core, vm, calls, probe } = await setup();
    core.setPendingZat("5000");
    await vm.load();
    vm.autoSync(probe, PACE);
    await vi.advanceTimersByTimeAsync(1000);
    expect(calls.sync).toBe(1);
    core.setPendingZat("0");
    await vi.advanceTimersByTimeAsync(1000);
    expect(calls.sync).toBe(2); // this sync sees it settled
    await vi.advanceTimersByTimeAsync(10_000);
    vm.stopAutoSync();
    expect(calls.sync).toBe(2);
  });

  it("a full sync at least every fullEveryMs, for a payment still in the mempool", async () => {
    const { vm, calls, probe } = await setup();
    vm.autoSync(probe, { ...PACE, fullEveryMs: 10_000 });
    await vi.advanceTimersByTimeAsync(9_000);
    expect(calls.sync).toBe(0);
    await vi.advanceTimersByTimeAsync(4_000); // the check at 12.125 s is past 10 s

    vm.stopAutoSync();
    expect(calls.sync).toBe(1);
  });

  it("a failing server: the error stays up, not cleared and set again at every check", async () => {
    const { core, vm, probe, seen } = await setup();
    core.setFailNetwork(true);
    vm.autoSync(probe, { ...PACE, fullEveryMs: 0 });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(vm.state.error).toContain("network");
    const shown = seen.errors.slice(seen.errors.indexOf(vm.state.error));
    expect(shown.every((e) => e === vm.state.error)).toBe(true);
    // the server answers again: the next check clears it
    core.setFailNetwork(false);
    await vi.advanceTimersByTimeAsync(5000);
    vm.stopAutoSync();
    expect(vm.state.error).toBe("");
  });

  it("the Sync button during a background sync shows it and waits for it", async () => {
    const core = new MockCore({ delayMs: 500 });
    const o = core.open(MOCK_SEED, 0, "http://localhost:8080", "regtest"); await vi.advanceTimersByTimeAsync(600); await o;
    const vm = new HomeVm(core);
    const a = vm.attach(); await vi.advanceTimersByTimeAsync(2000); await a;
    const p = vm.sync(); await vi.advanceTimersByTimeAsync(2000); await p; // the first sync
    vm.autoSync(() => core.latest_height("x", "regtest"), PACE);
    core.mine(1);
    await vi.advanceTimersByTimeAsync(1600); // the probe answered; the background sync is in flight
    expect(vm.state.syncing).toBe(false);
    const manual = vm.sync();
    expect(vm.state.syncing).toBe(true);
    await vi.advanceTimersByTimeAsync(2000); await manual;
    vm.stopAutoSync();
    expect(vm.state.syncing).toBe(false);
  });

  it("pacing follows the network; pending balances are read", () => {
    expect(pacing("regtest").baseMs).toBeLessThan(pacing("test").baseMs);
    expect(pacing("main").maxMs).toBeLessThanOrEqual(75_000);
    expect(hasPending(null)).toBe(false);
    expect(syncedLine(Date.UTC(2026, 10, 18, 14, 5), 512017)).toMatch(/^Synced .+ · block 512,017$/);
  });
});
