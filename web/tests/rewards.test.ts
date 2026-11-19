// @vitest-environment jsdom
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

// beta4: mining rewards (coinbase outputs) on Home, apart from every balance; a public address's mature
// rewards moved to Sapling at the exact amount; a post-quantum address's (FN-DSA-512, SLH-DSA) too, proved in the
// browser with the cached parameters, offered for download first when missing;
// the Receive screen's post-quantum tabs warn against mining payouts.
import { describe, expect, it } from "vitest";
import { MOCK_SEED, MockCore } from "../src/mock";
import { rewardFeeZat } from "../src/core";
import { HomeVm } from "../src/vm/home";
import { renderHome } from "../src/screens/home";
import { ReceiveVm } from "../src/vm/receive";
import { renderReceive } from "../src/screens/receive";

async function openWallet() { const c = new MockCore(); await c.open(MOCK_SEED, 0, "http://localhost:8080", "regtest"); return c; }
const PUB = "smMockMiner00000000000000000000000000";
const PQ = "rqfMockMiner000000000000000000000000000000000000000000";
const SLH = "rqsMockMiner000000000000000000000000000000000000000000";

describe("mining rewards", () => {
  it("home lists them apart, immature with blocks left; a public reward moves at the exact amount", async () => {
    const core = await openWallet();
    core.rewardRows = [
      { address: PUB, postQuantum: false, outpoint: "aa:0", valueZat: "1250000000", height: 400, maturesIn: 0 },
      { address: PUB, postQuantum: false, outpoint: "bb:0", valueZat: "625000000", height: 480, maturesIn: 21 },
    ];
    const vm = new HomeVm(core); await vm.load();
    const root = document.createElement("div"); renderHome(root, vm);
    expect(root.querySelector('[data-card="mining-rewards"]')?.textContent).toContain("Mining reward — shield first");
    expect(root.querySelector('[data-reward="immature"]')?.textContent).toMatch(/^6\.25\d* YEC matures in 21 blocks$/);
    (root.querySelector(`[data-reward-move="${PUB}"]`) as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 0));
    expect(vm.state.rewardPreview?.amountZat).toBe((1250000000n - BigInt(rewardFeeZat(vm.state.rewardPreview!))).toString());
    expect(root.querySelector('[data-reward="preview"]')?.textContent).toContain("Moves exactly");
    expect(core.broadcasts).toHaveLength(0);
    await vm.confirmReward();
    expect(core.broadcasts).toHaveLength(1);
    expect(vm.state.rewardNote).toContain("Moved to your private balance");
  });
  it("a post-quantum reward needs the proving parameters: offered for download, then moved at the exact amount", async () => {
    const core = await openWallet();
    core.rewardRows = [{ address: PQ, postQuantum: true, outpoint: "cc:0", valueZat: "1250000000", height: 400, maturesIn: 0 }];
    const vm = new HomeVm(core); await vm.load();
    const root = document.createElement("div"); renderHome(root, vm);
    (root.querySelector(`[data-reward-move="${PQ}"]`) as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 0));
    expect(vm.state.rewardPreview).toBeNull();
    expect(vm.state.rewardParamsFor).toBe(PQ);
    expect(root.querySelector('[data-reward="note"]')?.textContent).toContain("52 MB");
    (root.querySelector('[data-reward="fetch-params"]') as HTMLButtonElement).click();
    for (let i = 0; i < 5 && !vm.state.rewardPreview; i++) await new Promise((r) => setTimeout(r, 0));
    const p = vm.state.rewardPreview!;
    expect("feeZat" in p && p.changeZat).toBe("0");
    expect(BigInt(p.amountZat) + BigInt(rewardFeeZat(p))).toBe(1250000000n);
    expect(root.querySelector('[data-reward="fetch-params"]')).toBeNull();
    expect(core.broadcasts).toHaveLength(0);
    core.rewardRows = []; // the move spent the last reward: the card stays for its result
    await vm.confirmReward();
    expect(core.broadcasts).toHaveLength(1);
    expect(vm.state.rewardNote).toContain("Moved to your private balance");
    expect(root.querySelector('[data-reward="note"]')?.textContent).toContain("Moved to your private balance");
  });
  it("an SLH-DSA reward moves too, and a flagged fee is shown and accepted by Move", async () => {
    const core = await openWallet();
    await core.fetch_params(() => {});
    core.unusualPqFee = "This fee is unusual (mock).";
    core.rewardRows = [
      { address: SLH, postQuantum: true, outpoint: "dd:0", valueZat: "625000000", height: 400, maturesIn: 0 },
      { address: SLH, postQuantum: true, outpoint: "ee:0", valueZat: "625000000", height: 401, maturesIn: 0 },
    ];
    const vm = new HomeVm(core); await vm.load();
    const root = document.createElement("div"); renderHome(root, vm);
    await vm.previewReward(SLH);
    const p = vm.state.rewardPreview!;
    expect(BigInt(p.amountZat) + BigInt(rewardFeeZat(p))).toBe(1250000000n);
    expect(root.querySelector('[data-reward="fee-note"]')?.textContent).toContain("unusual");
    await vm.confirmReward();
    expect(core.broadcasts).toHaveLength(1);
    expect(vm.state.rewardNote).toContain("Moved to your private balance");
  });
  it("receive: the post-quantum tabs warn against mining payouts", async () => {
    const core = await openWallet(); const vm = new ReceiveVm(core);
    const root = document.createElement("div"); renderReceive(root, vm);
    await vm.show("pq_falcon"); await new Promise((r) => setTimeout(r, 0));
    expect(root.querySelector('[data-receive="pq-mining-warning"]')?.textContent).toContain("Not for mining payouts");
    await vm.show("transparent"); await new Promise((r) => setTimeout(r, 0));
    expect(root.querySelector('[data-receive="pq-mining-warning"]')).toBeNull();
  });
});
