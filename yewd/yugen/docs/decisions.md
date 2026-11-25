# yewd Yugen wallet: decisions and state (beta4 Yugen addendum §3.2, M1)

Provenance: keys, addresses, requests, notes, transfer, tree and statement are **Published**
(yugen-spec 0.5.1, d25a89c, `yugen-ref`, the Ycash developers' specification). The builder is
**Adapted** (`yugen-ref` `Wallet::build`, change: caller-set auxiliary flags, for `FLAG_LEAFFEE`).
The transaction envelope and `hashYugen` are **Original (the Ycash developers, 2026)**, a
proposal (yewd/yugen/docs/node-interface.md W-TX) built on ZIP-243 (**Published**, Zcash).

| Id | Decision | Options considered | Reason | Reverses if |
|---|---|---|---|---|
| Y-W1 | Separate Cargo workspace `yewd/yugen` (toolchain 1.98.1, own lock); spec and proof repos by path from `deps/`, checked out at `PINS` by `scripts/deps.sh` | git deps on `file://` URLs (break `yugen-ref`'s `../../yugen-falcon` path); path deps into the live repos (unpinned); join yewd's workspace (toolchain 1.92 too old for the provers) | pinned commits, yewd's lock and toolchain untouched | the proof crates publish a library release |
| Y-W2 | Provers linked as libraries, run as child processes `yewd-yugen prove a|b` in parallel, each verifying its own proof | in-process threads (one address space, footprints add); a prover daemon | memory isolation per system, footprint measurable per system, same binary | a signer-process prover is required (follow-up: move into `yewd-signer`) |
| Y-W3 | A: `e2::prove_consensus_leaf` (masked wallet program, row `CAT1_TREE_LEAF_SALTED`, rate 1/4, OS seeds); B: `statement04` + `ZkLeaf::setup("wallet/mode0/0.4", cs, 3)` (zk, rate 1/8, default build: Pin96 level, recursion feature on) | A unmasked shipped row; B `cat1` build | A: the repo's named production entry point; B: the configuration of its own 0.4 vector tests; the node's verifier must match (INTERFACES W-PROOF) | the lead architect fixes other rows |
| Y-W3b | Supersedes Y-W3 for System B (lead ruling 2026-11-24, Y-W3's publication step brought forward to M2): `yugen-proof-b2` 2b0cb46 with features `cat1t, blake3` (row Cat1, rate 1/8, 192 queries, BLAKE3 Merkle), `ZkLeaf::setup(WALLET_MODE0 = "wallet/mode0", cs, 3)`: `StatementId(..., zk)` with `wrapper_derives_public = true`, byte-equal to the bundle leaf key. System A unchanged: masked row `CAT1_TREE_LEAF_SALTED` = the bundle leaf row 8. `LEAF_PROOF_MAX_B` = 770,000 B in `prove.rs`, provisional pending spec 0.5.2 (0.5.1's 679,687 is below the ~760 KB proof) | keep Y-W3 (Pin96, SHA-256 Merkle, label `wallet/mode0/0.4`) | the bundler folds only leaves under its leaf key; tests `system_b_id_is_bundle_leaf_key`, `system_a_row_is_bundle_leaf_row_8` | the lead architect fixes another leaf row |
| Y-W4 | Deposits come from a P2PKH deposit key derived from the Yugen seed; `yugen_shield` funds it from yewd's transparent wallet (`sendtoaddress`) and spends that output unconfirmed | sign yewd's own UTXOs in its signer with a Yugen sighash (signer change) | no signer change at M1 | signer gains a Yugen sighash |
| Y-W5 | (superseded by Y-W12, docs/yugen-seed-at-rest.md) Wallet file JSON, seed in the clear (regtest/devnet only) | seal in the signer | M1 scope | before any public network |
| Y-W7 | Static address 0 handed out as its §12.1 full address in hex; memo to a request refused; withdrawals as leaf transfers (note + dummy, `value_balance` > 0, one vout, script from `validateaddress`); Yugen -> Sapling as withdraw-then-`z_sendmany`; a deposit may pay any static address directly | short address + record host (needs a host, M3); Sapling output inside a Yugen transaction (W-TX has no Sapling part; would need a Sapling prover in the wallet and a node rule change) | lead ruling 2026-11-24 (full spend matrix with and without memos); spec §9.2, §10, §12.1, §7.1, §7.9 r4 | the spec gives the full address a text form, or Yugen transactions gain Sapling parts |
| Y-W6 | Fee rung `m = 0`; anchor `wallet_anchor(tip)`; anchor resolved with the node's activation height (the reference's `resolve_anchor` uses the constant 4096) | | regtest activates by `-nuparams` | |

## Measured (M), Apple M-series, load ≈ 5, `/usr/bin/time -l`, 2026-11-24
Leaf transfer (1 note + 1 dummy, request + change): `yewd-yugen prove a` 1.17 s, peak footprint
546 MiB, proof 650 KB; `prove b` 1.47 s, 695 MiB, proof 291 KB (each includes setup and its own
verification). Above the plan's 174 MiB (A, non-hiding shipped row) and 1.27 GB (B) rows: A here is
the hiding consensus row.

## Found
- `yugen-proof-b2` 2b0cb46: the leaf-only build (`default-features = false`) does not compile
  (`src/phased.rs` refers to `crate::fold`, gated on `recursion`). Workaround: default features.
- `yugen-ref` `Wallet::build` never sets `FLAG_LEAFFEE`, so it cannot build a leaf-route transfer
  (spec §7.9); fixed here by Y-W2's adapted builder; suggest a parameter upstream in yugen-spec.

## Measured (M), 2026-11-24, Y-W3b build, load ≈ 6, `/usr/bin/time -l`
`yewd-yugen prove b` (cat1t, blake3): 1.0 to 1.3 s real, peak footprint 1.45 GB (1,454 MB; was
695 MiB under Pin96), proof 760,624 B (hex output 1.52 MB). Proof A 649,508 B (unchanged).

## Open / next
- Node side: the RPCs and W-TX of node-interface.md; `tests/e2e_regtest.rs` skips until set.
- Reorgs (scan assumes no rewind), static-address receive beyond address 0, bundle route, mailbox.

**Lead rulings (2026-11-24):** Y-W3 accepted for M1 on regtest/devnet only: the node's verifier must use exactly this proof setup. Before any public network, System B moves to the specification's consensus row (category 1 build) and System A keeps the masked row; that is a gate for publication, recorded in the beta4 addendum. Y-W4 accepted for M1 (deposit key funded from the transparent wallet; the node must accept the chained unconfirmed spend); the signer-sighash route is the later design. Y-W5 stands: regtest/devnet only.

## Y-W8 The one Yugen address (2026-11-24, ruling 9(a))

yewd shows one string, the Yugen address of proposal UX-1 (yugen-spec branch `ux-address` 104cc0b,
`spec/decision-yugen-address.md`): static address 0 in full form plus a fresh single-payer request,
or static only (`reusable`). The send side applies UX-1 P-3 (`wallet/src/yaddr.rs::choose`); paid
requests are kept in `wallet.json` `paid_requests`. Bech32m is coded in `yaddr.rs` because the
`bech32` crate caps at 1,023 characters. The deposit, static-hex and request calls are debug-only.
The pin stays yugen-spec 914f77a: the encoding lives in yewd until UX-1 is ruled and merged; then it
moves into yugen-ref and yewd re-pins. Vectors copied to `wallet/tests/data/yugen_address.json`.
Reverses with UX-1.

## Y-W8 Mailbox hosts in the wallet (ruling 11, 2026-11-24)

**Built:** `-yugenhosts=h1,h2` (yewd passes it to `yewd-yugen`). With it, static address 0 names the two
hosts (§12.1 hosts field), `yugen_getaddress` returns the short form (§12.2; 66 chars on mainnet `yqf`,
67 on regtest `yqrf`; 262/263 with the default fresh request), after writing the §12.3 record to both
hosts (deletion token derived from the seed). Paying a short address resolves it by one session of
`SYNC_ADDR_QUERIES` two-server DPF queries (real + cover), every answer checked against `aroot_h`
(§17.5); static-address payments are found only through the hosts' package buckets (four lists per
epoch, own + three covers; each entry's path checked against the note root both hosts publish and the
node's `root_after`); the direct chain scan stops trying packages.

| Option | Taken | Why |
|---|---|---|
| Full §17.8 schedule (sync only at h ≡ 0 mod 16 with jitter, carry queues) | no (devnet) | a payment to a short address would wait up to 16 blocks plus a session; the session shape (counts, order, covers, checks) is kept, the timing is not |
| §17.3 path records by DPF | no | a full path rides beside each package entry, which is downloaded whole anyway; path DPF is follow-up |
| §17.7 hybrid transport | no | plain HTTP on localhost; L-5 is open |
| DPF early termination (`Convert`) | no | output bit per leaf; answers are the same bytes, cost 32x evaluation (devnet tables are small) |

**Reverses if:** the lead requires the fixed schedule on the devnet (then `send` to a short address
returns "pending" and pays at the next sync).

## Y-W9 Yugen -> Sapling as one user action (2026-11-24, ruling 9(b); mirrors ycash6 N-S3)

**Built** (yewd `facade/src/yugen.rs` `to_sapling`): `yugen_send [zaddr, amount, {memo}]` to a Sapling
address withdraws `amount + 1000 zat` (spec §7.9 rule 4) to a fresh transparent address of yewd's own
wallet (`getnewaddress`, never shown), then `z_sendmany` from exactly that address, minconf 0, the hop
spent whole, no change, the memo on the Sapling output. One reply: `{operation: "yugen-to-sapling",
txid (Sapling leg), withdraw_txid, sapling_txid, amount, fee}`. Needed for it: yewd's wallet now reads
Yugen transactions (YEW core `Transaction::parse` knows group 0x59474e47 and skips the Yugen field;
zcash_primitives gets the transparent twin; txid per node N-D7), so the hop coin is seen in the
mempool and in blocks. Before this, any block holding a Yugen transaction stopped yewd's wallet scan.

| Option | Taken | Why |
|---|---|---|
| Fresh own t-address, spent whole, once (as N-S3) | yes | no change output on the hop, no address reuse; the only public link is the one the turnstile needs |
| Withdraw straight into a Sapling output | no | a Yugen transaction has no Sapling part (W-TX); needs a spec transaction shape |
| Reuse the deposit key as the hop | no | links every hop of the wallet to each other and to its deposits |
| Engine (yewd-yugen) does both legs | no | the engine has no Sapling signer or prover; yewd's wallet has both (zsend.rs) |

**What the hop reveals:** the withdrawal's `value_balance` (public by §7.1) and the hop output, which
equals `amount + 1000`; the next transaction spends it whole into one Sapling output. A watcher links
the two (adjacent, value minus the default fee): the transparent turnstile crossing ruling 10 requires to
be visible. Not revealed: which Yugen notes paid (the transfer's privacy), the Sapling recipient, the
memo. Timing: the forward follows within seconds (it does not wait for a block); a delay would not
unlink equal values.

**Reverses if:** the spec gains a Yugen-to-Sapling transaction shape, or the lead wants the hop amount
padded/split.

## Y-W10 The fixed sync schedule and the short address by default (2026-11-24, rulings 15, 16)

**Built:** `yugen_getaddress` returns the short Yugen address (67 chars on regtest `yqrf`, 66 on
mainnet `yqf`) by default; `[{"onetime": true}]` adds a fresh payment request (263/262). A sender still
prefers the request when the string has one (UX-1 P-3, unchanged). yewd runs the engine's scheduled
`sync` after every block `h ≡ 0 (mod 16)` at a delay drawn from `[0, 60]` s (`-yugensyncdelay` lowers
the bound for a devnet); the session waits while the hosts have not taken that boundary's snapshot (the
same for every wallet). A session: the address queries (exactly `SYNC_ADDR_QUERIES` = 2 to each host,
real ones for the oldest queued payments to short addresses, cover for the rest; none while `n_h = 0`),
then the package lists of every epoch since the last session; at most 96 periods per session
(`schedule.rs`). A payment to a short address not resolved before is queued (`{"status": "pending",
"next_sync"}`) and built at the session that resolves it; resolved addresses are cached, so a later
payment pays at once. `yugen_sync` no longer runs a session (chain scan and schedule state only);
`yugen_getbalances` gives `spendable`, `pending` (found, not yet anchored, or change), `outgoing_pending`.
The chain scan of the wallet's own node is not a host message and still runs on every call.

Not yet (spec §17.8 items not built, unchanged from Y-W8): §17.3 path queries (8 per session; a full
path rides with each package entry), §17.1 slim slices and slot queries (requests are found by the chain
scan), §17.7 transport, item 6 posts. The record write (`yh_putrecord`) is still sent when the address is
shown, not as a post in its own session.

**Reverses:** Y-W8's "Full §17.8 schedule: no (devnet)".

**Y-W9 status (walk m3, 2026-11-24): YELLOW.** The withdraw leg works; the Sapling leg is refused by the
node: `old-consensus-branch-id (Expected 59474e30, found 6d5b7a31)`. Missing: yewd's wallet builds and
signs every transaction under the Vault branch id (`core/src/build/*` `VAULT_BRANCH_ID`), and the
librustzcash6 pin (`a4935c51`) has no `BranchId::Yugen`, so zcash_primitives cannot compute a ZIP-243
sighash or Sapling binding signature under 0x59474e30. Fix: librustzcash6 adds `NetworkUpgrade::Yugen`
/ `BranchId::Yugen = 0x59474e30` (v4-only, as Vault), yewd re-pins and picks the branch id of the next
block (`getblockchaininfo.consensus.nextblock`) instead of the constant. Until then every yewd
wallet send (transparent, PQ, Sapling) fails once Yugen is active; the hop coins stay spendable.

**Y-W11 (2026-11-24): yewd signs under the next block's branch, Yugen included.** Fixes Y-W9's YELLOW
(`old-consensus-branch-id (Expected 59474e30, found 6d5b7a31)`). yewd already took the transparent
signing branch from `getblockchaininfo.consensus.nextblock`; what failed was the pin: librustzcash6
`a4935c51` has no `BranchId::Yugen`, so the Sapling builder (signer, `hybrid::sapling_prepare`) could not
parse or sign under 0x59474e30, and its regtest parameters knew no Yugen height. Done: a local branch
`yugen/wallet` of librustzcash6 (a local worktree) =
`a4935c51` + the two Yugen commits of `yugen/node` (cd7190fd, 068f0592; `yugen/node` itself lacks
a4935c51's rusqlite/fee/testnet commits, so it cannot be pinned as is); a local branch `yugen/wallet` of
x402-ycash (b91140e + `LocalNetwork.yugen`); yewd/Cargo.toml `[patch]`es both git
sources to those paths; `upgrades_spec` passes `yugen=<h>` from `upgrades["59474e30"]`. Options: re-pin
by local git rev (`file://`) or by path. Chosen: path, so the yew root manifest and core keep their
upstream git pins and only yewd (the Yugen-carrying shell) changes. Test: `yewd/qa/yugen_branch_sends.py`
(ECC, Sapling, SLH-DSA and FN-DSA sends from yewd under Vault and again under Yugen from the activation
block on): passed 12/12. Reverses: librustzcash6 merging Yugen on its own line, then a plain rev pin.
Reversed for publication: the path patches are dropped; every manifest pins librustzcash6 `c7f0a0a0`
(upgrade/yugen) and x402-ycash-light `192d96e` (upgrade/yugen) by git rev.
