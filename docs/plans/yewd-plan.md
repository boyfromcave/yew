# yewd — the YEW core as a daemon: plan

**Revision 2 (2026-11-01), S1** (revision 1: S0). `yewd` is the third shell on the YEW core, in `yew/yewd/`
beside `yew/app/` and `yew/web/` (workspace decision K-22, the Yellowback lead architect,
2026-11-01): a ycashd-compatible wallet-RPC façade in front of a wallet-less node, kogany or
ycash6 `-disablewallet`. The normative plan is the workspace's
`docs/plans/kogany/kogany-yellowback-plan.md`: §3b (the S0–S5 track), §4.3 (the sidecar's rules),
§5 ("yewd's CI") and decisions K-20, K-22–K-26. This file records what the `yew` repository
carries for it, as `yew-web-plan.md` does for `web/`. Usage and the command-line contract:
[`yewd/README.md`](../../yewd/README.md).

## 0. Decisions that bind this shell

| # | Decision (workspace plan §0) | Consequence here |
|---|---|---|
| K-20 | the product is kogany + a parity sidecar on yew-core | `yewd` exposes the ycashd wallet RPCs by name and shape; goal: kogany + `yewd` == ycash6 functional parity |
| K-22 | the name is `yewd`, the home is `yew/yewd/` | one core, one CI, one release train; crates `yewd-facade` (binary `yewd`), `yewd-wallet`, `yewd-signer` (binary `yewd-signer`), `yewd-proto`; yew-core by path |
| K-23 | lightwalletd-dd for what yew-core already reads, node JSON-RPC for the rest, indexer streams as wake-ups | no yew-core change for S1 |
| K-24 | a separate signer process; the façade holds public material only | `yewd-signer`, Unix socket with a peer-UID check (S2) |
| K-25 | exactly what parity needs: the 47, R7, the 34 stock wallet RPCs, three raw helpers | the method table (`yewd/facade/src/methods.rs`); the rest of ycashd's wallet table answers `-32601` "not served" |
| K-26 | reject-reason parity and regtest `setmocktime` are added to kogany (W7-e) | nothing in `yew` |

## 1. Rules (workspace plan §4.3)

1. `yewd` is a client: public JSON-RPC, the gRPC indexer streams and lightwalletd-dd only; never a
   node change from this repository; never a kogany crate for state.
2. Keys live in the signer, never in the façade or the node.
3. Parity is not byte-identity: the same script's transactions are accepted by both lines and give
   the same state hashes and asserted values.
4. A core change `yewd` needs lands in `core/` in the same PR, covered by the core's tests;
   nothing server-only (sockets, daemons, the JSON-RPC server) enters yew-core.
5. One contract: ycash6 `doc/vault-rpc.md`, `doc/yellowback-rpc.md` and their JSON contracts.
6. Naming: Yellowback is the system, YED is the unit (workspace AGENTS.md rule 6).

## 2. Layout and build

`yewd/` is its own Cargo workspace, as `web/core-wasm` is, so the daemon's server dependencies
never enter the root `Cargo.lock` or `scripts/check-deps.sh`'s yew-core allow-list; the root's
`[patch.crates-io]` tables are repeated in `yewd/Cargo.toml` and must stay in step. `yewd/Cargo.lock`
started as a copy of the root lock, and S0 adds no third-party crate (hyper, hyper-util, tokio,
serde_json, base64, getrandom and hex at the versions the root lock already holds). The toolchain is
the repository's `rust-toolchain.toml`.

## 3. Chunks

| Chunk | Scope (workspace plan §3b) | State |
|---|---|---|
| S0 | the shell: crate layout, façade skeleton (auth, the full method table answering `-32601`, forwarding with the backend's cookie, `help`, `stop`), the `YEWD_BIN` harness contract, the `yewd` CI job | **this revision** |
| S1 | wallet state and sync; the read-only wallet subset (against ycash6 `-disablewallet`; kogany after W7-a/b) | **this revision** (§3.1) |
| S2 | builders and the signer boundary | — |
| S3 | roles: attestor `attest` mode, Hawkeye member, x402 `rpcWalletSigner` | — |
| S4 | the façade complete: all 47, R7, the K-25 stock set, error parity, hazards H1–H11 | — |
| S5 | the parity gate (three-way matrix, the 48 wallet-needing scripts, 7 nightly days) | — |

### S0 exit gate (as run)

- `cargo build` and `cargo test` of the `yewd` workspace pass (`yewd/scripts/check-yewd.sh`).
- `facade/tests/table.rs`: every one of the 82 listed wallet methods (22 + 25 + 1 + 30 + 4)
  answers `-32601` "yewd: not yet implemented" with HTTP 404 and never reaches the backend; the 39
  out-of-scope ones answer "not served"; node RPCs are forwarded byte for byte; batches, `help`,
  `stop`, auth and the warm-up answer.
- `facade/tests/regtest.rs`: a forwarded `getblockchaininfo` round-trips against ycashd regtest
  `-disablewallet` reached with its cookie, and equals the node's direct answer.
- Not yet run, needs the harness chunk's `YEWD_BIN`: a ycash6 regtest script with `KOGANY_BIN` +
  `YEWD_BIN`, and the contract suites' *n*/47 baseline.

### 3.1 S1: wallet state and sync

**What it serves.** `yewd-wallet/src/rpc.rs` `SERVED`: of the 47, `vault_getnewowner`,
`set_listsigned` (R5) and `yed_getnewaddress`, `yed_validateaddress`, `yed_getbalance`,
`yed_listunspent`, `yed_listpositions`, `yed_listtransactions`, `yed_listaddresses` (R6), so
**9/47**; of the K-25 stock set, `getbalance`, `getnewaddress` (with `"pq"`/`"pqslh"`),
`getreceivedbyaddress`, `gettransaction`, `getwalletinfo`, `listlockunspent`, `listunspent`,
`z_getbalance`, `z_getnewaddress`, `z_listunspent` (10/34). The augmented reads get their wallet
fields: `getinfo` (balance, keypool), `validateaddress` (`ismine`, `pubkey`, …), `z_validateaddress`
(answered by yewd itself, below), `vault_list` (the `wallet` column and the `mine` filter),
`set_getinfo` (`memberlist[].wallet`). The method table's classes are S0's; S1 only moved these
methods from "not yet implemented" to served.

**Keys (K-24, §4.3 rule 2).** The façade holds the signer's public bundle (`yewd-proto`
`PublicBundle`): the BIP32 account node `m/44'/347'/0'` (CKDpub for `/{0,1}/i`), the Sapling DFVK
of `m/32'/347'/0'`, and a lookahead pool of PQ public keys (`DerivePQSeed`, scheme 1 and 2) the
signer tops up on request. `yewd-signer` holds the phrase (`<datadir>/<net>/signer/seed.json`,
0600; encrypted in S4) and in S1 is run as a child process (`init`, `public`); S2 replaces that
with the Unix socket. The derivations are yew-core's (`keys.rs`, `shielded_keys.rs`, `pq.rs`), so
the same seed in the app sees the same coins; `yewd-wallet` tests prove CKDpub equals yew-core's
private tree and the diversified addresses equal `SaplingAccount::address_at`.

**Chain reading: node JSON-RPC, not lightwalletd-dd (against K-23 (a), recorded here).** K-23
(a) says lightwalletd-dd for what yew-core already reads. S1 reads whole blocks from the node
instead (`getbestblockhash`, `getblockhash`, `getblock <hash> 0`, `getblock <hash> 1` for
`trees.sapling.size`, `getrawmempool`, `getrawtransaction`), because:
(1) lightwalletd's `GetTaddressTxids`/`GetAddressUtxos` proxy `getaddresstxids`/`getaddressutxos`,
which need `-insightexplorer`; the harness starts ycash6 `-disablewallet` without it, so neither
lightwalletd-dd nor the node's address RPCs can answer;
(2) yew-core's `sync.rs` and `shielded.rs` operate on `Wallet` and `Shielded`, which hold the seed
and the Sapling spending key, so binding them in the façade breaks K-24 without a core change
(proposed below), and §4.3 rule 4 puts any such change in `core/` with its tests, outside this
chunk's paths;
(3) one block reader serves the transparent, PQ, Sapling and template sides with the reorg
handling in one place, and needs nothing of the node beyond Zakura's own read RPCs.
The cost is wall-clock on a long chain (a full scan from the birthday); a new seed's birthday is
the node's height at creation, so only restores pay it. S4 adds kogany's indexer streams as
wake-ups and may route the transparent reads through lightwalletd-dd if the barrier latency on
kogany calls for it. yew-core is bound directly (keys, scripts, the transaction parser, payloads,
PQ ids, vault templates, the early-redeem fee); its `api.rs` is not used.

**Sapling as a viewing wallet.** Trial decryption of every scanned Sapling output with the
external and internal IVKs (sapling-crypto, ZIP-212 grace), the note's position from the node's
tree size, its nullifier from the DFVK's `nk`, spent when a scanned spend reveals it. Witnesses and
spends are the signer's (S2; K-24: "the signer runs the whole Sapling build").

**Sync discipline (H1, H2, H5).** Every wallet RPC first syncs to the node's best block (the
barrier): fork point from a window of 288 recent block hashes, every wallet transaction above it
rewound (coinbase dropped, the rest to the mempool view), new blocks read whole, then the mempool
(transactions that left it unmined are dropped). A reorg deeper than the window rescans from the
birthday. A poll (`-walletpoll`, 1 s) keeps the wallet at the tip between calls; ycash6 has no
indexer streams, kogany's `ChainTipChange` replaces the poll as the wake-up in S4. While the node
cannot be reached a wallet RPC answers `-28`.

**Coinbase (H8).** `yewd -initwallet` creates the wallet before the node and prints its coinbase
address (the first external key, in the address book); ycash6 `-disablewallet` needs
`-mineraddress=<it> -minetolocalwallet=0`. One address for every coinbase: H8's "distinct
coinbase addresses" question stays S0's §9 record.

**The wallet-state API S2 builds on** (`yewd-wallet`): `Wallet::open(dir, network, Box<dyn Signer>,
birthday)`, `Wallet::sync(&dyn Node)` (the barrier), `Wallet::call(&dyn Node, method, &[Value]) ->
J`, `Wallet::augment(...)`; state `Wallet::st` (`state::State`: `wtx`, `book`, `issued`, `owners`,
`locks`, `tip`), keys `Wallet::book` (`keys::KeyBook`: `by_hash`, `pq_by_id`, `owns_script`),
`Wallet::view` (`sapling::Viewing`), derived `Wallet::coins: Vec<Coin>` and `Wallet::notes:
Vec<NoteRow>`, `Wallet::available_coins(asof)`, `Wallet::balance(asof, min_depth)`,
`Wallet::trusted`, `Wallet::mempool_spent`, `Wallet::parsed(txid)`, `Wallet::save`; the signer seam
`Signer::public(&PublicRequest)` (S2 adds the sign request beside it); `node::Node` (one JSON-RPC
call) and `json::J` (eight-decimal amounts from integer zatoshi). In `yewd-facade`:
`wallet::WalletService` (`call`, `local`, `augment`, `spawn_poll`), `wallet::SignerSource`,
`wallet::ProcessSigner`; `start_with(cfg, SignerSource)`.

**Proposed core change (for S2's PR, §4.3 rule 4):** a viewing-only constructor for
`shielded::Shielded` (the DFVK, no `SaplingAccount`), so S2's signer and the façade can share
yew-core's note store and light-client sync if the barrier moves to lightwalletd-dd.

### S1 exit gate (as run)

- `yewd/scripts/check-yewd.sh`: fmt, clippy `-D warnings`, the four crates' tests, including
  `wallet/tests/sync.rs` (a scripted chain: reorg to a fork point, a payment back to the mempool and
  evicted, a rescan below the window, the state file reloaded) and `signer/tests/pq_wallet_vectors.rs`.
- `pq_wallet_vectors.json` replays through the signer's derivation path (phrase → BIP39 seed →
  `DerivePQSeed` → the SLH-DSA key the bundle hands the façade; both sections, both schemes), read
  by path (kogany `testdata/yellowback/` via `YEWD_PQ_WALLET_VECTORS`, else yew's byte-identical
  copy) and refused unless it hashes to the `vector` line of `yewd/PIN`.
- `yewd/qa/s1_wallet_reads.py` on ycash6 `vaults/kogany-compat` (`65cb4ae0f` binaries, harness
  `f4967b0d7`): node 6 = ycash6 `-disablewallet` + yewd, nodes 0-5 plain ycashd. The read subset of
  `yellowback-rpc-contract.json` (`yed_getnewaddress`, `yed_validateaddress`, `yed_getbalance`,
  `yed_listunspent`, `yed_listpositions`, `yed_listtransactions`, `yed_listaddresses`) and of
  `vault-rpc-contract.json` (`vault_getnewowner` and its error, `set_listsigned`, `vault_list`,
  `set_getinfo`) checked by the suites' own checkers on non-empty answers (a YED transfer in, a raw
  mint whose owner is the yewd wallet's, a `vault_lock` to a yewd owner); the stock reads checked
  against the plain ycashd wallet's key sets and the chain (`gettxout`); then the soak: a node
  restart (yewd answers `-28` meanwhile), a yewd restart, `invalidateblock` reorgs of 2 and 10 blocks
  (the payment back to `confirmations: 0`, balances recomputed, `reconsiderblock`, the snapshot equal).
- Not run here, and why: the same gate on **kogany** (W7-a/b not merged; the harness's kogany
  backend for a yewd pair is the next harness step), and the unchanged `vault_rpc_contract.py` /
  `yellowback_rpc_contract.py` (they call S2's builders before their reads; S4's gate).

## 4. CI (workspace plan §5)

The `yewd` job in `.github/workflows/ci.yml`: the unit leg (`scripts/check-yewd.sh`, blocking) and
the backend round trip against ycashd from a trusted ycash6 run at the commit `yewd/PIN` names
(blocking). The contract legs (vs ycash6, then vs kogany + `yewd`) join when the harness lands.
yew's security workflows already scan `yewd/` for code; their lockfile inputs (OSV, cargo audit)
name only the root `Cargo.lock` and `app/pubspec.lock` and are to be extended to `yewd/Cargo.lock`.
