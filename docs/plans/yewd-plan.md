# yewd — the YEW core as a daemon: plan

**Revision 4 (2026-11-01), S3** (revision 3: S2; revision 2: S1; revision 1: S0). `yewd` is the third shell on the YEW core, in `yew/yewd/`
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
| S2 | builders and the signer boundary | **this revision** (§3.2): 40/47; the Sapling build in the signer remains (F-S2-8) |
| S3 | roles: attestor `attest` mode, Hawkeye member, x402 `rpcWalletSigner` | **this revision** (§3.3): 47/47 |
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

### 3.2 S2: builders and the signer boundary

**What it serves.** Of the 47: all 22 R5 RPCs (`wallet/src/vaultrpc.rs`: the act RPCs, the vault
RPCs, the remembered builds of 07/N-2 with re-funding, `HandoffSend`'s foreign-input and outflow
refusals and its preview) and 18 of the 25 R6 RPCs (`wallet/src/yed.rs`: `yed_send`, `yed_sendmany`,
`yed_estimatesend`, `yed_redeem`, `yed_estimateredeem`, `yed_lockcoins`, `yed_unlockcoin`;
`mint.rs`: `yed_mint` in the two-step flow, `wait` or the poll, `yed_sweepcarriers`; `claim.rs`:
`yed_claim`, `yed_claimnotice`'s unarmed refusal) — **40/47**; the seven left are S3's
(`yed_buildcancel`, `yed_signcancelcosign`, the five attestor RPCs). Of the K-25 stock set:
`sendtoaddress`, `sendmany`, `lockunspent`, `fundrawtransaction`, `signrawtransaction`,
`getrawchangeaddress` (16/34 with S1's reads). Not yet: `z_sendmany` and its three operation RPCs,
a Sapling `from`/`to` of `yed_mint`/`yed_redeem` (the Sapling build in the signer, below).

**How the builders bind yew-core (F-S2-2).** yew-core's builders take its `Wallet` (the seed, the
SQLite store, the gRPC client) and sign in-process, so the façade cannot call them without breaking
K-24. S2 binds yew-core's pure parts instead — the floor-aware selector (`coinselect.rs`), the
payload codec, the V/I templates (`vault.rs`), `build::redeem::plan_vault_spend`,
`build::claim::plan_claim`, the ZIP-243 sighash and serializer (`tx.rs`), the fee and price
arithmetic (`params.rs`) — and takes the facts ycashd reads in-process from node RPCs
(`yed_getinfo`, `yed_getvault`, `yed_estimatecollateral`, `yed_listclaimable`, `yed_getfeepayee`,
`yed_buildbundle`, `set_getinfo`, `vault_list`, `gettxout`), with the node's dry run
(`yed_validaterawtransaction`: MINT-1..10, RED-1..5, MP-1) before a YED transaction is committed. No
yew-core change was needed; the viewing-only `Shielded` constructor S1 proposed waits for the
Sapling build in the signer.

**The signer (K-24).** Protocol version 1 (`yewd-proto`; README "The signer"): requests `hello`,
`public`, `sign`, `sign_act`, `sign_set`, `list_signed`, `import_signed`, `acknowledge_restore`
over a mode-0600 Unix socket with a peer-UID check; every input bound to a prevout (outpoint,
script, amount), every key named by derivation and checked against its script, the preview and the
outflow recomputed from the bytes, every digest recomputed. The sign-once records live in the
signer (`signonce.json`, fsynced before a signature leaves). The YV act codec and the set messages
are re-derived from ycash6 `src/vault/act.cpp` (plan §4.3 rule 1) and checked against
`vault_vectors.json`.

**Findings.**
- **F-S2-1** (interface): a Unix socket address takes at most 104 bytes on macOS and the harness's
  datadirs are longer; resolution: `<signer dir>/signer.sock` when it fits, else
  `/tmp/yewd-<uid>/<16 hex of SHA-256(dir)>.sock` (directory 0700, owner-checked), computed alike on
  both ends.
- **F-S2-2** (above): yew-core's builders are bound to its signing `Wallet`; S2 composes its pure
  parts with node facts. Proposed mapping §24 row: "M24-xx | YEW builds and signs in one `Wallet` |
  the façade holds no key | pure planners + node facts in `yewd-wallet`, signatures in `yewd-signer` |
  interface".
- **F-S2-3** (decision): ycashd's `ValidateSetSpend` (`set-sign-invalid`) runs `vault::CheckTx` on the
  unsigned spend in-process; no RPC dry-runs an unsigned set spend. yewd judges the structural part
  (a cancel before the intent's delay, an unlock's intents and byte-identical re-lock, S-2's value) and
  lets the rest reach the node at `vault_send`. Proposed: an additive node read for W7-b (a set-spend
  dry run), C++ lines first (§4.3 rule 5).
- **F-S2-4** (decision): while the attestation layer is armed, a mint's or claim's attestor fee
  payee (AFEE-W, `DefaultAttestPayee`) and a claim notice's `pEmerg` are not reported by any RPC in a
  form a wallet-less builder can use; yewd refuses those cases ("not served yet"). Unarmed mints and
  claims (the regtest default) are served. Proposed: `yed_estimatecollateral` / `yed_listclaimable`
  report `attestPayee` (additive, C++ lines first).
- **F-S2-5** (record): yew-core's `gate.rs` classifies inputs from its store; the signer has none.
  The signer applies its own path shapes plus the preview and outflow checks; `gate.rs` proper would
  need façade-supplied classes it cannot verify.
- **F-S2-6** (record): ycashd's one-shot vault builders sign with no outflow limit; the signer always
  enforces one, so the façade passes the outflow the request implies (amount + flat fee + folded
  change). No contract value changes.
- **F-S2-7** (decision for S4): `signrawtransaction` with `privatekeys` (even `[]`, the x402 verify
  call) is forwarded to the node, so keys never enter the façade; kogany has no `signrawtransaction`
  (W7), so that form needs a kogany RPC or a local verifier.
- **F-S2-8** (remaining work): the Sapling build in the signer (`z_sendmany` t→z/z→t/z→z, its
  operation ids, a Sapling `from`/`to` in `yed_mint`/`yed_redeem`) needs note witnesses; the façade
  tracks note positions only. Plan: the façade keeps incremental witnesses during its block scan (the
  frontier from `z_gettreestate`, then each block's commitments) and hands notes and witnesses to the
  signer, which holds the spending key and proves.
- **F-S2-9** (harness): `kogany.start_yewd_pair` can reach a backend that listens before it writes its
  cookie and fails on the 401; the S2 gate treats that 401 as warm-up. For the harness chunk.

### S2 exit gate (as run)

- `yewd/scripts/check-yewd.sh`: fmt, clippy `-D warnings`, the crates' tests, including
  `signer/tests/vault_vectors.rs` (`acts[]`, `actsInvalid[]`, `actScriptsInvalid[]`, `setSigMsgs[]`,
  `signatures[]`, `signaturesInvalid[]`, `ownerSpends[]` replayed through the signer's codecs and
  signing functions, byte for byte) and `signer/tests/policy.rs` (the refusals: no prevout, a prevout
  not spent, a negative amount, a key not owning its script, a lying preview — mutated amount, swapped
  recipient, foreign input, wrong fee —, outflow above the cap, template inputs on the YEC path, owner
  keys off the owner path, sign-once across a signer restart, a restored seed until acknowledged,
  another protocol version, the socket's mode). `pq_wallet_vectors.json` has no signing section; its
  derivation section replays as in S1.
- `yewd/qa/s2_wallet_builders.py` on ycash6 `vaults/kogany-compat` (`65cb4ae0f` binaries, harness
  `f4967b0d7`), **passing** (exit 0): node 6 = ycash6 `-disablewallet` + yewd + its signer, nodes 0-5
  plain ycashd. Every transaction yewd built was accepted and confirmed by all seven nodes with equal
  `vault_getinfo.statehash` and `yed_getstatehash` at each checkpoint, and each chain object compared
  with the same request made of ycashd: YEC (`sendtoaddress`, `sendmany`, `lockunspent`,
  `getrawchangeaddress`, `signrawtransaction` with and without keys, `fundrawtransaction`); sets
  (`set_create` beside ycashd's, `set_join` complete and cosigned both ways, `set_signact`,
  `set_sendact`, `set_heartbeat`, `set_buildact`, dry-run previews, three documented errors); vaults
  (`vault_lock` beside ycashd's, `vault_buildunlock` new/reused/refused, `set_signunlock` across yewd
  and ycashd, `vault_send`, a ycashd intent cancelled by yewd with `vault_buildcancel` +
  `set_signcancel`, the sign-once refusal and `set_importsigned`/`set_acknowledgerestore`,
  `vault_release`, `vault_refee`, `vault_ownerspend` — the SLH-DSA owner spend made in the signer —,
  the template-kind refusals); YED (`yed_mint` two-step beside ycashd's with `yed_getvault` and
  `yed_gettxinfo` equal but for byte-level fields, `yed_estimatesend`, `yed_send` beside ycashd's,
  `yed_sendmany`, `yed_estimateredeem`/`yed_redeem` early beside ycashd's, `yed_lockcoins`,
  `yed_unlockcoin`, the H7 `sendrawtransaction` guard, `yed_claim` after a price crash beside
  ycashd's, the claimant intent released to CLAIMED, `yed_sweepcarriers`): 28 of the 40 served build
  RPCs exercised on chain. Served but not exercised by the gate: `set_leave`, `set_equivocation`,
  `vault_app`, `yed_claimnotice` (its unarmed refusal).
- Not run here: the same gate on kogany (W4/W5/W7 not merged), and the mixed kogany + ycash6-peer
  acceptance check of the plan's S2 row (the acceptance by every ycash6 node of the network is what
  this gate checks).

### 3.3 S3: roles

**What it serves.** The seven S2 left (`wallet/src/attest.rs`): `yed_registerattestor` (a `set_join`
of a fresh wallet key to the attestor set, D-Q-30's floor and `bond-near-min` warning from
`yed_getinfo.params.attest`), `yed_signattestation` and `yed_revive` (the guarded attestation; the
revive's `SET_HEARTBEAT`), `yed_withdrawbond` (the bond's CLTV path, `KeyRef::Bond`),
`yed_reportequivocation` (EQV-1's conditions from `yed_listattestors` and the chain, the carrier of
exactly the two attestations, the `EQUIVOCATION` payload; `wait` or the poll), `yed_signcancelcosign`
and `yed_buildcancel` (the claim's target, `CurrentMember`, the refund and the `CANCEL_COSIGN` marker
on S2's `build_intent_cancel`, the co-signature carrier signed last) — **47/47**. Of the K-25 stock
set the roles need `signmessage` (the attestor agent's endpoint binding), `importprivkey` (the
role scripts import attestor keys into their attestor wallets) and `dumpprivkey`
(`yellowback_attest_wallet.py`): served, the keys in the signer — **19/34**. Nothing S3 owned is
left to S4.

**The signer (K-24).** The attestation equivocation guard (`signer/src/attest.rs`,
`attest-signed.jsonl`, fsynced before a signature leaves; keyed by key, cited height and block hash,
so another seq of the same key cannot sign a second price and a reorg is not equivocation), the
cancel co-signature (its price locked through the same guard; a claimable statement refused in the
signer), `sign_message` (the digest computed from the text), the imported-key store
(`imported.json`, chain 2 of a `bip32` reference) and `dump_key`. README "The signer" has the
requests. The 18 attestations of `yellowback_attest_vectors.json` (`vectors[]` with a secret,
`valid[]`) replay byte for byte through the signer (`signer/tests/attest.rs`; the file is read by path,
`YEWD_ATTEST_VECTORS` or a kogany checkout, hashed against `yewd/PIN`; one vector is inline so the
check also runs without the file).

**The roles.**
- *Attestor `attest` mode* (`ycash6/contrib/yellowback/attest`): runs unchanged against yewd. Its
  wallet calls (`yed_signattestation`, `yed_signcancelcosign`, `yed_buildcancel`, `signmessage`,
  `set_signcancel`, `vault_send`, and the on-chain fallback's `yed_listunspent`, `listunspent`,
  `createrawtransaction`, `signrawtransaction`, `sendrawtransaction`) are served or forwarded;
  `subscribe` mode's `yed_addattestation` is the node's.
- *Hawkeye member*: `hawkeye-ycash` reaches yewd as a ycashd. `yewd/qa/ycashd_pair.py` stands in for
  the `ycashd` a tool starts itself (it starts ycash6 `-disablewallet` + yewd, the pair on the
  caller's ports and credentials), so `crates/hawkeye/tests/regtest_self_signing.rs` runs unchanged
  against the pair. `bond_exit.rs` runs against Hawkeye's mock ycashd (no node); the bond exit on a
  real pair is the roles stage's `set_leave` + `yed_withdrawbond`.
- *x402 `rpcWalletSigner`*: its call set (`getrawchangeaddress`, `listunspent`, `gettxout`,
  `lockunspent`, `createrawtransaction` with the expiry and decimal-string amounts,
  `signrawtransaction`, the verify-only `signrawtransaction hex [] []`, `sendrawtransaction`,
  `yed_getnewaddress`, `yed_listunspent`) re-expressed in the roles stage against the pair. No
  x402 change.
- *Pool payout*: yolo calls no wallet RPC (the coinbase pays the pool, `yolo/src/rpc.rs:185-203`);
  W8-c covers it, nothing here.

**Findings.**
- **F-S3-1** (harness): under `YEWD_BIN` the harness skips the `fullyNotified` wait for every node
  (`util._yewd_skips_notified`), so the plain ycashd nodes of a mixed run lose their wallet
  notification wait: `yellowback_attest_wallet.py`'s Sapling-funded mint on node 0 failed
  (`insufficient-yec … in confirmed Sapling notes`, the note's block not yet notified). The S3 gate
  keeps the wait and lets a pair answer `fullyNotified` for itself (`PairProxy`; yewd's barrier
  brings its wallet to the tip at every call). For the harness chunk: skip the wait for pair nodes
  only.
- **F-S3-2** (Hawkeye, pre-existing, not yewd's): `regtest_self_signing.rs` fails against plain
  ycash6 `65cb4ae0f`: the self-signed `SET_JOIN`'s bond pays a member key the node wallet does not
  hold, so `set_sendact` refuses it (`vault-send-outflow`, rpcversion 8's `HandoffSend`). The engine
  sends the same way (`engine/mod.rs:558`, `engine/slash.rs:855`). Proposed (not committed, diff in the
  S3 report): the test passes `{"allowoutflow": …}`; the client gains `set_sendact` options and the
  engine passes the bond plus the fee. With the test change the test passes against ycash6 and
  against the pair.
- **F-S3-3** (record): `importprivkey` of a new key sets the signer's sign-once restore marker; ycashd
  sets it for a key that is, or later becomes, a set member (`MarkVaultKeyImported`,
  `VaultCheckJoins`). The role scripts import member keys, so the effect is the same there; a
  non-member import makes yewd ask for `set_acknowledgerestore` where ycashd would not.
- **F-S3-4** (record): `dumpprivkey` returns a WIF, so the secret passes through the façade's memory
  on its way to the caller; the signer produces it (§4.3 rule 2), the façade never stores it.
- **F-S3-5** (record): `yed_getvault` reports no claim intent's `claimRefHeight`; yewd reads the
  claim's `REDEEM` payload `refHeight` from the claim transaction (`getrawtransaction`, its intent
  unspent), which is what the index records and what ycashd's mempool path reads.
- **F-S3-6** (remaining, as F-S2-8): `yed_withdrawbond` to a Sapling address waits for the Sapling
  build in the signer.

### S3 exit gate (as run)

- `yewd/scripts/check-yewd.sh`: fmt, clippy `-D warnings`, the crates' tests, incl.
  `signer/tests/attest.rs` (the vectors; the guard: same price reused, a second price refused under
  the same and another seq, a reorg allowed, a restart kept; the co-signature's price lock and the
  claimable refusal; `signmessage`; import/dump; the bond's CLTV path).
- `yewd/qa/s3_roles.py` on ycash6 `vaults/kogany-compat` (`65cb4ae0f` binaries, harness of
  `eac62c942`), every stage **passing**:
  `--stage=attest_wallet` (`yellowback_attest_wallet.py` unchanged, nodes 6 and 7 pairs),
  `--stage=attest_bond` (`yellowback_attest_bond.py`, node 0 a pair: it registers and mints),
  `--stage=attest_agent` (`yellowback_attest_agent.py`, the shipped agent against pairs 6 and 7),
  `--stage=cancel_agent` (`yellowback_cancel_agent.py`, the four agents' wallet node 6 a pair:
  imports, bindings by `signmessage`, co-signatures, cancels over the direct path and the on-chain
  fallback), and `--stage=roles` (this file's steps: register, sign and the guard across a restart,
  `signmessage`/`verifymessage`, import/dump both ways, a ycashd claim co-signed and cancelled by yewd,
  an equivocation reported by yewd with `wait=false` ejecting the attestor, `set_leave` and
  `yed_withdrawbond`, the x402 call set), with `yed_getstatehash` and `vault_getinfo.statehash` equal
  on every node but the stock one at each checkpoint. `yellowback_cancel_limit.py` is re-expressed
  in the roles stage, not run on a pair: its node 0 mints, notices and claims while armed (F-S2-4).
- Hawkeye `crates/hawkeye/tests/regtest_self_signing.rs` with F-S3-2's test change, against ycash6
  alone and against `ycashd_pair.py` (pass both); `bond_exit.rs` (mock) passes.
- Not run here: the same on kogany (W5/W7 not merged).

## 4. CI (workspace plan §5)

Four jobs in `.github/workflows/ci.yml` (the cross-repository design is the workspace's
`docs/plans/kogany/ci-design.md`), each re-run on its own:

- `yewd-check`: the unit leg, `scripts/check-yewd.sh` (blocking).
- `yewd-bin`: the `yewd-bin` artifact (`yewd-bin.tgz`: `yewd`, `yewd-signer`, `yewd-bin.json`; dev
  profile, ubuntu-24.04; 30 days outside pull requests), which this run's gates and ycash6's mixed
  tier (at a pinned yew commit) consume.
- `yewd-node`: ycashd and ycash-cli from ycash6's `node-bin` at the commit `yewd/PIN` names (a push,
  schedule or dispatch run), re-uploaded as this run's `yewd-node`; it warns when the pinned
  `node-bin` has less than 7 days left.
- `yewd-gates`: one job per stage gate, on ycash6's functional framework at the `yewd/PIN` commit:
  the S0 backend round trip, S1, S2, and S3's `roles`, `attest_wallet` and `attest_bond` stages
  (`attest_agent` and `cancel_agent` need ycash6's attestation agent and join when the job builds
  it). Report-only until each stage's gate is seen green; the coordinator then sets the entry's
  `blocking: true`.

The contract legs through `yewd` run in ycash6's mixed tier (`yewd-pair`): backend ycash6 now,
kogany + `yewd` (column 3) once the harness has its kogany-backend mode (S5).
yew's security workflows scan `yewd/` for code, and their lockfile inputs (OSV in `secops.yml`,
cargo audit in `scripts/audit.sh`) include `yewd/Cargo.lock`.
