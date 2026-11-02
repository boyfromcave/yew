# yewd — the YEW core as a daemon: plan

**Revision 5 (2026-11-02), S4** (revision 4: S3; revision 3: S2; revision 2: S1; revision 1: S0). `yewd` is the third shell on the YEW core, in `yew/yewd/`
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
| S0 | the shell: crate layout, façade skeleton (auth, the full method table answering `-32601`, forwarding with the backend's cookie, `help`, `stop`), the `YEWD_BIN` harness contract, the `yewd` CI job | done |
| S1 | wallet state and sync; the read-only wallet subset (against ycash6 `-disablewallet`; kogany after W7-a/b) | done (§3.1) |
| S2 | builders and the signer boundary | done (§3.2): 40/47; the Sapling build in the signer: S4 |
| S3 | roles: attestor `attest` mode, Hawkeye member, x402 `rpcWalletSigner` | done (§3.3): 47/47 |
| S4 | the façade complete: all 47, R7, the K-25 stock set, error parity, hazards H1–H11 | **this revision** (§3.4): 47/47, R7, 34/34, the raw helpers |
| S5 | the parity gate (three-way matrix, the 48 wallet-needing scripts, 7 nightly days) | **this revision** (§3.5): column 3 runs end to end; the gate is not met — blocked on kogany node gaps (F-S5-3…), the 7 nightly days pending |

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

### 3.4 S4: the façade complete

**What it serves.** Every method of the façade's table: of the 47, all (S1–S3); R7's `z_importpqkey`;
of the K-25 stock set **34/34** — S4 added `addmultisigaddress`, `backupwallet`, `encryptwallet`,
`walletpassphrase`, `walletlock`, `settxfee`, `importwallet`, `z_exportwallet`, `z_importwallet`,
`z_getnewdiversifiedaddress`, `z_listreceivedbyaddress` (`wallet/src/admin.rs`) and `z_sendmany`,
`z_getoperationstatus`, `z_getoperationresult`, `z_listoperationids` (`wallet/src/zsend.rs`) — and the
three raw helpers `createrawtransaction`, `decoderawtransaction`, `decodescript`, answered by the façade
(`wallet/src/raw.rs`: `TxToJSON`, `ScriptToAsmStr`, `Solver`, `ExtractDestinations`, `ParseHashO`
re-expressed; kogany needs no change for them). No method answers "not yet implemented" any more.

**Arity, help, errors.** ycash6 checks arity in its RPC table before a handler runs
(`src/rpc/server.cpp` `CRPCTable::execute`, the parameter lists of `src/rpc/client.cpp`): `-32602`
"Not enough|Too many parameters for method `<m>`. Needed exactly <n> | at least <a> and at most <b>,
but received <k>", a blank line, the help text. The façade does the same from
`facade/src/ycashd_rpc.json` (every method's help text and bounds, generated from a plain ycash6
wallet node by `qa/gen_ycashd_rpc_table.py`; regenerate with `yewd/PIN`'s ycash6), `help <method>`
answers ycashd's text (`walletlock`/`walletpassphrase`: "help: unknown command" on an unencrypted wallet,
as ycashd), and the `help` listing is the backend's with ycashd's lines for the façade's methods merged
into ycashd's categories. Errors are ycashd's codes and texts method by method (`s4_facade.py` provokes
33 of them on both). Amounts: a negative one is `-3 "Amount out of range"` as `MoneyRange`.

**The rest of the K-25 stock set.**
- *Encryption* (`signer/src/seal.rs`): `encryptwallet` seals the phrase and the imported keys
  (ChaCha20-Poly1305 under PBKDF2-HMAC-SHA256 of the passphrase) and stops the pair as ycashd stops;
  the signer starts locked, answers `public` from its public cache, and refuses everything that needs a
  key (`locked`); `walletpassphrase` (`-14` on a wrong passphrase, `-15` unencrypted), `walletlock`, the
  timeout; `getwalletinfo`/`getinfo` carry `unlocked_until`. A locked wallet refuses the methods of
  `admin.rs` `NEEDS_UNLOCK` with `-13`, as `EnsureWalletIsUnlocked`.
- *Dumps*: `z_exportwallet` is written by the signer in ycashd's format (the WIF lines with
  `hdkeypath`, the `pqseed=` lines with `owner=`/`addr=`/`yecaddr=`, the `vaultsetsig=`/`vaultbuild=`/
  `vaultrecipient=` lines, the Sapling key lines, the recovery phrase); ycashd's `importwallet` reads it
  and yewd's `importwallet`/`z_importwallet` read ycashd's (the signer reads the file: keys, PQ seeds,
  sign-once records; the façade takes the public parts and rescans). `z_importpqkey` checks a dump line's
  `owner=`/`addr=`/`yecaddr=` before importing.
- *Backup*: `backupwallet` writes one file (the signer's files and the façade's state, by the signer);
  `-wallet=<it>` (or `<datadir>/<net>/wallet.dat`) restores it once at open (`yewd-signer restore`),
  `-salvagewallet` sets the sign-once restore marker, `-rescan` reads the chain again.
- `settxfee` (reported in `getwalletinfo.paytxfee`), `addmultisigaddress` (the same P2SH address as ycashd
  for the same keys; `validateaddress` shows the redeem script), `z_getnewdiversifiedaddress`,
  `z_listreceivedbyaddress`.

**Sapling in the signer (F-S2-8, resolved).** The façade keeps each received note (the note itself and
its tree position, `NoteRow`) and computes Merkle paths on demand: the node's tree state below the
earliest note (`z_gettreestate`, its `finalState` or `skipHash`), then every Sapling output of the blocks
up to the anchor (the tip), appended in chain order (`zsend.rs` `sapling_paths`); no witness is stored,
so a reorg needs nothing. The signer checks every path against the anchor and the note against its
account and scope, and builds:
- `z_sendmany` (`sapling_build`): t→z, z→t, z→z, t→t with librustzcash6's builder, P2PKH inputs signed
  by the signer's keys, the exact fee (ZIP-317's conventional fee, Sapling outputs padded to two, or the
  caller's, refused above 4× as ycashd), a Sapling source's change back to that address (ycashd's legacy
  address), coinbase only when shielded and without change; asynchronous operations with ycashd's status
  objects (`opid-…`, `creation_time`, `result.txid`, `execution_secs`, `method`, `params`), the
  input-selection errors as the operation's error;
- the YED builders' Sapling shapes (`sign` with a `SaplingPart`): a **mint funded from a Sapling address**
  (the carrier step from its notes too: no transparent input), a **redemption paying a Sapling address**
  (ycashd's order: change, payload, fee, attestor fee, residual; the collateral is the note) and a **bond
  withdrawal paying one**. The Sapling bundle is built and proven first, every transparent digest is then
  made over the whole transaction (librustzcash6's ZIP-243 with `hashShieldedSpends`/`hashShieldedOutputs`),
  the carrier, template, bond and coin inputs are signed as without a Sapling part, and the spends and the
  binding signature are authorized last. `yellowback_sapling.py` runs unchanged with every node a pair.

**The armed layer (F-S2-4, resolved; F-S1-4).** No new RPC was needed: `BundleAt` takes the pool's
bundle (`yed_buildbundle`: seqs, `aMint`, `aClaim`) or computes a given `bundleHex`'s statistics
(`BundleStat`, `WeightedQuantile` over `yed_listattestors R` weights); `AttestFeeFor`'s payee is
`DefaultAttestPayee` (yew-core's, over `getblockhash R`, the selector, the bundle's seqs;
`params.policy.preferredAttestor` first) paid to its `bondKeyAddress`, the fee AFEE-1′ at
`params.attest.attestFeeBps`; armed mints and claims carry it; `yed_claimnotice` is served (NOT-1's
`notice-standing`, `notice-not-underwater` at `pEmerg = min(xClaim, aClaim)`); `yed_listpositions`'
`canNotice` is `EstimateClaim`'s. `yed_listtransactions` gains the carrier fields of a two-step action,
the `carrier` rows of an uncompleted carrier, the `expired` rows of own payload transactions that left
the mempool unmined, and `claim_release`/`claim_cancel` (F-S1-5, resolved).

**Smaller S4 items.** `lockunspent` refuses to unlock a YED-held outpoint (`yed-locked-outpoint`);
`yed_getinfo` is augmented (`lockedOutputs`, `protectedByIndex`); the YED outputs a wallet commits are
locked at once (`LockOwn`); YEC selection takes confirmed coins first (`SelectCoins`' passes); the
builders refuse before the start height (`index-below-start`) as ycashd's builder `Context`;
`signrawtransaction` with keys is signed by the façade when the backend has no such method (kogany,
F-S2-7) and forwarded otherwise; `z_validateaddress` stays the façade's (needed for kogany, harmless on
the fixed ycash6 `eac62c942`+).

**Lifecycle (H5, H6).** `stop` stops both (`-stopbackend`), `encryptwallet` stops both, and with
`-stopbackend` yewd exits once its backend has been gone `-backendexitgrace` seconds (default 20) after
it was up — the pair is one node, so a node that stops itself (`AbortNode`) takes yewd with it, while a
restart within the grace is followed (S1's soak); `yellowback_rpc_contract.py`'s storage fault depends
on it. Signals, the cookie (written at start, removed at exit, the backend's re-read after a 401) are S0's.

**Findings.**
- **F-S4-1** (harness): the pair's backend mines only through `-mineraddress`, and ycashd takes a P2PKH
  `-mineraddress` as its default `-yellowbackpayoutaddress` (MINER-2, `init.cpp`), which a ycashd wallet
  node mining to its keypool never has (`yellowback_rpc_contract.py`'s `no-payout-address`). The S4 runner
  gives no coinbase address to a Yellowback-live node that names no payout address (the suites mine there
  only before the attestor set). For the harness chunk: take the H8 step (`-initwallet`, then the backend
  with the coinbase address) with that rule, or give kogany's `miner_address` without a payout default.
- **F-S4-2** (record): a caller's `bundleHex` while armed: its statistics are computed by the façade
  (`BundleStat` over the attestors' weights at `R`) rather than read from the node.
- **F-S4-3** (decision for the harness): the harness routes `-experimentalfeatures
  -developerencryptwallet` to the backend; yewd allows `encryptwallet` unless `-developerencryptwallet=0`,
  so a pair never answers ycashd's "wallet encryption is disabled" by default.
- **F-S4-4** (record): the raw helpers' refusals: the C++ deserializer's texts ("TX decode failed: …:
  unspecified iostream_category error") cannot be reproduced; a backend with the helper (ycash6) gives
  its own, one without it (kogany) gets the façade's.
- **F-S4-5** (record): ycashd lists `walletlock`/`walletpassphrase` in `help` only on an encrypted wallet;
  the façade's listing never does (their topic help follows the state, as ycashd's).
- **F-S4-6** (record): `z_importwallet` of another wallet's Sapling spending keys skips them (logged): the
  signer spends its own account only (K-24's one account); their transparent keys, PQ seeds and
  sign-once records are imported.
- **F-S4-7** (record): imported post-quantum seeds (`pqimported.json`) are gated by the lock but not sealed
  at rest; the phrase and the imported transparent keys are.
- **F-S4-8** (record): `z_sendmany`'s privacy policies: `LegacyCompat` is `AllowFullyTransparent`
  (ycashd's legacy strategy for non-unified addresses); of the policy refusals only the transparent
  recipient one is reproduced (no unified address exists on Ycash).
- **F-S4-9** (record, found by the `yellowback_sapling.py` probe): YEC selection spent the wallet's own
  unconfirmed change before confirmed coins; ycashd's `SelectCoins` tries confirmed coins first. Fixed.
- **F-S4-10** (record, same probe): ycashd locks the YED outputs it commits (`LockOwn`); yewd now does.
- **F-S4-11** (remaining, H11): `setmocktime` is forwarded to the node; the façade's own clock (unlock
  timeouts, dump times) is the system clock.
- **F-S4-12** (remaining): the kogany side of `signrawtransaction` with keys (F-S2-7's resolution) runs
  only against a backend without the method; exercised once W7 lands.

**Hazards (plan §3b S4) and their tests.** H1 (barrier) and H2 (reorg rewind) and H5 (start order, `-28`):
S1's soak and every gate since; H6 (`stop`, `encryptwallet`, the backend stopping itself):
`facade/tests/table.rs`, `s4_facade.py`, `yellowback_rpc_contract.py`'s storage fault on a pair; H8
(coinbase): the runners' H8 step; H9 (one writer, coin locks): the wallet mutex and `lockunspent`/LockOwn;
H10 (signer locked or away): `s4_facade.py`'s locked wallet (`-13`, nothing half-signed), S2's policy
tests; H7 (`allowyedburn`): S2. Not testable on a ycash6 backend: H3/H4 (kogany's indexer streams; the
poll stands in) and H11 (F-S4-11).

### S4 exit gate (as run)

Against ycash6 `vaults/kogany-compat` (`65cb4ae0f` binaries; the suites and harness of `d85332e97`).

- **The contract suites, unchanged, every node a pair** (`qa/s4_contract.py`, the harness's `YEWD_BIN`
  mode plus the H8 step, F-S4-1): `vault_rpc_contract.py` (2 pairs) and `yellowback_rpc_contract.py`
  (6 pairs: the whole wallet context, the armed v3 node and wallet contexts — pool-path mints with the
  attestor fee, the emergency notice and the clause-(b) claim, the cancel co-signature, the equivocation
  report, the bond withdrawal —, the invariant audit, the storage fault stopping a pair): **both pass**.
- **The façade leg** (`qa/s4_facade.py` against a plain ycashd wallet node): 144 arity checks (every
  method of the table, too few and too many arguments), 85 `help` texts, the K-25 lines of the `help`
  listing, 33 documented errors provoked on both, 13 raw-helper answers (coinbase, transparent and Sapling
  transactions; eight scripts; `createrawtransaction`) equal ycashd's, code and message; then `settxfee`,
  `addmultisigaddress`, `z_getnewdiversifiedaddress`, `z_listreceivedbyaddress`, `z_sendmany` t→z, z→t,
  z→z with a memo, a failed operation, the operations RPCs, `z_importpqkey`, the dumps both ways (yewd's
  read by ycashd's `importwallet`, ycashd's by yewd's `z_importwallet`), `backupwallet` and its restore,
  `encryptwallet` (the pair stops), the locked wallet's `-13`s, `walletpassphrase` (`-14`, the arity
  with its help text), `walletlock`: **passes**.
- **A probe ahead of S5**: `yellowback_sapling.py` unchanged with every node a pair (the Sapling-funded
  mint and its carrier, the redemptions to a Sapling address with and without YED change): **passes**.
- **The earlier gates on this build**: `s1_wallet_reads.py`, `s2_wallet_builders.py` (its `lockunspent`
  step now passes the two arguments ycash6's table requires), `s3_roles.py --stage=roles` (the bond now
  withdrawn to a Sapling address): **pass**.
- `yewd/scripts/check-yewd.sh` with `YEWD_PQ_WALLET_VECTORS`, `YEWD_VAULT_VECTORS`,
  `YEWD_ATTEST_VECTORS` (kogany `testdata/yellowback/`, hashes equal to `yewd/PIN`) and
  `YEWD_REQUIRE_VECTORS=1`: fmt, clippy `-D warnings`, the tests — green.
- Not run here: the same on **kogany** (W7 not merged; the plan's S4 row is gated on W7-e), the hazard
  tests that need kogany's indexer streams (H3, H4) and `setmocktime` (H11, F-S4-11).


### 3.5 S5: the parity gate

**Column 3 in the harness** (ycash6 `qa/rpc-tests/test_framework/kogany.py`, `YEWD_KOGANY`; ycash6
`kc/yewd-s5`). With `YEWD_BIN` and `YEWD_KOGANY=<zakurad>` every node *i* is **kogany *i* + yewd *i***
and no ycashd runs behind any node: kogany from `zakurad_config` (node *i*'s own arguments, slot *i*)
with P2P on `p2p_port(i)` (so `connect_nodes` and the scripts' topology carry over), cookie RPC on
`yewd_backend_rpc_port(i)`, the **indexer gRPC listener** on `yewd_backend_indexer_port(i)` and
`mining.miner_address` = the pair's coinbase address; yewd on `rpc_port(i)` with `-backendindexer`.
The scripts are unchanged. `YewdColumn` compares `vault_getinfo.statehash` and `yed_getstatehash`
across the pairs at every `sync_blocks` (a node that does not serve the read, a stock node, is
skipped). **The mixed variant** (`YEWD_YCASH6_PEER=1`) adds one ycashd `-disablewallet` that dials pair
`YEWD_PEER` (default 0) and nothing else; at every sync point it must reach the pairs' tip and equal
their state hashes, and at every mempool sync it must hold every pair's mempool transaction, so every
transaction a sidecar builds is judged by ycash6 (§4.3 rule 3). kogany never solves Equihash (K-16), so
in that variant a pair's `generate` is answered by the harness: kogany's template through yewd, the
framework's (48,5) solver (as kogany's W8-c `kogany_mines.py`), `submitblock` through yewd.

Other harness steps: **H8 for every pair** (`yewd -initwallet`, then the backend mines to its
address; F-S4-1's rule; on kogany a node that names `-yellowbackpayoutaddress` mines to that address,
F-S5-12); the 200-block cache (`cache_behavior='current'`) is mined by the run's own pairs
(`yewd_build_cache`: the cached ycashd chain and wallets are read by neither a pair's backend nor yewd);
`connect_nodes` uses `addnode "add"` and tolerates `-23` for a kogany pair; `-disablewallet`,
`-pqfeerate`, `-pqfalcon[height]` and `-salvagewallet` reach yewd too; every proxy of a pair is wrapped
(helpers make their own); a pair that lacks a mempool transaction another pair holds is fed it after a
grace (kogany's gossip, as the rig's W9-a/F-3), the ycash6 peer likewise, and the peer follows the pairs'
`invalidateblock`/`reconsiderblock`; a script that fails before `stop_nodes` leaves no pair running. The shard manifest gains the **`pair` group** (the 50 wallet-needing scripts of `sidecar`)
and the runner knows it.

**Fixes the gate found in yewd** (each committed with its finding):
- kogany's **indexer streams as wake-ups** (`facade/src/indexer.rs`, `-backendindexer`: H3, H4;
  `qa/s5_streams.py` shows both streams held and a kogany-mined block seen at once);
- the backend leg over a **pool of kept-alive connections** (F-S5-8: a connection per call exhausted
  the host's ephemeral ports under the suites);
- `signrawtransaction`'s completeness without a node verifier (F-S5-2), the façade's **mock clock**
  (H11, F-S4-11), `-disablewallet`, `help` without a Yellowback category on a stock node;
- the four stock reads beyond K-25 (`getaddressesbyaccount`, `listreceivedbyaddress`,
  `listtransactions`, `z_listaddresses`, F-S5-1), the z_* post-quantum refusals and the refusal-only
  `z_shieldcoinbase`/`z_mergetoaddress` (F-S5-10);
- ycashd wallet behaviours: `ReacceptWalletTransactions` at open, the chain facts read once at open,
  plain sends that select and price **PQ coins** (`CreateTransaction`'s PQ fee), `EnsurePQRecipientPayable`,
  the dust refusals (`GetPQDustThreshold`), the size-priced fee fallback to `-pqfeerate` (default the
  relay floor) without a price, `-pqfalconheight` read by the wallet itself, `yed_sweepcarriers` on a
  locked wallet, a mempool intent's vault for `vault_buildcancel`, vault/intent owner keys marked used
  (a restored wallet never hands them out again), an imported PQ key no longer moves the seed chain's
  index (the signer was asked for 2^31 keys), `-salvagewallet` on an already restored file,
  `z_sendmany`'s insufficient-funds target with the fee;
- the signer socket appears only at mode 0600 (bound under a temporary name, then renamed).

**Findings** (for the coordinator's §9; *kogany* = a node gap, not the sidecar's):
- **F-S5-1** (yewd, fixed): K-25's list missed four stock reads two scripts call.
- **F-S5-2** (kogany): no script verifier outside a live Yellowback (`signrawtransaction` with `[]`
  keys is ycashd's; kogany's `yed_validaterawtransaction` answers only while Yellowback is live).
- **F-S5-3** (kogany): `yed_setquote` never refuses `no-payout-address` (`yellowback_rpc_contract.py`).
- **F-S5-4** (kogany): `submitblock` answers a bare `rejected` where ycashd names the reason
  (`bad-yellowback-bad-mint-*`; `yellowback_rpc_contract`, `claim`, `interm`, `redeem_boundary`).
- **F-S5-5** (kogany): `yed_getvault.spendPending`/`spendTxid` are not read from the mempool.
- **F-S5-6** (kogany): no `disconnectnode`, so `split_network` cannot cut a kogany↔kogany link
  (`yellowback_lifecycle`, `activation_reorg`, …).
- **F-S5-7** (kogany): transactions of a disconnected block do not return to the mempool
  (`yellowback_reorg_restart`); a restarted kogany came back below its tip once (wallet_pq_address,
  a flake: the pairs then failed to re-sync within the timeout).
- **F-S5-8** (yewd, fixed): one TCP connection per backend call.
- **F-S5-9** (both lines): a coinbase address that names no YED payout key: kogany refuses a Sapling
  miner address ("Sapling coinbase construction is not supported"), so a Yellowback-live pair without a
  payout address cannot `generate` (`yellowback_attest_wallet`). A node option for a miner address
  without a payout default closes it.
- **F-S5-10** (yewd, fixed): `z_shieldcoinbase`/`z_mergetoaddress` are called for their PQ refusals.
- **F-S5-11** (kogany): no Falcon height (W3-c/F-1 open): `vault_pq_wallet_restore`, `yellowback_pq`,
  `pq_dayone`, `vault_policy`, `wallet_pq_address`'s Falcon part.
- **F-S5-12** (harness): kogany's payout key is its miner address only; a pair that names
  `-yellowbackpayoutaddress` mines to it.
- **F-S5-13** (record, §4.3 rule 3): scripts that read ycashd internals cannot run in column 3:
  `debug.log` (`vault_dos`, `vault_rpc`, `yellowback_index`, `upgrade`, `stock_node`, `wr_flags`,
  `mempool_limits`, `mining`), the datadir layout (`yellowback_hardening` h6, `vault_rpc`'s vault DB
  wipe), init-error texts (`yellowback_fees_reaccept`'s `-yellowbackmaxtxfee` floor).
- **F-S5-14** (harness, fixed): a script that failed inside `setup_network` never stopped its pairs and
  `wait_bitcoinds` waited forever.
- **F-S5-15** (yewd, record): ycashd's background Sapling consolidation (`yellowback_wr_flags`'s
  consolidation builds) is not in yewd. *Status (s5-yewd): not implemented; outside K-25 (an option, no RPC; it
  would have the signer sign transactions no RPC asked for, K-24), and the script also reads `debug.log` for
  `-deletetx` (F-S5-13): it needs a column-3 exclusion, not a yewd change.*
- **F-S5-16** (kogany): transaction gossip between koganys (and to a ycashd peer) is not reliable; the
  harness feeds the gap, as the rig does.
- **F-S5-17** (yewd, open): the seed-only restore (`-mnemonicfile` with `wallet.dat` wiped,
  `vault_pq_wallet_restore.py` (b)): yewd's wallet lives in `<net>/yewd` and the signer's directory, which
  the script's wipe does not reach; it needs a yewd `-mnemonicfile` that rebuilds the wallet from the dump's
  seed with the restore marker. *Status: fixed (yewd `-mnemonicfile`, the `wallet.dat` stand-in, pending member
  keys; harness routes the flag): `vault_pq_wallet_restore` passes on column 3 and 3m.*
- **F-S5-18** (kogany/rig): a regtest started without the Ycash upgrades (the framework's 200-block cache)
  mints coinbases without the founders' reward ycashd requires (`cb-no-founders-reward`), so the cached
  scripts cannot run with a ycash6 peer (the mixed variant; the rig's column 2 sees the same). *Status: harness
  fix (the peer gets kogany's regtest schedule, Blossom/Heartwood/Canopy at the Sapling height, and the solved
  generate adds the founders/YDF output): `vault_pq_wallet` passes in 3m; kogany's template paying it stays a
  node item.*
- kogany read/shape gaps met on the way (each a W7/W8 parity item): `getblocktemplate` carries
  `maxtime`, `yed_getstats.supplyCapCents` is null and its armed fields differ (`mint_armed`,
  `cancel_limit`), `yed_gettxinfo` lacks register rows (`yellowback_attest`), `z_validateaddress`
  answers `ismine: false`, `getblockchaininfo` lacks `chainhistoryroot` (`vault_upgrade`), reject texts
  (`old-consensus-branch-id`, `OP_VERIFY`).

### S5 exit gate (as run)

**Not met.** Column 3 runs every one of the 50 wallet-needing scripts end to end; **10 pass twice in a
row** on one build (rounds C and D below), and every other failure is classified, almost all to kogany
node gaps (the findings above) that a sidecar cannot close under §4.3 rule 1. The nightly's seven days
are wall clock: `.github/workflows/yewd-parity.yml` is written (report-only) and **pending** its first
scheduled runs on `vaults/kogany-compat`.

Builds: kogany `eaac2b78d` (`zakurad --features ycash`, debug, `$WS/wt/.bin/kc-yewd-s5/zakurad`); yewd at
yew `kc/yewd-s5` (`yewd`, `yewd-signer`, debug; the 07:44 build for rounds C and D and the mixed re-run);
ycashd `$WS/wt/.bin/ycash6-kc-w9m` (ycash6 `vaults/kogany-compat` src, the `-lightwalletd` and
`z_validateaddress -disablewallet` fixes; ycash6 `9db96a75b`'s `src/` is the same); the harness at ycash6
`kc/yewd-s5`. Each script on its own (`--srcdir`, a distinct `--portseed`, `--tmpdir`, two or three at
once on a shared host), as `yewd/qa/s5_parity.py` runs them:

    YCASH6=<ycash6 kc/yewd-s5> ZCASHD=<ycashd> YEWD_BIN=<yewd> ZAKURAD=<zakurad> KOGANY_LIVE=W1-Y1,W2-b \
        <venv>/bin/python yewd/qa/s5_parity.py --columns ycash6,rig,pair,pair-mixed --rounds 2 --out <dir>

Column 1 is the plain run, column 2 `KOGANY_SIDECAR=1` (with the manifest's `mirror`/`mempool` flags),
column 3 `YEWD_KOGANY`, 3m `YEWD_YCASH6_PEER=1`. Round D re-ran round C's passes (and
`yellowback_chainviz`, which passed an earlier round) on the same build. Two of column 1's scripts lost
their first run to another run's port (`Unable to start HTTP server`) and pass on a re-run.

| script | 1. ycash6 | 2. kogany + ycash6 rig | 3. kogany + yewd (round C) | 3. round D (same build) | 3m. mixed: + one ycash6 peer |
|---|---|---|---|---|---|
| z_validateaddress_nowallet | pass | pass | FAIL: kogany: z_validateaddress shape | — | FAIL: kogany: z_validateaddress shape |
| vault_upgrade | pass | FAIL | FAIL: kogany: getblockchaininfo shape | — | FAIL: kogany: getblockchaininfo shape |
| vault_primitive | pass | pass | FAIL: kogany: reject text | — | FAIL: kogany: reject text |
| vault_slashing | pass | pass | pass | pass | pass |
| vault_pq_reorg | pass | FAIL | FAIL: kogany: reconsiderblock of a block it did not invalidate | — | FAIL: kogany: reconsiderblock of a block it did not invalidate |
| vault_dos | pass | FAIL | FAIL: reads ycashd internals (F-S5-13) | — | FAIL: reads ycashd internals (F-S5-13) |
| vault_rpc | pass | pass | FAIL: reads ycashd internals (F-S5-13) | — | FAIL: reads ycashd internals (F-S5-13) |
| vault_rpc_contract | pass | pass | pass | pass | pass |
| vault_pq_relay | pass | pass | pass | pass | pass |
| vault_bridge | pass | pass | FAIL: kogany: reject text | — | FAIL: kogany: reject text |
| vault_pq | pass | pass | FAIL: kogany: PQ owner spend not in its template | — | FAIL: kogany: PQ owner spend not in its template |
| vault_pq_wallet | pass | FAIL | pass | pass | FAIL: cache: founders reward (F-S5-18) |
| vault_pq_wallet_restore | pass | FAIL | FAIL: yewd: seed-only restore (F-S5-17) | — | FAIL: cache: founders reward (F-S5-18) |
| wallet_pq_address | pass | FAIL | FAIL: kogany: getaddressmempool | — | FAIL: cache: founders reward (F-S5-18) |
| yellowback_lifecycle | pass | pass | FAIL: kogany: no disconnectnode (F-S5-6) | — | FAIL: kogany: no disconnectnode (F-S5-6) |
| yellowback_activation_reorg | pass | pass | FAIL: kogany: no disconnectnode (F-S5-6) | — | FAIL: peer kept an invalidated branch (mirror added after this pass) |
| yellowback_reorg_restart | pass | pass | FAIL: kogany: reorged txs not back in mempool (F-S5-7) | — | FAIL: peer kept an invalidated branch (mirror added after this pass) |
| yellowback_claim | pass | pass | FAIL: kogany: submitblock bare rejected (F-S5-4) | — | FAIL: kogany: submitblock bare rejected (F-S5-4) |
| yellowback_interm | pass | pass | FAIL: kogany: submitblock bare rejected (F-S5-4) | — | FAIL: kogany: submitblock bare rejected (F-S5-4) |
| yellowback_index | pass | FAIL | FAIL: reads ycashd internals (F-S5-13) | — | FAIL: reads ycashd internals (F-S5-13) |
| yellowback_upgrade | pass | pass | FAIL: reads ycashd internals (F-S5-13) | — | FAIL: peer kept an invalidated branch (mirror added after this pass) |
| yellowback_rpc_contract | pass | pass | FAIL: kogany: setquote payout (F-S5-3) | — | FAIL: kogany: setquote payout (F-S5-3) |
| yellowback_redeem_boundary | pass | pass | FAIL: kogany: submitblock bare rejected (F-S5-4) | — | FAIL: kogany: submitblock bare rejected (F-S5-4) |
| yellowback_cancel_limit | pass | pass | FAIL: kogany: armed reads | — | FAIL: kogany: armed reads |
| yellowback_pq | pass | pass | FAIL: kogany: params.pq.falconHeight (F-S5-11) | — | FAIL: 401 on rpc_port (port taken by another run) |
| yellowback_pq_dayone | pass | pass | FAIL: kogany: params.pq.falconHeight (F-S5-11) | — | FAIL: kogany: params.pq.falconHeight (F-S5-11) |
| yellowback_void_mint | pass | pass | FAIL: kogany: yed_getstats.supplyCapCents null | — | FAIL: kogany: yed_getstats.supplyCapCents null |
| yellowback_mint_armed | pass | pass | FAIL: kogany: yed_getstats armed fields | — | FAIL: kogany: yed_getstats armed fields |
| yellowback_wallet_restore | pass | pass | pass | pass | pass |
| yellowback_sapling | pass | pass | pass | pass | pass |
| yellowback_wallet_lifecycle | pass | pass | FAIL: kogany: payout = miner address (F-S5-12) | — | FAIL: kogany: payout = miner address (F-S5-12) |
| yellowback_hardening | pass | FAIL | FAIL: reads ycashd datadir (F-S5-13) | — | FAIL: reads ycashd datadir (F-S5-13) |
| yellowback_stock_node | pass | FAIL | FAIL: kogany: getblocktemplate maxtime | — | FAIL: kogany: getblocktemplate maxtime |
| yellowback_fees | pass | FAIL | pass | pass | pass |
| yellowback_fees_reaccept | pass | pass | FAIL: kogany starts on a config ycashd refuses (F-S5-13) | — | FAIL: kogany starts on a config ycashd refuses (F-S5-13) |
| yellowback_fee | pass | FAIL | pass | pass | pass |
| yellowback_mempool_limits | pass | FAIL | FAIL: kogany: yed_getvault of a raw mint | — | FAIL: kogany: yed_getvault of a raw mint |
| vault_policy | pass | pass | pass | pass | pass |
| vault_refee | pass | pass | pass | pass | pass |
| yellowback_wr_flags | pass | pass | FAIL: yewd: no consolidation (F-S5-15) | — | FAIL: yewd: no consolidation (F-S5-15) |
| yellowback_attest_evict | pass | pass | FAIL: kogany: set_getinfo active seats | — | FAIL: kogany: set_getinfo active seats |
| yellowback_attest_rejoin | pass | pass | FAIL: kogany: attestor records | — | FAIL: kogany: attestor records |
| yellowback_attest_live | pass | pass | FAIL: kogany: attestor records | — | FAIL: kogany: attestor records |
| yellowback_pricefeed | pass | pass | FAIL: kogany: yed_getstats mintableClasses | — | FAIL: kogany: yed_getstats mintableClasses |
| yellowback_mining | pass | FAIL | FAIL: kogany: getblocktemplate maxtime | — | FAIL: kogany: getblocktemplate maxtime |
| yellowback_stratum | pass | pass | FAIL: yolo on a pair: miner exit | — | FAIL: peer kept an invalidated branch (mirror added after this pass) |
| yellowback_attest | pass | pass | FAIL: kogany: yed_gettxinfo rows | — | FAIL: kogany: yed_gettxinfo rows |
| yellowback_attest_wallet | pass | pass | FAIL: no payout-free coinbase (F-S5-9) | — | FAIL: no payout-free coinbase (F-S5-9) |
| yellowback_attest_bond | pass | pass | FAIL: kogany: attestor records | — | FAIL: kogany: attestor records |
| yellowback_chainviz | pass | FAIL | FAIL: chain-viz mempool feed timing | FAIL: chain-viz mempool feed timing | FAIL: chain-viz mempool feed timing |
| **pass** | 50/50 | 36/50 | 10/50 | 10/11 | 9/50 |


**State hashes.** The harness asserts `vault_getinfo.statehash` and `yed_getstatehash` equal across the
pairs at every `sync_blocks`, and in the mixed variant equal to the ycash6 peer's (with the peer at the
pairs' tip, holding their mempool): in the passing mixed runs 6 to 259 sync points per script agreed with
ycash6, every pair-built transaction reached and was accepted by the ycashd peer (fed by the harness when
kogany's gossip did not bring it: up to 24 per script), and every block the pairs mined (up to 328 per
script, solved by the harness) was accepted by ycash6. Across columns the chains differ (other keys, other
blocks), so equality across columns is the per-run cross-line equality, not one hash for all three.

**Still to do for S5** (beyond the kogany gaps): F-S5-17 (`-mnemonicfile` seed-only restore), F-S5-15
(consolidation), F-S5-9 needs a node option on both lines, the chain-viz mempool-timing failure
(`yellowback_chainviz`: the mint reaches chain-viz's mempool snapshot later than its 15 s wait on a pair),
`yellowback_stratum`'s miner exit on a pair; then the gate's rounds and the nightly's seven days.

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

The contract legs through `yewd` run in ycash6's mixed tier (`yewd-pair`): backend ycash6. Column 3
(kogany + `yewd`, the harness's `YEWD_KOGANY` mode) is `.github/workflows/yewd-parity.yml`: nightly and
on dispatch, one job per column (`pair`, `pair-mixed`) and mixed group, `qa/s5_parity.py` over the
manifest's `pair` rows; report-only until S5's gate is seen green, and the gate's seven nights are read
from its schedule history. `yewd-gates` also carries the S4 legs (`s4-contract-vault`,
`s4-contract-yellowback`, `s4-facade`), report-only.
yew's security workflows scan `yewd/` for code, and their lockfile inputs (OSV in `secops.yml`,
cargo audit in `scripts/audit.sh`) include `yewd/Cargo.lock`.
