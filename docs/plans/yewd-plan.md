# yewd — the YEW core as a daemon: plan

**Revision 1 (2026-11-01), S0.** `yewd` is the third shell on the YEW core, in `yew/yewd/`
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
| S1 | wallet state and sync against kogany; the read-only wallet subset | — |
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

## 4. CI (workspace plan §5)

The `yewd` job in `.github/workflows/ci.yml`: the unit leg (`scripts/check-yewd.sh`, blocking) and
the backend round trip against ycashd from a trusted ycash6 run at the commit `yewd/PIN` names
(blocking). The contract legs (vs ycash6, then vs kogany + `yewd`) join when the harness lands.
yew's security workflows already scan `yewd/` for code; their lockfile inputs (OSV, cargo audit)
name only the root `Cargo.lock` and `app/pubspec.lock` and are to be extended to `yewd/Cargo.lock`.
