# YEW — Your Electronic Wallet

A small mobile wallet for **Ycash (YEC)** and **Ycash Yellowback (YED)**, a dollar on Ycash
backed by YEC locked in post-quantum vaults. iOS and Android, one Flutter UI over one Rust core.
YEW is one component of the [Ycash vaults and Yellowback](https://github.com/boyfromcave/yellowback)
project. A web wallet built on the same core is in progress (branch `up/web`).

**For users.** YEW holds YED and public YEC in transparent addresses and private YEC in a
shielded Ycash address (`ys1…`), and lets you receive, send and see your history for all of
them. YED is the main currency: 1 YED is a dollar; YED, its fees and every mint's collateral use
public YEC. Beyond send and receive, the Yellowback tab lets you mint YED against locked YEC,
watch and redeem your vaults, and claim an undercollateralized vault (the collateral is yours to
release after a claim delay, unless the attestors cancel a claim made at a wrong price). Public
addresses, balances and transactions are visible on the chain; private payments hide the
amount, the parties and the message (Home shows the two as **Private** and **Public**; a payment
from private to a public address is marked before you confirm). Your keys never leave the phone;
the app trusts one light-client server you choose for its view of the chain, and every YED
transaction is checked by that server's node before it is sent. The full statement is [docs/trust.md](docs/trust.md).

## Yellowback and the vault upgrade

YED depends on a proposed Ycash network upgrade that adds **post-quantum vaults**: YEC locked on
chain under rules every node checks, released only with the approval of a bonded **signer set**,
after a delay during which the release can be cancelled. Lock YEC in a vault to mint YED
(`1 YED = $1`); burn the YED to get the YEC back. If a vault's YEC becomes worth less than 125 %
of the YED it backs, others can claim it. The YEC/USD price comes from mining pools and from
**attestors**, the bonded members of Yellowback's signer set who sign prices.

> **Status: in development.** It runs on regtest and on a one-laptop devnet only. No activation
> height is set on mainnet or testnet, the upgrade has not been adopted by the Ycash Foundation,
> and there is no external audit. The app runs on the iOS simulator and the Android emulator; there
> are no public servers and no store builds yet ([What is left](#what-is-left)).

- **What YEW does with it:** mints, redeems, claims and releases, signing every vault spend
  itself, and signs every transaction for the consensus branch ID of the *next* block, so sends
  keep working across the upgrade's activation block. YEW does not touch the wYEC or nYEC bridges
  and does not run an attestor.
- **Post-quantum keys:** each vault's owner is an SLH-DSA key, and YED is received, held and sent
  with Falcon-512 keys, from the seed. YED addresses are 53 characters and start `yb…` on mainnet
  (`yt…` testnet, `yr…` regtest). Falcon is active from the upgrade's first block on mainnet.
  YEW sends YEC to plain post-quantum addresses (`sq…`) and finds payments to its own; post-quantum
  YEC it receives shows separately and moves into the wallet with one tap.
  Private (Sapling) YEC is not post-quantum.
- **Fees:** YEW computes every fee it signs. The protocol fee is in dollars of the debt, like tax
  brackets (1 % up to $1,000, 0.5 % up to $10,000, 0.1 % above, $1 minimum), charged at the mint
  and again at the redeem at the vault's mint price; redeeming before the end of the term adds 5 /
  2.5 / 1 % of the debt (class A / B / C). The largest mint is $100,000. Network fees are dollars
  per KB at the attested price, capped. The screens show fees in dollars and YEC.
- **What it needs:** a light-client server, [lightwalletd](https://github.com/boyfromcave/lightwalletd)
  (`lightwalletd-dd`) with `--yellowback`, over a `ycashd` built from the `upgrade/quantum-vaults`
  branch of [ycash-dd](https://github.com/boyfromcave/ycash-dd) or
  [ycash6](https://github.com/boyfromcave/ycash6) (this line joins `upgrade/vault` at release). The
  core requires Yellowback `rpcversion` 8.
- **Try it:** [Quick start for developers](#quick-start-for-developers) below brings up the local
  test network and runs the app on it.

## Quick start for developers

Prerequisites: Rust (the exact version is in `rust-toolchain.toml`; `rustup` installs it),
`protoc` on PATH, Flutter 3.47.5, and for devices Xcode or the Android SDK with NDK
28.2.13676358 plus `cargo install cargo-ndk`. Everything else is pinned in the repo.

```bash
git clone git@github.com:boyfromcave/yew.git && cd yew
cargo test --workspace                 # core, CLI and the node-generated vectors
(cd app && flutter test)               # widget tests over a fake bridge
```

To run the app you need the local test network (the "devnet": regtest nodes running the vault
upgrade, with YED live) and a lightwalletd on it. The scripts expect this repo inside the
`yellowback-workspace` checkout (at `yew/`), next to `ycash-dd/`, `lightwalletd-dd/` and the
workspace's Python venv:

```bash
scripts/devnet-w4.sh up                # once: a regtest devnet with prices live + lightwalletd on 127.0.0.1:9267
scripts/devnet-w4.sh status            # is it up?
scripts/run-ios.sh                     # build the core, run on the iPhone simulator
scripts/run-android.sh                 # build the core, boot the emulator, run
```

See [Running against the devnet](#running-against-the-devnet) for funding the wallet and
mining blocks.

## How it works

```
 ┌───────────────────────── app/ (Flutter, Dart) ─────────────────────────┐
 │ screens ──▶ AppState ──▶ WalletApi (interface) ──▶ RustWalletApi (frb) │
 └──────────────────────────────────┬──────────────────────────────────────┘
                                    │ flutter_rust_bridge (generated)
 ┌──────────────────────────────────▼──────────── core/ (Rust) ───────────┐
 │ api.rs ─▶ wallet.rs ─▶ sync.rs / coins.rs / build/* ─▶ gate.rs ─▶ net/* │
 │           keys · tx (v4 + ZIP-243) · script · payload · coinselect      │
 │           bundle · store (SQLite)                                        │
 └──────────────────────────────────┬──────────────────────────────────────┘
                                    │ gRPC (tonic), TLS or plain on regtest
                        lightwalletd-dd: CompactTxStreamer (YEC) + YellowbackStreamer (YED)
```

Three rules explain most of the design:

1. **The core owns every byte.** Keys, addresses, transaction serialization, the ZIP-243
   sighash, scripts, payloads and coin selection exist only in Rust. The Dart side sees typed
   models and calls; `scripts/check-app-imports.sh` fails CI if `app/lib` imports any crypto,
   gRPC, SQLite or socket package.
2. **Nothing is broadcast without passing the gate twice.** `gate.rs` first checks locally that
   every input is a class the transaction may spend, then asks the server's node to validate
   the exact bytes (`ValidateRawTransaction`) and refuses unless the verdict is `ok`, the burn
   equals what was planned and the node would accept it. There is no override, flag or test
   hook that skips it. This is what stands between a client bug and burned YED.
3. **Every UTXO has one class.** On Ycash a YED holding is a 10,000-zat transparent output whose
   dollars live in a payload; spending it as plain YEC burns it. So `coins.rs` classifies every
   output (`YEC`, `FEE_RESERVE`, `TOKEN`, `PENDING_TOKEN`, `VAULT`, `CARRIER`, `HELD`,
   `UNKNOWN_P2SH`) from server data, keeps a YEC reserve so YED is never stranded without fee
   money, and never lets the YEC path touch anything but `YEC` and `FEE_RESERVE`. The user
   sees two balances; a UTXO list exists only in `yew-cli coins`.

Other things worth knowing before reading code:

- **Sync is per address, not per block.** The wallet derives its addresses
  (`m/44'/347'/0'/{0,1}/i`, Ywallet-compatible, gap limit 20), asks the server for their UTXOs
  and transaction history, and asks the Yellowback service which of those outputs are YED.
  The private (Sapling) balance is synced differently: the `x402_ycash_light` library scans
  compact blocks from the account's birthday on the phone, over YEW's own connection, so the
  server never learns which private payments are the wallet's.
- **A mint is a persisted state machine, not a process.** Minting takes two transactions (a
  carrier holding the price attestations, then the mint itself) inside a 40-block window. The
  `mints` table holds every fact the second step needs, only the sync loop advances a row, and
  a killed app resumes from the table; a lapsed carrier is swept back.
- **Labels come from the node's verdicts.** History rows for Yellowback transactions are
  labelled from `GetTxInfo`, never from decoding the payload locally.
- **The node is the oracle for tests.** `core/tests/vectors/` holds transactions the node
  signed, addresses, mint/transfer/redeem templates and parameters, exported by the workspace's
  `yellowback-devnet vectors`; the core must reproduce them byte for byte. On the in-term line
  they come from an in-term devnet, and `scripts/vectors-in-term.py` adds an early redeem and an
  in-term claim to `templates.json` (procedure in its header).

- **Shielded YEC lives in the core and on the existing screens.** The same seed
  derives one Ycash Sapling account at ZIP-32 `m/32'/347'/0'` (`shielded_keys.rs`,
  YWallet-compatible). `shielded.rs` keeps it in a `zcash_client_sqlite` store under
  `<data dir>/shielded/<wallet file stem>/`, synced by the Ycash light client
  `x402_ycash_light` (boyfromcave/x402-ycash `light/`: compact blocks from lightwalletd-dd, the
  `GetTreeState` birthday checkpoint, ten-block reorg rewinds). YEW itself fetches memos
  (`GetTransaction` + `decrypt_and_store_transaction`), proposes, proves and signs spends, and
  broadcasts through its own channel. `sync_now` runs the transparent sync and then the private
  scan as one progress (`SyncEvent.percent`); a note is spendable only once the scan reaches the
  tip (`Balances.shieldedSendable`, "sending available at 100%": Ycash has no
  `GetSubtreeRoots`). `send_yec_preview` funds **privacy first** (`build/yec_private.rs`): a
  `ys1…` recipient (optional memo, ≤ 512 bytes) from notes; a transparent recipient from notes
  when they cover it (`revealsShielded`, the amber line), else from transparent YEC exactly as
  before. A shielded spend has no transparent input at all (gate path `Shielded`), so the fee
  reserve and every YED path never meet it. The Sapling proving parameters (52 MB) are fetched
  on first private send (`params_status` / `download_params`, `sapling_params.rs`) from a
  configurable HTTPS base URL and kept only if their SHA-256s match the pins; where they are
  hosted is not decided yet, so no URL is compiled in.
- **Moving YEC between private and public** is one explicit action, Home → "Move…"
  (`move_preview` / `move_confirm`, `build/yec_move.rs`). To private: plain `YEC` coins only
  (never the fee reserve, a token, a vault, a carrier or a held output) into one Sapling output
  to the wallet's own default `ys1…` address, transparent change back, ZIP-317 fee; built and
  signed by the librustzcash6 builder (`transparent-inputs`), since YEW's own serializer makes
  no Sapling outputs; gate path `Shield`. To public: a private spend to the wallet's own `s…`
  address (the amount is visible on the chain, `revealsShielded`). "Move YEC to public first"
  on Mint and Send YED opens Move → To public with the shortfall filled in.

The reasoning behind each rule, with the evidence from the devnet, is in
[docs/design-notes.md](docs/design-notes.md).

## Repository layout

```
Cargo.toml              Rust workspace: core (yew-core) and core/cli (yew-cli)
core/src/               the core; api.rs is the bridge surface, frb_generated.rs is generated
core/cli/               yew-cli: the developer's driver and what the devnet tests use
core/tests/             vectors.rs (node vectors), devnet.rs (acceptance incl. s2_ shielded and s4_ moves on both node lines; YEW_DEVNET=1, ignored otherwise)
core/tests/vectors/     node-generated vectors (ywallet.json is pending an owner capture; sapling_keys_ycash.json is node-confirmed)
app/                    Flutter project yew_app (org cash.ycash.yew)
app/lib/api/            WalletApi interface + the one file that calls the bridge
app/lib/state/          AppState, the single app state
app/lib/screens/        one file per screen, each under 300 lines
app/lib/src/rust/       generated by scripts/gen-bridge.sh; never edited
app/test/               widget tests over test/fake_wallet_api.dart
app/integration_test/   m1 (send/receive), m2 (mint/vault/claim) and s3 (private screens + screenshots) flows against a devnet
proto/                  the three lightwalletd-dd .proto files + PIN (the commit they came from)
scripts/                build, run, devnet and CI check scripts (listed below)
docs/                   trust.md, design-notes.md, security-review.md, release.md, licenses.md
flutter_rust_bridge.yaml   codegen config
.github/workflows/      ci.yml (build, tests, checks); semgrep.yml, codeql.yml, secops.yml, code-scanning.yml (SECURITY-CI.md); devnet-nightly.yml
```

## Toolchain

| Tool | Version | Pinned in |
|---|---|---|
| Rust (stable) | 1.92.0 | `rust-toolchain.toml` |
| Flutter | `3.47.5` (stable) | `app/pubspec.yaml`, CI (reads this row) |
| Dart SDK | `3.13.4` | `app/pubspec.yaml` |
| flutter_rust_bridge (crate, codegen, Dart package) | 2.13.0, all three | `core/Cargo.toml`, `app/pubspec.yaml`, `scripts/gen-bridge.sh` |
| Android NDK | 28.2.13676358 | `app/android/app/build.gradle.kts` |
| protoc | any 3.x+ on PATH | `core/build.rs` (not vendored) |
| Minimum iOS / Android | 15.0 / API 24 | Xcode project / Gradle |

Rust targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-linux-android`,
`x86_64-linux-android`, plus the host. Direct Rust dependencies are an allow-list
(`scripts/allowed-deps.txt`, checked in CI); versions are pinned exactly. Adding a crate is a
recorded decision, not a `cargo add`.

## Development

### Build, test and check

```bash
cargo build && cargo test --workspace     # core + CLI + node vectors
(cd app && flutter analyze && flutter test)
scripts/check-proto-pin.sh                # protos identical to ../lightwalletd-dd/walletrpc (skips if absent)
scripts/check-deps.sh                     # direct deps ⊆ allow-list
scripts/check-app-imports.sh              # no crypto/network/db imports under app/lib
scripts/check-trust-text.sh               # app copy of the trust statement == docs/trust.md
scripts/check-licenses.sh [--print]       # every linked crate's license in the allowed set
scripts/audit.sh                          # cargo audit (blocks only when a fix exists)
```

CI (`.github/workflows/ci.yml`) runs all of these on Linux and macOS, regenerates the bridge
and fails if it differs from the committed output.

### Change the bridge

Edit `core/src/api.rs`, then `scripts/gen-bridge.sh` (needs
`cargo install flutter_rust_bridge_codegen --version 2.13.0`). Commit both generated outputs.
The api functions are blocking Rust functions on a private tokio runtime (the store is not
`Send` across awaits); Dart still sees a `Future` per call. Amounts and heights cross as `i64`.

### Build the core for a device

```bash
scripts/build-core-ios.sh        # → app/ios/Frameworks/YewCore.xcframework
scripts/build-core-android.sh    # → app/android/app/src/main/jniLibs/*/libyew_core.so
```

`run-ios.sh` and `run-android.sh` call these for you. On iOS the static library is force-loaded
by `app/ios/Flutter/YewCore.xcconfig` (without it the linker silently drops all Rust code and the
build still succeeds) and the bridge resolves symbols from the process.

### The workspace

This repo is one component of `yellowback-workspace`, which holds the Ycash node fork
(`ycash-dd`), the lightwalletd fork (`lightwalletd-dd`) whose `YellowbackStreamer` service is
YEW's only source of YED information, the devnet tooling, and the plan
(`docs/plans/yellowback-wallet-plan.md`). The `proto/PIN` file records which lightwalletd-dd
commit the protos were copied from; `check-proto-pin.sh` keeps them identical.

## Running against the devnet

The devnet (eight regtest nodes running the vault upgrade, three attestors, prices live) comes from the
workspace's `ycash-dd/contrib/yellowback/devnet/yellowback-devnet`. `scripts/devnet-w4.sh`
wraps it for YEW: directory `~/yb-devnet-w0c`, port seed 9, `lightwalletd-dd --yellowback` on
`127.0.0.1:9267`, plain HTTP/2.

```bash
scripts/devnet-w4.sh up | status | down [--wipe]
scripts/run-ios.sh [host:port] [--test m1|m2|q]     # default server 127.0.0.1:9267
scripts/run-android.sh [host:port] [--test m1|m2|q] # default server 10.0.2.2:9267 (the emulator's name for the host)
```

**In the app**: Create, accept the trust statement, network **regtest**, server as above with
*Plain connection* on, *Check server*, *Continue*, *Finish*, back up the seed. Home shows the
synced height.

**The devnet has no heartbeat**: nothing confirms until a block is mined on a pool node
(2, 3 or 4), and each mine should be preceded by a re-quote or the price windows drain. From the
workspace root:

```bash
dn() { (cd ycash-dd && YELLOWBACK_DEVNET_DIR=$HOME/yb-devnet-w0c YELLOWBACK_DEVNET_PORTSEED=9 \
        ../.venv/bin/python contrib/yellowback/devnet/yellowback-devnet "$@"); }
dn cli --node 2 -- sendtoaddress <s-address> 1.0     # YEC (pool nodes hold the mature coinbases)
dn cli --node 0 -- yed_send <yr-address> 5000        # $50.00 of YED from node 0
dn price 50 && dn mine 1 2                           # re-quote, one block on pool node 2
```

Copy the `s…` address for YEC and the `yr…` address for YED from the Receive screen (on regtest;
once Falcon is active the YED address is a 53-character Falcon address with its own key). The integration tests print a `YEW M1:` / `YEW M2:` line whenever they need
you to fund or mine, and wait up to three minutes. `m1` passes on both platforms; `m2` reaches
the mint estimate and stops because the node's minimum mint is $100 while the test's amounts
were written smaller (see [What is left](#what-is-left)).

**The post-quantum flow (`q`) runs unattended.** It needs a quantum devnet with Falcon active
from the start, as on mainnet, and `scripts/devnet-operator.py`, a small HTTP server on the
host that funds and mines when the test asks (it binds 127.0.0.1; the emulator reaches it as
`10.0.2.2`). Node 0 needs YED to send, e.g. `dn cli -- yed_mint 300000 48 "" "" false` and two
mined blocks:

```bash
YEW_PQ_FALCON_HEIGHT=1 YELLOWBACK_DEVNET_PORTSEED=<seed> YEW_LWD_PORT=<lwd> scripts/devnet-falcon.sh up
YEW_DEVNET_TOOL=... YELLOWBACK_DEVNET_DIR=... YELLOWBACK_DEVNET_PORTSEED=<seed> scripts/devnet-operator.py --port <op> &
YEW_OPERATOR=127.0.0.1:<op> scripts/run-ios.sh 127.0.0.1:<lwd> --test q
YEW_OPERATOR=10.0.2.2:<op> scripts/run-android.sh 10.0.2.2:<lwd> --test q
```

It checks the 53-character Falcon receive address on screen, receives YEC and YED, sends YED
from a Falcon input, mints $100.00 with an SLH-DSA owner, redeems it in term from the Vault
screen, restores the second wallet, and prints `YEW Q: timing` / `YEW Q: jank` lines.
`cargo build -p yew-core --release --example pq_bench --target <device target>` times SLH-DSA
and Falcon keygen/sign/verify on the device itself (`xcrun simctl spawn booted …`,
`adb shell /data/local/tmp/pq_bench`).

## Testing

| Level | Where | Runs |
|---|---|---|
| Unit | `core/src/**` `#[test]` | `cargo test`; includes property tests that no YEC-path transaction ever spends a token, vault or carrier input, on thousands of random coin sets |
| Node vectors | `core/tests/vectors.rs`; `core/src/vault.rs`, `pq.rs` | `cargo test`; twelve node-signed transactions, addresses, templates reproduced byte for byte; the node's golden `vault_vectors.json` (both owner schemes: SLH-DSA and Falcon owner spends), `pq_vectors.json` and `pq_wallet_vectors.json` (the A-12 derivation, also from a BIP39 phrase) replayed. `scripts/check-node-vectors.sh` (CI, `core-linux`) compares the copies with both node lines at `core/tests/vectors/PIN`; it fails, never skips |
| Widget | `app/test/` | `flutter test`; 29 tests over the fake bridge |
| Devnet acceptance | `core/tests/devnet.rs` | `scripts/devnet-w1.sh test`, `devnet-w2.sh test`, `devnet-w4.sh test`; YEC round trip and restore, YED transfer and gate refusal, mint/redeem/claim/lapse/resume; `devnet-it.sh test [it|w4]` on the in-term line (early redeem in term, the in-term claim, listed-not-claimable refusal); `devnet-falcon.sh up && devnet-falcon.sh test` on the quantum line (Falcon YED holders across `-pqfalconheight`); `devnet-pqaddr.sh up && devnet-pqaddr.sh test` (`sq…` receive, send and move); nightly, non-gating: `.github/workflows/devnet-nightly.yml` job `hosted` on a GitHub-hosted runner (`q_falcon_*`, `q_pqaddr_*`; ycashd from the node CI artifact, 60 min), job `self-hosted` (every suite) on the owner's `yb-devnet` runner by manual dispatch (SECURITY-CI.md, "Devnet tiers"), an issue on failure |
| Shielded devnet | `core/tests/devnet.rs` `s2_` | `scripts/devnet-s2.sh dd <seed>` and `scripts/devnet-s2.sh 6 <seed>` (the 4.5.0 and 6.21.0 node lines; builds lightwalletd-dd 0b3448e+, needs the Sapling parameters on the machine): restore with a memo, z→z with a memo confirmed by `z_listreceivedbyaddress`, z→t with `revealsShielded`, transparent fallback, transparent YEC and YED regressions, no spending key in any file; `s4_`: move 1 YEC to private, 0.5 YEC to public, all to private, the mint shortfall to public and the mint, with YED and the fee reserve untouched and balances exact; `s5_`: restore with a birthday (at, after and without one), reorgs under a synced wallet (re-mined, dropped and re-mined, a send dropped past its expiry) with lightwalletd-dd following, an interrupted sync (future dropped, process killed) resuming to the same state |
| Device integration | `app/integration_test/` | `scripts/run-ios.sh --test m1`, `run-android.sh --test m1`; `--test q` on the quantum line (Falcon receive/send, SLH-DSA mint and redeem, restore; unattended with `scripts/devnet-operator.py`) |

`ywallet_derivation_vector` is `#[ignore]`d until `core/tests/vectors/ywallet.json` is filled
from a Ywallet desktop build.

**Re-pinning the node vectors.** The node declares the vectors; YEW copies them. After a node change
to `src/test/data/{vault,pq,pq_wallet}_vectors.json` lands on both lines (they must be identical),
fetch the sibling clones and run
`scripts/resync-node-vectors.sh` (both at `origin/upgrade/vault`; or
`scripts/resync-node-vectors.sh <ycash-dd rev> <ycash6 rev>`), then `cargo test --locked -p yew-core`
and `scripts/check-node-vectors.sh`, and commit the copies with `core/tests/vectors/PIN`. A new
owner-spend shape in the vector fails `owner_spend_is_signed_byte_for_byte` until it is added
there deliberately.

## `yew-cli`

The CLI drives the same core the app does and is the fastest way to reproduce anything.

```
yew-cli [--server host:port] [--plain] [--ca-pem PATH] [--wallet PATH] [--network regtest|testnet|mainnet]
        [--seed-file PATH | YEW_SEED="<mnemonic>"] [--passphrase P] [--birthday H] [--params DIR]
        status | yed-info | price | address [--new] [--shielded] [--falcon] | balance | coins | sync | history
        | send-yec <addr> <zat> [--all] [--memo TEXT] | send-yed <addr> <cents> [<addr> <cents> ...]
        | params-status | params-download <base-url>
        | export-wif <addr> | import-wif <wif>
        | mint-estimate <cents> <lockBlocks> | mint-start <cents> <lockBlocks>
        | mint-status [<id>] | mint-finish <id> | mint-sweep <id>
        | vaults | redeem <vaultTxid> | claimable | claim <vaultTxid>
        | intents | release <txid>:<n> | version
```

Defaults: `127.0.0.1:9067`, TLS on (`--plain` is refused outside regtest; `--ca-pem` pins one
certificate as the only trust anchor), `yew-wallet.sqlite`, regtest. `coins` lists every UTXO
with its class; `--all` lets a YEC send spend the fee reserve; `export-wif` is byte-identical to
`ycashd`'s `dumpprivkey`, so a YEW transparent key imports into YecWallet. It covers ordinary
(secp256k1) keys only: post-quantum vault owner and Falcon keys are not exported this way.

## Security

`docs/security-review.md` is the threat review: seed and key handling (key material is wiped,
the seed lives in the platform keystore and exists in the core only inside `Wallet::open`), the
gate (every `SendTransaction` call site sits behind both layers), TLS (plain is a regtest-only
property; CA pinning in the core and CLI), storage (`0600` cache, no Android backups,
`FLAG_SECURE` on seed and key screens), and the bridge boundary. `cargo audit` and a license
allow-list run in CI; Semgrep, CodeQL, zizmor, gitleaks, OSV-Scanner, the code-scanning dismissal
ledger and Dependabot are in [SECURITY-CI.md](SECURITY-CI.md), with how to accept a finding. The app has no telemetry and nothing in the core logs.

An internal review on 2026-10-01 added: every server-supplied mint,
claim and vault term is checked against the network's rules (`core/src/build/terms.rs`,
`params.rs`) before anything is signed, the pool and attestor fees are computed locally,
a redeem is previewed (fee and payee on screen) before it is confirmed, the server's
`consensusBranchId` must be a Ycash epoch, server streams are bounded, the Mozilla root bundle
backs TLS on iOS, a certificate can be pinned from Settings, and "device unlock" binds the seed
to the platform's presence check. On mainnet and testnet the Falcon (`TOK-PQ`) activation is
compiled in (`params.rs` `PQ_FALCON_HEIGHT_*`, `pqFalconHeight = 0` on both node lines): a server
reporting another one is refused and YED is hidden, never silently overridden. What is still not checked locally is the fee **payee**: the
node, not the wallet, knows which miners are eligible (`docs/trust.md`).

**Restore.** The post-quantum keys (vault owners, Falcon YED holders) are HKDF-SHA256 of the
64-byte BIP39 seed of the words and the passphrase (`core/src/pq.rs`, quantum spec A-12). Restore
the phrase in YEW to recover vaults and YED: Ywallet restores only the ordinary addresses, and
YecWallet / ycashd 4.5 derive their PQ keys from another seed. ycashd 6.x derives the same keys
from the same 24 English words without a passphrase (`pq_wallet_vectors.json`, section
`mnemonic`), but its restore scans its own index ranges, so it is not a recovery path YEW
promises (`docs/trust.md`, the seed screens).

Shielded YEC: the Sapling spending key is derived at unlock and never written by YEW; the
private store holds the account's viewing key, notes and memos (privacy, not funds); the
proving parameters are SHA-256 pinned. The private scan runs over YEW's own connection, so the
server's pinned certificate (if set) and iOS's webpki roots apply to it like every other call
(`docs/security-review.md`).

## What is left

Everything below needs a device, an account, a public server or a decision:

1. **Physical devices**: the signed iOS build, the biometric prompt, the camera scanner and
   `FLAG_SECURE` on real hardware; the M2 integration test after its amounts are re-based to the
   node's $100 minimum mint.
2. **Ywallet vector**: capture the address for the test mnemonic in `ywallet.json` from a
   Ywallet desktop build.
3. **Security decisions**: a SHA-256 certificate pin (needs `rustls` on the allow-list) versus
   the CA pin; recovery of a carrier stranded by deleting the database mid-mint; iOS switcher
   blur; the keystore binding, the iOS backup exclusion and the webpki roots on real devices.
4. **Public endpoints**: a `lightwalletd-dd --yellowback` over a `ycashd -insightexplorer`
   running the vault upgrade, behind TLS, once a release sets the network's activation height and
   YED attestor set, entered in `net/tls.rs` `default_servers` (mainnet and testnet
   ship empty; the app asks for a server until then).
5. **Testnet run**, store metadata and signing: `docs/release.md`.
6. **Private (Sapling) YEC, hardening**: the HTTPS
   Ycash-hosted mirror for the 52 MB proving files, to list first (today YEW defaults to the
   source ycashd uses; Settings can name another address); a YWallet-built `ys1…` address for the test seed to pin YWallet compatibility from a real
   binary; sync time, proving time and battery on real phones; `lite.ycash.xyz` upgraded to
   lightwalletd-dd with `GetChainInfo`. (Restore with a birthday, reorgs and interrupted sync
   run on both node lines in `s5_`; the private screens ran on the iOS simulator against both.)
7. **Post-quantum**: receiving YEC at an `sq…` address (YEW still hands out `s…`) and spending
   PQ coins directly in a YEC send (today they are moved first); signing on a real
   phone and the device keystore (`docs/design-notes.md` "Q7"). Falcon YED holders are done:
   YED is received, held and sent as Falcon `TX_PQPKH` from the Falcon height (mainnet and
   testnet: day one). The `q` device flow passes on the iOS simulator and the arm64 Android
   emulator; `pq_bench` there (Apple-silicon host, so near desktop speed, not a phone's): SLH-DSA
   keygen ~85 ms, sign ~0.75-0.8 s, verify 0.5 ms; Falcon keygen ~10 ms, sign ~3 ms. Signing
   runs on the bridge's worker thread: the UI kept drawing through the SLH-DSA redeem preview.
8. **Fee structure (rpcversion 8; the workspace's
   `docs/plans/yellowback-quantum-fees-spec.md`, owner decisions D-Q-23..D-Q-26)**: the core
   requires `rpcversion` 8 and computes every fee it signs locally — the protocol fee in dollars
   of the debt in marginal bands (1 % to $1,000, 0.5 % to $10,000, 0.1 % above, $1 minimum) at
   the vault's stored `pMint` (`params::protocol_fee_zat`), the early-redeem fee of the debt,
   `maxMint` $100,000, and network fees at `params.fees.network`'s dollars-per-KB rates
   (recomputed from their own price and target before use, capped at `maxTxFeeZat` and never
   above 10 YEC; the node's `YedEstimatedSize` for Yellowback transactions). The screens show the
   fees in dollars and YEC. `proto/` equals lightwalletd-dd's (`proto/PIN`), including the
   attestor fields. Open: `core/tests/vectors` are still the quantum devnet's (rpcversion 7) until
   they are regenerated on a fees-line devnet.

## Further reading

- [docs/design-notes.md](docs/design-notes.md) — the rules behind the code and the devnet evidence, phase by phase
- [docs/security-review.md](docs/security-review.md) — findings, fixes, deferrals
- [docs/release.md](docs/release.md) — reproducible build, endpoints, store checklist, testnet plan
- [docs/trust.md](docs/trust.md) — what the app trusts, shown to users at onboarding
- `docs/plans/yellowback-wallet-plan.md` in `yellowback-workspace` — the plan and its decision record

## License

MIT, see `LICENSE`.
