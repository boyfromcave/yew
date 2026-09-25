# YEW — Your Electronic Wallet

A small mobile wallet for **Ycash (YEC)** and **Ycash Yellowback (YED)**, the decentralized
dollar on Ycash. iOS and Android, one Flutter UI over one Rust core.

**For users.** YEW holds YEC and YED in transparent addresses and lets you receive, send and see
your history for both. YED is the main currency: 1 YED is a dollar, and the app shows YEC only
because every transaction needs a little YEC for fees and every mint needs YEC as collateral.
Beyond send and receive, the Yellowback tab lets you mint YED against locked YEC, watch and
redeem your vaults, and claim an undercollateralized vault. YEW is **transparent only**: your
addresses, balances and transactions are public on the chain, and it never holds shielded
funds. Your keys never leave the phone; the app trusts one light-client server you choose for
its view of the chain, and every YED transaction is checked by that server's node before it is
sent. The full statement is [docs/trust.md](docs/trust.md).

**Status (2026-09-25).** Feature complete for the plan's scope and running on the iOS simulator
and the Android emulator against a regtest devnet, where the full send/receive flow passes end
to end. Not released: no public server endpoints yet, no store builds, no testnet run. See
[What is left](#what-is-left) at the end.

## Quick start for developers

Prerequisites: Rust (the exact version is in `rust-toolchain.toml`; `rustup` installs it),
`protoc` on PATH, Flutter 3.47.5, and for devices Xcode or the Android SDK with NDK
28.2.13676358 plus `cargo install cargo-ndk`. Everything else is pinned in the repo.

```bash
git clone git@github.com:boyfromcave/yew.git && cd yew
cargo test --workspace                 # core, CLI and the node-generated vectors
(cd app && flutter test)               # widget tests over a fake bridge
```

To run the app you need a Yellowback devnet and its lightwalletd, which live in the
`yellowback-workspace` repository this repo is normally mounted in (at `yew/`). With that
workspace beside you:

```bash
scripts/devnet-w4.sh up                # once: an armed regtest devnet + lightwalletd on 127.0.0.1:9267
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
  No compact blocks, no shielded scanning.
- **A mint is a persisted state machine, not a process.** Minting takes two transactions (a
  carrier holding the price attestations, then the mint itself) inside a 40-block window. The
  `mints` table holds every fact the second step needs, only the sync loop advances a row, and
  a killed app resumes from the table; a lapsed carrier is swept back.
- **Labels come from the node's verdicts.** History rows for Yellowback transactions are
  labelled from `GetTxInfo`, never from decoding the payload locally.
- **The node is the oracle for tests.** `core/tests/vectors/` holds transactions the node
  signed, addresses, mint/transfer/redeem templates and parameters, exported by the workspace's
  `yellowback-devnet vectors`; the core must reproduce them byte for byte.

The reasoning behind each rule, with the evidence from the devnet, is in
[docs/design-notes.md](docs/design-notes.md).

## Repository layout

```
Cargo.toml              Rust workspace: core (yew-core) and core/cli (yew-cli)
core/src/               the core; api.rs is the bridge surface, frb_generated.rs is generated
core/cli/               yew-cli: the developer's driver and what the devnet tests use
core/tests/             vectors.rs (node vectors), devnet.rs (acceptance; YEW_DEVNET=1, ignored otherwise)
core/tests/vectors/     node-generated vectors (ywallet.json is pending an owner capture)
app/                    Flutter project yew_app (org cash.ycash.yew)
app/lib/api/            WalletApi interface + the one file that calls the bridge
app/lib/state/          AppState, the single app state
app/lib/screens/        one file per screen, each under 300 lines
app/lib/src/rust/       generated by scripts/gen-bridge.sh; never edited
app/test/               widget tests over test/fake_wallet_api.dart
app/integration_test/   m1 (send/receive) and m2 (mint/vault/claim) flows against a devnet
proto/                  the three lightwalletd-dd .proto files + PIN (the commit they came from)
scripts/                build, run, devnet and CI check scripts (listed below)
docs/                   trust.md, design-notes.md, security-review.md, release.md, licenses.md
flutter_rust_bridge.yaml   codegen config
.github/workflows/ci.yml
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

The armed regtest devnet (eight nodes, three attestors, the price layer live) comes from the
workspace's `ycash-dd/contrib/yellowback/devnet/yellowback-devnet`. `scripts/devnet-w4.sh`
wraps it for YEW: directory `~/yb-devnet-w0c`, port seed 9, `lightwalletd-dd --yellowback` on
`127.0.0.1:9267`, plain HTTP/2.

```bash
scripts/devnet-w4.sh up | status | down [--wipe]
scripts/run-ios.sh [host:port] [--test m1|m2]       # default server 127.0.0.1:9267
scripts/run-android.sh [host:port] [--test m1|m2]   # default server 10.0.2.2:9267 (the emulator's name for the host)
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
dn cli --node 0 -- yed_send <ye-address> 5000        # $50.00 of YED from node 0
dn price 50 && dn mine 1 2                           # re-quote, one block on pool node 2
```

Copy the `s…` address for YEC and the `ye…` address for YED from the Receive screen (same key,
two encodings). The integration tests print a `YEW M1:` / `YEW M2:` line whenever they need
you to fund or mine, and wait up to three minutes. `m1` passes on both platforms; `m2` reaches
the mint estimate and stops because the node's minimum mint is $100 while the test's amounts
were written smaller (see [What is left](#what-is-left)).

## Testing

| Level | Where | Runs |
|---|---|---|
| Unit | `core/src/**` `#[test]` | `cargo test`; includes property tests that no YEC-path transaction ever spends a token, vault or carrier input, on thousands of random coin sets |
| Node vectors | `core/tests/vectors.rs` | `cargo test`; twelve node-signed transactions, addresses, templates reproduced byte for byte |
| Widget | `app/test/` | `flutter test`; 29 tests over the fake bridge |
| Devnet acceptance | `core/tests/devnet.rs` | `scripts/devnet-w1.sh test`, `devnet-w2.sh test`, `devnet-w4.sh test`; YEC round trip and restore, YED transfer and gate refusal, mint/redeem/claim/lapse/resume; nightly, not CI |
| Device integration | `app/integration_test/` | `scripts/run-ios.sh --test m1`, `run-android.sh --test m1` |

`ywallet_derivation_vector` is `#[ignore]`d until `core/tests/vectors/ywallet.json` is filled
from a Ywallet desktop build.

## `yew-cli`

The CLI drives the same core the app does and is the fastest way to reproduce anything.

```
yew-cli [--server host:port] [--plain] [--ca-pem PATH] [--wallet PATH] [--network regtest|testnet|mainnet]
        [--seed-file PATH | YEW_SEED="<mnemonic>"] [--passphrase P] [--birthday H]
        status | yed-info | price | address [--new] | balance | coins | sync | history
        | send-yec <addr> <zat> [--all] | send-yed <addr> <cents> [<addr> <cents> ...]
        | export-wif <addr> | import-wif <wif>
        | mint-estimate <cents> <lockBlocks> | mint-start <cents> <lockBlocks>
        | mint-status [<id>] | mint-finish <id> | mint-sweep <id>
        | vaults | redeem <vaultTxid> | claimable | claim <vaultTxid> | version
```

Defaults: `127.0.0.1:9067`, TLS on (`--plain` is refused outside regtest; `--ca-pem` pins one
certificate as the only trust anchor), `yew-wallet.sqlite`, regtest. `coins` lists every UTXO
with its class; `--all` lets a YEC send spend the fee reserve; `export-wif` is byte-identical to
`ycashd`'s `dumpprivkey`, so a YEW key imports into YecWallet, vault ownership included.

## Security

`docs/security-review.md` is the threat review: seed and key handling (key material is wiped,
the seed lives in the platform keystore and exists in the core only inside `Wallet::open`), the
gate (every `SendTransaction` call site sits behind both layers), TLS (plain is a regtest-only
property; CA pinning in the core and CLI), storage (`0600` cache, no Android backups,
`FLAG_SECURE` on seed and key screens), and the bridge boundary. `cargo audit` and a license
allow-list run in CI. The app has no telemetry and nothing in the core logs.

Known gap: `rustls-native-certs` has no iOS backend, so a TLS server on iOS fails until webpki
roots are added (an allow-list decision) or a CA is pinned.

## What is left

Everything below needs a device, an account, a public server or a decision:

1. **Physical devices**: the signed iOS build, the biometric prompt, the camera scanner and
   `FLAG_SECURE` on real hardware; the M2 integration test after its amounts are re-based to the
   node's $100 minimum mint.
2. **Ywallet vector**: capture the address for the test mnemonic in `ywallet.json` from a
   Ywallet desktop build.
3. **Security decisions**: keystore-bound biometrics; a SHA-256 certificate pin (needs `rustls`
   on the allow-list) versus the CA pin; recovery of a carrier stranded by deleting the database
   mid-mint; iOS backup exclusion and switcher blur; iOS TLS roots (above); the app's pinning field.
4. **Public endpoints**: a `lightwalletd-dd --yellowback` over a `ycashd -yellowback
   -insightexplorer` behind TLS, entered in `net/tls.rs` `default_servers` (mainnet and testnet
   ship empty; the app asks for a server until then).
5. **Testnet run**, store metadata and signing: `docs/release.md`.

## Further reading

- [docs/design-notes.md](docs/design-notes.md) — the rules behind the code and the devnet evidence, phase by phase
- [docs/security-review.md](docs/security-review.md) — findings, fixes, deferrals
- [docs/release.md](docs/release.md) — reproducible build, endpoints, store checklist, testnet plan
- [docs/trust.md](docs/trust.md) — what the app trusts, shown to users at onboarding
- `docs/plans/yellowback-wallet-plan.md` in `yellowback-workspace` — the plan and its decision record

## License

MIT, see `LICENSE`.
