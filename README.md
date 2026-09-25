# YEW — Your Electronic Wallet

A transparent-only mobile wallet for YEC and Ycash Yellowback (YED): a small Flutter app for iOS
and Android over a small Rust core. YED is the main currency; everything about it comes through
`lightwalletd-dd`'s `YellowbackStreamer`, everything about YEC through the untouched
`CompactTxStreamer` transparent path. No compact-block scanning, nothing shielded, and no
transaction byte is ever built outside the Rust core.

Plan: `docs/plans/yellowback-wallet-plan.md` in the `yellowback-workspace` repository (this repo
is mounted there at `yew/`). Status: **Phase W1 done** (keys, transactions, YEC send, `yew-cli`,
devnet round trip); W2 (YED) next. Nothing here is a release; the app is the W0a scaffold.

## Layout

```
Cargo.toml          Rust workspace: core (yew-core) and core/cli (yew-cli)
core/               the core (module table below)
core/cli/           yew-cli, the developer's and the devnet tests' driver
core/tests/         vectors.rs (node-generated vectors), devnet.rs (YEW_DEVNET=1, ignored otherwise)
core/tests/vectors/ node-generated vectors from `yellowback-devnet vectors` (Phase W0c)
app/                Flutter project yew_app (org cash.ycash.yew; iOS + Android)
proto/              service.proto, compact_formats.proto, yellowback.proto + PIN (lightwalletd-dd commit)
scripts/            check-proto-pin.sh, check-deps.sh + allowed-deps.txt, devnet-w1.sh,
                    build-core-ios.sh, build-core-android.sh, gen-bridge.sh
.github/workflows/  ci.yml
```

## Core modules (plan §3.1, §3.6)

| Module | Phase | Status | Translated from / verified against |
|---|---|---|---|
| `params.rs` | W1 | done | `ycash-dd/src/chainparams.cpp`, `src/yellowback/params.{h,cpp}`, `src/primitives/transaction.h`; fee citations below |
| `keys.rs` | W1 | done | BIP39 (`bip39`), BIP32 over `hmac`/`sha2` (no extra crate), `m/44'/347'/0'/{0,1}/i` (D-W-7), `s…`/`ye…`/`yt…`/`yr…`, WIF (D-W-11). Tests: BIP32 vector 1, BIP39 TREZOR vector, `addresses.json` |
| `script.rs` | W1 (P2PKH/P2SH), W4 (vault, carrier) | W1 done | `CScript` push encoding (`ref/ycash/src/script/script.h`), `ycash-dd/src/yellowback/script.cpp` `GetPushes` |
| `tx.rs` | W1 | done | v4 serializer/parser (`transaction.h:575-640`), ZIP-243 (`qa/rpc-tests/test_framework/script.py` `SignatureHash`), RFC 6979 signing. `transparent.json`: 12 node transactions reproduced byte-for-byte (unsigned, every sighash, signed, txid) |
| `net/tls.rs`, `net/compact.rs` | W1 | done | `Server`, TLS (`rustls`, native roots) or `--plain`; `GetLightdInfo`, `GetLatestBlock`, `GetAddressUtxos` (paged), `GetTaddressTxids` (stream), `GetTaddressBalance`, `SendTransaction` |
| `net/yellowback.rs` | W2 | — | `YellowbackStreamer` |
| `store.rs` | W1 | done (schema v1) | meta, addresses, utxos+class, locks, history, own_outputs, pending_txs, imported_keys (wrapped) |
| `coins.rs` | W1 (YEC), W2 (YED) | W1 done | classes of §3.7; `SelectYec` from `txbuilder.cpp:399-420`; fee reserve; the YEC-only-phase HELD rule (below) |
| `sync.rs` | W1 (YEC), W2 (YED) | W1 done | §3.2 loop: gap-limit derivation, `GetTaddressTxids` history, `GetAddressUtxos` set, classification, lock release |
| `build/yec_send.rs` | W1 | done | YEC send with change, fee `FEE_ZAT`, `nExpiryHeight = tip + 40`, the `TOKEN_VALUE ± 1 zat` rules |
| `gate.rs` | W1 (YEC path), W2 (YED path) | W1 done | D-W-5; property test on random coin sets (§6.1 item 3) |
| `wallet.rs` | W1 | done | key ring + store + network; not in the plan's file list (added: the object `sync`, the builders and W3's `api.rs` share) |
| `payload.rs`, `bundle.rs`, `coinselect.rs`, `build/{yed_transfer,mint,redeem,claim}.rs`, `api.rs` | W2–W4 | stubs | |

### The fee (plan §7 W1, first task)

`FEE_ZAT = 1_000` zat, the node's flat fee: `ycash-dd/src/yellowback/params.h:79`
`DEFAULT_YELLOWBACK_FEE = 1000` ("equals policy DEFAULT_FEE", `src/policy/fees.h:15`), the floor of
`-yellowbackfee` (`src/init.cpp:1186-1189`), what every node-built template pays
(`src/yellowback/txbuilder.cpp:338`), and `src/wallet/wallet.h:265` `DEFAULT_TRANSACTION_MINFEE =
1000`. The relay floor is `src/main.h:68` `DEFAULT_MIN_RELAY_TX_FEE = 100` zat/kB. Confirmed on
the devnet: `yed_getinfo` → `params.feeZat = 1000`, and `params.json` from the W0c vectors.
`RESERVE_MIN = 105_000` zat = `5 · (FEE_ZAT + 2 · TOKEN_VALUE)`, so the reserve formula's two
terms are equal at the default fee.

### Rules recorded in W1 (plan §3.7)

- **HELD**: until W2 wires `GetAddressTokens`, an own P2PKH output of exactly `TOKEN_VALUE`
  (10,000 zat) cannot be told from a YED token, so it is class `HELD` and unspendable; `balance`
  lists them. W2 replaces this with the server's answer.
- **Fee reserve refinement**: outputs are reserved smallest-first up to the target, but an output
  larger than the whole reserve is never reserved (a one-coin wallet would otherwise show
  "available 0"). When the reserve is short, a YED operation takes its fee from class `YEC`.
- **`TOKEN_VALUE` avoidance**: a send of exactly 10,000 zat pays 10,001; a change of exactly
  10,000 becomes 9,999 (the zat goes to the fee). Change under 100 zat folds into the fee.
- **Imported keys** are stored wrapped under a key derived from the seed (HMAC-SHA256 keystream),
  not in the clear; W3 moves them to the platform keystore with the seed.
- The node's plain wallet RPCs (`sendtoaddress`, `validateaddress`) take the `s…` form; the
  `ye…` form is for the `yed_*` RPCs. `yew-cli address` prints both.

## Toolchain

| Tool | Version | Pinned in |
|---|---|---|
| Rust (stable) | `1.92.0` | `rust-toolchain.toml` |
| Flutter | `3.47.5` (stable) | `app/pubspec.yaml` `environment.flutter`, CI |
| Dart SDK | `3.13.4` | `app/pubspec.yaml` `environment.sdk` (exact lower bound) |
| flutter_rust_bridge (crate + codegen) | to pin (Phase W3; feature `bridge` is the placeholder) | `core/Cargo.toml`, `app/pubspec.yaml` |
| Android NDK | `28.2.13676358` | `app/android/app/build.gradle.kts` |
| protoc | any `>= 3.x` on PATH (`36.1` used) | `core/build.rs` (not vendored) |
| Minimum iOS | 15.0 | `app/ios/Runner.xcodeproj` (`IPHONEOS_DEPLOYMENT_TARGET`); `Podfile` once CocoaPods generates it |
| Minimum Android | API 24 (Flutter default) | `app/android/app/build.gradle.kts` (`flutter.minSdkVersion`) |

Rust targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-linux-android`,
`x86_64-linux-android`, plus the host for `yew-cli` and tests. Direct Rust dependencies are the
allow-list of plan §3.3 (`scripts/allowed-deps.txt`); versions are pinned exactly (`=x.y.z`).
`yew-cli` has no argument-parsing crate for that reason.

## Build and test

```bash
cargo build && cargo test --workspace   # core + cli + node vectors (needs protoc on PATH)
cargo run -p yew-cli -- version
scripts/check-proto-pin.sh           # protos identical to ../lightwalletd-dd/walletrpc (skips if absent)
scripts/check-deps.sh                # direct deps ⊆ allow-list
(cd app && flutter test && flutter analyze)
scripts/build-core-ios.sh            # → app/ios/Frameworks/YewCore.xcframework (Xcode)
scripts/build-core-android.sh        # → app/android/app/src/main/jniLibs (cargo-ndk + NDK)
scripts/gen-bridge.sh                # flutter_rust_bridge codegen (Phase W3)
```

`core/tests/vectors.rs` reads `core/tests/vectors/*.json`. `ywallet_derivation_vector` is
`#[ignore]`d while `ywallet.json` says `"pending": true` (the `[owner]` Ywallet capture, plan
D-W-7); run it with `--ignored` once the file is filled.

## `yew-cli`

```
yew-cli [--server host:port] [--plain] [--wallet PATH] [--network regtest|testnet|mainnet]
        [--seed-file PATH | YEW_SEED="<mnemonic>"] [--passphrase P | YEW_PASSPHRASE=P] [--birthday H]
        status | address [--new] | balance | sync | send-yec <addr> <zat> [--all]
        | export-wif <addr> | import-wif <wif> | history | version
```

Defaults: `127.0.0.1:9067`, TLS on (`--plain` is refused on mainnet), `yew-wallet.sqlite`,
`regtest`. `send-yec` syncs, builds, runs the gate, broadcasts, locks the inputs until the
transaction confirms or its `nExpiryHeight` passes; `--all` allows the fee reserve to be spent.
`import-wif` adds a YecWallet/`ycashd` key outside the HD tree (not covered by the seed);
`export-wif` is byte-identical to `dumpprivkey` (checked on the devnet).

## Devnet acceptance (plan §6.3, §7 W1)

`scripts/devnet-w1.sh` runs a private regtest devnet so the default one is never touched:
`YELLOWBACK_DEVNET_DIR=~/yb-devnet-w1`, `YELLOWBACK_DEVNET_PORTSEED=57`, `lightwalletd-dd` on
`127.0.0.1:9167` (plain HTTP/2).

```bash
scripts/devnet-w1.sh up       # yellowback-devnet up --no-attest --lean + lightwalletd start --port 9167
scripts/devnet-w1.sh test     # YEW_DEVNET=1 cargo test -p yew-core --test devnet -- --ignored
scripts/devnet-w1.sh status
scripts/devnet-w1.sh down [--wipe]
```

`core/tests/devnet.rs`: a fresh wallet syncs to zero, is funded 1.5 YEC from node 0, syncs, sends
0.5 YEC back (the node holds exactly the bytes the core built, `getreceivedbyaddress` agrees),
locks release on confirmation, and a restore from the same seed into a fresh database reproduces
the balance and UTXO set. Not part of CI (nightly on the owner's machine, plan §6.4).

## Trust statement

_Placeholder (plan §3.5, client contract rule 7)._ YEW trusts the light-client server it is
connected to for what it reports about the chain and about YED (verdicts, token sets, prices);
the server cannot spend your funds, and your keys never leave the device. The final text is
written in Phase W3 and shown once on first launch and from Settings.

## License

MIT, see `LICENSE`.
