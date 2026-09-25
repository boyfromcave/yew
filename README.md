# YEW — Your Electronic Wallet

A transparent-only mobile wallet for YEC and Ycash Yellowback (YED): a small Flutter app for iOS
and Android over a small Rust core. YED is the main currency; everything about it comes through
`lightwalletd-dd`'s `YellowbackStreamer`, everything about YEC through the untouched
`CompactTxStreamer` transparent path. No compact-block scanning, nothing shielded, and no
transaction byte is ever built outside the Rust core.

Plan: `docs/plans/yellowback-wallet-plan.md` in the `yellowback-workspace` repository (this repo
is mounted there at `yew/`). Status: Phase W0a (skeleton); nothing here holds funds yet.

## Layout

```
Cargo.toml          Rust workspace: core (yew-core) and core/cli (yew-cli)
core/               the core: keys, tx, script, payload, bundle, build/, net/, sync, coins,
                    coinselect, store, gate, api, params (stubs; each names its translation source)
core/cli/           yew-cli, the developer's and the devnet tests' driver
core/tests/vectors/ node-generated vectors (Phase W0c)
app/                Flutter project yew_app (org cash.ycash.yew; iOS + Android)
proto/              service.proto, compact_formats.proto, yellowback.proto + PIN (lightwalletd-dd commit)
scripts/            check-proto-pin.sh, check-deps.sh + allowed-deps.txt, build-core-ios.sh,
                    build-core-android.sh, gen-bridge.sh
.github/workflows/  ci.yml
```

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

## Build and test

```bash
cargo build && cargo test            # core + cli (needs protoc on PATH)
cargo run -p yew-cli -- version
scripts/check-proto-pin.sh           # protos identical to ../lightwalletd-dd/walletrpc (skips if absent)
scripts/check-deps.sh                # direct deps ⊆ allow-list
(cd app && flutter test && flutter analyze)
scripts/build-core-ios.sh            # → app/ios/Frameworks/YewCore.xcframework (Xcode)
scripts/build-core-android.sh        # → app/android/app/src/main/jniLibs (cargo-ndk + NDK)
scripts/gen-bridge.sh                # flutter_rust_bridge codegen (Phase W3)
```

Devnet tests (`YEW_DEVNET=1 cargo test -- --ignored`) run against the workspace's regtest devnet
and are not part of CI. To regenerate the Flutter platform folders see `app/README.md`.
`app/ios/ExportOptions.plist.example` is the owner's signing template; the real file stays out
of git.

## Trust statement

_Placeholder (plan §3.5, client contract rule 7)._ YEW trusts the light-client server it is
connected to for what it reports about the chain and about YED (verdicts, token sets, prices);
the server cannot spend your funds, and your keys never leave the device. The final text is
written in Phase W3 and shown once on first launch and from Settings.

## License

MIT, see `LICENSE`.
