# YEW Web — the browser shell on the YEW core: plan

**Revision 1 (2026-10-08).** From the workspace ideation document
(`docs/ideation/yellowback-web-wallet-and-k8s-plan.md`, branch `ideation/web-wallet`) and the
owner's decisions of the same day. Branch `up/web` off `upgrade/vault` (the in-term branch
`upgrade/vault-in-term` is not yet merged into `upgrade/vault` in this repo; merge it first, or
rebase `up/web` when it lands). The backend it runs against is the `ycash-infra` repository.

## 0. Owner decisions (2026-10-08)

| # | Decision | Answer |
|---|---|---|
| I-1 | Custody | **Non-custodial.** The seed never leaves the browser. |
| I-2 | Home | **`yew/web/`** beside `yew/app/`: one core, one CI, one release train. |
| I-3 | Scope of the first release | **Sapling from day one** (private YEC, memos, shield/unshield), plus everything the Flutter app does: public YEC, YED, mint/redeem/claim. |
| I-4 | Storage | **sqlite-wasm over OPFS**: keep `rusqlite` and `zcash_client_sqlite`; no IndexedDB rewrite of the store. |

**Decisions of 2026-10-09** (after W0.1; the owner leans to the most recent toolchains that still compile):

| # | Decision | Answer |
|---|---|---|
| D-1 | librustzcash6 toolchain pin on `up/web` | **1.96.0** (ycash6's pin, which already builds librustzcash6 inside its depends) |
| D-2 | rusqlite / arti line | **rusqlite 0.39 + arti 0.44** (+ fs-mistrust 0.15, `time-core` unpinned → `time` 0.3.55): the most recent set that resolves; arti 0.47 is blocked by the next RustCrypto generation against librustzcash6's pinned pre-releases. One-line tor.rs change (`Arc<TorClient>`). |
| D-3 | Consumers (`x402-ycash/light`, `yew-core`) | **move now**, on their own `up/web` branches |
| D-4 | Patched `schemerz-rusqlite` | **vendored** under `librustzcash6/components/` |

## 1. The shape

```
yew/
├── core/            yew-core (unchanged API; gains a `wasm` cargo feature, §2)
├── app/             the Flutter shell
└── web/
    ├── core-wasm/   crate yew-web-core: wasm-bindgen over yew-core's internal API (what api.rs is for Dart)
    ├── src/         TypeScript PWA: the six screens; cannot construct bytes (same rule as app/lib)
    ├── index.html, vite.config.ts, package.json
    └── scripts/     build-core-wasm.sh, check-web-imports.sh
```

The Dart bridge (`core/src/api.rs`, `flutter_rust_bridge`) and the wasm bridge
(`web/core-wasm/src/lib.rs`, `wasm-bindgen`) are two thin bindings over the same internal
functions. **No logic moves and nothing is reimplemented in TypeScript**: keys, serialization,
ZIP-243, scripts, payloads, builders, the broadcast gate, the Sapling builder and prover all run
in the WebAssembly module. `scripts/check-web-imports.sh` forbids crypto, sqlite and socket
packages under `web/src`, as `check-app-imports.sh` does for `app/lib`.

## 2. What must change in the core for `wasm32-unknown-unknown` (W0)

Every item is a cargo feature or a dependency swap, gated under `features = ["wasm"]` so the
iOS/Android builds are byte-for-byte what they are today.

| Today (`core/Cargo.toml`) | On wasm | Note |
|---|---|---|
| `tokio` rt-multi-thread + private runtime for blocking calls | `wasm-bindgen-futures`; the bridge is `async` and returns `Promise`s | the core's internals are already `async` behind `block_on` |
| `tonic` channel with `tls-ring` | `tonic-web-wasm-client` (gRPC-web over `fetch`) | the light library already takes an injected channel (S1/Z-3); TLS is the browser's |
| `rusqlite = { bundled }` (yew store + `zcash_client_sqlite`) | `sqlite-wasm-rs` as the `libsqlite3-sys` replacement (`[patch.crates-io]`), OPFS `opfs-sahpool` VFS | **I-4**. Verify first in W0: one crate graph, one SQLite, `zcash_client_sqlite` unchanged; `FsBlockDb` (compact blocks on disk) becomes a `BlockSource` over OPFS |
| `zcash_proofs` `multicore` (rayon) | `wasm-bindgen-rayon` in a Web Worker pool, or single-threaded | needs COOP/COEP (`SharedArrayBuffer`); the infra's nginx/gateway set them |
| `rustls-native-certs` / `webpki-roots` | not linked | |
| `rand` / `getrandom` | `getrandom` feature `js` | |
| `flutter_rust_bridge` | not linked | `yew-web-core` is a separate crate; `yew-core`'s `api.rs` stays Dart-only |

Proving parameters (52 MB) are fetched once into the Cache API from the same source order and
with the same SHA-256 pins as the Flutter app (S0-2), on first private send. Expect 10–30 s per
Sapling send in WASM; the slide-to-confirm plus progress sheet carries over.

## 3. Security

- **Seed at rest:** encrypted in IndexedDB under a key derived by WebAuthn **PRF** (passkey) with
  an Argon2id passphrase fallback; never in `localStorage`, never in a cookie, never sent.
  Unlock produces the seed inside the WASM module's memory only.
- **Code integrity:** strict CSP (`script-src 'self' 'wasm-unsafe-eval'`, `connect-src 'self'`),
  SRI on every asset, a reproducible build whose bundle hash is published with each release.
- **Same origin as the API**: the gateway serves both, so the wallet's one network destination is
  its own origin (ycash-infra chart, `web.enabled`).
- **The broadcast gate** (`gate.rs`) runs unchanged; every `confirm` passes it.
- **Stated limits** (`docs/trust.md` gains a web section): a compromised browser or extension
  is outside what any web wallet can defend; a native app with a platform keystore is stronger.

## 4. Chunks

| Chunk | Where | Size | Acceptance |
|---|---|---|---|
| **W0** core on wasm32 | `core/`, `web/core-wasm/` | **L** (2–3 wk) | `wasm-pack build web/core-wasm` succeeds; the node transparent vectors and the Sapling key vectors pass in `wasm-bindgen-test` (headless Chrome); the store opens on OPFS; a compact-block scan of the regtest chain runs in a worker |
| **W1** shell | `web/src` | **L** (2–3 wk) | the six screens (home, receive, send, history, settings, yellowback) + mint/vault/claimable; onboarding with passkey seed encryption; CSP/SRI; `check-web-imports.sh` |
| **W2** on kind | with `ycash-infra` K0/K4 | **M** (1 wk) | sync, private send with memo, shield/unshield, YED send, mint/redeem/claim through the gateway over gRPC-web; screenshots |
| **W3** hardening | both | **M** (1 wk) | reproducible build hash; trust text; restore-with-birthday; reorg; proving time on a low-end laptop; Safari/Firefox OPFS behaviour |

## 5. Status

- [x] W0 scaffold (2026-10-08): `web/` tree, `yew-web-core` crate skeleton, Vite shell with
  COOP/COEP dev headers, this plan.
- [x] **W0.1 sqlite-wasm verification (I-4) — done 2026-10-08, verdict: yes.** `web/spike-sqlite`
  (`web/scripts/test-spike-sqlite.sh`) runs two `wasm-bindgen-test`s in headless Chrome, in a
  dedicated worker, debug and release: a SQLite round trip that persists across connections on
  OPFS (sahpool VFS), and **`zcash_client_sqlite`'s `WalletDb` opening on OPFS with every
  migration run**. Findings, in order of consequence:
  1. **rusqlite 0.38 is the first release with a wasm32-unknown-unknown backend** (`sqlite-wasm-rs`
     0.5 behind its default `ffi-sqlite-wasm-rs` feature); librustzcash6 pins 0.37. The bump is
     in `librustzcash6` branch `up/web` (`wt/librustzcash6-web`, `2e7b5902`): rusqlite 0.38 with
     `fallible_uint` (0.38 moved the u64/usize SQL conversions behind that feature; with it,
     `zcash_client_sqlite` compiles **unchanged**), `schemerz-rusqlite` 0.370 carried under
     `components/` with its requirement raised (there is no 0.380), arti 0.39 + fs-mistrust 0.13
     for the `tor` feature (the only arti line that takes rusqlite 0.38 without moving `time`).
     **Owner decision:** arti 0.39 needs rustc 1.86 and librustzcash6's toolchain pin is 1.85.1;
     either raise the pin (ycash6 builds it with a newer toolchain anyway) or leave the `tor`
     feature unresolvable in that workspace. Checked natively with 1.92.
  2. Consumers must follow: `x402-ycash/light` (`rusqlite = "0.37"`) and `yew-core`
     (`rusqlite = "=0.37.0"`, allow-list) move to 0.38, and each root manifest repeats the
     `schemerz-rusqlite` path/git patch (patches do not propagate through dependencies).
  3. `sqlite-wasm-vfs` **0.2** is the VFS crate for this line (0.3 needs `sqlite-wasm-rs` 0.6,
     which no rusqlite release uses yet). Its sahpool tracks open files by name: one connection
     per file at a time, or its debug assertion fires on the second close.
  4. `SystemTime::now()` is unavailable on wasm32: the spike's `JsClock` (`js_sys::Date`)
     implements `zcash_client_sqlite::util::Clock`; `yew-core` needs the same under `wasm`.
  5. Toolchain: Apple clang cannot target wasm32 (secp256k1-sys compiles C), so Homebrew LLVM's
     clang via `CC_wasm32_unknown_unknown`; wasm-pack's ChromeDriver download can be newer than
     the installed Chrome and it ignores `$CHROMEDRIVER`, so the script drives `cargo test` with
     a version-matched driver. `getrandom` needs its `js` feature.
  Not yet covered: `FsBlockDb` (the compact-block cache is `std::fs` on disk) and the Sapling
  prover on wasm32 — the next W0 tasks, in that order.
  **Applied 2026-10-09 per D-1..D-4:** librustzcash6 `up/web` `7cc50e16` (rusqlite 0.39, arti 0.44,
  toolchain 1.96.0; 134 `zcash_client_sqlite` tests green; the browser spike green on 0.39);
  `x402-ycash` `up/web` `05bece7` (light on 0.39; 31+5 tests green); `yew` `up/web` (this commit:
  `yew-core` on `=0.39.0`; 123+6 tests, deps/licence checks green). **Until librustzcash6 and
  x402-ycash `up/web` are pushed, the three root manifests carry LOCAL path patches** (flagged
  in each `Cargo.toml`); the push replaces them with git revs, in the order librustzcash6 →
  x402-ycash → yew.
- [ ] W0.2 `FsBlockDb` → a `BlockSource` over OPFS (or `MemBlockCache`) for the browser
- [ ] W0.3 `zcash_proofs` local prover in a Web Worker (single-thread first; `wasm-bindgen-rayon` after)
- [x] **W0.4 `yew-core` and `x402-ycash/light` compile for wasm32 (network layer) — done
  2026-10-09.** `cargo check -p yew-core --target wasm32-unknown-unknown` and `cargo check
  --target wasm32-unknown-unknown` of `x402-ycash/light` (lib and bin) pass, warning-free;
  native is unchanged: yew 123+6 tests, `check-deps.sh` (now `--target all`), `check-licenses.sh`
  (364 crates), fmt; light 31+5 tests. `web/spike-net` (`web/scripts/test-spike-net.sh`) builds
  the whole of yew-core for wasm32 and runs three `wasm-bindgen-test`s in headless Chrome, debug
  and release: a `GetLightdInfo` over an `https://` gRPC-web channel and a `GetYellowbackInfo`
  over a plain one each come back as a `Status` error (no server listens: the channel builds
  offline and the request is attempted), and a pinned certificate is refused in the browser.
  Branches `up/web-core` in yew (`core/`, this commit) and x402-ycash (`light/`).
  **Not a cargo feature.** Plan §2 said `features = ["wasm"]`; the delta is pure
  `cfg(target_arch = "wasm32")`: per-target dependency tables and item gates. A feature would
  have to be asked for by every consumer and could be set on a native build; the target cfg
  cannot, and the native graph is byte-for-byte the old one (the native table is the old
  `[dependencies]` lines, same features). What changed per crate:
  - **`x402-ycash/light`** (the consumer yew-core reaches the Sapling sync through): `tokio`,
    `tonic`, the binary's deps (hyper, clap, tracing-subscriber), `zcash_proofs`,
    `zcash_client_sqlite` and `zcash_primitives` are per target; `lwd::Channel` is a per-target
    type alias (`tonic::transport::Channel` / `tonic_web_wasm_client::Client`) and
    `Options::channel`, `Wallet::channel()`, `lwd::connect` use it; the sync producer is
    `tokio::spawn` natively and `wasm_bindgen_futures::spawn_local` in the browser
    (`sync::spawn_producer`); `Wallet::build` answers `Error::ProverUnsupported` on wasm32 and
    `spend::assemble` is native-only; the `x402-light` binary is an empty program on wasm32.
    **The client stubs are now generated in `light/build.rs` from the vendored protos over the
    backend's message types** (`extern_path`, as librustzcash's own build does; `Exclude` maps
    to `GetMempoolTxRequest`, `CompactSpend`/`CompactOutput` to the Sapling names), and the
    `lightwalletd-tonic` feature of `zcash_client_backend` is dropped: its checked-in
    `service.rs` carries an unconditional `connect` over `tonic::transport::Channel`, which no
    tonic feature provides on wasm32 (the alternative was a librustzcash6 change —
    `build_transport(false)` — in a worktree this task does not own; worth doing there later so
    the feature can come back). Both targets use the same generated client.
  - **`yew-core`**: `net::Channel` is the same per-target alias (so one channel still serves the
    private sync, Z-3); `Server::connect` builds a `tonic_web_wasm_client::Client` from
    `Server::uri()` in the browser and refuses `ca_pem` (TLS is the browser's; a pin the page
    cannot honour must not look honoured); `net/tls.rs`'s endpoint/TLS, `NetError::Transport`,
    `api.rs` + `frb_generated.rs` (the Dart bridge and its tokio runtime), the parameters fetch
    in `sapling_params.rs` (`download` and the HTTP/TLS client under it; `status`,
    `ensure_verified`, `ParamsSource` stay) and the prover (`Shielded::build`, `build_shield`,
    `load_prover`) are native-only; on wasm32 `build`/`build_shield` answer
    `ShieldedError::ProverUnsupported`, and `Shielded::sync` runs without the progress ticker
    (a tokio task on a second store connection; the browser gets the final progress calls).
    `build.rs` generates both clients with `build_transport(false)` (nothing used the generated
    `connect`). `.cargo/config.toml` (new) sets `--cfg getrandom_backend="wasm_js"` for the
    wasm32 target.
  Dependency table (`core/Cargo.toml`; `light/Cargo.toml` mirrors it with caret versions):

  | Crate | native (unchanged) | wasm32-unknown-unknown |
  |---|---|---|
  | `tonic` 0.14.6 | `codegen, channel, tls-ring, tls-native-roots, tls-webpki-roots` | `codegen` only |
  | `tonic-web-wasm-client` | — | **0.9.2** (the tonic 0.14 line; 0.7 = tonic 0.13; MIT/Apache-2.0) |
  | `tokio` 1.53.1 | `rt-multi-thread, macros, sync, time, net, io-util` | `sync` (light: `sync, macros`) |
  | `wasm-bindgen-futures` | — | 0.4.78 |
  | `getrandom` | — | 0.2 `js` **and** 0.3 `wasm_js` (+ the cfg flag; secp256k1 0.33 → rand 0.9) |
  | `webpki-roots`, `tokio-rustls`, `flutter_rust_bridge` | as before | not linked |
  | `zcash_proofs` | `local-prover` | not linked (`local-prover` → `home`, no wasm32 build; W0.3) |
  | `zcash_client_sqlite` / `zcash_primitives` (light) | defaults (`multicore`) | `default-features = false`: halo2_proofs refuses `multicore` on wasm32 without atomics |

  Traps: (1) `zcash_client_backend` `lightwalletd-tonic` does not compile without tonic
  `channel` (above). (2) `zcash_proofs` `local-prover` is unbuildable on wasm32 through `home`.
  (3) halo2_proofs: `multicore` on, serial `maybe-rayon` → compile error; `multicore` must be
  off everywhere in the wasm32 graph, so every consumer declares `zcash_client_sqlite` and
  `zcash_primitives` without defaults there. (4) getrandom 0.3's wasm backend needs a cfg flag,
  not just a feature. (5) `cargo tree` without `--target all` does not show the wasm32 table
  (the deps check now passes it). (6) The generated gRPC clients' `connect` is the one thing in
  tonic codegen that names the transport; `build_transport(false)` on both build scripts.
  **Stubs W0.2 / W0.3 replace** (they compile on wasm32 and fail at run time, or answer
  `Unsupported`): `x402_ycash_light::Wallet::open` (`std::fs`, `FsBlockDb`, the `wallet.lock`
  file lock, `SystemClock`) and `sync.rs`'s `fs::write` of block files and `std::time::Instant`
  timings; `yew_core::shielded::Shielded::open` (`std::fs`, `SystemClock`); `Shielded::sync`'s
  `Instant::now()`; the two `ProverUnsupported` stubs (light `Wallet::build`, yew
  `Shielded::build` / `build_shield`) and `sapling_params::download` (native-only; the browser
  fetch into the Cache API); `rusqlite` on wasm32 needs the sahpool VFS installed before any
  open (W0.1's `install_opfs`). `web/core-wasm` can now depend on `yew-core` (its comment says
  how); it still exposes `status()` only.
- [ ] W0 complete
- [ ] W0 complete
- [ ] W1
- [ ] W2
- [ ] W3
