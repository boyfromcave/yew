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
- [x] **W0.2 the compact-block cache on OPFS — done 2026-10-09, option 1 (`BlockDb`).**
  `web/spike-blockdb` (`web/scripts/test-spike-blockdb.sh`) runs two `wasm-bindgen-test`s in
  headless Chrome, in a dedicated worker, debug and release: (a) three `CompactBlock`s written to
  `zcash_client_sqlite::BlockDb` on OPFS, read back byte-identical through the `BlockSource` API
  after the cache is dropped and reopened, the cache-miss semantics checked, then truncated; (b)
  **`scan_cached_blocks` over that cache against a `WalletDb` on OPFS with a fresh ZIP-32
  account** (`create_account`, birthday 1), the second of three blocks carrying a real
  Sapling output to the account's default address — the scan reports one received note, the
  wallet summary 100 000 zatoshis spendable, fully scanned to 3. Findings:
  1. **`BlockDb` is enough; no new storage code.** The old SQLite block source (one table,
     `compactblocks(height, data)`, `chain::init::init_cache_database`) is not feature-gated,
     reports a cache miss when `from_height` is not cached (as the sync loop expects), and on sahpool it is one more SQLite
     file beside the wallet's. `MemBlockCache` was not needed. The one adaptation: `BlockDb` owns
     its connection privately and has no write API, and sahpool allows **one connection per file
     name at a time** (W0.1 finding 3), so the spike's `BlockCache` holds only the path: writes
     (`INSERT OR REPLACE`) and truncation (`DELETE`) go through a short-lived
     `rusqlite::Connection`, and its `BlockSource` impl opens the `BlockDb` per `with_blocks`
     call and drops it after. Opening on sahpool is cheap (pooled handle, no I/O beyond the
     header). The debug build keeps the VFS's "DB closed without open" assertion live
     (`[profile.dev.package.sqlite-wasm-vfs] debug-assertions = true`) so the test proves it.
  2. **The trap: `scan_cached_blocks` hangs on wasm32 without threads.** `zcash_client_backend`
     depends on rayon unconditionally and trial-decrypts in batches it `rayon::spawn_fifo`s
     (`scan.rs:178`), then blocks on a channel for the results (`collect_results`). rayon-core's
     wasm fallback is a one-worker pool on the current thread whose spawned jobs run only when
     something yields to it; nothing in the scanner does, so the first block with an output
     waits forever (seen as a wasm-bindgen-test timeout after "blocks cached"). The fix needs no
     backend change: the cache's `with_blocks` calls `rayon::yield_now()` until it returns
     `Idle`, before the first row and after every row, which runs the pending batches on this
     thread (`run_pending_batches`, `cfg(target_arch = "wasm32")`; native builds have real
     workers and skip it). `wasm-bindgen-rayon` (W0.3's second step) would replace the fallback
     with real workers; the drain stays harmless then.
  3. The standalone spike workspace needed `[profile.dev.package."*"] opt-level = 3` (as the yew
     root manifest has): at opt-level 0 the debug scan overran wasm-bindgen-test's 20 s default;
     the script also sets `WASM_BINDGEN_TEST_TIMEOUT=120`. With it both tests finish in 0.3 s.
  4. Versions: the W0.1 recipe unchanged (rusqlite 0.39, sqlite-wasm-rs 0.5, sqlite-wasm-vfs 0.2,
     librustzcash6 `up/web` `7cc50e16` by local path); plus `zcash_note_encryption` 0.4,
     `sapling-crypto` 0.7 (`std`), `zcash_primitives` (`zip212_enforcement`) and `rayon` 1 for
     the test output builder and the drain. The output builder is
     `data_api::testing::compact_sapling_output` without its harness (the `test-dependencies`
     feature is not needed).
  **What W0.4 changes in x402-ycash/light's `Wallet`:** `cache: FsBlockDb` + `blocks_dir: PathBuf`
  become one `cache: BlockCache` (this spike's type, moved into light behind `cfg(target_arch =
  "wasm32")` or used on both targets — it is cross-platform and `BlockDb` works on disk too);
  `Wallet::open` calls `BlockCache::open(<data_dir>/cache.sqlite)` instead of `create_dir_all` +
  `FsBlockDb::for_path` + `init_blockmeta_db`; `scan_chunk` keeps the `chain_metadata` fill but
  replaces `fs::write` + `write_block_metadata` with `cache.insert(&blocks)` (the `BlockMeta`
  rows go away); `clear_cache` becomes `cache.truncate()`; the `FsBlockDbError` in the three
  `ChainError<_, FsBlockDbError>` signatures (`scan_chunk`, `bad_cmu`, `wallet.rs:861,868`)
  becomes `SqliteClientError`; and `scan_cached_blocks(&self.params, &self.cache, ...)` is
  unchanged. `fs::` in `Wallet::open` (data dir, lock file) and the `std::fs` cache walk are the
  only other `std::fs` uses on the sync path.
- [x] **W0.3 `zcash_proofs` local prover in a Web Worker — done 2026-10-09, verdict: yes,
  single-threaded, ~18 s for a spend + two outputs.** `web/spike-prover`
  (`web/scripts/test-spike-prover.sh`) runs two `wasm-bindgen-test`s in headless Chrome 154, in a
  dedicated worker, debug and release: the Sapling parameters fetched as bytes and pinned, a
  `LocalTxProver::from_bytes`, and **one Sapling spend + two outputs built, proved and signed**
  with it (`sapling_crypto::builder::Builder`, the shape of `zcash_primitives`' own
  `binding_sig_present_if_shielded_spend` test). Measured on the owner's M-series laptop (10
  cores, one used):

  | build | fetch (local http) | parse params | prove 1 spend + 2 outputs | linear memory after |
  |---|---|---|---|---|
  | dev (deps at opt-level 3, spike at 0) | 993 ms | 360 ms | **21.0 s** | 115 MiB |
  | release (lto, no wasm-opt) | 905 ms | 275 ms | **18.2 s** | 115 MiB |

  The 115 MiB is `WebAssembly.Memory` after parse and after prove (same figure: linear memory
  only grows, so it is a peak, and the proof itself fits in what the 52 MB download + the parsed
  parameters already reserved). The release test `.wasm` is 1.9 MB before wasm-opt.
  Findings, in order of consequence:
  1. **`zcash_proofs` feature set for wasm32: `default-features = false, features =
     ["local-prover"]`** — `multicore` off (rayon; no threads), `download-params`/`bundled-prover`
     off. `local-prover` cannot be dropped: `pub mod prover` (`LocalTxProver`, `from_bytes`
     included) is gated on `any(local-prover, bundled-prover)` (`zcash_proofs/src/lib.rs:32`),
     and `local-prover` = `directories` pulls `home`, `xdg`, `known-folders`; **`home` 0.5.12
     does not compile for wasm32** (`home_dir_inner` exists only for unix/windows). The spike
     gets past it with a test-only `[patch.crates-io] home = { path = "shim/home" }` returning
     `None`. **Fixed 2026-10-09 in librustzcash6 `up/web` (`f04a2ab9`):** the `directories`
     dependencies are `[target.'cfg(not(target_arch = "wasm32"))']` and the default-location
     lookup (`default_params_folder`, `with_default_location`) is native-only; `from_bytes` is
     the browser API. The spike builds without its shim (removed). `sapling-crypto` needs `circuit` (not
     `multicore`), which `zcash_proofs` already enables through `zcash_primitives/circuits`;
     `cargo tree -i rayon` is empty.
  2. **Parameters reach the prover as bytes, no filesystem**: `fetch_param` looks in the Cache
     API (`caches.open("yew-sapling-params-v1")`), else fetches `<source><name>` for the sources
     in order, and keeps bytes only if length and SHA-256 equal the pins
     `core/src/sapling_params.rs` carries (`SPEND`/`OUTPUT`/`DEFAULT_SOURCES`, copied verbatim
     into the spike with a citation; W0.4 links the module itself). A cache entry that no longer
     verifies is deleted, not used. Then `LocalTxProver::from_bytes(&spend, &output)` — the
     constructor `x402-ycash/light`'s `take_prover` and `yec_private.rs` should call on wasm
     instead of `new(Path)`. The test script serves the two files from `~/.cache/yew-web/
     sapling-params` (fetched once from download.z.cash; SHA-256 checked by the test anyway)
     over a 10-line Python HTTP server with `Access-Control-Allow-Origin: *`, base URL passed at
     compile time as `SPIKE_PARAMS_URL`; without it the test falls through to download.z.cash.
     `include_bytes!` was rejected: 52 MB in every test binary.
  3. **Threading decision: single-threaded for W1.** The proof runs inside the dedicated worker
     the test already uses, so the UI thread is free; 18 s per spend+2 outputs on one core is
     usable with a progress UI (`ProverProgress` is already a hook in `create_proofs`). The
     `wasm-bindgen-rayon` step was **not attempted**: it needs the std rebuilt with
     `+atomics,+bulk-memory,+mutable-globals` (`-Zbuild-std`, nightly only), and the yew
     toolchain pin is stable 1.92.0. The harness is not the blocker: wasm-bindgen-test-runner
     0.2.129 does serve `Cross-Origin-Opener-Policy: same-origin` /
     `Cross-Origin-Embedder-Policy: require-corp`, and the Vite shell already sets both. Revisit
     once stable ships an atomics std for wasm32 (or if the owner accepts a nightly for the web
     build only); expect roughly a 4–6x gain on an 8–10-core device from bellman's multiexp.
  4. Clocks and entropy: `std::time::Instant` is unavailable on wasm32, so the spike times with
     `performance.now()` from `WorkerGlobalScope`; `getrandom` 0.2 needs `js`; `OsRng` then
     works for the prover's randomness.
  5. Not covered: a Sapling *transaction* (the `zcash_primitives` `Builder` with fees and the
     transparent/`zcash_client_backend` plumbing) — only the Sapling bundle; the full build is
     W0.4's job once `yew-core` compiles for wasm32. Orchard is linked (`zcash_primitives/
     circuits` enables `orchard/circuit`) but not used; W0.4 may want `sapling` only to cut the
     binary.
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
- [x] **W0.5 the spikes wired into `x402-ycash/light`, `yew-core` and `yew-web-core`; the first
  end-to-end sync in the browser — done 2026-10-09.** Branches `up/web-wire` in yew (this
  commit) and x402-ycash (`light/`, `ecc90cd`); ycash-infra `upgrade/vault` `8917b28` (CORS).
  **What was wired.**
  - `light`: `src/cache.rs` = W0.2's `BlockCache` over `BlockDb` (one file, `cache.sqlite`,
    beside `wallet.sqlite`, **on both targets** — `FsBlockDb`, `blocks/` and the `BlockMeta`
    rows are gone natively too, so the native devnet path is the code the browser runs; the
    rayon `yield_now` drain stays `cfg(wasm32)`), `Wallet::open` without `create_dir_all` or the
    lock file on wasm32, a per-target store `Clock` (`SystemClock` / `JsClock` = W0.1's; in the
    `Db` alias, with `clock()`), `now_ms`/`elapsed_ms` (`SystemTime` natively, `Date.now()`
    in the browser) for every `Instant` timing site, `src/wasm.rs` `install_opfs` (idempotent,
    a thread-local flag), the prover from bytes (`Wallet::set_prover_bytes`; `build` and
    `spend::assemble` are one function on both targets, `take_prover` loads from the directory
    natively and answers `NoProvingParams` in the browser without injected bytes;
    `Error::ProverUnsupported` is gone), `Wallet::db`/`db_mut`, and `sync_with(chunk_blocks,
    on_chunk)` reporting `(scanned, tip)` after every scanned chunk. 32 + 5 native tests (one
    new: the cache round trip, miss, truncate), wasm32 check clean.
  - `yew-core` (`shielded.rs`): `Db` is the light library's alias; `open` skips the directory
    work on wasm32; `Shielded::db` is an `Option` behind `store()`/`store_mut()`: **in the
    browser YEW's own handle closes while the light client is open and every read goes through
    `LightWallet::db`** (the one-connection-per-file rule of W0.1 finding 3 — the native code
    kept both handles open and does so still); `disconnect`/`set_vault_activation`/`history`
    close and reopen in the right order. `sync` has no `Instant`; the progress ticker (a tokio
    task on a second connection) stays native-only — **the browser gets its ticks from the
    light library's `on_chunk` callback instead** (percent by blocks from the height scanned
    before the sync to the tip; the ticker was not re-added as a same-connection poll because
    the light sync holds the store mutably across its awaits). `history` takes `&mut self` on
    both targets (callers in `api.rs`, the CLI and the devnet tests adjusted); in the browser it
    drops both handles, queries, and reopens its own. `build`/`build_shield` are one function on
    both targets over `prover: Option<(PathBuf, LocalTxProver)>`; `set_prover_bytes(spend,
    output)` verifies both against the pins (`sapling_params::verify_bytes`, shared with
    `check_file`) and tags the prover `<bytes>`; `load_prover` in the browser answers
    `ParamsError::Missing` without it. `ShieldedError::ProverUnsupported` is gone.
    `sapling_params::fetch(sources)` (wasm32) is W0.3's `fetch_param` over the Cache API
    (`CACHE_NAME`, the same pins, a stale entry deleted); `install_storage()` re-exports the
    VFS install. New wasm32-only direct deps: `wasm-bindgen`, `js-sys`, `web-sys`
    (`WorkerGlobalScope`, `Cache`, `CacheStorage`, `Response`) and `zcash_proofs`
    (`local-prover`, no `multicore`) — allow-list updated. 123 + 6 native tests, `check-deps`
    (35 direct deps), `check-licenses` (384 crates), fmt, wasm32 check all green.
  - `web/core-wasm` (`yew-web-core`) depends on `yew-core` (no feature; the root's patch tables
    repeated) and exports `install_storage()`, `new_seed_words()`, `latest_height(server,
    network)`, `open(seed_words, birthday, server_url, network)` / `open_at(…, store_dir)`,
    `sync()`, `progress()`, `shielded_balance()`, `receive_address()`, `network()`, `close()`,
    `status()`. One session per worker in a thread-local; a call that needs it takes it out for
    its duration. `open` parses `http://host:port` (plain) / `https://host:port`, derives the
    Sapling account (`SaplingAccount::from_mnemonic`), opens `yew/<network>/` on OPFS, connects
    the gRPC-web channel and takes the vault activation height from `GetChainInfo`
    (`set_vault_activation`), as the app does.
  **The end-to-end test** (`web/core-wasm/tests/web.rs`, `web/scripts/test-core-wasm.sh`,
  headless Chrome 154, dedicated worker, debug and release): a random seed, birthday = tip − 20,
  sync to the tip, balance 0; then the script's funding helper (`web/scripts/fund-helper.py`, a
  loopback HTTP server the test calls: `z_shieldcoinbase` once, `z_sendmany` 1.5 YEC from the
  node's wallet) pays the wallet and the test re-syncs until the note is spendable; then a
  restore from height 1 scans the whole chain, and a second seed is refused on the first store.
  **Result (release, 2026-10-09; debug within 10 %):** open 195 ms (OPFS store + migrations +
  `GetChainInfo`); first sync of 21 blocks / 4 outputs from birthday 208 to tip 228 in **113 ms**;
  the payment seen spendable **4.4 s** after the node answered (one 5 s block); restore from
  height 1: **230 blocks, 10 outputs in 163 ms (1 400 blocks/s)** — an empty regtest chain, so
  this is the floor of per-block cost (download + cache + scan), not trial decryption.
  **Against which server.** Not the kind cluster: its regtest activates only the vault upgrade
  (`ycashd.extraArgs: "-nuparams=6d5b7a31:1"`, values-kind.yaml), so **Sapling is not active
  there** (`getblockchaininfo.upgrades` lists Vault alone; `z_gettreestate` has no `sapling`
  section) and lightwalletd answers every `GetTreeState` with "zcashd did not return
  treestate" — the first sync fails at the birthday checkpoint, and no shielded transaction can
  exist on that chain. The run above is against a **local ycash6 devnet** (`yellowback-devnet
  up --no-attest --heartbeat-rate 5`, every upgrade through Canopy at 1 and the vault at 103)
  with lightwalletd-dd (`--yellowback`) behind **`grpcwebproxy`** (improbable-eng, gRPC-web +
  CORS over plain HTTP) — the recipe is in the script's header. What the kind cluster did
  prove: `open` works over its gRPC-web listener (OPFS store, `GetChainInfo` → vault at 1).
  Fixing the cluster is an ycash-infra change (`-nuparams` for Overwinter…Canopy at 1 beside the
  vault, and a chain reset since the existing coinbases are pre-Overwinter v1) that this task
  did not make.
  **Gateway CORS (ycash-infra `8917b28`, applied to the kind cluster):** the plain listener
  already transcodes gRPC-web (Envoy Gateway adds the filter by default) but had no CORS, so
  the test runner's origin was refused at the preflight; `gateway.plaintextGrpcCors` (kind only)
  adds a `SecurityPolicy` with `cors` (any origin, POST/OPTIONS, the grpc-* headers exposed).
  Envoy Gateway 1.3 refuses `sectionName` on a SecurityPolicy, so it targets the GRPCRoute,
  which puts the policy on the HTTPS listener of a kind cluster too; production never sets it.
  **Traps.** (1) The sahpool rule reaches yew-core: YEW and the light library each opened the
  store, so the browser needed the `store()` indirection above; the second-open assertion fires
  on close, not open, so a wrong order shows up late. (2) `OnChunk` must be `+ Send` or the
  native binary's tokio tasks stop compiling. (3) `zcash_proofs` must be in every consumer's
  wasm32 table (`local-prover`, no `multicore`); the native line already had no `multicore` in
  yew-core. (4) `z_sendmany`/`z_shieldcoinbase` on 6.22 refuse a 0.0001 fee (ZIP-317: "greater
  than 4 times the conventional fee"); the helper omits the fee. (5) The devnet's heartbeat is
  off until `heartbeat start`; a chain that does not move never confirms the funding.
  (6) The spike crates keep their own path patches: `spike-net` now points at
  `../x402-w05/light` like the root manifest. All four spike scripts stay green (prover: 18.0 s
  release / 21.1 s debug, unchanged).
  **What W1 (the shell) needs from `yew-web-core`.** The surface above is enough for "restore
  or create, sync, show the private balance and address". W1 will want: (a) a progress event
  rather than `progress()` polling (a `js_sys::Function` callback on `sync`); (b) the public
  (transparent) side (`wallet.rs`/`sync.rs`/`store.rs` are not bound yet — the W0 work kept to
  the private path the spikes covered); (c) the spend path: `plan`, `set_prover_bytes` after
  `sapling_params::fetch` (bind `fetch_params(sources)` and surface its progress — 52 MB), `build`,
  the gate and `send_transaction`, and `history`; (d) `open` takes the seed words every time —
  the shell must keep them (its own encryption, plan §3) and the core never persists them;
  (e) one worker, one session: every call is serialised by the session take/put, and a second
  concurrent call answers "a call is in progress" — the shell queues; (f) errors are strings
  (`JsValue::from_str(Display)`); a typed error object can come later; (g) the store directory
  is `yew/<network>` — `open_at` exists for a second wallet; deleting a store (OPFS
  `clear_all`/`delete_db`) is not exposed yet.
  **Re-run against the kind cluster itself, 2026-10-09**, after ycash-infra `146c5a8` activated the
  seven regtest upgrades at height 1 (the chain had Vault only, then Overwinter+Sapling only: the
  light clients' regtest parameters assume Canopy from 1, and a pre-Canopy note is undecryptable
  to them) and `fund-helper.py` passed `AllowLinkingAccountAddresses` to `z_shieldcoinbase` and
  `z_sendmany` (6.22's default policy refuses to link the node account's own t-addresses): release
  — open 166 ms, first sync 21 blocks in 55 ms, funded 1.5 YEC, **the note spendable 4.4 s after
  the helper answered** (one block), restore from height 1: 212 blocks / 6 outputs in 178 ms
  (~1 200 blocks/s); debug the same within 10 %. `YEW_WEB_LWD=http://localhost:9067
  web/scripts/test-core-wasm.sh` is now the kind acceptance for W2.
- [x] **W1a the `yew-web-core` API completed to the contract — done 2026-10-10** (branch
  `up/web-api`; `upgrade/vault` `6eb6712` merged in first, because the kind cluster now runs
  rpcversion 6 and the core refuses an rpcversion it does not know — contract rule 1).
  **The exported surface** (`web/core-wasm/src/lib.rs`, DTOs in `src/dto.rs`; every call a
  Promise, every error a JS `Error` whose message is `<kind>: <detail>` with the kinds `busy`,
  `unsupported`, `network`, `store`, `gate`, `build`, `params`, `invalid`; amounts as decimal
  strings, heights and counts as numbers, field names camelCase on the W1a DTOs, the W0.5
  ones unchanged). Nothing is reimplemented: each function is the same internal call its
  `core/src/api.rs` namesake makes, and `dto.rs` carries the presentation mappings of `api.rs`
  (`history_item`/`merge_shielded`, `vault_summary`, `mint_status_of`, `claim_intent_of`,
  `validate_address`) translated line for line — `api.rs` itself cannot compile for wasm32
  (flutter_rust_bridge, tokio), and moving its mappings out would mean regenerating the Dart
  bridge. The session now holds a whole `Wallet` (`Wallet::open` at `yew/<network>/yew-<network>.sqlite`
  on OPFS: the transparent store, with the private store beside it in `shielded/yew-<network>/`,
  exactly the native layout) plus the lazily built connection (`api::Conn`: `CompactClient`,
  `Validator::detect`, the tip, the branch id) and the preview table.
  - As W0.5: `install_storage()`, `new_seed_words()`, `latest_height(url, network)`,
    `open(words, birthday, url, network)` / `open_at(…, dir)` → `{network, address, addressYe,
    addressS, birthday, vault_activation, registered}`, `sync()`, `progress()`,
    `shielded_balance()`, `network()`, `close()`, `status()` (now also `network`, `tip`,
    `yellowbackUsable`, `branchId`).
  - `set_progress_callback(fn | null)`: `fn({phase, pct, height, tip})` from `sync` — phases
    `connecting` 0, `scanning` 5, `shielded` 10..94 (by blocks), `memos` 97, `shielded` 99 at
    the final tick, `done` 100 — the `api::sync_now` percentages. `sync()` is now the combined
    sync of `sync_now`: the transparent §3.2 loop (addresses, YED, vaults, intents, the price)
    then the private scan; a failed private sync does not fail the call (`shielded_message`).
    The result keeps the W0.5 fields and adds `branch_id`, `transactions`, `utxos`, `tokens`,
    `yellowback`.
  - `balances()` → `{yecZat, yecReservedZat, yecPendingZat, yedCents, yedPendingCents,
    priceCents, priceMicroUsd, heldCount, syncHeight, yedSendMinZat, shieldedZat,
    shieldedSpendableZat, shieldedPendingZat, shieldedScannedHeight, shieldedSendable}`.
  - `receive_address(kind?)` → string (`shielded` — the default, as W0.5 —, `transparent`,
    `yed`); `receive_address_info(kind?)` → the `AddressPair` `{ye, s, path, coveredBySeed,
    address, kind}`; `new_shielded_address()` → string (remembered, as the app);
    `addresses()` → `AddressPair[]`.
  - `history(page)` → `[{txid, height, pending, yecDelta, yedDelta, label, verdict, kind,
    hasPayload, shielded, memo}]`, 50 a page, pending first then newest first, the private
    rows merged in.
  - `params_status()` → `{present, bytes, needed, loaded}` (the Cache API's verified copy, or
    the prover loaded in this session); `fetch_params(fn?, sources?)` → `fn({bytesDone,
    bytesTotal, name})` before and after each file (`sapling_params::fetch_with`, new; the
    browser's `fetch` hands a file over whole, so there is no finer grain), the default source
    `download.z.cash` when `sources` is empty, the bytes verified against the pins and loaded
    into the prover (`set_prover_bytes`). `confirm` reloads the prover from the Cache API on
    its own after a page reload (`sapling_params::cached`, new) and answers `params: …` only
    when the cache is empty.
  - Previews: `send_yec_preview(to, zat, memo?)` → `{previewId, to, amountZat, amountBumped,
    fee, change, inputs, usesReserve, keepsReservedZat, expiryHeight, txid, funding
    ("transparent" | "shielded"), revealsShielded, memo, paramsNeeded}` (privacy-first funding,
    `build::yec_private`); `move_preview("to_private" | "to_public", zat | null)` → the same;
    `send_yed_preview(to, cents)` → `{previewId, to, cents, stage, inputs, changeCents,
    yecInputs, feeZat, yecChangeZat, expiryHeight, txid, verdict, dryRun}`;
    `mint_availability()`; `mint_estimate(cents, lockBlocks)`; `mint_start(cents, lockBlocks,
    terms | null)` → `{previewId, cents, lockBlocks}`; `mint_finish(mintId)` / `mint_sweep(mintId)`
    → `{previewId, mintId, row}`; `mints()`; `vaults()`; `redeem_preview(vaultTxid)`;
    `claim_intents()`; `release_preview("txid:n")`; `claimable()`; `claim_preview(vaultTxid)`
    → `{previewId, item, maxBurnCents, minOutZat}` (the bounds the confirm holds the server
    to, H-9.3, from the row the node lists now). The in-term fields of the merge
    (`earlyRedeem`, `earlyRedeemFeeZat`, `nearThreshold`, `claimThresholdBps`, …) are carried.
  - `confirm(previewId)` → `{txid, verdict, mintId}`: **the only path that signs and
    broadcasts**, through both gate layers in the core (`confirm_yec_send`,
    `yed_transfer::broadcast`, `redeem_confirm`, `release_confirm`, and — a difference from
    the Dart surface, where `mint_start`/`mint_finish`/`mint_sweep`/`claim` broadcast
    themselves — the mint and claim steps, staged by their previews above, so that the
    contract's rule holds for every broadcast). A private send or shield is proved here.
    A consumed preview is gone; a `params: …` refusal keeps it.
  - `export_wif(address)` → string; `import_wif(wif, birthday?)` → `AddressPair`;
    `validate_address(s, network?)` → `{valid, kind, yellowbackForm, message}` (the open
    wallet's network, or the named one).
  **Nothing is `unsupported`.** Every internal the contract needs compiled for wasm32 already
  (W0.4/W0.5); the two yew-core additions are wasm32-only and additive (`sapling_params::fetch_with`,
  `cached`, with `web::open_cache`/`cached_param` factored out of `fetch_param`).
  **The browser test** (`web/core-wasm/tests/web.rs`, `web/scripts/test-core-wasm.sh`; the helper
  gained `GET /fund_t` — `sendtoaddress`, with a `z_sendmany … NoPrivacy` fallback — and
  `GET /params/<file>` serving `~/.cache/yew-web/sapling-params`, so the test never
  downloads), headless Chrome 154, dedicated worker, debug and release, against the kind
  cluster (`http://localhost:9067`): a fresh wallet opens (OPFS stores + `GetChainInfo`) and
  syncs with the progress events checked monotone; `busy` is answered to a call during a sync;
  **2 YEC paid to the public address** is spendable and in history as `received YEC`; a **t→t
  send** of 0.5 YEC to a foreign address: preview (fee 1 000 zat, 1 input) → confirm (`ok`, 15 ms)
  → pending in history → mined; **1.5 YEC paid to the private address** spendable; `params_status`
  empty → a shield preview whose confirm answers `params: …` → `fetch_params` from the helper in
  **≈0.7 s** (3 events) and from the cache in ≈0.5 s → `params_status` present+loaded → the
  **shield** (0.4 YEC to private) proved and broadcast in **4.2–4.4 s** → mined, both balances
  right; a **z→z send** of 0.3 YEC with a memo to a new diversified address of the same account:
  preview (`funding: shielded`, no txid yet) → confirm proved and broadcast in **17.1–17.6 s**
  → mined; a memo to a public address refused (`invalid: …`); a public recipient the notes cover
  is funded privately (`revealsShielded`); `send_yed_preview` without YED → `build:
  insufficient-yed: need 100 cents, have 0 confirmed and spendable`; `mint_availability` →
  `allowed false, "Minting is halted (NO_PRICE): no term class is mintable now."`, attest
  `UNARMED` (the kind devnet's attestors are unarmed, so no mint is possible there, as the
  briefing anticipated); `mint_estimate(100, 48)` → `invalid: bad-amount: 100 cents is outside
  the mint range [10000, 1000000] cents`; `claimable()` 0 rows; `claim_preview` of an unknown
  vault, `redeem_preview` of a foreign one (`build: vault-not-owned`), `mint_finish(7)`
  (`invalid: no mint with id 7`) refused with the right kinds; `export_wif`/`import_wif` round
  trip of a foreign key; 5 history rows at the end. Timings (release; debug within 10 %): open
  250–360 ms, first sync 21 blocks 130–200 ms, a receipt spendable one block after the helper
  answered (2–6 s on the shared cluster's 5 s blocks).
  **What had to change, and the traps.**
  1. **`tonic-web-wasm-client` 0.9.2 cannot read a Trailers-Only gRPC-web reply** (grpc-status
     in the HTTP headers, empty body): "malformed response". Envoy Gateway sends exactly that for
     an empty server stream — the kind cluster's yindex `GetTaddressTxids` for an address with
     no history, i.e. every address of a fresh wallet — so the transparent sync never completed
     in the browser (the W0.5 private sync never met one: `GetBlockRange` is never empty).
     Upstream issue #99; the fix is the open PR #113 ("end the body when the stream ends between
     frames"), **pinned by `[patch.crates-io]` at its head `cf9abc39`** in the root `Cargo.toml`
     and `web/core-wasm/Cargo.toml` (the spike crates keep the release; `spike-net` never
     hit an empty stream). Replace with the release that carries it. Verified by the curl
     probes in the W1a log: `GetAddressUtxos` answers a trailer frame, `GetTaddressTxids`
     headers only.
  2. The kind cluster moved to **rpcversion 6** (the in-term claims line) under this task:
     `upgrade/vault` was merged into `up/web-api` (clean), and the in-term fields of
     `vault_summary`, `RedeemPreview` and `ClaimableItem` were carried into `dto.rs`.
  3. A u8 percent arithmetic overflow (`percent * 85`) in the first progress mapping, and the
     final tick of the private sync reporting `percent 100` after the `memos` tick (99 is
     emitted for it so the events stay monotone).
  4. **Timing on a shared cluster.** The balance comes from `GetAddressUtxos` (yindex) and the
     history row from `GetTaddressTxids`: one sync can see the first and not yet the second,
     so the test waits for both. The transparent sync runs before the private scan: a block
     arriving in between leaves a shield's public change pending for one more sync. The
     private scan reaches the compact-block cache's tip, which can trail the node's by a block.
  5. **One finding for the core, not the binding** (the Dart app has it too): a z→z send to
     one of the wallet's **own diversified addresses** is two things to the store in turn.
     While the row rests on the sent outputs the builder recorded, history shows the memo and
     the full amount as sent and the private total is lower by it; once the scan has
     decrypted the output as received (in the same sync when the block is already there, a
     later one otherwise) the amount is credited, the row's delta is the fee alone — and the
     memo is gone, because `v_tx_outputs` marks a note received from the account's own
     transaction `is_change`, which `shielded::history_rows`' memo query excludes. So a
     self-send's memo is never shown once scanned (yew-core `shielded.rs`, the memo query's
     `is_change = 0`: to be looked at with the owner; the test accepts an empty memo and logs
     the row, and waits for the credit — 0–3 s).
  **For W1b.** The DTO field names above are the contract's where it names them (`yecZat`,
  `yedCents`, `priceCents`, `previewId`, `fee`, `change`, `revealsShielded`, `funding`,
  `yecDelta`, `yedDelta`, `bytesDone`/`bytesTotal`/`name`) and the Dart names camelCased
  elsewhere; the differences from the contract: `balances()` also carries the reserve,
  pending, held and height fields; `send_yed_preview` takes one recipient (`to, cents`), its
  `inputs` are the YED inputs and `verdict` is the dry run's; `mint_start` answers
  `{previewId, cents, lockBlocks}` (no `mintId` until `confirm`, which returns it);
  `mint_finish`/`mint_sweep` answer `{previewId, mintId, row}`; `confirm` carries `mintId`;
  `history(page)` is the array itself (no `total`); `params_status` adds `loaded`;
  `open` still takes `network` as its fourth argument (W0.5) and `receive_address` without an
  argument is the private address (W0.5). `fetch_params` holds the session (a sync meanwhile
  is `busy`). Amount arguments are accepted as strings, safe integers or BigInts. Run
  `fetch_params` once per browser profile; after that `confirm` finds the cache itself.
- [x] **W1b the browser shell on the yew-web-core contract — done 2026-10-09 (branch
  `up/web-shell`), against `MockCore`; waits for W1a for the real core.** `web/src` is plain
  TypeScript with a tiny `h()` DOM helper and a hash router (`dom.ts`): no framework, because
  six screens that re-render from a view-model's state fit in a few hundred lines, every
  dependency is one more thing the CSP and the import rule have to vouch for, and nothing here
  needs components to be shared. One runtime dependency: `qrcode-generator` (the receive QR, an
  SVG with no inline style). Shape:
  - `core.ts`: the whole W1a contract as the `Core` interface (DTOs with the Dart field names;
    amounts as strings), `CoreClient` (the worker RPC; the sync-progress and params-fetch
    callbacks arrive as `{event}` messages, `worker.ts` installs the worker-side functions and
    otherwise dispatches by name), `messageOf`/`kindOf` (the "<kind>: <detail>" errors), and
    `serialized(core)` — the shell talks to the core through a one-at-a-time queue, because the
    core rejects a concurrent call with "busy" and two screens race for it (a recipient check on
    blur against Preview on click; the smoke hit it).
  - `mock.ts`: `MockCore`, the contract with canned data (balances, four history rows, one vault,
    one claimable vault, the params fetch, previews as opaque ids, `confirm` the only path that
    records a broadcast); `?mock=1` or `VITE_MOCK=1` selects it in `main.ts`.
  - `vm/*.ts`: the view-models, one per screen (onboarding, home, send + move, receive,
    history, settings, yellowback), DOM-free, with `subscribe` for re-render; the flows of
    `app/lib/screens/*.dart` translated (the four-part check per screen is in each file's
    header). `screens/*.ts` render them; `widgets.ts` holds the preview card, slide-to-confirm
    (a range input dragged to the end, or End/Enter from the keyboard, fires `confirm()` once),
    the result card, the error card with the kind's hint, the progress bar and the QR.
  - `format.ts` = `app/lib/format.dart` on BigInt; `trust.ts` = `docs/trust.md` with the
    browser-specific substitutions and one web paragraph (plan §3 "stated limits").
  **The seven screens delivered:** onboarding (create → the phrase shown once as a numbered
  grid → confirm three random words → server (`http(s)://host:port`, a tip check; plain only
  for localhost outside dev) → the trust statement with a checkbox → unlock (passkey or
  passphrase) → opened; restore with 12/24 words + birthday), the returning-user unlock, home
  (YED, YEC private/public with pending lines, the price line, the sync progress bar from the
  callback, Receive / Send / Sync / Move…), receive (Private / Public / YED, QR, copy, new
  private address), send (YED/YEC toggle, address with the core's `validate_address`, amount,
  a memo field that appears for `ys1…`, the preview card with fee / change / "paid from" / the
  reveal warning / the YED dry-run verdict, slide to confirm → `confirm`, result with the txid),
  move (shield/unshield preview + slide), history (list with memo marks and pending rows, the
  detail with the verdict and the message), settings (server, params status + fetch with
  progress, the trust text, export WIF, import WIF, about, Lock, Forget), yellowback (YED held,
  the open vaults, Mint → estimate card → Start → slide to fund the carrier → Finish; Vault →
  redeem preview → slide; Claimable → list → claim preview → slide).
  **Seed at rest (`keystore.ts`, plan §3):** the phrase is AES-256-GCM-encrypted in IndexedDB
  (`yew`/`keystore`), never localStorage, never a cookie, never sent. Two wrapping-key paths:
  **WebAuthn PRF** — a resident passkey created with the `prf` extension, its 32-byte output for
  a random salt HKDF-SHA-256'd (info `yew-web seed v1`) to the AES key; the credential id and
  the salt are stored beside the ciphertext, and unlock is one `navigator.credentials.get` with
  the same salt — or **a passphrase through PBKDF2-SHA-256 at 600 000 iterations** (Web
  Crypto). **Argon2id is not used:** there is no Web Crypto Argon2, `@noble/hashes` is on the
  forbidden list of `check-web-imports.sh`, and any other implementation is a crypto package
  under `web/src`; the right home for Argon2id is the wasm module (W1a can export
  `argon2id(passphrase, salt)` from the Rust side, and `keystore.ts` swaps the derivation in one
  place). The plaintext goes straight to `core.open()` and is dropped; the onboarding view-model
  clears it from its state after `finish`. Metadata that is not secret (server, birthday,
  network) sits in the same record in clear.
  **CSP/SRI:** `index.html`'s policy is unchanged (`script-src 'self' 'wasm-unsafe-eval'`,
  `style-src 'self'`, …): no inline script or style anywhere (the two dynamic widths go through
  the CSSOM, which the policy allows; the QR is an SVG without style attributes). SRI stays with
  the build: Vite emits hashed asset names; `integrity` attributes on the emitted tags and the
  published bundle hash are W3's reproducible-build item (a `vite-plugin-sri`-style step or the
  ycash-infra image's nginx), not done here.
  **Tests:** `npm run check` = the import rule + `tsc --noEmit` + **vitest** (21 tests:
  `tests/format.test.ts`, `tests/screens.test.ts` — every view-model against `MockCore`,
  including: the seed does not linger after onboarding, YED to `ys1…` refused before the core is
  asked, a memo only for `ys1…`, the reveal warning, a gate refusal shown with its kind, shield
  needs the params, mint estimate → start → confirm → finish opens a vault, redeem closes it,
  claim, "busy" from the mock and the queue hiding it). `scripts/test-web-smoke.sh` builds and
  walks the real bundle in headless Chrome 154 (ChromeDriver from the W0 cache, WebDriver over
  stdlib HTTP in `scripts/smoke.py`) with `?mock=1`: create → phrase → confirm → server → trust
  → passphrase → home shows `$125.00` / `1.50000000 YEC` / the price line → Send → preview with
  the node verdict → slide → "Sent" → reload → the unlock screen → home again. Green.
  **What had to change outside `src`:** (1) `vite-plugin-top-level-await` is removed from
  `vite.config.ts` and `package.json`: with the wasm module present, `vite build` failed inside
  its swc pass ("missing field `type`") on the worker and then the main bundle; the build target
  is es2022, where top-level await is native, so the plugin was never needed (the W0 scaffold's
  build had not been run with a resolvable worker). (2) `tsconfig.json` includes `tests/` and the
  two configs. (3) `package.json`: `test` and `check` run vitest; `qrcode-generator` added;
  `package-lock.json` committed. (4) `worker.ts` is typed loosely over the glue; the build needs
  `scripts/build-core-wasm.sh` run first (`src/wasm/` is gitignored).
  **What waits for W1a:** everything past `status()` on the real core — the shell is coded to
  the contract and has only run on the mock. Specifically: `balances()`, `history(page)`,
  `validate_address`, `receive_address(kind)` with three kinds, `new_shielded_address`, the
  progress callback (`set_progress_callback(true|false)` from the worker: the worker installs a
  function that posts `{event:"progress"}`), `fetch_params(fn)` likewise (`{event:"params"}`),
  the six previews + `confirm`, mint start/finish/sweep, vaults/redeem, claimable/claim,
  export/import WIF, and `status().open`. Questions for W1a: `balances().priceCents` is read as
  cents per YEC (the Dart side has micro-USD; `format.ts` adapts in one function); the mint
  flow assumes `mint_start` returns the carrier's preview and `mint_finish` may answer "build:
  the carrier is not confirmed yet" until it is (the Mint screen keeps a Finish button for that);
  a `MintStatus` needs `inProgress`, `canSweep`, `state`, `vaultTxid` as the Dart row has;
  `Vault` needs `open`, `redeemable`, `blocksToLock`, `tip`. W1a's "unsupported: …" texts show
  as-is. Not done: the Flutter app's server screen (changing the server after onboarding means
  forget + restore here), the renew flow (redeem then mint again) and claim intents/release
  (the vault upgrade's second step), mint availability (`mintAvailability`, H-1/H-5) — none are
  in the W1a contract yet; a Playwright suite (the WebDriver smoke covers the acceptance path).
- [x] **W2 the shell on the real core, against the kind cluster, served by the gateway — done
  2026-10-10** (yew branch `up/web-kind`; ycash-infra `upgrade/vault`, K4). No core change:
  every mismatch between W1b's contract and W1a's DTOs was fixed in the shell. The walk below
  passed on both origins the same afternoon.
  **Reconciled in `web/src` (core.ts is now the W1a surface, DTOs camelCase as `dto.rs`):**
  `open(words, birthday, url, network)` and `latest_height(url, network)` take the network
  (`main.ts`: `VITE_NETWORK`, default `regtest`; the keystore's `meta.network` on unlock);
  **wasm-bindgen crosses a bare `u64`/`i64` as a BigInt** (`latest_height` answers one, `open`'s
  birthday, `mint_finish`/`mint_sweep`'s id and `import_wif`'s birthday want one — the first run
  died on "Cannot mix BigInt and other types"), so `CoreClient` converts at the boundary and the
  view-models stay on numbers (the DTOs' fields come through serde as numbers); `history(page)` is
  the array, rows carry `label` (the text shown: "received YEC", "sent private YEC", …), `kind`,
  `shielded`, `hasPayload`; `Balances` carries the reserve, pending, held and height fields,
  `priceCents` nullable; `YecPreview` is one DTO for send and move (`funding` is `transparent` |
  `shielded` — the shell had compared against `private` —, `paramsNeeded`, `txid` for a signed
  public preview); `YedPreview` carries the `dryRun`; `mint_start` answers `{previewId, cents,
  lockBlocks}` and **the mintId arrives from `confirm`**, after which `mint_finish(mintId)` /
  `mint_sweep` are *staged steps* (`{previewId, mintId, row}`) that `confirm` broadcasts — the
  Mint screen is now estimate → Start → slide (the carrier) → "Check the carrier" / slide to mint
  → the vault; `mint_availability()` is read on the Mint screen (the node's reason shown, Estimate
  disabled when halted; `mints()` refreshes the row after the step); `Vault` is `vault_summary`
  with the in-term fields (`blocksUntilRedeem` replaces `blocksToLock`); `RedeemPreview` has
  `collateralZat` (not `returnedZat`), `kind` and the early-redeem fee (shown as a warning);
  `ClaimPreview` is `{previewId, item, maxBurnCents, minOutZat}` (the bounds the confirm holds
  the server to are what the card shows); `Confirmed` carries `verdict` and `mintId`;
  `import_wif` answers an `AddressPair`; `validate_address` kinds are `sapling` / `p2pkh` / `p2sh`
  with `yellowbackForm` (the shell only needs `sapling`); `Status` has no `open` (`server` is
  null when none is). `fetch_params(fn, sources)`: Settings has a source field (advanced; the
  fingerprints are checked either way) prefilled from `?params=<base URL>`, which the kind smoke
  points at the helper. **The server defaults to the page's origin when served over https**
  (`https://host:443` — the core's `Server::parse` wants a port, so `normalizeServer` adds 443/80
  to a bare origin, also for a typed `https://host`); the dev loop over http keeps the explicit
  URL. **A new seed's birthday is tip − 20** (`BIRTHDAY_MARGIN`, set at the server step when the
  tip is known; a restore keeps its own). `MockCore` follows the real DTOs (the vitest tests
  are the same 21, the mint one now covering carrier → mintId → staged finish → confirm).
  `build-core-wasm.sh` exports the LLVM clang itself. `index.html`'s CSP `connect-src` adds
  `https://download.z.cash` (the proving files' standard source; mirrored by nginx below).
  **The acceptance** (`web/scripts/test-web-smoke.sh --kind [page-url]`, walk in `smoke.py`;
  headless Chrome 154, the W0 ChromeDriver cache; `fund-helper.py` gained `GET /address`, a
  fresh t-address of the node's wallet): the built bundle WITHOUT the mock — onboarding (new
  seed, birthday tip − 20) → home shows $0.00 / 0 YEC → the addresses from Receive → `/fund_t`
  2 YEC → Sync until the public balance shows → **a public send of 0.5 YEC** to the node's
  address (slide to confirm; `Paid from: your public balance`) → `/fund` 1.5 YEC private →
  Sync until the private balance shows → History (3 rows: received YEC, sent YEC, received
  private YEC) → Settings → Fetch (52 MB from the helper's `/params/`) → "Ready" → Move 0.4 YEC
  to private → slide → Moved → Receive → New private address → **a private send of 0.3 YEC z→z
  with the memo "hello from the web"** → slide → Sent → the memo on the pending history row →
  Sync until nothing is pending and the self-send is credited → reload → Unlock (passphrase) →
  the same two balance lines (OPFS) → Yellowback: $0.00, "No open vault", Mint shows the core's
  **"Minting is halted (NO_PRICE): no term class is mintable now."**, Claimable: "Nothing is
  claimable right now." The public send comes before the private funding on purpose: with
  private notes that cover the amount the core funds a public recipient privately
  (`revealsShielded`, W1a), which would need the proving files first.
  **Timings (2026-10-10, release bundle, the shared kind cluster's 5 s blocks, M-series laptop):**

  | step | vite preview + `http://localhost:9067` | gateway `https://localhost/` (K4) |
  |---|---|---|
  | onboarding: new seed → open → first sync → home | 1.4 s | 1.2 s |
  | 2 YEC public: helper answered → balance on Home | 4.7 s | 3.2 s |
  | public send 0.5 YEC: slide → Sent | 0.2 s | 0.2 s |
  | 1.5 YEC private: helper answered → balance | 5.9 s | 7.5 s |
  | fetch params (52 MB, loopback, verified, loaded) | 1.1 s | 1.0 s |
  | move 0.4 YEC to private: slide → proved, broadcast → Moved | 5.1 s | 5.2 s |
  | private send 0.3 YEC z→z + memo: slide → proved, broadcast → Sent | 19.8 s | 21.7 s |
  | everything mined and the self-send credited | 4.8 s | 4.8 s |
  | reload → unlock → balances back | 0.5 s | 0.5 s |
  | whole walk | 49 s | 51 s |

  The proof times are W0.3's (one core; the UI thread stays free — the worker proves). Final
  balances both runs: private 1.8999 YEC (1.5 + 0.4 − 0.0001), public 1.09984 YEC
  (2 − 0.5 − 0.00001 − 0.4 − 0.00015). The mock walk (`test-web-smoke.sh` without `--kind`)
  stays green; `test-core-wasm.sh` unchanged and green (the helper's addition is additive).
  **K4 (ycash-infra `upgrade/vault`, applied to the live cluster with one `helm upgrade`, which
  rolled the web Deployment, its Service and the HTTPRoute and nothing else — the render of the
  chart head equalled the live manifest beforehand):** `images/web/Dockerfile` takes the bundle
  as a named build context (`make image-web YEW=<tree>`: `docker buildx build --build-context
  dist=$(YEW)/web/dist`; the old `docker build` with `yew/web` as the context could not see
  `nginx.conf`), `nginx.conf` is an envsubst template whose CSP `connect-src` is `'self'
  https://download.z.cash $CSP_CONNECT_SRC_EXTRA` (chart `web.env`; `values-kind.yaml` sets
  `http://127.0.0.1:8766` so the kind smoke's helper may serve the proving files to the
  https page; production leaves it empty), the `.wasm` location's second `add_header` is gone
  (nginx drops the inherited headers when a location adds its own: the wasm response had lost
  COOP/COEP/CSP) in favour of `expires` on `/assets/`. `curl -I https://localhost/` shows
  `cross-origin-opener-policy: same-origin`, `cross-origin-embedder-policy: require-corp`, the
  CSP, `x-content-type-options`, `referrer-policy`; the hashed assets `max-age=31536000`.
  `web.enabled: true, replicas: 1` on kind. The plain `:9067` listener stays for the dev loop.
  **Traps.** (1) The BigInt boundary above. (2) A dedicated worker's CSP is its own script's
  response headers, not the document's `<meta>`: on vite preview the worker has no CSP at all
  (so the loopback helper and `:9067` just work), behind nginx it has the server's — which is why
  the `.wasm`/asset headers and the `connect-src` extra matter there. (3) The Receive screen
  keeps the last tab and re-renders on `show()`: a WebDriver click can go stale between find and
  click (`smoke.py` re-finds). (4) A self-send's memo is on the row only while pending (W1a
  finding 5): the smoke reads it before waiting for the block, and the private total is lower by
  the sent amount until the next sync credits it, so "no pending line" is not the steady state —
  the smoke waits for the expected total. (5) The fund helper binds its port a moment after the
  script starts it; a stale helper from an aborted run answers 404 for new routes (`/address`) —
  the script arms its trap before launching anything. (6) `serde_wasm_bindgen` keeps `u64`
  fields as numbers; only bare wasm-bindgen signatures use BigInt.
  **Open for W3.** The mint/claim/redeem screens ran only on the mock (no mintable class on
  kind: attestors unarmed, no price); a devnet with an armed set is the place to walk them on
  the real core. SRI/reproducible build of the bundle (W1b's note) and `integrity` on the
  emitted tags. Mainnet: `VITE_NETWORK=mainnet` and the https-only server rule are in place but
  untested; the network picker in onboarding is not built (one network per bundle). The
  passkey (PRF) path has no headless test (WebDriver has no authenticator here); the passphrase
  path is the one walked. A real Argon2id export from the core for `keystore.ts`. The in-term
  claim intents / release screens (`claim_intents`, `release_preview` exist in the core) are not
  in the shell.
- [ ] W0 complete
- [ ] W1
- [ ] W2
- [x] **W3 hardening — 2026-10-09 (branch `up/web-harden`)**: the reproducible build with
  SRI, the hardening browser tests, the other-browser record, a low-end timing, the security
  review's web section. In the briefing's order:
  1. **Reproducible build + SRI.** `npm run build` = `tsc --noEmit && vite build && node
     scripts/sri.mjs dist`. `web/scripts/build-release.sh` builds the wasm module twice (the
     second in a fresh `CARGO_TARGET_DIR`, a clean compile; `CLEAN=0` reuses the cache) and the
     Vite bundle twice into clean temporary directories, compares every file by SHA-256, fails on
     a difference, installs the second copies as `src/wasm` and `dist/`, and writes
     `dist/BUNDLE-SHA256SUMS` (sorted, relative). Proof on this laptop (rustc 1.92.0, node
     23.3.0, wasm-pack 0.15.0): the module identical across the cached and the clean build, the
     bundle identical across two builds; bundle hash (sha256 of the sums file)
     `71650b662ef3c848178092e25c09fff2c8f88f0a99620857c47a998af40ab7b6`, wasm
     `8a24a8110ed5b1a2fd0d7c5ffcf68a1b8f81094de425c176f9ee4948f70a2ee9` (11.47 MB). **What had
     to change for that**: the first clean rebuild differed by 192 bytes — rustc embeds the
     target directory in two strings (the prost-generated `cash.z.wallet.sdk.rpc.rs` path, in
     panic locations) and the checkout and `~/.cargo` in ~500 source paths, so the module was
     a function of where it was built. `build-release.sh` sets
     `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS` with `--remap-path-prefix` for the repo
     (`/src/yew`), the two siblings, cargo home, the sysroot and the target directory (read
     from `cargo metadata`, so a config.toml `target-dir` is honoured) — that variable replaces
     the config's target rustflags, so the getrandom cfg is repeated there — after which no
     `/Users/…` string remains and the clean rebuild in a fresh target directory matches. The
     dev build (`build-core-wasm.sh`) is not remapped and so differs from the release one. The
     choice: **`--no-opt`** — wasm-pack's `wasm-opt` is a binaryen it downloads unverified
     (version_117 for 0.15), one more input outside `Cargo.lock`; measured, it takes the module
     from 11.47 MB to 8.84 MB raw but only 4.69 MB to 4.29 MB gzipped (9 % on the wire), so the
     module is now a function of `rust-toolchain.toml`, `Cargo.lock` and wasm-bindgen only. To
     take the 9 % back later: a binaryen pinned by checksum, run by build-release.sh itself.
     Vite needed nothing: Rollup names chunks by content hash and writes no timestamps;
     `reportCompressedSize` is off so the build reads nothing outside the tree. **SRI**:
     `scripts/sri.mjs` is a post-step, not a Vite plugin — a `transformIndexHtml` hook sees the
     entry chunk before `vite:build-import-analysis` rewrites its preload list in
     `generateBundle`, so its sha384 was of the wrong bytes (found: the attribute did not match
     the written file); hashing the files on disk is right by construction. It pins the two tags
     index.html has (the main chunk and the stylesheet); the worker (`new Worker(url)`), the wasm
     (fetched by the glue) and the `mock` dynamic chunk take no `integrity` — they are bound by
     the content-hashed names the pinned chunk references and by the sums file.
     `scripts/verify-bundle.sh <origin>` fetches `BUNDLE-SHA256SUMS` (checked against
     `RELEASE_BUNDLE_HASH` when given — without it a self-served sums file proves only
     self-consistency, and the script says so), every listed file, recomputes the SRI attributes
     of the served index.html and prints COOP/COEP/CSP. **Verified on a served origin** (`vite
     preview`): 7 files match, 2 SRI attributes verified, COOP `same-origin`, COEP
     `require-corp`, CSP not in headers (it is the meta tag; the ycash-infra nginx adds the
     header); a one-byte change to the served index.html fails the run (exit 1, the file named).
     **CI**: `ci.yml` job `web`: `npm run check`, then — only when `up/web` exists upstream in
     both `boyfromcave/librustzcash6` and `boyfromcave/x402-ycash`, which the core-wasm
     `[patch]` paths need as siblings; today they are local-only (W0.1), so the job clones them
     when present and otherwise warns and skips — `build-release.sh` (apt clang for the wasm32
     C, wasm-pack 0.15.0 cached) and `verify-bundle.sh` against `python3 -m http.server` on
     the built dist; the sums file is uploaded as an artifact.
  2. **Browser tests** `web/core-wasm/tests/harden.rs`, run by `test-core-wasm.sh` (now
     `TESTS="web harden"` × `PROFILES="debug release"`; `FUND_PORT` for a second helper beside
     another run's — W2's smoke test holds 8766 at the same time; `YEW_WEB_NO_REORG=1` skips the
     disturbance). Against the kind cluster, debug profile, headless Chrome 154:
     - (a) `restore_from_seed_with_birthday`: a wallet paid 1.1 YEC public and 1.2 YEC private
       with a memo (`/fund&memo=`, new), both mined at 1312 (seen 4.3 s after funding); closed;
       opened from the seed in a **new store directory** with birthday 1310 (= funding − 2):
       **both balances and the memo back 353 ms after open** (one sync, `GetTreeState` at the
       birthday, 3 blocks scanned), one history row each at the same heights. Opened a third
       time with birthday 1313 (after the funding): the private note absent, **and the public
       receipt too** — the transparent sync asks the server from the birthday as well
       (`sync.rs` `address_utxos(…, birthday)`), so a wrong birthday hides money on both sides
       until a restore with an earlier one (the restore screen must say so). Expected and
       documented; the test asserts it.
     - (b) `reorg_during_private_sync`: a private receipt mined at 1377 (the tip);
       `/reorg?height=1377` (new helper route: `invalidateblock`, then `generate` until the new
       branch is one longer; the funding returns to the mempool and is mined again) answered
       `{oldTip 1377, invalidated 1377, newTip 1378}` in 466 ms; the wallet re-synced past it in
       2.2 s: `reorgs 1` reported by the light library, the balance exactly 1.2 YEC (counted
       once, spendable), one history row, a full-balance preview plans against one note.
       **The one disturbance of the shared cluster: 2026-10-09 18:19 PDT**, a one-block reorg
       (the funding sat at the tip, so `height = tip`; `depth=2` is the other form).
     - (c) `busy_under_concurrency`: with a `sync()` parked at its first await and again mid-flight,
       `sync`, `balances`, `history` and `shielded_balance` answer `busy: a call is in
       progress` and `open_at` `invalid: a wallet is already open`; three rounds (2 busy answers
       caught mid-sync each); then close, reopen the same directory (`registered` true), sync,
       the balance unchanged — no sahpool assertion, no "DB closed without open".
     **The finding the tests forced**: the sahpool's **default capacity is 6 files**
     (`OpfsSAHPoolCfg::default()`, sqlite-wasm-vfs 0.2); one wallet holds three
     (`yew-regtest.sqlite`, `shielded/yew-regtest/wallet.sqlite`, `…/cache.sqlite`; journals are
     transient), so the second store directory opened fine and the third failed with `store:
     sqlite: unable to open database file` / `block cache: unable to open database file`. The
     tests reserve capacity through the pool's management handle (`sahpool::install` on the
     registered VFS returns it without re-registering; `reserve_minimum_capacity`) and log the
     pool. **For W0.4 / the shell**: `install_storage` should reserve what the wallet needs
     with headroom (a restore beside an old store, the import/export paths), and "Forget" must
     `delete_db` the three files, or the next restore cannot open. Not changed here (x402-web
     `light::wasm::install_opfs` owns the config).
     The release profile ran (a) and (c) green as well; (b) ran once, in debug, by the rule.
  3. **Other browsers.** Firefox: not installed (`/Applications`, no `firefox`, no
     `geckodriver`); to run: `brew install --cask firefox && brew install geckodriver`, then
     `GECKODRIVER=$(which geckodriver)` in place of `CHROMEDRIVER` for `test-core-wasm.sh`'s
     `cargo test` lines (the runner picks the driver from the variable); expect OPFS sync access
     handles in a dedicated worker (Firefox 111+) and COOP/COEP from the runner's server
     (`WASM_BINDGEN_TEST_NO_ORIGIN_ISOLATION` unset). Safari 26.0: installed, `safaridriver`
     is enabled (`/status` answers ready) but a session could not be created from this
     non-interactive session ("timed out … launching a compatible local Safari"): run
     `SAFARIDRIVER=/usr/bin/safaridriver cargo test --target wasm32-unknown-unknown --test
     harden` from a logged-in Terminal with Safari's Develop → Allow Remote Automation on (not
     headless: Safari opens a window). Expected from the platform: OPFS `createSyncAccessHandle`
     in workers since Safari 17, WebAuthn PRF since 18, cross-origin isolation honoured;
     unverified here. Chrome 154 is the one browser covered. Memory: the prover's 115 MiB
     peak (W0.3) is recorded as the requirement in the security review's web section.
  4. **Low-end timing — an approximation, not a low-end machine.** The W0.3 prover spike
     (`test-spike-prover.sh`, one spend + two outputs, single worker), on the owner's 10-core
     M-series laptop: idle, 21.1 s debug / **18.1 s release**; the whole runner chain under
     `nice -n 19` with ten `yes > /dev/null` burners (one per core): 22.0 s debug / **19.8 s
     release** (+9 %), memory 115 MiB in all four. Honest reading: on macOS a nice'd process
     with as many burners as cores still gets most of a core, so this measures contention, not
     a slow CPU; a true low-end figure needs a real machine or CDP's CPU throttling (not
     reachable from WebDriver). Extrapolating by single-core performance, a 2017-class laptop
     (≈ 3× slower per core) is in the 50–60 s range per private send; the Send screen's
     progress sheet and the slide-to-confirm already assume tens of seconds.
  5. **`docs/security-review.md`, "The web shell"**: the threat table (altered code from the
     origin, XSS, extensions, other origins, the seed at rest, the server), what the CSP / SRI /
     COOP+COEP / keystore give and do not, the `tonic-web-wasm-client` PR-rev pin as the one
     out-of-tree git dependency, the parameter pins and the Cache API path, the sahpool rule
     with the capacity finding, the memory requirement. `docs/trust.md` / `trust.ts`: unchanged
     (W1b's web paragraph already states the code-from-the-server limit and the build hash).
  **Open**: the CI `web` job builds nothing until the `up/web` siblings are pushed (W0.1's
  "push replaces them with git revs"); Safari and Firefox runs; the sahpool capacity / forget
  flow (W0.4, the shell); the CSP as a response header is the ycash-infra image's.
