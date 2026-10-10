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
- [ ] W0 complete
- [ ] W1
- [ ] W2
- [ ] W3
