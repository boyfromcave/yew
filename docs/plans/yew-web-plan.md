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
- [ ] W0.4 `yew-core` `wasm` feature: tonic-web-wasm-client channel, the clock, no tokio runtime
- [ ] W0 complete
- [ ] W0 complete
- [ ] W1
- [ ] W2
- [ ] W3
