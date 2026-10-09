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
- [ ] W0.2 `FsBlockDb` → a `BlockSource` over OPFS (or `MemBlockCache`) for the browser
- [ ] W0.3 `zcash_proofs` local prover in a Web Worker (single-thread first; `wasm-bindgen-rayon` after)
- [ ] W0.4 `yew-core` `wasm` feature: tonic-web-wasm-client channel, the clock, no tokio runtime
- [ ] W0 complete
- [ ] W0 complete
- [ ] W1
- [ ] W2
- [ ] W3
