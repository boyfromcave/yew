# yew/web — YEW in the browser

The third shell on the YEW core (after iOS and Android): the same Rust core compiled to
WebAssembly, a small TypeScript PWA around it. Plan: `docs/plans/yew-web-plan.md`.

```bash
scripts/build-core-wasm.sh     # wasm-pack build core-wasm → src/wasm/ (needs rustup target wasm32-unknown-unknown, wasm-pack)
npm install && npm run dev     # Vite on http://localhost:5173 with COOP/COEP headers
npm run check                  # the import rule + tsc + vitest (the view-models against MockCore)
npm run build                  # dist/ for the ycash-infra web image (needs src/wasm/ built)
scripts/test-web-smoke.sh      # headless Chrome walks the built bundle with ?mock=1
scripts/test-web-smoke.sh --kind                     # … on the real core against the kind cluster (vite preview + http://localhost:9067)
scripts/test-web-smoke.sh --kind https://localhost/  # … the bundle the gateway serves (ycash-infra K4), API on the same origin
```

`http://localhost:5173/?mock=1` (or `VITE_MOCK=1`) runs the screens on `src/mock.ts`, a canned
core, without the wasm module or a server. Without it the real core runs in a worker: served
over https the server defaults to the page's origin; in the dev loop type the plain gRPC-web
listener (`http://localhost:9067` on kind). `?params=<base URL>` prefills a mirror for the
proving files (Settings); `VITE_NETWORK` picks the network of a build (default `regtest`).

**The Sapling proving files.** A private send or a shield proves with `sapling-spend.params`
(47,958,396 bytes) and `sapling-output.params` (3,592,860 bytes), 51.6 MB together. With
Source empty in Settings the browser fetches them from the page's own server, at
`/sapling-params/<file>` (ycash-infra's web image serves them there, fetched at build time
against the pinned SHA-256s): `download.z.cash`, the app's default, sends no CORS header, so no
web page can read it. Whatever the source, both files are kept only if their length and SHA-256
equal the pins in `core/src/sapling_params.rs`; a wrong file (for example a server's HTML page)
is refused with its size, and a missing one names the HTTP status. Where they are kept: the
browser's Cache API, cache `yew-sapling-params-v1`, per origin (the browser's HTTP cache may hold
a second copy; the image sends them `immutable` for a year). What a reload costs: no download;
the worker reads both files from the cache and hashes them again (about a second on a laptop).
They are fetched again only after the site's data is cleared, or if a cached copy stops matching
its pin (it is then deleted). A mirror in Source (`?params=<base URL>` prefills it) overrides
the default; it must send CORS headers and be allowed by the page's `connect-src`.

Rules (as `app/lib`): the TypeScript never constructs transaction bytes, keys or scripts, and
never imports a crypto, SQLite or socket package (`scripts/check-web-imports.sh`). Its only
network destination is its own origin (the gateway). `src/core.ts` is the whole surface the
screens see (the W1a contract); `src/keystore.ts` keeps the seed encrypted at rest (WebAuthn
PRF or PBKDF2 → AES-GCM, in IndexedDB).
