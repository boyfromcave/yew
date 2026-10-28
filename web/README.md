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

Rules (as `app/lib`): the TypeScript never constructs transaction bytes, keys or scripts, and
never imports a crypto, SQLite or socket package (`scripts/check-web-imports.sh`). Its only
network destination is its own origin (the gateway). `src/core.ts` is the whole surface the
screens see (the W1a contract); `src/keystore.ts` keeps the seed encrypted at rest (WebAuthn
PRF or PBKDF2 → AES-GCM, in IndexedDB).
