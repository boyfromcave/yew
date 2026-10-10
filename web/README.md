# yew/web — YEW in the browser

The third shell on the YEW core (after iOS and Android): the same Rust core compiled to
WebAssembly, a small TypeScript PWA around it. Plan: `docs/plans/yew-web-plan.md`.

```bash
scripts/build-core-wasm.sh     # wasm-pack build core-wasm → src/wasm/ (needs rustup target wasm32-unknown-unknown, wasm-pack)
npm install && npm run dev     # Vite on http://localhost:5173 with COOP/COEP headers
npm run check                  # the import rule + tsc + vitest (the view-models against MockCore)
npm run build                  # dist/ for the ycash-infra web image (needs src/wasm/ built)
scripts/test-web-smoke.sh      # headless Chrome walks the built bundle with ?mock=1
```

`http://localhost:5173/?mock=1` (or `VITE_MOCK=1`) runs the screens on `src/mock.ts`, a canned
core, without the wasm module or a server.

Rules (as `app/lib`): the TypeScript never constructs transaction bytes, keys or scripts, and
never imports a crypto, SQLite or socket package (`scripts/check-web-imports.sh`). Its only
network destination is its own origin (the gateway). `src/core.ts` is the whole surface the
screens see (the W1a contract); `src/keystore.ts` keeps the seed encrypted at rest (WebAuthn
PRF or PBKDF2 → AES-GCM, in IndexedDB).
