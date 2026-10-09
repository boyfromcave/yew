# yew/web — YEW in the browser

The third shell on the YEW core (after iOS and Android): the same Rust core compiled to
WebAssembly, a small TypeScript PWA around it. Plan: `docs/plans/yew-web-plan.md`.

```bash
scripts/build-core-wasm.sh     # wasm-pack build core-wasm → src/wasm/ (needs rustup target wasm32-unknown-unknown, wasm-pack)
npm install && npm run dev     # Vite on http://localhost:5173 with COOP/COEP headers
npm run build                  # dist/ for the ycash-infra web image
```

Rules (as `app/lib`): the TypeScript never constructs transaction bytes, keys or scripts, and
never imports a crypto, SQLite or socket package (`scripts/check-web-imports.sh`). Its only
network destination is its own origin (the gateway).
