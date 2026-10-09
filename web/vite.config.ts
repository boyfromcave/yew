import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

// COOP/COEP: SharedArrayBuffer for the prover's worker pool and OPFS sync access handles.
// Production gets the same headers (and the CSP) from the ycash-infra web image's nginx.conf.
const isolation = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
};

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  server: { headers: isolation, port: 5173 },
  preview: { headers: isolation },
  worker: { format: "es", plugins: () => [wasm(), topLevelAwait()] },
  build: { target: "es2022", sourcemap: false },
});
