import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";

// COOP/COEP: SharedArrayBuffer for the prover's worker pool and OPFS sync access handles.
// Production gets the same headers (and the CSP) from the ycash-infra web image's nginx.conf.
const isolation = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
};

// No vite-plugin-top-level-await: the build target is es2022, where top-level await is native,
// and that plugin's swc pass fails on the worker bundle ("missing field `type`", W1b).
//
// Reproducible (W3): Rollup names chunks by a content hash and writes no timestamps; nothing
// here reads the clock or the environment, so two builds of one tree are byte-identical
// (scripts/build-release.sh proves it and writes dist/BUNDLE-SHA256SUMS); scripts/sri.mjs,
// the post-step of `npm run build`, pins the tags of index.html to the written bytes. Keep it
// that way: no build-time dates, no
// `import.meta.env` values that differ by machine, no minifier randomness (esbuild is
// deterministic), `reportCompressedSize` off so the build neither reads nor writes anything
// outside dist/.
export default defineConfig({
  plugins: [wasm()],
  server: { headers: isolation, port: 5173 },
  preview: { headers: isolation },
  worker: { format: "es", plugins: () => [wasm()] },
  build: { target: "es2022", sourcemap: false, reportCompressedSize: false },
});
