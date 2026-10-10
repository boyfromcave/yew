#!/usr/bin/env node
// Subresource integrity for the built index.html (yew/web plan §3, W3), a post-step of
// `npm run build`: every <script src> and <link href> that points at a file in dist/ gets
// `integrity="sha384-…"` computed over the bytes ON DISK, so a served index.html pins the exact
// main chunk and stylesheet the build wrote. (A Vite transformIndexHtml hook sees the chunk
// before vite:build-import-analysis rewrites its preload lists in generateBundle, so its hash
// would be of the wrong bytes; the files are final here.) What SRI cannot cover: the worker
// (`new Worker(url)` takes no integrity), the wasm module (fetched by the glue) and the dynamic
// chunks (`import()`). Those are bound by the content-hashed names the pinned main chunk
// references, and the whole dist/ by BUNDLE-SHA256SUMS (scripts/build-release.sh,
// scripts/verify-bundle.sh).
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dist = process.argv[2] ?? "dist";
const index = join(dist, "index.html");
const TAG = /<(script|link)\b([^>]*?)\s(src|href)="\/([^"]+)"([^>]*)>/g;
let n = 0;
const html = readFileSync(index, "utf8").replace(TAG, (tag, el, before, attr, path, after) => {
  if (/\bintegrity=/.test(tag)) return tag;
  const sum = "sha384-" + createHash("sha384").update(readFileSync(join(dist, path))).digest("base64");
  const cross = /\bcrossorigin\b/.test(tag) ? "" : " crossorigin";
  n++;
  return `<${el}${before} ${attr}="/${path}" integrity="${sum}"${cross}${after}>`;
});
if (n === 0) { console.error(`sri: no script/link tags in ${index}`); process.exit(1); }
writeFileSync(index, html);
console.log(`sri: ${n} tags pinned in ${index}`);
