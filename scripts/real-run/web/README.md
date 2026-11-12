<!-- Copyright (c) 2026 The Ycash developers -->
<!-- Distributed under the MIT software license, see the accompanying -->
<!-- file LICENSE or https://www.opensource.org/licenses/mit-license.php . -->

# The web wallet's real-stack run (regtest)

`yew/web` (the wasm core in a browser) driven in headless Chrome against a real ycash6 node and
lightwalletd-dd, the node as the oracle. Not part of CI. The gRPC-web front is one Envoy
container (the `grpc_web` + `cors` filters ycash-infra's gateway adds), not the kind cluster: the
bundle needs nothing else from the cluster (the address calls are lightwalletd's own with
`-insightexplorer`).

| file | what |
|---|---|
| `run.sh` | `up` (the stack, Envoy, `vite preview`, chromedriver, two proving-file mirrors), `walk`, `down` |
| `web_real_stack.py` | regtest stack on ycash6's test framework: node 0 miner/pool/backend (`-insightexplorer -txindex`), node 1 the receiver, YED live (`activate_yed_late`), lightwalletd `--yellowback`; holds until `<tmpdir>/stop` |
| `web_real_walk.py` | the walk in phases: `addr,fund,params,sends,private,fresh,arm,yed,persist,restore` (see its docstring; `fresh` is a second browser profile with default settings) |
| `drive.py`, `wd.py` | the page (stdlib WebDriver over HTTP, a persistent session) and the nodes (`ycash-cli` from `stack.json`) |
| `sendcell.py`, `mint.py` | one send cell (preview, confirm, mempool, mine, the transaction, balances against the node) and one mint (estimate, carrier, MINT) |
| `attest_loop.py` | keeps node 0's attestation pool fresh after `arm` (devnet doc section 2, by hand) |
| `params_mirror.py` | a loopback mirror of the Sapling files with CORS (`--corrupt`: one byte flipped) |
| `lying_proxy.py` | a hostile gRPC-web server: rewrites the fee terms of `GetYellowbackInfo` |

Requirements: Docker (Envoy `envoyproxy/envoy:v1.32.3`), Google Chrome and a chromedriver of the
same major version (Chrome for Testing, unpacked anywhere: `CHROMEDRIVER=<path>`), a built ycash6
tree, a lightwalletd-dd binary, the workspace Python, the Sapling files in
`~/.cache/yew-web/sapling-params` (`web/scripts/test-spike-prover.sh` fetches them), and the web
bundle built from this tree:

```bash
(cd web && CARGO_TARGET_DIR=$PWD/../target scripts/build-core-wasm.sh && npm ci && npm run build)
(cd <lightwalletd-dd tree> && go build -o $S/bin/lightwalletd .)
CHROMEDRIVER=<chromedriver> S=<scratch dir> Y6=<ycash6 tree> scripts/real-run/web/run.sh up    # ~3 min
CHROMEDRIVER=<chromedriver> S=<scratch dir> scripts/real-run/web/run.sh walk                   # ~25 min
S=<scratch dir> scripts/real-run/web/run.sh down
```

To serve the page as production does, from ycash-infra's web image (the bundle and the Sapling
proving files at `/sapling-params/`, nginx with COOP/COEP/CSP), build that image from this tree's
`web/dist` and pass it: `WEB_IMAGE=<tag> NAME=<container prefix> … run.sh up`. With
`WEB_IMAGE` the `params` and `fresh` phases prove the default source; under `vite preview` the
default source has no files and the walk falls back to the loopback mirror. The whole walk
(`run.sh walk`, all phases) runs end to end in about 45 minutes; run `arm` once per stack.

Hostile fee terms: `lying_proxy.py 29773 http://127.0.0.1:29769 --rate-x 20 --price-micro 2500000`,
then restore the seed in a second browser session (`WD_STATE=<other file> wd.py new`) with
`http://127.0.0.1:29773` as the server and preview a post-quantum send. Inconsistent terms
(a rate that does not match the reported price) are refused as `inconsistent-server`;
consistent ones above twice the usual fee need "Pay this fee" before the slider works.

The ECC comparison in `sendcell.py` sums the node's `getaddressbalance` over the wallet's ECC
addresses it has seen (`own_ecc.json`: the receive address and every change address of a
recorded transaction); an address it missed shows as `CHECK`, not as a wallet fault.
