# yewd — the YEW core as a daemon

`yewd` is a wallet process that sits in front of a **wallet-less node** — kogany (the Ycash
developers' Zakura fork), or ycash6 started with `-disablewallet` — and answers the ycashd
wallet RPCs by name and JSON shape. The pair is a Ycash node with a wallet, with no ycashd wallet
involved. It is the third shell on the YEW core, beside `app/` (Flutter) and `web/` (browser), and
a **client** of the node: it reaches it only through public RPC (later also the gRPC indexer
streams and lightwalletd-dd), and never needs a node change.

Plan: [`docs/plans/yewd-plan.md`](../docs/plans/yewd-plan.md), which points into the workspace's
kogany plan (`docs/plans/kogany/kogany-yellowback-plan.md` §3b, §4.3, §5; decisions K-20, K-22–K-26).

**State: S1, wallet state and sync.** S0's shell (authentication, the full method table,
forwarding of every node RPC, `help`, `stop`) plus the wallet: public material only in the façade
(the signer derives it from the seed, K-24), a block-reading sync with reorg rewind, and the read
RPCs (`yewd-wallet/src/rpc.rs` `SERVED`: 9 of the 47, `vault_getnewowner`, `set_listsigned` and
the seven YED reads, plus 10 stock reads). Every other wallet RPC still answers `-32601` with
`yewd: not yet implemented (<method>; plan §3b S<n>)` until S2–S4 implement it.

## Layout

```
yewd/
├── Cargo.toml     its own Cargo workspace (as web/core-wasm): the server's dependencies stay out of
│                  the root Cargo.lock and scripts/check-deps.sh; yew-core by path (../core)
├── Cargo.lock     started as a copy of the root lock: the shared graph resolves to the core's versions
├── PIN            the ycash6 and kogany commits the CI legs pull
├── facade/        crate yewd-facade, binary `yewd`: JSON-RPC server, method table, forwarding
├── wallet/        crate yewd-wallet: wallet state, sync and builders on yew-core (S1, S2)
├── signer/        crate yewd-signer, binary `yewd-signer`: the seed and the public bundle (S1); signing,
│                  sign-once, the attestation guard (S2)
├── proto/         crate yewd-proto: the public bundle (S1), the sign request and response (S2)
├── qa/s1_wallet_reads.py   the S1 exit gate on ycash6's functional framework (below)
└── scripts/check-yewd.sh   the CI unit leg: naming/attribution greps, fmt, clippy, tests
```

Build and test (the root workspace, the app and the web builds are untouched):

```bash
cargo build --manifest-path yewd/Cargo.toml
yewd/scripts/check-yewd.sh
# with a backend: the regtest round trip (facade/tests/regtest.rs)
YEWD_TEST_YCASHD=/path/to/ycashd YEWD_TEST_REQUIRE_BACKEND=1 cargo test --manifest-path yewd/Cargo.toml --test regtest
# the S1 exit gate on ycash6's functional framework (ycash6 vaults/kogany-compat: the YEWD_BIN harness)
YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycash6>/src/ycashd YEWD_BIN=<target>/debug/yewd \
  <workspace>/.venv/bin/python yewd/qa/s1_wallet_reads.py --tmpdir=<dir>
# the pinned PQ wallet vectors from kogany (else yew's byte-identical copy is replayed)
YEWD_PQ_WALLET_VECTORS=<kogany>/testdata/yellowback/pq_wallet_vectors.json cargo test --manifest-path yewd/Cargo.toml -p yewd-signer
```

## The method table

`facade/src/methods.rs` lists every ycashd wallet RPC; a listed method is **never forwarded**, so
a backend that has a wallet of its own cannot answer for this one. Anything not listed is a node
RPC and goes to the backend unchanged (the request bytes out, the reply bytes back: amounts keep
the node's decimal text).

| Class | Methods | S1 answer |
|---|---|---|
| Wallet, R5 vault | the 22 `set_*` / `vault_*` wallet RPCs (ycash6 `src/rpc/vault.cpp`) | served: `vault_getnewowner`, `set_listsigned`; the rest `-32601` "yewd: not yet implemented" |
| Wallet, R6 YED | the 25 `yed_*` wallet RPCs (ycash6 `src/rpc/yellowbackwallet.cpp`) | served: `yed_getnewaddress`, `yed_validateaddress`, `yed_getbalance`, `yed_listunspent`, `yed_listpositions`, `yed_listtransactions`, `yed_listaddresses`; the rest `-32601` |
| Wallet, R7 | `z_importpqkey` | `-32601` "yewd: not yet implemented" |
| Wallet, K-25 stock | the 30 the Yellowback scripts call, and the 4 only the roles call | served: `getbalance`, `getnewaddress` (incl. `"pq"`/`"pqslh"`), `getreceivedbyaddress`, `gettransaction`, `getwalletinfo`, `listlockunspent`, `listunspent`, `z_getbalance`, `z_getnewaddress`, `z_listunspent`; the rest `-32601` |
| Out of scope | the rest of ycashd's wallet table (39: `listtransactions`, `z_shieldcoinbase`, …) | `-32601` "yewd: not served" |
| Local | `createrawtransaction`, `decoderawtransaction`, `decodescript` | forwarded; served from yew-core in S4 |
| Augmented | `getinfo`, `validateaddress`, `z_validateaddress`, `set_getinfo`, `vault_list`, `yed_gettxinfo` | forwarded, then the wallet adds its fields (`balance`…, `ismine`…, `memberlist[].wallet`, the `wallet` column and the `mine` filter of `vault_list`; `yed_gettxinfo` has none in rpcversion 8). `z_validateaddress` is answered by yewd itself: a ycash6 `-disablewallet` backend stops on it (it dereferences its absent wallet) |
| Own | `help` (the backend's listing plus a "Wallet (yewd)" section), `stop` | served |
| everything else | node RPCs | forwarded |

HTTP conventions are ycashd's (`src/httprpc.cpp`): POST only (405 otherwise), Basic auth (401 with
`WWW-Authenticate: Basic realm="jsonrpc"`, 250 ms delay on a wrong password), 403 for a peer
outside `-rpcallowip`, JSON-RPC 1.0 replies `{"result","error","id"}` with HTTP 404 for `-32601`,
400 for `-32600`, 500 for other errors, 200 for a batch. While the backend cannot be reached (not
started, or its cookie not written yet) a forwarded call answers `-28` (ycashd's warm-up code), so a
harness's "wait for RPC" loop waits for the pair (hazard H5).

## Command line

ycashd-style options: `-name=value`, `-name` (= 1), `-noname` (= 0); `--name` is accepted too.
The configuration file holds the same names as `name=value` lines (`#` comments); the command line
wins. Options yewd does not use are **reported on stderr and ignored**, so a harness can pass
ycashd's wallet arguments (`-keypool`, `-exportdir`, …) and a ycashd-format `ycash.conf`
(`port=`, `showmetrics=`, `listenonion=` are ignored) unchanged.

| Option | Default | Meaning |
|---|---|---|
| `-datadir=<dir>` | `~/.yewd` | data directory |
| `-conf=<file>` | `<datadir>/yewd.conf` (optional) | configuration file; relative to `-datadir`; a named file must exist |
| `-regtest` / `-testnet` | mainnet | picks the default `-rpcport` and the cookie subdirectory (`regtest/`, `testnet/`) |
| `-rpcbind=<ip>[:port]` | `127.0.0.1` | listen address, repeatable |
| `-rpcport=<port>` | 8832; 18832 on testnet and regtest | listen port (ycashd's defaults: the façade stands where ycashd stood) |
| `-rpcuser=<u>` `-rpcpassword=<p>` | — | client credentials; without `-rpcpassword`, cookie authentication |
| `-rpccookiefile=<file>` | `<datadir>/<net>/.cookie` | the cookie yewd writes (`__cookie__:<64 hex>`, mode 0600) and removes at exit; so `ycash-cli -datadir=<datadir>` finds it |
| `-rpcallowip=<ip\|ip/n\|ip/mask>` | loopback only | allowed client subnets, repeatable; loopback is always allowed |
| `-backendrpcconnect=<ip>` | `127.0.0.1` | the node's RPC address |
| `-backendrpcport=<port>` | **required** | the node's RPC port |
| `-backendrpccookiefile=<file>` | — | the node's `.cookie`; re-read after a 401, so a node restart is followed |
| `-backendrpcuser=<u>` `-backendrpcpassword=<p>` | — | instead of the cookie (one of the two is required) |
| `-stopbackend` | off | `stop` also sends `stop` to the node (the harness bundle: the pair is one node, H6) |
| `-signer=<socket>` | — | reserved for S2 (the signer's Unix socket) |
| `-signerbin=<file>` | `yewd-signer` beside `yewd` | the signer binary S1 runs as a child process (`init`, `public`) |
| `-walletpoll=<ms>` | 1000 | how often the wallet follows the node between calls (the poll fallback); 0 = only at calls (every wallet RPC syncs first anyway: the barrier, H1) |
| `-initwallet` | | create the wallet (the seed in `<datadir>/<net>/signer/`, birthday 0), print `{"mineaddress": "<s…>"}` and exit; needs no backend (H8, below) |
| `-debug` | off | log each method called |
| `-help`, `-version` | | |

`stop` answers `"yewd stopping"` (`"yewd stopping (backend stopping)"` with `-stopbackend`) and the
process exits about 200 ms later; SIGINT and SIGTERM stop it too. Logs go to stderr.

## The wallet (S1)

- **Files.** `<datadir>/<net>/signer/seed.json` (mode 0600 in a mode-0700 directory: the phrase,
  the signer's alone; S4 encrypts it) and `<datadir>/<net>/yewd/wallet.json` (public material,
  issue counters, the address book, the processed tip with a window of 288 recent block hashes,
  and the wallet transactions' bytes and block positions; coins, notes and balances are derived
  from them at load, as ycashd derives them from `mapWallet`). Nothing secret is in `wallet.json`.
- **Keys (K-24).** The façade holds the signer's public bundle: the BIP32 account node
  `m/44'/347'/0'` (CKDpub for `/{0,1}/i`, 100 keys of lookahead per chain), the Sapling DFVK of
  `m/32'/347'/0'` (diversified addresses, trial decryption, nullifiers) and a pool of PQ public
  keys (20 of lookahead per scheme, topped up by asking the signer, as ycashd's `TopUpPQKeys`).
  The same seed in the YEW app sees the same transparent and Sapling coins.
- **Sync.** The node's RPC is the truth: every wallet RPC first brings the wallet to the node's
  best block (`getbestblockhash`; the fork point found in the recent-hash window, every wallet
  transaction above it rewound; new blocks read whole with `getblock <hash> 0`; the mempool with
  `getrawmempool` + `getrawtransaction`), so a script's `generate` then wallet RPC never sees stale
  data (H1). A reorg deeper than the window rescans from the birthday (H2). While the backend
  cannot be reached a wallet RPC answers `-28` (H5).
- **Coinbase (H8).** A new wallet's first external address is its coinbase address. ycash6
  `-disablewallet` mines only with `-mineraddress=<it> -minetolocalwallet=0`; kogany takes it as its
  `miner_address`.

## Harness mode (`YEWD_BIN`)

**S1 adds one step for scripts that mine on a pair node (H8), for the harness chunk to take
over:** before the backend of node *i* starts, run `YEWD_BIN -datadir=node<i> -conf=ycash.conf
-regtest -initwallet` and give the backend `-mineraddress=<mineaddress> -minetolocalwallet=0`
(`yewd/qa/s1_wallet_reads.py` does this for its one pair node in `setup_network`/`node_args`).

The ycash6 functional harness (`qa/rpc-tests/test_framework/`) gains `YEWD_BIN` beside
`KOGANY_BIN` (the harness chunk implements it; nothing in ycash6 changes for S0). Node *i* becomes
**backend *i* + yewd *i***, and every script keeps talking to `rpc_url(i)`:

1. `initialize_datadir(dirname, i)` writes `node<i>/ycash.conf` as today (`rpcuser💻<i>`,
   `rpcpass🔑<i>`, `rpcport=rpc_port(i)`, `port=p2p_port(i)`, `regtest=1`). **yewd uses that file**:
   `-datadir=node<i> -conf=ycash.conf`, so it listens on `rpc_port(i)` with the script's
   credentials (the non-ASCII user names are handled) and `ycash-cli -datadir=node<i>` reaches it.
2. The backend gets its own directory `node<i>/backend/` and an RPC port outside the harness's
   `rpc_port` range (for example `rpc_port(i) + MAX_NODES` or a port from the same `PortSeed`
   formula with an offset), with **cookie** auth (no `rpcpassword` in its config): ycash6 is started
   `-disablewallet -datadir=node<i>/backend -rpcport=<b>` plus all the node arguments the script
   gave (`-nuparams`, `-debug`, `-mocktime`, `-yellowback*`, …) and the P2P port `p2p_port(i)`, so
   `connect_nodes_bi` and `disconnectnode('127.0.0.1:<p2p_port>')` work unchanged; kogany is
   started from its generated `zakurad.toml` with the same ports.
3. yewd is started
   `YEWD_BIN -datadir=node<i> -conf=ycash.conf -regtest -backendrpcport=<b>
   -backendrpccookiefile=node<i>/backend/regtest/.cookie -stopbackend <wallet args>`,
   where the wallet arguments are the ycashd wallet options split out of the script's
   arguments (`-keypool`, `-exportdir`, `-paytxfee`, `-mintxfee`, `-txconfirmtarget`,
   `-walletnotify`, `-spendzeroconfchange`, `-rescan`, `-wallet`; `-mocktime` goes to both).
   S0 ignores them; S4 gives them meaning. Order does not matter: yewd answers `-28` until the
   backend is up, which `wait_for_bitcoind_start` already retries.
4. `bitcoind_processes[i]` is the yewd process; the backend's process is kept beside it.
   `stop_node` / `stop_nodes` call `stop` on yewd (which stops the backend) and wait for **both**
   processes; `kill9` kills both.
5. Where a script needs the node directly (a `-28`-sensitive start, `assert_start_raises_init_error`,
   the backend's debug log in `check_node_log`), the harness maps it to `node<i>/backend/`.

Because the hook sits at `util.start_node` / `start_nodes` / `stop_node`, it covers scripts on
`BitcoinTestFramework` that call `start_nodes` themselves — both contract suites do — as well as
`YellowbackTestFramework`.

**The contract suites.** `qa/rpc-tests/vault_rpc_contract.py` (two nodes) and
`qa/rpc-tests/yellowback_rpc_contract.py` run unchanged with `YEWD_BIN` set: every node is a pair,
and each documented RPC is checked against its shape and error codes through the façade. In S0
they fail at the first wallet RPC, which is expected; the leg reports *n*/47 (plan §3b S0's
baseline). The count comes from each suite's per-command results: a command whose call answers
`-32601 yewd: not yet implemented` is counted as not served. Pointing them at plain ycash6 (no
`YEWD_BIN`) is the "contract vs ycash6" leg, which proves the harness and the contract copy.
