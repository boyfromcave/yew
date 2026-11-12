# yewd — the YEW core as a daemon

`yewd` is a wallet process that sits in front of a **wallet-less node** — kogany (the Ycash
developers' Zakura fork), or ycash6 started with `-disablewallet` — and answers the ycashd
wallet RPCs by name and JSON shape. The pair is a Ycash node with a wallet, with no ycashd wallet
involved. It is the third shell on the YEW core, beside `app/` (Flutter) and `web/` (browser), and
a **client** of the node: it reaches it only through public RPC (later also the gRPC indexer
streams and lightwalletd-dd), and never needs a node change.

Plan: [`docs/plans/yewd-plan.md`](../docs/plans/yewd-plan.md), which points into the workspace's
kogany plan (`docs/plans/kogany/kogany-yellowback-plan.md` §3b, §4.3, §5; decisions K-20, K-22–K-26).

**State: S4, the façade complete** (S3: the roles; S2: the builders and the signer boundary; S1:
the wallet; S0: the shell). Every wallet RPC of the façade's table is served — `yewd-wallet/src/rpc.rs`
`all_served()`: **47 of the 47** (all 22 R5 `set_*`/`vault_*`, all 25 R6 `yed_*`), R7's
`z_importpqkey`, and **34 of the 34** of the K-25 stock set (with the two reads K-25 gained when it was
amended for beta2, 2026-11-11: `z_gettotalbalance`, `listaddresses`) — and the three raw helpers
(`createrawtransaction`, `decoderawtransaction`, `decodescript`) are answered by the façade itself.
Arity is ycashd's (`-32602` "Not enough|Too many parameters for method …" with the help text,
`facade/src/ycashd_rpc.json`, generated from a plain ycash6 wallet node by `qa/gen_ycashd_rpc_table.py`),
`help <method>` is ycashd's text and the `help` listing holds ycashd's lines for these methods in
ycashd's categories. S4 added the wallet encryption (the seed and the imported keys sealed in the
signer), the dumps and their imports (written and read by the signer), `backupwallet` and its restore
(`-wallet`), `z_sendmany` and its operations with **the Sapling build in the signer** (the façade keeps the
notes and computes their Merkle paths from the node's tree state; the signer proves and signs), the same
Sapling build inside the YED builders (a mint funded from a Sapling address, a redemption or a bond
withdrawal paying one), the armed attestation layer's wallet facts (the AFEE-W attestor payee, the
claim notice, `canNotice`), and the backend-exit watch (H6).

## Layout

```
yewd/
├── Cargo.toml     its own Cargo workspace (as web/core-wasm): the server's dependencies stay out of
│                  the root Cargo.lock and scripts/check-deps.sh; yew-core by path (../core)
├── Cargo.lock     started as a copy of the root lock: the shared graph resolves to the core's versions
├── PIN            the ycash6 and kogany commits the CI legs pull
├── facade/        crate yewd-facade, binary `yewd`: JSON-RPC server, method table, forwarding
├── wallet/        crate yewd-wallet: wallet state, sync and builders on yew-core (S1, S2)
├── signer/        crate yewd-signer, binary `yewd-signer`: the seed and the public bundle (S1); the
│                  Unix-socket server, the signing policy, the sign-once records (S2)
├── proto/         crate yewd-proto: the protocol (version 1): requests, responses, key references, the
│                  preview both ends compute, the YV act codec and the set messages, the socket client
├── qa/s1_wallet_reads.py   the S1 exit gate on ycash6's functional framework (below)
├── qa/s2_wallet_builders.py   the S2 exit gate: every build RPC on yewd beside the same request on ycashd
├── qa/s3_roles.py   the S3 exit gate: the role scripts with their role nodes as pairs, and the roles stage
├── qa/ycashd_pair.py   a stand-in `ycashd` that starts the pair (for tools that start their own node: Hawkeye's tests)
├── qa/s4_contract.py   the S4 exit gate's contract legs: ycash6's two contract suites, unchanged, every node a pair
├── qa/s4_facade.py   the S4 exit gate's façade leg: arity, help, errors, raw helpers and the stock RPCs against ycashd
├── qa/gen_ycashd_rpc_table.py   regenerates facade/src/ycashd_rpc.json (ycashd's help texts and arity) from a ycash6 node
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
# the S2 exit gate: every build RPC through yewd, each beside the same request on a plain ycashd
YCASH6_QA=<ycash6>/qa/rpc-tests ZCASHD=<ycash6>/src/ycashd YEWD_BIN=<target>/debug/yewd \
  <workspace>/.venv/bin/python yewd/qa/s2_wallet_builders.py --tmpdir=<dir> --portseed=<n>
# the S3 exit gate: a role script with its role nodes as pairs, or the roles stage
YCASH6_QA=... ZCASHD=... YEWD_BIN=... <workspace>/.venv/bin/python yewd/qa/s3_roles.py --stage=attest_wallet|roles|attest_bond|attest_agent|cancel_agent --tmpdir=<dir> --portseed=<n>
# Hawkeye's regtest test against the pair (unchanged test; the node is the stand-in)
ZCASHD=... YEWD_BIN=... HAWKEYE_REGTEST_YCASHD=yewd/qa/ycashd_pair.py cargo test -p hawkeye --test regtest_self_signing
# the S4 exit gate: the contract suites unchanged with every node a pair; the façade leg against ycashd
YCASH6_QA=... ZCASHD=... YEWD_BIN=... <workspace>/.venv/bin/python yewd/qa/s4_contract.py --suite=vault|yellowback --tmpdir=<dir> --portseed=<n>
YCASH6_QA=... ZCASHD=... YEWD_BIN=... <workspace>/.venv/bin/python yewd/qa/s4_facade.py --tmpdir=<dir> --portseed=<n>
# any other ycash6 script with every node a pair (a probe ahead of S5's gate)
YCASH6_QA=... ZCASHD=... YEWD_BIN=... <workspace>/.venv/bin/python yewd/qa/s4_contract.py --script=yellowback_sapling --tmpdir=<dir> --portseed=<n>
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
| Wallet, R5 vault | the 22 `set_*` / `vault_*` wallet RPCs (ycash6 `src/rpc/vault.cpp`) | served (`wallet/src/vaultrpc.rs`; S1 reads, S2 builders) |
| Wallet, R6 YED | the 25 `yed_*` wallet RPCs (ycash6 `src/rpc/yellowbackwallet.cpp`) | served (`wallet/src/{rpc,yed,mint,claim,attest,armed,zfund}.rs`) |
| Wallet, R7 | `z_importpqkey` | served (`wallet/src/admin.rs`; the key in the signer) |
| Wallet, K-25 stock | the 30 the Yellowback scripts call, and the 4 only the roles call | served: the reads (S1), the sends and `signrawtransaction` (S2), `signmessage`/`importprivkey`/`dumpprivkey` (S3); S4's `addmultisigaddress`, `backupwallet`, `encryptwallet`, `walletpassphrase`, `walletlock`, `settxfee`, `importwallet`, `z_exportwallet`, `z_importwallet`, `z_getnewdiversifiedaddress`, `z_listreceivedbyaddress` (`wallet/src/admin.rs`), `z_sendmany`, `z_getoperationstatus`, `z_getoperationresult`, `z_listoperationids` (`wallet/src/zsend.rs`); the forwarded node RPC `sendrawtransaction` keeps ycashd's H7 wallet guard first (`allowyedburn`) |
| Wallet, K-25 amended for beta2 (2026-11-11) | `z_gettotalbalance`, `listaddresses`: the balance and the addresses by type (ECC, post-quantum by scheme, Sapling), read-only | served (`wallet/src/bytype.rs`); ycash-dd v4.5.0 has no `listaddresses`, ycash6's is the reference |
| Out of scope | the rest of ycashd's wallet table (33: `z_shieldcoinbase`, …) | `-32601` "yewd: not served" |
| Local | `createrawtransaction`, `decoderawtransaction`, `decodescript` | answered by the façade (`wallet/src/raw.rs`: ycashd's `TxToJSON`, `ScriptToAsmStr`, `Solver`); a refusal takes the backend's words when it has the helper (the C++ deserializer's texts), ours when it lacks it (kogany) |
| Augmented | `getinfo`, `validateaddress`, `z_validateaddress`, `set_getinfo`, `vault_list`, `yed_gettxinfo`, `yed_getinfo` | forwarded, then the wallet adds its fields (`balance`, `paytxfee`, `unlocked_until`…, `ismine`…, a known redeem script's `script`/`hex`/`addresses`/`sigsrequired`, `memberlist[].wallet`, the `wallet` column and the `mine` filter of `vault_list`, `yed_getinfo`'s `lockedOutputs`/`protectedByIndex`). `z_validateaddress` is answered by yewd itself: a ycash6 `-disablewallet` backend before `eac62c942` stops on it |
| Own | `help` (the backend's listing with ycashd's lines for the façade's methods merged in), `stop`, and yewd's own `clearunknownsubmission "txid"` (not a ycashd method; see "A submission's answer lost") | served |
| everything else | node RPCs | forwarded |

Arity: every wallet and local method is checked as ycash6's RPC table checks it, before the handler
(`-32602`, the help text after a blank line; `walletlock`/`walletpassphrase` only on an encrypted
wallet, as ycashd). A locked encrypted wallet refuses every method that signs, draws a key or reads a
secret with `-13` "Error: Please enter the wallet passphrase with walletpassphrase first."
(`wallet/src/admin.rs` `NEEDS_UNLOCK`).

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
| `-signer=<socket>` | — | a signer someone else runs (`yewd-signer serve`): its Unix socket; without it yewd starts its own |
| `-signerbin=<file>` | `yewd-signer` beside `yewd` | the signer binary yewd runs: `init` (and `public` for `-initwallet`), then `serve -watchstdin` |
| `-walletpoll=<ms>` | 1000 | how often the wallet follows the node between calls (the poll fallback); 0 = only at calls (every wallet RPC syncs first anyway: the barrier, H1) |
| `-initwallet` | | create the wallet (the seed in `<datadir>/<net>/signer/`, birthday 0), print `{"mineaddress": "<s…>"}` and exit; needs no backend (H8, below) |
| `-exportdir=<dir>` | — | where `z_exportwallet` and `backupwallet` write (ycashd's) |
| `-paytxfee=<amt>` | 0 | the legacy fee rate `settxfee` sets (YEC per 1000 bytes; reported, as ycashd's `payTxFee`) |
| `-developerencryptwallet=0` | (allowed) | refuse `encryptwallet` (`-16 "Error: wallet encryption is disabled."`); yewd allows it otherwise, F-S4-3 |
| `-wallet=<file>` | `wallet.dat` | a `backupwallet` file in `<datadir>/<net>/` (or absolute) restored once at the first wallet call |
| `-rescan` | off | read the chain again from the wallet's birthday at open |
| `-salvagewallet` | off | a restored backup carries the sign-once restore marker (07/NEW-1) |
| `-mnemonicfile=<file>` | — | ycashd's seed-only restore: a **new** wallet takes its seed from the recovery phrase in `<file>` (the phrase on one line, or a `z_exportwallet` file's `recovery_phrase=` line), read by the signer itself; birthday 0 (a scan from genesis) and the sign-once restore marker set; ignored for a wallet with this seed, refused for one with another (F-S5-17) |
| `-paramsdir=<dir>` | ycashd's (`~/Library/Application Support/ZcashParams`, `~/.zcash-params`) | the Sapling parameters the signer proves with |
| `-yellowback=0` | off | ycashd's acknowledgement: a wallet that has held YED (`getwalletinfo.yed_held`) may spend as plain YEC while the node reports Yellowback not live; logged at start and on each such send (below) |
| `-backendexitgrace=<s>` | 20 | with `-stopbackend`: exit once the backend has been gone this long after it was up (H6: the node stopped itself); 0 = never |
| `-backendlostexit=<s>` | 10 on regtest, else 0 | with `-stopbackend` and a cookie: once the backend has been gone this long with its cookie left (a crash), log it and end with SIGKILL, as the node did; 0 = never |
| `-debug` | off | log each method called |
| `-help`, `-version` | | |

`stop` answers `"yewd stopping"` (`"yewd stopping (backend stopping)"` with `-stopbackend`) and the
process exits about 200 ms later; SIGINT and SIGTERM stop it too; `encryptwallet` stops it as it stops
ycashd. With `-stopbackend` the pair is one node both ways: yewd also exits when its backend has stopped
by itself (an `AbortNode`, a `stop` sent to the node) and has not come back within
`-backendexitgrace`. Logs go to stderr.

## The wallet (S1)

- **Files.** `<datadir>/<net>/signer/seed.json` (mode 0600 in a mode-0700 directory: the phrase,
  the signer's alone; sealed under the wallet passphrase after `encryptwallet`) and `<datadir>/<net>/yewd/wallet.json` (public material,
  issue counters, the address book, the processed tip with a window of 288 recent block hashes,
  and the wallet transactions' bytes and block positions; coins, notes and balances are derived
  from them at load, as ycashd derives them from `mapWallet`). Nothing secret is in `wallet.json`.
  `<datadir>/<net>/wallet.dat` stands in for the two (a restored `backupwallet` file, or a small
  note yewd writes): removing it means what it means to ycashd, the next start opens a **new** wallet
  (the old `yewd/` and `signer/` are moved aside as `*.wiped-<time>`, never deleted).
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
- **YED outputs are never spent as plain YEC (beta2).** Every path that selects transparent or
  post-quantum coins for a plain YEC spend takes the YED outpoint set from the node's index, and
  only when the node can answer for it: `yed_getinfo` must say `healthy: true` and
  `yed_listtokens` must answer with a list (any other shape is an error, review YEW-REVIEW-3 L3),
  else the spend is refused with the C++ lines' string
  ("refusing to spend as plain YEC while the Yellowback index is unhealthy (…)…") and the node's
  error is logged. "Yellowback not live" is the node's `-32601` on `yed_getinfo` (the yed_*
  commands exist exactly where the vault upgrade and a YED attestor set are configured); then no
  token can exist and sends proceed, every own output of exactly `TOKEN_VALUE` (0.0001 YEC) still
  reserved unless `-yellowback=0` (an RPC-filtering proxy answers `-32601` too; the YEW app's
  classifier keeps such outputs HELD the same way, review L3), **unless the wallet has held YED**: the write-once
  `yed_held` marker in `wallet.json` (set when the wallet first sees a YED token of its own,
  commits a transaction whose payload assigns it YED, or issues a holder key with
  `yed_getnewaddress` p2pkh/pq) makes every such spend refuse ("This wallet has held YED, but
  Yellowback is not live on the connected node, …") unless yewd runs with `-yellowback=0`. The
  C++ lines refuse to start in that case; yewd refuses at send time instead, because it can be
  pointed at another node without a restart.
- **`sendtoaddress`, `sendmany`, `fundrawtransaction`: ordinary (ECC) coins only (beta2 audit
  M-1, review LOW-1/LOW-2, as the C++ lines).** The coins these calls choose are P2PKH coins; a
  post-quantum coin is spent by naming its address in `z_sendmany`, which returns the change to it
  (a `fundrawtransaction` input the transaction already names stays). When the ECC coins do not
  cover the payment and the wallet holds post-quantum coins `z_sendmany` would spend (confirmed,
  not coinbase, unlocked, not an output YED holds, FN-DSA-512 only once Falcon is active), the
  call is refused with the C++ lines' text, "Insufficient funds in ordinary transparent addresses;
  this wallet also holds <amount> YEC at post-quantum addresses: send from one with z_sendmany,
  which returns the change to it", and each call's code (`sendtoaddress` -4, `sendmany` -6,
  `fundrawtransaction` -32603); otherwise the insufficient-funds errors are unchanged.
  `z_shieldcoinbase` from a post-quantum address points to `z_sendmany`.
- **A submission's answer lost (review M1).** A transaction the node accepted always returns its
  txid (a failing sync after it is a warning). When `sendrawtransaction`'s answer is lost, the
  wallet asks the node for the txid of the bytes; not found, the call answers "…status unknown,
  txid <txid>: check before sending again", the inputs stay locked, and every submission is
  refused, nothing sent, until the outcome is certain (review YEW-REVIEW-3 L1): the node has it
  (refused once, "reached the node"), or it is dead and its coins are released, either because
  the chain is 10 blocks past its `nExpiryHeight` (the node's tip, or the wallet's last synced tip
  while the node cannot answer, so it always clears) or because one of its inputs is spent by
  another transaction 10 blocks deep. One "not found" from the node is not final: a timed-out
  submission can be processed late, and yewd can be pointed at another node. Until then the
  refusal names the height at which the coins clear. The operator can release them sooner with
  `clearunknownsubmission "txid"` (the outstanding txid only; it needs no node): **if that
  transaction reached any node it can still be mined until its expiry height, and a payment sent
  again from the released coins can go out twice.** Only the node's rejections `-25`, `-26`,
  `-27` count as a refusal; any other JSON-RPC error (a proxy's `-32603` or `-1`) or transport
  failure is "status unknown" (review L2). Nothing is submitted again automatically.
- **Coinbase (H8).** A new wallet's first external address is its coinbase address. ycash6
  `-disablewallet` mines only with `-mineraddress=<it> -minetolocalwallet=0`; kogany takes it as its
  `miner_address`.

## The signer (S2)

K-24 (a): the façade builds, the signer signs. `yewd` starts `yewd-signer -datadir=<datadir>/<net>/signer
serve -socket=<sock> -watchstdin` as its child (unless `-signer=<socket>` names one) and keeps the
child's standard input open; the signer exits when the façade does. The socket is
`<datadir>/<net>/signer/signer.sock`, or `/tmp/yewd-<uid>/<16 hex of SHA-256(signer dir)>.sock` when
that path is longer than a Unix socket address takes (macOS: 104 bytes; F-S2-1); both ends compute it
with `yewd_proto::client::socket_path`. Mode 0600, the directory 0700 and the caller's own, and the
signer checks every connection's peer UID (`getpeereid`, `SO_PEERCRED`) against its own.

**Protocol version 1** (`yewd-proto`). One JSON object per line each way, in order:
`{"version": 1, "op": <op>, "body": <body>}` → `{"result": <kind>, "body": <body>}`. A request of
another version is refused (`bad-version`) before it is read further.

| `op` | body | answer `result` |
|---|---|---|
| `hello` | — | `hello` `{version, network, seed_fp}` |
| `public` | `{"pq": [[scheme, from, count], …]}` | `public` (S1's `PublicBundle`) |
| `sign` | `SignRequest` | `signed` `{tx, sighashes: [hex\|null]}` |
| `sign_act` | `{tx, keys: [KeyRef]}` | `act_sigs` `{payload, msg, sigs: [65-byte hex]}` |
| `sign_set` | `{tx, branch_id, index, prevout, set_id, role, keys: [KeyRef], acknowledge_restore}` | `set_sigs` `{sighash, msg, sigs}` |
| `list_signed` | — | `records` `{restored, records: [{setid, prevout, role, sighash}]}` |
| `import_signed` | `[record]` | `imported` `{imported, present}` |
| `acknowledge_restore` | — | `acknowledged` (the records) |
| any | | `refused` `{code, reason}` |

`SignRequest` = `{tx, branch_id, inputs: [{prevout: {outpoint, script, amount_zat}, key: KeyRef,
carrier_bundle?}], own_outputs: [{n, key, bond_locktime?}], gate_path, outflow_cap_zat, preview:
{sign: [{vin, outpoint, amount_zat}], outputs: [{n, amount_zat, address|script, mine, kind}], fee_zat,
outflow_zat}}`; `KeyRef` = `{"kind": "none"}` | `bip32 {chain, index}` | `pq {scheme, index}` |
`pq_owner {scheme, index, selector}` | `carrier {chain, index}` | `bond {chain, index, locktime}` (S3: the
CLTV path of a bond `P2SH(<locktime> CLTV DROP <pk> CHECKSIG)`, scriptSig `<sig> <redeem>`); a `bip32`
reference with `chain` 2 names the signer's imported key `index` (`importprivkey`, S3); `gate_path` = `yec` | `vault` |
`owner` | `yed` | `raw`.

**Policy** (`signer/src/sign.rs`), in this order, before any signature leaves the signer:
1. the transaction parses; a shielded one is refused (Sapling spends are built whole in the signer, K-24);
2. **every input is bound to a prevout**: one `inputs[i]` per `vin[i]`, its outpoint equal to
   `vin[i].prevout`, a non-empty script, an amount in `[0, MAX_MONEY]` (`unbound-input`);
3. every key named is derived and must own the script it signs or recognises: the P2PKH of the
   BIP32 key, the `TX_PQPKH` of the PQ key, the V/I whose owner is the PQ key (selector 2/3 of a V, 3 of
   an I), the carrier `P2SH(carrierScript(pk, SHA256(bundle)))`, an own output's P2PKH / `TX_PQPKH` /
   join bond (`key-mismatch`);
4. the gate path's shape: no template input and no data output on `yec`, at most one template input
   and never an owner key on `vault`, the owner's key at input 0 on `owner` (`gate`);
5. the preview is recomputed from the bytes and the prevouts (`yewd_proto::preview::compute`) and must
   equal the request's: an input signed but not listed is `foreign-input`, any other difference (an
   amount, a recipient, an output, the fee, the outflow) `preview-mismatch`;
6. the net outflow (signed inputs minus own outputs) must not exceed `outflow_cap_zat` (`outflow`);
   the façade sets the cap to what the request itself spends (a payment's amount and fee, a vault's
   amount, the flat fee of an act), and to the fee cap or `allowoutflow` on a hand-off (`vault_send`,
   `set_sendact`);
7. each digest is recomputed (ZIP-243 under `branch_id`; `SIGHASH_ALL|ANYONECANPAY` of the template
   input and `SHA256d("YcashSetSig" ‖ setId ‖ role ‖ prevout ‖ sighash)` for a set signature;
   `SHA256d("YcashSetAct" ‖ P ‖ vin[0].prevout)` for an act), then signed: ECDSA (RFC 6979; recoverable
   compact for set and act signatures, byte-identical to `CKey::SignCompact`), SLH-DSA / FN-DSA through
   yew-core's `pq.rs`. The whole transaction is signed or the request refused (H10).

**Sign-once** (`signer/src/signonce.rs`): `<signer dir>/signonce.json`, fsynced before a set
signature is returned. A different role or sighash for a recorded `(setid, prevout)` is refused
(`set-sign-once`, also when no signature is asked for); the same sighash (the same spend re-funded)
is idempotent; a seed restored from a phrase (`init -mnemonic=`) starts with the restore marker set
(`set-sign-restored` until `acknowledge_restore` or `{"acknowledgerestore": true}`); an import that
differs from a record is refused whole. The façade maps `set-sign-once` / `set-sign-restored` /
`outflow` / `foreign-input` to `-4`, an unreachable signer to `-13`.

**The roles' requests (S3, protocol version 1, additive).**

| `op` | body | answer `result` |
|---|---|---|
| `sign_attestation` | `{key, pubkey, seq, price_micro_usd, cited_height, block_hash}` | `attestation` `{hex (74 bytes), reused}` |
| `cancel_cosign` | `{key, pubkey, seq, set_id, intent, ref_height, block_hash, price_micro_usd?, collateral_zat, minted_cents, claim_threshold_bps}` | `cosign` `{cosig (69 bytes), price_micro_usd, reused}` |
| `sign_message` | `{key, message}` | `message_sig` (65 recoverable bytes, hex; the façade writes base64) |
| `import_key` | `{wif}` | `imported_key` `{index, pubkey, new}` |
| `dump_key` | `KeyRef` | `dumped` (a WIF) |

The public bundle gains `imported` (the imported keys' public keys, in store order).

**S4's requests (protocol version 1, additive).**

| `op` | body | answer `result` |
|---|---|---|
| `encrypt` | `{passphrase, pq: [[scheme, from, count], …]}` | `wallet_state` `{encrypted, unlocked_until}` |
| `unlock` | `{passphrase, timeout}` | `wallet_state` |
| `lock` | — | `wallet_state` |
| `dump` | `{path, lines: [DumpLine]}` | `written` (the path) |
| `import_dump` | `{path, zkeys}` | `imported_dump` `{keys, pq, builds, recipients, records, skipped_zkeys}` |
| `import_pq` | `{scheme, index?, seed}` | `imported_pq` `{scheme, index, own, pk, added}` |
| `backup` | `{path, facade}` | `written` |
| `sapling_build` | `SaplingBuildRequest` (`z_sendmany`) | `built` (the transaction, hex) |
| `sign` | `SignRequest` with `sapling: SaplingPart` (a YED builder's Sapling part) | `signed` |

`hello` gains `encrypted` and `unlocked_until`. The encrypted store (`signer/src/seal.rs`): the phrase,
and the imported keys, sealed with ChaCha20-Poly1305 under PBKDF2-HMAC-SHA256 (100,000 iterations) of
the passphrase; `public.json` keeps the public bundle (with every PQ key the façade held) so a locked
signer still answers `public` for them, and refuses (`locked`) a key it would have to derive. A
`DumpLine` is `text`, `key` (a WIF before the façade's text), `pq_seed`, `sapling` (the account's
extended spending key) or `recovery` (the phrase). Imported post-quantum keys (`pqimported.json`) are
named `KeyRef::Pq { scheme, index: IMPORTED_PQ_BASE (2^31) + i }`. `yewd-signer restore -from=<backup>
[-salvage]` writes a backup's signer files back and prints the façade's state (yewd runs it at open
for `-wallet`). **The Sapling build** (`signer/src/sapling.rs`): `sapling_build` builds a whole
`z_sendmany` transaction with librustzcash6's builder (P2PKH inputs, the spends with the façade's
Merkle paths checked against the anchor, the outputs, the exact fee); a `sign` request with a
`SaplingPart` builds and proves the Sapling bundle first, makes every transparent digest over the whole
transaction (ZIP-243 with `hashShieldedSpends`/`hashShieldedOutputs`), signs the carrier, template, bond
and coin inputs as without one, then authorizes the spends and the binding signature. A `z_sendmany`
with a post-quantum party (beta2 D-2, D-4, D-5: a PQ from address, whose change returns to it, or a PQ
recipient, which librustzcash's builder cannot pay) takes that `sign` path on the YEC gate, its PQ inputs
signed with the PQ keys over the same digests; every other shape keeps `sapling_build`. `vault_lock`
takes a funding address, `"from"` (beta2 D-3, `wallet/src/lockfrom.rs`): an ECC or post-quantum
address's own coins (change back to it) or a Sapling address's notes (the same `sign` path).

**The attestation equivocation guard** (`signer/src/attest.rs`, ycash6 S16 / EQV-1 self-protection):
`<signer dir>/attest-signed.jsonl`, one record `(seq, key, citedHeight, blockHash, price, sig)` per
line, appended and fsynced before the signature leaves the signer. The same price again returns the
recorded signature (`reused`); another price for the same `(key, citedHeight, blockHash)` is refused
(`equivocation-guard: seq <s> already signed <p> for height <h>`, or `… this key already signed <p>
for height <h> under seq <s>` for another seq of the same key: EQV-1 binds the key); another block
hash at that height (a reorg) is not equivocation; a torn last line is cut off at load. The signer
derives the key, checks it is the attestor record's (`pubkey`, from the node), and computes the
74-byte message itself (`AttestMessage` over the cited block's hash). A cancel co-signature first
resolves its price (the given one, or the one this key signed for `R`; `price-required` when
neither), refuses a statement under which the vault was claimable (`cancel-statement-claimable`,
RED-4), passes the same guard for `(R, price)`, then signs `CancelCosignMessage` recoverably. A
`sign_message` digest is computed from the text with ycashd's magic prefix, so it can never be a
transaction digest. Imported keys live in `<signer dir>/imported.json` (0600; sealed with the seed after `encryptwallet`); a new
import sets the sign-once restore marker (an imported key brings no history, 07/F-5).

## Harness mode (`YEWD_BIN`)

**S1 adds one step for scripts that mine on a pair node (H8), for the harness chunk to take
over** (`qa/s4_contract.py` takes it for every pair: the wallet first, then the backend with its coinbase
address — except a Yellowback-live node that names no `-yellowbackpayoutaddress`, since ycashd takes a P2PKH
`-mineraddress` as its default payout address, F-S4-1): before the backend of node *i* starts, run `YEWD_BIN -datadir=node<i> -conf=ycash.conf
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
   S4 gives `-exportdir`, `-paytxfee`, `-wallet`, `-rescan` meaning (and reads `-salvagewallet`,
   `-developerencryptwallet`, `-paramsdir`); `-keypool`, `-mintxfee`, `-txconfirmtarget`,
   `-walletnotify`, `-spendzeroconfchange` are still reported and ignored. Order does not matter: yewd answers `-28` until the
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
