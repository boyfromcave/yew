# YEW — Your Electronic Wallet

A transparent-only mobile wallet for YEC and Ycash Yellowback (YED): a small Flutter app for iOS
and Android over a small Rust core. YED is the main currency; everything about it comes through
`lightwalletd-dd`'s `YellowbackStreamer`, everything about YEC through the untouched
`CompactTxStreamer` transparent path. No compact-block scanning, nothing shielded, and no
transaction byte is ever built outside the Rust core.

Plan: `docs/plans/yellowback-wallet-plan.md` in the `yellowback-workspace` repository (this repo
is mounted there at `yew/`). Status: **Phase W2 done** (YED tokens, TRANSFER, the full broadcast
gate, history labels, `yew-cli send-yed`, the armed-devnet acceptance) on top of W1 (keys,
transactions, YEC send); W3 (the app) next. Nothing here is a release; the app is the W0a scaffold.

## Layout

```
Cargo.toml          Rust workspace: core (yew-core) and core/cli (yew-cli)
core/               the core (module table below)
core/cli/           yew-cli, the developer's and the devnet tests' driver
core/tests/         vectors.rs (node-generated vectors), devnet.rs (w1_*, w2_*; YEW_DEVNET=1, ignored otherwise)
core/tests/vectors/ node-generated vectors from `yellowback-devnet vectors` (Phase W0c)
app/                Flutter project yew_app (org cash.ycash.yew; iOS + Android)
proto/              service.proto, compact_formats.proto, yellowback.proto + PIN (lightwalletd-dd commit)
scripts/            check-proto-pin.sh, check-deps.sh + allowed-deps.txt, devnet-w1.sh, devnet-w2.sh,
                    build-core-ios.sh, build-core-android.sh, gen-bridge.sh
.github/workflows/  ci.yml
```

## Core modules (plan §3.1, §3.6)

| Module | Phase | Status | Translated from / verified against |
|---|---|---|---|
| `params.rs` | W1 | done | `ycash-dd/src/chainparams.cpp`, `src/yellowback/params.{h,cpp}`, `src/primitives/transaction.h`; fee citations below |
| `keys.rs` | W1 | done | BIP39 (`bip39`), BIP32 over `hmac`/`sha2` (no extra crate), `m/44'/347'/0'/{0,1}/i` (D-W-7), `s…`/`ye…`/`yt…`/`yr…`, WIF (D-W-11). Tests: BIP32 vector 1, BIP39 TREZOR vector, `addresses.json` |
| `script.rs` | W1 (P2PKH/P2SH), W4 (vault, carrier) | W1 done | `CScript` push encoding (`ref/ycash/src/script/script.h`), `ycash-dd/src/yellowback/script.cpp` `GetPushes` |
| `tx.rs` | W1 | done | v4 serializer/parser (`transaction.h:575-640`), ZIP-243 (`qa/rpc-tests/test_framework/script.py` `SignatureHash`), RFC 6979 signing. `transparent.json`: 12 node transactions reproduced byte-for-byte (unsigned, every sighash, signed, txid) |
| `net/tls.rs`, `net/compact.rs` | W1 | done | `Server`, TLS (`rustls`, native roots) or `--plain`; `GetLightdInfo`, `GetLatestBlock`, `GetAddressUtxos` (paged), `GetTaddressTxids` (stream), `GetTaddressBalance`, `SendTransaction` |
| `net/yellowback.rs` | W2 | done | every `YellowbackStreamer` method (streams collected); `probe()` = contract rule 1 (`UNIMPLEMENTED` ⇒ absent, unknown `rpcversion` ⇒ refused, `enabled && active`); `FAILED_PRECONDITION` ⇒ `NetError::Node { identifier, message }` |
| `payload.rs` | W2 | done | `ycash-dd/src/yellowback/payload.{h,cpp}`: `"YB"‖0x03‖type`, all seven types encode/decode, `find_payload`; `templates.json` payloads reproduced both ways |
| `coinselect.rs` | W2 | done | `ycash-dd/src/yellowback/coinselect.{h,cpp}` verbatim (EXACT/SINGLE/GREEDY/SEARCH/BURN, `NearestWorkable`, budget 200,000); `src/test/yellowback_coinselect_tests.cpp` tables ported row for row; equals `yed_estimatesend` input-for-input on the devnet |
| `build/yed_transfer.rs` | W2 | done | `txbuilder.cpp:1213-1290` `BuildTransfer`: YED inputs, `TOKEN_VALUE` outputs, TRANSFER payload, YEC fee from `FEE_RESERVE` then `YEC`, one change address; refusals carry the node's identifiers (`change-floor` with the alternatives) |
| `store.rs` | W1, W2 | done (schema v2; v1 files migrate in place) | meta, addresses, utxos+class+cents, locks, history+labels, own_outputs, own_tokens, spent_tokens, pending_txs, imported_keys (wrapped) |
| `coins.rs` | W1 (YEC), W2 (YED) | done | classes of §3.7; `SelectYec` from `txbuilder.cpp:399-420`; fee reserve; `classify` (TOKEN from `GetAddressTokens` only, else HELD for `TOKEN_VALUE`); `pre_lock` from `wallet.cpp:410-427`; `ranked_tokens` from `txbuilder.cpp:501-510` |
| `sync.rs` | W1 (YEC), W2 (YED) | done | §3.2 loop: gap-limit derivation, `GetTaddressTxids` history, `GetAddressUtxos` set, `GetAddressTokens` set, classification, PENDING_TOKEN rows, lock release, `GetTxInfo` labels (`label_for`, from `yellowbackmodels.cpp`), `GetPrice.pMint` |
| `build/yec_send.rs` | W1 | done | YEC send with change, fee `FEE_ZAT`, `nExpiryHeight = tip + 40`, the `TOKEN_VALUE ± 1 zat` rules; `broadcast` runs both gate layers |
| `gate.rs` | W1 (YEC path), W2 (full) | done | D-W-5: local classes per path + `ValidateRawTransaction` (`valid && verdict == "ok" && burned == 0 && !wouldBeRejected`), no override; `Validator` built only by probing; property test on 2,000 random coin sets, both paths |
| `wallet.rs` | W1, W2 | done | key ring + store + network; `balances()` (§3.4 shape), `dollars()`; not in the plan's file list (added: the object `sync`, the builders and W3's `api.rs` share) |
| `bundle.rs`, `build/{mint,redeem,claim}.rs`, `api.rs` | W3–W4 | stubs | |

### The fee (plan §7 W1, first task)

`FEE_ZAT = 1_000` zat, the node's flat fee: `ycash-dd/src/yellowback/params.h:79`
`DEFAULT_YELLOWBACK_FEE = 1000` ("equals policy DEFAULT_FEE", `src/policy/fees.h:15`), the floor of
`-yellowbackfee` (`src/init.cpp:1186-1189`), what every node-built template pays
(`src/yellowback/txbuilder.cpp:338`), and `src/wallet/wallet.h:265` `DEFAULT_TRANSACTION_MINFEE =
1000`. The relay floor is `src/main.h:68` `DEFAULT_MIN_RELAY_TX_FEE = 100` zat/kB. Confirmed on
the devnet: `yed_getinfo` → `params.feeZat = 1000`, and `params.json` from the W0c vectors.
`RESERVE_MIN = 105_000` zat = `5 · (FEE_ZAT + 2 · TOKEN_VALUE)`, so the reserve formula's two
terms are equal at the default fee.

### Rules recorded in W1 (plan §3.7)

- **HELD** (W1 form): an own P2PKH output of exactly `TOKEN_VALUE` (10,000 zat) cannot be told
  from a YED token locally, so it is class `HELD` and unspendable. W2 narrows it (below).
- **Fee reserve refinement**: outputs are reserved smallest-first up to the target, but an output
  larger than the whole reserve is never reserved (a one-coin wallet would otherwise show
  "available 0"). When the reserve is short, a YED operation takes its fee from class `YEC`.
- **`TOKEN_VALUE` avoidance**: a send of exactly 10,000 zat pays 10,001; a change of exactly
  10,000 becomes 9,999 (the zat goes to the fee). Change under 100 zat folds into the fee.
- **Imported keys** are stored wrapped under a key derived from the seed (HMAC-SHA256 keystream),
  not in the clear; W3 moves them to the platform keystore with the seed.
- The node's plain wallet RPCs (`sendtoaddress`, `validateaddress`) take the `s…` form; the
  `ye…` form is for the `yed_*` RPCs. `yew-cli address` prints both.

### Rules recorded in W2 (plan §3.7, D-W-5, D-W-8)

- **TOKEN has one source.** `GetAddressTokens` (the node's `yed_listtokens`, whoever holds the
  keys) decides the TOKEN class and its cents; nothing local does. An own P2PKH output of
  exactly `TOKEN_VALUE` that the server does *not* list stays **HELD**, never YEC: it may be a
  VOID mint's `vout[1]`, a transaction the index has not digested, or a server without
  Yellowback, and spending it as YEC could burn. Spent tokens are never listed (IN-1 erases
  them), so the wallet keeps `own_tokens` / `spent_tokens` itself to value a spend in history.
- **PENDING_TOKEN** is written at broadcast by the `PreLock` rule (MINT ⇒ `vout[1]`,
  TRANSFER/REDEEM ⇒ the payload's own assignments) and re-derived from the pending record at
  every sync; it is "pending YED", in neither balance, until the server lists it (TOKEN) or the
  transaction confirms without it (HELD). Locked outputs (inputs of an own unconfirmed
  transaction) are in neither balance either; YEC change of such a transaction is "YEC pending".
- **The gate has two layers and no override.** Local: every input is a known unspent output of
  a class the path may spend (YEC path: `YEC`/`FEE_RESERVE`; transfer path: those plus `TOKEN`),
  no payload on the YEC path, exactly one decodable TRANSFER payload and at least one token on
  the transfer path. Remote: `ValidateRawTransaction` on the same bytes, `valid && verdict ==
  "ok" && burned == 0 && !wouldBeRejected`, the node's verdict in the error. A plain YEC send is
  validated too (the node answers `ok` for a non-Yellowback transaction). The `Validator` is
  built only by probing the server; on a server without the service the YED path is refused
  and the YEC path runs on the local layer (nothing can be TOKEN there, so every `TOKEN_VALUE`
  output is HELD and already refused).
- **Labels come from verdicts.** Every confirmed own transaction that carries an `OP_RETURN` or
  spends an own token is labelled from `GetTxInfo` (`minted $`, `sent $` / `received $` /
  `self-transfer`, `VOID mint (verdict)`, `redeemed`, `burned $`, `expired`); the local payload
  is read only for the pending label of a transaction this wallet itself broadcast, and for
  `PreLock`. A `tx-not-found` marks the row "payload, not yellowback".
- **YED selection is the node's.** `coinselect.rs` is `coinselect.cpp` verbatim over coins
  ranked `(cents, txid bytes, vout)`; on the devnet the wallet's answer equals
  `yed_estimatesend` input-for-input, stage, change and alternatives on 100 random targets over
  three coin sets. A TRANSFER's YEC comes from `FEE_RESERVE` then `YEC`, smallest first; surplus
  token value (more tokens in than out) returns as YEC change, as the node does.
- **The armed devnet has no heartbeat and node 0's blocks are untagged.** Every block of the
  acceptance is mined on a pool node (2-4, round-robin, after the transaction reached the
  pools' mempools) with the pools re-quoted first (`yellowback-devnet price 50`): a stale quote
  makes the pool tag its block `signal` only, the price windows drain, and `yed_mint` fails
  `mintpol-no-price`. The mint reads the price at `tip - refLag`, so the warm-up holds until
  `GetPrice(tip - 2).pMint` is defined. `yed_mint … wait=false` returns after the carrier; one
  pool block confirms it, the node's wallet then broadcasts the MINT by itself, one more block.
- **`getreceivedbyaddress` counts token value**: an address holding 0.5 YEC and one YED output
  reports 0.5001, the 10,000 zat of the token included.
- Node 1 of the armed devnet is the stock node (no `-yellowback`), so the key round trip uses
  node 5 (an attestor node with the wallet layer): `importprivkey … true` → `dumpprivkey` equals
  `export-wif`, `yed_getbalance` grows by the address's cents, `yed_listunspent` lists the token,
  `yed_send` moves it.

### Rules recorded in W4 (plan §3.7 VAULT / CARRIER, §4 rules 5 and 6, §5.3, §8.6, §8.7)

- **The two-step state machine is a table, not a process.** A mint or claim is a `mints` row
  (`schema v3`) from the moment its carrier is broadcast: `CARRIER_SENT → CARRIER_CONFIRMED →
  MAIN_SENT → DONE`, or `→ LAPSED → SWEEP_SENT → SWEPT`, or `→ FAILED` (the carrier's own
  funding expired unconfirmed). The row holds everything the main step needs (the bundle, the
  carrier key hash, `R`, the fee and attestor payees, the vault facts for a claim), so a wallet
  file closed mid-mint and reopened finishes from where it was. **Only the sync loop advances a
  row**, from what the history scan saw (the carrier confirmed, the main transaction confirmed,
  the window `R + REF_WINDOW` closed, the sweep confirmed); the app's steps (`mint_start`,
  `mint_finish`, `mint_sweep`) refuse a row that is not in the state they need. The window is
  open while `tip + 1 + TX_EXPIRING_SOON_THRESHOLD(3) <= R + REF_WINDOW`, the node's
  `CheckExpiry`; a `CARRIER_CONFIRMED` row past it is `LAPSED`.
- **VAULT and CARRIER are synthesised, never scanned.** `GetAddressUtxos` lists own-address
  P2PKH outputs only; a vault or a carrier is a P2SH output, so the sync loop adds them from
  its own tables: every open own vault (`vaults`, refreshed from `GetVault` for every mint row
  and every history row the server labelled `mint`, kept when `HASH160(ownerPubKey)` is an own
  key — a restore from seed finds its vaults this way) and every row that holds an unspent
  carrier. Both are locked to their flows by the gate and are in neither balance.
- **The gate has a path per template** (still two layers, still no override): carrier funding
  (`YEC`/`FEE_RESERVE` in, `vout[0]` a P2SH of `CARRIER_VALUE`, no payload); mint (those plus
  exactly one `CARRIER` as `vin[last]`, one MINT payload); redeem (the own `VAULT` at `vin[0]`,
  `TOKEN`s, a REDEEM payload, no carrier); release of a VOID vault (the vault alone, no
  payload); claim (the *named* foreign vault at `vin[0]` — it is nobody's UTXO here — then
  `TOKEN`s and the carrier last, a REDEEM payload); sweep (`CARRIER`s only, no payload). YEC
  never enters a vault spend: the fee comes from the vault (spec §3.5).
- **The bundle is verified before the carrier is funded** (plan §4 rule 6): shape, count in
  `[1, BUNDLE_MAX]`, every `seq` seated in `ListAttestors` and unique, every compact signature
  under that seat's key over `SHA256("YBATTEST1" ‖ seq ‖ price ‖ citedHeight ‖ blockHash)` with
  the block hash from `GetBlock` (internal order) — high-S refused, never normalised (R17). A
  bundle with one mutated byte is refused naming the attestor and height. Freshness and the
  price range are the node's rules and are judged by its dry run.
- **The node's templates reproduce byte-for-byte** (plan W4 acceptance, `tests/vectors.rs`
  `w4_templates_…`): the vault script and its P2SH hash, the carrier script and its hash, the
  carrier scriptSig `<bundle> <sig> <carrierScript>` push encoding, the MINT `vout` order
  (vault, token, payload, pool fee, attestor fee, change), the MINT and REDEEM payload bytes,
  the REDEEM plan (collateral, fee, payload; `nLockTime = lockHeight`, `vin[0].nSequence =
  0xFFFFFFFE`, `nExpiryHeight = R + REF_WINDOW`). Both node signatures (owner and carrier)
  verify under the core's ZIP-243 digests. Differences kept: the carrier and owner keys are the
  next unused change / external HD keys; the YEC side selects `FEE_RESERVE` then `YEC`; the
  collateral is `max(requiredZat, 4·feeMin)` rounded up to 1,000 zat exactly as `BuildMint`
  does (`yed_estimatecollateral.requiredZat` is *not* rounded); the attestor payee is the
  node's `DefaultAttestPayee` pick (`SHA256(blockHash(R) ‖ selector ‖ "A") mod |A|`) — AFEE-1
  accepts any `seq` of the bundle; the fee payee is `GetFeePayee.preferred`, else
  `default.payoutAddress`, else FEE-0.
- **Plan §8.7 (bundle push size)**: the largest bundle is `4 + 74·6 = 448` bytes, inside
  `MAX_SCRIPT_ELEMENT_SIZE = 520`; the push is `OP_PUSHDATA2` for four or more attestations,
  `OP_PUSHDATA1` below, exactly `CScript << bundle`; `carrier_script_sig` refuses a larger
  element. The node-built vector (three attestations, 226 bytes) confirms the encoding.
- **A claim takes the node's numbers at the tip.** `ListClaimable` names the vault, its
  `claimPath`, `feeZat`, `attestFeeZat` and `residualZat` (RED-5, paid to `P2PKH(ownerPubKey)`);
  `R` is the index tip; the bundle is for `outpointSelector(vault)` (txid internal bytes ‖ vout
  LE32). The wallet's YED must cover `mintedCents` before the carrier is funded; the BURN stage
  (a sub-dollar remainder) is allowed on redeem and claim, never on a transfer.
- **A redeem or claim burns by design, and the remote gate knows how much.** The W2 remote rule
  `burned == 0` refused the first devnet redeem (`valid, ok, burned 10000`): `gate::accept` now
  takes the *planned* burn — `0` on every path but redeem and claim, where `confirm_burning`
  passes the plan's `burn_cents` (the debt plus any sub-dollar remainder). Any other burn, more
  or less, is still refused with the node's numbers.
- **Plan §8.6 (open question 6) — answered on the devnet, no node change needed.** After
  `importprivkey <ownerWIF> … true` on node 5, `yed_listvaults` lists the yew-minted vault,
  `yed_getbalance` counts the address's YED, `yed_redeem` before `lockHeight` is refused
  `vault-locked: the vault is locked until height N (tip T)`, and at `lockHeight` node 5's
  `yed_redeem` builds, signs and broadcasts the owner-path redeem (`burnedCents 10000`,
  `collateralOut 950009000`); the yew side then sees the vault `CLOSED` at the next sync.
  The node recognises the vault by the owner pubkey, exactly as the question hoped.
- **Lightwalletd plan Q6 (the armed carrier path) and §8.7, as seen on the wire.** The claim's
  carrier scriptSig on the devnet is 373 bytes: `OP_PUSHDATA1` (0x4c) of the 226-byte bundle
  (three attestations), the DER signature, then the carrier redeem script; the node accepted
  every carrier spend (mint, resumed mint, claim) with verdict `ok` and the lapsed carrier's
  sweep too. Nothing in the light path needed the node's wallet.
- **Devnet funding comes from a pool node.** Node 0's YEC is what its own mints and the W2
  acceptance left (a few YEC); the acceptance funds its wallet from node 2 (mature coinbase).
- **Sweeping is explicit.** The sync loop marks a row `LAPSED`; `mint_sweep` builds the
  one-input sweep (`CARRIER_VALUE − FEE_ZAT` to a fresh change key) and `yew-cli sync` runs it
  for every lapsed row. The node answers `ok` to the sweep's dry run (a non-Yellowback
  transaction with a carrier-shaped input and no payload).

## Toolchain

| Tool | Version | Pinned in |
|---|---|---|
| Rust (stable) | `1.92.0` | `rust-toolchain.toml` |
| Flutter | `3.47.5` (stable) | `app/pubspec.yaml` `environment.flutter`, CI |
| Dart SDK | `3.13.4` | `app/pubspec.yaml` `environment.sdk` (exact lower bound) |
| flutter_rust_bridge (crate + codegen) | to pin (Phase W3; feature `bridge` is the placeholder) | `core/Cargo.toml`, `app/pubspec.yaml` |
| Android NDK | `28.2.13676358` | `app/android/app/build.gradle.kts` |
| protoc | any `>= 3.x` on PATH (`36.1` used) | `core/build.rs` (not vendored) |
| Minimum iOS | 15.0 | `app/ios/Runner.xcodeproj` (`IPHONEOS_DEPLOYMENT_TARGET`); `Podfile` once CocoaPods generates it |
| Minimum Android | API 24 (Flutter default) | `app/android/app/build.gradle.kts` (`flutter.minSdkVersion`) |

Rust targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-linux-android`,
`x86_64-linux-android`, plus the host for `yew-cli` and tests. Direct Rust dependencies are the
allow-list of plan §3.3 (`scripts/allowed-deps.txt`); versions are pinned exactly (`=x.y.z`).
`yew-cli` has no argument-parsing crate for that reason.

## Build and test

```bash
cargo build && cargo test --workspace   # core + cli + node vectors (needs protoc on PATH)
cargo run -p yew-cli -- version
scripts/check-proto-pin.sh           # protos identical to ../lightwalletd-dd/walletrpc (skips if absent)
scripts/check-deps.sh                # direct deps ⊆ allow-list
(cd app && flutter test && flutter analyze)
scripts/build-core-ios.sh            # → app/ios/Frameworks/YewCore.xcframework (Xcode)
scripts/build-core-android.sh        # → app/android/app/src/main/jniLibs (cargo-ndk + NDK)
scripts/gen-bridge.sh                # flutter_rust_bridge codegen (Phase W3)
```

`core/tests/vectors.rs` reads `core/tests/vectors/*.json`. `ywallet_derivation_vector` is
`#[ignore]`d while `ywallet.json` says `"pending": true` (the `[owner]` Ywallet capture, plan
D-W-7); run it with `--ignored` once the file is filled.

## `yew-cli`

```
yew-cli [--server host:port] [--plain] [--wallet PATH] [--network regtest|testnet|mainnet]
        [--seed-file PATH | YEW_SEED="<mnemonic>"] [--passphrase P | YEW_PASSPHRASE=P] [--birthday H]
        status | yed-info | price | address [--new] | balance | sync | coins
        | send-yec <addr> <zat> [--all] | send-yed <addr> <cents> [<addr> <cents> ...]
        | export-wif <addr> | import-wif <wif> | history | version
        | mint-estimate <cents> <lockBlocks> | mint-start <cents> <lockBlocks>
        | mint-status [<id>] | mint-finish <id> | mint-sweep <id>
        | vaults | redeem <vaultTxid> | claimable | claim <vaultTxid>
```

Defaults: `127.0.0.1:9067`, TLS on (`--plain` is refused on mainnet), `yew-wallet.sqlite`,
`regtest`. Every command that talks to the server probes `GetYellowbackInfo` first (contract
rule 1); `status` and `yed-info` print what it found, `price` the display price (`pMint`).
`balance` shows YED, pending YED, the price, YEC available / reserved / pending and any HELD
outputs; `coins` is the debug listing of every UTXO with its class, cents and lock; `history`
shows the verdict-derived labels. `send-yec` and `send-yed` sync, build, run both gate layers,
broadcast, lock the inputs until the transaction confirms or its `nExpiryHeight` passes;
`--all` lets a YEC send spend the fee reserve; `send-yed` takes `ye…`/`yr…`/`s…` addresses and
cents (up to 14 recipients).
`import-wif` adds a YecWallet/`ycashd` key outside the HD tree (not covered by the seed);
`export-wif` is byte-identical to `dumpprivkey` (checked on the devnet).
W4: `mint-estimate` prints the collateral, fees and whether the wallet can afford both steps;
`mint-start` funds the carrier and prints the mint id; after one block, `sync` (any syncing
command) advances the row and `mint-finish <id>` sends the MINT; `mint-status` lists the rows;
`vaults` the own vaults with their status; `redeem <vaultTxid>` the owner-path spend at or past
`lockHeight` (a VOID vault is released); `claimable` the liquidator's list; `claim <vaultTxid>`
starts the two-step claim (finished with `mint-finish`); `sync` sweeps every lapsed row,
`mint-sweep <id>` one by hand.

## Devnet acceptance (plan §6.3, §7 W1 and W2)

`scripts/devnet-w2.sh` runs the W2 acceptance on the **armed** devnet the W0c vectors came from
(`YELLOWBACK_DEVNET_DIR=~/yb-devnet-w0c`, `YELLOWBACK_DEVNET_PORTSEED=9`, `lightwalletd-dd
--yellowback` on `127.0.0.1:9267`, plain HTTP/2):

```bash
scripts/devnet-w2.sh up       # yellowback-devnet up (armed) + lightwalletd start --port 9267 --extra=--yellowback
scripts/devnet-w2.sh lwd      # (re)start only the lightwalletd on a running devnet
scripts/devnet-w2.sh test     # YEW_DEVNET=1 cargo test -p yew-core --test devnet -- --ignored w2_
scripts/devnet-w2.sh status / down [--wipe]
```

`w2_yed_tokens_transfer_gate_and_key_round_trip` (2026-09-24, 39 s): the service probes as
rpcversion 3, enabled and active; `yed_mint 100000 48` on node 0 (carrier, pool block, MINT,
pool block) confirms with verdict `ok`; node 0 sends 1 YEC and $50.00 to wallet A — nothing
before the block, TOKEN $50.00 and `received $50.00 / ok` after; A sends $12.34 to wallet B —
the $37.66 change is PENDING_TOKEN and `sending $12.34` until the block, then `sent $12.34`
on A and `received $12.34` on B, the node holds exactly the bytes the core built; a TRANSFER
assembled with an assignment of $99.99 over a $37.66 input passes the local layer and is
refused by the node's dry run with verdict `transfer-over-assigned`, nothing broadcast; $37.16
from a $37.66 coin is refused `change-floor` with alternatives 3666 / 3766; `coinselect.rs`
equals `yed_estimatesend` on node 0 input-for-input (stage, inputs, selected, change,
alternatives) on 100 random targets over three coin sets (node 0's, then split twice by
`yed_sendmany`); B's key exported as WIF, imported on node 5 with rescan: `dumpprivkey` equals,
`getreceivedbyaddress` 0.5001, `yed_getbalance` +1234, `yed_listunspent` lists the token,
`yed_estimatesend` on node 5 reports the same change-floor alternatives the core computes, and
node 5's `yed_send` moves the $12.34 back to A (B labels it `sent $12.34`); a YEC send from A
(holding tokens) spends only `YEC`/`FEE_RESERVE` inputs and passes the node's dry run. Offline:
56 unit tests (the gate property test on 2,000 random coin sets for both paths, the builder
property test on 1,000 random wallets, the node's coinselect tables), the template payload
vectors, the schema migration.

`scripts/devnet-w4.sh` runs the W4 acceptance on the same armed devnet (it finds the workspace
by walking up to `repos.yaml`, so it works from a git worktree too):

```bash
scripts/devnet-w4.sh test     # YEW_DEVNET=1 cargo test -p yew-core --test devnet -- --ignored w4_
```

`w4_mint_resume_lapse_redeem_import_and_claim` (2026-09-25, 271 s): wallet A is funded 40 YEC
from pool node 2 (node 0 holds only a few YEC after its own mints); `mint_estimate` of $100.00
for 48 blocks answers collateral 10 YEC, fee 0.5 YEC, attestor fee 0.125 YEC, bundle seqs
`[0, 1, 2]`, affordable; `mint_start` funds a `scripthash` carrier of `CARRIER_VALUE` and
`mint_finish` before its block is refused `WrongState`; after one pool block the sync advances
the row to `CARRIER_CONFIRMED` and lists the `CARRIER` UTXO, `mint_finish` sends the MINT
(verdict `ok`, type `mint`, the carrier at `vin[last]`), the $100 is PENDING_TOKEN until the
next block, then TOKEN, the row is `DONE`, `vaults` lists the vault `ACTIVE` with the node's
`lockHeight`/`claimHeight`, the `VAULT` UTXO is synthesised, the carrier is gone, the node
holds our bytes and the history row reads `minted $100.00`. A second mint is started, the
wallet dropped and reopened from the file (`CARRIER_SENT` survives), synced and finished
(`ok`). Its owner key goes to node 5 by `importprivkey … true` (plan §8.6). A third mint is
left unfinished: a bundle with one flipped signature byte is refused `bundle-refused:
signature …` (the intact one verifies), the pools mine past `R + REF_WINDOW`, the sync marks
the row `LAPSED`, `mint_finish` is refused, `mint_sweep` returns `CARRIER_VALUE − FEE_ZAT`
(verdict `ok`, type `none`) and the row ends `SWEPT`. Vault 1 is redeemed at `lockHeight`
(`nLockTime = lockHeight`, `nExpiryHeight = R + REF_WINDOW`, verdict `ok` path `owner`,
`burned 10000`), the vault is `CLOSED`, 9.50009 YEC of collateral returns as YEC and the row
reads `redeemed, burned $100.00`. The liquidator: node 0 sends A $100, `price --shock=-80%`,
pool blocks until `ListClaimable` names node 0's oldest ACTIVE vault (claimHeight 327, path
`a`, `pClaim` $10, claimant 9.37499 YEC), `claim` funds the carrier, `mint_finish` sends the
claim (`nLockTime = claimHeight`, the vault at `vin[0]`, the carrier last, verdict `ok` path
`claim` type `redeem`), the node marks the vault `CLAIMED` with our txid, A's YED falls by
the debt and its YEC grows by the collateral. The devnet is left at `price 50` (the windows
refill as the pools mine).

`scripts/devnet-w1.sh` runs a private regtest devnet so the default one is never touched:
`YELLOWBACK_DEVNET_DIR=~/yb-devnet-w1`, `YELLOWBACK_DEVNET_PORTSEED=57`, `lightwalletd-dd` on
`127.0.0.1:9167` (plain HTTP/2).

```bash
scripts/devnet-w1.sh up       # yellowback-devnet up --no-attest --lean + lightwalletd start --port 9167
scripts/devnet-w1.sh test     # YEW_DEVNET=1 cargo test -p yew-core --test devnet -- --ignored
scripts/devnet-w1.sh status
scripts/devnet-w1.sh down [--wipe]
```

`core/tests/devnet.rs`: a fresh wallet syncs to zero, is funded 1.5 YEC from node 0, syncs, sends
0.5 YEC back (the node holds exactly the bytes the core built, `getreceivedbyaddress` agrees),
locks release on confirmation, and a restore from the same seed into a fresh database reproduces
the balance and UTXO set. Not part of CI (nightly on the owner's machine, plan §6.4).

## Trust statement

_Placeholder (plan §3.5, client contract rule 7)._ YEW trusts the light-client server it is
connected to for what it reports about the chain and about YED (verdicts, token sets, prices);
the server cannot spend your funds, and your keys never leave the device. The final text is
written in Phase W3 and shown once on first launch and from Settings.

## License

MIT, see `LICENSE`.
