# YEW — security review of the core and the app (Phase W5)

_Plan: `docs/plans/yellowback-wallet-plan.md` §7 W5, D-W-5, D-W-6, D-W-11, §3.5. Reviewed at
`yew` `29e1ae4` (W4 delivered); the fixes below are the W5 commits that follow it. Severity:
**High** = funds or the seed at risk from a remote party; **Medium** = at risk from a
local attacker (device access, backup, memory) or a wrong assumption in the plan; **Low** =
hardening; **Info** = a property worth recording. Every finding says what was done._

## Summary table

| Id | Area | Finding | Severity | Status |
|---|---|---|---|---|
| S-1 | seed and keys | Nothing was wiped: the 64-byte seed, HMAC outputs, WIF payloads, the bridge's mnemonic / passphrase / WIF strings and the wrap key all stayed in freed memory | Medium | **fixed** (`keys::wipe`, `SecretString`, `Drop` on `ExtendedPrivKey` / `AddressKey` / `WrapSecret`, `bip39/zeroize`) — residual copies recorded |
| S-2 | gate | Every `SendTransaction` is behind both gate layers; no `cfg(test)` / feature bypass | Info | verified (call-site table below) |
| S-3 | TLS | `plain` was refused on mainnet only; the plan says "TLS required outside regtest" — testnet accepted plain | Medium | **fixed** (`Server::parse_for`: regtest only, core and CLI; the app's switch shows on regtest only) |
| S-3b | TLS | No certificate pinning setting | Low | **fixed in the core** (`Server::ca_pem`, `yew-cli --ca-pem`): a PEM trust anchor that replaces the system roots; a SHA-256 fingerprint pin is not possible without `rustls` as a direct dependency (allow-list) — recorded. App setting deferred (needs a bridge parameter and a Settings field) |
| S-3c | TLS | The host part of `host:port` was not validated; `/`, `?`, `@`, `#` or spaces could reshape the URI | Low | **fixed** (DNS name, IPv4 or `[IPv6]` only) |
| S-4 | server trust | Which answers are acted on without a local check | Info | recorded (table below); matches the trust statement |
| S-5 | storage | The SQLite cache was created `0644 & ~umask`; it holds the address list, history and the wrapped imported keys | Low | **fixed** (`0600` on Unix at every open) |
| S-5b | storage | "Rebuild from chain" (delete the file, restore from seed) loses the imported keys **and any mint / claim between its carrier step and its main step**: the carrier is P2SH, `GetAddressUtxos` never lists it, and without the `mints` row the wallet cannot finish or sweep it (`CARRIER_VALUE` stranded) | Medium | **deferred**: the app never deletes the file by itself, "Forget this wallet" is the only path and it warns; a recovery (scan own history for carrier fundings and rebuild the row) is a W6 item. Recorded in the README |
| S-6 | app / Android | `allowBackup` was the default (`true`): the keystore ciphertext and the SQLite cache went into device / cloud backups | Low | **fixed** (`allowBackup=false`, `fullBackupContent=false`, `dataExtractionRules` excluding everything) |
| S-7 | bridge boundary | What Dart passes and what the core checks | Info | verified (table below); no gap found beyond S-3c |
| A-1 | app / keystore | Seed and passphrase in `flutter_secure_storage`: iOS `first_unlock_this_device` (non-migrating); Android AES-GCM under an Android Keystore key. The "device unlock" toggle is an app-level `local_auth` prompt, **not** a keystore-bound requirement: a process with the app's sandbox access reads the seed without biometrics | Medium | **deferred** (owner decision): `AndroidOptions(enforceBiometrics: true)` / iOS `accessControl` bind the key to the biometric and change the UX (a prompt on every unlock, loss on biometric re-enrolment); recorded in `docs/release.md` §7 |
| A-2 | app / logging | The seed is never logged or `Debug`-printed: no `print` / `debugPrint` / `log` under `lib/` names it; the core's error strings never include a mnemonic (`bip39` errors carry an index, not a word); the core itself has no `log` dependency. But `init_app` called the bridge's `setup_default_user_utils`, which (the crate's `log` feature is on by default) installs a **Trace-level console logger** — every dependency's records (h2 frames, rustls handshakes, server hosts) would reach logcat / os_log in release builds | Low | **fixed**: `init_app` calls `setup_backtrace()` only |
| A-3 | app / screenshots | No `FLAG_SECURE`: the recovery phrase and the WIF could be screenshotted, screen-recorded or shown in the app switcher | Low | **fixed on Android** (`MethodChannel cash.ycash.yew/screen`, `MainActivity.kt`, on the seed, export and import screens). iOS has no flag; an app-switcher blur is deferred (unverifiable without Xcode) |
| A-4 | app / clipboard | The WIF screen has a Copy button (the user's action); the seed screen has none; nothing copies by itself. On Android < 13 the clipboard is readable by other apps | Low | accepted; the WIF warning text stays |
| A-5 | app / semantics | The seed words are `Chip` labels: an accessibility service (screen reader) can read them. No `ExcludeSemantics` | Low | accepted: a blind user needs them read; the screen is behind the device prompt |
| A-6 | app / telemetry | No crash reporter, analytics or network plugin: the only network user is the core's gRPC (`INTERNET` permission) | Info | verified; documented in `docs/release.md` §6 |
| A-7 | app / passphrase | The BIP39 passphrase is stored in the keystore beside the seed so unlock needs no typing; the passphrase therefore adds nothing against a keystore compromise, only against a seed-only backup thief | Info | recorded (by design; the backup screen says the phrase alone restores only without a passphrase) |

## S-1 — where the seed and the keys live

**Before.** `Wallet::open` derived the 64-byte seed on the stack, the account `xprv` from it,
and dropped everything without overwriting. `bip39::Mnemonic` was built without its `zeroize`
feature. The bridge hands `create_wallet` / `unlock` / `import_wif` plain `String`s, freed
untouched. `secp256k1::SecretKey` is `Copy` and has no drop-time erasure of its own (it offers
`non_secure_erase`). `store::wrap_key`'s unwrapped secret `Vec` and the WIF payload `Vec` were
dropped as they were.

**Now** (`core/src/keys.rs`, `wallet.rs`, `api.rs`):

- `keys::wipe(&mut [u8])`: volatile zero writes plus a compiler fence. No `zeroize` crate is
  added (plan §3.3 allow-list); `zeroize` is already in the tree through `rustls`, which is why
  enabling `bip39`'s `zeroize` feature costs nothing — the `Mnemonic` now wipes its word
  indices on drop.
- `keys::SecretString`: an owned `String` wiped on drop, never `Debug`-printed. The bridge's
  mnemonic, passphrase and WIF strings are wrapped in it on entry (`create_wallet`, `unlock`,
  `check_seed_words`, `import_wif`).
- `Wallet::open` wipes the seed array after `from_parts` (success or failure).
- `ExtendedPrivKey::master` / `child` copy the HMAC output into an array and wipe it, and wipe
  the hardened-path copy of the parent key. `impl Drop for ExtendedPrivKey` wipes the chain
  code and `non_secure_erase`s the key; `impl Drop for AddressKey` erases its key.
- `WrapSecret` (the imported-key wrapping key, `HMAC-SHA256("yew-wrap", seed)`) is wiped on
  drop; `key_for_hash` and `import_wif` wipe the unwrapped / to-be-wrapped 32 bytes.
- `encode_wif` / `decode_wif` wipe the payload.

**What stays in memory, and for how long.** While a wallet is unlocked: the account key
`m/44'/347'/0'` (`KeyRing`) and the wrap key, for the whole session — D-W-6 says "derived keys
in memory only", and this is the minimum for signing without the seed. Address keys are
derived per use (`key_for_hash`) and dropped with the transaction. The seed itself exists
only inside `Wallet::open`. `lock()` drops the handle (all of the above).

**Residual, accepted.** (a) Rust may copy a `[u8; N]` or a `SecretKey` (it is `Copy`) into a
register or another stack slot the wipe does not see; the wipe guarantees the *allocation we
own* is cleared, nothing more. (b) The Dart side: the seed is a Dart `String` (immutable,
garbage-collected, not wipeable) from the keystore read until the bridge call returns; the
generated mnemonic comes back from `create_wallet` once, by value, and is stored by the app
(D-W-6). (c) `flutter_rust_bridge`'s own decode buffer for a `String` argument is the bridge's
allocation, freed unwiped. A memory dump of the running app therefore reveals the account
`xprv` and the wrap key (always), the seed words (around unlock), and any address key in use.

## S-2 — the gate: every broadcast, proven

`send_transaction` (`net/compact.rs:237`) has exactly these callers in `core/src`
(`grep -rn send_transaction core/src`), and nothing under `core/cli`, `core/tests` or `app/`
calls it or `SendTransaction` directly:

| Call site | Guarded by, in the same function, before the send |
|---|---|
| `build/yec_send.rs` `broadcast` | `gate::confirm(Path::Yec)` |
| `build/yed_transfer.rs` `broadcast` | `gate::confirm(Path::YedTransfer)`, then `YellowbackAbsent` unless the node answered |
| `build/mint.rs` `send` (private helper), called from `carrier_step` | `gate::confirm(Path::Carrier)` |
| … from `finish` (MINT) | `gate::confirm(Path::Mint)` |
| … from `sweep` | `gate::confirm(Path::Sweep)` |
| … from `build/redeem.rs` `broadcast` | `gate::confirm_burning(Path::Redeem / Release, planned burn)` |
| … from `build/claim.rs` `broadcast` (`mint::send`) | `gate::confirm_burning(Path::Claim(vault), planned burn)` |

`gate::confirm_burning` runs the local layer (`check`) and, unless the `Validator` is
`Absent`, the node's `ValidateRawTransaction` with `accept` (`valid && verdict == "ok" &&
burned == planned && !wouldBeRejected`). `Absent` refuses every path that `needs_yellowback()`
and lets only the YEC path through on the local layer. There is no `cfg(test)`, `cfg(feature)`
or environment read anywhere in `gate.rs`, and the crate has no feature flags of its own
(`core/Cargo.toml`). `Validator` is built only by `Validator::detect` (a probe); the one other
mention of `Validator::Absent` (`api.rs:1302`) is a `match` arm, not a construction. A library
user of `yew-core` could call `CompactClient::send_transaction` on bytes of their own: that is
outside the wallet's surface (`api.rs` exposes no raw send) and is accepted.

## S-3 — TLS

- Scheme: `https://` unless `plain`; `h2` over `rustls` (`tonic` `tls-ring`,
  `tls-native-roots`): the platform's root store (`rustls-native-certs`). No `webpki-roots`
  bundle, so the device's own trust decisions (an enterprise root, a revoked CA) apply.
- `plain` is a `Server` field; **`Server::parse_for(network, …)` refuses it outside regtest**
  and is the only constructor the bridge (`api.rs::parse_server`) and the CLI use. Before W5
  testnet accepted plain (`api.rs`, `main.rs` tested `== Mainnet`); the plan's §3.5 says
  regtest only. The app's "plain" switch now appears on regtest only.
- Pinning: `Server::ca_pem` — a PEM certificate (the server's self-signed certificate or its
  private CA) used as the **only** trust anchor (`ClientTlsConfig::ca_certificate` without
  `with_native_roots`). Host-name verification still applies (`rustls` checks the SAN against
  the host). A SHA-256 *fingerprint* pin would need a custom `ServerCertVerifier`, i.e.
  `rustls` as a direct dependency (`tonic` 0.14 offers no verifier hook on `ClientTlsConfig`);
  that is an allow-list decision (plan §3.3) left to the owner. The CLI takes `--ca-pem PATH`;
  the app has no field for it yet (a bridge parameter on `set_server` / `probe_server` /
  `create_wallet` / `unlock`, a Settings field): deferred, listed in the README.
- `Server::parse` accepts a DNS name (`[A-Za-z0-9.-]`), an IPv4 address or a bracketed IPv6
  address and a port; anything else is refused before an `Endpoint` is built.

## S-4 — what the server says that the wallet acts on

The trust statement (`docs/trust.md`) promises: the server cannot spend, it can lie about the
chain. Concretely, acted on **without a local check**:

| Answer | Used for | Worst case of a lie |
|---|---|---|
| `GetLightdInfo.chainName`, `taddrSupport` | refuse a server for another chain | none (refusal only) |
| `GetLightdInfo.consensusBranchId` | the ZIP-243 signature | a wrong id makes every signature invalid: refusal by the node, no loss |
| `GetLatestBlock`, `blockHeight` | `nExpiryHeight = tip + 40`, mint windows, lock heights | a stale tip expires transactions early or judges a window wrongly; no loss |
| `GetAddressUtxos`, `GetTaddressTxids` | the UTXO set and the history | hidden coins (shown balance too low), phantom coins (a spend of them is refused by the node) |
| `GetAddressTokens` | **the only source of the TOKEN class** (D-W-8) | hidden YED; a listed non-token is refused by the node's dry run and, if it were relayed, would be a burn — this is exactly why the dry run is mandatory and why HELD is never spent |
| `GetTxInfo` | history labels | wrong labels only |
| `GetPrice.pMint` | display, the underwater flag | wrong display |
| `ValidateRawTransaction` | the remote gate layer | a false `ok` on a transaction the local layer already accepted: the local layer bounds it (only known classes, right payload shape), so the damage is a rejected transaction, not a burn of a wrongly-classed coin |
| `EstimateCollateral`, `EstimateFee`, `GetFeePayee`, `ListClaimable` | the mint / claim amounts and payees | overpaying a fee or a payee of the server's choice, within what the user confirmed on screen (amounts are shown before the slider) |
| `BuildBundle` + `ListAttestors` + `GetBlock` | the price bundle | the signatures are verified locally, but the attestor set and the block hash come from the same server: a server that forges all three could feed a bundle the node then refuses (the node knows the real set). No loss |
| `GetVault` | vault facts (lock heights, status) | a wrong `lockHeight` produces a redeem the node refuses |

Not trusted at all: transaction bytes, amounts, scripts, signatures, addresses (parsed locally
with the network prefix), the coin classes (local rules over the server's *lists*), payloads.

## S-5 — storage

`yew-<chain>.sqlite` in the app's support directory (`path_provider`), WAL mode. Tables:
`meta` (network, birthday, scanned height, primary key hash), `addresses` (chain, index, the
two address forms, hash160), `utxos` (+ class, cents), `locks`, `history` (+ labels),
`own_outputs`, `own_tokens`, `spent_tokens`, `pending_txs`, `imported_keys` (**wrapped**),
`mints` (the two-step rows: bundle bytes, carrier key hash, fees, txids — no secrets),
`vaults`. No seed, no HD key, no address key. The wrapped imported key is `secret XOR
HMAC-SHA256(wrap_key, "yew-imported-key-v1" ‖ hash160 ‖ counter)` with the wrap key derived
from the seed; there is no MAC, but a tampered ciphertext unwraps to a key whose `hash160`
differs from the row's and `key_for_hash` refuses it. A copy of the file reveals the whole
address list and history (privacy, not funds) and ciphertext that is useless without the seed.
Permissions: `0600` on Unix from W5. On iOS / Android the sandbox is the boundary; the file is
excluded from backups on Android (S-6); on iOS the support directory is backed up by iCloud
unless excluded (`[owner]`: set `NSURLIsExcludedFromBackupKey` or accept — the file holds no
secret, only privacy-relevant data).

## S-7 — the bridge boundary

| Dart passes | The core checks |
|---|---|
| `seed_words`, `passphrase` | `bip39` parse (wordlist, checksum, count); wiped after use |
| `server`, `plain` | `Server::parse_for`: host charset, port, `plain` regtest-only |
| `network` | an enum; the wallet file records it and refuses another |
| `data_dir` | the app's own directory (trusted; `format!("{dir}/yew-{chain}.sqlite")`) |
| `birthday` (i64) | clamped to `>= 0` |
| `to` / recipient addresses | `keys::parse_address` for the wallet's network (prefix, checksum, 22 bytes) |
| `zat` (i64) | `<= 0` refused in the builder; the `TOKEN_VALUE ± 1` rules; funds checked by selection |
| `cents` per recipient | `MIN_OUTPUT_CENTS ..= MAX_OUTPUT_CENTS`, at most 14 recipients |
| `mint cents`, `lock_blocks` | `cents <= 0` refused; the node's `EstimateCollateral` refuses a bad lock class; the local `MintEstimate` compares affordability |
| `mint_id` | a row lookup; a missing row is `NotFound`, a row in the wrong state `WrongState` |
| `vault_txid` | hex, exactly 32 bytes, before the wallet is looked at |
| `wif` | Base58Check, 34 bytes, compressed flag, the network's prefix, curve order |
| `preview_id` | a key into the in-memory preview map; a stale id is `NotFound` |
| `page`, `page_size` | `page_size == 0` becomes the default; SQL `LIMIT/OFFSET` |

## The app

- **Keystore** (`lib/state/secrets.dart`): `flutter_secure_storage` 11.2.0 with
  `IOSOptions(accessibility: first_unlock_this_device)` — the item does not migrate to a new
  device and needs the device to have been unlocked once since boot. Android: the plugin's
  default (`KeyCipherAlgorithm` AES in the Android Keystore, `StorageCipherAlgorithm`
  AES-GCM); `enforceBiometrics` is off (A-1). Keys: `seed`, `passphrase`, `settings` (JSON,
  no secret).
- **Seed flow**: `createWallet` receives the generated words once from the core and writes
  them to the keystore; `unlock` reads them and hands them to the core; `seedWordsForBackup`
  reads them again for the backup screen behind the `local_auth` prompt when biometrics are
  on. The words are never in `AppState` fields, never in a log, never in a `SnackBar`.
- **Screens**: `SeedBackupScreen`, `ExportKeyScreen`, `ImportKeyScreen` set `FLAG_SECURE`
  while mounted (Android). The import field is `obscureText`. The seed screen has no copy
  action; the export screen's copy is explicit and labelled.
- **Plugins and the network**: `flutter_secure_storage`, `local_auth`, `path_provider`,
  `qr_flutter`, `mobile_scanner` (camera), `flutter_rust_bridge`. None opens a socket; the
  `INTERNET` permission serves the core's gRPC only. No crash reporting, no analytics
  (`docs/release.md` §6).
