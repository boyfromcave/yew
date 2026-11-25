# Decision record: the Yugen seed at rest (Y-W12; ycashd N-A5)

Supersedes Y-W5 ("seed in the clear, regtest/devnet only"). Provenance: Original (the Ycash
developers, 2026), built on stock ycashd wallet encryption (`CCryptoKeyStore`) and yewd's existing
signer sealing (`yewd/signer/src/seal.rs`); no paper is used.

## Problem

`yewd-yugen` kept the Yugen account seed in `<datadir>/wallet.json` in hex, written with default
permissions, in ycashd (`<datadir>/yugenwallet/`) and in yewd (`<netdir>/yugen/`), also when the host
wallet was encrypted. A second defect: a dummy spend's nullifier followed a wallet-global
`dummy_counter` (spec §5.6 says: the smallest counter not yet used *with that anchor height*), which
a restore from the seed cannot recover, so a restored wallet could repeat a nullifier.

## Options

| Option | Seed at rest | Locked wallet | Change | Verdict |
|---|---|---|---|---|
| A. Engine encrypts its own file with a passphrase (argon2id/scrypt + AEAD) | encrypted | engine needs the passphrase per call: a second secret channel | engine KDF, passphrase plumbing in both hosts | rejected: a second passphrase beside the wallet's, two encryption schemes to review |
| B. Host keeps the seed under the host wallet's existing protection; engine gets it per call on an inherited pipe | ycashd: `wallet.dat` record under the master key (as the mnemonic seed); yewd: not stored, derived from the signer's sealed phrase (N-A2) | reads use the last state file; spends refused with the stock -13 | engine `-seedfd`; ycashd keystore record; yewd signer request | **chosen** |
| C. B plus a viewing-key cache on disk for locked background sync | as B, plus viewing material | scans and host sync keep running locked | a viewing/spending key split in the spec's key tree | deferred: spec §4 derives `nk`, `rsk`, `ivk_req`, `dkm`, `delm` together under `sk_a`; which of them suffices to scan without enabling a spend or linking needs a spec decision |

## Chosen (B)

1. `wallet.json` never holds the seed; it holds `seed_fp = BLAKE2b-256(personal "Ycash_YugenSd_FP", seed)`
   and the engine refuses a call whose seed has another fingerprint. Written atomically (temporary
   file 0600, fsync, rename, directory fsync), directory 0700 (`store.rs` `write_private`).
2. The engine takes the seed only as `-seedfd=N`: hex followed by `'\n'`, read byte by byte to
   the newline (never to end of file) into a fixed `Zeroizing` buffer (`store.rs` `read_seed_fd`). `-seed=` is refused. Without a seed every method is
   refused. Both hosts create the pipe close-on-exec and `dup2` it onto fd 3 in the child only.
3. ycashd: records `yugenseed` (plain wallet) / `cyugenseed` (encrypted, AES-256-CBC under the master
   key, IV = fingerprint, the mnemonic seed's scheme); `EncryptKeys` encrypts it and the write erases
   the plain record in the same transaction; `encryptwallet` ends with stock `CDB::Rewrite`.
   `walletpassphrasechange` re-wraps only the master key (stock), so it covers the seed.
   Locked: `z_getbalance`, `z_gettotalbalance`, listings read the last state (no engine call, no
   scan, no scheduled sync); `z_sendmany` from the account and `z_getnewaddress "yugen"` return -13.
4. yewd: the seed is `BLAKE2b-256(personal "Ycash_YugenSeed_", BIP 39 seed)` (N-A2, identical to
   ycashd; vector: phrase "abandon ×11 about" gives `3a3287aa…d538c`), computed by the signer from its
   phrase (sealed by `encryptwallet`: PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305, `seal.rs`) and given to
   the façade per call (`Request::YugenSeed`, refused while locked). Kept consistent with yewd's other
   keys rather than adding argon2id/scrypt.
5. Migration. ycashd: a state file with a `seed` field moves it into `wallet.dat` at start (plain
   wallet), at `walletpassphrase`, at `encryptwallet` (before encrypting) or at the next call; the file
   is rewritten without it and the old file overwritten with zeros before the rename. yewd: a seed
   equal to the derived one is dropped by the engine (same overwrite); an earlier yewd's own random
   seed is kept in `legacy-seed.sealed` (ChaCha20-Poly1305, key `BLAKE2b-256("Ycash_YugenWrap_",
   derived seed)`), so it is protected exactly as the phrase is.
6. Backup: `z_exportwallet`/`dumpwallet` still write `yugenseed=` (stock requires unlock); import
   restores it into the wallet record.
7. Dummy rule (spec §5.6, §7.7): per anchor height, the next counter is kept in `dummy_next`, and a
   candidate whose nullifier the node reports mined or pending (`gettransferstatus`) is skipped. The
   nullifier stays a function of seed, anchor height and counter (no free bytes); a restored wallet
   needs no counter record. ycashd's random counter start is removed (the change-index start stays).

8. Review fixes (2026-11-25; Original, the Ycash developers):
   - Scrub order (`store.rs` `write_private`, ycashd `WritePrivate`): the old file is opened first
     (`O_NOFOLLOW`, a regular file only), the new one renamed over it, the directory synced, then the
     old inode zeroed through the open descriptor. A crash leaves the old file whole or the new one.
   - yewd spawns: the seed pipe is made close-on-exec while `SPAWN_LOCK` is held for writing (macOS
     has no `pipe2`); every other yewd spawn holds it for reading (`spawn_guarded`); the engine child
     closes every non-close-on-exec descriptor from 4 up. The engine lock is a std mutex held by the
     blocking task that owns the child, so a cancelled caller never releases it while the child runs.
     The backend password reaches the engine in a per-call 0600 cookie-format file, not argv.
   - Backup of an earlier yewd's own seed (item 5): `z_exportwallet` writes `yugensealed=<hex>` (the
     `legacy-seed.sealed` blob, sealed under the phrase's derived seed) and `z_importwallet` restores it,
     so phrase + dump restore that account (test `earlier_yewd_seed_survives_dump_and_restore`). A
     read error on the sealed file other than not-found is an error, never a fall-back.
   - Imported post-quantum key seeds (`pqimported.json`) are sealed under the wallet passphrase in an
     encrypted wallet as `imported.json` is; a plain file in an encrypted wallet is sealed at the next
     unlock (`signer/tests/pq_imported_sealed.rs`). Secrets in signer responses (`Response::Dumped`)
     are a zeroed-on-drop `Secret`.
   - Dummy probing (item 7) sends candidate nullifiers to the node, which links them to the wallet's
     next transfer. It is done only when the node is on a loopback address. With a remote backend the
     wallet uses its own `dummy_next` record and, with none for that anchor height (e.g. after a
     restore), starts at a counter drawn uniformly from [2^31, 2^32 - 2^20). Spec §5.6's wallet rule
     ("the smallest value not yet used") is kept for a local node; the remote rule departs from it
     knowingly: §7.7 makes the counter wallet state, not a free byte, and this engine is its own
     signer and keeps the record §7.7's signer rule asks for, so no channel opens. Collision bound
     (round-2 review S3): two restores without a record that each make a transfer at the same anchor
     height draw starts s, t uniformly from N = 2^31 - 2^20 values; a transfer uses at most two dummy
     counters (s, s+1), so the pair shares a counter when |s - t| <= 1, about 3/N = 3·2^-31 per
     transfer pair. The outcome is a refused transfer (its dummy nullifier is already in the set);
     no funds are at risk, and the next attempt advances the record. Recorded in the specification as
     SPEC-215 (`yugen-spec` `spec/decisions.md`). Tests: `remote_backend_gets_no_dummy_probe`,
     `remote_backend_counter_follows_its_record`.

## Exposure stated

- On disk: the state file holds note values, positions, memos, nullifiers of own notes, txids, the
  seed fingerprint and counters: enough to link this wallet's history if the file is read, not to spend.
- In memory: the seed exists in the host for one call and in the engine process for its life
  (`Zeroizing`); the key tree derived inside `yugen_ref` (`AccountKeys`, the Falcon signer) is not
  zeroized (reference crate types). The scrub is best effort: APFS copy-on-write and SSD remapping
  can keep old blocks.
- yewd's Yugen methods all need the seed, so a locked yewd answers no `yugen_*` call (-13).

## Acceptance (tests)

- `wallet/tests/seed_at_rest.rs`: no seed hex or bytes in the datadir after create, legacy migration
  and restores; mode 0600; wrong seed refused; restore twice never repeats a mined dummy nullifier;
  N-A2 vector.
- `yewd/signer` `yugen_seed_n_a2_vector`, `tests/pq_imported_sealed.rs`; `yewd/facade` `seed_tests`
  (fd 3 delivery, no inherited descriptor, unreadable sealed file, dump/restore of the sealed seed,
  credential file).
- ycash6 `qa/rpc-tests/yugen_wallet_encrypted.py`, `yugen_wallet_rescan.py`; `yugen_wallet.py`,
  `yugen_wallet_stock.py` unchanged.

## What would reverse it

A spec viewing-key split (option C) for locked background sync; or a decision that yewd keep
Yugen accounts independent of the BIP 39 phrase (then the seed is sealed in the signer as imported keys are).
