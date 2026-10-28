# core/pq-c: the node's Falcon-512, vendored

`falcon/` is a byte copy of the Falcon sources the Ycash node verifies `OP_CHECKPQSIG` scheme `0x02`
with: ycash-dd `src/crypto/pq/falcon/` at `upgrade/quantum-vaults` (last change `ccf49e913`), which is
byte-identical to ycash6 `src/crypto/pq/falcon/` (last change `49bd673a7`). `SHA256SUMS` pins every
file; `pq.rs` `vendored_falcon_matches_its_manifest` fails if one drifts.

* Upstream: PQClean `crypto_sign/falcon-padded-512/clean/` and `common/fips202.{c,h}`,
  https://github.com/PQClean/PQClean commit `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` (archived).
* Licence: MIT (Falcon Project, `falcon/LICENSE`, unchanged, with its patent note); `fips202.{c,h}`
  public domain (header notice unchanged); the `ycash_falcon*` files MIT (The Ycash developers).
* Local patch carried from the node (P1, every line marked `YCASH LOCAL PATCH`): the SHAKE256
  incremental context lives inline (no `malloc`/`exit` in `fips202.c`).
* `pqclean.c` / `api.h` are not vendored: the node's `ycash_falcon_sign.c` (keygen from a caller's
  seed, signing with caller-supplied nonce and sampler seed) and `ycash_falcon_verify.c` replace them,
  so no `randombytes` symbol exists. YEW passes the OS RNG's bytes (`pq::PqKey::sign`).

Build (`core/build.rs`, the `cc` crate): C99, `-O2`, no target-feature flags. The `clean` Falcon
emulates floating point with integers (`fpr.h`: `typedef uint64_t fpr`), so keys and signatures are
the same bytes on every target (host, `aarch64-apple-ios[-sim]`, `aarch64`/`x86_64-linux-android`).
The public `fips202.c` symbols are renamed `yew_pq_*` with `-D` defines (no file edit), so they
cannot collide with another C library in the app binary.

Proof of byte identity (`cargo test -p yew-core pq::`): the node's golden vectors
(`tests/vectors/pq_vectors.json`: Falcon keygen from the 48-byte seed, signing with the recorded
88-byte entropy, verification) and the node's Falcon KATs (`tests/vectors/pq_falcon_kat.json`: NIST
round-3 counts 0-4 and PQClean's padded count 0, replayed through the NIST AES-256 CTR DRBG).
