// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Compiles the pinned lightwalletd protos (`../proto/*.proto`, pinned in `../proto/PIN`) into
//! client stubs for `CompactTxStreamer` and `YellowbackStreamer` (plan §3.1 `net/`).
//! Uses the `protoc` on PATH (or `PROTOC`); nothing is vendored.
//!
//! Also compiles the vendored Falcon-512 (PQClean `falcon-padded-512/clean` plus the Ycash
//! entry points, `pq-c/falcon/`, byte copies of ycash-dd `src/crypto/pq/falcon/`; see
//! `pq-c/README.md`) with the `cc` crate, for the host and for every mobile target the
//! `scripts/build-core-{ios,android}.sh` builds (cc picks Xcode's clang for iOS and the NDK clang
//! cargo-ndk exports for Android, as it already does for rusqlite's bundled SQLite). Portable C99
//! only: no target-feature flags (no AVX2, no `-ffast-math`); the `clean` Falcon emulates its
//! floating point with integers (`fpr.h`: `typedef uint64_t fpr`), so the bytes do not depend on
//! the target's FPU, the compiler or the optimisation level.

use std::path::PathBuf;

/// The public symbols of the vendored `fips202.c` (PQClean's generic `shake256`, `sha3_256`, …),
/// renamed `yew_pq_*` at compile time so they can never collide with another C library linked
/// into the app binary. A rename only: no byte of the vendored files changes.
const FIPS202_SYMBOLS: &[&str] = &[
    "sha3_256",
    "sha3_256_inc_absorb",
    "sha3_256_inc_ctx_clone",
    "sha3_256_inc_ctx_release",
    "sha3_256_inc_finalize",
    "sha3_256_inc_init",
    "sha3_384",
    "sha3_384_inc_absorb",
    "sha3_384_inc_ctx_clone",
    "sha3_384_inc_ctx_release",
    "sha3_384_inc_finalize",
    "sha3_384_inc_init",
    "sha3_512",
    "sha3_512_inc_absorb",
    "sha3_512_inc_ctx_clone",
    "sha3_512_inc_ctx_release",
    "sha3_512_inc_finalize",
    "sha3_512_inc_init",
    "shake128",
    "shake128_absorb",
    "shake128_ctx_clone",
    "shake128_ctx_release",
    "shake128_inc_absorb",
    "shake128_inc_ctx_clone",
    "shake128_inc_ctx_release",
    "shake128_inc_finalize",
    "shake128_inc_init",
    "shake128_inc_squeeze",
    "shake128_squeezeblocks",
    "shake256",
    "shake256_absorb",
    "shake256_ctx_clone",
    "shake256_ctx_release",
    "shake256_inc_absorb",
    "shake256_inc_ctx_clone",
    "shake256_inc_ctx_release",
    "shake256_inc_finalize",
    "shake256_inc_init",
    "shake256_inc_squeeze",
    "shake256_squeezeblocks",
];

/// The vendored Falcon translation units (`pq-c/falcon/`).
const FALCON_SOURCES: &[&str] = &[
    "codec.c",
    "common.c",
    "fft.c",
    "fips202.c",
    "fpr.c",
    "keygen.c",
    "rng.c",
    "sign.c",
    "vrfy.c",
    "ycash_falcon_sign.c",
    "ycash_falcon_verify.c",
];

fn build_falcon() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pq-c/falcon");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut b = cc::Build::new();
    b.include(&dir).std("c99").opt_level(2).warnings(false);
    for f in FALCON_SOURCES {
        b.file(dir.join(f));
    }
    for s in FIPS202_SYMBOLS {
        b.define(s, Some(format!("yew_pq_{s}").as_str()));
    }
    b.compile("yew_falcon");
}

fn main() {
    build_falcon();
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../proto");
    let protos =
        ["compact_formats.proto", "service.proto", "yellowback.proto"].map(|f| proto_dir.join(f));
    for p in &protos {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed={}", proto_dir.join("PIN").display());
    println!("cargo:rerun-if-env-changed=PROTOC");
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&protos, &[proto_dir])
        .expect("protoc failed: install protobuf (brew install protobuf / apt install protobuf-compiler)");
}
