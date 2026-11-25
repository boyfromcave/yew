// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! yewd's Yugen wallet (beta4 Yugen addendum §3.2, M1). Keys, addresses, notes and the transfer
//! come from the specification's reference implementation (`yugen-spec/yugen-ref`, spec 0.5.1,
//! `d25a89c`); the two mode-0 wallet provers from `yugen-proof-a` (`f79c8b5`) and
//! `yugen-proof-b2` (`2b0cb46`). Decisions: `../docs/decisions.md`.

pub mod account;
pub mod build;
pub mod dpf;
pub mod hosts;
pub mod engine;
pub mod node;
#[cfg(feature = "provers")]
pub mod prove;
pub mod scan;
pub mod schedule;
pub mod store;
pub mod tx;
pub mod yaddr;

pub use yugen_ref::hash::{B32, B48};

/// Value in zatoshi to a decimal YEC amount.
pub fn coins(z: u64) -> f64 {
    z as f64 / 1e8
}
/// Decimal YEC amount to zatoshi (rounded).
pub fn zats(c: f64) -> u64 {
    (c * 1e8).round() as u64
}

/// Decision N-A2: the Yugen account seed of a wallet whose seed is a BIP 39 phrase is
/// `BLAKE2b-256(personal "Ycash_YugenSeed_", bip39_seed)` over the 64-byte BIP 39 seed (empty
/// BIP 39 passphrase), exactly as ycashd derives it (`yugenwallet::DerivedSeed`), so one phrase
/// gives the same Yugen addresses in ycashd and in yewd.
pub fn yugen_seed_from_bip39(bip39_seed: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    let h = blake2b_simd::Params::new().hash_length(32).personal(b"Ycash_YugenSeed_").hash(bip39_seed);
    zeroize::Zeroizing::new(h.as_bytes().to_vec())
}
