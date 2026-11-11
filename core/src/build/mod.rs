// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Transaction builders: `any_to_any` (the shape planning shared with yewd, beta2 D-8), `pq_send`,
//! `yec_send`, `yec_private` (privacy-first funding, S2), `yec_move` (shield / unshield, S4), `yed_transfer`, `mint`, `redeem`, `claim` (one file each,
//! added by phase). Each produces the `preview` the screen renders and then signs the same bytes.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp` (MINT, TRANSFER,
//! REDEEM, CLAIM templates and `nLockTime` / `nSequence` / `nExpiryHeight`). Phase W1/W2/W4:
//! `mint` holds the carrier step and the sweep that `claim` shares, `redeem` the vault-spend
//! plan that `claim` shares.

/// The start of the refusal that asks for the user's go-ahead before the transactions that
/// created the notes a private spend takes are fetched from the server
/// (`sapling_pq::note_txs`, review YEW-REVIEW-8 M1); the API maps it to
/// `ErrorKind::NoteLookupNeeded`.
pub const NOTE_LOOKUP_NEEDED: &str = "note-lookup-needed: ";

pub mod any_to_any;
pub mod claim;
// review YEW-PORT-5 R3: the hybrid builder (native only: the prover is not in the browser build).
// Not an app API (review YEW-REVIEW-6 L3): `pub` for yewd-signer only; every caller passes the
// result through `gate::check`; `crate::api` and `web/core-wasm` name nothing from it.
#[cfg(not(target_arch = "wasm32"))]
pub mod hybrid;
pub mod mint;
// A mint funded from the private balance (beta2 D-3): the hybrid builder, so native only.
#[cfg(not(target_arch = "wasm32"))]
pub mod mint_sapling;
pub mod pq_send;
pub mod redeem;
pub mod release;
// Sapling -> post-quantum (beta2 D-2, D-8): the hybrid builder, so native only.
#[cfg(not(target_arch = "wasm32"))]
pub mod sapling_pq;
pub mod terms;
pub mod yec_move;
pub mod yec_private;
pub mod yec_send;
pub mod yed_transfer;
