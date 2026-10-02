// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Transaction builders: `yec_send`, `yed_transfer`, `mint`, `redeem`, `claim` (one file each,
//! added by phase). Each produces the `preview` the screen renders and then signs the same bytes.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp` (MINT, TRANSFER,
//! REDEEM, CLAIM templates and `nLockTime` / `nSequence` / `nExpiryHeight`). Phase W1/W2/W4:
//! `mint` holds the carrier step and the sweep that `claim` shares, `redeem` the vault-spend
//! plan that `claim` shares.

pub mod claim;
pub mod mint;
pub mod redeem;
pub mod terms;
pub mod yec_send;
pub mod yed_transfer;
