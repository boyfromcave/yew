//! Transaction builders: `yec_send`, `yed_transfer`, `mint`, `redeem`, `claim` (one file each,
//! added by phase). Each produces the `preview` the screen renders and then signs the same bytes.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp` (MINT, TRANSFER,
//! REDEEM, CLAIM templates and `nLockTime` / `nSequence` / `nExpiryHeight`). Phase W1/W2/W4.

pub mod yec_send;
pub mod yed_transfer;
