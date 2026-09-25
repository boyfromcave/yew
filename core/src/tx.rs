//! Transactions: the v4 (Sapling, `fOverwintered`) transparent-only serializer, the ZIP-243
//! sighash bound to `consensusBranchId`, and the signer (D-W-3, hand-written, no `zcash_*`).
//!
//! Verified byte-for-byte against the node-generated vectors in `tests/vectors/` (Phase W0c).
//! Translation source: `ycash-dd/src/primitives/transaction.h`, `src/script/interpreter.cpp`
//! (`SignatureHash`, ZIP-243 branch). Phase W1.
