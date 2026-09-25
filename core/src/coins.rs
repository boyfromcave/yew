//! UTXO classes (TOKEN, PENDING_TOKEN, VAULT, CARRIER, FEE_RESERVE, YEC, UNKNOWN_P2SH, FOREIGN),
//! the lock set, YEC selection with the fee reserve (plan §3.7, D-W-12).
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp:395-420` (`SelectYec`),
//! `wallet.cpp` `PreLock`/`LockOwn`/`Release`; the fee reserve is YEW's addition. Phase W1/W2.
