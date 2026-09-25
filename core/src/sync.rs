//! Sync (plan §3.2): address scan via `GetAddressTxids` + `GetTransaction`, the YEC UTXO set,
//! the YED token set via `GetAddressTokens`, history labels from `GetTxInfo` verdicts.
//!
//! Translation source (plan §3.6): `yecwallet-dd/src/yellowbackmodels.cpp`,
//! `yellowbackcontroller.cpp` (labels, the `PreLock` pending rule, verdict-to-display mapping).
//! Phase W1 (YEC), W2 (YED).
