// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's refusals (moved from `yewd_proto` and the signer, review YEW-PORT-5 R1;
//! `yewd_proto::refuse` and the signer re-export them, the wire codes unchanged).

/// The request names another protocol version.
pub const BAD_VERSION: &str = "bad-version";
/// The request does not parse, or the transaction does not.
pub const MALFORMED: &str = "malformed";
/// An input has no prevout, or its prevout is not the one the transaction spends.
pub const UNBOUND_INPUT: &str = "unbound-input";
/// A key reference does not own the script it is to spend or recognise.
pub const KEY_MISMATCH: &str = "key-mismatch";
/// The preview disagrees with the bytes (an amount, a recipient, an input, the fee).
pub const PREVIEW_MISMATCH: &str = "preview-mismatch";
/// A wallet coin is signed that the preview does not list.
pub const FOREIGN_INPUT: &str = "foreign-input";
/// The net outflow is above the cap.
pub const OUTFLOW: &str = "outflow";
/// The gate path's rules refuse the transaction.
pub const GATE: &str = "gate";
/// The sign-once record holds another role or sighash for `(setid, prevout)`.
pub const SET_SIGN_ONCE: &str = "set-sign-once";
/// The restore marker is set and the prevout has no record.
pub const SET_SIGN_RESTORED: &str = "set-sign-restored";
/// The equivocation guard holds another price for this key and height (EQV-1).
pub const EQUIVOCATION_GUARD: &str = "equivocation-guard";
/// A price outside `[PRICE_MIN, PRICE_MAX]`.
pub const ATTEST_RANGE: &str = "attest-range";
/// A cancel co-signature with no price given and none signed for the height.
pub const PRICE_REQUIRED: &str = "price-required";
/// A cancel co-signature whose price says the vault was claimable.
pub const CANCEL_STATEMENT_CLAIMABLE: &str = "cancel-statement-claimable";
/// The guard could not be written; nothing was signed.
pub const GUARD_WRITE_FAILED: &str = "guard-write-failed";
/// A key the signer does not hold (an imported index past its store, a bad WIF).
pub const KEY_NOT_HELD: &str = "key-not-held";
/// Anything else (a derivation, the store).
pub const FAILED: &str = "failed";
/// The wallet is encrypted and locked (S4): ycashd's `-13`.
pub const LOCKED: &str = "locked";
/// `walletpassphrase` with a wrong passphrase: ycashd's `-14`.
pub const BAD_PASSPHRASE: &str = "bad-passphrase";
/// `encryptwallet` on an encrypted wallet, `walletpassphrase`/`walletlock` on a plain one: `-15`.
pub const WRONG_ENC_STATE: &str = "wrong-enc-state";

/// A refusal: its code (one of the constants above) and the reason.
pub type Refused = (&'static str, String);

/// Refuse with `code` and `reason`.
pub fn no<T>(code: &'static str, reason: impl Into<String>) -> Result<T, Refused> {
    Err((code, reason.into()))
}
