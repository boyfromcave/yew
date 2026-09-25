//! UTXO classes (plan §3.7, D-W-12), the YEC-phase classifier, the fee reserve and `SelectYec`.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp:395-420` (`SelectYec`:
//! smallest-first, skip every P2SH, skip every token and vault); `wallet.cpp`
//! `PreLock`/`LockOwn`/`Release` (W2). The fee reserve is YEW's addition.
//!
//! **The YEC-only phase rule (W1).** Until W2 wires `GetAddressTokens`, nothing can tell a plain
//! 10,000-zat P2PKH output from a YED token, so a P2PKH output to an own key of exactly
//! `TOKEN_VALUE` is classed **HELD** (unspendable) rather than YEC. Losing a send to "sync
//! first" is acceptable; burning is not (§3.7). W2 replaces this rule with the server's answer.

use thiserror::Error;

use crate::params::{reserve_zat, TOKEN_VALUE};
use crate::script;
use crate::tx::OutPoint;

/// The class of a UTXO (plan §3.7). Every UTXO the wallet knows is in exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UtxoClass {
    /// A confirmed P2PKH output to an own key: YEC available.
    Yec,
    /// A YEC output set aside for YED fees.
    FeeReserve,
    /// A YED token listed by `GetAddressTokens` (W2). YED input only.
    Token,
    /// A token output the app broadcast, not yet confirmed by the server. Nothing.
    PendingToken,
    /// `vout[0]` of an own MINT. REDEEM only.
    Vault,
    /// A P2SH carrier the app created. Its paired transaction only.
    Carrier,
    /// Any P2SH the app did not create. Hidden, never spent.
    UnknownP2sh,
    /// An own P2PKH output of exactly `TOKEN_VALUE` in the YEC-only phase: unclassifiable.
    Held,
    /// Not to an own key.
    Foreign,
}

impl UtxoClass {
    /// The stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            UtxoClass::Yec => "YEC",
            UtxoClass::FeeReserve => "FEE_RESERVE",
            UtxoClass::Token => "TOKEN",
            UtxoClass::PendingToken => "PENDING_TOKEN",
            UtxoClass::Vault => "VAULT",
            UtxoClass::Carrier => "CARRIER",
            UtxoClass::UnknownP2sh => "UNKNOWN_P2SH",
            UtxoClass::Held => "HELD",
            UtxoClass::Foreign => "FOREIGN",
        }
    }

    /// From the stored name.
    pub fn parse(s: &str) -> Option<UtxoClass> {
        Some(match s {
            "YEC" => UtxoClass::Yec,
            "FEE_RESERVE" => UtxoClass::FeeReserve,
            "TOKEN" => UtxoClass::Token,
            "PENDING_TOKEN" => UtxoClass::PendingToken,
            "VAULT" => UtxoClass::Vault,
            "CARRIER" => UtxoClass::Carrier,
            "UNKNOWN_P2SH" => UtxoClass::UnknownP2sh,
            "HELD" => UtxoClass::Held,
            "FOREIGN" => UtxoClass::Foreign,
            _ => return None,
        })
    }

    /// True for the classes a **YEC-path** transaction may ever spend.
    pub fn yec_spendable(self) -> bool {
        matches!(self, UtxoClass::Yec | UtxoClass::FeeReserve)
    }

    /// True for the classes whose `nValue` counts toward the YEC balance.
    pub fn counts_as_yec(self) -> bool {
        self.yec_spendable()
    }
}

/// A UTXO with its class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// The outpoint.
    pub outpoint: OutPoint,
    /// The address the server matched.
    pub address: String,
    /// The scriptPubKey.
    pub script: Vec<u8>,
    /// `nValue`.
    pub value: i64,
    /// The height it was mined at.
    pub height: u64,
    /// The class.
    pub class: UtxoClass,
}

/// Selection errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoinError {
    /// `insufficient-yec` (`txbuilder.cpp:417`).
    #[error("insufficient-yec: need {need} zat, have {have} zat available")]
    Insufficient {
        /// The amount needed.
        need: i64,
        /// The amount selectable.
        have: i64,
    },
}

/// The YEC-only phase classifier for an output the server listed for an own address:
/// any P2SH → `UnknownP2sh`; P2PKH to an own key of exactly `TOKEN_VALUE` → `Held`
/// (module doc); any other P2PKH to an own key → `Yec`; anything else → `Foreign`.
pub fn classify_yec_phase(
    script: &[u8],
    value: i64,
    is_own_key: impl Fn(&[u8; 20]) -> bool,
) -> UtxoClass {
    if script::p2sh_hash(script).is_some() {
        return UtxoClass::UnknownP2sh;
    }
    match script::p2pkh_hash(script) {
        Some(h) if is_own_key(&h) => {
            if value == TOKEN_VALUE {
                UtxoClass::Held
            } else {
                UtxoClass::Yec
            }
        }
        _ => UtxoClass::Foreign,
    }
}

/// Re-evaluate the fee reserve (plan §3.7 item 1): every `FeeReserve` goes back to `Yec`, then
/// YEC outputs are marked `FeeReserve` smallest-first until they cover [`reserve_zat`].
/// Smallest-first (the node's `SelectYec` order) so that dust ends up paying YED fees and the
/// larger outputs stay available for YEC sends.
///
/// Refinement fixed in W1 (devnet): an output larger than the whole reserve is never put into
/// it. Otherwise a wallet with one coin would show "available 0, reserved everything" and every
/// YEC send would need the override. When no small outputs exist the reserve is short and a
/// YED operation takes its fee from class `YEC` (the class table allows it: "fee if the reserve
/// is short").
pub fn apply_fee_reserve(utxos: &mut [Utxo]) {
    let target = reserve_zat();
    for u in utxos.iter_mut() {
        if u.class == UtxoClass::FeeReserve {
            u.class = UtxoClass::Yec;
        }
    }
    let mut order: Vec<usize> = (0..utxos.len())
        .filter(|&i| utxos[i].class == UtxoClass::Yec)
        .collect();
    order.sort_by_key(|&i| (utxos[i].value, utxos[i].outpoint.txid, utxos[i].outpoint.n));
    let mut covered = 0i64;
    for i in order {
        if covered >= target || utxos[i].value > target {
            break;
        }
        utxos[i].class = UtxoClass::FeeReserve;
        covered += utxos[i].value;
    }
}

/// `SelectYec` (`txbuilder.cpp:399-420`): smallest-first outputs covering `needed`, from class
/// `Yec` only, or from `FeeReserve` first then `Yec` when `use_reserve` (a YED operation, or
/// the user's explicit "send everything anyway"). Every other class is skipped: that is the
/// line that keeps a token, a vault, a carrier or a held output out of a YEC transaction.
/// Deterministic: ties break on the outpoint.
pub fn select_yec(utxos: &[Utxo], needed: i64, use_reserve: bool) -> Result<Vec<Utxo>, CoinError> {
    if needed <= 0 {
        return Ok(Vec::new());
    }
    let mut pool: Vec<&Utxo> = utxos
        .iter()
        .filter(|u| u.class == UtxoClass::Yec || (use_reserve && u.class == UtxoClass::FeeReserve))
        .collect();
    // Reserve first when allowed, then smallest-first within each class.
    pool.sort_by_key(|u| {
        (
            u.class != UtxoClass::FeeReserve,
            u.value,
            u.outpoint.txid,
            u.outpoint.n,
        )
    });
    let mut selected = Vec::new();
    let mut total = 0i64;
    for u in &pool {
        selected.push((*u).clone());
        total += u.value;
        if total >= needed {
            return Ok(selected);
        }
    }
    Err(CoinError::Insufficient {
        need: needed,
        have: total,
    })
}

/// The two YEC numbers the user sees: `(available, reserved)`.
pub fn yec_balances(utxos: &[Utxo]) -> (i64, i64) {
    let mut avail = 0;
    let mut reserved = 0;
    for u in utxos {
        match u.class {
            UtxoClass::Yec => avail += u.value,
            UtxoClass::FeeReserve => reserved += u.value,
            _ => {}
        }
    }
    (avail, reserved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u32, value: i64, class: UtxoClass) -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: [n as u8; 32],
                n,
            },
            address: String::new(),
            script: Vec::new(),
            value,
            height: 1,
            class,
        }
    }

    #[test]
    fn classifier_yec_phase() {
        let own = [1u8; 20];
        let is_own = |h: &[u8; 20]| *h == own;
        assert_eq!(
            classify_yec_phase(&script::p2pkh_script(&own), 50_000, is_own),
            UtxoClass::Yec
        );
        assert_eq!(
            classify_yec_phase(&script::p2pkh_script(&own), TOKEN_VALUE, is_own),
            UtxoClass::Held
        );
        assert_eq!(
            classify_yec_phase(&script::p2sh_script(&own), 50_000, is_own),
            UtxoClass::UnknownP2sh
        );
        assert_eq!(
            classify_yec_phase(&script::p2pkh_script(&[2; 20]), 50_000, is_own),
            UtxoClass::Foreign
        );
        assert_eq!(
            classify_yec_phase(&[0x6a, 0x01, 0x00], 0, is_own),
            UtxoClass::Foreign
        );
        for c in [
            UtxoClass::Yec,
            UtxoClass::Held,
            UtxoClass::Token,
            UtxoClass::Vault,
        ] {
            assert_eq!(UtxoClass::parse(c.as_str()), Some(c));
        }
    }

    #[test]
    fn fee_reserve_takes_smallest_first_and_is_idempotent() {
        let mut v = vec![
            u(1, 100_000, UtxoClass::Yec),
            u(2, 4_000, UtxoClass::Yec),
            u(3, 2_000, UtxoClass::FeeReserve),
            u(4, TOKEN_VALUE, UtxoClass::Held),
            u(5, 500_000, UtxoClass::Yec),
        ];
        apply_fee_reserve(&mut v);
        // 2_000 + 4_000 + 100_000 = 106_000 >= 105_000; the 500_000 stays YEC.
        assert_eq!(v[2].class, UtxoClass::FeeReserve);
        assert_eq!(v[1].class, UtxoClass::FeeReserve);
        assert_eq!(v[0].class, UtxoClass::FeeReserve);
        assert_eq!(v[4].class, UtxoClass::Yec);
        assert_eq!(v[3].class, UtxoClass::Held);
        let snapshot = v.clone();
        apply_fee_reserve(&mut v);
        assert_eq!(v, snapshot);
        assert_eq!(yec_balances(&v), (500_000, 106_000));
        // One coin larger than the reserve is never reserved.
        let mut big = vec![
            u(1, 150_000_000, UtxoClass::Yec),
            u(2, 200_000, UtxoClass::Yec),
        ];
        apply_fee_reserve(&mut big);
        assert_eq!(yec_balances(&big), (150_200_000, 0));
    }

    #[test]
    fn select_yec_skips_every_non_yec_class() {
        let v = vec![
            u(1, 30_000, UtxoClass::Yec),
            u(2, 10_000, UtxoClass::Held),
            u(3, 10_000, UtxoClass::Token),
            u(4, 5_000, UtxoClass::FeeReserve),
            u(5, 20_000, UtxoClass::Yec),
            u(6, 1_000_000, UtxoClass::Vault),
            u(7, 1_000_000, UtxoClass::Carrier),
            u(8, 1_000_000, UtxoClass::UnknownP2sh),
        ];
        let s = select_yec(&v, 25_000, false).unwrap();
        assert_eq!(
            s.iter().map(|x| x.outpoint.n).collect::<Vec<_>>(),
            vec![5, 1]
        );
        assert_eq!(
            select_yec(&v, 60_000, false),
            Err(CoinError::Insufficient {
                need: 60_000,
                have: 50_000
            })
        );
        let r = select_yec(&v, 3_000, true).unwrap();
        assert_eq!(r[0].outpoint.n, 4, "reserve first when allowed");
        assert!(select_yec(&v, 0, false).unwrap().is_empty());
    }
}
