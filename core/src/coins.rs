//! UTXO classes (plan §3.7, D-W-12), the classifier, the fee reserve and `SelectYec`.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp:395-420` (`SelectYec`:
//! smallest-first, skip every P2SH, skip every token and vault); `wallet.cpp:410-427`
//! (`PreLock`: MINT ⇒ `vout[1]`, TRANSFER/REDEEM ⇒ the payload's assignments) and
//! `wallet.cpp:401-408` (`LockOwn`). The fee reserve is YEW's addition.
//!
//! **The TOKEN rule (W2, D-W-8).** `GetAddressTokens` is the *only* source of the TOKEN class.
//! An own P2PKH output of exactly `TOKEN_VALUE` that the server does not list as a token is
//! class **HELD** — never YEC — because the classifier cannot tell "10,000 zat of dust" from
//! "a token the server has not indexed yet" (a VOID mint's `vout[1]`, a transaction the index
//! is still digesting, a server without Yellowback). A HELD output is unspendable on every
//! path; losing a send to "sync first" is acceptable, burning is not (§3.7). W1 applied the
//! same rule to every `TOKEN_VALUE` output; W2 narrows it to the ones the server did not claim.
//!
//! **PENDING_TOKEN** (`PreLock`): an output of a transaction *this wallet* broadcast and has not
//! yet seen confirmed, at the vout the payload assigns cents to. Nothing may spend it; it counts
//! as "pending YED", in neither balance, until the server lists it as a token (then TOKEN) or
//! the transaction confirms without it (then HELD).

use std::collections::HashMap;

use thiserror::Error;

use crate::params::{reserve_zat, TOKEN_VALUE};
use crate::payload::{self, Payload};
use crate::script;
use crate::tx::{OutPoint, Transaction};

/// The class of a UTXO (plan §3.7). Every UTXO the wallet knows is in exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UtxoClass {
    /// A confirmed P2PKH output to an own key: YEC available.
    Yec,
    /// A YEC output set aside for YED fees.
    FeeReserve,
    /// A YED token listed by `GetAddressTokens`. YED input only.
    Token,
    /// A token output the app broadcast, not yet confirmed by the server. Nothing.
    PendingToken,
    /// `vout[0]` of an own MINT (W4). REDEEM only.
    Vault,
    /// A P2SH carrier the app created (W4). Its paired transaction only.
    Carrier,
    /// Any P2SH the app did not create. Hidden, never spent.
    UnknownP2sh,
    /// An own P2PKH output of exactly `TOKEN_VALUE` the server does not list as a token:
    /// unclassifiable, unspendable on every path (module doc).
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

    /// True for the classes a **YED transfer** may spend: its YED inputs are `Token`, its fee
    /// inputs `Yec` / `FeeReserve`. Never a pending token, a vault, a carrier, a held output.
    pub fn transfer_spendable(self) -> bool {
        matches!(
            self,
            UtxoClass::Token | UtxoClass::Yec | UtxoClass::FeeReserve
        )
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
    /// The height it was mined at (0 while pending).
    pub height: u64,
    /// The class.
    pub class: UtxoClass,
    /// The YED cents (`Token` from `GetAddressTokens`, `PendingToken` from the payload); 0
    /// for every other class.
    pub cents: u64,
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

/// The classifier for an output the server listed for an own address (plan §3.7):
/// any P2SH → `UnknownP2sh` (W4 will recognise vaults and carriers); P2PKH to an own key
/// listed in `tokens` → `Token` (with its cents); P2PKH to an own key of exactly
/// `TOKEN_VALUE` otherwise → `Held` (module doc); any other P2PKH to an own key → `Yec`;
/// anything else → `Foreign`. Returns `(class, cents)`.
pub fn classify(
    outpoint: &OutPoint,
    script: &[u8],
    value: i64,
    is_own_key: impl Fn(&[u8; 20]) -> bool,
    tokens: &HashMap<OutPoint, u64>,
) -> (UtxoClass, u64) {
    if script::p2sh_hash(script).is_some() {
        return (UtxoClass::UnknownP2sh, 0);
    }
    match script::p2pkh_hash(script) {
        Some(h) if is_own_key(&h) => {
            if let Some(&cents) = tokens.get(outpoint) {
                (UtxoClass::Token, cents)
            } else if value == TOKEN_VALUE {
                (UtxoClass::Held, 0)
            } else {
                (UtxoClass::Yec, 0)
            }
        }
        _ => (UtxoClass::Foreign, 0),
    }
}

/// `PreLock` (`wallet.cpp:410-427`): the outputs of `tx` — a transaction this wallet broadcast
/// — that its payload marks as YED for own keys: MINT ⇒ `vout[1]` (the minted cents),
/// TRANSFER / REDEEM ⇒ every assigned vout paid to an own key. Returns `(vout, cents)`.
/// Without a payload the transaction creates no YED and the list is empty.
pub fn pre_lock(tx: &Transaction, is_own_key: impl Fn(&[u8; 20]) -> bool) -> Vec<(u32, u64)> {
    let own = |n: usize| -> bool {
        tx.vout
            .get(n)
            .and_then(|o| script::p2pkh_hash(&o.script_pubkey))
            .map(|h| is_own_key(&h))
            .unwrap_or(false)
    };
    let fp = match payload::find_payload(tx) {
        Some(fp) => fp,
        None => return Vec::new(),
    };
    match &fp.payload {
        Payload::Mint { cents, .. } => {
            if tx.vout.len() > 1 && own(1) {
                vec![(1, *cents as u64)]
            } else {
                Vec::new()
            }
        }
        Payload::Transfer { assignments } | Payload::Redeem { assignments, .. } => assignments
            .iter()
            .filter(|a| own(a.vout as usize))
            .map(|a| (a.vout as u32, a.cents as u64))
            .collect(),
        _ => Vec::new(),
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

/// `RankedCoins` (`txbuilder.cpp:501-510`): the spendable YED coins in the selector's canonical
/// order `(cents, txid, vout)` — the txid compared as its internal bytes, as `uint256::operator<`
/// does — so two wallets with the same coins select the same inputs (H1).
pub fn ranked_tokens(utxos: &[Utxo]) -> Vec<Utxo> {
    let mut coins: Vec<Utxo> = utxos
        .iter()
        .filter(|u| u.class == UtxoClass::Token)
        .cloned()
        .collect();
    coins.sort_by(|a, b| {
        a.cents
            .cmp(&b.cents)
            .then(a.outpoint.txid.cmp(&b.outpoint.txid))
            .then(a.outpoint.n.cmp(&b.outpoint.n))
    });
    coins
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

/// The two YED numbers: `(cents, pending cents)` — `Token` and `PendingToken` respectively.
pub fn yed_balances(utxos: &[Utxo]) -> (u64, u64) {
    let mut cents = 0;
    let mut pending = 0;
    for u in utxos {
        match u.class {
            UtxoClass::Token => cents += u.cents,
            UtxoClass::PendingToken => pending += u.cents,
            _ => {}
        }
    }
    (cents, pending)
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
            cents: 0,
        }
    }

    #[test]
    fn classifier_token_held_yec_p2sh_foreign() {
        let own = [1u8; 20];
        let is_own = |h: &[u8; 20]| *h == own;
        let op = OutPoint {
            txid: [9; 32],
            n: 1,
        };
        let listed: HashMap<OutPoint, u64> = [(op, 500u64)].into_iter().collect();
        let none = HashMap::new();
        let p2pkh = script::p2pkh_script(&own);
        assert_eq!(
            classify(&op, &p2pkh, 50_000, is_own, &none),
            (UtxoClass::Yec, 0)
        );
        assert_eq!(
            classify(&op, &p2pkh, TOKEN_VALUE, is_own, &none),
            (UtxoClass::Held, 0)
        );
        assert_eq!(
            classify(&op, &p2pkh, TOKEN_VALUE, is_own, &listed),
            (UtxoClass::Token, 500)
        );
        // The server's word wins even over an odd value.
        assert_eq!(
            classify(&op, &p2pkh, 12_345, is_own, &listed),
            (UtxoClass::Token, 500)
        );
        let other = OutPoint {
            txid: [9; 32],
            n: 2,
        };
        assert_eq!(
            classify(&other, &p2pkh, TOKEN_VALUE, is_own, &listed),
            (UtxoClass::Held, 0)
        );
        assert_eq!(
            classify(&op, &script::p2sh_script(&own), 50_000, is_own, &listed),
            (UtxoClass::UnknownP2sh, 0)
        );
        assert_eq!(
            classify(
                &op,
                &script::p2pkh_script(&[2; 20]),
                50_000,
                is_own,
                &listed
            ),
            (UtxoClass::Foreign, 0)
        );
        assert_eq!(
            classify(&op, &[0x6a, 0x01, 0x00], 0, is_own, &listed),
            (UtxoClass::Foreign, 0)
        );
        for c in [
            UtxoClass::Yec,
            UtxoClass::Held,
            UtxoClass::Token,
            UtxoClass::PendingToken,
            UtxoClass::Vault,
        ] {
            assert_eq!(UtxoClass::parse(c.as_str()), Some(c));
        }
        assert!(UtxoClass::Token.transfer_spendable());
        assert!(!UtxoClass::PendingToken.transfer_spendable());
        assert!(!UtxoClass::Held.transfer_spendable());
        assert!(!UtxoClass::Token.yec_spendable());
    }

    #[test]
    fn pre_lock_rule() {
        use crate::payload::{encode, Assignment};
        use crate::tx::TxOut;
        let own = [1u8; 20];
        let is_own = |h: &[u8; 20]| *h == own;
        let mine = script::p2pkh_script(&own);
        let theirs = script::p2pkh_script(&[2; 20]);
        // TRANSFER: vout 0 theirs (500), vout 1 mine (250), payload at 2.
        let mut tx = Transaction::new_v4();
        tx.vout.push(TxOut {
            value: TOKEN_VALUE,
            script_pubkey: theirs.clone(),
        });
        tx.vout.push(TxOut {
            value: TOKEN_VALUE,
            script_pubkey: mine.clone(),
        });
        let p = Payload::Transfer {
            assignments: vec![
                Assignment {
                    vout: 0,
                    cents: 500,
                },
                Assignment {
                    vout: 1,
                    cents: 250,
                },
            ],
        };
        tx.vout.push(TxOut {
            value: 0,
            script_pubkey: payload::payload_script(&encode(&p).unwrap()),
        });
        assert_eq!(pre_lock(&tx, is_own), vec![(1, 250)]);
        // MINT: vout[1] is the token when mine.
        let mut m = Transaction::new_v4();
        m.vout.push(TxOut {
            value: 1_000,
            script_pubkey: script::p2sh_script(&[3; 20]),
        });
        m.vout.push(TxOut {
            value: TOKEN_VALUE,
            script_pubkey: mine.clone(),
        });
        let mp = Payload::Mint {
            term_class: 0,
            cents: 10_000,
            lock_height: 1,
            ref_height: 1,
            owner_key: [2; 33],
            fee_vout: 0xFF,
            attest_fee_vout: 0xFF,
        };
        m.vout.push(TxOut {
            value: 0,
            script_pubkey: payload::payload_script(&encode(&mp).unwrap()),
        });
        assert_eq!(pre_lock(&m, is_own), vec![(1, 10_000)]);
        m.vout[1].script_pubkey = theirs;
        assert!(pre_lock(&m, is_own).is_empty());
        // No payload: nothing.
        let mut plain = Transaction::new_v4();
        plain.vout.push(TxOut {
            value: TOKEN_VALUE,
            script_pubkey: mine,
        });
        assert!(pre_lock(&plain, is_own).is_empty());
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
            u(9, 10_000, UtxoClass::PendingToken),
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

    #[test]
    fn ranked_tokens_and_yed_balances() {
        let mut a = u(1, TOKEN_VALUE, UtxoClass::Token);
        a.cents = 500;
        a.outpoint.txid = [5; 32];
        let mut b = u(2, TOKEN_VALUE, UtxoClass::Token);
        b.cents = 500;
        b.outpoint.txid = [4; 32];
        let mut c = u(3, TOKEN_VALUE, UtxoClass::Token);
        c.cents = 100;
        let mut p = u(4, TOKEN_VALUE, UtxoClass::PendingToken);
        p.cents = 700;
        let v = vec![a.clone(), b.clone(), c.clone(), p, u(5, 9, UtxoClass::Yec)];
        let r = ranked_tokens(&v);
        assert_eq!(r, vec![c, b, a]);
        assert_eq!(yed_balances(&v), (1_100, 700));
    }
}
