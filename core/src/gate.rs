//! The broadcast gate (D-W-5): every `confirm` passes through here and there is no override.
//!
//! Phase W1 covers the **YEC path**: on the raw bytes about to be sent it asserts that every
//! input is of a class a YEC transaction may spend (`YEC`, `FEE_RESERVE`) — never `TOKEN`,
//! `PENDING_TOKEN`, `VAULT`, `CARRIER`, `HELD`, `UNKNOWN_P2SH`, `FOREIGN` or unknown — that the
//! transaction is transparent-only, and that it carries no `OP_RETURN` (a payload has no place
//! on the YEC path). Phase W2 adds the YED path: `ValidateRawTransaction` (`valid && verdict ==
//! "ok" && burned == 0`) and the payload round trip.

use thiserror::Error;

use crate::coins::UtxoClass;
use crate::script;
use crate::tx::{OutPoint, Transaction, TxError};

/// Why the gate refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GateError {
    /// The bytes do not parse as a transaction.
    #[error("gate: unparseable transaction: {0}")]
    Parse(TxError),
    /// Shielded components on a wallet that never makes them.
    #[error("gate: transaction has shielded components")]
    Shielded,
    /// No inputs.
    #[error("gate: transaction has no inputs")]
    NoInputs,
    /// An input the wallet does not know (never seen at sync): it cannot be classified.
    #[error("gate: input {0} is not a known unspent output of this wallet")]
    UnknownInput(String),
    /// An input of a class the YEC path must never spend.
    #[error("gate: input {outpoint} is class {class}; a YEC transaction would burn it")]
    ForbiddenInput {
        /// The input.
        outpoint: String,
        /// Its class name.
        class: &'static str,
    },
    /// An `OP_RETURN` output on the YEC path.
    #[error("gate: output {0} is OP_RETURN; the YEC path carries no payload")]
    PayloadOnYecPath(usize),
}

/// Which builder produced the transaction; selects the rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// A plain YEC send (`build::yec_send`).
    Yec,
}

/// Check `raw` for `path`, classifying inputs with `class_of` (the store's UTXO table).
/// Returns the parsed transaction on success.
pub fn check(
    path: Path,
    raw: &[u8],
    class_of: impl Fn(&OutPoint) -> Option<UtxoClass>,
) -> Result<Transaction, GateError> {
    let (tx, _) = Transaction::parse(raw).map_err(GateError::Parse)?;
    if tx.shielded.any() {
        return Err(GateError::Shielded);
    }
    if tx.vin.is_empty() {
        return Err(GateError::NoInputs);
    }
    for i in &tx.vin {
        match class_of(&i.prevout) {
            None => return Err(GateError::UnknownInput(i.prevout.display())),
            Some(c) if c.yec_spendable() => {}
            Some(c) => {
                return Err(GateError::ForbiddenInput {
                    outpoint: i.prevout.display(),
                    class: c.as_str(),
                })
            }
        }
    }
    match path {
        Path::Yec => {
            if let Some(i) = tx
                .vout
                .iter()
                .position(|o| script::is_op_return(&o.script_pubkey))
            {
                return Err(GateError::PayloadOnYecPath(i));
            }
        }
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{TxIn, TxOut};
    use std::collections::HashMap;

    const ALL: [UtxoClass; 9] = [
        UtxoClass::Yec,
        UtxoClass::FeeReserve,
        UtxoClass::Token,
        UtxoClass::PendingToken,
        UtxoClass::Vault,
        UtxoClass::Carrier,
        UtxoClass::UnknownP2sh,
        UtxoClass::Held,
        UtxoClass::Foreign,
    ];

    /// A tiny deterministic PRNG (xorshift) so the property test needs no crate.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn raw_spending(inputs: &[OutPoint], op_return: bool) -> Vec<u8> {
        let mut t = Transaction::new_v4();
        for op in inputs {
            t.vin.push(TxIn::new(*op));
        }
        t.vout.push(TxOut {
            value: 1,
            script_pubkey: script::p2pkh_script(&[3; 20]),
        });
        if op_return {
            t.vout.push(TxOut {
                value: 0,
                script_pubkey: vec![script::op::OP_RETURN, 0x02, 0x59, 0x42],
            });
        }
        t.serialize().unwrap()
    }

    /// Plan §6.1 item 3: on random coin sets, no YEC-path transaction that spends a
    /// TOKEN, PENDING_TOKEN, VAULT, CARRIER (or HELD / P2SH / FOREIGN / unknown) input ever
    /// passes, and every transaction over YEC / FEE_RESERVE inputs only does.
    #[test]
    fn property_no_yec_path_transaction_spends_a_forbidden_class() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..2000 {
            let n_coins = 1 + rng.below(12) as usize;
            let mut coins: HashMap<OutPoint, UtxoClass> = HashMap::new();
            let mut list = Vec::new();
            for i in 0..n_coins {
                let mut txid = [0u8; 32];
                txid[0] = i as u8;
                txid[1] = rng.below(256) as u8;
                let op = OutPoint {
                    txid,
                    n: rng.below(4) as u32,
                };
                let class = ALL[rng.below(ALL.len() as u64) as usize];
                coins.insert(op, class);
                list.push(op);
            }
            // Sometimes include an outpoint the wallet never saw.
            if rng.below(4) == 0 {
                list.push(OutPoint {
                    txid: [0xee; 32],
                    n: rng.below(4) as u32,
                });
            }
            let n_inputs = 1 + rng.below(list.len() as u64) as usize;
            let inputs: Vec<OutPoint> = (0..n_inputs)
                .map(|_| list[rng.below(list.len() as u64) as usize])
                .collect();
            let op_return = rng.below(8) == 0;
            let raw = raw_spending(&inputs, op_return);
            let result = check(Path::Yec, &raw, |op| coins.get(op).copied());
            let all_ok = inputs
                .iter()
                .all(|op| coins.get(op).map(|c| c.yec_spendable()).unwrap_or(false));
            if all_ok && !op_return {
                assert!(result.is_ok(), "{inputs:?} {:?}", result.err());
            } else {
                assert!(
                    result.is_err(),
                    "{inputs:?} passed with classes {:?}",
                    inputs.iter().map(|o| coins.get(o)).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn specific_refusals() {
        let a = OutPoint {
            txid: [1; 32],
            n: 0,
        };
        let classes = |c: UtxoClass| move |op: &OutPoint| if *op == a { Some(c) } else { None };
        assert_eq!(
            check(
                Path::Yec,
                &raw_spending(&[a], false),
                classes(UtxoClass::Token)
            )
            .unwrap_err(),
            GateError::ForbiddenInput {
                outpoint: a.display(),
                class: "TOKEN"
            }
        );
        assert_eq!(
            check(
                Path::Yec,
                &raw_spending(&[a], false),
                classes(UtxoClass::Held)
            )
            .unwrap_err(),
            GateError::ForbiddenInput {
                outpoint: a.display(),
                class: "HELD"
            }
        );
        assert_eq!(
            check(
                Path::Yec,
                &raw_spending(&[a], true),
                classes(UtxoClass::Yec)
            )
            .unwrap_err(),
            GateError::PayloadOnYecPath(1)
        );
        assert_eq!(
            check(
                Path::Yec,
                &raw_spending(&[], false),
                classes(UtxoClass::Yec)
            )
            .unwrap_err(),
            GateError::NoInputs
        );
        assert_eq!(
            check(
                Path::Yec,
                &raw_spending(
                    &[OutPoint {
                        txid: [2; 32],
                        n: 0
                    }],
                    false
                ),
                classes(UtxoClass::Yec)
            )
            .unwrap_err(),
            GateError::UnknownInput(
                OutPoint {
                    txid: [2; 32],
                    n: 0
                }
                .display()
            )
        );
        assert!(matches!(
            check(Path::Yec, &[1, 2, 3], classes(UtxoClass::Yec)).unwrap_err(),
            GateError::Parse(_)
        ));
        assert!(check(
            Path::Yec,
            &raw_spending(&[a], false),
            classes(UtxoClass::FeeReserve)
        )
        .is_ok());
    }
}
