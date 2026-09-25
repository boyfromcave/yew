//! The broadcast gate (D-W-5): every `confirm` passes through [`confirm`] and there is no
//! override — no "send anyway" parameter, no debug flag, no `cfg(test)` hook.
//!
//! Two layers, both mandatory:
//!
//! 1. **Local** ([`check`]), on the raw bytes about to be sent: every input is a known unspent
//!    output of this wallet of a class the path may spend — the YEC path `YEC` / `FEE_RESERVE`
//!    only, the YED transfer path `TOKEN` / `YEC` / `FEE_RESERVE` — never `PENDING_TOKEN`,
//!    `VAULT`, `CARRIER`, `HELD`, `UNKNOWN_P2SH`, `FOREIGN` or unknown; transparent-only; the
//!    YEC path carries no `OP_RETURN`, the transfer path carries exactly one that decodes as a
//!    TRANSFER and spends at least one token.
//! 2. **Remote** (client contract rule 4, lightwalletd plan §5): `ValidateRawTransaction` on the
//!    same bytes, refused unless `valid && verdict == "ok" && burned == 0 && !wouldBeRejected`.
//!    The refusal carries the node's verdict text. When the server offers no Yellowback service
//!    ([`Validator::Absent`], contract rule 1) the YED path is refused outright and the YEC path
//!    proceeds on the local layer alone: without `GetAddressTokens` nothing is class `TOKEN`,
//!    every `TOKEN_VALUE` output is `HELD`, and the local layer already refuses all of them.
//!    [`Validator`] is built only by probing the server ([`Validator::detect`]); nothing else
//!    constructs an `Absent`.

use thiserror::Error;

use crate::coins::UtxoClass;
use crate::net::{Availability, NetError, Validation, YellowbackClient};
use crate::payload::{self, Payload};
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
    /// An input of a class this path must never spend.
    #[error("gate: input {outpoint} is class {class}; spending it on the {path} path would burn or strand it")]
    ForbiddenInput {
        /// The input.
        outpoint: String,
        /// Its class name.
        class: &'static str,
        /// The path name.
        path: &'static str,
    },
    /// An `OP_RETURN` output on the YEC path.
    #[error("gate: output {0} is OP_RETURN; the YEC path carries no payload")]
    PayloadOnYecPath(usize),
    /// The transfer path has no decodable TRANSFER payload.
    #[error("gate: the transaction carries no TRANSFER payload")]
    NoTransferPayload,
    /// The transfer path spends no token.
    #[error("gate: a TRANSFER must spend at least one TOKEN input")]
    NoTokenInput,
    /// The server offers no Yellowback service, so nothing YED can be validated or sent.
    #[error("gate: the server offers no Yellowback service; YED cannot be sent through it")]
    YellowbackAbsent,
    /// `ValidateRawTransaction` could not be reached or answered with an error.
    #[error("gate: ValidateRawTransaction failed: {0}")]
    Validate(String),
    /// The node's dry run refused the transaction (the one check between a bug and a burn).
    #[error("gate: refused by the node's dry run: verdict {verdict:?}, valid {valid}, burned {burned} cents, wouldBeRejected {would_be_rejected}, {unconfirmed_inputs} unconfirmed input(s)")]
    Refused {
        /// `valid`.
        valid: bool,
        /// `verdict`, the node's identifier.
        verdict: String,
        /// `burned`.
        burned: i64,
        /// `wouldBeRejected`.
        would_be_rejected: bool,
        /// `unconfirmedInputs.len()`.
        unconfirmed_inputs: usize,
    },
}

/// Which builder produced the transaction; selects the local rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// A plain YEC send (`build::yec_send`).
    Yec,
    /// A YED transfer (`build::yed_transfer`).
    YedTransfer,
}

impl Path {
    fn name(self) -> &'static str {
        match self {
            Path::Yec => "YEC",
            Path::YedTransfer => "YED transfer",
        }
    }

    fn allows(self, c: UtxoClass) -> bool {
        match self {
            Path::Yec => c.yec_spendable(),
            Path::YedTransfer => c.transfer_spendable(),
        }
    }
}

/// The local layer: check `raw` for `path`, classifying inputs with `class_of` (the store's
/// UTXO table). Returns the parsed transaction on success.
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
    let mut tokens = 0;
    for i in &tx.vin {
        match class_of(&i.prevout) {
            None => return Err(GateError::UnknownInput(i.prevout.display())),
            Some(c) if path.allows(c) => {
                if c == UtxoClass::Token {
                    tokens += 1;
                }
            }
            Some(c) => {
                return Err(GateError::ForbiddenInput {
                    outpoint: i.prevout.display(),
                    class: c.as_str(),
                    path: path.name(),
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
        Path::YedTransfer => {
            match payload::find_payload(&tx) {
                Some(fp) if matches!(fp.payload, Payload::Transfer { .. }) => {}
                _ => return Err(GateError::NoTransferPayload),
            }
            if tokens == 0 {
                return Err(GateError::NoTokenInput);
            }
        }
    }
    Ok(tx)
}

/// The remote layer's rule on a [`Validation`] (contract rule 4, D-W-5).
pub fn accept(v: &Validation) -> Result<(), GateError> {
    if v.valid && v.verdict == "ok" && v.burned == 0 && !v.would_be_rejected {
        Ok(())
    } else {
        Err(GateError::Refused {
            valid: v.valid,
            verdict: v.verdict.clone(),
            burned: v.burned,
            would_be_rejected: v.would_be_rejected,
            unconfirmed_inputs: v.unconfirmed_inputs.len(),
        })
    }
}

/// The remote validator: the server's `YellowbackStreamer`, or the fact that there is none.
/// Built only by [`Validator::detect`].
#[derive(Debug)]
pub enum Validator {
    /// The server answered `UNIMPLEMENTED` to `GetYellowbackInfo` (contract rule 1).
    Absent,
    /// The server offers the service with a known `rpcversion`.
    Remote(YellowbackClient),
}

impl Validator {
    /// Probe `client` (contract rule 1) and wrap it. An unknown `rpcversion` is an error, not
    /// an `Absent`: a server that speaks a contract this build does not know is refused.
    pub async fn detect(
        mut client: YellowbackClient,
    ) -> Result<(Validator, Availability), NetError> {
        let a = client.probe().await?;
        Ok(match a {
            Availability::Absent => (Validator::Absent, a),
            Availability::Present { .. } => (Validator::Remote(client), a),
        })
    }

    /// The client, when present.
    pub fn client_mut(&mut self) -> Option<&mut YellowbackClient> {
        match self {
            Validator::Remote(c) => Some(c),
            Validator::Absent => None,
        }
    }
}

/// `confirm`: both layers on `raw`. Returns the parsed transaction and the node's validation
/// (`None` only on the YEC path against a server without Yellowback).
pub async fn confirm(
    validator: &mut Validator,
    path: Path,
    raw: &[u8],
    class_of: impl Fn(&OutPoint) -> Option<UtxoClass>,
) -> Result<(Transaction, Option<Validation>), GateError> {
    let tx = check(path, raw, class_of)?;
    let client = match validator {
        Validator::Remote(c) => c,
        Validator::Absent => {
            return match path {
                Path::Yec => Ok((tx, None)),
                Path::YedTransfer => Err(GateError::YellowbackAbsent),
            }
        }
    };
    let v = client
        .validate_raw(raw.to_vec())
        .await
        .map_err(|e| GateError::Validate(e.to_string()))?;
    accept(&v)?;
    Ok((tx, Some(v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{encode, Assignment};
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

    fn transfer_payload_script() -> Vec<u8> {
        payload::payload_script(
            &encode(&Payload::Transfer {
                assignments: vec![Assignment {
                    vout: 0,
                    cents: 100,
                }],
            })
            .unwrap(),
        )
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
                script_pubkey: transfer_payload_script(),
            });
        }
        t.serialize().unwrap()
    }

    /// Plan §6.1 item 3: on random coin sets, no YEC-path transaction that spends a
    /// TOKEN, PENDING_TOKEN, VAULT, CARRIER (or HELD / P2SH / FOREIGN / unknown) input ever
    /// passes, and every transaction over YEC / FEE_RESERVE inputs only does; on the transfer
    /// path only TOKEN / YEC / FEE_RESERVE inputs pass, with a payload and a token.
    #[test]
    fn property_no_path_spends_a_forbidden_class() {
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
            let op_return = rng.below(4) == 0;
            let raw = raw_spending(&inputs, op_return);
            let class = |op: &OutPoint| coins.get(op).copied();

            let yec = check(Path::Yec, &raw, class);
            let yec_ok = inputs
                .iter()
                .all(|op| class(op).map(|c| c.yec_spendable()).unwrap_or(false));
            assert_eq!(
                yec.is_ok(),
                yec_ok && !op_return,
                "YEC {inputs:?} {:?}",
                yec.err()
            );

            let yed = check(Path::YedTransfer, &raw, class);
            let yed_ok = inputs
                .iter()
                .all(|op| class(op).map(|c| c.transfer_spendable()).unwrap_or(false));
            let has_token = inputs.iter().any(|op| class(op) == Some(UtxoClass::Token));
            assert_eq!(
                yed.is_ok(),
                yed_ok && has_token && op_return,
                "YED {inputs:?} {:?}",
                yed.err()
            );
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
                class: "TOKEN",
                path: "YEC"
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
                class: "HELD",
                path: "YEC"
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
        let unknown = OutPoint {
            txid: [2; 32],
            n: 0,
        };
        assert_eq!(
            check(
                Path::Yec,
                &raw_spending(&[unknown], false),
                classes(UtxoClass::Yec)
            )
            .unwrap_err(),
            GateError::UnknownInput(unknown.display())
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
        // The transfer path.
        assert_eq!(
            check(
                Path::YedTransfer,
                &raw_spending(&[a], false),
                classes(UtxoClass::Token)
            )
            .unwrap_err(),
            GateError::NoTransferPayload
        );
        assert_eq!(
            check(
                Path::YedTransfer,
                &raw_spending(&[a], true),
                classes(UtxoClass::Yec)
            )
            .unwrap_err(),
            GateError::NoTokenInput
        );
        assert_eq!(
            check(
                Path::YedTransfer,
                &raw_spending(&[a], true),
                classes(UtxoClass::PendingToken)
            )
            .unwrap_err(),
            GateError::ForbiddenInput {
                outpoint: a.display(),
                class: "PENDING_TOKEN",
                path: "YED transfer"
            }
        );
        assert!(check(
            Path::YedTransfer,
            &raw_spending(&[a], true),
            classes(UtxoClass::Token)
        )
        .is_ok());
    }

    #[test]
    fn remote_rule_is_all_four_conditions() {
        let ok = Validation {
            valid: true,
            verdict: "ok".into(),
            burned: 0,
            would_be_rejected: false,
            block_valid: true,
            mempool_expiry_ok: true,
            unconfirmed_inputs: vec![],
            tx_type: "transfer".into(),
            path: String::new(),
            yed_in: 100,
            yed_out: 100,
            fee_zat: 0,
            payee: String::new(),
        };
        assert!(accept(&ok).is_ok());
        for bad in [
            Validation {
                valid: false,
                ..ok.clone()
            },
            Validation {
                verdict: "xfer-conservation".into(),
                ..ok.clone()
            },
            Validation {
                burned: 1,
                ..ok.clone()
            },
            Validation {
                would_be_rejected: true,
                ..ok.clone()
            },
        ] {
            let e = accept(&bad).unwrap_err();
            assert!(matches!(e, GateError::Refused { .. }), "{e}");
            assert!(e.to_string().contains("verdict"));
        }
    }
}
