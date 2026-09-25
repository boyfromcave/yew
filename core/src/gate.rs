//! The broadcast gate (D-W-5): every `confirm` passes through [`confirm`] and there is no
//! override — no "send anyway" parameter, no debug flag, no `cfg(test)` hook.
//!
//! Two layers, both mandatory:
//!
//! 1. **Local** ([`check`]), on the raw bytes about to be sent: every input is a known unspent
//!    output of this wallet of a class the path may spend — the YEC and carrier-funding paths
//!    `YEC` / `FEE_RESERVE` only, the YED transfer path `TOKEN` / `YEC` / `FEE_RESERVE`, the
//!    mint path those plus exactly one `CARRIER` at `vin[last]`, the redeem path the own
//!    `VAULT` at `vin[0]` plus `TOKEN`s, the claim path the named foreign vault at `vin[0]`
//!    plus `TOKEN`s and one `CARRIER` at `vin[last]`, the sweep path `CARRIER`s only — never
//!    `PENDING_TOKEN`, `HELD`, `UNKNOWN_P2SH`, `FOREIGN` or unknown; transparent-only; the
//!    payload matches the path (none on the YEC, carrier and sweep paths; exactly one TRANSFER,
//!    MINT or REDEEM on the others, the transfer path spending at least one token).
//! 2. **Remote** (client contract rule 4, lightwalletd plan §5): `ValidateRawTransaction` on the
//!    same bytes, refused unless `valid && verdict == "ok" && burned == <the planned burn> &&
//!    !wouldBeRejected` — the planned burn is 0 on every path but redeem and claim, which burn
//!    the debt (plus a sub-dollar remainder) by design. The refusal carries the node's verdict
//!    text. When the server offers no Yellowback service
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
    /// The path needs a payload of one type and the transaction carries none of that type.
    #[error("gate: the transaction carries no {0} payload")]
    NoPayload(&'static str),
    /// The path needs exactly one carrier input at `vin[last]`.
    #[error("gate: the {0} path needs exactly one CARRIER input, as the last input")]
    CarrierShape(&'static str),
    /// The path needs the vault at `vin[0]`.
    #[error("gate: the {0} path needs the vault {1} at vin[0]")]
    VaultShape(&'static str, String),
    /// The carrier-funding path pays `vout[0]` as something other than a P2SH carrier.
    #[error("gate: the carrier path needs vout[0] = P2SH of CARRIER_VALUE")]
    CarrierOutput,
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
    /// The carrier funding transaction of a mint or claim (`build::mint::carrier_step`).
    Carrier,
    /// The MINT (`build::mint`).
    Mint,
    /// The owner-path REDEEM of an ACTIVE own vault (`build::redeem`).
    Redeem,
    /// The owner-path release of a VOID own vault: no payload, no burn (`build::redeem`).
    Release,
    /// The CLAIM of another wallet's vault, named here since it is not an own output.
    Claim(OutPoint),
    /// The sweep of lapsed carriers (`build::mint::sweep`).
    Sweep,
}

impl Path {
    fn name(self) -> &'static str {
        match self {
            Path::Yec => "YEC",
            Path::YedTransfer => "YED transfer",
            Path::Carrier => "carrier",
            Path::Mint => "mint",
            Path::Redeem => "redeem",
            Path::Release => "release",
            Path::Claim(_) => "claim",
            Path::Sweep => "sweep",
        }
    }

    fn allows(self, c: UtxoClass) -> bool {
        match self {
            Path::Yec | Path::Carrier => c.yec_spendable(),
            Path::YedTransfer => c.transfer_spendable(),
            Path::Mint => c.mint_spendable(),
            Path::Redeem => c.redeem_spendable(),
            Path::Release => c == UtxoClass::Vault,
            Path::Claim(_) => c.claim_spendable(),
            Path::Sweep => c == UtxoClass::Carrier,
        }
    }

    /// True when the path's YED side is the node's business (the remote layer is mandatory).
    fn needs_yellowback(self) -> bool {
        !matches!(self, Path::Yec)
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
    let mut carriers: Vec<usize> = Vec::new();
    for (n, i) in tx.vin.iter().enumerate() {
        // The claim path's vault is another wallet's output: it is named, never classified.
        if let Path::Claim(vault) = path {
            if n == 0 {
                if i.prevout != vault {
                    return Err(GateError::VaultShape(path.name(), vault.display()));
                }
                continue;
            }
        }
        match class_of(&i.prevout) {
            None => return Err(GateError::UnknownInput(i.prevout.display())),
            Some(c) if path.allows(c) => {
                if c == UtxoClass::Token {
                    tokens += 1;
                }
                if c == UtxoClass::Carrier {
                    carriers.push(n);
                }
                if c == UtxoClass::Vault && n != 0 {
                    return Err(GateError::VaultShape(path.name(), i.prevout.display()));
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
    let no_payload = |tx: &Transaction| -> Result<(), GateError> {
        if let Some(i) = tx
            .vout
            .iter()
            .position(|o| script::is_op_return(&o.script_pubkey))
        {
            return Err(GateError::PayloadOnYecPath(i));
        }
        Ok(())
    };
    let one_carrier_last = |name: &'static str| -> Result<(), GateError> {
        if carriers.len() != 1 || carriers[0] != tx.vin.len() - 1 {
            return Err(GateError::CarrierShape(name));
        }
        Ok(())
    };
    match path {
        Path::Yec => no_payload(&tx)?,
        Path::Carrier => {
            no_payload(&tx)?;
            let ok = tx
                .vout
                .first()
                .map(|o| {
                    o.value == crate::params::CARRIER_VALUE
                        && script::p2sh_hash(&o.script_pubkey).is_some()
                })
                .unwrap_or(false);
            if !ok {
                return Err(GateError::CarrierOutput);
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
        Path::Mint => {
            match payload::find_payload(&tx) {
                Some(fp) if matches!(fp.payload, Payload::Mint { .. }) => {}
                _ => return Err(GateError::NoPayload("MINT")),
            }
            one_carrier_last("mint")?;
        }
        Path::Redeem | Path::Claim(_) => {
            match payload::find_payload(&tx) {
                Some(fp) if matches!(fp.payload, Payload::Redeem { .. }) => {}
                _ => return Err(GateError::NoPayload("REDEEM")),
            }
            if path == Path::Redeem {
                if class_of(&tx.vin[0].prevout) != Some(UtxoClass::Vault) {
                    return Err(GateError::VaultShape("redeem", tx.vin[0].prevout.display()));
                }
                if !carriers.is_empty() {
                    return Err(GateError::CarrierShape("redeem"));
                }
            } else {
                one_carrier_last("claim")?;
            }
        }
        Path::Release => {
            no_payload(&tx)?;
            if tx.vin.len() != 1 {
                return Err(GateError::VaultShape(
                    "release",
                    tx.vin[0].prevout.display(),
                ));
            }
        }
        Path::Sweep => no_payload(&tx)?,
    }
    Ok(tx)
}

/// The remote layer's rule on a [`Validation`] (contract rule 4, D-W-5): `burned` must equal
/// `planned_burn` — zero everywhere but on a redeem or claim, whose plan states the debt it
/// burns (W4: a redeem the node answered `ok, burned 10000` was refused by the `== 0` rule).
pub fn accept(v: &Validation, planned_burn: i64) -> Result<(), GateError> {
    if v.valid && v.verdict == "ok" && v.burned == planned_burn && !v.would_be_rejected {
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

/// `confirm`: both layers on `raw`, no burn planned. Returns the parsed transaction and the
/// node's validation (`None` only on the YEC path against a server without Yellowback).
pub async fn confirm(
    validator: &mut Validator,
    path: Path,
    raw: &[u8],
    class_of: impl Fn(&OutPoint) -> Option<UtxoClass>,
) -> Result<(Transaction, Option<Validation>), GateError> {
    confirm_burning(validator, path, raw, class_of, 0).await
}

/// [`confirm`] for a redeem or claim: the node's `burned` must equal `planned_burn` cents.
pub async fn confirm_burning(
    validator: &mut Validator,
    path: Path,
    raw: &[u8],
    class_of: impl Fn(&OutPoint) -> Option<UtxoClass>,
    planned_burn: i64,
) -> Result<(Transaction, Option<Validation>), GateError> {
    let tx = check(path, raw, class_of)?;
    let client = match validator {
        Validator::Remote(c) => c,
        Validator::Absent => {
            return if path.needs_yellowback() {
                Err(GateError::YellowbackAbsent)
            } else {
                Ok((tx, None))
            }
        }
    };
    let v = client
        .validate_raw(raw.to_vec())
        .await
        .map_err(|e| GateError::Validate(e.to_string()))?;
    accept(&v, planned_burn)?;
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
        assert!(accept(&ok, 0).is_ok());
        // A redeem burns what its plan says, no more, no less.
        let redeem = Validation {
            burned: 10_000,
            tx_type: "redeem".into(),
            ..ok.clone()
        };
        assert!(accept(&redeem, 10_000).is_ok());
        assert!(accept(&redeem, 0).is_err());
        assert!(accept(&redeem, 9_999).is_err());
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
            let e = accept(&bad, 0).unwrap_err();
            assert!(matches!(e, GateError::Refused { .. }), "{e}");
            assert!(e.to_string().contains("verdict"));
        }
    }

    #[test]
    fn w4_paths_shapes() {
        let vault = OutPoint {
            txid: [0x11; 32],
            n: 0,
        };
        let token = OutPoint {
            txid: [0x22; 32],
            n: 1,
        };
        let carrier = OutPoint {
            txid: [0x33; 32],
            n: 0,
        };
        let yec = OutPoint {
            txid: [0x44; 32],
            n: 2,
        };
        let foreign_vault = OutPoint {
            txid: [0x55; 32],
            n: 0,
        };
        let classes: HashMap<OutPoint, UtxoClass> = [
            (vault, UtxoClass::Vault),
            (token, UtxoClass::Token),
            (carrier, UtxoClass::Carrier),
            (yec, UtxoClass::Yec),
        ]
        .into_iter()
        .collect();
        let class = |op: &OutPoint| classes.get(op).copied();
        let build = |inputs: &[OutPoint], payload: Option<Payload>, first_out: Option<TxOut>| {
            let mut t = Transaction::new_v4();
            for op in inputs {
                t.vin.push(TxIn::new(*op));
            }
            t.vout.push(first_out.unwrap_or(TxOut {
                value: 1,
                script_pubkey: script::p2pkh_script(&[3; 20]),
            }));
            if let Some(p) = payload {
                t.vout.push(TxOut {
                    value: 0,
                    script_pubkey: payload::payload_script(&encode(&p).unwrap()),
                });
            }
            t.serialize().unwrap()
        };
        let mint_p = Payload::Mint {
            term_class: 0,
            cents: 10_000,
            lock_height: 10,
            ref_height: 5,
            owner_key: [2; 33],
            fee_vout: 0xff,
            attest_fee_vout: 0xff,
        };
        let redeem_p = Payload::Redeem {
            ref_height: 5,
            fee_vout: 0xff,
            attest_fee_vout: 0xff,
            assignments: vec![],
        };
        // Mint: YEC then the carrier last, one MINT payload.
        assert!(check(
            Path::Mint,
            &build(&[yec, carrier], Some(mint_p.clone()), None),
            class
        )
        .is_ok());
        assert_eq!(
            check(
                Path::Mint,
                &build(&[carrier, yec], Some(mint_p.clone()), None),
                class
            )
            .unwrap_err(),
            GateError::CarrierShape("mint")
        );
        assert_eq!(
            check(
                Path::Mint,
                &build(&[yec], Some(mint_p.clone()), None),
                class
            )
            .unwrap_err(),
            GateError::CarrierShape("mint")
        );
        assert_eq!(
            check(
                Path::Mint,
                &build(&[yec, carrier], Some(redeem_p.clone()), None),
                class
            )
            .unwrap_err(),
            GateError::NoPayload("MINT")
        );
        assert!(matches!(
            check(
                Path::Mint,
                &build(&[token, carrier], Some(mint_p.clone()), None),
                class
            )
            .unwrap_err(),
            GateError::ForbiddenInput { class: "TOKEN", .. }
        ));
        // Carrier funding: YEC inputs, vout[0] a P2SH of CARRIER_VALUE, no payload.
        let p2sh = TxOut {
            value: crate::params::CARRIER_VALUE,
            script_pubkey: script::p2sh_script(&[9; 20]),
        };
        assert!(check(
            Path::Carrier,
            &build(&[yec], None, Some(p2sh.clone())),
            class
        )
        .is_ok());
        assert_eq!(
            check(Path::Carrier, &build(&[yec], None, None), class).unwrap_err(),
            GateError::CarrierOutput
        );
        assert!(matches!(
            check(Path::Carrier, &build(&[carrier], None, Some(p2sh)), class).unwrap_err(),
            GateError::ForbiddenInput {
                class: "CARRIER",
                ..
            }
        ));
        // Redeem: the own vault first, tokens, a REDEEM payload, no carrier.
        assert!(check(
            Path::Redeem,
            &build(&[vault, token], Some(redeem_p.clone()), None),
            class
        )
        .is_ok());
        assert!(matches!(
            check(
                Path::Redeem,
                &build(&[token, vault], Some(redeem_p.clone()), None),
                class
            )
            .unwrap_err(),
            GateError::VaultShape("redeem", _)
        ));
        assert!(matches!(
            check(
                Path::Redeem,
                &build(&[vault, token, carrier], Some(redeem_p.clone()), None),
                class
            )
            .unwrap_err(),
            GateError::ForbiddenInput {
                class: "CARRIER",
                ..
            }
        ));
        assert!(matches!(
            check(
                Path::Redeem,
                &build(&[vault, yec], Some(redeem_p.clone()), None),
                class
            )
            .unwrap_err(),
            GateError::ForbiddenInput { class: "YEC", .. }
        ));
        // Release: the vault alone, no payload.
        assert!(check(Path::Release, &build(&[vault], None, None), class).is_ok());
        assert!(check(Path::Release, &build(&[vault, token], None, None), class).is_err());
        assert!(check(
            Path::Release,
            &build(&[vault], Some(redeem_p.clone()), None),
            class
        )
        .is_err());
        // Claim: the named foreign vault first, tokens, the carrier last.
        let claim = Path::Claim(foreign_vault);
        assert!(check(
            claim,
            &build(
                &[foreign_vault, token, carrier],
                Some(redeem_p.clone()),
                None
            ),
            class
        )
        .is_ok());
        assert!(matches!(
            check(
                claim,
                &build(&[vault, token, carrier], Some(redeem_p.clone()), None),
                class
            )
            .unwrap_err(),
            GateError::VaultShape("claim", _)
        ));
        assert_eq!(
            check(
                claim,
                &build(
                    &[foreign_vault, carrier, token],
                    Some(redeem_p.clone()),
                    None
                ),
                class
            )
            .unwrap_err(),
            GateError::CarrierShape("claim")
        );
        assert!(matches!(
            check(
                claim,
                &build(&[foreign_vault, yec, carrier], Some(redeem_p), None),
                class
            )
            .unwrap_err(),
            GateError::ForbiddenInput { class: "YEC", .. }
        ));
        // Sweep: carriers only, no payload.
        assert!(check(Path::Sweep, &build(&[carrier], None, None), class).is_ok());
        assert!(check(Path::Sweep, &build(&[carrier, yec], None, None), class).is_err());
        assert!(check(Path::Sweep, &build(&[carrier], Some(mint_p), None), class).is_err());
    }
}
