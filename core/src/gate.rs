// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

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
//!    MINT or REDEEM on the others, the transfer path spending at least one token). The one
//!    path that is not transparent-only is the shielded spend (yew-shielded plan S2): it must
//!    spend Sapling notes and **no transparent input at all** (so no YED, fee-reserve, vault or
//!    carrier output can ever leave through it), carry no Sprout JoinSplit and no `OP_RETURN`,
//!    and pay no transparent output of exactly `TOKEN_VALUE` (it would look like a token).
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
    /// The shielded path's shape rule was broken (transparent input, JoinSplit, no spend,
    /// token-valued output).
    #[error("gate: shielded spend refused: {0}")]
    ShieldedShape(&'static str),
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
    /// The RELEASE of a claim intent paying this wallet (the vault upgrade, U-15, U-23;
    /// `build::release`): the named intent at `vin[0]` (a template output, never classified),
    /// fee inputs `YEC` / `FeeReserve` only, no payload.
    IntentRelease(OutPoint),
    /// A spend of the wallet's Sapling notes (`shielded.rs`): no transparent input.
    Shielded,
    /// A shield (S4, `build::yec_move`): transparent `YEC` inputs only (never the fee reserve,
    /// never anything YED) into Sapling outputs; no Sapling spend.
    Shield,
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
            Path::IntentRelease(_) => "intent release",
            Path::Shielded => "shielded",
            Path::Shield => "shield",
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
            Path::IntentRelease(_) => c.yec_spendable(),
            Path::Shielded => false,
            Path::Shield => c == UtxoClass::Yec,
        }
    }

    /// True when the path's YED side is the node's business (the remote layer is mandatory).
    fn needs_yellowback(self) -> bool {
        !matches!(self, Path::Yec | Path::Shielded | Path::Shield)
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
    if path == Path::Shielded {
        return check_shielded(tx);
    }
    if path == Path::Shield {
        check_shield_shape(&tx)?;
    } else if tx.shielded.any() {
        return Err(GateError::Shielded);
    }
    if tx.vin.is_empty() {
        return Err(GateError::NoInputs);
    }
    let mut tokens = 0;
    let mut carriers: Vec<usize> = Vec::new();
    for (n, i) in tx.vin.iter().enumerate() {
        // The claim path's vault is another wallet's output, and a released intent a template
        // output: each is named, never classified.
        if let Path::Claim(named) | Path::IntentRelease(named) = path {
            if n == 0 {
                if i.prevout != named {
                    return Err(GateError::VaultShape(path.name(), named.display()));
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
        Path::Sweep | Path::Shield | Path::IntentRelease(_) => no_payload(&tx)?,
        Path::Shielded => unreachable!("checked by check_shielded above"),
    }
    Ok(tx)
}

/// The shape half of [`Path::Shield`] (its inputs are classified like every transparent path):
/// Sapling outputs, no Sapling spend, no JoinSplit, no transparent output of exactly
/// `TOKEN_VALUE`.
fn check_shield_shape(tx: &Transaction) -> Result<(), GateError> {
    if tx.shielded.joinsplits > 0 {
        return Err(GateError::ShieldedShape("it carries a Sprout JoinSplit"));
    }
    if tx.shielded.spends > 0 {
        return Err(GateError::ShieldedShape("a shield spends no Sapling note"));
    }
    if tx.shielded.outputs == 0 {
        return Err(GateError::ShieldedShape("a shield makes a Sapling output"));
    }
    if tx
        .vout
        .iter()
        .any(|o| o.value == crate::params::TOKEN_VALUE)
    {
        return Err(GateError::ShieldedShape(
            "a transparent output of exactly TOKEN_VALUE would look like a YED token",
        ));
    }
    Ok(())
}

/// The local layer of [`Path::Shielded`].
fn check_shielded(tx: Transaction) -> Result<Transaction, GateError> {
    if !tx.vin.is_empty() {
        return Err(GateError::ShieldedShape("it spends a transparent input"));
    }
    if tx.shielded.joinsplits > 0 {
        return Err(GateError::ShieldedShape("it carries a Sprout JoinSplit"));
    }
    if tx.shielded.spends == 0 {
        return Err(GateError::ShieldedShape("it spends no Sapling note"));
    }
    if let Some(i) = tx
        .vout
        .iter()
        .position(|o| script::is_op_return(&o.script_pubkey))
    {
        return Err(GateError::PayloadOnYecPath(i));
    }
    if tx
        .vout
        .iter()
        .any(|o| o.value == crate::params::TOKEN_VALUE)
    {
        return Err(GateError::ShieldedShape(
            "a transparent output of exactly TOKEN_VALUE would look like a YED token",
        ));
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
        // The vault upgrade (U-23): the claim's fees come from the claimant's YEC.
        assert!(check(
            claim,
            &build(
                &[foreign_vault, token, yec, carrier],
                Some(redeem_p.clone()),
                None
            ),
            class
        )
        .is_ok());
        // An intent release: the named intent at vin[0], YEC fee inputs, no payload, no token.
        let release = Path::IntentRelease(foreign_vault);
        assert!(check(release, &build(&[foreign_vault, yec], None, None), class).is_ok());
        assert!(check(release, &build(&[yec, foreign_vault], None, None), class).is_err());
        assert!(matches!(
            check(release, &build(&[foreign_vault, token], None, None), class).unwrap_err(),
            GateError::ForbiddenInput { class: "TOKEN", .. }
        ));
        assert!(check(
            release,
            &build(&[foreign_vault, yec], Some(redeem_p), None),
            class
        )
        .is_err());
        // Sweep: carriers only, no payload.
        assert!(check(Path::Sweep, &build(&[carrier], None, None), class).is_ok());
        assert!(check(Path::Sweep, &build(&[carrier, yec], None, None), class).is_err());
        assert!(check(Path::Sweep, &build(&[carrier], Some(mint_p), None), class).is_err());
    }

    /// A v4 transaction with `vin` transparent inputs, the given transparent outputs, `spends`
    /// Sapling spends, one Sapling output and `joinsplits` (always 0 here; a v4 JoinSplit is
    /// refused by the parser's size rules anyway, so the count is written only when 0).
    fn raw_shielded(vin: &[OutPoint], vout: &[(i64, Vec<u8>)], spends: u8) -> Vec<u8> {
        use crate::params::{SAPLING_VERSION_GROUP_ID, TX_HEADER_V4};
        let mut b = Vec::new();
        b.extend_from_slice(&TX_HEADER_V4.to_le_bytes());
        b.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());
        b.push(vin.len() as u8);
        for op in vin {
            b.extend_from_slice(&op.txid);
            b.extend_from_slice(&op.n.to_le_bytes());
            b.push(0); // empty scriptSig
            b.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        b.push(vout.len() as u8);
        for (v, spk) in vout {
            b.extend_from_slice(&v.to_le_bytes());
            b.push(spk.len() as u8);
            b.extend_from_slice(spk);
        }
        b.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
        b.extend_from_slice(&100u32.to_le_bytes()); // nExpiryHeight
        b.extend_from_slice(&0i64.to_le_bytes()); // valueBalance
        b.push(spends);
        b.extend(std::iter::repeat_n(0x11u8, 384 * spends as usize));
        b.push(1);
        b.extend(std::iter::repeat_n(0x22u8, 948));
        b.push(0); // joinsplits
        b.extend(std::iter::repeat_n(0x33u8, 64)); // bindingSig
        b
    }

    #[test]
    fn shielded_path_spends_notes_only() {
        let yec = OutPoint {
            txid: [7; 32],
            n: 0,
        };
        let class = |op: &OutPoint| (*op == yec).then_some(UtxoClass::Yec);
        let p2pkh = script::p2pkh_script(&[5; 20]);
        // z→z (no transparent output) and z→t: accepted.
        assert!(check(Path::Shielded, &raw_shielded(&[], &[], 1), class).is_ok());
        assert!(check(
            Path::Shielded,
            &raw_shielded(&[], &[(50_000, p2pkh.clone())], 2),
            class
        )
        .is_ok());
        // Any transparent input, even plain YEC, is refused: the YED machinery never meets this path.
        assert!(matches!(
            check(Path::Shielded, &raw_shielded(&[yec], &[], 1), class),
            Err(GateError::ShieldedShape(_))
        ));
        // No Sapling spend: not a shielded spend.
        assert!(matches!(
            check(Path::Shielded, &raw_shielded(&[], &[], 0), class),
            Err(GateError::ShieldedShape(_))
        ));
        // A payload, or an output that looks like a token.
        let op_return = transfer_payload_script();
        assert!(matches!(
            check(
                Path::Shielded,
                &raw_shielded(&[], &[(0, op_return)], 1),
                class
            ),
            Err(GateError::PayloadOnYecPath(0))
        ));
        assert!(matches!(
            check(
                Path::Shielded,
                &raw_shielded(&[], &[(crate::params::TOKEN_VALUE, p2pkh.clone())], 1),
                class
            ),
            Err(GateError::ShieldedShape(_))
        ));
        // And the transparent paths still refuse shielded components.
        assert_eq!(
            check(
                Path::Yec,
                &raw_shielded(&[yec], &[(50_000, p2pkh)], 1),
                class
            )
            .unwrap_err(),
            GateError::Shielded
        );
        assert!(!Path::Shielded.needs_yellowback());
        assert!(ALL.iter().all(|c| !Path::Shielded.allows(*c)));
    }

    #[test]
    fn shield_path_spends_plain_yec_into_sapling_only() {
        let op = |b: u8| OutPoint {
            txid: [b; 32],
            n: 0,
        };
        let (yec, reserve, token) = (op(7), op(8), op(9));
        let class = |o: &OutPoint| match o.txid[0] {
            7 => Some(UtxoClass::Yec),
            8 => Some(UtxoClass::FeeReserve),
            9 => Some(UtxoClass::Token),
            _ => None,
        };
        let p2pkh = script::p2pkh_script(&[5; 20]);
        // Plain YEC into a Sapling output, with or without transparent change: accepted.
        assert!(check(Path::Shield, &raw_shielded(&[yec], &[], 0), class).is_ok());
        assert!(check(
            Path::Shield,
            &raw_shielded(&[yec], &[(50_000, p2pkh.clone())], 0),
            class
        )
        .is_ok());
        // The fee reserve and YED are never shielded; unknown inputs are refused.
        for (o, name) in [(reserve, "FEE_RESERVE"), (token, "TOKEN")] {
            match check(Path::Shield, &raw_shielded(&[yec, o], &[], 0), class) {
                Err(GateError::ForbiddenInput { class, path, .. }) => {
                    assert_eq!((class, path), (name, "shield"))
                }
                other => panic!("{name}: {other:?}"),
            }
        }
        assert!(matches!(
            check(Path::Shield, &raw_shielded(&[op(1)], &[], 0), class),
            Err(GateError::UnknownInput(_))
        ));
        // No transparent input, a Sapling spend, a payload, a token-valued output: refused.
        assert!(matches!(
            check(Path::Shield, &raw_shielded(&[], &[], 0), class),
            Err(GateError::NoInputs)
        ));
        assert!(matches!(
            check(Path::Shield, &raw_shielded(&[yec], &[], 1), class),
            Err(GateError::ShieldedShape(_))
        ));
        assert!(matches!(
            check(
                Path::Shield,
                &raw_shielded(&[yec], &[(0, transfer_payload_script())], 0),
                class
            ),
            Err(GateError::PayloadOnYecPath(0))
        ));
        assert!(matches!(
            check(
                Path::Shield,
                &raw_shielded(&[yec], &[(crate::params::TOKEN_VALUE, p2pkh)], 0),
                class
            ),
            Err(GateError::ShieldedShape(_))
        ));
        assert!(!Path::Shield.needs_yellowback());
        assert!(ALL
            .iter()
            .all(|c| Path::Shield.allows(*c) == (*c == UtxoClass::Yec)));
    }
}
