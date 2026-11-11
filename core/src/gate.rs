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
//! 3. **Provenance** ([`confirm_provenance`], the plain-YEC paths [`Path::Yec`],
//!    [`Path::YecToPq`], [`Path::Shield`],
//!    [`Path::PqSpend`], and the YEC fee inputs of the YED builders' paths [`Path::Carrier`],
//!    [`Path::Mint`], [`Path::YedTransfer`], [`Path::Redeem`] / [`Path::Release`],
//!    [`Path::Claim`], [`Path::IntentRelease`], and the coins of [`Path::Sweep`] and
//!    [`Path::PqSweep`] ([`spent_as_yec`] names the inputs checked);
//!    review YEW-REVIEW-3, the structural finding): consensus does not pin a
//!    YED output's value, so "listed by `GetAddressTokens`, or exactly `TOKEN_VALUE`" is not
//!    enough against a server that omits a token and answers the dry run "burned 0". For every
//!    plain-YEC input the creating transaction is fetched (`GetTransaction`), its txid
//!    recomputed from the bytes, and its payload parsed here ([`payload::find_payload`], the
//!    node's `FindPayload`): an input a MINT (`vout[1]`, the token) or a TRANSFER / REDEEM
//!    assignment names is refused, and so is one whose creating transaction cannot be fetched or
//!    does not match (fail closed). Whether that assignment was valid needs chain state the
//!    light client does not have; it is judged as if it were (the safe direction).

use thiserror::Error;

use crate::coins::UtxoClass;
use crate::net::{Availability, CompactClient, NetError, Validation, YellowbackClient};
use crate::payload::{self, Payload};
use crate::script;
use crate::tx::{OutPoint, Transaction, TxError, TxOut};

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
    /// A YEC send to or from a post-quantum address ([`Path::YecToPq`], [`Path::SaplingToPq`],
    /// [`Path::PqToSapling`]) on a server without Yellowback: its dry run is mandatory and the
    /// server cannot run it (review YEW-REVIEW-6 L1: the generic
    /// [`GateError::YellowbackAbsent`] text names YED, which this send is not).
    #[error("gate: the server cannot check this transaction (it offers no Yellowback dry run), and a YEC send to or from a post-quantum address is only sent after that check. Nothing was sent; connect to a server that offers the Yellowback service and try again.")]
    NoDryRunForPqSend,
    /// The Sapling -> post-quantum or post-quantum -> Sapling path's shape rule was broken.
    #[error("gate: a YEC send between Sapling and a post-quantum address {0}")]
    SaplingPqShape(&'static str),
    /// A plain YEC spend of transparent coins by a wallet that has held YED, on a server without
    /// Yellowback: its YED outputs cannot be told apart from plain YEC (yewd's and the C++
    /// lines' has-held-YED guard, beta2 item 32).
    #[error("This wallet has held YED, but Yellowback is not live on the connected server, so its YED outputs cannot be told apart from plain YEC. Connect to a server with Yellowback to send YEC from public addresses.")]
    HeldYedNotLive,
    /// The plain YEC path pays a post-quantum key (beta2 item 3: that is [`Path::YecToPq`]'s, with
    /// its mandatory dry run).
    #[error("gate: output {0} pays a post-quantum key; a YEC send to a post-quantum address goes through its own path")]
    PqOutputOnYecPath(usize),
    /// The ECC → post-quantum path's output rule was broken.
    #[error("gate: a YEC send to a post-quantum address {0}")]
    YecToPqShape(&'static str),
    /// A post-quantum spend pays an output of exactly `TOKEN_VALUE` (it would look like a token).
    #[error("gate: output {0} is exactly TOKEN_VALUE; a plain YEC output must not look like a YED token")]
    TokenValuedOutput(usize),
    /// A plain-YEC input that the payload of its creating transaction assigns YED to (layer 3).
    #[error("gate: input {outpoint} carries YED (the {payload} payload of the transaction that created it assigns it); spending it as plain YEC would burn the YED")]
    InputCarriesYed {
        /// The input.
        outpoint: String,
        /// The creating payload's type name.
        payload: &'static str,
    },
    /// A plain-YEC input whose creating transaction could not be fetched or verified (layer 3).
    #[error("gate: input {outpoint}: {why}; whether it carries YED cannot be checked, so it is not spent as plain YEC")]
    InputProvenance {
        /// The input.
        outpoint: String,
        /// What failed.
        why: String,
    },
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
    /// A plain YEC send (`build::yec_send`) to a P2PKH or P2SH address: never a payload, never a
    /// `TX_PQPKH` output (beta2 item 3: paying a post-quantum key is [`Path::YecToPq`]).
    Yec,
    /// A plain YEC send from the wallet's ECC coins to a post-quantum key (beta2 item 3, D-2;
    /// `build::yec_send` with a decoded plain-YEC post-quantum address of this network): the
    /// inputs [`Path::Yec`] admits and no other; outputs exactly one `TX_PQPKH` paying the named
    /// key and at most one other, a P2PKH (the change); no payload; no output of exactly
    /// `TOKEN_VALUE`. The remote layer is mandatory (the node's dry run must see a transaction
    /// that pays a post-quantum key), so a server without Yellowback refuses it.
    YecToPq(crate::pq::PqKeyId),
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
    /// The move of an own post-quantum coin (`TX_PQPKH`: a released residual's, quantum spec
    /// F-3, or a `PQ_OWNED` row the sync found on an own `sq…` address; `build::release`) to an
    /// own P2PKH key: the named coin is the **only** input (one SLH-DSA or Falcon spend), no
    /// payload. Named, never classified here: the builders check a `PQ_OWNED` row's class
    /// themselves, and a residual's coin is known from the intent it released.
    PqSweep(OutPoint),
    /// A spend of the wallet's Sapling notes (`shielded.rs`): no transparent input.
    Shielded,
    /// A shield (S4, `build::yec_move`): transparent `YEC` inputs only (never the fee reserve,
    /// never anything YED) into Sapling outputs; no Sapling spend.
    Shield,
    /// A plain YEC send from the wallet's own post-quantum coins (beta2 D-2, D-8;
    /// `build::pq_send`): `PQ_OWNED` inputs only (never a token, a held output, the fee reserve,
    /// a P2PKH coin or anything YED), transparent-only, no payload, no output of exactly
    /// `TOKEN_VALUE`. The remote layer is mandatory: a server without Yellowback lists no
    /// post-quantum coin and validates nothing, so the path is refused there.
    PqSpend,
    /// A plain YEC send from the wallet's Sapling notes to a post-quantum key (beta2 D-2, D-5,
    /// D-8; the builder decodes a D-9 plain-YEC address of this network to the key): no
    /// transparent input; at least one Sapling spend, no JoinSplit; exactly one transparent
    /// output, a `TX_PQPKH` paying the named key, not of exactly `TOKEN_VALUE`; the change is a
    /// Sapling note; no payload. The remote layer is mandatory (the node's dry run must see a
    /// transaction that pays a post-quantum key). [`Path::Shielded`] refuses a `TX_PQPKH` output.
    SaplingToPq(crate::pq::PqKeyId),
    /// A plain YEC send from one own post-quantum address (the named source key) to Sapling
    /// (beta2 D-2, D-4, D-5, D-8): `PQ_OWNED` inputs only (never a token, a held output, the fee
    /// reserve, a P2PKH coin or anything YED); no Sapling spend, at least one Sapling output, no
    /// JoinSplit; at most one transparent output, the change, a `TX_PQPKH` paying the source key
    /// (D-4), not of exactly `TOKEN_VALUE`; no payload. The remote layer is mandatory.
    PqToSapling(crate::pq::PqKeyId),
}

impl Path {
    fn name(self) -> &'static str {
        match self {
            Path::Yec => "YEC",
            Path::YecToPq(_) => "YEC to post-quantum",
            Path::YedTransfer => "YED transfer",
            Path::Carrier => "carrier",
            Path::Mint => "mint",
            Path::Redeem => "redeem",
            Path::Release => "release",
            Path::Claim(_) => "claim",
            Path::Sweep => "sweep",
            Path::IntentRelease(_) => "intent release",
            Path::PqSweep(_) => "post-quantum coin move",
            Path::Shielded => "shielded",
            Path::Shield => "shield",
            Path::PqSpend => "post-quantum send",
            Path::SaplingToPq(_) => "Sapling to post-quantum",
            Path::PqToSapling(_) => "post-quantum to Sapling",
        }
    }

    fn allows(self, c: UtxoClass) -> bool {
        match self {
            Path::Yec | Path::YecToPq(_) | Path::Carrier => c.yec_spendable(),
            Path::YedTransfer => c.transfer_spendable(),
            Path::Mint => c.mint_spendable(),
            Path::Redeem => c.redeem_spendable(),
            Path::Release => c == UtxoClass::Vault,
            Path::Claim(_) => c.claim_spendable(),
            Path::Sweep => c == UtxoClass::Carrier,
            Path::IntentRelease(_) => c.yec_spendable(),
            Path::PqSweep(_) => false,
            Path::Shielded => false,
            Path::Shield => c == UtxoClass::Yec,
            Path::PqSpend => c == UtxoClass::PqOwned,
            Path::SaplingToPq(_) => false,
            Path::PqToSapling(_) => c == UtxoClass::PqOwned,
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
    if let Path::SaplingToPq(id) = path {
        return check_sapling_to_pq(tx, id);
    }
    if path == Path::Shield {
        check_shield_shape(&tx)?;
    } else if let Path::PqToSapling(_) = path {
        check_pq_to_sapling_shape(&tx)?;
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
        if let Path::Claim(named) | Path::IntentRelease(named) | Path::PqSweep(named) = path {
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
        Path::Yec => {
            no_payload(&tx)?;
            if let Some(i) = tx
                .vout
                .iter()
                .position(|o| crate::pq::pqpkh_of(&o.script_pubkey).is_some())
            {
                return Err(GateError::PqOutputOnYecPath(i));
            }
        }
        Path::YecToPq(id) => {
            no_payload(&tx)?;
            let mut paid = 0;
            for o in &tx.vout {
                match crate::pq::pqpkh_of(&o.script_pubkey) {
                    Some(k) if k == id => paid += 1,
                    Some(_) => {
                        return Err(GateError::YecToPqShape(
                            "must not pay a post-quantum key other than the recipient",
                        ))
                    }
                    None if script::p2pkh_hash(&o.script_pubkey).is_some() => {}
                    None => {
                        return Err(GateError::YecToPqShape(
                            "must pay only the recipient and P2PKH change",
                        ))
                    }
                }
                if o.value == crate::params::TOKEN_VALUE {
                    return Err(GateError::YecToPqShape(
                        "must not pay an output of exactly TOKEN_VALUE (it would look like a YED token)",
                    ));
                }
            }
            if paid != 1 {
                return Err(GateError::YecToPqShape(
                    "must pay the recipient exactly once",
                ));
            }
            if tx.vout.len() > 2 {
                return Err(GateError::YecToPqShape(
                    "must have at most one change output",
                ));
            }
        }
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
        Path::PqSpend => {
            no_payload(&tx)?;
            if let Some(i) = tx
                .vout
                .iter()
                .position(|o| o.value == crate::params::TOKEN_VALUE)
            {
                return Err(GateError::TokenValuedOutput(i));
            }
        }
        Path::PqSweep(named) => {
            no_payload(&tx)?;
            if tx.vin.len() != 1 {
                return Err(GateError::VaultShape(path.name(), named.display()));
            }
        }
        Path::PqToSapling(source) => {
            no_payload(&tx)?;
            if tx.vout.len() > 1 {
                return Err(GateError::SaplingPqShape(
                    "from a post-quantum address has at most one transparent output, the change to the source",
                ));
            }
            for (n, o) in tx.vout.iter().enumerate() {
                if crate::pq::pqpkh_of(&o.script_pubkey) != Some(source) {
                    return Err(GateError::SaplingPqShape(
                        "from a post-quantum address pays its change only to the source address",
                    ));
                }
                if o.value == crate::params::TOKEN_VALUE {
                    return Err(GateError::TokenValuedOutput(n));
                }
            }
        }
        Path::Shielded => unreachable!("checked by check_shielded above"),
        Path::SaplingToPq(_) => unreachable!("checked by check_sapling_to_pq above"),
    }
    Ok(tx)
}

/// The local layer of [`Path::SaplingToPq`] (beta2 D-2, D-8).
fn check_sapling_to_pq(tx: Transaction, id: crate::pq::PqKeyId) -> Result<Transaction, GateError> {
    if !tx.vin.is_empty() {
        return Err(GateError::SaplingPqShape(
            "from Sapling spends no transparent input",
        ));
    }
    if tx.shielded.joinsplits > 0 {
        return Err(GateError::ShieldedShape("it carries a Sprout JoinSplit"));
    }
    if tx.shielded.spends == 0 {
        return Err(GateError::SaplingPqShape(
            "from Sapling spends at least one Sapling note",
        ));
    }
    if tx.vout.len() != 1 {
        return Err(GateError::SaplingPqShape(
            "from Sapling has exactly one transparent output, the recipient",
        ));
    }
    let o = &tx.vout[0];
    if crate::pq::pqpkh_of(&o.script_pubkey) != Some(id) {
        return Err(GateError::SaplingPqShape(
            "from Sapling must pay the named post-quantum key",
        ));
    }
    if o.value == crate::params::TOKEN_VALUE {
        return Err(GateError::TokenValuedOutput(0));
    }
    Ok(tx)
}

/// The shape half of [`Path::PqToSapling`] (its inputs are classified like every transparent
/// path): Sapling outputs, no Sapling spend, no JoinSplit.
fn check_pq_to_sapling_shape(tx: &Transaction) -> Result<(), GateError> {
    if tx.shielded.joinsplits > 0 {
        return Err(GateError::ShieldedShape("it carries a Sprout JoinSplit"));
    }
    if tx.shielded.spends > 0 {
        return Err(GateError::SaplingPqShape(
            "from a post-quantum address spends no Sapling note",
        ));
    }
    if tx.shielded.outputs == 0 {
        return Err(GateError::SaplingPqShape(
            "from a post-quantum address makes a Sapling output",
        ));
    }
    Ok(())
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
    // beta2 item 5: paying a post-quantum key from Sapling is Path::SaplingToPq's, with its
    // mandatory dry run
    if let Some(i) = tx
        .vout
        .iter()
        .position(|o| crate::pq::pqpkh_of(&o.script_pubkey).is_some())
    {
        return Err(GateError::PqOutputOnYecPath(i));
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

/// The has-held-YED guard (beta2 item 32, as yewd's and the C++ lines'): a plain YEC spend of
/// transparent coins ([`Path::Yec`], [`Path::Shield`]) by a wallet that has held YED is refused
/// when the server offers no Yellowback ([`Validator::Absent`]): without the token set an own
/// output carrying YED at a value other than `TOKEN_VALUE` would classify as plain YEC, and the
/// local layer alone could not stop its burn. Every other path is unaffected (the YED paths and
/// [`Path::PqSpend`] already need the service; [`Path::Shielded`] spends no transparent input).
pub fn refuse_held_absent(
    validator: &Validator,
    path: Path,
    has_held_yed: bool,
) -> Result<(), GateError> {
    if has_held_yed
        && matches!(validator, Validator::Absent)
        && matches!(path, Path::Yec | Path::YecToPq(_) | Path::Shield)
    {
        return Err(GateError::HeldYedNotLive);
    }
    Ok(())
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
            return if let Path::YecToPq(_) | Path::SaplingToPq(_) | Path::PqToSapling(_) = path {
                Err(GateError::NoDryRunForPqSend)
            } else if path.needs_yellowback() {
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

/// Layer 3 on fetched data (pure; [`confirm_provenance`] fetches): every input of `tx` that
/// `checked` selects (the plain-YEC classes) must have its creating transaction in `created`
/// (raw bytes as the server returned them, by txid), whose txid recomputed from the bytes is
/// the input's, which has the output, and whose Yellowback payload (if any) assigns it no YED:
/// not `vout[1]` of a MINT, not an assignment of a TRANSFER or REDEEM, not an output at
/// index 1 or above of a claim cancel (CANCEL_COSIGN, CAN-1); and whose payload is not of a type or version
/// this build does not know ([`payload::unknown_yellowback`], fail closed).
///
/// Review YEW-REVIEW-4 L2: the verified output's value and script must also equal the coin the
/// wallet has stored for that outpoint (`coin_of`, the store's row, which is what the builder
/// signed and computed the fee over); a mismatch, or no stored coin, refuses. So the local fee
/// assertion rests on values proven by the creating transaction, not on the server's listing.
pub fn check_provenance(
    tx: &Transaction,
    created: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    checked: impl Fn(&OutPoint) -> bool,
    coin_of: impl Fn(&OutPoint) -> Option<TxOut>,
) -> Result<(), GateError> {
    for i in &tx.vin {
        let op = i.prevout;
        if !checked(&op) {
            continue;
        }
        let stored = coin_of(&op);
        output_provenance(
            &op,
            created.get(&op.txid).map(Vec::as_slice),
            stored.as_ref(),
        )?;
        if stored.is_none() {
            return Err(GateError::InputProvenance {
                outpoint: format!("{}:{}", crate::tx::txid_hex(&op.txid), op.n),
                why: "the wallet has no record of the coin it spends".to_string(),
            });
        }
    }
    Ok(())
}

/// The version of the layer-3 classifier ([`output_provenance`], [`payload::unknown_yellowback`])
/// stored with each final verdict (review YEW-REVIEW-5 L2). Raise it whenever the classifier
/// changes what it holds; the held verdicts of an older one are re-checked at the next sync.
/// 1: YEW-REVIEW-4 M3 (implicit, stored as 0); 2: the retired payload versions 1 and 2 (and a
/// MINT below version 4) are non-Yellowback, as on the node.
pub const PROVENANCE_CLASSIFIER: i64 = 2;

/// Layer 3's verdict on one output, from the bytes the server returned for the transaction that
/// created it (`None`: not returned). `Ok` only when those bytes are that transaction (txid
/// recomputed), it has the output, its payload is of a known type and version, and the payload
/// assigns the output no YED. With `stored` (the coin as the wallet recorded it), the output's
/// value and script must also equal it (review YEW-REVIEW-4 L2). Used at broadcast
/// ([`check_provenance`]) and at sync, where an own coin that fails is classified `HELD` (review
/// YEW-REVIEW-4 M3).
pub fn output_provenance(
    op: &OutPoint,
    raw: Option<&[u8]>,
    stored: Option<&TxOut>,
) -> Result<(), GateError> {
    let name = || format!("{}:{}", crate::tx::txid_hex(&op.txid), op.n);
    let bad = |why: &str| GateError::InputProvenance {
        outpoint: name(),
        why: why.to_string(),
    };
    let raw =
        raw.ok_or_else(|| bad("the server did not return the transaction that created it"))?;
    let (parent, txid) = Transaction::parse(raw)
        .map_err(|_| bad("the transaction the server returned for it does not parse"))?;
    if txid != op.txid {
        return Err(bad(
            "the server returned another transaction than the one that created it",
        ));
    }
    if op.n as usize >= parent.vout.len() {
        return Err(bad("its creating transaction has no such output"));
    }
    if let Some(c) = stored {
        let out = &parent.vout[op.n as usize];
        if out.value != c.value || out.script_pubkey != c.script_pubkey {
            return Err(bad(&format!(
                "its creating transaction pays {} zat to {}, not the {} zat to {} the server reported",
                out.value,
                crate::keys::hex(&out.script_pubkey),
                c.value,
                crate::keys::hex(&c.script_pubkey)
            )));
        }
    }
    if payload::unknown_yellowback(&parent) {
        return Err(bad(
            "its creating transaction carries a Yellowback payload of a type or version this app does not know",
        ));
    }
    if let Some(found) = payload::find_payload(&parent) {
        // every way an output comes to hold YED (ycash-dd state.cpp, the four TokenRecord
        // writes): a MINT's vout[1] (ApplyMint), a TRANSFER's assignments (ApplyTransfer), a
        // REDEEM's assignments on a vault spend (ApplyVaultSpend), and CAN-1's refund on a
        // claim cancel, which carries CANCEL_COSIGN (ApplyIntentSpend: the lowest output at
        // index >= 1 paying the claimant's refund script, at any non-zero value, from vault
        // state; over-approximated here as every output at index >= 1)
        let assigned = match &found.payload {
            Payload::Mint { .. } => op.n == 1,
            Payload::CancelCosign => op.n >= 1,
            p => p.assignments().iter().any(|a| a.vout as u32 == op.n),
        };
        if assigned {
            return Err(GateError::InputCarriesYed {
                outpoint: name(),
                payload: found.payload.payload_type().name(),
            });
        }
    }
    Ok(())
}

/// The inputs of `tx` that `path` spends as plain YEC, which layer 3 checks:
/// - every input of a plain-YEC class (`YEC`, `FEE_RESERVE`, `PQ_OWNED`), on every path. On the
///   YED paths these are the YEC fee inputs (a token smuggled in as a fee coin by a server that
///   omitted it from `GetAddressTokens` classifies `YEC`, so it is checked);
/// - every `CARRIER` (the mint and the claim spend it into fees, the sweep back to YEC; its
///   creating transaction is the wallet's own payload-free carrier funding, so an honest server
///   always passes it);
/// - the named coin at `vin[0]` of [`Path::PqSweep`] (a released residual, or any `PQ_OWNED` row
///   the sync found: it is moved as plain YEC).
///
/// Not checked, because they are not spent as plain YEC: `TOKEN` inputs (spent as YED: their
/// creating payload assigns them, which is the point), the own `VAULT`, and the named `vin[0]` of
/// [`Path::Claim`] (another wallet's vault) and [`Path::IntentRelease`] (a template output).
pub fn spent_as_yec(
    path: Path,
    tx: &Transaction,
    class_of: impl Fn(&OutPoint) -> Option<UtxoClass>,
) -> std::collections::HashSet<OutPoint> {
    tx.vin
        .iter()
        .enumerate()
        .filter(|(n, i)| match path {
            Path::Claim(_) | Path::IntentRelease(_) if *n == 0 => false,
            Path::PqSweep(_) if *n == 0 => true,
            _ => matches!(
                class_of(&i.prevout),
                Some(
                    UtxoClass::Yec
                        | UtxoClass::FeeReserve
                        | UtxoClass::PqOwned
                        | UtxoClass::Carrier
                )
            ),
        })
        .map(|(_, i)| i.prevout)
        .collect()
}

/// Layer 3 ([`check_provenance`]) on `path`: fetch the creating transaction of every input the
/// path spends as plain YEC ([`spent_as_yec`]) with `GetTransaction`; a fetch error or a
/// transaction the server does not know refuses (fail closed). Run after [`confirm`] on the
/// plain-YEC paths and on the YED builders' YEC fee inputs.
pub async fn confirm_provenance(
    client: &mut CompactClient,
    path: Path,
    raw: &[u8],
    class_of: impl Fn(&OutPoint) -> Option<UtxoClass>,
    coin_of: impl Fn(&OutPoint) -> Option<TxOut>,
) -> Result<(), GateError> {
    let (tx, _) = Transaction::parse(raw).map_err(GateError::Parse)?;
    let yec_inputs = spent_as_yec(path, &tx, class_of);
    let checked = |op: &OutPoint| yec_inputs.contains(op);
    let mut created = std::collections::HashMap::new();
    for i in &tx.vin {
        let id = i.prevout.txid;
        if !checked(&i.prevout) || created.contains_key(&id) {
            continue;
        }
        match client.get_transaction(&id).await {
            Ok(Some((bytes, _))) => {
                created.insert(id, bytes);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(GateError::InputProvenance {
                    outpoint: format!("{}:{}", crate::tx::txid_hex(&id), i.prevout.n),
                    why: format!("GetTransaction failed ({e})"),
                })
            }
        }
    }
    check_provenance(&tx, &created, checked, coin_of)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{encode, Assignment};
    use crate::tx::{TxIn, TxOut};
    use std::collections::HashMap;

    const ALL: [UtxoClass; 10] = [
        UtxoClass::Yec,
        UtxoClass::FeeReserve,
        UtxoClass::Token,
        UtxoClass::PendingToken,
        UtxoClass::Vault,
        UtxoClass::Carrier,
        UtxoClass::UnknownP2sh,
        UtxoClass::Held,
        UtxoClass::PqOwned,
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

            // beta2 D-8: the post-quantum send spends PQ_OWNED coins and nothing else
            let pqs = check(Path::PqSpend, &raw, class);
            let pqs_ok = inputs
                .iter()
                .all(|op| class(op) == Some(UtxoClass::PqOwned));
            assert_eq!(
                pqs.is_ok(),
                pqs_ok && !op_return,
                "PQ send {inputs:?} {:?}",
                pqs.err()
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
            owner: crate::pq::PqKeyId {
                scheme: 1,
                hash: [2; 32],
            },
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

    /// beta2 D-8: the post-quantum send path. Every class but `PQ_OWNED` is refused as an input
    /// (Token, PendingToken, Vault, Carrier, Held, FeeReserve, Yec, UnknownP2sh, Foreign), as are
    /// an unknown input, a payload, a shielded part and an output of exactly `TOKEN_VALUE`; a
    /// server without Yellowback refuses the path outright, and the held-YED guard refuses the
    /// transparent YEC paths there for a wallet that has held YED.
    #[test]
    fn pq_spend_path_and_held_yed_guard() {
        let pq = OutPoint {
            txid: [1; 32],
            n: 0,
        };
        let other = OutPoint {
            txid: [2; 32],
            n: 0,
        };
        for c in ALL {
            let class = |op: &OutPoint| {
                if *op == pq {
                    Some(UtxoClass::PqOwned)
                } else {
                    Some(c)
                }
            };
            let r = check(Path::PqSpend, &raw_spending(&[pq, other], false), class);
            assert_eq!(r.is_ok(), c == UtxoClass::PqOwned, "{c:?}: {r:?}");
            if c != UtxoClass::PqOwned {
                assert!(matches!(r, Err(GateError::ForbiddenInput { .. })), "{c:?}");
            }
        }
        let only_pq = |op: &OutPoint| (*op == pq).then_some(UtxoClass::PqOwned);
        assert!(check(Path::PqSpend, &raw_spending(&[pq], false), only_pq).is_ok());
        assert!(matches!(
            check(Path::PqSpend, &raw_spending(&[pq, other], false), only_pq),
            Err(GateError::UnknownInput(_))
        ));
        assert!(matches!(
            check(Path::PqSpend, &raw_spending(&[pq], true), only_pq),
            Err(GateError::PayloadOnYecPath(1))
        ));
        let mut t = Transaction::new_v4();
        t.vin.push(TxIn::new(pq));
        t.vout.push(TxOut {
            value: crate::params::TOKEN_VALUE,
            script_pubkey: script::p2pkh_script(&[3; 20]),
        });
        assert_eq!(
            check(Path::PqSpend, &t.serialize().unwrap(), only_pq).unwrap_err(),
            GateError::TokenValuedOutput(0)
        );
        assert!(Path::PqSpend.needs_yellowback());
        // the held-YED guard
        let absent = Validator::Absent;
        assert_eq!(
            refuse_held_absent(&absent, Path::Yec, true),
            Err(GateError::HeldYedNotLive)
        );
        assert_eq!(
            refuse_held_absent(&absent, Path::Shield, true),
            Err(GateError::HeldYedNotLive)
        );
        assert_eq!(refuse_held_absent(&absent, Path::Yec, false), Ok(()));
        assert_eq!(refuse_held_absent(&absent, Path::Shielded, true), Ok(()));
    }

    // ---- beta2 item 3: ECC -> post-quantum through its own path

    fn pq_id(b: u8) -> crate::pq::PqKeyId {
        crate::pq::PqKeyId {
            scheme: crate::pq::SCHEME_FN_DSA_512,
            hash: [b; 32],
        }
    }

    fn raw_paying(inputs: &[OutPoint], outs: &[(i64, Vec<u8>)]) -> Vec<u8> {
        let mut t = Transaction::new_v4();
        for op in inputs {
            t.vin.push(TxIn::new(*op));
        }
        for (v, spk) in outs {
            t.vout.push(TxOut {
                value: *v,
                script_pubkey: spk.clone(),
            });
        }
        t.serialize().unwrap()
    }

    /// Property, beta2 item 3: on random coin sets and random output shapes,
    /// - `Path::YecToPq` admits exactly the input classes `Path::Yec` admits;
    /// - `Path::Yec` passes exactly what it passed before (YEC-spendable inputs, no payload) minus
    ///   the shapes paying a `TX_PQPKH`: every ECC -> ECC shape is unchanged, and only post-quantum
    ///   outputs moved;
    /// - `Path::YecToPq(id)` passes exactly: YEC-spendable inputs, no payload, one output paying
    ///   `id`, at most one other output and it P2PKH, no output of exactly TOKEN_VALUE.
    #[test]
    fn yec_to_pq_property_over_every_class_and_shape() {
        for c in ALL {
            assert_eq!(
                Path::YecToPq(pq_id(1)).allows(c),
                Path::Yec.allows(c),
                "{c:?}"
            );
        }
        let id = pq_id(7);
        let to_pq = crate::pq::pqpkh_script(&id).unwrap();
        let other_pq = crate::pq::pqpkh_script(&pq_id(8)).unwrap();
        let slh = crate::pq::pqpkh_script(&crate::pq::PqKeyId {
            scheme: crate::pq::SCHEME_SLH_DSA_SHA2_128S,
            hash: [7; 32],
        })
        .unwrap();
        let p2pkh = script::p2pkh_script(&[3; 20]);
        let p2sh = script::p2sh_script(&[4; 20]);
        let op_ret = transfer_payload_script();
        let kinds = [
            to_pq.clone(),
            other_pq.clone(),
            slh.clone(),
            p2pkh.clone(),
            p2sh.clone(),
            op_ret.clone(),
        ];
        let mut rng = Rng(0x5eed_1234_abcd_ef01);
        for _ in 0..3000 {
            let n_coins = 1 + rng.below(6) as usize;
            let mut coins: HashMap<OutPoint, UtxoClass> = HashMap::new();
            let mut list = Vec::new();
            for i in 0..n_coins {
                let mut txid = [0u8; 32];
                txid[0] = i as u8;
                txid[1] = rng.below(256) as u8;
                let op = OutPoint { txid, n: 0 };
                coins.insert(op, ALL[rng.below(ALL.len() as u64) as usize]);
                list.push(op);
            }
            let n_in = 1 + rng.below(list.len() as u64) as usize;
            let inputs: Vec<OutPoint> = list[..n_in].to_vec();
            let n_out = 1 + rng.below(3) as usize;
            let outs: Vec<(i64, Vec<u8>)> = (0..n_out)
                .map(|_| {
                    let v = if rng.below(8) == 0 {
                        crate::params::TOKEN_VALUE
                    } else {
                        1_000 + rng.below(1_000_000) as i64
                    };
                    (v, kinds[rng.below(kinds.len() as u64) as usize].clone())
                })
                .collect();
            let raw = raw_paying(&inputs, &outs);
            let class = |op: &OutPoint| coins.get(op).copied();
            let inputs_ok = inputs
                .iter()
                .all(|op| class(op).is_some_and(|c| c.yec_spendable()));
            let has_payload = outs.iter().any(|(_, s)| script::is_op_return(s));
            let has_pq = outs.iter().any(|(_, s)| crate::pq::pqpkh_of(s).is_some());
            // Path::Yec: the old rule, minus the post-quantum outputs
            let old_rule = inputs_ok && !has_payload;
            let yec = check(Path::Yec, &raw, class);
            assert_eq!(yec.is_ok(), old_rule && !has_pq, "Yec {outs:?}: {yec:?}");
            if old_rule && has_pq {
                assert!(
                    matches!(yec, Err(GateError::PqOutputOnYecPath(_))),
                    "{yec:?}"
                );
            }
            // Path::YecToPq
            let paid = outs.iter().filter(|(_, s)| *s == to_pq).count();
            let others_p2pkh = outs
                .iter()
                .filter(|(_, s)| *s != to_pq)
                .all(|(_, s)| script::p2pkh_hash(s).is_some());
            let no_token_value = outs.iter().all(|(v, _)| *v != crate::params::TOKEN_VALUE);
            let want = inputs_ok
                && !has_payload
                && paid == 1
                && others_p2pkh
                && outs.len() <= 2
                && no_token_value;
            let r = check(Path::YecToPq(id), &raw, class);
            assert_eq!(r.is_ok(), want, "YecToPq {inputs:?} {outs:?}: {r:?}");
        }
    }

    /// A v4 transaction with the given transparent inputs and outputs, `spends` Sapling spends
    /// and `outputs` Sapling outputs (no JoinSplit; the binding signature when either is non-zero).
    fn raw_sapling(vin: &[OutPoint], vout: &[(i64, Vec<u8>)], spends: u8, outputs: u8) -> Vec<u8> {
        let mut t = Transaction::new_v4();
        for op in vin {
            t.vin.push(TxIn::new(*op));
        }
        for (v, spk) in vout {
            t.vout.push(TxOut {
                value: *v,
                script_pubkey: spk.clone(),
            });
        }
        let mut b = t.serialize().unwrap();
        // the transparent serialization ends: valueBalance (8), 0 spends, 0 outputs, 0 JoinSplits
        b.truncate(b.len() - 11);
        b.extend_from_slice(&0i64.to_le_bytes());
        b.push(spends);
        b.extend(std::iter::repeat_n(0x11u8, 384 * spends as usize));
        b.push(outputs);
        b.extend(std::iter::repeat_n(0x22u8, 948 * outputs as usize));
        b.push(0);
        if spends > 0 || outputs > 0 {
            b.extend(std::iter::repeat_n(0x33u8, 64));
        }
        b
    }

    /// Property, beta2 item 5 (review YEW-REVIEW-6): on random coin sets over every UTXO class,
    /// random transparent outputs (the named key, another post-quantum key of either scheme,
    /// P2PKH, P2SH, a payload; values sometimes exactly TOKEN_VALUE) and random Sapling parts:
    /// - `Path::SaplingToPq(id)` passes exactly: no transparent input, at least one Sapling spend,
    ///   exactly one transparent output, paying `id`, not of TOKEN_VALUE;
    /// - `Path::PqToSapling(src)` passes exactly: at least one input, every input PQ_OWNED, no
    ///   Sapling spend, at least one Sapling output, at most one transparent output and it pays
    ///   `src`, not of TOKEN_VALUE;
    /// - `Path::Shielded` passes nothing that pays a post-quantum key (it was its rule minus
    ///   those outputs);
    /// - neither new path admits any class but PQ_OWNED (`allows`), and both need the dry run.
    #[test]
    fn sapling_pq_paths_property_over_every_class_and_shape() {
        let id = pq_id(7);
        let src = crate::pq::PqKeyId {
            scheme: crate::pq::SCHEME_SLH_DSA_SHA2_128S,
            hash: [9; 32],
        };
        for c in ALL {
            assert!(!Path::SaplingToPq(id).allows(c), "{c:?}");
            assert_eq!(
                Path::PqToSapling(src).allows(c),
                c == UtxoClass::PqOwned,
                "{c:?}"
            );
        }
        assert!(Path::SaplingToPq(id).needs_yellowback());
        assert!(Path::PqToSapling(src).needs_yellowback());
        let to_pq = crate::pq::pqpkh_script(&id).unwrap();
        let to_src = crate::pq::pqpkh_script(&src).unwrap();
        let other_pq = crate::pq::pqpkh_script(&pq_id(8)).unwrap();
        let p2pkh = script::p2pkh_script(&[3; 20]);
        let p2sh = script::p2sh_script(&[4; 20]);
        let op_ret = transfer_payload_script();
        let kinds = [
            to_pq.clone(),
            to_src.clone(),
            other_pq.clone(),
            p2pkh.clone(),
            p2sh.clone(),
            op_ret.clone(),
        ];
        let mut rng = Rng(0x5a91_e2b0_7c3d_4f15);
        let mut passed = (0, 0);
        for _ in 0..4000 {
            let n_coins = 1 + rng.below(6) as usize;
            let mut coins: HashMap<OutPoint, UtxoClass> = HashMap::new();
            let mut list = Vec::new();
            for i in 0..n_coins {
                let mut txid = [0u8; 32];
                txid[0] = i as u8;
                txid[1] = rng.below(256) as u8;
                let op = OutPoint { txid, n: 0 };
                // PQ_OWNED half the time, so the passing shapes are reached
                let c = if rng.below(2) == 0 {
                    UtxoClass::PqOwned
                } else {
                    ALL[rng.below(ALL.len() as u64) as usize]
                };
                coins.insert(op, c);
                list.push(op);
            }
            let n_in = rng.below(list.len() as u64 + 1) as usize;
            let inputs: Vec<OutPoint> = list[..n_in].to_vec();
            let n_out = rng.below(3) as usize;
            let outs: Vec<(i64, Vec<u8>)> = (0..n_out)
                .map(|_| {
                    let v = if rng.below(8) == 0 {
                        crate::params::TOKEN_VALUE
                    } else {
                        1_000 + rng.below(1_000_000) as i64
                    };
                    (v, kinds[rng.below(kinds.len() as u64) as usize].clone())
                })
                .collect();
            let spends = rng.below(3) as u8;
            let sap_outs = rng.below(3) as u8;
            let raw = raw_sapling(&inputs, &outs, spends, sap_outs);
            let class = |op: &OutPoint| coins.get(op).copied();
            let no_token_value = outs.iter().all(|(v, _)| *v != crate::params::TOKEN_VALUE);
            // SaplingToPq
            let want = inputs.is_empty()
                && spends >= 1
                && outs.len() == 1
                && outs[0].1 == to_pq
                && no_token_value;
            let r = check(Path::SaplingToPq(id), &raw, class);
            assert_eq!(
                r.is_ok(),
                want,
                "SaplingToPq {inputs:?} {outs:?} {spends}/{sap_outs}: {r:?}"
            );
            passed.0 += usize::from(want);
            // PqToSapling
            let inputs_ok = !inputs.is_empty()
                && inputs
                    .iter()
                    .all(|op| class(op) == Some(UtxoClass::PqOwned));
            let want = inputs_ok
                && spends == 0
                && sap_outs >= 1
                && outs.len() <= 1
                && outs.iter().all(|(_, s)| *s == to_src)
                && no_token_value;
            let r = check(Path::PqToSapling(src), &raw, class);
            assert_eq!(
                r.is_ok(),
                want,
                "PqToSapling {inputs:?} {outs:?} {spends}/{sap_outs}: {r:?}"
            );
            passed.1 += usize::from(want);
            // Shielded never pays a post-quantum key
            if outs.iter().any(|(_, s)| crate::pq::pqpkh_of(s).is_some()) {
                assert!(check(Path::Shielded, &raw, class).is_err(), "{outs:?}");
            }
        }
        // the generator reaches the passing shapes of both paths
        assert!(passed.0 > 20 && passed.1 > 20, "{passed:?}");
    }

    /// Beta2 item 5: without the remote layer both new paths are refused with the path-specific
    /// text (never "YED"); with a held-YED wallet the refusal is the same (the guard's paths are
    /// unchanged: these paths need the service anyway); layer 3 checks every PQ_OWNED input.
    #[tokio::test]
    async fn sapling_pq_paths_need_the_dry_run() {
        let id = pq_id(7);
        let mut v = Validator::Absent;
        let raw = raw_sapling(
            &[],
            &[(50_000, crate::pq::pqpkh_script(&id).unwrap())],
            1,
            2,
        );
        assert!(check(Path::SaplingToPq(id), &raw, |_| None).is_ok());
        assert_eq!(
            confirm(&mut v, Path::SaplingToPq(id), &raw, |_| None)
                .await
                .unwrap_err(),
            GateError::NoDryRunForPqSend
        );
        let a = OutPoint {
            txid: [1; 32],
            n: 0,
        };
        let raw = raw_sapling(
            &[a],
            &[(50_000, crate::pq::pqpkh_script(&id).unwrap())],
            0,
            1,
        );
        let class = |_: &OutPoint| Some(UtxoClass::PqOwned);
        assert!(check(Path::PqToSapling(id), &raw, class).is_ok());
        assert_eq!(
            confirm(&mut v, Path::PqToSapling(id), &raw, class)
                .await
                .unwrap_err(),
            GateError::NoDryRunForPqSend
        );
        let (tx, _) = Transaction::parse(&raw).unwrap();
        assert!(spent_as_yec(Path::PqToSapling(id), &tx, class).contains(&a));
        // the existing shielded path no longer pays a post-quantum key
        let raw = raw_sapling(
            &[],
            &[(50_000, crate::pq::pqpkh_script(&id).unwrap())],
            1,
            2,
        );
        assert_eq!(
            check(Path::Shielded, &raw, |_| None).unwrap_err(),
            GateError::PqOutputOnYecPath(0)
        );
        let raw = raw_sapling(&[], &[(50_000, script::p2pkh_script(&[3; 20]))], 1, 2);
        assert!(check(Path::Shielded, &raw, |_| None).is_ok());
    }

    /// Beta2 item 3: every previously valid ECC -> ECC shape (P2PKH or P2SH recipient, with or
    /// without P2PKH change, from YEC or FEE_RESERVE coins) and ECC -> Sapling shape (`Path::Shield`)
    /// still passes; the same shapes paying a post-quantum key pass only on `Path::YecToPq`; the
    /// new path's dry run is mandatory and the held-YED guard covers it.
    #[tokio::test]
    async fn yec_path_tightening_keeps_every_ecc_shape() {
        let a = OutPoint {
            txid: [1; 32],
            n: 0,
        };
        let b = OutPoint {
            txid: [2; 32],
            n: 1,
        };
        let id = pq_id(9);
        let p2pkh = script::p2pkh_script(&[3; 20]);
        let change = script::p2pkh_script(&[5; 20]);
        let p2sh = script::p2sh_script(&[4; 20]);
        let to_pq = crate::pq::pqpkh_script(&id).unwrap();
        for classes in [
            [UtxoClass::Yec, UtxoClass::Yec],
            [UtxoClass::Yec, UtxoClass::FeeReserve],
            [UtxoClass::FeeReserve, UtxoClass::FeeReserve],
        ] {
            let class = |op: &OutPoint| Some(if *op == a { classes[0] } else { classes[1] });
            for dest in [&p2pkh, &p2sh] {
                for outs in [
                    vec![(50_000, dest.clone())],
                    vec![(50_000, dest.clone()), (7_000, change.clone())],
                ] {
                    let raw = raw_paying(&[a, b], &outs);
                    assert!(check(Path::Yec, &raw, class).is_ok(), "{outs:?}");
                    assert!(check(Path::YecToPq(id), &raw, class).is_err());
                }
            }
            for outs in [
                vec![(50_000, to_pq.clone())],
                vec![(50_000, to_pq.clone()), (7_000, change.clone())],
            ] {
                let raw = raw_paying(&[a, b], &outs);
                assert_eq!(
                    check(Path::Yec, &raw, class).unwrap_err(),
                    GateError::PqOutputOnYecPath(0)
                );
                assert!(check(Path::YecToPq(id), &raw, class).is_ok(), "{outs:?}");
                // the named key only
                assert!(check(Path::YecToPq(pq_id(10)), &raw, class).is_err());
            }
            // ECC -> Sapling (a shield) is its own path, unchanged
            let shield = raw_shielded(&[a], &[(7_000, change.clone())], 0);
            // (a shield spends YEC only, never the fee reserve: as before)
            assert_eq!(
                check(Path::Shield, &shield, class).is_ok(),
                classes[0] == UtxoClass::Yec
            );
            assert_eq!(
                check(Path::Yec, &shield, class).unwrap_err(),
                GateError::Shielded
            );
            assert_eq!(
                check(Path::YecToPq(id), &shield, class).unwrap_err(),
                GateError::Shielded
            );
        }
        // the shape errors name the rule
        let class = |_: &OutPoint| Some(UtxoClass::Yec);
        let e = check(
            Path::YecToPq(id),
            &raw_paying(&[a], &[(50_000, to_pq.clone()), (7_000, p2sh.clone())]),
            class,
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "gate: a YEC send to a post-quantum address must pay only the recipient and P2PKH change"
        );
        assert!(check(
            Path::YecToPq(id),
            &raw_paying(&[a], &[(crate::params::TOKEN_VALUE, to_pq.clone())]),
            class
        )
        .is_err());
        // the dry run is mandatory; the held-YED guard covers the path
        assert!(Path::YecToPq(id).needs_yellowback() && !Path::Yec.needs_yellowback());
        let raw = raw_paying(&[a], &[(50_000, to_pq.clone())]);
        let mut v = Validator::Absent;
        assert_eq!(
            confirm(&mut v, Path::YecToPq(id), &raw, class)
                .await
                .unwrap_err(),
            GateError::NoDryRunForPqSend
        );
        // review YEW-REVIEW-6 L1: the refusal names the check and the remedy, never YED
        let m = GateError::NoDryRunForPqSend.to_string();
        assert!(!m.contains("YED"), "{m}");
        assert!(m.contains("cannot check this transaction") && m.contains("Nothing was sent"));
        assert!(m.contains("connect to a server that offers the Yellowback service"));
        assert_eq!(
            refuse_held_absent(&Validator::Absent, Path::YecToPq(id), true),
            Err(GateError::HeldYedNotLive)
        );
        // layer 3 checks its inputs as plain YEC
        let (tx, _) = Transaction::parse(&raw).unwrap();
        assert!(spent_as_yec(Path::YecToPq(id), &tx, class).contains(&a));
    }

    /// Without the remote layer (a server answering `UNIMPLEMENTED`), the post-quantum send is
    /// refused even when its local layer passes; the plain YEC path proceeds on the local layer
    /// alone (and the held-YED guard decides before it, [`refuse_held_absent`]).
    #[tokio::test]
    async fn pq_spend_needs_the_remote_layer() {
        let pq = OutPoint {
            txid: [1; 32],
            n: 0,
        };
        let raw = raw_spending(&[pq], false);
        let mut v = Validator::Absent;
        let r = confirm(&mut v, Path::PqSpend, &raw, |_| Some(UtxoClass::PqOwned)).await;
        assert_eq!(r.unwrap_err(), GateError::YellowbackAbsent);
        let r = confirm(&mut v, Path::Yec, &raw, |_| Some(UtxoClass::Yec)).await;
        assert!(matches!(r, Ok((_, None))));
    }

    // ---- layer 3: provenance against a lying server (review YEW-REVIEW-3, structural)

    /// A parent transaction with `outs` plain outputs and, when given, `payload` as an OP_RETURN
    /// appended last; returns its bytes and txid.
    fn parent(outs: &[i64], p: Option<Payload>) -> (Vec<u8>, [u8; 32]) {
        let mut t = Transaction::new_v4();
        t.vin.push(TxIn::new(OutPoint {
            txid: [0xee; 32],
            n: 0,
        }));
        for v in outs {
            t.vout.push(TxOut {
                value: *v,
                script_pubkey: crate::script::p2pkh_script(&[0x11; 20]),
            });
        }
        if let Some(p) = p {
            t.vout.push(TxOut {
                value: 0,
                script_pubkey: payload::payload_script(&encode(&p).unwrap()),
            });
        }
        let raw = t.serialize().unwrap();
        let (_, id) = Transaction::parse(&raw).unwrap();
        (raw, id)
    }

    fn spend(ops: &[OutPoint]) -> Transaction {
        let mut t = Transaction::new_v4();
        for o in ops {
            t.vin.push(TxIn::new(*o));
        }
        t.vout.push(TxOut {
            value: 1,
            script_pubkey: crate::script::p2pkh_script(&[0x22; 20]),
        });
        t
    }

    fn served(parents: &[&(Vec<u8>, [u8; 32])]) -> HashMap<[u8; 32], Vec<u8>> {
        parents.iter().map(|(r, id)| (*id, r.clone())).collect()
    }

    /// The output `op` of the served parent, as an honest listing reports it.
    fn honest(served: &HashMap<[u8; 32], Vec<u8>>, op: &OutPoint) -> Option<TxOut> {
        let (t, _) = Transaction::parse(served.get(&op.txid)?).ok()?;
        t.vout.get(op.n as usize).cloned()
    }

    /// [`check_provenance`] with the wallet's stored coins as an honest listing reported them
    /// (equal to the served parents' outputs).
    fn check3(
        tx: &Transaction,
        served: &HashMap<[u8; 32], Vec<u8>>,
        checked: impl Fn(&OutPoint) -> bool,
    ) -> Result<(), GateError> {
        check_provenance(tx, served, checked, |op| honest(served, op))
    }

    /// Review YEW-REVIEW-4 L2: a server that lists an own coin at another value (or script) than
    /// its creating transaction pays is refused, so the local fee assertion (over the stored
    /// value) rests on the verified parent; an input the wallet has no record of is refused; the
    /// honest listing passes.
    #[test]
    fn provenance_refuses_a_listing_that_differs_from_the_parent() {
        let plain = parent(&[3_000_000, 70_000], None);
        let op = OutPoint {
            txid: plain.1,
            n: 0,
        };
        let all = |_: &OutPoint| true;
        let srv = served(&[&plain]);
        let honest_out = honest(&srv, &op).unwrap();
        assert_eq!(
            check_provenance(&spend(&[op]), &srv, all, |_| Some(honest_out.clone())),
            Ok(())
        );
        // the server listed the coin at a higher value (a fee computed over it would be larger
        // than the wallet believes, or the change short)
        let inflated = TxOut {
            value: 3_500_000,
            ..honest_out.clone()
        };
        let e = check_provenance(&spend(&[op]), &srv, all, |_| Some(inflated.clone())).unwrap_err();
        assert!(
            matches!(&e, GateError::InputProvenance { why, .. } if why.contains("pays 3000000 zat to") && why.contains("not the 3500000 zat to")),
            "{e}"
        );
        let deflated = TxOut {
            value: 2_999_999,
            ..honest_out.clone()
        };
        assert!(check_provenance(&spend(&[op]), &srv, all, |_| Some(deflated.clone())).is_err());
        let other_script = TxOut {
            script_pubkey: crate::script::p2pkh_script(&[0x33; 20]),
            ..honest_out.clone()
        };
        assert!(
            check_provenance(&spend(&[op]), &srv, all, |_| Some(other_script.clone())).is_err()
        );
        let e = check_provenance(&spend(&[op]), &srv, all, |_| None).unwrap_err();
        assert!(e.to_string().contains("no record of the coin"), "{e}");
        // the per-output check alone: no stored coin compares nothing; a stored one must match
        assert_eq!(output_provenance(&op, Some(&plain.0), None), Ok(()));
        assert!(output_provenance(&op, Some(&plain.0), Some(&inflated)).is_err());
        // an unchecked input (a TOKEN on a YED path) is neither fetched nor compared
        assert_eq!(
            check_provenance(&spend(&[op]), &srv, |_| false, |_| None),
            Ok(())
        );
    }

    /// A server that omits a token from `GetAddressTokens` (and would answer the dry run "burned
    /// 0") cannot get a YED output spent as YEC: the TRANSFER that created it names it, at any
    /// value; the other outputs of the same transaction stay spendable.
    #[test]
    fn provenance_refuses_an_output_a_transfer_assigns() {
        let p = parent(
            &[50_000, 3_000_000],
            Some(Payload::Transfer {
                assignments: vec![Assignment {
                    vout: 0,
                    cents: 500,
                }],
            }),
        );
        let yed = OutPoint { txid: p.1, n: 0 };
        let change = OutPoint { txid: p.1, n: 1 };
        let all = |_: &OutPoint| true;
        assert_eq!(
            check3(&spend(&[yed]), &served(&[&p]), all),
            Err(GateError::InputCarriesYed {
                outpoint: format!("{}:0", crate::tx::txid_hex(&p.1)),
                payload: "transfer",
            })
        );
        assert_eq!(check3(&spend(&[change]), &served(&[&p]), all), Ok(()));
        // only the plain-YEC classes are checked: a TOKEN input (the YED paths) is not
        assert_eq!(check3(&spend(&[yed]), &served(&[&p]), |_| false), Ok(()));
    }

    /// MINT: `vout[1]` is the token; the other outputs are not YED. REDEEM: its change
    /// assignments are.
    #[test]
    fn provenance_mint_token_and_redeem_change() {
        let mint = parent(
            &[1_000_000, 70_000, 5_000],
            Some(Payload::Mint {
                term_class: 0,
                cents: 10_000,
                lock_height: 100,
                ref_height: 90,
                owner: crate::pq::PqKeyId {
                    scheme: crate::pq::SCHEME_SLH_DSA_SHA2_128S,
                    hash: [3; 32],
                },
                fee_vout: 2,
                attest_fee_vout: payload::FEE_VOUT_NONE,
            }),
        );
        let all = |_: &OutPoint| true;
        let at = |id: [u8; 32], n: u32| spend(&[OutPoint { txid: id, n }]);
        assert!(matches!(
            check3(&at(mint.1, 1), &served(&[&mint]), all),
            Err(GateError::InputCarriesYed {
                payload: "mint",
                ..
            })
        ));
        assert_eq!(check3(&at(mint.1, 2), &served(&[&mint]), all), Ok(()));
        let redeem = parent(
            &[40_000, 900_000],
            Some(Payload::Redeem {
                ref_height: 90,
                fee_vout: payload::FEE_VOUT_NONE,
                attest_fee_vout: payload::FEE_VOUT_NONE,
                assignments: vec![Assignment { vout: 0, cents: 7 }],
            }),
        );
        assert!(matches!(
            check3(&at(redeem.1, 0), &served(&[&redeem]), all),
            Err(GateError::InputCarriesYed {
                payload: "redeem",
                ..
            })
        ));
        assert_eq!(check3(&at(redeem.1, 1), &served(&[&redeem]), all), Ok(()));
    }

    /// Fail closed: the creating transaction withheld, replaced by other bytes (the txid does not
    /// match), or lacking the output: refused. A plain parent: spendable.
    #[test]
    fn provenance_fails_closed_on_a_lying_server() {
        let plain = parent(&[3_000_000], None);
        let other = parent(&[3_000_001], None);
        let op = OutPoint {
            txid: plain.1,
            n: 0,
        };
        let all = |_: &OutPoint| true;
        assert_eq!(check3(&spend(&[op]), &served(&[&plain]), all), Ok(()));
        let e = check3(&spend(&[op]), &HashMap::new(), all).unwrap_err();
        assert!(e.to_string().contains("did not return"), "{e}");
        let mut lie = HashMap::new();
        lie.insert(plain.1, other.0.clone());
        let e = check3(&spend(&[op]), &lie, all).unwrap_err();
        assert!(e.to_string().contains("another transaction"), "{e}");
        lie.insert(plain.1, vec![1, 2, 3]);
        let e = check3(&spend(&[op]), &lie, all).unwrap_err();
        assert!(e.to_string().contains("does not parse"), "{e}");
        let past = OutPoint {
            txid: plain.1,
            n: 5,
        };
        let e = check3(&spend(&[past]), &served(&[&plain]), all).unwrap_err();
        assert!(e.to_string().contains("no such output"), "{e}");
    }

    /// Layer 3 as each builder runs it, minus the fetch: the local layer on `path`, then
    /// [`check_provenance`] over exactly the inputs [`spent_as_yec`] names, with `served` as the
    /// server's `GetTransaction` answers (what [`confirm_provenance`] collects).
    fn layer3(
        path: Path,
        raw: &[u8],
        class_of: impl Fn(&OutPoint) -> Option<UtxoClass> + Copy,
        served: &HashMap<[u8; 32], Vec<u8>>,
    ) -> Result<(), GateError> {
        let tx = check(path, raw, class_of)?;
        let yec_inputs = spent_as_yec(path, &tx, class_of);
        check3(&tx, served, |op| yec_inputs.contains(op))
    }

    /// The YED builders' YEC fee inputs (YEW-PORT-6 item 1), against a lying server that omitted
    /// a token from `GetAddressTokens` so that it classifies `YEC`, and answers the dry run
    /// "burned 0". For each builder's path: its legitimate YED inputs (TOKENs whose creating
    /// TRANSFER or MINT assigns them, the own vault, the carrier, a named vault or intent) are
    /// accepted without being fetched as plain YEC; a token smuggled in as a fee coin is refused
    /// (`InputCarriesYed`); a fee coin whose creating transaction is withheld is refused
    /// (`InputProvenance`).
    #[test]
    fn provenance_on_every_yed_builder_fee_input() {
        // parents: a TRANSFER assigning vout 0 (a token) with plain change at vout 1; a MINT
        // (vout 1 the token); a TRANSFER assigning a 50,000-zat vout 0 (the smuggled coin); a
        // plain parent (an honest fee coin)
        let transfer = |v0: i64| {
            parent(
                &[v0, 3_000_000],
                Some(Payload::Transfer {
                    assignments: vec![Assignment {
                        vout: 0,
                        cents: 250,
                    }],
                }),
            )
        };
        let tp = transfer(crate::params::TOKEN_VALUE);
        let mp = parent(
            &[1_000_000, crate::params::TOKEN_VALUE, 5_000],
            Some(Payload::Mint {
                term_class: 0,
                cents: 10_000,
                lock_height: 100,
                ref_height: 90,
                owner: crate::pq::PqKeyId {
                    scheme: crate::pq::SCHEME_SLH_DSA_SHA2_128S,
                    hash: [3; 32],
                },
                fee_vout: 2,
                attest_fee_vout: payload::FEE_VOUT_NONE,
            }),
        );
        let sp = transfer(50_000);
        let hp = parent(&[2_000_000], None);
        let token_t = OutPoint { txid: tp.1, n: 0 };
        let token_m = OutPoint { txid: mp.1, n: 1 };
        let smuggled = OutPoint { txid: sp.1, n: 0 };
        let honest = OutPoint { txid: hp.1, n: 0 };
        let tchange = OutPoint { txid: tp.1, n: 1 }; // plain change of a TRANSFER: a fine fee coin
        let vault = OutPoint {
            txid: [0x11; 32],
            n: 0,
        };
        // the carrier: created by the wallet's own payload-free carrier funding
        let cp = parent(&[crate::params::CARRIER_VALUE, 900_000], None);
        let carrier = OutPoint { txid: cp.1, n: 0 };
        let named = OutPoint {
            txid: [0x55; 32],
            n: 0,
        };
        let classes: HashMap<OutPoint, UtxoClass> = [
            (token_t, UtxoClass::Token),
            (token_m, UtxoClass::Token),
            (smuggled, UtxoClass::Yec), // the server left it out of GetAddressTokens
            (honest, UtxoClass::Yec),
            (tchange, UtxoClass::FeeReserve),
            (vault, UtxoClass::Vault),
            (carrier, UtxoClass::Carrier),
            // a named vin[0] the store happens to know as YEC: still never checked as plain YEC
            (named, UtxoClass::Yec),
        ]
        .into_iter()
        .collect();
        let class = |op: &OutPoint| classes.get(op).copied();
        // the honest server: every parent; the lying one withholds the honest fee coin's parent
        let all = served(&[&tp, &mp, &sp, &hp, &cp]);
        let withheld = served(&[&tp, &mp, &sp, &cp]);
        let build = |inputs: &[OutPoint], first: TxOut, p: Option<Payload>| {
            let mut t = Transaction::new_v4();
            for op in inputs {
                t.vin.push(TxIn::new(*op));
            }
            t.vout.push(first);
            if let Some(p) = p {
                t.vout.push(TxOut {
                    value: 0,
                    script_pubkey: payload::payload_script(&encode(&p).unwrap()),
                });
            }
            t.serialize().unwrap()
        };
        let p2pkh = TxOut {
            value: 1,
            script_pubkey: script::p2pkh_script(&[3; 20]),
        };
        let p2sh = TxOut {
            value: crate::params::CARRIER_VALUE,
            script_pubkey: script::p2sh_script(&[9; 20]),
        };
        let mint_p = Payload::Mint {
            term_class: 0,
            cents: 10_000,
            lock_height: 10,
            ref_height: 5,
            owner: crate::pq::PqKeyId {
                scheme: 1,
                hash: [2; 32],
            },
            fee_vout: 0xff,
            attest_fee_vout: 0xff,
        };
        let transfer_p = Payload::Transfer {
            assignments: vec![Assignment {
                vout: 0,
                cents: 250,
            }],
        };
        let redeem_p = Payload::Redeem {
            ref_height: 5,
            fee_vout: 0xff,
            attest_fee_vout: 0xff,
            assignments: vec![],
        };
        // (path, the legitimate inputs before the fee coin, after it, first output, payload)
        type Case = (Path, Vec<OutPoint>, Vec<OutPoint>, TxOut, Option<Payload>);
        let cases: Vec<Case> = vec![
            (Path::Carrier, vec![], vec![], p2sh, None),
            (
                Path::Mint,
                vec![],
                vec![carrier],
                p2pkh.clone(),
                Some(mint_p),
            ),
            (
                Path::YedTransfer,
                vec![token_t, token_m],
                vec![],
                p2pkh.clone(),
                Some(transfer_p),
            ),
            (
                Path::Claim(named),
                vec![named, token_t, token_m],
                vec![carrier],
                p2pkh.clone(),
                Some(redeem_p.clone()),
            ),
            (
                Path::IntentRelease(named),
                vec![named],
                vec![],
                p2pkh.clone(),
                None,
            ),
        ];
        for (path, before, after, first, p) in cases {
            let with = |fee: &[OutPoint]| {
                let ins: Vec<OutPoint> = before
                    .iter()
                    .chain(fee.iter())
                    .chain(after.iter())
                    .copied()
                    .collect();
                build(&ins, first.clone(), p.clone())
            };
            let name = path.name();
            // the legitimate YED inputs with honest fee coins: accepted, and only the fee coins
            // are checked as plain YEC
            let raw = with(&[honest, tchange]);
            assert_eq!(layer3(path, &raw, class, &all), Ok(()), "{name}");
            let (tx, _) = Transaction::parse(&raw).unwrap();
            let mut checked: Vec<OutPoint> = spent_as_yec(path, &tx, class).into_iter().collect();
            checked.sort_by_key(|o| (o.txid, o.n));
            let mut want = vec![honest, tchange];
            want.extend(after.iter().copied()); // the carrier, spent into fees
            want.sort_by_key(|o| (o.txid, o.n));
            assert_eq!(checked, want, "{name}: the inputs checked as plain YEC");
            // a token smuggled in as a fee coin: refused, whatever the dry run says
            let raw = with(&[honest, smuggled]);
            assert_eq!(
                layer3(path, &raw, class, &all),
                Err(GateError::InputCarriesYed {
                    outpoint: format!("{}:0", crate::tx::txid_hex(&sp.1)),
                    payload: "transfer",
                }),
                "{name}"
            );
            // a fee coin whose creating transaction the server withholds: refused (fail closed)
            let raw = with(&[honest]);
            assert!(
                matches!(
                    layer3(path, &raw, class, &withheld),
                    Err(GateError::InputProvenance { .. })
                ),
                "{name}"
            );
        }
        // Redeem and release: the own vault and tokens only (the fee comes from the vault), so no
        // input is spent as plain YEC and nothing needs fetching; a YEC input is refused by the
        // local layer before layer 3.
        let none = HashMap::new();
        let raw = build(
            &[vault, token_t, token_m],
            p2pkh.clone(),
            Some(redeem_p.clone()),
        );
        assert_eq!(layer3(Path::Redeem, &raw, class, &none), Ok(()));
        let (tx, _) = Transaction::parse(&raw).unwrap();
        assert!(spent_as_yec(Path::Redeem, &tx, class).is_empty());
        let raw = build(&[vault, token_t, smuggled], p2pkh.clone(), Some(redeem_p));
        assert!(matches!(
            layer3(Path::Redeem, &raw, class, &all),
            Err(GateError::ForbiddenInput { class: "YEC", .. })
        ));
        let raw = build(&[vault], p2pkh.clone(), None);
        assert_eq!(layer3(Path::Release, &raw, class, &none), Ok(()));
        // Sweep: the carrier, back to plain YEC; checked, so a withheld funding refuses, and a
        // carrier a payload assigns YED (possible before the Falcon height) is refused.
        let raw = build(&[carrier], p2pkh.clone(), None);
        assert_eq!(layer3(Path::Sweep, &raw, class, &all), Ok(()));
        assert!(matches!(
            layer3(Path::Sweep, &raw, class, &none),
            Err(GateError::InputProvenance { .. })
        ));
        let assigned_carrier = OutPoint { txid: tp.1, n: 0 };
        let as_carrier = |op: &OutPoint| (*op == assigned_carrier).then_some(UtxoClass::Carrier);
        let raw = build(&[assigned_carrier], p2pkh.clone(), None);
        assert!(matches!(
            layer3(Path::Sweep, &raw, as_carrier, &all),
            Err(GateError::InputCarriesYed { .. })
        ));
        // PqSweep: the named coin (never classified) is checked: a payload-free parent passes,
        // a coin a TRANSFER assigns (an FN-DSA holder's YED the server left unlisted) is refused.
        let raw = build(&[honest], p2pkh.clone(), None);
        assert_eq!(layer3(Path::PqSweep(honest), &raw, |_| None, &all), Ok(()));
        let raw = build(&[smuggled], p2pkh, None);
        assert!(matches!(
            layer3(Path::PqSweep(smuggled), &raw, |_| None, &all),
            Err(GateError::InputCarriesYed { .. })
        ));
    }

    /// Property: on every path, [`spent_as_yec`] is exactly the inputs of class `YEC`,
    /// `FEE_RESERVE`, `PQ_OWNED` or `CARRIER`, less the named `vin[0]` of the claim and intent
    /// release paths, plus the named coin of the post-quantum move; never a TOKEN, VAULT or any
    /// other class.
    #[test]
    fn spent_as_yec_property() {
        let mut rng = Rng(0x00c0_ffee_1234);
        let named = OutPoint {
            txid: [0xaa; 32],
            n: 0,
        };
        for _ in 0..500 {
            let n = 1 + rng.below(8) as usize;
            let mut classes: HashMap<OutPoint, UtxoClass> = HashMap::new();
            let mut t = Transaction::new_v4();
            for i in 0..n {
                let op = if i == 0 && rng.below(2) == 0 {
                    named
                } else {
                    OutPoint {
                        txid: [i as u8 + 1; 32],
                        n: rng.below(3) as u32,
                    }
                };
                if rng.below(8) != 0 {
                    classes.insert(op, ALL[rng.below(ALL.len() as u64) as usize]);
                }
                t.vin.push(TxIn::new(op));
            }
            let class = |op: &OutPoint| classes.get(op).copied();
            for path in [
                Path::Yec,
                Path::YedTransfer,
                Path::Carrier,
                Path::Mint,
                Path::Redeem,
                Path::Release,
                Path::Claim(named),
                Path::Sweep,
                Path::IntentRelease(named),
                Path::PqSweep(named),
                Path::Shield,
                Path::PqSpend,
            ] {
                let got = spent_as_yec(path, &t, class);
                let skips_named = matches!(path, Path::Claim(_) | Path::IntentRelease(_));
                let takes_named = matches!(path, Path::PqSweep(_));
                for (k, i) in t.vin.iter().enumerate() {
                    let plain = matches!(
                        class(&i.prevout),
                        Some(
                            UtxoClass::Yec
                                | UtxoClass::FeeReserve
                                | UtxoClass::PqOwned
                                | UtxoClass::Carrier
                        )
                    );
                    let want = if k == 0 && skips_named {
                        false
                    } else {
                        plain || (k == 0 && takes_named)
                    };
                    if want {
                        assert!(got.contains(&i.prevout), "{path:?} {k}");
                    }
                    // TOKEN, VAULT, HELD, PENDING_TOKEN, UNKNOWN_P2SH, FOREIGN, unknown: never
                    // (each outpoint appears once in these transactions)
                    if !want {
                        assert!(!got.contains(&i.prevout), "{path:?} {k}");
                    }
                }
                assert!(got.iter().all(|op| t.vin.iter().any(|i| i.prevout == *op)));
            }
        }
    }

    /// Review YEW-REVIEW-4 M1. A claim cancel (CANCEL_COSIGN) re-issues the burn to the
    /// claimant's refund output at any non-zero value, without an assignment: every output at
    /// index >= 1 of such a parent is refused as plain YEC (vout[0] is the re-created vault). A
    /// parent whose payload has a type or version this build does not know is refused (fail
    /// closed); a known type with a malformed body is non-Yellowback and passes.
    #[test]
    fn provenance_cancel_refund_and_unknown_payloads() {
        let cancel = parent(&[5_000_000, 12_345, 800_000], Some(Payload::CancelCosign));
        let all = |_: &OutPoint| true;
        let at = |id: [u8; 32], n: u32| spend(&[OutPoint { txid: id, n }]);
        assert_eq!(check3(&at(cancel.1, 0), &served(&[&cancel]), all), Ok(()));
        for n in [1, 2] {
            assert_eq!(
                check3(&at(cancel.1, n), &served(&[&cancel]), all),
                Err(GateError::InputCarriesYed {
                    outpoint: format!("{}:{n}", crate::tx::txid_hex(&cancel.1)),
                    payload: "cancelcosign",
                }),
            );
        }
        let with_data = |data: Vec<u8>| {
            let mut t = Transaction::new_v4();
            t.vin.push(TxIn::new(OutPoint {
                txid: [0xee; 32],
                n: 0,
            }));
            t.vout.push(TxOut {
                value: 70_000,
                script_pubkey: crate::script::p2pkh_script(&[0x11; 20]),
            });
            t.vout.push(TxOut {
                value: 0,
                script_pubkey: payload::payload_script(&data),
            });
            let raw = t.serialize().unwrap();
            let (_, id) = Transaction::parse(&raw).unwrap();
            (raw, id)
        };
        for data in [
            vec![0x59, 0x42, 0x03, 0x0a], // a type this build does not know
            vec![0x59, 0x42, 0x05, 0x02, 0, 0, 0, 0], // a version it does not know
        ] {
            let p = with_data(data);
            let e = check3(&at(p.1, 0), &served(&[&p]), all).unwrap_err();
            assert!(e.to_string().contains("does not know"), "{e}");
        }
        // a TRANSFER with a malformed body: non-Yellowback (the node assigns nothing)
        let p = with_data(vec![0x59, 0x42, 0x03, 0x02, 1, 0, 1, 0, 0, 0, 9]);
        assert_eq!(check3(&at(p.1, 0), &served(&[&p]), all), Ok(()));
    }

    /// Property: over random parents (plain, TRANSFER with random assignments, MINT, REDEEM,
    /// CANCEL_COSIGN) and
    /// every output, an input is refused exactly when the node's `FindPayload` reading assigns it
    /// YED; nothing assigned is ever let through.
    #[test]
    fn provenance_property_over_random_parents() {
        let mut rng = Rng(0x5eed_1234_abcd);
        for _ in 0..300 {
            let n_out = 1 + rng.below(6) as usize;
            let outs: Vec<i64> = (0..n_out)
                .map(|_| 1 + rng.below(5_000_000) as i64)
                .collect();
            let kind = rng.below(5);
            let p = match kind {
                0 => None,
                1 | 3 => {
                    let mut a: Vec<Assignment> = Vec::new();
                    for v in 0..n_out as u8 {
                        if rng.below(2) == 0 {
                            a.push(Assignment {
                                vout: v,
                                cents: 1 + rng.below(1000) as u32,
                            });
                        }
                    }
                    if a.is_empty() && kind == 1 {
                        a.push(Assignment { vout: 0, cents: 1 });
                    }
                    Some(if kind == 1 {
                        Payload::Transfer { assignments: a }
                    } else {
                        Payload::Redeem {
                            ref_height: 1,
                            fee_vout: payload::FEE_VOUT_NONE,
                            attest_fee_vout: payload::FEE_VOUT_NONE,
                            assignments: a,
                        }
                    })
                }
                4 => Some(Payload::CancelCosign),
                _ if n_out >= 2 => Some(Payload::Mint {
                    term_class: 0,
                    cents: 100,
                    lock_height: 1,
                    ref_height: 1,
                    owner: crate::pq::PqKeyId {
                        scheme: crate::pq::SCHEME_SLH_DSA_SHA2_128S,
                        hash: [1; 32],
                    },
                    fee_vout: payload::FEE_VOUT_NONE,
                    attest_fee_vout: payload::FEE_VOUT_NONE,
                }),
                _ => None,
            };
            let par = parent(&outs, p.clone());
            for n in 0..n_out as u32 {
                let want_yed = match &p {
                    Some(Payload::Mint { .. }) => n == 1,
                    Some(Payload::CancelCosign) => n >= 1,
                    Some(q) => q.assignments().iter().any(|a| a.vout as u32 == n),
                    None => false,
                };
                let r = check3(
                    &spend(&[OutPoint { txid: par.1, n }]),
                    &served(&[&par]),
                    |_| true,
                );
                assert_eq!(
                    matches!(r, Err(GateError::InputCarriesYed { .. })),
                    want_yed,
                    "{p:?} vout {n}: {r:?}"
                );
                if !want_yed {
                    assert_eq!(r, Ok(()));
                }
            }
        }
    }
}
