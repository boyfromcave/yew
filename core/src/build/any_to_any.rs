// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The shape planning of a send between address types (beta2 D-2, D-4, D-5, D-8), shared by the
//! YEW app ([`super::pq_send`]) and yewd's `z_sendmany` (`yewd/wallet/src/zsend.rs`): one
//! implementation of the privacy-policy lattice, the post-quantum fee rule, the size of a shape,
//! the dust thresholds, the post-quantum source's coin selection with its change back to the
//! source (D-4), and the balance split by address type and scheme (beta2 item 15).
//!
//! Pure functions over values and scripts: no store, no node, no key. The callers select the
//! candidate coins (each with its own Yellowback filter: yewd's `yed_reserved`, the app's UTXO
//! classes), sign, and submit. The error texts are ycash6's (`wallet/wallet_tx_builder.cpp`
//! `PreparePQTransaction`, `asyncrpcoperation_common.cpp` `ThrowInputSelectionError`) and
//! ycash-dd 8e67b2a35's PQ fee cap, byte for byte, with yewd's two additions (the checked
//! recipient total, review L2; the unsettled fee).

use std::fmt;

use crate::params::{zip317_conventional_fee, ZIP317_INPUT_SIZE, ZIP317_OUTPUT_SIZE};
use crate::pq;
use crate::tx::{OutPoint, MAX_P2PKH_SCRIPT_SIG};

/// The privacy policies of 6.x `z_sendmany` (`PrivacyPolicy`), weakest last.
pub const PRIVACY_POLICIES: &[&str] = &[
    "FullPrivacy",
    "AllowRevealedAmounts",
    "AllowRevealedRecipients",
    "AllowRevealedSenders",
    "AllowFullyTransparent",
    "AllowLinkingAccountAddresses",
    "NoPrivacy",
];

/// `MAX_PQ_INPUTS_PER_TX` (ycash6 `wallet/asyncrpcoperation_common.h`).
pub const MAX_PQ_INPUTS_PER_TX: usize = 100;
/// `MAX_STANDARD_TX_SIGOPS` (`policy/policy.h`: `MAX_BLOCK_SIGOPS / 5`).
pub const MAX_STANDARD_TX_SIGOPS: usize = 20_000 / 5;
/// `pq::SIGOP_COST`: the policy sigops of one `OP_CHECKPQSIG` (`crypto/pq/scheme.h`).
pub const PQ_SIGOP_COST: usize = 20;
/// `LEGACY_DEFAULT_FEE`: the floor of `PQSizeFee` (`PQSizeFee(LEGACY_DEFAULT_FEE, bytes)`).
pub const LEGACY_DEFAULT_FEE: i64 = 1000;
/// `DEFAULT_EXEMPT_SAPLING_OUTPUTS` / `DEFAULT_PER_SAPLING_OUTPUT_FEE` (ycash6 -feepolicy=peroutput).
pub const EXEMPT_SAPLING_OUTPUTS: usize = 50;
/// See [`EXEMPT_SAPLING_OUTPUTS`].
pub const PER_SAPLING_OUTPUT_FEE: i64 = 1000;
/// ycash6 `WalletTxBuilder::DefaultDustThreshold`: a P2PKH output's dust threshold at the fixed
/// `ONE_THIRD_DUST_THRESHOLD_RATE` (100 zat/kB): 3 × (34 + 148) × 100 / 1000.
pub const CHANGE_DUST_THRESHOLD: i64 = 54;
/// `MAX_MONEY` (`amount.h`).
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;
/// A v4 Sapling spend description (ZIP-243 size).
pub const SAPLING_SPEND_BYTES: usize = 384;
/// A v4 Sapling output description.
pub const SAPLING_OUTPUT_BYTES: usize = 948;
/// The Sapling binding signature.
pub const SAPLING_BINDING_SIG_BYTES: usize = 64;
/// The schemes a balance split reports, always both and in this order (beta2 item 15; ycashd's
/// `PQ_BALANCE_SCHEMES`): SLH-DSA-SHA2-128s, then FN-DSA-512.
pub const PQ_BALANCE_SCHEMES: [u8; 2] = [pq::SCHEME_SLH_DSA_SHA2_128S, pq::SCHEME_FN_DSA_512];

/// ycashd's `FormatMoney`: at least two decimals, trailing zeros dropped (`1.00`, `0.0001`).
pub fn format_money(zat: i64) -> String {
    let sign = if zat < 0 { "-" } else { "" };
    let z = zat.unsigned_abs();
    let frac = format!("{:08}", z % 100_000_000);
    let mut frac = frac.trim_end_matches('0').to_string();
    while frac.len() < 2 {
        frac.push('0');
    }
    format!("{sign}{}.{frac}", z / 100_000_000)
}

/// The privacy levels a policy permits (ycash6 `TransactionStrategy::IsCompatibleWith`, the
/// lattice of `PrivacyPolicyMeet`): whether `policy` allows a transaction that needs `required`.
/// An unknown name is `NoPrivacy` (callers check the name against [`PRIVACY_POLICIES`] first).
pub fn policy_allows(policy: &str, required: &str) -> bool {
    let allowed: &[&str] = match policy {
        "FullPrivacy" => &["FullPrivacy"],
        "AllowRevealedAmounts" => &["FullPrivacy", "AllowRevealedAmounts"],
        "AllowRevealedRecipients" => &[
            "FullPrivacy",
            "AllowRevealedAmounts",
            "AllowRevealedRecipients",
        ],
        "AllowRevealedSenders" => &[
            "FullPrivacy",
            "AllowRevealedAmounts",
            "AllowRevealedSenders",
        ],
        "AllowFullyTransparent" => &[
            "FullPrivacy",
            "AllowRevealedAmounts",
            "AllowRevealedRecipients",
            "AllowRevealedSenders",
            "AllowFullyTransparent",
        ],
        "AllowLinkingAccountAddresses" => &[
            "FullPrivacy",
            "AllowRevealedAmounts",
            "AllowRevealedSenders",
            "AllowLinkingAccountAddresses",
        ],
        _ => return true, // NoPrivacy
    };
    allowed.contains(&required)
}

/// The size of a compact-size length prefix.
pub fn compact(n: usize) -> usize {
    match n {
        0..=252 => 1,
        253..=0xffff => 3,
        _ => 5,
    }
}

/// A Sapling bundle's padded output count (the builder pads a lone output to two).
pub fn padded(outputs: usize) -> usize {
    if outputs == 1 {
        2
    } else {
        outputs
    }
}

/// ycash6 `CalcZIP317Fee` under `-feepolicy=peroutput` (the default): the base of the
/// post-quantum fee rule without an explicit fee, over the padded Sapling output count:
/// max(1000, (n − 50) × 1000 above 50 outputs, else 1000).
pub fn peroutput_fee(padded_sapling_outputs: usize) -> i64 {
    let per = if padded_sapling_outputs > EXEMPT_SAPLING_OUTPUTS {
        (padded_sapling_outputs - EXEMPT_SAPLING_OUTPUTS) as i64 * PER_SAPLING_OUTPUT_FEE
    } else {
        PER_SAPLING_OUTPUT_FEE
    };
    PER_SAPLING_OUTPUT_FEE.max(per)
}

/// ycash6 `PQBuilderFee(base, shape)`: max(min(max(base, PQSizeFee(LEGACY_DEFAULT_FEE, bytes)),
/// PQMaxTxFee()), the shape's ZIP-317 conventional fee), the size fee at the node's plain rate.
pub fn pq_builder_fee(base: i64, bytes: usize, conventional: i64, rate: i64, cap: i64) -> i64 {
    let size_fee = LEGACY_DEFAULT_FEE.max(rate * bytes as i64 / 1000);
    base.max(size_fee).min(cap).max(conventional)
}

/// The recipients' total, checked: no overflow, within `MAX_MONEY` (review L2; ycash6 has no
/// such check, a total out of range reaching its insufficient-funds answer instead).
pub fn checked_total(amounts: impl Iterator<Item = i64>) -> Result<i64, PlanError> {
    let mut t = 0i64;
    for a in amounts {
        t = t
            .checked_add(a)
            .filter(|t| (0..=MAX_MONEY).contains(t))
            .ok_or(PlanError::TotalOutOfRange)?;
    }
    Ok(t)
}

/// One post-quantum input's serialized size (`PQSpendInputSize`): the outpoint and sequence (40),
/// the scriptSig's compact size and the chunked pushes.
pub fn pq_input_size(scheme: u8) -> usize {
    let ss = pq::pq_sig_pushes_size(scheme).unwrap_or(0);
    40 + if ss > 252 { 3 } else { 1 } + ss
}

/// `GetPQDustThreshold` at `ONE_THIRD_DUST_THRESHOLD_RATE` (100 zat/kB): 3 × the fee of the output
/// plus the input that spends it, the input a post-quantum spend for `TX_PQPKH`, 148 bytes otherwise
/// (`CTxOut::GetDustThreshold`: 54 zat for P2PKH).
pub fn dust_threshold(script: &[u8]) -> i64 {
    let out = 8 + if script.len() > 252 { 3 } else { 1 } + script.len();
    let input = match pq::pqpkh_of(script) {
        Some(id) => pq_input_size(id.scheme),
        None => 148,
    };
    3 * (100 * (out + input) as i64 / 1000)
}

/// The scriptSig a wallet coin's input will carry: a post-quantum signature's pushes for
/// `TX_PQPKH`, the P2PKH maximum otherwise.
pub fn script_sig_size(script: &[u8]) -> usize {
    match pq::pqpkh_of(script) {
        Some(id) => pq::pq_sig_pushes_size(id.scheme).unwrap_or(MAX_P2PKH_SCRIPT_SIG),
        None => MAX_P2PKH_SCRIPT_SIG,
    }
}

/// The serialized size and the ZIP-317 conventional fee of a transparent shape with Sapling parts:
/// each input with the scriptSig its coin's script makes (a post-quantum signature's pushes at
/// their largest), each output at its real size, `spends` Sapling spends and `outs` (padded)
/// outputs.
pub fn shape_size<'a>(
    input_scripts: impl Iterator<Item = &'a [u8]>,
    outputs: &[(Vec<u8>, i64)],
    spends: usize,
    outs: usize,
) -> (usize, i64) {
    let mut n_in = 0usize;
    let in_bytes: usize = input_scripts
        .map(|s| {
            n_in += 1;
            let n = script_sig_size(s);
            36 + compact(n) + n + 4
        })
        .sum();
    let out_bytes: usize = outputs
        .iter()
        .map(|o| 8 + compact(o.0.len()) + o.0.len())
        .sum();
    let sapling = if spends + outs > 0 {
        spends * SAPLING_SPEND_BYTES + outs * SAPLING_OUTPUT_BYTES + SAPLING_BINDING_SIG_BYTES
    } else {
        0
    };
    // header, version group, lock time, expiry, valueBalance and the three counts of a v4
    // transaction, the input and output counts
    let fixed = 4 + 4 + 4 + 4 + 8 + 3 + compact(n_in) + compact(outputs.len());
    let bytes = fixed + in_bytes + out_bytes + sapling;
    let conventional = zip317_conventional_fee(in_bytes, out_bytes, spends.max(outs));
    (bytes, conventional)
}

/// ZIP-317's conventional fee of a `z_sendmany` shape: P2PKH inputs and outputs, Sapling spends,
/// and Sapling outputs padded to two whenever the bundle is present.
pub fn conventional_fee(t_in: usize, t_out: usize, z_spends: usize, z_outs: usize) -> i64 {
    conventional_fee_bytes(t_in, t_out, 0, z_spends, z_outs)
}

/// [`conventional_fee`] with `extra_out_bytes` more output bytes (a `TX_PQPKH` output is 10 bytes
/// longer than a P2PKH one).
pub fn conventional_fee_bytes(
    t_in: usize,
    t_out: usize,
    extra_out_bytes: usize,
    z_spends: usize,
    z_outs: usize,
) -> i64 {
    let padded = if z_spends + z_outs > 0 {
        z_outs.max(2)
    } else {
        0
    };
    let in_bytes = t_in * ZIP317_INPUT_SIZE;
    let out_bytes = t_out * ZIP317_OUTPUT_SIZE + extra_out_bytes;
    zip317_conventional_fee(in_bytes, out_bytes, z_spends.max(padded))
}

/// The transparent value of a wallet split by address type and post-quantum scheme (beta2 item
/// 15: ycashd's `GetWalletBalanceSplit`, `z_gettotalbalance`'s `transparent_ecc`/`transparent_pq`/
/// `pq_by_scheme`). Add each counted coin with [`TypeSplit::add`]; ECC is the total less the
/// post-quantum part.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TypeSplit {
    /// Every coin added, zat.
    pub transparent: i64,
    /// The `TX_PQPKH` part by scheme number (index 1 SLH-DSA, 2 FN-DSA-512; 0 unused).
    pub pq: [i64; 3],
}

impl TypeSplit {
    /// Count a coin of `value` zat paying `script`.
    pub fn add(&mut self, script: &[u8], value: i64) {
        self.transparent += value;
        if let Some(id) = pq::pqpkh_of(script) {
            if let Some(slot) = self.pq.get_mut(id.scheme as usize) {
                *slot += value;
            }
        }
    }

    /// The post-quantum part of every registered scheme.
    pub fn pq_total(&self) -> i64 {
        self.pq[1] + self.pq[2]
    }

    /// The ECC (P2PKH and any other non-PQ script) part.
    pub fn ecc(&self) -> i64 {
        self.transparent - self.pq_total()
    }

    /// The part of `scheme` (0 outside the registry).
    pub fn scheme(&self, scheme: u8) -> i64 {
        self.pq.get(scheme as usize).copied().unwrap_or(0)
    }
}

/// One recipient of a planned send: a transparent script (ECC P2PKH/P2SH or `TX_PQPKH`) or a
/// Sapling address (`None`: its output goes into the Sapling part).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanRecipient {
    /// The scriptPubKey, `None` for a Sapling recipient.
    pub script: Option<Vec<u8>>,
    /// The amount, zat.
    pub amount: i64,
}

/// A candidate coin of a post-quantum source: what the planner reads (`outpoint`, `value`,
/// `script`) and the caller's own handle (`key`), carried through to the selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqCoin<K> {
    /// The outpoint.
    pub outpoint: OutPoint,
    /// Its value, zat.
    pub value: i64,
    /// Its scriptPubKey (the source's `TX_PQPKH`).
    pub script: Vec<u8>,
    /// The caller's key reference.
    pub key: K,
}

/// What [`plan_pq_source`] settled on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqSourcePlan<K> {
    /// The coins to spend, in input order.
    pub selected: Vec<PqCoin<K>>,
    /// The transparent outputs in `vout` order: the ECC recipients, then the post-quantum ones
    /// (ycash6's order), the change last (back to the source, D-4).
    pub transparent_outputs: Vec<(Vec<u8>, i64)>,
    /// The change to the source, zat (0: none; change below the source's dust threshold is in
    /// the fee).
    pub change: i64,
    /// The fee, zat (any folded dust change included).
    pub fee: i64,
    /// The recipients' total, zat.
    pub send: i64,
    /// The padded Sapling output count.
    pub sapling_outputs: usize,
    /// The estimated serialized size, bytes (the post-quantum signatures at their largest).
    pub estimated_bytes: usize,
}

/// A refusal of the planner. `Display` is the node's text; [`PlanError::rpc_code`] its code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// A transparent recipient (ECC or post-quantum) under a policy that forbids revealing it.
    TransparentRecipientNotAllowed,
    /// A Sapling recipient paid from transparent funds under a policy that forbids it.
    RevealingSaplingAmountNotAllowed,
    /// The recipients' total overflows or exceeds `MAX_MONEY`.
    TotalOutOfRange,
    /// An explicit fee above the post-quantum cap, or the settled fee (folded change included).
    FeeAboveCap {
        /// The fee.
        fee: i64,
        /// The cap.
        cap: i64,
    },
    /// An explicit fee below what the shape needs.
    FeeBelowNeeded {
        /// The fee given.
        fee: i64,
        /// The fee needed.
        needed: i64,
    },
    /// The source has no spendable coin.
    NoCoins,
    /// The source's coins do not cover the total and the fee.
    Insufficient {
        /// What the selection reached.
        have: i64,
        /// The total and the fee.
        need: i64,
    },
    /// More post-quantum inputs than one transaction may carry.
    TooManyInputs(usize),
    /// More signature operations than a standard transaction allows.
    TooManySigops(usize),
    /// The fee did not settle in 16 rounds.
    Unsettled,
    /// The privacy policy does not permit the shape.
    Policy {
        /// The policy given.
        policy: String,
        /// The policy the shape needs.
        required: &'static str,
    },
    /// The signed transaction needs more than the estimate settled on.
    EstimateShort {
        /// The settled fee.
        fee: i64,
        /// The fee the signed transaction needs.
        needed: i64,
    },
}

/// The input-selection errors of ycash6 `ThrowInputSelectionError` (`asyncrpcoperation_common.cpp`).
const TRANSPARENT_RECIPIENT_NOT_ALLOWED: &str = "This transaction would have transparent recipients, which is not enabled by default because it will publicly reveal transaction recipients and amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit with the `privacyPolicy` parameter set to `AllowRevealedRecipients` or weaker if you wish to allow this transaction to proceed anyway.";
const REVEALING_SAPLING_AMOUNT_NOT_ALLOWED: &str = "Could not send to the Sapling shielded pool without spending non-Sapling funds, which would reveal transaction amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit with the `privacyPolicy` parameter set to `AllowRevealedAmounts` or weaker if you wish to allow this transaction to proceed anyway.";

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = format_money;
        match self {
            PlanError::TransparentRecipientNotAllowed => f.write_str(TRANSPARENT_RECIPIENT_NOT_ALLOWED),
            PlanError::RevealingSaplingAmountNotAllowed => {
                f.write_str(REVEALING_SAPLING_AMOUNT_NOT_ALLOWED)
            }
            PlanError::TotalOutOfRange => {
                f.write_str("Invalid parameter, the recipients' total amount is out of range")
            }
            PlanError::FeeAboveCap { fee, cap } => write!(
                f,
                "Fee {} is above the {} cap on a post-quantum spend (-maxtxfee, or $2 at the attested price, at most -yellowbackmaxtxfee)",
                m(*fee),
                m(*cap)
            ),
            PlanError::FeeBelowNeeded { fee, needed } => write!(
                f,
                "Fee {} is below the {} this post-quantum spend needs",
                m(*fee),
                m(*needed)
            ),
            PlanError::NoCoins => f.write_str(
                "Insufficient transparent funds, no UTXOs found for taddr from address.",
            ),
            PlanError::Insufficient { have, need } => write!(
                f,
                "Insufficient transparent funds, have {}, need {}",
                m(*have),
                m(*need)
            ),
            PlanError::TooManyInputs(n) => write!(
                f,
                "This send needs {n} post-quantum inputs, more than the {MAX_PQ_INPUTS_PER_TX} one transaction may carry; combine the address's coins first with z_mergetoaddress"
            ),
            PlanError::TooManySigops(n) => write!(
                f,
                "This transaction needs {n} signature operations, more than the {MAX_STANDARD_TX_SIGOPS} a standard transaction allows; spend fewer inputs"
            ),
            PlanError::Unsettled => {
                f.write_str("Could not settle the fee of this post-quantum spend")
            }
            PlanError::Policy { policy, required } => write!(
                f,
                "Failed to build transaction: The specified privacy policy, {policy}, does not permit the creation of the requested transaction. Select {required} or weaker to allow this transaction to be constructed."
            ),
            PlanError::EstimateShort { fee, needed } => write!(
                f,
                "Post-quantum fee estimate {} fell short of the {} the signed transaction needs",
                m(*fee),
                m(*needed)
            ),
        }
    }
}

impl std::error::Error for PlanError {}

impl PlanError {
    /// The JSON-RPC code ycashd answers with (`RPC_INVALID_PARAMETER` -8, `RPC_WALLET_ERROR` -4,
    /// `RPC_WALLET_INSUFFICIENT_FUNDS` -6).
    pub fn rpc_code(&self) -> i64 {
        match self {
            PlanError::TransparentRecipientNotAllowed
            | PlanError::RevealingSaplingAmountNotAllowed
            | PlanError::TotalOutOfRange
            | PlanError::FeeAboveCap { .. }
            | PlanError::FeeBelowNeeded { .. } => -8,
            PlanError::NoCoins | PlanError::Insufficient { .. } => -6,
            PlanError::TooManyInputs(_)
            | PlanError::TooManySigops(_)
            | PlanError::Unsettled
            | PlanError::Policy { .. }
            | PlanError::EstimateShort { .. } => -4,
        }
    }
}

/// ycash6 `WalletTxBuilder::PreparePQTransaction` (beta2 D-2, D-4, D-5): a send from the
/// post-quantum address whose `TX_PQPKH` is `source`, over `coins` (the caller's candidates:
/// already filtered to unspent, unlocked, mature, deep enough, never YED; any order). The fee is
/// priced on the transaction's size (`PQBuilderFee` at `rate` zat/kB, capped at `cap`) and settled
/// with the selection, largest coins first; change below the source's dust threshold goes to the
/// fee, any other back to `source`; `policy` is checked as a transparent sender's. `fee` is an
/// explicit fee, `None` for the node's default.
pub fn plan_pq_source<K: Clone>(
    coins: &[PqCoin<K>],
    source: &[u8],
    recipients: &[PlanRecipient],
    fee: Option<i64>,
    policy: &str,
    rate: i64,
    cap: i64,
) -> Result<PqSourcePlan<K>, PlanError> {
    if let Some(f) = fee {
        // EnsurePQFeeWithinCap (ycash-dd 8e67b2a35, audit H1): never build what the commit refuses
        if f > cap {
            return Err(PlanError::FeeAboveCap { fee: f, cap });
        }
    }
    // the payments: a PQ source has no shielded funds, so a Sapling recipient reveals the
    // amount; a transparent one (ECC or PQ) the recipient (D-5)
    for r in recipients {
        match r.script {
            Some(_) if !policy_allows(policy, "AllowRevealedRecipients") => {
                return Err(PlanError::TransparentRecipientNotAllowed)
            }
            None if !policy_allows(policy, "AllowRevealedAmounts") => {
                return Err(PlanError::RevealingSaplingAmountNotAllowed)
            }
            _ => {}
        }
    }
    let send = checked_total(recipients.iter().map(|r| r.amount))?;
    let mut coins: Vec<PqCoin<K>> = coins.to_vec();
    if coins.is_empty() {
        return Err(PlanError::NoCoins);
    }
    coins.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then((a.outpoint.txid, a.outpoint.n).cmp(&(b.outpoint.txid, b.outpoint.n)))
    });
    // the transparent outputs: the ECC recipients, then the PQ ones (ycash6's order), the
    // change last; the Sapling ones in the Sapling part
    let mut t_outs: Vec<(Vec<u8>, i64)> = Vec::new();
    for pq_first in [false, true] {
        for r in recipients {
            if let Some(s) = &r.script {
                if pq::pqpkh_of(s).is_some() == pq_first {
                    t_outs.push((s.clone(), r.amount));
                }
            }
        }
    }
    let n_z = recipients.iter().filter(|r| r.script.is_none()).count();
    let z_outs = padded(n_z);
    let base = fee.unwrap_or_else(|| peroutput_fee(z_outs));
    let mut cur_fee = base;
    let mut selected: Vec<PqCoin<K>> = Vec::new();
    let mut change;
    let mut bytes;
    let mut round = 0;
    loop {
        if round >= 16 {
            return Err(PlanError::Unsettled);
        }
        round += 1;
        let target = send + cur_fee;
        selected.clear();
        let mut sum = 0i64;
        for c in &coins {
            if sum >= target {
                break;
            }
            sum += c.value;
            selected.push(c.clone());
        }
        if sum < target {
            return Err(PlanError::Insufficient {
                have: sum,
                need: target,
            });
        }
        change = sum - target;
        // change below the PQ dust threshold goes to the fee: no dust output is made
        let mut dust_to_fee = 0;
        if change > 0 && change < dust_threshold(source) {
            dust_to_fee = change;
            change = 0;
        }
        let mut outs = t_outs.clone();
        if change > 0 {
            outs.push((source.to_vec(), change));
        }
        // EnsurePQShapeStandard
        if selected.len() > MAX_PQ_INPUTS_PER_TX {
            return Err(PlanError::TooManyInputs(selected.len()));
        }
        let sigops = selected.len() * PQ_SIGOP_COST
            + outs
                .iter()
                .filter(|o| crate::script::p2pkh_hash(&o.0).is_some())
                .count();
        if sigops > MAX_STANDARD_TX_SIGOPS {
            return Err(PlanError::TooManySigops(sigops));
        }
        let (b, conventional) = shape_size(
            selected.iter().map(|c| c.script.as_slice()),
            &outs,
            0,
            z_outs,
        );
        bytes = b;
        let needed = pq_builder_fee(base, bytes, conventional, rate, cap);
        if needed <= cur_fee {
            cur_fee += dust_to_fee;
            // review L3: the fee paid, folded change included, within the cap
            if cur_fee > cap {
                return Err(PlanError::FeeAboveCap { fee: cur_fee, cap });
            }
            break;
        }
        if let Some(f) = fee {
            return Err(PlanError::FeeBelowNeeded { fee: f, needed });
        }
        cur_fee = needed;
    }
    // ApproveAndBuild: a transparent sender, and a transparent recipient if any (the D-4
    // change is one)
    let required = if !t_outs.is_empty() || change > 0 {
        "AllowFullyTransparent"
    } else {
        "AllowRevealedSenders"
    };
    if !policy_allows(policy, required) {
        return Err(PlanError::Policy {
            policy: policy.to_string(),
            required,
        });
    }
    let mut transparent_outputs = t_outs;
    if change > 0 {
        // beta2 D-4: the change returns to the source address (same scheme, no new key)
        transparent_outputs.push((source.to_vec(), change));
    }
    Ok(PqSourcePlan {
        selected,
        transparent_outputs,
        change,
        fee: cur_fee,
        send,
        sapling_outputs: z_outs,
        estimated_bytes: bytes,
    })
}

/// The signed transaction re-priced (ycash6 `PQBuilderFee(fee, signedTx)`, the base the fee the
/// estimate settled on): `raw_len` its serialized size, `conventional` its ZIP-317 fee.
pub fn check_signed_fee(
    settled: i64,
    raw_len: usize,
    conventional: i64,
    rate: i64,
    cap: i64,
) -> Result<(), PlanError> {
    let needed = pq_builder_fee(settled, raw_len, conventional, rate, cap);
    if needed > settled {
        return Err(PlanError::EstimateShort {
            fee: settled,
            needed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pq_script(scheme: u8, b: u8) -> Vec<u8> {
        pq::pqpkh_script(&pq::PqKeyId {
            scheme,
            hash: [b; 32],
        })
        .unwrap()
    }

    fn coin(v: i64, n: u32, script: &[u8]) -> PqCoin<()> {
        PqCoin {
            outpoint: OutPoint { txid: [7; 32], n },
            value: v,
            script: script.to_vec(),
            key: (),
        }
    }

    #[test]
    fn money_and_fees() {
        assert_eq!(format_money(100_000_000), "1.00");
        assert_eq!(format_money(10_000), "0.0001");
        assert_eq!(format_money(-12_345_678), "-0.12345678");
        assert_eq!(conventional_fee(1, 1, 0, 0), 1000);
        assert_eq!(conventional_fee(1, 0, 0, 1), 1500);
        assert_eq!(peroutput_fee(0), 1000);
        assert_eq!(peroutput_fee(52), 2000);
        let p2pkh = [&[0x76, 0xa9, 0x14][..], &[0u8; 20], &[0x88, 0xac]].concat();
        assert_eq!(dust_threshold(&p2pkh), CHANGE_DUST_THRESHOLD);
        assert_eq!(dust_threshold(&pq_script(1, 0)), 2406);
        assert_eq!(dust_threshold(&pq_script(2, 0)), 498);
        assert_eq!(pq_input_size(1), crate::params::pq_spend_input_size(1));
        assert_eq!(checked_total([MAX_MONEY].into_iter()), Ok(MAX_MONEY));
        assert_eq!(
            checked_total([MAX_MONEY, 1].into_iter()),
            Err(PlanError::TotalOutOfRange)
        );
    }

    #[test]
    fn split_by_type() {
        let p2pkh = [&[0x76, 0xa9, 0x14][..], &[1u8; 20], &[0x88, 0xac]].concat();
        let mut s = TypeSplit::default();
        s.add(&p2pkh, 500);
        s.add(&pq_script(1, 1), 70);
        s.add(&pq_script(2, 2), 9);
        assert_eq!((s.transparent, s.ecc(), s.pq_total()), (579, 500, 79));
        assert_eq!((s.scheme(1), s.scheme(2), s.scheme(9)), (70, 9, 0));
    }

    #[test]
    fn policy_lattice() {
        assert!(policy_allows(
            "AllowRevealedSenders",
            "AllowRevealedAmounts"
        ));
        assert!(!policy_allows(
            "AllowRevealedSenders",
            "AllowRevealedRecipients"
        ));
        assert!(!policy_allows(
            "AllowRevealedRecipients",
            "AllowFullyTransparent"
        ));
        assert!(policy_allows("NoPrivacy", "AllowFullyTransparent"));
    }

    /// PQ source: largest first, change to the source, the fee on the size, the policy last.
    #[test]
    fn pq_source_selection_change_and_policy() {
        let src = pq_script(2, 5);
        let ecc = [&[0x76, 0xa9, 0x14][..], &[1u8; 20], &[0x88, 0xac]].concat();
        let coins = [
            coin(30_000, 0, &src),
            coin(5_000_000, 1, &src),
            coin(70_000, 2, &src),
        ];
        let r = [PlanRecipient {
            script: Some(ecc.clone()),
            amount: 1_000_000,
        }];
        let p = plan_pq_source(
            &coins,
            &src,
            &r,
            None,
            "AllowFullyTransparent",
            100,
            10_000_000,
        )
        .unwrap();
        assert_eq!(p.selected.len(), 1);
        assert_eq!(p.selected[0].value, 5_000_000);
        assert_eq!(p.transparent_outputs[0], (ecc.clone(), 1_000_000));
        assert_eq!(p.transparent_outputs[1].0, src);
        assert_eq!(p.change + p.fee + p.send, 5_000_000);
        assert!(p.fee >= 1000);
        // AllowRevealedRecipients does not permit the transparent sender
        let e = plan_pq_source(
            &coins,
            &src,
            &r,
            None,
            "AllowRevealedRecipients",
            100,
            10_000_000,
        )
        .unwrap_err();
        assert_eq!(
            e,
            PlanError::Policy {
                policy: "AllowRevealedRecipients".into(),
                required: "AllowFullyTransparent"
            }
        );
        assert_eq!(e.rpc_code(), -4);
        // a Sapling recipient under AllowRevealedSenders: allowed for the amount, and with an
        // exact selection no change, so the sender alone is revealed
        let z = [PlanRecipient {
            script: None,
            amount: 5_000_000 - 1000,
        }];
        let p = plan_pq_source(
            &coins[1..2],
            &src,
            &z,
            None,
            "AllowRevealedSenders",
            100,
            10_000_000,
        );
        // the size fee of one Falcon input at 100 zat/kB is below the 1,000 floor... but the
        // ZIP-317 fee of a Falcon input with two Sapling outputs is above it: insufficient
        assert!(matches!(p, Err(PlanError::Insufficient { .. })), "{p:?}");
        assert_eq!(
            plan_pq_source::<()>(&[], &src, &r, None, "NoPrivacy", 100, 10_000_000),
            Err(PlanError::NoCoins)
        );
        assert_eq!(
            plan_pq_source(
                &coins,
                &src,
                &r,
                Some(20_000_000),
                "NoPrivacy",
                100,
                10_000_000
            ),
            Err(PlanError::FeeAboveCap {
                fee: 20_000_000,
                cap: 10_000_000
            })
        );
    }

    /// Dust change folds into the fee and never exceeds the cap (review L3).
    #[test]
    fn pq_source_dust_change_folds() {
        let src = pq_script(1, 5);
        let ecc = [&[0x76, 0xa9, 0x14][..], &[1u8; 20], &[0x88, 0xac]].concat();
        let r = [PlanRecipient {
            script: Some(ecc),
            amount: 1_000_000,
        }];
        // find the settled fee for one SLH coin, then give a coin 100 zat above it
        let big = [coin(9_000_000, 0, &src)];
        let p = plan_pq_source(&big, &src, &r, None, "NoPrivacy", 100, 10_000_000).unwrap();
        let exact = 1_000_000 + p.fee + 100;
        let p2 = plan_pq_source(
            &[coin(exact, 0, &src)],
            &src,
            &r,
            None,
            "NoPrivacy",
            100,
            10_000_000,
        )
        .unwrap();
        assert_eq!(p2.change, 0);
        assert_eq!(p2.fee, p.fee + 100);
        assert_eq!(p2.transparent_outputs.len(), 1);
    }
}
