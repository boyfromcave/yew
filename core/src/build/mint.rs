// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The two-step MINT (plan §4 rule 5, §5.3; v3 spec §3.5): `EstimateCollateral` →
//! `BuildBundle` → the **carrier funding transaction** (`P2SH(carrierScript(freshKey,
//! SHA256(bundle)))` of `CARRIER_VALUE`) → one confirmation → the **MINT** with `vin[last]` the
//! carrier, `vout[0..4]` per the template, `nExpiryHeight = refHeight + REF_WINDOW`; and the
//! **sweep** of a carrier whose window lapsed. The state between the steps is a `mints` row
//! (`store.rs`), advanced by `sync.rs`, so a killed app resumes.
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp` — `MintOutputs`
//! `:37-56` (the vout order: vault, token, payload, fee, attestor fee), `BundleHash` /
//! `CarrierOutput` / `SignCarrierInput` `:167-193`, `BuildCarrier` `:1024-1085`, `BuildMint`
//! `:1087-1182` (the collateral floor and rounding `:1105-1106`, `needed = outputs + fee −
//! CARRIER_VALUE` `:1136`, the carrier appended as `vin[last]` before any signature `:1172`),
//! `AttestFeeFor` `:757-770`, `BuildSweepCarriers` `:1608-1633`; the Python light-client
//! reference `qa/rpc-tests/test_framework/yellowback_attest.py` (`build_carrier_tx` `:556-575`,
//! `spend_carrier` `:578-596`, `build_mint_tx_v3` `:603-644`). What the node computes from its
//! own index (`MintGate`, `BundleAt`, `CombineMint`, `DryRunOrThrow`) the client gets from the
//! relay: `EstimateCollateral`, `BuildBundle`, `GetFeePayee`, `ListAttestors`, and the node's
//! dry run through the gate (D-W-5).
//!
//! Differences from the node, recorded: the carrier and owner keys are the next unused
//! change / external HD keys (the node draws from its keypool); the YEC side selects from the
//! wallet's classes (`FEE_RESERVE` first, then `YEC`); the attestor payee is the node's
//! `DefaultAttestPayee` pick over the block hash the relay serves (AFEE-1 accepts any `seq` of
//! the bundle); the bundle is verified locally against `ListAttestors` before the carrier is
//! funded (plan §4 rule 6) — the node verifies its own pool's bundle in `BundleAt`.

use thiserror::Error;

use crate::bundle::{self, Seated};
use crate::coins::{self, Utxo, UtxoClass};
use crate::gate::{self, Validator};
use crate::keys::{self, unhex};
use crate::net::{CompactClient, Validation, YellowbackClient};
use crate::params::{
    CARRIER_VALUE, FEE_MIN_ZAT, FEE_ZAT, REF_WINDOW, TOKEN_VALUE, TX_EXPIRING_SOON_THRESHOLD,
    TX_EXPIRY_DELTA,
};
use crate::payload::{self, Payload, FEE_VOUT_NONE};
use crate::script;
use crate::store::{AddressRow, HistoryRow, MintKind, MintRow, MintState};
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn, TxOut};
use crate::wallet::{dollars, Wallet, WalletError};

use super::terms;
use super::yec_send::MIN_CHANGE;

/// Why a mint step could not proceed (the node's identifiers where one exists).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MintError {
    /// The wallet cannot cover the collateral, the carrier and the fees from spendable YEC.
    #[error("insufficient-yec: the mint needs {need} zat of YEC (collateral {collateral}, token {token}, fees {fees}, carrier {carrier}), have {have} zat spendable")]
    Unaffordable {
        /// Everything the two transactions need.
        need: i64,
        /// The collateral.
        collateral: i64,
        /// `TOKEN_VALUE`.
        token: i64,
        /// Enforcement + attestor + two network fees.
        fees: i64,
        /// `CARRIER_VALUE`.
        carrier: i64,
        /// Spendable `YEC` + `FEE_RESERVE`.
        have: i64,
    },
    /// The row is not in the state the step needs.
    #[error("mint {id} is {state}; {step} needs {want}")]
    WrongState {
        /// The row.
        id: i64,
        /// Its state.
        state: &'static str,
        /// The step asked for.
        step: &'static str,
        /// The state it needs.
        want: &'static str,
    },
    /// `carrier-lapsed`: the window closed before the main transaction could be sent.
    #[error("carrier-lapsed: the window (refHeight {ref_height} + {REF_WINDOW}) closes at {expiry}; tip {tip}; sweep the carrier")]
    Lapsed {
        /// `R`.
        ref_height: u32,
        /// `R + REF_WINDOW`.
        expiry: u32,
        /// The tip.
        tip: u64,
    },
    /// The bundle the relay returned did not verify (plan §4 rule 6).
    #[error(transparent)]
    Bundle(#[from] bundle::BundleError),
    /// A script template could not be built.
    #[error(transparent)]
    Script(#[from] script::ScriptError),
    /// The relay's answer was not usable (a field missing or malformed).
    #[error("relay: {0}")]
    Relay(String),
    /// No such row.
    #[error("no mint with id {0}")]
    NoSuchMint(i64),
    /// The server's terms do not follow the spec's rules for this network (audit G-1, G-2):
    /// acting on them would lock the collateral in a VOID vault or overpay a fee.
    #[error("inconsistent-server: the server answered an inconsistent vault ({what}); try another server")]
    Inconsistent {
        /// Which rule failed.
        what: String,
    },
    /// The terms at `mint_start` differ from the estimate the user confirmed (audit G-2).
    #[error("terms-changed: the mint's {what} changed since the estimate you confirmed ({was} → {now}); review the new estimate")]
    TermsChanged {
        /// Which term.
        what: &'static str,
        /// As confirmed.
        was: String,
        /// As the server answers now.
        now: String,
    },
    /// `cents` outside `[MIN_MINT, MAX_MINT]` (MINT-2; audit G-9).
    #[error("bad-amount: {cents} cents is outside the mint range [{min}, {max}] cents")]
    BadAmount {
        /// The cents asked for.
        cents: u64,
        /// `MIN_MINT`.
        min: u64,
        /// `MAX_MINT`.
        max: u64,
    },
    /// Minting is not possible now (hardening H-1 unarmed, H-5 / W16 / W20 no class mintable,
    /// or the class asked for is not among `mintableClasses`): the reason as shown.
    #[error("mint-blocked: {reason}")]
    Blocked {
        /// Why.
        reason: String,
    },
    /// A server number exceeds a bound the user confirmed (hardening H-9.3: the light-client
    /// form of `maxCollateralZat` / `maxBurnCents` / `minOutZat`); nothing was signed.
    #[error("{what}: {detail}")]
    BoundExceeded {
        /// The node's identifier for the same refusal.
        what: &'static str,
        /// What, in numbers.
        detail: String,
    },
    /// `lock_blocks` inside no term class of the network.
    #[error("bad-lock: a lock of {lock_blocks} blocks is inside no term class of {}", network.chain_name())]
    BadLock {
        /// The lock asked for.
        lock_blocks: u32,
        /// The network.
        network: crate::params::Network,
    },
}

/// The terms the user confirmed on the estimate, re-checked at `mint_start` (audit G-2): the
/// server's second answer may not differ from what was shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedTerms {
    /// `collateral_zat` of the estimate.
    pub collateral_zat: i64,
    /// `fee_zat` of the estimate.
    pub fee_zat: i64,
    /// `payee` of the estimate.
    pub payee: String,
    /// `term_class` of the estimate.
    pub term_class: String,
}

/// What the Mint screen shows before anything is signed (plan §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintEstimate {
    /// The cents asked for.
    pub cents: u64,
    /// The lock in blocks.
    pub lock_blocks: u32,
    /// The term class letter.
    pub term_class: String,
    /// `R = indexTip − REF_LAG`.
    pub ref_height: u32,
    /// `R + lockBlocks`.
    pub lock_height: u32,
    /// `lockHeight + GRACE`.
    pub claim_height: u32,
    /// `requiredZat` as the node reports it.
    pub required_zat: i64,
    /// The collateral the MINT will carry: `max(required, 4·feeMin)` rounded up to 1,000 zat.
    pub collateral_zat: i64,
    /// The enforcement fee for that collateral (0 under FEE-0).
    pub fee_zat: i64,
    /// The attestor fee (0 under AFEE-0).
    pub attest_fee_zat: i64,
    /// The enforcement fee payee for `(R, ownerPubKey)` (`s…`), empty under FEE-0. Checked
    /// against FEE-1 locally; its eligibility cannot be (`docs/trust.md`).
    pub payee: String,
    /// The owner key the estimate was made for (the next unused external key); `start`
    /// takes the same key.
    pub owner_hash160: [u8; 20],
    /// `pMint` at `R`, micro-USD per YEC.
    pub p_mint: i64,
    /// `armed` at `R`.
    pub armed: bool,
    /// The `seq`s the node's bundle would carry.
    pub bundle_seqs: Vec<u16>,
    /// Everything the two transactions need from YEC.
    pub total_zat: i64,
    /// Spendable `YEC` + `FEE_RESERVE`.
    pub available_zat: i64,
}

impl MintEstimate {
    /// True when the wallet can fund both steps.
    pub fn affordable(&self) -> bool {
        self.available_zat >= self.total_zat
    }
}

/// The result of a carrier step: what the row records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierStep {
    /// The carrier funding txid.
    pub txid: [u8; 32],
    /// The carrier key hash (an own change key).
    pub carrier_hash160: [u8; 20],
    /// `R + REF_WINDOW`.
    pub expiry_height: u32,
    /// The node's validation of the funding transaction.
    pub validation: Validation,
}

/// `FeeZat(collateral, feeMin, feeBps)` and the payee for `(R, selector)`, from `GetFeePayee`:
/// `(fee_zat, payee)`; `payee` empty under FEE-0 (no eligible pool). The fee is checked against
/// FEE-1 locally (`terms::check_fee`, audit G-2); the payee's eligibility cannot be.
pub(crate) async fn fee_payee(
    network: crate::params::Network,
    yb: &mut YellowbackClient,
    ref_height: u32,
    collateral_zat: i64,
    selector: &[u8],
) -> Result<(i64, String), WalletError> {
    let p = yb
        .fee_payee(ref_height, collateral_zat, &keys::hex(selector))
        .await?;
    let payee = if !p.preferred.is_empty() {
        p.preferred
    } else if let Some(d) = p.default {
        d.payout_address
    } else {
        String::new()
    };
    let fee = terms::check_fee(network, collateral_zat, &payee, p.fee_zat)?;
    Ok((fee, payee))
}

/// The seated set for bundle verification: `seq → attestorPubKey` from `ListAttestors`.
pub async fn seated_set(yb: &mut YellowbackClient) -> Result<Seated, WalletError> {
    let mut seated = Seated::new();
    for a in yb.list_attestors(0).await? {
        if !a.seated {
            continue;
        }
        let pk = unhex(&a.attestor_pub_key)
            .ok()
            .and_then(|v| <[u8; 33]>::try_from(v.as_slice()).ok())
            .ok_or_else(|| MintError::Relay(format!("attestor {} pubkey", a.seq)))?;
        seated.insert(a.seq as u16, pk);
    }
    Ok(seated)
}

/// Verify `bundle` against the seated set and the block hashes the relay serves (plan §4
/// rule 6). Returns the `seq`s in bundle order.
pub async fn verify_bundle(
    client: &mut CompactClient,
    yb: &mut YellowbackClient,
    bundle: &[u8],
) -> Result<Vec<u16>, WalletError> {
    Ok(verify_bundle_full(client, yb, bundle)
        .await?
        .iter()
        .map(|a| a.seq)
        .collect())
}

/// [`verify_bundle`], returning the verified attestations (prices included).
pub async fn verify_bundle_full(
    client: &mut CompactClient,
    yb: &mut YellowbackClient,
    bundle: &[u8],
) -> Result<Vec<bundle::Attestation>, WalletError> {
    let seated = seated_set(yb).await?;
    let atts = bundle::decode(bundle).map_err(MintError::Bundle)?;
    let mut hashes = std::collections::HashMap::new();
    for a in &atts {
        if let std::collections::hash_map::Entry::Vacant(e) = hashes.entry(a.cited_height) {
            if let Ok(h) = client.block_hash(a.cited_height as u64).await {
                e.insert(h);
            }
        }
    }
    let verified =
        bundle::verify(bundle, &seated, |h| hashes.get(&h).copied()).map_err(MintError::Bundle)?;
    Ok(verified)
}

/// The attestor payee (`bondKeyAddress`) and fee for a bundle of `seqs` at `(R, selector)`
/// (`AttestFeeFor`): `("", 0)` under AFEE-0 (no bundle). The fee is AFEE-1 with the local
/// `ATTEST_FEE_BPS` (audit G-2), never the server's figure.
pub async fn attest_payee(
    network: crate::params::Network,
    client: &mut CompactClient,
    yb: &mut YellowbackClient,
    ref_height: u32,
    selector: &[u8],
    seqs: &[u16],
    fee_zat: i64,
) -> Result<(String, i64), WalletError> {
    if seqs.is_empty() {
        return Ok((String::new(), 0));
    }
    let hash = client.block_hash(ref_height as u64).await?;
    let seq = bundle::default_attest_payee(&hash, selector, seqs)
        .ok_or_else(|| MintError::Relay("empty bundle".into()))?;
    let addr = yb
        .list_attestors(0)
        .await?
        .into_iter()
        .find(|a| a.seq as u16 == seq)
        .map(|a| a.bond_key_address)
        .ok_or_else(|| MintError::Relay(format!("attest-unknown-seq: attestor {seq}")))?;
    Ok((addr, terms::attest_fee(network, fee_zat, seqs)))
}

/// `BuildMint:1105-1106`: `max(required, 4 · FEE_MIN)` rounded up to 1,000 zat (MINT-5, K14);
/// `FEE_MIN` is the local constant (audit G-2).
pub fn collateral_for(required_zat: i64) -> i64 {
    let mut c = required_zat.max(4 * FEE_MIN_ZAT);
    if c % 1000 != 0 {
        c += 1000 - c % 1000;
    }
    c
}

/// `mint_estimate` (plan §3.4): the numbers the Mint screen shows, from `EstimateCollateral`
/// and `GetFeePayee`, each checked against the spec's rules for the network before it is
/// shown (`terms::check_estimate`, audit G-1). Nothing is signed or reserved; the owner key
/// is the next unused external key, which `start` then takes.
pub async fn estimate(
    wallet: &Wallet,
    yb: &mut YellowbackClient,
    cents: u64,
    lock_blocks: u32,
    tip: u64,
) -> Result<MintEstimate, WalletError> {
    terms::check_cents(wallet.network, cents)?;
    terms::class_for(wallet.network, lock_blocks)?;
    // The gate first (H-1, H-5): an unarmed price or no mintable class blocks the mint before
    // any estimate is shown; the server's parameter set must be this network's (H-9.3).
    let gate = gate_now(wallet.network, yb).await?;
    if let Some(reason) = gate.blocked {
        return Err(MintError::Blocked { reason }.into());
    }
    let e = yb.estimate_collateral(cents, lock_blocks, 0).await?;
    terms::check_estimate(wallet.network, tip, cents, lock_blocks, &e)?;
    if !gate.mintable_classes.contains(&e.term_class.as_str()) {
        return Err(MintError::Blocked {
            reason: format!(
                "class {} is not mintable now; mintable: {}",
                e.term_class,
                gate.mintable_classes.join(", ")
            ),
        }
        .into());
    }
    if gate.requires_armed && !e.armed {
        return Err(MintError::Blocked {
            reason: format!(
                "the price is not armed at the reference height {}: the node would make the mint VOID (mint-halted-unarmed)",
                e.ref_height
            ),
        }
        .into());
    }
    let collateral_zat = collateral_for(e.required_zat);
    let owner_row = wallet.receive_address(false)?;
    let owner_key = wallet
        .key_for_hash(&owner_row.hash160)?
        .ok_or_else(|| WalletError::Other("owner key".into()))?;
    let (fee_zat, payee) = fee_payee(
        wallet.network,
        yb,
        e.ref_height as u32,
        collateral_zat,
        &owner_key.pubkey,
    )
    .await?;
    let bundle_seqs: Vec<u16> = e.bundle_seqs.iter().map(|s| *s as u16).collect();
    let attest_fee_zat = terms::attest_fee(wallet.network, fee_zat, &bundle_seqs);
    let total_zat =
        collateral_zat + TOKEN_VALUE + fee_zat + attest_fee_zat + CARRIER_VALUE + 2 * FEE_ZAT;
    let (avail, reserved) = coins::yec_balances(&wallet.spendable_utxos()?);
    Ok(MintEstimate {
        cents,
        lock_blocks,
        term_class: e.term_class,
        ref_height: e.ref_height as u32,
        lock_height: e.lock_height as u32,
        claim_height: e.claim_height as u32,
        required_zat: e.required_zat,
        collateral_zat,
        fee_zat,
        attest_fee_zat,
        payee,
        owner_hash160: owner_row.hash160,
        p_mint: e.p_mint,
        armed: e.armed,
        bundle_seqs,
        total_zat,
        available_zat: avail + reserved,
    })
}

/// The mint gate now: `GetYellowbackInfo` (its parameter set checked against the network's,
/// `terms::check_server_params`), `GetPrice` at the index tip and `GetStats`.
pub async fn gate_now(
    network: crate::params::Network,
    yb: &mut YellowbackClient,
) -> Result<terms::MintGate, WalletError> {
    let info = yb.info().await?;
    terms::check_server_params(network, info.params.as_ref())?;
    let price = yb.price(0).await?;
    let stats = yb.stats().await?;
    Ok(terms::mint_gate(network, &info, &price, &stats)?)
}

/// The vault upgrade's terms now (rpcversion 5, U-22, U-23): `GetYellowbackInfo`, its parameter
/// set checked against the network's (`terms::check_server_params`), its attestor set and
/// `CLAIM_DELAY` checked (`terms::vault_terms`). The attestor set is remembered in the wallet's
/// meta the first time; a server that later names another set is refused (a network's YED
/// attestor set never changes).
pub async fn vault_terms_now(
    wallet: &Wallet,
    yb: &mut YellowbackClient,
) -> Result<terms::VaultTerms, WalletError> {
    let info = yb.info().await?;
    terms::check_server_params(wallet.network, info.params.as_ref())?;
    let t = terms::vault_terms(wallet.network, &info)?;
    let hex = keys::hex(&t.attestor_set_id);
    match wallet.store.meta("attestor_set_id")? {
        Some(known) if known != hex => {
            return Err(MintError::Inconsistent {
                what: format!(
                    "the server's attestor set {} is not the one this wallet knows ({}); try another server",
                    txid_hex(&t.attestor_set_id),
                    known
                ),
            }
            .into())
        }
        Some(_) => {}
        None => wallet.store.set_meta("attestor_set_id", &hex)?,
    }
    Ok(t)
}

/// True while a two-step's main transaction can still enter the mempool: `tip + 1 +
/// TX_EXPIRING_SOON_THRESHOLD <= expiry` (`CheckExpiry`).
pub fn window_open(tip: u64, expiry_height: u32) -> bool {
    tip + 1 + TX_EXPIRING_SOON_THRESHOLD as u64 <= expiry_height as u64
}

/// The next unused change-chain key, marked used (a fresh key per carrier / change output).
fn fresh_change(wallet: &Wallet) -> Result<AddressRow, WalletError> {
    let row = wallet.change_address()?;
    wallet.store.mark_used(&row.hash160)?;
    wallet.ensure_gap()?;
    Ok(row)
}

/// The next unused external key, marked used (the vault owner / token key, the redeem
/// destination).
pub(crate) fn fresh_external(wallet: &Wallet) -> Result<AddressRow, WalletError> {
    let row = wallet.receive_address(false)?;
    wallet.store.mark_used(&row.hash160)?;
    wallet.ensure_gap()?;
    Ok(row)
}

/// The carrier step (`BuildCarrier`; `build_carrier_tx`): fund `P2SH(carrierScript(fresh key,
/// SHA256(bundle)))` of `CARRIER_VALUE` from `FEE_RESERVE` then `YEC`, change to a fresh change
/// key, `nExpiryHeight = R + REF_WINDOW`, both gate layers, broadcast, locks, pending record.
pub async fn carrier_step(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    bundle: &[u8],
    ref_height: u32,
    tip: u64,
    branch_id: u32,
) -> Result<CarrierStep, WalletError> {
    let expiry_height = ref_height + REF_WINDOW;
    if !window_open(tip, expiry_height) {
        return Err(MintError::Lapsed {
            ref_height,
            expiry: expiry_height,
            tip,
        }
        .into());
    }
    let carrier_row = fresh_change(wallet)?;
    let carrier_key = wallet
        .key_for_hash(&carrier_row.hash160)?
        .ok_or_else(|| WalletError::Other("carrier key".into()))?;
    let redeem = script::carrier_script(&carrier_key.pubkey, &bundle::bundle_hash(bundle))
        .map_err(MintError::Script)?;
    let needed = CARRIER_VALUE + FEE_ZAT;
    let spendable = wallet.spendable_utxos()?;
    let inputs = coins::select_yec(&spendable, needed, true)?;
    let selected: i64 = inputs.iter().map(|u| u.value).sum();
    let mut change = selected - needed;
    if change == TOKEN_VALUE {
        change -= 1;
    }
    if change > 0 && change < MIN_CHANGE {
        change = 0;
    }
    let mut tx = Transaction::new_v4();
    tx.expiry_height = expiry_height;
    for u in &inputs {
        tx.vin.push(TxIn::new(u.outpoint));
    }
    tx.vout.push(TxOut {
        value: CARRIER_VALUE,
        script_pubkey: script::p2sh_of(&redeem),
    });
    let mut change_row = None;
    if change > 0 {
        let row = fresh_change(wallet)?;
        tx.vout.push(TxOut {
            value: change,
            script_pubkey: script::p2pkh_script(&row.hash160),
        });
        change_row = Some(row);
    }
    sign_p2pkh_inputs(wallet, &mut tx, &inputs, 0, branch_id)?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    let (_, validation) = gate::confirm(validator, gate::Path::Carrier, &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    send(client, &raw, &txid).await?;
    record_broadcast(wallet, &txid, &raw, expiry_height, &inputs)?;
    wallet.store.upsert_history(&HistoryRow {
        txid,
        height: 0,
        yec_delta: change - selected,
        has_payload: false,
        pending: true,
        shielded: false,
        yed_delta: 0,
        kind: "carrier".into(),
        verdict: String::new(),
        label: "funding carrier".into(),
        labelled: true,
    })?;
    if let Some(row) = change_row {
        wallet
            .store
            .insert_own_output(&OutPoint { txid, n: 1 }, change, &row.hash160)?;
    }
    Ok(CarrierStep {
        txid,
        carrier_hash160: carrier_row.hash160,
        expiry_height,
        validation,
    })
}

/// `mint_start` (plan §3.4): estimate (checked), bundle (verified, and `pMint` checked against
/// its prices), carrier step, and the `mints` row in state `CarrierSent`. With `confirmed`,
/// the collateral, fee, payee and class must equal what the user confirmed on the estimate
/// (audit G-2). Returns the row id.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    cents: u64,
    lock_blocks: u32,
    confirmed: Option<&ConfirmedTerms>,
    tip: u64,
    branch_id: u32,
) -> Result<i64, WalletError> {
    let yb = validator
        .client_mut()
        .ok_or(gate::GateError::YellowbackAbsent)?;
    let est = estimate(wallet, yb, cents, lock_blocks, tip).await?;
    if let Some(c) = confirmed {
        check_confirmed(c, &est)?;
    }
    if !est.affordable() {
        return Err(MintError::Unaffordable {
            need: est.total_zat,
            collateral: est.collateral_zat,
            token: TOKEN_VALUE,
            fees: est.fee_zat + est.attest_fee_zat + 2 * FEE_ZAT,
            carrier: CARRIER_VALUE,
            have: est.available_zat,
        }
        .into());
    }
    let r = est.ref_height;
    // The vault upgrade's terms (U-23) must be usable before the carrier is funded.
    vault_terms_now(wallet, yb).await?;
    // The bundle for (R, "") — the mint's selector is empty (BuildMint:1095).
    let b = yb.build_bundle(r, "").await?;
    let bundle_bytes = unhex(&b.hex).map_err(|e| MintError::Relay(format!("bundle hex: {e}")))?;
    let verified = verify_bundle_full(client, yb, &bundle_bytes).await?;
    // The verified bundle bounds pMint (audit G-1): the node computes aMint from these prices.
    if est.armed {
        terms::check_bundle_price(est.p_mint, &verified)?;
    }
    let seqs: Vec<u16> = verified.iter().map(|a| a.seq).collect();
    // The owner key the estimate was made for (the first unused external key), now taken.
    let owner_row = fresh_external(wallet)?;
    if owner_row.hash160 != est.owner_hash160 {
        return Err(MintError::TermsChanged {
            what: "owner key",
            was: keys::hex(&est.owner_hash160),
            now: keys::hex(&owner_row.hash160),
        }
        .into());
    }
    let owner_key = wallet
        .key_for_hash(&owner_row.hash160)?
        .ok_or_else(|| WalletError::Other("owner key".into()))?;
    // The fee payee for (R, ownerPubKey) is the estimate's (BuildMint:1121).
    let (fee_zat, payee) = (est.fee_zat, est.payee.clone());
    let (attest_payee_addr, attest_fee_zat) =
        attest_payee(wallet.network, client, yb, r, &[], &seqs, fee_zat).await?;
    let step = carrier_step(wallet, client, validator, &bundle_bytes, r, tip, branch_id).await?;
    let row = MintRow {
        id: 0,
        kind: MintKind::Mint,
        state: MintState::CarrierSent,
        created_height: tip,
        cents,
        lock_blocks,
        term_class: est.term_class,
        ref_height: r,
        lock_height: est.lock_height,
        claim_height: est.claim_height,
        collateral_zat: est.collateral_zat,
        fee_zat,
        payee,
        attest_fee_zat,
        attest_payee: attest_payee_addr,
        residual_zat: 0,
        bundle: bundle_bytes,
        bundle_seqs: seqs
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(","),
        carrier_hash160: step.carrier_hash160,
        owner_hash160: owner_row.hash160,
        carrier_txid: step.txid,
        carrier_vout: 0,
        main_txid: [0; 32],
        sweep_txid: [0; 32],
        expiry_height: step.expiry_height,
        vault_txid: [0; 32],
        owner_pubkey: owner_key.pubkey.to_vec(),
        note: String::new(),
    };
    Ok(wallet.store.insert_mint(&row)?)
}

/// The estimate at `start` against the one the user confirmed (audit G-2).
fn check_confirmed(c: &ConfirmedTerms, est: &MintEstimate) -> Result<(), MintError> {
    let changed = |what, was: String, now: String| MintError::TermsChanged { what, was, now };
    if est.term_class != c.term_class {
        return Err(changed(
            "term class",
            c.term_class.clone(),
            est.term_class.clone(),
        ));
    }
    if est.collateral_zat != c.collateral_zat {
        return Err(changed(
            "collateral",
            c.collateral_zat.to_string(),
            est.collateral_zat.to_string(),
        ));
    }
    if est.fee_zat != c.fee_zat {
        return Err(changed(
            "enforcement fee",
            c.fee_zat.to_string(),
            est.fee_zat.to_string(),
        ));
    }
    if est.payee != c.payee {
        return Err(changed("fee payee", c.payee.clone(), est.payee.clone()));
    }
    Ok(())
}

/// The carrier outpoint and redeem script of a row.
pub fn carrier_of(
    wallet: &Wallet,
    m: &MintRow,
) -> Result<(OutPoint, Vec<u8>, keys::AddressKey), WalletError> {
    let key = wallet
        .key_for_hash(&m.carrier_hash160)?
        .ok_or_else(|| WalletError::Other("carrier key missing".into()))?;
    let redeem = script::carrier_script(&key.pubkey, &bundle::bundle_hash(&m.bundle))
        .map_err(MintError::Script)?;
    Ok((
        OutPoint {
            txid: m.carrier_txid,
            n: m.carrier_vout,
        },
        redeem,
        key,
    ))
}

/// `SignCarrierInput` (`txbuilder.cpp:181-193`; `spend_carrier`): ZIP-243 over the carrier
/// redeem script with `amount = CARRIER_VALUE`, `SIGHASH_ALL`, scriptSig `<bundle> <sig>
/// <carrierScript>`.
pub fn sign_carrier_input(
    tx: &mut Transaction,
    index: usize,
    key: &keys::AddressKey,
    redeem: &[u8],
    bundle: &[u8],
    branch_id: u32,
) -> Result<(), WalletError> {
    let digest = tx.sighash(
        index,
        redeem,
        CARRIER_VALUE,
        crate::params::SIGHASH_ALL,
        branch_id,
    )?;
    let sig = secp256k1::ecdsa::sign(secp256k1::Message::from_digest(digest), &key.secret);
    let mut der = sig.serialize_der().to_vec();
    der.push(crate::params::SIGHASH_ALL as u8);
    tx.vin[index].script_sig =
        script::carrier_script_sig(bundle, &der, redeem).map_err(MintError::Script)?;
    Ok(())
}

/// Sign `inputs` (P2PKH, own keys) at `vin[first..]`.
pub(crate) fn sign_p2pkh_inputs(
    wallet: &Wallet,
    tx: &mut Transaction,
    inputs: &[Utxo],
    first: usize,
    branch_id: u32,
) -> Result<(), WalletError> {
    for (i, u) in inputs.iter().enumerate() {
        let h = script::p2pkh_hash(&u.script).ok_or_else(|| {
            WalletError::Other(format!("input {} is not P2PKH", u.outpoint.display()))
        })?;
        let key = wallet.key_for_hash(&h)?.ok_or_else(|| {
            WalletError::Other(format!("no key for input {}", u.outpoint.display()))
        })?;
        tx.sign_p2pkh_input(first + i, &key.secret, &u.script, u.value, branch_id)?;
    }
    Ok(())
}

/// `SendTransaction`, checking the reply names our txid.
pub(crate) async fn send(
    client: &mut CompactClient,
    raw: &[u8],
    txid: &[u8; 32],
) -> Result<(), WalletError> {
    let reply = client.send_transaction(raw.to_vec()).await?;
    let txid_str = txid_hex(txid);
    if !reply.is_empty() && reply != txid_str {
        return Err(WalletError::Other(format!(
            "server replied {reply} for txid {txid_str}"
        )));
    }
    Ok(())
}

/// Lock the inputs until the transaction confirms or expires, and record it pending.
pub(crate) fn record_broadcast(
    wallet: &Wallet,
    txid: &[u8; 32],
    raw: &[u8],
    expiry_height: u32,
    inputs: &[Utxo],
) -> Result<(), WalletError> {
    let reason = format!("spent-by:{}", txid_hex(txid));
    for u in inputs {
        wallet
            .store
            .lock(&u.outpoint, &reason, expiry_height as u64)?;
    }
    wallet
        .store
        .insert_pending_tx(txid, raw, expiry_height as u64)?;
    Ok(())
}

/// The MINT outputs (`MintOutputs`): vault, token, payload, [fee], [attestor fee]. Since the
/// vault upgrade `vout[0]` is the bare V template of the YED vault (U-23: tag `YED\0`, the
/// attestor set as both sets, `CLAIM_DELAY`; since the in-term plan's IT-1 and D-IT-15
/// `ownerHeight = appHeight = refHeight + 1`, so the owner may redeem and a claim is judged by θ
/// from the block after the mint — the payload's `lockHeight` is the term, for the class and
/// the early-redeem fee, no longer a CLTV); the v2 P2SH vault script and the pre-plan V
/// (`ownerHeight = lockHeight`, `appHeight = lockHeight + GRACE`) are refused for new mints
/// (MINT-3, `bad-mint-vault-script`).
pub fn mint_outputs(
    wallet: &Wallet,
    m: &MintRow,
    owner_pubkey: &[u8; 33],
    vt: &terms::VaultTerms,
) -> Result<Vec<TxOut>, WalletError> {
    if m.claim_height != m.lock_height + vt.grace {
        return Err(MintError::Inconsistent {
            what: format!(
                "claimHeight {} is not lockHeight {} + GRACE {}",
                m.claim_height, m.lock_height, vt.grace
            ),
        }
        .into());
    }
    let vault = vt.mint_vault_script(owner_pubkey, m.ref_height)?;
    let fee_vout = if m.payee.is_empty() { FEE_VOUT_NONE } else { 3 };
    let attest_fee_vout = if m.attest_payee.is_empty() {
        FEE_VOUT_NONE
    } else if m.payee.is_empty() {
        3
    } else {
        4
    };
    let term_class = match m.term_class.as_str() {
        "A" => 0,
        "B" => 1,
        "C" => 2,
        other => return Err(MintError::Relay(format!("term class {other}")).into()),
    };
    let payload_bytes = payload::encode(&Payload::Mint {
        term_class,
        cents: m.cents as u32,
        lock_height: m.lock_height,
        ref_height: m.ref_height,
        owner_key: *owner_pubkey,
        fee_vout,
        attest_fee_vout,
    })
    .ok_or_else(|| WalletError::Other("cannot encode the mint payload".into()))?;
    let mut vout = vec![
        TxOut {
            value: m.collateral_zat,
            script_pubkey: vault,
        },
        TxOut {
            value: TOKEN_VALUE,
            script_pubkey: script::p2pkh_script(&m.owner_hash160),
        },
        TxOut {
            value: 0,
            script_pubkey: payload::payload_script(&payload_bytes),
        },
    ];
    if !m.payee.is_empty() {
        vout.push(TxOut {
            value: m.fee_zat,
            script_pubkey: p2pkh_of_address(wallet, &m.payee)?,
        });
    }
    if !m.attest_payee.is_empty() {
        vout.push(TxOut {
            value: m.attest_fee_zat,
            script_pubkey: p2pkh_of_address(wallet, &m.attest_payee)?,
        });
    }
    Ok(vout)
}

/// The P2PKH script of an `s…` / `ye…` address.
pub(crate) fn p2pkh_of_address(wallet: &Wallet, address: &str) -> Result<Vec<u8>, WalletError> {
    match keys::parse_address(wallet.network, address)?.kind {
        keys::AddressKind::P2pkh(h) => Ok(script::p2pkh_script(&h)),
        keys::AddressKind::P2sh(h) => Ok(script::p2sh_script(&h)),
    }
}

/// What `finish` broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finished {
    /// The main transaction's txid (display form).
    pub txid: String,
    /// The node's validation.
    pub validation: Validation,
    /// The raw bytes.
    pub raw: Vec<u8>,
}

/// `mint_finish` (plan §3.4): the MINT over a confirmed carrier (`BuildMint`), or the CLAIM
/// for a row of kind `Claim` (`build::claim::assemble`). Both gate layers, then broadcast,
/// `PreLock`, locks, the row to `MainSent`.
pub async fn finish(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    id: i64,
    tip: u64,
    branch_id: u32,
) -> Result<Finished, WalletError> {
    let m = wallet.store.mint(id)?.ok_or(MintError::NoSuchMint(id))?;
    if m.state != MintState::CarrierConfirmed {
        return Err(MintError::WrongState {
            id,
            state: m.state.as_str(),
            step: "finish",
            want: MintState::CarrierConfirmed.as_str(),
        }
        .into());
    }
    if !window_open(tip, m.expiry_height) {
        wallet.store.set_mint_state(
            id,
            MintState::Lapsed,
            None,
            None,
            "window closed before the main transaction",
        )?;
        return Err(MintError::Lapsed {
            ref_height: m.ref_height,
            expiry: m.expiry_height,
            tip,
        }
        .into());
    }
    if m.kind == MintKind::Claim {
        return super::claim::finish(wallet, client, validator, &m, branch_id).await;
    }
    let owner_key = wallet
        .key_for_hash(&m.owner_hash160)?
        .ok_or_else(|| WalletError::Other("owner key missing".into()))?;
    let (carrier_op, redeem, carrier_key) = carrier_of(wallet, &m)?;
    let vt = {
        let yb = validator
            .client_mut()
            .ok_or(gate::GateError::YellowbackAbsent)?;
        vault_terms_now(wallet, yb).await?
    };
    let mut tx = Transaction::new_v4();
    tx.expiry_height = m.expiry_height;
    tx.vout = mint_outputs(wallet, &m, &owner_key.pubkey, &vt)?;
    let outputs: i64 = tx.vout.iter().map(|o| o.value).sum();
    // needed = outputs + fee − CARRIER_VALUE: the carrier input pays CARRIER_VALUE (:1136).
    let needed = outputs + FEE_ZAT - CARRIER_VALUE;
    let spendable = wallet.spendable_utxos()?;
    let inputs = coins::select_yec(&spendable, needed, true)?;
    let selected: i64 = inputs.iter().map(|u| u.value).sum();
    let mut change = selected - needed;
    if change == TOKEN_VALUE {
        change -= 1; // the zat goes to the fee (plan §3.7 "Change")
    }
    if change > 0 && change < MIN_CHANGE {
        change = 0;
    }
    let mut change_row = None;
    if change > 0 {
        let row = fresh_change(wallet)?;
        tx.vout.push(TxOut {
            value: change,
            script_pubkey: script::p2pkh_script(&row.hash160),
        });
        change_row = Some(row);
    }
    for u in &inputs {
        tx.vin.push(TxIn::new(u.outpoint));
    }
    // vin[last]: the carrier, appended before any signature (ZIP-243 commits to every prevout).
    tx.vin.push(TxIn::new(carrier_op));
    let carrier_vin = tx.vin.len() - 1;
    sign_p2pkh_inputs(wallet, &mut tx, &inputs, 0, branch_id)?;
    sign_carrier_input(
        &mut tx,
        carrier_vin,
        &carrier_key,
        &redeem,
        &m.bundle,
        branch_id,
    )?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    let (_, validation) = gate::confirm(validator, gate::Path::Mint, &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    send(client, &raw, &txid).await?;
    let mut locked = inputs.clone();
    locked.push(Utxo {
        outpoint: carrier_op,
        address: String::new(),
        script: script::p2sh_of(&redeem),
        value: CARRIER_VALUE,
        height: 0,
        class: UtxoClass::Carrier,
        cents: 0,
    });
    record_broadcast(wallet, &txid, &raw, m.expiry_height, &locked)?;
    // PreLock: vout[1] is the minted cents, pending until the server lists it.
    wallet.store.upsert_utxo(&Utxo {
        outpoint: OutPoint { txid, n: 1 },
        address: keys::encode_p2pkh(wallet.network, &m.owner_hash160),
        script: script::p2pkh_script(&m.owner_hash160),
        value: TOKEN_VALUE,
        height: 0,
        class: UtxoClass::PendingToken,
        cents: m.cents,
    })?;
    wallet
        .store
        .insert_own_output(&OutPoint { txid, n: 1 }, TOKEN_VALUE, &m.owner_hash160)?;
    if let Some(row) = change_row {
        let n = (tx.vout.len() - 1) as u32;
        wallet
            .store
            .insert_own_output(&OutPoint { txid, n }, change, &row.hash160)?;
    }
    wallet.store.upsert_history(&HistoryRow {
        txid,
        height: 0,
        yec_delta: change + TOKEN_VALUE - selected - CARRIER_VALUE,
        has_payload: true,
        pending: true,
        shielded: false,
        yed_delta: m.cents as i64,
        kind: "mint".into(),
        verdict: String::new(),
        label: format!("minting {}", dollars(m.cents as i64)),
        labelled: false,
    })?;
    wallet
        .store
        .set_mint_state(id, MintState::MainSent, Some(&txid), None, "")?;
    Ok(Finished {
        txid: txid_hex(&txid),
        validation,
        raw,
    })
}

/// `mint_sweep` (plan §4 rule 5, `BuildSweepCarriers`): spend the lapsed row's carrier to a
/// fresh change key, `CARRIER_VALUE − FEE_ZAT`, `nExpiryHeight = tip + TX_EXPIRY_DELTA`.
pub async fn sweep(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    id: i64,
    tip: u64,
    branch_id: u32,
) -> Result<Finished, WalletError> {
    let m = wallet.store.mint(id)?.ok_or(MintError::NoSuchMint(id))?;
    let sweepable = m.state == MintState::Lapsed
        || (m.state == MintState::CarrierConfirmed && !window_open(tip, m.expiry_height));
    if !sweepable {
        return Err(MintError::WrongState {
            id,
            state: m.state.as_str(),
            step: "sweep",
            want: MintState::Lapsed.as_str(),
        }
        .into());
    }
    let (carrier_op, redeem, carrier_key) = carrier_of(wallet, &m)?;
    let value = CARRIER_VALUE - FEE_ZAT;
    let dest = fresh_change(wallet)?;
    let mut tx = Transaction::new_v4();
    tx.expiry_height = (tip as u32).saturating_add(TX_EXPIRY_DELTA);
    tx.vin.push(TxIn::new(carrier_op));
    tx.vout.push(TxOut {
        value,
        script_pubkey: script::p2pkh_script(&dest.hash160),
    });
    sign_carrier_input(&mut tx, 0, &carrier_key, &redeem, &m.bundle, branch_id)?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    let (_, validation) = gate::confirm(validator, gate::Path::Sweep, &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    send(client, &raw, &txid).await?;
    let carrier = Utxo {
        outpoint: carrier_op,
        address: String::new(),
        script: script::p2sh_of(&redeem),
        value: CARRIER_VALUE,
        height: 0,
        class: UtxoClass::Carrier,
        cents: 0,
    };
    record_broadcast(
        wallet,
        &txid,
        &raw,
        tx.expiry_height,
        std::slice::from_ref(&carrier),
    )?;
    wallet
        .store
        .insert_own_output(&OutPoint { txid, n: 0 }, value, &dest.hash160)?;
    wallet.store.upsert_history(&HistoryRow {
        txid,
        height: 0,
        yec_delta: value - CARRIER_VALUE,
        has_payload: false,
        pending: true,
        shielded: false,
        yed_delta: 0,
        kind: "sweep".into(),
        verdict: String::new(),
        label: "sweeping lapsed carrier".into(),
        labelled: true,
    })?;
    wallet
        .store
        .set_mint_state(id, MintState::SweepSent, None, Some(&txid), "")?;
    Ok(Finished {
        txid: txid_hex(&txid),
        validation,
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collateral_floor_and_rounding() {
        assert_eq!(collateral_for(1_000_000_000), 1_000_000_000);
        assert_eq!(collateral_for(1_000_000_001), 1_000_001_000);
        assert_eq!(collateral_for(1), 200_000_000);
        assert!(window_open(480, 520));
        assert!(window_open(516, 520));
        assert!(!window_open(517, 520));
    }

    /// The second answer at `mint_start` may not differ from the confirmed estimate (audit G-2).
    #[test]
    fn changed_terms_are_refused() {
        let est = MintEstimate {
            cents: 10_000,
            lock_blocks: 48,
            term_class: "A".into(),
            ref_height: 480,
            lock_height: 528,
            claim_height: 552,
            required_zat: 96_153_846_154,
            collateral_zat: 96_153_847_000,
            fee_zat: 240_384_617,
            attest_fee_zat: 60_096_154,
            payee: "s1pool".into(),
            owner_hash160: [1; 20],
            p_mint: 520_000,
            armed: true,
            bundle_seqs: vec![0, 1],
            total_zat: 0,
            available_zat: 0,
        };
        let confirmed = ConfirmedTerms {
            collateral_zat: est.collateral_zat,
            fee_zat: est.fee_zat,
            payee: est.payee.clone(),
            term_class: est.term_class.clone(),
        };
        assert!(check_confirmed(&confirmed, &est).is_ok());
        for bent in [
            ConfirmedTerms {
                fee_zat: est.fee_zat - 1,
                ..confirmed.clone()
            },
            ConfirmedTerms {
                payee: "s1other".into(),
                ..confirmed.clone()
            },
            ConfirmedTerms {
                collateral_zat: est.collateral_zat + 1_000,
                ..confirmed.clone()
            },
            ConfirmedTerms {
                term_class: "B".into(),
                ..confirmed.clone()
            },
        ] {
            assert!(matches!(
                check_confirmed(&bent, &est),
                Err(MintError::TermsChanged { .. })
            ));
        }
    }
}
