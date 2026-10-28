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
//! **Post-quantum owner (quantum spec §3.6, C-1).** The vault owner is an SLH-DSA key and the
//! MINT payload is version 4 (`ownerScheme ‖ ownerHash`); the token (`vout[1]`) goes to the
//! fresh external P2PKH key — the holder is no longer the owner (an SLH-DSA holder would cost an
//! 8 KB scriptSig per transfer). The owner is the PQ key paired with that external key's index
//! ([`crate::wallet::Wallet::pq_owner_key`]), and FEE-W's selector is the payload's 33 owner
//! bytes, as the node's `BuildMint` (ycash-dd `q/yed` `txbuilder.cpp:1300-1304`). From
//! `pqFalconHeight` (`TOK-PQ`; mainnet and testnet from the vault upgrade's first block) the
//! token goes to the Falcon holder paired with that same external key
//! ([`crate::wallet::Wallet::yed_holder_script`]): a `TX_PQPKH` scheme 2, judged for the block
//! after `refHeight` (the earliest the MINT can confirm).
//!
//! Differences from the node, recorded: the carrier and holder keys are the next unused
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
use crate::net::{CompactClient, NetError, Validation, YellowbackClient};
use crate::params::{
    CARRIER_VALUE, FEE_ZAT, REF_WINDOW, TOKEN_VALUE, TX_EXPIRING_SOON_THRESHOLD, TX_EXPIRY_DELTA,
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
    /// The collateral the MINT will carry: `requiredZat` rounded up to 1,000 zat (MINT-5′,
    /// rpcversion 8: the `4 · FEE_MIN` floor is gone).
    pub collateral_zat: i64,
    /// The protocol fee (FEE-1′, rpcversion 8): the debt's dollars in bands at `p_mint`, in zat
    /// (0 under FEE-0).
    pub fee_zat: i64,
    /// The protocol fee in cents (`ProtocolFeeCents`; shown even under FEE-0, where it is not paid).
    pub protocol_fee_cents: i64,
    /// The network fees of the two transactions: the carrier's flat fee and the MINT's
    /// Yellowback size fee at one funding input (dollars per KB at the attested price).
    pub network_fee_zat: i64,
    /// The attestor fee (0 under AFEE-0).
    pub attest_fee_zat: i64,
    /// The protocol fee payee for `(R, owner)` (`s…`), empty under FEE-0. The fee is FEE-1′
    /// computed locally; the payee's eligibility cannot be checked (`docs/trust.md`).
    pub payee: String,
    /// The holder key the estimate was made for (the next unused external key; the vault owner
    /// is the PQ key paired with it); `start` takes the same key.
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

/// The protocol fee's payee for `(R, selector)`, from `GetFeePayee` (rpcversion 8: the RPC quotes no
/// fee; FEE-1′ is computed locally from the debt and the price, [`terms::protocol_fee`]); empty under
/// FEE-0 (no eligible pool). The payee's eligibility cannot be checked locally (`docs/trust.md`).
pub(crate) async fn fee_payee(
    yb: &mut YellowbackClient,
    ref_height: u32,
    selector: &[u8],
) -> Result<String, WalletError> {
    let p = yb.fee_payee(ref_height, &keys::hex(selector)).await?;
    Ok(if !p.preferred.is_empty() {
        p.preferred
    } else if let Some(d) = p.default {
        d.payout_address
    } else {
        String::new()
    })
}

/// The network fee of a MINT funded by `funding_inputs` P2PKH coins (`BuildMint`: `YedNetworkFee`
/// raised by `PQFeeFollower` as coins are selected — every selected input counts 150 bytes on the
/// 1,000-byte base, a post-quantum one its spend size; the carrier is not counted).
pub fn mint_network_fee(wallet: &Wallet, funding: &[Utxo]) -> i64 {
    let pq: Vec<u8> = funding
        .iter()
        .filter_map(|u| crate::pq::pqpkh_of(&u.script).map(|id| id.scheme))
        .collect();
    let other = funding.len() - pq.len();
    wallet.pq_terms().yed_network_fee(other, &pq)
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

/// `BuildMint`: the requirement rounded up to 1,000 zat (MINT-5′, rpcversion 8: the `4 · FEE_MIN`
/// floor of MINT-5 is gone, `requiredZatFloored = requiredZat`).
pub fn collateral_for(required_zat: i64) -> i64 {
    let mut c = required_zat;
    if c % 1000 != 0 {
        c += 1000 - c % 1000;
    }
    c
}

/// `mint_estimate` (plan §3.4): the numbers the Mint screen shows, from `EstimateCollateral`
/// and `GetFeePayee`, each checked against the spec's rules for the network before it is
/// shown (`terms::check_estimate`, audit G-1); the protocol fee is FEE-1′ of `cents` at the
/// estimate's `pMint`, computed here (rpcversion 8). Nothing is signed or reserved; the owner key
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
    let (_, owner) = wallet
        .pq_owner_for_hash(&owner_row.hash160)?
        .ok_or_else(|| WalletError::Other("owner key".into()))?;
    let payee = fee_payee(yb, e.ref_height as u32, &owner.to_bytes()).await?;
    let fee_zat = terms::protocol_fee(cents, e.p_mint, &payee)?;
    let bundle_seqs: Vec<u16> = e.bundle_seqs.iter().map(|s| *s as u16).collect();
    let attest_fee_zat = terms::attest_fee(wallet.network, fee_zat, &bundle_seqs);
    // The carrier pays the flat fee (`BuildCarrier`); the MINT the Yellowback size fee, here at one
    // P2PKH funding input (more inputs raise it at `finish`, from the reserve).
    let network_fee_zat = wallet.pq_terms().flat_zat
        + wallet
            .pq_terms()
            .yed_fee(crate::params::yed_estimated_size(1, &[]));
    let total_zat =
        collateral_zat + TOKEN_VALUE + fee_zat + attest_fee_zat + CARRIER_VALUE + network_fee_zat;
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
        protocol_fee_cents: crate::params::protocol_fee_cents(cents),
        network_fee_zat,
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
    wallet.note_server_params(info.params.as_ref())?;
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
///
/// `persist_row` records the caller's `mints` row for the step and returns its id; it runs
/// before `SendTransaction` (DigiByte v9.26.7 38895edb's order), so the bundle the carrier's
/// script commits to is on disk before the carrier can reach the chain. A refused send deletes
/// the row again ([`send_recorded`]).
#[allow(clippy::too_many_arguments)]
pub async fn carrier_step<R>(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    bundle: &[u8],
    ref_height: u32,
    tip: u64,
    branch_id: u32,
    persist_row: R,
) -> Result<(CarrierStep, i64), WalletError>
where
    R: FnOnce(&CarrierStep) -> Result<i64, WalletError>,
{
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
    // `BuildCarrier`: the flat Yellowback fee (`g_yellowbackFee`, `fees.network.flatZat`)
    let needed = CARRIER_VALUE + wallet.pq_terms().flat_zat;
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
    let step = CarrierStep {
        txid,
        carrier_hash160: carrier_row.hash160,
        expiry_height,
        validation,
    };
    let row_id = std::cell::Cell::new(None);
    send_recorded(
        wallet,
        &txid,
        &raw,
        expiry_height,
        &inputs,
        || {
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
            if let Some(row) = &change_row {
                wallet
                    .store
                    .insert_own_output(&OutPoint { txid, n: 1 }, change, &row.hash160)?;
            }
            row_id.set(Some(persist_row(&step)?));
            Ok(())
        },
        || match row_id.get() {
            Some(id) => Ok(wallet.store.delete_mint(id)?),
            None => Ok(()),
        },
        send(client, &raw, &txid),
    )
    .await?;
    let id = row_id
        .get()
        .ok_or_else(|| WalletError::Other("carrier row not recorded".into()))?;
    Ok((step, id))
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
            fees: est.fee_zat + est.attest_fee_zat + est.network_fee_zat,
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
    let (_, owner) = wallet
        .pq_owner_for_hash(&owner_row.hash160)?
        .ok_or_else(|| WalletError::Other("owner key".into()))?;
    // The fee payee for (R, owner bytes) is the estimate's (BuildMint:1121).
    let (fee_zat, payee) = (est.fee_zat, est.payee.clone());
    let (attest_payee_addr, attest_fee_zat) =
        attest_payee(wallet.network, client, yb, r, &[], &seqs, fee_zat).await?;
    let persist_row = |step: &CarrierStep| -> Result<i64, WalletError> {
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
            bundle: bundle_bytes.clone(),
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
            owner: Some(owner),
            note: String::new(),
        };
        Ok(wallet.store.insert_mint(&row)?)
    };
    let (_, id) = carrier_step(
        wallet,
        client,
        validator,
        &bundle_bytes,
        r,
        tip,
        branch_id,
        persist_row,
    )
    .await?;
    Ok(id)
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
            "protocol fee",
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

/// Sign `inputs` (own keys) at `vin[first..]`: a P2PKH input with its secp256k1 key, a Falcon
/// `TX_PQPKH` YED holder input (TOK-PQ) with its Falcon key and the chunked scriptSig
/// (`<sig_1> <sig_2> OP_2 <pk_1> <pk_2> OP_2`, 1,577 bytes).
pub(crate) fn sign_p2pkh_inputs(
    wallet: &Wallet,
    tx: &mut Transaction,
    inputs: &[Utxo],
    first: usize,
    branch_id: u32,
) -> Result<(), WalletError> {
    for (i, u) in inputs.iter().enumerate() {
        if let Some(id) = crate::pq::pqpkh_of(&u.script) {
            let key = wallet.falcon_key_for_id(&id)?.ok_or_else(|| {
                WalletError::Other(format!(
                    "no post-quantum key for input {}",
                    u.outpoint.display()
                ))
            })?;
            tx.sign_pqpkh_input(first + i, &key, &u.script, u.value, branch_id)?;
            continue;
        }
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

/// Whether a failed `SendTransaction` certainly put nothing on the network: the server refused
/// the transaction (`SendRejected`, the node's verdict), the connection never carried the
/// request (`Transport`), or the server refused the call itself (a gRPC status such as a rate
/// limit or a malformed request). A timeout, a cancel, an unavailable or internal status, or a
/// reply naming another txid may follow a broadcast that reached the node: what was recorded
/// then stays, and the sync settles it (the transaction confirms, or its expiry releases it).
pub(crate) fn send_refused(e: &WalletError) -> bool {
    use tonic::Code;
    match e {
        WalletError::Net(NetError::SendRejected { .. })
        | WalletError::Net(NetError::Transport(_)) => true,
        WalletError::Net(NetError::Status(s)) => matches!(
            s.code(),
            Code::InvalidArgument
                | Code::FailedPrecondition
                | Code::ResourceExhausted
                | Code::PermissionDenied
                | Code::Unauthenticated
                | Code::Unimplemented
                | Code::OutOfRange
                | Code::NotFound
        ),
        _ => false,
    }
}

/// Record, then send (cf. DigiByte v9.26.7 38895edb: the mint is written before it is
/// broadcast, and a failed write sends nothing). Locks the inputs and records the transaction
/// pending ([`record_broadcast`]), runs `persist` (the builder's own rows: history, own outputs,
/// pre-locked change, the `mints` row or its step), and only then awaits `send` — the
/// `SendTransaction` future, which does nothing until it is polled. An app killed at any point
/// therefore leaves either nothing sent or a complete record the sync settles (the transaction
/// confirms; or its expiry releases the locks and fails or lapses the row): never a carrier on
/// the chain whose bundle the wallet lost, nor inputs the next send could pick again.
///
/// A write that fails, or a send the server certainly refused ([`send_refused`]), is undone: the
/// inputs' locks are put back as they were, [`crate::store::Store::forget_tx`] drops the
/// transaction's rows, and `undo` reverses the builder's change to its `mints` row. The error is
/// returned either way.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_recorded<P, U, S>(
    wallet: &Wallet,
    txid: &[u8; 32],
    raw: &[u8],
    expiry_height: u32,
    inputs: &[Utxo],
    persist: P,
    undo: U,
    send: S,
) -> Result<(), WalletError>
where
    P: FnOnce() -> Result<(), WalletError>,
    U: FnOnce() -> Result<(), WalletError>,
    S: std::future::Future<Output = Result<(), WalletError>>,
{
    let ops: std::collections::HashSet<OutPoint> = inputs.iter().map(|u| u.outpoint).collect();
    let before: Vec<crate::store::LockRow> = wallet
        .store
        .locks()?
        .into_iter()
        .filter(|l| ops.contains(&l.outpoint))
        .collect();
    let rollback = |undo: U, cause: WalletError| -> WalletError {
        let undone = (|| -> Result<(), WalletError> {
            for u in inputs {
                wallet.store.unlock(&u.outpoint)?;
            }
            for l in &before {
                wallet.store.lock(&l.outpoint, &l.reason, l.expiry_height)?;
            }
            wallet.store.forget_tx(txid)?;
            undo()
        })();
        match undone {
            Ok(()) => cause,
            Err(e) => WalletError::Other(format!(
                "{cause}; undoing the record of {} also failed: {e}",
                txid_hex(txid)
            )),
        }
    };
    if let Err(e) =
        record_broadcast(wallet, txid, raw, expiry_height, inputs).and_then(|()| persist())
    {
        return Err(rollback(undo, e));
    }
    match send.await {
        Ok(()) => Ok(()),
        Err(e) if send_refused(&e) => Err(rollback(undo, e)),
        Err(e) => Err(e),
    }
}

/// Put a two-step row's step back as `m` had it (the undo of a `set_mint_state` whose broadcast
/// was refused).
pub(crate) fn restore_step(wallet: &Wallet, m: &MintRow) -> Result<(), WalletError> {
    wallet
        .store
        .restore_mint_step(m.id, m.state, &m.main_txid, &m.sweep_txid, &m.note)?;
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
/// The MINT token's holder (`vout[1]`): the fresh external key of the row (`owner_hash160`), as
/// a P2PKH before the Falcon height and as its paired Falcon `TX_PQPKH` from it (TOK-PQ, judged at
/// `refHeight + 1`).
pub fn mint_token_script(wallet: &Wallet, m: &MintRow) -> Result<Vec<u8>, WalletError> {
    let falcon = wallet.pq_terms().falcon_at(m.ref_height as u64 + 1);
    if !falcon {
        return Ok(script::p2pkh_script(&m.owner_hash160));
    }
    let row = wallet
        .addresses()?
        .into_iter()
        .find(|r| r.hash160 == m.owner_hash160)
        .ok_or_else(|| WalletError::Other("the mint's holder key is not in this wallet".into()))?;
    wallet.yed_holder_script(&row, true)
}

pub fn mint_outputs(
    wallet: &Wallet,
    m: &MintRow,
    owner: &crate::pq::PqKeyId,
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
    let vault = vt.mint_vault_script(owner, m.ref_height)?;
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
        owner: *owner,
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
            script_pubkey: mint_token_script(wallet, m)?,
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

/// The P2PKH script of an `s…` / `yb…` address.
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
    let owner = m
        .owner
        .filter(|o| {
            wallet
                .pq_owner_for_hash(&m.owner_hash160)
                .ok()
                .flatten()
                .map(|x| x.1)
                == Some(*o)
        })
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
    tx.vout = mint_outputs(wallet, &m, &owner, &vt)?;
    let outputs: i64 = tx.vout.iter().map(|o| o.value).sum();
    // needed = outputs + fee − CARRIER_VALUE: the carrier input pays CARRIER_VALUE (:1136). The fee
    // is the Yellowback size fee (rpcversion 8), raised as the selection grows (`PQFeeFollower`).
    let spendable = wallet.spendable_utxos()?;
    let mut fee = mint_network_fee(wallet, &[]);
    let inputs = loop {
        let sel = coins::select_yec(&spendable, outputs + fee - CARRIER_VALUE, true)?;
        let next = mint_network_fee(wallet, &sel);
        if next <= fee {
            break sel;
        }
        fee = next;
    };
    let needed = outputs + fee - CARRIER_VALUE;
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
    // PreLock: vout[1] is the minted cents, pending until the server lists it.
    let token_script = mint_token_script(wallet, &m)?;
    let change_n = (tx.vout.len() - 1) as u32;
    send_recorded(
        wallet,
        &txid,
        &raw,
        m.expiry_height,
        &locked,
        || {
            wallet.store.upsert_utxo(&Utxo {
                outpoint: OutPoint { txid, n: 1 },
                address: super::yed_transfer::holder_address(wallet.network, &token_script),
                script: token_script.clone(),
                value: TOKEN_VALUE,
                height: 0,
                class: UtxoClass::PendingToken,
                cents: m.cents,
            })?;
            wallet.store.insert_own_output(
                &OutPoint { txid, n: 1 },
                TOKEN_VALUE,
                &m.owner_hash160,
            )?;
            if let Some(row) = &change_row {
                wallet.store.insert_own_output(
                    &OutPoint { txid, n: change_n },
                    change,
                    &row.hash160,
                )?;
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
            Ok(())
        },
        || restore_step(wallet, &m),
        send(client, &raw, &txid),
    )
    .await?;
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
    let carrier = Utxo {
        outpoint: carrier_op,
        address: String::new(),
        script: script::p2sh_of(&redeem),
        value: CARRIER_VALUE,
        height: 0,
        class: UtxoClass::Carrier,
        cents: 0,
    };
    send_recorded(
        wallet,
        &txid,
        &raw,
        tx.expiry_height,
        std::slice::from_ref(&carrier),
        || {
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
            Ok(())
        },
        || restore_step(wallet, &m),
        send(client, &raw, &txid),
    )
    .await?;
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
        assert_eq!(collateral_for(1), 1_000); // MINT-5′: no 4 · FEE_MIN floor (rpcversion 8)
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
            fee_zat: 192_307_693, // FEE-1′: $1.00 (the floor of a $100 debt) at $0.52
            protocol_fee_cents: 100,
            network_fee_zat: 2_000,
            attest_fee_zat: 48_076_923,
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

    // ---- Y1: record before SendTransaction, undo on a certain refusal (DigiByte 38895edb)

    mod record_then_send {
        use super::super::*;
        use crate::params::Network;
        use crate::store::Store;
        use std::cell::Cell;

        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const TXID: [u8; 32] = [0x7a; 32];

        fn wallet() -> Wallet {
            let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
            Wallet::from_parts(
                Store::open_in_memory().unwrap(),
                Network::Regtest,
                &seed,
                None,
            )
            .unwrap()
        }

        fn utxo(n: u32, class: UtxoClass) -> Utxo {
            Utxo {
                outpoint: OutPoint {
                    txid: [0x11; 32],
                    n,
                },
                address: String::new(),
                script: Vec::new(),
                value: 1_000_000,
                height: 100,
                class,
                cents: 0,
            }
        }

        fn row() -> MintRow {
            MintRow {
                id: 0,
                kind: MintKind::Mint,
                state: MintState::CarrierSent,
                created_height: 480,
                cents: 10_000,
                lock_blocks: 48,
                term_class: "A".into(),
                ref_height: 478,
                lock_height: 526,
                claim_height: 550,
                collateral_zat: 1_000_000_000,
                fee_zat: 50_000_000,
                payee: "smX".into(),
                attest_fee_zat: 12_500_000,
                attest_payee: "smY".into(),
                residual_zat: 0,
                bundle: vec![0x59, 0x41, 1, 0],
                bundle_seqs: "0,1".into(),
                carrier_hash160: [1; 20],
                owner_hash160: [2; 20],
                carrier_txid: TXID,
                carrier_vout: 0,
                main_txid: [0; 32],
                sweep_txid: [0; 32],
                expiry_height: 518,
                vault_txid: [0; 32],
                owner: None,
                note: String::new(),
            }
        }

        fn history() -> HistoryRow {
            HistoryRow {
                txid: TXID,
                height: 0,
                yec_delta: -10_000,
                has_payload: false,
                pending: true,
                shielded: false,
                yed_delta: 0,
                kind: "carrier".into(),
                verdict: String::new(),
                label: "funding carrier".into(),
                labelled: true,
            }
        }

        /// The carrier step's shape: inputs (one already locked for another reason), the history
        /// row, an own change output and the `mints` row (with its bundle) persisted first.
        fn setup() -> (Wallet, Vec<Utxo>) {
            let mut w = wallet();
            let inputs = vec![utxo(0, UtxoClass::Yec), utxo(1, UtxoClass::Carrier)];
            w.store.replace_utxos(&inputs).unwrap();
            w.store.lock(&inputs[1].outpoint, "carrier:9", 0).unwrap();
            (w, inputs)
        }

        fn persist<'a>(
            w: &'a Wallet,
            id: &'a Cell<Option<i64>>,
        ) -> impl FnOnce() -> Result<(), WalletError> + 'a {
            move || {
                w.store.upsert_history(&history())?;
                w.store
                    .insert_own_output(&OutPoint { txid: TXID, n: 1 }, 5_000, &[3; 20])?;
                id.set(Some(w.store.insert_mint(&row())?));
                Ok(())
            }
        }

        fn undo<'a>(
            w: &'a Wallet,
            id: &'a Cell<Option<i64>>,
        ) -> impl FnOnce() -> Result<(), WalletError> + 'a {
            move || match id.get() {
                Some(id) => Ok(w.store.delete_mint(id)?),
                None => Ok(()),
            }
        }

        fn spent_by(w: &Wallet) -> usize {
            let reason = format!("spent-by:{}", txid_hex(&TXID));
            w.store
                .locks()
                .unwrap()
                .iter()
                .filter(|l| l.reason == reason)
                .count()
        }

        fn recorded(w: &Wallet) -> bool {
            let pending = w
                .store
                .pending_txs()
                .unwrap()
                .iter()
                .any(|(t, _, _)| *t == TXID);
            let history = w.store.history_row(&TXID).unwrap().is_some();
            let mint = w
                .store
                .mints()
                .unwrap()
                .iter()
                .any(|m| m.bundle == row().bundle);
            let own = !w.store.own_outputs_of(&TXID).unwrap().is_empty();
            assert_eq!(pending, history, "partial record");
            assert_eq!(pending, mint, "partial record");
            assert_eq!(pending, own, "partial record");
            assert_eq!(spent_by(w), if pending { 2 } else { 0 }, "locks");
            pending
        }

        /// Everything is on disk before the send future is first polled: a kill during the send
        /// leaves a record the sync settles, never a carrier without its bundle.
        #[tokio::test]
        async fn the_record_precedes_the_send() {
            let (w, inputs) = setup();
            let id = Cell::new(None);
            let polled = Cell::new(false);
            send_recorded(
                &w,
                &TXID,
                &[4, 0, 0, 0x80],
                518,
                &inputs,
                persist(&w, &id),
                undo(&w, &id),
                async {
                    polled.set(true);
                    assert!(recorded(&w), "nothing recorded when the send began");
                    Ok(())
                },
            )
            .await
            .unwrap();
            assert!(polled.get() && recorded(&w));
            assert!(
                w.spendable_utxos().unwrap().is_empty(),
                "the inputs stay locked"
            );
        }

        /// The app killed while the send is in flight (the future dropped unfinished): the
        /// record stays, the inputs stay locked.
        #[tokio::test]
        async fn a_kill_during_the_send_keeps_the_record() {
            let (w, inputs) = setup();
            let id = Cell::new(None);
            let killed = tokio::time::timeout(
                std::time::Duration::from_millis(20),
                send_recorded(
                    &w,
                    &TXID,
                    &[1],
                    518,
                    &inputs,
                    persist(&w, &id),
                    undo(&w, &id),
                    std::future::pending(),
                ),
            )
            .await;
            assert!(killed.is_err());
            assert!(recorded(&w));
            assert!(w.spendable_utxos().unwrap().is_empty());
        }

        /// A refusal by the node (`SendRejected`) undoes everything: no pending record, history,
        /// own output or `mints` row, the spent-by locks gone and the earlier lock back.
        #[tokio::test]
        async fn a_refused_send_is_rolled_back() {
            let (w, inputs) = setup();
            let id = Cell::new(None);
            let e = send_recorded(
                &w,
                &TXID,
                &[1],
                518,
                &inputs,
                persist(&w, &id),
                undo(&w, &id),
                async {
                    Err(WalletError::Net(NetError::SendRejected {
                        code: -26,
                        message: "bad-txns-inputs-spent".into(),
                    }))
                },
            )
            .await
            .unwrap_err();
            assert!(e.to_string().contains("bad-txns-inputs-spent"), "{e}");
            assert!(!recorded(&w));
            assert!(w.store.mints().unwrap().is_empty());
            let locks = w.store.locks().unwrap();
            assert_eq!(locks.len(), 1);
            assert_eq!(
                (locks[0].outpoint, locks[0].reason.as_str()),
                (inputs[1].outpoint, "carrier:9")
            );
            assert_eq!(w.spendable_utxos().unwrap(), vec![inputs[0].clone()]);
            // A server refusing the call itself (rate limit) is as certain.
            let id = Cell::new(None);
            let _ = send_recorded(
                &w,
                &TXID,
                &[1],
                518,
                &inputs,
                persist(&w, &id),
                undo(&w, &id),
                async {
                    Err(WalletError::Net(NetError::Status(
                        tonic::Status::resource_exhausted("slow down"),
                    )))
                },
            )
            .await
            .unwrap_err();
            assert!(!recorded(&w));
        }

        /// A failure that may follow a broadcast (a timeout) keeps the record: the sync settles
        /// it, as for a kill.
        #[tokio::test]
        async fn an_ambiguous_failure_keeps_the_record() {
            for status in [
                tonic::Status::deadline_exceeded("timeout"),
                tonic::Status::unavailable("reset"),
                tonic::Status::unknown("?"),
            ] {
                let (w, inputs) = setup();
                let id = Cell::new(None);
                let r = send_recorded(
                    &w,
                    &TXID,
                    &[1],
                    518,
                    &inputs,
                    persist(&w, &id),
                    undo(&w, &id),
                    async { Err(WalletError::Net(NetError::Status(status))) },
                )
                .await;
                assert!(r.is_err());
                assert!(recorded(&w));
            }
        }

        /// A write that fails sends nothing ("Nothing was sent") and leaves nothing behind.
        #[tokio::test]
        async fn a_failed_write_sends_nothing() {
            let (w, inputs) = setup();
            let id = Cell::new(None);
            let polled = Cell::new(false);
            let e = send_recorded(
                &w,
                &TXID,
                &[1],
                518,
                &inputs,
                || {
                    w.store.upsert_history(&history())?;
                    Err(WalletError::Other("disk full".into()))
                },
                undo(&w, &id),
                async {
                    polled.set(true);
                    Ok(())
                },
            )
            .await
            .unwrap_err();
            assert!(e.to_string().contains("disk full"));
            assert!(!polled.get(), "the send ran after a failed write");
            assert!(w.store.history_row(&TXID).unwrap().is_none());
            assert!(w.store.pending_txs().unwrap().is_empty());
            assert_eq!(spent_by(&w), 0);
        }

        /// A refused MINT puts the row's step back (CARRIER_CONFIRMED, no main txid).
        #[test]
        fn restore_step_puts_the_row_back() {
            let w = wallet();
            let id = w
                .store
                .insert_mint(&MintRow {
                    state: MintState::CarrierConfirmed,
                    note: "n".into(),
                    ..row()
                })
                .unwrap();
            let m = w.store.mint(id).unwrap().unwrap();
            w.store
                .set_mint_state(id, MintState::MainSent, Some(&[9; 32]), None, "")
                .unwrap();
            restore_step(&w, &m).unwrap();
            assert_eq!(w.store.mint(id).unwrap().unwrap(), m);
        }
    }
}
