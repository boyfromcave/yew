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
    /// The estimate's [`MintEstimate::fee_guard`] acknowledgement, when its fee was flagged
    /// (review YEW-REVIEW-4 M2): required then, refused otherwise.
    pub accept_unusual_fee: Option<String>,
    /// The carrier funding fee the user confirmed ([`MintEstimate::carrier_fee_zat`]; beta2 D-3:
    /// a post-quantum source prices it on the size). `start` refuses a carrier funding that pays
    /// more (the stored quote is what the user acknowledged, review YEW-REVIEW-6 M1). `None`: the
    /// estimate's at `start`.
    pub carrier_fee_zat: Option<i64>,
    /// The estimate's [`MintEstimate::carrier_fee_guard`] acknowledgement, when that fee was
    /// flagged: required then.
    pub accept_unusual_carrier_fee: Option<String>,
}

/// The mint estimates the core issued, by an id the core chose (review YEW-REVIEW-10 L2). A
/// start takes its terms from here, never from the page or screen: the collateral, fee, payee,
/// class, the carrier fee cap and the source are the ones the core computed and showed, so a
/// faulty or tampered caller cannot raise the carrier fee the funding may pay, or name another
/// source. Only the last [`IssuedEstimates::KEEP`] are kept.
#[derive(Clone, Debug, Default)]
pub struct IssuedEstimates {
    seq: u64,
    issued: std::collections::VecDeque<(String, MintEstimate)>,
}

impl IssuedEstimates {
    /// How many issued estimates are kept (the oldest is dropped first).
    pub const KEEP: usize = 16;

    /// Record `e` and return its id.
    pub fn issue(&mut self, e: &MintEstimate) -> String {
        self.seq += 1;
        let id = format!("e{}", self.seq);
        if self.issued.len() == Self::KEEP {
            self.issued.pop_front();
        }
        self.issued.push_back((id.clone(), e.clone()));
        id
    }

    /// The estimate issued under `id`, if it is still kept.
    pub fn get(&self, id: &str) -> Option<&MintEstimate> {
        self.issued.iter().find(|(i, _)| i == id).map(|(_, e)| e)
    }

    /// The last estimate issued for this amount, lock and source.
    pub fn latest_for(
        &self,
        cents: u64,
        lock_blocks: u32,
        source: MintSource,
    ) -> Option<&MintEstimate> {
        self.issued
            .iter()
            .rev()
            .map(|(_, e)| e)
            .find(|e| e.cents == cents && e.lock_blocks == lock_blocks && e.source == source)
    }

    /// Forget every issued estimate.
    pub fn clear(&mut self) {
        self.issued.clear();
    }
}

/// Where a mint's YEC comes from (beta2 D-3 in the app: "MINT funded from a chosen source"; the
/// app has no generic vault-lock builder). The MINT transaction is the same for every source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintSource {
    /// The wallet's transparent ECC coins (`FEE_RESERVE`, then `YEC`): the carrier funding and
    /// the MINT's own inputs, as before.
    Ecc,
    /// One own post-quantum address (`sqf…`/`sqs…`): the carrier funding transaction spends only
    /// that address's `PQ_OWNED` coins ([`gate::Path::CarrierFromPq`]) and pays, beside the
    /// carrier, the MINT's YEC need to a fresh own P2PKH key (the staged funding), the change
    /// back to the source (D-4). The MINT then spends the staged output first, as a plain `YEC`
    /// input, with the carrier.
    Pq(crate::pq::PqKeyId),
    /// The wallet's private (Sapling) balance: the carrier funding spends Sapling notes through
    /// the hybrid builder ([`gate::Path::CarrierFromSapling`]: no transparent input) and pays the
    /// carrier and the staged MINT funding to a fresh own P2PKH key, the change back to the
    /// private balance as a Sapling note. Native only (the browser has no prover); started with
    /// `start_from_sapling`.
    Sapling,
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
    /// The guard on the MINT's network fee (review YEW-REVIEW-4 M2): a flagged fee needs its
    /// acknowledgement in [`ConfirmedTerms::accept_unusual_fee`] at `start`.
    pub fee_guard: terms::FeeGuard,
    /// The source of the YEC (beta2 D-3).
    pub source: MintSource,
    /// The carrier funding transaction's fee: the flat Yellowback fee from ECC; from a
    /// post-quantum address the size fee of its signatures (at least the flat fee). Included in
    /// `network_fee_zat`.
    pub carrier_fee_zat: i64,
    /// The guard on a post-quantum source's carrier fee (it rests on the server's terms): a
    /// flagged fee needs [`ConfirmedTerms::accept_unusual_carrier_fee`]. `None` from ECC.
    pub carrier_fee_guard: Option<terms::FeeGuard>,
}

impl MintEstimate {
    /// True when the wallet can fund both steps.
    pub fn affordable(&self) -> bool {
        self.available_zat >= self.total_zat
    }

    /// The terms a start re-checks, taken from this estimate (review YEW-REVIEW-10 L2): the
    /// collateral, fee, payee and class the user saw, the carrier fee as the cap on the funding,
    /// and the acknowledgement tokens the caller passes back (each is compared with the guard's
    /// own token at `start`).
    pub fn confirmed_terms(
        &self,
        accept_unusual_fee: Option<String>,
        accept_unusual_carrier_fee: Option<String>,
    ) -> ConfirmedTerms {
        ConfirmedTerms {
            collateral_zat: self.collateral_zat,
            fee_zat: self.fee_zat,
            payee: self.payee.clone(),
            term_class: self.term_class.clone(),
            accept_unusual_fee,
            carrier_fee_zat: Some(self.carrier_fee_zat),
            accept_unusual_carrier_fee,
        }
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

/// The network fee [`finish`] would charge a MINT funded from the public balance whose outputs
/// (collateral, token, protocol and attestor fees) come to `outputs`: the same selection loop
/// over the coins spendable now. `None` when they do not cover it (the estimate's affordability
/// check says so).
pub fn ecc_mint_fee(wallet: &Wallet, outputs: i64) -> Option<i64> {
    let spendable = wallet.spendable_utxos().ok()?;
    let mut fee = mint_network_fee(wallet, &[]);
    for _ in 0..64 {
        let sel = coins::select_yec(&spendable, outputs + fee - CARRIER_VALUE, true).ok()?;
        let next = mint_network_fee(wallet, &sel);
        if next <= fee {
            return Some(fee);
        }
        fee = next;
    }
    None
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
    source: MintSource,
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
    let mint_fee = wallet
        .pq_terms()
        .yed_fee(crate::params::yed_estimated_size(1, &[]));
    let (avail, reserved) = coins::yec_balances(&wallet.spendable_utxos()?);
    // From the public balance the MINT selects its own coins at `finish`, raising its fee with
    // each input (`PQFeeFollower`): price it on the coins that selection takes now (real-stack
    // run WEB-REAL LOW-6: the estimate assumed one input and fell 0.0001 YEC short).
    let mint_fee = match source {
        MintSource::Ecc => ecc_mint_fee(
            wallet,
            collateral_zat
                + TOKEN_VALUE
                + if payee.is_empty() { 0 } else { fee_zat }
                + attest_fee_zat,
        )
        .unwrap_or(mint_fee),
        _ => mint_fee,
    };
    let (carrier_fee_zat, carrier_fee_guard, available_zat) = match source {
        MintSource::Ecc => (wallet.pq_terms().flat_zat, None, avail + reserved),
        MintSource::Pq(id) => {
            let staged = staged_value(
                wallet,
                collateral_zat,
                if payee.is_empty() { 0 } else { fee_zat },
                attest_fee_zat,
            );
            // the carrier's script does not change the size: any P2SH of the carrier's length
            let carrier_spk = script::p2sh_script(&[0; 20]);
            let stage_spk = script::p2pkh_script(&[0; 20]);
            let f = plan_pq_funding(wallet, &id, &carrier_spk, staged, &stage_spk, tip)?;
            let guard = wallet.guard_fee(
                terms::FeeKind::Plain,
                f.plan.fee,
                f.plan.estimated_bytes,
                f.conventional,
                "mint carrier",
            )?;
            (f.plan.fee, Some(guard), f.available)
        }
        MintSource::Sapling => {
            let staged = staged_value(
                wallet,
                collateral_zat,
                if payee.is_empty() { 0 } else { fee_zat },
                attest_fee_zat,
            );
            let q = sapling_funding_quote(wallet, staged)?;
            (q.fee, Some(q.guard), q.available)
        }
    };
    let network_fee_zat = carrier_fee_zat + mint_fee;
    let total_zat =
        collateral_zat + TOKEN_VALUE + fee_zat + attest_fee_zat + CARRIER_VALUE + network_fee_zat;
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
        available_zat,
        fee_guard: main_fee_guard(wallet, "mint")?,
        source,
        carrier_fee_zat,
        carrier_fee_guard,
    })
}

/// The MINT's YEC need at one P2PKH funding input (`BuildMint`: outputs + fee − `CARRIER_VALUE`):
/// what a carrier funded from another source stages for it.
///
/// Never exactly `TOKEN_VALUE` (it would look like a YED token): such a need is raised by one
/// zat, which the MINT's change or fee takes. It cannot happen while the collateral is positive.
pub fn staged_value(wallet: &Wallet, collateral: i64, protocol_fee: i64, attest_fee: i64) -> i64 {
    let v = collateral
        + TOKEN_VALUE
        + protocol_fee
        + attest_fee
        + wallet.pq_terms().yed_network_fee(1, &[]);
    if v == TOKEN_VALUE {
        v + 1
    } else {
        v
    }
}

/// The fee of a carrier funding from the private balance spending `notes` Sapling notes: the
/// ZIP-317 conventional fee of the shape (two transparent outputs, the carrier's P2SH and the
/// staged P2PKH, both within the standard output size; `notes` spends; the Sapling change, padded
/// to two outputs), at least the server's flat Yellowback fee (`BuildCarrier`'s floor, as the
/// post-quantum source takes it), capped at [`crate::params::MAX_FLAT_ZAT`] for that floor.
pub fn sapling_carrier_fee(flat_zat: i64, notes: usize) -> i64 {
    super::any_to_any::conventional_fee_bytes(0, 2, 0, notes, 1)
        .max(flat_zat.min(crate::params::MAX_FLAT_ZAT))
}

/// The size, in bytes, of a carrier funding from the private balance spending `notes` notes
/// (v4 header and transparent part ~150, 384 per spend, 948 per output padded to two, the
/// binding signature): what the fee guard compares the fee with before the transaction exists.
pub fn sapling_carrier_size(notes: usize) -> usize {
    150 + 384 * notes + 2 * 948 + 64
}

/// The estimate's quote of a carrier funding from the private balance.
pub struct SaplingFundingQuote {
    /// The fee, zat.
    pub fee: i64,
    /// Its guard (the server's flat fee enters it).
    pub guard: terms::FeeGuard,
    /// The private balance's spendable YEC, zat.
    pub available: i64,
    /// The notes it would spend.
    pub notes: usize,
}

/// Quote the carrier funding of `staged` zat from the private balance (read-only: the store's
/// selection without the paths, [`crate::shielded::Shielded::quote_spends`]).
#[cfg(not(target_arch = "wasm32"))]
pub fn sapling_funding_quote(
    wallet: &Wallet,
    staged: i64,
) -> Result<SaplingFundingQuote, WalletError> {
    if let Some(why) = wallet.terms_refused() {
        return Err(WalletError::Other(format!(
            "The server's fee terms were refused, so nothing is sent: {why}"
        )));
    }
    let flat = wallet.pq_terms().flat_zat;
    let sh = wallet.shielded()?;
    let available = sh.balance()?.spendable_zat as i64;
    let (notes, fee, _) = sh.quote_spends((CARRIER_VALUE + staged) as u64, |n| {
        sapling_carrier_fee(flat, n) as u64
    })?;
    let fee = fee as i64;
    let conventional = super::any_to_any::conventional_fee_bytes(0, 2, 0, notes, 1);
    let guard = wallet.guard_fee(
        terms::FeeKind::Plain,
        fee,
        sapling_carrier_size(notes),
        conventional,
        "mint carrier",
    )?;
    Ok(SaplingFundingQuote {
        fee,
        guard,
        available,
        notes,
    })
}

/// The browser has no prover: a mint is not funded from the private balance there.
#[cfg(target_arch = "wasm32")]
pub fn sapling_funding_quote(_: &Wallet, _: i64) -> Result<SaplingFundingQuote, WalletError> {
    Err(WalletError::Other(
        "a mint is funded from the private balance only in the app (the browser has no prover)"
            .into(),
    ))
}

/// A planned carrier funding from a post-quantum source.
pub struct PqFunding {
    /// The planner's settlement (coins, outputs in `vout` order, change, fee, size).
    pub plan: super::any_to_any::PqSourcePlan<Utxo>,
    /// The shape's ZIP-317 conventional fee at the estimated size.
    pub conventional: i64,
    /// The source's spendable post-quantum YEC, zat.
    pub available: i64,
}

/// Plan the carrier funding from the own post-quantum address `id` (beta2 D-3): the carrier
/// (`carrier_spk`, `CARRIER_VALUE`) and the staged MINT funding (`stage_spk`, `staged`) paid from
/// that address's confirmed `PQ_OWNED` coins by the planner `pq_send` and yewd's `z_sendmany`
/// use (size fee at the server's bounded rate, at least the flat Yellowback fee; the change back
/// to the source, D-4; never a change of exactly `TOKEN_VALUE`).
pub fn plan_pq_funding(
    wallet: &Wallet,
    id: &crate::pq::PqKeyId,
    carrier_spk: &[u8],
    staged: i64,
    stage_spk: &[u8],
    tip: u64,
) -> Result<PqFunding, WalletError> {
    use super::any_to_any::{self as plan, PlanRecipient, PqCoin};
    let other = |m: &str| WalletError::Other(m.to_string());
    if let Some(why) = wallet.terms_refused() {
        return Err(WalletError::Other(format!(
            "The server's fee terms were refused, so nothing is sent: {why}"
        )));
    }
    let terms = wallet.pq_terms();
    if id.scheme == crate::pq::SCHEME_FN_DSA_512 && !terms.falcon_at(tip + 1) {
        return Err(other(
            "an FN-DSA-512 (scheme 2) post-quantum address can be spent from only once Falcon is active at the next block",
        ));
    }
    let source = crate::pq::pqpkh_script(id)
        .ok_or_else(|| other("the address's scheme is not registered"))?;
    let spendable = wallet.spendable_utxos()?;
    let coins: Vec<PqCoin<Utxo>> = spendable
        .iter()
        .filter(|u| u.class == UtxoClass::PqOwned && u.script == source && u.height > 0)
        .map(|u| PqCoin {
            outpoint: u.outpoint,
            value: u.value,
            script: u.script.clone(),
            key: u.clone(),
        })
        .collect();
    let available = coins.iter().map(|c| c.value).sum();
    let recipients = [
        PlanRecipient {
            script: Some(carrier_spk.to_vec()),
            amount: CARRIER_VALUE,
        },
        PlanRecipient {
            script: Some(stage_spk.to_vec()),
            amount: staged,
        },
    ];
    let (rate, cap) = (terms.fee_rate_zat_per_kb, terms.max_fee_zat);
    let policy = super::pq_send::APP_POLICY;
    let mut p = plan::plan_pq_source(&coins, &source, &recipients, None, policy, rate, cap)
        .map_err(|e| WalletError::Other(e.to_string()))?;
    if p.fee < terms.flat_zat {
        // `BuildCarrier`'s flat Yellowback fee is the floor of a carrier funding
        p = plan::plan_pq_source(
            &coins,
            &source,
            &recipients,
            Some(terms.flat_zat),
            policy,
            rate,
            cap,
        )
        .map_err(|e| WalletError::Other(e.to_string()))?;
    }
    if p.change == TOKEN_VALUE {
        p.change -= 1;
        p.fee += 1;
        if let Some(o) = p.transparent_outputs.last_mut() {
            o.1 -= 1;
        }
    }
    let (_, conventional) = plan::shape_size(
        p.selected.iter().map(|c| c.script.as_slice()),
        &p.transparent_outputs,
        0,
        0,
    );
    Ok(PqFunding {
        plan: p,
        conventional,
        available,
    })
}

/// The guard on a two-step row's main transaction (the MINT, or a CLAIM) as its start sees it:
/// the Yellowback size fee at one P2PKH funding input (as the estimate prices it), labelled
/// `label` so the acknowledgement names the kind of row (review YEW-REVIEW-4 M2).
pub fn main_fee_guard(wallet: &Wallet, label: &str) -> Result<terms::FeeGuard, WalletError> {
    let size = crate::params::yed_estimated_size(1, &[]);
    let fee = wallet.pq_terms().yed_fee(size);
    wallet.guard_fee(terms::FeeKind::Yed, fee, size, 0, label)
}

/// The meta key under which the start of row `id` recorded the main fee it accepted
/// ([`note_fee_ack`]): `"<fee> <size> <flagged>"`.
fn fee_quote_key(id: i64) -> String {
    format!("fee_quote:{id}")
}

/// The main fee the start of a two-step row accepted (review YEW-REVIEW-5 M2): the fee, the size
/// it was quoted for, and whether it was flagged unusual (and acknowledged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FeeQuote {
    /// The accepted main fee, zat.
    pub fee: i64,
    /// The size it was quoted for, bytes.
    pub size: usize,
    /// It was unusual and the user acknowledged it.
    pub flagged: bool,
}

impl FeeQuote {
    /// The quote scaled to `size` bytes (rounded up): what the accepted terms give at the real
    /// size.
    pub fn at(&self, size: usize) -> i64 {
        let q = self.size.max(1) as i128;
        ((self.fee as i128 * size as i128 + q - 1) / q) as i64
    }
}

fn read_fee_quote(wallet: &Wallet, id: i64) -> Result<Option<FeeQuote>, WalletError> {
    let Some(v) = wallet.store.meta(&fee_quote_key(id))? else {
        return Ok(None);
    };
    let f: Vec<&str> = v.split(' ').collect();
    match f.as_slice() {
        [fee, size, flagged] => match (fee.parse(), size.parse(), *flagged) {
            (Ok(fee), Ok(size), "0" | "1") => Ok(Some(FeeQuote {
                fee,
                size,
                flagged: *flagged == "1",
            })),
            _ => Err(WalletError::Other(format!("fee quote of row {id}: {v:?}"))),
        },
        _ => Err(WalletError::Other(format!("fee quote of row {id}: {v:?}"))),
    }
}

fn write_fee_quote(wallet: &Wallet, id: i64, q: &FeeQuote) -> Result<(), WalletError> {
    wallet.store.set_meta(
        &fee_quote_key(id),
        &format!("{} {} {}", q.fee, q.size, u8::from(q.flagged)),
    )?;
    Ok(())
}

/// Record on row `id` the main fee its start accepted (review YEW-REVIEW-5 M2): exactly the fee
/// and size `g` (the guard required at the start, [`main_fee_guard`]) priced and the user saw,
/// and whether it was flagged. Never re-priced from the terms as they are now (review
/// YEW-REVIEW-6 M1: the start refreshes them after the guard). A restart keeps it (the store's
/// meta).
pub(crate) fn note_fee_ack(
    wallet: &Wallet,
    id: i64,
    g: &terms::FeeGuard,
) -> Result<(), WalletError> {
    write_fee_quote(
        wallet,
        id,
        &FeeQuote {
            fee: g.fee,
            size: g.size,
            flagged: g.ack.is_some(),
        },
    )
}

/// After a start has refreshed the server's terms ([`vault_terms_now`]), before anything is
/// funded (review YEW-REVIEW-6 M1): the main fee at `g`'s size under the terms now must not be
/// above the fee `g` priced (what the user saw and, when flagged, acknowledged). A server that
/// raised its rate within the start is refused here and the user starts again from a new preview.
pub(crate) fn check_fee_not_raised(
    wallet: &Wallet,
    g: &terms::FeeGuard,
    label: &str,
) -> Result<(), WalletError> {
    let now = wallet.pq_terms().yed_fee(g.size);
    if now > g.fee {
        return Err(WalletError::Other(format!(
            "fee-terms-changed: the server's fee terms changed while the {label} was starting: its fee would now be {} YEC, above the {} YEC you confirmed. Nothing was sent; review the new fee and start again.",
            crate::build::any_to_any::format_money(now),
            crate::build::any_to_any::format_money(g.fee)
        )));
    }
    Ok(())
}

/// The main transaction's fee at `finish` (review YEW-REVIEW-4 M2, YEW-REVIEW-5 M2):
/// - above this build's limit: refused;
/// - the start accepted a flagged fee: at most that fee scaled to the real size;
/// - the start accepted an unflagged fee: not flagged now, and at most twice that fee scaled to
///   the real size (the flag threshold);
/// - a row started by an older build (no quote; its `fee_ack:<id>` is ignored): not flagged now.
///
/// Anything else is refused with a new acknowledgement (`accept-unusual-fee:<fee>:row:<id>`); the
/// same call with `accept` equal to it pays the fee (still within the limit) and records it as the
/// row's new quote, so the server cannot raise its terms between the carrier and the MINT or
/// CLAIM without asking again.
pub(crate) fn check_main_fee(
    wallet: &Wallet,
    id: i64,
    fee: i64,
    inputs: &[Utxo],
    accept: Option<&str>,
) -> Result<(), WalletError> {
    let (size, conventional) = terms::yed_priced_size(inputs.iter().map(|u| u.script.as_slice()));
    let g = wallet.guard_fee(
        terms::FeeKind::Yed,
        fee,
        size,
        conventional,
        &format!("row:{id}"),
    )?;
    let quote = read_fee_quote(wallet, id)?;
    let within = match quote {
        Some(q) if q.flagged => fee <= q.at(size),
        Some(q) => g.ack.is_none() && fee <= q.at(size).saturating_mul(2),
        None => g.ack.is_none(),
    };
    if within {
        return Ok(());
    }
    let ack = format!("accept-unusual-fee:{fee}:row:{id}");
    if accept == Some(ack.as_str()) {
        return write_fee_quote(
            wallet,
            id,
            &FeeQuote {
                fee,
                size,
                flagged: true,
            },
        );
    }
    let was = match quote {
        Some(q) => format!(
            "You accepted {} YEC for {} bytes at the start ({} YEC at this size).",
            crate::build::any_to_any::format_money(q.fee),
            q.size,
            crate::build::any_to_any::format_money(q.at(size))
        ),
        None => "You accepted no unusual fee at the start.".to_string(),
    };
    Err(WalletError::Other(format!(
        "unusual-fee: the fee changed after you confirmed, so nothing was sent. It is now {} YEC for {size} bytes. {was} {}To pay it, confirm again with the acknowledgement {ack}; otherwise the carrier lapses at the end of its window and can then be swept back.",
        crate::build::any_to_any::format_money(fee),
        g.note.map(|n| format!("{n} ")).unwrap_or_default()
    )))
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
    funding: CarrierFunding,
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
    let (carrier_row, redeem) = carrier_key(wallet, bundle)?;
    if let CarrierFunding::Pq {
        id,
        staged,
        max_fee,
    } = funding
    {
        return carrier_step_pq(
            wallet,
            client,
            validator,
            (&carrier_row, &redeem, bundle),
            (id, staged, max_fee),
            (expiry_height, tip, branch_id),
            persist_row,
        )
        .await;
    }
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
    // review YEW-REVIEW-9 L3: the change key is derived and recorded before the transaction is
    // built; the gate compares vout[0] with the re-derived carrier and vout[1] with the record
    let change_row = if change > 0 {
        Some(record_carrier_change_key(wallet, &carrier_row.hash160)?)
    } else {
        None
    };
    let want = recorded_ecc_carrier_outputs(wallet, &carrier_row.hash160, bundle, change > 0)?;
    let mut tx = Transaction::new_v4();
    tx.expiry_height = expiry_height;
    for u in &inputs {
        tx.vin.push(TxIn::new(u.outpoint));
    }
    tx.vout.push(TxOut {
        value: CARRIER_VALUE,
        script_pubkey: script::p2sh_of(&redeem),
    });
    if let Some(row) = &change_row {
        tx.vout.push(TxOut {
            value: change,
            script_pubkey: script::p2pkh_script(&row.hash160),
        });
    }
    sign_p2pkh_inputs(wallet, &mut tx, &inputs, 0, branch_id)?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    let (_, validation) = gate::confirm(validator, gate::Path::Carrier(want), &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    // layer 3 on the YEC inputs (every input of the carrier funding): no input spent as plain YEC carries YED by its creating transaction
    gate::confirm_provenance(
        client,
        gate::Path::Carrier(want),
        &raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        |op| wallet.store.utxo_txout(op).ok().flatten(),
    )
    .await?;
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

/// A fresh carrier key (change chain, marked used) and the carrier redeem script it signs for,
/// committing to `bundle` (`BuildCarrier`).
pub(crate) fn carrier_key(
    wallet: &Wallet,
    bundle: &[u8],
) -> Result<(AddressRow, Vec<u8>), WalletError> {
    let carrier_row = fresh_change(wallet)?;
    let carrier_key = wallet
        .key_for_hash(&carrier_row.hash160)?
        .ok_or_else(|| WalletError::Other("carrier key".into()))?;
    let redeem = script::carrier_script(&carrier_key.pubkey, &bundle::bundle_hash(bundle))
        .map_err(MintError::Script)?;
    Ok((carrier_row, redeem))
}

/// How [`carrier_step`] funds the carrier (beta2 D-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierFunding {
    /// The wallet's transparent ECC coins, as before ([`gate::Path::Carrier`], now bound to the
    /// carrier and the recorded change key).
    Ecc,
    /// The own post-quantum address `id` ([`gate::Path::CarrierFromPq`]): the carrier and the
    /// staged MINT funding (`staged` zat to a fresh own P2PKH key), at most `max_fee` (the fee
    /// the user confirmed on the estimate).
    Pq {
        id: crate::pq::PqKeyId,
        staged: i64,
        max_fee: i64,
    },
}

/// The meta key under which a mint row records its staged funding output (`txid:n`, beta2 D-3).
pub(crate) fn stage_key(id: i64) -> String {
    format!("mint_stage:{id}")
}

/// The lock reason of a staged funding output (review YEW-REVIEW-8 L2): held for mint row `id`
/// from the carrier funding until the MINT spends it (its `spent-by:` lock replaces this one) or
/// the row leaves the carrier states (the sync releases it: the output is ordinary YEC again).
pub(crate) const STAGED_FOR_MINT: &str = "staged-for-mint:";

/// The meta key under which the staged funding key of the carrier whose key hash is
/// `carrier_key` is recorded before the carrier funding is built (review YEW-REVIEW-8 M2). The
/// mint row names the carrier key (`carrier_hash160`), so the record belongs to the row.
pub(crate) fn staging_record_key(carrier_key: &[u8; 20]) -> String {
    format!("mint_staging:{}", keys::hex(carrier_key))
}

/// Derive a fresh change key for a mint's staged funding and record it under the carrier's key
/// before anything is built (review YEW-REVIEW-8 M2).
pub(crate) fn record_stage_key(
    wallet: &Wallet,
    carrier_key: &[u8; 20],
) -> Result<AddressRow, WalletError> {
    let row = fresh_change(wallet)?;
    wallet
        .store
        .set_meta(&staging_record_key(carrier_key), &keys::hex(&row.hash160))?;
    Ok(row)
}

/// The HASH160 of the carrier redeem script, re-derived here (review YEW-REVIEW-9 L1) from the
/// carrier key hash and the bundle the way the sync derives a carrier it holds: the key must be a
/// change-chain key of this wallet's seed, re-derived at its recorded index (`key_for_hash`), and
/// the script is `carrier_script(its public key, bundle_hash(bundle))`. A builder that built
/// `vout[0]` from another key or another bundle than these fails the gate's comparison.
pub(crate) fn derived_carrier_hash(
    wallet: &Wallet,
    carrier_key: &[u8; 20],
    bundle: &[u8],
) -> Result<[u8; 20], WalletError> {
    let bad = |m: &str| WalletError::Other(format!("the mint's carrier key: {m}"));
    let row = wallet
        .store
        .addresses()?
        .into_iter()
        .find(|r| r.hash160 == *carrier_key)
        .ok_or_else(|| bad("not a key of this wallet"))?;
    if row.hd_chain() != Some(keys::Chain::Change) {
        return Err(bad("not a change key of this wallet's seed"));
    }
    let key = wallet
        .key_for_hash(carrier_key)?
        .ok_or_else(|| bad("not a key of this wallet"))?;
    let redeem = script::carrier_script(&key.pubkey, &bundle::bundle_hash(bundle))
        .map_err(MintError::Script)?;
    Ok(keys::hash160(&redeem))
}

/// The outputs the gate's carrier-from-another-source paths compare (review YEW-REVIEW-8 M2,
/// L1; YEW-REVIEW-9 L1): the carrier is `P2SH` of the redeem script re-derived from the carrier
/// key and `bundle` ([`derived_carrier_hash`], never the builder's own script); the staged key is
/// read back from the wallet's record for this carrier key (never taken from a builder's
/// argument) and must be a change-chain key of this wallet's seed (one a restore finds).
pub(crate) fn recorded_carrier_outputs(
    wallet: &Wallet,
    carrier_key: &[u8; 20],
    bundle: &[u8],
) -> Result<gate::CarrierOutputs, WalletError> {
    let staged_key = recorded_change_key(
        wallet,
        &staging_record_key(carrier_key),
        "the mint's staged funding key",
    )?;
    Ok(gate::CarrierOutputs {
        carrier_hash: derived_carrier_hash(wallet, carrier_key, bundle)?,
        staged_key,
    })
}

/// A key hash recorded under `meta_key`, checked to be a change-chain key of this wallet's seed:
/// it must have an address row on the change chain and re-derive at its recorded index
/// (`key_for_hash`). `what` names it in the refusals.
fn recorded_change_key(
    wallet: &Wallet,
    meta_key: &str,
    what: &str,
) -> Result<[u8; 20], WalletError> {
    let bad = |m: &str| WalletError::Other(format!("{what}: {m}"));
    let v = wallet
        .store
        .meta(meta_key)?
        .filter(|v| !v.is_empty())
        .ok_or_else(|| bad("not recorded"))?;
    let key: [u8; 20] = unhex(&v)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("unreadable record"))?;
    let row = wallet
        .store
        .addresses()?
        .into_iter()
        .find(|r| r.hash160 == key)
        .ok_or_else(|| bad("not a key of this wallet"))?;
    if row.hd_chain() != Some(keys::Chain::Change) {
        return Err(bad("not a change key of this wallet's seed"));
    }
    if wallet.key_for_hash(&key)?.is_none() {
        return Err(bad("not a key of this wallet"));
    }
    Ok(key)
}

/// The meta key under which the change key of the ECC carrier funding whose carrier key hash is
/// `carrier_key` is recorded before that transaction is built (review YEW-REVIEW-9 L3).
pub(crate) fn carrier_change_record_key(carrier_key: &[u8; 20]) -> String {
    format!("carrier_change:{}", keys::hex(carrier_key))
}

/// Derive a fresh change key for an ECC carrier funding and record it under the carrier's key
/// before anything is built (review YEW-REVIEW-9 L3).
pub(crate) fn record_carrier_change_key(
    wallet: &Wallet,
    carrier_key: &[u8; 20],
) -> Result<AddressRow, WalletError> {
    let row = fresh_change(wallet)?;
    wallet.store.set_meta(
        &carrier_change_record_key(carrier_key),
        &keys::hex(&row.hash160),
    )?;
    Ok(row)
}

/// What [`gate::Path::Carrier`] compares for an ECC carrier funding (review YEW-REVIEW-9 L3): the
/// carrier re-derived from the carrier key and `bundle` ([`derived_carrier_hash`]) and, when the
/// funding pays change, the change key read back from the record (a change-chain key of the
/// seed), never a builder's argument.
pub(crate) fn recorded_ecc_carrier_outputs(
    wallet: &Wallet,
    carrier_key: &[u8; 20],
    bundle: &[u8],
    with_change: bool,
) -> Result<gate::EccCarrierOutputs, WalletError> {
    let change_key = if with_change {
        Some(recorded_change_key(
            wallet,
            &carrier_change_record_key(carrier_key),
            "the carrier funding's change key",
        )?)
    } else {
        None
    };
    Ok(gate::EccCarrierOutputs {
        carrier_hash: derived_carrier_hash(wallet, carrier_key, bundle)?,
        change_key,
    })
}

/// Record mint row `id`'s staged funding output (`txid:1`) and lock it to the row (review
/// YEW-REVIEW-8 L2): no other coin selection takes it and it is not counted spendable.
pub(crate) fn record_staged_output(
    wallet: &Wallet,
    id: i64,
    txid: &[u8; 32],
    expiry_height: u32,
) -> Result<(), WalletError> {
    wallet
        .store
        .set_meta(&stage_key(id), &format!("{}:1", txid_hex(txid)))?;
    wallet.store.lock(
        &OutPoint { txid: *txid, n: 1 },
        &format!("{STAGED_FOR_MINT}{id}"),
        expiry_height as u64,
    )?;
    Ok(())
}

/// The undo of [`record_staged_output`] and the row, for a carrier funding the server refused.
pub(crate) fn undo_staged_output(
    wallet: &Wallet,
    id: Option<i64>,
    txid: &[u8; 32],
) -> Result<(), WalletError> {
    wallet.store.unlock(&OutPoint { txid: *txid, n: 1 })?;
    match id {
        Some(id) => {
            wallet.store.set_meta(&stage_key(id), "")?;
            Ok(wallet.store.delete_mint(id)?)
        }
        None => Ok(()),
    }
}

/// Release the staged-funding locks of rows that left the carrier states (review YEW-REVIEW-8
/// L2): a lapsed, failed or deleted row's staged output is ordinary YEC again. A row whose MINT
/// was sent has its output under the MINT's `spent-by:` lock instead. Returns how many.
pub(crate) fn release_staged_locks(wallet: &Wallet) -> Result<u32, WalletError> {
    let mut n = 0;
    for l in wallet.store.locks()? {
        let Some(id) = l.reason.strip_prefix(STAGED_FOR_MINT) else {
            continue;
        };
        let live = id
            .parse::<i64>()
            .ok()
            .and_then(|id| wallet.store.mint(id).ok().flatten());
        if !live.is_some_and(|m| {
            matches!(
                m.state,
                MintState::CarrierSent | MintState::CarrierConfirmed
            )
        }) {
            wallet.store.unlock(&l.outpoint)?;
            n += 1;
        }
    }
    Ok(n)
}

/// The YEC staged for mints in progress, zat: the wallet's outputs locked
/// `staged-for-mint:<id>` ([`record_staged_output`]). In no balance and in no selection; a
/// balance screen shows it on its own, never in the spendable total (beta2 D-8). Read-only.
pub fn staged_for_mint_zat(wallet: &Wallet) -> Result<i64, WalletError> {
    let staged: std::collections::HashSet<OutPoint> = wallet
        .store
        .locks()?
        .into_iter()
        .filter(|l| l.reason.starts_with(STAGED_FOR_MINT))
        .map(|l| l.outpoint)
        .collect();
    Ok(wallet
        .store
        .utxos()?
        .iter()
        .filter(|u| staged.contains(&u.outpoint))
        .map(|u| u.value)
        .sum())
}

/// [`carrier_step`] from a post-quantum source: [`plan_pq_funding`], each input signed with
/// the source's key through the existing `Transaction::sign_pqpkh_input` and checked against
/// its digest, the signed size re-priced, the fee bounded by this build's limit and by the
/// confirmed quote, both gate layers on [`gate::Path::CarrierFromPq`] (the stored scripts too),
/// layer 3 on every input, then recorded and sent as the ECC carrier is.
async fn carrier_step_pq<R>(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    (carrier_row, redeem, bundle): (&AddressRow, &[u8], &[u8]),
    (id, staged, max_fee): (crate::pq::PqKeyId, i64, i64),
    (expiry_height, tip, branch_id): (u32, u64, u32),
    persist_row: R,
) -> Result<(CarrierStep, i64), WalletError>
where
    R: FnOnce(&CarrierStep) -> Result<i64, WalletError>,
{
    use super::any_to_any as plan;
    let other = |m: String| WalletError::Other(m);
    if branch_id != crate::params::VAULT_BRANCH_ID {
        return Err(other(
            "post-quantum addresses can be spent from only once the vault upgrade is active at the next block".into(),
        ));
    }
    let key = super::release::own_pq_key(wallet, &id)?.ok_or_else(|| {
        other("From address does not belong to this node, post-quantum key not found.".into())
    })?;
    // review YEW-REVIEW-8 M2: the staged key is recorded before anything is built, and the gate
    // compares the outputs with what the record and the carrier script say
    let stage_row = record_stage_key(wallet, &carrier_row.hash160)?;
    let want = recorded_carrier_outputs(wallet, &carrier_row.hash160, bundle)?;
    let stage_spk = script::p2pkh_script(&want.staged_key);
    let carrier_spk = script::p2sh_of(redeem);
    let f = plan_pq_funding(wallet, &id, &carrier_spk, staged, &stage_spk, tip)?;
    let p = f.plan;
    if p.transparent_outputs.first().map(|o| o.0.as_slice()) != Some(carrier_spk.as_slice())
        || p.transparent_outputs.get(1).map(|o| o.0.as_slice()) != Some(stage_spk.as_slice())
    {
        return Err(other(
            "the planned carrier funding is not in the carrier's order".into(),
        ));
    }
    // review YEW-REVIEW-6 M1: never more than the fee the user confirmed on the estimate
    if p.fee > max_fee {
        return Err(other(format!(
            "fee-terms-changed: the server's fee terms changed while the mint was starting: the carrier funding would now pay {} YEC, above the {} YEC you confirmed. Nothing was sent; review the new fee and start again.",
            plan::format_money(p.fee),
            plan::format_money(max_fee)
        )));
    }
    let mut tx = Transaction::new_v4();
    tx.expiry_height = expiry_height;
    for c in &p.selected {
        tx.vin.push(TxIn::new(c.outpoint));
    }
    for (spk, value) in &p.transparent_outputs {
        tx.vout.push(TxOut {
            value: *value,
            script_pubkey: spk.clone(),
        });
    }
    for (i, c) in p.selected.iter().enumerate() {
        let digest = tx.sign_pqpkh_input(i, &key, &c.script, c.value, branch_id)?;
        let ok =
            crate::pq::parse_pqpkh_script_sig(&tx.vin[i].script_sig).is_some_and(|(sig, pk)| {
                crate::pq::verify(id.scheme, &pk, &sig[..sig.len() - 1], &digest)
            });
        if !ok {
            return Err(other("the post-quantum signature does not verify".into()));
        }
    }
    tx.check_script_sig_sizes()?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    let terms = wallet.pq_terms();
    let sizes: Vec<usize> = tx.vin.iter().map(|i| i.script_sig.len()).collect();
    let conventional = tx.zip317_conventional_fee(&sizes)?;
    plan::check_signed_fee(
        p.fee,
        raw.len(),
        conventional,
        terms.fee_rate_zat_per_kb,
        terms.max_fee_zat,
    )
    .map_err(|e| other(e.to_string()))?;
    let limit = crate::params::pq_send_fee_limit(raw.len(), conventional)
        .max(terms.flat_zat.min(crate::params::MAX_FLAT_ZAT));
    if p.fee > limit {
        return Err(other(format!(
            "Fee {} YEC is above this app's limit of {} YEC for a {}-byte post-quantum carrier funding. Nothing was sent; try another server.",
            plan::format_money(p.fee),
            plan::format_money(limit),
            raw.len()
        )));
    }
    let scripts = |op: &OutPoint| {
        wallet
            .store
            .utxo_txout(op)
            .ok()
            .flatten()
            .map(|o| o.script_pubkey)
    };
    let path = gate::Path::CarrierFromPq(id, want);
    let (_, validation) = gate::confirm_with_scripts(
        validator,
        path,
        &raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        scripts,
    )
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    // layer 3 on every post-quantum input
    gate::confirm_provenance(
        client,
        path,
        &raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        |op| wallet.store.utxo_txout(op).ok().flatten(),
    )
    .await?;
    let step = CarrierStep {
        txid,
        carrier_hash160: carrier_row.hash160,
        expiry_height,
        validation,
    };
    let inputs: Vec<Utxo> = p.selected.iter().map(|c| c.key.clone()).collect();
    let selected: i64 = inputs.iter().map(|u| u.value).sum();
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
                yec_delta: p.change + staged - selected,
                has_payload: false,
                pending: true,
                shielded: false,
                yed_delta: 0,
                kind: "carrier".into(),
                verdict: String::new(),
                label: "funding carrier from your post-quantum address".into(),
                labelled: true,
            })?;
            wallet
                .store
                .insert_own_output(&OutPoint { txid, n: 1 }, staged, &stage_row.hash160)?;
            let id = persist_row(&step)?;
            record_staged_output(wallet, id, &txid, expiry_height)?;
            row_id.set(Some(id));
            Ok(())
        },
        || undo_staged_output(wallet, row_id.get(), &txid),
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
    source: MintSource,
) -> Result<i64, WalletError> {
    if source == MintSource::Sapling {
        return Err(WalletError::Other(
            "a mint funded from the private balance is started with start_from_sapling (it needs the proving parameters)".into(),
        ));
    }
    let p = prepare_start(
        wallet,
        client,
        validator,
        cents,
        lock_blocks,
        confirmed,
        tip,
        source,
    )
    .await?;
    let funding = match source {
        MintSource::Pq(id) => CarrierFunding::Pq {
            id,
            staged: p.staged(wallet),
            max_fee: p.carrier_quote,
        },
        _ => CarrierFunding::Ecc,
    };
    let (_, id) = carrier_step(
        wallet,
        client,
        validator,
        &p.bundle_bytes,
        p.est.ref_height,
        tip,
        branch_id,
        funding,
        |step: &CarrierStep| p.persist_row(wallet, cents, lock_blocks, tip, step),
    )
    .await?;
    note_fee_ack(wallet, id, &p.est.fee_guard)?;
    Ok(id)
}

/// What [`start`] settles before the carrier funding: the estimate re-checked against the
/// confirmed terms and its acknowledgements, the verified bundle, the owner key (taken), the
/// attestor payee and fee.
pub(crate) struct Prepared {
    pub(crate) est: MintEstimate,
    /// The carrier funding fee the user confirmed (the stored-quote rule).
    pub(crate) carrier_quote: i64,
    pub(crate) bundle_bytes: Vec<u8>,
    seqs: Vec<u16>,
    owner_row: AddressRow,
    owner: crate::pq::PqKeyId,
    fee_zat: i64,
    payee: String,
    attest_payee_addr: String,
    attest_fee_zat: i64,
}

impl Prepared {
    /// The MINT's YEC need a carrier funded from another source stages ([`staged_value`]).
    pub(crate) fn staged(&self, wallet: &Wallet) -> i64 {
        staged_value(
            wallet,
            self.est.collateral_zat,
            if self.payee.is_empty() {
                0
            } else {
                self.fee_zat
            },
            self.attest_fee_zat,
        )
    }

    /// Record the `mints` row for the carrier `step` (state `CarrierSent`).
    pub(crate) fn persist_row(
        &self,
        wallet: &Wallet,
        cents: u64,
        lock_blocks: u32,
        tip: u64,
        step: &CarrierStep,
    ) -> Result<i64, WalletError> {
        let (est, r, seqs) = (&self.est, self.est.ref_height, &self.seqs);
        let (fee_zat, payee) = (self.fee_zat, self.payee.clone());
        let (attest_fee_zat, attest_payee_addr) =
            (self.attest_fee_zat, self.attest_payee_addr.clone());
        let (owner_row, owner) = (&self.owner_row, self.owner);
        let bundle_bytes = &self.bundle_bytes;
        let row = MintRow {
            id: 0,
            kind: MintKind::Mint,
            state: MintState::CarrierSent,
            created_height: tip,
            cents,
            lock_blocks,
            term_class: est.term_class.clone(),
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
    }
}

/// The part of [`start`] before the carrier funding (moved out unchanged so the private-balance
/// source, which needs `&mut Wallet` for its note selection between the two, shares it).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_start(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    cents: u64,
    lock_blocks: u32,
    confirmed: Option<&ConfirmedTerms>,
    tip: u64,
    source: MintSource,
) -> Result<Prepared, WalletError> {
    let yb = validator
        .client_mut()
        .ok_or(gate::GateError::YellowbackAbsent)?;
    let est = estimate(wallet, yb, cents, lock_blocks, tip, source).await?;
    if let Some(c) = confirmed {
        check_confirmed(c, &est)?;
    }
    // YEW-PORT-6 item 2 / review YEW-REVIEW-4 M2: a flagged fee needs its own acknowledgement
    terms::require_ack(
        &est.fee_guard,
        confirmed.and_then(|c| c.accept_unusual_fee.as_deref()),
    )?;
    // beta2 D-3: a post-quantum source's carrier fee rests on the server's terms
    if let Some(g) = &est.carrier_fee_guard {
        terms::require_ack(
            g,
            confirmed.and_then(|c| c.accept_unusual_carrier_fee.as_deref()),
        )?;
    }
    let carrier_quote = confirmed
        .and_then(|c| c.carrier_fee_zat)
        .unwrap_or(est.carrier_fee_zat);
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
    // review YEW-REVIEW-6 M1: the refresh must not have raised the fee the user confirmed
    check_fee_not_raised(wallet, &est.fee_guard, "mint")?;
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
    Ok(Prepared {
        est,
        carrier_quote,
        bundle_bytes,
        seqs,
        owner_row,
        owner,
        fee_zat,
        payee,
        attest_payee_addr,
        attest_fee_zat,
    })
}

/// The start terms for a caller that passes the terms back (the app's `api::mint_start`;
/// review YEW-REVIEW-10 L2): `shown` must be the terms of `issued`, the estimate the core issued
/// for this amount, lock and source, field for field, the carrier fee included; the terms used
/// are `issued`'s, with `shown`'s acknowledgement tokens. A caller that raises (or lowers) the
/// carrier fee, or changes any other term, is refused before anything is fetched.
pub fn terms_from_issued(
    issued: &MintEstimate,
    shown: &ConfirmedTerms,
) -> Result<ConfirmedTerms, MintError> {
    check_confirmed(shown, issued)?;
    if let Some(f) = shown.carrier_fee_zat {
        if f != issued.carrier_fee_zat {
            return Err(MintError::TermsChanged {
                what: "carrier fee",
                was: issued.carrier_fee_zat.to_string(),
                now: f.to_string(),
            });
        }
    }
    Ok(issued.confirmed_terms(
        shown.accept_unusual_fee.clone(),
        shown.accept_unusual_carrier_fee.clone(),
    ))
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
        WalletError::Net(NetError::SendRejected { .. }) => true,
        // The browser's gRPC-web client has no transport error type (NetError::Transport is native).
        #[cfg(not(target_arch = "wasm32"))]
        WalletError::Net(NetError::Transport(_)) => true,
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
    accept_unusual_fee: Option<&str>,
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
        return super::claim::finish(wallet, client, validator, &m, branch_id, accept_unusual_fee)
            .await;
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
    // beta2 D-3: a carrier funded from another source staged the MINT's YEC in its vout[1]; the
    // MINT spends that output first (a plain YEC input), and more YEC only if the fee rose. It is
    // locked to this row (review YEW-REVIEW-8 L2), so it is looked up among all the outputs.
    let staged = staged_input(wallet, m.id, &wallet.store.utxos()?)?;
    let rest: Vec<Utxo> = spendable
        .iter()
        .filter(|u| Some(u.outpoint) != staged.as_ref().map(|s| s.outpoint))
        .cloned()
        .collect();
    let mut fee = mint_network_fee(wallet, &[]);
    let inputs = loop {
        let need = outputs + fee - CARRIER_VALUE;
        let sel = match &staged {
            Some(st) if st.value >= need => vec![st.clone()],
            Some(st) => {
                let mut v = vec![st.clone()];
                v.extend(coins::select_yec(&rest, need - st.value, true)?);
                v
            }
            None => coins::select_yec(&spendable, need, true)?,
        };
        let next = mint_network_fee(wallet, &sel);
        if next <= fee {
            break sel;
        }
        fee = next;
    };
    check_main_fee(wallet, m.id, fee, &inputs, accept_unusual_fee)?;
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
    // layer 3 on the YEC fee inputs (not the carrier at vin[last]): no input spent as plain YEC carries YED by its creating transaction
    gate::confirm_provenance(
        client,
        gate::Path::Mint,
        &raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        |op| wallet.store.utxo_txout(op).ok().flatten(),
    )
    .await?;
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

/// The staged funding output a mint row's carrier paid (beta2 D-3), when there is one, among
/// `outputs` (every output the store holds: the staged one is locked to the row). It must be
/// plain `YEC` now; the finish runs only once the carrier confirmed, and the staged output is in
/// the same transaction, so a staged output missing from the store was spent by something else
/// (review YEW-REVIEW-8 L2): that is said plainly, with the way out.
fn staged_input(wallet: &Wallet, id: i64, outputs: &[Utxo]) -> Result<Option<Utxo>, WalletError> {
    let Some(v) = wallet.store.meta(&stage_key(id))?.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let (t, n) = v
        .split_once(':')
        .ok_or_else(|| WalletError::Other(format!("staged funding {v}")))?;
    let op = OutPoint {
        txid: crate::tx::txid_from_hex(t).map_err(|e| WalletError::Other(e.to_string()))?,
        n: n.parse()
            .map_err(|_| WalletError::Other(format!("staged funding {v}")))?,
    };
    match outputs.iter().find(|u| u.outpoint == op) {
        Some(u) if u.class == UtxoClass::Yec => Ok(Some(u.clone())),
        Some(_) => Err(WalletError::Other(format!(
            "the mint's staged funding {}:{} is not spendable YEC yet; sync and try again",
            t, op.n
        ))),
        None => Err(WalletError::Other(format!(
            "the mint's staged funding {}:{} was spent by another transaction, so this MINT cannot be sent. Nothing was sent. The carrier stays locked until the mint's window closes; then sweep it from the mint's row to get it back.",
            t, op.n
        ))),
    }
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
    // layer 3 on the carrier, swept back to plain YEC
    gate::confirm_provenance(
        client,
        gate::Path::Sweep,
        &raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        |op| wallet.store.utxo_txout(op).ok().flatten(),
    )
    .await?;
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

    /// Beta2 D-3: the carrier funding from a post-quantum address. Only that address's
    /// confirmed PQ_OWNED coins are candidates (never its HELD or TOKEN rows, another
    /// post-quantum address's coin or a P2PKH coin); `vout` is the carrier, the staged MINT
    /// funding, the change to the source (D-4); the fee is at least the flat Yellowback fee;
    /// the gate's CarrierFromPq path admits the shape for the source only, with the stored
    /// scripts; too little at the source is the planner's refusal.
    #[test]
    fn pq_funding_plan_and_gate() {
        use crate::params::Network;
        use crate::store::Store;
        let seed = keys::seed_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        let mut w = Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        let mut t = w.pq_terms();
        t.falcon_active = true;
        w.set_pq_terms_for_test(t);
        let holders = w.own_falcon_holders().unwrap();
        let mut ids = holders.keys().copied();
        let id = ids.next().expect("a Falcon holder");
        let src = crate::pq::pqpkh_script(&id).unwrap();
        let other = crate::pq::pqpkh_script(&crate::pq::PqKeyId {
            scheme: id.scheme,
            hash: [0x31; 32],
        })
        .unwrap();
        let row = |i: u8, v: i64, script: &[u8], class: UtxoClass| Utxo {
            outpoint: OutPoint {
                txid: [i; 32],
                n: 0,
            },
            address: String::new(),
            script: script.to_vec(),
            value: v,
            height: 10,
            class,
            cents: 0,
        };
        let p2pkh = script::p2pkh_script(&[5; 20]);
        w.store
            .replace_utxos(&[
                row(1, 300_000_000, &src, UtxoClass::PqOwned),
                row(2, 900_000_000, &src, UtxoClass::Held),
                row(3, 800_000_000, &src, UtxoClass::Token),
                row(4, 700_000_000, &other, UtxoClass::PqOwned),
                row(5, 600_000_000, &p2pkh, UtxoClass::Yec),
            ])
            .unwrap();
        let carrier = script::p2sh_script(&[7; 20]);
        let stage = script::p2pkh_script(&[8; 20]);
        let f = plan_pq_funding(&w, &id, &carrier, 200_000_000, &stage, 100).unwrap();
        assert_eq!(f.available, 300_000_000);
        let p = &f.plan;
        assert_eq!(p.selected.len(), 1);
        assert_eq!(p.selected[0].outpoint.txid, [1; 32]);
        assert!(p.fee >= w.pq_terms().flat_zat);
        assert_eq!(p.transparent_outputs[0], (carrier.clone(), CARRIER_VALUE));
        assert_eq!(p.transparent_outputs[1], (stage.clone(), 200_000_000));
        assert_eq!(p.transparent_outputs.len(), 3);
        assert_eq!(p.transparent_outputs[2], (src.clone(), p.change));
        assert_eq!(300_000_000 - CARRIER_VALUE - 200_000_000 - p.fee, p.change);
        // the shape through the gate (signatures are not the local layer's business)
        let mut tx = Transaction::new_v4();
        tx.vin.push(TxIn::new(p.selected[0].outpoint));
        for (spk, v) in &p.transparent_outputs {
            tx.vout.push(TxOut {
                value: *v,
                script_pubkey: spk.clone(),
            });
        }
        let raw = tx.serialize().unwrap();
        let class = |op: &OutPoint| w.store.utxo_class(op).ok().flatten();
        let scripts = |op: &OutPoint| {
            w.store
                .utxo_txout(op)
                .ok()
                .flatten()
                .map(|o| o.script_pubkey)
        };
        let want = gate::CarrierOutputs {
            carrier_hash: [7; 20],
            staged_key: [8; 20],
        };
        let r = gate::check_with_scripts(gate::Path::CarrierFromPq(id, want), &raw, class, scripts);
        assert!(r.is_ok(), "{r:?}");
        // review YEW-REVIEW-8 M2, L1: another staged key or another carrier is refused
        for other in [
            gate::CarrierOutputs {
                staged_key: [9; 20],
                ..want
            },
            gate::CarrierOutputs {
                carrier_hash: [9; 20],
                ..want
            },
        ] {
            assert!(gate::check_with_scripts(
                gate::Path::CarrierFromPq(id, other),
                &raw,
                class,
                scripts
            )
            .is_err());
        }
        let not_src = crate::pq::PqKeyId {
            scheme: id.scheme,
            hash: [0x31; 32],
        };
        assert!(gate::check_with_scripts(
            gate::Path::CarrierFromPq(not_src, want),
            &raw,
            class,
            scripts
        )
        .is_err());
        // the ECC carrier path, bound to the same carrier and the staged key as its change
        let ecc = gate::EccCarrierOutputs {
            carrier_hash: want.carrier_hash,
            change_key: Some(want.staged_key),
        };
        assert!(gate::check(gate::Path::Carrier(ecc), &raw, class).is_err());
        // too little at the source
        let e = plan_pq_funding(&w, &id, &carrier, 400_000_000, &stage, 100)
            .err()
            .unwrap();
        assert!(
            e.to_string().starts_with("Insufficient transparent funds"),
            "{e}"
        );
        // the staged value is the MINT's need at one P2PKH input
        assert_eq!(
            staged_value(&w, 1_000, 20, 30),
            1_000 + TOKEN_VALUE + 50 + w.pq_terms().yed_network_fee(1, &[])
        );
    }

    /// Beta2 D-3: the MINT spends a row's staged funding output first; none recorded: the old
    /// selection; recorded but not spendable YEC (not synced yet): the finish waits.
    #[test]
    fn staged_input_is_the_rows_output() {
        use crate::params::Network;
        use crate::store::Store;
        let seed = keys::seed_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        let w = Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        let u = Utxo {
            outpoint: OutPoint {
                txid: [6; 32],
                n: 1,
            },
            address: String::new(),
            script: script::p2pkh_script(&[6; 20]),
            value: 5_000_000,
            height: 20,
            class: UtxoClass::Yec,
            cents: 0,
        };
        assert_eq!(staged_input(&w, 7, std::slice::from_ref(&u)).unwrap(), None);
        w.store
            .set_meta(&stage_key(7), &format!("{}:1", txid_hex(&[6; 32])))
            .unwrap();
        assert_eq!(
            staged_input(&w, 7, std::slice::from_ref(&u)).unwrap(),
            Some(u.clone())
        );
        // review YEW-REVIEW-8 L2: gone from the store after the carrier confirmed = spent
        // elsewhere, said plainly with the way out
        let e = staged_input(&w, 7, &[]).unwrap_err();
        assert!(
            e.to_string().contains("was spent by another transaction"),
            "{e}"
        );
        assert!(e.to_string().contains("sweep"), "{e}");
        let held = Utxo {
            class: UtxoClass::Held,
            ..u
        };
        let e = staged_input(&w, 7, &[held]).unwrap_err();
        assert!(e.to_string().contains("not spendable YEC yet"), "{e}");
    }

    /// Review YEW-REVIEW-8 M2, L2 and the restore rule: the staged key is recorded under the
    /// carrier key before anything is built and read back from that record only (a missing
    /// record, an external key or a key not of this wallet is refused); the staged output is
    /// locked to its row (not spendable, not in the balance) while the row is in a carrier state
    /// and released by the sync's rule once the row lapses or is gone, so a mint killed between
    /// its two transactions leaves the staged YEC as ordinary balance; and a wallet restored from
    /// the same seed has the staged key in its derivation and scan set, and classifies the staged
    /// output as plain YEC.
    /// WEB-REAL LOW-6: from the public balance the estimate prices the MINT on the coins the
    /// finish's selection takes, not on one input (the run: estimate 0.0001 YEC below the spend).
    #[test]
    fn ecc_mint_fee_counts_the_inputs_the_finish_selects() {
        use crate::params::Network;
        use crate::store::Store;
        let seed = keys::seed_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        let mut w = Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        w.ensure_gap().unwrap();
        // the run's terms: 100,000 zat/kB for Yellowback transactions (a $50 price)
        let mut t = w.pq_terms();
        t.yed_rate_zat_per_kb = 100_000;
        t.max_fee_zat = 10_000_000;
        w.set_pq_terms_for_test(t);
        let rows = w.addresses().unwrap();
        // three coins of 2.5 YEC: a 6 YEC MINT needs all three
        let utxos: Vec<Utxo> = (0..3)
            .map(|i| Utxo {
                outpoint: OutPoint {
                    txid: [i as u8 + 1; 32],
                    n: 0,
                },
                address: rows[i].address_s.clone(),
                script: script::p2pkh_script(&rows[i].hash160),
                value: 250_000_000,
                height: 10,
                class: UtxoClass::Yec,
                cents: 0,
            })
            .collect();
        w.store.replace_utxos(&utxos).unwrap();
        let outputs = 600_000_000;
        let fee = ecc_mint_fee(&w, outputs).unwrap();
        // what finish's loop ends on: the fee of the coins it selects for outputs + fee
        let sel = coins::select_yec(
            &w.spendable_utxos().unwrap(),
            outputs + fee - CARRIER_VALUE,
            true,
        )
        .unwrap();
        assert_eq!(sel.len(), 3);
        assert_eq!(fee, mint_network_fee(&w, &sel));
        assert!(
            fee > w.pq_terms().yed_network_fee(1, &[]),
            "more than one input's fee"
        );
        // one coin covers a small MINT: the one-input fee
        assert_eq!(
            ecc_mint_fee(&w, 100_000_000).unwrap(),
            mint_network_fee(&w, &sel[..1])
        );
        // more than the coins hold: no estimate from the selection
        assert_eq!(ecc_mint_fee(&w, 800_000_000), None);
    }

    #[test]
    fn ecc_carrier_change_recorded_and_bound() {
        use crate::params::Network;
        use crate::store::Store;
        // review YEW-REVIEW-9 L3: the change key is recorded before the build, read back as a
        // change key of the seed, and the gate binds vout[0] and vout[1] to it
        let seed = keys::seed_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        let w = Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            None,
        )
        .unwrap();
        w.ensure_gap().unwrap();
        let bundle = vec![0x61u8; 40];
        let (carrier_row, redeem) = carrier_key(&w, &bundle).unwrap();
        // no change: nothing to read, and a second output is refused
        let none = recorded_ecc_carrier_outputs(&w, &carrier_row.hash160, &bundle, false).unwrap();
        assert_eq!(none.change_key, None);
        assert_eq!(none.carrier_hash, keys::hash160(&redeem));
        let e = recorded_ecc_carrier_outputs(&w, &carrier_row.hash160, &bundle, true).unwrap_err();
        assert!(e.to_string().contains("not recorded"), "{e}");
        let change = record_carrier_change_key(&w, &carrier_row.hash160).unwrap();
        let want = recorded_ecc_carrier_outputs(&w, &carrier_row.hash160, &bundle, true).unwrap();
        assert_eq!(want.change_key, Some(change.hash160));
        // the transaction as carrier_step builds it
        let coin = OutPoint {
            txid: [0x62; 32],
            n: 0,
        };
        let class = |op: &OutPoint| (*op == coin).then_some(UtxoClass::Yec);
        let tx_with = |change_spk: Vec<u8>| {
            let mut tx = Transaction::new_v4();
            tx.vin.push(TxIn::new(coin));
            tx.vout.push(TxOut {
                value: CARRIER_VALUE,
                script_pubkey: script::p2sh_of(&redeem),
            });
            tx.vout.push(TxOut {
                value: 4_000_000,
                script_pubkey: change_spk,
            });
            tx.serialize().unwrap()
        };
        let ok = tx_with(script::p2pkh_script(&change.hash160));
        assert!(gate::check(gate::Path::Carrier(want), &ok, class).is_ok());
        assert!(gate::check(gate::Path::Carrier(none), &ok, class).is_err());
        // the change paid to an external key, or a foreign one: refused
        let ext = w.receive_address(false).unwrap();
        for spk in [
            script::p2pkh_script(&ext.hash160),
            script::p2pkh_script(&[0x63; 20]),
        ] {
            assert!(gate::check(gate::Path::Carrier(want), &tx_with(spk), class).is_err());
        }
        // a record naming an external key is refused before anything is built
        w.store
            .set_meta(
                &carrier_change_record_key(&carrier_row.hash160),
                &keys::hex(&ext.hash160),
            )
            .unwrap();
        let e = recorded_ecc_carrier_outputs(&w, &carrier_row.hash160, &bundle, true).unwrap_err();
        assert!(
            e.to_string().contains("change key of this wallet's seed"),
            "{e}"
        );
    }

    #[test]
    fn staged_key_record_lock_and_restore() {
        use crate::params::Network;
        use crate::store::Store;
        let seed = keys::seed_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        let open = || {
            Wallet::from_parts(
                Store::open_in_memory().unwrap(),
                Network::Regtest,
                &seed,
                None,
            )
            .unwrap()
        };
        let w = open();
        w.ensure_gap().unwrap();
        // as carrier_step does: the carrier key, then the staged key recorded under it
        let carrier = fresh_change(&w).unwrap();
        let bundle = vec![0x51u8; 40];
        let e = recorded_carrier_outputs(&w, &carrier.hash160, &bundle).unwrap_err();
        assert!(e.to_string().contains("not recorded"), "{e}");
        let stage = record_stage_key(&w, &carrier.hash160).unwrap();
        let want = recorded_carrier_outputs(&w, &carrier.hash160, &bundle).unwrap();
        assert_eq!(want.staged_key, stage.hash160);
        // review YEW-REVIEW-9 L1: the carrier hash is re-derived from the key and the bundle
        let pubkey = w.key_for_hash(&carrier.hash160).unwrap().unwrap().pubkey;
        let redeem = script::carrier_script(&pubkey, &bundle::bundle_hash(&bundle)).unwrap();
        assert_eq!(want.carrier_hash, keys::hash160(&redeem));
        // another bundle, another carrier key: other hashes, so a vout[0] built from either
        // fails the comparison
        let other_bundle = vec![0x52u8; 40];
        assert_ne!(
            derived_carrier_hash(&w, &carrier.hash160, &other_bundle).unwrap(),
            want.carrier_hash
        );
        let other_key = fresh_change(&w).unwrap();
        assert_ne!(
            derived_carrier_hash(&w, &other_key.hash160, &bundle).unwrap(),
            want.carrier_hash
        );
        // a carrier key that is not a change key of the seed, or not a key at all, is refused
        let ext = w.receive_address(false).unwrap();
        assert!(derived_carrier_hash(&w, &ext.hash160, &bundle).is_err());
        // (a random hash160: no key of this wallet has it)
        let stranger: [u8; 20] = rand::random();
        assert!(derived_carrier_hash(&w, &stranger, &bundle).is_err());
        // a record naming an external key, or a key this wallet does not have, is refused
        let ext = w.receive_address(false).unwrap();
        w.store
            .set_meta(
                &staging_record_key(&carrier.hash160),
                &keys::hex(&ext.hash160),
            )
            .unwrap();
        assert!(recorded_carrier_outputs(&w, &carrier.hash160, &bundle).is_err());
        w.store
            .set_meta(
                &staging_record_key(&carrier.hash160),
                &keys::hex(&[0x77; 20]),
            )
            .unwrap();
        assert!(recorded_carrier_outputs(&w, &carrier.hash160, &bundle).is_err());
        w.store
            .set_meta(
                &staging_record_key(&carrier.hash160),
                &keys::hex(&stage.hash160),
            )
            .unwrap();

        // the carrier funding was sent and its row recorded; then the app was killed
        let txid = [0x3c; 32];
        let staged_value = 7_000_000;
        let row = MintRow {
            id: 0,
            kind: MintKind::Mint,
            state: MintState::CarrierSent,
            created_height: 10,
            cents: 10_000,
            lock_blocks: 48,
            term_class: "A".into(),
            ref_height: 10,
            lock_height: 58,
            claim_height: 70,
            collateral_zat: 1_000,
            fee_zat: 0,
            payee: String::new(),
            attest_fee_zat: 0,
            attest_payee: String::new(),
            residual_zat: 0,
            bundle: Vec::new(),
            bundle_seqs: String::new(),
            carrier_hash160: carrier.hash160,
            owner_hash160: [0; 20],
            carrier_txid: txid,
            carrier_vout: 0,
            main_txid: [0; 32],
            sweep_txid: [0; 32],
            expiry_height: 40,
            vault_txid: [0; 32],
            owner: None,
            note: String::new(),
        };
        let id = w.store.insert_mint(&row).unwrap();
        record_staged_output(&w, id, &txid, 40).unwrap();
        let op = OutPoint { txid, n: 1 };
        let stage_spk = script::p2pkh_script(&stage.hash160);
        let own = |h: &[u8; 20]| w.store.addresses().unwrap().iter().any(|r| r.hash160 == *h);
        let (class, _) = coins::classify(&op, &stage_spk, staged_value, own, &Default::default());
        assert_eq!(class, UtxoClass::Yec);
        let utxo = Utxo {
            outpoint: op,
            address: String::new(),
            script: stage_spk.clone(),
            value: staged_value,
            height: 12,
            class,
            cents: 0,
        };
        let mut w = w;
        w.store.replace_utxos(std::slice::from_ref(&utxo)).unwrap();
        // locked to the row: not spendable, not in the balance; the finish still finds it
        assert!(w.spendable_utxos().unwrap().is_empty());
        assert_eq!(staged_for_mint_zat(&w).unwrap(), staged_value);
        assert_eq!(release_staged_locks(&w).unwrap(), 0);
        assert_eq!(
            staged_input(&w, id, &w.store.utxos().unwrap()).unwrap(),
            Some(utxo.clone())
        );
        // the row lapses (the window closed): the sync's rule releases the lock
        w.store
            .set_mint_state(id, MintState::Lapsed, None, None, "test")
            .unwrap();
        assert_eq!(release_staged_locks(&w).unwrap(), 1);
        assert_eq!(staged_for_mint_zat(&w).unwrap(), 0);
        assert_eq!(w.spendable_utxos().unwrap(), vec![utxo.clone()]);
        let (yec, _) = coins::yec_balances(&w.spendable_utxos().unwrap());
        assert_eq!(yec, staged_value);

        // restored from the seed: the staged key is in the derivation and scan set
        let r = open();
        r.ensure_gap().unwrap();
        let rows = r.store.addresses().unwrap();
        let found = rows
            .iter()
            .find(|a| a.hash160 == stage.hash160)
            .expect("the staged key is in a restored wallet's scan set");
        assert_eq!(found.hd_chain(), Some(keys::Chain::Change));
        assert!(found.index < crate::params::GAP_LIMIT);
        let own_r = |h: &[u8; 20]| rows.iter().any(|a| a.hash160 == *h);
        let (class, _) = coins::classify(&op, &stage_spk, staged_value, own_r, &Default::default());
        assert_eq!(class, UtxoClass::Yec);
    }

    fn sample_estimate() -> MintEstimate {
        MintEstimate {
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
            fee_guard: Default::default(),
            source: MintSource::Ecc,
            carrier_fee_zat: 1_000,
            carrier_fee_guard: None,
        }
    }

    /// Review YEW-REVIEW-10 L2: a start takes its terms from an estimate the core issued. An id
    /// the core did not issue (or no longer keeps) finds nothing; the terms built from an issued
    /// estimate carry its carrier fee as the cap; a caller that passes the terms back cannot
    /// raise the carrier fee above the issued one, or change any other term.
    #[test]
    fn a_start_takes_the_issued_estimate() {
        let est = sample_estimate();
        let mut book = IssuedEstimates::default();
        assert!(book.get("e1").is_none());
        let id = book.issue(&est);
        assert_eq!(book.get(&id), Some(&est));
        assert!(book.get("e999").is_none() && book.get("").is_none());
        let t = book
            .get(&id)
            .unwrap()
            .confirmed_terms(None, Some("ack".into()));
        assert_eq!(t.carrier_fee_zat, Some(est.carrier_fee_zat));
        assert_eq!(t.accept_unusual_carrier_fee.as_deref(), Some("ack"));
        assert!(check_confirmed(&t, &est).is_ok());
        // the app's route: matched by amount, lock and source; the latest wins
        assert!(book
            .latest_for(est.cents, est.lock_blocks, MintSource::Sapling)
            .is_none());
        assert!(book
            .latest_for(est.cents + 1, est.lock_blocks, MintSource::Ecc)
            .is_none());
        let later = MintEstimate {
            carrier_fee_zat: 2_000,
            ..est.clone()
        };
        book.issue(&later);
        assert_eq!(
            book.latest_for(est.cents, est.lock_blocks, MintSource::Ecc),
            Some(&later)
        );
        let shown = est.confirmed_terms(None, None);
        assert_eq!(terms_from_issued(&est, &shown).unwrap(), shown);
        for f in [est.carrier_fee_zat + 1, i64::MAX, est.carrier_fee_zat - 1] {
            let raised = ConfirmedTerms {
                carrier_fee_zat: Some(f),
                ..shown.clone()
            };
            assert!(matches!(
                terms_from_issued(&est, &raised),
                Err(MintError::TermsChanged {
                    what: "carrier fee",
                    ..
                })
            ));
        }
        // no carrier fee passed: the issued one is the cap
        let none = ConfirmedTerms {
            carrier_fee_zat: None,
            ..shown.clone()
        };
        assert_eq!(
            terms_from_issued(&est, &none).unwrap().carrier_fee_zat,
            Some(est.carrier_fee_zat)
        );
        let bent = ConfirmedTerms {
            collateral_zat: est.collateral_zat - 1_000,
            ..shown
        };
        assert!(terms_from_issued(&est, &bent).is_err());
        // only the last KEEP are kept
        for _ in 0..IssuedEstimates::KEEP {
            book.issue(&est);
        }
        assert!(book.get(&id).is_none());
        book.clear();
        assert!(book
            .latest_for(est.cents, est.lock_blocks, MintSource::Ecc)
            .is_none());
    }

    /// The second answer at `mint_start` may not differ from the confirmed estimate (audit G-2).
    #[test]
    fn changed_terms_are_refused() {
        let est = sample_estimate();
        let confirmed = ConfirmedTerms {
            collateral_zat: est.collateral_zat,
            fee_zat: est.fee_zat,
            payee: est.payee.clone(),
            term_class: est.term_class.clone(),
            accept_unusual_fee: None,
            carrier_fee_zat: None,
            accept_unusual_carrier_fee: None,
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

    // ---- review YEW-REVIEW-5 M2: the finish is bound to the main fee its start accepted

    mod fee_quote {
        use super::super::*;
        use crate::params::{self, Network};
        use crate::store::Store;

        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        /// The reference YEC price ($1) and the terms at a reported `price`, with the Yellowback
        /// rate the node's default target gives at `rate_price`.
        const REF: i64 = 1_000_000;

        fn terms(price: i64, rate_price: i64) -> terms::PqTerms {
            terms::PqTerms {
                yed_rate_zat_per_kb: params::attested_rate_zat_per_kb(
                    params::DEFAULT_YED_FEE_USD_PER_KB_MICRO,
                    rate_price,
                    params::ATTESTED_FEE_FLOOR_ZAT_PER_KB,
                ),
                price_micro_usd: price,
                ..terms::PqTerms::default()
            }
        }

        fn open(store: Store) -> Wallet {
            let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
            Wallet::from_parts(store, Network::Regtest, &seed, None).unwrap()
        }

        /// A wallet that has seen the reference price, on `t`.
        fn wallet_on(store: Store, t: terms::PqTerms) -> Wallet {
            let w = open(store);
            w.set_fee_reference_for_test(REF);
            w.set_pq_terms_for_test(t);
            w
        }

        fn inputs(n: usize) -> Vec<Utxo> {
            (0..n)
                .map(|i| Utxo {
                    outpoint: OutPoint {
                        txid: [0x21; 32],
                        n: i as u32,
                    },
                    address: String::new(),
                    script: crate::script::p2pkh_script(&[3; 20]),
                    value: 1_000_000,
                    height: 1,
                    class: UtxoClass::Yec,
                    cents: 0,
                })
                .collect()
        }

        fn ack_in(e: WalletError) -> String {
            let m = e.to_string();
            assert!(
                m.starts_with("unusual-fee: the fee changed after you confirmed"),
                "{m}"
            );
            let i = m.find("accept-unusual-fee:").expect("an acknowledgement");
            m[i..].split(';').next().unwrap().to_string()
        }

        /// An unflagged start: the finish pays up to twice the accepted fee at its real size
        /// without asking, also after a restart; above it (the server raised its terms between
        /// the carrier and the MINT) it is refused with a new acknowledgement, which then pays it
        /// and becomes the row's quote.
        #[test]
        fn unflagged_start_bounds_the_finish_across_a_restart() {
            let w = wallet_on(Store::open_in_memory().unwrap(), terms(REF, REF));
            let g = main_fee_guard(&w, "mint").unwrap();
            assert!(g.ack.is_none());
            note_fee_ack(&w, 7, &g).unwrap();
            // restart between the start and the finish
            let w = open(w.store);
            w.set_pq_terms_for_test(terms(REF, REF));
            let ins = inputs(2);
            let (size, _) = terms::yed_priced_size(ins.iter().map(|u| u.script.as_slice()));
            let q = read_fee_quote(&w, 7).unwrap().unwrap();
            assert!(!q.flagged);
            assert!(check_main_fee(&w, 7, q.at(size), &ins, None).is_ok());
            assert!(check_main_fee(&w, 7, q.at(size) * 2, &ins, None).is_ok());
            // the server tripled its rate (its price fell): refused, then acknowledged
            w.set_pq_terms_for_test(terms(REF, REF / 3));
            let fee = q.at(size) * 2 + 1;
            let ack = ack_in(check_main_fee(&w, 7, fee, &ins, None).unwrap_err());
            assert_eq!(ack, format!("accept-unusual-fee:{fee}:row:7"));
            assert!(check_main_fee(&w, 7, fee, &ins, Some("accept-unusual-fee:1:row:7")).is_err());
            assert!(check_main_fee(&w, 7, fee, &ins, Some(&ack)).is_ok());
            let q2 = read_fee_quote(&w, 7).unwrap().unwrap();
            assert_eq!((q2.fee, q2.size, q2.flagged), (fee, size, true));
            assert!(check_main_fee(&w, 7, fee, &ins, None).is_ok());
            assert!(check_main_fee(&w, 7, fee + 1, &ins, None).is_err());
        }

        /// A server whose answers to `GetYellowbackInfo` are served in order (each a reported
        /// YEC price, µUSD, with the node's default rates at it): each call feeds the next answer
        /// through `Wallet::note_server_params`, exactly as `vault_terms_now` does with the
        /// start's second call (review YEW-REVIEW-6 M1).
        struct RaisingServer {
            answers: Vec<i64>,
        }

        impl RaisingServer {
            fn info(&mut self, w: &Wallet) {
                let price = self.answers.remove(0);
                let mut fees = terms::fallback_fee_params(1_000);
                let n = fees.network.as_mut().unwrap();
                n.price_source = "tip".into();
                n.price_micro_usd = price;
                let floor = n.floor_zat_per_kb.max(n.fallback_zat_per_kb);
                let plain = params::attested_rate_zat_per_kb(
                    params::DEFAULT_PQ_FEE_USD_PER_KB_MICRO,
                    price,
                    floor,
                );
                n.plain.as_mut().unwrap().zat_per_kb = plain;
                n.yellowback.as_mut().unwrap().zat_per_kb = params::attested_rate_zat_per_kb(
                    params::DEFAULT_YED_FEE_USD_PER_KB_MICRO,
                    price,
                    floor,
                );
                let p = crate::net::rpc::YellowbackParams {
                    pq: Some(crate::net::rpc::YellowbackPqParams {
                        schemes: vec![1],
                        falcon_active: false,
                        falcon_height: -1,
                        fee_rate_zat_per_kb: plain,
                    }),
                    fees: Some(fees),
                    ..Default::default()
                };
                w.note_server_params(Some(&p)).unwrap();
            }
        }

        /// Review YEW-REVIEW-6 M1: the server raises its Yellowback rate on the second info call
        /// within one start. The start refuses before funding anything (the user starts again
        /// from a new preview), and the quote is never stored at the raised value: what is stored
        /// is exactly the fee and size the acknowledged guard priced, also across a restart.
        #[test]
        fn a_rate_raised_within_the_start_is_refused_and_never_stored() {
            for label in ["mint", "claim"] {
                let w = open(Store::open_in_memory().unwrap());
                w.set_fee_reference_for_test(REF);
                // first answer (the estimate / preview), then the start's refresh at a third of the
                // price: 3x the Yellowback rate
                let mut server = RaisingServer {
                    answers: vec![3 * REF, REF],
                };
                server.info(&w);
                let g = main_fee_guard(&w, label).unwrap();
                assert_eq!(g.size, crate::params::yed_estimated_size(1, &[]));
                assert_eq!(g.fee, w.pq_terms().yed_fee(g.size));
                assert!(check_fee_not_raised(&w, &g, label).is_ok());
                server.info(&w);
                let raised = w.pq_terms().yed_fee(g.size);
                assert!(raised > g.fee, "{raised} > {}", g.fee);
                let e = check_fee_not_raised(&w, &g, label).unwrap_err().to_string();
                assert!(e.starts_with("fee-terms-changed:"), "{e}");
                assert!(
                    e.contains(&format!("while the {label} was starting")),
                    "{e}"
                );
                // even if a row were recorded (the refresh after a carrier), the quote is the
                // acknowledged one, not the raised one
                note_fee_ack(&w, 11, &g).unwrap();
                let q = read_fee_quote(&w, 11).unwrap().unwrap();
                assert_eq!((q.fee, q.size, q.flagged), (g.fee, g.size, g.ack.is_some()));
                assert_ne!(q.fee, raised);
                // restart between the start and the finish: the acknowledged quote is kept, and a
                // finish at the raised rate is not paid without a new acknowledgement
                let w = open(w.store);
                w.set_fee_reference_for_test(REF);
                let q2 = read_fee_quote(&w, 11).unwrap().unwrap();
                assert_eq!(q2, q);
                let ins = inputs(1);
                let (size, _) = terms::yed_priced_size(ins.iter().map(|u| u.script.as_slice()));
                let mut later = RaisingServer { answers: vec![REF] };
                later.info(&w);
                let fee = w.pq_terms().yed_fee(size);
                assert!(fee > q.at(size) * 2, "{fee} > 2 x {}", q.at(size));
                assert!(check_main_fee(&w, 11, fee, &ins, None).is_err());
                assert!(check_main_fee(&w, 11, q.at(size), &ins, None).is_ok());
            }
        }

        /// A rate lowered within the start is fine: the stored quote stays the acknowledged fee.
        #[test]
        fn a_rate_lowered_within_the_start_keeps_the_acknowledged_quote() {
            let w = open(Store::open_in_memory().unwrap());
            w.set_fee_reference_for_test(REF);
            let mut server = RaisingServer {
                answers: vec![REF, 3 * REF],
            };
            server.info(&w);
            let g = main_fee_guard(&w, "mint").unwrap();
            server.info(&w);
            assert!(check_fee_not_raised(&w, &g, "mint").is_ok());
            note_fee_ack(&w, 12, &g).unwrap();
            let q = read_fee_quote(&w, 12).unwrap().unwrap();
            assert_eq!((q.fee, q.size), (g.fee, g.size));
        }

        /// A flagged, acknowledged start: the finish pays at most that fee scaled to its real
        /// size, also after a restart; one zat more is refused with a new acknowledgement (no
        /// longer "anything up to the limit").
        #[test]
        fn flagged_start_pays_at_most_what_was_acknowledged() {
            // the server reports a price below half the reference: flagged
            let w = wallet_on(Store::open_in_memory().unwrap(), terms(REF / 3, REF / 3));
            let g = main_fee_guard(&w, "claim").unwrap();
            assert!(g.ack.is_some());
            note_fee_ack(&w, 9, &g).unwrap();
            let w = open(w.store);
            w.set_pq_terms_for_test(terms(REF / 3, REF / 3));
            let ins = inputs(1);
            let (size, _) = terms::yed_priced_size(ins.iter().map(|u| u.script.as_slice()));
            let q = read_fee_quote(&w, 9).unwrap().unwrap();
            assert!(q.flagged);
            assert!(check_main_fee(&w, 9, q.at(size), &ins, None).is_ok());
            let more = q.at(size) + 1;
            let ack = ack_in(check_main_fee(&w, 9, more, &ins, None).unwrap_err());
            assert!(check_main_fee(&w, 9, more, &ins, Some(&ack)).is_ok());
            // the limit still holds whatever was acknowledged
            let limit = params::yed_fee_limit(size, 0);
            assert!(check_main_fee(
                &w,
                9,
                limit + 1,
                &ins,
                Some(&format!("accept-unusual-fee:{}:row:9", limit + 1))
            )
            .is_err());
        }

        /// A row started by an older build (no quote): only an unflagged fee goes without asking.
        #[test]
        fn a_row_without_a_quote_takes_only_an_unflagged_fee() {
            let w = wallet_on(Store::open_in_memory().unwrap(), terms(REF, REF));
            w.store.set_meta("fee_ack:3", "1").unwrap();
            let ins = inputs(1);
            let (size, conv) = terms::yed_priced_size(ins.iter().map(|u| u.script.as_slice()));
            let usual = w
                .guard_fee(terms::FeeKind::Yed, 0, size, conv, "x")
                .unwrap()
                .usual_zat
                .unwrap();
            assert!(check_main_fee(&w, 3, usual, &ins, None).is_ok());
            assert!(check_main_fee(&w, 3, usual * 2 + 1, &ins, None).is_err());
        }

        /// Scaling rounds up and never divides by zero.
        #[test]
        fn quote_scales_with_size() {
            let q = FeeQuote {
                fee: 1_000,
                size: 300,
                flagged: false,
            };
            assert_eq!(q.at(300), 1_000);
            assert_eq!(q.at(600), 2_000);
            assert_eq!(q.at(301), 1_004);
            let z = FeeQuote { size: 0, ..q };
            assert_eq!(z.at(2), 2_000);
        }
    }
}
