// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The owner-path vault spend (plan §4 rule 6; spec §3.5 "REDEEM, owner path" and "VOID
//! RELEASE"): `vin[0]` = the own vault — since the vault upgrade the bare V template, spent
//! with `<ownerSig> OP_2` (selector 2, U-23; the v2 form was `<ownerSig> OP_1 <vaultScript>`
//! under P2SH) — and `nSequence 0xFFFFFFFE`, `vin[1..]` = own YED inputs covering `mintedCents` (the floor-aware selector
//! with the BURN stage, H4), outputs = collateral to a fresh own key, the enforcement fee to
//! `payee(R, vaultOutpoint)`, optional YED change, the REDEEM payload; `nLockTime =
//! ownerHeight` (the V's owner branch height: since the in-term plan's D-IT-15 `refHeight + 1`
//! of the mint, so the owner redeems at any height), `nExpiryHeight = R + REF_WINDOW`, `R` = the
//! index tip. A redeem before `lockHeight` pays the early-redeem fee on top of FEE-1, on the same
//! payee output (IT-9; not due under FEE-0). A VOID vault is released with no burn, no fee and no
//! payload (L14, K3).
//!
//! Translation source (plan §3.6): `ycash-dd/src/yellowback/txbuilder.cpp` — `PlanVaultSpend`
//! `:57-133` (the slot order COLLATERAL, FEE, CHANGE, [PAYLOAD], ATTEST, RESIDUAL, PAYLOAD and
//! `collateralOut`), `SignVaultSpend` `:136-162`, `SelectYed` with `allowBurn` `:529-549`,
//! `BuildVaultSpend` `:573-716` (the transparent shape), `BuildRedeem` `:1286-1299`. The fee
//! comes from `GetFeePayee(R, collateralZat, outpointSelector)`.

use crate::coins::{self, Utxo, UtxoClass};
use crate::coinselect::{self, SelectStage};
use crate::gate::{self, Validator};

use crate::net::{CompactClient, Validation, YellowbackClient};
use crate::params::{
    CARRIER_VALUE, FEE_ZAT, MAX_INPUTS, MIN_OUTPUT_CENTS, REF_WINDOW, SEQUENCE_LOCKTIME,
    TOKEN_VALUE,
};
use crate::payload::{self, Assignment, Payload, FEE_VOUT_NONE};
use crate::script;
use crate::store::{HistoryRow, VaultRow};
use crate::tx::{txid_hex, OutPoint, Transaction, TxIn, TxOut};
use crate::wallet::{dollars, Wallet, WalletError};

use super::mint::{self, MintError};
use super::yed_transfer::TransferError;

/// The shape of a vault spend (`VaultSpendShape`, `txbuilder.h:170-194`), transparent
/// destination only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSpendShape {
    /// The vault outpoint.
    pub vault_out: OutPoint,
    /// The vault's `nValue`.
    pub vault_value: i64,
    /// `lockHeight` (owner path `nLockTime`).
    pub lock_height: u32,
    /// `claimHeight`.
    pub claim_height: u32,
    /// The V's `ownerHeight` (owner path `nLockTime`).
    pub owner_height: u32,
    /// The V's `appHeight` (claim path `nLockTime`).
    pub app_height: u32,
    /// Owner path or claim path.
    pub owner_path: bool,
    /// With the REDEEM payload (false for a VOID release).
    pub with_payload: bool,
    /// `R`.
    pub ref_height: u32,
    /// The YED inputs `(utxo, cents)`.
    pub yed_inputs: Vec<Utxo>,
    /// YED change in cents (0 = none).
    pub change_cents: u64,
    /// The change token's script.
    pub change_script: Vec<u8>,
    /// The fee payee's script (`None` under FEE-0).
    pub payee_script: Option<Vec<u8>>,
    /// The fee output's value: the enforcement fee, plus the early-redeem fee on an owner redeem
    /// before `lockHeight` (IT-9).
    pub fee_zat: i64,
    /// The attestor payee's script (`None` under AFEE-0).
    pub attest_script: Option<Vec<u8>>,
    /// The attestor fee.
    pub attest_fee_zat: i64,
    /// RED-5's residual to the owner (0 = none).
    pub residual_zat: i64,
    /// `PQPKH(owner)` for the residual (quantum spec F-3, §3.3).
    pub owner_script: Vec<u8>,
    /// `CARRIER_VALUE` when a carrier input is spent, else 0.
    pub carrier_value: i64,
    /// The collateral destination.
    pub collateral_script: Vec<u8>,
    /// The network fee taken from the collateral: `FEE_ZAT`, or the size-priced fee of an owner
    /// spend (quantum plan §4.5: `max(FEE_ZAT, pqfeerate × size)`, [`super::terms::PqTerms::fee`]).
    pub network_fee: i64,
}

/// `VaultSpendPlan` (`txbuilder.h:196-208`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSpendPlan {
    /// `nLockTime`.
    pub lock_time: u32,
    /// The inputs: the vault, then the YED inputs.
    pub vin: Vec<TxIn>,
    /// The outputs in slot order.
    pub vout: Vec<TxOut>,
    /// The collateral output value.
    pub collateral_out: i64,
    /// The cents burned (`yedIn − change`).
    pub burn_cents: i64,
    /// Index of the fee output (−1 = none).
    pub fee_vout: i32,
    /// Index of the change output (−1 = none).
    pub change_vout: i32,
    /// Index of the attestor fee output (−1 = none).
    pub attest_fee_vout: i32,
    /// Index of the residual output (−1 = none).
    pub residual_vout: i32,
    /// The REDEEM payload bytes (empty without payload).
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Collateral,
    Fee,
    Change,
    Attest,
    Residual,
    Payload,
}

/// `PlanVaultSpend` (`txbuilder.cpp:57-133`), the transparent-destination branch; `nLockTime` is
/// the V's branch height (`ownerPath ? ownerHeight : appHeight`, branch `upgrade/vault-in-term`).
pub fn plan_vault_spend(s: &VaultSpendShape) -> Result<VaultSpendPlan, WalletError> {
    let lock_time = if s.owner_path {
        s.owner_height
    } else {
        s.app_height
    };
    let mut vin = vec![TxIn {
        prevout: s.vault_out,
        script_sig: Vec::new(),
        sequence: SEQUENCE_LOCKTIME,
    }];
    let mut yed_value = 0i64;
    let mut yed_in = 0i64;
    for c in &s.yed_inputs {
        vin.push(TxIn::new(c.outpoint));
        yed_value += c.value;
        yed_in += c.cents as i64;
    }
    let change = s.with_payload && s.change_cents > 0;
    let fee = s.with_payload && s.payee_script.is_some();
    let attest = s.with_payload && s.attest_script.is_some();
    let residual = s.with_payload && s.residual_zat > 0;
    let collateral_out = s.vault_value + s.carrier_value + yed_value
        - s.network_fee
        - if fee { s.fee_zat } else { 0 }
        - if attest { s.attest_fee_zat } else { 0 }
        - if residual { s.residual_zat } else { 0 }
        - if change { TOKEN_VALUE } else { 0 };
    if collateral_out <= 0 {
        return Err(WalletError::Other(
            "vault-value-too-small: the vault does not cover the fees".into(),
        ));
    }
    let burn_cents = if s.with_payload {
        yed_in - s.change_cents as i64
    } else {
        yed_in
    };
    let mut plan = VaultSpendPlan {
        lock_time,
        vin,
        vout: Vec::new(),
        collateral_out,
        burn_cents,
        fee_vout: -1,
        change_vout: -1,
        attest_fee_vout: -1,
        residual_vout: -1,
        payload: Vec::new(),
    };
    let mut order = vec![Slot::Collateral];
    if !s.with_payload {
        plan.vout.push(TxOut {
            value: collateral_out,
            script_pubkey: s.collateral_script.clone(),
        });
        return Ok(plan);
    }
    if fee {
        order.push(Slot::Fee);
    }
    if change {
        order.push(Slot::Change);
    }
    if attest && !fee && !change {
        order.push(Slot::Payload); // AFEE-1 excludes vout[1]: the payload takes it
    }
    if attest {
        order.push(Slot::Attest);
    }
    if residual {
        order.push(Slot::Residual);
    }
    if !order.contains(&Slot::Payload) {
        order.push(Slot::Payload);
    }
    let mut assignments = Vec::new();
    for (i, slot) in order.iter().enumerate() {
        match slot {
            Slot::Fee => plan.fee_vout = i as i32,
            Slot::Change => {
                plan.change_vout = i as i32;
                assignments.push(Assignment {
                    vout: i as u8,
                    cents: s.change_cents as u32,
                });
            }
            Slot::Attest => plan.attest_fee_vout = i as i32,
            Slot::Residual => plan.residual_vout = i as i32,
            _ => {}
        }
    }
    let vout_or_none = |v: i32| if v < 0 { FEE_VOUT_NONE } else { v as u8 };
    plan.payload = payload::encode(&Payload::Redeem {
        ref_height: s.ref_height,
        fee_vout: vout_or_none(plan.fee_vout),
        attest_fee_vout: vout_or_none(plan.attest_fee_vout),
        assignments,
    })
    .ok_or_else(|| WalletError::Other("cannot encode the redeem payload".into()))?;
    for slot in order {
        plan.vout.push(match slot {
            Slot::Collateral => TxOut {
                value: collateral_out,
                script_pubkey: s.collateral_script.clone(),
            },
            Slot::Fee => TxOut {
                value: s.fee_zat,
                script_pubkey: s.payee_script.clone().unwrap_or_default(),
            },
            Slot::Change => TxOut {
                value: TOKEN_VALUE,
                script_pubkey: s.change_script.clone(),
            },
            Slot::Attest => TxOut {
                value: s.attest_fee_zat,
                script_pubkey: s.attest_script.clone().unwrap_or_default(),
            },
            Slot::Residual => TxOut {
                value: s.residual_zat,
                script_pubkey: s.owner_script.clone(),
            },
            Slot::Payload => TxOut {
                value: 0,
                script_pubkey: payload::payload_script(&plan.payload),
            },
        });
    }
    Ok(plan)
}

/// `SelectYed(…, allowBurn = true)` (`txbuilder.cpp:529-549`, H4): the YED inputs covering
/// `needed`, the change, the extra burn and the stage.
pub fn select_yed_burn(
    wallet: &Wallet,
    needed: u64,
) -> Result<(Vec<Utxo>, u64, u64, SelectStage), WalletError> {
    let coins = coins::ranked_tokens(&wallet.spendable_utxos()?);
    let cents: Vec<i64> = coins.iter().map(|c| c.cents as i64).collect();
    let have: u64 = coins.iter().map(|c| c.cents).sum();
    let s = coinselect::select_floor_aware(
        &cents,
        needed as i64,
        MIN_OUTPUT_CENTS as i64,
        MAX_INPUTS,
        true,
    );
    if !s.ok {
        if s.insufficient {
            return Err(TransferError::InsufficientYed { need: needed, have }.into());
        }
        if s.too_many_inputs {
            return Err(TransferError::TooManyInputs.into());
        }
        let alt = coinselect::nearest_workable(
            &cents,
            needed as i64,
            MIN_OUTPUT_CENTS as i64,
            MAX_INPUTS,
        );
        return Err(TransferError::ChangeFloor {
            needed,
            below: alt.below,
            above: alt.above,
        }
        .into());
    }
    let sel: Vec<Utxo> = s.inputs.iter().map(|&i| coins[i].clone()).collect();
    Ok((sel, s.change as u64, s.extra_burn as u64, s.stage))
}

/// `SignVaultSpend`'s owner signature (`txbuilder.cpp`, branch `q/yed`; quantum spec §1.5,
/// §3.6): ZIP-243 over the bare V script (it is the scriptCode) with the vault's `nValue` and
/// the next block's branch id (the Vault id after activation), signed by the vault's SLH-DSA
/// owner, then `<sig_1>…<sig_16> OP_16 <pk> OP_1 OP_2` at `vin[0]` (the V's OWNER selector, U-23;
/// 7,939 bytes). The wallet checks its own signature before it leaves (the node judges).
pub fn sign_owner_input(
    tx: &mut Transaction,
    owner: &crate::pq::PqKey,
    vault_script: &[u8],
    vault_value: i64,
    branch_id: u32,
) -> Result<(), WalletError> {
    let (digest, sig) = tx.pq_signature(0, owner, vault_script, vault_value, branch_id)?;
    if !crate::pq::verify(
        owner.scheme(),
        owner.public_key(),
        &sig[..sig.len() - 1],
        &digest,
    ) {
        return Err(WalletError::Other(
            "the owner's post-quantum signature does not verify".into(),
        ));
    }
    tx.vin[0].script_sig = crate::vault::vault_owner_script_sig(&sig, owner.public_key())
        .map_err(crate::tx::TxError::from)?;
    Ok(())
}

/// What the Vault screen shows before the owner confirms, and what is broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemBuild {
    /// The vault's mint txid (display form).
    pub vault_txid: String,
    /// `"redeem"` (ACTIVE) or `"release"` (VOID).
    pub kind: &'static str,
    /// The YED inputs burned.
    pub yed_inputs: Vec<Utxo>,
    /// The selector stage.
    pub stage: SelectStage,
    /// The cents burned (the debt plus any sub-dollar remainder).
    pub burn_cents: u64,
    /// The sub-dollar remainder burned on top of the debt (H4).
    pub extra_burn_cents: u64,
    /// YED change (cents).
    pub change_cents: u64,
    /// What the fee output pays (0 under FEE-0): the protocol fee plus the early-redeem fee.
    pub fee_zat: i64,
    /// The protocol fee in cents (FEE-1′ of the debt, rpcversion 8), paid at the vault's `pMint`.
    pub protocol_fee_cents: i64,
    /// The vault's stored mint price, µUSD per YEC: the price both fees are struck at.
    pub p_mint: i64,
    /// The early-redeem fee within `fee_zat` (IT-9′): `earlyRedeemFeeBps[class]` of the debt at
    /// `pMint` when the redeem confirms before `lockHeight` (judged at `R + 1`, the node builder's
    /// reading), 0 at or after it and under FEE-0.
    pub early_redeem_fee_zat: i64,
    /// [`RedeemBuild::early_redeem_fee_zat`] in cents (the debt's share in dollars; 0 when none).
    pub early_redeem_fee_cents: i64,
    /// The vault's `lockHeight`: a redeem confirming before it pays the early-redeem fee.
    pub lock_height: u32,
    /// The fee payee (`s…`), empty under FEE-0.
    pub payee: String,
    /// The collateral returned, zat.
    pub collateral_out: i64,
    /// The address it goes to (`s…`, an own fresh key).
    pub collateral_address: String,
    /// `R`.
    pub ref_height: u32,
    /// `nLockTime` (= the V's `ownerHeight`).
    pub lock_time: u32,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The network fee taken from the collateral: the Yellowback size fee (dollars per KB at the
    /// attested price, [`owner_spend_network_fee`]).
    pub network_fee_zat: i64,
    /// The signed transaction.
    pub raw: Vec<u8>,
    /// Its txid.
    pub txid: [u8; 32],
}

/// The size an owner-path vault spend will have once signed, at most: `vin[0]` the owner's
/// chunked post-quantum scriptSig plus the selector (exact: 7,939 bytes for SLH-DSA), every other
/// input a P2PKH scriptSig at its largest ([`crate::tx::MAX_P2PKH_SCRIPT_SIG`]).
pub fn owner_spend_size_bound(tx: &Transaction, owner_scheme: u8) -> Result<usize, WalletError> {
    let owner = crate::pq::pq_sig_pushes_size(owner_scheme)
        .ok_or_else(|| WalletError::Other("the vault owner's scheme is not registered".into()))?
        + 1;
    let mut sizes = vec![crate::tx::MAX_P2PKH_SCRIPT_SIG; tx.vin.len()];
    sizes[0] = owner;
    Ok(tx.size_with_script_sigs(&sizes)?)
}

/// [`owner_spend_size_bound`] with the YED inputs at `vin[1..]` sized by their scripts: a Falcon
/// holder input's scriptSig is exact (1,577 bytes), a P2PKH one bounded.
pub fn owner_spend_size_bound_with(
    tx: &Transaction,
    owner_scheme: u8,
    inputs_from_1: &[Utxo],
) -> Result<usize, WalletError> {
    let owner = crate::pq::pq_sig_pushes_size(owner_scheme)
        .ok_or_else(|| WalletError::Other("the vault owner's scheme is not registered".into()))?
        + 1;
    let mut sizes = vec![crate::tx::MAX_P2PKH_SCRIPT_SIG; tx.vin.len()];
    sizes[0] = owner;
    for (i, u) in inputs_from_1.iter().enumerate() {
        if let Some(s) = sizes.get_mut(1 + i) {
            *s = crate::tx::script_sig_size_bound(&u.script);
        }
    }
    Ok(tx.size_with_script_sigs(&sizes)?)
}

/// The V script of a stored vault under the vault upgrade's terms (U-23), with its own branch
/// heights (in-term IT-1: `refHeight + 1` for a mint since the rule, `lockHeight` / `lockHeight +
/// GRACE` before it), as the last refresh checked them against `GetVault.scriptPubKey`.
pub fn vault_script_of(
    v: &VaultRow,
    vt: &super::terms::VaultTerms,
) -> Result<Vec<u8>, WalletError> {
    if v.owner_height == 0 || v.app_height == 0 {
        return Err(WalletError::Other(format!(
            "vault-not-synced: vault {} has no checked branch heights yet; sync and try again",
            txid_hex(&v.txid)
        )));
    }
    if v.claim_height != v.lock_height + vt.grace {
        return Err(MintError::Inconsistent {
            what: format!(
                "vault {}: claimHeight {} is not lockHeight {} + GRACE",
                txid_hex(&v.txid),
                v.claim_height,
                v.lock_height
            ),
        }
        .into());
    }
    let owner = Some(v.owner).filter(|o| o.is_known()).ok_or_else(|| {
        WalletError::Other("vault-not-owned: the vault's owner is not post-quantum".into())
    })?;
    Ok(vt.vault_script_at(&owner, v.owner_height, v.app_height)?)
}

/// IT-9′'s early-redeem fee of an owner redeem of `v` built at index height `r` (`EarlyRedeemFeeAt`
/// / `BuildVaultSpend`, `ycash-dd` branch `q/fees`: `earlyRedeemFeeBps[class]` of the **debt** at the
/// vault's stored `pMint`, rpcversion 8): the spend confirms at `r + 1`
/// at the earliest, so the fee is due when `r + 1 < lockHeight`; 0 at or past it, for a vault that
/// is not ACTIVE, under FEE-0 (`payee_known` false: RED-3 then charges neither fee), and for a
/// class this network does not know.
pub fn early_redeem_fee_for(
    network: crate::params::Network,
    v: &VaultRow,
    r: u32,
    payee_known: bool,
) -> i64 {
    if v.status != "ACTIVE" || !payee_known || r as u64 + 1 >= v.lock_height as u64 {
        return 0;
    }
    network
        .term_classes()
        .iter()
        .find(|c| c.letter == v.term_class && c.enabled())
        .map(|c| {
            crate::params::early_redeem_fee_zat(v.minted_cents, c.early_redeem_fee_bps, v.p_mint)
        })
        .unwrap_or(0)
}

/// [`early_redeem_fee_for`] in dollars (`yed_estimateredeem.earlyRedeemFeeCents`): what YEW shows
/// beside the debt, 0 when no early fee is due.
pub fn early_redeem_fee_cents_for(
    network: crate::params::Network,
    v: &VaultRow,
    r: u32,
    payee_known: bool,
) -> i64 {
    if early_redeem_fee_for(network, v, r, payee_known) == 0 {
        return 0;
    }
    network
        .term_classes()
        .iter()
        .find(|c| c.letter == v.term_class)
        .map(|c| crate::params::early_redeem_fee_cents(v.minted_cents, c.early_redeem_fee_bps))
        .unwrap_or(0)
}

/// The network fee of an owner-path vault spend (`BuildVaultSpend`, review B L-1, D-Q-23 (b)): the
/// Yellowback size fee at the node's estimated size (the owner's post-quantum input, each Falcon
/// holder input at its spend size, every other input 150 bytes); clamped to the floor rate
/// (`YedFloorSizeFee`) when it would take everything the vault has left after the protocol fees.
pub fn owner_spend_network_fee(
    t: &super::terms::PqTerms,
    owner_scheme: u8,
    yed_inputs: &[Utxo],
    spendable_before_fee: i64,
) -> i64 {
    let mut pq = vec![owner_scheme];
    let mut other = 0;
    for u in yed_inputs {
        match crate::pq::pqpkh_of(&u.script) {
            Some(id) => pq.push(id.scheme),
            None => other += 1,
        }
    }
    let size = crate::params::yed_estimated_size(other, &pq);
    // audit 04/N-1: the 6.20.0 ZIP-317 conventional fee is a floor of both the priced fee and
    // the small-vault clamp, as on the node (`YedNetworkFee`, `BuildVaultSpend`).
    let conventional = crate::params::yed_conventional_fee_estimate(other, &pq);
    let fee = t.yed_fee(size).max(conventional);
    if fee >= spendable_before_fee {
        t.yed_floor_fee(size).max(conventional)
    } else {
        fee
    }
}

/// The transaction a vault's outpoint is locked `spent-by` (display hex), if any: a redeem or
/// release this wallet broadcast that has not confirmed or expired yet, or a spend the server
/// reported pending (`YedVault.spendPending`, recorded by the sync). Cf. DigiByte v9.26.7
/// 00136af6: a pending redemption is told apart before any coin is selected.
pub fn pending_spend(
    wallet: &Wallet,
    v: &crate::store::VaultRow,
) -> Result<Option<String>, WalletError> {
    let op = OutPoint {
        txid: v.txid,
        n: v.vout,
    };
    Ok(wallet
        .store
        .locks()?
        .into_iter()
        .find(|l| l.outpoint == op && l.reason.starts_with(SPENT_BY))
        .map(|l| l.reason[SPENT_BY.len()..].to_string()))
}

/// The lock reason prefix of an outpoint a broadcast transaction spends.
pub const SPENT_BY: &str = "spent-by:";

/// The `vault-spend-pending` refusal.
pub fn spend_pending_error(spender: &str) -> WalletError {
    WalletError::Other(format!(
        "vault-spend-pending: a transaction spending this vault ({spender}) is waiting to confirm; wait until it confirms or expires"
    ))
}

/// Refuse a vault the server reports a pending spend of (`YedVault.spendPending`; a node that
/// predates the field answers false): a claim of it would conflict in the mempool.
pub fn check_no_pending_spend(v: &crate::net::rpc::YedVault) -> Result<(), WalletError> {
    if v.spend_pending {
        let spender = if v.spend_txid.is_empty() {
            "txid unknown"
        } else {
            v.spend_txid.as_str()
        };
        return Err(spend_pending_error(spender));
    }
    Ok(())
}

/// `BuildRedeem` (`txbuilder.cpp:1286-1299`): the owner-path spend of an own open vault at any
/// height from the V's `ownerHeight` (the block after the mint since D-IT-15; before `lockHeight`
/// with the early-redeem fee). `R` is the relay node's index tip (`GetYellowbackInfo.height`). This is
/// the **preview** (audit G-2): nothing is broadcast until [`broadcast`] is called with it,
/// so the fee, the payee and the collateral returned are on screen before the slider.
pub async fn build_redeem(
    wallet: &Wallet,
    yb: &mut YellowbackClient,
    vault_txid: &[u8; 32],
    tip: u64,
    branch_id: u32,
) -> Result<RedeemBuild, WalletError> {
    let v = wallet
        .store
        .vault(vault_txid)?
        .ok_or_else(|| WalletError::Other("vault-not-owned: not a vault of this wallet".into()))?;
    if !v.is_open() {
        return Err(WalletError::Other(format!(
            "vault-not-active: the vault is {}",
            v.status
        )));
    }
    if let Some(spender) = pending_spend(wallet, &v)? {
        return Err(spend_pending_error(&spender));
    }
    let info = yb.info().await?;
    let r = info.height as u32;
    if v.owner_height == 0 {
        return Err(WalletError::Other(
            "vault-not-synced: the vault's branch heights are not checked yet; sync and try again"
                .into(),
        ));
    }
    if (r as u64) < v.owner_height as u64 || tip < v.owner_height as u64 {
        return Err(WalletError::Other(format!(
            "vault-locked: the vault is locked until height {} (tip {tip}, index {r})",
            v.owner_height
        )));
    }
    let expiry_height = r + REF_WINDOW;
    if !mint::window_open(tip, expiry_height) {
        return Err(WalletError::Other(
            "expiring-too-soon: the index is too far behind the chain".into(),
        ));
    }
    let owner = wallet
        .pq_key_for_owner(&v.owner, &v.owner_hash160)?
        .ok_or_else(|| WalletError::Other("vault-not-owned: owner key missing".into()))?;
    let vt = mint::vault_terms_now(wallet, yb).await?;
    let vault_script = vault_script_of(&v, &vt)?;
    let vault_out = OutPoint {
        txid: v.txid,
        n: v.vout,
    };
    let dest = mint::fresh_external(wallet)?;
    let active = v.status == "ACTIVE";
    let (yed_inputs, change_cents, extra_burn, stage, fee_zat, payee) = if active {
        let (sel, change, extra, stage) = select_yed_burn(wallet, v.minted_cents)?;
        let selector = crate::bundle::outpoint_selector(&v.txid, v.vout);
        // FEE-1′ locally (audit G-2; rpcversion 8): the debt's dollars at the vault's stored pMint.
        let payee = mint::fee_payee(yb, r, &selector).await?;
        if v.p_mint <= 0 {
            return Err(WalletError::Other(
                "vault-not-synced: the vault's mint price is not known yet; sync and try again"
                    .into(),
            ));
        }
        let fee_zat = super::terms::protocol_fee(v.minted_cents, v.p_mint, &payee)?;
        (sel, change, extra, stage, fee_zat, payee)
    } else {
        (Vec::new(), 0, 0, SelectStage::None, 0, String::new())
    };
    // IT-9′ locally: the early-redeem fee rides on the FEE-1′ payee's output (RED-3′ checks that
    // output against FEE-1′ + the early fee; AFEE-1′ gives the owner path no attestor share).
    let early_redeem_fee_zat = early_redeem_fee_for(wallet.network, &v, r, !payee.is_empty());
    // TOK-PQ (quantum spec F-7, after the Falcon height): YED change goes to a Falcon holder.
    let falcon = wallet.pq_terms().falcon_at(r as u64 + 1);
    let change_row = if change_cents > 0 {
        Some(mint::fresh_external(wallet)?)
    } else {
        None
    };
    let mut shape = VaultSpendShape {
        vault_out,
        vault_value: v.collateral_zat,
        lock_height: v.lock_height,
        claim_height: v.claim_height,
        owner_height: v.owner_height,
        app_height: v.app_height,
        owner_path: true,
        with_payload: active,
        ref_height: r,
        yed_inputs: yed_inputs.clone(),
        change_cents,
        change_script: match change_row.as_ref() {
            Some(c) => wallet.yed_holder_script(c, falcon)?,
            None => Vec::new(),
        },
        payee_script: if payee.is_empty() {
            None
        } else {
            Some(mint::p2pkh_of_address(wallet, &payee)?)
        },
        fee_zat: if payee.is_empty() {
            0
        } else {
            fee_zat + early_redeem_fee_zat
        },
        attest_script: None,
        attest_fee_zat: 0,
        residual_zat: 0,
        owner_script: crate::pq::pqpkh_script(&owner.id()).ok_or_else(|| {
            WalletError::Other("the vault owner's scheme is not registered".into())
        })?,
        carrier_value: 0,
        collateral_script: script::p2pkh_script(&dest.hash160),
        network_fee: FEE_ZAT,
    };
    // The size-priced fee (quantum plan §4.5; client survey C-5), from the exact owner scriptSig
    // and a bound on each ECDSA one, before anything is signed (an SLH-DSA signature takes ~0.5 s).
    let unsigned = |shape: &VaultSpendShape| -> Result<(VaultSpendPlan, Transaction), WalletError> {
        let plan = plan_vault_spend(shape)?;
        let mut tx = Transaction::new_v4();
        tx.lock_time = plan.lock_time;
        tx.expiry_height = expiry_height;
        tx.vin = plan.vin.clone();
        tx.vout = plan.vout.clone();
        Ok((plan, tx))
    };
    let yed_value: i64 = yed_inputs.iter().map(|u| u.value).sum();
    shape.network_fee = owner_spend_network_fee(
        &wallet.pq_terms(),
        owner.scheme(),
        &yed_inputs,
        v.collateral_zat + yed_value
            - shape.fee_zat
            - if change_cents > 0 { TOKEN_VALUE } else { 0 },
    );
    let (plan, mut tx) = unsigned(&shape)?;
    sign_owner_input(&mut tx, &owner, &vault_script, v.collateral_zat, branch_id)?;
    mint::sign_p2pkh_inputs(wallet, &mut tx, &yed_inputs, 1, branch_id)?;
    tx.check_script_sig_sizes()?;
    let raw = tx.serialize()?;
    let txid = tx.txid()?;
    let path = if active {
        gate::Path::Redeem
    } else {
        gate::Path::Release
    };
    gate::check(path, &raw, |op| wallet.store.utxo_class(op).ok().flatten())?;
    let _ = CARRIER_VALUE;
    Ok(RedeemBuild {
        network_fee_zat: shape.network_fee,
        vault_txid: txid_hex(&v.txid),
        kind: if active { "redeem" } else { "release" },
        yed_inputs,
        stage,
        burn_cents: plan.burn_cents.max(0) as u64,
        extra_burn_cents: extra_burn,
        change_cents,
        fee_zat: shape.fee_zat,
        protocol_fee_cents: if active {
            crate::params::protocol_fee_cents(v.minted_cents)
        } else {
            0
        },
        p_mint: v.p_mint,
        early_redeem_fee_zat,
        early_redeem_fee_cents: early_redeem_fee_cents_for(
            wallet.network,
            &v,
            r,
            !payee.is_empty(),
        ),
        lock_height: v.lock_height,
        payee,
        collateral_out: plan.collateral_out,
        collateral_address: dest.address_s,
        ref_height: r,
        lock_time: plan.lock_time,
        expiry_height,
        raw,
        txid,
    })
}

/// `confirm`: both gate layers, broadcast, locks (the vault and the tokens), `PreLock` of the
/// change, the pending record and history row.
pub async fn broadcast(
    wallet: &Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    p: &RedeemBuild,
) -> Result<(String, Validation), WalletError> {
    let path = if p.kind == "redeem" {
        gate::Path::Redeem
    } else {
        gate::Path::Release
    };
    let (tx, validation) = gate::confirm_burning(
        validator,
        path,
        &p.raw,
        |op| wallet.store.utxo_class(op).ok().flatten(),
        p.burn_cents as i64,
    )
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    let vault_txid = crate::tx::txid_from_hex(&p.vault_txid).map_err(WalletError::Other)?;
    let mut locked = p.yed_inputs.clone();
    locked.push(Utxo {
        outpoint: OutPoint {
            txid: vault_txid,
            n: 0,
        },
        address: String::new(),
        script: Vec::new(),
        value: 0,
        height: 0,
        class: UtxoClass::Vault,
        cents: 0,
    });
    let persist = || -> Result<(), WalletError> {
        for u in &p.yed_inputs {
            wallet
                .store
                .insert_spent_token(&p.txid, &u.outpoint, u.cents)?;
        }
        let own = wallet.own_hashes()?;
        let own_falcon = wallet.own_falcon_holders_for(&tx)?;
        for (n, cents) in
            coins::pre_lock_scripts(&tx, |s| Wallet::is_own_holder_script(s, &own, &own_falcon))
        {
            let script_pubkey = tx.vout[n as usize].script_pubkey.clone();
            wallet.store.upsert_utxo(&Utxo {
                outpoint: OutPoint { txid: p.txid, n },
                address: super::yed_transfer::holder_address(wallet.network, &script_pubkey),
                script: script_pubkey,
                value: TOKEN_VALUE,
                height: 0,
                class: UtxoClass::PendingToken,
                cents,
            })?;
        }
        for (n, o) in tx.vout.iter().enumerate() {
            if let Some(h) = script::p2pkh_hash(&o.script_pubkey) {
                if own.contains(&h) {
                    wallet.store.insert_own_output(
                        &OutPoint {
                            txid: p.txid,
                            n: n as u32,
                        },
                        o.value,
                        &h,
                    )?;
                }
            }
        }
        let yed_spent: i64 = p.yed_inputs.iter().map(|u| u.value).sum();
        wallet.store.upsert_history(&HistoryRow {
            txid: p.txid,
            height: 0,
            yec_delta: p.collateral_out + if p.change_cents > 0 { TOKEN_VALUE } else { 0 }
                - yed_spent,
            has_payload: p.kind == "redeem",
            pending: true,
            shielded: false,
            yed_delta: -(p.burn_cents as i64),
            kind: p.kind.into(),
            verdict: String::new(),
            label: if p.kind == "redeem" {
                format!("redeeming, burning {}", dollars(p.burn_cents as i64))
            } else {
                "releasing VOID vault".into()
            },
            labelled: p.kind != "redeem",
        })?;
        Ok(())
    };
    mint::send_recorded(
        wallet,
        &p.txid,
        &p.raw,
        p.expiry_height,
        &locked,
        persist,
        || Ok(()),
        mint::send(client, &p.raw, &p.txid),
    )
    .await?;
    Ok((txid_hex(&p.txid), validation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(
        with_payload: bool,
        fee: bool,
        change: u64,
        attest: bool,
        residual: i64,
    ) -> VaultSpendShape {
        let mut yed = Vec::new();
        for i in 0..2u8 {
            yed.push(Utxo {
                outpoint: OutPoint {
                    txid: [i + 1; 32],
                    n: 0,
                },
                address: String::new(),
                script: script::p2pkh_script(&[i; 20]),
                value: TOKEN_VALUE,
                height: 1,
                class: UtxoClass::Token,
                cents: 6_000,
            });
        }
        VaultSpendShape {
            vault_out: OutPoint {
                txid: [9; 32],
                n: 0,
            },
            vault_value: 1_000_000_000,
            lock_height: 431,
            claim_height: 455,
            owner_height: 431,
            app_height: 455,
            owner_path: true,
            with_payload,
            ref_height: 431,
            yed_inputs: yed,
            change_cents: change,
            change_script: script::p2pkh_script(&[5; 20]),
            payee_script: fee.then(|| script::p2pkh_script(&[6; 20])),
            fee_zat: 50_000_000,
            attest_script: attest.then(|| script::p2pkh_script(&[7; 20])),
            attest_fee_zat: 12_500_000,
            residual_zat: residual,
            owner_script: crate::pq::pqpkh_script(&crate::pq::PqKeyId {
                scheme: 1,
                hash: [8; 32],
            })
            .unwrap(),
            carrier_value: 0,
            collateral_script: script::p2pkh_script(&[4; 20]),
            network_fee: FEE_ZAT,
        }
    }

    #[test]
    fn plan_reproduces_the_node_slot_order() {
        // The node's redeem template: collateral, fee, payload; two tokens in, no change.
        let p = plan_vault_spend(&shape(true, true, 0, false, 0)).unwrap();
        assert_eq!(p.lock_time, 431);
        assert_eq!(p.vin.len(), 3);
        assert_eq!(p.vin[0].sequence, SEQUENCE_LOCKTIME);
        assert_eq!(p.vout.len(), 3);
        assert_eq!(
            p.collateral_out,
            1_000_000_000 + 20_000 - 1_000 - 50_000_000
        );
        assert_eq!((p.fee_vout, p.change_vout, p.attest_fee_vout), (1, -1, -1));
        assert_eq!(p.burn_cents, 12_000);
        assert_eq!(
            payload::decode(&p.payload).unwrap(),
            Payload::Redeem {
                ref_height: 431,
                fee_vout: 1,
                attest_fee_vout: 0xff,
                assignments: vec![]
            }
        );
        // With change and an attestor fee (a claim shape): collateral, fee, change, attest, payload.
        let p = plan_vault_spend(&shape(true, true, 2_000, true, 0)).unwrap();
        assert_eq!(
            (
                p.fee_vout,
                p.change_vout,
                p.attest_fee_vout,
                p.residual_vout
            ),
            (1, 2, 3, -1)
        );
        assert_eq!(p.vout.len(), 5);
        assert_eq!(p.vout[2].value, TOKEN_VALUE);
        assert_eq!(p.burn_cents, 10_000);
        assert_eq!(
            payload::decode(&p.payload).unwrap().assignments(),
            &[Assignment {
                vout: 2,
                cents: 2_000
            }]
        );
        // Attest without fee or change: the payload takes vout[1] (AFEE-1 excludes vout[1]).
        let p = plan_vault_spend(&shape(true, false, 0, true, 200_000)).unwrap();
        assert!(script::is_op_return(&p.vout[1].script_pubkey));
        assert_eq!((p.attest_fee_vout, p.residual_vout), (2, 3));
        assert_eq!(p.vout[3].value, 200_000);
        // No payload (release): one output, no burn accounting.
        let p = plan_vault_spend(&shape(false, true, 0, false, 0)).unwrap();
        assert_eq!(p.vout.len(), 1);
        assert!(p.payload.is_empty());
        // A vault too small for the fees is refused.
        let mut tiny = shape(true, true, 0, false, 0);
        tiny.vault_value = 1_000;
        assert!(plan_vault_spend(&tiny).is_err());
    }

    #[test]
    fn in_term_owner_redeem_locks_at_owner_height_and_pays_the_early_fee() {
        // In-term IT-1 / D-IT-15: a V minted at R = 400 has ownerHeight = appHeight = 401; the
        // owner path's nLockTime is ownerHeight (the CLTV of the OWNER branch), the claim's appHeight.
        let mut s = shape(true, true, 0, false, 0);
        s.owner_height = 401;
        s.app_height = 401;
        let early = 50_000_000; // IT-9′'s figure (of the debt at pMint) is early_redeem_fee_for's
        s.fee_zat = 50_000_000 + early;
        let p = plan_vault_spend(&s).unwrap();
        assert_eq!(p.lock_time, 401);
        // IT-9: the early-redeem fee rides on the FEE-1 payee's output; the collateral pays it.
        assert_eq!(p.vout[p.fee_vout as usize].value, 50_000_000 + 50_000_000);
        assert_eq!(
            p.collateral_out,
            1_000_000_000 + 20_000 - 1_000 - 100_000_000
        );
        s.owner_path = false;
        assert_eq!(plan_vault_spend(&s).unwrap().lock_time, 401);
    }

    #[test]
    fn early_redeem_fee_follows_the_node_builder() {
        let v = VaultRow {
            txid: [1; 32],
            vout: 0,
            status: "ACTIVE".into(),
            owner_hash160: [2; 20],
            owner: crate::pq::PqKeyId {
                scheme: 1,
                hash: [2; 32],
            },
            term_class: "B".into(),
            lock_height: 600,
            claim_height: 624,
            collateral_zat: 400_000_000_000,
            minted_cents: 10_000,
            mint_height: 498,
            claimable: false,
            underwater_at: 0,
            sweep_before: 0,
            close_height: 0,
            closing_txid: String::new(),
            void_reason: String::new(),
            updated_height: 500,
            owner_height: 498,
            app_height: 498,
            p_mint: 50_000,
            cancel: Default::default(),
        };
        let r = crate::params::Network::Regtest;
        // IT-9′ (rpcversion 8): class B is 2.5 % of the $100 debt = $2.50, at the vault's pMint
        // $0.05 = 50 YEC, while R + 1 < lockHeight — whatever the collateral.
        assert_eq!(early_redeem_fee_for(r, &v, 500, true), 5_000_000_000);
        assert_eq!(early_redeem_fee_cents_for(r, &v, 500, true), 250);
        assert_eq!(early_redeem_fee_for(r, &v, 598, true), 5_000_000_000);
        let unsynced = VaultRow {
            p_mint: 0,
            ..v.clone()
        };
        assert_eq!(early_redeem_fee_for(r, &unsynced, 500, true), 0);
        // Built at R = 599 the spend confirms at 600 = lockHeight at the earliest: no fee.
        assert_eq!(early_redeem_fee_for(r, &v, 599, true), 0);
        assert_eq!(early_redeem_fee_for(r, &v, 700, true), 0);
        // FEE-0 (no eligible payee): RED-3 charges neither fee.
        assert_eq!(early_redeem_fee_for(r, &v, 500, false), 0);
        let void = VaultRow {
            status: "VOID".into(),
            ..v.clone()
        };
        assert_eq!(early_redeem_fee_for(r, &void, 500, true), 0);
        let a = VaultRow {
            term_class: "A".into(),
            ..v.clone()
        };
        assert_eq!(early_redeem_fee_for(r, &a, 500, true), 10_000_000_000);
        let c = VaultRow {
            term_class: "C".into(),
            ..v
        };
        assert_eq!(early_redeem_fee_for(r, &c, 500, true), 2_000_000_000);
        assert_eq!(early_redeem_fee_cents_for(r, &c, 599, true), 0);
    }

    /// rpcversion 8 (review B L-1): the owner spend's network fee is the Yellowback size fee at the
    /// node's estimated size, clamped to the floor rate when it would take what the vault has left.
    #[test]
    fn owner_spend_network_fee_is_the_nodes() {
        let t = super::super::terms::PqTerms {
            yed_rate_zat_per_kb: 12_500_000,
            floor_rate_zat_per_kb: 5_000,
            max_fee_zat: 500_000_000,
            ..Default::default()
        };
        // SLH-DSA owner (7,981) + 1,000, no YED input
        assert_eq!(
            owner_spend_network_fee(&t, 1, &[], 10 * crate::params::COIN),
            112_262_500
        );
        // a P2PKH YED input adds 150 bytes
        let u = Utxo {
            outpoint: OutPoint {
                txid: [3; 32],
                n: 0,
            },
            address: String::new(),
            script: script::p2pkh_script(&[4; 20]),
            value: TOKEN_VALUE,
            height: 1,
            class: UtxoClass::Token,
            cents: 100,
        };
        assert_eq!(
            owner_spend_network_fee(&t, 1, &[u], 10 * crate::params::COIN),
            12_500_000 * 9_131 / 1000
        );
        // a small vault after a crash: the floor rate instead of a refusal
        assert_eq!(
            owner_spend_network_fee(&t, 1, &[], 100_000_000),
            5_000 * 8_981 / 1000
        );
    }

    /// Quantum plan §4.5: the owner spend is priced on its size before signing; the bound is
    /// exact for the SLH-DSA owner scriptSig (7,939 bytes with the selector) and an upper bound
    /// for each ECDSA input; the relay limits hold.
    #[test]
    fn owner_spend_is_priced_by_size_and_within_the_relay_limits() {
        let shape = shape(true, true, 2_000, false, 0);
        let plan = plan_vault_spend(&shape).unwrap();
        let mut tx = Transaction::new_v4();
        tx.lock_time = plan.lock_time;
        tx.vin = plan.vin.clone();
        tx.vout = plan.vout.clone();
        let bound = owner_spend_size_bound(&tx, 1).unwrap();
        assert!(owner_spend_size_bound(&tx, 3).is_err());
        let key = crate::pq::PqKey::from_seed(1, &[7u8; 48]).unwrap();
        let script = vec![0x51]; // the scriptCode only enters the sighash
        sign_owner_input(&mut tx, &key, &script, shape.vault_value, 0x6d5b_7a31).unwrap();
        assert_eq!(tx.vin[0].script_sig.len(), 7_939);
        for i in &mut tx.vin[1..] {
            i.script_sig = vec![0; 106]; // a typical P2PKH scriptSig
        }
        let signed = tx.serialize().unwrap().len();
        assert!(
            signed <= bound && bound - signed == 2 * 2,
            "{signed} vs {bound}"
        );
        assert!(signed > 8_000, "an SLH-DSA owner spend is ~8 KB");
        tx.check_script_sig_sizes().unwrap();
        // 1x the relay floor: unchanged at 1,000 (C-5); 5x: size-priced.
        let t = super::super::terms::PqTerms::default();
        assert_eq!(t.fee(bound), FEE_ZAT);
        let t5 = super::super::terms::PqTerms {
            fee_rate_zat_per_kb: 500,
            ..t
        };
        assert_eq!(t5.fee(bound), 500 * bound as i64 / 1000);
        // the fee comes out of the collateral
        let priced = VaultSpendShape {
            network_fee: t5.fee(bound),
            ..shape.clone()
        };
        assert_eq!(
            plan.collateral_out - plan_vault_spend(&priced).unwrap().collateral_out,
            t5.fee(bound) - FEE_ZAT
        );
        // a P2PKH-sized input over 1,650 bytes, or a PQ one over 9,000, is refused
        tx.vin[1].script_sig = vec![0; 1_651];
        assert!(matches!(
            tx.check_script_sig_sizes(),
            Err(crate::tx::TxError::ScriptSigSize(1, 1_651, 1_650))
        ));
        tx.vin[1].script_sig = vec![0; 106];
        let mut big = tx.vin[0].script_sig.clone();
        big.splice(0..0, std::iter::repeat_n(0x00u8, 1_100)); // OP_0 pushes ahead: not PQ-shaped
        tx.vin[0].script_sig = big;
        assert!(tx.check_script_sig_sizes().is_err());
    }

    // ---- Y2: a vault whose outpoint a pending transaction spends (DigiByte 00136af6)

    fn y2_wallet() -> Wallet {
        let seed = crate::keys::seed_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        )
        .unwrap();
        crate::wallet::Wallet::from_parts(
            crate::store::Store::open_in_memory().unwrap(),
            crate::params::Network::Regtest,
            &seed,
            None,
        )
        .unwrap()
    }

    fn y2_vault() -> VaultRow {
        crate::store::VaultRow {
            txid: [0xef; 32],
            vout: 0,
            status: "ACTIVE".into(),
            owner_hash160: [2; 20],
            owner: crate::pq::PqKeyId {
                scheme: 1,
                hash: [3; 32],
            },
            term_class: "A".into(),
            lock_height: 518,
            claim_height: 538,
            collateral_zat: 950_000_000,
            minted_cents: 25_000,
            mint_height: 501,
            claimable: false,
            underwater_at: 400_000,
            sweep_before: 0,
            close_height: 0,
            closing_txid: String::new(),
            void_reason: String::new(),
            updated_height: 510,
            owner_height: 499,
            app_height: 499,
            p_mint: 520_000,
            cancel: Default::default(),
        }
    }

    /// `build_redeem` refuses a vault locked `spent-by` a pending transaction before it asks the
    /// server anything (the client below has no server: reaching it would be a transport error).
    #[tokio::test]
    async fn a_vault_with_a_pending_spend_is_not_redeemed_again() {
        let w = y2_wallet();
        let v = y2_vault();
        w.store.upsert_vault(&v).unwrap();
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let mut yb = YellowbackClient::from_channel(channel);
        assert_eq!(pending_spend(&w, &v).unwrap(), None);
        let e = build_redeem(&w, &mut yb, &v.txid, 510, 0x6d5b_7a31)
            .await
            .unwrap_err();
        assert!(!e.to_string().contains("vault-spend-pending"), "{e}");
        let spender = txid_hex(&[0x5e; 32]);
        w.store
            .lock(
                &OutPoint { txid: v.txid, n: 0 },
                &format!("{SPENT_BY}{spender}"),
                530,
            )
            .unwrap();
        assert_eq!(pending_spend(&w, &v).unwrap(), Some(spender.clone()));
        let e = build_redeem(&w, &mut yb, &v.txid, 510, 0x6d5b_7a31)
            .await
            .unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.starts_with("vault-spend-pending") && msg.contains(&spender),
            "{msg}"
        );
        // Another lock reason on the vault outpoint is not a pending spend.
        w.store
            .lock(&OutPoint { txid: v.txid, n: 0 }, "vault", 0)
            .unwrap();
        assert_eq!(pending_spend(&w, &v).unwrap(), None);
    }

    /// A claim refuses a vault the server reports a pending spend of; a node that predates the
    /// field (false, "") is no refusal.
    #[test]
    fn a_server_reported_pending_spend_refuses_a_claim() {
        let mut v = crate::net::rpc::YedVault::default();
        assert!(check_no_pending_spend(&v).is_ok());
        v.spend_pending = true;
        v.spend_txid = "ab".repeat(32);
        let e = check_no_pending_spend(&v).unwrap_err().to_string();
        assert!(
            e.starts_with("vault-spend-pending") && e.contains(&"ab".repeat(32)),
            "{e}"
        );
    }
}
