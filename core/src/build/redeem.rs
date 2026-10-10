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
use crate::keys::{self, AddressKey};
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
    /// `P2PKH(ownerPubKey)` for the residual.
    pub owner_script: Vec<u8>,
    /// `CARRIER_VALUE` when a carrier input is spent, else 0.
    pub carrier_value: i64,
    /// The collateral destination.
    pub collateral_script: Vec<u8>,
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
        - FEE_ZAT
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

/// `SignVaultSpend`'s owner signature (`txbuilder.cpp`, branch `upgrade/vault`): ZIP-243 over
/// the bare V script (it is the scriptCode) with the vault's `nValue` and the next block's
/// branch id (the Vault id after activation), then `<sig> OP_2` at `vin[0]` (the V's OWNER
/// selector, U-23).
pub fn sign_owner_input(
    tx: &mut Transaction,
    owner: &AddressKey,
    vault_script: &[u8],
    vault_value: i64,
    branch_id: u32,
) -> Result<(), WalletError> {
    let digest = tx.sighash(
        0,
        vault_script,
        vault_value,
        crate::params::SIGHASH_ALL,
        branch_id,
    )?;
    let sig = secp256k1::ecdsa::sign(secp256k1::Message::from_digest(digest), &owner.secret);
    let mut der = sig.serialize_der().to_vec();
    der.push(crate::params::SIGHASH_ALL as u8);
    tx.vin[0].script_sig = crate::vault::vault_owner_script_sig(&der);
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
    /// What the fee output pays (0 under FEE-0): the enforcement fee plus the early-redeem fee.
    pub fee_zat: i64,
    /// The early-redeem fee within `fee_zat` (IT-9): `collateral · earlyRedeemFeeBps[class] / 10⁴`
    /// when the redeem confirms before `lockHeight` (judged at `R + 1`, the node builder's
    /// reading), 0 at or after it and under FEE-0.
    pub early_redeem_fee_zat: i64,
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
    /// The signed transaction.
    pub raw: Vec<u8>,
    /// Its txid.
    pub txid: [u8; 32],
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
    Ok(vt.vault_script_at(&v.owner_pubkey, v.owner_height, v.app_height)?)
}

/// IT-9's early-redeem fee of an owner redeem of `v` built at index height `r` (`EarlyRedeemFeeAt`
/// / `BuildVaultSpend`, `ycash-dd` branch `upgrade/vault-in-term`): the spend confirms at `r + 1`
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
        .map(|c| crate::params::early_redeem_fee_zat(v.collateral_zat, c.early_redeem_fee_bps))
        .unwrap_or(0)
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
        .key_for_hash(&v.owner_hash160)?
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
        // FEE-1 locally (audit G-2): a server quoting more is refused before anything is signed.
        let (fee_zat, payee) =
            mint::fee_payee(wallet.network, yb, r, v.collateral_zat, &selector).await?;
        (sel, change, extra, stage, fee_zat, payee)
    } else {
        (Vec::new(), 0, 0, SelectStage::None, 0, String::new())
    };
    // IT-9 locally: the early-redeem fee rides on the FEE-1 payee's output (RED-3 checks that
    // output against FEE-1 + the early fee; AFEE-1 gives the owner path no attestor share).
    let early_redeem_fee_zat = early_redeem_fee_for(wallet.network, &v, r, !payee.is_empty());
    let change_row = if change_cents > 0 {
        Some(mint::fresh_external(wallet)?)
    } else {
        None
    };
    let shape = VaultSpendShape {
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
        change_script: change_row
            .as_ref()
            .map(|c| script::p2pkh_script(&c.hash160))
            .unwrap_or_default(),
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
        owner_script: script::p2pkh_script(&v.owner_hash160),
        carrier_value: 0,
        collateral_script: script::p2pkh_script(&dest.hash160),
    };
    let plan = plan_vault_spend(&shape)?;
    let mut tx = Transaction::new_v4();
    tx.lock_time = plan.lock_time;
    tx.expiry_height = expiry_height;
    tx.vin = plan.vin.clone();
    tx.vout = plan.vout.clone();
    sign_owner_input(&mut tx, &owner, &vault_script, v.collateral_zat, branch_id)?;
    mint::sign_p2pkh_inputs(wallet, &mut tx, &yed_inputs, 1, branch_id)?;
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
        vault_txid: txid_hex(&v.txid),
        kind: if active { "redeem" } else { "release" },
        yed_inputs,
        stage,
        burn_cents: plan.burn_cents.max(0) as u64,
        extra_burn_cents: extra_burn,
        change_cents,
        fee_zat: shape.fee_zat,
        early_redeem_fee_zat,
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
    mint::send(client, &p.raw, &p.txid).await?;
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
    mint::record_broadcast(wallet, &p.txid, &p.raw, p.expiry_height, &locked)?;
    for u in &p.yed_inputs {
        wallet
            .store
            .insert_spent_token(&p.txid, &u.outpoint, u.cents)?;
    }
    let own = wallet.own_hashes()?;
    for (n, cents) in coins::pre_lock(&tx, |h| own.contains(h)) {
        let script_pubkey = tx.vout[n as usize].script_pubkey.clone();
        wallet.store.upsert_utxo(&Utxo {
            outpoint: OutPoint { txid: p.txid, n },
            address: script::p2pkh_hash(&script_pubkey)
                .map(|h| keys::encode_p2pkh(wallet.network, &h))
                .unwrap_or_default(),
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
        yec_delta: p.collateral_out + if p.change_cents > 0 { TOKEN_VALUE } else { 0 } - yed_spent,
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
            owner_script: script::p2pkh_script(&[8; 20]),
            carrier_value: 0,
            collateral_script: script::p2pkh_script(&[4; 20]),
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
        let early = crate::params::early_redeem_fee_zat(s.vault_value, 500);
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
            owner_pubkey: [2; 33],
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
        };
        let r = crate::params::Network::Regtest;
        // Class B: 2.5 % of 4,000 YEC = 100 YEC while R + 1 < lockHeight.
        assert_eq!(early_redeem_fee_for(r, &v, 500, true), 10_000_000_000);
        assert_eq!(early_redeem_fee_for(r, &v, 598, true), 10_000_000_000);
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
        assert_eq!(early_redeem_fee_for(r, &a, 500, true), 20_000_000_000);
        let c = VaultRow {
            term_class: "C".into(),
            ..v
        };
        assert_eq!(early_redeem_fee_for(r, &c, 500, true), 4_000_000_000);
    }
}
