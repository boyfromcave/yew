// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A mint **funded from the private (Sapling) balance** (beta2 D-3 in the app: "MINT funded from
//! a chosen source"). The same staging design as the post-quantum source (`mint::carrier_step`
//! with `CarrierFunding::Pq`): only the carrier funding transaction changes, the MINT does not.
//!
//! - **The carrier funding**: no transparent input; Sapling notes from the light client's own
//!   store ([`crate::shielded::Shielded::select_spends`], paths at the store's anchor), spent
//!   through the hybrid builder (`build::hybrid::sapling_prepare`, `sign_hybrid` with no
//!   transparent input to sign; nothing in it is new signing code); `vout[0]` the carrier
//!   (`CARRIER_VALUE` to the P2SH of the carrier script the core built), `vout[1]` the MINT's YEC
//!   need ([`mint::staged_value`]) to a fresh own change key recorded for this mint before
//!   anything is built ([`mint::record_stage_key`]); the change back to the private balance as a
//!   Sapling note (D-4).
//! - **Fee**: [`mint::sapling_carrier_fee`] (the shape's ZIP-317 fee, at least the server's flat
//!   Yellowback fee), re-checked on the signed bytes, bounded by this app's limit and by the fee
//!   the user confirmed on the estimate (the stored-quote rule); the estimate's guard carries the
//!   unusual-fee acknowledgement.
//! - **Gate**: [`gate::Path::CarrierFromSapling`] with the outputs read back from the record
//!   ([`mint::recorded_carrier_outputs`]); the node's dry run is mandatory.
//! - **Recorded before it is sent** (`mint::send_recorded`): the row, the staged output (locked to
//!   the row), the pending transaction. Once the server has it (or its fate is unknown) the
//!   private store records it, so its notes count as spent until it is mined or expires.
//!
//! The MINT then spends the staged output first as a plain `YEC` input (`mint::finish`).

use std::cell::RefCell;

use crate::build::hybrid;
use crate::gate::{self, Validator};
use crate::params::{self, CARRIER_VALUE, REF_WINDOW, VAULT_BRANCH_ID};
use crate::sapling_part::{SaplingOut, SaplingPart};
use crate::script;
use crate::store::HistoryRow;
use crate::tx::{OutPoint, Transaction, TxOut};
use crate::wallet::{Wallet, WalletError};

use super::any_to_any as plan;
use super::mint::{self, CarrierStep, ConfirmedTerms, MintError, MintSource, Prepared};
use super::pq_send::SaplingSide;

fn other(m: impl Into<String>) -> WalletError {
    WalletError::Other(m.into())
}

/// `mint_start` with the private balance as the source: [`mint::prepare_start`] (the estimate
/// re-checked, its acknowledgements, the bundle, the owner key, the attestor payee), the note
/// selection for the carrier and the staged need with their paths, the notes' plaintexts, then
/// [`carrier_step_sapling`]. `params_dir` holds the Sapling proving parameters. The notes'
/// transactions come from the store; one it lacks is fetched only with `allow_note_lookup`
/// (`sapling_pq::note_txs`). Returns the row.
#[allow(clippy::too_many_arguments)]
pub async fn start_from_sapling(
    wallet: &mut Wallet,
    client: &mut crate::net::CompactClient,
    validator: &mut Validator,
    cents: u64,
    lock_blocks: u32,
    confirmed: Option<&ConfirmedTerms>,
    tip: u64,
    branch_id: u32,
    params_dir: &std::path::Path,
    allow_note_lookup: bool,
) -> Result<i64, WalletError> {
    if branch_id != VAULT_BRANCH_ID {
        return Err(other(
            "a mint can be funded from the private balance only once the vault upgrade is active at the next block",
        ));
    }
    let p = mint::prepare_start(
        wallet,
        client,
        validator,
        cents,
        lock_blocks,
        confirmed,
        tip,
        MintSource::Sapling,
    )
    .await?;
    let staged = p.staged(wallet);
    let flat = wallet.pq_terms().flat_zat;
    let picked = wallet
        .shielded_mut()?
        .select_spends((CARRIER_VALUE + staged) as u64, |n| {
            mint::sapling_carrier_fee(flat, n) as u64
        })?;
    // review YEW-REVIEW-8 M1: the notes' transactions from the store; the server only with the
    // user's go-ahead
    let fetched = super::sapling_pq::note_txs(
        client,
        wallet.shielded()?,
        super::sapling_pq::note_txids(&picked.notes),
        allow_note_lookup,
    )
    .await?;
    let side = SaplingSide::of(wallet, params_dir)?;
    let sent = RefCell::new(None);
    let r = carrier_step_sapling(
        wallet,
        client,
        validator,
        &p,
        (cents, lock_blocks, tip, branch_id),
        staged,
        (&picked, &fetched, &side),
        &sent,
    )
    .await;
    if let Some(raw) = sent.take() {
        let recorded = wallet.shielded_mut()?.record_sent(&raw, branch_id);
        if let (Ok(_), Err(e)) = (&r, recorded) {
            return Err(other(format!(
                "the carrier funding was sent, but recording it in the private wallet failed: {e}; sync before sending from the private balance again"
            )));
        }
    }
    let id = r?;
    mint::note_fee_ack(wallet, id, &p.est.fee_guard)?;
    Ok(id)
}

/// Build, check, record and send the carrier funding from the private balance (see the module
/// doc). `sent` receives the raw transaction once it was handed to the server or its fate is
/// unknown (the caller records it in the private store).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn carrier_step_sapling(
    wallet: &Wallet,
    client: &mut crate::net::CompactClient,
    validator: &mut Validator,
    p: &Prepared,
    (cents, lock_blocks, tip, branch_id): (u64, u32, u64, u32),
    staged: i64,
    (picked, fetched, side): (
        &crate::shielded::NoteSpends,
        &std::collections::HashMap<[u8; 32], Vec<u8>>,
        &SaplingSide,
    ),
    sent: &RefCell<Option<Vec<u8>>>,
) -> Result<i64, WalletError> {
    let ref_height = p.est.ref_height;
    let expiry_height = ref_height + REF_WINDOW;
    if !mint::window_open(tip, expiry_height) {
        return Err(MintError::Lapsed {
            ref_height,
            expiry: expiry_height,
            tip,
        }
        .into());
    }
    let SaplingCarrier {
        raw,
        txid,
        fee,
        carrier_row,
        stage_row,
        want,
    } = build_carrier_from_sapling(
        wallet,
        (&p.bundle_bytes, p.carrier_quote, staged),
        (picked, fetched, side),
        (tip, branch_id, expiry_height),
    )?;
    let path = gate::Path::CarrierFromSapling(want);
    let (_, validation) = gate::confirm(validator, path, &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let validation = validation.ok_or(gate::GateError::YellowbackAbsent)?;
    // no transparent input: nothing for layer 3 (provenance) to fetch
    let step = CarrierStep {
        txid,
        carrier_hash160: carrier_row.hash160,
        expiry_height,
        validation,
    };
    let row_id = std::cell::Cell::new(None);
    let send = async {
        let r = mint::send(client, &raw, &txid).await;
        if !matches!(&r, Err(e) if mint::send_refused(e)) {
            *sent.borrow_mut() = Some(raw.clone());
        }
        r
    };
    mint::send_recorded(
        wallet,
        &txid,
        &raw,
        expiry_height,
        &[],
        || {
            wallet.store.upsert_history(&HistoryRow {
                txid,
                height: 0,
                yec_delta: -(CARRIER_VALUE + fee),
                has_payload: false,
                pending: true,
                shielded: true,
                yed_delta: 0,
                kind: "carrier".into(),
                verdict: String::new(),
                label: "funding carrier from your private balance".into(),
                labelled: true,
            })?;
            wallet
                .store
                .insert_own_output(&OutPoint { txid, n: 1 }, staged, &stage_row.hash160)?;
            let id = p.persist_row(wallet, cents, lock_blocks, tip, &step)?;
            mint::record_staged_output(wallet, id, &txid, expiry_height)?;
            row_id.set(Some(id));
            Ok(())
        },
        || mint::undo_staged_output(wallet, row_id.get(), &txid),
        send,
    )
    .await?;
    row_id
        .get()
        .ok_or_else(|| other("carrier row not recorded"))
}

/// A built, authorized carrier funding from the private balance (not yet checked by the node).
pub(crate) struct SaplingCarrier {
    pub(crate) raw: Vec<u8>,
    pub(crate) txid: [u8; 32],
    pub(crate) fee: i64,
    pub(crate) carrier_row: crate::store::AddressRow,
    pub(crate) stage_row: crate::store::AddressRow,
    /// What the gate compares, read back from the record.
    pub(crate) want: gate::CarrierOutputs,
}

/// Derive the carrier key (its script commits to `bundle`) and the staged key (recorded first),
/// prove and authorize the carrier funding of `staged` zat from the selected notes, and check the
/// final bytes, the fee against the shape, this app's limit and `carrier_quote`, and the local
/// gate layer ([`gate::Path::CarrierFromSapling`] on the recorded outputs). Nothing is sent.
pub(crate) fn build_carrier_from_sapling(
    wallet: &Wallet,
    (bundle, carrier_quote, staged): (&[u8], i64, i64),
    (picked, fetched, side): (
        &crate::shielded::NoteSpends,
        &std::collections::HashMap<[u8; 32], Vec<u8>>,
        &SaplingSide,
    ),
    (tip, branch_id, expiry_height): (u64, u32, u32),
) -> Result<SaplingCarrier, WalletError> {
    let (carrier_row, redeem) = mint::carrier_key(wallet, bundle)?;
    // review YEW-REVIEW-8 M2: the staged key is recorded before anything is built, and the gate
    // compares the outputs with what the record and the carrier script say
    let stage_row = mint::record_stage_key(wallet, &carrier_row.hash160)?;
    let want = mint::recorded_carrier_outputs(wallet, &carrier_row.hash160, bundle)?;
    let fee = picked.fee_zat as i64;
    // review YEW-REVIEW-6 M1: never more than the fee the user confirmed on the estimate
    if fee > carrier_quote {
        return Err(other(format!(
            "fee-terms-changed: the server's fee terms changed while the mint was starting: the carrier funding would now pay {} YEC, above the {} YEC you confirmed. Nothing was sent; review the new fee and start again.",
            plan::format_money(fee),
            plan::format_money(carrier_quote)
        )));
    }
    let change = picked.total_zat as i64 - CARRIER_VALUE - staged - fee;
    if change < 0 {
        return Err(other(
            "the selected notes do not cover the carrier, the staged mint funding and the fee",
        ));
    }
    let spends = super::sapling_pq::note_spends(&side.extsk, &picked.notes, fetched)?;
    let n_notes = spends.len();
    let carrier_spk = script::p2sh_of(&redeem);
    let stage_spk = script::p2pkh_script(&want.staged_key);
    let mut tx = Transaction::new_v4();
    tx.expiry_height = expiry_height;
    tx.vout.push(TxOut {
        value: CARRIER_VALUE,
        script_pubkey: carrier_spk.clone(),
    });
    tx.vout.push(TxOut {
        value: staged,
        script_pubkey: stage_spk.clone(),
    });
    let part = SaplingPart {
        target_height: (tip as u32).saturating_add(1),
        vault_height: None,
        spends,
        outputs: if change > 0 {
            vec![SaplingOut::Change { value: change }]
        } else {
            Vec::new()
        },
        anchor: picked.anchor.clone(),
        params_dir: side.params_dir.display().to_string(),
    };
    let h = hybrid::sapling_prepare(
        side.extsk.clone(),
        wallet.network,
        &part,
        &tx,
        branch_id,
        rand_core::OsRng,
    )
    .map_err(|r| other(format!("{}: {}", r.0, r.1)))?;
    let (_, raw) = hybrid::sign_hybrid(h, tx, &[], branch_id, rand_core::OsRng)
        .map_err(|r| other(format!("{}: {}", r.0, r.1)))?;
    // the final bytes, parsed: exactly what the estimate described
    let (signed, txid) = Transaction::parse(&raw)?;
    if !signed.vin.is_empty()
        || signed.vout.len() != 2
        || signed.vout[0].script_pubkey != carrier_spk
        || signed.vout[0].value != CARRIER_VALUE
        || signed.vout[1].script_pubkey != stage_spk
        || signed.vout[1].value != staged
    {
        return Err(other(
            "the built carrier funding does not pay exactly the carrier and the staged mint funding",
        ));
    }
    if signed.shielded.spends != n_notes
        || signed.shielded.value_balance != CARRIER_VALUE + staged + fee
    {
        return Err(other(format!(
            "the built carrier funding takes {} zat out of the private balance, not the {} zat planned",
            signed.shielded.value_balance,
            CARRIER_VALUE + staged + fee
        )));
    }
    let conventional = signed.zip317_conventional_fee(&[])?;
    if fee < conventional {
        return Err(other(format!(
            "the fee {} YEC is below the {} YEC this transaction needs",
            plan::format_money(fee),
            plan::format_money(conventional)
        )));
    }
    let flat = wallet.pq_terms().flat_zat;
    let limit =
        params::pq_send_fee_limit(raw.len(), conventional).max(flat.min(params::MAX_FLAT_ZAT));
    if fee > limit {
        return Err(other(format!(
            "Fee {} YEC is above this app's limit of {} YEC for a {}-byte carrier funding. Nothing was sent; try another server.",
            plan::format_money(fee),
            plan::format_money(limit),
            raw.len()
        )));
    }
    gate::check(gate::Path::CarrierFromSapling(want), &raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })?;
    Ok(SaplingCarrier {
        raw,
        txid,
        fee,
        carrier_row,
        stage_row,
        want,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn params_dir() -> std::path::PathBuf {
        if let Ok(d) = std::env::var("YEW_SAPLING_PARAMS") {
            return d.into();
        }
        let home = std::env::var("HOME").unwrap_or_default();
        if cfg!(target_os = "macos") {
            format!("{home}/Library/Application Support/ZcashParams").into()
        } else {
            format!("{home}/.zcash-params").into()
        }
    }

    /// Beta2 D-3, a mint funded from the private balance, through the builder `mint_start` uses:
    /// the notes and paths from the store; no transparent input; `vout` exactly the carrier (the
    /// P2SH of the script the core built from its carrier key and the bundle) and the staged need
    /// to the change key recorded for this mint (read back from the record); the Sapling change to
    /// the account's internal address; the fee of the shape (at least the flat fee); the bundle
    /// verifies (proofs, spend authorizations, binding signature); the gate's
    /// CarrierFromSapling admits it for the recorded outputs only and no other path does; a fee
    /// above the confirmed quote is refused before anything is proven.
    #[test]
    fn carrier_from_sapling_end_to_end() {
        use zcash_primitives::transaction::sighash::SignableInput;
        use zcash_primitives::transaction::sighash_v4::v4_signature_hash;
        let dir = std::env::temp_dir().join(format!("yew-mintsapling-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("w.sqlite");
        let mut w = Wallet::open(
            path.to_str().unwrap(),
            params::Network::Regtest,
            PHRASE,
            "",
            Some(100),
        )
        .unwrap();
        w.set_vault_activation(Some(1)).unwrap();
        let raw = w.shielded_mut().unwrap().receive_for_test(
            100,
            120,
            &[30_000_000, 4_000_000],
            &params_dir(),
        );
        let (_, ptxid) = Transaction::parse(&raw).unwrap();
        let fetched: std::collections::HashMap<[u8; 32], Vec<u8>> =
            [(ptxid, raw)].into_iter().collect();
        let staged = 20_000_000i64;
        let flat = w.pq_terms().flat_zat;
        // the estimate's read-only quote equals the selection's settled fee
        let q = mint::sapling_funding_quote(&w, staged).unwrap();
        let picked = w
            .shielded_mut()
            .unwrap()
            .select_spends((CARRIER_VALUE + staged) as u64, |n| {
                mint::sapling_carrier_fee(flat, n) as u64
            })
            .unwrap();
        assert_eq!(q.fee, picked.fee_zat as i64);
        assert_eq!(q.notes, picked.notes.len());
        assert_eq!(q.available, 34_000_000);
        let side = SaplingSide::of(&w, &params_dir()).unwrap();
        let bundle = vec![0xb7u8; 40];
        let expiry = 160;
        // the stored-quote rule: a fee above what the user confirmed is refused
        let e = build_carrier_from_sapling(
            &w,
            (&bundle, q.fee - 1, staged),
            (&picked, &fetched, &side),
            (120, VAULT_BRANCH_ID, expiry),
        )
        .err()
        .unwrap();
        assert!(e.to_string().starts_with("fee-terms-changed"), "{e}");
        let c = build_carrier_from_sapling(
            &w,
            (&bundle, q.fee, staged),
            (&picked, &fetched, &side),
            (120, VAULT_BRANCH_ID, expiry),
        )
        .unwrap();
        // the recorded staged key is a change key of this wallet, the carrier the core's script
        assert_eq!(c.want.staged_key, c.stage_row.hash160);
        assert_eq!(c.stage_row.hd_chain(), Some(crate::keys::Chain::Change));
        let carrier_pk = w
            .key_for_hash(&c.carrier_row.hash160)
            .unwrap()
            .unwrap()
            .pubkey;
        let redeem =
            crate::script::carrier_script(&carrier_pk, &crate::bundle::bundle_hash(&bundle))
                .unwrap();
        assert_eq!(c.want.carrier_hash, crate::keys::hash160(&redeem));
        let (tx, txid) = Transaction::parse(&c.raw).unwrap();
        assert_eq!(txid, c.txid);
        assert!(tx.vin.is_empty());
        assert_eq!(tx.expiry_height, expiry);
        assert_eq!(tx.vout.len(), 2);
        assert_eq!(tx.vout[0].value, CARRIER_VALUE);
        assert_eq!(tx.vout[0].script_pubkey, script::p2sh_of(&redeem));
        assert_eq!(tx.vout[1].value, staged);
        assert_eq!(
            tx.vout[1].script_pubkey,
            script::p2pkh_script(&c.stage_row.hash160)
        );
        assert_eq!(c.fee, mint::sapling_carrier_fee(flat, picked.notes.len()));
        assert!(c.fee >= flat.min(params::MAX_FLAT_ZAT));
        assert_eq!(tx.shielded.value_balance, CARRIER_VALUE + staged + c.fee);
        // the verifying path; the change decrypts to the internal address
        let branch = zcash_protocol::consensus::BranchId::try_from(VAULT_BRANCH_ID).unwrap();
        let ztx = zcash_primitives::transaction::Transaction::read(&c.raw[..], branch).unwrap();
        let sighash: [u8; 32] = v4_signature_hash(&ztx, &SignableInput::Shielded)
            .as_ref()
            .try_into()
            .unwrap();
        let sb = ztx.sapling_bundle().cloned().unwrap();
        let ivk = sapling_crypto::note_encryption::PreparedIncomingViewingKey::new(
            &side
                .extsk
                .to_diversifiable_full_viewing_key()
                .to_ivk(zip32::Scope::Internal),
        );
        let change: i64 = sb
            .shielded_outputs()
            .iter()
            .filter_map(|o| {
                sapling_crypto::note_encryption::try_sapling_note_decryption(
                    &ivk,
                    o,
                    sapling_crypto::note_encryption::Zip212Enforcement::On,
                )
            })
            .map(|(n, _, _)| n.value().inner() as i64)
            .sum();
        assert_eq!(
            change,
            picked.total_zat as i64 - CARRIER_VALUE - staged - c.fee
        );
        let dp = params_dir();
        let params = zcash_proofs::load_parameters(
            &dp.join(crate::sapling_params::SPEND.name),
            &dp.join(crate::sapling_params::OUTPUT.name),
            None,
        );
        let mut bv = sapling_crypto::BatchValidator::new();
        assert!(bv.check_bundle(sb, sighash));
        assert!(bv.validate(
            &params.spend_params.verifying_key(),
            &params.output_params.verifying_key(),
            rand_core::OsRng
        ));
        // the gate: these outputs only; no other path
        let none = |_: &OutPoint| None;
        assert!(gate::check(gate::Path::CarrierFromSapling(c.want), &c.raw, none).is_ok());
        let other_key = gate::CarrierOutputs {
            staged_key: [0x99; 20],
            ..c.want
        };
        assert!(gate::check(gate::Path::CarrierFromSapling(other_key), &c.raw, none).is_err());
        for p in [gate::Path::Carrier, gate::Path::Shield, gate::Path::Yec] {
            assert!(gate::check(p, &c.raw, none).is_err(), "{p:?}");
        }
        drop(w);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
