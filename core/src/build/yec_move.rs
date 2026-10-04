// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Move YEC between the wallet's own public and private balances (yew-shielded plan S4): one
//! explicit action, two directions, the same preview / gate / confirm as a send.
//!
//! - **To private (shield, t→z):** transparent `YEC` coins only — `coins::select_yec` without
//!   the reserve, so the fee reserve and every YED-bearing, locked, pending or held output stay
//!   where they are — into one Sapling output to the wallet's own default `ys1…` address, with
//!   transparent change back to the next change address. Built by the librustzcash6 builder
//!   (`Shielded::build_shield`, ZIP-317 fee): YEW's own serializer makes no Sapling outputs,
//!   and the light library's shielding (`zcash_client_backend` transparent support) would pick
//!   coins from its own UTXO table by its own rules, blind to YEW's coin classes. Gate path
//!   [`GatePath::Shield`] (inputs class `YEC` only).
//! - **To public (unshield, z→t):** a private spend to the wallet's own current public `s…`
//!   address through the existing private send path (`Shielded::plan`, gate path `Shielded`).
//!   The amount becomes visible on the chain, so the plan says `reveals_shielded`.
//!
//! "All" moves everything the direction can: every `YEC` coin less the fee, or every spendable
//! note less the fee.

use std::path::Path;

use crate::build::yec_private::{Confirmed, Funding, YecSendPlan};
use crate::build::yec_send::MIN_CHANGE;
use crate::coins::{self, Utxo};
use crate::gate::{self, Path as GatePath, Validator};
use crate::net::CompactClient;
use crate::params::{MAX_INPUTS, TOKEN_VALUE, TX_EXPIRY_DELTA};
use crate::script;
use crate::shielded::{ShieldInput, ShieldedError};
use crate::store::HistoryRow;
use crate::tx::{txid_hex, OutPoint};
use crate::wallet::{Wallet, WalletError};

/// Which way a move goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Public (transparent) YEC into the private (Sapling) balance.
    ToPrivate,
    /// Private YEC out to the wallet's own public address.
    ToPublic,
}

/// A planned shield: what the preview shows and what confirm proves and signs.
#[derive(Clone, Debug)]
pub struct ShieldPlan {
    /// The wallet's own default Sapling address.
    pub to: String,
    /// Into the private balance, zat.
    pub amount: i64,
    /// The amount was raised to absorb a change of exactly `TOKEN_VALUE` or of dust.
    pub amount_bumped: bool,
    /// The ZIP-317 fee, zat.
    pub fee: i64,
    /// Transparent change, zat (0 = none).
    pub change: i64,
    /// The change address (`s…`) and its key hash when `change > 0`.
    pub change_address: Option<(String, [u8; 20])>,
    /// The coins spent (class `YEC` only).
    pub inputs: Vec<Utxo>,
    /// The same coins as the builder takes them.
    pub shield_inputs: Vec<ShieldInput>,
    /// The height the transaction is built for (the tip + 1).
    pub target: u32,
    /// `nExpiryHeight` (target + 40).
    pub expiry_height: u32,
}

/// Plan a move of `amount` zat (`None`: everything the direction can move) after a sync at
/// `tip`. Nothing is signed, proved or locked.
pub fn plan_move(
    wallet: &mut Wallet,
    direction: Direction,
    amount: Option<i64>,
    tip: u64,
) -> Result<YecSendPlan, WalletError> {
    if matches!(amount, Some(a) if a <= 0) {
        return Err(WalletError::Other("amount must be positive".into()));
    }
    match direction {
        Direction::ToPrivate => {
            let p = plan_shield(wallet, amount, tip)?;
            Ok(YecSendPlan {
                funding: Funding::Shield(Box::new(p)),
                reveals_shielded: false,
            })
        }
        Direction::ToPublic => {
            let to = wallet.receive_address(false)?.address_s;
            let sh = wallet.shielded_mut()?;
            let plan = match amount {
                Some(a) => sh.plan(&to, a as u64, None)?,
                None => {
                    // Everything spendable less the fee, which depends on the notes spent: ask
                    // for the balance less a first guess and correct by what the proposal says
                    // it needs (at most a few rounds; the fee only grows with note count).
                    let b = sh.balance()?;
                    if !b.sendable {
                        return Err(ShieldedError::NotSynced {
                            scanned: b.scanned_height,
                            tip: b.tip_height,
                        }
                        .into());
                    }
                    let mut fee = 15_000u64;
                    let mut out = None;
                    for _ in 0..8 {
                        let want = b.spendable_zat.checked_sub(fee).filter(|w| *w > 0).ok_or(
                            ShieldedError::Insufficient {
                                available: b.spendable_zat,
                                required: fee + 1,
                            },
                        )?;
                        match sh.plan(&to, want, None) {
                            Ok(p) if p.amount_zat + p.fee_zat + p.change_zat == b.spendable_zat => {
                                out = Some(p);
                                break;
                            }
                            // Over-estimated: the change is the slack; take it next round.
                            Ok(p) => fee = p.fee_zat,
                            Err(ShieldedError::Insufficient { required, .. }) => {
                                fee = required - want;
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                    out.ok_or_else(|| {
                        WalletError::Other("could not settle the fee for moving everything".into())
                    })?
                }
            };
            Ok(YecSendPlan {
                funding: Funding::Shielded(Box::new(plan)),
                reveals_shielded: true,
            })
        }
    }
}

fn plan_shield(wallet: &Wallet, amount: Option<i64>, tip: u64) -> Result<ShieldPlan, WalletError> {
    let sh = wallet.shielded()?;
    let to = sh.default_address().1;
    let target = (tip as u32).saturating_add(1);
    let spendable = wallet.spendable_utxos()?;
    let change_row = wallet.change_address()?;
    let change_h = change_row.hash160;

    // The coins: class YEC only (no reserve override exists on this path).
    let (inputs, mut amount_zat, mut change, fee) = match amount {
        None => {
            let mut all: Vec<Utxo> = spendable
                .iter()
                .filter(|u| u.class == coins::UtxoClass::Yec)
                .cloned()
                .collect();
            all.sort_by_key(|u| std::cmp::Reverse(u.value));
            all.truncate(MAX_INPUTS);
            if all.is_empty() {
                return Err(coins::CoinError::Insufficient { need: 1, have: 0 }.into());
            }
            let si = shield_inputs(wallet, &all)?;
            let total: i64 = all.iter().map(|u| u.value).sum();
            let fee = sh.shield_fee(target, &si, total as u64, None)? as i64;
            if total <= fee {
                return Err(coins::CoinError::Insufficient {
                    need: fee + 1,
                    have: total,
                }
                .into());
            }
            (all, total - fee, 0, fee)
        }
        Some(a) => {
            // The fee depends on how many coins are spent: select for amount + fee, recompute
            // the fee for that selection, repeat until it holds (it only grows with inputs).
            let mut fee = 10_000i64;
            loop {
                let sel = coins::select_yec(&spendable, a + fee, false)?;
                let si = shield_inputs(wallet, &sel)?;
                let f = sh.shield_fee(target, &si, a as u64, Some(change_h))? as i64;
                let total: i64 = sel.iter().map(|u| u.value).sum();
                if total >= a + f {
                    break (sel, a, total - a - f, f);
                }
                fee = f;
            }
        }
    };
    // No transparent output may look like a token, and dust change is not worth an output:
    // either goes into the private amount instead (the fee does not change — with at least
    // one input, ZIP-317 counts max(inputs, outputs) transparent actions).
    let mut amount_bumped = false;
    if change == TOKEN_VALUE {
        change -= 1;
        amount_zat += 1;
        amount_bumped = true;
    }
    if change > 0 && change < MIN_CHANGE {
        amount_zat += change;
        change = 0;
        amount_bumped = true;
    }
    let shield_inputs = shield_inputs(wallet, &inputs)?;
    Ok(ShieldPlan {
        to,
        amount: amount_zat,
        amount_bumped,
        fee,
        change,
        change_address: (change > 0).then(|| (change_row.address_s.clone(), change_h)),
        inputs,
        shield_inputs,
        target,
        expiry_height: target.saturating_add(TX_EXPIRY_DELTA),
    })
}

/// The builder's view of `coins`: P2PKH outputs of own keys (public keys only; the secrets are
/// fetched at confirm).
fn shield_inputs(wallet: &Wallet, coins: &[Utxo]) -> Result<Vec<ShieldInput>, WalletError> {
    coins
        .iter()
        .map(|u| {
            let h = script::p2pkh_hash(&u.script).ok_or_else(|| {
                WalletError::Other(format!("input {} is not P2PKH", u.outpoint.display()))
            })?;
            let key = wallet.key_for_hash(&h)?.ok_or_else(|| {
                WalletError::Other(format!("no key for input {}", u.outpoint.display()))
            })?;
            Ok(ShieldInput {
                txid: u.outpoint.txid,
                n: u.outpoint.n,
                value: u.value as u64,
                pubkey: key.pubkey,
                hash160: h,
            })
        })
        .collect()
}

/// Confirm a shield: check the server's branch id, prove and sign (keys fetched for this call
/// only), both gate layers on [`GatePath::Shield`], broadcast, then the bookkeeping a
/// transparent send does (locks, pending record, history row, own change output).
pub async fn confirm_shield(
    wallet: &mut Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    plan: &ShieldPlan,
    params_dir: &Path,
) -> Result<Confirmed, WalletError> {
    let chain = match validator.client_mut() {
        Some(yb) => yb.chain_info().await?,
        None => None,
    };
    let network = wallet.network;
    let mut secrets = Vec::with_capacity(plan.inputs.len());
    for i in &plan.shield_inputs {
        let key = wallet
            .key_for_hash(&i.hash160)?
            .ok_or_else(|| WalletError::Other("no key for a shield input".into()))?;
        secrets.push(key.secret.to_secret_bytes());
    }
    let info = match chain {
        Some(c) => Ok(c),
        None => client
            .lightd_info_for(network)
            .await
            .map(|i| (i.block_height, i.branch_id)),
    };
    let sh = wallet.shielded_mut()?;
    let built = match info {
        Ok((height, id)) => sh.check_branch(height, id, chain.is_some()).and_then(|_| {
            sh.build_shield(
                plan.target,
                &plan.shield_inputs,
                &secrets,
                plan.amount as u64,
                plan.change_address
                    .as_ref()
                    .map(|(_, h)| (*h, plan.change as u64)),
                params_dir,
            )
        }),
        Err(e) => Err(e.into()),
    };
    for s in secrets.iter_mut() {
        crate::keys::wipe(s);
    }
    let built = built?;
    if built.fee_zat != plan.fee as u64 {
        return Err(WalletError::Other(format!(
            "the built fee {} differs from the previewed {}",
            built.fee_zat, plan.fee
        )));
    }
    gate::confirm(validator, GatePath::Shield, &built.raw, |op| {
        wallet.store.utxo_class(op).ok().flatten()
    })
    .await?;
    let reply = client.send_transaction(built.raw.clone()).await?;
    let txid = txid_hex(&built.txid);
    if !reply.is_empty() && reply != txid {
        return Err(WalletError::Other(format!(
            "server replied {reply} for txid {txid}"
        )));
    }
    let reason = format!("spent-by:{txid}");
    for u in &plan.inputs {
        wallet
            .store
            .lock(&u.outpoint, &reason, built.expiry_height as u64)?;
    }
    wallet
        .store
        .insert_pending_tx(&built.txid, &built.raw, built.expiry_height as u64)?;
    let spent: i64 = plan.inputs.iter().map(|u| u.value).sum();
    wallet.store.upsert_history(&HistoryRow {
        txid: built.txid,
        height: 0,
        yec_delta: plan.change - spent,
        has_payload: false,
        pending: true,
        shielded: true,
        yed_delta: 0,
        kind: String::new(),
        verdict: String::new(),
        label: String::new(),
        labelled: true,
    })?;
    if let Some((_, h)) = &plan.change_address {
        wallet.store.mark_used(h)?;
        // The builder writes the one transparent output (the change) at index 0.
        wallet.store.insert_own_output(
            &OutPoint {
                txid: built.txid,
                n: 0,
            },
            plan.change,
            h,
        )?;
    }
    Ok(Confirmed {
        txid,
        params_millis: built.params_millis,
        prove_millis: built.prove_millis,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coins::UtxoClass;
    use crate::keys;
    use crate::params::Network;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A wallet with a private store and the given transparent coins on its first addresses.
    fn wallet_with(name: &str, values: &[(i64, UtxoClass)]) -> (Wallet, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("yew-move-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("w.sqlite");
        let mut w = Wallet::open(
            path.to_str().unwrap(),
            Network::Regtest,
            PHRASE,
            "",
            Some(5),
        )
        .unwrap();
        let rows = w.addresses().unwrap();
        let utxos: Vec<Utxo> = values
            .iter()
            .enumerate()
            .map(|(i, (v, c))| {
                let row = &rows[i % rows.len()];
                Utxo {
                    outpoint: OutPoint {
                        txid: [i as u8 + 1; 32],
                        n: 0,
                    },
                    address: row.address_s.clone(),
                    script: script::p2pkh_script(&row.hash160),
                    value: *v,
                    height: 10,
                    class: *c,
                    cents: 0,
                }
            })
            .collect();
        w.store.replace_utxos(&utxos).unwrap();
        (w, dir)
    }

    fn shield(p: &YecSendPlan) -> &ShieldPlan {
        match &p.funding {
            Funding::Shield(s) => s,
            other => panic!("not a shield: {other:?}"),
        }
    }

    #[test]
    fn shield_spends_plain_yec_only_and_keeps_the_reserve() {
        let (mut w, dir) = wallet_with(
            "only",
            &[
                (100_000_000, UtxoClass::Yec),
                (50_000_000, UtxoClass::Yec),
                (105_000, UtxoClass::FeeReserve),
                (TOKEN_VALUE, UtxoClass::Token),
                (TOKEN_VALUE, UtxoClass::Held),
                (7_000_000, UtxoClass::Vault),
            ],
        );
        let own_z = w.shielded().unwrap().default_address().1;
        // 1 YEC: the smallest coin that covers it, one input + change + two padded Sapling
        // outputs = three logical actions = 15,000 zat; change back to a change address.
        let p = plan_move(&mut w, Direction::ToPrivate, Some(40_000_000), 100).unwrap();
        assert!(!p.reveals_shielded);
        let s = shield(&p);
        assert_eq!(s.to, own_z);
        assert_eq!((s.amount, s.fee, s.inputs.len()), (40_000_000, 15_000, 1));
        assert_eq!(s.inputs[0].value, 50_000_000);
        assert_eq!(s.change, 50_000_000 - 40_000_000 - 15_000);
        assert!(s.change_address.is_some());
        assert_eq!((s.target, s.expiry_height), (101, 141));
        assert_eq!(p.amount_zat(), 40_000_000);
        assert_eq!(p.fee_zat(), 15_000);
        // Two inputs: four logical actions.
        let p = plan_move(&mut w, Direction::ToPrivate, Some(120_000_000), 100).unwrap();
        assert_eq!((shield(&p).inputs.len(), shield(&p).fee), (2, 20_000));
        // All: every YEC coin, never the reserve or anything YED, no change.
        let p = plan_move(&mut w, Direction::ToPrivate, None, 100).unwrap();
        let s = shield(&p);
        assert!(s.inputs.iter().all(|u| u.class == UtxoClass::Yec));
        assert_eq!(s.inputs.len(), 2);
        assert_eq!(
            (s.amount, s.change, s.fee),
            (150_000_000 - 20_000, 0, 20_000)
        );
        assert!(s.change_address.is_none());
        // More than the plain YEC: refused (the reserve is not an override here).
        let e = plan_move(&mut w, Direction::ToPrivate, Some(150_000_000), 100).unwrap_err();
        assert!(matches!(e, WalletError::Coins(_)), "{e}");
        assert!(plan_move(&mut w, Direction::ToPrivate, Some(0), 100).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shield_change_never_looks_like_a_token_or_dust() {
        let (mut w, dir) = wallet_with("change", &[(1_000_000, UtxoClass::Yec)]);
        let fee = 15_000;
        let p = plan_move(
            &mut w,
            Direction::ToPrivate,
            Some(1_000_000 - fee - TOKEN_VALUE),
            7,
        )
        .unwrap();
        let s = shield(&p);
        assert_eq!((s.change, s.amount_bumped), (TOKEN_VALUE - 1, true));
        assert_eq!(s.amount + s.change + s.fee, 1_000_000);
        let p = plan_move(&mut w, Direction::ToPrivate, Some(1_000_000 - fee - 40), 7).unwrap();
        let s = shield(&p);
        assert_eq!(
            (s.change, s.amount, s.amount_bumped),
            (0, 1_000_000 - fee, true)
        );
        assert!(s.change_address.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unshield_goes_to_the_own_public_address_and_needs_a_scan() {
        let (mut w, dir) = wallet_with("unshield", &[]);
        // No scan yet: the private side says so, it never falls back to anything else.
        for amount in [Some(1_000), None] {
            let e = plan_move(&mut w, Direction::ToPublic, amount, 100).unwrap_err();
            assert!(
                matches!(e, WalletError::Shielded(ShieldedError::NotSynced { .. })),
                "{e}"
            );
        }
        // An empty wallet cannot shield either.
        let e = plan_move(&mut w, Direction::ToPrivate, None, 100).unwrap_err();
        assert!(matches!(e, WalletError::Coins(_)), "{e}");
        assert!(keys::parse_address(
            Network::Regtest,
            &w.receive_address(false).unwrap().address_s
        )
        .is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
