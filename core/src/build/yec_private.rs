// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! A YEC send with automatic, **privacy-first** funding (yew-shielded plan §3, S2), and the
//! combined (transparent + shielded) sync the send runs first.
//!
//! Funding rule, one default, no manual choice:
//! 1. A Sapling recipient (`ys1…`) is paid from shielded notes, with an optional memo. Shielded
//!    funds only: YEW's transparent builder makes no Sapling outputs (shielding is S4).
//! 2. A transparent recipient is paid from shielded notes when they cover amount + fee and the
//!    wallet is scanned to the tip; the plan then says [`YecSendPlan::reveals_shielded`] (the
//!    amber line: "This send leaves the private pool"). No memo can go to a transparent address.
//! 3. Otherwise (no or too few spendable notes, the scan behind, or `send_everything`, which
//!    is the transparent fee-reserve override) the transparent path of [`super::yec_send`]
//!    runs exactly as before: same inputs (`YEC` / `FEE_RESERVE` only), same reserve rule,
//!    same gate path.
//!
//! The fee reserve and every YED path stay transparent and untouched: a shielded spend has no
//! transparent input at all (the gate's [`Path::Shielded`] refuses one), so it can neither
//! spend nor strand a token, a vault, a carrier or the reserve.

use std::path::Path;
use std::sync::Arc;

use crate::build::yec_move::ShieldPlan;
use crate::build::yec_send::{self, YecSendPreview};
use crate::gate::{self, Path as GatePath, Validator};
use crate::net::{CompactClient, Server};
use crate::shielded::{self, ShieldedError, ShieldedSyncReport, SpendPlan};
use crate::tx::txid_hex;
use crate::wallet::{Wallet, WalletError};

/// Where a planned send takes its money from.
#[derive(Debug)]
pub enum Funding {
    /// The transparent path (signed already; the existing preview).
    Transparent(YecSendPreview),
    /// Shielded notes (proposed; proved and signed at confirm). Boxed: the proposal is large.
    Shielded(Box<SpendPlan>),
    /// Transparent `YEC` into the wallet's own private balance (a move, S4; proved and signed
    /// at confirm).
    Shield(Box<ShieldPlan>),
}

impl Funding {
    /// Confirm needs the Sapling proving parameters.
    pub fn needs_params(&self) -> bool {
        !matches!(self, Funding::Transparent(_))
    }
}

/// A planned YEC send.
#[derive(Debug)]
pub struct YecSendPlan {
    /// The funding and its builder's preview.
    pub funding: Funding,
    /// Shielded funds go to a transparent address (leaves the private pool).
    pub reveals_shielded: bool,
}

impl YecSendPlan {
    /// The amount paid to the recipient, zat.
    pub fn amount_zat(&self) -> i64 {
        match &self.funding {
            Funding::Transparent(p) => p.amount,
            Funding::Shielded(p) => p.amount_zat as i64,
            Funding::Shield(p) => p.amount,
        }
    }

    /// The fee, zat.
    pub fn fee_zat(&self) -> i64 {
        match &self.funding {
            Funding::Transparent(p) => p.fee,
            Funding::Shielded(p) => p.fee_zat as i64,
            Funding::Shield(p) => p.fee,
        }
    }
}

/// A confirmed (broadcast) send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmed {
    /// The txid, display form.
    pub txid: String,
    /// A private send: milliseconds verifying and loading the proving parameters (0 once
    /// loaded in this session).
    pub params_millis: u64,
    /// A private send: milliseconds proving and signing.
    pub prove_millis: u64,
}

/// Plan a YEC send of `amount` zat to `to` by the funding rule above, after a sync at `tip`
/// with the server's `branch_id` (the transparent path signs with it). `memo` is for Sapling
/// recipients only.
pub fn plan_yec_send(
    wallet: &mut Wallet,
    to: &str,
    amount: i64,
    send_everything: bool,
    memo: Option<&str>,
    tip: u64,
    branch_id: u32,
) -> Result<YecSendPlan, WalletError> {
    if amount <= 0 {
        return Err(WalletError::Other("amount must be positive".into()));
    }
    let to = to.trim();
    let memo = memo.map(str::trim_end).filter(|m| !m.is_empty());
    let sapling_recipient = crate::shielded_keys::is_sapling_address(wallet.network, to);
    if sapling_recipient {
        let plan = wallet.shielded_mut()?.plan(to, amount as u64, memo)?;
        return Ok(YecSendPlan {
            funding: Funding::Shielded(Box::new(plan)),
            reveals_shielded: false,
        });
    }
    if memo.is_some() {
        return Err(ShieldedError::Memo(
            "A memo can only be sent to a private (ys1…) address.".into(),
        )
        .into());
    }
    // Validate the transparent recipient before looking at notes, so a bad address is an
    // input error whichever pool would have paid.
    crate::keys::parse_address(wallet.network, to)?;
    if !send_everything {
        if let Some(sh) = wallet.shielded.as_mut() {
            let b = sh.balance()?;
            if b.sendable && b.spendable_zat >= amount as u64 {
                match sh.plan(to, amount as u64, None) {
                    Ok(plan) => {
                        return Ok(YecSendPlan {
                            funding: Funding::Shielded(Box::new(plan)),
                            reveals_shielded: true,
                        })
                    }
                    // Not enough for amount + fee, or not scanned: the transparent path pays.
                    Err(ShieldedError::Insufficient { .. } | ShieldedError::NotSynced { .. }) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    let p = yec_send::build_yec_send(wallet, to, amount, send_everything, tip, branch_id)?;
    Ok(YecSendPlan {
        funding: Funding::Transparent(p),
        reveals_shielded: false,
    })
}

/// Confirm a planned send: the transparent path exactly as `yec_send::broadcast`; the shielded
/// path checks the server's next-block branch id against the wallet's Ycash parameters, proves
/// and signs with the parameters in `params_dir` (verified against their pins), runs both gate
/// layers ([`GatePath::Shielded`]) and broadcasts.
pub async fn confirm_yec_send(
    wallet: &mut Wallet,
    client: &mut CompactClient,
    validator: &mut Validator,
    plan: &YecSendPlan,
    params_dir: &Path,
) -> Result<Confirmed, WalletError> {
    match &plan.funding {
        Funding::Shield(p) => {
            crate::build::yec_move::confirm_shield(wallet, client, validator, p, params_dir).await
        }
        Funding::Transparent(p) => Ok(Confirmed {
            txid: yec_send::broadcast(wallet, client, validator, p).await?,
            params_millis: 0,
            prove_millis: 0,
        }),
        Funding::Shielded(p) => {
            // The next block's branch id (GetChainInfo), else the chaintip's (older server).
            let chain = match validator.client_mut() {
                Some(yb) => yb.chain_info().await?,
                None => None,
            };
            let network = wallet.network;
            let sh = wallet.shielded_mut()?;
            match chain {
                Some((height, id)) => sh.check_branch(height, id, true)?,
                None => {
                    let info = client.lightd_info_for(network).await?;
                    sh.check_branch(info.block_height, info.branch_id, false)?
                }
            }
            let built = sh.build(p, params_dir)?;
            gate::confirm(validator, GatePath::Shielded, &built.raw, |_| None).await?;
            let reply = client.send_transaction(built.raw.clone()).await?;
            let txid = txid_hex(&built.txid);
            if !reply.is_empty() && reply != txid {
                return Err(WalletError::Other(format!(
                    "server replied {reply} for txid {txid}"
                )));
            }
            Ok(Confirmed {
                txid,
                params_millis: built.params_millis,
                prove_millis: built.prove_millis,
            })
        }
    }
}

/// The shielded sync of `wallet` from its birthday. The light library scans over `client`'s
/// channel (YEW's TLS settings, roots and certificate pin, Z-3); `server` gives the label it
/// reports. Memos and status go through `client` as well. A server with a pinned certificate
/// is still refused here (the S2 rule); lifting it now that the channel carries the pin is
/// an owner decision.
pub async fn sync_shielded(
    wallet: &mut Wallet,
    server: &Server,
    client: &mut CompactClient,
    progress: shielded::ProgressFn,
) -> Result<ShieldedSyncReport, WalletError> {
    if server.ca_pem.is_some() {
        return Err(WalletError::Other(
            "Private sync cannot use a pinned certificate yet; remove the pin to sync private YEC."
                .into(),
        ));
    }
    // The restore field (the wallet's birthday) seeds the private account's birthday; a seed
    // this wallet generated without one starts at the current tip (nothing can predate it).
    let birthday = wallet.birthday()?;
    let new_seed = wallet.store.meta("new_seed")?.as_deref() == Some("1");
    let lwd = shielded::light_endpoint(&server.host, server.port, server.plain);
    let sh = wallet.shielded_mut()?;
    let birthday = if birthday == 0 && new_seed {
        None
    } else {
        Some(birthday.max(sh.sapling_activation()))
    };
    Ok(sh.sync(&lwd, birthday, client, progress).await?)
}

/// A progress callback that ignores every tick.
pub fn no_progress() -> shielded::ProgressFn {
    Arc::new(|_| {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use crate::params::Network;
    use crate::shielded_keys::SaplingAccount;
    use crate::store::Store;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> Wallet {
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        Wallet::from_parts(
            Store::open_in_memory().unwrap(),
            Network::Regtest,
            &seed,
            Some(5),
        )
        .unwrap()
    }

    #[test]
    fn funding_rules_before_any_note() {
        let mut w = wallet();
        let t = keys::encode_p2pkh(Network::Regtest, &[3; 20]);
        let z = SaplingAccount::from_mnemonic(PHRASE, "", Network::Regtest)
            .unwrap()
            .default_address()
            .1;
        // No amount, a memo to a transparent address, a bad address: refused up front.
        assert!(plan_yec_send(&mut w, &t, 0, false, None, 100, 1).is_err());
        let e = plan_yec_send(&mut w, &t, 1_000, false, Some("hi"), 100, 1).unwrap_err();
        assert!(e.to_string().contains("private (ys1…) address"), "{e}");
        assert!(plan_yec_send(&mut w, "s1nope", 1_000, false, None, 100, 1).is_err());
        // A whitespace-only memo is no memo: the transparent path is tried (and has no coins).
        let e = plan_yec_send(&mut w, &t, 1_000, false, Some("  "), 100, 1).unwrap_err();
        assert!(matches!(e, WalletError::Coins(_)), "{e}");
        // A ys1 recipient needs the private side; a wallet without one says so.
        let e = plan_yec_send(&mut w, &z, 1_000, false, Some("hi"), 100, 1).unwrap_err();
        assert!(e.to_string().contains("no shielded store"), "{e}");
    }

    #[test]
    fn a_private_store_without_notes_falls_back_or_refuses() {
        let dir = std::env::temp_dir().join(format!("yew-yecpriv-{}", std::process::id()));
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
        assert!(dir.join("shielded/w/wallet.sqlite").is_file());
        let z = w.shielded().unwrap().default_address().1;
        // Not scanned: a private recipient is "not ready", never silently transparent.
        let e = plan_yec_send(&mut w, &z, 1_000, false, None, 100, 1).unwrap_err();
        assert!(
            matches!(e, WalletError::Shielded(ShieldedError::NotSynced { .. })),
            "{e}"
        );
        // A transparent recipient falls through to the transparent builder (no coins here).
        let t = keys::encode_p2pkh(Network::Regtest, &[3; 20]);
        let e = plan_yec_send(&mut w, &t, 1_000, false, None, 100, 1).unwrap_err();
        assert!(matches!(e, WalletError::Coins(_)), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Z-3: the light library's scan runs over YEW's own channel, never a connection of its
    /// own. The server label points at one listener, YEW's TLS channel at another: only the
    /// channel's listener is dialed, and it receives a TLS ClientHello (YEW's TLS config).
    #[tokio::test]
    async fn shielded_sync_uses_the_wallets_channel() {
        use tokio::io::AsyncReadExt;
        let dir = std::env::temp_dir().join(format!("yew-yecchan-{}", std::process::id()));
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
        let listen = || async { tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap() };
        let (channel_side, label_side) = (listen().await, listen().await);
        let first_bytes = |l: tokio::net::TcpListener| {
            tokio::spawn(async move {
                let (mut s, _) = l.accept().await.unwrap();
                let mut b = [0u8; 3];
                s.read_exact(&mut b).await.unwrap();
                b
            })
        };
        let channel_port = channel_side.local_addr().unwrap().port();
        let label_addr = label_side.local_addr().unwrap();
        let hello = first_bytes(channel_side);
        let untouched = first_bytes(label_side);
        let ours = Server::parse(&format!("localhost:{channel_port}"), false).unwrap();
        let channel = ours.endpoint().unwrap().connect_lazy();
        let mut client = CompactClient::from_channel(channel);
        let label = Server::parse(&format!("127.0.0.1:{}", label_addr.port()), false).unwrap();
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            sync_shielded(&mut w, &label, &mut client, no_progress()),
        )
        .await
        .expect("the sync gives up on a server that never answers");
        assert!(r.is_err());
        let b = tokio::time::timeout(std::time::Duration::from_secs(5), hello)
            .await
            .expect("YEW's channel was dialed")
            .unwrap();
        assert_eq!(b, [0x16, 0x03, 0x01], "a TLS ClientHello on YEW's channel");
        assert!(
            !untouched.is_finished(),
            "the label's address was never dialed"
        );
        untouched.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
