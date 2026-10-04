// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The Ycash shielded (Sapling) side of the wallet (yew-shielded plan S2): one Sapling account
//! (ZIP-32 `m/32'/347'/0'` of the YEW seed, [`crate::shielded_keys`]) kept in a
//! `zcash_client_sqlite` store under `shielded/<wallet file stem>/` beside the transparent store,
//! synced by the Ycash light client `x402_ycash_light` (boyfromcave/x402-ycash `light/`).
//!
//! **Who does what.**
//! - The light library ([`LightWallet`]) owns compact-block sync: overlapped download and scan
//!   from lightwalletd-dd, the `GetTreeState` checkpoint at the birthday, checkpoint reorg
//!   rewinds, the synthesized tree sizes the 0.4.6 wire format lacks (its `sync.rs`). It is
//!   opened lazily at the first sync (it connects on open) and registers the account once.
//! - This module reads and writes the same store through its own `WalletDb` handle: balances
//!   (offline), the spend path (privacy-first funding is decided in `api.rs`; here: proposal
//!   with the ZIP-317 fee for the preview, then prove and sign at confirm, transparent recipients
//!   included), memo enhancement (`GetTransaction` + `decrypt_and_store_transaction`, which the
//!   light library does not do: compact outputs carry no memo), transaction status, history.
//! - Network calls other than the light library's sync go through YEW's own channel
//!   ([`CompactClient`]), so broadcast and memo fetches use YEW's TLS settings and CA pin.
//!
//! **Keys.** The spending key is never written by YEW. The store holds the account's viewing
//! key (the UFVK `import_account_ufvk` records: Sapling full viewing key only) and the wallet's
//! decrypted notes, memos and transactions — privacy-sensitive, not spend-capable; it lives in
//! the app's private, backup-excluded data directory. The light library receives the spending
//! key only for the one `register_key` call that creates the account and is then reopened
//! without it; a spend builds a transient unified spending key and drops it.
//! `tests::no_spending_key_in_any_file` checks every file under the directory.
//!
//! **Spendability.** Ycash has no `GetSubtreeRoots`, so a note has a witness only once the
//! wallet has scanned from its birthday to the tip: [`ShieldedBalance::sendable`] is that flag
//! ("sending available at 100 %"), and [`Shielded::plan`] refuses before it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use thiserror::Error;
use tonic::transport::Channel;
use x402_ycash_light::{Options as LightOptions, Wallet as LightWallet, YcashNetwork};
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, decrypt_and_store_transaction,
    propose_standard_transfer_to_address, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{
    Account as _, TransactionDataRequest, TransactionStatus, WalletRead, WalletSummary, WalletWrite,
};
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId, WalletDb};
use zcash_keys::address::Address;
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::zip317;
use zcash_primitives::transaction::Transaction as ZTransaction;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters};
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{ShieldedProtocol, TxId};
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_transparent::bundle::{OutPoint, TxOut};

use crate::net::{CompactClient, NetError};
use crate::params::{Network, TOKEN_VALUE};
use crate::sapling_params::{self, ParamsError};
use crate::shielded_keys::SaplingAccount;

/// The note store type: `zcash_client_sqlite` over Ycash parameters.
pub type Db = WalletDb<rusqlite::Connection, YcashNetwork, SystemClock, OsRng>;

/// The longest memo text (ZIP-302: 512 bytes, UTF-8).
pub const MAX_MEMO_BYTES: usize = 512;
/// Transaction data requests (memo fetches, status checks) answered per sync.
const MAX_ENHANCE_PER_SYNC: usize = 500;
/// How often the progress ticker reads the store during a scan.
const PROGRESS_EVERY: Duration = Duration::from_millis(400);

/// Stops the progress ticker when the sync that started it ends, returns early or is dropped
/// mid-await (an abandoned sync must not keep reading the store; S5).
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Shielded errors. The text is showable.
#[derive(Debug, Error)]
pub enum ShieldedError {
    /// The note store.
    #[error("private wallet store: {0}")]
    Store(String),
    /// The light client (sync, registration).
    #[error("private sync: {0}")]
    Light(x402_ycash_light::wallet::Error),
    /// The server's compact-block cache trails its node for a moment: sync again shortly.
    #[error("The server is still catching up (wallet at {wallet}, server at {server}); try again in a moment.")]
    ServerBehind {
        /// The wallet's tip (0 = none yet).
        wallet: u64,
        /// The server's tip.
        server: u64,
    },
    /// Another open wallet holds this private store (one per store per process).
    #[error("The private wallet is already open elsewhere in this app; close it and try again.")]
    Busy,
    /// YEW's own network calls.
    #[error(transparent)]
    Net(#[from] NetError),
    /// The proving parameters.
    #[error(transparent)]
    Params(#[from] ParamsError),
    /// The store holds another seed's account.
    #[error("the private wallet store belongs to another seed")]
    OtherSeed,
    /// Scanning has not reached the tip: no note has a witness yet.
    #[error("Private YEC can be sent once sync reaches 100% (scanned to {scanned}, tip {tip}).")]
    NotSynced {
        /// Fully scanned height.
        scanned: u64,
        /// The chain tip the store knows.
        tip: u64,
    },
    /// Not enough shielded funds.
    #[error("Not enough private YEC: {available} zat spendable, {required} zat needed (amount plus fee).")]
    Insufficient {
        /// Spendable zat.
        available: u64,
        /// Amount plus fee.
        required: u64,
    },
    /// A recipient this path cannot pay.
    #[error("{0}")]
    Address(String),
    /// A memo that cannot be sent.
    #[error("{0}")]
    Memo(String),
    /// The server's branch id disagrees with ours for the next block.
    #[error("branch id mismatch: the server wants {server:08x} for height {height}, this wallet's Ycash parameters give {ours:08x}")]
    Branch {
        /// The height compared.
        height: u64,
        /// The server's id.
        server: u32,
        /// Ours.
        ours: u32,
    },
    /// The proposal could not be made.
    #[error("cannot plan the private send: {0}")]
    Propose(String),
    /// Proving / signing failed.
    #[error("cannot build the private send: {0}")]
    Create(String),
}

impl From<x402_ycash_light::wallet::Error> for ShieldedError {
    fn from(e: x402_ycash_light::wallet::Error) -> Self {
        use x402_ycash_light::wallet::Error as L;
        match e {
            L::NotAtServerTip { wallet, server } => ShieldedError::ServerBehind {
                wallet: wallet.unwrap_or(0) as u64,
                server: server as u64,
            },
            L::Locked(_) => ShieldedError::Busy,
            other => ShieldedError::Light(other),
        }
    }
}

fn store_err(e: impl std::fmt::Display) -> ShieldedError {
    ShieldedError::Store(e.to_string())
}

/// The Ycash consensus parameters of a YEW network, as the light library knows them: mainnet and
/// testnet from librustzcash6's Ycash constants; regtest is the Yellowback devnets' (every
/// upgrade through Canopy at height 1, no NU5), which the light library checks against the
/// server's branch id on every sync.
pub fn ycash_network(n: Network) -> YcashNetwork {
    match n {
        Network::Mainnet => YcashNetwork::Main,
        Network::Testnet => YcashNetwork::Test,
        Network::Regtest => YcashNetwork::devnet_regtest(),
    }
}

/// The shielded store directory for a transparent store at `wallet_path`:
/// `<dir>/shielded/<file stem>/` (`yew-regtest.sqlite` → `shielded/yew-regtest/`).
pub fn shielded_dir(wallet_path: &Path) -> PathBuf {
    let parent = wallet_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = wallet_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wallet".into());
    parent.join("shielded").join(stem)
}

/// The shielded balance (one confirmation, the node's `z_sendmany` default).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShieldedBalance {
    /// Every unspent note, zat.
    pub total_zat: u64,
    /// Spendable now, zat (0 until scanning reaches the tip).
    pub spendable_zat: u64,
    /// Own change waiting for its confirmation, zat.
    pub pending_change_zat: u64,
    /// Received but not yet spendable (unconfirmed, or the scan is behind), zat.
    pub pending_incoming_zat: u64,
    /// The height scanned without gaps from the birthday (0 = never).
    pub scanned_height: u64,
    /// The chain tip as of the last sync (0 = never).
    pub tip_height: u64,
    /// Scanned to the tip: notes have witnesses, sending is available.
    pub sendable: bool,
    /// The account exists in the store (registered at the first sync).
    pub registered: bool,
}

/// A progress tick of the shielded scan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShieldedProgress {
    /// The fully scanned height.
    pub scanned_height: u64,
    /// The tip being scanned to.
    pub tip_height: u64,
    /// 0..=100, by Sapling outputs scanned in the ranges still to scan.
    pub percent: u8,
    /// Scanning has finished and memos/status are being fetched.
    pub enhancing: bool,
}

/// The progress callback (called from the ticker task and at the end).
pub type ProgressFn = Arc<dyn Fn(ShieldedProgress) + Send + Sync>;

/// What one shielded sync did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShieldedSyncReport {
    /// The tip scanned to.
    pub tip: u64,
    /// The fully scanned height afterwards.
    pub scanned_height: u64,
    /// Blocks scanned this run.
    pub blocks: u64,
    /// Sapling outputs trial-decrypted this run.
    pub outputs: u64,
    /// Notes received this run.
    pub received_notes: u64,
    /// Own notes seen spent this run.
    pub spent_notes: u64,
    /// Reorgs handled (each a ten-block rewind in the light library, or a rewind to the
    /// birthday when the store refuses that one; Z-9, fixed in the library).
    pub reorgs: u64,
    /// Of `reorgs`, those the light library answered by rewinding to the account birthday.
    pub birthday_rewinds: u64,
    /// Transactions fetched in full for memos.
    pub enhanced: u64,
    /// Status answers given to the store (mined / not in chain / unknown).
    pub statuses: u64,
    /// The account was registered in this run (first sync).
    pub registered_now: bool,
    /// Scanned to the tip.
    pub sendable: bool,
    /// Wall time, milliseconds.
    pub millis: u64,
}

/// A planned shielded spend (the preview): nothing proved, nothing stored, no note locked.
pub struct SpendPlan {
    /// The recipient as given.
    pub to: String,
    /// The amount paid, zat (after the `TOKEN_VALUE` bump for a transparent recipient).
    pub amount_zat: u64,
    /// The amount was bumped from exactly `TOKEN_VALUE`.
    pub amount_bumped: bool,
    /// The ZIP-317 fee, zat.
    pub fee_zat: u64,
    /// Shielded change back to the wallet, zat.
    pub change_zat: u64,
    /// Notes spent.
    pub notes: u32,
    /// The memo text, if any.
    pub memo: Option<String>,
    /// The recipient is transparent: funds leave the shielded pool.
    pub transparent_recipient: bool,
    /// `nExpiryHeight` the transaction will have (target height + 40, the builder's default).
    pub expiry_height: u32,
    proposal: Proposal<StandardFeeRule, ReceivedNoteId>,
}

impl std::fmt::Debug for SpendPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendPlan")
            .field("to", &self.to)
            .field("amount_zat", &self.amount_zat)
            .field("fee_zat", &self.fee_zat)
            .field("change_zat", &self.change_zat)
            .field("notes", &self.notes)
            .field("transparent_recipient", &self.transparent_recipient)
            .finish()
    }
}

/// A proved and signed shielded spend, recorded in the store (its notes are spent until it
/// expires unmined), ready for the gate and `SendTransaction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendBuilt {
    /// The raw transaction.
    pub raw: Vec<u8>,
    /// The txid, internal byte order.
    pub txid: [u8; 32],
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The fee paid, zat.
    pub fee_zat: u64,
    /// Milliseconds spent verifying and loading the proving parameters (0 when cached).
    pub params_millis: u64,
    /// Milliseconds spent proving and signing.
    pub prove_millis: u64,
}

/// A transparent P2PKH coin a shielding transaction spends (selected by YEW's coin rules).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldInput {
    /// Txid, internal byte order.
    pub txid: [u8; 32],
    /// Output index.
    pub n: u32,
    /// Value, zat.
    pub value: u64,
    /// The compressed public key of the P2PKH output.
    pub pubkey: [u8; 33],
    /// `HASH160(pubkey)`.
    pub hash160: [u8; 20],
}

fn zat(v: u64) -> Result<Zatoshis, ShieldedError> {
    Zatoshis::from_u64(v).map_err(|_| ShieldedError::Propose(format!("bad amount {v}")))
}

/// One shielded history row (from the store's `v_transactions` / `v_tx_outputs`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShieldedTx {
    /// Txid, internal byte order.
    pub txid: [u8; 32],
    /// Mined height (0 while unmined).
    pub height: u64,
    /// Net change of the shielded balance, zat (negative = sent; fee included).
    pub delta_zat: i64,
    /// The fee, when the wallet knows it (own sends).
    pub fee_zat: Option<u64>,
    /// The first text memo of a received or sent output, or empty.
    pub memo: String,
    /// Unmined and past its expiry height.
    pub expired: bool,
}

/// The shielded wallet.
pub struct Shielded {
    network: Network,
    params: YcashNetwork,
    dir: PathBuf,
    db: Db,
    account: SaplingAccount,
    light: Option<LightWallet>,
    light_lwd: String,
    /// The loaded prover (parameters verified once, parsed once per session).
    prover: Option<(PathBuf, LocalTxProver)>,
}

impl std::fmt::Debug for Shielded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Shielded({:?}, {})", self.network, self.dir.display())
    }
}

fn policy() -> ConfirmationsPolicy {
    x402_ycash_light::wallet::default_policy()
}

fn percent_of(s: &WalletSummary<AccountUuid>) -> u8 {
    if s.is_synced() {
        return 100;
    }
    let r = s.progress().scan();
    if *r.denominator() == 0 {
        return 0;
    }
    ((r.numerator().saturating_mul(100)) / r.denominator()).min(99) as u8
}

impl Shielded {
    /// Open (creating if needed) the store under `dir` for `account` on `network`. Offline:
    /// the light client connects at the first [`Shielded::sync`]. A store holding another
    /// seed's account is refused.
    pub fn open(
        dir: &Path,
        network: Network,
        account: SaplingAccount,
    ) -> Result<Shielded, ShieldedError> {
        std::fs::create_dir_all(dir).map_err(store_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let params = ycash_network(network);
        let mut db = WalletDb::for_path(dir.join("wallet.sqlite"), params, SystemClock, OsRng)
            .map_err(store_err)?;
        init_wallet_db(&mut db, None).map_err(store_err)?;
        let s = Shielded {
            network,
            params,
            dir: dir.to_path_buf(),
            db,
            account,
            light: None,
            light_lwd: String::new(),
            prover: None,
        };
        s.check_account()?;
        Ok(s)
    }

    fn account_id(&self) -> Result<Option<AccountUuid>, ShieldedError> {
        Ok(self
            .db
            .get_account_ids()
            .map_err(store_err)?
            .into_iter()
            .next())
    }

    /// The store's account must be ours (same viewing key).
    fn check_account(&self) -> Result<(), ShieldedError> {
        let Some(id) = self.account_id()? else {
            return Ok(());
        };
        let acct = self
            .db
            .get_account(id)
            .map_err(store_err)?
            .ok_or_else(|| store_err("account vanished"))?;
        let theirs = acct
            .ufvk()
            .and_then(|k| k.sapling().map(|d| d.to_bytes()))
            .ok_or(ShieldedError::OtherSeed)?;
        if theirs != self.account.viewing_key_bytes() {
            return Err(ShieldedError::OtherSeed);
        }
        Ok(())
    }

    /// The store directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The default shielded address (`ys1…` on mainnet) and its diversifier index.
    pub fn default_address(&self) -> (u64, String) {
        self.account.default_address()
    }

    /// A diversified address at the first valid index at or after `index`.
    pub fn address_at(&self, index: u64) -> Result<(u64, String), ShieldedError> {
        self.account
            .address_at(index)
            .map_err(|e| ShieldedError::Address(e.to_string()))
    }

    /// Is `s` a Sapling address of this network?
    pub fn is_address(&self, s: &str) -> bool {
        crate::shielded_keys::is_sapling_address(self.network, s)
    }

    /// The account is in the store.
    pub fn registered(&self) -> Result<bool, ShieldedError> {
        Ok(self.account_id()?.is_some())
    }

    /// The balance from the store (no network).
    pub fn balance(&self) -> Result<ShieldedBalance, ShieldedError> {
        let Some(id) = self.account_id()? else {
            return Ok(ShieldedBalance::default());
        };
        let mut out = ShieldedBalance {
            registered: true,
            ..Default::default()
        };
        if let Some(s) = self.db.get_wallet_summary(policy()).map_err(store_err)? {
            out.scanned_height = u32::from(s.fully_scanned_height()) as u64;
            out.tip_height = u32::from(s.chain_tip_height()) as u64;
            out.sendable = s.is_synced();
            if let Some(b) = s.account_balances().get(&id) {
                let sb = b.sapling_balance();
                out.total_zat = sb.total().into_u64();
                out.spendable_zat = sb.spendable_value().into_u64();
                out.pending_change_zat = sb.change_pending_confirmation().into_u64();
                out.pending_incoming_zat = sb.value_pending_spendability().into_u64();
            }
        }
        Ok(out)
    }

    /// Open the light client over `channel` (YEW's own: its TLS settings, the webpki roots and
    /// any pinned certificate; Z-3) if it is not open for `lwd` already. `lwd` is only the
    /// label the light library reports; it never dials it. The light wallet locks the store
    /// directory while open, so the previous one is dropped before the next is opened.
    async fn light(
        &mut self,
        lwd: &str,
        channel: &Channel,
    ) -> Result<&mut LightWallet, ShieldedError> {
        if self.light.is_none() || self.light_lwd != lwd {
            self.light = None;
            let w = LightWallet::open(LightOptions {
                channel: Some(channel.clone()),
                ..LightOptions::new(self.dir.clone(), lwd, self.params)
            })
            .await?;
            self.light = Some(w);
            self.light_lwd = lwd.to_string();
        }
        Ok(self.light.as_mut().expect("opened above"))
    }

    /// Drop the light client (its connection); the next sync reopens it.
    pub fn disconnect(&mut self) {
        self.light = None;
    }

    /// One shielded sync: register the account at `birthday` on the first run (`None`: the
    /// current tip, for a seed generated by this wallet), scan to the tip
    /// (the light library; resumable, reorgs rewound there), then fetch memos and answer status
    /// requests through `client`. `progress` ticks while scanning.
    pub async fn sync(
        &mut self,
        lwd: &str,
        birthday: Option<u64>,
        client: &mut CompactClient,
        progress: ProgressFn,
    ) -> Result<ShieldedSyncReport, ShieldedError> {
        let channel = client.channel();
        let started = Instant::now();
        let mut report = ShieldedSyncReport::default();
        if !self.registered()? {
            let extsk = self.account.extended_spending_key();
            let light = self.light(lwd, &channel).await?;
            light
                .register_key(
                    extsk,
                    birthday.map(|b| u32::try_from(b).unwrap_or(u32::MAX)),
                )
                .await?;
            // The light wallet now holds the key in memory; reopen it without.
            self.light = None;
            report.registered_now = true;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_guard = StopOnDrop(stop.clone());
        let ticker = {
            let stop = stop.clone();
            let path = self.dir.join("wallet.sqlite");
            let params = self.params;
            let progress = progress.clone();
            tokio::spawn(async move {
                let Ok(db) = WalletDb::for_path(&path, params, SystemClock, OsRng) else {
                    return;
                };
                while !stop.load(Ordering::SeqCst) {
                    if let Ok(Some(s)) = db.get_wallet_summary(policy()) {
                        progress(ShieldedProgress {
                            scanned_height: u32::from(s.fully_scanned_height()) as u64,
                            tip_height: u32::from(s.chain_tip_height()) as u64,
                            percent: percent_of(&s),
                            enhancing: false,
                        });
                    }
                    tokio::time::sleep(PROGRESS_EVERY).await;
                }
            })
        };
        // Reorgs, including those within ten blocks of the birthday (Z-9), are rewound in
        // the light library.
        let r = match self.light(lwd, &channel).await {
            Ok(l) => l
                .sync(x402_ycash_light::sync::DEFAULT_CHUNK_BLOCKS)
                .await
                .map_err(ShieldedError::from),
            Err(e) => Err(e),
        };
        drop(stop_guard);
        let _ = ticker.await;
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                // A failed connection is reopened next time.
                self.light = None;
                return Err(e);
            }
        };
        report.tip = r.tipHeight as u64;
        report.blocks = r.blocksScanned as u64;
        report.outputs = r.outputsScanned;
        report.received_notes = r.receivedNotes as u64;
        report.spent_notes = r.spentNotes as u64;
        report.reorgs = r.reorgs as u64;
        report.birthday_rewinds = r.birthdayRewinds as u64;

        let b = self.balance()?;
        progress(ShieldedProgress {
            scanned_height: b.scanned_height,
            tip_height: b.tip_height,
            percent: if b.sendable { 100 } else { 99 },
            enhancing: true,
        });
        let (enhanced, statuses) = self.enhance(client, report.tip).await?;
        report.enhanced = enhanced;
        report.statuses = statuses;
        let b = self.balance()?;
        report.scanned_height = b.scanned_height;
        report.sendable = b.sendable;
        report.millis = started.elapsed().as_millis() as u64;
        progress(ShieldedProgress {
            scanned_height: b.scanned_height,
            tip_height: b.tip_height,
            percent: if b.sendable { 100 } else { 99 },
            enhancing: false,
        });
        Ok(report)
    }

    /// Answer the store's transaction data requests: full transactions for memos
    /// (`Enhancement`), mined / not-in-chain / unknown for `GetStatus`. Returns the counts.
    async fn enhance(
        &mut self,
        client: &mut CompactClient,
        tip: u64,
    ) -> Result<(u64, u64), ShieldedError> {
        let requests = self.db.transaction_data_requests().map_err(store_err)?;
        let (mut enhanced, mut statuses) = (0u64, 0u64);
        for req in requests.into_iter().take(MAX_ENHANCE_PER_SYNC) {
            #[allow(unreachable_patterns)] // the transparent-inputs variant is not compiled in
            match req {
                TransactionDataRequest::Enhancement(txid) => {
                    match client.get_transaction(txid.as_ref()).await? {
                        Some((data, height)) => {
                            let mined = (height > 0).then(|| BlockHeight::from_u32(height as u32));
                            let branch = BranchId::for_height(
                                &self.params,
                                mined.unwrap_or(BlockHeight::from_u32(tip as u32 + 1)),
                            );
                            let tx = ZTransaction::read(&data[..], branch).map_err(|e| {
                                store_err(format!("transaction {txid} does not parse: {e}"))
                            })?;
                            if tx.txid() != txid {
                                return Err(store_err(format!(
                                    "the server answered {} for transaction {txid}",
                                    tx.txid()
                                )));
                            }
                            decrypt_and_store_transaction(&self.params, &mut self.db, &tx, mined)
                                .map_err(store_err)?;
                            enhanced += 1;
                        }
                        None => {
                            self.db
                                .set_transaction_status(txid, TransactionStatus::TxidNotRecognized)
                                .map_err(store_err)?;
                            statuses += 1;
                        }
                    }
                }
                TransactionDataRequest::GetStatus(txid) => {
                    let status = match client.get_transaction(txid.as_ref()).await? {
                        Some((_, h)) if h > 0 => {
                            TransactionStatus::Mined(BlockHeight::from_u32(h as u32))
                        }
                        Some(_) => TransactionStatus::NotInMainChain,
                        None => TransactionStatus::TxidNotRecognized,
                    };
                    self.db
                        .set_transaction_status(txid, status)
                        .map_err(store_err)?;
                    statuses += 1;
                }
                _ => {}
            }
        }
        Ok((enhanced, statuses))
    }

    /// Refuse to build unless our parameters give the server's branch id: `server_height` and
    /// `server_branch` from `GetChainInfo` (`next_block`: the id is the next block's) or, from
    /// an older server, `GetLightdInfo`'s chaintip id.
    pub fn check_branch(
        &self,
        server_height: u64,
        server_branch: u32,
        next_block: bool,
    ) -> Result<(), ShieldedError> {
        let at = if next_block {
            server_height + 1
        } else {
            server_height
        };
        let ours = u32::from(self.params.branch_id_at(BlockHeight::from_u32(at as u32)));
        if ours != server_branch {
            return Err(ShieldedError::Branch {
                height: at,
                server: server_branch,
                ours,
            });
        }
        Ok(())
    }

    /// Plan a shielded spend of `amount_zat` to `to` (a Sapling address of this network, or a
    /// transparent `s…` / `t…` one) with an optional text memo (Sapling recipients only, at most
    /// [`MAX_MEMO_BYTES`] bytes of UTF-8). ZIP-317 fee, change to the wallet's Sapling account,
    /// greedy note selection. Nothing is proved, stored or locked.
    pub fn plan(
        &mut self,
        to: &str,
        amount_zat: u64,
        memo: Option<&str>,
    ) -> Result<SpendPlan, ShieldedError> {
        let id = self
            .account_id()?
            .ok_or(ShieldedError::NotSynced { scanned: 0, tip: 0 })?;
        let b = self.balance()?;
        if !b.sendable {
            return Err(ShieldedError::NotSynced {
                scanned: b.scanned_height,
                tip: b.tip_height,
            });
        }
        let to = to.trim();
        let addr = Address::decode(&self.params, to).ok_or_else(|| {
            ShieldedError::Address(format!("{to} is not a Ycash address of this network"))
        })?;
        let transparent = match addr {
            Address::Sapling(_) => false,
            Address::Transparent(_) => true,
            _ => {
                return Err(ShieldedError::Address(format!(
                    "{to}: YEW pays Sapling (ys1…) and transparent (s1…) addresses only"
                )))
            }
        };
        let memo = memo.map(str::trim_end).filter(|m| !m.is_empty());
        let memo_bytes = match memo {
            None => None,
            Some(_) if transparent => {
                return Err(ShieldedError::Memo(
                    "A memo can only be sent to a private (ys1…) address.".into(),
                ))
            }
            Some(m) => Some(memo_to_bytes(m)?),
        };
        if amount_zat == 0 {
            return Err(ShieldedError::Propose("amount must be positive".into()));
        }
        // A transparent output of exactly TOKEN_VALUE would look like a YED token (plan §3.7).
        let (amount_zat, amount_bumped) = if transparent && amount_zat == TOKEN_VALUE as u64 {
            (amount_zat + 1, true)
        } else {
            (amount_zat, false)
        };
        let amount = Zatoshis::from_u64(amount_zat)
            .map_err(|_| ShieldedError::Propose(format!("bad amount {amount_zat}")))?;
        let params = self.params;
        let proposal = propose_standard_transfer_to_address::<_, _, std::convert::Infallible>(
            &mut self.db,
            &params,
            StandardFeeRule::Zip317,
            id,
            policy(),
            &addr,
            amount,
            memo_bytes,
            None,
            ShieldedProtocol::Sapling,
            None,
        )
        .map_err(|e| {
            use zcash_client_backend::data_api::error::Error as E;
            match e {
                E::InsufficientFunds {
                    available,
                    required,
                }
                | E::Change(zcash_client_backend::fees::ChangeError::InsufficientFunds {
                    available,
                    required,
                }) => ShieldedError::Insufficient {
                    available: available.into_u64(),
                    required: required.into_u64(),
                },
                E::ScanRequired => ShieldedError::NotSynced {
                    scanned: b.scanned_height,
                    tip: b.tip_height,
                },
                other => ShieldedError::Propose(other.to_string()),
            }
        })?;
        if proposal.steps().len() != 1 {
            return Err(ShieldedError::Propose(format!(
                "expected one transaction, planned {}",
                proposal.steps().len()
            )));
        }
        let step = &proposal.steps().head;
        let fee_zat = step.balance().fee_required().into_u64();
        let change_zat = step
            .balance()
            .proposed_change()
            .iter()
            .map(|c| c.value().into_u64())
            .sum();
        let target = u32::from(BlockHeight::from(proposal.min_target_height()));
        let expiry_height =
            target.saturating_add(zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA);
        let notes = step
            .shielded_inputs()
            .map(|i| i.notes().len() as u32)
            .unwrap_or(0);
        Ok(SpendPlan {
            to: to.to_string(),
            amount_zat,
            amount_bumped,
            fee_zat,
            change_zat,
            notes,
            memo: memo.map(str::to_string),
            transparent_recipient: transparent,
            expiry_height,
            proposal,
        })
    }

    /// Prove and sign `plan` with the parameters in `params_dir` (verified against their
    /// SHA-256 pins first). The transaction is recorded in the store (its notes count as spent
    /// until it is mined or expires); the caller runs the gate and broadcasts.
    pub fn build(
        &mut self,
        plan: &SpendPlan,
        params_dir: &Path,
    ) -> Result<SpendBuilt, ShieldedError> {
        let params_millis = self.load_prover(params_dir)?;
        let t1 = Instant::now();
        let (_, prover) = self.prover.as_ref().expect("loaded above");
        let usk = x402_ycash_light::keys::usk_from_extsk(&self.account.extended_spending_key());
        let params = self.params;
        let created = create_proposed_transactions::<
            _,
            _,
            std::convert::Infallible,
            _,
            std::convert::Infallible,
            _,
        >(
            &mut self.db,
            &params,
            prover,
            prover,
            &SpendingKeys::from_unified_spending_key(usk),
            OvkPolicy::Sender,
            &plan.proposal,
            None,
        )
        .map_err(|e| ShieldedError::Create(e.to_string()))?;
        let prove_millis = t1.elapsed().as_millis() as u64;
        if created.len() != 1 {
            return Err(ShieldedError::Create(format!(
                "expected one transaction, built {}",
                created.len()
            )));
        }
        let txid: TxId = created.head;
        let tx = self
            .db
            .get_transaction(txid)
            .map_err(store_err)?
            .ok_or_else(|| ShieldedError::Create("built transaction not stored".into()))?;
        let mut raw = Vec::new();
        tx.write(&mut raw)
            .map_err(|e| ShieldedError::Create(e.to_string()))?;
        let fee_zat = tx
            .fee_paid(|_| Ok::<_, zcash_protocol::value::BalanceError>(None))
            .ok()
            .flatten()
            .map(|z| z.into_u64())
            .unwrap_or(plan.fee_zat);
        Ok(SpendBuilt {
            raw,
            txid: *txid.as_ref(),
            expiry_height: u32::from(tx.expiry_height()),
            fee_zat,
            params_millis,
            prove_millis,
        })
    }

    /// The builder of a shielding transaction (S4): `inputs` (YEW's selected transparent P2PKH
    /// coins) pay `amount_zat` into one Sapling output to the wallet's own default address
    /// (external OVK, empty memo) and `change` back to a transparent address, at `target`
    /// (the next block; `nExpiryHeight` = target + 40, the builder's default).
    fn shield_builder(
        &self,
        target: u32,
        inputs: &[ShieldInput],
        amount_zat: u64,
        change: Option<([u8; 20], u64)>,
    ) -> Result<Builder<'static, YcashNetwork, ()>, ShieldedError> {
        let mut b = Builder::new(
            self.params,
            BlockHeight::from_u32(target),
            BuildConfig::Standard {
                sapling_anchor: Some(sapling_crypto::Anchor::empty_tree()),
                orchard_anchor: None,
            },
        );
        for i in inputs {
            let pubkey = secp256k1_zcash::PublicKey::from_slice(&i.pubkey)
                .map_err(|e| ShieldedError::Create(format!("bad input key: {e}")))?;
            let coin = TxOut::new(
                zat(i.value)?,
                TransparentAddress::PublicKeyHash(i.hash160).script().into(),
            );
            b.add_transparent_p2pkh_input(pubkey, OutPoint::new(i.txid, i.n), coin)
                .map_err(|e| ShieldedError::Create(e.to_string()))?;
        }
        let (to, ovk) = self.account.default_output();
        b.add_sapling_output::<std::convert::Infallible>(
            Some(ovk),
            to,
            zat(amount_zat)?,
            MemoBytes::empty(),
        )
        .map_err(|e| ShieldedError::Create(e.to_string()))?;
        if let Some((h, v)) = change {
            b.add_transparent_output(&TransparentAddress::PublicKeyHash(h), zat(v)?)
                .map_err(|e| ShieldedError::Create(e.to_string()))?;
        }
        Ok(b)
    }

    /// The ZIP-317 fee of the shielding transaction [`Shielded::build_shield`] would build with
    /// these inputs and outputs (no proving; the value of the change does not matter).
    pub fn shield_fee(
        &self,
        target: u32,
        inputs: &[ShieldInput],
        amount_zat: u64,
        change: Option<[u8; 20]>,
    ) -> Result<u64, ShieldedError> {
        let b = self.shield_builder(target, inputs, amount_zat.max(1), change.map(|h| (h, 1)))?;
        Ok(b.get_fee(&zip317::FeeRule::standard())
            .map_err(|e| ShieldedError::Propose(format!("fee: {e:?}")))?
            .into_u64())
    }

    /// Build the shielding transaction (S4): prove the Sapling output with the parameters in
    /// `params_dir` (verified against their pins first) and sign the transparent inputs with
    /// `secrets` (one 32-byte key per input, in order; used for this call only). The fee must
    /// be exactly what [`Shielded::shield_fee`] said, or the builder refuses. Nothing is written
    /// to the note store: the output is found by the next scan once mined.
    pub fn build_shield(
        &mut self,
        target: u32,
        inputs: &[ShieldInput],
        secrets: &[[u8; 32]],
        amount_zat: u64,
        change: Option<([u8; 20], u64)>,
        params_dir: &Path,
    ) -> Result<SpendBuilt, ShieldedError> {
        if inputs.is_empty() || secrets.len() != inputs.len() {
            return Err(ShieldedError::Create(
                "one key per transparent input".into(),
            ));
        }
        let params_millis = self.load_prover(params_dir)?;
        let t1 = Instant::now();
        let b = self.shield_builder(target, inputs, amount_zat, change)?;
        // The fee the builder charges (its own ZIP-317 computation; `fee_paid` cannot see the
        // transparent input values once built).
        let fee_zat = b
            .get_fee(&zip317::FeeRule::standard())
            .map_err(|e| ShieldedError::Propose(format!("fee: {e:?}")))?
            .into_u64();
        let mut keys = TransparentSigningSet::new();
        for s in secrets {
            let sk = secp256k1_zcash::SecretKey::from_slice(s)
                .map_err(|e| ShieldedError::Create(format!("bad input key: {e}")))?;
            keys.add_key(sk);
        }
        let (_, prover) = self.prover.as_ref().expect("loaded above");
        let built = b
            .build(
                &keys,
                &[],
                &[],
                OsRng,
                prover,
                prover,
                &zip317::FeeRule::standard(),
            )
            .map_err(|e| ShieldedError::Create(e.to_string()))?;
        drop(keys);
        let tx = built.transaction();
        let mut raw = Vec::new();
        tx.write(&mut raw)
            .map_err(|e| ShieldedError::Create(e.to_string()))?;
        Ok(SpendBuilt {
            raw,
            txid: *tx.txid().as_ref(),
            expiry_height: u32::from(tx.expiry_height()),
            fee_zat,
            params_millis,
            prove_millis: t1.elapsed().as_millis() as u64,
        })
    }

    /// Verify (once) and load the proving parameters from `params_dir`; returns the
    /// milliseconds it took (0 when already loaded from that directory).
    fn load_prover(&mut self, params_dir: &Path) -> Result<u64, ShieldedError> {
        let t0 = Instant::now();
        if matches!(&self.prover, Some((d, _)) if d == params_dir) {
            return Ok(0);
        }
        sapling_params::ensure_verified(params_dir)?;
        let prover = LocalTxProver::new(
            &params_dir.join(sapling_params::SPEND.name),
            &params_dir.join(sapling_params::OUTPUT.name),
        );
        self.prover = Some((params_dir.to_path_buf(), prover));
        Ok(t0.elapsed().as_millis() as u64)
    }

    /// The shielded history, newest first (unmined first).
    pub fn history(&self) -> Result<Vec<ShieldedTx>, ShieldedError> {
        let conn = rusqlite::Connection::open_with_flags(
            self.dir.join("wallet.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(store_err)?;
        let mut stmt = conn
            .prepare(
                "SELECT txid, mined_height, account_balance_delta, fee_paid, expired_unmined
                 FROM v_transactions
                 ORDER BY mined_height IS NOT NULL, mined_height DESC, tx_index DESC",
            )
            .map_err(store_err)?;
        let rows = stmt
            .query_map([], |r| {
                let txid: Vec<u8> = r.get(0)?;
                let height: Option<i64> = r.get(1)?;
                let delta: i64 = r.get(2)?;
                let fee: Option<i64> = r.get(3)?;
                let expired: Option<bool> = r.get(4)?;
                Ok((txid, height, delta, fee, expired.unwrap_or(false)))
            })
            .map_err(store_err)?;
        let mut memo_stmt = conn
            .prepare(
                "SELECT memo FROM v_tx_outputs
                 WHERE txid = ?1 AND output_pool = 2 AND memo IS NOT NULL AND is_change = 0
                 ORDER BY output_index",
            )
            .map_err(store_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (txid, height, delta, fee, expired) = row.map_err(store_err)?;
            let Ok(txid32) = <[u8; 32]>::try_from(txid.as_slice()) else {
                continue;
            };
            let memos = memo_stmt
                .query_map([&txid], |r| r.get::<_, Vec<u8>>(0))
                .map_err(store_err)?;
            let mut memo = String::new();
            for m in memos {
                if let Some(t) = memo_text(&m.map_err(store_err)?) {
                    memo = t;
                    break;
                }
            }
            out.push(ShieldedTx {
                txid: txid32,
                height: height.unwrap_or(0).max(0) as u64,
                delta_zat: delta,
                fee_zat: fee.map(|f| f.max(0) as u64),
                memo,
                expired,
            });
        }
        Ok(out)
    }

    /// The Sapling activation height of this network (the lowest useful birthday).
    pub fn sapling_activation(&self) -> u64 {
        self.params
            .activation_height(NetworkUpgrade::Sapling)
            .map(|h| u32::from(h) as u64)
            .unwrap_or(1)
    }
}

/// The memo bytes of a text memo (ZIP-302 text: UTF-8, at most 512 bytes).
pub fn memo_to_bytes(text: &str) -> Result<MemoBytes, ShieldedError> {
    if text.len() > MAX_MEMO_BYTES {
        return Err(ShieldedError::Memo(format!(
            "The memo is {} bytes; at most {MAX_MEMO_BYTES} bytes fit.",
            text.len()
        )));
    }
    let memo = text
        .parse::<Memo>()
        .map_err(|e| ShieldedError::Memo(format!("bad memo: {e:?}")))?;
    Ok(memo.encode())
}

/// The text of a stored memo blob, if it is a non-empty text memo.
pub fn memo_text(blob: &[u8]) -> Option<String> {
    let mb = MemoBytes::from_bytes(blob).ok()?;
    match Memo::try_from(&mb).ok()? {
        Memo::Text(t) => {
            let s: &str = &t;
            (!s.is_empty()).then(|| s.to_string())
        }
        _ => None,
    }
}

/// The light library's endpoint form for YEW's server: plaintext `grpc://` (regtest only, as
/// YEW enforces) or `grpcs://` (TLS with the platform roots).
pub fn light_endpoint(host: &str, port: u16, plain: bool) -> String {
    if plain {
        format!("grpc://{host}:{port}")
    } else {
        format!("grpcs://{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("yew-shielded-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn account(net: Network, pass: &str) -> SaplingAccount {
        SaplingAccount::from_mnemonic(PHRASE, pass, net).unwrap()
    }

    #[test]
    fn dirs_endpoints_and_networks() {
        assert_eq!(
            shielded_dir(Path::new("/data/yew-regtest.sqlite")),
            PathBuf::from("/data/shielded/yew-regtest")
        );
        assert_eq!(
            shielded_dir(Path::new("yew-wallet.sqlite")),
            PathBuf::from("./shielded/yew-wallet")
        );
        assert_eq!(
            light_endpoint("127.0.0.1", 9267, true),
            "grpc://127.0.0.1:9267"
        );
        assert_eq!(
            light_endpoint("lwd.example", 443, false),
            "grpcs://lwd.example:443"
        );
        assert_eq!(ycash_network(Network::Mainnet), YcashNetwork::Main);
        assert_eq!(ycash_network(Network::Regtest).name(), "regtest");
    }

    #[test]
    fn memos_are_text_and_bounded() {
        let b = memo_to_bytes("hello Ycash").unwrap();
        assert_eq!(memo_text(b.as_slice()).as_deref(), Some("hello Ycash"));
        // 512 bytes of UTF-8 fit, 513 do not; multi-byte characters count in bytes.
        assert!(memo_to_bytes(&"a".repeat(512)).is_ok());
        assert!(memo_to_bytes(&"a".repeat(513)).is_err());
        assert!(memo_to_bytes(&"é".repeat(256)).is_ok());
        assert!(memo_to_bytes(&"é".repeat(257)).is_err());
        // The empty memo (0xF6) is no text.
        assert_eq!(memo_text(MemoBytes::empty().as_slice()), None);
        assert_eq!(memo_text(&[0xff; 512]), None);
    }

    #[test]
    fn open_is_offline_and_empty_and_refuses_before_sync() {
        let dir = tmp("open");
        let mut s = Shielded::open(&dir, Network::Regtest, account(Network::Regtest, "")).unwrap();
        assert!(!s.registered().unwrap());
        assert_eq!(s.balance().unwrap(), ShieldedBalance::default());
        assert!(s.history().unwrap().is_empty());
        let (j, a) = s.default_address();
        assert!(a.starts_with("yregtestsapling1"));
        assert!(s.is_address(&a));
        let (j2, a2) = s.address_at(j + 1).unwrap();
        assert!(j2 > j && a2 != a);
        assert!(matches!(
            s.plan(&a, 1000, None),
            Err(ShieldedError::NotSynced { .. })
        ));
        assert_eq!(s.sapling_activation(), 1);
        // Branch check: regtest is Canopy from height 1, Ycash's Canopy id 19bd2d2f; the
        // upstream Zcash Canopy id (e9ff75a6) is another chain's.
        s.check_branch(100, 0x19bd_2d2f, true).unwrap();
        assert!(matches!(
            s.check_branch(100, 0xe9ff_75a6, true),
            Err(ShieldedError::Branch { .. })
        ));
        drop(s);
        // Reopening is fine; mainnet keys in the same directory are another network's store,
        // but an unregistered store has nothing to compare yet.
        Shielded::open(&dir, Network::Regtest, account(Network::Regtest, "")).unwrap();
    }

    /// The light wallet locks its directory: a second open in the same process is `Busy`
    /// (showable), and dropping the first releases it. YEW holds one per open wallet and drops
    /// it before reopening.
    #[tokio::test]
    async fn one_light_wallet_per_store() {
        let dir = tmp("lock");
        let mut a = Shielded::open(&dir, Network::Regtest, account(Network::Regtest, "")).unwrap();
        let mut b = Shielded::open(&dir, Network::Regtest, account(Network::Regtest, "")).unwrap();
        let ch = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        a.light("grpc://a", &ch).await.unwrap();
        // Reopening on another label drops the first light wallet before opening the next.
        a.light("grpc://a2", &ch).await.unwrap();
        let e = b.light("grpc://b", &ch).await.err().unwrap();
        assert!(matches!(e, ShieldedError::Busy), "{e}");
        assert!(e.to_string().contains("already open"));
        a.disconnect();
        b.light("grpc://b", &ch).await.unwrap();
    }

    #[test]
    fn another_seed_is_refused_once_registered() {
        let dir = tmp("other-seed");
        let s = Shielded::open(&dir, Network::Regtest, account(Network::Regtest, "")).unwrap();
        // Register the account the way the light library does (viewing key + birthday at 0),
        // without a server: the store then belongs to this seed.
        let mut db = s.db;
        let usk = x402_ycash_light::keys::usk_from_extsk(&s.account.extended_spending_key());
        let genesis = zcash_client_backend::data_api::chain::ChainState::empty(
            BlockHeight::from_u32(0),
            zcash_primitives::block::BlockHash([0; 32]),
        );
        db.import_account_ufvk(
            "test",
            &usk.to_unified_full_viewing_key(),
            &zcash_client_backend::data_api::AccountBirthday::from_parts(genesis, None),
            zcash_client_backend::data_api::AccountPurpose::Spending { derivation: None },
            None,
        )
        .unwrap();
        drop(db);
        let s = Shielded::open(&dir, Network::Regtest, account(Network::Regtest, "")).unwrap();
        assert!(s.registered().unwrap());
        let b = s.balance().unwrap();
        assert!(b.registered && b.total_zat == 0);
        drop(s);
        let e =
            Shielded::open(&dir, Network::Regtest, account(Network::Regtest, "other")).unwrap_err();
        assert!(matches!(e, ShieldedError::OtherSeed), "{e}");
        // Nothing under the directory holds the spending key, in any encoding.
        no_spending_key_in(&dir, &account(Network::Regtest, ""));
    }

    /// Every file under `dir`: neither the 169-byte key, nor its 32-byte `ask`/`nsk` halves'
    /// carrier (the serialized key), nor the Bech32 `secret-extended-key-…` text appears.
    pub(crate) fn no_spending_key_in(dir: &Path, a: &SaplingAccount) {
        let raw = a.spending_key_bytes();
        let bech = a.spending_key();
        // The expanded spending key (ask ‖ nsk ‖ ovk) sits at offset 41 of the serialization.
        let ask = &raw[41..73];
        let nsk = &raw[73..105];
        let mut stack = vec![dir.to_path_buf()];
        let mut files = 0;
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                files += 1;
                let bytes = std::fs::read(&p).unwrap();
                for (what, needle) in [
                    ("extsk", &raw[..]),
                    ("ask", ask),
                    ("nsk", nsk),
                    ("bech32", bech.as_bytes()),
                ] {
                    assert!(
                        !bytes.windows(needle.len()).any(|w| w == needle),
                        "{} holds the spending key ({what})",
                        p.display()
                    );
                }
            }
        }
        assert!(files > 0, "no files under {}", dir.display());
    }
}
