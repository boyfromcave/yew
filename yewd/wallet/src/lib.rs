// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The wallet behind the façade (workspace plan §3b S1): state and sync bound to yew-core's
//! modules directly (keys, scripts, the transaction parser, payloads, PQ ids, the vault
//! templates; never its `api.rs`, the Flutter bridge's one global wallet), and the read RPCs.
//!
//! **Keys (K-24).** The wallet holds public material only: the [`yewd_proto::PublicBundle`] the
//! signer derives from the seed. Transparent keys are CKDpub children of the account xpub,
//! Sapling notes are found with the account's viewing key, PQ keys are a lookahead pool of public
//! keys the signer tops up ([`Signer`]).
//!
//! **Sync (H1, H2).** The node's RPC is the truth. [`Wallet::sync`] brings the wallet to the
//! node's best block: it finds the fork point in its window of recent hashes, rewinds every
//! wallet transaction above it, then reads each new block whole (`getblock <hash> 0`) and the
//! mempool (`getrawmempool`, `getrawtransaction`). Every wallet RPC runs it first (the barrier),
//! and the façade also runs it on a timer (the poll fallback: ycash6 has no indexer streams;
//! kogany's `ChainTipChange` stream becomes the wake-up in S4). Reading blocks over JSON-RPC
//! instead of lightwalletd-dd's `GetTaddressTxids`/`GetAddressUtxos` (K-23 (a)) is recorded in
//! `docs/plans/yewd-plan.md` §3 S1: a wallet-less ycash6 runs without `-insightexplorer`, so the
//! address index is not there to ask, and one block reader serves the transparent, PQ and
//! Sapling sides with the reorg handling in one place.

pub mod admin;
pub mod armed;
pub mod attest;
pub mod build;
pub mod bytype;
pub mod claim;
pub mod json;
pub mod keys;
pub mod legacy;
pub mod lockfrom;
pub mod mint;
pub mod node;
pub mod raw;
pub mod rpc;
pub mod sapling;
pub mod send;
pub mod state;
pub mod vaultrpc;
pub mod yed;
pub mod zfund;
pub mod zsend;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};

pub use yew_core;
use yew_core::params::Network;
use yew_core::tx::Transaction as YTx;
use yewd_proto::{PublicBundle, PublicRequest};

use crate::keys::{KeyBook, Owner, EXTERNAL, INTERNAL, LOOKAHEAD, PQ_LOOKAHEAD};
use crate::node::{Node, NodeError};
use crate::sapling::{Received, Viewing};
use crate::state::{BlockRef, State, Tip, WalletTx, RECENT};

/// The yew-core version this daemon is built on (reported by `getwalletinfo`).
pub const CORE_VERSION: &str = yew_core::VERSION;

/// The vault network upgrade's branch ID, as yew-core signs for it.
pub const VAULT_BRANCH_ID: u32 = yew_core::params::VAULT_BRANCH_ID;

/// Coinbase maturity (`COINBASE_MATURITY`): spendable at depth 101.
pub const COINBASE_MATURITY: u32 = 100;

/// The signer as the wallet sees it: a source of public material (S1) and, from S2, the
/// signing protocol of `yewd-proto` (K-24). A signer that cannot sign (S1's child process for
/// `-initwallet`) answers every other request with an error, which the wallet maps to `-13`.
pub trait Signer: Send + Sync {
    fn public(&self, req: &PublicRequest) -> Result<PublicBundle, String>;
    fn request(&self, _r: yewd_proto::Request) -> Result<yewd_proto::Response, String> {
        Err("this signer does not sign".into())
    }
}

/// A JSON-RPC error the wallet answers with (code, message), ycashd's codes.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> RpcError {
        RpcError {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl From<NodeError> for RpcError {
    fn from(e: NodeError) -> RpcError {
        match e {
            NodeError::Rpc { code, message } => RpcError { code, message },
            NodeError::Unreachable(m) => {
                RpcError::new(code::IN_WARMUP, format!("yewd: backend not reachable: {m}"))
            }
            NodeError::Other(m) => RpcError::new(code::MISC_ERROR, format!("yewd: {m}")),
        }
    }
}

/// ycashd's error codes (`src/rpc/protocol.h`).
pub mod code {
    pub const MISC_ERROR: i64 = -1;
    pub const TYPE_ERROR: i64 = -3;
    pub const WALLET_ERROR: i64 = -4;
    pub const INVALID_ADDRESS_OR_KEY: i64 = -5;
    pub const WALLET_INSUFFICIENT_FUNDS: i64 = -6;
    pub const INVALID_PARAMETER: i64 = -8;
    pub const WALLET_INVALID_ACCOUNT_NAME: i64 = -11;
    /// ycashd's `RPC_WALLET_ACCOUNTS_UNSUPPORTED` (the same -11).
    pub const WALLET_ACCOUNTS_UNSUPPORTED: i64 = -11;
    pub const WALLET_UNLOCK_NEEDED: i64 = -13;
    pub const WALLET_PASSPHRASE_INCORRECT: i64 = -14;
    pub const WALLET_WRONG_ENC_STATE: i64 = -15;
    pub const WALLET_ENCRYPTION_FAILED: i64 = -16;
    pub const DESERIALIZATION_ERROR: i64 = -22;
    pub const TRANSACTION_ERROR: i64 = -25;
    pub const TRANSACTION_REJECTED: i64 = -26;
    pub const IN_WARMUP: i64 = -28;
    pub const INTERNAL_ERROR: i64 = -32603;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Internal (never on the wire): a `wait=true` call parked its completion on its carrier
    /// (`Wallet::defer_wait`); the message is the carrier outpoint.
    pub const CARRIER_PARKED: i64 = -90_001;
}

/// A transaction of the wallet, parsed once.
#[derive(Clone, Debug)]
pub struct Parsed {
    pub tx: YTx,
    pub size: usize,
    pub coinbase: bool,
    pub received: Vec<Received>,
    pub nullifiers: Vec<[u8; 32]>,
    /// Outputs that pay a PQ owner of this wallet's vault or intent templates.
    pub owned_templates: Vec<u32>,
    pub sapling_outputs: usize,
}

/// One coin of the wallet (an output to one of its scripts).
#[derive(Clone, Debug)]
pub struct Coin {
    pub txid: String,
    pub vout: u32,
    pub value: i64,
    pub script: Vec<u8>,
    pub owner: Owner,
    pub height: Option<u32>,
    pub coinbase: bool,
    /// Spent by a wallet transaction (confirmed or in the mempool).
    pub spent: bool,
}

/// One Sapling note of the wallet.
#[derive(Clone, Debug)]
pub struct NoteRow {
    pub txid: String,
    pub outindex: u32,
    pub value: u64,
    pub address: String,
    pub internal: bool,
    pub memo: [u8; 512],
    pub height: Option<u32>,
    pub nullifier: Option<[u8; 32]>,
    pub spent: bool,
    /// The note itself (for a spend in the signer, S4) and its commitment-tree position.
    pub note: sapling_crypto::Note,
    pub position: Option<u64>,
}

/// The open wallet.
pub struct Wallet {
    pub network: Network,
    path: PathBuf,
    pub st: State,
    pub book: KeyBook,
    pub view: Viewing,
    signer: Box<dyn Signer>,
    parsed: BTreeMap<String, Parsed>,
    mempool_seen: BTreeSet<String>,
    /// ycashd's `ReacceptWalletTransactions` at wallet open: the first mempool read offers the
    /// wallet's own unconfirmed transactions to the node again (a restarted node's mempool is
    /// empty; yellowback_fees_reaccept.py).
    reaccept_pending: bool,
    /// The chain facts (`refresh_chain`) were read since the wallet opened: a restarted pair whose
    /// wallet is already at the node's tip still reads them once (the Vault activation height).
    chain_read: bool,
    pub coins: Vec<Coin>,
    pub notes: Vec<NoteRow>,
    /// Chain facts the read RPCs need, refreshed by [`Wallet::sync`] when the tip moves.
    pub chain: ChainFacts,
    /// Mints between their carrier and their MINT (`yed_mint … wait = false`), completed by the
    /// poll once the carrier confirms; in memory only, as ycashd's.
    pub pending: Vec<mint::PendingMint>,
    /// Audit C-2: when set, a `wait=true` call parks its completion here (carrier outpoint →
    /// pending) and returns [`code::CARRIER_PARKED`], so the caller waits without the wallet.
    pub defer_wait: bool,
    pub parked: BTreeMap<String, mint::PendingMint>,
    /// The wallet options (`-exportdir`, `-paytxfee`, encryption allowed; S4).
    pub opts: admin::Opts,
    /// The asynchronous operations (`z_sendmany`'s operation ids), in memory as ycashd's.
    pub ops: zsend::Operations,
}

/// What the wallet knows about the chain beyond blocks (from `getblockchaininfo`).
#[derive(Clone, Debug, Default)]
pub struct ChainFacts {
    pub vault_activation: Option<u32>,
    /// The node's other upgrade heights, a `name=height` list for the signer's regtest
    /// parameters ([`upgrades_spec`]).
    pub upgrades: Option<String>,
    pub falcon_active: Option<bool>,
}

/// The backend is on the wallet's network (`getblockchaininfo`): on testnet, the testnet-yb-fast
/// profile (`testnetprofile`, when the node reports it: ycashd and kogany do) with the Vault height
/// this build compiles in. A node on testnet-yb-slow or testnet-legacy reports `chain` `test` too,
/// and a wallet following it would sign for the wrong branch: refused.
pub fn check_backend_network(network: Network, info: &serde_json::Value) -> Result<(), RpcError> {
    let Some(profile) = network.testnet_profile() else {
        return Ok(());
    };
    let bad = |what: String| {
        Err(RpcError::new(
            code::MISC_ERROR,
            format!("yewd: the backend is not on testnet-yb-fast: {what}"),
        ))
    };
    if let Some(chain) = info["chain"].as_str() {
        if chain != network.chain_name() {
            return bad(format!("it reports chain {chain:?}"));
        }
    }
    if let Some(p) = info["testnetprofile"].as_str() {
        if p != profile.name() {
            return bad(format!("it reports testnetprofile {p:?}"));
        }
    }
    let key = format!("{:08x}", VAULT_BRANCH_ID);
    let vault = info["upgrades"][&key]["activationheight"].as_u64();
    if info["upgrades"].is_object() && vault != network.vault_activation_height() {
        return bad(format!(
            "it schedules the vault upgrade at {vault:?}, this build at {:?}",
            network.vault_activation_height()
        ));
    }
    Ok(())
}

/// The node's upgrade heights before the vault upgrade (`getblockchaininfo.upgrades`, keyed by
/// branch id) as the light library's regtest spec (`YcashNetwork::with_upgrades`): every upgrade
/// through Canopy, its height, or `none` when the node does not list it (on regtest an upgrade
/// without `-nuparams` is not active). The vault upgrade travels separately (`vault_height`).
pub fn upgrades_spec(upgrades: &serde_json::Value) -> String {
    const BRANCHES: [(&str, &str); 6] = [
        ("overwinter", "5ba81b19"),
        ("sapling", "76b809bb"),
        ("ycash", "374d694f"),
        ("blossom", "8e471bd6"),
        ("heartwood", "66314da3"),
        ("canopy", "19bd2d2f"),
    ];
    BRANCHES
        .iter()
        .map(
            |(name, id)| match upgrades[*id]["activationheight"].as_u64() {
                Some(h) => format!("{name}={h}"),
                None => format!("{name}=none"),
            },
        )
        .collect::<Vec<_>>()
        .join(",")
}

/// The façade's mock clock (H11, F-S4-11): `-mocktime` at start and every `setmocktime` the façade
/// forwards set it, as ycashd's `SetMockTime`; 0 = the system clock.
static MOCKTIME: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// `-pqfeerate` (ycashd's, zat per kB): the size-priced fees' rate while no attested price is known
/// (the node reports none: Yellowback not live); 0 = ycashd's default, the relay floor (100 zat/kB).
static PQ_FEE_RATE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

pub fn set_pq_fee_rate(zat_per_kb: i64) {
    PQ_FEE_RATE.store(zat_per_kb.max(0), std::sync::atomic::Ordering::SeqCst);
}

/// `::pqFeeRate`: `-pqfeerate`, by default `-minrelaytxfee` (`DEFAULT_MIN_RELAY_TX_FEE`, 100 zat/kB).
pub fn pq_fee_rate() -> i64 {
    match PQ_FEE_RATE.load(std::sync::atomic::Ordering::SeqCst) {
        0 => 100,
        r => r,
    }
}

/// `-pqfalconheight` (`-pqfalcon=1` = 0), ycashd's regtest Falcon height, which the wallet reads
/// from its own options as ycashd's does (no node RPC reports it outside a live Yellowback);
/// -1 = not given.
static FALCON_HEIGHT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(-1);

pub fn set_falcon_height(h: i64) {
    FALCON_HEIGHT.store(h, std::sync::atomic::Ordering::SeqCst);
}

pub fn falcon_height() -> Option<i64> {
    match FALCON_HEIGHT.load(std::sync::atomic::Ordering::SeqCst) {
        h if h >= 0 => Some(h),
        _ => None,
    }
}

pub fn set_mocktime(t: i64) {
    MOCKTIME.store(t.max(0), std::sync::atomic::Ordering::SeqCst);
}

/// ycashd's `GetTime()`: the mock time when set, else the system clock.
pub fn now() -> i64 {
    let m = MOCKTIME.load(std::sync::atomic::Ordering::SeqCst);
    if m > 0 {
        return m;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The display txid (reversed hex) of internal bytes.
pub fn txid_hex(b: &[u8; 32]) -> String {
    yew_core::tx::txid_hex(b)
}

/// One transaction of a raw block: its bytes, and the zcash_primitives parse.
type BlockTx = (Vec<u8>, zcash_primitives::transaction::Transaction);

/// A raw block's header fields and transactions.
pub(crate) fn split_block(raw: &[u8]) -> Result<(BlockHead, Vec<BlockTx>), String> {
    if raw.len() < 140 {
        return Err("block too short".into());
    }
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&raw[4..36]);
    let time = u32::from_le_bytes(raw[100..104].try_into().expect("4 bytes")) as i64;
    let mut c = Cursor::new(raw);
    c.set_position(140);
    let sol = read_compact(&mut c)?;
    c.set_position(c.position() + sol);
    let n = read_compact(&mut c)?;
    let mut txs = Vec::with_capacity(n.min(10_000) as usize);
    for _ in 0..n {
        let start = c.position() as usize;
        let tx = zcash_primitives::transaction::Transaction::read(
            &mut c,
            zcash_protocol::consensus::BranchId::Sapling,
        )
        .map_err(|e| format!("transaction at byte {start}: {e}"))?;
        let end = c.position() as usize;
        txs.push((raw[start..end].to_vec(), tx));
    }
    if c.position() as usize != raw.len() {
        return Err("trailing bytes after the last transaction".into());
    }
    Ok((
        BlockHead {
            prev: txid_hex(&prev),
            time,
        },
        txs,
    ))
}

struct BlockHead {
    prev: String,
    time: i64,
}

fn read_compact(c: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let b = c.get_ref();
    let p = c.position() as usize;
    let first = *b.get(p).ok_or("truncated")?;
    let (n, len) = match first {
        0xfd => (
            u16::from_le_bytes(
                b.get(p + 1..p + 3)
                    .ok_or("truncated")?
                    .try_into()
                    .expect("2"),
            ) as u64,
            3,
        ),
        0xfe => (
            u32::from_le_bytes(
                b.get(p + 1..p + 5)
                    .ok_or("truncated")?
                    .try_into()
                    .expect("4"),
            ) as u64,
            5,
        ),
        0xff => (
            u64::from_le_bytes(
                b.get(p + 1..p + 9)
                    .ok_or("truncated")?
                    .try_into()
                    .expect("8"),
            ),
            9,
        ),
        n => (n as u64, 1),
    };
    c.set_position((p + len) as u64);
    Ok(n)
}

/// Parse one transaction's bytes (`zcash` = the zcash_primitives form, when the caller has it).
fn parse_tx(
    view: &Viewing,
    book: &KeyBook,
    bytes: &[u8],
    zcash: Option<&zcash_primitives::transaction::Transaction>,
) -> Result<Parsed, String> {
    let (tx, _) = YTx::parse(bytes).map_err(|e| e.to_string())?;
    let owned;
    let ztx = match zcash {
        Some(z) => z,
        None => {
            owned = zcash_primitives::transaction::Transaction::read(
                bytes,
                zcash_protocol::consensus::BranchId::Sapling,
            )
            .map_err(|e| e.to_string())?;
            &owned
        }
    };
    let (received, nullifiers, sapling_outputs) = match ztx.sapling_bundle() {
        Some(b) => (
            view.decrypt(b),
            sapling::nullifiers(b),
            b.shielded_outputs().len(),
        ),
        None => (Vec::new(), Vec::new(), 0),
    };
    let coinbase =
        tx.vin.len() == 1 && tx.vin[0].prevout.txid == [0u8; 32] && tx.vin[0].prevout.n == u32::MAX;
    let mut owned_templates = Vec::new();
    for (i, o) in tx.vout.iter().enumerate() {
        let owner = yew_core::vault::parse_vault(&o.script_pubkey)
            .map(|v| v.owner)
            .or_else(|| yew_core::vault::parse_intent(&o.script_pubkey).map(|p| p.owner));
        if owner.is_some_and(|id| book.pq_by_id(&id).is_some()) {
            owned_templates.push(i as u32);
        }
    }
    Ok(Parsed {
        tx,
        size: bytes.len(),
        coinbase,
        received,
        nullifiers,
        owned_templates,
        sapling_outputs,
    })
}

impl Wallet {
    /// Open the wallet in `dir` (`<datadir>/<net>/yewd`), creating it from the signer's bundle
    /// when there is none. `birthday` is used for a new wallet only.
    pub fn open(
        dir: &Path,
        network: Network,
        signer: Box<dyn Signer>,
        birthday: u32,
    ) -> Result<Wallet, String> {
        let path = dir.join("wallet.json");
        let st = match State::load(&path)? {
            Some(mut s) => {
                if s.network != network.chain_name() {
                    return Err(format!(
                        "{} is a {} wallet, asked for {}",
                        path.display(),
                        s.network,
                        network.chain_name()
                    ));
                }
                // D-9: a book from before the scheme-visible prefixes is rewritten once.
                let m = s.migrate_pq_book(network);
                for w in &m.warnings {
                    eprintln!("yewd: {w}");
                }
                if m.rewritten > 0 {
                    // as before D-9, a wallet on a datadir it cannot write still opens: the
                    // rewritten book is kept in memory and written at the next save that succeeds
                    if let Err(e) = s.save(&path) {
                        eprintln!("yewd: could not save the rewritten address book ({e}); continuing with it in memory");
                    }
                }
                s
            }
            None => {
                let public = signer.public(&PublicRequest {
                    pq: vec![(1, 0, PQ_LOOKAHEAD), (2, 0, PQ_LOOKAHEAD)],
                })?;
                if public.network != network.chain_name() {
                    return Err(format!(
                        "the signer's seed is for {}, asked for {}",
                        public.network,
                        network.chain_name()
                    ));
                }
                let mut s = State::new(public, birthday, now());
                // The coinbase address (H8): the first external key, issued and in the book, so
                // a backend started with -mineraddress=<it> pays this wallet.
                s.issued.external = 1;
                let w = Wallet::from_state(path.clone(), network, s, signer)?;
                let addr = w.taddr(EXTERNAL, 0);
                let mut s = w.st;
                s.book.insert(
                    addr,
                    state::BookEntry {
                        label: String::new(),
                        purpose: "receive".into(),
                    },
                );
                s.save(&path)?;
                return Wallet::from_state(path, network, s, w.signer);
            }
        };
        Wallet::from_state(path, network, st, signer)
    }

    fn from_state(
        path: PathBuf,
        network: Network,
        st: State,
        signer: Box<dyn Signer>,
    ) -> Result<Wallet, String> {
        let book = KeyBook::new(&st.public.account)?;
        let view = Viewing::new(network, &st.public.sapling_dfvk)?;
        let mut w = Wallet {
            network,
            path,
            st,
            book,
            view,
            signer,
            parsed: BTreeMap::new(),
            mempool_seen: BTreeSet::new(),
            reaccept_pending: true,
            chain_read: false,
            coins: Vec::new(),
            notes: Vec::new(),
            chain: ChainFacts::default(),
            pending: Vec::new(),
            defer_wait: false,
            parked: BTreeMap::new(),
            opts: admin::Opts::default(),
            ops: zsend::Operations::default(),
        };
        w.refresh_keys()?;
        let txids: Vec<String> = w.st.wtx.keys().cloned().collect();
        for t in txids {
            let bytes = hex::decode(&w.st.wtx[&t].hex).map_err(|e| e.to_string())?;
            let p = parse_tx(&w.view, &w.book, &bytes, None)?;
            w.parsed.insert(t, p);
        }
        w.rebuild();
        Ok(w)
    }

    /// `-rescan`: forget every block-derived row and read the chain again from the birthday at
    /// the next sync.
    pub fn rescan_all(&mut self) {
        self.rewind(None);
    }

    pub fn save(&self) -> Result<(), String> {
        self.st.save(&self.path)
    }

    /// Derive keys up to `issued + LOOKAHEAD`, and ask the signer for PQ keys up to
    /// `issued + PQ_LOOKAHEAD`.
    pub fn refresh_keys(&mut self) -> Result<(), String> {
        self.book
            .extend(EXTERNAL, self.st.issued.external + LOOKAHEAD)?;
        self.book
            .extend(INTERNAL, self.st.issued.internal + LOOKAHEAD)?;
        let mut req = PublicRequest::default();
        for scheme in [1u8, 2] {
            let have = self
                .st
                .public
                .pq
                .iter()
                .filter(|p| p.scheme == scheme && p.index < yewd_proto::IMPORTED_PQ_BASE)
                .count() as u32;
            // a state written before the guard in mark_used may hold an imported index here
            let issued = self.st.pq_issued(scheme);
            let issued = if issued > yewd_proto::IMPORTED_PQ_BASE {
                have.saturating_sub(PQ_LOOKAHEAD)
            } else {
                issued
            };
            let want = issued + PQ_LOOKAHEAD;
            if have < want {
                req.pq.push((scheme, have, want - have));
            }
        }
        if !req.pq.is_empty() {
            let b = self.signer.public(&req)?;
            if b.seed_fp != self.st.public.seed_fp {
                return Err("the signer holds another seed than this wallet's".into());
            }
            self.st.public.pq.extend(b.pq);
        }
        for p in self.st.public.pq.clone() {
            if self.book.pq_key(p.scheme, p.index).is_none() {
                self.book.add_pq(&p)?;
            }
        }
        for (i, pk) in self.st.public.imported.clone().iter().enumerate() {
            let pk: [u8; 33] = hex::decode(pk)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or("an imported public key is not 33 bytes")?;
            self.book.add_imported(i as u32, pk);
        }
        Ok(())
    }

    /// The `s…` address of a transparent key.
    pub fn taddr(&self, chain: u32, index: u32) -> String {
        let k = self.book.key(chain, index).expect("derived");
        yew_core::keys::encode_p2pkh(self.network, &k.hash)
    }

    pub fn tip_height(&self) -> u32 {
        self.st.tip.as_ref().map(|t| t.height).unwrap_or(0)
    }

    /// Depth of a block height (1 = the tip); 0 for the mempool.
    pub fn depth(&self, height: Option<u32>) -> i64 {
        match height {
            Some(h) if h <= self.tip_height() => (self.tip_height() - h + 1) as i64,
            _ => 0,
        }
    }

    /// Note a key as used: hand-outs move past it, and the lookahead follows.
    fn mark_used(&mut self, owner: Owner) -> bool {
        match owner {
            Owner::T(EXTERNAL, i) if i >= self.st.issued.external => {
                self.st.issued.external = i + 1;
                true
            }
            Owner::T(INTERNAL, i) if i >= self.st.issued.internal => {
                self.st.issued.internal = i + 1;
                true
            }
            // an imported PQ key (index from IMPORTED_PQ_BASE) is no hand-out of the seed's chain:
            // counting it asked the signer for two billion keys (vault_pq_wallet.py's importwallet)
            Owner::Pq(s, i) if i >= self.st.pq_issued(s) && i < yewd_proto::IMPORTED_PQ_BASE => {
                self.st.set_pq_issued(s, i + 1);
                true
            }
            _ => false,
        }
    }

    /// Whether a parsed transaction concerns the wallet (pays or spends it, a note, a
    /// nullifier of a note, a template it owns).
    fn relevant(
        &self,
        p: &Parsed,
        own_outpoints: &BTreeSet<(String, u32)>,
        own_nfs: &BTreeSet<[u8; 32]>,
    ) -> bool {
        p.tx.vout
            .iter()
            .any(|o| self.book.owns_script(&o.script_pubkey).is_some())
            || p.tx
                .vin
                .iter()
                .any(|i| own_outpoints.contains(&(txid_hex(&i.prevout.txid), i.prevout.n)))
            || !p.received.is_empty()
            || p.nullifiers.iter().any(|n| own_nfs.contains(n))
            || !p.owned_templates.is_empty()
            // a claim's release or cancel spends the intent of an own claim (a YED payload in a
            // wallet transaction): yed_history's claim_release / claim_released rows need it
            || p.tx.vin.first().is_some_and(|i| {
                self.parsed
                    .get(&txid_hex(&i.prevout.txid))
                    .is_some_and(|c| yew_core::payload::find_payload(&c.tx).is_some())
            })
    }

    fn own_sets(&self) -> (BTreeSet<(String, u32)>, BTreeSet<[u8; 32]>) {
        let outs = self
            .coins
            .iter()
            .map(|c| (c.txid.clone(), c.vout))
            .collect();
        let nfs = self.notes.iter().filter_map(|n| n.nullifier).collect();
        (outs, nfs)
    }

    /// Admit a relevant transaction; returns whether the key pool moved (a lookahead key used).
    fn admit(
        &mut self,
        txid: String,
        hex: String,
        block: Option<BlockRef>,
        p: Parsed,
    ) -> Result<bool, String> {
        let mut moved = false;
        for o in &p.tx.vout {
            if let Some(owner) = self.book.owns_script(&o.script_pubkey) {
                moved |= self.mark_used(owner);
            }
        }
        // a vault or intent this wallet's PQ key owns uses that key too (ycashd marks the owner key
        // seen on chain: a restored wallet never hands it out again, vault_pq_wallet_restore.py)
        for &i in &p.owned_templates {
            let s = &p.tx.vout[i as usize].script_pubkey;
            let id = yew_core::vault::parse_vault(s)
                .map(|v| v.owner)
                .or_else(|| yew_core::vault::parse_intent(s).map(|v| v.owner));
            if let Some(k) = id.and_then(|id| self.book.pq_by_id(&id)) {
                let owner = Owner::Pq(k.scheme, k.index);
                moved |= self.mark_used(owner);
            }
        }
        let time_received = self
            .st
            .wtx
            .get(&txid)
            .map(|w| w.time_received)
            .unwrap_or_else(|| block.as_ref().map(|b| b.time).unwrap_or_else(now));
        self.st.evicted.remove(&txid);
        self.st.wtx.insert(
            txid.clone(),
            WalletTx {
                hex,
                block,
                time_received,
            },
        );
        self.parsed.insert(txid, p);
        Ok(moved)
    }

    /// Derive coins and notes from the wallet transactions (as ycashd derives balances from
    /// `mapWallet`).
    pub fn rebuild(&mut self) {
        let mut spent: BTreeSet<(String, u32)> = BTreeSet::new();
        let mut nfs: BTreeSet<[u8; 32]> = BTreeSet::new();
        for p in self.parsed.values() {
            for i in &p.tx.vin {
                spent.insert((txid_hex(&i.prevout.txid), i.prevout.n));
            }
            nfs.extend(p.nullifiers.iter().copied());
        }
        let mut coins = Vec::new();
        let mut notes = Vec::new();
        for (txid, p) in &self.parsed {
            let w = &self.st.wtx[txid];
            let height = w.block.as_ref().map(|b| b.height);
            for (n, o) in p.tx.vout.iter().enumerate() {
                if let Some(owner) = self.book.owns_script(&o.script_pubkey) {
                    coins.push(Coin {
                        txid: txid.clone(),
                        vout: n as u32,
                        value: o.value,
                        script: o.script_pubkey.clone(),
                        owner,
                        height,
                        coinbase: p.coinbase,
                        spent: spent.contains(&(txid.clone(), n as u32)),
                    });
                }
            }
            for r in &p.received {
                let pos = w
                    .block
                    .as_ref()
                    .and_then(|b| b.sapling_pos)
                    .map(|p0| p0 + r.outindex as u64);
                let nullifier = pos.map(|pos| r.nullifier(&self.view, pos));
                notes.push(NoteRow {
                    txid: txid.clone(),
                    outindex: r.outindex,
                    value: r.value,
                    address: r.address.clone(),
                    internal: r.internal,
                    memo: r.memo,
                    height,
                    nullifier,
                    spent: nullifier.is_some_and(|n| nfs.contains(&n)),
                    note: r.note.clone(),
                    position: pos,
                });
            }
        }
        coins.sort_by(|a, b| {
            (a.height.unwrap_or(u32::MAX), &a.txid, a.vout).cmp(&(
                b.height.unwrap_or(u32::MAX),
                &b.txid,
                b.vout,
            ))
        });
        self.coins = coins;
        self.notes = notes;
    }

    /// Rewind every wallet transaction above `fork` (`None`: everything) to the mempool; coinbase
    /// transactions are dropped (they cannot return to the mempool). The mempool step then drops
    /// whatever the node did not put back.
    pub(crate) fn rewind(&mut self, fork: Option<u32>) {
        let above = |b: &Option<BlockRef>| {
            b.as_ref()
                .is_some_and(|b| fork.is_none_or(|f| b.height > f))
        };
        let drop: Vec<String> = self
            .st
            .wtx
            .iter()
            .filter(|(t, w)| above(&w.block) && self.parsed.get(*t).is_some_and(|p| p.coinbase))
            .map(|(t, _)| t.clone())
            .collect();
        for t in drop {
            self.st.wtx.remove(&t);
            self.parsed.remove(&t);
        }
        for w in self.st.wtx.values_mut() {
            if above(&w.block) {
                w.block = None;
            }
        }
        self.st
            .recent
            .retain(|t| fork.is_some_and(|f| t.height <= f));
        self.st.tip = self.st.recent.last().cloned();
        // the mempool view is re-read from scratch after a rewind
        self.mempool_seen.clear();
    }

    /// Bring the wallet to the node's best block and mempool (the barrier, H1/H2). Returns
    /// whether anything changed.
    /// Sync with the node; while the wallet has not held YED, a sync that saw something new also
    /// asks the node's index whether any of the wallet's outputs is a YED token (the write-once
    /// "has held YED" marker, beta2; a failing or absent index answer leaves it unset).
    pub async fn sync(&mut self, node: &dyn Node) -> Result<bool, RpcError> {
        let changed = self.sync_chain(node).await?;
        if changed && !self.st.yed_held {
            if let Ok(t) = self.tokens(node).await {
                if !t.is_empty() {
                    self.mark_yed_held();
                }
            }
        }
        Ok(changed)
    }

    async fn sync_chain(&mut self, node: &dyn Node) -> Result<bool, RpcError> {
        let mut changed = false;
        if !self.chain_read {
            self.refresh_chain(node).await?;
            self.chain_read = true;
        }
        for _attempt in 0..4 {
            let best = node::best_hash(node).await?;
            if self.st.tip.as_ref().is_some_and(|t| t.hash == best) {
                changed |= self.sync_mempool(node).await?;
                if changed {
                    self.save()
                        .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
                }
                return Ok(changed);
            }
            changed = true;
            self.refresh_chain(node).await?;
            // the fork point: the highest recent block still on the node's chain
            let mut fork: Option<u32> = None;
            let mut found = self.st.tip.is_none();
            for t in self.st.recent.clone().iter().rev() {
                match node::block_hash(node, t.height).await {
                    Ok(h) if h == t.hash => {
                        fork = Some(t.height);
                        found = true;
                        break;
                    }
                    Ok(_) | Err(NodeError::Rpc { .. }) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            let resume = match (found, fork, self.st.tip.as_ref()) {
                (true, Some(f), Some(t)) if f == t.height => f + 1,
                (true, Some(f), _) => {
                    self.rewind(Some(f));
                    f + 1
                }
                (true, None, None) => self.st.birthday.max(1),
                _ => {
                    // deeper than the window: rescan from the birthday
                    self.rewind(None);
                    self.st.birthday.max(1)
                }
            };
            match self.scan_from(node, resume).await {
                Ok(()) => {}
                Err(ScanError::Moved) => continue,
                Err(ScanError::Rpc(e)) => return Err(e),
            }
            self.sync_mempool(node).await?;
            self.rebuild();
            self.save()
                .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
            if self.st.tip.as_ref().is_some_and(|t| t.hash == best) {
                return Ok(true);
            }
        }
        Ok(changed)
    }

    async fn refresh_chain(&mut self, node: &dyn Node) -> Result<(), RpcError> {
        let info = node::call(node, "getblockchaininfo", serde_json::json!([])).await?;
        check_backend_network(self.network, &info)?;
        let key = format!("{:08x}", VAULT_BRANCH_ID);
        self.chain.vault_activation = info["upgrades"][&key]["activationheight"]
            .as_u64()
            .map(|h| h as u32);
        self.chain.upgrades = Some(upgrades_spec(&info["upgrades"]));
        Ok(())
    }

    async fn scan_from(&mut self, node: &dyn Node, from: u32) -> Result<(), ScanError> {
        let count = node::block_count(node).await?;
        let mut prev = self.st.tip.clone();
        for h in from..=count {
            let hash = node::block_hash(node, h).await?;
            let raw = node::raw_block(node, &hash).await?;
            let (head, txs) = split_block(&raw).map_err(|e| {
                ScanError::Rpc(RpcError::new(
                    code::MISC_ERROR,
                    format!("yewd: block {hash}: {e}"),
                ))
            })?;
            if let Some(p) = &prev {
                if head.prev != p.hash {
                    return Err(ScanError::Moved); // the chain moved under the scan: start over
                }
            }
            self.process_block(node, h, &hash, head.time, txs).await?;
            let tip = Tip {
                height: h,
                hash: hash.clone(),
            };
            self.st.recent.push(tip.clone());
            if self.st.recent.len() > RECENT {
                let n = self.st.recent.len() - RECENT;
                self.st.recent.drain(..n);
            }
            self.st.tip = Some(tip.clone());
            prev = Some(tip);
        }
        Ok(())
    }

    async fn process_block(
        &mut self,
        node: &dyn Node,
        height: u32,
        hash: &str,
        time: i64,
        txs: Vec<BlockTx>,
    ) -> Result<(), ScanError> {
        let mut admitted: Vec<(String, u64)> = Vec::new(); // txid, sapling outputs before it
        let mut outputs_before = 0u64;
        let mut moved = false;
        let mut joined: Vec<String> = Vec::new(); // imported member keys whose SET_JOIN connected
        for (index, (bytes, ztx)) in txs.into_iter().enumerate() {
            let txid = ztx.txid().to_string();
            joined.extend(self.imported_joins(&ztx));
            let p = parse_tx(&self.view, &self.book, &bytes, Some(&ztx)).map_err(|e| {
                ScanError::Rpc(RpcError::new(
                    code::MISC_ERROR,
                    format!("yewd: {txid}: {e}"),
                ))
            })?;
            let n_out = p.sapling_outputs as u64;
            let (outs, nfs) = self.own_sets();
            if self.st.wtx.contains_key(&txid) || self.relevant(&p, &outs, &nfs) {
                let block = BlockRef {
                    height,
                    hash: hash.to_string(),
                    index: index as u32,
                    time,
                    sapling_pos: None,
                };
                let has_notes = !p.received.is_empty();
                moved |= self
                    .admit(txid.clone(), hex::encode(&bytes), Some(block), p)
                    .map_err(|e| ScanError::Rpc(RpcError::new(code::WALLET_ERROR, e)))?;
                if has_notes {
                    admitted.push((txid, outputs_before));
                }
                self.rebuild();
            }
            outputs_before += n_out;
            if moved {
                self.refresh_keys()
                    .map_err(|e| ScanError::Rpc(RpcError::new(code::WALLET_ERROR, e)))?;
                moved = false;
            }
        }
        if !admitted.is_empty() {
            // positions: the tree size after the block, less the block's outputs
            let info = node::block_info(node, hash).await?;
            let size_after = info["trees"]["sapling"]["size"].as_u64().ok_or_else(|| {
                ScanError::Rpc(RpcError::new(
                    code::MISC_ERROR,
                    format!("yewd: getblock {hash}: no trees.sapling.size"),
                ))
            })?;
            let start = size_after.saturating_sub(outputs_before);
            for (txid, before) in admitted {
                if let Some(b) = self.st.wtx.get_mut(&txid).and_then(|w| w.block.as_mut()) {
                    b.sapling_pos = Some(start + before);
                }
            }
            self.rebuild();
        }
        if !joined.is_empty() {
            // ycash6 VaultCheckJoins: a pending imported key that joined a set brings no
            // sign-once history; the signer sets the restore marker (07/F-5 review S3)
            match self.signer.request(yewd_proto::Request::JoinsSeen(joined)) {
                Ok(yewd_proto::Response::Acknowledged(_)) => {}
                other => return Err(ScanError::Rpc(crate::build::signer_error(other))),
            }
        }
        Ok(())
    }

    /// The hash160s (hex) of imported keys of this wallet that `tx`'s `SET_JOIN` act names as
    /// its member key.
    fn imported_joins(&self, tx: &zcash_primitives::transaction::Transaction) -> Vec<String> {
        let Some(b) = tx.transparent_bundle() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for o in &b.vout {
            let spk = &o.script_pubkey().0 .0;
            if !yewd_proto::act::is_act_output(spk) {
                continue;
            }
            if let Ok(yewd_proto::act::Act {
                body: yewd_proto::act::Body::Join { member_key, .. },
                ..
            }) = yewd_proto::act::decode(spk)
            {
                let h = yew_core::keys::hash160(&member_key);
                if self
                    .book
                    .by_hash(&h)
                    .is_some_and(|k| k.chain == crate::keys::IMPORTED)
                {
                    out.push(hex::encode(h));
                }
            }
        }
        out
    }

    /// Read the node's mempool: admit relevant transactions not seen yet, drop wallet
    /// transactions that left it unmined.
    async fn sync_mempool(&mut self, node: &dyn Node) -> Result<bool, RpcError> {
        let mut ids: BTreeSet<String> = node::mempool(node).await?.into_iter().collect();
        if std::mem::take(&mut self.reaccept_pending) {
            let mut own: Vec<(i64, String, String)> = self
                .st
                .wtx
                .iter()
                .filter(|(t, w)| w.block.is_none() && !ids.contains(*t))
                .filter(|(t, _)| self.parsed.get(*t).is_some_and(|p| !p.coinbase))
                .map(|(t, w)| (w.time_received, t.clone(), w.hex.clone()))
                .collect();
            own.sort();
            for (_, txid, hex) in own {
                // the node judges it again; a refusal leaves it to the drop below
                match node::call(node, "sendrawtransaction", serde_json::json!([hex, true])).await {
                    Ok(_) => {
                        ids.insert(txid);
                    }
                    // ycashd logs the refusal at reaccept the same way (wallet.cpp)
                    Err(e) => eprintln!("yewd: reaccept {txid} refused: {e:?}"),
                }
            }
        }
        let mut changed = false;
        let mut fresh: Vec<(String, Vec<u8>)> = Vec::new();
        for txid in &ids {
            if self.mempool_seen.contains(txid)
                || self.st.wtx.get(txid).is_some_and(|w| w.block.is_some())
            {
                continue;
            }
            if let Some(bytes) = node::raw_tx(node, txid).await? {
                fresh.push((txid.clone(), bytes));
            }
        }
        // until nothing more is admitted: a mempool child of a mempool parent
        let examined: Vec<String> = fresh.iter().map(|(t, _)| t.clone()).collect();
        loop {
            let mut admitted = false;
            let mut rest = Vec::new();
            for (txid, bytes) in fresh {
                let p = parse_tx(&self.view, &self.book, &bytes, None)
                    .map_err(|e| RpcError::new(code::MISC_ERROR, format!("yewd: {txid}: {e}")))?;
                let (outs, nfs) = self.own_sets();
                if self.st.wtx.contains_key(&txid) || self.relevant(&p, &outs, &nfs) {
                    let moved = self
                        .admit(txid, hex::encode(&bytes), None, p)
                        .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
                    if moved {
                        self.refresh_keys()
                            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
                    }
                    self.rebuild();
                    admitted = true;
                    changed = true;
                } else {
                    rest.push((txid, bytes));
                }
            }
            fresh = rest;
            if !admitted || fresh.is_empty() {
                break;
            }
        }
        self.mempool_seen.extend(examined);
        self.mempool_seen.retain(|t| ids.contains(t));
        let gone: Vec<String> = self
            .st
            .wtx
            .iter()
            .filter(|(t, w)| w.block.is_none() && !ids.contains(*t))
            .map(|(t, _)| t.clone())
            .collect();
        for t in gone {
            if let Some(p) = self.parsed.get(&t) {
                if p.tx.expiry_height != 0 && yew_core::payload::find_payload(&p.tx).is_some() {
                    if let Some(w) = self.st.wtx.get(&t) {
                        self.st.expired.insert(t.clone(), w.hex.clone());
                    }
                }
            }
            if let Some(w) = self.st.wtx.remove(&t) {
                self.st.evicted.insert(t.clone(), w);
            }
            self.parsed.remove(&t);
            changed = true;
        }
        if changed {
            self.rebuild();
        }
        Ok(changed)
    }

    pub fn parsed(&self, txid: &str) -> Option<&Parsed> {
        self.parsed.get(txid)
    }

    pub fn parsed_all(&self) -> impl Iterator<Item = (&String, &Parsed)> {
        self.parsed.iter()
    }
}

enum ScanError {
    Moved,
    Rpc(RpcError),
}

impl From<NodeError> for ScanError {
    fn from(e: NodeError) -> ScanError {
        ScanError::Rpc(e.into())
    }
}

impl From<RpcError> for ScanError {
    fn from(e: RpcError) -> ScanError {
        ScanError::Rpc(e)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn links_the_core() {
        assert_eq!(super::VAULT_BRANCH_ID, 0x6d5b_7a31);
        assert!(!super::CORE_VERSION.is_empty());
    }

    /// The backend's `getblockchaininfo` must be testnet-yb-fast's on testnet (KG-TESTNET's
    /// koganyd reported `chain test`, `testnetprofile fast`, Vault 510,400 pending); a slow or
    /// legacy node, or another Vault height, is refused. Mainnet and regtest are not checked.
    #[test]
    fn the_backend_must_be_on_the_wallets_testnet_profile() {
        use super::{check_backend_network, Network};
        let info = |chain: &str, profile: Option<&str>, vault: Option<u64>| {
            let mut v = serde_json::json!({"chain": chain, "upgrades": {
                "19bd2d2f": {"name": "Canopy", "activationheight": 510_254}}});
            if let Some(p) = profile {
                v["testnetprofile"] = p.into();
            }
            if let Some(h) = vault {
                v["upgrades"]["6d5b7a31"] =
                    serde_json::json!({"name": "Vault", "activationheight": h});
            }
            v
        };
        let t = Network::Testnet;
        assert!(check_backend_network(t, &info("test", Some("fast"), Some(510_400))).is_ok());
        assert!(check_backend_network(t, &info("test", None, Some(510_400))).is_ok());
        for bad in [
            info("test", Some("slow"), None),
            info("test", Some("legacy"), None),
            info("test", Some("fast"), None),
            info("test", Some("fast"), Some(510_500)),
            info("main", None, Some(510_400)),
        ] {
            let e = check_backend_network(t, &bad).unwrap_err();
            assert!(e.message.contains("testnet-yb-fast"), "{}", e.message);
        }
        assert!(check_backend_network(Network::Mainnet, &info("main", None, None)).is_ok());
        assert!(check_backend_network(Network::Regtest, &info("regtest", None, Some(5))).is_ok());
    }
}

#[cfg(test)]
mod upgrades_spec_tests {
    /// The node's `getblockchaininfo.upgrades` as the signer's regtest spec: listed upgrades at
    /// their heights, an unlisted one `none`, the vault upgrade left out (it travels apart).
    #[test]
    fn upgrades_spec_mirrors_the_node() {
        let u = serde_json::json!({
            "5ba81b19": {"name": "Overwinter", "activationheight": 1},
            "76b809bb": {"name": "Sapling", "activationheight": 1},
            "374d694f": {"name": "Ycash", "activationheight": 1},
            "8e471bd6": {"name": "Blossom", "activationheight": 1},
            "66314da3": {"name": "Heartwood", "activationheight": 1},
            "19bd2d2f": {"name": "Canopy", "activationheight": 150},
            "6d5b7a31": {"name": "Vault", "activationheight": 210}
        });
        assert_eq!(
            super::upgrades_spec(&u),
            "overwinter=1,sapling=1,ycash=1,blossom=1,heartwood=1,canopy=150"
        );
        let mut no_canopy = u.clone();
        no_canopy.as_object_mut().unwrap().remove("19bd2d2f");
        assert!(super::upgrades_spec(&no_canopy).ends_with(",canopy=none"));
        let spec = super::upgrades_spec(&u);
        assert!(
            yew_core::shielded::ycash_network(yew_core::params::Network::Regtest)
                .with_upgrades(&spec)
                .is_ok()
        );
    }
}
