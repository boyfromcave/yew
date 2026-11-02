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
pub mod claim;
pub mod json;
pub mod keys;
pub mod legacy;
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
    pub coins: Vec<Coin>,
    pub notes: Vec<NoteRow>,
    /// Chain facts the read RPCs need, refreshed by [`Wallet::sync`] when the tip moves.
    pub chain: ChainFacts,
    /// Mints between their carrier and their MINT (`yed_mint … wait = false`), completed by the
    /// poll once the carrier confirms; in memory only, as ycashd's.
    pub pending: Vec<mint::PendingMint>,
    /// The wallet options (`-exportdir`, `-paytxfee`, encryption allowed; S4).
    pub opts: admin::Opts,
    /// The asynchronous operations (`z_sendmany`'s operation ids), in memory as ycashd's.
    pub ops: zsend::Operations,
}

/// What the wallet knows about the chain beyond blocks (from `getblockchaininfo`).
#[derive(Clone, Debug, Default)]
pub struct ChainFacts {
    pub vault_activation: Option<u32>,
    pub falcon_active: Option<bool>,
}

fn now() -> i64 {
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
            Some(s) => {
                if s.network != network.chain_name() {
                    return Err(format!(
                        "{} is a {} wallet, asked for {}",
                        path.display(),
                        s.network,
                        network.chain_name()
                    ));
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
            coins: Vec::new(),
            notes: Vec::new(),
            chain: ChainFacts::default(),
            pending: Vec::new(),
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
            let want = self.st.pq_issued(scheme) + PQ_LOOKAHEAD;
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
            Owner::Pq(s, i) if i >= self.st.pq_issued(s) => {
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
        let time_received = self
            .st
            .wtx
            .get(&txid)
            .map(|w| w.time_received)
            .unwrap_or_else(|| block.as_ref().map(|b| b.time).unwrap_or_else(now));
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
    pub async fn sync(&mut self, node: &dyn Node) -> Result<bool, RpcError> {
        let mut changed = false;
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
        let key = format!("{:08x}", VAULT_BRANCH_ID);
        self.chain.vault_activation = info["upgrades"][&key]["activationheight"]
            .as_u64()
            .map(|h| h as u32);
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
        for (index, (bytes, ztx)) in txs.into_iter().enumerate() {
            let txid = ztx.txid().to_string();
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
        Ok(())
    }

    /// Read the node's mempool: admit relevant transactions not seen yet, drop wallet
    /// transactions that left it unmined.
    async fn sync_mempool(&mut self, node: &dyn Node) -> Result<bool, RpcError> {
        let ids: BTreeSet<String> = node::mempool(node).await?.into_iter().collect();
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
            self.st.wtx.remove(&t);
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
}
