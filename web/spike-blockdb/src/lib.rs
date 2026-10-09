//! W0.2 spike (yew/web plan §2, §5): the compact-block cache on OPFS from wasm32.
//!
//! x402-ycash/light caches compact blocks with `FsBlockDb` (files under `blocks/` + a metadata
//! SQLite db); `std::fs` does not exist on wasm32-unknown-unknown. This spike uses the briefing's
//! option 1: `zcash_client_sqlite::BlockDb`, the SQLite-backed block source (one table,
//! `compactblocks(height, data)`), on the sahpool OPFS VFS. Nothing new is stored: the cache is
//! one more SQLite file beside the wallet's.
//!
//! The one adaptation: `BlockDb` owns its connection privately and offers no write API (callers
//! are expected to fill the table with plain SQL), and sahpool allows one connection per file name
//! at a time (W0.1 finding 3). So writes and truncation go through a short-lived
//! `rusqlite::Connection`, and the `BlockDb` is opened for the scan and dropped after it. Opening
//! on sahpool is cheap (the file handle is pooled; no I/O beyond the SQLite header read).
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use zcash_client_backend::data_api::chain::{scan_cached_blocks, BlockSource, ChainState};
use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite};
use zcash_client_backend::proto::compact_formats::{
    ChainMetadata, CompactBlock, CompactSaplingOutput, CompactTx,
};
use zcash_client_sqlite::chain::init::init_cache_database;
use zcash_client_sqlite::util::Clock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{BlockDb, WalletDb};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

/// `SystemTime::now()` is unavailable on wasm32-unknown-unknown; the browser's clock instead.
#[derive(Clone, Copy)]
pub struct JsClock;
impl Clock for JsClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(js_sys::Date::now() as u64)
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn js(e: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("{e:?}"))
}

pub async fn install_opfs() -> Result<(), JsValue> {
    use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfg};
    install::<sqlite_wasm_rs::WasmOsCallback>(&OpfsSAHPoolCfg::default(), true).await.map_err(js)?;
    Ok(())
}

/// The devnet's regtest (x402-ycash/light `YcashNetwork::devnet_regtest`): every upgrade through
/// Canopy at height 1.
pub fn devnet_regtest() -> LocalNetwork {
    let h1 = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: h1,
        sapling: h1,
        ycash: h1,
        blossom: h1,
        heartwood: h1,
        canopy: h1,
        nu5: None,
        nu6: None,
        nu6_1: None,
        nu6_2: None,
        vault: None,
    }
}

// ------------------------------------------------------------------ the cache

/// The compact-block cache: a `BlockDb` file on OPFS, opened per operation (see the module docs).
pub struct BlockCache {
    path: String,
}

impl BlockCache {
    /// Creates the `compactblocks` table if the file is new. Holds no connection afterwards.
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let db = BlockDb::for_path(path)?;
        init_cache_database(&db)?;
        Ok(BlockCache { path: path.to_owned() })
    }

    /// Writes the blocks (encoded protobufs) under their heights, replacing any at the same height
    /// (a reorg re-fetch). What light's `scan_chunk` does with `fs::write` + `write_block_metadata`.
    pub fn insert(&self, blocks: &[CompactBlock]) -> Result<(), rusqlite::Error> {
        let mut conn = rusqlite::Connection::open(&self.path)?;
        let tx = conn.transaction()?;
        {
            let mut stmt =
                tx.prepare("INSERT OR REPLACE INTO compactblocks (height, data) VALUES (?, ?)")?;
            for block in blocks {
                stmt.execute(rusqlite::params![u32::from(block.height()), block.encode_to_vec()])?;
            }
        }
        tx.commit()
    }

    /// Drops every cached block. What light's `clear_cache` does after each scanned chunk.
    pub fn truncate(&self) -> Result<(), rusqlite::Error> {
        let conn = rusqlite::Connection::open(&self.path)?;
        conn.execute("DELETE FROM compactblocks", [])?;
        Ok(())
    }

    /// Every cached block from `from` (which must be cached: `BlockDb` reports a cache miss
    /// otherwise), at most `limit`.
    pub fn read(&self, from: BlockHeight, limit: usize) -> Result<Vec<CompactBlock>, String> {
        let mut out = Vec::new();
        self.with_blocks::<_, ()>(Some(from), Some(limit), |b| {
            out.push(b);
            Ok(())
        })
        .map_err(|e| format!("{e:?}"))?;
        Ok(out)
    }
}

/// Runs the batch-decryption jobs `scan_cached_blocks` has handed to rayon.
///
/// `zcash_client_backend` trial-decrypts outputs in batches it `rayon::spawn_fifo`s and then
/// blocks on a channel for the results. Without threads (wasm32 without atomics) rayon falls back
/// to a one-worker pool on the current thread whose spawned jobs run only when something yields to
/// it — nothing in the scanner does, so the first `collect_results` would wait forever. Yielding
/// from the block source, between rows, runs them on this thread instead. Native builds have real
/// worker threads and need nothing.
#[inline]
fn run_pending_batches() {
    #[cfg(target_arch = "wasm32")]
    while rayon::yield_now() == Some(rayon::Yield::Executed) {}
}

impl BlockSource for BlockCache {
    type Error = zcash_client_sqlite::error::SqliteClientError;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_row: F,
    ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<DbErrT, Self::Error>>
    where
        F: FnMut(
            CompactBlock,
        )
            -> Result<(), zcash_client_backend::data_api::chain::error::Error<DbErrT, Self::Error>>,
    {
        let db = BlockDb::for_path(&self.path)
            .map_err(|e| zcash_client_backend::data_api::chain::error::Error::BlockSource(e.into()))?;
        run_pending_batches();
        db.with_blocks(from_height, limit, |block| {
            let r = with_row(block);
            run_pending_batches();
            r
        })
    }
}

// ------------------------------------------------------------------ test blocks

/// A deterministic block hash for the spike's chain.
pub fn fake_hash(height: u32) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[..4].copy_from_slice(&height.to_le_bytes());
    h[31] = 0x5a;
    h
}

/// A compact block at `height` whose one transaction carries `outputs`; `prev_sapling_tree_size`
/// is the tree size before it (light's `scan_chunk` fills `chain_metadata` the same way).
pub fn fake_block(
    height: u32,
    outputs: Vec<CompactSaplingOutput>,
    prev_sapling_tree_size: u32,
) -> CompactBlock {
    let n = outputs.len() as u32;
    let vtx = if outputs.is_empty() {
        vec![]
    } else {
        vec![CompactTx {
            index: 1,
            txid: fake_hash(0x1000 + height),
            outputs,
            ..Default::default()
        }]
    };
    CompactBlock {
        height: u64::from(height),
        hash: fake_hash(height),
        prev_hash: if height == 0 { vec![0; 32] } else { fake_hash(height - 1) },
        time: 1_600_000_000 + height,
        vtx,
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: prev_sapling_tree_size + n,
            orchard_commitment_tree_size: 0,
        }),
        ..Default::default()
    }
}

/// A compact Sapling output paying `recipient` `value` zatoshis at `height`
/// (zcash_client_backend `data_api::testing::compact_sapling_output`, minus the test harness).
pub fn fake_output<P: Parameters>(
    params: &P,
    height: BlockHeight,
    recipient: sapling::PaymentAddress,
    value: u64,
) -> CompactSaplingOutput {
    use sapling::note_encryption::{sapling_note_encryption, SaplingDomain};
    use zcash_note_encryption::Domain;
    use zcash_primitives::transaction::components::sapling::zip212_enforcement;
    let mut rng = OsRng;
    let rseed = sapling::util::generate_random_rseed(zip212_enforcement(params, height), &mut rng);
    let note = sapling::Note::from_parts(recipient, sapling::value::NoteValue::from_raw(value), rseed);
    let encryptor = sapling_note_encryption(None, note.clone(), [0u8; 512], &mut rng);
    CompactSaplingOutput {
        cmu: note.cmu().to_bytes().to_vec(),
        ephemeral_key: SaplingDomain::epk_bytes(encryptor.epk()).0.to_vec(),
        ciphertext: encryptor.encrypt_note_plaintext()[..52].to_vec(),
    }
}

// ------------------------------------------------------------------ the spikes

/// (a) Three blocks written in one session, read back through the `BlockSource` API in a second
/// (the cache dropped and reopened between); then truncated. Returns the heights read back.
#[wasm_bindgen]
pub async fn spike_roundtrip(path: &str) -> Result<Vec<u32>, JsValue> {
    install_opfs().await?;
    let blocks: Vec<_> = (1..=3).map(|h| fake_block(h, vec![], 0)).collect();
    {
        let cache = BlockCache::open(path).map_err(js)?;
        cache.insert(&blocks).map_err(js)?;
    }
    let cache = BlockCache::open(path).map_err(js)?;
    let read = cache.read(BlockHeight::from_u32(1), 10).map_err(js)?;
    for (a, b) in blocks.iter().zip(&read) {
        if a != b {
            return Err(js(format!("block {} differs after reopen", a.height())));
        }
    }
    // From a height that is not cached: BlockDb reports the miss instead of skipping ahead.
    if cache.read(BlockHeight::from_u32(2), 1).map_err(js)?.len() != 1
        || cache.read(BlockHeight::from_u32(7), 1).is_ok()
    {
        return Err(js("cache miss semantics"));
    }
    let heights = read.iter().map(|b| u32::from(b.height())).collect();
    cache.truncate().map_err(js)?;
    if cache.read(BlockHeight::from_u32(1), 10).is_ok() {
        return Err(js("not truncated"));
    }
    Ok(heights)
}

/// (b) A WalletDb on OPFS with a fresh ZIP-32 account (birthday 1), three cached blocks of which
/// the second pays the account, scanned with `scan_cached_blocks`. Returns
/// `[received notes, spendable balance in zatoshis, fully-scanned height]`.
#[wasm_bindgen]
pub async fn spike_scan(cache_path: &str, wallet_path: &str) -> Result<Vec<u32>, JsValue> {
    install_opfs().await?;
    let params = devnet_regtest();
    let mut db = WalletDb::for_path(wallet_path, params, JsClock, OsRng).map_err(js)?;
    init_wallet_db(&mut db, None).map_err(js)?;
    log("spike_scan: wallet db ready");

    // Birthday at height 1: the chain state before it is the empty tree at genesis.
    let genesis = zcash_primitives::block::BlockHash::from_slice(&fake_hash(0));
    let prior = ChainState::empty(BlockHeight::from_u32(0), genesis);
    let birthday = AccountBirthday::from_parts(prior.clone(), None);
    let seed = secrecy::SecretVec::new(vec![7u8; 32]);
    let (account, usk) = db.create_account("spike", &seed, &birthday, None).map_err(js)?;
    let (_, addr) = usk.sapling().default_address();
    log("spike_scan: account created");

    let value = 100_000u64;
    let blocks = vec![
        fake_block(1, vec![], 0),
        fake_block(2, vec![fake_output(&params, BlockHeight::from_u32(2), addr, value)], 0),
        fake_block(3, vec![], 1),
    ];
    let cache = BlockCache::open(cache_path).map_err(js)?;
    cache.insert(&blocks).map_err(js)?;
    log("spike_scan: blocks cached");
    let summary =
        scan_cached_blocks(&params, &cache, &mut db, BlockHeight::from_u32(1), &prior, blocks.len())
            .map_err(js)?;
    log("spike_scan: scanned");
    cache.truncate().map_err(js)?;

    let received = summary.received_sapling_note_count() as u32;
    let wallet = db
        .get_wallet_summary(zcash_client_backend::data_api::wallet::ConfirmationsPolicy::new_symmetrical(
            std::num::NonZeroU32::new(1).expect("nonzero"),
        ))
        .map_err(js)?
        .ok_or_else(|| js("no wallet summary"))?;
    let balance = wallet
        .account_balances()
        .get(&account)
        .map(|b| b.sapling_balance().spendable_value().into_u64() as u32)
        .unwrap_or(0);
    let scanned = db.block_fully_scanned().map_err(js)?.map(|m| u32::from(m.block_height())).unwrap_or(0);
    Ok(vec![received, balance, scanned])
}
