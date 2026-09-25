//! Storage (D-W-6): the SQLite schema (wallet meta, addresses, utxos with class and cents,
//! locks, history with labels, own outputs, own tokens, pending transactions, imported keys,
//! and — W4 — the mint / claim state machine and the own-vault table) and its queries.
//! `rusqlite`, bundled. Schema v2 (W2) adds `utxos.cents`, the history label columns and
//! `own_tokens`; schema v3 (W4) adds the `mints` and `vaults` tables (plan §5.3: `Estimated →
//! CarrierSent → CarrierConfirmed → MainSent → Done | Lapsed → Swept`, persisted so a killed
//! app resumes). Every migration is additive (`ALTER TABLE` / `CREATE TABLE IF NOT EXISTS`).
//!
//! The database is a cache: deleting it and restoring from seed plus birthday rebuilds it.
//! The seed is never here. Imported keys (D-W-11, "outside the HD tree") have to live
//! somewhere the core can read at spend time; in Phase W1 they are stored *wrapped* under a
//! key derived from the seed (HMAC-SHA256 counter keystream, `wrap_key`), never in the clear.
//! Phase W3 moves them to the platform keystore alongside the seed.

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

use crate::coins::{Utxo, UtxoClass};
use crate::keys::Chain;
use crate::tx::OutPoint;

/// Storage errors.
#[derive(Debug, Error)]
pub enum StoreError {
    /// SQLite.
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    /// A stored value did not parse (class name, number).
    #[error("corrupt store: {0}")]
    Corrupt(String),
}

/// The schema version this build writes and reads.
pub const SCHEMA_VERSION: i64 = 3;

/// The `chain` column value of an imported key (D-W-11): outside the HD tree.
pub const CHAIN_IMPORTED: u32 = 2;

/// One row of `addresses`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressRow {
    /// 0 external, 1 change, 2 imported.
    pub chain: u32,
    /// The derivation index (0 for imported keys; the hash keeps them apart).
    pub index: u32,
    /// The `s…` form.
    pub address_s: String,
    /// The `ye…` form.
    pub address_ye: String,
    /// `HASH160(pubkey)`.
    pub hash160: [u8; 20],
    /// Seen in any transaction.
    pub used: bool,
}

impl AddressRow {
    /// The HD chain, if this is an HD address.
    pub fn hd_chain(&self) -> Option<Chain> {
        Chain::from_number(self.chain)
    }
}

/// One row of `history`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRow {
    /// The txid (internal order).
    pub txid: [u8; 32],
    /// The height, or 0 while pending.
    pub height: u64,
    /// Net YEC change to the wallet's own P2PKH outputs minus own inputs, in zat.
    pub yec_delta: i64,
    /// The transaction carried an `OP_RETURN` output (a possible `"YB"` payload).
    pub has_payload: bool,
    /// Broadcast by this wallet and not yet seen confirmed.
    pub pending: bool,
    /// The transaction had shielded components.
    pub shielded: bool,
    /// Net YED change to this wallet in cents (own assigned cents minus own tokens spent),
    /// from `GetTxInfo` once labelled, from the local payload while pending.
    pub yed_delta: i64,
    /// `GetTxInfo.type` (`mint`, `transfer`, `redeem`, …) or `""`.
    pub kind: String,
    /// `GetTxInfo.verdict` (`ok`, a rule name, `expired`) or `""`.
    pub verdict: String,
    /// The display label derived from the verdict (`sync::label_for`), or `""`.
    pub label: String,
    /// `GetTxInfo` has answered for this row (or said `tx-not-found`).
    pub labelled: bool,
}

/// One row of `locks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockRow {
    /// The locked outpoint.
    pub outpoint: OutPoint,
    /// Why (`"spent-by:<txid hex>"`, `"token"`, `"vault"`, `"carrier:<mint id>"`).
    pub reason: String,
    /// Height after which the lock lapses (0 = never).
    pub expiry_height: u64,
}

/// A broadcast transaction awaiting confirmation: `(txid, raw bytes, expiry height)`.
pub type PendingTx = ([u8; 32], Vec<u8>, u64);

/// The state of a two-step operation (plan §5.3). `Estimated` is never stored: a row exists
/// from the carrier broadcast on. Translated from the wallet fork's in-memory flow
/// (`yecwallet-dd/src/yellowbackcontroller.cpp:811-851` `awaitPending`: the carrier, one
/// confirmation, the main transaction, the lapse when the chain passes `refHeight +
/// REF_WINDOW`) into rows the sync loop advances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintState {
    /// The carrier funding transaction was broadcast.
    CarrierSent,
    /// The carrier is confirmed; the main transaction can be built while the window is open.
    CarrierConfirmed,
    /// The main (MINT or CLAIM) transaction was broadcast.
    MainSent,
    /// The main transaction confirmed (its verdict is in `history`).
    Done,
    /// `refHeight + REF_WINDOW` passed without the main transaction confirming; the carrier is
    /// unspent and sweepable.
    Lapsed,
    /// The sweep of the lapsed carrier was broadcast.
    SweepSent,
    /// The sweep confirmed: `CARRIER_VALUE − fee` is back in class `YEC`.
    Swept,
    /// The carrier never confirmed (its funding expired); nothing is on the chain.
    Failed,
}

impl MintState {
    /// The stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            MintState::CarrierSent => "CARRIER_SENT",
            MintState::CarrierConfirmed => "CARRIER_CONFIRMED",
            MintState::MainSent => "MAIN_SENT",
            MintState::Done => "DONE",
            MintState::Lapsed => "LAPSED",
            MintState::SweepSent => "SWEEP_SENT",
            MintState::Swept => "SWEPT",
            MintState::Failed => "FAILED",
        }
    }

    /// From the stored name.
    pub fn parse(s: &str) -> Option<MintState> {
        Some(match s {
            "CARRIER_SENT" => MintState::CarrierSent,
            "CARRIER_CONFIRMED" => MintState::CarrierConfirmed,
            "MAIN_SENT" => MintState::MainSent,
            "DONE" => MintState::Done,
            "LAPSED" => MintState::Lapsed,
            "SWEEP_SENT" => MintState::SweepSent,
            "SWEPT" => MintState::Swept,
            "FAILED" => MintState::Failed,
            _ => return None,
        })
    }

    /// True while the sync loop still has something to do with the row.
    pub fn in_flight(self) -> bool {
        !matches!(self, MintState::Done | MintState::Swept | MintState::Failed)
    }

    /// True while the wallet holds an unspent carrier for the row (class `CARRIER`).
    pub fn holds_carrier(self) -> bool {
        matches!(
            self,
            MintState::CarrierConfirmed
                | MintState::MainSent
                | MintState::Lapsed
                | MintState::SweepSent
        )
    }
}

/// What a two-step row is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintKind {
    /// A MINT (the owner persona).
    Mint,
    /// A CLAIM of another wallet's vault (the liquidator persona).
    Claim,
}

impl MintKind {
    /// The stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            MintKind::Mint => "mint",
            MintKind::Claim => "claim",
        }
    }
}

/// One row of `mints`: everything the carrier step fixed, so the main step and the sweep can
/// be rebuilt from the file alone (D-W-6: a killed app resumes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintRow {
    /// The row id (`mint_id` of the API).
    pub id: i64,
    /// MINT or CLAIM.
    pub kind: MintKind,
    /// The state.
    pub state: MintState,
    /// The tip when the carrier was broadcast.
    pub created_height: u64,
    /// The cents to mint (MINT) or the debt to burn (CLAIM, `mintedCents`).
    pub cents: u64,
    /// `lockBlocks` (MINT).
    pub lock_blocks: u32,
    /// The term class letter (`"A"`, `"B"`, `"C"`).
    pub term_class: String,
    /// `R`, the reference height of the carrier and the main transaction.
    pub ref_height: u32,
    /// The vault's `lockHeight`.
    pub lock_height: u32,
    /// The vault's `claimHeight`.
    pub claim_height: u32,
    /// The collateral (`requiredZat` rounded, or the claimed vault's `collateralZat`).
    pub collateral_zat: i64,
    /// The enforcement fee (`feeZat`), 0 under FEE-0.
    pub fee_zat: i64,
    /// The fee payee (`s…`), empty under FEE-0.
    pub payee: String,
    /// The attestor fee (`attestFeeZat`), 0 under AFEE-0.
    pub attest_fee_zat: i64,
    /// The attestor payee (`bondKeyAddress`, `s…`), empty under AFEE-0.
    pub attest_payee: String,
    /// The claim's residual to the owner (RED-5), 0 when none is due.
    pub residual_zat: i64,
    /// The bundle bytes committed by the carrier.
    pub bundle: Vec<u8>,
    /// The `seq`s the bundle carries, as `"0,1,2"`.
    pub bundle_seqs: String,
    /// The carrier key's hash (an own key; re-derived through `Wallet::key_for_hash`).
    pub carrier_hash160: [u8; 20],
    /// The owner key's hash (MINT: the vault owner and the token recipient; CLAIM: unused).
    pub owner_hash160: [u8; 20],
    /// The carrier funding txid.
    pub carrier_txid: [u8; 32],
    /// The carrier output index (0).
    pub carrier_vout: u32,
    /// The main transaction's txid, once broadcast (zero before).
    pub main_txid: [u8; 32],
    /// The sweep's txid, once broadcast (zero before).
    pub sweep_txid: [u8; 32],
    /// `refHeight + REF_WINDOW`: the expiry of the carrier and of the main transaction.
    pub expiry_height: u32,
    /// CLAIM: the vault's txid (zero for a MINT).
    pub vault_txid: [u8; 32],
    /// CLAIM: the vault's owner key (33 bytes), for the residual output and the vault script.
    pub owner_pubkey: Vec<u8>,
    /// Why the row failed or lapsed, for the screen.
    pub note: String,
}

/// One row of `vaults`: an own vault as `GetVault` last reported it (plan §3.7 class VAULT).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRow {
    /// The mint txid (the vault outpoint is `txid:0`).
    pub txid: [u8; 32],
    /// The output index (0).
    pub vout: u32,
    /// `ACTIVE`, `VOID`, `CLOSED`, `CLAIMED`.
    pub status: String,
    /// The owner key hash (an own key).
    pub owner_hash160: [u8; 20],
    /// The owner's compressed public key.
    pub owner_pubkey: [u8; 33],
    /// The term class letter.
    pub term_class: String,
    /// `lockHeight`.
    pub lock_height: u32,
    /// `claimHeight`.
    pub claim_height: u32,
    /// `collateralZat`.
    pub collateral_zat: i64,
    /// `mintedCents`.
    pub minted_cents: u64,
    /// `mintHeight`.
    pub mint_height: u64,
    /// `claimable` as the node judges it at its tip.
    pub claimable: bool,
    /// `underwaterAt` (micro-USD per YEC), 0 when undefined.
    pub underwater_at: i64,
    /// `sweepBefore`, 0 when not applicable.
    pub sweep_before: u64,
    /// `closeHeight`, 0 while open.
    pub close_height: u64,
    /// `closingTxid` (display hex), empty while open.
    pub closing_txid: String,
    /// `voidReason`, empty unless VOID.
    pub void_reason: String,
    /// The tip at the last refresh.
    pub updated_height: u64,
}

impl VaultRow {
    /// True while the vault can still be spent by its owner (ACTIVE: REDEEM; VOID: release).
    pub fn is_open(&self) -> bool {
        self.status == "ACTIVE" || self.status == "VOID"
    }
}

/// The open wallet database.
pub struct Store {
    conn: Connection,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store")
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS addresses (
  chain INTEGER NOT NULL, idx INTEGER NOT NULL,
  address_s TEXT NOT NULL UNIQUE, address_ye TEXT NOT NULL UNIQUE,
  hash160 BLOB NOT NULL UNIQUE, used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (chain, idx, hash160));
CREATE TABLE IF NOT EXISTS imported_keys (hash160 BLOB PRIMARY KEY, wrapped BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS utxos (
  txid BLOB NOT NULL, n INTEGER NOT NULL, address TEXT NOT NULL, script BLOB NOT NULL,
  value INTEGER NOT NULL, height INTEGER NOT NULL, class TEXT NOT NULL,
  cents INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (txid, n));
CREATE TABLE IF NOT EXISTS locks (
  txid BLOB NOT NULL, n INTEGER NOT NULL, reason TEXT NOT NULL,
  expiry_height INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (txid, n));
CREATE TABLE IF NOT EXISTS history (
  txid BLOB PRIMARY KEY, height INTEGER NOT NULL, yec_delta INTEGER NOT NULL,
  has_payload INTEGER NOT NULL, pending INTEGER NOT NULL, shielded INTEGER NOT NULL,
  yed_delta INTEGER NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT '',
  verdict TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '',
  labelled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS pending_txs (txid BLOB PRIMARY KEY, raw BLOB NOT NULL, expiry_height INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS own_outputs (txid BLOB NOT NULL, n INTEGER NOT NULL, value INTEGER NOT NULL, hash160 BLOB NOT NULL, PRIMARY KEY (txid, n));
CREATE TABLE IF NOT EXISTS own_tokens (txid BLOB NOT NULL, n INTEGER NOT NULL, cents INTEGER NOT NULL, PRIMARY KEY (txid, n));
CREATE TABLE IF NOT EXISTS spent_tokens (spender BLOB NOT NULL, txid BLOB NOT NULL, n INTEGER NOT NULL, cents INTEGER NOT NULL, PRIMARY KEY (spender, txid, n));
CREATE TABLE IF NOT EXISTS mints (
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, state TEXT NOT NULL,
  created_height INTEGER NOT NULL, cents INTEGER NOT NULL, lock_blocks INTEGER NOT NULL,
  term_class TEXT NOT NULL, ref_height INTEGER NOT NULL, lock_height INTEGER NOT NULL,
  claim_height INTEGER NOT NULL, collateral_zat INTEGER NOT NULL, fee_zat INTEGER NOT NULL,
  payee TEXT NOT NULL, attest_fee_zat INTEGER NOT NULL, attest_payee TEXT NOT NULL,
  residual_zat INTEGER NOT NULL, bundle BLOB NOT NULL, bundle_seqs TEXT NOT NULL,
  carrier_hash160 BLOB NOT NULL, owner_hash160 BLOB NOT NULL, carrier_txid BLOB NOT NULL,
  carrier_vout INTEGER NOT NULL, main_txid BLOB NOT NULL, sweep_txid BLOB NOT NULL,
  expiry_height INTEGER NOT NULL, vault_txid BLOB NOT NULL, owner_pubkey BLOB NOT NULL,
  note TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS vaults (
  txid BLOB PRIMARY KEY, vout INTEGER NOT NULL, status TEXT NOT NULL, owner_hash160 BLOB NOT NULL,
  owner_pubkey BLOB NOT NULL, term_class TEXT NOT NULL, lock_height INTEGER NOT NULL,
  claim_height INTEGER NOT NULL, collateral_zat INTEGER NOT NULL, minted_cents INTEGER NOT NULL,
  mint_height INTEGER NOT NULL, claimable INTEGER NOT NULL, underwater_at INTEGER NOT NULL,
  sweep_before INTEGER NOT NULL, close_height INTEGER NOT NULL, closing_txid TEXT NOT NULL,
  void_reason TEXT NOT NULL, updated_height INTEGER NOT NULL);
";

/// The additive v1 → v2 migration (W2).
const MIGRATE_1_TO_2: &str = "
ALTER TABLE utxos ADD COLUMN cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE history ADD COLUMN yed_delta INTEGER NOT NULL DEFAULT 0;
ALTER TABLE history ADD COLUMN kind TEXT NOT NULL DEFAULT '';
ALTER TABLE history ADD COLUMN verdict TEXT NOT NULL DEFAULT '';
ALTER TABLE history ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE history ADD COLUMN labelled INTEGER NOT NULL DEFAULT 0;
";

impl Store {
    /// Open (or create) the database at `path` and ensure the schema.
    pub fn open(path: &str) -> Result<Store, StoreError> {
        let conn = Connection::open(path)?;
        Store::init(conn)
    }

    /// An in-memory database (tests).
    pub fn open_in_memory() -> Result<Store, StoreError> {
        Store::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store, StoreError> {
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        // Read the version before creating tables: a v1 `utxos` must be altered, not recreated.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if existing.as_deref() == Some("1") {
            conn.execute_batch(MIGRATE_1_TO_2)?;
            conn.execute(
                "UPDATE meta SET value = '2' WHERE key = 'schema_version'",
                [],
            )?;
        }
        conn.execute_batch(SCHEMA)?;
        // v2 → v3 (W4) is the two new tables SCHEMA just created: bump the version.
        if matches!(existing.as_deref(), Some("1") | Some("2")) {
            conn.execute(
                "UPDATE meta SET value = '3' WHERE key = 'schema_version'",
                [],
            )?;
        }
        let s = Store { conn };
        match s.meta("schema_version")? {
            None => s.set_meta("schema_version", &SCHEMA_VERSION.to_string())?,
            Some(v) if v == SCHEMA_VERSION.to_string() => {}
            Some(v) => {
                return Err(StoreError::Corrupt(format!(
                    "schema version {v}, want {SCHEMA_VERSION}"
                )))
            }
        }
        Ok(s)
    }

    // ---- meta

    /// Read a meta value.
    pub fn meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Write a meta value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// A numeric meta value, defaulting to 0.
    pub fn meta_u64(&self, key: &str) -> Result<u64, StoreError> {
        match self.meta(key)? {
            None => Ok(0),
            Some(v) => v
                .parse()
                .map_err(|_| StoreError::Corrupt(format!("meta {key} = {v:?}"))),
        }
    }

    // ---- addresses

    /// Insert an address row (ignored if the hash is already present).
    pub fn insert_address(&self, row: &AddressRow) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO addresses (chain, idx, address_s, address_ye, hash160, used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![row.chain, row.index, row.address_s, row.address_ye, row.hash160.as_slice(), row.used as i64],
        )?;
        Ok(())
    }

    /// Every address, ordered by chain then index.
    pub fn addresses(&self) -> Result<Vec<AddressRow>, StoreError> {
        let mut st = self.conn.prepare(
            "SELECT chain, idx, address_s, address_ye, hash160, used FROM addresses ORDER BY chain, idx",
        )?;
        let rows = st.query_map([], |r| {
            let h: Vec<u8> = r.get(4)?;
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                h,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (chain, index, address_s, address_ye, h, used) = row?;
            let hash160: [u8; 20] = h
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("hash160 length".into()))?;
            out.push(AddressRow {
                chain,
                index,
                address_s,
                address_ye,
                hash160,
                used: used != 0,
            });
        }
        Ok(out)
    }

    /// The highest index on `chain` (None when the chain has no address yet).
    pub fn max_index(&self, chain: u32) -> Result<Option<u32>, StoreError> {
        Ok(self.conn.query_row(
            "SELECT MAX(idx) FROM addresses WHERE chain = ?1",
            params![chain],
            |r| r.get::<_, Option<u32>>(0),
        )?)
    }

    /// The highest *used* index on `chain`.
    pub fn max_used_index(&self, chain: u32) -> Result<Option<u32>, StoreError> {
        Ok(self.conn.query_row(
            "SELECT MAX(idx) FROM addresses WHERE chain = ?1 AND used = 1",
            params![chain],
            |r| r.get::<_, Option<u32>>(0),
        )?)
    }

    /// Mark an address used by its key hash. Returns whether it was newly marked.
    pub fn mark_used(&self, hash160: &[u8; 20]) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "UPDATE addresses SET used = 1 WHERE hash160 = ?1 AND used = 0",
            params![hash160.as_slice()],
        )?;
        Ok(n > 0)
    }

    /// The lowest unused index on `chain`, if one exists.
    pub fn first_unused(&self, chain: u32) -> Result<Option<AddressRow>, StoreError> {
        Ok(self
            .addresses()?
            .into_iter()
            .find(|a| a.chain == chain && !a.used))
    }

    // ---- imported keys

    /// Store a wrapped imported key.
    pub fn insert_imported_key(
        &self,
        hash160: &[u8; 20],
        wrapped: &[u8],
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO imported_keys (hash160, wrapped) VALUES (?1, ?2)",
            params![hash160.as_slice(), wrapped],
        )?;
        Ok(())
    }

    /// Read a wrapped imported key.
    pub fn imported_key(&self, hash160: &[u8; 20]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT wrapped FROM imported_keys WHERE hash160 = ?1",
                params![hash160.as_slice()],
                |r| r.get(0),
            )
            .optional()?)
    }

    // ---- utxos

    /// Replace the whole UTXO table with `utxos` (the server's set, classified).
    pub fn replace_utxos(&mut self, utxos: &[Utxo]) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM utxos", [])?;
        {
            let mut st = tx.prepare(
                "INSERT INTO utxos (txid, n, address, script, value, height, class, cents) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for u in utxos {
                st.execute(params![
                    u.outpoint.txid.as_slice(),
                    u.outpoint.n,
                    u.address,
                    u.script,
                    u.value,
                    u.height as i64,
                    u.class.as_str(),
                    u.cents as i64
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Insert or replace one UTXO row (the builders add `PENDING_TOKEN` rows at broadcast;
    /// the next sync's `replace_utxos` re-derives them from the pending record).
    pub fn upsert_utxo(&self, u: &Utxo) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO utxos (txid, n, address, script, value, height, class, cents) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                u.outpoint.txid.as_slice(),
                u.outpoint.n,
                u.address,
                u.script,
                u.value,
                u.height as i64,
                u.class.as_str(),
                u.cents as i64
            ],
        )?;
        Ok(())
    }

    /// Every UTXO.
    pub fn utxos(&self) -> Result<Vec<Utxo>, StoreError> {
        let mut st = self.conn.prepare("SELECT txid, n, address, script, value, height, class, cents FROM utxos ORDER BY height, txid, n")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (t, n, address, script, value, height, class, cents) = row?;
            let txid: [u8; 32] = t
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("txid length".into()))?;
            let class = UtxoClass::parse(&class)
                .ok_or_else(|| StoreError::Corrupt(format!("class {class}")))?;
            out.push(Utxo {
                outpoint: OutPoint { txid, n },
                address,
                script,
                value,
                height: height as u64,
                class,
                cents: cents.max(0) as u64,
            });
        }
        Ok(out)
    }

    /// The class of one outpoint, if known.
    pub fn utxo_class(&self, op: &OutPoint) -> Result<Option<UtxoClass>, StoreError> {
        let c: Option<String> = self
            .conn
            .query_row(
                "SELECT class FROM utxos WHERE txid = ?1 AND n = ?2",
                params![op.txid.as_slice(), op.n],
                |r| r.get(0),
            )
            .optional()?;
        match c {
            None => Ok(None),
            Some(s) => UtxoClass::parse(&s)
                .map(Some)
                .ok_or_else(|| StoreError::Corrupt(format!("class {s}"))),
        }
    }

    // ---- locks

    /// Lock an outpoint.
    pub fn lock(&self, op: &OutPoint, reason: &str, expiry_height: u64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO locks (txid, n, reason, expiry_height) VALUES (?1, ?2, ?3, ?4)",
            params![op.txid.as_slice(), op.n, reason, expiry_height as i64],
        )?;
        Ok(())
    }

    /// Release one lock (sync only, never a screen).
    pub fn unlock(&self, op: &OutPoint) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM locks WHERE txid = ?1 AND n = ?2",
            params![op.txid.as_slice(), op.n],
        )?;
        Ok(())
    }

    /// Every lock.
    pub fn locks(&self) -> Result<Vec<LockRow>, StoreError> {
        let mut st = self
            .conn
            .prepare("SELECT txid, n, reason, expiry_height FROM locks")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (t, n, reason, e) = row?;
            let txid: [u8; 32] = t
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("txid length".into()))?;
            out.push(LockRow {
                outpoint: OutPoint { txid, n },
                reason,
                expiry_height: e as u64,
            });
        }
        Ok(out)
    }

    // ---- history and pending transactions

    /// Insert or update a history row (every column).
    pub fn upsert_history(&self, row: &HistoryRow) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO history (txid, height, yec_delta, has_payload, pending, shielded, yed_delta, kind, verdict, label, labelled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(txid) DO UPDATE SET height = excluded.height, yec_delta = excluded.yec_delta,
             has_payload = excluded.has_payload, pending = excluded.pending, shielded = excluded.shielded,
             yed_delta = excluded.yed_delta, kind = excluded.kind, verdict = excluded.verdict,
             label = excluded.label, labelled = excluded.labelled",
            params![row.txid.as_slice(), row.height as i64, row.yec_delta, row.has_payload as i64, row.pending as i64, row.shielded as i64,
                    row.yed_delta, row.kind, row.verdict, row.label, row.labelled as i64],
        )?;
        Ok(())
    }

    /// Update only the chain-side columns of a history row (height, yec delta, payload flag,
    /// pending, shielded), inserting it if absent; the label columns are kept.
    pub fn upsert_history_seen(&self, row: &HistoryRow) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO history (txid, height, yec_delta, has_payload, pending, shielded, yed_delta, kind, verdict, label, labelled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(txid) DO UPDATE SET height = excluded.height, yec_delta = excluded.yec_delta,
             has_payload = excluded.has_payload, pending = excluded.pending, shielded = excluded.shielded",
            params![row.txid.as_slice(), row.height as i64, row.yec_delta, row.has_payload as i64, row.pending as i64, row.shielded as i64,
                    row.yed_delta, row.kind, row.verdict, row.label, row.labelled as i64],
        )?;
        Ok(())
    }

    /// Set the label columns of a history row.
    pub fn set_history_label(
        &self,
        txid: &[u8; 32],
        yed_delta: i64,
        kind: &str,
        verdict: &str,
        label: &str,
        labelled: bool,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE history SET yed_delta = ?2, kind = ?3, verdict = ?4, label = ?5, labelled = ?6 WHERE txid = ?1",
            params![txid.as_slice(), yed_delta, kind, verdict, label, labelled as i64],
        )?;
        Ok(())
    }

    /// One history row.
    pub fn history_row(&self, txid: &[u8; 32]) -> Result<Option<HistoryRow>, StoreError> {
        Ok(self.history()?.into_iter().find(|h| h.txid == *txid))
    }

    /// History, newest first (pending rows first).
    pub fn history(&self) -> Result<Vec<HistoryRow>, StoreError> {
        let mut st = self.conn.prepare(
            "SELECT txid, height, yec_delta, has_payload, pending, shielded, yed_delta, kind, verdict, label, labelled
             FROM history ORDER BY pending DESC, height DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, i64>(10)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (t, height, yec_delta, p, pending, sh, yed_delta, kind, verdict, label, labelled) =
                row?;
            let txid: [u8; 32] = t
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("txid length".into()))?;
            out.push(HistoryRow {
                txid,
                height: height as u64,
                yec_delta,
                has_payload: p != 0,
                pending: pending != 0,
                shielded: sh != 0,
                yed_delta,
                kind,
                verdict,
                label,
                labelled: labelled != 0,
            });
        }
        Ok(out)
    }

    /// Record a broadcast transaction until it confirms or expires.
    pub fn insert_pending_tx(
        &self,
        txid: &[u8; 32],
        raw: &[u8],
        expiry_height: u64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_txs (txid, raw, expiry_height) VALUES (?1, ?2, ?3)",
            params![txid.as_slice(), raw, expiry_height as i64],
        )?;
        Ok(())
    }

    /// Pending transactions: `(txid, raw, expiry_height)`.
    pub fn pending_txs(&self) -> Result<Vec<PendingTx>, StoreError> {
        let mut st = self
            .conn
            .prepare("SELECT txid, raw, expiry_height FROM pending_txs")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (t, raw, e) = row?;
            let txid: [u8; 32] = t
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("txid length".into()))?;
            out.push((txid, raw, e as u64));
        }
        Ok(out)
    }

    /// Remember an output paid to an own key (so a later spend of it can be valued in history).
    pub fn insert_own_output(
        &self,
        op: &OutPoint,
        value: i64,
        hash160: &[u8; 20],
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO own_outputs (txid, n, value, hash160) VALUES (?1, ?2, ?3, ?4)",
            params![op.txid.as_slice(), op.n, value, hash160.as_slice()],
        )?;
        Ok(())
    }

    /// The value of an own output, if known.
    pub fn own_output_value(&self, op: &OutPoint) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM own_outputs WHERE txid = ?1 AND n = ?2",
                params![op.txid.as_slice(), op.n],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// The own outputs of one transaction: `(n, value, hash160)`.
    pub fn own_outputs_of(&self, txid: &[u8; 32]) -> Result<Vec<(u32, i64, [u8; 20])>, StoreError> {
        let mut st = self
            .conn
            .prepare("SELECT n, value, hash160 FROM own_outputs WHERE txid = ?1 ORDER BY n")?;
        let rows = st.query_map(params![txid.as_slice()], |r| {
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (n, v, h) = row?;
            let hash160: [u8; 20] = h
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("hash160 length".into()))?;
            out.push((n, v, hash160));
        }
        Ok(out)
    }

    /// Remember a token the wallet held (from `GetAddressTokens`), so a later spend of it can
    /// be valued in history after IN-1 erased it from the live set.
    pub fn insert_own_token(&self, op: &OutPoint, cents: u64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO own_tokens (txid, n, cents) VALUES (?1, ?2, ?3)",
            params![op.txid.as_slice(), op.n, cents as i64],
        )?;
        Ok(())
    }

    /// The cents of a token the wallet ever held, if known.
    pub fn own_token_cents(&self, op: &OutPoint) -> Result<Option<u64>, StoreError> {
        let c: Option<i64> = self
            .conn
            .query_row(
                "SELECT cents FROM own_tokens WHERE txid = ?1 AND n = ?2",
                params![op.txid.as_slice(), op.n],
                |r| r.get(0),
            )
            .optional()?;
        Ok(c.map(|c| c.max(0) as u64))
    }

    /// Record that `spender` spent the own token `op` of `cents`.
    pub fn insert_spent_token(
        &self,
        spender: &[u8; 32],
        op: &OutPoint,
        cents: u64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO spent_tokens (spender, txid, n, cents) VALUES (?1, ?2, ?3, ?4)",
            params![spender.as_slice(), op.txid.as_slice(), op.n, cents as i64],
        )?;
        Ok(())
    }

    /// The own tokens `spender` spent: `(outpoint, cents)`.
    pub fn spent_tokens_by(&self, spender: &[u8; 32]) -> Result<Vec<(OutPoint, u64)>, StoreError> {
        let mut st = self.conn.prepare(
            "SELECT txid, n, cents FROM spent_tokens WHERE spender = ?1 ORDER BY txid, n",
        )?;
        let rows = st.query_map(params![spender.as_slice()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (t, n, c) = row?;
            let txid: [u8; 32] = t
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("txid length".into()))?;
            out.push((OutPoint { txid, n }, c.max(0) as u64));
        }
        Ok(out)
    }

    /// Drop a pending transaction (confirmed or expired).
    pub fn remove_pending_tx(&self, txid: &[u8; 32]) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM pending_txs WHERE txid = ?1",
            params![txid.as_slice()],
        )?;
        Ok(())
    }

    // ---- mints (the two-step state machine, W4)

    /// Insert a new row (state `CarrierSent`); returns its id.
    pub fn insert_mint(&self, m: &MintRow) -> Result<i64, StoreError> {
        self.conn.execute(
            "INSERT INTO mints (kind, state, created_height, cents, lock_blocks, term_class, ref_height, lock_height, claim_height,
               collateral_zat, fee_zat, payee, attest_fee_zat, attest_payee, residual_zat, bundle, bundle_seqs, carrier_hash160,
               owner_hash160, carrier_txid, carrier_vout, main_txid, sweep_txid, expiry_height, vault_txid, owner_pubkey, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)",
            params![
                m.kind.as_str(), m.state.as_str(), m.created_height as i64, m.cents as i64, m.lock_blocks, m.term_class,
                m.ref_height, m.lock_height, m.claim_height, m.collateral_zat, m.fee_zat, m.payee, m.attest_fee_zat,
                m.attest_payee, m.residual_zat, m.bundle, m.bundle_seqs, m.carrier_hash160.as_slice(),
                m.owner_hash160.as_slice(), m.carrier_txid.as_slice(), m.carrier_vout, m.main_txid.as_slice(),
                m.sweep_txid.as_slice(), m.expiry_height, m.vault_txid.as_slice(), m.owner_pubkey, m.note
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Advance a row: state, the txid the step produced (main or sweep), and a note.
    pub fn set_mint_state(
        &self,
        id: i64,
        state: MintState,
        main_txid: Option<&[u8; 32]>,
        sweep_txid: Option<&[u8; 32]>,
        note: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE mints SET state = ?2, main_txid = COALESCE(?3, main_txid), sweep_txid = COALESCE(?4, sweep_txid), note = ?5 WHERE id = ?1",
            params![
                id,
                state.as_str(),
                main_txid.map(|t| t.as_slice()),
                sweep_txid.map(|t| t.as_slice()),
                note
            ],
        )?;
        Ok(())
    }

    /// One row.
    pub fn mint(&self, id: i64) -> Result<Option<MintRow>, StoreError> {
        Ok(self.mints()?.into_iter().find(|m| m.id == id))
    }

    /// Every row, oldest first.
    pub fn mints(&self) -> Result<Vec<MintRow>, StoreError> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, state, created_height, cents, lock_blocks, term_class, ref_height, lock_height, claim_height,
               collateral_zat, fee_zat, payee, attest_fee_zat, attest_payee, residual_zat, bundle, bundle_seqs, carrier_hash160,
               owner_hash160, carrier_txid, carrier_vout, main_txid, sweep_txid, expiry_height, vault_txid, owner_pubkey, note
             FROM mints ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(MintRowRaw {
                id: r.get(0)?,
                kind: r.get(1)?,
                state: r.get(2)?,
                created_height: r.get(3)?,
                cents: r.get(4)?,
                lock_blocks: r.get(5)?,
                term_class: r.get(6)?,
                ref_height: r.get(7)?,
                lock_height: r.get(8)?,
                claim_height: r.get(9)?,
                collateral_zat: r.get(10)?,
                fee_zat: r.get(11)?,
                payee: r.get(12)?,
                attest_fee_zat: r.get(13)?,
                attest_payee: r.get(14)?,
                residual_zat: r.get(15)?,
                bundle: r.get(16)?,
                bundle_seqs: r.get(17)?,
                carrier_hash160: r.get(18)?,
                owner_hash160: r.get(19)?,
                carrier_txid: r.get(20)?,
                carrier_vout: r.get(21)?,
                main_txid: r.get(22)?,
                sweep_txid: r.get(23)?,
                expiry_height: r.get(24)?,
                vault_txid: r.get(25)?,
                owner_pubkey: r.get(26)?,
                note: r.get(27)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            let r = row?;
            out.push(MintRow {
                id: r.id,
                kind: match r.kind.as_str() {
                    "mint" => MintKind::Mint,
                    "claim" => MintKind::Claim,
                    other => return Err(StoreError::Corrupt(format!("mint kind {other}"))),
                },
                state: MintState::parse(&r.state)
                    .ok_or_else(|| StoreError::Corrupt(format!("mint state {}", r.state)))?,
                created_height: r.created_height as u64,
                cents: r.cents as u64,
                lock_blocks: r.lock_blocks,
                term_class: r.term_class,
                ref_height: r.ref_height,
                lock_height: r.lock_height,
                claim_height: r.claim_height,
                collateral_zat: r.collateral_zat,
                fee_zat: r.fee_zat,
                payee: r.payee,
                attest_fee_zat: r.attest_fee_zat,
                attest_payee: r.attest_payee,
                residual_zat: r.residual_zat,
                bundle: r.bundle,
                bundle_seqs: r.bundle_seqs,
                carrier_hash160: arr20(&r.carrier_hash160)?,
                owner_hash160: arr20(&r.owner_hash160)?,
                carrier_txid: arr32(&r.carrier_txid)?,
                carrier_vout: r.carrier_vout,
                main_txid: arr32(&r.main_txid)?,
                sweep_txid: arr32(&r.sweep_txid)?,
                expiry_height: r.expiry_height,
                vault_txid: arr32(&r.vault_txid)?,
                owner_pubkey: r.owner_pubkey,
                note: r.note,
            });
        }
        Ok(out)
    }

    // ---- vaults (own vaults as GetVault reports them, W4)

    /// Insert or replace a vault row.
    pub fn upsert_vault(&self, v: &VaultRow) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO vaults (txid, vout, status, owner_hash160, owner_pubkey, term_class, lock_height, claim_height,
               collateral_zat, minted_cents, mint_height, claimable, underwater_at, sweep_before, close_height, closing_txid,
               void_reason, updated_height)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                v.txid.as_slice(), v.vout, v.status, v.owner_hash160.as_slice(), v.owner_pubkey.as_slice(), v.term_class,
                v.lock_height, v.claim_height, v.collateral_zat, v.minted_cents as i64, v.mint_height as i64,
                v.claimable as i64, v.underwater_at, v.sweep_before as i64, v.close_height as i64, v.closing_txid,
                v.void_reason, v.updated_height as i64
            ],
        )?;
        Ok(())
    }

    /// One vault by its mint txid.
    pub fn vault(&self, txid: &[u8; 32]) -> Result<Option<VaultRow>, StoreError> {
        Ok(self.vaults()?.into_iter().find(|v| v.txid == *txid))
    }

    /// Every vault, by mint height.
    pub fn vaults(&self) -> Result<Vec<VaultRow>, StoreError> {
        let mut st = self.conn.prepare(
            "SELECT txid, vout, status, owner_hash160, owner_pubkey, term_class, lock_height, claim_height, collateral_zat,
               minted_cents, mint_height, claimable, underwater_at, sweep_before, close_height, closing_txid, void_reason,
               updated_height FROM vaults ORDER BY mint_height, txid",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, u32>(6)?,
                r.get::<_, u32>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, i64>(10)?,
                r.get::<_, i64>(11)?,
                r.get::<_, i64>(12)?,
                r.get::<_, i64>(13)?,
                r.get::<_, i64>(14)?,
                r.get::<_, String>(15)?,
                r.get::<_, String>(16)?,
                r.get::<_, i64>(17)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                txid,
                vout,
                status,
                oh,
                opk,
                term_class,
                lock_height,
                claim_height,
                collateral_zat,
                minted,
                mint_height,
                claimable,
                underwater_at,
                sweep_before,
                close_height,
                closing_txid,
                void_reason,
                updated,
            ) = row?;
            let owner_pubkey: [u8; 33] = opk
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("owner pubkey length".into()))?;
            out.push(VaultRow {
                txid: arr32(&txid)?,
                vout,
                status,
                owner_hash160: arr20(&oh)?,
                owner_pubkey,
                term_class,
                lock_height,
                claim_height,
                collateral_zat,
                minted_cents: minted.max(0) as u64,
                mint_height: mint_height.max(0) as u64,
                claimable: claimable != 0,
                underwater_at,
                sweep_before: sweep_before.max(0) as u64,
                close_height: close_height.max(0) as u64,
                closing_txid,
                void_reason,
                updated_height: updated.max(0) as u64,
            });
        }
        Ok(out)
    }
}

/// The raw column tuple of `mints`, before validation.
struct MintRowRaw {
    id: i64,
    kind: String,
    state: String,
    created_height: i64,
    cents: i64,
    lock_blocks: u32,
    term_class: String,
    ref_height: u32,
    lock_height: u32,
    claim_height: u32,
    collateral_zat: i64,
    fee_zat: i64,
    payee: String,
    attest_fee_zat: i64,
    attest_payee: String,
    residual_zat: i64,
    bundle: Vec<u8>,
    bundle_seqs: String,
    carrier_hash160: Vec<u8>,
    owner_hash160: Vec<u8>,
    carrier_txid: Vec<u8>,
    carrier_vout: u32,
    main_txid: Vec<u8>,
    sweep_txid: Vec<u8>,
    expiry_height: u32,
    vault_txid: Vec<u8>,
    owner_pubkey: Vec<u8>,
    note: String,
}

fn arr32(v: &[u8]) -> Result<[u8; 32], StoreError> {
    v.try_into()
        .map_err(|_| StoreError::Corrupt("32-byte field length".into()))
}

fn arr20(v: &[u8]) -> Result<[u8; 20], StoreError> {
    v.try_into()
        .map_err(|_| StoreError::Corrupt("20-byte field length".into()))
}

/// Wrap or unwrap bytes under `key` with an HMAC-SHA256 counter keystream (XOR; symmetric).
/// `nonce` must be unique per secret (the key's own hash160 is used).
pub fn wrap_key(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut out = Vec::with_capacity(data.len());
    let mut counter = 0u32;
    while out.len() < data.len() {
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("any key length");
        mac.update(b"yew-imported-key-v1");
        mac.update(nonce);
        mac.update(&counter.to_le_bytes());
        let block = mac.finalize().into_bytes();
        for b in block.iter() {
            if out.len() == data.len() {
                break;
            }
            out.push(data[out.len()] ^ b);
        }
        counter += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_meta_addresses_utxos_locks_history() {
        let mut s = Store::open_in_memory().unwrap();
        assert_eq!(s.meta("schema_version").unwrap().as_deref(), Some("3"));
        s.set_meta("network", "regtest").unwrap();
        s.set_meta("network", "regtest").unwrap();
        assert_eq!(s.meta("network").unwrap().as_deref(), Some("regtest"));
        assert_eq!(s.meta_u64("last_synced_height").unwrap(), 0);

        let a = AddressRow {
            chain: 0,
            index: 0,
            address_s: "s".into(),
            address_ye: "y".into(),
            hash160: [1; 20],
            used: false,
        };
        s.insert_address(&a).unwrap();
        s.insert_address(&a).unwrap();
        assert_eq!(s.addresses().unwrap(), vec![a.clone()]);
        assert_eq!(s.max_index(0).unwrap(), Some(0));
        assert_eq!(s.max_index(1).unwrap(), None);
        assert!(s.mark_used(&[1; 20]).unwrap());
        assert!(!s.mark_used(&[1; 20]).unwrap());
        assert_eq!(s.max_used_index(0).unwrap(), Some(0));
        assert!(s.first_unused(0).unwrap().is_none());

        let u = Utxo {
            outpoint: OutPoint {
                txid: [2; 32],
                n: 1,
            },
            address: "s".into(),
            script: vec![1, 2],
            value: 5,
            height: 9,
            class: UtxoClass::Held,
            cents: 42,
        };
        s.replace_utxos(std::slice::from_ref(&u)).unwrap();
        assert_eq!(s.utxos().unwrap(), vec![u.clone()]);
        assert_eq!(s.utxo_class(&u.outpoint).unwrap(), Some(UtxoClass::Held));
        assert_eq!(
            s.utxo_class(&OutPoint {
                txid: [3; 32],
                n: 0
            })
            .unwrap(),
            None
        );

        s.lock(&u.outpoint, "spent-by:abc", 100).unwrap();
        assert_eq!(s.locks().unwrap().len(), 1);
        s.unlock(&u.outpoint).unwrap();
        assert!(s.locks().unwrap().is_empty());

        let h = HistoryRow {
            txid: [4; 32],
            height: 0,
            yec_delta: -7,
            has_payload: false,
            pending: true,
            shielded: false,
            yed_delta: 0,
            kind: String::new(),
            verdict: String::new(),
            label: String::new(),
            labelled: false,
        };
        s.upsert_history(&h).unwrap();
        s.set_history_label(&[4; 32], -500, "transfer", "ok", "sent $5.00", true)
            .unwrap();
        s.upsert_history_seen(&HistoryRow {
            height: 12,
            pending: false,
            ..h.clone()
        })
        .unwrap();
        let hist = s.history().unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].height, 12);
        assert!(!hist[0].pending);
        assert_eq!(
            (hist[0].yed_delta, hist[0].kind.as_str(), hist[0].labelled),
            (-500, "transfer", true)
        );
        assert_eq!(
            s.history_row(&[4; 32]).unwrap().unwrap().label,
            "sent $5.00"
        );
        s.insert_own_token(&u.outpoint, 42).unwrap();
        assert_eq!(s.own_token_cents(&u.outpoint).unwrap(), Some(42));
        assert_eq!(
            s.own_token_cents(&OutPoint {
                txid: [8; 32],
                n: 0
            })
            .unwrap(),
            None
        );
        s.insert_spent_token(&[4; 32], &u.outpoint, 42).unwrap();
        s.insert_spent_token(&[4; 32], &u.outpoint, 42).unwrap();
        assert_eq!(s.spent_tokens_by(&[4; 32]).unwrap(), vec![(u.outpoint, 42)]);
        assert!(s.spent_tokens_by(&[5; 32]).unwrap().is_empty());

        s.insert_pending_tx(&[4; 32], &[9, 9], 50).unwrap();
        assert_eq!(s.pending_txs().unwrap().len(), 1);
        s.remove_pending_tx(&[4; 32]).unwrap();
        assert!(s.pending_txs().unwrap().is_empty());

        s.insert_own_output(&u.outpoint, 5, &[1; 20]).unwrap();
        assert_eq!(s.own_output_value(&u.outpoint).unwrap(), Some(5));
        assert_eq!(s.own_outputs_of(&[2; 32]).unwrap(), vec![(1, 5, [1; 20])]);
        s.insert_imported_key(&[7; 20], &[1, 2, 3]).unwrap();
        assert_eq!(s.imported_key(&[7; 20]).unwrap(), Some(vec![1, 2, 3]));
    }

    #[test]
    fn v1_file_migrates_in_place() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta VALUES ('schema_version', '1');
             CREATE TABLE utxos (txid BLOB NOT NULL, n INTEGER NOT NULL, address TEXT NOT NULL, script BLOB NOT NULL,
               value INTEGER NOT NULL, height INTEGER NOT NULL, class TEXT NOT NULL, PRIMARY KEY (txid, n));
             CREATE TABLE history (txid BLOB PRIMARY KEY, height INTEGER NOT NULL, yec_delta INTEGER NOT NULL,
               has_payload INTEGER NOT NULL, pending INTEGER NOT NULL, shielded INTEGER NOT NULL);
             INSERT INTO history VALUES (x'0101010101010101010101010101010101010101010101010101010101010101', 3, 4, 0, 0, 0);",
        )
        .unwrap();
        let s = Store::init(conn).unwrap();
        assert_eq!(s.meta("schema_version").unwrap().as_deref(), Some("3"));
        assert!(s.mints().unwrap().is_empty() && s.vaults().unwrap().is_empty());
        assert!(s.utxos().unwrap().is_empty());
        let h = s.history().unwrap();
        assert_eq!(h.len(), 1);
        assert!(!h[0].labelled && h[0].label.is_empty());
    }

    #[test]
    fn wrap_is_symmetric_and_nonce_bound() {
        let secret = [0x5a; 32];
        let w = wrap_key(b"k", b"n1", &secret);
        assert_ne!(w, secret.to_vec());
        assert_eq!(wrap_key(b"k", b"n1", &w), secret.to_vec());
        assert_ne!(wrap_key(b"k", b"n2", &w), secret.to_vec());
        assert_eq!(wrap_key(b"k", b"n", &[0u8; 100]).len(), 100);
    }

    #[test]
    fn v2_file_gains_the_w4_tables_and_rows_round_trip() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta VALUES ('schema_version', '2');",
        )
        .unwrap();
        let s = Store::init(conn).unwrap();
        assert_eq!(s.meta("schema_version").unwrap().as_deref(), Some("3"));
        let m = MintRow {
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
            bundle_seqs: "0,1,2".into(),
            carrier_hash160: [1; 20],
            owner_hash160: [2; 20],
            carrier_txid: [3; 32],
            carrier_vout: 0,
            main_txid: [0; 32],
            sweep_txid: [0; 32],
            expiry_height: 518,
            vault_txid: [0; 32],
            owner_pubkey: Vec::new(),
            note: String::new(),
        };
        let id = s.insert_mint(&m).unwrap();
        assert_eq!(id, 1);
        assert_eq!(s.mint(1).unwrap().unwrap(), MintRow { id: 1, ..m.clone() });
        s.set_mint_state(1, MintState::MainSent, Some(&[4; 32]), None, "sent")
            .unwrap();
        let got = s.mint(1).unwrap().unwrap();
        assert_eq!(
            (got.state, got.main_txid, got.note.as_str()),
            (MintState::MainSent, [4; 32], "sent")
        );
        s.set_mint_state(1, MintState::Lapsed, None, Some(&[5; 32]), "")
            .unwrap();
        let got = s.mint(1).unwrap().unwrap();
        assert_eq!((got.main_txid, got.sweep_txid), ([4; 32], [5; 32]));
        assert!(MintState::Lapsed.in_flight() && !MintState::Swept.in_flight());
        for st in [
            MintState::CarrierSent,
            MintState::Done,
            MintState::Failed,
            MintState::SweepSent,
        ] {
            assert_eq!(MintState::parse(st.as_str()), Some(st));
        }
        let v = VaultRow {
            txid: [6; 32],
            vout: 0,
            status: "ACTIVE".into(),
            owner_hash160: [2; 20],
            owner_pubkey: [2; 33],
            term_class: "A".into(),
            lock_height: 526,
            claim_height: 550,
            collateral_zat: 1_000_000_000,
            minted_cents: 10_000,
            mint_height: 481,
            claimable: false,
            underwater_at: 11_000_000,
            sweep_before: 0,
            close_height: 0,
            closing_txid: String::new(),
            void_reason: String::new(),
            updated_height: 490,
        };
        s.upsert_vault(&v).unwrap();
        assert_eq!(s.vault(&[6; 32]).unwrap(), Some(v.clone()));
        assert!(v.is_open());
        s.upsert_vault(&VaultRow {
            status: "CLOSED".into(),
            close_height: 530,
            ..v
        })
        .unwrap();
        let got = s.vaults().unwrap();
        assert_eq!(got.len(), 1);
        assert!(!got[0].is_open() && got[0].close_height == 530);
    }
}
