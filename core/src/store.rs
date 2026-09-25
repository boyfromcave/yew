//! Storage (D-W-6): the SQLite schema (wallet meta, addresses, utxos with class and cents,
//! locks, history with labels, own outputs, own tokens, pending transactions, imported keys)
//! and its queries. `rusqlite`, bundled. Schema v2 (W2) adds `utxos.cents`, the history label
//! columns and `own_tokens`; a v1 file is migrated in place (`ALTER TABLE`, additive only).
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
pub const SCHEMA_VERSION: i64 = 2;

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
        assert_eq!(s.meta("schema_version").unwrap().as_deref(), Some("2"));
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
        assert_eq!(s.meta("schema_version").unwrap().as_deref(), Some("2"));
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
}
