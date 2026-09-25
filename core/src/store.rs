//! Storage (D-W-6): the SQLite schema v1 (wallet meta, addresses, utxos with class, locks,
//! history, own outputs, pending transactions, imported keys) and its queries. `rusqlite`, bundled.
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
pub const SCHEMA_VERSION: i64 = 1;

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
    /// The transaction carried an `OP_RETURN` output (a possible `"YB"` payload; W2 labels it).
    pub has_payload: bool,
    /// Broadcast by this wallet and not yet seen confirmed.
    pub pending: bool,
    /// The transaction had shielded components.
    pub shielded: bool,
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
  PRIMARY KEY (txid, n));
CREATE TABLE IF NOT EXISTS locks (
  txid BLOB NOT NULL, n INTEGER NOT NULL, reason TEXT NOT NULL,
  expiry_height INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (txid, n));
CREATE TABLE IF NOT EXISTS history (
  txid BLOB PRIMARY KEY, height INTEGER NOT NULL, yec_delta INTEGER NOT NULL,
  has_payload INTEGER NOT NULL, pending INTEGER NOT NULL, shielded INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pending_txs (txid BLOB PRIMARY KEY, raw BLOB NOT NULL, expiry_height INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS own_outputs (txid BLOB NOT NULL, n INTEGER NOT NULL, value INTEGER NOT NULL, hash160 BLOB NOT NULL, PRIMARY KEY (txid, n));
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
                "INSERT INTO utxos (txid, n, address, script, value, height, class) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for u in utxos {
                st.execute(params![
                    u.outpoint.txid.as_slice(),
                    u.outpoint.n,
                    u.address,
                    u.script,
                    u.value,
                    u.height as i64,
                    u.class.as_str()
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every UTXO.
    pub fn utxos(&self) -> Result<Vec<Utxo>, StoreError> {
        let mut st = self.conn.prepare("SELECT txid, n, address, script, value, height, class FROM utxos ORDER BY height, txid, n")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (t, n, address, script, value, height, class) = row?;
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

    /// Insert or update a history row.
    pub fn upsert_history(&self, row: &HistoryRow) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO history (txid, height, yec_delta, has_payload, pending, shielded) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(txid) DO UPDATE SET height = excluded.height, yec_delta = excluded.yec_delta,
             has_payload = excluded.has_payload, pending = excluded.pending, shielded = excluded.shielded",
            params![row.txid.as_slice(), row.height as i64, row.yec_delta, row.has_payload as i64, row.pending as i64, row.shielded as i64],
        )?;
        Ok(())
    }

    /// History, newest first (pending rows first).
    pub fn history(&self) -> Result<Vec<HistoryRow>, StoreError> {
        let mut st = self.conn.prepare("SELECT txid, height, yec_delta, has_payload, pending, shielded FROM history ORDER BY pending DESC, height DESC")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (t, height, yec_delta, p, pending, sh) = row?;
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
        assert_eq!(s.meta("schema_version").unwrap().as_deref(), Some("1"));
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
        };
        s.upsert_history(&h).unwrap();
        s.upsert_history(&HistoryRow {
            height: 12,
            pending: false,
            ..h.clone()
        })
        .unwrap();
        let hist = s.history().unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].height, 12);
        assert!(!hist[0].pending);

        s.insert_pending_tx(&[4; 32], &[9, 9], 50).unwrap();
        assert_eq!(s.pending_txs().unwrap().len(), 1);
        s.remove_pending_tx(&[4; 32]).unwrap();
        assert!(s.pending_txs().unwrap().is_empty());

        s.insert_own_output(&u.outpoint, 5, &[1; 20]).unwrap();
        assert_eq!(s.own_output_value(&u.outpoint).unwrap(), Some(5));
        s.insert_imported_key(&[7; 20], &[1, 2, 3]).unwrap();
        assert_eq!(s.imported_key(&[7; 20]).unwrap(), Some(vec![1, 2, 3]));
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
