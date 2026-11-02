// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The attestation **equivocation guard** (ycash6 S16, `src/yellowback/wallet.cpp`
//! `RecordSigned`/`LookupSigned`, `attest-signed.dat`), kept with the key (K-24, plan §4.3 rule 2:
//! a guard must live with the key it guards).
//!
//! `<signer dir>/attest-signed.jsonl`: one JSON record per line, appended and **fsynced before**
//! the signature leaves the signer, so a signer restart keeps every record. A record is
//! `(seq, attestor key, citedHeight, blockHash) → (price, signature)`. EQV-1 slashes two prices of
//! one key for one block, so the guard refuses a second price for the same `(key, citedHeight,
//! blockHash)` under any seq the key held (ycashd looks the guard up by key across seqs, review of
//! the cancel limit A L-3 / B6), and returns the recorded signature for the same price. Keyed on
//! the block hash as well (audit C-5): after a reorg across `citedHeight` a signature for the new
//! block is not equivocation.
//!
//! A torn last line (the process died mid-write) never acknowledged a signature, so it is ignored
//! at load; any other unreadable line refuses to load the guard.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const FILE: &str = "attest-signed.jsonl";

/// One signed attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub seq: u16,
    /// The attestor key, hex (33 bytes).
    pub pubkey: String,
    pub cited_height: u32,
    /// The cited block's hash (display hex).
    pub block_hash: String,
    pub price_micro_usd: u32,
    /// The compact signature `r ‖ s`, hex (64 bytes).
    pub sig: String,
}

/// The guard.
#[derive(Debug)]
pub struct Guard {
    path: PathBuf,
    records: Vec<Signed>,
}

impl Guard {
    pub fn load(dir: &Path) -> Result<Guard, String> {
        let path = dir.join(FILE);
        let mut records = Vec::new();
        match std::fs::read_to_string(&path) {
            Ok(t) => {
                let lines: Vec<&str> = t.split('\n').collect();
                let last = lines.len().saturating_sub(1);
                for (i, l) in lines.iter().enumerate() {
                    if l.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<Signed>(l) {
                        Ok(r) => records.push(r),
                        // the unterminated last line of an interrupted append: never
                        // acknowledged; cut it off so the next append starts a clean line
                        Err(_) if i == last => {
                            let keep = t.len() - l.len();
                            let f = std::fs::OpenOptions::new()
                                .write(true)
                                .open(&path)
                                .map_err(|e| format!("{}: {e}", path.display()))?;
                            f.set_len(keep as u64)
                                .and_then(|_| f.sync_all())
                                .map_err(|e| format!("{}: {e}", path.display()))?;
                        }
                        Err(e) => {
                            return Err(format!("{}: line {}: {e}", path.display(), i + 1));
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
        Ok(Guard { path, records })
    }

    /// The record of `seq` for `(cited_height, block_hash)`.
    pub fn by_seq(&self, seq: u16, cited_height: u32, block_hash: &str) -> Option<&Signed> {
        self.records
            .iter()
            .find(|r| r.seq == seq && r.cited_height == cited_height && r.block_hash == block_hash)
    }

    /// Every record of the key `pubkey` for `(cited_height, block_hash)`, under any seq.
    pub fn by_key<'a>(
        &'a self,
        pubkey: &'a str,
        cited_height: u32,
        block_hash: &'a str,
    ) -> impl Iterator<Item = &'a Signed> + 'a {
        self.records.iter().filter(move |r| {
            r.pubkey == pubkey && r.cited_height == cited_height && r.block_hash == block_hash
        })
    }

    /// Append `r` and fsync it; nothing is kept in memory unless it is on disk.
    pub fn record(&mut self, r: Signed) -> Result<(), String> {
        let mut line = serde_json::to_string(&r).map_err(|e| e.to_string())?;
        line.push('\n');
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o
            .open(&self.path)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        f.write_all(line.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        self.records.push(r);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u16, price: u32) -> Signed {
        Signed {
            seq,
            pubkey: "02aa".into(),
            cited_height: 10,
            block_hash: "bb".into(),
            price_micro_usd: price,
            sig: "00".repeat(64),
        }
    }

    #[test]
    fn records_survive_a_reload_and_a_torn_tail_is_ignored() {
        let dir = std::env::temp_dir().join(format!("yewd-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut g = Guard::load(&dir).unwrap();
        assert!(g.is_empty());
        g.record(rec(0, 5)).unwrap();
        g.record(rec(1, 6)).unwrap();
        let g = Guard::load(&dir).unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g.by_seq(0, 10, "bb").unwrap().price_micro_usd, 5);
        assert_eq!(g.by_key("02aa", 10, "bb").count(), 2);
        assert!(g.by_seq(0, 10, "cc").is_none());
        // an interrupted append
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(FILE))
            .unwrap();
        f.write_all(b"{\"seq\":2,\"pub").unwrap();
        let mut g = Guard::load(&dir).unwrap();
        assert_eq!(g.len(), 2);
        g.record(rec(3, 7)).unwrap();
        assert_eq!(Guard::load(&dir).unwrap().len(), 3);
        // a damaged record in the middle refuses the guard
        std::fs::write(dir.join(FILE), "garbage\n{}\n").unwrap();
        assert!(Guard::load(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
