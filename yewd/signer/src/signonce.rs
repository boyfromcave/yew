// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The set sign-once records and the restore marker (ycash6 `doc/vault-rpc.md`
//! `set_signunlock`, 07/F-5), kept **with the keys** (K-24: a guard must live with the key):
//! `<signer dir>/signonce.json`, written atomically and fsynced **before** a signature leaves the
//! signer, so a signer restart keeps every record and a second, different sighash for one
//! `(setid, prevout)` is refused.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yewd_proto::{SignedRecord, SignedRecords};

pub const FILE: &str = "signonce.json";
pub const FORMAT: &str = "yewd-signonce-1";

#[derive(Serialize, Deserialize)]
struct OnDisk {
    format: String,
    restored: bool,
    records: Vec<SignedRecord>,
}

/// The records, keyed by `(setid, prevout)`.
#[derive(Debug)]
pub struct SignOnce {
    path: PathBuf,
    pub restored: bool,
    records: BTreeMap<(String, String), (u8, String)>,
}

/// What [`SignOnce::check`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    /// The same role and sighash are recorded: signing again is idempotent.
    Same,
    /// Nothing is recorded for the pair.
    Absent,
    /// Another role or sighash is recorded: `(role, sighash)`.
    Different(u8, String),
}

impl SignOnce {
    /// Load `dir/signonce.json`; a missing file is an empty record set with the marker `restored`.
    pub fn load(dir: &Path, restored_if_new: bool) -> Result<SignOnce, String> {
        let path = dir.join(FILE);
        match std::fs::read_to_string(&path) {
            Ok(t) => {
                let d: OnDisk =
                    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))?;
                if d.format != FORMAT {
                    return Err(format!("{}: unknown format {}", path.display(), d.format));
                }
                let mut records = BTreeMap::new();
                for r in d.records {
                    records.insert((r.setid, r.prevout), (r.role, r.sighash));
                }
                Ok(SignOnce {
                    path,
                    restored: d.restored,
                    records,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let s = SignOnce {
                    path,
                    restored: restored_if_new,
                    records: BTreeMap::new(),
                };
                s.save()?;
                Ok(s)
            }
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn check(&self, setid: &str, prevout: &str, role: u8, sighash: &str) -> Check {
        match self.records.get(&(setid.to_string(), prevout.to_string())) {
            None => Check::Absent,
            Some((r, h)) if *r == role && h == sighash => Check::Same,
            Some((r, h)) => Check::Different(*r, h.clone()),
        }
    }

    /// Record `(setid, prevout) → (role, sighash)` and write it to disk before returning.
    pub fn record(
        &mut self,
        setid: &str,
        prevout: &str,
        role: u8,
        sighash: &str,
    ) -> Result<(), String> {
        self.records.insert(
            (setid.to_string(), prevout.to_string()),
            (role, sighash.to_string()),
        );
        self.save()
    }

    /// `set_importsigned`: all or nothing; a differing record refuses the whole import.
    pub fn import(&mut self, recs: &[SignedRecord]) -> Result<(u32, u32), String> {
        let mut added = 0;
        let mut present = 0;
        for r in recs {
            match self.check(&r.setid, &r.prevout, r.role, &r.sighash) {
                Check::Same => present += 1,
                Check::Absent => added += 1,
                Check::Different(role, h) => {
                    return Err(format!(
                        "set-sign-once: the wallet already holds a different record for set {} prevout {} (role {role}, sighash {h}); nothing was imported",
                        r.setid, r.prevout
                    ))
                }
            }
        }
        for r in recs {
            self.records.insert(
                (r.setid.clone(), r.prevout.clone()),
                (r.role, r.sighash.clone()),
            );
        }
        self.save()?;
        Ok((added, present))
    }

    pub fn acknowledge(&mut self) -> Result<(), String> {
        self.restored = false;
        self.save()
    }

    pub fn list(&self) -> SignedRecords {
        SignedRecords {
            restored: self.restored,
            records: self
                .records
                .iter()
                .map(|((s, p), (role, h))| SignedRecord {
                    setid: s.clone(),
                    prevout: p.clone(),
                    role: *role,
                    sighash: h.clone(),
                })
                .collect(),
        }
    }

    fn save(&self) -> Result<(), String> {
        use std::io::Write;
        let d = OnDisk {
            format: FORMAT.into(),
            restored: self.restored,
            records: self.list().records,
        };
        let text = serde_json::to_vec_pretty(&d).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("json.tmp");
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(&text)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}
