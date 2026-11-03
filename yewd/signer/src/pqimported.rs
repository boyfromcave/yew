// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's imported post-quantum keys (`z_importpqkey`, a dump's `pqseed=` lines; S4): keys
//! that are not this seed's own derivation, kept by their 48-byte keygen seed (ycash6 stores them
//! with `PQ_INDEX_NONE`). `<signer dir>/pqimported.json`, mode 0600, written atomically. Key `i` is
//! named `KeyRef::Pq { scheme, index: IMPORTED_PQ_BASE + i }`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const FILE: &str = "pqimported.json";
pub const FORMAT: &str = "yewd-signer-pqimported-1";

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub scheme: u8,
    /// The keygen seed, hex (48 bytes).
    pub seed: String,
}

#[derive(Serialize, Deserialize)]
struct OnDisk {
    format: String,
    keys: Vec<Entry>,
}

pub struct PqImported {
    path: PathBuf,
    pub keys: Vec<Entry>,
}

impl PqImported {
    pub fn load(dir: &Path) -> Result<PqImported, String> {
        let path = dir.join(FILE);
        let keys = match std::fs::read_to_string(&path) {
            Ok(t) => {
                let d: OnDisk =
                    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))?;
                if d.format != FORMAT {
                    return Err(format!("{}: unknown format {}", path.display(), d.format));
                }
                d.keys
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(PqImported { path, keys })
    }

    /// Add a key unless held: its store index and whether it was new.
    pub fn add(&mut self, scheme: u8, seed: &[u8]) -> Result<(u32, bool), String> {
        let h = hex::encode(seed);
        if let Some(i) = self
            .keys
            .iter()
            .position(|e| e.scheme == scheme && e.seed == h)
        {
            return Ok((i as u32, false));
        }
        self.keys.push(Entry { scheme, seed: h });
        if let Err(e) = self.save() {
            self.keys.pop();
            return Err(e);
        }
        Ok((self.keys.len() as u32 - 1, true))
    }

    fn save(&self) -> Result<(), String> {
        use std::io::Write;
        let d = OnDisk {
            format: FORMAT.into(),
            keys: self.keys.clone(),
        };
        let text = serde_json::to_vec(&d).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("json.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
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
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("{}: {e}", self.path.display()))
    }
}
