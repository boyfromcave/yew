// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's imported transparent keys (`importprivkey`, S3): keys that are not derived from
//! the seed, as an attestor or a Hawkeye member brings them. `<signer dir>/imported.json`, mode
//! 0600, written atomically. A key is named by its index in the store
//! (`KeyRef::Bip32 { chain: IMPORTED_CHAIN, index }`); the façade learns only the public keys
//! (`PublicBundle::imported`). The S4 encrypted store replaces the plain file with the seed's.

use std::path::{Path, PathBuf};

use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

pub const FILE: &str = "imported.json";
pub const FORMAT: &str = "yewd-signer-imported-1";

#[derive(Serialize, Deserialize)]
struct OnDisk {
    format: String,
    /// Secret keys, hex.
    keys: Vec<String>,
}

pub struct Imported {
    path: PathBuf,
    keys: Vec<SecretKey>,
}

impl std::fmt::Debug for Imported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Imported({} keys)", self.keys.len())
    }
}

impl Imported {
    pub fn load(dir: &Path) -> Result<Imported, String> {
        let path = dir.join(FILE);
        let keys = match std::fs::read_to_string(&path) {
            Ok(t) => {
                let d: OnDisk =
                    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))?;
                if d.format != FORMAT {
                    return Err(format!("{}: unknown format {}", path.display(), d.format));
                }
                d.keys
                    .iter()
                    .map(|h| {
                        let b: [u8; 32] = hex::decode(h)
                            .ok()
                            .and_then(|b| b.try_into().ok())
                            .ok_or_else(|| format!("{}: a key is not 32 bytes", path.display()))?;
                        SecretKey::from_secret_bytes(b)
                            .map_err(|_| format!("{}: a key is out of range", path.display()))
                    })
                    .collect::<Result<Vec<_>, String>>()?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(Imported { path, keys })
    }

    pub fn get(&self, index: u32) -> Option<&SecretKey> {
        self.keys.get(index as usize)
    }

    /// The compressed public keys, in store order.
    pub fn pubkeys(&self) -> Vec<[u8; 33]> {
        self.keys
            .iter()
            .map(|k| secp256k1::PublicKey::from_secret_key(k).serialize())
            .collect()
    }

    /// Add `key` unless it is held; its index and whether it was new. Written before returning.
    pub fn add(&mut self, key: SecretKey) -> Result<(u32, bool), String> {
        if let Some(i) = self.keys.iter().position(|k| k == &key) {
            return Ok((i as u32, false));
        }
        self.keys.push(key);
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
            keys: self
                .keys
                .iter()
                .map(|k| hex::encode(k.to_secret_bytes()))
                .collect(),
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
