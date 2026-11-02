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
    /// Secret keys, hex (empty once sealed).
    #[serde(default)]
    keys: Vec<String>,
    /// The public keys, hex, in store order (kept beside a sealed store, so a locked signer can
    /// still name them in its public bundle).
    #[serde(default)]
    pubkeys: Vec<String>,
    /// The keys sealed under the wallet passphrase (S4): the JSON array of `keys`, sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<crate::seal::Sealed>,
}

pub struct Imported {
    path: PathBuf,
    keys: Vec<SecretKey>,
    /// Public keys in store order (always known).
    pubs: Vec<[u8; 33]>,
    /// The passphrase-derived seal is in force: new imports are sealed, keys load on unlock.
    sealed: Option<crate::seal::Sealed>,
    /// While sealed and unlocked: the passphrase, to reseal after an import.
    pass: Option<yew_core::keys::SecretString>,
}

impl std::fmt::Debug for Imported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Imported({} keys)", self.keys.len())
    }
}

impl Imported {
    fn parse_keys(path: &Path, hexes: &[String]) -> Result<Vec<SecretKey>, String> {
        hexes
            .iter()
            .map(|h| {
                let b: [u8; 32] = hex::decode(h)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| format!("{}: a key is not 32 bytes", path.display()))?;
                SecretKey::from_secret_bytes(b)
                    .map_err(|_| format!("{}: a key is out of range", path.display()))
            })
            .collect()
    }

    pub fn load(dir: &Path) -> Result<Imported, String> {
        let path = dir.join(FILE);
        let (keys, pubs, sealed) = match std::fs::read_to_string(&path) {
            Ok(t) => {
                let d: OnDisk =
                    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))?;
                if d.format != FORMAT {
                    return Err(format!("{}: unknown format {}", path.display(), d.format));
                }
                let keys = Self::parse_keys(&path, &d.keys)?;
                let pubs = if d.sealed.is_some() {
                    d.pubkeys
                        .iter()
                        .map(|h| {
                            hex::decode(h)
                                .ok()
                                .and_then(|b| <[u8; 33]>::try_from(b).ok())
                                .ok_or_else(|| format!("{}: a public key", path.display()))
                        })
                        .collect::<Result<Vec<_>, String>>()?
                } else {
                    keys.iter()
                        .map(|k| secp256k1::PublicKey::from_secret_key(k).serialize())
                        .collect()
                };
                (keys, pubs, d.sealed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), Vec::new(), None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(Imported {
            path,
            keys,
            pubs,
            sealed,
            pass: None,
        })
    }

    pub fn get(&self, index: u32) -> Option<&SecretKey> {
        self.keys.get(index as usize)
    }

    /// The compressed public keys, in store order.
    pub fn pubkeys(&self) -> Vec<[u8; 33]> {
        self.pubs.clone()
    }

    /// Seal the store under `pass` (`encryptwallet`); the keys stay loaded until [`Self::lock`].
    pub fn encrypt(&mut self, pass: &str) -> Result<(), String> {
        self.pass = Some(yew_core::keys::SecretString::new(pass.to_string()));
        self.sealed = Some(crate::seal::seal(pass, b"[]")?);
        self.save()
    }

    /// Open the sealed store (`walletpassphrase`); false for a wrong passphrase.
    pub fn unlock(&mut self, pass: &str) -> Result<bool, String> {
        let Some(s) = &self.sealed else {
            return Ok(true);
        };
        let Some(plain) = crate::seal::open(pass, s) else {
            return Ok(false);
        };
        let hexes: Vec<String> =
            serde_json::from_slice(&plain).map_err(|e| format!("{}: {e}", self.path.display()))?;
        self.keys = Self::parse_keys(&self.path, &hexes)?;
        self.pass = Some(yew_core::keys::SecretString::new(pass.to_string()));
        Ok(true)
    }

    /// Forget the keys of a sealed store (`walletlock`).
    pub fn lock(&mut self) {
        if self.sealed.is_some() {
            self.keys.clear();
            self.pass = None;
        }
    }

    /// Add `key` unless it is held; its index and whether it was new. Written before returning.
    pub fn add(&mut self, key: SecretKey) -> Result<(u32, bool), String> {
        if let Some(i) = self.keys.iter().position(|k| k == &key) {
            return Ok((i as u32, false));
        }
        if self.sealed.is_some() && self.pass.is_none() {
            return Err("the wallet is locked".into());
        }
        self.keys.push(key);
        self.pubs
            .push(secp256k1::PublicKey::from_secret_key(&key).serialize());
        if let Err(e) = self.save() {
            self.keys.pop();
            self.pubs.pop();
            return Err(e);
        }
        Ok((self.keys.len() as u32 - 1, true))
    }

    fn save(&self) -> Result<(), String> {
        use std::io::Write;
        let hexes: Vec<String> = self
            .keys
            .iter()
            .map(|k| hex::encode(k.to_secret_bytes()))
            .collect();
        let d = match &self.pass {
            Some(pass) if self.sealed.is_some() => OnDisk {
                format: FORMAT.into(),
                keys: Vec::new(),
                pubkeys: self.pubs.iter().map(hex::encode).collect(),
                sealed: Some(crate::seal::seal(
                    pass,
                    &serde_json::to_vec(&hexes).map_err(|e| e.to_string())?,
                )?),
            },
            _ => OnDisk {
                format: FORMAT.into(),
                keys: hexes,
                pubkeys: self.pubs.iter().map(hex::encode).collect(),
                sealed: None,
            },
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
