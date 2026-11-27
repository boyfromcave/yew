// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's imported post-quantum keys (`z_importpqkey`, a dump's `pqseed=` lines; S4): keys
//! that are not this seed's own derivation, kept by their 48-byte keygen seed (ycash6 stores them
//! with `PQ_INDEX_NONE`). `<signer dir>/pqimported.json`, mode 0600, written atomically. Key `i` is
//! named `KeyRef::Pq { scheme, index: IMPORTED_PQ_BASE + i }`.
//!
//! In an encrypted wallet the seeds are sealed under the wallet passphrase as `imported.json`'s
//! keys are (`crate::seal`); the public keys stay beside the seal so a locked signer can still name
//! them. A plain file found in an encrypted wallet (written before this rule) is sealed at the
//! next unlock.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const FILE: &str = "pqimported.json";
pub const FORMAT: &str = "yewd-signer-pqimported-1";

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub scheme: u8,
    /// The keygen seed, hex (48 bytes).
    pub seed: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// A key's public part: what a locked signer still knows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PubEntry {
    pub scheme: u8,
    /// The public key, hex.
    pub pk: String,
}

#[derive(Serialize, Deserialize)]
struct OnDisk {
    format: String,
    /// Plain seeds (empty once sealed).
    #[serde(default)]
    keys: Vec<Entry>,
    /// Public keys in store order.
    #[serde(default)]
    pubs: Vec<PubEntry>,
    /// `keys` sealed under the wallet passphrase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<crate::seal::Sealed>,
}

pub struct PqImported {
    path: PathBuf,
    /// The seeds (empty while a sealed store is locked).
    pub keys: Vec<Entry>,
    pub pubs: Vec<PubEntry>,
    sealed: Option<crate::seal::Sealed>,
    pass: Option<yew_core::keys::SecretString>,
}

fn pub_of(e: &Entry) -> Result<PubEntry, String> {
    let mut seed = zeroize::Zeroizing::new(
        hex::decode(&e.seed).map_err(|_| "an imported post-quantum seed is not hex")?,
    );
    let k = yew_core::pq::PqKey::from_seed(e.scheme, &seed)
        .map_err(|_| "an imported post-quantum seed")?;
    seed.zeroize();
    Ok(PubEntry {
        scheme: e.scheme,
        pk: hex::encode(k.public_key()),
    })
}

fn open_old(path: &Path) -> Option<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    let f = o.open(path).ok()?;
    let m = f.metadata().ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() != 1 {
            return None;
        }
    }
    m.is_file().then_some(f)
}

impl PqImported {
    pub fn load(dir: &Path) -> Result<PqImported, String> {
        let path = dir.join(FILE);
        let (keys, pubs, sealed) = match std::fs::read(&path) {
            Ok(t) => {
                let t = zeroize::Zeroizing::new(t);
                // fixed messages: a parse error would quote the file, which may hold a seed
                let d: OnDisk = serde_json::from_slice(&t)
                    .map_err(|_| format!("{}: damaged (not the expected JSON)", path.display()))?;
                if d.format != FORMAT {
                    return Err(format!("{}: unknown format", path.display()));
                }
                let OnDisk {
                    keys, pubs, sealed, ..
                } = d;
                let pubs = if pubs.len() == keys.len() || sealed.is_some() {
                    pubs
                } else {
                    keys.iter().map(pub_of).collect::<Result<Vec<_>, _>>()?
                };
                (keys, pubs, sealed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), Vec::new(), None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(PqImported {
            path,
            keys,
            pubs,
            sealed,
            pass: None,
        })
    }

    /// Seal the store under `pass` (`encryptwallet`, and the migration of a plain file found in
    /// an encrypted wallet); the seeds stay loaded until [`Self::lock`].
    ///
    /// A store that is already sealed (an `encryptwallet` retried after a failure later in the
    /// sequence) is never sealed again: `pass` must open it, and the keys are loaded from it;
    /// another passphrase is an error. Sealing anew there would seal the empty key list of a
    /// locked store over the keys.
    pub fn encrypt(&mut self, pass: &str) -> Result<(), String> {
        if let Some(s) = &self.sealed {
            let Some(plain) = crate::seal::open(pass, s) else {
                return Err(
                    "the imported post-quantum keys are already sealed under another passphrase"
                        .into(),
                );
            };
            if self.pass.is_none() {
                let plain = zeroize::Zeroizing::new(plain);
                self.keys = serde_json::from_slice(&plain).map_err(|_| {
                    format!("{}: the sealed content is damaged", self.path.display())
                })?;
                self.pass = Some(yew_core::keys::SecretString::new(pass.to_string()));
            }
            return Ok(());
        }
        self.pass = Some(yew_core::keys::SecretString::new(pass.to_string()));
        self.sealed = Some(crate::seal::seal(pass, b"[]")?);
        self.save()
    }

    /// Open the sealed store (`walletpassphrase`); false for a wrong passphrase. A plain store in
    /// an encrypted wallet (`wallet_encrypted`) is sealed here.
    pub fn unlock(&mut self, pass: &str, wallet_encrypted: bool) -> Result<bool, String> {
        let Some(s) = &self.sealed else {
            if wallet_encrypted && !self.keys.is_empty() {
                self.encrypt(pass)?;
            }
            return Ok(true);
        };
        let Some(plain) = crate::seal::open(pass, s) else {
            return Ok(false);
        };
        let plain = zeroize::Zeroizing::new(plain);
        self.keys = serde_json::from_slice(&plain)
            .map_err(|_| format!("{}: the sealed content is damaged", self.path.display()))?;
        self.pass = Some(yew_core::keys::SecretString::new(pass.to_string()));
        Ok(true)
    }

    /// Forget the seeds of a sealed store (`walletlock`).
    pub fn lock(&mut self) {
        if self.sealed.is_some() {
            self.keys.clear();
            self.pass = None;
        }
    }

    /// The store is sealed and its seeds are not loaded.
    pub fn locked(&self) -> bool {
        self.sealed.is_some() && self.pass.is_none()
    }

    /// Add a key unless held: its store index and whether it was new.
    pub fn add(&mut self, scheme: u8, seed: &[u8]) -> Result<(u32, bool), String> {
        if self.locked() {
            return Err("the wallet is locked".into());
        }
        let h = zeroize::Zeroizing::new(hex::encode(seed));
        if let Some(i) = self
            .keys
            .iter()
            .position(|e| e.scheme == scheme && e.seed == *h)
        {
            return Ok((i as u32, false));
        }
        let e = Entry {
            scheme,
            seed: h.to_string(),
        };
        let p = pub_of(&e)?;
        self.keys.push(e);
        self.pubs.push(p);
        if let Err(e) = self.save() {
            self.keys.pop();
            self.pubs.pop();
            return Err(e);
        }
        Ok((self.keys.len() as u32 - 1, true))
    }

    fn save(&self) -> Result<(), String> {
        use std::io::Write;
        let d = match &self.pass {
            Some(pass) if self.sealed.is_some() => {
                let plain = zeroize::Zeroizing::new(
                    serde_json::to_vec(&self.keys).map_err(|e| e.to_string())?,
                );
                OnDisk {
                    format: FORMAT.into(),
                    keys: Vec::new(),
                    pubs: self.pubs.clone(),
                    sealed: Some(crate::seal::seal(pass, &plain)?),
                }
            }
            _ => OnDisk {
                format: FORMAT.into(),
                keys: self.keys.clone(),
                pubs: self.pubs.clone(),
                sealed: None,
            },
        };
        let text = zeroize::Zeroizing::new(serde_json::to_vec(&d).map_err(|e| e.to_string())?);
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
        // the plain file being replaced (a migration) is overwritten once the sealed one is in place
        // (O_NOFOLLOW, a regular file with a single link only: zeroing another link's content is not ours to do)
        let old = if self.sealed.is_some() {
            open_old(&self.path)
        } else {
            None
        };
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
        }
        if let Some(mut f) = old {
            use std::io::{Seek, SeekFrom};
            let n = f.metadata().map(|m| m.len()).unwrap_or(0) as usize;
            let _ = f
                .seek(SeekFrom::Start(0))
                .and_then(|_| f.write_all(&vec![0u8; n]))
                .and_then(|_| f.sync_all());
        }
        Ok(())
    }
}
