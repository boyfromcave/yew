// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's wallet files (S4): the dump (`z_exportwallet`: the façade writes the public text,
//! the signer each secret, §4.3 rule 2), the dump import (`importwallet`, `z_importwallet`: the
//! signer reads the file and keeps the secrets, the façade gets the public parts), the
//! post-quantum key import (`z_importpqkey`), and the backup (`backupwallet`) and its restore.
//!
//! The dump format is ycash6's (`src/wallet/rpcdump.cpp` `WriteWalletDumpToFile`,
//! `importwallet_impl`): `<WIF> <time> label=…|reserve=1|change=1 # addr=…`,
//! `pqseed=<scheme>:<index>:<seed> <time> # owner=… addr=… yecaddr=…`, the `vaultsetsig=`,
//! `vaultbuild=`, `vaultrecipient=` lines, and `<extsk> <time> <hdkeypath> <seedfp> # zaddr=…`.

use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use yew_core::keys;
use yew_core::pq::{PqKey, SEED_SIZE};
use yew_core::shielded_keys::SaplingAccount;
use yewd_proto::{
    refuse, BackupRequest, DumpLine, DumpRequest, ImportDumpRequest, ImportDumpResult, ImportedKey,
    PqImportRequest, PqImported, PqPublic, SignedRecord, BACKUP_FORMAT, IMPORTED_PQ_BASE,
};

use crate::sign::{no, Refused, SignerCore};

/// The files a backup carries (the socket and temporaries are not).
pub const BACKUP_FILES: &[&str] = &[
    crate::SEED_FILE,
    crate::PUBLIC_CACHE,
    crate::imported::FILE,
    crate::pqimported::FILE,
    "signonce.json",
    "attest-signed.jsonl",
];

/// A backup file: the signer's files by name, and the façade's state.
#[derive(Serialize, Deserialize)]
pub struct Backup {
    pub format: String,
    pub network: String,
    pub facade: String,
    pub signer: std::collections::BTreeMap<String, String>,
}

fn write_new(path: &str, text: &str, create_new: bool) -> Result<(), Refused> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if create_new {
        o.create_new(true);
    } else {
        o.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| {
        (
            refuse::FAILED,
            format!("Cannot open wallet dump file {path}: {e}"),
        )
    })?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| (refuse::FAILED, format!("{path}: {e}")))
}

/// `PqSeedRoot::derive` returns the keygen seed of `(scheme, index)`.
fn own_seed(core: &SignerCore, scheme: u8, index: u32) -> Result<[u8; SEED_SIZE], Refused> {
    let keys = core.keys()?;
    Ok(keys
        .as_ref()
        .expect("checked")
        .pq_root
        .derive(scheme, index))
}

impl SignerCore {
    /// The imported post-quantum keys' public keys (`PublicBundle::pq`, index above the base).
    pub fn pq_imported_public(&self) -> Vec<PqPublic> {
        let store = self.pq_imported.lock().unwrap_or_else(|e| e.into_inner());
        store
            .keys
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                let seed = hex::decode(&e.seed).ok()?;
                let k = PqKey::from_seed(e.scheme, &seed).ok()?;
                Some(PqPublic {
                    scheme: e.scheme,
                    index: IMPORTED_PQ_BASE + i as u32,
                    pk: hex::encode(k.public_key()),
                })
            })
            .collect()
    }

    /// The keygen seed of a post-quantum key reference (own or imported).
    fn pq_seed_of(&self, scheme: u8, index: u32) -> Result<[u8; SEED_SIZE], Refused> {
        if index >= IMPORTED_PQ_BASE {
            drop(self.keys()?);
            let store = self.pq_imported.lock().unwrap_or_else(|e| e.into_inner());
            let e = store
                .keys
                .get((index - IMPORTED_PQ_BASE) as usize)
                .ok_or_else(|| (refuse::KEY_NOT_HELD, format!("no imported key {index}")))?;
            return hex::decode(&e.seed)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| (refuse::FAILED, "an imported seed".to_string()));
        }
        own_seed(self, scheme, index)
    }

    /// `z_exportwallet`: the dump, secrets filled in here.
    pub fn dump(&self, r: &DumpRequest) -> Result<String, Refused> {
        drop(self.keys()?);
        let mut out = String::new();
        for l in &r.lines {
            match l {
                DumpLine::Text { text } => out.push_str(text),
                DumpLine::Key { key, rest } => {
                    let wif = self.dump_key(key)?;
                    out.push_str(&format!("{wif} {rest}"));
                }
                DumpLine::PqSeed {
                    scheme,
                    index,
                    index_text,
                    rest,
                } => {
                    let mut seed = self.pq_seed_of(*scheme, *index)?;
                    out.push_str(&format!(
                        "pqseed={scheme}:{index_text}:{} {rest}",
                        hex::encode(seed)
                    ));
                    keys::wipe(&mut seed);
                }
                DumpLine::Sapling { rest } => {
                    let ks = self.keystore();
                    let phrase = ks
                        .phrase()
                        .ok_or_else(|| (refuse::LOCKED, crate::LOCKED.to_string()))?;
                    let acct = SaplingAccount::from_mnemonic(phrase, "", self.network)
                        .map_err(|e| (refuse::FAILED, e.to_string()))?;
                    out.push_str(&format!("{} {rest}", &*acct.spending_key()));
                }
                DumpLine::Recovery => {
                    let ks = self.keystore();
                    let phrase = ks
                        .phrase()
                        .ok_or_else(|| (refuse::LOCKED, crate::LOCKED.to_string()))?;
                    out.push_str(&format!("# - recovery_phrase=\"{phrase}\""));
                }
            }
            out.push('\n');
        }
        write_new(&r.path, &out, true)?;
        Ok(r.path.clone())
    }

    /// One post-quantum key from its seed (`ImportPQKeySeed`): this seed's own key at `index`
    /// keeps its index; any other is stored as imported.
    fn add_pq(&self, scheme: u8, index: Option<u32>, seed: &[u8]) -> Result<PqImported, Refused> {
        if seed.len() != SEED_SIZE {
            return no(
                refuse::MALFORMED,
                format!("the seed must be {SEED_SIZE} bytes of hex"),
            );
        }
        let key = PqKey::from_seed(scheme, seed).map_err(|_| {
            (
                refuse::MALFORMED,
                "invalid post-quantum key seed or index".to_string(),
            )
        })?;
        let pk = hex::encode(key.public_key());
        if let Some(i) = index.filter(|i| *i < IMPORTED_PQ_BASE) {
            let mut own = own_seed(self, scheme, i)?;
            let same = own[..] == seed[..];
            keys::wipe(&mut own);
            if same {
                return Ok(PqImported {
                    scheme,
                    index: i,
                    own: true,
                    pk,
                    added: false,
                });
            }
        }
        let (i, added) = self
            .pq_imported
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add(scheme, seed)
            .map_err(|e| {
                (
                    refuse::FAILED,
                    format!("Error adding the post-quantum key to the wallet: {e}"),
                )
            })?;
        Ok(PqImported {
            scheme,
            index: IMPORTED_PQ_BASE + i,
            own: false,
            pk,
            added,
        })
    }

    /// `z_importpqkey`.
    pub fn import_pq(&self, r: &PqImportRequest) -> Result<PqImported, Refused> {
        drop(self.keys()?);
        let mut seed = hex::decode(&r.seed).map_err(|_| {
            (
                refuse::MALFORMED,
                format!("the seed must be {SEED_SIZE} bytes of hex"),
            )
        })?;
        let out = self.add_pq(r.scheme, r.index, &seed);
        keys::wipe(&mut seed);
        out
    }

    /// `importwallet` / `z_importwallet`: the dump at `path`, read here.
    pub fn import_dump(&self, r: &ImportDumpRequest) -> Result<ImportDumpResult, Refused> {
        drop(self.keys()?);
        let text = std::fs::read_to_string(&r.path).map_err(|e| {
            (
                refuse::MALFORMED,
                format!("Cannot open wallet dump file {}: {e}", r.path),
            )
        })?;
        let mut out = ImportDumpResult::default();
        let mut records = Vec::new();
        let mut bad = false;
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let v: Vec<&str> = line.split(' ').collect();
            let w = v[0];
            if w.starts_with("vaultsetsigs=") {
                continue;
            }
            if let Some(body) = w.strip_prefix("vaultsetsig=") {
                let f: Vec<&str> = body.split(':').collect();
                let hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
                let ok = f.len() == 5
                    && hex64(f[0])
                    && hex64(f[1])
                    && f[2].parse::<u32>().is_ok()
                    && matches!(f[3], "1" | "2")
                    && hex64(f[4]);
                if !ok {
                    return no(
                        refuse::MALFORMED,
                        format!("malformed vaultsetsig line: {w}"),
                    );
                }
                records.push(SignedRecord {
                    setid: f[0].to_lowercase(),
                    prevout: format!("{}:{}", f[1].to_lowercase(), f[2]),
                    role: f[3].parse().unwrap_or(1),
                    sighash: f[4].to_lowercase(),
                });
                continue;
            }
            if let Some(body) = w.strip_prefix("vaultbuild=") {
                let f: Vec<&str> = body.split(':').collect();
                if f.len() == 3 && f[0].len() == 64 && f[1].parse::<u32>().is_ok() {
                    out.builds.push((
                        format!("{}:{}", f[0].to_lowercase(), f[1]),
                        f[2].to_string(),
                    ));
                } else {
                    bad = true;
                }
                continue;
            }
            if let Some(body) = w.strip_prefix("vaultrecipient=") {
                match body.split_once(':') {
                    Some((h, sc)) if h.len() == 64 => {
                        out.recipients.push((h.to_lowercase(), sc.to_lowercase()))
                    }
                    _ => bad = true,
                }
                continue;
            }
            if v.len() < 2 {
                continue;
            }
            if r.zkeys && SaplingAccount::from_spending_key(self.network, w).is_ok() {
                // this signer spends its own account only (K-24); another account's key is
                // reported and skipped (finding F-S4-6)
                let own = {
                    let ks = self.keystore();
                    ks.phrase()
                        .and_then(|p| SaplingAccount::from_mnemonic(p, "", self.network).ok())
                        .map(|a| &*a.spending_key() == w)
                        .unwrap_or(false)
                };
                if !own {
                    out.skipped_zkeys += 1;
                }
                continue;
            }
            if let Some(body) = w.strip_prefix("pqseed=") {
                let f: Vec<&str> = body.split(':').collect();
                let parsed = if f.len() == 3 {
                    match (f[0].parse::<u8>(), f[1].parse::<u64>(), hex::decode(f[2])) {
                        (Ok(s), Ok(i), Ok(seed)) => Some((s, i, seed)),
                        _ => None,
                    }
                } else {
                    None
                };
                match parsed {
                    Some((scheme, index, mut seed)) => {
                        let idx = u32::try_from(index).ok();
                        match self.add_pq(scheme, idx, &seed) {
                            Ok(k) => out.pq.push(k),
                            Err(_) => bad = true,
                        }
                        keys::wipe(&mut seed);
                    }
                    None => bad = true,
                }
                continue;
            }
            let Ok(k) = keys::decode_wif(self.network, w) else {
                continue;
            };
            let mut label: Option<String> = Some(String::new());
            for t in &v[2..] {
                if t.starts_with('#') {
                    break;
                }
                if *t == "change=1" || *t == "reserve=1" {
                    label = None;
                }
                if let Some(l) = t.strip_prefix("label=") {
                    label = Some(decode_dump_string(l));
                }
            }
            match self.imports().add(k.secret) {
                Ok((index, new)) => out.keys.push((
                    ImportedKey {
                        index,
                        pubkey: hex::encode(k.pubkey),
                        new,
                    },
                    label,
                )),
                Err(_) => bad = true,
            }
        }
        if out.keys.iter().any(|(k, _)| k.new) {
            self.lock().mark_restored().map_err(|e| {
                (
                    refuse::FAILED,
                    format!("cannot write the vault sign-once restore marker: {e}"),
                )
            })?;
        }
        if !records.is_empty() {
            let mut o = self.lock();
            let (added, present) = o.import(&records).map_err(|e| {
                if e.starts_with("set-sign-once") {
                    (refuse::SET_SIGN_ONCE, e)
                } else {
                    (refuse::FAILED, e)
                }
            })?;
            out.records = (added + present) as usize;
        }
        if bad {
            return no(refuse::FAILED, "Error adding some keys to wallet");
        }
        Ok(out)
    }

    /// `backupwallet`: the signer's files and the façade's state, in one file at `path`.
    pub fn backup(&self, r: &BackupRequest) -> Result<String, Refused> {
        let mut files = std::collections::BTreeMap::new();
        for f in BACKUP_FILES {
            if let Ok(t) = std::fs::read_to_string(self.dir.join(f)) {
                files.insert(f.to_string(), t);
            }
        }
        let b = Backup {
            format: BACKUP_FORMAT.into(),
            network: self.network.chain_name().into(),
            facade: r.facade.clone(),
            signer: files,
        };
        let text = serde_json::to_string(&b).map_err(|e| (refuse::FAILED, e.to_string()))?;
        write_new(&r.path, &text, false)
            .map_err(|_| (refuse::FAILED, "Error: Wallet backup failed!".to_string()))?;
        Ok(r.path.clone())
    }
}

/// `DecodeDumpString`: `%xx` escapes.
fn decode_dump_string(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `yewd-signer restore -from=<backup>`: write the backup's signer files into `dir` (replacing
/// what is there), set the sign-once restore marker with `salvage` (`-salvagewallet`, 07/NEW-1),
/// and return the façade's state.
pub fn restore(dir: &Path, from: &Path, salvage: bool) -> Result<String, String> {
    let text = std::fs::read_to_string(from).map_err(|e| format!("{}: {e}", from.display()))?;
    let b: Backup = serde_json::from_str(&text)
        .map_err(|e| format!("{}: not a yewd backup: {e}", from.display()))?;
    if b.format != BACKUP_FORMAT {
        return Err(format!("{}: unknown format {}", from.display(), b.format));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for f in BACKUP_FILES {
        let p = dir.join(f);
        match b.signer.get(*f) {
            Some(t) => {
                let tmp = dir.join(format!("{f}.restore"));
                write_new(tmp.to_str().unwrap_or_default(), t, false).map_err(|e| e.1)?;
                std::fs::rename(&tmp, &p).map_err(|e| format!("{}: {e}", p.display()))?;
            }
            None => {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    if salvage {
        let mut once = crate::signonce::SignOnce::load(dir, false)?;
        once.mark_restored()?;
    }
    Ok(b.facade)
}

pub use yewd_proto::backup_digest;
