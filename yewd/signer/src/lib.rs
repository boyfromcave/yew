// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yewd-signer`: the process that holds the seed (workspace plan §3b, K-24, §4.3 rule 2). The
//! façade never reads the seed: it asks the signer for the wallet's **public bundle**
//! ([`yewd_proto::PublicBundle`]) and keeps only that.
//!
//! **S1** is the keystore half: [`init`] creates (or restores) the seed in the signer's own
//! directory, [`Keystore::public`] derives the public material from it with yew-core's own
//! derivations (`keys.rs` BIP32 `m/44'/347'/0'`, `shielded_keys.rs` ZIP-32 `m/32'/347'/0'`,
//! `pq.rs` `DerivePQSeed`), so a seed restored in the YEW app sees the same coins. S2 adds the
//! Unix-socket server, the encrypted store, signing, the sign-once records and the attestation
//! guard; until then the façade runs this binary as a child process for each bundle request.

pub mod attest;
pub mod imported;
pub mod pqimported;
pub mod sapling;
pub mod seal;
pub mod server;
pub mod sign;
pub mod signonce;
pub mod walletio;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yew_core::keys::{self, ExtendedPrivKey, SecretString, HARDENED};
use yew_core::params::{Network, ACCOUNT, BIP44_PURPOSE, COIN_TYPE};
use yew_core::pq::{PqKey, PqSeedRoot};
use yew_core::shielded_keys::SaplingAccount;
use yewd_proto::{AccountXpub, PqPublic, PublicBundle, PublicRequest, PUBLIC_FORMAT};

/// The seed file's name inside the signer directory, and its format tag.
pub const SEED_FILE: &str = "seed.json";
pub const SEED_FORMAT: &str = "yewd-signer-seed-1";

/// The socket `serve` listens on by default, inside the signer directory.
pub const SOCKET_FILE: &str = "signer.sock";

/// The most post-quantum keys one request may derive (SLH-DSA key generation is not free).
pub const MAX_PQ_PER_REQUEST: u32 = 1_000;

#[derive(Debug)]
pub struct SignerError(pub String);

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SignerError {}

fn err<T>(m: impl Into<String>) -> Result<T, SignerError> {
    Err(SignerError(m.into()))
}

/// The seed file. S1 keeps the phrase in a mode-0600 file in a mode-0700 directory; the
/// encrypted store (`encryptwallet`/`walletpassphrase`, plan §3b S4) replaces it.
#[derive(Serialize, Deserialize)]
struct SeedFile {
    format: String,
    network: String,
    /// The phrase; empty once the wallet is encrypted (`sealed` holds it).
    #[serde(default)]
    mnemonic: String,
    /// The phrase sealed under the wallet passphrase (`encryptwallet`, S4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<seal::Sealed>,
    /// The height a scan of this seed starts at (0: from genesis; a restored phrase).
    birthday: u64,
    /// The seed was restored from a phrase (`init -mnemonic=`): the sign-once restore marker
    /// starts set (07/F-5; ycashd's `-mnemonicfile` restore).
    #[serde(default)]
    restored: bool,
}

/// The seed file's path in `dir`.
pub fn seed_path(dir: &Path) -> PathBuf {
    dir.join(SEED_FILE)
}

/// Create the seed in `dir` (mode 0700) unless one is there: a fresh 24-word phrase, or
/// `mnemonic` (a restore). Returns whether a seed was created. An existing seed for another
/// network is an error; an existing seed is never replaced.
pub fn init(
    dir: &Path,
    network: Network,
    mnemonic: Option<&str>,
    birthday: u64,
) -> Result<bool, SignerError> {
    let path = seed_path(dir);
    if path.exists() {
        let ks = Keystore::load(dir, network)?;
        if let Some(m) = mnemonic {
            let held = ks
                .mnemonic
                .as_ref()
                .map(|h| h.to_string())
                .unwrap_or_default();
            // ycashd's texts (wallet.cpp, -mnemonicfile on an existing wallet)
            if ks.mnemonic.is_none() && ks.encrypted() {
                // locked: the seed is sealed; the public cache holds its fingerprint
                let mut given = keys::seed_from_mnemonic(m, "")
                    .map_err(|e| SignerError(format!("yewd-signer: bad mnemonic: {e}")))?;
                let fp = hex::encode(seed_fingerprint(&given));
                keys::wipe(&mut given);
                match read_public_cache(dir) {
                    Ok(c) if c.seed_fp != fp => {
                        return err(format!(
                            "-mnemonicfile applies only when creating a new wallet, and this wallet has another seed ({})",
                            path.display()
                        ))
                    }
                    Ok(_) => eprintln!("-mnemonicfile ignored: the wallet exists and has this seed"),
                    Err(_) => eprintln!(
                        "-mnemonicfile ignored: the wallet exists (its seed fingerprint is unknown)"
                    ),
                }
                return Ok(false);
            }
            if ks.mnemonic.is_none() {
                return err("-mnemonicfile applies only when creating a new wallet, and this existing wallet has no mnemonic seed".to_string());
            }
            if m.split_whitespace().collect::<Vec<_>>()
                != held.split_whitespace().collect::<Vec<_>>()
            {
                return err(format!(
                    "-mnemonicfile applies only when creating a new wallet, and this wallet has another seed ({})",
                    path.display()
                ));
            }
            eprintln!("-mnemonicfile ignored: the wallet exists and has this seed");
        }
        return Ok(false);
    }
    let phrase = match mnemonic {
        Some(m) => {
            // validate before writing
            keys::seed_from_mnemonic(m, "")
                .map_err(|e| SignerError(format!("yewd-signer: bad mnemonic: {e}")))?;
            m.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        None => {
            keys::generate_mnemonic(24).map_err(|e| SignerError(format!("yewd-signer: {e}")))?
        }
    };
    std::fs::create_dir_all(dir).map_err(|e| SignerError(format!("{}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| SignerError(format!("{}: {e}", dir.display())))?;
    }
    let file = SeedFile {
        format: SEED_FORMAT.into(),
        network: network.chain_name().into(),
        mnemonic: phrase,
        sealed: None,
        birthday,
        restored: mnemonic.is_some(),
    };
    write_seed_file(dir, &file)?;
    Ok(true)
}

/// The recovery phrase of a `-mnemonicfile` (ycashd's `ReadRecoveryPhraseFile`, 6.20.0): the
/// phrase on a line of its own, or a `z_exportwallet` file's `# - recovery_phrase="…"` line with
/// its `# - language=…` line (English when none is given; the only language yew-core reads). The
/// signer reads the file itself, so the phrase never passes through the façade or a command line.
pub fn read_recovery_phrase_file(path: &Path) -> Result<String, SignerError> {
    const PHRASE_KEY: &str = "recovery_phrase=\"";
    const LANGUAGE_KEY: &str = "# - language=";
    let text = std::fs::read_to_string(path)
        .map_err(|_| SignerError(format!("cannot open {}", path.display())))?;
    let mut phrase = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(at) = line.find(PHRASE_KEY) {
            let rest = &line[at + PHRASE_KEY.len()..];
            if let Some(end) = rest.find('"') {
                phrase = rest[..end].to_string();
            }
        } else if let Some(name) = line.strip_prefix(LANGUAGE_KEY) {
            if name != "English" {
                return err(format!(
                    "{} names an unknown phrase language '{name}'",
                    path.display()
                ));
            }
        } else if phrase.is_empty() && !line.is_empty() && !line.starts_with('#') {
            phrase = line.to_string();
        }
    }
    let phrase = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    if phrase.is_empty() || keys::seed_from_mnemonic(&phrase, "").is_err() {
        return err(format!(
            "{} does not hold a valid English recovery phrase",
            path.display()
        ));
    }
    Ok(phrase)
}

/// Write the seed file atomically, mode 0600.
fn write_seed_file(dir: &Path, file: &SeedFile) -> Result<(), SignerError> {
    let path = seed_path(dir);
    let text = serde_json::to_string_pretty(file).expect("serializable");
    let tmp = dir.join(format!("{SEED_FILE}.tmp"));
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let _ = std::fs::remove_file(&tmp);
        let mut f = o
            .open(&tmp)
            .map_err(|e| SignerError(format!("{}: {e}", tmp.display())))?;
        f.write_all(text.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| SignerError(format!("{}: {e}", tmp.display())))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| SignerError(format!("{}: {e}", path.display())))?;
    Ok(())
}

/// The loaded seed (the phrase; the BIP39 seed is recomputed per request and wiped).
pub struct Keystore {
    network: Network,
    /// The phrase; `None` while an encrypted wallet is locked.
    mnemonic: Option<SecretString>,
    /// The sealed phrase of an encrypted wallet.
    sealed: Option<seal::Sealed>,
    birthday: u64,
    restored: bool,
    dir: Option<PathBuf>,
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keystore({:?})", self.network)
    }
}

impl Keystore {
    /// Load the seed of `dir` for `network`.
    pub fn load(dir: &Path, network: Network) -> Result<Keystore, SignerError> {
        let path = seed_path(dir);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| SignerError(format!("yewd-signer: {}: {e}", path.display())))?;
        let f: SeedFile = serde_json::from_str(&text)
            .map_err(|e| SignerError(format!("yewd-signer: {}: {e}", path.display())))?;
        if f.format != SEED_FORMAT {
            return err(format!(
                "yewd-signer: {}: unknown format {}",
                path.display(),
                f.format
            ));
        }
        if f.network != network.chain_name() {
            return err(format!(
                "yewd-signer: {} is a {} seed, asked for {}",
                path.display(),
                f.network,
                network.chain_name()
            ));
        }
        let mnemonic = if f.sealed.is_some() {
            None
        } else {
            Some(SecretString::new(f.mnemonic))
        };
        Ok(Keystore {
            network,
            mnemonic,
            sealed: f.sealed,
            birthday: f.birthday,
            restored: f.restored,
            dir: Some(dir.to_path_buf()),
        })
    }

    /// Whether the wallet is encrypted.
    pub fn encrypted(&self) -> bool {
        self.sealed.is_some()
    }

    /// Whether the phrase is available (unencrypted, or unlocked).
    pub fn unlocked(&self) -> bool {
        self.mnemonic.is_some()
    }

    /// Open the sealed phrase with `pass` (`walletpassphrase`). False for a wrong passphrase.
    pub fn unlock(&mut self, pass: &str) -> bool {
        let Some(s) = &self.sealed else {
            return true;
        };
        match seal::open(pass, s).and_then(|b| String::from_utf8(b).ok()) {
            Some(m) => {
                self.mnemonic = Some(SecretString::new(m));
                true
            }
            None => false,
        }
    }

    /// Forget the phrase (`walletlock`); a no-op on an unencrypted wallet.
    pub fn lock(&mut self) {
        if self.sealed.is_some() {
            self.mnemonic = None;
        }
    }

    /// Seal the phrase under `pass` and rewrite the seed file (`encryptwallet`); the public cache
    /// is written first so a locked signer can still answer `public`.
    pub fn encrypt(&mut self, pass: &str, cache: &PublicBundle) -> Result<(), SignerError> {
        let dir = self
            .dir
            .clone()
            .ok_or_else(|| SignerError("yewd-signer: an in-memory keystore".into()))?;
        let phrase = self
            .mnemonic
            .as_ref()
            .ok_or_else(|| SignerError("yewd-signer: the wallet is locked".into()))?
            .to_string();
        write_public_cache(&dir, cache)?;
        let sealed = seal::seal(pass, phrase.as_bytes())
            .map_err(|e| SignerError(format!("yewd-signer: {e}")))?;
        let file = SeedFile {
            format: SEED_FORMAT.into(),
            network: self.network.chain_name().into(),
            mnemonic: String::new(),
            sealed: Some(sealed.clone()),
            birthday: self.birthday,
            restored: self.restored,
        };
        write_seed_file(&dir, &file)?;
        self.sealed = Some(sealed);
        self.mnemonic = None;
        Ok(())
    }

    /// A keystore over a phrase held in memory (tests, the vector replay).
    pub fn from_mnemonic(network: Network, mnemonic: &str) -> Keystore {
        Keystore {
            network,
            mnemonic: Some(SecretString::new(mnemonic.to_string())),
            sealed: None,
            birthday: 0,
            restored: false,
            dir: None,
        }
    }

    /// The phrase (the signer's own use only); `None` while locked.
    pub(crate) fn phrase(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// Whether the seed was restored from a phrase.
    pub fn restored(&self) -> bool {
        self.restored
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The height a scan of this seed starts at.
    pub fn birthday(&self) -> u64 {
        self.birthday
    }

    /// The public bundle: the account xpub, the Sapling DFVK, and the PQ keys `req` names.
    /// While an encrypted wallet is locked the answer comes from the public cache, and a
    /// post-quantum key it does not hold is refused ([`LOCKED`]); unlocked, the cache grows.
    pub fn public(&self, req: &PublicRequest) -> Result<PublicBundle, SignerError> {
        let Some(m) = &self.mnemonic else {
            let dir = self
                .dir
                .as_ref()
                .ok_or_else(|| SignerError(LOCKED.into()))?;
            let cache = read_public_cache(dir)?;
            let mut out = cache.clone();
            out.pq.clear();
            for &(scheme, from, count) in &req.pq {
                for index in from..from.saturating_add(count) {
                    match cache
                        .pq
                        .iter()
                        .find(|k| k.scheme == scheme && k.index == index)
                    {
                        Some(k) => out.pq.push(k.clone()),
                        None => return Err(SignerError(LOCKED.into())),
                    }
                }
            }
            return Ok(out);
        };
        let mut seed = keys::seed_from_mnemonic(m, "")
            .map_err(|e| SignerError(format!("yewd-signer: {e}")))?;
        let out = public_from_seed(self.network, &seed, req);
        keys::wipe(&mut seed);
        if let (Ok(b), true, Some(dir)) = (&out, self.sealed.is_some(), &self.dir) {
            if let Ok(mut cache) = read_public_cache(dir) {
                let mut grew = false;
                for k in &b.pq {
                    if !cache
                        .pq
                        .iter()
                        .any(|c| c.scheme == k.scheme && c.index == k.index)
                    {
                        cache.pq.push(k.clone());
                        grew = true;
                    }
                }
                if grew {
                    let _ = write_public_cache(dir, &cache);
                }
            }
        }
        out
    }
}

/// The refusal text of anything that needs the phrase while an encrypted wallet is locked.
pub const LOCKED: &str = "locked: the wallet is encrypted and locked; walletpassphrase first";

/// The public cache of an encrypted wallet (`public.json`): the bundle with every PQ key derived.
pub const PUBLIC_CACHE: &str = "public.json";

fn read_public_cache(dir: &Path) -> Result<PublicBundle, SignerError> {
    let p = dir.join(PUBLIC_CACHE);
    let t = std::fs::read_to_string(&p)
        .map_err(|e| SignerError(format!("yewd-signer: {}: {e}", p.display())))?;
    serde_json::from_str(&t).map_err(|e| SignerError(format!("yewd-signer: {}: {e}", p.display())))
}

fn write_public_cache(dir: &Path, b: &PublicBundle) -> Result<(), SignerError> {
    let p = dir.join(PUBLIC_CACHE);
    let tmp = dir.join(format!("{PUBLIC_CACHE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec(b).expect("serializable"))
        .and_then(|_| std::fs::rename(&tmp, &p))
        .map_err(|e| SignerError(format!("yewd-signer: {}: {e}", p.display())))
}

/// [`Keystore::public`] over a BIP39 seed.
pub fn public_from_seed(
    network: Network,
    seed: &[u8],
    req: &PublicRequest,
) -> Result<PublicBundle, SignerError> {
    let master = ExtendedPrivKey::master(seed).map_err(|e| SignerError(e.to_string()))?;
    let account = master
        .derive(&[
            BIP44_PURPOSE | HARDENED,
            COIN_TYPE | HARDENED,
            ACCOUNT | HARDENED,
        ])
        .map_err(|e| SignerError(e.to_string()))?;
    let sapling = SaplingAccount::from_seed(seed, network)
        .map_err(|e| SignerError(format!("yewd-signer: sapling: {e}")))?;
    let root = PqSeedRoot::from_seed(seed);
    let mut pq = Vec::new();
    let mut total = 0u32;
    for &(scheme, from, count) in &req.pq {
        total = total.saturating_add(count);
        if total > MAX_PQ_PER_REQUEST {
            return err(format!(
                "yewd-signer: at most {MAX_PQ_PER_REQUEST} post-quantum keys per request"
            ));
        }
        for index in from..from.saturating_add(count) {
            let key = PqKey::from_seed(scheme, &root.derive(scheme, index))
                .map_err(|e| SignerError(format!("yewd-signer: scheme {scheme}: {e}")))?;
            pq.push(PqPublic {
                scheme,
                index,
                pk: hex::encode(key.public_key()),
            });
        }
    }
    Ok(PublicBundle {
        format: PUBLIC_FORMAT.into(),
        network: network.chain_name().into(),
        seed_fp: hex::encode(seed_fingerprint(seed)),
        account: AccountXpub {
            pubkey: hex::encode(account.public_key()),
            chain_code: hex::encode(account.chain_code),
        },
        sapling_dfvk: hex::encode(sapling.viewing_key_bytes()),
        pq,
        imported: Vec::new(),
    })
}

/// ZIP-32's seed fingerprint: `BLAKE2b-256("Zcash_HD_Seed_FP", I2LEOSP_8(len(seed)) ‖ seed)`.
pub fn seed_fingerprint(seed: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(seed.len() + 1);
    data.push(seed.len() as u8);
    data.extend_from_slice(seed);
    let fp = yew_core::tx::blake2b_256(b"Zcash_HD_Seed_FP", &data);
    keys::wipe(&mut data);
    fp
}

#[cfg(test)]
mod tests {

    #[test]
    fn recovery_phrase_file() {
        let d = std::env::temp_dir().join(format!("yewd-phrase-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let dump = d.join("dump");
        std::fs::write(
            &dump,
            format!("# Wallet dump\n# - recovery_phrase=\"{phrase}\"\n# - language=English\nL1x 2026 label=\n"),
        )
        .unwrap();
        assert_eq!(read_recovery_phrase_file(&dump).unwrap(), phrase);
        let bare = d.join("bare");
        std::fs::write(&bare, format!("  {phrase}  \n")).unwrap();
        assert_eq!(read_recovery_phrase_file(&bare).unwrap(), phrase);
        let other = d.join("other");
        std::fs::write(&other, format!("# - language=French\n{phrase}\n")).unwrap();
        assert!(read_recovery_phrase_file(&other).is_err());
        let bad = d.join("bad");
        std::fs::write(&bad, "not a phrase\n").unwrap();
        assert!(read_recovery_phrase_file(&bad).is_err());
        assert!(read_recovery_phrase_file(&d.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn init_creates_once_and_refuses_another_seed() {
        let dir = std::env::temp_dir().join(format!("yewd-signer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(init(&dir, Network::Regtest, Some(PHRASE), 0).unwrap());
        assert!(!init(&dir, Network::Regtest, None, 0).unwrap());
        assert!(init(
            &dir,
            Network::Regtest,
            Some("legal winner thank year wave sausage worth useful legal winner thank yellow"),
            0
        )
        .is_err());
        assert!(Keystore::load(&dir, Network::Mainnet).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(seed_path(&dir))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o600);
        }
        let ks = Keystore::load(&dir, Network::Regtest).unwrap();
        let b = ks
            .public(&PublicRequest {
                pq: vec![(1, 0, 2)],
            })
            .unwrap();
        assert_eq!(b.pq.len(), 2);
        assert_eq!(b.format, PUBLIC_FORMAT);
        // nothing in the bundle is the phrase or a secret
        let text = serde_json::to_string(&b).unwrap();
        assert!(!text.contains("abandon"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_bundle_matches_yew_core() {
        let ks = Keystore::from_mnemonic(Network::Regtest, PHRASE);
        let b = ks.public(&PublicRequest::default()).unwrap();
        let seed = keys::seed_from_mnemonic(PHRASE, "").unwrap();
        let acct = SaplingAccount::from_seed(&seed, Network::Regtest).unwrap();
        assert_eq!(b.sapling_dfvk, hex::encode(acct.viewing_key_bytes()));
        assert_eq!(b.account.pubkey.len(), 66);
        assert!(public_from_seed(
            Network::Regtest,
            &seed,
            &PublicRequest {
                pq: vec![(1, 0, MAX_PQ_PER_REQUEST + 1)]
            }
        )
        .is_err());
    }
}
