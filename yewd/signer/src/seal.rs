// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's encrypted store (`encryptwallet`, `walletpassphrase`, `walletlock`; plan §3b S4):
//! a secret sealed under a passphrase. The key is Argon2id (RFC 9106) of the passphrase over a
//! random 16-byte salt, 64 MiB, 3 passes, 4 lanes (the parameters of RFC 9106 §4's second
//! recommended option, as recalled from the RFC, not re-read); the cipher is ChaCha20-Poly1305 with
//! a random 12-byte nonce. The `kdf` field versions the file: seals written before this rule
//! (`pbkdf2-hmac-sha256`, 100,000 iterations) still open, and are written anew with Argon2id at
//! the next save. ycashd's
//! `CCrypter` (AES-256-CBC over `EVP_BytesToKey`) is not reproduced: the file is the signer's own,
//! and the RPC contract (the passphrase, the timeout, the error codes) is what parity needs.

use chacha20poly1305::aead::{Aead, KeyInit as _};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};

/// PBKDF2 iterations (a passphrase guess costs this many HMACs).
pub const ITERATIONS: u32 = 100_000;

pub const KDF_PBKDF2: &str = "pbkdf2-hmac-sha256";
/// The KDF of every new seal.
pub const KDF: &str = "argon2id";
/// Argon2id memory (KiB), passes and lanes of a new seal.
pub const ARGON2_M_KIB: u32 = 64 * 1024;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 4;
pub const CIPHER: &str = "chacha20poly1305";

/// A sealed secret, as it is written to disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub kdf: String,
    /// PBKDF2 iterations, or Argon2id passes.
    pub iterations: u32,
    /// Argon2id memory in KiB (absent for PBKDF2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m_kib: Option<u32>,
    /// Argon2id lanes (absent for PBKDF2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lanes: Option<u32>,
    pub salt: String,
    pub cipher: String,
    pub nonce: String,
    pub ct: String,
}

/// PBKDF2-HMAC-SHA256 with one 32-byte block (RFC 8018 §5.2, `dkLen = hLen`).
fn pbkdf2_sha256(pass: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    type H = Hmac<sha2::Sha256>;
    let mut mac = <H as KeyInit>::new_from_slice(pass).expect("any key length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut out = u;
    for _ in 1..iterations {
        let mut mac = <H as KeyInit>::new_from_slice(pass).expect("any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// Argon2id (version 0x13), 32-byte output. Bounds keep a crafted file from asking for more than
/// 1 GiB or 16 passes.
fn argon2id(pass: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Option<[u8; 32]> {
    if !(1..=16).contains(&t) || !(1..=16).contains(&p) || m_kib < 8 * p || m_kib > 1 << 20 {
        return None;
    }
    let params = argon2::Params::new(m_kib, t, p, Some(32)).ok()?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(pass, salt, &mut out).ok()?;
    Some(out)
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| format!("no randomness: {e}"))?;
    Ok(b)
}

/// Seal `plain` under `pass`.
pub fn seal(pass: &str, plain: &[u8]) -> Result<Sealed, String> {
    let salt: [u8; 16] = random()?;
    let nonce: [u8; 12] = random()?;
    let mut k = argon2id(pass.as_bytes(), &salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P)
        .ok_or("cannot derive the key")?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
    k.fill(0);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| "cannot seal".to_string())?;
    Ok(Sealed {
        kdf: KDF.into(),
        iterations: ARGON2_T,
        m_kib: Some(ARGON2_M_KIB),
        lanes: Some(ARGON2_P),
        salt: hex::encode(salt),
        cipher: CIPHER.into(),
        nonce: hex::encode(nonce),
        ct: hex::encode(ct),
    })
}

/// Open `s` with `pass`: `None` for a wrong passphrase (or a damaged file).
pub fn open(pass: &str, s: &Sealed) -> Option<Vec<u8>> {
    if s.cipher != CIPHER || s.iterations == 0 {
        return None;
    }
    let salt = hex::decode(&s.salt).ok()?;
    let nonce = hex::decode(&s.nonce).ok()?;
    let ct = hex::decode(&s.ct).ok()?;
    if nonce.len() != 12 {
        return None;
    }
    let mut k = match s.kdf.as_str() {
        KDF => argon2id(pass.as_bytes(), &salt, s.m_kib?, s.iterations, s.lanes?)?,
        KDF_PBKDF2 => pbkdf2_sha256(pass.as_bytes(), &salt, s.iterations),
        _ => return None,
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
    k.fill(0);
    cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_rfc7914_vector() {
        // RFC 7914 §11: PBKDF2-HMAC-SHA256("passwd", "salt", 1), the first 32 bytes
        assert_eq!(
            hex::encode(pbkdf2_sha256(
                &std::hint::black_box(*b"passwd"),
                &std::hint::black_box(*b"salt"),
                1
            )),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    /// A seal written before Argon2id (PBKDF2, 100,000 iterations, no m_kib/lanes fields) opens.
    #[test]
    fn pbkdf2_seal_still_opens() {
        let salt: [u8; 16] = random().unwrap();
        let nonce: [u8; 12] = random().unwrap();
        let k = pbkdf2_sha256(b"old-pass", &salt, ITERATIONS);
        let ct = ChaCha20Poly1305::new(Key::from_slice(&k))
            .encrypt(Nonce::from_slice(&nonce), &b"old secret"[..])
            .unwrap();
        let json = format!(
            r#"{{"kdf":"pbkdf2-hmac-sha256","iterations":100000,"salt":"{}","cipher":"chacha20poly1305","nonce":"{}","ct":"{}"}}"#,
            hex::encode(salt),
            hex::encode(nonce),
            hex::encode(ct)
        );
        let s: Sealed = serde_json::from_str(&json).unwrap();
        assert_eq!(open("old-pass", &s).as_deref(), Some(&b"old secret"[..]));
        assert_eq!(open("wrong", &s), None);
    }

    /// New seals are Argon2id at the stated parameters; a crafted file asking for more is refused.
    #[test]
    fn new_seal_is_argon2id() {
        let s = seal("p", b"x").unwrap();
        assert_eq!(
            (s.kdf.as_str(), s.iterations, s.m_kib, s.lanes),
            (KDF, ARGON2_T, Some(ARGON2_M_KIB), Some(ARGON2_P))
        );
        let mut big = s.clone();
        big.m_kib = Some(4 << 20);
        assert_eq!(open("p", &big), None);
        let mut noparams = s.clone();
        noparams.m_kib = None;
        assert_eq!(open("p", &noparams), None);
    }

    /// RFC 9106 §5.3 test vector (Argon2id, version 0x13) through the crate and settings this
    /// module uses (expected tag as published in the RFC).
    #[test]
    fn argon2id_rfc9106_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[4u8; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let a = argon2::Argon2::new_with_secret(
            &[3u8; 8],
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        )
        .unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn seal_and_open() {
        // a random passphrase per run: the test exercises the round trip, not a fixed key
        let pass = hex::encode(random::<8>().unwrap());
        let wrong = format!("{pass}x");
        let s = seal(&pass, b"secret words").unwrap();
        assert_eq!(open(&pass, &s).as_deref(), Some(&b"secret words"[..]));
        assert_eq!(open(&wrong, &s), None);
        let mut t = s.clone();
        t.ct.replace_range(0..2, if &s.ct[0..2] == "00" { "01" } else { "00" });
        assert_eq!(open(&pass, &t), None);
    }
}
