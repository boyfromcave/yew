// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's encrypted store (`encryptwallet`, `walletpassphrase`, `walletlock`; plan §3b S4):
//! a secret sealed under a passphrase. The key is PBKDF2-HMAC-SHA256 of the passphrase over a
//! random 16-byte salt; the cipher is ChaCha20-Poly1305 with a random 12-byte nonce. ycashd's
//! `CCrypter` (AES-256-CBC over `EVP_BytesToKey`) is not reproduced: the file is the signer's own,
//! and the RPC contract (the passphrase, the timeout, the error codes) is what parity needs.

use chacha20poly1305::aead::{Aead, KeyInit as _};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};

/// PBKDF2 iterations (a passphrase guess costs this many HMACs).
pub const ITERATIONS: u32 = 100_000;

pub const KDF: &str = "pbkdf2-hmac-sha256";
pub const CIPHER: &str = "chacha20poly1305";

/// A sealed secret, as it is written to disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub kdf: String,
    pub iterations: u32,
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

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| format!("no randomness: {e}"))?;
    Ok(b)
}

/// Seal `plain` under `pass`.
pub fn seal(pass: &str, plain: &[u8]) -> Result<Sealed, String> {
    let salt: [u8; 16] = random()?;
    let nonce: [u8; 12] = random()?;
    let mut k = pbkdf2_sha256(pass.as_bytes(), &salt, ITERATIONS);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
    k.fill(0);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| "cannot seal".to_string())?;
    Ok(Sealed {
        kdf: KDF.into(),
        iterations: ITERATIONS,
        salt: hex::encode(salt),
        cipher: CIPHER.into(),
        nonce: hex::encode(nonce),
        ct: hex::encode(ct),
    })
}

/// Open `s` with `pass`: `None` for a wrong passphrase (or a damaged file).
pub fn open(pass: &str, s: &Sealed) -> Option<Vec<u8>> {
    if s.kdf != KDF || s.cipher != CIPHER || s.iterations == 0 {
        return None;
    }
    let salt = hex::decode(&s.salt).ok()?;
    let nonce = hex::decode(&s.nonce).ok()?;
    let ct = hex::decode(&s.ct).ok()?;
    if nonce.len() != 12 {
        return None;
    }
    let mut k = pbkdf2_sha256(pass.as_bytes(), &salt, s.iterations);
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
