// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Imported post-quantum key seeds are sealed in an encrypted wallet (no plaintext on disk), and a
//! plain file left by an earlier signer in an encrypted wallet is sealed at the next unlock.

use yewd_signer::pqimported::PqImported;

const SEED: [u8; 48] = [0x3c; 48];

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("yewd-pqimp-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn no_plain(dir: &std::path::Path) {
    let b = std::fs::read(dir.join("pqimported.json")).unwrap();
    let t = String::from_utf8_lossy(&b).to_lowercase();
    assert!(
        !t.contains(&hex::encode(SEED)),
        "pqimported.json holds the seed in hex"
    );
    assert!(
        !b.windows(48).any(|w| w == SEED),
        "pqimported.json holds the seed bytes"
    );
}

#[test]
fn encrypted_wallet_keeps_no_plain_pq_seed() {
    let dir = tmp("enc");
    let mut s = PqImported::load(&dir).unwrap();
    s.add(yew_core::pq::SCHEME_FN_DSA_512, &SEED).unwrap();
    let pk = s.pubs[0].clone();
    s.encrypt("pw").unwrap();
    no_plain(&dir);
    // an import while unlocked stays sealed
    s.add(yew_core::pq::SCHEME_SLH_DSA_SHA2_128S, &SEED)
        .unwrap();
    no_plain(&dir);
    s.lock();
    assert!(s.keys.is_empty());
    assert!(
        s.add(yew_core::pq::SCHEME_FN_DSA_512, &[0x11; 48]).is_err(),
        "locked: no import"
    );
    // a restart: public keys known while locked, seeds after the unlock
    let mut s = PqImported::load(&dir).unwrap();
    assert_eq!(s.pubs.len(), 2);
    assert_eq!(s.pubs[0], pk);
    assert!(s.keys.is_empty());
    assert!(!s.unlock("wrong", true).unwrap());
    assert!(s.unlock("pw", true).unwrap());
    assert_eq!(s.keys.len(), 2);
    assert_eq!(s.keys[0].seed, hex::encode(SEED));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plain_file_in_encrypted_wallet_is_sealed_at_unlock() {
    let dir = tmp("migrate");
    std::fs::write(
        dir.join("pqimported.json"),
        format!("{{\"format\":\"yewd-signer-pqimported-1\",\"keys\":[{{\"scheme\":2,\"seed\":\"{}\"}}]}}", hex::encode(SEED)),
    )
    .unwrap();
    let mut s = PqImported::load(&dir).unwrap();
    assert_eq!(s.pubs.len(), 1, "public keys rebuilt from the plain file");
    assert!(s.unlock("pw", true).unwrap());
    no_plain(&dir);
    let mut s = PqImported::load(&dir).unwrap();
    assert!(s.unlock("pw", true).unwrap());
    assert_eq!(s.keys[0].seed, hex::encode(SEED));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Round-2 review S2: an `encryptwallet` that failed after this store was sealed, then a restart
/// (sealed, locked) and a retry: the retry must never seal an empty key list over the keys.
#[test]
fn encrypt_over_a_sealed_locked_store_keeps_the_keys() {
    let dir = tmp("reseal");
    let mut s = PqImported::load(&dir).unwrap();
    s.add(yew_core::pq::SCHEME_FN_DSA_512, &SEED).unwrap();
    s.encrypt("pw").unwrap();
    drop(s);
    let mut s = PqImported::load(&dir).unwrap();
    assert!(s.locked());
    assert!(
        s.encrypt("other").is_err(),
        "a sealed store under another passphrase is refused"
    );
    s.encrypt("pw").unwrap(); // the retry with the same passphrase
    drop(s);
    let mut s = PqImported::load(&dir).unwrap();
    assert!(s.unlock("pw", true).unwrap());
    assert_eq!(s.keys.len(), 1, "the imported keys survive the retry");
    assert_eq!(s.keys[0].seed, hex::encode(SEED));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Leak hardening: a damaged file's error quotes none of its content.
#[test]
fn load_errors_quote_no_input() {
    let dir = tmp("leak");
    let secret = hex::encode(SEED);
    std::fs::write(
        dir.join("pqimported.json"),
        format!("{{\"format\":\"yewd-signer-pqimported-1\",\"keys\":[{{\"scheme\":\"{secret}\",\"seed\":5}}]}}"),
    )
    .unwrap();
    let e = PqImported::load(&dir)
        .err()
        .expect("a damaged file is refused");
    assert!(!e.contains(&secret[..16]), "the error quotes the file: {e}");
    let _ = std::fs::remove_dir_all(&dir);
}
