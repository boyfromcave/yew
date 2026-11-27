// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Round-2 review S2: sealing the imported transparent keys over a store that is already sealed
//! and locked (a retried `encryptwallet`) never replaces the keys with an empty list.

use yewd_signer::imported::Imported;

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("yewd-imp-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn encrypt_over_a_sealed_locked_store_keeps_the_keys() {
    let dir = tmp("reseal");
    let key = secp256k1::SecretKey::from_secret_bytes([7u8; 32]).unwrap();
    let mut s = Imported::load(&dir).unwrap();
    s.add(key).unwrap();
    s.encrypt("pw").unwrap();
    drop(s);
    let mut s = Imported::load(&dir).unwrap();
    assert!(s.get(0).is_none(), "locked after a restart");
    assert!(
        s.encrypt("other").is_err(),
        "a sealed store under another passphrase is refused"
    );
    s.encrypt("pw").unwrap();
    drop(s);
    let mut s = Imported::load(&dir).unwrap();
    assert!(s.unlock("pw").unwrap());
    assert_eq!(s.get(0), Some(&key), "the imported key survives the retry");
    let _ = std::fs::remove_dir_all(&dir);
}
