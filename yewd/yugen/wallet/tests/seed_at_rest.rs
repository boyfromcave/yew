// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The seed never reaches the wallet state on disk (decision record docs/yugen-seed-at-rest.md),
//! the dummy rule survives a restore (spec §5.6), and the N-A2 seed rule matches ycashd.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use yewd_yugen::engine::Engine;
use yewd_yugen::node::Rpc;
use yugen_ref::wallet::Spend;
use zeroize::Zeroizing;

const SEED: [u8; 32] = [0x5a; 32];

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("yewd-yugen-sar-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn seed() -> Option<Zeroizing<Vec<u8>>> {
    Some(Zeroizing::new(SEED.to_vec()))
}

/// Every file under `dir`: no seed hex (either case), no raw seed bytes; wallet.json is 0600.
fn assert_no_seed(dir: &Path, seed: &[u8]) {
    let hx = hex::encode(seed);
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let b = std::fs::read(&p).unwrap();
        let t = String::from_utf8_lossy(&b).to_lowercase();
        assert!(!t.contains(&hx), "{} holds the seed hex", p.display());
        assert!(!b.windows(seed.len()).any(|w| w == seed), "{} holds the seed bytes", p.display());
        if p.file_name().unwrap() == "wallet.json" {
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}

/// A node answering `gettransferstatus`: "mined" for nullifiers in the set, else "unknown".
fn mock_node(mined: Arc<Mutex<HashSet<String>>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = s.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                let t = String::from_utf8_lossy(&buf);
                if let Some((h, b)) = t.split_once("\r\n\r\n") {
                    let len: usize = h.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    if b.len() >= len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let t = String::from_utf8_lossy(&buf).to_string();
            let req: Value = serde_json::from_str(t.split_once("\r\n\r\n").unwrap().1).unwrap();
            let nf = req["params"][0].as_str().unwrap_or("").to_string();
            let state = if mined.lock().unwrap().contains(&nf) { "mined" } else { "unknown" };
            let body = json!({"result": {"state": state}, "error": null, "id": "yugen"}).to_string();
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
        }
    });
    addr
}

fn dummy_nf(e: &Engine, ha: u32, c: u32) -> String {
    let k = &e.acct.wallet.keys;
    hex::encode(yugen_ref::note::nullifier_dummy(&yugen_ref::note::dummy_preimage(&k.rsk, &k.nk, ha, c)))
}

#[test]
fn create_writes_no_seed_and_mode_0600() {
    let dir = tmp("create");
    let mut e = Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, seed()).unwrap();
    e.save().unwrap();
    let _ = e.static_address();
    assert_no_seed(&dir, &SEED);
    drop(e);
    // reopening needs the seed, and only that seed
    assert!(Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, None).is_err());
    let other = Some(Zeroizing::new(vec![0x11u8; 32]));
    assert!(Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, other).err().unwrap().contains("not this Yugen account"));
    assert!(Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, seed()).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_file_with_seed_is_migrated() {
    let dir = tmp("legacy");
    std::fs::create_dir_all(&dir).unwrap();
    let legacy = json!({"seed": hex::encode(SEED), "network": 2, "scanned": null, "leaves": [], "sizes": {},
        "requests": [[3, 1]], "next_change": 5, "otag_counters": {}, "dummy_counter": 7, "notes": [], "deposit_utxos": []});
    std::fs::write(dir.join("wallet.json"), serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
    std::fs::set_permissions(dir.join("wallet.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
    // another seed: refused, the file untouched
    let other = Some(Zeroizing::new(vec![0x11u8; 32]));
    assert!(Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, other).is_err());
    assert!(String::from_utf8(std::fs::read(dir.join("wallet.json")).unwrap()).unwrap().contains(&hex::encode(SEED)));
    // no seed: refused (the caller migrates the seed first)
    assert!(Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, None).is_err());
    let e = Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, seed()).unwrap();
    assert_eq!(e.st.requests, vec![(3, 1)]);
    assert_eq!(e.st.next_change, 5);
    assert_no_seed(&dir, &SEED);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restored_wallet_skips_dummy_nullifiers_on_chain() {
    let mined = Arc::new(Mutex::new(HashSet::new()));
    let addr = mock_node(mined.clone());
    let ha = 320;
    // the original wallet's two dummies at anchor 320 are on chain
    let dir = tmp("dummy");
    let mut e = Engine::open(&dir, Rpc::new(&addr, "", ""), 2, seed()).unwrap();
    for c in 0..2 {
        mined.lock().unwrap().insert(dummy_nf(&e, ha, c));
    }
    drop(e);
    // a restore from the seed alone (fresh state, twice): never a mined dummy nullifier
    for round in 0..2 {
        let _ = std::fs::remove_dir_all(&dir);
        e = Engine::open(&dir, Rpc::new(&addr, "", ""), 2, seed()).unwrap();
        for _ in 0..2 {
            let Spend::Dummy { c } = e.dummy(ha).unwrap() else { unreachable!() };
            let nf = dummy_nf(&e, ha, c);
            assert!(mined.lock().unwrap().insert(nf), "round {round}: dummy counter {c} repeats a nullifier");
        }
        e.save().unwrap();
        assert_no_seed(&dir, &SEED);
        drop(e);
    }
    // the counter also advances within one wallet: two dummies of one transfer differ
    let _ = std::fs::remove_dir_all(&dir);
    let mut e = Engine::open(&dir, Rpc::new(&addr, "", ""), 2, seed()).unwrap();
    let (Spend::Dummy { c: a }, Spend::Dummy { c: b }) = (e.dummy(ha + 16).unwrap(), e.dummy(ha + 16).unwrap()) else { unreachable!() };
    assert_eq!((a, b), (0, 1), "smallest unused counters at a fresh anchor (spec §5.6)");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Decision N-A2 vector, shared with ycashd (qa/rpc-tests/yugen_wallet_encrypted.py): the BIP 39
/// test phrase "abandon x11 about" (empty passphrase) gives this Yugen account seed.
#[test]
fn n_a2_seed_rule_vector() {
    let bip39 = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
    assert_eq!(hex::encode(&*yewd_yugen::yugen_seed_from_bip39(&bip39)), "3a3287aac7b77e6a5e1a1fd4931a267e6ee3f1b874f60513a5ba4fe0eafd538c");
}

#[test]
fn remote_backend_gets_no_dummy_probe() {
    // a non-loopback node address that would fail any connection: the dummy rule must not query it
    let dir = tmp("remote");
    let mut e = Engine::open(&dir, Rpc::new("192.0.2.1:9", "", ""), 2, seed()).unwrap();
    let Spend::Dummy { c } = e.dummy(320).unwrap() else { unreachable!() };
    assert!(c >= 1 << 31, "a remote backend's first dummy counter starts in the random range: {c}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remote_backend_counter_follows_its_record() {
    let dir = tmp("remote2");
    let mut e = Engine::open(&dir, Rpc::new("192.0.2.1:9", "", ""), 2, seed()).unwrap();
    let Spend::Dummy { c: a } = e.dummy(336).unwrap() else { unreachable!() };
    let Spend::Dummy { c: b } = e.dummy(336).unwrap() else { unreachable!() };
    assert_eq!(b, a + 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scrub_never_follows_a_symlink() {
    let dir = tmp("symlink");
    std::fs::create_dir_all(&dir).unwrap();
    let outside = dir.with_extension("outside");
    std::fs::write(&outside, b"not the wallet's to erase").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("wallet.json")).unwrap();
    yewd_yugen::store::write_private(&dir, "wallet.json", b"{}", true).unwrap();
    assert_eq!(std::fs::read(&outside).unwrap(), b"not the wallet's to erase");
    assert_eq!(std::fs::read(dir.join("wallet.json")).unwrap(), b"{}");
    let _ = std::fs::remove_file(&outside);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scrub_zeroes_the_old_inode_after_the_new_file_is_in_place() {
    let dir = tmp("inode");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("wallet.json"), b"SECRET-SECRET").unwrap();
    // the old inode is observed through a descriptor held across the replace (a hard link would
    // give it a second link, which the scrub now refuses to zero: see the next test)
    let mut held = std::fs::File::open(dir.join("wallet.json")).unwrap();
    yewd_yugen::store::write_private(&dir, "wallet.json", b"{\"new\":1}", true).unwrap();
    assert_eq!(std::fs::read(dir.join("wallet.json")).unwrap(), b"{\"new\":1}");
    let mut old = Vec::new();
    std::io::Read::read_to_end(&mut held, &mut old).unwrap();
    assert_eq!(old, vec![0u8; 13]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Round-2 review nit: a file with a second link is not zeroed (the other link is not ours to
/// erase); the new content still replaces the wallet's name.
#[test]
fn scrub_leaves_a_hard_linked_file_alone() {
    let dir = tmp("nlink");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("wallet.json"), b"OTHER-CONTENT").unwrap();
    std::fs::hard_link(dir.join("wallet.json"), dir.join("other-link")).unwrap();
    yewd_yugen::store::write_private(&dir, "wallet.json", b"{\"new\":1}", true).unwrap();
    assert_eq!(std::fs::read(dir.join("wallet.json")).unwrap(), b"{\"new\":1}");
    assert_eq!(std::fs::read(dir.join("other-link")).unwrap(), b"OTHER-CONTENT");
    let _ = std::fs::remove_dir_all(&dir);
}

fn pipe() -> (i32, i32) {
    let mut p = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
    (p[0], p[1])
}

#[test]
fn seed_fd_reads_to_the_newline_not_to_eof() {
    // the writer keeps its end open: reading to EOF would block forever
    let (r, w) = pipe();
    let line = format!("{}\nTRAILING", hex::encode(SEED));
    assert_eq!(unsafe { libc::write(w, line.as_ptr() as *const _, line.len()) }, line.len() as isize);
    let got = yewd_yugen::store::read_seed_fd(r).unwrap();
    assert_eq!(got.as_slice(), &SEED);
    unsafe { libc::close(w) };
    // no newline before EOF: refused
    let (r, w) = pipe();
    let h = hex::encode(SEED);
    unsafe { libc::write(w, h.as_ptr() as *const _, h.len()) };
    unsafe { libc::close(w) };
    assert!(yewd_yugen::store::read_seed_fd(r).is_err());
    // too long: refused without reading past 128 characters
    let (r, w) = pipe();
    let h = "ab".repeat(70) + "\n";
    unsafe { libc::write(w, h.as_ptr() as *const _, h.len()) };
    unsafe { libc::close(w) };
    assert!(yewd_yugen::store::read_seed_fd(r).is_err());
}

/// Leak hardening: a malformed legacy seed in the state file is refused with a fixed message that
/// quotes none of the file (a hex decoder's error names the offending character and position).
#[test]
fn malformed_legacy_seed_error_quotes_no_input() {
    let dir = tmp("legacybad");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = format!("{}Q0{}", "7e".repeat(20), "7e".repeat(11));
    drop(Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, seed()).unwrap());
    let mut v: Value = serde_json::from_slice(&std::fs::read(dir.join("wallet.json")).unwrap()).unwrap();
    v["seed"] = json!(bad);
    std::fs::write(dir.join("wallet.json"), serde_json::to_vec(&v).unwrap()).unwrap();
    let e = Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, seed()).err().expect("refused");
    assert!(!e.contains('Q') && !e.contains("position") && !e.contains("index"), "{e}");
    assert!(e.contains("malformed"), "{e}");
}
