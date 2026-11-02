// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The ninth pinned vector file, `pq_wallet_vectors.json` (quantum spec A-12, `DerivePQSeed`),
//! replayed through the signer's own derivation path: the seed a phrase gives, the 48-byte PQ
//! seeds, and the SLH-DSA public key and key hash the public bundle hands the façade. N/A for
//! kogany (a wallet-less node); this is its consumer (plan §3b, "What yew-core already gives").
//!
//! The file is read by path, never copied: `$YEWD_PQ_WALLET_VECTORS`, else kogany's
//! `testdata/yellowback/` beside yew (`$WS/kogany`, on `vaults/kogany-compat`), else yew's own copy
//! `core/tests/vectors/` (byte-identical, checked by `scripts/check-node-vectors.sh`). Whichever is
//! read must hash to the `vector pq_wallet_vectors.json` line of `yewd/PIN`.

use std::path::{Path, PathBuf};

use yew_core::keys;
use yew_core::params::Network;
use yew_core::pq::{PqKey, PqSeedRoot};
use yewd_proto::PublicRequest;
use yewd_signer::Keystore;

fn pinned_sha(file: &str) -> String {
    let pin =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../PIN")).unwrap();
    pin.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 3 && f[0] == "vector" && f[1] == file).then(|| f[2].to_string())
        })
        .next()
        .unwrap_or_else(|| panic!("yewd/PIN has no vector line for {file}"))
}

fn candidates() -> Vec<PathBuf> {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut v = Vec::new();
    if let Some(p) = std::env::var_os("YEWD_PQ_WALLET_VECTORS") {
        v.push(PathBuf::from(p));
    }
    // $WS/yew/yewd/signer -> $WS/kogany; $WS/wt/<worktree>/yewd/signer -> $WS/kogany
    for up in ["../../../kogany", "../../../../kogany"] {
        v.push(
            here.join(up)
                .join("testdata/yellowback/pq_wallet_vectors.json"),
        );
    }
    v.push(here.join("../../core/tests/vectors/pq_wallet_vectors.json"));
    v
}

fn load() -> (PathBuf, serde_json::Value) {
    let want = pinned_sha("pq_wallet_vectors.json");
    for p in candidates() {
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        let got = keys::hex(&keys::sha256(&bytes));
        assert_eq!(
            got,
            want,
            "{} does not hash to yewd/PIN's value",
            p.display()
        );
        return (p, serde_json::from_slice(&bytes).unwrap());
    }
    panic!(
        "pq_wallet_vectors.json not found (tried {:?})",
        candidates()
    );
}

fn unhex(v: &serde_json::Value) -> Vec<u8> {
    keys::unhex(v.as_str().unwrap()).unwrap()
}

#[test]
fn pq_wallet_vectors_replay() {
    let (path, v) = load();
    eprintln!("replaying {}", path.display());
    assert_eq!(v["format"], "ycash-pq-wallet-vectors-1");
    assert_eq!(v["info"], "Ycash PQ key");
    // Both sections: the v4.5.0 line's raw HD seed, and the 6.20.0 line's (and YEW's) BIP39 seed.
    for section in ["hdSeed", "mnemonic"] {
        let s = &v[section];
        let ikm = unhex(&s["ikm"]);
        if section == "mnemonic" {
            // the phrase gives exactly this seed (empty passphrase), as the signer computes it
            let seed = keys::seed_from_mnemonic(s["phrase"].as_str().unwrap(), "").unwrap();
            assert_eq!(seed.to_vec(), ikm, "BIP39 seed of the phrase");
        }
        let root = PqSeedRoot::from_seed(&ikm);
        let derive = s["derive"].as_array().unwrap();
        assert!(!derive.is_empty());
        for d in derive {
            let scheme = d["scheme"].as_u64().unwrap() as u8;
            let index = d["index"].as_u64().unwrap() as u32;
            assert_eq!(
                root.derive(scheme, index).to_vec(),
                unhex(&d["seed"]),
                "{section} derive {scheme}/{index}"
            );
        }
        let slh = &s["slh"];
        let index = slh["index"].as_u64().unwrap() as u32;
        let key = PqKey::from_seed(1, &root.derive(1, index)).unwrap();
        assert_eq!(
            key.public_key().to_vec(),
            unhex(&slh["pk"]),
            "{section} slh pk"
        );
        assert_eq!(
            key.id().hash.to_vec(),
            unhex(&slh["keyhash"]),
            "{section} slh keyhash"
        );
    }
    // The signer's own path, phrase -> public bundle: the SLH-DSA key it hands the façade is the vector's.
    let m = &v["mnemonic"];
    let ks = Keystore::from_mnemonic(Network::Regtest, m["phrase"].as_str().unwrap());
    let index = m["slh"]["index"].as_u64().unwrap() as u32;
    let b = ks
        .public(&PublicRequest {
            pq: vec![(1, index, 1), (2, 0, 2)],
        })
        .unwrap();
    assert_eq!(b.pq[0].pk, m["slh"]["pk"].as_str().unwrap());
    assert_eq!(b.pq[0].index, index);
    // Falcon: the bundle's keys are the ones the vector's derived seeds generate.
    let root = PqSeedRoot::from_seed(&unhex(&m["ikm"]));
    for (k, row) in b.pq[1..].iter().enumerate() {
        assert_eq!(row.scheme, 2);
        let key = PqKey::from_seed(2, &root.derive(2, k as u32)).unwrap();
        assert_eq!(row.pk, keys::hex(key.public_key()));
        let vector_seed = m["derive"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["scheme"] == 2 && d["index"] == k as u64)
            .map(|d| unhex(&d["seed"]));
        if let Some(seed) = vector_seed {
            assert_eq!(root.derive(2, k as u32).to_vec(), seed);
        }
    }
}
