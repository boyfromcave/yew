// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! W-1, W-2: keys, addresses and transfers against yugen-spec 0.5.1 (d25a89c) `vectors/`.

use serde_json::Value;
use yewd_yugen::account::Account;
use yewd_yugen::build::BuildExt;
use yugen_ref::address::FullAddress;
use yugen_ref::falcon::{FalconSigner, Signer};
use yugen_ref::keys::{self, AddrId};
use yugen_ref::registry::Registry;
use yugen_ref::request::{request_key, PaymentRequest};
use yugen_ref::tree::Tree;
use yugen_ref::wallet::{BuildParams, Output, Spend};

fn load(name: &str) -> Vec<Value> {
    let p = format!("{}/../deps/yugen-spec/vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["vectors"].as_array().unwrap().clone()
}
fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn keys_from_seed() {
    let mut n = 0;
    for v in load("keys").iter().filter(|v| v.get("kind").is_none()) {
        let seed = hx(&v["seed"]);
        let (net, account) = (v["network"].as_u64().unwrap() as u8, v["account"].as_u64().unwrap() as u32);
        let k = keys::derive_account(&seed, net, account).unwrap();
        for f in ["nk", "ovk_view", "rsk", "ivk_req", "falcon_seed", "sk_a"] {
            let got = match f {
                "nk" => k.nk,
                "ovk_view" => k.ovk_view,
                "rsk" => k.rsk,
                "ivk_req" => k.ivk_req,
                "falcon_seed" => k.falcon_seed,
                _ => k.sk_a,
            };
            assert_eq!(hex::encode(got), v[f].as_str().unwrap(), "{f}");
        }
        for a in v["addresses"].as_array().unwrap() {
            let d: [u8; 7] = hx(&a["d"]).try_into().unwrap();
            let id = AddrId { kind: d[0], a: u32::from_le_bytes(d[1..5].try_into().unwrap()), b: u16::from_le_bytes([d[5], d[6]]) };
            let ak = keys::derive_address(&k, id);
            assert_eq!(hex::encode(ak.nk_d), a["nk_d"].as_str().unwrap());
            assert_eq!(hex::encode(ak.nkc_d), a["nkc_d"].as_str().unwrap());
            assert_eq!(hex::encode(ak.salt_d), a["salt_d"].as_str().unwrap());
            assert_eq!(hex::encode(ak.rkh_d), a["rkh_d"].as_str().unwrap());
            let (_, ek) = keys::kem_keypair(&ak.kem_d, &ak.kem_z);
            assert_eq!(hex::encode(ek), a["ek_d"].as_str().unwrap());
        }
        if account == 0 {
            // The wallet's own account: the same derivation through `Account`.
            let acct = Account::from_seed(&seed, net).unwrap();
            assert_eq!(hex::encode(acct.wallet.keys.ivk_req), v["ivk_req"].as_str().unwrap());
        }
        n += 1;
    }
    assert_eq!(n, 10);
}

#[test]
fn falcon_key_and_auth() {
    let mut n = 0;
    for v in load("auth").iter().filter(|v| v["scheme"].as_str() == Some("1") || v["scheme"] == 1) {
        let fs: [u8; 32] = hx(&v["falcon_seed"]).try_into().unwrap();
        let pk = Signer::from_seed(&fs).public_key();
        assert_eq!(hex::encode(&pk), v["pk"].as_str().unwrap());
        let salt: [u8; 32] = hx(&v["salt_d"]).try_into().unwrap();
        let sigd = keys::sigd(&pk, &salt);
        assert_eq!(hex::encode(sigd), v["sig_d"].as_str().unwrap());
        let rkh: [u8; 32] = hx(&v["rkh_d"]).try_into().unwrap();
        assert_eq!(hex::encode(keys::auth(&rkh, &sigd)), v["auth_d"].as_str().unwrap());
        n += 1;
    }
    assert!(n > 0);
}

#[test]
fn address_strings() {
    for v in load("address") {
        let a = FullAddress::from_bytes(&hx(&v["full_address"])).expect("full address");
        assert_eq!(a.short_string(), v["string"].as_str().unwrap());
        assert_eq!(hex::encode(a.short()), v["short_address"].as_str().unwrap());
    }
}

#[test]
fn request_strings() {
    for v in load("request") {
        let r = PaymentRequest::from_bytes(&hx(&v["bytes"])).unwrap();
        assert_eq!(r.to_string(), v["string"].as_str().unwrap());
        assert_eq!(PaymentRequest::parse(v["string"].as_str().unwrap()).unwrap(), r);
        let ivk: [u8; 32] = hx(&v["ivk_req"]).try_into().unwrap();
        let k = request_key(&ivk, v["day"].as_u64().unwrap() as u32, v["c"].as_u64().unwrap() as u16);
        assert_eq!(hex::encode(k), v["k"].as_str().unwrap());
    }
}

#[test]
fn transfer_encoding_and_hash() {
    let mut n = 0;
    for v in load("transfer").iter().filter(|v| v["kind"] == "transfer") {
        let t = yugen_ref::transfer::Transfer::decode(&hx(&v["encoding"])).unwrap();
        assert_eq!(hex::encode(t.encode()), v["encoding"].as_str().unwrap());
        assert_eq!(t.fee().to_string(), v["fee"].as_str().map(String::from).unwrap_or_else(|| v["fee"].to_string()));
        n += 1;
    }
    assert!(n > 0);
}

/// W-2: with no auxiliary flag the builder is the reference's `Wallet::build`, byte for byte;
/// with `FLAG_LEAFFEE` the fee carries `LEAF_PROOF_FEE` and the statement holds.
#[test]
fn builder_equals_reference() {
    let payer = Account::from_seed(&[7u8; 32], 2).unwrap();
    let payee = Account::from_seed(&[9u8; 32], 2).unwrap();
    // A tree holding one note of the payer's change address 0 at position 3.
    let d = AddrId::internal(0);
    let auth = payer.wallet.auth(d);
    let nkc = payer.wallet.address_keys(d).nkc_d;
    let note = yugen_ref::note::Note { asset: 0, v: 5_000_000, auth, nkc, rho: [3; 48], rcm: [4; 32] };
    let mut tree = Tree::new();
    for i in 0..3u8 {
        tree.append(&[i; 48]);
    }
    let pos = tree.append(&note.cm());
    let spends = [Spend::Note { d, note: note.clone(), pos, path: Box::new(tree.path(pos)) }, Spend::Dummy { c: 0 }];
    let fee0 = yugen_ref::params::BASE_FEE;
    let outputs = |fee: u64| [Output::Request { req: payee.request(0, 0), v: 1_000_000 }, Output::Change { n: 1, v: 5_000_000 - 1_000_000 - fee }];
    let bp = BuildParams {
        branch_id: yugen_ref::params::BRANCH_ID,
        fee_class: 0,
        anchor_height: 208,
        anchor_root: tree.root(),
        anchor_block_hash: [5; 32],
        value_balance: 0,
        vout: vec![],
        otag_counter: [0, 1],
        auth_mode: 0,
        registry: Registry::default(),
    };
    let mut s1 = Signer::from_seed(&payer.wallet.keys.falcon_seed);
    let mut s2 = Signer::from_seed(&payer.wallet.keys.falcon_seed);
    let r = payer.wallet.build(&mut s1, &spends, &outputs(fee0), &bp);
    let m = payer.wallet.build_flags(&mut s2, &spends, &outputs(fee0), &bp, 0);
    assert_eq!(r.transfer, m.transfer);
    assert_eq!(r.transfer_hash, m.transfer_hash);
    assert_eq!(r.public, m.public);
    assert_eq!(r.witness, m.witness);
    yugen_ref::statement::check_statement(&m.public, &m.witness).unwrap();
    let leaf_fee = fee0 + yugen_ref::params::LEAF_PROOF_FEE;
    let mut s3 = Signer::from_seed(&payer.wallet.keys.falcon_seed);
    let l = payer.wallet.build_flags(&mut s3, &spends, &outputs(leaf_fee), &bp, yugen_ref::transfer::FLAG_LEAFFEE);
    assert_eq!(l.transfer.fee(), leaf_fee);
    yugen_ref::statement::check_statement(&l.public, &l.witness).unwrap();
}
