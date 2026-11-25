// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Static address, note package and memo (spec 0.5.2 §10, §12.1), the memo refusal for a payment
//! request (§9.2) and the withdrawal shape (§7.1, §7.9 rule 4), against yugen-spec vectors where
//! they exist (`vectors/package.json`, `vectors/address.json`).

use serde_json::Value;
use yewd_yugen::account::Account;
use yewd_yugen::build::BuildExt;
use yewd_yugen::engine::Engine;
use yewd_yugen::node::Rpc;
use yugen_ref::address::FullAddress;
use yugen_ref::keys::AddrId;
use yugen_ref::package::{self, Plain};
use yugen_ref::params::*;
use yugen_ref::registry::Registry;
use yugen_ref::transfer::{Transfer, FLAG_LEAFFEE, FLAG_PKG1, FLAG_PKG1_MEMO, FLAG_PKG2, FLAG_PKG2_MEMO, FLAG_VB};
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

/// §10.2/§10.3 against `vectors/package.json`: seal reproduces the package byte for byte, open
/// returns the plaintext; sizes 1,672 / 2,184.
#[test]
fn package_vectors() {
    let mut n = 0;
    for v in load("package").iter().filter(|v| v.get("package").is_some() && v.get("rsk").is_some()) {
        let cm: [u8; 48] = hx(&v["cm"]).try_into().unwrap();
        let rsk: [u8; 32] = hx(&v["rsk"]).try_into().unwrap();
        let (j, br, net) = (v["j"].as_u64().unwrap() as u8, v["branch_id"].as_u64().unwrap() as u32, v["network"].as_u64().unwrap() as u8);
        let plain = Plain::decode(&hx(&v["plaintext"])).unwrap();
        let pkg = package::seal(&rsk, &hx(&v["ek"]), &cm, j, br, net, &plain).unwrap();
        assert_eq!(hex::encode(&pkg), v["package"].as_str().unwrap());
        assert_eq!(pkg.len(), if plain.memo.is_empty() { PKG_SHORT_LEN } else { PKG_LONG_LEN });
        let open = package::open(&hx(&v["dk"]), &cm, j, br, net, &pkg).unwrap();
        assert_eq!(open.encode(), plain.encode());
        n += 1;
    }
    assert!(n > 0, "no package vectors");
    assert_eq!((PKG_SHORT_LEN, PKG_LONG_LEN), (1672, 2184));
}

/// §12.1 full address against `vectors/address.json`: decode, re-encode, validity.
#[test]
fn full_address_vectors() {
    for v in load("address") {
        let b = hx(&v["full_address"]);
        let a = FullAddress::from_bytes(&b).unwrap();
        assert!(a.valid());
        assert_eq!(a.to_bytes(), b);
    }
}

fn pay_static(memo: Vec<u8>, pay2: bool) -> (Account, Transfer) {
    let mut payer = Account::from_seed(&[7u8; 32], 2).unwrap();
    let payee = Account::from_seed(&[9u8; 32], 2).unwrap();
    let d = AddrId::internal(0);
    let note = yugen_ref::note::Note { asset: 0, v: 5_000_000, auth: payer.wallet.auth(d), nkc: payer.wallet.address_keys(d).nkc_d, rho: [3; 48], rcm: [4; 32] };
    let mut tree = Tree::new();
    tree.append(&[1; 48]);
    let pos = tree.append(&note.cm());
    let fee = BASE_FEE + LEAF_PROOF_FEE;
    let addr = payee.static_address(0);
    let spends = [Spend::Note { d, note, pos, path: Box::new(tree.path(pos)) }, Spend::Dummy { c: 0 }];
    let o1 = Output::Static { addr: addr.clone(), v: 1_000_000, memo: memo.clone() };
    let outputs = if pay2 { [Output::Change { n: 1, v: 5_000_000 - 1_000_000 - fee }, o1] } else { [o1, Output::Change { n: 1, v: 5_000_000 - 1_000_000 - fee }] };
    let bp = BuildParams {
        branch_id: BRANCH_ID, fee_class: 0, anchor_height: 208, anchor_root: tree.root(), anchor_block_hash: [5; 32],
        value_balance: 0, vout: vec![], otag_counter: [0, 1], auth_mode: 0, registry: Registry::default(),
    };
    let b = payer.wallet.build_flags(&mut payer.signer, &spends, &outputs, &bp, FLAG_LEAFFEE);
    yugen_ref::statement::check_statement(&b.public, &b.witness).unwrap();
    (payee, b.transfer)
}

/// A static-address payment carries a package (flag PKG1/PKG2, with _MEMO for a memo), decodes
/// from the wire, and the payee recovers the note and the memo text.
#[test]
fn static_payment_with_and_without_memo() {
    let mut memo = b"spend matrix memo".to_vec();
    memo.resize(MEMO_LEN, 0);
    for (m, pay2) in [(vec![], false), (memo.clone(), false), (vec![], true), (memo.clone(), true)] {
        let (payee, t) = pay_static(m.clone(), pay2);
        let t = Transfer::decode(&t.encode()).unwrap();
        let j = if pay2 { 2 } else { 1 };
        let pk = t.pkg[j as usize - 1].as_ref().unwrap();
        assert_eq!(pk.len(), 2 + if m.is_empty() { PKG_SHORT_LEN } else { PKG_LONG_LEN });
        let (f, fm) = if pay2 { (FLAG_PKG2, FLAG_PKG2_MEMO) } else { (FLAG_PKG1, FLAG_PKG1_MEMO) };
        let bits = t.flags();
        assert!(bits & f != 0 && ((bits & fm != 0) == !m.is_empty()));
        let (note, got) = payee.wallet.recover_static(&t, j, 0, BRANCH_ID).expect("payee recovers");
        assert_eq!(note.v, 1_000_000);
        assert_eq!(got, m);
    }
}

/// A bare §9.1 request string is refused before any node call (ruling 13); a memo to a request is
/// still never dropped: with a Yugen address the memo sends the payment to its static part (P-3).
#[test]
fn memo_to_request_refused() {
    let dir = std::env::temp_dir().join(format!("yewd-yugen-memo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut e = Engine::open(&dir, Rpc::new("127.0.0.1:1", "", ""), 2, Some(zeroize::Zeroizing::new(vec![9u8; 32]))).unwrap();
    let req = Account::from_seed(&[7u8; 32], 2).unwrap().request(0, 0).to_string();
    let r = e.send(&req, 1_000_000, Some("hello"));
    let msg = r.unwrap_err();
    assert!(msg.contains("ruling 13"), "{msg}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Withdrawal shape: note + dummy, positive value_balance (§7.1: value leaving the pool), FLAG_VB,
/// vout bound by the transfer hash; the statement holds with vb_out = amount.
#[test]
fn withdrawal_shape() {
    let mut payer = Account::from_seed(&[7u8; 32], 2).unwrap();
    let d = AddrId::internal(0);
    let note = yugen_ref::note::Note { asset: 0, v: 5_000_000, auth: payer.wallet.auth(d), nkc: payer.wallet.address_keys(d).nkc_d, rho: [3; 48], rcm: [4; 32] };
    let mut tree = Tree::new();
    let pos = tree.append(&note.cm());
    let fee = BASE_FEE + LEAF_PROOF_FEE;
    let vout = yewd_yugen::tx::vout_bytes(&[yewd_yugen::tx::TxOut { value: 1_000_000, script: vec![0x76, 0xa9, 0x14, 0, 0, 0] }]);
    let bp = BuildParams {
        branch_id: BRANCH_ID, fee_class: 0, anchor_height: 208, anchor_root: tree.root(), anchor_block_hash: [5; 32],
        value_balance: 1_000_000, vout, otag_counter: [0, 1], auth_mode: 0, registry: Registry::default(),
    };
    let spends = [Spend::Note { d, note, pos, path: Box::new(tree.path(pos)) }, Spend::Dummy { c: 0 }];
    let outputs = [Output::Change { n: 1, v: 5_000_000 - 1_000_000 - fee }, Output::Change { n: 2, v: 0 }];
    let b = payer.wallet.build_flags(&mut payer.signer, &spends, &outputs, &bp, FLAG_LEAFFEE);
    yugen_ref::statement::check_statement(&b.public, &b.witness).unwrap();
    assert_eq!(b.transfer.vb_split(), (0, 1_000_000));
    assert!(b.transfer.flags() & FLAG_VB != 0);
}
