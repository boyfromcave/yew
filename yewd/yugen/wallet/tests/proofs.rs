//! W-3: both mode-0 wallet proofs of a built leaf transfer, verified by each proof system's own
//! verifier; a flipped byte and another public input are refused.
mod common;
use serde_json::json;
use yewd_yugen::prove::{a, b};
use yugen_ref::vectors::{public_json, witness_json};

#[test]
fn both_wallet_proofs_verify() {
    let (_, _, _, built) = common::leaf_transfer();
    let (p, w) = (public_json(&built.public), witness_json(&built.witness));
    if let Ok(f) = std::env::var("YUGEN_STATEMENT_OUT") {
        std::fs::write(f, json!({"public": p, "witness": w}).to_string()).unwrap();
    }
    let mut other = p.clone();
    other["fee"] = json!((built.public.fee + 1).to_string());
    let sa = a::setup();
    let pa = a::prove(&sa, &p, &w).unwrap();
    a::verify(&sa, &p, &pa).unwrap();
    // The bundle leaf check: `verify_leaf_e2` under leaf row 8.
    let ap = a::public(&p).unwrap();
    let apf = verifier_e2::Proof::from_bytes(&pa).unwrap();
    yugen_proof_a::wallet::v04::verify_leaf_e2(yugen_proof_a::params::by_id(8).unwrap(), &sa.key, &sa.circuit, 0, &ap, &apf).unwrap();
    assert!(a::verify(&sa, &other, &pa).is_err());
    let mut fa = pa.clone();
    let i = fa.len() / 2;
    fa[i] ^= 1;
    assert!(a::verify(&sa, &p, &fa).is_err());
    println!("proof A: {} bytes", pa.len());
    drop(sa);
    let sb = b::setup();
    let pb = b::prove(&sb, &p, &w).unwrap();
    b::verify(&sb, &p, &pb).unwrap();
    assert!(pb.len() <= b::LEAF_PROOF_MAX_B);
    if let Ok(f) = std::env::var("YUGEN_PROOF_B_OUT") {
        std::fs::write(f, &pb).unwrap();
    }
    assert!(b::verify(&sb, &other, &pb).is_err());
    let mut fb = pb.clone();
    let i = fb.len() / 2;
    fb[i] ^= 1;
    assert!(b::verify(&sb, &p, &fb).is_err());
    println!("proof B: {} bytes", pb.len());
    // The node's verifier on the same transfer (ycash6 contrib/yugen-leafverify, `verify`), when
    // YUGEN_LEAFVERIFY names its binary.
    if let Ok(bin) = std::env::var("YUGEN_LEAFVERIFY") {
        let c = &built.ctx;
        let req = json!({
            "transfer": hex::encode(built.transfer.encode()), "branch_id": c.branch_id, "network": c.network,
            "anchor_height": c.anchor_height, "anchor_root": hex::encode(c.anchor_root),
            "anchor_block_hash": hex::encode(c.anchor_block_hash), "vout": hex::encode(&c.vout),
            "auth_mode": 0, "reg_root": p["reg_root"], "proof_a": hex::encode(&pa), "proof_b": hex::encode(&pb),
        });
        let f = std::env::temp_dir().join(format!("yugen-leafverify-req-{}.json", std::process::id()));
        std::fs::write(&f, req.to_string()).unwrap();
        let out = std::process::Command::new(&bin).arg("verify").arg(&f).output().unwrap();
        let _ = std::fs::remove_file(&f);
        let text = String::from_utf8_lossy(&out.stdout);
        println!("yugen-leafverify: {}", text.trim());
        assert!(out.status.success() && text.starts_with("ACCEPT"), "yugen-leafverify: {text}");
        let mut big = req.clone();
        big["proof_b"] = json!(hex::encode(vec![0u8; b::LEAF_PROOF_MAX_B + 1]));
        std::fs::write(&f, big.to_string()).unwrap();
        let out = std::process::Command::new(&bin).arg("verify").arg(&f).output().unwrap();
        let _ = std::fs::remove_file(&f);
        assert!(String::from_utf8_lossy(&out.stdout).contains("LEAF_PROOF_MAX_B"));
    }
}

/// Y-W3b: System A's leaf row is the bundle leaf row 8, the masked `CAT1_TREE_LEAF_SALTED`.
#[test]
fn system_a_row_is_bundle_leaf_row_8() {
    let row8 = yugen_proof_a::params::by_id(8).unwrap();
    assert!(std::ptr::eq(row8, &verifier_e2::params::CAT1_TREE_LEAF_SALTED));
    assert_ne!(verifier_e2::zk::flags(row8), 0, "row 8 is masked");
    assert_eq!(yugen_proof_a::circuit::Params::wallet04_masked(), yugen_proof_a::circuit::Params { masking: true, ..yugen_proof_a::circuit::Params::wallet04() });
}

/// Y-W3b: System B's statement identifier is the bundle leaf key:
/// `StatementId::new(WALLET_MODE0, cs, 3, true)` with `wrapper_derives_public = true`.
#[test]
fn system_b_id_is_bundle_leaf_key() {
    use yugen_proof_b2::prove::{StatementId, WALLET_MODE0};
    let sb = b::setup();
    let mut id = StatementId::new(WALLET_MODE0, sb.st.circuit.constraint_system(), 3, true);
    id.wrapper_derives_public = true;
    assert_eq!(sb.leaf.id.bytes(), id.bytes());
    assert_eq!(sb.leaf.id.circuit, "wallet/mode0");
    println!("row: {:?}", sb.leaf.id.row);
}
