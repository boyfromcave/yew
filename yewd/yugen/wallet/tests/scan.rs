//! W-5 (fixture): scanning a block that holds a leaf transfer credits the payee's note, with a
//! membership path to the root after the block, and the payer's change.
mod common;
use serde_json::json;
use yewd_yugen::scan::{apply_block, BlockData};
use yewd_yugen::store::Store;

#[test]
fn block_fixture_credits_note() {
    let (payer, payee, tree, built) = common::leaf_transfer();
    // The chain before the block holds the tree's two leaves; the block (height 210, anchor 208
    // in slot 13) appends cm_1, cm_2.
    let note_cm = built.witness.spends[0].clone();
    let note_cm = yugen_ref::note::commitment(0, note_cm.v as u64, &payer.wallet.auth(yugen_ref::keys::AddrId::internal(0)), &payer.wallet.address_keys(yugen_ref::keys::AddrId::internal(0)).nkc_d, &note_cm.rho, &note_cm.rcm);
    let mut after = tree.clone();
    after.append(&built.transfer.cm[0]);
    after.append(&built.transfer.cm[1]);
    let block = json!({"height": 210, "tree_size_before": 2, "root_after": hex::encode(after.root()),
        "transfers": [{"txid": "aa", "transfer": hex::encode(built.transfer.encode())}]});
    let b = BlockData::from_json(&block).unwrap();
    let pre = |seed: u8| Store {
        seed_fp: yewd_yugen::store::seed_fingerprint(&[seed; 32]),
        network: 2,
        leaves: vec![hex::encode(common::PRE_CM), hex::encode(note_cm)],
        sizes: [(209u32, 2u64)].into(),
        requests: vec![(0, 0)],
        ..Default::default()
    };
    let mut st = pre(9);
    assert_eq!(apply_block(&mut st, &payee, &b, 200, yugen_ref::params::BRANCH_ID).unwrap(), 1);
    assert_eq!(st.notes[0].v, common::PAY_V);
    assert!(st.notes[0].applied);
    assert_eq!(st.notes[0].pos, 2);
    assert_eq!(st.balance(), common::PAY_V);
    // The payer finds its change by the outgoing tag (epoch counter 1 was used).
    let mut sp = pre(7);
    sp.requests.clear();
    sp.otag_counters.insert(0, 2);
    assert_eq!(apply_block(&mut sp, &payer, &b, 200, yugen_ref::params::BRANCH_ID).unwrap(), 1);
    assert!(sp.notes[0].applied && sp.notes[0].pos == 3);
    // A node root that disagrees is refused.
    let mut bad = block.clone();
    bad["root_after"] = json!(hex::encode([0u8; 48]));
    let mut st2 = pre(9);
    assert!(apply_block(&mut st2, &payee, &BlockData::from_json(&bad).unwrap(), 200, yugen_ref::params::BRANCH_ID).is_err());
}

/// Spec §13.2: the activation block puts the canary commitment at position 0.
#[test]
fn activation_block_appends_canary_leaf() {
    let (_, payee, _, _) = common::leaf_transfer();
    let mut st = Store { network: 2, ..Default::default() };
    let b = BlockData::from_json(&json!({"height": 112, "tree_size_before": 0, "transfers": []})).unwrap();
    apply_block(&mut st, &payee, &b, 112, yugen_ref::params::BRANCH_ID).unwrap();
    assert_eq!(st.leaves, vec![hex::encode(yugen_ref::tree::canary_nullifier().1)]);
    let mut t = yugen_ref::tree::Tree::new();
    t.append(&yugen_ref::tree::canary_nullifier().1);
    assert_eq!(st.tree_at(112).root(), t.root());
    let b2 = BlockData::from_json(&json!({"height": 113, "tree_size_before": 1, "transfers": []})).unwrap();
    apply_block(&mut st, &payee, &b2, 112, yugen_ref::params::BRANCH_ID).unwrap();
}
