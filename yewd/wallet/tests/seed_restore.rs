// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The seed-only restore finds every coin of its seed (ycash6 beta2 P0: `wallet_seed_restore_ecc.py`,
//! `vault_pq_wallet_restore.py`; KG-YEWD-VAULT-PARITY rows 4 and 14): a transparent lookahead of
//! `-keypool` + 1 keys per chain (a coin after a gap of 100 unused addresses is found, one after
//! 101 is not), a post-quantum lookahead of 20 per scheme, and the re-pass that reads the scanned
//! blocks again while the lookahead grows (keys paid out of chain order, a coin found by a
//! re-pass and spent later, one transaction paying a far key before a near one). A restore stopped
//! part-way resumes where it was; a scan in which the lookahead does not grow reads each block once.

mod common;

use common::*;
use yewd_proto::PublicRequest;

/// The P2PKH script of external key `index` of the test seed (any index: CKDpub over the
/// signer's account xpub, as the wallet derives it).
fn ext(index: u32) -> Vec<u8> {
    let ks = yewd_signer::Keystore::from_mnemonic(Network::Regtest, PHRASE);
    let b = ks.public(&PublicRequest::default()).unwrap();
    let mut book = yewd_wallet::keys::KeyBook::new(&b.account).unwrap();
    book.extend(0, index + 1).unwrap();
    yew_core::script::p2pkh_script(&book.key(0, index).unwrap().hash)
}

/// The `TX_PQPKH` script of FN-DSA-512 key `index` of the test seed.
fn falcon(index: u32) -> Vec<u8> {
    let ks = yewd_signer::Keystore::from_mnemonic(Network::Regtest, PHRASE);
    let b = ks
        .public(&PublicRequest {
            pq: vec![(2, index, 1)],
        })
        .unwrap();
    let p = &b.pq[0];
    assert_eq!((p.scheme, p.index), (2, index));
    let id = yew_core::pq::PqKeyId::of(2, &hex::decode(&p.pk).unwrap());
    yew_core::pq::pqpkh_script(&id).unwrap()
}

fn foreign(n: u32) -> OutPoint {
    OutPoint { txid: [9; 32], n }
}

fn txid_of(tx: &[u8]) -> String {
    rev_hex(&Transaction::parse(tx).unwrap().1)
}

/// The wallet's unspent coins as (txid, vout, value), sorted.
fn unspent(w: &Wallet) -> Vec<(String, u32, i64)> {
    let mut v: Vec<_> = w
        .coins
        .iter()
        .filter(|c| !c.spent)
        .map(|c| (c.txid.clone(), c.vout, c.value))
        .collect();
    v.sort();
    v
}

/// Append a block holding `txs` (the mock's sibling salt is its height: one chain, no siblings).
fn mine(node: &MockNode, txs: Vec<Vec<u8>>) {
    let height = node.0.lock().unwrap().blocks.len() as u8;
    node.mine(txs, height);
}

fn reads(node: &MockNode) -> Vec<usize> {
    std::mem::take(&mut node.0.lock().unwrap().block_reads)
}

/// A restore finds coins paid after gaps of unused addresses beyond yewd's old 20 and up to 100;
/// a gap of 101 is the documented miss (ycashd's too), found once the addresses past it are issued
/// and the wallet rescans. A scan that does not grow the lookahead (every ordinary sync of a
/// wallet that issues its own addresses) reads each block once.
#[tokio::test]
async fn restore_finds_coins_past_gaps_up_to_the_keypool() {
    let node = MockNode::default();
    genesis(&node);
    // external keys 5, 60 (a gap of 54), 161 (a gap of 100), then 263 (a gap of 101)
    let p5 = payment(foreign(0), ext(5), 1_000);
    let p60 = payment(foreign(1), ext(60), 2_000);
    let p161 = payment(foreign(2), ext(161), 3_000);
    let p263 = payment(foreign(3), ext(263), 4_000);
    for (h, p) in [&p5, &p60, &p161, &p263].into_iter().enumerate() {
        mine(
            &node,
            vec![coinbase(h as u32 + 1, vec![0x51], 1), p.clone()],
        );
    }
    let d = dir("restore-gaps");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    w.restore_first_sapling().unwrap();
    w.sync(&node).await.unwrap();
    assert_eq!(
        unspent(&w),
        vec![
            (txid_of(&p5), 0, 1_000),
            (txid_of(&p60), 0, 2_000),
            (txid_of(&p161), 0, 3_000)
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
    assert_eq!(w.st.issued.external, 162);
    assert!(w.st.scan.is_none());
    // the lookahead grew in the main pass, so one re-pass reads the range again (and finds
    // nothing: no key was paid out of order), as ycashd's restore does
    assert_eq!(reads(&node), vec![1, 2, 3, 4, 1, 2, 3, 4]);
    let info = call_json(&mut w, &node, "getwalletinfo", &[]).await;
    assert_eq!(info["restore_in_progress"], json!(false));
    assert_eq!(info["lookahead_incomplete"], json!(false));

    // an ordinary block afterwards, and an ordinary sync with nothing new: no block read twice
    mine(&node, vec![coinbase(5, vec![0x51], 1)]);
    w.sync(&node).await.unwrap();
    assert!(!w.sync(&node).await.unwrap());
    assert_eq!(reads(&node), vec![5]);

    // the documented recovery: issue addresses past the gap, rescan
    while w.st.issued.external <= 263 - 101 {
        call_json(&mut w, &node, "getnewaddress", &[]).await;
    }
    w.rescan_all();
    w.sync(&node).await.unwrap();
    assert_eq!(unspent(&w).len(), 4);
    assert_eq!(w.st.issued.external, 264);
}

/// The chain of the out-of-order cases: key 150 paid before key 60 (found by the re-pass), key
/// 150's coin spent after that (the re-pass finds the coin and its spend), then one transaction
/// paying keys 300 and 210 in that order (210 is held once 150 is found; 300 once 210 is marked,
/// within the same transaction), then a block that pays nothing to the wallet.
struct OutOfOrder {
    p150: Vec<u8>,
    p60: Vec<u8>,
    spend150: Vec<u8>,
    pair: Vec<u8>,
}

fn out_of_order_chain(node: &MockNode) -> OutOfOrder {
    genesis(node);
    let p150 = payment(foreign(0), ext(150), 15_000);
    let p60 = payment(foreign(1), ext(60), 6_000);
    let spend150 = payment(
        OutPoint {
            txid: Transaction::parse(&p150).unwrap().1,
            n: 0,
        },
        vec![0x51],
        14_000,
    );
    let mut t = Transaction::parse(&payment(foreign(2), ext(300), 30_000))
        .unwrap()
        .0;
    t.vout.push(TxOut {
        value: 21_000,
        script_pubkey: ext(210),
    });
    let pair = t.serialize().unwrap();
    for (h, p) in [&p150, &p60, &spend150, &pair].into_iter().enumerate() {
        mine(node, vec![coinbase(h as u32 + 1, vec![0x51], 1), p.clone()]);
    }
    mine(node, vec![coinbase(5, vec![0x51], 1)]);
    OutOfOrder {
        p150,
        p60,
        spend150,
        pair,
    }
}

fn check_out_of_order(w: &Wallet, c: &OutOfOrder) {
    let mut want = vec![
        (txid_of(&c.p60), 0, 6_000),
        (txid_of(&c.pair), 0, 30_000),
        (txid_of(&c.pair), 1, 21_000),
    ];
    want.sort();
    assert_eq!(unspent(w), want);
    // the coin of key 150 is found, and spent
    assert!(w
        .coins
        .iter()
        .any(|x| x.txid == txid_of(&c.p150) && x.spent));
    assert!(w.st.wtx.contains_key(&txid_of(&c.spend150)));
    // the next address handed out is past every key the chain pays
    assert_eq!(w.st.issued.external, 301);
    assert!(w.st.scan.is_none());
    assert!(!w.st.restore_pending);
}

#[tokio::test]
async fn restore_finds_keys_paid_out_of_chain_order() {
    let node = MockNode::default();
    let c = out_of_order_chain(&node);
    let d = dir("restore-order");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    w.restore_first_sapling().unwrap();
    w.sync(&node).await.unwrap();
    check_out_of_order(&w, &c);
    // the main pass (60 found), a re-pass (150, its spend, 210 and 300), a last one finding nothing
    assert_eq!(
        reads(&node),
        vec![1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5]
    );
    // the state file reloads to the same wallet, and the next sync reads nothing
    drop(w);
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    check_out_of_order(&w, &c);
    assert!(!w.sync(&node).await.unwrap());
    assert_eq!(reads(&node), Vec::<usize>::new());
}

/// A post-quantum key paid out of chain order (KG-YEWD-VAULT-PARITY row 4): FN-DSA-512 key 30 in
/// an earlier block than key 10; the restore holds keys 0..20, finds 10, then the re-pass finds 30.
#[tokio::test]
async fn restore_finds_a_post_quantum_key_paid_out_of_order() {
    let node = MockNode::default();
    genesis(&node);
    let p30 = payment(foreign(0), falcon(30), 30_000);
    let p10 = payment(foreign(1), falcon(10), 10_000);
    mine(&node, vec![coinbase(1, vec![0x51], 1), p30.clone()]);
    mine(&node, vec![coinbase(2, vec![0x51], 1), p10.clone()]);
    let d = dir("restore-pq");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    assert!(w.book.pq_key(2, 30).is_none());
    w.restore_first_sapling().unwrap();
    w.sync(&node).await.unwrap();
    let mut want = vec![(txid_of(&p30), 0, 30_000), (txid_of(&p10), 0, 10_000)];
    want.sort();
    assert_eq!(unspent(&w), want);
    assert_eq!(w.st.pq_issued(2), 31);
    assert_eq!(reads(&node), vec![1, 2, 1, 2, 1, 2]);
    let info = call_json(&mut w, &node, "getwalletinfo", &[]).await;
    assert_eq!(info["pq_by_scheme"][1]["balance_pq"], json!(0.0004));
}

/// A restore stopped part-way (the backend lost, the daemon restarted) resumes where it was: in
/// its main pass, and in the middle of a re-pass; `restore_in_progress` holds until it is done.
#[tokio::test]
async fn an_interrupted_restore_resumes() {
    // stopped in the re-pass: the 8th read is block 3 of pass 2
    let node = MockNode::default();
    let c = out_of_order_chain(&node);
    let d = dir("restore-stop-repass");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    w.restore_first_sapling().unwrap();
    node.0.lock().unwrap().fail_read_at = Some(7);
    assert!(w.sync(&node).await.is_err());
    assert_eq!(reads(&node), vec![1, 2, 3, 4, 5, 1, 2]);
    let info = call_json(&mut w, &node, "getwalletinfo", &[]).await;
    assert_eq!(info["restore_in_progress"], json!(true));
    // a restart: the progress was written
    drop(w);
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    let m = w.st.scan.clone().unwrap();
    assert_eq!((m.from, m.pass, m.next), (1, 2, 3));
    assert!(w.st.restore_pending);
    w.sync(&node).await.unwrap();
    // the rest of pass 2, then pass 3
    assert_eq!(reads(&node), vec![3, 4, 5, 1, 2, 3, 4, 5]);
    check_out_of_order(&w, &c);
    let info = call_json(&mut w, &node, "getwalletinfo", &[]).await;
    assert_eq!(info["restore_in_progress"], json!(false));

    // stopped in the main pass, after key 60 grew the lookahead: the 4th read is block 4
    let node = MockNode::default();
    let c = out_of_order_chain(&node);
    let d = dir("restore-stop-main");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    w.restore_first_sapling().unwrap();
    node.0.lock().unwrap().fail_read_at = Some(3);
    assert!(w.sync(&node).await.is_err());
    drop(w);
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    assert_eq!(w.tip_height(), 3);
    let m = w.st.scan.clone().unwrap();
    assert_eq!((m.from, m.pass, m.grew), (1, 1, true));
    w.sync(&node).await.unwrap();
    assert_eq!(
        reads(&node),
        vec![1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5]
    );
    check_out_of_order(&w, &c);
}
