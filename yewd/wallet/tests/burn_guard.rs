// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `sendrawtransaction`'s H7 guard (`allowyedburn`; ycash6 `src/yellowback/wallet.cpp`
//! `YedBurnedByRawTransaction`, review 3 MEDIUM-2): a raw transaction is refused when it spends YED
//! of this wallet and reassigns less of it. YED of this wallet is a token the node's index lists,
//! and also an output of this wallet whose transaction the index has not judged (in the mempool,
//! or mined above the index's height) and to which that transaction's own payload may give YED:
//! a TRANSFER's assignment, counted at the payload's figure, or a claim cancel's CAN-1 refund,
//! whose amount is unknown before its block is judged, so it refuses outright. Where the wallet
//! cannot tell (the index unreadable, or a transaction it cannot read) it refuses too.

mod common;

use common::*;
use yew_core::payload::{self, Assignment, Payload};

const COIN: i64 = 100_000_000;
const WALLET_ERROR: i64 = -4;

fn addr_script(a: &str) -> Vec<u8> {
    yewd_wallet::rpc::parse_taddr_script(Network::Regtest, a).unwrap()
}

fn txid_of(raw: &[u8]) -> ([u8; 32], String) {
    let id = Transaction::parse(raw).unwrap().1;
    (id, rev_hex(&id))
}

fn payload_out(p: &Payload) -> TxOut {
    TxOut {
        value: 0,
        script_pubkey: payload::payload_script(&payload::encode(p).unwrap()),
    }
}

/// A claim cancel paying `to` the CAN-1 refund at vout 1, the re-created vault at vout 0, the
/// CANCEL_COSIGN payload last (yed_buildcancel's shape).
fn cancel_refund(to: &[u8]) -> Vec<u8> {
    let mut t = Transaction::new_v4();
    let mut i = TxIn::new(OutPoint {
        txid: [9; 32],
        n: 0,
    });
    i.script_sig = vec![0x51];
    t.vin.push(i);
    t.vout.push(TxOut {
        value: 6 * COIN,
        script_pubkey: yew_core::script::p2sh_of(&[0x51]),
    });
    t.vout.push(TxOut {
        value: COIN / 2,
        script_pubkey: to.to_vec(),
    });
    t.vout.push(payload_out(&Payload::CancelCosign));
    t.serialize().unwrap()
}

/// A TRANSFER assigning 2,500 cents to `to` (vout 0) and 700 to a foreign script (vout 1).
fn transfer(to: &[u8]) -> Vec<u8> {
    let mut t = Transaction::new_v4();
    let mut i = TxIn::new(OutPoint {
        txid: [8; 32],
        n: 1,
    });
    i.script_sig = vec![0x51];
    t.vin.push(i);
    t.vout.push(TxOut {
        value: 10_000,
        script_pubkey: to.to_vec(),
    });
    t.vout.push(TxOut {
        value: 10_000,
        script_pubkey: yew_core::script::p2pkh_script(&[0x55; 20]),
    });
    t.vout.push(payload_out(&Payload::Transfer {
        assignments: vec![
            Assignment {
                vout: 0,
                cents: 2500,
            },
            Assignment {
                vout: 1,
                cents: 700,
            },
        ],
    }));
    t.serialize().unwrap()
}

/// A raw spend of `inputs` (plus the wallet's plain coin), paying a foreign script, with `payload`.
fn spend(inputs: &[OutPoint], payload: Option<Payload>) -> Value {
    let mut t = Transaction::new_v4();
    for o in inputs {
        t.vin.push(TxIn::new(*o));
    }
    t.vout.push(TxOut {
        value: COIN / 10,
        script_pubkey: yew_core::script::p2pkh_script(&[0x66; 20]),
    });
    if let Some(p) = payload {
        t.vout.push(payload_out(&p));
    }
    json!(hex::encode(t.serialize().unwrap()))
}

/// A wallet with a plain coin (block 2), its address's script, and the coin; the index healthy
/// at the tip (`yed_getinfo`), listing no token.
async fn fixture(name: &str) -> (MockNode, Wallet, Vec<u8>, OutPoint) {
    let node = MockNode::default();
    genesis(&node);
    let d = dir(name);
    let mut w = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    w.sync(&node).await.unwrap();
    let ecc = w
        .call(&node, "getnewaddress", &[])
        .await
        .unwrap()
        .text()
        .trim_matches('"')
        .to_string();
    let script = addr_script(&ecc);
    let pay = payment(
        OutPoint {
            txid: [7; 32],
            n: 0,
        },
        script.clone(),
        3 * COIN / 10,
    );
    let plain = OutPoint {
        txid: txid_of(&pay).0,
        n: 0,
    };
    node.mine(vec![coinbase(1, vec![0x51], 0)], 1);
    node.mine(vec![coinbase(2, vec![0x51], 0), pay], 2);
    w.sync(&node).await.unwrap();
    index_at(&node, 2);
    (node, w, script, plain)
}

fn index_at(node: &MockNode, h: i64) {
    node.0.lock().unwrap().yed_info =
        Some(json!({"healthy": true, "unhealthyReason": "", "height": h}));
}

fn unjudged_text(list: &str) -> String {
    format!("yed-burn-refused: this transaction spends output(s) of this wallet whose transaction the Yellowback index has not judged yet and whose payload may give them YED ({list}); whatever YED they carry would be destroyed. Pass allowyedburn = true to send it anyway.")
}

async fn refusal(w: &Wallet, node: &MockNode, raw: Value) -> Option<(i64, String)> {
    w.yed_burn_guard(node, &[raw])
        .await
        .err()
        .map(|e| (e.code, e.message))
}

/// The claim cancel's refund in the mempool (the case the ycash6 script
/// wallet_yed_output_guard.py reaches before the cancel's block): refused, amount unknown; still
/// refused while the index lags its block; once judged, refused as a token if the index lists
/// one there, sent if it lists none; not live, no guard.
#[tokio::test]
async fn an_unconfirmed_claim_cancel_refund_is_refused() {
    let (node, mut w, script, plain) = fixture("burn-refund").await;
    let raw = cancel_refund(&script);
    let (id, cancel) = txid_of(&raw);
    let refund = OutPoint { txid: id, n: 1 };
    node.to_mempool(raw.clone());
    w.sync(&node).await.unwrap();
    let r = refusal(&w, &node, spend(&[refund, plain], None)).await;
    assert_eq!(
        r,
        Some((WALLET_ERROR, unjudged_text(&format!("{cancel}:1"))))
    );
    // a payload on the spend changes nothing: the refund's cents are unknown
    let with = Payload::Transfer {
        assignments: vec![Assignment {
            vout: 0,
            cents: 1_000_000,
        }],
    };
    assert!(refusal(&w, &node, spend(&[refund], Some(with)))
        .await
        .is_some());
    // the plain coin alone is not refused
    assert_eq!(refusal(&w, &node, spend(&[plain], None)).await, None);

    // mined at 3, the index at 2: not judged yet
    node.mine(vec![coinbase(3, vec![0x51], 0), raw], 3);
    w.sync(&node).await.unwrap();
    assert_eq!(
        refusal(&w, &node, spend(&[refund], None)).await,
        Some((WALLET_ERROR, unjudged_text(&format!("{cancel}:1"))))
    );
    // judged, the index lists the refund token: the token's refusal
    index_at(&node, 3);
    node.0.lock().unwrap().tokens = vec![json!({"txid": cancel, "vout": 1, "cents": 4321})];
    let (code, msg) = refusal(&w, &node, spend(&[refund], None)).await.unwrap();
    assert_eq!(code, WALLET_ERROR);
    assert_eq!(msg, format!("yed-burn-refused: this transaction spends 4321 cents of this wallet's YED ({cancel}:1) and its payload reassigns 0 of them, so 4321 cents of YED would be destroyed. Pass allowyedburn = true to send it anyway."));
    // judged, no token there: plain YEC
    node.0.lock().unwrap().tokens.clear();
    assert_eq!(refusal(&w, &node, spend(&[refund], None)).await, None);
    // the index unreadable (yed_listtokens fails): every input is read by its payload again
    node.0.lock().unwrap().tokens_error = Some((-1, "boom".into()));
    assert!(refusal(&w, &node, spend(&[refund], None)).await.is_some());
    node.0.lock().unwrap().tokens_error = None;
    // the index unhealthy: the same
    node.0.lock().unwrap().yed_info =
        Some(json!({"healthy": false, "unhealthyReason": "x", "height": 3}));
    assert!(refusal(&w, &node, spend(&[refund], None)).await.is_some());
    // Yellowback not live (-32601): no index, no guard (the raw transaction is the explicit path)
    node.0.lock().unwrap().yed_info = None;
    assert_eq!(refusal(&w, &node, spend(&[refund], None)).await, None);
}

/// A TRANSFER's assignment to this wallet in the mempool: counted at the payload's figure; a spend
/// that reassigns all of it passes, one that reassigns less is refused; the assignment to a
/// foreign script is not this wallet's.
#[tokio::test]
async fn an_unconfirmed_transfer_assignment_is_refused() {
    let (node, mut w, script, plain) = fixture("burn-transfer").await;
    let raw = transfer(&script);
    let (id, t) = txid_of(&raw);
    node.to_mempool(raw);
    w.sync(&node).await.unwrap();
    let mine = OutPoint { txid: id, n: 0 };
    assert_eq!(
        refusal(&w, &node, spend(&[mine, plain], None)).await,
        Some((WALLET_ERROR, format!("yed-burn-refused: this transaction spends 2500 cents of this wallet's YED ({t}:0 (not judged yet)) and its payload reassigns 0 of them, so 2500 cents of YED would be destroyed. Pass allowyedburn = true to send it anyway.")))
    );
    let part = Payload::Transfer {
        assignments: vec![Assignment {
            vout: 0,
            cents: 2000,
        }],
    };
    let r = refusal(&w, &node, spend(&[mine], Some(part)))
        .await
        .unwrap();
    assert!(
        r.1.contains("reassigns 2000 of them, so 500 cents"),
        "{}",
        r.1
    );
    let all = Payload::Transfer {
        assignments: vec![Assignment {
            vout: 0,
            cents: 2500,
        }],
    };
    assert_eq!(refusal(&w, &node, spend(&[mine], Some(all))).await, None);
    let foreign = OutPoint { txid: id, n: 1 };
    assert_eq!(refusal(&w, &node, spend(&[foreign], None)).await, None);
}

/// A transaction the wallet has not synced yet (the node has it, the wallet's view does not):
/// read from the node; one the node cannot show (mined above the index, no transaction index)
/// refuses (fail closed).
#[tokio::test]
async fn an_output_the_wallet_has_not_seen_is_read_from_the_node() {
    let (node, w, script, _) = fixture("burn-unsynced").await;
    let raw = cancel_refund(&script);
    let (id, cancel) = txid_of(&raw);
    let refund = OutPoint { txid: id, n: 1 };
    node.to_mempool(raw.clone());
    assert_eq!(
        refusal(&w, &node, spend(&[refund], None)).await,
        Some((WALLET_ERROR, unjudged_text(&format!("{cancel}:1"))))
    );
    node.mine(vec![coinbase(3, vec![0x51], 0), raw], 3);
    assert_eq!(
        refusal(&w, &node, spend(&[refund], None)).await,
        Some((WALLET_ERROR, unjudged_text(&format!("{cancel}:1"))))
    );
    // judged (index at the block): the index's word, no token there
    index_at(&node, 3);
    assert_eq!(refusal(&w, &node, spend(&[refund], None)).await, None);
}
