// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! An output that holds YED is never chosen as plain YEC, including the one no payload field names:
//! a claim cancel's CAN-1 refund (CANCEL_COSIGN; ycash6 `src/yellowback/state.cpp`
//! `ApplyIntentSpend`), at any value. Where the node's index has judged the transaction it lists the
//! token (`yed_listtokens`); where it has not (Yellowback not live, or the index below the block),
//! the transaction's own payload keeps the output out (`yew_core::payload::payload_assigns`). An
//! output the index judged plain stays spendable.

mod common;

use common::*;
use yew_core::payload::{self, Payload};

const COIN: i64 = 100_000_000;

fn addr_script(a: &str) -> Vec<u8> {
    yewd_wallet::rpc::parse_taddr_script(Network::Regtest, a).unwrap()
}

/// A claim cancel paying this wallet's address the CAN-1 refund at vout[1] (0.5 YEC, not
/// `TOKEN_VALUE`), the re-created vault at vout[0], the CANCEL_COSIGN payload last.
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
    let pl = payload::encode(&Payload::CancelCosign).unwrap();
    t.vout.push(TxOut {
        value: 0,
        script_pubkey: payload::payload_script(&pl),
    });
    t.serialize().unwrap()
}

/// A wallet with a 0.3 YEC plain coin (block 2) and the refund (block 3); `index` is what
/// `yed_getinfo` reports (`None`: Yellowback not live).
async fn fixture(name: &str, index: Option<i64>) -> (MockNode, Wallet) {
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
    node.mine(vec![coinbase(1, vec![0x51], 0)], 1);
    node.mine(
        vec![
            coinbase(2, vec![0x51], 0),
            payment(
                OutPoint {
                    txid: [7; 32],
                    n: 0,
                },
                addr_script(&ecc),
                3 * COIN / 10,
            ),
        ],
        2,
    );
    node.mine(
        vec![
            coinbase(3, vec![0x51], 0),
            cancel_refund(&addr_script(&ecc)),
        ],
        3,
    );
    node.mine(vec![coinbase(4, vec![0x51], 0)], 4);
    w.sync(&node).await.unwrap();
    {
        let mut c = node.0.lock().unwrap();
        match index {
            Some(h) => {
                c.yed_info = Some(json!({"healthy": true, "unhealthyReason": "", "height": h}))
            }
            None => {
                c.yed_info = None;
                c.tokens_error = Some((-32601, "Method not found".into()));
            }
        }
    }
    (node, w)
}

/// 0.4 YEC needs the refund: refused (nothing broadcast) where the index has not judged the
/// cancel; sent where the index judged it and lists no token there.
#[tokio::test]
async fn a_claim_cancel_refund_is_never_spent_as_plain_yec() {
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x44; 20]);
    for (name, index, spendable) in [
        ("can1-not-live", None, false),
        ("can1-index-behind", Some(2), false),
        ("can1-judged-plain", Some(4), true),
    ] {
        let (node, mut w) = fixture(name, index).await;
        for call in ["fundrawtransaction", "sendtoaddress"] {
            let p = if call == "sendtoaddress" {
                vec![json!(to), json!(0.4)]
            } else {
                let mut raw = Transaction::new_v4();
                raw.vout.push(TxOut {
                    value: 4 * COIN / 10,
                    script_pubkey: addr_script(&to),
                });
                vec![json!(hex::encode(raw.serialize().unwrap()))]
            };
            let r = w.call(&node, call, &p).await;
            assert_eq!(r.is_ok(), spendable, "{name} {call}: {:?}", r.err());
        }
        if !spendable {
            assert!(node.0.lock().unwrap().sent.is_empty(), "{name}");
        }
    }
}
