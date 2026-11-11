// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The sync discipline without a node binary (plan §3b S1, hazards H1/H2): a scripted chain of
//! real v4 transactions in synthetic blocks, a reorg rewound to its fork point (a coinbase
//! dropped, a payment back to the mempool, then evicted), a reorg deeper than nothing the wallet
//! recognises, and the state file reloaded.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use yew_core::params::Network;
use yew_core::tx::{OutPoint, Transaction, TxIn, TxOut};
use yewd_proto::{PublicBundle, PublicRequest};
use yewd_wallet::node::{Node, NodeError, NodeFuture};
use yewd_wallet::{Signer, Wallet};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

struct TestSigner(yewd_signer::Keystore);

impl Signer for TestSigner {
    fn public(&self, req: &PublicRequest) -> Result<PublicBundle, String> {
        self.0.public(req).map_err(|e| e.to_string())
    }
}

fn signer() -> Box<dyn Signer> {
    Box::new(TestSigner(yewd_signer::Keystore::from_mnemonic(
        Network::Regtest,
        PHRASE,
    )))
}

#[derive(Default)]
struct Chain {
    /// (display hash, raw block)
    blocks: Vec<(String, Vec<u8>)>,
    mempool: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Default)]
struct MockNode(Arc<Mutex<Chain>>);

fn rev_hex(b: &[u8]) -> String {
    let mut v = b.to_vec();
    v.reverse();
    hex::encode(v)
}

impl MockNode {
    /// Append a block (on top of the current tip) holding `txs`; `salt` makes sibling blocks differ.
    fn mine(&self, txs: Vec<Vec<u8>>, salt: u8) -> String {
        let mut c = self.0.lock().unwrap();
        let prev = c
            .blocks
            .last()
            .map(|(h, _)| {
                hex::decode(h)
                    .unwrap()
                    .into_iter()
                    .rev()
                    .collect::<Vec<u8>>()
            })
            .unwrap_or(vec![0; 32]);
        let mut raw = Vec::new();
        raw.extend_from_slice(&4u32.to_le_bytes());
        raw.extend_from_slice(&prev);
        raw.extend_from_slice(&[0u8; 64]);
        raw.extend_from_slice(&(1_700_000_000u32 + c.blocks.len() as u32).to_le_bytes());
        raw.extend_from_slice(&0x200f0f0fu32.to_le_bytes());
        let mut nonce = [0u8; 32];
        nonce[0] = salt;
        nonce[1] = c.blocks.len() as u8;
        raw.extend_from_slice(&nonce);
        raw.push(0); // empty solution
        raw.push(txs.len() as u8);
        for t in &txs {
            raw.extend_from_slice(t);
        }
        let hash = rev_hex(&yew_core::keys::sha256d(&raw));
        c.blocks.push((hash.clone(), raw));
        let mined: Vec<String> = txs
            .iter()
            .map(|t| Transaction::parse(t).unwrap().1)
            .map(|id| rev_hex(&id))
            .collect();
        c.mempool.retain(|(id, _)| !mined.contains(id));
        hash
    }

    /// Drop the blocks above `height` (their non-coinbase transactions go back to the mempool).
    fn disconnect_to(&self, height: usize) {
        let mut c = self.0.lock().unwrap();
        while c.blocks.len() > height + 1 {
            let (_, raw) = c.blocks.pop().unwrap();
            let _ = raw;
        }
    }

    fn to_mempool(&self, tx: Vec<u8>) -> String {
        let id = rev_hex(&Transaction::parse(&tx).unwrap().1);
        self.0.lock().unwrap().mempool.push((id.clone(), tx));
        id
    }

    fn clear_mempool(&self) {
        self.0.lock().unwrap().mempool.clear();
    }
}

impl Node for MockNode {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> NodeFuture<'a> {
        Box::pin(async move {
            let c = self.0.lock().unwrap();
            let p = params.as_array().cloned().unwrap_or_default();
            let tip = c.blocks.len() - 1;
            Ok(match method {
                "getbestblockhash" => json!(c.blocks[tip].0),
                "getblockcount" => json!(tip),
                "getblockhash" => {
                    let h = p[0].as_u64().unwrap() as usize;
                    match c.blocks.get(h) {
                        Some((hash, _)) => json!(hash),
                        None => {
                            return Err(NodeError::Rpc {
                                code: -8,
                                message: "Block height out of range".into(),
                            })
                        }
                    }
                }
                "getblock" => {
                    let want = p[0].as_str().unwrap();
                    let (_, raw) =
                        c.blocks
                            .iter()
                            .find(|(h, _)| h == want)
                            .ok_or(NodeError::Rpc {
                                code: -5,
                                message: "Block not found".into(),
                            })?;
                    if p[1].as_u64() == Some(0) {
                        json!(hex::encode(raw))
                    } else {
                        json!({"trees": {"sapling": {"size": 0}}})
                    }
                }
                "getblockchaininfo" => json!({"upgrades": {}}),
                "getrawmempool" => json!(c
                    .mempool
                    .iter()
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>()),
                "getrawtransaction" => {
                    let want = p[0].as_str().unwrap();
                    match c.mempool.iter().find(|(id, _)| id == want) {
                        Some((_, raw)) => json!(hex::encode(raw)),
                        None => {
                            return Err(NodeError::Rpc {
                                code: -5,
                                message: "No such mempool transaction".into(),
                            })
                        }
                    }
                }
                m => {
                    return Err(NodeError::Rpc {
                        code: -32601,
                        message: format!("mock: {m}"),
                    })
                }
            })
        })
    }
}

fn coinbase(height: u32, script: Vec<u8>, value: i64) -> Vec<u8> {
    let mut t = Transaction::new_v4();
    let mut i = TxIn::new(OutPoint {
        txid: [0; 32],
        n: u32::MAX,
    });
    i.script_sig = vec![0x03, height as u8, (height >> 8) as u8, 0];
    t.vin.push(i);
    t.vout.push(TxOut {
        value,
        script_pubkey: script,
    });
    t.expiry_height = 0;
    t.serialize().unwrap()
}

fn payment(from: OutPoint, script: Vec<u8>, value: i64) -> Vec<u8> {
    let mut t = Transaction::new_v4();
    let mut i = TxIn::new(from);
    i.script_sig = vec![0x51]; // never validated by the wallet
    t.vin.push(i);
    t.vout.push(TxOut {
        value,
        script_pubkey: script,
    });
    t.serialize().unwrap()
}

fn genesis(node: &MockNode) {
    node.mine(vec![coinbase(0, vec![0x51], 0)], 0);
}

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("yewd-wallet-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test]
async fn sync_reorg_and_reload() {
    let node = MockNode::default();
    genesis(&node);
    let d = dir("sync");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    let mine = yew_core::script::p2pkh_script(&w.book.key(0, 0).unwrap().hash);
    let lookahead = yew_core::script::p2pkh_script(&w.book.key(0, 50).unwrap().hash);
    let foreign = vec![0x51];
    let mut cb_ids = Vec::new();
    for h in 1..=5 {
        let tx = coinbase(h, mine.clone(), 1_000_000_000);
        cb_ids.push(Transaction::parse(&tx).unwrap().1);
        node.mine(vec![tx], 0);
    }
    // a payment to a lookahead key in block 6 (from a foreign coin)
    let pay = payment(
        OutPoint {
            txid: [7; 32],
            n: 0,
        },
        lookahead.clone(),
        300_000_000,
    );
    let pay_id = rev_hex(&Transaction::parse(&pay).unwrap().1);
    node.mine(vec![coinbase(6, foreign.clone(), 1), pay.clone()], 0);
    assert!(w.sync(&node).await.unwrap());
    assert_eq!(w.tip_height(), 6);
    assert_eq!(w.coins.len(), 6);
    // the used lookahead key moved the issue counter past it, and the pool followed
    assert_eq!(w.st.issued.external, 51);
    assert!(w.book.key(0, 150).is_some());
    // nothing new: the barrier is a no-op
    assert!(!w.sync(&node).await.unwrap());

    // reorg at height 4: blocks 5 and 6 replaced by 5', 6', 7' (no coinbase of ours, the payment unmined)
    node.disconnect_to(4);
    node.to_mempool(pay.clone());
    for h in 5..=7 {
        node.mine(vec![coinbase(h, foreign.clone(), 1)], 1);
    }
    assert!(w.sync(&node).await.unwrap());
    assert_eq!(w.tip_height(), 7);
    let mut heights: Vec<Option<u32>> = w.coins.iter().map(|c| c.height).collect();
    heights.sort();
    // the coinbases of blocks 1-4 stay, block 5's is gone, the payment is back in the mempool
    assert_eq!(heights, vec![None, Some(1), Some(2), Some(3), Some(4)]);
    assert!(w.st.wtx[&pay_id].block.is_none());
    assert_eq!(
        w.st.tip.as_ref().unwrap().hash,
        node.0.lock().unwrap().blocks[7].0
    );

    // evicted from the mempool: dropped from the wallet
    node.clear_mempool();
    assert!(w.sync(&node).await.unwrap());
    assert!(!w.st.wtx.contains_key(&pay_id));
    assert_eq!(w.coins.len(), 4);

    // mined again in block 8: confirmed again
    node.mine(vec![coinbase(8, foreign.clone(), 1), pay.clone()], 0);
    w.sync(&node).await.unwrap();
    assert_eq!(w.st.wtx[&pay_id].block.as_ref().unwrap().height, 8);

    // the state file reloads to the same wallet
    let coins: Vec<_> = w
        .coins
        .iter()
        .map(|c| (c.txid.clone(), c.vout, c.value, c.height))
        .collect();
    drop(w);
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    assert_eq!(
        w.coins
            .iter()
            .map(|c| (c.txid.clone(), c.vout, c.value, c.height))
            .collect::<Vec<_>>(),
        coins
    );
    assert!(!w.sync(&node).await.unwrap());

    // a reorg below everything the window remembers: a full rescan from the birthday
    node.disconnect_to(0);
    for h in 1..=3 {
        node.mine(vec![coinbase(h, mine.clone(), 2_000_000_000)], 9);
    }
    w.sync(&node).await.unwrap();
    assert_eq!(w.tip_height(), 3);
    assert_eq!(
        w.coins.iter().map(|c| c.value).collect::<Vec<_>>(),
        vec![2_000_000_000; 3]
    );
    let _ = cb_ids;
}

#[tokio::test]
async fn read_rpcs_over_the_mock_chain() {
    let node = MockNode::default();
    genesis(&node);
    let d = dir("rpc");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    let mine = yew_core::script::p2pkh_script(&w.book.key(0, 0).unwrap().hash);
    for h in 1..=102 {
        node.mine(vec![coinbase(h, mine.clone(), 1_000_000_000)], 0);
    }
    w.sync(&node).await.unwrap();
    // two mature coinbases (depth 102 and 101), 100 immature
    let b = w.call(&node, "getbalance", &[]).await.unwrap().text();
    assert_eq!(b, "20.00000000");
    let info: Value =
        serde_json::from_str(&w.call(&node, "getwalletinfo", &[]).await.unwrap().text()).unwrap();
    assert_eq!(info["immature_balance"].to_string(), "1000.0");
    let rows: Value =
        serde_json::from_str(&w.call(&node, "listunspent", &[]).await.unwrap().text()).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert_eq!(rows[0]["generated"], true);
    let a = w.call(&node, "getnewaddress", &[]).await.unwrap().text();
    assert!(a.starts_with("\"sm"), "{a}");
    let e = w
        .call(&node, "getnewaddress", &[json!(""), json!("pq")])
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.message.as_str()),
        (
            -8,
            "post-quantum addresses need the vault upgrade active at the next block"
        )
    );
    // beta2 item 10 (ycash6 c33854654): the type may come first; the old "" + type shape stands;
    // the arguments are judged before the vault-upgrade check and before any key is issued.
    for args in [
        vec![json!("p2pkh")],
        vec![json!(""), Value::Null],
        vec![json!(""), json!("p2pkh")],
    ] {
        let a = w.call(&node, "getnewaddress", &args).await.unwrap().text();
        assert!(a.starts_with("\"sm"), "{args:?}: {a}");
    }
    for args in [
        vec![json!("pq")],
        vec![json!("pqslh")],
        vec![json!("pq"), Value::Null],
    ] {
        let e = w.call(&node, "getnewaddress", &args).await.unwrap_err();
        assert_eq!(e.code, -8, "{args:?}");
        assert!(
            e.message.contains("vault upgrade"),
            "{args:?}: {}",
            e.message
        );
    }
    let accounts = "Accounts are unsupported; the first argument is the address type, \"p2pkh\", \"pq\" or \"pqslh\" (lower case), or \"\" followed by the type";
    for args in [
        vec![json!("savings")],
        vec![json!("savings"), json!("pq")],
        vec![json!("PQ")],
        vec![json!("Pq")],
        vec![json!("PQSLH")],
        vec![json!("P2PKH")],
    ] {
        let e = w.call(&node, "getnewaddress", &args).await.unwrap_err();
        assert_eq!((e.code, e.message.as_str()), (-11, accounts), "{args:?}");
    }
    let twice = "the address type is given first, so there is no second argument (getnewaddress pq, or getnewaddress \"\" pq)";
    for args in [
        vec![json!("pq"), json!("pq")],
        vec![json!("p2pkh"), json!("")],
    ] {
        let e = w.call(&node, "getnewaddress", &args).await.unwrap_err();
        assert_eq!((e.code, e.message.as_str()), (-8, twice), "{args:?}");
    }
    for args in [
        vec![json!(""), json!("PQ")],
        vec![json!(""), json!("bogus")],
    ] {
        let e = w.call(&node, "getnewaddress", &args).await.unwrap_err();
        assert!(
            e.message.starts_with("type must be"),
            "{args:?}: {}",
            e.message
        );
    }
    let e = w
        .call(&node, "gettransaction", &[json!("00".repeat(32))])
        .await
        .unwrap_err();
    assert_eq!(e.code, -5);
    let txid = rows[0]["txid"].as_str().unwrap();
    let t: Value = serde_json::from_str(
        &w.call(&node, "gettransaction", &[json!(txid)])
            .await
            .unwrap()
            .text(),
    )
    .unwrap();
    assert_eq!(t["details"][0]["category"], "generate");
    assert_eq!(t["generated"], true);
    let owner: Value = serde_json::from_str(
        &w.call(&node, "vault_getnewowner", &[])
            .await
            .unwrap()
            .text(),
    )
    .unwrap();
    assert_eq!(
        owner["owner"].as_str().unwrap(),
        format!("01{}", owner["keyhash"].as_str().unwrap())
    );
    let z = w.call(&node, "z_getnewaddress", &[]).await.unwrap().text();
    assert!(z.starts_with("\"yregtestsapling1"));
    let zb = w
        .call(&node, "z_getbalance", &[serde_json::from_str(&z).unwrap()])
        .await
        .unwrap()
        .text();
    assert_eq!(zb, "0.00000000");
}

/// Beta2 item 15 (ycash6 e2a8bdace, ycash-dd 322be29c5): getwalletinfo's split by address type
/// and scheme (ECC = the figure minus its PQ part; both schemes always listed, SLH-DSA first),
/// z_getbalance of an own PQ address and the refusal of a foreign transparent one, and the
/// listreceivedbyaddress rows of PQ keys that received coins without an address-book entry.
#[tokio::test]
async fn balances_by_type_over_the_mock_chain() {
    let node = MockNode::default();
    genesis(&node);
    let d = dir("bytype");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    let ecc = yew_core::script::p2pkh_script(&w.book.key(0, 0).unwrap().hash);
    let slh = w.book.pq_key(1, 0).unwrap().id;
    let fn_ = w.book.pq_key(2, 0).unwrap().id;
    let script = |id| yew_core::pq::pqpkh_script(&id).unwrap();
    let foreign = |n: u32| OutPoint { txid: [9; 32], n };
    node.mine(
        vec![
            coinbase(1, vec![0x51], 1_000_000_000),
            payment(foreign(0), script(fn_), 300_000_000),
            payment(foreign(1), script(slh), 100_000_000),
            payment(foreign(2), ecc.clone(), 50_000_000),
        ],
        0,
    );
    node.to_mempool(payment(foreign(3), script(fn_), 20_000_000));
    w.sync(&node).await.unwrap();
    let info: Value =
        serde_json::from_str(&w.call(&node, "getwalletinfo", &[]).await.unwrap().text()).unwrap();
    let amt = |v: &Value| (v.as_f64().unwrap() * 1e8).round() as i64;
    assert_eq!(amt(&info["balance"]), 450_000_000);
    assert_eq!(amt(&info["balance_ecc"]), 50_000_000);
    assert_eq!(amt(&info["balance_pq"]), 400_000_000);
    assert_eq!(amt(&info["unconfirmed_balance"]), 20_000_000);
    assert_eq!(amt(&info["unconfirmed_balance_ecc"]), 0);
    assert_eq!(amt(&info["unconfirmed_balance_pq"]), 20_000_000);
    let by = info["pq_by_scheme"].as_array().unwrap();
    assert_eq!(by.len(), 2);
    assert_eq!(
        (by[0]["pqscheme"].as_i64(), by[0]["pqschemename"].as_str()),
        (Some(1), Some("SLH-DSA-SHA2-128s"))
    );
    assert_eq!(
        (by[1]["pqscheme"].as_i64(), by[1]["pqschemename"].as_str()),
        (Some(2), Some("FN-DSA-512"))
    );
    assert_eq!(
        (
            amt(&by[0]["balance_pq"]),
            amt(&by[0]["unconfirmed_balance_pq"])
        ),
        (100_000_000, 0)
    );
    assert_eq!(
        (
            amt(&by[1]["balance_pq"]),
            amt(&by[1]["unconfirmed_balance_pq"])
        ),
        (300_000_000, 20_000_000)
    );
    // z_getbalance of an own PQ address (finding L-3), by depth
    let fn_addr = yew_core::keys::encode_pq_yec(Network::Regtest, &fn_).unwrap();
    for (minconf, want) in [(1, "3.00000000"), (0, "3.20000000")] {
        let b = w
            .call(&node, "z_getbalance", &[json!(fn_addr), json!(minconf)])
            .await
            .unwrap()
            .text();
        assert_eq!(b, want, "minconf {minconf}");
    }
    // a transparent address the wallet does not hold, ECC or PQ, is refused
    let other_pq = yew_core::pq::PqKeyId {
        scheme: 2,
        hash: [0x77; 32],
    };
    for a in [
        yew_core::keys::encode_pq_yec(Network::Regtest, &other_pq).unwrap(),
        yew_core::keys::encode_p2pkh(Network::Regtest, &[0x77; 20]),
    ] {
        let e = w
            .call(&node, "z_getbalance", &[json!(a)])
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            (
                -5,
                "From address does not belong to this node, transparent or post-quantum key or watch-only script not found."
            )
        );
    }
    // listreceivedbyaddress: the PQ keys that received, with their scheme, though not in the book
    let rows: Value = serde_json::from_str(
        &w.call(&node, "listreceivedbyaddress", &[json!(0)])
            .await
            .unwrap()
            .text(),
    )
    .unwrap();
    let row = |a: &str| {
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["address"] == a)
            .cloned()
            .unwrap_or_else(|| panic!("{a} not listed: {rows}"))
    };
    let f = row(&fn_addr);
    assert_eq!(
        (f["pqscheme"].as_i64(), f["pqschemename"].as_str()),
        (Some(2), Some("FN-DSA-512"))
    );
    assert_eq!(amt(&f["amount"]), 320_000_000);
    assert!(f.get("yed_holder").is_none());
    let s = row(&yew_core::keys::encode_pq_yec(Network::Regtest, &slh).unwrap());
    assert_eq!(s["pqschemename"].as_str(), Some("SLH-DSA-SHA2-128s"));
    let e = row(&yew_core::keys::encode_p2pkh(
        Network::Regtest,
        &w.book.key(0, 0).unwrap().hash,
    ));
    assert!(e.get("pqscheme").is_none());
}
