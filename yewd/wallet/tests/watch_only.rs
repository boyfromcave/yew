// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Watch-only scripts (`importaddress`, `importpubkey`; beta3 item 14) on the mock chain: the
//! three safety properties. A watched coin is never an input of a wallet transaction, a watched
//! script is never a change output, and a watched coin never makes a vault or YED path take it
//! for a coin of the wallet. Then the balances, the restart and the refusals.

mod common;

use std::sync::Mutex as StdMutex;

use common::*;
use yew_core::pq::PqKeyId;
use yewd_wallet::node::NodeFuture;

const COIN: i64 = 100_000_000;

fn addr_script(a: &str) -> Vec<u8> {
    yewd_wallet::rpc::parse_taddr_script(Network::Regtest, a).unwrap()
}

/// A node that records the addresses the wallet asks `yed_listtokens` about.
struct Recording {
    inner: MockNode,
    asked: StdMutex<Vec<String>>,
}

impl yewd_wallet::node::Node for Recording {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> NodeFuture<'a> {
        if method == "yed_listtokens" {
            if let Some(a) = params[0].as_array() {
                let mut v = self.asked.lock().unwrap();
                v.extend(a.iter().filter_map(|x| x.as_str().map(String::from)));
            }
        }
        self.inner.call(method, params)
    }
}

struct Fix {
    node: MockNode,
    w: Wallet,
    ecc: String,
    /// A watched ECC address (another wallet's key hash) with 50 YEC.
    watched: String,
    /// A watched post-quantum address with 20 YEC.
    watched_pq: String,
    name: String,
}

async fn fixture(name: &str) -> Fix {
    yewd_wallet::set_falcon_height(1);
    let node = MockNode::default();
    node.0.lock().unwrap().vault_height = Some(1);
    genesis(&node);
    let d = dir(name);
    let mut w = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    w.sync(&node).await.unwrap();
    let ecc = text(w.call(&node, "getnewaddress", &[]).await.unwrap());
    let watched = yew_core::keys::encode_p2pkh(Network::Regtest, &[7u8; 20]);
    let id = PqKeyId::of(1, &[5u8; 32]);
    let watched_pq = yew_core::keys::encode_pq_yec(Network::Regtest, &id).unwrap();
    let foreign = |n: u32| OutPoint { txid: [9; 32], n };
    node.mine(
        vec![
            coinbase(1, vec![0x51], 0),
            payment(foreign(0), addr_script(&ecc), 5 * COIN),
            payment(foreign(1), addr_script(&ecc), COIN),
            payment(foreign(2), addr_script(&watched), 50 * COIN),
            payment(foreign(3), addr_script(&watched_pq), 20 * COIN),
        ],
        0,
    );
    w.sync(&node).await.unwrap();
    for (a, label) in [(&watched, "w-ecc"), (&watched_pq, "w-pq")] {
        let r = w
            .call(&node, "importaddress", &[json!(a), json!(label)])
            .await
            .unwrap();
        assert_eq!(r.text(), "null");
    }
    Fix {
        node,
        w,
        ecc,
        watched,
        watched_pq,
        name: name.to_string(),
    }
}

fn text(v: yewd_wallet::json::J) -> String {
    v.text().trim_matches('"').to_string()
}

impl Fix {
    async fn j(&mut self, m: &str, p: &[Value]) -> Value {
        call_json(&mut self.w, &self.node, m, p).await
    }

    async fn err(&mut self, m: &str, p: &[Value]) -> (i64, String) {
        let e = self.w.call(&self.node, m, p).await.unwrap_err();
        (e.code, e.message)
    }

    fn watched_ops(&self) -> Vec<(String, u32)> {
        self.w
            .watch_coins
            .iter()
            .map(|c| (c.txid.clone(), c.vout))
            .collect()
    }

    fn sent(&self) -> Vec<Transaction> {
        self.node
            .0
            .lock()
            .unwrap()
            .sent
            .iter()
            .map(|h| Transaction::parse(&hex::decode(h).unwrap()).unwrap().0)
            .collect()
    }

    fn mine(&mut self) {
        let txs: Vec<Vec<u8>> = {
            let c = self.node.0.lock().unwrap();
            c.mempool.iter().map(|(_, t)| t.clone()).collect()
        };
        let h = self.node.0.lock().unwrap().blocks.len() as u32;
        let mut all = vec![coinbase(h, vec![0x51], 0)];
        all.extend(txs);
        self.node.mine(all, h as u8);
        self.node.0.lock().unwrap().mempool.clear();
    }
}

/// The rescan found the watched coins; the wallet's own coins are apart from them.
#[tokio::test]
async fn watched_coins_are_found_and_kept_apart() {
    let mut f = fixture("watch-found").await;
    assert_eq!(f.w.watch_coins.len(), 2);
    assert!(f
        .w
        .coins
        .iter()
        .all(|c| c.value < 50 * COIN && c.value != 20 * COIN));
    assert_eq!(zat(&f.j("getbalance", &[]).await), 6 * COIN);
    assert_eq!(
        zat(&f
            .j("getbalance", &[json!("*"), json!(1), json!(true)])
            .await),
        76 * COIN
    );
    assert_eq!(zat(&f.j("getwalletinfo", &[]).await["balance"]), 6 * COIN);
    let lu = f.j("listunspent", &[]).await;
    let watched: Vec<&Value> = lu
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["spendable"] == json!(false))
        .collect();
    assert_eq!(watched.len(), 2, "{lu}");
    let script = addr_script(&f.watched);
    assert!(f.w.is_watched(&script) && f.w.book.owns_script(&script).is_none());
}

/// Safety 1: a watched coin is never selected as an input, by any send or vault path; a send
/// the own coins cannot pay is refused, though the watched coins would cover it.
#[tokio::test]
async fn a_watched_coin_is_never_an_input() {
    let mut f = fixture("watch-input").await;
    let watched = f.watched_ops();
    let to = text(f.w.call(&f.node, "getnewaddress", &[]).await.unwrap());
    // more than the own 6 YEC, less than with the watched 70
    let (code, _) = f.err("sendtoaddress", &[json!(to), json!(10.0)]).await;
    assert_eq!(code, -6);
    // payable from the own coins: none of the watched in it
    f.w.call(&f.node, "sendtoaddress", &[json!(to), json!(5.5)])
        .await
        .unwrap();
    f.mine();
    f.w.sync(&f.node).await.unwrap();
    // the default vault funding
    let p = json!({"tag": "TEST", "setid": "11".repeat(32), "delay": 1, "ownerheight": 1000, "amount": 0.1});
    let _ = f.w.call(&f.node, "vault_lock", &[p]).await;
    // from a watched address: ycashd's -4
    for a in [f.watched.clone(), f.watched_pq.clone()] {
        let p = json!({"tag": "TEST", "setid": "11".repeat(32), "delay": 1, "ownerheight": 1000, "amount": 1.0, "from": a});
        assert_eq!(
            f.err("vault_lock", &[p]).await,
            (
                -4,
                "from: a watch-only address of this wallet (no spending key)".to_string()
            )
        );
    }
    // z_sendmany from a watched address: ycashd's -5 refusals
    let amounts = json!([{"address": to, "amount": 1.0}]);
    assert_eq!(
        f.err("z_sendmany", &[json!(f.watched), amounts.clone()])
            .await,
        (
            -5,
            "Invalid from address, no payment source found for address.".to_string()
        )
    );
    assert_eq!(
        f.err("z_sendmany", &[json!(f.watched_pq), amounts]).await.0,
        -5
    );
    let sent = f.sent();
    assert!(!sent.is_empty());
    for tx in &sent {
        for i in &tx.vin {
            let op = (yew_core::tx::txid_hex(&i.prevout.txid), i.prevout.n);
            assert!(!watched.contains(&op), "{op:?}: a watched coin spent");
        }
    }
}

/// Safety 2: a watched script is never a change output, and an own address cannot be watched.
#[tokio::test]
async fn a_watched_script_is_never_change() {
    let mut f = fixture("watch-change").await;
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[3u8; 20]);
    f.w.call(&f.node, "sendtoaddress", &[json!(to), json!(1.0)])
        .await
        .unwrap();
    let sent = f.sent();
    let tx = sent.last().unwrap();
    assert_eq!(tx.vout.len(), 2, "payment and change");
    for o in &tx.vout {
        assert!(
            !f.w.is_watched(&o.script_pubkey),
            "an output to a watched script"
        );
    }
    let change = tx
        .vout
        .iter()
        .find(|o| o.script_pubkey != addr_script(&to))
        .unwrap();
    assert!(f.w.book.owns_script(&change.script_pubkey).is_some());
    // an own address (and a key of the lookahead) is refused, as ycashd refuses it
    let own_key = (
        -4,
        "The wallet already contains the private key for this address or script".to_string(),
    );
    assert_eq!(f.err("importaddress", &[json!(f.ecc)]).await, own_key);
    let change_addr = yew_core::keys::encode_p2pkh(
        Network::Regtest,
        &yew_core::script::p2pkh_hash(&change.script_pubkey).unwrap(),
    );
    assert_eq!(f.err("importaddress", &[json!(change_addr)]).await, own_key);
}

/// Safety 3: a watched coin never makes a vault or YED path take it for the wallet's: the YED
/// index is never asked about a watched script, no holder key is a watched one, and the vault
/// funding never reaches it (above, `a_watched_coin_is_never_an_input`).
#[tokio::test]
async fn a_watched_coin_is_never_the_wallets_for_vault_or_yed() {
    let f = fixture("watch-yed").await;
    let watched_script = addr_script(&f.watched);
    let watched_pq_script = addr_script(&f.watched_pq);
    let rec = Recording {
        inner: f.node.clone(),
        asked: StdMutex::new(Vec::new()),
    };
    f.node.0.lock().unwrap().tokens =
        f.w.watch_coins
            .iter()
            .map(|c| json!({"txid": c.txid, "vout": c.vout, "cents": 100}))
            .collect();
    let mut w = f.w;
    let _ = w.call(&rec, "yed_getbalance", &[]).await;
    let _ = w
        .call(&rec, "listreceivedbyaddress", &[json!(0), json!(true)])
        .await;
    let asked = rec.asked.lock().unwrap().clone();
    assert!(!asked.is_empty(), "the wallet asked about its own scripts");
    for s in [&watched_script, &watched_pq_script] {
        let a = yewd_wallet::keys::yed_address(Network::Regtest, s).unwrap();
        assert!(
            !asked.contains(&a),
            "the index was asked about a watched script {a}"
        );
    }
    assert!(w.book.owns_script(&watched_script).is_none());
    assert!(w.book.owns_script(&watched_pq_script).is_none());
    assert!(w
        .coins
        .iter()
        .all(|c| c.script != watched_script && c.script != watched_pq_script));
    let _ = f.name;
}

/// The watched scripts survive a reopen of the wallet; a re-import relabels.
#[tokio::test]
async fn watched_scripts_survive_a_restart() {
    let f = fixture("watch-restart").await;
    let node = f.node.clone();
    let watched = f.watched.clone();
    let name = f.name.clone();
    drop(f);
    let d = std::env::temp_dir().join(format!("yewd-wallet-{}-{name}", std::process::id()));
    let mut w = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    w.sync(&node).await.unwrap();
    assert_eq!(w.watch_coins.len(), 2);
    let b = call_json(
        &mut w,
        &node,
        "getbalance",
        &[json!("*"), json!(1), json!(true)],
    )
    .await;
    assert_eq!(zat(&b), 76 * COIN);
    w.call(
        &node,
        "importaddress",
        &[json!(watched), json!("again"), json!(false)],
    )
    .await
    .unwrap();
    assert_eq!(w.st.book[&watched].label, "again");
}
