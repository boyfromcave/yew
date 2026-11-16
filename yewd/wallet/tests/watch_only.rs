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
            let asked: Vec<String> = params[0]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            self.asked.lock().unwrap().extend(asked.iter().cloned());
            // as the index answers: only the tokens at the addresses asked about
            let tokens: Vec<Value> = self
                .inner
                .0
                .lock()
                .unwrap()
                .tokens
                .iter()
                .filter(|t| asked.iter().any(|a| t["address"] == json!(a)))
                .cloned()
                .collect();
            return Box::pin(async move { Ok(json!(tokens)) });
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
    fixture_with(name, true).await
}

/// The fixture; without `own_funds` the wallet holds no coin of its own, only the watched ones.
async fn fixture_with(name: &str, own_funds: bool) -> Fix {
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
    let mut txs = vec![coinbase(1, vec![0x51], 0)];
    if own_funds {
        txs.push(payment(foreign(0), addr_script(&ecc), 5 * COIN));
        txs.push(payment(foreign(1), addr_script(&ecc), COIN));
    }
    txs.push(payment(foreign(2), addr_script(&watched), 50 * COIN));
    txs.push(payment(foreign(3), addr_script(&watched_pq), 20 * COIN));
    node.mine(txs, 0);
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
    // the default vault funding succeeds from the own coins (the 0.5 YEC left), not the watched
    let before = f.sent().len();
    let p = json!({"tag": "TEST", "setid": "11".repeat(32), "delay": 1, "ownerheight": 1000, "amount": 0.1});
    f.w.call(&f.node, "vault_lock", &[p])
        .await
        .expect("the default-funded vault_lock");
    let sent = f.sent();
    assert_eq!(sent.len(), before + 1, "the vault_lock was broadcast");
    for i in &sent.last().unwrap().vin {
        let op = (yew_core::tx::txid_hex(&i.prevout.txid), i.prevout.n);
        assert!(
            !watched.contains(&op),
            "{op:?}: the vault_lock spent a watched coin"
        );
    }
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
    // -sendchangeback sends the change to the largest input's script, largest first: were a
    // watched coin (50 YEC, the largest) selectable, the change would go to the watched script
    f.w.opts.send_change_back = true;
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[3u8; 20]);
    f.w.call(&f.node, "sendtoaddress", &[json!(to), json!(1.0)])
        .await
        .unwrap();
    let sent = f.sent();
    let tx = sent.last().unwrap();
    assert_eq!(tx.vout.len(), 2, "payment and change");
    let watched = f.watched_ops();
    for i in &tx.vin {
        let op = (yew_core::tx::txid_hex(&i.prevout.txid), i.prevout.n);
        assert!(!watched.contains(&op), "{op:?}: a watched coin spent");
    }
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
    assert_eq!(
        change.script_pubkey,
        addr_script(&f.ecc),
        "change back to the own input"
    );
    // and with a fresh change key (the default): the internal chain's newest key
    f.w.opts.send_change_back = false;
    f.w.call(&f.node, "sendtoaddress", &[json!(to), json!(1.0)])
        .await
        .unwrap();
    let sent = f.sent();
    let tx = sent.last().unwrap();
    let change = tx
        .vout
        .iter()
        .find(|o| o.script_pubkey != addr_script(&to))
        .unwrap();
    assert!(!f.w.is_watched(&change.script_pubkey));
    assert_eq!(
        f.w.book.owns_script(&change.script_pubkey),
        Some(yewd_wallet::keys::Owner::T(
            yewd_wallet::keys::INTERNAL,
            f.w.st.issued.internal - 1
        ))
    );
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
    // the index holds a token on each watched coin (100 cents) and one on an own coin (7 cents)
    f.node.0.lock().unwrap().yed_info = Some(
        json!({"healthy": true, "unhealthyReason": "", "height": 2, "startHeight": 0, "params": {}}),
    );
    let own = f.w.coins.first().expect("an own coin");
    let mut tokens: Vec<Value> =
        f.w.watch_coins
            .iter()
            .map(|c| {
                let a = yewd_wallet::keys::yed_address(Network::Regtest, &c.script).unwrap();
                json!({"txid": c.txid, "vout": c.vout, "cents": 100, "address": a})
            })
            .collect();
    let own_yed = yewd_wallet::keys::yed_address(Network::Regtest, &own.script).unwrap();
    tokens.push(json!({"txid": own.txid, "vout": own.vout, "cents": 7, "address": own_yed}));
    f.node.0.lock().unwrap().tokens = tokens;
    let mut w = f.w;
    let b: Value =
        serde_json::from_str(&w.call(&rec, "yed_getbalance", &[]).await.unwrap().text()).unwrap();
    assert_eq!(
        (b["confirmedCents"].as_i64(), b["spendableCents"].as_i64()),
        (Some(7), Some(7)),
        "the YED balance counts a watched coin's token: {b}"
    );
    w.call(&rec, "listreceivedbyaddress", &[json!(0), json!(true)])
        .await
        .unwrap();
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

/// A key the wallet derives later wins over the watch (ycashd's `IsMineInner`: spendable before
/// watch-only): the coin of an address imported beyond the lookahead moves from the watched coins
/// to the own ones when its key is derived, and `listunspent` lists it once, spendable.
#[tokio::test]
async fn a_derived_key_wins_over_the_watch() {
    let mut f = fixture("watch-key-wins").await;
    let index = f.w.st.issued.external + yewd_wallet::keys::WINDOW + 20;
    let mut book = f.w.book.clone();
    book.extend(yewd_wallet::keys::EXTERNAL, index + 1).unwrap();
    let hash = book.key(yewd_wallet::keys::EXTERNAL, index).unwrap().hash;
    let far = yew_core::keys::encode_p2pkh(Network::Regtest, &hash);
    // beyond the lookahead: not yet the wallet's, so it can be watched
    assert!(f.w.book.owns_script(&addr_script(&far)).is_none());
    f.w.call(
        &f.node,
        "importaddress",
        &[json!(far), json!("far"), json!(false)],
    )
    .await
    .unwrap();
    let h = f.node.0.lock().unwrap().blocks.len() as u32;
    f.node.mine(
        vec![
            coinbase(h, vec![0x51], 0),
            payment(
                OutPoint {
                    txid: [8; 32],
                    n: 0,
                },
                addr_script(&far),
                3 * COIN,
            ),
        ],
        h as u8,
    );
    f.w.sync(&f.node).await.unwrap();
    let far_script = addr_script(&far);
    assert!(f.w.watch_coins.iter().any(|c| c.script == far_script));
    assert!(f.w.coins.iter().all(|c| c.script != far_script));
    // derive keys until the address is the wallet's
    while f.w.book.owns_script(&far_script).is_none() {
        f.w.call(&f.node, "getnewaddress", &[]).await.unwrap();
    }
    assert!(f.w.coins.iter().any(|c| c.script == far_script));
    assert!(f.w.watch_coins.iter().all(|c| c.script != far_script));
    let lu = f.j("listunspent", &[]).await;
    let rows: Vec<&Value> = lu
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["address"] == json!(far))
        .collect();
    assert_eq!(rows.len(), 1, "{lu}");
    assert_eq!(rows[0]["spendable"], json!(true));
    assert_eq!(zat(&f.j("getbalance", &[]).await), 9 * COIN);
}

/// `z_mergetoaddress ["ANY_TADDR"]` with only watched transparent funds: ycashd's -6, nothing sent.
#[tokio::test]
async fn merging_any_taddr_never_takes_a_watched_coin() {
    let mut f = fixture_with("watch-merge", false).await;
    assert_eq!(f.w.coins.len(), 0);
    assert_eq!(f.w.watch_coins.len(), 2);
    let to = text(
        f.w.call(&f.node, "getnewaddress", &[json!(""), json!("pqslh")])
            .await
            .unwrap(),
    );
    assert_eq!(
        f.err("z_mergetoaddress", &[json!(["ANY_TADDR"]), json!(to)])
            .await,
        (-6, "Could not find any funds to merge.".to_string())
    );
    assert!(f.sent().is_empty());
}
