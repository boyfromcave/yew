// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The "has held YED" guard (beta2; the C++ lines' wallet.dat `yedheld` record and start-up
//! refusal): a wallet that has held YED, connected to a node where Yellowback is not live, cannot
//! tell its YED outputs from plain YEC, so every plain YEC spend is refused, unless yewd runs with
//! `-yellowback=0` (then it proceeds, with a warning). yewd refuses at send time rather than at
//! start, because it can be pointed at another node without a restart. The marker is set once and
//! survives a restart and the pre-D-9 address-book rewrite; older wallet files without it read as
//! unmarked.

mod common;

use common::*;
use yew_core::pq::PqKeyId;

const COIN: i64 = 100_000_000;

const REFUSAL: &str = "This wallet has held YED, but Yellowback is not live on the connected node, so its YED outputs cannot be told apart from plain YEC. Connect to a node with the network's attestor set, or start yewd with -yellowback=0 to acknowledge that they are spendable as plain YEC.";

fn live() -> Value {
    json!({"healthy": true, "unhealthyReason": "", "height": 2, "startHeight": 0, "params": {}})
}

struct Fix {
    node: MockNode,
    w: Wallet,
    dir: std::path::PathBuf,
    ecc: String,
    slh: String,
    zaddr: String,
}

fn addr_script(a: &str) -> Vec<u8> {
    yewd_wallet::rpc::parse_taddr_script(Network::Regtest, a).unwrap()
}

fn text(v: yewd_wallet::json::J) -> String {
    v.text().trim_matches('"').to_string()
}

async fn fixture(name: &str) -> Fix {
    let node = MockNode::default();
    node.0.lock().unwrap().vault_height = Some(1);
    genesis(&node);
    let dir = dir(name);
    let mut w = Wallet::open(&dir, Network::Regtest, core_signer(&dir.join("signer")), 0).unwrap();
    w.sync(&node).await.unwrap();
    let ecc = text(w.call(&node, "getnewaddress", &[]).await.unwrap());
    let slh = text(
        w.call(&node, "getnewaddress", &[json!("pqslh")])
            .await
            .unwrap(),
    );
    let zaddr = text(w.call(&node, "z_getnewaddress", &[]).await.unwrap());
    let foreign = |n: u32| OutPoint { txid: [5; 32], n };
    // one coin for each spend path: every send leaves its change unconfirmed
    let mut txs = vec![
        coinbase(1, vec![0x51], 0),
        payment(foreign(0), addr_script(&ecc), 5 * COIN),
        payment(foreign(1), addr_script(&slh), 5 * COIN),
    ];
    for n in 2..14 {
        txs.push(payment(foreign(n), addr_script(&ecc), COIN));
    }
    // post-quantum coins beside them (sendtoaddress and sendmany spend the ECC coins only)
    for n in 14..18 {
        txs.push(payment(foreign(n), addr_script(&slh), 5 * COIN));
    }
    node.mine(txs, 0);
    w.sync(&node).await.unwrap();
    Fix {
        node,
        w,
        dir,
        ecc,
        slh,
        zaddr,
    }
}

impl Fix {
    async fn call(&mut self, m: &str, p: &[Value]) -> Result<String, (i64, String)> {
        self.w
            .call(&self.node, m, p)
            .await
            .map(text)
            .map_err(|e| (e.code, e.message))
    }

    async fn held(&mut self) -> bool {
        let v: Value =
            serde_json::from_str(&self.call("getwalletinfo", &[]).await.unwrap()).unwrap();
        v["yed_held"].as_bool().unwrap()
    }

    /// Mark the wallet the way a user does: a holder key, while Yellowback is live.
    async fn mark(&mut self, typ: &str) {
        self.node.0.lock().unwrap().yed_info = Some(live());
        self.call("yed_getnewaddress", &[json!(typ)]).await.unwrap();
        self.node.0.lock().unwrap().yed_info = None;
    }

    async fn zsend(&mut self, from: &str, to: &str) -> Result<String, (i64, String)> {
        let p = [
            json!(from),
            json!([{"address": to, "amount": 0.5}]),
            json!(1),
            Value::Null,
            json!("AllowFullyTransparent"),
        ];
        let opid = self.call("z_sendmany", &p).await?;
        let r = call_json(
            &mut self.w,
            &self.node,
            "z_getoperationresult",
            &[json!([opid])],
        )
        .await;
        match r[0]["status"].as_str() {
            Some("success") => Ok(r[0]["result"]["txid"].as_str().unwrap().to_string()),
            _ => Err((
                r[0]["error"]["code"].as_i64().unwrap(),
                r[0]["error"]["message"].as_str().unwrap().to_string(),
            )),
        }
    }

    async fn lock(&mut self, from: Option<&str>) -> Result<String, (i64, String)> {
        let mut p = json!({
            "tag": "TEST",
            "setid": "11".repeat(32),
            "delay": 1,
            "ownerheight": 1000,
            "amount": 1.0,
        });
        if let Some(f) = from {
            p["from"] = json!(f);
        }
        self.call("vault_lock", &[p]).await
    }

    /// Every plain YEC spend path, each a fresh call: (name, its answer, the refusal's prefix).
    async fn every_spend(
        &mut self,
    ) -> Vec<(&'static str, Result<String, (i64, String)>, &'static str)> {
        let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x44; 20]);
        let mut raw = Transaction::new_v4();
        raw.vout.push(TxOut {
            value: COIN,
            script_pubkey: addr_script(&to),
        });
        let raw = hex::encode(raw.serialize().unwrap());
        let mut m = serde_json::Map::new();
        m.insert(to.clone(), json!(0.5));
        let (ecc, slh, zaddr) = (self.ecc.clone(), self.slh.clone(), self.zaddr.clone());
        vec![
            (
                "sendtoaddress",
                self.call("sendtoaddress", &[json!(to), json!(0.5)]).await,
                "",
            ),
            (
                "sendmany",
                self.call("sendmany", &[json!(""), Value::Object(m)]).await,
                "",
            ),
            (
                "fundrawtransaction",
                self.call("fundrawtransaction", &[json!(raw)]).await,
                "",
            ),
            ("z_sendmany ecc", self.zsend(&ecc, &to).await, ""),
            (
                "z_sendmany ecc->sapling",
                self.zsend(&ecc, &zaddr).await,
                "",
            ),
            ("z_sendmany pq", self.zsend(&slh, &to).await, ""),
            (
                "z_sendmany ANY_TADDR",
                self.zsend("ANY_TADDR", &to).await,
                "",
            ),
            ("vault_lock", self.lock(None).await, ""),
            ("vault_lock from ecc", self.lock(Some(&ecc)).await, "from: "),
            ("vault_lock from pq", self.lock(Some(&slh)).await, "from: "),
        ]
    }
}

/// Unmarked: a wallet that never held YED spends normally where Yellowback is not live.
#[tokio::test]
async fn an_unmarked_wallet_proceeds_where_yellowback_is_not_live() {
    let mut f = fixture("held-unmarked").await;
    assert!(!f.held().await);
    for (name, r, _) in f.every_spend().await {
        r.unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

/// Marked by a holder key: every plain YEC spend is refused, nothing is broadcast.
#[tokio::test]
async fn a_marked_wallet_refuses_every_spend_where_yellowback_is_not_live() {
    for typ in ["p2pkh", "pq"] {
        let mut f = fixture(&format!("held-{typ}")).await;
        f.mark(typ).await;
        assert!(f.held().await, "{typ}");
        for (name, r, prefix) in f.every_spend().await {
            assert_eq!(
                r.unwrap_err(),
                (-4, format!("{prefix}{REFUSAL}")),
                "{typ} {name}"
            );
        }
        assert!(f.node.0.lock().unwrap().sent.is_empty());
    }
}

/// A pqowner key is not a holder key: no mark.
#[tokio::test]
async fn a_pqowner_key_does_not_mark() {
    let mut f = fixture("held-owner").await;
    f.mark("pqowner").await;
    assert!(!f.held().await);
}

/// Marked by the index: a sync that finds a YED token among the wallet's outputs.
#[tokio::test]
async fn a_token_seen_at_sync_marks() {
    let mut f = fixture("held-token").await;
    let coin =
        f.w.coins
            .iter()
            .find(|c| c.script == addr_script(&f.ecc) && c.value == COIN)
            .unwrap()
            .clone();
    {
        let mut c = f.node.0.lock().unwrap();
        c.yed_info = Some(live());
        c.tokens = vec![json!({"txid": coin.txid, "vout": coin.vout})];
    }
    f.node.mine(vec![coinbase(2, vec![0x51], 0)], 0);
    f.w.sync(&f.node).await.unwrap();
    assert!(f.held().await);
}

/// `-yellowback=0`: the marked wallet proceeds (with the warning on each send).
#[tokio::test]
async fn the_override_proceeds() {
    let mut f = fixture("held-ack").await;
    f.mark("p2pkh").await;
    f.w.opts.yellowback_ack = true;
    for (name, r, _) in f.every_spend().await {
        r.unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

/// The marker survives a restart and the pre-D-9 address-book rewrite at load; a wallet file
/// written before the marker existed reads as unmarked.
#[tokio::test]
async fn the_marker_survives_restart_and_book_migration() {
    let mut f = fixture("held-restart").await;
    f.mark("p2pkh").await;
    let dir = f.dir.clone();
    drop(f.w);
    // a pre-D-9 book key, as an old wallet file holds it
    let path = dir.join("wallet.json");
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(v["yed_held"], json!(true));
    let id = PqKeyId {
        scheme: 1,
        hash: [0x21; 32],
    };
    let mut old = Network::Regtest.legacy_pq_versions().1.to_vec();
    old.extend_from_slice(&id.to_bytes());
    let old = yew_core::keys::base58check_encode(&old);
    v["book"][&old] = json!({"label": "old", "purpose": "receive"});
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let mut w = Wallet::open(&dir, Network::Regtest, core_signer(&dir.join("signer")), 0).unwrap();
    assert!(w.st.yed_held);
    assert!(!w.st.book.contains_key(&old), "the book was rewritten");
    w.sync(&f.node).await.unwrap();
    drop(w);
    // an older wallet file: no marker field
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("yed_held");
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let w = Wallet::open(&dir, Network::Regtest, core_signer(&dir.join("signer")), 0).unwrap();
    assert!(!w.st.yed_held);
}
