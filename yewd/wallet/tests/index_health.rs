// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Burn safety (beta2): every yewd path that selects transparent or post-quantum coins for a plain
//! YEC spend fails closed when the node cannot answer for its Yellowback index. Three node states,
//! for each path:
//!
//! - live and unhealthy (`yed_getinfo.healthy` false): refused with the C++ lines' string;
//! - live and healthy, but `yed_listtokens` fails: refused the same way (a failing read is never
//!   read as "no tokens");
//! - not live (`yed_getinfo` and `yed_listtokens` both `-32601`, what ycashd and kogany answer
//!   without the vault upgrade and a YED attestor set): the send goes ahead.
//!
//! The paths: `sendtoaddress`, `sendmany`, `fundrawtransaction`, `z_sendmany` from ECC (to a
//! transparent and to a Sapling recipient: the shielding), `z_sendmany` from a post-quantum
//! address, `vault_lock` funded from the wallet's coins (the `Fund` path every vault and Yellowback
//! builder shares: `set_join`, the vault builders' fees, `yed_mint` and the YED builders' fee
//! inputs) and `vault_lock` with `"from"`. Nothing is broadcast on a refusal.

mod common;

use common::*;

const COIN: i64 = 100_000_000;

const REFUSAL: &str = "refusing to spend as plain YEC while the Yellowback index is unhealthy (a test reason): the wallet's YED coin locks cannot be trusted; restart with -reindex-yellowback";

#[derive(Clone, Copy, Debug)]
enum State {
    Unhealthy,
    ReadFails,
    NotLive,
}

struct Fix {
    node: MockNode,
    w: Wallet,
    ecc: String,
    slh: String,
    zaddr: String,
}

fn addr_script(a: &str) -> Vec<u8> {
    yewd_wallet::rpc::parse_taddr_script(Network::Regtest, a).unwrap()
}

/// A wallet past the Vault activation with 5 YEC at its ECC address, 5 YEC at its first SLH-DSA
/// address and four 1 YEC coins at the ECC address.
async fn fixture(name: &str) -> Fix {
    let node = MockNode::default();
    node.0.lock().unwrap().vault_height = Some(1);
    genesis(&node);
    let d = dir(name);
    let mut w = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    w.sync(&node).await.unwrap();
    let text = |v: yewd_wallet::json::J| v.text().trim_matches('"').to_string();
    let ecc = text(w.call(&node, "getnewaddress", &[]).await.unwrap());
    let slh = text(
        w.call(&node, "getnewaddress", &[json!("pqslh")])
            .await
            .unwrap(),
    );
    let zaddr = text(w.call(&node, "z_getnewaddress", &[]).await.unwrap());
    let foreign = |n: u32| OutPoint { txid: [7; 32], n };
    let mut txs = vec![
        coinbase(1, vec![0x51], 0),
        payment(foreign(0), addr_script(&ecc), 5 * COIN),
        payment(foreign(1), addr_script(&slh), 5 * COIN),
    ];
    for n in 2..6 {
        txs.push(payment(foreign(n), addr_script(&ecc), COIN));
    }
    node.mine(txs, 0);
    w.sync(&node).await.unwrap();
    Fix {
        node,
        w,
        ecc,
        slh,
        zaddr,
    }
}

impl Fix {
    fn set(&self, s: State) {
        let mut c = self.node.0.lock().unwrap();
        match s {
            State::Unhealthy => {
                c.yed_info = Some(json!({"healthy": false, "unhealthyReason": "a test reason"}));
                c.tokens_error = Some((
                    -26,
                    "yellowback-unhealthy: a test reason; restart with -reindex-yellowback".into(),
                ));
            }
            State::ReadFails => {
                c.yed_info = Some(json!({"healthy": true, "unhealthyReason": ""}));
                c.tokens_error = Some((
                    -26,
                    "yellowback-unhealthy: a test reason; restart with -reindex-yellowback".into(),
                ));
            }
            State::NotLive => {
                c.yed_info = None;
                c.tokens_error = Some((-32601, "Method not found".into()));
            }
        }
    }

    fn sent(&self) -> usize {
        self.node.0.lock().unwrap().sent.len()
    }

    async fn call(&mut self, m: &str, p: &[Value]) -> Result<String, (i64, String)> {
        self.w
            .call(&self.node, m, p)
            .await
            .map(|v| v.text())
            .map_err(|e| (e.code, e.message))
    }

    /// `z_sendmany`, run to its end.
    async fn zsend(&mut self, from: &str, to: &str, amount: i64) -> Result<String, (i64, String)> {
        let p = [
            json!(from),
            json!([{"address": to, "amount": amount as f64 / COIN as f64}]),
            json!(1),
        ];
        let opid = self.call("z_sendmany", &p).await?;
        let r = call_json(
            &mut self.w,
            &self.node,
            "z_getoperationresult",
            &[json!([opid.trim_matches('"')])],
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
}

/// Run `op` in each state on a fresh wallet: refused (nothing broadcast) while the index cannot
/// answer, accepted when Yellowback is not live.
async fn each_state<F>(name: &str, prefix: &str, op: F)
where
    F: for<'a> Fn(
        &'a mut Fix,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, (i64, String)>> + 'a>,
    >,
{
    for s in [State::Unhealthy, State::ReadFails, State::NotLive] {
        let mut f = fixture(&format!("{name}-{s:?}")).await;
        f.set(s);
        let before = f.sent();
        let r = op(&mut f).await;
        match s {
            State::NotLive => {
                r.unwrap_or_else(|e| panic!("{name} {s:?}: {e:?}"));
                assert!(f.sent() > before, "{name} {s:?}: broadcast");
            }
            _ => {
                assert_eq!(
                    r.unwrap_err(),
                    (-4, format!("{prefix}{REFUSAL}")),
                    "{name} {s:?}"
                );
                assert_eq!(f.sent(), before, "{name} {s:?}: nothing broadcast");
            }
        }
    }
}

#[tokio::test]
async fn sendtoaddress_fails_closed() {
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x33; 20]);
    each_state("sendtoaddress", "", |f| {
        let to = to.clone();
        Box::pin(async move { f.call("sendtoaddress", &[json!(to), json!(1.0)]).await })
    })
    .await;
}

#[tokio::test]
async fn sendmany_fails_closed() {
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x34; 20]);
    each_state("sendmany", "", |f| {
        let to = to.clone();
        let mut m = serde_json::Map::new();
        m.insert(to.clone(), json!(1.0));
        Box::pin(async move { f.call("sendmany", &[json!(""), Value::Object(m)]).await })
    })
    .await;
}

/// fundrawtransaction only funds (nothing is broadcast), so its "accepted" leg checks the answer.
#[tokio::test]
async fn fundrawtransaction_fails_closed() {
    let mut t = Transaction::new_v4();
    t.vout.push(TxOut {
        value: COIN,
        script_pubkey: yewd_wallet::rpc::parse_taddr_script(
            Network::Regtest,
            &yew_core::keys::encode_p2pkh(Network::Regtest, &[0x35; 20]),
        )
        .unwrap(),
    });
    let raw = hex::encode(t.serialize().unwrap());
    for s in [State::Unhealthy, State::ReadFails, State::NotLive] {
        let mut f = fixture(&format!("fundraw-{s:?}")).await;
        f.set(s);
        let r = f.call("fundrawtransaction", &[json!(raw)]).await;
        match s {
            State::NotLive => {
                let v: Value = serde_json::from_str(&r.unwrap()).unwrap();
                assert!(v["hex"].as_str().is_some_and(|h| h.len() > raw.len()));
            }
            _ => assert_eq!(r.unwrap_err(), (-4, REFUSAL.to_string()), "{s:?}"),
        }
    }
}

#[tokio::test]
async fn z_sendmany_from_ecc_to_transparent_fails_closed() {
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x36; 20]);
    each_state("zsend-t", "", |f| {
        let (from, to) = (f.ecc.clone(), to.clone());
        Box::pin(async move { f.zsend(&from, &to, COIN).await })
    })
    .await;
}

/// Sapling shielding from transparent coins.
#[tokio::test]
async fn z_sendmany_shielding_from_ecc_fails_closed() {
    each_state("zsend-shield", "", |f| {
        let (from, to) = (f.ecc.clone(), f.zaddr.clone());
        Box::pin(async move { f.zsend(&from, &to, COIN).await })
    })
    .await;
}

#[tokio::test]
async fn z_sendmany_from_post_quantum_fails_closed() {
    each_state("zsend-pq", "", |f| {
        let (from, to) = (f.slh.clone(), f.ecc.clone());
        Box::pin(async move { f.zsend(&from, &to, COIN).await })
    })
    .await;
}

/// The default funding: `Fund` / `EligibleCoins`, which `set_join`, the vault builders' fee
/// inputs, `yed_mint` and the YED builders' fee inputs share.
#[tokio::test]
async fn vault_lock_default_funding_fails_closed() {
    each_state("lock-default", "", |f| Box::pin(f.lock(None))).await;
}

#[tokio::test]
async fn vault_lock_from_ecc_and_pq_fails_closed() {
    each_state("lock-from-ecc", "from: ", |f| {
        let from = f.ecc.clone();
        Box::pin(async move { f.lock(Some(&from)).await })
    })
    .await;
    each_state("lock-from-pq", "from: ", |f| {
        let from = f.slh.clone();
        Box::pin(async move { f.lock(Some(&from)).await })
    })
    .await;
}

/// A live `yed_getinfo` that does not say `healthy: true` is not trusted: refused.
#[tokio::test]
async fn a_live_answer_without_healthy_true_is_refused() {
    let mut f = fixture("getinfo-error").await;
    {
        let mut c = f.node.0.lock().unwrap();
        c.yed_info = Some(json!({"unhealthyReason": ""})); // no `healthy` field: not trusted
    }
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x37; 20]);
    let e = f
        .call("sendtoaddress", &[json!(to), json!(1.0)])
        .await
        .unwrap_err();
    assert_eq!(e, (-4, REFUSAL.replace("a test reason", "")));
    assert_eq!(f.sent(), 0);
}

/// M2: an ECC source paying a post-quantum recipient (the hybrid path of beta2 D-2).
#[tokio::test]
async fn z_sendmany_from_ecc_to_post_quantum_fails_closed() {
    each_state("zsend-t-pq", "", |f| {
        let (from, to) = (f.ecc.clone(), f.slh.clone());
        Box::pin(async move { f.zsend(&from, &to, COIN).await })
    })
    .await;
}

/// `ANY_TADDR` as the source, to an ECC, a post-quantum and a Sapling recipient.
#[tokio::test]
async fn z_sendmany_from_any_taddr_fails_closed() {
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x38; 20]);
    each_state("zsend-any", "", |f| {
        let to = to.clone();
        Box::pin(async move { f.zsend("ANY_TADDR", &to, COIN).await })
    })
    .await;
    each_state("zsend-any-pq", "", |f| {
        let to = f.slh.clone();
        Box::pin(async move { f.zsend("ANY_TADDR", &to, COIN).await })
    })
    .await;
    each_state("zsend-any-z", "", |f| {
        let to = f.zaddr.clone();
        Box::pin(async move { f.zsend("ANY_TADDR", &to, COIN).await })
    })
    .await;
}

/// The reads and lock RPCs that rest on the YED outpoint set: an error, never an answer as if
/// nothing were held (z_gettotalbalance would count YED as YEC; lockunspent would drop or release a
/// YED lock; yed_lockcoins would lock nothing); yed_getinfo answers with protectedByIndex false.
#[tokio::test]
async fn reads_and_locks_fail_closed() {
    for s in [State::Unhealthy, State::ReadFails] {
        let mut f = fixture(&format!("reads-{s:?}")).await;
        f.set(s);
        for (m, p) in [
            ("z_gettotalbalance", vec![]),
            ("lockunspent", vec![json!(true)]),
            (
                "lockunspent",
                vec![json!(true), json!([{"txid": "00".repeat(32), "vout": 0}])],
            ),
            ("yed_lockcoins", vec![]),
        ] {
            assert_eq!(
                f.call(m, &p).await.unwrap_err(),
                (-4, REFUSAL.to_string()),
                "{m} {s:?}"
            );
        }
        let info =
            f.w.augment(&f.node, "yed_getinfo", &[], r#"{"healthy":false}"#)
                .await
                .unwrap();
        let v: Value = serde_json::from_str(&info).unwrap();
        assert_eq!(v["protectedByIndex"], json!(false), "{s:?}");
    }
    let mut f = fixture("reads-notlive").await;
    f.set(State::NotLive);
    let v: Value = serde_json::from_str(&f.call("z_gettotalbalance", &[]).await.unwrap()).unwrap();
    assert_eq!(v["transparent"], json!("14.00"));
}

/// Review YEW-REVIEW-3 L3: a `yed_listtokens` answer that is not a list is an error (fail
/// closed), never "no tokens".
#[tokio::test]
async fn a_malformed_token_list_is_refused() {
    let mut f = fixture("l3-malformed").await;
    {
        let mut c = f.node.0.lock().unwrap();
        c.yed_info = Some(json!({"healthy": true, "unhealthyReason": ""}));
        c.tokens_raw = Some(json!({"tokens": []}));
    }
    let (code, msg) = f
        .call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
        .await
        .unwrap_err();
    assert_eq!(code, -4);
    assert!(
        msg.starts_with("refusing to spend as plain YEC while the Yellowback index is unhealthy (yed_listtokens answered something that is not a list: "),
        "{msg}"
    );
    assert_eq!(f.sent(), 0);
}

/// `z_sendmany` with these params, run to its end: the operation's result object.
async fn zsend_policy(f: &mut Fix, p: &[Value]) -> Value {
    let opid = f.call("z_sendmany", p).await.unwrap();
    let r = call_json(
        &mut f.w,
        &f.node,
        "z_getoperationresult",
        &[json!([opid.trim_matches('"')])],
    )
    .await;
    r[0].clone()
}

/// Review YEW-REVIEW-3 L3: Yellowback judged not live (`-32601`, also what an RPC-filtering
/// proxy answers): an own output of exactly TOKEN_VALUE stays reserved, as the app's classifier
/// keeps it HELD; with `-yellowback=0` it is spendable.
#[tokio::test]
async fn not_live_still_reserves_token_value_outputs() {
    let mut f = fixture("l3-notlive").await;
    let addr = f
        .call("getnewaddress", &[])
        .await
        .unwrap()
        .trim_matches('"')
        .to_string();
    let foreign = |n: u32| OutPoint { txid: [9; 32], n };
    f.node.mine(
        vec![
            payment(
                foreign(0),
                addr_script(&addr),
                yew_core::params::TOKEN_VALUE,
            ),
            payment(foreign(1), addr_script(&addr), COIN / 2),
        ],
        3,
    );
    f.w.sync(&f.node).await.unwrap();
    f.set(State::NotLive);
    // 0.50005 YEC plus the fee needs the 0.0001 coin
    let p = [
        json!(addr),
        json!([{"address": pay_to(), "amount": 0.50005}]),
        json!(1),
        Value::Null,
        json!("AllowFullyTransparent"),
    ];
    let r = zsend_policy(&mut f, &p).await;
    assert_eq!(r["status"], json!("failed"), "{r}");
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Insufficient funds: have 0.50"),
        "{r}"
    );
    assert_eq!(f.sent(), 0);
    f.w.opts.yellowback_ack = true;
    let r = zsend_policy(&mut f, &p).await;
    assert_eq!(r["status"], json!("success"), "{r}");
    assert_eq!(f.sent(), 1);
}

// ------------------------------------------------------------------ submission status (M1)

const UNKNOWN_TAIL: &str = ": check before sending again";

fn pay_to() -> String {
    yew_core::keys::encode_p2pkh(Network::Regtest, &[0x39; 20])
}

/// The node accepted, then the wallet's sync failed: the txid is returned, never an error.
#[tokio::test]
async fn accepted_then_sync_fails_returns_the_txid() {
    let mut f = fixture("m1-syncfail").await;
    f.node.0.lock().unwrap().fail_syncs_after_send = 3;
    let txid = f
        .call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
        .await
        .unwrap();
    let txid = txid.trim_matches('"').to_string();
    let c = f.node.0.lock().unwrap();
    assert_eq!(c.sent.len(), 1);
    assert!(c.mempool.iter().any(|(id, _)| *id == txid));
}

/// The answer to sendrawtransaction is lost but the node has the transaction: the txid.
#[tokio::test]
async fn lost_answer_with_the_tx_in_the_mempool_returns_the_txid() {
    let mut f = fixture("m1-lost-in").await;
    f.node.0.lock().unwrap().lose_answer = Some(true);
    let opid_txid = f.zsend(&f.ecc.clone(), &pay_to(), COIN).await.unwrap();
    let c = f.node.0.lock().unwrap();
    assert_eq!(c.sent.len(), 1);
    assert!(c.mempool.iter().any(|(id, _)| *id == opid_txid));
}

/// Mine `n` empty blocks.
fn mine_empty(node: &MockNode, n: u32) {
    for _ in 0..n {
        let h = node.0.lock().unwrap().blocks.len() as u32;
        node.mine(vec![coinbase(h, vec![0x51], 0)], 0);
    }
}

/// A lost answer with the transaction absent; returns its txid, its expiry height and its inputs.
async fn lose_one(f: &mut Fix) -> (String, u32, Vec<OutPoint>) {
    f.node.0.lock().unwrap().lose_answer = Some(false);
    let (code, msg) = f
        .call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
        .await
        .unwrap_err();
    assert_eq!(code, -4);
    f.node.0.lock().unwrap().lose_answer = None;
    let sent = f.node.0.lock().unwrap().sent.last().unwrap().clone();
    let (tx, id) = Transaction::parse(&hex::decode(&sent).unwrap()).unwrap();
    let txid = rev_hex(&id);
    assert!(
        msg.starts_with("the node did not answer the submission (")
            && msg.ends_with(&format!("; status unknown, txid {txid}{UNKNOWN_TAIL}")),
        "{msg}"
    );
    (
        txid,
        tx.expiry_height,
        tx.vin.iter().map(|i| i.prevout).collect(),
    )
}

fn still_unknown(txid: &str, clears: u32, expiry: u32, tip: u32) -> (i64, String) {
    (
        -4,
        format!("an earlier transaction's status is still unknown, txid {txid}: its coins stay locked until the chain reaches height {clears} (10 blocks past its expiry height {expiry}; the chain is at {tip}); nothing was sent. Check before sending again; clearunknownsubmission {txid} releases them now if you are sure it reached no node"),
    )
}

fn tip(f: &Fix) -> u32 {
    f.node.0.lock().unwrap().blocks.len() as u32 - 1
}

/// The answer is lost and the node does not have it: "status unknown" with the txid; nothing is
/// submitted again. Review YEW-REVIEW-3 L1: the node's "not found" alone releases nothing (a
/// late arrival or another node could still mine it): every send is refused, naming the height
/// at which the coins clear, also while the node cannot sync; once the chain is 10 blocks past
/// the expiry height the coins are released, and the send after that goes ahead.
#[tokio::test]
async fn lost_answer_with_the_tx_absent_is_status_unknown() {
    let mut f = fixture("m1-lost-out").await;
    let (txid, expiry, _) = lose_one(&mut f).await;
    let clears = expiry + 10;
    // the node says "not found": still locked
    assert_eq!(
        f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
            .await
            .unwrap_err(),
        still_unknown(&txid, clears, expiry, tip(&f))
    );
    // just short of the clearing height, the node unable to sync: still locked
    mine_empty(&f.node, clears - 1 - tip(&f));
    f.node.0.lock().unwrap().fail_syncs = 1;
    assert_eq!(
        f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
            .await
            .unwrap_err(),
        still_unknown(&txid, clears, expiry, clears - 1)
    );
    // at the clearing height, the node still unable to sync: released all the same
    mine_empty(&f.node, 1);
    f.node.0.lock().unwrap().fail_syncs = 1;
    assert_eq!(
        f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
            .await
            .unwrap_err(),
        (-4, format!("the earlier transaction {txid}, whose status was unknown, expired at height {expiry} without reaching the chain (the chain is at {clears}); its coins are released; nothing was sent now: send again"))
    );
    assert_eq!(f.sent(), 1, "nothing submitted again");
    f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
        .await
        .unwrap();
    assert_eq!(f.sent(), 2);
}

/// Review YEW-REVIEW-3 L1: one of the inputs spent by another transaction, 10 blocks deep: the
/// lost one can never be mined, its coins are released; one block shallower they stay locked.
#[tokio::test]
async fn lost_answer_released_by_a_conflicting_spend() {
    let mut f = fixture("m1-conflict").await;
    let (txid, expiry, inputs) = lose_one(&mut f).await;
    f.node.mine(vec![payment(inputs[0], vec![0x51], 1000)], 9);
    mine_empty(&f.node, 8);
    assert_eq!(
        f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
            .await
            .unwrap_err(),
        still_unknown(&txid, expiry + 10, expiry, tip(&f))
    );
    mine_empty(&f.node, 1);
    let op = format!("{}:{}", rev_hex(&inputs[0].txid), inputs[0].n);
    assert_eq!(
        f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
            .await
            .unwrap_err(),
        (-4, format!("the earlier transaction {txid}, whose status was unknown, can no longer be mined (its input {op} is spent by another transaction); its coins are released; nothing was sent now: send again"))
    );
}

/// Review YEW-REVIEW-3 L1: the operator's `clearunknownsubmission` needs the outstanding txid,
/// works while the node is down, and releases the coins at once.
#[tokio::test]
async fn clearunknownsubmission_releases_the_named_submission() {
    let mut f = fixture("m1-clear").await;
    assert_eq!(
        f.call("clearunknownsubmission", &[json!("00".repeat(32))])
            .await
            .unwrap_err(),
        (
            -8,
            "no submission of unknown status is outstanding".to_string()
        )
    );
    let (txid, expiry, inputs) = lose_one(&mut f).await;
    assert_eq!(
        f.call("clearunknownsubmission", &[json!("11".repeat(32))])
            .await
            .unwrap_err(),
        (
            -8,
            format!(
                "the submission of unknown status is {txid}, not {}",
                "11".repeat(32)
            )
        )
    );
    assert_eq!(
        f.call("clearunknownsubmission", &[]).await.unwrap_err().0,
        -1
    );
    f.node.0.lock().unwrap().fail_syncs = 5;
    let v: Value = serde_json::from_str(
        &f.call("clearunknownsubmission", &[json!(txid)])
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(v["txid"], json!(txid));
    assert_eq!(v["expiryheight"], json!(expiry));
    let released: Vec<String> = inputs
        .iter()
        .map(|o| format!("{}:{}", rev_hex(&o.txid), o.n))
        .collect();
    assert_eq!(v["released"], json!(released));
    f.node.0.lock().unwrap().fail_syncs = 0;
    f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
        .await
        .unwrap();
    assert_eq!(f.sent(), 2);
}

/// Review YEW-REVIEW-3 L2: only -25, -26 and -27 are refusals. A proxy's -32603 or -1 is a lost
/// answer: status unknown, coins locked; a -26 is a refusal, nothing recorded.
#[tokio::test]
async fn only_node_rejections_are_refusals() {
    for (code, unknown) in [
        (-32603, true),
        (-1, true),
        (-26, false),
        (-25, false),
        (-27, false),
    ] {
        let mut f = fixture(&format!("l2-{}", -code)).await;
        {
            let mut c = f.node.0.lock().unwrap();
            c.reject = Some("upstream: request timed out".into());
            c.reject_code = Some(code);
        }
        let (got, msg) = f
            .call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
            .await
            .unwrap_err();
        {
            let mut c = f.node.0.lock().unwrap();
            c.reject = None;
            c.reject_code = None;
        }
        if unknown {
            assert_eq!(got, -4, "{code}");
            assert!(msg.contains("; status unknown, txid "), "{code}: {msg}");
            let again = f
                .call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
                .await
                .unwrap_err();
            assert!(
                again
                    .1
                    .starts_with("an earlier transaction's status is still unknown"),
                "{code}: {again:?}"
            );
        } else {
            assert!(
                msg.contains("upstream: request timed out") && !msg.contains("status unknown"),
                "{code} {got}: {msg}"
            );
            f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
                .await
                .unwrap();
        }
    }
}

/// The lost transaction reaches the node late: the next send is refused once, saying so.
#[tokio::test]
async fn a_late_arrival_is_reported_before_any_new_send() {
    let mut f = fixture("m1-late").await;
    f.node.0.lock().unwrap().lose_answer = Some(false);
    f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
        .await
        .unwrap_err();
    let sent = f.node.0.lock().unwrap().sent[0].clone();
    let raw = hex::decode(&sent).unwrap();
    let txid = rev_hex(&Transaction::parse(&raw).unwrap().1);
    {
        let mut c = f.node.0.lock().unwrap();
        c.lose_answer = None;
        c.mempool.push((txid.clone(), raw));
    }
    assert_eq!(
        f.call("sendtoaddress", &[json!(pay_to()), json!(1.0)])
            .await
            .unwrap_err(),
        (-4, format!("the earlier transaction {txid}, whose status was unknown, reached the node; nothing was sent now: send again only if this is a new payment"))
    );
    assert_eq!(f.sent(), 1);
}
