// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The sync discipline without a node binary (plan §3b S1, hazards H1/H2): a scripted chain of
//! real v4 transactions in synthetic blocks, a reorg rewound to its fork point (a coinbase
//! dropped, a payment back to the mempool, then evicted), a reorg deeper than nothing the wallet
//! recognises, and the state file reloaded.

mod common;

use common::*;

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
    // ycashd's refusals: Sprout after Canopy names the type, anything else is the short text
    let e = w
        .call(&node, "z_getnewaddress", &[json!("sprout")])
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.message.as_str()),
        (
            -8,
            "Invalid address type, \"sprout\" is not allowed after Canopy"
        )
    );
    let e = w
        .call(&node, "z_getnewaddress", &[json!("bogus")])
        .await
        .unwrap_err();
    assert_eq!((e.code, e.message.as_str()), (-8, "Invalid address type"));
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

/// Review of stage 2, finding 4: the total and its ECC and post-quantum parts come from one
/// implementation, so getbalance = getwalletinfo balance = balance_ecc + balance_pq, with an
/// immature coinbase, a spent output and an unconfirmed one present.
#[tokio::test]
async fn balance_parts_add_up_with_immature_spent_and_unconfirmed() {
    let node = MockNode::default();
    genesis(&node);
    let d = dir("addup");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    let ecc = yew_core::script::p2pkh_script(&w.book.key(0, 0).unwrap().hash);
    let fn_ = yew_core::pq::pqpkh_script(&w.book.pq_key(2, 0).unwrap().id).unwrap();
    let slh = yew_core::pq::pqpkh_script(&w.book.pq_key(1, 0).unwrap().id).unwrap();
    let foreign = |n: u32| OutPoint { txid: [9; 32], n };
    let pay_fn = payment(foreign(0), fn_.clone(), 300_000_000);
    let pay_fn_id = Transaction::parse(&pay_fn).unwrap().1;
    node.mine(
        vec![
            coinbase(1, ecc.clone(), 1_000_000_000), // immature
            pay_fn,
            payment(foreign(1), slh.clone(), 100_000_000),
            payment(foreign(2), ecc.clone(), 50_000_000),
        ],
        0,
    );
    // the FN-DSA coin is spent (to a foreign script), the SLH-DSA one is not
    node.mine(
        vec![
            coinbase(2, vec![0x51], 0),
            payment(
                OutPoint {
                    txid: pay_fn_id,
                    n: 0,
                },
                vec![0x51],
                299_000_000,
            ),
        ],
        0,
    );
    node.to_mempool(payment(foreign(3), fn_.clone(), 20_000_000));
    w.sync(&node).await.unwrap();
    let info = call_json(&mut w, &node, "getwalletinfo", &[]).await;
    let bal = zat(&info["balance"]);
    assert_eq!(bal, 150_000_000);
    assert_eq!(zat(&info["balance_ecc"]) + zat(&info["balance_pq"]), bal);
    assert_eq!(zat(&info["balance_pq"]), 100_000_000);
    let unc = zat(&info["unconfirmed_balance"]);
    assert_eq!(unc, 20_000_000);
    assert_eq!(
        zat(&info["unconfirmed_balance_ecc"]) + zat(&info["unconfirmed_balance_pq"]),
        unc
    );
    let by: i64 = info["pq_by_scheme"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| zat(&s["balance_pq"]))
        .sum();
    assert_eq!(by, zat(&info["balance_pq"]));
    let gb = w.call(&node, "getbalance", &[]).await.unwrap().text();
    assert_eq!(zat(&Value::String(gb)), bal);
}

/// Review of stage 2, finding 5: `yed_holder` is present (true) on a PQ address at which the
/// index holds a token of this wallet, and absent on one without.
#[tokio::test]
async fn yed_holder_is_marked_where_the_index_holds_a_token() {
    let node = MockNode::default();
    genesis(&node);
    let d = dir("holder");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    let holder = w.book.pq_key(2, 0).unwrap().id;
    let plain = w.book.pq_key(2, 1).unwrap().id;
    let tok = payment(
        OutPoint {
            txid: [9; 32],
            n: 0,
        },
        yew_core::pq::pqpkh_script(&holder).unwrap(),
        10_000,
    );
    let tok_id = rev_hex(&Transaction::parse(&tok).unwrap().1);
    node.mine(
        vec![
            tok,
            payment(
                OutPoint {
                    txid: [9; 32],
                    n: 1,
                },
                yew_core::pq::pqpkh_script(&plain).unwrap(),
                50_000_000,
            ),
        ],
        0,
    );
    node.0.lock().unwrap().tokens = vec![json!({"txid": tok_id, "vout": 0})];
    w.sync(&node).await.unwrap();
    let rows = call_json(&mut w, &node, "listreceivedbyaddress", &[json!(0)]).await;
    let row = |id| {
        let a = yew_core::keys::encode_pq_yec(Network::Regtest, &id).unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["address"] == a.as_str())
            .cloned()
            .unwrap_or_else(|| panic!("{a} not listed: {rows}"))
    };
    assert_eq!(row(holder)["yed_holder"], json!(true));
    assert!(row(plain).get("yed_holder").is_none());
}

/// The pre-D-9 form of a PQ key: `version2 ‖ scheme ‖ keyHash` (YED form when `yed`).
fn old_pq_form(id: &yew_core::pq::PqKeyId, yed: bool) -> String {
    let (y, p) = Network::Regtest.legacy_pq_versions();
    let mut v = if yed { y.to_vec() } else { p.to_vec() };
    v.extend_from_slice(&id.to_bytes());
    yew_core::keys::base58check_encode(&v)
}

/// Review of stage 1, finding 5: a wallet whose book was written before D-9 opens with the book
/// keyed by the D-9 form (label kept), end to end through `Wallet::open` and the listings; and,
/// finding 3, a datadir it cannot write still opens, with the rewritten book in memory.
#[tokio::test]
async fn a_pre_d9_book_opens_rewritten_also_read_only() {
    let node = MockNode::default();
    genesis(&node);
    let d = dir("oldbook");
    let id = {
        let w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
        w.book.pq_key(1, 0).unwrap().id
    };
    let path = d.join("wallet.json");
    let mut st: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    st["book"][old_pq_form(&id, false)] = json!({"label": "old", "purpose": "receive"});
    std::fs::write(&path, serde_json::to_vec(&st).unwrap()).unwrap();
    let new = yew_core::keys::encode_pq_yec(Network::Regtest, &id).unwrap();
    // read-only datadir: opens, rewritten in memory, the file unchanged
    let mut perm = std::fs::metadata(&d).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perm.set_mode(0o555);
    std::fs::set_permissions(&d, perm.clone()).unwrap();
    let ro = Wallet::open(&d, Network::Regtest, signer(), 0);
    perm.set_mode(0o755);
    std::fs::set_permissions(&d, perm).unwrap();
    let ro = ro.expect("a read-only datadir still opens");
    assert_eq!(ro.st.book[&new].label, "old");
    assert!(!ro.st.book.contains_key(&old_pq_form(&id, false)));
    drop(ro);
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(on_disk["book"].get(old_pq_form(&id, false)).is_some());
    // writable: rewritten and saved, and the listings show the D-9 form
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(on_disk["book"].get(old_pq_form(&id, false)).is_none());
    assert_eq!(on_disk["book"][&new]["label"], "old");
    w.sync(&node).await.unwrap();
    let rows = call_json(
        &mut w,
        &node,
        "listreceivedbyaddress",
        &[json!(0), json!(true)],
    )
    .await;
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["address"] == new.as_str()),
        "{rows}"
    );
    assert!(!rows.to_string().contains(&old_pq_form(&id, false)));
}

/// Review of stage 1, finding 5: `z_importpqkey` accepts a dump line that names the key in the
/// pre-D-9 form (`addr=` YED, `yecaddr=` YEC), and refuses a line whose address, scheme or key
/// does not match the seed, importing nothing.
#[tokio::test]
async fn z_importpqkey_reads_a_pre_d9_dump_line() {
    let node = MockNode::default();
    genesis(&node);
    let d = dir("pqimport");
    let mut w = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    let seed = [0x42u8; yew_core::pq::SEED_SIZE];
    let id = yew_core::pq::PqKey::from_seed(2, &seed).unwrap().id();
    let other = yew_core::pq::PqKey::from_seed(2, &[0x43u8; yew_core::pq::SEED_SIZE])
        .unwrap()
        .id();
    let line = |scheme: u8, addr: &str, yecaddr: &str| {
        format!(
            "pqseed={scheme}:{} addr={addr} yecaddr={yecaddr}",
            hex::encode(seed)
        )
    };
    let refused = [
        // the address of another key
        line(2, &old_pq_form(&id, true), &old_pq_form(&other, false)),
        // the scheme of the line is not the one the address names (same seed, scheme 1)
        line(1, &old_pq_form(&id, true), &old_pq_form(&id, false)),
        // the YED form where the YEC form belongs
        line(2, &old_pq_form(&id, true), &old_pq_form(&id, true)),
    ];
    for l in &refused {
        let e = w
            .call(&node, "z_importpqkey", &[json!(l), json!(false)])
            .await
            .unwrap_err();
        assert_eq!(e.code, -5, "{l}: {e:?}");
        assert!(e.message.ends_with("nothing imported"), "{}", e.message);
    }
    let yec = yew_core::keys::encode_pq_yec(Network::Regtest, &id).unwrap();
    assert!(!w.st.book.contains_key(&yec));
    w.call(
        &node,
        "z_importpqkey",
        &[
            json!(line(2, &old_pq_form(&id, true), &old_pq_form(&id, false))),
            json!(false),
        ],
    )
    .await
    .unwrap();
    assert!(w.st.book.contains_key(&yec), "imported under the D-9 form");
    assert!(w.book.pq_by_id(&id).is_some());
    // listaddresses (K-25 amended for beta2): an imported PQ key is under source "imported"
    let la = call_json(&mut w, &node, "listaddresses", &[]).await;
    let imported = la
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["source"] == "imported")
        .unwrap_or_else(|| panic!("{la}"));
    assert_eq!(
        imported["pq"],
        json!([{"address": yec, "pqscheme": 2, "pqschemename": "FN-DSA-512"}])
    );
}

/// K-25 amended for beta2 (2026-11-11): `z_gettotalbalance` with ycash6 e9a6cf33f's fields
/// (amounts as `FormatMoney` strings; `transparent` = AvailableCoins at depth >= minconf, the
/// outputs YED holds left out as ycashd's lock leaves them out; `transparent_ecc` = transparent
/// minus `transparent_pq`; both schemes always, SLH-DSA first) and `listaddresses` by source
/// with the post-quantum addresses, their scheme and `yed_holder`.
#[tokio::test]
async fn z_gettotalbalance_and_listaddresses_over_the_mock_chain() {
    let node = MockNode::default();
    genesis(&node);
    node.0.lock().unwrap().vault_height = Some(1);
    let d = dir("totalbal");
    let mut w = Wallet::open(&d, Network::Regtest, signer(), 0).unwrap();
    w.sync(&node).await.unwrap();
    let ecc_addr = w
        .call(&node, "getnewaddress", &[])
        .await
        .unwrap()
        .text()
        .trim_matches('"')
        .to_string();
    let slh_addr = w
        .call(&node, "getnewaddress", &[json!("pqslh")])
        .await
        .unwrap()
        .text()
        .trim_matches('"')
        .to_string();
    let zaddr = w
        .call(&node, "z_getnewaddress", &[])
        .await
        .unwrap()
        .text()
        .trim_matches('"')
        .to_string();
    let ecc = yewd_wallet::rpc::parse_taddr_script(Network::Regtest, &ecc_addr).unwrap();
    let slh = yewd_wallet::rpc::parse_taddr_script(Network::Regtest, &slh_addr).unwrap();
    assert_eq!(yew_core::pq::pqpkh_of(&slh).unwrap().scheme, 1);
    let fn_id = w.book.pq_key(2, 0).unwrap().id;
    let fn_ = yew_core::pq::pqpkh_script(&fn_id).unwrap();
    let change = yew_core::script::p2pkh_script(&w.book.key(1, 0).unwrap().hash);
    let foreign = |n: u32| OutPoint { txid: [9; 32], n };
    let pay_ecc = payment(foreign(0), ecc.clone(), 50_000_000);
    let pay_ecc_id = Transaction::parse(&pay_ecc).unwrap().1;
    let token = payment(foreign(3), fn_.clone(), 10_000);
    let token_id = rev_hex(&Transaction::parse(&token).unwrap().1);
    node.mine(
        vec![
            coinbase(1, ecc.clone(), 1_000_000_000), // immature
            pay_ecc,
            payment(foreign(1), fn_.clone(), 300_000_000),
            payment(foreign(2), slh.clone(), 100_000_000),
            token,
        ],
        0,
    );
    // an own send: the ECC coin to a foreign script, change to the internal chain
    let mut own = Transaction::new_v4();
    let mut i = TxIn::new(OutPoint {
        txid: pay_ecc_id,
        n: 0,
    });
    i.script_sig = vec![0x51];
    own.vin.push(i);
    own.vout.push(TxOut {
        value: 30_000_000,
        script_pubkey: vec![0x51],
    });
    own.vout.push(TxOut {
        value: 19_990_000,
        script_pubkey: change.clone(),
    });
    node.mine(
        vec![coinbase(2, vec![0x51], 0), own.serialize().unwrap()],
        0,
    );
    node.to_mempool(payment(foreign(4), fn_.clone(), 20_000_000));
    {
        // the index lists the token: Yellowback is live on this node
        let mut c = node.0.lock().unwrap();
        c.yed_info = Some(json!({"healthy": true, "unhealthyReason": ""}));
        c.tokens = vec![json!({"txid": token_id, "vout": 0})];
    }
    w.sync(&node).await.unwrap();

    let tb = call_json(&mut w, &node, "z_gettotalbalance", &[]).await;
    // strings, FormatMoney (at least two decimals)
    assert_eq!(tb["transparent"], json!("4.1999"));
    assert_eq!(tb["private"], json!("0.00"));
    assert_eq!(tb["total"], json!("4.1999"));
    assert_eq!(tb["transparent_ecc"], json!("0.1999"));
    assert_eq!(tb["transparent_pq"], json!("4.00"));
    // ycashd's field order (serde_json sorts keys: read the order from the text)
    let text = w
        .call(&node, "z_gettotalbalance", &[])
        .await
        .unwrap()
        .text();
    let at = |k: &str| text.find(&format!("\"{k}\"")).unwrap();
    let order = [
        "transparent",
        "private",
        "total",
        "transparent_ecc",
        "transparent_pq",
        "pq_by_scheme",
    ];
    assert!(order.windows(2).all(|p| at(p[0]) < at(p[1])), "{text}");
    assert_eq!(
        tb["pq_by_scheme"],
        json!([
            {"pqscheme": 1, "pqschemename": "SLH-DSA-SHA2-128s", "transparent_pq": "1.00"},
            {"pqscheme": 2, "pqschemename": "FN-DSA-512", "transparent_pq": "3.00"}
        ])
    );
    // minconf 0 counts the mempool payment; the parts add up in zatoshi
    let tb0 = call_json(&mut w, &node, "z_gettotalbalance", &[json!(0), json!(true)]).await;
    assert_eq!(zat(&tb0["transparent"]), 439_990_000);
    assert_eq!(zat(&tb0["transparent_pq"]), 420_000_000);
    assert_eq!(
        zat(&tb0["transparent_ecc"]) + zat(&tb0["transparent_pq"]),
        zat(&tb0["transparent"])
    );
    // minconf 3 leaves out both blocks' outputs
    let tb3 = call_json(&mut w, &node, "z_gettotalbalance", &[json!(3)]).await;
    assert_eq!(tb3["transparent"], json!("0.00"));
    let e = w
        .call(&node, "z_gettotalbalance", &[json!(-1)])
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.message.as_str()),
        (-8, "Minimum number of confirmations cannot be less than 0")
    );
    assert!(w
        .call(
            &node,
            "z_gettotalbalance",
            &[json!(1), json!(false), json!(0)]
        )
        .await
        .is_err());

    let la = call_json(&mut w, &node, "listaddresses", &[]).await;
    let fn_addr = yew_core::keys::encode_pq_yec(Network::Regtest, &fn_id).unwrap();
    let change_addr =
        yew_core::keys::encode_p2pkh(Network::Regtest, &w.book.key(1, 0).unwrap().hash);
    // the book's P2PKH addresses (the one opened with the wallet and getnewaddress's), in
    // ycashd's std::set<CTxDestination> order: by key hash
    let mut book_t: Vec<(Vec<u8>, String)> =
        w.st.book
            .keys()
            .filter_map(|a| {
                let s = yewd_wallet::rpc::parse_taddr_script(Network::Regtest, a)?;
                Some((yew_core::script::p2pkh_hash(&s)?.to_vec(), a.clone()))
            })
            .collect();
    book_t.sort();
    let book_t: Vec<String> = book_t.into_iter().map(|(_, a)| a).collect();
    assert!(book_t.contains(&ecc_addr));
    assert_eq!(
        la,
        json!([{
            "source": "mnemonic_seed",
            "transparent": {"addresses": book_t, "changeAddresses": [change_addr]},
            "sapling": [{"zip32KeyPath": "m/32'/347'/0'", "addresses": [zaddr]}],
            "pq": [
                {"address": slh_addr, "pqscheme": 1, "pqschemename": "SLH-DSA-SHA2-128s"},
                {"address": fn_addr, "pqscheme": 2, "pqschemename": "FN-DSA-512", "yed_holder": true}
            ]
        }]),
        "{la}"
    );
    assert!(w.call(&node, "listaddresses", &[json!(1)]).await.is_err());
}
