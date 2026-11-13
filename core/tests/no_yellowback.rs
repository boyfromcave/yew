// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! W-P1: the YEW core's app API against a server **without the Yellowback service** on a network
//! where the vault upgrade is active (post-quantum addresses hold plain YEC) but the YED module
//! has no attestor set, so the node has no `yed_*` commands and lightwalletd-dd registers no
//! `YellowbackStreamer`: testnet-yb-fast as the beta2 walkthrough found it. Ignored unless
//! `YEW_NOYB=1`. Testnet only: on regtest the wallet learns the vault activation height from the
//! Yellowback service's `GetChainInfo`, so a regtest server without the service cannot be used
//! past the upgrade at all (`params::BranchError::VaultActivationUnknown`).
//!
//! The harness (`scripts/no-yellowback-run.sh`) runs the stack and sets:
//! `YEW_NOYB_SERVER` (host:port, TLS), `YEW_NOYB_CA` (the PEM file of the CA that signed the
//! server's certificate, pinned), `YEW_NOYB_CLI` (the backing node's `ycash-cli` command line,
//! space separated: it funds the wallet and mines; a testnet-yb-fast node whose only peer is
//! another local node, never the public network), `YEW_NOYB_DST` (`ecc=…,pq_falcon=…,pq_slh=…,
//! sapling=…`: the node wallet's own addresses; its ECC balance, at least 0.81 YEC, funds the
//! wallet with `sendtoaddress`), `YEW_NOYB_DIR` (a scratch directory) and
//! `YEW_NOYB_PARAMS` (the Sapling parameters); `YEW_NOYB_MINE_THREADS` (default 4) for the
//! node's internal miner. Every line the test prints that starts with `NOYB ` is a result.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;
use yew_core::api::{self, NetworkId, ReceiveKind};

fn cli(args: &[&str]) -> String {
    let pre = std::env::var("YEW_NOYB_CLI").expect("YEW_NOYB_CLI");
    let mut p = pre.split(' ');
    let out = Command::new(p.next().unwrap())
        .args(p)
        .args(args)
        .output()
        .expect("ycash-cli");
    assert!(
        out.status.success(),
        "ycash-cli {:?}: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn cli_json(args: &[&str]) -> Value {
    serde_json::from_str(&cli(args)).unwrap_or(Value::Null)
}

fn report(what: &str, v: Value) {
    println!("NOYB {what} {v}");
}

fn height() -> u64 {
    cli(&["getblockcount"]).parse().unwrap()
}

fn mined(txid: &str) -> bool {
    cli_json(&["getrawtransaction", txid, "1"])
        .get("blockhash")
        .is_some()
}

/// Mine with the node's internal miner until every one of `txids` is in a block and the chain
/// grew by at least one block (the miner does not rebuild a template while solving, so a
/// transaction sent just before can miss the first block). The miner is switched on here and
/// left on (stopping it waits for every solver thread; the harness stops it). Returns the tip.
fn mine_until(txids: &[String]) -> u64 {
    let start_h = height();
    if cli_json(&["getmininginfo"])["generate"] != Value::Bool(true) {
        let threads = std::env::var("YEW_NOYB_MINE_THREADS").unwrap_or_else(|_| "4".into());
        cli(&["setgenerate", "true", &threads]);
    }
    let start = Instant::now();
    loop {
        if height() > start_h && txids.iter().all(|t| mined(t)) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3600),
            "mining stalled at {} ({txids:?})",
            height()
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    height()
}

/// The node's index view of a transparent or post-quantum address, zat.
fn node_balance(addr: &str) -> i64 {
    let q = serde_json::json!({ "addresses": [addr] }).to_string();
    cli_json(&["getaddressbalance", &q])["balance"]
        .as_i64()
        .unwrap_or(-1)
}

/// Sync both pools until the wallet has the node's tip (a preview syncs first; its answer is not
/// used).
fn sync_to(tip: u64) -> api::Balances {
    let start = Instant::now();
    loop {
        let _ = api::move_preview(api::MoveDirection::ToPrivate, Some(1), true);
        let b = api::balances().expect("balances");
        if b.sync_height as u64 >= tip && b.shielded_scanned_height as u64 >= tip {
            return b;
        }
        assert!(
            start.elapsed() < Duration::from_secs(600),
            "sync stuck at {} / {}",
            b.sync_height,
            tip
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn bal_json(b: &api::Balances) -> Value {
    serde_json::json!({
        "ecc_zat": b.yec_zat, "reserved_zat": b.yec_reserved_zat, "pending_zat": b.yec_pending_zat,
        "pq_zat": b.yec_pq_zat, "pq_slh_zat": b.yec_pq_slh_zat, "pq_falcon_zat": b.yec_pq_falcon_zat,
        "shielded_zat": b.yec_shielded_zat, "held": b.held_count, "sync_height": b.sync_height,
    })
}

/// A confirm call: the preview id and the unusual-fee token when one is asked.
type Confirm = dyn Fn(&str, Option<String>) -> Result<api::SendResult, api::YewError>;

/// One send through the app API: the preview, then the confirm; the txid once the node's mempool
/// or chain has it. Panics with the refusal otherwise (W-P1 is that these are refused).
fn send(
    label: &str,
    preview: Result<(String, i64, Option<String>), api::YewError>,
    confirm: &Confirm,
) -> String {
    let (id, fee, ack) = preview.unwrap_or_else(|e| panic!("{label}: preview {e:?}"));
    let r = confirm(&id, ack.clone()).unwrap_or_else(|e| panic!("{label}: confirm {e:?}"));
    let start = Instant::now();
    while !cli_json(&["getrawtransaction", &r.txid, "1"]).is_object() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{label}: {} not at the node",
            r.txid
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    report(
        "send",
        serde_json::json!({"cell": label, "txid": r.txid, "fee": fee, "ack": ack, "verdict": r.verdict}),
    );
    // no dry run without the service: the verdict is empty, as on an ECC send
    assert_eq!(r.verdict, "", "{label}");
    r.txid
}

#[test]
#[ignore]
fn no_yellowback_pq_balances_and_sends() {
    if std::env::var("YEW_NOYB").ok().as_deref() != Some("1") {
        return;
    }
    let server = std::env::var("YEW_NOYB_SERVER").unwrap();
    let ca = std::fs::read_to_string(std::env::var("YEW_NOYB_CA").unwrap()).unwrap();
    let dir = std::env::var("YEW_NOYB_DIR").unwrap();
    let params = std::env::var("YEW_NOYB_PARAMS").unwrap();
    let dst: HashMap<String, String> = std::env::var("YEW_NOYB_DST")
        .unwrap()
        .split(',')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap();
            (k.to_string(), v.to_string())
        })
        .collect();
    std::fs::create_dir_all(format!("{dir}/w/sapling-params")).unwrap();
    for f in ["sapling-spend.params", "sapling-output.params"] {
        let _ = std::os::unix::fs::symlink(
            format!("{params}/{f}"),
            format!("{dir}/w/sapling-params/{f}"),
        );
    }
    api::init_app();
    let birthday = height() as i64;
    api::create_wallet(
        None,
        String::new(),
        Some(birthday - 1),
        NetworkId::Testnet,
        server,
        false,
        Some(ca),
        format!("{dir}/w"),
    )
    .expect("create_wallet");

    // the server offers no Yellowback service
    let st = api::status().expect("status");
    report("status", serde_json::json!(format!("{st:?}")));
    assert!(!st.yellowback.present, "{:?}", st.yellowback);

    // 1. Receive's addresses of every type, checked against the node
    let addr = |k| api::receive_address(k, false).unwrap().address;
    let t = addr(ReceiveKind::Transparent);
    let z = addr(ReceiveKind::Shielded);
    let slh = addr(ReceiveKind::PqSlh);
    let fal = addr(ReceiveKind::PqFalcon);
    assert!(
        slh.starts_with("tqs") && fal.starts_with("tqf"),
        "{slh} {fal}"
    );
    for a in [&t, &slh, &fal] {
        assert_eq!(
            cli_json(&["validateaddress", a])["isvalid"],
            Value::Bool(true),
            "{a}"
        );
    }
    report(
        "addresses",
        serde_json::json!({"ecc": t, "sapling": z, "pq_slh": slh, "pq_falcon": fal}),
    );

    // 2. fund from the node wallet: 0.3 YEC at the ECC, 0.25 at the FN-DSA-512 and 0.25 at the
    // SLH-DSA address
    let funding: Vec<String> = [(&t, "0.3"), (&fal, "0.25"), (&slh, "0.25")]
        .iter()
        .map(|(a, v)| cli(&["sendtoaddress", a, v]))
        .collect();
    let tip = mine_until(&funding);
    let b = sync_to(tip);
    report("balances_funded", bal_json(&b));
    // the defect: FN/SLH showed 0 while the node's index held the coins
    assert_eq!(b.yec_pq_falcon_zat, 25_000_000);
    assert_eq!(b.yec_pq_slh_zat, 25_000_000);
    assert_eq!(b.yec_pq_zat, 50_000_000);
    assert_eq!(b.yec_zat + b.yec_reserved_zat, 30_000_000);
    assert_eq!(node_balance(&fal), 25_000_000);
    assert_eq!(node_balance(&slh), 25_000_000);
    let sources = api::pq_sources().unwrap();
    report("pq_sources", serde_json::json!(format!("{sources:?}")));
    assert_eq!(sources.len(), 2);

    // 3. sends between the types, none of which the server can dry-run
    let yec_conf = |id: &str, _: Option<String>| api::send_yec_confirm(id.to_string());
    let pq_conf = |id: &str, ack: Option<String>| api::pq_send_confirm(id.to_string(), ack);
    let yec = |to: &str, zat: i64| {
        api::send_yec_preview(to.to_string(), zat, false, true, None)
            .map(|p| (p.preview_id, p.fee_zat, None))
    };
    let pq = |from: &str, to: &str, zat: i64| {
        api::pq_send_preview(from.to_string(), to.to_string(), zat)
            .map(|p| (p.preview_id, p.fee_zat, p.unusual_fee_ack))
    };
    // Each source pays once per block (its change is spendable once mined), so three rounds.
    let check = |round: &str, tip: u64| {
        let b = sync_to(tip);
        report(
            &format!("balances_after_{round}"),
            serde_json::json!({"app": bal_json(&b), "node_ecc_receive": node_balance(&t),
                "node_fal": node_balance(&fal), "node_slh": node_balance(&slh)}),
        );
        assert_eq!(b.yec_pq_falcon_zat, node_balance(&fal), "{round}");
        assert_eq!(b.yec_pq_slh_zat, node_balance(&slh), "{round}");
        assert_eq!(
            b.yec_pq_zat,
            b.yec_pq_falcon_zat + b.yec_pq_slh_zat,
            "{round}"
        );
        assert_eq!(b.held_count, 0, "{round}");
        b
    };
    // round 1: ECC -> FN, FN -> ECC, SLH -> this wallet's own private address
    let txids = vec![
        send(
            "ecc->pq_falcon",
            yec(&dst["pq_falcon"], 5_000_000),
            &yec_conf,
        ),
        send(
            "pq_falcon->ecc",
            pq(&fal, &dst["ecc"], 10_000_000),
            &pq_conf,
        ),
        send("pq_slh->own_sapling", pq(&slh, &z, 10_000_000), &pq_conf),
    ];
    let b = check("round_1", mine_until(&txids));
    assert_eq!(b.yec_shielded_zat, 10_000_000);
    // round 2: ECC -> SLH, SLH -> Sapling, FN -> SLH, and the private note of round 1 to FN
    // (Sapling to a post-quantum address) when the light client already counts it spendable
    let mut txids = vec![
        send("ecc->pq_slh", yec(&dst["pq_slh"], 5_000_000), &yec_conf),
        send(
            "pq_slh->sapling",
            pq(&slh, &dst["sapling"], 5_000_000),
            &pq_conf,
        ),
        send(
            "pq_falcon->pq_slh",
            pq(&fal, &dst["pq_slh"], 5_000_000),
            &pq_conf,
        ),
    ];
    let private_pq = || {
        api::private_pq_send_preview(dst["pq_falcon"].clone(), 5_000_000, true)
            .map(|p| (p.preview_id, p.fee_zat, p.unusual_fee_ack))
    };
    let mut private_sent = false;
    match private_pq() {
        Ok(p) => {
            txids.push(send("own_sapling->pq_falcon", Ok(p), &pq_conf));
            private_sent = true;
        }
        Err(e) => report(
            "deferred",
            serde_json::json!({"cell": "own_sapling->pq_falcon", "why": format!("{e:?}")}),
        ),
    }
    let mut b = check("round_2", mine_until(&txids));
    if !private_sent {
        let txids = vec![send("own_sapling->pq_falcon", private_pq(), &pq_conf)];
        b = check("round_3", mine_until(&txids));
    }
    assert!(b.yec_shielded_zat < 5_000_000);
}

/// The read-only leg (`YEW_NOYB_PHASE=restore`): restore `YEW_NOYB_WORDS` (birthday
/// `YEW_NOYB_BIRTHDAY`) against `YEW_NOYB_SERVER` / `YEW_NOYB_CA`, a server without the Yellowback
/// service, and print the balances by type and Receive's addresses; with `YEW_NOYB_EXPECT`
/// (`pq_falcon=<zat>,pq_slh=<zat>,ecc=<zat>`) they must match. Nothing is sent, no node is used:
/// this is the check against a live network (the beta2 walkthrough's web wallet on testnet-yb-fast).
#[test]
#[ignore]
fn no_yellowback_restore_balances() {
    if std::env::var("YEW_NOYB_PHASE").ok().as_deref() != Some("restore") {
        return;
    }
    let server = std::env::var("YEW_NOYB_SERVER").unwrap();
    let ca = std::fs::read_to_string(std::env::var("YEW_NOYB_CA").unwrap()).unwrap();
    let dir = std::env::var("YEW_NOYB_DIR").unwrap();
    let birthday: i64 = std::env::var("YEW_NOYB_BIRTHDAY").unwrap().parse().unwrap();
    api::init_app();
    api::create_wallet(
        Some(std::env::var("YEW_NOYB_WORDS").unwrap()),
        String::new(),
        Some(birthday),
        NetworkId::Testnet,
        server,
        false,
        Some(ca),
        format!("{dir}/r"),
    )
    .expect("create_wallet");
    let st = api::status().expect("status");
    assert!(!st.yellowback.present, "{:?}", st.yellowback);
    let addr = |k| api::receive_address(k, false).unwrap().address;
    report(
        "addresses",
        serde_json::json!({"ecc": addr(ReceiveKind::Transparent), "sapling": addr(ReceiveKind::Shielded),
            "pq_slh": addr(ReceiveKind::PqSlh), "pq_falcon": addr(ReceiveKind::PqFalcon)}),
    );
    let b = sync_to(st.tip as u64);
    report("balances", bal_json(&b));
    if let Ok(e) = std::env::var("YEW_NOYB_EXPECT") {
        for kv in e.split(',') {
            let (k, v) = kv.split_once('=').unwrap();
            let v: i64 = v.parse().unwrap();
            let got = match k {
                "pq_falcon" => b.yec_pq_falcon_zat,
                "pq_slh" => b.yec_pq_slh_zat,
                "ecc" => b.yec_zat + b.yec_reserved_zat,
                "sapling" => b.yec_shielded_zat,
                _ => panic!("unknown kind {k}"),
            };
            assert_eq!(got, v, "{k}");
        }
    }
}
