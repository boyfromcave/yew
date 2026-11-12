// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The YEW core's app API against a real regtest stack (ycash6 + lightwalletd-dd), ignored unless
//! `YEW_REAL=1`. The orchestrator (workspace `wt/scratch/yew-real/yew_real_light.py`) starts the
//! node and lightwalletd and sets:
//! `YEW_REAL_SERVER` (host:port, plaintext gRPC), `YEW_REAL_CLI` (the node's `ycash-cli` command line,
//! space separated), `YEW_REAL_DIR` (a scratch directory), `YEW_REAL_PARAMS` (the Sapling parameters).
//! Every line the test prints that starts with `REAL ` is a result.

use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;
use yew_core::api::{self, NetworkId, ReceiveKind};

fn cli(args: &[&str]) -> String {
    let pre = std::env::var("YEW_REAL_CLI").expect("YEW_REAL_CLI");
    let mut p = pre.split(' ');
    let bin = p.next().unwrap();
    let out = Command::new(bin)
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

fn mine(n: u32) -> u64 {
    cli(&["generate", &n.to_string()]);
    cli(&["getblockcount"]).parse().unwrap()
}

fn report(what: &str, v: Value) {
    println!("REAL {what} {v}");
}

/// Sync both pools until the wallet has the node's tip (a preview syncs first; its answer is not used).
fn sync_to(tip: u64) -> api::Balances {
    let start = Instant::now();
    loop {
        let _ = api::move_preview(api::MoveDirection::ToPrivate, Some(1));
        let b = api::balances().expect("balances");
        if b.sync_height as u64 >= tip && b.shielded_scanned_height as u64 >= tip {
            return b;
        }
        assert!(
            start.elapsed() < Duration::from_secs(180),
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
        "shielded_zat": b.yec_shielded_zat, "shielded_spendable_zat": b.yec_shielded_spendable_zat,
        "staged_for_mint_zat": b.yec_staged_for_mint_zat, "held": b.held_count, "yed_cents": b.yed_cents,
        "sync_height": b.sync_height,
    })
}

/// The node's view of a transparent or post-quantum address (insightexplorer's getaddressbalance).
fn node_balance(addr: &str) -> Value {
    let q = serde_json::json!({ "addresses": [addr] }).to_string();
    let pre = std::env::var("YEW_REAL_CLI").unwrap();
    let mut p = pre.split(' ');
    let bin = p.next().unwrap();
    let out = Command::new(bin)
        .args(p)
        .args(["getaddressbalance", &q])
        .output()
        .unwrap();
    if out.status.success() {
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
    } else {
        serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim() })
    }
}

fn in_mempool(txid: &str) -> bool {
    cli_json(&["getrawmempool"])
        .as_array()
        .map(|a| a.iter().any(|t| t.as_str() == Some(txid)))
        .unwrap_or(false)
}

fn mined_in(txid: &str) -> Option<String> {
    let v = cli_json(&["getrawtransaction", txid, "1"]);
    v.get("blockhash")
        .and_then(|h| h.as_str())
        .map(|s| s.to_string())
}

fn wait_mempool(txid: &str) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if in_mempool(txid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

/// A confirm call: the preview id and the unusual-fee token when one is asked.
type Confirm = dyn Fn(&str, Option<String>) -> Result<api::SendResult, api::YewError>;

/// One send: preview with `pre`, confirm with `conf` (the unusual-fee token when one is asked).
fn cell(
    label: &str,
    res: Result<(String, i64, Option<String>), api::YewError>,
    conf: &Confirm,
) -> Option<String> {
    match res {
        Err(e) => {
            report(
                "cell",
                serde_json::json!({"cell": label, "preview_error": format!("{:?}: {}", e.kind, e.message)}),
            );
            None
        }
        Ok((id, fee, ack)) => match conf(&id, ack.clone()) {
            Err(e) => {
                report(
                    "cell",
                    serde_json::json!({"cell": label, "fee": fee, "ack": ack, "confirm_error": format!("{:?}: {}", e.kind, e.message)}),
                );
                None
            }
            Ok(r) => {
                let acc = wait_mempool(&r.txid);
                report(
                    "cell",
                    serde_json::json!({"cell": label, "txid": r.txid, "fee": fee, "ack": ack, "verdict": format!("{:?}", r.verdict), "accepted": acc}),
                );
                Some(r.txid)
            }
        },
    }
}

#[test]
#[ignore]
fn real_stack_addresses_sends_balances_restore() {
    if std::env::var("YEW_REAL").ok().as_deref() != Some("1") {
        return;
    }
    let server = std::env::var("YEW_REAL_SERVER").unwrap();
    let dir = std::env::var("YEW_REAL_DIR").unwrap();
    let params = std::env::var("YEW_REAL_PARAMS").unwrap();
    let mk = |sub: &str| {
        let d = format!("{dir}/{sub}");
        std::fs::create_dir_all(format!("{d}/sapling-params")).unwrap();
        for f in ["sapling-spend.params", "sapling-output.params"] {
            let _ = std::os::unix::fs::symlink(
                format!("{params}/{f}"),
                format!("{d}/sapling-params/{f}"),
            );
        }
        d
    };
    api::init_app();
    let d1 = mk("w1");
    let created = api::create_wallet(
        None,
        String::new(),
        Some(1),
        NetworkId::Regtest,
        server.clone(),
        true,
        None,
        d1.clone(),
    )
    .expect("create_wallet");
    let words = created.seed_words.clone().expect("generated words");

    // 1. addresses of every type, checked against the node
    let t = api::receive_address(ReceiveKind::Transparent, false)
        .unwrap()
        .address;
    let z = api::receive_address(ReceiveKind::Shielded, false)
        .unwrap()
        .address;
    let slh = api::receive_address(ReceiveKind::PqSlh, false)
        .unwrap()
        .address;
    let fal = api::receive_address(ReceiveKind::PqFalcon, false);
    let fal = match fal {
        Ok(a) => a.address,
        Err(e) => {
            report(
                "falcon_address_error",
                serde_json::json!(format!("{:?}: {}", e.kind, e.message)),
            );
            String::new()
        }
    };
    for (k, a) in [
        ("ecc", &t),
        ("sapling", &z),
        ("pq_slh", &slh),
        ("pq_falcon", &fal),
    ] {
        let v = if k == "sapling" {
            cli_json(&["z_validateaddress", a])
        } else {
            cli_json(&["validateaddress", a])
        };
        let app = api::validate_address(NetworkId::Regtest, a.to_string());
        report(
            "address",
            serde_json::json!({"kind": k, "address": a, "len": a.len(), "node": v, "app": format!("{app:?}")}),
        );
    }
    let birthday = cli(&["getblockcount"]).parse::<u64>().unwrap();

    // 2. fund: 3 x 1 YEC at the ECC and each PQ address, 3 x 1 YEC notes
    let fund = cli(&["getnewaddress"]);
    for _ in 0..3 {
        for a in [&t, &slh, &fal] {
            if !a.is_empty() {
                cli(&["sendtoaddress", a, "1"]);
            }
        }
        cli(&["sendtoaddress", &fund, "1.1"]);
    }
    mine(1);
    // the 6.x wallet learns of a block asynchronously: wait until the funding coins are confirmed
    let start = Instant::now();
    while cli(&["z_getbalance", &fund, "1"])
        .parse::<f64>()
        .unwrap_or(0.0)
        < 3.0
    {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "funding coins not confirmed in the node wallet"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    for _ in 0..3 {
        let to = serde_json::json!([{ "address": z, "amount": 1 }]).to_string();
        let opid = cli(&[
            "z_sendmany",
            &fund,
            &to,
            "1",
            "null",
            "AllowFullyTransparent",
        ]);
        let start = Instant::now();
        loop {
            let r = cli_json(&["z_getoperationresult", &format!("[\"{opid}\"]")]);
            if r.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
                report("fund_z", r);
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(120));
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    let tip = mine(1);
    let b = sync_to(tip);
    report("balances_funded", bal_json(&b));
    for (k, a) in [("ecc", &t), ("pq_slh", &slh), ("pq_falcon", &fal)] {
        report(
            "node_balance",
            serde_json::json!({"label": "funded", "kind": k, "node": node_balance(a)}),
        );
    }
    report(
        "pq_sources",
        serde_json::json!(format!("{:?}", api::pq_sources())),
    );

    // 3. the matrix through the app API
    let dst: Vec<(String, String)> = std::env::var("YEW_REAL_DST")
        .unwrap()
        .split(',')
        .map(|kv| {
            let mut i = kv.splitn(2, '=');
            (i.next().unwrap().to_string(), i.next().unwrap().to_string())
        })
        .collect();
    let yec_conf = |id: &str, _ack: Option<String>| api::send_yec_confirm(id.to_string());
    let pq_conf = |id: &str, ack: Option<String>| api::pq_send_confirm(id.to_string(), ack);
    let mut amount = 1_000_000i64;
    let mut txids = vec![];
    for (dk, da) in &dst {
        amount += 10_000;
        // automatic funding (the app's default: privacy first for a private recipient)
        let p = api::send_yec_preview(da.clone(), amount, false, None)
            .map(|p| {
                report("preview", serde_json::json!({"cell": format!("auto->{dk}"), "funding": format!("{:?}", p.funding), "fee": p.fee_zat, "change": p.change_zat, "inputs": p.inputs}));
                (p.preview_id, p.fee_zat, None)
            });
        txids.extend(cell(&format!("auto->{dk}"), p, &yec_conf));
        for (sk, sa) in [("pq_slh", &slh), ("pq_falcon", &fal)] {
            if sa.is_empty() {
                continue;
            }
            amount += 10_000;
            let p = api::pq_send_preview(sa.to_string(), da.clone(), amount).map(|p| {
                report("preview", serde_json::json!({"cell": format!("{sk}->{dk}"), "fee": p.fee_zat, "change": p.change_zat, "size": p.size_bytes, "ack": p.unusual_fee_ack, "fee_note": p.fee_note}));
                (p.preview_id, p.fee_zat, p.unusual_fee_ack)
            });
            txids.extend(cell(&format!("{sk}->{dk}"), p, &pq_conf));
        }
        if dk.starts_with("pq") {
            amount += 10_000;
            let p = api::private_pq_send_preview(da.clone(), amount, true).map(|p| {
                report("preview", serde_json::json!({"cell": format!("sapling->{dk}"), "fee": p.fee_zat, "change": p.change_zat, "size": p.size_bytes, "ack": p.unusual_fee_ack}));
                (p.preview_id, p.fee_zat, p.unusual_fee_ack)
            });
            txids.extend(cell(&format!("sapling->{dk}"), p, &pq_conf));
        }
        let tip = mine(1);
        for x in &txids {
            report(
                "mined",
                serde_json::json!({"txid": x, "block": mined_in(x)}),
            );
        }
        txids.clear();
        let b = sync_to(tip);
        report(
            "balances",
            serde_json::json!({"after": dk, "app": bal_json(&b),
            "node_ecc": node_balance(&t), "node_slh": node_balance(&slh), "node_falcon": node_balance(&fal)}),
        );
    }
    // move to public and to private (the app's Move)
    for dir in [api::MoveDirection::ToPublic, api::MoveDirection::ToPrivate] {
        let p = api::move_preview(dir, Some(20_000_000)).map(|p| (p.preview_id, p.fee_zat, None));
        let label = format!("move {dir:?}");
        let mc = |id: &str, _a: Option<String>| api::move_confirm(id.to_string());
        let x = cell(&label, p, &mc);
        let tip = mine(1);
        if let Some(x) = x {
            report(
                "mined",
                serde_json::json!({"txid": x, "block": mined_in(&x)}),
            );
        }
        report(
            "balances",
            serde_json::json!({"after": label, "app": bal_json(&sync_to(tip))}),
        );
    }
    let tip = mine(1);
    let before = sync_to(tip);
    report("balances_before_restore", bal_json(&before));

    // 5. restore from the seed in a new directory
    let d2 = mk("w2");
    api::lock();
    let restored = api::create_wallet(
        Some(words),
        String::new(),
        Some(birthday as i64 - 1),
        NetworkId::Regtest,
        server,
        true,
        None,
        d2,
    );
    report(
        "restore_created",
        serde_json::json!(format!("{:?}", restored.map(|c| c.wallet_id))),
    );
    // the restored wallet must find its post-quantum keys again: issue them in the same order
    let _ = api::receive_address(ReceiveKind::PqSlh, false);
    let _ = api::receive_address(ReceiveKind::PqFalcon, false);
    let after = sync_to(tip);
    report("balances_after_restore", bal_json(&after));
}

/// The pre-Canopy leg (`scripts/real-run/yew_real_precanopy.py`, real-stack run YEW-REAL finding
/// 1): `YEW_REAL_PHASE=address` prints the Sapling address of the fixed regtest phrase (no
/// stack); the harness has the node pay notes to it before Canopy (pre-ZIP-212 notes), then
/// with `YEW_REAL_PHASE=spend` the app restores the phrase and spends those notes: private ->
/// post-quantum twice (the hybrid builder) and private -> private (the store's builder).
#[test]
#[ignore]
fn real_stack_pre_canopy_notes() {
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let Ok(phase) = std::env::var("YEW_REAL_PHASE") else {
        return;
    };
    if phase == "address" {
        let a = yew_core::shielded_keys::SaplingAccount::from_mnemonic(
            PHRASE,
            "",
            yew_core::params::Network::Regtest,
        )
        .unwrap();
        report("zaddr", serde_json::json!(a.default_address().1));
        return;
    }
    let server = std::env::var("YEW_REAL_SERVER").unwrap();
    let dir = std::env::var("YEW_REAL_DIR").unwrap();
    let params = std::env::var("YEW_REAL_PARAMS").unwrap();
    let d = format!("{dir}/pre");
    std::fs::create_dir_all(format!("{d}/sapling-params")).unwrap();
    for f in ["sapling-spend.params", "sapling-output.params"] {
        let _ =
            std::os::unix::fs::symlink(format!("{params}/{f}"), format!("{d}/sapling-params/{f}"));
    }
    let dst: std::collections::HashMap<String, String> = std::env::var("YEW_REAL_DST")
        .unwrap()
        .split(',')
        .map(|kv| {
            let mut i = kv.splitn(2, '=');
            (i.next().unwrap().to_string(), i.next().unwrap().to_string())
        })
        .collect();
    api::init_app();
    api::create_wallet(
        Some(PHRASE.to_string()),
        String::new(),
        Some(100),
        NetworkId::Regtest,
        server,
        true,
        None,
        d,
    )
    .expect("create_wallet");
    let tip = cli(&["getblockcount"]).parse().unwrap();
    report("balances_pre", bal_json(&sync_to(tip)));
    let pq_conf = |id: &str, ack: Option<String>| api::pq_send_confirm(id.to_string(), ack);
    let yec_conf = |id: &str, _ack: Option<String>| api::send_yec_confirm(id.to_string());
    let sends: [(&str, &str, i64); 3] = [
        ("sapling->pq_slh", "pq_slh", 1_100_000),
        ("sapling->sapling", "sapling", 600_000),
        ("sapling->pq_falcon", "pq_falcon", 1_200_000),
    ];
    for (label, dk, amount) in sends {
        let to = dst[dk].clone();
        let r = if dk.starts_with("pq") {
            let p = api::private_pq_send_preview(to, amount, true).map(|p| {
                report("preview", serde_json::json!({"cell": label, "fee": p.fee_zat, "change": p.change_zat, "inputs": p.inputs, "size": p.size_bytes}));
                (p.preview_id, p.fee_zat, p.unusual_fee_ack)
            });
            cell(label, p, &pq_conf)
        } else {
            let p = api::send_yec_preview(to, amount, false, None).map(|p| {
                report("preview", serde_json::json!({"cell": label, "funding": format!("{:?}", p.funding), "fee": p.fee_zat, "change": p.change_zat, "inputs": p.inputs}));
                (p.preview_id, p.fee_zat, None)
            });
            cell(label, p, &yec_conf)
        };
        let tip = mine(1);
        if let Some(x) = r {
            report(
                "mined",
                serde_json::json!({"cell": label, "txid": x, "block": mined_in(&x)}),
            );
        }
        report(
            "balances",
            serde_json::json!({"after": label, "app": bal_json(&sync_to(tip))}),
        );
    }
}
