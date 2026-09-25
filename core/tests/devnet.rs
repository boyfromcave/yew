//! Devnet acceptance (plan §6.3), ignored unless `YEW_DEVNET=1`.
//!
//! - `w1_yec_round_trip_and_restore` (plan §7 W1): the W1 devnet (`scripts/devnet-w1.sh`,
//!   `~/yb-devnet-w1`, portseed 57, lightwalletd `127.0.0.1:9167`).
//! - `w2_yed_tokens_transfer_gate_and_key_round_trip` (plan §7 W2): the ARMED devnet
//!   (`scripts/devnet-w2.sh`, `~/yb-devnet-w0c`, portseed 9, lightwalletd `--yellowback` on
//!   `127.0.0.1:9267`). The armed devnet has no heartbeat: every block is mined on a pool node
//!   (2-4, round-robin, one block per call, after the transaction reached that pool's mempool);
//!   node 0's untagged blocks would empty the price windows and the mint would fail
//!   `mintpol-no-price`.
//!
//! Environment (defaults match the scripts): `YEW_DEVNET=1` to run; `YEW_DEVNET_SERVER`;
//! `YELLOWBACK_DEVNET_DIR`, `YELLOWBACK_DEVNET_PORTSEED`; `YEW_DEVNET_TOOL`
//! (`<workspace>/ycash-dd/contrib/yellowback/devnet/yellowback-devnet`), `YEW_DEVNET_PYTHON`
//! (`<workspace>/.venv/bin/python`), where `<workspace>` is `yew/..`.
//!
//! Run: `YEW_DEVNET=1 cargo test -p yew-core --test devnet -- --ignored --nocapture [w1_|w2_]`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use yew_core::build::{yec_send, yed_transfer};
use yew_core::coins::{self, UtxoClass};
use yew_core::coinselect;
use yew_core::gate::{self, GateError, Validator};
use yew_core::keys;
use yew_core::net::{Availability, CompactClient, Server, YellowbackClient};
use yew_core::params::{reserve_zat, Network, FEE_ZAT, MAX_INPUTS, MIN_OUTPUT_CENTS, TOKEN_VALUE};
use yew_core::script;
use yew_core::sync::sync;
use yew_core::tx::{txid_from_hex, txid_hex, OutPoint, Transaction};
use yew_core::wallet::Wallet;

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn env_or(k: &str, d: String) -> String {
    std::env::var(k).unwrap_or(d)
}

/// A devnet's location: directory and portseed defaults, overridden by the environment.
struct Devnet {
    dir: String,
    portseed: String,
}

impl Devnet {
    fn new(dir_default: &str, portseed_default: &str) -> Devnet {
        let home = std::env::var("HOME").unwrap_or_default();
        Devnet {
            dir: env_or("YELLOWBACK_DEVNET_DIR", format!("{home}/{dir_default}")),
            portseed: env_or("YELLOWBACK_DEVNET_PORTSEED", portseed_default.into()),
        }
    }

    /// `yellowback-devnet <args>`; returns stdout trimmed (quotes stripped).
    fn run(&self, args: &[&str]) -> String {
        let py = env_or(
            "YEW_DEVNET_PYTHON",
            workspace()
                .join(".venv/bin/python")
                .to_string_lossy()
                .into(),
        );
        let tool = env_or(
            "YEW_DEVNET_TOOL",
            workspace()
                .join("ycash-dd/contrib/yellowback/devnet/yellowback-devnet")
                .to_string_lossy()
                .into(),
        );
        let out = Command::new(&py)
            .arg(&tool)
            .args(args)
            .env("YELLOWBACK_DEVNET_DIR", &self.dir)
            .env("YELLOWBACK_DEVNET_PORTSEED", &self.portseed)
            .output()
            .unwrap_or_else(|e| panic!("cannot run {py} {tool}: {e}"));
        assert!(
            out.status.success(),
            "yellowback-devnet {args:?} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .trim_matches('"')
            .to_string()
    }

    /// `ycash-cli` on node `n` through the devnet tool.
    fn node(&self, n: usize, args: &[&str]) -> String {
        let ns = n.to_string();
        let mut a = vec!["cli", "--node", &ns, "--"];
        a.extend_from_slice(args);
        self.run(&a)
    }

    /// `ycash-cli` on node `n`, parsed as JSON.
    fn node_json(&self, n: usize, args: &[&str]) -> Value {
        let s = self.node(n, args);
        serde_json::from_str(&s).unwrap_or_else(|e| panic!("node{n} {args:?}: not json ({e}): {s}"))
    }

    /// Mine one block on the next pool node (2, 3, 4 round-robin), after re-quoting the pools
    /// (`price 50`: a pool whose quote has gone stale tags its block `signal` only, and the
    /// price windows then drain — the block must carry a `quote` tag to keep `pMint` defined).
    /// The tool syncs every node before returning.
    fn mine_pool(&self) -> u64 {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        self.run(&["price", "50"]);
        let pool = 2 + NEXT.fetch_add(1, Ordering::SeqCst) % 3;
        let out = self.run(&["mine", "1", &pool.to_string()]);
        out.rsplit("-> ").next().unwrap().trim().parse().unwrap()
    }

    /// Wait until every pool's mempool holds `txid` (a `generate` before it arrives would mine
    /// a block without it; mapping.md §15).
    fn wait_mempool(&self, txid: &str) {
        let start = Instant::now();
        loop {
            let all = (2..5).all(|n| {
                self.node_json(n, &["getrawmempool"])
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t.as_str() == Some(txid))
            });
            if all {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "{txid} never reached the pools"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

async fn wait_for_height(c: &mut CompactClient, at_least: u64) -> u64 {
    let start = Instant::now();
    loop {
        let h = c.latest_height().await.unwrap();
        if h >= at_least {
            // lightwalletd ingests the block a moment after the node reports it, and the
            // node's Yellowback index a moment after that.
            tokio::time::sleep(Duration::from_millis(1500)).await;
            return h;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "lightwalletd did not reach height {at_least}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore = "needs the W1 regtest devnet (scripts/devnet-w1.sh) and YEW_DEVNET=1"]
async fn w1_yec_round_trip_and_restore() {
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return;
    }
    let dn = Devnet::new("yb-devnet-w1", "57");
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:9167".into()), true).unwrap();
    let channel = server.connect().await.expect("connect to lightwalletd");
    let mut c = CompactClient::from_channel(channel.clone());
    let (mut v, _) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .unwrap();
    let info = c.lightd_info_for(Network::Regtest).await.unwrap();
    let dir = std::env::temp_dir().join(format!("yew-devnet-w1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mnemonic = keys::generate_mnemonic(12).unwrap();
    let birthday = info.block_height.saturating_sub(1);
    let path = dir.join("a.sqlite").to_string_lossy().to_string();
    let mut w = Wallet::open(&path, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();

    // Empty wallet syncs to zero.
    let r = sync(&mut w, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yec, (0, 0));
    assert_eq!(r.branch_id, info.branch_id);

    // Fund from node 0, mine, sync.
    let addr = w.receive_address(false).unwrap();
    println!("funding {} ({})", addr.address_ye, addr.address_s);
    let fund_txid = dn.node(0, &["sendtoaddress", &addr.address_s, "1.5"]);
    assert_eq!(fund_txid.len(), 64, "sendtoaddress txid: {fund_txid}");
    dn.run(&["mine", "1"]);
    let h = c.latest_height().await.unwrap();
    wait_for_height(&mut c, h.max(info.block_height + 1)).await;
    let r = sync(&mut w, &mut c, v.client_mut()).await.unwrap();
    let funded = 150_000_000i64;
    assert_eq!(r.yec.0 + r.yec.1, funded, "balance after funding: {r:?}");
    assert!(
        r.yec.1 <= reserve_zat(),
        "fee reserve never exceeds its target: {r:?}"
    );
    assert_eq!(
        r.yec.1, 0,
        "one coin larger than the reserve is not reserved"
    );
    let hist = w.store.history().unwrap();
    assert!(
        hist.iter()
            .any(|x| txid_hex(&x.txid) == fund_txid && x.yec_delta == funded && !x.pending),
        "{hist:?}"
    );

    // Send half back to node 0.
    let dest = dn.node(0, &["getnewaddress"]);
    let send = 50_000_000i64;
    let p = yec_send::build_yec_send(&w, &dest, send, false, r.tip, r.branch_id).unwrap();
    assert_eq!(p.fee, FEE_ZAT);
    let txid = yec_send::broadcast(&w, &mut c, &mut v, &p)
        .await
        .expect("broadcast accepted by the node");
    println!("sent {txid}");
    assert_eq!(
        w.store.locks().unwrap().len(),
        p.inputs.len(),
        "inputs locked while pending"
    );
    let (avail, _) = coins::yec_balances(&w.spendable_utxos().unwrap());
    assert!(avail < funded - send, "locked inputs are not spendable");
    dn.run(&["mine", "1"]);
    let h = c.latest_height().await.unwrap();
    wait_for_height(&mut c, h + 1).await;
    let r = sync(&mut w, &mut c, v.client_mut()).await.unwrap();
    let expected = funded - send - FEE_ZAT;
    assert_eq!(r.yec.0 + r.yec.1, expected, "balance after send: {r:?}");
    assert!(
        w.store.locks().unwrap().is_empty(),
        "locks released on confirmation"
    );
    assert!(w.store.pending_txs().unwrap().is_empty());
    let hist = w.store.history().unwrap();
    let row = hist
        .iter()
        .find(|x| txid_hex(&x.txid) == txid)
        .expect("send in history");
    assert!(!row.pending && row.height > 0);
    assert_eq!(row.yec_delta, -(send + FEE_ZAT));
    let got = dn.node(0, &["getreceivedbyaddress", &dest, "1"]);
    assert_eq!(
        got.parse::<f64>().unwrap(),
        0.5,
        "node 0 received 0.5 YEC at {dest}"
    );
    let raw_on_node = dn.node(0, &["getrawtransaction", &txid]);
    assert_eq!(
        raw_on_node,
        keys::hex(&p.raw),
        "the node holds exactly the bytes we built"
    );

    // Restore from seed into a fresh file: same addresses, same balance.
    let path2 = dir.join("b.sqlite").to_string_lossy().to_string();
    let mut w2 = Wallet::open(&path2, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();
    let r2 = sync(&mut w2, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r2.yec, r.yec, "restore reproduces the balance");
    assert_eq!(
        w2.receive_address(false).unwrap().index,
        w.receive_address(false).unwrap().index
    );
    assert_eq!(w2.store.utxos().unwrap(), w.store.utxos().unwrap());
    let wif = w.export_wif(&addr.address_ye).unwrap();
    assert_eq!(
        keys::decode_wif(Network::Regtest, &wif).unwrap().hash160,
        addr.hash160
    );
    println!("W1 devnet round trip ok: funded {funded}, sent {send}, final {expected}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fresh wallet file with a fresh mnemonic in `dir`.
fn fresh_wallet(dir: &std::path::Path, name: &str, birthday: u64) -> (Wallet, String) {
    let mnemonic = keys::generate_mnemonic(12).unwrap();
    let path = dir
        .join(format!("{name}.sqlite"))
        .to_string_lossy()
        .to_string();
    (
        Wallet::open(&path, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap(),
        mnemonic,
    )
}

/// Node `n`'s spendable YED coins as `(outpoint, cents)` from `yed_listunspent` (the wallet's
/// own tokens; `locked` is the wallet layer's own lock, `spentUnconfirmed` excludes them).
fn node_tokens(dn: &Devnet, n: usize) -> Vec<(OutPoint, u64)> {
    dn.node_json(n, &["yed_listunspent"])
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| !t["spentUnconfirmed"].as_bool().unwrap_or(false))
        .map(|t| {
            (
                OutPoint {
                    txid: txid_from_hex(t["txid"].as_str().unwrap()).unwrap(),
                    n: t["vout"].as_u64().unwrap() as u32,
                },
                t["cents"].as_u64().unwrap(),
            )
        })
        .collect()
}

/// The node's canonical order of its coins (`RankedCoins`): `(cents, txid, vout)`.
fn ranked(mut coins: Vec<(OutPoint, u64)>) -> Vec<(OutPoint, u64)> {
    coins.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then(a.0.txid.cmp(&b.0.txid))
            .then(a.0.n.cmp(&b.0.n))
    });
    coins
}

/// A tiny xorshift so the random targets need no crate.
struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x % n
    }
}

/// Compare `coinselect` with `yed_estimatesend` on node `n` for `count` random targets over
/// the node's current coin set. Returns the number of comparisons made.
fn compare_estimatesend(dn: &Devnet, n: usize, rng: &mut Rng, count: usize) -> usize {
    let coins = ranked(node_tokens(dn, n));
    assert!(!coins.is_empty(), "node{n} holds no spendable YED");
    let cents: Vec<i64> = coins.iter().map(|c| c.1 as i64).collect();
    let total: i64 = cents.iter().sum();
    let floor = MIN_OUTPUT_CENTS as i64;
    let mut done = 0;
    for _ in 0..count {
        // Targets cluster around the coins and their sums so the band cases come up often.
        let target = match rng.below(4) {
            0 => floor + rng.below((total - floor).max(1) as u64) as i64,
            1 => {
                let c = cents[rng.below(cents.len() as u64) as usize];
                (c - rng.below(floor as u64) as i64).max(floor)
            }
            2 => {
                let c = cents[rng.below(cents.len() as u64) as usize];
                (c + rng.below(floor as u64) as i64).min(total)
            }
            _ => (total - rng.below(floor as u64) as i64).max(floor),
        };
        let ours = coinselect::select_floor_aware(&cents, target, floor, MAX_INPUTS, false);
        let node = dn.node_json(n, &["yed_estimatesend", &target.to_string()]);
        assert_eq!(
            node["workable"].as_bool().unwrap(),
            ours.ok,
            "target {target}: workable {node}"
        );
        assert_eq!(
            node["stage"].as_str().unwrap(),
            ours.stage.name(),
            "target {target}: stage {node}"
        );
        let node_inputs: Vec<(String, u64)> = node["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    i["txid"].as_str().unwrap().to_string(),
                    i["vout"].as_u64().unwrap(),
                )
            })
            .collect();
        let our_inputs: Vec<(String, u64)> = ours
            .inputs
            .iter()
            .map(|&i| (txid_hex(&coins[i].0.txid), coins[i].0.n as u64))
            .collect();
        assert_eq!(
            node_inputs, our_inputs,
            "target {target}: inputs input-for-input {node}"
        );
        assert_eq!(
            node["selectedCents"].as_i64().unwrap_or(0),
            ours.selected,
            "target {target}: selected"
        );
        assert_eq!(
            node["changeCents"].as_i64().unwrap_or(0),
            ours.change,
            "target {target}: change"
        );
        if !ours.ok {
            let alt = coinselect::nearest_workable(&cents, target, floor, MAX_INPUTS);
            let err = node["error"].as_str().unwrap();
            assert_eq!(
                err == "insufficient-yed",
                ours.insufficient,
                "target {target}: error {err}"
            );
            assert_eq!(
                node["alternatives"]["below"].as_i64(),
                alt.below,
                "target {target}: below {node}"
            );
            assert_eq!(
                node["alternatives"]["above"].as_i64(),
                alt.above,
                "target {target}: above {node}"
            );
        }
        done += 1;
    }
    done
}

#[tokio::test]
#[ignore = "needs the ARMED regtest devnet (scripts/devnet-w2.sh) and YEW_DEVNET=1"]
async fn w2_yed_tokens_transfer_gate_and_key_round_trip() {
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return;
    }
    let dn = Devnet::new("yb-devnet-w0c", "9");
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:9267".into()), true).unwrap();
    let channel = server.connect().await.expect("connect to lightwalletd");
    let mut c = CompactClient::from_channel(channel.clone());
    let info = c.lightd_info_for(Network::Regtest).await.unwrap();

    // Contract rule 1: the service is there, rpcversion 3, enabled and active.
    let (mut v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .expect("probe");
    assert!(availability.usable(), "{availability:?}");
    match &availability {
        Availability::Present { info, .. } => assert_eq!(info.rpcversion, 3),
        Availability::Absent => panic!("the W2 devnet's lightwalletd must run --yellowback"),
    }
    // Warm the price windows: pool blocks with fresh quotes until pMint is defined at the tip
    // and at the mint's reference height (tip - refLag; MINTPOL-1 is read there, not at the
    // tip — mapping.md §15).
    let ref_lag = match &availability {
        Availability::Present { info, .. } => {
            info.params.as_ref().map(|p| p.ref_lag).unwrap_or(2) as u32
        }
        Availability::Absent => 2,
    };
    let price = loop {
        let yb = v.client_mut().unwrap();
        let p = yb.price(0).await.unwrap();
        let at_ref = yb
            .price((p.height as u32).saturating_sub(ref_lag))
            .await
            .unwrap();
        if p.p_mint > 0 && at_ref.p_mint > 0 {
            break p;
        }
        println!(
            "warming the price windows: tip {:?}, ref {:?}",
            p.fill, at_ref.fill
        );
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
    };

    let dir = std::env::temp_dir().join(format!("yew-devnet-w2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let birthday = info.block_height.saturating_sub(1);
    let (mut a, _) = fresh_wallet(&dir, "a", birthday);
    let (mut b, _) = fresh_wallet(&dir, "b", birthday);

    // 1. yed_mint on node 0 (wait=false: the carrier first, a pool block, then the MINT the
    //    wallet broadcasts on its own, then another pool block).
    let before = dn.node_json(0, &["yed_getbalance"])["confirmedCents"]
        .as_u64()
        .unwrap();
    let mint = dn.node_json(0, &["yed_mint", "100000", "48", "", "", "false"]);
    let carrier = mint["carrierTxid"].as_str().unwrap().to_string();
    assert!(mint["pending"].as_bool().unwrap());
    dn.wait_mempool(&carrier);
    dn.mine_pool();
    // The wallet finishes the mint on the next block: wait for it in the pools' mempools.
    let start = Instant::now();
    let mint_txid = loop {
        let mp = dn.node_json(2, &["getrawmempool"]);
        if let Some(t) = mp.as_array().unwrap().first() {
            break t.as_str().unwrap().to_string();
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "node 0 never broadcast the MINT"
        );
        std::thread::sleep(Duration::from_millis(300));
    };
    dn.wait_mempool(&mint_txid);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let after = dn.node_json(0, &["yed_getbalance"])["confirmedCents"]
        .as_u64()
        .unwrap();
    assert_eq!(
        after,
        before + 100_000,
        "mint of $1000.00 confirmed on node 0"
    );
    let ti = v.client_mut().unwrap().tx_info(&mint_txid).await.unwrap();
    assert_eq!((ti.r#type.as_str(), ti.verdict.as_str()), ("mint", "ok"));

    // 2. Node 0 sends YED and YEC to wallet A: nothing before confirmation, YED after.
    let a_addr = a.receive_address(false).unwrap();
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!((r.yed, r.yec), ((0, 0), (0, 0)));
    let fund = dn.node(0, &["sendtoaddress", &a_addr.address_s, "1.0"]);
    let sent = dn.node_json(0, &["yed_send", &a_addr.address_ye, "5000"]);
    let sent_txid = sent["txid"].as_str().unwrap().to_string();
    dn.wait_mempool(&fund);
    dn.wait_mempool(&sent_txid);
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(
        r.yed,
        (0, 0),
        "unconfirmed YED from another wallet is not shown: {r:?}"
    );
    assert_eq!(r.utxos, 0);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yed, (5_000, 0), "{r:?}");
    assert_eq!(r.yec.0 + r.yec.1, 100_000_000);
    assert_eq!(r.tokens, 1);
    assert_eq!(r.price_micro_usd, Some(price.p_mint));
    let utxos = a.store.utxos().unwrap();
    let token = utxos
        .iter()
        .find(|u| u.class == UtxoClass::Token)
        .expect("TOKEN class");
    assert_eq!((token.cents, token.value), (5_000, TOKEN_VALUE));
    assert!(
        utxos.iter().all(|u| u.class != UtxoClass::Held),
        "nothing held: {utxos:?}"
    );
    let row = a
        .store
        .history_row(&txid_from_hex(&sent_txid).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.label.as_str(), row.verdict.as_str(), row.yed_delta),
        ("received $50.00", "ok", 5_000)
    );
    let bal = a.balances().unwrap();
    assert_eq!((bal.yed_cents, bal.yed_pending_cents), (5_000, 0));

    // 3. A sends $12.34 to B: the change is PENDING_TOKEN until the block; then B has YED.
    let b_addr = b.receive_address(false).unwrap();
    let p = yed_transfer::build_yed_transfer(
        &a,
        &[(b_addr.address_ye.clone(), 1_234)],
        r.tip,
        r.branch_id,
    )
    .unwrap();
    assert_eq!(
        (p.change_cents, p.yed_inputs.len(), p.fee),
        (3_766, 1, FEE_ZAT)
    );
    assert!(p.yec_inputs.iter().all(|u| u.class.yec_spendable()));
    let (txid, val) = yed_transfer::broadcast(&a, &mut c, &mut v, &p)
        .await
        .expect("accepted");
    assert_eq!(
        (val.verdict.as_str(), val.burned, val.yed_in, val.yed_out),
        ("ok", 0, 5_000, 5_000)
    );
    let bal = a.balances().unwrap();
    assert_eq!(
        (bal.yed_cents, bal.yed_pending_cents),
        (0, 3_766),
        "{bal:?}"
    );
    let pending: Vec<_> = a
        .store
        .utxos()
        .unwrap()
        .into_iter()
        .filter(|u| u.class == UtxoClass::PendingToken)
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!((pending[0].cents, pending[0].outpoint.n), (3_766, 1));
    let row = a.store.history_row(&p.txid).unwrap().unwrap();
    assert!(row.pending && row.label == "sending $12.34" && row.yed_delta == -1_234);
    let r = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yed, (0, 0), "B sees nothing before the block");
    dn.wait_mempool(&txid);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let ra = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(ra.yed, (3_766, 0), "A holds the change: {ra:?}");
    assert!(a.store.locks().unwrap().is_empty());
    let row = a.store.history_row(&p.txid).unwrap().unwrap();
    assert_eq!(
        (
            row.label.as_str(),
            row.verdict.as_str(),
            row.yed_delta,
            row.pending
        ),
        ("sent $12.34", "ok", -1_234, false)
    );
    let rb = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(rb.yed, (1_234, 0), "B holds the YED: {rb:?}");
    let row = b.store.history_row(&p.txid).unwrap().unwrap();
    assert_eq!(
        (row.label.as_str(), row.yed_delta),
        ("received $12.34", 1_234)
    );
    let raw_on_node = dn.node(0, &["getrawtransaction", &txid]);
    assert_eq!(
        raw_on_node,
        keys::hex(&p.raw),
        "the node holds exactly the bytes we built"
    );

    // 4. A deliberately malformed TRANSFER (assigns more cents than its inputs carry) passes
    //    the local layer and is refused by the node's dry run, verdict in the error.
    let a_token: Vec<_> = a
        .spendable_utxos()
        .unwrap()
        .into_iter()
        .filter(|u| u.class == UtxoClass::Token)
        .collect();
    assert_eq!(a_token.len(), 1);
    let change_row = a.change_address().unwrap();
    let bad = yed_transfer::assemble(
        &a,
        &a_token,
        &[(script::p2pkh_script(&b_addr.hash160), 9_999)],
        &change_row.hash160,
        ra.tip,
        ra.branch_id,
    )
    .unwrap();
    assert!(gate::check(gate::Path::YedTransfer, &bad.raw, |op| a
        .store
        .utxo_class(op)
        .ok()
        .flatten())
    .is_ok());
    let refused = gate::confirm(&mut v, gate::Path::YedTransfer, &bad.raw, |op| {
        a.store.utxo_class(op).ok().flatten()
    })
    .await
    .unwrap_err();
    match &refused {
        GateError::Refused { verdict, valid, .. } => {
            assert_ne!(verdict, "ok");
            println!("malformed TRANSFER refused: verdict {verdict} valid {valid}");
        }
        other => panic!("expected the node's refusal, got {other}"),
    }
    assert!(refused.to_string().contains("verdict"));
    // The node itself agrees the raw bytes are bad.
    let node_says = dn.node_json(0, &["yed_validaterawtransaction", &keys::hex(&bad.raw)]);
    assert_ne!(node_says["verdict"].as_str().unwrap(), "ok");
    assert!(
        a.store.pending_txs().unwrap().is_empty(),
        "nothing was broadcast"
    );

    // 5. Sub-dollar change is refused with the alternatives; the node's estimate on the same
    //    coins (after the key import below) reports the same two amounts.
    let e = yed_transfer::build_yed_transfer(
        &a,
        &[(b_addr.address_ye.clone(), 3_716)],
        ra.tip,
        ra.branch_id,
    )
    .unwrap_err();
    let (below, above) = match e {
        yew_core::wallet::WalletError::Transfer(yed_transfer::TransferError::ChangeFloor {
            needed,
            below,
            above,
        }) => {
            assert_eq!(needed, 3_716);
            (below, above)
        }
        other => panic!("{other}"),
    };
    assert_eq!((below, above), (Some(3_666), Some(3_766)));

    // 6. coinselect.rs vs yed_estimatesend on node 0, input-for-input, 100 random targets over
    //    three coin sets (node 0's, then twice split by yed_sendmany to its own addresses).
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut comparisons = compare_estimatesend(&dn, 0, &mut rng, 34);
    for round in 0..2 {
        let mut recipients = serde_json::Map::new();
        for _ in 0..7 {
            let s = dn.node(0, &["getnewaddress"]);
            let h = keys::parse_address(Network::Regtest, &s).unwrap().hash();
            let ye = keys::encode_yellowback(Network::Regtest, &h);
            recipients.insert(
                ye,
                Value::from(100 + rng.below(if round == 0 { 3_000 } else { 900 })),
            );
        }
        let arg = Value::Object(recipients).to_string();
        let out = dn.node_json(0, &["yed_sendmany", &arg]);
        let t = out["txid"].as_str().unwrap().to_string();
        dn.wait_mempool(&t);
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        comparisons += compare_estimatesend(&dn, 0, &mut rng, 33);
    }
    assert_eq!(comparisons, 100);

    // 7. The WIF round trip (D-W-11): fund B's address with YEC too, export its key, import it
    //    on node 5 (a -yellowback wallet node; node 1 is the stock node of the armed devnet),
    //    dumpprivkey equals, balances show, the node reports the same change-floor
    //    alternatives on those coins, and node 5 can yed_send them.
    let fund_b = dn.node(0, &["sendtoaddress", &b_addr.address_s, "0.5"]);
    dn.wait_mempool(&fund_b);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let rb = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    assert_eq!((rb.yed.0, rb.yec.0 + rb.yec.1), (1_234, 50_000_000));
    let wif = b.export_wif(&b_addr.address_ye).unwrap();
    let node5_before = dn.node_json(5, &["yed_getbalance"])["confirmedCents"]
        .as_u64()
        .unwrap();
    dn.node(5, &["importprivkey", &wif, "yew-b", "true"]);
    assert_eq!(
        dn.node(5, &["dumpprivkey", &b_addr.address_s]),
        wif,
        "dumpprivkey equals export-wif"
    );
    assert_eq!(
        dn.node(5, &["getreceivedbyaddress", &b_addr.address_s, "1"])
            .parse::<f64>()
            .unwrap(),
        0.5001,
        "0.5 YEC plus the token's TOKEN_VALUE, both received at the imported address"
    );
    let node5_after = dn.node_json(5, &["yed_getbalance"])["confirmedCents"]
        .as_u64()
        .unwrap();
    assert_eq!(
        node5_after,
        node5_before + 1_234,
        "yed_getbalance on node 5 shows the imported YED"
    );
    let listed = node_tokens(&dn, 5);
    assert!(
        listed
            .iter()
            .any(|(op, cents)| *cents == 1_234 && txid_hex(&op.txid) == txid),
        "{listed:?}"
    );
    // Node 5 may hold tokens from earlier runs: pick an amount the selector refuses over its
    // actual coin set (the total minus a sub-dollar remainder) and compare the two answers.
    let b_cents: Vec<i64> = ranked(listed).iter().map(|c| c.1 as i64).collect();
    let total: i64 = b_cents.iter().sum();
    let floor = MIN_OUTPUT_CENTS as i64;
    let unworkable = (1..floor)
        .map(|k| total - k)
        .find(|&t| {
            t >= floor && !coinselect::select_floor_aware(&b_cents, t, floor, MAX_INPUTS, false).ok
        })
        .expect("a sub-dollar remainder the selector refuses");
    let est = dn.node_json(5, &["yed_estimatesend", &unworkable.to_string()]);
    let alt = coinselect::nearest_workable(&b_cents, unworkable, floor, MAX_INPUTS);
    assert!(!est["workable"].as_bool().unwrap(), "{est}");
    assert_eq!(est["error"].as_str().unwrap(), "change-floor");
    assert_eq!(
        (
            est["alternatives"]["below"].as_i64(),
            est["alternatives"]["above"].as_i64()
        ),
        (alt.below, alt.above),
        "the node reports the same alternatives on the same coins: {est}"
    );
    assert!(alt.below.is_some() && alt.above == Some(total));
    let back = dn.node_json(5, &["yed_send", &a_addr.address_ye, "1234"]);
    let back_txid = back["txid"].as_str().unwrap().to_string();
    dn.wait_mempool(&back_txid);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let rb = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(rb.yed.0, 0, "B's token left with the imported key: {rb:?}");
    let row = b
        .store
        .history_row(&txid_from_hex(&back_txid).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!((row.label.as_str(), row.yed_delta), ("sent $12.34", -1_234));
    let ra = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(ra.yed.0, 3_766 + 1_234);

    // 8. A YEC send from a wallet holding tokens spends no token (the raw bytes), and the node
    //    accepts it through the gate's remote layer.
    let dest = dn.node(0, &["getnewaddress"]);
    let p = yec_send::build_yec_send(&a, &dest, 10_000_000, false, ra.tip, ra.branch_id).unwrap();
    let (tx, _) = Transaction::parse(&p.raw).unwrap();
    let classes: HashMap<OutPoint, UtxoClass> = a
        .store
        .utxos()
        .unwrap()
        .into_iter()
        .map(|u| (u.outpoint, u.class))
        .collect();
    assert!(tx.vin.iter().all(|i| classes[&i.prevout].yec_spendable()));
    let t = yec_send::broadcast(&a, &mut c, &mut v, &p).await.unwrap();
    dn.wait_mempool(&t);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let ra = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(ra.yed.0, 5_000, "YED untouched by the YEC send");
    println!("W2 devnet acceptance ok: mint {mint_txid}, transfer {txid}, key round trip {back_txid}, {comparisons} estimatesend comparisons");
    let _ = std::fs::remove_dir_all(&dir);
}
