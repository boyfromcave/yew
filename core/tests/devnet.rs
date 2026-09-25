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
//! - `w4_mint_resume_lapse_redeem_import_and_claim` (plan §7 W4): the same armed devnet
//!   (`scripts/devnet-w4.sh`): a full two-step mint from a YEW wallet; the wallet file closed
//!   and reopened mid-mint (kill-and-resume); the owner key of a vault imported into node 5
//!   (plan §8.6, open question 6); a mint left unfinished until its window lapses, then swept;
//!   a bundle with one mutated signature refused; a redeem after `lockHeight`; a −80 % price
//!   shock and the claim of node 0's vault by the YEW wallet (the liquidator persona).
//!
//! Run: `YEW_DEVNET=1 cargo test -p yew-core --test devnet -- --ignored --nocapture [w1_|w2_|w4_]`.

use std::cell::RefCell;
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
    /// The USD price every pool block re-quotes (`price N`), changed by a shock.
    price: RefCell<String>,
}

impl Devnet {
    fn new(dir_default: &str, portseed_default: &str) -> Devnet {
        let home = std::env::var("HOME").unwrap_or_default();
        Devnet {
            dir: env_or("YELLOWBACK_DEVNET_DIR", format!("{home}/{dir_default}")),
            portseed: env_or("YELLOWBACK_DEVNET_PORTSEED", portseed_default.into()),
            price: RefCell::new("50".into()),
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

    /// `ycash-cli` on node `n`, returning the error text instead of panicking (probes whose
    /// failure is a finding, not a defect).
    fn node_try(&self, n: usize, args: &[&str]) -> String {
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
        let ns = n.to_string();
        let out = Command::new(&py)
            .arg(&tool)
            .args(["cli", "--node", &ns, "--"])
            .args(args)
            .env("YELLOWBACK_DEVNET_DIR", &self.dir)
            .env("YELLOWBACK_DEVNET_PORTSEED", &self.portseed)
            .output()
            .unwrap();
        let text = if out.status.success() {
            String::from_utf8_lossy(&out.stdout).to_string()
        } else {
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        };
        text.split_whitespace().collect::<Vec<_>>().join(" ")
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
        let price = self.price.borrow().clone();
        self.run(&["price", &price]);
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

/// A pool block after `txid` reached the pools, then wait for lightwalletd. Returns the height.
async fn confirm(dn: &Devnet, c: &mut CompactClient, txid: &str) -> u64 {
    dn.wait_mempool(txid);
    let h = dn.mine_pool();
    wait_for_height(c, h).await
}

fn mint_state(w: &Wallet, id: i64) -> yew_core::store::MintState {
    w.store.mint(id).unwrap().unwrap().state
}

#[tokio::test]
#[ignore = "needs the ARMED regtest devnet (scripts/devnet-w4.sh) and YEW_DEVNET=1"]
async fn w4_mint_resume_lapse_redeem_import_and_claim() {
    use yew_core::build::mint::{self, window_open};
    use yew_core::bundle;
    use yew_core::params::{CARRIER_VALUE, REF_WINDOW};
    use yew_core::store::MintState;
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
    let (mut v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .expect("probe");
    assert!(availability.usable(), "{availability:?}");
    let (ref_lag, grace) = match &availability {
        Availability::Present { info, .. } => {
            let p = info.params.as_ref().unwrap();
            (p.ref_lag as u32, p.grace as u32)
        }
        Availability::Absent => unreachable!(),
    };
    // Warm the price windows (as W2).
    loop {
        let yb = v.client_mut().unwrap();
        let p = yb.price(0).await.unwrap();
        let at_ref = yb
            .price((p.height as u32).saturating_sub(ref_lag))
            .await
            .unwrap();
        if p.p_mint > 0 && at_ref.p_mint > 0 {
            break;
        }
        println!(
            "warming the price windows: tip {:?}, ref {:?}",
            p.fill, at_ref.fill
        );
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
    }
    // The block hash the relay serves is the node's, in internal order (bundle verification).
    let tip_now = c.latest_height().await.unwrap();
    let node_hash = dn.node(0, &["getblockhash", &tip_now.to_string()]);
    assert_eq!(
        txid_hex(&c.block_hash(tip_now).await.unwrap()),
        node_hash,
        "GetBlock.hash reversed equals getblockhash"
    );

    let dir = std::env::temp_dir().join(format!("yew-devnet-w4-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let birthday = info.block_height.saturating_sub(1);
    let (mut a, mnemonic) = fresh_wallet(&dir, "a", birthday);
    let a_path = dir.join("a.sqlite").to_string_lossy().to_string();

    // 0. Fund A as several coins (a two-step spends one and its change is unconfirmed for a
    //    block; role plan F-3), then sync.
    let addr = a.receive_address(true).unwrap();
    for amount in ["15", "10", "8", "5"] {
        let t = dn.node(0, &["sendtoaddress", &addr.address_s, amount]);
        assert_eq!(t.len(), 64, "{t}");
    }
    let addr2 = a.receive_address(true).unwrap();
    let t = dn.node(0, &["sendtoaddress", &addr2.address_s, "2"]);
    confirm(&dn, &mut c, &t).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yec.0 + r.yec.1, 40 * 100_000_000, "{r:?}");

    // 1. The full two-step mint of $100.00 for 48 blocks.
    let est = a.mint_estimate(&mut v, 10_000, 48).await.unwrap();
    println!("estimate: {est:?}");
    assert!(est.affordable() && est.armed && !est.bundle_seqs.is_empty());
    assert_eq!(est.claim_height, est.lock_height + grace);
    let id1 = a
        .mint_start(&mut c, &mut v, 10_000, 48, r.tip, r.branch_id)
        .await
        .unwrap();
    let m1 = a.store.mint(id1).unwrap().unwrap();
    assert_eq!(m1.state, MintState::CarrierSent);
    assert_eq!(m1.expiry_height, m1.ref_height + REF_WINDOW);
    assert!(
        !m1.attest_payee.is_empty() && !m1.payee.is_empty(),
        "{m1:?}"
    );
    let carrier1 = txid_hex(&m1.carrier_txid);
    // The carrier is a P2SH of CARRIER_VALUE committing SHA256(bundle) on the node.
    let raw_c = dn.node_json(0, &["getrawtransaction", &carrier1, "1"]);
    assert_eq!(
        raw_c["vout"][0]["valueZat"].as_i64().unwrap(),
        CARRIER_VALUE
    );
    assert_eq!(
        raw_c["vout"][0]["scriptPubKey"]["type"].as_str().unwrap(),
        "scripthash"
    );
    // Finishing before the carrier confirmed is refused by state.
    assert!(matches!(
        a.mint_finish(&mut c, &mut v, id1, r.tip, r.branch_id)
            .await
            .unwrap_err(),
        yew_core::wallet::WalletError::Mint(mint::MintError::WrongState { .. })
    ));
    confirm(&dn, &mut c, &carrier1).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(
        r.mints_advanced
            .contains(&(id1, MintState::CarrierConfirmed)),
        "{r:?}"
    );
    let carrier_utxo = a
        .store
        .utxos()
        .unwrap()
        .into_iter()
        .find(|u| u.class == UtxoClass::Carrier)
        .expect("CARRIER class listed");
    assert_eq!(
        (carrier_utxo.value, txid_hex(&carrier_utxo.outpoint.txid)),
        (CARRIER_VALUE, carrier1.clone())
    );
    let f1 = a
        .mint_finish(&mut c, &mut v, id1, r.tip, r.branch_id)
        .await
        .unwrap();
    assert_eq!(
        (
            f1.validation.verdict.as_str(),
            f1.validation.tx_type.as_str()
        ),
        ("ok", "mint")
    );
    assert_eq!(mint_state(&a, id1), MintState::MainSent);
    let bal = a.balances().unwrap();
    assert_eq!(
        (bal.yed_cents, bal.yed_pending_cents),
        (0, 10_000),
        "PreLock: pending YED"
    );
    confirm(&dn, &mut c, &f1.txid).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(r.mints_advanced.contains(&(id1, MintState::Done)), "{r:?}");
    assert_eq!(r.yed, (10_000, 0), "the minted YED is TOKEN: {r:?}");
    let ti = v.client_mut().unwrap().tx_info(&f1.txid).await.unwrap();
    assert_eq!((ti.r#type.as_str(), ti.verdict.as_str()), ("mint", "ok"));
    assert_eq!(
        dn.node(0, &["getrawtransaction", &f1.txid]),
        keys::hex(&f1.raw),
        "the node holds our bytes"
    );
    let vaults = a.vaults().unwrap();
    assert_eq!(vaults.len(), 1, "{vaults:?}");
    let v1 = vaults[0].clone();
    assert_eq!(
        (txid_hex(&v1.txid), v1.status.as_str(), v1.minted_cents),
        (f1.txid.clone(), "ACTIVE", 10_000)
    );
    assert_eq!(
        (v1.lock_height, v1.claim_height),
        (m1.lock_height, m1.claim_height)
    );
    let utxos = a.store.utxos().unwrap();
    assert!(
        utxos
            .iter()
            .any(|u| u.class == UtxoClass::Vault && u.value == m1.collateral_zat),
        "{utxos:?}"
    );
    assert!(
        utxos.iter().all(|u| u.class != UtxoClass::Carrier),
        "the carrier was spent"
    );
    let row = a
        .store
        .history_row(&txid_from_hex(&f1.txid).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.label.as_str(), row.yed_delta),
        ("minted $100.00", 10_000)
    );
    println!(
        "mint 1 done: {} vault {}:0 lock {} claim {}",
        f1.txid, f1.txid, v1.lock_height, v1.claim_height
    );

    // 2. Kill-and-resume: start a second mint, drop the wallet, reopen the file, sync, finish.
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let id2 = a
        .mint_start(&mut c, &mut v, 10_000, 48, r.tip, r.branch_id)
        .await
        .unwrap();
    let carrier2 = txid_hex(&a.store.mint(id2).unwrap().unwrap().carrier_txid);
    drop(a);
    let mut a = Wallet::open(&a_path, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();
    assert_eq!(
        mint_state(&a, id2),
        MintState::CarrierSent,
        "the row survived the close"
    );
    confirm(&dn, &mut c, &carrier2).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(mint_state(&a, id2), MintState::CarrierConfirmed);
    let f2 = a
        .mint_finish(&mut c, &mut v, id2, r.tip, r.branch_id)
        .await
        .unwrap();
    assert_eq!(f2.validation.verdict, "ok");
    confirm(&dn, &mut c, &f2.txid).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(mint_state(&a, id2), MintState::Done);
    assert_eq!(r.yed, (20_000, 0), "{r:?}");
    let v2 = a
        .vaults()
        .unwrap()
        .into_iter()
        .find(|x| txid_hex(&x.txid) == f2.txid)
        .expect("vault 2");
    println!("mint 2 (resumed) done: {} lock {}", f2.txid, v2.lock_height);

    // 3. Plan §8.6 / open question 6: the owner key of vault 2 into node 5 with rescan.
    let owner2_addr = keys::encode_yellowback(Network::Regtest, &v2.owner_hash160);
    let wif2 = a.export_wif(&owner2_addr).unwrap();
    dn.node(5, &["importprivkey", &wif2, "yew-vault-owner", "true"]);
    let listed5 = dn.node_json(5, &["yed_listvaults"]);
    let seen5 = listed5
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["txid"].as_str() == Some(&f2.txid));
    let node5_yed = dn.node_json(5, &["yed_getbalance"])["confirmedCents"]
        .as_u64()
        .unwrap();
    let early = dn.node_try(5, &["yed_redeem", &f2.txid]);
    println!(
        "Q6: node 5 after importprivkey: yed_listvaults lists vault 2 = {seen5} yed_getbalance {node5_yed} cents; yed_redeem before lockHeight -> {early}"
    );

    // 4. Forced lapse: a third mint left unfinished until refHeight + REF_WINDOW passes, then
    //    swept. Meanwhile a bundle with one mutated signature is refused by bundle.rs.
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let id3 = a
        .mint_start(&mut c, &mut v, 10_000, 48, r.tip, r.branch_id)
        .await
        .unwrap();
    let m3 = a.store.mint(id3).unwrap().unwrap();
    let mut mutated = m3.bundle.clone();
    let off = bundle::HEADER_SIZE + 10 + 5;
    mutated[off] ^= 0x01;
    let refused = mint::verify_bundle(&mut c, v.client_mut().unwrap(), &mutated)
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("bundle-refused: signature"),
        "{refused}"
    );
    assert!(
        mint::verify_bundle(&mut c, v.client_mut().unwrap(), &m3.bundle)
            .await
            .is_ok()
    );
    confirm(&dn, &mut c, &txid_hex(&m3.carrier_txid)).await;
    let mut r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(mint_state(&a, id3), MintState::CarrierConfirmed);
    while window_open(r.tip, m3.expiry_height) {
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    }
    assert_eq!(
        mint_state(&a, id3),
        MintState::Lapsed,
        "{:?}",
        a.store.mint(id3)
    );
    assert!(matches!(
        a.mint_finish(&mut c, &mut v, id3, r.tip, r.branch_id)
            .await
            .unwrap_err(),
        yew_core::wallet::WalletError::Mint(mint::MintError::WrongState { .. })
    ));
    let (yec_before, res_before) = (r.yec.0, r.yec.1);
    let sw = a
        .mint_sweep(&mut c, &mut v, id3, r.tip, r.branch_id)
        .await
        .unwrap();
    println!(
        "sweep {} verdict {} type {:?}",
        sw.txid, sw.validation.verdict, sw.validation.tx_type
    );
    assert_eq!(mint_state(&a, id3), MintState::SweepSent);
    confirm(&dn, &mut c, &sw.txid).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(mint_state(&a, id3), MintState::Swept);
    assert_eq!(
        r.yec.0 + r.yec.1,
        yec_before + res_before + CARRIER_VALUE - FEE_ZAT,
        "the sweep returned CARRIER_VALUE − fee: {r:?}"
    );
    assert!(a
        .store
        .utxos()
        .unwrap()
        .iter()
        .all(|u| u.class != UtxoClass::Carrier));

    // 5. Redeem vault 1 after lockHeight (mine up to it on the pools).
    let mut r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    while r.tip < v1.lock_height as u64 {
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    }
    let (sent, val, p) = a
        .redeem(&mut c, &mut v, &v1.txid, r.tip, r.branch_id)
        .await
        .unwrap();
    assert_eq!(
        (val.verdict.as_str(), val.path.as_str(), val.burned),
        ("ok", "owner", 10_000)
    );
    assert_eq!(
        (p.lock_time, p.burn_cents, p.change_cents),
        (v1.lock_height, 10_000, 0)
    );
    assert_eq!(p.expiry_height, p.ref_height + REF_WINDOW);
    assert!(p.fee_zat > 0 && !p.payee.is_empty());
    confirm(&dn, &mut c, &sent).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let v1_after = a.store.vault(&v1.txid).unwrap().unwrap();
    assert_eq!(
        (v1_after.status.as_str(), v1_after.closing_txid.as_str()),
        ("CLOSED", sent.as_str())
    );
    assert_eq!(r.yed, (10_000, 0), "$100 burned, $100 left: {r:?}");
    let row = a
        .store
        .history_row(&txid_from_hex(&sent).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(row.label, "redeemed, burned $100.00");
    assert!(
        a.store
            .utxos()
            .unwrap()
            .iter()
            .any(|u| u.class == UtxoClass::Yec && u.value == p.collateral_out),
        "the collateral came back as YEC"
    );
    println!("redeem {sent}: collateral {} zat back", p.collateral_out);

    // 5b. Open question 6, second half: node 5 redeems vault 2 with the imported key.
    let mut r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    while r.tip < v2.lock_height as u64 {
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    }
    let node5_redeem = dn.node_try(5, &["yed_redeem", &f2.txid]);
    println!("Q6: yed_redeem of vault 2 from node 5 after lockHeight -> {node5_redeem}");
    let q6_ok = node5_redeem.contains("\"txid\"");
    if q6_ok {
        let t: Value = serde_json::from_str(&node5_redeem).unwrap();
        confirm(&dn, &mut c, t["txid"].as_str().unwrap()).await;
        let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
        let v2_after = a.store.vault(&v2.txid).unwrap().unwrap();
        println!(
            "Q6: vault 2 on the yew side is now {} ; A's YED {:?}",
            v2_after.status, r.yed
        );
    }

    // 6. The liquidator persona: node 0 sends $1,000 YED to A; a −80 % shock; mine past
    //    node 0's vault's claimHeight until ListClaimable names it; claim it from A.
    let target: Vec<Value> = dn
        .node_json(0, &["yed_listvaults", "ACTIVE"])
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["ownerAddress"].as_str() != Some(&owner2_addr))
        .cloned()
        .collect();
    let target = target
        .iter()
        .min_by_key(|x| x["claimHeight"].as_u64().unwrap())
        .expect("node 0 has an ACTIVE vault");
    let target_txid = target["txid"].as_str().unwrap().to_string();
    let target_cents = target["mintedCents"].as_u64().unwrap();
    let target_collateral = target["collateralZat"].as_i64().unwrap();
    let target_claim_height = target["claimHeight"].as_u64().unwrap();
    println!("claim target: {target_txid} ${:.2} collateral {target_collateral} claimHeight {target_claim_height}", target_cents as f64 / 100.0);
    let a_addr = a.receive_address(true).unwrap();
    let fund_yed = dn.node_json(
        0,
        &["yed_send", &a_addr.address_ye, &target_cents.to_string()],
    );
    confirm(&dn, &mut c, fund_yed["txid"].as_str().unwrap()).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(r.yed.0 >= target_cents, "{r:?}");
    dn.run(&["price", "--shock=-80%"]);
    *dn.price.borrow_mut() = "10".into();
    let mut claimable = Vec::new();
    let mut r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let start = Instant::now();
    while claimable
        .iter()
        .all(|x: &yew_core::build::claim::Claimable| x.vault_txid != target_txid)
    {
        assert!(
            start.elapsed() < Duration::from_secs(900),
            "the vault never became claimable"
        );
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
        claimable = a.claimable(&mut v).await.unwrap();
        if r.tip % 10 == 0 {
            let p = v.client_mut().unwrap().price(0).await.unwrap();
            println!(
                "tip {} pClaim {} aClaim {} claimable {:?}",
                r.tip,
                p.p_claim,
                p.p_mint,
                claimable.iter().map(|x| &x.vault_txid).collect::<Vec<_>>()
            );
        }
    }
    let entry = claimable
        .iter()
        .find(|x| x.vault_txid == target_txid)
        .unwrap()
        .clone();
    println!("claimable: {entry:?}");
    assert!(r.tip >= target_claim_height);
    let target_id = txid_from_hex(&target_txid).unwrap();
    let idc = a
        .claim(&mut c, &mut v, &target_id, r.tip, r.branch_id)
        .await
        .unwrap();
    let mc = a.store.mint(idc).unwrap().unwrap();
    assert_eq!(
        (mc.kind, mc.cents, mc.collateral_zat),
        (
            yew_core::store::MintKind::Claim,
            target_cents,
            target_collateral
        )
    );
    confirm(&dn, &mut c, &txid_hex(&mc.carrier_txid)).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(mint_state(&a, idc), MintState::CarrierConfirmed);
    let (yed_before, yec_before) = (r.yed.0, r.yec.0 + r.yec.1);
    let fc = a
        .mint_finish(&mut c, &mut v, idc, r.tip, r.branch_id)
        .await
        .unwrap();
    assert_eq!(
        (
            fc.validation.verdict.as_str(),
            fc.validation.path.as_str(),
            fc.validation.tx_type.as_str()
        ),
        ("ok", "claim", "redeem")
    );
    assert_eq!(
        fc.validation.burned,
        target_cents as i64 + fc.validation.yed_in - fc.validation.yed_out - target_cents as i64
    );
    let (ctx, _) = Transaction::parse(&fc.raw).unwrap();
    assert_eq!(ctx.lock_time as u64, target_claim_height);
    assert_eq!(
        ctx.vin[0].prevout,
        OutPoint {
            txid: target_id,
            n: 0
        }
    );
    assert!(script::parse_carrier_script_sig(&ctx.vin[ctx.vin.len() - 1].script_sig).is_some());
    confirm(&dn, &mut c, &fc.txid).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(mint_state(&a, idc), MintState::Done);
    let node_vault = dn.node_json(0, &["yed_getvault", &target_txid]);
    assert_eq!(
        node_vault["status"].as_str().unwrap(),
        "CLAIMED",
        "{node_vault}"
    );
    assert_eq!(node_vault["closingTxid"].as_str().unwrap(), fc.txid);
    let ti = v.client_mut().unwrap().tx_info(&fc.txid).await.unwrap();
    assert_eq!(
        (ti.r#type.as_str(), ti.path.as_str(), ti.verdict.as_str()),
        ("redeem", "claim", "ok")
    );
    assert!(
        r.yed.0 < yed_before,
        "the debt was burned: {yed_before} -> {}",
        r.yed.0
    );
    assert!(
        r.yec.0 + r.yec.1 > yec_before + target_collateral / 2,
        "the collateral came to A: {yec_before} -> {}",
        r.yec.0 + r.yec.1
    );
    let row = a
        .store
        .history_row(&txid_from_hex(&fc.txid).unwrap())
        .unwrap()
        .unwrap();
    assert!(row.label.starts_with("claimed vault"), "{row:?}");
    println!(
        "W4 devnet acceptance ok: mint {} / resumed {} / lapsed+swept {} / redeem {sent} / claim {} (Q6 node-5 redeem ok = {q6_ok})",
        f1.txid, f2.txid, sw.txid, fc.txid
    );
    let _ = std::fs::remove_dir_all(&dir);
}
