// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

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
//! - `q_falcon_holders_receive_send_mint_and_restore` (quantum line, TOK-PQ): an ARMED devnet whose
//!   nodes run `-pqfalconheight=<F>` (`scripts/devnet-falcon.sh`): P2PKH YED before `F`, the
//!   Falcon receive address from `F`, a transfer spending a P2PKH and a Falcon token with Falcon
//!   change, a mint whose token goes to a Falcon holder, and a restore from the seed.
//!
//! - `q_pqaddr_sq_receive_send_and_move` (quantum line, D-Q-20/D-Q-21): an ARMED devnet in the
//!   mainnet regime with lightwalletd-dd q/pqaddr (`scripts/devnet-pqaddr.sh`): YEC and YED to the
//!   wallet's Falcon holder found through its `rq…` form (YED a TOKEN row only, a `TOKEN_VALUE`
//!   output HELD, plain YEC PQ_OWNED), a YEC send to the node's `rq…`, the PQ coin moved into the
//!   wallet, and a restore from the seed.
//!
//! Run: `YEW_DEVNET=1 cargo test -p yew-core --test devnet -- --ignored --nocapture [w1_|w2_|w4_|q_falcon_|q_pqaddr_]`.

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

/// The node that funds the test wallets (`YEW_DEVNET_FUND_NODE`, default pool node 2).
fn fund_node() -> usize {
    std::env::var("YEW_DEVNET_FUND_NODE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
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
        self.wait_mempool_on(txid, &[2, 3, 4]);
    }

    /// Wait until the mempool of every node in `nodes` holds `txid` (a split network: only the
    /// nodes on one side will ever see it).
    fn wait_mempool_on(&self, txid: &str, nodes: &[usize]) {
        let start = Instant::now();
        loop {
            let all = nodes.iter().all(|&n| {
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
    dn.wait_mempool(&fund_txid);
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
    dn.wait_mempool(&txid.to_string());
    // The height before the block: read after `mine`, lightwalletd may already hold the new
    // block and `h + 1` would never come.
    let h = c.latest_height().await.unwrap();
    dn.run(&["mine", "1"]);
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

/// The `z_importpqkey` argument (`"2:<seed hex>"`) of the Falcon holder key `id` of `w` (opened
/// from `mnemonic`, no passphrase): `DerivePQSeed(seed, 2, index)` at the holder's index. Under
/// TOK-PQ YED is held by Falcon keys, so this is the YED half of the key round trip (D-W-11).
fn falcon_pqseed(w: &Wallet, mnemonic: &str, id: &yew_core::pq::PqKeyId) -> String {
    let row = w
        .own_falcon_holders()
        .unwrap()
        .remove(id)
        .expect("an own Falcon holder");
    let idx = yew_core::wallet::falcon_holder_index(row.hd_chain().unwrap(), row.index).unwrap();
    let seed = keys::seed_from_mnemonic(mnemonic, "").unwrap();
    let pq =
        yew_core::pq::PqSeedRoot::from_seed(&seed).derive(yew_core::pq::SCHEME_FN_DSA_512, idx);
    format!("{}:{}", yew_core::pq::SCHEME_FN_DSA_512, keys::hex(&pq))
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

    // Contract rule 1: the service is there, rpcversion 4 (hardening H3-c), enabled and active.
    let (mut v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .expect("probe");
    assert!(availability.usable(), "{availability:?}");
    match &availability {
        Availability::Present { info, .. } => {
            assert_eq!(info.rpcversion, yew_core::net::yellowback::KNOWN_RPCVERSION)
        }
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
    let (mut b, b_mnemonic) = fresh_wallet(&dir, "b", birthday);

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

    // 2. Node 0 sends YED and YEC to wallet A: nothing before confirmation, YED after. The
    //    devnet runs Falcon from the vault activation, as mainnet: YED goes to A's Falcon holder
    //    address, and A's P2PKH YED address is refused by the node (TOK-PQ, bad-yed-holder).
    let a_addr = a.receive_address(false).unwrap();
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!((r.yed, r.yec), ((0, 0), (0, 0)));
    assert!(
        a.falcon_now(),
        "the devnet mirrors mainnet: Falcon from the vault activation"
    );
    let a_falcon = a.falcon_holder_address(&a_addr).unwrap();
    assert!(
        a_falcon.starts_with("yr") && a_falcon.len() == 53,
        "{a_falcon}"
    );
    let refused = dn.node_try(0, &["yed_send", &a_addr.address_ye, "5000"]);
    assert!(refused.contains("bad-yed-holder"), "TOK-PQ: {refused}");
    let fund = dn.node(0, &["sendtoaddress", &a_addr.address_s, "1.0"]);
    let sent = dn.node_json(0, &["yed_send", &a_falcon, "5000"]);
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

    // 3. A sends $12.34 to B's Falcon holder: the change (to A's Falcon holder) is
    //    PENDING_TOKEN until the block; then B has YED.
    let b_addr = b.receive_address(false).unwrap();
    let b_falcon_id = b.falcon_holder_id(&b_addr).unwrap();
    let b_falcon = b.falcon_holder_address(&b_addr).unwrap();
    let p = yed_transfer::build_yed_transfer(&a, &[(b_falcon.clone(), 1_234)], r.tip, r.branch_id)
        .unwrap();
    assert_eq!((p.change_cents, p.yed_inputs.len()), (3_766, 1));
    // A Falcon token input is spent with a 1,577-byte scriptSig: the size-rated fee is above
    // the FEE_ZAT floor (`max(FEE_ZAT, rate x size)`).
    assert!(p.fee >= FEE_ZAT, "fee {}", p.fee);
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
        &[(yew_core::pq::pqpkh_script(&b_falcon_id).unwrap(), 9_999)],
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
    let e =
        yed_transfer::build_yed_transfer(&a, &[(b_falcon.clone(), 3_716)], ra.tip, ra.branch_id)
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
            // node 0's own Falcon holder (yed_getnewaddress from the Falcon height, TOK-PQ)
            let ye = dn.node(0, &["yed_getnewaddress"]);
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

    // 7. The key round trip (D-W-11): fund B's address with YEC too, export its WIF and its
    //    Falcon holder seed and import both on node 5 (a -yellowback wallet node; node 1 is the
    //    stock node of the armed devnet): dumpprivkey equals, balances show, the node reports the
    //    same change-floor alternatives on those coins, and node 5 can yed_send them. Under TOK-PQ
    //    the token is held by B's Falcon key, so the YED comes over with z_importpqkey.
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
    dn.node(5, &["importprivkey", &wif, "yew-b", "false"]);
    let pqseed = falcon_pqseed(&b, &b_mnemonic, &b_falcon_id);
    let imported = dn.node_json(5, &["z_importpqkey", &pqseed, "true", "yew-b-falcon"]);
    assert_eq!(
        imported["pqkeyid"].as_str().unwrap(),
        keys::hex(&b_falcon_id.to_bytes()),
        "{imported}"
    );
    assert_eq!(
        dn.node(5, &["dumpprivkey", &b_addr.address_s]),
        wif,
        "dumpprivkey equals export-wif"
    );
    assert_eq!(
        dn.node(5, &["getreceivedbyaddress", &b_addr.address_s, "1"])
            .parse::<f64>()
            .unwrap(),
        0.5,
        "0.5 YEC received at the imported address (the token is at B's Falcon holder)"
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
    let back = dn.node_json(5, &["yed_send", &a_falcon, "1234"]);
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
    //    block; role plan F-3), then sync. The YEC comes from pool node 2 (mature coinbase):
    //    node 0's YEC is what the W2 acceptance and its own mints left, a few YEC.
    let addr = a.receive_address(true).unwrap();
    // YEW_DEVNET_FUND_NODE (default 2): a fresh vault-upgrade devnet's pools hold few mature
    // coinbases; node 0 (funded by `up`) can fund instead.
    let fund = fund_node();
    for amount in ["15", "10", "8", "5"] {
        let t = dn.node(fund, &["sendtoaddress", &addr.address_s, amount]);
        assert_eq!(t.len(), 64, "{t}");
    }
    let addr2 = a.receive_address(true).unwrap();
    let t = dn.node(fund, &["sendtoaddress", &addr2.address_s, "2"]);
    confirm(&dn, &mut c, &t).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yec.0 + r.yec.1, 40 * 100_000_000, "{r:?}");

    // 1. The full two-step mint of $100.00 for 48 blocks.
    let est = a.mint_estimate(&mut v, 10_000, 48, r.tip).await.unwrap();
    println!("estimate: {est:?}");
    assert!(est.affordable() && est.armed && !est.bundle_seqs.is_empty());
    assert_eq!(est.claim_height, est.lock_height + grace);
    let id1 = a
        .mint_start(&mut c, &mut v, 10_000, 48, None, r.tip, r.branch_id)
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
        .mint_start(&mut c, &mut v, 10_000, 48, None, r.tip, r.branch_id)
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

    // 3. Plan §8.6 / open question 6: the key of vault 2 into node 5 with rescan. On the quantum
    //    line (rpcversion 7) the owner is a post-quantum key the node cannot import (there is no
    //    PQ import RPC, and no owner public key is on chain): the WIF YEW exports is the token
    //    holder's (the external key the PQ owner is paired with), so node 5 gets the YED, not the
    //    vault.
    let owner2_addr = keys::encode_pq_yellowback(Network::Regtest, &v2.owner).unwrap();
    // Under TOK-PQ the minted token is held by the Falcon key paired with the mint's holder row
    // (`mint_token_script`), so node 5 gets it with z_importpqkey, not importprivkey.
    let holder2_row = a
        .addresses()
        .unwrap()
        .into_iter()
        .find(|r| r.hash160 == v2.owner_hash160)
        .expect("vault 2's holder row");
    let holder2 = a.falcon_holder_id(&holder2_row).unwrap();
    let pqseed2 = falcon_pqseed(&a, &mnemonic, &holder2);
    let imported = dn.node_json(5, &["z_importpqkey", &pqseed2, "true", "yew-vault-holder"]);
    assert_eq!(
        imported["pqkeyid"].as_str().unwrap(),
        keys::hex(&holder2.to_bytes()),
        "{imported}"
    );
    let listed5 = dn.node_json(5, &["yed_listvaults"]);
    let seen5 = listed5
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["txid"].as_str() == Some(&f2.txid));
    let node5_yed = dn.node_json(5, &["yed_getbalance"])["confirmedCents"]
        .as_u64()
        .unwrap();
    // In-term D-IT-15: a redeem before lockHeight is valid (with the early-redeem fee); before the
    // quantum line node 5 could close vault 2 with the imported key. Now it quotes the early fee
    // but cannot redeem (vault-not-owned: the owner is YEW's PQ key), and 5b records the refusal.
    let early = dn.node_try(5, &["yed_estimateredeem", &f2.txid]);
    // (`yed_listvaults` is the index's list of every vault: `seen5` says nothing about ownership.)
    assert!(
        early.contains("vault-not-owned") && early.contains("\"early\": true"),
        "{early}"
    );
    println!(
        "Q6: node 5 after importprivkey: yed_listvaults lists vault 2 = {seen5} yed_getbalance {node5_yed} cents; yed_estimateredeem before lockHeight -> {early}"
    );

    // 4. Forced lapse: a third mint left unfinished until refHeight + REF_WINDOW passes, then
    //    swept. Meanwhile a bundle with one mutated signature is refused by bundle.rs.
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let id3 = a
        .mint_start(&mut c, &mut v, 10_000, 48, None, r.tip, r.branch_id)
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
    // One block past lockHeight: the relay's index may trail the chain tip by a block.
    while r.tip <= v1.lock_height as u64 {
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    }
    let p = a
        .redeem_preview(&mut v, &v1.txid, r.tip, r.branch_id)
        .await
        .unwrap();
    // rpcversion 8: FEE-1′ of the debt at the vault's stored pMint
    assert_eq!(
        p.fee_zat,
        yew_core::params::protocol_fee_zat(v1.minted_cents, v1.p_mint).unwrap()
    );
    let (sent, val) = a.redeem_confirm(&mut c, &mut v, &p).await.unwrap();
    assert_eq!(
        (val.verdict.as_str(), val.path.as_str(), val.burned),
        ("ok", "owner", 10_000)
    );
    // In-term D-IT-15: the owner path's nLockTime is the V's ownerHeight (refHeight + 1).
    assert_eq!(
        (
            p.lock_time,
            p.burn_cents,
            p.change_cents,
            p.early_redeem_fee_zat
        ),
        (v1.owner_height, 10_000, 0, 0)
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
    // A fresh vault-upgrade devnet: node 0 holds only what its own mint left (less W2's 5,000
    // cents): top it up with a second mint (two-step without waiting; its wallet completes it on
    // the next blocks) so it can fund A with the target's whole debt.
    let have = dn.node_json(0, &["yed_getbalance"])["confirmedCents"]
        .as_u64()
        .unwrap();
    if have < target_cents {
        let top = (target_cents - have).max(10_000).to_string();
        let m = dn.node_json(0, &["yed_mint", &top, "48", "", "", "false"]);
        println!("node 0 top-up mint of {top} cents: {m}");
        let start = Instant::now();
        while dn.node_json(0, &["yed_getbalance"])["confirmedCents"]
            .as_u64()
            .unwrap()
            < target_cents
        {
            assert!(
                start.elapsed() < Duration::from_secs(300),
                "the top-up mint never confirmed"
            );
            let h = dn.mine_pool();
            wait_for_height(&mut c, h).await;
        }
    }
    let a_addr = a.receive_address(true).unwrap();
    // TOK-PQ: YED to A's Falcon holder (a P2PKH holder is bad-yed-holder from the Falcon height).
    let a_falcon = a.falcon_holder_address(&a_addr).unwrap();
    let fund_yed = dn.node_json(0, &["yed_send", &a_falcon, &target_cents.to_string()]);
    confirm(&dn, &mut c, fund_yed["txid"].as_str().unwrap()).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(r.yed.0 >= target_cents, "{r:?}");
    dn.run(&["price", "--shock=-80%"]);
    *dn.price.borrow_mut() = "10".into();
    let mut claimable = Vec::new();
    let mut r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let start = Instant::now();
    // rpcversion 6: the target is listed in term above θ with claimable false; wait for true.
    while claimable
        .iter()
        .all(|x: &yew_core::build::claim::Claimable| x.vault_txid != target_txid || !x.claimable)
    {
        assert!(
            start.elapsed() < Duration::from_secs(900),
            "the vault never became claimable"
        );
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        // Pace the loop under the server's per-peer rate limit (a sync of a wallet with vaults
        // and claim intents makes several whole-token calls; lightwalletd refills one per second).
        tokio::time::sleep(Duration::from_secs(3)).await;
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
    // In-term claims: claimable once under θ, in term or not (no claimHeight wait).
    assert!(entry.claimable);
    let target_id = txid_from_hex(&target_txid).unwrap();
    // H-9.3: bounds tighter than the server's numbers are refused before the carrier is funded
    // (no row, nothing signed); the bounds the screen showed pass.
    let rows_before = a.mints().unwrap().len();
    for (what, bounds) in [
        (
            "claim-burn-above-max",
            yew_core::build::terms::ClaimBounds {
                max_burn_cents: entry.minted_cents - 1,
                min_out_zat: entry.claimant_zat,
            },
        ),
        (
            "claim-out-below-min",
            yew_core::build::terms::ClaimBounds {
                max_burn_cents: entry.minted_cents,
                min_out_zat: entry.claimant_zat + 1,
            },
        ),
    ] {
        let e = a
            .claim(
                &mut c,
                &mut v,
                &target_id,
                Some(&bounds),
                r.tip,
                r.branch_id,
            )
            .await
            .unwrap_err();
        assert!(e.to_string().starts_with(what), "{what}: {e}");
    }
    assert_eq!(a.mints().unwrap().len(), rows_before);
    let bounds = yew_core::build::terms::ClaimBounds {
        max_burn_cents: entry.minted_cents,
        min_out_zat: entry.claimant_zat,
    };
    let idc = a
        .claim(
            &mut c,
            &mut v,
            &target_id,
            Some(&bounds),
            r.tip,
            r.branch_id,
        )
        .await
        .unwrap();
    assert_eq!(
        a.store.claim_bounds(idc).unwrap(),
        Some((entry.minted_cents, entry.claimant_zat))
    );
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
    // nLockTime is the V's appHeight: refHeight + 1 for an in-term mint (IT-1), claimHeight before.
    let target_app = target["refHeight"].as_u64().unwrap() + 1;
    assert!(
        ctx.lock_time as u64 == target_app || ctx.lock_time as u64 == target_claim_height,
        "nLockTime {} is neither appHeight {target_app} nor claimHeight {target_claim_height}",
        ctx.lock_time
    );
    assert_eq!(
        ctx.vin[0].prevout,
        OutPoint {
            txid: target_id,
            n: 0
        }
    );
    assert!(script::parse_carrier_script_sig(&ctx.vin[ctx.vin.len() - 1].script_sig).is_some());
    // The vault upgrade (U-23): vin[0] is the V spent with OP_4; vout[0] the claimant intent
    // paying A, of the collateral less the residual.
    assert_eq!(ctx.vin[0].script_sig, vec![0x54]);
    let ip =
        yew_core::vault::parse_intent(&ctx.vout[0].script_pubkey).expect("vout[0] is an intent");
    assert_eq!(ip.tag, yew_core::vault::YED_TAG);
    assert_eq!(ctx.vout[0].value, target_collateral - entry.residual_zat);
    confirm(&dn, &mut c, &fc.txid).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(mint_state(&a, idc), MintState::Done);
    let node_vault = dn.node_json(0, &["yed_getvault", &target_txid]);
    assert_eq!(
        node_vault["status"].as_str().unwrap(),
        "CLAIMING",
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
    // The claimant intent is pending release; a release before CLAIM_DELAY is refused locally.
    let intent_op = OutPoint {
        txid: txid_from_hex(&fc.txid).unwrap(),
        n: 0,
    };
    let row_i = a
        .store
        .intent(&intent_op)
        .unwrap()
        .expect("the claimant intent row");
    assert_eq!(
        (row_i.state, row_i.role.as_str(), row_i.value, row_i.height),
        (
            yew_core::store::IntentState::Pending,
            "claimant",
            target_collateral - entry.residual_zat,
            r.tip
        ),
        "{row_i:?}"
    );
    assert!(a.release_preview(&intent_op, r.tip, r.branch_id).is_err());
    let mut r = r;
    while yew_core::build::release::not_releasable(
        &a.store.intent(&intent_op).unwrap().unwrap(),
        r.tip,
    )
    .is_some()
    {
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        tokio::time::sleep(Duration::from_secs(3)).await; // the server's rate limit

        r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    }
    let rp = a.release_preview(&intent_op, r.tip, r.branch_id).unwrap();
    let (rtx, _) = Transaction::parse(&rp.raw).unwrap();
    assert_eq!(
        (rtx.vin[0].script_sig.clone(), rtx.vin[0].sequence as i64),
        (vec![0x51], row_i.delay)
    );
    let release_hex = keys::hex(&rp.raw);
    println!("release preview {}: {release_hex}", txid_hex(&rp.txid));
    // Node defect (found here, both node lines): yed_validaterawtransaction verifies scripts with
    // STANDARD_SCRIPT_VERIFY_FLAGS only (src/yellowback/policy.cpp VerifyAllInputs), without the
    // vault flags of tip+1 and without the set checker, so the intent's OP_CHECKSEQUENCEVERIFY is
    // an upgradable NOP there and every RELEASE answers valid:false. The gate refuses it (no
    // override). YEW_DEVNET_RELEASE_VIA_NODE=1 records the refusal and then sends YEW's exact
    // bytes with sendrawtransaction, to show they are consensus-valid and to drive the sync side.
    let rel = match a.release_confirm(&mut c, &mut v, &rp).await {
        Ok((rel, rv)) => {
            println!(
                "release {rel}: verdict {} type {:?}",
                rv.verdict, rv.tx_type
            );
            assert_eq!(rv.verdict, "ok");
            rel
        }
        Err(e) if std::env::var("YEW_DEVNET_RELEASE_VIA_NODE").as_deref() == Ok("1") => {
            println!("RELEASE GATE REFUSED (node defect, see above): {e}");
            println!(
                "node yed_validaterawtransaction: {}",
                dn.node_try(0, &["yed_validaterawtransaction", &release_hex])
            );
            let sent = dn.node(0, &["sendrawtransaction", &release_hex]);
            assert_eq!(
                sent,
                txid_hex(&rp.txid),
                "the node accepted YEW's release bytes"
            );
            println!("RELEASE SENT VIA NODE: {sent}");
            sent
        }
        Err(e) => panic!("release refused: {e}"),
    };
    confirm(&dn, &mut c, &rel).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(
        a.store.intent(&intent_op).unwrap().unwrap().state,
        yew_core::store::IntentState::Released
    );
    let node_vault = dn.node_json(0, &["yed_getvault", &target_txid]);
    assert_eq!(
        node_vault["status"].as_str().unwrap(),
        "CLAIMED",
        "{node_vault}"
    );
    let ti = v.client_mut().unwrap().tx_info(&rel).await.unwrap();
    assert_eq!(
        (ti.r#type.as_str(), ti.verdict.as_str()),
        ("claim_release", "ok")
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

/// The vault upgrade (U-24) with CAN-1 / CAN-2 / C4b (the cancel-limit design): a claim one
/// attestor says was made at a wrong price, cancelled during the claim delay, and the claimant's
/// burn coming back.
///
/// Node 0 mints a $100 vault. The first attestor goes offline (an aClaim is the bundle's highest
/// price, so while it attests a higher price no claim passes); the pools and the other attestors
/// move to a price at which the vault is at 120 % of its debt (under θ). Once its last attestation
/// has aged out of the bundle, YEW claims the vault by path (a), burning $100 from two tokens at its
/// Falcon holder (TOK-PQ: the devnet mirrors mainnet, so YED is held by Falcon holders only); the
/// node's `refundHolder` is that holder. The offline attestor, which never attested the claim's
/// `refHeight`, co-signs a cancel with a price statement 12 % higher, where the vault is above θ
/// ("not claimable", C4b): `yed_signcancelcosign`, `yed_buildcancel`, `set_signcancel`,
/// `vault_send`. YEW's sync then marks the intent `CANCELLED`, refuses a release, and finds the
/// refund: its YED balance is back to what it was before the claim, the refund token at its Falcon
/// holder. Needs the vault-upgrade devnet (`scripts/devnet-w4.sh`).
#[tokio::test]
#[ignore = "needs the ARMED vault-upgrade regtest devnet (scripts/devnet-w4.sh) and YEW_DEVNET=1"]
async fn w4_claim_cancelled_by_the_attestor_set() {
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
    let dir = std::env::temp_dir().join(format!("yew-devnet-w4c-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (mut b, _) = fresh_wallet(&dir, "b", info.block_height.saturating_sub(1));
    let attestors: Vec<usize> = {
        let st: Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{}/devnet.json", dn.dir)).unwrap(),
        )
        .unwrap();
        st["attestors"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_u64())
                    .map(|x| x as usize)
                    .collect()
            })
            .unwrap_or_else(|| vec![5, 6, 7])
    };
    assert!(!attestors.is_empty(), "an ARMED devnet has attestors");
    // Pools at `pool`, every attestor at `attested`, then one pool block (no `price` in between:
    // `price` also rewrites every automated attestor's mock price).
    let dissenter = attestors[0];
    // The pools and the running attestors at `pool`, then one pool block.
    let mine_split = |pool: &str, _attested: &str| -> u64 {
        dn.run(&["price", pool]);
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let p = 2 + NEXT.fetch_add(1, Ordering::SeqCst) % 3;
        let out = dn.run(&["mine", "1", &p.to_string()]);
        out.rsplit("-> ").next().unwrap().trim().parse().unwrap()
    };
    // A fresh $100 vault of node 0 (the target), and $120 of YED for B in two tokens.
    let active = |dn: &Devnet| -> Vec<String> {
        dn.node_json(0, &["yed_listvaults", "ACTIVE"])
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["txid"].as_str().unwrap().to_string())
            .collect()
    };
    // The dissenter's YEC is its bond: give it fee money for the cancel's carrier and fee.
    let fee_addr = dn.node(dissenter, &["getnewaddress"]);
    dn.node(0, &["sendtoaddress", &fee_addr, "1"]);
    // Node 0 mints twice: $100 of YED to fund B (with what is left of the target's), then the target.
    let mint_new = |cents: &str| {
        let before = active(&dn);
        let m = dn.node_json(0, &["yed_mint", cents, "48", "", "", "false"]);
        println!("mint {cents}: {m}");
        let start = Instant::now();
        loop {
            let h = dn.mine_pool();
            if let Some(t) = active(&dn).into_iter().find(|t| !before.contains(t)) {
                break (t, h);
            }
            assert!(
                start.elapsed() < Duration::from_secs(300),
                "the mint never confirmed"
            );
        }
    };
    mint_new("10000");
    let (target, h) = mint_new("10000");
    wait_for_height(&mut c, h).await;
    let tv = dn.node_json(0, &["yed_getvault", &target]);
    let coll_yec = tv["collateralZat"].as_f64().unwrap() / 1e8;
    let debt_usd = tv["mintedCents"].as_f64().unwrap() / 100.0;
    // The price at which the vault's collateral is `ratio` × its debt.
    let price_at = |ratio: f64| format!("{:.6}", ratio * debt_usd / coll_yec);
    let (pool_px, attested_px) = (price_at(1.20), price_at(1.20 * 1.12));
    println!("vault {target}: {coll_yec} YEC against ${debt_usd}; pools and two attestors ${pool_px} (120 %), node{dissenter} ${attested_px} (134 %)");
    let addr = b.receive_address(true).unwrap();
    for amount in ["5", "3", "2"] {
        dn.node(fund_node(), &["sendtoaddress", &addr.address_s, amount]);
    }
    let falcon = b
        .falcon_holder_id(&addr)
        .expect("a Falcon holder (the devnet mirrors mainnet)");
    let holder = keys::encode_pq_yellowback(Network::Regtest, &falcon).unwrap();
    // TOK-PQ: from the Falcon height YED is held by Falcon holders only (bad-yed-holder for a P2PKH
    // address), so both tokens are at the wallet's Falcon holder and so is the refund.
    let y1 = dn.node_json(0, &["yed_send", &holder, "6000"]);
    confirm(&dn, &mut c, y1["txid"].as_str().unwrap()).await;
    let y2 = dn.node_json(0, &["yed_send", &holder, "6000"]);
    confirm(&dn, &mut c, y2["txid"].as_str().unwrap()).await;
    let mut r = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    assert!(r.yed.0 >= 12_000, "{r:?}");
    let yed_before_claim = r.yed.0;

    // The dissenting attestor goes offline; the price falls until the vault is claimable at the
    // claim price (the windows follow, and the dissenter's last attestation ages out).
    dn.run(&["attestor", &dissenter.to_string(), "stop"]);
    let start = Instant::now();
    let entry = loop {
        assert!(
            start.elapsed() < Duration::from_secs(1200),
            "the target never became claimable"
        );
        let h = mine_split(&pool_px, &attested_px);
        wait_for_height(&mut c, h).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        r = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
        if let Some(e) = b
            .claimable(&mut v)
            .await
            .unwrap()
            .into_iter()
            .find(|x| x.vault_txid == target && x.claimable)
        {
            break e;
        }
    };
    assert_eq!(entry.claim_path, "a", "{entry:?}");
    // CAN-2 on yed_listclaimable (node fix/cancel-fields-2): a vault never cancelled needs one.
    assert_eq!(
        (entry.cancels_required, entry.cancel_count),
        (1, 0),
        "{entry:?}"
    );
    let target_id = txid_from_hex(&target).unwrap();
    let bounds = yew_core::build::terms::ClaimBounds {
        max_burn_cents: entry.minted_cents,
        min_out_zat: entry.claimant_zat,
    };
    let id = b
        .claim(
            &mut c,
            &mut v,
            &target_id,
            Some(&bounds),
            r.tip,
            r.branch_id,
        )
        .await
        .unwrap();
    let mc = b.store.mint(id).unwrap().unwrap();
    confirm(&dn, &mut c, &txid_hex(&mc.carrier_txid)).await;
    let r = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    let fc = b
        .mint_finish(&mut c, &mut v, id, r.tip, r.branch_id)
        .await
        .unwrap();
    assert_eq!(fc.validation.verdict, "ok");
    dn.wait_mempool(&fc.txid);
    let h = mine_split(&pool_px, &attested_px);
    wait_for_height(&mut c, h).await;
    let r = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    let intent = OutPoint {
        txid: txid_from_hex(&fc.txid).unwrap(),
        n: 0,
    };
    // CAN-1: the node's refundHolder is the claim's first YED input, YEW's Falcon holder.
    let claiming = dn.node_json(0, &["yed_getvault", &target]);
    assert_eq!(claiming["status"].as_str(), Some("CLAIMING"), "{claiming}");
    let holder_hex = claiming["refundHolder"]
        .as_str()
        .expect("a CLAIMING vault's refundHolder");
    let holder_script = keys::unhex(holder_hex).unwrap();
    assert_eq!(
        yew_core::pq::pqpkh_of(&holder_script),
        Some(falcon),
        "the refund goes to the wallet's Falcon holder"
    );
    let row = b.store.intent(&intent).unwrap().unwrap();
    assert_eq!(row.state, yew_core::store::IntentState::Pending);
    assert_eq!(row.refund.script, holder_script, "{row:?}");
    let burned = claiming["burnedCents"].as_u64().unwrap();
    assert_eq!(row.refund.cents, burned);
    assert_eq!(
        yed_before_claim - r.yed.0,
        burned,
        "the claim burned {burned}"
    );

    // The dissenting attestor cancels the claim within CLAIM_DELAY.
    let ip = format!("{}:0", fc.txid);
    // A cancel re-creates the vault at the cancel's output 0, so the claimed outpoint is gone.
    let cancelled = |dn: &Devnet| {
        let out = dn.node_try(0, &["yed_getvault", &target]);
        out.contains("vault-not-found")
            || serde_json::from_str::<Value>(&out).is_ok_and(|j| j["status"] != "CLAIMING")
    };
    let mut cancel = String::new();
    if !cancelled(&dn) {
        // C4b: a member with no attestation at the claim's refHeight states its price there.
        let micro = ((attested_px.parse::<f64>().unwrap()) * 1e6).round() as u64;
        let micro = micro.to_string();
        let mut cosig = None;
        for a in [dissenter] {
            let out = dn.node_try(a, &["yed_signcancelcosign", &ip, &micro]);
            match serde_json::from_str::<Value>(&out) {
                Ok(j) if j["cosig"].is_string() => {
                    cosig = Some((a, j["cosig"].as_str().unwrap().to_string()));
                    break;
                }
                _ => println!("node{a} yed_signcancelcosign: {out}"),
            }
        }
        let (a, cos) = cosig.expect("an attestor whose attested price says not claimable co-signs");
        let built = dn.node_json(a, &["yed_buildcancel", &ip, &format!("[\"{cos}\"]")]);
        println!("yed_buildcancel: {built}");
        if built["carrierTxid"].is_string() {
            dn.wait_mempool(built["carrierTxid"].as_str().unwrap());
        }
        let signed = dn.node_json(
            a,
            &[
                "set_signcancel",
                built["hex"].as_str().unwrap(),
                r#"{"acknowledgerestore":true}"#,
            ],
        );
        cancel = dn.node(a, &["vault_send", signed["hex"].as_str().unwrap()]);
        dn.wait_mempool(&cancel);
        let h = mine_split(&pool_px, &attested_px);
        wait_for_height(&mut c, h).await;
    }
    assert!(cancelled(&dn), "the claim was not cancelled");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let r = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    let row = b.store.intent(&intent).unwrap().unwrap();
    assert_eq!(
        row.state,
        yew_core::store::IntentState::Cancelled,
        "{row:?}"
    );
    assert!(row.note.contains("came back"), "{row:?}");
    assert!(b.release_preview(&intent, r.tip, r.branch_id).is_err());
    // CAN-1: the whole burn is back, as one token at the Falcon holder.
    assert_eq!(
        r.yed.0, yed_before_claim,
        "the burn is refunded (CAN-1): {r:?}"
    );
    let tokens = dn.node_json(0, &["yed_listtokens", &format!("[\"{holder}\"]")]);
    let refund = tokens
        .as_array()
        .unwrap()
        .iter()
        .find(|t| {
            t["cents"].as_u64() == Some(burned)
                && t["txid"].as_str() != y1["txid"].as_str()
                && t["txid"].as_str() != y2["txid"].as_str()
        })
        .unwrap_or_else(|| panic!("no refund token of {burned} cents at {holder}: {tokens}"));
    let cancel_txid = refund["txid"].as_str().unwrap().to_string();
    if !cancel.is_empty() {
        assert_eq!(cancel_txid, cancel);
    }
    let reopened = dn.node_json(0, &["yed_getvault", &cancel_txid]);
    assert_eq!(reopened["status"].as_str().unwrap(), "ACTIVE", "{reopened}");
    assert_eq!(reopened["cancelCount"].as_u64(), Some(1), "{reopened}");
    let ti = v.client_mut().unwrap().tx_info(&cancel_txid).await.unwrap();
    assert_eq!(ti.r#type, "claim_cancel");
    println!(
        "W4 cancel acceptance ok: claim {} cancelled by {cancel_txid}; {burned} cents refunded to the Falcon holder {holder}; the vault lives on at {cancel_txid}:0",
        fc.txid
    );
    dn.run(&["attestor", &dissenter.to_string(), "start"]);
    dn.run(&["price", "50"]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- yew-shielded plan S2: Sapling receive / send / memo on either node line ----------------

/// `z_sendmany` from a fresh, funded transparent address of node 0 to `to` with a text memo,
/// waiting for the operation; returns the txid. The 6.21.0 line needs a privacy policy for the
/// transparent change (x402 X-F12); the 4.5.0 line takes an explicit fee.
/// Mine pool blocks until lightwalletd's latest height reaches `h`, pacing under the server's
/// per-peer rate limit, then sync `w`.
async fn mine_and_sync(
    dn: &Devnet,
    c: &mut CompactClient,
    v: &mut Validator,
    w: &mut Wallet,
) -> yew_core::sync::SyncReport {
    let h = dn.mine_pool();
    wait_for_height(c, h).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    sync(w, c, v.client_mut()).await.unwrap()
}

/// In-term claims (the workspace's `docs/plans/yellowback-in-term-claims-plan.md`, rpcversion 6):
/// on an ARMED devnet of the in-term node (`scripts/devnet-it.sh`) with the in-term lightwalletd,
///
/// 1. a YEW mint's V opens both branches at `refHeight + 1` (IT-1, D-IT-15);
/// 2. YEW redeems it **in term**: the preview carries the early-redeem fee (IT-9: 5 % of the
///    collateral for class A, on the FEE-1 payee's output, computed locally and equal to the
///    node's `yed_estimateredeem` quote for the same vault), the node accepts the bytes and closes
///    the vault;
/// 3. node 0's fresh class-C vault is listed above θ with `claimable: false` and YEW refuses to
///    claim it before anything is funded; after a −80 % shock it becomes claimable **in term**
///    and YEW claims it (`nLockTime` = its `appHeight` = `refHeight + 1`, below `lockHeight`), the
///    node marks it CLAIMING; the claimant intent is released after the claim delay;
/// 4. YEW's own second vault, claimable after the shock, is redeemed in term by its owner before
///    anyone claims it ("redeeming stops it", IT-8), again with the early-redeem fee.
#[tokio::test]
#[ignore = "needs an ARMED in-term regtest devnet (scripts/devnet-it.sh) and YEW_DEVNET=1"]
async fn it_early_redeem_and_in_term_claim() {
    use yew_core::build::mint::window_open;
    use yew_core::params::{early_redeem_fee_zat, protocol_fee_zat, CLAIM_THRESHOLD_BPS};
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return;
    }
    let dn = Devnet::new("yb-devnet-it", "741");
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:9741".into()), true).unwrap();
    let channel = server.connect().await.expect("connect to lightwalletd");
    let mut c = CompactClient::from_channel(channel.clone());
    let info = c.lightd_info_for(Network::Regtest).await.unwrap();
    let (mut v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .expect("probe");
    assert!(availability.usable(), "{availability:?}");
    let ref_lag = match &availability {
        Availability::Present { info, .. } => {
            assert_eq!(
                info.rpcversion,
                yew_core::net::yellowback::KNOWN_RPCVERSION,
                "the in-term rules on the quantum line (rpcversion 7)"
            );
            let p = info.params.as_ref().unwrap();
            assert!(p.in_term_claims, "params.inTermClaims");
            assert_eq!(p.claim_threshold_bps, CLAIM_THRESHOLD_BPS);
            assert_eq!(p.early_redeem_fee_bps, vec![500, 250, 100]);
            p.ref_lag as u32
        }
        Availability::Absent => unreachable!(),
    };
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
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
    }
    let dir = std::env::temp_dir().join(format!("yew-devnet-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let birthday = info.block_height.saturating_sub(1);
    let (mut a, _mnemonic) = fresh_wallet(&dir, "a", birthday);
    let addr = a.receive_address(true).unwrap();
    let fund = fund_node();
    for amount in ["15", "10", "8", "5"] {
        let t = dn.node(fund, &["sendtoaddress", &addr.address_s, amount]);
        assert_eq!(t.len(), 64, "{t}");
    }
    let addr2 = a.receive_address(true).unwrap();
    let t = dn.node(fund, &["sendtoaddress", &addr2.address_s, "2"]);
    confirm(&dn, &mut c, &t).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yec.0 + r.yec.1, 40 * 100_000_000, "{r:?}");

    // A two-step mint from A ($100), returning the vault row once the node reports it.
    async fn mint_vault(
        dn: &Devnet,
        a: &mut Wallet,
        c: &mut CompactClient,
        v: &mut Validator,
        lock_blocks: u32,
    ) -> yew_core::store::VaultRow {
        let r = sync(a, c, v.client_mut()).await.unwrap();
        let id = a
            .mint_start(c, v, 10_000, lock_blocks, None, r.tip, r.branch_id)
            .await
            .unwrap();
        let m = a.store.mint(id).unwrap().unwrap();
        confirm(dn, c, &txid_hex(&m.carrier_txid)).await;
        let r = sync(a, c, v.client_mut()).await.unwrap();
        assert!(window_open(r.tip, m.expiry_height));
        let f = a.mint_finish(c, v, id, r.tip, r.branch_id).await.unwrap();
        assert_eq!(f.validation.verdict, "ok");
        confirm(dn, c, &f.txid).await;
        sync(a, c, v.client_mut()).await.unwrap();
        let row = a
            .vaults()
            .unwrap()
            .into_iter()
            .find(|x| txid_hex(&x.txid) == f.txid)
            .expect("the minted vault");
        // IT-1 / D-IT-15: the V the node holds opens both branches at refHeight + 1.
        let gv = v.client_mut().unwrap().vault(&f.txid).await.unwrap();
        let p = yew_core::vault::parse_vault(&keys::unhex(&gv.script_pub_key).unwrap()).unwrap();
        assert_eq!(
            (p.owner_height, p.app_height),
            (m.ref_height as i64 + 1, m.ref_height as i64 + 1),
            "IT-1: the in-term V"
        );
        assert_eq!(
            (row.owner_height, row.app_height),
            (m.ref_height + 1, m.ref_height + 1)
        );
        assert_eq!(row.lock_height, m.ref_height + lock_blocks);
        row
    }

    // 1-2. Mint, then redeem in term with the early-redeem fee.
    let v1 = mint_vault(&dn, &mut a, &mut c, &mut v, 48).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(r.tip + 1 < v1.lock_height as u64, "in term");
    let p = a
        .redeem_preview(&mut v, &v1.txid, r.tip, r.branch_id)
        .await
        .unwrap();
    let fee1 = protocol_fee_zat(v1.minted_cents, v1.p_mint).unwrap();
    let early = early_redeem_fee_zat(v1.minted_cents, 500, v1.p_mint);
    assert_eq!(
        (p.early_redeem_fee_zat, p.fee_zat, p.lock_time),
        (early, fee1 + early, v1.owner_height),
        "{p:?}"
    );
    assert!(!p.payee.is_empty());
    let (rtx, _) = Transaction::parse(&p.raw).unwrap();
    assert_eq!(
        rtx.vout[1].value,
        fee1 + early,
        "the early fee rides on the FEE-1 output"
    );
    // The node's own quote for the same vault: on the quantum line the owner is YEW's SLH-DSA
    // key, which no node RPC imports, so node 5 (holding only the paired holder key) quotes the
    // fees with `canRedeem: false` and "vault-not-owned"; the fees must still be YEW's.
    let owner_addr = keys::encode_yellowback(Network::Regtest, &v1.owner_hash160);
    let wif = a.export_wif(&owner_addr).unwrap();
    dn.node(5, &["importprivkey", &wif, "yew-it-holder", "true"]);
    let quote = dn.node_try(5, &["yed_estimateredeem", &txid_hex(&v1.txid)]);
    println!("node 5 yed_estimateredeem: {quote}");
    let q: Value = serde_json::from_str(&quote).expect("yed_estimateredeem answers a quote");
    assert_eq!(q["earlyRedeemFeeZat"].as_i64(), Some(early), "{q}");
    assert_eq!(q["feeZat"].as_i64(), Some(fee1 + early), "{q}");
    assert_eq!(q["early"].as_bool(), Some(true), "{q}");
    assert_eq!(q["canRedeem"].as_bool(), Some(false), "{q}");
    assert!(
        q["error"]
            .as_str()
            .unwrap_or("")
            .starts_with("vault-not-owned"),
        "{q}"
    );
    let (sent, val) = a.redeem_confirm(&mut c, &mut v, &p).await.unwrap();
    assert_eq!(
        (val.verdict.as_str(), val.path.as_str(), val.burned),
        ("ok", "owner", 10_000)
    );
    let h_redeem = confirm(&dn, &mut c, &sent).await;
    assert!(
        h_redeem < v1.lock_height as u64,
        "mined in term at {h_redeem}"
    );
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(a.store.vault(&v1.txid).unwrap().unwrap().status, "CLOSED");
    let ti = v.client_mut().unwrap().tx_info(&sent).await.unwrap();
    assert_eq!(
        (ti.r#type.as_str(), ti.verdict.as_str(), ti.fee_zat),
        ("redeem", "ok", fee1 + early),
        "{ti:?}"
    );
    println!(
        "early redeem {sent} at {h_redeem} < lockHeight {}: FEE-1 {fee1} + early-redeem fee {early} zat, collateral {} back",
        v1.lock_height, p.collateral_out
    );
    assert_eq!(r.yed, (0, 0), "{r:?}");

    // 3. Node 0's fresh class-C vault (240 blocks: in term through the price fall).
    let before: Vec<String> = dn
        .node_json(0, &["yed_listvaults", "ACTIVE"])
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["txid"].as_str().unwrap().to_string())
        .collect();
    let m = dn.node_json(0, &["yed_mint", "10000", "240", "", "", "false"]);
    println!("node 0 mint (class C): {m}");
    let start = Instant::now();
    let target = loop {
        let now = dn.node_json(0, &["yed_listvaults", "ACTIVE"]);
        if let Some(x) = now
            .as_array()
            .unwrap()
            .iter()
            .find(|x| !before.contains(&x["txid"].as_str().unwrap().to_string()))
        {
            break x.clone();
        }
        assert!(
            start.elapsed() < Duration::from_secs(300),
            "node 0's mint never confirmed"
        );
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
    };
    let target_txid = target["txid"].as_str().unwrap().to_string();
    let target_id = txid_from_hex(&target_txid).unwrap();
    let target_cents = target["mintedCents"].as_u64().unwrap();
    let target_lock = target["lockHeight"].as_u64().unwrap();
    let target_ref = target["refHeight"].as_u64().unwrap();
    assert_eq!(target["termClass"].as_str(), Some("C"), "{target}");
    // YEW's second vault (class A, 96 blocks), to be redeemed in term once it is claimable.
    let v2 = mint_vault(&dn, &mut a, &mut c, &mut v, 96).await;
    // Above θ: listed (the claim branch is open), claimable false, refused before any funding.
    let mut r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let rows = a.claimable(&mut v).await.unwrap();
    let row = rows
        .iter()
        .find(|x| x.vault_txid == target_txid)
        .expect("IT-7: the in-term vault is listed");
    assert!(
        !row.claimable && row.in_term && row.underwater_at > 0,
        "{row:?}"
    );
    let mints_before = a.mints().unwrap().len();
    let e = a
        .claim(&mut c, &mut v, &target_id, None, r.tip, r.branch_id)
        .await
        .unwrap_err();
    assert!(e.to_string().starts_with("claim-not-underwater"), "{e}");
    assert_eq!(a.mints().unwrap().len(), mints_before, "nothing funded");
    // A needs the target's debt in YED (its own $100 stays for v2's redeem).
    let a_addr = a.receive_address(true).unwrap();
    let fund_yed = dn.node_json(
        0,
        &["yed_send", &a_addr.address_ye, &target_cents.to_string()],
    );
    confirm(&dn, &mut c, fund_yed["txid"].as_str().unwrap()).await;
    r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yed.0, 10_000 + target_cents, "{r:?}");
    dn.run(&["price", "--shock=-80%"]);
    *dn.price.borrow_mut() = "10".into();
    let start = Instant::now();
    let entry = loop {
        assert!(
            start.elapsed() < Duration::from_secs(1200),
            "the vault never became claimable"
        );
        r = mine_and_sync(&dn, &mut c, &mut v, &mut a).await;
        assert!(
            r.tip < target_lock,
            "the target left its term before it became claimable"
        );
        let rows = a.claimable(&mut v).await.unwrap();
        if let Some(x) = rows
            .iter()
            .find(|x| x.vault_txid == target_txid && x.claimable)
        {
            break x.clone();
        }
        if r.tip % 10 == 0 {
            let p = v.client_mut().unwrap().price(0).await.unwrap();
            println!(
                "tip {} pClaim {} target listed {:?}",
                r.tip,
                p.p_claim,
                rows.iter()
                    .find(|x| x.vault_txid == target_txid)
                    .map(|x| (x.claimable, x.underwater_at))
            );
        }
    };
    println!("claimable in term: {entry:?}");
    assert!(entry.in_term && entry.claim_path == "a", "{entry:?}");
    // 4 (first half). YEW's own v2 is as underwater: the store says so (VaultSummary's warning).
    let v2_now = a.store.vault(&v2.txid).unwrap().unwrap();
    println!(
        "v2 after the shock: claimable {} underwaterAt {}",
        v2_now.claimable, v2_now.underwater_at
    );
    // The claim (in term).
    let bounds = yew_core::build::terms::ClaimBounds {
        max_burn_cents: entry.minted_cents,
        min_out_zat: entry.claimant_zat,
    };
    let idc = a
        .claim(
            &mut c,
            &mut v,
            &target_id,
            Some(&bounds),
            r.tip,
            r.branch_id,
        )
        .await
        .unwrap();
    let mc = a.store.mint(idc).unwrap().unwrap();
    confirm(&dn, &mut c, &txid_hex(&mc.carrier_txid)).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let fc = a
        .mint_finish(&mut c, &mut v, idc, r.tip, r.branch_id)
        .await
        .unwrap();
    assert_eq!(
        (fc.validation.verdict.as_str(), fc.validation.path.as_str()),
        ("ok", "claim")
    );
    let (ctx, _) = Transaction::parse(&fc.raw).unwrap();
    assert_eq!(
        ctx.lock_time as u64,
        target_ref + 1,
        "IT-1: nLockTime = appHeight = refHeight + 1"
    );
    assert_eq!(ctx.vin[0].script_sig, vec![0x54]);
    let h_claim = confirm(&dn, &mut c, &fc.txid).await;
    assert!(
        h_claim < target_lock,
        "the claim was mined in term ({h_claim} < {target_lock})"
    );
    let node_vault = dn.node_json(0, &["yed_getvault", &target_txid]);
    assert_eq!(
        node_vault["status"].as_str(),
        Some("CLAIMING"),
        "{node_vault}"
    );
    println!(
        "in-term claim {} at {h_claim} < lockHeight {target_lock}",
        fc.txid
    );

    // 4 (second half). "Redeeming stops it": v2's owner redeems it in term, early-redeem fee paid.
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    let p2 = a
        .redeem_preview(&mut v, &v2.txid, r.tip, r.branch_id)
        .await
        .unwrap();
    let early2 = early_redeem_fee_zat(v2.minted_cents, 500, v2.p_mint);
    assert_eq!(p2.early_redeem_fee_zat, early2, "{p2:?}");
    let (sent2, val2) = a.redeem_confirm(&mut c, &mut v, &p2).await.unwrap();
    assert_eq!((val2.verdict.as_str(), val2.path.as_str()), ("ok", "owner"));
    let h2 = confirm(&dn, &mut c, &sent2).await;
    assert!(h2 < v2.lock_height as u64);
    let mut r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(a.store.vault(&v2.txid).unwrap().unwrap().status, "CLOSED");
    println!(
        "v2 (claimable: {}) redeemed in term by its owner: {sent2} at {h2}, early fee {early2}",
        v2_now.claimable
    );

    // The claimant intent, released after the claim delay.
    let intent_op = OutPoint {
        txid: txid_from_hex(&fc.txid).unwrap(),
        n: 0,
    };
    while yew_core::build::release::not_releasable(
        &a.store.intent(&intent_op).unwrap().unwrap(),
        r.tip,
    )
    .is_some()
    {
        r = mine_and_sync(&dn, &mut c, &mut v, &mut a).await;
    }
    let rp = a.release_preview(&intent_op, r.tip, r.branch_id).unwrap();
    let (rel, rv) = a.release_confirm(&mut c, &mut v, &rp).await.unwrap();
    assert_eq!(rv.verdict, "ok");
    confirm(&dn, &mut c, &rel).await;
    sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(
        dn.node_json(0, &["yed_getvault", &target_txid])["status"].as_str(),
        Some("CLAIMED")
    );
    println!(
        "IN-TERM devnet acceptance ok: early redeem {sent} / in-term claim {} released {rel} / owner redeem of a claimable vault {sent2}",
        fc.txid
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn z_fund_from_node0(dn: &Devnet, line: &str, to: &str, amount: &str, memo: &str) -> String {
    let taddr = node0_coins(dn, 1).remove(0);
    z_send_from_node0(dn, line, &taddr, to, amount, memo)
}

/// `n` fresh transparent addresses of node 0, each holding one confirmed 3-YEC coin (one pool
/// block mines them all), for later `z_sendmany` calls that must not mine a block of their own.
/// Pool node 2 pays them: a `sendtoaddress` on node 0 could spend a coin set aside earlier.
fn node0_coins(dn: &Devnet, n: usize) -> Vec<String> {
    let taddrs: Vec<String> = (0..n).map(|_| dn.node(0, &["getnewaddress"])).collect();
    for taddr in &taddrs {
        let coin = dn.node(2, &["sendtoaddress", taddr, "3.0"]);
        dn.wait_mempool(&coin);
    }
    dn.mine_pool();
    taddrs
}

/// `z_sendmany` from node 0's transparent address `taddr` (a confirmed coin of
/// [`node0_coins`]) to `to` with a text memo, waiting for the operation; returns the txid.
fn z_send_from_node0(
    dn: &Devnet,
    line: &str,
    taddr: &str,
    to: &str,
    amount: &str,
    memo: &str,
) -> String {
    let taddr = taddr.to_string();
    let amounts = serde_json::json!([{ "address": to, "amount": amount.parse::<f64>().unwrap(),
        "memo": keys::hex(memo.as_bytes()) }])
    .to_string();
    let opid = if line == "dd" {
        dn.node(0, &["z_sendmany", &taddr, &amounts, "1", "0.0001"])
    } else {
        dn.node(
            0,
            &[
                "z_sendmany",
                &taddr,
                &amounts,
                "1",
                "null",
                "AllowFullyTransparent",
            ],
        )
    };
    let start = Instant::now();
    loop {
        let res = dn.node_json(0, &["z_getoperationresult", &format!("[\"{opid}\"]")]);
        if let Some(op) = res.as_array().and_then(|a| a.first()) {
            assert_eq!(op["status"], "success", "z_sendmany failed: {op}");
            return op["result"]["txid"].as_str().unwrap().to_string();
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "z_sendmany never finished"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Every file under `dir` is free of the account's spending key (raw, its `ask`/`nsk`
/// halves, the Bech32 form).
fn assert_no_spending_key(dir: &std::path::Path, a: &yew_core::shielded_keys::SaplingAccount) {
    let raw = a.spending_key_bytes();
    let bech = a.spending_key().to_string();
    let needles: [(&str, &[u8]); 4] = [
        ("extsk", &raw[..]),
        ("ask", &raw[41..73]),
        ("nsk", &raw[73..105]),
        ("bech32", bech.as_bytes()),
    ];
    let mut stack = vec![dir.to_path_buf()];
    let mut files = 0;
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            files += 1;
            let bytes = std::fs::read(&p).unwrap();
            for (what, n) in needles {
                assert!(
                    !bytes.windows(n.len()).any(|w| w == n),
                    "{} holds the spending key ({what})",
                    p.display()
                );
            }
        }
    }
    assert!(files > 0);
}

/// Sync both pools: the transparent §3.2 loop, then the private scan; returns the transparent
/// report and the private one.
async fn sync_both(
    w: &mut Wallet,
    server: &Server,
    c: &mut CompactClient,
    v: &mut Validator,
) -> (
    yew_core::sync::SyncReport,
    yew_core::shielded::ShieldedSyncReport,
) {
    let r = sync(w, c, v.client_mut()).await.unwrap();
    let z = yew_core::build::yec_private::sync_shielded(
        w,
        server,
        c,
        yew_core::build::yec_private::no_progress(),
    )
    .await
    .unwrap();
    (r, z)
}

/// A local copy of the Sapling proving parameters (`YEW_SAPLING_PARAMS`, or the ycashd
/// `fetch-params.sh` locations).
fn local_params_dir() -> String {
    [
        std::env::var("YEW_SAPLING_PARAMS").unwrap_or_default(),
        format!(
            "{}/Library/Application Support/ZcashParams",
            std::env::var("HOME").unwrap()
        ),
        format!("{}/.zcash-params", std::env::var("HOME").unwrap()),
    ]
    .into_iter()
    .find(|d| {
        !d.is_empty()
            && std::path::Path::new(d)
                .join("sapling-spend.params")
                .is_file()
    })
    .expect("Sapling parameters on this machine (YEW_SAPLING_PARAMS)")
}

/// Warm the price windows (pool blocks until `pMint` is defined at the tip and at `R`), then
/// give node 0 at least $100 of YED (a $1000 mint, as W2) for the YED regressions.
async fn warm_and_fund_node_yed(
    dn: &Devnet,
    c: &mut CompactClient,
    v: &mut Validator,
    availability: &Availability,
) {
    let ref_lag = match availability {
        Availability::Present { info, .. } => {
            info.params.as_ref().map(|p| p.ref_lag).unwrap_or(2) as u32
        }
        Availability::Absent => 2,
    };
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
        let h = dn.mine_pool();
        wait_for_height(c, h).await;
    }
    let node_yed = |dn: &Devnet| {
        dn.node_json(0, &["yed_getbalance"])["confirmedCents"]
            .as_u64()
            .unwrap()
    };
    if node_yed(dn) < 10_000 {
        let mint = dn.node_json(0, &["yed_mint", "100000", "48", "", "", "false"]);
        let carrier = mint["carrierTxid"].as_str().unwrap().to_string();
        dn.wait_mempool(&carrier);
        dn.mine_pool();
        let start = Instant::now();
        let mint_txid = loop {
            let mp = dn.node_json(2, &["getrawmempool"]);
            if let Some(t) = mp.as_array().unwrap().first() {
                break t.as_str().unwrap().to_string();
            }
            assert!(start.elapsed() < Duration::from_secs(60), "no MINT");
            std::thread::sleep(Duration::from_millis(300));
        };
        dn.wait_mempool(&mint_txid);
        let h = dn.mine_pool();
        wait_for_height(c, h).await;
        assert!(node_yed(dn) >= 100_000, "node 0 minted");
    }
}

#[tokio::test]
#[ignore = "needs an ARMED regtest devnet of either line (scripts/devnet-s2.sh) and YEW_DEVNET=1"]
async fn s2_shielded_receive_send_memo_and_regressions() {
    use yew_core::build::yec_private::{confirm_yec_send, plan_yec_send, Funding};
    use yew_core::shielded_keys::SaplingAccount;
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return;
    }
    let line = env_or("YEW_DEVNET_LINE", "dd".into());
    let dn = Devnet::new("yb-devnet-s2", "351");
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:9418".into()), true).unwrap();
    let channel = server.connect().await.expect("connect to lightwalletd");
    let mut c = CompactClient::from_channel(channel.clone());
    let (mut v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .unwrap();
    assert!(availability.usable(), "{availability:?}");
    let mut timings = serde_json::Map::new();
    timings.insert("line".into(), line.clone().into());

    // Warm the price windows, then give node 0 YED for the regression (a $1000 mint, as W2).
    warm_and_fund_node_yed(&dn, &mut c, &mut v, &availability).await;
    let node_yed = |dn: &Devnet| {
        dn.node_json(0, &["yed_getbalance"])["confirmedCents"]
            .as_u64()
            .unwrap()
    };

    // 1. A seed whose private address node 0 funds (with a memo) BEFORE the wallet exists:
    //    the restore case. The birthday is the tip before the funding.
    let mnemonic = keys::generate_mnemonic(12).unwrap();
    let acct = SaplingAccount::from_mnemonic(&mnemonic, "", Network::Regtest).unwrap();
    let (_, zaddr) = acct.default_address();
    let birthday = c.latest_height().await.unwrap();
    let memo_in = "hello from node 0 to a YEW wallet";
    let zfund = z_fund_from_node0(&dn, &line, &zaddr, "2.0", memo_in);
    dn.wait_mempool(&zfund);
    dn.mine_pool();

    let dir = std::env::temp_dir().join(format!("yew-devnet-s2-{line}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a.sqlite").to_string_lossy().to_string();
    let mut w = Wallet::open(&path, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();

    // Transparent YEC and YED for the regressions.
    let a_addr = w.receive_address(false).unwrap();
    let tfund = dn.node(0, &["sendtoaddress", &a_addr.address_s, "3.0"]);
    let yfund = dn.node_json(0, &["yed_send", &a_addr.address_ye, "5000"])["txid"]
        .as_str()
        .unwrap()
        .to_string();
    dn.wait_mempool(&tfund);
    dn.wait_mempool(&yfund);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;

    let t = Instant::now();
    let (r, z) = sync_both(&mut w, &server, &mut c, &mut v).await;
    timings.insert(
        "restoreSyncMillis".into(),
        (t.elapsed().as_millis() as u64).into(),
    );
    timings.insert("restoreShieldedMillis".into(), z.millis.into());
    timings.insert("restoreBlocks".into(), z.blocks.into());
    println!("restore: transparent {r:?}\nprivate {z:?}");
    assert!(z.registered_now && z.sendable, "{z:?}");
    assert_eq!(z.received_notes, 1, "{z:?}");
    assert!(z.enhanced >= 1, "the memo was fetched: {z:?}");
    assert_eq!(r.yec.0 + r.yec.1, 300_000_000);
    assert_eq!(r.yed, (5_000, 0));
    let zb = w.shielded().unwrap().balance().unwrap();
    assert_eq!(
        (zb.total_zat, zb.spendable_zat, zb.sendable),
        (200_000_000, 200_000_000, true),
        "{zb:?}"
    );
    let zh = w.shielded().unwrap().history().unwrap();
    let row = zh
        .iter()
        .find(|x| txid_hex(&x.txid) == zfund)
        .expect("the funding in the private history");
    assert_eq!((row.delta_zat, row.memo.as_str()), (200_000_000, memo_in));

    // 2. The proving parameters: "download" from a local copy (file://), pinned SHA-256s.
    let params = dir.join("sapling-params");
    let local = local_params_dir();
    let t = Instant::now();
    let src = yew_core::sapling_params::ParamsSource::parse(&format!("file://{local}/")).unwrap();
    let st = yew_core::sapling_params::download(&src, &params, |_| {})
        .await
        .unwrap();
    assert!(st.present() && st.verified);
    timings.insert(
        "paramsCopyMillis".into(),
        (t.elapsed().as_millis() as u64).into(),
    );

    // 3. Shielded → shielded with a memo to node 0's Sapling address.
    let node_z = dn.node(0, &["z_getnewaddress", "sapling"]);
    let memo_out = "hi node 0, private YEC from YEW";
    let t = Instant::now();
    let plan = plan_yec_send(
        &mut w,
        &node_z,
        50_000_000,
        false,
        Some(memo_out),
        r.tip,
        r.branch_id,
    )
    .unwrap();
    timings.insert(
        "zzPlanMillis".into(),
        (t.elapsed().as_millis() as u64).into(),
    );
    assert!(!plan.reveals_shielded);
    let Funding::Shielded(p) = &plan.funding else {
        panic!("a ys1 recipient is paid from notes: {plan:?}")
    };
    assert_eq!((p.fee_zat, p.notes, p.change_zat), (10_000, 1, 149_990_000));
    let t = Instant::now();
    let sent = confirm_yec_send(&mut w, &mut c, &mut v, &plan, &params)
        .await
        .expect("z→z accepted by the gate and the node");
    timings.insert(
        "zzConfirmMillis".into(),
        (t.elapsed().as_millis() as u64).into(),
    );
    timings.insert("zzParamsLoadMillis".into(), sent.params_millis.into());
    timings.insert("zzProveMillis".into(), sent.prove_millis.into());
    let zz = sent.txid;
    println!("z→z {zz}");
    dn.wait_mempool(&zz);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let got = dn.node_json(0, &["z_listreceivedbyaddress", &node_z, "1"]);
    let note = got
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["txid"] == zz.as_str())
        .unwrap_or_else(|| panic!("node 0 received {zz}: {got}"));
    assert_eq!(note["amount"].as_f64().unwrap(), 0.5, "{note}");
    assert!(
        note["memo"]
            .as_str()
            .unwrap()
            .starts_with(&keys::hex(memo_out.as_bytes())),
        "{note}"
    );
    let t = Instant::now();
    let (r, z) = sync_both(&mut w, &server, &mut c, &mut v).await;
    timings.insert(
        "catchUpSyncMillis".into(),
        (t.elapsed().as_millis() as u64).into(),
    );
    assert!(z.sendable);
    let zb = w.shielded().unwrap().balance().unwrap();
    assert_eq!(zb.total_zat, 149_990_000, "{zb:?}");
    let row = w
        .shielded()
        .unwrap()
        .history()
        .unwrap()
        .into_iter()
        .find(|x| txid_hex(&x.txid) == zz)
        .unwrap();
    assert_eq!(
        (row.delta_zat, row.memo.as_str(), row.height > 0),
        (-50_010_000, memo_out, true)
    );

    // 4. Shielded → transparent: privacy first pays from notes and says it reveals them; a memo
    //    to a transparent address is refused.
    let node_t = dn.node(0, &["getnewaddress"]);
    assert!(plan_yec_send(
        &mut w,
        &node_t,
        1_000,
        false,
        Some("no"),
        r.tip,
        r.branch_id
    )
    .is_err());
    let plan = plan_yec_send(&mut w, &node_t, 30_000_000, false, None, r.tip, r.branch_id).unwrap();
    assert!(plan.reveals_shielded, "{plan:?}");
    // ZIP-317: one spend, two Sapling outputs (change + padding) and one transparent output are
    // three logical actions.
    let zt_fee = plan.fee_zat();
    assert!(matches!(plan.funding, Funding::Shielded(_)));
    assert_eq!(zt_fee, 15_000);
    let t = Instant::now();
    let sent = confirm_yec_send(&mut w, &mut c, &mut v, &plan, &params)
        .await
        .expect("z→t accepted");
    timings.insert(
        "ztConfirmMillis".into(),
        (t.elapsed().as_millis() as u64).into(),
    );
    timings.insert("ztParamsLoadMillis".into(), sent.params_millis.into());
    timings.insert("ztProveMillis".into(), sent.prove_millis.into());
    let zt = sent.txid;
    dn.wait_mempool(&zt);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    assert_eq!(
        dn.node(0, &["getreceivedbyaddress", &node_t, "1"])
            .parse::<f64>()
            .unwrap(),
        0.3
    );
    let (r, _) = sync_both(&mut w, &server, &mut c, &mut v).await;
    let zb = w.shielded().unwrap().balance().unwrap();
    let after_zt = 149_990_000 - 30_000_000 - zt_fee as u64;
    assert_eq!(zb.total_zat, after_zt, "{zb:?}");
    assert_eq!(
        r.yec.0 + r.yec.1,
        300_000_000,
        "transparent untouched by private sends"
    );

    // 5. Regression: more than the notes hold falls back to the transparent path, unchanged
    //    (same builder, same gate path); a direct transparent send and a YED send still work.
    let plan = plan_yec_send(
        &mut w,
        &node_t,
        150_000_000,
        false,
        None,
        r.tip,
        r.branch_id,
    )
    .unwrap();
    assert!(!plan.reveals_shielded);
    let Funding::Transparent(tp) = &plan.funding else {
        panic!("{plan:?}")
    };
    assert_eq!(tp.fee, FEE_ZAT);
    let tt = confirm_yec_send(&mut w, &mut c, &mut v, &plan, &params)
        .await
        .unwrap()
        .txid;
    dn.wait_mempool(&tt);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let (r, _) = sync_both(&mut w, &server, &mut c, &mut v).await;
    assert_eq!(r.yec.0 + r.yec.1, 300_000_000 - 150_000_000 - FEE_ZAT);
    // Node 0's transparent address in its Yellowback form (same key, `ye…` encoding).
    let node_ye = keys::encode_yellowback(
        Network::Regtest,
        &keys::parse_address(Network::Regtest, &node_t)
            .unwrap()
            .hash(),
    );
    let node_yed_before = node_yed(&dn);
    let yp = yed_transfer::build_yed_transfer(&w, &[(node_ye.clone(), 1_234)], r.tip, r.branch_id)
        .unwrap();
    let (yt, val) = yed_transfer::broadcast(&w, &mut c, &mut v, &yp)
        .await
        .expect("YED transfer accepted");
    assert_eq!((val.verdict.as_str(), val.burned), ("ok", 0));
    dn.wait_mempool(&yt);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let (r, _) = sync_both(&mut w, &server, &mut c, &mut v).await;
    assert_eq!(r.yed.0, 5_000 - 1_234, "{r:?}");
    assert_eq!(
        node_yed(&dn),
        node_yed_before + 1_234,
        "node 0 received the YED"
    );
    let yec_before = r.yec.0 + r.yec.1;
    let p = yec_send::build_yec_send(&w, &node_t, 10_000_000, false, r.tip, r.branch_id).unwrap();
    let t2 = yec_send::broadcast(&w, &mut c, &mut v, &p).await.unwrap();
    dn.wait_mempool(&t2);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let (r, _) = sync_both(&mut w, &server, &mut c, &mut v).await;
    assert_eq!(r.yec.0 + r.yec.1, yec_before - 10_000_000 - p.fee, "{r:?}");
    let zb = w.shielded().unwrap().balance().unwrap();
    assert_eq!(
        zb.total_zat, after_zt,
        "private untouched by YEC/YED: {zb:?}"
    );

    // 6. A second restore of the same seed into a fresh file reproduces the private balance
    //    and the memos; no file under either private store holds the spending key.
    let path2 = dir.join("b.sqlite").to_string_lossy().to_string();
    let mut w2 = Wallet::open(&path2, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();
    let t = Instant::now();
    let (_, z2) = sync_both(&mut w2, &server, &mut c, &mut v).await;
    timings.insert(
        "secondRestoreMillis".into(),
        (t.elapsed().as_millis() as u64).into(),
    );
    assert!(z2.sendable);
    assert_eq!(w2.shielded().unwrap().balance().unwrap(), zb);
    let memos: Vec<String> = w2
        .shielded()
        .unwrap()
        .history()
        .unwrap()
        .into_iter()
        .map(|x| x.memo)
        .collect();
    assert!(memos.iter().any(|m| m == memo_in), "{memos:?}");
    assert!(
        memos.iter().any(|m| m == memo_out),
        "sent memo recovered by the OVK: {memos:?}"
    );
    assert_no_spending_key(&dir.join("shielded"), &acct);

    let out = serde_json::Value::Object(timings);
    println!("S2 devnet ({line}) ok: {out}");
    if let Ok(f) = std::env::var("YEW_DEVNET_TIMINGS") {
        std::fs::write(f, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- yew-shielded plan S4: move YEC between the own public and private balances -------------

#[tokio::test]
#[ignore = "needs an ARMED regtest devnet of either line (scripts/devnet-s2.sh) and YEW_DEVNET=1"]
async fn s4_move_to_private_and_public_then_mint() {
    use yew_core::build::mint::MintError;
    use yew_core::build::yec_move::{plan_move, Direction};
    use yew_core::build::yec_private::{confirm_yec_send, Funding};
    use yew_core::store::MintState;
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return;
    }
    let line = env_or("YEW_DEVNET_LINE", "dd".into());
    let dn = Devnet::new("yb-devnet-s2", "351");
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:9418".into()), true).unwrap();
    let channel = server.connect().await.expect("connect to lightwalletd");
    let mut c = CompactClient::from_channel(channel.clone());
    let (mut v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .unwrap();
    assert!(availability.usable(), "{availability:?}");
    warm_and_fund_node_yed(&dn, &mut c, &mut v, &availability).await;

    // A fresh wallet with three public coins (12 + 1 YEC and one reserve-sized coin) and $50.
    let mnemonic = keys::generate_mnemonic(12).unwrap();
    let birthday = c.latest_height().await.unwrap();
    let dir = std::env::temp_dir().join(format!("yew-devnet-s4-{line}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("m.sqlite").to_string_lossy().to_string();
    let mut w = Wallet::open(&path, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();
    let a = w.receive_address(false).unwrap();
    let mut funds = vec![];
    for amount in ["12.0", "1.0", "0.001"] {
        funds.push(dn.node(0, &["sendtoaddress", &a.address_s, amount]));
    }
    funds.push(
        dn.node_json(0, &["yed_send", &a.address_ye, "5000"])["txid"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    for t in &funds {
        dn.wait_mempool(t);
    }
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let (r, z) = sync_both(&mut w, &server, &mut c, &mut v).await;
    assert!(z.sendable, "{z:?}");
    const RESERVE: i64 = 100_000; // the small coin: within the reserve target, so reserved
    assert_eq!(r.yec, (1_300_000_000, RESERVE), "{r:?}");
    assert_eq!(r.yed, (5_000, 0));
    let params = dir.join("sapling-params");
    let src =
        yew_core::sapling_params::ParamsSource::parse(&format!("file://{}/", local_params_dir()))
            .unwrap();
    assert!(yew_core::sapling_params::download(&src, &params, |_| {})
        .await
        .unwrap()
        .present());
    let own_z = w.shielded().unwrap().default_address().1;

    // 1. Move 1 YEC to private: plain YEC only (the 1-YEC coin falls short of amount + fee, so
    //    both YEC coins), never the reserve or the token; change back to public.
    let plan = plan_move(&mut w, Direction::ToPrivate, Some(100_000_000), r.tip).unwrap();
    assert!(!plan.reveals_shielded);
    let Funding::Shield(s) = &plan.funding else {
        panic!("{plan:?}")
    };
    assert_eq!(s.to, own_z);
    assert_eq!((s.inputs.len(), s.fee), (2, 20_000), "{s:?}");
    assert!(s.inputs.iter().all(|u| u.class == UtxoClass::Yec));
    let shield_fee = s.fee;
    let sent = confirm_yec_send(&mut w, &mut c, &mut v, &plan, &params)
        .await
        .expect("shield accepted by the gate and the node");
    println!("t→z {} (prove {} ms)", sent.txid, sent.prove_millis);
    let raw = dn.node_json(0, &["getrawtransaction", &sent.txid, "1"]);
    assert_eq!(raw["vin"].as_array().unwrap().len(), 2, "{raw}");
    assert!(
        !raw["vShieldedOutput"].as_array().unwrap().is_empty(),
        "{raw}"
    );
    assert!(
        raw["vShieldedSpend"].as_array().unwrap().is_empty(),
        "{raw}"
    );
    dn.wait_mempool(&sent.txid);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let (r, z) = sync_both(&mut w, &server, &mut c, &mut v).await;
    assert!(z.sendable && z.received_notes == 1, "{z:?}");
    let zb = w.shielded().unwrap().balance().unwrap();
    assert_eq!((zb.total_zat, zb.spendable_zat), (100_000_000, 100_000_000));
    let public = 1_300_000_000 - 100_000_000 - shield_fee;
    assert_eq!(r.yec, (public, RESERVE), "fee reserve untouched: {r:?}");
    assert_eq!(r.yed, (5_000, 0), "YED untouched");

    // 2. Move 0.5 YEC back to public: to the wallet's own address, the amount revealed.
    let plan = plan_move(&mut w, Direction::ToPublic, Some(50_000_000), r.tip).unwrap();
    assert!(plan.reveals_shielded);
    let Funding::Shielded(p) = &plan.funding else {
        panic!("{plan:?}")
    };
    assert!(p.transparent_recipient && w.row_for_address(&p.to).unwrap().is_some());
    let unshield_fee = p.fee_zat as i64;
    assert_eq!(unshield_fee, 15_000);
    let sent = confirm_yec_send(&mut w, &mut c, &mut v, &plan, &params)
        .await
        .expect("unshield accepted");
    dn.wait_mempool(&sent.txid);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let (r, _) = sync_both(&mut w, &server, &mut c, &mut v).await;
    let private = 100_000_000 - 50_000_000 - unshield_fee;
    assert_eq!(
        w.shielded().unwrap().balance().unwrap().total_zat as i64,
        private
    );
    let public = public + 50_000_000;
    assert_eq!(r.yec, (public, RESERVE), "{r:?}");
    assert_eq!(r.yed, (5_000, 0));

    // 3. The S3 hint path: all public YEC to private, so a mint lacks public YEC; move exactly
    //    the shortfall to public; the mint then goes through.
    let plan = plan_move(&mut w, Direction::ToPrivate, None, r.tip).unwrap();
    let Funding::Shield(s) = &plan.funding else {
        panic!("{plan:?}")
    };
    assert_eq!((s.change, s.amount + s.fee), (0, public), "{s:?}");
    let all_in = s.amount;
    let sent = confirm_yec_send(&mut w, &mut c, &mut v, &plan, &params)
        .await
        .expect("move all to private");
    dn.wait_mempool(&sent.txid);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let (r, _) = sync_both(&mut w, &server, &mut c, &mut v).await;
    assert_eq!(r.yec, (0, RESERVE), "{r:?}");
    let private = private + all_in;
    assert_eq!(
        w.shielded().unwrap().balance().unwrap().total_zat as i64,
        private
    );
    let est = w.mint_estimate(&mut v, 10_000, 48, r.tip).await.unwrap();
    assert!(!est.affordable(), "{est:?}");
    let shortfall = est.total_zat - est.available_zat;
    assert!(matches!(
        w.mint_start(&mut c, &mut v, 10_000, 48, None, r.tip, r.branch_id)
            .await
            .unwrap_err(),
        yew_core::wallet::WalletError::Mint(MintError::Unaffordable { .. })
    ));
    let plan = plan_move(&mut w, Direction::ToPublic, Some(shortfall), r.tip).unwrap();
    let shortfall_fee = plan.fee_zat();
    let sent = confirm_yec_send(&mut w, &mut c, &mut v, &plan, &params)
        .await
        .expect("unshield the shortfall");
    dn.wait_mempool(&sent.txid);
    let h = dn.mine_pool();
    wait_for_height(&mut c, h).await;
    let (r, _) = sync_both(&mut w, &server, &mut c, &mut v).await;
    assert_eq!(r.yec, (shortfall, RESERVE), "{r:?}");
    let est = w.mint_estimate(&mut v, 10_000, 48, r.tip).await.unwrap();
    assert!(est.affordable(), "{est:?}");
    let id = w
        .mint_start(&mut c, &mut v, 10_000, 48, None, r.tip, r.branch_id)
        .await
        .expect("mint after the unshield");
    let carrier = txid_hex(&w.store.mint(id).unwrap().unwrap().carrier_txid);
    confirm(&dn, &mut c, &carrier).await;
    let r = sync(&mut w, &mut c, v.client_mut()).await.unwrap();
    let f = w
        .mint_finish(&mut c, &mut v, id, r.tip, r.branch_id)
        .await
        .unwrap();
    assert_eq!(f.validation.verdict, "ok");
    confirm(&dn, &mut c, &f.txid).await;
    let (r, _) = sync_both(&mut w, &server, &mut c, &mut v).await;
    assert_eq!(mint_state(&w, id), MintState::Done);
    assert_eq!(r.yed, (5_000 + 10_000, 0), "{r:?}");
    let private = private - shortfall - shortfall_fee;
    assert_eq!(
        w.shielded().unwrap().balance().unwrap().total_zat as i64,
        private,
        "the mint never touched private YEC"
    );
    println!(
        "S4 devnet ({line}) ok: shield fee {shield_fee}, unshield fee {unshield_fee}, mint shortfall {shortfall} zat"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- yew-shielded plan S5: restore with a birthday, reorgs, interrupted sync -----------------

/// One S5 test's devnet handles (the S2 setup without the YED warm-up).
struct S5 {
    line: String,
    dn: Devnet,
    server: Server,
    c: CompactClient,
    v: Validator,
    timings: serde_json::Map<String, Value>,
}

async fn s5_setup() -> Option<S5> {
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return None;
    }
    let line = env_or("YEW_DEVNET_LINE", "dd".into());
    let dn = Devnet::new("yb-devnet-s2", "351");
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:9418".into()), true).unwrap();
    let channel = server.connect().await.expect("connect to lightwalletd");
    let c = CompactClient::from_channel(channel.clone());
    let (v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .unwrap();
    assert!(availability.usable(), "{availability:?}");
    let mut timings = serde_json::Map::new();
    timings.insert("line".into(), line.clone().into());
    Some(S5 {
        line,
        dn,
        server,
        c,
        v,
        timings,
    })
}

fn time_into(t: &mut serde_json::Map<String, Value>, key: &str, since: Instant) -> u64 {
    let ms = since.elapsed().as_millis() as u64;
    t.insert(key.into(), ms.into());
    ms
}

impl S5 {
    /// Print the timings and write them beside the S2 file (`s5-<test>-<line>.json`).
    fn finish(self, test: &str) {
        let out = Value::Object(self.timings);
        println!("S5 {test} ({}) ok: {out}", self.line);
        if let Ok(f) = std::env::var("YEW_DEVNET_TIMINGS") {
            let dir = std::path::Path::new(&f).parent().unwrap().to_path_buf();
            let path = dir.join(format!("s5-{test}-{}.json", self.line));
            std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
        }
    }
}

fn s5_dir(test: &str, line: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("yew-devnet-{test}-{line}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_at(dir: &std::path::Path, name: &str, mnemonic: &str, birthday: Option<u64>) -> Wallet {
    let path = dir
        .join(format!("{name}.sqlite"))
        .to_string_lossy()
        .to_string();
    Wallet::open(&path, Network::Regtest, mnemonic, "", birthday).unwrap()
}

/// `(txid display hex, height, delta, memo, expired)` of every private history row, sorted.
fn private_rows(w: &Wallet) -> Vec<(String, u64, i64, String, bool)> {
    let mut rows: Vec<_> = w
        .shielded()
        .unwrap()
        .history()
        .unwrap()
        .into_iter()
        .map(|x| (txid_hex(&x.txid), x.height, x.delta_zat, x.memo, x.expired))
        .collect();
    rows.sort();
    rows
}

/// The devnet's node count (`devnet.json`).
fn node_count(dn: &Devnet) -> usize {
    let s = std::fs::read_to_string(format!("{}/devnet.json", dn.dir)).unwrap();
    serde_json::from_str::<Value>(&s).unwrap()["num_nodes"]
        .as_u64()
        .unwrap() as usize
}

/// Node `n`'s P2P address (`port=` in its `ycash.conf`).
fn p2p_addr(dn: &Devnet, n: usize) -> String {
    let conf = std::fs::read_to_string(format!("{}/node{n}/ycash.conf", dn.dir)).unwrap();
    let port = conf
        .lines()
        .find_map(|l| l.strip_prefix("port="))
        .unwrap()
        .trim()
        .to_string();
    format!("127.0.0.1:{port}")
}

fn tip_of(dn: &Devnet, n: usize) -> (u64, String) {
    let h = dn.node(n, &["getblockcount"]).parse().unwrap();
    (h, dn.node(n, &["getbestblockhash"]))
}

/// Wait until every node in `nodes` stands on `hash`.
fn wait_tip(dn: &Devnet, nodes: &[usize], hash: &str) {
    let start = Instant::now();
    while !nodes
        .iter()
        .all(|&n| dn.node(n, &["getbestblockhash"]) == hash)
    {
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "nodes {nodes:?} never reached {hash}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Mine `n` blocks on `node` alone, after re-quoting the pools; no devnet-wide block sync (the
/// network may be split). Returns the node's new tip.
fn mine_alone(dn: &Devnet, node: usize, n: u64) -> (u64, String) {
    let price = dn.price.borrow().clone();
    dn.run(&["price", &price]);
    dn.node(node, &["generate", &n.to_string()]);
    tip_of(dn, node)
}

fn connected(dn: &Devnet, a: usize, b: usize) -> bool {
    let addr = p2p_addr(dn, b);
    dn.node_json(a, &["getpeerinfo"])
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["addr"].as_str() == Some(addr.as_str()))
}

/// Split `node` off the devnet: it bans 127.0.0.1 (every peer), as x402-ycash's devnet suite
/// does. [`Rejoin`] undoes it.
fn isolate(dn: &Devnet, node: usize) {
    dn.node(node, &["setban", "127.0.0.1", "add", "3600"]);
    let start = Instant::now();
    while !dn
        .node_json(node, &["getpeerinfo"])
        .as_array()
        .unwrap()
        .is_empty()
    {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "node{node} kept its peers"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Re-add every missing pair of peers (x402-ycash X-F105: v4.5.0 drops a peer that relays
/// transactions expired by two blocks, so a reorg past an expiry can split the mesh).
fn heal_mesh(dn: &Devnet) {
    let n = node_count(dn);
    for a in 0..n {
        for b in (a + 1)..n {
            if !connected(dn, a, b) && !connected(dn, b, a) {
                let _ = dn.node_try(a, &["addnode", &p2p_addr(dn, b), "onetry"]);
            }
        }
    }
}

/// Unbans and reconnects an [`isolate`]d node when dropped (also on a failed assertion).
struct Rejoin<'a> {
    dn: &'a Devnet,
    node: usize,
    done: bool,
}

impl Rejoin<'_> {
    fn now(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        let _ = self
            .dn
            .node_try(self.node, &["setban", "127.0.0.1", "remove"]);
        let _ = self.dn.node_try(self.node, &["clearbanned"]);
        for m in (0..node_count(self.dn)).filter(|&m| m != self.node) {
            let addr = p2p_addr(self.dn, m);
            let _ = self.dn.node_try(self.node, &["addnode", &addr, "onetry"]);
        }
    }
}

impl Drop for Rejoin<'_> {
    fn drop(&mut self) {
        self.now();
    }
}

/// Wait until lightwalletd's tip is node 0's tip, block hash included (it follows a reorg by
/// noticing the next block's `prev_hash`, one block back at a time).
async fn wait_lwd_follows(dn: &Devnet, c: &mut CompactClient) -> u64 {
    let start = Instant::now();
    loop {
        let (h, hash) = tip_of(dn, 0);
        if c.latest_height().await.unwrap() == h
            && txid_hex(&c.block_hash(h).await.unwrap()) == hash
        {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            return h;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "lightwalletd did not follow node 0 to {h} {hash}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Item 2(a): restore from seed with a birthday. Four private receipts with memos in four
/// consecutive blocks (two before the birthday, one in the birthday block, one after) and two
/// public ones (before and in the birthday block); then three restores of the same seed.
#[tokio::test]
#[ignore = "needs an ARMED regtest devnet of either line (scripts/devnet-s2.sh) and YEW_DEVNET=1"]
async fn s5_restore_with_birthday() {
    use yew_core::shielded_keys::SaplingAccount;
    let Some(mut s) = s5_setup().await else {
        return;
    };
    let line = s.line.clone();
    let mnemonic = keys::generate_mnemonic(12).unwrap();
    let acct = SaplingAccount::from_mnemonic(&mnemonic, "", Network::Regtest).unwrap();
    let (_, zaddr) = acct.default_address();
    let dir = s5_dir("s5-restore", &line);
    let taddr = open_at(&dir, "probe", &mnemonic, Some(1))
        .receive_address(false)
        .unwrap()
        .address_s;

    let memos = [
        "two blocks before the birthday",
        "one block before the birthday",
        "in the birthday block",
        "after the birthday",
    ];
    let amounts: [u64; 4] = [110_000_000, 120_000_000, 130_000_000, 140_000_000];
    let public: [Option<&str>; 4] = [None, Some("0.7"), Some("0.8"), None];
    let coins = node0_coins(&s.dn, 4);
    let mut heights = vec![];
    let mut txids = vec![];
    for i in 0..4 {
        let z = z_send_from_node0(
            &s.dn,
            &line,
            &coins[i],
            &zaddr,
            &format!("{}", amounts[i] as f64 / 1e8),
            memos[i],
        );
        s.dn.wait_mempool(&z);
        if let Some(a) = public[i] {
            let t = s.dn.node(2, &["sendtoaddress", &taddr, a]);
            s.dn.wait_mempool(&t);
        }
        heights.push(s.dn.mine_pool());
        txids.push(z);
    }
    assert!(heights.windows(2).all(|w| w[1] == w[0] + 1), "{heights:?}");
    wait_for_height(&mut s.c, heights[3]).await;
    let birthday = heights[2];

    // (name, birthday, notes expected, public zat expected)
    let cases: [(&str, Option<u64>, &[usize], i64); 3] = [
        ("at-birthday", Some(birthday), &[2, 3], 80_000_000),
        ("birthday-after-a-note", Some(birthday + 1), &[3], 0),
        ("no-birthday", None, &[0, 1, 2, 3], 150_000_000),
    ];
    for (name, bday, expect, public_zat) in cases {
        let mut w = open_at(&dir, name, &mnemonic, bday);
        let t = Instant::now();
        let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
        time_into(&mut s.timings, &format!("{name}Millis"), t);
        s.timings.insert(format!("{name}Blocks"), z.blocks.into());
        println!("restore {name} (birthday {bday:?}): {z:?}");
        assert!(z.registered_now && z.sendable, "{name}: {z:?}");
        assert_eq!(z.received_notes, expect.len() as u64, "{name}: {z:?}");
        let want: u64 = expect.iter().map(|&i| amounts[i]).sum();
        let zb = w.shielded().unwrap().balance().unwrap();
        assert_eq!(
            (zb.total_zat, zb.spendable_zat),
            (want, want),
            "{name}: {zb:?}"
        );
        let mut got: Vec<(String, u64, i64, String)> = private_rows(&w)
            .into_iter()
            .map(|(t, h, d, m, _)| (t, h, d, m))
            .collect();
        got.sort();
        let mut exp: Vec<(String, u64, i64, String)> = expect
            .iter()
            .map(|&i| {
                (
                    txids[i].clone(),
                    heights[i],
                    amounts[i] as i64,
                    memos[i].to_string(),
                )
            })
            .collect();
        exp.sort();
        assert_eq!(
            got, exp,
            "{name}: exactly the notes at or after the birthday, all memos"
        );
        // The public side follows the same birthday rule (`GetAddressUtxos` from the birthday).
        assert_eq!(r.yec.0 + r.yec.1, public_zat, "{name}: {r:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    s.finish("restore");
}

/// Item 2(b): reorgs under a synced wallet, with lightwalletd-dd following node 0.
///
/// - R1: the block holding a private and a public receipt is invalidated on every node, the
///   wallet syncs while the node stands below it, the receipts are re-mined in a competing
///   block, the old block is reconsidered (shorter branch, no switch back).
/// - R2: a pool node split off mines a longer branch without the block holding a private and a
///   public receipt; the receipts disappear, then reappear when re-mined.
/// - R3: a private send mined on the main side is dropped by a longer branch that runs past its
///   expiry height; its notes come back, and they spend again.
#[tokio::test]
#[ignore = "needs an ARMED regtest devnet of either line (scripts/devnet-s2.sh) and YEW_DEVNET=1"]
async fn s5_reorg_private_and_public() {
    use yew_core::build::yec_private::{confirm_yec_send, plan_yec_send, Funding};
    let Some(mut s) = s5_setup().await else {
        return;
    };
    let line = s.line.clone();
    let n = node_count(&s.dn);
    let all: Vec<usize> = (0..n).collect();
    const LONER: usize = 4;
    let main_side: Vec<usize> = all.iter().copied().filter(|&m| m != LONER).collect();
    let dir = s5_dir("s5-reorg", &line);
    let mnemonic = keys::generate_mnemonic(12).unwrap();
    let birthday = s.c.latest_height().await.unwrap();
    let mut w = open_at(&dir, "w", &mnemonic, Some(birthday));
    let zaddr = w.shielded().unwrap().default_address().1;
    let taddr = w.receive_address(false).unwrap().address_s;
    let coins = node0_coins(&s.dn, 3);
    let z0 = z_fund_from_node0(&s.dn, &line, &zaddr, "2.0", "base");
    let t0 = s.dn.node(2, &["sendtoaddress", &taddr, "1.0"]);
    s.dn.wait_mempool(&z0);
    s.dn.wait_mempool(&t0);
    let h = s.dn.mine_pool();
    wait_for_height(&mut s.c, h).await;
    let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    assert!(z.sendable);
    let zbal = |w: &Wallet| {
        let b = w.shielded().unwrap().balance().unwrap();
        (b.total_zat, b.spendable_zat)
    };
    assert_eq!(zbal(&w), (200_000_000, 200_000_000));
    assert_eq!(r.yec.0 + r.yec.1, 100_000_000);
    let params = dir.join("sapling-params");
    let src =
        yew_core::sapling_params::ParamsSource::parse(&format!("file://{}/", local_params_dir()))
            .unwrap();
    assert!(yew_core::sapling_params::download(&src, &params, |_| {})
        .await
        .unwrap()
        .present());

    // ---- R1: invalidateblock / competing block / reconsiderblock -----------------------------
    let z1 = z_send_from_node0(&s.dn, &line, &coins[0], &zaddr, "0.5", "r1: re-mined");
    let t1 = s.dn.node(2, &["sendtoaddress", &taddr, "0.25"]);
    s.dn.wait_mempool(&z1);
    s.dn.wait_mempool(&t1);
    let hb = s.dn.mine_pool();
    wait_for_height(&mut s.c, hb).await;
    let (r, _) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    assert_eq!(zbal(&w), (250_000_000, 250_000_000));
    assert_eq!(r.yec.0 + r.yec.1, 125_000_000);
    let block_b = s.dn.node(0, &["getblockhash", &hb.to_string()]);
    for &m in &all {
        s.dn.node(m, &["invalidateblock", &block_b]);
    }
    let below = s.dn.node(0, &["getblockhash", &(hb - 1).to_string()]);
    wait_tip(&s.dn, &all, &below);
    // A sync while the node stands below the wallet's scanned height (lightwalletd has not
    // seen a new block yet, so it still serves B): nothing may fail or double.
    let t = Instant::now();
    let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    time_into(&mut s.timings, "r1DuringSyncMillis", t);
    let during = (zbal(&w), r.yec);
    println!(
        "R1 during the reorg: private {:?} public {:?}; {z:?}",
        during.0, during.1
    );
    s.timings.insert(
        "r1DuringObserved".into(),
        format!(
            "private {:?} public {:?} reorgs {}",
            during.0, during.1, z.reorgs
        )
        .into(),
    );
    assert!(during.0 .0 <= 250_000_000 && r.yec.0 + r.yec.1 <= 125_000_000);
    s.dn.wait_mempool(&z1);
    s.dn.wait_mempool(&t1);
    let hb2 = s.dn.mine_pool();
    assert_eq!(hb2, hb, "the competing block sits at B's height");
    let mined: Vec<String> = s.dn.node_json(
        0,
        &[
            "getblock",
            &s.dn.node(0, &["getblockhash", &hb.to_string()]),
        ],
    )["tx"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_string())
        .collect();
    assert!(
        mined.contains(&z1) && mined.contains(&t1),
        "re-mined in B': {mined:?}"
    );
    s.dn.mine_pool();
    wait_lwd_follows(&s.dn, &mut s.c).await;
    let t = Instant::now();
    let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    time_into(&mut s.timings, "r1AfterSyncMillis", t);
    println!("R1 after: {z:?}");
    assert!(
        z.reorgs >= 1 && z.sendable,
        "the light library rewound: {z:?}"
    );
    assert_eq!(zbal(&w), (250_000_000, 250_000_000), "nothing doubled");
    assert_eq!(r.yec.0 + r.yec.1, 125_000_000, "{r:?}");
    let rows = private_rows(&w);
    assert_eq!(rows.iter().filter(|x| x.0 == z1).count(), 1, "{rows:?}");
    assert!(rows
        .iter()
        .any(|x| x.0 == z1 && x.1 == hb && x.3 == "r1: re-mined"));
    let t1_row = w
        .store
        .history_row(&txid_from_hex(&t1).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!((t1_row.height, t1_row.pending), (hb, false), "{t1_row:?}");
    let tip_before = tip_of(&s.dn, 0);
    for &m in &all {
        s.dn.node(m, &["reconsiderblock", &block_b]);
    }
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        tip_of(&s.dn, 0),
        tip_before,
        "B is the shorter branch: no switch back"
    );
    let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    assert_eq!(
        (z.reorgs, zbal(&w), r.yec.0 + r.yec.1),
        (0, (250_000_000, 250_000_000), 125_000_000)
    );

    // ---- R2: a receipt dropped by a longer branch, then re-mined -----------------------------
    let mut rejoin = Rejoin {
        dn: &s.dn,
        node: LONER,
        done: false,
    };
    isolate(&s.dn, LONER);
    let z2 = z_send_from_node0(
        &s.dn,
        &line,
        &coins[1],
        &zaddr,
        "0.75",
        "r2: dropped, then back",
    );
    let t2 = s.dn.node(2, &["sendtoaddress", &taddr, "0.4"]);
    s.dn.wait_mempool_on(&z2, &[0, 2, 3]);
    s.dn.wait_mempool_on(&t2, &[0, 2, 3]);
    let (h2, main_tip) = mine_alone(&s.dn, 2, 1);
    wait_tip(&s.dn, &main_side, &main_tip);
    wait_lwd_follows(&s.dn, &mut s.c).await;
    let (r, _) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    assert_eq!(zbal(&w), (325_000_000, 325_000_000));
    assert_eq!(r.yec.0 + r.yec.1, 165_000_000);
    let (lh, loner_tip) = mine_alone(&s.dn, LONER, 2);
    assert_eq!(lh, h2 + 1);
    rejoin.now();
    wait_tip(&s.dn, &all, &loner_tip);
    wait_lwd_follows(&s.dn, &mut s.c).await;
    let t = Instant::now();
    let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    time_into(&mut s.timings, "r2DroppedSyncMillis", t);
    let dropped = (zbal(&w), r.yec, private_rows(&w));
    println!(
        "R2 dropped: private {:?} public {:?}; {z:?}\n{:?}",
        dropped.0, dropped.1, dropped.2
    );
    assert!(z.reorgs >= 1, "{z:?}");
    assert_eq!(
        dropped.0 .1, 250_000_000,
        "the dropped receipt is not spendable"
    );
    s.timings.insert(
        "r2DroppedObserved".into(),
        format!(
            "private (total, spendable) {:?} public {:?}",
            dropped.0, dropped.1
        )
        .into(),
    );
    // The receipt is unmined again but back in the mempools (resurrected by the switch): the
    // store keeps its note as pending incoming, out of the spendable balance, until it is mined
    // again or expires. Its history row shows height 0.
    let b = w.shielded().unwrap().balance().unwrap();
    assert_eq!(
        (b.total_zat, b.spendable_zat, b.pending_incoming_zat),
        (325_000_000, 250_000_000, 75_000_000),
        "the dropped receipt is pending, not spendable: {b:?}"
    );
    assert!(
        dropped.2.iter().any(|x| x.0 == z2 && x.1 == 0),
        "unmined in history"
    );
    // The public history re-reads its last ten blocks: the dropped receipt is pending again,
    // not confirmed at a height it no longer has.
    let t2_row = w
        .store
        .history_row(&txid_from_hex(&t2).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (t2_row.height, t2_row.pending, t2_row.yec_delta),
        (0, true, 40_000_000),
        "{t2_row:?}"
    );
    assert_eq!(
        r.yec.0 + r.yec.1,
        125_000_000,
        "the dropped public receipt left too"
    );
    // Re-mined: node 2 resurrected both into its mempool when it switched branches.
    s.dn.wait_mempool_on(&z2, &[2]);
    s.dn.wait_mempool_on(&t2, &[2]);
    s.dn.run(&["price", &s.dn.price.borrow().clone()]);
    s.dn.run(&["mine", "1", "2"]);
    wait_lwd_follows(&s.dn, &mut s.c).await;
    let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    println!("R2 re-mined: {z:?}");
    assert_eq!(zbal(&w), (325_000_000, 325_000_000), "back once re-mined");
    assert_eq!(r.yec.0 + r.yec.1, 165_000_000, "{r:?}");
    let rows = private_rows(&w);
    let z2rows: Vec<_> = rows.iter().filter(|x| x.0 == z2).collect();
    assert_eq!(z2rows.len(), 1, "{rows:?}");
    assert_eq!(
        (z2rows[0].1 > h2, z2rows[0].3.as_str()),
        (true, "r2: dropped, then back")
    );
    let t2_row = w
        .store
        .history_row(&txid_from_hex(&t2).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (t2_row.height, t2_row.pending),
        (z2rows[0].1, false),
        "{t2_row:?}"
    );

    drop(rejoin);

    // ---- R3: a private send dropped by a branch that runs past its expiry ---------------------
    let before = zbal(&w);
    let (public_before, tip) = (r.yec.0 + r.yec.1, r.tip);
    let mut rejoin = Rejoin {
        dn: &s.dn,
        node: LONER,
        done: false,
    };
    isolate(&s.dn, LONER);
    let node_z = s.dn.node(0, &["z_getnewaddress", "sapling"]);
    let plan = plan_yec_send(
        &mut w,
        &node_z,
        60_000_000,
        false,
        Some("r3: dropped send"),
        tip,
        r.branch_id,
    )
    .unwrap();
    let Funding::Shielded(p) = &plan.funding else {
        panic!("{plan:?}")
    };
    let (expiry, fee) = (p.expiry_height as u64, p.fee_zat);
    let sent = confirm_yec_send(&mut w, &mut s.c, &mut s.v, &plan, &params)
        .await
        .expect("z→z accepted");
    s.dn.wait_mempool_on(&sent.txid, &[0, 2, 3]);
    let (h3, main_tip) = mine_alone(&s.dn, 2, 1);
    wait_tip(&s.dn, &main_side, &main_tip);
    wait_lwd_follows(&s.dn, &mut s.c).await;
    let (_, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    assert!(z.sendable);
    assert_eq!(zbal(&w).0, before.0 - 60_000_000 - fee, "the send is mined");
    assert!(private_rows(&w)
        .iter()
        .any(|x| x.0 == sent.txid && x.1 == h3));
    // The loner runs past the expiry height: the block after nExpiryHeight drops the send from
    // every mempool it was resurrected into.
    let mut loner = tip_of(&s.dn, LONER);
    assert_eq!(loner.0, h3 - 1);
    while loner.0 <= expiry {
        loner = mine_alone(&s.dn, LONER, (expiry + 1 - loner.0).min(10));
    }
    s.timings
        .insert("r3BranchBlocks".into(), (loner.0 - (h3 - 1)).into());
    rejoin.now();
    wait_tip(&s.dn, &all, &loner.1);
    std::thread::sleep(Duration::from_secs(2));
    heal_mesh(&s.dn);
    for &m in &all {
        let mp = s.dn.node_json(m, &["getrawmempool"]);
        assert!(
            !mp.as_array()
                .unwrap()
                .iter()
                .any(|t| t.as_str() == Some(sent.txid.as_str())),
            "node{m} still holds the expired send"
        );
    }
    wait_lwd_follows(&s.dn, &mut s.c).await;
    let t = Instant::now();
    let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    time_into(&mut s.timings, "r3ExpiredSyncMillis", t);
    println!("R3 after expiry: {z:?} {:?}", zbal(&w));
    assert!(z.reorgs >= 1 && z.sendable, "{z:?}");
    assert_eq!(
        zbal(&w),
        before,
        "the dropped send's notes are back, nothing doubled"
    );
    assert_eq!(
        r.yec.0 + r.yec.1,
        public_before,
        "the public side is untouched"
    );
    let rows = private_rows(&w);
    let srow = rows
        .iter()
        .find(|x| x.0 == sent.txid)
        .expect("the send stays in history");
    assert_eq!((srow.1, srow.4), (0, true), "unmined and expired: {srow:?}");
    // The returned notes spend again.
    let plan = plan_yec_send(
        &mut w,
        &node_z,
        60_000_000,
        false,
        Some("r3: sent again"),
        r.tip,
        r.branch_id,
    )
    .unwrap();
    let again = confirm_yec_send(&mut w, &mut s.c, &mut s.v, &plan, &params)
        .await
        .expect("the returned notes spend");
    s.dn.wait_mempool(&again.txid);
    let h = s.dn.mine_pool();
    wait_for_height(&mut s.c, h).await;
    let got =
        s.dn.node_json(0, &["z_listreceivedbyaddress", &node_z, "1"]);
    let notes = got.as_array().unwrap();
    assert_eq!(
        notes.len(),
        1,
        "node 0 holds exactly the second send: {got}"
    );
    assert_eq!(notes[0]["txid"].as_str(), Some(again.txid.as_str()));
    let (_, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    assert!(z.sendable);
    assert_eq!(zbal(&w).0, before.0 - 60_000_000 - plan.fee_zat() as u64);
    drop(rejoin);
    let _ = std::fs::remove_dir_all(&dir);
    s.finish("reorg");
}

/// Item 2(c): an interrupted private sync resumes to the same state. A reference wallet syncs
/// uninterrupted; a second file is synced under ever longer timeouts (the future dropped at an
/// await point, as an app that abandons a sync would); a third is synced by `yew-cli sync`
/// killed with SIGKILL after ever longer delays (a phone killing the app mid-scan), then
/// resumed. Both must end equal to the reference.
#[tokio::test]
#[ignore = "needs an ARMED regtest devnet of either line (scripts/devnet-s2.sh) and YEW_DEVNET=1"]
async fn s5_interrupted_sync_resumes() {
    use std::sync::Arc;
    let Some(mut s) = s5_setup().await else {
        return;
    };
    let line = s.line.clone();
    let dir = s5_dir("s5-interrupt", &line);
    let mnemonic = keys::generate_mnemonic(12).unwrap();
    let zaddr = open_at(&dir, "probe", &mnemonic, Some(1))
        .shielded()
        .unwrap()
        .default_address()
        .1;
    let taddr = open_at(&dir, "probe2", &mnemonic, Some(1))
        .receive_address(false)
        .unwrap()
        .address_s;
    let coins = node0_coins(&s.dn, 3);
    for (i, coin) in coins.iter().enumerate() {
        let z = z_send_from_node0(
            &s.dn,
            &line,
            coin,
            &zaddr,
            "0.3",
            &format!("interrupted {i}"),
        );
        s.dn.wait_mempool(&z);
        if i == 1 {
            let t = s.dn.node(2, &["sendtoaddress", &taddr, "0.6"]);
            s.dn.wait_mempool(&t);
        }
        s.dn.mine_pool();
    }
    let h = s.dn.mine_pool();
    wait_for_height(&mut s.c, h).await;

    // The reference (no birthday: the scan runs from Sapling activation, the longest one).
    let mut reference = open_at(&dir, "reference", &mnemonic, None);
    let t = Instant::now();
    let (rr, rz) = sync_both(&mut reference, &s.server, &mut s.c, &mut s.v).await;
    time_into(&mut s.timings, "referenceMillis", t);
    println!("reference: {rz:?}");
    assert_eq!(rz.received_notes, 3);
    let want = (
        reference.shielded().unwrap().balance().unwrap(),
        private_rows(&reference),
        rr.yec,
    );
    assert_eq!(want.0.total_zat, 90_000_000);
    assert_eq!(
        want.1
            .iter()
            .filter(|x| x.3.starts_with("interrupted"))
            .count(),
        3
    );
    drop(reference);

    // 1. In-process: the sync future dropped after 1, 2, 4, … ms.
    let ticks = Arc::new(AtomicUsize::new(0));
    let progress: yew_core::shielded::ProgressFn = {
        let ticks = ticks.clone();
        Arc::new(move |_| {
            ticks.fetch_add(1, Ordering::SeqCst);
        })
    };
    let mut w = open_at(&dir, "dropped", &mnemonic, None);
    let mut interrupted = vec![];
    let mut ms = 1u64;
    let t = Instant::now();
    loop {
        let run = async {
            let r = sync(&mut w, &mut s.c, s.v.client_mut()).await.unwrap();
            let z = yew_core::build::yec_private::sync_shielded(
                &mut w,
                &s.server,
                &mut s.c,
                progress.clone(),
            )
            .await
            .unwrap();
            (r, z)
        };
        match tokio::time::timeout(Duration::from_millis(ms), run).await {
            Ok((r, z)) => {
                assert_eq!(r.yec, want.2);
                println!("dropped-future sync completed at {ms} ms: {z:?}");
                break;
            }
            Err(_) => {
                let b = w.shielded().unwrap().balance().unwrap();
                interrupted.push(format!("{ms}ms:{}", b.scanned_height));
                // The progress ticker of the abandoned sync must stop with it.
                let at = ticks.load(Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1000)).await;
                assert_eq!(
                    ticks.load(Ordering::SeqCst),
                    at,
                    "an abandoned sync keeps ticking"
                );
            }
        }
        ms *= 2;
        assert!(ms < 120_000, "never completed");
    }
    time_into(&mut s.timings, "droppedTotalMillis", t);
    println!("dropped-future interruptions (timeout:scanned height): {interrupted:?}");
    s.timings
        .insert("droppedInterruptions".into(), interrupted.join(" ").into());
    assert_eq!(w.shielded().unwrap().balance().unwrap(), want.0);
    assert_eq!(private_rows(&w), want.1);
    drop(w);

    // 2. A real process killed with SIGKILL after 100, 250, 400, … ms, then resumed here.
    let cli =
        std::env::var("YEW_CLI_BIN").expect("YEW_CLI_BIN (scripts/devnet-s2.sh builds yew-cli)");
    let killed_path = dir.join("killed.sqlite").to_string_lossy().to_string();
    let server_arg = env_or("YEW_DEVNET_SERVER", "127.0.0.1:9418".into());
    let mut kills = vec![];
    let mut delay = 100u64;
    let t = Instant::now();
    loop {
        let mut child = Command::new(&cli)
            .args([
                "--server",
                &server_arg,
                "--plain",
                "--wallet",
                &killed_path,
                "--network",
                "regtest",
                "sync",
            ])
            .env("YEW_SEED", &mnemonic)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(delay)).await;
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "yew-cli sync failed: {status}");
            println!("yew-cli sync completed before the {delay} ms kill");
            break;
        }
        child.kill().unwrap(); // SIGKILL
        child.wait().unwrap();
        let w = open_at(&dir, "killed", &mnemonic, None);
        let b = w.shielded().unwrap().balance().unwrap();
        kills.push(format!("{delay}ms:{}", b.scanned_height));
        drop(w);
        delay += 150;
        assert!(delay < 60_000, "never completed");
    }
    time_into(&mut s.timings, "killedTotalMillis", t);
    println!("SIGKILL interruptions (delay:scanned height): {kills:?}");
    s.timings
        .insert("killedInterruptions".into(), kills.join(" ").into());
    let mut w = open_at(&dir, "killed", &mnemonic, None);
    let (r, z) = sync_both(&mut w, &s.server, &mut s.c, &mut s.v).await;
    println!("resumed after the kills: {z:?}");
    assert_eq!(r.yec, want.2);
    assert_eq!(w.shielded().unwrap().balance().unwrap(), want.0);
    assert_eq!(private_rows(&w), want.1);
    let _ = std::fs::remove_dir_all(&dir);
    s.finish("interrupt");
}

/// Falcon YED holders (TOK-PQ; quantum spec F-7, owner decision 2026-10-10: Falcon from day one on
/// mainnet). On an ARMED devnet of the quantum node whose nodes all run `-pqfalconheight=<F>`
/// (`scripts/devnet-falcon.sh`, portseed 2200, lightwalletd on 2219):
///
/// 1. before `F` the wallet's YED receive address is its P2PKH key and node 0 pays it YED;
/// 2. from `F` the receive address is the 53-character Falcon holder of the same key, node 0 pays
///    it YED (a `TX_PQPKH` scheme 2 token, found through `GetAddressTokens`);
/// 3. YEW sends YED to node 0's Falcon address spending the P2PKH and the Falcon token (the
///    Falcon input signed with the vendored PQClean code, 1,577-byte scriptSig), its change
///    going to a Falcon holder; the node's gate verdict is `ok` and the block accepts it;
/// 4. a YEW mint after `F` puts its token on the holder key's Falcon pair;
/// 5. a wallet restored from the seed finds every Falcon token (the gap scan).
#[tokio::test]
#[ignore = "needs an ARMED quantum devnet with -pqfalconheight (scripts/devnet-falcon.sh) and YEW_DEVNET=1"]
async fn q_falcon_holders_receive_send_mint_and_restore() {
    use yew_core::build::mint::window_open;
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return;
    }
    let dn = Devnet::new("yb-devnet-falcon", "2200");
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:2219".into()), true).unwrap();
    let channel = server.connect().await.expect("connect to lightwalletd");
    let mut c = CompactClient::from_channel(channel.clone());
    let info = c.lightd_info_for(Network::Regtest).await.unwrap();
    let (mut v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .expect("probe");
    assert!(availability.usable(), "{availability:?}");
    let falcon_height = match &availability {
        Availability::Present { info, .. } => {
            let pq = info
                .params
                .as_ref()
                .unwrap()
                .pq
                .as_ref()
                .expect("params.pq");
            assert!(
                pq.falcon_height > 0,
                "the devnet runs -pqfalconheight: {pq:?}"
            );
            pq.falcon_height as u64
        }
        Availability::Absent => unreachable!(),
    };
    warm_and_fund_node_yed(&dn, &mut c, &mut v, &availability).await;
    let tip = c.latest_height().await.unwrap();
    assert!(
        tip + 6 < falcon_height,
        "start the test well before the Falcon height {falcon_height} (tip {tip})"
    );

    let dir = std::env::temp_dir().join(format!("yew-devnet-falcon-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let birthday = info.block_height.saturating_sub(1);
    let (mut a, mnemonic) = fresh_wallet(&dir, "a", birthday);
    let fund = fund_node();
    let addr = a.receive_address(false).unwrap();
    for amount in ["12", "3"] {
        let t = dn.node(fund, &["sendtoaddress", &addr.address_s, amount]);
        assert_eq!(t.len(), 64, "{t}");
        dn.wait_mempool(&t);
    }
    // 1. Before Falcon: a P2PKH YED receive address.
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(!a.falcon_now(), "tip {} before {falcon_height}", r.tip);
    let pre = dn.node_json(0, &["yed_send", &addr.address_ye, "5000"]);
    confirm(&dn, &mut c, pre["txid"].as_str().unwrap()).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yed, (5_000, 0), "{r:?}");
    assert_eq!(r.yec.0 + r.yec.1, 15 * 100_000_000);

    // 2. Mine to the Falcon height: the receive address becomes the Falcon holder.
    loop {
        let h = dn.mine_pool();
        wait_for_height(&mut c, h).await;
        if h + 1 >= falcon_height {
            break;
        }
    }
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(a.falcon_now(), "tip {} at {falcon_height}", r.tip);
    let row = a.receive_address(false).unwrap();
    let falcon_addr = a.falcon_holder_address(&row).unwrap();
    assert_eq!(falcon_addr.len(), 53, "{falcon_addr}");
    assert!(falcon_addr.starts_with("yr"));
    // the node agrees it is a Falcon holder address
    let va = dn.node_json(0, &["yed_validateaddress", &falcon_addr]);
    assert_eq!(va["isvalid"].as_bool(), Some(true), "{va}");
    // a P2PKH YED address is refused by the node now (TOK-PQ), as by YEW
    let refused = dn.node_try(0, &["yed_send", &addr.address_ye, "1000"]);
    assert!(refused.contains("bad-yed-holder"), "{refused}");
    let to_falcon = dn.node_json(0, &["yed_send", &falcon_addr, "3000"]);
    confirm(&dn, &mut c, to_falcon["txid"].as_str().unwrap()).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yed, (8_000, 0), "{r:?}");
    let utxos = a.store.utxos().unwrap();
    let falcon_token = utxos
        .iter()
        .find(|u| u.class == UtxoClass::Token && yew_core::pq::pqpkh_of(&u.script).is_some())
        .expect("a Falcon TOKEN row");
    assert_eq!(
        (falcon_token.cents, falcon_token.address.as_str()),
        (3_000, falcon_addr.as_str())
    );

    // 3. Send 6,000 cents to node 0's Falcon address: both tokens in, Falcon change.
    let node_falcon = dn.node(0, &["yed_getnewaddress"]);
    assert_eq!(node_falcon.len(), 53, "{node_falcon}");
    let p =
        yed_transfer::build_yed_transfer(&a, &[(node_falcon.clone(), 6_000)], r.tip, r.branch_id)
            .unwrap();
    assert_eq!((p.yed_inputs.len(), p.change_cents), (2, 2_000));
    let (tx, _) = Transaction::parse(&p.raw).unwrap();
    let falcon_in = tx
        .vin
        .iter()
        .find(|i| i.prevout == falcon_token.outpoint)
        .expect("the Falcon token is spent");
    assert_eq!(falcon_in.script_sig.len(), 1_577);
    let change = yew_core::pq::pqpkh_of(&tx.vout[1].script_pubkey).expect("Falcon change");
    assert!(a.own_falcon_holders().unwrap().contains_key(&change));
    let (txid, validation) = yed_transfer::broadcast(&a, &mut c, &mut v, &p)
        .await
        .unwrap();
    assert_eq!(validation.verdict, "ok", "{validation:?}");
    confirm(&dn, &mut c, &txid).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yed, (2_000, 0), "{r:?}");
    let listed = dn.node_json(0, &["yed_listtokens", &format!("[\"{node_falcon}\"]")]);
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["txid"] == txid.as_str() && t["cents"] == 6_000),
        "{listed}"
    );

    // 4. A mint after Falcon: the token goes to the holder key's Falcon pair.
    let id = a
        .mint_start(&mut c, &mut v, 10_000, 96, None, r.tip, r.branch_id)
        .await
        .unwrap();
    let m = a.store.mint(id).unwrap().unwrap();
    confirm(&dn, &mut c, &txid_hex(&m.carrier_txid)).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(window_open(r.tip, m.expiry_height));
    let f = a
        .mint_finish(&mut c, &mut v, id, r.tip, r.branch_id)
        .await
        .unwrap();
    assert_eq!(f.validation.verdict, "ok", "{:?}", f.validation);
    confirm(&dn, &mut c, &f.txid).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yed, (12_000, 0), "{r:?}");
    let (mtx, _) = Transaction::parse(&f.raw).unwrap();
    let minted = yew_core::pq::pqpkh_of(&mtx.vout[1].script_pubkey).expect("Falcon token");
    assert_eq!(minted.scheme, 2);
    assert!(a.own_falcon_holders().unwrap().contains_key(&minted));

    // 5. Restore from the seed: every Falcon token is found again.
    let path = dir.join("restored.sqlite").to_string_lossy().to_string();
    let mut b = Wallet::open(&path, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();
    let rb = sync(&mut b, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(rb.yed, r.yed, "{rb:?}");
    let falcon_rows = b
        .store
        .utxos()
        .unwrap()
        .into_iter()
        .filter(|u| u.class == UtxoClass::Token && yew_core::pq::pqpkh_of(&u.script).is_some())
        .count();
    assert_eq!(falcon_rows, 2, "the Falcon change and the minted token");
    println!(
        "Falcon devnet ok: F={falcon_height}, transfer {txid} (Falcon input + change), mint {}",
        f.txid
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Post-quantum addresses end to end (lightwalletd-dd q/pqaddr: `TX_PQPKH` in the taddr methods
/// under the plain `sq…`/`rq…` form). On an ARMED quantum devnet in the mainnet regime (Falcon
/// from the vault activation; `scripts/devnet-pqaddr.sh`, portseed 3370, lightwalletd on 3389):
///
/// 1. node 2 pays YEC to the `rq…` form of the wallet's Falcon holder (once plain, once exactly
///    `TOKEN_VALUE`) and node 0 pays YED to its `yr…` form: the sync finds all three through the
///    `rq…` address; the YED is one TOKEN row (from `GetAddressTokens`, not duplicated by
///    `GetAddressUtxos`), the `TOKEN_VALUE` output is HELD, the plain YEC is PQ_OWNED — in neither
///    YEC balance — and the payment is in history;
/// 2. YEW sends YEC to node 0's `rq…` address (a `TX_PQPKH` output the node and lightwalletd see)
///    and refuses its 53-character `yr…` form as a YEC destination;
/// 3. the PQ_OWNED coin moves into the wallet (one Falcon input, gate `ok`, mined);
/// 4. a wallet restored from the seed finds the same balances.
#[tokio::test]
#[ignore = "needs an ARMED quantum devnet and lightwalletd-dd q/pqaddr (scripts/devnet-pqaddr.sh) and YEW_DEVNET=1"]
async fn q_pqaddr_sq_receive_send_and_move() {
    if std::env::var("YEW_DEVNET").ok().as_deref() != Some("1") {
        eprintln!("YEW_DEVNET is not 1; skipping");
        return;
    }
    let dn = Devnet::new("yb-devnet-pqaddr", "3370");
    let server =
        Server::parse(&env_or("YEW_DEVNET_SERVER", "127.0.0.1:3389".into()), true).unwrap();
    let channel = server.connect().await.expect("connect to lightwalletd");
    let mut c = CompactClient::from_channel(channel.clone());
    let info = c.lightd_info_for(Network::Regtest).await.unwrap();
    let (mut v, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .expect("probe");
    assert!(availability.usable(), "{availability:?}");
    warm_and_fund_node_yed(&dn, &mut c, &mut v, &availability).await;

    let dir = std::env::temp_dir().join(format!("yew-devnet-pqaddr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let birthday = info.block_height.saturating_sub(1);
    let (mut a, mnemonic) = fresh_wallet(&dir, "a", birthday);
    let fund = fund_node();
    let addr = a.receive_address(false).unwrap();
    let t = dn.node(fund, &["sendtoaddress", &addr.address_s, "5"]);
    confirm(&dn, &mut c, &t).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(
        a.falcon_now(),
        "the devnet mirrors mainnet: Falcon from the vault activation"
    );
    assert_eq!(r.yec.0 + r.yec.1, 5 * 100_000_000);
    assert!(
        !r.pq_unindexed,
        "lightwalletd-dd q/pqaddr serves PQ addresses: {r:?}"
    );

    // 1. YEC and YED to the wallet's Falcon holder, YEC through its rq… form.
    let row = a.receive_address(false).unwrap();
    let falcon = a.falcon_holder_id(&row).unwrap();
    let holder_yr = keys::encode_pq_yellowback(Network::Regtest, &falcon).unwrap();
    let holder_rq = keys::encode_pq_yec(Network::Regtest, &falcon).unwrap();
    assert!(
        holder_rq.starts_with("rq") && holder_rq.len() == 53,
        "{holder_rq}"
    );
    let va = dn.node_json(0, &["validateaddress", &holder_rq]);
    assert_eq!(va["isvalid"].as_bool(), Some(true), "{va}");
    let pay = dn.node(fund, &["sendtoaddress", &holder_rq, "2"]);
    let token_sized = dn.node(fund, &["sendtoaddress", &holder_rq, "0.0001"]);
    dn.wait_mempool(&pay);
    dn.wait_mempool(&token_sized);
    let yed = dn.node_json(0, &["yed_send", &holder_yr, "3000"]);
    let yed_txid = yed["txid"].as_str().unwrap().to_string();
    confirm(&dn, &mut c, &yed_txid).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert!(r.pq_addresses > 0 && !r.pq_unindexed, "{r:?}");
    assert_eq!(r.yed, (3_000, 0), "{r:?}");
    assert_eq!(
        r.yec.0 + r.yec.1,
        5 * 100_000_000,
        "YEC at a PQ key is in neither balance"
    );
    let utxos = a.store.utxos().unwrap();
    let pq_of = |class: UtxoClass| {
        utxos
            .iter()
            .filter(|u| u.class == class && yew_core::pq::pqpkh_of(&u.script) == Some(falcon))
            .collect::<Vec<_>>()
    };
    let tokens = pq_of(UtxoClass::Token);
    assert_eq!(tokens.len(), 1, "one Falcon TOKEN row: {utxos:?}");
    assert_eq!(tokens[0].cents, 3_000);
    assert_eq!(txid_hex(&tokens[0].outpoint.txid), yed_txid);
    let held = pq_of(UtxoClass::Held);
    assert_eq!(held.len(), 1, "{utxos:?}");
    assert_eq!(held[0].value, TOKEN_VALUE);
    assert_eq!(txid_hex(&held[0].outpoint.txid), token_sized);
    let owned = pq_of(UtxoClass::PqOwned);
    assert_eq!(owned.len(), 1, "{utxos:?}");
    assert_eq!(owned[0].value, 2 * 100_000_000);
    assert_eq!(txid_hex(&owned[0].outpoint.txid), pay);
    let b = a.balances().unwrap();
    assert_eq!(b.yec_pq_zat, 2 * 100_000_000);
    assert_eq!(b.pq_coins, vec![owned[0].outpoint]);
    let hist = a.store.history().unwrap();
    let paid = hist
        .iter()
        .find(|h| txid_hex(&h.txid) == pay)
        .expect("the rq… payment is in history");
    assert!(paid.yec_delta >= 2 * 100_000_000, "{paid:?}");

    // 2. YEW → node 0's rq… address; its yr… form is refused as a YEC destination.
    let node_yr = dn.node(0, &["yed_getnewaddress"]);
    let node_id = keys::parse_pq_address(Network::Regtest, &node_yr).unwrap();
    let node_rq = keys::encode_pq_yec(Network::Regtest, &node_id).unwrap();
    let e =
        yec_send::build_yec_send(&a, &node_yr, 100_000_000, false, r.tip, r.branch_id).unwrap_err();
    assert!(e.to_string().contains("sq…"), "{e}");
    let p = yec_send::build_yec_send(&a, &node_rq, 100_000_000, false, r.tip, r.branch_id).unwrap();
    let sent = yec_send::broadcast(&a, &mut c, &mut v, &p).await.unwrap();
    confirm(&dn, &mut c, &sent).await;
    let out = dn.node_json(0, &["gettxout", &sent, "0"]);
    assert_eq!(
        out["scriptPubKey"]["type"].as_str(),
        Some("pqpubkeyhash"),
        "{out}"
    );
    let listed = c
        .address_utxos(std::slice::from_ref(&node_rq), 0)
        .await
        .unwrap();
    assert!(
        listed
            .iter()
            .any(|u| txid_hex(&u.txid) == sent && u.index == 0 && u.value_zat == 100_000_000),
        "lightwalletd lists the payment under {node_rq}"
    );
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yec.0 + r.yec.1, 4 * 100_000_000 - p.fee);

    // 3. The PQ_OWNED coin moves into the wallet.
    let coin = a.balances().unwrap().pq_coins[0];
    let mv = a.release_preview(&coin, r.tip, r.branch_id).unwrap();
    let (mtx, _) = Transaction::parse(&mv.raw).unwrap();
    assert_eq!(mtx.vin.len(), 1);
    assert_eq!(mtx.vin[0].script_sig.len(), 1_577);
    let (moved, validation) = a.release_confirm(&mut c, &mut v, &mv).await.unwrap();
    assert_eq!(validation.verdict, "ok", "{validation:?}");
    assert_eq!(validation.burned, 0);
    confirm(&dn, &mut c, &moved).await;
    let r = sync(&mut a, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(r.yec.0 + r.yec.1, 4 * 100_000_000 - p.fee + mv.value);
    assert_eq!(r.yed, (3_000, 0));
    let b = a.balances().unwrap();
    assert_eq!((b.yec_pq_zat, b.pq_coins.len()), (0, 0));

    // 4. Restore from the seed.
    let path = dir.join("restored.sqlite").to_string_lossy().to_string();
    let mut w = Wallet::open(&path, Network::Regtest, &mnemonic, "", Some(birthday)).unwrap();
    let rw = sync(&mut w, &mut c, v.client_mut()).await.unwrap();
    assert_eq!(
        (rw.yec.0 + rw.yec.1, rw.yed),
        (r.yec.0 + r.yec.1, r.yed),
        "{rw:?}"
    );
    assert_eq!(w.balances().unwrap().yec_pq_zat, 0);
    assert!(w
        .store
        .history()
        .unwrap()
        .iter()
        .any(|h| txid_hex(&h.txid) == pay));
    println!(
        "pqaddr devnet ok: rq… payment {pay}, YED {yed_txid}, YEW → {node_rq} {sent}, move {moved} ({} zat fee)",
        mv.fee
    );
    let _ = std::fs::remove_dir_all(&dir);
}
