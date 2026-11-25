//! `yewd-yugen`: the Yugen wallet engine yewd runs for its `yugen_*` RPCs.
//!
//!   yewd-yugen [-datadir=D] [-node=host:port] [-rpcuser=U -rpcpassword=P | -rpccookiefile=F]
//!              [-network=regtest|testnet|main] [-seedfd=N] [-yugenhosts=h1:port,h2:port] <method> [json params array]
//!   yewd-yugen prove a|b      statement JSON {public, witness} on stdin; proof hex on stdout
//!   yewd-yugen verify a|b     {public, proof} JSON on stdin; exit 0 iff the proof verifies
//!
//! Methods: getaddress [{onetime?}] (the Yugen address: short by default, ruling 15), newaddress (= getaddress onetime), debug: newrequest,
//! staticaddress, depositaddress; shield [fund_txid, static_to?, memo?], send [to, amount, memo?]
//! (to: a Yugen address; also a payment request string or a static full address in hex), withdraw [taddr, amount, memo?] (memo refused),
//! getbalance, getbalances, listreceived, listnotes, sync (scheduled, §17.8), syncstatus, status [nf1]. The result is one JSON value on stdout;
//! an error is `{"error": message}` on stdout with exit status 1.
//!
//! The account seed is never on the command line, in the environment or in a file: the caller
//! writes it (hex, one line) into a pipe whose read end this process inherits as fd N
//! (`-seedfd=N`). Without it every wallet method is refused (the caller's wallet is locked).

use std::io::Read;

use serde_json::{json, Value};
use yewd_yugen::engine::Engine;
use yewd_yugen::node::Rpc;
use yewd_yugen::zats;

fn stdin_json() -> Value {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    serde_json::from_str(&s).expect("JSON on stdin")
}

#[cfg(feature = "provers")]
fn prove(sys: &str) -> Result<String, String> {
    use yewd_yugen::prove::{a, b};
    let v = stdin_json();
    let proof = match sys {
        "a" => {
            let s = a::setup();
            let p = a::prove(&s, &v["public"], &v["witness"])?;
            a::verify(&s, &v["public"], &p)?;
            p
        }
        "b" => {
            let s = b::setup();
            let p = b::prove(&s, &v["public"], &v["witness"])?;
            b::verify(&s, &v["public"], &p)?;
            p
        }
        _ => return Err("prove a|b".into()),
    };
    Ok(hex::encode(proof))
}

#[cfg(feature = "provers")]
fn verify(sys: &str) -> Result<String, String> {
    use yewd_yugen::prove::{a, b};
    let v = stdin_json();
    let proof = hex::decode(v["proof"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
    match sys {
        "a" => a::verify(&a::setup(), &v["public"], &proof)?,
        "b" => b::verify(&b::setup(), &v["public"], &proof)?,
        _ => return Err("verify a|b".into()),
    }
    Ok("true".into())
}

fn main() {
    let mut opts = std::collections::HashMap::new();
    let mut pos = Vec::new();
    for a in std::env::args().skip(1) {
        if let Some(kv) = a.strip_prefix('-') {
            let (k, v) = kv.trim_start_matches('-').split_once('=').unwrap_or((kv, ""));
            opts.insert(k.to_string(), v.to_string());
        } else {
            pos.push(a);
        }
    }
    let method = pos.first().cloned().unwrap_or_default();
    let r: Result<String, String> = match method.as_str() {
        #[cfg(feature = "provers")]
        "prove" => prove(pos.get(1).map(String::as_str).unwrap_or("")),
        #[cfg(feature = "provers")]
        "verify" => verify(pos.get(1).map(String::as_str).unwrap_or("")),
        _ => run(&opts, &method, pos.get(1).map(|s| serde_json::from_str(s).unwrap_or(json!([]))).unwrap_or(json!([]))).map(|v| v.to_string()),
    };
    match r {
        Ok(s) => println!("{s}"),
        Err(e) => {
            println!("{}", json!({"error": e}));
            std::process::exit(1)
        }
    }
}

fn run(o: &std::collections::HashMap<String, String>, method: &str, p: Value) -> Result<Value, String> {
    let node_addr = o.get("node").cloned().unwrap_or_else(|| "127.0.0.1:18232".into());
    let node = match o.get("rpccookiefile") {
        Some(c) => Rpc::from_cookie(&node_addr, c).map_err(|e| e.to_string())?,
        None => Rpc::new(&node_addr, o.get("rpcuser").map(String::as_str).unwrap_or(""), o.get("rpcpassword").map(String::as_str).unwrap_or("")),
    };
    let network = match o.get("network").map(String::as_str) {
        Some("main") => 0,
        Some("testnet") => 1,
        _ => 2,
    };
    let dir = std::path::PathBuf::from(o.get("datadir").cloned().unwrap_or_else(|| ".".into()));
    if o.contains_key("seed") {
        return Err("-seed= is refused: pass the seed on an inherited descriptor (-seedfd=N)".into());
    }
    let seed = match o.get("seedfd") {
        Some(n) => Some(yewd_yugen::store::read_seed_fd(n.parse().map_err(|_| "-seedfd: a descriptor number")?)?),
        None => None,
    };
    let mut e = Engine::open(&dir, node, network, seed)?;
    if let Some(hs) = o.get("yugenhosts").filter(|s| !s.is_empty()) {
        e.set_hosts(yewd_yugen::hosts::Pair::new(hs)?);
    }
    let s = |i: usize| p.get(i).and_then(Value::as_str).map(String::from);
    let amt = |i: usize| p.get(i).and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    match method {
        // UX-1: the one Yugen address; [{"reusable": true}] for the static part only
        // ruling 15: the short address by default; [{"onetime": true}] adds a fresh payment request
        // ({"reusable": true} is the default now and is accepted)
        "getaddress" => e.get_address(p.get(0).and_then(|o| o.get("onetime")).and_then(Value::as_bool).unwrap_or(false)),
        // a new one-time address: the short address with a fresh payment request
        "newaddress" => e.get_address(true),
        // internal/debug forms, never shown to users (addendum ruling 9(a))
        "newrequest" => e.new_request().map(Value::from),
        "depositaddress" => Ok(e.deposit_address().into()),
        // the scheduled sync (§17.8): run by yewd's scheduler, a session at most once per boundary
        "sync" => e.sync(),
        // what a user's "sync" gets: the chain scan and the schedule, never a host session
        "syncstatus" => e.sync_status(),
        "getbalance" => {
            e.chain_scan()?;
            Ok(json!(e.balance()))
        }
        "getbalances" => e.balances(),
        "listreceived" | "listnotes" => {
            e.chain_scan()?;
            Ok(e.list_received())
        }
        "shield" => e.shield_to(&s(0).ok_or("shield [fund_txid, static_to?, memo?]")?, s(1).as_deref(), s(2).as_deref()),
        "send" => e.send(&s(0).ok_or("send [to, amount, memo?]")?, zats(amt(1).ok_or("amount")?), s(2).as_deref()),
        "withdraw" => e.withdraw(&s(0).ok_or("withdraw [taddr, amount, memo?]")?, zats(amt(1).ok_or("amount")?), s(2).as_deref()),
        "staticaddress" => Ok(e.static_address()),
        "status" => e.node.call("gettransferstatus", json!([s(0).unwrap_or_default()])).map_err(|e| e.to_string()),
        _ => Err(format!("unknown method {method}")),
    }
}
