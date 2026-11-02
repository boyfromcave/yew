// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yewd-signer`: the separate process that holds the seed (workspace plan §3b, K-24).
//!
//! S1 commands (the façade runs them as a child process; S2 replaces this with the Unix-socket
//! server and adds signing):
//!
//! ```text
//! yewd-signer -datadir=<dir> [-regtest|-testnet] init [-mnemonic="<words>"] [-birthday=<h>]
//! yewd-signer -datadir=<dir> [-regtest|-testnet] public [-pq=<scheme>:<from>:<count>]...
//! yewd-signer -version
//! ```
//!
//! `init` prints `{"created": bool, "birthday": n}`; `public` prints the
//! [`yewd_proto::PublicBundle`] JSON. Errors go to stderr with exit status 1.

use std::path::PathBuf;

use yew_core::params::Network;
use yewd_proto::PublicRequest;
use yewd_signer::{init, Keystore};

fn usage() -> ! {
    eprintln!(
        "usage: yewd-signer -datadir=<dir> [-regtest|-testnet] init [-mnemonic=\"<words>\"] [-birthday=<h>]\n       \
         yewd-signer -datadir=<dir> [-regtest|-testnet] public [-pq=<scheme>:<from>:<count>]...\n       \
         yewd-signer -version"
    );
    std::process::exit(2)
}

fn fail(m: impl std::fmt::Display) -> ! {
    eprintln!("{m}");
    std::process::exit(1)
}

fn main() {
    let mut datadir: Option<PathBuf> = None;
    let mut network = Network::Mainnet;
    let mut command: Option<String> = None;
    let mut mnemonic: Option<String> = None;
    let mut birthday = 0u64;
    let mut req = PublicRequest::default();
    for arg in std::env::args().skip(1) {
        let body = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .map(str::to_string);
        let Some(body) = body else {
            if command.is_some() {
                usage();
            }
            command = Some(arg);
            continue;
        };
        let (name, value) = match body.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => (body.clone(), String::new()),
        };
        match name.as_str() {
            "datadir" => datadir = Some(PathBuf::from(value)),
            "regtest" => network = Network::Regtest,
            "testnet" => network = Network::Testnet,
            "mnemonic" => mnemonic = Some(value),
            "birthday" => birthday = value.parse().unwrap_or_else(|_| usage()),
            "pq" => {
                let parts: Vec<&str> = value.split(':').collect();
                let [s, f, c] = parts.as_slice() else { usage() };
                let (Ok(s), Ok(f), Ok(c)) = (s.parse(), f.parse(), c.parse()) else {
                    usage()
                };
                req.pq.push((s, f, c));
            }
            "version" => {
                println!(
                    "yewd-signer {} (protocol {}, yew-core {})",
                    env!("CARGO_PKG_VERSION"),
                    yewd_proto::PROTO_VERSION,
                    yew_core::VERSION
                );
                return;
            }
            "help" | "?" => usage(),
            _ => fail(format!("yewd-signer: unknown option -{name}")),
        }
    }
    let Some(dir) = datadir else { usage() };
    match command.as_deref() {
        Some("init") => match init(&dir, network, mnemonic.as_deref(), birthday) {
            Ok(created) => {
                let ks = Keystore::load(&dir, network).unwrap_or_else(|e| fail(e));
                println!(
                    "{}",
                    serde_json::json!({"created": created, "birthday": ks.birthday()})
                );
            }
            Err(e) => fail(e),
        },
        Some("public") => {
            let ks = Keystore::load(&dir, network).unwrap_or_else(|e| fail(e));
            match ks.public(&req) {
                Ok(b) => println!("{}", serde_json::to_string(&b).expect("serializable")),
                Err(e) => fail(e),
            }
        }
        _ => usage(),
    }
}
