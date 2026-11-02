// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yewd`: the YEW core as a daemon. The command line is documented in `yewd/README.md`.

use yewd_facade::{Args, Config};

const USAGE: &str = "\
yewd: a ycashd-compatible wallet-RPC façade in front of a wallet-less node (kogany or ycashd -disablewallet)

Usage: yewd [options]

  -datadir=<dir>              data directory (default ~/.yewd); the cookie is <datadir>/<net>/.cookie
  -conf=<file>                configuration file (default <datadir>/yewd.conf; relative to -datadir)
  -regtest | -testnet         network (default mainnet); picks the default -rpcport and the cookie subdirectory
  -rpcbind=<ip>[:port]        listen address, repeatable (default 127.0.0.1)
  -rpcport=<port>             listen port (default 8832, 18832 on testnet and regtest: ycashd's)
  -rpcuser=<u> -rpcpassword=<p>   client credentials (without -rpcpassword: cookie authentication)
  -rpccookiefile=<file>       where to write the cookie (relative to <datadir>/<net>)
  -rpcallowip=<ip|ip/n|ip/mask>   allow a client subnet, repeatable (loopback is always allowed)
  -backendrpcconnect=<ip>     the node's RPC address (default 127.0.0.1)
  -backendrpcport=<port>      the node's RPC port (required)
  -backendrpccookiefile=<file>    the node's .cookie (re-read after a 401)
  -backendrpcuser=<u> -backendrpcpassword=<p>   instead of the cookie
  -stopbackend                `stop` stops the node too (the harness bundle)
  -signer=<socket>            the signer's Unix socket (reserved, S2)
  -debug                      log every method called
  -version                    print the version and exit

Other options are reported and ignored (ycashd wallet options are accepted for the harness).";

fn main() {
    let cli = match Args::from_cli(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            std::process::exit(1);
        }
    };
    if cli.has("help") || cli.has("?") {
        println!("{USAGE}");
        return;
    }
    if cli.has("version") {
        println!(
            "yewd {} (yew-core {})",
            env!("CARGO_PKG_VERSION"),
            yewd_wallet::CORE_VERSION
        );
        return;
    }
    let cfg = match Config::load(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    for o in &cfg.ignored {
        eprintln!("yewd: ignoring option {o} (not used by this version)");
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(async {
        let running = match yewd_facade::start(&cfg).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("yewd: cannot start: {e}");
                return 1;
            }
        };
        eprintln!(
            "yewd: listening on {:?}, backend {} ({})",
            running.addrs,
            cfg.backend,
            if cfg.user_pass.is_some() {
                "rpcpassword"
            } else {
                "cookie"
            }
        );
        let facade = running.facade.clone();
        tokio::spawn(async move {
            wait_for_signal().await;
            eprintln!("yewd: signal received, stopping");
            facade.shutdown();
        });
        let _ = running.task.await;
        drop(running.cookie);
        eprintln!("yewd: stopped");
        0
    });
    std::process::exit(code);
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
