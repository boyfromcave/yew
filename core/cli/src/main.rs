//! `yew-cli`: the developer's and the devnet tests' driver over `yew-core` (plan §6.3).
//!
//! ```text
//! yew-cli [--server host:port] [--plain] [--wallet PATH] [--network regtest|testnet|mainnet]
//!         [--seed-file PATH | YEW_SEED=<mnemonic>] [--passphrase P | YEW_PASSPHRASE=P]
//!         [--birthday H] <command>
//! commands: status | address [--new] | balance | sync | send-yec <addr> <zat> [--all]
//!           | export-wif <addr> | import-wif <wif> | history | version
//! ```
//!
//! No argument-parsing crate: the allow-list (plan §3.3) is the core's, and this binary keeps
//! to the core's dependencies plus `tokio`.

use std::process::exit;

use yew_core::build::yec_send;
use yew_core::coins::UtxoClass;
use yew_core::net::{CompactClient, Server};
use yew_core::params::Network;
use yew_core::sync;
use yew_core::tx::txid_hex;
use yew_core::wallet::Wallet;

struct Opts {
    server: String,
    plain: bool,
    wallet: String,
    network: Network,
    seed_file: Option<String>,
    passphrase: Option<String>,
    birthday: Option<u64>,
    rest: Vec<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: yew-cli [--server host:port] [--plain] [--wallet PATH] [--network N] \
         [--seed-file PATH] [--passphrase P] [--birthday H] <command>\n\
         commands: status | address [--new] | balance | sync | send-yec <addr> <zat> [--all]\n\
         \x20         | export-wif <addr> | import-wif <wif> | history | version\n\
         seed: --seed-file or the YEW_SEED environment variable (a BIP39 mnemonic);\n\
         passphrase: --passphrase or YEW_PASSPHRASE (default empty)."
    );
    exit(2)
}

fn parse_opts() -> Opts {
    let mut o = Opts {
        server: "127.0.0.1:9067".into(),
        plain: false,
        wallet: "yew-wallet.sqlite".into(),
        network: Network::Regtest,
        seed_file: None,
        passphrase: None,
        birthday: None,
        rest: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = |name: &str| {
            it.next().unwrap_or_else(|| {
                eprintln!("{name} needs a value");
                usage()
            })
        };
        match a.as_str() {
            "--server" => o.server = value("--server"),
            "--plain" => o.plain = true,
            "--wallet" => o.wallet = value("--wallet"),
            "--network" => {
                let n = value("--network");
                o.network = Network::from_name(&n).unwrap_or_else(|| {
                    eprintln!("unknown network {n}");
                    usage()
                });
            }
            "--seed-file" => o.seed_file = Some(value("--seed-file")),
            "--passphrase" => o.passphrase = Some(value("--passphrase")),
            "--birthday" => {
                o.birthday = Some(value("--birthday").parse().unwrap_or_else(|_| usage()))
            }
            "-h" | "--help" => usage(),
            _ => o.rest.push(a),
        }
    }
    if o.plain && o.network == Network::Mainnet {
        eprintln!("--plain is refused on mainnet (plan §3.5: TLS required outside regtest)");
        exit(2);
    }
    o
}

fn seed_phrase(o: &Opts) -> String {
    let phrase = match &o.seed_file {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("cannot read seed file {p}: {e}");
            exit(2)
        }),
        None => std::env::var("YEW_SEED").unwrap_or_else(|_| {
            eprintln!("no seed: pass --seed-file or set YEW_SEED");
            exit(2)
        }),
    };
    phrase.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn open_wallet(o: &Opts) -> Wallet {
    let phrase = seed_phrase(o);
    let pass = o
        .passphrase
        .clone()
        .or_else(|| std::env::var("YEW_PASSPHRASE").ok())
        .unwrap_or_default();
    Wallet::open(&o.wallet, o.network, &phrase, &pass, o.birthday).unwrap_or_else(|e| {
        eprintln!("cannot open wallet: {e}");
        exit(1)
    })
}

async fn client(o: &Opts) -> CompactClient {
    let server = Server::parse(&o.server, o.plain).unwrap_or_else(|e| {
        eprintln!("{e}");
        exit(2)
    });
    CompactClient::connect(&server).await.unwrap_or_else(|e| {
        eprintln!("cannot connect to {}: {e}", server.uri());
        exit(1)
    })
}

fn fail<T>(r: Result<T, impl std::fmt::Display>) -> T {
    r.unwrap_or_else(|e| {
        eprintln!("error: {e}");
        exit(1)
    })
}

fn yec(zat: i64) -> String {
    format!(
        "{}.{:08} YEC ({zat} zat)",
        zat / 100_000_000,
        (zat % 100_000_000).abs()
    )
}

#[tokio::main]
async fn main() {
    let o = parse_opts();
    let cmd = o.rest.first().map(String::as_str).unwrap_or("version");
    match cmd {
        "version" => println!(
            "yew-cli {} (yew-core {})",
            env!("CARGO_PKG_VERSION"),
            yew_core::VERSION
        ),
        "status" => {
            let mut c = client(&o).await;
            let info = fail(c.lightd_info().await);
            println!("server    {} ({})", o.server, info.version);
            println!(
                "chain     {} (wallet: {})",
                info.chain_name,
                o.network.chain_name()
            );
            println!("branch id {:08x}", info.branch_id);
            println!("tip       {}", info.block_height);
            println!("taddr     {}", info.taddr_support);
            println!("zcashd    {}", info.zcashd_build);
            if std::env::var("YEW_SEED").is_ok() || o.seed_file.is_some() {
                let w = open_wallet(&o);
                println!(
                    "wallet    {} (birthday {}, synced to {})",
                    o.wallet,
                    fail(w.birthday()),
                    fail(w.store.meta_u64("last_synced_height"))
                );
                println!("addresses {}", fail(w.addresses()).len());
            }
        }
        "address" => {
            let w = open_wallet(&o);
            let new = o.rest.iter().any(|a| a == "--new");
            let row = fail(w.receive_address(new));
            println!("{}", row.address_ye);
            println!("{}", row.address_s);
            println!("m/44'/347'/0'/{}/{}", row.chain, row.index);
        }
        "balance" => {
            let w = open_wallet(&o);
            let utxos = fail(w.store.utxos());
            let locked = fail(w.store.locks()).len();
            let (avail, reserved) = yew_core::coins::yec_balances(&utxos);
            println!("YEC available  {}", yec(avail));
            println!("reserved       {} (for YED fees)", yec(reserved));
            let held: i64 = utxos
                .iter()
                .filter(|u| u.class == UtxoClass::Held)
                .map(|u| u.value)
                .sum();
            let held_n = utxos.iter().filter(|u| u.class == UtxoClass::Held).count();
            if held_n > 0 {
                println!(
                    "held           {held_n} output(s), {} (exactly TOKEN_VALUE; classified in W2)",
                    yec(held)
                );
            }
            let pending = fail(w.store.history())
                .into_iter()
                .filter(|h| h.pending)
                .count();
            println!(
                "utxos {} (locked {}), pending tx {}, synced to {}",
                utxos.len(),
                locked,
                pending,
                fail(w.store.meta_u64("last_synced_height"))
            );
        }
        "sync" => {
            let mut w = open_wallet(&o);
            let mut c = client(&o).await;
            let r = fail(sync::sync(&mut w, &mut c).await);
            println!(
                "synced to {} (branch {:08x}): {} addresses, {} tx, {} utxos, {} locks released",
                r.tip, r.branch_id, r.addresses, r.transactions, r.utxos, r.locks_released
            );
            println!("YEC available {}, reserved {}", yec(r.yec.0), yec(r.yec.1));
        }
        "send-yec" => {
            let (to, zat) = match (o.rest.get(1), o.rest.get(2)) {
                (Some(a), Some(z)) => (a.clone(), z.parse::<i64>().unwrap_or_else(|_| usage())),
                _ => usage(),
            };
            let all = o.rest.iter().any(|a| a == "--all");
            let mut w = open_wallet(&o);
            let mut c = client(&o).await;
            let r = fail(sync::sync(&mut w, &mut c).await);
            let p = fail(yec_send::build_yec_send(
                &w,
                &to,
                zat,
                all,
                r.tip,
                r.branch_id,
            ));
            println!(
                "to {} amount {}{} fee {} change {} inputs {} expiry {}",
                p.to,
                yec(p.amount),
                if p.amount_bumped {
                    " (bumped +1 zat off TOKEN_VALUE)"
                } else {
                    ""
                },
                p.fee,
                p.change,
                p.inputs.len(),
                p.expiry_height
            );
            let txid = fail(yec_send::broadcast(&w, &mut c, &p).await);
            println!("sent {txid}");
        }
        "export-wif" => {
            let addr = o.rest.get(1).cloned().unwrap_or_else(|| usage());
            let w = open_wallet(&o);
            println!("{}", fail(w.export_wif(&addr)));
        }
        "import-wif" => {
            let wif = o.rest.get(1).cloned().unwrap_or_else(|| usage());
            let w = open_wallet(&o);
            let row = fail(w.import_wif(&wif));
            println!(
                "imported {} / {} (not covered by the seed backup; run sync)",
                row.address_ye, row.address_s
            );
        }
        "history" => {
            let w = open_wallet(&o);
            for h in fail(w.store.history()) {
                println!(
                    "{} {:>8} {:>+14} zat{}{}{}",
                    txid_hex(&h.txid),
                    if h.pending {
                        "pending".to_string()
                    } else {
                        h.height.to_string()
                    },
                    h.yec_delta,
                    if h.has_payload { " payload" } else { "" },
                    if h.shielded { " shielded" } else { "" },
                    if h.pending { " (unconfirmed)" } else { "" }
                );
            }
        }
        other => {
            eprintln!("unknown command `{other}`");
            usage()
        }
    }
}
