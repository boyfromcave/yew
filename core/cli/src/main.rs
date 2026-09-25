//! `yew-cli`: the developer's and the devnet tests' driver over `yew-core` (plan §6.3).
//!
//! ```text
//! yew-cli [--server host:port] [--plain] [--wallet PATH] [--network regtest|testnet|mainnet]
//!         [--seed-file PATH | YEW_SEED=<mnemonic>] [--passphrase P | YEW_PASSPHRASE=P]
//!         [--birthday H] <command>
//! commands: status | yed-info | price | address [--new] | balance | sync | coins
//!           | send-yec <addr> <zat> [--all] | send-yed <addr> <cents> [<addr> <cents> ...]
//!           | export-wif <addr> | import-wif <wif> | history | version
//! ```
//!
//! No argument-parsing crate: the allow-list (plan §3.3) is the core's, and this binary keeps
//! to the core's dependencies plus `tokio`. Every send goes through `gate::confirm` inside the
//! core's `broadcast`; the CLI has no flag that skips it (D-W-5).

use std::process::exit;

use yew_core::build::{yec_send, yed_transfer};
use yew_core::coins::UtxoClass;
use yew_core::gate::Validator;
use yew_core::net::{Availability, CompactClient, Server, YellowbackClient};
use yew_core::params::Network;
use yew_core::sync;
use yew_core::tx::txid_hex;
use yew_core::wallet::{dollars, Wallet};

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
         commands: status | yed-info | price | address [--new] | balance | sync | coins\n\
         \x20         | send-yec <addr> <zat> [--all] | send-yed <addr> <cents> [<addr> <cents> ...]\n\
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

/// Connect once: the T0 client and, over the same channel, the Yellowback validator
/// (contract rule 1 probed here; `Absent` hides YED).
async fn clients(o: &Opts) -> (CompactClient, Validator, Availability) {
    let server = Server::parse(&o.server, o.plain).unwrap_or_else(|e| {
        eprintln!("{e}");
        exit(2)
    });
    let channel = server.connect().await.unwrap_or_else(|e| {
        eprintln!("cannot connect to {}: {e}", server.uri());
        exit(1)
    });
    let compact = CompactClient::from_channel(channel.clone());
    let (validator, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .unwrap_or_else(|e| {
            eprintln!("Yellowback probe failed: {e}");
            exit(1)
        });
    (compact, validator, availability)
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

fn price_line(micro_usd: Option<i64>) -> String {
    match micro_usd {
        Some(p) => format!(
            "1 YED = $1.00 · mint price ${}.{:06} per YEC ({} YEC per YED)",
            p / 1_000_000,
            p % 1_000_000,
            if p > 0 {
                format!("{:.6}", 1_000_000.0 / p as f64)
            } else {
                "-".into()
            }
        ),
        None => "price: undefined (pMint null)".into(),
    }
}

async fn synced(o: &Opts) -> (Wallet, CompactClient, Validator, sync::SyncReport) {
    let mut w = open_wallet(o);
    let (mut c, mut v, _) = clients(o).await;
    let r = fail(sync::sync(&mut w, &mut c, v.client_mut()).await);
    (w, c, v, r)
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
            let (mut c, _, a) = clients(&o).await;
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
            match &a {
                Availability::Absent => println!("yellowback absent (T0 only)"),
                Availability::Present { info, enabled, active } => println!(
                    "yellowback rpcversion {} enabled {enabled} active {active} usable {} (server {})",
                    info.rpcversion,
                    a.usable(),
                    info.server_version
                ),
            }
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
        "yed-info" => {
            let (_, mut v, a) = clients(&o).await;
            match a {
                Availability::Absent => println!("yellowback absent (UNIMPLEMENTED)"),
                Availability::Present {
                    info,
                    enabled,
                    active,
                } => {
                    println!("rpcversion   {}", info.rpcversion);
                    println!("enabled      {enabled}");
                    println!("active       {active}");
                    println!("network      {}", info.network);
                    println!("height       {} (chain {})", info.height, info.chain_height);
                    println!("healthy      {} {}", info.healthy, info.unhealthy_reason);
                    println!("enforcing    {}", info.enforcing);
                    if let Some(at) = &info.attest {
                        println!(
                            "attest       {} armed {} seated {}",
                            at.status, at.armed, at.seated_count
                        );
                    }
                    if let Some(p) = &info.params {
                        println!(
                            "params       feeZat {} tokenValueZat {} refWindow {}",
                            p.fee_zat, p.token_value_zat, p.ref_window
                        );
                    }
                    println!("server       {}", info.server_version);
                    let yb = v.client_mut().expect("present");
                    let s = fail(yb.stats().await);
                    println!(
                        "stats        supply {} in {} active vault(s), minting allowed {}, global ratio {} bps",
                        dollars(s.supply_cents),
                        s.active_vaults,
                        s.minting_allowed,
                        s.global_ratio_bps
                    );
                }
            }
        }
        "price" => {
            let (_, mut v, _) = clients(&o).await;
            let yb = v.client_mut().unwrap_or_else(|| {
                eprintln!("yellowback absent: no price");
                exit(1)
            });
            let p = fail(yb.price(0).await);
            println!(
                "{}",
                price_line(if p.p_mint > 0 { Some(p.p_mint) } else { None })
            );
            println!(
                "height {} armed {} attest {} pFast {} pMid {} pSlow {} pClaim {} xMint {}",
                p.height,
                p.armed,
                p.attest_status,
                p.p_fast,
                p.p_mid,
                p.p_slow,
                p.p_claim,
                p.x_mint
            );
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
            let b = fail(w.balances());
            let utxos = fail(w.store.utxos());
            println!("YED            {}", dollars(b.yed_cents as i64));
            if b.yed_pending_cents > 0 {
                println!("YED pending    {}", dollars(b.yed_pending_cents as i64));
            }
            println!("{}", price_line(b.price_micro_usd));
            println!("YEC available  {}", yec(b.yec_zat));
            println!("reserved       {} (for YED fees)", yec(b.yec_reserved_zat));
            if b.yec_pending_zat > 0 {
                println!("YEC pending    {}", yec(b.yec_pending_zat));
            }
            let held: Vec<&yew_core::coins::Utxo> = utxos
                .iter()
                .filter(|u| u.class == UtxoClass::Held)
                .collect();
            if !held.is_empty() {
                println!(
                    "held           {} output(s), {} (TOKEN_VALUE, not listed by GetAddressTokens; unspendable)",
                    held.len(),
                    yec(held.iter().map(|u| u.value).sum())
                );
            }
            let locked = fail(w.store.locks()).len();
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
        "coins" => {
            let w = open_wallet(&o);
            let locked: std::collections::HashSet<_> = fail(w.store.locks())
                .into_iter()
                .map(|l| l.outpoint)
                .collect();
            for u in fail(w.store.utxos()) {
                println!(
                    "{:<14} {:>12} zat {:>10} {:>6} {} {}{}",
                    u.class.as_str(),
                    u.value,
                    if u.cents > 0 {
                        dollars(u.cents as i64)
                    } else {
                        String::new()
                    },
                    if u.height > 0 {
                        u.height.to_string()
                    } else {
                        "pending".into()
                    },
                    u.outpoint.display(),
                    u.address,
                    if locked.contains(&u.outpoint) {
                        " [locked]"
                    } else {
                        ""
                    }
                );
            }
        }
        "sync" => {
            let (_, _, _, r) = synced(&o).await;
            println!(
                "synced to {} (branch {:08x}): {} addresses, {} tx, {} utxos, {} tokens, {} labelled, {} locks released{}",
                r.tip, r.branch_id, r.addresses, r.transactions, r.utxos, r.tokens, r.labelled, r.locks_released,
                if r.yellowback { "" } else { " (yellowback absent)" }
            );
            println!(
                "YED {} (pending {}); YEC available {}, reserved {}",
                dollars(r.yed.0 as i64),
                dollars(r.yed.1 as i64),
                yec(r.yec.0),
                yec(r.yec.1)
            );
            println!("{}", price_line(r.price_micro_usd));
        }
        "send-yec" => {
            let (to, zat) = match (o.rest.get(1), o.rest.get(2)) {
                (Some(a), Some(z)) => (a.clone(), z.parse::<i64>().unwrap_or_else(|_| usage())),
                _ => usage(),
            };
            let all = o.rest.iter().any(|a| a == "--all");
            let (w, mut c, mut v, r) = synced(&o).await;
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
            let txid = fail(yec_send::broadcast(&w, &mut c, &mut v, &p).await);
            println!("sent {txid}");
        }
        "send-yed" => {
            let args = &o.rest[1..];
            if args.is_empty() || !args.len().is_multiple_of(2) {
                usage();
            }
            let recipients: Vec<(String, u64)> = args
                .chunks(2)
                .map(|p| {
                    (
                        p[0].clone(),
                        p[1].parse::<u64>().unwrap_or_else(|_| usage()),
                    )
                })
                .collect();
            let (w, mut c, mut v, r) = synced(&o).await;
            let p = fail(yed_transfer::build_yed_transfer(
                &w,
                &recipients,
                r.tip,
                r.branch_id,
            ));
            println!(
                "sending {} to {} recipient(s): stage {} yed inputs {} change {} | yec inputs {} fee {} zat change {} zat | expiry {} payload {}",
                dollars(recipients.iter().map(|r| r.1 as i64).sum()),
                recipients.len(),
                p.stage.name(),
                p.yed_inputs.len(),
                dollars(p.change_cents as i64),
                p.yec_inputs.len(),
                p.fee,
                p.yec_change,
                p.expiry_height,
                yew_core::keys::hex(&p.payload)
            );
            let (txid, val) = fail(yed_transfer::broadcast(&w, &mut c, &mut v, &p).await);
            println!(
                "sent {txid} (node dry run: verdict {} valid {} burned {} yedIn {} yedOut {})",
                val.verdict, val.valid, val.burned, val.yed_in, val.yed_out
            );
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
                    "{} {:>8} {:>+14} zat {:>+12} {:<32}{}{}{}",
                    txid_hex(&h.txid),
                    if h.pending {
                        "pending".to_string()
                    } else {
                        h.height.to_string()
                    },
                    h.yec_delta,
                    if h.yed_delta != 0 || !h.kind.is_empty() {
                        dollars(h.yed_delta)
                    } else {
                        String::new()
                    },
                    if h.label.is_empty() {
                        if h.has_payload {
                            if h.labelled {
                                "(payload, not yellowback)"
                            } else {
                                "(payload, unlabelled)"
                            }
                        } else {
                            ""
                        }
                        .to_string()
                    } else {
                        h.label.clone()
                    },
                    if h.verdict.is_empty() {
                        String::new()
                    } else {
                        format!(" verdict {}", h.verdict)
                    },
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
