// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The command line and the configuration file, ycashd-style: `-name=value`, `-name` (= 1),
//! `-noname` (= 0), `--name` accepted too; the file holds `name=value` lines, `#` comments.
//! The command line wins over the file. The contract is documented in `yewd/README.md`
//! ("Command line") for the harness (`YEWD_BIN`).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::allowip::AllowIp;

/// The network, which picks the default RPC port and the data subdirectory (as ycashd's
/// `chainparamsbase.cpp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
    Regtest,
}

impl Network {
    /// ycashd's default RPC port, so tools that assume it reach the façade.
    pub fn default_rpc_port(self) -> u16 {
        match self {
            Network::Main => 8832,
            Network::Test | Network::Regtest => 18832,
        }
    }

    /// The subdirectory of `-datadir` that holds `.cookie` (empty on mainnet).
    pub fn subdir(self) -> &'static str {
        match self {
            Network::Main => "",
            Network::Test => "testnet",
            Network::Regtest => "regtest",
        }
    }
}

/// The options yewd understands. Others are reported as ignored (stderr) and do not stop it,
/// so a harness can pass ycashd's wallet arguments wholesale (S4 gives them meaning).
pub const KNOWN: &[&str] = &[
    "conf",
    "datadir",
    "regtest",
    "testnet",
    "rpcbind",
    "rpcport",
    "rpcuser",
    "rpcpassword",
    "rpcallowip",
    "rpccookiefile",
    "backendrpcconnect",
    "backendrpcport",
    "backendrpccookiefile",
    "backendrpcuser",
    "backendrpcpassword",
    "stopbackend",
    "signer",
    "signerbin",
    "walletpoll",
    "initwallet",
    "exportdir",
    "paytxfee",
    "developerencryptwallet",
    "experimentalfeatures",
    "wallet",
    "rescan",
    "salvagewallet",
    "paramsdir",
    "backendexitgrace",
    "backendindexer",
    "disablewallet",
    "mocktime",
    "pqfeerate",
    "pqfalconheight",
    "pqfalcon",
    "printtoconsole",
    "debug",
    "help",
    "?",
    "version",
];

/// The resolved configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub network: Network,
    pub datadir: PathBuf,
    /// Where the façade listens.
    pub bind: Vec<SocketAddr>,
    /// `rpcuser:rpcpassword`, or `None` for cookie authentication.
    pub user_pass: Option<(String, String)>,
    /// The cookie file the façade writes when `user_pass` is `None`.
    pub cookie_file: PathBuf,
    pub allow: AllowIp,
    /// The backend's JSON-RPC endpoint (kogany, or ycash6 `-disablewallet`).
    pub backend: SocketAddr,
    pub backend_auth: BackendAuth,
    /// `stop` stops the backend too (the harness bundle: the pair is one node, hazard H6).
    pub stop_backend: bool,
    /// A signer someone else runs: its Unix-domain socket (`yewd-signer serve`); without it the
    /// façade starts its own signer process.
    pub signer: Option<PathBuf>,
    /// The `yewd-signer` binary (S1 runs it as a child process); default beside `yewd`.
    pub signer_bin: Option<PathBuf>,
    /// The wallet's poll interval in milliseconds (the fallback wake-up; 0 = barrier only).
    pub wallet_poll_ms: u64,
    pub debug: bool,
    /// The ycashd wallet arguments yewd gives meaning to (S4).
    pub wallet_args: crate::wallet::WalletArgs,
    /// With `-stopbackend`: exit when the backend has been unreachable this many seconds after
    /// it was reachable (the pair is one node, H6); 0 = never.
    pub backend_exit_grace: u64,
    /// kogany's indexer gRPC listener (`-backendindexer=<ip:port>`): its `ChainTipChange` and
    /// `MempoolChange` streams wake the wallet (H3, H4); never the source of truth.
    pub backend_indexer: Option<SocketAddr>,
    /// `-disablewallet` (ycashd's): no wallet is opened and no wallet method is served; the façade
    /// is the node's RPC alone (a node a script starts without a wallet, in the harness's pairs).
    pub disable_wallet: bool,
    /// `-mocktime=<t>` (ycashd's): the façade's clock starts mocked (H11).
    pub mocktime: i64,
    /// `-pqfeerate=<YEC/kB>` (ycashd's wallet fee option): the size-priced fees' rate without a price.
    pub pq_fee_rate: i64,
    /// `-pqfalconheight=<h>` / `-pqfalcon=1` (= 0): the regtest Falcon height; -1 = not given.
    pub falcon_height: i64,
    /// Options given but not understood (reported at start).
    pub ignored: Vec<String>,
}

/// How the façade authenticates to the backend.
#[derive(Clone, Debug)]
pub enum BackendAuth {
    /// The backend's `.cookie` (`__cookie__:<hex>`), re-read whenever the backend answers 401
    /// (a restarted backend writes a new one).
    Cookie(PathBuf),
    UserPass(String, String),
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(m: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(m.into()))
}

/// Parsed `name -> values` (a name may repeat: `rpcbind`, `rpcallowip`).
#[derive(Clone, Debug, Default)]
pub struct Args(BTreeMap<String, Vec<String>>);

impl Args {
    /// From the command line (without the program name).
    pub fn from_cli<I: IntoIterator<Item = String>>(it: I) -> Result<Self, ConfigError> {
        let mut a = Args::default();
        for arg in it {
            let Some(body) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
                return err(format!(
                    "yewd: unexpected argument {arg:?} (options start with -)"
                ));
            };
            a.push_option(body);
        }
        Ok(a)
    }

    /// From a configuration file's text.
    pub fn from_conf(text: &str) -> Self {
        let mut a = Args::default();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if !line.is_empty() {
                a.push_option(line);
            }
        }
        a
    }

    fn push_option(&mut self, body: &str) {
        let (name, value) = match body.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => match body.strip_prefix("no") {
                // `-nofoo` = `-foo=0`, as ycashd (only for a known option, so `-nonsense` stays itself)
                Some(rest) if KNOWN.contains(&rest) => (rest.to_string(), "0".to_string()),
                _ => (body.to_string(), "1".to_string()),
            },
        };
        self.0.entry(name).or_default().push(value);
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).and_then(|v| v.last()).map(String::as_str)
    }

    pub fn all(&self, name: &str) -> &[String] {
        self.0.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn flag(&self, name: &str) -> bool {
        matches!(self.get(name), Some(v) if v != "0" && !v.is_empty())
    }

    pub fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// `other` fills what `self` lacks (the command line over the file).
    pub fn over(mut self, other: Args) -> Self {
        for (k, v) in other.0 {
            self.0.entry(k).or_insert(v);
        }
        self
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

fn default_datadir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".yewd")
}

fn parse_port(name: &str, v: &str) -> Result<u16, ConfigError> {
    match v.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => err(format!("yewd: -{name}={v} is not a port")),
    }
}

fn parse_bind(v: &str, port: u16) -> Result<SocketAddr, ConfigError> {
    if let Ok(sa) = v.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let host = v.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, port)),
        Err(_) => err(format!(
            "yewd: -rpcbind={v} is not an IP address (host names are not resolved)"
        )),
    }
}

impl Config {
    /// Resolve the command line, reading `-conf` (default `<datadir>/yewd.conf`, optional).
    pub fn load(cli: Args) -> Result<Self, ConfigError> {
        let (a, datadir) = Self::merged(cli)?;
        Self::resolve(a, datadir)
    }

    /// The command line over the configuration file, and the data directory.
    pub fn merged(cli: Args) -> Result<(Args, PathBuf), ConfigError> {
        let datadir = cli
            .get("datadir")
            .map(PathBuf::from)
            .unwrap_or_else(default_datadir);
        let conf_given = cli.get("conf").map(PathBuf::from);
        let conf_path = match &conf_given {
            Some(p) if p.is_relative() => datadir.join(p),
            Some(p) => p.clone(),
            None => datadir.join("yewd.conf"),
        };
        let file = match std::fs::read_to_string(&conf_path) {
            Ok(t) => Args::from_conf(&t),
            Err(e) if conf_given.is_none() && e.kind() == std::io::ErrorKind::NotFound => {
                Args::default()
            }
            Err(e) => return err(format!("yewd: cannot read {}: {e}", conf_path.display())),
        };
        Ok((cli.over(file), datadir))
    }

    /// The network the merged options name.
    pub fn network_of(a: &Args) -> Result<Network, ConfigError> {
        match (a.flag("regtest"), a.flag("testnet")) {
            (true, true) => err("yewd: -regtest and -testnet together"),
            (true, false) => Ok(Network::Regtest),
            (false, true) => Ok(Network::Test),
            _ => Ok(Network::Main),
        }
    }

    /// Resolve already merged options.
    pub fn resolve(a: Args, datadir: PathBuf) -> Result<Self, ConfigError> {
        let network = Self::network_of(&a)?;
        let port = match a.get("rpcport") {
            Some(v) => parse_port("rpcport", v)?,
            None => network.default_rpc_port(),
        };
        let bind = if a.all("rpcbind").is_empty() {
            vec![SocketAddr::from(([127, 0, 0, 1], port))]
        } else {
            a.all("rpcbind")
                .iter()
                .map(|v| parse_bind(v, port))
                .collect::<Result<_, _>>()?
        };
        let user_pass = match (a.get("rpcuser"), a.get("rpcpassword")) {
            (_, None) | (_, Some("")) => None,
            (u, Some(p)) => Some((u.unwrap_or("").to_string(), p.to_string())),
        };
        let netdir = datadir.join(network.subdir());
        let cookie_file = match a.get("rpccookiefile") {
            Some(p) if Path::new(p).is_relative() => netdir.join(p),
            Some(p) => PathBuf::from(p),
            None => netdir.join(".cookie"),
        };
        let allow =
            AllowIp::parse(a.all("rpcallowip")).map_err(|e| ConfigError(format!("yewd: {e}")))?;
        let backend_host = a.get("backendrpcconnect").unwrap_or("127.0.0.1");
        let Some(backend_port) = a.get("backendrpcport") else {
            return err("yewd: -backendrpcport is required (the wallet-less node's RPC port)");
        };
        let backend_port = parse_port("backendrpcport", backend_port)?;
        let backend = parse_bind(backend_host, backend_port).map_err(|_| {
            ConfigError(format!(
                "yewd: -backendrpcconnect={backend_host} is not an IP address"
            ))
        })?;
        let backend_auth = match (a.get("backendrpccookiefile"), a.get("backendrpcpassword")) {
            (Some(c), None) => BackendAuth::Cookie(PathBuf::from(c)),
            (None, Some(p)) => BackendAuth::UserPass(
                a.get("backendrpcuser").unwrap_or("").to_string(),
                p.to_string(),
            ),
            (Some(_), Some(_)) => {
                return err("yewd: give -backendrpccookiefile or -backendrpcpassword, not both")
            }
            (None, None) => return err(
                "yewd: -backendrpccookiefile (or -backendrpcuser/-backendrpcpassword) is required",
            ),
        };
        let ignored = a
            .names()
            .filter(|n| !KNOWN.contains(n))
            .map(|n| format!("-{n}"))
            .collect();
        Ok(Config {
            network,
            datadir,
            bind,
            user_pass,
            cookie_file,
            allow,
            backend,
            backend_auth,
            stop_backend: a.flag("stopbackend"),
            signer: a.get("signer").map(PathBuf::from),
            signer_bin: a.get("signerbin").map(PathBuf::from),
            wallet_poll_ms: match a.get("walletpoll") {
                Some(v) => v.parse().map_err(|_| {
                    ConfigError(format!(
                        "yewd: -walletpoll={v} is not a number of milliseconds"
                    ))
                })?,
                None => 1000,
            },
            debug: a.has("debug"),
            wallet_args: crate::wallet::WalletArgs {
                opts: yewd_wallet::admin::Opts {
                    export_dir: a.get("exportdir").map(PathBuf::from),
                    // ycashd needs -experimentalfeatures -developerencryptwallet; the harness hands
                    // those to the backend, so yewd allows encryption unless told 0 (F-S4-3)
                    encrypt_allowed: a.get("developerencryptwallet") != Some("0"),
                    paytxfee: match a.get("paytxfee") {
                        Some(v) => yewd_wallet::json::parse_amount(v).ok_or_else(|| {
                            ConfigError(format!("yewd: -paytxfee={v} is not an amount"))
                        })?,
                        None => 0,
                    },
                    params_dir: a.get("paramsdir").map(PathBuf::from),
                },
                wallet_file: a.get("wallet").map(PathBuf::from),
                rescan: a.flag("rescan"),
                salvage: a.flag("salvagewallet"),
            },
            falcon_height: match (a.get("pqfalconheight"), a.get("pqfalcon")) {
                (Some(v), _) => v.parse().map_err(|_| {
                    ConfigError(format!("yewd: -pqfalconheight={v} is not a height"))
                })?,
                (None, Some("1" | "")) => 0,
                _ => -1,
            },
            pq_fee_rate: match a.get("pqfeerate") {
                Some(v) => yewd_wallet::json::parse_amount(v)
                    .filter(|n| *n > 0)
                    .ok_or_else(|| {
                        ConfigError(format!("Invalid amount for -pqfeerate=<amount>: '{v}'"))
                    })?,
                None => 0,
            },
            mocktime: match a.get("mocktime") {
                Some(v) => v.parse().map_err(|_| {
                    ConfigError(format!("yewd: -mocktime={v} is not a number of seconds"))
                })?,
                None => 0,
            },
            disable_wallet: a.get("disablewallet").is_some_and(|v| v != "0")
                || a.flag("disablewallet"),
            backend_indexer: match a.get("backendindexer") {
                Some(v) => Some(v.parse().map_err(|_| {
                    ConfigError(format!("yewd: -backendindexer={v} is not an ip:port"))
                })?),
                None => None,
            },
            backend_exit_grace: match a.get("backendexitgrace") {
                Some(v) => v.parse().map_err(|_| {
                    ConfigError(format!(
                        "yewd: -backendexitgrace={v} is not a number of seconds"
                    ))
                })?,
                None => 20,
            },
            ignored,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(v: &[&str]) -> Args {
        Args::from_cli(v.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn regtest_defaults() {
        let c = Config::resolve(
            cli(&[
                "-regtest",
                "-backendrpcport=28832",
                "-backendrpccookiefile=/b/.cookie",
            ]),
            PathBuf::from("/d"),
        )
        .unwrap();
        assert_eq!(c.network, Network::Regtest);
        assert_eq!(c.bind, vec!["127.0.0.1:18832".parse().unwrap()]);
        assert_eq!(c.cookie_file, PathBuf::from("/d/regtest/.cookie"));
        assert!(c.user_pass.is_none());
        assert!(!c.stop_backend);
        assert_eq!(c.backend, "127.0.0.1:28832".parse().unwrap());
    }

    #[test]
    fn cli_over_file_and_ignored_options() {
        let file = Args::from_conf(
            "regtest=1\nrpcuser=u\nrpcpassword=p # c\nrpcport=19000\nshowmetrics=0\n",
        );
        let a = cli(&[
            "-rpcport=19001",
            "--stopbackend",
            "-keypool=1",
            "-backendrpcport=1",
            "-backendrpcpassword=x",
        ])
        .over(file);
        let c = Config::resolve(a, PathBuf::from("/d")).unwrap();
        assert_eq!(c.bind[0].port(), 19001);
        assert_eq!(c.user_pass, Some(("u".into(), "p".into())));
        assert!(c.stop_backend);
        assert_eq!(
            c.ignored,
            vec!["-keypool".to_string(), "-showmetrics".to_string()]
        );
    }

    #[test]
    fn negation_and_errors() {
        assert!(!cli(&["-nostopbackend"]).flag("stopbackend"));
        assert!(Config::resolve(cli(&["-regtest"]), PathBuf::from("/d")).is_err());
        assert!(Config::resolve(cli(&["-backendrpcport=1"]), PathBuf::from("/d")).is_err());
        assert!(Args::from_cli(["plain".to_string()]).is_err());
    }
}
