// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yew-attestor`: the light attestor's transactions, built and signed by `yew-core`
//! (`build::attestor`) from a seat key file and sent through one or more lightwalletd-dd
//! endpoints — no node, no wallet (workspace `docs/plans/beta4/price-feed.md` §2.2, §2.3, B-T2,
//! B-T5; the agent's `[backend] kind = "lightwalletd"` calls it for the heartbeat, the cancel
//! driver and the on-chain co-signature fallback).
//!
//! ```text
//! yew-attestor --network regtest|testnet|mainnet --key-file PATH --lightwalletd URL [--lightwalletd URL2 ...]
//!              [--insecure] <command> [--dry-run]
//! commands: address
//!         | join --set SETID --bond ZAT --locktime H
//!         | heartbeat --set SETID
//!         | leave --set SETID
//!         | withdraw --set SETID [--to TADDR]
//!         | cancel --intent TXID:N --cosigs FILE|-
//!         | op-return --data HEX --fee-zat N
//! ```
//!
//! Every command prints one JSON object on stdout: exit 0 on success, exit 1 with
//! `{"error", "code"}` otherwise. The key file holds the seat's compressed WIF on its first
//! non-empty, non-`#` line and must not be readable by group or world. Funding: the seat's own
//! confirmed P2PKH coins (`GetAddressUtxos`), never a YED token (`GetAddressTokens`, and never a
//! coin of `TOKEN_VALUE` or less), never a bond or carrier (P2SH); change back to the seat.
//! Signing for the next block's branch (`GetChainInfo`). Each transaction is checked with
//! `ValidateRawTransaction` on the first endpoint, then sent to every endpoint (success when one
//! accepts). `--dry-run` builds, signs and checks, and sends nothing. `--insecure` (plaintext
//! h2c) is accepted for loopback hosts only.

use std::process::exit;

use serde_json::{json, Value};

use yew_core::build::attestor::{self as ba, BuildError, Coin};
use yew_core::cosign::CosignEntry;
use yew_core::keys::{self, AddressKey};
use yew_core::net::{CompactClient, Server, YellowbackClient};
use yew_core::params::{Network, REF_WINDOW, TOKEN_VALUE};
use yew_core::tx::{txid_from_hex, txid_hex, OutPoint, Transaction};
use yew_core::vault;

/// `DEFAULT_POST_BLOSSOM_TX_EXPIRY_DELTA`: a one-shot transaction expires this many blocks after
/// the next.
const EXPIRY_DELTA: u32 = 40;

type Fail = BuildError;

fn fail(code: &'static str, msg: impl Into<String>) -> Fail {
    BuildError::new(code, msg)
}

fn net_err(e: impl std::fmt::Display) -> Fail {
    fail("lightwalletd", e.to_string())
}

const USAGE: &str = "yew-attestor --network regtest|testnet|mainnet --key-file PATH --lightwalletd URL [--lightwalletd URL2 ...] [--insecure] <command> [--dry-run]; commands: address | join --set SETID --bond ZAT --locktime H | heartbeat --set SETID | leave --set SETID | withdraw --set SETID [--to TADDR] | cancel --intent TXID:N --cosigs FILE|- | op-return --data HEX --fee-zat N";

#[derive(Debug)]
struct Opts {
    network: Network,
    key_file: String,
    endpoints: Vec<String>,
    insecure: bool,
    dry_run: bool,
    command: String,
    args: Vec<(String, String)>,
}

impl Opts {
    fn get(&self, k: &str) -> Option<&str> {
        self.args
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }

    fn need(&self, k: &str) -> Result<&str, Fail> {
        self.get(k)
            .ok_or_else(|| fail("usage", format!("{} needs --{k}", self.command)))
    }

    fn int(&self, k: &str) -> Result<i64, Fail> {
        self.need(k)?
            .parse()
            .map_err(|_| fail("usage", format!("--{k} must be an integer")))
    }
}

fn parse_args(argv: &[String]) -> Result<Opts, Fail> {
    let mut network = None;
    let mut key_file = None;
    let mut endpoints = Vec::new();
    let mut insecure = false;
    let mut dry_run = false;
    let mut command = None;
    let mut args = Vec::new();
    let mut i = 0;
    let value = |i: usize| -> Result<String, Fail> {
        argv.get(i + 1)
            .cloned()
            .ok_or_else(|| fail("usage", format!("{} needs a value", argv[i])))
    };
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "--network" => {
                let v = value(i)?;
                network = Some(
                    Network::from_name(&v)
                        .ok_or_else(|| fail("usage", format!("unknown network {v}")))?,
                );
                i += 2;
            }
            "--key-file" => {
                key_file = Some(value(i)?);
                i += 2;
            }
            "--lightwalletd" => {
                endpoints.push(value(i)?);
                i += 2;
            }
            "--insecure" => {
                insecure = true;
                i += 1;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "-h" | "--help" => return Err(fail("usage", USAGE)),
            _ if a.starts_with("--") => {
                if command.is_none() {
                    return Err(fail("usage", format!("unknown option {a}")));
                }
                args.push((a[2..].to_string(), value(i)?));
                i += 2;
            }
            _ => {
                if command.is_some() {
                    return Err(fail("usage", format!("unexpected argument {a}")));
                }
                command = Some(a.to_string());
                i += 1;
            }
        }
    }
    let command = command.ok_or_else(|| fail("usage", USAGE))?;
    Ok(Opts {
        network: network.ok_or_else(|| fail("usage", "--network is required"))?,
        key_file: key_file.ok_or_else(|| fail("usage", "--key-file is required"))?,
        endpoints,
        insecure,
        dry_run,
        command,
        args,
    })
}

/// The seat key (§2 of the light-attestor contract): mode 0600 or stricter, the first
/// non-empty, non-`#` line a compressed WIF of `network`.
fn read_key(path: &str, network: Network) -> Result<AddressKey, Fail> {
    let meta = std::fs::metadata(path).map_err(|e| fail("key-file", format!("{path}: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(fail(
                "key-file",
                format!(
                    "{path} is readable by group or world (mode {:o}); chmod 600 it",
                    mode & 0o777
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    let text = keys::SecretString::new(
        std::fs::read_to_string(path).map_err(|e| fail("key-file", format!("{path}: {e}")))?,
    );
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| fail("key-file", format!("{path} holds no key")))?
        .to_string();
    let line = keys::SecretString::new(line);
    keys::decode_wif(network, &line).map_err(|e| fail("key-file", e.to_string()))
}

/// `https://host:port`, `http://host:port` (with `--insecure`) or `host:port`.
fn server_of(url: &str, insecure: bool) -> Result<Server, Fail> {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };
    let rest = rest.trim_end_matches('/');
    if scheme == Some("http") && !insecure {
        return Err(fail("usage", format!("{url}: plaintext needs --insecure")));
    }
    if !matches!(scheme, None | Some("http") | Some("https")) {
        return Err(fail("usage", format!("{url}: unknown scheme")));
    }
    let s = Server::parse(rest, insecure).map_err(|e| fail("usage", e))?;
    if insecure {
        let h = s.host.trim_start_matches('[').trim_end_matches(']');
        let loopback = h == "localhost"
            || h.parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if !loopback {
            return Err(fail(
                "insecure-remote",
                format!(
                    "--insecure is allowed only to loopback hosts, not {}",
                    s.host
                ),
            ));
        }
    }
    Ok(s)
}

struct Endpoint {
    url: String,
    compact: CompactClient,
    yb: YellowbackClient,
}

struct Ctx {
    network: Network,
    seat: AddressKey,
    eps: Vec<Endpoint>,
    tip: u32,
    branch: u32,
    dry_run: bool,
}

impl Ctx {
    async fn connect(o: &Opts) -> Result<Ctx, Fail> {
        let seat = read_key(&o.key_file, o.network)?;
        if o.endpoints.is_empty() {
            return Err(fail("usage", "at least one --lightwalletd is required"));
        }
        let mut eps = Vec::new();
        for url in &o.endpoints {
            let s = server_of(url, o.insecure)?;
            let ch = s
                .connect()
                .await
                .map_err(|e| fail("lightwalletd", format!("{url}: {e}")))?;
            let mut compact = CompactClient::from_channel(ch.clone());
            compact
                .lightd_info_for(o.network)
                .await
                .map_err(|e| fail("lightwalletd", format!("{url}: {e}")))?;
            eps.push(Endpoint {
                url: url.clone(),
                compact,
                yb: YellowbackClient::from_channel(ch),
            });
        }
        // `address` reads nothing from the chain
        let (mut tip, mut branch) = (0u64, 0u32);
        if o.command != "address" {
            (tip, branch) = eps[0]
                .yb
                .chain_info()
                .await
                .map_err(net_err)?
                .ok_or_else(|| {
                    fail(
                        "lightwalletd",
                        "the server has no GetChainInfo (next block's branch)",
                    )
                })?;
            // lightwalletd's answers can trail the node by a block; the higher of its two tips
            let latest = eps[0].compact.latest_height().await.map_err(net_err)?;
            tip = tip.max(latest);
        }
        Ok(Ctx {
            network: o.network,
            seat,
            eps,
            tip: tip as u32,
            branch,
            dry_run: o.dry_run,
        })
    }

    fn address(&self) -> String {
        self.seat.address_s(self.network)
    }

    fn next(&self) -> u32 {
        self.tip + 1
    }

    fn expiry(&self) -> u32 {
        self.next() + EXPIRY_DELTA
    }

    /// The seat's fundable coins: confirmed P2PKH of its key, never a YED token.
    async fn coins(&mut self) -> Result<Vec<Coin>, Fail> {
        let addr = self.address();
        let spk = ba::seat_script(&self.seat);
        let utxos = self.eps[0]
            .compact
            .address_utxos(std::slice::from_ref(&addr), 0)
            .await
            .map_err(net_err)?;
        let tokens = self.eps[0]
            .yb
            .address_tokens(std::slice::from_ref(&addr), 0)
            .await
            .map_err(net_err)?;
        Ok(utxos
            .into_iter()
            .filter(|u| u.script == spk && u.height > 0 && u.value_zat > TOKEN_VALUE)
            .map(|u| Coin {
                outpoint: OutPoint {
                    txid: u.txid,
                    n: u.index,
                },
                value: u.value_zat,
                script: u.script,
            })
            .filter(|c| !tokens.iter().any(|t| t.outpoint == c.outpoint))
            .collect())
    }

    /// `ValidateRawTransaction` on the first endpoint: valid, verdict ok, not refused.
    async fn validate(&mut self, tx: &Transaction) -> Result<Value, Fail> {
        let raw = tx.serialize()?;
        let v = self.eps[0].yb.validate_raw(raw).await.map_err(net_err)?;
        let j = json!({"valid": v.valid, "verdict": v.verdict, "wouldBeRejected": v.would_be_rejected,
                       "unconfirmedInputs": v.unconfirmed_inputs.len()});
        if !(v.valid && v.verdict == "ok" && !v.would_be_rejected) {
            return Err(fail(
                "invalid",
                format!("ValidateRawTransaction refused it: {j}"),
            ));
        }
        Ok(j)
    }

    /// `SendTransaction` to every endpoint; success when one accepts.
    async fn send(&mut self, tx: &Transaction) -> Result<Value, Fail> {
        let raw = tx.serialize()?;
        let mut sent = Vec::new();
        let mut ok = false;
        for ep in &mut self.eps {
            match ep.compact.send_transaction(raw.clone()).await {
                Ok(t) => {
                    ok = true;
                    sent.push(json!({"endpoint": ep.url, "ok": true, "txid": t}));
                }
                Err(e) => {
                    sent.push(json!({"endpoint": ep.url, "ok": false, "error": e.to_string()}))
                }
            }
        }
        if !ok {
            return Err(fail(
                "send",
                format!(
                    "no endpoint accepted the transaction: {}",
                    Value::Array(sent)
                ),
            ));
        }
        Ok(Value::Array(sent))
    }

    /// Validate, then (unless `--dry-run`) send; the result object gets `txid` and `hex` (dry
    /// run) or `sent`.
    async fn finish(&mut self, tx: &Transaction, mut out: Value) -> Result<Value, Fail> {
        let txid = txid_hex(&tx.txid()?);
        self.validate(tx).await?;
        out["txid"] = json!(txid);
        if self.dry_run {
            out["hex"] = json!(keys::hex(&tx.serialize()?));
        } else {
            out["sent"] = self.send(tx).await?;
        }
        Ok(out)
    }

    async fn set(&mut self, set: &str) -> Result<yew_core::net::rpc::VaultSet, Fail> {
        self.eps[0]
            .yb
            .get_set(set, 0)
            .await
            .map_err(|e| fail("unknown-set", format!("set {set}: {e}")))
    }

    async fn raw_tx(&mut self, txid: &[u8; 32]) -> Result<(Transaction, u64), Fail> {
        let (raw, h) = self.eps[0]
            .compact
            .get_transaction(txid)
            .await
            .map_err(net_err)?
            .ok_or_else(|| {
                fail(
                    "unknown-tx",
                    format!("transaction {} not found", txid_hex(txid)),
                )
            })?;
        let (t, _) = Transaction::parse(&raw)?;
        Ok((t, h))
    }
}

fn set_id_of(s: &str) -> Result<[u8; 32], Fail> {
    txid_from_hex(s).map_err(|e| fail("usage", format!("--set: {e}")))
}

fn outpoint_of(s: &str) -> Result<OutPoint, Fail> {
    let (t, n) = s
        .rsplit_once(':')
        .ok_or_else(|| fail("usage", format!("{s}: expected TXID:N")))?;
    Ok(OutPoint {
        txid: txid_from_hex(t).map_err(|e| fail("usage", e))?,
        n: n.parse()
            .map_err(|_| fail("usage", format!("{s}: bad output index")))?,
    })
}

async fn run(o: Opts) -> Result<Value, Fail> {
    let mut c = Ctx::connect(&o).await?;
    let pubkey = keys::hex(&c.seat.pubkey);
    match o.command.as_str() {
        "address" => Ok(json!({"pubkey": pubkey, "address": c.address()})),
        "join" => {
            let set_hex = o.need("set")?.to_string();
            let set = set_id_of(&set_hex)?;
            let bond = o.int("bond")?;
            let lt = o.int("locktime")?;
            if !(1..500_000_000).contains(&lt) {
                return Err(fail("usage", "--locktime must be a height below 500000000"));
            }
            let s = c.set(&set_hex).await?;
            if !s.open {
                return Err(fail(
                    "set-not-open",
                    "the set is not open: a join needs the admit key or slashThreshold members as well",
                ));
            }
            let coins = c.coins().await?;
            let tx = ba::build_join(&c.seat, &coins, &set, bond, lt as u32, c.branch, c.expiry())?;
            let txid = txid_hex(&tx.txid()?);
            c.finish(
                &tx,
                json!({"memberkey": pubkey, "bondoutpoint": format!("{txid}:0")}),
            )
            .await
        }
        "heartbeat" => {
            let set_hex = o.need("set")?.to_string();
            let set = set_id_of(&set_hex)?;
            c.set(&set_hex).await?;
            let coins = c.coins().await?;
            let tx = ba::build_heartbeat(&c.seat, &coins, &set, c.branch, c.expiry())?;
            c.finish(&tx, json!({})).await
        }
        "leave" => {
            let set_hex = o.need("set")?.to_string();
            let set = set_id_of(&set_hex)?;
            let s = c.set(&set_hex).await?;
            let coins = c.coins().await?;
            let tx = ba::build_leave(&c.seat, &coins, &set, c.branch, c.expiry())?;
            // the next block as seen now; set_getinfo's exitheight / unlockheight (the block the
            // leave confirms in) are the record
            let exit = c.next() as i64;
            c.finish(
                &tx,
                json!({"exitheight": exit, "bondspendableat": exit + s.maturity}),
            )
            .await
        }
        "withdraw" => {
            let set_hex = o.need("set")?.to_string();
            let s = c.set(&set_hex).await?;
            let m = s
                .memberlist
                .iter()
                .find(|m| m.key == pubkey)
                .cloned()
                .ok_or_else(|| {
                    fail(
                        "not-member",
                        "the seat key has no member record (or its bond is spent)",
                    )
                })?;
            if m.bondfrozen {
                return Err(fail("bond-frozen", "the bond is frozen (slashed)"));
            }
            if m.unlockheight == 0 {
                return Err(fail(
                    "bond-locked",
                    format!(
                        "the seat is still a member ({}); leave the set first",
                        m.status
                    ),
                ));
            }
            let next = c.next() as i64;
            if next < m.unlockheight {
                return Err(fail(
                    "bond-locked",
                    format!(
                        "the bond is returned at height {} (next block {next})",
                        m.unlockheight
                    ),
                ));
            }
            let lt = m.bondlocktime as u32;
            if lt as i64 >= next {
                return Err(fail(
                    "bond-locked",
                    format!("the bond is locked until height {lt} (next block {next})"),
                ));
            }
            let op = outpoint_of(&m.bondoutpoint)?;
            let (btx, _) = c.raw_tx(&op.txid).await?;
            let out = btx
                .vout
                .get(op.n as usize)
                .cloned()
                .ok_or_else(|| fail("unknown-tx", "the bond output does not exist"))?;
            let bond = Coin {
                outpoint: op,
                value: out.value,
                script: out.script_pubkey,
            };
            let dest = match o.get("to") {
                None => ba::seat_script(&c.seat),
                Some(a) => match keys::parse_address(c.network, a)
                    .map_err(|e| fail("usage", format!("--to: {e}")))?
                    .kind
                {
                    keys::AddressKind::P2pkh(h) => yew_core::script::p2pkh_script(&h),
                    keys::AddressKind::P2sh(h) => yew_core::script::p2sh_script(&h),
                },
            };
            let tx = ba::build_withdraw(&c.seat, &bond, lt, &dest, c.branch, c.expiry())?;
            c.finish(&tx, json!({"bondZat": bond.value, "out": tx.vout[0].value}))
                .await
        }
        "op-return" => {
            let data =
                keys::unhex(o.need("data")?).map_err(|e| fail("usage", format!("--data: {e}")))?;
            let fee = o.int("fee-zat")?;
            let coins = c.coins().await?;
            let tx = ba::build_op_return(&c.seat, &coins, &data, fee, c.branch, c.expiry())?;
            c.finish(&tx, json!({})).await
        }
        "cancel" => cancel(&mut c, &o).await,
        other => Err(fail("usage", format!("unknown command {other}; {USAGE}"))),
    }
}

/// `cancel`: the `yed_buildcancel` + `set_signcancel` port (B-T5).
async fn cancel(c: &mut Ctx, o: &Opts) -> Result<Value, Fail> {
    let op = outpoint_of(o.need("intent")?)?;
    let file = o.need("cosigs")?;
    let text = if file == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .map_err(|e| fail("usage", format!("stdin: {e}")))?;
        s
    } else {
        std::fs::read_to_string(file).map_err(|e| fail("usage", format!("{file}: {e}")))?
    };
    let given: Vec<String> = serde_json::from_str(&text).map_err(|e| {
        fail(
            "usage",
            format!("--cosigs: a JSON array of hex strings: {e}"),
        )
    })?;
    // the claim and its intent
    let (claim, height) = c.raw_tx(&op.txid).await?;
    if height == 0 {
        return Err(fail(
            "claim-unconfirmed",
            "co-sign and cancel a claim once it has confirmed",
        ));
    }
    let out = claim
        .vout
        .get(op.n as usize)
        .cloned()
        .ok_or_else(|| fail("not-claim", "no such output"))?;
    let ip = vault::parse_intent(&out.script_pubkey)
        .filter(|i| i.tag == vault::YED_TAG)
        .ok_or_else(|| fail("not-claim", "not a YED claim intent"))?;
    if c.next() as i64 - height as i64 >= ip.delay {
        return Err(fail(
            "intent-matured",
            format!("the intent matured at height {}", height as i64 + ip.delay),
        ));
    }
    let ref_height = ba::claim_ref_height(&claim)
        .ok_or_else(|| fail("not-claim", "the claim carries no REDEEM payload"))?;
    let vault_op = claim
        .vin
        .first()
        .map(|i| i.prevout)
        .ok_or_else(|| fail("not-claim", "the claim has no input"))?;
    let (vtx, _) = c.raw_tx(&vault_op.txid).await?;
    let origin = vtx
        .vout
        .get(vault_op.n as usize)
        .map(|o| o.script_pubkey.clone())
        .ok_or_else(|| fail("not-claim", "the claimed vault output does not exist"))?;
    if keys::sha256(&origin) != ip.vault_hash {
        return Err(fail(
            "not-claim",
            "the claim's vin 0 is not the intent's vault",
        ));
    }
    let v = c.eps[0]
        .yb
        .vault(&txid_hex(&vault_op.txid))
        .await
        .map_err(net_err)?;
    if v.status != "CLAIMING" {
        return Err(fail("not-claiming", format!("the vault is {}", v.status)));
    }
    let row = v
        .intents
        .iter()
        .find(|r| r.txid == txid_hex(&op.txid) && r.vout == op.n);
    if row.map(|r| r.role.as_str()) != Some("claimant") {
        return Err(fail(
            "not-claimant",
            "only the claimant's intent is cancelled (intent-cancel-residual)",
        ));
    }
    let holder = keys::unhex(&v.refund_holder).unwrap_or_default();
    if holder.is_empty() || v.burned_cents <= 0 {
        return Err(fail(
            "no-refund-holder",
            "the claim recorded no refund holder",
        ));
    }
    let required = v.cancels_required.max(1);
    // the co-signatures, checked as yed_buildcancel checks them
    let info = c.eps[0].yb.info().await.map_err(net_err)?;
    let p = info.params.unwrap_or_default();
    let att_set = txid_from_hex(&p.attestor_set_id)
        .map_err(|_| fail("lightwalletd", "the server names no attestor set"))?;
    let bh = c.eps[0]
        .compact
        .block_hash(ref_height as u64)
        .await
        .map_err(net_err)?;
    let members: Vec<[u8; 33]> = c
        .set(&p.attestor_set_id)
        .await?
        .memberlist
        .iter()
        .filter(|m| m.current)
        .filter_map(|m| keys::unhex(&m.key).ok()?.try_into().ok())
        .collect();
    let mut entries = Vec::new();
    let mut seen: Vec<[u8; 33]> = Vec::new();
    let mut warnings = Vec::new();
    for (i, h) in given.iter().enumerate() {
        let Some(e) = keys::unhex(h)
            .ok()
            .and_then(|b| CosignEntry::from_bytes(&b))
        else {
            warnings.push(format!(
                "cosigs[{i}] dropped: cancel-cosign-malformed: not a 69-byte co-signature"
            ));
            continue;
        };
        match ba::check_cosig(
            &e,
            &att_set,
            &op,
            ref_height,
            &bh,
            &members,
            &seen,
            (v.collateral_zat, v.minted_cents, p.claim_threshold_bps),
        ) {
            Ok(k) if entries.len() < yew_core::cosign::CANCEL_COSIGN_MAX => {
                seen.push(k);
                entries.push(e);
            }
            Ok(_) => warnings.push(format!("cosigs[{i}] dropped: beyond the carrier's entries")),
            Err(w) => warnings.push(format!("cosigs[{i}] dropped: {w}")),
        }
    }
    if (entries.len() as i64) < required {
        return Err(fail(
            "cancel-cosign-needed",
            format!(
                "this cancel needs {required} co-signature(s) of distinct current members, {} valid given; {}",
                entries.len(),
                warnings.join("; ")
            ),
        ));
    }
    // the cancel set: one signature completes it (the YED attestor set's cancelThreshold)
    let cset = c.set(&txid_hex(&ip.cancel_set_id)).await?;
    if cset.cancelthreshold != 1 {
        return Err(fail(
            "cancel-threshold",
            format!(
                "the cancel set needs {} set signatures; a light seat gives one",
                cset.cancelthreshold
            ),
        ));
    }
    if !cset
        .memberlist
        .iter()
        .any(|m| m.current && m.key == keys::hex(&c.seat.pubkey))
    {
        return Err(fail(
            "not-member",
            "the seat key is not a current member of the cancel set",
        ));
    }
    let coins = c.coins().await?;
    let inp = ba::CancelInputs {
        intent: Coin {
            outpoint: op,
            value: out.value,
            script: out.script_pubkey.clone(),
        },
        origin,
        refund_holder: holder.clone(),
        cosigs: entries,
        carrier_expiry: c.tip + REF_WINDOW,
    };
    let b = ba::build_cancel(&c.seat, &coins, &inp, c.branch)?;
    let carrier_txid = txid_hex(&b.carrier.txid()?);
    let txid = txid_hex(&b.cancel.txid()?);
    let mut r = json!({
        "carrierTxid": carrier_txid,
        "txid": txid,
        "carrierHex": keys::hex(&b.carrier.serialize()?),
        "hex": keys::hex(&b.cancel.serialize()?),
        "cancelsRequired": required,
        "refund": {"vout": 1, "script": keys::hex(&holder), "cents": v.burned_cents},
        "deadline": height as i64 + ip.delay - 1,
    });
    if !warnings.is_empty() {
        r["warnings"] = json!(warnings);
    }
    c.validate(&b.carrier).await?;
    if c.dry_run {
        // the cancel spends the carrier, which is not in the mempool on a dry run: its check is
        // reported, not required
        r["cancelValidation"] = match c.validate(&b.cancel).await {
            Ok(j) => j,
            Err(e) => json!(e.message),
        };
        return Ok(r);
    }
    r["carrierSent"] = c.send(&b.carrier).await?;
    c.validate(&b.cancel).await?;
    r["sent"] = c.send(&b.cancel).await?;
    Ok(r)
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let r = match parse_args(&argv) {
        Ok(o) => run(o).await,
        Err(e) => Err(e),
    };
    match r {
        Ok(v) => {
            println!("{v}");
        }
        Err(e) => {
            println!("{}", json!({"error": e.message, "code": e.code}));
            exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn options_parse_as_the_contract_names_them() {
        let o = parse_args(&args(
            "--network regtest --key-file k --lightwalletd 127.0.0.1:1 --lightwalletd https://b:2 --insecure join --set ab --bond 5 --locktime 9 --dry-run",
        ))
        .unwrap();
        assert_eq!(o.network, Network::Regtest);
        assert_eq!(o.endpoints.len(), 2);
        assert!(o.insecure && o.dry_run);
        assert_eq!(o.command, "join");
        assert_eq!(o.get("set"), Some("ab"));
        assert_eq!(o.int("bond").unwrap(), 5);
        assert_eq!(o.int("locktime").unwrap(), 9);
        assert_eq!(
            parse_args(&args("--key-file k address")).unwrap_err().code,
            "usage"
        );
    }

    #[test]
    fn insecure_is_loopback_only() {
        assert!(server_of("127.0.0.1:9067", true).unwrap().plain);
        assert!(server_of("http://localhost:9067", true).is_ok());
        assert!(server_of("http://[::1]:9067", true).is_ok());
        assert_eq!(
            server_of("10.0.0.1:9067", true).unwrap_err().code,
            "insecure-remote"
        );
        assert_eq!(server_of("http://a:1", false).unwrap_err().code, "usage");
        assert!(!server_of("https://lwd.example:9067", false).unwrap().plain);
    }

    #[test]
    fn the_key_file_must_be_private() {
        let dir = std::env::temp_dir().join(format!("yew-attestor-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("seat.key");
        // a regtest WIF (the network's prefix and a fixed key)
        let mut payload = vec![Network::Regtest.wif_prefix()];
        payload.extend_from_slice(&[9u8; 32]);
        payload.push(1);
        let wif = keys::base58check_encode(&payload);
        let k = keys::decode_wif(Network::Regtest, &wif).unwrap();
        std::fs::write(&p, format!("# seat\n\n{wif}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                read_key(p.to_str().unwrap(), Network::Regtest)
                    .unwrap_err()
                    .code,
                "key-file"
            );
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let got = read_key(p.to_str().unwrap(), Network::Regtest).unwrap();
        assert_eq!(got.pubkey, k.pubkey);
        assert!(read_key(p.to_str().unwrap(), Network::Mainnet).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn outpoints_parse() {
        let t = "11".repeat(32);
        let o = outpoint_of(&format!("{t}:3")).unwrap();
        assert_eq!(o.n, 3);
        assert!(outpoint_of(&t).is_err());
    }
}
