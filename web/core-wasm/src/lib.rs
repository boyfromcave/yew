//! yew-web-core: the browser binding of the YEW core (plan `docs/plans/yew-web-plan.md`).
//!
//! Every exported function is a thin `wasm_bindgen` wrapper over the same internals
//! `core/src/api.rs` exposes to Dart; no wallet logic lives here. W0.5 binds the minimum for an
//! end-to-end sync: storage, open, sync, balance, address. The shell (W1) grows it.
//!
//! One wallet per worker: [`open`] keeps the session in a thread-local; a call that needs it
//! takes it out for its duration (so a second call while one runs answers "busy" instead of
//! aliasing it) and puts it back.
use std::cell::RefCell;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use wasm_bindgen::prelude::*;
use yew_core::net::{CompactClient, Server, YellowbackClient};
use yew_core::params::Network;
use yew_core::shielded::{self, Shielded, ShieldedProgress};
use yew_core::shielded_keys::SaplingAccount;

struct Session {
    network: Network,
    shielded: Shielded,
    client: CompactClient,
    /// The light library's label for the server (`grpc://host:port`).
    lwd: String,
    birthday: Option<u64>,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
    static PROGRESS: RefCell<ShieldedProgress> = const { RefCell::new(ShieldedProgress {
        scanned_height: 0, tip_height: 0, percent: 0, enhancing: false }) };
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn to_js(v: &impl Serialize) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| js_err(e.to_string()))
}

fn take_session() -> Result<Session, JsValue> {
    SESSION
        .with(|s| s.borrow_mut().take())
        .ok_or_else(|| js_err("no wallet is open (open first, or a call is in progress)"))
}

fn put_session(s: Session) {
    SESSION.with(|c| *c.borrow_mut() = Some(s));
}

/// `host:port` and whether it is plain HTTP, from `http://host:port` / `https://host:port`
/// (or a bare `host:port`, TLS unless the network is regtest).
fn parse_server(network: Network, url: &str) -> Result<Server, JsValue> {
    let (plain, rest) = if let Some(r) = url.strip_prefix("http://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (false, r)
    } else {
        (network == Network::Regtest, url)
    };
    Server::parse_for(network, rest.trim_end_matches('/'), plain).map_err(js_err)
}

fn parse_network(name: &str) -> Result<Network, JsValue> {
    Network::from_name(name).ok_or_else(|| js_err(format!("unknown network {name:?}")))
}

#[derive(Serialize)]
struct Status {
    version: &'static str,
    server: Option<String>,
}

/// The core's version and connection state (mirrors `api::status`).
#[wasm_bindgen]
pub async fn status() -> Result<JsValue, JsValue> {
    let server = SESSION.with(|s| s.borrow().as_ref().map(|s| s.lwd.clone()));
    let s = Status {
        version: concat!(env!("CARGO_PKG_VERSION"), "-wasm"),
        server,
    };
    to_js(&s)
}

/// SQLite on OPFS (the sahpool VFS): once per worker, before `open`. Idempotent.
#[wasm_bindgen]
pub async fn install_storage() -> Result<(), JsValue> {
    shielded::install_storage().await.map_err(js_err)
}

/// A new 24-word seed phrase (BIP-39, English).
#[wasm_bindgen]
pub fn new_seed_words() -> Result<String, JsValue> {
    yew_core::keys::generate_mnemonic(24).map_err(js_err)
}

/// `GetLatestBlock` of `server_url` (the compact-block cache's tip), without opening a wallet.
#[wasm_bindgen]
pub async fn latest_height(server_url: &str, network: &str) -> Result<u64, JsValue> {
    let network = parse_network(network)?;
    let server = parse_server(network, server_url)?;
    let mut client = CompactClient::connect(&server).await.map_err(js_err)?;
    client.latest_height().await.map_err(js_err)
}

#[derive(Serialize)]
struct Opened {
    network: &'static str,
    address: String,
    birthday: Option<u64>,
    vault_activation: Option<u64>,
    registered: bool,
}

/// Open the private (Sapling) wallet of `seed_words` on `network` under the OPFS store
/// `yew/<network>/`, connected to `server_url` (gRPC-web). `birthday` 0 = the current tip
/// (a seed this wallet generated). Refuses a store holding another seed's account. The vault
/// upgrade's activation height is taken from the server (`GetChainInfo`), as the app does.
#[wasm_bindgen]
pub async fn open(
    seed_words: &str,
    birthday: u64,
    server_url: &str,
    network: &str,
) -> Result<JsValue, JsValue> {
    let n = parse_network(network)?;
    let dir = format!("yew/{}", n.chain_name());
    open_at(seed_words, birthday, server_url, network, &dir).await
}

/// [`open`] with the OPFS store directory named (`yew/<network>` is the default; a second
/// wallet, or a restore beside an existing store, takes another).
#[wasm_bindgen]
pub async fn open_at(
    seed_words: &str,
    birthday: u64,
    server_url: &str,
    network: &str,
    store_dir: &str,
) -> Result<JsValue, JsValue> {
    let network = parse_network(network)?;
    let server = parse_server(network, server_url)?;
    let account = SaplingAccount::from_mnemonic(seed_words, "", network).map_err(js_err)?;
    let mut sh = Shielded::open(Path::new(store_dir), network, account).map_err(js_err)?;
    let client = CompactClient::connect(&server).await.map_err(js_err)?;
    let mut yb = YellowbackClient::from_channel(client.channel());
    let vault = match yb.chain_info_vault().await.map_err(js_err)? {
        Some((_, _, vault)) => vault,
        None => None,
    };
    sh.set_vault_activation(vault).map_err(js_err)?;
    let registered = sh.registered().map_err(js_err)?;
    let opened = Opened {
        network: network.chain_name(),
        address: sh.default_address().1,
        birthday: (birthday > 0).then_some(birthday),
        vault_activation: sh.vault_activation(),
        registered,
    };
    put_session(Session {
        network,
        shielded: sh,
        client,
        lwd: shielded::light_endpoint(&server.host, server.port, server.plain),
        birthday: (birthday > 0).then_some(birthday),
    });
    to_js(&opened)
}

#[derive(Serialize)]
struct SyncResult {
    tip: u64,
    scanned_height: u64,
    blocks: u64,
    outputs: u64,
    received_notes: u64,
    spent_notes: u64,
    reorgs: u64,
    enhanced: u64,
    registered_now: bool,
    sendable: bool,
    millis: u64,
}

/// One private sync to the server's tip (registers the account at the birthday on the first
/// run). `progress()` reports the ticks meanwhile.
#[wasm_bindgen]
pub async fn sync() -> Result<JsValue, JsValue> {
    let mut s = take_session()?;
    let progress: shielded::ProgressFn = Arc::new(|p: ShieldedProgress| {
        PROGRESS.with(|c| *c.borrow_mut() = p);
    });
    let r = s
        .shielded
        .sync(&s.lwd, s.birthday, &mut s.client, progress)
        .await;
    put_session(s);
    let r = r.map_err(js_err)?;
    to_js(&SyncResult {
        tip: r.tip,
        scanned_height: r.scanned_height,
        blocks: r.blocks,
        outputs: r.outputs,
        received_notes: r.received_notes,
        spent_notes: r.spent_notes,
        reorgs: r.reorgs,
        enhanced: r.enhanced,
        registered_now: r.registered_now,
        sendable: r.sendable,
        millis: r.millis,
    })
}

#[derive(Serialize)]
struct Progress {
    scanned_height: u64,
    tip_height: u64,
    percent: u8,
    enhancing: bool,
}

/// The last progress tick of `sync` (polled by the shell while a sync runs).
#[wasm_bindgen]
pub fn progress() -> Result<JsValue, JsValue> {
    let p = PROGRESS.with(|c| *c.borrow());
    to_js(&Progress {
        scanned_height: p.scanned_height,
        tip_height: p.tip_height,
        percent: p.percent,
        enhancing: p.enhancing,
    })
}

#[derive(Serialize)]
struct Balance {
    total_zat: u64,
    spendable_zat: u64,
    pending_change_zat: u64,
    pending_incoming_zat: u64,
    scanned_height: u64,
    tip_height: u64,
    sendable: bool,
    registered: bool,
}

/// The private balance from the store (no network).
#[wasm_bindgen]
pub fn shielded_balance() -> Result<JsValue, JsValue> {
    SESSION.with(|c| {
        let cell = c.borrow();
        let s = cell.as_ref().ok_or_else(|| js_err("no wallet is open"))?;
        let b = s.shielded.balance().map_err(js_err)?;
        to_js(&Balance {
            total_zat: b.total_zat,
            spendable_zat: b.spendable_zat,
            pending_change_zat: b.pending_change_zat,
            pending_incoming_zat: b.pending_incoming_zat,
            scanned_height: b.scanned_height,
            tip_height: b.tip_height,
            sendable: b.sendable,
            registered: b.registered,
        })
    })
}

/// The wallet's default private address (`ys1…` on mainnet).
#[wasm_bindgen]
pub fn receive_address() -> Result<String, JsValue> {
    SESSION.with(|c| {
        let cell = c.borrow();
        let s = cell.as_ref().ok_or_else(|| js_err("no wallet is open"))?;
        Ok(s.shielded.default_address().1)
    })
}

/// The network of the open wallet.
#[wasm_bindgen]
pub fn network() -> Result<String, JsValue> {
    SESSION.with(|c| {
        let cell = c.borrow();
        let s = cell.as_ref().ok_or_else(|| js_err("no wallet is open"))?;
        Ok(s.network.chain_name().to_string())
    })
}

/// Close the wallet (drops the store handles and the connection).
#[wasm_bindgen]
pub fn close() {
    SESSION.with(|c| *c.borrow_mut() = None);
}
