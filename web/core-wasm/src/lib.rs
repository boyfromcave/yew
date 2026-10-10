//! yew-web-core: the browser binding of the YEW core (plan `docs/plans/yew-web-plan.md`).
//!
//! Every exported function is a thin `wasm_bindgen` wrapper over the same internals
//! `core/src/api.rs` exposes to Dart (that file is the map: one function here per function
//! there); no wallet logic lives here, the DTO mappings are in [`dto`]. W0.5 bound the private
//! sync; W1a binds the whole surface the shell codes against (the briefing's
//! API-yew-web-core.md): the transparent side (addresses, YED, history), the previews, the one
//! `confirm` that signs and broadcasts (through `gate.rs`, as `api.rs` does), the proving
//! parameters, the vault screens.
//!
//! One wallet per worker: [`open`] keeps the session in a thread-local; a call that needs it
//! takes it out for its duration (a second call meanwhile answers `busy: …`) and puts it back.
//! Every error is a JS `Error` whose message is `<kind>: <detail>` with the kinds of the
//! contract (`busy`, `unsupported`, `network`, `store`, `gate`, `build`, `params`, `invalid`).
//! Amounts cross as decimal strings (zatoshi, cents); heights and counts as numbers.
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use yew_core::build::mint::{ConfirmedTerms, MintError};
use yew_core::build::redeem::RedeemBuild;
use yew_core::build::release::ReleaseBuild;
use yew_core::build::terms::ClaimBounds;
use yew_core::build::yec_move;
use yew_core::build::yec_private::{self, YecSendPlan};
use yew_core::build::yed_transfer::{self, YedTransferPreview};
use yew_core::coins::UtxoClass;
use yew_core::gate::{GateError, Validator};
use yew_core::keys;
use yew_core::net::{Availability, CompactClient, NetError, Server, YellowbackClient};
use yew_core::params::{self, Network};
use yew_core::sapling_params::{self, ParamsError};
use yew_core::shielded::{self, ShieldedError, ShieldedProgress, ShieldedSyncReport};
use yew_core::sync::SyncReport;
use yew_core::tx::txid_hex;
use yew_core::wallet::{Wallet, WalletError};

mod dto;

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// A JS `Error` of `"<kind>: <detail>"`.
fn err(kind: &str, detail: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&format!("{kind}: {detail}")).into()
}

fn net_err(e: NetError) -> JsValue {
    err("network", e)
}

fn shielded_kind(e: &ShieldedError) -> &'static str {
    match e {
        ShieldedError::Params(_) => "params",
        ShieldedError::Address(_) | ShieldedError::Memo(_) => "invalid",
        ShieldedError::Net(_) | ShieldedError::Light(_) => "network",
        ShieldedError::Store(_) | ShieldedError::OtherSeed => "store",
        _ => "build",
    }
}

fn shielded_err(e: ShieldedError) -> JsValue {
    err(shielded_kind(&e), e)
}

/// The contract's kind of a core error (`api.rs`'s `From<WalletError> for YewError`).
fn wallet_err(e: WalletError) -> JsValue {
    let kind = match &e {
        WalletError::Gate(_) => "gate",
        WalletError::Net(_) => "network",
        WalletError::Store(_) => "store",
        WalletError::Key(_) => "invalid",
        WalletError::Mint(MintError::BadAmount { .. } | MintError::BadLock { .. }) => "invalid",
        WalletError::Shielded(s) => shielded_kind(s),
        WalletError::Coins(_)
        | WalletError::Tx(_)
        | WalletError::Transfer(_)
        | WalletError::Mint(_)
        | WalletError::Other(_) => "build",
    };
    err(kind, e)
}

fn store_err(e: yew_core::store::StoreError) -> JsValue {
    err("store", e)
}

fn to_js(v: &impl Serialize) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| err("invalid", e))
}

/// An amount argument: a decimal string (the contract), a JS integer or a BigInt.
fn amount_arg(v: &JsValue, what: &str) -> Result<i64, JsValue> {
    let bad = || err("invalid", format!("{what}: an integer amount, as a string"));
    if let Some(s) = v.as_string() {
        return s.trim().parse::<i64>().map_err(|_| bad());
    }
    if let Some(n) = v.as_f64() {
        if n.fract() == 0.0 && n.abs() < 9_007_199_254_740_992.0 {
            return Ok(n as i64);
        }
        return Err(bad());
    }
    if let Some(b) = v.dyn_ref::<js_sys::BigInt>() {
        let s = b.to_string(10).map_err(|_| bad())?;
        return String::from(s).parse::<i64>().map_err(|_| bad());
    }
    Err(bad())
}

fn parse_txid(s: &str) -> Result<[u8; 32], JsValue> {
    yew_core::tx::txid_from_hex(s.trim()).map_err(|m| err("invalid", m))
}

fn parse_outpoint(s: &str) -> Result<yew_core::tx::OutPoint, JsValue> {
    let (t, n) = s
        .trim()
        .split_once(':')
        .ok_or_else(|| err("invalid", "an outpoint is txid:n"))?;
    let n: u32 = n
        .parse()
        .map_err(|_| err("invalid", "an outpoint is txid:n"))?;
    Ok(yew_core::tx::OutPoint {
        txid: parse_txid(t)?,
        n,
    })
}

// ---------------------------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------------------------

/// The live connection (`api::Conn`), built lazily from the server.
struct Conn {
    compact: CompactClient,
    validator: Validator,
    availability: Availability,
    branch_id: u32,
    tip: u64,
}

/// A preview waiting for [`confirm`] — the only path that signs and broadcasts.
enum Preview {
    Yec(Box<YecSendPlan>),
    Yed(YedTransferPreview),
    Redeem(RedeemBuild),
    Release(ReleaseBuild),
    /// `mint_start`: the carrier is funded and broadcast at confirm (the core's `mint_start`).
    MintStart {
        cents: u64,
        lock_blocks: u32,
        terms: Option<ConfirmedTerms>,
    },
    MintFinish(i64),
    MintSweep(i64),
    Claim {
        vault_txid: [u8; 32],
        bounds: ClaimBounds,
    },
}

struct Session {
    network: Network,
    wallet: Wallet,
    server: Server,
    conn: Option<Conn>,
    previews: HashMap<String, Preview>,
    preview_seq: u64,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
    /// A call holds the session (taken out of `SESSION`).
    static BUSY: Cell<bool> = const { Cell::new(false) };
    static PROGRESS: RefCell<ShieldedProgress> = const { RefCell::new(ShieldedProgress {
        scanned_height: 0, tip_height: 0, percent: 0, enhancing: false }) };
    static PROGRESS_CB: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
}

fn take_session() -> Result<Session, JsValue> {
    if BUSY.with(|b| b.get()) {
        return Err(err("busy", "a call is in progress"));
    }
    let s = SESSION
        .with(|s| s.borrow_mut().take())
        .ok_or_else(|| err("invalid", "no wallet is open (open first)"))?;
    BUSY.with(|b| b.set(true));
    Ok(s)
}

fn put_session(s: Session) {
    SESSION.with(|c| *c.borrow_mut() = Some(s));
    BUSY.with(|b| b.set(false));
}

type SessFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, JsValue>> + 'a>>;

/// Run an async `f` with the session taken out (the session is put back whatever `f` returns).
async fn with_session<T>(
    f: impl for<'a> FnOnce(&'a mut Session) -> SessFut<'a, T>,
) -> Result<T, JsValue> {
    let mut s = take_session()?;
    let r = f(&mut s).await;
    put_session(s);
    r
}

/// Run a synchronous `f` with the session borrowed in place.
fn with_session_sync<T>(f: impl FnOnce(&mut Session) -> Result<T, JsValue>) -> Result<T, JsValue> {
    if BUSY.with(|b| b.get()) {
        return Err(err("busy", "a call is in progress"));
    }
    SESSION.with(|c| {
        let mut cell = c.borrow_mut();
        let s = cell
            .as_mut()
            .ok_or_else(|| err("invalid", "no wallet is open (open first)"))?;
        f(s)
    })
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
    Server::parse_for(network, rest.trim_end_matches('/'), plain).map_err(|m| err("invalid", m))
}

fn parse_network(name: &str) -> Result<Network, JsValue> {
    Network::from_name(name).ok_or_else(|| err("invalid", format!("unknown network {name:?}")))
}

/// `api::connect`: the channel, `GetLightdInfo`, the tip, the Yellowback probe.
async fn connect(server: &Server, network: Network) -> Result<Conn, JsValue> {
    let channel = server.connect().await.map_err(net_err)?;
    let mut compact = CompactClient::from_channel(channel.clone());
    let info = compact.lightd_info_for(network).await.map_err(net_err)?;
    let tip = compact
        .latest_height()
        .await
        .map_err(net_err)?
        .max(info.block_height);
    let (validator, availability) = Validator::detect(YellowbackClient::from_channel(channel))
        .await
        .map_err(net_err)?;
    Ok(Conn {
        compact,
        validator,
        availability,
        branch_id: info.branch_id,
        tip,
    })
}

fn now_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// The progress event of the contract: `{phase, pct, height, tip}` to the callback set by
/// [`set_progress_callback`] (and the last tick kept for [`progress`]).
fn emit(phase: &str, pct: u8, height: u64, tip: u64) {
    #[derive(Serialize)]
    struct Ev<'a> {
        phase: &'a str,
        pct: u8,
        height: u64,
        tip: u64,
    }
    PROGRESS_CB.with(|c| {
        if let Some(f) = c.borrow().as_ref() {
            if let Ok(v) = to_js(&Ev {
                phase,
                pct,
                height,
                tip,
            }) {
                let _ = f.call1(&JsValue::NULL, &v);
            }
        }
    });
}

impl Session {
    async fn ensure_conn(&mut self) -> Result<&mut Conn, JsValue> {
        if self.conn.is_none() {
            self.conn = Some(connect(&self.server, self.network).await?);
        }
        Ok(self.conn.as_mut().expect("set above"))
    }

    /// The transparent sync (`api::Open::sync`): connect if needed, the §3.2 loop; a network
    /// error drops the connection so the next call reconnects.
    async fn sync(&mut self) -> Result<SyncReport, JsValue> {
        self.ensure_conn().await?;
        let conn = self.conn.as_mut().expect("connected");
        let r = yew_core::sync::sync(
            &mut self.wallet,
            &mut conn.compact,
            conn.validator.client_mut(),
        )
        .await;
        match r {
            Ok(r) => {
                conn.tip = r.tip;
                conn.branch_id = r.branch_id;
                Ok(r)
            }
            Err(e) => {
                if matches!(e, WalletError::Net(_)) {
                    self.conn = None;
                }
                Err(wallet_err(e))
            }
        }
    }

    /// The private sync after [`Session::sync`] (`api::Open::sync_shielded`).
    async fn sync_shielded(
        &mut self,
        progress: shielded::ProgressFn,
    ) -> Result<ShieldedSyncReport, JsValue> {
        self.ensure_conn().await?;
        let Session {
            wallet,
            server,
            conn,
            ..
        } = self;
        let conn = conn.as_mut().expect("connected");
        yec_private::sync_shielded(wallet, server, &mut conn.compact, progress)
            .await
            .map_err(wallet_err)
    }

    fn synced_tip(&self) -> Result<u64, JsValue> {
        self.wallet
            .store
            .meta_u64("last_synced_height")
            .map_err(store_err)
    }

    fn next_preview_id(&mut self) -> String {
        self.preview_seq += 1;
        format!("z{}", self.preview_seq)
    }

    fn row_status(&self, id: i64) -> Result<dto::MintStatus, JsValue> {
        let m = self
            .wallet
            .store
            .mint(id)
            .map_err(store_err)?
            .ok_or_else(|| err("invalid", format!("no mint with id {id}")))?;
        Ok(dto::mint_status(&m, self.synced_tip()?))
    }

    fn has_prover(&self) -> bool {
        self.wallet
            .shielded
            .as_ref()
            .is_some_and(|s| s.has_prover())
    }

    /// The prover from the Cache API's verified copy when none is loaded (a page reload after
    /// `fetch_params`); `params: …` when the cache is empty.
    async fn ensure_prover(&mut self) -> Result<(), JsValue> {
        if self.has_prover() {
            return Ok(());
        }
        let cached = sapling_params::cached()
            .await
            .map_err(|e| err("params", e))?;
        match cached {
            Some((spend, output)) => self
                .wallet
                .shielded_mut()
                .map_err(wallet_err)?
                .set_prover_bytes(&spend, &output)
                .map_err(shielded_err),
            None => Err(err(
                "params",
                "Private sending needs a one-time download of 52 MB (the Sapling proving parameters): call fetch_params first.",
            )),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Without a wallet
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    version: &'static str,
    server: Option<String>,
    network: Option<&'static str>,
    /// The tip the connection last saw.
    tip: Option<u64>,
    /// The server offers a usable Yellowback service (contract rule 1): YED may be shown.
    yellowback_usable: Option<bool>,
    /// The vault upgrade's branch id in the next block, hex.
    branch_id: Option<String>,
}

/// The core's version and connection state (mirrors `api::status`; no network).
#[wasm_bindgen]
pub async fn status() -> Result<JsValue, JsValue> {
    let st = SESSION.with(|s| {
        let cell = s.borrow();
        let s = cell.as_ref()?;
        Some((
            format!("{}:{}", s.server.host, s.server.port),
            s.network.chain_name(),
            s.conn.as_ref().map(|c| c.tip),
            s.conn.as_ref().map(|c| c.availability.usable()),
            s.conn.as_ref().map(|c| format!("{:08x}", c.branch_id)),
        ))
    });
    to_js(&Status {
        version: concat!(env!("CARGO_PKG_VERSION"), "-wasm"),
        server: st.as_ref().map(|s| s.0.clone()),
        network: st.as_ref().map(|s| s.1),
        tip: st.as_ref().and_then(|s| s.2),
        yellowback_usable: st.as_ref().and_then(|s| s.3),
        branch_id: st.as_ref().and_then(|s| s.4.clone()),
    })
}

/// SQLite on OPFS (the sahpool VFS): once per worker, before `open`. Idempotent.
#[wasm_bindgen]
pub async fn install_storage() -> Result<(), JsValue> {
    shielded::install_storage().await.map_err(shielded_err)
}

/// A new 24-word seed phrase (BIP-39, English).
#[wasm_bindgen]
pub fn new_seed_words() -> Result<String, JsValue> {
    keys::generate_mnemonic(24).map_err(|e| err("invalid", e))
}

/// `GetLatestBlock` of `server_url` (the compact-block cache's tip), without opening a wallet.
#[wasm_bindgen]
pub async fn latest_height(server_url: &str, network: &str) -> Result<u64, JsValue> {
    let network = parse_network(network)?;
    let server = parse_server(network, server_url)?;
    let mut client = CompactClient::connect(&server).await.map_err(net_err)?;
    client.latest_height().await.map_err(net_err)
}

/// Parse an address (`api::validate_address`): for the open wallet's network, or `network`
/// when none is open.
#[wasm_bindgen]
pub fn validate_address(address: &str, network: Option<String>) -> Result<JsValue, JsValue> {
    let open = SESSION.with(|s| s.borrow().as_ref().map(|s| s.network));
    let network = match (open, network) {
        (_, Some(n)) => parse_network(&n)?,
        (Some(n), None) => n,
        (None, None) => return Err(err("invalid", "no wallet is open: name the network")),
    };
    to_js(&dto::validate_address(network, address))
}

// ---------------------------------------------------------------------------------------------
// Open / close / sync
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct Opened {
    network: &'static str,
    /// The default private address (as W0.5).
    address: String,
    #[serde(rename = "addressYe")]
    address_ye: String,
    #[serde(rename = "addressS")]
    address_s: String,
    birthday: Option<u64>,
    vault_activation: Option<u64>,
    registered: bool,
}

/// Open the wallet of `seed_words` on `network` under the OPFS store `yew/<network>/`
/// (the transparent file and, beside it, the private store), connected to `server_url`
/// (gRPC-web). `birthday` 0 = the current tip (a seed this wallet generated). Refuses a store
/// holding another seed. The vault upgrade's activation height is taken from the server
/// (`GetChainInfo`), as the app does.
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
    if SESSION.with(|s| s.borrow().is_some()) || BUSY.with(|b| b.get()) {
        return Err(err("invalid", "a wallet is already open (close first)"));
    }
    let network = parse_network(network)?;
    let server = parse_server(network, server_url)?;
    let path = format!(
        "{}/yew-{}.sqlite",
        store_dir.trim_end_matches('/'),
        network.chain_name()
    );
    let words =
        keys::SecretString::new(seed_words.split_whitespace().collect::<Vec<_>>().join(" "));
    let mut wallet = Wallet::open(
        &path,
        network,
        &words,
        "",
        (birthday > 0).then_some(birthday),
    )
    .map_err(|e| match e {
        WalletError::Key(k) => err("invalid", k),
        WalletError::Shielded(ShieldedError::OtherSeed) => err(
            "store",
            "wallet file belongs to another seed (private store)",
        ),
        WalletError::Other(m) => err("store", m),
        other => wallet_err(other),
    })?;
    if birthday == 0 {
        // A seed generated here has no history: the private account starts at the tip
        // (`build::yec_private::sync_shielded`).
        wallet.store.set_meta("new_seed", "1").map_err(store_err)?;
    }
    let conn = connect(&server, network).await?;
    let mut yb = YellowbackClient::from_channel(conn.compact.channel());
    if let Some((_, _, vault)) = yb.chain_info_vault().await.map_err(net_err)? {
        wallet.set_vault_activation(vault).map_err(wallet_err)?;
    }
    let primary = wallet.receive_address(false).map_err(wallet_err)?;
    let sh = wallet.shielded().map_err(wallet_err)?;
    let opened = Opened {
        network: network.chain_name(),
        address: sh.default_address().1,
        address_ye: primary.address_ye,
        address_s: primary.address_s,
        birthday: (birthday > 0).then_some(birthday),
        vault_activation: sh.vault_activation(),
        registered: sh.registered().map_err(shielded_err)?,
    };
    put_session(Session {
        network,
        wallet,
        server,
        conn: Some(conn),
        previews: HashMap::new(),
        preview_seq: 0,
    });
    to_js(&opened)
}

/// Close the wallet (drops the store handles, the connection and every preview).
#[wasm_bindgen]
pub fn close() {
    SESSION.with(|c| *c.borrow_mut() = None);
    BUSY.with(|b| b.set(false));
}

/// The network of the open wallet.
#[wasm_bindgen]
pub fn network() -> Result<String, JsValue> {
    with_session_sync(|s| Ok(s.network.chain_name().to_string()))
}

/// `f({phase, pct, height, tip})` is called from [`sync`] (phases `connecting`, `scanning`,
/// `shielded`, `memos`, `done`); `null` clears it. Replaces polling [`progress`].
#[wasm_bindgen]
pub fn set_progress_callback(f: Option<js_sys::Function>) {
    PROGRESS_CB.with(|c| *c.borrow_mut() = f);
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
    branch_id: String,
    transactions: u64,
    utxos: u64,
    tokens: u64,
    yellowback: bool,
    /// Why the private sync failed, empty when it succeeded (the transparent sync still
    /// counts: YED and public YEC are synced either way, as `api::sync_now`).
    shielded_message: String,
}

/// One sync to the server's tip (`api::sync_now`): the transparent side (addresses, YED,
/// vaults), then the private scan (registering the account at the birthday on the first run).
/// Progress goes to the callback meanwhile; the W0.5 fields of the result are kept.
#[wasm_bindgen]
pub async fn sync() -> Result<JsValue, JsValue> {
    with_session(|s| {
        Box::pin(async move {
            emit("connecting", 0, 0, 0);
            let tip = s.ensure_conn().await?.tip;
            emit("scanning", 5, 0, tip);
            let r = s.sync().await?;
            emit("shielded", 10, 0, r.tip);
            let progress: shielded::ProgressFn = Arc::new(|p: ShieldedProgress| {
                PROGRESS.with(|c| *c.borrow_mut() = p);
                // 10..94 while scanning, 97 while reading memos, 99 at the final tick, 100 done.
                if p.enhancing {
                    emit("memos", 97, p.scanned_height, p.tip_height);
                } else if p.percent >= 100 {
                    emit("shielded", 99, p.scanned_height, p.tip_height);
                } else {
                    emit(
                        "shielded",
                        (10 + (p.percent as u32 * 85) / 100) as u8,
                        p.scanned_height,
                        p.tip_height,
                    );
                }
            });
            let z = s.sync_shielded(progress).await;
            let (z, message) = match z {
                Ok(z) => (z, String::new()),
                Err(e) => (
                    ShieldedSyncReport::default(),
                    e.dyn_ref::<js_sys::Error>()
                        .map(|e| String::from(e.message()))
                        .unwrap_or_else(|| format!("{e:?}")),
                ),
            };
            emit("done", 100, r.tip, r.tip);
            to_js(&SyncResult {
                tip: r.tip,
                scanned_height: z.scanned_height,
                blocks: z.blocks,
                outputs: z.outputs,
                received_notes: z.received_notes,
                spent_notes: z.spent_notes,
                reorgs: z.reorgs,
                enhanced: z.enhanced,
                registered_now: z.registered_now,
                sendable: z.sendable,
                millis: z.millis,
                branch_id: format!("{:08x}", r.branch_id),
                transactions: r.transactions as u64,
                utxos: r.utxos as u64,
                tokens: r.tokens as u64,
                yellowback: r.yellowback,
                shielded_message: message,
            })
        })
    })
    .await
}

#[derive(Serialize)]
struct Progress {
    scanned_height: u64,
    tip_height: u64,
    percent: u8,
    enhancing: bool,
}

/// The last private-scan tick of [`sync`] (W0.5 polling; the callback supersedes it).
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

// ---------------------------------------------------------------------------------------------
// Balances, addresses, history
// ---------------------------------------------------------------------------------------------

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

/// The private balance from the store (no network; W0.5).
#[wasm_bindgen]
pub fn shielded_balance() -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let b = s
            .wallet
            .shielded()
            .map_err(wallet_err)?
            .balance()
            .map_err(shielded_err)?;
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

/// Every balance from the store (no network; `api::balances`): public YEC, the fee reserve,
/// YED, the price at the last sync, the private balance.
#[wasm_bindgen]
pub fn balances() -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let b = s.wallet.balances().map_err(wallet_err)?;
        let held = s
            .wallet
            .store
            .utxos()
            .map_err(store_err)?
            .iter()
            .filter(|u| u.class == UtxoClass::Held)
            .count() as u64;
        let z = match s.wallet.shielded.as_ref() {
            Some(sh) => sh.balance().map_err(shielded_err)?,
            None => Default::default(),
        };
        to_js(&dto::balances(&b, &z, held, s.synced_tip()?))
    })
}

/// The address at the first valid diversifier index at or after `index` (`api::shielded_pair`).
fn shielded_pair(s: &Session, index: u64) -> Result<dto::AddressPair, JsValue> {
    let sh = s.wallet.shielded().map_err(wallet_err)?;
    let (j, address) = if index == 0 {
        sh.default_address()
    } else {
        sh.address_at(index).map_err(shielded_err)?
    };
    Ok(dto::AddressPair {
        ye: String::new(),
        s: String::new(),
        path: format!("m/32'/347'/0' diversifier {j}"),
        covered_by_seed: true,
        address,
        kind: "shielded".into(),
    })
}

fn receive_pair(s: &Session, kind: &str) -> Result<dto::AddressPair, JsValue> {
    match kind {
        "shielded" => {
            let index = s
                .wallet
                .store
                .meta_u64("sapling_diversifier")
                .map_err(store_err)?;
            shielded_pair(s, index)
        }
        "transparent" | "yed" => {
            let row = s.wallet.receive_address(false).map_err(wallet_err)?;
            Ok(dto::AddressPair {
                address: if kind == "yed" {
                    row.address_ye.clone()
                } else {
                    row.address_s.clone()
                },
                kind: kind.into(),
                ye: row.address_ye,
                s: row.address_s,
                path: format!("m/44'/347'/0'/{}/{}", row.chain, row.index),
                covered_by_seed: true,
            })
        }
        other => Err(err(
            "invalid",
            format!("receive kind {other:?}: shielded, transparent or yed"),
        )),
    }
}

/// The receive address of `kind` (`shielded` — the default, as W0.5 —, `transparent` or
/// `yed`): the first unused external address for the transparent kinds, the private address
/// last handed out by [`new_shielded_address`] (or the default one) for `shielded`.
#[wasm_bindgen]
pub fn receive_address(kind: Option<String>) -> Result<String, JsValue> {
    with_session_sync(|s| Ok(receive_pair(s, kind.as_deref().unwrap_or("shielded"))?.address))
}

/// [`receive_address`] with both forms, the path and the seed coverage (`api::AddressPair`).
#[wasm_bindgen]
pub fn receive_address_info(kind: Option<String>) -> Result<JsValue, JsValue> {
    with_session_sync(|s| to_js(&receive_pair(s, kind.as_deref().unwrap_or("shielded"))?))
}

/// A new diversified private address of the same account (`api::new_shielded_address`):
/// remembered, so `receive_address("shielded")` shows it until the next one.
#[wasm_bindgen]
pub fn new_shielded_address() -> Result<String, JsValue> {
    with_session_sync(|s| {
        let last = s
            .wallet
            .store
            .meta_u64("sapling_diversifier")
            .map_err(store_err)?;
        let start = if last == 0 {
            s.wallet.shielded().map_err(wallet_err)?.default_address().0 + 1
        } else {
            last + 1
        };
        let pair = shielded_pair(s, start)?;
        let j: u64 = pair
            .path
            .rsplit(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(start);
        s.wallet
            .store
            .set_meta("sapling_diversifier", &j.to_string())
            .map_err(store_err)?;
        Ok(pair.address)
    })
}

/// Every transparent address of the wallet (`api::addresses`; Settings → export a key).
#[wasm_bindgen]
pub fn addresses() -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let rows: Vec<dto::AddressPair> = s
            .wallet
            .addresses()
            .map_err(wallet_err)?
            .into_iter()
            .map(|r| {
                let hd = r.hd_chain().is_some();
                dto::AddressPair {
                    address: r.address_s.clone(),
                    kind: "transparent".into(),
                    ye: r.address_ye,
                    s: r.address_s,
                    path: if hd {
                        format!("m/44'/347'/0'/{}/{}", r.chain, r.index)
                    } else {
                        "imported".into()
                    },
                    covered_by_seed: hd,
                }
            })
            .collect();
        to_js(&rows)
    })
}

/// One page of 50 history rows, pending first then newest first (`api::history`; the private
/// rows merged in). In the browser the private query closes and reopens the store handles.
#[wasm_bindgen]
pub fn history(page: u32) -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let all = s.wallet.store.history().map_err(store_err)?;
        let z = match s.wallet.shielded.as_mut() {
            Some(sh) => sh.history().map_err(shielded_err)?,
            None => Vec::new(),
        };
        to_js(&dto::history_page(&all, &z, page))
    })
}

// ---------------------------------------------------------------------------------------------
// The proving parameters
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct ParamsStatus {
    present: bool,
    bytes: u64,
    needed: u64,
    /// A prover is loaded in this session (a confirm needs no cache read).
    loaded: bool,
}

/// Where the proving parameters stand (`api::params_status`): the Cache API's verified copy,
/// or the prover loaded in this session.
#[wasm_bindgen]
pub async fn params_status() -> Result<JsValue, JsValue> {
    let loaded = with_session_sync(|s| Ok(s.has_prover()))?;
    let present = loaded
        || sapling_params::cached()
            .await
            .map_err(|e| err("params", e))?
            .is_some();
    let bytes = if present {
        sapling_params::TOTAL_BYTES
    } else {
        0
    };
    to_js(&ParamsStatus {
        present,
        bytes,
        needed: sapling_params::TOTAL_BYTES - bytes,
        loaded,
    })
}

/// Fetch the Sapling proving parameters (52 MB) into the Cache API — from `sources` (base
/// URLs ending in `/`; the default `download.z.cash` when empty) — verify them against the
/// pinned SHA-256s and load the prover (`api::download_params`; `sapling_params::fetch_with`).
/// `f({bytesDone, bytesTotal, name})` before and after each file. A rejected fetch caches
/// nothing. Must run before a private send or shield is confirmed.
#[wasm_bindgen]
pub async fn fetch_params(f: Option<js_sys::Function>, sources: JsValue) -> Result<(), JsValue> {
    let sources: Vec<String> = if sources.is_undefined() || sources.is_null() {
        Vec::new()
    } else {
        serde_wasm_bindgen::from_value(sources)
            .map_err(|e| err("invalid", format!("sources: an array of base URLs: {e}")))?
    };
    with_session(|s| {
        Box::pin(async move {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Ev<'a> {
                bytes_done: u64,
                bytes_total: u64,
                name: &'a str,
            }
            let refs: Vec<&str> = sources.iter().map(String::as_str).collect();
            let (spend, output) = sapling_params::fetch_with(&refs, |name, done, total| {
                if let Some(f) = &f {
                    if let Ok(v) = to_js(&Ev {
                        bytes_done: done,
                        bytes_total: total,
                        name,
                    }) {
                        let _ = f.call1(&JsValue::NULL, &v);
                    }
                }
            })
            .await
            .map_err(|e| {
                err(
                    match e {
                        ParamsError::Mismatch { .. } => "params",
                        _ => "network",
                    },
                    e,
                )
            })?;
            s.wallet
                .shielded_mut()
                .map_err(wallet_err)?
                .set_prover_bytes(&spend, &output)
                .map_err(shielded_err)
        })
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// Previews
// ---------------------------------------------------------------------------------------------

/// Plan a YEC send (`api::send_yec_preview`): after a sync of both pools, funded privacy first
/// (a `ys1…` recipient from private notes, with an optional memo; a transparent one from
/// private notes when they cover it — `revealsShielded` —, else from public YEC). A public
/// preview is signed already; a private one is proved and signed at [`confirm`].
#[wasm_bindgen]
pub async fn send_yec_preview(
    to: String,
    zat: JsValue,
    memo: Option<String>,
) -> Result<JsValue, JsValue> {
    let zat = amount_arg(&zat, "zat")?;
    with_session(|s| {
        Box::pin(async move {
            let r = s.sync().await?;
            let shielded = s.sync_shielded(yec_private::no_progress()).await;
            if yew_core::shielded_keys::is_sapling_address(s.network, to.trim()) {
                shielded?;
            }
            let plan = yec_private::plan_yec_send(
                &mut s.wallet,
                &to,
                zat,
                false,
                memo.as_deref(),
                r.tip,
                r.branch_id,
            )
            .map_err(wallet_err)?;
            let id = match &plan.funding {
                yec_private::Funding::Transparent(p) => txid_hex(&p.txid),
                _ => s.next_preview_id(),
            };
            let out = dto::yec_preview(id.clone(), &plan, r.yec.1, s.has_prover());
            s.previews.insert(id, Preview::Yec(Box::new(plan)));
            to_js(&out)
        })
    })
    .await
}

/// Plan a move between the wallet's own public and private balances
/// (`api::move_preview`): `to_private` shields public YEC (never the reserve or anything YED),
/// `to_public` unshields to the wallet's own public address. `zat` `null` = everything that
/// direction can move. Both prove at [`confirm`].
#[wasm_bindgen]
pub async fn move_preview(direction: String, zat: JsValue) -> Result<JsValue, JsValue> {
    let zat = if zat.is_undefined() || zat.is_null() {
        None
    } else {
        Some(amount_arg(&zat, "zat")?)
    };
    let direction = match direction.as_str() {
        "to_private" => yec_move::Direction::ToPrivate,
        "to_public" => yec_move::Direction::ToPublic,
        other => {
            return Err(err(
                "invalid",
                format!("direction {other:?}: to_private or to_public"),
            ))
        }
    };
    with_session(|s| {
        Box::pin(async move {
            let r = s.sync().await?;
            s.sync_shielded(yec_private::no_progress()).await?;
            let plan =
                yec_move::plan_move(&mut s.wallet, direction, zat, r.tip).map_err(wallet_err)?;
            let id = s.next_preview_id();
            let out = dto::yec_preview(id.clone(), &plan, r.yec.1, s.has_prover());
            s.previews.insert(id, Preview::Yec(Box::new(plan)));
            to_js(&out)
        })
    })
    .await
}

/// Build and sign a YED send of `cents` to `to` (`api::send_yed_preview`), after a sync, and
/// dry-run it on the node. Nothing is broadcast.
#[wasm_bindgen]
pub async fn send_yed_preview(to: String, cents: JsValue) -> Result<JsValue, JsValue> {
    let cents = amount_arg(&cents, "cents")?;
    with_session(|s| {
        Box::pin(async move {
            let r = s.sync().await?;
            let min = params::FEE_ZAT + 2 * params::TOKEN_VALUE;
            if r.yec.0 + r.yec.1 < min {
                return Err(err(
                    "build",
                    format!(
                        "You need about {}.{:08} YEC to send YED. Receive YEC first.",
                        min / 100_000_000,
                        min % 100_000_000
                    ),
                ));
            }
            let recips = [(to, cents.max(0) as u64)];
            let p = yed_transfer::build_yed_transfer(&s.wallet, &recips, r.tip, r.branch_id)
                .map_err(wallet_err)?;
            let conn = s.ensure_conn().await?;
            let yb = conn
                .validator
                .client_mut()
                .ok_or_else(|| err("gate", GateError::YellowbackAbsent))?;
            let v = yb.validate_raw(p.raw.clone()).await.map_err(net_err)?;
            let id = txid_hex(&p.txid);
            let out = dto::yed_preview(id.clone(), &p, &v);
            s.previews.insert(id, Preview::Yed(p));
            to_js(&out)
        })
    })
    .await
}

/// Whether a mint can be made now (`api::mint_availability`; connects, no sync).
#[wasm_bindgen]
pub async fn mint_availability() -> Result<JsValue, JsValue> {
    with_session(|s| {
        Box::pin(async move {
            s.ensure_conn().await?;
            let Session { wallet, conn, .. } = s;
            let conn = conn.as_mut().expect("connected");
            let g = wallet
                .mint_gate(&mut conn.validator)
                .await
                .map_err(wallet_err)?;
            to_js(&dto::mint_availability(&g, wallet.network))
        })
    })
    .await
}

fn cents_arg(cents: &JsValue) -> Result<u64, JsValue> {
    let c = amount_arg(cents, "cents")?;
    if c <= 0 || c > u32::MAX as i64 {
        return Err(err("invalid", "Enter an amount in dollars to mint."));
    }
    Ok(c as u64)
}

/// The mint estimate after a sync (`api::mint_estimate`): collateral, fees, payee, heights,
/// term class, attestor seqs. Nothing is signed.
#[wasm_bindgen]
pub async fn mint_estimate(cents: JsValue, lock_blocks: u32) -> Result<JsValue, JsValue> {
    let cents = cents_arg(&cents)?;
    with_session(|s| {
        Box::pin(async move {
            let r = s.sync().await?;
            let Session { wallet, conn, .. } = s;
            let conn = conn.as_mut().expect("connected");
            let e = wallet
                .mint_estimate(&mut conn.validator, cents, lock_blocks, r.tip)
                .await
                .map_err(wallet_err)?;
            to_js(&dto::mint_estimate(&e))
        })
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MintStartPreview {
    preview_id: String,
    cents: String,
    lock_blocks: u32,
}

/// Stage a mint (`api::mint_start`): [`confirm`] verifies the bundle, funds the carrier through
/// the gate and records the row (`CARRIER_SENT`; `mintId` in the confirm's result). `terms`
/// `{collateralZat, feeZat, payee, termClass}` from the estimate the user saw: a server answer
/// that differs is refused at confirm (`terms-changed`, audit G-2); `null` skips the check.
#[wasm_bindgen]
pub fn mint_start(cents: JsValue, lock_blocks: u32, terms: JsValue) -> Result<JsValue, JsValue> {
    let cents = cents_arg(&cents)?;
    let terms = if terms.is_undefined() || terms.is_null() {
        None
    } else {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Terms {
            collateral_zat: String,
            fee_zat: String,
            payee: String,
            term_class: String,
        }
        let t: Terms = serde_wasm_bindgen::from_value(terms)
            .map_err(|e| err("invalid", format!("terms: {e}")))?;
        Some(ConfirmedTerms {
            collateral_zat: amount_arg(&JsValue::from_str(&t.collateral_zat), "collateralZat")?,
            fee_zat: amount_arg(&JsValue::from_str(&t.fee_zat), "feeZat")?,
            payee: t.payee,
            term_class: t.term_class,
        })
    };
    with_session_sync(|s| {
        let id = s.next_preview_id();
        s.previews.insert(
            id.clone(),
            Preview::MintStart {
                cents,
                lock_blocks,
                terms,
            },
        );
        to_js(&MintStartPreview {
            preview_id: id,
            cents: dto::amt(cents as i64),
            lock_blocks,
        })
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MintStepPreview {
    preview_id: String,
    mint_id: i64,
    row: dto::MintStatus,
}

/// Stage the MINT (or a claim row's CLAIM) over a confirmed carrier (`api::mint_finish`):
/// [`confirm`] syncs, sends it through both gate layers and answers the row (`MAIN_SENT`).
#[wasm_bindgen]
pub fn mint_finish(mint_id: i64) -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let row = s.row_status(mint_id)?;
        let id = s.next_preview_id();
        s.previews.insert(id.clone(), Preview::MintFinish(mint_id));
        to_js(&MintStepPreview {
            preview_id: id,
            mint_id,
            row,
        })
    })
}

/// Stage the sweep of a `LAPSED` row's carrier (`api::mint_sweep`); [`confirm`] broadcasts.
#[wasm_bindgen]
pub fn mint_sweep(mint_id: i64) -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let row = s.row_status(mint_id)?;
        let id = s.next_preview_id();
        s.previews.insert(id.clone(), Preview::MintSweep(mint_id));
        to_js(&MintStepPreview {
            preview_id: id,
            mint_id,
            row,
        })
    })
}

/// Every two-step row (mints and claims), oldest first (`api::mints`; no network).
#[wasm_bindgen]
pub fn mints() -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let tip = s.synced_tip()?;
        let rows: Vec<dto::MintStatus> = s
            .wallet
            .mints()
            .map_err(wallet_err)?
            .iter()
            .map(|m| dto::mint_status(m, tip))
            .collect();
        to_js(&rows)
    })
}

/// The vaults this wallet owns as the last sync left them (`api::vaults`; no network).
#[wasm_bindgen]
pub fn vaults() -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let tip = s.synced_tip()?;
        let price = s.wallet.balances().map_err(wallet_err)?.price_micro_usd;
        let claim_price = match s.wallet.store.meta_u64("claim_price_micro_usd") {
            Ok(p) if p > 0 => Some(p as i64),
            _ => None,
        };
        let price = claim_price.or(price);
        let mints = s.wallet.mints().map_err(wallet_err)?;
        let now = now_secs();
        let rows: Vec<dto::VaultSummary> = s
            .wallet
            .vaults()
            .map_err(wallet_err)?
            .iter()
            .map(|v| dto::vault_summary(v, tip, price, s.network, &mints, now))
            .collect();
        to_js(&rows)
    })
}

/// Build and sign the REDEEM of an own `ACTIVE` vault at or past `lockHeight`, or the release
/// of a `VOID` one, after a sync (`api::redeem_preview`). Nothing is broadcast.
#[wasm_bindgen]
pub async fn redeem_preview(vault_txid: String) -> Result<JsValue, JsValue> {
    let txid = parse_txid(&vault_txid)?;
    with_session(|s| {
        Box::pin(async move {
            let r = s.sync().await?;
            let p = {
                let Session { wallet, conn, .. } = &mut *s;
                let conn = conn.as_mut().expect("connected");
                wallet
                    .redeem_preview(&mut conn.validator, &txid, r.tip, r.branch_id)
                    .await
                    .map_err(wallet_err)?
            };
            let id = txid_hex(&p.txid);
            let out = dto::redeem_preview(id.clone(), &p);
            s.previews.insert(id, Preview::Redeem(p));
            to_js(&out)
        })
    })
    .await
}

/// The claim intents paying this wallet as the last sync left them (`api::claim_intents`).
#[wasm_bindgen]
pub fn claim_intents() -> Result<JsValue, JsValue> {
    with_session_sync(|s| {
        let tip = s.synced_tip()?;
        let now = now_secs();
        let rows: Vec<dto::ClaimIntent> = s
            .wallet
            .intents()
            .map_err(wallet_err)?
            .iter()
            .map(|i| dto::claim_intent(i, tip, s.network, now))
            .collect();
        to_js(&rows)
    })
}

/// Build and sign the RELEASE of a matured claim intent `txid:n` after a sync
/// (`api::release_preview`). Nothing is broadcast.
#[wasm_bindgen]
pub async fn release_preview(intent: String) -> Result<JsValue, JsValue> {
    let op = parse_outpoint(&intent)?;
    with_session(|s| {
        Box::pin(async move {
            let r = s.sync().await?;
            let p = s
                .wallet
                .release_preview(&op, r.tip, r.branch_id)
                .map_err(wallet_err)?;
            let id = txid_hex(&p.txid);
            let out = dto::release_preview(id.clone(), &p);
            s.previews.insert(id, Preview::Release(p));
            to_js(&out)
        })
    })
    .await
}

async fn claimable_rows(
    s: &mut Session,
) -> Result<Vec<yew_core::build::claim::Claimable>, JsValue> {
    s.ensure_conn().await?;
    let Session { wallet, conn, .. } = s;
    let conn = conn.as_mut().expect("connected");
    wallet
        .claimable(&mut conn.validator)
        .await
        .map_err(wallet_err)
}

/// `ListClaimable` at the node's tip (`api::claimable`; the liquidator persona).
#[wasm_bindgen]
pub async fn claimable() -> Result<JsValue, JsValue> {
    with_session(|s| {
        Box::pin(async move {
            let rows: Vec<dto::ClaimableItem> = claimable_rows(s)
                .await?
                .iter()
                .map(dto::claimable_item)
                .collect();
            to_js(&rows)
        })
    })
    .await
}

/// Stage a claim of another wallet's claimable vault (`api::claim`): the row as the node lists
/// it now is what the user confirms, and [`confirm`] holds the server to its debt and take
/// (`claim-burn-above-max` / `claim-out-below-min`, H-9.3) before the bundle and the carrier
/// go through the gate.
#[wasm_bindgen]
pub async fn claim_preview(vault_txid: String) -> Result<JsValue, JsValue> {
    let txid = parse_txid(&vault_txid)?;
    with_session(|s| {
        Box::pin(async move {
            let rows = claimable_rows(s).await?;
            let item = rows
                .iter()
                .find(|c| c.vault_txid.eq_ignore_ascii_case(vault_txid.trim()))
                .ok_or_else(|| err("invalid", "the node does not list that vault as claimable"))?;
            if item.minted_cents == 0 || item.claimant_zat <= 0 {
                return Err(err(
                    "invalid",
                    "A claim needs the debt and the take you confirmed.",
                ));
            }
            let bounds = ClaimBounds {
                max_burn_cents: item.minted_cents,
                min_out_zat: item.claimant_zat,
            };
            let id = s.next_preview_id();
            let out = dto::ClaimPreview {
                preview_id: id.clone(),
                item: dto::claimable_item(item),
                max_burn_cents: dto::amt(item.minted_cents as i64),
                min_out_zat: dto::amt(item.claimant_zat),
            };
            s.previews.insert(
                id,
                Preview::Claim {
                    vault_txid: txid,
                    bounds,
                },
            );
            to_js(&out)
        })
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// Confirm
// ---------------------------------------------------------------------------------------------

/// Broadcast a preview (`api::*_confirm`): the only path that signs (a private send or shield is
/// proved here, seconds) and broadcasts, through both gate layers (`gate.rs`, D-W-5). A preview
/// is consumed, except when the proving parameters are missing (`params: …`): run
/// [`fetch_params`], then confirm again.
#[wasm_bindgen]
pub async fn confirm(preview_id: String) -> Result<JsValue, JsValue> {
    with_session(|s| {
        Box::pin(async move {
            let p = s
                .previews
                .remove(&preview_id)
                .ok_or_else(|| err("invalid", "This preview is no longer valid. Start again."))?;
            let out = match p {
                Preview::Yec(plan) => {
                    if plan.funding.needs_params() {
                        if let Err(e) = s.ensure_prover().await {
                            s.previews.insert(preview_id, Preview::Yec(plan));
                            return Err(e);
                        }
                    }
                    s.ensure_conn().await?;
                    let Session { wallet, conn, .. } = &mut *s;
                    let conn = conn.as_mut().expect("connected");
                    let c = yec_private::confirm_yec_send(
                        wallet,
                        &mut conn.compact,
                        &mut conn.validator,
                        &plan,
                        Path::new("<bytes>"),
                    )
                    .await
                    .map_err(wallet_err)?;
                    dto::SendResult {
                        txid: c.txid,
                        verdict: match &conn.validator {
                            Validator::Remote(_) => "ok".into(),
                            Validator::Absent => String::new(),
                        },
                        mint_id: None,
                    }
                }
                Preview::Yed(p) => {
                    s.ensure_conn().await?;
                    let Session { wallet, conn, .. } = &mut *s;
                    let conn = conn.as_mut().expect("connected");
                    let (txid, v) =
                        yed_transfer::broadcast(wallet, &mut conn.compact, &mut conn.validator, &p)
                            .await
                            .map_err(wallet_err)?;
                    dto::SendResult {
                        txid,
                        verdict: v.verdict,
                        mint_id: None,
                    }
                }
                Preview::Redeem(p) => {
                    s.ensure_conn().await?;
                    let Session { wallet, conn, .. } = &mut *s;
                    let conn = conn.as_mut().expect("connected");
                    let (txid, v) = wallet
                        .redeem_confirm(&mut conn.compact, &mut conn.validator, &p)
                        .await
                        .map_err(wallet_err)?;
                    dto::SendResult {
                        txid,
                        verdict: v.verdict,
                        mint_id: None,
                    }
                }
                Preview::Release(p) => {
                    s.ensure_conn().await?;
                    let Session { wallet, conn, .. } = &mut *s;
                    let conn = conn.as_mut().expect("connected");
                    let (txid, v) = wallet
                        .release_confirm(&mut conn.compact, &mut conn.validator, &p)
                        .await
                        .map_err(wallet_err)?;
                    dto::SendResult {
                        txid,
                        verdict: v.verdict,
                        mint_id: None,
                    }
                }
                Preview::MintStart {
                    cents,
                    lock_blocks,
                    terms,
                } => {
                    let r = s.sync().await?;
                    let id = {
                        let Session { wallet, conn, .. } = &mut *s;
                        let conn = conn.as_mut().expect("connected");
                        wallet
                            .mint_start(
                                &mut conn.compact,
                                &mut conn.validator,
                                cents,
                                lock_blocks,
                                terms.as_ref(),
                                r.tip,
                                r.branch_id,
                            )
                            .await
                            .map_err(wallet_err)?
                    };
                    let row = s.row_status(id)?;
                    dto::SendResult {
                        txid: row.carrier_txid,
                        verdict: "ok".into(),
                        mint_id: Some(id),
                    }
                }
                Preview::MintFinish(id) => {
                    let r = s.sync().await?;
                    {
                        let Session { wallet, conn, .. } = &mut *s;
                        let conn = conn.as_mut().expect("connected");
                        wallet
                            .mint_finish(
                                &mut conn.compact,
                                &mut conn.validator,
                                id,
                                r.tip,
                                r.branch_id,
                            )
                            .await
                            .map_err(wallet_err)?;
                    }
                    let row = s.row_status(id)?;
                    dto::SendResult {
                        txid: row.main_txid,
                        verdict: "ok".into(),
                        mint_id: Some(id),
                    }
                }
                Preview::MintSweep(id) => {
                    let r = s.sync().await?;
                    {
                        let Session { wallet, conn, .. } = &mut *s;
                        let conn = conn.as_mut().expect("connected");
                        wallet
                            .mint_sweep(
                                &mut conn.compact,
                                &mut conn.validator,
                                id,
                                r.tip,
                                r.branch_id,
                            )
                            .await
                            .map_err(wallet_err)?;
                    }
                    let row = s.row_status(id)?;
                    dto::SendResult {
                        txid: row.sweep_txid,
                        verdict: "ok".into(),
                        mint_id: Some(id),
                    }
                }
                Preview::Claim { vault_txid, bounds } => {
                    let r = s.sync().await?;
                    let id = {
                        let Session { wallet, conn, .. } = &mut *s;
                        let conn = conn.as_mut().expect("connected");
                        wallet
                            .claim(
                                &mut conn.compact,
                                &mut conn.validator,
                                &vault_txid,
                                Some(&bounds),
                                r.tip,
                                r.branch_id,
                            )
                            .await
                            .map_err(wallet_err)?
                    };
                    let row = s.row_status(id)?;
                    dto::SendResult {
                        txid: row.carrier_txid,
                        verdict: "ok".into(),
                        mint_id: Some(id),
                    }
                }
            };
            to_js(&out)
        })
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------

/// The WIF of an own transparent address (`api::export_wif`, D-W-11): YEC **and** YED on the
/// address move with the key.
#[wasm_bindgen]
pub fn export_wif(address: String) -> Result<String, JsValue> {
    with_session_sync(|s| {
        s.wallet
            .row_for_address(&address)
            .map_err(wallet_err)?
            .ok_or_else(|| {
                err(
                    "invalid",
                    format!("{address} is not an address of this wallet"),
                )
            })?;
        s.wallet.export_wif(&address).map_err(wallet_err)
    })
}

/// Import a WIF as a key outside the HD tree (`api::import_wif`, D-W-11); `birthday` lowers
/// the scan floor so the next sync finds the key's history. Answers the address pair.
#[wasm_bindgen]
pub fn import_wif(wif: String, birthday: Option<u64>) -> Result<JsValue, JsValue> {
    let wif = keys::SecretString::new(wif);
    with_session_sync(|s| {
        let row = s.wallet.import_wif(wif.trim()).map_err(wallet_err)?;
        if let Some(b) = birthday {
            let store = &s.wallet.store;
            let scanned = store.meta_u64("scanned_height").map_err(store_err)?;
            if scanned > 0 && b.saturating_sub(1) < scanned {
                store
                    .set_meta("scanned_height", &b.saturating_sub(1).to_string())
                    .map_err(store_err)?;
            }
            let wallet_birthday = store.meta_u64("birthday").map_err(store_err)?;
            if b < wallet_birthday {
                store
                    .set_meta("birthday", &b.to_string())
                    .map_err(store_err)?;
            }
        }
        to_js(&dto::AddressPair {
            address: row.address_s.clone(),
            kind: "transparent".into(),
            ye: row.address_ye,
            s: row.address_s,
            path: "imported".into(),
            covered_by_seed: false,
        })
    })
}
