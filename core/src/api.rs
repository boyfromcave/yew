//! The bridge surface (plan §3.4): the small set of calls the Flutter app sees through
//! `flutter_rust_bridge`, each returning a plain data struct or a [`YewError`] whose `message`
//! the UI may show verbatim (a gate refusal carries the node's verdict text).
//!
//! Shape (Phase W3):
//!
//! - One wallet handle, behind an async mutex ([`WALLET`]); seed material is passed at
//!   [`unlock`] / [`create_wallet`] and never returned (the one exception is a mnemonic this
//!   call *generated*, handed back once so the app can store it in the platform keystore,
//!   D-W-6). [`lock`] drops the handle and its derived keys.
//! - Every function here is a blocking Rust function (Dart sees a `Future`): it runs on the
//!   bridge's worker pool and drives the core's async network code on a private tokio runtime
//!   ([`runtime`]). The core's futures borrow the SQLite store across awaits and are not
//!   `Send`, which is why the calls are not `async fn` themselves.
//! - Every `*_confirm` goes through `gate::confirm` inside the core's `broadcast` (D-W-5);
//!   nothing here builds a transaction and nothing here can skip the gate.
//! - `mint_*`, `vaults`, `redeem`, `claimable`, `claim` (Phase W4) drive the core's two-step
//!   state machine and the vault builders exactly as `yew-cli` does: sync first, then the
//!   step with the sync's `tip` / `branch_id`; every broadcast runs both gate layers inside
//!   the core. The rows come back as [`MintStatus`] (the `mints` table, plan §5.3) so a
//!   screen reopened mid-mint renders the state the file holds.
//!
//! `yew-cli` (`core/cli/src/main.rs`) is the other driver of the same core; the two agree on
//! every step (connect → probe → sync → build → broadcast).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

use flutter_rust_bridge::frb;

use crate::frb_generated::StreamSink;
use tokio::sync::Mutex;

use crate::build::{yec_send, yed_transfer};
use crate::coins::UtxoClass;
use crate::gate::{GateError, Validator};
use crate::keys;
use crate::net::{Availability, CompactClient, NetError, Server, YellowbackClient};
use crate::params::{self, Network};
use crate::sync;
use crate::tx::txid_hex;
use crate::wallet::{Wallet, WalletError};

// ---------------------------------------------------------------------------------------------
// Plain data the app sees
// ---------------------------------------------------------------------------------------------

/// The network a wallet is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkId {
    /// Regtest (the devnet).
    Regtest,
    /// Testnet.
    Testnet,
    /// Mainnet.
    Mainnet,
}

impl NetworkId {
    fn to_network(self) -> Network {
        match self {
            NetworkId::Regtest => Network::Regtest,
            NetworkId::Testnet => Network::Testnet,
            NetworkId::Mainnet => Network::Mainnet,
        }
    }

    fn from_network(n: Network) -> NetworkId {
        match n {
            Network::Regtest => NetworkId::Regtest,
            Network::Testnet => NetworkId::Testnet,
            Network::Mainnet => NetworkId::Mainnet,
        }
    }
}

/// What kind of failure a [`YewError`] is; `message` is always the text to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// No wallet is open ([`unlock`] first).
    Locked,
    /// A wallet is already open ([`lock`] first).
    AlreadyOpen,
    /// A call the core does not offer yet (none in W4; kept for the app's exhaustive match).
    NotYetImplemented,
    /// The broadcast gate refused (the node's verdict is in `message`, D-W-5).
    Gate,
    /// The server could not be reached or answered with an error.
    Network,
    /// The server offers no usable Yellowback service (contract rule 1).
    YellowbackUnavailable,
    /// The builder refused (`change-floor`, `insufficient-yed`, bad address, ...).
    Refused,
    /// Not enough YEC for the fee of a YED operation (§3.7 item 4).
    NeedYecForFees,
    /// Bad input from the app (mnemonic, address, WIF, amount).
    Input,
    /// A preview id that no longer exists.
    PreviewExpired,
    /// Anything else (storage, key derivation).
    Other,
}

/// The one error type of the surface. `message` is complete and showable as-is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YewError {
    /// The kind.
    pub kind: ErrorKind,
    /// The text to show.
    pub message: String,
}

impl std::fmt::Display for YewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for YewError {}

impl YewError {
    fn new(kind: ErrorKind, message: impl Into<String>) -> YewError {
        YewError {
            kind,
            message: message.into(),
        }
    }

    fn locked() -> YewError {
        YewError::new(ErrorKind::Locked, "The wallet is locked. Unlock it first.")
    }
}

impl From<WalletError> for YewError {
    fn from(e: WalletError) -> YewError {
        let text = e.to_string();
        match e {
            WalletError::Gate(g) => YewError::new(ErrorKind::Gate, gate_message(&g)),
            WalletError::Net(n) => YewError::from(n),
            WalletError::Coins(c) => YewError::new(ErrorKind::NeedYecForFees, c.to_string()),
            WalletError::Transfer(t) => YewError::new(ErrorKind::Refused, t.to_string()),
            WalletError::Key(k) => YewError::new(ErrorKind::Input, k.to_string()),
            WalletError::Other(m) => YewError::new(ErrorKind::Refused, m),
            WalletError::Mint(crate::build::mint::MintError::Unaffordable { .. }) => {
                YewError::new(ErrorKind::NeedYecForFees, text)
            }
            WalletError::Mint(m) => YewError::new(ErrorKind::Refused, m.to_string()),
            other => YewError::new(ErrorKind::Other, other.to_string()),
        }
    }
}

impl From<NetError> for YewError {
    fn from(e: NetError) -> YewError {
        match e {
            NetError::Unimplemented | NetError::UnknownRpcVersion(_) => {
                YewError::new(ErrorKind::YellowbackUnavailable, e.to_string())
            }
            other => YewError::new(ErrorKind::Network, other.to_string()),
        }
    }
}

/// The verdict text of a gate refusal, verbatim from `GateError`'s display (the node's
/// `verdict` is inside it for the remote layer).
fn gate_message(g: &GateError) -> String {
    match g {
        GateError::YellowbackAbsent => g.to_string(),
        _ => g.to_string(),
    }
}

/// The result of [`create_wallet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Created {
    /// The wallet id (the primary address's key hash, hex-prefixed).
    pub wallet_id: String,
    /// The mnemonic, **only when this call generated it** (the app stores it in the platform
    /// keystore and shows it once for backup); `None` when the caller supplied the words.
    pub seed_words: Option<String>,
    /// The primary receive address, `ye…` form.
    pub address_ye: String,
}

/// Yellowback availability on the server (contract rule 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YellowbackStatus {
    /// The server offers the service (`GetYellowbackInfo` answered).
    pub present: bool,
    /// `enabled && active`: YED features may be shown.
    pub usable: bool,
    /// The `rpcversion` (0 when absent).
    pub rpcversion: i64,
    /// `enabled`.
    pub enabled: bool,
    /// `active`.
    pub active: bool,
    /// The server's Yellowback build string.
    pub server_version: String,
    /// The node's `feeZat` (0 when absent).
    pub fee_zat: i64,
}

/// [`status`]: the open wallet and its server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The wallet id.
    pub wallet_id: String,
    /// The network.
    pub network: NetworkId,
    /// `host:port`.
    pub server: String,
    /// Plain HTTP/2 (regtest only).
    pub plain: bool,
    /// The server's `version`.
    pub server_version: String,
    /// The server's chain name.
    pub chain_name: String,
    /// `consensusBranchId`, hex.
    pub branch_id: String,
    /// The tip.
    pub tip: i64,
    /// The wallet's birthday height.
    pub birthday: i64,
    /// The height the wallet last synced to (0 = never).
    pub sync_height: i64,
    /// The number of addresses the wallet watches.
    pub addresses: i64,
    /// Yellowback on this server.
    pub yellowback: YellowbackStatus,
    /// The core's version.
    pub core_version: String,
}

/// [`probe_server`]: what a server answers before any wallet is open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerProbe {
    /// The server's `version`.
    pub server_version: String,
    /// The server's chain name.
    pub chain_name: String,
    /// The tip (the default birthday of a new wallet).
    pub tip: i64,
    /// `taddrSupport`.
    pub taddr_support: bool,
    /// Yellowback on this server.
    pub yellowback: YellowbackStatus,
}

/// [`balances`] (plan §3.4 shape; computed from classes, §3.7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balances {
    /// YEC available (class `YEC`), zat.
    pub yec_zat: i64,
    /// YEC reserved for YED fees (class `FEE_RESERVE`), zat.
    pub yec_reserved_zat: i64,
    /// YEC change of own unconfirmed transactions, zat (in neither balance).
    pub yec_pending_zat: i64,
    /// YED (class `TOKEN`), cents.
    pub yed_cents: i64,
    /// Pending YED (class `PENDING_TOKEN`), cents.
    pub yed_pending_cents: i64,
    /// `GetPrice.pMint` at the last sync, micro-USD per YEC; `None` when undefined.
    pub price_micro_usd: Option<i64>,
    /// Outputs of `TOKEN_VALUE` the server does not list (class `HELD`): count.
    pub held_count: i64,
    /// The height the wallet last synced to (0 = never).
    pub sync_height: i64,
    /// The YEC a YED send needs at least (`fee + 2 · TOKEN_VALUE`), zat.
    pub yed_send_min_zat: i64,
}

/// A receive address in both forms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressPair {
    /// The Yellowback form (`ye…` / `yt…` / `yr…`).
    pub ye: String,
    /// The transparent form (`s1…` / `sm…`).
    pub s: String,
    /// The derivation path, or `imported`.
    pub path: String,
    /// `false` for an imported key (not covered by the seed backup).
    pub covered_by_seed: bool,
}

/// One history row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryItem {
    /// Txid, display form.
    pub txid: String,
    /// Block height (0 while pending).
    pub height: i64,
    /// Unconfirmed.
    pub pending: bool,
    /// Net YEC, zat (negative = sent).
    pub yec_delta_zat: i64,
    /// Net YED, cents (negative = sent).
    pub yed_delta_cents: i64,
    /// The verdict-derived label (`received $12.34`, `sent $12.34`, `minted $…`, ...), or the
    /// CLI's fallbacks for an unlabelled payload.
    pub label: String,
    /// The node's verdict, when known.
    pub verdict: String,
    /// The Yellowback kind (`transfer`, `mint`, ...), when known.
    pub kind: String,
    /// The transaction carries an `OP_RETURN`.
    pub has_payload: bool,
    /// The transaction has shielded components (a transparent leg of a shielded tx).
    pub shielded: bool,
}

/// One page of [`history`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPage {
    /// The rows of this page, pending first then newest first.
    pub rows: Vec<HistoryItem>,
    /// The page index requested.
    pub page: u32,
    /// Total rows.
    pub total: i64,
}

/// A YEC send, before confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YecPreview {
    /// Pass to [`send_yec_confirm`].
    pub preview_id: String,
    /// The recipient as given.
    pub to: String,
    /// The amount actually sent, zat.
    pub amount_zat: i64,
    /// The amount was raised by one zat off `TOKEN_VALUE`.
    pub amount_bumped: bool,
    /// The fee, zat.
    pub fee_zat: i64,
    /// The change, zat.
    pub change_zat: i64,
    /// Number of inputs.
    pub inputs: u32,
    /// The fee reserve was spent (`send_everything`).
    pub uses_reserve: bool,
    /// YEC that stays reserved for YED fees after this send, zat.
    pub keeps_reserved_zat: i64,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The txid the transaction will have.
    pub txid: String,
}

/// The node's dry run of a preview (`ValidateRawTransaction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DryRun {
    /// `valid`.
    pub valid: bool,
    /// `verdict`.
    pub verdict: String,
    /// `burned`, cents.
    pub burned_cents: i64,
    /// `wouldBeRejected`.
    pub would_be_rejected: bool,
    /// `yedIn`, cents.
    pub yed_in_cents: i64,
    /// `yedOut`, cents.
    pub yed_out_cents: i64,
    /// `true` when the gate would accept this validation.
    pub accepted: bool,
}

/// One recipient of a YED send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    /// `ye…` / `yr…` / `s…`.
    pub address: String,
    /// Cents.
    pub cents: i64,
}

/// A YED send, before confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YedPreview {
    /// Pass to [`send_yed_confirm`].
    pub preview_id: String,
    /// The recipients.
    pub recipients: Vec<Recipient>,
    /// Total cents to the recipients.
    pub total_cents: i64,
    /// The selection stage (`exact`, `single`, `greedy`, `search`).
    pub stage: String,
    /// Number of YED inputs.
    pub yed_inputs: u32,
    /// YED change, cents.
    pub change_cents: i64,
    /// Number of YEC inputs (fee).
    pub yec_inputs: u32,
    /// The fee, zat.
    pub fee_zat: i64,
    /// YEC change, zat.
    pub yec_change_zat: i64,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The txid the transaction will have.
    pub txid: String,
    /// The node's dry run on these bytes (the same rule the gate applies at confirm).
    pub dry_run: DryRun,
}

/// The result of a confirm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendResult {
    /// The txid, display form.
    pub txid: String,
    /// The node's verdict on the broadcast bytes (`ok`), empty on the YEC path against a
    /// server without Yellowback.
    pub verdict: String,
}

/// [`export_wif`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WifExport {
    /// The address, `ye…` form.
    pub address_ye: String,
    /// The address, `s…` form.
    pub address_s: String,
    /// The WIF (`dumpprivkey` format, D-W-11).
    pub wif: String,
    /// `false` for an imported key.
    pub covered_by_seed: bool,
}

/// [`validate_address`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressCheck {
    /// Parses for the network.
    pub valid: bool,
    /// `p2pkh` / `p2sh`, empty when invalid.
    pub kind: String,
    /// The `ye…` form was given.
    pub yellowback_form: bool,
    /// Why it is invalid, empty when valid.
    pub message: String,
}

/// A stage of [`sync_now`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncStage {
    /// Opening the channel.
    Connecting,
    /// `GetLightdInfo` + `GetYellowbackInfo`.
    Probing,
    /// The §3.2 loop.
    Scanning,
    /// Finished; `tip` and `sync_height` are set.
    Done,
    /// Failed; `message` is set.
    Failed,
}

/// One event of [`sync_now`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncEvent {
    /// The stage.
    pub stage: SyncStage,
    /// A one-line description (or the error on `Failed`).
    pub message: String,
    /// The tip (from `Probing` on).
    pub tip: i64,
    /// The height synced to (`Done`).
    pub sync_height: i64,
    /// Yellowback usable on this server (from `Probing` on).
    pub yellowback_usable: bool,
}

/// [`mint_estimate`]: what the Mint screen shows before anything is signed (plan §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintEstimate {
    /// Cents to mint.
    pub cents: i64,
    /// The lock in blocks.
    pub lock_blocks: u32,
    /// The term class letter (`A`, `B`, `C`).
    pub term_class: String,
    /// `R`, the reference height the two transactions cite.
    pub ref_height: i64,
    /// `R + lockBlocks`: when the owner may redeem.
    pub lock_height: i64,
    /// `lockHeight + GRACE`: when a liquidator may claim.
    pub claim_height: i64,
    /// `R + REF_WINDOW`: the carrier and the MINT expire here.
    pub expiry_height: i64,
    /// `requiredZat` as the node reports it.
    pub required_zat: i64,
    /// The collateral the MINT will lock (rounded as `BuildMint` does).
    pub collateral_zat: i64,
    /// The enforcement fee, zat (0 under FEE-0).
    pub fee_zat: i64,
    /// The attestor fee, zat (0 under AFEE-0).
    pub attest_fee_zat: i64,
    /// `CARRIER_VALUE`, zat.
    pub carrier_zat: i64,
    /// `TOKEN_VALUE` for the new YED output, zat.
    pub token_zat: i64,
    /// The two network fees, zat.
    pub network_fee_zat: i64,
    /// Everything the two steps need from YEC, zat.
    pub total_zat: i64,
    /// Spendable `YEC` + `FEE_RESERVE`, zat.
    pub available_zat: i64,
    /// `available_zat >= total_zat`.
    pub affordable: bool,
    /// `pMint` at `R`, micro-USD per YEC; `None` when undefined.
    pub p_mint_micro_usd: Option<i64>,
    /// `armed` at `R`.
    pub armed: bool,
    /// The attestor `seq`s the bundle would carry.
    pub bundle_seqs: Vec<u32>,
}

/// One `mints` row (plan §5.3, README "the two-step state machine is a table"): a mint or a
/// claim from the moment its carrier is broadcast. `state` is the stored name
/// (`CARRIER_SENT`, `CARRIER_CONFIRMED`, `MAIN_SENT`, `DONE`, `LAPSED`, `SWEEP_SENT`, `SWEPT`,
/// `FAILED`). Heights are judged against `tip`, the last height the wallet synced to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintStatus {
    /// The row id.
    pub mint_id: i64,
    /// `mint` or `claim`.
    pub kind: String,
    /// The stored state name.
    pub state: String,
    /// The tip when the carrier was broadcast.
    pub created_height: i64,
    /// Cents minted (mint) or the debt burned (claim).
    pub cents: i64,
    /// `lockBlocks` (mint).
    pub lock_blocks: u32,
    /// The term class letter.
    pub term_class: String,
    /// `R`.
    pub ref_height: i64,
    /// The vault's `lockHeight`.
    pub lock_height: i64,
    /// The vault's `claimHeight`.
    pub claim_height: i64,
    /// `R + REF_WINDOW`.
    pub expiry_height: i64,
    /// The collateral, zat.
    pub collateral_zat: i64,
    /// The enforcement fee, zat.
    pub fee_zat: i64,
    /// The attestor fee, zat.
    pub attest_fee_zat: i64,
    /// A claim's residual to the vault owner, zat.
    pub residual_zat: i64,
    /// The bundle's `seq`s as `"0,1,2"`.
    pub bundle_seqs: String,
    /// The carrier funding txid (display form).
    pub carrier_txid: String,
    /// The MINT / CLAIM txid, empty until `MAIN_SENT`.
    pub main_txid: String,
    /// The sweep txid, empty until `SWEEP_SENT`.
    pub sweep_txid: String,
    /// A claim's vault txid, empty for a mint.
    pub vault_txid: String,
    /// The last synced height the flags below were judged at.
    pub tip: i64,
    /// `CARRIER_SENT`, `CARRIER_CONFIRMED` or `MAIN_SENT`: still moving.
    pub in_progress: bool,
    /// The node would still accept the main transaction (`CheckExpiry` at `tip`).
    pub window_open: bool,
    /// Blocks until the window closes (0 when closed).
    pub blocks_left: i64,
    /// `CARRIER_CONFIRMED` with the window open: [`mint_finish`] may be called.
    pub can_finish: bool,
    /// `LAPSED`: [`mint_sweep`] may be called.
    pub can_sweep: bool,
    /// Why the row failed or lapsed, for the screen.
    pub note: String,
}

/// One own vault as `GetVault` last reported it (the Yellowback screen, plan §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSummary {
    /// The mint txid (the vault outpoint is `txid:0`).
    pub vault_txid: String,
    /// `ACTIVE`, `VOID`, `CLOSED`, `CLAIMED`.
    pub status: String,
    /// The owner address, `ye…` form (an own key).
    pub owner_address: String,
    /// The term class letter.
    pub term_class: String,
    /// Cents minted (the debt).
    pub cents: i64,
    /// Collateral, zat.
    pub collateral_zat: i64,
    /// `lockHeight`.
    pub lock_height: i64,
    /// `claimHeight`.
    pub claim_height: i64,
    /// `mintHeight`.
    pub mint_height: i64,
    /// The last synced height the flags below were judged at.
    pub tip: i64,
    /// `ACTIVE` or `VOID`: still spendable by its owner.
    pub open: bool,
    /// `ACTIVE` and `tip >= lockHeight`: [`redeem`] builds the owner-path REDEEM.
    pub redeemable: bool,
    /// Blocks until `lockHeight` (0 once reached).
    pub blocks_until_redeem: i64,
    /// `VOID`: [`redeem`] releases the collateral without a payload.
    pub releasable: bool,
    /// `claimable` as the node judged it at its tip (a liquidator may take it).
    pub claimable: bool,
    /// `underwaterAt`, micro-USD per YEC (0 when undefined).
    pub underwater_at_micro_usd: i64,
    /// The last sync's `pMint` is at or below `underwaterAt`: the warning.
    pub underwater: bool,
    /// `closeHeight`, 0 while open.
    pub close_height: i64,
    /// `closingTxid`, empty while open.
    pub closing_txid: String,
    /// `voidReason`, empty unless VOID.
    pub void_reason: String,
}

/// One `ListClaimable` row (the liquidator persona, plan §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimableItem {
    /// The vault's mint txid.
    pub vault_txid: String,
    /// The owner, `ye…`.
    pub owner_address: String,
    /// The debt to burn, cents (the wallet must hold at least this).
    pub cents: i64,
    /// The collateral, zat.
    pub collateral_zat: i64,
    /// `claimHeight`.
    pub claim_height: i64,
    /// `a` (underwater at `pClaim`) or `b` (notice + emergency price).
    pub claim_path: String,
    /// `pClaim` at the node's tip, micro-USD per YEC.
    pub p_claim_micro_usd: i64,
    /// The enforcement fee, zat.
    pub fee_zat: i64,
    /// The attestor fee, zat.
    pub attest_fee_zat: i64,
    /// RED-5's residual to the owner, zat.
    pub residual_zat: i64,
    /// What the claimant keeps, zat.
    pub claimant_zat: i64,
}

/// The result of [`redeem`]: the REDEEM (or the release of a VOID vault) was broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemResult {
    /// The txid, display form.
    pub txid: String,
    /// The node's verdict on the broadcast bytes.
    pub verdict: String,
    /// `redeem` (ACTIVE) or `release` (VOID).
    pub kind: String,
    /// Cents burned (the debt plus any sub-dollar remainder).
    pub burn_cents: i64,
    /// The sub-dollar remainder burned on top of the debt.
    pub extra_burn_cents: i64,
    /// YED change, cents.
    pub change_cents: i64,
    /// The enforcement fee, zat.
    pub fee_zat: i64,
    /// The collateral returned, zat.
    pub collateral_zat: i64,
    /// The own address it returns to.
    pub collateral_address: String,
    /// `nLockTime` (= `lockHeight`).
    pub lock_time: i64,
    /// `nExpiryHeight`.
    pub expiry_height: i64,
}

// ---------------------------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------------------------

/// The live connection, built lazily from `Open::server`.
struct Conn {
    compact: CompactClient,
    validator: Validator,
    availability: Availability,
    branch_id: u32,
    tip: u64,
    server_version: String,
    chain_name: String,
}

/// A signed preview waiting for its confirm.
enum Preview {
    Yec(yec_send::YecSendPreview),
    Yed(yed_transfer::YedTransferPreview),
}

/// The open wallet.
struct Open {
    wallet: Wallet,
    server: Server,
    conn: Option<Conn>,
    previews: HashMap<String, Preview>,
}

/// The single wallet handle.
static WALLET: Mutex<Option<Open>> = Mutex::const_new(None);

/// The private tokio runtime the core's network code runs on.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// Run `f` with the open wallet.
fn with_open<T>(f: impl FnOnce(&mut Open) -> Result<T, YewError>) -> Result<T, YewError> {
    runtime().block_on(async {
        let mut guard = WALLET.lock().await;
        let open = guard.as_mut().ok_or_else(YewError::locked)?;
        f(open)
    })
}

/// A future borrowing the open wallet.
type OpenFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, YewError>> + 'a>>;

/// Run an async `f` with the open wallet, on the private runtime.
fn with_open_async<T>(
    f: impl for<'a> FnOnce(&'a mut Open) -> OpenFuture<'a, T>,
) -> Result<T, YewError> {
    runtime().block_on(async {
        let mut guard = WALLET.lock().await;
        let open = guard.as_mut().ok_or_else(YewError::locked)?;
        f(open).await
    })
}

fn wallet_id(w: &Wallet) -> Result<String, YewError> {
    let h = w
        .store
        .meta("primary_hash160")
        .map_err(|e| YewError::new(ErrorKind::Other, e.to_string()))?
        .unwrap_or_default();
    Ok(format!("yew-{}", &h[..h.len().min(16)]))
}

fn yellowback_status(a: &Availability) -> YellowbackStatus {
    match a {
        Availability::Absent => YellowbackStatus {
            present: false,
            usable: false,
            rpcversion: 0,
            enabled: false,
            active: false,
            server_version: String::new(),
            fee_zat: 0,
        },
        Availability::Present {
            info,
            enabled,
            active,
        } => YellowbackStatus {
            present: true,
            usable: a.usable(),
            rpcversion: info.rpcversion,
            enabled: *enabled,
            active: *active,
            server_version: info.server_version.clone(),
            fee_zat: info.params.as_ref().map(|p| p.fee_zat).unwrap_or(0),
        },
    }
}

async fn connect(server: &Server, network: Network) -> Result<Conn, YewError> {
    let channel = server.connect().await?;
    let mut compact = CompactClient::from_channel(channel.clone());
    let info = compact.lightd_info_for(network).await?;
    let tip = compact.latest_height().await?.max(info.block_height);
    let (validator, availability) =
        Validator::detect(YellowbackClient::from_channel(channel)).await?;
    Ok(Conn {
        compact,
        validator,
        availability,
        branch_id: info.branch_id,
        tip,
        server_version: info.version,
        chain_name: info.chain_name,
    })
}

/// Connect if not connected.
async fn ensure_conn(o: &mut Open) -> Result<(), YewError> {
    if o.conn.is_none() {
        o.conn = Some(connect(&o.server, o.wallet.network).await?);
    }
    Ok(())
}

impl Open {
    /// Sync (the CLI's `synced`): connect if needed, run the §3.2 loop; on a network error
    /// drop the connection so the next call reconnects.
    async fn sync(&mut self) -> Result<sync::SyncReport, YewError> {
        let network = self.wallet.network;
        if self.conn.is_none() {
            self.conn = Some(connect(&self.server, network).await?);
        }
        let conn = self.conn.as_mut().expect("set above");
        let r = sync::sync(
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
                Err(e.into())
            }
        }
    }
}

fn parse_server(server: &str, plain: bool, network: Network) -> Result<Server, YewError> {
    if plain && network == Network::Mainnet {
        return Err(YewError::new(
            ErrorKind::Input,
            "A plain (non-TLS) connection is refused on mainnet.",
        ));
    }
    Server::parse(server, plain).map_err(|m| YewError::new(ErrorKind::Input, m))
}

fn open_wallet(
    data_dir: &str,
    network: Network,
    mnemonic: &str,
    passphrase: &str,
    birthday: Option<u64>,
) -> Result<Wallet, YewError> {
    let path = format!(
        "{}/yew-{}.sqlite",
        data_dir.trim_end_matches('/'),
        network.chain_name()
    );
    let words = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    Wallet::open(&path, network, &words, passphrase, birthday).map_err(|e| match e {
        WalletError::Key(k) => YewError::new(ErrorKind::Input, k.to_string()),
        other => YewError::new(ErrorKind::Other, other.to_string()),
    })
}

// ---------------------------------------------------------------------------------------------
// The surface
// ---------------------------------------------------------------------------------------------

/// Bridge initialisation hook (logging, panics as errors).
#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

/// The core's version.
#[frb(sync)]
pub fn core_version() -> String {
    crate::VERSION.to_string()
}

/// A fresh BIP39 English mnemonic of 12 or 24 words (the app stores it in the keystore).
#[frb(sync)]
pub fn generate_seed_words(words: u32) -> Result<String, YewError> {
    keys::generate_mnemonic(words as usize)
        .map_err(|e| YewError::new(ErrorKind::Input, e.to_string()))
}

/// Check a mnemonic without opening anything.
#[frb(sync)]
pub fn check_seed_words(seed_words: String) -> Result<(), YewError> {
    let words = seed_words.split_whitespace().collect::<Vec<_>>().join(" ");
    keys::seed_from_mnemonic(&words, "")
        .map(|_| ())
        .map_err(|e| YewError::new(ErrorKind::Input, e.to_string()))
}

/// Parse an address for `network` (the Send screen's field check).
#[frb(sync)]
pub fn validate_address(network: NetworkId, address: String) -> AddressCheck {
    match keys::parse_address(network.to_network(), address.trim()) {
        Ok(a) => AddressCheck {
            valid: true,
            kind: match a.kind {
                keys::AddressKind::P2pkh(_) => "p2pkh".into(),
                keys::AddressKind::P2sh(_) => "p2sh".into(),
            },
            yellowback_form: a.yellowback_form,
            message: String::new(),
        },
        Err(e) => AddressCheck {
            valid: false,
            kind: String::new(),
            yellowback_form: false,
            message: e.to_string(),
        },
    }
}

/// Probe a server before any wallet is open (Onboarding's default birthday, Settings' server
/// check). Contract rule 1: an unknown `rpcversion` is an error.
pub fn probe_server(
    server: String,
    plain: bool,
    network: NetworkId,
) -> Result<ServerProbe, YewError> {
    let network = network.to_network();
    let server = parse_server(&server, plain, network)?;
    runtime().block_on(async {
        let c = connect(&server, network).await?;
        Ok(ServerProbe {
            server_version: c.server_version,
            chain_name: c.chain_name,
            tip: c.tip as i64,
            taddr_support: true,
            yellowback: yellowback_status(&c.availability),
        })
    })
}

/// Create (or restore) a wallet and open it. `seed_words` `None` generates a 12-word mnemonic
/// and returns it once in [`Created::seed_words`]. `birthday` `None` = from the first block
/// (pass the server's tip for a new seed). `data_dir` is the app's private directory.
#[allow(clippy::too_many_arguments)]
pub fn create_wallet(
    seed_words: Option<String>,
    passphrase: String,
    birthday: Option<i64>,
    network: NetworkId,
    server: String,
    plain: bool,
    data_dir: String,
) -> Result<Created, YewError> {
    let network = network.to_network();
    let server = parse_server(&server, plain, network)?;
    let (words, generated) = match seed_words {
        Some(w) => (w, None),
        None => {
            let w = keys::generate_mnemonic(12)
                .map_err(|e| YewError::new(ErrorKind::Other, e.to_string()))?;
            (w.clone(), Some(w))
        }
    };
    runtime().block_on(async {
        let mut guard = WALLET.lock().await;
        if guard.is_some() {
            return Err(YewError::new(
                ErrorKind::AlreadyOpen,
                "A wallet is already open. Lock it first.",
            ));
        }
        let wallet = open_wallet(
            &data_dir,
            network,
            &words,
            &passphrase,
            birthday.map(|b| b.max(0) as u64),
        )?;
        let id = wallet_id(&wallet)?;
        let primary = wallet.receive_address(false)?;
        *guard = Some(Open {
            wallet,
            server,
            conn: None,
            previews: HashMap::new(),
        });
        Ok(Created {
            wallet_id: id,
            seed_words: generated,
            address_ye: primary.address_ye,
        })
    })
}

/// Open an existing wallet with its seed (from the keystore). Returns the wallet id.
pub fn unlock(
    seed_words: String,
    passphrase: String,
    network: NetworkId,
    server: String,
    plain: bool,
    data_dir: String,
) -> Result<String, YewError> {
    let network = network.to_network();
    let server = parse_server(&server, plain, network)?;
    runtime().block_on(async {
        let mut guard = WALLET.lock().await;
        if guard.is_some() {
            return Err(YewError::new(
                ErrorKind::AlreadyOpen,
                "A wallet is already open. Lock it first.",
            ));
        }
        let wallet = open_wallet(&data_dir, network, &seed_words, &passphrase, None)?;
        let id = wallet_id(&wallet)?;
        *guard = Some(Open {
            wallet,
            server,
            conn: None,
            previews: HashMap::new(),
        });
        Ok(id)
    })
}

/// Drop the wallet handle, its derived keys, its connection and any preview.
pub fn lock() {
    runtime().block_on(async {
        let mut guard = WALLET.lock().await;
        *guard = None;
    });
}

/// Is a wallet open?
#[frb(sync)]
pub fn is_unlocked() -> bool {
    runtime().block_on(async { WALLET.lock().await.is_some() })
}

/// Change the server of the open wallet (Settings). The next call reconnects.
pub fn set_server(server: String, plain: bool) -> Result<(), YewError> {
    with_open(|o| {
        o.server = parse_server(&server, plain, o.wallet.network)?;
        o.conn = None;
        o.previews.clear();
        Ok(())
    })
}

/// Server info, Yellowback info, tip, sync height (connects if needed).
pub fn status() -> Result<Status, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            let network = o.wallet.network;
            let server = o.server.clone();
            let birthday = o.wallet.birthday()?;
            let sync_height = o
                .wallet
                .store
                .meta_u64("last_synced_height")
                .map_err(|e| YewError::new(ErrorKind::Other, e.to_string()))?;
            let addresses = o.wallet.addresses()?.len() as u64;
            let id = wallet_id(&o.wallet)?;
            if let Err(e) = ensure_conn(o).await {
                o.conn = None;
                return Err(e);
            }
            let c = o.conn.as_mut().expect("connected");
            c.tip = c.compact.latest_height().await.unwrap_or(c.tip);
            Ok(Status {
                wallet_id: id,
                network: NetworkId::from_network(network),
                server: format!("{}:{}", server.host, server.port),
                plain: server.plain,
                server_version: c.server_version.clone(),
                chain_name: c.chain_name.clone(),
                branch_id: format!("{:08x}", c.branch_id),
                tip: c.tip as i64,
                birthday: birthday as i64,
                sync_height: sync_height as i64,
                addresses: addresses as i64,
                yellowback: yellowback_status(&c.availability),
                core_version: crate::VERSION.to_string(),
            })
        })
    })
}

/// The balances from the store (no network).
pub fn balances() -> Result<Balances, YewError> {
    with_open(|o| {
        let b = o.wallet.balances()?;
        let held = o
            .wallet
            .store
            .utxos()
            .map_err(|e| YewError::new(ErrorKind::Other, e.to_string()))?
            .iter()
            .filter(|u| u.class == UtxoClass::Held)
            .count() as u64;
        let sync_height = o
            .wallet
            .store
            .meta_u64("last_synced_height")
            .map_err(|e| YewError::new(ErrorKind::Other, e.to_string()))?;
        Ok(Balances {
            yec_zat: b.yec_zat,
            yec_reserved_zat: b.yec_reserved_zat,
            yec_pending_zat: b.yec_pending_zat,
            yed_cents: b.yed_cents as i64,
            yed_pending_cents: b.yed_pending_cents as i64,
            price_micro_usd: b.price_micro_usd,
            held_count: held as i64,
            sync_height: sync_height as i64,
            yed_send_min_zat: params::FEE_ZAT + 2 * params::TOKEN_VALUE,
        })
    })
}

/// The receive address (first unused external). `fresh` marks the current one used first.
pub fn receive_address(fresh: bool) -> Result<AddressPair, YewError> {
    with_open(|o| {
        let row = o.wallet.receive_address(fresh)?;
        Ok(AddressPair {
            ye: row.address_ye,
            s: row.address_s,
            path: format!("m/44'/347'/0'/{}/{}", row.chain, row.index),
            covered_by_seed: true,
        })
    })
}

/// Every address of the wallet (Settings → export private key picks one).
pub fn addresses() -> Result<Vec<AddressPair>, YewError> {
    with_open(|o| {
        Ok(o.wallet
            .addresses()?
            .into_iter()
            .map(|r| {
                let hd = r.hd_chain().is_some();
                AddressPair {
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
            .collect())
    })
}

fn history_item(h: &crate::store::HistoryRow) -> HistoryItem {
    let label = if h.label.is_empty() {
        if h.has_payload {
            if h.labelled {
                "payload, not yellowback"
            } else {
                "payload, unlabelled"
            }
        } else if h.yec_delta < 0 {
            "sent YEC"
        } else if h.yec_delta > 0 {
            "received YEC"
        } else {
            ""
        }
        .to_string()
    } else {
        h.label.clone()
    };
    HistoryItem {
        txid: txid_hex(&h.txid),
        height: h.height as i64,
        pending: h.pending,
        yec_delta_zat: h.yec_delta,
        yed_delta_cents: h.yed_delta,
        label,
        verdict: h.verdict.clone(),
        kind: h.kind.clone(),
        has_payload: h.has_payload,
        shielded: h.shielded,
    }
}

/// One page of history (pending first, then newest first). `page_size` 0 = 50.
pub fn history(page: u32, page_size: u32) -> Result<HistoryPage, YewError> {
    with_open(|o| {
        let all = o
            .wallet
            .store
            .history()
            .map_err(|e| YewError::new(ErrorKind::Other, e.to_string()))?;
        let size = if page_size == 0 {
            50
        } else {
            page_size as usize
        };
        let rows = all
            .iter()
            .skip(page as usize * size)
            .take(size)
            .map(history_item)
            .collect();
        Ok(HistoryPage {
            rows,
            page,
            total: all.len() as i64,
        })
    })
}

/// Build and sign a YEC send (after a sync). Nothing is broadcast.
pub fn send_yec_preview(
    to: String,
    zat: i64,
    send_everything: bool,
) -> Result<YecPreview, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            let r = o.sync().await?;
            let p =
                yec_send::build_yec_send(&o.wallet, &to, zat, send_everything, r.tip, r.branch_id)?;
            let txid = txid_hex(&p.txid);
            let reserved_spent: i64 = p
                .inputs
                .iter()
                .filter(|u| u.class == UtxoClass::FeeReserve)
                .map(|u| u.value)
                .sum();
            let out = YecPreview {
                preview_id: txid.clone(),
                to: p.to.clone(),
                amount_zat: p.amount,
                amount_bumped: p.amount_bumped,
                fee_zat: p.fee,
                change_zat: p.change,
                inputs: p.inputs.len() as u32,
                uses_reserve: p.uses_reserve,
                keeps_reserved_zat: r.yec.1 - reserved_spent,
                expiry_height: p.expiry_height,
                txid: txid.clone(),
            };
            o.previews.insert(txid, Preview::Yec(p));
            Ok(out)
        })
    })
}

/// Broadcast a YEC preview through the gate (D-W-5).
pub fn send_yec_confirm(preview_id: String) -> Result<SendResult, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            let p = match o.previews.remove(&preview_id) {
                Some(Preview::Yec(p)) => p,
                _ => {
                    return Err(YewError::new(
                        ErrorKind::PreviewExpired,
                        "This preview is no longer valid. Start the send again.",
                    ))
                }
            };
            ensure_conn(o).await?;
            let Open { wallet, conn, .. } = o;
            let conn = conn.as_mut().expect("connected");
            let txid =
                yec_send::broadcast(wallet, &mut conn.compact, &mut conn.validator, &p).await?;
            Ok(SendResult {
                txid,
                verdict: match &conn.validator {
                    Validator::Remote(_) => "ok".into(),
                    Validator::Absent => String::new(),
                },
            })
        })
    })
}

/// Build and sign a YED transfer (after a sync) and dry-run it on the node. Nothing is
/// broadcast. With too little YEC for the fee the error is [`ErrorKind::NeedYecForFees`].
pub fn send_yed_preview(recipients: Vec<Recipient>) -> Result<YedPreview, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            let r = o.sync().await?;
            let min = params::FEE_ZAT + 2 * params::TOKEN_VALUE;
            if r.yec.0 + r.yec.1 < min {
                return Err(YewError::new(
                    ErrorKind::NeedYecForFees,
                    format!(
                        "You need about {} YEC to send YED. Receive YEC first.",
                        format_yec(min)
                    ),
                ));
            }
            let recips: Vec<(String, u64)> = recipients
                .iter()
                .map(|r| (r.address.clone(), r.cents.max(0) as u64))
                .collect();
            let p = yed_transfer::build_yed_transfer(&o.wallet, &recips, r.tip, r.branch_id)?;
            ensure_conn(o).await?;
            let conn = o.conn.as_mut().expect("connected");
            let yb = conn.validator.client_mut().ok_or_else(|| {
                YewError::new(
                    ErrorKind::YellowbackUnavailable,
                    GateError::YellowbackAbsent.to_string(),
                )
            })?;
            let v = yb.validate_raw(p.raw.clone()).await?;
            let txid = txid_hex(&p.txid);
            let out = YedPreview {
                preview_id: txid.clone(),
                recipients,
                total_cents: recips.iter().map(|r| r.1 as i64).sum(),
                stage: p.stage.name().into(),
                yed_inputs: p.yed_inputs.len() as u32,
                change_cents: p.change_cents as i64,
                yec_inputs: p.yec_inputs.len() as u32,
                fee_zat: p.fee,
                yec_change_zat: p.yec_change,
                expiry_height: p.expiry_height,
                txid: txid.clone(),
                dry_run: DryRun {
                    valid: v.valid,
                    verdict: v.verdict.clone(),
                    burned_cents: v.burned,
                    would_be_rejected: v.would_be_rejected,
                    yed_in_cents: v.yed_in,
                    yed_out_cents: v.yed_out,
                    accepted: crate::gate::accept(&v, 0).is_ok(),
                },
            };
            o.previews.insert(txid, Preview::Yed(p));
            Ok(out)
        })
    })
}

/// Broadcast a YED preview through the gate (D-W-5): both layers again on the same bytes.
pub fn send_yed_confirm(preview_id: String) -> Result<SendResult, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            let p = match o.previews.remove(&preview_id) {
                Some(Preview::Yed(p)) => p,
                _ => {
                    return Err(YewError::new(
                        ErrorKind::PreviewExpired,
                        "This preview is no longer valid. Start the send again.",
                    ))
                }
            };
            ensure_conn(o).await?;
            let Open { wallet, conn, .. } = o;
            let conn = conn.as_mut().expect("connected");
            let (txid, v) =
                yed_transfer::broadcast(wallet, &mut conn.compact, &mut conn.validator, &p).await?;
            Ok(SendResult {
                txid,
                verdict: v.verdict,
            })
        })
    })
}

/// Export the WIF of an own address (D-W-11). The app shows the warning: YEC **and** YED on
/// this address move with the key.
pub fn export_wif(address: String) -> Result<WifExport, YewError> {
    with_open(|o| {
        let row = o.wallet.row_for_address(&address)?.ok_or_else(|| {
            YewError::new(
                ErrorKind::Input,
                format!("{address} is not an address of this wallet"),
            )
        })?;
        let wif = o.wallet.export_wif(&address)?;
        Ok(WifExport {
            address_ye: row.address_ye.clone(),
            address_s: row.address_s.clone(),
            wif,
            covered_by_seed: row.hd_chain().is_some(),
        })
    })
}

/// Import a WIF (from YecWallet / `dumpprivkey`) as a key outside the HD tree (D-W-11).
/// `birthday` (the height to rescan from) lowers the wallet's scan floor so the next sync
/// finds the key's history. The key is not covered by the seed backup.
pub fn import_wif(wif: String, birthday: Option<i64>) -> Result<AddressPair, YewError> {
    with_open(|o| {
        let row = o.wallet.import_wif(wif.trim())?;
        if let Some(b) = birthday {
            let b = b.max(0) as u64;
            let store = &o.wallet.store;
            let err = |e: crate::store::StoreError| YewError::new(ErrorKind::Other, e.to_string());
            let scanned = store.meta_u64("scanned_height").map_err(err)?;
            if scanned > 0 && b.saturating_sub(1) < scanned {
                store
                    .set_meta("scanned_height", &b.saturating_sub(1).to_string())
                    .map_err(err)?;
            }
            let wallet_birthday = store.meta_u64("birthday").map_err(err)?;
            if b < wallet_birthday {
                store.set_meta("birthday", &b.to_string()).map_err(err)?;
            }
        }
        Ok(AddressPair {
            ye: row.address_ye,
            s: row.address_s,
            path: "imported".into(),
            covered_by_seed: false,
        })
    })
}

/// Sync now, reporting progress on `sink` (Dart: a `Stream<SyncEvent>`), ending with `Done`
/// or `Failed`. The returned error mirrors the `Failed` event.
pub fn sync_now(sink: StreamSink<SyncEvent>) -> Result<(), YewError> {
    let emit = |e: SyncEvent| {
        let _ = sink.add(e);
    };
    let inner = sink.clone();
    let result: Result<sync::SyncReport, YewError> = with_open_async(|o| {
        Box::pin(async move {
            let emit = |e: SyncEvent| {
                let _ = inner.add(e);
            };
            emit(SyncEvent {
                stage: SyncStage::Connecting,
                message: format!("Connecting to {}:{}", o.server.host, o.server.port),
                tip: 0,
                sync_height: 0,
                yellowback_usable: false,
            });
            let network = o.wallet.network;
            if o.conn.is_none() {
                o.conn = Some(connect(&o.server, network).await?);
            }
            let (tip, usable) = {
                let c = o.conn.as_ref().expect("set above");
                (c.tip as i64, c.availability.usable())
            };
            emit(SyncEvent {
                stage: SyncStage::Probing,
                message: if usable {
                    "Yellowback service present".into()
                } else {
                    "No usable Yellowback service: YED hidden".into()
                },
                tip,
                sync_height: 0,
                yellowback_usable: usable,
            });
            emit(SyncEvent {
                stage: SyncStage::Scanning,
                message: "Scanning addresses".into(),
                tip,
                sync_height: 0,
                yellowback_usable: usable,
            });
            o.sync().await
        })
    });
    match result {
        Ok(r) => {
            emit(SyncEvent {
                stage: SyncStage::Done,
                message: format!(
                    "Synced to {}: {} transactions, {} outputs, {} tokens",
                    r.tip, r.transactions, r.utxos, r.tokens
                ),
                tip: r.tip as i64,
                sync_height: r.tip as i64,
                yellowback_usable: r.yellowback,
            });
            Ok(())
        }
        Err(e) => {
            emit(SyncEvent {
                stage: SyncStage::Failed,
                message: e.message.clone(),
                tip: 0,
                sync_height: 0,
                yellowback_usable: false,
            });
            Err(e)
        }
    }
}

// ---- Phase W4: the two-step mint / claim, the vaults ------------------------------------------

fn parse_txid(s: &str) -> Result<[u8; 32], YewError> {
    crate::tx::txid_from_hex(s.trim()).map_err(|m| YewError::new(ErrorKind::Input, m))
}

fn hex_or_empty(txid: &[u8; 32]) -> String {
    if *txid == [0; 32] {
        String::new()
    } else {
        txid_hex(txid)
    }
}

fn mint_status_of(m: &crate::store::MintRow, tip: u64) -> MintStatus {
    use crate::store::MintState as S;
    let open = crate::build::mint::window_open(tip, m.expiry_height);
    let blocks_left = (m.expiry_height as i64)
        .saturating_sub(tip as i64 + 1 + params::TX_EXPIRING_SOON_THRESHOLD as i64)
        .max(0);
    MintStatus {
        mint_id: m.id,
        kind: m.kind.as_str().into(),
        state: m.state.as_str().into(),
        created_height: m.created_height as i64,
        cents: m.cents as i64,
        lock_blocks: m.lock_blocks,
        term_class: m.term_class.clone(),
        ref_height: m.ref_height as i64,
        lock_height: m.lock_height as i64,
        claim_height: m.claim_height as i64,
        expiry_height: m.expiry_height as i64,
        collateral_zat: m.collateral_zat,
        fee_zat: m.fee_zat,
        attest_fee_zat: m.attest_fee_zat,
        residual_zat: m.residual_zat,
        bundle_seqs: m.bundle_seqs.clone(),
        carrier_txid: hex_or_empty(&m.carrier_txid),
        main_txid: hex_or_empty(&m.main_txid),
        sweep_txid: hex_or_empty(&m.sweep_txid),
        vault_txid: hex_or_empty(&m.vault_txid),
        tip: tip as i64,
        in_progress: matches!(m.state, S::CarrierSent | S::CarrierConfirmed | S::MainSent),
        window_open: open,
        blocks_left,
        can_finish: m.state == S::CarrierConfirmed && open,
        can_sweep: m.state == S::Lapsed,
        note: m.note.clone(),
    }
}

fn vault_summary(
    v: &crate::store::VaultRow,
    tip: u64,
    price: Option<i64>,
    network: Network,
) -> VaultSummary {
    let active = v.status == "ACTIVE";
    let void = v.status == "VOID";
    VaultSummary {
        vault_txid: txid_hex(&v.txid),
        status: v.status.clone(),
        owner_address: keys::encode_yellowback(network, &v.owner_hash160),
        term_class: v.term_class.clone(),
        cents: v.minted_cents as i64,
        collateral_zat: v.collateral_zat,
        lock_height: v.lock_height as i64,
        claim_height: v.claim_height as i64,
        mint_height: v.mint_height as i64,
        tip: tip as i64,
        open: v.is_open(),
        redeemable: active && tip >= v.lock_height as u64,
        blocks_until_redeem: (v.lock_height as i64 - tip as i64).max(0),
        releasable: void,
        claimable: v.claimable,
        underwater_at_micro_usd: v.underwater_at,
        underwater: v.is_open()
            && v.underwater_at > 0
            && price.is_some_and(|p| p > 0 && p <= v.underwater_at),
        close_height: v.close_height as i64,
        closing_txid: v.closing_txid.clone(),
        void_reason: v.void_reason.clone(),
    }
}

fn store_err(e: crate::store::StoreError) -> YewError {
    YewError::new(ErrorKind::Other, e.to_string())
}

/// The last synced height (what the store's rows are judged against without a network call).
fn synced_tip(o: &Open) -> Result<u64, YewError> {
    o.wallet
        .store
        .meta_u64("last_synced_height")
        .map_err(store_err)
}

fn row_status(o: &Open, id: i64) -> Result<MintStatus, YewError> {
    let m = o
        .wallet
        .store
        .mint(id)
        .map_err(store_err)?
        .ok_or_else(|| YewError::new(ErrorKind::Input, format!("no mint with id {id}")))?;
    Ok(mint_status_of(&m, synced_tip(o)?))
}

/// The mint estimate (after a sync): collateral, fees, heights, term class, attestor seqs.
/// Nothing is signed.
pub fn mint_estimate(cents: i64, lock_blocks: u32) -> Result<MintEstimate, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            if cents <= 0 {
                return Err(YewError::new(
                    ErrorKind::Input,
                    "Enter an amount in dollars to mint.",
                ));
            }
            o.sync().await?;
            let Open { wallet, conn, .. } = o;
            let conn = conn.as_mut().expect("connected");
            let e = wallet
                .mint_estimate(&mut conn.validator, cents as u64, lock_blocks)
                .await?;
            Ok(MintEstimate {
                cents: e.cents as i64,
                lock_blocks: e.lock_blocks,
                term_class: e.term_class.clone(),
                ref_height: e.ref_height as i64,
                lock_height: e.lock_height as i64,
                claim_height: e.claim_height as i64,
                expiry_height: e.ref_height as i64 + params::REF_WINDOW as i64,
                required_zat: e.required_zat,
                collateral_zat: e.collateral_zat,
                fee_zat: e.fee_zat,
                attest_fee_zat: e.attest_fee_zat,
                carrier_zat: params::CARRIER_VALUE,
                token_zat: params::TOKEN_VALUE,
                network_fee_zat: 2 * params::FEE_ZAT,
                total_zat: e.total_zat,
                available_zat: e.available_zat,
                affordable: e.affordable(),
                p_mint_micro_usd: if e.p_mint > 0 { Some(e.p_mint) } else { None },
                armed: e.armed,
                bundle_seqs: e.bundle_seqs.iter().map(|s| *s as u32).collect(),
            })
        })
    })
}

/// Start a mint (after a sync): verify the bundle, fund the carrier through the gate, record
/// the row. Returns the row (`CARRIER_SENT`); [`mint_finish`] sends the MINT once a sync has
/// seen the carrier confirm.
pub fn mint_start(cents: i64, lock_blocks: u32) -> Result<MintStatus, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            if cents <= 0 {
                return Err(YewError::new(
                    ErrorKind::Input,
                    "Enter an amount in dollars to mint.",
                ));
            }
            let r = o.sync().await?;
            let id = {
                let Open { wallet, conn, .. } = &mut *o;
                let conn = conn.as_mut().expect("connected");
                wallet
                    .mint_start(
                        &mut conn.compact,
                        &mut conn.validator,
                        cents as u64,
                        lock_blocks,
                        r.tip,
                        r.branch_id,
                    )
                    .await?
            };
            row_status(o, id)
        })
    })
}

/// One row of the two-step table (no network; heights judged at the last synced height).
pub fn mint_status(mint_id: i64) -> Result<MintStatus, YewError> {
    with_open(|o| row_status(o, mint_id))
}

/// Every two-step row (mints and claims), oldest first (no network).
pub fn mints() -> Result<Vec<MintStatus>, YewError> {
    with_open(|o| {
        let tip = synced_tip(o)?;
        Ok(o.wallet
            .mints()?
            .iter()
            .map(|m| mint_status_of(m, tip))
            .collect())
    })
}

/// Send the MINT (or, for a claim row, the CLAIM) over the confirmed carrier (after a sync;
/// both gate layers). The row must be `CARRIER_CONFIRMED` with the window open; a lapsed
/// row is refused with `carrier-lapsed`. Returns the row (`MAIN_SENT`).
pub fn mint_finish(mint_id: i64) -> Result<MintStatus, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            let r = o.sync().await?;
            {
                let Open { wallet, conn, .. } = &mut *o;
                let conn = conn.as_mut().expect("connected");
                wallet
                    .mint_finish(
                        &mut conn.compact,
                        &mut conn.validator,
                        mint_id,
                        r.tip,
                        r.branch_id,
                    )
                    .await?;
            }
            row_status(o, mint_id)
        })
    })
}

/// Sweep the carrier of a `LAPSED` row (`CARRIER_VALUE − fee` back to the wallet; after a
/// sync; both gate layers). Returns the row (`SWEEP_SENT`).
pub fn mint_sweep(mint_id: i64) -> Result<MintStatus, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            let r = o.sync().await?;
            {
                let Open { wallet, conn, .. } = &mut *o;
                let conn = conn.as_mut().expect("connected");
                wallet
                    .mint_sweep(
                        &mut conn.compact,
                        &mut conn.validator,
                        mint_id,
                        r.tip,
                        r.branch_id,
                    )
                    .await?;
            }
            row_status(o, mint_id)
        })
    })
}

/// The vaults this wallet owns, as the last sync left them (no network).
pub fn vaults() -> Result<Vec<VaultSummary>, YewError> {
    with_open(|o| {
        let tip = synced_tip(o)?;
        let price = o.wallet.balances()?.price_micro_usd;
        let network = o.wallet.network;
        Ok(o.wallet
            .vaults()?
            .iter()
            .map(|v| vault_summary(v, tip, price, network))
            .collect())
    })
}

/// Redeem an own `ACTIVE` vault at or past `lockHeight` (burning its debt from the wallet's
/// YED), or release a `VOID` one (after a sync; both gate layers, the planned burn known to
/// the remote layer).
pub fn redeem(vault_txid: String) -> Result<RedeemResult, YewError> {
    let txid = parse_txid(&vault_txid)?;
    with_open_async(|o| {
        Box::pin(async move {
            let r = o.sync().await?;
            let Open { wallet, conn, .. } = o;
            let conn = conn.as_mut().expect("connected");
            let (sent, v, p) = wallet
                .redeem(
                    &mut conn.compact,
                    &mut conn.validator,
                    &txid,
                    r.tip,
                    r.branch_id,
                )
                .await?;
            Ok(RedeemResult {
                txid: sent,
                verdict: v.verdict,
                kind: p.kind.into(),
                burn_cents: p.burn_cents as i64,
                extra_burn_cents: p.extra_burn_cents as i64,
                change_cents: p.change_cents as i64,
                fee_zat: p.fee_zat,
                collateral_zat: p.collateral_out,
                collateral_address: p.collateral_address,
                lock_time: p.lock_time as i64,
                expiry_height: p.expiry_height as i64,
            })
        })
    })
}

/// `ListClaimable` at the node's tip (connects; the liquidator persona).
pub fn claimable() -> Result<Vec<ClaimableItem>, YewError> {
    with_open_async(|o| {
        Box::pin(async move {
            ensure_conn(o).await?;
            let Open { wallet, conn, .. } = o;
            let conn = conn.as_mut().expect("connected");
            Ok(wallet
                .claimable(&mut conn.validator)
                .await?
                .into_iter()
                .map(|c| ClaimableItem {
                    vault_txid: c.vault_txid,
                    owner_address: c.owner_address,
                    cents: c.minted_cents as i64,
                    collateral_zat: c.collateral_zat,
                    claim_height: c.claim_height as i64,
                    claim_path: c.claim_path,
                    p_claim_micro_usd: c.p_claim,
                    fee_zat: c.fee_zat,
                    attest_fee_zat: c.attest_fee_zat,
                    residual_zat: c.residual_zat,
                    claimant_zat: c.claimant_zat,
                })
                .collect())
        })
    })
}

/// Start a claim of another wallet's claimable vault (after a sync): the bundle, the carrier
/// through the gate, a row of kind `claim`. Returns the row; [`mint_finish`] sends the CLAIM
/// once the carrier is confirmed.
pub fn claim(vault_txid: String) -> Result<MintStatus, YewError> {
    let txid = parse_txid(&vault_txid)?;
    with_open_async(|o| {
        Box::pin(async move {
            let r = o.sync().await?;
            let id = {
                let Open { wallet, conn, .. } = &mut *o;
                let conn = conn.as_mut().expect("connected");
                wallet
                    .claim(
                        &mut conn.compact,
                        &mut conn.validator,
                        &txid,
                        r.tip,
                        r.branch_id,
                    )
                    .await?
            };
            row_status(o, id)
        })
    })
}

/// `N.NNNNNNNN` for zat (no unit).
fn format_yec(zat: i64) -> String {
    format!("{}.{:08}", zat / 100_000_000, (zat % 100_000_000).abs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn tmp_dir(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("yew-api-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    #[test]
    fn locked_and_stubs_and_lifecycle() {
        lock();
        assert!(!is_unlocked());
        assert_eq!(balances().unwrap_err().kind, ErrorKind::Locked);
        assert_eq!(receive_address(false).unwrap_err().kind, ErrorKind::Locked);
        assert_eq!(history(0, 10).unwrap_err().kind, ErrorKind::Locked);
        assert_eq!(mint_estimate(100, 10).unwrap_err().kind, ErrorKind::Locked);
        assert_eq!(vaults().unwrap_err().kind, ErrorKind::Locked);
        assert_eq!(mints().unwrap_err().kind, ErrorKind::Locked);
        // A malformed vault txid is refused before the wallet is looked at.
        assert_eq!(claim("x".into()).unwrap_err().kind, ErrorKind::Input);
        assert_eq!(redeem("zz".into()).unwrap_err().kind, ErrorKind::Input);

        // A plain connection is refused on mainnet before anything is opened.
        let e = unlock(
            PHRASE.into(),
            String::new(),
            NetworkId::Mainnet,
            "127.0.0.1:1".into(),
            true,
            tmp_dir("main"),
        )
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Input);

        let dir = tmp_dir("regtest");
        let c = create_wallet(
            None,
            String::new(),
            Some(5),
            NetworkId::Regtest,
            "127.0.0.1:1".into(),
            true,
            dir.clone(),
        )
        .unwrap();
        let words = c
            .seed_words
            .clone()
            .expect("generated words are returned once");
        assert_eq!(words.split_whitespace().count(), 12);
        assert!(c.address_ye.starts_with("yr"));
        assert!(is_unlocked());
        let again = create_wallet(
            None,
            String::new(),
            None,
            NetworkId::Regtest,
            "127.0.0.1:1".into(),
            true,
            dir.clone(),
        )
        .unwrap_err();
        assert_eq!(again.kind, ErrorKind::AlreadyOpen);

        let b = balances().unwrap();
        assert_eq!(b.yed_cents, 0);
        assert_eq!(b.yed_send_min_zat, 21_000);
        let a = receive_address(false).unwrap();
        assert_eq!(a.ye, c.address_ye);
        assert!(a.s.starts_with("sm"));
        assert_eq!(a.path, "m/44'/347'/0'/0/0");
        let e = export_wif(a.ye.clone()).unwrap();
        assert_eq!(e.address_s, a.s);
        assert!(e.covered_by_seed);
        let foreign = keys::AddressKey::from_secret(
            secp256k1::SecretKey::from_secret_bytes([9u8; 32]).unwrap(),
        );
        let imported = import_wif(foreign.wif(Network::Regtest), Some(2)).unwrap();
        assert!(!imported.covered_by_seed);
        assert_eq!(addresses().unwrap().len(), 41);
        assert!(history(0, 0).unwrap().rows.is_empty());
        // W4, no network: an empty table, an empty vault list, an unknown row id.
        assert!(mints().unwrap().is_empty());
        assert!(vaults().unwrap().is_empty());
        assert_eq!(mint_status(7).unwrap_err().kind, ErrorKind::Input);
        assert_eq!(mint_estimate(0, 10).unwrap_err().kind, ErrorKind::Input);
        assert_eq!(
            send_yec_confirm("nope".into()).unwrap_err().kind,
            ErrorKind::PreviewExpired
        );
        // No server behind 127.0.0.1:1: the network error surfaces as such.
        assert_eq!(status().unwrap_err().kind, ErrorKind::Network);

        lock();
        assert!(!is_unlocked());
        // Reopen with the same words, a different seed is refused by the file.
        let id = unlock(
            words,
            String::new(),
            NetworkId::Regtest,
            "127.0.0.1:1".into(),
            true,
            dir.clone(),
        )
        .unwrap();
        assert_eq!(id, c.wallet_id);
        lock();
        let e = unlock(
            PHRASE.into(),
            String::new(),
            NetworkId::Regtest,
            "127.0.0.1:1".into(),
            true,
            dir,
        )
        .unwrap_err();
        assert!(e.message.contains("another seed"), "{e}");
        lock();
    }

    #[test]
    fn w4_rows_map_to_screen_flags() {
        use crate::store::{MintKind, MintRow, MintState, VaultRow};
        let row = MintRow {
            id: 3,
            kind: MintKind::Mint,
            state: MintState::CarrierConfirmed,
            created_height: 500,
            cents: 25_000,
            lock_blocks: 20,
            term_class: "A".into(),
            ref_height: 498,
            lock_height: 518,
            claim_height: 538,
            collateral_zat: 950_000_000,
            fee_zat: 1_000,
            payee: String::new(),
            attest_fee_zat: 0,
            attest_payee: String::new(),
            residual_zat: 0,
            bundle: vec![],
            bundle_seqs: "0,1".into(),
            carrier_hash160: [1; 20],
            owner_hash160: [2; 20],
            carrier_txid: [0xab; 32],
            carrier_vout: 0,
            main_txid: [0; 32],
            sweep_txid: [0; 32],
            expiry_height: 538,
            vault_txid: [0; 32],
            owner_pubkey: vec![],
            note: String::new(),
        };
        // Window open at tip 500: 500 + 1 + 3 <= 538, 34 blocks left; finish allowed.
        let s = mint_status_of(&row, 500);
        assert_eq!(
            (s.mint_id, s.kind.as_str(), s.state.as_str()),
            (3, "mint", "CARRIER_CONFIRMED")
        );
        assert!(s.in_progress && s.window_open && s.can_finish && !s.can_sweep);
        assert_eq!(s.blocks_left, 34);
        assert_eq!(s.carrier_txid, txid_hex(&[0xab; 32]));
        assert!(s.main_txid.is_empty() && s.vault_txid.is_empty());
        // The window closes at 535 (`CheckExpiry`): no finish, nothing to sweep yet either
        // (the sync loop marks the row LAPSED, the API never guesses).
        let s = mint_status_of(&row, 535);
        assert!(!s.window_open && !s.can_finish && s.blocks_left == 0 && !s.can_sweep);
        let lapsed = MintRow {
            state: MintState::Lapsed,
            ..row.clone()
        };
        let s = mint_status_of(&lapsed, 540);
        assert!(s.can_sweep && !s.in_progress);
        let done = MintRow {
            state: MintState::Done,
            main_txid: [0xcd; 32],
            ..row
        };
        let s = mint_status_of(&done, 540);
        assert!(!s.in_progress && !s.can_finish && s.main_txid == txid_hex(&[0xcd; 32]));

        let vault = VaultRow {
            txid: [0xef; 32],
            vout: 0,
            status: "ACTIVE".into(),
            owner_hash160: [2; 20],
            owner_pubkey: [3; 33],
            term_class: "A".into(),
            lock_height: 518,
            claim_height: 538,
            collateral_zat: 950_000_000,
            minted_cents: 25_000,
            mint_height: 501,
            claimable: false,
            underwater_at: 400_000,
            sweep_before: 0,
            close_height: 0,
            closing_txid: String::new(),
            void_reason: String::new(),
            updated_height: 510,
        };
        let v = vault_summary(&vault, 510, Some(520_000), Network::Regtest);
        assert!(v.open && !v.redeemable && !v.releasable && !v.underwater);
        assert_eq!(v.blocks_until_redeem, 8);
        assert_eq!(v.cents, 25_000);
        assert_eq!(
            v.owner_address,
            keys::encode_yellowback(Network::Regtest, &[2; 20])
        );
        let v = vault_summary(&vault, 518, Some(390_000), Network::Regtest);
        assert!(v.redeemable && v.underwater && v.blocks_until_redeem == 0);
        let void = VaultRow {
            status: "VOID".into(),
            void_reason: "abandoned".into(),
            ..vault.clone()
        };
        let v = vault_summary(&void, 510, None, Network::Regtest);
        assert!(v.open && v.releasable && !v.redeemable && !v.underwater);
        let closed = VaultRow {
            status: "CLOSED".into(),
            close_height: 520,
            ..vault
        };
        let v = vault_summary(&closed, 530, Some(100_000), Network::Regtest);
        assert!(!v.open && !v.redeemable && !v.underwater && v.close_height == 520);
    }

    #[test]
    fn sync_checks() {
        assert!(check_seed_words(PHRASE.into()).is_ok());
        assert_eq!(
            check_seed_words("abandon x".into()).unwrap_err().kind,
            ErrorKind::Input
        );
        assert_eq!(
            generate_seed_words(24).unwrap().split_whitespace().count(),
            24
        );
        let ok = validate_address(
            NetworkId::Regtest,
            keys::encode_yellowback(Network::Regtest, &[1; 20]),
        );
        assert!(ok.valid && ok.yellowback_form && ok.kind == "p2pkh");
        let bad = validate_address(NetworkId::Regtest, "ye-not-an-address".into());
        assert!(!bad.valid && !bad.message.is_empty());
        assert_eq!(format_yec(21_000), "0.00021000");
        assert!(!core_version().is_empty());
    }
}
