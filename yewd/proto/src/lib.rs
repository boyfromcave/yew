// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The façade↔signer protocol (workspace plan `docs/plans/kogany/kogany-yellowback-plan.md` §3b S2,
//! decision K-24), version [`PROTO_VERSION`].
//!
//! **The rule the types encode:** the signer is shown the **unsigned transaction bytes and every
//! spent prevout** (script and amount), and recomputes every digest itself: the ZIP-243 sighash of
//! each input it signs, the set-signature message of a vault spend, the act message of a `YV` act.
//! No field carries a digest for the signer to sign blindly. Every key the signer is asked to use
//! is named by its derivation ([`KeyRef`]) and checked against the script it is to spend, so a
//! request the signer cannot bind to a prevout and an amount is refused, never signed.
//!
//! **Transport.** One JSON object per line over a Unix-domain socket (`<datadir>/<net>/signer/
//! signer.sock`, mode 0600, the peer's UID checked by the signer): a [`Envelope`] request, a
//! [`Response`] answer, in order; a connection may carry many requests. A version other than
//! [`PROTO_VERSION`] is refused (`bad-version`) before the request is read further.
//!
//! **S1's public bundle** ([`PublicBundle`], [`PublicRequest`]) is unchanged: the façade holds
//! public material only (K-24, plan §4.3 rule 2).

pub mod act;
pub mod attest;
pub mod client;
pub mod preview;

use serde::{Deserialize, Serialize};

// Review YEW-PORT-5 R1: the refusal codes and the Sapling part's wire types live in yew-core
// (the hybrid builder moves there, R3); re-exported here, the wire format unchanged.
pub use yew_core::refuse;
pub use yew_core::sapling_part::{SaplingOut, SaplingPart, SaplingSpend};

/// The protocol version every request names; a signer refuses any other (S1 was version 0: the
/// child-process `init`/`public` commands, which version 1 keeps).
pub const PROTO_VERSION: u32 = 1;

/// One spent output, as the signer needs it to recompute the ZIP-243 digest and the outflow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prevout {
    /// `txid:n` (the display txid).
    pub outpoint: String,
    /// The spent output's `scriptPubKey`, hex.
    pub script: String,
    /// Its value in zatoshi.
    pub amount_zat: i64,
}

/// A key of the signer's seed, named by its derivation. The signer derives it and checks it
/// against the script it is asked to spend or to recognise: a reference that does not own the
/// script is refused (`key-mismatch`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyRef {
    /// Not the signer's input: a foreign input, or a template input whose scriptSig (set
    /// signatures, a selector) the façade already placed and the signer keeps as it is.
    None,
    /// The BIP32 key `m/44'/347'/0'/chain/index` (P2PKH; also a set member or admit key).
    /// `chain` [`IMPORTED_CHAIN`] names the signer's imported key `index` instead
    /// (`importprivkey`, S3): not a derivation, an entry of the signer's key store.
    Bip32 { chain: u32, index: u32 },
    /// The post-quantum key `DerivePQSeed(seed, scheme, index)` (`TX_PQPKH`).
    Pq { scheme: u8, index: u32 },
    /// The same key as a vault or intent **owner**: the V selector 2 (owner) or 3
    /// (owner-released), or the I selector 3 (quantum spec §1.5).
    PqOwner {
        scheme: u8,
        index: u32,
        selector: u8,
    },
    /// The BIP32 key of a v3 **carrier** `P2SH(carrierScript(pk, SHA256(bundle)))` (W7): the input
    /// carries the bundle ([`SignInput::carrier_bundle`]), which the signer hashes into the
    /// redeem script it checks the prevout against and pushes into the scriptSig.
    Carrier { chain: u32, index: u32 },
    /// The key of an attestor or set-member **bond** `P2SH(<locktime> CLTV DROP <pk> CHECKSIG)`
    /// (`yed_withdrawbond`, S3): the signer rebuilds the redeem script from the key and the
    /// locktime, checks the prevout against it and signs the CLTV path (`<sig> <redeem>`).
    Bond {
        chain: u32,
        index: u32,
        locktime: u32,
    },
}

/// The `chain` of a [`KeyRef::Bip32`] that names an imported key (`importprivkey`).
pub const IMPORTED_CHAIN: u32 = 2;

/// A [`KeyRef::Pq`] index at or above this names the signer's imported post-quantum key
/// `index - IMPORTED_PQ_BASE` (`z_importpqkey`, a dump's `pqseed=` lines; S4), never a derivation.
pub const IMPORTED_PQ_BASE: u32 = 0x8000_0000;

/// One transaction input as the signer sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInput {
    /// The output it spends: must name `vin[i].prevout`.
    pub prevout: Prevout,
    /// The key that signs it ([`KeyRef::None`]: not signed here).
    pub key: KeyRef,
    /// The attestation bundle of a [`KeyRef::Carrier`] input, hex (possibly empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_bundle: Option<String>,
}

/// An output the façade says pays the wallet: the signer checks the key owns the script, and
/// counts the value against the outflow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnOutput {
    pub n: u32,
    pub key: KeyRef,
    /// A `SET_JOIN` bond `P2SH(<locktime> CLTV DROP <memberkey> CHECKSIG)` of the member key
    /// [`OwnOutput::key`] (ycash6 `HandoffSend` counts it as the wallet's own).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_locktime: Option<u32>,
}

/// One input of a [`Preview`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewCoin {
    pub vin: u32,
    pub outpoint: String,
    pub amount_zat: i64,
}

/// One output of a [`Preview`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewOutput {
    pub n: u32,
    pub amount_zat: i64,
    /// The output's address when it has one (`s…`, `sq…`, P2SH), else `None` and [`Self::script`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The script, hex, when there is no address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    pub mine: bool,
    /// `payment`, `vault`, `intent`, `act`, `bond`, `data` (ycash6 `OutputKind`, plus `data` for a
    /// non-act `OP_RETURN`).
    pub kind: String,
}

/// The `HandoffPreview` of `ycash6/doc/vault-rpc.md` "Shapes", in zatoshi: what a human or a
/// device is shown, and what the signer recomputes from the bytes and refuses on any difference
/// (`preview-mismatch`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preview {
    /// The inputs the signer is asked to sign (every input with a key).
    pub sign: Vec<PreviewCoin>,
    pub outputs: Vec<PreviewOutput>,
    /// Inputs minus outputs (every prevout is known to the signer, so it is never absent).
    pub fee_zat: i64,
    /// The signed inputs minus the wallet's own outputs.
    pub outflow_zat: i64,
}

/// The broadcast-gate path (yew-core `gate.rs`, plus the vault primitive's) the signer checks the
/// inputs and outputs against before it signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatePath {
    /// A plain YEC payment (`sendtoaddress`, `sendmany`, a split): P2PKH / PQ inputs only, no
    /// template input, no data output.
    Yec,
    /// A vault primitive build (`vault_lock`, `vault_release`, `vault_send`, the act RPCs, …):
    /// at most one template input, never signed with a key (its scriptSig is the façade's).
    Vault,
    /// An owner spend of a V or I (`vault_ownerspend`, YED redeem's owner path): input 0 is the
    /// template, signed by its owner key ([`KeyRef::PqOwner`]).
    Owner,
    /// A YED transaction (`yed_send`, mint, redeem, claim): its payload is checked by the node
    /// (`yed_validaterawtransaction`) before broadcast; the signer checks the prevouts and the
    /// outflow.
    Yed,
    /// `signrawtransaction`: the caller's transaction, signed where the wallet's keys own a
    /// prevout. The cap is the caller's own statement (`outflow_cap_zat`).
    Raw,
}

/// A request to sign the transparent inputs of one transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// The transaction, hex: its inputs' scriptSigs are empty except where [`KeyRef::None`]
    /// keeps one (a template input, a foreign input already signed).
    pub tx: String,
    /// The consensus branch ID of the next block (ZIP-243 binds it).
    pub branch_id: u32,
    /// Exactly one per input, in input order.
    pub inputs: Vec<SignInput>,
    /// The outputs that pay the wallet.
    pub own_outputs: Vec<OwnOutput>,
    pub gate_path: GatePath,
    /// The largest net outflow the caller allows, in zatoshi.
    pub outflow_cap_zat: i64,
    pub preview: Preview,
    /// A Sapling part built with the transparent one (S4, F-S2-8: a YED transaction funded from
    /// or paying a Sapling address): the signer builds, proves and authorizes it, and every
    /// transparent digest covers it (ZIP-243's `hashShieldedSpends` / `hashShieldedOutputs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sapling: Option<SaplingPart>,
}

/// The whole transaction signed. Never half-signed (H10): every input with a key is signed, or
/// the request is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub tx: String,
    /// The ZIP-243 digest the signer signed for each input (`None` where it signed nothing).
    pub sighashes: Vec<Option<String>>,
}

/// A request for act signatures (`set_signact`, `set_join`, `set_heartbeat`, `set_leave`): the
/// signer decodes the act from the transaction's `YV` output, recomputes
/// `SHA256d("YcashSetAct" ‖ P ‖ vin[0].prevout)` and signs it with each key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActSignRequest {
    pub tx: String,
    /// The keys to add, in order (member keys and admit keys are BIP32 keys of the seed).
    pub keys: Vec<KeyRef>,
}

/// The act signatures, in request order: 65-byte recoverable compact signatures, hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActSigs {
    /// The payload `P` the signatures bind, hex.
    pub payload: String,
    pub msg: String,
    pub sigs: Vec<String>,
}

/// A request for set signatures over a vault spend (`set_signunlock`, `set_signcancel`): the
/// signer recomputes the ZIP-243 `SIGHASH_ALL|ANYONECANPAY` sighash of the template input from the
/// bytes and the template prevout, the set-signature message
/// `SHA256d("YcashSetSig" ‖ setId ‖ role ‖ prevout ‖ sighash)`, checks and writes its sign-once
/// record for `(setid, prevout)`, then signs it with each key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSignRequest {
    pub tx: String,
    pub branch_id: u32,
    /// The template input's index.
    pub index: u32,
    /// The template coin (a V for role 1, an I for role 2).
    pub prevout: Prevout,
    /// The set: the V's `setid` (role 1) or the I's `cancelsetid` (role 2); the signer checks it
    /// against the template.
    pub set_id: String,
    /// 1 unlock, 2 cancel.
    pub role: u8,
    /// The member keys to sign with (current members of the set, by the façade's reading of the
    /// set state).
    pub keys: Vec<KeyRef>,
    /// `{"acknowledgerestore": true}`: sign a prevout without a record while the restore marker
    /// is set (07/F-5).
    pub acknowledge_restore: bool,
}

/// The set signatures, in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSigs {
    /// The sighash, raw order hex (what `set_signunlock` reports).
    pub sighash: String,
    pub msg: String,
    pub sigs: Vec<String>,
}

/// One sign-once record (`set_listsigned`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignedRecord {
    /// Display hex.
    pub setid: String,
    /// `txid:n`.
    pub prevout: String,
    pub role: u8,
    /// Raw order hex.
    pub sighash: String,
}

/// The signer's sign-once records and its restore marker.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecords {
    pub restored: bool,
    pub records: Vec<SignedRecord>,
    /// Imported keys that were no set member when imported, watched for a `SET_JOIN` (07/F-5
    /// review S3; ycashd's `setVaultPendingKeys`): `set_acknowledgerestore`'s `pendingkeys`.
    #[serde(default)]
    pub pending: u32,
}

/// `set_importsigned`'s answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Imported {
    pub imported: u32,
    pub present: u32,
}

/// A price attestation (`yed_signattestation`, `yed_revive`; S3): the signer derives the key,
/// checks it is `pubkey` (the attestor record's key, from the node), recomputes `AttestMessage`
/// and passes the **equivocation guard** (`attest-signed`) before it signs: a second price for one
/// `(key, citedHeight, blockHash)` is refused, the same price returns the recorded signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestRequest {
    pub key: KeyRef,
    /// The attestor key the record names, hex (33 bytes).
    pub pubkey: String,
    pub seq: u16,
    pub price_micro_usd: u32,
    pub cited_height: u32,
    /// The block hash at `cited_height` (display hex).
    pub block_hash: String,
}

/// A signed (or recalled) attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestSigned {
    /// The 74 bytes, hex.
    pub hex: String,
    /// The guard already held this price for this height: the recorded signature.
    pub reused: bool,
}

/// A cancel co-signature (`yed_signcancelcosign`, S3): the member's price statement at the
/// claim's `R`, locked through the equivocation guard, then the recoverable signature over
/// `CancelCosignMessage`. The signer refuses a statement under which the vault was claimable
/// (`cancel-statement-claimable`), so it never signs a cancel of an honest claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosignRequest {
    pub key: KeyRef,
    pub pubkey: String,
    pub seq: u16,
    /// The attestor set (display hex).
    pub set_id: String,
    /// The claimant intent, `txid:n`.
    pub intent: String,
    pub ref_height: u32,
    /// The block hash at `ref_height` (display hex).
    pub block_hash: String,
    /// The price stated; `None`: the price this key already signed for `ref_height`.
    pub price_micro_usd: Option<u32>,
    /// The vault the claim spent, as the cancel is judged against it.
    pub collateral_zat: i64,
    pub minted_cents: i64,
    pub claim_threshold_bps: i64,
}

/// A co-signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosigned {
    /// The 69 bytes `price_le32 ‖ sig65`, hex.
    pub cosig: String,
    pub price_micro_usd: u32,
    pub reused: bool,
}

/// `signmessage` (S3): the signer computes the message digest itself (the magic prefix, so a
/// message can never be a transaction digest) and signs it recoverably.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRequest {
    pub key: KeyRef,
    pub message: String,
}

/// `importprivkey`: a WIF of this network into the signer's key store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportKeyRequest {
    pub wif: String,
    /// The hash160s (hex) of every set member key at the tip, as the façade read them
    /// (`set_list`, `set_getinfo`): a new key among them sets the restore marker, any other new
    /// key is kept pending until its `SET_JOIN` connects ([`Request::JoinsSeen`]; ycashd's
    /// `MarkVaultKeyImported`). `None` (not read): the marker is set, as for a member.
    #[serde(default)]
    pub members: Option<Vec<String>>,
}

/// The imported key's place in the store ([`KeyRef::Bip32`] with [`IMPORTED_CHAIN`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedKey {
    pub index: u32,
    pub pubkey: String,
    /// `false`: the store already held it.
    pub new: bool,
}

/// One line of a wallet dump (`z_exportwallet`, S4): the façade writes the public text, the
/// signer puts each secret in (§4.3 rule 2: "a dump is produced by the signer").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DumpLine {
    /// Written as is.
    Text { text: String },
    /// `<WIF of key> <rest>`.
    Key { key: KeyRef, rest: String },
    /// `pqseed=<scheme>:<index>:<seed hex> <rest>` (an imported key: index as `index_text`).
    PqSeed {
        scheme: u8,
        index: u32,
        index_text: String,
        rest: String,
    },
    /// `<the Sapling account's extended spending key> <rest>`.
    Sapling { rest: String },
    /// `# - recovery_phrase="<phrase>"`.
    Recovery,
}

/// `z_exportwallet`: write `lines` to `path` (which must not exist).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpRequest {
    pub path: String,
    pub lines: Vec<DumpLine>,
}

/// `importwallet` / `z_importwallet`: read the dump at `path`; the signer keeps its secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDumpRequest {
    pub path: String,
    /// `z_importwallet`: the Sapling key lines too.
    pub zkeys: bool,
    /// As [`ImportKeyRequest::members`], for the dump's new transparent keys.
    #[serde(default)]
    pub members: Option<Vec<String>>,
}

/// What an import added, public parts only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDumpResult {
    /// Transparent keys: the store entry and the line's label (`label=`; `None` for reserve/change).
    pub keys: Vec<(ImportedKey, Option<String>)>,
    pub pq: Vec<PqImported>,
    /// `vaultbuild=<txid>:<n>:<hex>` lines: (outpoint, hex).
    pub builds: Vec<(String, String)>,
    /// `vaultrecipient=<hash>:<script>` lines.
    pub recipients: Vec<(String, String)>,
    /// `vaultsetsig=` records imported into the sign-once store.
    pub records: usize,
    /// Sapling key lines this signer could not import (another account's spending key).
    pub skipped_zkeys: usize,
}

/// `z_importpqkey`: one post-quantum key from its keygen seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqImportRequest {
    pub scheme: u8,
    /// The HD index the caller claims (`<scheme>:<index>:<seed>`), if any.
    pub index: Option<u32>,
    /// 48 bytes, hex.
    pub seed: String,
}

/// An imported post-quantum key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqImported {
    pub scheme: u8,
    /// Its own derivation index when it is this seed's key, else `IMPORTED_PQ_BASE + store index`.
    pub index: u32,
    /// Whether it is this seed's own key at `index`.
    pub own: bool,
    pub pk: String,
    /// `false`: already held.
    pub added: bool,
}

/// `backupwallet`: write a backup of the signer's files and the façade's state to `path`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupRequest {
    pub path: String,
    /// The façade's `wallet.json` text (public material).
    pub facade: String,
}

/// A transparent input of a Sapling-capable build: a wallet P2PKH coin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaplingTInput {
    pub prevout: Prevout,
    pub key: KeyRef,
}

/// `z_sendmany` (S4): the whole build in the signer (K-24: the spending key never leaves it):
/// transparent P2PKH inputs, Sapling spends with their paths, the outputs, the exact fee; the
/// signer proves, signs and returns the transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaplingBuildRequest {
    /// The height the transaction is for (its branch: the Vault branch from `vault_height`).
    pub target_height: u32,
    pub expiry_height: u32,
    /// Regtest's vault activation height (`-nuparams=6d5b7a31:<h>`), if any.
    pub vault_height: Option<u32>,
    pub inputs: Vec<SaplingTInput>,
    pub spends: Vec<SaplingSpend>,
    pub outputs: Vec<SaplingOut>,
    pub fee_zat: i64,
    /// The Sapling anchor (the root the spends' paths lead to), 32 bytes hex; empty without spends.
    pub anchor: String,
    /// Inputs minus the own outputs may not exceed this (the payment and its fee).
    pub outflow_cap_zat: i64,
    /// The directory holding `sapling-spend.params` and `sapling-output.params`.
    pub params_dir: String,
}

/// The backup file's format tag.
pub const BACKUP_FORMAT: &str = "yewd-backup-1";

/// Whether `path` holds a yewd backup (its format tag), and the SHA-256 of its bytes (hex).
pub fn backup_digest(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    if v["format"].as_str() != Some(BACKUP_FORMAT) {
        return None;
    }
    Some(hex::encode(yew_core::keys::sha256(&bytes)))
}

/// What the signer says about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub network: String,
    pub seed_fp: String,
    /// The wallet is encrypted (`encryptwallet`, S4).
    #[serde(default)]
    pub encrypted: bool,
    /// Unix time the unlock lasts until; 0 while locked (or never encrypted).
    #[serde(default)]
    pub unlocked_until: i64,
}

/// `encryptwallet` (S4): seal the seed under `passphrase`; `pq` names the post-quantum public
/// keys the façade holds, which the signer caches so a locked signer can still answer `public`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub passphrase: String,
    #[serde(default)]
    pub pq: Vec<(u8, u32, u32)>,
}

/// `walletpassphrase` (S4): unlock for `timeout` seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockRequest {
    pub passphrase: String,
    pub timeout: i64,
}

/// The encryption state after `encrypt`, `unlock` or `lock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletState {
    pub encrypted: bool,
    pub unlocked_until: i64,
}

/// A request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "body", rename_all = "snake_case")]
pub enum Request {
    Hello,
    Public(PublicRequest),
    Sign(SignRequest),
    SignAct(ActSignRequest),
    SignSet(SetSignRequest),
    ListSigned,
    ImportSigned(Vec<SignedRecord>),
    AcknowledgeRestore,
    SignAttestation(AttestRequest),
    CancelCosign(CosignRequest),
    SignMessage(MessageRequest),
    ImportKey(ImportKeyRequest),
    /// `dumpprivkey`: the WIF of a transparent key (the dump is the signer's, §4.3 rule 2).
    DumpKey(KeyRef),
    /// `encryptwallet` (S4).
    Encrypt(EncryptRequest),
    /// `walletpassphrase` (S4).
    Unlock(UnlockRequest),
    /// `walletlock` (S4).
    Lock,
    /// `z_exportwallet` (S4).
    Dump(DumpRequest),
    /// `importwallet`, `z_importwallet` (S4).
    ImportDump(ImportDumpRequest),
    /// `z_importpqkey` (S4).
    ImportPq(PqImportRequest),
    /// `backupwallet` (S4).
    Backup(BackupRequest),
    /// `z_sendmany` (S4).
    SaplingBuild(SaplingBuildRequest),
    /// The hash160s (hex) of member keys whose `SET_JOIN` connected in a block the wallet read:
    /// a pending imported key among them sets the restore marker (ycashd's `VaultCheckJoins`).
    /// Answered with [`Response::Acknowledged`].
    JoinsSeen(Vec<String>),
}

/// A request with its protocol version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u32,
    #[serde(flatten)]
    pub request: Request,
}

impl Envelope {
    pub fn new(request: Request) -> Envelope {
        Envelope {
            version: PROTO_VERSION,
            request,
        }
    }
}

/// Why the signer refused. `code` is stable (the façade maps it to ycashd's RPC error); `reason`
/// is for the operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub code: String,
    pub reason: String,
}

/// An answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "body", rename_all = "snake_case")]
pub enum Response {
    Hello(Hello),
    Public(PublicBundle),
    Signed(Signed),
    ActSigs(ActSigs),
    SetSigs(SetSigs),
    Records(SignedRecords),
    Imported(Imported),
    Acknowledged(SignedRecords),
    Attestation(AttestSigned),
    Cosign(Cosigned),
    /// A `signmessage` signature: the 65 recoverable bytes, hex (the façade writes them base64).
    MessageSig(String),
    ImportedKey(ImportedKey),
    /// A WIF.
    Dumped(String),
    /// After `encrypt`, `unlock`, `lock` (S4).
    WalletState(WalletState),
    /// The file written (`dump`, `backup`).
    Written(String),
    ImportedDump(ImportDumpResult),
    ImportedPq(PqImported),
    /// A built transaction, hex (`sapling_build`).
    Built(String),
    Refused(Refusal),
}

impl Response {
    pub fn refused(code: &str, reason: impl Into<String>) -> Response {
        Response::Refused(Refusal {
            code: code.to_string(),
            reason: reason.into(),
        })
    }
}

/// The format tag a [`PublicBundle`] carries.
pub const PUBLIC_FORMAT: &str = "yewd-public-1";

/// A BIP32 extended public key without depth, fingerprint or child number (yew-core never
/// serializes xpubs): the account node `m/44'/347'/0'`; the façade derives `/chain/index` itself
/// (CKDpub, non-hardened).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountXpub {
    /// The compressed public key, hex (33 bytes).
    pub pubkey: String,
    /// The chain code, hex (32 bytes).
    pub chain_code: String,
}

/// One post-quantum public key of the seed (quantum spec A-12: `DerivePQSeed(seed, scheme, index)`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPublic {
    /// 1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512.
    pub scheme: u8,
    /// The derivation index within the scheme.
    pub index: u32,
    /// The public key, hex (32 bytes for scheme 1, 897 for scheme 2).
    pub pk: String,
}

/// What the façade asks the signer for: the post-quantum keys `[from, from + count)` of each
/// listed scheme (the transparent and Sapling material always comes with it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRequest {
    /// `(scheme, from, count)`.
    pub pq: Vec<(u8, u32, u32)>,
}

/// The public material of one seed: everything the façade needs to recognise the wallet's
/// coins, notes and vaults, and nothing that can spend them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicBundle {
    /// [`PUBLIC_FORMAT`].
    pub format: String,
    /// `main`, `test` or `regtest` (yew-core `Network::chain_name`).
    pub network: String,
    /// The ZIP-32 seed fingerprint (`BLAKE2b-256("Zcash_HD_Seed_FP", len ‖ seed)`), hex: what
    /// ycashd's `getwalletinfo` reports as `mnemonic_seedfp`; it identifies the seed, it does not
    /// reveal it.
    pub seed_fp: String,
    /// The transparent account node `m/44'/347'/0'`.
    pub account: AccountXpub,
    /// The Sapling diversifiable full viewing key of the account `m/32'/347'/0'`
    /// (`ak ‖ nk ‖ ovk ‖ dk`, 128 bytes), hex.
    pub sapling_dfvk: String,
    /// The post-quantum public keys asked for.
    pub pq: Vec<PqPublic>,
    /// The public keys of the signer's imported keys, in store order (S3, `importprivkey`), hex.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imported: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_round_trips() {
        let r = Response::refused(refuse::PREVIEW_MISMATCH, "output 0 amount");
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(
            s,
            r#"{"result":"refused","body":{"code":"preview-mismatch","reason":"output 0 amount"}}"#
        );
        assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), r);
    }

    #[test]
    fn envelope_carries_the_version() {
        let e = Envelope::new(Request::Hello);
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, r#"{"version":1,"op":"hello"}"#);
        assert_eq!(serde_json::from_str::<Envelope>(&s).unwrap(), e);
        let e = Envelope::new(Request::Public(PublicRequest {
            pq: vec![(1, 0, 20)],
        }));
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, r#"{"version":1,"op":"public","body":{"pq":[[1,0,20]]}}"#);
        assert_eq!(serde_json::from_str::<Envelope>(&s).unwrap(), e);
    }

    #[test]
    fn key_refs_are_tagged() {
        let k = KeyRef::PqOwner {
            scheme: 1,
            index: 3,
            selector: 2,
        };
        let s = serde_json::to_string(&k).unwrap();
        assert_eq!(
            s,
            r#"{"kind":"pq_owner","scheme":1,"index":3,"selector":2}"#
        );
        assert_eq!(
            serde_json::to_string(&KeyRef::None).unwrap(),
            r#"{"kind":"none"}"#
        );
    }

    #[test]
    fn public_request_round_trips() {
        let r = PublicRequest {
            pq: vec![(1, 0, 20), (2, 5, 1)],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"pq":[[1,0,20],[2,5,1]]}"#);
        assert_eq!(serde_json::from_str::<PublicRequest>(&s).unwrap(), r);
    }
}
