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
pub mod client;
pub mod preview;

use serde::{Deserialize, Serialize};

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
}

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
}

/// `set_importsigned`'s answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Imported {
    pub imported: u32,
    pub present: u32,
}

/// What the signer says about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub network: String,
    pub seed_fp: String,
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

/// The refusal codes.
pub mod refuse {
    /// The request names another protocol version.
    pub const BAD_VERSION: &str = "bad-version";
    /// The request does not parse, or the transaction does not.
    pub const MALFORMED: &str = "malformed";
    /// An input has no prevout, or its prevout is not the one the transaction spends.
    pub const UNBOUND_INPUT: &str = "unbound-input";
    /// A key reference does not own the script it is to spend or recognise.
    pub const KEY_MISMATCH: &str = "key-mismatch";
    /// The preview disagrees with the bytes (an amount, a recipient, an input, the fee).
    pub const PREVIEW_MISMATCH: &str = "preview-mismatch";
    /// A wallet coin is signed that the preview does not list.
    pub const FOREIGN_INPUT: &str = "foreign-input";
    /// The net outflow is above the cap.
    pub const OUTFLOW: &str = "outflow";
    /// The gate path's rules refuse the transaction.
    pub const GATE: &str = "gate";
    /// The sign-once record holds another role or sighash for `(setid, prevout)`.
    pub const SET_SIGN_ONCE: &str = "set-sign-once";
    /// The restore marker is set and the prevout has no record.
    pub const SET_SIGN_RESTORED: &str = "set-sign-restored";
    /// Anything else (a derivation, the store).
    pub const FAILED: &str = "failed";
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
