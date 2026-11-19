// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The light attestor's transactions (workspace `docs/plans/beta4/price-feed.md` §2.2-§2.4,
//! B-T2 and B-T5): a seat that runs no node builds and signs every transaction of its role from
//! its one key, funded from the seat's own P2PKH coins (`GetAddressUtxos`), and the caller checks
//! each with `ValidateRawTransaction` before `SendTransaction`. Pure: no network, no store.
//!
//! - [`build_join`], [`build_heartbeat`], [`build_leave`]: the `YV` acts `SET_JOIN` (the bond
//!   P2SH(`<lock> CLTV DROP <memberKey> CHECKSIG`) at vout 0), `SET_HEARTBEAT` and the member's own
//!   `SET_REMOVE` (burn 0), signed by the member key alone (`yew_core::act`), then the act output
//!   and the change. Translation source: ycash6 `src/rpc/vault.cpp` `set_join` / `set_heartbeat`
//!   / `set_leave` (`BuildActTx`: the outputs before the act, the act, `Fund`'s change last), and
//!   yewd's port (`yewd/wallet/src/vaultrpc.rs`).
//! - [`build_withdraw`]: the bond's CLTV path (`yed_withdrawbond`; `txbuilder.cpp`
//!   `SignBondInput`: `<sig> <bond script>`, `nLockTime` = the bond's locktime).
//! - [`build_cancel`]: `yed_buildcancel` + `set_signcancel` (`src/rpc/yellowbackwallet.cpp`,
//!   `BuildYedIntentCancel`): the carrier holding the co-signatures (the `"YC"` list,
//!   `CarrierScript(seat key, SHA256(list))`), and the cancel — vin 0 the intent with the set
//!   signature (`SIGHASH_ALL|ANYONECANPAY` under the next block's branch), the fee inputs, the
//!   carrier last; vout 0 re-creates the vault, vout 1 refunds the burn (`TOKEN_VALUE`) to the
//!   refund holder, vout 2 the `CANCEL_COSIGN` marker, then `Fund`'s change, exactly the node's
//!   order. As the node's, the cancel is funded before the carrier input is added, so the
//!   carrier's `CARRIER_VALUE` adds to its fee.
//! - [`build_op_return`]: one seat coin, the change back to it, one `OP_RETURN` output with the
//!   given data, the fee exactly as asked (the agent's "YF" co-signature record, `onchain.rs`).
//!
//! Fees are the node's `Fund` rule (`vault.cpp` `Fund`, beta2 item 21b): `max(VAULT_RPC_FEE, the
//! relay fee, the ZIP-317 conventional fee)` of the transaction as signed.

use secp256k1::{Message, SecretKey};

use crate::act::{self, Act, Body};
use crate::bundle::bundle_hash;
use crate::cosign::{self, CosignEntry};
use crate::keys::{self, AddressKey};
use crate::params::{CARRIER_VALUE, SEQUENCE_LOCKTIME, TOKEN_VALUE};
use crate::payload::{self, Payload};
use crate::script;
use crate::tx::{OutPoint, Transaction, TxIn, TxOut, MAX_P2PKH_SCRIPT_SIG};
use crate::vault;

/// `VAULT_RPC_FEE` (ycash6 `policy.h`): the floor of every fee here.
pub const VAULT_RPC_FEE: i64 = 10_000;
/// `VAULT_RPC_MIN_CHANGE` (`vault.cpp`): smaller change is left to the fee.
pub const VAULT_RPC_MIN_CHANGE: i64 = 1_000;
/// `DEFAULT_MIN_RELAY_TX_FEE` (`main.h`), zatoshi per 1000 bytes.
pub const MIN_RELAY_FEE_PER_KB: i64 = 100;
/// The dust bound [`build_op_return`] keeps its change above (twice this beyond the fee).
pub const DUST: i64 = 546;
/// The largest `OP_RETURN` data a node relays (`MAX_OP_RETURN_RELAY` 83 = OP_RETURN, PUSHDATA1, length, 80).
pub const MAX_OP_RETURN_DATA: usize = 80;
/// `SIGHASH_ALL | SIGHASH_ANYONECANPAY`: the set signature's hash type (`SetSighash`).
pub const SIGHASH_ALL_ANYONECANPAY: u32 = 0x81;
const SIGHASH_ALL: u32 = 0x01;

/// A refusal: a short code (the CLI's `"code"`) and the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildError {
    pub code: &'static str,
    pub message: String,
}

impl BuildError {
    pub fn new(code: &'static str, message: impl Into<String>) -> BuildError {
        BuildError {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BuildError {}

impl From<crate::tx::TxError> for BuildError {
    fn from(e: crate::tx::TxError) -> BuildError {
        BuildError::new("tx", e.to_string())
    }
}

/// One spendable output: a seat coin (P2PKH of the seat key), the bond, the intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub value: i64,
    pub script: Vec<u8>,
}

/// The seat's P2PKH script.
pub fn seat_script(seat: &AddressKey) -> Vec<u8> {
    script::p2pkh_script(&seat.hash160)
}

/// The fee the node's `Fund` requires of `tx` with input `i`'s scriptSig `sizes[i]` bytes long.
pub fn required_fee(tx: &Transaction, sizes: &[usize]) -> Result<i64, BuildError> {
    let size = tx.size_with_script_sigs(sizes)? as i64;
    let relay = size * MIN_RELAY_FEE_PER_KB / 1000;
    let conventional = tx.zip317_conventional_fee(sizes)?;
    Ok(VAULT_RPC_FEE.max(relay).max(conventional))
}

/// How [`fund`] picks coins (`FundMode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundMode {
    /// Largest first until covered.
    LargestFirst,
    /// The smallest single coin that covers the need, else largest first.
    SmallChange,
}

/// `Fund`: add seat coins (P2PKH inputs) and a change output to `change_script` (when at least
/// [`VAULT_RPC_MIN_CHANGE`]) so that the inputs pay the outputs and the required fee. `sizes` are
/// the scriptSig sizes of the inputs `tx` already has (whose value is `input_value`); every added
/// input is priced at [`MAX_P2PKH_SCRIPT_SIG`]. Returns the coins added, in input order.
pub fn fund(
    tx: &mut Transaction,
    sizes: &[usize],
    input_value: i64,
    coins: &[Coin],
    change_script: &[u8],
    mode: FundMode,
) -> Result<Vec<Coin>, BuildError> {
    if sizes.len() != tx.vin.len() {
        return Err(BuildError::new(
            "internal",
            "fund: one size per existing input",
        ));
    }
    let mut eligible: Vec<Coin> = coins
        .iter()
        .filter(|c| !tx.vin.iter().any(|i| i.prevout == c.outpoint))
        .cloned()
        .collect();
    eligible.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then((a.outpoint.txid, a.outpoint.n).cmp(&(b.outpoint.txid, b.outpoint.n)))
    });
    let (n_in, n_out) = (tx.vin.len(), tx.vout.len());
    let out: i64 = tx.output_total();
    let mut fee = VAULT_RPC_FEE;
    for _pass in 0..8 {
        tx.vin.truncate(n_in);
        tx.vout.truncate(n_out);
        let needed = out + fee - input_value;
        let mut chosen: Vec<Coin> = Vec::new();
        let mut got = 0i64;
        if needed > 0 && mode == FundMode::SmallChange {
            if let Some(c) = eligible.iter().rev().find(|c| c.value >= needed) {
                got = c.value;
                chosen.push(c.clone());
            }
        }
        if chosen.is_empty() {
            for c in &eligible {
                if needed <= 0 || got >= needed {
                    break;
                }
                got += c.value;
                chosen.push(c.clone());
            }
        }
        if got < needed {
            return Err(BuildError::new(
                "insufficient-funds",
                format!(
                    "insufficient confirmed seat coins: need {} zat more",
                    needed - got
                ),
            ));
        }
        for c in &chosen {
            tx.vin.push(TxIn::new(c.outpoint));
        }
        let change = got - needed;
        if change >= VAULT_RPC_MIN_CHANGE {
            tx.vout.push(TxOut {
                value: change,
                script_pubkey: change_script.to_vec(),
            });
        }
        let mut all = sizes.to_vec();
        all.resize(tx.vin.len(), MAX_P2PKH_SCRIPT_SIG);
        let required = required_fee(tx, &all)?;
        let paid = input_value + got - tx.output_total();
        if paid >= required {
            return Ok(chosen);
        }
        fee = required.max(fee + 1);
    }
    Err(BuildError::new(
        "internal",
        "the funding fee did not settle",
    ))
}

/// Sign the P2PKH inputs `idx..` of `tx` spending `coins` (in order) with the seat key,
/// `SIGHASH_ALL` under `branch`.
pub fn sign_seat_inputs(
    tx: &mut Transaction,
    first: usize,
    coins: &[Coin],
    seat: &AddressKey,
    branch: u32,
) -> Result<(), BuildError> {
    for (k, c) in coins.iter().enumerate() {
        if script::p2pkh_hash(&c.script) != Some(seat.hash160) {
            return Err(BuildError::new(
                "not-seat-coin",
                format!("{} does not pay the seat key", c.outpoint.display()),
            ));
        }
        tx.sign_p2pkh_input(first + k, &seat.secret, &c.script, c.value, branch)?;
    }
    Ok(())
}

/// The act signature of `secret` over `body` bound to `vin0` (`ActMsg`, `SignRecoverable`).
pub fn sign_act(body: &Body, vin0: &OutPoint, secret: &SecretKey) -> [u8; act::SIG_SIZE] {
    let msg = act::act_msg(&act::encode_payload(body), &act::OutPoint::from(*vin0));
    act::sign_recoverable(secret, &msg)
}

/// `BuildActTx` + the member's signature: `before`, the act (vout `before.len()`), the change.
fn act_tx(
    seat: &AddressKey,
    coins: &[Coin],
    before: Vec<TxOut>,
    body: Body,
    branch: u32,
    expiry_height: u32,
) -> Result<Transaction, BuildError> {
    let mut tx = Transaction::new_v4();
    tx.expiry_height = expiry_height;
    tx.vout = before;
    let ai = tx.vout.len();
    // priced with its one signature in place (65 bytes; the bytes are set once vin 0 is known)
    let mut a = Act {
        body,
        sigs: vec![[0u8; act::SIG_SIZE]],
    };
    tx.vout.push(TxOut {
        value: 0,
        script_pubkey: act::encode(&a),
    });
    let chosen = fund(
        &mut tx,
        &[],
        0,
        coins,
        &seat_script(seat),
        FundMode::LargestFirst,
    )?;
    let vin0 = tx.vin[0].prevout;
    a.sigs = vec![sign_act(&a.body, &vin0, &seat.secret)];
    tx.vout[ai].script_pubkey = act::encode(&a);
    sign_seat_inputs(&mut tx, 0, &chosen, seat, branch)?;
    Ok(tx)
}

/// `SET_JOIN` of the seat's key to `set_id` with a bond of `bond_zat` locked to `locktime`
/// (vout 0, `bondVout` 0), signed by the member alone: enough for an open set (a closed set also
/// needs the admit key or `slashThreshold` members, which a light seat does not hold).
pub fn build_join(
    seat: &AddressKey,
    coins: &[Coin],
    set_id: &[u8; 32],
    bond_zat: i64,
    locktime: u32,
    branch: u32,
    expiry_height: u32,
) -> Result<Transaction, BuildError> {
    if !(1..script::LOCKTIME_THRESHOLD).contains(&locktime) {
        return Err(BuildError::new(
            "bad-locktime",
            "the bond locktime must be a height below 500000000",
        ));
    }
    if bond_zat <= 0 {
        return Err(BuildError::new("bad-bond", "the bond must be positive"));
    }
    let bond = TxOut {
        value: bond_zat,
        script_pubkey: act::bond_script_pubkey(locktime, &seat.pubkey),
    };
    let body = Body::Join {
        set_id: *set_id,
        member_key: seat.pubkey,
        bond_locktime: locktime,
        bond_vout: 0,
    };
    act_tx(seat, coins, vec![bond], body, branch, expiry_height)
}

/// `SET_HEARTBEAT` of the seat's key in `set_id`.
pub fn build_heartbeat(
    seat: &AddressKey,
    coins: &[Coin],
    set_id: &[u8; 32],
    branch: u32,
    expiry_height: u32,
) -> Result<Transaction, BuildError> {
    let body = Body::Heartbeat {
        set_id: *set_id,
        member_key: seat.pubkey,
    };
    act_tx(seat, coins, vec![], body, branch, expiry_height)
}

/// The member's own `SET_REMOVE` (burn 0: the bond is returned after the set's exit delay).
pub fn build_leave(
    seat: &AddressKey,
    coins: &[Coin],
    set_id: &[u8; 32],
    branch: u32,
    expiry_height: u32,
) -> Result<Transaction, BuildError> {
    let body = Body::Remove {
        set_id: *set_id,
        member_key: seat.pubkey,
        burn: 0,
    };
    act_tx(seat, coins, vec![], body, branch, expiry_height)
}

/// The bond spend (the CLTV path, `yed_withdrawbond`): the bond at `bond` (P2SH of the seat's
/// bond script for `locktime`) to `dest`, less the fee; `nLockTime` = `locktime`, the input's
/// sequence non-final. The caller checks the exit delay (the member's `unlockheight`).
pub fn build_withdraw(
    seat: &AddressKey,
    bond: &Coin,
    locktime: u32,
    dest: &[u8],
    branch: u32,
    expiry_height: u32,
) -> Result<Transaction, BuildError> {
    let redeem = act::bond_redeem_script(locktime, &seat.pubkey);
    if script::p2sh_of(&redeem) != bond.script {
        return Err(BuildError::new(
            "not-seat-bond",
            "the bond output is not the seat key's bond for this locktime",
        ));
    }
    let mut tx = Transaction::new_v4();
    tx.lock_time = locktime;
    tx.expiry_height = expiry_height;
    let mut i = TxIn::new(bond.outpoint);
    i.sequence = SEQUENCE_LOCKTIME;
    tx.vin.push(i);
    tx.vout.push(TxOut {
        value: 0,
        script_pubkey: dest.to_vec(),
    });
    // <DER sig (<= 72) || hashtype> <redeem>, each with a one-byte push
    let ss = 1 + 73 + 1 + redeem.len();
    let fee = required_fee(&tx, &[ss])?;
    let out = bond.value - fee;
    if out <= 0 {
        return Err(BuildError::new(
            "bond-too-small",
            "the bond does not cover the network fee",
        ));
    }
    tx.vout[0].value = out;
    let digest = tx.sighash(0, &redeem, bond.value, SIGHASH_ALL, branch)?;
    let sig = secp256k1::ecdsa::sign(Message::from_digest(digest), &seat.secret);
    let mut der = sig.serialize_der().to_vec();
    der.push(SIGHASH_ALL as u8);
    let mut s = Vec::with_capacity(ss);
    script::push_data(&mut s, &der);
    script::push_data(&mut s, &redeem);
    tx.vin[0].script_sig = s;
    Ok(tx)
}

/// One `OP_RETURN` output carrying `data` (one minimal push), funded from the smallest seat coin
/// above `fee + 2 × DUST` (and above `TOKEN_VALUE`), the change back to the seat first, the fee
/// exactly `fee`.
pub fn build_op_return(
    seat: &AddressKey,
    coins: &[Coin],
    data: &[u8],
    fee: i64,
    branch: u32,
    expiry_height: u32,
) -> Result<Transaction, BuildError> {
    if data.is_empty() || data.len() > MAX_OP_RETURN_DATA {
        return Err(BuildError::new(
            "bad-data",
            format!("the data must be 1 to {MAX_OP_RETURN_DATA} bytes"),
        ));
    }
    if fee < 0 {
        return Err(BuildError::new("bad-fee", "the fee must not be negative"));
    }
    let floor = fee + 2 * DUST;
    let coin = coins
        .iter()
        .filter(|c| c.value > floor && c.value > TOKEN_VALUE)
        .min_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then((a.outpoint.txid, a.outpoint.n).cmp(&(b.outpoint.txid, b.outpoint.n)))
        })
        .cloned()
        .ok_or_else(|| {
            BuildError::new(
                "insufficient-funds",
                format!("no confirmed seat coin above {floor} zat"),
            )
        })?;
    let mut spk = vec![script::op::OP_RETURN];
    script::push_data(&mut spk, data);
    let mut tx = Transaction::new_v4();
    tx.expiry_height = expiry_height;
    tx.vin.push(TxIn::new(coin.outpoint));
    tx.vout.push(TxOut {
        value: coin.value - fee,
        script_pubkey: seat_script(seat),
    });
    tx.vout.push(TxOut {
        value: 0,
        script_pubkey: spk,
    });
    sign_seat_inputs(&mut tx, 0, std::slice::from_ref(&coin), seat, branch)?;
    Ok(tx)
}

/// `set_signcancel` for one member: the set signature of `secret` over the cancel `tx`'s template
/// input `idx` (the intent `intent`, cancelled by `set_id`): `SignRecoverable(SetSigMsg(set,
/// ROLE_CANCEL, prevout, SetSighash))`. Returns `(sighash, signature)`.
pub fn set_sign_cancel(
    tx: &Transaction,
    idx: usize,
    intent: &Coin,
    set_id: &[u8; 32],
    secret: &SecretKey,
    branch: u32,
) -> Result<([u8; 32], [u8; act::SIG_SIZE]), BuildError> {
    let sighash = tx.sighash(
        idx,
        &intent.script,
        intent.value,
        SIGHASH_ALL_ANYONECANPAY,
        branch,
    )?;
    let msg = act::set_sig_msg(
        set_id,
        vault::ROLE_CANCEL,
        &act::OutPoint::from(intent.outpoint),
        &sighash,
    );
    Ok((sighash, act::sign_recoverable(secret, &msg)))
}

/// The intent's cancel scriptSig: the set signatures, then the selector `OP_2`.
pub fn cancel_script_sig(sigs: &[[u8; act::SIG_SIZE]]) -> Vec<u8> {
    let mut s = Vec::with_capacity(sigs.len() * 66 + 1);
    for sig in sigs {
        script::push_data(&mut s, sig);
    }
    s.push(vault::OP_2);
    s
}

/// What [`build_cancel`] takes besides the seat and its coins.
#[derive(Clone, Debug)]
pub struct CancelInputs {
    /// The claimant intent (outpoint, value, the I script).
    pub intent: Coin,
    /// The originating V script (`SHA256` must be the intent's vault hash).
    pub origin: Vec<u8>,
    /// The refund holder's script (`yed_getvault.refundHolder`).
    pub refund_holder: Vec<u8>,
    /// The co-signatures the carrier holds (checked by the caller; 1 to 7).
    pub cosigs: Vec<CosignEntry>,
    /// The carrier's `nExpiryHeight` (the node's: its reference height + `REF_WINDOW`).
    pub carrier_expiry: u32,
}

/// The two transactions of a cancel.
#[derive(Clone, Debug)]
pub struct CancelBuild {
    /// The carrier (send first; the cancel spends its vout 0 from the mempool).
    pub carrier: Transaction,
    /// The cancel, signed: the set signature, the fee inputs and the carrier input.
    pub cancel: Transaction,
    /// The set sighash the member signed.
    pub sighash: [u8; 32],
}

/// `yed_buildcancel` + `set_signcancel` + the fee-input signatures, for a set whose
/// `cancelThreshold` is 1 (the YED attestor set's): the seat key signs the template input as
/// the one set signature. The carrier is funded from `coins`, the cancel from the coins left.
pub fn build_cancel(
    seat: &AddressKey,
    coins: &[Coin],
    inp: &CancelInputs,
    branch: u32,
) -> Result<CancelBuild, BuildError> {
    let ip = vault::parse_intent(&inp.intent.script)
        .ok_or_else(|| BuildError::new("not-intent", "the intent output is not an I template"))?;
    if keys::sha256(&inp.origin) != ip.vault_hash {
        return Err(BuildError::new(
            "bad-origin",
            "the origin script is not the intent's originating vault",
        ));
    }
    if inp.refund_holder.is_empty() {
        return Err(BuildError::new(
            "no-refund-holder",
            "the claim recorded no refund holder",
        ));
    }
    let blob = cosign::encode_cosigns(&inp.cosigs).ok_or_else(|| {
        BuildError::new(
            "cancel-cosign-count",
            format!("1 to {} co-signatures", cosign::CANCEL_COSIGN_MAX),
        )
    })?;
    let change = seat_script(seat);
    // the carrier
    let redeem = script::carrier_script(&seat.pubkey, &bundle_hash(&blob))
        .map_err(|e| BuildError::new("internal", e.to_string()))?;
    let mut carrier = Transaction::new_v4();
    carrier.expiry_height = inp.carrier_expiry;
    carrier.vout.push(TxOut {
        value: CARRIER_VALUE,
        script_pubkey: script::p2sh_of(&redeem),
    });
    let c_in = fund(&mut carrier, &[], 0, coins, &change, FundMode::LargestFirst)?;
    sign_seat_inputs(&mut carrier, 0, &c_in, seat, branch)?;
    let carrier_op = OutPoint {
        txid: carrier.txid()?,
        n: 0,
    };
    // the cancel: vin 0 the intent; vault, refund, marker; funded from the coins left
    let left: Vec<Coin> = coins
        .iter()
        .filter(|c| !c_in.iter().any(|u| u.outpoint == c.outpoint))
        .cloned()
        .collect();
    let marker = payload::encode(&Payload::CancelCosign)
        .ok_or_else(|| BuildError::new("internal", "the CANCEL_COSIGN marker"))?;
    let mut tx = Transaction::new_v4();
    tx.expiry_height = 0;
    tx.vin.push(TxIn::new(inp.intent.outpoint));
    tx.vout.push(TxOut {
        value: inp.intent.value,
        script_pubkey: inp.origin.clone(),
    });
    tx.vout.push(TxOut {
        value: TOKEN_VALUE,
        script_pubkey: inp.refund_holder.clone(),
    });
    tx.vout.push(TxOut {
        value: 0,
        script_pubkey: payload::payload_script(&marker),
    });
    let f_in = fund(
        &mut tx,
        &[1 + 66],
        inp.intent.value,
        &left,
        &change,
        FundMode::SmallChange,
    )?;
    tx.vin.push(TxIn::new(carrier_op));
    let ci = tx.vin.len() - 1;
    // the set signature (ANYONECANPAY: the fee inputs and the carrier are not covered)
    let (sighash, sig) =
        set_sign_cancel(&tx, 0, &inp.intent, &ip.cancel_set_id, &seat.secret, branch)?;
    tx.vin[0].script_sig = cancel_script_sig(&[sig]);
    sign_seat_inputs(&mut tx, 1, &f_in, seat, branch)?;
    let digest = tx.sighash(ci, &redeem, CARRIER_VALUE, SIGHASH_ALL, branch)?;
    let csig = secp256k1::ecdsa::sign(Message::from_digest(digest), &seat.secret);
    let mut der = csig.serialize_der().to_vec();
    der.push(SIGHASH_ALL as u8);
    tx.vin[ci].script_sig = script::carrier_script_sig(&blob, &der, &redeem)
        .map_err(|e| BuildError::new("internal", e.to_string()))?;
    Ok(CancelBuild {
        carrier,
        cancel: tx,
        sighash,
    })
}

/// The claim's `refHeight` (its `YB` REDEEM payload), as `yed_buildcancel` reads it.
pub fn claim_ref_height(claim: &Transaction) -> Option<u32> {
    match payload::find_payload(claim)?.payload {
        Payload::Redeem { ref_height, .. } => Some(ref_height),
        _ => None,
    }
}

/// One co-signature checked as `yed_buildcancel` checks it before the carrier is built: it
/// recovers over this intent's message to a key in `members` not yet in `seen`, its price is in
/// range and not a claimable statement (RED-4). `Err` names why it is dropped.
#[allow(clippy::too_many_arguments)]
pub fn check_cosig(
    e: &CosignEntry,
    attestor_set_id: &[u8; 32],
    intent: &OutPoint,
    ref_height: u32,
    block_hash: &[u8; 32],
    members: &[[u8; 33]],
    seen: &[[u8; 33]],
    (collateral_zat, minted_cents, claim_threshold_bps): (i64, i64, i64),
) -> Result<[u8; 33], String> {
    let msg = cosign::cancel_cosign_message(
        attestor_set_id,
        &intent.txid,
        intent.n,
        ref_height,
        e.price_micro_usd,
        block_hash,
    );
    let key = act::recover(&msg, &e.sig)
        .ok_or("cancel-cosign-malformed: does not sign this intent's cancel")?;
    if seen.contains(&key) {
        return Err(format!("a repeat of key {}", keys::hex(&key)));
    }
    if !members.contains(&key) {
        return Err(format!(
            "cancel-cosign-not-member: key {} is not a current member of the attestor set",
            keys::hex(&key)
        ));
    }
    let price = e.price_micro_usd as i64;
    if !(cosign::PRICE_MIN..=cosign::PRICE_MAX).contains(&price) {
        return Err(format!("attest-range: {price} micro-USD"));
    }
    if cosign::is_underwater(collateral_zat, price, minted_cents, claim_threshold_bps) {
        return Err(format!(
            "cancel-statement-claimable: {price} micro-USD, at which the vault was claimable at refHeight {ref_height}"
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::VAULT_BRANCH_ID;
    use secp256k1::ecdsa::Signature;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../tests/vectors/vault_vectors.json")).unwrap()
    }

    fn unhex(v: &serde_json::Value) -> Vec<u8> {
        keys::unhex(v.as_str().unwrap()).unwrap()
    }

    fn arr<const N: usize>(v: &serde_json::Value) -> [u8; N] {
        unhex(v).try_into().unwrap()
    }

    fn key_of(v: &serde_json::Value, label: &str) -> AddressKey {
        let k = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["label"] == label)
            .unwrap();
        AddressKey::from_secret(SecretKey::from_secret_bytes(arr(&k["secret"])).unwrap())
    }

    fn seat() -> AddressKey {
        AddressKey::from_secret(SecretKey::from_secret_bytes([7u8; 32]).unwrap())
    }

    fn coin(seat: &AddressKey, b: u8, value: i64) -> Coin {
        Coin {
            outpoint: OutPoint {
                txid: [b; 32],
                n: b as u32,
            },
            value,
            script: seat_script(seat),
        }
    }

    /// Every P2PKH input verifies under the seat key (SIGHASH_ALL, the branch).
    fn check_p2pkh(tx: &Transaction, coins: &[(usize, &Coin)], seat: &AddressKey) {
        let pk = secp256k1::PublicKey::from_slice(&seat.pubkey).unwrap();
        for (i, c) in coins {
            let pushes = script::pushes(&tx.vin[*i].script_sig).unwrap();
            assert_eq!(pushes[1], seat.pubkey);
            let d = tx
                .sighash(*i, &c.script, c.value, SIGHASH_ALL, VAULT_BRANCH_ID)
                .unwrap();
            let der = &pushes[0][..pushes[0].len() - 1];
            Signature::from_der(der)
                .unwrap()
                .verify(Message::from_digest(d), &pk)
                .unwrap();
        }
    }

    fn fee_of(tx: &Transaction, inputs: i64) -> i64 {
        inputs - tx.output_total()
    }

    #[test]
    fn act_signatures_are_the_nodes() {
        // vault_vectors.json acts[]: each signer's RFC 6979 recoverable signature over ActMsg
        let v = vectors();
        let mut n = 0;
        for a in v["acts"].as_array().unwrap() {
            let spk = unhex(&a["script"]);
            let act = act::decode(&spk).unwrap();
            let po = unhex(&a["prevout"]);
            let vin0 = OutPoint {
                txid: po[..32].try_into().unwrap(),
                n: u32::from_le_bytes(po[32..].try_into().unwrap()),
            };
            for (i, s) in a["signers"].as_array().unwrap().iter().enumerate() {
                let k = key_of(&v, s.as_str().unwrap());
                assert_eq!(
                    sign_act(&act.body, &vin0, &k.secret).to_vec(),
                    unhex(&a["sigs"][i]),
                    "{}",
                    a["name"]
                );
                n += 1;
            }
        }
        assert!(n >= 3);
    }

    #[test]
    fn bond_scripts_are_the_nodes() {
        let v = vectors();
        for b in v["bonds"].as_array().unwrap() {
            let key: [u8; 33] = arr(&b["memberKey"]);
            let lt = b["locktime"].as_u64().unwrap() as u32;
            assert_eq!(act::bond_redeem_script(lt, &key), unhex(&b["redeem"]));
            assert_eq!(act::bond_script_pubkey(lt, &key), unhex(&b["spk"]));
        }
    }

    #[test]
    fn the_cancel_set_signature_is_the_nodes() {
        // vault_vectors.json spends[] "cancel": SetSighash, SetSigMsg, the member's signature and
        // the scriptSig `<sig> OP_2`, byte for byte
        let v = vectors();
        let s = v["spends"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "cancel")
            .unwrap();
        let (tx, _) = Transaction::parse(&unhex(&s["tx"])).unwrap();
        let n = s["nIn"].as_u64().unwrap() as usize;
        let intent = Coin {
            outpoint: tx.vin[n].prevout,
            value: s["amount"].as_i64().unwrap(),
            script: unhex(&s["scriptCode"]),
        };
        let set: [u8; 32] = arr(&s["setId"]);
        let k = key_of(&v, s["signers"][0].as_str().unwrap());
        let branch = s["branchId"].as_u64().unwrap() as u32;
        assert_eq!(branch, VAULT_BRANCH_ID);
        let (sighash, sig) = set_sign_cancel(&tx, n, &intent, &set, &k.secret, branch).unwrap();
        assert_eq!(sighash.to_vec(), unhex(&s["sighash"]));
        assert_eq!(sig.to_vec(), unhex(&s["sigs"][0]));
        assert_eq!(cancel_script_sig(&[sig]), unhex(&s["scriptSig"]));
    }

    #[test]
    fn join_heartbeat_leave_have_the_nodes_shape() {
        let k = seat();
        let coins = vec![coin(&k, 1, 50_000), coin(&k, 2, 3_000_000_000)];
        let set = [9u8; 32];
        let j = build_join(&k, &coins, &set, 1_000_000_000, 500, VAULT_BRANCH_ID, 140).unwrap();
        assert_eq!(j.expiry_height, 140);
        assert_eq!(
            j.vout[0].script_pubkey,
            act::bond_script_pubkey(500, &k.pubkey)
        );
        assert_eq!(j.vout[0].value, 1_000_000_000);
        let a = act::decode(&j.vout[1].script_pubkey).unwrap();
        assert!(act::fields_valid(&a));
        assert_eq!(
            a.body,
            Body::Join {
                set_id: set,
                member_key: k.pubkey,
                bond_locktime: 500,
                bond_vout: 0
            }
        );
        let msg = act::act_msg(
            &act::encode_payload(&a.body),
            &act::OutPoint::from(j.vin[0].prevout),
        );
        assert_eq!(act::recover(&msg, &a.sigs[0]), Some(k.pubkey));
        assert_eq!(j.vout[2].script_pubkey, seat_script(&k));
        assert_eq!(j.vin.len(), 1); // the largest coin alone
        assert_eq!(fee_of(&j, 3_000_000_000), VAULT_RPC_FEE);
        check_p2pkh(&j, &[(0, &coins[1])], &k);

        let h = build_heartbeat(&k, &coins, &set, VAULT_BRANCH_ID, 0).unwrap();
        assert_eq!(h.vout.len(), 2);
        let a = act::decode(&h.vout[0].script_pubkey).unwrap();
        assert_eq!(a.body.type_byte(), act::SET_HEARTBEAT);
        assert_eq!(fee_of(&h, 3_000_000_000), VAULT_RPC_FEE);

        let l = build_leave(&k, &coins, &set, VAULT_BRANCH_ID, 0).unwrap();
        let a = act::decode(&l.vout[0].script_pubkey).unwrap();
        assert_eq!(
            a.body,
            Body::Remove {
                set_id: set,
                member_key: k.pubkey,
                burn: 0
            }
        );
        // too little: refused
        let e = build_heartbeat(&k, &coins[..1][..0], &set, VAULT_BRANCH_ID, 0).unwrap_err();
        assert_eq!(e.code, "insufficient-funds");
        // a small coin with no change worth keeping: the remainder goes to the fee
        let h = build_heartbeat(&k, &[coin(&k, 3, 10_500)], &set, VAULT_BRANCH_ID, 0).unwrap();
        assert_eq!(h.vout.len(), 1);
        assert_eq!(fee_of(&h, 10_500), 10_500);
    }

    #[test]
    fn withdraw_spends_the_bond_by_its_cltv_path() {
        let k = seat();
        let bond = Coin {
            outpoint: OutPoint {
                txid: [5u8; 32],
                n: 0,
            },
            value: 1_000_000_000,
            script: act::bond_script_pubkey(700, &k.pubkey),
        };
        let to = seat_script(&k);
        let t = build_withdraw(&k, &bond, 700, &to, VAULT_BRANCH_ID, 800).unwrap();
        assert_eq!(t.lock_time, 700);
        assert_eq!(t.vin[0].sequence, SEQUENCE_LOCKTIME);
        assert_eq!(t.vout[0].value, 1_000_000_000 - VAULT_RPC_FEE);
        let p = script::pushes(&t.vin[0].script_sig).unwrap();
        assert_eq!(p[1], act::bond_redeem_script(700, &k.pubkey));
        let d = t
            .sighash(0, &p[1], bond.value, SIGHASH_ALL, VAULT_BRANCH_ID)
            .unwrap();
        Signature::from_der(&p[0][..p[0].len() - 1])
            .unwrap()
            .verify(
                Message::from_digest(d),
                &secp256k1::PublicKey::from_slice(&k.pubkey).unwrap(),
            )
            .unwrap();
        // another locktime's bond is not this seat's
        assert_eq!(
            build_withdraw(&k, &bond, 701, &to, VAULT_BRANCH_ID, 800)
                .unwrap_err()
                .code,
            "not-seat-bond"
        );
    }

    #[test]
    fn op_return_pays_exactly_the_fee() {
        let k = seat();
        let coins = vec![
            coin(&k, 1, 10_000), // a token's value: never
            coin(&k, 2, 40_000),
            coin(&k, 3, 2_000_000),
        ];
        let data = [0x59u8; 79];
        let t = build_op_return(&k, &coins, &data, 30_000, VAULT_BRANCH_ID, 0).unwrap();
        assert_eq!(t.vin[0].prevout, coins[1].outpoint); // the smallest above fee + 2 dust
        assert_eq!(fee_of(&t, 40_000), 30_000);
        assert_eq!(t.vout[0].script_pubkey, seat_script(&k));
        assert_eq!(&t.vout[1].script_pubkey[..3], &[0x6a, 0x4c, 79]);
        assert_eq!(&t.vout[1].script_pubkey[3..], &data[..]);
        check_p2pkh(&t, &[(0, &coins[1])], &k);
        assert!(build_op_return(&k, &coins, &[0u8; 81], 1, VAULT_BRANCH_ID, 0).is_err());
        assert_eq!(
            build_op_return(&k, &coins[..1], &data, 1_000, VAULT_BRANCH_ID, 0)
                .unwrap_err()
                .code,
            "insufficient-funds"
        );
    }

    #[test]
    fn cancel_has_yed_buildcancels_shape() {
        let v = vectors();
        let k = seat();
        // an intent from the vectors (any valid I template), with its originating V
        let intent_script = unhex(&v["intents"][0]["script"]);
        let ip = vault::parse_intent(&intent_script).unwrap();
        let origin = unhex(&v["intents"][0]["vaultScript"]);
        assert_eq!(keys::sha256(&origin), ip.vault_hash);
        let intent = Coin {
            outpoint: OutPoint {
                txid: [0xaa; 32],
                n: 0,
            },
            value: 2_000_000_000,
            script: intent_script,
        };
        let holder = script::p2pkh_script(&[0x44; 20]);
        let cosig = CosignEntry {
            price_micro_usd: 50_000,
            sig: [0x1f; 65],
        };
        let coins = vec![coin(&k, 1, 100_000), coin(&k, 2, 60_000)];
        let inp = CancelInputs {
            intent: intent.clone(),
            origin: origin.clone(),
            refund_holder: holder.clone(),
            cosigs: vec![cosig.clone()],
            carrier_expiry: 240,
        };
        let b = build_cancel(&k, &coins, &inp, VAULT_BRANCH_ID).unwrap();
        // the carrier: CARRIER_VALUE to P2SH(CarrierScript(seat, SHA256(list))), from the largest coin
        let blob = cosign::encode_cosigns(&[cosig]).unwrap();
        let redeem = script::carrier_script(&k.pubkey, &bundle_hash(&blob)).unwrap();
        assert_eq!(b.carrier.vout[0].script_pubkey, script::p2sh_of(&redeem));
        assert_eq!(b.carrier.vout[0].value, CARRIER_VALUE);
        assert_eq!(b.carrier.expiry_height, 240);
        assert_eq!(b.carrier.vin[0].prevout, coins[0].outpoint);
        // the cancel: intent first, carrier last; vault, refund, marker, change
        let c = &b.cancel;
        assert_eq!(c.vin[0].prevout, intent.outpoint);
        assert_eq!(c.vin[1].prevout, coins[1].outpoint);
        assert_eq!(
            c.vin.last().unwrap().prevout,
            OutPoint {
                txid: b.carrier.txid().unwrap(),
                n: 0
            }
        );
        assert_eq!(c.vout[0].script_pubkey, origin);
        assert_eq!(c.vout[0].value, intent.value);
        assert_eq!(c.vout[1].script_pubkey, holder);
        assert_eq!(c.vout[1].value, TOKEN_VALUE);
        let fp = payload::find_payload(c).unwrap();
        assert_eq!(fp.payload, Payload::CancelCosign);
        assert_eq!(fp.op_return_index, 2);
        // the set signature recovers to the seat key over SetSigMsg(cancel set, 2, intent, sighash)
        let (sel, sigs) = vault::parse_selector(vault::Kind::Intent, &c.vin[0].script_sig).unwrap();
        assert_eq!(sel, vault::ROLE_CANCEL);
        let msg = act::set_sig_msg(
            &ip.cancel_set_id,
            vault::ROLE_CANCEL,
            &act::OutPoint::from(intent.outpoint),
            &b.sighash,
        );
        assert_eq!(
            act::recover(&msg, &sigs[0].clone().try_into().unwrap()),
            Some(k.pubkey)
        );
        // ANYONECANPAY: the sighash does not move with the fee inputs
        let mut other = c.clone();
        other.vin.truncate(1);
        assert_eq!(
            other
                .sighash(
                    0,
                    &intent.script,
                    intent.value,
                    SIGHASH_ALL_ANYONECANPAY,
                    VAULT_BRANCH_ID
                )
                .unwrap(),
            b.sighash
        );
        check_p2pkh(c, &[(1, &coins[1])], &k);
        let cs = script::parse_carrier_script_sig(&c.vin.last().unwrap().script_sig).unwrap();
        assert_eq!(cs.bundle, blob);
        assert_eq!(cs.pk, k.pubkey);
        // the fee: Fund's, plus the carrier's value (the carrier is added after funding)
        let fee = intent.value + 60_000 + CARRIER_VALUE - c.output_total();
        assert!(fee >= VAULT_RPC_FEE + CARRIER_VALUE);
    }

    #[test]
    fn cosigs_are_checked_as_yed_buildcancel_does() {
        let k = seat();
        let set = [3u8; 32];
        let intent = OutPoint {
            txid: [4u8; 32],
            n: 1,
        };
        let bh = [5u8; 32];
        let msg = cosign::cancel_cosign_message(&set, &intent.txid, 1, 90, 50_000, &bh);
        let e = CosignEntry {
            price_micro_usd: 50_000,
            sig: act::sign_recoverable(&k.secret, &msg),
        };
        let terms = (10_000_000_000, 100, 12_500);
        assert_eq!(
            check_cosig(&e, &set, &intent, 90, &bh, &[k.pubkey], &[], terms),
            Ok(k.pubkey)
        );
        assert!(check_cosig(&e, &set, &intent, 90, &bh, &[], &[], terms)
            .unwrap_err()
            .starts_with("cancel-cosign-not-member"));
        assert!(
            check_cosig(&e, &set, &intent, 90, &bh, &[k.pubkey], &[k.pubkey], terms)
                .unwrap_err()
                .starts_with("a repeat")
        );
        assert!(check_cosig(&e, &set, &intent, 91, &bh, &[k.pubkey], &[], terms).is_err());
        // a claimable statement (1 YEC at $0.05 against $1 of debt)
        assert!(check_cosig(&e, &set, &intent, 90, &bh, &[k.pubkey], &[], terms).is_ok());
        assert!(check_cosig(
            &e,
            &set,
            &intent,
            90,
            &bh,
            &[k.pubkey],
            &[],
            (1_000_000, 100, 12_500)
        )
        .unwrap_err()
        .starts_with("cancel-statement-claimable"));
    }
}
