// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Signing and its policy (K-24, plan §3b S2): what the signer checks before any signature leaves
//! it, and how it signs.
//!
//! **Policy.** For every request the signer
//! 1. parses the transaction bytes itself (a shielded transaction is refused here: Sapling spends
//!    are built whole in the signer, K-24, never handed in as bytes);
//! 2. **binds every input to a prevout**: one [`yewd_proto::SignInput`] per input, its outpoint
//!    equal to `vin[i].prevout`, a script and a non-negative amount (`unbound-input` otherwise);
//! 3. derives every key it is asked to use and checks that the key owns the script it signs
//!    (P2PKH, `TX_PQPKH`, the owner of a V or I) or recognises (an own output, a bond)
//!    (`key-mismatch`);
//! 4. checks the gate path's shape ([`GatePath`]: no template input on a YEC payment, the template
//!    input never signed with a key on a vault build, the owner path's template at `vin[0]`);
//! 5. recomputes the preview from the bytes and the prevouts ([`yewd_proto::preview::compute`]) and
//!    refuses any difference from the request's (`preview-mismatch`): a mutated amount, a swapped
//!    recipient, a dropped or added input, the fee;
//! 6. refuses a net outflow (signed inputs minus own outputs) above the request's cap
//!    (`outflow`);
//! 7. only then signs, each digest recomputed (ZIP-243 under the request's branch ID; the set
//!    message; the act message), and returns the whole transaction or nothing.
//!
//! Set signatures pass the **sign-once** record ([`crate::signonce`]) before they are made.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

use secp256k1::SecretKey;
use yew_core::keys::{self, ExtendedPrivKey, HARDENED};
use yew_core::params::{Network, ACCOUNT, BIP44_PURPOSE, COIN_TYPE, SIGHASH_ALL};
use yew_core::pq::{PqKey, PqKeyId, PqSeedRoot};
use yew_core::tx::Transaction;
use yew_core::vault;
use yewd_proto::act::{self, OutPoint};
use yewd_proto::{
    refuse, ActSignRequest, ActSigs, Envelope, GatePath, Hello, KeyRef, Prevout, Request, Response,
    SetSignRequest, SetSigs, SignRequest, Signed, PROTO_VERSION,
};

use crate::signonce::{Check, SignOnce};
use crate::Keystore;

/// The largest amount (`MAX_MONEY`).
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;
const ANYONECANPAY: u32 = 0x80;

type Refused = (&'static str, String);

fn no<T>(code: &'static str, reason: impl Into<String>) -> Result<T, Refused> {
    Err((code, reason.into()))
}

/// The keys of one seed, derived once: the BIP32 account node and the PQ seed root.
struct Keys {
    account: ExtendedPrivKey,
    pq_root: PqSeedRoot,
}

/// The signer: the keystore, its derived keys and its sign-once records. One request at a time
/// (the server serialises them).
pub struct SignerCore {
    pub network: Network,
    pub seed_fp: String,
    keys: Keys,
    pub once: Mutex<SignOnce>,
    ks: Keystore,
}

impl std::fmt::Debug for SignerCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignerCore({:?})", self.network)
    }
}

/// A key derived for one request.
enum Derived {
    T(SecretKey, [u8; 33]),
    Pq(PqKey),
}

impl SignerCore {
    /// The signer over `ks`, its records in `dir` (`restored_if_new`: the marker a first start
    /// writes; [`crate::init`] sets it for a restored phrase).
    pub fn open(ks: Keystore, dir: &Path) -> Result<SignerCore, String> {
        let mut seed = keys::seed_from_mnemonic(ks.phrase(), "").map_err(|e| e.to_string())?;
        let master = ExtendedPrivKey::master(&seed).map_err(|e| e.to_string())?;
        let account = master
            .derive(&[
                BIP44_PURPOSE | HARDENED,
                COIN_TYPE | HARDENED,
                ACCOUNT | HARDENED,
            ])
            .map_err(|e| e.to_string())?;
        let pq_root = PqSeedRoot::from_seed(&seed);
        let seed_fp = hex::encode(crate::seed_fingerprint(&seed));
        keys::wipe(&mut seed);
        let once = SignOnce::load(dir, ks.restored())?;
        Ok(SignerCore {
            network: ks.network(),
            seed_fp,
            keys: Keys { account, pq_root },
            once: Mutex::new(once),
            ks,
        })
    }

    /// One request, answered (never panics on a bad request).
    pub fn handle(&self, env: &Envelope) -> Response {
        if env.version != PROTO_VERSION {
            return Response::refused(
                refuse::BAD_VERSION,
                format!(
                    "yewd-signer speaks protocol {PROTO_VERSION}, the request is version {}",
                    env.version
                ),
            );
        }
        let r = match &env.request {
            Request::Hello => Ok(Response::Hello(Hello {
                version: PROTO_VERSION,
                network: self.network.chain_name().into(),
                seed_fp: self.seed_fp.clone(),
            })),
            Request::Public(p) => self
                .ks
                .public(p)
                .map(Response::Public)
                .map_err(|e| (refuse::FAILED, e.to_string())),
            Request::Sign(s) => self.sign(s).map(Response::Signed),
            Request::SignAct(a) => self.sign_act(a).map(Response::ActSigs),
            Request::SignSet(s) => self.sign_set(s).map(Response::SetSigs),
            Request::ListSigned => Ok(Response::Records(self.lock().list())),
            Request::ImportSigned(recs) => {
                let mut o = self.lock();
                match o.import(recs) {
                    Ok((imported, present)) => Ok(Response::Imported(yewd_proto::Imported {
                        imported,
                        present,
                    })),
                    Err(e) if e.starts_with("set-sign-once") => Err((refuse::SET_SIGN_ONCE, e)),
                    Err(e) => Err((refuse::FAILED, e)),
                }
            }
            Request::AcknowledgeRestore => {
                let mut o = self.lock();
                o.acknowledge()
                    .map(|_| Response::Acknowledged(o.list()))
                    .map_err(|e| (refuse::FAILED, e))
            }
        };
        r.unwrap_or_else(|(c, m)| Response::refused(c, m))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SignOnce> {
        self.once.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn derive(&self, k: &KeyRef) -> Result<Option<Derived>, Refused> {
        match *k {
            KeyRef::None => Ok(None),
            KeyRef::Bip32 { chain, index } => {
                if chain > 1 || index >= HARDENED {
                    return no(
                        refuse::KEY_MISMATCH,
                        format!("no key m/44'/347'/0'/{chain}/{index}"),
                    );
                }
                let x = self
                    .keys
                    .account
                    .derive(&[chain, index])
                    .map_err(|e| (refuse::FAILED, e.to_string()))?;
                let pk = x.public_key();
                Ok(Some(Derived::T(x.key, pk)))
            }
            KeyRef::Pq { scheme, index } | KeyRef::PqOwner { scheme, index, .. } => {
                let mut seed = self.keys.pq_root.derive(scheme, index);
                let key = PqKey::from_seed(scheme, &seed).map_err(|e| {
                    (
                        refuse::KEY_MISMATCH,
                        format!("post-quantum key {scheme}/{index}: {e}"),
                    )
                });
                keys::wipe(&mut seed);
                Ok(Some(Derived::Pq(key?)))
            }
        }
    }

    /// The public key of a BIP32 reference (`None` for any other kind).
    fn tpub(&self, k: &KeyRef) -> Result<Option<[u8; 33]>, Refused> {
        match self.derive(k)? {
            Some(Derived::T(_, pk)) => Ok(Some(pk)),
            _ => Ok(None),
        }
    }

    /// The transparent signing request.
    pub fn sign(&self, r: &SignRequest) -> Result<Signed, Refused> {
        let raw = hex::decode(&r.tx).map_err(|e| (refuse::MALFORMED, format!("tx: {e}")))?;
        let (mut tx, _) =
            Transaction::parse(&raw).map_err(|e| (refuse::MALFORMED, format!("tx: {e}")))?;
        if tx.shielded.any() {
            return no(
                refuse::MALFORMED,
                "a transaction with shielded parts is not signed from bytes (the signer builds Sapling spends itself)",
            );
        }
        let prevouts = bind_inputs(&tx, r.inputs.iter().map(|i| &i.prevout))?;
        // keys, ownership, the gate path's shape
        let mut derived: Vec<Option<Derived>> = Vec::with_capacity(tx.vin.len());
        let mut signed: BTreeSet<u32> = BTreeSet::new();
        let mut templates = 0usize;
        for (i, (inp, script)) in r.inputs.iter().zip(&prevouts).enumerate() {
            let template =
                vault::parse_vault(script).is_some() || vault::parse_intent(script).is_some();
            templates += template as usize;
            let d = self.derive(&inp.key)?;
            if let Some(d) = &d {
                owns_input(&inp.key, d, script)
                    .map_err(|m| (refuse::KEY_MISMATCH, format!("input {i}: {m}")))?;
                signed.insert(i as u32);
            }
            match (r.gate_path, &inp.key) {
                (GatePath::Yec, KeyRef::PqOwner { .. })
                | (GatePath::Vault, KeyRef::PqOwner { .. }) => {
                    return no(
                        refuse::GATE,
                        format!("input {i}: an owner spend on the {:?} path", r.gate_path),
                    );
                }
                (GatePath::Owner, KeyRef::PqOwner { .. }) if i != 0 => {
                    return no(
                        refuse::GATE,
                        format!("input {i}: the owner path spends its template at input 0 only"),
                    );
                }
                _ => {}
            }
            if template && r.gate_path == GatePath::Yec {
                return no(
                    refuse::GATE,
                    format!("input {i} is a vault or intent: not a YEC payment"),
                );
            }
            derived.push(d);
        }
        match r.gate_path {
            GatePath::Vault if templates > 1 => {
                return no(refuse::GATE, "more than one template input (S-1)");
            }
            GatePath::Owner
                if !matches!(
                    r.inputs.first().map(|i| i.key),
                    Some(KeyRef::PqOwner { .. })
                ) =>
            {
                return no(
                    refuse::GATE,
                    "the owner path needs the owner's key at input 0",
                );
            }
            GatePath::Yec
                if tx
                    .vout
                    .iter()
                    .any(|o| yew_core::script::is_op_return(&o.script_pubkey)) =>
            {
                return no(refuse::GATE, "a YEC payment carries no data output");
            }
            _ => {}
        }
        // own outputs
        let mut own: BTreeSet<u32> = BTreeSet::new();
        for o in &r.own_outputs {
            let out = tx.vout.get(o.n as usize).ok_or_else(|| {
                (
                    refuse::KEY_MISMATCH,
                    format!("own output {} does not exist", o.n),
                )
            })?;
            let ok = match (o.bond_locktime, self.derive(&o.key)?) {
                (Some(lt), Some(Derived::T(_, pk))) => {
                    act::bond_script_pubkey(lt, &pk) == out.script_pubkey
                }
                (None, Some(Derived::T(_, pk))) => {
                    yew_core::script::p2pkh_script(&keys::hash160(&pk)) == out.script_pubkey
                }
                (None, Some(Derived::Pq(k))) => {
                    yew_core::pq::pqpkh_script(&k.id()).as_deref() == Some(&out.script_pubkey[..])
                }
                _ => false,
            };
            if !ok {
                return no(
                    refuse::KEY_MISMATCH,
                    format!("output {} is not paid to the named key", o.n),
                );
            }
            own.insert(o.n);
        }
        // the preview, recomputed from the bytes
        let full: Vec<Prevout> = r.inputs.iter().map(|i| i.prevout.clone()).collect();
        let want = yewd_proto::preview::compute(self.network, &tx, &full, &signed, &own);
        if let Some(d) = yewd_proto::preview::difference(&want, &r.preview) {
            // an input signed but not shown is a foreign input, named as such
            let shown: BTreeSet<u32> = r.preview.sign.iter().map(|c| c.vin).collect();
            if let Some(f) = signed.iter().find(|i| !shown.contains(i)) {
                return no(
                    refuse::FOREIGN_INPUT,
                    format!(
                        "input {f} ({}) would be signed but the preview does not list it",
                        full[*f as usize].outpoint
                    ),
                );
            }
            return no(
                refuse::PREVIEW_MISMATCH,
                format!("the preview disagrees with the bytes: {d}"),
            );
        }
        if want.fee_zat < 0 {
            return no(refuse::PREVIEW_MISMATCH, "the outputs exceed the inputs");
        }
        if want.outflow_zat > r.outflow_cap_zat {
            return no(
                refuse::OUTFLOW,
                format!(
                    "the wallet would pay {} zat beyond its own outputs, above the cap {} zat",
                    want.outflow_zat, r.outflow_cap_zat
                ),
            );
        }
        // sign
        let mut sighashes = vec![None; tx.vin.len()];
        for (i, d) in derived.into_iter().enumerate() {
            let Some(d) = d else { continue };
            let script = &prevouts[i];
            let amount = r.inputs[i].prevout.amount_zat;
            let digest = match (&r.inputs[i].key, d) {
                (KeyRef::Bip32 { .. }, Derived::T(sk, _)) => tx
                    .sign_p2pkh_input(i, &sk, script, amount, r.branch_id)
                    .map_err(|e| (refuse::FAILED, e.to_string()))?,
                (KeyRef::Pq { .. }, Derived::Pq(k)) => tx
                    .sign_pqpkh_input(i, &k, script, amount, r.branch_id)
                    .map_err(|e| (refuse::FAILED, e.to_string()))?,
                (KeyRef::PqOwner { selector, .. }, Derived::Pq(k)) => {
                    let (digest, sig) = tx
                        .pq_signature(i, &k, script, amount, r.branch_id)
                        .map_err(|e| (refuse::FAILED, e.to_string()))?;
                    let ss = owner_script_sig(script, *selector, &sig, k.public_key())?;
                    tx.vin[i].script_sig = ss;
                    digest
                }
                _ => return no(refuse::FAILED, "key kind and derivation disagree"),
            };
            sighashes[i] = Some(hex::encode(digest));
        }
        let out = tx
            .serialize()
            .map_err(|e| (refuse::FAILED, e.to_string()))?;
        Ok(Signed {
            tx: hex::encode(out),
            sighashes,
        })
    }

    /// Act signatures over the transaction's `YV` act.
    pub fn sign_act(&self, r: &ActSignRequest) -> Result<ActSigs, Refused> {
        let raw = hex::decode(&r.tx).map_err(|e| (refuse::MALFORMED, format!("tx: {e}")))?;
        let (tx, _) =
            Transaction::parse(&raw).map_err(|e| (refuse::MALFORMED, format!("tx: {e}")))?;
        let out = tx
            .vout
            .iter()
            .find(|o| act::is_act_output(&o.script_pubkey))
            .ok_or_else(|| {
                (
                    refuse::MALFORMED,
                    "the transaction carries no YV act".to_string(),
                )
            })?;
        let a = act::decode(&out.script_pubkey)
            .map_err(|e| (refuse::MALFORMED, format!("the act does not decode: {e}")))?;
        let vin0 = tx.vin.first().ok_or_else(|| {
            (
                refuse::UNBOUND_INPUT,
                "an act transaction needs vin[0]".to_string(),
            )
        })?;
        let payload = act::encode_payload(&a.body);
        let msg = act::act_msg(&payload, &OutPoint::from(vin0.prevout));
        let mut sigs = Vec::new();
        for k in &r.keys {
            match self.derive(k)? {
                Some(Derived::T(sk, _)) => sigs.push(hex::encode(act::sign_recoverable(&sk, &msg))),
                _ => {
                    return no(
                        refuse::KEY_MISMATCH,
                        "act signatures are made with BIP32 member or admit keys",
                    )
                }
            }
        }
        Ok(ActSigs {
            payload: hex::encode(payload),
            msg: hex::encode(msg),
            sigs,
        })
    }

    /// Set signatures over a vault spend, through the sign-once record.
    pub fn sign_set(&self, r: &SetSignRequest) -> Result<SetSigs, Refused> {
        let raw = hex::decode(&r.tx).map_err(|e| (refuse::MALFORMED, format!("tx: {e}")))?;
        let (tx, _) =
            Transaction::parse(&raw).map_err(|e| (refuse::MALFORMED, format!("tx: {e}")))?;
        let idx = r.index as usize;
        let vin = tx
            .vin
            .get(idx)
            .ok_or_else(|| (refuse::UNBOUND_INPUT, format!("input {idx} does not exist")))?;
        let op = OutPoint::parse(&r.prevout.outpoint).ok_or_else(|| {
            (
                refuse::UNBOUND_INPUT,
                "the template prevout is not txid:n".to_string(),
            )
        })?;
        if OutPoint::from(vin.prevout) != op {
            return no(
                refuse::UNBOUND_INPUT,
                format!(
                    "input {idx} spends {}, not {}",
                    OutPoint::from(vin.prevout).display(),
                    op.display()
                ),
            );
        }
        let script = hex::decode(&r.prevout.script)
            .map_err(|e| (refuse::UNBOUND_INPUT, format!("script: {e}")))?;
        if r.prevout.amount_zat < 0 || r.prevout.amount_zat > MAX_MONEY {
            return no(refuse::UNBOUND_INPUT, "the template amount is out of range");
        }
        let set = yew_core::tx::txid_from_hex(&r.set_id)
            .map_err(|e| (refuse::MALFORMED, format!("set id: {e}")))?;
        let template_set = match r.role {
            1 => vault::parse_vault(&script).map(|v| v.set_id),
            2 => vault::parse_intent(&script).map(|i| i.cancel_set_id),
            _ => return no(refuse::MALFORMED, "role must be 1 (unlock) or 2 (cancel)"),
        };
        match template_set {
            None => {
                return no(
                    refuse::GATE,
                    if r.role == 1 {
                        "the template input is not a vault"
                    } else {
                        "the template input is not an intent"
                    },
                )
            }
            Some(s) if s != set => {
                return no(
                    refuse::GATE,
                    "the set does not govern this template's branch",
                )
            }
            Some(_) => {}
        }
        if tx.shielded.any() {
            return no(refuse::MALFORMED, "a vault spend has no shielded part");
        }
        let sighash = tx
            .sighash(
                idx,
                &script,
                r.prevout.amount_zat,
                SIGHASH_ALL | ANYONECANPAY,
                r.branch_id,
            )
            .map_err(|e| (refuse::FAILED, e.to_string()))?;
        let msg = act::set_sig_msg(&set, r.role, &op, &sighash);
        let sighash_hex = hex::encode(sighash);
        let set_hex = r.set_id.clone();
        let prevout = op.display();
        // derive every key before anything is recorded
        let mut secrets = Vec::new();
        for k in &r.keys {
            match self.derive(k)? {
                Some(Derived::T(sk, _)) => secrets.push(sk),
                _ => {
                    return no(
                        refuse::KEY_MISMATCH,
                        "set signatures are made with BIP32 member keys",
                    )
                }
            }
        }
        {
            let mut once = self.lock();
            match once.check(&set_hex, &prevout, r.role, &sighash_hex) {
                Check::Same => {}
                Check::Different(role, h) => {
                    return no(
                        refuse::SET_SIGN_ONCE,
                        format!(
                            "set-sign-once: this wallet already signed a different {} (role {role}, sighash {h}) of {prevout} for set {set_hex}; a second signature is a provable equivocation (SET_EQUIVOCATION ejects the member and freezes its bond). Collect signatures on the transaction already signed",
                            if role == 1 { "unlock" } else { "cancel" }
                        ),
                    )
                }
                // nothing is recorded until a signature is about to leave the signer
                Check::Absent if secrets.is_empty() => {}
                Check::Absent => {
                    if once.restored && !r.acknowledge_restore {
                        return no(
                            refuse::SET_SIGN_RESTORED,
                            format!("set-sign-restored: this wallet was restored or imported a member key and has no sign-once history; import it with set_importsigned (or a wallet dump) and then set_acknowledgerestore, or pass {{\"acknowledgerestore\": true}} if this key has never signed a set spend of {prevout}"),
                        );
                    }
                    once.record(&set_hex, &prevout, r.role, &sighash_hex)
                        .map_err(|e| (refuse::FAILED, format!("set-sign-once: cannot record the signature; nothing was signed: {e}")))?;
                }
            }
        }
        let sigs = secrets
            .iter()
            .map(|sk| hex::encode(act::sign_recoverable(sk, &msg)))
            .collect();
        Ok(SetSigs {
            sighash: sighash_hex,
            msg: hex::encode(msg),
            sigs,
        })
    }

    /// The compressed public key of a BIP32 reference, for tests and the hello check.
    pub fn bip32_pubkey(&self, chain: u32, index: u32) -> Option<[u8; 33]> {
        self.tpub(&KeyRef::Bip32 { chain, index }).ok().flatten()
    }
}

/// Every input bound to its prevout; returns the scripts.
fn bind_inputs<'a>(
    tx: &Transaction,
    prevouts: impl ExactSizeIterator<Item = &'a Prevout>,
) -> Result<Vec<Vec<u8>>, Refused> {
    if prevouts.len() != tx.vin.len() {
        return no(
            refuse::UNBOUND_INPUT,
            format!(
                "the transaction has {} inputs, the request names {} prevouts",
                tx.vin.len(),
                prevouts.len()
            ),
        );
    }
    let mut scripts = Vec::with_capacity(tx.vin.len());
    for (i, (vin, p)) in tx.vin.iter().zip(prevouts).enumerate() {
        let op = OutPoint::parse(&p.outpoint).ok_or_else(|| {
            (
                refuse::UNBOUND_INPUT,
                format!("input {i}: prevout {:?} is not txid:n", p.outpoint),
            )
        })?;
        if op != OutPoint::from(vin.prevout) {
            return no(
                refuse::UNBOUND_INPUT,
                format!(
                    "input {i} spends {}, the request names {}",
                    OutPoint::from(vin.prevout).display(),
                    op.display()
                ),
            );
        }
        if p.amount_zat < 0 || p.amount_zat > MAX_MONEY {
            return no(
                refuse::UNBOUND_INPUT,
                format!("input {i}: amount {} out of range", p.amount_zat),
            );
        }
        let s = hex::decode(&p.script)
            .map_err(|e| (refuse::UNBOUND_INPUT, format!("input {i}: script: {e}")))?;
        if s.is_empty() {
            return no(refuse::UNBOUND_INPUT, format!("input {i}: no script"));
        }
        scripts.push(s);
    }
    Ok(scripts)
}

/// Whether the derived key owns the script it is to sign.
fn owns_input(k: &KeyRef, d: &Derived, script: &[u8]) -> Result<(), String> {
    match (k, d) {
        (KeyRef::Bip32 { .. }, Derived::T(_, pk)) => {
            if yew_core::script::p2pkh_hash(script) == Some(keys::hash160(pk)) {
                Ok(())
            } else {
                Err("the script is not the P2PKH of the named key".into())
            }
        }
        (KeyRef::Pq { .. }, Derived::Pq(key)) => {
            if yew_core::pq::pqpkh_of(script) == Some(key.id()) {
                Ok(())
            } else {
                Err("the script is not the TX_PQPKH of the named key".into())
            }
        }
        (KeyRef::PqOwner { selector, .. }, Derived::Pq(key)) => {
            let id: PqKeyId = key.id();
            if let Some(v) = vault::parse_vault(script) {
                if v.owner != id {
                    return Err("the vault's owner is not the named key".into());
                }
                if *selector != vault::SEL_OWNER && *selector != vault::SEL_RELEASED {
                    return Err(format!(
                        "selector {selector} is not an owner branch of a vault"
                    ));
                }
                Ok(())
            } else if let Some(i) = vault::parse_intent(script) {
                if i.owner != id {
                    return Err("the intent's owner is not the named key".into());
                }
                if *selector != vault::SEL_RELEASED {
                    return Err(format!(
                        "selector {selector} is not an owner branch of an intent"
                    ));
                }
                Ok(())
            } else {
                Err("an owner key signs a vault or an intent only".into())
            }
        }
        _ => Err("key kind and derivation disagree".into()),
    }
}

/// The owner scriptSig of a V (selector 2 or 3) or an I (selector 3) around `sig ‖ hashtype`.
pub fn owner_script_sig(
    script: &[u8],
    selector: u8,
    sig: &[u8],
    pk: &[u8],
) -> Result<Vec<u8>, (&'static str, String)> {
    let r = if vault::parse_vault(script).is_some() {
        if selector == vault::SEL_OWNER {
            vault::vault_owner_script_sig(sig, pk)
        } else {
            vault::vault_owner_released_script_sig(sig, pk)
        }
    } else {
        vault::intent_owner_released_script_sig(sig, pk)
    };
    r.map_err(|e| (refuse::FAILED, e.to_string()))
}
