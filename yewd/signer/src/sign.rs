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
use yew_core::build::hybrid as hybrid_sign;
use yew_core::keys::{self, ExtendedPrivKey, HARDENED};
use yew_core::params::{Network, ACCOUNT, BIP44_PURPOSE, COIN_TYPE, SIGHASH_ALL};
use yew_core::pq::{PqKey, PqKeyId, PqSeedRoot};
use yew_core::tx::Transaction;
use yew_core::vault;
use yewd_proto::act::{self, OutPoint};
use yewd_proto::{
    refuse, ActSignRequest, ActSigs, AttestRequest, AttestSigned, CosignRequest, Cosigned,
    Envelope, GatePath, Hello, ImportedKey, KeyRef, MessageRequest, Prevout, Request, Response,
    SetSignRequest, SetSigs, SignRequest, Signed, IMPORTED_CHAIN, PROTO_VERSION,
};

use crate::attest::Guard;
use crate::imported::Imported;
use crate::signonce::{Check, SignOnce};
use crate::Keystore;

/// The largest amount (`MAX_MONEY`).
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;
const ANYONECANPAY: u32 = 0x80;

// review YEW-PORT-5 R1: moved to yew-core, re-exported (no logic change)
pub(crate) use yew_core::refuse::{no, Refused};

fn no_guard<T>() -> Result<T, Refused> {
    no(refuse::LOCKED, crate::LOCKED)
}

/// The keys of one seed, derived once: the BIP32 account node and the PQ seed root.
pub(crate) struct Keys {
    pub(crate) account: ExtendedPrivKey,
    pub(crate) pq_root: PqSeedRoot,
}

/// The signer: the keystore, its derived keys and its sign-once records. One request at a time
/// (the server serialises them).
pub struct SignerCore {
    pub network: Network,
    pub seed_fp: String,
    /// `None` while an encrypted wallet is locked (S4).
    pub(crate) keys: std::sync::RwLock<Option<Keys>>,
    pub once: Mutex<SignOnce>,
    /// The attestation equivocation guard (S3).
    pub guard: Mutex<Guard>,
    /// The imported transparent keys (S3, `importprivkey`).
    pub(crate) imported: Mutex<Imported>,
    /// The imported post-quantum keys (S4, `z_importpqkey`, `pqseed=` lines).
    pub(crate) pq_imported: Mutex<crate::pqimported::PqImported>,
    pub(crate) ks: Mutex<Keystore>,
    /// Unix time an unlock lasts until (0: locked, or never encrypted).
    unlocked_until: Mutex<i64>,
    /// The signer's directory.
    pub(crate) dir: std::path::PathBuf,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn derive_keys(phrase: &str) -> Result<(Keys, String), String> {
    let mut seed = keys::seed_from_mnemonic(phrase, "").map_err(|e| e.to_string())?;
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
    Ok((Keys { account, pq_root }, seed_fp))
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
        // a locked encrypted wallet starts without keys; its fingerprint is in the public cache
        let (keys, seed_fp) = match ks.phrase() {
            Some(p) => {
                let (k, fp) = derive_keys(p)?;
                (Some(k), fp)
            }
            None => (
                None,
                ks.public(&yewd_proto::PublicRequest::default())
                    .map(|b| b.seed_fp)
                    .map_err(|e| e.to_string())?,
            ),
        };
        let once = SignOnce::load(dir, ks.restored())?;
        let guard = Guard::load(dir)?;
        let imported = Imported::load(dir)?;
        let pq_imported = crate::pqimported::PqImported::load(dir)?;
        Ok(SignerCore {
            network: ks.network(),
            seed_fp,
            keys: std::sync::RwLock::new(keys),
            once: Mutex::new(once),
            guard: Mutex::new(guard),
            imported: Mutex::new(imported),
            ks: Mutex::new(ks),
            unlocked_until: Mutex::new(0),
            pq_imported: Mutex::new(pq_imported),
            dir: dir.to_path_buf(),
        })
    }

    pub(crate) fn keystore(&self) -> std::sync::MutexGuard<'_, Keystore> {
        self.ks.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The encryption state: `(encrypted, unlocked_until)`; an unlock past its time is undone here.
    fn enc_state(&self) -> (bool, i64) {
        let encrypted = self.keystore().encrypted();
        if !encrypted {
            return (false, 0);
        }
        let mut until = self
            .unlocked_until
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if *until != 0 && now() >= *until {
            *until = 0;
            drop(until);
            self.do_lock();
            return (true, 0);
        }
        (true, *until)
    }

    fn do_lock(&self) {
        *self.keys.write().unwrap_or_else(|e| e.into_inner()) = None;
        self.keystore().lock();
        self.imports().lock();
        *self
            .unlocked_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = 0;
    }

    /// The keys, or the `locked` refusal.
    pub(crate) fn keys(&self) -> Result<std::sync::RwLockReadGuard<'_, Option<Keys>>, Refused> {
        let (encrypted, until) = self.enc_state();
        let g = self.keys.read().unwrap_or_else(|e| e.into_inner());
        if g.is_none() || (encrypted && until == 0) {
            return no_guard();
        }
        Ok(g)
    }

    /// `encryptwallet`: seal the seed and the imported keys; the signer stays unlocked until the
    /// façade restarts it (ycashd stops after encrypting).
    fn encrypt(&self, r: &yewd_proto::EncryptRequest) -> Result<yewd_proto::WalletState, Refused> {
        if self.keystore().encrypted() {
            return no(
                refuse::WRONG_ENC_STATE,
                "Error: running with an encrypted wallet, but encryptwallet was called.",
            );
        }
        if r.passphrase.is_empty() {
            return no(
                refuse::FAILED,
                "encryptwallet <passphrase>\nEncrypts the wallet with <passphrase>.",
            );
        }
        let cache = self
            .keystore()
            .public(&yewd_proto::PublicRequest { pq: r.pq.clone() })
            .map_err(|e| (refuse::FAILED, e.to_string()))?;
        let mut cache = cache;
        cache.imported = self.imports().pubkeys().iter().map(hex::encode).collect();
        self.imports().encrypt(&r.passphrase).map_err(|e| {
            (
                refuse::FAILED,
                format!("Error: Failed to encrypt the wallet. {e}"),
            )
        })?;
        self.keystore()
            .encrypt(&r.passphrase, &cache)
            .map_err(|e| {
                (
                    refuse::FAILED,
                    format!("Error: Failed to encrypt the wallet. {e}"),
                )
            })?;
        self.do_lock();
        Ok(yewd_proto::WalletState {
            encrypted: true,
            unlocked_until: 0,
        })
    }

    /// `walletpassphrase`.
    fn unlock(&self, r: &yewd_proto::UnlockRequest) -> Result<yewd_proto::WalletState, Refused> {
        if !self.keystore().encrypted() {
            return no(
                refuse::WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletpassphrase was called.",
            );
        }
        let phrase = {
            let mut ks = self.keystore();
            if !ks.unlock(&r.passphrase) {
                return no(
                    refuse::BAD_PASSPHRASE,
                    "Error: The wallet passphrase entered was incorrect.",
                );
            }
            ks.phrase().unwrap_or_default().to_string()
        };
        match self.imports().unlock(&r.passphrase) {
            Ok(true) => {}
            Ok(false) => {
                self.do_lock();
                return no(
                    refuse::BAD_PASSPHRASE,
                    "Error: The wallet passphrase entered was incorrect.",
                );
            }
            Err(e) => return no(refuse::FAILED, e),
        }
        let (k, _) = derive_keys(&phrase).map_err(|e| (refuse::FAILED, e))?;
        *self.keys.write().unwrap_or_else(|e| e.into_inner()) = Some(k);
        let until = now().saturating_add(r.timeout.max(0));
        *self
            .unlocked_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = until;
        Ok(yewd_proto::WalletState {
            encrypted: true,
            unlocked_until: until,
        })
    }

    /// `walletlock`.
    fn wallet_lock(&self) -> Result<yewd_proto::WalletState, Refused> {
        if !self.keystore().encrypted() {
            return no(
                refuse::WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletlock was called.",
            );
        }
        self.do_lock();
        Ok(yewd_proto::WalletState {
            encrypted: true,
            unlocked_until: 0,
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
            Request::Hello => {
                let (encrypted, unlocked_until) = self.enc_state();
                Ok(Response::Hello(Hello {
                    version: PROTO_VERSION,
                    network: self.network.chain_name().into(),
                    seed_fp: self.seed_fp.clone(),
                    encrypted,
                    unlocked_until,
                }))
            }
            Request::Encrypt(e) => self.encrypt(e).map(Response::WalletState),
            Request::Unlock(u) => self.unlock(u).map(Response::WalletState),
            Request::Lock => self.wallet_lock().map(Response::WalletState),
            Request::Dump(d) => self.dump(d).map(Response::Written),
            Request::ImportDump(d) => self.import_dump(d).map(Response::ImportedDump),
            Request::ImportPq(q) => self.import_pq(q).map(Response::ImportedPq),
            Request::Backup(b) => self.backup(b).map(Response::Written),
            Request::SaplingBuild(b) => self.sapling_build(b).map(Response::Built),
            Request::Public(p) => {
                let _ = self.enc_state();
                self.keystore()
                    .public(p)
                    .map(|mut b| {
                        b.imported = self.imports().pubkeys().iter().map(hex::encode).collect();
                        b.pq.extend(self.pq_imported_public());
                        Response::Public(b)
                    })
                    .map_err(|e| {
                        let m = e.to_string();
                        if m.starts_with("locked") {
                            (refuse::LOCKED, m)
                        } else {
                            (refuse::FAILED, m)
                        }
                    })
            }
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
            Request::SignAttestation(a) => self.sign_attestation(a).map(Response::Attestation),
            Request::CancelCosign(c) => self.cancel_cosign(c).map(Response::Cosign),
            Request::SignMessage(m) => self.sign_message(m).map(Response::MessageSig),
            Request::ImportKey(i) => self
                .import_key(&i.wif, i.members.as_deref())
                .map(Response::ImportedKey),
            Request::JoinsSeen(h) => {
                let mut o = self.lock();
                o.joins_seen(h)
                    .map(|_| Response::Acknowledged(o.list()))
                    .map_err(|e| (refuse::FAILED, e))
            }
            Request::DumpKey(k) => self.dump_key(k).map(Response::Dumped),
        };
        r.unwrap_or_else(|(c, m)| Response::refused(c, m))
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, SignOnce> {
        self.once.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn imports(&self) -> std::sync::MutexGuard<'_, Imported> {
        self.imported.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn attest_guard(&self) -> std::sync::MutexGuard<'_, Guard> {
        self.guard.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A transparent key: `m/44'/347'/0'/chain/index`, or imported key `index` on
    /// [`IMPORTED_CHAIN`].
    pub(crate) fn transparent(
        &self,
        chain: u32,
        index: u32,
    ) -> Result<(SecretKey, [u8; 33]), Refused> {
        let keys = self.keys()?;
        let k = keys.as_ref().expect("checked");
        if chain == IMPORTED_CHAIN {
            let sk = *self.imports().get(index).ok_or_else(|| {
                (
                    refuse::KEY_NOT_HELD,
                    format!("no imported key {index} in this signer"),
                )
            })?;
            let pk = secp256k1::PublicKey::from_secret_key(&sk).serialize();
            return Ok((sk, pk));
        }
        if chain > 1 || index >= HARDENED {
            return no(
                refuse::KEY_MISMATCH,
                format!("no key m/44'/347'/0'/{chain}/{index}"),
            );
        }
        let x = k
            .account
            .derive(&[chain, index])
            .map_err(|e| (refuse::FAILED, e.to_string()))?;
        let pk = x.public_key();
        Ok((x.key, pk))
    }

    fn derive(&self, k: &KeyRef) -> Result<Option<Derived>, Refused> {
        match *k {
            KeyRef::None => Ok(None),
            KeyRef::Bip32 { chain, index }
            | KeyRef::Carrier { chain, index }
            | KeyRef::Bond { chain, index, .. } => {
                let (sk, pk) = self.transparent(chain, index)?;
                Ok(Some(Derived::T(sk, pk)))
            }
            KeyRef::Pq { scheme, index } | KeyRef::PqOwner { scheme, index, .. }
                if index >= yewd_proto::IMPORTED_PQ_BASE =>
            {
                drop(self.keys()?);
                let e = self
                    .pq_imported
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .keys
                    .get((index - yewd_proto::IMPORTED_PQ_BASE) as usize)
                    .cloned()
                    .ok_or_else(|| {
                        (
                            refuse::KEY_NOT_HELD,
                            format!("no imported post-quantum key {index}"),
                        )
                    })?;
                let mut seed: [u8; 48] = hex::decode(&e.seed)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| (refuse::FAILED, "an imported seed".to_string()))?;
                if e.scheme != scheme {
                    return no(
                        refuse::KEY_MISMATCH,
                        "the imported key is of another scheme",
                    );
                }
                let key = PqKey::from_seed(scheme, &seed)
                    .map_err(|err| (refuse::KEY_MISMATCH, format!("imported key {index}: {err}")));
                keys::wipe(&mut seed);
                Ok(Some(Derived::Pq(key?)))
            }
            KeyRef::Pq { scheme, index } | KeyRef::PqOwner { scheme, index, .. } => {
                let keys = self.keys()?;
                let mut seed = keys
                    .as_ref()
                    .expect("checked")
                    .pq_root
                    .derive(scheme, index);
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
                owns_input(&inp.key, d, script, inp.carrier_bundle.as_deref())
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
        let want = yewd_proto::preview::with_sapling(
            yewd_proto::preview::compute(self.network, &tx, &full, &signed, &own),
            r.sapling.as_ref(),
        );
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
        // sign: each digest ZIP-243 under the request's branch; with a Sapling part, over the
        // proven Sapling bundle too (S4)
        let hybrid = match &r.sapling {
            Some(part) => Some(self.sapling_prepare(part, &tx, r.branch_id)?),
            None => None,
        };
        // review YEW-REVIEW-6 item 4: the digest, the ECDSA signature, the P2PKH and
        // post-quantum arms and the finish moved to yew_core::build::hybrid (a pure move)
        let digest_of = |tx: &Transaction,
                         i: usize,
                         script_code: &[u8],
                         script: &[u8],
                         amount: i64|
         -> Result<[u8; 32], Refused> {
            hybrid_sign::input_digest(
                hybrid.as_ref(),
                r.branch_id,
                tx,
                i,
                script_code,
                script,
                amount,
            )
        };
        let ecdsa = hybrid_sign::ecdsa;
        let mut sighashes = vec![None; tx.vin.len()];
        for (i, d) in derived.into_iter().enumerate() {
            let Some(d) = d else { continue };
            let script = prevouts[i].clone();
            let amount = r.inputs[i].prevout.amount_zat;
            let digest = match (&r.inputs[i].key, d) {
                (KeyRef::Bip32 { .. }, Derived::T(sk, pk)) => hybrid_sign::sign_p2pkh_input(
                    hybrid.as_ref(),
                    r.branch_id,
                    &mut tx,
                    i,
                    &script,
                    amount,
                    &sk,
                    &pk,
                )?,
                (KeyRef::Pq { .. }, Derived::Pq(k)) => hybrid_sign::sign_pq_input(
                    hybrid.as_ref(),
                    r.branch_id,
                    &mut tx,
                    i,
                    &script,
                    amount,
                    &k,
                )?,
                (KeyRef::Carrier { .. }, Derived::T(sk, pk)) => {
                    let bundle = carrier_bundle(r.inputs[i].carrier_bundle.as_deref())?;
                    let redeem = yew_core::script::carrier_script(&pk, &keys::sha256(&bundle))
                        .map_err(|e| (refuse::FAILED, e.to_string()))?;
                    let digest = digest_of(&tx, i, &redeem, &script, amount)?;
                    tx.vin[i].script_sig =
                        yew_core::script::carrier_script_sig(&bundle, &ecdsa(digest, &sk), &redeem)
                            .map_err(|e| (refuse::FAILED, e.to_string()))?;
                    digest
                }
                (KeyRef::Bond { locktime, .. }, Derived::T(sk, pk)) => {
                    let redeem = act::bond_redeem_script(*locktime, &pk);
                    let digest = digest_of(&tx, i, &redeem, &script, amount)?;
                    let der = ecdsa(digest, &sk);
                    let mut ss = Vec::with_capacity(der.len() + redeem.len() + 4);
                    yew_core::script::push_data(&mut ss, &der);
                    yew_core::script::push_data(&mut ss, &redeem);
                    tx.vin[i].script_sig = ss;
                    digest
                }
                (KeyRef::PqOwner { selector, .. }, Derived::Pq(k)) => {
                    let digest = digest_of(&tx, i, &script, &script, amount)?;
                    let mut sig = k.sign(&digest);
                    sig.push(SIGHASH_ALL as u8);
                    tx.vin[i].script_sig =
                        owner_script_sig(&script, *selector, &sig, k.public_key())?;
                    digest
                }
                _ => return no(refuse::FAILED, "key kind and derivation disagree"),
            };
            sighashes[i] = Some(hex::encode(digest));
        }
        let out = hybrid_sign::finish_signed(hybrid, &tx, rand_core::OsRng)?;
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

    /// The transparent key a role request names, checked to be `pubkey` (the node's record).
    fn role_key(
        &self,
        k: &KeyRef,
        pubkey: &str,
        what: &str,
    ) -> Result<(SecretKey, [u8; 33]), Refused> {
        let (sk, pk) = match *k {
            KeyRef::Bip32 { chain, index } => self.transparent(chain, index)?,
            _ => {
                return no(
                    refuse::KEY_MISMATCH,
                    format!("{what} is made with a transparent key"),
                )
            }
        };
        if hex::encode(pk) != pubkey.to_ascii_lowercase() {
            return no(
                refuse::KEY_MISMATCH,
                format!("the named key is not {what}'s key {pubkey}"),
            );
        }
        Ok((sk, pk))
    }

    /// `SignAttestationGuarded` (S16) once the key is derived: the guard decides before anything
    /// is signed, and the record is on disk before the signature leaves.
    fn guarded_attestation(
        &self,
        sk: &SecretKey,
        pk: &[u8; 33],
        seq: u16,
        price: u32,
        cited: u32,
        block_hash: &str,
    ) -> Result<([u8; 64], bool), Refused> {
        let bh_display = block_hash.to_ascii_lowercase();
        let bh = yew_core::tx::txid_from_hex(&bh_display)
            .map_err(|e| (refuse::MALFORMED, format!("block hash: {e}")))?;
        let pk_hex = hex::encode(pk);
        let mut g = self.attest_guard();
        if let Some(other) = g
            .by_key(&pk_hex, cited, &bh_display)
            .find(|r| r.seq != seq && r.price_micro_usd != price)
        {
            return no(
                refuse::EQUIVOCATION_GUARD,
                format!(
                    "equivocation-guard: this key already signed {} for height {cited} under seq {}",
                    other.price_micro_usd, other.seq
                ),
            );
        }
        if let Some(prior) = g.by_seq(seq, cited, &bh_display) {
            if prior.price_micro_usd != price {
                return no(
                    refuse::EQUIVOCATION_GUARD,
                    format!(
                        "equivocation-guard: seq {seq} already signed {} for height {cited}",
                        prior.price_micro_usd
                    ),
                );
            }
            let sig: [u8; 64] = hex::decode(&prior.sig)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| (refuse::FAILED, "the guard's record is damaged".to_string()))?;
            return Ok((sig, true));
        }
        let msg = yew_core::bundle::attest_message(seq, price, cited, &bh);
        // RFC 6979, low-S (libsecp256k1 normalises), r ‖ s: ycashd's `CKey::Sign` + `DerToCompact`
        let sig =
            secp256k1::ecdsa::sign(secp256k1::Message::from_digest(msg), sk).serialize_compact();
        if !yew_core::bundle::verify_compact_sig(pk, &msg, &sig) {
            return no(refuse::FAILED, "attestation signature does not verify");
        }
        g.record(crate::attest::Signed {
            seq,
            pubkey: pk_hex,
            cited_height: cited,
            block_hash: bh_display,
            price_micro_usd: price,
            sig: hex::encode(sig),
        })
        .map_err(|e| {
            eprintln!("yewd-signer: guard-write-failed: {e}");
            (
                refuse::GUARD_WRITE_FAILED,
                "guard-write-failed: the equivocation guard could not be written; nothing was returned"
                    .to_string(),
            )
        })?;
        Ok((sig, false))
    }

    /// `yed_signattestation`'s signature (S16): one 74-byte attestation through the guard.
    pub fn sign_attestation(&self, r: &AttestRequest) -> Result<AttestSigned, Refused> {
        if (r.price_micro_usd as i64) < yewd_proto::attest::PRICE_MIN {
            return no(
                refuse::ATTEST_RANGE,
                format!(
                    "attest-range: priceMicroUsd must be in [{}, {}]",
                    yewd_proto::attest::PRICE_MIN,
                    yewd_proto::attest::PRICE_MAX
                ),
            );
        }
        let (sk, pk) = self.role_key(&r.key, &r.pubkey, "an attestation")?;
        let (sig, reused) = self.guarded_attestation(
            &sk,
            &pk,
            r.seq,
            r.price_micro_usd,
            r.cited_height,
            &r.block_hash,
        )?;
        let a = yew_core::bundle::Attestation {
            seq: r.seq,
            price_micro_usd: r.price_micro_usd,
            cited_height: r.cited_height,
            sig,
        };
        Ok(AttestSigned {
            hex: hex::encode(a.encode()),
            reused,
        })
    }

    /// `yed_signcancelcosign`'s signature (CAN-2 + C4b): the price statement at `R` locked
    /// through the guard, then the recoverable signature over `CancelCosignMessage`.
    pub fn cancel_cosign(&self, r: &CosignRequest) -> Result<Cosigned, Refused> {
        let (sk, pk) = self.role_key(&r.key, &r.pubkey, "a cancel co-signature")?;
        let bh_display = r.block_hash.to_ascii_lowercase();
        let pk_hex = hex::encode(pk);
        // the price this key already stated for R, under any seq (EQV-1 binds the key)
        let prior: Option<(u16, u32)> = {
            let g = self.attest_guard();
            let mut prior: Option<(u16, u32)> = None;
            for rec in g.by_key(&pk_hex, r.ref_height, &bh_display) {
                if let Some((_, p)) = prior {
                    if p != rec.price_micro_usd {
                        return no(
                            refuse::EQUIVOCATION_GUARD,
                            format!(
                                "equivocation-guard: this key already signed two prices for height {}",
                                r.ref_height
                            ),
                        );
                    }
                }
                prior = Some((rec.seq, rec.price_micro_usd));
            }
            prior
        };
        let price = match (r.price_micro_usd, prior) {
            (Some(p), Some((s, q))) if p != q => {
                return no(
                    refuse::EQUIVOCATION_GUARD,
                    format!(
                        "equivocation-guard: seq {s} already signed {q} for height {}",
                        r.ref_height
                    ),
                )
            }
            (Some(p), _) => p,
            (None, Some((_, q))) => q,
            (None, None) => {
                return no(
                    refuse::PRICE_REQUIRED,
                    format!(
                        "price-required: this key signed no price for the claim's refHeight {}; pass priceMicroUsd",
                        r.ref_height
                    ),
                )
            }
        };
        if (price as i64) < yewd_proto::attest::PRICE_MIN {
            return no(
                refuse::ATTEST_RANGE,
                format!(
                    "attest-range: priceMicroUsd must be in [{}, {}]",
                    yewd_proto::attest::PRICE_MIN,
                    yewd_proto::attest::PRICE_MAX
                ),
            );
        }
        if yewd_proto::attest::is_underwater(
            r.collateral_zat,
            price as i64,
            r.minted_cents,
            r.claim_threshold_bps,
        ) {
            return no(
                refuse::CANCEL_STATEMENT_CLAIMABLE,
                format!(
                    "cancel-statement-claimable: at {price} micro-USD the vault was claimable at refHeight {}; a cancel co-signature states it was not",
                    r.ref_height
                ),
            );
        }
        let (_, reused) =
            self.guarded_attestation(&sk, &pk, r.seq, price, r.ref_height, &bh_display)?;
        let set = yew_core::tx::txid_from_hex(&r.set_id)
            .map_err(|e| (refuse::MALFORMED, format!("set id: {e}")))?;
        let intent = OutPoint::parse(&r.intent)
            .ok_or_else(|| (refuse::MALFORMED, "the intent is not txid:n".to_string()))?;
        let bh = yew_core::tx::txid_from_hex(&bh_display)
            .map_err(|e| (refuse::MALFORMED, format!("block hash: {e}")))?;
        let msg = yewd_proto::attest::cancel_cosign_message(
            &set,
            &intent.txid,
            intent.n,
            r.ref_height,
            price,
            &bh,
        );
        let e = yewd_proto::attest::CosignEntry {
            price_micro_usd: price,
            sig: act::sign_recoverable(&sk, &msg),
        };
        Ok(Cosigned {
            cosig: hex::encode(e.bytes()),
            price_micro_usd: price,
            reused,
        })
    }

    /// `signmessage`: the digest is computed here from the text (the magic prefix first).
    pub fn sign_message(&self, r: &MessageRequest) -> Result<String, Refused> {
        let (sk, _) = match r.key {
            KeyRef::Bip32 { chain, index } => self.transparent(chain, index)?,
            _ => {
                return no(
                    refuse::KEY_MISMATCH,
                    "signmessage signs with a transparent key",
                )
            }
        };
        let h = yewd_proto::attest::message_hash(&r.message);
        Ok(hex::encode(act::sign_recoverable(&sk, &h)))
    }

    /// `importprivkey`: a compressed WIF of this network into the store; a new key brings no
    /// sign-once history (07/F-5): the restore marker is set for a set member, any other new key
    /// is watched for its `SET_JOIN` ([`crate::signonce::SignOnce::key_imported`]).
    pub fn import_key(
        &self,
        wif: &str,
        members: Option<&[String]>,
    ) -> Result<ImportedKey, Refused> {
        drop(self.keys()?);
        let k = keys::decode_wif(self.network, wif.trim()).map_err(|_| {
            (
                refuse::KEY_NOT_HELD,
                "Invalid private key encoding".to_string(),
            )
        })?;
        let (index, new) = self
            .imports()
            .add(k.secret)
            .map_err(|e| (refuse::FAILED, format!("Error adding key to wallet: {e}")))?;
        if new {
            let hash = hex::encode(keys::hash160(&k.pubkey));
            self.lock().key_imported(&hash, members).map_err(|e| {
                (
                    refuse::FAILED,
                    format!("cannot write the vault sign-once restore marker: {e}"),
                )
            })?;
        }
        Ok(ImportedKey {
            index,
            pubkey: hex::encode(k.pubkey),
            new,
        })
    }

    /// `dumpprivkey`: the WIF of a transparent key.
    pub fn dump_key(&self, k: &KeyRef) -> Result<String, Refused> {
        match *k {
            KeyRef::Bip32 { chain, index } => {
                let (sk, _) = self.transparent(chain, index)?;
                Ok(keys::encode_wif(self.network, &sk))
            }
            _ => no(refuse::KEY_MISMATCH, "only a transparent key has a WIF"),
        }
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

fn carrier_bundle(h: Option<&str>) -> Result<Vec<u8>, Refused> {
    hex::decode(h.unwrap_or("")).map_err(|e| (refuse::MALFORMED, format!("carrier bundle: {e}")))
}

/// Whether the derived key owns the script it is to sign.
fn owns_input(k: &KeyRef, d: &Derived, script: &[u8], bundle: Option<&str>) -> Result<(), String> {
    match (k, d) {
        (KeyRef::Carrier { .. }, Derived::T(_, pk)) => {
            let b = hex::decode(bundle.ok_or("a carrier input carries its bundle")?)
                .map_err(|e| e.to_string())?;
            let redeem = yew_core::script::carrier_script(pk, &keys::sha256(&b))
                .map_err(|e| e.to_string())?;
            if yew_core::script::p2sh_of(&redeem) == script {
                Ok(())
            } else {
                Err("the script is not the carrier of the named key and bundle".into())
            }
        }
        (KeyRef::Bond { locktime, .. }, Derived::T(_, pk)) => {
            if act::bond_script_pubkey(*locktime, pk) == script {
                Ok(())
            } else {
                Err("the script is not the bond of the named key and locktime".into())
            }
        }
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
