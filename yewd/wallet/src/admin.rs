// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The rest of the K-25 stock set (workspace plan §3b S4): wallet encryption (`encryptwallet`,
//! `walletpassphrase`, `walletlock`), `settxfee`, the wallet files (`backupwallet`,
//! `z_exportwallet`, `importwallet`, `z_importwallet`, R7's `z_importpqkey`), `addmultisigaddress`,
//! and the Sapling address reads `z_getnewdiversifiedaddress`, `z_listreceivedbyaddress`.
//!
//! By ycashd's names, arguments, results and error codes (ycash6 `src/wallet/rpcwallet.cpp`,
//! `src/wallet/rpcdump.cpp`). Every secret stays in the signer (K-24, §4.3 rule 2): the
//! passphrase goes to it, the dump is written by it (the façade composes the public text), an
//! import is read by it, and a backup is written by it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;
use yewd_proto::{
    refuse, BackupRequest, DumpLine, DumpRequest, EncryptRequest, ImportDumpRequest, KeyRef,
    PqImportRequest, PqPublic, Request, Response, UnlockRequest, IMPORTED_PQ_BASE,
};

use crate::build::signer_error;
use crate::json::J;
use crate::keys::{pqkeyid_hex, EXTERNAL, IMPORTED, INTERNAL};
use crate::node::Node;
use crate::rpc::{invalid, p_int, param};
use crate::{code, RpcError, Wallet};

pub const SERVED: &[&str] = &[
    "encryptwallet",
    "walletpassphrase",
    "walletlock",
    "settxfee",
    "backupwallet",
    "z_exportwallet",
    "importwallet",
    "z_importwallet",
    "z_importpqkey",
    "addmultisigaddress",
    "z_getnewdiversifiedaddress",
    "z_listreceivedbyaddress",
];

/// The wallet RPCs a locked wallet refuses (`EnsureWalletIsUnlocked`, or a builder's
/// `wallet-locked`): everything that signs, draws a key or reads a secret.
pub const NEEDS_UNLOCK: &[&str] = &[
    // R5
    "set_create",
    "set_join",
    "set_heartbeat",
    "set_leave",
    "set_buildact",
    "set_signact",
    "set_sendact",
    "set_equivocation",
    "vault_lock",
    "vault_getnewowner",
    "vault_buildunlock",
    "set_signunlock",
    "vault_buildcancel",
    "set_signcancel",
    "vault_refee",
    "vault_send",
    "vault_release",
    "vault_ownerspend",
    "vault_app",
    // R6
    "yed_getnewaddress",
    "yed_mint",
    "yed_send",
    "yed_sendmany",
    "yed_redeem",
    "yed_claim",
    "yed_claimnotice",
    // yed_sweepcarriers: unlock checked only when something lapsed is swept (mint.rs; ycashd reads
    // the outstanding carriers without the passphrase, yellowback_wallet_restore.py)
    "yed_buildcancel",
    "yed_signcancelcosign",
    "yed_registerattestor",
    "yed_withdrawbond",
    "yed_revive",
    "yed_reportequivocation",
    "yed_signattestation",
    // R7 and the stock set
    "z_importpqkey",
    "dumpprivkey",
    "getnewaddress",
    "importprivkey",
    "importwallet",
    "sendmany",
    "sendtoaddress",
    "z_exportwallet",
    "z_getnewaddress",
    "z_importwallet",
    "z_sendmany",
    "signmessage",
    "z_getnewdiversifiedaddress",
];

/// The message of a locked wallet (`EnsureWalletIsUnlocked`, `RPC_WALLET_UNLOCK_NEEDED`).
pub const UNLOCK_NEEDED: &str =
    "Error: Please enter the wallet passphrase with walletpassphrase first.";

/// The wallet's options from the command line (the ycashd wallet arguments the harness hands
/// yewd, K-25 S4).
#[derive(Clone, Debug)]
pub struct Opts {
    /// `-exportdir` (`z_exportwallet`, `backupwallet`).
    pub export_dir: Option<PathBuf>,
    /// `-developerencryptwallet` (yewd allows `encryptwallet` unless it is set to 0; F-S4-3).
    pub encrypt_allowed: bool,
    /// `-paytxfee` / `settxfee`: zat per 1000 bytes (0: the default fee).
    pub paytxfee: i64,
    /// `-paramsdir`: the Sapling parameters (default ycashd's).
    pub params_dir: Option<PathBuf>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            export_dir: None,
            encrypt_allowed: true,
            paytxfee: 0,
            params_dir: None,
        }
    }
}

fn str_arg(p: &[Value], i: usize) -> Result<&str, RpcError> {
    p.get(i)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected"))
}

/// `SanitizeFilename`: alphanumerics only.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

/// `EncodeDumpTime`: `%Y-%m-%dT%H:%M:%SZ`.
pub fn dump_time(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// `EncodeDumpString`: bytes `<= 32`, `>= 128` and `%` as `%xx`.
fn dump_string(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b <= 32 || b >= 128 || b == b'%' {
            out.push_str(&format!("%{b:02x}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

fn now() -> i64 {
    crate::now()
}

impl Wallet {
    pub async fn admin_call(
        &mut self,
        node: &dyn Node,
        method: &str,
        p: &[Value],
    ) -> Result<J, RpcError> {
        match method {
            "encryptwallet" => self.encryptwallet(p),
            "walletpassphrase" => self.walletpassphrase(p),
            "walletlock" => self.walletlock(),
            "settxfee" => self.settxfee(p),
            "backupwallet" => self.backupwallet(p),
            "z_exportwallet" => self.z_exportwallet(node, p).await,
            "importwallet" => self.importwallet(node, p, false).await,
            "z_importwallet" => self.importwallet(node, p, true).await,
            "z_importpqkey" => self.z_importpqkey(node, p).await,
            "addmultisigaddress" => self.addmultisigaddress(p),
            "z_getnewdiversifiedaddress" => self.z_getnewdiversifiedaddress(p),
            "z_listreceivedbyaddress" => self.z_listreceivedbyaddress(p),
            _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
        }
    }

    /// The signer's encryption state: `(encrypted, unlocked_until)` (`(false, 0)` when it cannot
    /// be asked).
    pub fn signer_state(&self) -> (bool, i64) {
        match self.signer.request(Request::Hello) {
            Ok(Response::Hello(h)) => (h.encrypted, h.unlocked_until),
            _ => (false, 0),
        }
    }

    /// `-13` while an encrypted wallet is locked.
    pub fn ensure_unlocked(&self) -> Result<(), RpcError> {
        let (enc, until) = self.signer_state();
        if enc && until == 0 {
            return Err(RpcError::new(code::WALLET_UNLOCK_NEEDED, UNLOCK_NEEDED));
        }
        Ok(())
    }

    fn state_call(&self, r: Request) -> Result<(), RpcError> {
        match self.signer.request(r) {
            Ok(Response::WalletState(_)) => Ok(()),
            other => Err(signer_error(other)),
        }
    }

    /// `encryptwallet "passphrase"`: the signer seals the seed and its imported keys; the façade
    /// then stops (ycashd's `StartShutdown`).
    fn encryptwallet(&mut self, p: &[Value]) -> Result<J, RpcError> {
        if self.signer_state().0 {
            return Err(RpcError::new(
                code::WALLET_WRONG_ENC_STATE,
                "Error: running with an encrypted wallet, but encryptwallet was called.",
            ));
        }
        if !self.opts.encrypt_allowed {
            return Err(RpcError::new(
                code::WALLET_ENCRYPTION_FAILED,
                "Error: wallet encryption is disabled.",
            ));
        }
        let pass = str_arg(p, 0)?;
        if pass.is_empty() {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "encryptwallet <passphrase>\nEncrypts the wallet with <passphrase>.",
            ));
        }
        // the PQ public keys the façade holds go into the signer's public cache
        let mut ranges: Vec<(u8, u32, u32)> = Vec::new();
        for scheme in [1u8, 2] {
            let n = self
                .st
                .public
                .pq
                .iter()
                .filter(|k| k.scheme == scheme && k.index < IMPORTED_PQ_BASE)
                .count() as u32;
            if n > 0 {
                ranges.push((scheme, 0, n));
            }
        }
        self.state_call(Request::Encrypt(EncryptRequest {
            passphrase: pass.to_string(),
            pq: ranges,
        }))
        .map_err(|e| {
            if e.code == code::WALLET_ERROR {
                RpcError::new(
                    code::WALLET_ENCRYPTION_FAILED,
                    "Error: Failed to encrypt the wallet.",
                )
            } else {
                e
            }
        })?;
        Ok(J::Str("wallet encrypted; Ycash server stopping, restart to run with encrypted wallet. The keypool has been flushed, you need to make a new backup.".into()))
    }

    /// `walletpassphrase "passphrase" timeout`.
    fn walletpassphrase(&mut self, p: &[Value]) -> Result<J, RpcError> {
        if !self.signer_state().0 {
            return Err(RpcError::new(
                code::WALLET_WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletpassphrase was called.",
            ));
        }
        let pass = str_arg(p, 0)?;
        if pass.is_empty() {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "walletpassphrase <passphrase> <timeout>\nStores the wallet decryption key in memory for <timeout> seconds.",
            ));
        }
        let timeout = p.get(1).and_then(|v| v.as_i64()).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not an integer as expected")
        })?;
        self.state_call(Request::Unlock(UnlockRequest {
            passphrase: pass.to_string(),
            timeout,
        }))?;
        // the keypool top-up a locked wallet could not do
        let _ = self.refresh_keys();
        let _ = self.save();
        Ok(J::Null)
    }

    /// `walletlock`.
    fn walletlock(&mut self) -> Result<J, RpcError> {
        if !self.signer_state().0 {
            return Err(RpcError::new(
                code::WALLET_WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletlock was called.",
            ));
        }
        self.state_call(Request::Lock)?;
        Ok(J::Null)
    }

    /// `settxfee amount`: the fee rate legacy sends pay (per 1000 bytes), in memory as ycashd's
    /// `payTxFee`.
    fn settxfee(&mut self, p: &[Value]) -> Result<J, RpcError> {
        let v = p.first().cloned().unwrap_or(Value::Null);
        let amount = crate::build::amount_param(&v)?;
        self.opts.paytxfee = amount;
        Ok(J::Bool(true))
    }

    fn export_path(&self, name: &str, what: &str) -> Result<PathBuf, RpcError> {
        let dir = self.opts.export_dir.clone().ok_or_else(|| {
            RpcError::new(
                code::WALLET_ERROR,
                if what == "backup" {
                    "Cannot backup wallet until the -exportdir option has been set".to_string()
                } else {
                    "Cannot export wallet until the zcashd -exportdir option has been set"
                        .to_string()
                },
            )
        })?;
        let clean = sanitize(name);
        if clean != name {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                format!("Filename is invalid as only alphanumeric characters are allowed.  Try '{clean}' instead."),
            ));
        }
        Ok(dir.join(clean))
    }

    /// `backupwallet "destination"`: one file in `-exportdir` with the signer's files and the
    /// façade's state, written by the signer; `-wallet=<it>` (or `<datadir>/<net>/wallet.dat`)
    /// restores it at the next start.
    fn backupwallet(&mut self, p: &[Value]) -> Result<J, RpcError> {
        let name = str_arg(p, 0)?;
        let path = self.export_path(name, "backup")?;
        self.save()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        let facade = serde_json::to_string(&self.st)
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e.to_string()))?;
        match self.signer.request(Request::Backup(BackupRequest {
            path: path.display().to_string(),
            facade,
        })) {
            Ok(Response::Written(p)) => Ok(J::Str(p)),
            Ok(Response::Refused(r)) if r.code == refuse::FAILED => {
                Err(RpcError::new(code::WALLET_ERROR, r.reason))
            }
            other => Err(signer_error(other)),
        }
    }

    /// `z_exportwallet "filename"`: ycashd's dump format; the signer writes it.
    async fn z_exportwallet(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        self.ensure_unlocked()?;
        let name = str_arg(p, 0)?;
        let path = self.export_path(name, "export")?;
        if path.exists() {
            return Err(invalid(format!(
                "Cannot overwrite existing file {}",
                path.display()
            )));
        }
        let height = crate::node::block_count(node).await.unwrap_or(0);
        let best = crate::node::call(node, "getbestblockhash", serde_json::json!([]))
            .await
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        let created = dump_time(self.st.created);
        let text = |t: String| DumpLine::Text { text: t };
        let mut lines = vec![
            text(format!(
                "# Wallet dump created by yewd {}",
                env!("CARGO_PKG_VERSION")
            )),
            text(format!("# * Created on {}", dump_time(now()))),
            text(format!(
                "# * Best block at time of backup was {height} ({best}),"
            )),
            text("# Emergency Recovery Information:".into()),
            DumpLine::Recovery,
            text("# - language=English".into()),
            text(format!("# - fingerprint={}", self.st.public.seed_fp)),
        ];
        if !self.st.public.imported.is_empty() {
            for t in [
                "#",
                "# WARNING: This wallet contains imported keys that are NOT derived",
                "#   from the recovery phrase / HD seed above. Restoring from the",
                "#   recovery phrase ALONE will NOT recover funds held at those",
                "#   imported addresses. Keep this full dump file (or the imported",
                "#   private keys) backed up separately.",
            ] {
                lines.push(text(t.into()));
            }
        }
        lines.push(text(String::new()));
        // transparent keys: the issued ones on both chains, then the imported ones
        let mut tkeys: Vec<(u32, u32)> = (0..self.st.issued.external)
            .map(|i| (EXTERNAL, i))
            .chain((0..self.st.issued.internal).map(|i| (INTERNAL, i)))
            .collect();
        tkeys.extend((0..self.st.public.imported.len() as u32).map(|i| (IMPORTED, i)));
        for (chain, index) in tkeys {
            let Some(k) = self.book.key(chain, index) else {
                continue;
            };
            let addr = yew_core::keys::encode_p2pkh(self.network, &k.hash);
            let tag = match self.st.book.get(&addr) {
                Some(e) => format!("label={}", dump_string(&e.label)),
                None if chain == EXTERNAL => "reserve=1".into(),
                None => "change=1".into(),
            };
            let path = if chain == IMPORTED {
                String::new()
            } else {
                format!(
                    " hdkeypath=m/44'/347'/0'/{chain}/{index} seedfp={}",
                    self.st.public.seed_fp
                )
            };
            lines.push(DumpLine::Key {
                key: KeyRef::Bip32 { chain, index },
                rest: format!("{created} {tag} # addr={addr}{path}"),
            });
        }
        lines.push(text(String::new()));
        lines.push(text(
            "# Post-quantum keys (pqseed=<scheme>:<index>:<seed>)".into(),
        ));
        let mut pq: Vec<PqPublic> = self
            .st
            .public
            .pq
            .iter()
            .filter(|k| k.index >= IMPORTED_PQ_BASE || k.index < self.st.pq_issued(k.scheme))
            .cloned()
            .collect();
        pq.sort_by_key(|k| (k.index >= IMPORTED_PQ_BASE, k.scheme, k.index));
        for k in pq {
            let Some(own) = self.book.pq_key(k.scheme, k.index) else {
                continue;
            };
            let id = own.id;
            lines.push(DumpLine::PqSeed {
                scheme: k.scheme,
                index: k.index,
                index_text: if k.index >= IMPORTED_PQ_BASE {
                    u32::MAX.to_string()
                } else {
                    k.index.to_string()
                },
                rest: format!(
                    "{created} # owner={} addr={} yecaddr={}",
                    pqkeyid_hex(&id),
                    yew_core::keys::encode_pq_yellowback(self.network, &id).unwrap_or_default(),
                    yew_core::keys::encode_pq_yec(self.network, &id).unwrap_or_default()
                ),
            });
        }
        lines.push(text(String::new()));
        // the sign-once history and the remembered builds (07/F-5, 01/V-2)
        let records = match self.signer.request(Request::ListSigned) {
            Ok(Response::Records(r)) => r.records,
            other => return Err(signer_error(other)),
        };
        lines.push(text("# Vault set sign-once history (vaultsetsig=<setid>:<txid>:<n>:<role>:<sighash>); import it before a restored".into()));
        lines.push(text(
            "# member key signs (doc/vault-rpc.md, \"Sign once\")".into(),
        ));
        lines.push(text(format!("vaultsetsigs={} # records", records.len())));
        for r in &records {
            let (txid, n) = r
                .prevout
                .split_once(':')
                .unwrap_or((r.prevout.as_str(), "0"));
            lines.push(text(format!(
                "vaultsetsig={}:{txid}:{n}:{}:{} # {}",
                r.setid,
                r.role,
                r.sighash,
                if r.role == 1 { "unlock" } else { "cancel" }
            )));
        }
        for (op, hexs) in &self.st.builds {
            let (txid, n) = op.split_once(':').unwrap_or((op.as_str(), "0"));
            lines.push(text(format!(
                "vaultbuild={txid}:{n}:{hexs} # remembered vault build"
            )));
        }
        for (h, sc) in &self.st.recipients {
            lines.push(text(format!("vaultrecipient={h}:{sc} # intent recipient")));
        }
        lines.push(text(String::new()));
        lines.push(text(String::new()));
        lines.push(text("# Zkeys".into()));
        lines.push(text(String::new()));
        lines.push(text(String::new()));
        lines.push(text("# Sapling keys".into()));
        lines.push(text(String::new()));
        let mut idx = self.st.issued.sapling.clone();
        if idx.is_empty() {
            idx.push(self.view.address_at(0).map(|a| a.0).unwrap_or(0));
        }
        for j in idx {
            if let Some((_, addr)) = self.view.address_at(j) {
                lines.push(DumpLine::Sapling {
                    rest: format!(
                        "{created} m/32'/347'/0' {} # zaddr={addr}",
                        self.st.public.seed_fp
                    ),
                });
            }
        }
        lines.push(text(String::new()));
        lines.push(text("# End of dump".into()));
        match self.signer.request(Request::Dump(DumpRequest {
            path: path.display().to_string(),
            lines,
        })) {
            Ok(Response::Written(p)) => Ok(J::Str(p)),
            Ok(Response::Refused(r)) if r.code == refuse::FAILED => {
                Err(RpcError::new(code::INVALID_PARAMETER, r.reason))
            }
            other => Err(signer_error(other)),
        }
    }

    /// `importwallet "filename"` / `z_importwallet "filename"`: the signer reads the dump and
    /// keeps its secrets; the façade watches the new keys and rescans.
    async fn importwallet(
        &mut self,
        node: &dyn Node,
        p: &[Value],
        zkeys: bool,
    ) -> Result<J, RpcError> {
        self.ensure_unlocked()?;
        let path = str_arg(p, 0)?;
        let r = match self.signer.request(Request::ImportDump(ImportDumpRequest {
            path: path.to_string(),
            zkeys,
        })) {
            Ok(Response::ImportedDump(r)) => r,
            Ok(Response::Refused(r)) if r.code == refuse::MALFORMED => {
                let c = if r.reason.starts_with("malformed vaultsetsig") {
                    code::DESERIALIZATION_ERROR
                } else {
                    code::INVALID_PARAMETER
                };
                return Err(RpcError::new(c, r.reason));
            }
            Ok(Response::Refused(r))
                if r.code == refuse::FAILED || r.code == refuse::SET_SIGN_ONCE =>
            {
                return Err(RpcError::new(code::WALLET_ERROR, r.reason))
            }
            other => return Err(signer_error(other)),
        };
        if r.skipped_zkeys > 0 {
            eprintln!(
                "yewd: {}: {} Sapling key(s) of another account not imported (the signer spends its own account only; F-S4-6)",
                path, r.skipped_zkeys
            );
        }
        self.absorb_imports(&r.keys, &r.pq)?;
        for (op, h) in r.builds {
            self.st.builds.entry(op).or_insert(h);
        }
        for (h, sc) in r.recipients {
            self.st.recipients.entry(h).or_insert(sc);
        }
        self.save()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        // ycashd rescans from the oldest key's time: the whole chain here
        self.st.birthday = 0;
        self.rewind(None);
        self.sync(node).await?;
        // audit C-1 / H8: the imported YED outputs are locked before the RPC returns, so no plain
        // YEC selection spends them (yellowback_wallet_restore.py); a node without a live Yellowback
        // has none to read
        if let Ok(tokens) = self.tokens(node).await {
            for t in tokens {
                if let (Some(txid), Some(vout)) = (t["txid"].as_str(), t["vout"].as_u64()) {
                    self.st.locks.insert(format!("{txid}:{vout}"));
                }
            }
            self.save()
                .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        }
        Ok(J::Null)
    }

    /// Watch the keys an import added: transparent keys by their store index, PQ keys by theirs.
    fn absorb_imports(
        &mut self,
        keys: &[(yewd_proto::ImportedKey, Option<String>)],
        pq: &[yewd_proto::PqImported],
    ) -> Result<(), RpcError> {
        for (k, label) in keys {
            let idx = k.index as usize;
            if self.st.public.imported.len() <= idx {
                self.st.public.imported.resize(idx + 1, String::new());
            }
            self.st.public.imported[idx] = k.pubkey.clone();
            if let (Some(l), Ok(pk)) = (label, hex::decode(&k.pubkey)) {
                let addr =
                    yew_core::keys::encode_p2pkh(self.network, &yew_core::keys::hash160(&pk));
                self.st.book.insert(
                    addr,
                    crate::state::BookEntry {
                        label: l.clone(),
                        purpose: "receive".into(),
                    },
                );
            }
        }
        for q in pq {
            if !q.own
                && !self
                    .st
                    .public
                    .pq
                    .iter()
                    .any(|k| k.scheme == q.scheme && k.index == q.index)
            {
                self.st.public.pq.push(PqPublic {
                    scheme: q.scheme,
                    index: q.index,
                    pk: q.pk.clone(),
                });
            }
        }
        self.refresh_keys()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))
    }

    /// `z_importpqkey "pqseed" ( rescan "label" )` (R7).
    async fn z_importpqkey(&mut self, node: &dyn Node, p: &[Value]) -> Result<J, RpcError> {
        self.ensure_unlocked()?;
        let line = str_arg(p, 0)?.trim().to_string();
        let words: Vec<&str> = line.split([' ', '\t']).filter(|w| !w.is_empty()).collect();
        let mut arg = words.first().copied().unwrap_or("");
        if let Some(a) = arg.strip_prefix("pqseed=") {
            arg = a;
        }
        let mut expect: BTreeMap<&str, String> = BTreeMap::new();
        for w in words.iter().skip(1) {
            for k in ["owner=", "addr=", "yecaddr="] {
                if let Some(v) = w.strip_prefix(k) {
                    expect.insert(&k[..k.len() - 1], v.to_string());
                }
            }
        }
        let f: Vec<&str> = arg.split(':').collect();
        let bad_shape =
            || invalid("pqseed must be \"<scheme>:<seed hex>\" or \"<scheme>:<index>:<seed hex>\"");
        if f.len() != 2 && f.len() != 3 {
            return Err(bad_shape());
        }
        let scheme: i64 = f[0].parse().map_err(|_| bad_shape())?;
        let index: Option<u32> = if f.len() == 3 {
            let i: i64 = f[1].parse().map_err(|_| bad_shape())?;
            if !(0..=u32::MAX as i64).contains(&i) {
                return Err(invalid("invalid post-quantum key seed or index"));
            }
            Some(i as u32)
        } else {
            None
        };
        if !(0..=255).contains(&scheme) || !yew_core::pq::is_known_scheme(scheme as u8) {
            return Err(invalid(
                "unknown post-quantum scheme (1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512)",
            ));
        }
        let scheme = scheme as u8;
        let hexs = f[f.len() - 1];
        let size = yew_core::pq::SEED_SIZE;
        if hexs.len() != 2 * size || !hexs.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid(format!("the seed must be {size} bytes of hex")));
        }
        if !expect.is_empty() {
            // the line's fields must name the key its seed makes (the seed is in this process
            // already: it is the RPC argument; the key made from it is dropped here)
            let mut seed = hex::decode(hexs).unwrap_or_default();
            let probe = yew_core::pq::PqKey::from_seed(scheme, &seed)
                .map_err(|_| invalid("invalid post-quantum key seed or index"));
            yew_core::keys::wipe(&mut seed);
            let id = probe?.id();
            let have: BTreeMap<&str, String> = [
                ("owner", pqkeyid_hex(&id)),
                (
                    "addr",
                    yew_core::keys::encode_pq_yellowback(self.network, &id).unwrap_or_default(),
                ),
                (
                    "yecaddr",
                    yew_core::keys::encode_pq_yec(self.network, &id).unwrap_or_default(),
                ),
            ]
            .into_iter()
            .collect();
            for (k, v) in &expect {
                if *v != have[k] {
                    return Err(RpcError::new(code::INVALID_ADDRESS_OR_KEY, format!(
                        "the line's {k}={v} does not match the key its seed makes under scheme {scheme} ({}); nothing imported",
                        have["yecaddr"]
                    )));
                }
            }
        }
        let rescan = match param(p, 1) {
            None => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                return Err(RpcError::new(
                    code::MISC_ERROR,
                    "JSON value is not a boolean as expected",
                ))
            }
        };
        let label = match param(p, 2) {
            None => String::new(),
            Some(v) => v
                .as_str()
                .ok_or_else(|| {
                    RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
                })?
                .to_string(),
        };
        let q = match self.signer.request(Request::ImportPq(PqImportRequest {
            scheme,
            index,
            seed: hexs.to_string(),
        })) {
            Ok(Response::ImportedPq(q)) => q,
            Ok(Response::Refused(r)) if r.code == refuse::MALFORMED => {
                return Err(invalid(r.reason))
            }
            other => return Err(signer_error(other)),
        };
        self.absorb_imports(&[], std::slice::from_ref(&q))?;
        let pk = hex::decode(&q.pk).unwrap_or_default();
        let id = yew_core::pq::PqKeyId::of(scheme, &pk);
        let address = yew_core::keys::encode_pq_yec(self.network, &id).unwrap_or_default();
        self.st.book.insert(
            address.clone(),
            crate::state::BookEntry {
                label,
                purpose: "receive".into(),
            },
        );
        self.save()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        if q.added && rescan {
            self.st.birthday = 0;
            self.rewind(None);
            self.sync(node).await?;
        }
        Ok(J::obj()
            .with("scheme", scheme as i64)
            .with("keyhash", hex::encode(id.hash))
            .with("pqkeyid", pqkeyid_hex(&id))
            .with("address", address)
            .with(
                "index",
                if q.own {
                    J::Int(q.index as i64)
                } else {
                    J::Null
                },
            )
            .with("added", q.added))
    }

    /// `addmultisigaddress nrequired ["key",...] ( "" )` (`_createmultisig_redeemScript`): the
    /// P2SH address of an m-of-n multisig, its redeem script kept (validateaddress shows it).
    fn addmultisigaddress(&mut self, p: &[Value]) -> Result<J, RpcError> {
        if let Some(v) = param(p, 2) {
            if v.as_str() != Some("") {
                return Err(invalid("dummy argument must be excluded or set to \"\"."));
            }
        }
        let label = String::new();
        let required = p_int(p, 0, 0)?;
        let keys = p.get(1).and_then(|v| v.as_array()).ok_or_else(|| {
            RpcError::new(code::MISC_ERROR, "JSON value is not an array as expected")
        })?;
        if required < 1 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "a multisignature address must require at least one key to redeem",
            ));
        }
        if (keys.len() as i64) < required {
            return Err(RpcError::new(
                code::MISC_ERROR,
                format!(
                "not enough keys supplied (got {} keys, but need at least {required} to redeem)",
                keys.len()
            ),
            ));
        }
        if keys.len() > 16 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                "Number of addresses involved in the multisignature address creation > 16\nReduce the number",
            ));
        }
        let mut pubkeys: Vec<Vec<u8>> = Vec::new();
        for k in keys {
            let ks = k.as_str().ok_or_else(|| {
                RpcError::new(code::MISC_ERROR, "JSON value is not a string as expected")
            })?;
            if let Some(script) = crate::rpc::parse_taddr_script(self.network, ks) {
                let h = yew_core::script::p2pkh_hash(&script).ok_or_else(|| {
                    RpcError::new(code::MISC_ERROR, format!("{ks} does not refer to a key"))
                })?;
                let tk = self.book.by_hash(&h).ok_or_else(|| {
                    RpcError::new(
                        code::MISC_ERROR,
                        format!("no full public key for address {ks}"),
                    )
                })?;
                pubkeys.push(tk.pubkey.to_vec());
            } else {
                let b = hex::decode(ks)
                    .ok()
                    .filter(|b| secp256k1::PublicKey::from_slice(b).is_ok());
                match b {
                    Some(b) => pubkeys.push(b),
                    None => {
                        return Err(RpcError::new(
                            code::MISC_ERROR,
                            format!(" Invalid public key: {ks}"),
                        ))
                    }
                }
            }
        }
        let mut script = vec![0x50 + required as u8];
        for pk in &pubkeys {
            script.push(pk.len() as u8);
            script.extend_from_slice(pk);
        }
        script.push(0x50 + pubkeys.len() as u8);
        script.push(0xae); // OP_CHECKMULTISIG
        if script.len() > 520 {
            return Err(RpcError::new(
                code::MISC_ERROR,
                format!("redeemScript exceeds size limit: {} > 520", script.len()),
            ));
        }
        let h = yew_core::keys::hash160(&script);
        let addr = yew_core::keys::encode_p2sh(self.network, &h);
        self.st.scripts.insert(addr.clone(), hex::encode(&script));
        self.st.book.insert(
            addr.clone(),
            crate::state::BookEntry {
                label,
                purpose: "send".into(),
            },
        );
        self.save()
            .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
        Ok(J::Str(addr))
    }

    /// `z_getnewdiversifiedaddress "zaddr"`: the next unused diversified address of the account.
    fn z_getnewdiversifiedaddress(&mut self, p: &[Value]) -> Result<J, RpcError> {
        let a = str_arg(p, 0)?;
        if !yew_core::shielded_keys::is_sapling_address(self.network, a) {
            return Err(RpcError::new(code::INVALID_ADDRESS_OR_KEY, "Invalid zaddr"));
        }
        let Some(j0) = self.view.owns_address(a) else {
            return Err(RpcError::new(
                code::WALLET_ERROR,
                "Wallet does not hold the spending key for this zaddr",
            ));
        };
        let mut j = j0 + 1;
        loop {
            let (jj, addr) = self.view.address_at(j).ok_or_else(|| {
                RpcError::new(
                    code::WALLET_ERROR,
                    "Diversifier space exhausted; no new address could be derived",
                )
            })?;
            if !self.st.issued.sapling.contains(&jj) {
                self.st.issued.sapling.push(jj);
                self.save()
                    .map_err(|e| RpcError::new(code::WALLET_ERROR, e))?;
                return Ok(J::Str(addr));
            }
            j = jj + 1;
        }
    }

    /// `z_listreceivedbyaddress "address" ( minconf asOfHeight )`: the notes (or, for a
    /// transparent address, the outputs) the address received.
    fn z_listreceivedbyaddress(&self, p: &[Value]) -> Result<J, RpcError> {
        let a = str_arg(p, 0)?;
        let asof = match p_int(p, 2, -1)? {
            -1 => None,
            h if h < 0 => {
                return Err(invalid(
                    "Can not perform the query as of a negative block height",
                ))
            }
            h => Some(h as u32),
        };
        let min = p_int(p, 1, 1)?;
        if min < 0 {
            return Err(invalid("Invalid parameter, minconf must be non-negative"));
        }
        let mut rows = Vec::new();
        if let Some(script) = crate::rpc::parse_taddr_script(self.network, a) {
            if self.book.owns_script(&script).is_none() {
                return Err(RpcError::new(code::INVALID_ADDRESS_OR_KEY, "From address does not belong to this node, zaddr spending key or viewing key not found."));
            }
            for c in self.coins.iter().filter(|c| c.script == script) {
                let d = self.depth_asof(c.height, asof);
                if d < min {
                    continue;
                }
                let b = self.block_of(&c.txid);
                rows.push(
                    J::obj()
                        .with("pool", "transparent")
                        .with("txid", c.txid.clone())
                        .with("amount", J::Amount(c.value))
                        .with("amountZat", c.value)
                        .with("outindex", c.vout)
                        .with("confirmations", d)
                        .with("change", self.book.is_change_script(&script))
                        .with("blockheight", b.0)
                        .with("blockindex", b.1)
                        .with("blocktime", b.2),
                );
            }
            return Ok(J::Arr(rows));
        }
        if !yew_core::shielded_keys::is_sapling_address(self.network, a) {
            return Err(RpcError::new(
                code::INVALID_ADDRESS_OR_KEY,
                "Invalid zaddr.",
            ));
        }
        if self.view.owns_address(a).is_none() {
            return Err(RpcError::new(code::INVALID_ADDRESS_OR_KEY, "From address does not belong to this node, zaddr spending key or viewing key not found."));
        }
        let mut notes: Vec<_> = self.notes.iter().filter(|n| n.address == a).collect();
        notes.sort_by(|x, y| (&x.txid, x.outindex).cmp(&(&y.txid, y.outindex)));
        for n in notes {
            let d = self.depth_asof(n.height, asof);
            if d < min {
                continue;
            }
            let b = self.block_of(&n.txid);
            let mut o = J::obj()
                .with("pool", "sapling")
                .with("txid", n.txid.clone())
                .with("amount", J::Amount(n.value as i64))
                .with("amountZat", n.value as i64)
                .with("memo", hex::encode(n.memo));
            if let Some(s) = crate::rpc::memo_str(&n.memo) {
                o.push("memoStr", J::Str(s));
            }
            o.push("outindex", J::Int(n.outindex as i64));
            o.push("confirmations", J::Int(d));
            o.push("blockheight", J::Int(b.0));
            o.push("blockindex", J::Int(b.1));
            o.push("blocktime", J::Int(b.2));
            o.push("change", J::Bool(n.internal));
            rows.push(o);
        }
        Ok(J::Arr(rows))
    }

    fn depth_asof(&self, height: Option<u32>, asof: Option<u32>) -> i64 {
        let top = asof
            .map(|a| a.min(self.tip_height()))
            .unwrap_or(self.tip_height());
        match height {
            Some(h) if h <= top => (top - h + 1) as i64,
            Some(_) => -1,
            None if asof.is_some() => -1,
            None => 0,
        }
    }

    /// `txblock`: (height, index in the block, block time), `-1`s for the mempool.
    fn block_of(&self, txid: &str) -> (i64, i64, i64) {
        match self.st.wtx.get(txid).and_then(|w| w.block.as_ref()) {
            Some(b) => (b.height as i64, b.index as i64, b.time),
            None => (-1, -1, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_time_and_string() {
        assert_eq!(dump_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(dump_time(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(dump_string("a b%c"), "a%20b%25c");
        assert_eq!(sanitize("ab/c.d1"), "abcd1");
    }
}
