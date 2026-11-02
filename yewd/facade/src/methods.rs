// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The façade's method table (workspace plan §3b S0, K-25).
//!
//! Every ycashd wallet RPC is listed here by name, so a wallet method is **never forwarded** to
//! the backend: a backend that happens to have a wallet (a ycashd without `-disablewallet`) must
//! not answer for this one. Anything not listed is a node RPC and is forwarded unchanged.
//!
//! The sources are ycash6 `src/rpc/vault.cpp` (the `ENABLE_WALLET` half of its table),
//! `src/rpc/yellowbackwallet.cpp`, `src/wallet/rpcwallet.cpp`, `src/wallet/rpcdump.cpp` and
//! `src/rpc/rawtransaction.cpp` at the revision `yewd/PIN` names; `doc/vault-rpc.md` and
//! `doc/yellowback-rpc.md` define their shapes.

/// What the façade does with a method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A wallet RPC the façade serves (the 47, R7 and the K-25 stock set), tagged with the chunk
    /// that implemented it; one not served (none since S4) answers `-32601 yewd: not yet
    /// implemented`.
    Wallet { group: Group, stage: Stage },
    /// A ycashd wallet RPC outside the façade's scope (K-25 (a)): `-32601`, never forwarded.
    OutOfScope,
    /// A raw-transaction helper ycashd serves without a wallet and Zakura lacks, answered by the
    /// façade itself (S4, `yewd-wallet/src/raw.rs`).
    Local,
    /// A node RPC whose answer carries wallet fields (`ismine`, `mine`, `wallet`, the balance in
    /// `getinfo`). Forwarded; from S1 the façade adds the wallet fields to the backend's answer.
    Augmented,
    /// Answered by the façade itself (`help`, `stop`).
    Own,
}

/// Where a wallet RPC comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// R5: the vault primitive's act and wallet RPCs (`set_*`, `vault_*`), 22.
    Vault,
    /// R6: the YED wallet RPCs (`yed_*`), 25.
    Yed,
    /// R7: the post-quantum wallet RPC beyond the stock set (`z_importpqkey`).
    Pq,
    /// K-25: the 30 stock wallet RPCs the Yellowback functional scripts call.
    Stock,
    /// K-25: the 4 stock wallet RPCs only the roles (attestor, x402) call.
    Role,
}

/// The chunk that implements a wallet RPC (plan §3b).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    S1,
    S2,
    S3,
    S4,
    S5,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Stage::S1 => "S1",
            Stage::S2 => "S2",
            Stage::S3 => "S3",
            Stage::S4 => "S4",
            Stage::S5 => "S5",
        }
    }
}

use Group::*;
use Stage::*;

/// R5: `ycash6/src/rpc/vault.cpp` (the wallet half of `commands[]`), in table order.
pub const VAULT_WALLET: &[(&str, Stage)] = &[
    ("set_create", S2),
    ("set_join", S2),
    ("set_heartbeat", S2),
    ("set_leave", S2),
    ("set_buildact", S2),
    ("set_signact", S2),
    ("set_sendact", S2),
    ("set_equivocation", S2),
    ("vault_lock", S2),
    ("vault_getnewowner", S1),
    ("vault_buildunlock", S2),
    ("set_signunlock", S2),
    ("vault_buildcancel", S2),
    ("set_signcancel", S2),
    ("vault_refee", S2),
    ("set_listsigned", S1),
    ("set_importsigned", S2),
    ("set_acknowledgerestore", S2),
    ("vault_send", S2),
    ("vault_release", S2),
    ("vault_ownerspend", S2),
    ("vault_app", S2),
];

/// R6: `ycash6/src/rpc/yellowbackwallet.cpp` `commands[]`, in table order.
pub const YED_WALLET: &[(&str, Stage)] = &[
    ("yed_getnewaddress", S1),
    ("yed_validateaddress", S1),
    ("yed_getbalance", S1),
    ("yed_listunspent", S1),
    ("yed_mint", S2),
    ("yed_send", S2),
    ("yed_sendmany", S2),
    ("yed_redeem", S2),
    ("yed_claim", S2),
    ("yed_listpositions", S1),
    ("yed_listtransactions", S1),
    ("yed_listaddresses", S1),
    ("yed_lockcoins", S2),
    ("yed_estimatesend", S2),
    ("yed_estimateredeem", S2),
    ("yed_unlockcoin", S2),
    ("yed_buildcancel", S3),
    ("yed_signcancelcosign", S3),
    ("yed_claimnotice", S2),
    ("yed_sweepcarriers", S2),
    ("yed_registerattestor", S3),
    ("yed_withdrawbond", S3),
    ("yed_revive", S3),
    ("yed_reportequivocation", S3),
    ("yed_signattestation", S3),
];

/// R7 beyond the stock set (`getnewaddress "" "pq"` is `getnewaddress`; the dump lines are
/// `z_exportwallet` / `z_importwallet`).
pub const PQ_WALLET: &[(&str, Stage)] = &[("z_importpqkey", S4)];

/// K-25: the 30 stock wallet RPCs the 58 Yellowback functional scripts call (plan §3b S4).
pub const STOCK_WALLET: &[(&str, Stage)] = &[
    ("addmultisigaddress", S4),
    ("backupwallet", S4),
    ("dumpprivkey", S4),
    ("encryptwallet", S4),
    ("fundrawtransaction", S2),
    ("getbalance", S1),
    ("getnewaddress", S1),
    ("getreceivedbyaddress", S1),
    ("gettransaction", S1),
    ("getwalletinfo", S1),
    ("importprivkey", S4),
    ("importwallet", S4),
    ("listlockunspent", S1),
    ("listunspent", S1),
    ("lockunspent", S2),
    ("sendmany", S2),
    ("sendtoaddress", S2),
    ("settxfee", S4),
    ("signrawtransaction", S2),
    ("walletlock", S4),
    ("walletpassphrase", S4),
    ("z_exportwallet", S4),
    ("z_getbalance", S1),
    ("z_getnewaddress", S1),
    ("z_getoperationresult", S4),
    ("z_getoperationstatus", S4),
    ("z_importwallet", S4),
    ("z_listoperationids", S4),
    ("z_listunspent", S1),
    ("z_sendmany", S4),
];

/// K-25: the 4 stock wallet RPCs only the roles call (attestor `signmessage`; x402).
pub const ROLE_WALLET: &[(&str, Stage)] = &[
    ("getrawchangeaddress", S3),
    ("signmessage", S3),
    ("z_getnewdiversifiedaddress", S4),
    ("z_listreceivedbyaddress", S4),
];

/// Stock wallet reads the scripts call beyond K-25's list, found by the S5 gate (F-S5-1):
/// `wallet_pq_address.py`, `yellowback_wallet_restore.py`.
pub const GATE_WALLET: &[(&str, Stage)] = &[
    ("getaddressesbyaccount", S5),
    ("listreceivedbyaddress", S5),
    ("listtransactions", S5),
    ("z_listaddresses", S5),
];

/// The rest of ycashd's wallet table (`src/wallet/rpcwallet.cpp`, `rpcdump.cpp`, the
/// disclosure pair): outside K-25, answered `-32601` and never forwarded.
pub const OUT_OF_SCOPE: &[&str] = &[
    "resendwallettransactions",
    "dumpwallet",
    "z_converttex",
    "getunconfirmedbalance",
    "importaddress",
    "importpubkey",
    "keypoolrefill",
    "listaddresses",
    "listaddressgroupings",
    "listsinceblock",
    "walletpassphrasechange",
    "walletconfirmbackup",
    "zcbenchmark",
    "zcsamplejoinsplit",
    "z_gettotalbalance",
    "z_getbalanceforviewingkey",
    "z_getbalanceforaccount",
    "z_mergetoaddress",
    "z_setmigration",
    "z_getmigrationstatus",
    "z_shieldcoinbase",
    "z_getnewaccount",
    "z_listaccounts",
    "z_listunifiedreceivers",
    "z_getaddressforaccount",
    "z_exportkey",
    "z_importkey",
    "z_exportviewingkey",
    "z_importviewingkey",
    "z_exportivk",
    "z_importivk",
    "z_getalldiversifiedaddresses",
    "z_viewtransaction",
    "z_getnotescount",
    "z_getpaymentdisclosure",
    "z_validatepaymentdisclosure",
];

/// Raw-transaction helpers served locally (S4; Zakura's method table has none of them).
pub const LOCAL: &[&str] = &[
    "createrawtransaction",
    "decoderawtransaction",
    "decodescript",
];

/// Node RPCs whose answers carry wallet fields the façade fills (S1; `yed_getinfo` from S4).
pub const AUGMENTED: &[&str] = &[
    "getinfo",
    "validateaddress",
    "z_validateaddress",
    "set_getinfo",
    "vault_list",
    "yed_gettxinfo",
    "yed_getinfo",
];

/// Answered by the façade itself.
pub const OWN: &[&str] = &["help", "stop"];

/// Every wallet RPC the façade serves, with its group and stage, in table order:
/// R5 (22), R6 (25), R7 (1), the K-25 stock set (30 + 4).
pub fn wallet_methods() -> impl Iterator<Item = (&'static str, Group, Stage)> {
    let g = |t: &'static [(&'static str, Stage)], g: Group| t.iter().map(move |&(m, s)| (m, g, s));
    g(VAULT_WALLET, Vault)
        .chain(g(YED_WALLET, Yed))
        .chain(g(PQ_WALLET, Pq))
        .chain(g(STOCK_WALLET, Stock))
        .chain(g(ROLE_WALLET, Role))
        .chain(g(GATE_WALLET, Stock))
}

/// The class of `method`; `None` = a node RPC, forwarded unchanged.
pub fn classify(method: &str) -> Option<Class> {
    if let Some((_, group, stage)) = wallet_methods().find(|&(m, _, _)| m == method) {
        return Some(Class::Wallet { group, stage });
    }
    if OUT_OF_SCOPE.contains(&method) {
        return Some(Class::OutOfScope);
    }
    if LOCAL.contains(&method) {
        return Some(Class::Local);
    }
    if AUGMENTED.contains(&method) {
        return Some(Class::Augmented);
    }
    if OWN.contains(&method) {
        return Some(Class::Own);
    }
    None
}

/// Whether the façade answers `method` itself in this build (as opposed to forwarding it).
pub fn answered_locally(method: &str) -> bool {
    matches!(
        classify(method),
        Some(Class::Wallet { .. } | Class::OutOfScope | Class::Own | Class::Local)
    )
}

/// The `-32601` message for a wallet RPC not implemented yet.
pub fn not_implemented_message(method: &str, stage: Stage) -> String {
    format!(
        "yewd: not yet implemented ({method}; plan §3b {})",
        stage.name()
    )
}

/// The `-32601` message for a ycashd wallet RPC outside the façade's scope.
pub fn out_of_scope_message(method: &str) -> String {
    format!("yewd: not served ({method} is outside the façade's scope, K-25)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn counts_match_the_plan() {
        assert_eq!(VAULT_WALLET.len(), 22, "R5");
        assert_eq!(YED_WALLET.len(), 25, "R6");
        assert_eq!(VAULT_WALLET.len() + YED_WALLET.len(), 47);
        assert_eq!(STOCK_WALLET.len(), 30, "K-25 scripts");
        assert_eq!(ROLE_WALLET.len(), 4, "K-25 roles");
        assert_eq!(GATE_WALLET.len(), 4, "S5's finding F-S5-1");
        assert_eq!(OUT_OF_SCOPE.len(), 36, "the rest of ycashd's wallet table");
    }

    #[test]
    fn every_name_is_in_one_class_only() {
        let mut seen = HashSet::new();
        let all = wallet_methods()
            .map(|(m, _, _)| m)
            .chain(OUT_OF_SCOPE.iter().copied())
            .chain(LOCAL.iter().copied())
            .chain(AUGMENTED.iter().copied())
            .chain(OWN.iter().copied());
        for m in all {
            assert!(seen.insert(m), "{m} listed twice");
        }
    }

    #[test]
    fn prefixes_follow_the_groups() {
        for &(m, _) in VAULT_WALLET {
            assert!(m.starts_with("set_") || m.starts_with("vault_"), "{m}");
        }
        for &(m, _) in YED_WALLET {
            assert!(m.starts_with("yed_"), "{m}");
        }
    }

    #[test]
    fn node_rpcs_are_forwarded() {
        for m in [
            "getblockchaininfo",
            "getblockcount",
            "generate",
            "sendrawtransaction",
            "vault_getinfo",
        ] {
            assert_eq!(classify(m), None, "{m}");
        }
        assert!(answered_locally("decoderawtransaction"));
        assert!(!answered_locally("validateaddress"));
    }
}
