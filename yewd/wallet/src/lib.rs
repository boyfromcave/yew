// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The wallet behind the façade: state, sync and builders bound directly to yew-core's modules
//! (not its `api.rs`, the Flutter bridge's one global wallet). S1 brings sync and the read
//! RPCs, S2 the builders; S0 links yew-core by path so the daemon builds beside the app and web
//! shells, and holds public material only (plan §4.3 rule 2).

pub use yew_core;

/// The yew-core version this daemon is built on (reported by `getwalletinfo` from S1).
pub const CORE_VERSION: &str = yew_core::VERSION;

/// The vault network upgrade's branch ID, as yew-core signs for it.
pub const VAULT_BRANCH_ID: u32 = yew_core::params::VAULT_BRANCH_ID;

#[cfg(test)]
mod tests {
    #[test]
    fn links_the_core() {
        assert_eq!(super::VAULT_BRANCH_ID, 0x6d5b_7a31);
        assert!(!super::CORE_VERSION.is_empty());
    }
}
