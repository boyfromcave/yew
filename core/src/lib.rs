//! `yew-core`: the Rust core of YEW ("Your Electronic Wallet"), a transparent-only mobile
//! wallet for YEC and Ycash Yellowback (YED).
//!
//! Every wire byte, script byte, key and signature of the wallet lives here; the Flutter app is a
//! view over [`api`]. Plan: `docs/plans/yellowback-wallet-plan.md` (workspace), §3.
//! Modules are stubs in Phase W0a; each names its translation source (plan §3.6).

pub mod api;
pub mod build;
pub mod bundle;
pub mod coins;
pub mod coinselect;
pub mod gate;
pub mod keys;
pub mod net;
pub mod params;
pub mod payload;
pub mod script;
pub mod store;
pub mod sync;
pub mod tx;

/// Crate version, as pinned in the workspace `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
