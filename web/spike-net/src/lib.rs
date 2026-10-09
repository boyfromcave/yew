//! W0.4 spike: yew-core's gRPC-web channel from the browser. The browser tests are in
//! `tests/web.rs`; this crate only re-exports what they call.
pub use yew_core::net::{CompactClient, NetError, Server, YellowbackClient};
pub use yew_core::params::Network;
