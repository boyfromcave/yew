//! Runs in headless Chrome: `web/scripts/test-spike-net.sh`. No lightwalletd listens on the
//! addresses used here, so every call must come back as an error of the connection kind —
//! which proves the channel was built and the request attempted (W0.4: the network layer
//! compiles and runs; a gateway with gRPC-web is W2).
use wasm_bindgen_test::*;

use spike_net::{CompactClient, NetError, Network, Server, YellowbackClient};

wasm_bindgen_test_configure!(run_in_browser);

/// A connection-kind failure: tonic-web-wasm-client surfaces `fetch` failures as a `Status`
/// (never as a transport error, which wasm32 has no variant for).
fn connection_failed(e: &NetError) -> bool {
    matches!(e, NetError::Status(_))
}

#[wasm_bindgen_test]
async fn https_channel_attempts_get_lightd_info() {
    // A TLS endpoint nothing answers on (RFC 2606 name, resolves nowhere).
    let server = Server::parse_for(Network::Mainnet, "lwd.invalid:443", false).unwrap();
    assert_eq!(server.uri(), "https://lwd.invalid:443");
    let mut client = CompactClient::connect(&server).await.expect("the channel builds offline");
    let err = client.lightd_info().await.expect_err("no server listens");
    assert!(connection_failed(&err), "unexpected error: {err}");
}

#[wasm_bindgen_test]
async fn plain_channel_on_a_closed_loopback_port() {
    // Port 9 (discard) on loopback: refused immediately, no DNS involved.
    let server = Server::parse_for(Network::Regtest, "127.0.0.1:9", true).unwrap();
    let mut client = YellowbackClient::connect(&server).await.expect("the channel builds offline");
    let err = client.probe().await.expect_err("no server listens");
    assert!(connection_failed(&err), "unexpected error: {err}");
}

#[wasm_bindgen_test]
async fn a_pinned_certificate_is_refused_in_the_browser() {
    let server = Server::parse_for(Network::Mainnet, "lwd.invalid:443", false)
        .unwrap()
        .with_ca_pem(Some("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".into()));
    let err = CompactClient::connect(&server).await.expect_err("the browser cannot pin");
    assert!(matches!(err, NetError::Config(_)), "unexpected error: {err}");
}
