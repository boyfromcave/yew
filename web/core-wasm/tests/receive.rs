//! Final-run D-1: the browser hands out the YED address the app does. From the Falcon height
//! (mainnet and testnet: the first block) YED is held by Falcon keys only (`bad-yed-holder`), so
//! Receive → YED and the address list must show the 53-character Falcon holder paired with the
//! receive key (`ybf…`/`ytf…`/`yrf…`, D-9), as `core/src/api.rs` `receive_address` and
//! `addresses` do; before it (regtest before its Falcon height) the 35-character P2PKH form.
//! A wallet on OPFS in a dedicated worker, opened without a server (the mainnet terms are
//! compiled in; regtest's come from the server, so a fresh regtest wallet is before Falcon).
//! Needs no server (web/scripts/test-core-wasm.sh: `FUND=0 TESTS=receive`).
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;
use yew_core::keys;
use yew_core::params::Network;
use yew_core::wallet::Wallet;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn s(v: &JsValue, key: &str) -> String {
    js_sys::Reflect::get(v, &key.into())
        .unwrap()
        .as_string()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn open(network: Network, dir: &str) -> Wallet {
    Wallet::open(
        &format!("{dir}/yew-{}.sqlite", network.chain_name()),
        network,
        PHRASE,
        "",
        Some(5),
    )
    .expect("open")
}

#[wasm_bindgen_test]
async fn the_yed_receive_address_is_the_falcon_holder_from_the_falcon_height() {
    yew_web_core::install_storage().await.expect("opfs");
    for (network, prefix) in [(Network::Mainnet, "ybf"), (Network::Testnet, "ytf")] {
        let w = open(
            network,
            &format!("yew-test-receive/{}", network.chain_name()),
        );
        let row = w.receive_address(false).unwrap();
        let holder = w
            .falcon_holder_address(&row)
            .expect("an HD key has a Falcon pair");
        let (pair, list) = yew_web_core::address_forms_of(&w, "yed").unwrap();
        let address = s(&pair, "address");
        assert_eq!(address, holder, "{network:?}: Receive → YED");
        assert_eq!((address.len(), &address[..3]), (53, prefix), "{address}");
        assert_eq!(s(&pair, "ye"), holder);
        assert!(s(&pair, "path").ends_with("(Falcon holder)"));
        // what a sender's node checks: the address names this wallet's Falcon key
        let id = keys::parse_pq_address(network, &address).unwrap();
        assert_eq!(Some(id), w.falcon_holder_id(&row));
        assert_eq!(id.scheme, yew_core::pq::SCHEME_FN_DSA_512);
        // the transparent kind keeps the s… address, with the same YED form beside it
        let (t, _) = yew_web_core::address_forms_of(&w, "transparent").unwrap();
        assert_eq!(s(&t, "address"), row.address_s);
        assert_eq!(s(&t, "ye"), holder);
        // the address list (Settings) shows the Falcon holders too
        let rows = js_sys::Array::from(&list);
        assert!(rows.length() > 0);
        for r in rows.iter() {
            let ye = s(&r, "ye");
            assert_eq!((ye.len(), &ye[..3]), (53, prefix), "{ye}");
        }
        assert!(rows.iter().any(|r| s(&r, "ye") == holder));
    }
    // regtest before its Falcon height (no server terms yet): the P2PKH form, as the app
    let w = open(Network::Regtest, "yew-test-receive/regtest");
    let row = w.receive_address(false).unwrap();
    let (pair, _) = yew_web_core::address_forms_of(&w, "yed").unwrap();
    assert_eq!(s(&pair, "address"), row.address_ye);
    assert_eq!((row.address_ye.len(), &row.address_ye[..2]), (35, "yr"));
}
