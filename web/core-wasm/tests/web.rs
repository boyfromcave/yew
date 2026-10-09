//! End to end in headless Chrome, in a dedicated worker (OPFS sync access handles live there),
//! against a lightwalletd gateway that speaks gRPC-web and allows this origin:
//! web/scripts/test-core-wasm.sh (plan §5, W0.5).
//!
//! A fresh wallet (random seed, birthday = tip − 20) syncs to the server's tip and has nothing;
//! then, when the script runs its funding helper (`YEW_WEB_FUND_URL`: `GET /fund?addr=…&zat=…`
//! sends from the devnet node's wallet and mines), the wallet is paid and re-synced until the
//! note shows up.
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const LWD: &str = match option_env!("YEW_WEB_LWD") {
    Some(u) => u,
    None => "http://localhost:9067",
};
const NETWORK: &str = "regtest";
const FUND_ZAT: u64 = 150_000_000;

fn field_u64(v: &wasm_bindgen::JsValue, key: &str) -> u64 {
    js_sys::Reflect::get(v, &key.into())
        .ok()
        .and_then(|x| x.as_f64())
        .unwrap_or_else(|| panic!("{key} missing")) as u64
}

fn field_bool(v: &wasm_bindgen::JsValue, key: &str) -> bool {
    js_sys::Reflect::get(v, &key.into())
        .ok()
        .and_then(|x| x.as_bool())
        .unwrap_or(false)
}

fn now() -> f64 {
    js_sys::Date::now()
}

async fn sleep_ms(ms: i32) {
    let p = js_sys::Promise::new(&mut |resolve, _| {
        let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        scope
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms)
            .unwrap();
    });
    JsFuture::from(p).await.unwrap();
}

/// Asks the script's helper to pay `addr`; answers the txid.
async fn fund(url: &str, addr: &str, zat: u64) -> Result<String, String> {
    let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let full = format!("{url}/fund?addr={addr}&zat={zat}");
    let resp: web_sys::Response = JsFuture::from(scope.fetch_with_str(&full))
        .await
        .map_err(|e| format!("{e:?}"))?
        .unchecked_into();
    let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let text = text.as_string().unwrap_or_default();
    if !resp.ok() {
        return Err(format!("helper: HTTP {} {text}", resp.status()));
    }
    Ok(text.trim().to_string())
}

#[wasm_bindgen_test]
async fn fresh_wallet_syncs_to_the_tip_and_receives_a_payment() {
    yew_web_core::install_storage().await.expect("opfs");
    let words = yew_web_core::new_seed_words().expect("seed");
    let tip0 = yew_web_core::latest_height(LWD, NETWORK)
        .await
        .expect("tip");
    let birthday = tip0.saturating_sub(20).max(1);
    let t0 = now();
    let opened = yew_web_core::open(&words, birthday, LWD, NETWORK)
        .await
        .expect("open");
    let address = yew_web_core::receive_address().expect("address");
    console_log!(
        "yew-web-core: opened in {:.0} ms; server tip {tip0}, birthday {birthday}, vault activation {:?}, address {address}",
        now() - t0,
        js_sys::Reflect::get(&opened, &"vault_activation".into()).ok()
    );
    assert!(address.starts_with("yregtestsapling1"), "{address}");
    assert!(
        !field_bool(&opened, "registered"),
        "a fresh store has no account"
    );

    let t1 = now();
    let r = yew_web_core::sync().await.expect("sync");
    let sync_ms = now() - t1;
    let tip1 = yew_web_core::latest_height(LWD, NETWORK)
        .await
        .expect("tip");
    let (tip, scanned, blocks) = (
        field_u64(&r, "tip"),
        field_u64(&r, "scanned_height"),
        field_u64(&r, "blocks"),
    );
    console_log!(
        "yew-web-core: first sync {sync_ms:.0} ms: tip {tip}, scanned {scanned}, {blocks} blocks, {} outputs, registered_now {}, sendable {}; server tip now {tip1}",
        field_u64(&r, "outputs"),
        field_bool(&r, "registered_now"),
        field_bool(&r, "sendable")
    );
    assert!(field_bool(&r, "registered_now"));
    assert_eq!(scanned, tip, "scanned to the tip of this sync");
    assert!(
        tip >= tip0 && tip + 2 >= tip1,
        "tip0 {tip0} ≤ {tip}, within two of {tip1}"
    );
    assert_eq!(blocks, tip - birthday + 1, "from the birthday to the tip");
    let b = yew_web_core::shielded_balance().expect("balance");
    assert_eq!(field_u64(&b, "total_zat"), 0);
    assert!(field_bool(&b, "registered") && field_bool(&b, "sendable"));

    // A second sync right after: nothing or a block or two.
    let r = yew_web_core::sync().await.expect("sync again");
    assert!(field_u64(&r, "blocks") <= 3, "{}", field_u64(&r, "blocks"));

    let Some(fund_url) = option_env!("YEW_WEB_FUND_URL") else {
        console_log!("yew-web-core: no YEW_WEB_FUND_URL; the funded half is skipped");
        return;
    };
    let t2 = now();
    let txid = fund(fund_url, &address, FUND_ZAT).await.expect("fund");
    console_log!(
        "yew-web-core: funded by {txid} in {:.0} ms; syncing until it lands",
        now() - t2
    );
    let deadline = now() + 240_000.0;
    let mut last = 0;
    loop {
        let r = yew_web_core::sync().await.expect("sync");
        let b = yew_web_core::shielded_balance().expect("balance");
        let total = field_u64(&b, "total_zat");
        if total != last {
            console_log!(
                "yew-web-core: tip {} scanned {} total {total} zat spendable {} pending {} ({} received notes this sync, {} ms)",
                field_u64(&r, "tip"),
                field_u64(&r, "scanned_height"),
                field_u64(&b, "spendable_zat"),
                field_u64(&b, "pending_incoming_zat"),
                field_u64(&r, "received_notes"),
                field_u64(&r, "millis")
            );
            last = total;
        }
        if total >= FUND_ZAT && field_u64(&b, "spendable_zat") >= FUND_ZAT {
            break;
        }
        assert!(
            now() < deadline,
            "the payment did not land within 240 s (total {total})"
        );
        sleep_ms(3000).await;
    }
    console_log!(
        "yew-web-core: payment seen {:.0} ms after the helper answered",
        now() - t2
    );

    // A restore from the chain's first block: the whole chain scanned (the throughput figure),
    // and the store refuses the first seed's account on open (another seed's store).
    yew_web_core::close();
    let other = yew_web_core::new_seed_words().expect("seed");
    let e = yew_web_core::open(&other, 1, LWD, NETWORK)
        .await
        .expect_err("another seed");
    assert!(format!("{e:?}").contains("another seed"), "{e:?}");
    yew_web_core::close();
    let t3 = now();
    let whole = yew_web_core::open_at(&other, 1, LWD, NETWORK, "yew/regtest-restore")
        .await
        .expect("open");
    let _ = whole;
    let r = yew_web_core::sync().await.expect("sync from 1");
    let (tip, blocks, outputs) = (
        field_u64(&r, "tip"),
        field_u64(&r, "blocks"),
        field_u64(&r, "outputs"),
    );
    console_log!(
        "yew-web-core: restore from height 1: {blocks} blocks, {outputs} outputs to tip {tip} in {:.0} ms ({:.0} blocks/s)",
        now() - t3,
        blocks as f64 * 1000.0 / (now() - t3).max(1.0)
    );
    assert_eq!(field_u64(&r, "scanned_height"), tip);
}
