//! Runs in headless Chrome in a dedicated worker (OPFS sync access handles need a worker):
//! `wasm-pack test --headless --chrome` from web/spike-sqlite.
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn sqlite_persists_on_opfs() {
    let n = spike_sqlite::spike_persist("spike-persist.sqlite").await.expect("persist");
    assert_eq!(n, 42);
}

#[wasm_bindgen_test]
async fn wallet_db_migrates_on_opfs() {
    let tables = spike_sqlite::spike_wallet("spike-wallet.sqlite").await.expect("wallet");
    assert!(tables > 10, "schema has {tables} tables");
}
