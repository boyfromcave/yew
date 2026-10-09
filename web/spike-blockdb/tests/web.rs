//! Runs in headless Chrome in a dedicated worker (OPFS sync access handles need a worker):
//! web/scripts/test-spike-blockdb.sh.
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn blockdb_persists_on_opfs_across_sessions() {
    let heights = spike_blockdb::spike_roundtrip("spike-blocks.sqlite").await.expect("roundtrip");
    assert_eq!(heights, vec![1, 2, 3]);
}

#[wasm_bindgen_test]
async fn scan_cached_blocks_from_opfs_finds_the_note() {
    let r = spike_blockdb::spike_scan("spike-scan-blocks.sqlite", "spike-scan-wallet.sqlite")
        .await
        .expect("scan");
    assert_eq!(r, vec![1, 100_000, 3], "[received, spendable, fully scanned]");
}
