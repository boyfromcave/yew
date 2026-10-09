//! Runs in headless Chrome in a dedicated worker (the production prover runs in a Web Worker
//! so the UI thread stays responsive; the Cache API is available there too):
//! web/scripts/test-spike-prover.sh.
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The test script serves the parameter files from a local directory (with CORS) and passes
/// its base URL at compile time; without it the download.z.cash source is tried.
fn sources() -> Vec<&'static str> {
    let mut v = vec![];
    if let Some(local) = option_env!("SPIKE_PARAMS_URL") {
        v.push(local);
    }
    v.extend_from_slice(spike_prover::DEFAULT_SOURCES);
    v
}

#[wasm_bindgen_test]
async fn sapling_spend_and_two_outputs_prove() {
    let t = spike_prover::spike_prove(&sources()).await.expect("prove");
    console_log!(
        "spike-prover: fetch {:.0} ms, parse {:.0} ms, prove(1 spend + 2 outputs) {:.0} ms; \
         memory after parse {} MiB, after prove {} MiB",
        t.fetch_ms,
        t.parse_ms,
        t.prove_ms,
        t.memory_after_parse >> 20,
        t.memory_after_prove >> 20
    );
    assert!(t.prove_ms > 0.0);
}

#[wasm_bindgen_test]
fn pins_refuse_other_bytes() {
    assert!(spike_prover::verify(&spike_prover::OUTPUT, b"not the parameters").is_err());
}
