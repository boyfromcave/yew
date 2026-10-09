//! yew-web-core: the browser binding of the YEW core (plan `docs/plans/yew-web-plan.md`).
//!
//! Every exported function is a thin `wasm_bindgen` wrapper over the same internal functions
//! `core/src/api.rs` exposes to Dart; no wallet logic lives here. W0 fills this in once
//! `yew-core` compiles for `wasm32-unknown-unknown` (feature `core`).
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct Status {
    version: &'static str,
    server: Option<String>,
}

/// The core's version and connection state (mirrors `api::status`).
#[wasm_bindgen]
pub async fn status() -> Result<JsValue, JsValue> {
    let s = Status { version: concat!(env!("CARGO_PKG_VERSION"), "-wasm"), server: None };
    serde_wasm_bindgen::to_value(&s).map_err(|e| JsValue::from_str(&e.to_string()))
}
