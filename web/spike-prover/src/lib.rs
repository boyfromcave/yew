//! W0 spike (yew/web plan §2, W0.3): the Sapling prover on wasm32 in a browser worker.
//! 1. the two parameter files reach the prover as bytes: fetched (Cache API first, then the
//!    configured sources in order) and refused unless their length and SHA-256 equal the pins
//!    `core/src/sapling_params.rs` carries — no filesystem anywhere;
//! 2. `LocalTxProver::from_bytes` parses them (zcash_proofs without `local-prover`/`multicore`);
//! 3. a Sapling bundle with one spend and two outputs is built, proved and signed with it, the
//!    way `zcash_primitives`' own builder tests do, and the wall time is measured.
use rand::{rngs::OsRng, Rng};
use sapling_crypto::{
    builder::{Builder, BundleType},
    note_encryption::Zip212Enforcement,
    value::NoteValue,
    zip32::ExtendedSpendingKey,
    Anchor, CommitmentTree, IncrementalWitness, Node, Rseed,
};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zcash_proofs::prover::LocalTxProver;

/// The parameter pins, verbatim from `core/src/sapling_params.rs` (`SPEND`, `OUTPUT`,
/// `DEFAULT_SOURCES`): the sums of the upstream Zcash `fetch-params.sh`. The core module itself
/// is not linked here because the rest of `yew-core` is not wasm-ready yet (W0.4).
pub struct ParamFile {
    pub name: &'static str,
    pub bytes: u64,
    pub sha256: &'static str,
}
pub const SPEND: ParamFile = ParamFile {
    name: "sapling-spend.params",
    bytes: 47_958_396,
    sha256: "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13",
};
pub const OUTPUT: ParamFile = ParamFile {
    name: "sapling-output.params",
    bytes: 3_592_860,
    sha256: "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4",
};
pub const DEFAULT_SOURCES: &[&str] = &["https://download.z.cash/downloads/"];
/// The Cache API cache the verified files are kept in (the browser's replacement for the
/// `~/.cache` / `Application Support` directory the native YEW uses).
pub const CACHE_NAME: &str = "yew-sapling-params-v1";

fn js(e: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("{e:?}"))
}

fn scope() -> web_sys::WorkerGlobalScope {
    js_sys::global().unchecked_into()
}

/// The wall clock: `Instant` is unavailable on wasm32-unknown-unknown; `performance.now()`.
pub fn now_ms() -> f64 {
    scope().performance().map(|p| p.now()).unwrap_or_else(|| js_sys::Date::now())
}

/// The linear memory size in bytes (grows, never shrinks: a peak, not a live figure).
pub fn memory_bytes() -> u32 {
    let mem: js_sys::WebAssembly::Memory = wasm_bindgen::memory().unchecked_into();
    js_sys::ArrayBuffer::from(mem.buffer()).byte_length()
}

async fn response_bytes(resp: &web_sys::Response) -> Result<Vec<u8>, JsValue> {
    let buf = JsFuture::from(resp.array_buffer()?).await?;
    Ok(js_sys::Uint8Array::new(&buf).to_vec())
}

/// Refuses bytes whose length or SHA-256 differ from the pin.
pub fn verify(f: &ParamFile, data: &[u8]) -> Result<(), String> {
    let sha = hex(&Sha256::digest(data));
    if data.len() as u64 != f.bytes || sha != f.sha256 {
        return Err(format!(
            "{}: got {} bytes with SHA-256 {sha}, expected {} bytes with SHA-256 {}; refused",
            f.name,
            data.len(),
            f.bytes,
            f.sha256
        ));
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One parameter file as verified bytes: the Cache API copy if there is one, else the first of
/// `sources` (base URLs ending in `/`) that serves bytes matching the pin, which is then cached.
pub async fn fetch_param(f: &ParamFile, sources: &[&str]) -> Result<Vec<u8>, JsValue> {
    let caches = scope().caches()?;
    let cache: web_sys::Cache = JsFuture::from(caches.open(CACHE_NAME)).await?.unchecked_into();
    let key = format!("/{}", f.name);
    let hit = JsFuture::from(cache.match_with_str(&key)).await?;
    if !hit.is_undefined() {
        let data = response_bytes(&hit.unchecked_into()).await?;
        if verify(f, &data).is_ok() {
            return Ok(data);
        }
        // A cache entry that no longer matches the pin is dropped, not used.
        JsFuture::from(cache.delete_with_str(&key)).await?;
    }
    let mut errors = vec![];
    for base in sources {
        let url = format!("{base}{}", f.name);
        let resp: web_sys::Response = match JsFuture::from(scope().fetch_with_str(&url)).await {
            Ok(r) => r.unchecked_into(),
            Err(e) => {
                errors.push(format!("{url}: {e:?}"));
                continue;
            }
        };
        if !resp.ok() {
            errors.push(format!("{url}: HTTP {}", resp.status()));
            continue;
        }
        let data = response_bytes(&resp).await?;
        if let Err(e) = verify(f, &data) {
            errors.push(format!("{url}: {e}"));
            continue;
        }
        let body = js_sys::Uint8Array::from(data.as_slice());
        let cached = web_sys::Response::new_with_opt_buffer_source(Some(&body))?;
        JsFuture::from(cache.put_with_str(&key, &cached)).await?;
        return Ok(data);
    }
    Err(js(errors))
}

/// What the spike measured, in milliseconds and bytes.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Default)]
pub struct Timings {
    pub fetch_ms: f64,
    pub parse_ms: f64,
    pub prove_ms: f64,
    pub memory_after_parse: u32,
    pub memory_after_prove: u32,
}

/// Fetches and verifies the parameters, parses them into a prover, and proves one Sapling
/// spend + two outputs; the bundle is signed to show the proved bundle is complete.
pub async fn spike_prove(sources: &[&str]) -> Result<Timings, JsValue> {
    let mut t = Timings::default();
    let t0 = now_ms();
    let spend = fetch_param(&SPEND, sources).await?;
    let output = fetch_param(&OUTPUT, sources).await?;
    t.fetch_ms = now_ms() - t0;

    let t0 = now_ms();
    let prover = LocalTxProver::from_bytes(&spend, &output);
    drop((spend, output));
    t.parse_ms = now_ms() - t0;
    t.memory_after_parse = memory_bytes();

    let t0 = now_ms();
    prove_one_spend_two_outputs(&prover).map_err(js)?;
    t.prove_ms = now_ms() - t0;
    t.memory_after_prove = memory_bytes();
    Ok(t)
}

/// As `zcash_primitives/src/transaction/builder.rs` `binding_sig_present_if_shielded_spend`
/// (minus the transaction around it): a note in a one-leaf tree, spent to two outputs.
pub fn prove_one_spend_two_outputs(prover: &LocalTxProver) -> Result<(), String> {
    let mut rng = OsRng;
    let extsk = ExtendedSpendingKey::master(&[0u8; 32]);
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let to = dfvk.default_address().1;

    let note = to.create_note(
        NoteValue::from_raw(50_000),
        Rseed::AfterZip212(rng.gen()),
    );
    let mut tree = CommitmentTree::empty();
    tree.append(Node::from_cmu(&note.cmu())).map_err(|_| "tree full")?;
    let witness = IncrementalWitness::from_tree(tree).ok_or("witness")?;
    let anchor = Anchor::from(witness.root());

    let mut builder = Builder::new(Zip212Enforcement::On, BundleType::DEFAULT, anchor);
    builder
        .add_spend(dfvk.fvk().clone(), note, witness.path().ok_or("path")?)
        .map_err(|e| format!("{e:?}"))?;
    builder
        .add_output(Some(dfvk.fvk().ovk), to, NoteValue::from_raw(30_000), [0u8; 512])
        .map_err(|e| format!("{e:?}"))?;
    builder
        .add_output(None, to, NoteValue::from_raw(19_000), [0u8; 512])
        .map_err(|e| format!("{e:?}"))?;

    let (bundle, _meta) = builder
        .build::<LocalTxProver, LocalTxProver, _, i64>(std::slice::from_ref(&extsk), &mut rng)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("empty bundle")?;
    let bundle = bundle.create_proofs(prover, prover, &mut rng, ());
    let bundle = bundle
        .apply_signatures(&mut rng, [7u8; 32], &[extsk.expsk.ask])
        .map_err(|e| format!("{e:?}"))?;
    if bundle.shielded_spends().len() != 1 || bundle.shielded_outputs().len() != 2 {
        return Err("bundle shape".into());
    }
    Ok(())
}
