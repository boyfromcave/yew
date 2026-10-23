// Test cases for contrib/semgrep/rules/yew.yaml (`semgrep --test`): `ruleid:` lines must match,
// `ok:` lines must not. Never compiled.

use rand::rngs::{OsRng, SmallRng, StdRng};
use rand::{RngCore, SeedableRng};

fn rngs() {
    let mut seed = [0u8; 32];
    // ok: yew.keys.non-crypto-rng
    OsRng.fill_bytes(&mut seed);
    // ruleid: yew.keys.non-crypto-rng
    let r = StdRng::seed_from_u64(42);
    // ruleid: yew.keys.non-crypto-rng
    let s = SmallRng::from_entropy();
    // ruleid: yew.keys.non-crypto-rng
    let t = StdRng::from_seed(seed);
    // ruleid: yew.keys.non-crypto-rng
    let n = fastrand::u64(..);
}

#[cfg(test)]
mod tests {
    fn deterministic() {
        // ok: yew.keys.non-crypto-rng
        let r = StdRng::seed_from_u64(7);
        // ok: yew.net.unwrap-on-server-response
        let v = parse(reply).unwrap();
    }
}

// ruleid: yew.keys.secret-type-derives-debug
#[derive(Clone, Debug)]
pub struct SeedBytes([u8; 64]);

// ruleid: yew.keys.secret-type-derives-debug
#[derive(Debug, PartialEq)]
struct SpendingKeyHolder {
    sk: [u8; 32],
}

// ok: yew.keys.secret-type-derives-debug
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    height: u32,
}

// ok: yew.keys.secret-type-derives-debug
#[derive(Clone)]
pub struct PrivateSeedRoot([u8; 32]);

// ok: yew.keys.secret-type-implements-display
impl std::fmt::Debug for PrivateSeedRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateSeedRoot(..)")
    }
}

// ruleid: yew.keys.secret-type-implements-display
impl std::fmt::Display for PrivateSeedRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

// ok: yew.keys.secret-type-implements-display
impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn logging(seed: &[u8], mnemonic: &str, height: u32, key: &AddressKey) {
    // ruleid: yew.keys.secret-logged
    println!("seed {:?}", seed);
    // ruleid: yew.keys.secret-logged
    eprintln!("{}", mnemonic);
    // ruleid: yew.keys.secret-logged
    log::debug!("wif {}", key.wif());
    // ruleid: yew.keys.secret-logged
    println!("{seed:?}");
    // ok: yew.keys.secret-logged
    println!("synced to {}", height);
    // ok: yew.keys.secret-logged
    eprintln!("no seed: pass --seed-file or set YEW_SEED");
    // ok: yew.keys.secret-logged
    println!("imported {} (not covered by the seed backup)", height);
}

fn on_reply(reply: Reply) -> Result<u32, NetError> {
    // ruleid: yew.net.unwrap-on-server-response
    let h = reply.block.unwrap();
    // ruleid: yew.net.unwrap-on-server-response
    let t = decode(&reply.tx).expect("server sent a valid tx");
    // ok: yew.net.unwrap-on-server-response
    let u = reply.block.ok_or(NetError::Malformed)?;
    Ok(h.height)
}
