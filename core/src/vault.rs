// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The vault primitive's script templates as YEW builds and reads them (the vault upgrade,
//! `UPGRADE_VAULT`, branch id `0x6d5b7a31`; workspace `docs/plans/yellowback-upgrade-plan.md`
//! §15.3, §15.10): the vault **V** and the intent **I**, both bare scriptPubKeys (U-12), their
//! selectors (the last push of the spending scriptSig), and the YED parameters of a mint's
//! vault (U-23): `tag = YED\0`, `setId = cancelSetId = attestorSetId`, `delay = CLAIM_DELAY`,
//! `ownerHeight = lockHeight`, `appHeight = lockHeight + GRACE`.
//!
//! Translation source: `ycash-dd/src/vault/template.{h,cpp}` (`BuildVault`, `BuildIntent`,
//! `ParseVault`, `ParseIntent`, `IntentFor`, `ParseSelector`) and `src/yellowback/script.cpp`
//! (`YedVaultParams`, `YedVaultScript`) on branch `upgrade/vault`; the Python reference
//! `qa/rpc-tests/test_framework/vault.py`. Builders emit the exact byte shapes with minimal
//! pushes; parsers accept only those shapes (parse the fields, rebuild, compare bytes), so a
//! non-minimal or out-of-range field is not a template. The golden vector
//! `src/test/data/vault_vectors.json` (byte-identical on both node lines) is replayed in the
//! tests below from `core/tests/vectors/vault_vectors.json`, a byte-identical copy.
//!
//! "Compressed" is the node's reading A-2: 33 bytes with prefix `02`/`03`, no curve check (an
//! off-curve key parses and can never sign).

use crate::keys::sha256;
use crate::script::{self, op, ScriptOp};

/// `OP_2`.
pub const OP_2: u8 = 0x52;
/// `OP_3`.
pub const OP_3: u8 = 0x53;
/// `OP_4`.
pub const OP_4: u8 = 0x54;
/// `OP_VERIFY`.
pub const OP_VERIFY: u8 = 0x69;
/// `OP_2DROP`.
pub const OP_2DROP: u8 = 0x6d;
/// `OP_CHECKSEQUENCEVERIFY`: BIP112's own byte (`OP_NOP3`, U-10).
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
/// `OP_CHECKSETSIG` (§15.2).
pub const OP_CHECKSETSIG: u8 = 0xc0;
/// `OP_CHECKSETDORMANT` (§15.2).
pub const OP_CHECKSETDORMANT: u8 = 0xc1;

/// `OP_CHECKSETSIG` roles (U-13).
pub const ROLE_UNLOCK: u8 = 1;
/// See [`ROLE_UNLOCK`].
pub const ROLE_CANCEL: u8 = 2;

/// V: set unlock; I: RELEASE.
pub const SEL_UNLOCK: u8 = 1;
/// V: owner at `ownerHeight`; I: CANCEL.
pub const SEL_OWNER: u8 = 2;
/// V and I: owner when the set is released.
pub const SEL_RELEASED: u8 = 3;
/// V only: the APP branch (a YED claim).
pub const SEL_APP: u8 = 4;

/// `delay` range (§15.3).
pub const MIN_DELAY: i64 = 1;
/// See [`MIN_DELAY`].
pub const MAX_DELAY: i64 = 65_535;
/// The largest `ownerHeight` / `appHeight` (below `LOCKTIME_THRESHOLD`).
pub const MAX_TEMPLATE_HEIGHT: i64 = 499_999_999;

/// The YED application tag `YED\0` (`src/yellowback/script.cpp` `YED_TAG`, §15.7).
pub const YED_TAG: [u8; 4] = [b'Y', b'E', b'D', 0x00];

/// BIP68: bit 31 of `nSequence` disables the relative lock (`CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG`).
pub const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;
/// BIP68: bit 22 selects a time-based lock, invalid under the upgrade (U-11).
pub const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;
/// BIP68: the low 16 bits hold the height lock.
pub const SEQUENCE_MASK: u32 = 0xffff;

/// A set id: the txid of its `SET_CREATE` transaction, as its 32 internal bytes.
pub type SetId = [u8; 32];

/// The parameters of a vault V (`vault::VaultParams`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultParams {
    /// The application tag.
    pub tag: [u8; 4],
    /// The set whose members may cancel its intents.
    pub cancel_set_id: SetId,
    /// The intents' delay in blocks (`CLAIM_DELAY` for YED).
    pub delay: i64,
    /// The set whose members may unlock it.
    pub set_id: SetId,
    /// The owner branch's CLTV height (`lockHeight` for YED).
    pub owner_height: i64,
    /// The owner's key (compressed bytes).
    pub owner_key: [u8; 33],
    /// The APP branch's CLTV height (`claimHeight = lockHeight + GRACE` for YED); 0 disables it.
    pub app_height: i64,
}

/// The parameters of an intent I (`vault::IntentParams`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentParams {
    /// The application tag (the originating V's).
    pub tag: [u8; 4],
    /// `SHA256(recipient scriptPubKey)`.
    pub recipient_hash: [u8; 32],
    /// `SHA256(originating V scriptPubKey)`.
    pub vault_hash: [u8; 32],
    /// The release delay (the V's).
    pub delay: i64,
    /// The cancelling set (the V's).
    pub cancel_set_id: SetId,
    /// The V's unlocking set (read by the owner-released branch).
    pub set_id: SetId,
    /// The V's owner.
    pub owner_key: [u8; 33],
}

/// 33 bytes with a `02`/`03` header (no curve check; A-2).
pub fn is_compressed_key_bytes(key: &[u8]) -> bool {
    key.len() == 33 && (key[0] == 0x02 || key[0] == 0x03)
}

/// `VaultParamsValid`: the §15.3 field ranges.
pub fn vault_params_valid(p: &VaultParams) -> bool {
    (MIN_DELAY..=MAX_DELAY).contains(&p.delay)
        && (1..=MAX_TEMPLATE_HEIGHT).contains(&p.owner_height)
        && (0..=MAX_TEMPLATE_HEIGHT).contains(&p.app_height)
        && is_compressed_key_bytes(&p.owner_key)
}

/// `IntentParamsValid`.
pub fn intent_params_valid(p: &IntentParams) -> bool {
    (MIN_DELAY..=MAX_DELAY).contains(&p.delay) && is_compressed_key_bytes(&p.owner_key)
}

/// `BuildVault` (§15.3); `None` when a field is out of range.
pub fn build_vault(p: &VaultParams) -> Option<Vec<u8>> {
    if !vault_params_valid(p) {
        return None;
    }
    let mut s = Vec::with_capacity(220);
    script::push_data(&mut s, &p.tag);
    script::push_data(&mut s, &p.cancel_set_id);
    script::push_int(&mut s, p.delay);
    s.extend_from_slice(&[OP_2DROP, op::OP_DROP]);
    s.extend_from_slice(&[op::OP_DUP, op::OP_1, op::OP_EQUAL, op::OP_IF, op::OP_DROP]);
    script::push_data(&mut s, &p.set_id);
    s.extend_from_slice(&[op::OP_1, OP_CHECKSETSIG]);
    s.extend_from_slice(&[
        op::OP_ELSE,
        op::OP_DUP,
        OP_2,
        op::OP_EQUAL,
        op::OP_IF,
        op::OP_DROP,
    ]);
    script::push_int(&mut s, p.owner_height);
    s.extend_from_slice(&[op::OP_CHECKLOCKTIMEVERIFY, op::OP_DROP]);
    script::push_data(&mut s, &p.owner_key);
    s.push(op::OP_CHECKSIG);
    s.extend_from_slice(&[
        op::OP_ELSE,
        op::OP_DUP,
        OP_3,
        op::OP_EQUAL,
        op::OP_IF,
        op::OP_DROP,
    ]);
    script::push_data(&mut s, &p.set_id);
    s.extend_from_slice(&[OP_CHECKSETDORMANT, OP_VERIFY]);
    script::push_data(&mut s, &p.owner_key);
    s.push(op::OP_CHECKSIG);
    s.extend_from_slice(&[op::OP_ELSE, OP_4, op::OP_EQUALVERIFY]);
    script::push_int(&mut s, p.app_height);
    s.push(op::OP_CHECKLOCKTIMEVERIFY);
    s.extend_from_slice(&[op::OP_ENDIF, op::OP_ENDIF, op::OP_ENDIF]);
    Some(s)
}

/// `BuildIntent` (§15.3); `None` when a field is out of range.
pub fn build_intent(p: &IntentParams) -> Option<Vec<u8>> {
    if !intent_params_valid(p) {
        return None;
    }
    let mut s = Vec::with_capacity(220);
    script::push_data(&mut s, &p.tag);
    script::push_data(&mut s, &p.recipient_hash);
    script::push_data(&mut s, &p.vault_hash);
    s.extend_from_slice(&[OP_2DROP, op::OP_DROP]);
    s.extend_from_slice(&[op::OP_DUP, op::OP_1, op::OP_EQUAL, op::OP_IF, op::OP_DROP]);
    script::push_int(&mut s, p.delay);
    s.push(OP_CHECKSEQUENCEVERIFY);
    s.extend_from_slice(&[
        op::OP_ELSE,
        op::OP_DUP,
        OP_2,
        op::OP_EQUAL,
        op::OP_IF,
        op::OP_DROP,
    ]);
    script::push_data(&mut s, &p.cancel_set_id);
    s.extend_from_slice(&[OP_2, OP_CHECKSETSIG]);
    s.extend_from_slice(&[op::OP_ELSE, OP_3, op::OP_EQUALVERIFY]);
    script::push_data(&mut s, &p.set_id);
    s.extend_from_slice(&[OP_CHECKSETDORMANT, OP_VERIFY]);
    script::push_data(&mut s, &p.owner_key);
    s.push(op::OP_CHECKSIG);
    s.extend_from_slice(&[op::OP_ENDIF, op::OP_ENDIF]);
    Some(s)
}

/// A script number push (`OP_0`, `OP_1..OP_16`, or a data push of at most 5 bytes), decoded
/// without the minimality test: the caller rebuilds and compares bytes.
fn read_num(o: &ScriptOp) -> Option<i64> {
    if o.opcode == op::OP_0 {
        return Some(0);
    }
    if (op::OP_1..=op::OP_16).contains(&o.opcode) {
        return Some((o.opcode - op::OP_1 + 1) as i64);
    }
    if o.opcode == op::OP_1NEGATE {
        return Some(-1);
    }
    if o.opcode > op::OP_PUSHDATA4 || o.data.is_empty() || o.data.len() > 5 {
        return None;
    }
    let d = &o.data;
    let mut v: i64 = 0;
    for (i, b) in d.iter().enumerate() {
        let b = if i == d.len() - 1 { b & 0x7f } else { *b };
        v |= (b as i64) << (8 * i);
    }
    if d[d.len() - 1] & 0x80 != 0 {
        v = -v;
    }
    Some(v)
}

fn data_of<const N: usize>(o: &ScriptOp) -> Option<[u8; N]> {
    if o.opcode > op::OP_PUSHDATA4 || o.data.len() != N {
        return None;
    }
    o.data.as_slice().try_into().ok()
}

/// `ParseVault`: the parameters of an exact, minimal, in-range V; `None` otherwise.
pub fn parse_vault(spk: &[u8]) -> Option<VaultParams> {
    let o = script::ops(spk).ok()?;
    if o.len() != 43 {
        return None;
    }
    let p = VaultParams {
        tag: data_of::<4>(&o[0])?,
        cancel_set_id: data_of::<32>(&o[1])?,
        delay: read_num(&o[2])?,
        set_id: data_of::<32>(&o[10])?,
        owner_height: read_num(&o[19])?,
        owner_key: data_of::<33>(&o[22])?,
        app_height: read_num(&o[38])?,
    };
    // The setId pushed in the unlock and the owner-released branches must agree, and so must
    // the owner keys: rebuilding from the first copies and comparing bytes checks every opcode,
    // every push form and both copies at once.
    (build_vault(&p)? == spk).then_some(p)
}

/// `ParseIntent`: the parameters of an exact, minimal, in-range I; `None` otherwise.
pub fn parse_intent(spk: &[u8]) -> Option<IntentParams> {
    let o = script::ops(spk).ok()?;
    if o.len() != 31 {
        return None;
    }
    let p = IntentParams {
        tag: data_of::<4>(&o[0])?,
        recipient_hash: data_of::<32>(&o[1])?,
        vault_hash: data_of::<32>(&o[2])?,
        delay: read_num(&o[10])?,
        cancel_set_id: data_of::<32>(&o[18])?,
        set_id: data_of::<32>(&o[24])?,
        owner_key: data_of::<33>(&o[27])?,
    };
    (build_intent(&p)? == spk).then_some(p)
}

/// SHA256 (single) of a script, as `recipientHash` / `vaultHash` (`ScriptHash256`).
pub fn script_hash256(script: &[u8]) -> [u8; 32] {
    sha256(script)
}

/// `IntentFor` (S-2): the intent a V's UNLOCK / APP spend may create paying `recipient`.
pub fn intent_for(v: &VaultParams, vault_spk: &[u8], recipient: &[u8]) -> IntentParams {
    IntentParams {
        tag: v.tag,
        recipient_hash: script_hash256(recipient),
        vault_hash: script_hash256(vault_spk),
        delay: v.delay,
        cancel_set_id: v.cancel_set_id,
        set_id: v.set_id,
        owner_key: v.owner_key,
    }
}

/// Which template a scriptSig spends (the selector sets differ).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A vault V (selectors 1..4).
    Vault,
    /// An intent I (selectors 1..3; A-10).
    Intent,
}

/// `ParseSelector`: a push-only scriptSig whose last element is exactly `OP_1..OP_4` (`OP_1..OP_3`
/// for an intent). Returns the selector and the pushes before it.
pub fn parse_selector(kind: Kind, script_sig: &[u8]) -> Option<(u8, Vec<Vec<u8>>)> {
    let o = script::ops(script_sig).ok()?;
    let (last, args) = o.split_last()?;
    if args.iter().any(|x| x.opcode > op::OP_16) {
        return None;
    }
    let max = match kind {
        Kind::Vault => OP_4,
        Kind::Intent => OP_3,
    };
    if last.opcode < op::OP_1 || last.opcode > max {
        return None;
    }
    Some((
        last.opcode - op::OP_1 + 1,
        args.iter().map(|a| a.data.clone()).collect(),
    ))
}

/// V OWNER (selector 2): `<ownerSig ‖ hashtype> OP_2`.
pub fn vault_owner_script_sig(owner_sig: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(owner_sig.len() + 2);
    script::push_data(&mut s, owner_sig);
    s.push(OP_2);
    s
}

/// V OWNER-RELEASED (selector 3): `<ownerSig ‖ hashtype> OP_3`.
pub fn vault_owner_released_script_sig(owner_sig: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(owner_sig.len() + 2);
    script::push_data(&mut s, owner_sig);
    s.push(OP_3);
    s
}

/// V APP (selector 4, the YED claim): `OP_4`.
pub fn vault_app_script_sig() -> Vec<u8> {
    vec![OP_4]
}

/// I RELEASE (selector 1): `OP_1`; the input's `nSequence` must be the intent's `delay`.
pub fn intent_release_script_sig() -> Vec<u8> {
    vec![op::OP_1]
}

/// BIP68 (U-11), Bitcoin's height test: an input with `n_sequence` spending a coin mined at
/// `coin_height` may be in a block at `height` (true when the relative lock is disabled).
pub fn bip68_ok(coin_height: u64, n_sequence: u32, height: u64) -> bool {
    if n_sequence & SEQUENCE_DISABLE_FLAG != 0 {
        return true;
    }
    if n_sequence & SEQUENCE_TYPE_FLAG != 0 {
        return false;
    }
    coin_height + (n_sequence & SEQUENCE_MASK) as u64 <= height
}

/// The first height at which an intent mined at `coin_height` with `delay` can be released
/// (`yed_getvault.intents[].releaseHeight = height + CLAIM_DELAY`).
pub fn release_height(coin_height: u64, delay: i64) -> u64 {
    coin_height + delay.max(0) as u64
}

/// `YedVaultParamsAt` (`src/yellowback/script.cpp`, branch `upgrade/vault-in-term`): the YED V of
/// `owner` with the given branch heights, under the network's attestor set and `CLAIM_DELAY`.
/// A mint since the in-term plan (IT-1, D-IT-15) has `owner_height = app_height = refHeight + 1`
/// ([`yed_mint_vault_params`]); a vault minted before it has `lockHeight`, `lockHeight + GRACE`
/// ([`yed_vault_params`]) and stays spendable.
pub fn yed_vault_params_at(
    attestor_set_id: &SetId,
    claim_delay: i64,
    owner: &[u8; 33],
    owner_height: i64,
    app_height: i64,
) -> VaultParams {
    VaultParams {
        tag: YED_TAG,
        cancel_set_id: *attestor_set_id,
        delay: claim_delay,
        set_id: *attestor_set_id,
        owner_height,
        owner_key: *owner,
        app_height,
    }
}

/// `YedVaultParams(P, owner, refHeight)` (in-term plan IT-1, D-IT-15): the V of a new mint at
/// reference height `ref_height` — both the owner's branch and the claim branch open from the
/// block after the mint (`refHeight + 1`); RED-4's threshold test decides a claim, and the owner
/// may redeem at any height (before `lockHeight` with the early-redeem fee, IT-9).
pub fn yed_mint_vault_params(
    attestor_set_id: &SetId,
    claim_delay: i64,
    owner: &[u8; 33],
    ref_height: u32,
) -> VaultParams {
    let h = ref_height as i64 + 1;
    yed_vault_params_at(attestor_set_id, claim_delay, owner, h, h)
}

/// The pre-plan V (upgrade plan U-23, before the in-term plan): a mint by `owner` locked until
/// `lock_height`, claimable from `lock_height + GRACE`. New mints of this shape are refused
/// (MINT-3, `bad-mint-vault-script`); existing ones are still YED vaults.
pub fn yed_vault_params(
    attestor_set_id: &SetId,
    claim_delay: i64,
    grace: u32,
    owner: &[u8; 33],
    lock_height: u32,
) -> VaultParams {
    VaultParams {
        tag: YED_TAG,
        cancel_set_id: *attestor_set_id,
        delay: claim_delay,
        set_id: *attestor_set_id,
        owner_height: lock_height as i64,
        owner_key: *owner,
        app_height: lock_height as i64 + grace as i64,
    }
}

/// True when `p` is the shape of a YED vault for `attestor_set_id` / `claim_delay` / `grace`
/// (the module's MINT-3 for a V output).
pub fn is_yed_vault(
    p: &VaultParams,
    attestor_set_id: &SetId,
    claim_delay: i64,
    grace: u32,
) -> bool {
    p.tag == YED_TAG
        && p.set_id == *attestor_set_id
        && p.cancel_set_id == *attestor_set_id
        && p.delay == claim_delay
        // In-term plan IT-1 (`Module::ValidateCreate`): the APP branch is open (≥ 1) and no later
        // than the pre-plan `lockHeight + GRACE`; MINT-3 pins a new mint's exact value.
        && p.app_height >= 1
        && p.app_height <= p.owner_height + grace as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::unhex;
    use crate::tx::Transaction;
    use serde_json::Value;

    fn vectors() -> Value {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/vault_vectors.json");
        serde_json::from_str(&std::fs::read_to_string(p).expect("vault_vectors.json")).unwrap()
    }

    fn h<const N: usize>(v: &Value) -> [u8; N] {
        unhex(v.as_str().unwrap()).unwrap().try_into().unwrap()
    }

    fn vault_of(p: &Value) -> VaultParams {
        VaultParams {
            tag: h::<4>(&p["tag"]),
            cancel_set_id: h::<32>(&p["cancelSetId"]),
            delay: p["delay"].as_i64().unwrap(),
            set_id: h::<32>(&p["setId"]),
            owner_height: p["ownerHeight"].as_i64().unwrap(),
            owner_key: h::<33>(&p["ownerKey"]),
            app_height: p["appHeight"].as_i64().unwrap(),
        }
    }

    fn intent_of(p: &Value) -> IntentParams {
        IntentParams {
            tag: h::<4>(&p["tag"]),
            recipient_hash: h::<32>(&p["recipientHash"]),
            vault_hash: h::<32>(&p["vaultHash"]),
            delay: p["delay"].as_i64().unwrap(),
            cancel_set_id: h::<32>(&p["cancelSetId"]),
            set_id: h::<32>(&p["setId"]),
            owner_key: h::<33>(&p["ownerKey"]),
        }
    }

    #[test]
    fn constants_match_the_vector() {
        let v = vectors();
        assert_eq!(
            v["branchId"].as_u64().unwrap() as u32,
            crate::params::VAULT_BRANCH_ID
        );
        assert_eq!(
            v["opcodes"]["CHECKSEQUENCEVERIFY"].as_u64(),
            Some(OP_CHECKSEQUENCEVERIFY as u64)
        );
        assert_eq!(
            v["opcodes"]["CHECKSETSIG"].as_u64(),
            Some(OP_CHECKSETSIG as u64)
        );
        assert_eq!(
            v["opcodes"]["CHECKSETDORMANT"].as_u64(),
            Some(OP_CHECKSETDORMANT as u64)
        );
    }

    #[test]
    fn vaults_build_and_parse_byte_for_byte() {
        let v = vectors();
        for e in v["vaults"].as_array().unwrap() {
            let name = e["name"].as_str().unwrap();
            let p = vault_of(&e["params"]);
            let spk = unhex(e["script"].as_str().unwrap()).unwrap();
            assert_eq!(build_vault(&p).as_deref(), Some(&spk[..]), "build {name}");
            assert_eq!(parse_vault(&spk), Some(p), "parse {name}");
            assert_eq!(parse_intent(&spk), None, "{name} is not an intent");
        }
        for e in v["vaultsInvalid"].as_array().unwrap() {
            let spk = unhex(e["script"].as_str().unwrap()).unwrap();
            assert_eq!(parse_vault(&spk), None, "{}", e["name"]);
        }
    }

    #[test]
    fn intents_build_parse_and_derive_byte_for_byte() {
        let v = vectors();
        for e in v["intents"].as_array().unwrap() {
            let name = e["name"].as_str().unwrap();
            let p = intent_of(&e["params"]);
            let spk = unhex(e["script"].as_str().unwrap()).unwrap();
            assert_eq!(build_intent(&p).as_deref(), Some(&spk[..]), "build {name}");
            assert_eq!(parse_intent(&spk), Some(p.clone()), "parse {name}");
            assert_eq!(parse_vault(&spk), None);
            // IntentFor(vault, recipient) gives the same intent.
            let vspk = unhex(e["vaultScript"].as_str().unwrap()).unwrap();
            let rspk = unhex(e["recipientScript"].as_str().unwrap()).unwrap();
            let vp = parse_vault(&vspk).expect("the vector's vault parses");
            assert_eq!(intent_for(&vp, &vspk, &rspk), p, "IntentFor {name}");
        }
        for e in v["intentsInvalid"].as_array().unwrap() {
            let spk = unhex(e["script"].as_str().unwrap()).unwrap();
            assert_eq!(parse_intent(&spk), None, "{}", e["name"]);
        }
    }

    #[test]
    fn selectors_match_the_vector() {
        let v = vectors();
        let kind = |e: &Value| match e["kind"].as_str().unwrap() {
            "V" => Kind::Vault,
            _ => Kind::Intent,
        };
        for e in v["selectors"].as_array().unwrap() {
            let ss = unhex(e["scriptSig"].as_str().unwrap()).unwrap();
            let (sel, args) = parse_selector(kind(e), &ss).expect("selector parses");
            assert_eq!(sel as u64, e["selector"].as_u64().unwrap());
            assert_eq!(args.len() as u64, e["nArgs"].as_u64().unwrap());
        }
        for e in v["selectorsInvalid"].as_array().unwrap() {
            let ss = unhex(e["scriptSig"].as_str().unwrap()).unwrap();
            assert_eq!(parse_selector(kind(e), &ss), None, "{}", e["reason"]);
        }
        // The scriptSigs YEW writes are the vector's shapes.
        assert_eq!(vault_app_script_sig(), unhex("54").unwrap());
        assert_eq!(intent_release_script_sig(), unhex("51").unwrap());
        let sig = unhex("300600000000000001").unwrap();
        assert_eq!(
            vault_owner_script_sig(&sig),
            unhex("0930060000000000000152").unwrap()
        );
        assert_eq!(
            parse_selector(Kind::Vault, &vault_owner_script_sig(&sig)),
            Some((SEL_OWNER, vec![sig.clone()]))
        );
        assert_eq!(
            parse_selector(Kind::Vault, &vault_owner_released_script_sig(&sig)),
            Some((SEL_RELEASED, vec![sig]))
        );
    }

    /// The ZIP-243 sighash under the Vault branch id (`spends[]`): YEW's signer computes the
    /// node's `SignatureHash(scriptCode = V or I, tx, nIn, SIGHASH_ALL, amount, 0x6d5b7a31)`.
    #[test]
    fn spends_sighash_under_the_vault_branch_id() {
        let v = vectors();
        let spends = v["spends"].as_array().unwrap();
        assert!(!spends.is_empty());
        for e in spends {
            let raw = unhex(e["tx"].as_str().unwrap()).unwrap();
            let (tx, _) = Transaction::parse(&raw).unwrap();
            assert_eq!(tx.serialize().unwrap(), raw);
            let code = unhex(e["scriptCode"].as_str().unwrap()).unwrap();
            let branch = e["branchId"].as_u64().unwrap() as u32;
            assert_eq!(branch, crate::params::VAULT_BRANCH_ID);
            let got = tx
                .sighash(
                    e["nIn"].as_u64().unwrap() as usize,
                    &code,
                    e["amount"].as_i64().unwrap(),
                    crate::params::SIGHASH_ALL,
                    branch,
                )
                .unwrap();
            assert_eq!(got, h::<32>(&e["sighash"]), "{}", e["name"]);
            // And the scriptSig's selector parses for the template it spends.
            let kind = if parse_vault(&code).is_some() {
                Kind::Vault
            } else {
                assert!(parse_intent(&code).is_some());
                Kind::Intent
            };
            let ss = unhex(e["scriptSig"].as_str().unwrap()).unwrap();
            assert!(parse_selector(kind, &ss).is_some());
        }
    }

    /// The YED vault (U-23) is the vector's `app-enabled` shape: tag `YED\0`, one set as both
    /// sets, `appHeight = ownerHeight + GRACE`.
    #[test]
    fn yed_vault_matches_the_app_enabled_vector() {
        let v = vectors();
        let e = v["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == "app-enabled")
            .unwrap();
        let p = vault_of(&e["params"]);
        assert_eq!(p.tag, YED_TAG);
        let grace = (p.app_height - p.owner_height) as u32;
        let y = yed_vault_params(
            &p.set_id,
            p.delay,
            grace,
            &p.owner_key,
            p.owner_height as u32,
        );
        assert_eq!(y, p);
        assert!(is_yed_vault(&p, &p.set_id, p.delay, grace));
        assert!(!is_yed_vault(&p, &[0; 32], p.delay, grace));
        assert!(!is_yed_vault(&p, &p.set_id, p.delay + 1, grace));
        // IT-1: a new mint's V opens both branches at refHeight + 1, and is a YED vault too.
        let m = yed_mint_vault_params(&p.set_id, p.delay, &p.owner_key, 376);
        assert_eq!((m.owner_height, m.app_height), (377, 377));
        assert!(is_yed_vault(&m, &p.set_id, p.delay, grace));
        let late = VaultParams {
            app_height: p.owner_height + grace as i64 + 1,
            ..p.clone()
        };
        assert!(!is_yed_vault(&late, &p.set_id, p.delay, grace));
        assert_eq!(
            build_vault(&y).unwrap(),
            unhex(e["script"].as_str().unwrap()).unwrap()
        );
    }

    #[test]
    fn bip68_is_bitcoins_height_test() {
        // RELEASE valid from coinHeight + delay; CANCEL (I-2) while h - coinHeight < delay.
        assert!(!bip68_ok(100, 10, 109));
        assert!(bip68_ok(100, 10, 110));
        assert!(bip68_ok(100, 0xffff_fffe, 100));
        assert!(!bip68_ok(100, SEQUENCE_TYPE_FLAG | 1, 1_000));
        assert_eq!(release_height(100, 10), 110);
    }

    #[test]
    fn out_of_range_fields_do_not_build() {
        let mut p = VaultParams {
            tag: YED_TAG,
            cancel_set_id: [1; 32],
            delay: 10,
            set_id: [1; 32],
            owner_height: 500,
            owner_key: [2; 33],
            app_height: 524,
        };
        assert!(build_vault(&p).is_some());
        p.delay = 0;
        assert!(build_vault(&p).is_none());
        p.delay = 65_536;
        assert!(build_vault(&p).is_none());
        p.delay = 10;
        p.owner_key[0] = 4;
        assert!(build_vault(&p).is_none());
        p.owner_key[0] = 3;
        p.app_height = 500_000_000;
        assert!(build_vault(&p).is_none());
    }
}
