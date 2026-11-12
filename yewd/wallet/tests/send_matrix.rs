// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `z_sendmany` between every address type on the mock chain (beta2 D-2, D-4, D-5): every source
//! (ECC transparent, SLH-DSA, FN-DSA, Sapling) to every recipient type, the change destination of
//! each, the post-quantum fee on the real signature size, the post-quantum signatures checked
//! against their ZIP-243 digests under the Vault branch, the Yellowback outputs never spent as
//! plain YEC, and a refused send never broadcast again. The signer is the real signer core; the
//! Sapling parts are proven with the local Sapling parameters.

mod common;

use common::*;
use yew_core::pq::PqKeyId;

const VAULT_BRANCH: u32 = 0x6d5b7a31;
const COIN: i64 = 100_000_000;

struct Fix {
    node: MockNode,
    w: Wallet,
    ecc: String,
    slh: String,
    fn_: String,
    zaddr: String,
}

fn addr_script(a: &str) -> Vec<u8> {
    yewd_wallet::rpc::parse_taddr_script(Network::Regtest, a).unwrap()
}

/// A wallet on a chain past the Vault activation (Falcon on), funded with 5 YEC at its first SLH-DSA
/// and FN-DSA keys and at its ECC address (and four more coins of 1 YEC there), each in its own coin.
async fn fixture(name: &str) -> Fix {
    yewd_wallet::set_falcon_height(1);
    let node = MockNode::default();
    node.0.lock().unwrap().vault_height = Some(1);
    genesis(&node);
    let d = dir(name);
    let mut w = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    w.sync(&node).await.unwrap();
    let text = |v: yewd_wallet::json::J| v.text().trim_matches('"').to_string();
    let ecc = text(w.call(&node, "getnewaddress", &[]).await.unwrap());
    let slh = text(
        w.call(&node, "getnewaddress", &[json!("pqslh")])
            .await
            .unwrap(),
    );
    let fn_ = text(
        w.call(&node, "getnewaddress", &[json!("pq")])
            .await
            .unwrap(),
    );
    assert!(
        fn_.starts_with("rqf") && slh.starts_with("rqs"),
        "{fn_} {slh}"
    );
    let zaddr = text(w.call(&node, "z_getnewaddress", &[]).await.unwrap());
    let foreign = |n: u32| OutPoint { txid: [9; 32], n };
    node.mine(
        vec![
            coinbase(1, vec![0x51], 0),
            payment(foreign(0), addr_script(&ecc), 5 * COIN),
            payment(foreign(1), addr_script(&slh), 5 * COIN),
            payment(foreign(2), addr_script(&fn_), 5 * COIN),
            payment(foreign(3), addr_script(&ecc), COIN),
            payment(foreign(4), addr_script(&ecc), COIN),
            payment(foreign(5), addr_script(&ecc), COIN),
            payment(foreign(6), addr_script(&ecc), COIN),
        ],
        0,
    );
    w.sync(&node).await.unwrap();
    Fix {
        node,
        w,
        ecc,
        slh,
        fn_,
        zaddr,
    }
}

impl Fix {
    /// `z_sendmany from [{address, amount}] 1 fee policy`, run to its end: the txid, or the
    /// operation's (code, message), or the call's own refusal.
    async fn send(
        &mut self,
        from: &str,
        to: &[(&str, i64)],
        fee: Option<i64>,
        policy: Option<&str>,
    ) -> Result<String, (i64, String)> {
        let amounts: Vec<Value> = to
            .iter()
            .map(|(a, v)| json!({"address": a, "amount": *v as f64 / COIN as f64}))
            .collect();
        let mut p = vec![json!(from), json!(amounts), json!(1)];
        p.push(fee.map_or(Value::Null, |f| json!(f as f64 / COIN as f64)));
        if let Some(pol) = policy {
            p.push(json!(pol));
        }
        let opid = match self.w.call(&self.node, "z_sendmany", &p).await {
            Ok(v) => v.text().trim_matches('"').to_string(),
            Err(e) => return Err((e.code, e.message)),
        };
        let r = call_json(
            &mut self.w,
            &self.node,
            "z_getoperationresult",
            &[json!([opid])],
        )
        .await;
        let r = &r[0];
        match r["status"].as_str() {
            Some("success") => Ok(r["result"]["txid"].as_str().unwrap().to_string()),
            _ => Err((
                r["error"]["code"].as_i64().unwrap(),
                r["error"]["message"].as_str().unwrap().to_string(),
            )),
        }
    }

    /// The last transaction handed to `sendrawtransaction`.
    fn last_sent(&self) -> (Transaction, Vec<u8>) {
        let hexs = self.node.0.lock().unwrap().sent.last().cloned().unwrap();
        let raw = hex::decode(hexs).unwrap();
        (Transaction::parse(&raw).unwrap().0, raw)
    }

    fn mine(&mut self) {
        let txs: Vec<Vec<u8>> = {
            let c = self.node.0.lock().unwrap();
            c.mempool.iter().map(|(_, t)| t.clone()).collect()
        };
        let h = self.node.0.lock().unwrap().blocks.len() as u32;
        let mut all = vec![coinbase(h, vec![0x51], 0)];
        all.extend(txs);
        self.node.mine(all, 0);
    }

    async fn mine_sync(&mut self) {
        self.mine();
        self.w.sync(&self.node).await.unwrap();
    }

    async fn zbalance(&mut self, a: &str) -> i64 {
        let v = self
            .w
            .call(
                &self.node,
                "z_getbalance",
                &[json!(a), json!(1), json!(true)],
            )
            .await
            .unwrap();
        v.text().parse().unwrap()
    }

    /// The value of a wallet coin, by outpoint, from the transactions the wallet has seen.
    fn prevout(&self, txid: &[u8; 32], n: u32) -> (Vec<u8>, i64) {
        let id = yew_core::tx::txid_hex(txid);
        let coin = self
            .w
            .coins
            .iter()
            .find(|c| c.txid == id && c.vout == n)
            .unwrap_or_else(|| panic!("{id}:{n} is not a wallet coin"));
        (coin.script.clone(), coin.value)
    }
}

/// Every post-quantum input of a transparent-only `tx` carries a valid signature by the key its
/// coin names, over the ZIP-243 digest under the Vault branch (SIGHASH_ALL).
fn check_pq_signatures(f: &Fix, tx: &Transaction) {
    assert!(!tx.shielded.any());
    for (i, vin) in tx.vin.iter().enumerate() {
        let (script, value) = f.prevout(&vin.prevout.txid, vin.prevout.n);
        let Some(id) = yew_core::pq::pqpkh_of(&script) else {
            continue;
        };
        let (sig, pk) = yew_core::pq::parse_pqpkh_script_sig(&vin.script_sig)
            .unwrap_or_else(|| panic!("input {i}: a TX_PQPKH scriptSig"));
        let (sig, pk) = (&sig, &pk);
        assert_eq!(*sig.last().unwrap(), 1, "SIGHASH_ALL");
        assert_eq!(PqKeyId::of(id.scheme, pk), id, "input {i}: the coin's key");
        let digest = tx.sighash(i, &script, value, 1, VAULT_BRANCH).unwrap();
        assert!(
            yew_core::pq::verify(id.scheme, pk, &sig[..sig.len() - 1], &digest),
            "input {i}: the signature verifies"
        );
    }
}

/// A post-quantum input of a transaction with a Sapling part: its signature verifies over
/// librustzcash's ZIP-243 digest of the broadcast bytes (hashShieldedSpends / hashShieldedOutputs
/// and valueBalance included) under the Vault branch.
fn check_pq_signature_with_sapling(f: &Fix, raw: &[u8], tx: &Transaction) {
    use zcash_primitives::transaction::sighash::SignableInput;
    let branch = zcash_protocol::consensus::BranchId::try_from(VAULT_BRANCH).unwrap();
    let full = zcash_primitives::transaction::Transaction::read(raw, branch).unwrap();
    assert!(full.sapling_bundle().is_some());
    let bundle = full.transparent_bundle().unwrap();
    for (i, vin) in tx.vin.iter().enumerate() {
        let (script, value) = f.prevout(&vin.prevout.txid, vin.prevout.n);
        let id = yew_core::pq::pqpkh_of(&script).unwrap();
        // a 35-byte script: one length byte, then the script (Script::read's encoding)
        let mut enc = vec![script.len() as u8];
        enc.extend_from_slice(&script);
        let s = zcash_transparent::address::Script::read(&enc[..]).unwrap();
        let input = zcash_transparent::sighash::SignableInput::from_parts(
            bundle,
            zcash_transparent::sighash::SighashType::ALL,
            i,
            &s,
            &s,
            zcash_protocol::value::Zatoshis::from_u64(value as u64).unwrap(),
        )
        .unwrap();
        let digest: [u8; 32] = zcash_primitives::transaction::sighash_v4::v4_signature_hash(
            &*full,
            &SignableInput::Transparent(input),
        )
        .as_bytes()
        .try_into()
        .unwrap();
        let (sig, pk) = yew_core::pq::parse_pqpkh_script_sig(&vin.script_sig).unwrap();
        assert_eq!(PqKeyId::of(id.scheme, &pk), id);
        assert!(
            yew_core::pq::verify(id.scheme, &pk, &sig[..sig.len() - 1], &digest),
            "input {i}: the signature verifies over the digest with the Sapling part"
        );
        // (yew-core's transparent-only digest refuses a transaction with shielded parts)
        assert!(tx.sighash(i, &script, value, 1, VAULT_BRANCH).is_err());
    }
}

/// The address matrix: every source type to every recipient type, the change destination of each
/// (a PQ source's change back to the source address, D-4; an ECC source's to a new internal key;
/// a Sapling source's to itself), the fee, and the post-quantum signatures.
#[tokio::test]
async fn address_matrix_every_source_to_every_recipient() {
    let mut f = fixture("matrix").await;
    // the Sapling source's notes: 2 YEC from the ECC address (the signer's Sapling build)
    let zaddr = f.zaddr.clone();
    let ecc = f.ecc.clone();
    f.send(&ecc, &[(&zaddr, 2 * COIN)], None, None)
        .await
        .unwrap();
    f.mine_sync().await;
    assert_eq!(f.zbalance(&zaddr).await, 2 * COIN);
    // the recipients: foreign ECC and PQ addresses of both schemes, and this wallet's Sapling one
    let r_ecc = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x33; 20]);
    let r_slh = yew_core::keys::encode_pq_yec(
        Network::Regtest,
        &PqKeyId {
            scheme: 1,
            hash: [0x44; 32],
        },
    )
    .unwrap();
    let r_fn = yew_core::keys::encode_pq_yec(
        Network::Regtest,
        &PqKeyId {
            scheme: 2,
            hash: [0x55; 32],
        },
    )
    .unwrap();
    let sources = [
        ("ecc", f.ecc.clone()),
        ("slh", f.slh.clone()),
        ("fn", f.fn_.clone()),
        ("sapling", zaddr.clone()),
    ];
    let recipients = [
        ("ecc", r_ecc.clone()),
        ("slh", r_slh.clone()),
        ("fn", r_fn.clone()),
        ("sapling", zaddr.clone()),
    ];
    let amount = COIN / 10;
    for (sk, src) in &sources {
        for (rk, to) in &recipients {
            if sk == rk && *sk == "sapling" {
                continue; // Sapling to itself: the existing path, not a type move
            }
            let what = format!("{sk} -> {rk}");
            let z_before = f.zbalance(&zaddr).await;
            let txid = f
                .send(src, &[(to.as_str(), amount)], None, None)
                .await
                .unwrap_or_else(|e| panic!("{what}: {e:?}"));
            let (tx, raw) = f.last_sent();
            assert_eq!(
                yew_core::tx::txid_hex(&Transaction::parse(&raw).unwrap().1),
                txid,
                "{what}"
            );
            // the recipient's output
            if *rk == "sapling" {
                assert!(
                    tx.shielded.outputs >= 2,
                    "{what}: the Sapling output, padded"
                );
            } else {
                let s = addr_script(to);
                assert!(
                    tx.vout
                        .iter()
                        .any(|o| o.script_pubkey == s && o.value == amount),
                    "{what}: the payment"
                );
            }
            // the inputs and the change
            let src_script = (*sk != "sapling").then(|| addr_script(src));
            let mut in_value = 0;
            for vin in &tx.vin {
                let (s, v) = f.prevout(&vin.prevout.txid, vin.prevout.n);
                assert_eq!(
                    Some(&s),
                    src_script.as_ref(),
                    "{what}: spends only its source"
                );
                in_value += v;
            }
            let t_out: i64 = tx.vout.iter().map(|o| o.value).sum();
            match *sk {
                "slh" | "fn" => {
                    // D-4: the change returns to the source address
                    let change: Vec<_> = tx
                        .vout
                        .iter()
                        .filter(|o| Some(&o.script_pubkey) == src_script.as_ref())
                        .collect();
                    assert_eq!(change.len(), 1, "{what}: one change output, to the source");
                    assert!(tx.shielded.spends == 0);
                    let fee = in_value - t_out - if *rk == "sapling" { amount } else { 0 };
                    let min = if *sk == "slh" { 27_000 } else { 5_500 };
                    assert!(fee >= min, "{what}: fee {fee} >= {min}");
                    assert!(fee <= min + 2 * 500 + 2_000, "{what}: fee {fee} near {min}");
                    if *rk != "sapling" {
                        check_pq_signatures(&f, &tx);
                    } else {
                        check_pq_signature_with_sapling(&f, &raw, &tx);
                    }
                }
                "ecc" => {
                    // an ECC source's change: a new key of the internal chain
                    let change = tx
                        .vout
                        .iter()
                        .find(|o| f.w.book.is_change_script(&o.script_pubkey))
                        .unwrap_or_else(|| panic!("{what}: ECC change"));
                    assert!(change.value > 0);
                }
                _ => {
                    // a Sapling source: no transparent input, its change a note back to it
                    assert!(tx.vin.is_empty(), "{what}");
                    assert!(tx.shielded.spends >= 1, "{what}");
                }
            }
            f.mine_sync().await;
            if *sk == "sapling" || *rk == "sapling" {
                let z_after = f.zbalance(&zaddr).await;
                if *rk == "sapling" {
                    assert_eq!(z_after - z_before, amount, "{what}: the note arrived");
                } else {
                    assert!(z_after < z_before - amount, "{what}: the change note");
                }
            }
        }
    }
}

/// A post-quantum source never spends an output YED holds (`yed_reserved`, the coin lock's
/// equivalent here): not a token the index lists, not an output of an unconfirmed transaction
/// carrying a Yellowback payload; and while the node cannot answer for its index, it spends
/// nothing (ycash6 `YellowbackInputRefusal`).
#[tokio::test]
async fn pq_source_never_spends_a_yellowback_output() {
    let mut f = fixture("tokens").await;
    let fn_ = f.fn_.clone();
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x33; 20]);
    // the FN-DSA address's only coin is a token: nothing to spend
    let coin =
        f.w.coins
            .iter()
            .find(|c| c.script == addr_script(&fn_))
            .unwrap()
            .clone();
    {
        // Yellowback live and healthy, the index listing the token
        let mut c = f.node.0.lock().unwrap();
        c.yed_info = Some(json!({"healthy": true, "unhealthyReason": ""}));
        c.tokens = vec![json!({"txid": coin.txid, "vout": coin.vout})];
    }
    let e = f.send(&fn_, &[(&to, COIN)], None, None).await.unwrap_err();
    assert_eq!(
        e,
        (
            -6,
            "Insufficient transparent funds, no UTXOs found for taddr from address.".into()
        )
    );
    // with a plain coin beside it, only the plain coin is spent
    f.node.mine(
        vec![
            coinbase(2, vec![0x51], 0),
            payment(
                OutPoint {
                    txid: [8; 32],
                    n: 0,
                },
                addr_script(&fn_),
                3 * COIN,
            ),
        ],
        0,
    );
    f.w.sync(&f.node).await.unwrap();
    f.send(&fn_, &[(&to, COIN)], None, None).await.unwrap();
    let (tx, _) = f.last_sent();
    assert_eq!(tx.vin.len(), 1);
    assert_ne!(
        (
            yew_core::tx::txid_hex(&tx.vin[0].prevout.txid),
            tx.vin[0].prevout.n
        ),
        (coin.txid.clone(), coin.vout),
        "the token is not spent"
    );
    f.mine_sync().await;
    // an unconfirmed output of a transaction with a Yellowback payload (minconf 0 reaches it)
    let mut t = Transaction::new_v4();
    t.vin.push(TxIn::new(OutPoint {
        txid: [7; 32],
        n: 0,
    }));
    t.vout.push(TxOut {
        value: 2 * COIN,
        script_pubkey: addr_script(&f.slh),
    });
    t.vout.push(TxOut {
        value: 0,
        // an OP_RETURN that is not a vault act: a Yellowback payload to yed_reserved
        script_pubkey: vec![0x6a, 0x04, 0x59, 0x45, 0x44, 0x00],
    });
    f.node.to_mempool(t.serialize().unwrap());
    f.w.sync(&f.node).await.unwrap();
    // spend everything the SLH-DSA address has at minconf 0 and more: the payload output is not counted
    let slh = f.slh.clone();
    let amounts = vec![json!({"address": to, "amount": 6.0})];
    let opid =
        f.w.call(
            &f.node,
            "z_sendmany",
            &[json!(slh), json!(amounts), json!(0)],
        )
        .await
        .unwrap()
        .text();
    let r = call_json(
        &mut f.w,
        &f.node,
        "z_getoperationresult",
        &[json!([opid.trim_matches('"')])],
    )
    .await;
    let msg = r[0]["error"]["message"].as_str().unwrap().to_string();
    assert_eq!(
        msg,
        "Insufficient transparent funds, have 5.00, need 6.00001"
    );
    // the index cannot answer: nothing is spent as plain YEC
    f.node.0.lock().unwrap().tokens_error = Some((
        -26,
        "yellowback-unhealthy: a test reason; restart with -reindex-yellowback".into(),
    ));
    let sent_before = f.node.0.lock().unwrap().sent.len();
    let e = f.send(&slh, &[(&to, COIN)], None, None).await.unwrap_err();
    assert_eq!(
        e,
        (
            -4,
            "refusing to spend as plain YEC while the Yellowback index is unhealthy (a test reason): the wallet's YED coin locks cannot be trusted; restart with -reindex-yellowback".into()
        )
    );
    assert_eq!(f.node.0.lock().unwrap().sent.len(), sent_before);
    // Yellowback not live (-32601): this wallet has held YED (the sync saw its token), so it
    // cannot tell its YED outputs from plain YEC there; -yellowback=0 acknowledges it
    {
        let mut c = f.node.0.lock().unwrap();
        c.yed_info = None;
        c.tokens_error = Some((-32601, "Method not found".into()));
    }
    assert!(f.w.st.yed_held);
    let e = f.send(&slh, &[(&to, COIN)], None, None).await.unwrap_err();
    assert_eq!(e, (-4, yewd_wallet::build::HELD_YED_REFUSAL.into()));
    f.w.opts.yellowback_ack = true;
    f.send(&slh, &[(&to, COIN)], None, None).await.unwrap();
}

/// A send the node refuses fails its operation, is not recorded, and is never broadcast again (no
/// reaccept at the next start, audit H1's class); its coins stay spendable.
#[tokio::test]
async fn a_refused_send_is_never_broadcast_again() {
    let mut f = fixture("refused").await;
    let slh = f.slh.clone();
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x33; 20]);
    f.node.0.lock().unwrap().reject = Some("absurdly-high-fee".into());
    let e = f.send(&slh, &[(&to, COIN)], None, None).await.unwrap_err();
    assert_eq!(
        e,
        (
            -4,
            "SendTransaction: Transaction commit failed:: absurdly-high-fee (-26)".into()
        )
    );
    let (refused, raw) = f.last_sent();
    let refused_id = yew_core::tx::txid_hex(&Transaction::parse(&raw).unwrap().1);
    assert!(!f.w.st.wtx.contains_key(&refused_id), "not recorded");
    assert_eq!(f.node.0.lock().unwrap().sent.len(), 1, "one attempt");
    // a restart: the wallet reaccepts its unconfirmed transactions; the refused one is not among them
    f.node.0.lock().unwrap().reject = None;
    let d = dir("refused");
    let mut w2 = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    w2.sync(&f.node).await.unwrap();
    let sent = f.node.0.lock().unwrap().sent.clone();
    assert_eq!(sent.len(), 1, "nothing broadcast at the restart");
    assert!(f.node.0.lock().unwrap().mempool.is_empty());
    // the coin it would have spent is still spendable
    f.w = w2;
    f.send(&slh, &[(&to, COIN)], None, None).await.unwrap();
    let (tx, _) = f.last_sent();
    assert_eq!(tx.vin[0].prevout, refused.vin[0].prevout);
}

/// The call's refusals and the privacy policy of a PQ party, with ycash6 92e434626's strings.
#[tokio::test]
async fn pq_refusals_fees_and_privacy() {
    let mut f = fixture("refusals").await;
    let (slh, fn_, zaddr) = (f.slh.clone(), f.fn_.clone(), f.zaddr.clone());
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x33; 20]);
    let other_pq = yew_core::keys::encode_pq_yec(
        Network::Regtest,
        &PqKeyId {
            scheme: 2,
            hash: [0x66; 32],
        },
    )
    .unwrap();
    let e = f
        .send(&other_pq, &[(&to, COIN)], None, None)
        .await
        .unwrap_err();
    assert_eq!(
        e,
        (
            -5,
            "From address does not belong to this node, post-quantum key not found.".into()
        )
    );
    // a memo to a PQ recipient
    let p = [
        json!(f.ecc),
        json!([{"address": other_pq, "amount": 1.0, "memo": "00"}]),
    ];
    let e = f.w.call(&f.node, "z_sendmany", &p).await.unwrap_err();
    assert_eq!(
        (e.code, e.message.as_str()),
        (-8, "Memos cannot be sent to transparent addresses.")
    );
    // a PQ recipient below its dust threshold
    let dust = 3 * (100 * (8 + 1 + 35 + yew_core::params::pq_spend_input_size(2) as i64) / 1000);
    let e = f
        .send(&f.ecc.clone(), &[(&other_pq, dust - 1)], None, None)
        .await
        .unwrap_err();
    assert_eq!(e.0, -8);
    assert_eq!(e.1, "Invalid parameter, amount 0.00000497 is below the dust threshold 0.00000498 of a post-quantum output");
    // an explicit fee below what the PQ spend needs, and one above the cap
    let e = f
        .send(&slh, &[(&to, COIN)], Some(1_000), None)
        .await
        .unwrap_err();
    assert_eq!(e.0, -8);
    assert_eq!(
        e.1,
        "Fee 0.00001 is below the 0.00027 this post-quantum spend needs"
    );
    let e = f
        .send(&slh, &[(&to, COIN)], Some(20_000_000), None)
        .await
        .unwrap_err();
    assert_eq!(
        e,
        (-8, "Fee 0.20 is above the 0.10 cap on a post-quantum spend (-maxtxfee, or $2 at the attested price, at most -yellowbackmaxtxfee)".into())
    );
    // privacy (D-5): PQ -> Sapling without change needs AllowRevealedSenders, with the D-4 change
    // AllowFullyTransparent; a PQ recipient needs AllowRevealedRecipients
    let exact = 5 * COIN - 5_500 - 1_000; // FN input, two padded Sapling outputs
    let e = f
        .send(
            &fn_,
            &[(&zaddr, exact)],
            None,
            Some("AllowRevealedRecipients"),
        )
        .await
        .unwrap_err();
    assert_eq!(e, (-4, "Failed to build transaction: The specified privacy policy, AllowRevealedRecipients, does not permit the creation of the requested transaction. Select AllowRevealedSenders or weaker to allow this transaction to be constructed.".into()));
    let e = f
        .send(&fn_, &[(&zaddr, COIN)], None, Some("AllowRevealedSenders"))
        .await
        .unwrap_err();
    assert_eq!(e, (-4, "Failed to build transaction: The specified privacy policy, AllowRevealedSenders, does not permit the creation of the requested transaction. Select AllowFullyTransparent or weaker to allow this transaction to be constructed.".into()));
    let e = f
        .send(&fn_, &[(&zaddr, COIN)], None, Some("FullPrivacy"))
        .await
        .unwrap_err();
    assert_eq!(e.0, -8);
    assert_eq!(e.1, "Could not send to the Sapling shielded pool without spending non-Sapling funds, which would reveal transaction amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit with the `privacyPolicy` parameter set to `AllowRevealedAmounts` or weaker if you wish to allow this transaction to proceed anyway.");
    let e = f
        .send(&fn_, &[(&to, COIN)], None, Some("AllowRevealedAmounts"))
        .await
        .unwrap_err();
    assert_eq!(e.0, -8);
    assert_eq!(e.1, "This transaction would have transparent recipients, which is not enabled by default because it will publicly reveal transaction recipients and amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit with the `privacyPolicy` parameter set to `AllowRevealedRecipients` or weaker if you wish to allow this transaction to proceed anyway.");
    let txid = f
        .send(&fn_, &[(&zaddr, exact)], None, Some("AllowRevealedSenders"))
        .await
        .unwrap();
    let (tx, _) = f.last_sent();
    assert!(tx.vout.is_empty(), "no change: {txid}");
    f.mine_sync().await;
    assert_eq!(f.zbalance(&zaddr).await, exact);
}

/// More post-quantum inputs than one transaction may carry: refused before signing.
#[tokio::test]
async fn more_than_100_pq_inputs_are_refused() {
    let mut f = fixture("inputs").await;
    let fn_ = f.fn_.clone();
    let coins: Vec<Vec<u8>> = (0..101u32)
        .map(|n| payment(OutPoint { txid: [6; 32], n }, addr_script(&fn_), 10_000_000))
        .collect();
    let mut block = vec![coinbase(2, vec![0x51], 0)];
    block.extend(coins);
    f.node.mine(block, 0);
    f.w.sync(&f.node).await.unwrap();
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x33; 20]);
    // 5 YEC + 101 x 0.1: all 102 coins are needed for 15 YEC and the fee of their inputs
    let e = f
        .send(&fn_, &[(&to, 15 * COIN)], None, None)
        .await
        .unwrap_err();
    assert_eq!(e, (-4, "This send needs 102 post-quantum inputs, more than the 100 one transaction may carry; combine the address's coins first with z_mergetoaddress".into()));
    assert!(f.node.0.lock().unwrap().sent.is_empty());
}

// ------------------------------------------------------------------ vault_lock "from" (D-3)

impl Fix {
    async fn lock(&mut self, from: Option<Value>) -> Result<Value, (i64, String)> {
        let mut p = json!({
            "tag": "TEST",
            "setid": "11".repeat(32),
            "delay": 1,
            "ownerheight": 1000,
            "amount": 1.0,
        });
        if let Some(f) = from {
            p["from"] = f;
        }
        match self.w.call(&self.node, "vault_lock", &[p]).await {
            Ok(v) => Ok(serde_json::from_str(&v.text()).unwrap()),
            Err(e) => Err((e.code, e.message)),
        }
    }
}

/// vault_lock funded from each address type: the V first, the inputs only the from address's
/// coins (or its notes), the change back to it, the fee per its rule, the PQ signatures valid.
#[tokio::test]
async fn vault_lock_from_every_address_type() {
    let mut f = fixture("lockfrom").await;
    let zaddr = f.zaddr.clone();
    let ecc = f.ecc.clone();
    f.send(&ecc, &[(&zaddr, 2 * COIN)], None, None)
        .await
        .unwrap();
    f.mine_sync().await;
    for (kind, from) in [
        ("ecc", f.ecc.clone()),
        ("slh", f.slh.clone()),
        ("fn", f.fn_.clone()),
        ("sapling", zaddr.clone()),
    ] {
        let z_before = f.zbalance(&zaddr).await;
        let r = f
            .lock(Some(json!(from)))
            .await
            .unwrap_or_else(|e| panic!("{kind}: {e:?}"));
        let (tx, raw) = f.last_sent();
        assert_eq!(
            r["txid"].as_str().unwrap(),
            yew_core::tx::txid_hex(&Transaction::parse(&raw).unwrap().1)
        );
        assert_eq!(tx.vout[0].value, COIN, "{kind}: the V first");
        assert!(yew_core::vault::parse_vault(&tx.vout[0].script_pubkey).is_some());
        if kind == "sapling" {
            assert!(tx.vin.is_empty() && tx.shielded.spends >= 1, "{kind}");
            assert_eq!(tx.vout.len(), 1, "{kind}: the change is a note");
            f.mine_sync().await;
            let fee = z_before - COIN - f.zbalance(&zaddr).await;
            assert_eq!(fee, 10_000, "{kind}: max(10,000, conventional)");
            continue;
        }
        let only = addr_script(&from);
        let mut in_value = 0;
        for vin in &tx.vin {
            let (s, v) = f.prevout(&vin.prevout.txid, vin.prevout.n);
            assert_eq!(s, only, "{kind}: spends only its from address");
            in_value += v;
        }
        assert_eq!(tx.vout.len(), 2, "{kind}: the V and the change");
        assert_eq!(
            tx.vout[1].script_pubkey, only,
            "{kind}: change back to from (D-4)"
        );
        let fee = in_value - tx.output_total();
        let want = match kind {
            "slh" => 27_000, // 54 ZIP-317 actions of one SLH-DSA input
            _ => 10_000,     // VAULT_RPC_FEE (an FN-DSA input: 11 actions, 5,500)
        };
        assert_eq!(fee, want, "{kind}: fee");
        if kind != "ecc" {
            check_pq_signatures(&f, &tx);
        }
        f.mine_sync().await;
    }
    // "" and no from: the default funding, the wallet's transparent P2PKH coins
    f.lock(Some(json!(""))).await.unwrap();
    let (tx, _) = f.last_sent();
    for vin in &tx.vin {
        let (s, _) = f.prevout(&vin.prevout.txid, vin.prevout.n);
        assert!(yew_core::script::p2pkh_hash(&s).is_some());
    }
}

/// vault_lock "from" refusals (ycash-dd 97338f107 / ycash6 554f07fc1 strings), and a PQ from
/// never spends an output YED holds.
#[tokio::test]
async fn vault_lock_from_refusals_and_tokens() {
    let mut f = fixture("lockfromno").await;
    let e = f.lock(Some(json!(7))).await.unwrap_err();
    assert_eq!(e, (-8, "from must be an address string".into()));
    let p2sh = yew_core::keys::encode_p2sh(Network::Regtest, &[0x22; 20]);
    for bad in [p2sh.as_str(), "nonsense"] {
        let e = f.lock(Some(json!(bad))).await.unwrap_err();
        assert_eq!(e, (-5, "bad-address: from: not a transparent P2PKH, post-quantum or Sapling address of this network".into()), "{bad}");
    }
    let foreign_pq = yew_core::keys::encode_pq_yec(
        Network::Regtest,
        &PqKeyId {
            scheme: 1,
            hash: [0x66; 32],
        },
    )
    .unwrap();
    let foreign_ecc = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x33; 20]);
    for a in [foreign_pq, foreign_ecc] {
        let e = f.lock(Some(json!(a))).await.unwrap_err();
        assert_eq!(e, (-4, "from: not an address of this wallet".into()), "{a}");
    }
    // an address of this wallet with no coins, and an empty Sapling address
    let empty = yew_core::keys::encode_pq_yec(Network::Regtest, &f.w.book.pq_key(1, 1).unwrap().id)
        .unwrap();
    let e = f.lock(Some(json!(empty))).await.unwrap_err();
    assert_eq!(
        e,
        (
            -6,
            format!("insufficient confirmed funds at {empty}: need 1.0001 more")
        )
    );
    let e = f.lock(Some(json!(f.zaddr.clone()))).await.unwrap_err();
    assert_eq!(
        e,
        (
            -6,
            format!(
                "insufficient-yec: need 1.0001, have 0.00 in confirmed Sapling notes at {}",
                f.zaddr
            )
        )
    );
    // a token is never spent as plain YEC: the FN-DSA address's only coin, named when the address
    // cannot fund the lock without it (ycash-dd 97338f107 vault.cpp:1816)
    let fn_ = f.fn_.clone();
    let coin =
        f.w.coins
            .iter()
            .find(|c| c.script == addr_script(&fn_))
            .unwrap()
            .clone();
    f.node.0.lock().unwrap().tokens = vec![json!({"txid": coin.txid, "vout": coin.vout})];
    let e = f.lock(Some(json!(fn_))).await.unwrap_err();
    assert_eq!(
        e,
        (
            -4,
            format!("from: refusing to spend a Yellowback outpoint as plain YEC: {}:{} (its YED would burn; lock it again with yed_lockcoins or lockunspent true)", coin.txid, coin.vout)
        )
    );
    // the index cannot answer: nothing is spent from a transparent or PQ from
    f.node.0.lock().unwrap().tokens_error = Some((
        -26,
        "yellowback-unhealthy: a test reason; restart with -reindex-yellowback".into(),
    ));
    let slh = f.slh.clone();
    let e = f.lock(Some(json!(slh))).await.unwrap_err();
    assert_eq!(e, (-4, "from: refusing to spend as plain YEC while the Yellowback index is unhealthy (a test reason): the wallet's YED coin locks cannot be trusted; restart with -reindex-yellowback".into()));
    assert!(f.node.0.lock().unwrap().sent.is_empty());
}

/// The digest `check_pq_signatures` verifies against (yew-core's ZIP-243 `sighash`) is the node's:
/// it reproduces every `sighashPerInput` of the node-generated `transparent.json` (ycash-dd
/// `gen` vectors, branch 0x6d5b7a31, `core/tests/vectors/PIN`), a digest produced outside the
/// signer's code path. There is no node-generated vector for a transaction with both a
/// post-quantum input and a Sapling part; `check_pq_signature_with_sapling` rests on
/// librustzcash's `v4_signature_hash` (the same algorithm the signer runs, over the re-parsed
/// broadcast bytes).
#[test]
fn node_zip243_vectors_anchor_the_digest_checks() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../core/tests/vectors/transparent.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let txs = v["transactions"].as_array().unwrap();
    assert!(txs.len() >= 10);
    let mut checked = 0;
    for (n, t) in txs.iter().enumerate() {
        let raw = hex::decode(t["unsignedHex"].as_str().unwrap()).unwrap();
        let (tx, _) = Transaction::parse(&raw).unwrap();
        let branch = u32::from_str_radix(t["branchId"].as_str().unwrap(), 16).unwrap();
        assert_eq!(branch, VAULT_BRANCH);
        for (i, p) in t["prevouts"].as_array().unwrap().iter().enumerate() {
            let spk = hex::decode(p["scriptPubKeyHex"].as_str().unwrap()).unwrap();
            let amount = p["valueZat"].as_i64().unwrap();
            let digest = tx.sighash(i, &spk, amount, 1, branch).unwrap();
            assert_eq!(
                hex::encode(digest),
                t["sighashPerInput"][i].as_str().unwrap(),
                "tx {n} input {i}"
            );
            checked += 1;
        }
    }
    assert!(checked >= txs.len());
}

/// Exact fees for an ECC and a Sapling source; ANY_TADDR as the source; several recipient types
/// in one send.
#[tokio::test]
async fn exact_fees_any_taddr_and_mixed_recipients() {
    let mut f = fixture("exact").await;
    let r_ecc = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x61; 20]);
    let r_slh = yew_core::keys::encode_pq_yec(
        Network::Regtest,
        &PqKeyId {
            scheme: 1,
            hash: [0x62; 32],
        },
    )
    .unwrap();
    let fee_of = |f: &Fix, tx: &Transaction| -> i64 {
        let ins: i64 = tx
            .vin
            .iter()
            .map(|i| f.prevout(&i.prevout.txid, i.prevout.n).1)
            .sum();
        ins - tx.output_total()
    };
    // ECC -> ECC: one input, the payment and the change (ZIP-317: 2 logical actions)
    let ecc = f.ecc.clone();
    f.send(&ecc, &[(&r_ecc, COIN)], None, Some("AllowFullyTransparent"))
        .await
        .unwrap();
    // yewd prices a send with no PQ party at the ZIP-317 conventional fee (500 zat a logical
    // action, two at least), where ycash6's default -feepolicy=peroutput charges a flat 1,000 zat:
    // a pre-existing difference, recorded in the stage-5 notes
    let (tx, _) = f.last_sent();
    assert_eq!((tx.vin.len(), tx.vout.len()), (1, 2));
    assert_eq!(fee_of(&f, &tx), 1_000, "2 logical actions");
    f.mine_sync().await;
    // ANY_TADDR -> ECC + SLH-DSA + Sapling in one send
    let zaddr = f.zaddr.clone();
    let r = f
        .send(
            "ANY_TADDR",
            &[(&r_ecc, COIN / 10), (&r_slh, COIN / 10), (&zaddr, 2 * COIN)],
            None,
            Some("AllowFullyTransparent"),
        )
        .await;
    r.unwrap();
    let (tx, _) = f.last_sent();
    // one 5 YEC input; the ECC and PQ payments and the ECC change (34 + 44 + 34 bytes: 4 transparent
    // actions) and two Sapling outputs: 6 actions
    assert_eq!(
        (tx.vin.len(), tx.vout.len(), tx.shielded.outputs),
        (1, 3, 2)
    );
    assert_eq!(fee_of(&f, &tx) - 2 * COIN, 3_000);
    for (a, v) in [(&r_ecc, COIN / 10), (&r_slh, COIN / 10)] {
        let s = addr_script(a);
        assert!(
            tx.vout.iter().any(|o| o.script_pubkey == s && o.value == v),
            "{a}"
        );
    }
    let (s, _) = f.prevout(&tx.vin[0].prevout.txid, tx.vin[0].prevout.n);
    assert!(
        yew_core::script::p2pkh_hash(&s).is_some(),
        "ANY_TADDR spends ECC coins"
    );
    f.mine_sync().await;
    // Sapling -> ECC: one spend, the payment, the change note (padded outputs)
    let before = f.zbalance(&zaddr).await;
    f.send(
        &zaddr,
        &[(&r_ecc, COIN / 10)],
        None,
        Some("AllowRevealedRecipients"),
    )
    .await
    .unwrap();
    f.mine_sync().await;
    // one spend, two (padded) outputs, one transparent output: 3 actions
    assert_eq!(before - f.zbalance(&zaddr).await - COIN / 10, 1_500);
}

/// Review L3: the fee a post-quantum send pays, its folded dust change included, stays within the
/// cap. Change below the dust threshold on an ECC source: another coin is taken (ycash6
/// `LimitToAmount`), and when none is left the send is refused (`DustThresholdError`).
#[tokio::test]
async fn folded_fee_cap_and_change_dust() {
    let mut f = fixture("dustcap").await;
    let slh = f.slh.clone();
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x71; 20]);
    // without a live Yellowback the cap is -maxtxfee's 0.1 YEC; SLH change dust is 2,406 zat
    let fee = 9_999_000;
    let e = f
        .send(&slh, &[(&to, 5 * COIN - fee - 2_000)], Some(fee), None)
        .await
        .unwrap_err();
    assert_eq!(e, (-8, "Fee 0.10001 is above the 0.10 cap on a post-quantum spend (-maxtxfee, or $2 at the attested price, at most -yellowbackmaxtxfee)".into()));
    assert!(f.node.0.lock().unwrap().sent.is_empty());
    // ECC: 30 zat of change on the 5 YEC coin: a 1 YEC coin is added instead
    let ecc = f.ecc.clone();
    f.send(&ecc, &[(&to, 5 * COIN - 1_000 - 30)], None, None)
        .await
        .unwrap();
    let (tx, _) = f.last_sent();
    assert_eq!(tx.vin.len(), 2, "no dust change");
    f.mine_sync().await;
    // every ECC coin and still 30 zat of change: refused
    let have: i64 =
        f.w.coins
            .iter()
            .filter(|c| !c.spent && c.script == addr_script(&ecc))
            .map(|c| c.value)
            .sum();
    let n =
        f.w.coins
            .iter()
            .filter(|c| !c.spent && c.script == addr_script(&ecc))
            .count();
    let e = f
        .send(
            &ecc,
            &[(&to, have - 500 * n.max(2) as i64 - 30)],
            None,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!((n, have), (3, 3 * COIN));
    assert_eq!(e, (-8, "Insufficient funds: have 3.00, need 0.00000024 more to avoid creating invalid change output 0.0000003 (dust threshold is 0.00000054); note that coinbase outputs will not be selected if you specify ANY_TADDR, any transparent recipients are included, or if the `privacyPolicy` parameter is not set to `AllowRevealedSenders` or weaker.".into()));
}

/// A call's answer: its text, or its (code, message).
type Answer = Result<String, (i64, String)>;

/// ycash6 `CWallet::CreateTransaction`'s refusal when the ECC coins fall short and the wallet holds
/// post-quantum coins `z_sendmany` would spend (beta2 audit M-1).
fn pq_refusal(pq: i64) -> String {
    format!(
        "Insufficient funds in ordinary transparent addresses; this wallet also holds {} YEC at post-quantum addresses: send from one with z_sendmany, which returns the change to it",
        yewd_wallet::rpc::format_money(pq)
    )
}

impl Fix {
    /// One stock coin-selecting call paying `amount` to `to`.
    async fn stock_send(
        &mut self,
        call: &str,
        to: &str,
        amount: f64,
    ) -> Result<String, (i64, String)> {
        let p = match call {
            "sendtoaddress" => vec![json!(to), json!(amount)],
            "sendmany" => {
                let mut m = serde_json::Map::new();
                m.insert(to.to_string(), json!(amount));
                vec![json!(""), Value::Object(m)]
            }
            _ => {
                let mut raw = Transaction::new_v4();
                raw.vout.push(TxOut {
                    value: (amount * COIN as f64) as i64,
                    script_pubkey: addr_script(to),
                });
                vec![json!(hex::encode(raw.serialize().unwrap()))]
            }
        };
        self.w
            .call(&self.node, call, &p)
            .await
            .map(|v| v.text())
            .map_err(|e| (e.code, e.message))
    }

    /// The three stock coin-selecting calls, each paying `amount` to `to`: (call, its answer).
    async fn stock_sends(&mut self, to: &str, amount: f64) -> Vec<(&'static str, Answer)> {
        let mut out = Vec::new();
        for name in ["sendtoaddress", "sendmany", "fundrawtransaction"] {
            out.push((name, self.stock_send(name, to, amount).await));
        }
        out
    }

    /// The scripts of the coins `tx` spends (every one a wallet coin).
    fn input_scripts(&self, tx: &Transaction) -> Vec<Vec<u8>> {
        tx.vin
            .iter()
            .map(|i| self.prevout(&i.prevout.txid, i.prevout.n).0)
            .collect()
    }

    fn coin_at(&self, a: &str) -> yewd_wallet::Coin {
        self.w
            .coins
            .iter()
            .find(|c| c.script == addr_script(a))
            .unwrap()
            .clone()
    }
}

/// `sendtoaddress`, `sendmany` and `fundrawtransaction` select ordinary (ECC) coins only (beta2
/// audit M-1, review LOW-1, the C++ lines' `SelectCoins`): 8 YEC is covered by the 9 YEC of ECC
/// coins, so no post-quantum coin is spent even though two of the three 5 YEC coins are
/// post-quantum (largest first used to take them, with the change on a new ECC key).
#[tokio::test]
async fn stock_sends_spend_ecc_coins_only() {
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x34; 20]);
    for call in ["sendtoaddress", "sendmany", "fundrawtransaction"] {
        let mut f = fixture(&format!("ecc-only-{call}")).await;
        let ecc = addr_script(&f.ecc.clone());
        let r = f
            .stock_send(call, &to, 8.0)
            .await
            .unwrap_or_else(|e| panic!("{call}: {e:?}"));
        let tx = if call == "fundrawtransaction" {
            let v: Value = serde_json::from_str(&r).unwrap();
            let raw = hex::decode(v["hex"].as_str().unwrap()).unwrap();
            Transaction::parse(&raw).unwrap().0
        } else {
            f.last_sent().0
        };
        let scripts = f.input_scripts(&tx);
        assert!(!scripts.is_empty(), "{call}");
        for s in &scripts {
            assert_eq!(s, &ecc, "{call}: a post-quantum coin was selected");
        }
        // the change, if any, is a new ECC key's (never a post-quantum one)
        for o in &tx.vout {
            assert!(yew_core::pq::pqpkh_of(&o.script_pubkey).is_none(), "{call}");
        }
    }
}

/// ECC coins short, post-quantum coins present: each call refuses with the C++ lines' text and
/// its own code (`sendtoaddress` -4 after SendMoney's checks, `sendmany` -6, `fundrawtransaction`
/// -32603), naming only the post-quantum value `z_sendmany` would spend: no FN-DSA coin before
/// Falcon, no output YED holds, no unconfirmed coin, no locked coin. A YED-bearing ECC output is
/// never selected or counted either. Without such post-quantum coins the errors stay the ordinary
/// insufficient-funds ones. Nothing is broadcast.
#[tokio::test]
async fn stock_sends_name_the_post_quantum_value_when_ecc_coins_fall_short() {
    let mut f = fixture("ecc-short").await;
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x35; 20]);
    let codes = [
        ("sendtoaddress", -4),
        ("sendmany", -6),
        ("fundrawtransaction", -32603),
    ];
    let expect = |got: Vec<(&'static str, Answer)>, pq: i64| {
        for ((name, r), (n2, c)) in got.into_iter().zip(codes) {
            assert_eq!(name, n2);
            assert_eq!(r, Err((c, pq_refusal(pq))), "{name}");
        }
    };
    // 12 YEC: 9 at ECC, 5 SLH-DSA + 5 FN-DSA
    let got = f.stock_sends(&to, 12.0).await;
    expect(got, 10 * COIN);
    // before Falcon an FN-DSA coin is not one z_sendmany would spend
    f.w.chain.falcon_active = Some(false);
    let got = f.stock_sends(&to, 12.0).await;
    expect(got, 5 * COIN);
    f.w.chain.falcon_active = Some(true);
    // an unconfirmed post-quantum payment is not counted (z_sendmany's minconf 1)
    f.node.to_mempool(payment(
        OutPoint {
            txid: [6; 32],
            n: 0,
        },
        addr_script(&f.slh.clone()),
        3 * COIN,
    ));
    f.w.sync(&f.node).await.unwrap();
    let got = f.stock_sends(&to, 12.0).await;
    expect(got, 10 * COIN);
    // outputs YED holds (Yellowback live, the index listing them): the SLH-DSA coin is not
    // counted, the ECC 5 YEC coin neither counted nor selected
    let (slh_coin, ecc_coin) = (f.coin_at(&f.slh.clone()), f.coin_at(&f.ecc.clone()));
    let ecc_coin =
        f.w.coins
            .iter()
            .find(|c| c.script == ecc_coin.script && c.value == 5 * COIN)
            .unwrap()
            .clone();
    {
        let mut c = f.node.0.lock().unwrap();
        c.yed_info = Some(json!({"healthy": true, "unhealthyReason": ""}));
        c.tokens = vec![
            json!({"txid": slh_coin.txid, "vout": slh_coin.vout}),
            json!({"txid": ecc_coin.txid, "vout": ecc_coin.vout}),
        ];
    }
    // 4.5 YEC: the ECC coins without the token hold 4
    let got = f.stock_sends(&to, 4.5).await;
    expect(got, 5 * COIN);
    assert!(
        f.node.0.lock().unwrap().sent.is_empty(),
        "nothing broadcast"
    );
    // 3 YEC is covered by the ECC coins: the token is not among the inputs
    f.w.call(&f.node, "sendtoaddress", &[json!(to), json!(3.0)])
        .await
        .unwrap();
    let (tx, _) = f.last_sent();
    assert!(tx
        .vin
        .iter()
        .all(|i| (yew_core::tx::txid_hex(&i.prevout.txid), i.prevout.n)
            != (ecc_coin.txid.clone(), ecc_coin.vout)));
    for s in f.input_scripts(&tx) {
        assert!(yew_core::pq::pqpkh_of(&s).is_none());
    }
}

/// ECC coins short and no post-quantum coin `z_sendmany` would spend (here: locked): the ordinary
/// insufficient-funds errors, unchanged.
#[tokio::test]
async fn stock_sends_without_spendable_pq_coins_keep_the_insufficient_funds_errors() {
    let mut f = fixture("ecc-short-no-pq").await;
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x36; 20]);
    let (slh, fn_) = (f.coin_at(&f.slh.clone()), f.coin_at(&f.fn_.clone()));
    f.w.call(
        &f.node,
        "lockunspent",
        &[
            json!(false),
            json!([{"txid": slh.txid, "vout": slh.vout}, {"txid": fn_.txid, "vout": fn_.vout}]),
        ],
    )
    .await
    .unwrap();
    let got = f.stock_sends(&to, 12.0).await;
    let want = [
        ("sendtoaddress", (-6, "Insufficient funds")),
        ("sendmany", (-6, "Insufficient funds")),
        ("fundrawtransaction", (-32603, "Insufficient funds")),
    ];
    for ((name, r), (n2, (c, m))) in got.into_iter().zip(want) {
        assert_eq!(name, n2);
        assert_eq!(r, Err((c, m.to_string())), "{name}");
    }
    assert!(f.node.0.lock().unwrap().sent.is_empty());
}

/// YEWD-PARITY gap 2: a post-quantum input NAMED in `fundrawtransaction` is priced by its real
/// size, as ycashd's `CreateTransaction` prices it with dummy signatures: max(min(max(the
/// ZIP-317 fee, the plain PQ rate x size), PQMaxTxFee()), the ZIP-317 conventional fee), the
/// conventional fee counting the SLH-DSA signature's bytes. It used to be priced as a P2PKH input
/// (10,000 zat, a seventh of the conventional fee alone).
#[tokio::test]
async fn fundrawtransaction_prices_a_named_pq_input_by_size() {
    let mut f = fixture("fund-named-pq").await;
    let rate = 40_000i64;
    let cap = 4_000_000i64;
    {
        let mut c = f.node.0.lock().unwrap();
        c.yed_info = Some(json!({"healthy": true, "unhealthyReason": "",
            "params": {"fees": {"network": {"plain": {"zatPerKB": rate},
                                            "yellowback": {"maxTxFeeZat": cap}}}}}));
    }
    let to = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x35; 20]);
    // the fixture's 5 YEC SLH-DSA coin, as the wallet lists it
    let list: Value =
        serde_json::from_str(&f.w.call(&f.node, "listunspent", &[]).await.unwrap().text()).unwrap();
    let coin = list
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["address"].as_str() == Some(f.slh.as_str()))
        .expect("the SLH-DSA coin")
        .clone();
    let mut txid: [u8; 32] = hex::decode(coin["txid"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    txid.reverse();
    let mut raw = Transaction::new_v4();
    raw.vin.push(TxIn::new(OutPoint {
        txid,
        n: coin["vout"].as_u64().unwrap() as u32,
    }));
    raw.vout.push(TxOut {
        value: COIN,
        script_pubkey: addr_script(&to),
    });
    let r =
        f.w.call(
            &f.node,
            "fundrawtransaction",
            &[json!(hex::encode(raw.serialize().unwrap()))],
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let v: Value = serde_json::from_str(&r.text()).unwrap();
    let tx = Transaction::parse(&hex::decode(v["hex"].as_str().unwrap()).unwrap())
        .unwrap()
        .0;
    let slh = yew_core::pq::pq_sig_pushes_size(yew_core::pq::SCHEME_SLH_DSA_SHA2_128S).unwrap();
    let mut sizes = vec![slh];
    sizes.resize(tx.vin.len(), yew_core::tx::MAX_P2PKH_SCRIPT_SIG);
    let bytes = tx.size_with_script_sigs(&sizes).unwrap();
    let conventional = tx.zip317_conventional_fee(&sizes).unwrap();
    let want = (rate * bytes as i64 / 1000)
        .max(conventional)
        .min(cap)
        .max(conventional);
    let fee = (v["fee"].as_f64().unwrap() * COIN as f64).round() as i64;
    assert_eq!(fee, want, "bytes {bytes} conventional {conventional}");
    assert!(fee > 300_000, "{fee}");
    let paid: i64 = 5 * COIN - tx.vout.iter().map(|o| o.value).sum::<i64>()
        + tx.vin[1..]
            .iter()
            .map(|i| f.prevout(&i.prevout.txid, i.prevout.n).1)
            .sum::<i64>();
    assert_eq!(paid, fee);
}

/// ycashd's linking rule (wallet_tx_builder.cpp GetRequiredPrivacyPolicy): ANY_TADDR combines coins
/// of several transparent addresses only under NoPrivacy (a transparent recipient) or
/// AllowLinkingAccountAddresses (a shielded one); its "Insufficient funds" carries the linking hint
/// unless the policy allows linking. Found by KG-YEWD-REAL against a ycash6 wallet node.
#[tokio::test]
async fn any_taddr_links_addresses_only_where_the_policy_allows() {
    let mut f = fixture("linking").await;
    let r_ecc = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x61; 20]);
    let text = |v: yewd_wallet::json::J| v.text().trim_matches('"').to_string();
    let ecc2 = text(f.w.call(&f.node, "getnewaddress", &[]).await.unwrap());
    // the 5 YEC coin pays 3 YEC to a second own address, its change to a third: three funded addresses
    let ecc = f.ecc.clone();
    f.send(
        &ecc,
        &[(&ecc2, 3 * COIN)],
        None,
        Some("AllowFullyTransparent"),
    )
    .await
    .unwrap();
    f.mine_sync().await;
    // one address covers 1 YEC: the default policy (LegacyCompat = AllowFullyTransparent) builds it
    f.send("ANY_TADDR", &[(&r_ecc, COIN)], None, None)
        .await
        .unwrap();
    f.mine_sync().await;
    // 6 YEC needs two addresses: refused as ycashd refuses, NoPrivacy builds it
    let e = f
        .send("ANY_TADDR", &[(&r_ecc, 6 * COIN)], None, None)
        .await
        .unwrap_err();
    assert_eq!(e, (-4, "Failed to build transaction: The specified privacy policy, AllowFullyTransparent, does not permit the creation of the requested transaction. Select NoPrivacy to allow this transaction to be constructed.".into()));
    // a shielded recipient needs AllowLinkingAccountAddresses or weaker
    let zaddr = f.zaddr.clone();
    let e = f
        .send(
            "ANY_TADDR",
            &[(&zaddr, 6 * COIN)],
            None,
            Some("AllowRevealedSenders"),
        )
        .await
        .unwrap_err();
    assert_eq!(e, (-4, "Failed to build transaction: The specified privacy policy, AllowRevealedSenders, does not permit the creation of the requested transaction. Select AllowLinkingAccountAddresses or weaker to allow this transaction to be constructed.".into()));
    // more than the wallet holds: the hint replaces the final full stop, unless linking is allowed
    let e = f
        .send("ANY_TADDR", &[(&r_ecc, 1000 * COIN)], None, None)
        .await
        .unwrap_err();
    assert_eq!(e.0, -8);
    assert!(
        e.1.ends_with("or weaker. (This transaction may require selecting transparent coins that were sent to multiple addresses, which is not enabled by default because it would create a public link between those addresses. THIS MAY AFFECT YOUR PRIVACY. Resubmit with the `privacyPolicy` parameter set to `AllowLinkingAccountAddresses` or weaker if you wish to allow this transaction to proceed anyway.)"),
        "{}",
        e.1
    );
    let e = f
        .send(
            "ANY_TADDR",
            &[(&r_ecc, 1000 * COIN)],
            None,
            Some("NoPrivacy"),
        )
        .await
        .unwrap_err();
    assert!(
        e.1.starts_with("Insufficient funds") && !e.1.contains("public link"),
        "{}",
        e.1
    );
    f.send("ANY_TADDR", &[(&r_ecc, 6 * COIN)], None, Some("NoPrivacy"))
        .await
        .unwrap();
}
