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
    f.node.0.lock().unwrap().tokens = vec![json!({"txid": coin.txid, "vout": coin.vout})];
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
    assert!(
        msg.starts_with("Insufficient transparent funds, have 5.00, need 6.0"),
        "{msg}"
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
    // Yellowback not live (-32601): no token can exist, the send goes ahead
    f.node.0.lock().unwrap().tokens_error = Some((-32601, "Method not found".into()));
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
    assert!(
        e.1.starts_with("Invalid parameter, amount 0.0000")
            && e.1.ends_with(" of a post-quantum output"),
        "{}",
        e.1
    );
    // an explicit fee below what the PQ spend needs, and one above the cap
    let e = f
        .send(&slh, &[(&to, COIN)], Some(1_000), None)
        .await
        .unwrap_err();
    assert_eq!(e.0, -8);
    assert!(
        e.1.starts_with("Fee 0.00001 is below the 0.00")
            && e.1.ends_with(" this post-quantum spend needs"),
        "{}",
        e.1
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
    assert!(e.1.starts_with(
        "Could not send to the Sapling shielded pool without spending non-Sapling funds"
    ));
    let e = f
        .send(&fn_, &[(&to, COIN)], None, Some("AllowRevealedAmounts"))
        .await
        .unwrap_err();
    assert_eq!(e.0, -8);
    assert!(e
        .1
        .starts_with("This transaction would have transparent recipients"));
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
    // a token is never spent as plain YEC: the FN-DSA address's only coin
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
            -6,
            format!("insufficient confirmed funds at {fn_}: need 1.0001 more")
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
