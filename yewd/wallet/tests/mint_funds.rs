// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! `yed_mint` refuses a mint its source cannot cover in full before the carrier is broadcast
//! (real-stack run YEW-REAL finding 5, review M-1). The whole need is the collateral,
//! `TOKEN_VALUE`, the protocol fee (when the window has a payee), the attestor fee (while armed)
//! and the carrier's and the MINT's network fees. A wallet one zatoshi short of it broadcasts
//! nothing; a wallet holding exactly that much gets its carrier. The source is the wallet's plain
//! coins (`from` empty) or one transparent address. (A Sapling source is covered by the planner's
//! unit tests in `mint.rs`; building its notes here would need the Sapling proving parameters.)

mod common;

use common::*;
use yew_core::params::TOKEN_VALUE;

const COIN: i64 = 100_000_000;
const FLAT: i64 = 10_000;
const COLLATERAL: i64 = 6 * COIN;
const CENTS: i64 = 20_000;
const P_MINT: i64 = 50_000_000;
const ATTEST_BPS: i64 = 1_000;

#[derive(Clone, Copy, Debug)]
struct Case {
    payee: bool,
    armed: bool,
}

struct Fix {
    node: MockNode,
    w: Wallet,
    ecc: String,
}

fn addr_script(a: &str) -> Vec<u8> {
    yewd_wallet::rpc::parse_taddr_script(Network::Regtest, a).unwrap()
}

fn protocol_fee() -> i64 {
    yew_core::params::protocol_fee_zat(CENTS as u64, P_MINT).unwrap()
}

/// The whole need of the case: every output of the MINT and both network fees (the flat fee:
/// neither shape reaches the ZIP-317 conventional fee above it).
fn need(c: Case) -> i64 {
    let fee = if c.payee { protocol_fee() } else { 0 };
    let attest = if c.armed {
        protocol_fee() * ATTEST_BPS / 10_000
    } else {
        0
    };
    COLLATERAL + TOKEN_VALUE + fee + attest + 2 * FLAT
}

/// A wallet past the Vault activation whose ECC address holds `coins` (and nothing else).
async fn fixture(name: &str, c: Case, coins: &[i64]) -> Fix {
    let node = MockNode::default();
    node.0.lock().unwrap().vault_height = Some(1);
    genesis(&node);
    let d = dir(name);
    let mut w = Wallet::open(&d, Network::Regtest, core_signer(&d.join("signer")), 0).unwrap();
    w.sync(&node).await.unwrap();
    let ecc = w
        .call(&node, "getnewaddress", &[])
        .await
        .unwrap()
        .text()
        .trim_matches('"')
        .to_string();
    let foreign = |n: u32| OutPoint { txid: [7; 32], n };
    let mut txs = vec![coinbase(1, vec![0x51], 0)];
    for (i, v) in coins.iter().enumerate() {
        txs.push(payment(foreign(i as u32), addr_script(&ecc), *v));
    }
    // the coins' block, then four more; the block salt is the block's place in this list
    let mut blocks = vec![txs];
    for h in 2..6u32 {
        blocks.push(vec![coinbase(h, vec![0x51], 0)]);
    }
    for (i, txs) in blocks.into_iter().enumerate() {
        node.mine(txs, u8::try_from(i).unwrap());
    }
    w.sync(&node).await.unwrap();
    let tip = node.0.lock().unwrap().blocks.len() as i64 - 1;
    let r = tip - 2;
    let payee = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x41; 20]);
    let bond = yew_core::keys::encode_p2pkh(Network::Regtest, &[0x42; 20]);
    {
        let mut ch = node.0.lock().unwrap();
        ch.yed_info = Some(json!({
            "healthy": true,
            "unhealthyReason": "",
            "height": tip,
            "startHeight": 1,
            "params": {
                "minMintCents": 10_000,
                "maxMintCents": 10_000_000,
                "feeZat": FLAT,
                "refLag": 2,
                "refWindow": 40,
                "claimDelay": 10,
                "attestorSetId": "11".repeat(32),
                "attest": {"attestFeeBps": ATTEST_BPS, "divergeBpsAttest": 500},
                "policy": {},
            },
        }));
        let a = &mut ch.answers;
        a.insert(
            "yed_estimatecollateral".into(),
            Ok(json!({
                "requiredZat": COLLATERAL,
                "refHeight": r,
                "pMint": P_MINT,
                "xMint": P_MINT,
                "termClass": "A",
                "claimHeight": r + 1000,
                "mintBlocked": false,
            })),
        );
        a.insert("yed_getprice".into(), Ok(json!({"armed": c.armed})));
        a.insert(
            "yed_buildbundle".into(),
            Ok(json!({"hex": "aa".repeat(74), "seqs": [1], "aMint": P_MINT, "aClaim": P_MINT})),
        );
        a.insert(
            "yed_listattestors".into(),
            Ok(json!([{"seq": 1, "weight": 1, "bondKeyAddress": bond}])),
        );
        a.insert(
            "yed_getfeepayee".into(),
            if c.payee {
                Ok(json!({"eligible": [payee], "preferred": payee}))
            } else {
                Err((
                    -26,
                    "fee-no-eligible-payee: no pool quoted in the payee window (FEE-0)".into(),
                ))
            },
        );
    }
    Fix { node, w, ecc }
}

impl Fix {
    fn sent(&self) -> usize {
        self.node.0.lock().unwrap().sent.len()
    }

    /// `yed_mint CENTS 1000 from "" false` (the carrier only).
    async fn mint(&mut self, from: &str) -> Result<Value, (i64, String)> {
        let p = [
            json!(CENTS),
            json!(1000),
            json!(from),
            json!(""),
            json!(false),
        ];
        self.w
            .call(&self.node, "yed_mint", &p)
            .await
            .map(|v| serde_json::from_str(&v.text()).unwrap())
            .map_err(|e| (e.code, e.message))
    }
}

fn money(z: i64) -> String {
    yewd_wallet::rpc::format_money(z)
}

/// Each case, from the wallet's coins and from its one address: one zatoshi short of the whole
/// need is refused with that need and nothing is broadcast; exactly the need gets the carrier.
#[tokio::test]
async fn a_mint_short_of_its_whole_need_broadcasts_nothing() {
    let cases = [
        Case {
            payee: false,
            armed: false,
        },
        Case {
            payee: true,
            armed: false,
        },
        Case {
            payee: false,
            armed: true,
        },
        Case {
            payee: true,
            armed: true,
        },
    ];
    for c in cases {
        let n = need(c);
        // the old check (the collateral and one flat fee) passed every one of these wallets
        assert!(n > COLLATERAL + FLAT);
        for (k, split) in [vec![n - 1], vec![COIN, 2 * COIN, n - 1 - 3 * COIN]]
            .into_iter()
            .enumerate()
        {
            for from_addr in [false, true] {
                let name = format!("mintfunds-short-{}-{}-{k}-{from_addr}", c.payee, c.armed);
                let mut f = fixture(&name, c, &split).await;
                let from = if from_addr {
                    f.ecc.clone()
                } else {
                    String::new()
                };
                let e = f.mint(&from).await.unwrap_err();
                assert_eq!(
                    e,
                    (
                        -4,
                        format!(
                            "insufficient-yec: need {}, have {} confirmed and unlocked",
                            money(n),
                            money(n - 1)
                        )
                    ),
                    "{c:?} {k} {from_addr}"
                );
                assert_eq!(f.sent(), 0, "{c:?} {k} {from_addr}: nothing broadcast");
            }
        }
        // exactly the need: the carrier goes out
        let name = format!("mintfunds-exact-{}-{}", c.payee, c.armed);
        let mut f = fixture(&name, c, &[COIN, n - COIN]).await;
        let r = f.mint("").await.unwrap_or_else(|e| panic!("{c:?}: {e:?}"));
        assert_eq!(r["pending"], json!(true), "{c:?}");
        assert_eq!(f.sent(), 1, "{c:?}: the carrier");
    }
}
