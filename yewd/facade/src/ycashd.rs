// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! ycashd's own answers about its methods (workspace plan §3b S4, "arity and help"): the help text
//! and the accepted argument counts of every method the façade serves itself, and ycashd's `help`
//! listing, from `ycashd_rpc.json` (generated from a plain ycash6 wallet node by
//! `yewd/qa/gen_ycashd_rpc_table.py`; regenerate it when `yewd/PIN`'s ycash6 moves).
//!
//! ycash6 checks arity in its RPC table before a handler runs (`src/rpc/server.cpp`
//! `CRPCTable::execute`): too few or too many arguments answer `-32602` with
//! "Not enough|Too many parameters for method `<m>`. Needed exactly <n> | at least <a> and at most
//! <b>, but received <k>", then a blank line and the help text (absent when the handler's help
//! branch does not throw: `walletlock`/`walletpassphrase` on an unencrypted wallet).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct MethodInfo {
    pub help: String,
    pub min: Option<usize>,
    pub max: Option<usize>,
    #[serde(default)]
    pub helptail: bool,
}

#[derive(Debug, Deserialize)]
struct Table {
    #[serde(rename = "_help")]
    help: String,
    methods: BTreeMap<String, MethodInfo>,
}

fn table() -> &'static Table {
    static T: OnceLock<Table> = OnceLock::new();
    T.get_or_init(|| {
        serde_json::from_str(include_str!("ycashd_rpc.json")).expect("ycashd_rpc.json parses")
    })
}

pub fn info(method: &str) -> Option<&'static MethodInfo> {
    table().methods.get(method)
}

/// ycashd's help text of `method`, if the table has it.
pub fn help(method: &str) -> Option<&'static str> {
    info(method).map(|i| i.help.as_str())
}

/// The `-32602` message for `n` arguments, or `None` when `n` is accepted. `encrypted` decides
/// the help tail of the two methods whose help branch depends on it.
pub fn arity_error(method: &str, n: usize, encrypted: bool) -> Option<String> {
    let i = info(method)?;
    let (lo, hi) = (i.min?, i.max?);
    if (lo..=hi).contains(&n) {
        return None;
    }
    let tail = match method {
        "walletlock" | "walletpassphrase" => encrypted,
        _ => i.helptail,
    };
    Some(format!(
        "{} for method `{method}`. Needed {}, but received {n}{}",
        if n < lo {
            "Not enough parameters"
        } else {
            "Too many parameters"
        },
        if lo == hi {
            format!("exactly {lo}")
        } else {
            format!("at least {lo} and at most {hi}")
        },
        if tail {
            format!("\n\n{}", i.help)
        } else {
            String::new()
        }
    ))
}

/// One `help` listing, parsed: categories in order, each with its lines (`"<method> <synopsis>"`).
fn parse_listing(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        if let Some(c) = line.strip_prefix("== ").and_then(|l| l.strip_suffix(" ==")) {
            out.push((c.to_string(), Vec::new()));
        } else if !line.trim().is_empty() {
            if out.is_empty() {
                out.push((String::new(), Vec::new()));
            }
            out.last_mut().expect("pushed").1.push(line.to_string());
        }
    }
    out
}

fn method_of(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

/// The `help` listing the façade answers: the backend's, with ycashd's lines for every method
/// `served(method)` merged into ycashd's categories (in ycashd's order), so the pair lists what a
/// ycashd wallet node lists for the façade's methods.
pub fn merged_listing(backend: &str, served: impl Fn(&str) -> bool) -> String {
    let reference = parse_listing(&table().help);
    let mut have = parse_listing(backend);
    for (cat, lines) in &reference {
        let add: Vec<&String> = lines.iter().filter(|l| served(method_of(l))).collect();
        if add.is_empty() {
            continue;
        }
        let pos = match have.iter().position(|(c, _)| c == cat) {
            Some(p) => p,
            // a node without a live Yellowback lists no Yellowback category, and a ycashd wallet
            // node then registers no yed_ command either (yellowback_stock_node.py): none is added
            None if cat == "Yellowback" => continue,
            None => {
                // a category the backend lacks: after the last reference category before it
                let before: Vec<&String> = reference
                    .iter()
                    .take_while(|(c, _)| c != cat)
                    .map(|(c, _)| c)
                    .collect();
                let at = have
                    .iter()
                    .rposition(|(c, _)| before.contains(&c))
                    .map(|p| p + 1)
                    .unwrap_or(have.len());
                have.insert(at, (cat.clone(), Vec::new()));
                at
            }
        };
        let entry = &mut have[pos].1;
        for l in add {
            if !entry.iter().any(|e| method_of(e) == method_of(l)) {
                entry.push(l.clone());
            }
        }
        entry.sort_by(|a, b| method_of(a).cmp(method_of(b)));
    }
    let mut s = String::new();
    for (i, (cat, lines)) in have.iter().enumerate() {
        if i > 0 {
            s.push('\n');
        }
        if !cat.is_empty() {
            s.push_str(&format!("== {cat} ==\n"));
        }
        for l in lines {
            s.push_str(l);
            s.push('\n');
        }
    }
    s.trim_end_matches('\n').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_covers_the_wallet_methods() {
        for (m, _, _) in crate::methods::wallet_methods() {
            let i = info(m).unwrap_or_else(|| panic!("{m} is not in ycashd_rpc.json"));
            assert!(i.min.is_some() && i.max.is_some(), "{m}");
            assert!(i.help.starts_with(m), "{m}");
        }
        for m in crate::methods::LOCAL {
            assert!(info(m).is_some(), "{m}");
        }
    }

    #[test]
    fn arity_messages() {
        let m = arity_error("getbalance", 9, false).unwrap();
        assert!(m.starts_with(
            "Too many parameters for method `getbalance`. Needed at least 0 and at most 5, but received 9\n\ngetbalance ("
        ));
        assert_eq!(arity_error("getbalance", 5, false), None);
        let m = arity_error("dumpprivkey", 0, false).unwrap();
        assert!(m.starts_with(
            "Not enough parameters for method `dumpprivkey`. Needed exactly 1, but received 0\n\n"
        ));
        assert_eq!(
            arity_error("walletlock", 1, false).unwrap(),
            "Too many parameters for method `walletlock`. Needed exactly 0, but received 1"
        );
        assert!(arity_error("walletlock", 1, true)
            .unwrap()
            .contains("\n\nwalletlock"));
    }

    #[test]
    fn the_listing_merges_into_ycashd_categories() {
        let backend = "== Blockchain ==\ngetblockcount\n\n== Util ==\nvalidateaddress \"address\"\n\n== Yellowback ==\nyed_getinfo";
        let out = merged_listing(backend, |m| m == "getbalance" || m == "yed_mint");
        assert!(out.contains("== Wallet ==\ngetbalance ("), "{out}");
        assert!(out.contains("yed_mint cents lockBlocks"), "{out}");
        // a node without a live Yellowback (no Yellowback category): no yed_ line is added
        let stock = "== Blockchain ==\ngetblockcount";
        let out = merged_listing(stock, |m| m == "getbalance" || m == "yed_mint");
        assert!(!out.contains("yed_"), "{out}");
        assert!(out.contains("getbalance"), "{out}");
        assert!(
            out.starts_with("== Blockchain ==\ngetblockcount\n"),
            "{out}"
        );
    }
}
