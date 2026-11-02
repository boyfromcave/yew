// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The wallet's JSON writer. ycashd writes YEC amounts as JSON numbers with exactly eight
//! decimals (`ValueFromAmount`: `1.50000000`), never through a binary float (plan §3b S4,
//! "Number formatting"); [`J::Amount`] does the same from integer zatoshi. Keys keep their
//! insertion order, as `UniValue` does. [`J::Raw`] embeds JSON text from the node unchanged.

use std::fmt::Write;

/// A JSON value as the façade writes it.
#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Int(i64),
    /// A YEC amount in zatoshi, written `n.nnnnnnnn`.
    Amount(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
    /// JSON text taken from the node as is.
    Raw(String),
}

impl J {
    pub fn obj() -> J {
        J::Obj(Vec::new())
    }

    /// Append `key: value` to an object (no-op on anything else).
    pub fn push(&mut self, key: &str, value: J) -> &mut J {
        if let J::Obj(v) = self {
            if let Some(slot) = v.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value;
            } else {
                v.push((key.to_string(), value));
            }
        }
        self
    }

    /// `push` that returns `self` (builder style).
    pub fn with(mut self, key: &str, value: impl Into<J>) -> J {
        self.push(key, value.into());
        self
    }

    pub fn write(&self, out: &mut String) {
        match self {
            J::Null => out.push_str("null"),
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::Int(i) => {
                let _ = write!(out, "{i}");
            }
            J::Amount(z) => out.push_str(&amount_text(*z)),
            J::Str(s) => out.push_str(&serde_json::to_string(s).expect("a string serializes")),
            J::Arr(v) => {
                out.push('[');
                for (i, e) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    e.write(out);
                }
                out.push(']');
            }
            J::Obj(v) => {
                out.push('{');
                for (i, (k, e)) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).expect("a string serializes"));
                    out.push(':');
                    e.write(out);
                }
                out.push('}');
            }
            J::Raw(r) => out.push_str(r),
        }
    }

    pub fn text(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }
}

impl From<bool> for J {
    fn from(b: bool) -> J {
        J::Bool(b)
    }
}
impl From<i64> for J {
    fn from(i: i64) -> J {
        J::Int(i)
    }
}
impl From<u32> for J {
    fn from(i: u32) -> J {
        J::Int(i as i64)
    }
}
impl From<u64> for J {
    fn from(i: u64) -> J {
        J::Int(i as i64)
    }
}
impl From<i32> for J {
    fn from(i: i32) -> J {
        J::Int(i as i64)
    }
}
impl From<usize> for J {
    fn from(i: usize) -> J {
        J::Int(i as i64)
    }
}
impl From<&str> for J {
    fn from(s: &str) -> J {
        J::Str(s.to_string())
    }
}
impl From<String> for J {
    fn from(s: String) -> J {
        J::Str(s)
    }
}
impl From<Vec<J>> for J {
    fn from(v: Vec<J>) -> J {
        J::Arr(v)
    }
}
impl<T: Into<J>> From<Option<T>> for J {
    fn from(o: Option<T>) -> J {
        o.map(Into::into).unwrap_or(J::Null)
    }
}

/// `ValueFromAmount`: `-0.00000244`, `30.00000000`.
pub fn amount_text(zat: i64) -> String {
    let sign = if zat < 0 { "-" } else { "" };
    let z = zat.unsigned_abs();
    format!("{sign}{}.{:08}", z / 100_000_000, z % 100_000_000)
}

/// A YEC amount argument (`AmountFromValue`): a JSON number or a numeric string, at most eight
/// decimals, parsed from its text (never through a float). `None` for anything else.
pub fn amount_from_json(v: &serde_json::Value) -> Option<i64> {
    let text = match v {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => return None,
    };
    parse_amount(&text)
}

/// Parse `"1.5"`, `"1e-8"` style decimal text into zatoshi (eight decimals at most).
pub fn parse_amount(text: &str) -> Option<i64> {
    let t = text.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    // exponent form (serde_json writes small floats as 1e-8)
    let (mant, exp) = match t.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>().ok()?),
        None => (t, 0),
    };
    let (int, frac) = match mant.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mant, ""),
    };
    if int.is_empty() && frac.is_empty()
        || !int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let digits = format!("{int}{frac}");
    let scale = frac.len() as i32 - exp; // value = digits * 10^-scale
    let shift = 8 - scale; // zat = digits * 10^shift
    let digits = digits.trim_start_matches('0');
    let mut zat: i128 = if digits.is_empty() {
        0
    } else {
        digits.parse().ok()?
    };
    if shift >= 0 {
        zat = zat.checked_mul(10i128.checked_pow(shift as u32)?)?;
    } else {
        let d = 10i128.checked_pow((-shift) as u32)?;
        if zat % d != 0 {
            return None; // more than eight decimals
        }
        zat /= d;
    }
    let zat = i64::try_from(zat).ok()?;
    Some(if neg { -zat } else { zat })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(amount_text(150_000_000), "1.50000000");
        assert_eq!(amount_text(-244), "-0.00000244");
        assert_eq!(parse_amount("1.5"), Some(150_000_000));
        assert_eq!(parse_amount("1e-8"), Some(1));
        assert_eq!(parse_amount("0.000000001"), None);
        assert_eq!(
            parse_amount("20999999.99999999"),
            Some(2_099_999_999_999_999)
        );
        assert_eq!(parse_amount("-0.5"), Some(-50_000_000));
        assert_eq!(parse_amount("abc"), None);
    }

    #[test]
    fn writes_in_order() {
        let j = J::obj()
            .with("b", 1i64)
            .with("a", J::Amount(10))
            .with("s", "x\"y")
            .with("n", J::Null)
            .with("r", J::Raw("[1,2]".into()));
        assert_eq!(
            j.text(),
            r#"{"b":1,"a":0.00000010,"s":"x\"y","n":null,"r":[1,2]}"#
        );
    }
}
