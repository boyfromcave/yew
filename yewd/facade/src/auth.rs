// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! Client→façade authentication, as ycashd: HTTP Basic against `rpcuser:rpcpassword`, or
//! against the cookie the façade writes at start (`__cookie__:<64 hex>`, file mode 0600) when no
//! password is configured. Compared in constant time.

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;

pub const COOKIE_USER: &str = "__cookie__";

/// The accepted `user:password` strings.
#[derive(Clone)]
pub struct Credentials {
    accepted: Vec<Vec<u8>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials({} accepted)", self.accepted.len())
    }
}

fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    // the length is not secret (ycashd's TimingResistantEqual also leaks it)
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Credentials {
    pub fn user_pass(user: &str, pass: &str) -> Self {
        Credentials {
            accepted: vec![format!("{user}:{pass}").into_bytes()],
        }
    }

    /// Whether an `Authorization` header value is accepted.
    pub fn check(&self, header: Option<&[u8]>) -> bool {
        let Some(h) = header else { return false };
        let Ok(h) = std::str::from_utf8(h) else {
            return false;
        };
        let Some(b64) = h.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
            return false;
        };
        // no early exit: every accepted value is compared
        self.accepted
            .iter()
            .fold(false, |ok, a| eq_ct(a, &decoded) | ok)
    }
}

/// A cookie file written at start and removed at exit.
pub struct Cookie {
    path: PathBuf,
}

impl Cookie {
    /// Write a fresh cookie at `path` and return the credentials it grants.
    pub fn create(path: &Path) -> std::io::Result<(Cookie, Credentials)> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(std::io::Error::other)?;
        let line = format!("{COOKIE_USER}:{}", hex::encode(secret));
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let mut f = o.open(&tmp)?;
            f.write_all(line.as_bytes())?;
        }
        std::fs::rename(&tmp, path)?;
        Ok((
            Cookie {
                path: path.to_path_buf(),
            },
            Credentials {
                accepted: vec![line.into_bytes()],
            },
        ))
    }
}

impl Drop for Cookie {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The `Authorization` header value for `user:pass`.
pub fn basic_header(user_pass: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(user_pass)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_and_cookie() {
        // the harness's user names are not ASCII (test_framework/util.py rpc_auth_pair)
        let c = Credentials::user_pass("rpcuser💻0", "rpcpass🔑0");
        assert!(c.check(Some(basic_header("rpcuser💻0:rpcpass🔑0").as_bytes())));
        assert!(!c.check(Some(basic_header("rpcuser💻0:wrong").as_bytes())));
        assert!(!c.check(None));
        assert!(!c.check(Some(b"Bearer x")));

        let dir = std::env::temp_dir().join(format!("yewd-auth-{}", std::process::id()));
        let path = dir.join(".cookie");
        let (cookie, creds) = Cookie::create(&path).unwrap();
        let line = std::fs::read_to_string(&path).unwrap();
        assert!(line.starts_with("__cookie__:") && line.len() == 11 + 64);
        assert!(creds.check(Some(basic_header(&line).as_bytes())));
        drop(cookie);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
