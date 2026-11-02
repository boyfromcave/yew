// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The façade's end of the signer socket: one connection, reopened once when it broke (a signer
//! restart), one request at a time.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use crate::{Envelope, Request, Response};

pub struct SocketClient {
    pub path: PathBuf,
    conn: Mutex<Option<BufReader<UnixStream>>>,
}

impl SocketClient {
    pub fn new(path: PathBuf) -> SocketClient {
        SocketClient {
            path,
            conn: Mutex::new(None),
        }
    }

    fn connect(&self) -> Result<BufReader<UnixStream>, String> {
        let s = UnixStream::connect(&self.path).map_err(|e| {
            format!(
                "the signer at {} is not reachable: {e}",
                self.path.display()
            )
        })?;
        // an SLH-DSA owner spend takes a fraction of a second; a stuck signer is an error
        s.set_read_timeout(Some(Duration::from_secs(120))).ok();
        Ok(BufReader::new(s))
    }

    fn once(c: &mut BufReader<UnixStream>, line: &str) -> std::io::Result<String> {
        c.get_mut().write_all(line.as_bytes())?;
        let mut out = String::new();
        if c.read_line(&mut out)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the signer closed the connection",
            ));
        }
        Ok(out)
    }

    /// Send one request and read its answer.
    pub fn call(&self, request: Request) -> Result<Response, String> {
        let mut line = serde_json::to_string(&Envelope::new(request)).map_err(|e| e.to_string())?;
        line.push('\n');
        let mut slot = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for attempt in 0..2 {
            if slot.is_none() {
                *slot = Some(self.connect()?);
            }
            let c = slot.as_mut().expect("connected");
            match Self::once(c, &line) {
                Ok(out) => {
                    return serde_json::from_str(out.trim_end())
                        .map_err(|e| format!("the signer's answer does not parse: {e}"))
                }
                Err(e) => {
                    *slot = None;
                    if attempt == 1 {
                        return Err(format!("the signer at {}: {e}", self.path.display()));
                    }
                }
            }
        }
        unreachable!()
    }
}
