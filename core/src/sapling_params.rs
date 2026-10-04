// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The Sapling proving parameters (yew-shielded plan S0-2): `sapling-spend.params` (47,958,396
//! bytes) and `sapling-output.params` (3,592,860 bytes), the Groth16 parameters of the Sapling
//! MPC that every Ycash node and wallet proves with (Ycash inherited Sapling unchanged; ycashd
//! 4.5.0's `fetch-params.sh` fetches the same two files, ycashd 6.21.0 links them in). Only a
//! shielded **send** needs them; receiving and syncing never do, so YEW downloads them on the
//! first shielded send instead of shipping 52 MB in the app.
//!
//! **Integrity is the SHA-256 pin, not the transport.** Each file is streamed to `<name>.part`
//! while hashed; it is kept (renamed into place) only if its length and SHA-256 equal the
//! constants below (the sums `x402-ycash/light/README.md` records, which are those of the
//! upstream Zcash `fetch-params.sh`). A server, CDN or network that substitutes other bytes gets a
//! refusal, never a different circuit. Before a proof the files are hashed again, once per
//! process ([`ensure_verified`]), so a file changed on disk after download is refused too.
//!
//! **Sources.** The base URL is configurable ([`ParamsSource::parse`]): `https://host[:port]/dir/`
//! (rustls over `tokio-rustls`, the Mozilla roots of `webpki-roots`, up to five redirects to
//! another `https` URL), `http://` only to a loopback host (tests), and `file:///dir/` (tests,
//! and a copy already on the device). The HTTP/1.1 client is deliberately small (one `GET`,
//! `Content-Length`, chunked or close-delimited bodies) because the bytes are verified anyway.
//! With no address in Settings, [`DEFAULT_SOURCES`] are tried in order (owner decision
//! 2026-10-04): a Ycash-hosted mirror first as soon as one exists, then the source ycashd's own
//! `zcutil/fetch-params.sh` uses today. The pinned SHA-256s make the host a question of
//! availability, not trust.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// One parameter file and its pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParamFile {
    /// The file name, under the parameters directory and the base URL.
    pub name: &'static str,
    /// Its exact length.
    pub bytes: u64,
    /// Its SHA-256, lowercase hex.
    pub sha256: &'static str,
}

/// The Sapling spend parameters.
pub const SPEND: ParamFile = ParamFile {
    name: "sapling-spend.params",
    bytes: 47_958_396,
    sha256: "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13",
};

/// The Sapling output parameters.
pub const OUTPUT: ParamFile = ParamFile {
    name: "sapling-output.params",
    bytes: 3_592_860,
    sha256: "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4",
};

/// Both files, in download order.
pub const FILES: [ParamFile; 2] = [SPEND, OUTPUT];

/// Where the files are fetched when Settings names no address, tried in order. A Ycash-hosted
/// mirror is listed first as soon as one exists (owner, 2026-10-04: the Ycash Foundation is
/// being asked). Until then the only entry is the base URL ycashd's own parameter fetcher
/// downloads from (`DOWNLOAD_URL`, `ycash/zcutil/fetch-params.sh:20`). Every file is checked
/// against [`FILES`]' pinned SHA-256 whatever its source.
pub const DEFAULT_SOURCES: &[&str] = &["https://download.z.cash/downloads/"];

/// Total bytes of a download from nothing.
pub const TOTAL_BYTES: u64 = SPEND.bytes + OUTPUT.bytes;

/// Redirects followed per file.
const MAX_REDIRECTS: usize = 5;
/// Bound on a response header block.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Parameter errors.
#[derive(Debug, Error)]
pub enum ParamsError {
    /// The base URL is not usable.
    #[error("parameters source {0}: {1}")]
    Source(String, String),
    /// A local file operation failed.
    #[error("parameters file {0}: {1}")]
    Io(String, std::io::Error),
    /// The transfer failed.
    #[error("downloading {0}: {1}")]
    Transfer(String, String),
    /// The bytes are not the pinned file.
    #[error("{name}: got {got_bytes} bytes with SHA-256 {got_sha256}, expected {bytes} bytes with SHA-256 {sha256}; refused")]
    Mismatch {
        /// The file.
        name: &'static str,
        /// What arrived.
        got_bytes: u64,
        /// Its hash.
        got_sha256: String,
        /// The pinned length.
        bytes: u64,
        /// The pinned hash.
        sha256: &'static str,
    },
    /// The files are not there.
    #[error("the Sapling proving parameters are not downloaded yet ({0})")]
    Missing(String),
}

/// What [`status`] reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParamsState {
    /// `sapling-spend.params` is present with the pinned length.
    pub spend_present: bool,
    /// `sapling-output.params` is present with the pinned length.
    pub output_present: bool,
    /// Both files are present and were hashed against the pins in this process.
    pub verified: bool,
    /// Bytes still to download.
    pub missing_bytes: u64,
}

impl ParamsState {
    /// Both files are present (with the pinned lengths).
    pub fn present(&self) -> bool {
        self.spend_present && self.output_present
    }
}

/// Directories verified in this process (path → true), so a send hashes the 52 MB once.
fn verified_dirs() -> &'static Mutex<Vec<PathBuf>> {
    static V: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    V.get_or_init(|| Mutex::new(Vec::new()))
}

fn is_verified(dir: &Path) -> bool {
    verified_dirs()
        .lock()
        .map(|v| v.iter().any(|d| d == dir))
        .unwrap_or(false)
}

fn mark_verified(dir: &Path, yes: bool) {
    if let Ok(mut v) = verified_dirs().lock() {
        v.retain(|d| d != dir);
        if yes {
            v.push(dir.to_path_buf());
        }
    }
}

fn present(dir: &Path, f: &ParamFile) -> bool {
    fs::metadata(dir.join(f.name))
        .map(|m| m.is_file() && m.len() == f.bytes)
        .unwrap_or(false)
}

/// Presence (by length) of both files under `dir`; no hashing.
pub fn status(dir: &Path) -> ParamsState {
    let spend_present = present(dir, &SPEND);
    let output_present = present(dir, &OUTPUT);
    let missing_bytes = (if spend_present { 0 } else { SPEND.bytes })
        + (if output_present { 0 } else { OUTPUT.bytes });
    ParamsState {
        spend_present,
        output_present,
        verified: spend_present && output_present && is_verified(dir),
        missing_bytes,
    }
}

/// SHA-256 and length of a file.
fn hash_file(path: &Path) -> Result<(u64, String), std::io::Error> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut n = 0u64;
    loop {
        let k = std::io::Read::read(&mut f, &mut buf)?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        n += k as u64;
    }
    Ok((n, crate::keys::hex(&h.finalize())))
}

fn check_file(dir: &Path, f: &ParamFile) -> Result<(), ParamsError> {
    let path = dir.join(f.name);
    let (got_bytes, got_sha256) =
        hash_file(&path).map_err(|e| ParamsError::Io(path.display().to_string(), e))?;
    if got_bytes != f.bytes || got_sha256 != f.sha256 {
        return Err(ParamsError::Mismatch {
            name: f.name,
            got_bytes,
            got_sha256,
            bytes: f.bytes,
            sha256: f.sha256,
        });
    }
    Ok(())
}

/// Hash both files against the pins (once per process per directory). The prover is loaded
/// only after this returned `Ok`.
pub fn ensure_verified(dir: &Path) -> Result<(), ParamsError> {
    let s = status(dir);
    if !s.present() {
        return Err(ParamsError::Missing(dir.display().to_string()));
    }
    if s.verified {
        return Ok(());
    }
    let r = FILES.iter().try_for_each(|f| check_file(dir, f));
    mark_verified(dir, r.is_ok());
    r
}

/// Where the files come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamsSource {
    /// `https://host[:port]/base/` (or `http://` to a loopback host).
    Http {
        /// TLS.
        tls: bool,
        /// Host name or address.
        host: String,
        /// Port.
        port: u16,
        /// Path prefix, ending in `/`.
        path: String,
    },
    /// `file:///dir/`.
    File(PathBuf),
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

impl ParamsSource {
    /// Parse a base URL. `http://` is accepted only for a loopback host.
    pub fn parse(url: &str) -> Result<ParamsSource, ParamsError> {
        let url = url.trim();
        let bad = |m: &str| ParamsError::Source(url.to_string(), m.to_string());
        if let Some(rest) = url.strip_prefix("file://") {
            if rest.is_empty() {
                return Err(bad("empty path"));
            }
            return Ok(ParamsSource::File(PathBuf::from(rest)));
        }
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(bad(
                "must be https:// (or file://, or http:// to a loopback host)",
            ));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(bad("bad host"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
                (h, p.parse::<u16>().map_err(|_| bad("bad port"))?)
            }
            _ => (authority, if tls { 443 } else { 80 }),
        };
        if !tls && !is_loopback(host) {
            return Err(bad("plain http is allowed only to a loopback host"));
        }
        let mut path = path.to_string();
        if !path.ends_with('/') {
            path.push('/');
        }
        Ok(ParamsSource::Http {
            tls,
            host: host.to_string(),
            port,
            path,
        })
    }
}

/// Download progress: bytes so far of `total` (the files still missing when the call began).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// The file being fetched.
    pub file: &'static str,
    /// Bytes received over all files of this call.
    pub done: u64,
    /// Bytes to receive over all files of this call.
    pub total: u64,
}

/// Fetch every missing or wrong file from `source` into `dir` (created `0700` if absent),
/// verifying each against its pin before it is renamed into place. Files already present and
/// matching are kept. Returns the final [`ParamsState`] (verified).
pub async fn download(
    source: &ParamsSource,
    dir: &Path,
    progress: impl Fn(Progress) + Send + Sync,
) -> Result<ParamsState, ParamsError> {
    fs::create_dir_all(dir).map_err(|e| ParamsError::Io(dir.display().to_string(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let mut todo = Vec::new();
    for f in FILES {
        if present(dir, &f) && check_file(dir, &f).is_ok() {
            continue;
        }
        todo.push(f);
    }
    let total: u64 = todo.iter().map(|f| f.bytes).sum();
    let mut done = 0u64;
    for f in todo {
        let part = dir.join(format!("{}.part", f.name));
        let _ = fs::remove_file(&part);
        let r = fetch_one(source, &f, &part, done, total, &progress).await;
        let (n, sha) = match r {
            Ok(x) => x,
            Err(e) => {
                let _ = fs::remove_file(&part);
                return Err(e);
            }
        };
        if n != f.bytes || sha != f.sha256 {
            let _ = fs::remove_file(&part);
            return Err(ParamsError::Mismatch {
                name: f.name,
                got_bytes: n,
                got_sha256: sha,
                bytes: f.bytes,
                sha256: f.sha256,
            });
        }
        fs::rename(&part, dir.join(f.name))
            .map_err(|e| ParamsError::Io(dir.join(f.name).display().to_string(), e))?;
        done += f.bytes;
    }
    mark_verified(dir, true);
    Ok(status(dir))
}

/// The sink of one file: the `.part` file and the running hash, bounded by the pinned length.
struct Sink<'a> {
    file: File,
    hash: Sha256,
    n: u64,
    f: &'a ParamFile,
    base: u64,
    total: u64,
    progress: &'a (dyn Fn(Progress) + Send + Sync),
    path: &'a Path,
}

impl Sink<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<(), ParamsError> {
        if self.n + buf.len() as u64 > self.f.bytes {
            return Err(ParamsError::Transfer(
                self.f.name.into(),
                format!("more than the pinned {} bytes", self.f.bytes),
            ));
        }
        self.file
            .write_all(buf)
            .map_err(|e| ParamsError::Io(self.path.display().to_string(), e))?;
        self.hash.update(buf);
        let before = self.n / (1 << 20);
        self.n += buf.len() as u64;
        if self.n / (1 << 20) != before || self.n == self.f.bytes {
            (self.progress)(Progress {
                file: self.f.name,
                done: self.base + self.n,
                total: self.total,
            });
        }
        Ok(())
    }

    fn finish(self) -> Result<(u64, String), ParamsError> {
        self.file
            .sync_all()
            .map_err(|e| ParamsError::Io(self.path.display().to_string(), e))?;
        Ok((self.n, crate::keys::hex(&self.hash.finalize())))
    }
}

async fn fetch_one(
    source: &ParamsSource,
    f: &ParamFile,
    part: &Path,
    base: u64,
    total: u64,
    progress: &(dyn Fn(Progress) + Send + Sync),
) -> Result<(u64, String), ParamsError> {
    let file = File::create(part).map_err(|e| ParamsError::Io(part.display().to_string(), e))?;
    let mut sink = Sink {
        file,
        hash: Sha256::new(),
        n: 0,
        f,
        base,
        total,
        progress,
        path: part,
    };
    match source {
        ParamsSource::File(dir) => {
            let src = dir.join(f.name);
            let mut r =
                File::open(&src).map_err(|e| ParamsError::Io(src.display().to_string(), e))?;
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let k = std::io::Read::read(&mut r, &mut buf)
                    .map_err(|e| ParamsError::Io(src.display().to_string(), e))?;
                if k == 0 {
                    break;
                }
                sink.write(&buf[..k])?;
            }
        }
        ParamsSource::Http {
            tls,
            host,
            port,
            path,
        } => {
            let mut target = ParamsSource::Http {
                tls: *tls,
                host: host.clone(),
                port: *port,
                path: format!("{path}{}", f.name),
            };
            let mut hops = 0;
            loop {
                match http_get(&target, &mut sink).await? {
                    Fetched::Done => break,
                    Fetched::Redirect(location) => {
                        hops += 1;
                        if hops > MAX_REDIRECTS {
                            return Err(ParamsError::Transfer(
                                f.name.into(),
                                "too many redirects".into(),
                            ));
                        }
                        target = redirect_target(&target, &location)
                            .map_err(|m| ParamsError::Transfer(f.name.into(), m))?;
                    }
                }
            }
        }
    }
    sink.finish()
}

/// Resolve a `Location` against the current target. A redirect may not downgrade TLS.
fn redirect_target(cur: &ParamsSource, location: &str) -> Result<ParamsSource, String> {
    let ParamsSource::Http {
        tls, host, port, ..
    } = cur
    else {
        return Err("redirect from a file source".into());
    };
    if location.starts_with('/') {
        return Ok(ParamsSource::Http {
            tls: *tls,
            host: host.clone(),
            port: *port,
            path: location.to_string(),
        });
    }
    let next = ParamsSource::parse(location).map_err(|e| e.to_string())?;
    match next {
        ParamsSource::Http {
            tls: next_tls,
            host,
            port,
            path,
        } => {
            if *tls && !next_tls {
                return Err(format!("refusing a redirect from https to {location}"));
            }
            // `parse` appended a `/` for a base URL; a redirect names the file itself.
            let path = path.trim_end_matches('/').to_string();
            Ok(ParamsSource::Http {
                tls: next_tls,
                host,
                port,
                path,
            })
        }
        ParamsSource::File(_) => Err(format!("refusing a redirect to {location}")),
    }
}

async fn read_line(r: &mut BufReader<Box<dyn Io>>, line: &mut Vec<u8>) -> std::io::Result<usize> {
    line.clear();
    r.read_until(b'\n', line).await
}

enum Fetched {
    Done,
    Redirect(String),
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

fn tls_config() -> Arc<tokio_rustls::rustls::ClientConfig> {
    static CFG: OnceLock<Arc<tokio_rustls::rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        Arc::new(
            tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

async fn connect(tls: bool, host: &str, port: u16) -> Result<Box<dyn Io>, String> {
    let tcp = TcpStream::connect((host.trim_matches(|c| c == '[' || c == ']'), port))
        .await
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    if !tls {
        return Ok(Box::new(tcp));
    }
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(
        host.trim_matches(|c| c == '[' || c == ']').to_string(),
    )
    .map_err(|e| format!("server name {host}: {e}"))?;
    let stream = tokio_rustls::TlsConnector::from(tls_config())
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS {host}: {e}"))?;
    Ok(Box::new(stream))
}

/// One `GET`; the body goes to `sink`. A 3xx with `Location` is returned for the caller.
async fn http_get(target: &ParamsSource, sink: &mut Sink<'_>) -> Result<Fetched, ParamsError> {
    let ParamsSource::Http {
        tls,
        host,
        port,
        path,
    } = target
    else {
        unreachable!("http_get on a file source");
    };
    let name = sink.f.name;
    let terr = |m: String| ParamsError::Transfer(name.into(), m);
    let mut io = connect(*tls, host, *port).await.map_err(terr)?;
    let default_port = if *tls { 443 } else { 80 };
    let host_header = if *port == default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: yew-core/{}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        crate::VERSION
    );
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| terr(e.to_string()))?;
    io.flush().await.map_err(|e| terr(e.to_string()))?;
    let mut r = BufReader::new(io);

    // Status line and headers.
    let mut header_bytes = 0usize;
    let mut line = Vec::new();
    let n = read_line(&mut r, &mut line)
        .await
        .map_err(|e| terr(e.to_string()))?;
    header_bytes += n;
    let status_line = String::from_utf8_lossy(&line).trim().to_string();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| terr(format!("bad status line {status_line:?}")))?;
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    let mut location = None;
    loop {
        let n = read_line(&mut r, &mut line)
            .await
            .map_err(|e| terr(e.to_string()))?;
        header_bytes += n;
        if header_bytes > MAX_HEADER_BYTES {
            return Err(terr("response headers too large".into()));
        }
        if n == 0 {
            return Err(terr("connection closed in the headers".into()));
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\r', '\n']);
        if text.is_empty() {
            break;
        }
        if let Some((k, v)) = text.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "content-length" => content_length = v.parse().ok(),
                "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                "location" => location = Some(v.to_string()),
                _ => {}
            }
        }
    }
    if (300..400).contains(&code) {
        return location
            .map(Fetched::Redirect)
            .ok_or_else(|| terr(format!("HTTP {code} without Location")));
    }
    if code != 200 {
        return Err(terr(format!("HTTP {code} for {path}")));
    }

    let mut buf = vec![0u8; 1 << 16];
    if chunked {
        loop {
            let n = read_line(&mut r, &mut line)
                .await
                .map_err(|e| terr(e.to_string()))?;
            if n == 0 {
                return Err(terr("connection closed in a chunk header".into()));
            }
            let text = String::from_utf8_lossy(&line);
            let size_hex = text
                .trim()
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let mut left = u64::from_str_radix(&size_hex, 16)
                .map_err(|_| terr(format!("bad chunk size {size_hex:?}")))?;
            if left == 0 {
                break;
            }
            while left > 0 {
                let want = (left as usize).min(buf.len());
                r.read_exact(&mut buf[..want])
                    .await
                    .map_err(|e| terr(e.to_string()))?;
                sink.write(&buf[..want])?;
                left -= want as u64;
            }
            // The CRLF after the chunk data.
            read_line(&mut r, &mut line)
                .await
                .map_err(|e| terr(e.to_string()))?;
        }
    } else if let Some(len) = content_length {
        if len != sink.f.bytes {
            return Err(terr(format!(
                "Content-Length {len}, the pinned file is {} bytes",
                sink.f.bytes
            )));
        }
        let mut left = len;
        while left > 0 {
            let want = (left as usize).min(buf.len());
            let k = r
                .read(&mut buf[..want])
                .await
                .map_err(|e| terr(e.to_string()))?;
            if k == 0 {
                return Err(terr(format!("connection closed {left} bytes early")));
            }
            sink.write(&buf[..k])?;
            left -= k as u64;
        }
    } else {
        loop {
            let k = r.read(&mut buf).await.map_err(|e| terr(e.to_string()))?;
            if k == 0 {
                break;
            }
            sink.write(&buf[..k])?;
        }
    }
    Ok(Fetched::Done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("yew-params-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sources_parse_and_refuse() {
        assert_eq!(
            ParamsSource::parse("https://params.example.org/sapling").unwrap(),
            ParamsSource::Http {
                tls: true,
                host: "params.example.org".into(),
                port: 443,
                path: "/sapling/".into()
            }
        );
        assert_eq!(
            ParamsSource::parse("http://127.0.0.1:8123/").unwrap(),
            ParamsSource::Http {
                tls: false,
                host: "127.0.0.1".into(),
                port: 8123,
                path: "/".into()
            }
        );
        assert!(ParamsSource::parse("http://params.example.org/").is_err());
        assert!(ParamsSource::parse("ftp://x/").is_err());
        assert!(ParamsSource::parse("https://user@host/").is_err());
        assert_eq!(
            ParamsSource::parse("file:///tmp/p").unwrap(),
            ParamsSource::File(PathBuf::from("/tmp/p"))
        );
        // Redirects: relative paths stay on the host, https never downgrades.
        let cur = ParamsSource::parse("https://a.example/x/").unwrap();
        assert_eq!(
            redirect_target(&cur, "/y/sapling-spend.params").unwrap(),
            ParamsSource::Http {
                tls: true,
                host: "a.example".into(),
                port: 443,
                path: "/y/sapling-spend.params".into()
            }
        );
        assert!(redirect_target(&cur, "http://127.0.0.1/z").is_err());
        assert!(redirect_target(&cur, "file:///etc/passwd").is_err());
    }

    #[test]
    fn wrong_bytes_are_refused_and_nothing_is_kept() {
        let src = tmp("src-bad");
        fs::write(src.join(SPEND.name), b"not the parameters").unwrap();
        fs::write(src.join(OUTPUT.name), b"nor these").unwrap();
        let dst = tmp("dst-bad");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let e = rt
            .block_on(download(&ParamsSource::File(src.clone()), &dst, |_| {}))
            .unwrap_err();
        assert!(
            matches!(e, ParamsError::Mismatch { name, .. } if name == SPEND.name),
            "{e}"
        );
        assert!(!dst.join(SPEND.name).exists());
        assert!(!dst.join(format!("{}.part", SPEND.name)).exists());
        assert!(!status(&dst).present());
        assert_eq!(status(&dst).missing_bytes, TOTAL_BYTES);
        assert!(matches!(
            ensure_verified(&dst),
            Err(ParamsError::Missing(_))
        ));
    }

    #[test]
    fn oversized_bodies_stop_at_the_pin() {
        // A source longer than the pinned length is cut off at the pin, not written in full.
        let src = tmp("src-big");
        let f = File::create(src.join(SPEND.name)).unwrap();
        f.set_len(SPEND.bytes + 10).unwrap();
        let dst = tmp("dst-big");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let e = rt
            .block_on(download(&ParamsSource::File(src), &dst, |_| {}))
            .unwrap_err();
        assert!(e.to_string().contains("more than the pinned"), "{e}");
    }

    /// The real files, when this machine has them (a ycashd 4.5.0 install): a `file://` copy and
    /// a loopback HTTP server (chunked and Content-Length) both verify and land.
    #[test]
    fn real_parameters_verify_over_file_and_http_when_available() {
        let Some(have) = local_params_dir() else {
            eprintln!("no local Sapling parameters; skipped");
            return;
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let dst = tmp("dst-file");
        let seen = AtomicU64::new(0);
        let s = rt
            .block_on(download(&ParamsSource::File(have.clone()), &dst, |p| {
                seen.store(p.done, Ordering::SeqCst);
                assert_eq!(p.total, TOTAL_BYTES);
            }))
            .unwrap();
        assert!(s.present() && s.verified, "{s:?}");
        assert_eq!(seen.load(Ordering::SeqCst), TOTAL_BYTES);
        ensure_verified(&dst).unwrap();
        // Already there: nothing to fetch, still verified.
        let again = rt
            .block_on(download(
                &ParamsSource::File(PathBuf::from("/nonexistent")),
                &dst,
                |_| {},
            ))
            .unwrap();
        assert!(again.verified);

        for chunked in [false, true] {
            let dst = tmp(if chunked { "dst-chunked" } else { "dst-length" });
            let port = rt.block_on(serve_dir(have.clone(), chunked));
            let src = ParamsSource::parse(&format!("http://127.0.0.1:{port}/p/")).unwrap();
            let s = rt.block_on(download(&src, &dst, |_| {})).unwrap();
            assert!(s.present() && s.verified, "chunked={chunked}: {s:?}");
        }
        // A file changed on disk after verification is refused at the next process's check.
        mark_verified(&dst, false);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(dst.join(OUTPUT.name))
            .unwrap();
        f.write_all(b"x").unwrap();
        drop(f);
        assert!(matches!(
            ensure_verified(&dst),
            Err(ParamsError::Mismatch { .. })
        ));
    }

    pub(crate) fn local_params_dir() -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        [
            std::env::var("YEW_SAPLING_PARAMS").unwrap_or_default(),
            format!("{home}/Library/Application Support/ZcashParams"),
            format!("{home}/.zcash-params"),
        ]
        .into_iter()
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .find(|d| present(d, &SPEND) && present(d, &OUTPUT))
    }

    /// A one-request-per-connection HTTP server over `dir` (`/p/<name>`), with a redirect from
    /// `/p/<name>` to `/q/<name>` first so the redirect path is exercised.
    async fn serve_dir(dir: PathBuf, chunked: bool) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let dir = dir.clone();
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut b = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        let n = s.read(&mut b).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        req.extend_from_slice(&b[..n]);
                    }
                    let text = String::from_utf8_lossy(&req);
                    let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                    if let Some(name) = path.strip_prefix("/p/") {
                        let resp = format!("HTTP/1.1 302 Found\r\nLocation: /q/{name}\r\nContent-Length: 0\r\n\r\n");
                        let _ = s.write_all(resp.as_bytes()).await;
                        return;
                    }
                    let name = path.trim_start_matches("/q/");
                    let Ok(body) = fs::read(dir.join(name)) else {
                        let _ = s
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                            .await;
                        return;
                    };
                    if chunked {
                        let _ = s
                            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                            .await;
                        for c in body.chunks(100_000) {
                            let _ = s.write_all(format!("{:x}\r\n", c.len()).as_bytes()).await;
                            let _ = s.write_all(c).await;
                            let _ = s.write_all(b"\r\n").await;
                        }
                        let _ = s.write_all(b"0\r\n\r\n").await;
                    } else {
                        let _ = s
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                                    body.len()
                                )
                                .as_bytes(),
                            )
                            .await;
                        let _ = s.write_all(&body).await;
                    }
                });
            }
        });
        port
    }
}
