// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or https://www.opensource.org/licenses/mit-license.php .

//! The signer's Unix-socket server (K-24 (a)): one JSON [`yewd_proto::Envelope`] per line in, one
//! [`yewd_proto::Response`] per line out. The socket is created mode 0600 in the signer's mode-0700
//! directory, and every connection's peer is checked to run as this process's user (the peer-UID
//! check); requests are answered one at a time.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use yewd_proto::{refuse, Envelope, Response};

use crate::sign::SignerCore;

/// The largest request line (a transaction with many PQ inputs is ~100 kB of hex; a block of
/// them is refused).
pub const MAX_LINE: usize = 8 << 20;

/// The UID of the process at the other end of `s`.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn peer_uid(s: &UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: getpeereid writes two integers through valid pointers to locals.
    let r = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

/// The UID of the process at the other end of `s`.
#[cfg(target_os = "linux")]
pub fn peer_uid(s: &UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into the local `cred`.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// This process's effective UID.
pub fn my_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// Bind the socket at `path` (a stale socket is replaced; any other file is an error), mode 0600.
pub fn bind(path: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::FileTypeExt;
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if m.file_type().is_socket() {
            let _ = std::fs::remove_file(path);
        } else {
            return Err(format!("{} exists and is not a socket", path.display()));
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        // a short socket directory outside the signer's own (yewd_proto::client::socket_path) is
        // this user's alone
        if dir.starts_with("/tmp") {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let m = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            if m.uid() != my_uid() {
                return Err(format!("{} belongs to another user", dir.display()));
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
    }
    // bound under a temporary name, made 0600, then renamed into place: the socket never appears
    // at `path` with the default mode (a client, or a test, could otherwise meet it before the
    // chmod)
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let l = UnixListener::bind(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(l)
}

/// Answer one connection until it closes.
pub fn serve_connection(core: &Mutex<SignerCore>, s: UnixStream) {
    match peer_uid(&s) {
        Ok(uid) if uid == my_uid() => {}
        Ok(_) => {
            eprintln!("yewd-signer: refused a connection from another user");
            return;
        }
        Err(e) => {
            eprintln!("yewd-signer: cannot check the peer: {e}");
            return;
        }
    }
    let mut w = match s.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut r = BufReader::new(s);
    let mut line = String::new();
    loop {
        line.clear();
        match std::io::Read::take(&mut r, MAX_LINE as u64 + 1).read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let resp = if line.len() > MAX_LINE {
            Response::refused(refuse::MALFORMED, "request too long")
        } else {
            match serde_json::from_str::<Envelope>(line.trim_end()) {
                Ok(env) => {
                    let c = core.lock().unwrap_or_else(|e| e.into_inner());
                    c.handle(&env)
                }
                Err(e) => {
                    // a request of another version may not parse as this one's: say so
                    let v: Option<u64> = serde_json::from_str::<serde_json::Value>(line.trim_end())
                        .ok()
                        .and_then(|v| v.get("version").and_then(|n| n.as_u64()));
                    match v {
                        Some(v) if v != yewd_proto::PROTO_VERSION as u64 => Response::refused(
                            refuse::BAD_VERSION,
                            format!(
                                "yewd-signer speaks protocol {}, the request is version {v}",
                                yewd_proto::PROTO_VERSION
                            ),
                        ),
                        _ => Response::refused(refuse::MALFORMED, format!("bad request: {e}")),
                    }
                }
            }
        };
        let mut out = serde_json::to_string(&resp).expect("serializable");
        out.push('\n');
        if w.write_all(out.as_bytes()).is_err() {
            return;
        }
    }
}

/// Serve `core` on `path` until the process exits. With `watch_stdin`, the server exits (and
/// removes the socket) when its standard input closes: the façade that started it is gone.
pub fn serve(core: SignerCore, path: PathBuf, watch_stdin: bool) -> Result<(), String> {
    let l = bind(&path)?;
    let core = Arc::new(Mutex::new(core));
    if watch_stdin {
        let p = path.clone();
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut sink);
            let _ = std::fs::remove_file(&p);
            std::process::exit(0);
        });
    }
    println!(
        "{}",
        serde_json::json!({"listening": path.display().to_string()})
    );
    let _ = std::io::stdout().flush();
    for s in l.incoming() {
        match s {
            Ok(s) => {
                let c = core.clone();
                std::thread::spawn(move || serve_connection(&c, s));
            }
            Err(e) => eprintln!("yewd-signer: accept: {e}"),
        }
    }
    Ok(())
}
