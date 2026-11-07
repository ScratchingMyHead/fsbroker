//! Sandbox-facing request socket.
//!
//! `fsbroker-request` lets the agent *ask* for a path to be added to the
//! virtual root. The request goes to the broker, which shows the user a
//! dialog; only an approval adds the mapping, and it lasts until the daemon
//! stops.
//!
//! Unlike the control socket, this one is deliberately reachable from inside
//! the sandbox (the launcher binds it in). It can only ask — it can never widen
//! access on its own, and it does not reveal whether a host path exists until
//! the user has already seen and approved the request.
//!
//! Protocol: one request per connection, response until close.
//!
//!   REQUEST <path> <ro|rw>
//!   -> OK added <path> <ro|rw>
//!   -> OK already-visible
//!   -> DENY
//!   -> ERR <message>
//!   PING

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};

use crate::broker::{self, RequestDecision};
use crate::config::{Mount, MountTable};

const MAX_LINE: u64 = 8192;

pub fn serve(sock: PathBuf, table: Arc<RwLock<MountTable>>, broker: Option<PathBuf>) -> Result<()> {
    if sock.exists() {
        let _ = std::fs::remove_file(&sock);
    }
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(&sock)
        .with_context(|| format!("binding request socket {}", sock.display()))?;
    // Same uid as the sandbox user; the socket is only useful once the launcher
    // has bound it inside.
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    log::info!("request socket: {}", sock.display());

    std::thread::Builder::new()
        .name("vroot-req".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        if let Err(e) = handle(stream, &table, &broker) {
                            log::warn!("request: {e}");
                        }
                    }
                    Err(e) => log::warn!("request accept: {e}"),
                }
            }
        })?;
    Ok(())
}

fn handle(
    mut stream: UnixStream,
    table: &Arc<RwLock<MountTable>>,
    broker: &Option<PathBuf>,
) -> std::io::Result<()> {
    // A client that connects and never sends a newline must not pin this
    // thread forever.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let (pid, uid) = peer_cred(&stream).unwrap_or((0, 0));

    let mut line = String::new();
    {
        let mut reader = BufReader::new((&stream).take(MAX_LINE));
        reader.read_line(&mut line)?;
    }
    let response = dispatch(line.trim(), table, broker, pid, uid);
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn dispatch(
    line: &str,
    table: &Arc<RwLock<MountTable>>,
    broker: &Option<PathBuf>,
    pid: u32,
    uid: u32,
) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.first().map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("PING") => "OK pong\n".to_string(),
        Some("REQUEST") => {
            let Some(raw) = parts.get(1).copied() else {
                return "ERR usage: REQUEST <path> <ro|rw>\n".to_string();
            };
            let writable = match *parts.get(2).unwrap_or(&"ro") {
                "rw" => true,
                "ro" => false,
                _ => return "ERR mode must be ro or rw\n".to_string(),
            };
            let Some(vpath) = normalize(raw) else {
                return "ERR path must be absolute and clean\n".to_string();
            };

            // Decide whether there is anything to ask.
            {
                let t = table.read().unwrap();
                match t.classify(&vpath) {
                    // Already backed by a real mount: nothing to do.
                    Some(crate::config::NodeKind::Host(_)) => {
                        return "OK already-visible\n".to_string();
                    }
                    // A synthetic directory only exists because a mount lives
                    // *under* it; the real folder is not mapped. Adding it here
                    // would nest with that mount, which is not supported, so say
                    // so plainly instead of pretending it is already visible.
                    Some(crate::config::NodeKind::Synthetic) => {
                        let child = t
                            .mounts
                            .iter()
                            .find(|m| m.vpath != vpath && m.vpath.starts_with(&vpath));
                        let detail = match child {
                            Some(m) => format!(" (it contains the mapping {})", m.vpath.display()),
                            None => String::new(),
                        };
                        return format!(
                            "ERR {} exists only as a partial directory{}; it cannot be added over an existing mapping\n",
                            vpath.display(),
                            detail
                        );
                    }
                    None => {}
                }
            }

            let Some(sock) = broker else {
                return "ERR no broker configured\n".to_string();
            };
            match broker::request(sock, &vpath, writable, pid, uid) {
                RequestDecision::Allow { writable } => {
                    let mount = match Mount::open(vpath.clone(), &vpath, writable) {
                        Ok(m) => m,
                        Err(e) => return format!("ERR {e}\n"),
                    };
                    let added = table.write().unwrap().add(mount);
                    match added {
                        Ok(()) => {
                            log::info!(
                                "request: added {} ({}) by pid {}",
                                vpath.display(),
                                if writable { "rw" } else { "ro" },
                                pid
                            );
                            format!(
                                "OK added {} {}\n",
                                vpath.display(),
                                if writable { "rw" } else { "ro" }
                            )
                        }
                        Err(e) => format!("ERR {e}\n"),
                    }
                }
                RequestDecision::Deny => "DENY\n".to_string(),
                RequestDecision::Unavailable => "ERR broker unavailable\n".to_string(),
            }
        }
        None => "ERR empty request\n".to_string(),
        Some(other) => format!("ERR unknown command: {other}\n"),
    }
}

/// Peer pid/uid via `SO_PEERCRED` (std's `peer_cred` is still unstable). The
/// kernel translates the pid into the daemon's namespace, so it is the host pid.
fn peer_cred(stream: &UnixStream) -> Option<(u32, u32)> {
    use std::os::unix::io::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r == 0 {
        Some((cred.pid as u32, cred.uid))
    } else {
        None
    }
}

fn normalize(raw: &str) -> Option<PathBuf> {
    if !raw.starts_with('/') {
        return None;
    }
    let mut out = PathBuf::from("/");
    for c in Path::new(raw).components() {
        match c {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(n) => out.push(n),
            _ => return None,
        }
    }
    if out == Path::new("/") {
        return None;
    }
    Some(out)
}
