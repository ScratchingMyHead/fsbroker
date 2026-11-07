//! Host-only control socket for runtime grants.
//!
//! The daemon serves a line protocol on a `0600` Unix socket next to the mount
//! point. It is deliberately *not* bind-mounted into the sandbox: a process
//! inside must never be able to grant itself anything. The request channel for
//! the sandbox (Phase 3) will be a separate, ask-only socket.
//!
//! Protocol: one command per connection, response until EOF.
//!
//!   PING
//!   LIST                       active write grants
//!   MOUNTS                     the live mount table (config + runtime)
//!   GRANT <once|session> <absolute path>
//!   REVOKE <absolute path>
//!   CLEAR

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};

use crate::config::MountTable;
use crate::policy::{Policy, Scope};

/// Longest command line accepted; paths are short and this bounds the read.
const MAX_LINE: u64 = 8192;

pub fn serve(
    sock: PathBuf,
    policy: Arc<Mutex<Policy>>,
    table: Arc<RwLock<MountTable>>,
) -> Result<()> {
    if sock.exists() {
        let _ = std::fs::remove_file(&sock);
    }
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(&sock)
        .with_context(|| format!("binding control socket {}", sock.display()))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    log::info!("control socket: {}", sock.display());

    std::thread::Builder::new()
        .name("vrootctl".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        if let Err(e) = handle(stream, &policy, &table) {
                            log::warn!("control: {e}");
                        }
                    }
                    Err(e) => log::warn!("control accept: {e}"),
                }
            }
        })?;
    Ok(())
}

fn handle(
    mut stream: UnixStream,
    policy: &Arc<Mutex<Policy>>,
    table: &Arc<RwLock<MountTable>>,
) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut line = String::new();
    {
        let mut reader = BufReader::new((&stream).take(MAX_LINE));
        reader.read_line(&mut line)?;
    }
    let response = dispatch(line.trim(), policy, table);
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn dispatch(line: &str, policy: &Arc<Mutex<Policy>>, table: &Arc<RwLock<MountTable>>) -> String {
    let (cmd, rest) = match line.split_once(' ') {
        Some((c, r)) => (c, r.trim()),
        None => (line, ""),
    };
    match cmd.to_ascii_uppercase().as_str() {
        "PING" => "OK pong\n".to_string(),
        "LIST" => {
            let mut p = policy.lock().unwrap();
            let grants = p.list();
            let mut out = format!("OK {}\n", grants.len());
            for (scope, path) in grants {
                out.push_str(&format!("grant {scope} {}\n", path.display()));
            }
            out
        }
        "MOUNTS" => {
            let t = table.read().unwrap();
            let mut out = format!("OK {}\n", t.mounts.len());
            for m in &t.mounts {
                out.push_str(&format!(
                    "mount {} {} {} {}\n",
                    if m.writable { "rw" } else { "ro" },
                    if m.runtime { "runtime" } else { "config" },
                    m.vpath.display(),
                    m.host.display()
                ));
            }
            out
        }
        "GRANT" => {
            let parsed = rest
                .split_once(' ')
                .and_then(|(scope, path)| Some((Scope::parse(scope)?, path.trim())));
            match parsed {
                Some((scope, raw)) => match normalize(raw) {
                    Some(path) => {
                        policy.lock().unwrap().grant(path.clone(), scope);
                        log::info!("grant {} {}", scope.as_str(), path.display());
                        format!("OK granted {} {}\n", scope.as_str(), path.display())
                    }
                    None => "ERR path must be absolute and clean\n".to_string(),
                },
                None => "ERR usage: GRANT <once|session> <absolute path>\n".to_string(),
            }
        }
        "REVOKE" => match normalize(rest) {
            Some(path) => {
                let n = policy.lock().unwrap().revoke(&path);
                log::info!("revoke {} ({n})", path.display());
                format!("OK revoked {n} {}\n", path.display())
            }
            None => "ERR usage: REVOKE <absolute path>\n".to_string(),
        },
        "CLEAR" => {
            let n = policy.lock().unwrap().clear();
            log::info!("cleared {n} grants");
            format!("OK cleared {n}\n")
        }
        "" => "ERR empty command\n".to_string(),
        other => format!("ERR unknown command: {other}\n"),
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
    Some(out)
}
