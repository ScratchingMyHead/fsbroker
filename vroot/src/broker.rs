//! Client for the prompt broker.
//!
//! When a mutation on a read-only path has no covering grant, the daemon asks
//! the broker, which runs on the host outside the sandbox, shows the user a
//! dialog and answers with a scope. The connection is deliberately one-shot
//! and short: a request line, one response line, close.
//!
//! Protocol (newline-terminated, text):
//!
//! ```text
//! -> ASK <op> <pid> <uid> <path> [<path>...]
//! <- ALLOW <scope> <path> [<path>...]
//! <- DENY
//! ```
//!
//! `<scope>` is `once`, `session`, `always`, or `timed:<seconds>`. `always`
//! means the broker has persisted the grant and the daemon can hold it for the
//! rest of its run; the broker is still the authority on future daemons.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::policy::Scope;

/// How long the daemon is willing to wait for the user to answer.
const ASK_TIMEOUT: Duration = Duration::from_secs(300);

pub enum Decision {
    Allow { scope: Scope, paths: Vec<PathBuf> },
    Deny,
    /// The broker is not running, did not answer in time, or spoke nonsense.
    /// The daemon treats this as a denial.
    Unavailable,
}

pub fn ask(sock: &Path, op: &str, paths: &[&Path], pid: u32, uid: u32) -> Decision {
    let mut stream = match UnixStream::connect(sock) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("broker unavailable at {}: {e}", sock.display());
            return Decision::Unavailable;
        }
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_read_timeout(Some(ASK_TIMEOUT));

    let mut line = format!("ASK {op} {pid} {uid}");
    for p in paths {
        line.push(' ');
        line.push_str(&p.display().to_string());
    }
    line.push('\n');
    if let Err(e) = stream.write_all(line.as_bytes()) {
        log::warn!("broker write failed: {e}");
        return Decision::Unavailable;
    }

    let mut response = String::new();
    match BufReader::new(&stream).read_line(&mut response) {
        Ok(0) => Decision::Unavailable,
        Ok(_) => parse(response.trim()),
        Err(e) => {
            log::warn!("broker read failed: {e}");
            Decision::Unavailable
        }
    }
}

/// A reply to an `fsbroker-request`: add the path, or not.
pub enum RequestDecision {
    Allow { writable: bool },
    Deny,
    Unavailable,
}

/// Ask the broker to add a path to the virtual root. This is the only way a
/// process inside the sandbox can widen its own view, and it only ever asks:
/// the broker decides and the daemon performs the addition.
pub fn request(sock: &Path, path: &Path, writable: bool, pid: u32, uid: u32) -> RequestDecision {
    let mut stream = match UnixStream::connect(sock) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("broker unavailable at {}: {e}", sock.display());
            return RequestDecision::Unavailable;
        }
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_read_timeout(Some(ASK_TIMEOUT));

    let line = format!(
        "REQUEST {pid} {uid} {} {}\n",
        if writable { "rw" } else { "ro" },
        path.display()
    );
    if let Err(e) = stream.write_all(line.as_bytes()) {
        log::warn!("broker write failed: {e}");
        return RequestDecision::Unavailable;
    }

    let mut response = String::new();
    match BufReader::new(&stream).read_line(&mut response) {
        Ok(0) => RequestDecision::Unavailable,
        Ok(_) => match response.trim() {
            "ALLOW read-only" => RequestDecision::Allow { writable: false },
            "ALLOW read-write" => RequestDecision::Allow { writable: true },
            "DENY" => RequestDecision::Deny,
            other => {
                log::warn!("broker sent an unparseable request reply: {other}");
                RequestDecision::Unavailable
            }
        },
        Err(e) => {
            log::warn!("broker read failed: {e}");
            RequestDecision::Unavailable
        }
    }
}

fn parse(line: &str) -> Decision {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("DENY") => Decision::Deny,
        Some("ALLOW") => {
            // "always" is a broker-only scope; from the daemon's point of view
            // it is a session grant, because the broker persists it and will
            // answer without prompting for future runs.
            let token = parts.next().unwrap_or("");
            let scope = if token == "always" {
                Some(Scope::Session)
            } else {
                Scope::parse(token)
            };
            let Some(scope) = scope else {
                log::warn!("broker sent an unknown scope: {line}");
                return Decision::Unavailable;
            };
            let paths: Vec<PathBuf> = parts.map(PathBuf::from).collect();
            if paths.is_empty() {
                log::warn!("broker allowed nothing: {line}");
                return Decision::Unavailable;
            }
            Decision::Allow { scope, paths }
        }
        _ => {
            log::warn!("broker sent an unparseable reply: {line}");
            Decision::Unavailable
        }
    }
}
