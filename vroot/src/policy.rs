//! Runtime write grants layered on top of the static mount map.
//!
//! The mount table decides what is *visible* and its default access. A grant
//! widens that default for one path prefix:
//!
//! * `once` — the next matching operation,
//! * `session` — until the daemon stops,
//! * `timed` — for a fixed duration (the prompt broker's "allow for 10 min"…).
//!
//! Grants are added through the host-only control socket, or by the daemon
//! itself after it asks the prompt broker. Denials are not remembered here: a
//! denial that should persist is a rule the broker holds, and it answers the
//! next ask without prompting.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Once,
    Session,
    Timed(Duration),
}

impl Scope {
    /// Parse the wire form used by the control socket and the broker:
    /// `once`, `session`, or `timed:<seconds>`.
    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "once" => Some(Scope::Once),
            "session" => Some(Scope::Session),
            _ => s
                .strip_prefix("timed:")
                .and_then(|n| n.parse::<u64>().ok())
                .map(|secs| Scope::Timed(Duration::from_secs(secs))),
        }
    }

    pub fn as_str(self) -> String {
        match self {
            Scope::Once => "once".to_string(),
            Scope::Session => "session".to_string(),
            Scope::Timed(d) => format!("timed:{}", d.as_secs()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Grant {
    pub path: PathBuf,
    pub scope: Scope,
    /// Monotonic deadline; `None` for scopes that do not expire.
    pub expires: Option<Instant>,
}

impl Grant {
    pub fn remaining(&self) -> Option<Duration> {
        self.expires.map(|e| e.saturating_duration_since(Instant::now()))
    }
}

#[derive(Default)]
pub struct Policy {
    grants: Vec<Grant>,
}

impl Policy {
    pub fn grant(&mut self, path: PathBuf, scope: Scope) {
        self.grants.retain(|g| g.path != path);
        let expires = match scope {
            Scope::Timed(d) => Some(Instant::now() + d),
            _ => None,
        };
        self.grants.push(Grant {
            path,
            scope,
            expires,
        });
    }

    pub fn revoke(&mut self, path: &Path) -> usize {
        let before = self.grants.len();
        self.grants.retain(|g| g.path != path);
        before - self.grants.len()
    }

    pub fn clear(&mut self) -> usize {
        let n = self.grants.len();
        self.grants.clear();
        n
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.grants
            .retain(|g| g.expires.map_or(true, |e| e > now));
    }

    /// Does a grant cover `v`? Does not consume a `once` grant.
    pub fn peek(&mut self, v: &Path) -> bool {
        self.prune();
        self.grants.iter().any(|g| v.starts_with(&g.path))
    }

    /// Does a grant cover `v`? A matching `once` grant is consumed.
    pub fn consume(&mut self, v: &Path) -> bool {
        self.prune();
        match self.grants.iter().position(|g| v.starts_with(&g.path)) {
            Some(i) => {
                if self.grants[i].scope == Scope::Once {
                    self.grants.remove(i);
                }
                true
            }
            None => false,
        }
    }

    /// Snapshot for the control socket's `LIST`, with the remaining time for
    /// timed grants.
    pub fn list(&mut self) -> Vec<(String, PathBuf)> {
        self.prune();
        self.grants
            .iter()
            .map(|g| {
                let scope = match g.remaining() {
                    Some(d) => format!("timed:{}", d.as_secs()),
                    None => g.scope.as_str(),
                };
                (scope, g.path.clone())
            })
            .collect()
    }
}
