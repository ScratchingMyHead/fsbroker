//! Configuration: a deny-by-default map from virtual paths to host paths.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::io::OwnedFd;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    /// Default mount point for the daemon. Can be overridden on the command line.
    #[serde(default)]
    pub mount_point: Option<PathBuf>,
    /// Pass `-o allow_other` (requires `user_allow_other` in /etc/fuse.conf).
    #[serde(default)]
    pub allow_other: bool,
    /// Refuse every mutating operation, regardless of per-mount flags.
    #[serde(default)]
    pub read_only: bool,
    #[serde(default, rename = "mount")]
    pub mounts: Vec<MountSpec>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountSpec {
    /// Absolute path as seen inside the virtual root. When omitted it is the
    /// host path itself, so the agent sees the real folder at its real path.
    #[serde(default)]
    pub virtual_path: Option<String>,
    /// Host directory that backs it.
    pub host: PathBuf,
    /// Whether the agent may modify this subtree.
    #[serde(default)]
    pub writable: bool,
}

/// A validated, opened mount.
pub struct Mount {
    pub vpath: PathBuf,
    pub host: PathBuf,
    pub writable: bool,
    pub dirfd: OwnedFd,
    /// Added at runtime by an approved request (session-only), as opposed to
    /// loaded from the config (permanent).
    pub runtime: bool,
}

impl Mount {
    /// Validate and open a directory as a mount. Used for runtime additions;
    /// the config loader does the same checks inline with better messages.
    pub fn open(vpath: PathBuf, host: &Path, writable: bool) -> Result<Mount> {
        let host = fs::canonicalize(host)
            .with_context(|| format!("resolving host path {}", host.display()))?;
        let meta = fs::metadata(&host)
            .with_context(|| format!("stat host path {}", host.display()))?;
        if !meta.is_dir() {
            bail!("only directories can be added: {}", host.display());
        }
        let dirfd = crate::sys::openat2(
            libc::AT_FDCWD,
            &host,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
            0,
        )
        .with_context(|| format!("opening host path {}", host.display()))?;
        Ok(Mount {
            vpath,
            host,
            writable,
            dirfd,
            runtime: true,
        })
    }
}

pub struct Config {
    pub mount_point: Option<PathBuf>,
    pub allow_other: bool,
    pub read_only: bool,
    pub mounts: Vec<Mount>,
    /// Every directory that exists only in the virtual tree: `/` plus every
    /// strict ancestor of a mount point.
    pub synthetic: BTreeSet<PathBuf>,
}

/// What a virtual path refers to: a real whitelisted host subtree (by index
/// into [`MountTable::mounts`]) or a directory that exists only in the virtual
/// tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Synthetic,
    Host(usize),
}

/// The live mapping set. The daemon holds it behind a lock because the broker
/// can add entries at runtime (an approved `fsbroker-request`).
pub struct MountTable {
    pub mounts: Vec<Mount>,
    pub synthetic: BTreeSet<PathBuf>,
}

impl MountTable {
    pub fn new(mounts: Vec<Mount>, synthetic: BTreeSet<PathBuf>) -> MountTable {
        MountTable { mounts, synthetic }
    }

    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// The most specific mount whose virtual path is a prefix of `v`.
    pub fn find_mount(&self, v: &Path) -> Option<usize> {
        self.mounts
            .iter()
            .position(|m| v == m.vpath || v.starts_with(&m.vpath))
    }

    pub fn classify(&self, v: &Path) -> Option<NodeKind> {
        if let Some(mi) = self.find_mount(v) {
            return Some(NodeKind::Host(mi));
        }
        if self.synthetic.contains(v) {
            return Some(NodeKind::Synthetic);
        }
        None
    }

    pub fn rel_for(&self, v: &Path, mi: usize) -> PathBuf {
        v.strip_prefix(&self.mounts[mi].vpath)
            .unwrap_or(Path::new(""))
            .to_path_buf()
    }

    pub fn writable(&self, mi: usize) -> bool {
        self.mounts[mi].writable
    }

    /// Add one mapping at runtime. Refuses a duplicate or a nesting that would
    /// make "which mount owns this path" ambiguous — the same rule the config
    /// loader applies.
    pub fn add(&mut self, mount: Mount) -> Result<()> {
        if self.mounts.iter().any(|m| m.vpath == mount.vpath) {
            bail!("already mapped: {}", mount.vpath.display());
        }
        for m in &self.mounts {
            if mount.vpath.starts_with(&m.vpath) || m.vpath.starts_with(&mount.vpath) {
                bail!(
                    "would nest with the existing mapping {}: {}",
                    m.vpath.display(),
                    mount.vpath.display()
                );
            }
        }
        if mount.vpath == Path::new("/") {
            bail!("refusing to map /");
        }
        // Append, never reorder: `NodeKind::Host(mi)` indices are baked into
        // inodes that already exist, so the vector order must be stable for the
        // daemon's lifetime. Nested mounts are impossible, so at most one mount
        // can match any path and the order does not affect lookup.
        self.mounts.push(mount);
        self.rebuild_synthetic();
        Ok(())
    }

    fn rebuild_synthetic(&mut self) {
        self.synthetic.clear();
        self.synthetic.insert(PathBuf::from("/"));
        for m in &self.mounts {
            let mut cur = m.vpath.parent();
            while let Some(p) = cur {
                self.synthetic.insert(p.to_path_buf());
                if p == Path::new("/") {
                    break;
                }
                cur = p.parent();
            }
        }
    }
}

fn normalize_virtual(raw: &str) -> Result<PathBuf> {
    if !raw.starts_with('/') {
        bail!("virtual_path must be absolute: {raw}");
    }
    let p = Path::new(raw);
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => out.push(n),
            Component::CurDir | Component::ParentDir => {
                bail!("virtual_path must not contain . or ..: {raw}")
            }
            Component::Prefix(_) => bail!("unsupported virtual_path: {raw}"),
        }
    }
    Ok(out)
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let raw: RootConfig = toml::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;

        if raw.mounts.is_empty() {
            bail!("config has no [[mount]] entries: an empty virtual root is useless");
        }

        let mut mounts: Vec<Mount> = Vec::new();
        for spec in raw.mounts {
            // Default: the host path itself, so inside and outside agree.
            let vpath = match &spec.virtual_path {
                Some(v) => normalize_virtual(v)?,
                None => {
                    let h = spec.host.to_str().with_context(|| {
                        format!("host path is not valid UTF-8: {}", spec.host.display())
                    })?;
                    normalize_virtual(h)?
                }
            };
            if vpath == Path::new("/") {
                bail!("refusing to map / to a host directory; map explicit subtrees instead");
            }
            if mounts.iter().any(|m| m.vpath == vpath) {
                bail!("duplicate virtual_path {}", vpath.display());
            }
            // Nested mounts would make "which mount owns this path" ambiguous.
            for m in &mounts {
                if vpath.starts_with(&m.vpath) || m.vpath.starts_with(&vpath) {
                    bail!(
                        "nested mounts are not supported: {} and {}\n\
                         hint: map either the parent or the child, not both",
                        vpath.display(),
                        m.vpath.display()
                    );
                }
            }

            let host = fs::canonicalize(&spec.host).with_context(|| {
                format!("resolving host path {} for {}", spec.host.display(), vpath.display())
            })?;
            let meta = fs::metadata(&host)
                .with_context(|| format!("stat host path {}", host.display()))?;
            if !meta.is_dir() {
                bail!("host path is not a directory: {}", host.display());
            }

            let dirfd = sys::openat2(
                libc::AT_FDCWD,
                &host,
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
                0,
            )
            .with_context(|| format!("opening host path {}", host.display()))?;

            mounts.push(Mount {
                vpath,
                host,
                writable: spec.writable && !raw.read_only,
                dirfd,
                runtime: false,
            });
        }

        // Longest virtual path first so prefix matching is unambiguous even if
        // nesting is added later.
        mounts.sort_by(|a, b| b.vpath.as_os_str().len().cmp(&a.vpath.as_os_str().len()));

        let mut synthetic = BTreeSet::new();
        synthetic.insert(PathBuf::from("/"));
        for m in &mounts {
            let mut cur = m.vpath.parent();
            while let Some(p) = cur {
                synthetic.insert(p.to_path_buf());
                if p == Path::new("/") {
                    break;
                }
                cur = p.parent();
            }
        }

        Ok(Config {
            mount_point: raw.mount_point,
            allow_other: raw.allow_other,
            read_only: raw.read_only,
            mounts,
            synthetic,
        })
    }
}

// `sys` is a sibling module of the crate root.
use crate::sys;
