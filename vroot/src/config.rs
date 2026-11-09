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
    /// Bind pass-throughs. Parsed only to keep the field known; see `PassSpec`.
    #[serde(default)]
    pub pass: Vec<PassSpec>,
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

/// One `[[pass]]` entry: a host object bound in as-is.
///
/// The daemon never acts on these — `bin/fsbroker` reads them when it builds
/// bubblewrap's arguments — but they have to be a known field, because the
/// config is parsed with `deny_unknown_fields` and a typo should still be an
/// error rather than a silently ignored line.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]     // read by bin/fsbroker, not by the daemon
pub struct PassSpec {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub dev: bool,
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
    /// Dropped at runtime by the user. The entry stays in the vector — mount
    /// indices are baked into live inodes, so the order must never change — but
    /// it no longer classifies any path, and so no longer exists in the sandbox.
    pub removed: bool,
    /// From the sidecar of permanently-approved mounts rather than the user's
    /// own config. Those are the ones the rule manager may remove; the user's
    /// written config is permanent by definition.
    pub generated: bool,
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
            removed: false,
            generated: false,
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
        self.mounts.iter().filter(|m| !m.removed).count()
    }

    /// The most specific mount whose virtual path is a prefix of `v`. A mount
    /// the user has dropped does not classify anything, so its paths stop
    /// existing.
    pub fn find_mount(&self, v: &Path) -> Option<usize> {
        self.mounts
            .iter()
            .position(|m| !m.removed && (v == m.vpath || v.starts_with(&m.vpath)))
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
        if let Some(i) = self.mounts.iter().position(|m| m.vpath == mount.vpath) {
            if self.mounts[i].removed {
                // Re-adding a path that was dropped: reuse the slot rather than
                // appending a duplicate. The index matches the path either way,
                // and any inode still holding it now refers to the new mount.
                self.mounts[i] = mount;
                self.rebuild_synthetic();
                return Ok(());
            }
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

    /// Drop a mapping added at runtime. Config mounts are permanent: only the
    /// user's own config file can take those away, by editing it and restarting.
    pub fn remove(&mut self, vpath: &Path) -> Result<()> {
        let idx = match self.mounts.iter().position(|m| m.vpath == vpath && !m.removed) {
            Some(i) => i,
            None => bail!("not mapped: {}", vpath.display()),
        };
        if !(self.mounts[idx].runtime || self.mounts[idx].generated) {
            bail!(
                "{} is in your config file, not an approved request",
                vpath.display()
            );
        }
        self.mounts[idx].removed = true;
        self.rebuild_synthetic();
        Ok(())
    }

    fn rebuild_synthetic(&mut self) {
        self.synthetic.clear();
        self.synthetic.insert(PathBuf::from("/"));
        for m in self.mounts.iter().filter(|m| !m.removed) {
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

/// Validate and open one `[[mount]]` spec.
fn open_spec(spec: &MountSpec, read_only: bool) -> Result<(PathBuf, Mount)> {
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
    Ok((
        vpath.clone(),
        Mount {
            vpath,
            host,
            writable: spec.writable && !read_only,
            dirfd,
            runtime: false,
            removed: false,
            generated: false,
        },
    ))
}

/// Append the sidecar of permanently-approved mounts, marking each `generated`.
///
/// Those are the furthest a rule can go without the user editing the config, so
/// they are also the only configured mounts the rule manager may remove. A
/// collision with the user's own config is skipped with a warning rather than
/// failing the mount: what the user wrote wins, and a stale approval must never
/// stop the sandbox from starting. A missing file is not an error.
pub fn add_generated(cfg: &mut Config, path: &Path) -> Result<usize> {
    let mounts = &mut cfg.mounts;
    let read_only = cfg.read_only;
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let raw: RootConfig = match toml::from_str(&text) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("ignoring unreadable {}: {e}", path.display());
            return Ok(0);
        }
    };
    let read_only = read_only || raw.read_only;
    let mut added = 0;
    for spec in &raw.mounts {
        let (vpath, mut mount) = match open_spec(spec, read_only) {
            Ok(x) => x,
            Err(e) => {
                log::warn!("skipping approved mount {}: {e}", spec.host.display());
                continue;
            }
        };
        if mounts.iter().any(|m| {
            !m.removed
                && (m.vpath == vpath
                    || vpath.starts_with(&m.vpath)
                    || m.vpath.starts_with(&vpath))
        }) {
            log::warn!(
                "skipping approved mount {}: the config already covers it",
                vpath.display()
            );
            continue;
        }
        mount.generated = true;
        mounts.push(mount);
        added += 1;
    }
    // The synthetic directories are computed when the config is loaded, so a
    // mount added afterwards would otherwise exist with no /var or /var/tmp to
    // reach it through.
    if added > 0 {
        mounts.sort_by(|a, b| b.vpath.as_os_str().len().cmp(&a.vpath.as_os_str().len()));
        cfg.synthetic = synthetic_from(mounts);
    }
    Ok(added)
}

/// Every directory that exists only in the virtual tree: `/` plus each strict
/// ancestor of a mount point.
fn synthetic_from(mounts: &[Mount]) -> BTreeSet<PathBuf> {
    let mut synthetic = BTreeSet::new();
    synthetic.insert(PathBuf::from("/"));
    for m in mounts {
        let mut cur = m.vpath.parent();
        while let Some(p) = cur {
            synthetic.insert(p.to_path_buf());
            if p == Path::new("/") {
                break;
            }
            cur = p.parent();
        }
    }
    synthetic
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
            let (vpath, mount) = open_spec(&spec, raw.read_only)?;
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
            mounts.push(mount);
        }

        // Longest virtual path first so prefix matching is unambiguous even if
        // nesting is added later.
        mounts.sort_by(|a, b| b.vpath.as_os_str().len().cmp(&a.vpath.as_os_str().len()));

        let synthetic = synthetic_from(&mounts);

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
