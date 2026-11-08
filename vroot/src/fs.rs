//! The FUSE filesystem: a deny-by-default virtual root.
//!
//! Invariants:
//! - A path exists only if it is a configured mount, something below one, or a
//!   synthetic directory that is an ancestor of a mount. Everything else is
//!   `ENOENT`; there is no fallback to the host root.
//! - Host paths are only ever reached through an `openat2` call whose
//!   directory fd is a mount root and whose resolution flags are
//!   `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS`.
//! - Mutations are refused unless the owning mount is writable or a runtime
//!   grant covers the path being written.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};
use log::{debug, warn};

use crate::broker::{self, Decision};
use crate::config::{MountTable, NodeKind};
use crate::policy::Policy;
use crate::sys;

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

/// Open flags that mean something for the backing file.
///
/// Everything else must be dropped before the backend `openat2`: the kernel
/// piggybacks internal bits on `fuse_open_in.flags` — most importantly
/// `__FMODE_EXEC` (`0x20`) on every exec open — and `openat2` rejects unknown
/// bits with `EINVAL`. That turned every exec through the mount into
/// `execve: Invalid argument`. `O_DIRECT` is dropped too, because our reads
/// use unaligned buffers and must stay in the page cache.
const BACKING_OPEN_FLAGS: i32 = libc::O_ACCMODE
    | libc::O_APPEND
    | libc::O_TRUNC
    | libc::O_EXCL
    | libc::O_NONBLOCK
    | libc::O_DSYNC
    | libc::O_SYNC
    | libc::O_LARGEFILE
    | libc::O_NOFOLLOW
    | libc::O_NOATIME;

struct Node {
    vpath: PathBuf,
    kind: NodeKind,
    lookup: u64,
    /// The name this inode was reached by has been deleted, but the kernel
    /// still holds the inode (an open file, or simply a reference it has not
    /// forgotten yet). `stat` must keep working for such inodes.
    orphan: bool,
    /// Last attributes seen while the path still resolved; used to answer
    /// `stat` for an orphan once no open handle is left to ask.
    last: Option<FileAttr>,
}

struct FileHandle {
    fd: OwnedFd,
    ino: u64,
    writable: bool,
}

struct DirEntryOut {
    name: OsString,
    ino: u64,
    kind: FileType,
}

struct DirHandle {
    entries: Vec<DirEntryOut>,
}

pub struct VrootFs {
    table: Arc<RwLock<MountTable>>,
    nodes: HashMap<u64, Node>,
    paths: HashMap<PathBuf, u64>,
    next_ino: u64,
    files: HashMap<u64, FileHandle>,
    dirs: HashMap<u64, DirHandle>,
    next_fh: u64,
    ttl: Duration,
    policy: Arc<Mutex<Policy>>,
    /// Prompt broker socket, if one is configured or present.
    broker: Option<PathBuf>,
}

/// Human-readable `a -> b` for one or two paths, for log lines.
fn describe(paths: &[&Path]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn errno(e: io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn systime(sec: i64, nsec: i64) -> SystemTime {
    let d = Duration::new(sec.unsigned_abs(), nsec.clamp(0, 999_999_999) as u32);
    if sec >= 0 {
        UNIX_EPOCH + d
    } else {
        UNIX_EPOCH - d
    }
}

fn ftype(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        _ => FileType::RegularFile,
    }
}

fn check_name(name: &OsStr) -> Result<(), i32> {
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') || b.contains(&0) {
        return Err(libc::EINVAL);
    }
    Ok(())
}

fn join_v(parent: &Path, name: &OsStr) -> PathBuf {
    let mut p = parent.to_path_buf();
    p.push(name);
    p
}

fn split_parent(rel: &Path) -> (PathBuf, OsString) {
    match rel.file_name() {
        Some(n) => (
            rel.parent().map(|p| p.to_path_buf()).unwrap_or_default(),
            n.to_os_string(),
        ),
        None => (PathBuf::new(), OsString::from(".")),
    }
}

fn time_or_now(t: Option<TimeOrNow>) -> libc::timespec {
    match t {
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        Some(TimeOrNow::Now) => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
        Some(TimeOrNow::SpecificTime(st)) => {
            let d = st.duration_since(UNIX_EPOCH).unwrap_or_default();
            libc::timespec {
                tv_sec: d.as_secs() as libc::time_t,
                tv_nsec: d.subsec_nanos() as i64,
            }
        }
    }
}

impl VrootFs {
    pub fn new(
        table: Arc<RwLock<MountTable>>,
        policy: Arc<Mutex<Policy>>,
        broker: Option<PathBuf>,
    ) -> VrootFs {
        let mut fs = VrootFs {
            table,
            nodes: HashMap::new(),
            paths: HashMap::new(),
            next_ino: ROOT_INO + 1,
            files: HashMap::new(),
            dirs: HashMap::new(),
            next_fh: 1,
            ttl: TTL,
            policy,
            broker,
        };
        fs.paths.insert(PathBuf::from("/"), ROOT_INO);
        fs.nodes.insert(
            ROOT_INO,
            Node {
                vpath: PathBuf::from("/"),
                kind: NodeKind::Synthetic,
                lookup: 1,
                orphan: false,
                last: None,
            },
        );
        fs
    }

    // ---- virtual tree bookkeeping -------------------------------------

    fn node_kind(&self, ino: u64) -> Result<(PathBuf, NodeKind), i32> {
        let n = self.nodes.get(&ino).ok_or(libc::ENOENT)?;
        // A runtime mapping the user has since dropped. The inode may still be
        // referenced by the kernel, but the path it names no longer exists, so
        // nothing new may be done through it. Already-open descriptors keep
        // working, like an unlinked file.
        if let NodeKind::Host(mi) = n.kind {
            let table = self.table.read().unwrap();
            if table.mounts.get(mi).map_or(true, |m| m.removed) {
                return Err(libc::ENOENT);
            }
        }
        Ok((n.vpath.clone(), n.kind))
    }

    fn classify(&self, v: &Path) -> Option<NodeKind> {
        self.table.read().unwrap().classify(v)
    }

    fn intern(&mut self, v: &Path) -> u64 {
        if let Some(&ino) = self.paths.get(v) {
            return ino;
        }
        let kind = self.classify(v).unwrap_or(NodeKind::Synthetic);
        let ino = self.next_ino;
        self.next_ino += 1;
        self.paths.insert(v.to_path_buf(), ino);
        self.nodes.insert(
            ino,
            Node {
                vpath: v.to_path_buf(),
                kind,
                lookup: 1,
                orphan: false,
                last: None,
            },
        );
        ino
    }

    /// Mark `v` and everything below it as unlinked.
    ///
    /// The path→inode mapping is dropped so a file later created at the same
    /// path gets a fresh inode — reusing the old id would let the kernel serve
    /// cached pages from the deleted file. The nodes themselves stay alive as
    /// orphans while the kernel still references them, because `stat` on an
    /// unlinked-but-open file has to keep working until the last close.
    fn mark_unlinked(&mut self, v: &Path) {
        let stale: Vec<(PathBuf, u64)> = self
            .paths
            .iter()
            .filter(|(p, _)| p.starts_with(v))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect();
        for (p, ino) in stale {
            self.paths.remove(&p);
            if let Some(n) = self.nodes.get_mut(&ino) {
                n.orphan = true;
            }
        }
    }

    /// Re-point bookkeeping after a rename.
    ///
    /// The kernel keeps the inode it already has for the moved file, so it will
    /// address that inode by its *old* node id while expecting the file at the
    /// *new* path. Without this, the first access after an atomic
    /// write-temp-then-rename (the pattern every editor and the OpenCode CLI
    /// use) resolved the stale path and failed with `ENOENT`.
    fn rename_subtree(&mut self, from: &Path, to: &Path) {
        let moved: Vec<(PathBuf, u64)> = self
            .paths
            .iter()
            .filter(|(p, _)| p.starts_with(from))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect();
        // The destination may have been overwritten; its inode is gone from
        // this path, but the kernel may still hold it open.
        self.mark_unlinked(to);
        for (old, ino) in moved {
            self.paths.remove(&old);
            let rel = old.strip_prefix(from).unwrap_or(Path::new(""));
            let new = if rel.as_os_str().is_empty() {
                to.to_path_buf()
            } else {
                to.join(rel)
            };
            if let Some(n) = self.nodes.get_mut(&ino) {
                n.vpath = new.clone();
            }
            self.paths.insert(new, ino);
        }
    }

    fn rel_for(&self, v: &Path, mi: usize) -> PathBuf {
        self.table.read().unwrap().rel_for(v, mi)
    }

    /// Resolve `rel` under mount `mi` with the only resolution policy the
    /// daemon allows.
    fn open_mount(&self, mi: usize, rel: &Path, flags: i32) -> io::Result<OwnedFd> {
        let table = self.table.read().unwrap();
        let m = &table.mounts[mi];
        let p: &Path = if rel.as_os_str().is_empty() {
            Path::new(".")
        } else {
            rel
        };
        sys::openat2(
            m.dirfd.as_raw_fd(),
            p,
            flags | libc::O_CLOEXEC,
            0,
            sys::SAFE_RESOLVE,
        )
    }

    fn open_mount_dir(&self, mi: usize, rel: &Path) -> io::Result<OwnedFd> {
        self.open_mount(mi, rel, libc::O_PATH | libc::O_DIRECTORY)
    }

    fn open_parent(&self, mi: usize, rel: &Path) -> io::Result<(OwnedFd, OsString)> {
        let (parent, name) = split_parent(rel);
        let fd = self.open_mount_dir(mi, &parent)?;
        Ok((fd, name))
    }

    /// Open the directory a mutating FUSE request names as its parent.
    /// Callers pass the parent's own path, not a child path.
    fn open_dir(&self, mi: usize, rel: &Path) -> io::Result<OwnedFd> {
        self.open_mount_dir(mi, rel)
    }

    fn attr_from(&self, st: &libc::stat, ino: u64, allow_write: bool) -> FileAttr {
        let mut perm = (st.st_mode as u32 & 0o7777) as u16;
        if !allow_write && self.broker.is_none() {
            // Without a broker there is nothing to ask, so read-only mounts deny
            // a write at the permission-bits level and the kernel never has to
            // bother the daemon. With a broker configured, the mode bits must
            // stay honest: `default_permissions` would otherwise refuse the
            // write here and the daemon would never get to prompt.
            perm &= !0o222;
        }
        FileAttr {
            ino,
            size: st.st_size as u64,
            blocks: st.st_blocks as u64,
            atime: systime(st.st_atime, st.st_atime_nsec),
            mtime: systime(st.st_mtime, st.st_mtime_nsec),
            ctime: systime(st.st_ctime, st.st_ctime_nsec),
            crtime: systime(st.st_ctime, st.st_ctime_nsec),
            kind: ftype(st.st_mode as u32),
            perm,
            nlink: st.st_nlink as u32,
            uid: st.st_uid,
            gid: st.st_gid,
            rdev: st.st_rdev as u32,
            blksize: st.st_blksize as u32,
            flags: 0,
        }
    }

    fn synthetic_attr(&self, ino: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn attr_of(&mut self, v: &Path, kind: NodeKind, ino: u64) -> Result<FileAttr, i32> {
        match kind {
            NodeKind::Synthetic => Ok(self.synthetic_attr(ino)),
            NodeKind::Host(mi) => {
                let allow_write = self.writable(v, mi);
                let rel = self.rel_for(v, mi);
                let opened = self.open_mount(mi, &rel, libc::O_PATH | libc::O_NOFOLLOW);
                let st = match opened {
                    Ok(fd) => {
                        let st = sys::stat_fd(fd.as_raw_fd()).map_err(errno)?;
                        let attr = self.attr_from(&st, ino, allow_write);
                        if let Some(n) = self.nodes.get_mut(&ino) {
                            n.last = Some(attr);
                        }
                        return Ok(attr);
                    }
                    Err(e)
                        if e.raw_os_error() == Some(libc::ENOENT)
                            && self.nodes.get(&ino).is_some_and(|n| n.orphan) =>
                    {
                        // The name is gone but the kernel still holds this
                        // inode: answer from an open handle if there is one,
                        // otherwise from the attributes it last had.
                        if let Some(h) = self.files.values().find(|h| h.ino == ino) {
                            sys::stat_fd(h.fd.as_raw_fd()).map_err(errno)?
                        } else {
                            return self
                                .nodes
                                .get(&ino)
                                .and_then(|n| n.last)
                                .ok_or(libc::ENOENT);
                        }
                    }
                    Err(e) => return Err(errno(e)),
                };
                Ok(self.attr_from(&st, ino, allow_write))
            }
        }
    }

    /// True if `v` is writable-by-default: the mount is writable or a runtime
    /// grant covers it. Does not consume a `once` grant.
    fn writable(&self, v: &Path, mi: usize) -> bool {
        self.table.read().unwrap().writable(mi) || self.policy.lock().unwrap().peek(v)
    }

    /// Authorize a mutation. `paths` is every path the operation touches — one
    /// for `open`/`create`/`mkdir`/`unlink`, two for `rename`. All must be
    /// covered by the mount's writability, by local grants, or by a decision
    /// from the prompt broker.
    fn authorize(&mut self, req: &Request<'_>, op: &str, paths: &[&Path], mi: usize) -> Result<(), i32> {
        if self.table.read().unwrap().writable(mi) {
            return Ok(());
        }
        {
            let mut p = self.policy.lock().unwrap();
            if paths.iter().all(|v| p.peek(v)) {
                for v in paths {
                    p.consume(v);
                }
                debug!("grant: {op} allowed for {}", describe(paths));
                return Ok(());
            }
        }

        let Some(sock) = self.broker.clone() else {
            warn!("deny: {op} without grant (no broker) for {}", describe(paths));
            return Err(libc::EACCES);
        };

        match broker::ask(&sock, op, paths, req.pid(), req.uid()) {
            Decision::Allow { scope, paths: granted } => {
                // The broker is the single source of truth for anything wider
                // than this one operation: it remembers the session/timed/
                // always grant itself, so a revoke or expiry takes effect
                // immediately and the daemon holds no stale copy. `once` needs
                // no bookkeeping either — this call *is* the one operation.
                debug!(
                    "grant: broker allowed {op} as {} ({})",
                    scope.as_str(),
                    describe(paths)
                );
                let _ = granted;
                Ok(())
            }
            Decision::Deny => {
                // Nothing is remembered here: a denial the user wants to stick
                // is a rule the broker holds, and it answers without prompting.
                // A one-off "deny" is simply this operation failing.
                warn!("deny: broker refused {op} on {}", describe(paths));
                Err(libc::EACCES)
            }
            Decision::Unavailable => {
                warn!("deny: broker unavailable for {op} on {}", describe(paths));
                Err(libc::EACCES)
            }
        }
    }
    // ---- lookups ------------------------------------------------------

    fn lookup_inner(&mut self, parent: u64, name: &OsStr) -> Result<(u64, FileAttr), i32> {
        if name == OsStr::new(".") {
            let (v, k) = self.node_kind(parent)?;
            return Ok((parent, self.attr_of(&v, k, parent)?));
        }
        if name == OsStr::new("..") {
            let (v, _) = self.node_kind(parent)?;
            let p = v.parent().unwrap_or(Path::new("/")).to_path_buf();
            let ino = self.intern(&p);
            let (pv, pk) = self.node_kind(ino)?;
            return Ok((ino, self.attr_of(&pv, pk, ino)?));
        }
        check_name(name)?;
        let (pv, _) = self.node_kind(parent)?;
        let child = join_v(&pv, name);
        let kind = match self.classify(&child) {
            Some(k) => k,
            None => {
                warn!("deny: lookup of unmapped path {}", child.display());
                return Err(libc::ENOENT);
            }
        };
        let ino = self.intern(&child);
        let attr = self.attr_of(&child, kind, ino)?;
        if let Some(n) = self.nodes.get_mut(&ino) {
            n.lookup += 1;
        }
        Ok((ino, attr))
    }

    fn ensure_host(&self, ino: u64) -> Result<(PathBuf, usize), i32> {
        let (v, k) = self.node_kind(ino)?;
        match k {
            NodeKind::Host(mi) => Ok((v, mi)),
            NodeKind::Synthetic => {
                warn!("deny: mutation of synthetic path {}", v.display());
                Err(libc::EROFS)
            }
        }
    }

    fn guard_mount_root(&self, child: &Path, mi: usize) -> Result<(), i32> {
        if child == self.table.read().unwrap().mounts[mi].vpath {
            warn!("deny: attempt to modify mount point {}", child.display());
            Err(libc::EBUSY)
        } else {
            Ok(())
        }
    }

    // ---- attribute changes --------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn setattr_inner(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<FileAttr, i32> {
        let (v, mi) = self.ensure_host(ino)?;
        let rel = self.rel_for(&v, mi);
        let (pfd, name) = self.open_parent(mi, &rel).map_err(errno)?;
        let cname = sys::cname(&name).map_err(errno)?;

        if size.is_some() || mode.is_some() || uid.is_some() || gid.is_some() {
            self.authorize(req, "write", &[&v], mi)?;
        }

        if let Some(sz) = size {
            let fd = self
                .open_mount(mi, &rel, libc::O_WRONLY)
                .map_err(errno)?;
            let r = unsafe { libc::ftruncate(fd.as_raw_fd(), sz as libc::off_t) };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
        }
        if let Some(m) = mode {
            let r = unsafe {
                libc::fchmodat(
                    pfd.as_raw_fd(),
                    cname.as_ptr(),
                    (m & 0o7777) as libc::mode_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
        }
        if uid.is_some() || gid.is_some() {
            let r = unsafe {
                libc::fchownat(
                    pfd.as_raw_fd(),
                    cname.as_ptr(),
                    uid.unwrap_or(u32::MAX),
                    gid.unwrap_or(u32::MAX),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
        }
        if atime.is_some() || mtime.is_some() {
            let times = [time_or_now(atime), time_or_now(mtime)];
            let r = unsafe {
                libc::utimensat(
                    pfd.as_raw_fd(),
                    cname.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
        }

        self.attr_of(&v, NodeKind::Host(mi), ino)
    }

    fn build_dir_entries(&mut self, ino: u64) -> Result<Vec<DirEntryOut>, i32> {
        let (vpath, kind) = self.node_kind(ino)?;
        let parent_v = vpath.parent().unwrap_or(Path::new("/")).to_path_buf();
        let parent_ino = self.intern(&parent_v);

        let mut entries = Vec::new();
        entries.push(DirEntryOut {
            name: OsString::from("."),
            ino,
            kind: FileType::Directory,
        });
        entries.push(DirEntryOut {
            name: OsString::from(".."),
            ino: parent_ino,
            kind: FileType::Directory,
        });

        match kind {
            NodeKind::Synthetic => {
                let mut children: Vec<PathBuf> = Vec::new();
                let table = self.table.read().unwrap();
                for m in &table.mounts {
                    if !m.removed && m.vpath.parent() == Some(vpath.as_path()) {
                        children.push(m.vpath.clone());
                    }
                }
                for s in &table.synthetic {
                    if s.parent() == Some(vpath.as_path()) {
                        children.push(s.clone());
                    }
                }
                drop(table);
                children.sort();
                children.dedup();
                for c in children {
                    let name = c
                        .file_name()
                        .map(|n| n.to_os_string())
                        .unwrap_or_else(|| c.as_os_str().to_os_string());
                    let cino = self.intern(&c);
                    entries.push(DirEntryOut {
                        name,
                        ino: cino,
                        kind: FileType::Directory,
                    });
                }
            }
            NodeKind::Host(mi) => {
                let rel = self.rel_for(&vpath, mi);
                let fd = self
                    .open_mount(mi, &rel, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)
                    .map_err(errno)?;
                let list = sys::read_dir_all(fd.as_raw_fd()).map_err(errno)?;
                for d in list {
                    let child = join_v(&vpath, &d.name);
                    let ckind = match sys::dtype_to_kind(d.dtype) {
                        Some(k) => k,
                        None => {
                            let crel = self.rel_for(&child, mi);
                            let cfd = self
                                .open_mount(mi, &crel, libc::O_PATH | libc::O_NOFOLLOW)
                                .map_err(errno)?;
                            let st = sys::stat_fd(cfd.as_raw_fd()).map_err(errno)?;
                            ftype(st.st_mode as u32)
                        }
                    };
                    let cino = self.intern(&child);
                    entries.push(DirEntryOut {
                        name: d.name,
                        ino: cino,
                        kind: ckind,
                    });
                }
            }
        }
        Ok(entries)
    }
}

impl Filesystem for VrootFs {
    fn init(&mut self, _req: &Request<'_>, _config: &mut fuser::KernelConfig) -> Result<(), libc::c_int> {
        debug!(
            "vroot mounted with {} mappings",
            self.table.read().unwrap().len()
        );
        Ok(())
    }

    fn destroy(&mut self) {
        debug!("vroot unmounted");
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.lookup_inner(parent, name) {
            Ok((_ino, attr)) => reply.entry(&self.ttl, &attr, 0),
            Err(e) => reply.error(e),
        }
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        let Some(n) = self.nodes.get_mut(&ino) else {
            return;
        };
        n.lookup = n.lookup.saturating_sub(nlookup);
        if n.lookup == 0 && n.orphan {
            // Nobody can reach it any more: the name is gone and the kernel
            // has dropped its last reference.
            self.nodes.remove(&ino);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match self.node_kind(ino) {
            Ok((v, k)) => match self.attr_of(&v, k, ino) {
                Ok(a) => reply.attr(&self.ttl, &a),
                Err(e) => reply.error(e),
            },
            Err(e) => reply.error(e),
        }
    }

    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        match self.setattr_inner(req, ino, mode, uid, gid, size, atime, mtime) {
            Ok(a) => reply.attr(&self.ttl, &a),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let (v, mi) = match self.ensure_host(ino) {
            Ok(x) => x,
            Err(e) => return reply.error(e),
        };
        let rel = self.rel_for(&v, mi);
        let fd = match self.open_mount(mi, &rel, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(e) => return reply.error(errno(e)),
        };
        let mut buf = vec![0u8; 4096];
        let empty = std::ffi::CString::new("").unwrap();
        let n = unsafe {
            libc::readlinkat(
                fd.as_raw_fd(),
                empty.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if n < 0 {
            return reply.error(errno(io::Error::last_os_error()));
        }
        reply.data(&buf[..n as usize]);
    }

    fn mknod(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        // Device nodes, FIFOs and sockets have no business in the agent's view.
        warn!("deny: mknod {:?}", name);
        reply.error(libc::EPERM);
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let r = (|| -> Result<(u64, FileAttr), i32> {
            check_name(name)?;
            let (v, mi) = self.ensure_host(parent)?;
            let child = join_v(&v, name);
            self.authorize(req, "mkdir", &[&child], mi)?;
            let pfd = self.open_dir(mi, &self.rel_for(&v, mi)).map_err(errno)?;
            let cname = sys::cname(name).map_err(errno)?;
            let r = unsafe {
                libc::mkdirat(
                    pfd.as_raw_fd(),
                    cname.as_ptr(),
                    (mode & 0o7777 & !umask) as libc::mode_t,
                )
            };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
            let ino = self.intern(&child);
            let attr = self.attr_of(&child, NodeKind::Host(mi), ino)?;
            Ok((ino, attr))
        })();
        match r {
            Ok((_ino, attr)) => reply.entry(&self.ttl, &attr, 0),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let r = (|| -> Result<(), i32> {
            check_name(name)?;
            let (v, mi) = self.ensure_host(parent)?;
            let child = join_v(&v, name);
            self.authorize(req, "unlink", &[&child], mi)?;
            self.guard_mount_root(&child, mi)?;
            let pfd = self.open_dir(mi, &self.rel_for(&v, mi)).map_err(errno)?;
            let cname = sys::cname(name).map_err(errno)?;
            let r = unsafe { libc::unlinkat(pfd.as_raw_fd(), cname.as_ptr(), 0) };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
            self.mark_unlinked(&child);
            Ok(())
        })();
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let r = (|| -> Result<(), i32> {
            check_name(name)?;
            let (v, mi) = self.ensure_host(parent)?;
            let child = join_v(&v, name);
            self.authorize(req, "rmdir", &[&child], mi)?;
            self.guard_mount_root(&child, mi)?;
            let pfd = self.open_dir(mi, &self.rel_for(&v, mi)).map_err(errno)?;
            let cname = sys::cname(name).map_err(errno)?;
            let r = unsafe { libc::unlinkat(pfd.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR) };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
            self.mark_unlinked(&child);
            Ok(())
        })();
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let r = (|| -> Result<(u64, FileAttr), i32> {
            check_name(link_name)?;
            let (v, mi) = self.ensure_host(parent)?;
            let child = join_v(&v, link_name);
            self.authorize(req, "symlink", &[&child], mi)?;
            let pfd = self.open_dir(mi, &self.rel_for(&v, mi)).map_err(errno)?;
            let cname = sys::cname(link_name).map_err(errno)?;
            let ctarget = sys::cpath(target).map_err(errno)?;
            let r = unsafe { libc::symlinkat(ctarget.as_ptr(), pfd.as_raw_fd(), cname.as_ptr()) };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
            let ino = self.intern(&child);
            let attr = self.attr_of(&child, NodeKind::Host(mi), ino)?;
            Ok((ino, attr))
        })();
        match r {
            Ok((_ino, attr)) => reply.entry(&self.ttl, &attr, 0),
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let r = (|| -> Result<(), i32> {
            check_name(name)?;
            check_name(newname)?;
            let (pv, pmi) = self.ensure_host(parent)?;
            let (nv, nmi) = self.ensure_host(newparent)?;
            if pmi != nmi {
                warn!(
                    "deny: cross-mount rename {} -> {}",
                    join_v(&pv, name).display(),
                    join_v(&nv, newname).display()
                );
                return Err(libc::EXDEV);
            }
            let src = join_v(&pv, name);
            let dst = join_v(&nv, newname);
            self.authorize(req, "rename", &[&src, &dst], pmi)?;
            self.guard_mount_root(&src, pmi)?;
            self.guard_mount_root(&dst, nmi)?;

            let opfd = self.open_dir(pmi, &self.rel_for(&pv, pmi)).map_err(errno)?;
            let npfd = self.open_dir(nmi, &self.rel_for(&nv, nmi)).map_err(errno)?;
            let oname = sys::cname(name).map_err(errno)?;
            let nname = sys::cname(newname).map_err(errno)?;
            let r = unsafe {
                libc::renameat2(
                    opfd.as_raw_fd(),
                    oname.as_ptr(),
                    npfd.as_raw_fd(),
                    nname.as_ptr(),
                    flags,
                )
            };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
            self.rename_subtree(&src, &dst);
            Ok(())
        })();
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn link(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let r = (|| -> Result<(u64, FileAttr), i32> {
            check_name(newname)?;
            let (ov, omi) = self.ensure_host(ino)?;
            let (nv, nmi) = self.ensure_host(newparent)?;
            if omi != nmi {
                return Err(libc::EXDEV);
            }
            let child = join_v(&nv, newname);
            self.authorize(req, "link", &[&child], omi)?;
            let (opfd, oname) = self.open_parent(omi, &self.rel_for(&ov, omi)).map_err(errno)?;
            let npfd = self.open_dir(nmi, &self.rel_for(&nv, nmi)).map_err(errno)?;
            let cob = sys::cname(&oname).map_err(errno)?;
            let cnb = sys::cname(newname).map_err(errno)?;
            let r = unsafe {
                libc::linkat(
                    opfd.as_raw_fd(),
                    cob.as_ptr(),
                    npfd.as_raw_fd(),
                    cnb.as_ptr(),
                    0,
                )
            };
            if r < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
            let cino = self.intern(&child);
            let attr = self.attr_of(&child, NodeKind::Host(nmi), cino)?;
            Ok((cino, attr))
        })();
        match r {
            Ok((_cino, attr)) => reply.entry(&self.ttl, &attr, 0),
            Err(e) => reply.error(e),
        }
    }

    fn open(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let (v, mi) = match self.ensure_host(ino) {
            Ok(x) => x,
            Err(libc::EROFS) => return reply.error(libc::EISDIR),
            Err(e) => return reply.error(e),
        };
        let flags = flags & BACKING_OPEN_FLAGS;
        let wants_write = flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC | libc::O_APPEND) != 0;
        if wants_write {
            if let Err(e) = self.authorize(req, "open", &[&v], mi) {
                return reply.error(e);
            }
        }
        let rel = self.rel_for(&v, mi);
        match self.open_mount(mi, &rel, flags) {
            Ok(fd) => {
                let fh = self.next_fh;
                self.next_fh += 1;
                self.files.insert(
                    fh,
                    FileHandle {
                        fd,
                        ino,
                        writable: wants_write,
                    },
                );
                reply.opened(fh, 0);
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(h) = self.files.get(&fh) else {
            return reply.error(libc::EBADF);
        };
        let mut buf = vec![0u8; size as usize];
        match sys::pread(h.fd.as_raw_fd(), &mut buf, offset) {
            Ok(n) => reply.data(&buf[..n]),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let Some(h) = self.files.get(&fh) else {
            return reply.error(libc::EBADF);
        };
        if !h.writable {
            warn!("deny: write through a handle opened read-only");
            return reply.error(libc::EACCES);
        }
        match sys::pwrite(h.fd.as_raw_fd(), data, offset) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.files.remove(&fh);
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let Some(h) = self.files.get(&fh) else {
            return reply.error(libc::EBADF);
        };
        let r = unsafe {
            if datasync {
                libc::fdatasync(h.fd.as_raw_fd())
            } else {
                libc::fsync(h.fd.as_raw_fd())
            }
        };
        if r < 0 {
            reply.error(errno(io::Error::last_os_error()));
        } else {
            reply.ok();
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        match self.build_dir_entries(ino) {
            Ok(entries) => {
                let fh = self.next_fh;
                self.next_fh += 1;
                self.dirs.insert(fh, DirHandle { entries });
                reply.opened(fh, 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(h) = self.dirs.get(&fh) else {
            return reply.error(libc::EBADF);
        };
        let mut idx = offset.max(0) as usize;
        while idx < h.entries.len() {
            let e = &h.entries[idx];
            if reply.add(e.ino, (idx + 1) as i64, e.kind, &e.name) {
                break;
            }
            idx += 1;
        }
        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        self.dirs.remove(&fh);
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let table = self.table.read().unwrap();
        let Some(m) = table.mounts.first() else {
            return reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
        };
        match sys::statfs_fd(m.dirfd.as_raw_fd()) {
            Ok(st) => reply.statfs(
                st.f_blocks,
                st.f_bfree,
                st.f_bavail,
                st.f_files,
                st.f_ffree,
                st.f_bsize as u32,
                st.f_namelen as u32,
                st.f_bsize as u32,
            ),
            Err(_) => reply.statfs(0, 0, 0, 0, 0, 512, 255, 0),
        }
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, _mask: i32, reply: ReplyEmpty) {
        match self.node_kind(ino) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let r = (|| -> Result<(u64, FileAttr, FileHandle), i32> {
            check_name(name)?;
            let (v, mi) = self.ensure_host(parent)?;
            let child = join_v(&v, name);
            self.authorize(req, "create", &[&child], mi)?;
            let pfd = self.open_dir(mi, &self.rel_for(&v, mi)).map_err(errno)?;
            let cname = sys::cname(name).map_err(errno)?;
            let oflags = (flags & BACKING_OPEN_FLAGS)
                | libc::O_CREAT
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW;
            let fd = unsafe {
                libc::openat(
                    pfd.as_raw_fd(),
                    cname.as_ptr(),
                    oflags,
                    (mode & 0o7777 & !umask) as libc::c_uint,
                )
            };
            if fd < 0 {
                return Err(errno(io::Error::last_os_error()));
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let st = sys::stat_fd(fd.as_raw_fd()).map_err(errno)?;
            let ino = self.intern(&child);
            let attr = self.attr_from(&st, ino, true);
            Ok((
                ino,
                attr,
                FileHandle {
                    fd,
                    ino,
                    writable: true,
                },
            ))
        })();
        match r {
            Ok((_ino, attr, h)) => {
                let fh = self.next_fh;
                self.next_fh += 1;
                self.files.insert(fh, h);
                reply.created(&self.ttl, &attr, 0, fh, 0);
            }
            Err(e) => reply.error(e),
        }
    }
}
