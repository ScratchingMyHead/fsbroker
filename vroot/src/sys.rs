//! Thin, explicit wrappers around the Linux syscalls the virtual root needs.
//!
//! Everything that touches a host path goes through `openat2` with
//! `RESOLVE_IN_ROOT`, so a symlink whose target is `/etc/passwd` is resolved
//! relative to the mount root and cannot escape it.

#![allow(dead_code)]

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::path::Path;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;
pub const RESOLVE_IN_ROOT: u64 = 0x10;

/// The only resolution policy used by the daemon. `RESOLVE_IN_ROOT` clamps
/// absolute symlink targets to the mount root; `RESOLVE_NO_MAGICLINKS` blocks
/// `/proc/self/fd/N` style escapes.
pub const SAFE_RESOLVE: u64 = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;

pub fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

pub fn cname(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// `openat2(2)`. Returns an owned descriptor.
pub fn openat2(
    dirfd: RawFd,
    path: &Path,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> io::Result<OwnedFd> {
    let c = cpath(path)?;
    let how = OpenHow {
        flags: flags as u64,
        mode: mode as u64,
        resolve,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
    }
}

pub fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstat(fd, &mut st) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(st)
    }
}

pub fn statfs_fd(fd: RawFd) -> io::Result<libc::statfs> {
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatfs(fd, &mut st) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(st)
    }
}

pub fn pread(fd: RawFd, buf: &mut [u8], offset: i64) -> io::Result<usize> {
    loop {
        let r = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                offset as libc::off_t,
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        return Ok(r as usize);
    }
}

pub fn pwrite(fd: RawFd, buf: &[u8], offset: i64) -> io::Result<usize> {
    loop {
        let r = unsafe {
            libc::pwrite(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                offset as libc::off_t,
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        return Ok(r as usize);
    }
}

pub struct Dirent {
    pub name: OsString,
    /// `d_type` as reported by `getdents64`.
    pub dtype: u8,
}

const DT_UNKNOWN: u8 = 0;
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;

/// Read every entry of an already-open directory.
///
/// The descriptor's offset is reset first so the list is complete, and `.`
/// and `..` are filtered out: the FUSE layer synthesises those.
pub fn read_dir_all(fd: RawFd) -> io::Result<Vec<Dirent>> {
    unsafe {
        libc::lseek(fd, 0, libc::SEEK_SET);
    }
    let mut buf = vec![0u8; 64 * 1024];
    let mut out = Vec::new();
    loop {
        let n = unsafe {
            libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len())
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            break;
        }
        let total = n as usize;
        let mut off = 0usize;
        while off < total {
            let rec = &buf[off..];
            if rec.len() < 19 {
                break;
            }
            // struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen;
            //                          u8 d_type; char d_name[]; }
            let reclen = u16::from_ne_bytes([rec[16], rec[17]]) as usize;
            let dtype = rec[18];
            if reclen < 19 || off + reclen > total {
                break;
            }
            let name_field = &rec[19..reclen];
            let end = name_field
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_field.len());
            let name = OsString::from_vec(name_field[..end].to_vec());
            if name != "." && name != ".." {
                out.push(Dirent { name, dtype });
            }
            off += reclen;
        }
    }
    Ok(out)
}

/// Map a `d_type` to a `fuser::FileType`; `None` means "unknown, stat it".
pub fn dtype_to_kind(dtype: u8) -> Option<fuser::FileType> {
    use fuser::FileType;
    match dtype {
        DT_DIR => Some(FileType::Directory),
        DT_REG => Some(FileType::RegularFile),
        DT_LNK => Some(FileType::Symlink),
        DT_FIFO => Some(FileType::NamedPipe),
        DT_SOCK => Some(FileType::Socket),
        DT_CHR => Some(FileType::CharDevice),
        DT_BLK => Some(FileType::BlockDevice),
        DT_UNKNOWN => None,
        _ => None,
    }
}
