mod broker;
mod config;
mod ctl;
mod fs;
mod policy;
mod req;
mod sys;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use fuser::MountOption;

use crate::config::{Config, MountTable, NodeKind};
use crate::fs::VrootFs;

fn usage() {
    eprintln!(
        "vroot — deny-by-default FUSE virtual root

Usage:
  vroot --config <file> --run-dir <dir> [--mount-point <dir>]
  vroot --config <file> [--mount-point <dir>] [--control-socket <path>]
                        [--broker-socket <path>] [--request-socket <path>]
                        [--read-only]
  vroot --config <file> --check <virtual-path>...
  vroot --config <file> --tree

The config file is TOML:

  mount_point = \"/run/user/1000/vroot\"

  [[mount]]
  virtual_path = \"/projects/demo\"
  host = \"/srv/demo\"
  writable = true

Every path not covered by a [[mount]] is ENOENT. Writes to a read-only mount
can be granted at runtime through the control socket (host-only). If a prompt
broker is listening on the broker socket the daemon asks it before refusing
such a write.

--run-dir is where the daemon keeps its sockets and nothing else of the
program: vroot.sock, broker.sock and request.sock are derived from it. Without
it they default to the mount point's parent directory."
    );
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut config_path: Option<PathBuf> = None;
    let mut mount_point: Option<PathBuf> = None;
    let mut run_dir: Option<PathBuf> = None;
    let mut control_socket: Option<PathBuf> = None;
    let mut broker_socket: Option<PathBuf> = None;
    let mut request_socket: Option<PathBuf> = None;
    let mut read_only = false;
    let mut checks: Vec<String> = Vec::new();
    let mut show_tree = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => {
                config_path = Some(PathBuf::from(
                    args.next().context("--config needs a path")?,
                ))
            }
            "--run-dir" => {
                run_dir = Some(PathBuf::from(
                    args.next().context("--run-dir needs a directory")?,
                ))
            }
            "-m" | "--mount-point" => {
                mount_point = Some(PathBuf::from(
                    args.next().context("--mount-point needs a directory")?,
                ))
            }
            "--control-socket" => {
                control_socket = Some(PathBuf::from(
                    args.next().context("--control-socket needs a path")?,
                ))
            }
            "--broker-socket" => {
                broker_socket = Some(PathBuf::from(
                    args.next().context("--broker-socket needs a path")?,
                ))
            }
            "--request-socket" => {
                request_socket = Some(PathBuf::from(
                    args.next().context("--request-socket needs a path")?,
                ))
            }
            "--read-only" => read_only = true,
            "--check" => checks.push(args.next().context("--check needs a virtual path")?),
            "--tree" => show_tree = true,
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            other => bail!("unknown argument: {other} (try --help)"),
        }
    }

    let config_path = config_path.context("missing --config <file>")?;
    let mut cfg = Config::load(&config_path)?;
    if read_only {
        cfg.read_only = true;
        for m in &mut cfg.mounts {
            m.writable = false;
        }
    }

    if show_tree {
        print_tree(&cfg);
        return Ok(());
    }

    if !checks.is_empty() {
        for c in &checks {
            print_check(&cfg, c);
        }
        return Ok(());
    }

    let mp = mount_point
        .or_else(|| cfg.mount_point.clone())
        .context("no mount point: set mount_point in the config or pass --mount-point")?;

    if !mp.exists() {
        std::fs::create_dir_all(&mp)
            .with_context(|| format!("creating mount point {}", mp.display()))?;
    }
    if !mp.is_dir() {
        bail!("mount point is not a directory: {}", mp.display());
    }
    if std::fs::read_dir(&mp)?.next().is_some() {
        bail!("mount point is not empty: {}", mp.display());
    }

    log::info!("virtual root mappings:");
    for m in &cfg.mounts {
        log::info!(
            "  {:<24} -> {} ({})",
            m.vpath.display(),
            m.host.display(),
            if m.writable { "writable" } else { "read-only" }
        );
    }
    for s in &cfg.synthetic {
        if s != Path::new("/") {
            log::info!("  {:<24} -> (synthetic directory)", s.display());
        }
    }

    let mut opts = vec![
        MountOption::FSName("vroot".to_string()),
        MountOption::Subtype("vroot".to_string()),
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
    ];
    if cfg.allow_other {
        opts.push(MountOption::AllowOther);
    }

    // Sockets default to the run directory when one is given, else beside the
    // mount point (the older behaviour).
    let socket_dir = run_dir
        .clone()
        .or_else(|| mp.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("/"));
    let sock = control_socket.unwrap_or_else(|| socket_dir.join("vroot.sock"));
    let table = std::sync::Arc::new(std::sync::RwLock::new(MountTable::new(
        cfg.mounts,
        cfg.synthetic,
    )));
    let policy = std::sync::Arc::new(std::sync::Mutex::new(policy::Policy::default()));
    ctl::serve(sock, policy.clone(), table.clone())?;

    let broker = broker_socket
        .clone()
        .or_else(|| Some(socket_dir.join("broker.sock")));
    if let Some(b) = &broker {
        log::info!("prompt broker socket: {} (optional)", b.display());
    }

    let request = request_socket.unwrap_or_else(|| socket_dir.join("request.sock"));
    req::serve(request, table.clone(), broker.clone())?;
    let fs = VrootFs::new(table, policy, broker);
    log::info!("mounting at {}", mp.display());
    fuser::mount2(fs, &mp, &opts).with_context(|| format!("mounting {}", mp.display()))?;
    Ok(())
}

fn print_tree(cfg: &Config) {
    println!("/");
    let mut dirs: Vec<&Path> = cfg
        .synthetic
        .iter()
        .map(|p| p.as_path())
        .filter(|p| *p != Path::new("/"))
        .collect();
    dirs.sort();
    for d in dirs {
        println!("{}/  (synthetic)", d.display());
    }
    for m in &cfg.mounts {
        println!(
            "{}  ->  {}  [{}]",
            m.vpath.display(),
            m.host.display(),
            if m.writable { "rw" } else { "ro" }
        );
    }
}

fn print_check(cfg: &Config, raw: &str) {
    let p = match normalize(raw) {
        Some(p) => p,
        None => {
            println!("{raw}: DENY (invalid virtual path)");
            return;
        }
    };
    if cfg.synthetic.contains(&p) {
        println!("{}: synthetic directory", p.display());
        return;
    }
    for m in &cfg.mounts {
        if p.starts_with(&m.vpath) {
            let rel = p.strip_prefix(&m.vpath).unwrap();
            let host = m.host.join(rel);
            let exists = if rel.as_os_str().is_empty() {
                true
            } else {
                // Check through the host directory without following anything
                // outside the mount root: the daemon itself uses openat2.
                host.exists()
            };
            println!(
                "{}: {} mapping -> {}{} [{}]",
                p.display(),
                if exists { "MAPPED" } else { "missing" },
                host.display(),
                if exists { "" } else { " (not found)" },
                if m.writable { "rw" } else { "ro" }
            );
            return;
        }
    }
    println!("{}: DENY (not mapped)", p.display());
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

// Keep NodeKind referenced so the module link is obvious even when the
// compiler inlines everything.
#[allow(dead_code)]
fn _kind_name(k: NodeKind) -> &'static str {
    match k {
        NodeKind::Synthetic => "synthetic",
        NodeKind::Host(_) => "host",
    }
}
