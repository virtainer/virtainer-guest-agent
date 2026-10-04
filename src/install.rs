// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `install` / `uninstall`: put this binary in place and run it as a service.
//!
//! The install logic lives here, in the binary, rather than in per-distro
//! cloud-config: distro differences are handled once, in tested code. It is
//! safe to re-run (a cloud-init boothook runs it every boot): nothing is
//! rewritten or restarted unless the binary or the service file changed.
//! Services are started with `--no-block`: install usually runs inside
//! cloud-init, and a blocking start from there must never wait on boot
//! ordering.

use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::sys;

pub const BIN_PATH: &str = "/usr/local/sbin/virtainer-guest-agent";
const SERVICE: &str = "virtainer-guest-agent";
const UNIT_PATH: &str = "/etc/systemd/system/virtainer-guest-agent.service";
const OPENRC_PATH: &str = "/etc/init.d/virtainer-guest-agent";
pub const RUNTIME_DIR: &str = "/run/virtainer-guest-agent";

/// No default dependencies: they would order the agent after sysinit.target,
/// and cloud-init's network stage sits before sysinit.target waiting for
/// the network to come online (up to two minutes on Ubuntu when it never
/// does). The host needs the agent most when the guest network is broken.
///
/// KillMode=process: stopping or updating the agent ends its Shell sessions
/// (their terminals hang up), but must not kill what users started from a
/// Shell or with guest-exec. OpenRC's supervise-daemon behaves the same.
const SYSTEMD_UNIT: &str = "\
# Installed by `virtainer-guest-agent install`; reinstalling overwrites it.
[Unit]
Description=Virtainer guest agent
DefaultDependencies=no
After=local-fs.target systemd-modules-load.service
Before=shutdown.target
Conflicts=shutdown.target
IgnoreOnIsolate=yes

[Service]
ExecStart=/usr/local/sbin/virtainer-guest-agent
Restart=always
RestartSec=1
KillMode=process

[Install]
WantedBy=multi-user.target
";

const OPENRC_SCRIPT: &str = "\
#!/sbin/openrc-run
# Installed by `virtainer-guest-agent install`; reinstalling overwrites it.

description=\"Virtainer guest agent\"
command=\"/usr/local/sbin/virtainer-guest-agent\"
supervisor=\"supervise-daemon\"
respawn_delay=1
respawn_max=0

depend() {
\tneed localmount
\tafter bootmisc
}
";

/// A qemu-ga unit that earlier Virtainer releases pointed at vsock port 100.
/// It is set aside (kept as `.bak`) or the port stays taken.
const LEGACY_QGA_UNIT: &str = "/etc/systemd/system/qemu-guest-agent.service";

enum Init {
    Systemd,
    OpenRc,
}

fn detect_init() -> Option<Init> {
    if Path::new("/run/systemd/system").is_dir() {
        Some(Init::Systemd)
    } else if Path::new("/run/openrc").is_dir() || Path::new("/sbin/openrc-run").exists() {
        Some(Init::OpenRc)
    } else {
        None
    }
}

/// Replace `path` atomically if its content differs; returns whether it did.
fn put_file(path: &Path, content: &[u8], mode: u32) -> io::Result<bool> {
    put_file_as(path, content, mode, 0)
}

/// Create the temp file exclusively, never through a symlink. A leftover from
/// an earlier run is removed only when it is a regular file owned by `owner`;
/// anything else at that name is not ours to delete.
fn create_temp(tmp: &Path, mode: u32, owner: u32) -> io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let open = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(tmp)
    };
    match open() {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(tmp)?;
            if !meta.file_type().is_file() || meta.uid() != owner {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "{} exists and is not a regular file owned by root",
                        tmp.display()
                    ),
                ));
            }
            std::fs::remove_file(tmp)?;
            open()
        }
        other => other,
    }
}

fn put_file_as(path: &Path, content: &[u8], mode: u32, owner: u32) -> io::Result<bool> {
    if std::fs::read(path).is_ok_and(|current| current == content) {
        let meta = std::fs::metadata(path)?;
        if meta.permissions().mode() & 0o7777 != mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
        return Ok(false);
    }
    let dir = path.parent().unwrap_or(Path::new("/"));
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    // A temp name that is not ours stays untouched, so only what this call
    // created is cleaned up on failure.
    let mut file = create_temp(&tmp, mode, owner)?;
    let result = (|| {
        file.write_all(content)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map(|()| true)
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// New files get their directory's default type, but restorecon is the
/// only way to be sure the binary is bin_t and the unit systemd_unit_file_t.
fn relabel(paths: &[&str]) {
    if !Path::new("/sys/fs/selinux/enforce").exists() {
        return;
    }
    if let Some(restorecon) = sys::find_program("restorecon") {
        let restorecon = restorecon.to_string_lossy();
        if let Err(e) = run(&restorecon, paths) {
            eprintln!("warning: {e}");
        }
    }
}

/// Whether `unit` runs qemu-ga with the vsock-listen method on `3:100`.
/// Whole arguments are compared, so port `3:1000` does not match.
fn is_legacy_qga_unit(unit: &str) -> bool {
    let arg = |token: &str, value: &str| {
        token == value || token.strip_suffix(value).is_some_and(|p| p.ends_with('='))
    };
    let mut method = false;
    let mut port = false;
    for token in unit.split_whitespace() {
        method |= arg(token, "vsock-listen");
        port |= arg(token, "3:100");
    }
    method && port
}

fn migrate_legacy_qga() -> Result<(), String> {
    let Ok(unit) = std::fs::read_to_string(LEGACY_QGA_UNIT) else {
        return Ok(());
    };
    if !is_legacy_qga_unit(&unit) {
        return Ok(());
    }
    println!(
        "disabling qemu-guest-agent's vsock override (port {}) in favour of this agent",
        crate::server::PORT
    );
    // Disable first, while the override's [Install] section still names the
    // symlink it created.
    let _ = run("systemctl", &["disable", "qemu-guest-agent.service"]);
    let _ = run("systemctl", &["stop", "qemu-guest-agent.service"]);
    let backup = format!("{LEGACY_QGA_UNIT}.bak");
    std::fs::rename(LEGACY_QGA_UNIT, &backup)
        .map_err(|e| format!("cannot move {LEGACY_QGA_UNIT} to {backup}: {e}"))?;
    run("systemctl", &["daemon-reload"])
}

pub fn install() -> Result<(), String> {
    if !sys::is_root() {
        return Err("install must run as root".into());
    }
    let init = detect_init().ok_or(
        "no supported init system found (systemd or OpenRC); run /usr/local/sbin/virtainer-guest-agent under your service manager",
    );
    let me =
        std::fs::read("/proc/self/exe").map_err(|e| format!("cannot read this binary: {e}"))?;
    let binary_changed = put_file(Path::new(BIN_PATH), &me, 0o755)
        .map_err(|e| format!("cannot write {BIN_PATH}: {e}"))?;
    println!(
        "{BIN_PATH}: {}",
        if binary_changed {
            "installed"
        } else {
            "up to date"
        }
    );
    let init = init?;

    match init {
        Init::Systemd => {
            migrate_legacy_qga()?;
            let unit_changed = put_file(Path::new(UNIT_PATH), SYSTEMD_UNIT.as_bytes(), 0o644)
                .map_err(|e| format!("cannot write {UNIT_PATH}: {e}"))?;
            relabel(&[BIN_PATH, UNIT_PATH]);
            if unit_changed {
                run("systemctl", &["daemon-reload"])?;
            }
            run(
                "systemctl",
                &["enable", "--quiet", "virtainer-guest-agent.service"],
            )?;
            let verb = if binary_changed || unit_changed {
                "restart"
            } else {
                "start"
            };
            run(
                "systemctl",
                &[verb, "--no-block", "virtainer-guest-agent.service"],
            )?;
            println!("{SERVICE}.service: enabled, {verb} queued");
        }
        Init::OpenRc => {
            let script_changed = put_file(Path::new(OPENRC_PATH), OPENRC_SCRIPT.as_bytes(), 0o755)
                .map_err(|e| format!("cannot write {OPENRC_PATH}: {e}"))?;
            relabel(&[BIN_PATH, OPENRC_PATH]);
            run("rc-update", &["add", SERVICE, "default"])?;
            let verb = if binary_changed || script_changed {
                "restart"
            } else {
                "start"
            };
            run("rc-service", &[SERVICE, verb])?;
            println!("{SERVICE}: added to the default runlevel, {verb}ed");
        }
    }
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    if !sys::is_root() {
        return Err("uninstall must run as root".into());
    }
    match detect_init() {
        Some(Init::Systemd) => {
            let _ = run(
                "systemctl",
                &["disable", "--now", "virtainer-guest-agent.service"],
            );
            remove(UNIT_PATH)?;
            run("systemctl", &["daemon-reload"])?;
        }
        Some(Init::OpenRc) => {
            let _ = run("rc-service", &[SERVICE, "stop"]);
            let _ = run("rc-update", &["del", SERVICE, "default"]);
            remove(OPENRC_PATH)?;
        }
        None => {}
    }
    remove(BIN_PATH)?;
    let _ = std::fs::remove_dir_all(RUNTIME_DIR);
    println!("virtainer-guest-agent removed");
    Ok(())
}

fn remove(path: &str) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {path}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_file_only_rewrites_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/file");
        assert!(put_file(&path, b"one", 0o755).unwrap());
        assert!(!put_file(&path, b"one", 0o755).unwrap());
        assert!(put_file(&path, b"two", 0o755).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
        // Mode drift is repaired without a rewrite.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!put_file(&path, b"two", 0o755).unwrap());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::read_dir(dir.path().join("sub")).unwrap().count(),
            1
        );
    }

    #[test]
    fn legacy_unit_match_is_exact() {
        let unit = |port: &str| {
            format!("[Service]\nExecStart=/usr/bin/qemu-ga -m vsock-listen -p {port} -t /var/run\n")
        };
        assert!(is_legacy_qga_unit(&unit("3:100")));
        assert!(!is_legacy_qga_unit(&unit("3:1000")));
        assert!(!is_legacy_qga_unit(&unit("13:100")));
        assert!(is_legacy_qga_unit(
            "ExecStart=/usr/bin/qemu-ga --method=vsock-listen --path=3:100\n"
        ));
        assert!(!is_legacy_qga_unit(
            "ExecStart=/usr/bin/qemu-ga -m virtio-serial -p /dev/vport0p1\n"
        ));
    }

    #[test]
    fn temp_file_is_exclusive_and_not_followed() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        let tmp = dir
            .path()
            .join(format!(".target.tmp-{}", std::process::id()));
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        // SAFETY: plain getter.
        let me = unsafe { libc::geteuid() };
        assert!(put_file_as(&path, b"new", 0o644, me).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(!path.exists());
        std::fs::remove_file(&tmp).unwrap();

        // A stale regular file is replaced only when the owner matches.
        std::fs::write(&tmp, b"stale").unwrap();
        assert!(put_file_as(&path, b"new", 0o644, me + 1).is_err());
        assert_eq!(std::fs::read(&tmp).unwrap(), b"stale");
        assert!(put_file_as(&path, b"new", 0o644, me).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&path).unwrap().uid(), me);
    }

    #[test]
    fn service_files_point_at_the_installed_binary() {
        assert!(SYSTEMD_UNIT.contains(&format!("ExecStart={BIN_PATH}\n")));
        assert!(SYSTEMD_UNIT.contains("\nKillMode=process\n"));
        assert!(OPENRC_SCRIPT.contains(&format!("command=\"{BIN_PATH}\"")));
    }
}
