// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `/etc/virtainer-guest-agent.conf`: `key = value` lines, `#` comments.
//!
//! The file is optional. A file that cannot be parsed stops the agent rather
//! than being half-applied: a typo in `block-rpcs` must not silently re-enable
//! a command the guest owner meant to switch off.

use std::path::{Path, PathBuf};
use std::time::Duration;

pub const PATH: &str = "/etc/virtainer-guest-agent.conf";

/// qemu-ga's hook locations (RHEL family, then upstream/Debian), so database
/// hooks written for qemu-ga keep running when this agent freezes.
pub const QEMU_GA_HOOKS: &[&str] = &["/etc/qemu-ga/fsfreeze-hook", "/etc/qemu/fsfreeze-hook"];

/// Long enough that no legitimate snapshot window reaches it (Virtainer's
/// longest window is a few minutes), short enough that a guest whose host
/// vanished mid-snapshot recovers on its own.
pub const DEFAULT_FREEZE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsfreezeHook {
    /// The first executable of [`QEMU_GA_HOOKS`], looked up at each freeze.
    QemuGaDefault,
    Path(PathBuf),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub block_rpcs: Vec<String>,
    pub allow_rpcs: Option<Vec<String>>,
    pub fsfreeze_hook: FsfreezeHook,
    /// `None`: never thaw on our own.
    pub freeze_timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            block_rpcs: Vec::new(),
            allow_rpcs: None,
            fsfreeze_hook: FsfreezeHook::QemuGaDefault,
            freeze_timeout: Some(DEFAULT_FREEZE_TIMEOUT),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                // Refused rather than warned about: the file decides which
                // root-run hook executes, and the agent already stops on a
                // config it cannot trust to be what the owner wrote.
                check_trusted(path)?;
                parse(&text).map_err(|e| format!("{}: {e}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    pub fn hook_path(&self) -> Option<PathBuf> {
        match &self.fsfreeze_hook {
            FsfreezeHook::Disabled => None,
            FsfreezeHook::Path(path) => Some(path.clone()),
            FsfreezeHook::QemuGaDefault => QEMU_GA_HOOKS
                .iter()
                .map(PathBuf::from)
                .find(|p| crate::sys::is_executable(p)),
        }
    }
}

/// Owner of config and hook files that this agent will trust. Tests run
/// unprivileged and own their fixtures.
fn trusted_owner() -> u32 {
    if cfg!(test) {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    } else {
        0
    }
}

/// The config and the fsfreeze hook are read or executed as root, so each must
/// be owned by root and not writable by group or others.
pub fn check_trusted(path: &Path) -> Result<(), String> {
    check_trusted_as(path, trusted_owner())
}

fn check_trusted_as(path: &Path, owner: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta =
        std::fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if meta.uid() != owner {
        return Err(format!(
            "{} must be owned by root (owner uid {})",
            path.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} must not be writable by group or others (mode {:04o})",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

fn parse(text: &str) -> Result<Config, String> {
    let mut config = Config::default();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |msg: String| format!("line {}: {msg}", index + 1);
        let Some((key, value)) = line.split_once('=') else {
            return Err(at(format!("expected 'key = value', got '{line}'")));
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "block-rpcs" => config.block_rpcs = list(value),
            "allow-rpcs" => config.allow_rpcs = Some(list(value)),
            "fsfreeze-hook" => {
                config.fsfreeze_hook = if value.is_empty() {
                    FsfreezeHook::Disabled
                } else if value.starts_with('/') {
                    FsfreezeHook::Path(PathBuf::from(value))
                } else {
                    return Err(at(format!(
                        "fsfreeze-hook must be an absolute path, got '{value}'"
                    )));
                }
            }
            "freeze-timeout" => {
                let secs: u64 = value.parse().map_err(|_| {
                    at(format!(
                        "freeze-timeout must be whole seconds, got '{value}'"
                    ))
                })?;
                config.freeze_timeout = (secs > 0).then(|| Duration::from_secs(secs));
            }
            other => return Err(at(format!("unknown key '{other}'"))),
        }
    }
    Ok(config)
}

fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_files_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conf");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        // SAFETY: plain getter.
        let me = unsafe { libc::geteuid() };
        assert!(check_trusted_as(&path, me).is_ok());
        assert!(Config::load(&path).is_ok());
        assert!(check_trusted_as(&path, me + 1)
            .unwrap_err()
            .contains("must be owned by root"));
        for mode in [0o664, 0o646] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(check_trusted_as(&path, me)
                .unwrap_err()
                .contains("must not be writable"));
            assert!(Config::load(&path).is_err());
        }
    }

    #[test]
    fn empty_file_is_the_default() {
        assert_eq!(parse("# nothing\n\n").unwrap(), Config::default());
    }

    #[test]
    fn every_key_parses() {
        let config = parse(
            "block-rpcs = guest-exec, guest-file-open\n\
             allow-rpcs=guest-ping\n\
             fsfreeze-hook = /usr/local/bin/hook\n\
             freeze-timeout = 0\n",
        )
        .unwrap();
        assert_eq!(config.block_rpcs, vec!["guest-exec", "guest-file-open"]);
        assert_eq!(config.allow_rpcs, Some(vec!["guest-ping".to_string()]));
        assert_eq!(
            config.fsfreeze_hook,
            FsfreezeHook::Path("/usr/local/bin/hook".into())
        );
        assert_eq!(config.freeze_timeout, None);
        assert_eq!(
            parse("fsfreeze-hook =").unwrap().fsfreeze_hook,
            FsfreezeHook::Disabled
        );
    }

    #[test]
    fn mistakes_are_rejected_not_ignored() {
        assert!(parse("block-rpc = guest-exec")
            .unwrap_err()
            .contains("unknown key"));
        assert!(parse("freeze-timeout = 5m").is_err());
        assert!(parse("fsfreeze-hook = hook").is_err());
        assert!(parse("just words").unwrap_err().starts_with("line 1:"));
    }
}
