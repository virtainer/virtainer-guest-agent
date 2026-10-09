// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! The Windows MVP command surface, independent of Windows syscalls.

pub const SUPPORTED: &[&str] = &[
    "guest-sync-delimited",
    "guest-sync",
    "guest-ping",
    "guest-info",
    "guest-get-osinfo",
    "guest-get-host-name",
    "guest-get-time",
    "guest-set-time",
    "guest-shutdown",
    "guest-network-get-interfaces",
    "guest-exec",
    "guest-exec-status",
    "guest-file-open",
    "guest-file-close",
    "guest-file-read",
    "guest-file-write",
    "guest-file-seek",
    "guest-file-flush",
    "guest-set-user-password",
    "__io.virtainer_provision",
];
pub const UNSUPPORTED: &[&str] = &[
    "guest-fsfreeze-status",
    "guest-fsfreeze-freeze",
    "guest-fsfreeze-freeze-list",
    "guest-fsfreeze-thaw",
    "guest-fstrim",
    "guest-get-fsinfo",
    "guest-get-disks",
    "guest-get-timezone",
    "guest-get-users",
    "guest-network-get-route",
    "guest-ssh-get-authorized-keys",
    "guest-ssh-add-authorized-keys",
    "guest-ssh-remove-authorized-keys",
    "guest-get-vcpus",
    "guest-set-vcpus",
    "guest-get-memory-blocks",
    "guest-set-memory-blocks",
    "guest-get-memory-block-info",
    "guest-get-load",
    "guest-get-cpustats",
    "guest-get-diskstats",
    "guest-suspend-disk",
    "guest-suspend-ram",
    "guest-suspend-hybrid",
    "guest-get-devices",
    "__io.virtainer_shell",
];
pub fn unsupported(name: &str) -> crate::qmp::QgaError {
    crate::qmp::QgaError::generic(format!("Command {name} is not supported"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn table_is_unique_and_required_commands_are_supported() {
        let mut names = std::collections::HashSet::new();
        for name in SUPPORTED.iter().chain(UNSUPPORTED) {
            assert!(names.insert(name), "{name}");
        }
        assert!(SUPPORTED.contains(&"__io.virtainer_provision"));
        assert!(SUPPORTED.contains(&"guest-shutdown"));
        assert!(UNSUPPORTED.contains(&"guest-fsfreeze-freeze"));
        assert!(UNSUPPORTED.contains(&"__io.virtainer_shell"));
        assert_eq!(
            unsupported("guest-fstrim").to_json(),
            serde_json::json!({"class":"GenericError","desc":"Command guest-fstrim is not supported"})
        );
    }
}
