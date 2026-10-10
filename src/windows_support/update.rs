// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Exact executable/seed identities for crash-safe update suppression.
//! Store executable bytes rather than adding a hashing dependency.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

const MAGIC: &[u8; 8] = b"VGAUPD1\0";
const EXE_LIMIT: usize = 64 << 20;
const HEADER_LIMIT: usize = 4096;
const RECORD_LIMIT: usize = EXE_LIMIT + HEADER_LIMIT + 12;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    instance_id: String,
    seed_version: String,
    executable_len: usize,
}
fn valid(identity: &Identity) -> bool {
    super::provision::uuid(&identity.instance_id)
        && identity.seed_version.len() == 64
        && identity.seed_version.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn checkpoint(
    instance_id: &str,
    seed_version: &str,
    executable: &[u8],
) -> Result<Vec<u8>, String> {
    let identity = Identity {
        instance_id: instance_id.into(),
        seed_version: seed_version.into(),
        executable_len: executable.len(),
    };
    if !valid(&identity) || executable.is_empty() || executable.len() > EXE_LIMIT {
        return Err("invalid update input identity".into());
    }
    let header = serde_json::to_vec(&identity).map_err(|_| "cannot encode update identity")?;
    let mut result = Vec::with_capacity(12 + header.len() + executable.len());
    result.extend_from_slice(MAGIC);
    result.extend_from_slice(&(header.len() as u32).to_le_bytes());
    result.extend_from_slice(&header);
    result.extend_from_slice(executable);
    Ok(result)
}

pub fn executable(record: &[u8]) -> Result<&[u8], String> {
    let invalid = || "invalid persisted update checkpoint".to_string();
    if record.len() < 12 || record.len() > RECORD_LIMIT || &record[..8] != MAGIC {
        return Err(invalid());
    }
    let header_len = u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize;
    if header_len > HEADER_LIMIT || 12 + header_len >= record.len() {
        return Err(invalid());
    }
    let identity: Identity =
        serde_json::from_slice(&record[12..12 + header_len]).map_err(|_| invalid())?;
    let bytes = &record[12 + header_len..];
    if !valid(&identity) || bytes.len() > EXE_LIMIT || bytes.len() != identity.executable_len {
        return Err(invalid());
    }
    Ok(bytes)
}

pub fn suppressed(previous: Option<&[u8]>, candidate: &[u8]) -> Result<bool, String> {
    executable(candidate)?;
    if let Some(previous) = previous {
        executable(previous)?;
        Ok(previous == candidate)
    } else {
        Ok(false)
    }
}

pub fn load(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot read update checkpoint".into()),
    };
    let mut record = Vec::new();
    file.take(RECORD_LIMIT as u64 + 1)
        .read_to_end(&mut record)
        .map_err(|_| "cannot read update checkpoint")?;
    executable(&record)?;
    Ok(Some(record))
}

/// Run the installed version's updater with the replacement kept as data.
pub fn stage_helper(
    installed: &Path,
    current: &[u8],
    replacement: &[u8],
    mut write: impl FnMut(&Path, &[u8]) -> Result<(), String>,
    launch: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    write(&installed.with_extension("next.exe"), replacement)?;
    let helper = installed.with_extension("updater.exe");
    write(&helper, current)?;
    launch(&helper)
}

/// Copy the installed executable without removing the SCM startup path.
pub fn retain_previous(
    installed: &Path,
    write: impl FnOnce(&Path, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    let current = std::fs::read(installed).map_err(|e| e.to_string())?;
    write(&installed.with_extension("previous.exe"), &current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    const INSTANCE: &str = "00000000-0000-4000-8000-000000000001";

    #[cfg(unix)]
    #[test]
    fn installed_updater_runs_when_replacement_exits_during_initialization() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("agent.exe");
        let current = b"#!/bin/sh\n[ \"$1\" = update ] || exit 88\nprintf ready > \"${0%.updater.exe}.started\"\n";
        let replacement = b"#!/bin/sh\nexit 99\n";
        std::fs::write(&installed, current).unwrap();
        stage_helper(
            &installed,
            current,
            replacement,
            |path, bytes| std::fs::write(path, bytes).map_err(|e| e.to_string()),
            |helper| {
                assert_eq!(helper, installed.with_extension("updater.exe"));
                std::fs::set_permissions(helper, std::fs::Permissions::from_mode(0o700)).unwrap();
                assert!(Command::new(helper)
                    .arg("update")
                    .status()
                    .unwrap()
                    .success());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(installed.with_extension("started")).unwrap(),
            b"ready"
        );
        assert_eq!(std::fs::read(&installed).unwrap(), current);
        let staged = installed.with_extension("next.exe");
        assert_eq!(std::fs::read(&staged).unwrap(), replacement);
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(Command::new(staged).status().unwrap().code(), Some(99));
    }

    #[test]
    fn staging_and_launch_failures_leave_the_installed_executable_present() {
        for failed_step in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let installed = dir.path().join("agent.exe");
            std::fs::write(&installed, b"working executable").unwrap();
            let step = Cell::new(0);
            let result = stage_helper(
                &installed,
                b"working executable",
                b"replacement",
                |path, bytes| {
                    let current_step = step.get();
                    step.set(current_step + 1);
                    if failed_step == current_step {
                        return Err("write failed".into());
                    }
                    std::fs::write(path, bytes).map_err(|e| e.to_string())
                },
                |_| {
                    assert_eq!(step.get(), 2);
                    step.set(3);
                    Err("launch failed".into())
                },
            );
            assert!(result.is_err());
            assert_eq!(step.get(), failed_step + 1);
            assert_eq!(std::fs::read(&installed).unwrap(), b"working executable");
        }
    }

    #[test]
    fn interrupted_update_after_backup_keeps_the_service_executable_available() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("agent.exe");
        let backup = installed.with_extension("previous.exe");
        std::fs::write(&installed, b"working executable").unwrap();
        std::fs::write(&backup, b"older executable").unwrap();
        retain_previous(&installed, |path, bytes| {
            assert_eq!(path, backup);
            assert_eq!(std::fs::read(&installed).unwrap(), b"working executable");
            std::fs::write(path, bytes).map_err(|e| e.to_string())
        })
        .unwrap();
        // No activation occurs: the installed path must still boot the old service.
        assert_eq!(std::fs::read(&installed).unwrap(), b"working executable");
        assert_eq!(std::fs::read(&backup).unwrap(), b"working executable");
    }

    #[test]
    fn failed_backup_copy_keeps_the_installed_executable_and_existing_backup() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("agent.exe");
        let backup = installed.with_extension("previous.exe");
        std::fs::write(&installed, b"working executable").unwrap();
        std::fs::write(&backup, b"older executable").unwrap();
        assert!(retain_previous(&installed, |_, _| Err("disk full".into())).is_err());
        assert_eq!(std::fs::read(&installed).unwrap(), b"working executable");
        assert_eq!(std::fs::read(&backup).unwrap(), b"older executable");
    }

    #[test]
    fn failed_input_stays_suppressed_across_restarts_until_input_changes_or_explicit_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("failed-update");
        let candidate = checkpoint(INSTANCE, &"a".repeat(64), b"replacement").unwrap();
        assert!(!suppressed(load(&path).unwrap().as_deref(), &candidate).unwrap());
        std::fs::write(&path, &candidate).unwrap();
        for _ in 0..3 {
            assert!(suppressed(load(&path).unwrap().as_deref(), &candidate).unwrap());
        }
        for changed in [
            checkpoint(INSTANCE, &"b".repeat(64), b"replacement").unwrap(),
            checkpoint(INSTANCE, &"a".repeat(64), b"different executable").unwrap(),
            checkpoint(
                "00000000-0000-4000-8000-000000000002",
                &"a".repeat(64),
                b"replacement",
            )
            .unwrap(),
        ] {
            assert!(!suppressed(load(&path).unwrap().as_deref(), &changed).unwrap());
        }
        std::fs::remove_file(&path).unwrap();
        assert!(!suppressed(load(&path).unwrap().as_deref(), &candidate).unwrap());
    }

    #[test]
    fn corrupt_checkpoints_fail_closed_and_cannot_hide_a_staged_binary_mismatch() {
        let record = checkpoint(INSTANCE, &"a".repeat(64), b"replacement").unwrap();
        assert_eq!(executable(&record).unwrap(), b"replacement");
        for len in 0..record.len() {
            assert!(suppressed(Some(&record[..len]), &record).is_err());
        }
        let mut corrupt = record.clone();
        corrupt[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(suppressed(Some(&corrupt), &record).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("failed-update");
        std::fs::write(&path, corrupt).unwrap();
        assert!(load(&path).is_err());
        assert!(checkpoint(INSTANCE, &"a".repeat(64), b"").is_err());
        assert!(checkpoint("bad", &"a".repeat(64), b"replacement").is_err());
    }
}
