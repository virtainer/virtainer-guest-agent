// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Boot-time replacement from the trusted seed. Live host push is outside MVP.

use super::{binary_path, provision, service};
use crate::windows_support::update as identity;
use std::process::{Command, Stdio};

fn executable(bytes: &[u8]) -> bool {
    if bytes.len() < 64 || &bytes[..2] != b"MZ" {
        return false;
    }
    let at = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    bytes
        .get(at..at.saturating_add(6))
        .is_some_and(|v| v == b"PE\0\0\x64\x86")
}
pub fn stage() -> Result<bool, String> {
    let Some(seed) = provision::discover()? else {
        return Ok(false);
    };
    stage_seed(&seed)
}

pub fn stage_seed(seed: &provision::Seed) -> Result<bool, String> {
    let bytes = seed
        .fat
        .file("virtainer-guest-agent.exe")
        .map_err(|_| "cannot read agent executable from seed".to_string())?
        .ok_or_else(|| "seed is missing virtainer-guest-agent.exe".to_string())?;
    if !executable(&bytes) {
        return Err("seed executable is not an amd64 PE image".into());
    }
    let current = std::fs::read(binary_path()).map_err(|e| e.to_string())?;
    if current == bytes {
        return Ok(false);
    }
    seed.stable()?;
    let checkpoint =
        identity::checkpoint(&seed.config.instance_id, &seed.config.seed_version, &bytes)?;
    if identity::suppressed(identity::load(&checkpoint_path())?.as_deref(), &checkpoint)? {
        return Ok(false);
    }
    // Persist before launching: a helper crash or an early initialization
    // failure must also leave this input suppressed on the next service boot.
    suppress(&checkpoint)?;
    // A previous helper may still have updater.exe mapped. A sharing violation
    // leaves the installed service running and the failed input suppressed.
    identity::stage_helper(
        &binary_path(),
        &current,
        &bytes,
        provision::atomic_write,
        |helper| {
            Command::new(helper)
                .arg("update")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map(|_| ())
                .map_err(|e| format!("cannot launch update helper: {e}"))
        },
    )?;
    Ok(true)
}
pub fn finish() -> Result<(), String> {
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    if source != binary_path().with_extension("updater.exe") {
        return Err("update must run from the installed version's updater".into());
    }
    let bytes =
        std::fs::read(binary_path().with_extension("next.exe")).map_err(|e| e.to_string())?;
    if !executable(&bytes) {
        return Err("staged executable is not an amd64 PE image".into());
    }
    let checkpoint = identity::load(&checkpoint_path())?
        .ok_or_else(|| "update helper has no persisted input checkpoint".to_string())?;
    if identity::executable(&checkpoint)? != bytes {
        return Err("staged executable does not match update checkpoint".into());
    }
    service::finish_update(&bytes, &checkpoint)?;
    // Do not erase a different attempt if input changed during startup.
    if identity::load(&checkpoint_path())?.as_deref() == Some(checkpoint.as_slice()) {
        clear()?;
    }
    Ok(())
}
fn checkpoint_path() -> std::path::PathBuf {
    super::data_dir().join("failed-update")
}
pub fn suppress(checkpoint: &[u8]) -> Result<(), String> {
    identity::executable(checkpoint)?;
    provision::atomic_write(&checkpoint_path(), checkpoint)
}
pub fn clear() -> Result<(), String> {
    match std::fs::remove_file(checkpoint_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
