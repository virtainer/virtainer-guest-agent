// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Windows file, pipe and built-in PowerShell helpers.

use crate::qmp::QgaError;
use crate::windows::api;
use base64::Engine;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn strerror(e: &io::Error) -> String {
    e.to_string()
}
pub fn random_u32() -> u32 {
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(algorithm: api::Handle, buffer: *mut u8, size: u32, flags: u32) -> i32;
    }
    let mut bytes = [0u8; 4];
    // SAFETY: valid four-byte output buffer; system-preferred RNG has no algorithm handle.
    let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), bytes.as_mut_ptr(), 4, 2) };
    if status >= 0 {
        u32::from_ne_bytes(bytes)
    } else {
        std::process::id()
    }
}
pub fn pipe_ready(pipe: api::Handle) -> io::Result<bool> {
    api::pipe_ready(pipe)
}
pub fn system_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
}
pub fn powershell() -> Command {
    let mut command = Command::new(system_dir().join("WindowsPowerShell/v1.0/powershell.exe"));
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
    ]);
    command
}
pub fn open_file(path: &str, mode: &str) -> Result<File, QgaError> {
    let (read, write, create, truncate, append) = match mode {
        "r" | "rb" => (true, false, false, false, false),
        "r+" | "rb+" | "r+b" => (true, true, false, false, false),
        "w" | "wb" => (false, true, true, true, false),
        "w+" | "wb+" | "w+b" => (true, true, true, true, false),
        "a" | "ab" => (false, true, true, false, true),
        "a+" | "ab+" | "a+b" => (true, true, true, false, true),
        _ => {
            return Err(QgaError::generic(format!(
                "invalid file open mode '{mode}'"
            )))
        }
    };
    let open = (|| {
        let mut options = OpenOptions::new();
        options
            .read(read)
            .write(write && !append)
            .append(append)
            .create(create);
        if write {
            options.custom_flags(0x00200000);
        } // FILE_FLAG_OPEN_REPARSE_POINT
        let file = options.open(path)?;
        // Check the opened object before truncating, avoiding a path-check race.
        if write && file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "write through reparse point refused",
            ));
        }
        if truncate {
            file.set_len(0)?;
        }
        Ok(file)
    })();
    open.map_err(|e: io::Error| {
        QgaError::os(format!("failed to open file '{path}' (mode: '{mode}')"), &e)
    })
}

/// Execute fixed helper code with data on stdin, never in argv. Stderr is
/// discarded. A failing helper reports one marker line on stdout (error
/// category, id and message); the agent keeps it only after scrubbing `secrets`
/// and bounding its length. Query output is bounded and pipes are drained with
/// the same finite grace as exec.
pub fn ps(
    code: &str,
    input: &serde_json::Value,
    action: &str,
    secrets: &[&str],
) -> Result<Vec<u8>, String> {
    let code = crate::windows_support::helper::wrap(code);
    let bytes: Vec<u8> = code.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut command = powershell();
    command.args([
        "-EncodedCommand",
        &base64::engine::general_purpose::STANDARD.encode(bytes),
    ]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| format!("{action}: cannot start PowerShell"))?;
    let mut stdin = child.stdin.take().unwrap();
    let input = serde_json::to_vec(input).map_err(|_| format!("{action}: cannot encode input"))?;
    if stdin.write_all(&input).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("{action}: cannot write input"));
    }
    drop(stdin);
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut read_thread = Some(std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match api::pipe_ready(std::os::windows::io::AsRawHandle::as_raw_handle(&stdout)) {
                Ok(false) => {
                    if rx.try_recv().is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(_) => break,
                Ok(true) => {}
            }
            match stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => out
                    .extend_from_slice(&chunk[..n.min((1_usize << 20).saturating_sub(out.len()))]),
                Err(_) => break,
            }
        }
        out
    }));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Err(_) => break Err(format!("{action}: cannot wait for PowerShell")),
            Ok(None) => {}
        }
        if crate::windows::service::stopping() || started.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            break Err(format!("{action}: stopped or timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = tx.send(());
    let out = read_thread.take().unwrap().join().unwrap_or_default();
    let status = status?;
    if status.success() {
        Ok(out)
    } else {
        let status = status.code().unwrap_or(-1);
        Err(
            match crate::windows_support::helper::failure_detail(&out, secrets) {
                Some(detail) => format!("{action}: {detail}"),
                None => format!("{action}: exit status {status}"),
            },
        )
    }
}
pub fn protect_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    if std::fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .file_attributes()
        & 0x400
        != 0
    {
        return Err("private directory is a reparse point".into());
    }
    // Install an exact protected DACL rather than retaining explicit grants
    // left on an existing directory. SIDs work on localized installations.
    api::private_directory(path).map_err(|_| "cannot secure private directory ACL".into())
}

/// Serialize specialize and service provisioning across processes. Windows
/// share denial lasts only for the handle lifetime, so a crash releases it.
pub fn provision_lock(path: &Path) -> Result<File, String> {
    let started = Instant::now();
    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .custom_flags(0x00200000)
            .open(path)
        {
            Ok(file) => {
                if file
                    .metadata()
                    .map_err(|e| e.to_string())?
                    .file_attributes()
                    & 0x400
                    != 0
                {
                    return Err("provision lock is a reparse point".into());
                }
                return Ok(file);
            }
            Err(e)
                if e.raw_os_error() == Some(32) && started.elapsed() < Duration::from_secs(120) =>
            {
                if crate::windows::service::stopping() {
                    return Err("stopped while waiting for provision lock".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return Err("cannot acquire exclusive provision lock".into()),
        }
    }
}
