// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `guest-file-*`: handle-based file access for the host.
//!
//! Handles are unbuffered file descriptors, so `guest-file-flush` has nothing
//! to push and the read/write switching dance qemu-ga does around stdio
//! buffers is not needed. Files are opened non-blocking (a FIFO must not hang
//! the agent) and close-on-exec (guest-exec children must not inherit them).
//!
//! One deliberate difference from qemu-ga: a created file gets mode 0644, not
//! 0666. qemu-ga makes every file it creates world-writable regardless of
//! umask; a root-owned file pushed by the host should not be writable by every
//! guest user.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::Engine;
use serde_json::{json, Value};

use super::Ctx;
use crate::qmp::{enum_value, type_error, Args, QgaError, Reply};
use crate::sys;

/// qemu-ga's limit: 48 MiB plus base64 overhead stays under the 64 MiB JSON
/// message limit.
pub const READ_COUNT_MAX: i64 = 48 << 20;
const READ_COUNT_DEFAULT: i64 = 4096;
/// Open handles share RLIMIT_NOFILE with exec pipes; stay well below a
/// 1024 soft limit.
const MAX_OPEN_FILES: usize = 256;
const NEW_FILE_MODE: libc::mode_t = 0o644;

pub struct FileTable {
    inner: Mutex<Inner>,
}

struct Inner {
    next: i64,
    open: HashMap<i64, Arc<Mutex<File>>>,
}

impl Default for FileTable {
    fn default() -> Self {
        // A random start makes a handle from before an agent restart unlikely
        // to name a different file now.
        Self {
            inner: Mutex::new(Inner {
                next: 1000 + i64::from(sys::random_u32()),
                open: HashMap::new(),
            }),
        }
    }
}

impl FileTable {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn insert(&self, file: File) -> Result<i64, QgaError> {
        let mut inner = self.lock();
        if inner.open.len() >= MAX_OPEN_FILES {
            return Err(QgaError::generic("too many open file handles"));
        }
        let handle = inner.next;
        inner.next += 1;
        inner.open.insert(handle, Arc::new(Mutex::new(file)));
        Ok(handle)
    }

    fn get(&self, handle: i64) -> Result<Arc<Mutex<File>>, QgaError> {
        self.lock()
            .open
            .get(&handle)
            .cloned()
            .ok_or_else(|| not_found(handle))
    }

    fn remove(&self, handle: i64) -> Result<Arc<Mutex<File>>, QgaError> {
        self.lock()
            .open
            .remove(&handle)
            .ok_or_else(|| not_found(handle))
    }
}

fn not_found(handle: i64) -> QgaError {
    QgaError::generic(format!("handle '{handle}' has not been found"))
}

/// fopen(3) modes, as qemu-ga accepts them.
fn open_flags(mode: &str) -> Option<i32> {
    use libc::{O_APPEND, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY};
    let flags = match mode {
        "r" | "rb" => O_RDONLY,
        "w" | "wb" => O_WRONLY | O_CREAT | O_TRUNC,
        "a" | "ab" => O_WRONLY | O_CREAT | O_APPEND,
        "r+" | "rb+" | "r+b" => O_RDWR,
        "w+" | "wb+" | "w+b" => O_RDWR | O_CREAT | O_TRUNC,
        "a+" | "ab+" | "a+b" => O_RDWR | O_CREAT | O_APPEND,
        _ => return None,
    };
    Some(flags | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
}

fn open_path(path: &CString, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: path is NUL-terminated; open returns a new fd or -1.
    let fd = unsafe { libc::open(path.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        Err(sys::last_error())
    } else {
        // SAFETY: fd was just opened and is owned by nobody else.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// Create exclusively first so the mode can be set regardless of umask; an
/// existing file is opened as is and keeps its mode. The fallback does not
/// follow a symlink: a guest user could otherwise plant one at a predictable
/// path and have a root-owned open truncate or append to its target.
fn open_or_create(path: &str, flags: i32) -> io::Result<File> {
    let c_path = sys::cstring(Path::new(path))?;
    if flags & libc::O_CREAT == 0 {
        return open_path(&c_path, flags, 0);
    }
    match open_path(&c_path, flags | libc::O_EXCL, NEW_FILE_MODE) {
        Ok(file) => {
            use std::os::fd::AsRawFd;
            // SAFETY: the fd is valid for the lifetime of file.
            if unsafe { libc::fchmod(file.as_raw_fd(), NEW_FILE_MODE) } != 0 {
                let err = sys::last_error();
                drop(file);
                let _ = std::fs::remove_file(path);
                return Err(err);
            }
            Ok(file)
        }
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            open_path(&c_path, (flags & !libc::O_CREAT) | libc::O_NOFOLLOW, 0)
        }
        Err(e) => Err(e),
    }
}

pub fn open(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let path = args.str("path")?;
    let mode = args.opt_str("mode")?.unwrap_or_else(|| "r".into());
    args.finish()?;
    let flags = open_flags(&mode)
        .ok_or_else(|| QgaError::generic(format!("invalid file open mode '{mode}'")))?;
    crate::info!("guest-file-open called, filepath: {path}, mode: {mode}");
    let file = open_or_create(&path, flags)
        .map_err(|e| QgaError::os(format!("failed to open file '{path}' (mode: '{mode}')"), &e))?;
    let handle = ctx.agent.files.insert(file)?;
    Ok(json!(handle))
}

pub fn close(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let handle = args.int("handle")?;
    args.finish()?;
    let file = ctx.agent.files.remove(handle)?;
    // Another connection may still be mid-read on this handle; it finishes
    // with its own reference and the fd closes when the last one drops.
    if let Some(file) = Arc::into_inner(file) {
        let fd = file
            .into_inner()
            .unwrap_or_else(|p| p.into_inner())
            .into_raw_fd();
        // SAFETY: fd came from into_raw_fd and is closed exactly once.
        if unsafe { libc::close(fd) } != 0 {
            return Err(QgaError::os("failed to close handle", &sys::last_error()));
        }
    }
    Ok(json!({}))
}

pub fn read(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let handle = args.int("handle")?;
    let count = args.opt_int("count")?;
    args.finish()?;
    let file = ctx.agent.files.get(handle)?;
    let count = match count {
        None => READ_COUNT_DEFAULT,
        Some(c) if (0..=READ_COUNT_MAX).contains(&c) => c,
        Some(c) => {
            return Err(QgaError::generic(format!(
                "value '{c}' is invalid for argument count"
            )))
        }
    };
    let mut file = file.lock().unwrap_or_else(|p| p.into_inner());
    let mut data = Vec::new();
    data.try_reserve_exact(count as usize)
        .map_err(|_| QgaError::generic("failed to allocate the read buffer"))?;
    data.resize(count as usize, 0);
    let mut filled = 0;
    let mut eof = false;
    while filled < data.len() {
        match file.read(&mut data[filled..]) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // Non-blocking FIFO with nothing more to give.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if filled > 0 => {
                crate::warning!("guest-file-read: short read on handle {handle}: {e}");
                break;
            }
            Err(e) => return Err(QgaError::os("failed to read file", &e)),
        }
    }
    data.truncate(filled);
    Ok(json!({
        "count": filled,
        "buf-b64": base64::engine::general_purpose::STANDARD.encode(&data),
        "eof": eof,
    }))
}

/// Base64 as glib decodes it: padding optional, no other leniency.
pub fn decode_base64(data: &str) -> Result<Vec<u8>, QgaError> {
    use base64::engine::{
        general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig,
    };
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    ENGINE
        .decode(data)
        .map_err(|_| QgaError::generic("Base64 data is not valid"))
}

pub fn write(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let handle = args.int("handle")?;
    let buf = args.str("buf-b64")?;
    let count = args.opt_int("count")?;
    args.finish()?;
    let file = ctx.agent.files.get(handle)?;
    let data = decode_base64(&buf)?;
    let count = match count {
        None => data.len(),
        Some(c) if c >= 0 && (c as usize) <= data.len() => c as usize,
        Some(c) => {
            return Err(QgaError::generic(format!(
                "value '{c}' is invalid for argument count"
            )))
        }
    };
    let mut file = file.lock().unwrap_or_else(|p| p.into_inner());
    let mut written = 0;
    while written < count {
        match file.write(&data[written..count]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(QgaError::os("failed to write to file", &e)),
        }
    }
    Ok(json!({ "count": written, "eof": false }))
}

pub fn seek(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let handle = args.int("handle")?;
    let offset = args.int("offset")?;
    let (whence, name) = args.opt_raw("whence");
    let whence = match whence {
        None => return Err(QgaError::generic(format!("Parameter '{name}' is missing"))),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(code) => code,
            None => return Err(type_error(&name, "integer")),
        },
        Some(Value::String(s)) => match enum_value(&s, &name, &["set", "cur", "end"])? {
            "set" => 0,
            "cur" => 1,
            _ => 2,
        },
        Some(_) => return Err(type_error(&name, "GuestFileWhence")),
    };
    args.finish()?;
    let file = ctx.agent.files.get(handle)?;
    let target = match whence {
        0 => SeekFrom::Start(offset as u64),
        1 => SeekFrom::Current(offset),
        2 => SeekFrom::End(offset),
        other => return Err(QgaError::generic(format!("invalid whence code {other}"))),
    };
    if whence == 0 && offset < 0 {
        return Err(QgaError::os(
            "failed to seek file",
            &io::Error::from_raw_os_error(libc::EINVAL),
        ));
    }
    let mut file = file.lock().unwrap_or_else(|p| p.into_inner());
    let position = file
        .seek(target)
        .map_err(|e| QgaError::os("failed to seek file", &e))?;
    Ok(json!({ "position": position, "eof": false }))
}

pub fn flush(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let handle = args.int("handle")?;
    args.finish()?;
    ctx.agent.files.get(handle)?;
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::config::Config;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        agent: Agent,
        _dir: tempfile::TempDir,
        root: std::path::PathBuf,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        Fixture {
            agent: Agent::new(Config::default(), root.join("run")),
            _dir: dir,
            root,
        }
    }

    fn call(agent: &Agent, f: fn(&mut Ctx<'_>, Args) -> Reply, args: Value) -> Reply {
        let mut ctx = Ctx::new(agent);
        let Value::Object(map) = args else { panic!() };
        f(&mut ctx, Args::new(map))
    }

    #[test]
    fn write_seek_read_round_trip() {
        let f = fixture();
        let path = f.root.join("hello.txt");
        let handle = call(
            &f.agent,
            open,
            json!({"path": path.to_str().unwrap(), "mode": "w+"}),
        )
        .unwrap();
        let reply = call(
            &f.agent,
            write,
            json!({"handle": handle, "buf-b64": "aGVsbG8gd29ybGQ="}),
        )
        .unwrap();
        assert_eq!(reply, json!({"count": 11, "eof": false}));
        let reply = call(
            &f.agent,
            seek,
            json!({"handle": handle, "offset": 6, "whence": "set"}),
        )
        .unwrap();
        assert_eq!(reply, json!({"position": 6, "eof": false}));
        let reply = call(&f.agent, read, json!({"handle": handle, "count": 100})).unwrap();
        assert_eq!(
            reply,
            json!({"count": 5, "buf-b64": "d29ybGQ=", "eof": true})
        );
        call(&f.agent, close, json!({"handle": handle})).unwrap();
        assert_eq!(
            call(&f.agent, read, json!({"handle": handle}))
                .unwrap_err()
                .desc,
            format!("handle '{handle}' has not been found")
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn numeric_whence_and_errors() {
        let f = fixture();
        let path = f.root.join("x");
        std::fs::write(&path, b"abc").unwrap();
        let handle = call(&f.agent, open, json!({"path": path.to_str().unwrap()})).unwrap();
        let reply = call(
            &f.agent,
            seek,
            json!({"handle": handle, "offset": -1, "whence": 2}),
        )
        .unwrap();
        assert_eq!(reply["position"], json!(2));
        assert_eq!(
            call(
                &f.agent,
                seek,
                json!({"handle": handle, "offset": 0, "whence": 7})
            )
            .unwrap_err()
            .desc,
            "invalid whence code 7"
        );
        assert_eq!(
            call(
                &f.agent,
                seek,
                json!({"handle": handle, "offset": 0, "whence": "middle"})
            )
            .unwrap_err()
            .desc,
            "Parameter 'whence' does not accept value 'middle'"
        );
        assert_eq!(
            call(&f.agent, read, json!({"handle": handle, "count": -1}))
                .unwrap_err()
                .desc,
            "value '-1' is invalid for argument count"
        );
    }

    #[test]
    fn open_errors_name_the_file_and_mode() {
        let f = fixture();
        let missing = f.root.join("missing");
        let err = call(&f.agent, open, json!({"path": missing.to_str().unwrap()})).unwrap_err();
        assert_eq!(
            err.desc,
            format!(
                "failed to open file '{}' (mode: 'r'): No such file or directory",
                missing.display()
            )
        );
        let err = call(&f.agent, open, json!({"path": "/x", "mode": "rw"})).unwrap_err();
        assert_eq!(err.desc, "invalid file open mode 'rw'");
    }

    #[test]
    fn creating_modes_do_not_follow_a_planted_symlink() {
        let f = fixture();
        let target = f.root.join("precious");
        std::fs::write(&target, b"secret").unwrap();
        let link = f.root.join("planted");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        for mode in ["w", "a", "w+", "a+"] {
            let err = call(
                &f.agent,
                open,
                json!({"path": link.to_str().unwrap(), "mode": mode}),
            )
            .unwrap_err();
            assert!(
                err.desc.ends_with("Symbolic link loop"),
                "{mode}: {}",
                err.desc
            );
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
        // Reading through a symlink keeps working.
        call(&f.agent, open, json!({"path": link.to_str().unwrap()})).unwrap();
    }

    #[test]
    fn open_handles_are_capped_below_the_fd_limit() {
        let f = fixture();
        let path = f.root.join("x");
        std::fs::write(&path, b"").unwrap();
        for _ in 0..MAX_OPEN_FILES {
            call(&f.agent, open, json!({"path": path.to_str().unwrap()})).unwrap();
        }
        let err = call(&f.agent, open, json!({"path": path.to_str().unwrap()})).unwrap_err();
        assert_eq!(err.desc, "too many open file handles");
    }

    #[test]
    fn existing_file_keeps_its_mode_and_is_truncated_by_w() {
        let f = fixture();
        let path = f.root.join("keep");
        std::fs::write(&path, b"old contents").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let handle = call(
            &f.agent,
            open,
            json!({"path": path.to_str().unwrap(), "mode": "w"}),
        )
        .unwrap();
        call(&f.agent, close, json!({"handle": handle})).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
