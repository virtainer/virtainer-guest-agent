// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Small wrappers over libc and child processes shared by the commands.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::qmp::QgaError;

/// `strerror(errno)` text, which is what qemu-ga puts after the colon.
pub fn strerror(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => {
            let text = io::Error::from_raw_os_error(code).to_string();
            match text.rfind(" (os error ") {
                Some(cut) => text[..cut].to_string(),
                None => text,
            }
        }
        None => err.to_string(),
    }
}

pub fn last_error() -> io::Error {
    io::Error::last_os_error()
}

pub fn cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

/// `ioctl(fd, request, arg)` returning the OS error on failure.
///
/// # Safety
/// `arg` must point to memory of the type and size `request` expects.
pub unsafe fn ioctl<T>(fd: i32, request: u64, arg: *mut T) -> io::Result<i32> {
    // The request parameter is `c_int` on musl and `c_ulong` on glibc.
    let rc = libc::ioctl(fd, request as _, arg);
    if rc < 0 {
        Err(last_error())
    } else {
        Ok(rc)
    }
}

pub fn clock_gettime(clock: libc::clockid_t) -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out-pointer; the clocks used here always exist.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Monotonic time that keeps counting through suspend and survives an agent
/// restart, unlike `Instant`, so deadlines can be stored in /run.
pub fn boottime() -> Duration {
    clock_gettime(libc::CLOCK_BOOTTIME)
}

pub fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    // SAFETY: bytes is a valid buffer of the given length.
    let n = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if n == bytes.len() as isize {
        u32::from_ne_bytes(bytes)
    } else {
        // Uniqueness across restarts is a convenience, not a guarantee.
        std::process::id() ^ (boottime().as_nanos() as u32)
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Output kept from a helper command for its error message.
const HELPER_OUTPUT_CAP: usize = 64 * 1024;

/// Bound for helpers (chpasswd, shutdown) that go through PAM or init and
/// could otherwise pin a connection thread forever.
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(60);

/// Run a helper the way qemu-ga's `ga_run_command` does: own session, stdin
/// from `input` (or /dev/null), stdout and stderr captured together, and an
/// error naming `action` when it fails. `timeout` kills the whole session.
pub fn run_helper(
    argv: &[&str],
    input: Option<&[u8]>,
    action: &str,
    timeout: Option<Duration>,
) -> Result<(), QgaError> {
    let failed = |detail: String| {
        QgaError::generic(format!("child process has failed to {action}: {detail}"))
    };

    let (mut reader, writer) = io::pipe()
        .map_err(|e| QgaError::generic(format!("cannot create pipe FDs: {}", strerror(&e))))?;
    let writer_err = writer
        .try_clone()
        .map_err(|e| QgaError::generic(format!("cannot create pipe FDs: {}", strerror(&e))))?;

    let mut command = Command::new(argv[0]);
    command
        .args(&argv[1..])
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(writer)
        .stderr(writer_err);
    // SAFETY: setsid is async-signal-safe and touches no Rust state.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| failed(format!("failed to exec '{}': {}", argv[0], strerror(&e))))?;
    // The parent's copies of the write end must go, or the reader never sees EOF.
    drop(command);

    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }

    // A helper that leaves a daemon holding the pipe must not hang us, so the
    // output is read on its own thread and abandoned once the child is gone.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let room = HELPER_OUTPUT_CAP.saturating_sub(kept.len());
                    kept.extend_from_slice(&chunk[..n.min(room)]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = tx.send(kept);
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                return Err(QgaError::generic(format!(
                    "failed to wait for child (pid: {}): {}",
                    child.id(),
                    strerror(&e)
                )))
            }
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            // SAFETY: the child called setsid, so its pid is its process group.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
            return Err(failed(format!(
                "timed out after {} seconds",
                timeout.unwrap_or_default().as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let output = rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
    let output = String::from_utf8_lossy(&output);
    let output = output.trim_end();

    match status.code() {
        Some(0) => Ok(()),
        Some(code) if output.is_empty() => Err(failed(format!("exit status {code}"))),
        Some(_) => Err(failed(output.to_string())),
        None => {
            let signal = status.signal().unwrap_or(0);
            if output.is_empty() {
                Err(QgaError::generic(format!(
                    "child process has terminated abnormally (signal {signal})"
                )))
            } else {
                Err(QgaError::generic(format!(
                    "child process has terminated abnormally: {output}"
                )))
            }
        }
    }
}

/// Find an executable the way a shell would, without spawning one.
pub fn find_program(name: &str) -> Option<std::path::PathBuf> {
    const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    PATH.split(':')
        .map(|dir| Path::new(dir).join(name))
        .find(|candidate| is_executable(candidate))
}

pub fn is_executable(path: &Path) -> bool {
    let Ok(c) = cstring(path) else { return false };
    // SAFETY: c is a valid NUL-terminated path.
    let executable = unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 };
    executable && path.metadata().is_ok_and(|m| m.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strerror_drops_the_rust_suffix() {
        let err = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(strerror(&err), "No such file or directory");
    }

    #[test]
    fn helper_reports_output_of_a_failing_command() {
        let err = run_helper(
            &["/bin/sh", "-c", "echo oops >&2; exit 3"],
            None,
            "do things",
            None,
        )
        .unwrap_err();
        assert_eq!(err.desc, "child process has failed to do things: oops");

        let err = run_helper(&["/bin/sh", "-c", "exit 4"], None, "x", None).unwrap_err();
        assert_eq!(err.desc, "child process has failed to x: exit status 4");
    }

    #[test]
    fn helper_feeds_stdin_and_accepts_success() {
        run_helper(
            &["/bin/sh", "-c", "read line; [ \"$line\" = hello ]"],
            Some(b"hello\n"),
            "read",
            None,
        )
        .unwrap();
    }

    #[test]
    fn helper_missing_program_names_it() {
        let err = run_helper(&["/nonexistent/prog"], None, "run", None).unwrap_err();
        assert_eq!(
            err.desc,
            "child process has failed to run: failed to exec '/nonexistent/prog': No such file or directory"
        );
    }

    #[test]
    fn helper_timeout_kills_the_session() {
        let started = Instant::now();
        let err = run_helper(
            &["/bin/sh", "-c", "sleep 30 & sleep 30"],
            None,
            "wait",
            Some(Duration::from_millis(200)),
        )
        .unwrap_err();
        assert!(err.desc.contains("timed out"), "{}", err.desc);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
