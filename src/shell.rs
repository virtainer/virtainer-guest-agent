// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Shell sessions on Linux: the relay between a connection that carries
//! Shell frames (shell_protocol.rs) and a pseudo-terminal.
//!
//! A session uses its connection's thread. It polls the connection, the
//! terminal and a pidfd for the shell, so typing never waits for output and
//! the shell's exit is seen even while a background job holds the terminal.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::pty;
use crate::shell_protocol::{frame, resize, Frame, Frames, Slot, CHUNK, CONTROL, DATA};

/// Keystrokes accepted but not yet taken by the terminal. Past this, the
/// connection is not read until the shell catches up.
const MAX_PENDING_INPUT: usize = 256 << 10;
/// Output still forwarded after the shell has exited.
const MAX_FINAL_OUTPUT: usize = 1 << 20;
/// How often to look for the shell's exit when the kernel has no pidfd.
const EXIT_POLL: Duration = Duration::from_millis(500);

pub struct Session<'a> {
    slot: Slot<'a>,
    user: String,
    master: File,
    child: Option<Child>,
    pid: u32,
    pidfd: Option<OwnedFd>,
    started: Instant,
    /// How the session ended, for the log line.
    ended: String,
}

impl<'a> Session<'a> {
    pub fn new(slot: Slot<'a>, user: String, master: File, child: Child) -> Self {
        let pid = child.id();
        crate::notice!(
            "Shell session {} opened for user '{user}' (pid {pid})",
            slot.id
        );
        Session {
            slot,
            user,
            master,
            child: Some(child),
            pid,
            pidfd: pty::pidfd(pid),
            started: Instant::now(),
            ended: "the reply to the host failed".into(),
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // The master closes right after this body, which hangs the terminal
        // up: the shell and its foreground job get SIGHUP. Reap the shell on
        // a thread of its own so it never lingers as a zombie.
        if let Some(mut child) = self.child.take() {
            let _ = std::thread::Builder::new()
                .name("shell-reaper".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
        crate::notice!(
            "Shell session {} for user '{}' ended: {} after {}s",
            self.slot.id,
            self.user,
            self.ended,
            self.started.elapsed().as_secs()
        );
    }
}

/// Relay between the connection and the terminal until one side ends.
pub fn relay<S: Read + Write + AsRawFd>(mut session: Session<'_>, stream: &mut S) {
    session.ended = match run(&mut session, stream) {
        Ok(how) => how,
        Err(e) => format!("the connection failed: {}", crate::sys::strerror(&e)),
    };
}

fn run<S: Read + Write + AsRawFd>(session: &mut Session<'_>, stream: &mut S) -> io::Result<String> {
    let master_fd = session.master.as_raw_fd();
    pty::set_nonblocking(master_fd)?;
    let mut frames = Frames::default();
    let mut pending: Vec<u8> = Vec::new();
    let mut terminal_open = true;
    let mut buf = vec![0u8; CHUNK];
    loop {
        if !terminal_open {
            // A shell that closed its terminal reads no keystrokes; keeping
            // them would only stop us from noticing that the host left.
            pending.clear();
        }
        let mut fds = vec![pollfd(
            stream.as_raw_fd(),
            if pending.len() < MAX_PENDING_INPUT {
                libc::POLLIN
            } else {
                0
            },
        )];
        let terminal_at = terminal_open.then(|| {
            let out = if pending.is_empty() { 0 } else { libc::POLLOUT };
            fds.push(pollfd(master_fd, libc::POLLIN | out));
            fds.len() - 1
        });
        let pidfd_at = session.pidfd.as_ref().map(|fd| {
            fds.push(pollfd(fd.as_raw_fd(), libc::POLLIN));
            fds.len() - 1
        });
        let timeout = if pidfd_at.is_some() {
            -1
        } else {
            EXIT_POLL.as_millis() as i32
        };
        poll(&mut fds, timeout)?;

        if let Some(at) = terminal_at {
            let revents = fds[at].revents;
            if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                match (&session.master).read(&mut buf) {
                    Ok(0) => terminal_open = false,
                    Ok(n) => write_frame(stream, DATA, &buf[..n])?,
                    Err(e) if retry(&e) => {}
                    // EIO: nothing holds the terminal open any more.
                    Err(_) => terminal_open = false,
                }
            }
            if terminal_open && !pending.is_empty() {
                write_pending(&session.master, &mut pending, &mut terminal_open);
            }
        }

        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(e) if retry(&e) => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                return Ok("the host closed the connection".into());
            }
            frames.push(&buf[..n]);
            loop {
                match frames.next() {
                    Ok(None) => break,
                    Ok(Some(Frame::Data(bytes))) => pending.extend_from_slice(&bytes),
                    Ok(Some(Frame::Control(control))) => {
                        if let Some((rows, cols)) = resize(&control) {
                            let _ = pty::set_size(master_fd, rows, cols);
                        }
                    }
                    Ok(Some(Frame::Other)) => {}
                    Err(why) => return Ok(format!("protocol error: {why}")),
                }
            }
            if terminal_open && !pending.is_empty() {
                write_pending(&session.master, &mut pending, &mut terminal_open);
            }
        }

        let exited = match pidfd_at {
            Some(at) => fds[at].revents & libc::POLLIN != 0,
            None => match session.child.as_mut() {
                Some(child) => child.try_wait()?.is_some(),
                None => true,
            },
        };
        if exited {
            let status = match session.child.take() {
                Some(mut child) => child.wait()?,
                None => return Ok("the shell exited".into()),
            };
            if terminal_open {
                forward_final_output(&session.master, stream, &mut buf)?;
            }
            let (control, how) = exit_report(status);
            write_frame(stream, CONTROL, control.to_string().as_bytes())?;
            return Ok(how);
        }
    }
}

fn retry(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

fn write_pending(master: &File, pending: &mut Vec<u8>, terminal_open: &mut bool) {
    match (&*master).write(pending) {
        Ok(n) => {
            pending.drain(..n);
        }
        Err(e) if retry(&e) => {}
        Err(_) => {
            pending.clear();
            *terminal_open = false;
        }
    }
}

/// What the shell printed just before it exited.
fn forward_final_output<S: Write>(master: &File, stream: &mut S, buf: &mut [u8]) -> io::Result<()> {
    let mut sent = 0;
    while sent < MAX_FINAL_OUTPUT {
        match (&*master).read(buf) {
            Ok(0) => break,
            Ok(n) => {
                write_frame(stream, DATA, &buf[..n])?;
                sent += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    Ok(())
}

fn exit_report(status: ExitStatus) -> (Value, String) {
    match (status.code(), status.signal()) {
        (Some(code), _) => (
            json!({ "exitcode": code }),
            format!("the shell exited with code {code}"),
        ),
        (None, Some(signal)) => (
            json!({ "signal": signal }),
            format!("the shell was killed by signal {signal}"),
        ),
        (None, None) => (json!({ "exitcode": -1 }), "the shell exited".into()),
    }
}

fn write_frame<W: Write>(out: &mut W, kind: u8, payload: &[u8]) -> io::Result<()> {
    out.write_all(&frame(kind, payload))?;
    out.flush()
}

fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

fn poll(fds: &mut [libc::pollfd], timeout: libc::c_int) -> io::Result<()> {
    loop {
        // SAFETY: fds is a valid, writable array of pollfd.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) } >= 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_reports_follow_guest_exec_status_names() {
        assert_eq!(
            exit_report(ExitStatus::from_raw(7 << 8)).0,
            json!({"exitcode": 7})
        );
        assert_eq!(
            exit_report(ExitStatus::from_raw(libc::SIGKILL)).0,
            json!({"signal": 9})
        );
    }
}
