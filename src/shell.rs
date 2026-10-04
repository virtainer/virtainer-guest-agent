// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Shell sessions (README.md, "Shell protocol"): what a connection carries
//! after `__io.virtainer_shell`, and the relay between it and the terminal.
//!
//! Frames in both directions: a type byte, a little-endian u32 payload length,
//! then the payload. Type 0 carries terminal bytes; type 1 carries one JSON
//! object (`{"resize": [rows, cols]}` from the host; `{"exitcode": N}` or
//! `{"signal": N}` from the agent, once, as the last frame). They map one to
//! one onto the browser's binary and text WebSocket messages.
//!
//! A session uses its connection's thread. It polls the connection, the
//! terminal and a pidfd for the shell, so typing never waits for output and
//! the shell's exit is seen even while a background job holds the terminal.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::pty;
use crate::qmp::QgaError;

pub const MAX_SESSIONS: usize = 8;
const DATA: u8 = 0;
const CONTROL: u8 = 1;
const HEADER: usize = 5;
const MAX_DATA: usize = 64 << 10;
const MAX_CONTROL: usize = 4 << 10;
/// Terminal output read at once; one data frame each.
const CHUNK: usize = 16 << 10;
/// Keystrokes accepted but not yet taken by the terminal. Past this, the
/// connection is not read until the shell catches up.
const MAX_PENDING_INPUT: usize = 256 << 10;
/// Output still forwarded after the shell has exited.
const MAX_FINAL_OUTPUT: usize = 1 << 20;
/// How often to look for the shell's exit when the kernel has no pidfd.
const EXIT_POLL: Duration = Duration::from_millis(500);

/// The open sessions, counted apart from QGA connections.
#[derive(Default)]
pub struct Sessions {
    open: AtomicUsize,
    last_id: AtomicU64,
}

impl Sessions {
    pub fn reserve(&self) -> Result<Slot<'_>, QgaError> {
        self.open
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_SESSIONS).then_some(n + 1)
            })
            .map_err(|_| {
                QgaError::generic(format!("too many Shell sessions are open ({MAX_SESSIONS})"))
            })?;
        Ok(Slot {
            sessions: self,
            id: self.last_id.fetch_add(1, Ordering::SeqCst) + 1,
        })
    }
}

/// One place among the open sessions, given back on drop.
pub struct Slot<'a> {
    sessions: &'a Sessions,
    id: u64,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.sessions.open.fetch_sub(1, Ordering::SeqCst);
    }
}

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

fn write_frame<W: Write>(out: &mut W, kind: u8, payload: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(HEADER + payload.len());
    frame.push(kind);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    out.write_all(&frame)?;
    out.flush()
}

/// `{"resize": [rows, cols]}` with both in 1..=9999.
fn resize(control: &Value) -> Option<(u16, u16)> {
    let [rows, cols] = control.get("resize")?.as_array()?.as_slice() else {
        return None;
    };
    let dimension = |v: &Value| {
        v.as_u64()
            .filter(|n| (1..=9999).contains(n))
            .map(|n| n as u16)
    };
    Some((dimension(rows)?, dimension(cols)?))
}

#[derive(Debug, PartialEq)]
enum Frame {
    Data(Vec<u8>),
    Control(Value),
    /// An unknown type, or a control payload that is not a JSON object.
    Other,
}

/// Splits the host's byte stream into frames.
#[derive(Default)]
struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn next(&mut self) -> Result<Option<Frame>, String> {
        if self.buf.len() < HEADER {
            return Ok(None);
        }
        let kind = self.buf[0];
        let len = u32::from_le_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        let limit = if kind == CONTROL {
            MAX_CONTROL
        } else {
            MAX_DATA
        };
        if len > limit {
            return Err(format!(
                "a type {kind} frame of {len} bytes is over the {limit}-byte limit"
            ));
        }
        if self.buf.len() < HEADER + len {
            return Ok(None);
        }
        let payload = self.buf[HEADER..HEADER + len].to_vec();
        self.buf.drain(..HEADER + len);
        Ok(Some(match kind {
            DATA => Frame::Data(payload),
            CONTROL => match serde_json::from_slice::<Value>(&payload) {
                Ok(object @ Value::Object(_)) => Frame::Control(object),
                _ => Frame::Other,
            },
            _ => Frame::Other,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, kind, payload).unwrap();
        out
    }

    #[test]
    fn frames_survive_any_split() {
        let mut stream = frame(DATA, b"echo hi\r");
        stream.extend(frame(CONTROL, br#"{"resize":[40,120]}"#));
        stream.extend(frame(7, b"from the future"));
        stream.extend(frame(DATA, b""));
        for cut in 0..=stream.len() {
            let mut frames = Frames::default();
            let mut got = Vec::new();
            for part in [&stream[..cut], &stream[cut..]] {
                frames.push(part);
                while let Some(f) = frames.next().unwrap() {
                    got.push(f);
                }
            }
            assert_eq!(
                got,
                vec![
                    Frame::Data(b"echo hi\r".to_vec()),
                    Frame::Control(json!({"resize": [40, 120]})),
                    Frame::Other,
                    Frame::Data(Vec::new()),
                ],
                "split at {cut}"
            );
        }
    }

    #[test]
    fn oversized_frames_end_the_session() {
        let mut frames = Frames::default();
        frames.push(&[CONTROL, 0x01, 0x10, 0, 0]);
        assert!(frames
            .next()
            .unwrap_err()
            .contains("over the 4096-byte limit"));
        let mut frames = Frames::default();
        frames.push(&[DATA, 0x01, 0x00, 0x01, 0]);
        assert!(frames.next().is_err());
    }

    #[test]
    fn a_control_payload_that_is_not_an_object_is_ignored() {
        let mut frames = Frames::default();
        frames.push(&frame(CONTROL, b"[1,2]"));
        frames.push(&frame(CONTROL, b"not json"));
        assert_eq!(frames.next(), Ok(Some(Frame::Other)));
        assert_eq!(frames.next(), Ok(Some(Frame::Other)));
        assert_eq!(frames.next(), Ok(None));
    }

    #[test]
    fn resize_wants_two_sane_dimensions() {
        assert_eq!(resize(&json!({"resize": [50, 160]})), Some((50, 160)));
        assert_eq!(resize(&json!({"resize": [0, 80]})), None);
        assert_eq!(resize(&json!({"resize": [24, 10000]})), None);
        assert_eq!(resize(&json!({"resize": [24]})), None);
        assert_eq!(resize(&json!({"resize": "24x80"})), None);
        assert_eq!(resize(&json!({"other": 1})), None);
    }

    #[test]
    fn sessions_are_capped_and_slots_come_back() {
        let sessions = Sessions::default();
        let slots: Vec<Slot<'_>> = (0..MAX_SESSIONS)
            .map(|_| sessions.reserve().unwrap())
            .collect();
        let refused = sessions.reserve().err().unwrap();
        assert_eq!(refused.desc, "too many Shell sessions are open (8)");
        let ids: Vec<u64> = slots.iter().map(|s| s.id).collect();
        assert_eq!(ids, (1..=8).collect::<Vec<u64>>());
        drop(slots);
        assert_eq!(sessions.reserve().unwrap().id, 9);
    }

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
