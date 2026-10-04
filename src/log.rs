// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Run log.
//!
//! Under systemd stderr is a journal stream and a `<N>` prefix sets the
//! priority. Without systemd (OpenRC) lines go to syslog through /dev/log;
//! failing both, plain stderr.
//!
//! Logging must never block the agent: journald and syslogd write to disk,
//! and a frozen disk stops them. A log call that blocked behind a stuck
//! journald could stall the very thaw that would unstick it. So writes are
//! non-blocking (a line is dropped rather than waited for), and while this
//! agent holds filesystems frozen, lines are kept in memory and written after
//! the thaw. Sockets use `MSG_DONTWAIT`; a pipe or tty is written only when
//! `poll` says it can take the whole line (lines are capped at `PIPE_BUF`).
//! The one exception is stderr redirected to a regular file on a frozen
//! filesystem, which no readiness check can detect.
//!
//! A message is always exactly one line: control characters in it (host
//! supplied strings reach the log) are escaped, so a value can neither start
//! a new journal entry nor set its own priority.

use std::fmt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
}

enum Sink {
    Journal,
    Syslog {
        path: PathBuf,
        socket: Option<UnixDatagram>,
        last_connect: Option<Instant>,
    },
    Stderr,
}

struct Logger {
    sink: Sink,
    held: Option<Vec<(Level, String)>>,
    dropped: usize,
}

/// Lines kept in memory while frozen; a freeze window is seconds long.
const HELD_LINES: usize = 64;
/// A pipe write of at most this many bytes is atomic and, once `poll` has
/// reported room, cannot block.
const MAX_LINE_BYTES: usize = 4000;
/// Minimum time between attempts to reconnect to syslogd.
const RECONNECT_EVERY: Duration = Duration::from_secs(1);

static LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

pub fn init() {
    // SAFETY: isatty has no preconditions.
    let interactive = unsafe { libc::isatty(2) } == 1;
    let sink = if std::env::var_os("JOURNAL_STREAM").is_some() {
        Sink::Journal
    } else if interactive {
        Sink::Stderr
    } else {
        match connect_syslog("/dev/log") {
            Ok(socket) => Sink::Syslog {
                path: "/dev/log".into(),
                socket: Some(socket),
                last_connect: None,
            },
            Err(_) => Sink::Stderr,
        }
    };
    *lock() = Some(Logger {
        sink,
        held: None,
        dropped: 0,
    });
}

fn connect_syslog(path: &str) -> std::io::Result<UnixDatagram> {
    let socket = UnixDatagram::unbound()?;
    socket.connect(path)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn lock() -> std::sync::MutexGuard<'static, Option<Logger>> {
    LOGGER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Keep lines in memory (`true`) or write them, including the kept ones.
pub fn hold(on: bool) {
    let mut guard = lock();
    let Some(logger) = guard.as_mut() else {
        return;
    };
    if on {
        logger.held.get_or_insert_with(Vec::new);
        return;
    }
    for (level, line) in logger.held.take().unwrap_or_default() {
        logger.write(level, &line);
    }
    logger.report_dropped();
}

pub fn emit(level: Level, args: fmt::Arguments<'_>) {
    let line = sanitize(&args.to_string());
    let mut guard = lock();
    let Some(logger) = guard.as_mut() else {
        eprintln!("{line}");
        return;
    };
    match logger.held.as_mut() {
        Some(held) if held.len() < HELD_LINES => held.push((level, line)),
        Some(_) => logger.dropped += 1,
        None => logger.write(level, &line),
    }
}

/// One physical line: control characters become visible escapes and the
/// length is capped on a character boundary.
fn sanitize(line: &str) -> String {
    let mut out = String::with_capacity(line.len().min(MAX_LINE_BYTES));
    for c in line.chars() {
        let mut piece = [0u8; 4];
        let piece: &str = match c {
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            c if c.is_ascii_control() => {
                let escaped = format!("\\x{:02x}", c as u8);
                if out.len() + escaped.len() > MAX_LINE_BYTES {
                    break;
                }
                out.push_str(&escaped);
                continue;
            }
            c => c.encode_utf8(&mut piece),
        };
        if out.len() + piece.len() > MAX_LINE_BYTES {
            break;
        }
        out.push_str(piece);
    }
    out
}

impl Logger {
    fn write(&mut self, level: Level, line: &str) {
        if self.deliver(level, line) {
            self.report_dropped();
        } else {
            self.dropped += 1;
        }
    }

    /// Tell the reader that lines are missing, once the sink takes input again.
    fn report_dropped(&mut self) {
        if self.dropped == 0 {
            return;
        }
        let line = format!("{} log lines were dropped", self.dropped);
        if self.deliver(Level::Warning, &line) {
            self.dropped = 0;
        }
    }

    fn deliver(&mut self, level: Level, line: &str) -> bool {
        match &mut self.sink {
            Sink::Journal => send_nonblocking(2, format!("<{}>{line}\n", level as u8).as_bytes()),
            Sink::Syslog {
                path,
                socket,
                last_connect,
            } => {
                // RFC 3164: facility daemon (3), our tag and pid.
                let message = format!(
                    "<{}>virtainer-guest-agent[{}]: {line}",
                    3 * 8 + level as u8,
                    std::process::id()
                );
                if socket
                    .as_ref()
                    .is_some_and(|s| s.send(message.as_bytes()).is_ok())
                {
                    return true;
                }
                // syslogd restarted (or never was there): reconnect, at most
                // once per interval, and retry this line once.
                if last_connect.is_some_and(|t| t.elapsed() < RECONNECT_EVERY) {
                    return false;
                }
                *last_connect = Some(Instant::now());
                *socket = path.to_str().and_then(|p| connect_syslog(p).ok());
                socket
                    .as_ref()
                    .is_some_and(|s| s.send(message.as_bytes()).is_ok())
            }
            Sink::Stderr => send_nonblocking(2, format!("{line}\n").as_bytes()),
        }
    }
}

/// Write without blocking: `send(MSG_DONTWAIT)` on a socket (the journal
/// stream); on anything else wait for `poll` to report room first.
fn send_nonblocking(fd: i32, bytes: &[u8]) -> bool {
    // SAFETY: bytes is a valid buffer for the given length.
    let sent = unsafe {
        libc::send(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if sent >= 0 {
        return true;
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOTSOCK) {
        return false;
    }
    if bytes.len() > MAX_LINE_BYTES + 16 {
        return false;
    }
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: pfd is a valid pollfd and the count is 1.
    if unsafe { libc::poll(&mut pfd, 1, 0) } != 1 || pfd.revents & libc::POLLOUT == 0 {
        return false;
    }
    // SAFETY: bytes is a valid buffer for the given length.
    unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) >= 0 }
}

/// Route the process-wide logger to a datagram socket at `path`.
#[cfg(test)]
pub fn capture_to(path: &std::path::Path) {
    let socket = connect_syslog(path.to_str().unwrap()).unwrap();
    *lock() = Some(Logger {
        sink: Sink::Syslog {
            path: path.into(),
            socket: Some(socket),
            last_connect: None,
        },
        held: None,
        dropped: 0,
    });
}

#[macro_export]
macro_rules! error {
    ($($t:tt)*) => { $crate::log::emit($crate::log::Level::Error, format_args!($($t)*)) };
}

#[macro_export]
macro_rules! warning {
    ($($t:tt)*) => { $crate::log::emit($crate::log::Level::Warning, format_args!($($t)*)) };
}

#[macro_export]
macro_rules! notice {
    ($($t:tt)*) => { $crate::log::emit($crate::log::Level::Notice, format_args!($($t)*)) };
}

#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { $crate::log::emit($crate::log::Level::Info, format_args!($($t)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_cannot_split_or_forge_lines() {
        let line = sanitize("a\n<3>forged\r\t\x1b[31m\x7f\0é");
        assert_eq!(line, "a\\n<3>forged\\r\\t\\x1b[31m\\x7f\\x00é");
        assert!(!line.chars().any(|c| c.is_control()));
    }

    #[test]
    fn long_lines_are_capped_on_a_character_boundary() {
        let line = sanitize(&"é".repeat(MAX_LINE_BYTES));
        assert!(line.len() <= MAX_LINE_BYTES);
        assert!(line.chars().all(|c| c == 'é'));
    }

    fn recv_all(socket: &UnixDatagram) -> Vec<String> {
        let mut lines = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(n) = socket.recv(&mut buf) {
            lines.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        lines
    }

    fn syslog_logger(path: &std::path::Path) -> Logger {
        Logger {
            sink: Sink::Syslog {
                path: path.into(),
                socket: Some(connect_syslog(path.to_str().unwrap()).unwrap()),
                last_connect: None,
            },
            held: None,
            dropped: 0,
        }
    }

    #[test]
    fn syslog_reconnects_after_the_daemon_restarts_and_reports_drops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let first = UnixDatagram::bind(&path).unwrap();
        first.set_nonblocking(true).unwrap();
        let mut logger = syslog_logger(&path);
        logger.write(Level::Info, "one");
        assert_eq!(recv_all(&first).len(), 1);

        drop(first);
        std::fs::remove_file(&path).unwrap();
        logger.write(Level::Info, "lost 1");
        // Inside the reconnect interval nothing is retried.
        logger.write(Level::Info, "lost 2");
        assert_eq!(logger.dropped, 2);

        let second = UnixDatagram::bind(&path).unwrap();
        second.set_nonblocking(true).unwrap();
        if let Sink::Syslog { last_connect, .. } = &mut logger.sink {
            *last_connect = Instant::now().checked_sub(2 * RECONNECT_EVERY);
        }
        logger.write(Level::Info, "three");
        let lines = recv_all(&second);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].ends_with(": three"), "{lines:?}");
        assert!(
            lines[1].ends_with(": 2 log lines were dropped"),
            "{lines:?}"
        );
        assert_eq!(logger.dropped, 0);
    }
}
