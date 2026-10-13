// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! The Windows Shell apart from ConPTY itself: who may ask for it, what it
//! runs, and the relay between the connection and the pseudo console.
//!
//! viosock sockets cannot be made non-blocking, and neither can the console's
//! pipes, so the relay uses threads instead of one poll loop. The
//! connection's own thread waits for host input in recv with a short
//! timeout, queues keystrokes and applies resizes, and between reads looks
//! for the shell's exit and for a failed send. It never waits on the
//! console. (select would not do: on a viosock socket it never reports the
//! host leaving, while recv does.) One thread writes the queued keystrokes
//! to the console, another copies the console's output into data frames.
//! When the session ends, the console is closed, which ends its output and
//! fails a write still waiting on it; the exit frame follows the last output.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use serde_json::json;

use crate::qmp::QgaError;
use crate::shell_protocol::{frame, resize, Frame, Frames, CHUNK, CONTROL, DATA};

/// The only account a Windows Shell runs as: the service's own, LocalSystem.
pub const USER: &str = "SYSTEM";
/// How long recv waits for host input before looking for the shell's exit.
const EXIT_POLL: Duration = Duration::from_millis(200);
/// Keystrokes queued but not yet taken by the console. Past this the console
/// is taking no input, and further keystrokes are dropped.
const MAX_PENDING_INPUT: usize = 1 << 20;

pub fn check_user(user: &str) -> Result<(), QgaError> {
    if user.eq_ignore_ascii_case(USER) {
        Ok(())
    } else {
        Err(QgaError::generic(format!(
            "failed to lookup user '{user}': a Windows Shell runs as {USER} only"
        )))
    }
}

/// Windows PowerShell 5.1, which every supported Windows ships.
pub fn command_line(system_dir: &Path) -> String {
    format!(
        "\"{}\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo",
        system_dir.display()
    )
}

/// A session's connection, shared by the relay's two threads.
pub trait Connection: Sync {
    /// Make `recv` give up after `timeout` without input, with `TimedOut`
    /// or `WouldBlock`. This replaces the idle timeout: a Shell may sit idle
    /// as long as its user likes.
    fn set_recv_timeout(&self, timeout: Duration) -> io::Result<()>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn send_all(&self, data: &[u8]) -> io::Result<()>;
}

/// The pseudo console and the processes on it.
pub trait Console {
    fn resize(&self, rows: u16, cols: u16);
    /// The shell's exit code, once it has exited.
    fn exit_code(&self) -> Option<u32>;
    /// End the shell and everything it started, and close the console,
    /// which ends its output.
    fn close(&mut self);
}

enum End {
    HostClosed,
    Exited(u32),
    Protocol(String),
    Failed(io::Error),
    /// Sending output failed; `forward` holds the error.
    OutputFailed,
}

/// Relay until the shell exits or the host leaves; returns how it ended.
pub fn relay<C, I, O, P>(conn: &C, input: I, output: O, console: &mut P) -> String
where
    C: Connection,
    I: Write + Send + 'static,
    O: Read + Send,
    P: Console,
{
    let output_failed = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let failed = &output_failed;
        let forward = scope.spawn(move || forward(conn, output, failed));
        let end = match conn
            .set_recv_timeout(EXIT_POLL)
            .and_then(|()| Keystrokes::start(input))
        {
            Ok(keystrokes) => pump(conn, keystrokes, console, &output_failed),
            Err(e) => End::Failed(e),
        };
        console.close();
        // The console's output has ended, so the copy finishes.
        let forwarded = forward.join().unwrap_or(Ok(()));
        match (end, forwarded) {
            (End::HostClosed, _) => "the host closed the connection".into(),
            (End::Protocol(why), _) => format!("protocol error: {why}"),
            (End::Failed(e), _) | (End::Exited(_) | End::OutputFailed, Err(e)) => {
                format!("the connection failed: {e}")
            }
            (End::OutputFailed, Ok(())) => "the connection failed".into(),
            (End::Exited(code), Ok(())) => {
                // Signed, as guest-exec-status reports a Windows exit code.
                let control = json!({ "exitcode": code as i32 }).to_string();
                match conn.send_all(&frame(CONTROL, control.as_bytes())) {
                    Ok(()) => format!("the shell exited with code {}", code as i32),
                    Err(e) => format!("the connection failed: {e}"),
                }
            }
        }
    })
}

/// Host input to the console until the shell exits, the host leaves or
/// output can no longer be sent.
fn pump<C: Connection, P: Console>(
    conn: &C,
    keystrokes: Keystrokes,
    console: &P,
    output_failed: &AtomicBool,
) -> End {
    let mut frames = Frames::default();
    let mut buf = vec![0u8; CHUNK];
    loop {
        if let Some(code) = console.exit_code() {
            return End::Exited(code);
        }
        if output_failed.load(Ordering::SeqCst) {
            return End::OutputFailed;
        }
        let n = match conn.recv(&mut buf) {
            Ok(0) => return End::HostClosed,
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return End::Failed(e),
        };
        frames.push(&buf[..n]);
        loop {
            match frames.next() {
                Ok(None) => break,
                Ok(Some(Frame::Data(bytes))) => keystrokes.queue(bytes),
                Ok(Some(Frame::Control(control))) => {
                    if let Some((rows, cols)) = resize(&control) {
                        console.resize(rows, cols);
                    }
                }
                Ok(Some(Frame::Other)) => {}
                Err(why) => return End::Protocol(why),
            }
        }
    }
}

/// Keystrokes on their way to the console, written by a thread of their own
/// so that a console that takes no input never stops the relay. The thread
/// ends once the queue is dropped or a write fails, as one still waiting
/// does when the console closes; it is not joined, so not even a console
/// that never closes holds up the end of the session.
struct Keystrokes {
    queue: mpsc::Sender<Vec<u8>>,
    pending: Arc<AtomicUsize>,
}

impl Keystrokes {
    fn start<I: Write + Send + 'static>(mut input: I) -> io::Result<Self> {
        let (queue, keystrokes) = mpsc::channel::<Vec<u8>>();
        let pending = Arc::new(AtomicUsize::new(0));
        let written = pending.clone();
        std::thread::Builder::new()
            .name("shell-input".into())
            .spawn(move || {
                for bytes in keystrokes {
                    if input.write_all(&bytes).is_err() {
                        return;
                    }
                    written.fetch_sub(bytes.len(), Ordering::SeqCst);
                }
            })?;
        Ok(Keystrokes { queue, pending })
    }

    fn queue(&self, bytes: Vec<u8>) {
        let len = bytes.len();
        let room = self
            .pending
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n + len <= MAX_PENDING_INPUT).then_some(n + len)
            });
        if room.is_ok() {
            // A writer that has stopped drops what it is sent.
            let _ = self.queue.send(bytes);
        }
    }
}

/// Console output to the host until the console closes. A failed send is
/// flagged so that the pump ends the session; output is still read to the
/// end, since closing a pseudo console can wait until it has been read.
fn forward<C: Connection, O: Read>(conn: &C, mut output: O, failed: &AtomicBool) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut result = Ok(());
    loop {
        match output.read(&mut buf) {
            Ok(0) => return result,
            Ok(n) => {
                if result.is_ok() {
                    result = conn.send_all(&frame(DATA, &buf[..n]));
                    if result.is_err() {
                        failed.store(true, Ordering::SeqCst);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_system_may_ask() {
        assert!(check_user("SYSTEM").is_ok());
        assert!(check_user("system").is_ok());
        assert_eq!(
            check_user("Administrator").unwrap_err().desc,
            "failed to lookup user 'Administrator': a Windows Shell runs as SYSTEM only"
        );
        assert!(check_user("").is_err());
    }

    #[test]
    fn the_shell_is_windows_powershell() {
        assert_eq!(
            command_line(Path::new("C:\\Windows\\System32")),
            "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo"
        );
    }

    /// The relay over a Unix socket pair, with pipes and a fake shell for
    /// the console.
    #[cfg(unix)]
    mod relay {
        use super::*;
        use serde_json::Value;
        use std::io::{BufRead, PipeReader, PipeWriter};
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Mutex};

        impl Connection for UnixStream {
            fn set_recv_timeout(&self, timeout: Duration) -> io::Result<()> {
                self.set_read_timeout(Some(timeout))
            }

            fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
                (&*self).read(buf)
            }

            fn send_all(&self, data: &[u8]) -> io::Result<()> {
                (&*self).write_all(data)
            }
        }

        /// Echoes each line of input in capitals; `exit N` prints `bye` and
        /// exits with N.
        struct FakeConsole {
            output: Arc<Mutex<Option<PipeWriter>>>,
            exit: Arc<AtomicU32>,
            size: Mutex<Option<(u16, u16)>>,
            closed: bool,
        }

        const RUNNING: u32 = u32::MAX - 1;

        fn console() -> (FakeConsole, PipeWriter, PipeReader) {
            let (input_reader, input_writer) = std::io::pipe().unwrap();
            let (output_reader, output_writer) = std::io::pipe().unwrap();
            let output = Arc::new(Mutex::new(Some(output_writer)));
            let exit = Arc::new(AtomicU32::new(RUNNING));
            {
                let output = output.clone();
                let exit = exit.clone();
                std::thread::spawn(move || {
                    for line in io::BufReader::new(input_reader).split(b'\r') {
                        let Ok(line) = line else { break };
                        let text = String::from_utf8_lossy(&line).into_owned();
                        let mut output = output.lock().unwrap();
                        let Some(out) = output.as_mut() else { break };
                        if let Some(code) = text.strip_prefix("exit ") {
                            out.write_all(b"bye\r\n").unwrap();
                            exit.store(code.parse().unwrap(), Ordering::SeqCst);
                        } else {
                            out.write_all(text.to_uppercase().as_bytes()).unwrap();
                            out.write_all(b"\r\n").unwrap();
                        }
                    }
                });
            }
            (
                FakeConsole {
                    output,
                    exit,
                    size: Mutex::new(None),
                    closed: false,
                },
                input_writer,
                output_reader,
            )
        }

        impl Console for FakeConsole {
            fn resize(&self, rows: u16, cols: u16) {
                *self.size.lock().unwrap() = Some((rows, cols));
            }

            fn exit_code(&self) -> Option<u32> {
                Some(self.exit.load(Ordering::SeqCst)).filter(|&code| code != RUNNING)
            }

            fn close(&mut self) {
                self.output.lock().unwrap().take();
                self.closed = true;
            }
        }

        /// What the host received, until the agent closed the connection.
        fn received(mut host: &UnixStream) -> (Vec<u8>, Vec<Value>) {
            let mut bytes = Vec::new();
            host.read_to_end(&mut bytes).unwrap();
            let (mut output, mut controls) = (Vec::new(), Vec::new());
            let mut frames = Frames::default();
            frames.push(&bytes);
            while let Some(frame) = frames.next().unwrap() {
                match frame {
                    Frame::Data(data) => {
                        assert!(controls.is_empty(), "output after the exit frame");
                        output.extend(data);
                    }
                    Frame::Control(control) => controls.push(control),
                    Frame::Other => panic!("unexpected frame"),
                }
            }
            (output, controls)
        }

        fn run_session(
            input_frames: &[Vec<u8>],
            close_host: bool,
        ) -> (String, FakeConsole, Vec<u8>, Vec<Value>) {
            let (host, guest) = UnixStream::pair().unwrap();
            let (mut fake, input, output) = console();
            for f in input_frames {
                (&host).write_all(f).unwrap();
            }
            if close_host {
                host.shutdown(std::net::Shutdown::Write).unwrap();
            }
            let how = std::thread::scope(|scope| {
                let session = scope.spawn(|| {
                    let how = relay(&guest, input, output, &mut fake);
                    guest.shutdown(std::net::Shutdown::Both).unwrap();
                    how
                });
                let got = received(&host);
                (session.join().unwrap(), got)
            });
            let (how, (out, controls)) = how;
            (how, fake, out, controls)
        }

        /// A host that stays connected but stopped reading: every send
        /// times out.
        struct StalledHost(UnixStream);

        impl Connection for StalledHost {
            fn set_recv_timeout(&self, timeout: Duration) -> io::Result<()> {
                self.0.set_recv_timeout(timeout)
            }

            fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.recv(buf)
            }

            fn send_all(&self, _: &[u8]) -> io::Result<()> {
                Err(io::ErrorKind::TimedOut.into())
            }
        }

        #[test]
        fn a_failed_send_ends_the_session() {
            let (host, guest) = UnixStream::pair().unwrap();
            let guest = StalledHost(guest);
            let (mut fake, input, output) = console();
            (&host).write_all(&frame(DATA, b"echo hi\r")).unwrap();
            let (done, ended) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let how = relay(&guest, input, output, &mut fake);
                let _ = done.send((how, fake.closed));
            });
            let (how, closed) = ended
                .recv_timeout(Duration::from_secs(10))
                .expect("the session outlived its connection");
            assert_eq!(how, "the connection failed: timed out");
            assert!(closed);
            drop(host);
        }

        /// A console that never reads its input. Closing it closes the
        /// input pipe's read end, as closing a pseudo console does.
        struct StalledConsole {
            input: Option<PipeReader>,
            output: Option<PipeWriter>,
        }

        impl Console for StalledConsole {
            fn resize(&self, _: u16, _: u16) {}

            fn exit_code(&self) -> Option<u32> {
                None
            }

            fn close(&mut self) {
                self.input.take();
                self.output.take();
            }
        }

        #[test]
        fn a_console_that_takes_no_input_does_not_hold_the_session() {
            let (host, guest) = UnixStream::pair().unwrap();
            let (input_reader, input) = std::io::pipe().unwrap();
            let (output, output_writer) = std::io::pipe().unwrap();
            let mut console = StalledConsole {
                input: Some(input_reader),
                output: Some(output_writer),
            };
            let (done, ended) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let how = relay(&guest, input, output, &mut console);
                let _ = done.send((how, console.input.is_none()));
            });
            // Far more than a pipe holds, then more than the queue holds;
            // the relay keeps reading all of it.
            let keys = vec![b'x'; 60 << 10];
            for _ in 0..24 {
                (&host).write_all(&frame(DATA, &keys)).unwrap();
            }
            // Still relaying: resizes and keystrokes are taken.
            (&host)
                .write_all(&frame(CONTROL, br#"{"resize": [30, 90]}"#))
                .unwrap();
            assert!(ended.recv_timeout(Duration::from_millis(500)).is_err());
            host.shutdown(std::net::Shutdown::Write).unwrap();
            let (how, closed) = ended
                .recv_timeout(Duration::from_secs(10))
                .expect("a blocked console write held the session");
            assert_eq!(how, "the host closed the connection");
            assert!(closed);
        }

        #[test]
        fn queued_keystrokes_are_bounded() {
            const KEYS: usize = 60 << 10;
            let (mut input_reader, input) = std::io::pipe().unwrap();
            let keystrokes = Keystrokes::start(input).unwrap();
            for _ in 0..40 {
                keystrokes.queue(vec![b'x'; KEYS]);
            }
            assert!(keystrokes.pending.load(Ordering::SeqCst) <= MAX_PENDING_INPUT);
            // Once the console reads again, everything accepted arrives.
            drop(keystrokes);
            let mut got = Vec::new();
            input_reader.read_to_end(&mut got).unwrap();
            assert_eq!(got.len() % KEYS, 0);
            assert!(got.len() > MAX_PENDING_INPUT - KEYS, "{}", got.len());
            assert!(got.len() < 40 * KEYS, "nothing was dropped");
        }

        #[test]
        fn output_and_the_exit_code_reach_the_host_in_order() {
            let (how, fake, output, controls) = run_session(
                &[
                    frame(DATA, b"echo hi\r"),
                    frame(CONTROL, br#"{"resize": [50, 160]}"#),
                    frame(DATA, b"exit 3221225786\r"),
                ],
                false,
            );
            assert_eq!(String::from_utf8_lossy(&output), "ECHO HI\r\nbye\r\n");
            assert_eq!(controls, vec![json!({"exitcode": -1073741510})]);
            assert_eq!(how, "the shell exited with code -1073741510");
            assert_eq!(*fake.size.lock().unwrap(), Some((50, 160)));
            assert!(fake.closed);
        }

        #[test]
        fn the_host_leaving_closes_the_console() {
            let (how, fake, output, controls) = run_session(&[frame(DATA, b"dir\r")], true);
            assert_eq!(how, "the host closed the connection");
            assert!(fake.closed);
            assert!(controls.is_empty());
            // Whatever the console wrote before it closed may or may not arrive.
            assert!(b"DIR\r\n".starts_with(&output), "{output:?}");
        }

        #[test]
        fn an_oversized_frame_ends_the_session() {
            let mut huge = frame(DATA, &[]);
            huge[1..5].copy_from_slice(&(1u32 << 20).to_le_bytes());
            let (how, fake, _, controls) = run_session(&[huge], false);
            assert_eq!(
                how,
                "protocol error: a type 0 frame of 1048576 bytes is over the 65536-byte limit"
            );
            assert!(fake.closed);
            assert!(controls.is_empty());
        }
    }
}
