// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! One host connection: framed requests in, one reply line per request out.
//!
//! After a successful `__io.virtainer_shell` the connection carries a Shell
//! session instead (shell.rs). The host waits for that reply before it sends
//! frames, so anything still queued behind the request is not a QGA message
//! and is dropped.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;

use serde_json::Value;

use crate::agent::Agent;
use crate::commands::{self, Ctx};
use crate::framer::{Event, Framer};
use crate::json;
use crate::qmp::QgaError;

/// Serve requests until the peer closes the stream. `slot` is this
/// connection's place among the QGA connections; it is given up when the
/// connection becomes a Shell session.
pub fn serve<S: Read + Write + AsRawFd, G>(
    agent: &Agent,
    mut stream: S,
    slot: G,
) -> io::Result<()> {
    let mut slot = Some(slot);
    let mut framer = Framer::default();
    let mut ctx = Ctx::new(agent);
    let mut buf = vec![0u8; 64 * 1024];
    let mut events = Vec::new();
    loop {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            framer.finish(&mut events);
        } else {
            framer.push(&buf[..n], &mut events);
        }
        for event in events.drain(..) {
            match event {
                Event::Message(bytes) => {
                    let reply = match serde_json::from_slice::<Value>(&bytes) {
                        Ok(request) => commands::dispatch(&mut ctx, request),
                        Err(e) => Some(commands::envelope(
                            Err(QgaError::generic(format!("JSON parse error, {e}"))),
                            None,
                        )),
                    };
                    if let Some(reply) = reply {
                        send(&mut stream, &mut ctx, &reply)?;
                    }
                    if let Some(session) = ctx.upgrade.take() {
                        drop(slot.take());
                        crate::shell::relay(session, &mut stream);
                        return Ok(());
                    }
                }
                Event::TooLarge => {
                    let reply = commands::envelope(
                        Err(QgaError::generic("JSON token size limit exceeded")),
                        None,
                    );
                    send(&mut stream, &mut ctx, &reply)?;
                    // The rest of that message is still on the wire; a clean
                    // close is cheaper than resynchronizing on it.
                    return Ok(());
                }
            }
        }
        if n == 0 {
            return Ok(());
        }
    }
}

fn send<S: Write>(stream: &mut S, ctx: &mut Ctx<'_>, reply: &Value) -> io::Result<()> {
    let mut out = Vec::with_capacity(256);
    if std::mem::take(&mut ctx.delimit_next) {
        out.push(0xff);
    }
    out.extend_from_slice(&json::to_vec(reply));
    out.push(b'\n');
    stream.write_all(&out)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::io::BufRead;
    use std::os::unix::net::UnixStream;

    struct Peer {
        writer: UnixStream,
        reader: io::BufReader<UnixStream>,
        _server: std::thread::JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    fn start(config: Config) -> Peer {
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(config, dir.path().to_path_buf());
        let (host, guest) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let _ = serve(&agent, guest, ());
        });
        Peer {
            reader: io::BufReader::new(host.try_clone().unwrap()),
            writer: host,
            _server: server,
            _dir: dir,
        }
    }

    impl Peer {
        fn send(&mut self, bytes: &[u8]) {
            self.writer.write_all(bytes).unwrap();
        }

        fn line(&mut self) -> Vec<u8> {
            let mut line = Vec::new();
            self.reader.read_until(b'\n', &mut line).unwrap();
            line
        }
    }

    #[test]
    fn virtainer_host_handshake() {
        // Exactly what the Virtainer host sends.
        let mut peer = start(Config::default());
        peer.send(b"\xff{\"execute\":\"guest-sync-delimited\",\"arguments\":{\"id\":1234}}\n");
        assert_eq!(peer.line(), b"\xff{\"return\": 1234}\n");
        peer.send(b"{\"execute\":\"guest-fsfreeze-status\"}\n");
        assert_eq!(peer.line(), b"{\"return\": \"thawed\"}\n");
    }

    #[test]
    fn only_the_reply_to_sync_delimited_carries_the_sentinel() {
        let mut peer = start(Config::default());
        peer.send(b"{\"execute\":\"guest-sync\",\"arguments\":{\"id\":1}}{\"execute\":\"guest-ping\",\"id\":\"p\"}");
        assert_eq!(peer.line(), b"{\"return\": 1}\n");
        assert_eq!(peer.line(), b"{\"return\": {}, \"id\": \"p\"}\n");
    }

    #[test]
    fn garbage_gets_an_error_and_the_session_continues() {
        let mut peer = start(Config::default());
        peer.send(b"{\"execute\": ]\n");
        let line = String::from_utf8(peer.line()).unwrap();
        assert!(
            line.starts_with(
                "{\"error\": {\"class\": \"GenericError\", \"desc\": \"JSON parse error, "
            ),
            "{line}"
        );
        peer.send(b"42\n");
        assert_eq!(
            peer.line(),
            b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"QMP input must be a JSON object\"}}\n"
        );
        peer.send(b"{\"execute\":\"guest-ping\"}");
        assert_eq!(peer.line(), b"{\"return\": {}}\n");
    }

    #[test]
    fn a_flood_of_tiny_tokens_gets_the_size_error_and_a_close() {
        let mut peer = start(Config::default());
        let mut input = b"[".to_vec();
        input.extend(std::iter::repeat_n(&b"1,"[..], 66_000).flatten());
        // Just past the token limit, so the server has read everything it is
        // sent before it closes and the close is clean.
        peer.send(&input);
        assert_eq!(
            peer.line(),
            b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"JSON token size limit exceeded\"}}\n"
        );
        assert_eq!(peer.line(), b"");
    }

    #[test]
    fn stale_partial_request_is_flushed_by_the_sentinel() {
        let mut peer = start(Config::default());
        peer.send(b"{\"execute\":\"guest-fsfreeze-fre");
        peer.send(b"\xff{\"execute\":\"guest-sync-delimited\",\"arguments\":{\"id\":7}}");
        assert_eq!(peer.line(), b"\xff{\"return\": 7}\n");
    }
}
