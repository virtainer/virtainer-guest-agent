// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! The Shell protocol (README.md, "Shell protocol"), shared by the Linux and
//! Windows sessions: the request's arguments, the session limit and the
//! frames a session's connection carries.
//!
//! Frames in both directions: a type byte, a little-endian u32 payload length,
//! then the payload. Type 0 carries terminal bytes; type 1 carries one JSON
//! object (`{"resize": [rows, cols]}` from the host; `{"exitcode": N}` or
//! `{"signal": N}` from the agent, once, as the last frame). They map one to
//! one onto the browser's binary and text WebSocket messages.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde_json::Value;

use crate::qmp::{Args, QgaError};

pub const NAME: &str = "__io.virtainer_shell";
pub const MAX_SESSIONS: usize = 8;
pub const DATA: u8 = 0;
pub const CONTROL: u8 = 1;
const HEADER: usize = 5;
const MAX_DATA: usize = 64 << 10;
const MAX_CONTROL: usize = 4 << 10;
/// Terminal output read at once; one data frame each.
pub const CHUNK: usize = 16 << 10;
const DEFAULT_TERM: &str = "xterm-256color";

/// The arguments of `__io.virtainer_shell`.
#[derive(Debug, PartialEq)]
pub struct Request {
    pub user: String,
    pub rows: u16,
    pub cols: u16,
    pub term: String,
}

impl Request {
    pub fn parse(mut args: Args) -> Result<Self, QgaError> {
        let user = args.str("user")?;
        let rows = dimension(args.opt_int("rows")?, "rows", 24)?;
        let cols = dimension(args.opt_int("cols")?, "cols", 80)?;
        let term = args.opt_str("term")?;
        args.finish()?;
        let term = term.unwrap_or_else(|| DEFAULT_TERM.to_string());
        if !valid_term(&term) {
            return Err(QgaError::generic(format!("invalid terminal type '{term}'")));
        }
        Ok(Request {
            user,
            rows,
            cols,
            term,
        })
    }
}

fn dimension(value: Option<i64>, name: &str, default: u16) -> Result<u16, QgaError> {
    match value {
        None => Ok(default),
        Some(n @ 1..=9999) => Ok(n as u16),
        Some(_) => Err(QgaError::generic(format!(
            "Parameter '{name}' expects a value between 1 and 9999"
        ))),
    }
}

fn valid_term(term: &str) -> bool {
    !term.is_empty()
        && term.len() <= 64
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

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
    pub id: u64,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.sessions.open.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One frame, header and payload.
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER + payload.len());
    frame.push(kind);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// `{"resize": [rows, cols]}` with both in 1..=9999.
pub fn resize(control: &Value) -> Option<(u16, u16)> {
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
pub enum Frame {
    Data(Vec<u8>),
    Control(Value),
    /// An unknown type, or a control payload that is not a JSON object.
    Other,
}

/// Splits the host's byte stream into frames.
#[derive(Default)]
pub struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next(&mut self) -> Result<Option<Frame>, String> {
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
    use serde_json::json;

    fn parse(arguments: Value) -> Result<Request, String> {
        let Value::Object(members) = arguments else {
            unreachable!()
        };
        Request::parse(Args::new(members)).map_err(|e| e.desc)
    }

    #[test]
    fn requests_are_checked_and_defaulted() {
        assert_eq!(
            parse(json!({"user": "root"})),
            Ok(Request {
                user: "root".into(),
                rows: 24,
                cols: 80,
                term: "xterm-256color".into(),
            })
        );
        assert_eq!(
            parse(json!({"user": "SYSTEM", "rows": 40, "cols": 120, "term": "xterm"})),
            Ok(Request {
                user: "SYSTEM".into(),
                rows: 40,
                cols: 120,
                term: "xterm".into(),
            })
        );
        assert_eq!(parse(json!({})), Err("Parameter 'user' is missing".into()));
        assert_eq!(
            parse(json!({"user": "root", "cols": 10000})),
            Err("Parameter 'cols' expects a value between 1 and 9999".into())
        );
        assert_eq!(
            parse(json!({"user": "root", "term": ""})),
            Err("invalid terminal type ''".into())
        );
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
}
