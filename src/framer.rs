// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Splits the byte stream from the host into JSON messages.
//!
//! Requests are not line-delimited: clients may send several objects in one
//! write, split one object across writes, or omit newlines entirely. Framing
//! only tracks string state and bracket depth; the message itself is parsed
//! by serde_json once a top-level value is complete.
//!
//! A `0xFF` or `0xFE` byte (never valid UTF-8) discards any partial message.
//! Clients send `0xFF` before `guest-sync-delimited` to flush what a previous
//! client left behind (QGA spec), so it resets silently instead of producing
//! an error reply the client would have to skip.

/// QEMU's JSON parser limit per message (`MAX_TOKEN_SIZE`): 48 MiB of file
/// data plus base64 overhead. Only `guest-file-write` needs it.
pub const MAX_MESSAGE_BYTES: usize = 64 << 20;
/// Limit for every other message. A message past it is accepted only if it
/// names `guest-file-write` within these first bytes (clients put `execute`
/// first).
pub const PLAIN_MESSAGE_BYTES: usize = 1 << 20;
/// Non-whitespace bytes outside strings (brackets, commas, numbers, quote
/// marks) allowed per message. serde_json turns a two-byte `1,` into a
/// 32-byte `Value`, so this bounds the parsed size independently of the byte
/// limits: a 64 MiB string is one token, 64 MiB of `[1,1,...` is not allowed.
const MAX_TOKENS: usize = 128 << 10;
const LARGE_MARKER: &[u8] = b"\"guest-file-write\"";

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Message(Vec<u8>),
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    /// Inside `{...}` or `[...]`.
    Nested {
        depth: usize,
        in_string: bool,
        escaped: bool,
    },
    /// A top-level string, e.g. a stray `"abc"`.
    TopString {
        escaped: bool,
    },
    /// A top-level bare token such as `123`, `true` or a stray `}`.
    Bare,
    /// After an oversized message: everything up to the next sentinel byte
    /// belongs to it.
    Discard,
}

pub struct Framer {
    buf: Vec<u8>,
    state: State,
    max: usize,
    plain_max: usize,
    /// The message is allowed to exceed `plain_max`.
    large: bool,
    tokens: usize,
}

impl Default for Framer {
    fn default() -> Self {
        Self::with_limits(MAX_MESSAGE_BYTES, PLAIN_MESSAGE_BYTES)
    }
}

impl Framer {
    #[cfg(test)]
    pub fn new(max: usize) -> Self {
        Self::with_limits(max, max)
    }

    pub fn with_limits(max: usize, plain_max: usize) -> Self {
        Self {
            buf: Vec::new(),
            state: State::Idle,
            max,
            plain_max,
            large: false,
            tokens: 0,
        }
    }

    pub fn push(&mut self, data: &[u8], out: &mut Vec<Event>) {
        for &byte in data {
            self.byte(byte, out);
        }
    }

    /// End of stream: a pending bare token (e.g. `123` with no newline) is
    /// still a message.
    pub fn finish(&mut self, out: &mut Vec<Event>) {
        if self.state == State::Bare && !self.buf.is_empty() {
            self.emit(out);
        }
        self.reset();
    }

    fn byte(&mut self, byte: u8, out: &mut Vec<Event>) {
        if byte == 0xff || byte == 0xfe {
            self.reset();
            return;
        }
        match self.state {
            State::Discard => return,
            State::Idle => match byte {
                b' ' | b'\t' | b'\r' | b'\n' => return,
                b'{' | b'[' => {
                    self.state = State::Nested {
                        depth: 1,
                        in_string: false,
                        escaped: false,
                    }
                }
                b'"' => self.state = State::TopString { escaped: false },
                _ => self.state = State::Bare,
            },
            State::Nested {
                depth,
                in_string,
                escaped,
            } => {
                let (depth, in_string, escaped) = match (in_string, escaped, byte) {
                    (true, true, _) => (depth, true, false),
                    (true, false, b'\\') => (depth, true, true),
                    (true, false, b'"') => (depth, false, false),
                    (true, false, _) => (depth, true, false),
                    (false, _, b'"') => (depth, true, false),
                    (false, _, b'{' | b'[') => (depth + 1, false, false),
                    (false, _, b'}' | b']') => (depth - 1, false, false),
                    (false, _, _) => (depth, false, false),
                };
                if !in_string && !byte.is_ascii_whitespace() {
                    self.tokens += 1;
                }
                if !self.append(byte, out) {
                    return;
                }
                if depth == 0 {
                    self.emit(out);
                } else if self.tokens > MAX_TOKENS {
                    self.too_large(out);
                } else {
                    self.state = State::Nested {
                        depth,
                        in_string,
                        escaped,
                    };
                }
                return;
            }
            State::TopString { escaped } => {
                if !self.append(byte, out) {
                    return;
                }
                match (escaped, byte) {
                    (false, b'"') => self.emit(out),
                    (false, b'\\') => self.state = State::TopString { escaped: true },
                    _ => self.state = State::TopString { escaped: false },
                }
                return;
            }
            State::Bare => {
                if matches!(
                    byte,
                    b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'[' | b'"' | b'}' | b']' | b',' | b':'
                ) {
                    self.emit(out);
                    // The delimiter is whitespace or starts the next message.
                    self.byte(byte, out);
                    return;
                }
            }
        }
        self.append(byte, out);
    }

    /// Append a byte; `false` if the message was rejected instead. Capacity
    /// is grown fallibly so a peer-driven size cannot abort the process.
    fn append(&mut self, byte: u8, out: &mut Vec<Event>) -> bool {
        if self.buf.len() == self.buf.capacity() {
            let extra = self.buf.len().clamp(4096, 1 << 20);
            if self.buf.try_reserve(extra).is_err() {
                self.too_large(out);
                return false;
            }
        }
        self.buf.push(byte);
        if self.buf.len() > self.plain_max && !self.large {
            self.large = self
                .buf
                .windows(LARGE_MARKER.len())
                .any(|w| w == LARGE_MARKER);
            if !self.large {
                self.too_large(out);
                return false;
            }
        }
        if self.buf.len() > self.max {
            self.too_large(out);
            return false;
        }
        true
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.state = State::Idle;
        self.large = false;
        self.tokens = 0;
    }

    fn emit(&mut self, out: &mut Vec<Event>) {
        out.push(Event::Message(std::mem::take(&mut self.buf)));
        self.reset();
    }

    fn too_large(&mut self, out: &mut Vec<Event>) {
        self.buf = Vec::new();
        self.state = State::Discard;
        self.large = false;
        self.tokens = 0;
        out.push(Event::TooLarge);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames_with(mut framer: Framer, chunks: &[&[u8]]) -> Vec<String> {
        let mut out = Vec::new();
        for chunk in chunks {
            framer.push(chunk, &mut out);
        }
        framer.finish(&mut out);
        out.into_iter()
            .map(|e| match e {
                Event::Message(m) => String::from_utf8(m).unwrap(),
                Event::TooLarge => "<too large>".into(),
            })
            .collect()
    }

    fn frames(chunks: &[&[u8]]) -> Vec<String> {
        frames_with(Framer::default(), chunks)
    }

    #[test]
    fn objects_without_newlines_and_split_across_reads() {
        assert_eq!(
            frames(&[b"{\"execute\":\"a\"}{\"exe", b"cute\":\"b\"}\n"]),
            vec!["{\"execute\":\"a\"}", "{\"execute\":\"b\"}"]
        );
    }

    #[test]
    fn brackets_inside_strings_do_not_count() {
        assert_eq!(frames(&[br#"{"a":"}{\"]"}"#]), vec![r#"{"a":"}{\"]"}"#]);
    }

    #[test]
    fn sentinel_discards_a_partial_message() {
        assert_eq!(
            frames(&[b"{\"execute\":\"stale", b"\xff{\"execute\":\"guest-ping\"}"]),
            vec!["{\"execute\":\"guest-ping\"}"]
        );
        assert_eq!(frames(&[b"\xff\xff\n"]), Vec::<String>::new());
    }

    #[test]
    fn top_level_scalars_and_stray_brackets_are_messages() {
        assert_eq!(frames(&[b"123 \"x\" }"]), vec!["123", "\"x\"", "}"]);
        assert_eq!(frames(&[b"true{}"]), vec!["true", "{}"]);
        assert_eq!(frames(&[b"42"]), vec!["42"]);
    }

    /// Random input: never panics, never emits more than the limit, and how
    /// the bytes are split across reads never changes the messages.
    #[test]
    fn random_input_is_chunking_invariant_and_bounded() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        const ALPHABET: &[u8] = b"{}[]\"\\:, \nab1\xff";
        for _ in 0..200 {
            let len = (next() % 400) as usize;
            let input: Vec<u8> = (0..len)
                .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize])
                .collect();
            let whole = frames_with(Framer::new(64), &[&input]);
            let mut chunks = Vec::new();
            let mut rest = &input[..];
            while !rest.is_empty() {
                let take = 1 + (next() % 7) as usize;
                let (head, tail) = rest.split_at(take.min(rest.len()));
                chunks.push(head);
                rest = tail;
            }
            assert_eq!(frames_with(Framer::new(64), &chunks), whole);
            assert!(whole.iter().all(|m| m.len() <= 64 || m == "<too large>"));
        }
    }

    #[test]
    fn many_small_tokens_are_rejected_long_before_the_byte_limit() {
        let mut input = b"[".to_vec();
        input.extend(std::iter::repeat_n(&b"1,"[..], 200_000).flatten());
        input.extend_from_slice(b"1]");
        let mut framer = Framer::default();
        let mut out = Vec::new();
        framer.push(&input, &mut out);
        assert_eq!(out, vec![Event::TooLarge]);
        assert_eq!(framer.buf.capacity(), 0, "the partial message is freed");
    }

    #[test]
    fn only_guest_file_write_may_exceed_the_plain_limit() {
        let big = "A".repeat(4000);
        let write =
            format!(r#"{{"execute":"guest-file-write","arguments":{{"buf-b64":"{big}"}}}}"#);
        let other = format!(r#"{{"execute":"guest-exec","arguments":{{"input-data":"{big}"}}}}"#);
        assert_eq!(
            frames_with(Framer::with_limits(1 << 20, 1000), &[write.as_bytes()]),
            vec![write.clone()]
        );
        assert_eq!(
            frames_with(Framer::with_limits(1 << 20, 1000), &[other.as_bytes()]),
            vec!["<too large>"]
        );
        // The hard limit still applies to a write.
        assert_eq!(
            frames_with(Framer::with_limits(2000, 1000), &[write.as_bytes()]),
            vec!["<too large>"]
        );
    }

    #[test]
    fn oversized_message_is_dropped_until_the_next_sentinel() {
        assert_eq!(
            frames_with(Framer::new(8), &[b"{\"a\":\"0123456789\"}{}"]),
            vec!["<too large>"]
        );
        assert_eq!(
            frames_with(Framer::new(8), &[b"{\"a\":\"0123456789\"}{}\xff{}"]),
            vec!["<too large>", "{}"]
        );
    }
}
