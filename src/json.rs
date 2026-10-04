// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! QEMU's compact JSON spelling: `{"a": 1, "b": [1, 2]}`, ASCII only.
//!
//! qemu-ga escapes every code point outside printable ASCII as `\uXXXX`
//! (uppercase hex, surrogate pairs above the BMP). Writing the same bytes keeps
//! replies comparable with real qemu-ga output and keeps the wire 7-bit clean,
//! whatever a guest file name or user name contains.

use std::io::{self, Write};

use serde::Serialize;
use serde_json::ser::{CharEscape, Formatter, Serializer};

struct QemuFormatter;

impl Formatter for QemuFormatter {
    fn begin_array_value<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            w.write_all(b", ")
        }
    }

    fn begin_object_key<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            w.write_all(b", ")
        }
    }

    fn begin_object_value<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }

    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        // serde_json routes control characters, quote and backslash through
        // write_char_escape; everything else arrives here.
        if fragment.bytes().all(|b| b < 0x7f) {
            return w.write_all(fragment.as_bytes());
        }
        let mut units = [0u16; 2];
        for c in fragment.chars() {
            if (c as u32) < 0x7f {
                w.write_all(&[c as u8])?;
            } else {
                for unit in c.encode_utf16(&mut units) {
                    write!(w, "\\u{unit:04X}")?;
                }
            }
        }
        Ok(())
    }

    fn write_char_escape<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        escape: CharEscape,
    ) -> io::Result<()> {
        let text: &[u8] = match escape {
            CharEscape::Quote => b"\\\"",
            CharEscape::ReverseSolidus => b"\\\\",
            CharEscape::Solidus => b"\\/",
            CharEscape::Backspace => b"\\b",
            CharEscape::FormFeed => b"\\f",
            CharEscape::LineFeed => b"\\n",
            CharEscape::CarriageReturn => b"\\r",
            CharEscape::Tab => b"\\t",
            CharEscape::AsciiControl(byte) => return write!(w, "\\u{byte:04X}"),
        };
        w.write_all(text)
    }
}

/// Serialize `value` the way qemu-ga's JSON writer does.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    let mut ser = Serializer::with_formatter(&mut out, QemuFormatter);
    // Values built from serde_json::Value and derived structs cannot fail to
    // serialize into a Vec.
    value
        .serialize(&mut ser)
        .expect("serializing to memory cannot fail");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text(value: serde_json::Value) -> String {
        String::from_utf8(to_vec(&value)).unwrap()
    }

    #[test]
    fn separators_match_qemu() {
        assert_eq!(
            text(json!({"return": {"a": [1, 2], "b": {}}, "id": "x"})),
            r#"{"return": {"a": [1, 2], "b": {}}, "id": "x"}"#
        );
        assert_eq!(text(json!([])), "[]");
    }

    #[test]
    fn non_ascii_is_escaped_with_uppercase_hex() {
        let bs = '\\';
        let e_acute = char::from_u32(0xe9).unwrap().to_string();
        let grin = char::from_u32(0x1f600).unwrap().to_string();
        assert_eq!(text(json!(e_acute)), format!("\"{bs}u00E9\""));
        assert_eq!(text(json!(grin)), format!("\"{bs}uD83D{bs}uDE00\""));
        assert_eq!(text(json!("a\u{7f}b")), format!("\"a{bs}u007Fb\""));
        assert_eq!(
            text(json!("\u{1}\n\"\\")),
            format!("\"{bs}u0001{bs}n{bs}\"{bs}{bs}\"")
        );
    }
}
