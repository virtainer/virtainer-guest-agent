// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! PowerShell helper failure reporting: the fixed wrapper turns a terminating
//! error into one marker line, and the agent keeps a bounded, scrubbed detail.

/// Prefix of the single line a failing helper writes to stdout.
pub const MARKER: &str = "VIRTAINER-HELPER-ERROR";
/// Longest detail kept in a provisioning error or log line, in characters.
const MAX_DETAIL: usize = 300;

/// Wrap fixed helper code so that a terminating error is reported as
/// `MARKER|category|error id|message` before a nonzero exit.
pub fn wrap(code: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); \
         [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); \
         try {{ $p=[Console]::In.ReadToEnd() | ConvertFrom-Json; {code}\n}} \
         catch {{ $e=$_; [Console]::Out.WriteLine('{MARKER}|' + [string]$e.CategoryInfo.Category + '|' + \
         [string]$e.FullyQualifiedErrorId + '|' + ([string]$e.Exception.Message -replace '[\\r\\n]+',' ')); exit 1 }}"
    )
}

/// Extract the failure detail from a failed helper's stdout, if it wrote one.
/// Every occurrence of a secret is replaced, control characters and runs of
/// whitespace collapse to one space, and the result is length-bounded.
pub fn failure_detail(stdout: &[u8], secrets: &[&str]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix(MARKER)?.strip_prefix('|'))?;
    let mut line = line.to_string();
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        line = line.replace(secret, "***");
    }
    let mut fields = line.splitn(3, '|').map(clean);
    let (category, id, message) = (fields.next()?, fields.next()?, fields.next()?);
    let detail = [category, id, message]
        .into_iter()
        .filter(|f| !f.is_empty())
        .collect::<Vec<_>>()
        .join(": ");
    if detail.is_empty() {
        return None;
    }
    Some(bound(&detail))
}

fn clean(field: &str) -> String {
    field
        .split(|c: char| c.is_control() || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn bound(text: &str) -> String {
    if text.chars().count() <= MAX_DETAIL {
        return text.to_string();
    }
    let mut kept: String = text.chars().take(MAX_DETAIL).collect();
    kept.push_str("...");
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_category_error_id_and_message() {
        let out = b"VIRTAINER-HELPER-ERROR|NotSpecified|Windows System Error 1722,Set-NetIPInterface|The RPC server is unavailable.\r\n";
        assert_eq!(
            failure_detail(out, &[]).unwrap(),
            "NotSpecified: Windows System Error 1722,Set-NetIPInterface: The RPC server is unavailable."
        );
    }

    #[test]
    fn message_may_contain_the_separator() {
        let out = b"VIRTAINER-HELPER-ERROR|InvalidArgument|X|a|b|c\n";
        assert_eq!(
            failure_detail(out, &[]).unwrap(),
            "InvalidArgument: X: a|b|c"
        );
    }

    #[test]
    fn ignores_output_without_a_marker_line() {
        assert_eq!(failure_detail(b"some query output\n", &[]), None);
        assert_eq!(failure_detail(b"", &[]), None);
        assert_eq!(
            failure_detail(b"VIRTAINER-HELPER-ERRORX|a|b|c\n", &[]),
            None
        );
    }

    #[test]
    fn the_last_marker_line_wins() {
        let out = b"VIRTAINER-HELPER-ERROR|A|B|first\nVIRTAINER-HELPER-ERROR|C|D|second\n";
        assert_eq!(failure_detail(out, &[]).unwrap(), "C: D: second");
    }

    #[test]
    fn secrets_never_survive() {
        let out =
            b"VIRTAINER-HELPER-ERROR|InvalidData|E|password 'Hunter2 x' rejected, Hunter2 x\n";
        let detail = failure_detail(out, &["Hunter2 x"]).unwrap();
        assert!(!detail.contains("Hunter2"));
        assert!(detail.contains("***"));
    }

    #[test]
    fn control_characters_and_whitespace_collapse() {
        let out = "VIRTAINER-HELPER-ERROR|A|B|one\t\ttwo\u{1b}[31m  three\n".as_bytes();
        let detail = failure_detail(out, &[]).unwrap();
        assert_eq!(detail, "A: B: one two [31m three");
    }

    #[test]
    fn detail_is_bounded_on_a_character_boundary() {
        let long = "é".repeat(1000);
        let out = format!("VIRTAINER-HELPER-ERROR|A|B|{long}\n");
        let detail = failure_detail(out.as_bytes(), &[]).unwrap();
        assert!(detail.chars().count() <= MAX_DETAIL + 3);
        assert!(detail.ends_with("..."));
    }

    #[test]
    fn wrapper_catches_errors_and_keeps_code_inside_the_try() {
        let script = wrap("Get-Thing");
        assert!(script.contains("try { $p="));
        assert!(script.contains("Get-Thing\n} catch"));
        assert!(script.contains(MARKER));
        assert!(script.contains("exit 1"));
    }
}
