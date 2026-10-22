// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `__io.virtainer_winrm_https`: the WinRM HTTPS listener and the
//! certificate it is bound to, so that a client can pin that certificate.
//!
//! PowerShell reads the listener from WS-Management and the certificate from
//! the LocalMachine\My store; the subject alternative names are read here
//! from the certificate itself, because Windows renders them localized.

use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const NAME: &str = "__io.virtainer_winrm_https";

/// Writes `null` when the WinRM service is not running or has no enabled HTTPS
/// listener; otherwise the listener, and the certificate when the store has
/// the one the listener names.
pub const QUERY: &str = r#"
$s = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($null -eq $s -or "$($s.Status)" -ne 'Running') { 'null'; return }
$l = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate | Where-Object { "$($_.Transport)" -eq 'HTTPS' -and "$($_.Enabled)" -eq 'true' }) | Select-Object -First 1
if ($null -eq $l) { 'null'; return }
$t = "$($l.CertificateThumbprint)" -replace '[^0-9A-Fa-f]', ''
$c = $null
if ($t) { $c = Get-Item -LiteralPath "Cert:\LocalMachine\My\$t" -ErrorAction SilentlyContinue }
$o = [ordered]@{ port = [int]$l.Port; hostname = "$($l.Hostname)"; sha256 = $null; not_after = $null; der = $null }
if ($null -ne $c) {
    $h = [Security.Cryptography.SHA256]::Create()
    $o.sha256 = ([BitConverter]::ToString($h.ComputeHash($c.RawData)) -replace '-', '').ToLowerInvariant()
    $o.not_after = $c.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $o.der = [Convert]::ToBase64String($c.RawData)
}
$o | ConvertTo-Json -Compress
"#;

#[derive(Deserialize)]
struct Listener {
    port: u16,
    hostname: String,
    sha256: Option<String>,
    not_after: Option<String>,
    der: Option<String>,
}

/// The QAPI reply for the helper's output.
pub fn reply(output: &[u8]) -> Result<Value, String> {
    let listener: Option<Listener> = serde_json::from_slice(output)
        .map_err(|_| "invalid WinRM listener response".to_string())?;
    let Some(listener) = listener else {
        return Ok(Value::Null);
    };
    let certificate = match (listener.sha256, listener.not_after, listener.der) {
        (Some(sha256), Some(not_after), Some(der)) => {
            let der = base64::engine::general_purpose::STANDARD
                .decode(der)
                .map_err(|_| "invalid WinRM certificate encoding".to_string())?;
            let names = subject_alt_names(&der)
                .ok_or_else(|| "unreadable WinRM certificate".to_string())?;
            json!({
                "sha256": sha256,
                "not-after": not_after,
                "dns-names": names.dns,
                "ip-addresses": names.ip,
            })
        }
        _ => Value::Null,
    };
    Ok(json!({
        "port": listener.port,
        "hostname": listener.hostname,
        "certificate": certificate,
    }))
}

#[derive(Debug, Default, PartialEq)]
struct Names {
    dns: Vec<String>,
    ip: Vec<String>,
}

/// One DER element: tag, contents, and what follows it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |len, &b| len << 8 | usize::from(b));
        (len, &rest[count..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

fn expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, body, rest) = element(input)?;
    (found == tag).then_some((body, rest))
}

const SEQUENCE: u8 = 0x30;
const EXTENSIONS: u8 = 0xa3;
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const DNS_NAME: u8 = 0x82;
const IP_ADDRESS: u8 = 0x87;

/// DNS names and IP addresses of the certificate's subjectAltName extension;
/// empty lists when it has none, `None` when the certificate is malformed.
fn subject_alt_names(der: &[u8]) -> Option<Names> {
    let (certificate, _) = expect(der, SEQUENCE)?;
    let (mut tbs, _) = expect(certificate, SEQUENCE)?;
    let mut names = Names::default();
    while !tbs.is_empty() {
        let (tag, body, rest) = element(tbs)?;
        tbs = rest;
        if tag != EXTENSIONS {
            continue;
        }
        let (mut extensions, _) = expect(body, SEQUENCE)?;
        while !extensions.is_empty() {
            let (extension, rest) = expect(extensions, SEQUENCE)?;
            extensions = rest;
            let (oid, mut value) = expect(extension, 0x06)?;
            if oid != SUBJECT_ALT_NAME {
                continue;
            }
            if let Some((_, rest)) = expect(value, 0x01) {
                value = rest; // critical
            }
            let (octets, _) = expect(value, 0x04)?;
            let (mut general_names, _) = expect(octets, SEQUENCE)?;
            while !general_names.is_empty() {
                let (tag, body, rest) = element(general_names)?;
                general_names = rest;
                match (tag, body.len()) {
                    (DNS_NAME, _) => names.dns.push(String::from_utf8(body.to_vec()).ok()?),
                    (IP_ADDRESS, 4) => {
                        let octets: [u8; 4] = body.try_into().ok()?;
                        names.ip.push(Ipv4Addr::from(octets).to_string());
                    }
                    (IP_ADDRESS, 16) => {
                        let octets: [u8; 16] = body.try_into().ok()?;
                        names.ip.push(Ipv6Addr::from(octets).to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    Some(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// openssl req -x509 -subj /CN=WIN-TEST1
    ///   -addext subjectAltName=DNS:WIN-TEST1,IP:10.0.0.5,IP:fd00::5
    const CERTIFICATE: &str = concat!(
        "MIIDWzCCAkOgAwIBAgIUTGljcSv5IJymXuikBb84vYG+9D0wDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJV0lOLVRFU1Qx",
        "MB4XDTI2MTAxODE1MzY1NloXDTI3MTAxODE1MzY1NlowFDESMBAGA1UEAwwJV0lOLVRFU1QxMIIBIjANBgkqhkiG9w0BAQEF",
        "AAOCAQ8AMIIBCgKCAQEAlMFsmnR4S72AV/x+afTYd+iylyEARwzvK1CuEXD+zD0I2sfUJXmEBGFVMRNCz5bmVFcE147Jmh37",
        "q5+dyNcP7T9u2whhMZ7BT5zEE7KcKK4+91sjzpJU9diGNRsY0l/XLWxuJ3wy7nfTRjFi6cPJFcCbSFUmE08XLD7ki+HZuKPk",
        "oQgfwiahnmkAL3N4OihTWXBnIg+yZFn/sz0EgUrwREzgcnes1Dey4g+3g/Kod0XmIACMw8zhlYv+DbxKRD3/sX6WWy5ql2SN",
        "906T9lutzoGnFEBUVYnQDFMUX8d8fdNMdycIkoHXJlBixwvN8ZN1kHkNMbVLsgUUnca6h/Ny8QIDAQABo4GkMIGhMB0GA1Ud",
        "DgQWBBQQRS5vtOWnFZ6Nt9BU+gIKV0XR6DAfBgNVHSMEGDAWgBQQRS5vtOWnFZ6Nt9BU+gIKV0XR6DAPBgNVHRMBAf8EBTAD",
        "AQH/MCwGA1UdEQQlMCOCCVdJTi1URVNUMYcECgAABYcQ/QAAAAAAAAAAAAAAAAAABTALBgNVHQ8EBAMCBaAwEwYDVR0lBAww",
        "CgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAJMdXTMVCWyFw9A7fpQ96UclZ+0AAo2iQPrnoOE72N7NNiz8MbQhVSRB",
        "VXgycmExYIvwWDbqWFAi+J8cxscawYvqozvahkhkMitLwCzw3+Q8udJG9TgKpyCdLukudrnCiMy4298v1zrJWy0vBSjgki88",
        "WydJqeCB0deFdEHMSIN/ySHHhbO7Qw6270gZVoi2VX2YtqB9QjzAvffPxyU8r5RLFw107uBgN2hSgimTAit9RuJKU3xFwPcf",
        "W6N+SkRg06h4oM9t6w/eMaUOkrErGV/UCsPcq3Zgk0YgLJXyKd6TDI1OeBqn6qWZrz9ZlH5PXqCNv2lU2qV+9LVpKuEAIS0=",
    );

    #[test]
    fn names_come_from_the_subject_alt_name_extension() {
        let der = base64::engine::general_purpose::STANDARD
            .decode(CERTIFICATE)
            .unwrap();
        assert_eq!(
            subject_alt_names(&der),
            Some(Names {
                dns: vec!["WIN-TEST1".into()],
                ip: vec!["10.0.0.5".into(), "fd00::5".into()],
            })
        );
        assert_eq!(subject_alt_names(&der[..200]), None);
        assert_eq!(subject_alt_names(&[]), None);
    }

    #[test]
    fn reply_reports_the_listener_and_its_certificate() {
        let output = json!({
            "port": 5986, "hostname": "WIN-TEST1",
            "sha256": "e298d4be182e6fcc146856d156ef50514390dfe07db0c557b3b22d9f44d2ead1",
            "not_after": "2027-10-18T15:36:56Z", "der": CERTIFICATE,
        });
        assert_eq!(
            reply(output.to_string().as_bytes()).unwrap(),
            json!({
                "port": 5986, "hostname": "WIN-TEST1",
                "certificate": {
                    "sha256": "e298d4be182e6fcc146856d156ef50514390dfe07db0c557b3b22d9f44d2ead1",
                    "not-after": "2027-10-18T15:36:56Z",
                    "dns-names": ["WIN-TEST1"],
                    "ip-addresses": ["10.0.0.5", "fd00::5"],
                },
            })
        );
    }

    #[test]
    fn no_listener_and_a_missing_certificate_are_null() {
        assert_eq!(reply(b"null\r\n").unwrap(), Value::Null);
        let missing = json!({"port": 5986, "hostname": "WIN-TEST1", "sha256": null, "not_after": null, "der": null});
        assert_eq!(
            reply(missing.to_string().as_bytes()).unwrap(),
            json!({"port": 5986, "hostname": "WIN-TEST1", "certificate": null})
        );
        assert!(reply(b"").is_err());
        let bad =
            json!({"port": 5986, "hostname": "x", "sha256": "00", "not_after": "x", "der": "AAAA"});
        assert!(reply(bad.to_string().as_bytes()).is_err());
    }
}
