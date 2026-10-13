// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! QGA network inventory formatting, independent of the Windows API.

use serde_json::{json, Value};
use std::net::IpAddr;

pub fn mac_address(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

pub fn ip_address(address: IpAddr, scope: u32, prefix: u8) -> Value {
    let (text, family) = match address {
        IpAddr::V4(ip) => (ip.to_string(), "ipv4"),
        IpAddr::V6(ip) => {
            let text = if ip.is_unicast_link_local() && scope != 0 {
                format!("{ip}%{scope}")
            } else {
                ip.to_string()
            };
            (text, "ipv6")
        }
    };
    json!({"ip-address": text, "ip-address-type": family, "prefix": prefix})
}

pub fn interface(name: &[u16], mac: &[u8], addresses: Vec<Value>) -> Value {
    let mut entry = json!({"name": String::from_utf16_lossy(name)});
    if let Some(mac) = mac_address(mac) {
        entry["hardware-address"] = json!(mac);
    }
    if !addresses.is_empty() {
        entry["ip-addresses"] = json!(addresses);
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_uses_lowercase_colons_and_keeps_leading_zeroes() {
        assert_eq!(mac_address(&[]), None);
        assert_eq!(
            mac_address(&[0, 1, 0x0a, 0xab, 0xcd, 0xff]).as_deref(),
            Some("00:01:0a:ab:cd:ff")
        );
        assert_eq!(mac_address(&[0x12, 0x34]).as_deref(), Some("12:34"));
    }

    #[test]
    fn address_families_keep_the_supplied_prefix() {
        for (text, family, prefixes) in [
            ("192.0.2.5", "ipv4", [0, 24, 32]),
            ("2001:db8::5", "ipv6", [0, 64, 128]),
        ] {
            for prefix in prefixes {
                assert_eq!(
                    ip_address(text.parse().unwrap(), 17, prefix),
                    json!({"ip-address": text, "ip-address-type": family, "prefix": prefix})
                );
            }
        }
    }

    #[test]
    fn link_local_ipv6_keeps_its_numeric_scope() {
        assert_eq!(
            ip_address("fe80::1234".parse().unwrap(), 12, 64),
            json!({"ip-address": "fe80::1234%12", "ip-address-type": "ipv6", "prefix": 64})
        );
        assert_eq!(
            ip_address("fe80::1234".parse().unwrap(), 0, 64)["ip-address"],
            "fe80::1234"
        );
    }

    #[test]
    fn interface_shape_omits_empty_optional_members() {
        let name: Vec<_> = "以太网 🖧".encode_utf16().collect();
        assert_eq!(interface(&name, &[], vec![]), json!({"name": "以太网 🖧"}));
        let ip = ip_address("192.0.2.5".parse().unwrap(), 0, 24);
        assert_eq!(
            json!([interface(
                &name,
                &[0x52, 0x54, 0, 0xab, 0xcd, 0xef],
                vec![ip]
            )]),
            json!([{
                "name": "以太网 🖧",
                "hardware-address": "52:54:00:ab:cd:ef",
                "ip-addresses": [{
                    "ip-address": "192.0.2.5", "ip-address-type": "ipv4", "prefix": 24
                }]
            }])
        );
        assert_eq!(
            interface(&[], &[0, 1], vec![]),
            json!({"name": "", "hardware-address": "00:01"})
        );
    }
}
