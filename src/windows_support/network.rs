// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Partition a validated network request into the shared DHCP reset and static
//! configuration paths. Adapter lookup and cmdlets remain Windows-only.

use super::provision::Network;
use serde_json::{json, Value};

pub fn plan(network: &[Network]) -> Value {
    let dhcp: Vec<_> = network
        .iter()
        .filter(|n| n.addresses.is_empty())
        .map(|n| &n.mac)
        .collect();
    let statics: Vec<_> = network
        .iter()
        .filter(|n| !n.addresses.is_empty())
        .map(|n| json!({"mac":n.mac,"addresses":n.addresses,"gateway":n.gateway,"dns":n.dns}))
        .collect();
    json!({"dhcp_all":network.is_empty(),"dhcp_macs":dhcp,"static":statics})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_support::provision::Provision;

    #[test]
    fn empty_and_mac_selected_dhcp_share_the_reset_path_without_touching_static_adapters() {
        let make = |network| {
            Provision::parse(
                &serde_json::to_vec(&json!({
                    "schema":1,"instance_id":"00000000-0000-4000-8000-000000000001",
                    "seed_version":"a".repeat(64),"network":network
                }))
                .unwrap(),
            )
            .unwrap()
        };
        let empty = make(json!([]));
        assert_eq!(
            plan(&empty.network),
            json!({"dhcp_all":true,"dhcp_macs":[],"static":[]})
        );
        let selected = make(json!([
            {"mac":"52:54:00:aa:bb:cc","addresses":[],"dns":["2001:db8::53"]},
            {"mac":"52:54:00:aa:bb:dd","addresses":["2001:db8::2/64"],"gateway":"2001:db8::1","dns":["2001:db8::53"]}
        ]));
        let plan = plan(&selected.network);
        assert_eq!(plan["dhcp_all"], false);
        assert_eq!(plan["dhcp_macs"], json!(["52:54:00:aa:bb:cc"]));
        assert_eq!(
            plan["static"],
            json!([
                {"mac":"52:54:00:aa:bb:dd","addresses":["2001:db8::2/64"],"gateway":"2001:db8::1","dns":["2001:db8::53"]}
            ])
        );
    }
}
