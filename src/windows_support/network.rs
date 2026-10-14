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

    /// The script cannot run without Windows, so these pin the structure that
    /// the behaviour depends on.
    #[test]
    fn script_waits_for_the_interface_and_keeps_an_existing_dhcp_configuration() {
        let ps = include_str!("../windows/network.ps1");
        // Bounded wait: 60 s, polled every 2 s, one deadline for the script.
        assert!(ps.contains("$netIpWaitSeconds = 60"));
        assert!(ps.contains("$netIpPollSeconds = 2"));
        assert!(ps.contains("Start-Sleep -Seconds $netIpPollSeconds"));
        assert!(ps.contains("if ((Get-Date) -ge $script:netIpDeadline) {"));
        assert!(ps.contains("return $null"));
        // Only a not-found result is absence; other errors are thrown, and
        // the lookup never suppresses errors or matches message text.
        let wait_fn = &ps[ps.find("function Wait-VirtainerNetIPInterface").unwrap()
            ..ps.find("function Reset-VirtainerDhcp").unwrap()];
        assert!(wait_fn.contains("-ErrorAction Stop"));
        assert!(!wait_fn.contains("SilentlyContinue"));
        assert!(ps.contains("CmdletizationQuery_NotFound*"));
        assert!(ps.contains("-eq 'ObjectNotFound'"));
        assert!(wait_fn.contains("if ($failure) { throw $failure }"));
        assert!(!wait_fn.contains("$_.Exception.Message"));
        // DHCP: an interface that never appears is skipped with a warning.
        let dhcp =
            &ps[ps.find("function Reset-VirtainerDhcp").unwrap()..ps.find("$adapters = ").unwrap()];
        let wait = dhcp
            .find("Wait-VirtainerNetIPInterface $index $family")
            .unwrap();
        let skip = dhcp.find("continue").unwrap();
        let first_set = dhcp.find("Set-NetIPInterface").unwrap();
        assert!(wait < skip && skip < first_set);
        assert!(dhcp.contains("Write-VirtainerWarning"));
        assert!(!dhcp.contains("elseif (-not $current)"));
        assert!(dhcp.contains("if ($current.Dhcp -ne 'Enabled')"));
        // DHCP: an interface that already has DHCP keeps its addresses and
        // routes, so the gateway its lease installed (reported as NetMgmt)
        // survives. Only a switch from static removes the manual addresses
        // and the static default route, then enables DHCP and renews.
        let switch = dhcp.find("if ($current.Dhcp -ne 'Enabled') {").unwrap();
        let switch_end = switch + dhcp[switch..].find("\n        }\n").unwrap();
        let switching = &dhcp[switch..switch_end];
        for removal in ["Remove-NetIPAddress", "Remove-NetRoute"] {
            assert_eq!(dhcp.matches(removal).count(), 1, "{removal}");
            assert!(switching.contains(removal), "{removal}");
        }
        let enable = switching
            .find("Set-NetIPInterface -InterfaceIndex $index -AddressFamily $family -Dhcp Enabled")
            .unwrap();
        assert!(switching.find("Remove-NetRoute").unwrap() < enable);
        assert!(switching.find("Remove-NetIPAddress").unwrap() < enable);
        assert!(switching.contains("$renew = $current.InterfaceAlias"));
        assert!(switching.contains("Where-Object { $_.Protocol -eq 'NetMgmt' }"));
        // Router discovery is still enabled for IPv6 either way.
        assert!(dhcp[switch_end..]
            .contains("Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -RouterDiscovery Enabled"));
        // Both DHCP selections, all hardware adapters and by MAC, take this
        // path; nothing else outside the static branch removes routes.
        let selection = &ps
            [ps.find("if ($p.dhcp_all) {").unwrap()..ps.find("foreach ($n in $p.static)").unwrap()];
        assert_eq!(selection.matches("Reset-VirtainerDhcp").count(), 2);
        assert!(!selection.contains("Remove-Net"));
        assert_eq!(ps.matches("Remove-NetRoute").count(), 2);
        // Static: the interface is required, naming the MAC and family.
        let statics = &ps[ps.find("foreach ($n in $p.static)").unwrap()..];
        let require = statics
            .find("Require-VirtainerNetIPInterface $index $n.mac $family")
            .unwrap();
        assert!(require < statics.find("Set-NetIPInterface").unwrap());
        assert!(ps.contains("adapter {0} has no {1} interface; cannot apply the requested static"));
        // Every Set-NetIPInterface is behind a lookup; none is unconditional.
        assert_eq!(ps.matches("Set-NetIPInterface").count(), 4);
    }
}
