// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Windows network inventory through IP Helper; OS identity through CIM; the
//! WinRM HTTPS listener through WS-Management.

use crate::{
    qmp::{QgaError, Reply},
    sys,
    windows_support::{inventory, winrm},
};
use serde_json::json;
use std::{
    io,
    mem::{size_of, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_SOFTWARE_LOOPBACK,
        IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
    },
    System::Threading::{GetActiveProcessorCount, ALL_PROCESSOR_GROUPS},
};

fn query(code: &str, action: &str) -> Reply {
    let out = sys::ps(code, &json!({}), action, &[]).map_err(QgaError::generic)?;
    serde_json::from_slice(&out)
        .map_err(|_| QgaError::generic(format!("{action}: invalid inventory response")))
}
/// Counted across every processor group, so a guest with more than 64 vCPUs is whole.
pub fn vcpus() -> Reply {
    // SAFETY: no pointers; 0 means failure.
    let active = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
    if active == 0 {
        return Err(QgaError::os(
            "failed to count logical processors",
            &io::Error::last_os_error(),
        ));
    }
    Ok(inventory::logical_processors(active))
}
pub fn osinfo() -> Reply {
    query(
        r#"
$o=Get-CimInstance Win32_OperatingSystem;
[ordered]@{'kernel-name'='Windows';'kernel-release'=$o.Version;'kernel-version'=$o.BuildNumber;
'machine'='x86_64';'id'='mswindows';'name'=$o.Caption;'pretty-name'=$o.Caption;
'version'=$o.Version;'version-id'=$o.Version} | ConvertTo-Json -Compress
"#,
        "get OS info",
    )
}
pub fn winrm_https() -> Reply {
    let action = "get the WinRM HTTPS listener";
    let out = sys::ps(winrm::QUERY, &json!({}), action, &[]).map_err(QgaError::generic)?;
    winrm::reply(&out).map_err(|e| QgaError::generic(format!("{action}: {e}")))
}
pub fn interfaces() -> Reply {
    adapter_interfaces()
        .map_err(|error| QgaError::generic(format!("get network interfaces: {error}")))
}

fn adapter_interfaces() -> io::Result<serde_json::Value> {
    // Start with the API's recommended 15 KB. Typed storage supplies the alignment
    // required by the adapter structures, unlike a Vec<u8>.
    let mut size = 15_000u32;
    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    // An adapter can appear between calls and increase the required buffer size.
    for _ in 0..3 {
        let count = (size as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer = vec![MaybeUninit::<IP_ADAPTER_ADDRESSES_LH>::zeroed(); count];
        let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: head is aligned writable storage of at least size bytes. The
        // reserved pointer is null, and the size out-parameter lives for the call.
        let status = unsafe {
            GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, ptr::null(), head, &mut size)
        };
        match status {
            ERROR_BUFFER_OVERFLOW => continue,
            ERROR_NO_DATA => return Ok(json!([])),
            NO_ERROR => {}
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }

        let mut entries = Vec::new();
        let mut adapter = head;
        // SAFETY: on success the API returns linked adapter/unicast structures,
        // socket addresses and terminated UTF-16 names within buffer. The buffer
        // stays alive and is never resized while these pointers are traversed.
        // Supported Windows versions (Server 2019 / Windows 11 and later) provide
        // the LH layouts, including OnLinkPrefixLength.
        unsafe {
            while let Some(current) = adapter.as_ref() {
                adapter = current.Next;
                // Get-NetAdapter did not list software loopback.
                if current.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                    continue;
                }
                let mut name_len = 0;
                let name = if current.FriendlyName.is_null() {
                    &[]
                } else {
                    while *current.FriendlyName.add(name_len) != 0 {
                        name_len += 1;
                    }
                    std::slice::from_raw_parts(current.FriendlyName, name_len)
                };
                let mac = current
                    .PhysicalAddress
                    .get(..current.PhysicalAddressLength as usize)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid physical address length",
                        )
                    })?;
                let mut addresses = Vec::new();
                let mut unicast = current.FirstUnicastAddress;
                while let Some(ip) = unicast.as_ref() {
                    if let Some(address) = socket_address(ip.Address, ip.OnLinkPrefixLength) {
                        addresses.push(address);
                    }
                    unicast = ip.Next;
                }
                entries.push(inventory::interface(name, mac, addresses));
            }
        }
        return Ok(json!(entries));
    }
    Err(io::Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32))
}

/// The socket pointer must refer to iSockaddrLength readable bytes returned by
/// GetAdaptersAddresses, and its owning buffer must remain alive for this call.
unsafe fn socket_address(socket: SOCKET_ADDRESS, prefix: u8) -> Option<serde_json::Value> {
    if socket.lpSockaddr.is_null() || socket.iSockaddrLength < size_of::<u16>() as i32 {
        return None;
    }
    // SAFETY: the caller guarantees readable storage; each concrete structure is
    // read only after checking its size and family. Unaligned reads avoid imposing
    // additional alignment requirements on socket pointers within the API buffer.
    unsafe {
        let family = socket.lpSockaddr.cast::<u16>().read_unaligned();
        let (address, scope) = match family {
            AF_INET if socket.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 => {
                let ip = socket.lpSockaddr.cast::<SOCKADDR_IN>().read_unaligned();
                // S_addr stores network-order bytes, regardless of host endianness.
                (
                    IpAddr::V4(Ipv4Addr::from(ip.sin_addr.S_un.S_addr.to_ne_bytes())),
                    0,
                )
            }
            AF_INET6 if socket.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 => {
                let ip = socket.lpSockaddr.cast::<SOCKADDR_IN6>().read_unaligned();
                (
                    IpAddr::V6(Ipv6Addr::from(ip.sin6_addr.u.Byte)),
                    ip.Anonymous.sin6_scope_id,
                )
            }
            _ => return None,
        };
        Some(inventory::ip_address(address, scope, prefix))
    }
}
