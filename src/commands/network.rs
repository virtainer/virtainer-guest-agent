// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `guest-network-get-interfaces` and `guest-network-get-route`.
//!
//! Interfaces come from getifaddrs(3) in its order (links first, then IPv4,
//! then IPv6 addresses), MAC addresses from SIOCGIFHWADDR, counters from
//! /proc/net/dev. As in qemu-ga, an interface without any address carries
//! neither `ip-addresses` nor `statistics`.

use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use serde::Serialize;
use serde_json::Value;

use super::{no_args, to_value, Ctx};
use crate::qmp::{Args, QgaError, Reply};
use crate::sys;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Interface {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_addresses: Option<Vec<IpAddress>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    statistics: Option<Stats>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct IpAddress {
    ip_address: String,
    ip_address_type: &'static str,
    prefix: u32,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
struct Stats {
    rx_bytes: u64,
    rx_packets: u64,
    rx_errs: u64,
    rx_dropped: u64,
    tx_bytes: u64,
    tx_packets: u64,
    tx_errs: u64,
    tx_dropped: u64,
}

/// One interface's counters from /proc/net/dev.
fn parse_net_dev(text: &str, name: &str) -> Option<Stats> {
    text.lines().find_map(|line| {
        let (iface, counters) = line.trim_start().split_once(':')?;
        if iface != name {
            return None;
        }
        let v: Vec<u64> = counters
            .split_whitespace()
            .map(|n| n.parse().ok())
            .collect::<Option<_>>()?;
        (v.len() >= 16).then(|| Stats {
            rx_bytes: v[0],
            rx_packets: v[1],
            rx_errs: v[2],
            rx_dropped: v[3],
            tx_bytes: v[8],
            tx_packets: v[9],
            tx_errs: v[10],
            tx_dropped: v[11],
        })
    })
}

fn hardware_address(sock: &OwnedFd, name: &CStr) -> Option<String> {
    // SAFETY: ifreq is plain data.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.to_bytes()) {
        *dst = *src as libc::c_char;
    }
    // SAFETY: SIOCGIFHWADDR fills ifr.ifr_ifru.ifru_hwaddr.
    unsafe { sys::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR, &mut ifr) }.ok()?;
    // SAFETY: the union member written by SIOCGIFHWADDR.
    let data = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    Some(
        data[..6]
            .iter()
            .map(|b| format!("{:02x}", *b as u8))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Bit count of a netmask: the prefix length of a contiguous mask.
fn prefix_of(mask: &[u8]) -> u32 {
    mask.iter().map(|b| b.count_ones()).sum()
}

pub fn get_interfaces(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let net_dev = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    // SAFETY: plain socket(2); the fd is owned below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(QgaError::os("failed to create socket", &sys::last_error()));
    }
    // SAFETY: fd is a freshly created socket.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: head is a valid out-pointer; freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(QgaError::os("getifaddrs failed", &sys::last_error()));
    }
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor walks the list getifaddrs returned, which stays
        // valid until freeifaddrs.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let c_name = unsafe { CStr::from_ptr(ifa.ifa_name) };
        let name = c_name.to_string_lossy().into_owned();
        let index = match interfaces.iter().position(|i| i.name == name) {
            Some(index) => index,
            None => {
                interfaces.push(Interface {
                    hardware_address: hardware_address(&sock, c_name),
                    name: name.clone(),
                    ip_addresses: None,
                    statistics: None,
                });
                interfaces.len() - 1
            }
        };
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr points to a sockaddr whose family says its type;
        // the netmask has the same family.
        let address = unsafe {
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let addr: libc::sockaddr_in = read_sockaddr(ifa.ifa_addr);
                    let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                    let prefix = (!ifa.ifa_netmask.is_null()).then(|| {
                        let mask: libc::sockaddr_in = read_sockaddr(ifa.ifa_netmask);
                        prefix_of(&mask.sin_addr.s_addr.to_ne_bytes())
                    });
                    IpAddress {
                        ip_address: ip.to_string(),
                        ip_address_type: "ipv4",
                        prefix: prefix.unwrap_or(0),
                    }
                }
                libc::AF_INET6 => {
                    let addr: libc::sockaddr_in6 = read_sockaddr(ifa.ifa_addr);
                    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                    let prefix = (!ifa.ifa_netmask.is_null()).then(|| {
                        let mask: libc::sockaddr_in6 = read_sockaddr(ifa.ifa_netmask);
                        prefix_of(&mask.sin6_addr.s6_addr)
                    });
                    IpAddress {
                        ip_address: ip.to_string(),
                        ip_address_type: "ipv6",
                        prefix: prefix.unwrap_or(0),
                    }
                }
                _ => continue,
            }
        };
        let interface = &mut interfaces[index];
        interface
            .ip_addresses
            .get_or_insert_with(Vec::new)
            .push(address);
        if interface.statistics.is_none() {
            interface.statistics = parse_net_dev(&net_dev, &interface.name);
        }
    }
    // SAFETY: head came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(to_value(interfaces))
}

#[derive(Serialize, Default, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
struct Route {
    iface: String,
    destination: String,
    metric: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mask: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    irtt: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refcnt: Option<i64>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    use_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    desprefixlen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    srcprefixlen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nexthop: Option<String>,
    version: i64,
}

/// /proc/net/route stores IPv4 addresses as host-order hex words.
fn ipv4_hex(hex: &str) -> Option<String> {
    let word = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(word.to_le_bytes()).to_string())
}

fn ipv6_hex(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

fn parse_ipv4_routes(text: &str) -> Vec<Route> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 11 {
                return None;
            }
            let dec = |s: &str| s.parse::<i64>().ok();
            Some(Route {
                iface: f[0].to_string(),
                destination: ipv4_hex(f[1])?,
                gateway: Some(ipv4_hex(f[2])?),
                flags: Some(u64::from_str_radix(f[3], 16).ok()?),
                refcnt: Some(dec(f[4])?),
                use_count: Some(dec(f[5])?),
                metric: dec(f[6])?,
                mask: Some(ipv4_hex(f[7])?),
                mtu: Some(dec(f[8])?),
                window: Some(dec(f[9])?),
                irtt: Some(dec(f[10])?),
                version: 4,
                ..Route::default()
            })
        })
        .collect()
}

fn parse_ipv6_routes(text: &str) -> Vec<Route> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let hex = |s: &str| i64::from_str_radix(s, 16).ok();
            Some(Route {
                destination: ipv6_hex(f[0])?,
                desprefixlen: Some(hex(f[1])?.to_string()),
                source: Some(ipv6_hex(f[2])?),
                srcprefixlen: Some(hex(f[3])?.to_string()),
                nexthop: Some(ipv6_hex(f[4])?),
                metric: hex(f[5])?,
                refcnt: Some(hex(f[6])?),
                use_count: Some(hex(f[7])?),
                flags: Some(u64::from_str_radix(f[8], 16).ok()?),
                iface: f[9].to_string(),
                version: 6,
                ..Route::default()
            })
        })
        .collect()
}

pub fn get_route(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let v4 = std::fs::read_to_string("/proc/net/route");
    // Missing when IPv6 is disabled; that is not an error.
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
    let v4 = v4.map_err(|e| QgaError::os("open(\"/proc/net/route\")", &e))?;
    let mut routes = parse_ipv4_routes(&v4);
    routes.extend(parse_ipv6_routes(&v6));
    Ok(Value::from(
        routes.into_iter().map(to_value).collect::<Vec<_>>(),
    ))
}

/// # Safety
/// `p` must point to a complete `T` (its family says which); alignment is not
/// assumed.
unsafe fn read_sockaddr<T>(p: *const libc::sockaddr) -> T {
    std::ptr::read_unaligned(p.cast::<T>())
}

#[cfg(test)]
mod tests {
    #[test]
    fn sockaddr_is_read_without_alignment_assumptions() {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([10, 1, 2, 3]),
            },
            sin_zero: [0; 8],
        };
        let size = std::mem::size_of::<libc::sockaddr_in>();
        let mut bytes = vec![0u8; size + 1];
        // SAFETY: bytes has room for one sockaddr_in at offset 1.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&addr as *const libc::sockaddr_in).cast::<u8>(),
                bytes.as_mut_ptr().add(1),
                size,
            );
        }
        // SAFETY: the buffer holds a complete sockaddr_in at an odd address.
        let read: libc::sockaddr_in =
            unsafe { read_sockaddr(bytes.as_ptr().add(1).cast::<libc::sockaddr>()) };
        assert_eq!(read.sin_addr.s_addr, addr.sin_addr.s_addr);
    }

    use super::*;

    #[test]
    fn net_dev_counters() {
        let text = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n    lo: 100 2 0 0 0 0 0 0 100 2 0 0 0 0 0 0\n  eth0: 5 6 7 8 0 0 0 0 9 10 11 12 0 0 0 0\n";
        assert_eq!(
            parse_net_dev(text, "eth0"),
            Some(Stats {
                rx_bytes: 5,
                rx_packets: 6,
                rx_errs: 7,
                rx_dropped: 8,
                tx_bytes: 9,
                tx_packets: 10,
                tx_errs: 11,
                tx_dropped: 12,
            })
        );
        assert_eq!(parse_net_dev(text, "eth"), None);
    }

    #[test]
    fn ipv4_routes_decode_host_order_words() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        let routes = parse_ipv4_routes(text);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "0.0.0.0");
        assert_eq!(routes[0].gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(routes[0].flags, Some(3));
        assert_eq!(routes[0].metric, 100);
    }

    #[test]
    fn ipv6_routes() {
        let text = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n";
        let routes = parse_ipv6_routes(text);
        assert_eq!(routes[0].destination, "fe80::");
        assert_eq!(routes[0].desprefixlen.as_deref(), Some("64"));
        assert_eq!(routes[0].metric, 256);
        assert_eq!(routes[0].iface, "eth0");
    }

    #[test]
    fn loopback_is_listed_with_its_address() {
        let dir = tempfile::tempdir().unwrap();
        let agent = crate::agent::Agent::new(Default::default(), dir.path().to_path_buf());
        let mut ctx = Ctx::new(&agent);
        let reply = get_interfaces(&mut ctx, Args::new(Default::default())).unwrap();
        let lo = reply
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == "lo")
            .expect("lo exists");
        assert_eq!(lo["hardware-address"], "00:00:00:00:00:00");
        assert!(lo["ip-addresses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["ip-address"] == "127.0.0.1" && a["prefix"] == 8));
        assert!(lo["statistics"]["rx-bytes"].is_u64());
    }
}
