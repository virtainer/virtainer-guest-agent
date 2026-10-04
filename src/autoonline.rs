// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Ant Financial
// Copyright 2026 The Virtainer authors (modifications)
//
// Derived from Kata Containers 4.2.0, src/agent/src/uevent.rs (uevent parsing
// and the NETLINK_KOBJECT_UEVENT listener) and src/agent/src/sandbox.rs
// (onlining offline CPUs and memory blocks through sysfs). Changes: std
// threads instead of tokio and netlink-sys; no sandbox state or watchers;
// hot-added CPUs are onlined on their own `add` event instead of on an
// OnlineCPUMem request; only messages from the kernel are accepted.

//! Bring hot-added vCPUs and memory online.
//!
//! Cloud Hypervisor hot-adds vCPUs and memory through ACPI. The kernel never
//! onlines a hot-added CPU by itself, and whether memory comes online depends
//! on the kernel config. Only the RHEL and SUSE families ship udev rules for
//! this; on Ubuntu, Debian, Fedora, Arch and Alpine a resized VM keeps its new
//! vCPUs offline. The agent does what those udev rules do: on the kernel's
//! `add` event for a CPU or memory block, online it. Devices present when the
//! agent starts are left alone, so a CPU an administrator took offline stays
//! offline across agent restarts.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use crate::sys;

const NETLINK_KOBJECT_UEVENT: i32 = 15;
/// The kernel's uevent multicast group (udev rebroadcasts on group 2).
const KERNEL_GROUP: u32 = 1;

#[derive(Debug, Default, PartialEq, Eq)]
struct Uevent {
    action: String,
    devpath: String,
    subsystem: String,
}

impl Uevent {
    /// `action@devpath\0KEY=value\0KEY=value...`
    fn parse(message: &[u8]) -> Self {
        let mut event = Uevent::default();
        for field in message.split(|b| *b == 0).skip(1) {
            let field = String::from_utf8_lossy(field);
            match field.split_once('=') {
                Some(("ACTION", v)) => event.action = v.to_string(),
                Some(("DEVPATH", v)) => event.devpath = v.to_string(),
                Some(("SUBSYSTEM", v)) => event.subsystem = v.to_string(),
                _ => {}
            }
        }
        event
    }
}

fn listen() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the fd is owned right below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_KOBJECT_UEVENT,
        )
    };
    if fd < 0 {
        return Err(sys::last_error());
    }
    // SAFETY: fd was just created.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zeroed sockaddr_nl is valid; family and groups set below.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = KERNEL_GROUP;
    // SAFETY: addr is a valid sockaddr_nl of the given size.
    let rc = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(sys::last_error());
    }
    Ok(socket)
}

/// Write `value` to the device's sysfs `file` while it still reads
/// `offline_value`. A failed write is only reported if the device is still
/// offline afterwards: the kernel may online memory itself between the event
/// and our write.
fn online(devpath: &str, file: &str, offline_value: &str, value: &str) {
    let path = Path::new("/sys")
        .join(devpath.trim_start_matches('/'))
        .join(file);
    let Ok(current) = std::fs::read_to_string(&path) else {
        return;
    };
    if current.trim() != offline_value {
        return;
    }
    match std::fs::write(&path, value) {
        Ok(()) => crate::info!(
            "onlined hot-added {}",
            devpath.rsplit('/').next().unwrap_or(devpath)
        ),
        Err(e) => {
            if std::fs::read_to_string(&path).is_ok_and(|now| now.trim() == offline_value) {
                crate::warning!("cannot online hot-added {devpath}: {e}");
            }
        }
    }
}

fn handle(event: &Uevent) {
    if event.action != "add" {
        return;
    }
    match event.subsystem.as_str() {
        "cpu" if event.devpath.starts_with("/devices/system/cpu/cpu") => {
            online(&event.devpath, "online", "0", "1")
        }
        "memory" if event.devpath.starts_with("/devices/system/memory/memory") => {
            online(&event.devpath, "state", "offline", "online")
        }
        _ => {}
    }
}

/// Runs on its own thread for the life of the agent.
pub fn watch() {
    let socket = match listen() {
        Ok(socket) => socket,
        Err(e) => {
            crate::warning!("cannot watch for CPU and memory hot-add: {e}");
            return;
        }
    };
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        // SAFETY: zeroed sockaddr_nl is a valid out-parameter.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: buf, sender and len are valid for the call.
        let n = unsafe {
            libc::recvfrom(
                socket.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&mut sender as *mut libc::sockaddr_nl).cast(),
                &mut len,
            )
        };
        if n < 0 {
            let e = sys::last_error();
            match e.raw_os_error() {
                // ENOBUFS: a burst overflowed the socket; later events still come.
                Some(libc::EINTR | libc::ENOBUFS) => continue,
                _ => {
                    crate::warning!("stopped watching for hot-add: {e}");
                    return;
                }
            }
        }
        // Only the kernel (port 0) may tell us a device appeared.
        if sender.nl_pid != 0 {
            continue;
        }
        handle(&Uevent::parse(&buf[..n as usize]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_uevent_fields() {
        let msg = b"add@/devices/system/cpu/cpu4\0ACTION=add\0DEVPATH=/devices/system/cpu/cpu4\0SUBSYSTEM=cpu\0SEQNUM=4242\0";
        assert_eq!(
            Uevent::parse(msg),
            Uevent {
                action: "add".into(),
                devpath: "/devices/system/cpu/cpu4".into(),
                subsystem: "cpu".into(),
            }
        );
    }

    #[test]
    fn unrelated_events_are_ignored() {
        // Must not touch sysfs for a block device or a removal.
        handle(&Uevent {
            action: "add".into(),
            devpath: "/devices/virtual/block/loop0".into(),
            subsystem: "block".into(),
        });
        handle(&Uevent {
            action: "remove".into(),
            devpath: "/devices/system/cpu/cpu9".into(),
            subsystem: "cpu".into(),
        });
    }
}
