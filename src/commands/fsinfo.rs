// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `guest-get-fsinfo` and `guest-get-disks`: which disks back which mounts.
//!
//! The PCI address is how a host maps a guest mount to one of its disks. It
//! comes from the device's sysfs path; device nodes come from the `uevent`
//! file and serials and device-mapper names from udev's database in
//! /run/udev/data, which is what libudev itself reads. No libudev, so the
//! static binary works on every distro. NVMe disks also get their SMART log
//! (nvme.rs).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use super::mounts::{local_mounts, Mount};
use super::{no_args, to_value, Ctx};
use crate::qmp::{Args, QgaError, Reply};
use crate::sys;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct PciAddress {
    domain: i64,
    bus: i64,
    slot: i64,
    function: i64,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
struct DiskAddress {
    pci_controller: PciAddress,
    bus_type: &'static str,
    bus: i64,
    target: i64,
    unit: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dev: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct FilesystemInfo {
    name: String,
    mountpoint: String,
    #[serde(rename = "type")]
    fstype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_bytes_privileged: Option<u64>,
    disk: Vec<DiskAddress>,
}

#[derive(Serialize)]
struct DiskInfo {
    name: String,
    partition: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<DiskAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    smart: Option<Value>,
}

/// `/dev/<DEVNAME>` from a sysfs device's uevent file.
fn devnode(syspath: &Path) -> Option<String> {
    let uevent = fs::read_to_string(syspath.join("uevent")).ok()?;
    uevent
        .lines()
        .find_map(|l| l.strip_prefix("DEVNAME="))
        .map(|name| format!("/dev/{name}"))
}

/// A property udev recorded for a block device (`E:KEY=value`).
fn udev_property(syspath: &Path, key: &str) -> Option<String> {
    let dev = fs::read_to_string(syspath.join("dev")).ok()?;
    let db = fs::read_to_string(format!("/run/udev/data/b{}", dev.trim())).ok()?;
    let prefix = format!("E:{key}=");
    db.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn hex(s: &str) -> Option<i64> {
    i64::from_str_radix(s, 16).ok()
}

/// `dddd:bb:ss.f` at the start of `s`, and the length it used.
fn pci_component(s: &str) -> Option<(PciAddress, usize)> {
    let end = s.find('/').unwrap_or(s.len());
    let text = &s[..end];
    let (domain, rest) = text.split_once(':')?;
    let (bus, rest) = rest.split_once(':')?;
    let (slot, function) = rest.split_once('.')?;
    Some((
        PciAddress {
            domain: hex(domain)?,
            bus: hex(bus)?,
            slot: hex(slot)?,
            function: hex(function)?,
        },
        end,
    ))
}

/// The three numbers after `host:` in `/targetH:C:I/H:C:I:L`.
fn scsi_target(syspath: &str) -> Option<[i64; 3]> {
    let at = syspath.find("/target")?;
    let rest = &syspath[at + 7..];
    let (_, after) = rest.split_once('/')?;
    let hctl = after.split('/').next()?;
    let parts: Vec<i64> = hctl
        .split(':')
        .map(|n| n.parse().ok())
        .collect::<Option<_>>()?;
    (parts.len() == 4).then(|| [parts[1], parts[2], parts[3]])
}

/// Position of `host`'s number among the sorted `ataN`/`hostN` siblings.
fn host_index(syspath: &str, marker_at: usize, ata: bool) -> Option<i64> {
    let prefix = if ata { "ata" } else { "host" };
    let digits: String = syspath[marker_at + 1 + prefix.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let host: i64 = digits.parse().ok()?;
    let mut hosts: Vec<i64> = fs::read_dir(&syspath[..marker_at])
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str()?.strip_prefix(prefix)?.parse().ok())
        .collect();
    hosts.sort_unstable();
    hosts.iter().position(|h| *h == host).map(|i| i as i64)
}

const KNOWN_DRIVERS: &[&str] = &[
    "ata_piix",
    "sym53c8xx",
    "virtio-pci",
    "ahci",
    "nvme",
    "xhci_hcd",
    "ehci-pci",
];

/// Fill in a disk behind a PCI controller. Walks down nested PCI devices
/// (bridges, root ports) until one is bound to a storage driver we know.
fn pci_disk(syspath: &str, disk: &mut DiskAddress) -> bool {
    let Some(start) = syspath.find("/devices/pci") else {
        return false;
    };
    // Skip the root complex name (`pci0000:00/`).
    let Some(slash) = syspath[start + 12..].find('/') else {
        return false;
    };
    let mut cursor = start + 12 + slash + 1;
    let (driver, pci) = loop {
        let Some((pci, len)) = pci_component(&syspath[cursor..]) else {
            return false;
        };
        cursor += len;
        let driver = fs::read_link(format!("{}/driver", &syspath[..cursor]))
            .ok()
            .and_then(|l| l.file_name()?.to_str().map(str::to_string));
        if let Some(driver) = driver.filter(|d| KNOWN_DRIVERS.contains(&d.as_str())) {
            break (driver, pci);
        }
        if !syspath[cursor..].starts_with('/') {
            return false;
        }
        cursor += 1;
    };
    let target = scsi_target(syspath);
    let host = match syspath.find("/ata") {
        Some(at) => Some((at, true)),
        None => syspath.find("/host").map(|at| (at, false)),
    }
    .and_then(|(at, ata)| host_index(syspath, at, ata));

    disk.pci_controller = pci;
    match (driver.as_str(), host, target) {
        ("ata_piix", Some(host), Some(t)) => {
            disk.bus_type = "ide";
            disk.bus = host;
            disk.unit = t[1];
        }
        ("sym53c8xx", _, Some(t)) => {
            disk.bus_type = "scsi";
            disk.unit = t[1];
        }
        ("virtio-pci", _, Some(t)) => {
            disk.bus_type = "scsi";
            disk.unit = t[2];
        }
        ("virtio-pci", _, None) => disk.bus_type = "virtio",
        ("ahci", Some(host), Some(_)) => {
            disk.bus_type = "sata";
            disk.unit = host;
        }
        ("nvme", _, _) => disk.bus_type = "nvme",
        ("xhci_hcd" | "ehci-pci", _, _) => disk.bus_type = "usb",
        _ => return false,
    }
    true
}

/// virtio over MMIO or CCW: no PCI address to report.
fn nonpci_virtio_disk(syspath: &str, disk: &mut DiskAddress) -> bool {
    if !syspath.contains("/block") {
        return false;
    }
    match scsi_target(syspath) {
        Some(t) => {
            disk.bus_type = "scsi";
            disk.bus = t[0];
            disk.target = t[1];
            disk.unit = t[2];
        }
        None => disk.bus_type = "virtio",
    }
    true
}

fn real_device(syspath: &Path) -> Option<DiskAddress> {
    let mut disk = DiskAddress {
        pci_controller: PciAddress {
            domain: -1,
            bus: -1,
            slot: -1,
            function: -1,
        },
        bus_type: "unknown",
        bus: 0,
        target: 0,
        unit: 0,
        serial: udev_property(syspath, "ID_SERIAL"),
        dev: devnode(syspath),
    };
    let text = syspath.to_string_lossy();
    let known = if text.contains("/devices/pci") {
        pci_disk(&text, &mut disk)
    } else if text.contains("/virtio") {
        nonpci_virtio_disk(&text, &mut disk)
    } else {
        false
    };
    (known || disk.dev.is_some() || disk.serial.is_some()).then_some(disk)
}

fn is_virtual(syspath: &Path) -> bool {
    syspath
        .to_string_lossy()
        .contains("/devices/virtual/block/")
}

/// Collect the disks under `devpath`, following device-mapper and md slaves
/// down to real devices. The first device seen names the filesystem.
fn disks_of(
    devpath: &Path,
    name: &mut Option<String>,
    out: &mut Vec<DiskAddress>,
) -> io::Result<()> {
    let syspath = match fs::canonicalize(devpath) {
        Ok(path) => path,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            name.get_or_insert_with(|| basename(devpath));
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    name.get_or_insert_with(|| basename(&syspath));
    if is_virtual(&syspath) {
        let slaves = match fs::read_dir(syspath.join("slaves")) {
            Ok(slaves) => slaves,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        for slave in slaves {
            let slave = slave?;
            if slave.file_type()?.is_symlink() {
                disks_of(&slave.path(), name, out)?;
            }
        }
    } else if let Some(disk) = real_device(&syspath) {
        // qemu-ga prepends.
        out.insert(0, disk);
    }
    Ok(())
}

fn basename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// (used, total, privileged total) in bytes. Some filesystems report
/// `f_bfree > f_blocks`; the arithmetic saturates instead of wrapping.
fn space_bytes(frsize: u64, blocks: u64, bfree: u64, bavail: u64) -> (u64, u64, u64) {
    let used = blocks.saturating_sub(bfree);
    (
        used.saturating_mul(frsize),
        used.saturating_add(bavail).saturating_mul(frsize),
        blocks.saturating_mul(frsize),
    )
}

fn fsinfo(mount: &Mount) -> Result<FilesystemInfo, QgaError> {
    let mut name = None;
    let mut disk = Vec::new();
    let devpath = PathBuf::from(format!("/sys/dev/block/{}:{}", mount.major, mount.minor));
    disks_of(&devpath, &mut name, &mut disk)
        .map_err(|e| QgaError::os(format!("realpath(\"{}\")", devpath.display()), &e))?;
    let mut info = FilesystemInfo {
        name: name.unwrap_or_default(),
        mountpoint: mount.dir_lossy(),
        fstype: mount.fstype.clone(),
        used_bytes: None,
        total_bytes: None,
        total_bytes_privileged: None,
        disk,
    };
    if let Ok(path) = sys::cstring(&mount.dir) {
        // SAFETY: st is a valid out-parameter for statvfs.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: path is NUL-terminated.
        if unsafe { libc::statvfs(path.as_ptr(), &mut st) } == 0 {
            let (used, total, privileged) = space_bytes(
                st.f_frsize as u64,
                st.f_blocks as u64,
                st.f_bfree as u64,
                st.f_bavail as u64,
            );
            info.used_bytes = Some(used);
            info.total_bytes = Some(total);
            info.total_bytes_privileged = Some(privileged);
        }
    }
    Ok(info)
}

pub fn get_fsinfo(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let mounts =
        local_mounts().map_err(|e| QgaError::os("failed to read /proc/self/mountinfo", &e))?;
    let mut list = mounts.iter().map(fsinfo).collect::<Result<Vec<_>, _>>()?;
    list.reverse();
    Ok(Value::Array(list.into_iter().map(to_value).collect()))
}

fn dependencies(disk_dir: &Path) -> Option<Vec<String>> {
    let entries = fs::read_dir(disk_dir.join("slaves")).ok()?;
    let mut deps: Vec<String> = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        if let Some(node) = devnode(&entry.path()) {
            deps.insert(0, node);
        }
    }
    Some(deps)
}

fn is_partition_of(disk: &str, entry: &str) -> bool {
    let Some(rest) = entry.strip_prefix(disk) else {
        return false;
    };
    let rest = rest
        .strip_prefix('p')
        .filter(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or(rest);
    rest.starts_with(|c: char| c.is_ascii_digit())
}

pub fn get_disks(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let entries = fs::read_dir("/sys/block")
        .map_err(|e| QgaError::os("Can't open directory \"/sys/block\"", &e))?;
    // Built in qemu-ga's prepend order, reversed at the end.
    let mut pushed: Vec<DiskInfo> = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        if !entry.file_type().is_ok_and(|t| t.is_symlink()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let disk_dir = PathBuf::from("/sys/block").join(&name);
        match fs::read_to_string(disk_dir.join("size")) {
            Ok(size) if size.trim() != "0" => {}
            _ => continue,
        }
        let Some(node) = devnode(&disk_dir) else {
            continue;
        };
        let address = fs::canonicalize(&disk_dir)
            .ok()
            .filter(|p| !is_virtual(p))
            .and_then(|_| {
                let mut out = Vec::new();
                disks_of(&disk_dir, &mut None, &mut out).ok()?;
                out.into_iter().next()
            });
        // qemu-ga asks for SMART only when the address says NVMe.
        let smart = address
            .as_ref()
            .filter(|a| a.bus_type == "nvme")
            .and_then(|_| super::nvme::smart(&node));
        pushed.push(DiskInfo {
            name: node.clone(),
            partition: false,
            dependencies: dependencies(&disk_dir),
            address,
            alias: udev_property(&disk_dir, "DM_NAME"),
            smart,
        });
        let Ok(children) = fs::read_dir(&disk_dir) else {
            continue;
        };
        for child in children.filter_map(Result::ok) {
            let child_name = child.file_name().to_string_lossy().into_owned();
            if !child.file_type().is_ok_and(|t| t.is_dir()) || !is_partition_of(&name, &child_name)
            {
                continue;
            }
            if let Some(part) = devnode(&child.path()) {
                pushed.push(DiskInfo {
                    name: part,
                    partition: true,
                    dependencies: Some(vec![node.clone()]),
                    address: None,
                    alias: None,
                    smart: None,
                });
            }
        }
    }
    pushed.reverse();
    Ok(Value::Array(pushed.into_iter().map(to_value).collect()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn space_arithmetic_saturates() {
        assert_eq!(
            super::space_bytes(4096, 100, 40, 30),
            (245_760, 368_640, 409_600)
        );
        assert_eq!(super::space_bytes(4096, 10, 20, 5), (0, 20_480, 40_960));
        assert_eq!(
            super::space_bytes(u64::MAX, 2, 0, 0),
            (u64::MAX, u64::MAX, u64::MAX)
        );
    }

    use super::*;

    #[test]
    fn pci_components_and_targets() {
        let (pci, len) = pci_component("0000:00:05.0/virtio3/block/vda").unwrap();
        assert_eq!(
            pci,
            PciAddress {
                domain: 0,
                bus: 0,
                slot: 5,
                function: 0
            }
        );
        assert_eq!(len, 12);
        assert_eq!(
            scsi_target(
                "/sys/devices/pci0000:00/0000:00:04.0/virtio1/host2/target2:0:1/2:0:1:3/block/sda"
            ),
            Some([0, 1, 3])
        );
        assert_eq!(scsi_target("/sys/devices/virtual/block/dm-0"), None);
    }

    #[test]
    fn partitions_of_a_disk() {
        assert!(is_partition_of("vda", "vda1"));
        assert!(is_partition_of("nvme0n1", "nvme0n1p2"));
        assert!(!is_partition_of("vda", "vdab"));
        assert!(!is_partition_of("vda", "queue"));
        assert!(!is_partition_of("vda", "vda"));
    }

    #[test]
    fn listing_this_machine_does_not_fail() {
        let dir = tempfile::tempdir().unwrap();
        let agent = crate::agent::Agent::new(Default::default(), dir.path().to_path_buf());
        let mut ctx = Ctx::new(&agent);
        let fs = get_fsinfo(&mut ctx, Args::new(Default::default())).unwrap();
        assert!(fs
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["mountpoint"] == "/"));
        get_disks(&mut ctx, Args::new(Default::default())).unwrap();
    }
}
