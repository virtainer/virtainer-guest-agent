// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! NVMe SMART / Health Information (log page 02h) for `guest-get-disks`, as
//! qemu-ga reports it (`get_nvme_smart` in qga/commands-linux.c): the whole
//! 512-byte page, read with an admin "Get Log Page" command through the
//! disk's block device. A disk that cannot be opened or does not answer just
//! has no `smart` member, as with qemu-ga.

use std::fs::File;
use std::os::fd::AsRawFd;

use serde_json::{Map, Value};

use crate::sys;

/// `NVME_IOCTL_ADMIN_CMD`: `_IOWR('N', 0x41, struct nvme_passthru_cmd)`.
const ADMIN_CMD: u64 = 0xC048_4E41;
const GET_LOG_PAGE: u8 = 0x02;
const SMART_LOG: u32 = 0x02;
/// Retain Asynchronous Event: reading the page must not clear a SMART event
/// that the kernel driver has not consumed yet.
const RAE: u32 = 1 << 15;
/// The log for the whole controller, not one namespace.
const NSID_ALL: u32 = 0xFFFF_FFFF;
const LOG_LEN: usize = 512;

/// The 128-bit little-endian counters: member stem and byte offset.
const COUNTERS: [(&str, usize); 10] = [
    ("data-units-read", 32),
    ("data-units-written", 48),
    ("host-read-commands", 64),
    ("host-write-commands", 80),
    ("controller-busy-time", 96),
    ("power-cycles", 112),
    ("power-on-hours", 128),
    ("unsafe-shutdowns", 144),
    ("media-errors", 160),
    ("number-of-error-log-entries", 176),
];

/// `struct nvme_passthru_cmd` from <linux/nvme_ioctl.h>.
#[repr(C)]
#[derive(Default)]
struct PassthruCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

/// The `smart` member for the NVMe disk at `device`, if it answers.
pub fn smart(device: &str) -> Option<Value> {
    let file = File::open(device).ok()?;
    let mut log = [0u8; LOG_LEN];
    let mut cmd = PassthruCmd {
        opcode: GET_LOG_PAGE,
        nsid: NSID_ALL,
        addr: log.as_mut_ptr() as u64,
        data_len: LOG_LEN as u32,
        // The page length in dwords, minus one, goes in bits 16-27.
        cdw10: SMART_LOG | RAE | ((LOG_LEN as u32 / 4 - 1) << 16),
        ..PassthruCmd::default()
    };
    // SAFETY: the command points at `log`, which outlives the call, and the
    // ioctl reads and updates exactly one nvme_passthru_cmd.
    unsafe { sys::ioctl(file.as_raw_fd(), ADMIN_CMD, &mut cmd) }.ok()?;
    Some(parse(&log))
}

/// The GuestNVMeSmart members in schema order, behind the union's `type`.
fn parse(log: &[u8; LOG_LEN]) -> Value {
    let u64_at = |at: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&log[at..at + 8]);
        u64::from_le_bytes(bytes)
    };
    let mut smart = Map::new();
    smart.insert("type".into(), "nvme".into());
    smart.insert("critical-warning".into(), log[0].into());
    smart.insert(
        "temperature".into(),
        u16::from_le_bytes([log[1], log[2]]).into(),
    );
    smart.insert("available-spare".into(), log[3].into());
    smart.insert("available-spare-threshold".into(), log[4].into());
    smart.insert("percentage-used".into(), log[5].into());
    for (stem, at) in COUNTERS {
        smart.insert(format!("{stem}-lo"), u64_at(at).into());
        smart.insert(format!("{stem}-hi"), u64_at(at + 8).into());
    }
    Value::Object(smart)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_matches_the_kernel_abi() {
        assert_eq!(std::mem::size_of::<PassthruCmd>(), 72);
        // _IOWR: read and write, the struct size, type 'N', number 0x41.
        let iowr = (3u64 << 30) | (72 << 16) | ((b'N' as u64) << 8) | 0x41;
        assert_eq!(ADMIN_CMD, iowr);
        assert_eq!(
            SMART_LOG | RAE | ((LOG_LEN as u32 / 4 - 1) << 16),
            0x007F_8002
        );
    }

    #[test]
    fn a_log_page_becomes_qemu_ga_members_in_schema_order() {
        let mut log = [0u8; LOG_LEN];
        log[..6].copy_from_slice(&[0x04, 0x43, 0x01, 100, 10, 3]);
        for (i, (_, at)) in COUNTERS.iter().enumerate() {
            log[*at..at + 8].copy_from_slice(&(1000 + i as u64).to_le_bytes());
            log[at + 8..at + 16].copy_from_slice(&(i as u64).to_le_bytes());
        }
        let json = String::from_utf8(crate::json::to_vec(&parse(&log))).unwrap();
        assert!(json.starts_with(
            "{\"type\": \"nvme\", \"critical-warning\": 4, \"temperature\": 323, \
             \"available-spare\": 100, \"available-spare-threshold\": 10, \
             \"percentage-used\": 3, \"data-units-read-lo\": 1000, \"data-units-read-hi\": 0, \
             \"data-units-written-lo\": 1001, \"data-units-written-hi\": 1"
        ));
        assert!(json.ends_with(
            "\"number-of-error-log-entries-lo\": 1009, \"number-of-error-log-entries-hi\": 9}"
        ));
        assert_eq!(parse(&log).as_object().unwrap().len(), 26);
    }

    #[test]
    fn something_that_is_not_an_nvme_disk_has_no_smart() {
        assert_eq!(smart("/dev/null"), None);
        assert_eq!(smart("/nonexistent/nvme0n1"), None);
    }
}
