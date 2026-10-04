// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! The local filesystems that freeze, thaw, fstrim and fsinfo operate on.
//!
//! One entry per filesystem, in mount order: bind mounts and btrfs subvolumes
//! show up several times in mountinfo, and freezing a filesystem twice fails
//! with EBUSY. Mounts without a block device (tmpfs, proc, overlay, NFS, ...)
//! are not local disks and are skipped, except btrfs, whose mountinfo device
//! number is anonymous and is resolved through its source device instead.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub dir: PathBuf,
    pub fstype: String,
    pub major: u32,
    pub minor: u32,
}

impl Mount {
    pub fn dir_lossy(&self) -> String {
        String::from_utf8_lossy(self.dir.as_os_str().as_bytes()).into_owned()
    }
}

pub fn local_mounts() -> io::Result<Vec<Mount>> {
    let text = std::fs::read("/proc/self/mountinfo")?;
    Ok(parse_mountinfo(&text, block_device_numbers))
}

fn block_device_numbers(path: &Path) -> Option<(u32, u32)> {
    let meta = std::fs::metadata(path).ok()?;
    meta.file_type().is_block_device().then(|| {
        let dev = meta.rdev();
        (libc::major(dev), libc::minor(dev))
    })
}

/// mountinfo(5): `id parent major:minor root mountpoint options... - fstype source superopts`.
pub fn parse_mountinfo(text: &[u8], device_of: impl Fn(&Path) -> Option<(u32, u32)>) -> Vec<Mount> {
    let mut mounts: Vec<Mount> = Vec::new();
    for line in text.split(|b| *b == b'\n') {
        let fields: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
        if fields.len() < 7 {
            continue;
        }
        let Some((major, minor)) = std::str::from_utf8(fields[2])
            .ok()
            .and_then(|dev| dev.split_once(':'))
            .and_then(|(ma, mi)| Some((ma.parse::<u32>().ok()?, mi.parse::<u32>().ok()?)))
        else {
            continue;
        };
        let Some(dash) = fields
            .iter()
            .skip(6)
            .position(|f| *f == b"-")
            .map(|i| i + 6)
        else {
            continue;
        };
        let Some(fstype) = fields.get(dash + 1) else {
            continue;
        };
        let fstype = String::from_utf8_lossy(fstype).into_owned();
        let source = fields
            .get(dash + 2)
            .map(|s| unescape(s))
            .unwrap_or_default();
        let (major, minor) = if major == 0 {
            if fstype != "btrfs" {
                continue;
            }
            match device_of(&source) {
                Some(dev) => dev,
                None => continue,
            }
        } else {
            (major, minor)
        };
        if mounts.iter().any(|m| m.major == major && m.minor == minor) {
            continue;
        }
        mounts.push(Mount {
            dir: unescape(fields[4]),
            fstype,
            major,
            minor,
        });
    }
    mounts
}

/// The kernel escapes space, tab, newline and backslash as `\ooo`.
fn unescape(raw: &[u8]) -> PathBuf {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let octal = raw.get(i + 1..i + 4).filter(|d| {
            (b'0'..=b'3').contains(&d[0]) && d[1..].iter().all(|c| (b'0'..=b'7').contains(c))
        });
        match (raw[i], octal) {
            (b'\\', Some(d)) => {
                out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
                i += 4;
            }
            (b'\\', None) if raw.get(i + 1) == Some(&b'\\') => {
                out.push(b'\\');
                i += 2;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    PathBuf::from(OsString::from_vec(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"\
22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
23 22 0:21 / /proc rw,nosuid shared:5 - proc proc rw
24 22 0:5 / /dev rw shared:2 - devtmpfs devtmpfs rw,size=4096k
40 22 252:16 / /mnt/data\\040disk rw,relatime shared:20 - xfs /dev/vdb rw
41 22 252:1 /srv /srv/bind rw,relatime shared:1 - ext4 /dev/vda1 rw
42 22 0:45 /@home /home rw,relatime shared:30 - btrfs /dev/vdc rw,subvol=/@home
43 22 0:45 /@var /var rw,relatime shared:31 - btrfs /dev/vdc rw,subvol=/@var
44 22 0:46 / /mnt/nfs rw shared:40 - nfs4 server:/export rw
45 22 0:47 / /run rw shared:3 - tmpfs tmpfs rw
";

    #[test]
    fn one_entry_per_local_filesystem_in_mount_order() {
        let mounts = parse_mountinfo(SAMPLE, |source| {
            (source == Path::new("/dev/vdc")).then_some((252, 32))
        });
        let dirs: Vec<String> = mounts.iter().map(Mount::dir_lossy).collect();
        assert_eq!(dirs, vec!["/", "/mnt/data disk", "/home"]);
        assert_eq!(mounts[2].fstype, "btrfs");
        assert_eq!((mounts[2].major, mounts[2].minor), (252, 32));
    }

    #[test]
    fn optional_fields_before_the_separator_are_skipped() {
        let line = b"36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 shared:7 - ext3 /dev/root rw,errors=continue\n";
        let mounts = parse_mountinfo(line, |_| None);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].dir, PathBuf::from("/mnt2"));
        assert_eq!(mounts[0].fstype, "ext3");
    }

    #[test]
    fn backslash_escapes() {
        assert_eq!(unescape(br"a\134b\011c"), PathBuf::from("a\\b\tc"));
        assert_eq!(unescape(br"plain\"), PathBuf::from("plain\\"));
    }
}
