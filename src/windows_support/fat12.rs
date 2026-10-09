// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Bounded, read-only FAT12 superfloppy reader. Only root files are needed.
//! Long names are decoded from validated VFAT entries; no mounted volume is needed.

use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom};

pub const MAX_IMAGE: usize = 256 << 20;
pub const MAX_FILE: usize = 64 << 20;

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid FAT12 seed")
}
fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Fat12 {
    image: Vec<u8>,
    fat: usize,
    fat_len: usize,
    root: usize,
    root_len: usize,
    data: usize,
    cluster_size: usize,
    clusters: usize,
}

impl Fat12 {
    pub fn read(mut disk: impl Read + Seek) -> io::Result<Self> {
        let mut boot = [0u8; 512];
        disk.seek(SeekFrom::Start(0))?;
        disk.read_exact(&mut boot)?;
        if boot[510..512] != [0x55, 0xaa] || !matches!(boot[0], 0xeb | 0xe9) {
            return Err(bad());
        }
        let bps = usize::from(u16_at(&boot, 11));
        let spc = usize::from(boot[13]);
        let reserved = usize::from(u16_at(&boot, 14));
        let copies = usize::from(boot[16]);
        let entries = usize::from(u16_at(&boot, 17));
        let sectors16 = usize::from(u16_at(&boot, 19));
        let sectors = if sectors16 == 0 {
            u32_at(&boot, 32) as usize
        } else {
            sectors16
        };
        let fat_sectors = usize::from(u16_at(&boot, 22));
        if !matches!(bps, 512 | 1024 | 2048 | 4096)
            || spc == 0
            || !spc.is_power_of_two()
            || spc > 128
            || reserved == 0
            || !(1..=2).contains(&copies)
            || entries == 0
            || fat_sectors == 0
        {
            return Err(bad());
        }
        let size = sectors
            .checked_mul(bps)
            .filter(|n| (512..=MAX_IMAGE).contains(n))
            .ok_or_else(bad)?;
        let root_sectors = (entries * 32).div_ceil(bps);
        let data_sector = reserved + copies * fat_sectors + root_sectors;
        let clusters = sectors.checked_sub(data_sector).ok_or_else(bad)? / spc;
        if !(1..4085).contains(&clusters) || ((clusters + 2) * 3).div_ceil(2) > fat_sectors * bps {
            return Err(bad());
        }
        let mut image = Vec::new();
        image.try_reserve_exact(size).map_err(|_| bad())?;
        image.resize(size, 0);
        disk.seek(SeekFrom::Start(0))?;
        disk.read_exact(&mut image)?;
        let fat = reserved * bps;
        let fat_len = fat_sectors * bps;
        if image[fat] != boot[21] || image[fat + 1..fat + 3] != [0xff, 0xff] {
            return Err(bad());
        }
        if copies == 2 && image[fat..fat + fat_len] != image[fat + fat_len..fat + 2 * fat_len] {
            return Err(bad());
        }
        Ok(Self {
            image,
            fat,
            fat_len,
            root: (reserved + copies * fat_sectors) * bps,
            root_len: entries * 32,
            data: data_sector * bps,
            cluster_size: spc * bps,
            clusters,
        })
    }

    pub fn label(&self) -> String {
        for entry in self.image[self.root..self.root + self.root_len].chunks_exact(32) {
            if entry[0] == 0 {
                break;
            }
            if entry[0] != 0xe5 && entry[11] == 8 {
                return String::from_utf8_lossy(&entry[..11]).trim().to_string();
            }
        }
        String::from_utf8_lossy(&self.image[43..54])
            .trim()
            .to_string()
    }

    pub fn file(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        if name.is_empty() || name.contains(['/', '\\', ':']) {
            return Err(bad());
        }
        let mut long = Vec::<u16>::new();
        let mut expected = 0;
        let mut checksum = 0;
        let mut found = None;
        for entry in self.image[self.root..self.root + self.root_len].chunks_exact(32) {
            if entry[0] == 0 {
                break;
            }
            if entry[0] == 0xe5 {
                long.clear();
                expected = 0;
                continue;
            }
            if entry[11] == 0x0f {
                let seq = entry[0] & 0x1f;
                if entry[0] & 0x40 != 0 {
                    long.clear();
                    expected = seq;
                    checksum = entry[13];
                    if (1..=20).contains(&seq) {
                        long.resize(usize::from(seq) * 13, 0xffff);
                    }
                }
                if expected != seq
                    || seq == 0
                    || long.is_empty()
                    || entry[13] != checksum
                    || entry[12] != 0
                    || u16_at(entry, 26) != 0
                    || entry[0] & 0xa0 != 0
                {
                    long.clear();
                    expected = 0;
                    continue;
                }
                let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                for (i, offset) in offsets.into_iter().enumerate() {
                    long[(usize::from(seq) - 1) * 13 + i] = u16_at(entry, offset);
                }
                expected -= 1;
                continue;
            }
            let sum = entry[..11]
                .iter()
                .fold(0u8, |sum, b| sum.rotate_right(1).wrapping_add(*b));
            let long_name = if expected == 0 && !long.is_empty() && checksum == sum {
                let end = long
                    .iter()
                    .position(|v| *v == 0 || *v == 0xffff)
                    .unwrap_or(long.len());
                String::from_utf16(&long[..end]).ok()
            } else {
                None
            };
            long.clear();
            expected = 0;
            if entry[11] & 0x18 != 0 {
                continue;
            }
            let base = String::from_utf8_lossy(&entry[..8]).trim_end().to_string();
            let ext = String::from_utf8_lossy(&entry[8..11])
                .trim_end()
                .to_string();
            let short = if ext.is_empty() {
                base
            } else {
                format!("{base}.{ext}")
            };
            if short.eq_ignore_ascii_case(name)
                || long_name
                    .as_ref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(name))
            {
                if found.is_some() || u16_at(entry, 20) != 0 {
                    return Err(bad());
                }
                found = Some(self.contents(u16_at(entry, 26), u32_at(entry, 28) as usize)?);
            }
        }
        Ok(found)
    }

    fn contents(&self, first: u16, size: usize) -> io::Result<Vec<u8>> {
        if size > MAX_FILE || size > self.clusters * self.cluster_size {
            return Err(bad());
        }
        if size == 0 {
            return if first == 0 {
                Ok(Vec::new())
            } else {
                Err(bad())
            };
        }
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| bad())?;
        let mut visited = HashSet::new();
        let mut cluster = usize::from(first);
        loop {
            if !(2..self.clusters + 2).contains(&cluster) || !visited.insert(cluster) {
                return Err(bad());
            }
            let offset = self.data + (cluster - 2) * self.cluster_size;
            let take = (size - out.len()).min(self.cluster_size);
            out.extend_from_slice(&self.image[offset..offset + take]);
            let at = cluster + cluster / 2;
            if at + 1 >= self.fat_len {
                return Err(bad());
            }
            let word = u16_at(&self.image, self.fat + at);
            let next = if cluster & 1 == 0 {
                word & 0xfff
            } else {
                word >> 4
            };
            if out.len() == size {
                return if next >= 0xff8 { Ok(out) } else { Err(bad()) };
            }
            if next >= 0xff0 {
                return Err(bad());
            }
            cluster = usize::from(next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn put16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn image() -> Vec<u8> {
        let mut b = vec![0; 512 * 32];
        b[0] = 0xeb;
        b[510] = 0x55;
        b[511] = 0xaa;
        put16(&mut b, 11, 512);
        b[13] = 1;
        put16(&mut b, 14, 1);
        b[16] = 1;
        put16(&mut b, 17, 16);
        put16(&mut b, 19, 32);
        put16(&mut b, 22, 1);
        b[21] = 0xf8;
        b[512..515].copy_from_slice(&[0xf8, 0xff, 0xff]);
        b[515..518].copy_from_slice(&[3, 0xf0, 0xff]); // 2 -> 3 -> EOC
        b[1024..1035].copy_from_slice(b"VIRTSEED   ");
        b[1035] = 8;
        b[1056..1067].copy_from_slice(b"HELLO   TXT");
        b[1067] = 0x20;
        put16(&mut b, 1082, 2);
        put32(&mut b, 1084, 700);
        b[1536..2236].fill(b'x');
        b
    }
    #[test]
    fn root_label_and_even_odd_cluster_chain() {
        let fat = Fat12::read(Cursor::new(image())).unwrap();
        assert_eq!(fat.label(), "VIRTSEED");
        assert_eq!(fat.file("hello.txt").unwrap().unwrap(), vec![b'x'; 700]);
        assert!(fat.file("missing").unwrap().is_none());
        assert!(fat.file("../hello.txt").is_err());
    }
    #[test]
    fn a_fat_that_exactly_fits_an_odd_entry_count_is_accepted() {
        // 339 data clusters plus 2 reserved entries need 341 * 12 bits = 512 bytes.
        let mut b = image();
        b.resize(512 * 342, 0);
        put16(&mut b, 19, 342);
        let fat = Fat12::read(Cursor::new(b.clone())).unwrap();
        assert_eq!(fat.file("hello.txt").unwrap().unwrap(), vec![b'x'; 700]);
        b.resize(512 * 343, 0);
        put16(&mut b, 19, 343);
        assert!(Fat12::read(Cursor::new(b)).is_err());
    }
    #[test]
    fn long_names_require_sequence_and_checksum() {
        let mut b = image();
        let name = "virtainer-provision.json";
        let mut short = b[1056..1088].to_vec();
        short[..11].copy_from_slice(b"VIRTAI~1JSN");
        let sum = short[..11]
            .iter()
            .fold(0u8, |s, b| s.rotate_right(1).wrapping_add(*b));
        let mut units: Vec<_> = name.encode_utf16().collect();
        units.push(0);
        units.resize(26, 0xffff);
        for (disk_index, seq) in [2u8, 1].into_iter().enumerate() {
            let at = 1056 + disk_index * 32;
            b[at..at + 32].fill(0);
            b[at] = seq | if seq == 2 { 0x40 } else { 0 };
            b[at + 11] = 0xf;
            b[at + 13] = sum;
            for (i, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                .into_iter()
                .enumerate()
            {
                put16(&mut b, at + offset, units[(usize::from(seq) - 1) * 13 + i]);
            }
        }
        b[1120..1152].copy_from_slice(&short);
        assert!(Fat12::read(Cursor::new(&b))
            .unwrap()
            .file(name)
            .unwrap()
            .is_some());
        b[1069] ^= 1;
        assert!(Fat12::read(Cursor::new(&b))
            .unwrap()
            .file(name)
            .unwrap()
            .is_none());
    }
    #[test]
    fn corrupt_chains_geometry_and_truncation_are_rejected() {
        for next in [0, 1, 2, 0xff7, 0xfff] {
            let mut b = image();
            put16(&mut b, 515, next);
            assert!(Fat12::read(Cursor::new(b))
                .unwrap()
                .file("HELLO.TXT")
                .is_err());
        }
        for at in [12, 13, 14, 16, 17, 19, 22, 510] {
            let mut b = image();
            b[at] = 0;
            assert!(Fat12::read(Cursor::new(b)).is_err(), "offset {at}");
        }
        let b = image();
        for len in [0, 1, 511, 512, 1024, b.len() - 1] {
            assert!(Fat12::read(Cursor::new(&b[..len])).is_err());
        }
    }
    #[test]
    fn corrupt_input_never_panics_or_allocates_unboundedly() {
        let mut rng = 0x123456789abcdefu64;
        for round in 0..2000 {
            let mut b = image();
            for _ in 0..1 + round % 20 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let at = (rng as usize) % b.len();
                b[at] = (rng >> 32) as u8;
            }
            if let Ok(fat) = Fat12::read(Cursor::new(b)) {
                let _ = fat.label();
                let _ = fat.file("HELLO.TXT");
                let _ = fat.file("virtainer-provision.json");
            }
        }
    }
}
