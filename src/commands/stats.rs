// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `guest-get-load`, `guest-get-cpustats`, `guest-get-diskstats` from /proc.

use serde::Serialize;
use serde_json::{json, Value};

use super::{no_args, to_value, Ctx};
use crate::qmp::{Args, QgaError, Reply};

pub fn get_load(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let text = std::fs::read_to_string("/proc/loadavg")
        .map_err(|e| QgaError::os("cannot query load average", &e))?;
    let loads: Vec<f64> = text
        .split_whitespace()
        .take(3)
        .filter_map(|v| v.parse().ok())
        .collect();
    if loads.len() != 3 {
        return Err(QgaError::generic(
            "cannot query load average: unexpected /proc/loadavg",
        ));
    }
    Ok(json!({ "load1m": loads[0], "load5m": loads[1], "load15m": loads[2] }))
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct CpuStats {
    #[serde(rename = "type")]
    kind: &'static str,
    cpu: i64,
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    iowait: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    irq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    softirq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    steal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guestnice: Option<u64>,
}

/// Per-CPU lines of /proc/stat, converted from clock ticks to milliseconds.
fn parse_cpustats(text: &str, ticks_per_sec: u64) -> Vec<CpuStats> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        // "cpu" alone is the aggregate.
        let Some(cpu) = name.strip_prefix("cpu").filter(|n| !n.is_empty()) else {
            continue;
        };
        let Ok(cpu) = cpu.parse::<i64>() else {
            continue;
        };
        let ms: Vec<u64> = fields
            .take(10)
            .map_while(|v| v.parse::<u64>().ok())
            .map(|ticks| ticks * 1000 / ticks_per_sec)
            .collect();
        if ms.len() < 4 {
            break;
        }
        let at = |i: usize| ms.get(i).copied();
        out.push(CpuStats {
            kind: "linux",
            cpu,
            user: ms[0],
            nice: ms[1],
            system: ms[2],
            idle: ms[3],
            iowait: at(4),
            irq: at(5),
            softirq: at(6),
            steal: at(7),
            guest: at(8),
            guestnice: at(9),
        });
    }
    out
}

pub fn get_cpustats(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let text = std::fs::read_to_string("/proc/stat")
        .map_err(|e| QgaError::os("Could not open file '/proc/stat'", &e))?;
    // SAFETY: sysconf has no preconditions.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let ticks = if ticks > 0 { ticks as u64 } else { 100 };
    Ok(Value::Array(
        parse_cpustats(&text, ticks)
            .into_iter()
            .map(to_value)
            .collect(),
    ))
}

#[derive(Serialize, Default, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
struct DiskStats {
    #[serde(skip_serializing_if = "Option::is_none")]
    read_sectors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_ios: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_merges: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_sectors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_ios: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_merges: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discard_sectors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discard_ios: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discard_merges: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flush_ios: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_ticks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_ticks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discard_ticks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flush_ticks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ios_pgr: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_ticks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight_ticks: Option<u64>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct DiskStatsInfo {
    name: String,
    major: u64,
    minor: u64,
    stats: DiskStats,
}

/// /proc/diskstats (Documentation/admin-guide/iostats.rst). Old kernels
/// printed 4 counters for partitions; newer ones 11, 15 or 17.
fn parse_diskstats(text: &str) -> Vec<DiskStatsInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 7 {
            continue;
        }
        let (Ok(major), Ok(minor)) = (f[0].parse::<u64>(), f[1].parse::<u64>()) else {
            continue;
        };
        let n: Vec<u64> = f[3..].iter().map_while(|v| v.parse().ok()).collect();
        let mut s = DiskStats::default();
        if n.len() == 4 {
            s.read_ios = Some(n[0]);
            s.read_sectors = Some(n[1]);
            s.write_ios = Some(n[2]);
            s.write_sectors = Some(n[3]);
        }
        if n.len() >= 11 {
            s.read_ios = Some(n[0]);
            s.read_merges = Some(n[1]);
            s.read_sectors = Some(n[2]);
            s.read_ticks = Some(n[3]);
            s.write_ios = Some(n[4]);
            s.write_merges = Some(n[5]);
            s.write_sectors = Some(n[6]);
            s.write_ticks = Some(n[7]);
            s.ios_pgr = Some(n[8]);
            s.total_ticks = Some(n[9]);
            s.weight_ticks = Some(n[10]);
        }
        if n.len() >= 15 {
            s.discard_ios = Some(n[11]);
            s.discard_merges = Some(n[12]);
            s.discard_sectors = Some(n[13]);
            s.discard_ticks = Some(n[14]);
        }
        if n.len() >= 17 {
            s.flush_ios = Some(n[15]);
            s.flush_ticks = Some(n[16]);
        }
        out.push(DiskStatsInfo {
            name: f[2].to_string(),
            major,
            minor,
            stats: s,
        });
    }
    out
}

pub fn get_diskstats(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let text = std::fs::read_to_string("/proc/diskstats")
        .map_err(|e| QgaError::os("Could not open file '/proc/diskstats'", &e))?;
    Ok(Value::Array(
        parse_diskstats(&text).into_iter().map(to_value).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpustats_skip_the_aggregate_and_convert_ticks() {
        let text =
            "cpu  10 0 20 30 0 0 0 0 0 0\ncpu0 100 2 300 400 5 6 7 8 9 10\ncpu1 1 2 3 4\nintr 1\n";
        let stats = parse_cpustats(text, 100);
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].cpu, 0);
        assert_eq!(stats[0].user, 1000);
        assert_eq!(stats[0].guestnice, Some(100));
        assert_eq!(stats[1].iowait, None);
        assert_eq!(
            to_value(&stats[1]),
            json!({"type": "linux", "cpu": 1, "user": 10, "nice": 20, "system": 30, "idle": 40})
        );
    }

    #[test]
    fn diskstats_field_counts() {
        let text =
            " 252       0 vda 9 1 2 3 4 5 6 7 0 8 9 10 11 12 13 14 15\n 252       1 vda1 1 2 3 4\n";
        let stats = parse_diskstats(text);
        assert_eq!(stats[0].name, "vda");
        assert_eq!(stats[0].stats.read_sectors, Some(2));
        assert_eq!(stats[0].stats.flush_ticks, Some(15));
        assert_eq!(stats[1].stats.write_sectors, Some(4));
        assert_eq!(stats[1].stats.read_merges, None);
    }
}
