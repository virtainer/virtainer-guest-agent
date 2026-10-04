// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Session, identity, time and power commands.

use std::collections::HashMap;
use std::ffi::CStr;
use std::path::Path;

use serde::Serialize;
use serde_json::{json, Value};

use super::{is_enabled, no_args, to_value, Ctx, COMMANDS};
use crate::qmp::{Args, QgaError, Reply};
use crate::sys;

pub fn sync_delimited(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let id = args.int("id")?;
    args.finish()?;
    ctx.delimit_next = true;
    Ok(json!(id))
}

pub fn sync(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let id = args.int("id")?;
    args.finish()?;
    Ok(json!(id))
}

pub fn ping(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    Ok(json!({}))
}

#[derive(Serialize)]
struct CommandInfo {
    name: &'static str,
    enabled: bool,
    #[serde(rename = "success-response")]
    success_response: bool,
}

pub fn info(ctx: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    // qemu-ga prepends while walking its command table, so the list comes
    // out in reverse schema order.
    let commands: Vec<CommandInfo> = COMMANDS
        .iter()
        .rev()
        .map(|c| CommandInfo {
            name: c.name,
            enabled: is_enabled(ctx.agent, c.name),
            success_response: c.success_response,
        })
        .collect();
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "supported_commands": commands,
    }))
}

pub fn get_time(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let now = sys::clock_gettime(libc::CLOCK_REALTIME);
    Ok(json!(now.as_nanos() as i64))
}

pub fn set_time(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let time = args.opt_int("time")?;
    args.finish()?;
    match time {
        Some(ns) => {
            let secs = ns / 1_000_000_000;
            let year = rtc::utc_year(secs);
            if !(1970..2070).contains(&year) {
                return Err(QgaError::generic("Invalid time"));
            }
            let ts = libc::timespec {
                tv_sec: secs as _,
                tv_nsec: (ns % 1_000_000_000) as _,
            };
            // SAFETY: ts is a valid timespec.
            if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } != 0 {
                return Err(QgaError::os(
                    "Failed to set time to guest",
                    &sys::last_error(),
                ));
            }
            crate::info!("guest-set-time: system clock set to {secs}");
            match rtc::write_from_system() {
                // No RTC device: the system clock is the only clock to set.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                result => result
                    .map_err(|e| QgaError::os("failed to set hardware clock to system time", &e)),
            }
        }
        None => {
            let secs = rtc::read().map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    QgaError::generic(
                        "this guest has no hardware clock to read the time from; pass 'time'",
                    )
                } else {
                    QgaError::os("failed to read the hardware clock", &e)
                }
            })?;
            let ts = libc::timespec {
                tv_sec: secs as _,
                tv_nsec: 0,
            };
            // SAFETY: ts is a valid timespec.
            if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } != 0 {
                return Err(QgaError::os(
                    "Failed to set time to guest",
                    &sys::last_error(),
                ));
            }
            crate::info!("guest-set-time: system clock set from the hardware clock ({secs})");
            Ok(())
        }
    }
    .map(|()| json!({}))
}

/// The hardware clock, without hwclock(8): Debian and Ubuntu cloud images no
/// longer ship it (util-linux-extra), and qemu-ga's set-time fails there.
///
/// Under Cloud Hypervisor (v53) there is usually no RTC at all: the guest's
/// rtc_cmos driver fails to probe its CMOS emulation. Setting an explicit time
/// then only sets the system clock, and a host that wants to fix a restored
/// guest's clock has to pass its own time.
mod rtc {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    use crate::sys;

    #[repr(C)]
    #[derive(Default)]
    struct RtcTime {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
    }

    const RTC_RD_TIME: u64 = 0x8024_7009;
    const RTC_SET_TIME: u64 = 0x4024_700a;

    fn open() -> io::Result<File> {
        File::open("/dev/rtc0").or_else(|_| File::open("/dev/rtc"))
    }

    /// hwclock's convention: the RTC keeps UTC unless /etc/adjtime says LOCAL.
    fn rtc_is_local() -> bool {
        std::fs::read_to_string("/etc/adjtime")
            .map(|text| text.lines().nth(2).map(str::trim) == Some("LOCAL"))
            .unwrap_or(false)
    }

    pub fn utc_year(secs: i64) -> i64 {
        // SAFETY: tm is a valid out-parameter for gmtime_r.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let t = secs as _;
        // SAFETY: both pointers are valid for the call.
        if unsafe { libc::gmtime_r(&t, &mut tm) }.is_null() {
            return i64::MIN;
        }
        tm.tm_year as i64 + 1900
    }

    pub fn read() -> io::Result<i64> {
        let file = open()?;
        let mut rtc = RtcTime::default();
        // SAFETY: RTC_RD_TIME fills a struct rtc_time.
        unsafe { sys::ioctl(file.as_raw_fd(), RTC_RD_TIME, &mut rtc)? };
        // SAFETY: zeroed tm is valid; fields are filled below.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_sec = rtc.tm_sec;
        tm.tm_min = rtc.tm_min;
        tm.tm_hour = rtc.tm_hour;
        tm.tm_mday = rtc.tm_mday;
        tm.tm_mon = rtc.tm_mon;
        tm.tm_year = rtc.tm_year;
        tm.tm_isdst = -1;
        // SAFETY: tm is a valid struct tm.
        let secs = unsafe {
            if rtc_is_local() {
                libc::mktime(&mut tm)
            } else {
                libc::timegm(&mut tm)
            }
        };
        if secs == -1 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(secs as i64)
    }

    pub fn write_from_system() -> io::Result<()> {
        let file = open()?;
        let now = sys::clock_gettime(libc::CLOCK_REALTIME).as_secs() as _;
        // SAFETY: tm is a valid out-parameter.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: both pointers are valid for the call.
        let ok = unsafe {
            if rtc_is_local() {
                !libc::localtime_r(&now, &mut tm).is_null()
            } else {
                !libc::gmtime_r(&now, &mut tm).is_null()
            }
        };
        if !ok {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        let mut rtc = RtcTime {
            tm_sec: tm.tm_sec,
            tm_min: tm.tm_min,
            tm_hour: tm.tm_hour,
            tm_mday: tm.tm_mday,
            tm_mon: tm.tm_mon,
            tm_year: tm.tm_year,
            tm_wday: tm.tm_wday,
            tm_yday: tm.tm_yday,
            tm_isdst: 0,
        };
        // SAFETY: RTC_SET_TIME reads a struct rtc_time.
        unsafe { sys::ioctl(file.as_raw_fd(), RTC_SET_TIME, &mut rtc)? };
        Ok(())
    }
}

pub fn shutdown(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let mode = args.opt_str("mode")?;
    args.finish()?;
    let (direct, flag) = match mode.as_deref() {
        None | Some("powerdown") => ("/sbin/poweroff", "-P"),
        Some("halt") => ("/sbin/halt", "-H"),
        Some("reboot") => ("/sbin/reboot", "-r"),
        Some(_) => {
            return Err(QgaError::generic(
                "mode is invalid (valid values are: halt|powerdown|reboot)",
            ))
        }
    };
    crate::notice!(
        "guest-shutdown called, mode: {}",
        mode.as_deref().unwrap_or("powerdown")
    );
    if sys::is_executable(Path::new(direct)) {
        sys::run_helper(&[direct], None, "shutdown", Some(sys::HELPER_TIMEOUT))?;
    } else {
        sys::run_helper(
            &[
                "/sbin/shutdown",
                "-h",
                flag,
                "+0",
                "hypervisor initiated shutdown",
            ],
            None,
            "shutdown",
            Some(sys::HELPER_TIMEOUT),
        )?;
    }
    Ok(Value::Null)
}

fn uname() -> libc::utsname {
    // SAFETY: utsname is plain data; uname fills it and cannot fail on Linux.
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        libc::uname(&mut uts);
        uts
    }
}

fn field(raw: &[libc::c_char]) -> String {
    // SAFETY: the kernel NUL-terminates every utsname field.
    unsafe { CStr::from_ptr(raw.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

pub fn get_host_name(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let mut name = field(&uname().nodename);
    if name.is_empty() {
        name = "localhost".into();
    }
    Ok(json!({ "host-name": name }))
}

pub fn get_timezone(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let now = sys::clock_gettime(libc::CLOCK_REALTIME).as_secs() as _;
    // SAFETY: tm is a valid out-parameter; musl and glibc fill tm_zone with a
    // pointer to static storage.
    let (offset, zone) = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return Err(QgaError::generic("Couldn't retrieve local timezone"));
        }
        let zone = (!tm.tm_zone.is_null())
            .then(|| CStr::from_ptr(tm.tm_zone).to_string_lossy().into_owned());
        (tm.tm_gmtoff as i64, zone)
    };
    let mut reply = serde_json::Map::new();
    if let Some(zone) = zone {
        reply.insert("zone".into(), json!(zone));
    }
    reply.insert("offset".into(), json!(offset));
    Ok(Value::Object(reply))
}

#[derive(Serialize, Default)]
#[serde(rename_all = "kebab-case")]
struct OsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pretty_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant_id: Option<String>,
}

pub fn get_osinfo(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let uts = uname();
    let mut info = OsInfo {
        kernel_release: Some(field(&uts.release)),
        kernel_version: Some(field(&uts.version)),
        machine: Some(field(&uts.machine)),
        ..OsInfo::default()
    };
    let release = ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|path| std::fs::read(path).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|text| parse_os_release(&text))
        .unwrap_or_default();
    let get = |key: &str| release.get(key).cloned();
    info.id = get("ID");
    info.name = get("NAME");
    info.pretty_name = get("PRETTY_NAME");
    info.version = get("VERSION");
    info.version_id = get("VERSION_ID");
    info.variant = get("VARIANT");
    info.variant_id = get("VARIANT_ID");
    Ok(to_value(info))
}

/// os-release(5): shell-style assignments with optional single or double
/// quotes and backslash escapes.
fn parse_os_release(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let mut value = String::new();
        let mut chars = raw.chars();
        match raw.chars().next() {
            Some(quote @ ('"' | '\'')) => {
                chars.next();
                while let Some(c) = chars.next() {
                    match c {
                        c if c == quote => break,
                        '\\' if quote == '"' => match chars.next() {
                            Some(e @ ('$' | '"' | '\\' | '`')) => value.push(e),
                            Some(other) => {
                                value.push('\\');
                                value.push(other);
                            }
                            None => value.push('\\'),
                        },
                        c => value.push(c),
                    }
                }
            }
            _ => {
                while let Some(c) = chars.next() {
                    match c {
                        c if c.is_whitespace() || c == ';' => break,
                        '\\' => {
                            if let Some(e) = chars.next() {
                                value.push(e);
                            }
                        }
                        c => value.push(c),
                    }
                }
            }
        }
        out.insert(key.trim().to_string(), value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::config::Config;

    #[test]
    fn os_release_quoting() {
        let parsed = parse_os_release(
            "NAME=\"Fedora Linux\"\n\
             ID=fedora\n\
             VERSION='44 (Cloud Edition)'\n\
             PRETTY_NAME=\"A \\\"quoted\\\" \\$name\"\n\
             # comment\n\
             VARIANT_ID=cloud # trailing\n",
        );
        assert_eq!(parsed["NAME"], "Fedora Linux");
        assert_eq!(parsed["ID"], "fedora");
        assert_eq!(parsed["VERSION"], "44 (Cloud Edition)");
        assert_eq!(parsed["PRETTY_NAME"], "A \"quoted\" $name");
        assert_eq!(parsed["VARIANT_ID"], "cloud");
    }

    #[test]
    fn info_lists_commands_in_reverse_schema_order() {
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(Config::default(), dir.path().to_path_buf());
        let mut ctx = Ctx::new(&agent);
        let info = super::info(&mut ctx, Args::new(Default::default())).unwrap();
        let names: Vec<&str> = info["supported_commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.first(), Some(&"__io.virtainer_shell"));
        assert_eq!(names.get(1), Some(&"guest-network-get-route"));
        assert_eq!(names.last(), Some(&"guest-sync-delimited"));
        let shutdown = info["supported_commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "guest-shutdown")
            .unwrap();
        assert_eq!(shutdown["success-response"], json!(false));
    }

    #[test]
    fn sync_delimited_marks_the_next_reply() {
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(Config::default(), dir.path().to_path_buf());
        let mut ctx = Ctx::new(&agent);
        let mut map = serde_json::Map::new();
        map.insert("id".into(), json!(42));
        assert_eq!(sync_delimited(&mut ctx, Args::new(map)).unwrap(), json!(42));
        assert!(ctx.delimit_next);
    }

    #[test]
    fn shutdown_rejects_an_unknown_mode() {
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(Config::default(), dir.path().to_path_buf());
        let mut ctx = Ctx::new(&agent);
        let mut map = serde_json::Map::new();
        map.insert("mode".into(), json!("explode"));
        assert!(shutdown(&mut ctx, Args::new(map)).is_err());
    }

    #[test]
    fn time_validation_matches_qemu_range() {
        assert_eq!(rtc::utc_year(0), 1970);
        assert!(rtc::utc_year(4_102_444_800) >= 2100);
    }
}
