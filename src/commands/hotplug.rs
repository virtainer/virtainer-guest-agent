// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! vCPU and memory-block onlining: `guest-get/set-vcpus`,
//! `guest-get/set-memory-blocks`, `guest-get-memory-block-info`.
//!
//! Cloud Hypervisor hot-adds vCPUs and memory through ACPI; the guest kernel
//! announces them, and whether they come online depends on the distro. These
//! commands let the host finish the job the way it does with qemu-ga.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};

use super::{no_args, to_value, Ctx};
use crate::qmp::{Args, QgaError, Reply};

const CPU_DIR: &str = "/sys/devices/system/cpu";
const MEMORY_DIR: &str = "/sys/devices/system/memory";

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct LogicalProcessor {
    logical_id: i64,
    online: bool,
    can_offline: bool,
}

/// `cpuN` directory names, numerically sorted for a stable answer.
fn numbered_entries(dir: &Path, prefix: &str) -> io::Result<Vec<u64>> {
    let mut ids: Vec<u64> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str()?.strip_prefix(prefix)?.parse().ok())
        .collect();
    ids.sort_unstable();
    Ok(ids)
}

/// A CPU without an `online` file (usually cpu0) is online and cannot be
/// taken offline.
fn read_cpu(id: i64) -> Result<LogicalProcessor, QgaError> {
    let path = PathBuf::from(format!("{CPU_DIR}/cpu{id}/online"));
    match fs::read(&path) {
        Ok(status) => Ok(LogicalProcessor {
            logical_id: id,
            online: status.first().is_some_and(|b| *b != b'0'),
            can_offline: true,
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(LogicalProcessor {
            logical_id: id,
            online: true,
            can_offline: false,
        }),
        Err(e) => Err(QgaError::os(
            format!("could not open {}", path.display()),
            &e,
        )),
    }
}

pub fn get_vcpus(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let ids = numbered_entries(Path::new(CPU_DIR), "cpu")
        .map_err(|e| QgaError::os(format!("failed to list entries: {CPU_DIR}"), &e))?;
    let cpus = ids
        .into_iter()
        .map(|id| read_cpu(id as i64))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(to_value(cpus))
}

fn set_cpu(id: i64, online: bool) -> Result<(), QgaError> {
    let dir = format!("{CPU_DIR}/cpu{id}");
    if !Path::new(&dir).is_dir() {
        return Err(QgaError::generic(format!(
            "Could not open file '{dir}/': No such file or directory"
        )));
    }
    let current = read_cpu(id)?;
    if !current.can_offline {
        return if online {
            Ok(())
        } else {
            Err(QgaError::generic(format!(
                "logical processor #{id} can't be offlined"
            )))
        };
    }
    if current.online == online {
        return Ok(());
    }
    // The error text names pwrite(2) because that is what qemu-ga reports.
    fs::write(format!("{dir}/online"), if online { "1" } else { "0" })
        .map_err(|e| QgaError::os(format!("pwrite(\"{dir}/online\")"), &e))
}

/// Applies the list in order and reports how far it got; only a failure on
/// the first element is an error.
pub fn set_vcpus(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let vcpus = args.object_list("vcpus", |v| {
        let id = v.int("logical-id")?;
        let online = v.bool("online")?;
        // Ignored on input, as the schema says.
        v.opt_bool("can-offline")?;
        Ok((id, online))
    })?;
    args.finish()?;
    let mut processed = 0i64;
    for (id, online) in vcpus {
        if let Err(e) = set_cpu(id, online) {
            if processed == 0 {
                return Err(e);
            }
            crate::warning!("guest-set-vcpus stopped at cpu{id}: {}", e.desc);
            break;
        }
        crate::info!(
            "guest-set-vcpus: cpu{id} {}",
            if online { "online" } else { "offline" }
        );
        processed += 1;
    }
    Ok(json!(processed))
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct MemoryBlock {
    phys_index: u64,
    online: bool,
    can_offline: bool,
}

fn read_block(index: u64) -> Result<MemoryBlock, QgaError> {
    let dir = PathBuf::from(format!("{MEMORY_DIR}/memory{index}"));
    let state = match fs::read_to_string(dir.join("state")) {
        Ok(state) => state,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(MemoryBlock {
                phys_index: index,
                online: true,
                can_offline: false,
            })
        }
        Err(e) => {
            return Err(QgaError::os(
                format!("open sysfs file \"{}\"", dir.join("state").display()),
                &e,
            ))
        }
    };
    let can_offline = match fs::read(dir.join("removable")) {
        Ok(flag) => flag.first().is_some_and(|b| *b != b'0'),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(QgaError::os(
                format!("open sysfs file \"{}\"", dir.join("removable").display()),
                &e,
            ))
        }
    };
    Ok(MemoryBlock {
        phys_index: index,
        online: state.starts_with("online"),
        can_offline,
    })
}

pub fn get_memory_blocks(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let indexes = match numbered_entries(Path::new(MEMORY_DIR), "memory") {
        Ok(indexes) => indexes,
        // No memory hotplug support in this kernel: nothing to list.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(json!([])),
        Err(e) => {
            return Err(QgaError::os(
                format!("Can't open directory\"{MEMORY_DIR}/\""),
                &e,
            ))
        }
    };
    if indexes.is_empty() {
        return Err(QgaError::generic("guest reported zero memory blocks!"));
    }
    let blocks = indexes
        .into_iter()
        .map(read_block)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(to_value(blocks))
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct BlockResponse {
    phys_index: u64,
    response: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<i32>,
}

fn set_block(index: u64, online: bool) -> BlockResponse {
    let fail = |response: &'static str, err: &io::Error| BlockResponse {
        phys_index: index,
        response,
        error_code: Some(err.raw_os_error().unwrap_or(0)),
    };
    if !Path::new(MEMORY_DIR).is_dir() {
        return fail(
            "operation-not-supported",
            &io::Error::from_raw_os_error(libc::ENOENT),
        );
    }
    let state_path = format!("{MEMORY_DIR}/memory{index}/state");
    if !Path::new(&state_path).parent().is_some_and(Path::is_dir) {
        return fail("not-found", &io::Error::from_raw_os_error(libc::ENOENT));
    }
    let state = match fs::read_to_string(&state_path) {
        Ok(state) => state,
        Err(e) if e.kind() == io::ErrorKind::NotFound && online => {
            return BlockResponse {
                phys_index: index,
                response: "success",
                error_code: None,
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return fail("operation-not-supported", &e)
        }
        Err(e) => return fail("operation-failed", &e),
    };
    if state.starts_with("online") != online {
        if let Err(e) = fs::write(&state_path, if online { "online" } else { "offline" }) {
            return fail("operation-failed", &e);
        }
        crate::info!(
            "guest-set-memory-blocks: memory{index} {}",
            if online { "online" } else { "offline" }
        );
    }
    BlockResponse {
        phys_index: index,
        response: "success",
        error_code: None,
    }
}

pub fn set_memory_blocks(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let blocks = args.object_list("mem-blks", |b| {
        let index = b.uint("phys-index")?;
        let online = b.bool("online")?;
        b.opt_bool("can-offline")?;
        Ok((index, online))
    })?;
    args.finish()?;
    let results: Vec<Value> = blocks
        .into_iter()
        .map(|(index, online)| to_value(set_block(index, online)))
        .collect();
    Ok(Value::Array(results))
}

pub fn get_memory_block_info(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let path = format!("{MEMORY_DIR}/block_size_bytes");
    let text = fs::read_to_string(&path)
        .map_err(|e| QgaError::os(format!("open sysfs file \"{path}\""), &e))?;
    let size = u64::from_str_radix(text.trim(), 16)
        .map_err(|_| QgaError::generic(format!("unexpected content in {path}")))?;
    Ok(json!({ "size": size }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_agent() -> (crate::agent::Agent, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (
            crate::agent::Agent::new(Default::default(), dir.path().to_path_buf()),
            dir,
        )
    }

    #[test]
    fn this_machine_has_vcpus_and_cpu0_comes_first() {
        let (agent, _dir) = ctx_agent();
        let mut ctx = Ctx::new(&agent);
        let cpus = get_vcpus(&mut ctx, Args::new(Default::default())).unwrap();
        let cpus = cpus.as_array().unwrap();
        assert!(!cpus.is_empty());
        assert_eq!(cpus[0]["logical-id"], json!(0));
        assert!(cpus
            .iter()
            .all(|c| c["online"].is_boolean() && c["can-offline"].is_boolean()));
    }

    #[test]
    fn set_vcpus_with_an_empty_list_changes_nothing() {
        let (agent, _dir) = ctx_agent();
        let mut ctx = Ctx::new(&agent);
        let mut map = serde_json::Map::new();
        map.insert("vcpus".into(), json!([]));
        assert_eq!(set_vcpus(&mut ctx, Args::new(map)).unwrap(), json!(0));
    }

    #[test]
    fn an_unknown_memory_block_is_not_found() {
        let response = set_block(u64::MAX - 1, true);
        if Path::new(MEMORY_DIR).is_dir() {
            assert_eq!(response.response, "not-found");
            assert_eq!(response.error_code, Some(libc::ENOENT));
        }
    }
}
