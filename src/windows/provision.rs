// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Raw seed discovery and SYSTEM provisioning. State never contains secrets.

use super::{api, data_dir};
use crate::windows_support::{
    fat12::Fat12,
    provision::{uuid, Phase, Provision, Record, State},
};
use crate::{agent::Agent, sys};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Seed {
    pub config: Provision,
    pub disk: PathBuf,
    pub fat: Fat12,
}
impl Seed {
    pub fn stable(&self) -> Result<(), String> {
        let file = File::open(&self.disk).map_err(|_| "cannot reread seed".to_string())?;
        let fat = Fat12::read(file).map_err(|_| "cannot reread FAT12 seed".to_string())?;
        if fat == self.fat {
            Ok(())
        } else {
            Err("seed content changed during provisioning".into())
        }
    }
}
pub fn discover() -> Result<Option<Seed>, String> {
    let mut found = None;
    for number in 0..256 {
        let path = PathBuf::from(format!(r"\\.\PhysicalDrive{number}"));
        let Ok(file) = File::open(&path) else {
            continue;
        };
        let fat = match Fat12::read(file) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let bytes = fat
            .file("virtainer-provision.json")
            .map_err(|_| "invalid provision file on FAT12 seed".to_string())?;
        // The contract filename on a valid FAT12 volume is the seed signature;
        // no dependency on Windows assigning a drive letter or a particular label.
        let Some(bytes) = bytes else {
            if ["cidata", "VIRTSEED", "VIRTWIN"]
                .iter()
                .any(|label| fat.label().eq_ignore_ascii_case(label))
            {
                return Err("labeled seed is missing virtainer-provision.json".into());
            }
            continue;
        };
        if found.is_some() {
            return Err("multiple Windows provision seeds found".into());
        }
        let config = Provision::parse(&bytes)?;
        let seed = Seed {
            config,
            disk: path,
            fat,
        };
        seed.stable()?;
        found = Some(seed);
    }
    Ok(found)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write_with(path, bytes, |from, to| {
        clear_readonly(to);
        api::replace(from, to).map_err(|e| e.to_string())
    })
}
/// A read-only destination makes the replace fail; the containing directory is
/// private, so clearing the attribute on an existing regular file is safe.
// On Windows this clears FILE_ATTRIBUTE_READONLY only; this module never builds elsewhere.
#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.is_file() && meta.permissions().readonly() {
            let mut permissions = meta.permissions();
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }
}
pub fn atomic_write_with(
    path: &Path,
    bytes: &[u8],
    replace: impl FnOnce(&Path, &Path) -> Result<(), String>,
) -> Result<(), String> {
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    // The containing directory has a SYSTEM/Administrators-only ACL. Do not
    // follow stale temporary files or reparse points from a previous failure.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        replace(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
fn state_dir() -> PathBuf {
    data_dir().join("instances")
}
fn load(p: &Provision) -> Result<Record, String> {
    let path = state_dir().join(format!("{}.json", p.instance_id));
    crate::windows_support::provision::load_record(&path, p)
}
fn save(r: &Record) -> Result<(), String> {
    atomic_write(
        &state_dir().join(format!("{}.json", r.instance_id)),
        &serde_json::to_vec(r).map_err(|e| e.to_string())?,
    )
}
pub fn last_report() -> Result<Value, String> {
    let current = match std::fs::read_to_string(data_dir().join("current-instance")) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(pending()),
        Err(_) => return Err("cannot read current instance".into()),
    };
    if !uuid(&current) {
        return Err("invalid persisted instance ID".into());
    }
    let file = std::fs::File::open(state_dir().join(format!("{current}.json")))
        .map_err(|_| "cannot read current provision state".to_string())?;
    Ok(crate::windows_support::provision::read_record(file, &current)?.report())
}
pub fn pending() -> Value {
    json!({"instance_id":null,"seed_version":null,"state":"pending","errors":[],"agent_version":env!("CARGO_PKG_VERSION")})
}
fn secure_state() -> Result<(), String> {
    super::secure_directories()?;
    sys::protect_dir(&state_dir())
}

fn apply_system(seed: &Seed, phase: Phase) -> Result<(), String> {
    seed.stable()?;
    let p = &seed.config;
    let result = match phase {
        // The image's specialize RunSynchronousCommand runs as SYSTEM before the
        // network stack's RPC services exist, so only the hostname is set here.
        Phase::Specialize => match &p.hostname {
            Some(name) => api::set_hostname(name).map_err(|_| "set hostname failed".to_string()),
            None => Ok(()),
        },
        Phase::Service => service_phase(p),
    };
    if let Err(error) = &result {
        crate::error!("provisioning step failed: {error}");
    }
    result?;
    seed.stable()
}
fn service_phase(p: &crate::windows_support::provision::Provision) -> Result<(), String> {
    sys::ps(
        include_str!("network.ps1"),
        &crate::windows_support::network::plan(&p.network),
        "configure network",
        &[],
    )?;
    let admin = p
        .admin
        .as_ref()
        .map(|a| json!({"username":a.username,"password":a.password}));
    let secrets: Vec<&str> = p.admin.iter().map(|a| a.password.as_str()).collect();
    sys::ps(
        include_str!("accounts.ps1"),
        &json!({"admin":admin,"timezone":p.timezone,"keys":p.ssh_authorized_keys}),
        "configure account, keys and timezone",
        &secrets,
    )?;
    Ok(())
}
fn user_script(seed: &Seed) -> Result<(), String> {
    seed.stable()?;
    let bytes = seed
        .fat
        .file("user-script.ps1")
        .map_err(|_| "cannot read user script".to_string())?
        .ok_or_else(|| "user-script.ps1 is missing".to_string())?;
    // Windows PowerShell 5.1 treats a BOM-less script as the ANSI code page.
    // Seed text is UTF-8; preserve an explicit Unicode BOM or add a UTF-8 BOM.
    let bytes = if bytes.starts_with(&[0xef, 0xbb, 0xbf])
        || bytes.starts_with(&[0xff, 0xfe])
        || bytes.starts_with(&[0xfe, 0xff])
    {
        bytes
    } else {
        std::str::from_utf8(&bytes)
            .map_err(|_| "user script must be UTF-8 or carry a Unicode BOM".to_string())?;
        let mut encoded = vec![0xef, 0xbb, 0xbf];
        encoded.extend_from_slice(&bytes);
        encoded
    };
    let path = data_dir().join("user-script.ps1");
    atomic_write(&path, &bytes)?;
    // No script text or output is logged or persisted; SYSTEM is inherited.
    let mut child = sys::powershell()
        .arg("-File")
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| "cannot start user script".to_string())?;
    let started = Instant::now();
    let result = loop {
        match child.try_wait() {
            Ok(Some(s)) if s.success() => break seed.stable(),
            Ok(Some(s)) => {
                break Err(format!(
                    "user script failed (exit status {})",
                    s.code().unwrap_or(-1)
                ))
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("cannot wait for user script; outcome unknown".into());
            }
            Ok(None) => {}
        }
        if super::service::stopping() || started.elapsed() > Duration::from_secs(1800) {
            let _ = child.kill();
            let _ = child.wait();
            break Err("user script stopped or timed out; outcome unknown".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = std::fs::remove_file(path);
    result
}
fn apply(seed: &Seed, phase: Phase, agent: Option<&Agent>) -> Result<Record, String> {
    secure_state()?;
    let _lock = sys::provision_lock(&data_dir().join("provision.lock"))?;
    let mut record = load(&seed.config)?;
    save(&record)?;
    atomic_write(
        &data_dir().join("current-instance"),
        record.instance_id.as_bytes(),
    )?;
    let effective_hostname = if matches!(phase, Phase::Service)
        && seed.config.hostname.is_some()
        && !matches!(record.state, State::Done | State::Failed)
    {
        Some(api::hostname().map_err(|_| "cannot read active hostname".to_string())?)
    } else {
        None
    };
    let result = record.apply(
        &seed.config,
        phase,
        effective_hostname.as_deref(),
        |r| {
            if r.state == State::Done {
                seed.stable()?;
            }
            save(r)?;
            if let Some(agent) = agent {
                *agent.provision.lock().unwrap_or_else(|p| p.into_inner()) = r.report();
            }
            Ok(())
        },
        |phase| apply_system(seed, phase),
        || user_script(seed),
    );
    // A failed final checkpoint can leave `record` marked done in memory; publish only on success.
    result?;
    if let Some(agent) = agent {
        *agent.provision.lock().unwrap_or_else(|p| p.into_inner()) = record.report();
    }
    Ok(record)
}
pub fn specialize() -> Result<(), String> {
    let seed = discover()?.ok_or_else(|| "Windows provision seed not found".to_string())?;
    let record = apply(&seed, Phase::Specialize, None)?;
    if record.state == State::Failed {
        return Err("specialize provisioning failed; inspect persisted errors".into());
    }
    Ok(())
}
pub fn serve(agent: Arc<Agent>) {
    while !super::service::stopping() {
        match discover() {
            Ok(Some(seed)) => {
                match super::update::stage_seed(&seed) {
                    Ok(true) => {
                        super::service::request_stop();
                        return;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        let mut report = seed.config_report();
                        report["state"] = json!("failed");
                        report["errors"] = json!([error]);
                        *agent.provision.lock().unwrap_or_else(|p| p.into_inner()) = report;
                        return;
                    }
                }
                match apply(&seed, Phase::Service, Some(&agent)) {
                    Ok(record) if record.state == State::Pending => {}
                    Ok(_) => return,
                    Err(e) => {
                        let mut report = seed.config_report();
                        report["state"] = json!("failed");
                        report["errors"] = json!([e]);
                        *agent.provision.lock().unwrap_or_else(|p| p.into_inner()) = report;
                        return;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                let mut report = pending();
                report["state"] = json!("failed");
                report["errors"] = json!([e]);
                *agent.provision.lock().unwrap_or_else(|p| p.into_inner()) = report;
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
impl Seed {
    fn config_report(&self) -> Value {
        Record::new(&self.config).report()
    }
}
