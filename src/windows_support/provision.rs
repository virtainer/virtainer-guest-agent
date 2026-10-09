// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Binding Windows provisioning schema and durable transitions. No OS calls.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provision {
    pub schema: u32,
    pub instance_id: String,
    pub seed_version: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub admin: Option<Admin>,
    #[serde(default)]
    pub ssh_authorized_keys: Vec<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub network: Vec<Network>,
    #[serde(default)]
    pub user_script: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    pub username: String,
    pub password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub mac: String,
    pub addresses: Vec<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
}

fn clean(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(char::is_control)
}
pub fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}
pub fn mac(s: &str) -> Option<String> {
    let parts: Vec<_> = s.split(':').collect();
    (parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())))
    .then(|| s.to_ascii_lowercase())
}
pub fn address(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = s.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= if ip.is_ipv4() { 32 } else { 128 }).then_some((ip, prefix))
}

impl Provision {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 1 << 20 {
            return Err("provision JSON exceeds 1 MiB".into());
        }
        // Do not include parser context or values: the document contains credentials.
        let p: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid provision JSON".to_string())?;
        p.validate()?;
        Ok(p)
    }
    fn validate(&self) -> Result<(), String> {
        let invalid = |field| Err(format!("invalid provision field: {field}"));
        if self.schema != 1 {
            return invalid("schema");
        }
        if !uuid(&self.instance_id) {
            return invalid("instance_id");
        }
        if self.seed_version.len() != 64
            || !self.seed_version.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return invalid("seed_version");
        }
        if let Some(s) = &self.hostname {
            if s.len() > 15
                || s.is_empty()
                || s.bytes().all(|b| b.is_ascii_digit())
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || s.starts_with('-')
                || s.ends_with('-')
            {
                return invalid("hostname");
            }
        }
        if let Some(admin) = &self.admin {
            if !clean(&admin.username)
                || admin.username.len() > 20
                || admin.username.contains([
                    '"', '/', '\\', '[', ']', ':', ';', '|', '=', '+', ',', '?', '*', '<', '>', '@',
                ])
                || admin.username.ends_with(['.', ' '])
                || admin.password.is_empty()
                || admin.password.contains('\0')
                || admin.password.encode_utf16().count() > 256
            {
                return invalid("admin");
            }
        }
        if self.ssh_authorized_keys.len() > 1024
            || self
                .ssh_authorized_keys
                .iter()
                .any(|s| !clean(s) || s.len() > 16384)
        {
            return invalid("ssh_authorized_keys");
        }
        if self
            .timezone
            .as_ref()
            .is_some_and(|s| !clean(s) || s.len() > 128)
        {
            return invalid("timezone");
        }
        if self
            .user_script
            .as_deref()
            .is_some_and(|s| s != "user-script.ps1")
        {
            return invalid("user_script");
        }
        let mut seen = HashSet::new();
        if self.network.len() > 256 {
            return invalid("network");
        }
        for n in &self.network {
            let Some(mac) = mac(&n.mac) else {
                return invalid("network.mac");
            };
            if !seen.insert(mac) {
                return invalid("network.mac duplicate");
            }
            if n.addresses.len() > 64 || n.addresses.iter().any(|s| address(s).is_none()) {
                return invalid("network.addresses");
            }
            if n.gateway.as_ref().is_some_and(|s| {
                s.parse::<IpAddr>().is_err()
                    || !n.addresses.iter().any(|a| {
                        address(a).is_some_and(|(ip, _)| {
                            ip.is_ipv4() == s.parse::<IpAddr>().unwrap().is_ipv4()
                        })
                    })
            }) {
                return invalid("network.gateway");
            }
            if n.dns.len() > 16 || n.dns.iter().any(|s| s.parse::<IpAddr>().is_err()) {
                return invalid("network.dns");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Pending,
    Applying,
    Done,
    Failed,
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Script {
    #[default]
    Pending,
    Started,
    Finished,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub instance_id: String,
    pub seed_version: String,
    pub state: State,
    pub errors: Vec<String>,
    pub specialized: bool,
    pub configured: bool,
    pub script: Script,
    pub script_requested: bool,
}
#[derive(Clone, Copy)]
pub enum Phase {
    Specialize,
    Service,
}

impl Record {
    pub fn new(p: &Provision) -> Self {
        Self {
            instance_id: p.instance_id.clone(),
            seed_version: p.seed_version.clone(),
            state: State::Pending,
            errors: Vec::new(),
            specialized: false,
            configured: false,
            script: Script::Pending,
            script_requested: p.user_script.is_some(),
        }
    }
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({"instance_id":self.instance_id, "seed_version":self.seed_version,
            "state":self.state, "errors":self.errors, "agent_version":env!("CARGO_PKG_VERSION")})
    }
    fn fail(&mut self, error: String) {
        self.state = State::Failed;
        self.errors.push(error);
    }

    /// Every action is preceded by a durable checkpoint. Uncertain system
    /// changes fail closed. Script uncertainty is non-blocking per the contract.
    pub fn apply(
        &mut self,
        p: &Provision,
        phase: Phase,
        effective_hostname: Option<&str>,
        mut save: impl FnMut(&Self) -> Result<(), String>,
        mut system: impl FnMut(Phase) -> Result<(), String>,
        mut script: impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        if self.instance_id != p.instance_id {
            return Err("provision instance mismatch".into());
        }
        if matches!(self.state, State::Done | State::Failed) {
            return Ok(());
        }
        if self.seed_version != p.seed_version {
            self.fail("seed changed while provisioning this instance".into());
            return save(self);
        }
        if self.state == State::Applying && !self.configured {
            self.fail("system provisioning interrupted; outcome unknown".into());
            return save(self);
        }
        match phase {
            Phase::Specialize => {
                if self.specialized {
                    return Ok(());
                }
                self.state = State::Applying;
                save(self)?;
                match system(phase) {
                    Ok(()) => {
                        self.specialized = true;
                        self.state = State::Pending;
                    }
                    Err(e) => self.fail(e),
                }
                save(self)
            }
            Phase::Service => {
                if !self.specialized
                    || p.hostname.as_deref().is_some_and(|requested| {
                        !effective_hostname
                            .is_some_and(|active| active.eq_ignore_ascii_case(requested))
                    })
                {
                    // An ordinary service boot must not rename the machine and
                    // claim success while the active name still needs a reboot.
                    return Ok(());
                }
                if !self.configured {
                    self.state = State::Applying;
                    save(self)?;
                    if let Err(e) = system(phase) {
                        self.fail(e);
                        return save(self);
                    }
                    self.configured = true;
                    save(self)?;
                }
                if p.user_script.is_some() {
                    match self.script {
                        Script::Pending => {
                            self.script = Script::Started;
                            save(self)?;
                            if let Err(e) = script() {
                                self.errors.push(e);
                            }
                            self.script = Script::Finished;
                        }
                        Script::Started => {
                            self.errors.push(
                                "user script interrupted; outcome unknown; not replayed".into(),
                            );
                            self.script = Script::Finished;
                        }
                        Script::Finished => {}
                    }
                }
                self.state = State::Done;
                save(self)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn document() -> serde_json::Value {
        json!({"schema":1,"instance_id":"00000000-0000-4000-8000-000000000001",
            "seed_version":"a".repeat(64),"hostname":"WEB-01",
            "admin":{"username":"Administrator","password":"private-test-value"},
            "ssh_authorized_keys":["ssh-ed25519 test"],"timezone":"UTC","network":[
                {"mac":"52:54:00:aa:bb:cc","addresses":["10.0.0.5/24","2001:db8::2/64"],"gateway":"10.0.0.1","dns":["1.1.1.1"]}],
            "user_script":"user-script.ps1"})
    }
    fn config() -> Provision {
        Provision::parse(&serde_json::to_vec(&document()).unwrap()).unwrap()
    }
    #[test]
    fn schema_and_validation_do_not_leak_credentials() {
        let p = config();
        assert_eq!(p.network.len(), 1);
        for (field, v) in [
            ("schema", json!(2)),
            ("hostname", json!("too-long-hostname")),
            ("hostname", json!("123")),
            ("hostname", json!("bad.name")),
            ("instance_id", json!("../x")),
            ("seed_version", json!("x")),
            ("user_script", json!("../run.ps1")),
            ("timezone", json!("UTC\n")),
            ("network", json!([{"mac":"bad","addresses":[]}])),
        ] {
            let mut d = document();
            d[field] = v;
            let err = Provision::parse(&serde_json::to_vec(&d).unwrap())
                .err()
                .unwrap();
            assert!(!err.contains("private-test-value"));
        }
        let mut d = document();
        d["unknown"] = json!(true);
        assert!(Provision::parse(&serde_json::to_vec(&d).unwrap()).is_err());
        for a in ["10.0.0.1/33", "::1/129", "10.0.0.1", "bad/1"] {
            assert!(address(a).is_none());
        }
        assert_eq!(mac("52:54:00:AA:BB:CC").unwrap(), "52:54:00:aa:bb:cc");
        let mut d = document();
        d["network"] = json!([]);
        assert!(Provision::parse(&serde_json::to_vec(&d).unwrap())
            .unwrap()
            .network
            .is_empty());
    }
    #[test]
    fn active_hostname_gates_accounts_and_script_across_service_restarts() {
        let p = config();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let save = |r: &Record| {
            std::fs::write(&path, serde_json::to_vec(r).unwrap()).map_err(|e| e.to_string())
        };
        let mut r = Record::new(&p);
        r.apply(&p, Phase::Specialize, None, save, |_| Ok(()), || panic!())
            .unwrap();
        for active in [Some("OLD-NAME"), None, Some("OLD-NAME")] {
            let mut r = load_record(&path, &p).unwrap();
            assert!(r.specialized);
            r.apply(
                &p,
                Phase::Service,
                active,
                |_| panic!(),
                |_| panic!(),
                || panic!(),
            )
            .unwrap();
            assert_eq!(r.report()["state"], "pending");
            assert!(!r.configured);
            assert_eq!(r.script, Script::Pending);
        }
        let mut r = load_record(&path, &p).unwrap();
        r.apply(
            &p,
            Phase::Service,
            Some("web-01"),
            save,
            |_| Ok(()),
            || Ok(()),
        )
        .unwrap();
        let mut r = load_record(&path, &p).unwrap();
        assert_eq!(r.state, State::Done);
        r.apply(
            &p,
            Phase::Service,
            Some("web-01"),
            |_| panic!(),
            |_| panic!(),
            || panic!(),
        )
        .unwrap();
    }
    #[test]
    fn no_requested_rename_needs_no_hostname_observation() {
        let mut p = config();
        p.hostname = None;
        let mut r = Record::new(&p);
        r.specialized = true;
        r.apply(&p, Phase::Service, None, |_| Ok(()), |_| Ok(()), || Ok(()))
            .unwrap();
        assert_eq!(r.state, State::Done);
    }
    #[test]
    fn specialize_then_service_once_and_script_failure_still_done() {
        let p = config();
        let mut r = Record::new(&p);
        let mut calls = 0;
        r.apply(
            &p,
            Phase::Service,
            Some("web-01"),
            |_| Ok(()),
            |_| panic!("before specialize"),
            || panic!(),
        )
        .unwrap();
        assert_eq!(r.state, State::Pending);
        r.apply(
            &p,
            Phase::Specialize,
            Some("web-01"),
            |_| Ok(()),
            |_| {
                calls += 1;
                Ok(())
            },
            || panic!(),
        )
        .unwrap();
        r.apply(
            &p,
            Phase::Service,
            Some("web-01"),
            |_| Ok(()),
            |_| {
                calls += 1;
                Ok(())
            },
            || Err("user script failed (exit status 1)".into()),
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(r.state, State::Done);
        assert_eq!(r.errors.len(), 1);
        for phase in [Phase::Specialize, Phase::Service] {
            r.apply(
                &p,
                phase,
                Some("web-01"),
                |_| panic!(),
                |_| panic!(),
                || panic!(),
            )
            .unwrap();
        }
        let mut newer = config();
        newer.seed_version = "b".repeat(64);
        r.apply(
            &newer,
            Phase::Service,
            Some("web-01"),
            |_| panic!(),
            |_| panic!(),
            || panic!(),
        )
        .unwrap();
        assert_eq!(r.seed_version, p.seed_version);
        let new_instance = Record::new(&Provision {
            instance_id: "00000000-0000-4000-8000-000000000002".into(),
            ..config()
        });
        assert_eq!(new_instance.state, State::Pending);
        assert_eq!(r.report()["state"], "done");
        assert!(r.report().get("specialized").is_none());
    }
    #[test]
    fn durable_checkpoints_precede_actions_and_uncertain_actions_are_not_replayed() {
        let p = config();
        let mut r = Record::new(&p);
        assert!(r
            .apply(
                &p,
                Phase::Specialize,
                Some("web-01"),
                |_| Err("disk full".into()),
                |_| panic!(),
                || panic!()
            )
            .is_err());
        let mut recovered: Record =
            serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        recovered
            .apply(
                &p,
                Phase::Specialize,
                Some("web-01"),
                |_| Ok(()),
                |_| panic!(),
                || panic!(),
            )
            .unwrap();
        assert_eq!(recovered.state, State::Failed);
        let mut r = Record::new(&p);
        r.specialized = true;
        r.configured = true;
        r.state = State::Applying;
        r.script = Script::Started;
        r.apply(
            &p,
            Phase::Service,
            Some("web-01"),
            |_| Ok(()),
            |_| panic!(),
            || panic!("must not replay"),
        )
        .unwrap();
        assert_eq!(r.state, State::Done);
        assert_eq!(r.errors.len(), 1);
    }
    #[test]
    fn system_failure_and_seed_drift_are_terminal() {
        let p = config();
        let mut r = Record::new(&p);
        r.apply(
            &p,
            Phase::Specialize,
            Some("web-01"),
            |_| Ok(()),
            |_| Err("network failed".into()),
            || panic!(),
        )
        .unwrap();
        assert_eq!(r.state, State::Failed);
        r.apply(
            &p,
            Phase::Specialize,
            Some("web-01"),
            |_| panic!(),
            |_| panic!(),
            || panic!(),
        )
        .unwrap();
        let mut r = Record::new(&p);
        r.seed_version = "b".repeat(64);
        r.apply(
            &p,
            Phase::Specialize,
            Some("web-01"),
            |_| Ok(()),
            |_| panic!(),
            || panic!(),
        )
        .unwrap();
        assert_eq!(r.state, State::Failed);
    }
}

/// Read a bounded, credential-free record. Missing state is a new instance;
/// unreadable or corrupt state must never be interpreted as a fresh boot.
pub fn load_record(path: &std::path::Path, p: &Provision) -> Result<Record, String> {
    match std::fs::File::open(path) {
        Ok(file) => read_record(file, &p.instance_id),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Record::new(p)),
        Err(_) => Err("cannot read persisted provisioning record".into()),
    }
}

/// Reads a persisted record, bounded in size, and checks that it belongs to
/// `instance_id` and that its state flags are consistent.
pub fn read_record(file: std::fs::File, instance_id: &str) -> Result<Record, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take((1 << 20) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read persisted provisioning record")?;
    if bytes.len() > 1 << 20 {
        return Err("persisted provisioning record exceeds limit".into());
    }
    let r: Record = serde_json::from_slice(&bytes)
        .map_err(|_| "invalid persisted provisioning record".to_string())?;
    if r.instance_id != instance_id
        || !uuid(&r.instance_id)
        || r.seed_version.len() != 64
        || !r.seed_version.bytes().all(|b| b.is_ascii_hexdigit())
        || (r.configured && !r.specialized)
        || (r.state == State::Done
            && (!r.specialized
                || !r.configured
                || (r.script_requested && r.script != Script::Finished)))
    {
        return Err("persisted provisioning record is inconsistent".into());
    }
    Ok(r)
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn restart_restores_completion_and_missing_corrupt_and_other_instances_are_distinct() {
        let p = Provision::parse(&serde_json::to_vec(&serde_json::json!({
            "schema": 1, "instance_id":"00000000-0000-4000-8000-000000000001", "seed_version":"a".repeat(64)
        })).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(load_record(&path, &p).unwrap().state, State::Pending);
        let mut r = Record::new(&p);
        let save = |r: &Record| {
            std::fs::write(&path, serde_json::to_vec(r).unwrap()).map_err(|e| e.to_string())
        };
        r.apply(
            &p,
            Phase::Specialize,
            Some("web-01"),
            save,
            |_| Ok(()),
            || panic!(),
        )
        .unwrap();
        let mut r = load_record(&path, &p).unwrap();
        r.apply(
            &p,
            Phase::Service,
            Some("web-01"),
            save,
            |_| Ok(()),
            || panic!(),
        )
        .unwrap();
        let mut r = load_record(&path, &p).unwrap();
        r.apply(
            &p,
            Phase::Service,
            Some("web-01"),
            |_| panic!(),
            |_| panic!(),
            || panic!(),
        )
        .unwrap();
        assert_eq!(r.state, State::Done);
        let serialized = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&serialized).contains("password"));
        let other = Provision {
            instance_id: "00000000-0000-4000-8000-000000000002".into(),
            ..p
        };
        assert!(load_record(&path, &other).is_err());
        assert_eq!(
            load_record(&dir.path().join("other.json"), &other)
                .unwrap()
                .state,
            State::Pending
        );
        std::fs::write(&path, b"{").unwrap();
        assert!(load_record(&path, &other).is_err());
        let mut invalid = Record::new(&other);
        invalid.state = State::Done;
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(load_record(&path, &other).is_err());
    }
}
