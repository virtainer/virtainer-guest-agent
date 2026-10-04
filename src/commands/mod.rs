// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Command table and dispatch.
//!
//! The table follows the order of QEMU's `qga/qapi-schema.json` so that
//! `guest-info` lists commands in the same order qemu-ga does. Commands that
//! are Windows-only (`guest-get-devices`) or that Cloud Hypervisor cannot wake
//! from (`guest-suspend-*`) are absent: advertising them would only promise a
//! failure. Virtainer's own commands come last, so `guest-info` lists them
//! first. They follow QAPI's rule for downstream extensions: `__` plus the
//! vendor's reversed domain, virtainer.io, hence `__io.virtainer_*`.

pub mod core;
pub mod exec;
pub mod file;
pub mod fsfreeze;
pub mod fsinfo;
pub mod hotplug;
pub mod mounts;
pub mod network;
pub mod nvme;
pub mod shell;
pub mod stats;
pub mod users;

use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{Map, Value};

use crate::agent::Agent;
use crate::qmp::{parse_request, Args, QgaError, Reply};

/// Per-connection context handed to every command.
pub struct Ctx<'a> {
    pub agent: &'a Agent,
    /// Set by `guest-sync-delimited`: prefix the next reply with 0xFF.
    pub delimit_next: bool,
    /// Set by `__io.virtainer_shell`: after the reply, this connection
    /// carries the session instead of QGA messages.
    pub upgrade: Option<crate::shell::Session<'a>>,
}

impl<'a> Ctx<'a> {
    pub fn new(agent: &'a Agent) -> Self {
        Ctx {
            agent,
            delimit_next: false,
            upgrade: None,
        }
    }
}

type Handler = fn(&mut Ctx<'_>, Args) -> Reply;

pub struct Command {
    pub name: &'static str,
    pub run: Handler,
    /// False for commands whose success is the guest going away.
    pub success_response: bool,
}

const fn cmd(name: &'static str, run: Handler) -> Command {
    Command {
        name,
        run,
        success_response: true,
    }
}

pub static COMMANDS: &[Command] = &[
    cmd("guest-sync-delimited", core::sync_delimited),
    cmd("guest-sync", core::sync),
    cmd("guest-ping", core::ping),
    cmd("guest-get-time", core::get_time),
    cmd("guest-set-time", core::set_time),
    cmd("guest-info", core::info),
    Command {
        name: "guest-shutdown",
        run: core::shutdown,
        success_response: false,
    },
    cmd("guest-file-open", file::open),
    cmd("guest-file-close", file::close),
    cmd("guest-file-read", file::read),
    cmd("guest-file-write", file::write),
    cmd("guest-file-seek", file::seek),
    cmd("guest-file-flush", file::flush),
    cmd("guest-fsfreeze-status", fsfreeze::status),
    cmd("guest-fsfreeze-freeze", fsfreeze::freeze),
    cmd("guest-fsfreeze-freeze-list", fsfreeze::freeze_list),
    cmd("guest-fsfreeze-thaw", fsfreeze::thaw),
    cmd("guest-fstrim", fsfreeze::fstrim),
    cmd("guest-network-get-interfaces", network::get_interfaces),
    cmd("guest-get-vcpus", hotplug::get_vcpus),
    cmd("guest-set-vcpus", hotplug::set_vcpus),
    cmd("guest-get-disks", fsinfo::get_disks),
    cmd("guest-get-fsinfo", fsinfo::get_fsinfo),
    cmd("guest-set-user-password", users::set_user_password),
    cmd("guest-get-memory-blocks", hotplug::get_memory_blocks),
    cmd("guest-set-memory-blocks", hotplug::set_memory_blocks),
    cmd(
        "guest-get-memory-block-info",
        hotplug::get_memory_block_info,
    ),
    cmd("guest-exec-status", exec::exec_status),
    cmd("guest-exec", exec::exec),
    cmd("guest-get-host-name", core::get_host_name),
    cmd("guest-get-users", users::get_users),
    cmd("guest-get-timezone", core::get_timezone),
    cmd("guest-get-osinfo", core::get_osinfo),
    cmd(
        "guest-ssh-get-authorized-keys",
        users::ssh_get_authorized_keys,
    ),
    cmd(
        "guest-ssh-add-authorized-keys",
        users::ssh_add_authorized_keys,
    ),
    cmd(
        "guest-ssh-remove-authorized-keys",
        users::ssh_remove_authorized_keys,
    ),
    cmd("guest-get-diskstats", stats::get_diskstats),
    cmd("guest-get-cpustats", stats::get_cpustats),
    cmd("guest-get-load", stats::get_load),
    cmd("guest-network-get-route", network::get_route),
    cmd(shell::NAME, shell::open),
];

/// What may run while filesystems are frozen: nothing that could write to a
/// frozen disk and wedge the agent (qemu-ga's `ga_freeze_allowlist`).
pub const ALLOWED_WHILE_FROZEN: &[&str] = &[
    "guest-ping",
    "guest-info",
    "guest-sync",
    "guest-sync-delimited",
    "guest-fsfreeze-status",
    "guest-fsfreeze-thaw",
];

pub fn find(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|c| c.name == name)
}

/// qemu-ga's filter order: allow-list, then block-list, and the freeze
/// allow-list above both. The Shell runs commands just as `guest-exec` does,
/// so a guest that turns `guest-exec` off turns the Shell off too.
pub fn is_enabled(agent: &Agent, name: &str) -> bool {
    if agent.freezer.is_frozen() {
        return ALLOWED_WHILE_FROZEN.contains(&name);
    }
    let config = &agent.config;
    let allowed = config
        .allow_rpcs
        .as_ref()
        .is_none_or(|allow| allow.iter().any(|n| n == name));
    allowed
        && !config.block_rpcs.iter().any(|n| n == name)
        && (name != shell::NAME || is_enabled(agent, "guest-exec"))
}

/// Run one request; `None` means no reply is sent (a successful
/// `guest-shutdown`).
pub fn dispatch(ctx: &mut Ctx<'_>, request: Value) -> Option<Value> {
    let (reply, id) = match parse_request(request) {
        Err((error, id)) => (Err(error), id),
        Ok((request, id)) => match find(&request.execute) {
            None => (
                Err(QgaError::command_not_found(format!(
                    "The command {} has not been found",
                    request.execute
                ))),
                id,
            ),
            Some(command) if !is_enabled(ctx.agent, command.name) => (
                Err(QgaError::command_not_found(format!(
                    "Command {} has been disabled: the command is not allowed",
                    command.name
                ))),
                id,
            ),
            Some(command) => {
                let args = Args::new(request.arguments);
                let reply = catch_unwind(AssertUnwindSafe(|| (command.run)(ctx, args)))
                    .unwrap_or_else(|panic| {
                        let what = panic
                            .downcast_ref::<String>()
                            .map(String::as_str)
                            .or_else(|| panic.downcast_ref::<&str>().copied())
                            .unwrap_or("unknown panic");
                        crate::error!("{} failed internally: {what}", command.name);
                        Err(QgaError::generic(format!("internal error: {what}")))
                    });
                if reply.is_ok() && !command.success_response {
                    return None;
                }
                (reply, id)
            }
        },
    };
    Some(envelope(reply, id))
}

pub fn envelope(reply: Reply, id: Option<Value>) -> Value {
    let mut response = Map::new();
    match reply {
        Ok(value) => response.insert("return".into(), value),
        Err(error) => response.insert("error".into(), error.to_json()),
    };
    if let Some(id) = id {
        response.insert("id".into(), id);
    }
    Value::Object(response)
}

/// For commands without arguments.
pub fn no_args(args: Args) -> Result<(), QgaError> {
    args.finish()
}

/// Serialize a reply struct; derived structs cannot fail to convert.
pub fn to_value<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("reply types serialize to JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use serde_json::json;

    fn agent(config: Config) -> (Agent, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Agent::new(config, dir.path().to_path_buf()), dir)
    }

    fn run(agent: &Agent, request: Value) -> Value {
        let mut ctx = Ctx::new(agent);
        dispatch(&mut ctx, request).unwrap()
    }

    #[test]
    fn unknown_and_blocked_commands_are_command_not_found() {
        let (agent, _dir) = agent(Config {
            block_rpcs: vec!["guest-get-osinfo".into()],
            ..Config::default()
        });
        assert_eq!(
            run(&agent, json!({"execute": "guest-nope", "id": 1})),
            json!({"error": {"class": "CommandNotFound", "desc": "The command guest-nope has not been found"}, "id": 1})
        );
        assert_eq!(
            run(&agent, json!({"execute": "guest-get-osinfo"})),
            json!({"error": {"class": "CommandNotFound", "desc": "Command guest-get-osinfo has been disabled: the command is not allowed"}})
        );
    }

    #[test]
    fn allow_list_then_block_list() {
        let (agent, _dir) = agent(Config {
            allow_rpcs: Some(vec!["guest-ping".into(), "guest-info".into()]),
            block_rpcs: vec!["guest-info".into()],
            ..Config::default()
        });
        assert!(is_enabled(&agent, "guest-ping"));
        assert!(!is_enabled(&agent, "guest-info"));
        assert!(!is_enabled(&agent, "guest-exec"));
    }

    #[test]
    fn every_command_rejects_an_unexpected_argument_before_acting() {
        let (agent, _dir) = agent(Config::default());
        for command in COMMANDS {
            let reply = run(
                &agent,
                json!({"execute": command.name, "arguments": {"zz-bogus": 1}}),
            );
            let desc = reply["error"]["desc"].as_str().unwrap_or_default();
            // Required arguments are checked first, like QAPI does.
            assert!(
                desc == "Parameter 'zz-bogus' is unexpected" || desc.ends_with("is missing"),
                "{}: {reply}",
                command.name
            );
        }
    }

    #[test]
    fn the_shell_follows_guest_exec() {
        let (blocked, _dir) = agent(Config {
            block_rpcs: vec!["guest-exec".into()],
            ..Config::default()
        });
        assert!(!is_enabled(&blocked, shell::NAME));
        let (allowed_alone, _dir) = agent(Config {
            allow_rpcs: Some(vec![shell::NAME.into()]),
            ..Config::default()
        });
        assert!(!is_enabled(&allowed_alone, shell::NAME));
        let (allowed_both, _dir) = agent(Config {
            allow_rpcs: Some(vec![shell::NAME.into(), "guest-exec".into()]),
            ..Config::default()
        });
        assert!(is_enabled(&allowed_both, shell::NAME));
        let (default, _dir) = agent(Config::default());
        assert!(is_enabled(&default, shell::NAME));
    }

    #[test]
    fn id_is_echoed_verbatim() {
        let (agent, _dir) = agent(Config::default());
        assert_eq!(
            run(
                &agent,
                json!({"execute": "guest-ping", "id": {"any": ["json"]}})
            ),
            json!({"return": {}, "id": {"any": ["json"]}})
        );
    }
}
