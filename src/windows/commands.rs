// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Windows QGA dispatch. Shared file/exec implementations retain Linux limits.

#[path = "../commands/exec.rs"]
pub mod exec;
#[path = "../commands/file.rs"]
pub mod file;

use crate::windows::{api, queries};
use crate::windows_support::table;
use crate::{
    agent::Agent,
    qmp::{parse_request, Args, QgaError, Reply},
};
use serde_json::{json, Value};

pub struct Ctx<'a> {
    pub agent: &'a Agent,
    pub delimit_next: bool,
}
impl<'a> Ctx<'a> {
    pub fn new(agent: &'a Agent) -> Self {
        Self {
            agent,
            delimit_next: false,
        }
    }
}
pub fn envelope(reply: Reply, id: Option<Value>) -> Value {
    let mut v = match reply {
        Ok(v) => json!({"return":v}),
        Err(e) => json!({"error":e.to_json()}),
    };
    if let Some(id) = id {
        v["id"] = id;
    }
    v
}
pub fn dispatch(ctx: &mut Ctx<'_>, request: Value) -> Option<Value> {
    let (request, id) = match parse_request(request) {
        Ok(v) => v,
        Err((e, id)) => return Some(envelope(Err(e), id)),
    };
    let name = request.execute.as_str();
    if !table::SUPPORTED.contains(&name) && !table::UNSUPPORTED.contains(&name) {
        return Some(envelope(
            Err(QgaError::command_not_found(format!(
                "The command {name} has not been found"
            ))),
            id,
        ));
    }
    if !ctx.agent.config.enabled(name) {
        return Some(envelope(
            Err(QgaError::command_not_found(format!(
                "Command {name} has been disabled: the command is not allowed"
            ))),
            id,
        ));
    }
    if table::UNSUPPORTED.contains(&name) {
        return Some(envelope(Err(table::unsupported(name)), id));
    }
    let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(ctx, name, Args::new(request.arguments))
    }))
    .unwrap_or_else(|_| Err(QgaError::generic("internal command error")));
    if name == "guest-shutdown" && reply.is_ok() {
        None
    } else {
        Some(envelope(reply, id))
    }
}
fn run(ctx: &mut Ctx<'_>, name: &str, mut args: Args) -> Reply {
    match name {
        "guest-sync" | "guest-sync-delimited" => {
            let id = args.int("id")?;
            args.finish()?;
            ctx.delimit_next = name == "guest-sync-delimited";
            Ok(json!(id))
        }
        "guest-file-open" => file::open(ctx, args),
        "guest-file-close" => file::close(ctx, args),
        "guest-file-read" => file::read(ctx, args),
        "guest-file-write" => file::write(ctx, args),
        "guest-file-seek" => file::seek(ctx, args),
        "guest-file-flush" => file::flush(ctx, args),
        "guest-exec" => exec::exec(ctx, args),
        "guest-exec-status" => exec::exec_status(ctx, args),
        "guest-set-time" => {
            let time = args.opt_int("time")?;
            args.finish()?;
            let time = time
                .ok_or_else(|| QgaError::generic("time is required on Windows; no readable RTC"))?;
            api::set_time(time).map_err(|e| QgaError::os("failed to set time", &e))?;
            Ok(json!({}))
        }
        "guest-shutdown" => {
            let mode = args.opt_str("mode")?.unwrap_or_else(|| "powerdown".into());
            args.finish()?;
            crate::qmp::enum_value(&mode, "mode", &["powerdown", "halt", "reboot"])?;
            api::shutdown(mode == "reboot").map_err(|e| QgaError::os("failed to shutdown", &e))?;
            Ok(json!({}))
        }
        "guest-set-user-password" => {
            let user = args.str("username")?;
            let password = args.str("password")?;
            let crypted = args.bool("crypted")?;
            args.finish()?;
            if crypted {
                return Err(QgaError::generic("Crypted passwords are not supported"));
            }
            let bytes = file::decode_base64(&password)?;
            let password =
                String::from_utf8(bytes).map_err(|_| QgaError::generic("password is not UTF-8"))?;
            api::set_password(&user, &password)
                .map_err(|e| QgaError::os("failed to set user password", &e))?;
            Ok(json!({}))
        }
        _ => {
            args.finish()?;
            match name {
                "guest-ping" => Ok(json!({})),
                "guest-info" => Ok(
                    json!({"version":env!("CARGO_PKG_VERSION"),"supported_commands":table::SUPPORTED.iter().rev()
                    .map(|name|json!({"name":name,"enabled":ctx.agent.config.enabled(name),"success-response":*name!="guest-shutdown"})).collect::<Vec<_>>()}),
                ),
                "guest-get-time" => {
                    let time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| QgaError::generic("system time before Unix epoch"))?;
                    Ok(json!(time.as_nanos() as i64))
                }
                "guest-get-host-name" => Ok(
                    json!({"host-name":api::hostname().map_err(|e|QgaError::os("failed to get hostname",&e))?}),
                ),
                "guest-get-osinfo" => queries::osinfo(),
                "guest-network-get-interfaces" => queries::interfaces(),
                "__io.virtainer_provision" => Ok(ctx
                    .agent
                    .provision
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()),
                _ => Err(table::unsupported(name)),
            }
        }
    }
}
