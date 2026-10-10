// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Windows entry points; Linux's service installation and startup stay separate.

pub mod api;
mod provision;
pub mod queries;
pub mod service;
mod update;
mod vsock;
use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()))
        .join("Virtainer/GuestAgent")
}
pub fn binary_path() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()))
        .join("Virtainer/GuestAgent/virtainer-guest-agent.exe")
}
pub fn secure_directories() -> Result<(), String> {
    let data = data_dir();
    let binary = binary_path();
    for path in [
        data.parent().unwrap(),
        data.as_path(),
        binary.parent().unwrap().parent().unwrap(),
        binary.parent().unwrap(),
    ] {
        crate::sys::protect_dir(path)?;
    }
    Ok(())
}

pub fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() > 1 {
        return Err("unexpected command argument".into());
    }
    match args.first().map(String::as_str).unwrap_or("run") {
        "run" => service::run(),
        "install" => service::install(),
        "uninstall" => service::uninstall(),
        "specialize" => provision::specialize(),
        "update" => update::finish(),
        "retry-update" => service::retry_update(),
        "version" | "--version" | "-V" => {
            println!("virtainer-guest-agent {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "licenses" => {
            print!("{}", crate::LICENSES);
            Ok(())
        }
        "help" | "--help" | "-h" => {
            println!("usage: virtainer-guest-agent [run|install|uninstall|specialize|retry-update|licenses|version]\nrun: SCM service (default)\ninstall: register auto-start LocalSystem service in Program Files\nspecialize: apply hostname/network from raw seed during sysprep specialize\nretry-update: clear the failed update checkpoint while the service is stopped");
            Ok(())
        }
        _ => Err("unknown command".into()),
    }
}
