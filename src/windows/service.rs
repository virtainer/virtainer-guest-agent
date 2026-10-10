// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! LocalSystem auto-start service and SCM lifecycle.

use super::api::{self, wide, Handle};
use crate::windows_support::lifecycle::{self, Startup};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const NAME: &str = "virtainer-guest-agent";
static STOP: AtomicBool = AtomicBool::new(false);
static STATUS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static CURRENT_STATE: AtomicU32 = AtomicU32::new(2);
#[repr(C)]
#[derive(Default)]
struct Status {
    kind: u32,
    state: u32,
    accepted: u32,
    win32_exit: u32,
    specific_exit: u32,
    checkpoint: u32,
    hint: u32,
}
#[repr(C)]
struct Entry {
    name: *const u16,
    main: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn StartServiceCtrlDispatcherW(table: *const Entry) -> i32;
    fn RegisterServiceCtrlHandlerExW(
        name: *const u16,
        handler: unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32,
        context: *mut c_void,
    ) -> Handle;
    fn SetServiceStatus(handle: Handle, status: *const Status) -> i32;
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
    fn OpenServiceW(manager: Handle, name: *const u16, access: u32) -> Handle;
    fn CreateServiceW(
        manager: Handle,
        name: *const u16,
        display: *const u16,
        access: u32,
        kind: u32,
        start: u32,
        error: u32,
        binary: *const u16,
        group: *const u16,
        tag: *mut u32,
        deps: *const u16,
        account: *const u16,
        password: *const u16,
    ) -> Handle;
    fn ChangeServiceConfigW(
        service: Handle,
        kind: u32,
        start: u32,
        error: u32,
        binary: *const u16,
        group: *const u16,
        tag: *mut u32,
        deps: *const u16,
        account: *const u16,
        password: *const u16,
        display: *const u16,
    ) -> i32;
    fn StartServiceW(service: Handle, count: u32, args: *const *const u16) -> i32;
    fn ControlService(service: Handle, control: u32, status: *mut Status) -> i32;
    fn QueryServiceStatus(service: Handle, status: *mut Status) -> i32;
    fn DeleteService(service: Handle) -> i32;
    fn CloseServiceHandle(handle: Handle) -> i32;
}
struct Owned(Handle);
impl Owned {
    fn new(handle: Handle) -> Result<Self, String> {
        if handle.is_null() {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(Self(handle))
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: owns this SCM handle.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
    report(3, 0);
}

pub fn stopping() -> bool {
    STOP.load(Ordering::SeqCst)
}
fn report(state: u32, exit: u32) {
    CURRENT_STATE.store(state, Ordering::SeqCst);
    let handle = STATUS.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    let status = Status {
        kind: 16,
        state,
        accepted: if state == 4 { 1 | 4 } else { 0 },
        win32_exit: exit,
        checkpoint: if state == 2 || state == 3 { 1 } else { 0 },
        hint: if state == 2 || state == 3 { 30_000 } else { 0 },
        ..Default::default()
    };
    // SAFETY: registered status handle; status is a live SERVICE_STATUS.
    unsafe {
        SetServiceStatus(handle, &status);
    }
}
unsafe extern "system" fn control(
    code: u32,
    _kind: u32,
    _data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match code {
        1 | 5 => {
            STOP.store(true, Ordering::SeqCst);
            report(3, 0);
        }
        4 => report(CURRENT_STATE.load(Ordering::SeqCst), 0),
        _ => return 120,
    }
    0
}
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    // SAFETY: callback has SCM signature; the name lives through registration.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(wide(NAME).as_ptr(), control, std::ptr::null_mut())
    };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle, Ordering::SeqCst);
    report(2, 0);
    // No panic may unwind across the system ABI.
    let result = std::panic::catch_unwind(|| {
        super::secure_directories()?;
        let config = crate::config::Config::load()?;
        let report_value = super::provision::last_report()?;
        let agent = Arc::new(crate::agent::Agent::new(config, report_value));
        // Stage the update before any provisioning. The helper waits for this
        // process to stop, replaces the installed binary and restarts SCM.
        let provision = agent.clone();
        let worker = match super::update::stage() {
            Ok(true) => return Ok(()),
            Ok(false) => Some(
                std::thread::Builder::new()
                    .name("provision".into())
                    .spawn(move || super::provision::serve(provision))
                    .map_err(|e| e.to_string())?,
            ),
            Err(error) => {
                let mut value = super::provision::pending();
                value["state"] = serde_json::json!("failed");
                value["errors"] = serde_json::json!([error]);
                *agent.provision.lock().unwrap_or_else(|p| p.into_inner()) = value;
                None
            }
        };
        let result = super::vsock::run(agent);
        request_stop();
        if let Some(worker) = worker {
            let _ = worker.join();
        }
        result
    });
    let exit = if matches!(result, Ok(Ok(()))) { 0 } else { 1 };
    if exit != 0 {
        crate::error!("Windows service startup failed");
    }
    report(1, exit);
}
pub fn ready() {
    if !stopping() {
        report(4, 0);
    }
}
pub fn run() -> Result<(), String> {
    let name = wide(NAME);
    let table = [
        Entry {
            name: name.as_ptr(),
            main: Some(service_main),
        },
        Entry {
            name: std::ptr::null(),
            main: None,
        },
    ];
    // SAFETY: terminated service table, valid callbacks and string for the blocking call.
    unsafe { api::ok(StartServiceCtrlDispatcherW(table.as_ptr())).map_err(|e| e.to_string()) }
}
fn manager() -> Result<Owned, String> {
    // SAFETY: local SCM, connect/create service access.
    Owned::new(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), 1 | 2) })
}
fn open(manager: &Owned) -> Result<Option<Owned>, String> {
    // SAFETY: live SCM, terminated service name; request query/config/start/stop/delete.
    let h = unsafe {
        OpenServiceW(
            manager.0,
            wide(NAME).as_ptr(),
            0x10000 | 1 | 2 | 4 | 16 | 32,
        )
    };
    if h.is_null() && std::io::Error::last_os_error().raw_os_error() == Some(1060) {
        Ok(None)
    } else {
        Owned::new(h).map(Some)
    }
}
fn status(service: &Owned) -> Result<Status, String> {
    let mut status = Status::default();
    // SAFETY: valid SCM service and writable SERVICE_STATUS.
    unsafe {
        api::ok(QueryServiceStatus(service.0, &mut status)).map_err(|e| e.to_string())?;
    }
    Ok(status)
}
fn stop(service: &Owned) -> Result<(), String> {
    if status(service)?.state == 1 {
        return Ok(());
    }
    let mut s = Status::default();
    // SAFETY: stop a live service, with valid status output.
    if unsafe { ControlService(service.0, 1, &mut s) } == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(1062) && status(service)?.state != 3 {
            return Err(e.to_string());
        }
    }
    wait_stopped(service)
}
fn wait_stopped(service: &Owned) -> Result<(), String> {
    let started = Instant::now();
    while status(service)?.state != 1 {
        if started.elapsed() > Duration::from_secs(60) {
            return Err("service did not stop within 60 seconds".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
fn start(service: &Owned) -> Result<(), String> {
    // SAFETY: start registered service with no arguments.
    if unsafe { StartServiceW(service.0, 0, std::ptr::null()) } == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(1056) {
            return Err(e.to_string());
        }
    }
    let started = Instant::now();
    let mut startup = Startup::default();
    loop {
        let status = status(service)?;
        if startup.observe(
            started.elapsed(),
            status.state,
            status.win32_exit,
            status.specific_exit,
        )? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
pub fn install() -> Result<(), String> {
    let manager = manager()?;
    let existing = open(&manager)?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let bytes = std::fs::read(me).map_err(|e| e.to_string())?;
    let target = super::binary_path();
    super::secure_directories()?;
    let changed = match std::fs::read(&target) {
        Ok(old) => old != bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => return Err(e.to_string()),
    };
    if changed {
        if let Some(s) = &existing {
            stop(s)?;
        }
        // SCM reports STOPPED before the process exits, so the old image can still be mapped.
        super::provision::atomic_write_with(&target, &bytes, replace_unmapped)?;
    }
    let command = wide(format!("\"{}\" run", target.display()));
    let service = if let Some(s) = existing {
        // SAFETY: update service kind, auto-start and LocalSystem account explicitly.
        unsafe {
            api::ok(ChangeServiceConfigW(
                s.0,
                16,
                2,
                1,
                command.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                wide("LocalSystem").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            ))
            .map_err(|e| e.to_string())?;
        }
        s
    } else {
        // SAFETY: terminated strings, LocalSystem (null account), no dependencies.
        Owned::new(unsafe {
            CreateServiceW(
                manager.0,
                wide(NAME).as_ptr(),
                wide("Virtainer Guest Agent").as_ptr(),
                0xf01ff,
                16,
                2,
                1,
                command.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        })?
    };
    start(&service)?;
    println!(
        "{}: installed as an auto-start LocalSystem service",
        target.display()
    );
    Ok(())
}
pub fn uninstall() -> Result<(), String> {
    let manager = manager()?;
    if let Some(service) = open(&manager)? {
        stop(&service)?;
        // SAFETY: owns an opened service with DELETE access, already stopped.
        unsafe {
            api::ok(DeleteService(service.0)).map_err(|e| e.to_string())?;
        }
    }
    let target = super::binary_path();
    let running_from_target = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .ok()
        .zip(std::fs::canonicalize(&target).ok())
        .is_some_and(|(me, target)| {
            me.to_string_lossy()
                .eq_ignore_ascii_case(&target.to_string_lossy())
        });
    if lifecycle::uninstall_delete(
        running_from_target,
        || std::fs::remove_file(&target),
        || api::delete_on_reboot(&target),
    )
    .map_err(|e| e.to_string())?
    {
        println!("service removed; executable removal scheduled for the next reboot; reboot before reinstalling");
    }
    // Keep once-per-instance records: uninstall/reinstall must not replay scripts.
    Ok(())
}
pub fn retry_update() -> Result<(), String> {
    let manager = manager()?;
    if let Some(service) = open(&manager)? {
        if status(&service)?.state != 1 {
            return Err("stop the service before clearing the failed update checkpoint".into());
        }
    }
    super::update::clear()
}
fn replace_unmapped(from: &std::path::Path, to: &std::path::Path) -> Result<(), String> {
    // SCM STOPPED can precede process exit and release of the executable's
    // image mapping. Both activation and rollback must allow that short gap.
    let started = Instant::now();
    loop {
        match api::replace(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if started.elapsed() >= Duration::from_secs(30) => return Err(e.to_string()),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}
pub fn finish_update(bytes: &[u8], checkpoint: &[u8]) -> Result<(), String> {
    let manager = manager()?;
    let service = open(&manager)?.ok_or_else(|| "service is not installed".to_string())?;
    wait_stopped(&service)?;
    let target = super::binary_path();
    let backup = target.with_extension("previous.exe");
    if let Err(error) =
        crate::windows_support::update::retain_previous(&target, super::provision::atomic_write)
    {
        // The installed executable is still present if copying the backup fails.
        start(&service)
            .map_err(|e| format!("cannot retain previous binary: {error}; restart failed: {e}"))?;
        return Err(format!("cannot retain previous binary: {error}"));
    }
    lifecycle::finish_attempt(
        || {
            super::provision::atomic_write_with(&target, bytes, replace_unmapped)?;
            start(&service)
        },
        || super::update::suppress(checkpoint),
        || {
            stop(&service)?;
            replace_unmapped(&backup, &target)?;
            start(&service)
        },
    )
}
