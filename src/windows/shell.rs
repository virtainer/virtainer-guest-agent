// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `__io.virtainer_shell` on Windows: Windows PowerShell on a pseudo console
//! (ConPTY), as the service's own account, LocalSystem.
//!
//! The shell starts suspended inside a job object that kills every process
//! in it when its last handle closes, so ending a session ends the shell and
//! everything it started, as a hang-up does on Linux. ConPTY reads keystrokes
//! as UTF-8 and writes UTF-8 VT output; Ctrl-C arrives as 0x03 and ConPTY
//! raises it in the foreground process. The relay is in
//! windows_support/shell.rs.

use std::fs::File;
use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::ptr;
use std::time::Instant;

use serde_json::json;
use windows_sys::Win32::{
    Foundation::{HANDLE, WAIT_OBJECT_0},
    System::{
        Console::{ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON},
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::CreatePipe,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED,
            EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        },
    },
};

use super::api::wide;
use crate::commands::Ctx;
use crate::qmp::{Args, QgaError, Reply};
use crate::shell_protocol::{Request, Slot};
use crate::windows_support::shell::{self as support, Connection, Console};

pub fn open(ctx: &mut Ctx<'_>, args: Args) -> Reply {
    let request = Request::parse(args)?;
    support::check_user(&request.user)?;
    let slot = ctx.agent.shells.reserve()?;
    let session = start(slot, request.rows, request.cols)?;
    let pid = session.pid;
    ctx.upgrade = Some(session);
    Ok(json!({ "pid": pid }))
}

pub struct Session<'a> {
    slot: Slot<'a>,
    console: PseudoConsole,
    input: Option<File>,
    output: Option<File>,
    pid: u32,
    started: Instant,
    /// How the session ended, for the log line.
    ended: String,
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // Without a relay nobody reads the output, and closing the console
        // can wait until somebody does.
        drop(self.input.take());
        if let Some(mut output) = self.output.take() {
            let drain = std::thread::spawn(move || io::copy(&mut output, &mut io::sink()));
            self.console.close();
            let _ = drain.join();
        }
        crate::info!(
            "Shell session {} for user '{}' ended: {} after {}s",
            self.slot.id,
            support::USER,
            self.ended,
            self.started.elapsed().as_secs()
        );
    }
}

/// Relay between the connection and the console until one side ends.
pub fn relay<C: Connection>(mut session: Session<'_>, stream: &C) {
    let (Some(input), Some(output)) = (session.input.take(), session.output.take()) else {
        return;
    };
    session.ended = support::relay(stream, input, output, &mut session.console);
}

/// The console, the shell's process and the job holding its process tree.
struct PseudoConsole {
    console: Option<HPCON>,
    process: Option<OwnedHandle>,
    job: Option<OwnedHandle>,
}

impl Console for PseudoConsole {
    fn resize(&self, rows: u16, cols: u16) {
        if let Some(console) = self.console {
            // SAFETY: a live pseudo console; both dimensions are at most 9999.
            unsafe { ResizePseudoConsole(console, coord(rows, cols)) };
        }
    }

    fn exit_code(&self) -> Option<u32> {
        let process = raw(self.process.as_ref()?);
        // SAFETY: a live process handle.
        if unsafe { WaitForSingleObject(process, 0) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0;
        // SAFETY: as above, with a valid output.
        (unsafe { GetExitCodeProcess(process, &mut code) } != 0).then_some(code)
    }

    fn close(&mut self) {
        if let Some(job) = self.job.take() {
            // SAFETY: a live job handle. Closing it would kill the tree too;
            // terminating first means nothing is left attached to the console
            // when it closes.
            unsafe { TerminateJobObject(raw(&job), 1) };
        }
        if let Some(console) = self.console.take() {
            // SAFETY: closes the pseudo console exactly once.
            unsafe { ClosePseudoConsole(console) };
        }
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        self.close();
    }
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    std::os::windows::io::AsRawHandle::as_raw_handle(handle)
}

fn coord(rows: u16, cols: u16) -> COORD {
    COORD {
        X: cols as i16,
        Y: rows as i16,
    }
}

fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a fresh handle owned by the caller from here on.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

/// A non-inheritable anonymous pipe: (read end, write end).
fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: valid outputs; no security attributes, so neither end is
    // inherited by a child process.
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((owned(read)?, owned(write)?))
}

/// A job that kills every process in it once its last handle closes.
fn kill_on_close_job() -> io::Result<OwnedHandle> {
    // SAFETY: an anonymous job with default security.
    let job = owned(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
    // SAFETY: zero is a valid value of this plain C structure.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: a live job and a structure of the size passed.
    let set = unsafe {
        SetInformationJobObject(
            raw(&job),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if set == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

/// A process attribute list that attaches the child to a pseudo console.
struct Attributes(Vec<usize>);

impl Attributes {
    fn pseudo_console(console: &HPCON) -> io::Result<Self> {
        let mut size = 0;
        // SAFETY: a size query; it fails with ERROR_INSUFFICIENT_BUFFER by design.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
        let mut list = Attributes(vec![0; size.div_ceil(size_of::<usize>())]);
        // SAFETY: a buffer of at least the size asked for, aligned for pointers.
        if unsafe { InitializeProcThreadAttributeList(list.raw(), 1, 0, &mut size) } == 0 {
            list.0.clear();
            return Err(io::Error::last_os_error());
        }
        // SAFETY: an initialized list; `console` outlives the list's use in
        // CreateProcessW, which copies what it needs.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                list.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                (console as *const HPCON).cast(),
                size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if updated == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(list)
    }

    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            // SAFETY: an initialized list, deleted once.
            unsafe { DeleteProcThreadAttributeList(self.raw()) };
        }
    }
}

/// Open a pseudo console and start the shell on it.
fn start(slot: Slot<'_>, rows: u16, cols: u16) -> Result<Session<'_>, QgaError> {
    let console_error = |e: io::Error| QgaError::os("cannot open a pseudo console", &e);
    let (console_input, input) = pipe().map_err(console_error)?;
    let (output, console_output) = pipe().map_err(console_error)?;
    let mut hpc: HPCON = 0;
    // SAFETY: live pipe ends and a valid output. The console duplicates the
    // ends it is given, so ours are closed below.
    let hr = unsafe {
        CreatePseudoConsole(
            coord(rows, cols),
            raw(&console_input),
            raw(&console_output),
            0,
            &mut hpc,
        )
    };
    if hr < 0 {
        return Err(console_error(io::Error::from_raw_os_error(hr)));
    }
    drop((console_input, console_output));
    let mut console = PseudoConsole {
        console: Some(hpc),
        process: None,
        job: None,
    };
    let job = kill_on_close_job().map_err(console_error)?;

    let command_line = support::command_line(&crate::sys::system_dir());
    let start_error = |e: io::Error| {
        QgaError::generic(format!(
            "Failed to execute child process \u{201c}{command_line}\u{201d} ({e})"
        ))
    };
    let mut attributes = Attributes::pseudo_console(&hpc).map_err(start_error)?;
    // SAFETY: zero is a valid value of this plain C structure.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    // Null standard handles: the child takes the pseudo console's, not
    // whatever the service's own standard handles are.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.lpAttributeList = attributes.raw();
    let mut line = wide(&command_line);
    let home = home();
    let home = home.as_ref().map(wide);
    // SAFETY: zero is a valid value of this plain C structure.
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a writable, NUL-terminated command line; NUL-terminated
    // directory or null; the startup structure and attribute list live
    // through the call; no handles are inherited; the child inherits the
    // service's environment.
    let created = unsafe {
        CreateProcessW(
            ptr::null(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            ptr::null(),
            home.as_ref().map_or(ptr::null(), |dir| dir.as_ptr()),
            &startup.StartupInfo,
            &mut process,
        )
    };
    if created == 0 {
        return Err(start_error(io::Error::last_os_error()));
    }
    drop(attributes);
    let thread = owned(process.hThread).map_err(start_error)?;
    let child = owned(process.hProcess).map_err(start_error)?;
    // Into the job before its first instruction, so nothing it starts
    // escapes the job.
    // SAFETY: live job and process handles.
    if unsafe { AssignProcessToJobObject(raw(&job), raw(&child)) } == 0 {
        let e = io::Error::last_os_error();
        // SAFETY: the suspended child, which never ran.
        unsafe { TerminateProcess(raw(&child), 1) };
        return Err(start_error(e));
    }
    console.process = Some(child);
    console.job = Some(job);
    // SAFETY: the child's suspended main thread.
    if unsafe { ResumeThread(raw(&thread)) } == u32::MAX {
        return Err(start_error(io::Error::last_os_error()));
    }
    let pid = process.dwProcessId;
    crate::info!(
        "Shell session {} opened for user '{}' (pid {pid})",
        slot.id,
        support::USER
    );
    Ok(Session {
        slot,
        console,
        input: Some(File::from(input)),
        output: Some(File::from(output)),
        pid,
        started: Instant::now(),
        ended: "the reply to the host failed".into(),
    })
}

/// LocalSystem's profile directory, where the shell starts.
fn home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .filter(|dir| dir.is_dir())
}
