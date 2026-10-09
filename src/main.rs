// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Virtainer guest agent: a QEMU Guest Agent compatible agent for Linux VMs
//! on Cloud Hypervisor, reached by the host over vsock.

mod agent;
mod autoonline;
mod commands;
mod config;
mod framer;
mod install;
mod json;
mod log;
mod pty;
mod qmp;
mod server;
mod session;
mod shell;
mod sys;
mod vsock;
#[cfg(any(target_os = "windows", test))]
mod windows_support;

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use agent::Agent;
use config::Config;

const USAGE: &str = "\
usage: virtainer-guest-agent [COMMAND]

Commands:
  run         Serve the host over vsock port 100 (default)
  install     Install this binary as /usr/local/sbin/virtainer-guest-agent
              and enable it as a systemd or OpenRC service
  uninstall   Stop the service and remove what install created
  licenses    Print the third-party notices and licenses
  version     Print the version
";

/// Shipped inside the binary, so whichever way it reaches a guest (seed,
/// ISO, update), the notices and licence texts Apache-2.0 and MIT require
/// travel with it.
const LICENSES: &str = concat!(
    include_str!("../THIRD_PARTY_NOTICES.md"),
    "\n\n",
    include_str!("../LICENSES/Apache-2.0.txt"),
    "\n\n",
    include_str!("../LICENSES/RUST-STD.txt"),
    "\n\n",
    include_str!("../LICENSES/MUSL-COPYRIGHT.txt"),
    "\n\n",
    include_str!("../LICENSES/THIRD-PARTY-RUST.txt"),
);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("run");
    if args.len() > 1 {
        fail_usage(&format!("unexpected argument '{}'", args[1]));
    }
    match command {
        "run" => run(),
        "install" => exit_with(install::install()),
        "uninstall" => exit_with(install::uninstall()),
        "version" | "--version" | "-V" => {
            println!("virtainer-guest-agent {}", env!("CARGO_PKG_VERSION"))
        }
        "licenses" => print!("{LICENSES}"),
        "help" | "--help" | "-h" => print!("{USAGE}"),
        other => fail_usage(&format!("unknown command '{other}'")),
    }
}

fn fail_usage(message: &str) -> ! {
    eprintln!("virtainer-guest-agent: {message}\n\n{USAGE}");
    std::process::exit(2);
}

fn exit_with(result: Result<(), String>) {
    if let Err(e) = result {
        eprintln!("virtainer-guest-agent: {e}");
        std::process::exit(1);
    }
}

fn run() {
    log::init();
    let config = match Config::load(Path::new(config::PATH)) {
        Ok(config) => config,
        Err(e) => {
            error!("refusing to start: {e}");
            std::process::exit(1);
        }
    };
    for name in config
        .block_rpcs
        .iter()
        .chain(config.allow_rpcs.iter().flatten())
    {
        if commands::find(name).is_none() {
            warning!(
                "{}: '{name}' is not a command this agent knows",
                config::PATH
            );
        }
    }
    if !sys::is_root() {
        warning!("not running as root; most commands will fail");
    }
    let _ = std::env::set_current_dir("/");

    let signals = signal_pipe();

    let agent = Arc::new(Agent::new(config, PathBuf::from(install::RUNTIME_DIR)));
    if agent.freezer.is_frozen() {
        warning!("a previous agent left filesystems frozen; only thaw is accepted until then");
    }
    {
        let agent = agent.clone();
        std::thread::spawn(move || agent.freezer.watchdog(|| agent.config.hook_path()));
    }
    std::thread::spawn(autoonline::watch);
    {
        let agent = agent.clone();
        std::thread::spawn(move || server::run(agent));
    }
    notice!(
        "Virtainer guest agent {} started",
        env!("CARGO_PKG_VERSION")
    );

    loop {
        let mut signal = 0u8;
        // SAFETY: reading one byte into a valid buffer.
        let n = unsafe { libc::read(signals.as_raw_fd(), (&mut signal as *mut u8).cast(), 1) };
        if n != 1 || i32::from(signal) == libc::SIGHUP {
            continue;
        }
        if agent.freezer.is_frozen() {
            notice!("stopping while filesystems are frozen; thawing them first");
            if let Err(e) = agent.freezer.thaw(agent.config.hook_path()) {
                error!("thaw before exit failed: {}", e.desc);
            }
        }
        notice!("Virtainer guest agent stopping");
        log::hold(false);
        std::process::exit(0);
    }
}

/// Write end of the pipe the signal handler reports into.
static SIGNAL_WRITER: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(signal: libc::c_int) {
    // SAFETY: errno is thread-local and saved around write(2), the only
    // call here, which is async-signal-safe.
    unsafe {
        let errno = *libc::__errno_location();
        let byte = signal as u8;
        libc::write(
            SIGNAL_WRITER.load(Ordering::Relaxed),
            (&byte as *const u8).cast(),
            1,
        );
        *libc::__errno_location() = errno;
    }
}

/// SIGTERM, SIGINT and SIGHUP arrive as bytes on the returned pipe.
///
/// Handlers rather than a blocked mask plus sigwait: a blocked mask is
/// inherited by every thread and, through them, by every process the agent
/// starts (Rust's spawn keeps the parent's mask), so guest-exec children
/// would ignore SIGTERM. Handlers are reset to the default on exec.
fn signal_pipe() -> OwnedFd {
    let mut fds = [0; 2];
    // SAFETY: fds has room for the two descriptors pipe2 returns.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        error!("cannot create the signal pipe: {}", sys::last_error());
        std::process::exit(1);
    }
    SIGNAL_WRITER.store(fds[1], Ordering::Relaxed);
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: a zeroed sigaction with a valid handler and an empty mask.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
    // SAFETY: fds[0] is the read end just created, owned from here on.
    unsafe { OwnedFd::from_raw_fd(fds[0]) }
}
