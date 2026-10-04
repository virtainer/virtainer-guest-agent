// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! The vsock listener: one thread per host connection.
//!
//! Only the host may talk to the agent. With `vsock_loopback` loaded, any
//! unprivileged guest process could connect to the agent's port and run
//! commands as root; nested VMs on vhost-vsock could too. virtio-serial
//! protected qemu-ga with /dev permissions; here the peer CID is the guard.
//! The port is below 1024, so an unprivileged process cannot squat on it
//! while the agent is down either.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::agent::Agent;
use crate::{session, vsock};

/// The vsock port the host connects to.
pub const PORT: u32 = 100;

const MAX_CONNECTIONS: usize = 16;
/// A connection idle this long is dropped; clients reconnect anyway after
/// a restore or an agent restart.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// A host that stops reading must not hold a thread forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
const RETRY: Duration = Duration::from_secs(5);

/// Lets one message through per interval and counts what it swallowed, so a
/// flood of identical events cannot flood the journal.
struct LogGate {
    every: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl LogGate {
    fn new(every: Duration) -> Self {
        Self {
            every,
            last: None,
            suppressed: 0,
        }
    }

    /// `Some(n)` when a line may be logged now, `n` being how many were
    /// suppressed since the previous one.
    fn pass(&mut self) -> Option<u64> {
        if self.last.is_some_and(|t| t.elapsed() < self.every) {
            self.suppressed += 1;
            return None;
        }
        self.last = Some(Instant::now());
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// A place among the open QGA connections, given back when the connection
/// ends or becomes a Shell session (those have their own limit).
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn run(agent: Arc<Agent>) {
    let listener = bind_with_retry();
    crate::notice!("listening on vsock port {PORT}");
    let active = Arc::new(AtomicUsize::new(0));
    let log_every = Duration::from_secs(60);
    let mut foreign_gate = LogGate::new(log_every);
    let mut busy_gate = LogGate::new(log_every);
    let mut accept_gate = LogGate::new(log_every);
    loop {
        let (stream, cid) = match vsock::accept(&listener) {
            Ok(accepted) => accepted,
            Err(e) => {
                if !matches!(
                    e.raw_os_error(),
                    Some(libc::EINTR | libc::ECONNABORTED | libc::EAGAIN)
                ) {
                    if let Some(n) = accept_gate.pass() {
                        crate::error!("vsock accept failed: {e} ({n} similar errors suppressed)");
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                continue;
            }
        };
        // A rejected peer is closed right here, before it can take a slot or
        // a thread; rejecting costs no sleep, so a local flood cannot delay
        // the host's connection beyond the accept queue order.
        if cid != vsock::VMADDR_CID_HOST {
            drop(stream);
            if let Some(n) = foreign_gate.pass() {
                crate::warning!(
                    "rejected a vsock connection from CID {cid}; only the host (CID 2) may connect ({n} similar rejections suppressed)"
                );
            }
            continue;
        }
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            drop(stream);
            if let Some(n) = busy_gate.pass() {
                crate::warning!(
                    "rejected a host connection: {MAX_CONNECTIONS} are already open ({n} similar rejections suppressed)"
                );
            }
            continue;
        }
        if let Err(e) = vsock::set_timeouts(&stream, IDLE_TIMEOUT, WRITE_TIMEOUT) {
            crate::warning!("cannot set socket timeouts: {e}");
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (agent, slot) = (agent.clone(), Slot(active.clone()));
        // A thread that cannot start drops its closure, and the slot with it.
        let spawned = std::thread::Builder::new()
            .name("connection".into())
            .spawn(move || {
                let _ = session::serve(&agent, stream, slot);
            });
        if let Err(e) = spawned {
            crate::error!("cannot start a connection thread: {e}");
        }
    }
}

/// The vsock device or its driver may show up after the agent starts, and
/// a vsock qemu-ga left behind may still hold the port.
fn bind_with_retry() -> std::os::fd::OwnedFd {
    let mut reported = None::<i32>;
    let mut tried_modprobe = false;
    loop {
        match vsock::listen(PORT) {
            Ok(listener) => return listener,
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                if code == libc::EAFNOSUPPORT && !tried_modprobe {
                    tried_modprobe = true;
                    load_vsock_transport();
                    continue;
                }
                if reported != Some(code) {
                    reported = Some(code);
                    match code {
                        libc::EADDRINUSE => crate::error!(
                            "vsock port {PORT} is already in use; another guest agent (qemu-ga with -m vsock-listen?) holds it; retrying"
                        ),
                        libc::EAFNOSUPPORT => crate::error!(
                            "this kernel has no vsock support (vmw_vsock_virtio_transport); retrying"
                        ),
                        _ => crate::error!("cannot listen on vsock port {PORT}: {e}; retrying"),
                    }
                }
                std::thread::sleep(RETRY);
            }
        }
    }
}

fn load_vsock_transport() {
    let Some(modprobe) = crate::sys::find_program("modprobe") else {
        return;
    };
    let _ = std::process::Command::new(modprobe)
        .args(["-q", "vmw_vsock_virtio_transport"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_gate_passes_one_line_per_interval_and_counts_the_rest() {
        let mut gate = LogGate::new(Duration::from_millis(50));
        assert_eq!(gate.pass(), Some(0));
        assert_eq!(gate.pass(), None);
        assert_eq!(gate.pass(), None);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(gate.pass(), Some(2));
    }
}
