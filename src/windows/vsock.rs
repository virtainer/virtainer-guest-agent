// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Winsock AF_VSOCK ABI (virtio-win viosock provider), independent of TCP.

use crate::agent::Agent;
use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use crate::windows_support::transport::{host_peer, Address, AF_VSOCK};
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut c_void) -> i32;
    fn WSACleanup() -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(family: i32, kind: i32, protocol: i32) -> usize;
    fn bind(socket: usize, address: *const Address, length: i32) -> i32;
    fn listen(socket: usize, backlog: i32) -> i32;
    fn accept(socket: usize, address: *mut Address, length: *mut i32) -> usize;
    fn closesocket(socket: usize) -> i32;
    fn recv(socket: usize, data: *mut u8, length: i32, flags: i32) -> i32;
    fn send(socket: usize, data: *const u8, length: i32, flags: i32) -> i32;
    fn setsockopt(socket: usize, level: i32, option: i32, value: *const u32, length: i32) -> i32;
    fn select(
        count: i32,
        read: *mut FdSet,
        write: *mut FdSet,
        except: *mut FdSet,
        timeout: *const TimeVal,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
}
#[repr(C)]
struct FdSet {
    count: u32,
    sockets: [usize; 64],
}
#[repr(C)]
struct TimeVal {
    seconds: i32,
    microseconds: i32,
}
fn error() -> io::Error {
    // SAFETY: retrieves thread-local Winsock error.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}
struct Winsock;
impl Winsock {
    fn new() -> io::Result<Self> {
        // WSADATA is at most 408 bytes on Win64. usize alignment covers its pointers.
        let mut data = [0usize; 64];
        // SAFETY: output is aligned and large enough for WSADATA.
        let rc = unsafe { WSAStartup(0x202, data.as_mut_ptr().cast()) };
        if rc == 0 {
            Ok(Self)
        } else {
            Err(io::Error::from_raw_os_error(rc))
        }
    }
}
impl Drop for Winsock {
    fn drop(&mut self) {
        // SAFETY: balances this process's WSAStartup.
        unsafe {
            WSACleanup();
        }
    }
}
struct Socket(usize);
impl Socket {
    fn owned(raw: usize) -> io::Result<Self> {
        if raw == usize::MAX {
            return Err(error());
        }
        let s = Self(raw);
        // SAFETY: live Winsock socket HANDLE, clear inheritance for exec children.
        if unsafe { SetHandleInformation(raw as *mut c_void, 1, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(s)
    }
    fn timeouts(&self) -> io::Result<()> {
        for (option, value) in [(0x1006, 600_000u32), (0x1005, 60_000u32)] {
            // SAFETY: timeout is a DWORD for SOL_SOCKET; lives through the call.
            if unsafe { setsockopt(self.0, 0xffff, option, &value, 4) } != 0 {
                return Err(error());
            }
        }
        Ok(())
    }
}
impl Socket {
    /// Wait until a connection is pending or the timeout passes. viosock sockets
    /// must stay in their default blocking mode: any FIONBIO call, including
    /// clearing it, leaves the socket non-blocking, so readiness is polled
    /// with select instead.
    fn readable(&self, timeout: Duration) -> io::Result<bool> {
        let mut set = FdSet {
            count: 1,
            sockets: [0; 64],
        };
        set.sockets[0] = self.0;
        let wait = TimeVal {
            seconds: timeout.as_secs() as i32,
            microseconds: timeout.subsec_micros() as i32,
        };
        // SAFETY: one live socket in a properly laid out fd_set, a valid timeout,
        // and no write or except sets.
        let ready = unsafe {
            select(
                0,
                &mut set,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &wait,
            )
        };
        if ready < 0 {
            Err(error())
        } else {
            Ok(ready > 0)
        }
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        // SAFETY: closes the socket exactly once.
        unsafe {
            closesocket(self.0);
        }
    }
}
impl Read for Socket {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        // SAFETY: b describes a writable buffer of the bounded length.
        let n = unsafe {
            recv(
                self.0,
                b.as_mut_ptr(),
                b.len().min(i32::MAX as usize) as i32,
                0,
            )
        };
        if n < 0 {
            Err(error())
        } else {
            Ok(n as usize)
        }
    }
}
impl Write for Socket {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        // SAFETY: b describes a readable buffer of the bounded length.
        let n = unsafe { send(self.0, b.as_ptr(), b.len().min(i32::MAX as usize) as i32, 0) };
        if n < 0 {
            Err(error())
        } else {
            Ok(n as usize)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
fn listener() -> io::Result<Socket> {
    // SAFETY: asks the installed viosock provider for a stream socket.
    let socket = Socket::owned(unsafe { socket(i32::from(AF_VSOCK), 1, 0) })?;
    let addr = Address {
        family: AF_VSOCK,
        cid: u32::MAX,
        port: 100,
        ..Default::default()
    };
    // SAFETY: valid sockaddr_vm with the provider's 12-byte layout.
    if unsafe { bind(socket.0, &addr, size_of::<Address>() as i32) } != 0 {
        return Err(error());
    }
    // SAFETY: bound listening socket.
    if unsafe { listen(socket.0, 16) } != 0 {
        return Err(error());
    }
    Ok(socket)
}
pub fn run(agent: Arc<Agent>) -> Result<(), String> {
    // Keep Winsock alive until the process exits, including live connection threads.
    let _winsock = Winsock::new().map_err(|e| e.to_string())?;
    let active = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let listener = loop {
        if super::service::stopping() {
            return Ok(());
        }
        match listener() {
            Ok(s) => break s,
            Err(_) if started.elapsed() >= Duration::from_secs(30) => {
                return Err("vsock listener did not start within 30 seconds".into());
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    };
    super::service::ready();
    while !super::service::stopping() {
        // Wake regularly so a service stop is noticed while no client connects.
        match listener.readable(Duration::from_millis(500)) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        }
        let mut addr = Address::default();
        let mut len = size_of::<Address>() as i32;
        // SAFETY: addr and len are writable outputs; listener is alive.
        let stream = unsafe { accept(listener.0, &mut addr, &mut len) };
        if stream == usize::MAX {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let stream = match Socket::owned(stream) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Reject a malformed address or a guest/nested caller before allocating a thread.
        if !host_peer(&addr, len) || active.load(Ordering::SeqCst) >= 16 {
            continue;
        }
        if stream.timeouts().is_err() {
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let slot = Slot(active.clone());
        let agent = agent.clone();
        let _ = std::thread::Builder::new()
            .name("connection".into())
            .spawn(move || {
                let _ = crate::session::serve(&agent, stream, slot);
            });
    }
    // Service shutdown terminates the process immediately after the dispatcher returns.
    Ok(())
}
