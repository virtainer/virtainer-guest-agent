// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! AF_VSOCK listening socket, with libc directly.

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::sys;

pub const VMADDR_CID_HOST: u32 = 2;

pub fn listen(port: u32) -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the fd is owned right below.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(sys::last_error());
    }
    // SAFETY: fd was just created and has no other owner.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zeroed sockaddr_vm is valid; fields are set below.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    addr.svm_port = port;
    // SAFETY: addr is a valid sockaddr_vm of the given size.
    let rc = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&addr as *const libc::sockaddr_vm).cast(),
            size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(sys::last_error());
    }
    // SAFETY: listen on a bound socket.
    if unsafe { libc::listen(socket.as_raw_fd(), 16) } != 0 {
        return Err(sys::last_error());
    }
    Ok(socket)
}

/// Accept one connection; returns the stream and the peer's CID.
pub fn accept(listener: &OwnedFd) -> io::Result<(File, u32)> {
    // SAFETY: zeroed sockaddr_vm is a valid out-parameter.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_vm>() as libc::socklen_t;
    // SAFETY: addr and len describe a writable sockaddr_vm.
    let fd = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            (&mut addr as *mut libc::sockaddr_vm).cast(),
            &mut len,
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(sys::last_error());
    }
    // SAFETY: accept4 returned a new fd that we now own.
    Ok((unsafe { File::from_raw_fd(fd) }, addr.svm_cid))
}

pub fn set_timeouts(stream: &File, read: Duration, write: Duration) -> io::Result<()> {
    for (option, duration) in [(libc::SO_RCVTIMEO, read), (libc::SO_SNDTIMEO, write)] {
        let tv = libc::timeval {
            tv_sec: duration.as_secs() as _,
            tv_usec: duration.subsec_micros() as _,
        };
        // SAFETY: tv is a valid timeval for the duration of the call.
        let rc = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&tv as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(sys::last_error());
        }
    }
    Ok(())
}
