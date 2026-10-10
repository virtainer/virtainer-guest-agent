// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Small Win32 ABI boundary. No provisioning policy lives here.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

pub type Handle = *mut c_void;
pub fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
pub fn ok(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[repr(C)]
#[derive(Default)]
struct FileTime {
    low: u32,
    high: u32,
}
#[repr(C)]
#[derive(Default)]
struct SystemTime {
    year: u16,
    month: u16,
    weekday: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    millis: u16,
}
#[repr(C)]
#[derive(Default)]
struct Luid {
    low: u32,
    high: i32,
}
#[repr(C)]
struct Privileges {
    count: u32,
    luid: Luid,
    attributes: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn FileTimeToSystemTime(time: *const FileTime, system: *mut SystemTime) -> i32;
    fn SetSystemTime(system: *const SystemTime) -> i32;
    fn GetComputerNameExW(format: u32, buffer: *mut u16, size: *mut u32) -> i32;
    fn SetComputerNameExW(format: u32, name: *const u16) -> i32;
    pub fn GetCurrentProcess() -> Handle;
    pub fn CloseHandle(handle: Handle) -> i32;
    fn PeekNamedPipe(
        pipe: Handle,
        buffer: *mut c_void,
        size: u32,
        read: *mut u32,
        available: *mut u32,
        left: *mut u32,
    ) -> i32;
    fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
    fn AdjustTokenPrivileges(
        token: Handle,
        disable: i32,
        new: *const Privileges,
        length: u32,
        previous: *mut c_void,
        returned: *mut u32,
    ) -> i32;
    fn InitiateSystemShutdownExW(
        machine: *mut u16,
        message: *mut u16,
        timeout: u32,
        force: i32,
        reboot: i32,
        reason: u32,
    ) -> i32;
}
#[link(name = "netapi32")]
unsafe extern "system" {
    fn NetUserSetInfo(
        server: *const u16,
        user: *const u16,
        level: u32,
        data: *const c_void,
        error: *mut u32,
    ) -> u32;
}

pub fn pipe_ready(pipe: Handle) -> io::Result<bool> {
    let mut available = 0;
    // SAFETY: pipe is borrowed from a live child pipe; only the byte count is requested.
    unsafe {
        ok(PeekNamedPipe(
            pipe,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        ))?;
    }
    Ok(available > 0)
}
pub fn replace(from: &Path, to: &Path) -> io::Result<()> {
    // SAFETY: both buffers are terminated paths, valid for the call; replace + write-through.
    unsafe { ok(MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), 1 | 8)) }
}
pub fn delete_on_reboot(path: &Path) -> io::Result<()> {
    // SAFETY: terminated local path; null destination and DELAY_UNTIL_REBOOT
    // register deletion after the uninstall process releases its mapping.
    unsafe { ok(MoveFileExW(wide(path).as_ptr(), std::ptr::null(), 4)) }
}
pub fn hostname() -> io::Result<String> {
    let mut b = [0u16; 256];
    let mut n = b.len() as u32;
    // SAFETY: b is a writable buffer of n UTF-16 units.
    unsafe {
        ok(GetComputerNameExW(1, b.as_mut_ptr(), &mut n))?;
    }
    String::from_utf16(&b[..n as usize])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hostname"))
}
pub fn set_hostname(name: &str) -> io::Result<()> {
    // SAFETY: terminated UTF-16 name, already validated by the provision parser.
    unsafe { ok(SetComputerNameExW(5, wide(name).as_ptr())) }
}
pub fn set_time(ns: i64) -> io::Result<()> {
    if ns < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "time is before the Unix epoch",
        ));
    }
    let ticks = ns as u64 / 100 + 116_444_736_000_000_000;
    let ft = FileTime {
        low: ticks as u32,
        high: (ticks >> 32) as u32,
    };
    let mut st = SystemTime::default();
    // SAFETY: two valid fixed-layout time structs; SetSystemTime enables its privilege.
    unsafe {
        ok(FileTimeToSystemTime(&ft, &mut st))?;
        ok(SetSystemTime(&st))
    }
}
pub fn shutdown(reboot: bool) -> io::Result<()> {
    let mut token = std::ptr::null_mut();
    // SAFETY: current process pseudo-handle, writable token out-parameter.
    unsafe {
        ok(OpenProcessToken(GetCurrentProcess(), 0x20 | 8, &mut token))?;
    }
    let result = (|| {
        let mut luid = Luid::default();
        // SAFETY: terminated privilege name, valid out-pointer and token.
        unsafe {
            ok(LookupPrivilegeValueW(
                std::ptr::null(),
                wide("SeShutdownPrivilege").as_ptr(),
                &mut luid,
            ))?;
            let privileges = Privileges {
                count: 1,
                luid,
                attributes: 2,
            };
            ok(AdjustTokenPrivileges(
                token,
                0,
                &privileges,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ))?;
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(1300) {
                return Err(error);
            }
            ok(InitiateSystemShutdownExW(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
                i32::from(reboot),
                0x80040000,
            ))
        }
    })();
    // SAFETY: owns the token returned by OpenProcessToken.
    unsafe {
        CloseHandle(token);
    }
    result
}
pub fn set_password(user: &str, password: &str) -> io::Result<()> {
    if user.is_empty() || user.contains('\0') || password.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid username or password",
        ));
    }
    let user = wide(user);
    let password = wide(password);
    #[repr(C)]
    struct User1003 {
        password: *const u16,
    }
    let data = User1003 {
        password: password.as_ptr(),
    };
    // SAFETY: level 1003 takes USER_INFO_1003; buffers live for the call.
    let result = unsafe {
        NetUserSetInfo(
            std::ptr::null(),
            user.as_ptr(),
            1003,
            (&data as *const User1003).cast(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

pub fn private_directory(path: &Path) -> io::Result<()> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut Handle,
            size: *mut u32,
        ) -> i32;
        fn SetFileSecurityW(path: *const u16, information: u32, descriptor: Handle) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: Handle) -> Handle;
    }
    let mut descriptor = std::ptr::null_mut();
    let text = wide("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    // SAFETY: terminated SDDL and valid output pointer; descriptor is LocalFree-owned.
    unsafe {
        ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        ))?;
    }
    // SAFETY: sets owner/group and a protected exact DACL from the valid descriptor.
    let result = unsafe {
        ok(SetFileSecurityW(
            wide(path).as_ptr(),
            0x80000007,
            descriptor,
        ))
    };
    // SAFETY: releases the descriptor allocated by the converter.
    unsafe {
        LocalFree(descriptor);
    }
    result
}
