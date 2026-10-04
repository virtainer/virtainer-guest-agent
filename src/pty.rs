// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Pseudo-terminals for the Shell: allocation, window size, and starting the
//! shell process on one.
//!
//! Every descriptor here is close-on-exec; the shell gets the terminal
//! through its standard streams only.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::sys;

/// Both sides of a new pseudo-terminal: the agent keeps `master`, the shell
/// gets `terminal`.
pub struct Pty {
    pub master: OwnedFd,
    pub terminal: OwnedFd,
}

pub fn open() -> io::Result<Pty> {
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: plain posix_openpt(3); the fd is owned right below.
    let fd = unsafe { libc::posix_openpt(flags) };
    if fd < 0 {
        return Err(sys::last_error());
    }
    // SAFETY: fd was just opened and has no other owner.
    let master = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: grantpt and unlockpt on the master we own.
    if unsafe { libc::grantpt(fd) } != 0 || unsafe { libc::unlockpt(fd) } != 0 {
        return Err(sys::last_error());
    }
    // TIOCGPTPEER (Linux 4.13) opens the terminal without a path lookup.
    // SAFETY: the ioctl takes the open flags by value and returns a new fd.
    let peer = unsafe { libc::ioctl(fd, libc::TIOCGPTPEER as _, flags) };
    let terminal = if peer >= 0 {
        // SAFETY: the ioctl returned a new fd that we now own.
        unsafe { OwnedFd::from_raw_fd(peer) }
    } else {
        open_by_name(fd, flags)?
    };
    Ok(Pty { master, terminal })
}

fn open_by_name(master: RawFd, flags: libc::c_int) -> io::Result<OwnedFd> {
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: name is a writable buffer of the given length.
    let rc = unsafe { libc::ptsname_r(master, name.as_mut_ptr(), name.len()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    // SAFETY: ptsname_r wrote a NUL-terminated path into name.
    let fd = unsafe { libc::open(name.as_ptr(), flags) };
    if fd < 0 {
        return Err(sys::last_error());
    }
    // SAFETY: open returned a new fd that we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Set the window size. On the master this also sends SIGWINCH to the
/// terminal's foreground process group.
pub fn set_size(fd: RawFd, rows: u16, cols: u16) -> io::Result<()> {
    let mut size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads one winsize.
    unsafe { sys::ioctl(fd, libc::TIOCSWINSZ as u64, &mut size) }.map(|_| ())
}

/// The `tty` group that terminal devices belong to, if the guest has one.
pub fn tty_group() -> Option<u32> {
    // SAFETY: group is plain data filled by getgrnam_r into buf.
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; strings point into buf.
    let rc = unsafe {
        libc::getgrnam_r(
            c"tty".as_ptr(),
            &mut group,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    (rc == 0 && !result.is_null()).then_some(group.gr_gid)
}

/// Hand the terminal device to the session's user, as login(1) does: owner
/// read and write, nothing for others, and group write (for `write` and
/// `wall`) only when `gid` is the dedicated `tty` group. A user's primary
/// group may be shared by every account, so it never gets write access.
pub fn give_to(terminal: &OwnedFd, uid: u32, gid: u32, gid_is_tty: bool) -> io::Result<()> {
    let fd = terminal.as_raw_fd();
    // An unprivileged agent (the unit tests) keeps its own ownership.
    // SAFETY: fchown and fchmod on an fd we own.
    if sys::is_root() && unsafe { libc::fchown(fd, uid, gid) } != 0 {
        return Err(sys::last_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fchmod(fd, if gid_is_tty { 0o620 } else { 0o600 }) } != 0 {
        return Err(sys::last_error());
    }
    Ok(())
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl flag queries and updates on an fd the caller owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(sys::last_error());
    }
    Ok(())
}

/// A descriptor that becomes readable when `pid` exits (pidfd_open, Linux
/// 5.3); `None` on older kernels. Always close-on-exec.
pub fn pidfd(pid: u32) -> Option<OwnedFd> {
    // SAFETY: pidfd_open(2) with no flags; the fd is owned right below.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
    // SAFETY: a non-negative return is a new fd that we now own.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Who the shell runs as.
pub struct Identity<'a> {
    pub uid: u32,
    pub gid: u32,
    pub groups: &'a [libc::gid_t],
    pub home: &'a Path,
}

/// Start `program` as a login shell on `terminal`: a session of its own with
/// the terminal as its controlling terminal, the account's credentials, the
/// home directory (or `/`), a clean signal state and only `env`.
pub fn spawn(
    terminal: &OwnedFd,
    program: &Path,
    env: &[(&str, OsString)],
    who: &Identity<'_>,
) -> io::Result<Child> {
    // Switching identity needs root. An unprivileged agent (the unit tests)
    // can only start a shell for itself.
    let switch = sys::is_root();
    // SAFETY: geteuid has no preconditions.
    if !switch && who.uid != unsafe { libc::geteuid() } {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let name = program
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let home = sys::cstring(who.home)?;
    let groups = who.groups.to_vec();
    let (uid, gid) = (who.uid as libc::c_long, who.gid as libc::c_long);

    let mut command = Command::new(program);
    command
        .arg0(format!("-{name}"))
        .env_clear()
        .envs(env.iter().map(|(key, value)| (*key, value)))
        .stdin(Stdio::from(terminal.try_clone()?))
        .stdout(Stdio::from(terminal.try_clone()?))
        .stderr(Stdio::from(terminal.try_clone()?));
    // SAFETY: the closure runs in the forked child before exec. It only makes
    // async-signal-safe system calls on data prepared above, and the raw
    // credential syscalls avoid libc's all-threads machinery.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if switch
                && (libc::syscall(
                    libc::SYS_setgroups,
                    groups.len() as libc::c_long,
                    groups.as_ptr(),
                ) != 0
                    || libc::syscall(libc::SYS_setresgid, gid, gid, gid) != 0
                    || libc::syscall(libc::SYS_setresuid, uid, uid, uid) != 0)
            {
                return Err(io::Error::last_os_error());
            }
            // As the user, like login(1): an unreadable home falls back to /.
            if libc::chdir(home.as_ptr()) != 0 {
                libc::chdir(c"/".as_ptr());
            }
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            for signal in [
                libc::SIGPIPE,
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGTERM,
                libc::SIGCHLD,
                libc::SIGTSTP,
                libc::SIGTTIN,
                libc::SIGTTOU,
            ] {
                libc::signal(signal, libc::SIG_DFL);
            }
            Ok(())
        });
    }
    let child = command.spawn();
    // Drop our copies of the terminal now that the child has its own.
    drop(command);
    child
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_after(gid_is_tty: bool) -> u32 {
        let pty = open().unwrap();
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        give_to(&pty.terminal, uid, gid, gid_is_tty).unwrap();
        let meta = std::fs::File::from(pty.terminal.try_clone().unwrap())
            .metadata()
            .unwrap();
        meta.permissions().mode() & 0o777
    }

    #[test]
    fn group_write_only_for_the_tty_group() {
        assert_eq!(mode_after(true), 0o620);
        assert_eq!(mode_after(false), 0o600);
    }
}
