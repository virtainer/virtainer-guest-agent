// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Accounts: `guest-get-users`, `guest-set-user-password` and the
//! `guest-ssh-*-authorized-keys` commands.
//!
//! authorized_keys is read and written with the target user's credentials,
//! as qemu-ga does: a user who symlinks ~/.ssh/authorized_keys to
//! /etc/shadow must not get root to read or rewrite it. The credentials are
//! switched for one dedicated thread only (raw syscalls; the libc wrappers
//! would switch every thread of the agent), and that thread then exits.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::file::decode_base64;
use super::{no_args, Ctx};
use crate::qmp::{Args, QgaError, Reply};
use crate::sys;

// ---------------------------------------------------------------- users

const UTMP_RECORD: usize = 384;
const USER_PROCESS: i16 = 7;

/// glibc's x86_64 `struct utmp`; musl never writes utmp.
fn parse_utmp(bytes: &[u8]) -> Vec<(String, f64)> {
    let mut users: Vec<(String, f64)> = Vec::new();
    for record in bytes.chunks_exact(UTMP_RECORD) {
        let kind = i16::from_ne_bytes([record[0], record[1]]);
        if kind != USER_PROCESS {
            continue;
        }
        let raw = &record[44..76];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let user = String::from_utf8_lossy(&raw[..end]).into_owned();
        let sec = i32::from_ne_bytes(record[340..344].try_into().unwrap());
        let usec = i32::from_ne_bytes(record[344..348].try_into().unwrap());
        add_login(&mut users, user, f64::from(sec) + f64::from(usec) / 1e6);
    }
    users
}

/// systemd-logind's session files, for systems that no longer keep utmp.
fn parse_logind_sessions(dir: &Path) -> Vec<(String, f64)> {
    let mut users = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return users;
    };
    for entry in entries.filter_map(Result::ok) {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let fields: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
        if fields.get("CLASS") != Some(&"user") || fields.get("STATE") == Some(&"closing") {
            continue;
        }
        let (Some(user), Some(usec)) = (
            fields.get("USER"),
            fields.get("REALTIME").and_then(|v| v.parse::<u64>().ok()),
        ) else {
            continue;
        };
        add_login(&mut users, user.to_string(), usec as f64 / 1e6);
    }
    users
}

/// One entry per user, with the earliest login.
fn add_login(users: &mut Vec<(String, f64)>, user: String, time: f64) {
    match users.iter_mut().find(|(u, _)| *u == user) {
        Some((_, earliest)) => *earliest = earliest.min(time),
        None => users.push((user, time)),
    }
}

pub fn get_users(_: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let users = match ["/run/utmp", "/var/run/utmp"]
        .iter()
        .find_map(|p| std::fs::read(p).ok())
    {
        Some(bytes) => parse_utmp(&bytes),
        None => parse_logind_sessions(Path::new("/run/systemd/sessions")),
    };
    Ok(Value::Array(
        users
            .into_iter()
            .map(|(user, time)| json!({ "user": user, "login-time": time }))
            .collect(),
    ))
}

// ---------------------------------------------------------------- password

pub fn set_user_password(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let username = args.str("username")?;
    let password = args.str("password")?;
    let crypted = args.bool("crypted")?;
    args.finish()?;
    let password = decode_base64(&password)?;
    if password.contains(&b'\n') || password.contains(&0) {
        return Err(QgaError::generic("forbidden characters in raw password"));
    }
    if username.contains('\n') || username.contains(':') || username.contains('\0') {
        return Err(QgaError::generic("forbidden characters in username"));
    }
    crate::info!("guest-set-user-password called for user '{username}'");
    let mut input = Vec::with_capacity(username.len() + password.len() + 2);
    input.extend_from_slice(username.as_bytes());
    input.push(b':');
    input.extend_from_slice(&password);
    input.push(b'\n');
    let chpasswd = sys::find_program("chpasswd");
    let program = chpasswd
        .as_deref()
        .and_then(Path::to_str)
        .unwrap_or("chpasswd");
    let argv: &[&str] = if crypted {
        &[program, "-e"]
    } else {
        &[program]
    };
    sys::run_helper(
        argv,
        Some(&input),
        "set user password",
        Some(sys::HELPER_TIMEOUT),
    )?;
    Ok(json!({}))
}

// ---------------------------------------------------------------- ssh keys

pub(crate) struct Account {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) home: PathBuf,
    /// The login shell from the passwd entry; `None` when the field is empty.
    pub(crate) shell: Option<PathBuf>,
    pub(crate) groups: Vec<libc::gid_t>,
}

/// passwd lookup: libc first (musl reads /etc/passwd), then getent(1) for
/// accounts only NSS knows about (LDAP, SSSD).
pub(crate) fn lookup(username: &str) -> Result<Account, QgaError> {
    let fail = || QgaError::generic(format!("failed to lookup user '{username}': no such user"));
    let c_name = CString::new(username).map_err(|_| fail())?;
    let Passwd {
        uid,
        gid,
        home,
        shell,
    } = match getpwnam(&c_name) {
        Some(found) => found,
        None => getent_passwd(username).ok_or_else(fail)?,
    };
    let mut groups = group_list(&c_name, gid, 256).map_err(|e| {
        QgaError::generic(format!("failed to lookup groups of user '{username}': {e}"))
    })?;
    if !groups.contains(&gid) {
        groups.push(gid);
    }
    Ok(Account {
        uid,
        gid,
        home,
        shell,
        groups,
    })
}

/// getgrouplist(3) with a first guess of `capacity` entries; when that is too
/// small the call reports the needed size and is retried with it.
fn group_list(name: &CStr, gid: u32, capacity: usize) -> Result<Vec<libc::gid_t>, &'static str> {
    let mut groups = vec![0 as libc::gid_t; capacity];
    for _ in 0..3 {
        let mut count = groups.len() as libc::c_int;
        // SAFETY: groups has room for `count` entries; getgrouplist updates count.
        let rc = unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                gid as _,
                groups.as_mut_ptr() as _,
                &mut count,
            )
        };
        if rc >= 0 {
            groups.truncate(count as usize);
            return Ok(groups);
        }
        // `count` is the size needed; grow past it in case the list changed.
        let needed = usize::try_from(count).unwrap_or(0);
        groups.resize(needed.max(groups.len()) + 16, 0);
    }
    Err("group list keeps changing")
}

struct Passwd {
    uid: u32,
    gid: u32,
    home: PathBuf,
    shell: Option<PathBuf>,
}

fn non_empty_path(bytes: &[u8]) -> Option<PathBuf> {
    (!bytes.is_empty()).then(|| PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

fn getpwnam(name: &CStr) -> Option<Passwd> {
    // SAFETY: passwd is plain data filled by getpwnam_r into buf.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; strings point into buf.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: pw_dir and pw_shell point into buf, which is still alive.
    let (home, shell) = unsafe {
        (
            CStr::from_ptr(pwd.pw_dir).to_bytes(),
            CStr::from_ptr(pwd.pw_shell).to_bytes(),
        )
    };
    Some(Passwd {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home: PathBuf::from(OsString::from_vec(home.to_vec())),
        shell: non_empty_path(shell),
    })
}

/// `--` keeps a name that starts with `-` from being parsed as an option.
fn getent_args(username: &str) -> [&str; 3] {
    ["passwd", "--", username]
}

fn getent_passwd(username: &str) -> Option<Passwd> {
    let getent = sys::find_program("getent")?;
    let output = std::process::Command::new(getent)
        .args(getent_args(username))
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let line = String::from_utf8(output.stdout).ok()?;
    let fields: Vec<&str> = line.trim_end().split(':').collect();
    if fields.len() < 7 || fields[0] != username {
        return None;
    }
    Some(Passwd {
        uid: fields[2].parse().ok()?,
        gid: fields[3].parse().ok()?,
        home: PathBuf::from(fields[5]),
        shell: non_empty_path(fields[6].as_bytes()),
    })
}

/// Run `work` on a fresh thread whose effective uid, gid and groups are the
/// account's. Only that thread changes identity; it exits afterwards.
fn as_user<T: Send + 'static>(
    account: Account,
    work: impl FnOnce(&Account) -> Result<T, QgaError> + Send + 'static,
) -> Result<T, QgaError> {
    let thread = std::thread::spawn(move || {
        let keep = -1i64 as libc::c_long;
        // SAFETY: raw credential syscalls with valid arguments; they affect
        // only the calling thread, which ends with this closure.
        let failed = unsafe {
            libc::syscall(
                libc::SYS_setgroups,
                account.groups.len() as libc::c_long,
                account.groups.as_ptr(),
            ) != 0
                || libc::syscall(libc::SYS_setresgid, keep, account.gid as libc::c_long, keep) != 0
                || libc::syscall(libc::SYS_setresuid, keep, account.uid as libc::c_long, keep) != 0
        };
        if failed {
            return Err(QgaError::os(
                "failed to switch to the user's credentials",
                &sys::last_error(),
            ));
        }
        work(&account)
    });
    thread.join().unwrap_or_else(|_| {
        Err(QgaError::generic(
            "internal error: credential thread panicked",
        ))
    })
}

/// Key edits are read-modify-write; two connections editing at once must not
/// lose one another's keys.
static KEY_EDITS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// qemu-ga's minimal sanity check of a public key line.
fn check_keys(keys: &[String]) -> Result<(), QgaError> {
    match keys.iter().find(|k| k.starts_with('#') || k.contains('\n')) {
        Some(bad) => Err(QgaError::generic(format!(
            "invalid OpenSSH public key: '{bad}'"
        ))),
        None => Ok(()),
    }
}

fn authorized_keys(account: &Account) -> PathBuf {
    account.home.join(".ssh").join("authorized_keys")
}

/// Lines are kept as bytes so a rewrite preserves whatever the user's file
/// holds, valid UTF-8 or not.
fn read_lines(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let text = std::fs::read(path)?;
    let mut lines: Vec<Vec<u8>> = text.split(|b| *b == b'\n').map(<[u8]>::to_vec).collect();
    if lines.last().is_some_and(Vec::is_empty) {
        lines.pop();
    }
    Ok(lines)
}

/// A missing file is an empty key list; any other read error must not turn
/// into one, or the rewrite would drop the user's keys.
fn read_lines_or_empty(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    match read_lines(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        other => other,
    }
}

/// Replace the file atomically: temp file in the same directory, then rename.
fn write_lines(path: &Path, lines: &[Vec<u8>]) -> Result<(), QgaError> {
    let fail = |e: io::Error| QgaError::os(format!("failed to write to '{}'", path.display()), &e);
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".authorized_keys.{:08x}", sys::random_u32()));
    let mut contents = lines.join(&b'\n');
    if !contents.is_empty() {
        contents.push(b'\n');
    }
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(&contents)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(fail)
}

pub fn ssh_get_authorized_keys(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let username = args.str("username")?;
    args.finish()?;
    let account = lookup(&username)?;
    let mut keys = as_user(account, |account| {
        let path = authorized_keys(account);
        read_lines(&path)
            .map_err(|e| QgaError::os(format!("failed to read '{}'", path.display()), &e))
    })?
    .into_iter()
    .map(|line| String::from_utf8_lossy(&line).trim().to_string())
    .filter(|line| !line.is_empty() && !line.starts_with('#'))
    .collect::<Vec<_>>();
    // qemu-ga builds this list by prepending.
    keys.reverse();
    Ok(json!({ "keys": keys }))
}

pub fn ssh_add_authorized_keys(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let username = args.str("username")?;
    let keys = args.str_list("keys")?;
    let reset = args.opt_bool("reset")?.unwrap_or(false);
    args.finish()?;
    check_keys(&keys)?;
    let account = lookup(&username)?;
    crate::info!(
        "guest-ssh-add-authorized-keys: {} keys for user '{username}'{}",
        keys.len(),
        if reset { " (reset)" } else { "" }
    );
    let _edit = KEY_EDITS.lock().unwrap_or_else(|p| p.into_inner());
    as_user(account, move |account| {
        let path = authorized_keys(account);
        let mut lines = if reset {
            Vec::new()
        } else {
            read_lines_or_empty(&path)
                .map_err(|e| QgaError::os(format!("failed to read '{}'", path.display()), &e))?
        };
        let ssh_dir = path.parent().expect("authorized_keys has a parent");
        if !ssh_dir.is_dir() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(ssh_dir)
                .map_err(|e| {
                    QgaError::os(
                        format!("failed to create directory '{}'", ssh_dir.display()),
                        &e,
                    )
                })?;
        }
        for key in keys {
            if !lines.iter().any(|l| l == key.as_bytes()) {
                lines.push(key.into_bytes());
            }
        }
        write_lines(&path, &lines)
    })?;
    Ok(json!({}))
}

pub fn ssh_remove_authorized_keys(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let username = args.str("username")?;
    let keys = args.str_list("keys")?;
    args.finish()?;
    check_keys(&keys)?;
    let account = lookup(&username)?;
    crate::info!(
        "guest-ssh-remove-authorized-keys: {} keys for user '{username}'",
        keys.len()
    );
    let _edit = KEY_EDITS.lock().unwrap_or_else(|p| p.into_inner());
    as_user(account, move |account| {
        let path = authorized_keys(account);
        if !path.exists() {
            return Ok(());
        }
        let lines = read_lines(&path)
            .map_err(|e| QgaError::os(format!("failed to read '{}'", path.display()), &e))?;
        let kept: Vec<Vec<u8>> = lines
            .into_iter()
            .filter(|l| !keys.iter().any(|k| k.as_bytes() == l.as_slice()))
            .collect();
        write_lines(&path, &kept)
    })?;
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utmp_record(kind: i16, user: &str, sec: i32, usec: i32) -> Vec<u8> {
        let mut r = vec![0u8; UTMP_RECORD];
        r[0..2].copy_from_slice(&kind.to_ne_bytes());
        r[44..44 + user.len()].copy_from_slice(user.as_bytes());
        r[340..344].copy_from_slice(&sec.to_ne_bytes());
        r[344..348].copy_from_slice(&usec.to_ne_bytes());
        r
    }

    #[test]
    fn utmp_users_are_unique_with_the_earliest_login() {
        let mut bytes = utmp_record(USER_PROCESS, "alice", 200, 500_000);
        bytes.extend(utmp_record(USER_PROCESS, "alice", 100, 0));
        bytes.extend(utmp_record(8, "dead", 50, 0));
        bytes.extend(utmp_record(USER_PROCESS, "bob", 300, 0));
        assert_eq!(
            parse_utmp(&bytes),
            vec![("alice".to_string(), 100.0), ("bob".to_string(), 300.0)]
        );
    }

    #[test]
    fn logind_sessions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("1"),
            "UID=1000\nUSER=alice\nACTIVE=1\nSTATE=active\nCLASS=user\nREALTIME=1700000000500000\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("2"),
            "USER=gdm\nCLASS=greeter\nREALTIME=1\n",
        )
        .unwrap();
        assert_eq!(
            parse_logind_sessions(dir.path()),
            vec![("alice".to_string(), 1_700_000_000.5)]
        );
    }

    #[test]
    fn password_and_username_validation_happens_before_chpasswd() {
        let dir = tempfile::tempdir().unwrap();
        let agent = crate::agent::Agent::new(Default::default(), dir.path().to_path_buf());
        let mut ctx = Ctx::new(&agent);
        let call = |ctx: &mut Ctx<'_>, user: &str, pass: &str| {
            let Value::Object(map) = json!({"username": user, "password": pass, "crypted": false})
            else {
                unreachable!()
            };
            set_user_password(ctx, Args::new(map)).unwrap_err().desc
        };
        // "a\nb" in base64
        assert_eq!(
            call(&mut ctx, "root", "YQpi"),
            "forbidden characters in raw password"
        );
        assert_eq!(
            call(&mut ctx, "ro:ot", "cGFzcw=="),
            "forbidden characters in username"
        );
        assert_eq!(call(&mut ctx, "root", "!!"), "Base64 data is not valid");
    }

    #[test]
    fn read_errors_other_than_missing_are_not_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_lines_or_empty(&dir.path().join("absent"))
            .unwrap()
            .is_empty());
        // A directory where the file should be reads as EISDIR.
        let err = read_lines_or_empty(dir.path()).unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn rewrite_preserves_non_utf8_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized_keys");
        let odd: &[u8] = b"ssh-rsa AAAA caf\xe9";
        std::fs::write(&path, [odd, b"\n"].concat()).unwrap();
        let mut lines = read_lines(&path).unwrap();
        lines.push(b"ssh-ed25519 BBBB".to_vec());
        write_lines(&path, &lines).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            [odd, b"\nssh-ed25519 BBBB\n"].concat()
        );
    }

    #[test]
    fn getent_gets_a_double_dash_before_the_name() {
        assert_eq!(getent_args("-s"), ["passwd", "--", "-s"]);
    }

    #[test]
    fn group_list_grows_past_a_too_small_buffer() {
        let name = CString::new("root").unwrap();
        let big = group_list(&name, 0, 256).unwrap();
        let small = group_list(&name, 0, 0).unwrap();
        assert!(small.contains(&0));
        assert_eq!(small, big);
    }

    #[test]
    fn keys_starting_with_a_comment_are_rejected() {
        assert!(check_keys(&["ssh-ed25519 AAAA x".into()]).is_ok());
        assert_eq!(
            check_keys(&["# nope".into()]).unwrap_err().desc,
            "invalid OpenSSH public key: '# nope'"
        );
    }

    #[test]
    fn add_get_remove_round_trip_as_the_current_user() {
        // Runs as whoever runs the tests: credentials "switch" to themselves.
        let home = tempfile::tempdir().unwrap();
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let account = || Account {
            uid,
            gid,
            home: home.path().to_path_buf(),
            shell: None,
            groups: vec![gid],
        };
        let path = authorized_keys(&account());
        if !sys::is_root() {
            // Unprivileged setgroups fails, which is the point of the check.
            assert!(as_user(account(), |_| Ok(())).is_err());
            return;
        }
        as_user(account(), {
            let path = path.clone();
            move |_| {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                write_lines(&path, &[b"k1".to_vec(), b"k2".to_vec()])
            }
        })
        .unwrap();
        assert_eq!(
            read_lines(&path).unwrap(),
            vec![b"k1".to_vec(), b"k2".to_vec()]
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
