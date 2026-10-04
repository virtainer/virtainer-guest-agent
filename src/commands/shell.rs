// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `__io.virtainer_shell`: turn this connection into a Shell session
//! (README.md, "Shell protocol").
//!
//! The terminal and the shell are set up here, before the reply, so every
//! failure is still an ordinary QGA error on a QGA connection. session.rs
//! starts the relay once the reply is out.

use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::users::{self, Account};
use super::Ctx;
use crate::qmp::{Args, QgaError, Reply};
use crate::shell::{Session, Slot};
use crate::{pty, sys};

pub const NAME: &str = "__io.virtainer_shell";
const DEFAULT_TERM: &str = "xterm-256color";
const DEFAULT_SHELL: &str = "/bin/sh";
const ROOT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const USER_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

pub fn open(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let user = args.str("user")?;
    let rows = dimension(args.opt_int("rows")?, "rows", 24)?;
    let cols = dimension(args.opt_int("cols")?, "cols", 80)?;
    let term = args.opt_str("term")?;
    args.finish()?;
    let term = term.unwrap_or_else(|| DEFAULT_TERM.to_string());
    if !valid_term(&term) {
        return Err(QgaError::generic(format!("invalid terminal type '{term}'")));
    }
    let account = users::lookup(&user)?;
    let agent = ctx.agent;
    let slot = agent.shells.reserve()?;
    let session = start(slot, &user, &account, (rows, cols), &term)?;
    let pid = session.pid();
    ctx.upgrade = Some(session);
    Ok(json!({ "pid": pid }))
}

fn dimension(value: Option<i64>, name: &str, default: u16) -> Result<u16, QgaError> {
    match value {
        None => Ok(default),
        Some(n @ 1..=9999) => Ok(n as u16),
        Some(_) => Err(QgaError::generic(format!(
            "Parameter '{name}' expects a value between 1 and 9999"
        ))),
    }
}

fn valid_term(term: &str) -> bool {
    !term.is_empty()
        && term.len() <= 64
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

/// Open a terminal and start the account's login shell on it.
pub(crate) fn start<'a>(
    slot: Slot<'a>,
    user: &str,
    account: &Account,
    (rows, cols): (u16, u16),
    term: &str,
) -> Result<Session<'a>, QgaError> {
    let terminal_error = |e: std::io::Error| QgaError::os("cannot open a terminal", &e);
    let pty = pty::open().map_err(terminal_error)?;
    pty::set_size(pty.master.as_raw_fd(), rows, cols).map_err(terminal_error)?;
    let tty = pty::tty_group();
    pty::give_to(
        &pty.terminal,
        account.uid,
        tty.unwrap_or(account.gid),
        tty.is_some(),
    )
    .map_err(terminal_error)?;
    let shell = account
        .shell
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SHELL));
    let env = environment(user, account, &shell, term);
    let identity = pty::Identity {
        uid: account.uid,
        gid: account.gid,
        groups: &account.groups,
        home: &account.home,
    };
    let child = pty::spawn(&pty.terminal, &shell, &env, &identity).map_err(|e| {
        QgaError::generic(format!(
            "Failed to execute child process \u{201c}{}\u{201d} ({})",
            shell.display(),
            sys::strerror(&e)
        ))
    })?;
    // Only the shell holds the terminal now, so the master sees it close.
    drop(pty.terminal);
    Ok(Session::new(
        slot,
        user.to_string(),
        File::from(pty.master),
        child,
    ))
}

/// A fresh environment, as login(1) builds it, plus the system locale.
fn environment(
    user: &str,
    account: &Account,
    shell: &Path,
    term: &str,
) -> Vec<(&'static str, OsString)> {
    let path = if account.uid == 0 {
        ROOT_PATH
    } else {
        USER_PATH
    };
    vec![
        ("HOME", account.home.clone().into_os_string()),
        ("USER", user.into()),
        ("LOGNAME", user.into()),
        ("SHELL", shell.as_os_str().to_owned()),
        ("PATH", path.into()),
        ("TERM", term.into()),
        ("LANG", system_locale().into()),
    ]
}

/// LANG from systemd's /etc/locale.conf, else Debian's /etc/default/locale.
/// Without PAM nothing else would set it.
fn system_locale() -> String {
    ["/etc/locale.conf", "/etc/default/locale"]
        .iter()
        .filter_map(|file| std::fs::read_to_string(file).ok())
        .find_map(|text| parse_lang(&text))
        .unwrap_or_else(|| "C.UTF-8".into())
}

fn parse_lang(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("LANG="))
        .map(|value| value.trim().trim_matches(['"', '\'']).to_string())
        .find(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::commands::dispatch;
    use crate::config::Config;
    use serde_json::{json, Value};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn agent() -> (Agent, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Agent::new(Config::default(), dir.path().to_path_buf()), dir)
    }

    fn call(agent: &Agent, arguments: Value) -> Value {
        let mut ctx = Ctx::new(agent);
        dispatch(&mut ctx, json!({"execute": NAME, "arguments": arguments})).unwrap()
    }

    #[test]
    fn arguments_are_checked_before_anything_starts() {
        let (agent, _dir) = agent();
        let desc = |arguments: Value| call(&agent, arguments)["error"]["desc"].clone();
        assert_eq!(desc(json!({})), json!("Parameter 'user' is missing"));
        assert_eq!(
            desc(json!({"user": "root", "rows": 0})),
            json!("Parameter 'rows' expects a value between 1 and 9999")
        );
        assert_eq!(
            desc(json!({"user": "root", "term": "xterm; reboot"})),
            json!("invalid terminal type 'xterm; reboot'")
        );
        assert_eq!(
            desc(json!({"user": "no-such-user-vga"})),
            json!("failed to lookup user 'no-such-user-vga': no such user")
        );
    }

    #[test]
    fn the_guest_owner_can_turn_it_off() {
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(
            Config {
                block_rpcs: vec![NAME.into()],
                ..Config::default()
            },
            dir.path().to_path_buf(),
        );
        assert_eq!(
            call(&agent, json!({"user": "root"}))["error"],
            json!({"class": "CommandNotFound", "desc": "Command __io.virtainer_shell has been disabled: the command is not allowed"})
        );
    }

    #[test]
    fn lang_comes_from_the_locale_files() {
        assert_eq!(
            parse_lang("LANG=\"en_US.UTF-8\"\n"),
            Some("en_US.UTF-8".into())
        );
        assert_eq!(
            parse_lang("# x\nLC_ALL=C\nLANG=C.UTF-8\n"),
            Some("C.UTF-8".into())
        );
        assert_eq!(parse_lang("LANG=$(reboot)\n"), None);
        assert_eq!(parse_lang(""), None);
    }

    /// Our own account with /bin/sh, so the test runs unprivileged.
    fn me(home: &Path) -> Account {
        // SAFETY: geteuid and getegid have no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Account {
            uid,
            gid,
            home: home.to_path_buf(),
            shell: Some(PathBuf::from("/bin/sh")),
            groups: vec![gid],
        }
    }

    struct Host {
        stream: UnixStream,
        output: Vec<u8>,
        exit: Option<Value>,
    }

    impl Host {
        fn send(&mut self, kind: u8, payload: &[u8]) {
            let mut frame = vec![kind];
            frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            frame.extend_from_slice(payload);
            self.stream.write_all(&frame).unwrap();
        }

        /// Read frames until `done` holds or the agent closes the stream.
        fn until(&mut self, done: impl Fn(&Host) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !done(self) && Instant::now() < deadline {
                let mut header = [0u8; 5];
                if self.stream.read_exact(&mut header).is_err() {
                    return;
                }
                let len = u32::from_le_bytes(header[1..].try_into().unwrap()) as usize;
                let mut payload = vec![0u8; len];
                self.stream.read_exact(&mut payload).unwrap();
                match header[0] {
                    0 => self.output.extend_from_slice(&payload),
                    _ => self.exit = Some(serde_json::from_slice(&payload).unwrap()),
                }
            }
        }

        fn saw(&self, text: &str) -> bool {
            String::from_utf8_lossy(&self.output).contains(text)
        }
    }

    #[test]
    fn a_session_runs_a_login_shell_and_reports_its_exit() {
        let (agent, dir) = agent();
        let (host, guest) = UnixStream::pair().unwrap();
        std::thread::scope(|scope| {
            let slot = agent.shells.reserve().unwrap();
            let session = start(slot, "tester", &me(dir.path()), (30, 100), "xterm").unwrap();
            let mut guest = guest;
            scope.spawn(move || crate::shell::relay(session, &mut guest));
            let mut host = Host {
                stream: host,
                output: Vec::new(),
                exit: None,
            };
            host.send(0, b"echo vga-$((6*7)) $TERM $LOGNAME; stty size; pwd\n");
            host.until(|h| h.saw("vga-42 xterm tester") && h.saw("30 100"));
            assert!(
                host.saw("vga-42 xterm tester"),
                "{:?}",
                String::from_utf8_lossy(&host.output)
            );
            host.send(1, br#"{"resize": [50, 160]}"#);
            host.send(0, b"stty size; exit 7\n");
            host.until(|h| h.exit.is_some());
            let output = String::from_utf8_lossy(&host.output).into_owned();
            assert!(output.contains("50 160"), "{output}");
            assert!(
                output.contains(&dir.path().display().to_string()),
                "{output}"
            );
            assert_eq!(host.exit, Some(json!({"exitcode": 7})));
        });
    }

    #[test]
    fn closing_the_connection_hangs_the_shell_up() {
        let (agent, dir) = agent();
        let (host, guest) = UnixStream::pair().unwrap();
        let slot = agent.shells.reserve().unwrap();
        let session = start(slot, "tester", &me(dir.path()), (24, 80), "xterm").unwrap();
        let pid = session.pid() as libc::pid_t;
        std::thread::scope(|scope| {
            let mut guest = guest;
            scope.spawn(move || crate::shell::relay(session, &mut guest));
            let mut host = Host {
                stream: host,
                output: Vec::new(),
                exit: None,
            };
            host.send(0, b"echo ready-$((1+1)); sleep 1000\n");
            host.until(|h| h.saw("ready-2"));
            drop(host);
        });
        // The relay has returned; the reaper collects the hung-up shell.
        let deadline = Instant::now() + Duration::from_secs(10);
        // SAFETY: kill with signal 0 only checks that the pid exists.
        while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        // SAFETY: as above.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "shell {pid} still running"
        );
    }
}
