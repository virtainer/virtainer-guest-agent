// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Filesystem freeze/thaw and fstrim.
//!
//! The ordering rules are qemu-ga's, because hosts rely on its counts:
//! - freeze walks local filesystems in reverse mount order (children before
//!   parents), counts the ones it froze, ignores EOPNOTSUPP and EBUSY, and on
//!   any other error thaws everything and fails;
//! - thaw walks every local filesystem, repeats FITHAW until it fails, and
//!   counts each filesystem it thawed once. Thawing a thawed guest returns 0,
//!   so a host can detect that something thawed part of its window early;
//! - "frozen" is this agent's own state, persisted in /run so a restarted
//!   agent still refuses everything but thaw.
//!
//! Additions: the hook runs under a timeout, and a watchdog thaws on its own
//! when no thaw arrives within `freeze-timeout` (a host that dies mid-snapshot
//! must not leave the guest hung forever). An early thaw is visible to the
//! host as a count mismatch, so it can never pass for a quiesced snapshot.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

use serde::Serialize;
use serde_json::json;

use super::mounts::{local_mounts, Mount};
use super::{no_args, to_value, Ctx};
use crate::qmp::{Args, QgaError, Reply};
use crate::sys;

const FIFREEZE: u64 = 0xC004_5877;
const FITHAW: u64 = 0xC004_5878;
const FITRIM: u64 = 0xC018_5879;

/// A hook that has not finished in this long is killed; holding the freeze
/// lock forever would also block every thaw.
const HOOK_TIMEOUT: Duration = Duration::from_secs(300);
const WATCHDOG_RETRY: Duration = Duration::from_secs(10);

/// What freezing does to the filesystems. `Kernel` is the agent's; the tests
/// put a stand-in in its place, so the freezer's own state machine can be
/// driven without freezing the filesystems of the machine running them.
trait Filesystems: Send + Sync {
    fn mounts(&self) -> std::io::Result<Vec<Mount>>;
    fn freeze(&self, mounts: &[Mount], only: Option<&[String]>) -> Result<i64, QgaError>;
    fn thaw(&self, mounts: &[Mount]) -> i64;
}

struct Kernel;

impl Filesystems for Kernel {
    fn mounts(&self) -> std::io::Result<Vec<Mount>> {
        local_mounts()
    }

    fn freeze(&self, mounts: &[Mount], only: Option<&[String]>) -> Result<i64, QgaError> {
        freeze_mounts(mounts, only)
    }

    fn thaw(&self, mounts: &[Mount]) -> i64 {
        thaw_mounts(mounts)
    }
}

pub struct Freezer {
    fs: Box<dyn Filesystems>,
    frozen: AtomicBool,
    state: Mutex<State>,
    wake: Condvar,
    marker: PathBuf,
    timeout: Option<Duration>,
}

struct State {
    /// Bumped by every freeze and by every thaw that got as far as the
    /// filesystems: the watchdog tells by it whether its thaw did anything.
    generation: u64,
    /// Boot-clock deadline for the watchdog.
    deadline: Option<Duration>,
}

impl Freezer {
    pub fn new(marker: PathBuf, timeout: Option<Duration>) -> Self {
        Self::with_fs(Box::new(Kernel), marker, timeout)
    }

    fn with_fs(fs: Box<dyn Filesystems>, marker: PathBuf, timeout: Option<Duration>) -> Self {
        let restored = std::fs::read_to_string(&marker).ok();
        let deadline = restored.as_ref().and_then(|text| {
            text.trim()
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| timeout.map(|t| sys::boottime() + t))
        });
        Self {
            fs,
            frozen: AtomicBool::new(restored.is_some()),
            state: Mutex::new(State {
                generation: 0,
                deadline,
            }),
            wake: Condvar::new(),
            marker,
            timeout,
        }
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::SeqCst)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Enter the frozen state before the first FIFREEZE: from here on nothing
    /// may write to disk, including the run log.
    fn mark_frozen(&self, deadline: Option<Duration>) {
        crate::log::hold(true);
        self.frozen.store(true, Ordering::SeqCst);
        let content = deadline
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default();
        if let Some(dir) = self.marker.parent() {
            ensure_private_dir(dir);
        }
        if let Err(e) = std::fs::write(&self.marker, content) {
            crate::warning!(
                "cannot record the frozen state in {}: {e}; a restarted agent would not know",
                self.marker.display()
            );
        }
    }

    fn mark_thawed(&self) {
        self.frozen.store(false, Ordering::SeqCst);
        let _ = std::fs::remove_file(&self.marker);
        crate::log::hold(false);
    }

    /// `command` names the request in the refusal a second, concurrent
    /// freeze gets: dispatch saw "thawed" for both, but only one may freeze.
    /// Otherwise the loser would find every filesystem EBUSY, count 0, and
    /// clear the frozen state while the guest is still frozen.
    pub fn freeze(
        &self,
        command: &str,
        hook: Option<PathBuf>,
        mountpoints: Option<Vec<String>>,
    ) -> Result<i64, QgaError> {
        let mut state = self.lock();
        if self.is_frozen() {
            return Err(QgaError::command_not_found(format!(
                "Command {command} has been disabled: the command is not allowed"
            )));
        }
        crate::info!("guest-fsfreeze called");
        run_hook(hook.as_ref(), "freeze")?;
        let mounts = match self.fs.mounts() {
            Ok(mounts) => mounts,
            Err(e) => {
                // Nothing got frozen; let the hook resume what it paused.
                if let Err(hook_error) = run_hook(hook.as_ref(), "thaw") {
                    crate::error!("{}", hook_error.desc);
                }
                return Err(QgaError::os("failed to read /proc/self/mountinfo", &e));
            }
        };

        let deadline = self.timeout.map(|t| sys::boottime() + t);
        self.mark_frozen(deadline);
        state.generation += 1;
        match self.fs.freeze(&mounts, mountpoints.as_deref()) {
            Ok(0) => {
                // Nothing was frozen, but the hook already paused the guest's
                // applications.
                self.mark_thawed();
                if let Err(hook_error) = run_hook(hook.as_ref(), "thaw") {
                    crate::error!("{}", hook_error.desc);
                }
                Ok(0)
            }
            Ok(count) => {
                state.deadline = deadline;
                self.wake.notify_all();
                Ok(count)
            }
            Err(error) => {
                if let Err(thaw_error) = self.thaw_locked(&mut state, hook) {
                    crate::error!("thaw after a failed freeze failed: {}", thaw_error.desc);
                }
                Err(error)
            }
        }
    }

    pub fn thaw(&self, hook: Option<PathBuf>) -> Result<i64, QgaError> {
        let mut state = self.lock();
        self.thaw_locked(&mut state, hook)
    }

    /// Thaw, with the state already locked by the caller: whatever made the
    /// caller decide to thaw still holds when it does, as no freeze or thaw
    /// can run in between.
    fn thaw_locked(&self, state: &mut State, hook: Option<PathBuf>) -> Result<i64, QgaError> {
        let mounts = self
            .fs
            .mounts()
            .map_err(|e| QgaError::os("failed to read /proc/self/mountinfo", &e))?;
        let count = self.fs.thaw(&mounts);
        state.generation += 1;
        state.deadline = None;
        let was_frozen = self.is_frozen();
        self.mark_thawed();
        if was_frozen || count > 0 {
            crate::info!("guest-fsthaw called: {count} filesystems thawed");
        }
        run_hook(hook.as_ref(), "thaw")?;
        Ok(count)
    }

    /// Thaw when a freeze outlives its deadline. Runs forever on its own thread.
    pub fn watchdog(&self, hook: impl Fn() -> Option<PathBuf>) {
        let mut state = self.lock();
        loop {
            let Some(deadline) = state.deadline else {
                state = self.wake.wait(state).unwrap_or_else(|p| p.into_inner());
                continue;
            };
            let now = sys::boottime();
            if now < deadline {
                state = self
                    .wake
                    .wait_timeout(state, deadline - now)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
                continue;
            }
            // The window is overdue. It is thawed under the same guard that
            // saw it overdue: a host's thaw of it and its next freeze wait,
            // so the next window can never be the one thawed here.
            let generation = state.generation;
            crate::warning!(
                "no thaw arrived within freeze-timeout; thawing filesystems on our own"
            );
            match self.thaw_locked(&mut state, hook()) {
                Ok(count) => crate::warning!("auto-thawed {count} filesystems"),
                Err(e) => crate::error!("auto-thaw failed: {}", e.desc),
            }
            if state.generation == generation {
                // Thaw failed before it got anywhere (mountinfo unreadable):
                // try again shortly rather than spin or give up.
                state.deadline = Some(sys::boottime() + WATCHDOG_RETRY);
            }
        }
    }
}

/// The marker directory is created 0700 whatever the umask; an existing
/// directory is left as the administrator set it.
fn ensure_private_dir(dir: &std::path::Path) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if dir.exists() {
        return;
    }
    let created = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir);
    if created.is_ok() {
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
}

fn run_hook(hook: Option<&PathBuf>, arg: &str) -> Result<(), QgaError> {
    let Some(hook) = hook else { return Ok(()) };
    crate::config::check_trusted(hook)
        .map_err(|e| QgaError::generic(format!("fsfreeze hook: {e}")))?;
    let path = hook.to_string_lossy();
    if arg == "freeze" {
        crate::info!("executing fsfreeze hook with arg '{arg}'");
    }
    sys::run_helper(
        &[path.as_ref(), arg],
        None,
        "execute fsfreeze hook",
        Some(HOOK_TIMEOUT),
    )
}

/// Non-blocking, so a mountpoint that is somehow a FIFO cannot hang us.
fn open_dir(mount: &Mount) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&mount.dir)
}

fn freeze_mounts(mounts: &[Mount], only: Option<&[String]>) -> Result<i64, QgaError> {
    let mut count = 0;
    for mount in mounts.iter().rev() {
        if let Some(only) = only {
            if !only
                .iter()
                .any(|m| m.as_bytes() == mount.dir.as_os_str().as_encoded_bytes())
            {
                continue;
            }
        }
        let dir = open_dir(mount)
            .map_err(|e| QgaError::os(format!("failed to open {}", mount.dir_lossy()), &e))?;
        // SAFETY: FIFREEZE takes an int argument that the kernel ignores.
        match unsafe { sys::ioctl(dir.as_raw_fd(), FIFREEZE, &mut 0i32) } {
            Ok(_) => count += 1,
            // Not freezable, or already frozen through another mount.
            Err(e) if matches!(e.raw_os_error(), Some(libc::EOPNOTSUPP | libc::EBUSY)) => {}
            Err(e) => {
                return Err(QgaError::os(
                    format!("failed to freeze {}", mount.dir_lossy()),
                    &e,
                ))
            }
        }
    }
    Ok(count)
}

fn thaw_mounts(mounts: &[Mount]) -> i64 {
    let mut count = 0;
    for mount in mounts {
        let Ok(dir) = open_dir(mount) else { continue };
        let mut thawed = false;
        // Every successful FIFREEZE needs its own FITHAW; the last one that
        // succeeds is the one that actually thawed.
        // SAFETY: FITHAW takes an int argument that the kernel ignores.
        while unsafe { sys::ioctl(dir.as_raw_fd(), FITHAW, &mut 0i32) }.is_ok() {
            thawed = true;
        }
        if thawed {
            count += 1;
        }
    }
    count
}

pub fn status(ctx: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    Ok(json!(if ctx.agent.freezer.is_frozen() {
        "frozen"
    } else {
        "thawed"
    }))
}

pub fn freeze(ctx: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let agent = ctx.agent;
    agent
        .freezer
        .freeze("guest-fsfreeze-freeze", agent.config.hook_path(), None)
        .map(|n| json!(n))
}

pub fn freeze_list(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let mountpoints = args.opt_str_list("mountpoints")?;
    args.finish()?;
    let agent = ctx.agent;
    agent
        .freezer
        .freeze(
            "guest-fsfreeze-freeze-list",
            agent.config.hook_path(),
            mountpoints,
        )
        .map(|n| json!(n))
}

pub fn thaw(ctx: &mut Ctx<'_>, args: Args) -> Reply {
    no_args(args)?;
    let agent = ctx.agent;
    agent
        .freezer
        .thaw(agent.config.hook_path())
        .map(|n| json!(n))
}

#[repr(C)]
struct FstrimRange {
    start: u64,
    len: u64,
    minlen: u64,
}

#[derive(Serialize)]
struct TrimResult {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    trimmed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn fstrim(_: &mut Ctx<'_>, mut args: Args) -> Reply {
    let minimum = args.opt_int("minimum")?;
    args.finish()?;
    crate::info!("guest-fstrim called");
    let mounts =
        local_mounts().map_err(|e| QgaError::os("failed to read /proc/self/mountinfo", &e))?;
    let mut paths = Vec::with_capacity(mounts.len());
    for mount in &mounts {
        let mut result = TrimResult {
            path: mount.dir_lossy(),
            trimmed: None,
            minimum: None,
            error: None,
        };
        match open_dir(mount) {
            Err(e) => result.error = Some(format!("failed to open: {}", sys::strerror(&e))),
            Ok(dir) => {
                let mut range = FstrimRange {
                    start: 0,
                    len: u64::MAX,
                    minlen: minimum.unwrap_or(0) as u64,
                };
                // SAFETY: FITRIM reads and updates a struct fstrim_range.
                match unsafe { sys::ioctl(dir.as_raw_fd(), FITRIM, &mut range) } {
                    Ok(_) => {
                        result.trimmed = Some(range.len);
                        result.minimum = Some(range.minlen);
                    }
                    Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTTY | libc::EOPNOTSUPP)) => {
                        result.error = Some("trim not supported".into())
                    }
                    Err(e) => result.error = Some(format!("failed to trim: {}", sys::strerror(&e))),
                }
            }
        }
        paths.push(result);
    }
    // qemu-ga builds this list by prepending.
    paths.reverse();
    Ok(json!({ "paths": to_value(paths) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restarted_agent_remembers_it_is_frozen() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("frozen");
        std::fs::write(&marker, "123").unwrap();
        let freezer = Freezer::new(marker.clone(), Some(Duration::from_secs(5)));
        assert!(freezer.is_frozen());
        assert_eq!(freezer.lock().deadline, Some(Duration::from_secs(123)));

        std::fs::write(&marker, "").unwrap();
        let freezer = Freezer::new(marker.clone(), Some(Duration::from_secs(5)));
        assert!(freezer.is_frozen());
        assert!(freezer.lock().deadline.is_some());

        std::fs::remove_file(&marker).unwrap();
        assert!(!Freezer::new(marker, None).is_frozen());
    }

    #[test]
    fn freeze_list_with_no_matching_mountpoint_freezes_nothing() {
        // Runs unprivileged: nothing matches, so no ioctl is attempted.
        let dir = tempfile::tempdir().unwrap();
        let freezer = Freezer::new(dir.path().join("frozen"), None);
        let count = freezer
            .freeze("t", None, Some(vec!["/definitely/not/a/mount".into()]))
            .unwrap();
        assert_eq!(count, 0);
        assert!(!freezer.is_frozen());
        assert!(!dir.path().join("frozen").exists());
    }

    #[test]
    fn freeze_with_nothing_matched_still_runs_the_thaw_hook() {
        let dir = tempfile::tempdir().unwrap();
        let hook = dir.path().join("hook");
        let log = dir.path().join("calls");
        install_hook(
            &hook,
            &format!("#!/bin/sh\necho \"$1\" >> {}\n", log.display()),
        );
        let freezer = Freezer::new(dir.path().join("frozen"), None);
        let count = freezer
            .freeze(
                "t",
                Some(hook),
                Some(vec!["/definitely/not/a/mount".into()]),
            )
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "freeze\nthaw\n");
    }

    #[test]
    fn the_marker_directory_is_private_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run").join("agent");
        // SAFETY: umask only changes this process's creation mask.
        let old = unsafe { libc::umask(0) };
        ensure_private_dir(&run);
        unsafe { libc::umask(old) };
        let mode = std::fs::metadata(&run).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// Writes an executable hook without this process ever holding a writable
    /// descriptor on it. Tests run in parallel threads, and a child forked by
    /// another test inherits every open descriptor until it execs; if that
    /// includes a write descriptor on the hook, executing the hook fails with
    /// ETXTBSY. The script goes to a side file and a child process installs it.
    fn install_hook(hook: &std::path::Path, script: &str) {
        let source = hook.with_extension("src");
        std::fs::write(&source, script).unwrap();
        let status = std::process::Command::new("install")
            .args(["-m", "0755"])
            .arg(&source)
            .arg(hook)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn a_failing_freeze_hook_freezes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let hook = dir.path().join("hook");
        install_hook(&hook, "#!/bin/sh\necho \"no $1 today\"; exit 1\n");
        let freezer = Freezer::new(dir.path().join("frozen"), None);
        let err = freezer.freeze("t", Some(hook), None).unwrap_err();
        assert_eq!(
            err.desc,
            "child process has failed to execute fsfreeze hook: no freeze today"
        );
        assert!(!freezer.is_frozen());
    }

    #[test]
    fn a_second_freeze_is_refused_while_frozen() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("frozen");
        std::fs::write(&marker, "").unwrap();
        let freezer = Freezer::new(marker, None);
        let err = freezer
            .freeze("guest-fsfreeze-freeze", None, None)
            .unwrap_err();
        assert_eq!(
            err.desc,
            "Command guest-fsfreeze-freeze has been disabled: the command is not allowed"
        );
        assert!(freezer.is_frozen());
    }

    /// Stand-in filesystems: one mount, frozen or not, and a record of what
    /// was done to it and by which thread.
    #[derive(Default)]
    struct Fake {
        frozen: Mutex<bool>,
        log: Mutex<Vec<String>>,
        /// Fail this many mount table reads.
        unreadable: Mutex<u32>,
        fail_freeze: AtomicBool,
    }

    struct Shared(std::sync::Arc<Fake>);

    fn thread_name() -> String {
        std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string()
    }

    impl Filesystems for Shared {
        fn mounts(&self) -> std::io::Result<Vec<Mount>> {
            let mut left = self.0.unreadable.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(std::io::Error::other("mount table unreadable"));
            }
            Ok(vec![Mount {
                dir: "/fake".into(),
                fstype: "ext4".into(),
                major: 0,
                minor: 0,
            }])
        }

        fn freeze(&self, _: &[Mount], _: Option<&[String]>) -> Result<i64, QgaError> {
            if self.0.fail_freeze.load(Ordering::SeqCst) {
                return Err(QgaError::generic("freeze failed"));
            }
            *self.0.frozen.lock().unwrap() = true;
            self.0
                .log
                .lock()
                .unwrap()
                .push(format!("freeze by {}", thread_name()));
            Ok(1)
        }

        fn thaw(&self, _: &[Mount]) -> i64 {
            let was = std::mem::take(&mut *self.0.frozen.lock().unwrap());
            self.0
                .log
                .lock()
                .unwrap()
                .push(format!("thaw {} by {}", was as i64, thread_name()));
            was as i64
        }
    }

    fn fake_freezer(fake: &std::sync::Arc<Fake>) -> (tempfile::TempDir, std::sync::Arc<Freezer>) {
        let dir = tempfile::tempdir().unwrap();
        let f = Freezer::with_fs(
            Box::new(Shared(fake.clone())),
            dir.path().join("frozen"),
            Some(Duration::from_secs(3600)),
        );
        (dir, std::sync::Arc::new(f))
    }

    /// Run the watchdog on a thread named "watchdog", with `hook` as its hook.
    fn watchdog(f: &std::sync::Arc<Freezer>, hook: impl Fn() -> Option<PathBuf> + Send + 'static) {
        let f = f.clone();
        std::thread::Builder::new()
            .name("watchdog".into())
            .spawn(move || f.watchdog(hook))
            .unwrap();
    }

    /// Make the current window overdue, as if its deadline had passed.
    fn expire(f: &Freezer) {
        f.lock().deadline = Some(Duration::ZERO);
        f.wake.notify_all();
    }

    /// Wait up to five seconds for `done`.
    fn eventually(what: &str, done: impl Fn() -> bool) {
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(std::time::Instant::now() < until, "{what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn the_watchdog_thaws_an_overdue_freeze() {
        let fake = std::sync::Arc::new(Fake::default());
        let (_dir, f) = fake_freezer(&fake);
        assert_eq!(f.freeze("t", None, None).unwrap(), 1);
        let generation = f.lock().generation;
        watchdog(&f, || None);
        expire(&f);
        eventually("the watchdog thaws", || !f.is_frozen());
        assert_eq!(
            *fake.log.lock().unwrap().last().unwrap(),
            "thaw 1 by watchdog"
        );
        let state = f.lock();
        assert_eq!((state.generation, state.deadline), (generation + 1, None));
    }

    #[test]
    fn a_stale_watchdog_never_thaws_the_next_freeze() {
        // The watchdog decides to thaw window A. In the same moment a host
        // thaws A and freezes B. Whichever order the two take, B must stay
        // frozen: the watchdog may thaw A, never B.
        let fake = std::sync::Arc::new(Fake::default());
        let (_dir, f) = fake_freezer(&fake);
        assert_eq!(f.freeze("t", None, None).unwrap(), 1);
        let host = f.clone();
        let started = std::sync::Arc::new(Mutex::new(None));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (tx, rx) = (Mutex::new(Some(tx)), Mutex::new(rx));
        let handle = started.clone();
        // The watchdog asks for its hook once it decided to act: let the host
        // go then, and give it half a second before the watchdog goes on.
        watchdog(&f, move || {
            if let Some(tx) = tx.lock().unwrap().take() {
                let host = host.clone();
                let h = std::thread::Builder::new()
                    .name("host".into())
                    .spawn(move || {
                        host.thaw(None).unwrap();
                        host.freeze("t", None, None).unwrap();
                        let _ = tx.send(());
                    })
                    .unwrap();
                *handle.lock().unwrap() = Some(h);
                let _ = rx.lock().unwrap().recv_timeout(Duration::from_millis(500));
            }
            None
        });
        expire(&f);
        eventually("the host thread starts", || {
            started.lock().unwrap().is_some()
        });
        started.lock().unwrap().take().unwrap().join().unwrap();
        eventually("both thaws and the second freeze happened", || {
            fake.log.lock().unwrap().len() == 4
        });
        // Nothing more is due before B's own deadline.
        std::thread::sleep(Duration::from_millis(200));
        let log = fake.log.lock().unwrap().clone();
        assert_eq!(log.len(), 4, "{log:?}");
        assert_eq!(
            log[3], "freeze by host",
            "B was thawed after it froze: {log:?}"
        );
        assert!(log.contains(&"thaw 1 by watchdog".to_string()), "{log:?}");
        assert!(f.is_frozen(), "{log:?}");
        assert!(*fake.frozen.lock().unwrap());
        assert!(f.lock().deadline.is_some_and(|d| d > sys::boottime()));
    }

    #[test]
    fn an_auto_thaw_that_cannot_read_the_mount_table_is_retried() {
        let fake = std::sync::Arc::new(Fake::default());
        let (_dir, f) = fake_freezer(&fake);
        f.freeze("t", None, None).unwrap();
        *fake.unreadable.lock().unwrap() = 1;
        watchdog(&f, || None);
        expire(&f);
        eventually("the watchdog schedules a retry", || {
            f.lock().deadline.is_some_and(|d| d > sys::boottime())
        });
        assert!(f.is_frozen(), "still frozen after the failed attempt");
        let retry = f.lock().deadline.unwrap() - sys::boottime();
        assert!(retry <= WATCHDOG_RETRY, "{retry:?}");
        expire(&f);
        eventually("the retry thaws", || !f.is_frozen());
        assert_eq!(
            *fake.log.lock().unwrap().last().unwrap(),
            "thaw 1 by watchdog"
        );
    }

    #[test]
    fn a_freeze_that_fails_thaws_what_it_froze() {
        let fake = std::sync::Arc::new(Fake::default());
        let (_dir, f) = fake_freezer(&fake);
        fake.fail_freeze.store(true, Ordering::SeqCst);
        *fake.frozen.lock().unwrap() = true;
        let generation = f.lock().generation;
        assert_eq!(f.freeze("t", None, None).unwrap_err().desc, "freeze failed");
        assert!(!f.is_frozen());
        assert!(
            !*fake.frozen.lock().unwrap(),
            "the partial freeze was thawed"
        );
        let state = f.lock();
        assert_eq!((state.generation, state.deadline), (generation + 2, None));
    }

    #[test]
    fn status_reports_a_bare_string() {
        let dir = tempfile::tempdir().unwrap();
        let agent = crate::agent::Agent::new(Default::default(), dir.path().to_path_buf());
        let mut ctx = Ctx::new(&agent);
        assert_eq!(
            status(&mut ctx, Args::new(Default::default())).unwrap(),
            json!("thawed")
        );
    }
}
