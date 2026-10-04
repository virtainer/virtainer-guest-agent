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

pub struct Freezer {
    frozen: AtomicBool,
    state: Mutex<State>,
    wake: Condvar,
    marker: PathBuf,
    timeout: Option<Duration>,
}

struct State {
    /// Bumped by every freeze and thaw, so a watchdog that decided to act on
    /// one window never thaws the next.
    generation: u64,
    /// Boot-clock deadline for the watchdog.
    deadline: Option<Duration>,
}

impl Freezer {
    pub fn new(marker: PathBuf, timeout: Option<Duration>) -> Self {
        let restored = std::fs::read_to_string(&marker).ok();
        let deadline = restored.as_ref().and_then(|text| {
            text.trim()
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| timeout.map(|t| sys::boottime() + t))
        });
        Self {
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
        let mounts = match local_mounts() {
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
        match freeze_mounts(&mounts, mountpoints.as_deref()) {
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
                drop(state);
                if let Err(thaw_error) = self.thaw(hook) {
                    crate::error!("thaw after a failed freeze failed: {}", thaw_error.desc);
                }
                Err(error)
            }
        }
    }

    pub fn thaw(&self, hook: Option<PathBuf>) -> Result<i64, QgaError> {
        let mut state = self.lock();
        let mounts =
            local_mounts().map_err(|e| QgaError::os("failed to read /proc/self/mountinfo", &e))?;
        let count = thaw_mounts(&mounts);
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
            let generation = state.generation;
            drop(state);
            if self.lock().generation == generation {
                crate::warning!(
                    "no thaw arrived within freeze-timeout; thawing filesystems on our own"
                );
                match self.thaw(hook()) {
                    Ok(count) => crate::warning!("auto-thawed {count} filesystems"),
                    Err(e) => crate::error!("auto-thaw failed: {}", e.desc),
                }
            }
            state = self.lock();
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
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let hook = dir.path().join("hook");
        let log = dir.path().join("calls");
        std::fs::write(
            &hook,
            format!("#!/bin/sh\necho \"$1\" >> {}\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
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

    #[test]
    fn a_failing_freeze_hook_freezes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let hook = dir.path().join("hook");
        std::fs::write(&hook, "#!/bin/sh\necho \"no $1 today\"; exit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
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
