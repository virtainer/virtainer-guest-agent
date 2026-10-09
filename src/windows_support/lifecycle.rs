// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Service readiness and recovery decisions without Windows syscalls.

use std::io;
use std::time::Duration;

pub const START_TIMEOUT: Duration = Duration::from_secs(60);
const RUNNING_SETTLE: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct Startup {
    running_since: Option<Duration>,
}
impl Startup {
    /// SCM RUNNING is published only after the listener is ready. Observe it
    /// continuously for two seconds to catch immediate initialization failures.
    pub fn observe(
        &mut self,
        elapsed: Duration,
        state: u32,
        win32_exit: u32,
        specific_exit: u32,
    ) -> Result<bool, String> {
        if win32_exit != 0 || specific_exit != 0 || !matches!(state, 2 | 4) {
            return Err(format!(
                "service startup failed (state {state}, Windows exit {win32_exit}, service exit {specific_exit})"
            ));
        }
        if state == 4 {
            let since = *self.running_since.get_or_insert(elapsed);
            if elapsed.saturating_sub(since) >= RUNNING_SETTLE {
                return Ok(true);
            }
        } else {
            self.running_since = None;
        }
        if elapsed >= START_TIMEOUT {
            return Err("service did not become ready within 60 seconds".into());
        }
        Ok(false)
    }
}

/// A restored executable must never start until the failed input is durably
/// suppressed. Failure to checkpoint leaves the backup available for recovery.
pub fn finish_attempt(
    activate: impl FnOnce() -> Result<(), String>,
    suppress: impl FnOnce() -> Result<(), String>,
    rollback: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if let Err(error) = activate() {
        suppress().map_err(|e| format!("update failed: {error}; cannot suppress retry: {e}"))?;
        rollback().map_err(|e| format!("update failed: {error}; rollback failed: {e}"))?;
        return Err(error);
    }
    Ok(())
}

/// Only the executable mapped by this uninstall process may use deferred
/// removal. Other access failures remain errors, including registry failures.
pub fn uninstall_delete(
    running_from_target: bool,
    remove: impl FnOnce() -> io::Result<()>,
    defer: impl FnOnce() -> io::Result<()>,
) -> io::Result<bool> {
    match remove() {
        Ok(()) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) if running_from_target && matches!(e.raw_os_error(), Some(5 | 32)) => {
            defer()?;
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn accepted_start_waits_for_stable_running_and_detects_late_failure() {
        let mut startup = Startup::default();
        assert!(!startup.observe(Duration::ZERO, 2, 0, 0).unwrap());
        assert!(!startup.observe(Duration::from_secs(1), 4, 0, 0).unwrap());
        assert!(!startup.observe(Duration::from_secs(2), 4, 0, 0).unwrap());
        assert!(startup.observe(Duration::from_secs(3), 4, 0, 0).unwrap());
        for (state, exit, specific) in [(1, 1, 0), (1, 0, 0), (4, 1066, 7), (3, 0, 0)] {
            let mut startup = Startup::default();
            assert!(!startup.observe(Duration::ZERO, 4, 0, 0).unwrap());
            assert!(startup
                .observe(Duration::from_secs(1), state, exit, specific)
                .is_err());
        }
    }

    #[test]
    fn pending_has_a_deadline_and_interrupted_readiness_restarts_the_settle_window() {
        let mut startup = Startup::default();
        assert!(startup.observe(START_TIMEOUT, 2, 0, 0).is_err());
        let mut startup = Startup::default();
        startup.observe(Duration::ZERO, 4, 0, 0).unwrap();
        startup.observe(Duration::from_secs(1), 2, 0, 0).unwrap();
        assert!(!startup.observe(Duration::from_secs(2), 4, 0, 0).unwrap());
        assert!(startup.observe(Duration::from_secs(4), 4, 0, 0).unwrap());
    }

    #[test]
    fn failed_start_checkpoints_before_fallback_and_checkpoint_failure_blocks_restart() {
        let events = RefCell::new(Vec::new());
        let error = finish_attempt(
            || {
                events.borrow_mut().push("start failed");
                Err("startup failure".into())
            },
            || {
                events.borrow_mut().push("checkpoint");
                Ok(())
            },
            || {
                events.borrow_mut().push("restore and start");
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error, "startup failure");
        assert_eq!(
            *events.borrow(),
            ["start failed", "checkpoint", "restore and start"]
        );
        assert!(finish_attempt(
            || Err("stopped".into()),
            || Err("disk full".into()),
            || panic!()
        )
        .is_err());
        finish_attempt(|| Ok(()), || panic!(), || panic!()).unwrap();
        let error = finish_attempt(
            || Err("startup".into()),
            || Ok(()),
            || Err("restore".into()),
        )
        .unwrap_err();
        assert!(error.contains("startup") && error.contains("restore"));
    }

    #[test]
    fn mapped_self_is_deferred_but_unrelated_failures_are_reported() {
        for code in [5, 32] {
            assert!(
                uninstall_delete(true, || Err(io::Error::from_raw_os_error(code)), || Ok(()))
                    .unwrap()
            );
            assert!(uninstall_delete(
                false,
                || Err(io::Error::from_raw_os_error(code)),
                || panic!()
            )
            .is_err());
        }
        assert!(!uninstall_delete(true, || Ok(()), || panic!()).unwrap());
        assert!(!uninstall_delete(
            true,
            || Err(io::Error::from(io::ErrorKind::NotFound)),
            || panic!()
        )
        .unwrap());
        assert!(uninstall_delete(
            true,
            || Err(io::Error::from_raw_os_error(5)),
            || Err(io::Error::from(io::ErrorKind::PermissionDenied))
        )
        .is_err());
        assert!(uninstall_delete(
            true,
            || Err(io::Error::from(io::ErrorKind::InvalidInput)),
            || panic!()
        )
        .is_err());
    }
}
