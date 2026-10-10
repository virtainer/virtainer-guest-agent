// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `guest-exec` / `guest-exec-status`.
//!
//! Each started process gets a supervisor thread that feeds stdin, drains the
//! captured pipes and reaps the child. A process counts as exited once its
//! pipes are closed too, so the status does not report output that is still
//! arriving (qemu-ga's rule) -- except that a daemon the child left behind,
//! still holding the pipes, may delay the report only by `PIPE_GRACE`; what
//! was captured by then is reported and the drain threads let go. The entry is
//! dropped when its exit is reported.
//!
//! Entries are kept per pid in start order: the kernel may hand a pid out
//! again while an earlier process with that pid is still unreported, and
//! `guest-exec-status` (keyed by pid, as in qemu-ga) then reports them oldest
//! first rather than losing either.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Map, Value};

use super::file::decode_base64;
use super::Ctx;
use crate::qmp::{enum_value, type_error, Args, QgaError, Reply};
use crate::sys;

/// qemu-ga's capture limit per stream.
const OUTPUT_CAP: usize = 16 << 20;
/// Output retained across all unreported entries together.
const TOTAL_OUTPUT_CAP: usize = 256 << 20;
/// Started-but-unreported processes kept at once. qemu-ga has no bound; an
/// unbounded table would let a careless client grow the agent forever. Each
/// running entry holds up to three fds here, which together with the file
/// handle cap must stay well below a 1024 soft `RLIMIT_NOFILE`.
const MAX_TRACKED: usize = 128;
/// How long after the child exits its output pipes may stay open.
const PIPE_GRACE: Duration = Duration::from_secs(2);
/// How often a drain thread checks whether it has been told to let go.
#[cfg(target_os = "linux")]
const DRAIN_POLL_MS: i32 = 250;

type Slot = Mutex<Option<Finished>>;

pub struct ExecTable {
    inner: Mutex<HashMap<i64, VecDeque<Arc<Slot>>>>,
    budget: Arc<Budget>,
}

impl Default for ExecTable {
    fn default() -> Self {
        Self::with_output_cap(TOTAL_OUTPUT_CAP)
    }
}

impl ExecTable {
    fn with_output_cap(limit: usize) -> Self {
        Self {
            inner: Mutex::default(),
            budget: Arc::new(Budget {
                limit,
                used: AtomicUsize::new(0),
            }),
        }
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<i64, VecDeque<Arc<Slot>>>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The oldest entry for `pid` if it has finished; `None` if no entry
    /// exists, `Some(None)` if it is still running.
    fn take_finished(&self, pid: i64) -> Option<Option<Finished>> {
        let mut table = self.entries();
        let queue = table.get_mut(&pid)?;
        let done = queue
            .front()?
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if done.is_some() {
            queue.pop_front();
            if queue.is_empty() {
                table.remove(&pid);
            }
        }
        Some(done)
    }
}

/// Output bytes retained by all entries; reservations are returned when the
/// captured data is dropped.
struct Budget {
    limit: usize,
    used: AtomicUsize,
}

impl Budget {
    /// Reserve up to `want` bytes; the amount granted may be smaller.
    fn take(&self, want: usize) -> usize {
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let grant = want.min(self.limit.saturating_sub(used));
            match self.used.compare_exchange_weak(
                used,
                used + grant,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return grant,
                Err(now) => used = now,
            }
        }
    }

    fn release(&self, n: usize) {
        self.used.fetch_sub(n, Ordering::AcqRel);
    }
}

struct Finished {
    status: io::Result<ExitStatus>,
    out: Option<Captured>,
    err: Option<Captured>,
}

struct Captured {
    data: Vec<u8>,
    truncated: bool,
    /// Set once the collector has taken the data: the drain thread stops.
    closed: bool,
    budget: Arc<Budget>,
}

impl Captured {
    fn new(budget: Arc<Budget>) -> Self {
        Self {
            data: Vec::new(),
            truncated: false,
            closed: false,
            budget,
        }
    }
}

impl Drop for Captured {
    fn drop(&mut self) {
        self.budget.release(self.data.len());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Capture {
    None,
    Stdout,
    Stderr,
    Separated,
    Merged,
}

fn capture_mode(value: Option<Value>, name: &str) -> Result<Capture, QgaError> {
    Ok(match value {
        None | Some(Value::Bool(false)) => Capture::None,
        Some(Value::Bool(true)) => Capture::Separated,
        Some(Value::String(s)) => match enum_value(
            &s,
            name,
            &["none", "stdout", "stderr", "separated", "merged"],
        )? {
            "none" => Capture::None,
            "stdout" => Capture::Stdout,
            "stderr" => Capture::Stderr,
            "separated" => Capture::Separated,
            _ => Capture::Merged,
        },
        Some(_) => return Err(type_error(name, "GuestExecCaptureOutput")),
    })
}

/// A thread reading one pipe into a shared buffer.
struct Drain {
    shared: Arc<Mutex<Captured>>,
    /// Disconnects when the thread ends.
    ended: mpsc::Receiver<()>,
}

#[cfg(target_os = "linux")]
trait Pipe: Read + AsFd {}
#[cfg(target_os = "linux")]
impl<T: Read + AsFd> Pipe for T {}
#[cfg(target_os = "windows")]
trait Pipe: Read + AsRawHandle {}
#[cfg(target_os = "windows")]
impl<T: Read + AsRawHandle> Pipe for T {}

fn spawn_drain(mut pipe: impl Pipe + Send + 'static, budget: Arc<Budget>) -> io::Result<Drain> {
    let shared = Arc::new(Mutex::new(Captured::new(budget)));
    let (ended_tx, ended) = mpsc::channel::<()>();
    let state = shared.clone();
    std::thread::Builder::new()
        .name("exec-drain".into())
        .spawn(move || {
            let _ended = ended_tx;
            let mut chunk = [0u8; 4096];
            loop {
                if state.lock().unwrap_or_else(|p| p.into_inner()).closed {
                    return;
                }
                #[cfg(target_os = "windows")]
                match sys::pipe_ready(pipe.as_raw_handle()) {
                    Ok(false) => {
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    Err(_) => return,
                    Ok(true) => {}
                }
                #[cfg(target_os = "linux")]
                let mut pfd = libc::pollfd {
                    fd: pipe.as_fd().as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: pfd is a valid pollfd and the count is 1.
                #[cfg(target_os = "linux")]
                match unsafe { libc::poll(&mut pfd, 1, DRAIN_POLL_MS) } {
                    0 => continue,
                    r if r < 0
                        && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted =>
                    {
                        continue
                    }
                    r if r < 0 => return,
                    _ => {}
                }
                match pipe.read(&mut chunk) {
                    Ok(0) => return,
                    Ok(n) => {
                        let mut captured = state.lock().unwrap_or_else(|p| p.into_inner());
                        let want = n.min(OUTPUT_CAP - captured.data.len());
                        let got = captured.budget.take(want);
                        if got < n {
                            captured.truncated = true;
                        }
                        if captured.data.try_reserve(got).is_ok() {
                            captured.data.extend_from_slice(&chunk[..got]);
                        } else {
                            captured.budget.release(got);
                            captured.truncated = true;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return,
                }
            }
        })?;
    Ok(Drain { shared, ended })
}

impl Drain {
    /// What was captured, waiting for the pipe to close until `deadline`.
    /// A thread still reading after that is told to let go.
    fn collect(self, deadline: Instant) -> Captured {
        let _ = self
            .ended
            .recv_timeout(deadline.saturating_duration_since(Instant::now()));
        let mut shared = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        shared.closed = true;
        Captured {
            data: std::mem::take(&mut shared.data),
            truncated: shared.truncated,
            closed: true,
            budget: shared.budget.clone(),
        }
    }

    /// Stop the thread; its data is not wanted.
    fn abandon(self) {
        self.shared.lock().unwrap_or_else(|p| p.into_inner()).closed = true;
    }
}

pub fn exec(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let path = args.str("path")?;
    let argv = args.opt_str_list("arg")?.unwrap_or_default();
    let env = args.opt_str_list("env")?;
    let input = args.opt_str("input-data")?;
    let (capture, name) = args.opt_raw("capture-output");
    let capture = capture_mode(capture, &name)?;
    args.finish()?;

    let input = input.map(|data| decode_base64(&data)).transpose()?;
    let mut command = Command::new(&path);
    command.args(&argv);
    #[cfg(target_os = "linux")]
    command.current_dir("/");
    #[cfg(target_os = "windows")]
    command.current_dir(sys::system_dir());
    if let Some(env) = env {
        command.env_clear();
        for entry in env {
            let Some((key, value)) = entry.split_once('=') else {
                return Err(QgaError::generic(format!(
                    "invalid environment entry '{entry}' (expected NAME=VALUE)"
                )));
            };
            command.env(key, value);
        }
    }
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut merged_reader = None;
    match capture {
        Capture::None => {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        Capture::Stdout => {
            command.stdout(Stdio::piped()).stderr(Stdio::null());
        }
        Capture::Stderr => {
            command.stdout(Stdio::null()).stderr(Stdio::piped());
        }
        Capture::Separated => {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        Capture::Merged => {
            let pipe_error = |e: io::Error| QgaError::os("cannot create pipe FDs", &e);
            let (reader, writer) = io::pipe().map_err(pipe_error)?;
            let writer_err = writer.try_clone().map_err(pipe_error)?;
            command.stdout(writer).stderr(writer_err);
            merged_reader = Some(reader);
        }
    }

    let table = &ctx.agent.execs;
    let mut entries = table.entries();
    if entries.values().map(VecDeque::len).sum::<usize>() >= MAX_TRACKED {
        return Err(QgaError::generic(
            "too many guest-exec processes are tracked; collect finished ones with guest-exec-status",
        ));
    }
    let child = command.spawn().map_err(|e| {
        QgaError::generic(format!(
            "Failed to execute child process \u{201c}{path}\u{201d} ({})",
            sys::strerror(&e)
        ))
    })?;
    // Drop our copies of the merged pipe's write end now that the child has its own.
    drop(command);
    let pid = i64::from(child.id());
    // Arguments and environment routinely carry secrets; the journal gets
    // only what identifies the call.
    crate::info!(
        "guest-exec called: \"{path}\" (pid {pid}, {} arguments)",
        argv.len()
    );

    let slot = match start_supervision(child, input, capture, merged_reader, table) {
        Ok(slot) => slot,
        Err((e, mut child)) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(QgaError::os("cannot start the exec supervisor", &e));
        }
    };
    entries.entry(pid).or_default().push_back(slot);
    Ok(json!({ "pid": pid }))
}

/// Start the drain and supervisor threads. On error nothing is left running
/// and the child is still the caller's to kill and reap.
fn start_supervision(
    mut child: Child,
    input: Option<Vec<u8>>,
    capture: Capture,
    merged_reader: Option<io::PipeReader>,
    table: &ExecTable,
) -> Result<Arc<Slot>, (io::Error, Child)> {
    let stdin = child.stdin.take();
    let budget = &table.budget;
    let drains = (|| {
        let out = match capture {
            Capture::Merged => merged_reader
                .map(|r| spawn_drain(r, budget.clone()))
                .transpose()?,
            _ => child
                .stdout
                .take()
                .map(|r| spawn_drain(r, budget.clone()))
                .transpose()?,
        };
        match child.stderr.take().map(|r| spawn_drain(r, budget.clone())) {
            Some(Ok(err)) => Ok((out, Some(err))),
            Some(Err(e)) => {
                out.into_iter().for_each(Drain::abandon);
                Err(e)
            }
            None => Ok((out, None)),
        }
    })();
    let (out, err) = match drains {
        Ok(drains) => drains,
        Err(e) => return Err((e, child)),
    };
    let slot = Arc::new(Mutex::new(None));
    // The child moves to the supervisor only once it runs, so a failed spawn
    // leaves it with the caller.
    let (child_tx, child_rx) = mpsc::channel::<Child>();
    let (out_keep, err_keep) = (
        out.as_ref().map(|d| d.shared.clone()),
        err.as_ref().map(|d| d.shared.clone()),
    );
    let supervised = slot.clone();
    let spawned = std::thread::Builder::new()
        .name("exec-supervisor".into())
        .spawn(move || {
            if let Ok(child) = child_rx.recv() {
                supervise(child, stdin, input, out, err, supervised);
            }
        });
    if let Err(e) = spawned {
        for shared in [out_keep, err_keep].into_iter().flatten() {
            shared.lock().unwrap_or_else(|p| p.into_inner()).closed = true;
        }
        return Err((e, child));
    }
    // The supervisor thread is alive and waiting; hand the child over.
    let _ = child_tx.send(child);
    Ok(slot)
}

fn supervise(
    mut child: Child,
    stdin: Option<std::process::ChildStdin>,
    input: Option<Vec<u8>>,
    out: Option<Drain>,
    err: Option<Drain>,
    slot: Arc<Slot>,
) {
    if let (Some(mut stdin), Some(input)) = (stdin, input) {
        // A child that never reads stdin must not keep us from reaping it.
        // Without a thread the child simply sees end of input.
        let _ = std::thread::Builder::new()
            .name("exec-stdin".into())
            .spawn(move || {
                let _ = stdin.write_all(&input);
            });
    }
    let status = child.wait();
    let deadline = Instant::now() + PIPE_GRACE;
    let out = out.map(|d| d.collect(deadline));
    let err = err.map(|d| d.collect(deadline));
    *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(Finished { status, out, err });
}

pub fn exec_status(ctx: &mut Ctx<'_>, mut args: Args) -> Reply {
    let pid = args.int("pid")?;
    args.finish()?;
    let done = match ctx.agent.execs.take_finished(pid) {
        None => return Err(QgaError::generic(format!("PID {pid} does not exist"))),
        Some(None) => return Ok(json!({ "exited": false })),
        Some(Some(done)) => done,
    };

    let mut reply = Map::new();
    reply.insert("exited".into(), json!(true));
    match &done.status {
        Ok(status) => {
            if let Some(code) = status.code() {
                reply.insert("exitcode".into(), json!(code));
            }
            #[cfg(target_os = "linux")]
            if let Some(signal) = status.signal() {
                reply.insert("signal".into(), json!(signal));
            }
        }
        Err(e) => crate::warning!("guest-exec: waiting for pid {pid} failed: {e}"),
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    if let Some(out) = done.out.as_ref().filter(|c| !c.data.is_empty()) {
        reply.insert("out-data".into(), json!(b64.encode(&out.data)));
    }
    if let Some(err) = done.err.as_ref().filter(|c| !c.data.is_empty()) {
        reply.insert("err-data".into(), json!(b64.encode(&err.data)));
    }
    for (key, stream) in [("out-truncated", &done.out), ("err-truncated", &done.err)] {
        if let Some(c) = stream
            .as_ref()
            .filter(|c| !c.data.is_empty() || c.truncated)
        {
            reply.insert(key.into(), json!(c.truncated));
        }
    }
    Ok(Value::Object(reply))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::config::Config;
    use std::time::{Duration, Instant};

    fn call(agent: &Agent, f: fn(&mut Ctx<'_>, Args) -> Reply, args: Value) -> Reply {
        let mut ctx = Ctx::new(agent);
        let Value::Object(map) = args else { panic!() };
        f(&mut ctx, Args::new(map))
    }

    fn wait(agent: &Agent, pid: &Value) -> Value {
        let started = Instant::now();
        loop {
            let status = call(agent, exec_status, json!({ "pid": pid })).unwrap();
            if status["exited"] == json!(true) {
                return status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "child never exited"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn agent() -> (Agent, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Agent::new(Config::default(), dir.path().to_path_buf()), dir)
    }

    #[test]
    fn separated_capture_with_stdin_and_exit_code() {
        let (agent, _dir) = agent();
        let reply = call(
            &agent,
            exec,
            json!({
                "path": "/bin/sh",
                "arg": ["-c", "cat; echo err >&2; exit 3"],
                "input-data": "aGk=",
                "capture-output": true,
            }),
        )
        .unwrap();
        let status = wait(&agent, &reply["pid"]);
        assert_eq!(
            status,
            json!({
                "exited": true,
                "exitcode": 3,
                "out-data": "aGk=",
                "err-data": "ZXJyCg==",
                "out-truncated": false,
                "err-truncated": false,
            })
        );
        // Reported once, then forgotten.
        assert!(call(&agent, exec_status, json!({ "pid": reply["pid"] })).is_err());
    }

    #[test]
    fn merged_capture_and_signal() {
        let (agent, _dir) = agent();
        let reply = call(
            &agent,
            exec,
            json!({
                "path": "sh",
                "arg": ["-c", "echo a; echo b >&2; kill -9 $$"],
                "capture-output": "merged",
            }),
        )
        .unwrap();
        let status = wait(&agent, &reply["pid"]);
        assert_eq!(status["signal"], json!(9));
        assert_eq!(status["out-data"], json!("YQpiCg=="));
        assert!(status.get("err-data").is_none());
    }

    #[test]
    fn env_replaces_the_environment() {
        let (agent, _dir) = agent();
        let reply = call(
            &agent,
            exec,
            json!({
                "path": "/bin/sh",
                "arg": ["-c", "printf %s \"$ONLY\"; [ -z \"$HOME\" ]"],
                "env": ["ONLY=yes"],
                "capture-output": "stdout",
            }),
        )
        .unwrap();
        let status = wait(&agent, &reply["pid"]);
        assert_eq!(status["exitcode"], json!(0));
        assert_eq!(status["out-data"], json!("eWVz"));
    }

    #[test]
    fn spawn_failure_and_unknown_pid() {
        let (agent, _dir) = agent();
        let err = call(&agent, exec, json!({"path": "/no/such/binary"})).unwrap_err();
        assert_eq!(
            err.desc,
            "Failed to execute child process \u{201c}/no/such/binary\u{201d} (No such file or directory)"
        );
        let err = call(&agent, exec_status, json!({"pid": 999_999_999})).unwrap_err();
        assert_eq!(err.desc, "PID 999999999 does not exist");
        let err = call(
            &agent,
            exec,
            json!({"path": "/bin/true", "capture-output": "loud"}),
        )
        .unwrap_err();
        assert_eq!(
            err.desc,
            "Parameter 'capture-output' does not accept value 'loud'"
        );
    }

    #[test]
    fn arguments_and_environment_stay_out_of_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let sink = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        sink.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        crate::log::capture_to(&path);
        let (agent, _dir) = agent();
        let reply = call(
            &agent,
            exec,
            json!({
                "path": "/bin/sh",
                "arg": ["-c", "exit 0", "hunter2-argument"],
                "env": ["API_TOKEN=hunter2-env"],
            }),
        )
        .unwrap();
        wait(&agent, &reply["pid"]);
        let marker = format!("(pid {}, ", reply["pid"]);
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        sink.set_nonblocking(true).unwrap();
        while let Ok(n) = sink.recv(&mut buf) {
            seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        let line = seen
            .iter()
            .find(|l| l.contains(&marker))
            .unwrap_or_else(|| panic!("no exec log line in {seen:?}"));
        assert!(
            line.contains("\"/bin/sh\"") && line.contains("3 arguments"),
            "{line}"
        );
        assert!(seen.iter().all(|l| !l.contains("hunter2")), "{seen:?}");
    }

    #[test]
    fn a_daemon_holding_the_pipes_does_not_delay_the_exit_report() {
        let (agent, _dir) = agent();
        let reply = call(
            &agent,
            exec,
            json!({
                "path": "/bin/sh",
                "arg": ["-c", "echo started; sleep 6 & exit 0"],
                "capture-output": "separated",
            }),
        )
        .unwrap();
        let begun = Instant::now();
        let status = wait(&agent, &reply["pid"]);
        assert!(
            begun.elapsed() < Duration::from_secs(5),
            "waited for the daemon"
        );
        assert_eq!(status["exitcode"], json!(0));
        assert_eq!(status["out-data"], json!("c3RhcnRlZAo="));
    }

    fn finished(budget: &Arc<Budget>, text: &str) -> Finished {
        let mut out = Captured::new(budget.clone());
        out.data = text.as_bytes().to_vec();
        Finished {
            status: Ok(ExitStatus::from_raw(0)),
            out: Some(out),
            err: None,
        }
    }

    #[test]
    fn a_recycled_pid_does_not_replace_an_unreported_entry() {
        let table = ExecTable::default();
        for text in ["first", "second"] {
            let slot = Arc::new(Mutex::new(Some(finished(&table.budget, text))));
            table.entries().entry(42).or_default().push_back(slot);
        }
        let report = |t: &ExecTable| {
            let done = t.take_finished(42).unwrap().unwrap();
            String::from_utf8(done.out.as_ref().unwrap().data.clone()).unwrap()
        };
        assert_eq!(report(&table), "first");
        assert_eq!(report(&table), "second");
        assert!(table.take_finished(42).is_none());
    }

    #[test]
    fn retained_output_is_capped_across_entries() {
        let (mut agent, _dir) = agent();
        agent.execs = ExecTable::with_output_cap(150);
        let run = |agent: &Agent| {
            call(
                agent,
                exec,
                json!({
                    "path": "/bin/sh",
                    "arg": ["-c", "head -c 100 /dev/zero"],
                    "capture-output": "stdout",
                }),
            )
            .unwrap()["pid"]
                .clone()
        };
        let (first, second) = (run(&agent), run(&agent));
        // Neither is collected until both are done, so both hold their output.
        let started = Instant::now();
        while agent
            .execs
            .entries()
            .values()
            .flatten()
            .any(|s| s.lock().unwrap().is_none())
        {
            assert!(started.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(20));
        }
        let a = call(&agent, exec_status, json!({ "pid": first })).unwrap();
        let b = call(&agent, exec_status, json!({ "pid": second })).unwrap();
        let retained = |v: &Value| {
            base64::engine::general_purpose::STANDARD
                .decode(v["out-data"].as_str().unwrap_or(""))
                .unwrap()
                .len()
        };
        assert_eq!(retained(&a) + retained(&b), 150);
        assert_eq!(a["out-truncated"], json!(retained(&a) < 100));
        assert_eq!(b["out-truncated"], json!(retained(&b) < 100));
        assert!(a["out-truncated"] == json!(true) || b["out-truncated"] == json!(true));
        assert_eq!(agent.execs.budget.used.load(Ordering::SeqCst), 0);
    }
}
