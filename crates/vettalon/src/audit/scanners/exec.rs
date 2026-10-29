//! Shared subprocess execution for OSS scanners.
//!
//! Every scanner is spawned the same way: bounded wall-clock timeout, bounded
//! stdout capture, and a small stderr tail for diagnostics. stdout is always
//! returned (even on a non-zero exit) because several scanners exit non-zero
//! *by design* when they find something. The caller applies each scanner's
//! exit-code and JSON contract together, retaining partial findings while
//! recording errors; parseable or empty output alone never proves success.

use std::path::Path;
#[cfg(not(windows))]
use std::process::Stdio;
use std::time::Duration;
#[cfg(not(windows))]
use std::time::Instant;

#[cfg(not(windows))]
use tokio::io::AsyncReadExt;

#[cfg(windows)]
#[path = "exec_windows.rs"]
mod windows;

/// Default wall-clock budget per scanner invocation (task spec: "timeout 5 分鐘").
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Default stdout capture cap (task spec: "輸出上限 16MB").
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// stderr is only kept for diagnostics on failure — a small tail is plenty.
const STDERR_TAIL_BYTES: usize = 64 * 1024;

/// Ambient Git variables must never redirect a scanner from its validated
/// repository root. The local repository config is still available, but
/// system/global configuration and caller-supplied path overrides are not.
pub(super) const GIT_ENV_REMOVE: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_INDEX_FILE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_SHALLOW_FILE",
];

#[derive(Debug, Clone, Copy)]
pub struct RunLimits {
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl Default for RunLimits {
    fn default() -> Self {
        RunLimits {
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub stdout: String,
    /// `true` when capture exceeded `max_output_bytes`. The cap bounds saved
    /// bytes; subprocess lifetime is governed separately by the wall timeout
    /// and owned-process cleanup. Reaching the cap does not prove exit.
    pub stdout_truncated: bool,
    pub stderr_tail: String,
    pub exit_code: Option<i32>,
    pub duration: Duration,
    pub timed_out: bool,
    /// Set when the process could not even be spawned (binary vanished
    /// between `which_cli` detection and spawn, permission error, ...).
    pub spawn_error: Option<String>,
    /// Failure to terminate/reap owned processes, independent of capture/exit.
    /// Completed stdout remains available so callers retain partial candidates.
    pub cleanup_error: Option<String>,
}

impl RunOutcome {
    fn spawn_failed(err: String, duration: Duration) -> Self {
        RunOutcome {
            stdout: String::new(),
            stdout_truncated: false,
            stderr_tail: String::new(),
            exit_code: None,
            duration,
            timed_out: false,
            spawn_error: Some(err),
            cleanup_error: None,
        }
    }
}

/// Time allowed to reap a signalled direct child; cleanup never waits forever.
#[cfg(not(windows))]
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);

/// Private group minted by Command::process_group(0), never the caller's group.
/// The leader stays unreaped until cleanup, reserving its PID/PGID against reuse.
/// This is process ownership cleanup, not a sandbox against setsid/group escapes.
#[cfg(unix)]
struct OwnedGroup {
    pgid: libc::pid_t,
    armed: bool,
}

#[cfg(unix)]
impl OwnedGroup {
    fn new(child: &tokio::process::Child) -> std::io::Result<Self> {
        let pgid = child
            .id()
            .and_then(|id| libc::pid_t::try_from(id).ok())
            .filter(|id| *id > 1)
            .ok_or_else(|| std::io::Error::other("spawned child has no valid process-group ID"))?;
        // SAFETY: getpgrp has no arguments and only reads this process's group.
        if pgid == unsafe { libc::getpgrp() } {
            return Err(std::io::Error::other(
                "refusing to own the caller's process group",
            ));
        }
        Ok(Self { pgid, armed: true })
    }

    fn cleanup(&mut self) -> std::io::Result<()> {
        self.cleanup_with(child_exited_unreaped, signal_owned_group)
    }

    fn cleanup_with(
        &mut self,
        mut probe: impl FnMut(libc::pid_t) -> std::io::Result<bool>,
        signal: impl FnOnce(libc::pid_t) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        // Disarm before any caller may reap the leader. A failed ownership
        // check (including ECHILD) must never signal a potentially reused ID.
        self.armed = false;
        let mut last_interruption = None;
        for _ in 0..3 {
            match probe(self.pgid) {
                Ok(_) => return signal(self.pgid),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    last_interruption = Some(error);
                }
                Err(error) => {
                    return Err(std::io::Error::other(format!(
                        "cannot confirm unreaped child ownership; no group signal sent: {error}"
                    )));
                }
            }
        }
        Err(std::io::Error::other(format!(
            "ownership check interrupted three times; no group signal sent: {}",
            last_interruption.unwrap_or_else(|| std::io::Error::other("interrupted"))
        )))
    }
}

#[cfg(unix)]
fn signal_owned_group(pgid: libc::pid_t) -> std::io::Result<()> {
    // SAFETY: the caller just confirmed the unreaped child in its private
    // group. Only this owner waits for that child; negative PGID cannot select
    // the parent or an arbitrary process. No external SIGCHLD reaper is used.
    if unsafe { libc::kill(-pgid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    if error.raw_os_error() == Some(libc::EPERM) && !darwin_group_has_live_members(pgid)? {
        // XNU skips zombies in killpg1 and may return EPERM for an otherwise
        // empty group containing only the still-waitable zombie leader.
        return Ok(());
    }
    Err(error)
}

#[cfg(target_os = "macos")]
fn darwin_group_has_live_members(pgid: libc::pid_t) -> std::io::Result<bool> {
    // proc_pidinfo may return ESRCH for a zombie even while proc_listpids
    // includes it. WNOWAIT is the authoritative exit/ownership observation.
    if !child_exited_unreaped(pgid)? {
        return Err(std::io::Error::other(
            "permission denied while owned group leader is still live",
        ));
    }
    // Bounded inspection only, never a per-PID kill. A full/failed/short
    // response is not evidence that the group is empty.
    const MAX_MEMBERS: usize = 4096;
    const PROC_PGRP_ONLY: u32 = 2; // macOS SDK sys/proc_info.h
    let mut pids = [0 as libc::pid_t; MAX_MEMBERS];
    let bytes = std::mem::size_of_val(&pids);
    // SAFETY: the buffer has exactly bytes writable bytes and pgid is positive.
    let used = unsafe {
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            pgid as u32,
            pids.as_mut_ptr().cast(),
            bytes as i32,
        )
    };
    if used < 0
        || used as usize >= bytes
        || !(used as usize).is_multiple_of(std::mem::size_of::<libc::pid_t>())
    {
        return Err(std::io::Error::other(
            "could not enumerate a bounded owned process group",
        ));
    }
    if used == 0 {
        // The unreaped leader should still be visible. Zero may be an API
        // failure, so it cannot justify ignoring the original EPERM.
        return Err(std::io::Error::other(
            "owned process group enumeration returned no evidence",
        ));
    }
    let mut saw_zombie_leader = false;
    for pid in pids
        .into_iter()
        .take(used as usize / std::mem::size_of::<libc::pid_t>())
    {
        if pid <= 0 {
            continue;
        }
        if pid == pgid {
            saw_zombie_leader = true;
            continue;
        }
        // SAFETY: this C output struct contains integers and fixed arrays only.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info);
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size as i32,
            )
        };
        if got != size as i32 {
            if got <= 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(std::io::Error::other(format!(
                    "owned group member inspection failed: {error}"
                )));
            }
            return Err(std::io::Error::other(
                "owned group member inspection returned a short record",
            ));
        }
        if info.pbi_pid != pid as u32 {
            return Err(std::io::Error::other(
                "owned group member identity changed during inspection",
            ));
        }
        if info.pbi_pgid == pgid as u32 {
            if info.pbi_status != libc::SZOMB {
                return Ok(true);
            }
            if pid == pgid {
                saw_zombie_leader = true;
            }
        }
    }
    if !saw_zombie_leader {
        return Err(std::io::Error::other(
            "owned group inspection did not confirm its unreaped zombie leader",
        ));
    }
    Ok(false)
}

#[cfg(unix)]
impl Drop for OwnedGroup {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            // Cancellation has no remaining receiver for a RunOutcome.
            // Logging is best effort and must not panic from a Drop path.
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "[vettalon] scanner group cleanup failed: {error}"
            );
        }
    }
}

#[cfg(unix)]
fn child_exited_unreaped(pid: libc::pid_t) -> std::io::Result<bool> {
    // SAFETY: a zeroed siginfo_t is valid storage for waitid's output. It
    // remains local and initialized; no union field is read. WNOWAIT keeps
    // the child waitable, so group cleanup precedes all reaping/ID reuse.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == 0 {
        return Ok(info.si_signo != 0);
    }
    Err(std::io::Error::last_os_error())
}

#[cfg(unix)]
async fn wait_unreaped(pid: libc::pid_t) -> std::io::Result<()> {
    loop {
        match child_exited_unreaped(pid) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Spawn `program args...` in `cwd`, capped by `limits`. Never panics — every
/// failure mode (spawn error, timeout, truncated output) is represented in
/// [`RunOutcome`] instead of an `Err`, since a scanner being unavailable or
/// misbehaving is an expected, reportable outcome for `secaudit`, not an
/// infra failure of the command itself.
pub async fn run_capped(
    program: &str,
    args: &[&str],
    cwd: &Path,
    limits: &RunLimits,
) -> RunOutcome {
    #[cfg(windows)]
    {
        windows::run_capped(program, args, cwd, limits).await
    }
    #[cfg(not(windows))]
    {
        run_capped_direct(program, args, cwd, limits).await
    }
}

#[cfg(not(windows))]
async fn run_capped_direct(
    program: &str,
    args: &[&str],
    cwd: &Path,
    limits: &RunLimits,
) -> RunOutcome {
    let start = Instant::now();
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Unix cleanup must verify ownership before signalling. In particular,
        // an external reap/ECHILD must not trigger Tokio's numeric-PID kill.
        .kill_on_drop(cfg!(not(unix)));
    cmd.env("PATH", crate::util::trusted_path_for_scan(cwd));
    for name in GIT_ENV_REMOVE {
        cmd.env_remove(name);
    }
    for index in 0..64 {
        cmd.env_remove(format!("GIT_CONFIG_KEY_{index}"));
        cmd.env_remove(format!("GIT_CONFIG_VALUE_{index}"));
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1");

    #[cfg(unix)]
    cmd.process_group(0);
    // Non-Unix retains the existing direct-child path. Tree enforcement there
    // is explicitly pending a Job Object implementation and live acceptance.
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return RunOutcome::spawn_failed(e.to_string(), start.elapsed()),
    };

    // Declared after child, so cancellation/early returns drop the group guard
    // first. The capture future borrows child and never owns/reaps it on drop.
    #[cfg(unix)]
    let mut group = match OwnedGroup::new(&child) {
        Ok(group) => group,
        Err(error) => return RunOutcome::spawn_failed(error.to_string(), start.elapsed()),
    };
    let mut stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            return RunOutcome::spawn_failed(
                "child had no stdout pipe".to_string(),
                start.elapsed(),
            );
        }
    };
    let mut stderr = match child.stderr.take() {
        Some(s) => s,
        None => {
            return RunOutcome::spawn_failed(
                "child had no stderr pipe".to_string(),
                start.elapsed(),
            );
        }
    };
    let max = limits.max_output_bytes;

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    // Drain both pipes concurrently. Borrowed buffers preserve captured bytes
    // even when the future is cancelled by the wall-clock timeout.
    let capture = async {
        let stdout_fut = async {
            let _ = (&mut stdout)
                .take((max as u64).saturating_add(1))
                .read_to_end(&mut stdout_buf)
                .await;
        };
        let stderr_fut = async {
            let _ = (&mut stderr)
                .take(STDERR_TAIL_BYTES as u64)
                .read_to_end(&mut stderr_buf)
                .await;
        };
        tokio::join!(stdout_fut, stderr_fut);
        #[cfg(unix)]
        {
            wait_unreaped(group.pgid).await?;
            Ok::<Option<std::process::ExitStatus>, std::io::Error>(None)
        }
        #[cfg(not(unix))]
        {
            child.wait().await.map(Some)
        }
    };
    let captured = tokio::time::timeout(limits.timeout, capture).await;
    let timed_out = captured.is_err();
    // Pipes must close before cleanup/reaping. Child processes may have kept
    // their inherited descriptors open after the leader finished.
    drop(stdout);
    drop(stderr);
    #[cfg(unix)]
    let mut cleanup_error = group
        .cleanup()
        .err()
        .map(|e| format!("process-group cleanup failed: {e}"));
    #[cfg(not(unix))]
    let mut cleanup_error = None;

    let captured_status = match captured {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            cleanup_error = Some(format!(
                "could not observe owned child exit: {error}{}",
                cleanup_error
                    .as_ref()
                    .map(|e| format!("; {e}"))
                    .unwrap_or_default()
            ));
            None
        }
        Err(_) => None,
    };
    // Unix: cleanup happened with a still-waitable leader. Non-Unix: this only
    // kills the direct child; it does not claim descendant-tree enforcement.
    #[cfg(not(unix))]
    if timed_out || cleanup_error.is_some() {
        let _ = child.start_kill();
    }
    let status = match captured_status {
        Some(status) => Some(status),
        None => match tokio::time::timeout(CLEANUP_TIMEOUT, child.wait()).await {
            Ok(Ok(status)) => Some(status),
            other => {
                let error =
                    format!("owned child reap failed or exceeded {CLEANUP_TIMEOUT:?}: {other:?}");
                cleanup_error = Some(match cleanup_error {
                    Some(prior) => format!("{prior}; {error}"),
                    None => error,
                });
                None
            }
        },
    };
    let stdout_truncated = stdout_buf.len() > max;
    stdout_buf.truncate(max);
    RunOutcome {
        stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
        stdout_truncated,
        stderr_tail: String::from_utf8_lossy(&stderr_buf).into_owned(),
        exit_code: status.and_then(|s| s.code()),
        duration: start.elapsed(),
        timed_out,
        spawn_error: None,
        cleanup_error,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    struct FixtureCleanup {
        pid: u32,
        release: std::path::PathBuf,
        armed: bool,
    }

    impl Drop for FixtureCleanup {
        fn drop(&mut self) {
            if self.armed {
                let _ = std::fs::write(&self.release, b"release");
            }
        }
    }

    const FIXTURE_LOOP: &str = "(n=0; while [ -d \"$PWD\" ] && [ ! -e release ] && [ \"$n\" -lt 240 ]; do sleep 0.05; n=$((n+1)); done)";

    fn fixture_child(dir: &Path) -> FixtureCleanup {
        let path = dir.join("child.pid");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(raw) = std::fs::read_to_string(&path)
                && let Ok(pid) = raw.trim().parse::<u32>()
            {
                return FixtureCleanup {
                    pid,
                    release: dir.join("release"),
                    armed: true,
                };
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out after 5 seconds waiting for a parseable fixture PID in {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    async fn assert_not_live(child: &mut FixtureCleanup) {
        for _ in 0..40 {
            let mut ps = tokio::process::Command::new("/bin/ps");
            ps.args(["-o", "stat=", "-p", &child.pid.to_string()])
                .kill_on_drop(true);
            let status = tokio::time::timeout(Duration::from_secs(1), ps.output())
                .await
                .expect("bounded ps inspection timed out")
                .unwrap();
            let state = String::from_utf8_lossy(&status.stdout);
            // A zombie cannot execute or retain working memory. Some container
            // PID 1 processes defer orphan reaping, so report that boundary.
            if !status.status.success() || state.trim().is_empty() || state.trim().starts_with('Z')
            {
                child.armed = false;
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("owned fixture descendant {} is still live", child.pid);
    }

    #[tokio::test]
    async fn timeout_kills_owned_descendant_not_only_the_leader() {
        let dir = tempfile::tempdir().unwrap();
        let script = format!("{FIXTURE_LOOP} & printf '%s' \"$!\" > child.pid; wait");
        let result = run_capped(
            "/bin/sh",
            &["-c", &script],
            dir.path(),
            &RunLimits {
                timeout: Duration::from_millis(300),
                max_output_bytes: 1024,
            },
        )
        .await;
        let mut child = fixture_child(dir.path());
        assert!(result.timed_out);
        assert!(result.cleanup_error.is_none(), "{result:?}");
        assert_not_live(&mut child).await;
    }

    #[tokio::test]
    async fn cancellation_kills_owned_descendant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_owned();
        let handle = tokio::spawn(async move {
            let script = format!("{FIXTURE_LOOP} & printf '%s' \"$!\" > child.pid; wait");
            run_capped("/bin/sh", &["-c", &script], &path, &RunLimits::default()).await
        });
        for _ in 0..40 {
            if dir.path().join("child.pid").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        // Cleanup is installed before any assertion can panic.
        let mut child = fixture_child(dir.path());
        handle.abort();
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert_not_live(&mut child).await;
    }

    #[tokio::test]
    async fn normal_completion_cleans_owned_background_descendant() {
        let dir = tempfile::tempdir().unwrap();
        let script = format!(
            "{FIXTURE_LOOP} </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > child.pid; printf done"
        );
        let result = run_capped(
            "/bin/sh",
            &["-c", &script],
            dir.path(),
            &RunLimits {
                timeout: Duration::from_secs(2),
                max_output_bytes: 1024,
            },
        )
        .await;
        let mut child = fixture_child(dir.path());
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, "done");
        assert!(result.cleanup_error.is_none(), "{result:?}");
        assert_not_live(&mut child).await;
    }

    #[tokio::test]
    async fn capped_capture_timeout_cleans_owned_descendant() {
        let dir = tempfile::tempdir().unwrap();
        let script =
            format!("{FIXTURE_LOOP} & printf '%s' \"$!\" > child.pid; printf '%050d' 0; wait");
        let result = run_capped(
            "/bin/sh",
            &["-c", &script],
            dir.path(),
            &RunLimits {
                timeout: Duration::from_millis(300),
                max_output_bytes: 10,
            },
        )
        .await;
        let mut child = fixture_child(dir.path());
        assert!(result.timed_out);
        assert_eq!(result.stdout.len(), 10);
        assert!(result.stdout_truncated);
        assert!(result.cleanup_error.is_none(), "{result:?}");
        assert_not_live(&mut child).await;
    }

    #[test]
    fn lost_wait_ownership_disarms_without_signalling_or_drop_retry() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let mut group = OwnedGroup {
            pgid: 42,
            armed: true,
        };
        let error = group
            .cleanup_with(
                |_| Err(std::io::Error::from_raw_os_error(libc::ECHILD)),
                |_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("no group signal sent"));
        assert!(!group.armed);
        assert_eq!(calls.get(), 0);
        drop(group); // Must not retry a numeric ID after ownership was lost.
    }

    #[test]
    fn interrupted_ownership_probe_is_bounded_and_never_signals_without_success() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let signals = Cell::new(0);
        let mut group = OwnedGroup {
            pgid: 42,
            armed: true,
        };
        let result = group.cleanup_with(
            |_| {
                calls.set(calls.get() + 1);
                Err(std::io::Error::from_raw_os_error(libc::EINTR))
            },
            |_| {
                signals.set(signals.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), 3);
        assert_eq!(signals.get(), 0);
        assert!(!group.armed);
    }

    #[test]
    fn signal_failure_is_reported_once_without_a_drop_retry() {
        use std::cell::Cell;
        let signals = Cell::new(0);
        let mut group = OwnedGroup {
            pgid: 42,
            armed: true,
        };
        let result = group.cleanup_with(
            |_| Ok(false),
            |_| {
                signals.set(signals.get() + 1);
                Err(std::io::Error::from_raw_os_error(libc::EPERM))
            },
        );
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert!(!group.armed);
        drop(group);
        assert_eq!(signals.get(), 1);
    }

    #[tokio::test]
    async fn owned_group_drop_cleans_descendant_on_early_return() {
        async fn early_return(path: &Path) -> FixtureCleanup {
            let script = format!("{FIXTURE_LOOP} & printf '%s' \"$!\" > child.pid; wait");
            let mut command = tokio::process::Command::new("/bin/sh");
            command
                .args(["-c", &script])
                .current_dir(path)
                .process_group(0)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(false);
            let mut child = command.spawn().unwrap();
            let _group = OwnedGroup::new(&child).unwrap();
            for _ in 0..40 {
                if std::fs::read_to_string(path.join("child.pid"))
                    .ok()
                    .and_then(|raw| raw.trim().parse::<u32>().ok())
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let fixture = fixture_child(path);
            // A missing/closed capture pipe cannot skip the ownership guard.
            drop(child.stdout.take());
            fixture
        }
        let dir = tempfile::tempdir().unwrap();
        let mut fixture = early_return(dir.path()).await;
        assert_not_live(&mut fixture).await;
    }

    #[tokio::test]
    async fn captures_stdout_and_exit_code() {
        let outcome = run_capped(
            "sh",
            &["-c", "printf hello"],
            Path::new("."),
            &RunLimits::default(),
        )
        .await;
        assert_eq!(outcome.stdout, "hello");
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out);
        assert!(outcome.spawn_error.is_none());
    }

    #[tokio::test]
    async fn nonzero_exit_still_returns_stdout() {
        // The executor retains nonzero output; each scanner adapter decides
        // validity from its specific invocation/JSON contract.
        let outcome = run_capped(
            "sh",
            &["-c", "printf data; exit 1"],
            Path::new("."),
            &RunLimits::default(),
        )
        .await;
        assert_eq!(outcome.stdout, "data");
        assert_eq!(outcome.exit_code, Some(1));
    }

    #[tokio::test]
    async fn spawn_error_for_missing_binary() {
        let outcome = run_capped(
            "vettalon-definitely-not-a-real-binary",
            &[],
            Path::new("."),
            &RunLimits::default(),
        )
        .await;
        assert!(outcome.spawn_error.is_some());
    }

    #[tokio::test]
    async fn timeout_is_reported_not_hung() {
        let limits = RunLimits {
            timeout: Duration::from_millis(50),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        };
        let outcome = run_capped("sh", &["-c", "sleep 5"], Path::new("."), &limits).await;
        assert!(outcome.timed_out);
    }

    #[tokio::test]
    async fn output_beyond_cap_is_truncated_and_flagged() {
        let limits = RunLimits {
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: 10,
        };
        let outcome = run_capped("sh", &["-c", "printf '%050d' 0"], Path::new("."), &limits).await;
        assert_eq!(outcome.stdout.len(), 10);
        assert!(outcome.stdout_truncated);
    }

    #[tokio::test]
    async fn stderr_tail_is_captured() {
        let outcome = run_capped(
            "sh",
            &["-c", "printf oops 1>&2"],
            Path::new("."),
            &RunLimits::default(),
        )
        .await;
        assert_eq!(outcome.stderr_tail, "oops");
    }
}
