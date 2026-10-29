//! Windows scanner ownership uses a suspended spawn inside a kill-on-close job.
//! Native Windows tests are required; cross compilation is not runtime evidence.

use std::io;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Instant;

use process_wrap::tokio::{ChildWrapper, CommandWrap, JobObject, KillOnDrop};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{GIT_ENV_REMOVE, RunLimits, RunOutcome};

const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Own the outer wrapper, whose Drop closes the kill-on-close Job Object.
/// No consuming unwrap is allowed: process-wrap intentionally leaks the job
/// handle in into_inner(), disabling the cleanup contract needed here.
struct OwnedJob {
    child: Box<dyn ChildWrapper>,
    cleanup_requested: bool,
}

impl OwnedJob {
    fn request_cleanup(&mut self) -> io::Result<()> {
        self.cleanup_requested = true;
        // Nonblocking TerminateJobObject; never library kill().await/wait().
        self.child.start_kill()
    }
}

impl Drop for OwnedJob {
    fn drop(&mut self) {
        if !self.cleanup_requested {
            if let Err(error) = self.child.start_kill() {
                // Cancellation has no remaining RunOutcome receiver. The
                // wrapper still closes its kill-on-close job after this Drop.
                use std::io::Write;
                let _ = writeln!(
                    std::io::stderr(),
                    "[vettalon] scanner job cleanup failed: {error}"
                );
            }
        }
    }
}

fn spawn_job(program: &str, args: &[&str], cwd: &Path) -> io::Result<OwnedJob> {
    let mut command = CommandWrap::with_new(program, |command| {
        command
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PATH", crate::util::trusted_path_for_scan(cwd))
            .env("NoDefaultCurrentDirectoryInExePath", "1");
        for name in GIT_ENV_REMOVE {
            command.env_remove(name);
        }
        for index in 0..64 {
            command.env_remove(format!("GIT_CONFIG_KEY_{index}"));
            command.env_remove(format!("GIT_CONFIG_VALUE_{index}"));
        }
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "NUL")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1");
    });
    // KillOnDrop must be registered as a wrapper: JobObject queries it before
    // enabling JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. A raw Command flag is not enough.
    command.wrap(KillOnDrop).wrap(JobObject);
    Ok(OwnedJob {
        child: command.spawn()?,
        cleanup_requested: false,
    })
}

async fn poll_leader(child: &mut dyn ChildWrapper) -> io::Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Keep at most one byte beyond the cap, so exact-sized output remains complete.
/// The caller retains the buffer even when cancellation drops this future.
async fn capture_stdout(
    pipe: &mut (impl AsyncRead + Unpin),
    bytes: &mut Vec<u8>,
    max: usize,
) -> io::Result<bool> {
    let cap = max.saturating_add(1);
    let mut chunk = [0_u8; 8192];
    while bytes.len() < cap {
        let take = chunk.len().min(cap - bytes.len());
        let count = pipe.read(&mut chunk[..take]).await?;
        if count == 0 {
            return Ok(false);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes.len() > max)
}

/// Drain concurrently even after filling the bounded diagnostic tail; otherwise
/// a scanner writing stderr can block before it emits its stdout JSON.
async fn capture_stderr(
    pipe: &mut (impl AsyncRead + Unpin),
    bytes: &mut Vec<u8>,
) -> io::Result<()> {
    let mut chunk = [0_u8; 8192];
    loop {
        let count = pipe.read(&mut chunk).await?;
        if count == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > super::STDERR_TAIL_BYTES {
            bytes.drain(..bytes.len() - super::STDERR_TAIL_BYTES);
        }
    }
}

enum Stop {
    Leader(io::Result<ExitStatus>),
    Timeout,
    OutputCap,
    CaptureError(&'static str, io::Error),
}

pub(super) async fn run_capped(
    program: &str,
    args: &[&str],
    cwd: &Path,
    limits: &RunLimits,
) -> RunOutcome {
    let start = Instant::now();
    let job = match spawn_job(program, args, cwd) {
        Ok(job) => job,
        Err(error) => return RunOutcome::spawn_failed(error.to_string(), start.elapsed()),
    };
    run_spawned(job, start, limits).await
}

async fn run_spawned(mut job: OwnedJob, start: Instant, limits: &RunLimits) -> RunOutcome {
    let Some(deadline) = tokio::time::Instant::from_std(start).checked_add(limits.timeout) else {
        return reject_spawned(job, "scanner timeout exceeds the clock range", start).await;
    };
    let Some(mut stdout) = job.child.stdout().take() else {
        return reject_spawned(job, "child had no stdout pipe", start).await;
    };
    let Some(mut stderr) = job.child.stderr().take() else {
        return reject_spawned(job, "child had no stderr pipe", start).await;
    };
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_done = false;
    let mut stderr_done = false;
    let stop = {
        let stdout_capture =
            capture_stdout(&mut stdout, &mut stdout_bytes, limits.max_output_bytes);
        let stderr_capture = capture_stderr(&mut stderr, &mut stderr_bytes);
        let leader = poll_leader(job.child.as_mut());
        tokio::pin!(stdout_capture, stderr_capture, leader);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break Stop::Timeout,
                status = &mut leader => break Stop::Leader(status),
                result = &mut stdout_capture, if !stdout_done => {
                    stdout_done = true;
                    match result {
                        Ok(true) => break Stop::OutputCap,
                        Ok(false) => {},
                        Err(error) => break Stop::CaptureError("stdout", error),
                    }
                },
                result = &mut stderr_capture, if !stderr_done => {
                    stderr_done = true;
                    if let Err(error) = result {
                        break Stop::CaptureError("stderr", error);
                    }
                },
            }
        }
    };
    let timed_out = matches!(stop, Stop::Timeout);
    let mut exit_code = None;
    let mut errors = Vec::new();
    match stop {
        Stop::Leader(Ok(status)) => exit_code = status.code(),
        Stop::Leader(Err(error)) => errors.push(format!("scanner leader poll failed: {error}")),
        Stop::CaptureError(pipe, error) => {
            errors.push(format!("scanner {pipe} capture failed: {error}"))
        }
        Stop::Timeout | Stop::OutputCap => {}
    }

    // Terminate the whole job on normal leader exit too, before waiting for
    // pipe EOF: a background descendant may have inherited either pipe.
    let cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
    if let Err(error) = job.request_cleanup() {
        errors.push(format!("scanner job termination failed: {error}"));
    }
    match tokio::time::timeout_at(cleanup_deadline, poll_leader(job.child.as_mut())).await {
        Ok(Ok(status)) => {
            exit_code = exit_code.or_else(|| status.code());
        }
        Ok(Err(error)) => errors.push(format!("scanner leader cleanup failed: {error}")),
        Err(_) => errors.push("scanner leader cleanup exceeded its budget".into()),
    }
    // Closing the last job handle is a second OS-enforced cleanup path. Keep
    // both pipes local so their final bounded bytes can still be captured.
    drop(job);
    let drain = async {
        let out = async {
            if stdout_done {
                Ok(false)
            } else {
                capture_stdout(&mut stdout, &mut stdout_bytes, limits.max_output_bytes).await
            }
        };
        let err = async {
            if stderr_done {
                Ok(())
            } else {
                capture_stderr(&mut stderr, &mut stderr_bytes).await
            }
        };
        tokio::join!(out, err)
    };
    match tokio::time::timeout_at(cleanup_deadline, drain).await {
        Ok((out, err)) => {
            if let Err(error) = out {
                errors.push(format!("scanner stdout cleanup failed: {error}"));
            }
            if let Err(error) = err {
                errors.push(format!("scanner stderr cleanup failed: {error}"));
            }
        }
        Err(_) => errors.push("scanner pipe cleanup exceeded its budget".into()),
    }
    let stdout_truncated = stdout_bytes.len() > limits.max_output_bytes;
    stdout_bytes.truncate(limits.max_output_bytes);
    RunOutcome {
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stdout_truncated,
        stderr_tail: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        exit_code,
        duration: start.elapsed(),
        timed_out,
        spawn_error: None,
        cleanup_error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

async fn reject_spawned(mut job: OwnedJob, reason: &str, start: Instant) -> RunOutcome {
    let mut outcome = RunOutcome::spawn_failed(reason.into(), start.elapsed());
    let mut errors = Vec::new();
    if let Err(error) = job.request_cleanup() {
        errors.push(format!("scanner job termination failed: {error}"));
    }
    match tokio::time::timeout(CLEANUP_TIMEOUT, poll_leader(job.child.as_mut())).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => errors.push(format!("scanner leader cleanup failed: {error}")),
        Err(_) => errors.push("scanner leader cleanup exceeded its budget".into()),
    }
    drop(job);
    outcome.duration = start.elapsed();
    outcome.cleanup_error = (!errors.is_empty()).then(|| errors.join("; "));
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use std::io::Write;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn fixture_entry_selector() -> &'static str {
        // libtest selectors omit the crate name included by module_path!().
        const FULL_PATH: &str = concat!(module_path!(), "::fixture_entry");
        FULL_PATH
            .split_once("::")
            .expect("fixture has a module path")
            .1
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn TerminateProcess(handle: *mut c_void, code: u32) -> i32;
    }

    struct FixtureProcess(OwnedHandle);

    impl FixtureProcess {
        async fn assert_stopped(&self) {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                // SAFETY: the handle was opened for this test's live fixture and
                // remains owned until this guard is dropped. Zero never blocks.
                let state = unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) };
                if state == 0 {
                    return;
                }
                assert_eq!(state, 258, "owned fixture wait failed");
                assert!(
                    Instant::now() < deadline,
                    "owned descendant survived cleanup"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    impl Drop for FixtureProcess {
        fn drop(&mut self) {
            // SAFETY: cleanup targets the retained handle, never a reused PID.
            unsafe { TerminateProcess(self.0.as_raw_handle(), 1) };
        }
    }

    async fn descendant_handle(path: &Path) -> FixtureProcess {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(pid) = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                // SAFETY: the fixture waits for the release file, so this owned
                // descendant is live while its process handle is acquired.
                let handle = unsafe { OpenProcess(0x0010_0000 | 0x0001, 0, pid) };
                assert!(!handle.is_null(), "cannot open owned fixture process");
                return FixtureProcess(unsafe { OwnedHandle::from_raw_handle(handle) });
            }
            assert!(
                Instant::now() < deadline,
                "fixture did not publish its child"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn fixture_dir(mode: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("fixture-mode.txt"), mode).unwrap();
        dir
    }

    fn start_fixture(path: &Path, max_output_bytes: usize) -> tokio::task::JoinHandle<RunOutcome> {
        let path = path.to_owned();
        tokio::spawn(async move {
            run_capped(
                std::env::current_exe().unwrap().to_str().unwrap(),
                &[
                    fixture_entry_selector(),
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ],
                &path,
                &RunLimits {
                    timeout: Duration::from_secs(3),
                    max_output_bytes,
                },
            )
            .await
        })
    }

    fn release(dir: &Path) {
        std::fs::write(dir.join("release"), b"go").unwrap();
    }

    #[test]
    #[ignore = "bounded local subprocess fixture, invoked only by these tests"]
    fn fixture_entry() {
        let dir = std::env::current_dir().unwrap();
        let mode = std::fs::read_to_string(dir.join("fixture-mode.txt")).unwrap();
        if mode == "leaf" {
            std::thread::sleep(Duration::from_secs(15));
            return;
        }
        let leaf = dir.join("leaf");
        std::fs::create_dir(&leaf).unwrap();
        std::fs::write(
            leaf.join("fixture-mode.txt"),
            if mode == "grandchild" {
                "branch"
            } else {
                "leaf"
            },
        )
        .unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                fixture_entry_selector(),
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(leaf)
            .stdin(Stdio::null());
        if mode != "normal_inherit" {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        let mut child = command.spawn().unwrap();
        std::fs::write(dir.join("child.pid"), child.id().to_string()).unwrap();
        if mode == "branch" {
            let _ = child.wait();
            return;
        }
        print!("SOURCE_PARTIAL");
        std::io::stdout().flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !dir.join("release").exists() {
            assert!(Instant::now() < deadline, "fixture release deadline");
            std::thread::sleep(Duration::from_millis(5));
        }
        match mode.as_str() {
            "normal_redirect" | "normal_inherit" => print!("FIXTURE_COMPLETE"),
            "nonzero" => std::process::exit(7),
            "stderr" => {
                std::io::stderr().write_all(&vec![b'e'; 96 * 1024]).unwrap();
                print!("FIXTURE_COMPLETE");
            }
            "capped" => {
                let _ = std::io::stdout().write_all(&vec![b'x'; 96 * 1024]);
                let _ = child.wait();
            }
            "timeout" | "grandchild" => {
                let _ = child.wait();
            }
            _ => panic!("unknown local fixture mode"),
        }
    }

    #[tokio::test]
    async fn windows_timeout_retains_partial_and_stops_descendant() {
        let dir = fixture_dir("timeout");
        let task = start_fixture(dir.path(), 8192);
        let child = descendant_handle(&dir.path().join("child.pid")).await;
        release(dir.path());
        let result = task.await.unwrap();
        assert!(result.timed_out);
        assert!(result.stdout.contains("SOURCE_PARTIAL"));
        assert!(result.cleanup_error.is_none(), "{:?}", result.cleanup_error);
        child.assert_stopped().await;
    }

    #[tokio::test]
    async fn windows_cancellation_stops_owned_descendant() {
        let dir = fixture_dir("timeout");
        let task = start_fixture(dir.path(), 8192);
        let child = descendant_handle(&dir.path().join("child.pid")).await;
        task.abort();
        let _ = task.await;
        child.assert_stopped().await;
    }

    #[tokio::test]
    async fn windows_timeout_stops_owned_child_and_grandchild() {
        let dir = fixture_dir("grandchild");
        let task = start_fixture(dir.path(), 8192);
        let child = descendant_handle(&dir.path().join("child.pid")).await;
        let grandchild = descendant_handle(&dir.path().join("leaf/child.pid")).await;
        release(dir.path());
        let result = task.await.unwrap();
        assert!(result.timed_out);
        child.assert_stopped().await;
        grandchild.assert_stopped().await;
    }

    async fn normal_completion(mode: &str) {
        let dir = fixture_dir(mode);
        let task = start_fixture(dir.path(), 8192);
        let child = descendant_handle(&dir.path().join("child.pid")).await;
        release(dir.path());
        let result = task.await.unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out);
        assert!(result.stdout.contains("FIXTURE_COMPLETE"));
        assert!(result.cleanup_error.is_none(), "{:?}", result.cleanup_error);
        child.assert_stopped().await;
    }

    #[tokio::test]
    async fn windows_normal_leader_exit_cleans_redirected_descendant() {
        normal_completion("normal_redirect").await;
    }

    #[tokio::test]
    async fn windows_leader_exit_cleans_descendant_holding_stdout() {
        normal_completion("normal_inherit").await;
    }

    #[tokio::test]
    async fn windows_stderr_flood_does_not_block_stdout_or_cleanup() {
        normal_completion("stderr").await;
    }

    #[tokio::test]
    async fn windows_output_cap_stops_owned_descendant() {
        let dir = fixture_dir("capped");
        let task = start_fixture(dir.path(), 4096);
        let child = descendant_handle(&dir.path().join("child.pid")).await;
        release(dir.path());
        let result = task.await.unwrap();
        assert_eq!(result.stdout.len(), 4096);
        assert!(result.stdout_truncated);
        child.assert_stopped().await;
    }

    #[tokio::test]
    async fn windows_nonzero_exit_is_preserved_with_partial_output() {
        let dir = fixture_dir("nonzero");
        let task = start_fixture(dir.path(), 8192);
        let child = descendant_handle(&dir.path().join("child.pid")).await;
        release(dir.path());
        let result = task.await.unwrap();
        assert_eq!(result.exit_code, Some(7));
        assert!(result.stdout.contains("SOURCE_PARTIAL"));
        child.assert_stopped().await;
    }

    #[tokio::test]
    async fn windows_missing_binary_is_an_explicit_spawn_failure() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_capped(
            dir.path().join("absent.exe").to_str().unwrap(),
            &[],
            dir.path(),
            &RunLimits::default(),
        )
        .await;
        assert!(result.spawn_error.is_some());
        assert!(result.exit_code.is_none());
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn windows_stdout_exact_cap_is_complete_but_one_more_is_truncated() {
        let mut exact = &b"1234"[..];
        let mut bytes = Vec::new();
        assert!(!capture_stdout(&mut exact, &mut bytes, 4).await.unwrap());
        assert_eq!(bytes, b"1234");
        let mut excess = &b"12345"[..];
        bytes.clear();
        assert!(capture_stdout(&mut excess, &mut bytes, 4).await.unwrap());
        assert_eq!(bytes, b"12345");
    }

    #[tokio::test]
    async fn windows_stderr_keeps_bounded_tail_while_draining() {
        let mut source = vec![b'a'; super::super::STDERR_TAIL_BYTES + 11];
        source.extend_from_slice(b"END");
        let mut pipe = source.as_slice();
        let mut bytes = Vec::new();
        capture_stderr(&mut pipe, &mut bytes).await.unwrap();
        assert_eq!(bytes.len(), super::super::STDERR_TAIL_BYTES);
        assert!(bytes.ends_with(b"END"));
        assert!(pipe.is_empty());
    }

    #[derive(Debug)]
    struct FailedTermination(Box<dyn ChildWrapper>);

    impl ChildWrapper for FailedTermination {
        fn inner(&self) -> &dyn ChildWrapper {
            self.0.as_ref()
        }
        fn inner_mut(&mut self) -> &mut dyn ChildWrapper {
            self.0.as_mut()
        }
        fn into_inner(self: Box<Self>) -> Box<dyn ChildWrapper> {
            self.0
        }
        fn start_kill(&mut self) -> io::Result<()> {
            Err(io::Error::other("synthetic owned-job termination failure"))
        }
    }

    #[tokio::test]
    async fn windows_cleanup_failure_retains_partial_and_drop_still_closes_job() {
        let dir = fixture_dir("normal_redirect");
        let path = dir.path().to_owned();
        let task = tokio::spawn(async move {
            let mut command = CommandWrap::with_new(std::env::current_exe().unwrap(), |command| {
                command
                    .args([
                        fixture_entry_selector(),
                        "--exact",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .current_dir(&path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            });
            command.wrap(KillOnDrop).wrap(JobObject);
            let job = OwnedJob {
                child: Box::new(FailedTermination(command.spawn().unwrap())),
                cleanup_requested: false,
            };
            run_spawned(
                job,
                Instant::now(),
                &RunLimits {
                    timeout: Duration::from_secs(3),
                    max_output_bytes: 8192,
                },
            )
            .await
        });
        let child = descendant_handle(&dir.path().join("child.pid")).await;
        release(dir.path());
        let result = task.await.unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.contains("SOURCE_PARTIAL"));
        assert!(
            result
                .cleanup_error
                .as_deref()
                .unwrap()
                .contains("synthetic owned-job")
        );
        child.assert_stopped().await;
    }
}
