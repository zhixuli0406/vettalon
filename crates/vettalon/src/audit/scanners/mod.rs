//! OSS scanner detection + orchestration.
//!
//! For every scanner: detect via `which_cli` → not found ⇒ `EngineMissing`
//! with an honest reason (task discipline: "工具失效停工上報...絕不靜默跳過也
//! 絕不自動安裝"); found ⇒ run it (capped timeout + output, `exec.rs`) →
//! normalize its output into `Finding`s via that scanner's own module. A
//! scanner's raw stdout is untrusted DATA: a parse failure is recorded as
//! `EngineRun.parse_error`, never a panic.
//!
//! `osv-scanner` is a deliberate exception: this wave never invokes it at
//! all (see [`osv_scanner_missing`]) because it queries the network OSV
//! database. Baseline scanner policy avoids that lookup; deep model providers,
//! optional Jev ranking and third-party scanner behavior have separate network
//! boundaries. This module is not an OS egress firewall.
//!
//! Tool discovery is environment-dependent. Private executable-injection seams
//! exercise the same production dispatch with fixed, self-authored subprocess
//! stubs, without changing PATH or invoking installed third-party scanners.
//! JSON contracts also have pure fixture tests in each normalizer.

pub mod cargo_audit;
mod exec;
pub use exec::{
    RunLimits as SubprocessLimits, RunOutcome as SubprocessOutcome,
    run_capped as run_bounded_subprocess,
};
pub mod gitleaks;
pub mod semgrep;

use std::path::Path;

use exec::{RunLimits, run_capped};

use crate::audit::schema::{EngineMissing, EngineRun, Finding};

/// Run every applicable OSS scanner against `repo_root` (assumed already
/// canonicalized + validated to exist by the caller). Returns everything
/// needed to build an `AuditReport`: what ran, what didn't (+why), and every
/// normalized finding.
pub async fn run_all(repo_root: &Path) -> (Vec<EngineRun>, Vec<EngineMissing>, Vec<Finding>) {
    let mut engines_run = Vec::new();
    let mut engines_missing = Vec::new();
    let mut findings = Vec::new();

    run_semgrep(
        repo_root,
        &mut engines_run,
        &mut engines_missing,
        &mut findings,
    )
    .await;
    run_gitleaks(
        repo_root,
        &mut engines_run,
        &mut engines_missing,
        &mut findings,
    )
    .await;
    run_osv_scanner(&mut engines_missing);
    run_cargo_audit(
        repo_root,
        &mut engines_run,
        &mut engines_missing,
        &mut findings,
    )
    .await;

    (engines_run, engines_missing, findings)
}

/// Executed engines with failed or partial output cannot prove a complete scan.
pub(super) fn runs_failed(runs: &[EngineRun]) -> bool {
    runs.iter()
        .any(|run| run.parse_error.is_some() || run.timed_out)
}

/// Shared tail for scanners that stream their report as JSON on stdout
/// (semgrep, cargo-audit): classify the capped-subprocess outcome into
/// either a successful `EngineRun` (+ findings) or one with `parse_error`
/// set. Extracted as a free function (not a closure inline in each caller)
/// specifically so its branching is unit-testable without spawning a real
/// process.
fn record_cleanup_error(runs: &mut [EngineRun], error: Option<String>) {
    if let (Some(run), Some(error)) = (runs.last_mut(), error) {
        run.parse_error = Some(match run.parse_error.take() {
            Some(prior) => format!("{prior}; {error}"),
            None => error,
        });
    }
}

fn record_stdout_scanner(
    engine: &str,
    outcome: exec::RunOutcome,
    parse: impl FnOnce(&str) -> Result<(Vec<Finding>, Option<String>), String>,
    engines_run: &mut Vec<EngineRun>,
    findings: &mut Vec<Finding>,
) {
    let cleanup_error = outcome.cleanup_error.clone();
    record_stdout_scanner_inner(engine, outcome, parse, engines_run, findings);
    record_cleanup_error(engines_run, cleanup_error);
}

fn record_stdout_scanner_inner(
    engine: &str,
    outcome: exec::RunOutcome,
    parse: impl FnOnce(&str) -> Result<(Vec<Finding>, Option<String>), String>,
    engines_run: &mut Vec<EngineRun>,
    findings: &mut Vec<Finding>,
) {
    if let Some(err) = outcome.spawn_error {
        engines_run.push(EngineRun {
            engine: engine.to_string(),
            findings_count: 0,
            duration_ms: outcome.duration.as_millis(),
            parse_error: Some(format!("failed to execute: {err}")),
            timed_out: false,
        });
        return;
    }
    if outcome.timed_out {
        engines_run.push(EngineRun {
            engine: engine.to_string(),
            findings_count: 0,
            duration_ms: outcome.duration.as_millis(),
            parse_error: Some(format!("timed out after {:?}", exec::DEFAULT_TIMEOUT)),
            timed_out: true,
        });
        return;
    }
    if outcome.stdout_truncated {
        // Don't attempt to parse output cut off mid-stream — truncated JSON
        // usually fails to parse anyway, but "usually" isn't good enough
        // when the failure mode would otherwise be silently-incomplete
        // findings instead of an honest, explicit report.
        engines_run.push(EngineRun {
            engine: engine.to_string(),
            findings_count: 0,
            duration_ms: outcome.duration.as_millis(),
            parse_error: Some(format!(
                "stdout truncated at the {}-byte output cap — output too large to parse reliably",
                exec::DEFAULT_MAX_OUTPUT_BYTES
            )),
            timed_out: false,
        });
        return;
    }
    match parse(&outcome.stdout) {
        Ok((parsed, diagnostic)) => {
            let count = parsed.len();
            findings.extend(parsed);
            engines_run.push(EngineRun {
                engine: engine.to_string(),
                findings_count: count,
                duration_ms: outcome.duration.as_millis(),
                parse_error: diagnostic
                    .or_else(|| {
                        let findings_exit = outcome.exit_code == Some(1)
                            && count > 0
                            && engine == cargo_audit::ENGINE_NAME;
                        (outcome.exit_code != Some(0) && !findings_exit)
                            .then(|| "scanner failed".to_string())
                    })
                    .map(|error| {
                        format!(
                            "{error} (exit_code={:?}, stderr_tail={:?})",
                            outcome.exit_code,
                            crate::util::truncate_bytes(outcome.stderr_tail.trim(), 300)
                        )
                    }),
                timed_out: false,
            });
        }
        Err(e) => {
            engines_run.push(EngineRun {
                engine: engine.to_string(),
                findings_count: 0,
                duration_ms: outcome.duration.as_millis(),
                parse_error: Some(format!(
                    "{e} (exit_code={:?}, stderr_tail={:?})",
                    outcome.exit_code,
                    crate::util::truncate_bytes(outcome.stderr_tail.trim(), 300)
                )),
                timed_out: false,
            });
        }
    }
}

async fn run_semgrep(
    repo_root: &Path,
    engines_run: &mut Vec<EngineRun>,
    engines_missing: &mut Vec<EngineMissing>,
    findings: &mut Vec<Finding>,
) {
    let bin = match crate::util::which_cli("semgrep") {
        Some(b) => b,
        None => {
            engines_missing.push(EngineMissing {
                engine: semgrep::ENGINE_NAME.to_string(),
                reason: "not installed (not found on PATH or common install locations)".to_string(),
            });
            return;
        }
    };
    run_semgrep_with_bin(repo_root, &bin, engines_run, engines_missing, findings).await;
}

async fn run_semgrep_with_bin(
    repo_root: &Path,
    bin: &str,
    engines_run: &mut Vec<EngineRun>,
    engines_missing: &mut Vec<EngineMissing>,
    findings: &mut Vec<Finding>,
) {
    let rules_file = match semgrep::TempRulesFile::create() {
        Ok(f) => f,
        Err(e) => {
            engines_missing.push(EngineMissing {
                engine: semgrep::ENGINE_NAME.to_string(),
                reason: format!("could not stage bundled offline ruleset: {e}"),
            });
            return;
        }
    };
    let rules_path = rules_file.0.to_string_lossy().to_string();
    // Local filesystem `--config` path — never triggers a network fetch
    // (unlike `--config auto` / `--config p/<pack>`; see semgrep.rs module doc).
    // `.as_str()` (not `&rules_path`) so every array element is a plain
    // `&str`, matching the string literals with no coercion involved.
    let args = semgrep::args(rules_path.as_str());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = run_capped(bin, &arg_refs, repo_root, &RunLimits::default()).await;
    record_stdout_scanner(
        semgrep::ENGINE_NAME,
        outcome,
        semgrep::parse_with_diagnostics,
        engines_run,
        findings,
    );
    // `rules_file` drops here, cleaning up the temp ruleset file.
}

async fn run_gitleaks(
    repo_root: &Path,
    engines_run: &mut Vec<EngineRun>,
    engines_missing: &mut Vec<EngineMissing>,
    findings: &mut Vec<Finding>,
) {
    let bin = match crate::util::which_cli("gitleaks") {
        Some(b) => b,
        None => {
            engines_missing.push(EngineMissing {
                engine: gitleaks::ENGINE_NAME.to_string(),
                reason: "not installed (not found on PATH or common install locations)".to_string(),
            });
            return;
        }
    };
    run_gitleaks_with_bin(repo_root, &bin, engines_run, findings).await;
}

async fn run_gitleaks_with_bin(
    repo_root: &Path,
    bin: &str,
    engines_run: &mut Vec<EngineRun>,
    findings: &mut Vec<Finding>,
) {
    // gitleaks' stdout-vs-report-file default behavior is not verified in
    // this offline sandbox (no gitleaks binary / no network to check docs
    // against) — using the well-documented, stable `--report-path` flag to
    // a known temp location sidesteps the ambiguity entirely rather than
    // guessing at stdout parsing.
    let report_path =
        std::env::temp_dir().join(format!("vettalon-gitleaks-{}.json", uuid::Uuid::new_v4()));
    let report_path_str = report_path.to_string_lossy().to_string();
    // Mode selection (live-fired against the real 8.30.1 binary, 2026-09-01):
    // `detect` walks *git history* — on a plain directory it logs "0 commits
    // scanned, ~0 bytes", writes an empty report, and exits 0, i.e. a
    // permanent fake-clean that no exit-code check can catch. `dir` (v8.19+)
    // walks the files actually on disk. The OS daily scan target
    // (a deployed data dir) is exactly the non-git shape, so anything without a
    // .git entry MUST take the `dir` path; git repos keep `detect` so
    // existing history-scan behavior is unchanged.
    let git_mode = repo_root.join(".git").exists();
    let args = gitleaks_args(git_mode, report_path_str.as_str());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = run_capped(bin, &arg_refs, repo_root, &RunLimits::default()).await;

    let cleanup_error = outcome.cleanup_error.clone();
    record_gitleaks_outcome(outcome, &report_path, engines_run, findings);
    record_cleanup_error(engines_run, cleanup_error);
}

fn record_gitleaks_outcome(
    outcome: exec::RunOutcome,
    report_path: &Path,
    engines_run: &mut Vec<EngineRun>,
    findings: &mut Vec<Finding>,
) {
    if let Some(err) = outcome.spawn_error {
        let _ = std::fs::remove_file(report_path);
        engines_run.push(EngineRun {
            engine: gitleaks::ENGINE_NAME.to_string(),
            findings_count: 0,
            duration_ms: outcome.duration.as_millis(),
            parse_error: Some(format!("failed to execute: {err}")),
            timed_out: false,
        });
        return;
    }
    if outcome.timed_out {
        let _ = std::fs::remove_file(report_path);
        engines_run.push(EngineRun {
            engine: gitleaks::ENGINE_NAME.to_string(),
            findings_count: 0,
            duration_ms: outcome.duration.as_millis(),
            parse_error: Some(format!("timed out after {:?}", exec::DEFAULT_TIMEOUT)),
            timed_out: true,
        });
        return;
    }

    // Fail closed on engine failure (coding convention 4): a non-zero exit
    // with NO report file means the scan never ran — e.g. a pre-8.19 binary
    // that lacks the `dir` subcommand ("unknown command"), or a config
    // error. With `--exit-code 0` a *findings* exit is 0, so non-zero here
    // is never "leaks found". Reporting it as clean would be a silent
    // fail-open in a security scanner.
    if outcome.exit_code != Some(0) && !report_path.exists() {
        engines_run.push(EngineRun {
            engine: gitleaks::ENGINE_NAME.to_string(),
            findings_count: 0,
            duration_ms: outcome.duration.as_millis(),
            parse_error: Some(format!(
                "gitleaks exited with {:?} and wrote no report (stderr_tail={:?})",
                outcome.exit_code,
                crate::util::truncate_bytes(outcome.stderr_tail.trim(), 300)
            )),
            timed_out: false,
        });
        return;
    }

    // The requested report file is the completion evidence; no file is not an empty report.
    // Report-file size is capped the same as stdout for the other scanners
    // (task spec: "輸出上限 16MB") — `run_capped` only bounds the piped
    // stdout/stderr it reads itself, not a file gitleaks writes on its own,
    // so this file needs its own explicit bound before we read it in full.
    let raw = match std::fs::metadata(report_path) {
        Err(e) => Err(format!("could not stat gitleaks report file: {e}")),
        Ok(meta) if meta.len() > exec::DEFAULT_MAX_OUTPUT_BYTES as u64 => Err(format!(
            "gitleaks report file too large ({} bytes > {}-byte cap) — not read",
            meta.len(),
            exec::DEFAULT_MAX_OUTPUT_BYTES
        )),
        Ok(_) => std::fs::read_to_string(report_path)
            .map_err(|e| format!("could not read gitleaks report file: {e}")),
    };
    let _ = std::fs::remove_file(report_path);

    match raw.and_then(|r| {
        if r.trim().is_empty() {
            Err("gitleaks report file is empty (expected a JSON array)".to_string())
        } else {
            gitleaks::parse(&r)
        }
    }) {
        Ok(parsed) => {
            let count = parsed.len();
            findings.extend(parsed);
            engines_run.push(EngineRun {
                engine: gitleaks::ENGINE_NAME.to_string(),
                findings_count: count,
                duration_ms: outcome.duration.as_millis(),
                parse_error: (outcome.exit_code != Some(0)).then(|| format!(
                    "gitleaks failed despite a readable report (exit_code={:?}, stderr_tail={:?})",
                    outcome.exit_code, crate::util::truncate_bytes(outcome.stderr_tail.trim(), 300)
                )),
                timed_out: false,
            });
        }
        Err(e) => {
            engines_run.push(EngineRun {
                engine: gitleaks::ENGINE_NAME.to_string(),
                findings_count: 0,
                duration_ms: outcome.duration.as_millis(),
                parse_error: Some(format!(
                    "{e} (exit_code={:?}, stderr_tail={:?})",
                    outcome.exit_code,
                    crate::util::truncate_bytes(outcome.stderr_tail.trim(), 300)
                )),
                timed_out: false,
            });
        }
    }
}

/// Pure arg builder for the gitleaks invocation so the git-vs-dir mode split
/// is unit-testable without a gitleaks binary. `git_mode` ⇒ `detect` (git
/// history, matches pre-2026-09 behavior on repos); otherwise `dir` (files on
/// disk — the only mode that scans anything in a non-git directory).
fn gitleaks_args(git_mode: bool, report_path: &str) -> Vec<String> {
    let mut args: Vec<String> = if git_mode {
        vec!["detect".into(), "--source".into(), ".".into()]
    } else {
        vec!["dir".into(), ".".into()]
    };
    args.extend(
        [
            "--report-format",
            "json",
            "--report-path",
            report_path,
            "--no-banner",
            "--exit-code",
            "0",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    args
}

/// osv-scanner is never actually invoked this wave — pure decision function so the reason text is unit-testable
/// without touching PATH.
fn osv_scanner_missing(installed: bool) -> EngineMissing {
    let reason = if installed {
        "installed but skipped: osv-scanner queries the network OSV vulnerability database; \
         disabled under vettalon's zero-network policy — run it manually for CVE coverage"
            .to_string()
    } else {
        "not installed, and would be skipped anyway: osv-scanner requires network access to \
         query the OSV database, disabled under vettalon's zero-network policy"
            .to_string()
    };
    EngineMissing {
        engine: "osv-scanner".to_string(),
        reason,
    }
}

fn run_osv_scanner(engines_missing: &mut Vec<EngineMissing>) {
    let installed = crate::util::which_cli("osv-scanner").is_some();
    engines_missing.push(osv_scanner_missing(installed));
}

/// Pure filesystem check, extracted for direct unit testing.
fn cargo_lock_present(repo_root: &Path) -> bool {
    repo_root.join("Cargo.lock").exists()
}

async fn run_cargo_audit(
    repo_root: &Path,
    engines_run: &mut Vec<EngineRun>,
    engines_missing: &mut Vec<EngineMissing>,
    findings: &mut Vec<Finding>,
) {
    if !cargo_lock_present(repo_root) {
        engines_missing.push(EngineMissing {
            engine: cargo_audit::ENGINE_NAME.to_string(),
            reason: "not applicable: no Cargo.lock found at repo root".to_string(),
        });
        return;
    }
    if crate::util::which_cli("cargo-audit").is_none() {
        engines_missing.push(EngineMissing {
            engine: cargo_audit::ENGINE_NAME.to_string(),
            reason: "not installed (install via `cargo install cargo-audit`)".to_string(),
        });
        return;
    }
    run_cargo_audit_with_bin(repo_root, "cargo", engines_run, findings).await;
}

async fn run_cargo_audit_with_bin(
    repo_root: &Path,
    bin: &str,
    engines_run: &mut Vec<EngineRun>,
    findings: &mut Vec<Finding>,
) {
    // Invoked via `cargo audit`, not the `cargo-audit` binary directly —
    // lets cargo's own subcommand resolution handle argv shaping.
    // `--no-fetch` uses whatever advisory-db is already cached locally
    // instead of git-fetching an update (zero-network discipline; if no
    // cache exists at all the command fails, which surfaces below as a
    // normal parse_error, not a crash).
    let outcome = run_capped(
        bin,
        &["audit", "--json", "--no-fetch"],
        repo_root,
        &RunLimits::default(),
    )
    .await;
    record_stdout_scanner(
        cargo_audit::ENGINE_NAME,
        outcome,
        |raw| cargo_audit::parse(raw).map(|findings| (findings, None)),
        engines_run,
        findings,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ok_outcome(stdout: &str) -> exec::RunOutcome {
        exec::RunOutcome {
            stdout: stdout.to_string(),
            stdout_truncated: false,
            stderr_tail: String::new(),
            exit_code: Some(0),
            duration: Duration::from_millis(5),
            timed_out: false,
            spawn_error: None,
            cleanup_error: None,
        }
    }

    #[test]
    fn gitleaks_args_git_mode_uses_detect_with_source() {
        let args = gitleaks_args(true, "/tmp/r.json");
        assert_eq!(args[0], "detect");
        assert_eq!(&args[1..3], ["--source", "."]);
        assert!(args.contains(&"--report-path".to_string()));
        assert!(args.contains(&"/tmp/r.json".to_string()));
        // `--exit-code 0` must survive both modes: findings never become a
        // non-zero exit that the fail-closed guard would misread as failure.
        assert_eq!(&args[args.len() - 2..], ["--exit-code", "0"]);
    }

    #[test]
    fn gitleaks_args_non_git_uses_dir_subcommand() {
        let args = gitleaks_args(false, "/tmp/r.json");
        // `detect` on a non-git dir scans 0 bytes and exits 0 (live-fired
        // fake-clean) — the dir subcommand is load-bearing, not stylistic.
        assert_eq!(&args[0..2], ["dir", "."]);
        assert!(!args.contains(&"--source".to_string()));
        assert_eq!(&args[args.len() - 2..], ["--exit-code", "0"]);
    }

    #[test]
    fn record_stdout_scanner_success_path_records_findings() {
        let mut engines_run = Vec::new();
        let mut findings = Vec::new();
        record_stdout_scanner(
            "fake-engine",
            ok_outcome("anything"),
            |_raw| {
                Ok((
                    vec![Finding::candidate(
                        "fake-engine",
                        crate::audit::schema::FindingKind::Other,
                        crate::audit::schema::Severity::Low,
                        "t",
                        "f",
                        None,
                        "s",
                        "r",
                        vec![],
                    )],
                    None,
                ))
            },
            &mut engines_run,
            &mut findings,
        );
        assert_eq!(engines_run.len(), 1);
        assert_eq!(engines_run[0].findings_count, 1);
        assert!(engines_run[0].parse_error.is_none());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn record_stdout_scanner_parse_failure_sets_parse_error_not_panic() {
        let mut engines_run = Vec::new();
        let mut findings = Vec::new();
        record_stdout_scanner(
            "fake-engine",
            ok_outcome("garbage"),
            |_raw| Err("bad shape".to_string()),
            &mut engines_run,
            &mut findings,
        );
        assert_eq!(engines_run.len(), 1);
        assert_eq!(engines_run[0].findings_count, 0);
        assert!(
            engines_run[0]
                .parse_error
                .as_ref()
                .unwrap()
                .contains("bad shape")
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn cleanup_failure_keeps_candidates_but_marks_the_run_failed() {
        let mut outcome =
            ok_outcome(r#"{"results":[{"check_id":"fixture","path":"fixture.py"}],"errors":[]}"#);
        outcome.cleanup_error = Some("owned group cleanup failed".into());
        let (mut runs, mut findings) = (vec![], vec![]);
        record_stdout_scanner(
            semgrep::ENGINE_NAME,
            outcome,
            semgrep::parse_with_diagnostics,
            &mut runs,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(runs_failed(&runs));
        assert!(
            runs[0]
                .parse_error
                .as_ref()
                .unwrap()
                .contains("owned group cleanup failed")
        );
    }

    #[test]
    fn record_stdout_scanner_spawn_error_is_reported() {
        let mut engines_run = Vec::new();
        let mut findings = Vec::new();
        let outcome = exec::RunOutcome {
            stdout: String::new(),
            stdout_truncated: false,
            stderr_tail: String::new(),
            exit_code: None,
            duration: Duration::from_millis(1),
            timed_out: false,
            spawn_error: Some("no such file".to_string()),
            cleanup_error: None,
        };
        record_stdout_scanner(
            "fake-engine",
            outcome,
            |_| Ok((vec![], None)),
            &mut engines_run,
            &mut findings,
        );
        assert!(
            engines_run[0]
                .parse_error
                .as_ref()
                .unwrap()
                .contains("no such file")
        );
    }

    #[test]
    fn record_stdout_scanner_truncated_output_is_reported_and_not_parsed() {
        let mut engines_run = Vec::new();
        let mut findings = Vec::new();
        let mut outcome = ok_outcome("truncated-garbage");
        outcome.stdout_truncated = true;
        // The parse closure must never even be called on truncated output —
        // if it were, this would panic and fail the test.
        record_stdout_scanner(
            "fake-engine",
            outcome,
            |_raw| panic!("parse must not run on truncated stdout"),
            &mut engines_run,
            &mut findings,
        );
        assert_eq!(engines_run.len(), 1);
        assert_eq!(engines_run[0].findings_count, 0);
        assert!(
            engines_run[0]
                .parse_error
                .as_ref()
                .unwrap()
                .contains("truncated")
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn record_stdout_scanner_timeout_is_reported() {
        let mut engines_run = Vec::new();
        let mut findings = Vec::new();
        let outcome = exec::RunOutcome {
            stdout: String::new(),
            stdout_truncated: false,
            stderr_tail: String::new(),
            exit_code: None,
            duration: Duration::from_secs(300),
            timed_out: true,
            spawn_error: None,
            cleanup_error: None,
        };
        record_stdout_scanner(
            "fake-engine",
            outcome,
            |_| Ok((vec![], None)),
            &mut engines_run,
            &mut findings,
        );
        assert!(engines_run[0].timed_out);
        assert!(engines_run[0].parse_error.is_some());
    }

    #[test]
    fn osv_scanner_is_always_missing_with_a_reason_either_way() {
        let installed = osv_scanner_missing(true);
        assert_eq!(installed.engine, "osv-scanner");
        assert!(installed.reason.contains("installed but skipped"));

        let absent = osv_scanner_missing(false);
        assert!(absent.reason.contains("not installed"));
        // Both reasons must explain the *actual* cause (network policy),
        // not just "missing" — an operator who has it installed shouldn't
        // wonder why it didn't run.
        assert!(installed.reason.contains("network"));
        assert!(absent.reason.contains("network"));
    }

    #[test]
    fn run_failure_summary_distinguishes_missing_success_error_and_timeout() {
        assert!(
            !runs_failed(&[]),
            "missing engines use a separate scope record"
        );
        let mut run = EngineRun {
            engine: "fixture".into(),
            findings_count: 0,
            duration_ms: 1,
            parse_error: None,
            timed_out: false,
        };
        assert!(!runs_failed(std::slice::from_ref(&run)));
        run.parse_error = Some("failed output contract".into());
        assert!(runs_failed(std::slice::from_ref(&run)));
        run.parse_error = None;
        run.timed_out = true;
        assert!(
            runs_failed(&[run]),
            "timeout remains failed without a parse diagnostic"
        );
    }

    #[test]
    fn cargo_lock_present_detects_file_existence() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!cargo_lock_present(dir.path()));
        std::fs::write(dir.path().join("Cargo.lock"), "").unwrap();
        assert!(cargo_lock_present(dir.path()));
    }
}

#[cfg(all(test, unix))]
mod subprocess_contract_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // A self-authored fixed script is the scanner executable. No repository
    // content is evaluated, and production discovery/PATH is never mutated.
    fn stub(dir: &Path, body: &str) -> String {
        let path = dir.join("scanner-stub");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn emit(raw: &str, exit: i32) -> String {
        let quoted = raw.replace('\'', "'\"'\"'");
        format!("printf '%s' '{quoted}'; printf '%s' 'fixture diagnostic' >&2; exit {exit}")
    }

    #[tokio::test]
    async fn cargo_subprocess_failure_and_findings_exits_remain_distinct() {
        let valid = r#"{"vulnerabilities":{"found":true,"count":1,"list":[{"advisory":{"id":"RUSTSEC-fixture"},"package":{"name":"fixture","version":"1"}}]}}"#;
        let clean = r#"{"vulnerabilities":{"found":false,"count":0,"list":[]}}"#;
        for (raw, exit, count, failed) in [
            ("", 1, 0, true),
            ("{}", 0, 0, true),
            (clean, 1, 0, true),
            (clean, 0, 0, false),
            (valid, 1, 1, false),
            (valid, 2, 1, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let bin = stub(dir.path(), &emit(raw, exit));
            let (mut runs, mut findings) = (vec![], vec![]);
            run_cargo_audit_with_bin(dir.path(), &bin, &mut runs, &mut findings).await;
            assert_eq!(findings.len(), count, "{raw} / {exit}");
            assert_eq!(runs_failed(&runs), failed, "{raw} / {exit}: {runs:?}");
            assert_eq!(runs[0].findings_count, count);
            assert!(
                findings
                    .iter()
                    .all(|f| f.status == crate::audit::schema::FindingStatus::Candidate)
            );
            if raw.is_empty() {
                let error = runs[0].parse_error.as_deref().unwrap();
                assert!(
                    error.contains("exit_code=Some(1)") && error.contains("fixture diagnostic")
                );
            }
        }
    }

    #[tokio::test]
    async fn semgrep_subprocess_partial_errors_retain_candidates_and_fail_completion() {
        let partial = r#"{"results":[{"check_id":"fixture","path":"fixture.py"}],"errors":[{"type":"PartialParsing","level":"warn"}]}"#;
        let valid = r#"{"results":[{"check_id":"fixture","path":"fixture.py"}],"errors":[]}"#;
        for (raw, exit, count, failed) in [
            ("", 0, 0, true),
            ("{}", 0, 0, true),
            (r#"{"results":[],"errors":[]}"#, 0, 0, false),
            (partial, 0, 1, true),
            (valid, 2, 1, true),
            (valid, 1, 1, true),
            (valid, 0, 1, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let body = format!(
                "[ \"$4\" = '--disable-version-check' ] || exit 93; {}",
                emit(raw, exit)
            );
            let bin = stub(dir.path(), &body);
            let (mut runs, mut missing, mut findings) = (vec![], vec![], vec![]);
            run_semgrep_with_bin(dir.path(), &bin, &mut runs, &mut missing, &mut findings).await;
            assert!(missing.is_empty());
            assert_eq!(findings.len(), count, "{raw} / {exit}");
            assert_eq!(runs_failed(&runs), failed, "{raw} / {exit}: {runs:?}");
            if raw == partial {
                assert!(
                    runs[0]
                        .parse_error
                        .as_ref()
                        .unwrap()
                        .contains("PartialParsing")
                );
            }
        }
    }

    #[tokio::test]
    async fn gitleaks_requires_a_readable_json_report_and_success_exit() {
        for (report, exit, failed) in [
            (Some("[]"), 0, false),
            (Some("[]"), 2, true),
            (Some(""), 0, true),
            (None, 0, true),
            (None, 2, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let body = match report {
                Some(raw) => format!(
                    "while [ \"$#\" -gt 0 ]; do if [ \"$1\" = '--report-path' ]; then shift; printf '%s' '{raw}' > \"$1\"; break; fi; shift; done; exit {exit}"
                ),
                None => format!("exit {exit}"),
            };
            let bin = stub(dir.path(), &body);
            let (mut runs, mut findings) = (vec![], vec![]);
            run_gitleaks_with_bin(dir.path(), &bin, &mut runs, &mut findings).await;
            assert_eq!(runs_failed(&runs), failed, "{report:?} / {exit}: {runs:?}");
            assert!(findings.is_empty());
        }
    }
}
