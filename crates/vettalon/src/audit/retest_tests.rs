use std::path::Path;
use std::time::{Duration, Instant};

use super::*;
use crate::audit::schema::*;
use crate::audit::target_poc::tests::FakeTargetSandbox;
use crate::audit::target_poc::{TargetArgument, TargetSandbox};

const VULNERABLE: &str = "# VULNERABLE\nimport os\ndef read_file(payload):\n    return open(os.path.join(os.environ['VTL_BASE'], payload)).read()\n";
const SAFE: &str = "# SAFE\nimport os\ndef read_file(payload):\n    if '/' in payload: return ''\n    return open(os.path.join(os.environ['VTL_BASE'], payload)).read()\n";
const RENAMED: &str =
    "# VULNERABLE\nimport os\ndef read_any(payload):\n    return open(payload).read()\n";
const DIFF: &str =
    "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none";

struct SandboxRunner<'a, S>(&'a S);

#[async_trait::async_trait]
impl<S: TargetSandbox> RetestRunner for SandboxRunner<'_, S> {
    async fn run(
        &self,
        repo: &Path,
        finding: &Finding,
        call: &TargetCall,
        replays: u32,
        deadline: Instant,
    ) -> TargetPocReceipt {
        target_poc::run_replays_until(repo, finding, call, self.0, false, replays, Some(deadline))
            .await
            .receipt
    }
}

/// Sleeps before delegating, so a short deadline expires mid-run.
struct SlowRunner<'a>(&'a FakeTargetSandbox, Duration);

#[async_trait::async_trait]
impl RetestRunner for SlowRunner<'_> {
    async fn run(
        &self,
        repo: &Path,
        finding: &Finding,
        call: &TargetCall,
        replays: u32,
        deadline: Instant,
    ) -> TargetPocReceipt {
        tokio::time::sleep(self.1).await;
        SandboxRunner(self.0)
            .run(repo, finding, call, replays, deadline)
            .await
    }
}

fn far_deadline() -> Instant {
    Instant::now() + Duration::from_secs(DEFAULT_RETEST_DEADLINE_SECS)
}

fn call() -> TargetCall {
    TargetCall {
        file: "app.py".into(),
        function: "read_file".into(),
        args: vec![TargetArgument::Payload],
    }
}

/// A finding pinned to `pinned` source; `differential` adds the recorded
/// harness-judged differential PoC that makes it `poc_differential`.
fn finding(id: &str, pinned: &str, differential: bool) -> Finding {
    let mut finding = Finding::candidate(
        "ai_audit",
        FindingKind::Other,
        Severity::High,
        "path read",
        "app.py",
        Some(3),
        "open(...)",
        "ai-audit/path-traversal",
        vec![],
    );
    finding.id = id.into();
    finding.status = FindingStatus::NeedsHuman;
    finding.cwe = Some("CWE-22".into());
    finding.file_hash = Some(sha256_hex(pinned.as_bytes()));
    if differential {
        finding.evidence.push(EvidenceItem {
            kind: EvidenceKind::PocOracle,
            source: "test".into(),
            detail: DIFF.into(),
            recorded_at: "2026-11-01T00:00:00Z".into(),
        });
    }
    finding
}

fn report(repo: &Path, findings: Vec<Finding>) -> AuditReport {
    AuditReport {
        repo_commit: Some("a".repeat(40)),
        repo_tree_clean: Some(true),
        since_last: None,
        attack_classes: None,
        schema_version: CURRENT_SCHEMA_VERSION,
        scope: None,
        repo: repo.to_string_lossy().into_owned(),
        started_at: "2026-11-01T00:00:00Z".into(),
        profile: ScanProfile {
            mode: ProfileMode::Deep,
            intake: None,
        },
        engines_run: vec![],
        engines_missing: vec![],
        summary: Summary::from_findings(&[], 0, 0, GatePolicy::default(), &[]),
        findings,
        run_status: vettalon_contract::coverage::RunStatus::Complete,
        incomplete_reason: None,
        coverage: vec![],
        prior_run: None,
        verifier: Default::default(),
        ensemble: Default::default(),
    }
}

fn old(repo: &Path, findings: Vec<Finding>) -> OldReport {
    let report = report(repo, findings);
    let bytes = serde_json::to_vec(&report).unwrap();
    OldReport {
        path: repo.join("old.json"),
        report,
        sha256: sha256_hex(&bytes),
    }
}

fn repo_with(source: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    if let Some(source) = source {
        std::fs::write(dir.path().join("app.py"), source).unwrap();
    }
    dir
}

fn plans(ids: &[&str]) -> BTreeMap<String, TargetCall> {
    ids.iter().map(|id| (id.to_string(), call())).collect()
}

async fn retest(
    repo: &Path,
    old: &OldReport,
    plans: &BTreeMap<String, TargetCall>,
    sandbox: &FakeTargetSandbox,
    replays: u32,
    max: usize,
) -> RetestReport {
    let repo = std::fs::canonicalize(repo).unwrap();
    let runner = SandboxRunner(sandbox);
    run_retest_with(&repo, old, plans, &runner, replays, max, far_deadline())
        .await
        .unwrap()
}

fn by_id<'a>(report: &'a RetestReport, id: &str) -> &'a RetestResult {
    report.results.iter().find(|r| r.finding_id == id).unwrap()
}

fn reason(result: &RetestResult) -> &str {
    result.reason.as_deref().unwrap_or("")
}

#[tokio::test]
async fn only_poc_differential_with_a_plan_runs_in_report_order_up_to_the_cap() {
    let repo = repo_with(Some(VULNERABLE));
    let mut mismatched = finding("f6", VULNERABLE, true);
    mismatched.file = "other.py".into();
    let old = old(
        repo.path(),
        vec![
            finding("f1", VULNERABLE, true),
            finding("f2", VULNERABLE, false),
            finding("f3", VULNERABLE, true),
            finding("f4", VULNERABLE, true),
            finding("f5", VULNERABLE, true),
            mismatched,
        ],
    );
    let sandbox = FakeTargetSandbox::default();
    let planned = plans(&["f1", "f4", "f5"]);
    let report = retest(repo.path(), &old, &planned, &sandbox, 1, 2).await;
    let ids: Vec<&str> = report
        .results
        .iter()
        .map(|r| r.finding_id.as_str())
        .collect();
    assert_eq!(ids, ["f1", "f2", "f3", "f4", "f5", "f6"]);
    let status = |id| by_id(&report, id).status;
    assert_eq!(status("f1"), RetestStatus::StillObserved);
    assert_eq!(status("f2"), RetestStatus::NotReproducibleBefore);
    assert_eq!(reason(by_id(&report, "f2")), "evidence_level_static_only");
    assert_eq!(status("f3"), RetestStatus::NotReproducibleBefore);
    assert_eq!(reason(by_id(&report, "f3")), "no_target_plan");
    assert_eq!(status("f4"), RetestStatus::StillObserved);
    assert_eq!(status("f5"), RetestStatus::RetestCapReached);
    assert!(by_id(&report, "f5").receipt.is_none());
    assert_eq!(status("f6"), RetestStatus::NotReproducibleBefore);
    assert_eq!(reason(by_id(&report, "f6")), "no_target_plan");
    // Two targets, three containers each; nothing else entered the sandbox.
    assert_eq!(sandbox.seen.lock().unwrap().len(), 6);
    assert!(!by_id(&report, "f1").rebound);
    assert_eq!(report.summary.still_observed, 2);
    assert_eq!(report.summary.not_reproducible_before, 3);
    assert_eq!(report.summary.retest_cap_reached, 1);
    assert_eq!(report.version, RETEST_REPORT_VERSION);
    assert_eq!(report.old_report_sha256, old.sha256);
    assert_eq!(report.old_repo_commit, old.report.repo_commit);
    assert_eq!(report.exit_code(), 1);
}

#[tokio::test]
async fn generated_retest_passes_signing_extraction_and_package_loading() {
    let repo = repo_with(Some(SAFE));
    let mut finding = finding("f1", VULNERABLE, true);
    finding.trace = vec![TraceStep {
        kind: TraceKind::Sink,
        file: "app.py".into(),
        line: 3,
        scope: "read_file".into(),
        description: "file read".into(),
    }];
    finding.blockers = vec!["deployment context needs confirmation".into()];
    finding.validation_plan = Some(ValidationPlan {
        local: Some("rerun the differential PoC".into()),
        deployment: None,
    });
    finding.evidence.push(EvidenceItem {
        kind: EvidenceKind::AdversarialReview,
        source: "test".into(),
        detail: "plausible: file read reaches the supplied path".into(),
        recorded_at: "2026-11-01T00:00:00Z".into(),
    });
    assert_generated_retest_delivery(repo.path(), finding, call(), &FakeTargetSandbox::default())
        .await;
}

pub(crate) async fn assert_generated_retest_delivery<S: TargetSandbox>(
    repo: &Path,
    finding: Finding,
    call: TargetCall,
    sandbox: &S,
) {
    use crate::attest::statement::{build_statement, check_statement};
    use crate::attest::{ReceiptKind, extract};
    use crate::audit::retest_package::{PackageRequest, load_inputs};

    let planned = BTreeMap::from([(finding.id.clone(), call)]);
    let mut old = old(repo, vec![finding]);
    old.report.summary =
        Summary::from_findings(&old.report.findings, 0, 0, GatePolicy::default(), &[]);
    let old_raw = serde_json::to_vec(&old.report).unwrap();
    old.sha256 = sha256_hex(&old_raw);
    crate::audit::parse_report_for_delivery(&old_raw).unwrap();
    let canonical = std::fs::canonicalize(repo).unwrap();
    let report = run_retest_with(
        &canonical,
        &old,
        &planned,
        &SandboxRunner(sandbox),
        1,
        20,
        far_deadline(),
    )
    .await
    .unwrap();
    assert!(
        report.results[0]
            .receipt
            .as_ref()
            .unwrap()
            .verification_event
            .is_some()
    );
    let raw = serde_json::to_vec(&report).unwrap();
    let extracted = extract(std::str::from_utf8(&raw).unwrap()).unwrap();
    assert_eq!(extracted.kind, ReceiptKind::Retest);
    let statement = build_statement("retest.json", &raw, extracted.kind, &extracted.predicate);
    check_statement(&statement, &raw, extracted.kind, &extracted.predicate).unwrap();

    let path = repo.join("retest.json");
    std::fs::write(&path, raw).unwrap();
    std::fs::write(&old.path, old_raw).unwrap();
    let inputs = load_inputs(&PackageRequest {
        retest: Some(path),
        report: Some(old.path),
        include_report: true,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        inputs.report_sha256(),
        Some(report.old_report_sha256.as_str())
    );
}

#[tokio::test]
async fn changed_file_is_rebound_and_both_hashes_are_recorded() {
    let repo = repo_with(Some(SAFE));
    let old = old(repo.path(), vec![finding("f1", VULNERABLE, true)]);
    let sandbox = FakeTargetSandbox::default();
    let report = retest(repo.path(), &old, &plans(&["f1"]), &sandbox, 1, 20).await;
    let result = by_id(&report, "f1");
    assert_eq!(result.status, RetestStatus::NotObserved);
    assert!(result.rebound);
    assert_eq!(
        result.old_file_sha256.as_deref(),
        Some(sha256_hex(VULNERABLE.as_bytes()).as_str())
    );
    let new = sha256_hex(SAFE.as_bytes());
    assert_eq!(result.new_file_sha256.as_deref(), Some(new.as_str()));
    let receipt = result.receipt.as_ref().unwrap();
    assert_eq!(receipt.target_file_sha256.as_deref(), Some(new.as_str()));
    // The old finding is untouched: the re-bound copy only lives in the run.
    assert_eq!(
        old.report.findings[0].file_hash.as_deref(),
        Some(sha256_hex(VULNERABLE.as_bytes()).as_str())
    );
    assert_eq!(report.exit_code(), 0);
    let text = render_text(&report);
    assert!(
        text.contains("not observed on this revision with these inputs"),
        "{text}"
    );
    assert!(!text.to_lowercase().contains("fixed"), "{text}");
}

#[tokio::test]
async fn deleted_file_or_removed_function_is_target_missing_without_running() {
    let sandbox = FakeTargetSandbox::default();
    let deleted = repo_with(None);
    let old_deleted = old(deleted.path(), vec![finding("f1", VULNERABLE, true)]);
    let report = retest(
        deleted.path(),
        &old_deleted,
        &plans(&["f1"]),
        &sandbox,
        1,
        20,
    )
    .await;
    let result = by_id(&report, "f1");
    assert_eq!(result.status, RetestStatus::TargetMissing);
    assert_eq!(reason(result), "target_file_missing");
    assert_eq!(result.new_file_sha256, None);

    let renamed = repo_with(Some(RENAMED));
    let old_renamed = old(renamed.path(), vec![finding("f1", VULNERABLE, true)]);
    let report = retest(
        renamed.path(),
        &old_renamed,
        &plans(&["f1"]),
        &sandbox,
        1,
        20,
    )
    .await;
    let result = by_id(&report, "f1");
    assert_eq!(result.status, RetestStatus::TargetMissing);
    assert_eq!(reason(result), "function_not_declared");
    assert!(result.rebound);
    assert_eq!(
        result.new_file_sha256.as_deref(),
        Some(sha256_hex(RENAMED.as_bytes()).as_str())
    );
    assert!(sandbox.seen.lock().unwrap().is_empty());
    // Nothing ran and the target is missing: never a clean exit.
    assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_target_is_refused_not_missing() {
    let repo = repo_with(None);
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("app.py"), VULNERABLE).unwrap();
    std::os::unix::fs::symlink(outside.path().join("app.py"), repo.path().join("app.py")).unwrap();
    let old = old(repo.path(), vec![finding("f1", VULNERABLE, true)]);
    let sandbox = FakeTargetSandbox::default();
    let report = retest(repo.path(), &old, &plans(&["f1"]), &sandbox, 1, 20).await;
    let result = by_id(&report, "f1");
    assert_eq!(result.status, RetestStatus::Inconclusive);
    assert_eq!(reason(result), "unsafe_target_path");
    assert!(sandbox.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn each_aggregate_maps_to_its_status_and_keeps_the_reason() {
    let repo = repo_with(Some(VULNERABLE));
    let old = old(repo.path(), vec![finding("f1", VULNERABLE, true)]);
    let plans = plans(&["f1"]);

    let capture = FakeTargetSandbox {
        fail_phase: Some(0),
        ..Default::default()
    };
    let report = retest(repo.path(), &old, &plans, &capture, 1, 20).await;
    let result = by_id(&report, "f1");
    assert_eq!(result.status, RetestStatus::EnvironmentUnavailable);
    assert_eq!(reason(result), "incomplete_sandbox_capture");
    assert_eq!(report.exit_code(), 2);

    // A hanging target is not the environment: inconclusive, target_timeout,
    // and no further replay is started after it.
    let hang = FakeTargetSandbox {
        timeout_phase: Some(0),
        ..Default::default()
    };
    let report = retest(repo.path(), &old, &plans, &hang, 3, 5).await;
    let result = by_id(&report, "f1");
    assert_eq!(result.status, RetestStatus::Inconclusive);
    assert_eq!(reason(result), "target_timeout");
    assert_eq!(hang.seen.lock().unwrap().len(), 3);
    assert_eq!(report.exit_code(), EXIT_INCONCLUSIVE);
    use crate::sandbox::EXECUTION_TIMEOUT_PREFIX as TIMEOUT;
    assert_eq!(
        target_poc::sandbox_error_reason(&format!("{TIMEOUT}1ms hard timeout")),
        "target_timeout"
    );
    assert_eq!(
        target_poc::sandbox_error_reason(&format!(
            "{TIMEOUT}1ms hard timeout; sandbox cleanup unconfirmed: x"
        )),
        "incomplete_sandbox_capture"
    );
    assert_eq!(
        target_poc::sandbox_error_reason("container terminated by a signal"),
        "incomplete_sandbox_capture"
    );

    let inconsistent = FakeTargetSandbox {
        absent_replay: Some(1),
        ..Default::default()
    };
    let report = retest(repo.path(), &old, &plans, &inconsistent, 2, 20).await;
    let result = by_id(&report, "f1");
    assert_eq!(result.status, RetestStatus::Inconclusive);
    assert_eq!(reason(result), "replay_inconsistent");
    let receipt = result.receipt.as_ref().unwrap();
    assert_eq!(receipt.replay_summary().requested, 2);
    assert_eq!(report.replays, 2);
    assert_eq!(report.exit_code(), 2);

    let forged = FakeTargetSandbox {
        forge_print_only: true,
        ..Default::default()
    };
    let report = retest(repo.path(), &old, &plans, &forged, 1, 20).await;
    assert_eq!(by_id(&report, "f1").status, RetestStatus::Inconclusive);
    assert!(reason(by_id(&report, "f1")).contains("verdict"));

    use RetestStatus as S;
    use TargetPocOutcome as O;
    assert_eq!(status_for(O::EffectObserved, None), S::StillObserved);
    assert_eq!(status_for(O::EffectAbsent, None), S::NotObserved);
    for env in ENVIRONMENT_REASONS {
        assert_eq!(
            status_for(O::Inconclusive, Some(*env)),
            S::EnvironmentUnavailable
        );
    }
    for other in [None, Some("replay_inconsistent"), Some("stale_source")] {
        assert_eq!(status_for(O::Inconclusive, other), S::Inconclusive);
    }
}

#[test]
fn exit_code_is_fail_closed() {
    let summary = |f: fn(&mut RetestSummary)| {
        let mut s = RetestSummary::default();
        f(&mut s);
        exit_code_for(&s)
    };
    // 0 only when something ran and every run finding is not_observed.
    assert_eq!(summary(|s| s.not_observed = 1), EXIT_NOT_OBSERVED);
    assert_eq!(
        summary(|s| {
            s.not_observed = 2;
            s.not_reproducible_before = 3;
        }),
        EXIT_NOT_OBSERVED
    );
    // Nothing ran at all.
    assert_eq!(summary(|_| {}), EXIT_INCOMPLETE);
    assert_eq!(summary(|s| s.not_reproducible_before = 4), EXIT_INCOMPLETE);
    assert_eq!(summary(|s| s.target_missing = 1), EXIT_INCOMPLETE);
    assert_eq!(summary(|s| s.retest_cap_reached = 1), EXIT_INCOMPLETE);
    // A missing or capped finding spoils an otherwise clean run.
    assert_eq!(
        summary(|s| {
            s.not_observed = 1;
            s.target_missing = 1;
        }),
        EXIT_INCOMPLETE
    );
    assert_eq!(
        summary(|s| {
            s.not_observed = 1;
            s.retest_cap_reached = 1;
        }),
        EXIT_INCOMPLETE
    );
    // Inconclusive / environment beat incomplete.
    assert_eq!(
        summary(|s| {
            s.inconclusive = 1;
            s.target_missing = 1;
        }),
        EXIT_INCONCLUSIVE
    );
    assert_eq!(
        summary(|s| s.environment_unavailable = 1),
        EXIT_INCONCLUSIVE
    );
    // Still observed beats everything.
    assert_eq!(
        summary(|s| {
            s.still_observed = 1;
            s.inconclusive = 1;
            s.retest_cap_reached = 1;
        }),
        EXIT_STILL_OBSERVED
    );
    assert_eq!([EXIT_NOT_OBSERVED, EXIT_STILL_OBSERVED], [0, 1]);
    assert_eq!([EXIT_INCONCLUSIVE, EXIT_INCOMPLETE], [2, 3]);
}

#[tokio::test]
async fn run_where_only_unplanned_findings_exist_exits_incomplete() {
    let repo = repo_with(Some(SAFE));
    let old = old(repo.path(), vec![finding("f1", VULNERABLE, true)]);
    let sandbox = FakeTargetSandbox::default();
    let report = retest(repo.path(), &old, &plans(&[]), &sandbox, 1, 20).await;
    assert_eq!(
        by_id(&report, "f1").status,
        RetestStatus::NotReproducibleBefore
    );
    assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
    assert!(sandbox.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn old_report_file_is_never_modified() {
    let repo = repo_with(Some(SAFE));
    let report_path = repo.path().join("old.json");
    let mut old = old(repo.path(), vec![finding("f1", VULNERABLE, true)]);
    let bytes = serde_json::to_vec_pretty(&old.report).unwrap();
    std::fs::write(&report_path, &bytes).unwrap();
    old.sha256 = sha256_hex(&bytes);
    old.path = report_path.clone();
    let sandbox = FakeTargetSandbox::default();
    let report = retest(repo.path(), &old, &plans(&["f1"]), &sandbox, 1, 20).await;
    assert_eq!(std::fs::read(&report_path).unwrap(), bytes);
    assert_eq!(report.old_report_sha256, sha256_hex(&bytes));
}

#[tokio::test]
async fn output_is_create_new_and_private() {
    let repo = repo_with(Some(SAFE));
    let old = old(repo.path(), vec![finding("f1", VULNERABLE, true)]);
    let sandbox = FakeTargetSandbox::default();
    let report = retest(repo.path(), &old, &plans(&["f1"]), &sandbox, 1, 20).await;
    let out_dir = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(out_dir.path()).unwrap();
    let out = dir.join("retest.json");
    let first = crate::remediation::write_new_remediation_output(&out, &report);
    assert_eq!(first, Ok(()));
    let written = std::fs::read(&out).unwrap();
    let parsed: RetestReport = serde_json::from_slice(&written).unwrap();
    assert_eq!(parsed.summary, report.summary);
    assert_eq!(parsed.results[0].status, RetestStatus::NotObserved);
    let second = crate::remediation::write_new_remediation_output(&out, &report);
    let error = second.unwrap_err();
    assert!(error.contains("already exists"), "{error}");
    assert_eq!(std::fs::read(&out).unwrap(), written);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn baseline_auto_selection_refuses_when_none_is_trusted() {
    let repo = repo_with(Some(SAFE));
    let home = tempfile::tempdir().unwrap();
    let error = load_old_report(repo.path(), None, home.path())
        .await
        .unwrap_err();
    assert!(error.contains("no baseline report"), "{error}");

    // A saved report for another repository is never a baseline here.
    let other = tempfile::tempdir().unwrap();
    std::fs::create_dir(home.path().join("reports")).unwrap();
    std::fs::write(
        home.path().join("reports").join("other.json"),
        serde_json::to_vec(&report(other.path(), vec![])).unwrap(),
    )
    .unwrap();
    let error = load_old_report(repo.path(), None, home.path())
        .await
        .unwrap_err();
    assert!(error.contains("no baseline report"), "{error}");
    assert!(error.contains("--report"), "{error}");
}

#[test]
fn repository_identity_is_still_required() {
    let repo = repo_with(Some(SAFE));
    let other = tempfile::tempdir().unwrap();
    let report = report(other.path(), vec![]);
    let error = crate::remediation::check_report_repository(repo.path(), &report).unwrap_err();
    assert!(error.contains("repository identity mismatch"), "{error}");
    let same = self::report(repo.path(), vec![]);
    assert_eq!(
        crate::remediation::check_report_repository(repo.path(), &same).unwrap(),
        std::fs::canonicalize(repo.path()).unwrap()
    );
}

#[tokio::test]
async fn plans_and_limits_are_validated() {
    let parsed = parse_target_plans(
        r#"{"f1":{"file":"app.py","function":"read_file","args":[{"kind":"payload"}]}}"#,
    )
    .unwrap();
    assert_eq!(parsed.get("f1"), Some(&call()));
    for bad in [
        "[]",
        r#"{"f1":{"file":"app.py","function":"read_file","args":[]}}"#,
        r#"{"f1":{"file":"../app.py","function":"read_file","args":[{"kind":"payload"}]}}"#,
        r#"{"f1":{"file":"app.py","function":"x","args":[{"kind":"payload"}],"code":"1"}}"#,
    ] {
        assert!(parse_target_plans(bad).is_err(), "{bad}");
    }
    let repo = repo_with(Some(VULNERABLE));
    let canonical = std::fs::canonicalize(repo.path()).unwrap();
    let old = old(repo.path(), vec![finding("f1", VULNERABLE, true)]);
    let sandbox = FakeTargetSandbox::default();
    let runner = SandboxRunner(&sandbox);
    let deadline = far_deadline();
    let nope = plans(&["nope"]);
    let unknown = run_retest_with(&canonical, &old, &nope, &runner, 1, 20, deadline).await;
    assert!(unknown.unwrap_err().contains("not in the old report"));
    for (replays, max) in [(0, 20), (21, 20), (1, 0), (1, 21), (3, 20), (20, 3)] {
        let plans = plans(&["f1"]);
        assert!(
            run_retest_with(&canonical, &old, &plans, &runner, replays, max, deadline)
                .await
                .is_err(),
            "{replays} {max}"
        );
    }
    assert!(sandbox.seen.lock().unwrap().is_empty());
}

#[test]
fn container_product_cap_is_enforced_with_an_explanation() {
    // replays * max_findings * 3 <= 120.
    assert_eq!(validate_limits(1, 20, 3600), Ok(()));
    assert_eq!(validate_limits(2, 20, 3600), Ok(()));
    assert_eq!(validate_limits(20, 2, 3600), Ok(()));
    let error = validate_limits(3, 20, 3600).unwrap_err();
    assert!(error.contains("--replays 3"), "{error}");
    assert!(error.contains("--max-findings 20"), "{error}");
    assert!(error.contains("180"), "{error}");
    assert!(error.contains("120"), "{error}");
    assert!(validate_limits(20, 3, 3600).unwrap_err().contains("180"));
    // Deadline bounds.
    assert!(validate_limits(1, 1, 0).is_err());
    assert!(validate_limits(1, 1, MAX_RETEST_DEADLINE_SECS).is_ok());
    assert!(validate_limits(1, 1, MAX_RETEST_DEADLINE_SECS + 1).is_err());
}

#[tokio::test]
async fn plans_for_findings_that_cannot_be_rerun_refuse_the_whole_run() {
    let repo = repo_with(Some(VULNERABLE));
    let canonical = std::fs::canonicalize(repo.path()).unwrap();
    let mut mismatched = finding("f2", VULNERABLE, true);
    mismatched.file = "other.py".into();
    let mut xss = finding("f3", VULNERABLE, true);
    xss.cwe = Some("CWE-79".into());
    xss.rule_id = "ai-audit/xss".into();
    let old = old(
        repo.path(),
        vec![
            finding("f1", VULNERABLE, true),
            mismatched,
            xss,
            finding("f4", VULNERABLE, false),
        ],
    );
    let sandbox = FakeTargetSandbox::default();
    let runner = SandboxRunner(&sandbox);
    let deadline = far_deadline();
    for (id, expected) in [
        ("f2", "target_plan_file_mismatch"),
        ("f3", "refused"),
        ("f4", "evidence_level_static_only"),
    ] {
        let plans = plans(&["f1", id]);
        let error = run_retest_with(&canonical, &old, &plans, &runner, 1, 20, deadline)
            .await
            .unwrap_err();
        assert!(error.contains(&format!("{id:?}")), "{error}");
        assert!(error.contains(expected), "{error}");
    }
    // Refused before anything ran, including the valid f1 plan.
    assert!(sandbox.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn expired_deadline_marks_every_eligible_finding_without_running() {
    let repo = repo_with(Some(VULNERABLE));
    let canonical = std::fs::canonicalize(repo.path()).unwrap();
    let old = old(
        repo.path(),
        vec![
            finding("f1", VULNERABLE, true),
            finding("f2", VULNERABLE, true),
        ],
    );
    let sandbox = FakeTargetSandbox::default();
    let runner = SandboxRunner(&sandbox);
    let plans = plans(&["f1", "f2"]);
    let report = run_retest_with(&canonical, &old, &plans, &runner, 1, 20, Instant::now())
        .await
        .unwrap();
    for id in ["f1", "f2"] {
        let result = by_id(&report, id);
        assert_eq!(result.status, RetestStatus::RetestCapReached);
        assert_eq!(reason(result), DEADLINE_EXCEEDED);
        assert!(result.receipt.is_none());
    }
    assert!(sandbox.seen.lock().unwrap().is_empty());
    assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
}

#[tokio::test]
async fn deadline_reached_mid_run_marks_the_remaining_findings() {
    let repo = repo_with(Some(VULNERABLE));
    let canonical = std::fs::canonicalize(repo.path()).unwrap();
    let old = old(
        repo.path(),
        vec![
            finding("f1", VULNERABLE, true),
            finding("f2", VULNERABLE, true),
            finding("f3", VULNERABLE, true),
        ],
    );
    let sandbox = FakeTargetSandbox::default();
    // f1 starts in time; the runner outlives the deadline before its first
    // replay, so f1 is cut short and f2/f3 never start.
    let runner = SlowRunner(&sandbox, Duration::from_millis(1500));
    let plans = plans(&["f1", "f2", "f3"]);
    let deadline = Instant::now() + Duration::from_millis(1000);
    let report = run_retest_with(&canonical, &old, &plans, &runner, 2, 20, deadline)
        .await
        .unwrap();
    for id in ["f1", "f2", "f3"] {
        let result = by_id(&report, id);
        assert_eq!(result.status, RetestStatus::RetestCapReached, "{id}");
        assert_eq!(reason(result), DEADLINE_EXCEEDED, "{id}");
    }
    assert!(by_id(&report, "f1").receipt.is_none());
    crate::attest::extract(&serde_json::to_string(&report).unwrap()).unwrap();
    assert!(by_id(&report, "f2").receipt.is_none());
    assert!(sandbox.seen.lock().unwrap().is_empty());
    assert_eq!(report.summary.retest_cap_reached, 3);
    assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
}

#[tokio::test]
async fn deadline_between_replays_keeps_the_partial_receipt() {
    let repo = repo_with(Some(VULNERABLE));
    let canonical = std::fs::canonicalize(repo.path()).unwrap();
    let pinned = finding("f1", VULNERABLE, true);
    let sandbox = FakeTargetSandbox::default();
    // Replay 0 runs (deadline still ahead); it is checked again before
    // replay 1, which is not started once the deadline has passed.
    let deadline = Instant::now() + Duration::from_millis(500);
    let first = target_poc::run_replays_until(
        &canonical,
        &pinned,
        &call(),
        &SlowSandbox(&sandbox, Duration::from_millis(250)),
        false,
        3,
        Some(deadline),
    )
    .await
    .receipt;
    let summary = first.replay_summary();
    assert_eq!(summary.requested, 3);
    assert_eq!(summary.completed, 1);
    assert_eq!(first.outcome, TargetPocOutcome::Inconclusive);
    assert_eq!(first.reason.as_deref(), Some(DEADLINE_EXCEEDED));
    assert_eq!(sandbox.seen.lock().unwrap().len(), 3);
}

/// A sandbox whose containers each take the given duration, so a deadline
/// can pass between replays.
struct SlowSandbox<'a>(&'a FakeTargetSandbox, Duration);

#[async_trait::async_trait]
impl TargetSandbox for SlowSandbox<'_> {
    fn image_id(&self) -> &str {
        self.0.image_id()
    }

    async fn run(
        &self,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
    ) -> Result<(i64, String), String> {
        tokio::time::sleep(self.1).await;
        self.0.run(tree, runner, adapter, input).await
    }
}

#[test]
fn old_report_text_is_escaped_for_the_terminal() {
    let repo = repo_with(None);
    let mut hostile = finding("f\u{1b}[2J\u{7}x", VULNERABLE, true);
    hostile.title = "t\u{1b}]0;pwned\u{7}".into();
    let result = skipped(
        &hostile,
        RetestStatus::NotReproducibleBefore,
        "no_target_plan".into(),
    );
    let report = RetestReport {
        version: RETEST_REPORT_VERSION,
        repo: repo.path().to_string_lossy().into_owned(),
        old_report_sha256: "0".repeat(64),
        old_repo_commit: None,
        new_repo_commit: None,
        new_tree_clean: None,
        replays: 1,
        summary: RetestSummary::from_results(std::slice::from_ref(&result)),
        results: vec![result],
    };
    let text = render_text(&report);
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(!text.contains('\u{7}'), "{text:?}");
    assert!(text.contains("f\\u{1b}[2J\\u{7}x"), "{text:?}");
    assert_eq!(
        terminal_safe("a\u{1b}b\u{202e}c\nd"),
        "a\\u{1b}b\\u{202e}c\\nd"
    );
    assert_eq!(terminal_safe("plain-id_1"), "plain-id_1");
}

#[test]
fn explicit_report_needs_a_full_hex_commit() {
    let repo = repo_with(None);
    let mut report = report(repo.path(), vec![]);
    assert_eq!(require_full_commit(&report), Ok(()));
    report.repo_commit = Some("b".repeat(64));
    assert_eq!(require_full_commit(&report), Ok(()));
    for bad in [None, Some("main".to_string()), Some("a".repeat(39))] {
        report.repo_commit = bad;
        let error = require_full_commit(&report).unwrap_err();
        assert!(error.contains("full hex OID"), "{error}");
    }
    report.repo_commit = Some(format!("--{}", "a".repeat(38)));
    assert!(require_full_commit(&report).is_err());
}

#[tokio::test]
async fn generated_retest_without_an_event_keeps_failure_without_unbound_evidence() {
    struct RefusedRunner(&'static str);
    #[async_trait::async_trait]
    impl RetestRunner for RefusedRunner {
        async fn run(
            &self,
            _repo: &Path,
            _finding: &Finding,
            call: &TargetCall,
            replays: u32,
            _deadline: Instant,
        ) -> TargetPocReceipt {
            target_poc::refused_with(call, self.0, false, replays).receipt
        }
    }
    for (failure, status, reason) in [
        (
            "sandbox_unavailable",
            RetestStatus::EnvironmentUnavailable,
            "sandbox_unavailable",
        ),
        (
            "node_runtime_unavailable",
            RetestStatus::EnvironmentUnavailable,
            "node_runtime_unavailable",
        ),
        (
            DEADLINE_EXCEEDED,
            RetestStatus::RetestCapReached,
            DEADLINE_EXCEEDED,
        ),
        (
            "stale_source",
            RetestStatus::Inconclusive,
            "unbound_receipt",
        ),
    ] {
        let repo = repo_with(Some(SAFE));
        let canonical = std::fs::canonicalize(repo.path()).unwrap();
        let old = old(&canonical, vec![finding("f1", VULNERABLE, true)]);
        let report = run_retest_with(
            &canonical,
            &old,
            &plans(&["f1"]),
            &RefusedRunner(failure),
            2,
            20,
            far_deadline(),
        )
        .await
        .unwrap();
        let result = &report.results[0];
        assert_eq!(result.status, status);
        assert_eq!(result.reason.as_deref(), Some(reason));
        assert!(result.receipt.is_none());
        assert!(result.rebound);
        assert_eq!(result.new_file_sha256, Some(sha256_hex(SAFE.as_bytes())));
        let raw = serde_json::to_string(&report).unwrap();
        crate::attest::extract(&raw).unwrap();
        let path = repo.path().join("retest.json");
        std::fs::write(&path, raw).unwrap();
        crate::audit::retest_package::load_inputs(&crate::audit::retest_package::PackageRequest {
            retest: Some(path),
            ..Default::default()
        })
        .unwrap();
    }
}
