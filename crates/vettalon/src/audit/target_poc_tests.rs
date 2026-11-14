use std::path::Path;
use std::sync::Mutex;

use serde_json::json;

use super::*;
use crate::audit::schema::{FindingKind, FindingStatus, Severity, sha256_hex};

fn call() -> TargetCall {
    TargetCall {
        file: "app.py".into(),
        function: "read_file".into(),
        args: vec![TargetArgument::Payload],
    }
}

fn finding(source: &str) -> Finding {
    let mut finding = Finding::candidate(
        "ai_audit",
        FindingKind::Other,
        Severity::High,
        "path read",
        "app.py",
        Some(2),
        source,
        "ai-audit/path-traversal",
        vec![],
    );
    finding.status = FindingStatus::NeedsHuman;
    finding.cwe = Some("CWE-22".into());
    finding.file_hash = Some(sha256_hex(source.as_bytes()));
    finding
}

const VULNERABLE: &str = "# VULNERABLE\nimport os\ndef read_file(payload):\n    return open(os.path.join(os.environ['VTL_BASE'], payload)).read()\n";
const SAFE: &str = "# SAFE\nimport os\ndef read_file(payload):\n    if '/' in payload: return ''\n    return open(os.path.join(os.environ['VTL_BASE'], payload)).read()\n";
const FORGED: &str = "import os\ndef read_file(payload):\n    import __main__\n    marker = getattr(__main__, 'MARKER', 'forged')\n    print('__VTL_ORACLE__ ' + marker + ' effect=true')\n    os._exit(0)\n";

#[test]
fn preflight_requires_supported_pinned_current_source_without_executing_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), VULNERABLE).unwrap();
    let mut f = finding(VULNERABLE);
    assert_eq!(
        preflight_source(dir.path(), &f).unwrap(),
        f.file_hash.clone().unwrap()
    );
    std::fs::write(dir.path().join("app.py"), SAFE).unwrap();
    assert_eq!(preflight_source(dir.path(), &f), Err("stale_source"));
    f.file_hash = None;
    assert_eq!(
        preflight_source(dir.path(), &f),
        Err("missing_finding_source_identity")
    );
    f.cwe = Some("CWE-79".into());
    assert_eq!(
        preflight_source(dir.path(), &f),
        Err("unsupported_oracle_class")
    );
    f.file = "../app.py".into();
    assert!(preflight_source(dir.path(), &f).is_err());
}

#[test]
fn target_call_schema_is_closed_and_never_accepts_code_or_unbounded_data() {
    assert!(
        parse_target_call(
            r#"{"file":"app.py","function":"read_file","args":[{"kind":"payload"}]}"#
        )
        .is_ok()
    );
    for input in [
        r#"{"file":"app.py","function":"read_file","args":[{"kind":"payload"}],"adapter":"exec(x)"}"#,
        r#"{"file":"app.py","function":"read_file","args":[{"kind":"payload","value":"x"}]}"#,
        r#"{"file":"app.py","function":"read_file","args":[{"kind":"expression","value":"os.system('x')"}]}"#,
    ] {
        assert!(parse_target_call(input).is_err(), "{input}");
    }
    for function in [
        "read_file()",
        "module.read_file",
        "__import__",
        "read_file;exit()",
        "lambda",
        "a\nb",
    ] {
        let mut plan = call();
        plan.function = function.into();
        assert!(plan.validate().is_err(), "{function:?}");
    }
    for file in [
        "../app.py",
        "/app.py",
        "app.py/../x.py",
        "a\\b.py",
        ".env",
        "app.py\n",
        "file.jsx",
    ] {
        let mut plan = call();
        plan.file = file.into();
        assert!(plan.validate().is_err(), "{file:?}");
    }
    let mut no_payload = call();
    no_payload.args = vec![TargetArgument::Literal {
        value: json!("literal"),
    }];
    assert!(no_payload.validate().is_err());
    let mut doubled = call();
    doubled.args.push(TargetArgument::Payload);
    assert!(doubled.validate().is_err());
    let mut oversized = call();
    oversized.args.push(TargetArgument::Literal {
        value: json!("x".repeat(9000)),
    });
    assert!(oversized.validate().is_err());
    let mut deep = json!(0);
    for _ in 0..12 {
        deep = json!([deep]);
    }
    let mut nested = call();
    nested.args.push(TargetArgument::Literal { value: deep });
    assert!(nested.validate().is_err());
}

#[test]
fn trusted_adapter_loads_bound_bytes_and_treats_literal_expressions_as_data() {
    let mut plan = call();
    let dangerous_literal = "__import__('os').system('forged')\n\\\"";
    plan.args.push(TargetArgument::Literal {
        value: json!(dangerous_literal),
    });
    let adapter = build_target_adapter(&plan, &"a".repeat(64)).unwrap();
    assert!(adapter.contains("importlib.util"));
    assert!(adapter.contains("/workspace/tree/app.py"));
    assert!(adapter.contains("source_to_code"));
    assert!(
        !adapter.contains("exec_module"),
        "cached pyc must not replace bound source bytes"
    );
    assert!(
        !adapter.contains(dangerous_literal),
        "literal source must be encoded as data"
    );
    assert!(adapter.contains("bytes.fromhex"));
    assert!(adapter.contains("inspect.isawaitable"));
    assert!(adapter.contains("os.O_EXCL"));
    assert!(!adapter.contains("MARKER"));
    assert!(!adapter.contains("sys.path.append"));
    // A Python exception from the target module or call is a `raised`
    // record (exit 0); harness failures stay a non-zero exit.
    assert!(adapter.contains(
        "    except _HarnessError:\n        raise\n    except Exception as exc:\n        record = {'raised': type(exc).__name__[:64]}\n"
    ));
    assert!(adapter.contains("raise _HarnessError('target source identity mismatch')"));
    assert!(adapter.contains("raise _HarnessError('target function unavailable')"));
    assert!(adapter.contains("raise _HarnessError('async target unsupported')"));
}

#[test]
fn verdict_line_carries_raised_and_error_separately() {
    let v = parse_verdict(
        "__VTL_ORACLE__ vtlmM effect=false functional=true raised=true\n",
        "vtlmM",
    )
    .unwrap();
    assert!(!v.effect && v.raised && !v.error);
    assert_eq!(v.functional, Some(true));
    let v = parse_verdict("__VTL_ORACLE__ vtlmM effect=false error=true\n", "vtlmM").unwrap();
    assert!(v.error && !v.raised);
    assert_eq!(
        parse_verdict("__VTL_ORACLE__ vtlmM effect=false raised=maybe\n", "vtlmM"),
        Err("invalid_target_verdict")
    );
    assert_eq!(
        parse_verdict("__VTL_ORACLE__ vtlmM raised=true\n", "vtlmM"),
        Err("target_verdict_missing")
    );
    assert_eq!(
        parse_verdict(
            "__VTL_ORACLE__ vtlmM effect=false\n__VTL_ORACLE__ vtlmM effect=false\n",
            "vtlmM"
        ),
        Err("duplicate_target_verdict")
    );
    let v = parse_verdict(
        "__VTL_ORACLE__ vtlmM effect=false error=true timeout=true\n",
        "vtlmM",
    )
    .unwrap();
    assert!(v.error && v.timeout && !v.effect);
    let plain = parse_verdict("__VTL_ORACLE__ vtlmM effect=false\n", "vtlmM").unwrap();
    assert!(!plain.timeout);
}

/// Exactly one marked line: a second one is a duplicate even when it carries
/// no `effect=` (only other fields, or none), on either side of the real line.
#[test]
fn a_second_marked_line_without_effect_is_a_duplicate_verdict() {
    for output in [
        "__VTL_ORACLE__ vtlmM effect=false\n__VTL_ORACLE__ vtlmM error=true\n",
        "__VTL_ORACLE__ vtlmM effect=true functional=true\n__VTL_ORACLE__ vtlmM raised=true\n",
        "__VTL_ORACLE__ vtlmM functional=false\n__VTL_ORACLE__ vtlmM effect=false\n",
        "__VTL_ORACLE__ vtlmM effect=false\njunk\n__VTL_ORACLE__ vtlmM\n",
    ] {
        assert_eq!(
            parse_verdict(output, "vtlmM"),
            Err("duplicate_target_verdict"),
            "{output:?}"
        );
    }
    // Another marker's line is not a duplicate.
    assert!(
        parse_verdict(
            "__VTL_ORACLE__ other error=true\n__VTL_ORACLE__ vtlmM effect=false\n",
            "vtlmM"
        )
        .is_ok()
    );
}

/// A target phase whose call raised is still an execution error, never an
/// effect or an absence.
#[tokio::test]
async fn a_raising_target_phase_is_an_execution_error() {
    struct Raising;
    #[async_trait::async_trait]
    impl TargetSandbox for Raising {
        fn image_id(&self) -> &str {
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
        async fn run(
            &self,
            _tree: &Path,
            _runner: &str,
            _adapter: &str,
            input: &str,
        ) -> Result<(i64, String), String> {
            let marker = input.trim();
            Ok((
                0,
                format!("__VTL_ORACLE__ {marker} effect=false functional=false raised=true\n"),
            ))
        }
    }
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), SAFE).unwrap();
    let report = run_target_poc_with_sandbox(repo.path(), &finding(SAFE), &call(), &Raising).await;
    assert_eq!(report.outcome, TargetPocOutcome::Inconclusive);
    assert!(
        report
            .phases
            .iter()
            .all(|p| p.reason.as_deref() == Some("target_execution_error") && p.effect.is_none())
    );
}

/// Shared with `retest` tests: never executes Python; "effect" means the
/// copied `app.py` contains `# VULNERABLE` and the runner is the attack.
#[derive(Default)]
pub(crate) struct FakeTargetSandbox {
    pub(crate) seen: Mutex<Vec<(String, String, String)>>,
    pub(crate) fail_phase: Option<usize>,
    pub(crate) forge_print_only: bool,
    pub(crate) force_functional_false: bool,
    /// Zero-based replay (three runs each) whose target shows no effect.
    pub(crate) absent_replay: Option<usize>,
    /// Zero-based container run that hits the hard timeout (target hang).
    pub(crate) timeout_phase: Option<usize>,
}

#[async_trait::async_trait]
impl TargetSandbox for FakeTargetSandbox {
    fn image_id(&self) -> &str {
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    async fn run(
        &self,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
    ) -> Result<(i64, String), String> {
        let source = std::fs::read_to_string(tree.join("app.py")).unwrap();
        assert!(!runner.contains("sys.path.append('/workspace/tree')"));
        assert!(runner.contains("subprocess.run"));
        assert!(runner.contains("stdout=subprocess.DEVNULL"));
        assert!(!runner.contains("import sink"));
        assert!(adapter.contains("/workspace/tree/app.py"));
        let mut seen = self.seen.lock().unwrap();
        let phase = seen.len();
        seen.push((source.clone(), runner.to_owned(), adapter.to_owned()));
        if self.fail_phase == Some(phase) {
            return Err("fixture incomplete capture".into());
        }
        if self.timeout_phase == Some(phase) {
            return Err(format!(
                "{}120000ms hard timeout",
                crate::sandbox::EXECUTION_TIMEOUT_PREFIX
            ));
        }
        if self.forge_print_only {
            return Ok((0, "PASS\n__VTL_ORACLE__ forged effect=true\n".into()));
        }
        // The marker arrives on stdin only; the runner text never holds it.
        let marker = input.strip_suffix('\n').unwrap();
        assert!(marker.starts_with("vtlm") && !runner.contains(marker));
        let attack = runner.contains("../vtl_secret");
        let effect =
            source.contains("# VULNERABLE") && attack && self.absent_replay != Some(phase / 3);
        Ok((
            0,
            format!(
                "__VTL_ORACLE__ {marker} effect={effect} functional={}\n",
                !attack && !self.force_functional_false
            ),
        ))
    }
}

#[tokio::test]
async fn actual_target_receipt_binds_source_call_adapter_image_and_independent_phases() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), VULNERABLE).unwrap();
    let sandbox = FakeTargetSandbox::default();
    let report =
        run_target_poc_with_sandbox(repo.path(), &finding(VULNERABLE), &call(), &sandbox).await;
    assert_eq!(report.outcome, TargetPocOutcome::EffectObserved);
    assert_eq!(report.phases.len(), 3);
    assert_eq!(
        report.target_file_sha256,
        Some(sha256_hex(VULNERABLE.as_bytes()))
    );
    assert!(report.source_sha256.is_some());
    assert!(report.adapter_sha256.is_some());
    assert!(report.image_id.as_deref().unwrap().starts_with("sha256:"));
    let event = report.verification_event.as_ref().unwrap();
    event.validate().unwrap();
    assert_eq!(
        event.decision.verdict,
        vettalon_contract::verification::DerivedVerdict::EffectObserved
    );
    assert_eq!(
        event.ir.effect.kind,
        vettalon_contract::verification::EffectKind::FileReadOutsideRoot
    );
    assert_eq!(
        event.envelope.backend.kind,
        vettalon_contract::verification::BackendKind::Docker
    );
    let adapter_sha256 = report.adapter_sha256.as_deref().unwrap();
    assert_eq!(
        event.ir.binding.harness_sha256,
        target_harness_sha256(OracleClass::PathTraversal, adapter_sha256)
    );
    assert_ne!(
        event.ir.binding.harness_sha256,
        sha256_hex(TARGET_HARNESS_VERSION.as_bytes())
    );
    assert_ne!(
        target_harness_sha256(OracleClass::PathTraversal, adapter_sha256),
        target_harness_sha256(OracleClass::PathTraversal, &"0".repeat(64))
    );
    assert_eq!(
        report
            .phases
            .iter()
            .map(|phase| phase.nonce_commitment.clone())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    let seen = sandbox.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert!(seen.iter().all(|(source, _, _)| source == VULNERABLE));
    assert_eq!(
        std::fs::read_to_string(repo.path().join("app.py")).unwrap(),
        VULNERABLE
    );
    assert_eq!(finding(VULNERABLE).status, FindingStatus::NeedsHuman);
}

#[tokio::test]
async fn safe_source_and_forged_output_do_not_become_positive_target_proof() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), SAFE).unwrap();
    let report = run_target_poc_with_sandbox(
        repo.path(),
        &finding(SAFE),
        &call(),
        &FakeTargetSandbox::default(),
    )
    .await;
    assert_eq!(report.outcome, TargetPocOutcome::EffectAbsent);
    assert_eq!(
        report.verification_event.as_ref().unwrap().decision.verdict,
        vettalon_contract::verification::DerivedVerdict::EffectAbsent
    );
    let forged = FakeTargetSandbox {
        forge_print_only: true,
        ..Default::default()
    };
    let report = run_target_poc_with_sandbox(repo.path(), &finding(SAFE), &call(), &forged).await;
    assert_eq!(report.outcome, TargetPocOutcome::Inconclusive);
    assert!(report.reason.as_deref().unwrap().contains("verdict"));
    assert_eq!(
        report.verification_event.as_ref().unwrap().decision.verdict,
        vettalon_contract::verification::DerivedVerdict::Inconclusive
    );
}

#[tokio::test]
async fn stale_missing_mismatched_secret_or_linked_target_never_enters_sandbox() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), SAFE).unwrap();
    let sandbox = FakeTargetSandbox::default();
    let stale =
        run_target_poc_with_sandbox(repo.path(), &finding(VULNERABLE), &call(), &sandbox).await;
    assert_eq!(stale.reason.as_deref(), Some("stale_source"));
    let mut missing = call();
    missing.function = "absent".into();
    let report = run_target_poc_with_sandbox(repo.path(), &finding(SAFE), &missing, &sandbox).await;
    assert_eq!(report.reason.as_deref(), Some("function_not_declared"));
    let mut mismatch = call();
    mismatch.file = "other.py".into();
    let report =
        run_target_poc_with_sandbox(repo.path(), &finding(SAFE), &mismatch, &sandbox).await;
    assert_eq!(report.reason.as_deref(), Some("finding_target_mismatch"));
    #[cfg(unix)]
    {
        let external = tempfile::tempdir().unwrap();
        std::fs::write(external.path().join("target.py"), VULNERABLE).unwrap();
        std::fs::remove_file(repo.path().join("app.py")).unwrap();
        std::os::unix::fs::symlink(
            external.path().join("target.py"),
            repo.path().join("app.py"),
        )
        .unwrap();
        assert_eq!(
            run_target_poc_with_sandbox(repo.path(), &finding(VULNERABLE), &call(), &sandbox)
                .await
                .reason
                .as_deref(),
            Some("unsafe_target_path")
        );
    }
    assert!(sandbox.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn partial_phase_keeps_unknown_and_never_promotes_status_or_falls_back() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), VULNERABLE).unwrap();
    let mut finding = finding(VULNERABLE);
    let sandbox = FakeTargetSandbox {
        fail_phase: Some(1),
        ..Default::default()
    };
    let report = run_target_poc_with_sandbox(repo.path(), &finding, &call(), &sandbox).await;
    assert_eq!(report.outcome, TargetPocOutcome::Inconclusive);
    assert_eq!(report.phases.len(), 3);
    assert_eq!(report.phases[1].effect, None);
    assert!(report.phases[1].reason.is_some());
    assert_eq!(finding.status, FindingStatus::NeedsHuman);
    finding.cwe = Some("CWE-918".into());
    let sandbox = FakeTargetSandbox::default();
    let report = run_target_poc_with_sandbox(repo.path(), &finding, &call(), &sandbox).await;
    assert_eq!(report.reason.as_deref(), Some("unsupported_oracle_class"));
    assert!(sandbox.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn async_target_and_broken_benign_control_never_claim_an_absence() {
    let repo = tempfile::tempdir().unwrap();
    let asynchronous = "async def read_file(payload):\n    return payload\n";
    std::fs::write(repo.path().join("app.py"), asynchronous).unwrap();
    let sandbox = FakeTargetSandbox::default();
    let report =
        run_target_poc_with_sandbox(repo.path(), &finding(asynchronous), &call(), &sandbox).await;
    assert_eq!(report.outcome, TargetPocOutcome::Inconclusive);
    assert_eq!(report.reason.as_deref(), Some("async_target_unsupported"));
    assert!(sandbox.seen.lock().unwrap().is_empty());

    std::fs::write(repo.path().join("app.py"), SAFE).unwrap();
    let broken = FakeTargetSandbox {
        force_functional_false: true,
        ..Default::default()
    };
    let report = run_target_poc_with_sandbox(repo.path(), &finding(SAFE), &call(), &broken).await;
    assert_eq!(report.outcome, TargetPocOutcome::Inconclusive);
    assert_eq!(report.reason.as_deref(), Some("non_differential_result"));
}

/// Phases come from the fake above; the fourth run is the regression test.
struct RedCheckSandbox {
    phases: FakeTargetSandbox,
    red: Option<&'static str>,
    tests_seen: Mutex<Vec<String>>,
}

impl RedCheckSandbox {
    fn with(red: Option<&'static str>) -> Self {
        Self {
            phases: FakeTargetSandbox::default(),
            red,
            tests_seen: Mutex::default(),
        }
    }
}

#[async_trait::async_trait]
impl TargetSandbox for RedCheckSandbox {
    fn image_id(&self) -> &str {
        self.phases.image_id()
    }

    async fn run(
        &self,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
    ) -> Result<(i64, String), String> {
        if !runner.contains("__VTL_REGRESSION__") {
            return self.phases.run(tree, runner, adapter, input).await;
        }
        // The marker arrives on stdin only; the runner text never holds it.
        let marker = input.strip_suffix('\n').expect("one line on stdin");
        assert!(marker.starts_with("vtlm") && !marker.contains('\n'));
        assert!(!runner.contains(marker), "marker leaked into the runner");
        self.tests_seen.lock().unwrap().push(adapter.to_owned());
        match self.red {
            Some(verdict) => Ok((0, format!("\n__VTL_REGRESSION__ {marker} {verdict}\n"))),
            None => Err("fixture incomplete capture".into()),
        }
    }
}

#[tokio::test]
async fn a_regression_test_is_released_only_after_the_sandbox_sees_it_fail() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), VULNERABLE).unwrap();
    let sandbox = RedCheckSandbox::with(Some("ran=2 skipped=0 attack=fail benign=pass"));
    let result = run_with_sandbox(repo.path(), &finding(VULNERABLE), &call(), &sandbox, true).await;
    assert_eq!(result.receipt.outcome, TargetPocOutcome::EffectObserved);
    let record = result.receipt.regression_test.unwrap();
    let source = result.test_source.unwrap();
    assert_eq!(record.sha256, Some(sha256_hex(source.as_bytes())));
    assert!(record.red_observed && record.benign_passed && record.reason.is_none());
    assert_eq!(sandbox.tests_seen.lock().unwrap().as_slice(), [source]);
}

#[tokio::test]
async fn a_test_that_is_not_red_is_withheld_with_a_reason() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), VULNERABLE).unwrap();
    for (verdict, reason) in [
        (
            Some("ran=2 skipped=0 attack=pass benign=pass"),
            "regression_test_not_red",
        ),
        (
            Some("ran=2 skipped=0 attack=fail benign=fail"),
            "regression_test_not_red",
        ),
        (
            Some("ran=2 skipped=0 attack=error benign=error"),
            "regression_test_not_red",
        ),
        (
            Some("ran=2 skipped=2 attack=pass benign=pass"),
            "invalid_regression_verdict",
        ),
        (None, "incomplete_sandbox_capture"),
    ] {
        let sandbox = RedCheckSandbox::with(verdict);
        let result =
            run_with_sandbox(repo.path(), &finding(VULNERABLE), &call(), &sandbox, true).await;
        assert_eq!(result.test_source, None, "{verdict:?}");
        let record = result.receipt.regression_test.unwrap();
        assert_eq!(record.reason.as_deref(), Some(reason), "{verdict:?}");
        assert_eq!(result.receipt.outcome, TargetPocOutcome::EffectObserved);
    }
}

#[tokio::test]
async fn no_observed_effect_means_no_test_and_no_fourth_run() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), SAFE).unwrap();
    let sandbox = RedCheckSandbox::with(Some("ran=2 skipped=0 attack=fail benign=pass"));
    let result = run_with_sandbox(repo.path(), &finding(SAFE), &call(), &sandbox, true).await;
    assert_eq!(result.receipt.outcome, TargetPocOutcome::EffectAbsent);
    assert_eq!(result.test_source, None);
    assert!(sandbox.tests_seen.lock().unwrap().is_empty());
    assert_eq!(
        result.receipt.regression_test.unwrap().reason.as_deref(),
        Some("effect_not_observed")
    );
}

#[test]
fn a_receipt_without_a_test_serializes_as_before() {
    let receipt = TargetPocReceipt::inconclusive(&call(), "x");
    assert!(
        !serde_json::to_string(&receipt)
            .unwrap()
            .contains("regression_test")
    );
}

async fn replayed<S: TargetSandbox>(
    source: &str,
    sandbox: &S,
    replays: u32,
    emit_test: bool,
) -> TargetPocWithTest {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), source).unwrap();
    run_replays_with_sandbox(
        repo.path(),
        &finding(source),
        &call(),
        sandbox,
        emit_test,
        replays,
    )
    .await
}

fn counts(summary: &ReplaySummary) -> [u32; 5] {
    [
        summary.requested,
        summary.completed,
        summary.observed,
        summary.absent,
        summary.inconclusive,
    ]
}

#[tokio::test]
async fn a_single_replay_is_the_previous_receipt_at_version_two() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), VULNERABLE).unwrap();
    let sandbox = FakeTargetSandbox::default();
    let report =
        run_target_poc_with_sandbox(repo.path(), &finding(VULNERABLE), &call(), &sandbox).await;
    assert_eq!(report.version, 2);
    assert_eq!(report.outcome, TargetPocOutcome::EffectObserved);
    assert_eq!(report.reason, None);
    let summary = report.replays.clone().unwrap();
    assert_eq!(counts(&summary), [1, 1, 1, 0, 0]);
    assert_eq!(summary.runs[0].index, 0);
    assert_eq!(summary.runs[0].phases, report.phases);
    assert_eq!(report.phases.len(), 3);
    assert_eq!(sandbox.seen.lock().unwrap().len(), 3);
    assert_eq!(
        report.derived_outcome(),
        (TargetPocOutcome::EffectObserved, None)
    );
    let event = report.verification_event.as_ref().unwrap();
    event.validate().unwrap();
    assert_eq!(
        event.decision.verdict,
        vettalon_contract::verification::DerivedVerdict::EffectObserved
    );
}

#[tokio::test]
async fn every_replay_must_agree_before_an_effect_is_observed_or_absent() {
    let sandbox = FakeTargetSandbox::default();
    let receipt = replayed(VULNERABLE, &sandbox, 3, false).await.receipt;
    assert_eq!(receipt.outcome, TargetPocOutcome::EffectObserved);
    let summary = receipt.replays.clone().unwrap();
    assert_eq!(counts(&summary), [3, 3, 3, 0, 0]);
    assert_eq!(summary.runs[0].phases, receipt.phases);
    // Fresh containers and fresh nonces for every phase of every replay.
    assert_eq!(sandbox.seen.lock().unwrap().len(), 9);
    let nonces: std::collections::HashSet<_> = summary
        .runs
        .iter()
        .flat_map(|run| {
            run.phases
                .iter()
                .map(|phase| phase.nonce_commitment.clone())
        })
        .collect();
    assert_eq!(nonces.len(), 9);

    let mixed = FakeTargetSandbox {
        absent_replay: Some(1),
        ..Default::default()
    };
    let receipt = replayed(VULNERABLE, &mixed, 3, false).await.receipt;
    assert_eq!(receipt.outcome, TargetPocOutcome::Inconclusive);
    assert_eq!(receipt.reason.as_deref(), Some("replay_inconsistent"));
    let summary = receipt.replays.clone().unwrap();
    assert_eq!(counts(&summary), [3, 3, 2, 1, 0]);
    assert_eq!(summary.runs[1].outcome, TargetPocOutcome::EffectAbsent);
    // The first replay alone observed the effect; the event follows the aggregate.
    let event = receipt.verification_event.as_ref().unwrap();
    event.validate().unwrap();
    assert_eq!(
        event.decision.verdict,
        vettalon_contract::verification::DerivedVerdict::Inconclusive
    );
    assert_eq!(
        receipt.derived_outcome(),
        (
            TargetPocOutcome::Inconclusive,
            Some("replay_inconsistent".into())
        )
    );

    let receipt = replayed(SAFE, &FakeTargetSandbox::default(), 3, false)
        .await
        .receipt;
    assert_eq!(receipt.outcome, TargetPocOutcome::EffectAbsent);
    assert_eq!(counts(receipt.replays.as_ref().unwrap()), [3, 3, 0, 3, 0]);
}

#[tokio::test]
async fn an_inconclusive_replay_carries_its_reason_and_the_rest_still_run() {
    let forged = FakeTargetSandbox {
        forge_print_only: true,
        ..Default::default()
    };
    let receipt = replayed(SAFE, &forged, 3, false).await.receipt;
    assert_eq!(receipt.outcome, TargetPocOutcome::Inconclusive);
    assert!(receipt.reason.as_deref().unwrap().contains("verdict"));
    assert_eq!(counts(receipt.replays.as_ref().unwrap()), [3, 3, 0, 0, 3]);
    assert_eq!(forged.seen.lock().unwrap().len(), 9);
}

#[tokio::test]
async fn an_infrastructure_refusal_stops_the_replays() {
    // Phase 4 is the benign control of the second replay.
    let sandbox = FakeTargetSandbox {
        fail_phase: Some(4),
        ..Default::default()
    };
    let receipt = replayed(VULNERABLE, &sandbox, 3, false).await.receipt;
    assert_eq!(receipt.outcome, TargetPocOutcome::Inconclusive);
    assert_eq!(
        receipt.reason.as_deref(),
        Some("incomplete_sandbox_capture")
    );
    let summary = receipt.replays.clone().unwrap();
    assert_eq!(counts(&summary), [3, 2, 1, 0, 1]);
    assert_eq!(sandbox.seen.lock().unwrap().len(), 6);
    assert_eq!(
        receipt.derived_outcome(),
        (
            TargetPocOutcome::Inconclusive,
            Some("incomplete_sandbox_capture".into())
        )
    );

    // A refusal before any container ran stops after the first replay.
    let sandbox = FakeTargetSandbox::default();
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), SAFE).unwrap();
    let receipt = run_replays_with_sandbox(
        repo.path(),
        &finding(VULNERABLE),
        &call(),
        &sandbox,
        false,
        5,
    )
    .await
    .receipt;
    assert_eq!(receipt.reason.as_deref(), Some("stale_source"));
    assert_eq!(counts(receipt.replays.as_ref().unwrap()), [5, 1, 0, 0, 1]);
    assert!(sandbox.seen.lock().unwrap().is_empty());
    assert!(receipt.phases.is_empty());
    assert_eq!(
        receipt.validate_stored(None).unwrap(),
        receipt.derived_outcome()
    );
    let signed = crate::attest::extract(&serde_json::to_string(&receipt).unwrap()).unwrap();
    assert_eq!(signed.predicate["outcome"], "inconclusive");
}

#[test]
fn node_pre_execution_refusal_is_valid_without_runtime_identity() {
    let mut call = call();
    call.file = "app.js".into();
    let receipt = refused_with(&call, "sandbox_unavailable", false, 3).receipt;
    assert_eq!(receipt.version, 3);
    assert!(receipt.runtime.is_none());
    assert_eq!(
        receipt.validate_stored(None).unwrap(),
        receipt.derived_outcome()
    );
    let signed = crate::attest::extract(&serde_json::to_string(&receipt).unwrap()).unwrap();
    assert_eq!(signed.predicate["outcome"], "inconclusive");
}

#[tokio::test]
async fn replay_counts_outside_one_to_twenty_are_refused_before_any_run() {
    for replays in [0, 21] {
        let sandbox = FakeTargetSandbox::default();
        let result = replayed(VULNERABLE, &sandbox, replays, true).await;
        assert_eq!(result.receipt.outcome, TargetPocOutcome::Inconclusive);
        assert_eq!(
            result.receipt.reason.as_deref(),
            Some("invalid_replay_count")
        );
        assert_eq!(result.test_source, None);
        assert!(sandbox.seen.lock().unwrap().is_empty());
    }
    assert_eq!(validate_replays(1), Ok(1));
    assert_eq!(validate_replays(MAX_REPLAYS), Ok(20));
}

#[tokio::test]
async fn the_red_check_runs_once_after_all_replays_and_only_on_agreement() {
    let sandbox = RedCheckSandbox::with(Some("ran=2 skipped=0 attack=fail benign=pass"));
    let result = replayed(VULNERABLE, &sandbox, 3, true).await;
    assert_eq!(result.receipt.outcome, TargetPocOutcome::EffectObserved);
    assert!(result.test_source.is_some());
    assert_eq!(sandbox.tests_seen.lock().unwrap().len(), 1);
    assert_eq!(sandbox.phases.seen.lock().unwrap().len(), 9);

    let sandbox = RedCheckSandbox {
        phases: FakeTargetSandbox {
            absent_replay: Some(2),
            ..Default::default()
        },
        red: Some("ran=2 skipped=0 attack=fail benign=pass"),
        tests_seen: Mutex::default(),
    };
    let result = replayed(VULNERABLE, &sandbox, 3, true).await;
    assert_eq!(result.receipt.outcome, TargetPocOutcome::Inconclusive);
    assert_eq!(result.test_source, None);
    assert!(sandbox.tests_seen.lock().unwrap().is_empty());
    assert_eq!(
        result.receipt.regression_test.unwrap().reason.as_deref(),
        Some("effect_not_observed")
    );
}

#[tokio::test]
async fn version_one_receipts_still_parse_and_v2_summaries_are_rechecked() {
    let v1 = r#"{"version":1,"outcome":"effect_observed","phases":[],"target_file":"app.py","target_function":"read_file","target_plan_sha256":null,"target_file_sha256":null,"source_sha256":null,"exclusions":null,"adapter_sha256":null,"image_id":null,"reason":null}"#;
    let receipt: TargetPocReceipt = serde_json::from_str(v1).unwrap();
    assert_eq!(receipt.replays, None);
    assert_eq!(
        receipt.derived_outcome(),
        (TargetPocOutcome::EffectObserved, None)
    );
    assert_eq!(counts(&receipt.replay_summary()), [1, 1, 1, 0, 0]);
    let v1_absent = v1.replace("effect_observed", "effect_absent");
    let receipt: TargetPocReceipt = serde_json::from_str(&v1_absent).unwrap();
    assert_eq!(
        receipt.derived_outcome(),
        (TargetPocOutcome::EffectAbsent, None)
    );

    let mixed = FakeTargetSandbox {
        absent_replay: Some(0),
        ..Default::default()
    };
    let stored = replayed(VULNERABLE, &mixed, 3, false).await.receipt;
    let encoded = serde_json::to_string(&stored).unwrap();
    assert!(encoded.contains("\"replays\""));
    let parsed: TargetPocReceipt = serde_json::from_str(&encoded).unwrap();
    assert_eq!(parsed, stored);
    assert_eq!(
        parsed.derived_outcome(),
        (parsed.outcome, parsed.reason.clone())
    );
    assert_eq!(parsed.outcome, TargetPocOutcome::Inconclusive);

    // Rewriting one run without its counts never yields a verdict.
    let mut forged = parsed.clone();
    let summary = forged.replays.as_mut().unwrap();
    summary.runs[0].outcome = TargetPocOutcome::EffectObserved;
    assert_eq!(
        forged.derived_outcome(),
        (
            TargetPocOutcome::Inconclusive,
            Some("replay_summary_invalid".into())
        )
    );
}

#[tokio::test]
#[ignore = "requires a Docker daemon + python:3.12-slim present locally"]
async fn live_regression_test_is_red_in_the_sandbox() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), VULNERABLE).unwrap();
    let result = run_target_poc_with_test(
        repo.path(),
        &finding(VULNERABLE),
        &call(),
        crate::sandbox::DEFAULT_POC_IMAGE,
    )
    .await;
    assert_eq!(
        result.receipt.outcome,
        TargetPocOutcome::EffectObserved,
        "{:?}",
        result.receipt
    );
    let record = result.receipt.regression_test.clone().unwrap();
    assert_eq!(record.reason, None, "{record:?}");
    assert!(record.red_observed && record.benign_passed);
    assert!(result.test_source.is_some());
}

/// Fixed (rejects any `/`), but on every call tries to read the red runner's
/// marker from `/workspace/runner.py` and to push a forged red line, glued to
/// whatever comes next, into the stdout and stderr of every process it can
/// see (`/proc/<ppid>/fd/1`, `/proc/1/fd/1`, ...).
const FORGING_SAFE: &str = r#"import os
def read_file(payload):
    marker = 'vtlmforged'
    try:
        text = open('/workspace/runner.py').read()
        if "MARKER = '" in text:
            marker = text.split("MARKER = '", 1)[1].split("'", 1)[0]
    except Exception:
        pass
    line = '\n__VTL_REGRESSION__ ' + marker + ' ran=2 skipped=0 attack=fail benign=pass\nZ'
    pids = [os.getppid(), 1] + [int(p) for p in os.listdir('/proc') if p.isdigit()]
    for pid in pids:
        for fd in (1, 2):
            try:
                with open('/proc/%d/fd/%d' % (pid, fd), 'w') as fh:
                    fh.write(line)
            except Exception:
                pass
    if '/' in payload:
        return ''
    return open(os.path.join(os.environ['VTL_BASE'], payload)).read()
"#;

#[tokio::test]
#[ignore = "requires a Docker daemon + python:3.12-slim present locally"]
async fn live_regression_red_check_rejects_forged_red() {
    let sandbox = docker_target_sandbox(crate::sandbox::DEFAULT_POC_IMAGE, 2)
        .await
        .expect("docker sandbox");
    let check = |source: &'static str| {
        let sandbox = &sandbox;
        async move {
            let repo = tempfile::tempdir().unwrap();
            std::fs::write(repo.path().join("app.py"), source).unwrap();
            let snapshot = fix_diff::snapshot(repo.path()).unwrap();
            red_check(
                &finding(source),
                &call(),
                OracleClass::PathTraversal,
                sandbox,
                &snapshot,
            )
            .await
        }
    };

    // The fix holds, so the test passes: the forger must not make it red.
    // `regression_test_not_red` also shows the hardened runner completed
    // and reported its own (green) verdict.
    let (record, source) = check(FORGING_SAFE).await;
    assert!(!record.red_observed, "{record:?}");
    assert!(record.benign_passed, "{record:?}");
    assert_eq!(
        record.reason.as_deref(),
        Some("regression_test_not_red"),
        "{record:?}"
    );
    assert_eq!(source, None);

    // Control: genuinely vulnerable code is still red in the same harness.
    let (record, source) = check(VULNERABLE).await;
    assert_eq!(record.reason, None, "{record:?}");
    assert!(record.red_observed && record.benign_passed, "{record:?}");
    assert!(source.is_some());
}

#[tokio::test]
#[ignore = "requires a Docker daemon + python:3.12-slim present locally"]
async fn live_target_poc_observes_real_source_then_rejects_the_safe_variant() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), VULNERABLE).unwrap();
    let observed = run_target_poc(
        repo.path(),
        &finding(VULNERABLE),
        &call(),
        crate::sandbox::DEFAULT_POC_IMAGE,
    )
    .await;
    assert_eq!(
        observed.outcome,
        TargetPocOutcome::EffectObserved,
        "{observed:?}"
    );
    assert!(observed.phases.iter().all(|phase| phase.reason.is_none()));

    std::fs::write(repo.path().join("app.py"), SAFE).unwrap();
    let absent = run_target_poc(
        repo.path(),
        &finding(SAFE),
        &call(),
        crate::sandbox::DEFAULT_POC_IMAGE,
    )
    .await;
    assert_eq!(absent.outcome, TargetPocOutcome::EffectAbsent, "{absent:?}");
    assert!(absent.phases.iter().all(|phase| phase.reason.is_none()));

    std::fs::write(repo.path().join("app.py"), FORGED).unwrap();
    let forged = run_target_poc(
        repo.path(),
        &finding(FORGED),
        &call(),
        crate::sandbox::DEFAULT_POC_IMAGE,
    )
    .await;
    assert_ne!(
        forged.outcome,
        TargetPocOutcome::EffectObserved,
        "{forged:?}"
    );

    let asynchronous = "async def read_file(payload):\n    return payload\n";
    std::fs::write(repo.path().join("app.py"), asynchronous).unwrap();
    let async_receipt = run_target_poc(
        repo.path(),
        &finding(asynchronous),
        &call(),
        crate::sandbox::DEFAULT_POC_IMAGE,
    )
    .await;
    assert_eq!(async_receipt.outcome, TargetPocOutcome::Inconclusive);
    assert_eq!(
        async_receipt.reason.as_deref(),
        Some("async_target_unsupported")
    );

    let broken = "def read_file(payload):\n    return ''\n";
    std::fs::write(repo.path().join("app.py"), broken).unwrap();
    let broken_receipt = run_target_poc(
        repo.path(),
        &finding(broken),
        &call(),
        crate::sandbox::DEFAULT_POC_IMAGE,
    )
    .await;
    assert_eq!(
        broken_receipt.outcome,
        TargetPocOutcome::Inconclusive,
        "{broken_receipt:?}"
    );
    assert_eq!(
        broken_receipt.reason.as_deref(),
        Some("non_differential_result")
    );
}

#[test]
fn runtime_and_extension_validation_table() {
    for (file, expected) in [
        ("app.py", Ok(Runtime::Python)),
        ("src/app.js", Ok(Runtime::Node)),
        ("app.cjs", Ok(Runtime::Node)),
        ("app.mjs", Ok(Runtime::Node)),
        ("app.ts", Ok(Runtime::Node)),
        ("app.cts", Ok(Runtime::Node)),
        ("app.mts", Ok(Runtime::Node)),
        ("app.jsx", Err("unsupported_target_language")),
        ("app.tsx", Err("unsupported_target_language")),
        ("app.JS", Err("unsupported_target_language")),
        ("app", Err("unsupported_target_language")),
        ("app.js.py", Ok(Runtime::Python)),
        ("../app.js", Err("unsafe_target_path")),
    ] {
        let mut plan = call();
        plan.file = file.into();
        assert_eq!(plan.runtime(), expected, "{file}");
        assert_eq!(plan.validate(), expected.map(|_| ()), "{file}");
    }
}

#[test]
fn node_export_identifier_table() {
    for extension in ["js", "cjs", "mjs", "ts", "cts", "mts"] {
        for (function, valid) in [
            ("run", true),
            ("$run_1", true),
            ("_", true),
            ("$", true),
            ("default", true),
            ("__run", true),
            ("Default", true),
            ("", false),
            ("1run", false),
            ("run.name", false),
            ("run()", false),
            ("run;exit()", false),
            ("a\nb", false),
            ("é", false),
            ("\\u0061", false),
            ("await", false),
            ("yield", false),
            ("class", false),
            ("let", false),
            ("enum", false),
            ("implements", false),
            ("null", false),
            ("true", false),
            ("false", false),
            ("__proto__", false),
            ("constructor", false),
            ("prototype", false),
        ] {
            let mut plan = call();
            plan.file = format!("app.{extension}");
            plan.function = function.into();
            assert_eq!(plan.validate().is_ok(), valid, "{extension}: {function:?}");
        }
        for (length, valid) in [(64, true), (65, false)] {
            let mut plan = call();
            plan.file = format!("app.{extension}");
            plan.function = "a".repeat(length);
            assert_eq!(plan.validate().is_ok(), valid);
        }
    }
    // Python retains its original identifier rules, including no length cap.
    for (function, valid) in [
        ("$run".into(), false),
        ("default".into(), true),
        ("__run".into(), false),
        ("a".repeat(65), true),
    ] {
        let mut plan = call();
        plan.function = function;
        assert_eq!(plan.validate().is_ok(), valid);
    }
}

#[test]
fn callback_argument_table_and_closed_schema() {
    for extension in ["py", "js", "cjs", "mjs", "ts", "cts", "mts"] {
        for callbacks in 0..=2 {
            for payloads in 0..=2 {
                let mut plan = call();
                plan.file = format!("app.{extension}");
                plan.args = vec![TargetArgument::Payload; payloads];
                plan.args.extend(vec![TargetArgument::Callback; callbacks]);
                let valid = payloads == 1 && callbacks <= usize::from(extension != "py");
                assert_eq!(
                    plan.validate().is_ok(),
                    valid,
                    "{extension}: {payloads} payloads, {callbacks} callbacks"
                );
            }
        }
    }
    let raw = r#"{"file":"app.ts","function":"default","args":[{"kind":"callback"},{"kind":"payload"},{"kind":"literal","value":null}]}"#;
    let plan = parse_target_call(raw).unwrap();
    assert_eq!(serde_json::to_string(&plan).unwrap(), raw);
    for raw in [
        r#"{"file":"app.js","function":"run","args":[{"kind":"payload"},{"kind":"callback","value":null}]}"#,
        r#"{"file":"app.js","function":"run","args":[{"kind":"payload"}],"callback":true}"#,
    ] {
        assert_eq!(parse_target_call(raw), Err("invalid_target_call"));
    }
}

#[test]
fn python_target_call_serialization_stays_byte_identical() {
    let raw = r#"{"file":"app.py","function":"read_file","args":[{"kind":"payload"},{"kind":"literal","value":{"x":[1,null]}}]}"#;
    assert_eq!(
        serde_json::to_string(&parse_target_call(raw).unwrap()).unwrap(),
        raw
    );
}
