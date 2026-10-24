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
        "file.js",
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
}

#[derive(Default)]
struct FakeTargetSandbox {
    seen: Mutex<Vec<(String, String, String)>>,
    fail_phase: Option<usize>,
    forge_print_only: bool,
    force_functional_false: bool,
}

#[async_trait::async_trait]
impl TargetSandbox for FakeTargetSandbox {
    fn image_id(&self) -> &str {
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    async fn run(&self, tree: &Path, runner: &str, adapter: &str) -> Result<(i64, String), String> {
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
        if self.forge_print_only {
            return Ok((0, "PASS\n__VTL_ORACLE__ forged effect=true\n".into()));
        }
        let marker = runner
            .split("MARKER = '")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap();
        let attack = runner.contains("../vtl_secret");
        let effect = source.contains("# VULNERABLE") && attack;
        Ok((
            0,
            format!(
                "__VTL_ORACLE__ {marker} effect={effect}\n__VTL_ORACLE__ {marker} functional={}\n",
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
