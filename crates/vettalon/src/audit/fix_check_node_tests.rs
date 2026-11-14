//! Node fix-check classification with synthetic runner verdicts; no Docker.
use super::super::node::dispatch::{self, Installer};
use super::super::target_poc::TargetCall;
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

const APP: &str = include_str!("../../tests/fixtures/node-e2e/esm-path/app.mjs");
const FIX: &str = include_str!("../../tests/fixtures/node-e2e/esm-path/fix.patch");

struct NodeSandbox {
    decoding_applicable: bool,
    original_reached: Option<bool>,
    original_flags: &'static str,
    scored_variant_effect: bool,
    scored_variant_reached: Option<bool>,
    decoding_reached: Option<bool>,
    decoding_flags: &'static str,
    fixed_reached: Option<bool>,
    fixed_flags: &'static str,
    benign_raises: bool,
    original_benign_flags: Option<&'static str>,
    fixed_benign_flags: Option<&'static str>,
    fixed_benign_effect: bool,
    listener_failure: Option<bool>,
    listener_benign_only: bool,
    listener_marked_verdict: bool,
    test_runs: AtomicUsize,
    decoding_runs: AtomicUsize,
}

impl Default for NodeSandbox {
    fn default() -> Self {
        Self {
            decoding_applicable: false,
            original_reached: Some(true),
            original_flags: "",
            scored_variant_effect: true,
            scored_variant_reached: Some(true),
            decoding_reached: Some(true),
            decoding_flags: "raised=true",
            fixed_reached: None,
            fixed_flags: "raised=true",
            benign_raises: false,
            original_benign_flags: None,
            fixed_benign_flags: None,
            fixed_benign_effect: false,
            listener_failure: None,
            listener_benign_only: false,
            listener_marked_verdict: false,
            test_runs: AtomicUsize::new(0),
            decoding_runs: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl Installer for NodeSandbox {
    async fn version(&self) -> Result<String, &'static str> {
        Ok("v22.15.0".into())
    }

    async fn install(
        &self,
        _manifest: &[u8],
        _lock: &[u8],
    ) -> Result<Option<crate::sandbox::InstalledDependencies>, &'static str> {
        panic!("dependency-free fixture must not install")
    }
}

#[async_trait::async_trait]
impl FixSandbox for NodeSandbox {
    fn image_identity(&self) -> Option<&str> {
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    }

    async fn prepare_node(&self, tree: &Path) -> Result<Arc<NodeExecution>, &'static str> {
        dispatch::prepare(tree, self, None).await.map(Arc::new)
    }

    async fn run_harness(
        &self,
        _tree: &Path,
        _runner: &str,
        _adapter: &str,
        _input: &str,
    ) -> Result<String, String> {
        panic!("Node must use its own runner")
    }

    async fn run_tests(&self, _tree: &Path, _command: &str) -> Result<i64, String> {
        panic!("Node must use its own test dispatch")
    }

    async fn run_node_tests(
        &self,
        _node: &NodeExecution,
        _tree: &Path,
        _command: &str,
    ) -> Result<i64, String> {
        self.test_runs.fetch_add(1, SeqCst);
        Ok(0)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_node(
        &self,
        _node: &NodeExecution,
        tree: &Path,
        runner: &str,
        _adapter: &str,
        input: &str,
        class: crate::audit::poc_oracle::OracleClass,
    ) -> Result<String, String> {
        let source = std::fs::read_to_string(tree.join("app.mjs")).unwrap();
        let fixed = source != APP;
        let payload = runner
            .lines()
            .find_map(|line| line.strip_prefix("PAYLOAD = "))
            .unwrap();
        let payload: String = serde_json::from_str(payload).unwrap();
        let benign = payload == benign_input(class);
        if self.listener_failure == Some(fixed) && (!self.listener_benign_only || benign) {
            let output = if self.listener_marked_verdict {
                format!(
                    "__VTL_ORACLE__ {} effect=true reached=true functional=true\n",
                    input.trim()
                )
            } else {
                String::new()
            };
            return successful_harness_output(4, output, input.trim());
        }
        let decoding = if class == OracleClass::Ssrf {
            super::super::variants::variant_set_for(class, Runtime::Node)
                .variants
                .iter()
                .find(|item| item.input == payload)
                .is_some_and(|item| item.requires_decoding)
        } else {
            payload.contains('%')
        };
        if decoding {
            self.decoding_runs.fetch_add(1, SeqCst);
        }
        let scored_variant = payload == "./../vtl_secret";
        let effect = (fixed && benign && self.fixed_benign_effect)
            || (!fixed
                && !benign
                && (!decoding || self.decoding_applicable)
                && (!scored_variant || self.scored_variant_effect));
        let (reached, flags) = if fixed {
            let flags = if benign {
                if let Some(flags) = self.fixed_benign_flags {
                    flags
                } else if self.benign_raises {
                    "raised=true"
                } else {
                    "functional=true"
                }
            } else {
                self.fixed_flags
            };
            (self.fixed_reached, flags)
        } else {
            let flags = if let Some(flags) = self.original_benign_flags.filter(|_| benign) {
                flags
            } else if !self.original_flags.is_empty() {
                self.original_flags
            } else if decoding && !effect {
                self.decoding_flags
            } else {
                "functional=true"
            };
            let reached = if decoding {
                self.decoding_reached
            } else if scored_variant {
                self.scored_variant_reached
            } else {
                self.original_reached
            };
            (reached, flags)
        };
        let reach = serde_json::json!({
            "reach_source": "in_process_hook",
            "events_total": if reached.is_some() { 1 } else { 0 },
            "first_match": if reached == Some(true) {
                serde_json::json!({
                    "api": "fs.readFileSync", "field": "path",
                    "display": "fixture path", "payload_in_text": null
                })
            } else { serde_json::Value::Null }
        });
        let reached = match reached {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        };
        Ok(format!(
            "__VTL_ORACLE__ {} effect={effect} reached={reached} reach={} {flags}\n",
            input.trim(),
            hex::encode(reach.to_string())
        ))
    }
}

async fn check_node(sandbox: &NodeSandbox) -> FixCheckRun {
    check_node_class(sandbox, OracleClass::PathTraversal).await
}

async fn check_node_class(sandbox: &NodeSandbox, class: OracleClass) -> FixCheckRun {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.mjs"), APP).unwrap();
    let call: TargetCall = serde_json::from_str(include_str!(
        "../../tests/fixtures/node-e2e/esm-path/target.json"
    ))
    .unwrap();
    check_target_fix_bound(
        dir.path(),
        &TargetFixRequest {
            class,
            call: &call,
            diff: FIX,
            test_command: Some("true"),
        },
        sandbox,
        VerificationTarget {
            file: "app.mjs",
            file_hash: Some(&sha256_hex(APP.as_bytes())),
        },
        None,
    )
    .await
}

#[tokio::test]
async fn node_fixed_raising_decoding_inputs_follow_python_counts() {
    for decoding_applicable in [false, true] {
        for fixed_reached in [None, Some(false), Some(true)] {
            let sandbox = NodeSandbox {
                decoding_applicable,
                fixed_reached,
                ..Default::default()
            };
            let run = check_node(&sandbox).await;
            let check = &run.check;
            assert_eq!(run.outcome(), FixOutcome::FixVerified, "{check:?}");
            assert_eq!((check.inputs_blocked, check.inputs_total), (5, 5));
            let applicable = if decoding_applicable { 2 } else { 0 };
            assert_eq!(
                (
                    check.decoding_blocked,
                    check.decoding_applicable,
                    check.decoding_total
                ),
                (applicable, applicable, 2)
            );
            assert_eq!(check.tests, CheckResult::Pass);
            assert_eq!(sandbox.test_runs.load(SeqCst), 2);
            let stamp = check.variant_set.as_ref().unwrap();
            assert!(stamp.decoding_ids_not_blocked.is_empty());
            let expected = if decoding_applicable {
                vec![]
            } else {
                vec!["path-pct-dot", "path-pct-slash"]
            };
            assert_eq!(stamp.decoding_ids_not_applicable, expected);
            let reach = run.reach_summary.unwrap();
            // Existing diagnostics include the successful benign run too.
            assert_eq!(
                reach.blocked_at_sink,
                if fixed_reached == Some(true) { 8 } else { 0 }
            );
            assert_eq!(
                reach.blocked_before_sink,
                if fixed_reached == Some(true) { 0 } else { 8 }
            );
        }
    }
}

#[tokio::test]
async fn node_fixed_always_raises_is_rejected_by_benign_control() {
    let sandbox = NodeSandbox {
        benign_raises: true,
        ..Default::default()
    };
    let run = check_node(&sandbox).await;
    assert_eq!(run.outcome(), FixOutcome::FixRejected);
    assert_eq!(run.check.benign, CheckResult::Fail);
    assert_eq!(run.check.reason.as_deref(), Some("fix_breaks_benign_input"));
    assert_eq!(sandbox.test_runs.load(SeqCst), 0);
}

#[tokio::test]
async fn node_fixed_runner_error_is_never_blocked() {
    for fixed_flags in ["error=true", "error=true raised=true"] {
        let sandbox = NodeSandbox {
            decoding_applicable: true,
            fixed_flags,
            ..Default::default()
        };
        let run = check_node(&sandbox).await;
        assert_eq!(run.outcome(), FixOutcome::FixUnverified);
        assert_eq!(run.check.reason.as_deref(), Some(FIXED_COPY_NO_VERDICT));
        assert_eq!(run.check.inputs_blocked, 0);
        assert_eq!(
            (run.check.decoding_blocked, run.check.decoding_applicable),
            (0, 2)
        );
        assert_eq!(sandbox.test_runs.load(SeqCst), 0);
    }
}

#[tokio::test]
async fn node_original_still_requires_reach_and_rejects_execution_failures() {
    for original_reached in [None, Some(false)] {
        let sandbox = NodeSandbox {
            original_reached,
            ..Default::default()
        };
        let run = check_node(&sandbox).await;
        assert_eq!(run.outcome(), FixOutcome::FixUnverified);
        assert_eq!(
            run.check.reason.as_deref(),
            Some("original_effect_without_reach")
        );
    }
    for original_flags in ["raised=true", "error=true"] {
        let sandbox = NodeSandbox {
            original_flags,
            ..Default::default()
        };
        let run = check_node(&sandbox).await;
        assert_eq!(run.outcome(), FixOutcome::FixUnverified);
        assert_eq!(run.check.reason.as_deref(), Some("target_execution_error"));
    }
}

#[tokio::test]
async fn node_original_decoding_without_effect_is_not_applicable_regardless_of_reach() {
    for decoding_flags in ["raised=true", "functional=true"] {
        for decoding_reached in [None, Some(false), Some(true)] {
            let sandbox = NodeSandbox {
                decoding_flags,
                decoding_reached,
                ..Default::default()
            };
            let run = check_node(&sandbox).await;
            let check = &run.check;
            assert_eq!(run.outcome(), FixOutcome::FixVerified, "{check:?}");
            assert_eq!((check.inputs_blocked, check.inputs_total), (5, 5));
            assert_eq!(
                (
                    check.decoding_blocked,
                    check.decoding_applicable,
                    check.decoding_total
                ),
                (0, 0, 2)
            );
            assert_eq!(check.tests, CheckResult::Pass);
            assert_eq!(check.reason, None);
            assert_eq!(sandbox.test_runs.load(SeqCst), 2);
            assert_eq!(sandbox.decoding_runs.load(SeqCst), 4);
            let stamp = check.variant_set.as_ref().unwrap();
            assert_eq!(
                stamp.decoding_ids_not_applicable,
                vec!["path-pct-dot", "path-pct-slash"]
            );
            assert!(stamp.decoding_ids_not_blocked.is_empty());
        }
    }
}

#[tokio::test]
async fn node_original_decoding_effect_without_reach_remains_inconclusive() {
    for decoding_reached in [None, Some(false)] {
        let sandbox = NodeSandbox {
            decoding_applicable: true,
            decoding_reached,
            ..Default::default()
        };
        let run = check_node(&sandbox).await;
        let check = &run.check;
        assert_eq!(run.outcome(), FixOutcome::FixUnverified, "{check:?}");
        assert_eq!(check.original, CheckResult::Pass);
        assert_eq!(check.variants, CheckResult::Inconclusive);
        assert_eq!(
            check.reason.as_deref(),
            Some("original_effect_without_reach")
        );
        assert_eq!(
            (
                check.decoding_blocked,
                check.decoding_applicable,
                check.decoding_total
            ),
            (0, 0, 2)
        );
        assert_eq!(sandbox.decoding_runs.load(SeqCst), 1);
        assert_eq!(sandbox.test_runs.load(SeqCst), 0);
        assert!(
            check
                .variant_set
                .as_ref()
                .unwrap()
                .decoding_ids_not_applicable
                .is_empty()
        );
    }
}

#[tokio::test]
async fn node_original_scored_variant_still_requires_reach() {
    for scored_variant_reached in [None, Some(false)] {
        for scored_variant_effect in [false, true] {
            let sandbox = NodeSandbox {
                scored_variant_effect,
                scored_variant_reached,
                ..Default::default()
            };
            let run = check_node(&sandbox).await;
            assert_eq!(run.outcome(), FixOutcome::FixUnverified);
            assert_eq!(run.check.original, CheckResult::Pass);
            assert_eq!(
                run.check.reason.as_deref(),
                Some(if scored_variant_effect {
                    "original_effect_without_reach"
                } else {
                    "original_sink_not_reached"
                })
            );
            assert_eq!(sandbox.test_runs.load(SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn node_original_decoding_still_requires_valid_runner() {
    for (decoding_flags, reason) in [
        ("raised=true error=true", "target_execution_error"),
        ("raised=true error=true timeout=true", "target_timeout"),
        ("raised=true missing=true", "target_missing"),
    ] {
        let sandbox = NodeSandbox {
            decoding_flags,
            decoding_reached: Some(false),
            ..Default::default()
        };
        let run = check_node(&sandbox).await;
        assert_eq!(run.outcome(), FixOutcome::FixUnverified);
        assert_eq!(run.check.reason.as_deref(), Some(reason));
    }
}

#[tokio::test]
async fn ssrf_fix_benign_table_requires_confirmed_functionality() {
    for (flags, effect, result, reason) in [
        ("functional=true", false, CheckResult::Pass, None),
        (
            "functional=true",
            true,
            CheckResult::Fail,
            Some("fix_breaks_benign_input"),
        ),
        (
            "functional=false",
            true,
            CheckResult::Fail,
            Some("fix_breaks_benign_input"),
        ),
        (
            "raised=true",
            true,
            CheckResult::Fail,
            Some("fix_breaks_benign_input"),
        ),
        (
            "functional=false",
            false,
            CheckResult::Inconclusive,
            Some("ssrf_benign_unconfirmed"),
        ),
        (
            "raised=true",
            false,
            CheckResult::Inconclusive,
            Some("ssrf_benign_unconfirmed"),
        ),
        (
            "",
            false,
            CheckResult::Inconclusive,
            Some("ssrf_benign_unconfirmed"),
        ),
    ] {
        let sandbox = NodeSandbox {
            fixed_benign_flags: Some(flags),
            fixed_benign_effect: effect,
            ..Default::default()
        };
        let run = check_node_class(&sandbox, OracleClass::Ssrf).await;
        assert_eq!(
            run.check.benign, result,
            "{flags} {effect}: {:?}",
            run.check
        );
        assert_eq!(run.check.reason.as_deref(), reason, "{:?}", run.check);
        assert_eq!(run.check.blocker(), Blocker::None);
        assert_eq!(
            run.outcome(),
            match result {
                CheckResult::Pass => FixOutcome::FixVerified,
                CheckResult::Fail => FixOutcome::FixRejected,
                _ => FixOutcome::FixUnverified,
            }
        );
        assert_eq!((run.check.inputs_blocked, run.check.inputs_total), (14, 14));
        // Stored fix receipts also infer the Node-only variant set without a class.
        let stored: FixCheckRun =
            serde_json::from_slice(&serde_json::to_vec(&run).unwrap()).unwrap();
        assert_eq!(stored.outcome(), run.outcome());
    }
    for flags in ["", "functional=false"] {
        let sandbox = NodeSandbox {
            original_benign_flags: Some(flags),
            ..Default::default()
        };
        let run = check_node_class(&sandbox, OracleClass::Ssrf).await;
        assert_eq!(run.check.benign, CheckResult::Inconclusive);
        assert_eq!(
            run.check.reason.as_deref(),
            Some("benign_control_unavailable")
        );
        assert_eq!(run.outcome(), FixOutcome::FixUnverified);
    }
}

#[tokio::test]
async fn ssrf_fix_listener_failure_stops_either_copy_as_environment_blocker() {
    for fixed in [false, true] {
        for listener_benign_only in [false, true] {
            let sandbox = NodeSandbox {
                listener_failure: Some(fixed),
                listener_benign_only,
                ..Default::default()
            };
            let run = check_node_class(&sandbox, OracleClass::Ssrf).await;
            assert_eq!(run.outcome(), FixOutcome::FixUnverified, "{:?}", run.check);
            assert_eq!(
                run.check.reason.as_deref(),
                Some("ssrf_listener_unavailable"),
                "{:?}",
                run.check
            );
            assert_eq!(run.check.blocker(), Blocker::Environment);
            assert!(!run.check.to_detail().contains(FIXED_COPY_NO_VERDICT));
        }
    }
}

#[tokio::test]
async fn python_ssrf_fix_is_refused_before_sandbox_setup() {
    let mut finding = Finding::candidate(
        "ai_audit",
        super::super::schema::FindingKind::Other,
        super::super::schema::Severity::High,
        "SSRF",
        "app.py",
        Some(1),
        "def run(url): return url",
        "ai-audit/ssrf",
        vec![],
    );
    finding.cwe = Some("CWE-918".into());
    let call = TargetCall {
        file: finding.file.clone(),
        function: "run".into(),
        args: vec![super::super::target_poc::TargetArgument::Payload],
    };
    let repo = tempfile::tempdir().unwrap();
    let run = run_target_fix(repo.path(), &finding, &call, FIX, None, "unused", None).await;
    assert_eq!(
        run.check.reason.as_deref(),
        Some("unsupported_oracle_class")
    );
    assert_eq!(run.check.blocker(), Blocker::None);
    assert_eq!(current_variant_identity(&finding), None);
}

#[tokio::test]
async fn ssrf_fix_exit_four_with_marked_verdict_is_execution_error() {
    for fixed in [false, true] {
        let sandbox = NodeSandbox {
            listener_failure: Some(fixed),
            listener_marked_verdict: true,
            ..Default::default()
        };
        let run = check_node_class(&sandbox, OracleClass::Ssrf).await;
        assert_ne!(run.outcome(), FixOutcome::FixVerified, "{:?}", run.check);
        assert_eq!(
            run.check.reason.as_deref(),
            Some(if fixed {
                FIXED_COPY_NO_VERDICT
            } else {
                "sandbox_error"
            }),
            "{:?}",
            run.check
        );
    }
}

#[test]
fn ssrf_listener_failure_ignores_other_runs_markers() {
    let error = successful_harness_output(4, "__VTL_ORACLE__ other effect=true\n".into(), "marker")
        .unwrap_err();
    assert_eq!(harness_exit_code(&error), Some(4));
}
