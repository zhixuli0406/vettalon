use super::*;
use crate::audit::verification_context::VerificationTarget;
use crate::audit::{
    fix_check::*,
    schema::{Finding, FindingKind, Severity},
    target_poc::*,
};
use std::sync::atomic::{AtomicUsize, Ordering};

const SOURCE: &str = "export function read(x) { return x; }\n";
const SECRET: &str = "arbitrary-auth-value-without-secret-pattern";

#[derive(Default)]
struct Fake {
    installs: AtomicUsize,
    prepares: AtomicUsize,
    executions: AtomicUsize,
    contexts: std::sync::Mutex<Vec<usize>>,
    unavailable: bool,
    fixture: Option<fixture::NodeFixture>,
}

#[async_trait::async_trait]
impl Installer for Fake {
    async fn version(&self) -> Result<String, &'static str> {
        if self.unavailable {
            Err("node_runtime_unavailable")
        } else {
            Ok("v26.0.0".into())
        }
    }
    async fn install(
        &self,
        _: &[u8],
        _: &[u8],
    ) -> Result<Option<InstalledDependencies>, &'static str> {
        self.installs.fetch_add(1, Ordering::Relaxed);
        Ok(None)
    }
}

impl Fake {
    fn output(&self, node: &NodeExecution, tree: &Path, runner: &str, input: &str) -> String {
        assert!(tree.join("node_modules").is_dir());
        assert!(!tree.join("node_modules/host-only").exists());
        assert!(runner.contains("/usr/local/bin/node"));
        self.executions.fetch_add(1, Ordering::Relaxed);
        self.contexts
            .lock()
            .unwrap()
            .push(node as *const _ as usize);
        let source = std::fs::read_to_string(tree.join("app.mjs")).unwrap();
        let attack = !runner.contains("PAYLOAD = \"safe.txt\"");
        let fixed = source.contains("FIXED");
        let reached = !fixed || !attack;
        let first = reached.then(|| serde_json::json!({"api":SECRET,"field":"path","display":SECRET,"payload_in_text":null}));
        let reach = hex::encode(
            serde_json::to_vec(&serde_json::json!({
                "reach_source":"in_process_hook", "events_total":1, "first_match":first
            }))
            .unwrap(),
        );
        format!(
            "__VTL_ORACLE__ {} effect={} functional={} reached={reached} reach={reach}\n",
            input.trim(),
            attack && !fixed,
            !attack
        )
    }
}

#[async_trait::async_trait]
impl TargetSandbox for Fake {
    fn image_id(&self) -> &str {
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
    async fn prepare_node(&self, tree: &Path) -> Result<Arc<NodeExecution>, &'static str> {
        self.prepares.fetch_add(1, Ordering::Relaxed);
        prepare(tree, self, self.fixture.clone())
            .await
            .map(Arc::new)
    }
    async fn run(&self, _: &Path, _: &str, _: &str, _: &str) -> Result<(i64, String), String> {
        panic!("Node must not enter Python dispatch")
    }
    #[allow(clippy::too_many_arguments)]
    async fn run_node(
        &self,
        node: &NodeExecution,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
        _class: crate::audit::poc_oracle::OracleClass,
    ) -> Result<(i64, String), String> {
        assert!(adapter.contains("await import(targetUrl)"));
        Ok((0, self.output(node, tree, runner, input)))
    }
}

#[async_trait::async_trait]
impl FixSandbox for Fake {
    fn image_identity(&self) -> Option<&str> {
        Some(self.image_id())
    }
    async fn prepare_node(&self, tree: &Path) -> Result<Arc<NodeExecution>, &'static str> {
        TargetSandbox::prepare_node(self, tree).await
    }
    async fn run_harness(&self, _: &Path, _: &str, _: &str, _: &str) -> Result<String, String> {
        panic!("Node must not enter Python dispatch")
    }
    async fn run_tests(&self, _: &Path, _: &str) -> Result<i64, String> {
        panic!("Node must not enter Python project tests")
    }
    async fn run_node_tests(&self, _: &NodeExecution, _: &Path, _: &str) -> Result<i64, String> {
        Ok(0)
    }
    #[allow(clippy::too_many_arguments)]
    async fn run_node(
        &self,
        node: &NodeExecution,
        tree: &Path,
        runner: &str,
        _: &str,
        input: &str,
        _class: crate::audit::poc_oracle::OracleClass,
    ) -> Result<String, String> {
        Ok(self.output(node, tree, runner, input))
    }
}

fn project(deps: bool) -> (tempfile::TempDir, Finding, TargetCall) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.mjs"), SOURCE).unwrap();
    std::fs::create_dir(dir.path().join("node_modules")).unwrap();
    std::fs::write(dir.path().join("node_modules/host-only"), "excluded").unwrap();
    let manifest = if deps {
        serde_json::json!({"dependencies":{"a":"1.0.0"}})
    } else {
        serde_json::json!({})
    };
    std::fs::write(dir.path().join("package.json"), manifest.to_string()).unwrap();
    if deps {
        let integrity = format!("sha512-{}==", "A".repeat(86));
        let lock = serde_json::json!({"lockfileVersion":3,"packages":{"":manifest,"node_modules/a":{
            "version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":integrity
        }}});
        std::fs::write(dir.path().join("package-lock.json"), lock.to_string()).unwrap();
    }
    let mut finding = Finding::candidate(
        "semgrep",
        FindingKind::Other,
        Severity::High,
        "path read",
        "app.mjs",
        Some(1),
        SOURCE,
        "node-e2e",
        vec![],
    );
    finding.cwe = Some("CWE-22".into());
    finding.file_hash = Some(sha256_hex(SOURCE.as_bytes()));
    let call = TargetCall {
        file: "app.mjs".into(),
        function: "read".into(),
        args: vec![TargetArgument::Payload],
    };
    (dir, finding, call)
}

#[tokio::test]
async fn install_once_and_reuse_across_replays_without_fixture_values_in_receipts() {
    let (dir, finding, call) = project(true);
    let fixture = fixture::validate_fixture(
        serde_json::json!({"schema":fixture::FIXTURE_SCHEMA,"env":{"TOKEN":SECRET}})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let digest = fixture.sha256().to_string();
    let fake = Fake {
        fixture: Some(fixture),
        ..Default::default()
    };
    let result = run_replays_until(dir.path(), &finding, &call, &fake, false, 3, None).await;
    assert_eq!(result.receipt.outcome, TargetPocOutcome::EffectObserved);
    assert_eq!(fake.installs.load(Ordering::Relaxed), 1);
    assert_eq!(fake.prepares.load(Ordering::Relaxed), 1);
    assert_eq!(fake.executions.load(Ordering::Relaxed), 9);
    let contexts = fake.contexts.lock().unwrap();
    assert!(contexts.iter().all(|ptr| ptr == &contexts[0]));
    let json = serde_json::to_string(&result.receipt).unwrap();
    assert!(!json.contains(SECRET));
    assert!(json.contains(&digest));
    assert!(result.receipt.validate_stored(None).is_ok());
}

#[tokio::test]
async fn dependency_free_project_skips_install_and_refusals_run_no_phases() {
    let (dir, finding, call) = project(false);
    let fake = Fake::default();
    let result = run_replays_until(dir.path(), &finding, &call, &fake, false, 2, None).await;
    assert_eq!(result.receipt.outcome, TargetPocOutcome::EffectObserved);
    assert_eq!(fake.installs.load(Ordering::Relaxed), 0);
    for (manifest, lock, unavailable, reason) in [
        ("{}", None, true, "node_runtime_unavailable"),
        (
            r#"{"dependencies":{"a":"1.0.0"}}"#,
            None,
            false,
            "node_lockfile_missing",
        ),
        (
            "{}",
            Some("{\"lockfileVersion\":1}"),
            false,
            "node_lockfile_refused",
        ),
        (
            r#"{"dependencies":{"a":"file:../a"}}"#,
            None,
            false,
            "node_lockfile_refused",
        ),
    ] {
        std::fs::write(dir.path().join("package.json"), manifest).unwrap();
        if let Some(lock) = lock {
            std::fs::write(dir.path().join("package-lock.json"), lock).unwrap();
        } else {
            let _ = std::fs::remove_file(dir.path().join("package-lock.json"));
        }
        let fake = Fake {
            unavailable,
            ..Default::default()
        };
        let result = run_replays_until(dir.path(), &finding, &call, &fake, false, 3, None).await;
        assert_eq!(result.receipt.reason.as_deref(), Some(reason));
        assert_eq!(fake.executions.load(Ordering::Relaxed), 0);
        assert_eq!(fake.installs.load(Ordering::Relaxed), 0);
        assert_eq!(
            crate::audit::retest::status_for(result.receipt.outcome, Some(reason)),
            crate::audit::retest::RetestStatus::EnvironmentUnavailable
        );
    }
}

#[tokio::test]
async fn fix_variants_reuse_one_install_and_refuse_dependency_diffs() {
    let (dir, finding, call) = project(true);
    let diff = format!(
        "--- a/app.mjs\n+++ b/app.mjs\n@@ -1 +1 @@\n-{}+export function read(x) {{ return 'FIXED'; }}\n",
        SOURCE
    );
    let target = VerificationTarget {
        file: &finding.file,
        file_hash: finding.file_hash.as_deref(),
    };
    let request = TargetFixRequest {
        class: crate::audit::poc_oracle::OracleClass::PathTraversal,
        call: &call,
        diff: &diff,
        test_command: Some("node --version"),
    };
    let fake = Fake::default();
    let result = check_target_fix_bound(dir.path(), &request, &fake, target, None).await;
    assert_eq!(
        result.check.outcome(),
        FixOutcome::FixVerified,
        "{} {:?}",
        result.check.to_detail(),
        result.note
    );
    assert!(result.binding.as_ref().unwrap().complete());
    assert!(result.runtime.is_some());
    assert!(result.reach_summary.unwrap().blocked_before_sink > 0);
    assert_eq!(fake.installs.load(Ordering::Relaxed), 1);
    assert_eq!(fake.prepares.load(Ordering::Relaxed), 1);
    {
        let contexts = fake.contexts.lock().unwrap();
        assert!(contexts.len() > 6);
        assert!(contexts.iter().all(|ptr| ptr == &contexts[0]));
    }
    for path in [
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "sub/package.json",
        "node_modules/a/index.js",
    ] {
        let diff = format!("--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n");
        let fake = Fake::default();
        let request = TargetFixRequest {
            diff: &diff,
            ..request
        };
        let result = check_target_fix_bound(dir.path(), &request, &fake, target, None).await;
        assert_eq!(
            result.check.reason.as_deref(),
            Some("diff_changes_dependencies")
        );
        assert_eq!(result.check.blocker(), Blocker::None);
        assert_eq!(fake.prepares.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn fixture_errors_never_include_values_and_inputs_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("fixture.json");
    std::fs::write(&file, format!("{{\"secret\":\"{SECRET}\"}}")).unwrap();
    assert_eq!(
        NodeOptions::read(
            "local".into(),
            Some(&file),
            tempfile::tempdir().unwrap().path()
        )
        .err()
        .unwrap(),
        "node_fixture_refused"
    );
    std::fs::write(
        dir.path().join("package.json"),
        vec![b' '; lockfile::PACKAGE_JSON_MAX_BYTES + 1],
    )
    .unwrap();
    assert_eq!(inputs(dir.path()).err(), Some("node_lockfile_refused"));
}

struct CachedFake {
    fake: Fake,
    session: Session,
    python: crate::audit::target_poc::tests::FakeTargetSandbox,
}

#[async_trait::async_trait]
impl TargetSandbox for CachedFake {
    fn image_id(&self) -> &str {
        self.fake.image_id()
    }
    async fn prepare_node(&self, tree: &Path) -> Result<Arc<NodeExecution>, &'static str> {
        self.session.prepare(tree, &self.fake, None).await
    }
    async fn run(
        &self,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
    ) -> Result<(i64, String), String> {
        self.python.run(tree, runner, adapter, input).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn run_node(
        &self,
        node: &NodeExecution,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
        class: crate::audit::poc_oracle::OracleClass,
    ) -> Result<(i64, String), String> {
        TargetSandbox::run_node(&self.fake, node, tree, runner, adapter, input, class).await
    }
}

#[async_trait::async_trait]
impl crate::audit::retest::RetestRunner for CachedFake {
    async fn run(
        &self,
        repo: &Path,
        finding: &Finding,
        call: &TargetCall,
        replays: u32,
        deadline: std::time::Instant,
    ) -> TargetPocReceipt {
        run_replays_until(repo, finding, call, self, false, replays, Some(deadline))
            .await
            .receipt
    }
}

#[tokio::test]
async fn mixed_retest_keeps_python_dispatch_and_installs_node_once_for_revision() {
    use crate::audit::schema::{AuditReport, EvidenceItem, EvidenceKind};
    let (dir, mut finding, call) = project(true);
    let python = "# VULNERABLE\nimport os\ndef read_file(x):\n    return open(os.path.join(os.environ['VTL_BASE'], x)).read()\n";
    std::fs::write(dir.path().join("app.py"), python).unwrap();
    finding.evidence.push(EvidenceItem {
        kind: EvidenceKind::PocOracle,
        source: "fixture".into(),
        detail: "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none"
            .into(),
        recorded_at: "2026-11-12T00:00:00Z".into(),
    });
    let mut second = finding.clone();
    second.id = "second-node".into();
    let mut py = finding.clone();
    py.id = "python".into();
    py.file = "app.py".into();
    py.file_hash = Some(sha256_hex(python.as_bytes()));
    let py_call = TargetCall {
        file: "app.py".into(),
        function: "read_file".into(),
        args: vec![TargetArgument::Payload],
    };
    let plans = [
        (finding.id.clone(), call.clone()),
        (second.id.clone(), call),
        (py.id.clone(), py_call),
    ]
    .into_iter()
    .collect();
    let report: AuditReport = serde_json::from_value(serde_json::json!({
        "schema_version":3,"repo":dir.path(),"repo_commit":"a".repeat(40),
        "started_at":"2026-11-12T00:00:00Z","profile":{"mode":"quick"},
        "engines_run":[],"engines_missing":[],"findings":[finding,second,py],
        "summary":{"total_findings":3,"by_severity":{"critical":0,"high":3,"medium":0,"low":0,"info":0},"engines_run_count":0,"engines_missing_count":0}
    })).unwrap();
    let old = crate::audit::retest::OldReport {
        path: dir.path().join("old.json"),
        sha256: "b".repeat(64),
        report,
    };
    let runner = CachedFake {
        fake: Fake::default(),
        session: Session::default(),
        python: Default::default(),
    };
    let result = crate::audit::retest::run_retest_with(
        dir.path(),
        &old,
        &plans,
        &runner,
        2,
        3,
        std::time::Instant::now() + std::time::Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(result.summary.still_observed, 3);
    assert_eq!(runner.fake.installs.load(Ordering::Relaxed), 1);
    assert_eq!(runner.fake.executions.load(Ordering::Relaxed), 12);
    let py = result.results[2].receipt.as_ref().unwrap();
    assert_eq!(py.version, 2);
    assert!(py.runtime.is_none());
    assert!(!serde_json::to_string(py).unwrap().contains("node_version"));
}

#[tokio::test]
async fn command_session_caches_failures_and_refuses_dependency_drift() {
    let (dir, _, _) = project(true);
    let fake = Fake::default();
    let session = Session::default();
    let first = session.prepare(dir.path(), &fake, None).await.unwrap();
    let second = session.prepare(dir.path(), &fake, None).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(fake.installs.load(Ordering::Relaxed), 1);
    std::fs::write(dir.path().join("package.json"), "{}").unwrap();
    assert!(session.prepare(dir.path(), &fake, None).await.is_err());
    assert_eq!(fake.installs.load(Ordering::Relaxed), 1);
    let (dir, _, _) = project(false);
    let session = Session::default();
    let fake = Fake {
        unavailable: true,
        ..Default::default()
    };
    assert_eq!(
        session.prepare(dir.path(), &fake, None).await.err(),
        Some("node_runtime_unavailable")
    );
    assert_eq!(
        session
            .prepare(dir.path(), &Fake::default(), None)
            .await
            .err(),
        Some("node_runtime_unavailable")
    );
}

#[test]
fn reviewer_fixture_reports_and_patch_inputs_are_validator_clean() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/node-e2e");
    let output = tempfile::tempdir().unwrap();
    for name in ["cjs-command", "esm-path", "ts-sqlite", "pg-reach"] {
        let path = output.path().join(format!("{name}.json"));
        let status = std::process::Command::new("python3")
            .arg(root.join("make-report.py"))
            .arg(root.join(name))
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let report = crate::audit::load_report_for_delivery(&path).unwrap();
        let call = parse_target_call(
            &std::fs::read_to_string(root.join(name).join("target.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(report.findings[0].file, call.file);
        if name != "pg-reach" {
            let diff = std::fs::read_to_string(root.join(name).join("fix.patch")).unwrap();
            crate::audit::validate_fix_diff(&diff).unwrap();
            assert!(!inputs(&root.join(name)).unwrap().summary.needs_install());
        }
    }
}

#[tokio::test]
async fn sql_driver_is_host_selected_and_only_applies_to_sql_targets() {
    use crate::audit::poc_oracle::OracleClass;
    let (dir, _, call) = project(false);
    let fake = Fake::default();
    let execution = prepare(dir.path(), &fake, None).await.unwrap();
    let source = "import pg from 'pg'; export function read(x) { return x; }";
    let sql = execution.runtime(dir.path(), &call, source, OracleClass::Sqli);
    assert_eq!(sql.driver, Some(NodeDriver::Pg));
    assert!(!sql.executable());
    let path = execution.runtime(dir.path(), &call, source, OracleClass::PathTraversal);
    assert!(path.driver.is_none());
    assert!(path.executable());
}

#[test]
fn fixture_must_be_outside_canonical_repository_and_not_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("project");
    let sibling = dir.path().join("project-private");
    std::fs::create_dir(&repo).unwrap();
    std::fs::create_dir(&sibling).unwrap();
    let bytes =
        serde_json::json!({"schema":fixture::FIXTURE_SCHEMA,"env":{"TOKEN":SECRET}}).to_string();
    let inside = repo.join("auth.json");
    let outside = sibling.join("auth.json");
    for path in [&inside, &outside] {
        std::fs::write(path, &bytes).unwrap();
    }
    let error = NodeOptions::read("local".into(), Some(&inside), &repo)
        .err()
        .unwrap();
    assert_eq!(
        error,
        "node_fixture_refused: --fixture must be outside the repository"
    );
    assert!(!error.contains(SECRET));
    assert!(NodeOptions::read("local".into(), Some(&outside), &repo).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let alias = dir.path().join("alias");
        symlink(&repo, &alias).unwrap();
        assert!(
            NodeOptions::read("local".into(), Some(&alias.join("auth.json")), &repo)
                .err()
                .unwrap()
                .contains("must be outside")
        );
        assert!(
            NodeOptions::read("local".into(), Some(&inside), &alias)
                .err()
                .unwrap()
                .contains("must be outside")
        );
        let link = sibling.join("link.json");
        symlink(&outside, &link).unwrap();
        assert!(
            NodeOptions::read("local".into(), Some(&link), &repo)
                .err()
                .unwrap()
                .contains("non-symlink")
        );
    }
}
