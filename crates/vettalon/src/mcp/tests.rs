use super::*;
use crate::audit::schema::*;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, LocalBackend, Vec<u8>) {
    let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let dir = tempfile::tempdir_in(root).unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let mut finding = Finding::candidate(
        "semgrep",
        FindingKind::StaticAnalysis,
        Severity::High,
        "secret AKIAIOSFODNN7EXAMPLE",
        "a.py",
        Some(1),
        "danger",
        "fix",
        vec![],
    );
    finding.id = "f1".into();
    let findings = vec![finding];
    let report = AuditReport {
        repo_commit: None,
        repo_tree_clean: None,
        since_last: None,
        attack_classes: None,
        schema_version: CURRENT_SCHEMA_VERSION,
        scope: None,
        repo: repo.to_string_lossy().into(),
        started_at: "2026-11-02T00:00:00Z".into(),
        profile: ScanProfile {
            mode: ProfileMode::Quick,
            intake: None,
        },
        engines_run: vec![],
        engines_missing: vec![],
        summary: Summary::from_findings(&findings, 0, 0, GatePolicy::default(), &[]),
        findings,
        run_status: vettalon_contract::coverage::RunStatus::Complete,
        incomplete_reason: None,
        coverage: vec![],
        prior_run: None,
        verifier: Default::default(),
        ensemble: Default::default(),
    };
    let report_path = dir.path().join("report.json");
    let bytes = serde_json::to_vec(&report).unwrap();
    std::fs::write(&report_path, &bytes).unwrap();
    let backend = LocalBackend::new(
        &repo,
        Some(report_path),
        &dir.path().join("home"),
        None,
        crate::sandbox::DEFAULT_POC_IMAGE.into(),
    )
    .unwrap();
    (dir, backend, bytes)
}

#[test]
fn mcp_tool_descriptions_are_informative() {
    for schema in tools::schemas() {
        let name = schema["name"].as_str().unwrap();
        let description = schema["description"].as_str().unwrap();
        assert!(description.len() >= 40, "{name}: {description}");
        assert_ne!(description, name);
        assert!(description.contains("never changes a finding's status"));
        if matches!(name, "vettalon_reproduce" | "vettalon_check_fix") {
            for phrase in [
                "isolated Docker sandbox",
                "private copy",
                "exactly one payload argument",
            ] {
                assert!(description.contains(phrase), "{name}: missing {phrase}");
            }
        }
    }
    assert!(
        tools::schemas()
            .iter()
            .find(|schema| schema["name"] == "vettalon_suggest_noise")
            .unwrap()["description"]
            .as_str()
            .unwrap()
            .contains("vettalon triage")
    );
}

#[test]
fn mcp_tools_read_mask_and_preserve_report() {
    let (_dir, mut backend, bytes) = fixture();
    for (name, args) in [
        ("vettalon_report_summary", json!({})),
        ("vettalon_list_findings", json!({"limit":100})),
        ("vettalon_get_finding", json!({"finding":"f1"})),
        ("vettalon_fix_brief", json!({"finding":"f1"})),
        (
            "vettalon_suggest_noise",
            json!({"finding":"f1", "reason":"human review requested"}),
        ),
    ] {
        tools::validate_args(name, &args).unwrap();
        let value = backend.call(name, args).unwrap();
        assert_eq!(value["untrusted_data"], true);
        assert!(!value.to_string().contains("AKIAIOSFODNN7EXAMPLE"));
        match name {
            "vettalon_list_findings" => {
                assert_eq!(value["findings"][0]["id"], "f1");
                assert_eq!(value["findings"][0]["reproducible"], false);
            }
            "vettalon_get_finding" => assert_eq!(value["finding"]["file"], "a.py"),
            "vettalon_fix_brief" => {
                assert_eq!(value["where"]["file"], "a.py");
                assert!(
                    value["instructions"]
                        .to_string()
                        .contains("Do not edit tests")
                );
                assert!(!value["instructions"].to_string().contains("secret"));
            }
            _ => {}
        }
        assert_eq!(
            std::fs::read(backend.report.as_ref().unwrap()).unwrap(),
            bytes
        );
    }
}

#[test]
fn mcp_report_summary_omits_coverage_rows_and_keeps_counts() {
    let (dir, mut backend, _) = fixture();
    let path = backend.report.as_ref().unwrap().clone();
    let mut report = audit::load_report_for_delivery(&path).unwrap();
    report.coverage.push(crate::audit::schema::ModuleCoverage {
        attack_classes: None,
        prior_status: None,
        checks: vec![],
        hardening: vec![],
        leads: vec![],
        module_path: "src".into(),
        status: crate::audit::schema::ModuleCoverageStatus::Covered,
        reason: None,
        reviewed_paths: vec!["src/a.py".into()],
        truncated_paths: vec![],
        candidate_ids: vec![],
        scope_paths: vec![],
        selected: false,
        attempts: vec![],
    });
    report.summary = Summary::from_findings(
        &report.findings,
        0,
        0,
        GatePolicy::default(),
        &report.coverage,
    );
    std::fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
    let value = backend.call("vettalon_report_summary", json!({})).unwrap();
    assert!(value.get("coverage").is_none());
    assert_eq!(value["modules_total"], 1);
    assert_eq!(value["summary"]["coverage"]["modules_total"], 1);
    drop(dir);
}

#[test]
fn mcp_tools_strict_arguments_and_traversal() {
    let (_dir, mut backend, _) = fixture();
    assert!(
        tools::validate_args(
            "vettalon_get_finding",
            &json!({"finding":"f1","path":"/etc/passwd"})
        )
        .is_err()
    );
    for id in ["../f1", "/etc/passwd", "", "f1/../../x"] {
        assert!(tools::validate_args("vettalon_get_finding", &json!({"finding":id})).is_err());
        assert!(
            backend
                .call("vettalon_get_finding", json!({"finding":id}))
                .is_err()
        );
    }
    assert!(tools::validate_args("vettalon_list_findings", &json!({"limit":101})).is_err());
    let max = crate::audit::SUGGESTED_FIX_MAX_BYTES;
    let diff = "x".repeat(max);
    assert!(tools::validate_args("vettalon_check_fix", &json!({"finding":"f1","target":{"file":"a.py","function":"run","args":[{"kind":"payload"}]},"diff":diff})).is_ok());
    let diff = "x".repeat(max + 1);
    assert!(tools::validate_args("vettalon_check_fix", &json!({"finding":"f1","target":{"file":"a.py","function":"run","args":[{"kind":"payload"}]},"diff":diff})).unwrap_err().contains("64 KiB"));
    let schema = tools::schemas()
        .into_iter()
        .find(|schema| schema["name"] == "vettalon_check_fix")
        .unwrap();
    assert_eq!(
        schema["inputSchema"]["properties"]["diff"]["maxLength"],
        max
    );
}

#[test]
fn mcp_proposals_append_cap_and_refuse_symlinks() {
    let (dir, mut backend, bytes) = fixture();
    let args = json!({"finding":"f1","reason":"review"});
    for _ in 0..2 {
        backend
            .call("vettalon_suggest_noise", args.clone())
            .unwrap();
    }
    let path = backend.state_dir.join("proposals.jsonl");
    let raw = std::fs::read_to_string(&path).unwrap();
    assert_eq!(raw.lines().count(), 2);
    for line in raw.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(row["report_sha256"], sha256_hex(&bytes));
    }
    std::fs::write(&path, vec![b' '; 1024 * 1024]).unwrap();
    assert!(
        backend
            .call("vettalon_suggest_noise", args.clone())
            .is_err()
    );
    assert!(
        backend
            .call(
                "vettalon_suggest_noise",
                json!({"finding":"f1","reason":"a\nb"})
            )
            .is_err()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            std::fs::metadata(&backend.state_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::remove_file(&path).unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        symlink(&victim, &path).unwrap();
        assert!(backend.call("vettalon_suggest_noise", args).is_err());
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "untouched");
    }
}

#[test]
fn mcp_reload_validation_and_missing_report() {
    let (_dir, mut backend, _) = fixture();
    std::fs::write(backend.report.as_ref().unwrap(), "{}").unwrap();
    assert!(backend.call("vettalon_report_summary", json!({})).is_err());
    backend.report = None;
    assert!(
        backend
            .call("vettalon_report_summary", json!({}))
            .unwrap_err()
            .contains("vettalon scan --save")
    );
}

struct FakeExecutor {
    calls: Vec<String>,
}
impl Executor for FakeExecutor {
    fn reproduce(
        &mut self,
        _repo: &std::path::Path,
        finding: &Finding,
        target: &TargetCall,
        _image: &str,
        emit: bool,
        replays: u32,
    ) -> TargetPocWithTest {
        self.calls.push(if replays == 1 {
            format!("reproduce:{emit}")
        } else {
            format!("reproduce:{emit}:{replays}")
        });
        TargetPocWithTest {
            receipt: serde_json::from_value(json!({"version":1,"outcome":"effect_observed","phases":[],"target_file":target.file,"target_function":target.function,"target_plan_sha256":null,"target_file_sha256":null,"source_sha256":null,"exclusions":null,"adapter_sha256":null,"image_id":null,"reason":null})).unwrap(),
            test_source: emit.then(|| crate::audit::regression_test::generate(finding, crate::audit::poc_oracle::classify(finding).unwrap(), target).unwrap()),
        }
    }
    fn check_fix(
        &mut self,
        _repo: &std::path::Path,
        _finding: &Finding,
        _target: &TargetCall,
        diff: &str,
        command: Option<&str>,
        _image: &str,
    ) -> FixCheckRun {
        assert_eq!(command, Some("python3 -m unittest"));
        self.calls.push("fix".into());
        FixCheckRun {
            runtime: None,
            reach_summary: None,
            check: audit::fix_check::FixCheck::not_run(diff, 1, "sandbox_unavailable"),
            note: None,
            binding: None,
        }
    }
}

#[test]
fn mcp_fake_execution_writes_only_state_and_preserves_source_and_report() {
    let (_dir, original, _) = fixture();
    let path = original.report.as_ref().unwrap();
    let mut report = audit::load_report_for_delivery(path).unwrap();
    report.findings[0].cwe = Some("CWE-78".into());
    report.findings[0].id = "AKIAIOSFODNN7EXAMPLE".into();
    std::fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
    let before = std::fs::read(path).unwrap();
    let source_path = original.repo.join("a.py");
    std::fs::write(&source_path, "def run(x): return x\n").unwrap();
    let mut backend = LocalBackend::with_executor(
        &original.repo,
        original.report.clone(),
        original.state_dir.parent().unwrap().parent().unwrap(),
        Some("python3 -m unittest".into()),
        original.image.clone(),
        FakeExecutor { calls: vec![] },
    )
    .unwrap();
    let target = json!({"file":"a.py","function":"run","args":[{"kind":"payload"}]});
    for emit in [false, true] {
        let value = backend
            .call(
                "vettalon_reproduce",
                json!({"finding":report.findings[0].id,"target":target,"emit_test":emit}),
            )
            .unwrap();
        assert_eq!(value["outcome"], "effect_observed");
        // The fake returns a version-1 receipt: read as one requested replay.
        assert_eq!(value["replays"]["requested"], 1);
        assert_eq!(value["replays"]["observed"], 1);
        if emit {
            let test = value["test"].as_str().unwrap();
            assert!(!test.contains("AKIAIOSFODNN7EXAMPLE"));
            assert_eq!(
                test,
                crate::audit::regression_test::generate(
                    &report.findings[0],
                    crate::audit::poc_oracle::classify(&report.findings[0]).unwrap(),
                    &serde_json::from_value(target.clone()).unwrap()
                )
                .unwrap()
            );
            let mut child = std::process::Command::new("python3")
                .args([
                    "-I",
                    "-B",
                    "-c",
                    "import sys; compile(sys.stdin.read(), '<mcp-test>', 'exec')",
                ])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(test.as_bytes())
                .unwrap();
            assert!(child.wait().unwrap().success());
        } else {
            assert!(value["test"].is_null());
        }
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
    for paths in [
        vec!["AKIAIOSFODNN7EXAMPLE.py"],
        vec!["a.py", "AKIAIOSFODNN7EXAMPLE.py"],
    ] {
        let diff = paths
            .iter()
            .map(|path| format!("--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"))
            .collect::<String>();
        let calls = backend.executor.calls.len();
        let error = backend
            .call(
                "vettalon_check_fix",
                json!({
                    "finding":report.findings[0].id,"target":target,"diff":diff
                }),
            )
            .unwrap_err();
        assert_eq!(
            error,
            format!(
                "MCP single-file check_fix rule: only the finding's file may be touched; multi-file fixes go through vettalon fix check by a person. touched file count: {}",
                paths.len()
            )
        );
        assert_eq!(backend.executor.calls.len(), calls);
    }
    let diff =
        "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-def run(x): return x\n+def run(x): return str(x)\n";
    let result = backend
        .call(
            "vettalon_check_fix",
            json!({"finding":report.findings[0].id,"target":target,"diff":diff}),
        )
        .unwrap();
    assert_eq!(result["nothing_applied"], true);
    assert_eq!(result["touched_paths"], json!(["a.py"]));
    assert_eq!(result["outcome"], "fix_unverified");
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(
        std::fs::read_to_string(source_path).unwrap(),
        "def run(x): return x\n"
    );
    assert_eq!(
        backend.executor.calls,
        ["reproduce:false", "reproduce:true", "fix"]
    );
    let files: Vec<_> = std::fs::read_dir(&backend.state_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 4);
    let updated = files
        .iter()
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("fix-report")
        })
        .unwrap();
    let updated = audit::load_report_for_delivery(updated).unwrap();
    assert_eq!(updated.findings[0].status, report.findings[0].status);
}

#[test]
fn mcp_reproduce_replays_are_optional_and_bounded() {
    let schema = tools::schemas()
        .into_iter()
        .find(|s| s["name"] == "vettalon_reproduce")
        .unwrap();
    let replays = &schema["inputSchema"]["properties"]["replays"];
    assert_eq!(replays["type"], "integer");
    assert_eq!(replays["minimum"], 1);
    assert_eq!(replays["maximum"], 20);
    assert_eq!(replays["default"], 1);
    assert!(
        !schema["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("replays"))
    );
    let target = json!({"file":"a.py","function":"run","args":[{"kind":"payload"}]});
    let args = |replays: Value| json!({"finding":"f1","target":target,"replays":replays});
    for ok in [1, 3, 20] {
        tools::validate_args("vettalon_reproduce", &args(json!(ok))).unwrap();
    }
    for refused in [json!(0), json!(21), json!(-1), json!(2.5), json!("3")] {
        assert!(
            tools::validate_args("vettalon_reproduce", &args(refused.clone())).is_err(),
            "{refused}"
        );
    }
    assert!(
        tools::validate_args(
            "vettalon_check_fix",
            &json!({"finding":"f1","target":target,"diff":"","replays":2})
        )
        .is_err()
    );
}

#[test]
fn mcp_state_rejects_repository_and_symlink_and_escapes_proposal_controls() {
    let (dir, backend, _) = fixture();
    assert!(state_dir(&backend.repo.join("state"), &backend.repo).is_err());
    assert!(!backend.repo.join("state").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = dir.path().join("actual-home");
        std::fs::create_dir(&target).unwrap();
        let ancestor = dir.path().join("linked-ancestor");
        symlink(dir.path(), &ancestor).unwrap();
        let through_link = ancestor.join("actual-home");
        let resolved = state_dir(&through_link, &backend.repo).unwrap();
        assert!(resolved.is_absolute());
        assert_eq!(std::fs::canonicalize(&resolved).unwrap(), resolved);
        let output = resolved.join("created.json");
        preflight_new_output(&output).unwrap();
        std::fs::write(&output, "ok").unwrap();
        assert_eq!(std::fs::read_to_string(output).unwrap(), "ok");

        let mcp_home = dir.path().join("mcp-link-home");
        std::fs::create_dir(&mcp_home).unwrap();
        symlink(&target, mcp_home.join("mcp")).unwrap();
        assert!(state_dir(&mcp_home, &backend.repo).is_err());

        let hash = sha256_hex(backend.repo.as_os_str().as_encoded_bytes());
        let hash_home = dir.path().join("hash-link-home");
        std::fs::create_dir_all(hash_home.join("mcp")).unwrap();
        symlink(&target, hash_home.join("mcp").join(&hash[..16])).unwrap();
        assert!(state_dir(&hash_home, &backend.repo).is_err());

        let repo_link = dir.path().join("repo-link");
        symlink(&backend.repo, &repo_link).unwrap();
        assert!(state_dir(&repo_link.join("nested-home"), &backend.repo).is_err());
        assert!(!backend.repo.join("nested-home").exists());
    }
    let path = backend.state_dir.join("proposals.jsonl");
    let value = json!({"reason":"AKIAIOSFODNN7EXAMPLE text\u{009b}\u{007f}\n"});
    std::fs::write(&path, format!("{value}\n")).unwrap();
    let printed =
        print_proposals(backend.report.as_ref().unwrap(), &dir.path().join("home")).unwrap();
    assert!(!printed.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!printed.chars().any(char::is_control));
    assert!(printed.contains("\\u009b"));
    assert!(printed.contains("\\u007f"));
}

#[test]
fn mcp_auto_selects_newest_saved_report_and_binds_it() {
    let (dir, original, _) = fixture();
    let home = dir.path().join("home");
    let reports = home.join("reports");
    std::fs::create_dir(&reports).unwrap();
    let mut report = audit::load_report_for_delivery(original.report.as_ref().unwrap()).unwrap();
    for (name, title) in [
        ("20261101-000000.json", "old"),
        ("20261102-000000.json", "new"),
    ] {
        report.findings[0].title = title.into();
        std::fs::write(reports.join(name), serde_json::to_vec(&report).unwrap()).unwrap();
    }
    let mut backend =
        LocalBackend::new(&original.repo, None, &home, None, original.image.clone()).unwrap();
    let value = backend
        .call("vettalon_get_finding", json!({"finding":"f1"}))
        .unwrap();
    assert_eq!(value["finding"]["title"], "new");
    for args in [
        json!({"offset":1}),
        json!({"min_severity":"critical"}),
        json!({"status":"suppressed"}),
    ] {
        assert!(
            backend.call("vettalon_list_findings", args).unwrap()["findings"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    report.findings[0].title = "later".into();
    std::fs::write(
        reports.join("20261103-000000.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    assert_eq!(
        backend
            .call("vettalon_get_finding", json!({"finding":"f1"}))
            .unwrap()["finding"]["title"],
        "new"
    );
}

#[test]
fn mcp_check_fix_refuses_other_paths_and_renames_before_executor() {
    let (_dir, original, _) = fixture();
    let path = original.report.as_ref().unwrap();
    let mut report = audit::load_report_for_delivery(path).unwrap();
    report.findings[0].cwe = Some("CWE-78".into());
    std::fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
    let mut backend = LocalBackend::with_executor(
        &original.repo,
        original.report.clone(),
        original.state_dir.parent().unwrap().parent().unwrap(),
        None,
        original.image.clone(),
        FakeExecutor { calls: vec![] },
    )
    .unwrap();
    let target = json!({"file":"a.py","function":"run","args":[{"kind":"payload"}]});
    for diff in [
        "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+new\n--- a/test.py\n+++ b/test.py\n@@ -1 +1 @@\n-old\n+new\n",
        "--- a/a.py\n+++ b/renamed.py\n@@ -1 +1 @@\n-old\n+new\n",
    ] {
        let err = backend
            .call(
                "vettalon_check_fix",
                json!({"finding":"f1","target":target,"diff":diff}),
            )
            .unwrap_err();
        assert!(err.contains("single-file"), "{err}");
        assert!(err.contains("vettalon fix check"), "{err}");
        assert!(backend.executor.calls.is_empty());
        assert_eq!(std::fs::read_dir(&backend.state_dir).unwrap().count(), 0);
    }
}

#[test]
fn mcp_get_finding_oversize_is_error_without_evidence_fallback() {
    let (_dir, backend, _) = fixture();
    let path = backend.report.as_ref().unwrap();
    let mut report = audit::load_report_for_delivery(path).unwrap();
    for _ in 0..100 {
        report.findings[0].evidence.push(EvidenceItem {
            kind: EvidenceKind::StaticHit,
            source: "fixture".into(),
            detail: "x".repeat(16 * 1024),
            recorded_at: "2026-11-02T00:00:00Z".into(),
        });
    }
    std::fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
    let mut state = State::new(backend);
    state.initialized = true;
    let raw = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"vettalon_get_finding","arguments":{"finding":"f1"}}});
    // Exercise the production transport, including its double JSON encoding.
    let response = handle_message(&mut state, &raw.to_string()).unwrap();
    let response: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["result"]["isError"], true);
    assert!(
        response.to_string().contains("narrower pagination"),
        "{response}"
    );
}

#[test]
fn mcp_receipt_retention_keeps_100_regular_files_per_prefix() {
    let (_dir, backend, _) = fixture();
    for prefix in ["reproduce", "fix-receipt", "fix-report"] {
        for i in 0..103 {
            let path = backend.state_dir.join(format!("{prefix}-{i:03}.json"));
            let file = std::fs::File::create(&path).unwrap();
            file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(i))
                .unwrap();
        }
    }
    std::fs::write(backend.state_dir.join("proposals.jsonl"), "preserve").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        backend.state_dir.join("proposals.jsonl"),
        backend.state_dir.join("reproduce-link.json"),
    )
    .unwrap();
    for prefix in ["reproduce", "fix-receipt", "fix-report"] {
        prune_outputs(&backend.state_dir, prefix).unwrap();
        std::fs::write(backend.output(prefix), "new").unwrap();
        let count = std::fs::read_dir(&backend.state_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_type().unwrap().is_file()
                    && e.file_name()
                        .to_string_lossy()
                        .starts_with(&format!("{prefix}-"))
            })
            .count();
        assert_eq!(count, 100);
        for i in 0..4 {
            assert!(
                !backend
                    .state_dir
                    .join(format!("{prefix}-{i:03}.json"))
                    .exists()
            );
        }
        assert!(
            backend
                .state_dir
                .join(format!("{prefix}-004.json"))
                .exists()
        );
    }
    assert_eq!(
        std::fs::read_to_string(backend.state_dir.join("proposals.jsonl")).unwrap(),
        "preserve"
    );
    #[cfg(unix)]
    assert!(
        std::fs::symlink_metadata(backend.state_dir.join("reproduce-link.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn mcp_state_refuses_unresolved_dot_components_without_creating_anything() {
    let (dir, backend, _) = fixture();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    for suffix in ["new/../../repo/.state", "new/./state", "new/../state"] {
        let home = out.join(suffix);
        assert!(state_dir(&home, &backend.repo).is_err(), "{suffix}");
        assert!(resolve_state_dir(&home, &backend.repo, false).is_err());
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
        assert!(!backend.repo.join(".state").exists());
    }
    // Existing dot and symlink prefixes keep their canonical filesystem meaning.
    let home = out.join("./valid/new/home");
    let state = state_dir(&home, &backend.repo).unwrap();
    assert!(state.starts_with(std::fs::canonicalize(&home).unwrap()));
}

#[test]
fn mcp_check_fix_success_sanitizes_touched_paths() {
    let (_dir, original, _) = fixture();
    let path = original.report.as_ref().unwrap();
    let mut report = audit::load_report_for_delivery(path).unwrap();
    let file = "AKIAIOSFODNN7EXAMPLE.py";
    report.findings[0].cwe = Some("CWE-78".into());
    report.findings[0].file = file.into();
    std::fs::write(path, serde_json::to_vec(&report).unwrap()).unwrap();
    let mut backend = LocalBackend::with_executor(
        &original.repo,
        original.report.clone(),
        original.state_dir.parent().unwrap().parent().unwrap(),
        Some("python3 -m unittest".into()),
        original.image.clone(),
        FakeExecutor { calls: vec![] },
    )
    .unwrap();
    let target = json!({"file":file,"function":"run","args":[{"kind":"payload"}]});
    let diff = format!("--- a/{file}\n+++ b/{file}\n@@ -1 +1 @@\n-old\n+new\n");
    let result = backend
        .call(
            "vettalon_check_fix",
            json!({"finding":"f1","target":target,"diff":diff}),
        )
        .unwrap();
    let paths = result["touched_paths"].as_array().unwrap();
    assert_eq!(paths.len(), 1);
    assert!(!paths[0].as_str().unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
    assert_eq!(backend.executor.calls, vec!["fix"]);
}
