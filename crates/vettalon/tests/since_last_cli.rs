#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use vettalon::audit::{SubprocessLimits, run_bounded_subprocess};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    config: PathBuf,
}

async fn git(root: &Path, args: &[&str]) -> String {
    let bin = vettalon::util::which_cli_for_scan("git", root).unwrap();
    let mut command = vec![
        "-c",
        "user.name=Scope Test",
        "-c",
        "user.email=scope@example.invalid",
        "-c",
        "commit.gpgsign=false",
    ];
    command.extend_from_slice(args);
    let out = run_bounded_subprocess(
        &bin,
        &command,
        root,
        &SubprocessLimits {
            timeout: std::time::Duration::from_secs(10),
            max_output_bytes: 4096,
        },
    )
    .await;
    assert_eq!(out.exit_code, Some(0), "{out:?}");
    assert!(out.cleanup_error.is_none());
    out.stdout
}

impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        let home = temp.path().join("home");
        let bin = temp.path().join("bin");
        for path in [&root, &home, &bin] {
            std::fs::create_dir(path).unwrap();
        }
        let git_bin = vettalon::util::which_cli_for_scan("git", &root).unwrap();
        std::os::unix::fs::symlink(git_bin, bin.join("git")).unwrap();
        std::fs::create_dir(root.join("old")).unwrap();
        std::fs::create_dir(root.join("new")).unwrap();
        std::fs::write(root.join("old/a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(root.join("new/b.rs"), "fn b() {}\n").unwrap();
        git(&root, &["init", "-q"]).await;
        git(&root, &["add", "--all"]).await;
        git(&root, &["commit", "-qm", "base"]).await;
        git(&root, &["tag", "base"]).await;
        std::fs::write(root.join("new/b.rs"), "fn b() { changed(); }\n").unwrap();
        git(&root, &["add", "--all"]).await;
        git(&root, &["commit", "-qm", "head"]).await;
        let finder = temp.path().join("finder.sh");
        std::fs::write(&finder, "/bin/cat > /dev/null\nprintf '%s' '[]'\n").unwrap();
        let config = home.join("config.toml");
        std::fs::write(&config, format!("[[model]]\nid = 'mock'\nbackend = 'cli'\nfamily = 'test'\nroles = ['finder']\nprogram = '/bin/sh'\nargs = [{}]\nprompt_via = 'stdin'\nallow_agent_tools = true\n", serde_json::to_string(&finder).unwrap())).unwrap();
        let fixture = Self {
            _temp: temp,
            root,
            home,
            bin,
            config,
        };
        fixture.scanner_raw("[]");
        fixture
    }

    fn scan(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vettalon"))
            .env("VETTALON_HOME", &self.home)
            .env("PATH", &self.bin)
            .args(["--lang", "en", "scan"])
            .arg(&self.root)
            .arg("--config")
            .arg(&self.config)
            .args(["--report"])
            .arg(self.home.join("out.json"))
            .args(args)
            .output()
            .unwrap()
    }

    fn report(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.home.join("out.json")).unwrap()).unwrap()
    }

    #[allow(dead_code)]
    fn scanner(&self, file: &str) {
        self.scanner_raw(&serde_json::json!([{"File":file,"StartLine":1,"RuleID":"fixture","Description":"fixture secret"}]).to_string());
    }

    fn scanner_raw(&self, payload: &str) {
        let scanner = self.bin.join("gitleaks");
        std::fs::write(&scanner, format!("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n if [ \"$1\" = '--report-path' ]; then shift; printf '%s' '{payload}' > \"$1\"; exit 0; fi\n shift\ndone\nexit 1\n")).unwrap();
        std::fs::set_permissions(scanner, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn assert_ok(out: &Output) {
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Fixture {
    fn baseline(&self) -> serde_json::Value {
        assert_ok(&self.scan(&["--profile", "deep"]));
        let r = self.report();
        assert_eq!(r["run_status"], "complete");
        r
    }
    fn save(&self, name: &str, r: &serde_json::Value) {
        let parsed = serde_json::from_value(r.clone()).unwrap();
        assert!(
            vettalon::audit::validation_errors(&parsed).is_empty(),
            "{:?}",
            vettalon::audit::validation_errors(&parsed)
        );
        std::fs::create_dir_all(self.home.join("reports")).unwrap();
        std::fs::write(self.home.join("reports").join(name), r.to_string()).unwrap();
    }
}

#[tokio::test]
async fn no_base_full_scan_then_unchanged_skips_without_model_scanner_or_save() {
    let f = Fixture::new().await;
    let out = f.scan(&["--profile", "deep", "--since-last"]);
    assert_ok(&out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("no usable base"));
    let r = f.report();
    assert!(r.get("since_last").is_none());
    assert_eq!(r["repo_tree_clean"], true);
    assert_eq!(r["repo_commit"].as_str().unwrap().len(), 40);
    f.save("20261101T000000Z.json", &r);
    let calls = f._temp.path().join("called");
    std::fs::write(
        f._temp.path().join("finder.sh"),
        format!("printf called >> '{}'\nexit 99\n", calls.display()),
    )
    .unwrap();
    let scanner_marker = f._temp.path().join("scanner-called");
    std::fs::write(
        f.bin.join("gitleaks"),
        format!(
            "#!/bin/sh\nprintf called >> '{}'\nexit 99\n",
            scanner_marker.display()
        ),
    )
    .unwrap();

    let out = f.scan(&["--profile", "deep", "--since-last", "--save"]);
    assert_ok(&out);
    assert_eq!(f.report()["since_last"]["skipped"], true);
    assert!(!calls.exists());
    assert!(!scanner_marker.exists());
    assert_eq!(
        std::fs::read_dir(f.home.join("reports")).unwrap().count(),
        1
    );
}

#[tokio::test]
async fn incompatible_baselines_fall_back_to_full() {
    for variant in [
        "dirty",
        "incomplete",
        "profile",
        "attack_classes",
        "oid",
        "invalid",
    ] {
        let f = Fixture::new().await;
        let mut r = f.baseline();
        match variant {
            "dirty" => r["repo_tree_clean"] = false.into(),
            "incomplete" => {
                r["run_status"] = "incomplete".into();
                r["incomplete_reason"] = "units_failed".into();
            }
            "profile" => r["profile"]["mode"] = "quick".into(),
            "attack_classes" => r["attack_classes"] = "all".into(),
            "oid" => r["repo_commit"] = "--exec=bad".into(),
            _ => r["summary"]["total_findings"] = 99.into(),
        }
        std::fs::create_dir_all(f.home.join("reports")).unwrap();
        std::fs::write(f.home.join("reports/20261101T000000Z.json"), r.to_string()).unwrap();
        let out = f.scan(&["--profile", "deep", "--since-last"]);
        assert_ok(&out);
        assert!(f.report().get("since_last").is_none(), "{variant}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("skipping base:"),
            "{variant}: {out:?}"
        );
    }
}

#[tokio::test]
async fn changed_runs_chain_through_partial_base_and_merge_newer_incomplete_gap() {
    let f = Fixture::new().await;
    f.save("20261101T000000Z.json", &f.baseline());
    std::fs::write(f.root.join("new/b.rs"), "fn b() { next(); }\n").unwrap();
    git(&f.root, &["commit", "-qam", "next"]).await;
    assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
    let r = f.report();
    assert_eq!(r["run_status"], "partial_by_design");
    assert_eq!(r["scope"]["changed_files"], 1);
    assert!(
        r["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["module_path"] == "new" && c["status"] != "out_of_scope")
    );
    f.save("20261102T000000Z.json", &r);
    // A later unfinished run must preserve the last completed base.
    std::fs::write(f.root.join("new/b.rs"), "fn b() { third(); }\n").unwrap();
    git(&f.root, &["commit", "-qam", "third"]).await;
    let mut incomplete = r.clone();
    incomplete["repo_commit"] = git(&f.root, &["rev-parse", "HEAD"]).await.trim().into();
    incomplete["started_at"] = "2026-11-03T00:00:00Z".into();
    incomplete["run_status"] = "incomplete".into();
    incomplete["incomplete_reason"] = "units_failed".into();
    let c = incomplete["coverage"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|c| c["module_path"] == "new")
        .unwrap();
    c["status"] = "deferred".into();
    c["reason"] = "provider_usage_limit".into();
    // Rebuild derived coverage counts after mutation.
    let mut parsed: vettalon::audit::schema::AuditReport =
        serde_json::from_value(incomplete).unwrap();
    parsed.summary = vettalon::audit::schema::Summary::from_findings(
        &parsed.findings,
        parsed.engines_run.len(),
        parsed.engines_missing.len(),
        Default::default(),
        &parsed.coverage,
    );
    f.save(
        "20261103T000000Z.json",
        &serde_json::to_value(parsed).unwrap(),
    );
    assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
    let chained = f.report();
    assert_eq!(
        chained["since_last"]["base_report"],
        "20261102T000000Z.json"
    );
    assert!(
        chained["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["module_path"] == "new"
                && c["prior_status"] == "prior_gap:provider_usage_limit"
                && c["status"] != "out_of_scope")
    );
}

#[tokio::test]
async fn rewritten_history_uses_full_scan() {
    let f = Fixture::new().await;
    f.save("20261101T000000Z.json", &f.baseline());
    git(&f.root, &["reset", "--hard", "base"]).await;
    assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
    assert!(f.report().get("since_last").is_none());
}

#[tokio::test]
async fn conflicts_exit_two_before_work() {
    let f = Fixture::new().await;
    for args in [
        vec!["--since-last"],
        vec!["--since-last", "--profile", "deep", "--no-prior"],
        vec!["--since-last", "--profile", "deep", "--diff-base", "HEAD"],
    ] {
        assert_eq!(f.scan(&args).status.code(), Some(2));
        assert!(!f.home.join("out.json").exists());
    }
}

#[tokio::test]
async fn skipped_open_finding_recomputes_fail_on_and_gate() {
    use vettalon::audit::schema::*;
    let f = Fixture::new().await;
    let mut r: AuditReport = serde_json::from_value(f.baseline()).unwrap();
    r.findings.push(Finding::candidate(
        "gitleaks",
        FindingKind::Secret,
        Severity::High,
        "open",
        "new/b.rs",
        Some(1),
        "",
        "open",
        vec![],
    ));
    r.summary = Summary::from_findings(
        &r.findings,
        r.engines_run.len(),
        r.engines_missing.len(),
        GatePolicy::default(),
        &r.coverage,
    );
    f.save("20261101T000000Z.json", &serde_json::to_value(r).unwrap());
    for args in [
        vec!["--fail-on", "high"],
        vec!["--gate", "severity>=high count>0", "--fail-on", "none"],
    ] {
        let mut flags = vec!["--profile", "deep", "--since-last"];
        flags.extend(args);
        assert_eq!(f.scan(&flags).status.code(), Some(1));
        assert_eq!(f.report()["since_last"]["skipped"], true);
    }
}

#[tokio::test]
async fn outside_scope_baseline_finding_gates_in_changed_run_and_skip() {
    use vettalon::audit::schema::*;
    for changed in [true, false] {
        let f = Fixture::new().await;
        let mut baseline: AuditReport = serde_json::from_value(f.baseline()).unwrap();
        baseline.scope = Some(DiffScope {
            mode: DiffScopeMode::Diff,
            base: "base".into(),
            merge_base: git(&f.root, &["rev-parse", "HEAD"]).await.trim().into(),
            head: git(&f.root, &["rev-parse", "HEAD"]).await.trim().into(),
            base_oid: git(&f.root, &["rev-parse", "base"]).await.trim().into(),
            worktree_changes: 0,
            untracked: 0,
            changed_files: 1,
            invalid_paths: 0,
            changed_during_scan: 0,
        });
        baseline.run_status = serde_json::from_value("partial_by_design".into()).unwrap();
        baseline.incomplete_reason = None;
        baseline.since_last = Some(SinceLast {
            base_report: "prior.json".into(),
            base_commit: baseline.repo_commit.clone().unwrap(),
            skipped: false,
            carried_findings: 0,
        });
        let mut finding = Finding::candidate(
            "gitleaks",
            FindingKind::Secret,
            Severity::High,
            "open",
            "old/a.rs",
            Some(1),
            "",
            "open",
            vec![],
        );
        finding.evidence.push(EvidenceItem {
            kind: EvidenceKind::ScopeNote,
            source: "diff_scope".into(),
            detail: "outside_diff_scope".into(),
            recorded_at: "2026-11-01T00:00:00Z".into(),
        });
        baseline.findings.push(finding);
        refresh_summary(&mut baseline);
        f.save(
            "20261101T000000Z.json",
            &serde_json::to_value(baseline).unwrap(),
        );
        if changed {
            std::fs::write(f.root.join("new/b.rs"), "fn b() { changed_again(); }\n").unwrap();
            git(&f.root, &["commit", "-qam", "changed after baseline"]).await;
        }
        let out = f.scan(&["--profile", "deep", "--since-last", "--fail-on", "high"]);
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        let report = f.report();
        assert_eq!(report["since_last"]["skipped"], !changed);
        let carried = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["file"] == "old/a.rs")
            .unwrap();
        assert!(!carried["evidence"].as_array().unwrap().iter().any(|e| {
            e["kind"] == "scope_note"
                && e["source"] == "diff_scope"
                && e["detail"] == "outside_diff_scope"
        }));
    }
}

#[tokio::test]
async fn hidden_index_changes_never_skip() {
    for flag in ["--assume-unchanged", "--skip-worktree"] {
        let f = Fixture::new().await;
        f.save("20261101T000000Z.json", &f.baseline());
        git(&f.root, &["update-index", flag, "new/b.rs"]).await;
        std::fs::write(f.root.join("new/b.rs"), "fn hidden_change() {}\n").unwrap();
        let out = f.scan(&["--profile", "deep", "--since-last"]);
        assert_ok(&out);
        assert_ne!(f.report()["since_last"]["skipped"], true);
        assert_ne!(f.report()["repo_tree_clean"], true);
        assert!(f.report()["repo_commit"].is_string());
    }
}

fn refresh_summary(report: &mut vettalon::audit::schema::AuditReport) {
    use vettalon::audit::schema::*;
    report.summary = Summary::from_findings(
        &report.findings,
        report.engines_run.len(),
        report.engines_missing.len(),
        GatePolicy::default(),
        &report.coverage,
    );
}

#[tokio::test]
async fn scheduled_chain_preserves_open_and_human_decisions_without_new_review() {
    use vettalon::audit::schema::*;
    let f = Fixture::new().await;
    // Monday: obtain a real scanner finding, then add independent human decisions.
    f.scanner("old/a.rs");
    assert_eq!(
        f.scan(&["--profile", "deep", "--fail-on", "high"])
            .status
            .code(),
        Some(1)
    );
    let mut monday: AuditReport = serde_json::from_value(f.report()).unwrap();
    for (index, status) in [
        FindingStatus::Suppressed,
        FindingStatus::Refuted,
        FindingStatus::Confirmed,
    ]
    .into_iter()
    .enumerate()
    {
        let mut finding = Finding::candidate(
            "gitleaks",
            FindingKind::Secret,
            Severity::High,
            format!("human {status:?}"),
            "old/a.rs",
            Some(index as u32 + 2),
            "",
            "human",
            vec![],
        );
        finding.status = status;
        finding.file_hash = monday.findings[0].file_hash.clone();
        finding.severity_basis = SeverityBasis::Operator;
        finding.evidence.push(EvidenceItem {
            kind: EvidenceKind::OperatorReview,
            source: "dashboard".into(),
            detail: format!(
                "operator_decision: {}",
                serde_json::to_value(status).unwrap().as_str().unwrap()
            ),
            recorded_at: "2026-11-01T00:00:00Z".into(),
        });
        monday.findings.push(finding);
    }
    refresh_summary(&mut monday);
    let expected = serde_json::to_value(&monday.findings).unwrap();
    f.save(
        "20261101T000000Z.json",
        &serde_json::to_value(monday).unwrap(),
    );

    // The scanner re-finds the same ID outside the diff; baseline evidence must win.
    for (file, name) in [
        ("new/b.rs", "20261102T000000Z.json"),
        ("new/c.rs", "20261103T000000Z.json"),
    ] {
        std::fs::write(f.root.join(file), "fn changed() {}\n").unwrap();
        git(&f.root, &["add", "--all"]).await;
        git(&f.root, &["commit", "-qm", "next day"]).await;
        let out = f.scan(&["--profile", "deep", "--since-last", "--fail-on", "high"]);
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        let report = f.report();
        assert_eq!(report["findings"], expected);
        assert_eq!(report["since_last"]["carried_findings"], 4);
        assert_eq!(report["run_status"], "partial_by_design");
        assert!(
            report["coverage"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["module_path"] == "old" && row["status"] == "out_of_scope")
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("carried 4 findings"));
        f.save(name, &report);
        let out = f.scan(&[
            "--profile",
            "deep",
            "--since-last",
            "--fail-on",
            "none",
            "--gate",
            "severity>=high count>0",
        ]);
        assert_eq!(out.status.code(), Some(1), "{out:?}");
    }
    // Thursday: unchanged checkout reuses Wednesday without losing gate visibility.
    f.scanner_raw("[]");
    assert_eq!(
        f.scan(&["--profile", "deep", "--since-last", "--fail-on", "high"])
            .status
            .code(),
        Some(1)
    );
    let report = f.report();
    assert_eq!(report["since_last"]["skipped"], true);
    assert_eq!(report["findings"], expected);
    let parsed = serde_json::from_value(report).unwrap();
    assert!(
        vettalon::audit::validation_errors(&parsed).is_empty(),
        "{:?}",
        vettalon::audit::validation_errors(&parsed)
    );
}

#[tokio::test]
async fn selected_base_drives_prior_despite_newer_incomplete_report() {
    for same_hash in [false, true] {
        let f = Fixture::new().await;
        std::fs::write(f.root.join("a.py"), "password = 'old-secret'\n").unwrap();
        git(&f.root, &["add", "a.py"]).await;
        git(&f.root, &["commit", "-qm", "add python file"]).await;
        f.scanner("a.py");
        assert_eq!(f.scan(&["--profile", "deep"]).status.code(), Some(1));
        let mut baseline = f.report();
        // The fixture has no verifier. Model the eligible completed scanner
        // baseline explicitly while retaining its open claim and source hash.
        baseline["run_status"] = "complete".into();
        baseline["incomplete_reason"] = serde_json::Value::Null;
        let id = baseline["findings"][0]["id"].clone();
        f.save("20261101T000000Z.json", &baseline);
        // A valid, newer incomplete report must not replace the selected prior.
        f.scanner_raw("[]");
        let mut newer: vettalon::audit::schema::AuditReport =
            serde_json::from_value(baseline.clone()).unwrap();
        newer.findings.clear();
        refresh_summary(&mut newer);
        let mut newer = serde_json::to_value(newer).unwrap();
        newer["run_status"] = "incomplete".into();
        newer["incomplete_reason"] = "scope_not_fully_reviewed".into();
        f.save("20261102T000000Z.json", &newer);
        if same_hash {
            // A mode-only Git change retains the source hash while staying in scope.
            git(&f.root, &["update-index", "--chmod=+x", "a.py"]).await;
            std::fs::set_permissions(f.root.join("a.py"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        } else {
            std::fs::write(f.root.join("a.py"), "password = 'fixed'\n").unwrap();
        }
        git(&f.root, &["commit", "-qam", "change python file"]).await;
        let out = f.scan(&["--profile", "deep", "--since-last", "--fail-on", "high"]);
        let report = f.report();
        assert_eq!(report["since_last"]["base_report"], "20261101T000000Z.json");
        assert_eq!(report["prior_run"]["report_file"], "20261101T000000Z.json");
        if same_hash {
            assert_eq!(out.status.code(), Some(1), "{out:?}");
            let findings = report["findings"].as_array().unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0]["status"], "candidate");
            assert_eq!(findings[0]["file"], "a.py");
            assert_eq!(findings[0]["id"], id);
            assert!(
                findings[0]["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["source"] == "prior_run")
            );
        } else {
            assert_ok(&out);
            assert!(report["findings"].as_array().unwrap().is_empty());
            let changed = report["prior_run"]["changed_unrediscovered"]
                .as_array()
                .unwrap();
            assert_eq!(changed.len(), 1);
            assert_eq!(changed[0]["file"], "a.py");
            assert_eq!(changed[0]["reason"], "source_changed");
        }
    }
}

#[tokio::test]
async fn changed_or_deleted_confirmed_finding_is_not_carried_by_since_last() {
    use vettalon::audit::schema::*;
    for deleted in [false, true] {
        let f = Fixture::new().await;
        let mut base: AuditReport = serde_json::from_value(f.baseline()).unwrap();
        let mut finding = Finding::candidate(
            "gitleaks",
            FindingKind::Secret,
            Severity::High,
            "human",
            "old/a.rs",
            Some(1),
            "",
            "",
            vec![],
        );
        finding.status = FindingStatus::Confirmed;
        finding.severity_basis = SeverityBasis::Operator;
        base.findings.push(finding);
        refresh_summary(&mut base);
        f.save(
            "20261101T000000Z.json",
            &serde_json::to_value(base).unwrap(),
        );
        if deleted {
            std::fs::remove_file(f.root.join("old/a.rs")).unwrap();
        } else {
            std::fs::write(f.root.join("old/a.rs"), "fn fixed() {}\n").unwrap();
        }
        git(&f.root, &["commit", "-qam", "fixed or deleted"]).await;
        assert_eq!(
            f.scan(&["--profile", "deep", "--since-last", "--fail-on", "high"])
                .status
                .code(),
            Some(0)
        );
        let report = f.report();
        assert!(report["findings"].as_array().unwrap().is_empty());
        assert!(report["since_last"].get("carried_findings").is_none());
    }
}

#[tokio::test]
async fn explicit_diff_base_keeps_outside_scanner_finding_excluded() {
    let f = Fixture::new().await;
    f.scanner("old/a.rs");
    let _ = f.scan(&["--profile", "deep"]);
    f.save("20261101T000000Z.json", &f.report());
    assert_ok(&f.scan(&[
        "--profile",
        "deep",
        "--diff-base",
        "base",
        "--fail-on",
        "high",
    ]));
    let report = f.report();
    assert!(report.get("since_last").is_none());
    assert!(
        report["findings"][0]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["detail"] == "outside_diff_scope")
    );
}

#[tokio::test]
async fn ignored_intake_files_force_full_on_skip_and_changed_paths() {
    for changed in [false, true] {
        let f = Fixture::new().await;
        std::fs::write(f.root.join(".gitignore"), "*.secret.rs\n").unwrap();
        git(&f.root, &["add", "--all"]).await;
        git(&f.root, &["commit", "-qm", "ignore"]).await;
        f.save("20261101T000000Z.json", &f.baseline());
        std::fs::write(f.root.join("private.secret.rs"), "fn hidden() {}\n").unwrap();
        if changed {
            std::fs::write(f.root.join("new/b.rs"), "fn changed() {}\n").unwrap();
        }
        let out = f.scan(&["--profile", "deep", "--since-last"]);
        assert_ok(&out);
        assert!(f.report().get("since_last").is_none(), "{changed}");
        assert!(f.report().get("scope").is_none());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("1 ignored intake files"), "{stderr}");
        assert!(!stderr.contains("private.secret.rs"));
    }
}

#[tokio::test]
async fn index_flags_force_full_on_skip_and_changed_paths() {
    for flag in ["--assume-unchanged", "--skip-worktree"] {
        for changed in [false, true] {
            let f = Fixture::new().await;
            f.save("20261101T000000Z.json", &f.baseline());
            git(&f.root, &["update-index", flag, "old/a.rs"]).await;
            std::fs::write(f.root.join("old/a.rs"), "fn hidden() {}\n").unwrap();
            if changed {
                std::fs::write(f.root.join("new/b.rs"), "fn visible() {}\n").unwrap();
            }
            assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
            assert!(f.report().get("since_last").is_none(), "{flag} {changed}");
            assert!(f.report().get("scope").is_none());
        }
    }
}

#[tokio::test]
async fn closed_hash_mismatch_forces_full_even_on_skip_path() {
    use vettalon::audit::schema::*;
    for status in [FindingStatus::Refuted, FindingStatus::Suppressed] {
        for hash in [None, Some("0".repeat(64))] {
            let f = Fixture::new().await;
            let mut r: AuditReport = serde_json::from_value(f.baseline()).unwrap();
            let mut finding = Finding::candidate(
                "gitleaks",
                FindingKind::Secret,
                Severity::High,
                "closed",
                "old/a.rs",
                Some(1),
                "",
                "closed",
                vec![],
            );
            finding.status = status;
            finding.severity_basis = SeverityBasis::Operator;
            finding.file_hash = hash;
            finding.evidence.push(EvidenceItem {
                kind: EvidenceKind::OperatorReview,
                source: "dashboard".into(),
                detail: format!(
                    "operator_decision: {}",
                    serde_json::to_value(status).unwrap().as_str().unwrap()
                ),
                recorded_at: "2026-11-01T00:00:00Z".into(),
            });
            r.findings.push(finding);
            r.summary = Summary::from_findings(
                &r.findings,
                r.engines_run.len(),
                r.engines_missing.len(),
                GatePolicy::default(),
                &r.coverage,
            );
            f.save("20261101T000000Z.json", &serde_json::to_value(r).unwrap());
            assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
            assert!(f.report().get("since_last").is_none());
            assert!(f.report().get("scope").is_none());
        }
    }
}

#[tokio::test]
async fn since_last_mid_scan_change_is_incomplete_and_cannot_advance_base() {
    let f = Fixture::new().await;
    let baseline = f.baseline();
    f.save("20261101T000000Z.json", &baseline);
    std::fs::write(f.root.join("new/b.rs"), "fn next() {}\n").unwrap();
    git(&f.root, &["commit", "-qam", "next"]).await;
    let target = serde_json::to_string(&f.root.join("old/a.rs")).unwrap();
    std::fs::write(
        f._temp.path().join("finder.sh"),
        format!(
            "/bin/cat > /dev/null\nprintf '%s' 'fn changed() {{}}' > {target}\nprintf '%s' '[]'\n"
        ),
    )
    .unwrap();
    let out = f.scan(&["--profile", "deep", "--since-last"]);
    // Existing incomplete handling uses the gate verdict when a finder ran.
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let r = f.report();
    assert_eq!(r["scope"]["changed_during_scan"], 1);
    assert_eq!(r["run_status"], "incomplete");
    assert_eq!(r["incomplete_reason"], "scope_not_fully_reviewed");
    f.save("20261102T000000Z.json", &r);
    git(&f.root, &["checkout", "--", "old/a.rs"]).await;
    std::fs::write(
        f._temp.path().join("finder.sh"),
        "/bin/cat > /dev/null\nprintf '%s' '[]'\n",
    )
    .unwrap();
    assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
    assert_eq!(
        f.report()["since_last"]["base_report"],
        "20261101T000000Z.json"
    );
}

#[tokio::test]
async fn since_last_mid_scan_usage_limit_keeps_scope_reason() {
    let f = Fixture::new().await;
    f.save("20261101T000000Z.json", &f.baseline());
    std::fs::write(f.root.join("new/b.rs"), "fn next() {}\n").unwrap();
    git(&f.root, &["commit", "-qam", "next"]).await;
    let target = serde_json::to_string(&f.root.join("old/a.rs")).unwrap();
    let codex = f.bin.join("codex");
    std::fs::write(&codex, format!("#!/bin/sh\n/bin/cat > /dev/null\nprintf '%s' 'fn changed() {{}}' > {target}\nprintf usage_limit_reached >&2\nexit 1\n")).unwrap();
    std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = std::fs::read_to_string(&f.config).unwrap().replace(
        "program = '/bin/sh'",
        &format!("program = {}", serde_json::to_string(&codex).unwrap()),
    );
    std::fs::write(&f.config, config).unwrap();
    let out = f.scan(&["--profile", "deep", "--since-last"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let r = f.report();
    assert_eq!(r["scope"]["changed_during_scan"], 1);
    assert_eq!(r["run_status"], "incomplete");
    assert_eq!(r["incomplete_reason"], "scope_not_fully_reviewed");
}

#[tokio::test]
async fn since_last_existing_changed_content_or_new_ignored_intake_cannot_advance_base() {
    for ignored in [false, true] {
        let f = Fixture::new().await;
        std::fs::write(f.root.join(".gitignore"), "*.secret.rs\n").unwrap();
        git(&f.root, &["add", "--all"]).await;
        git(&f.root, &["commit", "-qm", "ignore intake"]).await;
        f.save("20261101T000000Z.json", &f.baseline());
        std::fs::write(f.root.join("new/b.rs"), "fn next() {}\n").unwrap();
        git(&f.root, &["commit", "-qam", "next"]).await;
        let path = if ignored {
            "new/private.secret.rs"
        } else {
            "new/b.rs"
        };
        let target = serde_json::to_string(&f.root.join(path)).unwrap();
        std::fs::write(
            f._temp.path().join("finder.sh"),
            format!(
                "/bin/cat > /dev/null\nprintf '%s' 'fn drift() {{}}' > {target}\nprintf '%s' '[]'\n"
            ),
        )
        .unwrap();
        let out = f.scan(&["--profile", "deep", "--since-last"]);
        assert_ok(&out);
        let r = f.report();
        assert_eq!(r["scope"]["changed_during_scan"].as_u64().unwrap_or(0), 0);
        assert_eq!(r["run_status"], "incomplete", "{r}");
        assert_eq!(r["incomplete_reason"], "scope_not_fully_reviewed");
        f.save("20261102T000000Z.json", &r);
        if ignored {
            std::fs::remove_file(f.root.join(path)).unwrap();
        } else {
            git(&f.root, &["checkout", "--", path]).await;
        }
        std::fs::write(
            f._temp.path().join("finder.sh"),
            "/bin/cat > /dev/null\nprintf '%s' '[]'\n",
        )
        .unwrap();
        assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
        assert_eq!(
            f.report()["since_last"]["base_report"],
            "20261101T000000Z.json"
        );
    }
}

#[tokio::test]
async fn newer_supplement_findings_survive_carry_prior_and_skip() {
    use vettalon::audit::schema::*;
    for variant in [
        "unchanged",
        "changed",
        "mode_only",
        "suppressed",
        "newest_suppressed",
        "nonancestor",
        "dirty",
        "missing_commit",
        "old_started_at",
        "confirmed_base_suppressed_supplement",
        "confirmed_base_needs_human_supplement",
        "confirmed_base_candidate_supplement",
        "suppressed_base_confirmed_supplement",
        "candidate_base_suppressed_supplement",
        "skip",
    ] {
        let f = Fixture::new().await;
        let mut base = f.baseline();
        f.scanner("old/a.rs");
        assert_eq!(f.scan(&["--profile", "deep"]).status.code(), Some(1));
        let mut newer: AuditReport = serde_json::from_value(f.report()).unwrap();
        let id = newer.findings[0].id.clone();
        if matches!(
            variant,
            "newest_suppressed"
                | "confirmed_base_suppressed_supplement"
                | "confirmed_base_needs_human_supplement"
                | "confirmed_base_candidate_supplement"
                | "suppressed_base_confirmed_supplement"
        ) {
            if variant == "confirmed_base_suppressed_supplement" {
                let mut parsed: AuditReport = serde_json::from_value(base.clone()).unwrap();
                parsed.findings = newer.findings.clone();
                parsed.findings[0].status = FindingStatus::Confirmed;
                parsed.findings[0].severity_basis = SeverityBasis::Operator;
                parsed.findings[0].evidence.push(EvidenceItem {
                    kind: EvidenceKind::OperatorReview,
                    source: "dashboard".into(),
                    detail: "operator_decision: confirmed".into(),
                    recorded_at: "2026-11-01T00:00:00Z".into(),
                });
                refresh_summary(&mut parsed);
                base = serde_json::to_value(parsed).unwrap();
            }
            if matches!(
                variant,
                "confirmed_base_needs_human_supplement" | "confirmed_base_candidate_supplement"
            ) {
                let mut parsed: AuditReport = serde_json::from_value(base.clone()).unwrap();
                parsed.findings = newer.findings.clone();
                parsed.findings[0].status = FindingStatus::Confirmed;
                parsed.findings[0].severity_basis = SeverityBasis::Operator;
                parsed.findings[0].evidence.push(EvidenceItem {
                    kind: EvidenceKind::OperatorReview,
                    source: "dashboard".into(),
                    detail: "operator_decision: confirmed".into(),
                    recorded_at: "2026-11-01T00:00:00Z".into(),
                });
                refresh_summary(&mut parsed);
                base = serde_json::to_value(parsed).unwrap();
            }
            if variant == "suppressed_base_confirmed_supplement" {
                let mut parsed: AuditReport = serde_json::from_value(base.clone()).unwrap();
                parsed.findings = newer.findings.clone();
                parsed.findings[0].status = FindingStatus::Suppressed;
                parsed.findings[0].severity_basis = SeverityBasis::Operator;
                refresh_summary(&mut parsed);
                base = serde_json::to_value(parsed).unwrap();
            }
            if variant == "newest_suppressed" {
                base["findings"] = serde_json::to_value(&newer.findings).unwrap();
                let mut parsed = serde_json::from_value(base).unwrap();
                refresh_summary(&mut parsed);
                base = serde_json::to_value(parsed).unwrap();
            }
        }
        f.save("20261101T000000Z.json", &base);
        if matches!(
            variant,
            "suppressed"
                | "newest_suppressed"
                | "confirmed_base_suppressed_supplement"
                | "confirmed_base_needs_human_supplement"
                | "candidate_base_suppressed_supplement"
        ) {
            let finding = &mut newer.findings[0];
            finding.status = FindingStatus::Suppressed;
            finding.severity_basis = SeverityBasis::Operator;
            finding.evidence.push(EvidenceItem {
                kind: EvidenceKind::OperatorReview,
                source: "dashboard".into(),
                detail: "operator_decision: suppressed".into(),
                recorded_at: "2026-11-02T00:00:00Z".into(),
            });
        }
        newer.run_status = vettalon_contract::coverage::RunStatus::Incomplete;
        newer.incomplete_reason = Some(vettalon_contract::coverage::IncompleteReason::UnitsFailed);
        if variant == "dirty" {
            newer.run_status = vettalon_contract::coverage::RunStatus::Complete;
            newer.incomplete_reason = None;
            newer.repo_tree_clean = Some(false);
        }
        if variant == "missing_commit" {
            newer.repo_commit = None;
        }
        if variant == "old_started_at" {
            newer.started_at = "2026-10-01T00:00:00Z".into();
        }
        if variant == "suppressed_base_confirmed_supplement" {
            newer.findings[0].status = FindingStatus::Confirmed;
            newer.findings[0].severity_basis = SeverityBasis::Operator;
            newer.findings[0].evidence.push(EvidenceItem {
                kind: EvidenceKind::OperatorReview,
                source: "dashboard".into(),
                detail: "operator_decision: confirmed".into(),
                recorded_at: "2026-11-02T00:00:00Z".into(),
            });
        }
        if variant == "candidate_base_suppressed_supplement" {
            newer.findings[0].status = FindingStatus::Suppressed;
            newer.findings[0].severity_basis = SeverityBasis::Operator;
        }
        if variant == "confirmed_base_needs_human_supplement" {
            newer.findings[0].status = FindingStatus::NeedsHuman;
            newer.findings[0].evidence.push(EvidenceItem {
                kind: EvidenceKind::AdversarialReview,
                source: "fixture_review".into(),
                detail: format!("{} fixture", vettalon::audit::schema::PLAUSIBLE_PREFIX),
                recorded_at: "2026-11-02T00:00:00Z".into(),
            });
            newer.findings[0].blockers = vec!["manual validation required".into()];
            newer.findings[0].validation_plan = Some(ValidationPlan {
                local: Some("validate the finding locally".into()),
                deployment: None,
            });
        }
        if variant == "confirmed_base_candidate_supplement" {
            newer.findings[0].status = FindingStatus::Candidate;
        }
        if variant == "nonancestor" {
            git(&f.root, &["checkout", "-qb", "side"]).await;
            std::fs::write(f.root.join("old/a.rs"), "fn side() {}\n").unwrap();
            git(&f.root, &["commit", "-qam", "side"]).await;
            newer.repo_commit = Some(git(&f.root, &["rev-parse", "HEAD"]).await.trim().into());
            git(&f.root, &["checkout", "-q", "-"]).await;
        }
        refresh_summary(&mut newer);
        f.save(
            if variant == "old_started_at" {
                "zzzz-newest-name.json"
            } else {
                "20261102T000000Z.json"
            },
            &serde_json::to_value(newer).unwrap(),
        );
        f.scanner_raw("[]");
        match variant {
            "changed" => std::fs::write(f.root.join("old/a.rs"), "fn fixed() {}\n").unwrap(),
            "mode_only" => {
                git(&f.root, &["update-index", "--chmod=+x", "old/a.rs"]).await;
                std::fs::set_permissions(
                    f.root.join("old/a.rs"),
                    std::fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }
            "skip" => {}
            _ => std::fs::write(f.root.join("new/b.rs"), "fn next() {}\n").unwrap(),
        }
        if variant != "skip" {
            git(&f.root, &["commit", "-qam", "next"]).await;
        }
        let out = f.scan(&["--profile", "deep", "--since-last", "--fail-on", "high"]);
        let report = f.report();
        assert_eq!(
            report["since_last"]["base_report"], "20261101T000000Z.json",
            "{variant}: {report}"
        );
        assert_eq!(report["since_last"]["base_commit"], base["repo_commit"]);
        assert_eq!(report["since_last"]["skipped"], variant == "skip");
        let findings = report["findings"].as_array().unwrap();
        if matches!(variant, "missing_commit" | "old_started_at") {
            assert_ok(&out);
            assert!(findings.is_empty(), "{variant}: {report}");
            assert_eq!(report["summary"]["carried_from_prior"], 0);
            continue;
        }
        if matches!(variant, "changed" | "nonancestor") {
            assert_ok(&out);
            assert!(findings.is_empty(), "{variant}: {report}");
            if variant == "changed" {
                assert_eq!(
                    report["prior_run"]["changed_unrediscovered"][0]["file"],
                    "old/a.rs"
                );
                assert_eq!(
                    report["prior_run"]["changed_unrediscovered"][0]["reason"],
                    "source_changed"
                );
            }
        } else {
            assert_eq!(findings.len(), 1, "{variant}: {report}");
            assert_eq!(findings[0]["id"], id);
            if matches!(
                variant,
                "suppressed"
                    | "newest_suppressed"
                    | "candidate_base_suppressed_supplement"
                    | "confirmed_base_suppressed_supplement"
                    | "suppressed_base_confirmed_supplement"
                    | "old_started_at"
            ) {
                if matches!(
                    variant,
                    "suppressed" | "newest_suppressed" | "candidate_base_suppressed_supplement"
                ) {
                    assert_ok(&out);
                }
                if variant == "confirmed_base_suppressed_supplement" {
                    assert_eq!(findings[0]["status"], "confirmed");
                } else if matches!(
                    variant,
                    "confirmed_base_needs_human_supplement"
                        | "confirmed_base_candidate_supplement"
                        | "suppressed_base_confirmed_supplement"
                ) {
                    assert_eq!(findings[0]["status"], "confirmed");
                    assert_eq!(out.status.code(), Some(1));
                } else if variant == "candidate_base_suppressed_supplement" {
                    assert_eq!(findings[0]["status"], "suppressed");
                    assert_eq!(out.status.code(), Some(0));
                } else if variant == "old_started_at" {
                    assert_eq!(findings[0]["status"], "candidate");
                    assert_eq!(out.status.code(), Some(1));
                } else {
                    assert_eq!(findings[0]["status"], "suppressed");
                }
                if matches!(variant, "suppressed" | "newest_suppressed") {
                    assert!(
                        findings[0]["evidence"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|e| e["source"] == "dashboard")
                    );
                }
            } else {
                assert_eq!(out.status.code(), Some(1), "{variant}: {out:?}");
            }
            if variant == "mode_only" {
                assert!(
                    findings[0]["evidence"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|e| e["source"] == "prior_run")
                );
            }
        }
    }
}

#[tokio::test]
async fn deleted_file_completes_advances_baseline_then_skips() {
    let f = Fixture::new().await;
    f.save("20261101T000000Z.json", &f.baseline());
    std::fs::remove_file(f.root.join("old/a.rs")).unwrap();
    git(&f.root, &["commit", "-qam", "delete file"]).await;
    assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
    let report = f.report();
    assert_eq!(report["run_status"], "partial_by_design");
    assert_eq!(report["since_last"]["skipped"], false);
    f.save("20261102T000000Z.json", &report);
    assert_ok(&f.scan(&["--profile", "deep", "--since-last"]));
    assert_eq!(f.report()["since_last"]["skipped"], true);
    assert_eq!(
        f.report()["since_last"]["base_report"],
        "20261102T000000Z.json"
    );
}

#[tokio::test]
async fn supplements_are_limited_to_five_newest_compatible_reports() {
    let f = Fixture::new().await;
    let base = f.baseline();
    f.save("20261101T000000Z.json", &base);
    f.scanner("old/a.rs");
    assert_eq!(f.scan(&["--profile", "deep"]).status.code(), Some(1));
    let mut oldest = f.report();
    oldest["run_status"] = "incomplete".into();
    oldest["incomplete_reason"] = "units_failed".into();
    f.save("20261102T000000Z.json", &oldest);
    for day in 3..=7 {
        let mut newer = base.clone();
        newer["run_status"] = "incomplete".into();
        newer["incomplete_reason"] = "units_failed".into();
        newer["started_at"] = format!("2026-10-{day:02}T00:00:00Z").into();
        f.save(&format!("202611{day:02}T000000Z.json"), &newer);
    }
    let mut truly_newer = base.clone();
    truly_newer["run_status"] = "incomplete".into();
    truly_newer["incomplete_reason"] = "units_failed".into();
    truly_newer["started_at"] = "2026-11-03T00:00:00Z".into();
    f.save("20261031T000000Z.json", &truly_newer);
    f.scanner_raw("[]");
    std::fs::write(f.root.join("new/b.rs"), "fn next() {}\n").unwrap();
    git(&f.root, &["commit", "-qam", "next"]).await;
    let out = f.scan(&["--profile", "deep", "--since-last"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let report = f.report();
    assert_eq!(report["findings"][0]["file"], "old/a.rs");
    assert_eq!(report["since_last"]["base_report"], "20261101T000000Z.json");
}
