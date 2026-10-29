#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use vettalon::audit::schema::{
    CURRENT_SCHEMA_VERSION, EvidenceItem, EvidenceKind, Finding, FindingKind, FindingStatus,
    GatePolicy, PLAUSIBLE_PREFIX, Severity, Summary, ValidationPlan,
};

struct Fixture {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    empty_path: PathBuf,
    calls: PathBuf,
    finding: Finding,
}

impl Fixture {
    fn new(status: FindingStatus) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let home = dir.path().join("home");
        let empty_path = dir.path().join("empty-path");
        std::fs::create_dir(&repo).unwrap();
        std::fs::create_dir(&empty_path).unwrap();
        std::fs::create_dir_all(home.join("reports")).unwrap();
        let source = "fn main() { println!(\"hello\"); }\n";
        std::fs::write(repo.join("main.rs"), source).unwrap();
        let mut finding = Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::High,
            "Prior claim",
            "main.rs",
            Some(1),
            "",
            "prior-cli-test",
            vec![],
        );
        finding.status = status;
        if status == FindingStatus::NeedsHuman {
            finding.evidence.push(EvidenceItem {
                kind: EvidenceKind::AdversarialReview,
                source: "fixture_review".into(),
                detail: format!("{PLAUSIBLE_PREFIX} fixture"),
                recorded_at: "2026-10-01T00:00:00Z".into(),
            });
            finding.blockers = vec!["fixture needs manual validation".into()];
            finding.validation_plan = Some(ValidationPlan {
                local: Some("validate fixture claim".into()),
                deployment: None,
            });
        }
        finding.found_by = vec!["retired-finder".into()];
        finding.file_hash = Some(hex::encode(Sha256::digest(source.as_bytes())));
        let prior = serde_json::json!({
            "schema_version": CURRENT_SCHEMA_VERSION,
            "repo": repo.canonicalize().unwrap(),
            "started_at": "2026-10-01T00:00:00Z",
            "profile": {"mode": "quick", "intake": null},
            "engines_run": [], "engines_missing": [],
            "summary": Summary::from_findings(std::slice::from_ref(&finding), 0, 0, GatePolicy::default(), &[]),
            "findings": [finding]
        });
        let parsed = serde_json::from_value(prior.clone()).unwrap();
        let violations = vettalon::audit::validation_errors(&parsed);
        assert!(
            violations.is_empty(),
            "invalid prior fixture: {violations:?}"
        );
        std::fs::write(home.join("reports/p.json"), prior.to_string()).unwrap();
        let script = dir.path().join("verifier.sh");
        std::fs::write(
            &script,
            r#"/bin/cat > /dev/null
printf 'called\n' >> "$0.called"
printf '%s' '{"verdict":"refuted","reason":"not reachable","blockers":[],"validation_plan":{"local":null,"deployment":null},"refute_basis":"unreachable"}'
"#,
        )
        .unwrap();
        std::fs::write(
            home.join("config.toml"),
            format!(
                "[[model]]\nid = \"checker\"\nbackend = \"cli\"\nfamily = \"test\"\nroles = [\"verifier\"]\nprogram = \"/bin/sh\"\nargs = [{}]\nprompt_via = \"stdin\"\nallow_agent_tools = true\n",
                serde_json::to_string(&script).unwrap()
            ),
        )
        .unwrap();
        Self {
            calls: script.with_extension("sh.called"),
            _dir: dir,
            repo,
            home,
            empty_path,
            finding,
        }
    }

    fn scan(&self, args: &[&str], lang: &str) -> (Output, serde_json::Value) {
        let output_path = self.home.join("out.json");
        let output = Command::new(env!("CARGO_BIN_EXE_vettalon"))
            .env("VETTALON_HOME", &self.home)
            // Keep host-installed scanners out of this model-boundary test.
            .env("PATH", &self.empty_path)
            .args(["--lang", lang, "scan"])
            .arg(&self.repo)
            .args([
                "--refuter-runs",
                "1",
                "--fail-on",
                "high",
                "--fail-on-needs-human",
                "--gate",
                "severity>=high status=candidate,confirmed,needs_human count>0",
                "--report",
            ])
            .arg(&output_path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = serde_json::from_slice(&std::fs::read(output_path).unwrap()).unwrap();
        (output, report)
    }

    fn call_count(&self) -> usize {
        if self.calls.exists() {
            std::fs::read_to_string(&self.calls)
                .unwrap()
                .lines()
                .count()
        } else {
            0
        }
    }
}

#[test]
fn quick_prior_claims_are_display_only_without_loading_or_calling_models() {
    for status in [FindingStatus::Candidate, FindingStatus::NeedsHuman] {
        for lang in ["en", "zh-TW"] {
            let fixture = Fixture::new(status);
            let args: &[&str] = if lang == "en" {
                &[]
            } else {
                &["--profile", "quick"]
            };
            let (output, report) = fixture.scan(args, lang);
            assert_eq!(
                fixture.call_count(),
                0,
                "quick must never invoke the verifier"
            );
            assert!(report["findings"].as_array().unwrap().is_empty());
            assert!(report["ensemble"]["models"].as_array().unwrap().is_empty());
            assert_eq!(report["prior_run"]["carried_not_rediscovered"], 0);
            assert_eq!(report["prior_run"]["prior_gap_modules"], 0);
            assert_eq!(
                report["prior_run"]["changed_unrediscovered"],
                serde_json::json!([{
                    "id": fixture.finding.id,
                    "file": fixture.finding.file,
                    "title": fixture.finding.title,
                    "reason": "quick_profile_not_rechecked"
                }])
            );
            assert_eq!(report["summary"]["total_findings"], 0);
            assert_eq!(report["summary"]["policy"][0]["count"], 0);
            assert_eq!(report["summary"]["policy"][0]["failed"], false);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("--profile deep"));
            assert!(stdout.contains(if lang == "en" {
                "1 not re-checked"
            } else {
                "1 筆未重新檢查"
            }));
            assert!(!String::from_utf8_lossy(&output.stderr).contains("models ("));
        }
    }
}

#[test]
fn quick_prior_claims_do_not_even_read_model_config() {
    let fixture = Fixture::new(FindingStatus::Candidate);
    std::fs::write(fixture.home.join("config.toml"), "invalid model config [").unwrap();
    let (output, report) = fixture.scan(&["--time-budget", "60"], "en");
    assert_eq!(fixture.call_count(), 0);
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("quick runs no model"));
}

#[test]
fn deep_prior_claims_are_carried_and_verified_once_without_a_finder() {
    for status in [FindingStatus::Candidate, FindingStatus::NeedsHuman] {
        let fixture = Fixture::new(status);
        let (output, report) = fixture.scan(&["--profile", "deep", "--allow-incomplete"], "en");
        assert_eq!(fixture.call_count(), 1);
        assert_eq!(report["prior_run"]["carried_not_rediscovered"], 1);
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["id"], fixture.finding.id);
        assert_eq!(findings[0]["status"], "refuted");
        assert!(findings[0]["found_by"].as_array().unwrap().is_empty());
        assert_eq!(findings[0]["verification"][0]["cross_family"], false);
        assert_eq!(findings[0]["verification"][0]["same_model"], false);
        assert_eq!(findings[0]["verification"].as_array().unwrap().len(), 1);
        assert!(findings[0]["evidence"].as_array().unwrap().iter().any(|e| {
            e["source"] == "prior_run"
                && e["detail"]
                    .as_str()
                    .unwrap()
                    .starts_with("prior_not_rediscovered:")
        }));
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 carried for review"));
    }
}

#[test]
fn no_prior_disables_both_quick_display_and_deep_carry_and_verification() {
    for status in [FindingStatus::Candidate, FindingStatus::NeedsHuman] {
        for profile in ["quick", "deep"] {
            let fixture = Fixture::new(status);
            let (_, report) = fixture.scan(
                &["--profile", profile, "--no-prior", "--allow-incomplete"],
                "en",
            );
            assert_eq!(fixture.call_count(), 0);
            assert!(report["prior_run"].is_null());
            assert!(report["findings"].as_array().unwrap().is_empty());
        }
    }
}

#[test]
fn invalid_prior_is_skipped_with_one_stderr_line_in_both_profiles() {
    for profile in ["quick", "deep"] {
        let fixture = Fixture::new(FindingStatus::Candidate);
        let path = fixture.home.join("reports/p.json");
        let mut prior: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        prior["summary"]["total_findings"] = 999.into();
        std::fs::write(path, prior.to_string()).unwrap();
        let (output, report) = fixture.scan(&["--profile", profile, "--allow-incomplete"], "en");
        assert!(report["prior_run"].is_null());
        assert!(report["findings"].as_array().unwrap().is_empty());
        assert_eq!(fixture.call_count(), 0);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains("skipping previous report"))
            .collect();
        assert_eq!(
            lines,
            ["[vettalon] skipping previous report: report validation failed"]
        );
    }
}
