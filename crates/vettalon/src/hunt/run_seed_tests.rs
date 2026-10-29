//! Offline tests for risk ordering (O8) and variant seeds (O7) in the hunt loop.

use super::*;
use crate::audit::schema::{FindingKind, Severity};
use crate::hunt::seeds::{AdvisorySeed, CommitSeed, SeedMatch};
use chrono::{DateTime, Utc};
use std::sync::{Arc, Mutex};

struct NoOsv;
#[async_trait]
impl OsvClient for NoOsv {
    async fn known_vulns(&self, _: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
        Ok(vec![])
    }
}

/// Unmatched at plan time, a new advisory at the post-seed re-check.
struct LateAdvisory(Mutex<usize>);
#[async_trait]
impl OsvClient for LateAdvisory {
    async fn known_vulns(&self, _: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
        let mut n = self.0.lock().unwrap();
        *n += 1;
        Ok(if *n > 1 {
            vec![KnownVuln {
                id: "GHSA-late".into(),
                aliases: vec![],
            }]
        } else {
            vec![]
        })
    }
}

struct WriteFetcher;
#[async_trait]
impl SourceFetcher for WriteFetcher {
    async fn fetch_into(
        &self,
        t: &DependencyTarget,
        dest: &Path,
    ) -> Result<super::super::fetch::ExtractStats, String> {
        let root = dest.join(format!("{}-{}", t.name, t.version));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='x'\nversion='1.0.0'\nrepository='https://github.com/acme/x'\n",
        )
        .unwrap();
        std::fs::write(root.join("src/unpack.rs"), "fn f(){}").unwrap();
        Ok(super::super::fetch::ExtractStats { files: 2, bytes: 8 })
    }
}

fn finding(file: &str, cwe: &str) -> Finding {
    let mut f = Finding::candidate(
        "ai_audit",
        FindingKind::Other,
        Severity::High,
        "t",
        file,
        Some(1),
        "s",
        "ai-audit/x",
        vec![],
    );
    f.status = FindingStatus::NeedsHuman;
    f.cwe = Some(cwe.into());
    f
}

/// Records the seed block it was given and returns two findings.
struct SeedAwareAuditor {
    seen: Arc<Mutex<Option<String>>>,
}
#[async_trait]
impl DirAuditor for SeedAwareAuditor {
    async fn audit(&self, _: &Path) -> Result<Vec<Finding>, String> {
        unreachable!("evidence path is used")
    }
    async fn audit_with_evidence(&self, _: &Path) -> Result<DirAuditResult, String> {
        Ok(DirAuditResult {
            findings: vec![
                finding("src/unpack.rs", "CWE-22"),
                finding("src/other.rs", "CWE-79"),
            ],
            evidence: DependencyAuditEvidence {
                run_status: Some(RunStatus::Complete),
                ..Default::default()
            },
        })
    }
    async fn audit_seeded(
        &self,
        dir: &Path,
        seeds: &SeedContext,
    ) -> Result<(DirAuditResult, bool), String> {
        *self.seen.lock().unwrap() = Some(seeds.block.clone());
        Ok((self.audit_with_evidence(dir).await?, true))
    }
}

struct FakeSeeds;
#[async_trait]
impl SeedSource for FakeSeeds {
    async fn osv_history(&self, _: &DependencyTarget) -> Result<Vec<AdvisorySeed>, String> {
        Ok(vec![AdvisorySeed {
            id: "GHSA-old".into(),
            summary: "path traversal in unpack.rs".into(),
            cwe_ids: vec!["CWE-22".into()],
            // Fixed above the locked 1.0.0, so the advisory claims this version.
            fixed_versions: vec!["1.0.1".into()],
            ..Default::default()
        }])
    }
    async fn security_commits(
        &self,
        slug: &str,
        _: DateTime<Utc>,
    ) -> Result<Vec<CommitSeed>, String> {
        assert_eq!(slug, "acme/x", "slug comes from the fetched manifest");
        Ok(vec![CommitSeed {
            sha: "abc".into(),
            date: "2026-10-01".into(),
            subject: "security: reject absolute paths".into(),
            url: String::new(),
        }])
    }
}

fn project(dir: &Path, deps: &[&str]) {
    let mut toml = String::from("[package]\nname=\"app\"\nversion=\"0.1.0\"\n[dependencies]\n");
    let mut lock = String::from("[[package]]\nname=\"app\"\nversion=\"0.1.0\"\n");
    for d in deps {
        toml.push_str(&format!("{d} = \"1\"\n"));
        lock.push_str(&format!(
            "\n[[package]]\nname=\"{d}\"\nversion=\"1.0.0\"\nsource=\"registry+x\"\n"
        ));
    }
    std::fs::write(dir.join("Cargo.toml"), toml).unwrap();
    std::fs::write(dir.join("Cargo.lock"), lock).unwrap();
}

#[tokio::test]
async fn risk_priority_reorders_selection_and_records_breakdown() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path(), &["aaa-plain", "quick-xml", "zzz-other"]);
    let default = plan_hunt(dir.path(), &HuntOptions::default(), &NoOsv)
        .await
        .unwrap();
    assert_eq!(default.selected[0].target.name, "aaa-plain");
    assert!(default.priorities.is_empty());
    let opts = HuntOptions {
        dep_priority: DepPriority::Risk,
        max_deps: 1,
        ..Default::default()
    };
    let risk = plan_hunt(dir.path(), &opts, &NoOsv).await.unwrap();
    assert_eq!(
        risk.selected[0].target.name, "quick-xml",
        "parser exposure wins the slot"
    );
    assert_eq!(
        risk.priorities.len(),
        3,
        "breakdown for selected and over-budget"
    );
    assert_eq!(risk.priorities[0].target.name, "quick-xml");
    let text = render_plan(&risk);
    assert!(text.contains("score "), "{text}");
    assert!(text.contains("exposure 1.00"), "{text}");
}

#[tokio::test]
async fn seeds_reach_the_finder_and_known_duplicates_are_never_novel() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path(), &["x"]);
    let seen = Arc::new(Mutex::new(None));
    let opts = HuntOptions {
        variant_seeds: Some(SeedOptions::default()),
        ..Default::default()
    };
    let report = run_hunt_seeded(
        dir.path(),
        &opts,
        &NoOsv,
        &WriteFetcher,
        &SeedAwareAuditor { seen: seen.clone() },
        &NoHuntProgress,
        Some(&FakeSeeds),
    )
    .await
    .unwrap();
    let block = seen.lock().unwrap().clone().unwrap();
    assert!(block.contains("GHSA-old") && block.contains("reject absolute paths"));
    let dep = &report.audited[0];
    let seeds = dep.seeds.as_ref().unwrap();
    assert!(seeds.delivered_to_finders);
    assert_eq!(seeds.osv_recheck, OsvStatus::Unmatched);
    assert_eq!(seeds.dedup[0].verdict, SeedMatch::DuplicateOfKnown);
    assert_eq!(
        seeds.dedup.len(),
        1,
        "the unrelated CWE-79 finding has no seed relation"
    );
    let novel = report.novel_candidates();
    assert_eq!(novel.len(), 1, "the duplicate of GHSA-old is excluded");
    assert_eq!(novel[0].1.file, "src/other.rs");
    assert!(render_summary(&report).contains("GHSA-old"));
}

#[tokio::test]
async fn post_seed_osv_recheck_turns_a_late_advisory_into_known() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path(), &["x"]);
    let opts = HuntOptions {
        variant_seeds: Some(SeedOptions::default()),
        ..Default::default()
    };
    let report = run_hunt_seeded(
        dir.path(),
        &opts,
        &LateAdvisory(Mutex::new(0)),
        &WriteFetcher,
        &SeedAwareAuditor {
            seen: Default::default(),
        },
        &NoHuntProgress,
        Some(&FakeSeeds),
    )
    .await
    .unwrap();
    let dep = &report.audited[0];
    assert_eq!(dep.seeds.as_ref().unwrap().osv_recheck, OsvStatus::Matched);
    assert_eq!(dep.known[0].id, "GHSA-late");
    assert!(report.novel_candidates().is_empty());
}

#[tokio::test]
async fn seed_request_without_source_or_seed_support_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    project(dir.path(), &["x"]);
    let opts = HuntOptions {
        variant_seeds: Some(SeedOptions::default()),
        ..Default::default()
    };
    struct Plain;
    #[async_trait]
    impl DirAuditor for Plain {
        async fn audit(&self, _: &Path) -> Result<Vec<Finding>, String> {
            Ok(vec![])
        }
    }
    let report = run_hunt_seeded(
        dir.path(),
        &opts,
        &NoOsv,
        &WriteFetcher,
        &Plain,
        &NoHuntProgress,
        Some(&FakeSeeds),
    )
    .await
    .unwrap();
    let seeds = report.audited[0].seeds.as_ref().unwrap();
    assert!(
        !seeds.delivered_to_finders,
        "a legacy auditor ignores seeds and says so"
    );
    let none = run_hunt_seeded(
        dir.path(),
        &opts,
        &NoOsv,
        &WriteFetcher,
        &Plain,
        &NoHuntProgress,
        None,
    )
    .await
    .unwrap();
    assert!(none.audited[0].seeds.as_ref().unwrap().errors[0].contains("no seed source"));
    assert!(
        none.incomplete_reasons
            .contains(&"variant_seed_lookup_failed".to_string())
    );
}

#[tokio::test]
async fn engine_auditor_prepends_seeds_to_finder_prompts_only() {
    struct Capture(Arc<Mutex<Vec<String>>>);
    #[async_trait]
    impl crate::llm::LlmCaller for Capture {
        async fn complete(&self, p: &str) -> crate::llm::Result<String> {
            self.0.lock().unwrap().push(p.to_string());
            Ok("[]".into())
        }
    }
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let home = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("lib.rs"), "fn f(){}").unwrap();
    let auditor = EngineAuditor {
        attack_classes: Default::default(),
        home: home.path().into(),
        finders: vec![crate::llm::ModelHandle {
            id: "mock".into(),
            family: "fixture".into(),
            caller: Arc::new(Capture(prompts.clone())),
        }],
        verifiers: vec![],
        poc_models: vec![],
        roster: vec![],
        max_modules: 1,
        poc: false,
        poc_image: crate::sandbox::DEFAULT_POC_IMAGE.into(),
    };
    let ctx = SeedContext {
        record: SeedRecord::default(),
        block: "=== VARIANT SEEDS for x@1 ===\nhint\n=== END VARIANT SEEDS ===\n".into(),
    };
    let (_, delivered) = auditor.audit_seeded(src.path(), &ctx).await.unwrap();
    assert!(delivered);
    let prompts = prompts.lock().unwrap();
    assert!(!prompts.is_empty());
    assert!(prompts.iter().all(|p| p.starts_with("=== VARIANT SEEDS")));
}
