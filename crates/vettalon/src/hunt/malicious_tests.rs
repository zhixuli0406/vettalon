//! Offline tests and the replay measurement for malicious-package signals.

use super::*;
use crate::hunt::mal_index;
use crate::hunt::osv::{OsvEvidence, OsvStatus};
use crate::hunt::registry::ScriptFacts;
use async_trait::async_trait;

fn t(eco: Ecosystem, name: &str, version: &str) -> DependencyTarget {
    DependencyTarget {
        ecosystem: eco,
        name: name.into(),
        version: version.into(),
        direct: true,
    }
}

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-20T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn old_benign_facts() -> ReleaseFacts {
    ReleaseFacts {
        exists: Some(true),
        published_at: Some(now() - chrono::Duration::days(200)),
        previous_version: Some("0.9.0".into()),
        scripts: Some(ScriptFacts::default()),
        previous_scripts: Some(ScriptFacts::default()),
        provenance: Provenance::Absent,
        previous_provenance: Provenance::Absent,
        ..Default::default()
    }
}

#[test]
fn edit_distance_handles_transpositions_and_bounds() {
    assert_eq!(edit_distance("lodash", "lodahs", 1), Some(1));
    assert_eq!(edit_distance("requests", "reqeusts", 1), Some(1));
    assert_eq!(edit_distance("abc", "abc", 1), Some(0));
    assert_eq!(edit_distance("express", "expresss", 1), Some(1));
    assert_eq!(edit_distance("react", "preact-x", 1), None);
}

#[test]
fn typosquat_flags_near_misses_but_not_listed_or_short_names() {
    let s = typosquat(Ecosystem::Npm, "expresss").unwrap().unwrap();
    assert!(s.evidence.contains("'express'"), "{}", s.evidence);
    assert!(typosquat(Ecosystem::Npm, "express").unwrap().is_none());
    assert!(typosquat(Ecosystem::PyPi, "requets").unwrap().is_some());
    assert!(
        typosquat(Ecosystem::PyPi, "Requests").unwrap().is_none(),
        "PEP 503"
    );
    assert!(typosquat(Ecosystem::Cargo, "serde_json").unwrap().is_none());
    assert!(
        typosquat(Ecosystem::Npm, "abcd").unwrap().is_none(),
        "too short"
    );
    assert!(
        typosquat(Ecosystem::Go, "github.com/x/y").is_err(),
        "unsupported is unknown"
    );
}

#[test]
fn registry_rules_cover_age_hooks_provenance_and_existence() {
    let opts = MaliciousOptions::default();
    let target = t(Ecosystem::Npm, "some-lib", "4.2.1");
    let mut facts = old_benign_facts();
    let mut check = PackageCheck::default();
    registry_signals(&target, &facts, &opts, now(), &mut check);
    assert!(check.signals.is_empty(), "{:?}", check.signals);
    assert!(
        check
            .rules_evaluated
            .contains(&"install_scripts".to_string())
    );

    facts.published_at = Some(now() - chrono::Duration::hours(5));
    facts.scripts = Some(ScriptFacts {
        hooks: vec!["postinstall".into()],
        digest: Some("x".into()),
    });
    facts.previous_provenance = Provenance::Present {
        repository: None,
        workflow: None,
        ref_kind: None,
    };
    let mut check = PackageCheck {
        target: Some(target.clone()),
        ..Default::default()
    };
    registry_signals(&target, &facts, &opts, now(), &mut check);
    let kinds: Vec<SignalKind> = check.signals.iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        vec![
            SignalKind::YoungRelease,
            SignalKind::InstallScriptAdded,
            SignalKind::ProvenanceDropped
        ]
    );
    let f = finding_for(&check).unwrap();
    assert_eq!(f.status, MaliciousStatus::NeedsHuman);
    assert_eq!(f.kind, "malicious_package_signal");
    assert_eq!(
        serde_json::to_value(f.status).unwrap(),
        serde_json::json!("needs_human")
    );

    // Cooldown allowlist removes only the age rule.
    let allow = MaliciousOptions {
        cooldown_exclude: vec!["Some-Lib".into()],
        ..Default::default()
    };
    let mut check = PackageCheck::default();
    registry_signals(&target, &facts, &allow, now(), &mut check);
    assert!(
        !check
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::YoungRelease)
    );

    let mut check = PackageCheck::default();
    let gone = ReleaseFacts {
        exists: Some(false),
        ..Default::default()
    };
    registry_signals(&target, &gone, &opts, now(), &mut check);
    assert_eq!(check.signals[0].kind, SignalKind::NonexistentName);
}

#[test]
fn provenance_ref_kind_change_is_a_signal_but_tag_bumps_are_not() {
    let present = |kind: &str| Provenance::Present {
        repository: Some("https://github.com/o/r".into()),
        workflow: Some(".github/workflows/release.yml".into()),
        ref_kind: Some(kind.into()),
    };
    let target = t(Ecosystem::Npm, "x-lib", "1.0.1");
    let mut facts = old_benign_facts();
    facts.provenance = present("tags");
    facts.previous_provenance = present("tags");
    let mut check = PackageCheck::default();
    registry_signals(
        &target,
        &facts,
        &MaliciousOptions::default(),
        now(),
        &mut check,
    );
    assert!(check.signals.is_empty());
    facts.provenance = present("heads");
    let mut check = PackageCheck::default();
    registry_signals(
        &target,
        &facts,
        &MaliciousOptions::default(),
        now(),
        &mut check,
    );
    assert_eq!(check.signals[0].kind, SignalKind::ProvenanceChanged);
}

#[test]
fn single_medium_signal_is_an_observation_not_a_finding() {
    let check = offline_check(&t(Ecosystem::Npm, "expresss", "1.0.0"), Some(&[]), &[]);
    assert_eq!(check.signals.len(), 1);
    assert!(finding_for(&check).is_none());
    assert!(
        check
            .rules_unknown
            .iter()
            .any(|r| r.starts_with("mal_index"))
    );
}

#[test]
fn osv_mal_id_is_strong_and_failed_osv_is_unknown() {
    let known = vec![KnownVuln {
        id: "MAL-2026-6959".into(),
        aliases: vec![],
    }];
    let check = offline_check(
        &t(Ecosystem::Cargo, "proton-pfff", "99.99.5"),
        Some(&known),
        &[],
    );
    assert!(finding_for(&check).is_some());
    let unknown = offline_check(&t(Ecosystem::Cargo, "proton-pfff", "99.99.5"), None, &[]);
    assert!(
        unknown
            .rules_unknown
            .iter()
            .any(|r| r.starts_with("osv_mal_id"))
    );
}

struct FixedProbe(ReleaseFacts);
#[async_trait]
impl RegistryProbe for FixedProbe {
    async fn release_facts(&self, _: &DependencyTarget) -> Result<ReleaseFacts, String> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn check_all_respects_budget_ignores_failed_osv_and_reports_completeness() {
    let targets = vec![
        t(Ecosystem::Npm, "a-lib", "1.0.0"),
        t(Ecosystem::Npm, "b-lib", "1.0.0"),
    ];
    let rows = vec![DependencyAdvisories {
        target: targets[0].clone(),
        known: vec![],
        osv: OsvEvidence {
            status: OsvStatus::Failed,
            ..Default::default()
        },
    }];
    let probe = FixedProbe(old_benign_facts());
    let opts = MaliciousOptions {
        max_registry_checks: 1,
        ..Default::default()
    };
    let r = check_all(&targets, &rows, Some(&probe), &[], &opts, now()).await;
    assert_eq!(r.checks.len(), 2);
    assert!(r.findings.is_empty());
    assert!(!r.complete);
    assert!(
        r.incomplete_reasons
            .contains(&"registry_check_budget_exhausted".to_string())
    );
    assert!(
        r.incomplete_reasons
            .contains(&"mal_index_absent".to_string())
    );
    assert!(
        r.incomplete_reasons
            .contains(&"osv_mal_id_unknown".to_string()),
        "a failed OSV query is an incomplete report, not a clean one: {:?}",
        r.incomplete_reasons
    );
    assert!(
        r.checks[0]
            .rules_unknown
            .iter()
            .any(|x| x == "osv_mal_id: OSV query failed for this dependency")
    );
    assert!(
        r.checks[1]
            .rules_unknown
            .iter()
            .any(|x| x.contains("budget"))
    );
    assert!(render(&r).contains("[incomplete: "));
}

// ── replay: real MAL names (metadata only) and benign popular packages ──

#[derive(serde::Deserialize)]
struct Replay {
    source: String,
    rows: Vec<ReplayRow>,
}

#[derive(serde::Deserialize)]
struct ReplayRow {
    id: String,
    ecosystem: String,
    name: String,
    versions: Vec<String>,
    all_versions: bool,
}

fn replay() -> Replay {
    serde_json::from_str(include_str!("testdata/mal-replay-90d.json")).unwrap()
}

fn benign(eco: Ecosystem) -> Vec<String> {
    let text = match eco {
        Ecosystem::Cargo => include_str!("testdata/benign-crates.txt"),
        Ecosystem::Npm => include_str!("testdata/benign-npm.txt"),
        Ecosystem::PyPi => include_str!("testdata/benign-pypi.txt"),
        Ecosystem::Go => "",
    };
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Build per-ecosystem indexes from the replay rows (real record shapes).
fn replay_indexes(rows: &[ReplayRow]) -> Vec<MalIndex> {
    let mut by_eco: HashMap<&str, Vec<serde_json::Value>> = HashMap::new();
    for r in rows {
        by_eco.entry(r.ecosystem.as_str()).or_default().push(serde_json::json!({
            "id": r.id,
            "affected": [{
                "package": {"ecosystem": r.ecosystem, "name": r.name},
                "versions": r.versions,
                "ranges": if r.all_versions { serde_json::json!([{"type":"SEMVER","events":[{"introduced":"0"}]}]) } else { serde_json::json!([]) }
            }]
        }));
    }
    by_eco
        .into_iter()
        .map(|(eco, recs)| {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            for (i, rec) in recs.iter().enumerate() {
                use std::io::Write;
                w.start_file(
                    format!("MAL-{i}.json"),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
                w.write_all(rec.to_string().as_bytes()).unwrap();
            }
            let bytes = w.finish().unwrap().into_inner();
            mal_index::build_from_zip(
                std::io::Cursor::new(bytes),
                eco,
                ("replay", "replay-sha", 0, false, "2026-10-20T00:00:00Z"),
            )
            .unwrap()
        })
        .collect()
}

#[tokio::test]
async fn replay_recall_on_recent_mal_entries_and_fp_on_benign_popular_packages() {
    let data = replay();
    assert!(data.source.contains("Apache-2.0"));
    assert!(data.rows.len() > 500, "fixture covers three ecosystems");
    let indexes = replay_indexes(&data.rows);
    let opts = MaliciousOptions::default();

    // Recall with the local index: every replayed MAL row must produce a finding.
    let mut targets = Vec::new();
    for r in &data.rows {
        let eco = mal_index::ecosystem_of(&r.ecosystem).unwrap();
        let version = r
            .versions
            .first()
            .cloned()
            .unwrap_or_else(|| "0.0.0".into());
        targets.push(t(eco, &r.name, &version));
    }
    let with_index = check_all(&targets, &[], None, &indexes, &opts, now()).await;
    assert_eq!(
        with_index.findings.len(),
        targets.len(),
        "index match recall"
    );

    // Recall of the name rule alone (no index, no registry): measured, reported.
    let names_only = check_all(&targets, &[], None, &[], &opts, now()).await;
    let typo_hits = names_only
        .checks
        .iter()
        .filter(|c| c.signals.iter().any(|s| s.kind == SignalKind::Typosquat))
        .count();
    assert!(
        names_only.findings.is_empty(),
        "a name signal alone never makes a finding"
    );

    // FP on benign packages ranked 1001-2000 (not in the shipped list), with
    // benign registry facts: findings must stay under 1%; name-rule hits are reported.
    let mut benign_targets = Vec::new();
    for eco in [Ecosystem::Cargo, Ecosystem::Npm, Ecosystem::PyPi] {
        benign_targets.extend(benign(eco).into_iter().map(|n| t(eco, &n, "1.0.0")));
    }
    let probe = FixedProbe(old_benign_facts());
    let benign_opts = MaliciousOptions {
        max_registry_checks: usize::MAX,
        ..Default::default()
    };
    let benign_report = check_all(
        &benign_targets,
        &[],
        Some(&probe),
        &indexes,
        &benign_opts,
        now(),
    )
    .await;
    let benign_name_hits = benign_report
        .checks
        .iter()
        .filter(|c| c.signals.iter().any(|s| s.kind == SignalKind::Typosquat))
        .count();
    let fp = benign_report.findings.len() as f64 / benign_targets.len() as f64;
    eprintln!(
        "[o18-replay] MAL rows {} | index recall {}/{} | name-rule recall {}/{} ({:.1}%) | benign {} | name-rule hits {} ({:.1}%) | findings FP {} ({:.2}%)",
        targets.len(),
        with_index.findings.len(),
        targets.len(),
        typo_hits,
        targets.len(),
        100.0 * typo_hits as f64 / targets.len() as f64,
        benign_targets.len(),
        benign_name_hits,
        100.0 * benign_name_hits as f64 / benign_targets.len() as f64,
        benign_report.findings.len(),
        100.0 * fp
    );
    assert!(fp < 0.01, "finding FP rate {fp} must stay under 1%");
}
