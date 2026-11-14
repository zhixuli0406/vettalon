//! Bounded selection of trusted-home incremental baselines (VET-03).
use std::io::Read;
use std::path::Path;

use super::ScanOptions;
use super::attack_classes::AttackClassMode;
use super::diff_scope::{self, DiffSelection};
use super::schema::{
    AuditReport, Finding, FindingStatus, ProfileMode, is_supported_schema_version,
};
use vettalon_contract::coverage::RunStatus;

const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REPORT_FILES: usize = 1000;

pub(super) fn validate_options(opts: &ScanOptions, mode: ProfileMode) -> Result<(), String> {
    if opts.since_last && (mode != ProfileMode::Deep || opts.no_prior || opts.diff_base.is_some()) {
        return Err(
            "--since-last requires --profile deep and conflicts with --no-prior and --diff-base"
                .into(),
        );
    }
    Ok(())
}

fn read_report(path: &Path) -> Result<AuditReport, &'static str> {
    read_report_with_sha256(path).map(|(report, _)| report)
}

/// [`read_report`] plus the SHA-256 of the exact bytes parsed.
fn read_report_with_sha256(path: &Path) -> Result<(AuditReport, String), &'static str> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "unreadable report")?;
    if !meta.is_file() || meta.len() > MAX_REPORT_BYTES {
        return Err("report is not a regular file or exceeds size cap");
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "unreadable report")?;
    let opened = file.metadata().map_err(|_| "unreadable report")?;
    if !opened.is_file() || opened.len() > MAX_REPORT_BYTES {
        return Err("report is not a regular file or exceeds size cap");
    }
    let mut raw = Vec::new();
    file.take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "unreadable report")?;
    if raw.len() as u64 > MAX_REPORT_BYTES {
        return Err("report exceeds size cap");
    }
    let report = serde_json::from_slice(&raw).map_err(|_| "cannot parse report")?;
    Ok((report, super::schema::sha256_hex(&raw)))
}

/// Schema, validator and commit checks every trusted base must pass,
/// independent of the profile and attack classes it was scanned with.
fn eligible_base(report: &AuditReport) -> Result<Option<&str>, &'static str> {
    if !is_supported_schema_version(report.schema_version)
        || !super::validator::validate_report(report).is_empty()
    {
        return Err("report validation failed");
    }
    let commit = report.repo_commit.as_deref();
    // A saved report must never introduce revision syntax or Git options.
    if !is_full_hex_oid(commit) {
        return Err("repo_commit is not a full hex OID");
    }
    Ok(commit)
}

/// True for a full 40- or 64-character hex object id.
pub(crate) fn is_full_hex_oid(commit: Option<&str>) -> bool {
    commit.is_some_and(|commit| {
        [40, 64].contains(&commit.len()) && commit.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

fn eligible(
    report: &AuditReport,
    mode: ProfileMode,
    classes: AttackClassMode,
) -> Result<Option<&str>, &'static str> {
    let commit = eligible_base(report)?;
    if report.profile.mode != mode {
        return Err("profile differs");
    }
    // Older reports persisted the setting only on submitted coverage rows.
    let recorded = report.attack_classes.unwrap_or_else(|| {
        report
            .coverage
            .iter()
            .find_map(|c| c.attack_classes.as_ref().map(|a| a.mode))
            .unwrap_or_default()
    });
    if recorded != classes
        || report
            .coverage
            .iter()
            .filter_map(|c| c.attack_classes.as_ref())
            .any(|c| c.mode != recorded)
    {
        return Err("attack_classes differs");
    }
    Ok(commit)
}

pub(super) struct Selection {
    pub name: String,
    pub base: AuditReport,
    pub diff: DiffSelection,
    // Chronological order: oldest first, newest last.
    pub supplements: Vec<(String, AuditReport)>,
}

pub(super) fn skip_intake_safe(ignored: Result<usize, String>) -> bool {
    matches!(ignored, Ok(0))
}

/// Saved report file names under `home/reports`, newest first. `Err(None)`
/// when the directory is unavailable; `Err(Some(reason))` when the bounded
/// enumeration cap is exceeded.
fn saved_report_names(home: &Path) -> Result<Vec<String>, Option<&'static str>> {
    let entries = std::fs::read_dir(home.join("reports")).map_err(|_| None)?;
    let mut names = Vec::new();
    // Bound directory enumeration as well as parsing and Git ancestry checks.
    for (index, entry) in entries.enumerate() {
        if index >= MAX_REPORT_FILES {
            return Err(Some("report file count cap exceeded"));
        }
        if let Ok(entry) = entry
            && let Some(name) = entry.file_name().to_str()
            && name.ends_with(".json")
        {
            names.push(name.to_owned());
        }
    }
    names.sort_by(|a, b| {
        super::report::saved_report_sort_key(b).cmp(&super::report::saved_report_sort_key(a))
    });
    Ok(names)
}

/// A baseline report chosen by the `--since-last` trust rules.
pub(crate) struct Baseline {
    pub path: std::path::PathBuf,
    pub report: AuditReport,
    /// SHA-256 of the exact saved bytes (before any in-memory migration).
    pub sha256: String,
}

/// The newest saved report `--since-last` would trust as a base for `root`
/// (same enumeration cap, size cap, trust-policy migration, validator and
/// commit checks, clean and complete run, commit an ancestor of HEAD), but
/// without the profile / attack-class match: `retest` re-runs recorded
/// findings, it does not merge scan coverage. `root` must be canonical.
pub(crate) async fn select_baseline(home: &Path, root: &Path) -> Result<Baseline, String> {
    let names = saved_report_names(home).map_err(|reason| {
        format!(
            "no baseline report: {}",
            reason.unwrap_or("no saved reports directory")
        )
    })?;
    for name in names {
        let path = home.join("reports").join(&name);
        let (mut report, sha256) = match read_report_with_sha256(&path) {
            Ok(value) => value,
            Err(reason) => {
                eprintln!("[vettalon] retest: skipping base {name}: {reason}");
                continue;
            }
        };
        if report.repo != root.to_string_lossy() {
            continue;
        }
        super::trust_policy::migrate_capped_refutations(&mut report);
        let commit = match eligible_base(&report) {
            Ok(Some(commit)) => commit.to_owned(),
            Ok(None) => continue,
            Err(reason) => {
                eprintln!("[vettalon] retest: skipping base {name}: {reason}");
                continue;
            }
        };
        let completed = report.run_status == RunStatus::Complete
            || (report.run_status == RunStatus::PartialByDesign && report.since_last.is_some());
        if report.repo_tree_clean != Some(true) || !completed {
            eprintln!("[vettalon] retest: skipping base {name}: dirty or unfinished report");
            continue;
        }
        match diff_scope::compute(root, &commit).await {
            Ok(selection) if selection.scope.merge_base == selection.scope.base_oid => {
                return Ok(Baseline {
                    path,
                    report,
                    sha256,
                });
            }
            _ => eprintln!(
                "[vettalon] retest: skipping base {name}: commit is not an ancestor of HEAD or Git state unavailable"
            ),
        }
    }
    Err(NO_BASELINE.into())
}

const NO_BASELINE: &str =
    "no baseline report for this repository passed the --since-last trust rules; pass --report";

pub(super) async fn select(
    home: &Path,
    root: &Path,
    mode: ProfileMode,
    classes: AttackClassMode,
) -> Option<Selection> {
    let ignored = diff_scope::ignored_intake_count(root).await;
    let (count, note) = match ignored {
        Ok(count) => (count, ""),
        Err(_) => (1, " (conservative minimum; Git state unavailable)"),
    };
    if count > 0 {
        eprintln!("[vettalon] --since-last: {count} ignored intake files{note}; running full scan");
        return None;
    }
    match diff_scope::repo_state(root).await {
        Ok(state) if state.clean.is_some() => {}
        Ok(state) if state.submodules => {
            eprintln!("[vettalon] --since-last: repository has submodules; running full scan");
            return None;
        }
        _ => {
            eprintln!(
                "[vettalon] --since-last: index flags or unavailable Git state; running full scan"
            );
            return None;
        }
    }
    let names = match saved_report_names(home) {
        Ok(names) => names,
        Err(Some(reason)) => {
            eprintln!("[vettalon] --since-last: skipping base: {reason}");
            return None;
        }
        Err(None) => return None,
    };
    let mut supplements = Vec::new();
    for name in names {
        let result = read_report(&home.join("reports").join(&name));
        let mut report = match result {
            Ok(report) => report,
            Err(reason) => {
                eprintln!("[vettalon] --since-last: skipping base: {reason}");
                continue;
            }
        };
        if report.repo != root.to_string_lossy() {
            continue;
        }
        // A report saved before the per-CWE trust policy: reopen its
        // model-only refutations of capped CWEs, then `eligible` validates
        // strictly.
        let migrated = super::trust_policy::migrate_capped_refutations(&mut report);
        if migrated > 0 {
            eprintln!(
                "[vettalon] --since-last: {}",
                super::trust_policy::migration_note(
                    &crate::tr!("基準報告", "base report"),
                    migrated
                )
            );
        }
        let commit = match eligible(&report, mode, classes) {
            Ok(commit) => commit,
            Err(reason) => {
                eprintln!("[vettalon] --since-last: skipping base: {reason}");
                continue;
            }
        };
        let completed = report.run_status == RunStatus::Complete
            || (report.run_status == RunStatus::PartialByDesign && report.since_last.is_some());
        if report.repo_tree_clean != Some(true) || !completed {
            eprintln!("[vettalon] --since-last: skipping base: dirty or unfinished report");
            if let Some(commit) = commit
                && diff_scope::compute(root, commit)
                    .await
                    .is_ok_and(|d| d.scope.merge_base == d.scope.base_oid)
            {
                supplements.push((name, report));
            }
            continue;
        }
        let Some(commit) = commit else {
            eprintln!("[vettalon] --since-last: skipping base: missing repo_commit");
            continue;
        };
        match diff_scope::compute(root, commit).await {
            Ok(selection) if selection.scope.merge_base == selection.scope.base_oid => {
                let base_started_at = chrono::DateTime::parse_from_rfc3339(&report.started_at).ok();
                supplements.retain(|(_, supplement)| {
                    let Some(base_started_at) = base_started_at else {
                        return false;
                    };
                    chrono::DateTime::parse_from_rfc3339(&supplement.started_at)
                        .is_ok_and(|started_at| started_at > base_started_at)
                });
                supplements.sort_by(|(a_name, a), (b_name, b)| {
                    let a_time = chrono::DateTime::parse_from_rfc3339(&a.started_at).unwrap();
                    let b_time = chrono::DateTime::parse_from_rfc3339(&b.started_at).unwrap();
                    a_time.cmp(&b_time).then_with(|| a_name.cmp(b_name))
                });
                retain_newest_and_confirmed(&mut supplements);
                let findings = merged_findings(&report, &supplements);
                if selection.changed.is_empty() && !closed_hashes_match(root, &findings) {
                    eprintln!(
                        "[vettalon] --since-last: closed finding source hash unavailable or changed; running full scan"
                    );
                    return None;
                }
                return Some(Selection {
                    name,
                    base: report,
                    diff: selection,
                    supplements,
                });
            }
            _ => eprintln!(
                "[vettalon] --since-last: skipping base: commit is not an ancestor of HEAD or Git state unavailable"
            ),
        }
    }
    None
}

fn retain_newest_and_confirmed(supplements: &mut Vec<(String, AuditReport)>) {
    let discard = supplements.len().saturating_sub(5);
    if discard == 0 {
        return;
    }
    let mut index = 0;
    supplements.retain(|(_, report)| {
        let keep = index >= discard
            || report
                .findings
                .iter()
                .any(|finding| finding.status == FindingStatus::Confirmed);
        index += 1;
        keep
    });
}

/// Fingerprint the selected incremental scope with a fresh, bounded hash budget.
/// Deleted paths have explicit tombstones; unavailable reads fail closed.
pub(super) async fn snapshot(root: &Path, diff: &DiffSelection) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let state = diff_scope::repo_state(root).await.ok()?;
    let clean = state.clean?;
    let ignored = diff_scope::ignored_intake_count(root).await.ok()?;
    let mut hasher = Sha256::new();
    hasher.update(state.commit.as_bytes());
    hasher.update([u8::from(clean)]);
    hasher.update(ignored.to_le_bytes());
    let mut budget = super::prior_run::HashBudget::default();
    // DiffSelection uses a BTreeSet, so paths have a stable sorted order.
    for path in &diff.changed {
        let hash = budget.snapshot_hash(root, path).ok()?;
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        match hash {
            Some(hash) => {
                hasher.update([1]);
                hasher.update(hash.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    Some(hasher.finalize().into())
}

fn is_closed(finding: &Finding) -> bool {
    matches!(
        finding.status,
        FindingStatus::Refuted | FindingStatus::Suppressed
    )
}

fn closed_hash_matches(
    root: &Path,
    finding: &Finding,
    budget: &mut super::prior_run::HashBudget,
) -> bool {
    finding.file_hash.as_ref().is_some_and(|expected| {
        budget.hash(root, &finding.file).ok().flatten().as_ref() == Some(expected)
    })
}

pub(super) fn closed_hashes_match(root: &Path, findings: &[Finding]) -> bool {
    let mut budget = super::prior_run::HashBudget::default();
    findings
        .iter()
        .filter(|f| is_closed(f))
        .all(|f| closed_hash_matches(root, f, &mut budget))
}

/// Resolve duplicate IDs before carry checks so the latest human decision wins.
pub(super) fn merged_findings(
    base: &AuditReport,
    supplements: &[(String, AuditReport)],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut positions = std::collections::HashMap::new();
    for report in std::iter::once(base).chain(supplements.iter().map(|(_, r)| r)) {
        for finding in &report.findings {
            if let Some(&index) = positions.get(&finding.id) {
                if !confirmed_over_closed(&findings[index], finding) {
                    findings[index] = finding.clone();
                }
            } else {
                positions.insert(finding.id.clone(), findings.len());
                findings.push(finding.clone());
            }
        }
    }
    findings
}

fn confirmed_over_closed(existing: &Finding, incoming: &Finding) -> bool {
    existing.status == FindingStatus::Confirmed && incoming.status != FindingStatus::Confirmed
}

/// Preserve unchanged open claims and hash-matching unchanged closed claims after review.
/// A current scanner duplicate excluded by PR scope must not hide a baseline claim.
pub(super) fn carry_findings(
    root: &Path,
    base: &[Finding],
    diff: &DiffSelection,
    findings: &mut Vec<Finding>,
) -> usize {
    let mut positions: std::collections::HashMap<String, usize> = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| (finding.id.clone(), index))
        .collect();
    let mut carried = 0;
    let mut budget = super::prior_run::HashBudget::default();
    for finding in base {
        let path = diff_scope::scope_path(finding).unwrap_or(&finding.file);
        if diff.path_changed(path) {
            continue;
        }
        if is_closed(finding) && !closed_hash_matches(root, finding, &mut budget) {
            continue;
        }
        if let Some(&index) = positions.get(&finding.id) {
            if !diff_scope::outside_diff_scope(&findings[index])
                || confirmed_over_closed(&findings[index], finding)
            {
                continue;
            }
            findings[index] = finding.clone();
        } else {
            positions.insert(finding.id.clone(), findings.len());
            findings.push(finding.clone());
        }
        carried += 1;
    }
    carried
}

/// Remove run-specific diff annotations from findings reused by --since-last.
pub(super) fn remove_outside_diff_scope(findings: &mut [Finding]) {
    for finding in findings {
        finding.evidence.retain(|e| {
            !(e.kind == super::schema::EvidenceKind::ScopeNote
                && e.source == "diff_scope"
                && e.detail == "outside_diff_scope")
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::schema::{DiffScope, DiffScopeMode, FindingKind, Severity};
    use super::*;
    use std::collections::BTreeSet;

    fn selection() -> DiffSelection {
        DiffSelection {
            scope: DiffScope {
                mode: DiffScopeMode::Diff,
                base: "base".into(),
                merge_base: "a".repeat(40),
                head: "b".repeat(40),
                base_oid: "a".repeat(40),
                worktree_changes: 0,
                untracked: 0,
                changed_files: 1,
                invalid_paths: 0,
                changed_during_scan: 0,
            },
            changed: BTreeSet::from(["b.rs".into()]),
            tracked_dependencies: BTreeSet::new(),
            gitlinks: BTreeSet::new(),
        }
    }

    fn finding(file: &str) -> Finding {
        Finding::candidate(
            "gitleaks",
            FindingKind::Secret,
            Severity::High,
            "open",
            file,
            Some(1),
            "",
            "open",
            vec![],
        )
    }

    /// N1: a pre-policy baseline with a model-only CWE-614 refutation is
    /// rejected by the strict check until it is migrated, then eligible.
    #[test]
    fn pre_policy_baseline_is_eligible_once_migrated() {
        use super::super::schema::{EvidenceItem, EvidenceKind, GatePolicy, Summary};
        let mut report: AuditReport = serde_json::from_value(serde_json::json!({
            "schema_version": 3,
            "repo": "/repo",
            "started_at": "2026-10-01T00:00:00Z",
            "profile": {"mode":"deep", "intake":null},
            "findings": [], "engines_run": [], "engines_missing": [],
            "summary": {"total_findings":0,"by_severity":{"critical":0,"high":0,"medium":0,"low":0,"info":0},"engines_run_count":0,"engines_missing_count":0},
            "run_status":"complete"
        }))
        .unwrap();
        report.repo_commit = Some("a".repeat(40));
        let mut f = finding("a.rs");
        f.status = FindingStatus::Refuted;
        f.cwe = Some("CWE-614".into());
        f.evidence.push(EvidenceItem {
            kind: EvidenceKind::AdversarialReview,
            source: "verifier".into(),
            detail: "refuted: cookie is not sensitive".into(),
            recorded_at: "2026-10-01T00:00:00Z".into(),
        });
        report.findings.push(f);
        report.summary = Summary::from_findings(&report.findings, 0, 0, GatePolicy::default(), &[]);
        let classes = AttackClassMode::default();
        assert_eq!(
            eligible(&report, ProfileMode::Deep, classes),
            Err("report validation failed")
        );
        assert_eq!(
            super::super::trust_policy::migrate_capped_refutations(&mut report),
            1
        );
        assert_eq!(report.findings[0].status, FindingStatus::NeedsHuman);
        assert!(eligible(&report, ProfileMode::Deep, classes).is_ok());
    }

    #[test]
    fn supplement_limit_keeps_newest_started_at_after_filtering() {
        let base_time = chrono::DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z").unwrap();
        let mut supplements: Vec<(String, AuditReport)> = (0..5)
            .map(|index| {
                let mut report: AuditReport = serde_json::from_value(serde_json::json!({
                    "schema_version": 3,
                    "repo": "/repo",
                    "started_at": format!("2026-09-{:02}T00:00:00Z", index + 1),
                    "profile": {"mode":"deep", "intake":null},
                    "findings": [], "engines_run": [], "engines_missing": [],
                    "summary": {"total_findings":0,"by_severity":{"critical":0,"high":0,"medium":0,"low":0,"info":0},"engines_run_count":0,"engines_missing_count":0}, "run_status":"incomplete"
                })).unwrap();
                report.started_at = format!("2026-09-{:02}T00:00:00Z", index + 1);
                (format!("newer-name-{index}.json"), report)
            })
            .collect();
        let mut newest: AuditReport = serde_json::from_value(serde_json::json!({
            "schema_version": 3,
            "repo": "/repo",
            "started_at": "2026-10-02T00:00:00Z",
            "profile": {"mode":"deep", "intake":null},
            "findings": [], "engines_run": [], "engines_missing": [],
            "summary": {"total_findings":0,"by_severity":{"critical":0,"high":0,"medium":0,"low":0,"info":0},"engines_run_count":0,"engines_missing_count":0}, "run_status":"incomplete"
        })).unwrap();
        newest.started_at = "2026-10-02T00:00:00Z".into();
        supplements.push(("old-name-newer-time.json".into(), newest));
        supplements.retain(|(_, report)| {
            chrono::DateTime::parse_from_rfc3339(&report.started_at)
                .is_ok_and(|started_at| started_at > base_time)
        });
        supplements.sort_by_key(|(_, report)| {
            chrono::DateTime::parse_from_rfc3339(&report.started_at).unwrap()
        });
        let discard = supplements.len().saturating_sub(5);
        supplements.drain(..discard);
        assert_eq!(supplements.len(), 1);
        assert_eq!(supplements[0].0, "old-name-newer-time.json");
    }

    #[test]
    fn supplement_limit_keeps_older_confirmed_and_drops_older_candidate_only() {
        let mut supplements: Vec<(String, AuditReport)> = (0..6)
            .map(|index| {
                let mut report: AuditReport = serde_json::from_value(serde_json::json!({
                    "schema_version": 3,
                    "repo": "/repo",
                    "started_at": format!("2026-10-{:02}T00:00:00Z", index + 1),
                    "profile": {"mode":"deep", "intake":null},
                    "findings": [],
                    "engines_run": [], "engines_missing": [],
                    "summary": {"total_findings":1,"by_severity":{"critical":0,"high":1,"medium":0,"low":0,"info":0},"engines_run_count":0,"engines_missing_count":0},
                    "run_status":"incomplete"
                })).unwrap();
                let mut item = finding("a.rs");
                item.id = "same-finding".into();
                if index == 0 {
                    item.status = FindingStatus::Confirmed;
                }
                report.findings.push(item);
                (format!("report-{index}.json"), report)
            })
            .collect();
        retain_newest_and_confirmed(&mut supplements);
        assert_eq!(supplements.len(), 6);
        let base = supplements[0].1.clone();
        assert_eq!(
            merged_findings(&base, &supplements)[0].status,
            FindingStatus::Confirmed
        );
        let summary = super::super::schema::Summary::from_findings(
            &merged_findings(&base, &supplements),
            0,
            0,
            super::super::schema::GatePolicy::default(),
            &base.coverage,
        );
        assert_eq!(summary.total_findings, 1);
        assert_eq!(summary.by_severity.high, 1);

        let mut candidate_only = supplements.clone();
        candidate_only[0].1.findings[0].status = FindingStatus::Candidate;
        retain_newest_and_confirmed(&mut candidate_only);
        assert_eq!(candidate_only.len(), 5);
        assert_eq!(candidate_only[0].0, "report-1.json");
    }

    #[test]
    fn appends_unchanged_without_evidence_and_keeps_visible_duplicate() {
        let diff = selection();
        let base = vec![finding("a.rs"), finding("b.rs")];
        let mut current = Vec::new();
        assert_eq!(
            carry_findings(Path::new("."), &base, &diff, &mut current),
            1
        );
        assert_eq!(
            serde_json::to_value(&current[0]).unwrap(),
            serde_json::to_value(&base[0]).unwrap()
        );
        current[0].title = "current visible result".into();
        assert_eq!(
            carry_findings(Path::new("."), &base, &diff, &mut current),
            0
        );
        assert_eq!(current[0].title, "current visible result");
    }

    #[test]
    fn changed_files_are_not_carried_and_unchanged_open_claims_survive_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "source").unwrap();
        let hash = super::super::prior_run::hash_repo_file(dir.path(), "a.rs").unwrap();
        for status in [FindingStatus::Refuted, FindingStatus::Suppressed] {
            for expected in [None, Some("0".repeat(64)), Some(hash.clone())] {
                let mut f = finding("a.rs");
                f.status = status;
                f.file_hash = expected.clone();
                let valid = expected.as_ref() == Some(&hash);
                let mut current = Vec::new();
                let diff = selection();
                assert_eq!(
                    carry_findings(dir.path(), &[f.clone()], &diff, &mut current),
                    usize::from(valid)
                );
                assert_eq!(closed_hashes_match(dir.path(), &[f]), valid);
            }
        }
        for status in [
            FindingStatus::Candidate,
            FindingStatus::NeedsHuman,
            FindingStatus::Confirmed,
        ] {
            let mut f = finding("b.rs");
            f.status = status;
            let mut current = Vec::new();
            assert_eq!(
                carry_findings(dir.path(), &[f], &selection(), &mut current),
                0
            );
            let mut f = finding("unchanged.rs");
            f.status = status;
            assert_eq!(
                carry_findings(dir.path(), &[f], &selection(), &mut current),
                1
            );
        }
        std::fs::remove_file(dir.path().join("a.rs")).unwrap();
        let mut f = finding("a.rs");
        f.status = FindingStatus::Refuted;
        f.file_hash = Some(hash);
        assert_eq!(
            carry_findings(dir.path(), &[f], &selection(), &mut Vec::new()),
            0
        );
    }

    #[test]
    fn closed_hash_budget_exhaustion_refuses_carry_and_skip() {
        let dir = tempfile::tempdir().unwrap();
        let mut base = Vec::new();
        // The shared prior-run hash budget allows at most 200 distinct files.
        for i in 0..201 {
            let file = format!("{i}.rs");
            std::fs::write(dir.path().join(&file), "source").unwrap();
            let mut f = finding(&file);
            f.status = FindingStatus::Suppressed;
            f.file_hash = super::super::prior_run::hash_repo_file(dir.path(), &file);
            base.push(f);
        }
        let mut current = Vec::new();
        assert_eq!(
            carry_findings(dir.path(), &base, &selection(), &mut current),
            200
        );
        assert!(!closed_hashes_match(dir.path(), &base));
    }

    #[test]
    fn outside_duplicate_is_replaced_verbatim() {
        let diff = selection();
        let base = vec![finding("a.rs")];
        let mut current = base.clone();
        diff.annotate_findings(&mut current);
        assert!(diff_scope::outside_diff_scope(&current[0]));
        assert_eq!(
            carry_findings(Path::new("."), &base, &diff, &mut current),
            1
        );
        assert!(!diff_scope::outside_diff_scope(&current[0]));
        assert_eq!(
            serde_json::to_value(current).unwrap(),
            serde_json::to_value(base).unwrap()
        );
    }

    #[test]
    fn changed_paths_are_not_carried_including_dependency_suffixes() {
        let mut diff = selection();
        diff.changed.insert("Cargo.lock".into());
        let mut dependency = finding("Cargo.lock (crate-name 1.2.3)");
        dependency.source_engine = "cargo-audit".into();
        dependency.kind = FindingKind::DependencyVulnerability;
        let base = vec![finding("./b.rs"), dependency];
        let mut current = Vec::new();
        assert_eq!(
            carry_findings(Path::new("."), &base, &diff, &mut current),
            0
        );
        assert!(current.is_empty());
    }

    #[tokio::test]
    async fn since_last_snapshot_fails_closed_on_read_failure_and_hash_budget() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let git = crate::util::which_cli_for_scan("git", root).unwrap();
        for args in [
            vec!["init", "-q"],
            vec![
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "base",
                "--allow-empty",
            ],
        ] {
            assert!(
                crate::audit::scanners::git_test_command(&git)
                    .args(args)
                    .current_dir(root)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let mut diff = selection();
        diff.changed.clear();
        let empty = snapshot(root, &diff).await.unwrap();
        assert_eq!(snapshot(root, &diff).await, Some(empty));
        diff.changed.insert("deleted.rs".into());
        let absent = snapshot(root, &diff).await.unwrap();
        assert_ne!(absent, empty);
        assert_eq!(snapshot(root, &diff).await, Some(absent));
        std::fs::write(root.join("deleted.rs"), "").unwrap();
        assert_ne!(snapshot(root, &diff).await.unwrap(), absent);
        std::fs::remove_file(root.join("deleted.rs")).unwrap();
        assert_eq!(snapshot(root, &diff).await, Some(absent));
        std::fs::create_dir(root.join("deleted.rs")).unwrap();
        assert!(snapshot(root, &diff).await.is_none());
        diff.changed.clear();
        diff.changed.insert("../unsafe.rs".into());
        assert!(snapshot(root, &diff).await.is_none());
        diff.changed.clear();
        for i in 0..201 {
            let path = format!("{i}.rs");
            std::fs::write(root.join(&path), "source").unwrap();
            diff.changed.insert(path);
        }
        assert!(snapshot(root, &diff).await.is_none());
    }

    #[test]
    fn since_last_skip_recheck_requires_zero_ignored_intake() {
        assert!(skip_intake_safe(Ok(0)));
        assert!(!skip_intake_safe(Ok(1)));
        assert!(!skip_intake_safe(Ok(usize::MAX)));
        assert!(!skip_intake_safe(Err("Git state unavailable".into())));
    }

    #[test]
    fn since_last_count_defaults_and_omits_zero() {
        let mut info: super::super::schema::SinceLast = serde_json::from_value(
            serde_json::json!({"base_report":"base.json", "base_commit":"base", "skipped":false}),
        )
        .unwrap();
        assert_eq!(info.carried_findings, 0);
        assert!(
            serde_json::to_value(&info)
                .unwrap()
                .get("carried_findings")
                .is_none()
        );
        info.carried_findings = 2;
        assert_eq!(serde_json::to_value(info).unwrap()["carried_findings"], 2);
    }
}
