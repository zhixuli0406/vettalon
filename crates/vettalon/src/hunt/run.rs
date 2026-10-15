//! Supply-chain hunt: orchestration (phase 2).
//!
//! Ties the pieces together: intake → OSV classify → select → fetch → run the
//! existing deep audit on each dependency's source → collect findings into a
//! [`HuntReport`]. The expensive parts (network, LLM) are injected as traits
//! ([`super::osv::OsvClient`], [`super::fetch::SourceFetcher`], [`DirAuditor`])
//! so the orchestration is unit-tested with mocks; the live path runs through
//! the CLI `hunt` command.
//!
//! Cost control (the default): only DIRECT dependencies are considered, OSV is
//! consulted first (cheap), versions that already carry a known CVE are skipped
//! (SCA tools already track those — the AI budget goes to finding the NOT-yet
//! disclosed), and at most `max_deps` are audited.

use std::path::Path;

use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use super::fetch::SourceFetcher;
use super::osv::{DependencyAdvisories, KnownVuln, OsvClient, scan_known};
use super::{DependencyTarget, Ecosystem, targets_from_dir};
use crate::audit::schema::{Finding, FindingStatus};

/// Knobs for one hunt. Defaults match the agreed cost policy.
#[derive(Debug, Clone)]
pub struct HuntOptions {
    /// Cap on how many dependencies are actually fetched + audited.
    pub max_deps: usize,
    /// Audit transitive dependencies too (default: direct only).
    pub include_transitive: bool,
    /// Audit versions that already have a known CVE (default: skip them).
    pub reaudit_known: bool,
    /// Wall-clock budget for ONE dependency's fetch + audit. A dependency that
    /// exceeds it is recorded as an error and the hunt moves on, so one slow
    /// or hanging dependency cannot sink the whole run.
    pub per_dep_timeout: std::time::Duration,
    /// How many dependencies are fetched + audited at once. Total token use is
    /// the same as a serial run; what grows is the number of simultaneous calls
    /// each model receives (one per in-flight dependency), so CLI accounts can
    /// hit rate limits sooner. Clamped to `1..=MAX_DEP_CONCURRENCY`.
    pub dep_concurrency: usize,
}

/// Upper bound on [`HuntOptions::dep_concurrency`]: each in-flight dependency
/// runs its own deep audit (every finder model busy, plus PoC containers).
pub const MAX_DEP_CONCURRENCY: usize = 4;

impl Default for HuntOptions {
    fn default() -> Self {
        HuntOptions {
            max_deps: 20,
            include_transitive: false,
            reaudit_known: false,
            per_dep_timeout: std::time::Duration::from_secs(300),
            dep_concurrency: 2,
        }
    }
}

/// Why a dependency was not audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Transitive, and `--include-transitive` was not set.
    Transitive,
    /// Already has a known CVE for this version (SCA already covers it).
    KnownCve,
    /// Past the `max_deps` budget.
    OverBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedDep {
    pub target: DependencyTarget,
    pub reason: SkipReason,
    pub known: Vec<KnownVuln>,
}

/// Where an upstream disclosure for this dependency would go, derived from the
/// fetched source (so a novelty candidate can be drafted against the real
/// project, not the enterprise's).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamInfo {
    /// `owner/repo` when the upstream is on GitHub.
    pub github: Option<String>,
    /// Security-contact emails found in the package's SECURITY.md.
    pub security_emails: Vec<String>,
}

/// One audited dependency and what the deep audit found in its source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHunt {
    pub target: DependencyTarget,
    pub known: Vec<KnownVuln>,
    /// False when fetch or audit failed (see `error`).
    pub audited: bool,
    pub error: Option<String>,
    pub upstream: UpstreamInfo,
    pub findings: Vec<Finding>,
}

impl DependencyHunt {
    /// Findings worth a human's attention: confirmed or needs-human. In a
    /// dependency OSV reports no advisory for, these are novelty candidates
    /// (nothing known matches them).
    pub fn actionable(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| {
            matches!(
                f.status,
                FindingStatus::Confirmed | FindingStatus::NeedsHuman
            )
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    pub project: String,
    /// Every dependency resolved from the lockfiles.
    pub total_targets: usize,
    pub audited: Vec<DependencyHunt>,
    pub skipped: Vec<SkippedDep>,
}

impl HuntReport {
    /// Novelty candidates: actionable findings in dependencies with no known
    /// OSV advisory. These are the responsible-disclosure candidates.
    pub fn novel_candidates(&self) -> Vec<(&DependencyHunt, &Finding)> {
        self.audited
            .iter()
            .filter(|d| d.known.is_empty())
            .flat_map(|d| d.actionable().map(move |f| (d, f)))
            .collect()
    }
}

/// Audits a directory of source with the deep engine. Injected so the hunt
/// orchestration is testable without models.
#[async_trait]
pub trait DirAuditor: Send + Sync {
    async fn audit(&self, dir: &Path) -> Result<Vec<Finding>, String>;
}

/// The real auditor: runs the deep engine ([`crate::audit::run_scan`]) on a
/// fetched dependency's source directory. Deep profile, no prior-run carry-over
/// (each dependency is audited fresh), no gate / fail-on (hunt decides outcomes
/// itself).
pub struct EngineAuditor {
    pub home: std::path::PathBuf,
    pub finders: Vec<crate::llm::ModelHandle>,
    pub verifiers: Vec<crate::llm::ModelHandle>,
    pub poc_models: Vec<crate::llm::ModelHandle>,
    pub roster: Vec<crate::audit::schema::ModelInfo>,
    pub max_modules: usize,
    pub poc: bool,
}

#[async_trait]
impl DirAuditor for EngineAuditor {
    async fn audit(&self, dir: &Path) -> Result<Vec<Finding>, String> {
        let opts = crate::audit::ScanOptions {
            repo_path: dir.to_path_buf(),
            profile: "deep".into(),
            report: None,
            sarif: None,
            fail_on: "none".into(),
            gates: Vec::new(),
            max_modules: self.max_modules,
            poc: self.poc,
            save: false,
            cross_check_top: 0,
            fail_on_needs_human: false,
            no_prior: true,
            rank: crate::audit::RankStrategy::Heuristic,
            trace: None,
            time_budget: None,
            finders: self.finders.clone(),
            verifiers: self.verifiers.clone(),
            poc_models: self.poc_models.clone(),
            roster: self.roster.clone(),
        };
        let report = crate::audit::run_scan(&self.home, &opts)
            .await
            .map_err(|e| e.to_string())?;
        Ok(report.findings)
    }
}

/// Decide which OSV-classified candidates to audit vs skip (pure). Direct
/// filtering happens before OSV (to save calls), so `rows` are the candidates
/// that were classified; `pre_skipped` carries the transitive ones already set
/// aside. Direct dependencies fill the `max_deps` budget first.
pub fn partition(
    mut rows: Vec<DependencyAdvisories>,
    opts: &HuntOptions,
) -> (Vec<DependencyAdvisories>, Vec<SkippedDep>) {
    rows.sort_by_key(|r| !r.target.direct); // direct first (stable)
    let mut selected = Vec::new();
    let mut skipped = Vec::new();
    for row in rows {
        if !opts.reaudit_known && !row.known.is_empty() {
            skipped.push(SkippedDep {
                target: row.target,
                reason: SkipReason::KnownCve,
                known: row.known,
            });
        } else if selected.len() >= opts.max_deps {
            skipped.push(SkippedDep {
                target: row.target,
                reason: SkipReason::OverBudget,
                known: row.known,
            });
        } else {
            selected.push(row);
        }
    }
    (selected, skipped)
}

/// What a hunt WOULD audit: intake + OSV + selection, no fetch or LLM. Cheap,
/// so `--dry-run` can preview the cost before spending tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntPlan {
    pub project: String,
    pub total_targets: usize,
    pub selected: Vec<DependencyAdvisories>,
    pub skipped: Vec<SkippedDep>,
}

/// Resolve the plan: intake, direct pre-filter (before OSV, to save calls),
/// OSV classify, then [`partition`].
pub async fn plan_hunt<O: OsvClient>(
    project: &Path,
    opts: &HuntOptions,
    osv: &O,
) -> Result<HuntPlan, String> {
    let targets = targets_from_dir(project)?;
    let total_targets = targets.len();

    let mut skipped: Vec<SkippedDep> = Vec::new();
    let candidates: Vec<DependencyTarget> = targets
        .into_iter()
        .filter(|t| {
            if !opts.include_transitive && !t.direct {
                skipped.push(SkippedDep {
                    target: t.clone(),
                    reason: SkipReason::Transitive,
                    known: Vec::new(),
                });
                false
            } else {
                true
            }
        })
        .collect();

    let rows = scan_known(&candidates, osv).await;
    let (selected, known_or_budget) = partition(rows, opts);
    skipped.extend(known_or_budget);

    Ok(HuntPlan {
        project: project.display().to_string(),
        total_targets,
        selected,
        skipped,
    })
}

/// Run a hunt: [`plan_hunt`], then fetch + deep-audit each selected dependency.
/// Progress over a hunt's dependencies: `start` fires before a dependency is
/// fetched and audited, `done` after, with its 1-based position in the plan.
/// Up to `dep_concurrency` dependencies run at once, so events from different
/// dependencies interleave. Each can take minutes, so without this the CLI
/// looks hung for the whole run.
pub trait HuntProgress {
    fn start(&self, index: usize, total: usize, target: &DependencyTarget);
    fn done(&self, index: usize, total: usize, hunt: &DependencyHunt);
}

/// A no-op sink for callers that do not want progress.
pub struct NoHuntProgress;
impl HuntProgress for NoHuntProgress {
    fn start(&self, _: usize, _: usize, _: &DependencyTarget) {}
    fn done(&self, _: usize, _: usize, _: &DependencyHunt) {}
}

pub async fn run_hunt<O, F, A>(
    project: &Path,
    opts: &HuntOptions,
    osv: &O,
    fetcher: &F,
    auditor: &A,
) -> Result<HuntReport, String>
where
    O: OsvClient,
    F: SourceFetcher,
    A: DirAuditor,
{
    run_hunt_with_progress(project, opts, osv, fetcher, auditor, &NoHuntProgress).await
}

/// [`run_hunt`] that reports per-dependency progress.
pub async fn run_hunt_with_progress<O, F, A, P>(
    project: &Path,
    opts: &HuntOptions,
    osv: &O,
    fetcher: &F,
    auditor: &A,
    progress: &P,
) -> Result<HuntReport, String>
where
    O: OsvClient,
    F: SourceFetcher,
    A: DirAuditor,
    P: HuntProgress,
{
    let plan = plan_hunt(project, opts, osv).await?;
    let total = plan.selected.len();
    let limit = opts.dep_concurrency.clamp(1, MAX_DEP_CONCURRENCY);
    // Runs on the caller's task (no spawn), so the injected traits need not be
    // 'static. Results are re-sorted into plan order: the report must not
    // depend on which dependency happened to finish first.
    let mut finished: Vec<(usize, DependencyHunt)> =
        futures::stream::iter(plan.selected.iter().enumerate())
            .map(|(i, row)| async move {
                progress.start(i + 1, total, &row.target);
                let hunt = audit_within_timeout(row, opts.per_dep_timeout, fetcher, auditor).await;
                progress.done(i + 1, total, &hunt);
                (i, hunt)
            })
            .buffer_unordered(limit)
            .collect()
            .await;
    finished.sort_by_key(|(i, _)| *i);
    let audited = finished.into_iter().map(|(_, hunt)| hunt).collect();
    Ok(HuntReport {
        project: plan.project,
        total_targets: plan.total_targets,
        audited,
        skipped: plan.skipped,
    })
}

/// Fetch + audit one dependency, recording a timeout as an unaudited
/// dependency instead of failing the hunt.
async fn audit_within_timeout<F: SourceFetcher, A: DirAuditor>(
    row: &DependencyAdvisories,
    timeout: std::time::Duration,
    fetcher: &F,
    auditor: &A,
) -> DependencyHunt {
    match tokio::time::timeout(timeout, audit_one(row, fetcher, auditor)).await {
        Ok(h) => h,
        Err(_) => DependencyHunt {
            target: row.target.clone(),
            known: row.known.clone(),
            audited: false,
            error: Some(format!(
                "timed out after {}s (fetch + audit)",
                timeout.as_secs()
            )),
            upstream: UpstreamInfo::default(),
            findings: Vec::new(),
        },
    }
}

fn skip_counts(skipped: &[SkippedDep]) -> (usize, usize, usize) {
    let mut t = 0;
    let mut k = 0;
    let mut b = 0;
    for s in skipped {
        match s.reason {
            SkipReason::Transitive => t += 1,
            SkipReason::KnownCve => k += 1,
            SkipReason::OverBudget => b += 1,
        }
    }
    (t, k, b)
}

/// zh-TW preview for `--dry-run`: what would be audited and what is skipped.
pub fn render_plan(plan: &HuntPlan) -> String {
    let (t, k, b) = skip_counts(&plan.skipped);
    let mut out = format!(
        "供應鏈獵捕（預覽）：{}\n  相依總數：{}　將審：{}　略過：{}（transitive {t}、已知 CVE {k}、超出上限 {b}）\n",
        plan.project,
        plan.total_targets,
        plan.selected.len(),
        plan.skipped.len(),
    );
    out.push_str("  將審查（OSV 查無已知漏洞、優先直接依賴）：\n");
    for row in &plan.selected {
        out.push_str(&format!(
            "    - {} {}@{}{}\n",
            row.target.ecosystem.as_str(),
            row.target.name,
            row.target.version,
            if row.target.direct {
                ""
            } else {
                "（transitive）"
            },
        ));
    }
    out
}

/// zh-TW summary of a completed hunt.
pub fn render_summary(report: &HuntReport) -> String {
    let (t, k, b) = skip_counts(&report.skipped);
    let novel = report.novel_candidates();
    let errors: Vec<&DependencyHunt> = report.audited.iter().filter(|d| !d.audited).collect();
    let mut out = format!(
        "供應鏈獵捕：{}\n  相依總數：{}　已審：{}　略過：{}（transitive {t}、已知 CVE {k}、超出上限 {b}）\n  可能的新漏洞（OSV 查無、待揭露候選）：{}\n",
        report.project,
        report.total_targets,
        report.audited.len(),
        report.skipped.len(),
        novel.len(),
    );
    for (dep, f) in &novel {
        out.push_str(&format!(
            "    - [{}] {}@{} — {}（{}）@ {}{}\n",
            f.severity.as_str(),
            dep.target.name,
            dep.target.version,
            f.title,
            status_word(f.status),
            f.file,
            f.line.map(|l| format!(":{l}")).unwrap_or_default(),
        ));
    }
    if !errors.is_empty() {
        out.push_str("  抓取／審查失敗：\n");
        for d in errors {
            out.push_str(&format!(
                "    - {}@{}：{}\n",
                d.target.name,
                d.target.version,
                d.error.as_deref().unwrap_or("unknown"),
            ));
        }
    }
    out
}

/// One upstream disclosure draft for a novelty candidate. Draft only — the
/// human reviews, decides the channel, and sends (nothing is sent here).
#[derive(Debug, Clone, Serialize)]
pub struct HuntDisclosure {
    /// `name@version` of the dependency the finding is in.
    pub dependency: String,
    pub finding_id: String,
    pub finding_title: String,
    pub draft: crate::disclose::Draft,
}

fn project_meta_for(dep: &DependencyHunt) -> crate::disclose::ProjectMeta {
    let ecosystem = match dep.target.ecosystem {
        super::Ecosystem::Cargo => "Rust",
        super::Ecosystem::Npm => "npm",
        super::Ecosystem::PyPi => "pip",
        super::Ecosystem::Go => "Go",
    };
    crate::disclose::ProjectMeta {
        name: Some(dep.target.name.clone()),
        version: Some(dep.target.version.clone()),
        ecosystem: Some(ecosystem.to_string()),
        github: dep.upstream.github.clone(),
        commit: None,
        security_policy: None,
        security_emails: dep.upstream.security_emails.clone(),
    }
}

/// Build upstream disclosure drafts for every eligible novelty candidate
/// (confirmed / needs-human, in a dependency with no known OSV advisory).
/// The channel is the top recommendation for that dependency's upstream.
/// Drafts only — the review + send stay a human step.
pub fn disclosure_drafts(report: &HuntReport, today: chrono::NaiveDate) -> Vec<HuntDisclosure> {
    let mut out = Vec::new();
    for (dep, f) in report.novel_candidates() {
        if crate::disclose::eligible(f).is_err() {
            continue;
        }
        let meta = project_meta_for(dep);
        let channel = crate::disclose::recommend(&meta)
            .into_iter()
            .next()
            .map(|c| c.channel)
            .unwrap_or(crate::disclose::Channel::GithubAdvisory);
        out.push(HuntDisclosure {
            dependency: format!("{}@{}", dep.target.name, dep.target.version),
            finding_id: f.id.clone(),
            finding_title: f.title.clone(),
            draft: crate::disclose::draft(f, &meta, channel, today),
        });
    }
    out
}

/// Full disclosure package (ranked channels, draft, pre-send checklist) for
/// one novelty candidate, so the dashboard/desktop can reuse the scan report's
/// disclosure panel. Only an eligible novelty candidate qualifies: a finding in
/// a dependency with a known OSV advisory, or one not confirmed/needs-human,
/// is refused. Draft only — nothing is sent.
pub fn disclosure_package(
    report: &HuntReport,
    dependency: &str,
    finding_id: &str,
    channel: Option<crate::disclose::Channel>,
    today: chrono::NaiveDate,
) -> Result<crate::disclose::DisclosurePackage, String> {
    let (dep, f) = report
        .novel_candidates()
        .into_iter()
        .find(|(d, f)| {
            f.id == finding_id && format!("{}@{}", d.target.name, d.target.version) == dependency
        })
        .ok_or_else(|| format!("{dependency} 沒有可揭露的新漏洞候選 {finding_id}"))?;
    crate::disclose::package_for(f, project_meta_for(dep), channel, today)
}

/// Read a saved hunt report (`vettalon hunt --report`) for delivery: size
/// capped, then parsed. The file is operator-chosen but may have been edited
/// or come from elsewhere, so it is never trusted beyond its shape.
pub fn load_hunt_report(path: &std::path::Path) -> Result<HuntReport, String> {
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    let meta = std::fs::metadata(path).map_err(|e| format!("無法讀取 {}：{e}", path.display()))?;
    if meta.len() > MAX_BYTES {
        return Err(format!(
            "報告檔過大（{} bytes，上限 {MAX_BYTES}）",
            meta.len()
        ));
    }
    let raw = std::fs::read(path).map_err(|e| format!("無法讀取 {}：{e}", path.display()))?;
    serde_json::from_slice(&raw).map_err(|e| format!("不是有效的供應鏈獵捕報告：{e}"))
}

fn status_word(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::Candidate => "candidate",
        FindingStatus::NeedsHuman => "needs_human",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::Refuted => "refuted",
        FindingStatus::Suppressed => "suppressed",
    }
}

async fn audit_one<F: SourceFetcher, A: DirAuditor>(
    row: &DependencyAdvisories,
    fetcher: &F,
    auditor: &A,
) -> DependencyHunt {
    let base = DependencyHunt {
        target: row.target.clone(),
        known: row.known.clone(),
        audited: false,
        error: None,
        upstream: UpstreamInfo::default(),
        findings: Vec::new(),
    };
    let tmp = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return DependencyHunt {
                error: Some(format!("scratch dir failed: {e}")),
                ..base
            };
        }
    };
    if let Err(e) = fetcher.fetch_into(&row.target, tmp.path()).await {
        return DependencyHunt {
            error: Some(format!("fetch failed: {e}")),
            ..base
        };
    }
    // Derive the upstream disclosure target from the fetched source while it is
    // still on disk.
    let upstream = detect_upstream(tmp.path(), &row.target);
    match auditor.audit(tmp.path()).await {
        Ok(findings) => DependencyHunt {
            audited: true,
            upstream,
            findings,
            ..base
        },
        Err(e) => DependencyHunt {
            error: Some(format!("audit failed: {e}")),
            upstream,
            ..base
        },
    }
}

/// The package root inside an extracted archive: registry tarballs wrap the
/// files in a single top-level directory (`<name>-<version>/`, `package/`),
/// so detection must look there, not at the scratch root.
fn package_root(extracted: &Path) -> std::path::PathBuf {
    let mut subdirs: Vec<std::path::PathBuf> = std::fs::read_dir(extracted)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    if subdirs.len() == 1 {
        subdirs.pop().unwrap()
    } else {
        extracted.to_path_buf()
    }
}

/// Derive the upstream disclosure target from a fetched dependency's source:
/// reuse `disclose::detect_project` (SECURITY.md, manifests), and fill the
/// GitHub slug from the manifest `repository` field (the extracted source has
/// no `.git`, so detect_project cannot).
fn detect_upstream(extracted: &Path, target: &DependencyTarget) -> UpstreamInfo {
    let root = package_root(extracted);
    let meta = crate::disclose::detect_project(&root);
    let github = meta.github.clone().or_else(|| {
        manifest_repository(&root, target)
            .as_deref()
            .and_then(crate::disclose::github_slug)
    });
    UpstreamInfo {
        github,
        security_emails: meta.security_emails,
    }
}

/// Best-effort upstream repository URL from a package manifest.
fn manifest_repository(root: &Path, target: &DependencyTarget) -> Option<String> {
    match target.ecosystem {
        Ecosystem::Go => Some(format!("https://{}", target.name)), // module path is the repo
        Ecosystem::Cargo => {
            let t = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
            let m: toml::Value = toml::from_str(&t).ok()?;
            m.get("package")?
                .get("repository")?
                .as_str()
                .map(str::to_string)
        }
        Ecosystem::Npm => {
            let t = std::fs::read_to_string(root.join("package.json")).ok()?;
            let v: serde_json::Value = serde_json::from_str(&t).ok()?;
            match v.get("repository") {
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(obj) => obj.get("url").and_then(|u| u.as_str()).map(str::to_string),
                None => None,
            }
        }
        Ecosystem::PyPi => {
            let t = std::fs::read_to_string(root.join("pyproject.toml")).ok()?;
            let m: toml::Value = toml::from_str(&t).ok()?;
            let urls = m.get("project")?.get("urls")?;
            ["Repository", "Source", "Homepage"]
                .iter()
                .find_map(|k| urls.get(k).and_then(|u| u.as_str()).map(str::to_string))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, Severity};
    use crate::hunt::Ecosystem;
    use std::collections::HashMap;

    fn target(name: &str, direct: bool) -> DependencyTarget {
        DependencyTarget {
            ecosystem: Ecosystem::Cargo,
            name: name.into(),
            version: "1.0.0".into(),
            direct,
        }
    }

    fn adv(name: &str, direct: bool, known: &[&str]) -> DependencyAdvisories {
        DependencyAdvisories {
            target: target(name, direct),
            known: known
                .iter()
                .map(|id| KnownVuln {
                    id: (*id).into(),
                    aliases: vec![],
                })
                .collect(),
        }
    }

    #[test]
    fn partition_skips_known_cve_and_caps_budget_direct_first() {
        let opts = HuntOptions {
            max_deps: 1,
            ..Default::default()
        };
        let rows = vec![
            adv("transitive-ish", false, &[]),
            adv("vulnerable", true, &["CVE-x"]),
            adv("clean-direct", true, &[]),
        ];
        let (selected, skipped) = partition(rows, &opts);
        // clean-direct wins the single slot (direct, no known CVE).
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].target.name, "clean-direct");
        // vulnerable skipped as KnownCve; the other direct/transitive over budget.
        let reasons: HashMap<&str, SkipReason> = skipped
            .iter()
            .map(|s| (s.target.name.as_str(), s.reason))
            .collect();
        assert_eq!(reasons["vulnerable"], SkipReason::KnownCve);
        assert_eq!(reasons["transitive-ish"], SkipReason::OverBudget);
    }

    #[test]
    fn partition_can_reaudit_known_when_asked() {
        let opts = HuntOptions {
            max_deps: 10,
            reaudit_known: true,
            ..Default::default()
        };
        let (selected, skipped) = partition(vec![adv("v", true, &["CVE-x"])], &opts);
        assert_eq!(selected.len(), 1);
        assert!(skipped.is_empty());
    }

    // ── orchestration with mocks ──────────────────────────────────────
    struct FakeOsv(HashMap<String, Vec<KnownVuln>>);
    #[async_trait]
    impl OsvClient for FakeOsv {
        async fn known_vulns(&self, t: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
            Ok(self.0.get(&t.name).cloned().unwrap_or_default())
        }
    }

    struct FakeFetcher;
    #[async_trait]
    impl SourceFetcher for FakeFetcher {
        async fn fetch_into(
            &self,
            _t: &DependencyTarget,
            dest: &Path,
        ) -> Result<super::super::fetch::ExtractStats, String> {
            std::fs::write(dest.join("lib.rs"), "fn f(){}").unwrap();
            Ok(super::super::fetch::ExtractStats { files: 1, bytes: 8 })
        }
    }

    struct FakeAuditor;
    #[async_trait]
    impl DirAuditor for FakeAuditor {
        async fn audit(&self, _dir: &Path) -> Result<Vec<Finding>, String> {
            let mut f = Finding::candidate(
                "ai_audit",
                FindingKind::Other,
                Severity::High,
                "t",
                "lib.rs",
                Some(1),
                "s",
                "ai-audit/x",
                vec![],
            );
            f.status = FindingStatus::NeedsHuman;
            Ok(vec![f])
        }
    }

    fn write_cargo_project(dir: &Path) {
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname=\"app\"\nversion=\"0.1.0\"\n[dependencies]\ngood = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname=\"app\"\nversion=\"0.1.0\"\n\n\
             [[package]]\nname=\"good\"\nversion=\"1.0.0\"\nsource=\"registry+x\"\n\n\
             [[package]]\nname=\"deep\"\nversion=\"2.0.0\"\nsource=\"registry+x\"\n",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn run_hunt_default_audits_direct_clean_deps_and_reports_novelty() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        let osv = FakeOsv(HashMap::new()); // nothing known
        let report = run_hunt(
            dir.path(),
            &HuntOptions::default(),
            &osv,
            &FakeFetcher,
            &FakeAuditor,
        )
        .await
        .unwrap();

        assert_eq!(report.total_targets, 2, "good + deep (app excluded)");
        // Only `good` is direct → audited; `deep` is transitive → skipped.
        assert_eq!(report.audited.len(), 1);
        assert_eq!(report.audited[0].target.name, "good");
        assert!(report.audited[0].audited);
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.target.name == "deep" && s.reason == SkipReason::Transitive)
        );
        // The needs-human finding in a clean dep is a novelty candidate.
        let novel = report.novel_candidates();
        assert_eq!(novel.len(), 1);
        assert_eq!(novel[0].0.target.name, "good");
    }

    #[test]
    fn disclosure_drafts_only_for_eligible_novelty_candidates() {
        let mut nh = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "SQLi in query builder",
            "src/db.rs",
            Some(10),
            "s",
            "ai-audit/sql_injection",
            vec![],
        );
        nh.status = FindingStatus::NeedsHuman;
        let clean_dep = DependencyHunt {
            target: target("vuln-lib", true),
            known: vec![],
            audited: true,
            error: None,
            upstream: UpstreamInfo {
                github: Some("acme/vuln-lib".into()),
                security_emails: vec![],
            },
            findings: vec![nh],
        };
        // A dependency with a known CVE is NOT a novelty candidate → no draft.
        let known_dep = DependencyHunt {
            target: target("known", true),
            known: vec![KnownVuln {
                id: "CVE-x".into(),
                aliases: vec![],
            }],
            audited: true,
            error: None,
            upstream: UpstreamInfo::default(),
            findings: vec![{
                let mut f = Finding::candidate(
                    "ai_audit",
                    FindingKind::Other,
                    Severity::High,
                    "t",
                    "a.rs",
                    Some(1),
                    "s",
                    "ai-audit/x",
                    vec![],
                );
                f.status = FindingStatus::NeedsHuman;
                f
            }],
        };
        let report = HuntReport {
            project: "p".into(),
            total_targets: 2,
            audited: vec![clean_dep, known_dep],
            skipped: vec![],
        };
        let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 14).unwrap();
        let drafts = disclosure_drafts(&report, today);
        assert_eq!(drafts.len(), 1, "only the clean dep's finding drafts");
        assert_eq!(drafts[0].dependency, "vuln-lib@1.0.0");
        assert!(!drafts[0].draft.body.is_empty());
        assert!(!drafts[0].draft.subject.is_empty());

        // The UI's per-candidate package: same eligibility, plus channels and
        // the pre-send checklist; GitHub upstream ranks the advisory first.
        let fid = drafts[0].finding_id.clone();
        let pkg = disclosure_package(&report, "vuln-lib@1.0.0", &fid, None, today).unwrap();
        assert_eq!(pkg.finding_id, fid);
        assert_eq!(
            pkg.channels[0].channel,
            crate::disclose::Channel::GithubAdvisory
        );
        assert!(!pkg.checklist.is_empty());
        // A known-CVE dependency's finding, or a wrong dependency, is refused.
        let known_id = report.audited[1].findings[0].id.clone();
        assert!(disclosure_package(&report, "known@1.0.0", &known_id, None, today).is_err());
        assert!(disclosure_package(&report, "other@1.0.0", &fid, None, today).is_err());
    }

    #[test]
    fn load_hunt_report_round_trips_and_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let report = HuntReport {
            project: "p".into(),
            total_targets: 0,
            audited: vec![],
            skipped: vec![],
        };
        let good = dir.path().join("hunt.json");
        std::fs::write(&good, serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(load_hunt_report(&good).unwrap().project, "p");
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, b"{\"findings\": []}").unwrap();
        assert!(load_hunt_report(&bad).is_err());
    }

    struct SlowAuditor;
    #[async_trait]
    impl DirAuditor for SlowAuditor {
        async fn audit(&self, _dir: &Path) -> Result<Vec<Finding>, String> {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn run_hunt_times_out_a_slow_dependency_and_continues() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        let opts = HuntOptions {
            per_dep_timeout: std::time::Duration::from_millis(50),
            ..Default::default()
        };
        let report = run_hunt(
            dir.path(),
            &opts,
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &SlowAuditor,
        )
        .await
        .unwrap();
        assert_eq!(report.audited.len(), 1);
        assert!(!report.audited[0].audited);
        assert!(
            report.audited[0]
                .error
                .as_deref()
                .unwrap_or("")
                .contains("timed out"),
            "{:?}",
            report.audited[0].error
        );
    }

    #[tokio::test]
    async fn run_hunt_skips_a_direct_dep_with_a_known_cve() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        let mut known = HashMap::new();
        known.insert(
            "good".to_string(),
            vec![KnownVuln {
                id: "CVE-known".into(),
                aliases: vec![],
            }],
        );
        let report = run_hunt(
            dir.path(),
            &HuntOptions::default(),
            &FakeOsv(known),
            &FakeFetcher,
            &FakeAuditor,
        )
        .await
        .unwrap();
        assert!(
            report.audited.is_empty(),
            "known-CVE dep is skipped by default"
        );
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.target.name == "good" && s.reason == SkipReason::KnownCve)
        );
    }

    // ── dependency-level concurrency ──────────────────────────────────
    fn write_cargo_project_with(dir: &Path, deps: &[&str]) {
        let mut manifest =
            String::from("[package]\nname=\"app\"\nversion=\"0.1.0\"\n[dependencies]\n");
        let mut lock = String::from("[[package]]\nname=\"app\"\nversion=\"0.1.0\"\n\n");
        for d in deps {
            manifest.push_str(&format!("{d} = \"1\"\n"));
            lock.push_str(&format!(
                "[[package]]\nname=\"{d}\"\nversion=\"1.0.0\"\nsource=\"registry+x\"\n\n"
            ));
        }
        std::fs::write(dir.join("Cargo.toml"), manifest).unwrap();
        std::fs::write(dir.join("Cargo.lock"), lock).unwrap();
    }

    /// Records how many audits overlap. Earlier calls sleep longer, so with
    /// concurrency the audits finish out of plan order.
    #[derive(Default)]
    struct OverlapAuditor {
        in_flight: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl DirAuditor for OverlapAuditor {
        async fn audit(&self, _dir: &Path) -> Result<Vec<Finding>, String> {
            use std::sync::atomic::Ordering::SeqCst;
            let nth = self.calls.fetch_add(1, SeqCst);
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            let ms = 120u64.saturating_sub(30 * nth as u64).max(20);
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            self.in_flight.fetch_sub(1, SeqCst);
            Ok(vec![])
        }
    }

    async fn hunt_with_concurrency(dep_concurrency: usize, deps: &[&str]) -> (HuntReport, usize) {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project_with(dir.path(), deps);
        let opts = HuntOptions {
            dep_concurrency,
            ..Default::default()
        };
        let auditor = OverlapAuditor::default();
        let report = run_hunt(
            dir.path(),
            &opts,
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &auditor,
        )
        .await
        .unwrap();
        (
            report,
            auditor.peak.load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    #[tokio::test]
    async fn run_hunt_audits_dependencies_concurrently_up_to_the_limit() {
        let deps = ["aa", "bb", "cc", "dd", "ee"];
        let (report, peak) = hunt_with_concurrency(2, &deps).await;
        assert_eq!(peak, 2, "two dependencies in flight at once");
        assert_eq!(report.audited.len(), 5);
        assert!(report.audited.iter().all(|d| d.audited));

        let (_, serial_peak) = hunt_with_concurrency(1, &deps).await;
        assert_eq!(
            serial_peak, 1,
            "concurrency 1 keeps the old serial behaviour"
        );
    }

    #[tokio::test]
    async fn run_hunt_keeps_plan_order_when_audits_finish_out_of_order() {
        let deps = ["aa", "bb", "cc", "dd"];
        let (report, _) = hunt_with_concurrency(4, &deps).await;
        let names: Vec<&str> = report
            .audited
            .iter()
            .map(|d| d.target.name.as_str())
            .collect();
        assert_eq!(names, deps, "report order must not depend on finish order");
    }

    #[tokio::test]
    async fn run_hunt_clamps_dependency_concurrency() {
        let deps = ["aa", "bb", "cc", "dd", "ee", "ff"];
        // 0 would stall a buffered stream forever; it is treated as 1.
        let (report, peak) = hunt_with_concurrency(0, &deps).await;
        assert_eq!(peak, 1);
        assert_eq!(report.audited.len(), 6);
        let (_, peak) = hunt_with_concurrency(99, &deps).await;
        assert_eq!(peak, MAX_DEP_CONCURRENCY);
    }

    #[test]
    fn default_dependency_concurrency_is_two() {
        assert_eq!(HuntOptions::default().dep_concurrency, 2);
    }
}
