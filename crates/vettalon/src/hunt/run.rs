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

use std::collections::{HashMap, HashSet};
use std::path::Path;

use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use super::fetch::SourceFetcher;
use super::malicious::MaliciousReport;
use super::osv::{DependencyAdvisories, KnownVuln, OsvClient, OsvEvidence, OsvStatus, scan_known};
use super::priority::{DepPriority, DependencyPriority, ReachRecord};
use super::seeds::{SeedContext, SeedOptions, SeedRecord, SeedSource};
use super::{DependencyTarget, Ecosystem, IntakeEvidence, intake_from_dir};
use crate::audit::schema::{Finding, FindingStatus};
use vettalon_contract::coverage::{IncompleteReason, RunStatus};

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
    /// Candidate order before the `max_deps` cap (`--dep-priority`).
    pub dep_priority: DepPriority,
    /// Operator-supplied reachability verdicts used by the risk score.
    pub reach_evidence: Vec<ReachRecord>,
    /// `Some` = collect variant seeds for each audited dependency (O7).
    pub variant_seeds: Option<SeedOptions>,
    /// `--hunt-budget`: a total split across dependencies with rollover
    /// ([`crate::budget::DepBudget`]). When set, `per_dep_timeout` is not
    /// used; the rollover's own cap bounds one share. `None` = a fixed
    /// `per_dep_timeout` for every dependency.
    pub rollover: Option<crate::budget::RolloverBudget>,
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
            dep_priority: DepPriority::Default,
            reach_evidence: Vec::new(),
            variant_seeds: None,
            rollover: None,
        }
    }
}

/// Why a dependency was not audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Transitive, and `--include-transitive` was not set.
    Transitive,
    /// Directness could not be established; do not silently call it transitive.
    DirectnessUnknown,
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
    #[serde(default)]
    pub osv: OsvEvidence,
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
    /// Requirement-looking lines from the package's security policy, quoted
    /// as DATA for human confirmation (never acted on).
    #[serde(default)]
    pub policy_requirements: Vec<String>,
    /// Where `github` came from (package metadata file and field, or the Go
    /// module path). Absent in reports written before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_source: Option<crate::disclose::UpstreamOrigin>,
}

/// Stage evidence is unknown for reports written before this ledger existed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    #[default]
    Unknown,
    NotStarted,
    Succeeded,
    Incomplete,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageEvidence {
    pub status: StageStatus,
    pub duration_ms: u64,
    pub files: Option<usize>,
    pub bytes: Option<u64>,
}

/// Private child-scan evidence. Findings stay in DependencyHunt; this retains
/// scope and engine gaps without duplicating source snippets or transcripts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyAuditEvidence {
    pub run_status: Option<RunStatus>,
    pub incomplete_reason: Option<IncompleteReason>,
    pub coverage: Vec<crate::audit::schema::ModuleCoverage>,
    pub summary: Option<crate::audit::schema::CoverageSummary>,
    pub engines_missing: Vec<crate::audit::schema::EngineMissing>,
}

pub struct DirAuditResult {
    pub findings: Vec<Finding>,
    pub evidence: DependencyAuditEvidence,
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
    #[serde(default)]
    pub osv: OsvEvidence,
    #[serde(default)]
    pub fetch: StageEvidence,
    #[serde(default)]
    pub audit: StageEvidence,
    #[serde(default)]
    pub audit_evidence: DependencyAuditEvidence,
    #[serde(default)]
    pub duration_ms: u64,
    /// Variant-seed ledger when `--variant-seeds` ran for this dependency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seeds: Option<SeedRecord>,
}

impl DependencyHunt {
    pub fn has_completed_audit(&self) -> bool {
        self.audited
            && self.audit.status == StageStatus::Succeeded
            && self.audit_evidence.run_status == Some(RunStatus::Complete)
    }

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

    /// Novelty candidates in this dependency: actionable findings when OSV
    /// reports no advisory for the locked version, minus findings the
    /// variant-seed de-dup tied to a known advisory. Empty otherwise.
    pub fn novel_findings(&self) -> impl Iterator<Item = &Finding> {
        let eligible = self.known.is_empty() && self.osv.status == OsvStatus::Unmatched;
        self.actionable().filter(move |f| {
            eligible
                && !self
                    .seeds
                    .as_ref()
                    .is_some_and(|s| s.is_known_duplicate(&f.id))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    /// None for legacy reports; absence never proves successful intake.
    #[serde(default)]
    pub intake: Option<IntakeEvidence>,
    pub project: String,
    /// Every dependency resolved from the lockfiles.
    pub total_targets: usize,
    pub audited: Vec<DependencyHunt>,
    pub skipped: Vec<SkippedDep>,
    /// Unknown for reports predating the dependency evidence ledger.
    #[serde(default)]
    pub run_status: Option<RunStatus>,
    #[serde(default)]
    pub incomplete_reasons: Vec<String>,
    /// Candidate ordering used for this hunt (legacy reports: default order).
    #[serde(default)]
    pub dep_priority: DepPriority,
    /// Score breakdown per candidate when `--dep-priority risk` ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub priorities: Vec<DependencyPriority>,
    /// Rule-based malicious-package signals when `--malicious-signals` ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub malicious: Option<MaliciousReport>,
    /// The budget mode, what each dependency was granted and used, and how
    /// many were deferred. Absent in reports from earlier releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<crate::budget::HuntBudgetRecord>,
}

impl HuntReport {
    pub fn has_complete_scope_evidence(&self) -> bool {
        self.run_status == Some(RunStatus::Complete)
            && self
                .intake
                .as_ref()
                .is_some_and(|v| v.is_complete() && v.resolved_targets == self.total_targets)
    }

    /// Novelty candidates: actionable findings in dependencies with no known
    /// OSV advisory. These are the responsible-disclosure candidates.
    pub fn novel_candidates(&self) -> Vec<(&DependencyHunt, &Finding)> {
        self.audited
            .iter()
            .flat_map(|d| d.novel_findings().map(move |f| (d, f)))
            .collect()
    }
}

/// Audits a directory of source with the deep engine. Injected so the hunt
/// orchestration is testable without models.
#[async_trait]
pub trait DirAuditor: Send + Sync {
    async fn audit(&self, dir: &Path) -> Result<Vec<Finding>, String>;

    /// Existing third-party auditors stay source-compatible. A finding list
    /// alone cannot establish completion or source coverage.
    async fn audit_with_evidence(&self, dir: &Path) -> Result<DirAuditResult, String> {
        Ok(DirAuditResult {
            findings: self.audit(dir).await?,
            evidence: DependencyAuditEvidence::default(),
        })
    }

    /// Audit with variant seeds for the finder. Returns whether the seeds were
    /// actually delivered; the default ignores them (and says so).
    async fn audit_seeded(
        &self,
        dir: &Path,
        _seeds: &SeedContext,
    ) -> Result<(DirAuditResult, bool), String> {
        Ok((self.audit_with_evidence(dir).await?, false))
    }
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
    /// Per-dependency-operation sandbox image. Callers upgrading struct
    /// literals may use `crate::sandbox::DEFAULT_POC_IMAGE.into()`.
    pub poc_image: String,
}

#[async_trait]
impl DirAuditor for EngineAuditor {
    async fn audit(&self, dir: &Path) -> Result<Vec<Finding>, String> {
        Ok(self.audit_with_evidence(dir).await?.findings)
    }

    async fn audit_with_evidence(&self, dir: &Path) -> Result<DirAuditResult, String> {
        self.scan(dir, self.finders.clone()).await
    }

    async fn audit_seeded(
        &self,
        dir: &Path,
        seeds: &SeedContext,
    ) -> Result<(DirAuditResult, bool), String> {
        if seeds.block.is_empty() {
            return Ok((self.scan(dir, self.finders.clone()).await?, false));
        }
        // Only finder prompts carry seeds; verifiers and PoC models never see them.
        let block: std::sync::Arc<str> = std::sync::Arc::from(seeds.block.as_str());
        let finders = self
            .finders
            .iter()
            .map(|m| crate::llm::ModelHandle {
                id: m.id.clone(),
                family: m.family.clone(),
                caller: std::sync::Arc::new(super::seeds::SeededCaller {
                    inner: m.caller.clone(),
                    block: block.clone(),
                }),
            })
            .collect();
        Ok((self.scan(dir, finders).await?, true))
    }
}

impl EngineAuditor {
    async fn scan(
        &self,
        dir: &Path,
        finders: Vec<crate::llm::ModelHandle>,
    ) -> Result<DirAuditResult, String> {
        let opts = crate::audit::ScanOptions {
            repo_path: dir.to_path_buf(),
            profile: "deep".into(),
            report: None,
            sarif: None,
            cyclonedx: None,
            fail_on: "none".into(),
            gates: Vec::new(),
            max_modules: self.max_modules,
            poc: self.poc,
            poc_image: self.poc_image.clone(),
            save: false,
            cross_check_top: 0,
            dual_finder_top: 0,
            fail_on_needs_human: false,
            no_prior: true,
            rank: crate::audit::RankStrategy::Heuristic,
            trace: None,
            source_receipts: false,
            time_budget: None,
            refuter_runs: crate::audit::DEFAULT_REFUTER_RUNS,
            finder_parse_retries: crate::audit::DEFAULT_FINDER_PARSE_RETRIES,
            verifier_parse_retries: crate::audit::DEFAULT_VERIFIER_PARSE_RETRIES,
            refuter_policy: crate::audit::RefuterPolicy::CURRENT,
            refuter_score: false,
            refuter_score_threshold: None,
            prescreen: None,
            role_caps: Default::default(),
            fix_test_command: None,
            finders,
            verifiers: self.verifiers.clone(),
            poc_models: self.poc_models.clone(),
            roster: self.roster.clone(),
        };
        let report = crate::audit::run_scan(&self.home, &opts)
            .await
            .map_err(|e| e.english())?;
        Ok(DirAuditResult {
            findings: report.findings,
            evidence: DependencyAuditEvidence {
                run_status: Some(report.run_status),
                incomplete_reason: report.incomplete_reason,
                coverage: report.coverage,
                summary: Some(report.summary.coverage),
                engines_missing: report.engines_missing,
            },
        })
    }
}

/// Decide which OSV-classified candidates to audit vs skip (pure). Direct
/// filtering happens before OSV (to save calls), so `rows` are the candidates
/// that were classified; `pre_skipped` carries the transitive ones already set
/// aside. Direct dependencies fill the `max_deps` budget first.
pub fn partition(
    rows: Vec<DependencyAdvisories>,
    opts: &HuntOptions,
) -> (Vec<DependencyAdvisories>, Vec<SkippedDep>) {
    partition_scored(rows, opts, None)
}

type ScoreKey = (Ecosystem, String, String);

/// [`partition`] with an optional risk score per candidate
/// (`--dep-priority risk`): highest score first, ties direct-first then name.
pub fn partition_scored(
    mut rows: Vec<DependencyAdvisories>,
    opts: &HuntOptions,
    scores: Option<&HashMap<ScoreKey, DependencyPriority>>,
) -> (Vec<DependencyAdvisories>, Vec<SkippedDep>) {
    match scores {
        Some(scores) => {
            let score_of = |t: &DependencyTarget| {
                scores
                    .get(&(t.ecosystem, t.name.clone(), t.version.clone()))
                    .map_or(0.0, |p| p.score)
            };
            rows.sort_by(|a, b| {
                super::priority::risk_cmp(
                    (&a.target, score_of(&a.target)),
                    (&b.target, score_of(&b.target)),
                )
            });
        }
        None => rows.sort_by_key(|r| !r.target.direct), // direct first (stable)
    }
    let mut selected = Vec::new();
    let mut skipped = Vec::new();
    for row in rows {
        if !opts.reaudit_known && !row.known.is_empty() {
            skipped.push(SkippedDep {
                target: row.target,
                reason: SkipReason::KnownCve,
                known: row.known,
                osv: row.osv,
            });
        } else if selected.len() >= opts.max_deps {
            skipped.push(SkippedDep {
                target: row.target,
                reason: SkipReason::OverBudget,
                known: row.known,
                osv: row.osv,
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
    #[serde(default)]
    pub intake: Option<IntakeEvidence>,
    pub project: String,
    pub total_targets: usize,
    pub selected: Vec<DependencyAdvisories>,
    pub skipped: Vec<SkippedDep>,
    #[serde(default)]
    pub dep_priority: DepPriority,
    /// Score breakdown for every OSV-classified candidate (risk order only),
    /// in selection order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub priorities: Vec<DependencyPriority>,
}

impl HuntPlan {
    /// Every candidate the plan classified with OSV, plus pre-filtered ones,
    /// paired with its advisory row when one exists.
    pub fn all_targets(&self) -> Vec<DependencyTarget> {
        self.selected
            .iter()
            .map(|r| r.target.clone())
            .chain(self.skipped.iter().map(|s| s.target.clone()))
            .collect()
    }

    /// OSV rows for every classified candidate (selected and skipped-after-OSV).
    pub fn osv_rows(&self) -> Vec<DependencyAdvisories> {
        self.selected
            .iter()
            .cloned()
            .chain(
                self.skipped
                    .iter()
                    .filter(|s| s.osv.status != OsvStatus::Unknown)
                    .map(|s| DependencyAdvisories {
                        target: s.target.clone(),
                        known: s.known.clone(),
                        osv: s.osv.clone(),
                    }),
            )
            .collect()
    }
}

/// Resolve the plan: intake, direct pre-filter (before OSV, to save calls),
/// OSV classify, then [`partition`].
pub async fn plan_hunt<O: OsvClient>(
    project: &Path,
    opts: &HuntOptions,
    osv: &O,
) -> Result<HuntPlan, String> {
    let intake = intake_from_dir(project)?;
    let total_targets = intake.targets.len();
    let evidence = intake.evidence;
    let targets = intake.targets;
    let unknown_directness: HashSet<_> = evidence
        .directness_unknown
        .iter()
        .map(|t| (t.ecosystem.as_str(), t.name.as_str(), t.version.as_str()))
        .collect();

    let mut skipped: Vec<SkippedDep> = Vec::new();
    let candidates: Vec<DependencyTarget> = targets
        .into_iter()
        .filter(|t| {
            if !opts.include_transitive && !t.direct {
                skipped.push(SkippedDep {
                    target: t.clone(),
                    reason: if unknown_directness.contains(&(
                        t.ecosystem.as_str(),
                        t.name.as_str(),
                        t.version.as_str(),
                    )) {
                        SkipReason::DirectnessUnknown
                    } else {
                        SkipReason::Transitive
                    },
                    known: Vec::new(),
                    osv: OsvEvidence::default(),
                });
                false
            } else {
                true
            }
        })
        .collect();

    let scores = (opts.dep_priority == DepPriority::Risk).then(|| {
        let graph = super::graph::graph_from_dir(project);
        super::priority::score_all(&candidates, &graph, &opts.reach_evidence)
    });
    let rows = scan_known(&candidates, osv).await;
    let (selected, known_or_budget) = partition_scored(rows, opts, scores.as_ref());
    let priorities = scores
        .map(|mut scores| {
            selected
                .iter()
                .map(|r| &r.target)
                .chain(known_or_budget.iter().map(|s| &s.target))
                .filter_map(|t| scores.remove(&(t.ecosystem, t.name.clone(), t.version.clone())))
                .collect()
        })
        .unwrap_or_default();
    skipped.extend(known_or_budget);

    Ok(HuntPlan {
        intake: Some(evidence),
        project: project.display().to_string(),
        total_targets,
        selected,
        skipped,
        dep_priority: opts.dep_priority,
        priorities,
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
    /// The effective budget table, once the plan's dependency count is known.
    fn budget(&self, _table: &str) {}
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
    run_hunt_seeded(project, opts, osv, fetcher, auditor, progress, None).await
}

/// [`run_hunt_with_progress`] with an optional variant-seed source. Seeds are
/// collected only when `opts.variant_seeds` is set; without a source that
/// request is recorded per dependency as an error, never silently dropped.
pub async fn run_hunt_seeded<O, F, A, P>(
    project: &Path,
    opts: &HuntOptions,
    osv: &O,
    fetcher: &F,
    auditor: &A,
    progress: &P,
    seeds: Option<&dyn SeedSource>,
) -> Result<HuntReport, String>
where
    O: OsvClient,
    F: SourceFetcher,
    A: DirAuditor,
    P: HuntProgress,
{
    let plan = plan_hunt(project, opts, osv).await?;
    let seeding = opts.variant_seeds.as_ref().map(|o| SeedPlan {
        source: seeds,
        options: o,
        osv,
    });
    let seeding = seeding.as_ref();
    let total = plan.selected.len();
    let limit = opts.dep_concurrency.clamp(1, MAX_DEP_CONCURRENCY);
    let mode = match opts.rollover {
        Some(r) => crate::budget::HuntBudget::Rollover(r),
        None => crate::budget::HuntBudget::Fixed {
            per_dep: opts.per_dep_timeout,
        },
    };
    progress.budget(&mode.render_table(total));
    let allocator = opts
        .rollover
        .map(|r| crate::budget::DepBudget::new(r.total, r.cap, total));
    let allocator = allocator.as_ref();
    // Runs on the caller's task (no spawn), so the injected traits need not be
    // 'static. Results are re-sorted into plan order: the report must not
    // depend on which dependency happened to finish first. A rollover share
    // is computed when the dependency starts, so time an earlier dependency
    // left unused reaches the later ones.
    let mut finished: Vec<(usize, DependencyHunt, Option<std::time::Duration>)> =
        futures::stream::iter(plan.selected.iter().enumerate())
            .map(|(i, row)| async move {
                progress.start(i + 1, total, &row.target);
                let (hunt, granted) = match allocator {
                    None => (
                        audit_dependency(row, opts.per_dep_timeout, fetcher, auditor, seeding)
                            .await,
                        Some(opts.per_dep_timeout),
                    ),
                    Some(budget) => match budget.allocate().await {
                        None => (deferred_for_budget(row), None),
                        Some(share) => {
                            let hunt =
                                audit_dependency(row, share, fetcher, auditor, seeding).await;
                            budget
                                .settle(share, std::time::Duration::from_millis(hunt.duration_ms));
                            (hunt, Some(share))
                        }
                    },
                };
                progress.done(i + 1, total, &hunt);
                (i, hunt, granted)
            })
            .buffer_unordered(limit)
            .collect()
            .await;
    finished.sort_by_key(|(i, ..)| *i);
    let budget = budget_record(&mode, &finished);
    let audited: Vec<DependencyHunt> = finished.into_iter().map(|(_, hunt, _)| hunt).collect();
    let mut incomplete_reasons = Vec::new();
    if !plan
        .intake
        .as_ref()
        .is_some_and(IntakeEvidence::is_complete)
    {
        incomplete_reasons.push("dependency_intake_incomplete".into());
    }
    if audited.iter().any(|d| !d.audited) {
        incomplete_reasons.push("dependency_audit_incomplete".into());
    }
    if audited
        .iter()
        .any(|d| matches!(d.osv.status, OsvStatus::Failed | OsvStatus::Unknown))
    {
        incomplete_reasons.push("advisory_query_unknown".into());
    }
    if audited
        .iter()
        .any(|d| d.seeds.as_ref().is_some_and(|s| !s.errors.is_empty()))
    {
        incomplete_reasons.push("variant_seed_lookup_failed".into());
    }
    if plan
        .skipped
        .iter()
        .any(|d| d.reason == SkipReason::OverBudget)
    {
        incomplete_reasons.push("dependency_budget_exhausted".into());
    }
    if budget.deferred > 0 {
        incomplete_reasons.push("hunt_time_budget_exhausted".into());
    }
    let run_status = Some(if incomplete_reasons.is_empty() {
        RunStatus::Complete
    } else {
        RunStatus::Incomplete
    });
    Ok(HuntReport {
        intake: plan.intake,
        project: plan.project,
        total_targets: plan.total_targets,
        audited,
        skipped: plan.skipped,
        run_status,
        incomplete_reasons,
        dep_priority: plan.dep_priority,
        priorities: plan.priorities,
        malicious: None,
        budget: Some(budget),
    })
}

/// A dependency `--hunt-budget` could no longer fund: recorded, not started.
fn deferred_for_budget(row: &DependencyAdvisories) -> DependencyHunt {
    DependencyHunt {
        target: row.target.clone(),
        known: row.known.clone(),
        osv: row.osv.clone(),
        audited: false,
        error: Some(DEFERRED_FOR_BUDGET.into()),
        upstream: UpstreamInfo::default(),
        findings: Vec::new(),
        fetch: StageEvidence {
            status: StageStatus::NotStarted,
            ..Default::default()
        },
        audit: StageEvidence {
            status: StageStatus::NotStarted,
            ..Default::default()
        },
        audit_evidence: DependencyAuditEvidence::default(),
        duration_ms: 0,
        seeds: None,
    }
}

/// Error text of a dependency deferred by `--hunt-budget`.
pub const DEFERRED_FOR_BUDGET: &str =
    "deferred: the hunt budget could not fund this dependency (--hunt-budget)";

fn budget_record(
    mode: &crate::budget::HuntBudget,
    finished: &[(usize, DependencyHunt, Option<std::time::Duration>)],
) -> crate::budget::HuntBudgetRecord {
    let allocations: Vec<crate::budget::DepAllocation> = finished
        .iter()
        .map(|(_, h, granted)| crate::budget::DepAllocation {
            ecosystem: h.target.ecosystem.as_str().to_string(),
            name: h.target.name.clone(),
            version: h.target.version.clone(),
            granted_secs: granted.map(|d| d.as_secs()),
            used_ms: h.duration_ms,
            deferred: granted.is_none(),
        })
        .collect();
    let (mode_name, total_secs, dep_cap_secs) = match mode {
        crate::budget::HuntBudget::Fixed { per_dep } => ("fixed", None, Some(per_dep.as_secs())),
        crate::budget::HuntBudget::Rollover(r) => (
            "rollover",
            Some(r.total.as_secs()),
            r.cap.map(|c| c.as_secs()),
        ),
    };
    crate::budget::HuntBudgetRecord {
        mode: mode_name.into(),
        total_secs,
        dep_cap_secs,
        spent_ms: allocations.iter().map(|a| a.used_ms).sum(),
        deferred: allocations.iter().filter(|a| a.deferred).count(),
        allocations,
    }
}

/// Variant-seed inputs for one hunt.
struct SeedPlan<'a> {
    source: Option<&'a dyn SeedSource>,
    options: &'a SeedOptions,
    /// Re-queried after the audit so a known advisory is never reported as novel.
    osv: &'a dyn OsvClient,
}

/// Fetch + audit one dependency, recording a timeout as an unaudited
/// dependency instead of failing the hunt.
#[cfg(test)]
async fn audit_within_timeout<F: SourceFetcher, A: DirAuditor>(
    row: &DependencyAdvisories,
    timeout: std::time::Duration,
    fetcher: &F,
    auditor: &A,
) -> DependencyHunt {
    audit_dependency(row, timeout, fetcher, auditor, None).await
}

async fn audit_dependency<F: SourceFetcher, A: DirAuditor>(
    row: &DependencyAdvisories,
    timeout: std::time::Duration,
    fetcher: &F,
    auditor: &A,
    seeding: Option<&SeedPlan<'_>>,
) -> DependencyHunt {
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + timeout;
    let elapsed =
        |since: std::time::Instant| since.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let mut result = DependencyHunt {
        target: row.target.clone(),
        known: row.known.clone(),
        osv: row.osv.clone(),
        audited: false,
        error: None,
        upstream: UpstreamInfo::default(),
        findings: Vec::new(),
        fetch: StageEvidence {
            status: StageStatus::NotStarted,
            ..Default::default()
        },
        audit: StageEvidence {
            status: StageStatus::NotStarted,
            ..Default::default()
        },
        audit_evidence: DependencyAuditEvidence::default(),
        duration_ms: 0,
        seeds: None,
    };
    let tmp = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => {
            result.fetch.status = StageStatus::Failed;
            result.error = Some(format!("scratch dir failed: {error}"));
            return result;
        }
    };
    let fetching = std::time::Instant::now();
    let fetch =
        tokio::time::timeout_at(deadline, fetcher.fetch_into(&row.target, tmp.path())).await;
    result.fetch.duration_ms = elapsed(fetching);
    match fetch {
        Ok(Ok(stats)) => {
            result.fetch.status = StageStatus::Succeeded;
            result.fetch.files = Some(stats.files);
            result.fetch.bytes = Some(stats.bytes);
        }
        Ok(Err(error)) => {
            result.fetch.status = StageStatus::Failed;
            result.error = Some(format!(
                "fetch failed: {}",
                crate::util::mask_sensitive_text(&error)
            ));
        }
        Err(_) => {
            result.fetch.status = StageStatus::TimedOut;
            result.error = Some(format!("timed out after {}s (fetch)", timeout.as_secs()));
        }
    }
    if result.fetch.status != StageStatus::Succeeded {
        result.duration_ms = elapsed(started);
        return result;
    }
    result.upstream = detect_upstream(tmp.path(), &row.target);
    let context = match seeding {
        None => None,
        Some(plan) => Some(match plan.source {
            None => SeedContext {
                record: SeedRecord {
                    errors: vec!["no seed source configured".into()],
                    ..Default::default()
                },
                block: String::new(),
            },
            Some(source) => {
                let collecting = super::seeds::collect(
                    source,
                    &row.target,
                    result.upstream.github.as_deref(),
                    plan.options,
                    chrono::Utc::now(),
                );
                match tokio::time::timeout_at(deadline, collecting).await {
                    Ok(ctx) => ctx,
                    Err(_) => SeedContext {
                        record: SeedRecord {
                            errors: vec!["seed collection timed out".into()],
                            ..Default::default()
                        },
                        block: String::new(),
                    },
                }
            }
        }),
    };
    let auditing = std::time::Instant::now();
    let audit = match &context {
        Some(ctx) => tokio::time::timeout_at(deadline, auditor.audit_seeded(tmp.path(), ctx))
            .await
            .map(|r| {
                r.map(|(audit, delivered)| {
                    result.seeds = Some(SeedRecord {
                        delivered_to_finders: delivered,
                        ..ctx.record.clone()
                    });
                    audit
                })
            }),
        None => tokio::time::timeout_at(deadline, auditor.audit_with_evidence(tmp.path())).await,
    };
    if result.seeds.is_none()
        && let Some(ctx) = &context
    {
        result.seeds = Some(ctx.record.clone());
    }
    result.audit.duration_ms = elapsed(auditing);
    match audit {
        Ok(Ok(audit)) => {
            result.findings = audit.findings;
            result.audit_evidence = audit.evidence;
            result.audit.status = match result.audit_evidence.run_status {
                Some(RunStatus::Complete) => StageStatus::Succeeded,
                Some(RunStatus::Incomplete) => StageStatus::Incomplete,
                None => StageStatus::Unknown,
            };
            result.audited = result.audit.status == StageStatus::Succeeded;
            if !result.audited {
                result.error = Some(match result.audit_evidence.run_status {
                    Some(_) => {
                        "child scan incomplete; inspect audit_evidence for scope and reason".into()
                    }
                    None => "auditor returned findings without child-scan coverage evidence".into(),
                });
            }
        }
        Ok(Err(error)) => {
            result.audit.status = StageStatus::Failed;
            result.error = Some(format!(
                "audit failed: {}",
                crate::util::mask_sensitive_text(&error)
            ));
        }
        Err(_) => {
            result.audit.status = StageStatus::TimedOut;
            result.error = Some(format!("timed out after {}s (audit)", timeout.as_secs()));
        }
    }
    if let (Some(plan), Some(record)) = (seeding, result.seeds.as_mut()) {
        record.dedup = super::seeds::dedup(&result.findings, record, &row.target.version);
        // Re-check OSV after seeding: anything published for this version
        // meanwhile makes the dependency known, so nothing in it is novel.
        match plan
            .osv
            .known_vulns_batch(std::slice::from_ref(&row.target))
            .await
        {
            Ok(rows) if rows.len() == 1 => {
                let known = rows.into_iter().next().unwrap_or_default();
                if known.is_empty() {
                    record.osv_recheck = OsvStatus::Unmatched;
                } else {
                    record.osv_recheck = OsvStatus::Matched;
                    result.known = known;
                    result.osv.status = OsvStatus::Matched;
                }
            }
            other => {
                record.osv_recheck = OsvStatus::Failed;
                result.osv.status = OsvStatus::Failed;
                result.osv.error = Some(match other {
                    Err(e) => format!(
                        "post-seed OSV re-check failed: {}",
                        crate::util::mask_sensitive_text(crate::util::truncate_bytes(&e, 200))
                    ),
                    Ok(_) => "post-seed OSV re-check returned the wrong row count".into(),
                });
            }
        }
    }
    result.duration_ms = elapsed(started);
    result
}

fn skip_counts(skipped: &[SkippedDep]) -> (usize, usize, usize, usize) {
    let mut t = 0;
    let mut k = 0;
    let mut b = 0;
    let mut u = 0;
    for s in skipped {
        match s.reason {
            SkipReason::Transitive => t += 1,
            SkipReason::DirectnessUnknown => u += 1,
            SkipReason::KnownCve => k += 1,
            SkipReason::OverBudget => b += 1,
        }
    }
    (t, k, b, u)
}

/// Summarize intake without exposing raw parser messages or input lines.
pub fn render_intake(intake: Option<&IntakeEvidence>, total: usize) -> String {
    let Some(evidence) = intake else {
        return "  Intake: unknown (legacy evidence); resolved count is not a complete inventory.\n".into();
    };
    let complete = evidence.is_complete() && evidence.resolved_targets == total;
    let mut out = format!(
        "  Intake: {}; resolved targets only; failed-source denominator unknown.\n",
        if complete {
            "complete for supported scope"
        } else {
            "incomplete"
        }
    );
    for source in &evidence.sources {
        if !matches!(
            source.status,
            super::IntakeSourceStatus::Parsed | super::IntakeSourceStatus::Absent
        ) {
            out.push_str(&format!(
                "    - {}: {} ({})\n",
                source.file,
                source.status.as_str(),
                source.reason_codes.join(", ")
            ));
        }
    }
    out
}

/// Preview for `--dry-run`: what would be audited and what is skipped.
pub fn render_plan(plan: &HuntPlan) -> String {
    let (t, k, b, u) = skip_counts(&plan.skipped);
    let mut out = crate::tr!(
        "供應鏈獵捕（預覽）：{}\n  已解析相依：{}　將審：{}　略過：{}（transitive {t}、已知 CVE {k}、超出上限 {b}、直接性未知 {u}）\n",
        "Supply-chain hunt (preview): {}\n  Resolved dependencies: {}  to audit: {}  skipped: {} (transitive {t}, known CVE {k}, over the cap {b}, directness unknown {u})\n",
        plan.project,
        plan.total_targets,
        plan.selected.len(),
        plan.skipped.len(),
    );
    out.push_str(&render_intake(plan.intake.as_ref(), plan.total_targets));
    out.push_str(match plan.dep_priority {
        DepPriority::Default => crate::lang::pick(
            "  將審查（OSV 查無已知漏洞、優先直接依賴）：\n",
            "  Will audit (no known vulnerability in OSV, direct dependencies first):\n",
        ),
        DepPriority::Risk => crate::lang::pick(
            "  將審查（OSV 查無已知漏洞、依風險分數 exposure × reach × criticality 排序；? 表示未知，以中性值計）：\n",
            "  Will audit (no known vulnerability in OSV, ordered by risk score exposure × reach × criticality; ? = unknown, neutral value used):\n",
        ),
    });
    for row in &plan.selected {
        out.push_str(&format!(
            "    - {} {}@{}{}\n",
            row.target.ecosystem.as_str(),
            row.target.name,
            row.target.version,
            if row.target.direct {
                ""
            } else {
                crate::lang::pick("（transitive）", " (transitive)")
            },
        ));
        out.push_str(&priority_line(&plan.priorities, &row.target));
    }
    out
}

fn priority_line(priorities: &[DependencyPriority], t: &DependencyTarget) -> String {
    priorities
        .iter()
        .find(|p| p.target == *t)
        .map(|p| format!("        {}\n", super::priority::render_breakdown(p)))
        .unwrap_or_default()
}

/// Summary of a completed hunt.
pub fn render_summary(report: &HuntReport) -> String {
    let (t, k, b, u) = skip_counts(&report.skipped);
    let novel = report.novel_candidates();
    let errors: Vec<&DependencyHunt> = report.audited.iter().filter(|d| !d.audited).collect();
    let mut out = crate::tr!(
        "供應鏈獵捕：{}\n  已解析相依：{}　已審：{}　略過：{}（transitive {t}、已知 CVE {k}、超出上限 {b}、直接性未知 {u}）\n  OSV 未命中的待人工候選（不代表已確認的新漏洞）：{}\n",
        "Supply-chain hunt: {}\n  Resolved dependencies: {}  audited: {}  skipped: {} (transitive {t}, known CVE {k}, over the cap {b}, directness unknown {u})\n  OSV-unmatched candidates for human review (not confirmed novel vulnerabilities): {}\n",
        report.project,
        report.total_targets,
        report
            .audited
            .iter()
            .filter(|d| d.has_completed_audit())
            .count(),
        report.skipped.len(),
        novel.len(),
    );
    out.push_str(&render_intake(report.intake.as_ref(), report.total_targets));
    if !report.has_complete_scope_evidence() {
        out.push_str(crate::lang::pick("  範圍狀態：不完整或舊報告缺乏證據，請查看每個依賴的 fetch/audit/OSV 紀錄。\n", "  Scope status: incomplete or legacy evidence unknown; inspect per-dependency fetch/audit/OSV records.\n"));
    }
    for dep in report
        .audited
        .iter()
        .filter(|d| matches!(d.osv.status, OsvStatus::Unknown | OsvStatus::Failed))
    {
        out.push_str(&format!(
            "  OSV unknown: {}@{} ({})\n",
            dep.target.name,
            dep.target.version,
            dep.osv
                .error
                .as_deref()
                .unwrap_or("legacy query evidence unavailable")
        ));
    }
    for (dep, f) in &novel {
        out.push_str(&crate::tr!(
            "    - [{}] {}@{} — {}（{}）@ {}{}\n",
            "    - [{}] {}@{} — {} ({}) @ {}{}\n",
            f.severity.as_str(),
            dep.target.name,
            dep.target.version,
            f.title,
            status_word(f.status),
            f.file,
            f.line.map(|l| format!(":{l}")).unwrap_or_default(),
        ));
    }
    out.push_str(&render_seeds(report));
    if !report.priorities.is_empty() {
        out.push_str(crate::lang::pick(
            "  依賴優先序（風險分數）：\n",
            "  Dependency priority (risk score):\n",
        ));
        for d in &report.audited {
            out.push_str(&format!("    - {}@{}\n", d.target.name, d.target.version));
            out.push_str(&priority_line(&report.priorities, &d.target));
        }
    }
    if let Some(m) = &report.malicious {
        out.push_str(&super::malicious::render(m));
    }
    if !errors.is_empty() {
        out.push_str(crate::lang::pick(
            "  抓取／審查失敗：\n",
            "  Fetch / audit failures:\n",
        ));
        for d in errors {
            out.push_str(&crate::tr!(
                "    - {}@{}：{}\n",
                "    - {}@{}: {}\n",
                d.target.name,
                d.target.version,
                d.error.as_deref().unwrap_or("unknown"),
            ));
        }
    }
    out
}

/// Variant-seed lines: what was seeded, de-dup verdicts, and lookup gaps.
fn render_seeds(report: &HuntReport) -> String {
    let mut out = String::new();
    for d in &report.audited {
        let Some(s) = &d.seeds else { continue };
        out.push_str(&crate::tr!(
            "  變體種子 {}@{}：OSV 紀錄 {}、安全相關 commit {}、{}送入 finder；OSV 複查 {:?}\n",
            "  Variant seeds {}@{}: {} OSV records, {} security commits, {} to finders; OSV re-check {:?}\n",
            d.target.name,
            d.target.version,
            s.advisories.len(),
            s.commits.len(),
            if s.delivered_to_finders {
                crate::lang::pick("已", "delivered")
            } else {
                crate::lang::pick("未", "not delivered")
            },
            s.osv_recheck,
        ));
        for e in &s.errors {
            out.push_str(&format!("    ! {e}\n"));
        }
        for x in &s.dedup {
            out.push_str(&format!(
                "    · {} {:?} {} ({})\n",
                x.finding_id,
                x.verdict,
                x.advisories.join(", "),
                x.reason
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
    pub package: crate::disclose::DisclosurePackage,
}

/// A novelty candidate the drafting rules skipped, and why.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedDraft {
    pub dependency: String,
    pub finding_id: String,
    pub reason: String,
}

/// Planned channel for one novelty candidate (no draft, no reviewer needed):
/// what a delivery report shows as the disclosure plan.
#[derive(Debug, Clone, Serialize)]
pub struct HuntDisclosurePlan {
    pub dependency: String,
    pub finding_id: String,
    pub channel: crate::disclose::Channel,
    pub submit: Option<String>,
    pub disclose_by: String,
    pub evidence_level: crate::audit::evidence_level::EvidenceLevel,
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
        github_source: dep.upstream.github_source.clone(),
        non_github_upstream: None,
        commit: None,
        security_policy: None,
        security_emails: dep.upstream.security_emails.clone(),
        policy_requirements: dep.upstream.policy_requirements.clone(),
    }
}

fn dep_key(dep: &DependencyHunt) -> String {
    format!("{}@{}", dep.target.name, dep.target.version)
}

/// Channel plan for every novelty candidate that could ever be drafted (not
/// `static_only`, not refuted/suppressed). Unproven ones still need
/// `--allow-unproven` and a human reproduction before any draft.
pub fn disclosure_plan(report: &HuntReport, today: chrono::NaiveDate) -> Vec<HuntDisclosurePlan> {
    report
        .novel_candidates()
        .into_iter()
        .filter_map(|(dep, f)| {
            let e = crate::disclose::draft_eligibility(f, true).ok()?;
            let top = crate::disclose::recommend(&project_meta_for(dep))
                .into_iter()
                .next()?;
            Some(HuntDisclosurePlan {
                dependency: dep_key(dep),
                finding_id: f.id.clone(),
                channel: top.channel,
                submit: top.submit,
                disclose_by: (today + chrono::Duration::days(top.window_days)).to_string(),
                evidence_level: e.level,
            })
        })
        .collect()
}

async fn hunt_extras(
    report: &HuntReport,
    dep: &DependencyHunt,
    f: &Finding,
    meta: &crate::disclose::ProjectMeta,
    dedupe: Option<&dyn crate::disclose::DedupeSource>,
    today: chrono::NaiveDate,
) -> crate::disclose::FindingExtras {
    let dedupe = match dedupe {
        Some(src) => crate::disclose::dedupe::check(src, meta, &f.file, today).await,
        None => crate::disclose::DedupeReport::not_requested(),
    };
    crate::disclose::FindingExtras {
        dedupe,
        dependency: Some((dep_key(dep), report.project.clone())),
    }
}

/// Build upstream disclosure drafts for every novelty candidate that passes
/// the drafting rules (evidence gate, throttle). The channel is the top
/// recommendation for that dependency's upstream. Within one call a second
/// candidate for the same upstream is skipped like an unanswered draft
/// (unless the throttle is forced). Drafts only; the caller records each
/// written draft with [`crate::disclose::record_draft`].
pub async fn disclosure_drafts(
    report: &HuntReport,
    today: chrono::NaiveDate,
    opts: &crate::disclose::DraftOptions,
    dedupe: Option<&dyn crate::disclose::DedupeSource>,
) -> (Vec<HuntDisclosure>, Vec<SkippedDraft>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut drafted_projects: Vec<String> = Vec::new();
    for (dep, f) in report.novel_candidates() {
        let skip = |reason: String| SkippedDraft {
            dependency: dep_key(dep),
            finding_id: f.id.clone(),
            reason,
        };
        if let Err(e) = crate::disclose::draft_eligibility(f, opts.allow_unproven) {
            skipped.push(skip(e));
            continue;
        }
        let meta = project_meta_for(dep);
        let project = crate::disclose::ledger::project_key(&meta);
        if drafted_projects.contains(&project) && opts.force_throttle.is_none() {
            skipped.push(skip(crate::tr!(
                "節流：本次已為 {project} 產生一份草稿；一次只送一份（或用 --force-throttle <理由>）。",
                "throttled: a draft for {project} was already produced in this run; send one at a time (or pass --force-throttle <reason>)."
            )));
            continue;
        }
        let extras = hunt_extras(report, dep, f, &meta, dedupe, today).await;
        match crate::disclose::package_for(f, meta, None, today, opts, extras) {
            Ok(package) => {
                drafted_projects.push(project);
                out.push(HuntDisclosure {
                    dependency: dep_key(dep),
                    finding_id: f.id.clone(),
                    finding_title: f.title.clone(),
                    package,
                });
            }
            Err(e) => skipped.push(skip(e)),
        }
    }
    (out, skipped)
}

/// Full disclosure package (ranked channels, draft, pre-send checklist) for
/// one novelty candidate, so the dashboard/desktop can reuse the scan report's
/// disclosure panel. Only a novelty candidate qualifies: a finding in a
/// dependency with a known OSV advisory, or one the drafting rules refuse,
/// is refused. Draft only — nothing is sent.
pub async fn disclosure_package(
    report: &HuntReport,
    dependency: &str,
    finding_id: &str,
    channel: Option<crate::disclose::Channel>,
    today: chrono::NaiveDate,
    opts: &crate::disclose::DraftOptions,
    dedupe: Option<&dyn crate::disclose::DedupeSource>,
) -> Result<crate::disclose::DisclosurePackage, String> {
    let (dep, f) = report
        .novel_candidates()
        .into_iter()
        .find(|(d, f)| f.id == finding_id && dep_key(d) == dependency)
        .ok_or_else(|| {
            crate::tr!(
                "{dependency} 沒有可揭露的新漏洞候選 {finding_id}",
                "{dependency} has no disclosable novelty candidate {finding_id}"
            )
        })?;
    // Gate before any network use.
    crate::disclose::draft_eligibility(f, opts.allow_unproven)?;
    let meta = project_meta_for(dep);
    let extras = hunt_extras(report, dep, f, &meta, dedupe, today).await;
    crate::disclose::package_for(f, meta, channel, today, opts, extras)
}

/// Read a saved hunt report (`vettalon hunt --report`) for delivery: size
/// capped, then parsed. The file is operator-chosen but may have been edited
/// or come from elsewhere, so it is never trusted beyond its shape.
pub fn load_hunt_report(path: &std::path::Path) -> Result<HuntReport, String> {
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    let meta = std::fs::metadata(path)
        .map_err(|e| crate::tr!("無法讀取 {}：{e}", "cannot read {}: {e}", path.display()))?;
    if meta.len() > MAX_BYTES {
        return Err(crate::tr!(
            "報告檔過大（{} bytes，上限 {MAX_BYTES}）",
            "report file too large ({} bytes, limit {MAX_BYTES})",
            meta.len()
        ));
    }
    let raw = std::fs::read(path)
        .map_err(|e| crate::tr!("無法讀取 {}：{e}", "cannot read {}: {e}", path.display()))?;
    let report: HuntReport = serde_json::from_slice(&raw).map_err(|e| {
        crate::tr!(
            "不是有效的供應鏈獵捕報告：{e}",
            "not a valid supply-chain hunt report: {e}"
        )
    })?;
    if report.run_status == Some(RunStatus::Complete)
        && report.intake.is_some()
        && !report.has_complete_scope_evidence()
    {
        return Err("complete hunt report contradicts dependency intake evidence".into());
    }
    Ok(report)
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
/// reuse `disclose::detect_project_as` (SECURITY.md, manifests, and the
/// repository URL in the package's own metadata first, since the extracted
/// source has no `.git`). For Go the module path the registry served names
/// the repository and wins over any other manifest in the tree.
fn detect_upstream(extracted: &Path, target: &DependencyTarget) -> UpstreamInfo {
    let root = package_root(extracted);
    let eco = match target.ecosystem {
        Ecosystem::Cargo => "Rust",
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "pip",
        Ecosystem::Go => "Go",
    };
    let meta = crate::disclose::detect_project_as(&root, Some(eco));
    let go_module = (target.ecosystem == Ecosystem::Go)
        .then(|| crate::disclose::github_slug(&crate::disclose::go_module_url(&target.name)))
        .flatten()
        .map(|slug| {
            (
                slug,
                crate::disclose::UpstreamOrigin::PackageMetadata {
                    file: "go.mod".into(),
                    field: "module path".into(),
                },
            )
        });
    let (github, github_source) = match go_module {
        Some((g, src)) => (Some(g), Some(src)),
        None => (meta.github, meta.github_source),
    };
    UpstreamInfo {
        github,
        security_emails: meta.security_emails,
        policy_requirements: meta.policy_requirements,
        github_source,
    }
}

#[cfg(test)]
#[path = "run_seed_tests.rs"]
mod seed_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, Severity};
    use crate::hunt::Ecosystem;
    use std::collections::HashMap;

    /// A dependency's stored `error` is report data: a zh-TW terminal must
    /// not write Chinese into it (the report renders later in any language).
    #[test]
    fn engine_auditor_error_is_english_under_a_zh_terminal() {
        let home = tempfile::tempdir().unwrap();
        let missing = home.path().join("no-such-source");
        let auditor = EngineAuditor {
            home: home.path().to_path_buf(),
            finders: Vec::new(),
            verifiers: Vec::new(),
            poc_models: Vec::new(),
            roster: Vec::new(),
            max_modules: 1,
            poc: false,
            poc_image: crate::sandbox::DEFAULT_POC_IMAGE.into(),
        };
        let err = crate::lang::with(crate::lang::Lang::ZhTw, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(auditor.audit_with_evidence(&missing))
                .err()
                .expect("a missing source directory fails before any model call")
        });
        assert!(err.starts_with("cannot resolve the target path"), "{err}");
        assert!(
            !err.chars()
                .any(|c| matches!(c as u32, 0x3000..=0x30FF | 0x4E00..=0x9FFF | 0xFF00..=0xFFEF)),
            "{err}"
        );
        // The terminal still gets its own language.
        let zh = crate::lang::with(crate::lang::Lang::ZhTw, || {
            crate::audit::ScanError::NotADirectory("x".into()).to_string()
        });
        assert!(zh.contains("資料夾"), "{zh}");
    }

    /// Reports written by older versions may carry a zh-TW `error`; they
    /// still parse and render as-is.
    #[test]
    fn legacy_zh_dependency_error_still_parses() {
        let raw = r#"{"target":{"ecosystem":"cargo","name":"legacy","version":"1.0.0","direct":true},"known":[],"audited":false,"error":"audit failed: 掃描目標不是資料夾：/x","upstream":{"github":null,"security_emails":[]},"findings":[]}"#;
        let d: DependencyHunt = serde_json::from_str(raw).unwrap();
        assert!(d.error.unwrap().contains("資料夾"));
    }

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
            osv: OsvEvidence {
                status: if known.is_empty() {
                    OsvStatus::Unmatched
                } else {
                    OsvStatus::Matched
                },
                ..Default::default()
            },
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
        async fn audit_with_evidence(&self, dir: &Path) -> Result<DirAuditResult, String> {
            Ok(DirAuditResult {
                findings: self.audit(dir).await?,
                evidence: DependencyAuditEvidence {
                    run_status: Some(RunStatus::Complete),
                    ..Default::default()
                },
            })
        }
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

    struct IncompleteAuditor;
    #[async_trait]
    impl DirAuditor for IncompleteAuditor {
        async fn audit(&self, _: &Path) -> Result<Vec<Finding>, String> {
            panic!("use evidence seam")
        }
        async fn audit_with_evidence(&self, _: &Path) -> Result<DirAuditResult, String> {
            let coverage = vec![crate::audit::schema::ModuleCoverage {
                module_path: "omitted".into(),
                status: crate::audit::schema::ModuleCoverageStatus::Deferred,
                reason: Some("max_modules".into()),
                scope_paths: vec!["lib.rs".into()],
                selected: false,
                reviewed_paths: vec![],
                truncated_paths: vec![],
                candidate_ids: vec![],
                attempts: vec![],
            }];
            let summary = crate::audit::schema::CoverageSummary::from_coverage(&coverage);
            Ok(DirAuditResult {
                findings: vec![],
                evidence: DependencyAuditEvidence {
                    run_status: Some(RunStatus::Incomplete),
                    incomplete_reason: Some(IncompleteReason::ScopeNotFullyReviewed),
                    coverage,
                    summary: Some(summary),
                    engines_missing: vec![],
                },
            })
        }
    }

    struct LegacyAuditor;
    #[async_trait]
    impl DirAuditor for LegacyAuditor {
        async fn audit(&self, _: &Path) -> Result<Vec<Finding>, String> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn hunt_retains_child_incomplete_scope_instead_of_promoting_to_clean() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        let report = run_hunt(
            dir.path(),
            &HuntOptions::default(),
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &IncompleteAuditor,
        )
        .await
        .unwrap();
        let dep = &report.audited[0];
        assert!(!dep.audited);
        assert_eq!(dep.audit.status, StageStatus::Incomplete);
        assert_eq!(dep.fetch.status, StageStatus::Succeeded);
        assert_eq!((dep.fetch.files, dep.fetch.bytes), (Some(1), Some(8)));
        assert_eq!(dep.audit_evidence.run_status, Some(RunStatus::Incomplete));
        assert_eq!(dep.audit_evidence.coverage[0].scope_paths, vec!["lib.rs"]);
        assert_eq!(
            dep.audit_evidence.incomplete_reason,
            Some(IncompleteReason::ScopeNotFullyReviewed)
        );
        assert_eq!(report.run_status, Some(RunStatus::Incomplete));
        if let Some(output) = std::env::var_os("VETTALON_HUNT_ARTIFACT_DIR") {
            std::fs::create_dir_all(&output).unwrap();
            std::fs::write(
                std::path::PathBuf::from(output).join("child-scope-incomplete.json"),
                serde_json::to_string_pretty(&report).unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn engine_auditor_preserves_real_child_ledger_with_a_mock_model() {
        struct EmptyModel;
        #[async_trait]
        impl crate::llm::LlmCaller for EmptyModel {
            async fn complete(&self, _: &str) -> crate::llm::Result<String> {
                Ok("[]".into())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        let auditor = EngineAuditor {
            home: home.path().into(),
            finders: vec![crate::llm::ModelHandle {
                id: "mock-model".into(),
                family: "fixture".into(),
                caller: std::sync::Arc::new(EmptyModel),
            }],
            verifiers: vec![],
            poc_models: vec![],
            roster: vec![],
            max_modules: 5,
            poc: false,
            poc_image: crate::sandbox::DEFAULT_POC_IMAGE.into(),
        };
        let report = run_hunt(
            dir.path(),
            &HuntOptions::default(),
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &auditor,
        )
        .await
        .unwrap();
        let dep = &report.audited[0];
        assert!(dep.has_completed_audit());
        assert_eq!(dep.audit_evidence.coverage.len(), 1);
        assert_eq!(dep.audit_evidence.coverage[0].scope_paths, vec!["lib.rs"]);
        assert_eq!(
            dep.audit_evidence.coverage[0].attempts[0].model,
            "mock-model"
        );
        assert_eq!(
            dep.audit_evidence.coverage[0].attempts[0].files[0].submitted_bytes,
            8
        );
        assert_eq!(dep.osv.status, OsvStatus::Unmatched);
        assert_eq!(report.run_status, Some(RunStatus::Complete));
        if let Some(output) = std::env::var_os("VETTALON_HUNT_ARTIFACT_DIR") {
            std::fs::create_dir_all(&output).unwrap();
            std::fs::write(
                std::path::PathBuf::from(output).join("complete-child-ledger.json"),
                serde_json::to_string_pretty(&report).unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn legacy_custom_auditor_without_child_evidence_stays_unknown() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        let report = run_hunt(
            dir.path(),
            &HuntOptions::default(),
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &LegacyAuditor,
        )
        .await
        .unwrap();
        assert!(!report.audited[0].has_completed_audit());
        assert_eq!(report.audited[0].audit.status, StageStatus::Unknown);
        assert!(report.audited[0].audit_evidence.run_status.is_none());
        assert_eq!(report.run_status, Some(RunStatus::Incomplete));
    }

    struct FailedOsv;
    #[async_trait]
    impl OsvClient for FailedOsv {
        async fn known_vulns(&self, _: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
            Err("network unavailable".into())
        }
    }

    #[tokio::test]
    async fn failed_advisory_query_never_becomes_a_novel_candidate() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        let report = run_hunt(
            dir.path(),
            &HuntOptions::default(),
            &FailedOsv,
            &FakeFetcher,
            &FakeAuditor,
        )
        .await
        .unwrap();
        assert!(
            report.audited[0].has_completed_audit(),
            "the source audit can still finish"
        );
        assert_eq!(report.audited[0].findings.len(), 1);
        assert_eq!(report.audited[0].osv.status, OsvStatus::Failed);
        assert!(report.audited[0].osv.error.is_some());
        assert!(report.novel_candidates().is_empty());
        assert!(
            disclosure_plan(
                &report,
                chrono::NaiveDate::from_ymd_opt(2026, 10, 16).unwrap()
            )
            .is_empty()
        );
        assert_eq!(report.run_status, Some(RunStatus::Incomplete));
        assert!(
            report
                .incomplete_reasons
                .iter()
                .any(|r| r == "advisory_query_unknown")
        );
    }

    struct FailedFetcher;
    #[async_trait]
    impl SourceFetcher for FailedFetcher {
        async fn fetch_into(
            &self,
            _: &DependencyTarget,
            _: &Path,
        ) -> Result<super::super::fetch::ExtractStats, String> {
            Err("registry unavailable".into())
        }
    }

    #[tokio::test]
    async fn fetch_failure_records_stage_and_never_calls_auditor() {
        let row = adv("good", true, &[]);
        let dep = audit_within_timeout(
            &row,
            std::time::Duration::from_secs(1),
            &FailedFetcher,
            &IncompleteAuditor,
        )
        .await;
        assert_eq!(dep.fetch.status, StageStatus::Failed);
        assert_eq!(dep.audit.status, StageStatus::NotStarted);
        assert!(!dep.audited);
        assert!(dep.audit_evidence.run_status.is_none());
    }

    #[test]
    fn legacy_dependency_json_does_not_acquire_new_query_or_audit_proof() {
        let raw = r#"{"target":{"ecosystem":"cargo","name":"legacy","version":"1.0.0","direct":true},"known":[],"audited":true,"error":null,"upstream":{"github":null,"security_emails":[]},"findings":[]}"#;
        let dep: DependencyHunt = serde_json::from_str(raw).unwrap();
        assert_eq!(dep.osv.status, OsvStatus::Unknown);
        assert_eq!(dep.audit.status, StageStatus::Unknown);
        assert!(!dep.has_completed_audit());
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

    #[tokio::test]
    async fn disclosure_drafts_only_for_eligible_novelty_candidates() {
        let mut nh = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "SQLi in query builder",
            "src/db.rs",
            Some(10),
            "s",
            "ai-audit/sql_injection",
            vec![crate::audit::schema::EvidenceItem {
                kind: crate::audit::schema::EvidenceKind::AdversarialReview,
                source: "verifier".into(),
                detail: "plausible: unescaped input reaches the query".into(),
                recorded_at: "2026-10-14T00:00:00Z".into(),
            }],
        );
        nh.status = FindingStatus::NeedsHuman;
        let mut nh2 = nh.clone();
        nh2.id = "second-in-same-upstream".into();
        let clean_dep = DependencyHunt {
            osv: OsvEvidence {
                status: OsvStatus::Unmatched,
                ..Default::default()
            },
            fetch: StageEvidence::default(),
            audit: StageEvidence::default(),
            audit_evidence: DependencyAuditEvidence::default(),
            duration_ms: 0,
            target: target("vuln-lib", true),
            known: vec![],
            audited: true,
            error: None,
            upstream: UpstreamInfo {
                github: Some("acme/vuln-lib".into()),
                security_emails: vec![],
                policy_requirements: vec![],
                github_source: None,
            },
            findings: vec![nh, nh2],
            seeds: None,
        };
        // A dependency with a known CVE is NOT a novelty candidate → no draft.
        let known_dep = DependencyHunt {
            osv: OsvEvidence {
                status: OsvStatus::Matched,
                ..Default::default()
            },
            fetch: StageEvidence::default(),
            audit: StageEvidence::default(),
            audit_evidence: DependencyAuditEvidence::default(),
            duration_ms: 0,
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
            seeds: None,
        };
        let report = HuntReport {
            intake: None,
            run_status: None,
            incomplete_reasons: Vec::new(),
            dep_priority: Default::default(),
            priorities: Vec::new(),
            malicious: None,
            budget: None,
            project: "p".into(),
            total_targets: 2,
            audited: vec![clean_dep, known_dep],
            skipped: vec![],
        };
        let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 14).unwrap();
        let home = tempfile::tempdir().unwrap();
        let reviewer =
            crate::disclose::Reviewer::resolve(Some("night-owl"), None, None, today).unwrap();
        let mut opts = crate::disclose::DraftOptions::new(reviewer, home.path());
        // Refuter-only evidence: nothing by default, only with --allow-unproven.
        let (drafts, skipped) = disclosure_drafts(&report, today, &opts, None).await;
        assert!(drafts.is_empty());
        assert!(
            skipped
                .iter()
                .all(|s| s.reason.contains("--allow-unproven"))
        );
        opts.allow_unproven = true;
        let (drafts, skipped) = disclosure_drafts(&report, today, &opts, None).await;
        assert_eq!(drafts.len(), 1, "one draft per upstream per run");
        assert_eq!(drafts[0].dependency, "vuln-lib@1.0.0");
        assert!(drafts[0].package.unproven);
        assert!(drafts[0].package.draft.body.starts_with("!!! UNPROVEN"));
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].reason.contains("--force-throttle"));
        let scope = drafts[0].package.dependency_scope.as_ref().unwrap();
        assert_eq!(scope.host_project, "p");
        assert_eq!(
            scope.host_reachability,
            crate::disclose::Reachability::Unknown
        );
        assert_eq!(disclosure_plan(&report, today).len(), 2);

        // The UI's per-candidate package: same eligibility, plus channels and
        // the pre-send checklist; GitHub upstream ranks the advisory first.
        let fid = drafts[0].finding_id.clone();
        let pkg = disclosure_package(&report, "vuln-lib@1.0.0", &fid, None, today, &opts, None)
            .await
            .unwrap();
        assert_eq!(pkg.finding_id, fid);
        assert_eq!(
            pkg.channels[0].channel,
            crate::disclose::Channel::GithubAdvisory
        );
        assert!(!pkg.checklist.is_empty());
        // A known-CVE dependency's finding, or a wrong dependency, is refused.
        let known_id = report.audited[1].findings[0].id.clone();
        assert!(
            disclosure_package(&report, "known@1.0.0", &known_id, None, today, &opts, None)
                .await
                .is_err()
        );
        assert!(
            disclosure_package(&report, "other@1.0.0", &fid, None, today, &opts, None)
                .await
                .is_err()
        );
    }

    #[test]
    fn load_hunt_report_round_trips_and_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let report = HuntReport {
            intake: None,
            run_status: None,
            incomplete_reasons: Vec::new(),
            dep_priority: Default::default(),
            priorities: Vec::new(),
            malicious: None,
            budget: None,
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

    #[tokio::test]
    async fn malformed_intake_is_not_complete_zero_and_dry_run_is_visible() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "[ broken =").unwrap();
        let opts = HuntOptions::default();
        let plan = plan_hunt(dir.path(), &opts, &FakeOsv(HashMap::new()))
            .await
            .unwrap();
        assert!(render_plan(&plan).to_ascii_lowercase().contains("intake"));
        let report = run_hunt(
            dir.path(),
            &opts,
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &FakeAuditor,
        )
        .await
        .unwrap();
        assert_eq!(report.run_status, Some(RunStatus::Incomplete));
        assert!(
            report
                .incomplete_reasons
                .iter()
                .any(|v| v == "dependency_intake_incomplete")
        );
        assert_eq!(report.total_targets, 0);
    }

    #[tokio::test]
    async fn mixed_intake_audits_valid_targets_but_scope_stays_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "[ broken =").unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "flask==2.3.3\n").unwrap();
        let report = run_hunt(
            dir.path(),
            &HuntOptions::default(),
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &FakeAuditor,
        )
        .await
        .unwrap();
        assert_eq!(report.total_targets, 1);
        assert_eq!(report.audited.len(), 1);
        assert_eq!(report.run_status, Some(RunStatus::Incomplete));
        assert!(!report.has_complete_scope_evidence());
        let mut forged = report;
        forged.run_status = Some(RunStatus::Complete);
        assert!(!forged.has_complete_scope_evidence());
        let path = dir.path().join("forged.json");
        std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(load_hunt_report(&path).is_err());
        let mut json = serde_json::to_value(&forged).unwrap();
        json.as_object_mut().unwrap().remove("intake");
        let legacy: HuntReport = serde_json::from_value(json).unwrap();
        assert!(legacy.intake.is_none());
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(load_hunt_report(&path).unwrap().intake.is_none());
        assert!(!legacy.has_complete_scope_evidence());
    }

    #[tokio::test]
    async fn unknown_directness_is_typed_skip_and_not_audited() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "version=3\n[[package]]\nname='dep'\nversion='1.0.0'\nsource='registry+https://example.invalid'\n").unwrap();
        let plan = plan_hunt(
            dir.path(),
            &HuntOptions::default(),
            &FakeOsv(HashMap::new()),
        )
        .await
        .unwrap();
        assert!(plan.selected.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].reason, SkipReason::DirectnessUnknown);
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
        assert_eq!(report.audited[0].fetch.status, StageStatus::Succeeded);
        assert_eq!(report.audited[0].fetch.files, Some(1));
        assert_eq!(report.audited[0].audit.status, StageStatus::TimedOut);
        assert!(report.audited[0].audit_evidence.run_status.is_none());
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
    async fn fixed_budget_is_recorded_per_dependency() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        let report = run_hunt(
            dir.path(),
            &HuntOptions::default(),
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &FakeAuditor,
        )
        .await
        .unwrap();
        let b = report.budget.expect("budget record");
        assert_eq!(b.mode, "fixed");
        assert_eq!(b.total_secs, None);
        assert_eq!(b.dep_cap_secs, Some(300));
        assert_eq!(b.deferred, 0);
        assert_eq!(b.allocations.len(), 1);
        assert_eq!(b.allocations[0].name, "good");
        assert_eq!(b.allocations[0].granted_secs, Some(300));
    }

    #[tokio::test]
    async fn rollover_budget_grants_shares_and_records_them() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project_with(dir.path(), &["a", "b", "c"]);
        let opts = HuntOptions {
            dep_concurrency: 1,
            rollover: Some(crate::budget::RolloverBudget {
                total: std::time::Duration::from_secs(600),
                cap: None,
            }),
            ..Default::default()
        };
        let report = run_hunt(
            dir.path(),
            &opts,
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &FakeAuditor,
        )
        .await
        .unwrap();
        let b = report.budget.clone().expect("budget record");
        assert_eq!(b.mode, "rollover");
        assert_eq!(b.total_secs, Some(600));
        assert_eq!(b.deferred, 0);
        let granted: Vec<Option<u64>> = b.allocations.iter().map(|a| a.granted_secs).collect();
        // Each dependency finishes almost at once, so nearly all of its share
        // rolls forward: 600/3, then ~600/2, then ~600.
        assert_eq!(granted[0], Some(200));
        assert!(granted[1].unwrap() >= 299, "{granted:?}");
        assert!(granted[2].unwrap() >= 598, "{granted:?}");
        assert!(report.audited.iter().all(|d| d.audited));
        assert!(
            !report
                .incomplete_reasons
                .contains(&"hunt_time_budget_exhausted".to_string())
        );
    }

    #[tokio::test]
    async fn rollover_budget_that_cannot_fund_a_dependency_defers_it() {
        let dir = tempfile::tempdir().unwrap();
        write_cargo_project(dir.path());
        // A per-dependency cap below the 90 s minimum: nothing can be funded.
        // (The CLI rejects this at startup; the library still fails safe.)
        let opts = HuntOptions {
            rollover: Some(crate::budget::RolloverBudget {
                total: std::time::Duration::from_secs(600),
                cap: Some(std::time::Duration::from_secs(10)),
            }),
            ..Default::default()
        };
        let report = run_hunt(
            dir.path(),
            &opts,
            &FakeOsv(HashMap::new()),
            &FakeFetcher,
            &FakeAuditor,
        )
        .await
        .unwrap();
        let dep = &report.audited[0];
        assert!(!dep.audited);
        assert_eq!(dep.fetch.status, StageStatus::NotStarted);
        assert_eq!(dep.error.as_deref(), Some(DEFERRED_FOR_BUDGET));
        let b = report.budget.as_ref().unwrap();
        assert_eq!(b.deferred, 1);
        assert!(b.allocations[0].deferred);
        assert_eq!(b.allocations[0].granted_secs, None);
        assert_eq!(report.run_status, Some(RunStatus::Incomplete));
        assert!(
            report
                .incomplete_reasons
                .contains(&"hunt_time_budget_exhausted".to_string())
        );
        // The record round-trips through JSON (the report a GUI reads).
        let json = serde_json::to_string(&report).unwrap();
        let back: HuntReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.budget, report.budget);
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
        async fn audit_with_evidence(&self, dir: &Path) -> Result<DirAuditResult, String> {
            Ok(DirAuditResult {
                findings: self.audit(dir).await?,
                evidence: DependencyAuditEvidence {
                    run_status: Some(RunStatus::Complete),
                    ..Default::default()
                },
            })
        }
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

    /// `--malicious-signals` results never become disclosure drafts: they
    /// live in `report.malicious` (not in any dependency's findings), and a
    /// hand-edited report that smuggles one into the findings is refused by
    /// the drafting gate before anything is recorded.
    #[tokio::test]
    async fn malicious_signal_findings_never_become_disclosure_drafts() {
        use super::super::malicious::{
            MaliciousFinding, MaliciousReport, MaliciousStatus, Signal, SignalKind, Strength,
        };
        let evil = target("evil-pkg", true);
        let mut smuggled = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::Critical,
            "install hook exfiltrates env",
            "package.json",
            Some(1),
            "s",
            crate::disclose::eligibility::MALICIOUS_SIGNAL_KIND,
            vec![crate::audit::schema::EvidenceItem {
                kind: crate::audit::schema::EvidenceKind::AdversarialReview,
                source: "verifier".into(),
                detail: "plausible: hook runs on install".into(),
                recorded_at: "2026-10-20T00:00:00Z".into(),
            }],
        );
        smuggled.id = "smuggled".into();
        smuggled.status = FindingStatus::NeedsHuman;
        let dep = DependencyHunt {
            osv: OsvEvidence {
                status: OsvStatus::Unmatched,
                ..Default::default()
            },
            fetch: StageEvidence::default(),
            audit: StageEvidence::default(),
            audit_evidence: DependencyAuditEvidence::default(),
            duration_ms: 0,
            target: evil.clone(),
            known: vec![],
            audited: true,
            error: None,
            upstream: UpstreamInfo {
                github: Some("evil/evil-pkg".into()),
                security_emails: vec![],
                policy_requirements: vec![],
                github_source: None,
            },
            findings: vec![smuggled],
            seeds: None,
        };
        let report = HuntReport {
            intake: None,
            run_status: None,
            incomplete_reasons: Vec::new(),
            project: "p".into(),
            total_targets: 1,
            audited: vec![dep],
            skipped: vec![],
            dep_priority: Default::default(),
            priorities: vec![],
            budget: None,
            malicious: Some(MaliciousReport {
                rules: "test".into(),
                cooldown_hours: 72,
                checks: vec![],
                findings: vec![MaliciousFinding {
                    kind: "malicious_package_signal".into(),
                    target: evil,
                    status: MaliciousStatus::NeedsHuman,
                    signals: vec![Signal {
                        kind: SignalKind::MalIdMatch,
                        strength: Strength::Strong,
                        evidence: "MAL-2026-1".into(),
                        source: "osv".into(),
                    }],
                    rationale: "strong rule signal".into(),
                }],
                mal_index: vec![],
                complete: true,
                incomplete_reasons: vec![],
            }),
        };
        let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        let home = tempfile::tempdir().unwrap();
        let reviewer =
            crate::disclose::Reviewer::resolve(Some("night-owl"), None, None, today).unwrap();
        let mut opts = crate::disclose::DraftOptions::new(reviewer, home.path());
        opts.allow_unproven = true;
        opts.force_throttle = Some("test".into());
        let (drafts, skipped) = disclosure_drafts(&report, today, &opts, None).await;
        assert!(drafts.is_empty(), "no draft for a malicious-package signal");
        assert!(
            skipped
                .iter()
                .all(|s| s.reason.contains("malicious-package") || s.reason.contains("惡意套件")),
            "{skipped:?}"
        );
        assert!(disclosure_plan(&report, today).is_empty());
        let err = disclosure_package(
            &report,
            "evil-pkg@1.0.0",
            "smuggled",
            None,
            today,
            &opts,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("malicious-package") || err.contains("惡意套件"),
            "{err}"
        );
        assert!(
            !home
                .path()
                .join(crate::disclose::ledger::LEDGER_FILE)
                .exists(),
            "nothing recorded"
        );
    }

    #[test]
    fn upstream_prefers_the_package_own_manifest_and_go_module_path() {
        use crate::disclose::UpstreamOrigin;
        let write = |dir: &Path, files: &[(&str, &str)]| {
            for (name, body) in files {
                std::fs::write(dir.join(name), body).unwrap();
            }
        };
        // npm package that also ships a Cargo.toml (e.g. a native addon).
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package");
        std::fs::create_dir(&pkg).unwrap();
        write(
            &pkg,
            &[
                (
                    "package.json",
                    r#"{"name":"a","version":"1.0.0","repository":"github:npm-owner/a"}"#,
                ),
                (
                    "Cargo.toml",
                    "[package]\nname = \"a\"\nrepository = \"https://github.com/other/a\"\n",
                ),
            ],
        );
        let mut t = target("a", true);
        t.ecosystem = Ecosystem::Npm;
        let up = detect_upstream(tmp.path(), &t);
        assert_eq!(up.github.as_deref(), Some("npm-owner/a"));
        assert_eq!(
            up.github_source,
            Some(UpstreamOrigin::PackageMetadata {
                file: "package.json".into(),
                field: "repository".into(),
            })
        );

        // Go module zip with a stray package.json: the module path wins, and a
        // major-version suffix still names the repository.
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            &[
                ("go.mod", "module github.com/go-owner/mod/v2\n"),
                (
                    "package.json",
                    r#"{"name":"x","repository":"github:other/x"}"#,
                ),
                ("setup.cfg", "[flake8]\nmax-line-length = 100\n"),
            ],
        );
        let mut t = target("github.com/go-owner/mod/v2", true);
        t.ecosystem = Ecosystem::Go;
        let up = detect_upstream(tmp.path(), &t);
        assert_eq!(up.github.as_deref(), Some("go-owner/mod"));
        assert_eq!(
            up.github_source,
            Some(UpstreamOrigin::PackageMetadata {
                file: "go.mod".into(),
                field: "module path".into(),
            })
        );
    }
}
