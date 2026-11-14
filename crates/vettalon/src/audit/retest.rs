//! `vettalon retest`: re-run the recorded differential PoCs of an old report
//! against a new revision of the same repository.
//!
//! Only findings whose derived evidence level is `poc_differential` and for
//! which the operator supplied a closed [`TargetCall`] are re-run. The old
//! report pins `file_hash` to the old bytes; retest re-binds the finding to
//! the bytes now at the same `target_file` (same path-safety rules as
//! `reproduce`), checks the target function is still declared, and runs the
//! replayed three-phase protocol against the new tree. The old report is
//! only read. `not_observed` means "not observed on this revision with these
//! inputs": it is never a claim that the defect is fixed or the code safe.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::evidence_level::EvidenceLevel;
use super::poc_oracle::{OracleClass, classify_target};
use super::schema::{AuditReport, Finding};
use super::target_poc::{
    self, TargetCall, TargetPocOutcome, TargetPocReceipt, declares_top_level_async_function,
    declares_top_level_function, parse_target_call, read_target_source, validate_replays,
};

/// Current retest report version.
pub const RETEST_REPORT_VERSION: u32 = 1;
/// Upper bound (and default) for `--max-findings`.
pub const MAX_RETEST_FINDINGS: usize = 20;
/// Size cap of the `--targets` plan file.
pub const TARGET_PLANS_MAX_BYTES: usize = 256 * 1024;
/// Upper bound on the containers one retest may start:
/// `replays * max_findings * 3` must not exceed it.
pub const MAX_RETEST_CONTAINERS: u64 = 120;
/// Default wall-clock budget of one retest, in seconds (`--deadline`).
pub const DEFAULT_RETEST_DEADLINE_SECS: u64 = 3600;
/// Upper bound for `--deadline`, in seconds.
pub const MAX_RETEST_DEADLINE_SECS: u64 = 86_400;
/// Reason recorded on findings not run (or cut short) by `--deadline`.
pub const DEADLINE_EXCEEDED: &str = "deadline_exceeded";

/// Exit code: at least one finding ran and every run finding is
/// `not_observed`, with nothing missing, capped or inconclusive.
pub const EXIT_NOT_OBSERVED: i32 = 0;
/// Exit code: some finding is `still_observed`.
pub const EXIT_STILL_OBSERVED: i32 = 1;
/// Exit code: some finding is `inconclusive` / `environment_unavailable`,
/// or the run was refused (hard error).
pub const EXIT_INCONCLUSIVE: i32 = 2;
/// Exit code: nothing ran, or some finding is `target_missing` /
/// `retest_cap_reached` (including `deadline_exceeded`).
pub const EXIT_INCOMPLETE: i32 = 3;

/// Aggregate reasons that say the sandbox could not give a result, not that
/// the target behaved one way or another.
const ENVIRONMENT_REASONS: &[&str] = &[
    "node_runtime_unavailable",
    "node_lockfile_missing",
    "node_lockfile_refused",
    "node_deps_install_failed",
    "node_deps_too_large",
    "sql_dialect_not_executable",
    "ssrf_listener_unavailable",
    "sandbox_unavailable",
    "invalid_image_identity",
    "incomplete_sandbox_capture",
    "target_poc_budget_exhausted",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetestStatus {
    /// Every replay observed the effect on the new revision.
    StillObserved,
    /// Every replay ran and none observed the effect. Not proof of a fix.
    NotObserved,
    /// Replays ran but disagreed or did not yield a differential result.
    Inconclusive,
    /// The sandbox could not run or capture the replays.
    EnvironmentUnavailable,
    /// The target file or the target function is gone on the new revision.
    TargetMissing,
    /// Not a re-runnable differential PoC in the old report (or no plan).
    NotReproducibleBefore,
    /// Eligible, but beyond `--max-findings`; not run.
    RetestCapReached,
}

impl RetestStatus {
    pub const ALL: [RetestStatus; 7] = [
        Self::StillObserved,
        Self::NotObserved,
        Self::Inconclusive,
        Self::EnvironmentUnavailable,
        Self::TargetMissing,
        Self::NotReproducibleBefore,
        Self::RetestCapReached,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::StillObserved => "still_observed",
            Self::NotObserved => "not_observed",
            Self::Inconclusive => "inconclusive",
            Self::EnvironmentUnavailable => "environment_unavailable",
            Self::TargetMissing => "target_missing",
            Self::NotReproducibleBefore => "not_reproducible_before",
            Self::RetestCapReached => "retest_cap_reached",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetestResult {
    pub finding_id: String,
    pub title: String,
    pub cwe: Option<String>,
    pub status: RetestStatus,
    pub reason: Option<String>,
    /// `file_hash` pinned by the old report.
    pub old_file_sha256: Option<String>,
    /// Hash of the bytes now at the same path; `None` when not read.
    pub new_file_sha256: Option<String>,
    /// True when the finding was re-bound to different bytes.
    pub rebound: bool,
    pub receipt: Option<TargetPocReceipt>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetestSummary {
    pub still_observed: usize,
    pub not_observed: usize,
    pub inconclusive: usize,
    pub environment_unavailable: usize,
    pub target_missing: usize,
    pub not_reproducible_before: usize,
    pub retest_cap_reached: usize,
}

impl RetestSummary {
    pub fn from_results(results: &[RetestResult]) -> Self {
        let mut summary = Self::default();
        for result in results {
            let slot = match result.status {
                RetestStatus::StillObserved => &mut summary.still_observed,
                RetestStatus::NotObserved => &mut summary.not_observed,
                RetestStatus::Inconclusive => &mut summary.inconclusive,
                RetestStatus::EnvironmentUnavailable => &mut summary.environment_unavailable,
                RetestStatus::TargetMissing => &mut summary.target_missing,
                RetestStatus::NotReproducibleBefore => &mut summary.not_reproducible_before,
                RetestStatus::RetestCapReached => &mut summary.retest_cap_reached,
            };
            *slot += 1;
        }
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetestReport {
    pub version: u32,
    pub repo: String,
    pub old_report_sha256: String,
    pub old_repo_commit: Option<String>,
    pub new_repo_commit: Option<String>,
    /// `None` when Git state is unavailable or index flags can hide edits.
    pub new_tree_clean: Option<bool>,
    pub replays: u32,
    pub results: Vec<RetestResult>,
    pub summary: RetestSummary,
}

/// Shared validation failure; package loading preserves the missing-receipt token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetestStateError {
    MissingReceipt,
    InvalidReportHash,
    InvalidRevision(&'static str),
    FileHashMismatch(String),
    DuplicateFinding(String),
    InvalidFindingId(String),
    InvalidField(String),
    Invalid(String),
}

impl std::fmt::Display for RetestStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingReceipt => f.write_str("retest run status carries no receipt"),
            Self::InvalidReportHash => {
                f.write_str("old_report_sha256 is not a lowercase hex sha256")
            }
            Self::InvalidRevision(field) => write!(f, "{field} is not a full hex object id"),
            Self::FileHashMismatch(message)
            | Self::DuplicateFinding(message)
            | Self::InvalidFindingId(message)
            | Self::InvalidField(message)
            | Self::Invalid(message) => f.write_str(message),
        }
    }
}

/// Re-derive the outer state from validated receipts, or the generator's
/// pre-execution reasons. A deadline marker alone cannot relabel a complete run.
/// Returns each validated receipt's oracle class, or None for receipt-less rows.
pub fn validate_retest_state(
    report: &RetestReport,
) -> Result<Vec<Option<OracleClass>>, RetestStateError> {
    use RetestStateError::{Invalid, MissingReceipt};
    if report.version != RETEST_REPORT_VERSION {
        return Err(Invalid("unsupported retest report version".into()));
    }
    if !super::verification_context::is_sha256(&report.old_report_sha256) {
        return Err(RetestStateError::InvalidReportHash);
    }
    for (field, commit) in [
        ("old_repo_commit", &report.old_repo_commit),
        ("new_repo_commit", &report.new_repo_commit),
    ] {
        if commit.as_deref().is_some_and(|value| {
            !matches!(value.len(), 40 | 64)
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(RetestStateError::InvalidRevision(field));
        }
    }
    validate_replays(report.replays).map_err(|e| Invalid(e.into()))?;
    if report.summary != RetestSummary::from_results(&report.results) {
        return Err(Invalid(
            "the retest summary does not match its results".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut classes = Vec::with_capacity(report.results.len());
    for result in &report.results {
        use super::receipt_fields::{
            check_finding_id, check_hash, check_receipt_fields, check_token,
        };
        check_finding_id(&result.finding_id).map_err(RetestStateError::InvalidFindingId)?;
        if !seen.insert(&result.finding_id) {
            return Err(RetestStateError::DuplicateFinding(format!(
                "two retest results name finding {:?}",
                result.finding_id
            )));
        }
        check_token(result.reason.as_deref(), "retest reason")
            .map_err(RetestStateError::InvalidField)?;
        let old_hash = result
            .old_file_sha256
            .as_deref()
            .map(|hash| hash.trim().to_ascii_lowercase());
        check_hash(old_hash.as_deref(), "old_file_sha256")
            .map_err(RetestStateError::InvalidField)?;
        check_hash(result.new_file_sha256.as_deref(), "new_file_sha256")
            .map_err(RetestStateError::InvalidField)?;
        // Match retest_one exactly: no new bytes means no rebind; otherwise
        // compare the recorded old hash verbatim, including an absent old hash.
        let rebound = result
            .new_file_sha256
            .as_deref()
            .is_some_and(|new| result.old_file_sha256.as_deref() != Some(new));
        if result.rebound != rebound {
            return Err(RetestStateError::FileHashMismatch(
                "retest rebound flag disagrees with its old and new file hashes".into(),
            ));
        }
        let (status, reason) = if let Some(receipt) = &result.receipt {
            check_receipt_fields(receipt, "retest receipt")
                .map_err(RetestStateError::InvalidField)?;
            // validate_stored also compares the receipt's file and function
            // with the canonical verification-event subject. RetestResult has
            // no separate target fields.
            let (outcome, reason, class) =
                receipt.validate_stored_with_class(None).map_err(Invalid)?;
            classes.push(class);
            let event = receipt.verification_event.as_ref().ok_or_else(|| {
                Invalid("retest receipt has no verification event binding its finding id".into())
            })?;
            if event.ir.binding.finding_id != result.finding_id {
                return Err(Invalid(
                    "retest finding and verification event identities disagree".into(),
                ));
            }
            if result.new_file_sha256 != receipt.target_file_sha256 {
                return Err(RetestStateError::FileHashMismatch(
                    "retest new_file_sha256 is not its receipt's target_file_sha256".into(),
                ));
            }
            let summary = receipt.replay_summary();
            if summary.requested != report.replays {
                return Err(Invalid(
                    "retest replays differ from receipt requested replays".into(),
                ));
            }
            if receipt.reason.as_deref() == Some(DEADLINE_EXCEEDED) {
                // The generator records this only before the first replay or
                // between replays; every retained run must have finished.
                if outcome != TargetPocOutcome::Inconclusive
                    || summary.completed >= summary.requested
                    || summary.runs.len() != summary.completed as usize
                    || !matches!(
                        reason.as_deref(),
                        Some("replay_incomplete" | DEADLINE_EXCEEDED)
                    )
                {
                    return Err(Invalid(
                        "deadline receipt does not prove an interrupted replay sequence".into(),
                    ));
                }
                (
                    RetestStatus::RetestCapReached,
                    Some(DEADLINE_EXCEEDED.to_owned()),
                )
            } else {
                (status_for(outcome, reason.as_deref()), reason)
            }
        } else {
            classes.push(None);
            if matches!(
                result.status,
                RetestStatus::StillObserved | RetestStatus::NotObserved
            ) {
                return Err(MissingReceipt);
            }
            let status = match result.reason.as_deref() {
                Some("retest_cap_reached" | DEADLINE_EXCEEDED) => RetestStatus::RetestCapReached,
                Some("target_file_missing" | "function_not_declared" | "target_missing") => {
                    RetestStatus::TargetMissing
                }
                Some(
                    "unsafe_target_path"
                    | "source_changed_during_read"
                    | "target_source_not_utf8"
                    | "async_target_unsupported"
                    | "unbound_receipt",
                ) => RetestStatus::Inconclusive,
                Some(
                    "no_target_plan"
                    | "target_plan_file_mismatch"
                    | "unsupported_oracle_class"
                    | "evidence_level_static_only"
                    | "evidence_level_refuter_survived"
                    | "evidence_level_refuter_consistent"
                    | "evidence_level_poc_effect_no_control"
                    | "evidence_level_maintainer_confirmed",
                ) => RetestStatus::NotReproducibleBefore,
                Some(reason) if ENVIRONMENT_REASONS.contains(&reason) => {
                    RetestStatus::EnvironmentUnavailable
                }
                _ => return Err(Invalid("unsupported receipt-less retest reason".into())),
            };
            (status, result.reason.clone())
        };
        if result.status != status || result.reason != reason {
            return Err(Invalid(
                "retest status or reason disagrees with its receipt/state".into(),
            ));
        }
    }
    Ok(classes)
}

impl RetestReport {
    /// See [`exit_code_for`].
    pub fn exit_code(&self) -> i32 {
        exit_code_for(&self.summary)
    }
}

/// Fail-closed exit code, first match wins:
/// 1 any `still_observed`; 2 any `inconclusive` / `environment_unavailable`;
/// 3 nothing ran, or any `target_missing` / `retest_cap_reached`;
/// 0 otherwise (at least one ran and every run finding is `not_observed`).
/// `not_reproducible_before` (no plan) never yields 0 on its own; a plan for
/// a finding that cannot be re-run is refused before the run (exit 2).
pub fn exit_code_for(summary: &RetestSummary) -> i32 {
    let ran = summary.still_observed
        + summary.not_observed
        + summary.inconclusive
        + summary.environment_unavailable;
    if summary.still_observed > 0 {
        EXIT_STILL_OBSERVED
    } else if summary.inconclusive > 0 || summary.environment_unavailable > 0 {
        EXIT_INCONCLUSIVE
    } else if ran == 0 || summary.target_missing > 0 || summary.retest_cap_reached > 0 {
        EXIT_INCOMPLETE
    } else {
        EXIT_NOT_OBSERVED
    }
}

/// Refuse limits outside their ranges, and a run that could start more than
/// [`MAX_RETEST_CONTAINERS`] containers (`replays * max_findings * 3`).
pub fn validate_limits(
    replays: u32,
    max_findings: usize,
    deadline_secs: u64,
) -> Result<(), String> {
    validate_replays(replays).map_err(|reason| format!("--replays refused: {reason}"))?;
    if !(1..=MAX_RETEST_FINDINGS).contains(&max_findings) {
        return Err(format!(
            "--max-findings must be between 1 and {MAX_RETEST_FINDINGS}"
        ));
    }
    if !(1..=MAX_RETEST_DEADLINE_SECS).contains(&deadline_secs) {
        return Err(format!(
            "--deadline must be between 1 and {MAX_RETEST_DEADLINE_SECS} seconds"
        ));
    }
    let containers = u64::from(replays) * max_findings as u64 * 3;
    if containers > MAX_RETEST_CONTAINERS {
        return Err(format!(
            "--replays {replays} x --max-findings {max_findings} x 3 containers = {containers} \
             exceeds the retest cap of {MAX_RETEST_CONTAINERS} containers; lower --replays or \
             --max-findings"
        ));
    }
    Ok(())
}

/// Old-report text (ids, titles, paths) made safe for a terminal: control,
/// escape and other non-printable characters are shown escaped.
pub fn terminal_safe(text: &str) -> String {
    text.chars().flat_map(char::escape_debug).collect()
}

/// Map an aggregate reproduce outcome (and its reason) to a retest status.
pub fn status_for(outcome: TargetPocOutcome, reason: Option<&str>) -> RetestStatus {
    match outcome {
        TargetPocOutcome::EffectObserved => RetestStatus::StillObserved,
        TargetPocOutcome::EffectAbsent => RetestStatus::NotObserved,
        TargetPocOutcome::Inconclusive
            if reason.is_some_and(|reason| ENVIRONMENT_REASONS.contains(&reason)) =>
        {
            RetestStatus::EnvironmentUnavailable
        }
        TargetPocOutcome::Inconclusive if reason == Some("target_missing") => {
            RetestStatus::TargetMissing
        }
        TargetPocOutcome::Inconclusive => RetestStatus::Inconclusive,
    }
}

/// The old report as read: never written back.
#[derive(Debug, Clone)]
pub struct OldReport {
    pub path: PathBuf,
    pub report: AuditReport,
    /// SHA-256 of the exact bytes read.
    pub sha256: String,
}

/// Load the old report (`--report`, else the newest baseline the
/// `--since-last` rules trust) and require that `repo` is its repository.
/// Returns the canonical repository path.
pub async fn load_old_report(
    repo: &Path,
    report: Option<&Path>,
    home: &Path,
) -> Result<(PathBuf, OldReport), String> {
    let old = match report {
        Some(path) => {
            let (report, sha256) = super::load_report_for_delivery_with_sha256(path)?;
            require_full_commit(&report)?;
            OldReport {
                path: path.to_path_buf(),
                report,
                sha256,
            }
        }
        None => {
            let root = std::fs::canonicalize(repo)
                .map_err(|e| format!("cannot resolve repository {}: {e}", repo.display()))?;
            let baseline = super::since_last::select_baseline(home, &root).await?;
            OldReport {
                path: baseline.path,
                report: baseline.report,
                sha256: baseline.sha256,
            }
        }
    };
    let repo = crate::remediation::check_report_repository(repo, &old.report)?;
    Ok((repo, old))
}

/// An explicit `--report` must carry the same full hex `repo_commit` an
/// automatically selected baseline needs.
pub(crate) fn require_full_commit(report: &AuditReport) -> Result<(), String> {
    if super::since_last::is_full_hex_oid(report.repo_commit.as_deref()) {
        Ok(())
    } else {
        Err("old report refused: repo_commit is not a full hex OID".into())
    }
}

/// Parse the closed `--targets` file: a JSON object mapping exact finding
/// ids to the same TargetCall JSON `reproduce --target` accepts.
pub fn parse_target_plans(raw: &str) -> Result<BTreeMap<String, TargetCall>, String> {
    let entries: BTreeMap<String, serde_json::Value> =
        vettalon_contract::strict_json::parse_strict_with_limit(raw, TARGET_PLANS_MAX_BYTES)
            .map_err(|_| "target plans must be a JSON object of finding id -> TargetCall")?;
    entries
        .into_iter()
        .map(|(id, value)| {
            let call = parse_target_call(&value.to_string())
                .map_err(|reason| format!("target plan for {id:?} refused: {reason}"))?;
            Ok((id, call))
        })
        .collect()
}

/// Read and parse `--targets` with the remediation input protections.
pub fn read_target_plans(path: &Path) -> Result<BTreeMap<String, TargetCall>, String> {
    let raw = crate::remediation::read_regular_capped(
        path,
        TARGET_PLANS_MAX_BYTES as u64,
        "target plans",
    )?;
    parse_target_plans(&raw)
}

/// How one finding of the old report is re-run.
#[async_trait::async_trait]
pub(crate) trait RetestRunner: Send + Sync {
    async fn run(
        &self,
        repo: &Path,
        finding: &Finding,
        call: &TargetCall,
        replays: u32,
        deadline: Instant,
    ) -> TargetPocReceipt;
}

struct DockerRunner<'a> {
    image: &'a str,
    node: &'a super::node::dispatch::NodeOptions,
    python_session: tokio::sync::OnceCell<Result<target_poc::DockerTargetSandbox, String>>,
    node_session: tokio::sync::OnceCell<Result<target_poc::DockerTargetSandbox, String>>,
}

#[async_trait::async_trait]
impl RetestRunner for DockerRunner<'_> {
    async fn run(
        &self,
        repo: &Path,
        finding: &Finding,
        call: &TargetCall,
        replays: u32,
        deadline: Instant,
    ) -> TargetPocReceipt {
        let is_node = call.runtime() == Ok(target_poc::Runtime::Node);
        let runner = if is_node {
            self.node_session
                .get_or_init(|| {
                    target_poc::node_docker_sandbox(self.node, MAX_RETEST_CONTAINERS as usize)
                })
                .await
        } else {
            self.python_session
                .get_or_init(|| {
                    target_poc::docker_target_sandbox(self.image, MAX_RETEST_CONTAINERS as usize)
                })
                .await
        };
        match runner {
            Ok(runner) => {
                target_poc::run_replays_until(
                    repo,
                    finding,
                    call,
                    runner,
                    false,
                    replays,
                    Some(deadline),
                )
                .await
                .receipt
            }
            Err(_) => {
                target_poc::refused_with(
                    call,
                    if is_node {
                        "node_runtime_unavailable"
                    } else {
                        "sandbox_unavailable"
                    },
                    false,
                    replays,
                )
                .receipt
            }
        }
    }
}

/// Re-run the eligible findings of `old` against the tree at `repo`
/// (canonical, already checked to be the report's repository).
pub async fn run_retest(
    repo: &Path,
    old: &OldReport,
    plans: &BTreeMap<String, TargetCall>,
    poc_image: &str,
    replays: u32,
    max_findings: usize,
    deadline_secs: u64,
) -> Result<RetestReport, String> {
    run_retest_with_node(
        repo,
        old,
        plans,
        poc_image,
        replays,
        max_findings,
        deadline_secs,
        &super::node::dispatch::NodeOptions {
            image: crate::sandbox::default_node_poc_image().into(),
            fixture: None,
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_retest_with_node(
    repo: &Path,
    old: &OldReport,
    plans: &BTreeMap<String, TargetCall>,
    poc_image: &str,
    replays: u32,
    max_findings: usize,
    deadline_secs: u64,
    node: &super::node::dispatch::NodeOptions,
) -> Result<RetestReport, String> {
    validate_limits(replays, max_findings, deadline_secs)?;
    let runner = DockerRunner {
        image: poc_image,
        node,
        python_session: Default::default(),
        node_session: Default::default(),
    };
    let deadline = Instant::now() + Duration::from_secs(deadline_secs);
    run_retest_with(repo, old, plans, &runner, replays, max_findings, deadline).await
}

/// Testable core. `deadline` is checked before each finding and, inside the
/// runner, before each replay; findings it stops get `retest_cap_reached`
/// with reason `deadline_exceeded`.
pub(crate) async fn run_retest_with<R: RetestRunner>(
    repo: &Path,
    old: &OldReport,
    plans: &BTreeMap<String, TargetCall>,
    runner: &R,
    replays: u32,
    max_findings: usize,
    deadline: Instant,
) -> Result<RetestReport, String> {
    validate_limits(replays, max_findings, DEFAULT_RETEST_DEADLINE_SECS)?;
    check_plans(old, plans)?;
    let state = super::diff_scope::repo_state(repo).await.ok();
    let mut results = Vec::with_capacity(old.report.findings.len());
    let mut selected = 0usize;
    for finding in &old.report.findings {
        let call = match eligibility(finding, plans.get(&finding.id)) {
            Ok(call) => call,
            Err(reason) => {
                results.push(skipped(
                    finding,
                    RetestStatus::NotReproducibleBefore,
                    reason,
                ));
                continue;
            }
        };
        if selected >= max_findings {
            results.push(skipped(
                finding,
                RetestStatus::RetestCapReached,
                "retest_cap_reached".into(),
            ));
            continue;
        }
        if Instant::now() >= deadline {
            results.push(skipped(
                finding,
                RetestStatus::RetestCapReached,
                DEADLINE_EXCEEDED.into(),
            ));
            continue;
        }
        selected += 1;
        results.push(retest_one(repo, finding, call, runner, replays, deadline).await);
    }
    let summary = RetestSummary::from_results(&results);
    let report = RetestReport {
        version: RETEST_REPORT_VERSION,
        repo: repo.to_string_lossy().into_owned(),
        old_report_sha256: old.sha256.clone(),
        old_repo_commit: old.report.repo_commit.clone(),
        new_repo_commit: state.as_ref().map(|state| state.commit.clone()),
        new_tree_clean: state.and_then(|state| state.clean),
        replays,
        results,
        summary,
    };
    validate_retest_state(&report).map_err(|e| e.to_string())?;
    Ok(report)
}

/// Every plan must name a finding of the old report that can be re-run: a
/// recorded differential PoC, the plan's file equal to the finding's file,
/// and a supported oracle class. Anything else refuses the whole run, so a
/// plan can never be silently skipped.
fn check_plans(old: &OldReport, plans: &BTreeMap<String, TargetCall>) -> Result<(), String> {
    for (id, call) in plans {
        let Some(finding) = old.report.findings.iter().find(|f| &f.id == id) else {
            return Err(format!(
                "target plan names finding {id:?}, which is not in the old report"
            ));
        };
        if let Err(reason) = eligibility(finding, Some(call)) {
            return Err(format!("target plan for finding {id:?} refused: {reason}"));
        }
    }
    Ok(())
}

/// A finding is re-run only with a recorded differential PoC, an operator
/// plan for its own file, and a supported oracle class.
fn eligibility<'a>(
    finding: &Finding,
    plan: Option<&'a TargetCall>,
) -> Result<&'a TargetCall, String> {
    let level = finding.evidence_level();
    if level != EvidenceLevel::PocDifferential {
        return Err(format!("evidence_level_{}", level.key()));
    }
    let Some(call) = plan else {
        return Err("no_target_plan".into());
    };
    if call.file != finding.file {
        return Err("target_plan_file_mismatch".into());
    }
    if call
        .runtime()
        .ok()
        .and_then(|runtime| classify_target(finding, runtime))
        .is_none()
    {
        return Err("unsupported_oracle_class".into());
    }
    Ok(call)
}

fn skipped(finding: &Finding, status: RetestStatus, reason: String) -> RetestResult {
    RetestResult {
        finding_id: finding.id.clone(),
        title: finding.title.clone(),
        cwe: finding.cwe.clone(),
        status,
        reason: Some(reason),
        old_file_sha256: finding.file_hash.clone(),
        new_file_sha256: None,
        rebound: false,
        receipt: None,
    }
}

async fn retest_one<R: RetestRunner>(
    repo: &Path,
    finding: &Finding,
    call: &TargetCall,
    runner: &R,
    replays: u32,
    deadline: Instant,
) -> RetestResult {
    let mut result = skipped(finding, RetestStatus::Inconclusive, String::new());
    let (source, new_hash) = match read_target_source(repo, &call.file) {
        Ok(value) => value,
        Err(reason) => {
            if target_absent(repo, &call.file) {
                result.status = RetestStatus::TargetMissing;
                result.reason = Some("target_file_missing".into());
            } else {
                result.reason = Some(reason.into());
            }
            return result;
        }
    };
    result.rebound = finding.file_hash.as_deref() != Some(new_hash.as_str());
    result.new_file_sha256 = Some(new_hash.clone());
    let python = call.runtime() == Ok(target_poc::Runtime::Python);
    if python && declares_top_level_async_function(&source, &call.function) {
        result.reason = Some("async_target_unsupported".into());
        return result;
    }
    if python && !declares_top_level_function(&source, &call.function) {
        result.status = RetestStatus::TargetMissing;
        result.reason = Some("function_not_declared".into());
        return result;
    }
    // Re-bind: the run now pins the bytes just read. If they change before
    // the snapshot, reproduce refuses with `stale_source` (inconclusive).
    let mut rebound = finding.clone();
    rebound.file_hash = Some(new_hash);
    let receipt = runner.run(repo, &rebound, call, replays, deadline).await;
    let (outcome, reason) = receipt.derived_outcome();
    if receipt.reason.as_deref() == Some(DEADLINE_EXCEEDED) {
        // Stopped between replays: the partial receipt is kept, but the
        // finding counts as not (fully) run.
        result.status = RetestStatus::RetestCapReached;
        result.reason = Some(DEADLINE_EXCEEDED.into());
    } else {
        result.status = status_for(outcome, reason.as_deref());
        result.reason = reason;
    }
    if receipt.verification_event.is_some() {
        result.receipt = Some(receipt);
    } else if result.status == RetestStatus::Inconclusive
        || matches!(
            result.status,
            RetestStatus::StillObserved | RetestStatus::NotObserved
        )
    {
        // Pre-execution refusals may have no event. Never embed an unbound
        // receipt as evidence for this finding, or credit an unbound outcome.
        result.status = RetestStatus::Inconclusive;
        result.reason = Some("unbound_receipt".into());
    }
    result
}

/// True only when a component of the (already safe) relative path does not
/// exist. A symlink or other unsafe component is not "missing".
fn target_absent(repo: &Path, file: &str) -> bool {
    let mut path = repo.to_path_buf();
    for part in file.split('/') {
        path.push(part);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => return false,
            Ok(_) => {}
            Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
        }
    }
    false
}

/// Human summary. Never says "fixed".
pub fn render_text(report: &RetestReport) -> String {
    let mut out = String::new();
    for result in &report.results {
        let meaning = match result.status {
            RetestStatus::StillObserved => "effect still observed on this revision",
            RetestStatus::NotObserved => {
                "not observed on this revision with these inputs (not proof of a fix)"
            }
            RetestStatus::Inconclusive => "inconclusive",
            RetestStatus::EnvironmentUnavailable => "sandbox environment unavailable",
            RetestStatus::TargetMissing => "target file or function missing on this revision",
            RetestStatus::NotReproducibleBefore => "no re-runnable differential PoC; not run",
            RetestStatus::RetestCapReached => "over --max-findings or --deadline; not run",
        };
        let reason = result
            .reason
            .as_deref()
            .map(|reason| format!(" ({})", terminal_safe(reason)))
            .unwrap_or_default();
        let rebound = if result.rebound { " [rebound]" } else { "" };
        // Ids come from the old report: never raw to a terminal.
        out.push_str(&format!(
            "  {} {}: {meaning}{reason}{rebound}\n",
            result.status.key(),
            terminal_safe(crate::util::truncate_bytes(&result.finding_id, 16)),
        ));
    }
    let s = &report.summary;
    out.push_str(&format!(
        "  still_observed={} not_observed={} inconclusive={} environment_unavailable={} \
         target_missing={} not_reproducible_before={} retest_cap_reached={}\n",
        s.still_observed,
        s.not_observed,
        s.inconclusive,
        s.environment_unavailable,
        s.target_missing,
        s.not_reproducible_before,
        s.retest_cap_reached,
    ));
    out
}

#[cfg(test)]
#[path = "retest_tests.rs"]
pub(crate) mod tests;
