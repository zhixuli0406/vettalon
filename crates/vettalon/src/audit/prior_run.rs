//! Carry-over from a prior report. On by default; `--no-prior` turns it off.
//!
//! The prior report is the newest file under `<home>/reports/` (by the UTC
//! timestamp in its name, see `report::saved_report_sort_key`)
//! whose `repo` equals the current canonical repo path and whose
//! `schema_version` is supported by this binary. Unparsable and unsupported reports for the
//! same repo are skipped with one stderr line each; the search continues
//! with the next-newest file.
//!
//! Matching is by `root_fingerprint` (semantic identity) AND `file_hash`
//! (the file bytes are unchanged). Rules, applied to every current
//! `Candidate` finding (scanner and ai_audit alike) before adversarial
//! review:
//! - prior `Suppressed`, same hash ⇒ `Suppressed`, evidence
//!   `carried_from_prior: <file>`, zero LLM;
//! - prior `Refuted`, same hash ⇒ `Refuted`, same evidence, and therefore
//!   no verifier call;
//! - prior `Confirmed`, same hash ⇒ stays `Candidate` (re-verified on the
//!   current path), evidence `prior_confirmed_same_source`, counted in
//!   `revalidated_prior_confirmed`;
//! - a fingerprint match whose hash differs (or either hash is missing) ⇒
//!   not carried, counted in `changed_source`.
//!
//! When several prior findings share the fingerprint and the hash, a prior
//! `Confirmed` (or any still-open status) wins over suppression: a prior
//! record may raise attention, never hide something that was not
//! uniformly dismissed. `Suppressed` is carried only when every same-hash
//! match is `Suppressed`; `Refuted` when every match is `Refuted` or
//! `Suppressed`.

//! In deep mode, prior coverage gaps are promoted within the usual module
//! cap. Missing open claims on unchanged, safe source are reopened as fresh
//! Candidates (at most 50); changed/unavailable claims remain display-only.
//! In quick mode, missing open claims are only listed as not re-checked.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::schema::{
    AuditReport, CARRIED_FROM_PRIOR_PREFIX, CURRENT_SCHEMA_VERSION, ChangedUnrediscovered,
    EvidenceItem, EvidenceKind, Finding, FindingStatus, MIN_SUPPORTED_SCHEMA_VERSION,
    ModuleCoverage, ModuleCoverageStatus, PRIOR_CHANGED_PREFIX, PRIOR_CONFIRMED_PREFIX,
    PRIOR_NOT_REDISCOVERED_PREFIX, PriorRunInfo, is_supported_schema_version,
};

/// Reports bigger than this are not read (a corrupted or hostile file must
/// not exhaust memory).
const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum prior-only claims admitted to this run's verifier budget.
pub const MAX_CARRIED_FINDINGS: usize = 50;
const MAX_PRIOR_FINDINGS: usize = 500;
const MAX_HASH_FILES: usize = 200;
/// Bound each untrusted claim as well as the number of verifier inputs.
const MAX_CARRIED_CLAIM_BYTES: usize = 64 * 1024;
/// Per-file hash limit and scan-wide source byte budget shared by current hashes and prior carry.
/// Oversized files are unavailable; only scan-wide exhaustion stops remaining prior carry.
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

/// One prior finding, reduced to what the carry rules need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorEntry {
    pub file: String,
    pub status: FindingStatus,
    pub file_hash: Option<String>,
}

/// The prior report, indexed by root fingerprint.
#[derive(Debug, Clone, Default)]
pub struct PriorIndex {
    pub report_file: String,
    pub by_fingerprint: HashMap<String, Vec<PriorEntry>>,
    pub gap_modules: HashMap<String, String>,
    open_findings: Vec<Finding>,
}

impl PriorIndex {
    pub fn from_report(report_file: &str, report: &AuditReport) -> Self {
        let mut by_fingerprint: HashMap<String, Vec<PriorEntry>> = HashMap::new();
        for f in &report.findings {
            if f.root_fingerprint.is_empty() {
                continue;
            }
            by_fingerprint
                .entry(f.root_fingerprint.clone())
                .or_default()
                .push(PriorEntry {
                    file: f.file.clone(),
                    status: f.status,
                    file_hash: f.file_hash.clone(),
                });
        }
        PriorIndex {
            report_file: report_file.to_string(),
            by_fingerprint,
            gap_modules: report
                .coverage
                .iter()
                .filter_map(|c| {
                    let status = match c.status {
                        ModuleCoverageStatus::Deferred => "deferred",
                        ModuleCoverageStatus::LlmFailed => "llm_failed",
                        ModuleCoverageStatus::ParseFailed => "parse_failed",
                        ModuleCoverageStatus::PartiallyReviewed => "partially_reviewed",
                        ModuleCoverageStatus::ReviewedNoChecks => "shallow_no_checks",
                        _ if super::schema::CoverageSummary::from_coverage(
                            std::slice::from_ref(c),
                        )
                        .partial
                            && c.status.has_valid_reply() =>
                        {
                            "partial"
                        }
                        _ => return None,
                    };
                    Some((
                        module_base(&c.module_path).to_string(),
                        c.reason.clone().unwrap_or_else(|| status.into()),
                    ))
                })
                .collect(),
            open_findings: report
                .findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.status,
                        FindingStatus::Candidate | FindingStatus::NeedsHuman
                    )
                })
                .cloned()
                .collect(),
        }
    }

    /// Limit all carry decisions and prior-gap priority to this PR scope.
    pub fn restrict_diff_scope(
        &mut self,
        diff: &super::diff_scope::DiffSelection,
        modules: &[super::ai_audit::ModuleTarget],
    ) {
        self.open_findings
            .retain(|f| diff.changed.contains(&f.file));
        self.by_fingerprint.retain(|_, entries| {
            entries.retain(|e| diff.changed.contains(&e.file));
            !entries.is_empty()
        });
        let changed_modules: HashSet<&str> = modules
            .iter()
            .filter(|m| diff.contains_module(m))
            .map(|m| module_base(&m.module_path))
            .collect();
        self.gap_modules
            .retain(|path, _| changed_modules.contains(path.as_str()));
    }

    fn gap_reason(&self, module_path: &str) -> Option<&str> {
        // Page boundaries can change; gaps apply to the parent module.
        self.gap_modules
            .get(module_base(module_path))
            .map(String::as_str)
    }

    pub fn prioritize_modules(&self, ranked: &mut [super::ai_audit::ModuleTarget], cap: usize) {
        // Stable partition only the bounded promoted prefix. Every remaining
        // unit keeps its normal risk rank, including unpromoted prior gaps.
        let limit = cap.div_ceil(4).max(1);
        let mut promoted = 0;
        for index in 0..ranked.len() {
            if promoted >= limit || cap == 0 {
                break;
            }
            if self.gap_reason(&ranked[index].module_path).is_some() {
                ranked[promoted..=index].rotate_right(1);
                promoted += 1;
            }
        }
    }

    pub fn annotate_coverage(&self, coverage: &mut [ModuleCoverage]) -> usize {
        let mut count = 0;
        for c in coverage {
            if let Some(reason) = self.gap_reason(&c.module_path) {
                c.prior_status = Some(format!("prior_gap:{reason}"));
                count += 1;
            }
        }
        count
    }
}

fn module_base(path: &str) -> &str {
    path.rsplit_once(" #")
        .filter(|(_, page)| page.parse::<usize>().is_ok())
        .map_or(path, |(base, _)| base)
}

/// Evidence added only after the prior claim has passed the carry checks.
pub fn is_carried(f: &Finding) -> bool {
    f.evidence
        .iter()
        .any(|e| e.source == "prior_run" && e.detail.starts_with(PRIOR_NOT_REDISCOVERED_PREFIX))
}

/// List missing open claims without reading their source or reopening them.
/// Quick runs never admit historical claims to findings or model inputs.
pub fn record_quick_unrediscovered(
    findings: &[Finding],
    prior: &PriorIndex,
    info: &mut PriorRunInfo,
) {
    let mut seen: HashSet<&str> = findings
        .iter()
        .map(|f| f.root_fingerprint.as_str())
        .collect();
    for old in &prior.open_findings {
        if old.root_fingerprint.is_empty() || !seen.insert(&old.root_fingerprint) {
            continue;
        }
        info.changed_unrediscovered.push(ChangedUnrediscovered {
            id: old.id.clone(),
            file: old.file.clone(),
            title: crate::util::mask_sensitive_text(crate::util::truncate_bytes(&old.title, 300)),
            reason: "quick_profile_not_rechecked".into(),
        });
    }
}

/// Reopen prior claims absent from this run. All historical decisions and
/// proofs are discarded; only claim data enters the normal verifier.
pub fn carry_unrediscovered(
    repo_root: &Path,
    findings: &mut Vec<Finding>,
    prior: &PriorIndex,
    info: &mut PriorRunInfo,
) {
    carry_with_budget(repo_root, findings, prior, info, &mut HashBudget::default());
}

pub fn carry_with_budget(
    repo_root: &Path,
    findings: &mut Vec<Finding>,
    prior: &PriorIndex,
    info: &mut PriorRunInfo,
    budget: &mut HashBudget,
) {
    let current: HashSet<String> = findings
        .iter()
        .map(|f| f.root_fingerprint.clone())
        .collect();
    let mut carried = HashSet::new();
    let mut changed = HashSet::new();
    let mut changed_records = Vec::new();
    let mut ids: HashSet<String> = findings.iter().map(|f| f.id.clone()).collect();
    for (index, old) in prior.open_findings.iter().enumerate() {
        // Stop before resolving a path or touching source metadata/content.
        if index >= MAX_PRIOR_FINDINGS || info.carried_not_rediscovered >= MAX_CARRIED_FINDINGS {
            info.carried_not_rediscovered_overflow += prior.open_findings.len() - index;
            break;
        }
        if old.root_fingerprint.is_empty()
            || current.contains(&old.root_fingerprint)
            || carried.contains(&old.root_fingerprint)
        {
            continue;
        }
        let safe = vettalon_contract::safe_path::SafeRepoPath::parse(&old.file).is_ok();
        let hash = if safe {
            match budget.hash(repo_root, &old.file) {
                Ok(hash) => hash,
                Err(()) => {
                    let remaining = prior.open_findings.len() - index;
                    info.hash_budget_exhausted += remaining;
                    info.carried_not_rediscovered_overflow += remaining;
                    break;
                }
            }
        } else {
            None
        };
        let hash = hash.as_deref();
        let reason = if !safe {
            Some("unsafe_path")
        } else if hash.is_none() {
            Some("missing_or_unreadable")
        } else if old.file_hash.as_deref() != hash {
            Some("source_changed")
        } else if vettalon_contract::fingerprint::Fingerprint::parse(&old.root_fingerprint).is_err()
            || ids.contains(&old.id)
        {
            Some("invalid_identity")
        } else {
            None
        };
        if let Some(reason) = reason {
            if !changed.insert((old.root_fingerprint.clone(), old.file.clone(), reason)) {
                continue;
            }
            changed_records.push((
                old.root_fingerprint.clone(),
                ChangedUnrediscovered {
                    id: old.id.clone(),
                    file: old.file.clone(),
                    title: crate::util::mask_sensitive_text(crate::util::truncate_bytes(
                        &old.title, 300,
                    )),
                    reason: reason.into(),
                },
            ));
            continue;
        }
        let mut f = Finding::candidate(
            &old.source_engine,
            old.kind,
            old.severity,
            &old.title,
            &old.file,
            old.line,
            &old.snippet,
            &old.rule_id,
            vec![],
        );
        f.id = old.id.clone();
        f.root_fingerprint = old.root_fingerprint.clone();
        f.file_hash = hash.map(str::to_string);
        // Severity decomposition is claim data, not a historical verdict.
        // Legacy claims keep their stored severity without inventing an impact.
        f.severity_claimed = old.severity_claimed;
        f.likelihood = old.likelihood.clone();
        f.impact = old.impact.clone();
        if old.severity_basis == super::schema::SeverityBasis::ModelDecomposed {
            f.severity_basis = super::schema::SeverityBasis::ModelDecomposed;
        }
        f.threat_model = old.threat_model.clone();
        f.trace = old.trace.clone();
        f.conditions = old.conditions.clone();
        // Historical model identity is not provenance for this run. Keep
        // the fresh candidate's empty found_by; the prior report is linked
        // by evidence instead of claiming current finder attribution.
        f.cwe = old.cwe.clone();
        f.cve = old.cve.clone();
        f.package = old.package.clone();
        if serde_json::to_vec(&f).map_or(true, |v| v.len() > MAX_CARRIED_CLAIM_BYTES) {
            changed_records.push((
                old.root_fingerprint.clone(),
                ChangedUnrediscovered {
                    id: old.id.clone(),
                    file: old.file.clone(),
                    title: crate::util::mask_sensitive_text(crate::util::truncate_bytes(
                        &old.title, 300,
                    )),
                    reason: "claim_too_large".into(),
                },
            ));
            continue;
        }
        push_prior_evidence(
            &mut f,
            format!("{PRIOR_NOT_REDISCOVERED_PREFIX} {}", prior.report_file),
        );
        // Trace line checks share the same bounded reads as file hashing.
        let oracle = BudgetLines {
            root: repo_root,
            budget: std::cell::RefCell::new(&mut *budget),
            exhausted: std::cell::Cell::new(false),
        };
        let mut violations = super::precheck::check_file_and_line(&f.file, f.line, &oracle);
        if f.source_engine == super::schema::AI_AUDIT_ENGINE_NAME {
            violations.extend(super::precheck::check_trace(&f.trace, &oracle));
            match &f.threat_model {
                Some(tm) => violations.extend(super::precheck::check_threat_model(tm)),
                None => violations.push("missing threat model".into()),
            }
        } else if !f.trace.is_empty() {
            violations.extend(super::precheck::check_trace(&f.trace, &oracle));
        }
        if oracle.exhausted.get() {
            let remaining = prior.open_findings.len() - index;
            info.hash_budget_exhausted += remaining;
            info.carried_not_rediscovered_overflow += remaining;
            break;
        }
        super::precheck::apply_precheck(&mut f, violations);
        carried.insert(f.root_fingerprint.clone());
        ids.insert(f.id.clone());
        findings.push(f);
        info.carried_not_rediscovered += 1;
    }
    // A later valid version of the same root supersedes stale duplicates.
    info.changed_unrediscovered.extend(
        changed_records
            .into_iter()
            .filter(|(root, _)| !carried.contains(root))
            .map(|(_, record)| record),
    );
}

/// Find and load the newest qualifying prior report. `None` when there is
/// none (no directory, no report for this repo, or only skipped files).
pub fn load_prior(home_dir: &Path, canonical_repo: &str) -> Option<PriorIndex> {
    let dir = home_dir.join("reports");
    let entries = std::fs::read_dir(&dir).ok()?;
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| n.ends_with(".json"))
        .collect();
    // Newest first. Saved names are UTC timestamps (with or without
    // sub-second precision and a collision suffix); the key orders both the
    // current and the older form chronologically.
    names.sort_by(|a, b| {
        super::report::saved_report_sort_key(b).cmp(&super::report::saved_report_sort_key(a))
    });
    for name in names {
        let path = dir.join(&name);
        let too_big = std::fs::metadata(&path)
            .map(|m| m.len() > MAX_REPORT_BYTES)
            .unwrap_or(true);
        if too_big {
            eprintln!(
                "[vettalon] {}",
                crate::tr!(
                    "略過先前報告：檔案無法讀取或過大",
                    "skipping previous report: unreadable or too large"
                )
            );
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(r) => r,
            Err(_) => {
                eprintln!(
                    "[vettalon] {}",
                    crate::tr!(
                        "略過先前報告：無法讀取",
                        "skipping previous report: cannot read it"
                    )
                );
                continue;
            }
        };
        let report: AuditReport = match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(_) => {
                eprintln!(
                    "[vettalon] {}",
                    crate::tr!(
                        "略過先前報告：格式無法解析",
                        "skipping previous report: cannot parse it"
                    )
                );
                continue;
            }
        };
        if report.repo != canonical_repo {
            continue;
        }
        if !is_supported_schema_version(report.schema_version) {
            eprintln!(
                "[vettalon] {}",
                crate::tr!(
                    "略過先前報告：不支援的格式（schema_version {}），支援範圍為 {MIN_SUPPORTED_SCHEMA_VERSION}..={CURRENT_SCHEMA_VERSION}",
                    "skipping previous report: unsupported schema_version {}, supported range is {MIN_SUPPORTED_SCHEMA_VERSION}..={CURRENT_SCHEMA_VERSION}",
                    report.schema_version
                )
            );
            continue;
        }
        if !super::validator::validate_report(&report).is_empty() {
            // Report names and validator details can contain attacker data.
            eprintln!(
                "[vettalon] {}",
                crate::tr!(
                    "略過先前報告：報告驗證未通過",
                    "skipping previous report: report validation failed"
                )
            );
            continue;
        }
        return Some(PriorIndex::from_report(&name, &report));
    }
    None
}

/// What the carry rules decided for one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryDecision {
    None,
    Suppressed,
    Refuted,
    RevalidateConfirmed,
    ChangedSource,
}

/// Pure decision for one finding against the prior entries sharing its
/// fingerprint. See the module doc for the rules.
pub fn decide(current_hash: Option<&str>, prior: &[PriorEntry]) -> CarryDecision {
    if prior.is_empty() {
        return CarryDecision::None;
    }
    let same: Vec<&PriorEntry> = match current_hash {
        Some(h) => prior
            .iter()
            .filter(|p| p.file_hash.as_deref() == Some(h))
            .collect(),
        None => Vec::new(),
    };
    if same.is_empty() {
        return CarryDecision::ChangedSource;
    }
    if same.iter().any(|p| p.status == FindingStatus::Confirmed) {
        return CarryDecision::RevalidateConfirmed;
    }
    if same.iter().all(|p| p.status == FindingStatus::Suppressed) {
        return CarryDecision::Suppressed;
    }
    if same
        .iter()
        .all(|p| matches!(p.status, FindingStatus::Refuted | FindingStatus::Suppressed))
    {
        return CarryDecision::Refuted;
    }
    CarryDecision::None
}

/// P2-2: distinct prior statuses at one fingerprint, in a stable order, as a
/// comma-separated list for the episodic note (e.g. `confirmed, refuted`).
fn prior_status_summary(entries: &[PriorEntry]) -> String {
    let mut seen: Vec<FindingStatus> = Vec::new();
    for e in entries {
        if !seen.contains(&e.status) {
            seen.push(e.status);
        }
    }
    seen.iter()
        .map(|s| status_word(*s))
        .collect::<Vec<_>>()
        .join(", ")
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

fn push_prior_evidence(f: &mut Finding, detail: String) {
    f.evidence.push(EvidenceItem {
        kind: EvidenceKind::AdversarialReview,
        source: "prior_run".to_string(),
        detail,
        recorded_at: chrono::Utc::now().to_rfc3339(),
    });
}

/// Apply the carry rules to every current `Candidate` finding.
pub fn apply_prior(findings: &mut [Finding], prior: &PriorIndex) -> PriorRunInfo {
    let mut info = PriorRunInfo {
        report_file: prior.report_file.clone(),
        ..PriorRunInfo::default()
    };
    for f in findings.iter_mut() {
        if f.status != FindingStatus::Candidate || f.root_fingerprint.is_empty() {
            continue;
        }
        let Some(entries) = prior.by_fingerprint.get(&f.root_fingerprint) else {
            continue;
        };
        match decide(f.file_hash.as_deref(), entries) {
            CarryDecision::None => {}
            CarryDecision::ChangedSource => {
                info.changed_source += 1;
                // P2-2 episodic memory: the verdict is NOT carried (source
                // changed), but a spot a prior run judged is worth another
                // look, so the prior judgement is surfaced as a note.
                push_prior_evidence(
                    f,
                    format!(
                        "{PRIOR_CHANGED_PREFIX}: {} judged this root cause as {} before; the source has changed, so the verdict is not carried over (re-assess)",
                        prior.report_file,
                        prior_status_summary(entries),
                    ),
                );
            }
            CarryDecision::Suppressed => {
                f.status = FindingStatus::Suppressed;
                push_prior_evidence(
                    f,
                    format!(
                        "{CARRIED_FROM_PRIOR_PREFIX} {} (prior status suppressed, source unchanged)",
                        prior.report_file
                    ),
                );
                info.carried_suppressed += 1;
            }
            CarryDecision::Refuted => {
                f.status = FindingStatus::Refuted;
                push_prior_evidence(
                    f,
                    format!(
                        "{CARRIED_FROM_PRIOR_PREFIX} {} (prior status refuted, source unchanged)",
                        prior.report_file
                    ),
                );
                info.carried_refuted += 1;
            }
            CarryDecision::RevalidateConfirmed => {
                push_prior_evidence(
                    f,
                    format!(
                        "{PRIOR_CONFIRMED_PREFIX}: {} confirmed this on identical source; re-verifying",
                        prior.report_file
                    ),
                );
                info.revalidated_prior_confirmed += 1;
            }
        }
    }
    info
}

/// A bounded cache for one phase: current hashing OR prior carry and its line checks.
#[derive(Debug)]
pub struct HashBudget {
    remaining_bytes: u64,
    per_file_limit: u64,
    // Failed resolutions count too: bound metadata work before any file I/O.
    files: HashMap<String, Result<Option<FileDigest>, ()>>,
}

#[derive(Debug, Clone)]
struct FileDigest {
    hash: String,
    lines: usize,
}

impl Default for HashBudget {
    fn default() -> Self {
        Self {
            remaining_bytes: MAX_HASH_BYTES,
            per_file_limit: MAX_HASH_BYTES,
            files: HashMap::new(),
        }
    }
}

impl HashBudget {
    fn hash(&mut self, repo_root: &Path, file: &str) -> Result<Option<String>, ()> {
        self.read(repo_root, file)
            .map(|digest| digest.map(|d| d.hash))
    }

    fn read(&mut self, repo_root: &Path, file: &str) -> Result<Option<FileDigest>, ()> {
        if let Some(cached) = self.files.get(file) {
            return cached.clone();
        }
        if self.files.len() >= MAX_HASH_FILES || self.remaining_bytes == 0 {
            return Err(());
        }
        self.files.insert(file.to_owned(), Ok(None));
        let digest = self.read_uncached(repo_root, file);
        self.files.insert(file.to_owned(), digest.clone());
        digest
    }

    /// Reserve bytes before reading, then stream only that bounded snapshot.
    /// Growth/shrinkage invalidates the hash without reading beyond the budget.
    fn read_uncached(&mut self, repo_root: &Path, file: &str) -> Result<Option<FileDigest>, ()> {
        let Ok(full) = crate::util::resolve_in_repo(repo_root, file) else {
            return Ok(None);
        };
        let Ok(meta) = std::fs::metadata(&full) else {
            return Ok(None);
        };
        if !meta.is_file() {
            return Ok(None);
        }
        if meta.len() > self.per_file_limit {
            return Ok(None);
        }
        if meta.len() > self.remaining_bytes {
            return Err(());
        }
        self.remaining_bytes -= meta.len();
        let Ok(mut input) = std::fs::File::open(full) else {
            return Ok(None);
        };
        let mut hasher = Sha256::new();
        let mut remaining = meta.len();
        let mut lines = 0;
        let mut last = None;
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            let Ok(n) = input.read(&mut buffer[..take]) else {
                return Ok(None);
            };
            if n == 0 {
                return Ok(None);
            }
            hasher.update(&buffer[..n]);
            lines += buffer[..n].iter().filter(|&&b| b == b'\n').count();
            last = Some(buffer[n - 1]);
            remaining -= n as u64;
        }
        if input.metadata().ok().is_none_or(|m| m.len() != meta.len()) {
            return Ok(None);
        }
        if last.is_some_and(|b| b != b'\n') {
            lines += 1;
        }
        Ok(Some(FileDigest {
            hash: hex::encode(hasher.finalize()),
            lines,
        }))
    }
}

struct BudgetLines<'a, 'b> {
    root: &'a Path,
    budget: std::cell::RefCell<&'b mut HashBudget>,
    exhausted: std::cell::Cell<bool>,
}

impl super::precheck::LineOracle for BudgetLines<'_, '_> {
    fn line_count(&self, path: &vettalon_contract::safe_path::SafeRepoPath) -> Option<usize> {
        match self.budget.borrow_mut().read(self.root, path.as_str()) {
            Ok(digest) => digest.map(|d| d.lines),
            Err(()) => {
                self.exhausted.set(true);
                None
            }
        }
    }
}

#[cfg(test)]
pub fn hash_repo_file(repo_root: &Path, file: &str) -> Option<String> {
    HashBudget::default().hash(repo_root, file).ok().flatten()
}

/// Fill hashes with a dedicated budget that cannot starve prior carry.
pub fn fill_file_hashes(repo_root: &Path, findings: &mut [Finding]) {
    let mut budget = HashBudget::default();
    for f in findings.iter_mut() {
        f.file_hash = budget.hash(repo_root, &f.file).ok().flatten();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{
        FindingKind, GatePolicy, ProfileMode, ScanProfile, Severity, Summary, VerifierInfo,
    };
    use vettalon_contract::coverage::RunStatus;

    fn finding(file: &str, rule: &str, status: FindingStatus, hash: Option<&str>) -> Finding {
        let mut f = Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::High,
            "t",
            file,
            Some(1),
            "s",
            rule,
            vec![],
        );
        f.status = status;
        f.file_hash = hash.map(str::to_string);
        f
    }

    fn report(repo: &str, version: u32, mut findings: Vec<Finding>) -> AuditReport {
        for f in &mut findings {
            if matches!(
                f.status,
                FindingStatus::Suppressed | FindingStatus::Refuted | FindingStatus::Confirmed
            ) {
                f.evidence.push(EvidenceItem {
                    kind: EvidenceKind::OperatorReview,
                    source: "operator_review".into(),
                    detail: "fixture decision".into(),
                    recorded_at: "2026-10-01T00:00:00Z".into(),
                });
            }
        }
        AuditReport {
            schema_version: version,
            scope: None,
            repo: repo.to_string(),
            started_at: "2026-10-01T00:00:00Z".into(),
            profile: ScanProfile {
                mode: ProfileMode::Quick,
                intake: None,
            },
            engines_run: vec![],
            engines_missing: vec![],
            summary: Summary::from_findings(&findings, 0, 0, GatePolicy::default(), &[]),
            findings,
            run_status: RunStatus::Complete,
            incomplete_reason: None,
            coverage: vec![],
            prior_run: None,
            verifier: VerifierInfo::default(),
            ensemble: Default::default(),
        }
    }

    fn write(home: &Path, name: &str, r: &AuditReport) {
        let dir = home.join("reports");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), serde_json::to_string(r).unwrap()).unwrap();
    }

    // ── decide ────────────────────────────────────────────────────────

    fn e(status: FindingStatus, h: &str) -> PriorEntry {
        PriorEntry {
            file: "src/a.rs".into(),
            status,
            file_hash: Some(h.into()),
        }
    }

    #[test]
    fn decide_follows_the_carry_rules() {
        use FindingStatus::*;
        assert_eq!(decide(Some("h"), &[]), CarryDecision::None);
        assert_eq!(
            decide(Some("h"), &[e(Suppressed, "h")]),
            CarryDecision::Suppressed
        );
        assert_eq!(
            decide(Some("h"), &[e(Refuted, "h")]),
            CarryDecision::Refuted
        );
        assert_eq!(
            decide(Some("h"), &[e(Confirmed, "h")]),
            CarryDecision::RevalidateConfirmed
        );
        assert_eq!(
            decide(Some("h"), &[e(Refuted, "old")]),
            CarryDecision::ChangedSource
        );
        assert_eq!(
            decide(None, &[e(Refuted, "h")]),
            CarryDecision::ChangedSource
        );
        // Mixed: a Confirmed wins; an open status blocks suppression.
        assert_eq!(
            decide(Some("h"), &[e(Suppressed, "h"), e(Confirmed, "h")]),
            CarryDecision::RevalidateConfirmed
        );
        assert_eq!(
            decide(Some("h"), &[e(Refuted, "h"), e(NeedsHuman, "h")]),
            CarryDecision::None
        );
        assert_eq!(
            decide(Some("h"), &[e(Refuted, "h"), e(Suppressed, "h")]),
            CarryDecision::Refuted
        );
    }

    // ── load_prior + apply_prior ─────────────────────────────────────

    #[test]
    fn carry_rules_end_to_end_from_a_saved_report() {
        let home = tempfile::tempdir().unwrap();
        let prior = report(
            "/repo",
            2,
            vec![
                finding("a.rs", "r-sup", FindingStatus::Suppressed, Some("h1")),
                finding("b.rs", "r-ref", FindingStatus::Refuted, Some("h2")),
                finding("c.rs", "r-conf", FindingStatus::Confirmed, Some("h3")),
                finding("d.rs", "r-chg", FindingStatus::Refuted, Some("old")),
            ],
        );
        write(home.path(), "20261001T000000Z.json", &prior);

        let idx = load_prior(home.path(), "/repo").expect("prior found");
        assert_eq!(idx.report_file, "20261001T000000Z.json");

        // Current findings at different lines (fingerprint ignores line).
        let mut current = vec![
            finding("a.rs", "r-sup", FindingStatus::Candidate, Some("h1")),
            finding("b.rs", "r-ref", FindingStatus::Candidate, Some("h2")),
            finding("c.rs", "r-conf", FindingStatus::Candidate, Some("h3")),
            finding("d.rs", "r-chg", FindingStatus::Candidate, Some("new")),
            finding("e.rs", "r-new", FindingStatus::Candidate, Some("h5")),
        ];
        current[0].line = Some(77);
        let info = apply_prior(&mut current, &idx);
        assert_eq!(current[0].status, FindingStatus::Suppressed);
        assert_eq!(current[1].status, FindingStatus::Refuted);
        assert_eq!(current[2].status, FindingStatus::Candidate);
        assert_eq!(current[3].status, FindingStatus::Candidate);
        assert_eq!(current[4].status, FindingStatus::Candidate);
        assert!(
            current[0].evidence[0]
                .detail
                .starts_with(CARRIED_FROM_PRIOR_PREFIX)
        );
        assert_eq!(current[0].evidence[0].kind, EvidenceKind::AdversarialReview);
        assert!(
            current[2].evidence[0]
                .detail
                .starts_with(PRIOR_CONFIRMED_PREFIX)
        );
        // P2-2: the changed-source finding is NOT carried (stays Candidate)
        // but carries an episodic note naming the prior verdict.
        assert_eq!(current[3].status, FindingStatus::Candidate);
        assert!(
            current[3].evidence.iter().any(|e| {
                e.detail.starts_with(PRIOR_CHANGED_PREFIX) && e.detail.contains("refuted")
            }),
            "changed-source finding should carry an episodic note: {:?}",
            current[3].evidence
        );
        // Stored evidence is report data: English whatever the terminal says.
        let note = current[3]
            .evidence
            .iter()
            .find(|e| e.detail.starts_with(PRIOR_CHANGED_PREFIX))
            .unwrap();
        assert!(
            !note
                .detail
                .chars()
                .any(|c| matches!(c as u32, 0x3000..=0x30FF | 0x4E00..=0x9FFF | 0xFF00..=0xFFEF)),
            "{}",
            note.detail
        );
        // The genuinely-new finding (no prior fingerprint) carries nothing.
        assert!(current[4].evidence.is_empty());
        assert_eq!(
            info,
            PriorRunInfo {
                report_file: "20261001T000000Z.json".into(),
                carried_suppressed: 1,
                carried_refuted: 1,
                revalidated_prior_confirmed: 1,
                changed_source: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn load_prior_skips_other_repos_old_schema_and_broken_files() {
        let home = tempfile::tempdir().unwrap();
        // Newest first: broken, other repo, v1 same repo, then the good one.
        write(
            home.path(),
            "20261001T000000Z.json",
            &report(
                "/repo",
                2,
                vec![finding("a.rs", "r", FindingStatus::Refuted, Some("h"))],
            ),
        );
        write(
            home.path(),
            "20261002T000000Z.json",
            &report("/repo", 1, vec![]),
        );
        write(
            home.path(),
            "20261003T000000Z.json",
            &report("/other", 2, vec![]),
        );
        let dir = home.path().join("reports");
        std::fs::write(dir.join("20261004T000000Z.json"), "{ not json").unwrap();
        std::fs::write(dir.join("notes.txt"), "x").unwrap();
        write(
            home.path(),
            "20261005T000000Z.json",
            &report("/repo", 4, vec![]),
        );

        let idx = load_prior(home.path(), "/repo").expect("falls through to the v2 report");
        assert_eq!(idx.report_file, "20261001T000000Z.json");
        assert_eq!(idx.by_fingerprint.len(), 1);
    }

    /// The real 2026-08 v1 file shape (no schema_version) is skipped
    /// gracefully: no prior, no panic.
    #[test]
    fn load_prior_skips_a_v1_report_without_schema_version() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("reports");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("20260817T222007Z.json"),
            r#"{"repo":"/repo","started_at":"t","profile":{"mode":"quick","intake":null},
                "engines_run":[],"engines_missing":[],"findings":[],
                "summary":{"total_findings":0,"by_severity":{"critical":0,"high":0,"medium":0,"low":0,"info":0},
                "engines_run_count":0,"engines_missing_count":0}}"#,
        )
        .unwrap();
        assert!(load_prior(home.path(), "/repo").is_none());
    }

    /// Newest is chronological across the older second-precision names and
    /// the current microsecond names with collision suffixes (plain lexical
    /// order would rank `…061029Z.json` above `…061029.100000Z-10.json`,
    /// and `-2` above `-10`).
    #[test]
    fn load_prior_picks_the_newest_across_old_and_new_names() {
        let home = tempfile::tempdir().unwrap();
        let r = report("/repo", 2, vec![]);
        for name in [
            "20261021T061027.999999Z.json",
            "20261021T061028Z.json",
            "20261021T061029Z.json",
            "20261021T061029.100000Z.json",
            "20261021T061029.100000Z-2.json",
            "20261021T061029.100000Z-10.json",
        ] {
            write(home.path(), name, &r);
        }
        let idx = load_prior(home.path(), "/repo").unwrap();
        assert_eq!(idx.report_file, "20261021T061029.100000Z-10.json");

        let home = tempfile::tempdir().unwrap();
        write(home.path(), "20261021T061027.999999Z.json", &r);
        write(home.path(), "20261021T061028Z.json", &r);
        let idx = load_prior(home.path(), "/repo").unwrap();
        assert_eq!(idx.report_file, "20261021T061028Z.json");
    }

    #[test]
    fn load_prior_without_a_reports_dir_is_none() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_prior(home.path(), "/repo").is_none());
    }

    #[test]
    fn apply_prior_leaves_settled_findings_alone() {
        let prior = PriorIndex::from_report(
            "p.json",
            &report(
                "/repo",
                2,
                vec![finding("a.rs", "r", FindingStatus::Suppressed, Some("h"))],
            ),
        );
        let mut current = vec![finding("a.rs", "r", FindingStatus::Refuted, Some("h"))];
        let info = apply_prior(&mut current, &prior);
        assert_eq!(current[0].status, FindingStatus::Refuted);
        assert!(current[0].evidence.is_empty());
        assert_eq!(info.carried_suppressed, 0);
    }

    fn gap(
        path: &str,
        status: super::super::schema::ModuleCoverageStatus,
        reason: &str,
    ) -> super::super::schema::ModuleCoverage {
        serde_json::from_value(serde_json::json!({
            "module_path": path, "status": status, "reason": reason
        }))
        .unwrap()
    }

    #[test]
    fn prior_gaps_rank_existing_modules_first_and_mark_coverage() {
        use super::super::schema::ModuleCoverageStatus::*;
        let mut r = report("/repo", 2, vec![]);
        r.coverage = vec![
            gap("b", Deferred, "time_budget"),
            gap("gone", LlmFailed, "offline"),
            gap("c", PartiallyReviewed, "shallow_no_checks"),
        ];
        let prior = PriorIndex::from_report("p.json", &r);
        let mut ranked = super::super::ai_audit::rank_modules(
            &["a/x.rs".into(), "b/x.rs".into(), "c/x.rs".into()],
            &[],
            &[],
        );
        prior.prioritize_modules(&mut ranked, 8);
        assert_eq!(
            ranked
                .iter()
                .map(|m| m.module_path.as_str())
                .collect::<Vec<_>>(),
            ["b", "c", "a"]
        );
        let mut coverage = super::super::coverage::build_module_coverage(&ranked, &[]);
        assert_eq!(prior.annotate_coverage(&mut coverage), 2);
        assert_eq!(
            coverage[0].prior_status.as_deref(),
            Some("prior_gap:time_budget")
        );
        assert_eq!(
            coverage[1].prior_status.as_deref(),
            Some("prior_gap:shallow_no_checks")
        );
        assert!(coverage[2].prior_status.is_none());
        assert_eq!(coverage.len(), 3);
    }

    #[test]
    fn prior_reviewed_no_checks_is_prior_gap_but_v2_covered_is_not() {
        for reason in [None, Some("shallow_no_checks")] {
            let mut r = report("/repo", 3, vec![]);
            let mut shallow = gap("z", ModuleCoverageStatus::ReviewedNoChecks, "");
            shallow.reason = reason.map(str::to_owned);
            r.coverage = vec![shallow];
            let prior = PriorIndex::from_report("p.json", &r);
            let mut ranked =
                super::super::ai_audit::rank_modules(&["a/x.rs".into(), "z/x.rs".into()], &[], &[]);
            prior.prioritize_modules(&mut ranked, 8);
            assert_eq!(ranked[0].module_path, "z");
            let mut coverage = super::super::coverage::build_module_coverage(&ranked, &[]);
            assert_eq!(prior.annotate_coverage(&mut coverage), 1);
            assert_eq!(
                coverage[0].prior_status.as_deref(),
                Some("prior_gap:shallow_no_checks")
            );
        }
        let mut legacy = report("/repo", 2, vec![]);
        legacy.coverage = vec![gap("z", ModuleCoverageStatus::Covered, "")];
        assert!(
            PriorIndex::from_report("v2.json", &legacy)
                .gap_modules
                .is_empty()
        );
    }

    #[test]
    fn unrediscovered_same_hash_is_a_fresh_candidate_and_duplicates_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "abc").unwrap();
        let hash = hash_repo_file(dir.path(), "a.rs").unwrap();
        let mut old = finding("a.rs", "r", FindingStatus::NeedsHuman, Some(&hash));
        old.found_by = vec!["retired-finder".into()];
        old.blockers.push("old blocker".into());
        old.evidence.push(EvidenceItem {
            kind: EvidenceKind::OperatorReview,
            source: "operator".into(),
            detail: "old".into(),
            recorded_at: "t".into(),
        });
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, vec![old.clone(), old]));
        let mut current = vec![];
        let mut info = PriorRunInfo::default();
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].status, FindingStatus::Candidate);
        assert!(current[0].found_by.is_empty());
        assert!(current[0].blockers.is_empty() && current[0].verification.is_empty());
        assert_eq!(current[0].evidence.len(), 1);
        assert_eq!(
            current[0].evidence[0].detail,
            "prior_not_rediscovered: p.json"
        );
        assert_eq!(info.carried_not_rediscovered, 1);
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert_eq!(current.len(), 1);
    }

    #[test]
    fn carried_v3_claim_retains_severity_decomposition_without_historical_proofs() {
        use super::super::schema::{SeverityAssessment, SeverityBasis};
        use vettalon_contract::severity::Level;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.rs"),
            "fn main() {\n    let q = read();\n    db.execute(q);\n}\n",
        )
        .unwrap();
        let hash = hash_repo_file(dir.path(), "a.rs").unwrap();
        let mut old = finding("a.rs", "r", FindingStatus::NeedsHuman, Some(&hash));
        old.severity = Severity::Medium;
        old.severity_claimed = Some(Severity::High);
        old.likelihood = Some(SeverityAssessment {
            level: Level::High,
            reason: "directly reachable".into(),
        });
        old.impact = Some(SeverityAssessment {
            level: Level::Medium,
            reason: "limited damage".into(),
        });
        old.severity_basis = SeverityBasis::ModelDecomposed;
        old.source_engine = super::super::schema::AI_AUDIT_ENGINE_NAME.into();
        old.line = Some(3);
        let raw: serde_json::Value =
            serde_json::from_str(&super::super::ai_audit::tests::cand_json("a.rs", 3)).unwrap();
        old.threat_model = serde_json::from_value(raw["threat_model"].clone()).unwrap();
        old.trace = serde_json::from_value(raw["trace"].clone()).unwrap();
        let prior = PriorIndex::from_report("p.json", &report("/repo", 3, vec![old.clone()]));
        let mut current = vec![];
        let mut info = PriorRunInfo::default();
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert_eq!(current.len(), 1);
        let carried = &current[0];
        assert_eq!(carried.status, FindingStatus::Candidate);
        assert_eq!(carried.severity, Severity::Medium);
        assert_eq!(carried.severity_claimed, old.severity_claimed);
        assert_eq!(carried.likelihood, old.likelihood);
        assert_eq!(carried.impact, old.impact);
        assert_eq!(carried.severity_basis, SeverityBasis::ModelDecomposed);
        assert!(carried.verification.is_empty() && carried.proof_evidence.is_empty());
        assert!(is_carried(carried));
    }

    #[test]
    fn unrediscovered_changed_missing_and_hostile_paths_are_display_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "new").unwrap();
        let paths = [
            "a.rs".to_string(),
            "missing.rs".into(),
            "../escape.rs".into(),
            dir.path().join("a.rs").display().to_string(),
        ];
        let old = paths
            .iter()
            .map(|p| finding(p, "r", FindingStatus::Candidate, Some("old")))
            .collect();
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, old));
        let mut current = vec![];
        let mut info = PriorRunInfo::default();
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert!(current.is_empty());
        assert_eq!(info.changed_unrediscovered.len(), 4);
        assert_eq!(info.changed_unrediscovered[0].reason, "source_changed");
        assert_eq!(
            info.changed_unrediscovered[1].reason,
            "missing_or_unreadable"
        );
        assert!(
            info.changed_unrediscovered[2..]
                .iter()
                .all(|f| f.reason == "unsafe_path")
        );
    }

    #[cfg(unix)]
    #[test]
    fn unrediscovered_symlink_outside_repo_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link.rs")).unwrap();
        let prior = PriorIndex::from_report(
            "p.json",
            &report(
                "/repo",
                2,
                vec![finding("link.rs", "r", FindingStatus::Candidate, Some("h"))],
            ),
        );
        let mut current = vec![];
        let mut info = PriorRunInfo::default();
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert!(current.is_empty());
        assert_eq!(info.changed_unrediscovered.len(), 1);
    }

    #[test]
    fn stale_duplicate_cannot_hide_an_unchanged_open_claim() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "abc").unwrap();
        let hash = hash_repo_file(dir.path(), "a.rs").unwrap();
        let mut stale = finding("a.rs", "r", FindingStatus::Candidate, Some("stale"));
        stale.id.push_str("-different-location");
        let valid = finding("a.rs", "r", FindingStatus::NeedsHuman, Some(&hash));
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, vec![stale, valid]));
        let mut current = vec![];
        let mut info = PriorRunInfo::default();
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert_eq!(current.len(), 1);
        assert_eq!(info.carried_not_rediscovered, 1);
        assert!(info.changed_unrediscovered.is_empty());
    }

    #[test]
    fn unrediscovered_cap_counts_overflow_without_duplicate_cost() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "abc").unwrap();
        let hash = hash_repo_file(dir.path(), "a.rs").unwrap();
        let old = (0..MAX_CARRIED_FINDINGS + 3)
            .map(|i| {
                finding(
                    "a.rs",
                    &format!("r{i}"),
                    FindingStatus::Candidate,
                    Some(&hash),
                )
            })
            .collect();
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, old));
        let mut current = vec![];
        let mut info = PriorRunInfo::default();
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert_eq!(current.len(), MAX_CARRIED_FINDINGS);
        assert_eq!(info.carried_not_rediscovered, MAX_CARRIED_FINDINGS);
        assert_eq!(info.carried_not_rediscovered_overflow, 3);
    }

    #[test]
    fn oversized_prior_claim_is_display_only_and_costs_no_verifier_input() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "abc").unwrap();
        let hash = hash_repo_file(dir.path(), "a.rs").unwrap();
        let mut old = finding("a.rs", "r", FindingStatus::Candidate, Some(&hash));
        old.title = "x".repeat(MAX_CARRIED_CLAIM_BYTES + 1);
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, vec![old]));
        let mut current = vec![];
        let mut info = PriorRunInfo::default();
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert!(current.is_empty());
        assert_eq!(info.changed_unrediscovered[0].reason, "claim_too_large");
        assert_eq!(info.changed_unrediscovered[0].title.len(), 300);
    }

    #[test]
    fn quick_unrediscovered_only_lists_unique_missing_open_claims_without_a_carry_cap() {
        let rediscovered = finding("a.rs", "r", FindingStatus::Candidate, None);
        let missing = finding("missing.rs", "r", FindingStatus::NeedsHuman, None);
        let mut old = vec![
            rediscovered.clone(),
            missing.clone(),
            missing,
            finding("closed.rs", "r", FindingStatus::Refuted, None),
            finding("confirmed.rs", "r", FindingStatus::Confirmed, None),
        ];
        old.extend(
            (0..MAX_CARRIED_FINDINGS + 1)
                .map(|i| finding(&format!("gone-{i}.rs"), "r", FindingStatus::Candidate, None)),
        );
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, old));
        let current = vec![rediscovered];
        let mut info = PriorRunInfo::default();
        record_quick_unrediscovered(&current, &prior, &mut info);
        assert_eq!(current.len(), 1);
        assert_eq!(info.changed_unrediscovered.len(), MAX_CARRIED_FINDINGS + 2);
        assert!(
            info.changed_unrediscovered
                .iter()
                .all(|f| f.reason == "quick_profile_not_rechecked")
        );
        assert_eq!(info.carried_not_rediscovered, 0);
        assert_eq!(info.carried_not_rediscovered_overflow, 0);
    }

    #[test]
    fn old_prior_info_fields_default_and_optional_prior_status_is_omitted() {
        let info: PriorRunInfo = serde_json::from_value(serde_json::json!({
            "report_file": "p.json", "carried_suppressed": 0, "carried_refuted": 0,
            "revalidated_prior_confirmed": 0, "changed_source": 0
        }))
        .unwrap();
        assert_eq!(info.carried_not_rediscovered, 0);
        assert_eq!(info.hash_budget_exhausted, 0);
        assert!(info.changed_unrediscovered.is_empty());
        assert_eq!(info.prior_gap_modules, 0);
        let c = gap("a", ModuleCoverageStatus::Covered, "");
        assert!(
            serde_json::to_value(c)
                .unwrap()
                .get("prior_status")
                .is_none()
        );
    }

    #[test]
    fn all_prior_gap_statuses_and_pages_are_promoted() {
        use ModuleCoverageStatus::*;
        for status in [Deferred, LlmFailed, ParseFailed, PartiallyReviewed] {
            let mut r = report("/repo", 2, vec![]);
            r.coverage = vec![gap("z #2", status, "gap")];
            let prior = PriorIndex::from_report("p.json", &r);
            let mut ranked =
                super::super::ai_audit::rank_modules(&["a/x.rs".into(), "z/x.rs".into()], &[], &[]);
            prior.prioritize_modules(&mut ranked, 8);
            assert_eq!(ranked[0].module_path, "z");
        }
    }

    #[test]
    fn prior_report_without_coverage_is_still_loaded() {
        let home = tempfile::tempdir().unwrap();
        let mut value = serde_json::to_value(report("/repo", 2, vec![])).unwrap();
        value.as_object_mut().unwrap().remove("coverage");
        std::fs::create_dir(home.path().join("reports")).unwrap();
        std::fs::write(home.path().join("reports/p.json"), value.to_string()).unwrap();
        assert!(
            load_prior(home.path(), "/repo")
                .unwrap()
                .gap_modules
                .is_empty()
        );
    }

    // ── hashing ───────────────────────────────────────────────────────

    #[test]
    fn fill_file_hashes_hashes_real_files_and_refuses_unsafe_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "abc").unwrap();
        let mut fs = vec![
            finding("a.rs", "r1", FindingStatus::Candidate, None),
            finding("a.rs", "r2", FindingStatus::Candidate, None),
            finding("/etc/passwd", "r3", FindingStatus::Candidate, None),
            finding("missing.rs", "r4", FindingStatus::Candidate, None),
        ];
        fill_file_hashes(dir.path(), &mut fs);
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(fs[0].file_hash.as_deref(), Some(abc));
        assert_eq!(fs[1].file_hash.as_deref(), Some(abc));
        assert!(fs[2].file_hash.is_none());
        assert!(fs[3].file_hash.is_none());
    }
    #[test]
    fn previous_schema_v2_report_remains_eligible_without_v3_fields() {
        let home = tempfile::tempdir().unwrap();
        let prior = finding("a.rs", "rule", FindingStatus::Refuted, Some("hash"));
        let mut raw = serde_json::to_value(report("/repo", 2, vec![prior.clone()])).unwrap();
        let row = raw["findings"][0].as_object_mut().unwrap();
        for key in ["likelihood", "impact", "severity_claimed"] {
            row.remove(key);
        }
        let dir = home.path().join("reports");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("20261028T000000Z.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        let loaded = load_prior(home.path(), "/repo").expect("v2 has comparable root fingerprints");
        assert_eq!(
            loaded.by_fingerprint[&prior.root_fingerprint][0].status,
            FindingStatus::Refuted
        );
        assert_eq!(
            loaded.by_fingerprint[&prior.root_fingerprint][0]
                .file_hash
                .as_deref(),
            Some("hash")
        );
    }

    #[test]
    fn prior_gap_promotion_is_a_quarter_of_cap_and_preserves_remaining_risk_order() {
        let paths: Vec<String> = (0..12).map(|i| format!("m{i:02}/x.rs")).collect();
        let original = super::super::ai_audit::rank_modules(&paths, &[], &[]);
        let mut prior = PriorIndex::default();
        for module in &original[6..] {
            prior
                .gap_modules
                .insert(module.module_path.clone(), "deferred".into());
        }
        for (cap, promoted) in [(0, 0), (1, 1), (4, 1), (5, 2), (8, 2), (12, 3)] {
            let mut ranked = original.clone();
            prior.prioritize_modules(&mut ranked, cap);
            let expected: Vec<_> = original[6..6 + promoted]
                .iter()
                .chain(original[..6].iter())
                .chain(original[6 + promoted..].iter())
                .map(|m| m.module_path.as_str())
                .collect();
            assert_eq!(
                ranked
                    .iter()
                    .map(|m| m.module_path.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "cap={cap}"
            );
        }
    }

    #[test]
    fn load_prior_skips_semantically_invalid_reports_before_using_gaps_or_claims() {
        let home = tempfile::tempdir().unwrap();
        let good = report("/repo", CURRENT_SCHEMA_VERSION, vec![]);
        assert!(super::super::validator::validate_report(&good).is_empty());
        write(home.path(), "20261001T000000Z.json", &good);
        for variant in 0..4 {
            let mut bad = report(
                "/repo",
                CURRENT_SCHEMA_VERSION,
                vec![finding("a.rs", "rule", FindingStatus::Candidate, Some("h"))],
            );
            bad.coverage = vec![gap(
                "untrusted",
                ModuleCoverageStatus::Deferred,
                "time_budget",
            )];
            bad.summary =
                Summary::from_findings(&bad.findings, 0, 0, GatePolicy::default(), &bad.coverage);
            assert!(super::super::validator::validate_report(&bad).is_empty());
            match variant {
                0 => bad.summary.total_findings += 1,
                1 => {
                    bad.findings[0].status = FindingStatus::Suppressed;
                    bad.summary = Summary::from_findings(
                        &bad.findings,
                        0,
                        0,
                        GatePolicy::default(),
                        &bad.coverage,
                    );
                }
                // Plain ASCII words are valid fingerprints; '!' is forbidden.
                2 => bad.findings[0].root_fingerprint = "!invalid".into(),
                _ => bad.coverage[0].candidate_ids = vec!["missing-id".into()],
            }
            assert!(
                !super::super::validator::validate_report(&bad).is_empty(),
                "mutation variant {variant} was accepted"
            );
            write(home.path(), "20261002T000000Z.json", &bad);
            let loaded = load_prior(home.path(), "/repo").unwrap();
            assert_eq!(loaded.report_file, "20261001T000000Z.json");
            assert!(loaded.gap_modules.is_empty());
            assert!(loaded.open_findings.is_empty());
            assert!(loaded.by_fingerprint.is_empty());
        }
        std::fs::remove_file(home.path().join("reports/20261001T000000Z.json")).unwrap();
        assert!(load_prior(home.path(), "/repo").is_none());
    }

    #[test]
    fn prior_consideration_cap_stops_before_next_file_io() {
        let dir = tempfile::tempdir().unwrap();
        let mut old: Vec<_> = (0..MAX_PRIOR_FINDINGS)
            .map(|i| {
                finding(
                    "missing.rs",
                    &format!("rule{i}"),
                    FindingStatus::Candidate,
                    None,
                )
            })
            .collect();
        old.push(finding(
            "must-not-read.rs",
            "last",
            FindingStatus::Candidate,
            None,
        ));
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, old));
        let mut budget = HashBudget::default();
        let mut info = PriorRunInfo::default();
        carry_with_budget(dir.path(), &mut vec![], &prior, &mut info, &mut budget);
        assert_eq!(info.changed_unrediscovered.len(), MAX_PRIOR_FINDINGS);
        assert_eq!(info.carried_not_rediscovered_overflow, 1);
        assert_eq!(info.hash_budget_exhausted, 0);
        assert_eq!(budget.files.len(), 1);
        assert!(!budget.files.contains_key("must-not-read.rs"));
    }

    #[test]
    fn carry_cap_is_checked_before_hashing_next_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "abc").unwrap();
        let hash = hash_repo_file(dir.path(), "a.rs").unwrap();
        let mut old: Vec<_> = (0..MAX_CARRIED_FINDINGS)
            .map(|i| {
                finding(
                    "a.rs",
                    &format!("rule{i}"),
                    FindingStatus::Candidate,
                    Some(&hash),
                )
            })
            .collect();
        old.push(finding(
            "must-not-read.rs",
            "last",
            FindingStatus::Candidate,
            Some(&hash),
        ));
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, old));
        let mut budget = HashBudget::default();
        let mut info = PriorRunInfo::default();
        let mut current = vec![];
        carry_with_budget(dir.path(), &mut current, &prior, &mut info, &mut budget);
        assert_eq!(current.len(), MAX_CARRIED_FINDINGS);
        assert_eq!(info.carried_not_rediscovered_overflow, 1);
        assert_eq!(info.hash_budget_exhausted, 0);
        assert_eq!(budget.remaining_bytes, MAX_HASH_BYTES - 3);
        assert_eq!(budget.files.len(), 1);
        assert!(!budget.files.contains_key("must-not-read.rs"));
    }

    #[test]
    fn distinct_file_budget_bounds_failed_lookups_and_counts_remaining_claims() {
        let dir = tempfile::tempdir().unwrap();
        let old = (0..MAX_HASH_FILES + 2)
            .map(|i| {
                finding(
                    &format!("missing-{i}.rs"),
                    "rule",
                    FindingStatus::Candidate,
                    None,
                )
            })
            .collect();
        let prior = PriorIndex::from_report("p.json", &report("/repo", 2, old));
        let mut budget = HashBudget::default();
        let mut info = PriorRunInfo::default();
        carry_with_budget(dir.path(), &mut vec![], &prior, &mut info, &mut budget);
        assert_eq!(budget.files.len(), MAX_HASH_FILES);
        assert_eq!(info.changed_unrediscovered.len(), MAX_HASH_FILES);
        assert_eq!(info.hash_budget_exhausted, 2);
        assert_eq!(info.carried_not_rediscovered_overflow, 2);
        assert!(!budget.files.contains_key("missing-200.rs"));
    }

    #[test]
    fn current_hash_exhaustion_does_not_starve_prior_carry() {
        let dir = tempfile::tempdir().unwrap();
        let mut current = Vec::new();
        for i in 0..MAX_HASH_FILES + 1 {
            let path = format!("current-{i}.rs");
            std::fs::write(dir.path().join(&path), "current\n").unwrap();
            let mut f = finding(&path, "current", FindingStatus::Candidate, None);
            f.source_engine = "semgrep".into();
            f.evidence.push(EvidenceItem {
                kind: EvidenceKind::ScopeNote,
                source: "diff_scope".into(),
                detail: "outside_diff_scope".into(),
                recorded_at: chrono::Utc::now().to_rfc3339(),
            });
            current.push(f);
        }
        fill_file_hashes(dir.path(), &mut current);
        assert_eq!(
            current.iter().filter(|f| f.file_hash.is_some()).count(),
            MAX_HASH_FILES
        );
        assert!(current.last().unwrap().file_hash.is_none());
        std::fs::write(dir.path().join("prior.rs"), "prior\n").unwrap();
        let hash = hash_repo_file(dir.path(), "prior.rs").unwrap();
        let prior = PriorIndex::from_report(
            "p.json",
            &report(
                "/repo",
                2,
                vec![finding(
                    "prior.rs",
                    "prior",
                    FindingStatus::Candidate,
                    Some(&hash),
                )],
            ),
        );
        let mut info = PriorRunInfo::default();
        carry_unrediscovered(dir.path(), &mut current, &prior, &mut info);
        assert_eq!(info.carried_not_rediscovered, 1);
        assert_eq!(info.hash_budget_exhausted, 0);
        assert_eq!(info.carried_not_rediscovered_overflow, 0);
        assert!(
            current
                .iter()
                .any(|f| f.file == "prior.rs" && is_carried(f))
        );
    }

    #[test]
    fn prior_byte_budget_is_cached_and_checked_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["current.rs", "prior.rs", "overflow.rs"] {
            std::fs::write(dir.path().join(path), "abc").unwrap();
        }
        let mut current = vec![finding(
            "current.rs",
            "current",
            FindingStatus::Candidate,
            None,
        )];
        fill_file_hashes(dir.path(), &mut current);
        let mut budget = HashBudget::default();
        assert_eq!(budget.remaining_bytes, MAX_HASH_BYTES);
        assert_eq!(
            budget.hash(dir.path(), "current.rs").unwrap(),
            current[0].file_hash
        );
        assert_eq!(budget.remaining_bytes, MAX_HASH_BYTES - 3);
        budget.hash(dir.path(), "current.rs").unwrap();
        assert_eq!(budget.remaining_bytes, MAX_HASH_BYTES - 3);
        // Small remaining budget exercises the same boundary without large fixtures.
        budget.remaining_bytes = 3;
        let hash = current[0].file_hash.clone();
        let prior = PriorIndex::from_report(
            "p.json",
            &report(
                "/repo",
                2,
                vec![
                    finding(
                        "prior.rs",
                        "prior",
                        FindingStatus::Candidate,
                        hash.as_deref(),
                    ),
                    finding(
                        "overflow.rs",
                        "overflow",
                        FindingStatus::Candidate,
                        hash.as_deref(),
                    ),
                ],
            ),
        );
        let mut info = PriorRunInfo::default();
        carry_with_budget(dir.path(), &mut current, &prior, &mut info, &mut budget);
        assert_eq!(info.carried_not_rediscovered, 1);
        assert_eq!(info.hash_budget_exhausted, 1);
        assert_eq!(info.carried_not_rediscovered_overflow, 1);
        assert_eq!(budget.remaining_bytes, 0);
        assert!(!budget.files.contains_key("overflow.rs"));
    }

    #[test]
    fn oversized_file_does_not_exhaust_budget_or_stop_prior_carry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("large.rs"), "abcdef").unwrap();
        std::fs::write(dir.path().join("small.rs"), "abc").unwrap();
        let hash = hash_repo_file(dir.path(), "small.rs").unwrap();
        let mut budget = HashBudget {
            per_file_limit: 3,
            ..Default::default()
        };
        assert_eq!(budget.hash(dir.path(), "large.rs"), Ok(None));
        assert_eq!(budget.remaining_bytes, MAX_HASH_BYTES);
        let prior = PriorIndex::from_report(
            "p.json",
            &report(
                "/repo",
                2,
                vec![
                    finding("large.rs", "large", FindingStatus::Candidate, Some("h")),
                    finding("small.rs", "small", FindingStatus::Candidate, Some(&hash)),
                ],
            ),
        );
        let mut findings = vec![];
        let mut info = PriorRunInfo::default();
        carry_with_budget(dir.path(), &mut findings, &prior, &mut info, &mut budget);
        assert_eq!(info.changed_unrediscovered.len(), 1);
        assert_eq!(info.changed_unrediscovered[0].file, "large.rs");
        assert_eq!(
            info.changed_unrediscovered[0].reason,
            "missing_or_unreadable"
        );
        assert_eq!(info.carried_not_rediscovered, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "small.rs");
        assert_eq!(info.hash_budget_exhausted, 0);
        assert_eq!(info.carried_not_rediscovered_overflow, 0);
        assert_eq!(budget.remaining_bytes, MAX_HASH_BYTES - 3);
    }

    #[test]
    fn cached_budget_failure_is_not_misreported_as_missing_source() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("large.rs"), "abcdef").unwrap();
        let mut budget = HashBudget {
            remaining_bytes: 3,
            ..Default::default()
        };
        assert!(budget.hash(dir.path(), "large.rs").is_err());
        assert!(budget.hash(dir.path(), "large.rs").is_err());
        let prior = PriorIndex::from_report(
            "p.json",
            &report(
                "/repo",
                2,
                vec![finding(
                    "large.rs",
                    "prior",
                    FindingStatus::Candidate,
                    Some("h"),
                )],
            ),
        );
        let mut info = PriorRunInfo::default();
        carry_with_budget(dir.path(), &mut vec![], &prior, &mut info, &mut budget);
        assert_eq!(info.hash_budget_exhausted, 1);
        assert_eq!(info.carried_not_rediscovered_overflow, 1);
        assert!(info.changed_unrediscovered.is_empty());
        assert_eq!(budget.remaining_bytes, 3);
    }

    #[test]
    fn current_hashing_uses_the_same_distinct_file_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut findings: Vec<_> = (0..MAX_HASH_FILES + 1)
            .map(|i| {
                finding(
                    &format!("missing-{i}.rs"),
                    "rule",
                    FindingStatus::Candidate,
                    None,
                )
            })
            .collect();
        let mut budget = HashBudget::default();
        for finding in &mut findings {
            finding.file_hash = budget.hash(dir.path(), &finding.file).ok().flatten();
        }
        assert_eq!(budget.files.len(), MAX_HASH_FILES);
        assert!(!budget.files.contains_key("missing-200.rs"));
    }

    #[test]
    fn streamed_line_counts_match_precheck_semantics_without_another_read() {
        use super::super::precheck::LineOracle;
        let dir = tempfile::tempdir().unwrap();
        for contents in ["", "abc", "a\nb\n", "a\r\nb\r", "\n\n"] {
            std::fs::write(dir.path().join("a.rs"), contents).unwrap();
            let mut budget = HashBudget::default();
            budget.hash(dir.path(), "a.rs").unwrap();
            let bytes_left = budget.remaining_bytes;
            {
                let oracle = BudgetLines {
                    root: dir.path(),
                    budget: std::cell::RefCell::new(&mut budget),
                    exhausted: std::cell::Cell::new(false),
                };
                let path = vettalon_contract::safe_path::SafeRepoPath::parse("a.rs").unwrap();
                assert_eq!(oracle.line_count(&path), Some(contents.lines().count()));
                assert!(!oracle.exhausted.get());
            }
            assert_eq!(budget.remaining_bytes, bytes_left);
        }
    }
}
