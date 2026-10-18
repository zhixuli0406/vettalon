//! Report validator.
//!
//! The semantic invariants of an [`AuditReport`] are checked by this code,
//! not trusted to the pipeline that produced the report. `write_json_report`
//! (and therefore `--save`) runs it before writing anything: a report with a
//! violation is never written, the violations are printed and the command
//! exits 2. `vettalon validate <report.json>` runs it on a file.
//!
//! Interpretations where the design is silent:
//! - Status provenance. An operator decision (dashboard) is recorded by the
//!   gateway as an `operator_review` evidence item plus
//!   `severity_basis = operator` (contract on `EvidenceKind::OperatorReview`).
//!   `Confirmed` is valid only with that operator provenance (either
//!   marker). `Refuted` and `Suppressed` are valid with operator provenance
//!   OR an `adversarial_review` evidence item (verifier verdict, pre-check,
//!   or `carried_from_prior:`).
//! - Summary after a dashboard edit: the gateway recomputes
//!   `by_severity` / `needs_human_by_severity` (rule:
//!   `schema::severity_buckets`) and `ai_audit_refuted` /
//!   `ai_audit_needs_human`, so every summary field is compared strictly,
//!   operator-edited or not. Blockers left on a
//!   former `NeedsHuman` finding the operator settled are allowed.
//! - `verifier.independence = not_run` means no finding carries evidence
//!   from the verifier (`source == "adversarial"`).
//! - A finding the pre-check refuted keeps the model's claim verbatim (it
//!   is the record of why it was refuted), so the file / line / trace
//!   location rules are not applied to it.
//! - Coverage status shape: `candidate` ⇔ non-empty `candidate_ids`;
//!   `covered` has none; `deferred` has no reviewed paths.

use std::collections::HashSet;
use std::fmt;

use vettalon_contract::coverage::RunStatus;
use vettalon_contract::fingerprint::Fingerprint;
use vettalon_contract::safe_path::SafeRepoPath;

use super::precheck::trace_shape_violations;
use super::schema::{
    AI_AUDIT_ENGINE_NAME, AuditReport, CURRENT_SCHEMA_VERSION, EvidenceKind, Finding,
    FindingStatus, GatePolicy, ModuleCoverage, ModuleCoverageStatus, PLAUSIBLE_PREFIX,
    SeverityBasis, Summary, VERIFIER_CORRECTED_PREFIX, VerifierIndependence, VoteVerdict,
    has_operator_review,
};

/// Closed set of report violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportViolation {
    SchemaVersion {
        found: u32,
    },
    DuplicateFindingId {
        id: String,
    },
    UnsafeFindingPath {
        id: String,
        detail: String,
    },
    LineZero {
        id: String,
    },
    InvalidRootFingerprint {
        id: String,
    },
    ProofShape {
        id: String,
        detail: String,
    },
    TraceShape {
        id: String,
        detail: String,
    },
    RefutedWithoutReviewEvidence {
        id: String,
    },
    NeedsHumanWithoutPlausible {
        id: String,
    },
    NeedsHumanWithoutBlockers {
        id: String,
    },
    NeedsHumanWithoutValidationPlan {
        id: String,
    },
    BlockersOnNonNeedsHuman {
        id: String,
    },
    StatusWithoutProvenance {
        id: String,
        status: FindingStatus,
    },
    SeverityBasisMismatch {
        id: String,
        engine: String,
        basis: SeverityBasis,
    },
    SummaryMismatch {
        field: &'static str,
    },
    DuplicateCoverageModule {
        module_path: String,
    },
    CoverageCandidateMissing {
        module_path: String,
        id: String,
    },
    CoverageStatusShape {
        module_path: String,
        detail: String,
    },
    IncompleteWithoutReason,
    CompleteWithReason,
    VerifierInconsistent {
        detail: String,
    },
    /// A finding carrying a `verifier_corrected:` evidence item must have
    /// `precheck.passed == true`.
    CorrectedWithoutPassedPrecheck {
        id: String,
    },
}

impl fmt::Display for ReportViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ReportViolation::*;
        match self {
            SchemaVersion { found } => {
                write!(
                    f,
                    "schema_version is {found}, expected {CURRENT_SCHEMA_VERSION}"
                )
            }
            DuplicateFindingId { id } => write!(f, "finding id {id} appears more than once"),
            UnsafeFindingPath { id, detail } => {
                write!(
                    f,
                    "finding {id}: file is not a safe repo-relative path ({detail})"
                )
            }
            LineZero { id } => write!(f, "finding {id}: line must be >= 1"),
            InvalidRootFingerprint { id } => {
                write!(f, "finding {id}: root_fingerprint is missing or malformed")
            }
            ProofShape { id, detail } => write!(f, "finding {id}: proof shape: {detail}"),
            TraceShape { id, detail } => write!(f, "finding {id}: trace shape: {detail}"),
            RefutedWithoutReviewEvidence { id } => write!(
                f,
                "finding {id}: refuted without adversarial_review evidence (verifier, precheck or carried) or an operator decision"
            ),
            NeedsHumanWithoutPlausible { id } => {
                write!(
                    f,
                    "finding {id}: needs_human without a plausible verdict in evidence"
                )
            }
            NeedsHumanWithoutBlockers { id } => {
                write!(f, "finding {id}: needs_human with empty blockers")
            }
            NeedsHumanWithoutValidationPlan { id } => {
                write!(f, "finding {id}: needs_human without a validation plan")
            }
            BlockersOnNonNeedsHuman { id } => {
                write!(
                    f,
                    "finding {id}: blockers set on a finding that is not needs_human"
                )
            }
            StatusWithoutProvenance { id, status } => write!(
                f,
                "finding {id}: status {status:?} must come from an operator decision (or, for suppressed, review/carried evidence)"
            ),
            SeverityBasisMismatch { id, engine, basis } => write!(
                f,
                "finding {id}: severity_basis {basis:?} does not match engine {engine}"
            ),
            SummaryMismatch { field } => {
                write!(f, "summary.{field} does not match the findings/coverage")
            }
            DuplicateCoverageModule { module_path } => {
                write!(f, "coverage lists module {module_path} more than once")
            }
            CoverageCandidateMissing { module_path, id } => write!(
                f,
                "coverage module {module_path} references finding {id} which is not in findings"
            ),
            CoverageStatusShape {
                module_path,
                detail,
            } => write!(f, "coverage module {module_path}: {detail}"),
            IncompleteWithoutReason => {
                write!(f, "run_status is incomplete but incomplete_reason is null")
            }
            CompleteWithReason => {
                write!(f, "run_status is complete but incomplete_reason is set")
            }
            VerifierInconsistent { detail } => write!(f, "verifier: {detail}"),
            CorrectedWithoutPassedPrecheck { id } => write!(
                f,
                "finding {id}: carries a verifier_corrected record but precheck.passed is not true"
            ),
        }
    }
}

impl std::error::Error for ReportViolation {}

fn check_finding(f: &Finding, out: &mut Vec<ReportViolation>) {
    for detail in super::poc::proof_violations(f) {
        out.push(ReportViolation::ProofShape {
            id: f.id.clone(),
            detail,
        });
    }
    let id = || f.id.clone();
    // A pre-check refutation keeps the model's claim verbatim (an unsafe
    // path, line 0, a malformed trace) as the record of WHY it was refuted;
    // the location rules apply to every other finding.
    let refuted_by_precheck = f.precheck_failed() && f.status == FindingStatus::Refuted;
    if !refuted_by_precheck {
        if let Err(e) = SafeRepoPath::parse(&f.file) {
            out.push(ReportViolation::UnsafeFindingPath {
                id: id(),
                detail: e.to_string(),
            });
        }
        if f.line == Some(0) {
            out.push(ReportViolation::LineZero { id: id() });
        }
    }
    if Fingerprint::parse(&f.root_fingerprint).is_err() {
        out.push(ReportViolation::InvalidRootFingerprint { id: id() });
    }
    if !refuted_by_precheck {
        for (i, step) in f.trace.iter().enumerate() {
            if step.line == 0 {
                out.push(ReportViolation::TraceShape {
                    id: id(),
                    detail: format!("trace[{i}].line must be >= 1"),
                });
            }
            if let Err(e) = SafeRepoPath::parse(&step.file) {
                out.push(ReportViolation::TraceShape {
                    id: id(),
                    detail: format!("trace[{i}].file unsafe ({e})"),
                });
            }
        }
        for v in trace_shape_violations(&f.trace) {
            out.push(ReportViolation::TraceShape {
                id: id(),
                detail: v,
            });
        }
    }

    let has_review = f
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::AdversarialReview);
    let by_operator = has_operator_review(f) || f.severity_basis == SeverityBasis::Operator;
    match f.status {
        FindingStatus::Refuted if !(has_review || by_operator) => {
            out.push(ReportViolation::RefutedWithoutReviewEvidence { id: id() })
        }
        FindingStatus::NeedsHuman => {
            let plausible = f.evidence.iter().any(|e| {
                e.kind == EvidenceKind::AdversarialReview && e.detail.starts_with(PLAUSIBLE_PREFIX)
            });
            if !plausible {
                out.push(ReportViolation::NeedsHumanWithoutPlausible { id: id() });
            }
            if f.blockers.is_empty() {
                out.push(ReportViolation::NeedsHumanWithoutBlockers { id: id() });
            }
            if f.validation_plan.as_ref().is_none_or(|p| p.is_empty()) {
                out.push(ReportViolation::NeedsHumanWithoutValidationPlan { id: id() });
            }
        }
        FindingStatus::Suppressed if !(has_review || by_operator) => {
            out.push(ReportViolation::StatusWithoutProvenance {
                id: id(),
                status: f.status,
            })
        }
        FindingStatus::Confirmed if !by_operator => {
            out.push(ReportViolation::StatusWithoutProvenance {
                id: id(),
                status: f.status,
            })
        }
        _ => {}
    }
    // An operator decision on a former NeedsHuman finding keeps the
    // verifier's blockers as history (the gateway only changes status).
    if f.status != FindingStatus::NeedsHuman && !f.blockers.is_empty() && !by_operator {
        out.push(ReportViolation::BlockersOnNonNeedsHuman { id: id() });
    }

    // A verifier correction is only ever applied to a finding that passed
    // the pre-check (and the corrected values re-passed it).
    let corrected = f
        .evidence
        .iter()
        .any(|e| e.detail.starts_with(VERIFIER_CORRECTED_PREFIX));
    if corrected && !f.precheck.as_ref().is_some_and(|p| p.passed) {
        out.push(ReportViolation::CorrectedWithoutPassedPrecheck { id: id() });
    }

    let is_ai = f.source_engine == AI_AUDIT_ENGINE_NAME;
    let basis_ok = match f.severity_basis {
        SeverityBasis::Operator => true,
        SeverityBasis::ModelSelfReported => is_ai,
        SeverityBasis::ScannerRule => !is_ai,
    };
    if !basis_ok {
        out.push(ReportViolation::SeverityBasisMismatch {
            id: id(),
            engine: f.source_engine.clone(),
            basis: f.severity_basis,
        });
    }
}

fn check_summary(r: &AuditReport, out: &mut Vec<ReportViolation>) {
    let expect = Summary::from_findings(
        &r.findings,
        r.engines_run.len(),
        r.engines_missing.len(),
        GatePolicy {
            include_needs_human: r.summary.gate_includes_needs_human,
        },
        &r.coverage,
    );
    let got = &r.summary;
    // Each stored condition must be one the `--gate` parser could produce
    // (rejects e.g. `count>=0`, empty or closed statuses written by hand),
    // and its outcome must match the findings. This proves consistency, not
    // provenance: a report edited to drop a condition still validates — the
    // CI exit code at scan time is the authoritative gate.
    let policy_same = got.policy.iter().all(|g| {
        g.condition
            .to_string()
            .parse::<crate::audit::gate::GateCondition>()
            .is_ok_and(|c| c == g.condition)
    }) && got.policy == crate::audit::gate::reevaluate(&got.policy, &r.findings);
    let mut field = |name: &'static str, same: bool| {
        if !same {
            out.push(ReportViolation::SummaryMismatch { field: name });
        }
    };
    field(
        "total_findings",
        got.total_findings == expect.total_findings,
    );
    field("by_severity", got.by_severity == expect.by_severity);
    field("policy", policy_same);
    field(
        "engines_run_count",
        got.engines_run_count == expect.engines_run_count,
    );
    field(
        "engines_missing_count",
        got.engines_missing_count == expect.engines_missing_count,
    );
    field(
        "ai_audit_candidates",
        got.ai_audit_candidates == expect.ai_audit_candidates,
    );
    field(
        "ai_audit_refuted",
        got.ai_audit_refuted == expect.ai_audit_refuted,
    );
    field(
        "ai_audit_needs_human",
        got.ai_audit_needs_human == expect.ai_audit_needs_human,
    );
    field("poc_ran", got.poc_ran == expect.poc_ran);
    field(
        "needs_human_by_severity",
        got.needs_human_by_severity == expect.needs_human_by_severity,
    );
    field("coverage", got.coverage == expect.coverage);
    field(
        "precheck_refuted",
        got.precheck_refuted == expect.precheck_refuted,
    );
    field(
        "carried_from_prior",
        got.carried_from_prior == expect.carried_from_prior,
    );
}

fn check_coverage(r: &AuditReport, ids: &HashSet<&str>, out: &mut Vec<ReportViolation>) {
    let modern = r.coverage.iter().any(ModuleCoverage::has_ledger);
    if modern
        && super::schema::CoverageSummary::from_coverage(&r.coverage).partial
        && r.run_status == RunStatus::Complete
    {
        out.push(ReportViolation::CoverageStatusShape {
            module_path: "(run)".into(),
            detail: "new coverage evidence is partial but run_status is complete".into(),
        });
    }
    let mut seen: HashSet<&str> = HashSet::new();
    for m in &r.coverage {
        if !seen.insert(m.module_path.as_str()) {
            out.push(ReportViolation::DuplicateCoverageModule {
                module_path: m.module_path.clone(),
            });
        }
        for cid in &m.candidate_ids {
            if !ids.contains(cid.as_str()) {
                out.push(ReportViolation::CoverageCandidateMissing {
                    module_path: m.module_path.clone(),
                    id: cid.clone(),
                });
            }
        }
        let shape = |detail: &str| ReportViolation::CoverageStatusShape {
            module_path: m.module_path.clone(),
            detail: detail.to_string(),
        };
        if modern {
            use super::schema::FileReadStatus;
            let partial =
                super::schema::CoverageSummary::from_coverage(std::slice::from_ref(m)).partial;
            if partial && r.run_status == RunStatus::Complete {
                out.push(shape(
                    "new coverage evidence is partial but run_status is complete",
                ));
            }
            if m.status == ModuleCoverageStatus::Covered && partial {
                out.push(shape(
                    "covered status with incomplete source or finder evidence",
                ));
            }
            if !m.selected && !m.attempts.is_empty() {
                out.push(shape("finder attempts exist on an unselected module"));
            }
            if m.scope_paths
                .iter()
                .any(|p| SafeRepoPath::parse(p).is_err())
            {
                out.push(shape("scope contains an unsafe repository path"));
            }
            let scope: HashSet<&str> = m.scope_paths.iter().map(String::as_str).collect();
            if scope.len() != m.scope_paths.len() {
                out.push(shape(
                    "duplicate scope paths cannot define a source denominator",
                ));
            }
            if m.status.has_valid_reply() && !m.has_effective_review() {
                out.push(shape("reviewed status requires selected, nonempty source scope and a valid attempt with effective content"));
            }
            if m.status == ModuleCoverageStatus::Covered && !m.has_full_review() {
                out.push(shape(
                    "covered status requires every finder to review its full nonempty source scope",
                ));
            }

            let mut reviewed = HashSet::new();
            for attempt in &m.attempts {
                use super::schema::{SourceCallKind, SourceCallResponse};
                let valid_reply = matches!(
                    attempt.status,
                    ModuleCoverageStatus::Covered
                        | ModuleCoverageStatus::Candidate
                        | ModuleCoverageStatus::PartiallyReviewed
                );
                let digest_ok = |v: &str| {
                    v.len() == 64
                        && v.bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                };
                if let Some(receipt) = &attempt.source_receipt {
                    if receipt.calls.is_empty()
                        || receipt.calls[0].kind != SourceCallKind::Primary
                        || receipt.calls[1..]
                            .iter()
                            .any(|call| call.kind != SourceCallKind::Reflector)
                    {
                        out.push(shape(
                            "source receipt has no primary call or invalid call order",
                        ));
                    }
                    let valid_calls = receipt.calls.iter().filter(|c| c.valid_reply).count();
                    if valid_calls != usize::from(valid_reply) {
                        out.push(shape(
                            "source receipt valid reply does not match attempt status",
                        ));
                    }
                    for call in &receipt.calls {
                        if call.prompt_bytes == 0 || !digest_ok(&call.prompt_sha256) {
                            out.push(shape(
                                "source receipt has invalid prompt hash or byte count",
                            ));
                        }
                        if call.valid_reply && call.response != SourceCallResponse::Returned {
                            out.push(shape(
                                "source receipt claims valid reply without observed response",
                            ));
                        }
                    }
                }
                if valid_reply {
                    if !attempt.files.iter().any(|file| {
                        file.read_status == FileReadStatus::Included && file.submitted_bytes > 0
                    }) {
                        out.push(shape("valid reply attempt has no effective content"));
                    }
                    let accounted: HashSet<&str> =
                        attempt.files.iter().map(|f| f.path.as_str()).collect();
                    if accounted != scope || attempt.files.len() != scope.len() {
                        out.push(shape(
                            "reviewed attempt does not account for every scope path exactly once",
                        ));
                    }
                }
                for file in &attempt.files {
                    if let Some(hash) = &file.source_sha256
                        && (!digest_ok(hash) || file.source_bytes.is_none())
                    {
                        out.push(shape(
                            "source snapshot hash is invalid or has no source bytes",
                        ));
                    }
                    if let Some(hash) = &file.submitted_sha256
                        && (!digest_ok(hash) || file.submitted_bytes == 0)
                    {
                        out.push(shape(
                            "submitted source hash is invalid or has no submitted bytes",
                        ));
                    }
                    if file.submitted_sha256.is_some() && attempt.source_receipt.is_none() {
                        out.push(shape("submitted source hash has no call receipt"));
                    }
                    if attempt.source_receipt.is_some()
                        && file.source_bytes.is_some()
                        && file.source_sha256.is_none()
                    {
                        out.push(shape("source receipt is missing source snapshot hash"));
                    }
                    if attempt.source_receipt.is_some()
                        && file.submitted_bytes > 0
                        && file.submitted_sha256.is_none()
                    {
                        out.push(shape("source receipt is missing submitted source hash"));
                    }
                    if !file.truncated
                        && file.submitted_bytes > 0
                        && file.source_sha256 != file.submitted_sha256
                    {
                        out.push(shape(
                            "full submitted source hash differs from source snapshot",
                        ));
                    }
                    if !scope.contains(file.path.as_str()) {
                        out.push(shape("attempt file is outside scope_paths"));
                    }
                    let included = file.read_status == FileReadStatus::Included;
                    if included && file.submitted_bytes == 0 {
                        out.push(shape("included file has no submitted content"));
                    }
                    if !included
                        && (file.submitted_bytes > 0
                            || file.start_line.is_some()
                            || file.end_line.is_some())
                    {
                        out.push(shape("excluded file claims submitted content"));
                    }
                    if file.submitted_bytes > 0
                        && (file.start_line != Some(1) || file.end_line.is_none_or(|n| n == 0))
                    {
                        out.push(shape("submitted file has no valid line range"));
                    }
                    if file.source_bytes.is_some_and(|n| file.submitted_bytes > n) {
                        out.push(shape("submitted bytes exceed source bytes"));
                    }
                    if included {
                        match (file.source_bytes, file.source_lines, file.end_line) {
                            (Some(bytes), Some(lines), Some(end)) if bytes > 0 && lines > 0 => {
                                if file.truncated != (file.submitted_bytes < bytes) {
                                    out.push(shape(
                                        "truncation does not match submitted/source byte counts",
                                    ));
                                }
                                if end > lines || (!file.truncated && end != lines) {
                                    out.push(shape(
                                        "submitted line range exceeds or contradicts source lines",
                                    ));
                                }
                            }
                            _ => out.push(shape("included file is missing valid source metadata")),
                        }
                    }
                    if valid_reply && included {
                        reviewed.insert(file.path.as_str());
                    }
                }
            }
            let truncated: HashSet<&str> = m
                .attempts
                .iter()
                .flat_map(|a| a.files.iter())
                .filter(|f| f.truncated)
                .map(|f| f.path.as_str())
                .collect();
            let reported_truncated: HashSet<&str> =
                m.truncated_paths.iter().map(String::as_str).collect();
            if truncated != reported_truncated {
                out.push(shape("truncated_paths do not match finder file evidence"));
            }
            let aggregate: HashSet<&str> = m.reviewed_paths.iter().map(String::as_str).collect();
            if reviewed != aggregate {
                out.push(shape("reviewed_paths do not match valid finder replies"));
            }
        }
        match m.status {
            ModuleCoverageStatus::Candidate if m.candidate_ids.is_empty() => {
                out.push(shape("candidate status with no candidate_ids"))
            }
            ModuleCoverageStatus::Covered if !m.candidate_ids.is_empty() => {
                out.push(shape("covered status with candidate_ids"))
            }
            ModuleCoverageStatus::Deferred if !m.reviewed_paths.is_empty() => {
                out.push(shape("deferred status with reviewed_paths"))
            }
            ModuleCoverageStatus::Deferred if m.reason.is_none() => {
                out.push(shape("deferred status without a reason"))
            }
            s if s.is_failed() && m.reason.is_none() => {
                out.push(shape("failed status without a reason"))
            }
            _ => {}
        }
    }
}

fn check_verifier(r: &AuditReport, out: &mut Vec<ReportViolation>) {
    let v = &r.verifier;
    let mut bad = |detail: &str| {
        out.push(ReportViolation::VerifierInconsistent {
            detail: detail.to_string(),
        })
    };
    let vettalon_report = !r.ensemble.models.is_empty();
    match v.independence {
        // Legacy single-agent states; a vettalon run never emits them.
        VerifierIndependence::SameAgent | VerifierIndependence::DifferentAgent
            if vettalon_report =>
        {
            bad("legacy same_agent/different_agent independence in a multi-model report")
        }
        VerifierIndependence::SameAgent if v.audit_agent != v.verifier_agent => {
            bad("independence same_agent but audit_agent differs from verifier_agent")
        }
        VerifierIndependence::DifferentAgent if v.audit_agent == v.verifier_agent => {
            bad("independence different_agent but audit_agent equals verifier_agent")
        }
        // Legacy reports: not_run means no verifier evidence at all. A
        // vettalon report may carry zero-LLM settlements and failed calls
        // under not_run; `check_ensemble` checks it against the votes.
        VerifierIndependence::NotRun if !vettalon_report => {
            let any = r
                .findings
                .iter()
                .flat_map(|f| f.evidence.iter())
                .any(|e| e.source == "adversarial");
            if any {
                bad("independence not_run but findings carry verifier evidence");
            }
        }
        _ => {}
    }
    check_ensemble(r, out);
}

/// vettalon ensemble rules: votes name roster models, `cross_family` is
/// what the roster says it is, and `independence` matches the votes.
fn check_ensemble(r: &AuditReport, out: &mut Vec<ReportViolation>) {
    let mut bad = |detail: String| out.push(ReportViolation::VerifierInconsistent { detail });
    let family_of = |id: &str| {
        r.ensemble
            .models
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.family.as_str())
    };
    let roster = !r.ensemble.models.is_empty();
    let (mut cross, mut same) = (0usize, 0usize);
    for f in &r.findings {
        if roster {
            for m in &f.found_by {
                if family_of(m).is_none() {
                    bad(format!("finding {} found_by unknown model {m}", f.id));
                }
            }
        }
        for v in &f.verification {
            if roster {
                match family_of(&v.model) {
                    None => bad(format!(
                        "finding {} voted on by unknown model {}",
                        f.id, v.model
                    )),
                    Some(fam) if fam != v.family => bad(format!(
                        "finding {} vote family {} != roster {fam}",
                        f.id, v.family
                    )),
                    Some(fam) => {
                        let expect = !f.found_by.iter().any(|m| family_of(m) == Some(fam));
                        if expect != v.cross_family {
                            bad(format!(
                                "finding {} vote by {} has wrong cross_family",
                                f.id, v.model
                            ));
                        }
                    }
                }
            }
            if v.same_model && (v.cross_family || !f.found_by.contains(&v.model)) {
                bad(format!(
                    "finding {} vote by {} marked same_model inconsistently",
                    f.id, v.model
                ));
            }
            // Only a settled vote is a review; a failed call is not.
            if v.verdict == VoteVerdict::NoVerdict {
                continue;
            }
            if v.cross_family {
                cross += 1;
            } else {
                same += 1;
            }
        }
    }
    let ok = match r.verifier.independence {
        VerifierIndependence::CrossFamily => cross > 0 && same == 0,
        VerifierIndependence::MixedFamily => cross > 0 && same > 0,
        VerifierIndependence::SameFamily => cross == 0 && same > 0,
        VerifierIndependence::NotRun => cross + same == 0,
        _ => true,
    };
    if !ok {
        bad(format!(
            "independence {:?} does not match settled votes ({cross} cross-family, {same} same-family)",
            r.verifier.independence
        ));
    }
}

/// Check every rule in the module doc. Empty ⇒ valid.
pub fn validate_report(r: &AuditReport) -> Vec<ReportViolation> {
    let mut out = Vec::new();
    if r.schema_version != CURRENT_SCHEMA_VERSION {
        out.push(ReportViolation::SchemaVersion {
            found: r.schema_version,
        });
    }
    let mut ids: HashSet<&str> = HashSet::new();
    for f in &r.findings {
        if !ids.insert(f.id.as_str()) {
            out.push(ReportViolation::DuplicateFindingId { id: f.id.clone() });
        }
        check_finding(f, &mut out);
    }
    check_summary(r, &mut out);
    check_coverage(r, &ids, &mut out);
    match (r.run_status, r.incomplete_reason) {
        (RunStatus::Incomplete, None) => out.push(ReportViolation::IncompleteWithoutReason),
        (RunStatus::Complete, Some(_)) => out.push(ReportViolation::CompleteWithReason),
        _ => {}
    }
    check_verifier(r, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{
        CARRIED_FROM_PRIOR_PREFIX, EvidenceItem, FindingKind, ModuleCoverage, ProfileMode,
        ScanProfile, Severity, TraceKind, TraceStep, ValidationPlan, VerifierInfo,
    };
    use vettalon_contract::coverage::IncompleteReason;

    fn ev(source: &str, detail: &str) -> EvidenceItem {
        EvidenceItem {
            kind: EvidenceKind::AdversarialReview,
            source: source.into(),
            detail: detail.into(),
            recorded_at: "t".into(),
        }
    }

    fn scanner(file: &str) -> Finding {
        Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::High,
            "t",
            file,
            Some(1),
            "s",
            "r",
            vec![],
        )
    }

    fn ai(file: &str) -> Finding {
        let mut f = Finding::candidate(
            AI_AUDIT_ENGINE_NAME,
            FindingKind::Other,
            Severity::High,
            "t",
            file,
            Some(1),
            "s",
            "ai-audit/x",
            vec![],
        );
        f.trace = vec![TraceStep {
            kind: TraceKind::Sink,
            file: file.into(),
            line: 1,
            scope: "f".into(),
            description: "d".into(),
        }];
        f
    }

    fn needs_human(file: &str) -> Finding {
        let mut f = ai(file);
        f.status = FindingStatus::NeedsHuman;
        f.blockers = vec!["b".into()];
        f.validation_plan = Some(ValidationPlan {
            local: Some("x".into()),
            deployment: None,
        });
        f.evidence.push(ev("adversarial", "plausible: r"));
        f
    }

    /// A report whose summary is recomputed from its findings (so only the
    /// rule under test can fail).
    fn report(findings: Vec<Finding>, coverage: Vec<ModuleCoverage>) -> AuditReport {
        let any_adv = findings
            .iter()
            .flat_map(|f| f.evidence.iter())
            .any(|e| e.source == "adversarial");
        AuditReport {
            schema_version: CURRENT_SCHEMA_VERSION,
            repo: "/repo".into(),
            started_at: "t".into(),
            profile: ScanProfile {
                mode: ProfileMode::Deep,
                intake: None,
            },
            engines_run: vec![],
            engines_missing: vec![],
            summary: Summary::from_findings(&findings, 0, 0, GatePolicy::default(), &coverage),
            findings,
            run_status: RunStatus::Complete,
            incomplete_reason: None,
            coverage,
            prior_run: None,
            verifier: VerifierInfo {
                independence: if any_adv {
                    VerifierIndependence::SameAgent
                } else {
                    VerifierIndependence::NotRun
                },
                audit_agent: None,
                verifier_agent: None,
            },
            ensemble: Default::default(),
        }
    }

    fn only(r: &AuditReport) -> Vec<ReportViolation> {
        validate_report(r)
    }

    #[test]
    fn a_well_formed_report_is_valid() {
        let mut refuted = ai("src/b.rs");
        refuted.status = FindingStatus::Refuted;
        refuted.evidence.push(ev("adversarial", "refuted: no"));
        let cov = vec![ModuleCoverage {
            module_path: "src".into(),
            status: ModuleCoverageStatus::Candidate,
            reason: None,
            reviewed_paths: vec!["src/a.rs".into()],
            truncated_paths: vec![],
            candidate_ids: vec![refuted.id.clone()],
            scope_paths: vec![],
            selected: false,
            attempts: vec![],
        }];
        let r = report(
            vec![scanner("src/a.rs"), needs_human("src/c.rs"), refuted],
            cov,
        );
        assert_eq!(only(&r), vec![]);
    }

    #[test]
    fn schema_version_must_be_2() {
        let mut r = report(vec![], vec![]);
        r.schema_version = 1;
        assert_eq!(only(&r), vec![ReportViolation::SchemaVersion { found: 1 }]);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let a = scanner("src/a.rs");
        let r = report(vec![a.clone(), a.clone()], vec![]);
        assert!(only(&r).contains(&ReportViolation::DuplicateFindingId { id: a.id }));
    }

    #[test]
    fn unsafe_file_line_zero_and_bad_fingerprint() {
        let mut f = scanner("../etc/passwd");
        f.line = Some(0);
        f.root_fingerprint = "!bad".into();
        let id = f.id.clone();
        let v = only(&report(vec![f], vec![]));
        assert!(
            v.iter()
                .any(|x| matches!(x, ReportViolation::UnsafeFindingPath { .. }))
        );
        assert!(v.contains(&ReportViolation::LineZero { id: id.clone() }));
        assert!(v.contains(&ReportViolation::InvalidRootFingerprint { id }));
    }

    #[test]
    fn trace_shape_is_checked_unless_precheck_refuted() {
        let mut f = ai("src/a.rs");
        f.trace[0].kind = TraceKind::Propagation;
        assert!(
            only(&report(vec![f.clone()], vec![]))
                .iter()
                .any(|x| matches!(x, ReportViolation::TraceShape { .. }))
        );
        crate::audit::precheck::apply_precheck(&mut f, vec!["trace[0].kind".into()]);
        assert_eq!(only(&report(vec![f], vec![])), vec![]);
    }

    #[test]
    fn precheck_refuted_hostile_path_is_recorded_not_rejected() {
        let mut f = ai("/etc/passwd");
        f.line = Some(0);
        crate::audit::precheck::apply_precheck(&mut f, vec!["file: unsafe path".into()]);
        assert_eq!(only(&report(vec![f], vec![])), vec![]);
    }

    #[test]
    fn refuted_needs_review_evidence() {
        let mut f = scanner("src/a.rs");
        f.status = FindingStatus::Refuted;
        let id = f.id.clone();
        assert_eq!(
            only(&report(vec![f], vec![])),
            vec![ReportViolation::RefutedWithoutReviewEvidence { id }]
        );
    }

    #[test]
    fn needs_human_needs_plausible_blockers_and_plan() {
        let mut f = needs_human("src/a.rs");
        f.evidence.clear();
        f.blockers.clear();
        f.validation_plan = None;
        let id = f.id.clone();
        let v = only(&report(vec![f], vec![]));
        assert!(v.contains(&ReportViolation::NeedsHumanWithoutPlausible { id: id.clone() }));
        assert!(v.contains(&ReportViolation::NeedsHumanWithoutBlockers { id: id.clone() }));
        assert!(v.contains(&ReportViolation::NeedsHumanWithoutValidationPlan { id }));
    }

    #[test]
    fn blockers_only_on_needs_human() {
        let mut f = scanner("src/a.rs");
        f.blockers = vec!["x".into()];
        let id = f.id.clone();
        assert_eq!(
            only(&report(vec![f], vec![])),
            vec![ReportViolation::BlockersOnNonNeedsHuman { id }]
        );
    }

    #[test]
    fn suppressed_and_confirmed_need_operator_or_carried_provenance() {
        let mut s = scanner("src/a.rs");
        s.status = FindingStatus::Suppressed;
        let mut c = scanner("src/b.rs");
        c.status = FindingStatus::Confirmed;
        let v = only(&report(vec![s.clone(), c.clone()], vec![]));
        assert_eq!(v.len(), 2, "{v:?}");
        s.evidence.push(ev(
            "prior_run",
            &format!("{CARRIED_FROM_PRIOR_PREFIX} p.json"),
        ));
        c.severity_basis = SeverityBasis::Operator;
        assert_eq!(only(&report(vec![s, c], vec![])), vec![]);
    }

    /// The gateway's dashboard write (contract on
    /// `EvidenceKind::OperatorReview`): status + operator_review evidence +
    /// severity_basis operator + by_severity / needs_human_by_severity
    /// recomputed with `severity_buckets`; nothing else in the summary.
    fn operator_edit(r: &mut AuditReport, idx: usize, status: FindingStatus) {
        let f = &mut r.findings[idx];
        f.status = status;
        f.severity_basis = SeverityBasis::Operator;
        f.evidence.push(EvidenceItem {
            kind: EvidenceKind::OperatorReview,
            source: "dashboard".into(),
            detail: format!("operator_decision: {status:?}").to_lowercase(),
            recorded_at: "2026-10-03T00:00:00Z".into(),
        });
        let (by, nh) = crate::audit::schema::severity_buckets(
            &r.findings,
            r.summary.gate_includes_needs_human,
        );
        r.summary.by_severity = by;
        r.summary.needs_human_by_severity = nh;
        r.summary.ai_audit_refuted = r
            .findings
            .iter()
            .filter(|f| {
                f.source_engine == AI_AUDIT_ENGINE_NAME && f.status == FindingStatus::Refuted
            })
            .count();
        r.summary.ai_audit_needs_human = r
            .findings
            .iter()
            .filter(|f| {
                f.source_engine == AI_AUDIT_ENGINE_NAME && f.status == FindingStatus::NeedsHuman
            })
            .count();
    }

    #[test]
    fn operator_decisions_validate_for_each_status() {
        for status in [
            FindingStatus::Confirmed,
            FindingStatus::Suppressed,
            FindingStatus::Refuted,
        ] {
            // A scanner finding and an ai_audit NeedsHuman finding.
            let mut r = report(vec![scanner("src/a.rs"), needs_human("src/c.rs")], vec![]);
            operator_edit(&mut r, 0, status);
            assert_eq!(only(&r), vec![], "scanner -> {status:?}");
            operator_edit(&mut r, 1, status);
            assert_eq!(only(&r), vec![], "needs_human -> {status:?}");
        }
    }

    #[test]
    fn operator_review_evidence_alone_or_basis_alone_is_enough() {
        let mut ev_only = scanner("src/a.rs");
        ev_only.status = FindingStatus::Confirmed;
        ev_only.evidence.push(EvidenceItem {
            kind: EvidenceKind::OperatorReview,
            source: "dashboard".into(),
            detail: "operator_decision: confirmed".into(),
            recorded_at: "t".into(),
        });
        let mut basis_only = scanner("src/b.rs");
        basis_only.status = FindingStatus::Refuted;
        basis_only.severity_basis = SeverityBasis::Operator;
        assert_eq!(only(&report(vec![ev_only, basis_only], vec![])), vec![]);
    }

    #[test]
    fn operator_edit_without_summary_recompute_is_rejected() {
        let mut r = report(vec![scanner("src/a.rs")], vec![]);
        let before = r.summary.clone();
        operator_edit(&mut r, 0, FindingStatus::Suppressed);
        r.summary = before;
        assert!(only(&r).contains(&ReportViolation::SummaryMismatch {
            field: "by_severity"
        }));
    }

    #[test]
    fn operator_edit_with_stale_ai_audit_counters_is_rejected() {
        let mut r = report(vec![needs_human("src/c.rs")], vec![]);
        let stale = r.summary.clone();
        operator_edit(&mut r, 0, FindingStatus::Refuted);
        r.summary.ai_audit_refuted = stale.ai_audit_refuted;
        r.summary.ai_audit_needs_human = stale.ai_audit_needs_human;
        let v = only(&r);
        assert!(v.contains(&ReportViolation::SummaryMismatch {
            field: "ai_audit_refuted"
        }));
        assert!(v.contains(&ReportViolation::SummaryMismatch {
            field: "ai_audit_needs_human"
        }));
    }

    #[test]
    fn confirmed_needs_operator_provenance_even_with_review_evidence() {
        let mut c = ai("src/a.rs");
        c.status = FindingStatus::Confirmed;
        c.evidence.push(ev("adversarial", "plausible: r"));
        let id = c.id.clone();
        let v = only(&report(vec![c], vec![]));
        assert!(v.contains(&ReportViolation::StatusWithoutProvenance {
            id,
            status: FindingStatus::Confirmed
        }));
    }

    #[test]
    fn severity_basis_must_match_engine() {
        let mut a = ai("src/a.rs");
        a.severity_basis = SeverityBasis::ScannerRule;
        let mut b = scanner("src/b.rs");
        b.severity_basis = SeverityBasis::ModelSelfReported;
        let v = only(&report(vec![a, b], vec![]));
        assert_eq!(
            v.iter()
                .filter(|x| matches!(x, ReportViolation::SeverityBasisMismatch { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn summary_must_match_a_recomputation() {
        let mut r = report(vec![scanner("src/a.rs")], vec![]);
        r.summary.by_severity.high = 0;
        r.summary.carried_from_prior = 3;
        let v = only(&r);
        assert!(v.contains(&ReportViolation::SummaryMismatch {
            field: "by_severity"
        }));
        assert!(v.contains(&ReportViolation::SummaryMismatch {
            field: "carried_from_prior"
        }));
    }

    #[test]
    fn coverage_paths_unique_ids_present_and_shapes() {
        let m = |p: &str, status, ids: Vec<String>| ModuleCoverage {
            module_path: p.into(),
            status,
            reason: None,
            reviewed_paths: vec![],
            truncated_paths: vec![],
            candidate_ids: ids,
            scope_paths: vec![],
            selected: false,
            attempts: vec![],
        };
        let cov = vec![
            m("a", ModuleCoverageStatus::Covered, vec![]),
            m("a", ModuleCoverageStatus::Covered, vec![]),
            m("b", ModuleCoverageStatus::Candidate, vec!["ghost".into()]),
            m("c", ModuleCoverageStatus::Candidate, vec![]),
            m("d", ModuleCoverageStatus::Deferred, vec![]),
            m("e", ModuleCoverageStatus::ParseFailed, vec![]),
        ];
        let v = only(&report(vec![], cov));
        assert!(v.contains(&ReportViolation::DuplicateCoverageModule {
            module_path: "a".into()
        }));
        assert!(v.contains(&ReportViolation::CoverageCandidateMissing {
            module_path: "b".into(),
            id: "ghost".into()
        }));
        let shapes = v
            .iter()
            .filter(|x| matches!(x, ReportViolation::CoverageStatusShape { .. }))
            .count();
        assert_eq!(shapes, 3, "{v:?}");
    }

    fn complete_coverage_fixture() -> ModuleCoverage {
        serde_json::from_value(serde_json::json!({
            "module_path": "src", "status": "covered", "reason": null,
            "selected": true, "scope_paths": ["src/a.rs"],
            "reviewed_paths": ["src/a.rs"], "truncated_paths": [], "candidate_ids": [],
            "attempts": [{"model": "mock", "family": "fixture", "status": "covered", "reason": null,
                "duration_ms": 1, "timed_out": false,
                "files": [{"path": "src/a.rs", "read_status": "included", "source_bytes": 1,
                    "source_lines": 1, "submitted_bytes": 1, "start_line": 1, "end_line": 1,
                    "truncated": false, "reason": null}]}]
        }))
        .unwrap()
    }

    #[test]
    fn modern_covered_without_content_is_partial_and_rejected() {
        let valid = complete_coverage_fixture();
        assert!(only(&report(vec![], vec![valid.clone()])).is_empty());
        for scenario in [
            "no_attempts",
            "empty_scope",
            "only_empty_files",
            "failed_attempt",
            "duplicate_scope",
            "candidate_without_attempt",
        ] {
            let mut module = valid.clone();
            match scenario {
                "no_attempts" => {
                    module.attempts.clear();
                    module.reviewed_paths.clear();
                }
                "empty_scope" => {
                    module.scope_paths.clear();
                    module.attempts[0].files.clear();
                    module.reviewed_paths.clear();
                }
                "only_empty_files" => {
                    let file = &mut module.attempts[0].files[0];
                    file.read_status = super::super::schema::FileReadStatus::Empty;
                    file.source_bytes = Some(0);
                    file.source_lines = Some(0);
                    file.submitted_bytes = 0;
                    file.start_line = None;
                    file.end_line = None;
                    module.reviewed_paths.clear();
                }
                "failed_attempt" => {
                    module.attempts[0].status = ModuleCoverageStatus::LlmFailed;
                    module.reviewed_paths.clear();
                }
                "duplicate_scope" => module.scope_paths.push("src/a.rs".into()),
                "candidate_without_attempt" => {
                    module.status = ModuleCoverageStatus::Candidate;
                    module.attempts.clear();
                    module.reviewed_paths.clear();
                }
                _ => unreachable!(),
            }
            let summary =
                super::super::schema::CoverageSummary::from_coverage(std::slice::from_ref(&module));
            assert!(
                summary.partial,
                "{scenario}: missing content must count as partial"
            );
            assert_eq!(
                summary.scanned, 0,
                "{scenario}: malformed evidence must not count as scanned"
            );
            assert!(only(&report(vec![], vec![module])).iter().any(|v| matches!(v,
                ReportViolation::CoverageStatusShape { detail, .. } if detail.contains("effective content") || detail.contains("source scope") || detail.contains("duplicate scope"))), "{scenario}");
        }
    }

    #[test]
    fn modern_ledger_cannot_mix_in_legacy_covered_as_verified() {
        let mut legacy = complete_coverage_fixture();
        legacy.module_path = "legacy".into();
        legacy.selected = false;
        legacy.scope_paths.clear();
        legacy.attempts.clear();
        let legacy_only = report(vec![], vec![legacy.clone()]);
        assert!(
            only(&legacy_only).is_empty(),
            "wholly legacy JSON remains readable and unknown"
        );
        let mixed = vec![complete_coverage_fixture(), legacy];
        let summary = super::super::schema::CoverageSummary::from_coverage(&mixed);
        assert!(summary.partial);
        assert_eq!((summary.scanned, summary.skipped), (1, 1));
        assert!(only(&report(vec![], mixed)).iter().any(|v| matches!(v,
            ReportViolation::CoverageStatusShape { detail, .. } if detail.contains("effective content"))));
    }

    #[test]
    fn new_deferred_scope_without_attempts_cannot_claim_complete() {
        let module = ModuleCoverage {
            module_path: "src".into(),
            status: ModuleCoverageStatus::Deferred,
            reason: Some("max_modules".into()),
            scope_paths: vec!["src/a.rs".into()],
            selected: false,
            reviewed_paths: vec![],
            truncated_paths: vec![],
            candidate_ids: vec![],
            attempts: vec![],
        };
        let mut report = report(vec![], vec![module]);
        assert!(only(&report).iter().any(|v| matches!(v, ReportViolation::CoverageStatusShape { detail, .. } if detail.contains("run_status is complete"))));
        report.run_status = RunStatus::Incomplete;
        report.incomplete_reason = Some(IncompleteReason::ScopeNotFullyReviewed);
        assert!(only(&report).is_empty());
    }

    #[test]
    fn new_partial_coverage_cannot_claim_complete_or_full_coverage() {
        use super::super::schema::{FileCoverage, FileReadStatus, ModuleAttempt};
        let file = FileCoverage {
            path: "src/a.rs".into(),
            read_status: FileReadStatus::Included,
            source_bytes: Some(10),
            source_lines: Some(2),
            submitted_bytes: 5,
            start_line: Some(1),
            end_line: Some(1),
            truncated: true,
            reason: None,
            source_sha256: None,
            submitted_sha256: None,
        };
        let attempt = ModuleAttempt {
            model: "mock".into(),
            family: "mock".into(),
            status: ModuleCoverageStatus::PartiallyReviewed,
            reason: None,
            files: vec![file],
            duration_ms: 1,
            timed_out: false,
            source_receipt: None,
        };
        let module = ModuleCoverage {
            module_path: "src".into(),
            status: ModuleCoverageStatus::PartiallyReviewed,
            reason: None,
            scope_paths: vec!["src/a.rs".into()],
            selected: true,
            reviewed_paths: vec!["src/a.rs".into()],
            truncated_paths: vec!["src/a.rs".into()],
            candidate_ids: vec![],
            attempts: vec![attempt],
        };
        let mut report = report(vec![], vec![module]);
        assert!(only(&report).iter().any(|v| matches!(v, ReportViolation::CoverageStatusShape { detail, .. } if detail.contains("run_status is complete"))));
        report.run_status = RunStatus::Incomplete;
        report.incomplete_reason = Some(IncompleteReason::ScopeNotFullyReviewed);
        assert!(only(&report).is_empty());
        use super::super::schema::{
            SourceCallKind, SourceCallReceipt, SourceCallResponse, SourceReceipt,
        };
        report.coverage[0].attempts[0].files[0].source_sha256 = Some("a".repeat(64));
        report.coverage[0].attempts[0].files[0].submitted_sha256 = Some("b".repeat(64));
        report.coverage[0].attempts[0].source_receipt = Some(SourceReceipt {
            calls: vec![SourceCallReceipt {
                kind: SourceCallKind::Primary,
                prompt_sha256: "c".repeat(64),
                prompt_bytes: 100,
                response: SourceCallResponse::Returned,
                valid_reply: true,
            }],
        });
        assert!(only(&report).is_empty());
        report.coverage[0].attempts[0]
            .source_receipt
            .as_mut()
            .unwrap()
            .calls[0]
            .response = SourceCallResponse::Unknown;
        assert!(only(&report).iter().any(|v| matches!(v, ReportViolation::CoverageStatusShape { detail, .. } if detail.contains("without observed response"))));
        report.coverage[0].attempts[0]
            .source_receipt
            .as_mut()
            .unwrap()
            .calls[0]
            .response = SourceCallResponse::Returned;
        report.coverage[0].attempts[0].files[0].submitted_sha256 = None;
        assert!(only(&report).iter().any(|v| matches!(v, ReportViolation::CoverageStatusShape { detail, .. } if detail.contains("missing submitted source hash"))));
        report.coverage[0].status = ModuleCoverageStatus::Covered;
        assert!(only(&report).iter().any(|v| matches!(v, ReportViolation::CoverageStatusShape { detail, .. } if detail.contains("covered status with incomplete"))));
        report.coverage[0].status = ModuleCoverageStatus::PartiallyReviewed;
        report.coverage[0].attempts[0].files[0].source_bytes = Some(1000);
        report.coverage[0].attempts[0].files[0].source_lines = Some(1000);
        report.coverage[0].attempts[0].files[0].end_line = Some(9999);
        report.coverage[0].attempts[0].files[0].truncated = false;
        let violations = only(&report);
        for detail in [
            "truncation does not match",
            "line range exceeds",
            "truncated_paths do not match",
        ] {
            assert!(violations.iter().any(|v| matches!(v, ReportViolation::CoverageStatusShape { detail: actual, .. } if actual.contains(detail))), "{detail}: {violations:?}");
        }
        report.coverage[0].scope_paths.push("src/missing.rs".into());
        assert!(only(&report).iter().any(|v| matches!(v, ReportViolation::CoverageStatusShape { detail, .. } if detail.contains("every scope path"))));
    }

    #[test]
    fn run_status_and_reason_must_agree() {
        let mut r = report(vec![], vec![]);
        r.run_status = RunStatus::Incomplete;
        assert_eq!(only(&r), vec![ReportViolation::IncompleteWithoutReason]);
        r.run_status = RunStatus::Complete;
        r.incomplete_reason = Some(IncompleteReason::EngineUnavailable);
        assert_eq!(only(&r), vec![ReportViolation::CompleteWithReason]);
        r.run_status = RunStatus::Incomplete;
        assert_eq!(only(&r), vec![]);
    }

    #[test]
    fn verifier_independence_must_match_agents_and_evidence() {
        let mut r = report(vec![], vec![]);
        r.verifier = VerifierInfo {
            independence: VerifierIndependence::DifferentAgent,
            audit_agent: Some("a".into()),
            verifier_agent: Some("a".into()),
        };
        assert_eq!(only(&r).len(), 1);
        r.verifier.independence = VerifierIndependence::SameAgent;
        r.verifier.verifier_agent = Some("b".into());
        assert_eq!(only(&r).len(), 1);
        r.verifier.verifier_agent = Some("a".into());
        assert_eq!(only(&r), vec![]);

        let mut nh = report(vec![needs_human("src/a.rs")], vec![]);
        nh.verifier.independence = VerifierIndependence::NotRun;
        assert_eq!(only(&nh).len(), 1);
    }

    #[test]
    fn verifier_correction_requires_a_passed_precheck() {
        let mut f = needs_human("src/a.rs");
        f.evidence
            .push(ev("adversarial", "verifier_corrected: line 10→14"));
        let id = f.id.clone();
        assert_eq!(
            only(&report(vec![f.clone()], vec![])),
            vec![ReportViolation::CorrectedWithoutPassedPrecheck { id: id.clone() }]
        );
        f.precheck = Some(crate::audit::schema::PrecheckResult {
            passed: false,
            violations: vec!["x".into()],
        });
        assert!(
            only(&report(vec![f.clone()], vec![]))
                .contains(&ReportViolation::CorrectedWithoutPassedPrecheck { id })
        );
        f.precheck = Some(crate::audit::schema::PrecheckResult {
            passed: true,
            violations: vec![],
        });
        assert_eq!(only(&report(vec![f], vec![])), vec![]);
    }

    #[test]
    fn violations_display_as_one_line_each() {
        let v = ReportViolation::SummaryMismatch { field: "coverage" };
        assert_eq!(
            v.to_string(),
            "summary.coverage does not match the findings/coverage"
        );
        assert!(
            !ReportViolation::IncompleteWithoutReason
                .to_string()
                .contains('\n')
        );
    }
}
