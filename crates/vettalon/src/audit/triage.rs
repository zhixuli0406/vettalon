//! Operator decisions on a finding (the triage actions of a review UI).
//!
//! Implements the contract documented on `EvidenceKind::OperatorReview`:
//! push an `operator_review` evidence item, set `severity_basis = operator`,
//! then recompute the summary with the exact rule the report validator
//! checks. Only a human sets `Confirmed`; this module is how they do it, and
//! a reason is mandatory so the report can explain every decision (the
//! exclusion / false-positive lists of a Taiwanese assessment report need
//! one).

use super::schema::{
    AuditReport, EvidenceItem, EvidenceKind, FindingStatus, GatePolicy, SeverityBasis, Summary,
};

/// What the operator decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Manually verified as a real, exploitable issue.
    Confirmed,
    /// Not a vulnerability (false positive).
    Refuted,
    /// Accepted / out of scope: excluded from the to-fix list.
    Suppressed,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Decision::Confirmed => "confirmed",
            Decision::Refuted => "refuted",
            Decision::Suppressed => "suppressed",
        }
    }
    fn status(self) -> FindingStatus {
        match self {
            Decision::Confirmed => FindingStatus::Confirmed,
            Decision::Refuted => FindingStatus::Refuted,
            Decision::Suppressed => FindingStatus::Suppressed,
        }
    }
}

/// Marker the report renderer splits on to show the human reason.
pub const REASON_MARKER: &str = "; reason: ";
const REASON_MAX_BYTES: usize = 500;

/// Apply one operator decision to `report` in place. The report must stay
/// validator-clean afterwards; if it would not, nothing is changed.
pub fn apply(
    report: &mut AuditReport,
    finding_id: &str,
    decision: Decision,
    reason: &str,
) -> Result<(), String> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err("請填寫判定理由（會寫進報告的誤判清單／排除清單）".into());
    }
    let reason =
        crate::util::mask_sensitive_text(crate::util::truncate_bytes(reason, REASON_MAX_BYTES));
    let mut next = report.clone();
    let f = next
        .findings
        .iter_mut()
        .find(|f| f.id == finding_id)
        .ok_or_else(|| format!("找不到 finding {finding_id}"))?;
    f.evidence.push(EvidenceItem {
        kind: EvidenceKind::OperatorReview,
        source: "dashboard".into(),
        detail: format!(
            "operator_decision: {}{REASON_MARKER}{reason}",
            decision.as_str()
        ),
        recorded_at: chrono::Utc::now().to_rfc3339(),
    });
    f.status = decision.status();
    f.severity_basis = SeverityBasis::Operator;
    next.summary = Summary::from_findings(
        &next.findings,
        next.engines_run.len(),
        next.engines_missing.len(),
        GatePolicy {
            include_needs_human: next.summary.gate_includes_needs_human,
        },
        &next.coverage,
    );
    let errors = super::validation_errors(&next);
    if let Some(first) = errors.first() {
        return Err(format!("判定後報告不一致，未套用：{first}"));
    }
    *report = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{
        Finding, FindingKind, ProfileMode, ScanProfile, Severity, VerifierInfo,
    };

    fn report() -> AuditReport {
        let mut f = Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::High,
            "t",
            "a.py",
            Some(1),
            "x",
            "r",
            vec![],
        );
        f.id = "f1".into();
        let findings = vec![f];
        AuditReport {
            schema_version: 2,
            repo: "/r".into(),
            started_at: "2026-10-13T00:00:00Z".into(),
            profile: ScanProfile {
                mode: ProfileMode::Quick,
                intake: None,
            },
            engines_run: vec![],
            engines_missing: vec![],
            summary: Summary::from_findings(&findings, 0, 0, GatePolicy::default(), &[]),
            findings,
            run_status: vettalon_contract::coverage::RunStatus::Complete,
            incomplete_reason: None,
            coverage: vec![],
            prior_run: None,
            verifier: VerifierInfo::default(),
            ensemble: Default::default(),
        }
    }

    #[test]
    fn each_decision_keeps_the_report_valid_and_summary_in_sync() {
        for d in [Decision::Confirmed, Decision::Refuted, Decision::Suppressed] {
            let mut r = report();
            apply(&mut r, "f1", d, "人工確認：測試理由").unwrap();
            assert_eq!(r.findings[0].status, d.status());
            assert_eq!(r.findings[0].severity_basis, SeverityBasis::Operator);
            assert!(crate::audit::validation_errors(&r).is_empty(), "{d:?}");
            let expect_high = usize::from(d == Decision::Confirmed);
            assert_eq!(r.summary.by_severity.high, expect_high, "{d:?}");
            let ev = r.findings[0].evidence.last().unwrap();
            assert!(
                ev.detail
                    .starts_with(&format!("operator_decision: {}", d.as_str()))
            );
            assert!(ev.detail.contains("測試理由"));
        }
    }

    #[test]
    fn reason_is_required_and_unknown_ids_change_nothing() {
        let mut r = report();
        let before = serde_json::to_string(&r).unwrap();
        assert!(apply(&mut r, "f1", Decision::Suppressed, "   ").is_err());
        assert!(apply(&mut r, "nope", Decision::Suppressed, "x").is_err());
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            before,
            "a failed decision leaves the report untouched"
        );
    }

    #[test]
    fn secrets_in_reasons_are_masked() {
        let mut r = report();
        apply(
            &mut r,
            "f1",
            Decision::Refuted,
            "test key AKIAIOSFODNN7EXAMPLE was fake",
        )
        .unwrap();
        assert!(
            !r.findings[0]
                .evidence
                .last()
                .unwrap()
                .detail
                .contains("AKIAIOSFODNN7EXAMPLE")
        );
    }
}
