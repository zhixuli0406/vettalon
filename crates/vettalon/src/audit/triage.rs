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
        return Err(crate::tr!(
            "請填寫判定理由（會寫進報告的誤判清單／排除清單）",
            "Enter a reason for the decision (it goes into the report's false-positive / exclusion list)"
        ));
    }
    let reason =
        crate::util::mask_sensitive_text(crate::util::truncate_bytes(reason, REASON_MAX_BYTES));
    let mut next = report.clone();
    let f = next
        .findings
        .iter_mut()
        .find(|f| f.id == finding_id)
        .ok_or_else(|| crate::tr!("找不到 finding {finding_id}", "no finding {finding_id}"))?;
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
    next.summary.policy = super::gate::reevaluate(&report.summary.policy, &next.findings);
    let errors = super::validation_errors(&next);
    if let Some(first) = errors.first() {
        return Err(crate::tr!(
            "判定後報告不一致，未套用：{first}",
            "the report would be inconsistent after this decision, so nothing was applied: {first}"
        ));
    }
    *report = next;
    Ok(())
}

/// Apply one decision to several findings (batch triage), all or nothing:
/// if any id is unknown or the result would not validate, `report` is left
/// unchanged.
pub fn apply_many(
    report: &mut AuditReport,
    finding_ids: &[String],
    decision: Decision,
    reason: &str,
) -> Result<usize, String> {
    if finding_ids.is_empty() {
        return Err(crate::tr!("沒有選取任何發現", "no findings selected"));
    }
    let mut next = report.clone();
    let mut seen = std::collections::HashSet::new();
    for id in finding_ids.iter().filter(|id| seen.insert(id.as_str())) {
        if let Err(e) = apply(&mut next, id, decision, reason) {
            let title = next
                .findings
                .iter()
                .find(|f| &f.id == id)
                .map(|f| f.title.as_str())
                .unwrap_or(id.as_str());
            return Err(crate::tr!(
                "「{title}」無法套用，整批未變更：{e}",
                "cannot apply to \"{title}\", so the batch was left unchanged: {e}"
            ));
        }
    }
    *report = next;
    Ok(seen.len())
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
    fn policy_gate_is_reevaluated_and_validated() {
        let mut r = report();
        let conds = crate::audit::gate::parse_all(&["severity>=high count>0".into()]).unwrap();
        r.summary.policy = crate::audit::gate::evaluate_all(&conds, &r.findings);
        assert!(r.summary.policy[0].failed);
        assert!(crate::audit::validation_errors(&r).is_empty());
        assert_eq!(super::super::report::exit_code_with(&r, None), 1);

        apply(&mut r, "f1", Decision::Refuted, "誤判：輸入已白名單").unwrap();
        assert!(
            !r.summary.policy[0].failed,
            "closing the finding passes the gate"
        );
        assert_eq!(r.summary.policy[0].count, 0);
        assert_eq!(super::super::report::exit_code_with(&r, None), 0);

        // A stale policy outcome is a summary mismatch.
        r.summary.policy[0].failed = true;
        assert!(
            crate::audit::validation_errors(&r)
                .iter()
                .any(|e| e.contains("summary.policy"))
        );
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

    /// The dashboard shows these errors; they follow the UI language.
    #[test]
    fn errors_follow_the_language() {
        use crate::lang::{Lang, with};
        let errors = || {
            let mut r = report();
            [
                apply(&mut r, "f1", Decision::Suppressed, " ").unwrap_err(),
                apply(&mut r, "nope", Decision::Suppressed, "x").unwrap_err(),
                apply_many(&mut r, &[], Decision::Suppressed, "x").unwrap_err(),
                apply_many(&mut r, &["nope".into()], Decision::Suppressed, "x").unwrap_err(),
            ]
        };
        let zh = with(Lang::ZhTw, errors);
        assert!(zh[0].starts_with("請填寫判定理由"), "{zh:?}");
        assert_eq!(zh[1], "找不到 finding nope");
        let en = with(Lang::En, errors);
        assert!(
            en.iter()
                .all(|e| !e.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c))),
            "{en:?}"
        );
        assert_eq!(en[2], "no findings selected");
        assert!(en[3].contains("\"nope\""), "{en:?}");
    }

    #[test]
    fn hand_written_invalid_conditions_fail_validation() {
        let mut r = report();
        let conds = crate::audit::gate::parse_all(&["count>0".into()]).unwrap();
        r.summary.policy = crate::audit::gate::evaluate_all(&conds, &r.findings);
        assert!(crate::audit::validation_errors(&r).is_empty());
        // `count>=0` (always failing) can't come from the parser.
        let mut forged = r.clone();
        forged.summary.policy[0].condition.op = crate::audit::gate::CountOp::Gte;
        forged.summary.policy =
            crate::audit::gate::reevaluate(&forged.summary.policy, &forged.findings);
        assert!(!crate::audit::validation_errors(&forged).is_empty());
        // Closed statuses can't gate.
        let mut forged = r.clone();
        forged.summary.policy[0].condition.statuses = vec![FindingStatus::Refuted];
        forged.summary.policy =
            crate::audit::gate::reevaluate(&forged.summary.policy, &forged.findings);
        assert!(!crate::audit::validation_errors(&forged).is_empty());
    }

    #[test]
    fn batch_is_all_or_nothing() {
        let mut r = report();
        let mut g = r.findings[0].clone();
        g.id = "f2".into();
        r.findings.push(g);
        r.summary = Summary::from_findings(&r.findings, 0, 0, GatePolicy::default(), &[]);
        let before = serde_json::to_string(&r).unwrap();
        let bad = vec!["f1".to_string(), "missing".to_string()];
        assert!(apply_many(&mut r, &bad, Decision::Refuted, "批次").is_err());
        assert_eq!(serde_json::to_string(&r).unwrap(), before);

        let ids = vec!["f1".to_string(), "f2".to_string(), "f1".to_string()];
        assert_eq!(
            apply_many(&mut r, &ids, Decision::Suppressed, "接受風險").unwrap(),
            2
        );
        assert!(
            r.findings
                .iter()
                .all(|f| f.status == FindingStatus::Suppressed)
        );
        assert!(crate::audit::validation_errors(&r).is_empty());
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
