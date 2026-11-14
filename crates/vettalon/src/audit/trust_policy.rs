//! Per-CWE trust policy: weakness classes where a model's refutation alone
//! does not close a finding.
//!
//! Sifting the Noise (ISSTA 2026, arXiv 2601.22952) measured, per CWE, how
//! often LLM agents dismissed true positives: 77.17% for CWE-327, 84.50% for
//! CWE-328, 77.11% for CWE-501 and 50% for CWE-614, against 2.38% for
//! CWE-78. For every CWE in [`RULES`], a refuter verdict that would set
//! `Refuted` parks the finding at `NeedsHuman` instead, with one
//! `trust_policy: llm_refute_capped CWE-<n>` evidence item
//! ([`evidence_detail`]), a blocker and a validation plan for the person who
//! settles it.
//!
//! Model (refuter) verdicts are capped in `adversarial::settle_verdicts`,
//! which both `vettalon scan` and `vettalon verify` go through.
//! Deterministic outcomes stay as they are: zero-LLM pre-check and
//! source-validation failures, execution proof and operator decisions.
//!
//! Saved reports are covered too. A report written before this policy
//! existed may hold a model-only `Refuted` for a capped CWE; every path that
//! loads a saved report for further use (prior-run carry-over, the
//! `--since-last` baseline, delivery / MCP / remediation loads, the Pro
//! workspace and dashboard) first runs [`migrate_capped_refutations`], which
//! reopens each such finding at `NeedsHuman` exactly as
//! `cap_model_refutation` would have, and only then validates the report
//! strictly. Carry-over itself applies the same rule: a prior `Refuted` for a
//! capped CWE is carried only when the prior finding was closed by something
//! other than a model: an operator decision, a failed pre-check, or an
//! earlier carry of either ([`is_deterministic_refutation`]). The carried
//! finding then gets the exact line [`carried_detail`]
//! (`trust_policy: carried_refutation CWE-<n>`), which the next run reads as
//! the same kind of basis. Any other prior refutation is not carried: the
//! finding is re-assessed (and capped again if the refuter still refutes),
//! with a [`not_carried_detail`] note naming the prior report. The report
//! validator holds every `Refuted` finding of a capped CWE to the same rule.
//!
//! What this guarantees: a model refutation, current or saved before the
//! policy, is never what closes a capped CWE. What it does not do: authenticate
//! a report. The operator, pre-check and carried markers are plain report
//! fields; someone who edits the JSON can write them, and the policy cannot
//! tell that apart from a genuine decision.
//!
//! The table is static on purpose: changing it changes which findings a scan
//! may close, so it is reviewed as code.

use super::schema::{
    AuditReport, EvidenceItem, EvidenceKind, Finding, FindingStatus, GatePolicy, PRECHECK_PREFIX,
    SeverityBasis, Summary, ValidationPlan, has_operator_review,
};

/// Evidence `detail` prefix of a trust-policy item.
pub const TRUST_POLICY_PREFIX: &str = "trust_policy:";
/// The action recorded after [`TRUST_POLICY_PREFIX`].
pub const LLM_REFUTE_CAPPED: &str = "llm_refute_capped";
/// A prior non-model refutation of a capped CWE was carried over.
pub const CARRIED_REFUTATION: &str = "carried_refutation";
/// A prior model-only refutation of a capped CWE was not carried over.
pub const PRIOR_REFUTATION_NOT_CARRIED: &str = "prior_refutation_not_carried";
/// Evidence `source` of the item [`migrate_capped_refutations`] adds.
pub const MIGRATION_SOURCE: &str = "trust_policy_migration";
/// Citation for every rule in [`RULES`].
pub const SIFTING_THE_NOISE: &str = "Sifting the Noise, ISSTA 2026, arXiv 2601.22952";

/// One CWE whose model refutation is capped at `NeedsHuman`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustRule {
    /// Normalized id, `CWE-<n>` (the form [`super::cwe::normalize`] returns).
    pub id: &'static str,
    pub name: &'static str,
    /// Share of true positives LLM agents wrongly dismissed, as published.
    pub false_dismissal_rate: &'static str,
    /// Where the rate comes from.
    pub source: &'static str,
}

/// Crypto and policy weaknesses with a high measured wrong-dismissal rate.
pub const RULES: &[TrustRule] = &[
    TrustRule {
        id: "CWE-327",
        name: "Use of a Broken or Risky Cryptographic Algorithm",
        false_dismissal_rate: "77.17%",
        source: SIFTING_THE_NOISE,
    },
    TrustRule {
        id: "CWE-328",
        name: "Use of Weak Hash",
        false_dismissal_rate: "84.50%",
        source: SIFTING_THE_NOISE,
    },
    TrustRule {
        id: "CWE-501",
        name: "Trust Boundary Violation",
        false_dismissal_rate: "77.11%",
        source: SIFTING_THE_NOISE,
    },
    TrustRule {
        id: "CWE-614",
        name: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        false_dismissal_rate: "50%",
        source: SIFTING_THE_NOISE,
    },
];

/// The rule capping a model refutation for this CWE, if any. Every shape
/// [`super::cwe::normalize_tag`] accepts is recognized (`CWE-327`, `cwe-327`,
/// `327`, `CWE-327: Use of …`, `external/cwe/cwe-327`); the id is compared
/// whole, so `CWE-3270` is not `CWE-327`. Anything unparseable is `None`.
pub fn llm_refute_cap(cwe: Option<&str>) -> Option<&'static TrustRule> {
    let id = super::cwe::normalize_tag(cwe?)?;
    RULES.iter().find(|r| r.id == id)
}

/// The exact evidence detail recorded when `rule` capped a refutation.
pub fn evidence_detail(rule: &TrustRule) -> String {
    format!("{TRUST_POLICY_PREFIX} {LLM_REFUTE_CAPPED} {}", rule.id)
}

/// The exact evidence detail on a finding whose prior non-model refutation
/// of `rule`'s CWE was carried over.
pub fn carried_detail(rule: &TrustRule) -> String {
    format!("{TRUST_POLICY_PREFIX} {CARRIED_REFUTATION} {}", rule.id)
}

/// The note on a finding whose prior model-only refutation of `rule`'s CWE
/// was not carried over from `report_file`.
pub fn not_carried_detail(rule: &TrustRule, report_file: &str) -> String {
    format!(
        "{TRUST_POLICY_PREFIX} {PRIOR_REFUTATION_NOT_CARRIED} {}: {report_file} refuted this root cause with a model verdict only; a model refutation alone cannot close {}, so the verdict is not carried over (re-assess)",
        rule.id, rule.id
    )
}

/// The finding was closed (`Refuted`) by something other than a model, as
/// far as its record shows: an operator decision, a failed deterministic
/// pre-check, or (with `rule`) a carried refutation of that kind for the
/// rule's CWE ([`carried_detail`]). A `refuted:` verifier line or a bare
/// `carried_from_prior:` line is not enough.
pub fn is_deterministic_refutation(f: &Finding, rule: Option<&TrustRule>) -> bool {
    let by_operator = has_operator_review(f) || f.severity_basis == SeverityBasis::Operator;
    let carried = rule.map(carried_detail);
    let by_precheck_or_carry = f.evidence.iter().any(|e| {
        e.kind == EvidenceKind::AdversarialReview
            && (e.detail.starts_with(PRECHECK_PREFIX)
                || carried.as_deref() == Some(e.detail.as_str()))
    });
    by_operator || f.precheck_failed() || by_precheck_or_carry
}

/// The rule that keeps this finding open: it is `NeedsHuman`, its CWE is
/// capped and its evidence carries the matching [`evidence_detail`] line
/// from the verifier. (A finding a person has since settled, or one reset to
/// `Candidate`, is no longer held by the policy.)
pub fn capped_rule(f: &Finding) -> Option<&'static TrustRule> {
    if f.status != FindingStatus::NeedsHuman {
        return None;
    }
    let rule = llm_refute_cap(f.cwe.as_deref())?;
    let detail = evidence_detail(rule);
    f.evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::AdversarialReview && e.detail == detail)
        .then_some(rule)
}

/// Where a model refutation would set `Refuted`: for a capped CWE, park the
/// finding at `NeedsHuman` with a blocker, a validation plan and the
/// trust-policy evidence item, and return `true`. Any other CWE (or none) is
/// left alone and `false` is returned, so the caller sets `Refuted`.
pub(super) fn cap_model_refutation(finding: &mut Finding) -> bool {
    cap_refutation_at(finding, "adversarial", chrono::Utc::now().to_rfc3339())
}

/// [`cap_model_refutation`] with the evidence item's `source` and
/// `recorded_at` given.
fn cap_refutation_at(finding: &mut Finding, source: &str, recorded_at: String) -> bool {
    let Some(rule) = llm_refute_cap(finding.cwe.as_deref()) else {
        return false;
    };
    finding.status = FindingStatus::NeedsHuman;
    finding.blockers = vec![format!(
        "a model refutation alone cannot close {} ({}); a person must check the refutation against the code",
        rule.id, rule.name
    )];
    finding.validation_plan = Some(ValidationPlan {
        local: Some(format!(
            "Read the refuter's reason (the `refuted:` evidence) next to the cited code and decide whether the {} weakness is really absent; keep the finding open until a person or a deterministic check settles it",
            rule.id
        )),
        deployment: None,
    });
    finding.evidence.push(EvidenceItem {
        kind: EvidenceKind::AdversarialReview,
        source: source.to_string(),
        detail: evidence_detail(rule),
        recorded_at,
    });
    true
}

/// A model-only refutation of a capped CWE: `Refuted`, with verifier
/// evidence, but no operator decision, failed pre-check or carried
/// non-model refutation. Exactly what the validator rejects as
/// `RefutedCappedCweByModelOnly`.
fn is_model_only_capped_refutation(f: &Finding) -> bool {
    f.status == FindingStatus::Refuted
        && f.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::AdversarialReview)
        && llm_refute_cap(f.cwe.as_deref())
            .is_some_and(|rule| !is_deterministic_refutation(f, Some(rule)))
}

/// Migration on read for a saved report (one written before this policy
/// existed): every model-only `Refuted` finding of a capped CWE is reopened
/// at `NeedsHuman` with the [`evidence_detail`] line, a blocker and a
/// validation plan, as `cap_model_refutation` does during a run; the
/// summary and policy-gate outcomes are then recomputed with the rule the
/// validator checks. Returns how many findings changed (0 leaves the report
/// untouched). Idempotent. The new evidence item has source
/// [`MIGRATION_SOURCE`] (no verifier ran, so it is not `adversarial`
/// evidence) and is dated with the report's `started_at`, so migrating the
/// same file twice gives the same bytes.
pub fn migrate_capped_refutations(report: &mut AuditReport) -> usize {
    let recorded_at = report.started_at.clone();
    let mut migrated = 0;
    for f in &mut report.findings {
        if is_model_only_capped_refutation(f)
            && cap_refutation_at(f, MIGRATION_SOURCE, recorded_at.clone())
        {
            migrated += 1;
        }
    }
    if migrated > 0 {
        let previous = std::mem::take(&mut report.summary.policy);
        report.summary = Summary::from_findings(
            &report.findings,
            report.engines_run.len(),
            report.engines_missing.len(),
            GatePolicy {
                include_needs_human: report.summary.gate_includes_needs_human,
            },
            &report.coverage,
        );
        report.summary.policy = super::gate::reevaluate(&previous, &report.findings);
    }
    migrated
}

/// The one-line note shown when [`migrate_capped_refutations`] changed
/// `migrated` findings of the report at `what`.
pub fn migration_note(what: &str, migrated: usize) -> String {
    crate::tr!(
        "{what}：{migrated} 個在信任政策之前僅由模型駁回的受限 CWE 發現已改回 needs_human（trust_policy: llm_refute_capped）",
        "{what}: reopened {migrated} finding(s) of a trust-policy CWE that a model alone had refuted before the policy existed; they are needs_human now (trust_policy: llm_refute_capped)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, Severity};

    fn finding(cwe: Option<&str>) -> Finding {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "weak hash",
            "src/a.py",
            Some(1),
            "",
            "ai-audit/weak-hash",
            vec![],
        );
        f.cwe = cwe.map(str::to_string);
        f
    }

    #[test]
    fn table_lists_the_four_measured_cwes_with_their_source() {
        let ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        assert_eq!(ids, ["CWE-327", "CWE-328", "CWE-501", "CWE-614"]);
        for r in RULES {
            assert_eq!(r.source, SIFTING_THE_NOISE);
            assert_eq!(
                crate::audit::cwe::normalize(r.id).as_deref(),
                Some(r.id),
                "ids are stored normalized"
            );
            assert!(r.false_dismissal_rate.ends_with('%'));
        }
        assert!(SIFTING_THE_NOISE.contains("2601.22952"));
    }

    #[test]
    fn every_cwe_shape_is_recognized_and_ids_compare_whole() {
        for raw in [
            "CWE-327",
            "cwe-327",
            "CWE 327",
            "327",
            "CWE-0327",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "external/cwe/cwe-327",
            "EXTERNAL/CWE/CWE-327",
        ] {
            let rule = llm_refute_cap(Some(raw)).expect(raw);
            assert_eq!(rule.id, "CWE-327", "{raw}");
        }
        assert_eq!(llm_refute_cap(Some("614")).unwrap().id, "CWE-614");
        for raw in [
            "CWE-3270",
            "CWE-32",
            "CWE-27",
            "CWE-327a",
            "xCWE-327",
            "CWE-78",
            "CWE-79",
            "",
            "external/cwe/cwe-3270",
            "see CWE-327",
        ] {
            assert!(llm_refute_cap(Some(raw)).is_none(), "{raw}");
        }
        assert!(llm_refute_cap(None).is_none());
    }

    #[test]
    fn cap_parks_needs_human_with_blocker_plan_and_evidence() {
        let mut f = finding(Some("CWE-328"));
        assert!(cap_model_refutation(&mut f));
        assert_eq!(f.status, FindingStatus::NeedsHuman);
        assert_eq!(f.blockers.len(), 1);
        assert!(f.blockers[0].contains("CWE-328"));
        assert!(!f.validation_plan.as_ref().unwrap().is_empty());
        assert_eq!(
            f.evidence.last().unwrap().detail,
            "trust_policy: llm_refute_capped CWE-328"
        );
        assert_eq!(capped_rule(&f).map(|r| r.id), Some("CWE-328"));
    }

    #[test]
    fn uncapped_or_missing_cwe_is_left_alone() {
        for cwe in [Some("CWE-78"), Some("CWE-3270"), None] {
            let mut f = finding(cwe);
            let before = f.evidence.len();
            assert!(!cap_model_refutation(&mut f), "{cwe:?}");
            assert_eq!(f.status, FindingStatus::Candidate);
            assert!(f.blockers.is_empty() && f.validation_plan.is_none());
            assert_eq!(f.evidence.len(), before);
            assert!(capped_rule(&f).is_none());
        }
    }

    #[test]
    fn capped_rule_needs_the_line_for_the_findings_own_cwe() {
        let mut f = finding(Some("CWE-327"));
        f.status = FindingStatus::NeedsHuman;
        f.evidence.push(EvidenceItem {
            kind: EvidenceKind::AdversarialReview,
            source: "adversarial".into(),
            detail: "trust_policy: llm_refute_capped CWE-328".into(),
            recorded_at: String::new(),
        });
        assert!(capped_rule(&f).is_none(), "line for another CWE");
        f.evidence.push(EvidenceItem {
            kind: EvidenceKind::AiAnalysis,
            source: "ai_audit".into(),
            detail: "trust_policy: llm_refute_capped CWE-327".into(),
            recorded_at: String::new(),
        });
        assert!(capped_rule(&f).is_none(), "not a verifier item");
        f.evidence.push(EvidenceItem {
            kind: EvidenceKind::AdversarialReview,
            source: "adversarial".into(),
            detail: "trust_policy: llm_refute_capped CWE-327".into(),
            recorded_at: String::new(),
        });
        assert!(capped_rule(&f).is_some());
        // Settled by a person (or reset to candidate): no longer held.
        f.status = FindingStatus::Refuted;
        assert!(capped_rule(&f).is_none());
    }

    fn review(source: &str, detail: &str) -> EvidenceItem {
        EvidenceItem {
            kind: EvidenceKind::AdversarialReview,
            source: source.into(),
            detail: detail.into(),
            recorded_at: String::new(),
        }
    }

    #[test]
    fn only_operator_precheck_or_marked_carry_is_a_deterministic_refutation() {
        let rule = llm_refute_cap(Some("CWE-327")).unwrap();
        let mut f = finding(Some("CWE-327"));
        f.status = FindingStatus::Refuted;
        f.evidence
            .push(review("adversarial", "refuted: constant key"));
        f.evidence.push(review(
            "prior_run",
            "carried_from_prior: 2026.json (prior status refuted)",
        ));
        assert!(
            !is_deterministic_refutation(&f, Some(rule)),
            "model + bare carry"
        );
        // The carried marker must name this rule's CWE and be a review item.
        let other = llm_refute_cap(Some("CWE-328")).unwrap();
        f.evidence.push(review("prior_run", &carried_detail(other)));
        assert!(!is_deterministic_refutation(&f, Some(rule)));
        let mut ai = review("prior_run", &carried_detail(rule));
        ai.kind = EvidenceKind::AiAnalysis;
        f.evidence.push(ai);
        assert!(!is_deterministic_refutation(&f, Some(rule)));
        let mut carried = f.clone();
        carried
            .evidence
            .push(review("prior_run", &carried_detail(rule)));
        assert!(is_deterministic_refutation(&carried, Some(rule)));
        assert!(
            !is_deterministic_refutation(&carried, None),
            "the marker only counts for its rule"
        );
        assert_eq!(
            carried_detail(rule),
            "trust_policy: carried_refutation CWE-327"
        );
        let mut pre = f.clone();
        crate::audit::precheck::apply_precheck(&mut pre, vec!["line out of range".into()]);
        assert!(is_deterministic_refutation(&pre, Some(rule)));
        assert!(is_deterministic_refutation(&pre, None));
        let mut op = f.clone();
        op.evidence.push(EvidenceItem {
            kind: EvidenceKind::OperatorReview,
            source: "dashboard".into(),
            detail: "operator_decision: refuted".into(),
            recorded_at: String::new(),
        });
        assert!(is_deterministic_refutation(&op, Some(rule)));
        let mut basis = f.clone();
        basis.severity_basis = SeverityBasis::Operator;
        assert!(is_deterministic_refutation(&basis, Some(rule)));
        let note = not_carried_detail(rule, "20261001T000000Z.json");
        assert!(note.starts_with("trust_policy: prior_refutation_not_carried CWE-327: "));
        assert!(note.ends_with("(re-assess)"));
    }
}
