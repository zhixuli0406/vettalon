//! Which findings a disclosure draft may be written for, by evidence level.
//!
//! Default: only findings whose evidence reached `poc_effect_no_control` or
//! above. `--allow-unproven` (explicit) also admits the refuter-only levels
//! and marks the draft with a loud "unproven" banner. `static_only` is never
//! drafted, and refuted / suppressed findings never are either.
//!
//! The level is the shared derivation [`Finding::evidence_level`]: a model
//! verdict alone stays at the refuter levels, only a harness-judged
//! `poc_oracle` reaches the `poc_*` levels (a legacy PoC transcript or a
//! pattern demonstration does not), and `maintainer_confirmed` is human only.

use serde::Serialize;

use crate::audit::evidence_level::EvidenceLevel;
use crate::audit::schema::{Finding, FindingStatus};

/// Lowest level drafted without `--allow-unproven`.
pub const DEFAULT_MINIMUM: EvidenceLevel = EvidenceLevel::PocEffectNoControl;

/// The outcome of the eligibility gate for one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Eligibility {
    pub level: EvidenceLevel,
    /// True when the draft is only allowed because of `--allow-unproven`.
    pub unproven: bool,
}

/// Kind tag of `hunt --malicious-signals` results. Those are registry /
/// package-takedown matters, never upstream vulnerability reports, so no
/// draft is ever written for them, whatever their evidence.
pub const MALICIOUS_SIGNAL_KIND: &str = "malicious_package_signal";

fn is_malicious_signal(f: &Finding) -> bool {
    f.rule_id == MALICIOUS_SIGNAL_KIND
        || f.rule_id.starts_with("malicious_package_signal/")
        || f.source_engine == MALICIOUS_SIGNAL_KIND
}

/// The gate. `allow_unproven` admits the refuter levels (flagged `unproven`);
/// nothing admits `static_only`, refuted or suppressed findings.
pub fn draft_eligibility(f: &Finding, allow_unproven: bool) -> Result<Eligibility, String> {
    if is_malicious_signal(f) {
        return Err(crate::tr!(
            "惡意套件訊號不是上游漏洞，不提供揭露草稿；請由人工判斷後向套件登錄處或安全團隊回報。",
            "a malicious-package signal is not an upstream vulnerability; no disclosure draft is offered. A human decides whether to report it to the registry or a security team."
        ));
    }
    match f.status {
        FindingStatus::Refuted => {
            return Err(crate::tr!(
                "此項目經覆核判定為誤判，不提供提交草稿。",
                "this finding was refuted on review; no draft is offered."
            ));
        }
        FindingStatus::Suppressed => {
            return Err(crate::tr!(
                "此項目已被排除，不提供提交草稿。",
                "this finding is suppressed; no draft is offered."
            ));
        }
        _ => {}
    }
    let level = f.evidence_level();
    if level == EvidenceLevel::StaticOnly {
        return Err(crate::tr!(
            "證據等級 static_only（只有掃描或模型分析），任何選項都不提供草稿。請先以 deep 模式覆核並重現。",
            "evidence level static_only (scanner or model analysis only): no draft under any option. Review it in deep mode and reproduce it first."
        ));
    }
    if level >= DEFAULT_MINIMUM {
        return Ok(Eligibility {
            level,
            unproven: false,
        });
    }
    if allow_unproven {
        return Ok(Eligibility {
            level,
            unproven: true,
        });
    }
    Err(crate::tr!(
        "證據等級 {} 未達預設門檻 poc_effect_no_control（需要由執行框架判定的 PoC 效果，或人工確認）。確定要為未證實的項目產生草稿，請明確加上 --allow-unproven；草稿會標示「未證實」。",
        "evidence level {} is below the default threshold poc_effect_no_control (a harness-judged PoC effect, or a human confirmation). To draft an unproven finding anyway, pass --allow-unproven explicitly; the draft is marked UNPROVEN.",
        level.key()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{EvidenceItem, EvidenceKind, FindingKind, Severity, SeverityBasis};

    fn ev(kind: EvidenceKind, detail: &str) -> EvidenceItem {
        EvidenceItem {
            kind,
            source: "t".into(),
            detail: detail.into(),
            recorded_at: "2026-10-20T00:00:00Z".into(),
        }
    }

    fn finding(status: FindingStatus, evidence: Vec<EvidenceItem>) -> Finding {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "t",
            "a.rs",
            Some(1),
            "s",
            "ai-audit/x",
            evidence,
        );
        f.status = status;
        f
    }

    const ORACLE_NO_CONTROL: &str =
        "poc_oracle: effect=true control=none rerun=none nonce_bound=true rejected=none";
    const ORACLE_DIFFERENTIAL: &str =
        "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none";

    #[test]
    fn default_refuses_refuter_only_levels_and_allow_unproven_flags_them() {
        let f = finding(
            FindingStatus::NeedsHuman,
            vec![ev(EvidenceKind::AdversarialReview, "plausible: ok")],
        );
        assert_eq!(f.evidence_level(), EvidenceLevel::RefuterSurvived);
        let err = draft_eligibility(&f, false).unwrap_err();
        assert!(err.contains("--allow-unproven"), "{err}");
        let ok = draft_eligibility(&f, true).unwrap();
        assert!(ok.unproven);
        assert_eq!(ok.level, EvidenceLevel::RefuterSurvived);
    }

    #[test]
    fn legacy_poc_transcript_is_not_a_harness_oracle() {
        let f = finding(
            FindingStatus::NeedsHuman,
            vec![
                ev(EvidenceKind::AdversarialReview, "plausible: ok"),
                ev(EvidenceKind::PocTranscript, "exit 0\nVULN_CONFIRMED"),
            ],
        );
        assert!(draft_eligibility(&f, false).is_err());
        assert!(draft_eligibility(&f, true).unwrap().unproven);
    }

    #[test]
    fn harness_oracle_is_drafted_by_default() {
        for (detail, want) in [
            (ORACLE_NO_CONTROL, EvidenceLevel::PocEffectNoControl),
            (ORACLE_DIFFERENTIAL, EvidenceLevel::PocDifferential),
        ] {
            let f = finding(
                FindingStatus::NeedsHuman,
                vec![
                    ev(EvidenceKind::AdversarialReview, "plausible: ok"),
                    ev(EvidenceKind::PocOracle, detail),
                ],
            );
            let ok = draft_eligibility(&f, false).unwrap();
            assert_eq!(ok.level, want, "{detail}");
            assert!(!ok.unproven);
        }
    }

    #[test]
    fn rejected_or_malformed_oracle_does_not_pass_the_gate() {
        for detail in [
            "poc_oracle: effect=true control=none rerun=none nonce_bound=true rejected=hardcoded_canary",
            "poc_oracle: effect=true control=none rerun=none nonce_bound=false rejected=none",
            "poc_oracle:effect=true control=none rerun=none nonce_bound=true rejected=none",
        ] {
            let f = finding(
                FindingStatus::NeedsHuman,
                vec![
                    ev(EvidenceKind::AdversarialReview, "plausible: ok"),
                    ev(EvidenceKind::PocOracle, detail),
                ],
            );
            assert!(draft_eligibility(&f, false).is_err(), "{detail}");
        }
    }

    #[test]
    fn verify_uncertain_caps_below_the_default_gate() {
        let f = finding(
            FindingStatus::Candidate,
            vec![
                ev(EvidenceKind::AdversarialReview, "plausible: ok"),
                ev(EvidenceKind::PocOracle, ORACLE_DIFFERENTIAL),
                ev(
                    EvidenceKind::VerifyUncertain,
                    "verify_uncertain: 2/3 plausible",
                ),
            ],
        );
        assert_eq!(f.evidence_level(), EvidenceLevel::RefuterSurvived);
        assert!(draft_eligibility(&f, false).is_err());
    }

    #[test]
    fn malicious_signal_findings_are_never_drafted() {
        for (engine, rule) in [
            ("ai_audit", MALICIOUS_SIGNAL_KIND),
            (MALICIOUS_SIGNAL_KIND, "x"),
            ("ai_audit", "malicious_package_signal/typosquat"),
        ] {
            let mut f = finding(
                FindingStatus::Confirmed,
                vec![
                    ev(EvidenceKind::PocOracle, ORACLE_DIFFERENTIAL),
                    ev(
                        EvidenceKind::OperatorReview,
                        "operator_decision: confirmed; reason: r",
                    ),
                ],
            );
            f.source_engine = engine.into();
            f.rule_id = rule.into();
            let err = draft_eligibility(&f, true).unwrap_err();
            assert!(
                err.contains("malicious-package") || err.contains("惡意套件"),
                "{err}"
            );
        }
    }

    #[test]
    fn static_only_is_never_drafted() {
        let f = finding(
            FindingStatus::Candidate,
            vec![ev(EvidenceKind::StaticHit, "semgrep")],
        );
        assert!(draft_eligibility(&f, false).is_err());
        assert!(draft_eligibility(&f, true).is_err());
    }

    #[test]
    fn refuted_and_suppressed_are_never_drafted() {
        for s in [FindingStatus::Refuted, FindingStatus::Suppressed] {
            let f = finding(
                s,
                vec![
                    ev(EvidenceKind::AdversarialReview, "plausible: x"),
                    ev(EvidenceKind::PocOracle, ORACLE_DIFFERENTIAL),
                ],
            );
            assert!(draft_eligibility(&f, true).is_err());
        }
    }

    #[test]
    fn operator_confirmation_is_drafted_by_default() {
        let f = finding(
            FindingStatus::Confirmed,
            vec![ev(
                EvidenceKind::OperatorReview,
                "operator_decision: confirmed; reason: reproduced",
            )],
        );
        let ok = draft_eligibility(&f, false).unwrap();
        assert_eq!(ok.level, EvidenceLevel::MaintainerConfirmed);
        assert!(!ok.unproven);
        // A Confirmed status without operator provenance never upgrades.
        let mut bare = finding(FindingStatus::Confirmed, vec![]);
        bare.severity_basis = SeverityBasis::default();
        assert_eq!(bare.evidence_level(), EvidenceLevel::StaticOnly);
        assert!(draft_eligibility(&bare, true).is_err());
    }

    #[test]
    fn refuter_consistent_is_still_below_the_default_gate() {
        let f = finding(
            FindingStatus::NeedsHuman,
            vec![
                ev(EvidenceKind::AdversarialReview, "plausible: ok"),
                ev(EvidenceKind::AdversarialReview, "refuter_consistent: 3/3"),
            ],
        );
        assert_eq!(f.evidence_level(), EvidenceLevel::RefuterConsistent);
        assert!(draft_eligibility(&f, false).is_err());
        assert!(draft_eligibility(&f, true).unwrap().unproven);
    }
}
