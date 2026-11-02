//! Evidence funnel derived at render time, without changing the report schema.

use super::evidence_level::{EvidenceLevel, PocOracle};
use super::fix_check::FixOutcome;
use super::schema::{AI_AUDIT_ENGINE_NAME, AuditReport, EvidenceKind, FindingStatus};
use serde::Serialize;

/// Independent counts over retained AI findings; stages can overlap and need
/// not decrease. Scanner findings are kept outside the AI population.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EvidenceFunnel {
    pub candidates: usize,
    pub refuted: usize,
    pub needs_human: usize,
    pub poc_differential: usize,
    pub fix_verified: usize,
    pub human_confirmed: usize,
    pub scanner_findings: usize,
}

/// Pure projection of recorded evidence. Summary counters and model prose
/// never supply evidence; no report or gate state is changed.
pub fn derive(report: &AuditReport) -> EvidenceFunnel {
    let mut out = EvidenceFunnel::default();
    for finding in &report.findings {
        if finding.source_engine != AI_AUDIT_ENGINE_NAME {
            out.scanner_findings += 1;
            continue;
        }
        out.candidates += 1;
        out.refuted += usize::from(finding.status == FindingStatus::Refuted);
        out.needs_human += usize::from(finding.status == FindingStatus::NeedsHuman);
        out.poc_differential += usize::from(finding.evidence.iter().any(|e| {
            e.kind == EvidenceKind::PocOracle
                && PocOracle::parse(&e.detail)
                    .is_some_and(|o| o.level() == Some(EvidenceLevel::PocDifferential))
        }));
        out.fix_verified += usize::from(
            finding
                .fix_check()
                .is_some_and(|c| c.outcome == FixOutcome::FixVerified),
        );
        out.human_confirmed +=
            usize::from(finding.evidence_level() == EvidenceLevel::MaintainerConfirmed);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::*;

    fn finding(engine: &str) -> Finding {
        Finding::candidate(
            engine,
            FindingKind::StaticAnalysis,
            Severity::High,
            "test",
            "a.py",
            Some(1),
            "x",
            "r",
            vec![],
        )
    }
    fn report(findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            repo_commit: None,
            repo_tree_clean: None,
            since_last: None,
            attack_classes: None,
            schema_version: CURRENT_SCHEMA_VERSION,
            scope: None,
            repo: "/r".into(),
            started_at: "t".into(),
            profile: ScanProfile {
                mode: ProfileMode::Deep,
                intake: None,
            },
            engines_run: vec![],
            engines_missing: vec![],
            summary: Summary::from_findings(&[], 0, 0, GatePolicy::default(), &[]),
            findings,
            run_status: vettalon_contract::coverage::RunStatus::Complete,
            incomplete_reason: None,
            coverage: vec![],
            prior_run: None,
            verifier: Default::default(),
            ensemble: Default::default(),
        }
    }
    #[test]
    fn funnel_uses_findings_and_separates_scanners_and_unknown_target() {
        let mut refuted = finding("ai_audit");
        refuted.status = FindingStatus::Refuted;
        let mut human = finding("ai_audit");
        human.status = FindingStatus::Confirmed;
        human.severity_basis = SeverityBasis::Operator;
        let mut needs = finding("ai_audit");
        needs.status = FindingStatus::NeedsHuman;
        let r = report(vec![
            finding("semgrep"),
            finding("ai_audit"),
            refuted,
            needs,
            human,
        ]);
        let f = derive(&r);
        assert_eq!(f.candidates, 4);
        assert_eq!(f.refuted, 1);
        assert_eq!(f.needs_human, 1);
        assert_eq!(f.scanner_findings, 1);
        assert_eq!(f.human_confirmed, 1);
        assert_eq!(f.fix_verified, 0);
        assert_eq!(f.poc_differential, 0);
        assert_eq!(
            crate::audit::sarif::to_sarif(&r)["runs"][0]["properties"]["vettalon.funnel"],
            serde_json::to_value(f).unwrap()
        );
    }
    #[test]
    fn funnel_ignores_transcripts_forged_confirmation_and_legacy_fix() {
        let mut f = finding("ai_audit");
        f.status = FindingStatus::Confirmed;
        for (kind, detail) in [
            (EvidenceKind::PocTranscript, "exit_code=0 target_reproduced"),
            (EvidenceKind::AiAnalysis, "operator_decision: confirmed"),
            (EvidenceKind::FixCheck, "fix_verified"),
        ] {
            f.evidence.push(EvidenceItem {
                kind,
                source: "test".into(),
                detail: detail.into(),
                recorded_at: "t".into(),
            });
        }
        let mut r = report(vec![f]);
        assert_eq!(derive(&r).human_confirmed, 0);
        assert_eq!(derive(&r).fix_verified, 0);
        assert_eq!(derive(&r).poc_differential, 0);
        r.findings[0].evidence.push(EvidenceItem {
            kind: EvidenceKind::PocOracle,
            source: "poc".into(),
            detail:
                "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none"
                    .into(),
            recorded_at: "t".into(),
        });
        assert_eq!(derive(&r).poc_differential, 1);
    }
}
