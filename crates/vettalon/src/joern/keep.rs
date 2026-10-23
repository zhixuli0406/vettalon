//! Applying a Joern answer to a finding. One direction only: a path can
//! reopen a refuted finding; nothing here can close one.

use crate::audit::schema::{EvidenceItem, EvidenceKind, Finding, FindingStatus};

use super::query::{PathStep, QueryOutcome};
use super::{JOERN_VERSION, SOURCES_VERSION, TEMPLATE_ID};

/// Evidence line for a path that kept a finding open.
pub const JOERN_PATH_PREFIX: &str = "joern_path:";
/// Evidence line for every other answer (recorded, no effect).
pub const JOERN_EVIDENCE_PREFIX: &str = "joern:";
/// The `verify_uncertain:` item a kept finding gets.
pub const JOERN_UNCERTAIN: &str = "verify_uncertain: joern path (refutation not applied)";
/// Cap on one evidence line built from untrusted path text.
const EVIDENCE_MAX_BYTES: usize = 2048;

/// Which reported paths count. Chosen on the S3 development split only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeepRule {
    /// Only paths with no hop between two arguments of the same non-operator
    /// call (Joern assumes such hops for calls it has no model of; the smoke
    /// test showed them carrying a source to unrelated later calls).
    #[default]
    Strict,
    /// Any reported path.
    AnyFlow,
}

impl KeepRule {
    pub fn token(self) -> &'static str {
        match self {
            KeepRule::Strict => "strict",
            KeepRule::AnyFlow => "any",
        }
    }

    /// Whether `o` is a path this rule accepts.
    pub fn accepts(self, o: &QueryOutcome) -> bool {
        match (self, o) {
            (KeepRule::Strict, QueryOutcome::Path { strict_flows, .. }) => *strict_flows > 0,
            (KeepRule::AnyFlow, QueryOutcome::Path { flows, .. }) => *flows > 0,
            _ => false,
        }
    }
}

/// Joern's answer for one finding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum JoernVerdict {
    Answered(QueryOutcome),
    /// Not asked (unsupported language, unusable location, no image).
    Skipped(String),
    /// Asked, and the run failed (timeout, crash, malformed output).
    Error(String),
}

fn push(finding: &mut Finding, kind: EvidenceKind, detail: String) {
    finding.evidence.push(EvidenceItem {
        kind,
        source: "joern".to_string(),
        detail: crate::util::truncate_bytes(&detail, EVIDENCE_MAX_BYTES).to_string(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
    });
}

fn provenance(rule: KeepRule) -> String {
    format!(
        "rule={} template={TEMPLATE_ID} {SOURCES_VERSION} joern={JOERN_VERSION}",
        rule.token()
    )
}

fn render_steps(steps: &[PathStep]) -> String {
    steps
        .iter()
        .map(|s| {
            let line = s.line.map(|l| l.to_string()).unwrap_or_else(|| "-".into());
            // A backtick in the analysed code would end the code span.
            format!("{}:{line} `{}`", s.file, s.code.replace('`', "'"))
        })
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// Record Joern's answer on a finding and, only when the finding is
/// `Refuted` and `rule` accepts a reported path, reopen it as `Candidate`.
/// Returns whether the finding was reopened.
///
/// Invariant (tested): the status after this call is either unchanged or
/// `Candidate` coming from `Refuted`. It never becomes `Refuted`, and no
/// other status changes.
pub fn apply_keep(finding: &mut Finding, verdict: &JoernVerdict, rule: KeepRule) -> bool {
    let prov = provenance(rule);
    match verdict {
        JoernVerdict::Answered(
            o @ QueryOutcome::Path {
                flows,
                strict_flows,
                steps,
            },
        ) => {
            let path = render_steps(steps);
            if rule.accepts(o) && finding.status == FindingStatus::Refuted {
                finding.status = FindingStatus::Candidate;
                let blocker =
                    crate::util::truncate_bytes(&format!("joern source-to-sink path: {path}"), 512)
                        .to_string();
                finding.blockers = vec![blocker];
                push(
                    finding,
                    EvidenceKind::AdversarialReview,
                    format!(
                        "{JOERN_PATH_PREFIX} {prov} flows={flows} strict={strict_flows}; path={path}"
                    ),
                );
                push(
                    finding,
                    EvidenceKind::VerifyUncertain,
                    JOERN_UNCERTAIN.into(),
                );
                true
            } else {
                let why = if rule.accepts(o) {
                    "finding was not closed"
                } else {
                    "path not accepted by the rule; refutation stands"
                };
                push(
                    finding,
                    EvidenceKind::AdversarialReview,
                    format!(
                        "{JOERN_EVIDENCE_PREFIX} path {prov} flows={flows} strict={strict_flows} ({why}); path={path}"
                    ),
                );
                false
            }
        }
        JoernVerdict::Answered(QueryOutcome::NoPath) => {
            push(
                finding,
                EvidenceKind::AdversarialReview,
                format!(
                    "{JOERN_EVIDENCE_PREFIX} no_path {prov} (no effect: a missing path is not evidence)"
                ),
            );
            false
        }
        JoernVerdict::Answered(QueryOutcome::NoSink) => {
            push(
                finding,
                EvidenceKind::AdversarialReview,
                format!(
                    "{JOERN_EVIDENCE_PREFIX} no_sink {prov} (no call on the claimed line; no effect)"
                ),
            );
            false
        }
        JoernVerdict::Answered(QueryOutcome::NoFile) => {
            push(
                finding,
                EvidenceKind::AdversarialReview,
                format!(
                    "{JOERN_EVIDENCE_PREFIX} error {prov}: claimed file is not in the CPG (no effect)"
                ),
            );
            false
        }
        JoernVerdict::Skipped(why) => {
            push(
                finding,
                EvidenceKind::AdversarialReview,
                format!("{JOERN_EVIDENCE_PREFIX} skipped {prov}: {why} (no effect)"),
            );
            false
        }
        JoernVerdict::Error(why) => {
            push(
                finding,
                EvidenceKind::AdversarialReview,
                format!("{JOERN_EVIDENCE_PREFIX} error {prov}: {why} (no effect)"),
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, Severity};

    fn finding(status: FindingStatus) -> Finding {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "SQL injection",
            "web/index.php",
            Some(4),
            "",
            "CWE-89",
            vec![],
        );
        f.status = status;
        f
    }

    fn path(flows: usize, strict: usize) -> JoernVerdict {
        JoernVerdict::Answered(QueryOutcome::Path {
            flows,
            strict_flows: strict,
            steps: vec![
                PathStep {
                    file: "web/index.php".into(),
                    line: Some(2),
                    code: "$_GET[\"id\"]".into(),
                },
                PathStep {
                    file: "web/index.php".into(),
                    line: Some(4),
                    code: "$q".into(),
                },
            ],
        })
    }

    fn all_verdicts() -> Vec<JoernVerdict> {
        vec![
            path(3, 1),
            path(3, 0),
            JoernVerdict::Answered(QueryOutcome::NoPath),
            JoernVerdict::Answered(QueryOutcome::NoSink),
            JoernVerdict::Answered(QueryOutcome::NoFile),
            JoernVerdict::Skipped("unsupported language".into()),
            JoernVerdict::Error("timed out".into()),
        ]
    }

    const STATUSES: [FindingStatus; 5] = [
        FindingStatus::Candidate,
        FindingStatus::Confirmed,
        FindingStatus::Refuted,
        FindingStatus::NeedsHuman,
        FindingStatus::Suppressed,
    ];

    #[test]
    fn joern_can_never_close_a_finding() {
        for status in STATUSES {
            for v in all_verdicts() {
                for rule in [KeepRule::Strict, KeepRule::AnyFlow] {
                    let mut f = finding(status);
                    let reopened = apply_keep(&mut f, &v, rule);
                    if status == FindingStatus::Refuted && reopened {
                        assert_eq!(f.status, FindingStatus::Candidate);
                    } else {
                        assert_eq!(f.status, status, "{status:?} {v:?} {rule:?}");
                    }
                    if status != FindingStatus::Refuted {
                        assert_ne!(f.status, FindingStatus::Refuted);
                        assert!(!reopened);
                    }
                    // Every answer is recorded, exactly once.
                    let lines = f
                        .evidence
                        .iter()
                        .filter(|e| {
                            e.source == "joern" && e.kind == EvidenceKind::AdversarialReview
                        })
                        .count();
                    assert_eq!(lines, 1);
                }
            }
        }
    }

    #[test]
    fn a_strict_path_reopens_a_refuted_finding_with_evidence() {
        let mut f = finding(FindingStatus::Refuted);
        assert!(apply_keep(&mut f, &path(3, 1), KeepRule::Strict));
        assert_eq!(f.status, FindingStatus::Candidate);
        let d = &f.evidence[0].detail;
        assert!(d.starts_with(JOERN_PATH_PREFIX), "{d}");
        assert!(d.contains("rule=strict"), "{d}");
        assert!(d.contains("flows=3 strict=1"), "{d}");
        assert!(
            d.contains("web/index.php:2 `$_GET[\"id\"]` -> web/index.php:4 `$q`"),
            "{d}"
        );
        assert_eq!(f.evidence[1].kind, EvidenceKind::VerifyUncertain);
        assert!(f.evidence[1].detail.starts_with("verify_uncertain:"));
        assert!(f.evidence_level() <= crate::audit::evidence_level::EvidenceLevel::RefuterSurvived);
        assert_eq!(f.blockers.len(), 1);
    }

    #[test]
    fn a_non_strict_path_keeps_only_under_any_flow() {
        let mut f = finding(FindingStatus::Refuted);
        assert!(!apply_keep(&mut f, &path(3, 0), KeepRule::Strict));
        assert_eq!(f.status, FindingStatus::Refuted);
        assert!(f.evidence[0].detail.contains("refutation stands"));
        let mut g = finding(FindingStatus::Refuted);
        assert!(apply_keep(&mut g, &path(3, 0), KeepRule::AnyFlow));
        assert_eq!(g.status, FindingStatus::Candidate);
    }

    #[test]
    fn untrusted_path_text_is_capped() {
        let long = JoernVerdict::Answered(QueryOutcome::Path {
            flows: 1,
            strict_flows: 1,
            steps: vec![
                PathStep {
                    file: "a.php".into(),
                    line: None,
                    code: "x".repeat(150),
                };
                12
            ],
        });
        let mut f = finding(FindingStatus::Refuted);
        apply_keep(&mut f, &long, KeepRule::Strict);
        assert!(f.evidence[0].detail.len() <= EVIDENCE_MAX_BYTES);
        assert!(f.blockers[0].len() <= 512);
    }
}
