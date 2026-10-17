//! Deep-audit module coverage.
//!
//! Every ranked module gets exactly one [`ModuleCoverage`] entry, in rank
//! order, including the ones never sent to the model: a report must show
//! how much was audited, not only what was found. Status table:
//!
//! | outcome | status |
//! |---|---|
//! | reviewed, zero findings | `covered` |
//! | reviewed, ≥1 finding (pre-check refutations included) | `candidate` |
//! | outside `--max-modules` | `deferred`, reason `max_modules` |
//! | run-wide candidate cap already reached | `deferred`, reason `candidate_cap` |
//! | not attempted after the engine was found unreachable | `deferred`, reason `engine_unavailable` |
//! | no readable text | `unreadable` |
//! | LLM call failed | `llm_failed` |
//! | reply violated the JSON contract | `parse_failed` |

use std::collections::{BTreeSet, HashMap};

use super::ai_audit::{ModuleAuditReport, ModuleOutcome, ModuleTarget};
use super::schema::{FileReadStatus, ModuleAttempt, ModuleCoverage, ModuleCoverageStatus};

pub const DEFER_MAX_MODULES: &str = "max_modules";
pub const DEFER_CANDIDATE_CAP: &str = "candidate_cap";
pub const DEFER_ENGINE_UNAVAILABLE: &str = "engine_unavailable";
/// The scan's wall-clock budget ran out before this module was audited.
pub const DEFER_TIME_BUDGET: &str = "time_budget";

fn from_report(r: &ModuleAuditReport) -> ModuleCoverage {
    let (status, reason) = match &r.outcome {
        ModuleOutcome::Reviewed { note } => {
            if r.candidate_ids.is_empty() {
                let incomplete = !r.truncated_paths.is_empty()
                    || r.files.iter().any(|f| {
                        f.truncated
                            || matches!(
                                f.read_status,
                                FileReadStatus::BudgetExcluded | FileReadStatus::Unreadable
                            )
                    });
                (
                    if incomplete {
                        ModuleCoverageStatus::PartiallyReviewed
                    } else {
                        ModuleCoverageStatus::Covered
                    },
                    note.clone(),
                )
            } else {
                (ModuleCoverageStatus::Candidate, note.clone())
            }
        }
        ModuleOutcome::Unreadable { reason } => {
            (ModuleCoverageStatus::Unreadable, Some(reason.clone()))
        }
        ModuleOutcome::LlmFailed { reason } => {
            (ModuleCoverageStatus::LlmFailed, Some(reason.clone()))
        }
        ModuleOutcome::ParseFailed { reason } => {
            (ModuleCoverageStatus::ParseFailed, Some(reason.clone()))
        }
        ModuleOutcome::Deferred { reason } => {
            (ModuleCoverageStatus::Deferred, Some(reason.clone()))
        }
    };
    ModuleCoverage {
        module_path: r.module_path.clone(),
        status,
        reason: reason.clone(),
        reviewed_paths: r.reviewed_paths.clone(),
        truncated_paths: r.truncated_paths.clone(),
        candidate_ids: r.candidate_ids.clone(),
        scope_paths: Vec::new(),
        selected: true,
        attempts: vec![ModuleAttempt {
            model: r.model.clone(),
            family: r.family.clone(),
            status,
            reason: reason.clone(),
            files: r.files.clone(),
            duration_ms: r.duration_ms,
            timed_out: r.timed_out,
        }],
    }
}

/// Build the coverage list from ALL ranked modules plus the per-module audit
/// reports. A ranked module with no report was never handed to the audit
/// step (outside `--max-modules`) and is `deferred` / `max_modules`.
pub fn build_module_coverage(
    ranked: &[ModuleTarget],
    reports: &[ModuleAuditReport],
) -> Vec<ModuleCoverage> {
    let mut by_path: HashMap<&str, Vec<&ModuleAuditReport>> = HashMap::new();
    for report in reports {
        by_path.entry(&report.module_path).or_default().push(report);
    }
    ranked
        .iter()
        .map(|m| {
            let mut coverage = ModuleCoverage {
                module_path: m.module_path.clone(),
                status: ModuleCoverageStatus::Deferred,
                reason: Some(DEFER_MAX_MODULES.into()),
                reviewed_paths: Vec::new(),
                truncated_paths: Vec::new(),
                candidate_ids: Vec::new(),
                scope_paths: m.files.clone(),
                selected: false,
                attempts: Vec::new(),
            };
            if let Some(reports) = by_path.get(m.module_path.as_str()) {
                coverage.selected = true;
                let mut reviewed = BTreeSet::new();
                let mut truncated = BTreeSet::new();
                let mut ids = BTreeSet::new();
                for report in reports {
                    let entry = from_report(report);
                    reviewed.extend(entry.reviewed_paths);
                    truncated.extend(entry.truncated_paths);
                    ids.extend(entry.candidate_ids);
                    coverage.attempts.extend(entry.attempts);
                }
                coverage.reviewed_paths = reviewed.into_iter().collect();
                coverage.truncated_paths = truncated.into_iter().collect();
                coverage.candidate_ids = ids.into_iter().collect();
                let all_complete = coverage.attempts.iter().all(|a| {
                    matches!(
                        a.status,
                        ModuleCoverageStatus::Covered | ModuleCoverageStatus::Candidate
                    ) && a.files.iter().all(|f| {
                        !f.truncated
                            && !matches!(
                                f.read_status,
                                FileReadStatus::Unreadable | FileReadStatus::BudgetExcluded
                            )
                    })
                });
                coverage.status = if !coverage.candidate_ids.is_empty() {
                    ModuleCoverageStatus::Candidate
                } else if !coverage.reviewed_paths.is_empty() {
                    if all_complete {
                        ModuleCoverageStatus::Covered
                    } else {
                        ModuleCoverageStatus::PartiallyReviewed
                    }
                } else {
                    coverage.attempts[0].status
                };
                let reasons: Vec<String> = coverage
                    .attempts
                    .iter()
                    .filter_map(|a| a.reason.clone())
                    .collect();
                coverage.reason = if reasons.is_empty() {
                    None
                } else {
                    Some(reasons.join("; "))
                };
            }
            coverage
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(p: &str) -> ModuleTarget {
        ModuleTarget {
            module_path: p.to_string(),
            score: 1,
            high_risk: false,
            files: vec![format!("{p}/x.rs")],
        }
    }

    fn report(p: &str, outcome: ModuleOutcome, ids: &[&str]) -> ModuleAuditReport {
        ModuleAuditReport {
            module_path: p.to_string(),
            outcome: outcome.clone(),
            reviewed_paths: if matches!(outcome, ModuleOutcome::Reviewed { .. }) {
                vec![format!("{p}/x.rs")]
            } else {
                vec![]
            },
            truncated_paths: vec![],
            candidate_ids: ids.iter().map(|s| s.to_string()).collect(),
            model: "mock".into(),
            family: "test".into(),
            files: Vec::new(),
            duration_ms: 0,
            timed_out: false,
        }
    }

    #[test]
    fn every_status_maps_and_unreported_modules_are_deferred_max_modules() {
        let ranked: Vec<ModuleTarget> = ["a", "b", "c", "d", "e", "f", "g", "h"]
            .iter()
            .map(|p| target(p))
            .collect();
        let reports = vec![
            report("a", ModuleOutcome::Reviewed { note: None }, &[]),
            report("b", ModuleOutcome::Reviewed { note: None }, &["id1"]),
            report(
                "c",
                ModuleOutcome::Unreadable {
                    reason: "bin".into(),
                },
                &[],
            ),
            report("d", ModuleOutcome::LlmFailed { reason: "t".into() }, &[]),
            report("e", ModuleOutcome::ParseFailed { reason: "p".into() }, &[]),
            report(
                "f",
                ModuleOutcome::Deferred {
                    reason: DEFER_CANDIDATE_CAP.into(),
                },
                &[],
            ),
            report(
                "g",
                ModuleOutcome::Deferred {
                    reason: DEFER_ENGINE_UNAVAILABLE.into(),
                },
                &[],
            ),
        ];
        let cov = build_module_coverage(&ranked, &reports);
        let statuses: Vec<ModuleCoverageStatus> = cov.iter().map(|c| c.status).collect();
        assert_eq!(
            statuses,
            vec![
                ModuleCoverageStatus::Covered,
                ModuleCoverageStatus::Candidate,
                ModuleCoverageStatus::Unreadable,
                ModuleCoverageStatus::LlmFailed,
                ModuleCoverageStatus::ParseFailed,
                ModuleCoverageStatus::Deferred,
                ModuleCoverageStatus::Deferred,
                ModuleCoverageStatus::Deferred,
            ]
        );
        assert_eq!(cov[5].reason.as_deref(), Some(DEFER_CANDIDATE_CAP));
        assert_eq!(cov[6].reason.as_deref(), Some(DEFER_ENGINE_UNAVAILABLE));
        assert_eq!(cov[7].reason.as_deref(), Some(DEFER_MAX_MODULES));
        assert!(cov[7].reviewed_paths.is_empty());
        assert_eq!(cov[1].candidate_ids, vec!["id1".to_string()]);
        assert!(cov[0].reason.is_none());
    }

    #[test]
    fn cross_finder_failure_does_not_overwrite_success_or_disappear() {
        let ranked = vec![target("a")];
        for reverse in [false, true] {
            let mut reports = vec![
                report("a", ModuleOutcome::Reviewed { note: None }, &[]),
                report(
                    "a",
                    ModuleOutcome::LlmFailed {
                        reason: "offline".into(),
                    },
                    &[],
                ),
            ];
            if reverse {
                reports.reverse();
            }
            let cov = build_module_coverage(&ranked, &reports);
            assert_eq!(cov[0].attempts.len(), 2);
            assert_eq!(cov[0].status, ModuleCoverageStatus::PartiallyReviewed);
            assert_eq!(cov[0].reviewed_paths, vec!["a/x.rs"]);
            assert!(super::super::schema::CoverageSummary::from_coverage(&cov).partial);
        }
    }

    #[test]
    fn empty_ranking_is_empty_coverage() {
        assert!(build_module_coverage(&[], &[]).is_empty());
    }
}
