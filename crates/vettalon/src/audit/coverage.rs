//! Deep-audit module coverage.
//!
//! Every ranked module gets exactly one [`ModuleCoverage`] entry, in rank
//! order, including the ones never sent to the model: a report must show
//! how much was audited, not only what was found. Status table:
//!
//! | outcome | status |
//! |---|---|
//! | reviewed, zero findings, valid checks | `covered` |
//! | reviewed, zero findings, no checks | `reviewed_no_checks` |
//! | reviewed, ≥1 finding (pre-check refutations included) | `candidate` |
//! | outside `--max-modules` | `deferred`, reason `max_modules` |
//! | in the `--prescreen` pool but below its cut | `deferred`, reason `prescreen_cut` |
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
    let missing = r
        .attack_classes
        .as_ref()
        .map(|classes| classes.missing_checks(&r.checks))
        .unwrap_or_default();
    let shallow_reason = if missing.is_empty() {
        "shallow_no_checks".to_string()
    } else {
        format!("shallow_missing_class_checks: {}", missing.join(", "))
    };
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
                    if r.checks.is_empty() || !missing.is_empty() {
                        ModuleCoverageStatus::ReviewedNoChecks
                    } else if incomplete {
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
        attack_classes: r.attack_classes.clone(),
        prior_status: None,
        checks: r.checks.clone(),
        hardening: r.hardening.clone(),
        leads: r.leads.clone(),
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
            reason: if status == ModuleCoverageStatus::ReviewedNoChecks {
                Some(match &reason {
                    Some(note) => format!("{shallow_reason}; {note}"),
                    None => shallow_reason.clone(),
                })
            } else {
                reason.clone()
            },
            files: r.files.clone(),
            duration_ms: r.duration_ms,
            timed_out: r.timed_out,
            source_receipt: r.source_receipt.clone(),
        }],
    }
}

/// A module may be read by multiple finder attempts. Keep every selected class
/// if the source changed between those reads; a later attempt cannot erase scope.
fn merge_attack_classes(
    current: &mut Option<super::attack_classes::AttackClassSelection>,
    incoming: Option<super::attack_classes::AttackClassSelection>,
) {
    use super::attack_classes::{AttackClassMode, CLASSES, ExcludedClass};
    let Some(incoming) = incoming else { return };
    let Some(current) = current else {
        *current = Some(incoming);
        return;
    };
    if *current == incoming {
        return;
    }
    if incoming.mode == AttackClassMode::All {
        current.mode = AttackClassMode::All;
    }
    let selected: Vec<String> = CLASSES
        .iter()
        .map(|class| class.id)
        .filter(|id| {
            current
                .selected
                .iter()
                .chain(&incoming.selected)
                .any(|s| s == *id)
        })
        .map(str::to_string)
        .collect();
    let excluded = CLASSES
        .iter()
        .map(|class| class.id)
        .filter(|id| !selected.iter().any(|s| s == *id))
        .map(|id| ExcludedClass {
            class: id.to_string(),
            reason: if current
                .excluded
                .iter()
                .chain(&incoming.excluded)
                .any(|e| e.class == id && e.reason == "cap")
            {
                "cap"
            } else {
                "no_signal"
            }
            .into(),
        })
        .collect();
    current.selected = selected;
    current.excluded = excluded;
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
                attack_classes: None,
                prior_status: None,
                checks: Vec::new(),
                hardening: Vec::new(),
                leads: Vec::new(),
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
                    merge_attack_classes(&mut coverage.attack_classes, entry.attack_classes);
                    reviewed.extend(entry.reviewed_paths);
                    truncated.extend(entry.truncated_paths);
                    ids.extend(entry.candidate_ids);
                    coverage.attempts.extend(entry.attempts);
                    for check in entry.checks {
                        if !coverage.checks.contains(&check) {
                            coverage.checks.push(check);
                        }
                    }
                    coverage.hardening.extend(entry.hardening);
                    coverage.leads.extend(entry.leads);
                }
                coverage.reviewed_paths = reviewed.into_iter().collect();
                coverage.truncated_paths = truncated.into_iter().collect();
                coverage.candidate_ids = ids.into_iter().collect();
                let all_complete = coverage.attempts.iter().all(|a| {
                    matches!(
                        a.status,
                        ModuleCoverageStatus::Covered
                            | ModuleCoverageStatus::ReviewedNoChecks
                            | ModuleCoverageStatus::Candidate
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
                    if (coverage.checks.is_empty()
                        || coverage.missing_class_check_reason().is_some())
                        && coverage.attempts.iter().any(|a| a.status.has_valid_reply())
                    {
                        ModuleCoverageStatus::ReviewedNoChecks
                    } else if all_complete {
                        ModuleCoverageStatus::Covered
                    } else {
                        ModuleCoverageStatus::PartiallyReviewed
                    }
                } else {
                    coverage.attempts[0].status
                };
                let mut reasons: Vec<String> = coverage
                    .attempts
                    .iter()
                    .filter_map(|a| a.reason.clone())
                    .collect();
                for (name, count) in [
                    ("hardening", coverage.hardening.len()),
                    ("leads", coverage.leads.len()),
                ] {
                    if count > 5 {
                        let note = format!(
                            "{name}: {} extra item(s) truncated across finder attempts (max 5)",
                            count - 5
                        );
                        // Keep aggregation notes even when the module reason is shallow_no_checks.
                        if let Some(attempt) = coverage.attempts.last_mut() {
                            attempt.reason = Some(match &attempt.reason {
                                Some(reason) => format!("{reason}; {note}"),
                                None => note.clone(),
                            });
                        }
                        reasons.push(note);
                    }
                }
                coverage.hardening.truncate(5);
                coverage.leads.truncate(5);
                coverage.reason = if coverage.status == ModuleCoverageStatus::ReviewedNoChecks {
                    Some(
                        coverage
                            .missing_class_check_reason()
                            .unwrap_or_else(|| "shallow_no_checks".into()),
                    )
                } else if reasons.is_empty() {
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
            attack_classes: None,
            checks: Vec::new(),
            hardening: Vec::new(),
            leads: Vec::new(),
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
            source_receipt: None,
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
                ModuleCoverageStatus::ReviewedNoChecks,
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
        assert_eq!(cov[0].reason.as_deref(), Some("shallow_no_checks"));
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
            assert_eq!(cov[0].status, ModuleCoverageStatus::ReviewedNoChecks);
            assert_eq!(cov[0].reviewed_paths, vec!["a/x.rs"]);
            assert!(super::super::schema::CoverageSummary::from_coverage(&cov).partial);
        }
    }

    #[test]
    fn auxiliary_notes_are_capped_across_finders_with_visible_reason() {
        let mut r = report("a", ModuleOutcome::Reviewed { note: None }, &[]);
        r.hardening = vec![
            super::super::schema::HardeningNote {
                file: "a/x.rs".into(),
                line: 1,
                note: "advice".into()
            };
            4
        ];
        r.leads = vec![
            super::super::schema::AuditLead {
                path: "b/x.rs".into(),
                reason: "flow".into()
            };
            4
        ];
        let coverage = build_module_coverage(&[target("a")], &[r.clone(), r]);
        assert_eq!(coverage[0].hardening.len(), 5);
        assert_eq!(coverage[0].leads.len(), 5);
        let reason = coverage[0]
            .attempts
            .last()
            .unwrap()
            .reason
            .as_ref()
            .unwrap();
        assert!(reason.contains("hardening: 3 extra"));
        assert!(reason.contains("leads: 3 extra"));
    }

    fn class_check(class: &str) -> super::super::schema::CoverageCheck {
        super::super::schema::CoverageCheck {
            attack_class: Some(class.into()),
            invariant: "Untrusted input cannot reach the sink without validation".into(),
            paths: vec!["a/x.rs".into()],
            result: "Reviewed the source and sink and their intervening checks".into(),
        }
    }

    #[test]
    fn attack_classes_require_every_selected_check_and_preserve_source_limits() {
        use super::super::attack_classes::{AttackClassMode, select};
        let mut r = report("a", ModuleOutcome::Reviewed { note: None }, &[]);
        r.attack_classes = select(
            AttackClassMode::Auto,
            &[("a/x.rs".into(), "eval( fetch(".into())],
        );
        r.checks = vec![class_check("injection")];
        let cov = build_module_coverage(&[target("a")], &[r.clone()]);
        assert_eq!(cov[0].status, ModuleCoverageStatus::ReviewedNoChecks);
        assert_eq!(
            cov[0].reason.as_deref(),
            Some("shallow_missing_class_checks: ssrf")
        );
        assert_eq!(cov[0].checks.len(), 1);
        r.checks.push(class_check("ssrf"));
        let cov = build_module_coverage(&[target("a")], &[r.clone()]);
        assert_eq!(cov[0].status, ModuleCoverageStatus::Covered);
        r.truncated_paths.push("a/x.rs".into());
        let cov = build_module_coverage(&[target("a")], &[r]);
        assert_eq!(cov[0].status, ModuleCoverageStatus::PartiallyReviewed);
    }

    #[test]
    fn attack_class_checks_aggregate_across_finders_without_erasing_selection() {
        use super::super::attack_classes::{AttackClassMode, select};
        let mut first = report("a", ModuleOutcome::Reviewed { note: None }, &[]);
        first.attack_classes = select(
            AttackClassMode::Auto,
            &[("a/x.rs".into(), "eval( fetch(".into())],
        );
        first.checks = vec![class_check("injection")];
        let mut second = first.clone();
        second.attack_classes =
            select(AttackClassMode::Auto, &[("a/x.rs".into(), "fetch(".into())]);
        second.checks = vec![class_check("ssrf")];
        for reports in [
            [first.clone(), second.clone()],
            [second.clone(), first.clone()],
        ] {
            let cov = build_module_coverage(&[target("a")], &reports);
            assert_eq!(cov[0].status, ModuleCoverageStatus::Covered);
            assert_eq!(
                cov[0].attack_classes.as_ref().unwrap().selected,
                ["injection", "ssrf"]
            );
        }
        second.checks.clear();
        let cov = build_module_coverage(&[target("a")], &[first, second]);
        assert_eq!(cov[0].status, ModuleCoverageStatus::ReviewedNoChecks);
    }

    #[test]
    fn attack_class_report_serialization_and_no_signal_stay_shallow() {
        use super::super::attack_classes::{AttackClassMode, select};
        let mut r = report("a", ModuleOutcome::Reviewed { note: None }, &[]);
        let cov = build_module_coverage(&[target("a")], &[r.clone()]);
        let json = serde_json::to_value(&cov[0]).unwrap();
        assert!(json.get("attack_classes").is_none());
        assert_eq!(
            serde_json::from_value::<ModuleCoverage>(json)
                .unwrap()
                .attack_classes,
            None
        );
        r.attack_classes = select(
            AttackClassMode::Auto,
            &[("a/x.rs".into(), "plain text".into())],
        );
        let cov = build_module_coverage(&[target("a")], &[r]);
        assert_eq!(cov[0].status, ModuleCoverageStatus::ReviewedNoChecks);
        assert_eq!(cov[0].reason.as_deref(), Some("shallow_no_checks"));
        let json = serde_json::to_value(&cov[0]).unwrap();
        assert_eq!(json["attack_classes"]["mode"], "auto");
        assert_eq!(json["attack_classes"]["selected"], serde_json::json!([]));
        assert_eq!(
            json["attack_classes"]["excluded"].as_array().unwrap().len(),
            8
        );
    }

    #[test]
    fn empty_ranking_is_empty_coverage() {
        assert!(build_module_coverage(&[], &[]).is_empty());
    }
}
