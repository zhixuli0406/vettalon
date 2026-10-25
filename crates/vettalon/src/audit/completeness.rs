//! Evidence-derived scan gaps shared by the dashboard and exported reports.
//!
//! This does not change finding verdicts, scan policy, or CI exit codes. A
//! completed process may still have missing engines or unreviewed source.
use serde::Serialize;
use vettalon_contract::coverage::{IncompleteReason, RunStatus};

use super::schema::{AuditReport, FileReadStatus, ModuleCoverageStatus as S, ProfileMode};

const MAX_ISSUES: usize = 200;
const MAX_DETAIL_CHARS: usize = 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessState {
    Complete,
    Incomplete,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepairAction {
    ConfigureScan,
    Models,
    Tools,
    Files,
    ManualReview,
    Inspect,
}

#[derive(Debug, Clone, Serialize)]
pub struct Gap {
    pub code: String,
    pub subject: String,
    pub detail: Option<String>,
    pub detail_truncated: bool,
    pub action: RepairAction,
}

#[derive(Debug, Clone, Serialize)]
pub struct Completeness {
    pub state: CompletenessState,
    pub modules_total: usize,
    pub modules_fully_reviewed: usize,
    pub modules_partially_reviewed: usize,
    pub modules_not_reviewed: usize,
    pub total_issues: usize,
    pub omitted_issues: usize,
    pub issues: Vec<Gap>,
}

impl Completeness {
    fn push(&mut self, code: &str, subject: &str, detail: Option<&str>, action: RepairAction) {
        self.total_issues += 1;
        if !matches!(
            code,
            "coverage_unknown" | "coverage_unproven" | "engine_evidence_unknown"
        ) {
            self.state = CompletenessState::Incomplete;
        }
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(Gap {
                code: code.into(),
                subject: subject.into(),
                detail: detail.map(|s| s.chars().take(MAX_DETAIL_CHARS).collect()),
                detail_truncated: detail.is_some_and(|s| s.chars().count() > MAX_DETAIL_CHARS),
                action,
            });
        } else {
            self.omitted_issues += 1;
        }
    }
}

fn reason_code(reason: IncompleteReason) -> (&'static str, RepairAction) {
    use IncompleteReason as R;
    use RepairAction as A;
    match reason {
        R::BudgetCannotFundReserves | R::ValidationBudgetExhausted | R::CriticBudgetExhausted => {
            ("validation_budget", A::ConfigureScan)
        }
        R::TimeBudgetExhausted => ("time_budget", A::ConfigureScan),
        R::EngineUnavailable => ("engine_unavailable", A::Models),
        R::ScopeNotFullyReviewed => ("scope_partial", A::ConfigureScan),
        R::Interrupted => ("interrupted", A::ConfigureScan),
        R::ModelRefused => ("model_refused", A::ManualReview),
        R::UnitsFailed => ("units_failed", A::Inspect),
        R::InjectionUncrosschecked => ("injection_uncrosschecked", A::Models),
    }
}

fn module_code(status: S, reason: Option<&str>) -> (&'static str, RepairAction) {
    use RepairAction as A;
    match (status, reason) {
        (_, Some("max_modules")) => ("module_limit", A::ConfigureScan),
        (_, Some("time_budget")) => ("time_budget", A::ConfigureScan),
        (_, Some("prescreen_cut")) => ("prescreen_cut", A::ConfigureScan),
        (_, Some("candidate_cap")) => ("candidate_limit", A::ConfigureScan),
        (_, Some("engine_unavailable")) => ("engine_unavailable", A::Models),
        (S::Unreadable, _) => ("source_unreadable", A::Files),
        (S::LlmFailed, _) => ("model_failed", A::Models),
        (S::ParseFailed, _) => ("model_output", A::Models),
        (S::PartiallyReviewed, _) => ("scope_partial", A::ConfigureScan),
        _ => ("module_deferred", A::Inspect),
    }
}

/// Recompute from source evidence; never trust a serialized display diagnosis.
pub fn diagnose(report: &AuditReport) -> Completeness {
    use RepairAction as A;
    let deep = report.profile.mode == ProfileMode::Deep;
    let mut out = Completeness {
        state: CompletenessState::Complete,
        modules_total: report.coverage.len(),
        modules_fully_reviewed: 0,
        modules_partially_reviewed: 0,
        modules_not_reviewed: 0,
        total_issues: 0,
        omitted_issues: 0,
        issues: vec![],
    };
    if let Some(reason) = report.incomplete_reason {
        let (code, action) = reason_code(reason);
        out.push(code, &report.repo, Some(&reason.to_string()), action);
    } else if report.run_status == RunStatus::Incomplete {
        out.push("unknown_reason", &report.repo, None, A::Inspect);
    }
    for engine in &report.engines_missing {
        if engine.reason.starts_with("not applicable") {
            continue;
        }
        // Policy exclusions remain exclusions even after installing the tool.
        // Do not turn this into an installation or blind-rerun instruction.
        if engine.reason.to_ascii_lowercase().contains("zero-network") {
            out.push(
                "engine_network_policy",
                &engine.engine,
                Some(&engine.reason),
                A::Inspect,
            );
            continue;
        }
        let action = if engine.engine.starts_with("ai_audit") {
            A::Models
        } else {
            A::Tools
        };
        out.push(
            "engine_missing",
            &engine.engine,
            Some(&engine.reason),
            action,
        );
    }
    for engine in &report.engines_run {
        if engine.timed_out {
            out.push(
                "engine_timeout",
                &engine.engine,
                engine.parse_error.as_deref(),
                A::ConfigureScan,
            );
        } else if let Some(error) = &engine.parse_error {
            out.push("engine_output", &engine.engine, Some(error), A::Tools);
        }
    }
    for module in &report.coverage {
        if module.has_full_review() {
            out.modules_fully_reviewed += 1;
        } else if module.has_effective_review() {
            out.modules_partially_reviewed += 1;
        } else {
            out.modules_not_reviewed += 1;
        }
        let before = out.total_issues;
        if !matches!(module.status, S::Covered | S::Candidate) {
            let (code, action) = module_code(module.status, module.reason.as_deref());
            out.push(code, &module.module_path, module.reason.as_deref(), action);
        }
        for attempt in &module.attempts {
            let subject = format!("{} · {}", module.module_path, attempt.model);
            if attempt.timed_out {
                out.push(
                    "model_timeout",
                    &subject,
                    attempt.reason.as_deref(),
                    A::ConfigureScan,
                );
            } else if !matches!(
                attempt.status,
                S::Covered | S::Candidate | S::PartiallyReviewed
            ) {
                let (code, action) = module_code(attempt.status, attempt.reason.as_deref());
                out.push(code, &subject, attempt.reason.as_deref(), action);
            }
            for file in &attempt.files {
                let subject = format!("{} · {}", file.path, attempt.model);
                let code = match file.read_status {
                    FileReadStatus::Unreadable => Some(("source_unreadable", A::Files)),
                    FileReadStatus::BudgetExcluded => Some(("source_excluded", A::ConfigureScan)),
                    _ if file.truncated => Some(("source_truncated", A::ConfigureScan)),
                    _ => None,
                };
                if let Some((code, action)) = code {
                    let detail = format!(
                        "{}; submitted_bytes={}; source_bytes={}",
                        file.reason.as_deref().unwrap_or(""),
                        file.submitted_bytes,
                        file.source_bytes
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "unknown".into())
                    );
                    out.push(code, &subject, Some(&detail), action);
                }
            }
        }
        if module.attempts.is_empty() {
            for path in &module.truncated_paths {
                out.push("source_truncated", path, None, A::ConfigureScan);
            }
        }
        if !module.has_full_review() && out.total_issues == before {
            out.push(
                "coverage_unproven",
                &module.module_path,
                module.reason.as_deref(),
                A::Inspect,
            );
        }
    }
    for refusal in &report.ensemble.refusals {
        out.push(
            "model_refused",
            &format!("{} · {}", refusal.model, refusal.step),
            Some(&refusal.excerpt),
            A::ManualReview,
        );
    }
    let legacy = report.schema_version < 2 || (deep && report.coverage.is_empty());
    let has_gap = out.state == CompletenessState::Incomplete
        || report.run_status == RunStatus::Incomplete
        || report.summary.coverage.partial;
    if report.summary.coverage.partial && out.total_issues == 0 {
        out.push("scope_partial", &report.repo, None, A::Inspect);
    }
    if legacy {
        out.push("coverage_unknown", &report.repo, None, A::Inspect);
    }
    // An empty or entirely inapplicable engine list is not evidence of any
    // successful check. Existing explicit failures already explain their gap.
    if !has_gap
        && !report
            .engines_run
            .iter()
            .any(|engine| !engine.timed_out && engine.parse_error.is_none())
    {
        out.push("engine_evidence_unknown", &report.repo, None, A::Inspect);
    }
    out.state = if has_gap {
        CompletenessState::Incomplete
    } else if legacy || out.total_issues > 0 {
        CompletenessState::Unknown
    } else {
        CompletenessState::Complete
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{EngineMissing, EngineRun};
    fn report() -> AuditReport {
        serde_json::from_str(include_str!(
            "../../../../fixtures/coverage/samples/complete.json"
        ))
        .unwrap()
    }
    #[test]
    fn engine_gaps_survive_complete_status_and_not_applicable_is_excluded() {
        let mut r = report();
        r.engines_missing = vec![EngineMissing {
            engine: "cargo-audit".into(),
            reason: "not applicable: no lockfile".into(),
        }];
        let before = diagnose(&r).total_issues;
        r.engines_missing.push(EngineMissing {
            engine: "semgrep".into(),
            reason: "not installed".into(),
        });
        let d = diagnose(&r);
        assert_eq!(d.total_issues, before + 1);
        assert_eq!(d.state, CompletenessState::Incomplete);
        assert!(
            d.issues
                .iter()
                .any(|i| i.subject == "semgrep" && i.code == "engine_missing")
        );
    }
    #[test]
    fn explicit_timeout_and_untrusted_output_are_not_clean_runs() {
        let mut r = report();
        r.engines_run = vec![EngineRun {
            engine: "fixture".into(),
            findings_count: 0,
            duration_ms: 1,
            parse_error: Some("malformed output".into()),
            timed_out: false,
        }];
        assert!(
            diagnose(&r)
                .issues
                .iter()
                .any(|i| i.code == "engine_output")
        );
        r.engines_run[0].timed_out = true;
        assert!(
            diagnose(&r)
                .issues
                .iter()
                .any(|i| i.code == "engine_timeout")
        );
    }
    #[test]
    fn issues_are_bounded_without_hiding_the_total() {
        let mut r = report();
        r.engines_missing = (0..250)
            .map(|n| EngineMissing {
                engine: format!("tool-{n}"),
                reason: "x".repeat(2000),
            })
            .collect();
        let d = diagnose(&r);
        assert_eq!(d.issues.len(), MAX_ISSUES);
        assert_eq!(d.total_issues, d.issues.len() + d.omitted_issues);
        let item = d
            .issues
            .iter()
            .find(|x| x.code == "engine_missing")
            .unwrap();
        assert!(item.detail_truncated);
        assert_eq!(
            item.detail.as_ref().unwrap().chars().count(),
            MAX_DETAIL_CHARS
        );
    }
    #[test]
    fn old_deep_report_is_unknown_not_fully_reviewed() {
        let mut r = report();
        r.schema_version = 1;
        r.coverage.clear();
        r.engines_missing.clear();
        r.incomplete_reason = None;
        r.run_status = RunStatus::Complete;
        r.summary.coverage.partial = false;
        assert_eq!(diagnose(&r).state, CompletenessState::Unknown);
    }

    #[test]
    fn successful_finder_does_not_hide_failed_second_attempt() {
        let mut r = report();
        r.engines_missing.clear();
        let mut failed = r.coverage[0].attempts[0].clone();
        failed.model = "second-model".into();
        failed.status = S::LlmFailed;
        failed.reason = Some("connection failed".into());
        r.coverage[0].attempts.push(failed);
        let d = diagnose(&r);
        assert_eq!(d.state, CompletenessState::Incomplete);
        assert!(
            d.issues
                .iter()
                .any(|i| i.code == "model_failed" && i.subject.contains("second-model"))
        );
        assert_eq!(d.modules_fully_reviewed, 0);
        assert_eq!(d.modules_partially_reviewed, 1);
    }

    #[test]
    fn truncated_and_budget_excluded_files_have_distinct_repair_causes() {
        let mut r = report();
        r.engines_missing.clear();
        r.coverage[0].attempts[0].files[0].truncated = true;
        let d = diagnose(&r);
        assert!(
            d.issues
                .iter()
                .any(|i| i.code == "source_truncated" && i.subject.contains("a/util.py"))
        );
        r.coverage[0].attempts[0].files[0].read_status = FileReadStatus::BudgetExcluded;
        let d = diagnose(&r);
        assert!(d.issues.iter().any(|i| i.code == "source_excluded"));
        assert!(!d.issues.iter().any(|i| i.code == "source_truncated"));
    }

    #[test]
    fn planned_scope_has_specific_limits_and_does_not_claim_a_rerun_is_a_fix() {
        let mut r = report();
        r.coverage[0].status = S::Deferred;
        r.coverage[0].reason = Some("max_modules".into());
        r.coverage[0].attempts.clear();
        let d = diagnose(&r);
        let item = d.issues.iter().find(|i| i.code == "module_limit").unwrap();
        assert_eq!(item.subject, "a");
        assert_eq!(item.action, RepairAction::ConfigureScan);
        assert_eq!(d.modules_not_reviewed, 1);
    }

    #[test]
    fn completed_quick_scan_without_successful_engine_evidence_is_unknown() {
        let mut r = report();
        r.profile.mode = ProfileMode::Quick;
        r.profile.intake = None;
        r.coverage.clear();
        r.engines_run.clear();
        r.engines_missing.clear();
        r.summary.coverage = Default::default();
        r.run_status = RunStatus::Complete;
        r.incomplete_reason = None;
        for missing in [
            vec![],
            vec![EngineMissing {
                engine: "cargo-audit".into(),
                reason: "not applicable: no Cargo.lock".into(),
            }],
        ] {
            r.engines_missing = missing;
            let d = diagnose(&r);
            assert_eq!(d.state, CompletenessState::Unknown);
            assert_eq!(d.modules_total, 0);
            assert_eq!(d.modules_fully_reviewed, 0);
            assert!(d.issues.iter().any(|i| i.code == "engine_evidence_unknown"));
            assert!(!d.issues.iter().any(|i| i.code == "engine_missing"));
        }
        r.engines_run.push(EngineRun {
            engine: "fixture-scanner".into(),
            findings_count: 0,
            duration_ms: 1,
            parse_error: None,
            timed_out: false,
        });
        let d = diagnose(&r);
        assert_eq!(d.state, CompletenessState::Complete);
        assert_eq!(d.total_issues, 0);
        r.engines_run[0].timed_out = true;
        let d = diagnose(&r);
        assert_eq!(d.state, CompletenessState::Incomplete);
        assert!(d.issues.iter().any(|i| i.code == "engine_timeout"));
        assert!(!d.issues.iter().any(|i| i.code == "engine_evidence_unknown"));
    }

    #[test]
    fn network_policy_exclusion_is_not_fixed_by_installing_the_tool() {
        let mut r = report();
        for reason in [
            "installed but skipped: osv-scanner queries the network OSV vulnerability database; disabled under vettalon's zero-network policy — run it manually for CVE coverage",
            "not installed, and would be skipped anyway: osv-scanner requires network access to query the OSV database, disabled under vettalon's zero-network policy",
        ] {
            r.engines_missing = vec![EngineMissing {
                engine: "osv-scanner".into(),
                reason: reason.into(),
            }];
            let d = diagnose(&r);
            assert_eq!(d.state, CompletenessState::Incomplete);
            let gap = d
                .issues
                .iter()
                .find(|i| i.subject == "osv-scanner")
                .unwrap();
            assert_eq!(gap.code, "engine_network_policy");
            assert_eq!(gap.action, RepairAction::Inspect);
            assert_eq!(gap.detail.as_deref(), Some(reason));
            assert!(
                !d.issues
                    .iter()
                    .any(|i| i.subject == "osv-scanner" && i.code == "engine_missing")
            );
        }
    }
}
