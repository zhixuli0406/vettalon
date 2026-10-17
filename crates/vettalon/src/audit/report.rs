//! Report rendering (human summary in the [`crate::lang`] language) + JSON file output + CI exit code.
//!
//! Mirrors the usual CI-gate convention: a human-readable summary is
//! always printed; `--report <path>` additionally writes the full JSON
//! report to disk. Exit code follows the task spec exactly: `0` when no
//! finding meets `--fail-on` (this also covers the "zero findings at all"
//! and "all scanners missing" cases — see `cmd_secaudit`'s dogfood
//! requirement), `1` when at least one does, `2` reserved for infra errors
//! that prevent `secaudit` itself from completing (invalid repo path,
//! `--report` file write failure) — never for "a scanner was unavailable",
//! which is an ordinary, honestly-reported outcome.

use std::path::{Path, PathBuf};

use vettalon_contract::coverage::RunStatus;

use crate::audit::schema::{
    AuditReport, ProfileMode, Severity, SeverityCounts, VerifierIndependence,
};
use crate::audit::validator::validate_report;
use crate::lang::pick;
use crate::tr;

/// CI exit code for a completed scan. `0` unless at least one finding the
/// gate reads ([`crate::audit::schema::Summary::gate_counts`] =
/// `by_severity`: `Candidate` / `Confirmed`, plus `NeedsHuman` under
/// `--fail-on-needs-human`, rule `schema::severity_buckets`) is at or
/// above `fail_on`. Pure function over the already-computed summary —
/// infra-level failures (bad repo path, can't write `--report`, a report
/// that fails validation) are decided by the caller and use `2` directly.
#[cfg(test)]
pub fn exit_code(report: &AuditReport, fail_on: Severity) -> i32 {
    exit_code_with(report, Some(fail_on))
}

/// [`exit_code`] with `--fail-on` optional (`none`, or only `--gate`
/// conditions set): `1` when the severity threshold is met or any policy
/// gate condition in `summary.policy` failed.
pub fn exit_code_with(report: &AuditReport, fail_on: Option<Severity>) -> i32 {
    let by_severity =
        fail_on.is_some_and(|s| report.summary.gate_counts().count_at_or_above(s) > 0);
    if by_severity || crate::audit::gate::any_failed(&report.summary.policy) {
        1
    } else {
        0
    }
}

/// zh-TW human-readable summary. Pure function (returns a `String`) so it's
/// testable without capturing stdout.
#[cfg(test)]
pub fn render_summary(report: &AuditReport, fail_on: Severity) -> String {
    render_summary_with(report, Some(fail_on))
}

/// [`render_summary`] with `--fail-on` optional and the policy gate shown.
pub fn render_summary_with(report: &AuditReport, fail_on: Option<Severity>) -> String {
    let mut out = String::new();
    out.push_str(pick(
        "程式碼安全審計（vettalon）\n",
        "Code security audit (vettalon)\n",
    ));
    out.push_str(&tr!("  掃描目標：{}\n", "  Target:  {}\n", report.repo));
    out.push_str(&tr!(
        "  掃描模式：{}\n",
        "  Profile: {}\n",
        match report.profile.mode {
            crate::audit::schema::ProfileMode::Quick => "quick",
            crate::audit::schema::ProfileMode::Deep => "deep",
        }
    ));
    out.push_str(&tr!(
        "  開始時間：{}\n",
        "  Started: {}\n",
        report.started_at
    ));
    out.push('\n');

    out.push_str(pick("引擎執行狀況：\n", "Engines:\n"));
    for run in &report.engines_run {
        if let Some(err) = &run.parse_error {
            let detail = if run.timed_out {
                tr!("逾時：{err}", "timed out: {err}")
            } else {
                err.clone()
            };
            out.push_str(&tr!(
                "  [異常] {} — {}\n",
                "  [error]   {} — {}\n",
                run.engine,
                detail
            ));
        } else {
            out.push_str(&tr!(
                "  [完成] {} — {} 個發現（{} ms）\n",
                "  [done]    {} — {} findings ({} ms)\n",
                run.engine,
                run.findings_count,
                run.duration_ms
            ));
        }
    }
    for missing in &report.engines_missing {
        out.push_str(&tr!(
            "  [略過] {} — {}\n",
            "  [skipped] {} — {}\n",
            missing.engine,
            missing.reason
        ));
    }
    if report.engines_run.is_empty() && report.engines_missing.is_empty() {
        out.push_str(pick("  （無引擎資訊）\n", "  (no engine information)\n"));
    }
    out.push('\n');

    out.push_str(pick("Findings 統計：\n", "Findings:\n"));
    let (gated, needs_human, inert) = finding_buckets(report);
    if needs_human + inert > 0 {
        out.push_str(&tr!(
            "  總計：{}（計入 fail-on {gated}、待人工判斷 {needs_human}、已證偽/已壓制 {inert}）\n",
            "  Total: {} ({gated} counted for --fail-on, {needs_human} need human review, {inert} refuted/suppressed)\n",
            report.summary.total_findings
        ));
        out.push_str(pick(
            "  （已證偽/已壓制的發現永遠不計入嚴重度統計與 fail-on 判定）\n",
            "  (refuted and suppressed findings never count toward severities or --fail-on)\n",
        ));
    } else {
        out.push_str(&tr!(
            "  總計：{}\n",
            "  Total: {}\n",
            report.summary.total_findings
        ));
    }
    out.push_str(&format!(
        "  {}\n",
        severity_row(&report.summary.by_severity)
    ));
    if report.summary.gate_includes_needs_human {
        // Flag on: NeedsHuman is already inside `by_severity`
        // (`schema::severity_buckets`); say so instead of a second row.
        let (with_nh, without_nh) = (
            crate::audit::schema::severity_buckets(&report.findings, true).0,
            crate::audit::schema::severity_buckets(&report.findings, false).0,
        );
        let nh = with_nh.total().saturating_sub(without_nh.total());
        if nh > 0 {
            out.push_str(&tr!(
                "  待人工判斷：{nh} 筆（模型自評、已計入上方統計與 fail-on，--fail-on-needs-human）\n",
                "  Needs human review: {nh} (model self-assessed; included above and in --fail-on, --fail-on-needs-human)\n"
            ));
        }
    } else {
        let nh = &report.summary.needs_human_by_severity;
        if nh.total() > 0 {
            out.push_str(&tr!(
                "  待人工判斷（模型自評、不計入 fail-on）：{}\n",
                "  Needs human review (model self-assessed, not counted for --fail-on): {}\n",
                severity_row(nh)
            ));
        }
    }
    if report.summary.carried_from_prior > 0 {
        out.push_str(&tr!(
            "  沿用先前報告判定：{}（原始碼未變更，未重新呼叫模型）\n",
            "  Carried over from the previous report: {} (source unchanged, models not called again)\n",
            report.summary.carried_from_prior
        ));
    }

    if report.profile.mode == ProfileMode::Deep {
        out.push('\n');
        out.push_str(pick(
            "AI 深度審計／對抗式覆核／PoC（deep profile）：\n",
            "AI audit / adversarial verification / PoC (deep profile):\n",
        ));
        out.push_str(&tr!(
            "  AI 候選：{}　已證偽：{}（其中前置檢查證偽 {}）　待人工覆核：{}　PoC 已執行：{}\n",
            "  AI candidates: {}  refuted: {} ({} by pre-checks)  needs human review: {}  PoCs run: {}\n",
            report.summary.ai_audit_candidates,
            report.summary.ai_audit_refuted,
            report.summary.precheck_refuted,
            report.summary.ai_audit_needs_human,
            report.summary.poc_ran,
        ));
        render_coverage(report, &mut out);
        render_verifier_and_prior(report, &mut out);
    }
    if report.run_status == RunStatus::Incomplete {
        out.push_str(&tr!(
            "  執行狀態：未完成（{}）\n",
            "  Run status: incomplete ({})\n",
            report
                .incomplete_reason
                .map(incomplete_reason)
                .unwrap_or_else(|| pick("原因未記錄", "reason not recorded"))
        ));
    }

    if let Some(intake) = &report.profile.intake {
        out.push('\n');
        out.push_str(pick(
            "Intake / 威脅建模（deep profile）：\n",
            "Intake / threat modelling (deep profile):\n",
        ));
        match &intake.git_history {
            crate::audit::intake::GitHistoryStatus::Available { hotspots } => {
                if hotspots.is_empty() {
                    out.push_str(pick(
                        "  git 熱點：近一年內無安全關鍵詞相關 commit\n",
                        "  git hotspots: no security-keyword commits in the past year\n",
                    ));
                } else {
                    out.push_str(pick(
                        "  git 熱點（近一年，安全關鍵詞 commit 觸及的檔案）：\n",
                        "  git hotspots (files touched by security-keyword commits in the past year):\n",
                    ));
                    for h in hotspots.iter().take(10) {
                        out.push_str(&tr!(
                            "    {} — 安全相關異動 {} 次（總異動 {} 次）\n",
                            "    {} — {} security-related changes ({} in total)\n",
                            h.file,
                            h.security_touches,
                            h.total_touches
                        ));
                    }
                }
            }
            crate::audit::intake::GitHistoryStatus::Unavailable { reason } => {
                out.push_str(&tr!(
                    "  git 熱點：不可用（{reason}）\n",
                    "  git hotspots: unavailable ({reason})\n"
                ));
            }
        }
        if !intake.entry_points.is_empty() {
            out.push_str(&tr!(
                "  偵測到的進入點：{}\n",
                "  Entry points detected: {}\n",
                intake.entry_points.join(", ")
            ));
        }
        if !intake.language_census.is_empty() {
            let top: Vec<String> = intake
                .language_census
                .iter()
                .take(5)
                .map(|s| format!("{}×{}", s.extension, s.file_count))
                .collect();
            out.push_str(&tr!(
                "  語言統計（前 5）：{}\n",
                "  Languages (top 5): {}\n",
                top.join(pick("、", ", "))
            ));
        }
    }

    out.push('\n');
    if !report.summary.policy.is_empty() {
        out.push_str(pick("政策門檻（--gate）：\n", "Policy gate (--gate):\n"));
        for r in &report.summary.policy {
            out.push_str(&tr!(
                "  [{}] {} — 實際 {} 筆\n",
                "  [{}] {} — {} matched\n",
                if r.failed {
                    pick("未通過", "fail")
                } else {
                    pick("通過", "pass")
                },
                r.expr,
                r.count
            ));
        }
        out.push('\n');
    }
    for finding in &report.findings {
        out.push_str(&format!(
            "  Proof {}:\n{}\n",
            finding.id,
            finding.proof_summary()
        ));
    }
    let policy_failed = crate::audit::gate::any_failed(&report.summary.policy);
    let severity_hits = fail_on.map(|s| (s, report.summary.gate_counts().count_at_or_above(s)));
    match severity_hits {
        Some((s, n)) if n > 0 => out.push_str(&tr!(
            "結論：發現 {n} 項 {} 以上等級的問題，未通過。\n",
            "Result: FAIL, {n} finding(s) at {} or above.\n",
            s.as_str()
        )),
        _ if policy_failed => out.push_str(pick(
            "結論：政策門檻有條件未通過，未通過。\n",
            "Result: FAIL, a policy gate condition failed.\n",
        )),
        Some((s, _)) => out.push_str(&tr!(
            "結論：未達 --fail-on 門檻（{}），視為通過。\n",
            "Result: PASS, nothing reached the --fail-on threshold ({}).\n",
            s.as_str()
        )),
        None if report.summary.policy.is_empty() => out.push_str(pick(
            "結論：未設定 --fail-on 或 --gate 門檻，僅供參考。\n",
            "Result: no --fail-on or --gate threshold set; for information only.\n",
        )),
        None => out.push_str(pick(
            "結論：政策門檻全部通過。\n",
            "Result: PASS, every policy gate condition passed.\n",
        )),
    }
    let failed = policy_failed || severity_hits.is_some_and(|(_, n)| n > 0);
    if !failed && report.run_status == RunStatus::Incomplete {
        out.push_str(pick(
            "注意：本次掃描不完整，通過只代表「已審查的部分」沒有達到門檻，不代表沒有問題。\n",
            "Note: this scan is incomplete. A pass only means the reviewed part stayed under the threshold, not that there are no problems.\n",
        ));
    }
    out
}

/// `(gated, needs_human, inert)` counted from the findings: refuted +
/// suppressed are inert; needs_human is its own bucket only when the
/// `--fail-on-needs-human` flag is off (otherwise it is gated, matching
/// `schema::severity_buckets`); everything else is gated.
fn finding_buckets(report: &AuditReport) -> (usize, usize, usize) {
    use crate::audit::schema::FindingStatus;
    let include_nh = report.summary.gate_includes_needs_human;
    let (mut gated, mut needs_human, mut inert) = (0, 0, 0);
    for f in &report.findings {
        match f.status {
            FindingStatus::Refuted | FindingStatus::Suppressed => inert += 1,
            FindingStatus::NeedsHuman if !include_nh => needs_human += 1,
            _ => gated += 1,
        }
    }
    (gated, needs_human, inert)
}

fn severity_row(c: &SeverityCounts) -> String {
    format!(
        "Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}",
        c.critical, c.high, c.medium, c.low, c.info
    )
}

fn incomplete_reason(r: vettalon_contract::coverage::IncompleteReason) -> &'static str {
    use vettalon_contract::coverage::IncompleteReason as R;
    match r {
        R::ScopeNotFullyReviewed => pick(
            "部分模組或原始碼未完整審查（模組／提示內容上限）",
            "some ranked modules or source bytes were excluded by module or prompt limits",
        ),
        R::EngineUnavailable => pick("AI 引擎無法使用", "the AI engine was unavailable"),
        R::ValidationBudgetExhausted => pick(
            "候選數已達全程上限（多模型時由各 finder 分攤），部分候選或模組未處理",
            "the run-wide candidate cap was reached (shared across finders), so some candidates or modules were not processed",
        ),
        R::BudgetCannotFundReserves => pick(
            "預算不足以保留覆核額度",
            "the budget could not reserve verification capacity",
        ),
        R::CriticBudgetExhausted => pick("覆核預算用盡", "the verification budget ran out"),
        R::TimeBudgetExhausted => pick(
            "已達掃描時間預算，部分模組未審（--time-budget）",
            "the time budget ran out and some modules were not reviewed (--time-budget)",
        ),
        R::Interrupted => pick("執行被中斷", "the run was interrupted"),
        R::ModelRefused => pick(
            "有模型拒答，對應的模組或發現未審",
            "a model refused, so the affected modules or findings were not reviewed",
        ),
        R::UnitsFailed => pick(
            "部分掃描引擎、模組或候選沒有得到可用結果（執行失敗、輸出格式錯誤或未覆核）",
            "some scan engines, modules, or candidates got no usable result (execution failed, malformed output, or not verified)",
        ),
        R::InjectionUncrosschecked => pick(
            "偵測到疑似 prompt injection 的模組，因本次只有單一模型家族，無法交叉覆審（建議加入不同家族的模型）",
            "modules with suspected prompt injection could not be cross-checked because only one model family was available (add a model from another family)",
        ),
    }
}

fn render_coverage(report: &AuditReport, out: &mut String) {
    let c = &report.summary.coverage;
    out.push_str(&tr!(
        "  模組覆蓋：共 {}　取得有效回覆 {}（完整無候選 {}、有候選 {}）　延後 {}　失敗 {}\n",
        "  Module coverage: {} total, {} with valid replies ({} fully reviewed without candidates, {} with candidates), {} deferred, {} failed\n",
        c.modules_total,
        c.covered + c.candidate + c.partially_reviewed,
        c.covered,
        c.candidate,
        c.deferred,
        c.failed
    ));
    if c.partial {
        out.push_str(&tr!(
            "  部分覆蓋：{} 模組未審，{} 模組僅部分完成；請查 JSON coverage 的檔案範圍與各次審查結果\n",
            "  Partial coverage: {} modules not reviewed, {} partially reviewed; inspect JSON coverage for file scope and finder attempts\n",
            c.deferred + c.failed, c.partially_reviewed
        ));
    }
}

fn render_verifier_and_prior(report: &AuditReport, out: &mut String) {
    let v = &report.verifier;
    let who = |a: &Option<String>| {
        a.clone()
            .unwrap_or_else(|| pick("（無）", "(none)").to_string())
    };
    let line = match v.independence {
        VerifierIndependence::NotRun => pick("未執行覆核", "not run").to_string(),
        VerifierIndependence::SameAgent => tr!(
            "同一 agent 覆核（{}）",
            "verified by the same agent ({})",
            who(&v.verifier_agent)
        ),
        VerifierIndependence::DifferentAgent => tr!(
            "獨立 agent 覆核（審計：{}；覆核：{}）",
            "verified by a separate agent (audit: {}; verify: {})",
            who(&v.audit_agent),
            who(&v.verifier_agent)
        ),
        VerifierIndependence::CrossFamily => tr!(
            "全部跨家族覆核（找洞：{}；覆核：{}）",
            "all cross-family (find: {}; verify: {})",
            who(&v.audit_agent),
            who(&v.verifier_agent)
        ),
        VerifierIndependence::MixedFamily => tr!(
            "部分跨家族覆核，部分同家族（找洞：{}；覆核：{}）",
            "partly cross-family, partly same-family (find: {}; verify: {})",
            who(&v.audit_agent),
            who(&v.verifier_agent)
        ),
        VerifierIndependence::SameFamily => tr!(
            "同家族覆核，模型清單裡沒有其他家族（找洞：{}；覆核：{}）",
            "same-family only, no other family in the roster (find: {}; verify: {})",
            who(&v.audit_agent),
            who(&v.verifier_agent)
        ),
    };
    out.push_str(&tr!(
        "  覆核獨立性：{line}\n",
        "  Verifier independence: {line}\n"
    ));
    let self_reviews = report
        .findings
        .iter()
        .flat_map(|f| f.verification.iter())
        .filter(|v| v.same_model && v.verdict != super::schema::VoteVerdict::NoVerdict)
        .count();
    if self_reviews > 0 {
        out.push_str(&tr!(
            "  自我覆核：{self_reviews} 筆由 finder 自己覆核（模型清單裡沒有其他可用的 verifier）\n",
            "  Self-review: {self_reviews} verified by their own finder (no other verifier available in the roster)\n"
        ));
    }
    let unverified = report
        .findings
        .iter()
        .filter(|f| {
            f.source_engine == super::schema::AI_AUDIT_ENGINE_NAME
                && f.status == super::schema::FindingStatus::Candidate
        })
        .count();
    if unverified > 0 {
        out.push_str(&tr!(
            "  未覆核：{unverified} 筆 AI 候選沒有得到覆核結論（見各發現的 verify_error）\n",
            "  Unverified: {unverified} AI candidates got no verification verdict (see each finding's verify_error)\n"
        ));
    }
    if report.ensemble.cross_checked > 0 {
        out.push_str(&tr!(
            "  雙模型複審：{} 個模組由兩家族各審一次（高風險、疑似 injection 或 --cross-check-top）\n",
            "  Cross-checked: {} modules reviewed once by each of two families (high risk, suspected injection, or --cross-check-top)\n",
            report.ensemble.cross_checked
        ));
    }
    if !report.ensemble.suspected_injection.is_empty() {
        out.push_str(&tr!(
            "  疑似 prompt injection：{} 個模組的原始碼含有針對審查模型的文字（已另交不同家族模型覆審；見 ensemble.suspected_injection）\n",
            "  Suspected prompt injection: {} modules contain text aimed at the reviewing model (sent to a different-family model for review; see ensemble.suspected_injection)\n",
            report.ensemble.suspected_injection.len()
        ));
        for s in &report.ensemble.suspected_injection {
            out.push_str(&format!(
                "    [injection:{}] {}\n",
                s.module_path,
                s.signals.join(",")
            ));
        }
    }
    if !report.ensemble.refusals.is_empty() {
        out.push_str(&tr!(
            "  模型拒答：{} 次（對應的模組／發現未審，未轉給其他模型）\n",
            "  Model refusals: {} (the affected modules/findings were not reviewed or passed to another model)\n",
            report.ensemble.refusals.len()
        ));
        for r in &report.ensemble.refusals {
            out.push_str(&tr!(
                "    [refused:{}] 步驟 {}\n",
                "    [refused:{}] step {}\n",
                r.model,
                r.step
            ));
        }
    }
    match &report.prior_run {
        Some(p) => out.push_str(&tr!(
            "  先前報告承接：{}　沿用已壓制 {}、沿用已證偽 {}、重新覆核先前確認 {}、原始碼已變更 {}\n",
            "  Previous report: {}  carried suppressed {}, carried refuted {}, re-verified previously confirmed {}, source changed {}\n",
            p.report_file,
            p.carried_suppressed,
            p.carried_refuted,
            p.revalidated_prior_confirmed,
            p.changed_source
        )),
        None => out.push_str(pick(
            "  先前報告承接：無（沒有可承接的先前報告，或已用 --no-prior 停用）\n",
            "  Previous report: none (no earlier report to carry over, or --no-prior)\n",
        )),
    }
}

/// Write the full JSON report to `path` (pretty-printed, matching the
/// eval`'s `--report` convention). The report validator runs first: a
/// report with any violation is not written and the error lists every
/// violation, one per line. Any failure here is an infra error (exit 2) at
/// the call site.
pub fn write_json_report(report: &AuditReport, path: &Path) -> std::io::Result<()> {
    let violations = validate_report(report);
    if !violations.is_empty() {
        let lines: Vec<String> = violations.iter().map(|v| v.to_string()).collect();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("report failed validation:\n{}", lines.join("\n")),
        ));
    }
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| std::io::Error::other(format!("serialize report: {e}")))?;
    crate::util::write_private(path, (json + "\n").as_bytes())
}

/// UTC ISO 8601 "basic" form (no separators — filesystem-safe, sorts
/// lexically = chronologically), e.g. `20260818T093000Z`. `prior_run`
/// relies on this ordering to find the newest report.
pub fn save_timestamp_basic(now: chrono::DateTime<chrono::Utc>) -> String {
    now.format("%Y%m%dT%H%M%SZ").to_string()
}

/// `--save`: write a copy of the report to
/// `<home>/reports/<UTC-ISO8601-basic>.json`, creating the directory if
/// needed, with owner-only (0600) permissions. Same JSON as `--report`
/// (this calls [`write_json_report`] at a different path). Returns the path
/// written.
pub fn save_report(home_dir: &Path, report: &AuditReport) -> std::io::Result<PathBuf> {
    // Validate before creating anything (write_json_report validates again;
    // this keeps a bad report from leaving an empty reports directory).
    let violations = validate_report(report);
    if !violations.is_empty() {
        let lines: Vec<String> = violations.iter().map(|v| v.to_string()).collect();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("report failed validation:\n{}", lines.join("\n")),
        ));
    }
    let dir = home_dir.join("reports");
    std::fs::create_dir_all(&dir)?;
    let filename = format!("{}.json", save_timestamp_basic(chrono::Utc::now()));
    let path = dir.join(filename);
    write_json_report(report, &path)?;
    // Best-effort: a permission-set failure shouldn't un-write an
    // already-saved report (the write already succeeded above).
    let _ = crate::util::set_owner_only(&path);
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::intake::{GitHistoryStatus, HotspotFile, LanguageStat, RepoProfile};
    use crate::audit::schema::{
        CURRENT_SCHEMA_VERSION, CoverageSummary, EngineMissing, EngineRun, Finding, FindingKind,
        FindingStatus, GatePolicy, PriorRunInfo, ProfileMode, ScanProfile, Summary, VerifierInfo,
    };

    fn base_report(findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            repo: "/tmp/repo".to_string(),
            started_at: "2026-08-17T00:00:00Z".to_string(),
            profile: ScanProfile {
                mode: ProfileMode::Quick,
                intake: None,
            },
            engines_run: vec![EngineRun {
                engine: "gitleaks".to_string(),
                findings_count: findings.len(),
                duration_ms: 10,
                parse_error: None,
                timed_out: false,
            }],
            engines_missing: vec![EngineMissing {
                engine: "osv-scanner".to_string(),
                reason: "requires network access".to_string(),
            }],
            summary: Summary::from_findings(&findings, 1, 1, GatePolicy::default(), &[]),
            findings,
            schema_version: CURRENT_SCHEMA_VERSION,
            run_status: RunStatus::Complete,
            incomplete_reason: None,
            coverage: vec![],
            prior_run: None,
            verifier: VerifierInfo::default(),
            ensemble: Default::default(),
        }
    }

    // ── exit_code ─────────────────────────────────────────────────────

    #[test]
    fn exit_code_zero_when_no_findings_at_all() {
        let report = base_report(vec![]);
        assert_eq!(exit_code(&report, Severity::High), 0);
    }

    #[test]
    fn exit_code_zero_when_findings_all_below_threshold() {
        let findings = vec![Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::Low,
            "t",
            "f",
            None,
            "s",
            "r",
            vec![],
        )];
        let report = base_report(findings);
        assert_eq!(exit_code(&report, Severity::High), 0);
    }

    #[test]
    fn exit_code_one_when_a_finding_meets_threshold() {
        let findings = vec![Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::High,
            "t",
            "f",
            None,
            "s",
            "r",
            vec![],
        )];
        let report = base_report(findings);
        assert_eq!(exit_code(&report, Severity::High), 1);
    }

    #[test]
    fn exit_code_one_when_a_finding_exceeds_threshold() {
        let findings = vec![Finding::candidate(
            "gitleaks",
            FindingKind::Secret,
            Severity::Critical,
            "t",
            "f",
            None,
            "s",
            "r",
            vec![],
        )];
        let report = base_report(findings);
        assert_eq!(exit_code(&report, Severity::Medium), 1);
    }

    #[test]
    fn exit_code_zero_on_machine_with_all_engines_missing() {
        // Dogfood requirement: a machine with zero scanners installed must
        // still produce exit 0 with an honest, non-empty engines_missing list.
        let report = AuditReport {
            repo: "/tmp/repo".to_string(),
            started_at: "2026-08-17T00:00:00Z".to_string(),
            profile: ScanProfile {
                mode: ProfileMode::Quick,
                intake: None,
            },
            engines_run: vec![],
            engines_missing: vec![
                EngineMissing {
                    engine: "semgrep".to_string(),
                    reason: "not installed".to_string(),
                },
                EngineMissing {
                    engine: "gitleaks".to_string(),
                    reason: "not installed".to_string(),
                },
                EngineMissing {
                    engine: "osv-scanner".to_string(),
                    reason: "network policy".to_string(),
                },
                EngineMissing {
                    engine: "cargo-audit".to_string(),
                    reason: "not applicable".to_string(),
                },
            ],
            findings: vec![],
            summary: Summary::from_findings(&[], 0, 4, GatePolicy::default(), &[]),
            schema_version: CURRENT_SCHEMA_VERSION,
            run_status: RunStatus::Complete,
            incomplete_reason: None,
            coverage: vec![],
            prior_run: None,
            verifier: VerifierInfo::default(),
            ensemble: Default::default(),
        };
        assert_eq!(exit_code(&report, Severity::High), 0);
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("semgrep"));
        assert!(text.contains("gitleaks"));
        assert!(text.contains("osv-scanner"));
        assert!(text.contains("cargo-audit"));
        assert!(text.contains("通過"));
    }

    // ── render_summary ───────────────────────────────────────────────

    #[test]
    fn render_summary_includes_repo_and_counts() {
        let findings = vec![Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::High,
            "t",
            "f",
            None,
            "s",
            "r",
            vec![],
        )];
        let report = base_report(findings);
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("/tmp/repo"));
        assert!(text.contains("總計：1"));
        assert!(text.contains("未通過"));
    }

    #[test]
    fn render_summary_shows_engine_run_and_missing_entries() {
        let report = base_report(vec![]);
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("gitleaks"));
        assert!(text.contains("osv-scanner"));
        assert!(text.contains("requires network access"));
    }

    #[test]
    fn render_summary_includes_deep_profile_intake_data() {
        let mut report = base_report(vec![]);
        report.profile.mode = ProfileMode::Deep;
        report.profile.intake = Some(RepoProfile {
            language_census: vec![LanguageStat {
                extension: "rs".to_string(),
                file_count: 42,
            }],
            entry_points: vec!["src/main.rs".to_string()],
            git_history: GitHistoryStatus::Available {
                hotspots: vec![HotspotFile {
                    file: "src/auth.rs".to_string(),
                    total_touches: 5,
                    security_touches: 3,
                }],
            },
        });
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("src/auth.rs"));
        assert!(text.contains("src/main.rs"));
        assert!(text.contains("rs×42"));
    }

    #[test]
    fn render_summary_reports_unavailable_git_history_honestly() {
        let mut report = base_report(vec![]);
        report.profile.mode = ProfileMode::Deep;
        report.profile.intake = Some(RepoProfile {
            language_census: vec![],
            entry_points: vec![],
            git_history: GitHistoryStatus::Unavailable {
                reason: "not a git repository".to_string(),
            },
        });
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("不可用"));
        assert!(text.contains("not a git repository"));
    }

    #[test]
    fn render_summary_marks_engine_parse_error() {
        let mut report = base_report(vec![]);
        report.engines_run.push(EngineRun {
            engine: "cargo-audit".to_string(),
            findings_count: 0,
            duration_ms: 5,
            parse_error: Some("JSON parse failed: unexpected token".to_string()),
            timed_out: false,
        });
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("[異常] cargo-audit"));
        assert!(text.contains("unexpected token"));
    }

    // ── write_json_report ────────────────────────────────────────────

    #[test]
    fn write_json_report_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let report = base_report(vec![]);
        write_json_report(&report, &path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: AuditReport = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.repo, "/tmp/repo");
    }

    #[test]
    fn write_json_report_fails_on_unwritable_path() {
        let report = base_report(vec![]);
        let bad_path = Path::new("/nonexistent-dir-xyz/report.json");
        assert!(write_json_report(&report, bad_path).is_err());
    }

    // ── deep-profile AI summary block ────────────────────────────────

    #[test]
    fn render_summary_shows_ai_audit_block_only_in_deep_profile() {
        let mut deep = base_report(vec![]);
        deep.profile.mode = ProfileMode::Deep;
        deep.summary.ai_audit_candidates = 3;
        deep.summary.ai_audit_refuted = 1;
        deep.summary.ai_audit_needs_human = 2;
        deep.summary.poc_ran = 1;
        let text = render_summary(&deep, Severity::High);
        assert!(text.contains("AI 深度審計"));
        assert!(text.contains("AI 候選：3"));
        assert!(text.contains("已證偽：1（其中前置檢查證偽 0）"));
        assert!(text.contains("待人工覆核：2"));
        assert!(text.contains("PoC 已執行：1"));

        let quick = base_report(vec![]); // mode defaults to Quick in base_report
        let text = render_summary(&quick, Severity::High);
        assert!(!text.contains("AI 深度審計"));
    }

    fn has_cjk(s: &str) -> bool {
        s.chars().any(|c| {
            ('\u{4e00}'..='\u{9fff}').contains(&c)
                || ('\u{3000}'..='\u{303f}').contains(&c)
                || ('\u{ff00}'..='\u{ffef}').contains(&c)
        })
    }

    #[test]
    fn render_summary_in_english_has_no_chinese() {
        use crate::lang::{Lang, with};
        let findings = vec![Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::High,
            "t",
            "f",
            None,
            "s",
            "r",
            vec![],
        )];
        let mut deep = base_report(findings);
        deep.profile.mode = ProfileMode::Deep;
        deep.summary.ai_audit_candidates = 3;
        deep.run_status = RunStatus::Incomplete;
        deep.incomplete_reason =
            Some(vettalon_contract::coverage::IncompleteReason::TimeBudgetExhausted);
        let text = with(Lang::En, || render_summary(&deep, Severity::High));
        assert!(text.starts_with("Code security audit (vettalon)"));
        assert!(text.contains("Total: 1"));
        assert!(text.contains("AI candidates: 3"));
        assert!(text.contains("Run status: incomplete (the time budget ran out"));
        assert!(text.contains("Result: FAIL, 1 finding(s) at high or above."));
        assert!(!has_cjk(&text), "Chinese text in English summary:\n{text}");

        let clean = base_report(vec![]);
        let text = with(Lang::En, || render_summary(&clean, Severity::High));
        assert!(text.contains("Result: PASS"));
        assert!(!has_cjk(&text), "Chinese text in English summary:\n{text}");
    }

    // ── save_timestamp_basic / save_report ───────────────────────────

    #[test]
    fn save_timestamp_basic_has_no_separators() {
        let ts = chrono::DateTime::parse_from_rfc3339("2026-08-18T09:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(save_timestamp_basic(ts), "20260818T093000Z");
    }

    #[test]
    fn save_report_creates_dir_and_writes_readable_json() {
        let home = tempfile::tempdir().unwrap();
        let report = base_report(vec![]);
        let path = save_report(home.path(), &report).unwrap();
        assert!(path.starts_with(home.path().join("reports")));
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: AuditReport = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.repo, "/tmp/repo");
    }

    #[cfg(unix)]
    #[test]
    fn save_report_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let report = base_report(vec![]);
        let path = save_report(home.path(), &report).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // ── v2 sections ──────────────────────────────────────────────────

    fn needs_human_high() -> Finding {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "t",
            "f",
            None,
            "s",
            "r",
            vec![],
        );
        f.status = FindingStatus::NeedsHuman;
        f
    }

    #[test]
    fn incomplete_pass_is_qualified() {
        let mut report = base_report(vec![]);
        assert!(!render_summary(&report, Severity::High).contains("本次掃描不完整"));
        report.run_status = RunStatus::Incomplete;
        report.incomplete_reason =
            Some(vettalon_contract::coverage::IncompleteReason::EngineUnavailable);
        assert!(render_summary(&report, Severity::High).contains("本次掃描不完整"));
    }

    #[test]
    fn needs_human_is_shown_but_not_gated_by_default() {
        let mut report = base_report(vec![]);
        report.summary =
            Summary::from_findings(&[needs_human_high()], 1, 1, GatePolicy::default(), &[]);
        assert_eq!(exit_code(&report, Severity::High), 0);
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("待人工判斷（模型自評、不計入 fail-on）"));
        assert!(text.contains("通過"));
    }

    #[test]
    fn fail_on_needs_human_gates_needs_human() {
        let mut report = base_report(vec![needs_human_high()]);
        report.summary = Summary::from_findings(
            &[needs_human_high()],
            1,
            1,
            GatePolicy {
                include_needs_human: true,
            },
            &[],
        );
        assert_eq!(exit_code(&report, Severity::High), 1);
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("待人工判斷：1 筆"));
        assert!(text.contains("已計入上方統計與 fail-on"));
        assert!(text.contains("High: 1"));
        assert!(text.contains("未通過"));
    }

    #[test]
    fn render_summary_shows_coverage_verifier_and_prior_in_deep_profile() {
        let mut report = base_report(vec![]);
        report.profile.mode = ProfileMode::Deep;
        report.summary.coverage = CoverageSummary {
            modules_total: 7,
            covered: 2,
            candidate: 1,
            deferred: 3,
            failed: 1,
            partial: true,
            ..Default::default()
        };
        report.verifier = VerifierInfo {
            independence: VerifierIndependence::DifferentAgent,
            audit_agent: Some("auditor".into()),
            verifier_agent: Some("checker".into()),
        };
        report.prior_run = Some(PriorRunInfo {
            report_file: "20261001T000000Z.json".into(),
            carried_suppressed: 1,
            carried_refuted: 2,
            revalidated_prior_confirmed: 0,
            changed_source: 4,
        });
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("模組覆蓋：共 7"));
        assert!(text.contains("部分覆蓋：4 模組未審"));
        assert!(text.contains("獨立 agent 覆核（審計：auditor；覆核：checker）"));
        assert!(text.contains("20261001T000000Z.json"));
        assert!(text.contains("原始碼已變更 4"));

        report.prior_run = None;
        report.verifier = VerifierInfo::default();
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("先前報告承接：無"));
        assert!(text.contains("未執行覆核"));
    }

    #[test]
    fn render_summary_marks_incomplete_runs() {
        let mut report = base_report(vec![]);
        report.run_status = RunStatus::Incomplete;
        report.incomplete_reason =
            Some(vettalon_contract::coverage::IncompleteReason::EngineUnavailable);
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("執行狀態：未完成（AI 引擎無法使用）"));
    }

    #[test]
    fn write_and_save_refuse_an_invalid_report() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = base_report(vec![]);
        report.schema_version = 1;
        let path = dir.path().join("r.json");
        let err = write_json_report(&report, &path).unwrap_err();
        assert!(err.to_string().contains("schema_version is 1"));
        assert!(!path.exists());
        let home = tempfile::tempdir().unwrap();
        assert!(save_report(home.path(), &report).is_err());
        assert!(!home.path().join("reports").exists());
    }

    #[test]
    fn total_line_shows_three_buckets_from_the_findings() {
        let mut refuted = needs_human_high();
        refuted.status = FindingStatus::Refuted;
        refuted.title = "other".into();
        refuted.file = "g".into();
        let scanner_hit = Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::Low,
            "t",
            "f",
            None,
            "s",
            "r",
            vec![],
        );
        let findings = vec![needs_human_high(), needs_human_high(), refuted, scanner_hit];
        let mut report = base_report(findings.clone());
        let text = render_summary(&report, Severity::High);
        assert!(
            text.contains("總計：4（計入 fail-on 1、待人工判斷 2、已證偽/已壓制 1）"),
            "{text}"
        );
        assert!(text.contains("永遠不計入嚴重度統計與 fail-on 判定"));

        // Live-run regression: 2 NeedsHuman, nothing refuted.
        let only_nh = base_report(vec![needs_human_high(), needs_human_high()]);
        let text = render_summary(&only_nh, Severity::High);
        assert!(
            text.contains("總計：2（計入 fail-on 0、待人工判斷 2、已證偽/已壓制 0）"),
            "{text}"
        );

        // Flag on: NeedsHuman is gated.
        report.summary = Summary::from_findings(
            &findings,
            1,
            1,
            GatePolicy {
                include_needs_human: true,
            },
            &[],
        );
        let text = render_summary(&report, Severity::High);
        assert!(
            text.contains("總計：4（計入 fail-on 3、待人工判斷 0、已證偽/已壓制 1）"),
            "{text}"
        );
    }
}
