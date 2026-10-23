//! Report rendering (human summary in the [`crate::lang`] language) + JSON file output + CI exit code.
//!
//! Mirrors the usual CI-gate convention: a human-readable summary is
//! always printed; `--report <path>` additionally writes the full JSON
//! report to disk. Exit code: `0` when no finding meets `--fail-on` (this
//! also covers the "zero findings at all" and "all scanners missing" cases
//! — see `cmd_secaudit`'s dogfood requirement), `1` when at least one does,
//! `2` reserved for infra errors that prevent the scan itself from
//! completing (invalid repo path, `--report` file write failure), and
//! [`AI_UNAVAILABLE_EXIT`] (`4`) when a deep scan's AI audit could not run
//! at all. A missing OSS scanner is still an ordinary, honestly-reported
//! outcome; a deep scan that reviewed nothing with AI is not, because CI
//! would otherwise read it as a clean deep scan.

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

/// Exit code of a deep scan whose AI audit could not run at all (see
/// [`ai_audit_unavailable`]). `3` is not used because the Vettalon Pro CLI already
/// exits 3 for "license required"; keeping the codes disjoint lets a script
/// that calls both binaries tell them apart.
pub const AI_UNAVAILABLE_EXIT: i32 = 4;

/// A deep scan in which no AI finder engine produced a single review: every
/// configured finder failed before reaching its model (container image
/// missing, CLI not found, provider unreachable), or no finder was
/// configured although there were modules to audit. The report then says
/// `incomplete` / `engine_unavailable` and has no `ai_audit` engine run.
/// When at least one finder ran, the run is partial instead (still
/// `engine_unavailable`, with the missing finders under `engines_missing`)
/// and this is false. Pure: derived from the report alone.
pub fn ai_audit_unavailable(report: &AuditReport) -> bool {
    report.profile.mode == ProfileMode::Deep
        && report.run_status == RunStatus::Incomplete
        && report.incomplete_reason
            == Some(vettalon_contract::coverage::IncompleteReason::EngineUnavailable)
        && !report
            .engines_run
            .iter()
            .any(|r| r.engine.starts_with(AI_AUDIT_ENGINE))
}

/// AI finder engines listed under `engines_missing` (`ai_audit[<model>]`,
/// or `ai_audit` when no finder was configured).
fn missing_ai_engines(report: &AuditReport) -> usize {
    report
        .engines_missing
        .iter()
        .filter(|m| m.engine.starts_with(AI_AUDIT_ENGINE))
        .count()
}

pub(super) const AI_AUDIT_ENGINE: &str = "ai_audit";

/// `vettalon scan`'s exit code: [`AI_UNAVAILABLE_EXIT`] when the deep AI
/// audit could not run at all (unless `allow_incomplete`), else
/// [`exit_code_with`]. It takes precedence over `1`: a gate verdict over a
/// deep scan that reviewed nothing with AI is not the result that was asked
/// for. The summary's verdict then says "incomplete" and prints a failed
/// gate on its own line (`report_verdict`).
pub fn scan_exit_code(
    report: &AuditReport,
    fail_on: Option<Severity>,
    allow_incomplete: bool,
) -> i32 {
    if !allow_incomplete && ai_audit_unavailable(report) {
        AI_UNAVAILABLE_EXIT
    } else {
        exit_code_with(report, fail_on)
    }
}

/// zh-TW human-readable summary. Pure function (returns a `String`) so it's
/// testable without capturing stdout.
#[cfg(test)]
pub fn render_summary(report: &AuditReport, fail_on: Severity) -> String {
    render_summary_with(report, Some(fail_on))
}

/// [`render_summary`] with `--fail-on` optional and the policy gate shown.
/// The verdict matches `vettalon scan` without `--allow-incomplete`.
#[cfg(test)]
pub fn render_summary_with(report: &AuditReport, fail_on: Option<Severity>) -> String {
    render_scan_summary(report, fail_on, false)
}

/// The summary `vettalon scan` prints. `allow_incomplete` only changes the
/// verdict lines of a deep scan whose AI audit could not run at all (see
/// `report_verdict`), matching [`scan_exit_code`].
pub fn render_scan_summary(
    report: &AuditReport,
    fail_on: Option<Severity>,
    allow_incomplete: bool,
) -> String {
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
            run_status_reason(report)
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
    crate::audit::report_evidence::render_finding_evidence(report, &mut out);
    crate::audit::report_verdict::render_verdict(report, fail_on, allow_incomplete, &mut out);
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

/// The "Run status: incomplete (...)" text. `engine_unavailable` is split
/// into "no AI engine ran" and "some did not", which the reason code alone
/// cannot tell apart.
fn run_status_reason(report: &AuditReport) -> String {
    use vettalon_contract::coverage::IncompleteReason as R;
    match report.incomplete_reason {
        Some(R::EngineUnavailable) if ai_audit_unavailable(report) => pick(
            "沒有任何 AI 引擎能執行，AI 審查一個模組都沒有審",
            "no AI engine could run, so the AI audit reviewed no module",
        )
        .to_string(),
        Some(R::EngineUnavailable) if missing_ai_engines(report) > 0 => {
            let n = missing_ai_engines(report);
            tr!(
                "{n} 個 AI 引擎無法使用，分給它的模組沒有審查；其他引擎照常執行",
                "{n} AI engine(s) were unavailable and the modules assigned to them were not reviewed; the other engines ran"
            )
        }
        Some(r) => incomplete_reason(r).to_string(),
        None => pick("原因未記錄", "reason not recorded").to_string(),
    }
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
        R::CriticBudgetExhausted => pick(
            "覆核預算用盡，部分發現未覆核（--refuter-budget）",
            "the verification budget ran out and some findings were not reviewed (--refuter-budget)",
        ),
        R::TimeBudgetExhausted => pick(
            "已達時間預算，部分模組未審或 PoC 未執行（--time-budget、--finder-budget 或 --poc-budget）",
            "the time budget ran out, so some modules were not reviewed or some PoCs did not run (--time-budget, --finder-budget or --poc-budget)",
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
    // Findings, not votes: repeated refuter runs add one vote per run.
    let self_reviews = report
        .findings
        .iter()
        .filter(|f| {
            f.verification
                .iter()
                .any(|v| v.same_model && v.verdict != super::schema::VoteVerdict::NoVerdict)
        })
        .count();
    if self_reviews > 0 {
        out.push_str(&tr!(
            "  自我覆核：{self_reviews} 筆由 finder 自己覆核（模型清單裡沒有其他可用的 verifier）\n",
            "  Self-review: {self_reviews} verified by their own finder (no other verifier available in the roster)\n"
        ));
    }
    let pending: Vec<&super::schema::Finding> = report
        .findings
        .iter()
        .filter(|f| {
            f.source_engine == super::schema::AI_AUDIT_ENGINE_NAME
                && f.status == super::schema::FindingStatus::Candidate
        })
        .collect();
    let uncertain = pending
        .iter()
        .filter(|f| {
            f.evidence
                .iter()
                .any(|e| e.kind == super::schema::EvidenceKind::VerifyUncertain)
        })
        .count();
    let unverified = pending.len() - uncertain;
    if uncertain > 0 {
        out.push_str(&tr!(
            "  覆核不一致：{uncertain} 筆 AI 候選的多次反駁覆核結論不一致，維持 candidate（見各發現的 verify_uncertain）\n",
            "  Inconsistent: {uncertain} AI candidates got disagreeing verdicts from repeated refuter runs and stay candidate (see each finding's verify_uncertain)\n"
        ));
    }
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
    if let Some(d) = &report.ensemble.dual_finder {
        render_dual_finder(d, out);
    }
    let count_kind = |k: super::schema::EvidenceKind| {
        report
            .findings
            .iter()
            .filter(|f| f.evidence.iter().any(|e| e.kind == k))
            .count()
    };
    let sensitive = count_kind(super::schema::EvidenceKind::CommentSensitivity);
    if sensitive > 0 {
        out.push_str(&tr!(
            "  註解影響判斷：{sensitive} 筆發現在「看得到註解」與「去除註解」兩種覆核下結論相反（見 comment_sensitivity；可能是註解植入攻擊）\n",
            "  Comment-sensitive: {sensitive} findings got opposite verdicts with and without code comments (see comment_sensitivity; possible comment injection)\n"
        ));
    }
    let tier_split = report
        .findings
        .iter()
        .filter(|f| super::exploitability::assess_finding(f).disagreement())
        .count();
    if tier_split > 0 {
        out.push_str(&tr!(
            "  可利用性判斷不一致：{tier_split} 筆發現的發現模型與反駁覆核給出不同可利用性等級，已採摩擦較高者（見 tier_disagreement）\n",
            "  Tier disagreement: {tier_split} findings got a different exploitability tier from the refuter than from the finder; the higher-friction tier is used (see tier_disagreement)\n"
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

/// Names `--save` tries for one timestamp before giving up (the first plus
/// `-1` … `-99`). Only reached when other runs saved in the same
/// microsecond.
const SAVE_NAME_ATTEMPTS: u32 = 100;

/// File name of a `--save` copy: UTC ISO 8601 "basic" form with
/// microseconds (no separators, filesystem-safe), e.g.
/// `20260818T093000.123456Z.json`; `attempt` > 0 appends `-<attempt>` when
/// that name is already taken. Older versions saved
/// `20260818T093000Z.json`; [`saved_report_sort_key`] orders both forms.
pub fn saved_report_filename(now: chrono::DateTime<chrono::Utc>, attempt: u32) -> String {
    let stem = now.format("%Y%m%dT%H%M%S%.6fZ");
    if attempt == 0 {
        format!("{stem}.json")
    } else {
        format!("{stem}-{attempt}.json")
    }
}

/// Sort key for a file name under `<home>/reports/`: ascending = older to
/// newer. Saved names (`<YYYYMMDD>T<HHMMSS>[.<fraction>]Z[-<n>].json`) order
/// by second, then fraction, then collision suffix; an older name without
/// a fraction counts as the start of its second. Any other name keeps plain
/// lexical order against the timestamp part, as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SavedReportKey<'a> {
    second: &'a str,
    nanos: u32,
    seq: u32,
    name: &'a str,
}

pub fn saved_report_sort_key(name: &str) -> SavedReportKey<'_> {
    parse_saved_report_name(name).unwrap_or(SavedReportKey {
        second: name,
        nanos: 0,
        seq: 0,
        name,
    })
}

fn parse_saved_report_name(name: &str) -> Option<SavedReportKey<'_>> {
    let stem = name.strip_suffix(".json")?;
    let second = stem.get(..15)?;
    let all_digits = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_digit);
    let b = second.as_bytes();
    if !(all_digits(&b[..8]) && b[8] == b'T' && all_digits(&b[9..])) {
        return None;
    }
    let rest = &stem[15..];
    let (fraction, rest) = match rest.strip_prefix('.') {
        Some(r) => {
            let end = r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len());
            if end == 0 || end > 9 {
                return None;
            }
            (&r[..end], &r[end..])
        }
        None => ("", rest),
    };
    let rest = rest.strip_prefix('Z')?;
    let seq = if rest.is_empty() {
        0
    } else {
        let n = rest.strip_prefix('-')?;
        if !all_digits(n.as_bytes()) {
            return None;
        }
        n.parse().ok()?
    };
    let nanos = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<9}").parse().ok()?
    };
    Some(SavedReportKey {
        second,
        nanos,
        seq,
        name,
    })
}

/// `--save`: write a copy of the report to
/// `<home>/reports/<UTC-ISO8601-basic>.json` (see [`saved_report_filename`]),
/// creating the directory if needed, with owner-only (0600) permissions.
/// Same JSON as `--report`. An existing saved report is never overwritten:
/// the copy is written to a temporary file in the same directory and moved
/// to its final name only if that name is free (otherwise the next suffix
/// is tried), so runs that finish in the same instant, also in separate
/// processes, each keep their own file and nobody reads a half-written one.
/// Returns the path written.
pub fn save_report(home_dir: &Path, report: &AuditReport) -> std::io::Result<PathBuf> {
    save_report_at(home_dir, report, chrono::Utc::now())
}

fn save_report_at(
    home_dir: &Path,
    report: &AuditReport,
    now: chrono::DateTime<chrono::Utc>,
) -> std::io::Result<PathBuf> {
    use std::io::Write;
    // Validate before creating anything, so a bad report never leaves an
    // empty reports directory.
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
    let dir = home_dir.join("reports");
    std::fs::create_dir_all(&dir)?;
    // Not `.json`, so `prior_run` never picks up a temporary file. Created
    // 0600 on Unix and removed on drop if it is never persisted.
    let mut tmp = tempfile::Builder::new()
        .prefix(".save-")
        .suffix(".tmp")
        .tempfile_in(&dir)?;
    tmp.write_all(json.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    for attempt in 0..SAVE_NAME_ATTEMPTS {
        let path = dir.join(saved_report_filename(now, attempt));
        match tmp.persist_noclobber(&path) {
            Ok(_) => {
                // Best-effort: the copy is already saved.
                let _ = crate::util::set_owner_only(&path);
                return Ok(path);
            }
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => tmp = e.file,
            Err(e) => return Err(e.error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "{SAVE_NAME_ATTEMPTS} saved-report names for {} are already taken in {}",
            saved_report_filename(now, 0),
            dir.display()
        ),
    ))
}

/// O9 `--dual-finder-top`: per-family unique root causes and the marginal
/// yield of the added finder family.
fn render_dual_finder(d: &crate::audit::DualFinderReport, out: &mut String) {
    if let Some(why) = &d.skipped {
        out.push_str(&tr!(
            "  雙家族 finder（--dual-finder-top {}）：未執行，{why}\n",
            "  Dual finder (--dual-finder-top {}): not run, {why}\n",
            d.top
        ));
        return;
    }
    let merged = d.merged_same_patch + d.merged_location_cwe + d.merged_identical_claim;
    out.push_str(&tr!(
        "  雙家族 finder（--dual-finder-top {}）：{} 個模組，合併 {merged} 筆重複（同一修補 {}、位置＋CWE {}、相同主張 {}），兩家族都找到的根因 {}\n",
        "  Dual finder (--dual-finder-top {}): {} modules, {merged} duplicates merged (same patch {}, location+CWE {}, identical claim {}), {} root causes found by both families\n",
        d.top,
        d.modules.len(),
        d.merged_same_patch,
        d.merged_location_cwe,
        d.merged_identical_claim,
        d.shared_root_causes
    ));
    for y in &d.families {
        out.push_str(&tr!(
            "    [{}] 候選 {}，獨有根因 {}（其中 needs_human {}）\n",
            "    [{}] {} candidates, {} unique root causes ({} needs_human)\n",
            y.family,
            y.candidates,
            y.unique_root_causes,
            y.unique_needs_human
        ));
    }
    let m = &d.marginal;
    let per = m
        .calls_per_extra_needs_human
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".to_string());
    out.push_str(&tr!(
        "    邊際產出：加開的 finder 呼叫 {} 次（送出原始碼 {} KiB），多 {} 筆 needs_human，每筆約 {per} 次呼叫\n",
        "    Marginal yield: the added finder made {} calls ({} KiB of source sent) for {} extra needs_human, about {per} calls each\n",
        m.calls,
        m.prompt_bytes.div_ceil(1024),
        m.extra_needs_human
    ));
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

    #[test]
    fn render_summary_groups_finding_evidence_before_a_blank_line_and_result() {
        use crate::lang::{Lang, with};
        let finding = Finding::candidate(
            "cargo-audit",
            FindingKind::DependencyVulnerability,
            Severity::High,
            "t",
            "Cargo.lock",
            None,
            "s",
            "RUSTSEC-2021-0003",
            vec![],
        );
        let id = finding.id.clone();
        let report = base_report(vec![finding]);
        for (lang, header, result) in [
            (Lang::En, "Evidence per finding:", "Result: FAIL"),
            (Lang::ZhTw, "各項發現的證據：", "結論："),
        ] {
            let text = with(lang, || render_summary(&report, Severity::High));
            let block = &text[text.find(header).expect(header)..];
            assert!(
                block.starts_with(&format!("{header}\n  {id}\n    ")),
                "{text}"
            );
            assert!(block.contains(&format!("\n\n{result}")), "{text}");
            assert_eq!(text.matches(&id).count(), 1, "{text}");
            for jargon in [
                "Proof limits",
                "proof_level=",
                "proof_gaps=",
                "legacy transcripts",
            ] {
                assert!(!text.contains(jargon), "{jargon} in:\n{text}");
            }
        }
    }

    // ── saved_report_filename / saved_report_sort_key / save_report ──

    fn at(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn saved_report_filename_is_basic_utc_with_micros_and_suffix() {
        let ts = at("2026-08-18T09:30:00.123456789Z");
        assert_eq!(saved_report_filename(ts, 0), "20260818T093000.123456Z.json");
        assert_eq!(
            saved_report_filename(ts, 3),
            "20260818T093000.123456Z-3.json"
        );
        assert_eq!(
            saved_report_filename(at("2026-08-18T09:30:00Z"), 0),
            "20260818T093000.000000Z.json"
        );
    }

    #[test]
    fn saved_report_sort_key_orders_old_and_new_names_chronologically() {
        let expected = [
            "20261021T061028.999999Z-3.json",
            "20261021T061029Z.json", // older form: start of its second
            "20261021T061029.000001Z.json",
            "20261021T061029.497741Z.json",
            "20261021T061029.497741Z-1.json",
            "20261021T061029.497741Z-2.json",
            "20261021T061029.497741Z-10.json",
            "20261021T061029.5Z.json",
            "20261021T061030Z.json",
            "notes.json", // not a saved name: plain lexical order, as before
        ];
        let mut names = expected.to_vec();
        names.reverse();
        names.sort_by_key(|n| saved_report_sort_key(n));
        assert_eq!(names, expected);
        // Malformed timestamp-like names are not parsed as saved names.
        for bad in [
            "20261021T061029.json",
            "20261021T061029.Z.json",
            "20261021T061029.1234567890Z.json",
            "20261021T061029Z-.json",
            "20261021T061029Z-x.json",
            "20261021X061029Z.json",
        ] {
            assert_eq!(saved_report_sort_key(bad).nanos, 0, "{bad}");
            assert_eq!(saved_report_sort_key(bad).second, bad, "{bad}");
        }
    }

    fn report_started(started_at: &str) -> AuditReport {
        let mut r = base_report(vec![]);
        r.started_at = started_at.to_string();
        r
    }

    fn saved_started_at(path: &Path) -> String {
        let raw = std::fs::read_to_string(path).unwrap();
        serde_json::from_str::<AuditReport>(&raw)
            .unwrap()
            .started_at
    }

    /// Two runs that save in the same instant (the 2026-10-21 report: two
    /// `scan --save` runs in one second left one file) each keep their copy;
    /// a name someone else already holds is left untouched.
    #[test]
    fn save_report_never_overwrites_a_saved_report() {
        let home = tempfile::tempdir().unwrap();
        let now = at("2026-10-21T06:10:29.497741Z");
        let first = save_report_at(home.path(), &report_started("first"), now).unwrap();
        let second = save_report_at(home.path(), &report_started("second"), now).unwrap();
        assert_eq!(first.file_name().unwrap(), "20261021T061029.497741Z.json");
        assert_eq!(
            second.file_name().unwrap(),
            "20261021T061029.497741Z-1.json"
        );
        let dir = home.path().join("reports");
        std::fs::write(dir.join("20261021T061029.497741Z-2.json"), "keep").unwrap();
        let third = save_report_at(home.path(), &report_started("third"), now).unwrap();
        assert_eq!(third.file_name().unwrap(), "20261021T061029.497741Z-3.json");
        assert_eq!(saved_started_at(&first), "first");
        assert_eq!(saved_started_at(&second), "second");
        assert_eq!(saved_started_at(&third), "third");
        assert_eq!(
            std::fs::read_to_string(dir.join("20261021T061029.497741Z-2.json")).unwrap(),
            "keep"
        );
        // No temporary file is left behind.
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 4, "{names:?}");
        assert!(names.iter().all(|n| n.ends_with(".json")), "{names:?}");
    }

    #[test]
    fn save_report_gives_up_when_every_name_is_taken() {
        let home = tempfile::tempdir().unwrap();
        let now = at("2026-10-21T06:10:29.497741Z");
        let dir = home.path().join("reports");
        std::fs::create_dir_all(&dir).unwrap();
        for attempt in 0..SAVE_NAME_ATTEMPTS {
            std::fs::write(dir.join(saved_report_filename(now, attempt)), "x").unwrap();
        }
        let err = save_report_at(home.path(), &report_started("late"), now).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(
            entries.len(),
            SAVE_NAME_ATTEMPTS as usize,
            "temp file removed"
        );
        for attempt in 0..SAVE_NAME_ATTEMPTS {
            let kept = std::fs::read_to_string(dir.join(saved_report_filename(now, attempt)));
            assert_eq!(kept.unwrap(), "x");
        }
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

    // ── deep scan with no AI engine (exit 4) ──────────────────────────

    /// A deep report whose finders are `ran` (engine runs recorded) and
    /// `missing` (listed under engines_missing).
    fn deep_report(ran: &[&str], missing: &[&str], findings: Vec<Finding>) -> AuditReport {
        let mut r = base_report(findings);
        r.profile.mode = ProfileMode::Deep;
        r.engines_run.extend(ran.iter().map(|m| EngineRun {
            engine: format!("ai_audit[{m}]:src"),
            findings_count: 0,
            duration_ms: 5,
            parse_error: None,
            timed_out: false,
        }));
        r.engines_missing
            .extend(missing.iter().map(|m| EngineMissing {
                engine: format!("ai_audit[{m}]"),
                reason: "LLM call failed: container image vettalon-agents:x is missing".into(),
            }));
        if !missing.is_empty() {
            r.run_status = RunStatus::Incomplete;
            r.incomplete_reason =
                Some(vettalon_contract::coverage::IncompleteReason::EngineUnavailable);
        }
        r
    }

    fn high_candidate() -> Finding {
        Finding::candidate(
            "gitleaks",
            FindingKind::Other,
            Severity::High,
            "t",
            "f",
            None,
            "s",
            "r",
            vec![],
        )
    }

    #[test]
    fn deep_scan_with_every_ai_engine_unavailable_exits_4() {
        let report = deep_report(&[], &["codex", "grok"], vec![]);
        assert!(ai_audit_unavailable(&report));
        assert_eq!(scan_exit_code(&report, Some(Severity::High), false), 4);
        // Opt-out: the 0.3.x behaviour.
        assert_eq!(scan_exit_code(&report, Some(Severity::High), true), 0);
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("執行狀態：未完成（沒有任何 AI 引擎能執行"));
        assert!(text.contains(
            "結論：未完成。所有 AI 引擎都無法使用（codex、grok：容器映像檔不存在），AI 審查沒有執行；結果只含已執行的掃描器。結束碼 4。\n"
        ), "{text}");
        assert!(text.contains("`vettalon agents pull`"), "{text}");
        assert!(
            !text.contains("視為通過"),
            "no PASS verdict on exit 4:\n{text}"
        );
        assert!(
            !text.contains("門檻："),
            "the gate passed, so no gate line:\n{text}"
        );
        assert!(!text.contains("本次掃描不完整"), "one note, not two");
    }

    #[test]
    fn exit_4_verdict_names_each_cause_in_both_languages() {
        use crate::lang::{Lang, with};
        let mut report = deep_report(&[], &["codex"], vec![high_candidate()]);
        report.engines_missing.push(EngineMissing {
            engine: "ai_audit[ghost]".into(),
            reason: "LLM call failed: /x/ghost-cli CLI not found on PATH".into(),
        });
        report.summary = Summary::from_findings(&report.findings, 1, 2, GatePolicy::default(), &[]);
        let en = with(Lang::En, || {
            render_scan_summary(&report, Some(Severity::High), false)
        });
        let tail = &en[en.find("Result:").expect("verdict")..];
        assert!(tail.starts_with(
            "Result: INCOMPLETE. No AI engine could run (codex: container image missing; ghost: CLI not found), so the AI audit did not run; the result covers only the scanners that ran. Exit code 4.\n\
             Gate: FAIL, 1 finding(s) at high or above.\n\
             \x20 To fix: make sure Docker is running, then run `vettalon agents pull` or `vettalon agents build` to get the image; install the CLI or fix its `program` path in the config. To exit on the gate result instead, pass --allow-incomplete.\n"
        ), "{tail}");
        assert!(!has_cjk(&en), "Chinese text in English summary:\n{en}");

        let zh = with(Lang::ZhTw, || {
            render_scan_summary(&report, Some(Severity::High), false)
        });
        assert!(
            zh.contains(
                "結論：未完成。所有 AI 引擎都無法使用（codex：容器映像檔不存在；ghost：找不到 CLI）"
            ),
            "{zh}"
        );
        assert!(
            zh.contains("\n門檻：發現 1 項 high 以上等級的問題，未通過。\n"),
            "{zh}"
        );
        assert!(
            zh.contains("要改以門檻結果結束，加 --allow-incomplete。"),
            "{zh}"
        );
    }

    #[test]
    fn allow_incomplete_prints_the_gate_verdict_and_still_says_incomplete() {
        use crate::lang::{Lang, with};
        let clean = deep_report(&[], &["codex"], vec![]);
        let en = with(Lang::En, || {
            render_scan_summary(&clean, Some(Severity::High), true)
        });
        assert!(
            en.contains(
                "Result: PASS, nothing reached the --fail-on threshold (high).\n\
             Note: this scan is INCOMPLETE. No AI engine could run (codex: container image missing)"
            ),
            "{en}"
        );
        assert!(en.contains("the exit code follows the gate"), "{en}");
        assert!(!en.contains("Exit code 4"), "{en}");
        assert!(!has_cjk(&en), "{en}");

        let mut failed = deep_report(&[], &["codex"], vec![high_candidate()]);
        failed.summary = Summary::from_findings(&failed.findings, 1, 2, GatePolicy::default(), &[]);
        let zh = with(Lang::ZhTw, || {
            render_scan_summary(&failed, Some(Severity::High), true)
        });
        assert!(zh.contains(
            "結論：發現 1 項 high 以上等級的問題，未通過。\n注意：本次掃描未完成。所有 AI 引擎都無法使用（codex：容器映像檔不存在）"
        ), "{zh}");
        assert!(
            zh.contains("因為有 --allow-incomplete，結束碼照門檻結果。"),
            "{zh}"
        );
        assert!(
            !zh.contains("門檻："),
            "the gate is the verdict here:\n{zh}"
        );
    }

    #[test]
    fn no_finder_configured_is_also_unavailable() {
        let mut report = deep_report(&[], &[], vec![]);
        report.engines_missing.push(EngineMissing {
            engine: "ai_audit".into(),
            reason: "no finder model configured".into(),
        });
        report.run_status = RunStatus::Incomplete;
        report.incomplete_reason =
            Some(vettalon_contract::coverage::IncompleteReason::EngineUnavailable);
        assert_eq!(scan_exit_code(&report, Some(Severity::High), false), 4);
    }

    #[test]
    fn exit_4_wins_over_a_failed_gate_unless_allowed() {
        let mut report = deep_report(&[], &["codex"], vec![high_candidate()]);
        report.summary = Summary::from_findings(&report.findings, 1, 2, GatePolicy::default(), &[]);
        assert_eq!(exit_code_with(&report, Some(Severity::High)), 1);
        assert_eq!(scan_exit_code(&report, Some(Severity::High), false), 4);
        assert_eq!(scan_exit_code(&report, Some(Severity::High), true), 1);
        let text = render_summary(&report, Severity::High);
        assert!(
            text.contains("門檻：發現 1 項 high 以上等級的問題，未通過。"),
            "the gate result is still shown"
        );
        assert!(text.contains("結論：未完成。"));
    }

    #[test]
    fn partial_ai_engine_loss_keeps_the_old_exit_and_says_so() {
        let report = deep_report(&["claude"], &["codex"], vec![]);
        assert!(!ai_audit_unavailable(&report));
        assert_eq!(scan_exit_code(&report, Some(Severity::High), false), 0);
        let text = render_summary(&report, Severity::High);
        assert!(text.contains("1 個 AI 引擎無法使用，分給它的模組沒有審查"));
        assert!(
            text.contains("結論：未達 --fail-on 門檻（high），視為通過。\n注意：本次掃描不完整")
        );
        assert!(!text.contains("未完成。所有 AI 引擎"), "{text}");
    }

    #[test]
    fn quick_and_complete_deep_scans_are_unaffected() {
        // Quick never runs AI, whatever the report says about engines.
        let mut quick = base_report(vec![]);
        quick.run_status = RunStatus::Incomplete;
        quick.incomplete_reason =
            Some(vettalon_contract::coverage::IncompleteReason::EngineUnavailable);
        assert!(!ai_audit_unavailable(&quick));
        assert_eq!(scan_exit_code(&quick, Some(Severity::High), false), 0);
        let deep = deep_report(&["claude"], &[], vec![]);
        assert_eq!(deep.run_status, RunStatus::Complete);
        assert_eq!(scan_exit_code(&deep, Some(Severity::High), false), 0);
        // Another incomplete reason with no AI run (time budget before the
        // first call) is not "engine unavailable".
        let mut budget = deep_report(&[], &[], vec![]);
        budget.run_status = RunStatus::Incomplete;
        budget.incomplete_reason =
            Some(vettalon_contract::coverage::IncompleteReason::TimeBudgetExhausted);
        assert_eq!(scan_exit_code(&budget, Some(Severity::High), false), 0);
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
