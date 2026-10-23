//! The closing verdict of the `scan` terminal summary.
//!
//! Terminal text only: the JSON report, SARIF and CycloneDX never carry it.
//! A deep scan whose AI audit could not run at all
//! ([`ai_audit_unavailable`]) exits [`AI_UNAVAILABLE_EXIT`] unless
//! `--allow-incomplete`, so its verdict line says "incomplete" with the
//! reason instead of a gate PASS/FAIL the exit code does not follow; a
//! failed gate is still shown on its own line. With `--allow-incomplete`
//! the gate verdict is printed as before, followed by an explicit
//! "incomplete" note, because only the exit code changes.

use vettalon_contract::coverage::RunStatus;

use crate::audit::report::{AI_AUDIT_ENGINE, AI_UNAVAILABLE_EXIT, ai_audit_unavailable};
use crate::audit::schema::{AuditReport, Severity};
use crate::lang::pick;
use crate::tr;

/// Prefix `ai_audit` puts in front of a finder's call error.
const LLM_FAILED_PREFIX: &str = "LLM call failed: ";
/// Distinct causes named in the verdict before the rest are counted.
const MAX_CAUSE_GROUPS: usize = 3;
/// Byte cap on an unrecognised reason quoted in the verdict.
const MAX_OTHER_REASON_BYTES: usize = 80;

/// Appends the verdict lines (the last lines of the summary).
pub(super) fn render_verdict(
    report: &AuditReport,
    fail_on: Option<Severity>,
    allow_incomplete: bool,
    out: &mut String,
) {
    let gate = gate_outcome(report, fail_on);
    if !ai_audit_unavailable(report) {
        out.push_str(&tr!("結論：{}\n", "Result: {}\n", gate.text));
        if !gate.failed && report.run_status == RunStatus::Incomplete {
            out.push_str(pick(
                "注意：本次掃描不完整，通過只代表「已審查的部分」沒有達到門檻，不代表沒有問題。\n",
                "Note: this scan is incomplete. A pass only means the reviewed part stayed under the threshold, not that there are no problems.\n",
            ));
        }
        return;
    }
    let causes = UnavailableCauses::from_report(report);
    if allow_incomplete {
        out.push_str(&tr!("結論：{}\n", "Result: {}\n", gate.text));
        out.push_str(&tr!(
            "注意：本次掃描未完成。所有 AI 引擎都無法使用（{}），AI 審查沒有執行；結果只含已執行的掃描器。因為有 --allow-incomplete，結束碼照門檻結果。\n",
            "Note: this scan is INCOMPLETE. No AI engine could run ({}), so the AI audit did not run; the result covers only the scanners that ran. --allow-incomplete is set, so the exit code follows the gate.\n",
            causes.summary()
        ));
        out.push_str(&tr!("  建議：{}。\n", "  To fix: {}.\n", causes.hints()));
        return;
    }
    out.push_str(&tr!(
        "結論：未完成。所有 AI 引擎都無法使用（{}），AI 審查沒有執行；結果只含已執行的掃描器。結束碼 {}。\n",
        "Result: INCOMPLETE. No AI engine could run ({}), so the AI audit did not run; the result covers only the scanners that ran. Exit code {}.\n",
        causes.summary(),
        AI_UNAVAILABLE_EXIT
    ));
    if gate.failed {
        out.push_str(&tr!("門檻：{}\n", "Gate: {}\n", gate.text));
    }
    out.push_str(&tr!(
        "  建議：{}；要改以門檻結果結束，加 --allow-incomplete。\n",
        "  To fix: {}. To exit on the gate result instead, pass --allow-incomplete.\n",
        causes.hints()
    ));
}

/// The gate result in words, without the `Result:` / `Gate:` label.
struct GateOutcome {
    failed: bool,
    text: String,
}

fn gate_outcome(report: &AuditReport, fail_on: Option<Severity>) -> GateOutcome {
    let policy_failed = crate::audit::gate::any_failed(&report.summary.policy);
    let severity_hits = fail_on.map(|s| (s, report.summary.gate_counts().count_at_or_above(s)));
    let text = match severity_hits {
        Some((s, n)) if n > 0 => tr!(
            "發現 {n} 項 {} 以上等級的問題，未通過。",
            "FAIL, {n} finding(s) at {} or above.",
            s.as_str()
        ),
        _ if policy_failed => pick(
            "政策門檻有條件未通過，未通過。",
            "FAIL, a policy gate condition failed.",
        )
        .to_string(),
        Some((s, _)) => tr!(
            "未達 --fail-on 門檻（{}），視為通過。",
            "PASS, nothing reached the --fail-on threshold ({}).",
            s.as_str()
        ),
        None if report.summary.policy.is_empty() => pick(
            "未設定 --fail-on 或 --gate 門檻，僅供參考。",
            "no --fail-on or --gate threshold set; for information only.",
        )
        .to_string(),
        None => pick(
            "政策門檻全部通過。",
            "PASS, every policy gate condition passed.",
        )
        .to_string(),
    };
    GateOutcome {
        failed: policy_failed || severity_hits.is_some_and(|(_, n)| n > 0),
        text,
    }
}

/// Why one AI finder could not run, from its `engines_missing` reason.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cause {
    ImageMissing,
    DockerUnavailable,
    CliNotFound,
    ApiKeyUnset,
    ProviderFailed,
    NoFinder,
    Other(String),
}

impl Cause {
    fn classify(reason: &str) -> Self {
        let r = reason.strip_prefix(LLM_FAILED_PREFIX).unwrap_or(reason);
        if r.contains("container image ") && r.contains(" is missing") {
            Self::ImageMissing
        } else if r.contains("docker CLI not found")
            || r.starts_with("cannot run docker")
            || r.starts_with("cannot start docker")
        {
            Self::DockerUnavailable
        } else if r.contains("CLI not found on PATH") {
            Self::CliNotFound
        } else if r.starts_with("environment variable ") && r.ends_with(" is not set") {
            Self::ApiKeyUnset
        } else if r.starts_with("request failed:")
            || r.starts_with("HTTP ")
            || r.starts_with("cannot read response:")
        {
            Self::ProviderFailed
        } else if r.starts_with("no finder model configured") {
            Self::NoFinder
        } else {
            Self::Other(crate::util::truncate_bytes(r.trim(), MAX_OTHER_REASON_BYTES).to_string())
        }
    }

    fn label(&self) -> String {
        match self {
            // `image_present` also says "missing" when the Docker daemon is
            // down, so the hint covers both.
            Self::ImageMissing => pick("容器映像檔不存在", "container image missing").into(),
            Self::DockerUnavailable => pick("無法執行 docker", "docker not available").into(),
            Self::CliNotFound => pick("找不到 CLI", "CLI not found").into(),
            Self::ApiKeyUnset => pick(
                "API 金鑰環境變數未設定",
                "API key environment variable not set",
            )
            .into(),
            Self::ProviderFailed => pick(
                "連不上供應商或請求失敗",
                "provider unreachable or request failed",
            )
            .into(),
            Self::NoFinder => pick("沒有設定 finder 模型", "no finder model configured").into(),
            Self::Other(r) => r.clone(),
        }
    }

    fn hint(&self) -> &'static str {
        match self {
            Self::ImageMissing => pick(
                "確認 Docker 有在執行，再用 `vettalon agents pull` 或 `vettalon agents build` 取得映像檔",
                "make sure Docker is running, then run `vettalon agents pull` or `vettalon agents build` to get the image",
            ),
            Self::DockerUnavailable => pick("安裝或啟動 Docker", "install or start Docker"),
            Self::CliNotFound => pick(
                "安裝該 CLI，或修正設定檔裡的 program 路徑",
                "install the CLI or fix its `program` path in the config",
            ),
            Self::ApiKeyUnset => pick(
                "設定設定檔指定的 API 金鑰環境變數",
                "set the API key environment variable the config names",
            ),
            Self::ProviderFailed => pick(
                "確認網路連線、endpoint 與 API 金鑰",
                "check the network, the endpoint and the API key",
            ),
            Self::NoFinder => pick(
                "在 vettalon.toml 設定 finder 模型，或把 claude、codex、grok 其中之一放進 PATH",
                "configure a finder in vettalon.toml, or put claude, codex or grok on PATH",
            ),
            Self::Other(_) => pick(
                "看上方 [略過] ai_audit 列的完整原因",
                "see the [skipped] ai_audit lines above for the full reason",
            ),
        }
    }
}

/// The AI finders that could not run, grouped by cause in report order.
struct UnavailableCauses {
    /// `(cause, finder ids)`; ids are empty for the bare `ai_audit` entry.
    groups: Vec<(Cause, Vec<String>)>,
}

impl UnavailableCauses {
    fn from_report(report: &AuditReport) -> Self {
        let mut groups: Vec<(Cause, Vec<String>)> = Vec::new();
        for missing in report
            .engines_missing
            .iter()
            .filter(|m| m.engine.starts_with(AI_AUDIT_ENGINE))
        {
            let cause = Cause::classify(&missing.reason);
            let model = missing
                .engine
                .strip_prefix(AI_AUDIT_ENGINE)
                .and_then(|rest| rest.strip_prefix('['))
                .and_then(|rest| rest.strip_suffix(']'))
                .map(str::to_string);
            match groups.iter_mut().find(|(c, _)| *c == cause) {
                Some((_, models)) => models.extend(model),
                None => groups.push((cause, model.into_iter().collect())),
            }
        }
        Self { groups }
    }

    /// One line: `codex：容器映像檔不存在；ghost：找不到 CLI`.
    fn summary(&self) -> String {
        if self.groups.is_empty() {
            return pick("原因未記錄", "reason not recorded").to_string();
        }
        let mut parts: Vec<String> = self
            .groups
            .iter()
            .take(MAX_CAUSE_GROUPS)
            .map(|(cause, models)| {
                if models.is_empty() {
                    cause.label()
                } else {
                    tr!(
                        "{}：{}",
                        "{}: {}",
                        models.join(pick("、", ", ")),
                        cause.label()
                    )
                }
            })
            .collect();
        let rest = self.groups.len().saturating_sub(MAX_CAUSE_GROUPS);
        if rest > 0 {
            parts.push(tr!("另有 {rest} 種原因", "{rest} more cause(s)"));
        }
        parts.join(pick("；", "; "))
    }

    /// The fix for each distinct cause, in the same order as the summary.
    fn hints(&self) -> String {
        let mut hints: Vec<&str> = Vec::new();
        for (cause, _) in &self.groups {
            let hint = cause.hint();
            if !hints.contains(&hint) {
                hints.push(hint);
            }
        }
        if hints.is_empty() {
            hints.push(Cause::Other(String::new()).hint());
        }
        hints.join(pick("；", "; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_preflight_failures_the_finders_report() {
        for (reason, cause) in [
            (
                "LLM call failed: container image vettalon-agents:abc is missing; run `vettalon agents pull` (or `agents build`); needs Docker and network access",
                Cause::ImageMissing,
            ),
            (
                "LLM call failed: docker CLI not found on PATH",
                Cause::DockerUnavailable,
            ),
            (
                "LLM call failed: /x/ghost-cli CLI not found on PATH",
                Cause::CliNotFound,
            ),
            (
                "LLM call failed: environment variable OPENAI_API_KEY is not set",
                Cause::ApiKeyUnset,
            ),
            (
                "LLM call failed: request failed: error sending request",
                Cause::ProviderFailed,
            ),
            (
                "LLM call failed: HTTP 401 Unauthorized: bad key",
                Cause::ProviderFailed,
            ),
            (
                "no finder model configured (vettalon.toml, or claude/codex/grok on PATH)",
                Cause::NoFinder,
            ),
        ] {
            assert_eq!(Cause::classify(reason), cause, "{reason}");
        }
        let long = format!("LLM call failed: {}", "x".repeat(300));
        match Cause::classify(&long) {
            Cause::Other(r) => assert_eq!(r.len(), MAX_OTHER_REASON_BYTES),
            other => panic!("{other:?}"),
        }
    }
}
