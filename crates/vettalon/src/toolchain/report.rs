//! The `vettalon.toolchain/1` report and its text rendering.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Agent, Kind, Scope};
use crate::audit::schema::Severity;
use crate::lang::pick;
use crate::tr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolchainReport {
    pub schema: String,
    pub vettalon_version: String,
    pub rules_version: String,
    pub generated_at: String,
    pub scope: ReportScope,
    pub online: bool,
    pub items: Vec<ReportItem>,
    pub findings: Vec<ReportFinding>,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportScope {
    pub agents: Vec<Agent>,
    pub scopes: Vec<Scope>,
    pub project: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PinState {
    Match,
    Changed,
    Unpinned,
}

impl PinState {
    pub fn as_str(self) -> &'static str {
        match self {
            PinState::Match => "match",
            PinState::Changed => "changed",
            PinState::Unpinned => "unpinned",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportItem {
    pub id: String,
    pub agent: Agent,
    pub kind: Kind,
    pub scope: Scope,
    pub path: String,
    pub hash: String,
    pub pin: PinState,
    pub files: usize,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
    pub id: String,
    pub rule: String,
    pub severity: Severity,
    pub item: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub message: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub items: usize,
    pub findings_by_severity: BTreeMap<String, usize>,
    pub complete: bool,
    pub incomplete_reasons: Vec<String>,
}

impl ToolchainReport {
    /// `true` when at least one finding is at or above `fail_on`.
    pub fn gate_failed(&self, fail_on: Option<Severity>) -> bool {
        fail_on.is_some_and(|t| self.findings.iter().any(|f| f.severity >= t))
    }

    /// CLI exit code: `1` when the gate failed; otherwise `2` when the audit
    /// is incomplete (an incomplete audit never passes) unless
    /// `allow_incomplete`; else `0`.
    pub fn exit_code(&self, fail_on: Option<Severity>, allow_incomplete: bool) -> i32 {
        if self.gate_failed(fail_on) {
            1
        } else if !self.summary.complete && !allow_incomplete {
            super::EXIT_INCOMPLETE
        } else {
            0
        }
    }
}

pub fn severity_counts(findings: &[ReportFinding]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        *m.entry(f.severity.as_str().to_string()).or_insert(0) += 1;
    }
    m
}

/// Text output grouped by item, highest severity first.
pub fn render_text(
    report: &ToolchainReport,
    fail_on: Option<Severity>,
    allow_incomplete: bool,
) -> String {
    let mut out = String::new();
    out.push_str(&tr!(
        "vettalon toolchain audit（規則 {}）：{} 個項目、{} 個發現\n",
        "vettalon toolchain audit (rules {}): {} items, {} findings\n",
        report.rules_version,
        report.items.len(),
        report.findings.len()
    ));
    out.push_str(&tr!(
        "範圍：{} · {} · 專案 {}{}\n",
        "Scope: {} · {} · project {}{}\n",
        report
            .scope
            .agents
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        report
            .scope
            .scopes
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        report.scope.project,
        if report.online { " · online" } else { "" }
    ));
    let unpinned = report.findings.iter().filter(|f| f.rule == "PN002").count();
    let mut groups: Vec<(&ReportItem, Vec<&ReportFinding>)> = report
        .items
        .iter()
        .map(|it| {
            let mut fs: Vec<&ReportFinding> = report
                .findings
                .iter()
                .filter(|f| f.item == it.id && f.rule != "PN002")
                .collect();
            fs.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule.cmp(&b.rule)));
            (it, fs)
        })
        .filter(|(_, fs)| !fs.is_empty())
        .collect();
    groups.sort_by_key(|g| std::cmp::Reverse(g.1[0].severity));
    for (item, fs) in &groups {
        out.push_str(&format!(
            "\n[{}] {}  ({}, pin: {})\n",
            fs[0].severity.as_str(),
            item.id,
            item.path,
            item.pin.as_str()
        ));
        for f in fs {
            render_finding(&mut out, f);
        }
    }
    let missing: Vec<&ReportFinding> = report
        .findings
        .iter()
        .filter(|f| f.rule == "PN003")
        .collect();
    if !missing.is_empty() {
        out.push_str(pick(
            "\n已釘選但找不到的項目：\n",
            "\nPinned items no longer found:\n",
        ));
        for f in missing {
            render_finding(&mut out, f);
        }
    }
    let clean = report.items.len() - groups.len();
    out.push('\n');
    out.push_str(&tr!(
        "沒有發現的項目：{clean}；未釘選（PN002）：{unpinned}\n",
        "Items without findings: {clean}; unpinned (PN002): {unpinned}\n",
    ));
    render_footer(&mut out, report, fail_on, allow_incomplete);
    out
}

fn render_finding(out: &mut String, f: &ReportFinding) {
    let loc = match (&f.file, f.line) {
        (Some(file), Some(line)) => format!("{file}:{line}"),
        (Some(file), None) => file.clone(),
        _ => String::new(),
    };
    out.push_str(&format!(
        "  - {} {:<8} {loc}  {}\n",
        f.rule,
        f.severity.as_str(),
        f.message
    ));
    if !f.excerpt.is_empty() {
        out.push_str(&format!("      > {}\n", f.excerpt));
    }
}

fn render_footer(
    out: &mut String,
    report: &ToolchainReport,
    fail_on: Option<Severity>,
    allow_incomplete: bool,
) {
    let counts = report
        .summary
        .findings_by_severity
        .iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&tr!(
        "嚴重度：{}\n",
        "By severity: {}\n",
        if counts.is_empty() {
            "-".to_string()
        } else {
            counts
        }
    ));
    if report.summary.complete {
        out.push_str(pick("稽核完整：是\n", "Audit complete: yes\n"));
    } else {
        out.push_str(pick(
            "稽核完整：否（不可視為乾淨）原因：\n",
            "Audit complete: NO (do not read as clean). Reasons:\n",
        ));
        for r in &report.summary.incomplete_reasons {
            out.push_str(&format!("  - {r}\n"));
        }
    }
    let gate = match fail_on {
        None => pick(
            "門檻：無（--fail-on none）\n",
            "Gate: none (--fail-on none)\n",
        )
        .to_string(),
        Some(t) if report.gate_failed(fail_on) => tr!(
            "門檻：失敗（有 {} 以上的發現）\n",
            "Gate: FAILED (findings at or above {})\n",
            t.as_str()
        ),
        Some(t) => tr!(
            "門檻：通過（沒有 {} 以上的發現）\n",
            "Gate: passed (no finding at or above {})\n",
            t.as_str()
        ),
    };
    out.push_str(&gate);
    if !report.summary.complete && !report.gate_failed(fail_on) {
        out.push_str(if allow_incomplete {
            pick(
                "稽核不完整，但已指定 --allow-incomplete：結束碼只依門檻\n",
                "Audit incomplete, but --allow-incomplete was given: exit code follows the gate only\n",
            )
        } else {
            pick(
                "結束碼 2：稽核不完整（確認原因後可加 --allow-incomplete）\n",
                "Exit 2: the audit is incomplete (add --allow-incomplete after reviewing the reasons)\n",
            )
        });
    }
    out.push_str(pick(
        "注意：沒有發現代表「沒有規則命中」，不代表安全。\n",
        "Note: no finding means no rule matched, not that the items are safe.\n",
    ));
}
