//! Draft templates by destination format.
//!
//! - `ghsa`: GitHub advisory fields (ecosystem, package, affected range,
//!   CWE).
//! - `minimal`: short, plain, minimal PoC and tested versions; no heavy
//!   headings, no self-assessment (the style some projects ask for).
//! - `kernel`: plain text, exact commit/version, tested patch section; the
//!   Linux kernel treats AI-assisted findings as public.
//! - `email`: the project security contact (the long-standing default).
//! - TWCERT/CC and HITCON ZeroDay keep their zh-TW forms.
//!
//! Severity is never filled in by the tool unless a human set it, and no
//! template carries a CVSS vector or score (the reporter's number is
//! rarely the maintainer's); the patch section can be switched off for
//! projects that refuse tool-written patches. Every template carries the AI
//! use statement. Drafts are plain markdown-ish text: the only HTML is the
//! GitHub advisory-fields comment of the `ghsa` template.

use crate::audit::evidence_level::ProofGap;
use crate::audit::schema::{EvidenceKind, Finding, Severity};
use crate::kb;

use super::{Channel, DraftContext, DraftFormat, ProjectMeta};

/// The concrete template used for a draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Template {
    Ghsa,
    Minimal,
    Kernel,
    Email,
    Twcert,
    Hitcon,
}

impl Template {
    pub(super) fn resolve(channel: Channel, format: Option<DraftFormat>) -> Template {
        match (format, channel) {
            (Some(DraftFormat::Ghsa), _) => Template::Ghsa,
            (Some(DraftFormat::Minimal), _) => Template::Minimal,
            (Some(DraftFormat::Kernel), _) => Template::Kernel,
            (Some(DraftFormat::Email), _) => Template::Email,
            (None, Channel::GithubAdvisory) => Template::Ghsa,
            (None, Channel::VendorEmail) => Template::Email,
            (None, Channel::Twcert) => Template::Twcert,
            (None, Channel::HitconZeroday) => Template::Hitcon,
        }
    }

    pub(super) fn key(self) -> &'static str {
        match self {
            Template::Ghsa => "ghsa",
            Template::Minimal => "minimal",
            Template::Kernel => "kernel",
            Template::Email => "email",
            Template::Twcert => "twcert_form",
            Template::Hitcon => "hitcon_form",
        }
    }

    pub(super) fn zh(self) -> bool {
        matches!(self, Template::Twcert | Template::Hitcon)
    }
}

pub(super) fn severity_en(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Informational",
    }
}

fn severity_zh(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "嚴重",
        Severity::High => "高",
        Severity::Medium => "中",
        Severity::Low => "低",
        Severity::Info => "資訊",
    }
}

fn location(f: &Finding) -> String {
    match f.line {
        Some(l) if l > 0 => format!("{}:{l}", f.file),
        _ => f.file.clone(),
    }
}

fn analysis(f: &Finding) -> String {
    f.evidence
        .iter()
        .find(|e| matches!(e.kind, EvidenceKind::AiAnalysis | EvidenceKind::StaticHit))
        .map(|e| {
            e.detail
                .strip_prefix("reasoning: ")
                .unwrap_or(&e.detail)
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| f.title.clone())
}

fn steps(f: &Finding, markdown: bool) -> Vec<String> {
    f.trace
        .iter()
        .map(|s| {
            if markdown {
                format!(
                    "`{}:{}` ({}) — {}",
                    s.file,
                    s.line,
                    s.scope,
                    s.description.trim()
                )
            } else {
                format!(
                    "{}:{} ({}): {}",
                    s.file,
                    s.line,
                    s.scope,
                    s.description.trim()
                )
            }
        })
        .collect()
}

fn cwe_line(f: &Finding) -> Option<(String, Option<&'static kb::CweEntry>)> {
    let kind = f.rule_id.strip_prefix("ai-audit/").unwrap_or("");
    let id = f
        .cwe
        .clone()
        .or_else(|| kb::for_kind(kind).map(|e| e.id.clone()))?;
    let entry = kb::lookup(&id);
    Some((id, entry))
}

pub(super) fn finding_cwe(f: &Finding) -> Option<String> {
    cwe_line(f).map(|(id, _)| id)
}

fn poc(f: &Finding) -> Option<String> {
    f.evidence
        .iter()
        .rev()
        .find(|e| e.kind == EvidenceKind::PocTranscript)
        .map(|e| e.detail.trim().to_string())
}

/// Product, version and commit, in the draft language.
pub(super) fn affected(meta: &ProjectMeta, zh: bool) -> String {
    let mut s = meta.name.clone().unwrap_or_else(|| {
        if zh {
            "【產品／專案名稱】".into()
        } else {
            "[product / project name]".into()
        }
    });
    if let Some(v) = &meta.version {
        s.push_str(&format!(" {v}"));
    }
    if let Some(c) = &meta.commit {
        s.push_str(&if zh {
            format!("（commit {c}）")
        } else {
            format!(" (commit {c})")
        });
    }
    s
}

/// The Details-section commit line: the audited commit, or an explicit
/// "commit unknown" so nobody reads a missing line as "latest".
fn commit_line(meta: &ProjectMeta, zh: bool) -> String {
    match (&meta.commit, zh) {
        (Some(c), true) => format!("Commit：{c}"),
        (Some(c), false) => format!("Commit: {c}"),
        (None, true) => "Commit：commit 未知（沒有記錄儲存庫 commit，送出前請補上確切 commit）".into(),
        (None, false) => {
            "Commit: commit unknown (no repository commit was recorded; add the exact commit before sending)"
                .into()
        }
    }
}

/// Longest template text, in Unicode scalar values (not bytes), counted
/// after invisible characters are made visible.
pub(super) const MAX_BODY_CHARS: usize = 8_000;

/// Room left for a closing fence and line breaks around a truncation notice.
const CUT_SLACK: usize = 16;
/// Shortening attempts per section before it is cut to the notice alone.
const CUT_ATTEMPTS: usize = 4;

/// The template sections the cap may shorten. Everything else (headings,
/// location and commit, receipt, impact, fix, disclosure section, AI use
/// statement, reviewer line) is fixed text and is never cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Section {
    PocTranscript,
    Trace,
    Analysis,
}

impl Section {
    /// Tie order when two sections are the same size.
    const ORDER: [Section; 3] = [Section::PocTranscript, Section::Trace, Section::Analysis];

    pub(super) fn name(self, zh: bool) -> &'static str {
        match (self, zh) {
            (Section::PocTranscript, false) => "PoC transcript",
            (Section::Trace, false) => "details trace",
            (Section::Analysis, false) => "analysis text",
            (Section::PocTranscript, true) => "PoC 執行紀錄",
            (Section::Trace, true) => "追蹤步驟",
            (Section::Analysis, true) => "技術描述",
        }
    }
}

/// The line that replaces the cut part of a section.
pub(super) fn truncation_notice(section: Section, zh: bool) -> String {
    if zh {
        format!(
            "[Vettalon 已截斷：{} 已縮短以符合 8,000 字元上限]",
            section.name(true)
        )
    } else {
        format!(
            "[Truncated by Vettalon: {} shortened to fit the 8,000-character limit]",
            section.name(false)
        )
    }
}

/// Character budget per variable section (`None`: not cut).
#[derive(Debug, Clone, Copy, Default)]
struct Budgets {
    poc: Option<usize>,
    trace: Option<usize>,
    analysis: Option<usize>,
}

impl Budgets {
    fn set(&mut self, section: Section, keep: usize) {
        match section {
            Section::PocTranscript => self.poc = Some(keep),
            Section::Trace => self.trace = Some(keep),
            Section::Analysis => self.analysis = Some(keep),
        }
    }
}

/// The code fence still open at the end of `text`, if any (a line starting
/// with 3+ backticks or tildes opens one; a line of at least as many of the
/// same character, and nothing else, closes it).
pub(super) fn open_fence(text: &str) -> Option<String> {
    let mut open: Option<(char, usize)> = None;
    for line in text.lines() {
        // CommonMark: 4+ columns of indentation (a tab counts as 4) is an
        // indented code block, not a fence.
        let indent = line.chars().take_while(|c| *c == ' ').count();
        if indent > 3 {
            continue;
        }
        let l = &line[indent..];
        let Some(c) = l.chars().next().filter(|c| matches!(c, '`' | '~')) else {
            continue;
        };
        let n = l.chars().take_while(|x| *x == c).count();
        if n < 3 {
            continue;
        }
        match open {
            None => open = Some((c, n)),
            // `c` is ASCII: `n` chars are `n` bytes.
            Some((oc, on)) if oc == c && n >= on && l[n..].trim().is_empty() => open = None,
            Some(_) => {}
        }
    }
    open.map(|(c, n)| c.to_string().repeat(n))
}

/// `text` cut to at most `keep` chars: whole lines when a line break falls
/// inside the budget, else a cut on a char boundary; a code fence the cut
/// left open is closed. `None` when `text` already fits.
fn cut_to(text: &str, keep: usize) -> Option<String> {
    let (cut, _) = text.char_indices().nth(keep)?;
    let head = &text[..cut];
    // `cut` starts a new line when the char there is a newline: keep every
    // complete line before it; otherwise drop the partial last line.
    let kept = if text[cut..].starts_with('\n') {
        head
    } else {
        head.rfind('\n').map_or(head, |nl| &head[..nl])
    };
    let mut out = kept.trim_end().to_string();
    if let Some(fence) = open_fence(&out) {
        out.push('\n');
        out.push_str(&fence);
    }
    Some(out)
}

/// `text` within its budget; a cut one ends with the notice on its own line.
fn budgeted(
    text: &str,
    keep: Option<usize>,
    section: Section,
    zh: bool,
    cut: &mut Vec<Section>,
) -> String {
    let Some(kept) = keep.and_then(|k| cut_to(text, k)) else {
        // Fits, but an unbalanced fence must not swallow what follows.
        let mut out = text.to_string();
        if let Some(fence) = open_fence(text) {
            out.push('\n');
            out.push_str(&fence);
        }
        return out;
    };
    cut.push(section);
    let notice = truncation_notice(section, zh);
    if kept.is_empty() {
        notice
    } else {
        format!("{kept}\n{notice}")
    }
}

/// A backtick fence longer than any backtick run in `text`, so the text can
/// never close it early.
pub(crate) fn fence_for(text: &str) -> String {
    let (mut longest, mut run) = (0usize, 0usize);
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat(longest.max(2) + 1)
}

/// The analysis text as the maintainer reads it (invisible characters shown).
fn analysis_text(f: &Finding) -> String {
    super::show_invisible(&analysis(f))
}

/// The PoC transcript as the maintainer reads it.
fn poc_text(f: &Finding) -> Option<String> {
    poc(f).map(|p| super::show_invisible(&p))
}

/// The trace block of a template, uncut.
fn trace_text(t: Template, f: &Finding) -> String {
    let text = match t {
        Template::Minimal => steps(f, false).join(" -> "),
        Template::Kernel => numbered(
            &steps(f, false),
            "[add the conditions that trigger the bug]",
        ),
        Template::Twcert | Template::Hitcon => {
            numbered(&steps(f, true), "【請補上可照做的重現步驟】")
        }
        Template::Ghsa | Template::Email => {
            numbered(&steps(f, true), "[add steps a maintainer can follow]")
        }
    };
    super::show_invisible(&text)
}

/// Uncut length of a section in a template (0: the template has none).
fn section_chars(t: Template, f: &Finding, section: Section) -> usize {
    match section {
        Section::PocTranscript if t == Template::Kernel => 0,
        Section::PocTranscript => poc_text(f).map_or(0, |p| p.chars().count()),
        Section::Trace => trace_text(t, f).chars().count(),
        Section::Analysis => analysis_text(f).chars().count(),
    }
}

/// The variable sections of one template, within `budgets`.
struct Variable {
    analysis: String,
    trace: String,
    /// The PoC block: fenced with its label (`ghsa`, `email`, zh-TW forms),
    /// the bare transcript (`minimal`, `None` without one), empty (`kernel`).
    poc: Option<String>,
    cut: Vec<Section>,
}

impl Variable {
    fn build(t: Template, f: &Finding, b: &Budgets) -> Variable {
        let zh = t.zh();
        let mut cut = Vec::new();
        let analysis = budgeted(
            &analysis_text(f),
            b.analysis,
            Section::Analysis,
            zh,
            &mut cut,
        );
        let trace = budgeted(&trace_text(t, f), b.trace, Section::Trace, zh, &mut cut);
        let poc = match (t, poc_text(f)) {
            (Template::Kernel, _) | (_, None) => None,
            (Template::Minimal, Some(p)) => {
                Some(budgeted(&p, b.poc, Section::PocTranscript, zh, &mut cut))
            }
            (_, Some(p)) => {
                // The notice goes after the closing fence, never inside it.
                let kept = b.poc.and_then(|k| cut_to(&p, k));
                let text = kept.as_deref().unwrap_or(&p);
                let fence = fence_for(text);
                let label = if zh {
                    "沙箱 PoC 執行紀錄（送出前請確認未含敏感資料）："
                } else {
                    "Sandbox PoC transcript (check it holds no sensitive data):"
                };
                let mut s = format!("\n\n{label}\n{fence}\n{text}\n{fence}");
                if kept.is_some() {
                    cut.push(Section::PocTranscript);
                    s.push('\n');
                    s.push_str(&truncation_notice(Section::PocTranscript, zh));
                }
                Some(s)
            }
        };
        Variable {
            analysis,
            trace,
            poc,
            cut,
        }
    }
}

fn numbered(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        return format!("1. {empty}");
    }
    items
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{}. {s}", i + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

fn bullets(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        return format!("- {empty}");
    }
    items
        .iter()
        .map(|s| format!("- {s}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn gap_en(g: ProofGap) -> &'static str {
    match g {
        ProofGap::NoRefuter => "no adversarial review",
        ProofGap::RefuterInconsistent => "repeated reviews disagreed",
        ProofGap::NoPoc => "no PoC executed",
        ProofGap::PocNotHarnessJudged => "PoC effect not judged by a harness",
        ProofGap::NoControl => "no control run",
        ProofGap::NoFreshRerun => "no re-run in a fresh container",
        ProofGap::ReachabilityUnknown => "reachability not shown by execution",
        ProofGap::NoMaintainerConfirmation => "no human confirmation recorded",
    }
}

/// The evidence lines every draft carries: the derived level, what is still
/// missing, and the strongest recorded counter-evidence (if any).
fn evidence_lines(f: &Finding, zh: bool) -> String {
    let level = f.evidence_level();
    let gaps = f.proof_gaps();
    let counter = f
        .strongest_counterevidence()
        .map(|c| super::defang_markers(&c));
    if zh {
        let gaps = if gaps.is_empty() {
            "無".to_string()
        } else {
            gaps.iter()
                .map(|g| g.label_zh())
                .collect::<Vec<_>>()
                .join("、")
        };
        format!(
            "證據等級：{}（{}）\n尚缺證據：{gaps}\n最強反證：{}",
            level.key(),
            level.label_zh(),
            counter.as_deref().unwrap_or("無紀錄")
        )
    } else {
        let gaps = if gaps.is_empty() {
            "none".to_string()
        } else {
            gaps.iter()
                .map(|g| gap_en(*g))
                .collect::<Vec<_>>()
                .join("; ")
        };
        format!(
            "Evidence level: {}\nNot yet shown: {gaps}\nStrongest counter-evidence: {}",
            level.key(),
            counter.as_deref().unwrap_or("none recorded")
        )
    }
}

/// Rendered draft parts.
pub(super) struct Rendered {
    pub subject: String,
    pub body: String,
    pub submit: Option<String>,
    /// Sections shortened to fit [`MAX_BODY_CHARS`] (each carries a notice).
    pub truncated: Vec<Section>,
    /// Still over [`MAX_BODY_CHARS`] with every variable section cut: the
    /// fixed text alone is too long (it is kept whole, never cut).
    pub over_limit: bool,
}

const SEV_DRAFT_EN: &str =
    "DRAFT, human must review (the tool does not fill in severity; see reviewer notes)";
const SEV_DRAFT_ZH: &str = "草擬，待人工覆核（工具不自填嚴重度；模型建議見審閱備註）";

/// Render the template within [`MAX_BODY_CHARS`] (counted after invisible
/// characters are made visible). Only the variable sections (PoC
/// transcript, trace, analysis text) are shortened, largest first, each just
/// far enough and each with a notice; the fixed text, including the AI use
/// statement, the reviewer line and the disclosure section, is always kept
/// whole.
pub(super) fn render(
    t: Template,
    f: &Finding,
    meta: &ProjectMeta,
    disclose_by: &str,
    ctx: &DraftContext<'_>,
) -> Rendered {
    let zh = t.zh();
    let count = |r: &Rendered| super::show_invisible(&r.body).chars().count();
    let mut budgets = Budgets::default();
    let mut r = render_with(t, f, meta, disclose_by, ctx, &budgets);
    // Largest section first (ties: PoC transcript, trace, analysis), so a
    // short section is not cut for a long one's sake.
    let mut order: Vec<(Section, usize)> = Section::ORDER
        .iter()
        .map(|&s| (s, section_chars(t, f, s)))
        .collect();
    order.sort_by_key(|&(_, chars)| std::cmp::Reverse(chars));
    for (section, content) in order {
        let total = count(&r);
        if total <= MAX_BODY_CHARS {
            break;
        }
        if content == 0 {
            continue;
        }
        let overhead = truncation_notice(section, zh).chars().count() + CUT_SLACK;
        let mut keep = content.saturating_sub(total - MAX_BODY_CHARS + overhead);
        for attempt in 0..CUT_ATTEMPTS {
            budgets.set(section, keep);
            r = render_with(t, f, meta, disclose_by, ctx, &budgets);
            let total = count(&r);
            if total <= MAX_BODY_CHARS || keep == 0 {
                break;
            }
            keep = if attempt + 2 == CUT_ATTEMPTS {
                0
            } else {
                keep.saturating_sub(total - MAX_BODY_CHARS)
            };
        }
    }
    r.over_limit = count(&r) > MAX_BODY_CHARS;
    r
}

fn render_with(
    t: Template,
    f: &Finding,
    meta: &ProjectMeta,
    disclose_by: &str,
    ctx: &DraftContext<'_>,
    budgets: &Budgets,
) -> Rendered {
    let var = Variable::build(t, f, budgets);
    let cwe = cwe_line(f);
    let cwe_text = cwe
        .as_ref()
        .map(|(id, e)| match e {
            Some(e) => format!("{id} {}", e.name_en),
            None => id.clone(),
        })
        .unwrap_or_else(|| "(choose a CWE)".into());
    let cwe_zh = cwe
        .as_ref()
        .map(|(id, e)| match e {
            Some(e) => format!("{id} {}", e.name_zh),
            None => id.clone(),
        })
        .unwrap_or_else(|| "【請填寫弱點類型】".into());
    // Mitigation text follows the draft language: zh-TW only for the zh-TW
    // forms; English drafts read the English KB and fall back to the
    // placeholder, never to the zh-TW text.
    let fixes: Vec<String> = cwe
        .as_ref()
        .and_then(|(id, e)| {
            if t.zh() {
                e.map(|e| e.mitigations_zh.clone())
            } else {
                kb::localized(id, "en").map(|l| l.mitigations.clone())
            }
        })
        .unwrap_or_default();
    // Severity: only a human-set value is filled in.
    let human_sev = ctx.severity.human_severity.is_some();
    let sev_en = if human_sev {
        format!("{} (set by the human reviewer)", severity_en(f.severity))
    } else {
        SEV_DRAFT_EN.to_string()
    };
    let sev_zh = if human_sev {
        format!("{}（人工審閱者設定）", severity_zh(f.severity))
    } else {
        SEV_DRAFT_ZH.to_string()
    };
    let impact = match (&f.threat_model, t.zh()) {
        (Some(m), true) => format!("{}（受影響：{}）", m.result.trim(), m.affected.trim()),
        (Some(m), false) => format!("{} (affected: {})", m.result.trim(), m.affected.trim()),
        (None, true) => "【請描述攻擊者可達成的影響】".into(),
        (None, false) => "[describe what an attacker can achieve]".into(),
    };
    let analysis = &var.analysis;
    let steps = &var.trace;
    let affected = affected(meta, t.zh());
    let loc = location(f);
    let receipt_en = ctx
        .receipt
        .map(|r| format!("\n\n{}", r.render_en()))
        .unwrap_or_default();
    let receipt_zh = ctx
        .receipt
        .map(|r| format!("\n\n{}", r.render_zh()))
        .unwrap_or_default();
    // `ghsa` / `email` / zh-TW forms: the fenced block (or nothing).
    let poc_block = var.poc.clone().unwrap_or_default();
    let poc_md = format!("{poc_block}{receipt_en}");
    let poc_zh = format!("{poc_block}{receipt_zh}");
    let commit_en = commit_line(meta, false);
    let commit_zh = commit_line(meta, true);
    let ai_en = ctx.ai_use.render_en();
    let ai_zh = ctx.ai_use.render_zh();
    let scope_en = ctx.dependency.map(|d| d.render_en()).unwrap_or_default();
    let scope_zh = ctx.dependency.map(|d| d.render_zh()).unwrap_or_default();
    let verified_zh = "【已人工重現／尚未重現——請擇一，未重現請勿以「已確認漏洞」通報】";
    let verified_en = "[manually reproduced / not yet reproduced: pick one]";
    let evidence_en = evidence_lines(f, false);
    let evidence_zh = evidence_lines(f, true);
    let patch = ctx.include_patch;

    match t {
        Template::Ghsa => {
            let fix = if patch {
                format!(
                    "\n\n### Suggested fix\n{}\n\nProposed patch: [attach a minimal patch you built and tested, or delete this line]",
                    bullets(&fixes, "(describe the fix)")
                )
            } else {
                String::new()
            };
            let scope = if scope_en.is_empty() {
                String::new()
            } else {
                format!("\n\n### Scope\n{scope_en}")
            };
            let body = format!(
                "<!-- GitHub Security Advisory fields\nTitle: {title}\nEcosystem: {eco}\nPackage name: {pkg}\nAffected versions: {ver}\nPatched versions: (leave empty until a fix ships)\nSeverity: {sev_en}\nCWE: {cwe_text}\n-->\n\n### Summary\n{analysis}\n\n### Details\nLocation: `{loc}`\n{commit_en}\n\n{steps}\n\n### PoC\nVerification status: {verified_en}\n{evidence_en}{poc}\n\n### Impact\n{impact}{scope}{fix}\n\n### Disclosure\nSuggested coordination checkpoint: {disclose_by}. Please discuss the repair and disclosure plan with us. Reaching this date does not authorize publication; any publication requires separate approval after checking repair status, public advisories and coordination agreements.\n\n### AI use statement\n{ai_en}",
                title = f.title,
                eco = meta.ecosystem.as_deref().unwrap_or("(choose)"),
                pkg = meta.name.as_deref().unwrap_or("(package name)"),
                ver = meta
                    .version
                    .as_deref()
                    .map(|v| format!("<= {v}"))
                    .unwrap_or_else(|| "(affected range)".into()),
                poc = poc_md,
            );
            Rendered {
                subject: f.title.clone(),
                body,
                submit: None,
                truncated: var.cut,
                over_limit: false,
            }
        }
        Template::Email => {
            let fix = if patch {
                format!(
                    "\n\nSuggested fix:\n{}\n\nProposed patch: [attach a minimal patch you built and tested, or delete this paragraph]",
                    bullets(&fixes, "(see details)")
                )
            } else {
                String::new()
            };
            let scope = if scope_en.is_empty() {
                String::new()
            } else {
                format!("\n\nScope:\n{scope_en}")
            };
            let body = format!(
                "Hello maintainers,\n\nI'd like to privately report a security issue in {affected}.\n\nSummary: {title}\nSeverity: {sev_en}\nWeakness: {cwe_text}\nLocation: {loc}\n{commit_en}\nVerification status: {verified_en}\n{evidence_en}\n\nDetails:\n{analysis}\n\nSteps to reproduce:\n{steps}\n\nImpact:\n{impact}{scope}{fix}{poc}\n\nI propose {disclose_by} ({days} days) as a coordination checkpoint, subject to agreement. Reaching this date does not authorize publication; any publication requires separate approval after checking repair status, public advisories and coordination agreements. Please let me know if the coordination plan needs adjustment.\n\nAI use statement:\n{ai_en}\n\nThanks,\n{who}",
                title = f.title,
                poc = poc_md,
                days = Channel::VendorEmail.window_days(),
                who = ctx.ai_use.reviewer.pseudonym,
            );
            Rendered {
                subject: format!(
                    "[Security] {} in {}",
                    f.title,
                    meta.name.as_deref().unwrap_or("your project")
                ),
                body,
                submit: None,
                truncated: var.cut,
                over_limit: false,
            }
        }
        Template::Minimal => {
            let path_line = if steps.is_empty() {
                String::new()
            } else {
                format!("\nPath: {steps}")
            };
            let poc_text = var.poc.clone().unwrap_or_else(|| {
                "[paste a minimal, self-contained PoC that uses only the public API]".into()
            });
            let fix = if patch {
                "\n\nMinimal patch (optional): [attach a small diff you tested, or delete this line]"
                    .to_string()
            } else {
                String::new()
            };
            let scope = if scope_en.is_empty() {
                String::new()
            } else {
                format!("\n\n{scope_en}")
            };
            let body = format!(
                "{title}.\n\n{analysis}\n\nLocation: {loc}{path_line}\n{commit_en}\nVersions tested: {affected}; runtime/language version: [fill in]\n\nProof of concept:\n{poc_text}{receipt_en}\n\n{evidence_en}{fix}{scope}\n\nAI use: {ai_en}\n\n{who}",
                title = f.title.trim_end_matches('.'),
                who = ctx.ai_use.reviewer.pseudonym,
            );
            Rendered {
                subject: format!(
                    "Security issue in {}: {}",
                    meta.name.as_deref().unwrap_or("your project"),
                    f.title
                ),
                body,
                submit: None,
                truncated: var.cut,
                over_limit: false,
            }
        }
        Template::Kernel => {
            let exact = match (&meta.commit, &meta.version) {
                (Some(c), _) => format!("commit {c}"),
                (None, Some(v)) => format!("version {v}"),
                (None, None) => {
                    "[exact commit id or version required; \"latest mainline\" is not accepted]"
                        .into()
                }
            };
            let fix = if patch {
                "\n\nTested fix:\n[paste the fix you built and tested, formatted for direct merge with a Fixes: tag naming the commit that introduced the bug; or explain why it could not be tested]".to_string()
            } else {
                String::new()
            };
            let scope = if scope_en.is_empty() {
                String::new()
            } else {
                format!("\n\n{scope_en}")
            };
            let body = format!(
                "Affected: {exact}\nLocation: {loc}\n{commit_en}\n\nDescription:\n{analysis}\n\nTriggering conditions:\n{steps}\n\nReproducer: available to the maintainers on request (not posted publicly).{receipt_en}\n\n{evidence_en}{fix}{scope}\n\nAI use statement:\n{ai_en}\n\n{who}",
                who = ctx.ai_use.reviewer.pseudonym,
            );
            Rendered {
                subject: format!("{} ({})", f.title, f.file),
                body,
                submit: None,
                truncated: var.cut,
                over_limit: false,
            }
        }
        Template::Twcert => {
            let fix = if patch {
                format!(
                    "\n九、建議修補方式：\n{}",
                    bullets(&fixes, "【請描述修補方式】")
                )
            } else {
                "\n九、建議修補方式：（依專案政策不附修補）".to_string()
            };
            let scope = if scope_zh.is_empty() {
                String::new()
            } else {
                format!("\n範圍說明：\n{scope_zh}")
            };
            let body = format!(
                "TWCERT/CC 您好：\n\n以下通報 {affected} 之安全弱點，請協助確認並與原廠協調處理。\n\n一、漏洞概述：{title}\n二、受影響產品與版本：{affected}；問題位置：{loc}；{commit_zh}\n三、弱點類型：{cwe_zh}\n四、風險評估：{sev_zh}\n五、驗證狀態：{verified_zh}\n{evidence_zh}\n六、漏洞技術描述：\n{analysis}\n七、重現方法：\n{steps}\n八、潛在影響：{impact}{scope}{fix}{poc}\n十、揭露意願與協調：尚待人工核准；建議於 {disclose_by} 協調進度，日期不代表公開授權。修補、公告、公開範圍與時程須另行核對、協商及核准；署名方式：【具名稱呼／匿名】\n十一、通報者聯絡資訊：【姓名／Email／電話】；是否同意提供聯絡方式予原廠：【是／否】\n十二、AI 使用聲明：\n{ai_zh}\n\n（送出前請核對現行受理政策、聯絡管道及加密方式。）",
                title = f.title,
                poc = poc_zh,
            );
            Rendered {
                subject: format!("[漏洞通報] {affected}：{}", f.title),
                body,
                submit: Some("mailto:cve@cert.org.tw".into()),
                truncated: var.cut,
                over_limit: false,
            }
        }
        Template::Hitcon => {
            let fix = if patch {
                format!("\n\n處理建議：\n{}", bullets(&fixes, "【請描述修補方式】"))
            } else {
                String::new()
            };
            let scope = if scope_zh.is_empty() {
                String::new()
            } else {
                format!("\n\n範圍說明：\n{scope_zh}")
            };
            let body = format!(
                "標題：{title}\n風險等級：{sev_zh}\n類型：{cwe_zh}\n受影響網站／服務：【網址】\n問題位置：{loc}\n{commit_zh}\n\n敘述：\n{analysis}\n\n驗證狀態：{verified_zh}\n{evidence_zh}\n\n重現步驟：\n{steps}{scope}{fix}{poc}\n\nAI 使用聲明：\n{ai_zh}\n\n（送出前請核對 HITCON ZeroDay 的受理範圍、現行政策與公開設定。建議於 {disclose_by} 協調進度，日期不代表公開授權；未取得本次公開核准前，不同意公開任何內容。）",
                title = f.title,
                poc = poc_zh,
            );
            Rendered {
                subject: f.title.clone(),
                body,
                submit: Some("https://zeroday.hitcon.org/".into()),
                truncated: var.cut,
                over_limit: false,
            }
        }
    }
}
