//! Draft templates by destination format.
//!
//! - `ghsa`: GitHub advisory fields (ecosystem, package, affected range,
//!   CWE, CVSS vector left for the human).
//! - `minimal`: short, plain, minimal PoC and tested versions; no CVSS, no
//!   heavy headings, no self-assessment (the style some projects ask for).
//! - `kernel`: plain text, exact commit/version, tested patch section; the
//!   Linux kernel treats AI-assisted findings as public.
//! - `email`: the project security contact (the long-standing default).
//! - TWCERT/CC and HITCON ZeroDay keep their zh-TW forms.
//!
//! Severity is never filled in by the tool unless a human set it; the
//! patch section can be switched off for projects that refuse tool-written
//! patches. Every template carries the AI use statement.

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

fn poc(f: &Finding) -> Option<String> {
    f.evidence
        .iter()
        .rev()
        .find(|e| e.kind == EvidenceKind::PocTranscript)
        .map(|e| e.detail.trim().to_string())
}

pub(super) fn affected(meta: &ProjectMeta) -> String {
    let mut s = meta
        .name
        .clone()
        .unwrap_or_else(|| "【產品／專案名稱】".into());
    if let Some(v) = &meta.version {
        s.push_str(&format!(" {v}"));
    }
    if let Some(c) = &meta.commit {
        s.push_str(&format!("（commit {c}）"));
    }
    s
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
}

const SEV_DRAFT_EN: &str =
    "DRAFT, human must review (the tool does not fill in severity; see reviewer notes)";
const SEV_DRAFT_ZH: &str = "草擬，待人工覆核（工具不自填嚴重度；模型建議見審閱備註）";

pub(super) fn render(
    t: Template,
    f: &Finding,
    meta: &ProjectMeta,
    disclose_by: &str,
    ctx: &DraftContext<'_>,
) -> Rendered {
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
    let fixes: Vec<String> = cwe
        .as_ref()
        .and_then(|(_, e)| e.map(|e| e.mitigations_zh.clone()))
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
    let cvss_en = match (&f.cvss, human_sev) {
        (Some(c), true) => format!("CVSS {} {}", c.cvss_version, c.cvss_vector),
        _ => "DRAFT, human must review: compute the vector with the FIRST calculator".into(),
    };
    let impact = f
        .threat_model
        .as_ref()
        .map(|t| format!("{}（受影響：{}）", t.result.trim(), t.affected.trim()))
        .unwrap_or_else(|| "【請描述攻擊者可達成的影響】".into());
    let analysis = analysis(f);
    let affected = affected(meta);
    let loc = location(f);
    let poc_md = poc(f).map(|p| {
        format!("\n\nSandbox PoC transcript (check it holds no sensitive data):\n```\n{p}\n```")
    });
    let poc_zh = poc(f)
        .map(|p| format!("\n\n沙箱 PoC 執行紀錄（送出前請確認未含敏感資料）：\n```\n{p}\n```"));
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
                "<!-- GitHub Security Advisory fields\nTitle: {title}\nEcosystem: {eco}\nPackage name: {pkg}\nAffected versions: {ver}\nPatched versions: (leave empty until a fix ships)\nSeverity: {sev_en}\nCVSS vector: {cvss_en}\nCWE: {cwe_text}\n-->\n\n### Summary\n{analysis}\n\n### Details\nLocation: `{loc}`\n\n{steps}\n\n### PoC\nVerification status: {verified_en}\n{evidence_en}{poc}\n\n### Impact\n{impact}{scope}{fix}\n\n### Disclosure\nSuggested coordination checkpoint: {disclose_by}. Please discuss the repair and disclosure plan with us. Reaching this date does not authorize publication; any publication requires separate approval after checking repair status, public advisories and coordination agreements.\n\n### AI use statement\n{ai_en}",
                title = f.title,
                eco = meta.ecosystem.as_deref().unwrap_or("(choose)"),
                pkg = meta.name.as_deref().unwrap_or("(package name)"),
                ver = meta
                    .version
                    .as_deref()
                    .map(|v| format!("<= {v}"))
                    .unwrap_or_else(|| "(affected range)".into()),
                steps = numbered(&steps(f, true), "[add steps a maintainer can follow]"),
                poc = poc_md.clone().unwrap_or_default(),
            );
            Rendered {
                subject: f.title.clone(),
                body,
                submit: None,
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
                "Hello maintainers,\n\nI'd like to privately report a security issue in {affected}.\n\nSummary: {title}\nSeverity: {sev_en}\nWeakness: {cwe_text}\nLocation: {loc}\nVerification status: {verified_en}\n{evidence_en}\n\nDetails:\n{analysis}\n\nSteps to reproduce:\n{steps}\n\nImpact:\n{impact}{scope}{fix}{poc}\n\nI propose {disclose_by} ({days} days) as a coordination checkpoint, subject to agreement. Reaching this date does not authorize publication; any publication requires separate approval after checking repair status, public advisories and coordination agreements. Please let me know if the coordination plan needs adjustment.\n\nAI use statement:\n{ai_en}\n\nThanks,\n{who}",
                title = f.title,
                steps = numbered(&steps(f, true), "[add steps a maintainer can follow]"),
                poc = poc_md.clone().unwrap_or_default(),
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
            }
        }
        Template::Minimal => {
            let path = steps(f, false);
            let path_line = if path.is_empty() {
                String::new()
            } else {
                format!("\nPath: {}", path.join(" -> "))
            };
            let poc_text = poc(f).unwrap_or_else(|| {
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
                "{title}.\n\n{analysis}\n\nLocation: {loc}{path_line}\nVersions tested: {affected}; runtime/language version: [fill in]\n\nProof of concept:\n{poc_text}\n\n{evidence_en}{fix}{scope}\n\nAI use: {ai_en}\n\n{who}",
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
                "Affected: {exact}\nLocation: {loc}\n\nDescription:\n{analysis}\n\nTriggering conditions:\n{steps}\n\nReproducer: available to the maintainers on request (not posted publicly).\n\n{evidence_en}{fix}{scope}\n\nAI use statement:\n{ai_en}\n\n{who}",
                steps = numbered(
                    &steps(f, false),
                    "[add the conditions that trigger the bug]"
                ),
                who = ctx.ai_use.reviewer.pseudonym,
            );
            Rendered {
                subject: format!("{} ({})", f.title, f.file),
                body,
                submit: None,
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
                "TWCERT/CC 您好：\n\n以下通報 {affected} 之安全弱點，請協助確認並與原廠協調處理。\n\n一、漏洞概述：{title}\n二、受影響產品與版本：{affected}；問題位置：{loc}\n三、弱點類型：{cwe_zh}\n四、風險評估：{sev_zh}\n五、驗證狀態：{verified_zh}\n{evidence_zh}\n六、漏洞技術描述：\n{analysis}\n七、重現方法：\n{steps}\n八、潛在影響：{impact}{scope}{fix}{poc}\n十、揭露意願與協調：尚待人工核准；建議於 {disclose_by} 協調進度，日期不代表公開授權。修補、公告、公開範圍與時程須另行核對、協商及核准；署名方式：【具名稱呼／匿名】\n十一、通報者聯絡資訊：【姓名／Email／電話】；是否同意提供聯絡方式予原廠：【是／否】\n十二、AI 使用聲明：\n{ai_zh}\n\n（送出前請核對現行受理政策、聯絡管道及加密方式。）",
                title = f.title,
                steps = numbered(&steps(f, true), "【請補上可照做的重現步驟】"),
                poc = poc_zh.clone().unwrap_or_default(),
            );
            Rendered {
                subject: format!("[漏洞通報] {affected}：{}", f.title),
                body,
                submit: Some("mailto:cve@cert.org.tw".into()),
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
                "標題：{title}\n風險等級：{sev_zh}\n類型：{cwe_zh}\n受影響網站／服務：【網址】\n\n敘述：\n{analysis}\n\n驗證狀態：{verified_zh}\n{evidence_zh}\n\n重現步驟：\n{steps}{scope}{fix}{poc}\n\nAI 使用聲明：\n{ai_zh}\n\n（送出前請核對 HITCON ZeroDay 的受理範圍、現行政策與公開設定。建議於 {disclose_by} 協調進度，日期不代表公開授權；未取得本次公開核准前，不同意公開任何內容。）",
                title = f.title,
                steps = numbered(&steps(f, true), "【請補上可照做的重現步驟】"),
                poc = poc_zh.unwrap_or_default(),
            );
            Rendered {
                subject: f.title.clone(),
                body,
                submit: Some("https://zeroday.hitcon.org/".into()),
            }
        }
    }
}
