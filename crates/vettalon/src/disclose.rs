//! Developer disclosure assistant: pick a reporting channel for a finding and
//! draft the report in that channel's expected format.
//!
//! Hard line: this module only WRITES DRAFTS. It never sends, posts or
//! contacts anyone — submitting, talking to the vendor and deciding the
//! disclosure date are the human's job (coordinated vulnerability disclosure
//! ethics, and the reporter's legal safety). Channel detection is local:
//! the repo's git remote, SECURITY.md and package manifest — no network.
//!
//! Only findings a review left standing (`needs_human`, `confirmed`) can be
//! drafted; an unreviewed candidate or a refuted one is refused, so the tool
//! never helps file a report it has no grounds for.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit::schema::{AuditReport, EvidenceKind, Finding, FindingStatus, Severity};
use crate::kb;

/// Where a report can be filed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// GitHub private vulnerability reporting / repository security advisory.
    GithubAdvisory,
    /// The project's own security contact (SECURITY.md / manifest).
    VendorEmail,
    /// TWCERT/CC — product vulnerabilities, CVE assignment (CNA), 90 days.
    Twcert,
    /// HITCON ZeroDay — websites / online services, 60 days.
    HitconZeroday,
}

impl std::str::FromStr for Channel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "ghsa" | "github" | "github_advisory" => Ok(Channel::GithubAdvisory),
            "email" | "vendor" | "vendor_email" => Ok(Channel::VendorEmail),
            "twcert" => Ok(Channel::Twcert),
            "hitcon" | "zeroday" | "hitcon_zeroday" => Ok(Channel::HitconZeroday),
            other => Err(format!(
                "unknown channel {other:?} (ghsa | email | twcert | hitcon)"
            )),
        }
    }
}

impl Channel {
    /// Standard public-disclosure window, in days.
    pub fn window_days(self) -> i64 {
        match self {
            Channel::HitconZeroday => 60,
            _ => 90,
        }
    }
}

/// What the repo itself says about the project (all local reads).
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProjectMeta {
    pub name: Option<String>,
    pub version: Option<String>,
    /// GitHub advisory ecosystem: Rust | npm | pip | Go.
    pub ecosystem: Option<String>,
    /// `owner/repo` when the origin remote is on github.com.
    pub github: Option<String>,
    pub commit: Option<String>,
    pub security_policy: Option<String>,
    pub security_emails: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelOption {
    pub channel: Channel,
    pub label: String,
    pub reason: String,
    /// Where to submit (URL or `mailto:`), when known.
    pub submit: Option<String>,
    pub window_days: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Draft {
    pub channel: Channel,
    pub subject: String,
    pub body: String,
    pub submit: Option<String>,
    /// Suggested public-disclosure date (today + the channel's window).
    pub disclose_by: String,
}

/// Everything the UI needs for one finding.
#[derive(Debug, Clone, Serialize)]
pub struct DisclosurePackage {
    pub finding_id: String,
    pub finding_title: String,
    pub project: ProjectMeta,
    pub channels: Vec<ChannelOption>,
    pub draft: Draft,
    /// Must all be done by the human before anything is sent.
    pub checklist: Vec<String>,
}

pub const CHECKLIST: &[&str] = &[
    "已人工重現此問題，並確認可利用性與影響範圍（自動分析結果不能直接當成已證實的漏洞）",
    "測試全程在授權範圍內進行，未對他人的正式環境做未經授權的存取",
    "草稿中沒有真實帳密、金鑰、個資或客戶資料",
    "已確認通報對象正確（產品漏洞找原廠或 TWCERT/CC，網站服務找 HITCON ZeroDay）",
    "已決定署名方式（具名或匿名）與公開時程，並準備好與對方溝通",
];

// ── eligibility ──────────────────────────────────────────────────────────

/// A draft is only offered for a finding a review left standing.
pub fn eligible(f: &Finding) -> Result<(), String> {
    match f.status {
        FindingStatus::NeedsHuman | FindingStatus::Confirmed => Ok(()),
        FindingStatus::Candidate => Err(
            "此項目尚未經跨家族覆核或人工確認，不提供提交草稿。請先以 deep 模式重新檢測，或人工確認後再通報。".into(),
        ),
        FindingStatus::Refuted => Err("此項目經覆核判定為誤判，不提供提交草稿。".into()),
        FindingStatus::Suppressed => Err("此項目已被排除，不提供提交草稿。".into()),
    }
}

// ── local project detection ──────────────────────────────────────────────

const META_MAX_BYTES: u64 = 256 * 1024;

/// Read a small regular file inside the repo (no symlinks, size-capped).
fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > META_MAX_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// `owner/repo` from a GitHub remote URL (https or scp-style ssh).
pub fn github_slug(url: &str) -> Option<String> {
    let u = url.trim();
    let rest = u
        .strip_prefix("https://github.com/")
        .or_else(|| u.strip_prefix("http://github.com/"))
        .or_else(|| u.strip_prefix("ssh://git@github.com/"))
        .or_else(|| u.strip_prefix("git@github.com:"))?;
    let rest = rest.trim_end_matches('/').trim_end_matches(".git");
    let mut parts = rest.split('/');
    let (owner, repo) = (parts.next()?, parts.next()?);
    let ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    };
    (ok(owner) && ok(repo) && parts.next().is_none()).then(|| format!("{owner}/{repo}"))
}

fn origin_url(git_config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in git_config.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_origin = l == r#"[remote "origin"]"#;
        } else if in_origin && let Some(v) = l.strip_prefix("url") {
            return Some(v.trim_start().trim_start_matches('=').trim().to_string());
        }
    }
    None
}

fn head_commit(git_dir: &Path) -> Option<String> {
    let head = read_small(&git_dir.join("HEAD"))?;
    let head = head.trim();
    let sha = match head.strip_prefix("ref: ") {
        Some(r) if !r.contains("..") => read_small(&git_dir.join(r))
            .map(|s| s.trim().to_string())
            .or_else(|| {
                // Packed refs: `<sha> <ref>` lines.
                read_small(&git_dir.join("packed-refs"))?
                    .lines()
                    .find_map(|l| l.strip_suffix(r).map(|s| s.trim().to_string()))
            })?,
        Some(_) => return None,
        None => head.to_string(),
    };
    (sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| sha[..12.min(sha.len())].to_string())
}

fn emails_in(text: &str) -> Vec<String> {
    let re =
        regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").expect("static regex");
    let mut out: Vec<String> = Vec::new();
    for m in re.find_iter(text) {
        let e = m.as_str().trim_end_matches('.').to_ascii_lowercase();
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out.truncate(5);
    out
}

fn toml_field(text: &str, section: &str, key: &str) -> Option<String> {
    let v: toml::Value = toml::from_str(text).ok()?;
    let mut cur = &v;
    for part in section.split('.') {
        cur = cur.get(part)?;
    }
    cur.get(key)?.as_str().map(str::to_string)
}

/// Everything the repo says about where to report (local reads only).
pub fn detect_project(repo: &Path) -> ProjectMeta {
    let mut m = ProjectMeta::default();
    if !repo.is_dir() {
        return m;
    }
    let git = repo.join(".git");
    if let Some(cfg) = read_small(&git.join("config")) {
        m.github = origin_url(&cfg).as_deref().and_then(github_slug);
    }
    m.commit = head_commit(&git);
    for rel in [
        "SECURITY.md",
        ".github/SECURITY.md",
        "docs/SECURITY.md",
        "security.md",
    ] {
        if let Some(t) = read_small(&repo.join(rel)) {
            m.security_policy = Some(rel.to_string());
            m.security_emails = emails_in(&t);
            break;
        }
    }
    if let Some(t) = read_small(&repo.join("Cargo.toml")) {
        m.name = toml_field(&t, "package", "name");
        m.version = toml_field(&t, "package", "version");
        m.ecosystem = Some("Rust".into());
    } else if let Some(t) = read_small(&repo.join("package.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
            m.name = v.get("name").and_then(|x| x.as_str()).map(str::to_string);
            m.version = v
                .get("version")
                .and_then(|x| x.as_str())
                .map(str::to_string);
        }
        m.ecosystem = Some("npm".into());
    } else if let Some(t) = read_small(&repo.join("pyproject.toml")) {
        m.name =
            toml_field(&t, "project", "name").or_else(|| toml_field(&t, "tool.poetry", "name"));
        m.version = toml_field(&t, "project", "version")
            .or_else(|| toml_field(&t, "tool.poetry", "version"));
        m.ecosystem = Some("pip".into());
    } else if let Some(t) = read_small(&repo.join("go.mod")) {
        m.name = t
            .lines()
            .find_map(|l| l.trim().strip_prefix("module "))
            .map(|s| s.trim().to_string());
        m.ecosystem = Some("Go".into());
    }
    if m.name.is_none() {
        m.name = repo.file_name().map(|n| n.to_string_lossy().to_string());
    }
    m
}

/// Ranked channel options for this project.
pub fn recommend(meta: &ProjectMeta) -> Vec<ChannelOption> {
    let mut out = Vec::new();
    if let Some(slug) = &meta.github {
        out.push(ChannelOption {
            channel: Channel::GithubAdvisory,
            label: "GitHub 私密漏洞回報".into(),
            reason: format!("專案託管於 GitHub（{slug}），可用私密回報直接通知維護者，不會公開。"),
            submit: Some(format!("https://github.com/{slug}/security/advisories/new")),
            window_days: Channel::GithubAdvisory.window_days(),
        });
    }
    if let Some(email) = meta.security_emails.first() {
        out.push(ChannelOption {
            channel: Channel::VendorEmail,
            label: "專案安全聯絡窗口".into(),
            reason: format!(
                "{} 指定的安全聯絡信箱。",
                meta.security_policy.as_deref().unwrap_or("專案文件")
            ),
            submit: Some(format!("mailto:{email}")),
            window_days: Channel::VendorEmail.window_days(),
        });
    }
    out.push(ChannelOption {
        channel: Channel::Twcert,
        label: "TWCERT/CC（台灣漏洞通報，可申請 CVE）".into(),
        reason: "適用軟體／韌體產品漏洞；原廠無回應或為台灣廠商時優先。TWCERT/CC 為 CVE 編號管理者，自報告完整起 90 日曆天內公開基本資訊。".into(),
        submit: Some("mailto:cve@cert.org.tw".into()),
        window_days: Channel::Twcert.window_days(),
    });
    out.push(ChannelOption {
        channel: Channel::HitconZeroday,
        label: "HITCON ZeroDay（網站／服務漏洞）".into(),
        reason: "適用網站與線上服務（使用者無法自行修補的 SaaS）；第 60 天自動公開。程式庫／產品漏洞不適用。".into(),
        submit: Some("https://zeroday.hitcon.org/".into()),
        window_days: Channel::HitconZeroday.window_days(),
    });
    out
}

// ── drafting ─────────────────────────────────────────────────────────────

fn severity_en(s: Severity) -> &'static str {
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

fn steps(f: &Finding) -> Vec<String> {
    f.trace
        .iter()
        .map(|s| {
            format!(
                "`{}:{}` ({}) — {}",
                s.file,
                s.line,
                s.scope,
                s.description.trim()
            )
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

fn affected(meta: &ProjectMeta) -> String {
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

fn numbered(items: &[String]) -> String {
    if items.is_empty() {
        return "1. 【請補上可照做的重現步驟】".into();
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

/// Draft the report for `channel`. `today` is injected for testability.
pub fn draft(f: &Finding, meta: &ProjectMeta, channel: Channel, today: chrono::NaiveDate) -> Draft {
    let d = draft_raw(f, meta, channel, today);
    Draft {
        subject: show_invisible(&d.subject),
        body: show_invisible(&d.body),
        ..d
    }
}

/// Show bidi overrides/isolates and zero-width characters as `[U+XXXX]`.
/// Titles and paths in a draft come from the audited code; an invisible
/// U+202E would make the maintainer read a different file name than the one
/// meant ("Trojan Source") in a message that is copied and sent verbatim.
fn show_invisible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if matches!(cp, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF) {
            out.push_str(&format!("[U+{cp:04X}]"));
        } else {
            out.push(c);
        }
    }
    out
}

fn draft_raw(f: &Finding, meta: &ProjectMeta, channel: Channel, today: chrono::NaiveDate) -> Draft {
    let disclose_by = (today + chrono::Duration::days(channel.window_days())).to_string();
    let cwe = cwe_line(f);
    let cwe_text = cwe
        .as_ref()
        .map(|(id, e)| match e {
            Some(e) => format!("{id} {}", e.name_en),
            None => id.clone(),
        })
        .unwrap_or_else(|| "【請填寫 CWE 分類】".into());
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
    let cvss = f
        .cvss
        .as_ref()
        .map(|c| {
            format!(
                "CVSS {} {:.1}（{}）",
                c.cvss_version, c.base_score, c.cvss_vector
            )
        })
        .unwrap_or_else(|| "CVSS：【建議自行以 FIRST 計算器評估】".into());
    let impact = f
        .threat_model
        .as_ref()
        .map(|t| format!("{}（受影響：{}）", t.result.trim(), t.affected.trim()))
        .unwrap_or_else(|| "【請描述攻擊者可達成的影響】".into());
    let steps = steps(f);
    let analysis = analysis(f);
    let affected = affected(meta);
    let loc = location(f);
    let verified = "【已人工重現／尚未重現——請擇一，未重現請勿以「已確認漏洞」通報】";
    let poc_block = poc(f)
        .map(|p| format!("\n\n沙箱 PoC 執行紀錄（送出前請確認未含敏感資料）：\n```\n{p}\n```"));

    match channel {
        Channel::GithubAdvisory => {
            let subject = f.title.clone();
            let mut body = format!(
                "<!-- GitHub Security Advisory fields\nTitle: {title}\nEcosystem: {eco}\nPackage name: {pkg}\nAffected versions: {ver}\nPatched versions: (leave empty until a fix ships)\nSeverity: {sev}\nCWE: {cwe_text}\n-->\n\n### Summary\n{summary}\n\n### Details\nLocation: `{loc}`\n\n{steps_md}\n\n### PoC\nVerification status: {verified_en}\n{poc}\n\n### Impact\n{impact}\n\n### Suggested fix\n{fix}\n\n### Disclosure\nI'd like to coordinate disclosure: details stay private until a fix is released or {date}, whichever comes first.",
                title = f.title,
                eco = meta.ecosystem.as_deref().unwrap_or("(choose)"),
                pkg = meta.name.as_deref().unwrap_or("(package name)"),
                ver = meta
                    .version
                    .as_deref()
                    .map(|v| format!("<= {v}"))
                    .unwrap_or_else(|| "(affected range)".into()),
                sev = severity_en(f.severity),
                summary = analysis,
                steps_md = numbered(&steps),
                verified_en = "[manually reproduced / not yet reproduced — pick one]",
                poc = poc_block.clone().unwrap_or_default(),
                impact = impact,
                fix = bullets(&fixes, "(describe the fix)"),
                date = disclose_by,
            );
            body.push_str(&format!(
                "\n\n(Generated by vettalon from automated multi-model review; {cvss}.)"
            ));
            Draft {
                channel,
                subject,
                body,
                submit: None,
                disclose_by,
            }
        }
        Channel::VendorEmail => {
            let subject = format!(
                "[Security] {} in {}",
                f.title,
                meta.name.as_deref().unwrap_or("your project")
            );
            let body = format!(
                "Hello maintainers,\n\nI'd like to privately report a security issue in {affected}.\n\nSummary: {title}\nSeverity (assessed): {sev}; {cvss}\nWeakness: {cwe_text}\nLocation: {loc}\nVerification status: [manually reproduced / not yet reproduced — pick one]\n\nDetails:\n{analysis}\n\nSteps to reproduce:\n{steps}\n\nImpact:\n{impact}\n\nSuggested fix:\n{fix}{poc}\n\nI propose coordinated disclosure: I will keep this private until a fix is released or {date} ({days} days), whichever comes first. Please let me know if you need more time.\n\nThanks,\n[your name or handle]",
                title = f.title,
                sev = severity_en(f.severity),
                steps = numbered(&steps),
                fix = bullets(&fixes, "(see details)"),
                poc = poc_block.clone().unwrap_or_default(),
                date = disclose_by,
                days = channel.window_days(),
            );
            Draft {
                channel,
                subject,
                body,
                submit: None,
                disclose_by,
            }
        }
        Channel::Twcert => {
            let subject = format!("[漏洞通報] {affected}：{}", f.title);
            let body = format!(
                "TWCERT/CC 您好：\n\n以下通報 {affected} 之安全弱點，請協助確認並與原廠協調處理。\n\n一、漏洞概述：{title}\n二、受影響產品與版本：{affected}；問題位置：{loc}\n三、弱點類型：{cwe_zh}\n四、風險評估：{sev}；{cvss}\n五、驗證狀態：{verified}\n六、漏洞技術描述：\n{analysis}\n七、重現方法：\n{steps}\n八、潛在影響：{impact}\n九、建議修補方式：\n{fix}{poc}\n十、揭露意願：同意依貴中心漏洞揭露政策，自報告確認完整之日起 90 日曆天內公開基本資訊（預計 {date} 前）；署名方式：【具名稱呼／匿名】\n十一、通報者聯絡資訊：【姓名／Email／電話】；是否同意提供聯絡方式予原廠：【是／否】\n\n（可選擇以 PGP 加密寄送，TWCERT/CC 公開金鑰 KeyID 1E9D1F1B）",
                title = f.title,
                sev = severity_zh(f.severity),
                steps = numbered(&steps),
                fix = bullets(&fixes, "【請描述修補方式】"),
                poc = poc_block.clone().unwrap_or_default(),
                date = disclose_by,
            );
            Draft {
                channel,
                subject,
                body,
                submit: Some("mailto:cve@cert.org.tw".into()),
                disclose_by,
            }
        }
        Channel::HitconZeroday => {
            let subject = f.title.clone();
            let body = format!(
                "標題：{title}\n風險等級：{sev}\n類型：{cwe_zh}\n受影響網站／服務：【網址】\n\n敘述：\n{analysis}\n\n驗證狀態：{verified}\n\n重現步驟：\n{steps}\n\n處理建議：\n{fix}{poc}\n\n（HITCON ZeroDay 適用網站與線上服務；程式庫或產品漏洞請改通報原廠或 TWCERT/CC。平台於第 60 天自動公開，預計 {date}。）",
                title = f.title,
                sev = severity_zh(f.severity),
                steps = numbered(&steps),
                fix = bullets(&fixes, "【請描述修補方式】"),
                poc = poc_block.unwrap_or_default(),
                date = disclose_by,
            );
            Draft {
                channel,
                subject,
                body,
                submit: Some("https://zeroday.hitcon.org/".into()),
                disclose_by,
            }
        }
    }
}

/// Build the package for one finding of `report`: project detection,
/// channel ranking and the draft for `channel` (default: the top option).
pub fn prepare(
    report: &AuditReport,
    finding_id: &str,
    channel: Option<Channel>,
) -> Result<DisclosurePackage, String> {
    let f = report
        .findings
        .iter()
        .find(|f| f.id == finding_id)
        .ok_or_else(|| format!("找不到 finding {finding_id}"))?;
    let project = detect_project(Path::new(&report.repo));
    package_for(f, project, channel, chrono::Local::now().date_naive())
}

/// Build the disclosure package for one finding of a known project: the
/// ranked channels, a draft for the chosen (or top-recommended) channel, and
/// the pre-send checklist. Shared by scan reports and supply-chain hunts.
pub fn package_for(
    f: &Finding,
    project: ProjectMeta,
    channel: Option<Channel>,
    today: chrono::NaiveDate,
) -> Result<DisclosurePackage, String> {
    eligible(f)?;
    let channels = recommend(&project);
    let chosen = channel.unwrap_or(channels[0].channel);
    let mut d = draft(f, &project, chosen, today);
    if d.submit.is_none() {
        d.submit = channels
            .iter()
            .find(|c| c.channel == chosen)
            .and_then(|c| c.submit.clone());
    }
    Ok(DisclosurePackage {
        finding_id: f.id.clone(),
        finding_title: f.title.clone(),
        project,
        channels,
        draft: d,
        checklist: CHECKLIST.iter().map(|s| s.to_string()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, ThreatModel, TraceKind, TraceStep};

    #[test]
    fn draft_shows_bidi_characters_from_the_audited_code() {
        let mut f = finding(FindingStatus::NeedsHuman);
        f.file = "lib/run\u{202E}exe.js".into();
        f.title = "x\u{200B}y".into();
        let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 15).unwrap();
        let d = draft(&f, &ProjectMeta::default(), Channel::Twcert, today);
        assert!(d.body.contains("run[U+202E]exe.js"), "{}", d.body);
        assert!(d.subject.contains("x[U+200B]y"));
        assert!(!d.body.contains('\u{202E}') && !d.subject.contains('\u{200B}'));
    }

    fn finding(status: FindingStatus) -> Finding {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "SQL injection in /search",
            "app/db.py",
            Some(42),
            "cur.execute(q)",
            "ai-audit/sql_injection",
            vec![crate::audit::schema::EvidenceItem {
                kind: EvidenceKind::AiAnalysis,
                source: "ai_audit".into(),
                detail: "reasoning: user input flows into execute()".into(),
                recorded_at: "2026-10-13T00:00:00Z".into(),
            }],
        );
        f.status = status;
        f.threat_model = Some(ThreatModel {
            principal: "anon".into(),
            input: "q".into(),
            control: "none".into(),
            boundary: "net".into(),
            affected: "orders table".into(),
            result: "read any order".into(),
        });
        f.trace = vec![TraceStep {
            kind: TraceKind::Entrypoint,
            file: "app/web.py".into(),
            line: 10,
            scope: "search".into(),
            description: "q from query string".into(),
        }];
        f
    }

    fn repo() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(".git/refs/heads")).unwrap();
        std::fs::write(
            d.path().join(".git/config"),
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:acme/shop.git\n",
        )
        .unwrap();
        std::fs::write(d.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            d.path().join(".git/refs/heads/main"),
            "0123456789abcdef0123456789abcdef01234567\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("SECURITY.md"),
            "Report to security@acme.example please.",
        )
        .unwrap();
        std::fs::write(
            d.path().join("Cargo.toml"),
            "[package]\nname = \"shop\"\nversion = \"1.2.3\"\n",
        )
        .unwrap();
        d
    }

    #[test]
    fn only_reviewed_findings_are_eligible() {
        assert!(eligible(&finding(FindingStatus::NeedsHuman)).is_ok());
        assert!(eligible(&finding(FindingStatus::Confirmed)).is_ok());
        assert!(eligible(&finding(FindingStatus::Candidate)).is_err());
        assert!(eligible(&finding(FindingStatus::Refuted)).is_err());
        assert!(eligible(&finding(FindingStatus::Suppressed)).is_err());
    }

    #[test]
    fn detects_project_locally() {
        let d = repo();
        let m = detect_project(d.path());
        assert_eq!(m.github.as_deref(), Some("acme/shop"));
        assert_eq!(m.name.as_deref(), Some("shop"));
        assert_eq!(m.version.as_deref(), Some("1.2.3"));
        assert_eq!(m.ecosystem.as_deref(), Some("Rust"));
        assert_eq!(m.commit.as_deref(), Some("0123456789ab"));
        assert_eq!(m.security_emails, vec!["security@acme.example".to_string()]);
        let ch = recommend(&m);
        assert_eq!(ch[0].channel, Channel::GithubAdvisory);
        assert_eq!(
            ch[0].submit.as_deref(),
            Some("https://github.com/acme/shop/security/advisories/new")
        );
        assert_eq!(ch[1].channel, Channel::VendorEmail);
    }

    #[test]
    fn github_slug_shapes() {
        assert_eq!(
            github_slug("https://github.com/a/b.git").as_deref(),
            Some("a/b")
        );
        assert_eq!(github_slug("git@github.com:a/b").as_deref(), Some("a/b"));
        assert!(github_slug("https://gitlab.com/a/b").is_none());
        assert!(github_slug("https://github.com/a/b/c").is_none());
    }

    #[test]
    fn drafts_carry_required_fields_and_never_claim_verification() {
        let f = finding(FindingStatus::NeedsHuman);
        let m = detect_project(repo().path());
        let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 13).unwrap();
        let tw = draft(&f, &m, Channel::Twcert, today);
        for needle in [
            "受影響產品與版本",
            "shop 1.2.3",
            "CWE-89",
            "重現方法",
            "揭露意願",
            "2027-01-11",
            "已人工重現／尚未重現",
        ] {
            assert!(tw.body.contains(needle), "TWCERT draft missing {needle:?}");
        }
        assert_eq!(tw.submit.as_deref(), Some("mailto:cve@cert.org.tw"));
        let gh = draft(&f, &m, Channel::GithubAdvisory, today);
        assert!(gh.body.contains("### Impact") && gh.body.contains("Ecosystem: Rust"));
        let hc = draft(&f, &m, Channel::HitconZeroday, today);
        assert_eq!(hc.disclose_by, "2026-12-12", "HITCON 60 days");
    }

    #[test]
    fn prepare_refuses_unreviewed_and_picks_top_channel() {
        let d = repo();
        let mut ok = finding(FindingStatus::NeedsHuman);
        let bad = finding(FindingStatus::Candidate);
        ok.id = "ok".into();
        let mut r: AuditReport = serde_json::from_value(serde_json::json!({
            "schema_version": 2, "repo": d.path().to_string_lossy(), "started_at": "2026-10-13T00:00:00Z",
            "profile": {"mode": "deep"}, "engines_run": [], "engines_missing": [],
            "findings": [], "summary": {"total_findings": 0, "by_severity": {"critical":0,"high":0,"medium":0,"low":0,"info":0},
            "engines_run_count": 0, "engines_missing_count": 0}
        }))
        .unwrap();
        let bad_id = bad.id.clone();
        r.findings = vec![ok, bad];
        let pkg = prepare(&r, "ok", None).unwrap();
        assert_eq!(pkg.draft.channel, Channel::GithubAdvisory);
        assert!(
            pkg.draft
                .submit
                .unwrap()
                .contains("security/advisories/new")
        );
        assert_eq!(pkg.checklist.len(), CHECKLIST.len());
        assert!(prepare(&r, &bad_id, None).is_err());
        assert!(prepare(&r, "nope", None).is_err());
    }
}
