//! Developer disclosure assistant: pick a reporting channel for a finding and
//! draft the report in the destination's expected format.
//!
//! Hard line: this module only WRITES DRAFTS. It never sends, posts or
//! contacts anyone. Submitting, talking to the vendor and deciding the
//! disclosure date are the human's job (coordinated vulnerability disclosure
//! ethics, and the reporter's legal safety). Channel detection is local: the
//! repo's git remote (without one, the repository URL in the package
//! metadata, as untrusted data), SECURITY.md and package manifest. The only network use
//! is the optional pre-send duplicate check ([`dedupe`]), and only when the
//! operator asks for it.
//!
//! Rules every draft follows:
//! - evidence gate ([`eligibility`]): by default only findings at
//!   `poc_effect_no_control` or above; `--allow-unproven` admits the refuter
//!   levels with an UNPROVEN banner; `static_only` is never drafted;
//! - a fixed AI use statement naming a human reviewer pseudonym and review
//!   date ([`ai_use`]); no reviewer, no draft;
//! - severity is never filled in by the tool (a human-set severity is);
//! - target policy files are data ([`policy`]);
//! - one unanswered draft per project at a time ([`ledger`]);
//! - dependency findings keep "upstream vulnerable" and "does this project
//!   reach it" apart; the second is unknown without executed evidence.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit::schema::{AuditReport, Finding, ModelInfo, SeverityBasis};

pub mod ai_use;
pub mod dedupe;
mod detect;
pub mod eligibility;
mod formats;
pub mod ledger;
pub mod policy;
mod upstream;

pub use crate::audit::evidence_level::{EvidenceLevel, ProofGap};
pub use ai_use::{AiUseStatement, Reviewer};
pub use dedupe::{DedupeReport, DedupeSource};
pub use detect::{detect_project, detect_project_as, github_slug, recommend};
pub use eligibility::{Eligibility, draft_eligibility};
pub use ledger::ThrottleStatus;
pub use upstream::{UpstreamOrigin, go_module_url, normalize_github};

/// Where a report can be filed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// GitHub private vulnerability reporting / repository security advisory.
    GithubAdvisory,
    /// The project's own security contact (SECURITY.md / manifest).
    VendorEmail,
    /// TWCERT/CC — product vulnerability coordination.
    Twcert,
    /// HITCON ZeroDay — website / online service coordination.
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
    /// Legacy suggested coordination interval, not a platform policy or publication grant.
    pub fn window_days(self) -> i64 {
        match self {
            Channel::HitconZeroday => 60,
            _ => 90,
        }
    }
}

/// Destination format of the draft body. Without one, the channel's own
/// form is used (GitHub advisory → `ghsa`, project email → `email`,
/// TWCERT/CC and HITCON ZeroDay → their zh-TW forms).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftFormat {
    Ghsa,
    /// Short and plain: minimal PoC, tested versions, no CVSS or headings.
    Minimal,
    /// Linux kernel: plain text, exact commit, tested patch; AI-assisted
    /// findings are treated as public by the kernel's process.
    Kernel,
    Email,
}

impl std::str::FromStr for DraftFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ghsa" => Ok(DraftFormat::Ghsa),
            "minimal" => Ok(DraftFormat::Minimal),
            "kernel" => Ok(DraftFormat::Kernel),
            "email" => Ok(DraftFormat::Email),
            other => Err(format!(
                "unknown format {other:?} (ghsa | minimal | kernel | email)"
            )),
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
    /// `owner/repo` of the upstream on github.com: the origin remote, or
    /// (with no GitHub remote) the repository URL in the package metadata.
    pub github: Option<String>,
    /// Where `github` came from (git remote vs. a package metadata field).
    pub github_source: Option<UpstreamOrigin>,
    /// A metadata repository URL that is not a github.com repo, recorded as
    /// `<host> (<file> <field>)`; no GitHub advisory channel follows from it.
    pub non_github_upstream: Option<String>,
    pub commit: Option<String>,
    pub security_policy: Option<String>,
    pub security_emails: Vec<String>,
    /// Requirement-looking lines from the security policy, quoted as data
    /// for human confirmation. Never acted on.
    pub policy_requirements: Vec<String>,
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
    /// Suggested coordination checkpoint; the legacy field name does not grant publication.
    pub disclose_by: String,
}

/// Severity handling: the tool never fills it in. The model's (or scanner
/// rule's) value is kept apart for later comparison with the human's and
/// the maintainer's rating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeverityReview {
    /// The pre-human value and where it came from (`model_self_reported` /
    /// `scanner_rule`). `None` once a human set the severity.
    pub ai_severity: Option<String>,
    pub ai_basis: Option<String>,
    /// Set only when a human set the severity (`severity_basis: operator`).
    pub human_severity: Option<String>,
}

impl SeverityReview {
    pub fn of(f: &Finding) -> SeverityReview {
        if f.severity_basis == SeverityBasis::Operator {
            return SeverityReview {
                ai_severity: None,
                ai_basis: None,
                human_severity: Some(f.severity.as_str().to_string()),
            };
        }
        let basis = match f.severity_basis {
            SeverityBasis::ModelSelfReported => "model_self_reported",
            SeverityBasis::ModelDecomposed => "model_decomposed",
            _ => "scanner_rule",
        };
        SeverityReview {
            ai_severity: Some(f.severity.as_str().to_string()),
            ai_basis: Some(basis.into()),
            human_severity: None,
        }
    }
}

/// Whether the host project reaches the vulnerable dependency code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// No executed evidence from the host project. Never inferred as safe
    /// or as affected.
    Unknown,
}

/// Dependency findings: two separate judgements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyScope {
    /// `name@version` of the upstream package.
    pub dependency: String,
    /// The project that depends on it (never named in the upstream draft).
    pub host_project: String,
    /// (a) Is the upstream package vulnerable? Stated from the evidence level.
    pub upstream_vulnerable: String,
    /// (b) Does the host project reach the code?
    pub host_reachability: Reachability,
    pub reachability_basis: String,
}

impl DependencyScope {
    pub fn new(dependency: &str, host_project: &str, e: &Eligibility) -> DependencyScope {
        let upstream_vulnerable = if e.unproven {
            format!(
                "not yet proven (evidence level {}); a human must reproduce it against {dependency} before sending",
                e.level.key()
            )
        } else {
            format!(
                "supported at evidence level {} for {dependency}",
                e.level.key()
            )
        };
        DependencyScope {
            dependency: dependency.to_string(),
            host_project: host_project.to_string(),
            upstream_vulnerable,
            host_reachability: Reachability::Unknown,
            reachability_basis: "no executed evidence from the depending project is recorded"
                .into(),
        }
    }

    /// Maintainer-facing text: claims nothing about any downstream project.
    fn render_en(&self) -> String {
        format!(
            "- Upstream package {}: {}.\n- Downstream impact: not claimed. Whether any particular application reaches this code is unknown; no executed reachability evidence is recorded.",
            self.dependency, self.upstream_vulnerable
        )
    }

    fn render_zh(&self) -> String {
        format!(
            "- 上游套件 {}：{}。\n- 下游影響：本報告不主張。任何特定應用程式是否會執行到這段程式碼目前未知，沒有實際執行的可達性證據。",
            self.dependency, self.upstream_vulnerable
        )
    }
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
    pub evidence_level: EvidenceLevel,
    /// What the finding still lacks (shared derivation; see `audit::evidence_level`).
    pub proof_gaps: Vec<ProofGap>,
    /// The most damaging recorded counter-evidence, masked and bounded.
    pub strongest_counterevidence: Option<String>,
    /// True when drafted only because of `--allow-unproven`.
    pub unproven: bool,
    /// `ghsa` | `minimal` | `kernel` | `email` | `twcert_form` | `hitcon_form`.
    pub format: String,
    pub include_patch: bool,
    pub ai_use: AiUseStatement,
    pub severity: SeverityReview,
    pub dedupe: DedupeReport,
    pub dependency_scope: Option<DependencyScope>,
    pub throttle: ThrottleStatus,
    pub warnings: Vec<String>,
}

pub const CHECKLIST: &[&str] = &[
    "已完成獨立的人工覆核，確認可利用性與影響範圍；自動分析或草稿產生不等於人工確認",
    "已保存對應目標與來源識別（版本、commit 或摘要）及沙盒重現紀錄，並核對結果與限制",
    "測試全程在授權範圍內進行，未對他人的正式環境做未經授權的存取",
    "草稿中沒有真實帳密、金鑰、個資或客戶資料",
    "已核對維護者現行政策、授權範圍、正確收件管道與已知公告，未代替任何人同意公開",
    "已取得本次私下通報核准並留下核准人、內容與署名方式；公開須另行核准，建議日期或期限到期不代表公開授權",
    "AI 使用聲明中的審閱者化名、審閱日期與「已人工重現」敘述都屬實；化名會公開",
    "已逐項看過重複檢查結果（標示「未檢查」的項目已自行查過），嚴重度由人工判定後才填入",
    "已刪除草稿開頭的審閱備註區塊，並把引用的模型分析改寫成自己的話",
];

/// [`CHECKLIST`] for an English terminal (same items, same order).
pub const CHECKLIST_EN: &[&str] = &[
    "Independent human review is done and confirms exploitability and impact; automated analysis or a generated draft is not human confirmation",
    "The target and source identity (version, commit or digest) and the sandbox reproduction record are saved, and the results and limits were checked",
    "All testing stayed within the authorized scope, with no unauthorized access to anyone else's production systems",
    "The draft holds no real credentials, keys, personal data or customer data",
    "The maintainer's current policy, scope, correct reporting channel and known advisories were checked; nobody's consent to publication was assumed",
    "Approval for this private report is obtained and the approver, content and attribution are recorded; publication needs separate approval, and reaching a suggested date or deadline does not authorize it",
    "The reviewer pseudonym, review date and \"manually reproduced\" statement in the AI use statement are true; the pseudonym will be public",
    "Every duplicate-check result was reviewed (items marked NOT CHECKED were checked by hand), and severity is filled in only after a human rated it",
    "The reviewer notes block at the top of the draft is deleted and the quoted model analysis is rewritten in your own words",
];

/// The pre-send checklist in the terminal language (`crate::lang`).
pub fn checklist() -> Vec<String> {
    let items = match crate::lang::get() {
        crate::lang::Lang::ZhTw => CHECKLIST,
        crate::lang::Lang::En => CHECKLIST_EN,
    };
    items.iter().map(|s| s.to_string()).collect()
}

/// Operator choices for drafting. A reviewer is required by construction.
#[derive(Debug, Clone)]
pub struct DraftOptions {
    pub allow_unproven: bool,
    pub format: Option<DraftFormat>,
    /// `false` drops the suggested-fix / patch section (projects that refuse
    /// tool-written patches).
    pub include_patch: bool,
    pub reviewer: Reviewer,
    /// Override the per-project throttle; must carry a reason.
    pub force_throttle: Option<String>,
    /// The throttle ledger (`<vettalon home>/disclosure-ledger.json`).
    pub ledger_path: PathBuf,
    /// The run's model roster (families and roles for the AI use statement).
    pub roster: Vec<ModelInfo>,
}

impl DraftOptions {
    pub fn new(reviewer: Reviewer, home: &Path) -> DraftOptions {
        DraftOptions {
            allow_unproven: false,
            format: None,
            include_patch: true,
            reviewer,
            force_throttle: None,
            ledger_path: ledger::default_path(home),
            roster: Vec::new(),
        }
    }
}

/// Per-finding inputs gathered before drafting.
#[derive(Debug, Clone)]
pub struct FindingExtras {
    pub dedupe: DedupeReport,
    /// `(name@version, host project)` for a finding inside a dependency.
    pub dependency: Option<(String, String)>,
}

impl Default for FindingExtras {
    fn default() -> Self {
        FindingExtras {
            dedupe: DedupeReport::not_requested(),
            dependency: None,
        }
    }
}

/// Inputs a template needs besides the finding and project.
pub(crate) struct DraftContext<'a> {
    pub include_patch: bool,
    pub ai_use: &'a AiUseStatement,
    pub severity: &'a SeverityReview,
    pub dependency: Option<&'a DependencyScope>,
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

/// The Linux kernel (by GitHub mirror or name).
pub fn is_linux_kernel(meta: &ProjectMeta) -> bool {
    matches!(
        meta.github
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("torvalds/linux" | "gregkh/linux")
    ) || meta.name.as_deref() == Some("linux")
}

pub const KERNEL_WARNING: &str = "Linux kernel: per the kernel's documented process an AI-assisted finding is treated as public. Send it to the maintainers and lists printed by scripts/get_maintainer.pl, not to a private channel. Do not post the reproducer publicly; share it only when the maintainers ask. Include the exact commit or version and a tested fix.";

const NOTES_START_EN: &str = "----- REVIEWER NOTES: delete this block before sending -----";
const NOTES_END_EN: &str = "----- END REVIEWER NOTES -----";
const NOTES_START_ZH: &str = "----- 審閱備註：送出前請刪除本區塊 -----";
const NOTES_END_ZH: &str = "----- 審閱備註結束 -----";

/// Marker that ends the reviewer-notes block (either language).
pub fn notes_end_marker(zh: bool) -> &'static str {
    if zh { NOTES_END_ZH } else { NOTES_END_EN }
}

/// External text (policy lines, commit messages, issue titles) must not be
/// able to fake the start or end of the reviewer-notes block.
pub(super) fn defang_markers(s: &str) -> String {
    s.replace("-----", "- - - - -")
}

fn unproven_banner(e: &Eligibility, zh: bool) -> String {
    if zh {
        format!(
            "!!! 未證實（UNPROVEN）：證據等級 {}，沒有由執行框架判定的 PoC。只因 --allow-unproven 才產生；不可當成已確認漏洞送出。 !!!",
            e.level.key()
        )
    } else {
        format!(
            "!!! UNPROVEN: evidence level {}, no harness-judged PoC. Drafted only because of --allow-unproven; do not present this as a confirmed vulnerability. !!!",
            e.level.key()
        )
    }
}

struct Notes<'a> {
    eligibility: &'a Eligibility,
    severity: &'a SeverityReview,
    dedupe: &'a DedupeReport,
    meta: &'a ProjectMeta,
    dependency: Option<&'a DependencyScope>,
    warnings: &'a [String],
}

/// Where the upstream repository came from, for the reviewer. A value read
/// from package metadata was written by the package author: confirm it.
fn upstream_note(meta: &ProjectMeta, zh: bool) -> Option<String> {
    match (&meta.github, &meta.github_source, &meta.non_github_upstream) {
        (Some(slug), Some(src @ UpstreamOrigin::PackageMetadata { .. }), _) => Some(if zh {
            format!(
                "上游儲存庫：github.com/{slug}，來源：{}。此值由套件作者填寫，送出前請確認它是真正的上游。",
                src.render(true)
            )
        } else {
            format!(
                "Upstream repository: github.com/{slug}, from {}. The package author wrote this value; confirm it is the real upstream before sending.",
                src.render(false)
            )
        }),
        (Some(slug), Some(src), _) => Some(if zh {
            format!(
                "上游儲存庫：github.com/{slug}，來源：{}。",
                src.render(true)
            )
        } else {
            format!(
                "Upstream repository: github.com/{slug}, from {}.",
                src.render(false)
            )
        }),
        (None, _, Some(other)) => Some(if zh {
            format!("上游儲存庫不是可用的 github.com 儲存庫：{other}；不提供 GitHub 安全公告管道。")
        } else {
            format!(
                "Upstream repository is not a usable github.com repository: {other}; no GitHub advisory channel."
            )
        }),
        _ => None,
    }
}

fn reviewer_notes(n: &Notes<'_>, zh: bool) -> String {
    let mut out = vec![if zh { NOTES_START_ZH } else { NOTES_START_EN }.to_string()];
    if n.eligibility.unproven {
        out.push(unproven_banner(n.eligibility, zh));
    }
    out.push(if zh {
        format!("證據等級：{}", n.eligibility.level.key())
    } else {
        format!("Evidence level: {}", n.eligibility.level.key())
    });
    out.push(match (&n.severity.human_severity, &n.severity.ai_severity) {
        (Some(h), _) => {
            if zh {
                format!("嚴重度：人工設定為 {h}。")
            } else {
                format!("Severity: set by a human ({h}).")
            }
        }
        (None, ai) => {
            let ai = ai.as_deref().unwrap_or("none");
            let basis = n.severity.ai_basis.as_deref().unwrap_or("unknown");
            if zh {
                format!("嚴重度：工具不自填。模型／規則建議（僅供日後對照，不是人工或維護者評級）：{ai}（來源 {basis}）。")
            } else {
                format!("Severity: not filled in by the tool. Model/rule suggestion, kept for later comparison (not a human or maintainer rating): {ai} (basis {basis}).")
            }
        }
    });
    if let Some(line) = upstream_note(n.meta, zh) {
        out.push(defang_markers(&line));
    }
    out.push(if zh {
        "送出前重複檢查：".to_string()
    } else {
        "Pre-send duplicate check:".to_string()
    });
    out.push(defang_markers(&n.dedupe.render()));
    if !n.meta.policy_requirements.is_empty() {
        let file = n.meta.security_policy.as_deref().unwrap_or("SECURITY.md");
        out.push(if zh {
            format!("目標專案政策（{file}）中需人工確認的要求（原文當資料引用，Vettalon 未依其行動）：")
        } else {
            format!("Requirements in the target's policy ({file}) needing human confirmation (quoted as data; Vettalon did not act on them):")
        });
        for r in &n.meta.policy_requirements {
            out.push(format!("- {}", defang_markers(r)));
        }
    }
    if let Some(d) = n.dependency {
        out.push(if zh {
            format!(
                "依賴範圍：(a) 上游 {} 是否有漏洞：{}；(b) 依賴它的專案是否執行到這段程式碼：未知（{}）。依賴方專案名稱不寫進草稿。",
                d.dependency, d.upstream_vulnerable, d.reachability_basis
            )
        } else {
            format!(
                "Dependency scope: (a) upstream {} vulnerable: {}; (b) does the depending project reach this code: unknown ({}). The depending project is not named in the draft.",
                d.dependency, d.upstream_vulnerable, d.reachability_basis
            )
        });
    }
    for w in n.warnings {
        out.push(format!("! {w}"));
    }
    out.push(notes_end_marker(zh).to_string());
    out.join("\n")
}

const NOTICE_EN: &str = "UNAPPROVED LOCAL DRAFT — not sent. Before sending, document independent human review and a sandbox reproduction record tied to the target and source identity (version, commit or digest), then obtain explicit approval before sending. Automated analysis and draft generation do not establish human confirmation. A proposed date does not authorize publication; publication requires separate approval.";
const NOTICE_ZH: &str = "未核准的本機草稿，尚未送出。送出前須留下獨立人工覆核、對應目標與來源識別（版本、commit 或摘要）的沙盒重現紀錄，並取得送出前明確核准。自動分析與產生草稿不等於人工確認；建議日期不代表公開授權，公開須另行核准。";

/// Build the package for one finding of a known project: eligibility gate,
/// throttle check, the draft for the chosen (or top-recommended) channel,
/// and the pre-send checklist. Does not write the ledger; call
/// [`record_draft`] once the draft has been handed to the human.
pub fn package_for(
    f: &Finding,
    project: ProjectMeta,
    channel: Option<Channel>,
    today: chrono::NaiveDate,
    opts: &DraftOptions,
    extras: FindingExtras,
) -> Result<DisclosurePackage, String> {
    let eligibility = draft_eligibility(f, opts.allow_unproven)?;
    let throttle = ledger::check(
        &ledger::load(&opts.ledger_path)?,
        &ledger::project_key(&project),
        &f.id,
        opts.force_throttle.as_deref(),
    )?;
    let channels = recommend(&project);
    let chosen = channel.unwrap_or(channels[0].channel);
    let template = formats::Template::resolve(chosen, opts.format);
    let zh = template.zh();

    let mut warnings = Vec::new();
    if template == formats::Template::Kernel {
        warnings.push(KERNEL_WARNING.to_string());
    } else if chosen == Channel::VendorEmail && !project.security_emails.is_empty() {
        // The address is read from a file the target wrote; confirm it.
        warnings.push(format!(
            "Recipient {} was read from {}; confirm it is the project's real security contact before sending.",
            project.security_emails[0],
            project.security_policy.as_deref().unwrap_or("the project files")
        ));
    } else if is_linux_kernel(&project) {
        warnings.push(format!(
            "This looks like the Linux kernel; use --format kernel. {KERNEL_WARNING}"
        ));
    }
    if let Some(reason) = &throttle.forced_reason
        && !throttle.open_for_project.is_empty()
    {
        warnings.push(format!(
            "Throttle overridden ({reason}); unanswered drafts for this project: {}",
            throttle.open_for_project.join(", ")
        ));
    }

    let ai_use = AiUseStatement::build(
        f,
        &opts.roster,
        opts.reviewer.clone(),
        eligibility.level == EvidenceLevel::MaintainerConfirmed,
    );
    let severity = SeverityReview::of(f);
    // Only a finding inside a hunted dependency gets the upstream/host split;
    // a scan finding is reported to the scanned project itself.
    let dependency = extras
        .dependency
        .as_ref()
        .map(|(dep, host)| DependencyScope::new(dep, host, &eligibility));
    let disclose_by = if template == formats::Template::Kernel {
        // Treated as public from the start; no private window to suggest.
        today.to_string()
    } else {
        (today + chrono::Duration::days(chosen.window_days())).to_string()
    };
    let ctx = DraftContext {
        include_patch: opts.include_patch,
        ai_use: &ai_use,
        severity: &severity,
        dependency: dependency.as_ref(),
    };
    let rendered = formats::render(template, f, &project, &disclose_by, &ctx);
    let notes = reviewer_notes(
        &Notes {
            eligibility: &eligibility,
            severity: &severity,
            dedupe: &extras.dedupe,
            meta: &project,
            dependency: dependency.as_ref(),
            warnings: &warnings,
        },
        zh,
    );
    let mut head = String::new();
    if eligibility.unproven {
        head.push_str(&unproven_banner(&eligibility, zh));
        head.push_str("\n\n");
    }
    head.push_str(if zh { NOTICE_ZH } else { NOTICE_EN });
    let body = format!("{head}\n\n{notes}\n\n{}", rendered.body);
    let submit = if template == formats::Template::Kernel {
        None
    } else {
        rendered.submit.or_else(|| {
            channels
                .iter()
                .find(|c| c.channel == chosen)
                .and_then(|c| c.submit.clone())
        })
    };
    let draft = Draft {
        channel: chosen,
        subject: show_invisible(&rendered.subject),
        body: show_invisible(&body),
        submit,
        disclose_by,
    };
    Ok(DisclosurePackage {
        finding_id: f.id.clone(),
        finding_title: f.title.clone(),
        project,
        channels,
        draft,
        checklist: checklist(),
        evidence_level: eligibility.level,
        proof_gaps: f.proof_gaps(),
        strongest_counterevidence: f.strongest_counterevidence().map(|c| defang_markers(&c)),
        unproven: eligibility.unproven,
        format: template.key().to_string(),
        include_patch: opts.include_patch,
        ai_use,
        severity,
        dedupe: extras.dedupe,
        dependency_scope: dependency,
        throttle,
        warnings,
    })
}

/// Record a produced draft in the throttle ledger.
pub fn record_draft(
    opts: &DraftOptions,
    pkg: &DisclosurePackage,
    today: chrono::NaiveDate,
) -> Result<(), String> {
    ledger::record(&opts.ledger_path, &pkg.throttle, &pkg.finding_id, today)
}

/// Build the package for one finding of a scan `report`: project detection,
/// optional online duplicate check, channel ranking and the draft.
pub async fn prepare(
    report: &AuditReport,
    finding_id: &str,
    channel: Option<Channel>,
    opts: &DraftOptions,
    dedupe_src: Option<&dyn DedupeSource>,
) -> Result<DisclosurePackage, String> {
    let f = report
        .findings
        .iter()
        .find(|f| f.id == finding_id)
        .ok_or_else(|| crate::tr!("找不到 finding {finding_id}", "no finding {finding_id}"))?;
    // Gate before any network use.
    draft_eligibility(f, opts.allow_unproven)?;
    let project = detect_project(Path::new(&report.repo));
    let today = chrono::Local::now().date_naive();
    let dedupe = match dedupe_src {
        Some(src) => dedupe::check(src, &project, &f.file, today).await,
        None => DedupeReport::not_requested(),
    };
    let mut opts = opts.clone();
    if opts.roster.is_empty() {
        opts.roster = report.ensemble.models.clone();
    }
    package_for(
        f,
        project,
        channel,
        today,
        &opts,
        FindingExtras {
            dedupe,
            dependency: None,
        },
    )
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod upstream_tests;
