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
//!   `poc_differential` or above; `--allow-unproven` admits
//!   `poc_effect_no_control` and the refuter levels with an UNPROVEN banner;
//!   `static_only` is never drafted;
//! - a fixed AI use statement naming a human reviewer pseudonym and review
//!   date ([`ai_use`]); no reviewer, no draft;
//! - severity is never filled in by the tool (a human-set severity is), and
//!   no draft carries a CVSS vector or score;
//! - template text is capped at 8,000 characters by shortening only the
//!   analysis, trace and PoC transcript (the AI use statement, reviewer line
//!   and disclosure section are never cut); the Details section names the
//!   commit (or says it is unknown);
//! - an optional reproduce receipt is tied to the finding (file, file hash,
//!   function, outcome re-derived from its phases) and quoted by name,
//!   SHA-256 and outcome ([`receipt`]); its signature is not verified here,
//!   and the draft says so;
//! - the target's out-of-scope statements are a reviewer-notes hint only
//!   ([`scope`]);
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
pub(crate) mod formats;
pub mod ledger;
pub mod policy;
pub mod receipt;
pub mod scope;
mod upstream;

pub use crate::audit::evidence_level::{EvidenceLevel, ProofGap};
pub use ai_use::{AiUseStatement, Reviewer};
pub use dedupe::{DedupeReport, DedupeSource};
pub use detect::{detect_project, detect_project_as, github_slug, recommend};
pub use eligibility::{Eligibility, draft_eligibility};
pub use ledger::ThrottleStatus;
pub use receipt::ReceiptNote;
pub use scope::ScopeCheck;
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
    /// Out-of-scope lines of the policy / threat-model files, for the
    /// reviewer-notes scope hint. Not serialized.
    #[serde(skip)]
    pub scope_docs: Vec<scope::ScopeDoc>,
}

/// The finding's CWE id (its own, else the one its rule kind maps to).
pub fn finding_cwe(f: &Finding) -> Option<String> {
    formats::finding_cwe(f)
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
    /// Hint from the target's out-of-scope statements (reviewer notes only;
    /// never changes eligibility or the draft).
    pub scope_check: ScopeCheck,
    /// The reproduce receipt quoted in the PoC section, when attached.
    pub receipt: Option<ReceiptNote>,
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
    /// A `vettalon reproduce` receipt for the finding (`--receipt`).
    pub receipt: Option<PathBuf>,
    /// Its signature bundle (`--receipt-bundle`); needs `receipt`.
    pub receipt_bundle: Option<PathBuf>,
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
            receipt: None,
            receipt_bundle: None,
        }
    }

    /// Read and check the receipt files for `f` (none asked: `Ok(None)`).
    /// A bundle without a receipt is refused.
    pub fn load_receipt(&self, f: &Finding) -> Result<Option<ReceiptNote>, String> {
        match (&self.receipt, &self.receipt_bundle) {
            (Some(r), b) => receipt::load(r, b.as_deref(), f).map(Some),
            (None, Some(_)) => Err("--receipt-bundle requires --receipt".into()),
            (None, None) => Ok(None),
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
    pub receipt: Option<&'a ReceiptNote>,
}

/// A character that renders as nothing (or as blank space) and can hide or
/// reorder text: every code point of Unicode general categories Cf (format),
/// Zl and Zp, plus the fillers and selectors that display empty (U+00AD,
/// U+034F, U+115F, U+1160, U+3164, U+FFA0, U+180E, variation selectors
/// U+FE00–FE0F and U+E0100–E01EF) and the tag block U+E0000–E007F.
/// Explicit ranges (Unicode 15.1), so no Unicode-table dependency.
pub(crate) fn is_invisible(c: char) -> bool {
    matches!(
        c as u32,
        // Cf
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            // Zl, Zp
            | 0x2028
            | 0x2029
            // Fillers, grapheme joiner, variation selectors
            | 0x034F
            | 0x115F
            | 0x1160
            | 0x3164
            | 0xFFA0
            | 0xFE00..=0xFE0F
            | 0xE0100..=0xE01EF
            // Tags (Cf: U+E0001, U+E0020–E007F; the rest of the block too)
            | 0xE0000..=0xE007F
    )
}

/// Show invisible characters ([`is_invisible`]: bidi overrides/isolates,
/// zero-width and other format characters, line/paragraph separators,
/// fillers, variation selectors, tags) as `[U+XXXX]`. Titles and paths in a
/// draft come from the audited code; an invisible U+202E would make the
/// maintainer read a different file name than the one meant ("Trojan
/// Source") in a message that is copied and sent verbatim.
pub(crate) fn show_invisible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_invisible(c) {
            out.push_str(&format!("[U+{:04X}]", c as u32));
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

/// ASCII `-` and the characters that look like it. The list cannot be
/// complete, so [`defang_markers`] also defangs the marker phrases.
fn is_dash_like(c: char) -> bool {
    matches!(
        c,
        '-' | '\u{02D7}'
            | '\u{207B}'
            | '\u{208B}'
            | '\u{2010}'..='\u{2015}'
            | '\u{2043}'
            | '\u{2212}'
            | '\u{23AF}'
            | '\u{2500}'
            | '\u{2501}'
            | '\u{2574}'..='\u{257F}'
            | '\u{2796}'
            | '\u{2E3A}'
            | '\u{2E3B}'
            | '\u{30FC}'
            | '\u{4E00}'
            | '\u{FE31}'
            | '\u{FE32}'
            | '\u{FE58}'
            | '\u{FE63}'
            | '\u{FF0D}'
            // Armenian hyphen, Hebrew maqaf, Ogham space mark.
            | '\u{058A}'
            | '\u{05BE}'
            | '\u{1680}'
            // Hangul EU (compatibility jamo and jungseong).
            | '\u{1173}'
            | '\u{3161}'
            // Kangxi radical one, straightness symbol.
            | '\u{2F00}'
            | '\u{23E4}'
            // Dashed box-drawing lines.
            | '\u{2504}'
            | '\u{2505}'
            | '\u{2508}'
            | '\u{2509}'
            | '\u{254C}'
            | '\u{254D}'
    )
}

/// The words shared by the start and end markers of the reviewer-notes
/// block ([`NOTES_START_EN`]/[`NOTES_END_EN`]: "REVIEWER NOTES";
/// [`NOTES_START_ZH`]/[`NOTES_END_ZH`]: "審閱備註").
const MARKER_PHRASES: &[&[&str]] = &[&["REVIEWER", "NOTES"], &["審閱備註"]];

/// Characters skipped between two letters of a marker phrase: whitespace,
/// punctuation and invisible characters (anything not alphanumeric), at
/// most this many in a row and never a line break.
const MARKER_PHRASE_MAX_GAP: usize = 8;

/// The Latin letter a mathematical alphanumeric symbol is styled from
/// (bold, italic, script, fraktur, double-struck, sans-serif, monospace
/// and their combinations), or the Greek letter for the mathematical Greek
/// blocks, which [`marker_letter`] then folds like plain Greek.
fn math_alphanumeric_base(c: char) -> Option<char> {
    let cp = c as u32;
    match cp {
        // 13 styles of A-Z then a-z. The holes are reserved (unassigned)
        // code points whose letters live in Letterlike Symbols; they are
        // mapped here too, so `marker_letter` must not call this for a
        // non-alphanumeric character.
        0x1D400..=0x1D6A3 => {
            let i = ((cp - 0x1D400) % 52) as u8;
            Some(if i < 26 {
                char::from(b'A' + i)
            } else {
                char::from(b'a' + i - 26)
            })
        }
        // Mathematical italic dotless i.
        0x1D6A4 => Some('\u{0131}'),
        // 5 styles of 58 Greek symbols: 25 capitals (U+0391..), nabla,
        // 25 small letters (U+03B1..), then symbol variants.
        0x1D6A8..=0x1D7C9 => {
            let i = (cp - 0x1D6A8) % 58;
            match i {
                0..=24 => char::from_u32(0x0391 + i),
                26..=50 => char::from_u32(0x03B1 + i - 26),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The marker letter `c` reads as: ASCII letters uppercased, fullwidth
/// and mathematical Latin letters as ASCII, the lookalikes below as the
/// Latin letter of "REVIEWER NOTES" they imitate, and variant or
/// simplified forms of 審閱備註 as the traditional character. Any other
/// character is returned as is.
///
/// This confusables table is kept in one place and cannot be complete
/// (Unicode has more lookalikes, and fonts differ), so it only narrows the
/// gap: the dash-run defanging in [`defang_markers`] does not depend on it.
/// Every entry must be alphanumeric, because the phrase matcher treats
/// non-alphanumeric characters as gaps. A non-alphanumeric `c` is returned
/// as is before any mapping: the reserved holes of the mathematical
/// alphanumeric block (unassigned, so not alphanumeric) would otherwise
/// fold to a Latin letter.
fn marker_letter(c: char) -> char {
    if !c.is_alphanumeric() {
        return c;
    }
    let c = match c {
        '\u{FF21}'..='\u{FF3A}' | '\u{FF41}'..='\u{FF5A}' => {
            char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
        }
        _ => math_alphanumeric_base(c).unwrap_or(c),
    };
    // Lowercase L reads as a capital I in many fonts.
    let c = if c == 'l' {
        'I'
    } else {
        c.to_ascii_uppercase()
    };
    match c {
        // Small capital, Cherokee E/SV, Lisu ZHA, script/fraktur/
        // double-struck R.
        '\u{0280}' | '\u{13A1}' | '\u{13D2}' | '\u{A4E3}' | '\u{211B}' | '\u{211C}'
        | '\u{211D}' => 'R',
        // Cyrillic Е е, Greek Ε ε, small capital, Cherokee, Lisu, script.
        '\u{0415}' | '\u{0435}' | '\u{0395}' | '\u{03B5}' | '\u{1D07}' | '\u{13AC}'
        | '\u{A4F0}' | '\u{2130}' | '\u{212F}' => 'E',
        // Cyrillic izhitsa, Greek nu, small capital, Roman numeral five,
        // Cherokee, Lisu.
        '\u{0474}' | '\u{0475}' | '\u{03BD}' | '\u{1D20}' | '\u{2164}' | '\u{2174}'
        | '\u{13D9}' | '\u{A4E6}' => 'V',
        // Cyrillic І і Ӏ ӏ, Greek Ι ι, Roman numeral one, small capital,
        // dotless i, script/fraktur I, dental click, Lisu, Coptic.
        '\u{0406}' | '\u{0456}' | '\u{04C0}' | '\u{04CF}' | '\u{0399}' | '\u{03B9}'
        | '\u{2160}' | '\u{2170}' | '\u{026A}' | '\u{0131}' | '\u{2110}' | '\u{2111}'
        | '\u{01C0}' | '\u{A4F2}' | '\u{2C92}' => 'I',
        // Cyrillic Ԝ ԝ ѡ, small capital, Cherokee LA/TA, Lisu.
        '\u{051C}' | '\u{051D}' | '\u{0461}' | '\u{1D21}' | '\u{13B3}' | '\u{13D4}'
        | '\u{A4EA}' => 'W',
        // Greek Ν, small capital, Lisu, double-struck, Coptic.
        '\u{039D}' | '\u{0274}' | '\u{A4E0}' | '\u{2115}' | '\u{2C9A}' => 'N',
        // Cyrillic О о, Greek Ο ο, small capital, Armenian oh, Coptic,
        // Lisu, script o, ideographic zero.
        '\u{041E}' | '\u{043E}' | '\u{039F}' | '\u{03BF}' | '\u{1D0F}' | '\u{0585}'
        | '\u{2C9E}' | '\u{2C9F}' | '\u{A4F3}' | '\u{2134}' | '\u{3007}' => 'O',
        // Cyrillic Т т, Greek Τ τ, small capital, Cherokee, Lisu, Coptic.
        '\u{0422}' | '\u{0442}' | '\u{03A4}' | '\u{03C4}' | '\u{1D1B}' | '\u{13A2}'
        | '\u{A4D4}' | '\u{2CA6}' | '\u{2CA7}' => 'T',
        // Cyrillic Ѕ ѕ, Cherokee DE/SU, Lisu, small capital.
        '\u{0405}' | '\u{0455}' | '\u{13D5}' | '\u{13DA}' | '\u{A4E2}' | '\u{A731}' => 'S',
        // Simplified and variant forms of 審閱備註.
        '审' => '審',
        '阅' | '\u{95B2}' => '閱',
        '备' | '\u{4FFB}' => '備',
        '注' => '註',
        _ => c,
    }
}

/// `c` reads as the marker letter `expected` (see [`marker_letter`]).
fn marker_char_matches(expected: char, c: char) -> bool {
    marker_letter(c) == marker_letter(expected)
}

/// The end (exclusive) of a marker phrase starting at `chars[start]`, with
/// the index of each matched letter, in phrase order, written to `letters`
/// (cleared first; its contents are unspecified when `None` is returned).
/// A gap longer than [`MARKER_PHRASE_MAX_GAP`] or containing a line break
/// ends the match; the gap scan reads at most `MARKER_PHRASE_MAX_GAP + 1`
/// characters, so each start position costs O(phrase length × gap).
fn marker_phrase_end(
    chars: &[char],
    start: usize,
    words: &[&str],
    letters: &mut Vec<usize>,
) -> Option<usize> {
    letters.clear();
    let mut k = start;
    let mut first = true;
    for expected in words.iter().flat_map(|word| word.chars()) {
        if !first {
            let mut gap = 0;
            for &c in chars[k..].iter().take(MARKER_PHRASE_MAX_GAP + 1) {
                if c.is_alphanumeric() {
                    break;
                }
                if c == '\n' || c == '\r' {
                    return None;
                }
                gap += 1;
            }
            if gap > MARKER_PHRASE_MAX_GAP {
                return None;
            }
            k += gap;
        }
        first = false;
        if !marker_char_matches(expected, *chars.get(k)?) {
            return None;
        }
        letters.push(k);
        k += 1;
    }
    Some(k)
}

/// Space out every occurrence of a marker phrase (`R E V I E W E R  N O T E S`,
/// `審 閱 備 註`), keeping its letters as written and dropping the gap
/// characters between them. The letters emitted are exactly those
/// [`marker_phrase_end`] matched, so the output cannot drift from the match.
fn defang_marker_phrases(chars: &[char]) -> Vec<char> {
    let mut out = Vec::with_capacity(chars.len());
    let mut letters = Vec::new();
    let mut i = 0;
    'outer: while i < chars.len() {
        for words in MARKER_PHRASES {
            let Some(end) = marker_phrase_end(chars, i, words, &mut letters) else {
                continue;
            };
            let mut matched = letters.iter();
            for (w, word) in words.iter().enumerate() {
                for l in 0..word.chars().count() {
                    let Some(&k) = matched.next() else {
                        break;
                    };
                    if w > 0 && l == 0 {
                        out.extend([' ', ' ']);
                    } else if l > 0 {
                        out.push(' ');
                    }
                    out.push(chars[k]);
                }
            }
            i = end;
            continue 'outer;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// External text (policy lines, commit messages, issue titles) must not be
/// able to fake the start or end of the reviewer-notes block: the marker
/// phrases are spaced out (see [`defang_marker_phrases`]), and any run of 5
/// or more dash-like characters (soft hyphens U+00AD allowed between them)
/// is spaced out (`- - - - -`), its soft hyphens dropped.
pub(crate) fn defang_markers(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let chars = defang_marker_phrases(&chars);
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if !is_dash_like(chars[i]) {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        // The run starts and ends on a dash; soft hyphens inside it do not
        // count and do not break it.
        let mut dashes = 0;
        let mut end = i;
        let mut j = i;
        while j < chars.len() && (is_dash_like(chars[j]) || chars[j] == '\u{AD}') {
            if is_dash_like(chars[j]) {
                dashes += 1;
                end = j + 1;
            }
            j += 1;
        }
        if dashes >= 5 {
            let mut first = true;
            for &c in chars[i..end].iter().filter(|&&c| c != '\u{AD}') {
                if !first {
                    out.push(' ');
                }
                out.push(c);
                first = false;
            }
        } else {
            out.extend(&chars[i..end]);
        }
        i = end;
    }
    out
}

fn unproven_banner(e: &Eligibility, zh: bool) -> String {
    let no_control = e.level == EvidenceLevel::PocEffectNoControl;
    if zh {
        let why = if no_control {
            "PoC 缺少通過的對照或全新容器重跑"
        } else {
            "沒有由執行框架判定的 PoC"
        };
        format!(
            "!!! 未證實（UNPROVEN）：證據等級 {}，{why}。只因 --allow-unproven 才產生；不可當成已確認漏洞送出。 !!!",
            e.level.key()
        )
    } else {
        let why = if no_control {
            "the PoC lacked a passing control or fresh re-run"
        } else {
            "no harness-judged PoC"
        };
        format!(
            "!!! UNPROVEN: evidence level {}, {why}. Drafted only because of --allow-unproven; do not present this as a confirmed vulnerability. !!!",
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
    scope: &'a ScopeCheck,
    warnings: &'a [String],
}

/// The scope-hint lines of the reviewer notes (data from the target's own
/// files, quoted; never acted on).
fn scope_notes(s: &ScopeCheck, zh: bool) -> Vec<String> {
    let mut out = Vec::new();
    if s.checked_files.is_empty() {
        out.push(if zh {
            "範圍提示：未找到 SECURITY.md／THREAT_MODEL.md 等範圍文件；請自行核對維護者的範圍規定。"
                .to_string()
        } else {
            "Scope hint: no SECURITY.md / THREAT_MODEL.md style scope file found; check the maintainers' scope rules yourself."
                .to_string()
        });
        return out;
    }
    let files = s.checked_files.join(", ");
    out.push(match (s.possibly_out_of_scope, zh) {
        (true, true) => format!(
            "範圍提示（僅供參考，不影響草稿）：可能在範圍外。已讀取：{files}。以下為符合的「範圍外」原文（當資料引用，Vettalon 未依其行動）："
        ),
        (true, false) => format!(
            "Scope hint (reference only; the draft is unchanged): possibly out of scope. Files read: {files}. Matching out-of-scope lines, quoted as data (Vettalon did not act on them):"
        ),
        (false, true) => format!(
            "範圍提示（僅供參考，不影響草稿）：未發現符合的「範圍外」敘述。已讀取：{files}。這不代表在範圍內。"
        ),
        (false, false) => format!(
            "Scope hint (reference only; the draft is unchanged): no matching out-of-scope statement found. Files read: {files}. This does not mean it is in scope."
        ),
    });
    for m in &s.matched {
        out.push(format!("- {}:{}: {}", m.file, m.line_no, m.text));
    }
    out
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
    for line in scope_notes(n.scope, zh) {
        out.push(defang_markers(&line));
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
    let receipt = opts.load_receipt(f)?;
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
        receipt: receipt.as_ref(),
    };
    // The template text is capped inside `render` (counted after invisible
    // characters are made visible, so the count is of what the maintainer
    // reads): only the analysis, trace and PoC transcript are shortened; the
    // AI use statement, reviewer line and disclosure section stay whole.
    let rendered = formats::render(template, f, &project, &disclose_by, &ctx);
    let template_text = show_invisible(&rendered.body);
    let mut checklist = checklist();
    if !rendered.truncated.is_empty() {
        let sections = rendered
            .truncated
            .iter()
            .map(|s| s.name(false))
            .collect::<Vec<_>>()
            .join(", ");
        warnings.push(format!(
            "The draft text was truncated to fit {} characters: shortened {sections} (each marked with a notice). The AI use statement, reviewer line and disclosure section were kept whole. Restore what matters from the full finding before sending.",
            formats::MAX_BODY_CHARS
        ));
        checklist.push(
            crate::lang::pick(
                "草稿文字超過 8,000 字元，部分段落（技術描述、追蹤步驟或 PoC 執行紀錄）已縮短並標示；送出前請對照完整 finding 確認縮短的內容",
                "The draft text exceeded 8,000 characters and some sections (analysis, trace or PoC transcript) were shortened and marked; check them against the full finding before sending",
            )
            .to_string(),
        );
    }
    if rendered.over_limit {
        warnings.push(format!(
            "The draft text is still over {} characters after shortening the analysis, trace and PoC transcript; the rest is fixed text and was not cut. Shorten it by hand before sending.",
            formats::MAX_BODY_CHARS
        ));
    }
    let scope_check = scope::check(&project.scope_docs, f);
    let notes = reviewer_notes(
        &Notes {
            eligibility: &eligibility,
            severity: &severity,
            dedupe: &extras.dedupe,
            meta: &project,
            dependency: dependency.as_ref(),
            scope: &scope_check,
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
    let body = format!("{head}\n\n{notes}\n\n{template_text}");
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
        checklist,
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
        scope_check,
        receipt,
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
    // A bad receipt is refused before any network use as well.
    opts.load_receipt(f)?;
    let mut project = detect_project(Path::new(&report.repo));
    // The commit the scan recorded beats whatever HEAD is now.
    if let Some(c) = report
        .repo_commit
        .as_deref()
        .map(str::trim)
        .filter(|c| (7..=64).contains(&c.len()) && c.chars().all(|ch| ch.is_ascii_hexdigit()))
    {
        project.commit = Some(c.to_string());
    }
    let today = chrono::Local::now().date_naive();
    let cwe = finding_cwe(f);
    let dedupe = match dedupe_src {
        Some(src) => dedupe::check(src, &project, &f.file, cwe.as_deref(), today).await,
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
