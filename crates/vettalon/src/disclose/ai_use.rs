//! The fixed "AI use statement" every draft carries, and the human reviewer
//! it names.
//!
//! Projects that accept AI-assisted reports ask the reporter to say which
//! tool was used, for what, and which human verified the result. The
//! statement is built from what the report records (finder, verifier and PoC
//! models), never from model output, and a draft without a reviewer
//! pseudonym is refused. The pseudonym is public: it appears in the draft.

use serde::Serialize;

use crate::audit::schema::{EvidenceKind, Finding, ModelInfo};

const REVIEWER_MAX_CHARS: usize = 64;

/// The human who reviewed the draft. Public on the draft by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reviewer {
    pub pseudonym: String,
    /// ISO 8601 date of the human review.
    pub review_date: String,
}

impl Reviewer {
    /// Resolve the reviewer from the CLI/request value, else the config.
    /// `review_date` defaults to `today` and may not be in the future.
    pub fn resolve(
        flag: Option<&str>,
        config: Option<&str>,
        review_date: Option<&str>,
        today: chrono::NaiveDate,
    ) -> Result<Reviewer, String> {
        let raw = flag
            .filter(|s| !s.trim().is_empty())
            .or(config.filter(|s| !s.trim().is_empty()))
            .ok_or_else(|| {
                crate::tr!(
                    "拒絕產生草稿：缺少人工審閱者化名。請用 --reviewer <化名>，或在設定檔 [disclosure] reviewer 設定。化名會公開出現在草稿的 AI 使用聲明中。",
                    "draft refused: no human reviewer pseudonym. Pass --reviewer <pseudonym> or set [disclosure] reviewer in the config. The pseudonym is shown publicly in the draft's AI use statement."
                )
            })?;
        let pseudonym = validate_pseudonym(raw)?;
        let date = match review_date.map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
                crate::tr!(
                    "審閱日期須為 YYYY-MM-DD：{s:?}",
                    "review date must be YYYY-MM-DD: {s:?}"
                )
            })?,
            None => today,
        };
        if date > today {
            return Err(crate::tr!(
                "審閱日期 {date} 晚於今天，不接受未來日期。",
                "review date {date} is in the future."
            ));
        }
        Ok(Reviewer {
            pseudonym,
            review_date: date.to_string(),
        })
    }
}

/// Non-empty, bounded, printable. Invisible or control characters would let
/// a pseudonym read differently from what is stored.
pub fn validate_pseudonym(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    let bad = s.chars().any(|c| {
        c.is_control()
            || matches!(c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF)
    });
    if s.is_empty() || bad || s.chars().count() > REVIEWER_MAX_CHARS {
        return Err(crate::tr!(
            "審閱者化名須為 1–{REVIEWER_MAX_CHARS} 個可見字元，不可含控制或隱形字元。",
            "the reviewer pseudonym must be 1-{REVIEWER_MAX_CHARS} visible characters, without control or invisible characters."
        ));
    }
    Ok(s.to_string())
}

/// What the draft states about AI use. Every field comes from the report.
#[derive(Debug, Clone, Serialize)]
pub struct AiUseStatement {
    pub tool: String,
    /// Models that proposed the finding (`id (family)`), or the scanner.
    pub finding: Vec<String>,
    pub verification: Vec<String>,
    pub poc: Vec<String>,
    /// How the draft text itself was produced.
    pub wording: String,
    pub reviewer: Reviewer,
    /// True only when the report records a human confirmation (operator
    /// review). Otherwise the statement leaves reproduction for the reviewer
    /// to state, instead of asserting it on their behalf.
    pub human_confirmed: bool,
}

fn with_family(id: &str, roster: &[ModelInfo]) -> String {
    match roster.iter().find(|m| m.id == id) {
        Some(m) if !m.family.is_empty() => format!("{id} ({})", m.family),
        _ => format!("{id} (family not recorded)"),
    }
}

fn push_unique(out: &mut Vec<String>, s: String) {
    if !out.contains(&s) {
        out.push(s);
    }
}

impl AiUseStatement {
    pub fn build(
        f: &Finding,
        roster: &[ModelInfo],
        reviewer: Reviewer,
        human_confirmed: bool,
    ) -> AiUseStatement {
        let mut finding = Vec::new();
        for id in &f.found_by {
            push_unique(&mut finding, with_family(id, roster));
        }
        if finding.is_empty() {
            finding.push(format!("{} (no model recorded)", f.source_engine));
        }
        let mut verification = Vec::new();
        for v in &f.verification {
            let fam = if v.family.is_empty() {
                "family not recorded"
            } else {
                v.family.as_str()
            };
            push_unique(&mut verification, format!("{} ({fam})", v.model));
        }
        let poc_attempted = f.evidence.iter().any(|e| {
            matches!(
                e.kind,
                EvidenceKind::PocTranscript | EvidenceKind::PocSkipped
            )
        });
        let mut poc = Vec::new();
        if poc_attempted {
            for m in roster.iter().filter(|m| m.roles.iter().any(|r| r == "poc")) {
                push_unique(&mut poc, with_family(&m.id, roster));
            }
            if poc.is_empty() {
                poc.push("PoC attempted; generating model not recorded".into());
            }
        }
        AiUseStatement {
            tool: format!("Vettalon {}", env!("CARGO_PKG_VERSION")),
            finding,
            verification,
            poc,
            wording: "fixed template filled by Vettalon from the report; the description and impact text quote the finding model's analysis and must be checked and rewritten by the human reviewer".into(),
            reviewer,
            human_confirmed,
        }
    }

    fn list(items: &[String], none: &str) -> String {
        if items.is_empty() {
            none.to_string()
        } else {
            items.join(", ")
        }
    }

    /// English section text (plain lines; callers add their own heading).
    pub fn render_en(&self) -> String {
        format!(
            "Tool: {tool} (multi-model security audit).\n\
Models and what they were used for:\n\
- finding the issue: {finding}\n\
- verification (adversarial review): {verification}\n\
- PoC generation: {poc}\n\
- report wording: {wording}\n\
Human review: {who} reviewed this report on {date}. {repro}",
            tool = self.tool,
            finding = Self::list(&self.finding, "none"),
            verification = Self::list(&self.verification, "none"),
            poc = Self::list(&self.poc, "not used"),
            wording = self.wording,
            who = self.reviewer.pseudonym,
            date = self.reviewer.review_date,
            repro = if self.human_confirmed {
                "A human confirmed the finding (operator review recorded) and reviewed every statement in this report."
            } else {
                "[Reviewer: state how you reproduced the issue before sending; do not send if you have not reproduced it.]"
            },
        )
    }

    /// zh-TW section text, for the TWCERT/CC and HITCON ZeroDay forms.
    pub fn render_zh(&self) -> String {
        format!(
            "工具：{tool}（多模型安全審查）。\n\
使用的模型與用途：\n\
- 發現問題：{finding}\n\
- 覆核（對抗式審查）：{verification}\n\
- 產生 PoC：{poc}\n\
- 報告文字：{wording}\n\
人工審閱：{who} 於 {date} 審閱本報告。{repro}",
            tool = self.tool,
            finding = Self::list(&self.finding, "無"),
            verification = Self::list(&self.verification, "無"),
            poc = Self::list(&self.poc, "未使用"),
            wording = "由 Vettalon 以固定範本依報告內容填寫；技術描述與影響引用發現模型的分析，須由人工審閱者核對並改寫",
            who = self.reviewer.pseudonym,
            date = self.reviewer.review_date,
            repro = if self.human_confirmed {
                "已有人工確認紀錄（操作者覆核），並逐項核對本報告內容。"
            } else {
                "【審閱者：請說明你如何重現此問題；尚未重現請勿送出。】"
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{EvidenceItem, FindingKind, Severity, VerifierVote, VoteVerdict};

    fn today() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 20).unwrap()
    }

    #[test]
    fn no_reviewer_refuses() {
        let err = Reviewer::resolve(None, None, None, today()).unwrap_err();
        assert!(err.contains("--reviewer"), "{err}");
        assert!(Reviewer::resolve(Some("  "), Some(""), None, today()).is_err());
    }

    #[test]
    fn flag_wins_over_config_and_date_defaults_to_today() {
        let r = Reviewer::resolve(Some("night-owl"), Some("cfg"), None, today()).unwrap();
        assert_eq!(r.pseudonym, "night-owl");
        assert_eq!(r.review_date, "2026-10-20");
        let r = Reviewer::resolve(None, Some("cfg"), Some("2026-10-18"), today()).unwrap();
        assert_eq!(
            (r.pseudonym.as_str(), r.review_date.as_str()),
            ("cfg", "2026-10-18")
        );
    }

    #[test]
    fn rejects_bad_pseudonyms_and_dates() {
        for bad in ["a\u{202E}b", "x\ny", &"z".repeat(65)] {
            assert!(
                Reviewer::resolve(Some(bad), None, None, today()).is_err(),
                "{bad:?}"
            );
        }
        assert!(Reviewer::resolve(Some("ok"), None, Some("2026-10-21"), today()).is_err());
        assert!(Reviewer::resolve(Some("ok"), None, Some("20/10/2026"), today()).is_err());
    }

    #[test]
    fn statement_lists_models_by_use_and_the_reviewer() {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "t",
            "a.rs",
            Some(1),
            "s",
            "ai-audit/x",
            vec![EvidenceItem {
                kind: EvidenceKind::PocTranscript,
                source: "poc".into(),
                detail: "ran".into(),
                recorded_at: "2026-10-20T00:00:00Z".into(),
            }],
        );
        f.found_by = vec!["claude".into()];
        f.verification = vec![VerifierVote {
            model: "codex".into(),
            family: "openai".into(),
            verdict: VoteVerdict::Plausible,
            cross_family: true,
            same_model: false,
        }];
        let roster = vec![
            ModelInfo {
                id: "claude".into(),
                family: "anthropic".into(),
                roles: vec!["finder".into(), "poc".into()],
            },
            ModelInfo {
                id: "codex".into(),
                family: "openai".into(),
                roles: vec!["verifier".into()],
            },
        ];
        let reviewer = Reviewer::resolve(Some("night-owl"), None, None, today()).unwrap();
        let s = AiUseStatement::build(&f, &roster, reviewer.clone(), true);
        let en = s.render_en();
        for needle in [
            "Vettalon ",
            "finding the issue: claude (anthropic)",
            "verification (adversarial review): codex (openai)",
            "PoC generation: claude (anthropic)",
            "must be checked and rewritten by the human reviewer",
            "night-owl reviewed this report on 2026-10-20",
            "A human confirmed the finding (operator review recorded)",
        ] {
            assert!(en.contains(needle), "missing {needle:?} in {en}");
        }
        assert!(s.render_zh().contains("night-owl 於 2026-10-20"));
        // Without a recorded human confirmation nothing is asserted for the
        // reviewer; they must state the reproduction themselves.
        let unconfirmed = AiUseStatement::build(&f, &roster, reviewer, false).render_en();
        assert!(!unconfirmed.contains("A human confirmed"));
        assert!(unconfirmed.contains("state how you reproduced"));
    }
}
