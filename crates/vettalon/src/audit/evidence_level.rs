//! Derived evidence level, proof gaps and strongest counter-evidence.
//!
//! All three are computed from a finding's recorded evidence chain every time
//! they are read or written. They are never an input: a model reply cannot
//! set them, and a value stored in a report file is ignored on read (see the
//! `Serialize` impl on [`Finding`]). An old report that predates the inputs
//! derives honestly from what it does carry and is never upgraded.
//!
//! Derivation table (first matching row wins, then the caps apply):
//!
//! | level | requires |
//! |---|---|
//! | `maintainer_confirmed` | status `confirmed` with operator provenance (an `operator_review` decision or `severity_basis = operator`) — human only |
//! | `poc_differential` | a valid `poc_oracle` item: effect, nonce bound, not rejected, `control=false`, `rerun=true` |
//! | `poc_effect_no_control` | a valid `poc_oracle` item with a nonce-bound effect, not rejected, `control` not `true`, but no passing control or no fresh re-run |
//! | `refuter_consistent` | `plausible:` verdict plus `refuter_consistent: n/n` with n ≥ 3 |
//! | `refuter_survived` | an `adversarial_review` `plausible:` verdict |
//! | `static_only` | anything else (scanner hit, AI analysis only, refuted, unverified) |
//!
//! Caps: any `verify_error:` evidence → at most `static_only`; any
//! `verify_uncertain` evidence → at most `refuter_survived`. A sandbox
//! transcript (`poc_transcript`, pattern demo) never raises the level: only
//! the harness-judged `poc_oracle` format does. Operator confirmation is a
//! human decision and is not capped.

use serde::{Deserialize, Serialize};

use super::schema::{
    EvidenceKind, Finding, FindingStatus, PLAUSIBLE_PREFIX, PRECHECK_PREFIX, SeverityBasis,
};

/// Evidence `detail` prefix for a verification attempt that produced no
/// usable verdict (the finding stays `Candidate`).
pub const VERIFY_ERROR_PREFIX: &str = "verify_error:";
/// Evidence `detail` prefix of an [`EvidenceKind::VerifyUncertain`] item.
pub const VERIFY_UNCERTAIN_PREFIX: &str = "verify_uncertain:";
/// Evidence `detail` prefix recorded when every repeated refuter run
/// answered `plausible` (`refuter_consistent: 3/3`).
pub const REFUTER_CONSISTENT_PREFIX: &str = "refuter_consistent:";
/// Evidence `detail` prefix of an [`EvidenceKind::PocOracle`] item.
pub const POC_ORACLE_PREFIX: &str = "poc_oracle:";
/// Fewest unanimous refuter runs that count as `refuter_consistent`.
pub const MIN_CONSISTENT_RUNS: u32 = 3;
/// Cap on `strongest_counterevidence`.
pub const COUNTEREVIDENCE_MAX_BYTES: usize = 300;
/// Cap on a `poc_oracle` rejection reason token.
const REJECT_REASON_MAX_BYTES: usize = 64;

/// How strong the recorded evidence for a finding is, ordered low → high.
/// Derived only (see the module docs); never a model's self-assessment.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// Only scanner / AI-analysis evidence.
    #[default]
    StaticOnly,
    /// One refuter run judged the claim plausible.
    RefuterSurvived,
    /// Every one of n ≥ 3 independent refuter runs judged it plausible.
    RefuterConsistent,
    /// A harness-judged effect was observed, without a passing control run
    /// or without a fresh re-run.
    PocEffectNoControl,
    /// Harness-judged effect on the target, none on the control, reproduced
    /// in a fresh container.
    PocDifferential,
    /// An operator (maintainer) confirmed it. Human only.
    MaintainerConfirmed,
}

impl EvidenceLevel {
    pub const ALL: [EvidenceLevel; 6] = [
        Self::StaticOnly,
        Self::RefuterSurvived,
        Self::RefuterConsistent,
        Self::PocEffectNoControl,
        Self::PocDifferential,
        Self::MaintainerConfirmed,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::StaticOnly => "static_only",
            Self::RefuterSurvived => "refuter_survived",
            Self::RefuterConsistent => "refuter_consistent",
            Self::PocEffectNoControl => "poc_effect_no_control",
            Self::PocDifferential => "poc_differential",
            Self::MaintainerConfirmed => "maintainer_confirmed",
        }
    }

    pub fn label_zh(self) -> &'static str {
        match self {
            Self::StaticOnly => "僅靜態／模型分析",
            Self::RefuterSurvived => "通過一次反駁覆核",
            Self::RefuterConsistent => "多次反駁覆核一致成立",
            Self::PocEffectNoControl => "PoC 觀察到效果（缺對照或重跑）",
            Self::PocDifferential => "PoC 差分驗證（含對照與重跑）",
            Self::MaintainerConfirmed => "人工確認",
        }
    }
}

/// What a finding still lacks before it is proven. Derived only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofGap {
    /// No refuter verdict was recorded.
    NoRefuter,
    /// Repeated refuter runs disagreed (`verify_uncertain`).
    RefuterInconsistent,
    /// No PoC was executed.
    NoPoc,
    /// A PoC ran, but no harness-judged effect was recorded.
    PocNotHarnessJudged,
    /// No control run without the effect.
    NoControl,
    /// No reproduction in a fresh container.
    NoFreshRerun,
    /// No executed evidence that the target code path is reached.
    ReachabilityUnknown,
    /// No operator / maintainer confirmation.
    NoMaintainerConfirmation,
}

impl ProofGap {
    pub fn key(self) -> &'static str {
        match self {
            Self::NoRefuter => "no_refuter",
            Self::RefuterInconsistent => "refuter_inconsistent",
            Self::NoPoc => "no_poc",
            Self::PocNotHarnessJudged => "poc_not_harness_judged",
            Self::NoControl => "no_control",
            Self::NoFreshRerun => "no_fresh_rerun",
            Self::ReachabilityUnknown => "reachability_unknown",
            Self::NoMaintainerConfirmation => "no_maintainer_confirmation",
        }
    }

    pub fn label_zh(self) -> &'static str {
        match self {
            Self::NoRefuter => "未經反駁覆核",
            Self::RefuterInconsistent => "多次覆核結論不一致",
            Self::NoPoc => "未執行 PoC",
            Self::PocNotHarnessJudged => "PoC 效果未經 harness 判定",
            Self::NoControl => "缺對照組驗證",
            Self::NoFreshRerun => "未在全新容器重跑",
            Self::ReachabilityUnknown => "可達性未經執行證實",
            Self::NoMaintainerConfirmation => "未經人工確認",
        }
    }
}

/// A parsed `poc_oracle` evidence detail. The format is fixed and strict:
/// exactly `poc_oracle: effect=<b> control=<t> rerun=<t> nonce_bound=<b>
/// rejected=<reason|none>` (single spaces, this key order, `<b>` =
/// `true|false`, `<t>` = `true|false|none`, `<reason>` = 1–64 chars of
/// `[a-z0-9_-]`). Anything else parses to `None` and is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocOracle {
    /// The harness observed the effect on the target.
    pub effect: bool,
    /// Effect observed on the control: `Some(false)` is a passing control,
    /// `Some(true)` a failed one, `None` no control run.
    pub control: Option<bool>,
    /// Fresh-container re-run reproduced the effect; `None` = not re-run.
    pub rerun: Option<bool>,
    /// The effect carried the harness's one-time nonce / canary.
    pub nonce_bound: bool,
    /// Anti-cheat rejection reason; `None` when the PoC was accepted.
    pub rejected: Option<String>,
}

impl PocOracle {
    pub fn parse(detail: &str) -> Option<Self> {
        let rest = detail.strip_prefix(POC_ORACLE_PREFIX)?.strip_prefix(' ')?;
        let parts: Vec<&str> = rest.split(' ').collect();
        let [effect, control, rerun, nonce_bound, rejected] = parts.as_slice() else {
            return None;
        };
        let value = |part: &str, key: &str| -> Option<String> {
            part.strip_prefix(key)?
                .strip_prefix('=')
                .map(str::to_string)
        };
        let boolean = |v: String| match v.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
        let tri = |v: String| match v.as_str() {
            "true" => Some(Some(true)),
            "false" => Some(Some(false)),
            "none" => Some(None),
            _ => None,
        };
        let rejected = match value(rejected, "rejected")? {
            v if v == "none" => None,
            v if !v.is_empty()
                && v.len() <= REJECT_REASON_MAX_BYTES
                && v.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                }) =>
            {
                Some(v)
            }
            _ => return None,
        };
        Some(PocOracle {
            effect: boolean(value(effect, "effect")?)?,
            control: tri(value(control, "control")?)?,
            rerun: tri(value(rerun, "rerun")?)?,
            nonce_bound: boolean(value(nonce_bound, "nonce_bound")?)?,
            rejected,
        })
    }

    /// The canonical detail string (what a producer must write).
    pub fn to_detail(&self) -> String {
        let tri = |v: Option<bool>| match v {
            Some(true) => "true",
            Some(false) => "false",
            None => "none",
        };
        format!(
            "{POC_ORACLE_PREFIX} effect={} control={} rerun={} nonce_bound={} rejected={}",
            self.effect,
            tri(self.control),
            tri(self.rerun),
            self.nonce_bound,
            self.rejected.as_deref().unwrap_or("none"),
        )
    }

    /// An accepted, nonce-bound effect on the target (control not yet judged).
    pub fn has_harness_effect(&self) -> bool {
        self.effect && self.nonce_bound && self.rejected.is_none()
    }

    /// The level this oracle result supports on its own. A failed control
    /// (`control=true`) means the effect is not specific to the defect, so it
    /// supports nothing.
    pub fn level(&self) -> Option<EvidenceLevel> {
        if !self.has_harness_effect() || self.control == Some(true) {
            return None;
        }
        if self.control == Some(false) && self.rerun == Some(true) {
            Some(EvidenceLevel::PocDifferential)
        } else {
            Some(EvidenceLevel::PocEffectNoControl)
        }
    }
}

/// Parse `refuter_consistent: <k>/<n>` and return `n` when k == n ≥ 3.
fn consistent_runs(detail: &str) -> Option<u32> {
    let rest = detail.strip_prefix(REFUTER_CONSISTENT_PREFIX)?.trim();
    let (k, n) = rest.split_once('/')?;
    let (k, n) = (k.parse::<u32>().ok()?, n.parse::<u32>().ok()?);
    (k == n && n >= MIN_CONSISTENT_RUNS).then_some(n)
}

/// The operator decision word of an `operator_review` detail
/// (`operator_decision: confirmed; reason: …` → `confirmed`).
fn operator_decision(detail: &str) -> Option<&str> {
    let rest = detail.strip_prefix("operator_decision:")?.trim_start();
    rest.split([';', ' ', '\n'])
        .next()
        .filter(|w| !w.is_empty())
}

/// Everything the derivation reads, gathered in one pass.
struct Signals {
    plausible: bool,
    consistent: bool,
    uncertain: bool,
    verify_error: bool,
    refuter_verdict: bool,
    poc_ran: bool,
    oracles: Vec<PocOracle>,
    maintainer_confirmed: bool,
}

/// Per-run refutation record written in multi-run mode
/// (`refuter_run 2/3: refuted: <reason>`).
fn per_run_refutation(detail: &str) -> Option<&str> {
    let rest = detail.strip_prefix("refuter_run ")?;
    let (_, verdict) = rest.split_once(": ")?;
    verdict.strip_prefix("refuted: ")
}

fn signals(f: &Finding) -> Signals {
    let mut s = Signals {
        plausible: false,
        consistent: false,
        uncertain: false,
        verify_error: false,
        refuter_verdict: false,
        poc_ran: false,
        oracles: Vec::new(),
        maintainer_confirmed: false,
    };
    let mut last_operator: Option<&str> = None;
    for e in &f.evidence {
        let d = e.detail.as_str();
        match e.kind {
            EvidenceKind::AdversarialReview => {
                if d.starts_with(PLAUSIBLE_PREFIX) {
                    s.plausible = true;
                    s.refuter_verdict = true;
                } else if consistent_runs(d).is_some() {
                    s.consistent = true;
                } else if d.starts_with(VERIFY_ERROR_PREFIX) {
                    s.verify_error = true;
                } else if d.starts_with("refuted") || d.starts_with("refuter_run ") {
                    s.refuter_verdict = true;
                }
            }
            EvidenceKind::VerifyUncertain if d.starts_with(VERIFY_UNCERTAIN_PREFIX) => {
                s.uncertain = true;
                s.refuter_verdict = true;
            }
            EvidenceKind::PocTranscript => s.poc_ran = true,
            EvidenceKind::PocOracle => {
                if let Some(o) = PocOracle::parse(d) {
                    s.poc_ran = true;
                    s.oracles.push(o);
                }
            }
            EvidenceKind::OperatorReview => {
                if let Some(word) = operator_decision(d) {
                    last_operator = Some(word);
                }
            }
            _ => {}
        }
    }
    let by_operator = last_operator == Some("confirmed")
        || (last_operator.is_none() && f.severity_basis == SeverityBasis::Operator);
    s.maintainer_confirmed = f.status == FindingStatus::Confirmed && by_operator;
    s
}

fn derive_level(s: &Signals) -> EvidenceLevel {
    if s.maintainer_confirmed {
        return EvidenceLevel::MaintainerConfirmed;
    }
    let mut level = EvidenceLevel::StaticOnly;
    if s.plausible {
        level = if s.consistent {
            EvidenceLevel::RefuterConsistent
        } else {
            EvidenceLevel::RefuterSurvived
        };
    }
    if let Some(poc) = s.oracles.iter().filter_map(PocOracle::level).max() {
        level = level.max(poc);
    }
    if s.verify_error {
        level = level.min(EvidenceLevel::StaticOnly);
    }
    if s.uncertain {
        level = level.min(EvidenceLevel::RefuterSurvived);
    }
    level
}

impl Finding {
    /// The derived evidence level (see the module docs for the table).
    pub fn evidence_level(&self) -> EvidenceLevel {
        derive_level(&signals(self))
    }

    /// What this finding still lacks, in a stable order.
    pub fn proof_gaps(&self) -> Vec<ProofGap> {
        let s = signals(self);
        let level = derive_level(&s);
        let mut gaps = Vec::new();
        if !s.refuter_verdict {
            gaps.push(ProofGap::NoRefuter);
        }
        if s.uncertain {
            gaps.push(ProofGap::RefuterInconsistent);
        }
        // Prefer the oracle that supports the most, then any accepted effect.
        let effect = s
            .oracles
            .iter()
            .filter(|o| o.has_harness_effect())
            .max_by_key(|o| o.level());
        match effect {
            None if !s.poc_ran => gaps.push(ProofGap::NoPoc),
            None => gaps.push(ProofGap::PocNotHarnessJudged),
            Some(o) => {
                if o.control != Some(false) {
                    gaps.push(ProofGap::NoControl);
                }
                if o.rerun != Some(true) {
                    gaps.push(ProofGap::NoFreshRerun);
                }
            }
        }
        if level != EvidenceLevel::MaintainerConfirmed {
            if level < EvidenceLevel::PocEffectNoControl {
                gaps.push(ProofGap::ReachabilityUnknown);
            }
            gaps.push(ProofGap::NoMaintainerConfirmation);
        }
        gaps
    }

    /// The most damaging recorded counter-evidence, masked and bounded:
    /// a failed PoC control first, then the latest refuter / pre-check
    /// rationale, then an anti-cheat PoC rejection. `None` when there is none.
    pub fn strongest_counterevidence(&self) -> Option<String> {
        let s = signals(self);
        let failed_control = s
            .oracles
            .iter()
            .any(|o| o.has_harness_effect() && o.control == Some(true));
        // O10: when the verdict flipped on the code's comments, a refutation
        // from the run that read them may just repeat a planted comment; it
        // is not quoted as counter-evidence.
        let comment_flip = self
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::CommentSensitivity);
        let text = if failed_control {
            "control: the PoC effect also appeared on the control run, so it is not specific to the claimed defect".to_string()
        } else if let Some(t) = self.evidence.iter().rev().find_map(|e| {
            if e.kind != EvidenceKind::AdversarialReview {
                return None;
            }
            let d = e.detail.as_str();
            if comment_flip && d.starts_with("refuter_run ") && d.contains(" (with comments): ") {
                return None;
            }
            d.strip_prefix("refuted (zero-LLM): ")
                .or_else(|| d.strip_prefix("refuted: "))
                .or_else(|| per_run_refutation(d))
                .map(|r| format!("refuter: {}", r.trim()))
                .or_else(|| {
                    d.strip_prefix(PRECHECK_PREFIX)
                        .map(|r| format!("precheck: {}", r.trim()))
                })
        }) {
            t
        } else {
            let reason = s.oracles.iter().find_map(|o| o.rejected.as_deref())?;
            format!("poc: rejected before execution ({reason})")
        };
        let masked = crate::util::mask_sensitive_text(&text);
        let bounded = crate::util::truncate_bytes(masked.trim(), COUNTEREVIDENCE_MAX_BYTES);
        (!bounded.is_empty()).then(|| bounded.to_string())
    }

    /// One line of keys: level, gaps, counter-evidence and fix check. The
    /// terminal summary renders the same facts in plain words
    /// (`report_evidence`).
    pub fn evidence_summary(&self) -> String {
        let gaps: Vec<&str> = self.proof_gaps().iter().map(|g| g.key()).collect();
        let mut line = format!(
            "evidence_level={} proof_gaps={}",
            self.evidence_level().key(),
            if gaps.is_empty() {
                "none".to_string()
            } else {
                gaps.join(",")
            }
        );
        if let Some(c) = self.strongest_counterevidence() {
            line.push_str(&format!(" strongest_counterevidence={c:?}"));
        }
        if let Some(fix) = self.fix_check() {
            line.push_str(&format!(" fix_check={}", fix.outcome.key()));
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{EvidenceItem, FindingKind, Severity};

    fn finding() -> Finding {
        Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "t",
            "src/a.py",
            Some(1),
            "s",
            "ai-audit/x",
            vec![ev(EvidenceKind::AiAnalysis, "reasoning: model narrative")],
        )
    }

    fn ev(kind: EvidenceKind, detail: &str) -> EvidenceItem {
        EvidenceItem {
            kind,
            source: "test".into(),
            detail: detail.into(),
            recorded_at: "2026-10-20T00:00:00Z".into(),
        }
    }

    fn with(mut f: Finding, items: &[(EvidenceKind, &str)]) -> Finding {
        for (k, d) in items {
            f.evidence.push(ev(*k, d));
        }
        f
    }

    const PLAUS: (EvidenceKind, &str) =
        (EvidenceKind::AdversarialReview, "plausible: flow visible");
    const CONSISTENT: (EvidenceKind, &str) =
        (EvidenceKind::AdversarialReview, "refuter_consistent: 3/3");
    const DIFF: (EvidenceKind, &str) = (
        EvidenceKind::PocOracle,
        "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none",
    );
    const NO_CONTROL: (EvidenceKind, &str) = (
        EvidenceKind::PocOracle,
        "poc_oracle: effect=true control=none rerun=none nonce_bound=true rejected=none",
    );

    #[test]
    fn derivation_table() {
        use EvidenceLevel as L;
        type Case = (&'static str, Vec<(EvidenceKind, &'static str)>, L);
        let cases: Vec<Case> = vec![
            ("analysis only", vec![], L::StaticOnly),
            ("one plausible", vec![PLAUS], L::RefuterSurvived),
            (
                "3/3 consistent",
                vec![CONSISTENT, PLAUS],
                L::RefuterConsistent,
            ),
            (
                "2/2 is not consistent",
                vec![
                    (EvidenceKind::AdversarialReview, "refuter_consistent: 2/2"),
                    PLAUS,
                ],
                L::RefuterSurvived,
            ),
            (
                "consistent without plausible is nothing",
                vec![CONSISTENT],
                L::StaticOnly,
            ),
            (
                "effect, no control",
                vec![PLAUS, NO_CONTROL],
                L::PocEffectNoControl,
            ),
            ("differential", vec![PLAUS, DIFF], L::PocDifferential),
            (
                "failed control supports nothing",
                vec![(
                    EvidenceKind::PocOracle,
                    "poc_oracle: effect=true control=true rerun=true nonce_bound=true rejected=none",
                )],
                L::StaticOnly,
            ),
            (
                "rejected PoC supports nothing",
                vec![(
                    EvidenceKind::PocOracle,
                    "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=nonce_literal",
                )],
                L::StaticOnly,
            ),
            (
                "effect without nonce supports nothing",
                vec![(
                    EvidenceKind::PocOracle,
                    "poc_oracle: effect=true control=false rerun=true nonce_bound=false rejected=none",
                )],
                L::StaticOnly,
            ),
            (
                "pattern transcript never upgrades",
                vec![PLAUS, (EvidenceKind::PocTranscript, "exit_code=0")],
                L::RefuterSurvived,
            ),
            (
                "malformed oracle is ignored",
                vec![(
                    EvidenceKind::PocOracle,
                    "poc_oracle: effect=true control=false rerun=true nonce_bound=true",
                )],
                L::StaticOnly,
            ),
            (
                "oracle text under another kind is ignored",
                vec![(EvidenceKind::AiAnalysis, DIFF.1)],
                L::StaticOnly,
            ),
            (
                "verify_error caps at static_only",
                vec![
                    PLAUS,
                    DIFF,
                    (EvidenceKind::AdversarialReview, "verify_error: x"),
                ],
                L::StaticOnly,
            ),
            (
                "verify_uncertain caps at refuter_survived",
                vec![
                    PLAUS,
                    CONSISTENT,
                    DIFF,
                    (
                        EvidenceKind::VerifyUncertain,
                        "verify_uncertain: 2/3 plausible",
                    ),
                ],
                L::RefuterSurvived,
            ),
            (
                "uncertain alone stays static_only",
                vec![(
                    EvidenceKind::VerifyUncertain,
                    "verify_uncertain: 2/3 plausible",
                )],
                L::StaticOnly,
            ),
        ];
        for (name, items, want) in cases {
            assert_eq!(with(finding(), &items).evidence_level(), want, "{name}");
        }
    }

    #[test]
    fn uncertain_never_upgrades_whatever_follows() {
        let base = with(
            finding(),
            &[(
                EvidenceKind::VerifyUncertain,
                "verify_uncertain: 1/3 plausible",
            )],
        );
        for extra in [PLAUS, CONSISTENT, DIFF, NO_CONTROL] {
            let f = with(base.clone(), &[extra, PLAUS, CONSISTENT, DIFF]);
            assert!(f.evidence_level() <= EvidenceLevel::RefuterSurvived);
        }
    }

    #[test]
    fn maintainer_confirmed_needs_operator_status_and_decision() {
        let mut f = with(finding(), &[PLAUS]);
        f.evidence.push(ev(
            EvidenceKind::OperatorReview,
            "operator_decision: confirmed; reason: reproduced",
        ));
        assert_eq!(
            f.evidence_level(),
            EvidenceLevel::RefuterSurvived,
            "status not confirmed yet"
        );
        f.status = FindingStatus::Confirmed;
        f.severity_basis = SeverityBasis::Operator;
        assert_eq!(f.evidence_level(), EvidenceLevel::MaintainerConfirmed);
        assert!(!f.proof_gaps().contains(&ProofGap::NoMaintainerConfirmation));
        // A later operator decision that is not "confirmed" wins.
        f.evidence.push(ev(
            EvidenceKind::OperatorReview,
            "operator_decision: refuted",
        ));
        assert_ne!(f.evidence_level(), EvidenceLevel::MaintainerConfirmed);
    }

    #[test]
    fn model_text_cannot_claim_maintainer_confirmation() {
        let mut f = with(
            finding(),
            &[
                PLAUS,
                (
                    EvidenceKind::AdversarialReview,
                    "operator_decision: confirmed",
                ),
                (EvidenceKind::AiAnalysis, "maintainer_confirmed"),
            ],
        );
        f.status = FindingStatus::NeedsHuman;
        assert_eq!(f.evidence_level(), EvidenceLevel::RefuterSurvived);
    }

    #[test]
    fn refuted_and_suppressed_still_report_a_level() {
        let mut f = with(finding(), &[PLAUS]);
        f.status = FindingStatus::Suppressed;
        assert_eq!(f.evidence_level(), EvidenceLevel::RefuterSurvived);
        f.status = FindingStatus::Refuted;
        assert_eq!(f.evidence_level(), EvidenceLevel::RefuterSurvived);
    }

    #[test]
    fn proof_gaps_follow_the_evidence() {
        use ProofGap as G;
        assert_eq!(
            finding().proof_gaps(),
            vec![
                G::NoRefuter,
                G::NoPoc,
                G::ReachabilityUnknown,
                G::NoMaintainerConfirmation
            ]
        );
        assert_eq!(
            with(
                finding(),
                &[PLAUS, (EvidenceKind::PocTranscript, "exit_code=0")]
            )
            .proof_gaps(),
            vec![
                G::PocNotHarnessJudged,
                G::ReachabilityUnknown,
                G::NoMaintainerConfirmation
            ]
        );
        assert_eq!(
            with(finding(), &[PLAUS, NO_CONTROL]).proof_gaps(),
            vec![G::NoControl, G::NoFreshRerun, G::NoMaintainerConfirmation]
        );
        assert_eq!(
            with(finding(), &[PLAUS, DIFF]).proof_gaps(),
            vec![G::NoMaintainerConfirmation]
        );
        assert!(
            with(
                finding(),
                &[(
                    EvidenceKind::VerifyUncertain,
                    "verify_uncertain: 2/3 plausible"
                )]
            )
            .proof_gaps()
            .contains(&G::RefuterInconsistent)
        );
        let mut refuted = with(
            finding(),
            &[(EvidenceKind::AdversarialReview, "refuted: input is escaped")],
        );
        refuted.status = FindingStatus::Refuted;
        assert!(!refuted.proof_gaps().contains(&G::NoRefuter));
    }

    #[test]
    fn strongest_counterevidence_prefers_failed_control_then_refuter() {
        assert_eq!(finding().strongest_counterevidence(), None);
        let f = with(
            finding(),
            &[
                (
                    EvidenceKind::AdversarialReview,
                    "refuter_run 1/3: refuted: escaped at line 4",
                ),
                (
                    EvidenceKind::AdversarialReview,
                    "refuter_run 2/3: plausible: flow visible",
                ),
            ],
        );
        assert_eq!(
            f.strongest_counterevidence().as_deref(),
            Some("refuter: escaped at line 4")
        );
        let f = with(
            f,
            &[(
                EvidenceKind::PocOracle,
                "poc_oracle: effect=true control=true rerun=none nonce_bound=true rejected=none",
            )],
        );
        assert!(
            f.strongest_counterevidence()
                .unwrap()
                .starts_with("control:")
        );
        let pre = with(
            finding(),
            &[(
                EvidenceKind::AdversarialReview,
                "precheck: file: does not exist",
            )],
        );
        assert_eq!(
            pre.strongest_counterevidence().as_deref(),
            Some("precheck: file: does not exist")
        );
    }

    #[test]
    fn strongest_counterevidence_is_masked_and_bounded() {
        let long = format!("refuted: password: hunter2 {}", "x".repeat(2000));
        let f = with(
            finding(),
            &[(EvidenceKind::AdversarialReview, long.as_str())],
        );
        let c = f.strongest_counterevidence().unwrap();
        assert!(c.len() <= COUNTEREVIDENCE_MAX_BYTES);
        assert!(!c.contains("hunter2"), "{c}");
    }

    #[test]
    fn poc_oracle_parser_is_strict_and_round_trips() {
        let o = PocOracle::parse(DIFF.1).unwrap();
        assert_eq!(o.to_detail(), DIFF.1);
        assert_eq!(o.level(), Some(EvidenceLevel::PocDifferential));
        let rejected = PocOracle {
            effect: false,
            control: None,
            rerun: Some(false),
            nonce_bound: false,
            rejected: Some("writes_repo_tree".into()),
        };
        assert_eq!(PocOracle::parse(&rejected.to_detail()), Some(rejected));
        for bad in [
            "",
            "poc_oracle:",
            "poc_oracle: effect=true",
            "poc_oracle:  effect=true control=false rerun=true nonce_bound=true rejected=none",
            "poc_oracle: effect=TRUE control=false rerun=true nonce_bound=true rejected=none",
            "poc_oracle: effect=true control=maybe rerun=true nonce_bound=true rejected=none",
            "poc_oracle: control=false effect=true rerun=true nonce_bound=true rejected=none",
            "poc_oracle: effect=true control=false rerun=true nonce_bound=none rejected=none",
            "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=Bad Reason",
            "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=",
            "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none extra=1",
            "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none\n",
            "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none ",
            "POC_ORACLE: effect=true control=false rerun=true nonce_bound=true rejected=none",
        ] {
            assert_eq!(PocOracle::parse(bad), None, "{bad:?}");
        }
        let long = format!(
            "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected={}",
            "a".repeat(65)
        );
        assert_eq!(PocOracle::parse(&long), None);
    }

    /// A historical report (no `evidence_level` / `proof_gaps` keys, no new
    /// evidence kinds) loads and derives from what it carries.
    #[test]
    fn old_report_finding_reads_and_derives_honestly() {
        let mut v = serde_json::to_value(with(finding(), &[PLAUS])).unwrap();
        let obj = v.as_object_mut().unwrap();
        for k in ["evidence_level", "proof_gaps", "strongest_counterevidence"] {
            obj.remove(k);
        }
        let old: Finding = serde_json::from_value(v).unwrap();
        assert_eq!(old.evidence_level(), EvidenceLevel::RefuterSurvived);
        let out = serde_json::to_value(&old).unwrap();
        assert_eq!(out["evidence_level"], "refuter_survived");
        assert!(out["proof_gaps"].is_array());
    }

    /// A stored (possibly forged) level is never trusted on read.
    #[test]
    fn stored_derived_fields_are_ignored_on_read() {
        let mut v = serde_json::to_value(finding()).unwrap();
        v["evidence_level"] = "maintainer_confirmed".into();
        v["proof_gaps"] = serde_json::json!([]);
        v["strongest_counterevidence"] = "none".into();
        let f: Finding = serde_json::from_value(v).unwrap();
        let out = serde_json::to_value(&f).unwrap();
        assert_eq!(out["evidence_level"], "static_only");
        assert_eq!(out["proof_gaps"][0], "no_refuter");
        assert!(out.get("strongest_counterevidence").is_none());
    }

    #[test]
    fn levels_are_ordered_and_serialize_snake_case() {
        assert!(EvidenceLevel::ALL.windows(2).all(|w| w[0] < w[1]));
        for l in EvidenceLevel::ALL {
            assert_eq!(serde_json::to_value(l).unwrap(), l.key());
        }
        assert_eq!(
            serde_json::to_value(EvidenceKind::VerifyUncertain).unwrap(),
            "verify_uncertain"
        );
        assert_eq!(
            serde_json::to_value(EvidenceKind::PocOracle).unwrap(),
            "poc_oracle"
        );
        assert_eq!(
            serde_json::to_value(ProofGap::PocNotHarnessJudged).unwrap(),
            "poc_not_harness_judged"
        );
    }

    #[test]
    fn evidence_summary_is_one_line_of_keys() {
        let s = with(finding(), &[PLAUS]).evidence_summary();
        assert!(
            s.starts_with("evidence_level=refuter_survived proof_gaps=no_poc,"),
            "{s}"
        );
        assert!(!s.contains('\n'));
    }
}
