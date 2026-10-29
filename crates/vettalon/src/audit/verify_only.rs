//! `vettalon verify`: run the refuter on findings that already exist,
//! without any finder call.
//!
//! Two inputs:
//! - a `vettalon scan --report` JSON (for example a finder-only scan): its
//!   unreviewed ai_audit candidates are reviewed exactly as `scan` would
//!   review them;
//! - a claims file (`{"schema": "vettalon.claims/1", "claims": [...]}`):
//!   findings from another tool (a SAST alert, a benchmark case), each
//!   turned into a candidate and reviewed.
//!
//! Every reviewed finding goes through [`adversarial::review_with`], the
//! same prompt, excerpts, pre-checks, refuter runs and settlement as in a
//! scan. Each model call becomes one [`VerifierVote`]. Nothing else in the
//! input changes.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::adversarial;
use super::schema::{
    Finding, FindingKind, FindingStatus, Severity, TraceKind, TraceStep, VerifierVote,
};
use crate::llm::{ModelHandle, RefusalLog, StepCaller, TraceLog};

pub const VERIFY_SCHEMA: &str = "vettalon.verify/1";
pub const CLAIMS_SCHEMA: &str = "vettalon.claims/1";
/// Engine name on findings built from claims.
pub const EXTERNAL_ENGINE: &str = "external";
/// Longest claim title kept (the rest is cut, never dropped silently: the
/// output records `title_truncated`).
pub const CLAIM_TITLE_MAX_BYTES: usize = 2000;
pub const MAX_CLAIM_LOCATIONS: usize = 10;

/// One externally produced finding.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// Caller's id, echoed in the output (`claim_ids`).
    pub id: String,
    /// Repo-relative path of the claimed defect.
    pub file: String,
    pub line: Option<u32>,
    /// What is claimed (weakness name, scanner message).
    pub title: String,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Who produced the claim, recorded in `found_by` as `external:<source>`.
    #[serde(default)]
    pub source: Option<String>,
    /// Further locations, shown to the refuter as trace steps.
    #[serde(default)]
    pub locations: Vec<ClaimLocation>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLocation {
    pub file: String,
    pub line: u32,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimsFile {
    schema: String,
    claims: Vec<Claim>,
}

/// What a verify run reads.
#[derive(Debug)]
pub enum VerifyInput {
    /// Findings of a scan report; only unreviewed ai_audit candidates are
    /// reviewed, the rest pass through.
    Report(Vec<Finding>),
    /// Claims; every one becomes a candidate and is reviewed.
    Claims(Vec<Claim>),
}

impl VerifyInput {
    /// A scan report (an object with `findings`) or a claims file.
    pub fn parse(text: &str) -> Result<VerifyInput, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("input is not JSON: {e}"))?;
        if v.get("schema").and_then(|s| s.as_str()) == Some(CLAIMS_SCHEMA) {
            let f: ClaimsFile =
                serde_json::from_value(v).map_err(|e| format!("invalid claims file: {e}"))?;
            debug_assert_eq!(f.schema, CLAIMS_SCHEMA);
            let mut seen = std::collections::HashSet::new();
            for c in &f.claims {
                if c.id.trim().is_empty() || !seen.insert(c.id.as_str()) {
                    return Err(format!("claim id {:?} is empty or repeated", c.id));
                }
                if c.file.trim().is_empty() || c.title.trim().is_empty() {
                    return Err(format!("claim {:?} needs a file and a title", c.id));
                }
                if c.locations.len() > MAX_CLAIM_LOCATIONS {
                    return Err(format!(
                        "claim {:?} has {} locations (max {MAX_CLAIM_LOCATIONS})",
                        c.id,
                        c.locations.len()
                    ));
                }
            }
            return Ok(VerifyInput::Claims(f.claims));
        }
        match v.get("findings") {
            Some(findings) => serde_json::from_value(findings.clone())
                .map(VerifyInput::Report)
                .map_err(|e| format!("report findings do not parse: {e}")),
            None => Err(format!(
                "input is neither a scan report (no `findings`) nor a {CLAIMS_SCHEMA} file"
            )),
        }
    }
}

/// A claim as a candidate finding. The refuter sees file, line, title,
/// severity and the extra locations; nothing else from the claim.
pub fn claim_to_finding(c: &Claim) -> (Finding, bool) {
    let title = crate::util::truncate_bytes(c.title.trim(), CLAIM_TITLE_MAX_BYTES);
    let truncated = title.len() < c.title.trim().len();
    let rule_id = c
        .rule_id
        .clone()
        .or_else(|| c.cwe.as_ref().map(|w| format!("external/{w}")))
        .unwrap_or_else(|| "external/claim".to_string());
    let mut f = Finding::candidate(
        EXTERNAL_ENGINE,
        FindingKind::StaticAnalysis,
        c.severity.unwrap_or(Severity::Medium),
        title,
        c.file.clone(),
        c.line,
        "",
        rule_id,
        Vec::new(),
    );
    f.cwe = c.cwe.clone();
    f.found_by = vec![format!(
        "{EXTERNAL_ENGINE}:{}",
        c.source.as_deref().unwrap_or("claim")
    )];
    f.trace = c
        .locations
        .iter()
        .map(|l| TraceStep {
            kind: TraceKind::Propagation,
            file: l.file.clone(),
            line: l.line,
            scope: l.scope.clone().unwrap_or_default(),
            description: String::new(),
        })
        .collect();
    (f, truncated)
}

/// Settings of one verify run.
pub struct VerifyOptions<'a> {
    pub verifier: ModelHandle,
    /// Family of each roster model id, to label votes `cross_family` /
    /// `same_model` against the finding's `found_by` as a scan does. Claims
    /// have no finder model, so their votes are never cross-family.
    pub families: &'a HashMap<String, String>,
    /// `--refuter-runs` (High and above; lower severities get one).
    pub refuter_runs: usize,
    /// Extra refuter runs do not start after this.
    pub deadline: Option<Instant>,
    /// Correction calls per run for a reply that breaks the contract.
    pub parse_retries: usize,
    /// `--refuter-policy`.
    pub policy: super::refuter_policy::RefuterPolicy,
    /// Record scores without changing any verdict.
    pub score: bool,
    /// `--refuter-score-threshold`: close only on `p_real` below this.
    pub score_threshold: Option<u8>,
    /// `--joern-keep` (experimental): after review, a Joern source→sink path
    /// to the claimed line reopens a finding the refuter closed. `None` =
    /// off (the default). It never closes anything.
    pub joern: Option<crate::joern::JoernSettings>,
    pub trace: TraceLog,
}

/// What `--joern-keep` did in one verify run (written only when set).
#[derive(Debug, Serialize)]
pub struct JoernKeepInfo {
    pub image: String,
    pub joern: &'static str,
    pub template: &'static str,
    pub sources: &'static str,
    pub rule: &'static str,
    pub timeout_secs: u64,
    /// Findings the refuter closed with a model reply (asked about).
    pub checked: usize,
    /// Of those, reopened by a path.
    pub kept: usize,
    /// One entry per container run (frontend).
    pub runs: Vec<crate::joern::LangRun>,
}

#[derive(Debug, Serialize)]
pub struct VerifyOutput {
    pub schema: &'static str,
    pub input: &'static str,
    pub verifier: VerifierInfo,
    pub refuter_runs: usize,
    /// `--refuter-policy` the run used (`current` by default).
    pub refuter_policy: String,
    /// `--refuter-score` was on (written only then, so default output is
    /// unchanged); each reply's score is a `refuter_score:` evidence line.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub refuter_score: bool,
    /// `--refuter-score-threshold` (written only when set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refuter_score_threshold: Option<u8>,
    /// `--joern-keep` (written only when set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joern_keep: Option<JoernKeepInfo>,
    /// Every input finding in input order; reviewed ones carry their votes.
    pub findings: Vec<Finding>,
    /// Claims mode: `claim_ids[i]` is the id of `findings[i]`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claim_ids: Vec<String>,
    /// Claims mode: ids whose title was cut to [`CLAIM_TITLE_MAX_BYTES`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub title_truncated: Vec<String>,
    pub reviewed: usize,
    /// Eligible findings left Candidate without a completed uncertain
    /// review: source/claim validation failures, failed/malformed calls,
    /// incomplete runs, and findings skipped by the dead-verifier breaker.
    /// Completed model disagreements follow the scan's rule and do not
    /// count as unverified.
    pub unverified: usize,
    /// Source/claim validation failed without a model call. These findings
    /// also count as unverified; zero calls do not imply a settled verdict.
    pub zero_llm: usize,
    pub passed_through: usize,
    pub calls: usize,
    /// True when a finding meant for review was left unverified.
    pub incomplete: bool,
}

#[derive(Debug, Serialize)]
pub struct VerifierInfo {
    pub id: String,
    pub family: String,
}

/// Review the input's findings with one verifier, sequentially.
pub async fn run_verify(
    repo_root: &Path,
    input: VerifyInput,
    o: VerifyOptions<'_>,
) -> VerifyOutput {
    let (mut findings, claim_ids, title_truncated, mode) = match input {
        VerifyInput::Report(f) => (f, Vec::new(), Vec::new(), "report"),
        VerifyInput::Claims(claims) => {
            let mut ids = Vec::new();
            let mut cut = Vec::new();
            let mut out = Vec::new();
            for c in &claims {
                let (f, truncated) = claim_to_finding(c);
                if truncated {
                    cut.push(c.id.clone());
                }
                ids.push(c.id.clone());
                out.push(f);
            }
            (out, ids, cut, "claims")
        }
    };
    let caller = StepCaller::new(o.verifier.clone(), "verify", RefusalLog::default())
        .with_trace(o.trace.clone());
    let (mut reviewed, mut unverified, mut zero_llm, mut passed) = (0, 0, 0, 0);
    let (mut answered_once, mut dead) = (false, false);
    // Findings closed after a model reply: the only ones `--joern-keep` asks
    // about (a zero-call source failure is not a refutation).
    let mut model_refuted: Vec<usize> = Vec::new();
    for (idx, f) in findings.iter_mut().enumerate() {
        let eligible = match mode {
            "claims" => f.status == FindingStatus::Candidate,
            _ => adversarial::is_eligible(f) && f.verification.is_empty(),
        };
        if !eligible {
            passed += 1;
            continue;
        }
        if dead {
            adversarial::note_unverified(
                f,
                &format!(
                    "verifier {} unreachable earlier in this run; not attempted",
                    o.verifier.id
                ),
            );
            unverified += 1;
            continue;
        }
        let finder_families: Vec<&str> = f
            .found_by
            .iter()
            .filter_map(|id| o.families.get(id).map(String::as_str))
            .collect();
        let cross_family =
            !finder_families.is_empty() && !finder_families.contains(&o.verifier.family.as_str());
        let same_model = f.found_by.iter().any(|m| m == &o.verifier.id);
        let plan = adversarial::ReviewPlan {
            runs: adversarial::runs_for(f, o.refuter_runs),
            independent_refuter: cross_family && !same_model,
            deadline: o.deadline,
            parse_retries: o.parse_retries,
            policy: o.policy,
            score: o.score,
            score_threshold: o.score_threshold,
        };
        let votes = match adversarial::review_with(repo_root, f, &caller, plan).await {
            adversarial::ReviewOutcome::ZeroLlm => {
                zero_llm += 1;
                Vec::new()
            }
            adversarial::ReviewOutcome::Reviewed {
                votes,
                answered,
                call_failed,
                refused,
            } => {
                answered_once |= answered;
                if call_failed {
                    dead = !refused && !answered_once;
                }
                reviewed += 1;
                if f.status == FindingStatus::Refuted {
                    model_refuted.push(idx);
                }
                votes
            }
        };
        for verdict in votes {
            f.verification.push(VerifierVote {
                model: o.verifier.id.clone(),
                family: o.verifier.family.clone(),
                verdict,
                cross_family,
                same_model,
            });
        }
        if f.status == FindingStatus::Candidate && !adversarial::is_uncertain(f) {
            unverified += 1;
        }
    }
    let joern_keep = match &o.joern {
        Some(s) => Some(joern_keep(repo_root, &mut findings, &model_refuted, s).await),
        None => None,
    };
    VerifyOutput {
        schema: VERIFY_SCHEMA,
        input: mode,
        verifier: VerifierInfo {
            id: o.verifier.id.clone(),
            family: o.verifier.family.clone(),
        },
        refuter_runs: o.refuter_runs,
        refuter_policy: o.policy.label(),
        refuter_score: o.score || o.score_threshold.is_some(),
        refuter_score_threshold: o.score_threshold,
        joern_keep,
        findings,
        claim_ids,
        title_truncated,
        reviewed,
        unverified,
        zero_llm,
        passed_through: passed,
        calls: caller.call_count(),
        incomplete: unverified > 0,
    }
}

/// `--joern-keep`: ask Joern about every finding in `refuted` (closed after
/// a model reply) and reopen those with an accepted path. Only
/// [`crate::joern::apply_keep`] touches a status, and it can only turn
/// `Refuted` into `Candidate`.
async fn joern_keep(
    repo_root: &Path,
    findings: &mut [Finding],
    refuted: &[usize],
    s: &crate::joern::JoernSettings,
) -> JoernKeepInfo {
    let items: Vec<crate::joern::ItemCheck> = refuted
        .iter()
        .map(|&i| crate::joern::ItemCheck {
            file: findings[i].file.clone(),
            line: findings[i].line,
        })
        .collect();
    let (verdicts, runs) = if items.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        crate::joern::check_items(repo_root, &items, s).await
    };
    let mut kept = 0;
    for (&i, v) in refuted.iter().zip(&verdicts) {
        if crate::joern::apply_keep(&mut findings[i], v, s.rule) {
            kept += 1;
        }
    }
    JoernKeepInfo {
        image: s.image.clone(),
        joern: crate::joern::JOERN_VERSION,
        template: crate::joern::TEMPLATE_ID,
        sources: crate::joern::SOURCES_VERSION,
        rule: s.rule.token(),
        timeout_secs: s.timeout_secs,
        checked: refuted.len(),
        kept,
        runs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{LlmCaller, LlmError};
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    struct Replies(Mutex<Vec<crate::llm::Result<String>>>);
    #[async_trait]
    impl LlmCaller for Replies {
        async fn complete(&self, _p: &str) -> crate::llm::Result<String> {
            self.0.lock().unwrap().remove(0)
        }
    }

    fn handle(id: &str, family: &str, replies: Vec<crate::llm::Result<String>>) -> ModelHandle {
        ModelHandle {
            id: id.into(),
            family: family.into(),
            caller: Arc::new(Replies(Mutex::new(replies))),
        }
    }

    const REFUTED: &str = r#"{"verdict":"refuted","reason":"constant input","blockers":[],"validation_plan":{"local":null,"deployment":null},"corrected_line":null,"corrected_trace":null,"refute_basis":"defect_absent","guard":null,"conditions":null}"#;

    fn repo() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("src")).unwrap();
        std::fs::write(
            d.path().join("src/app.py"),
            "import os\nq = input()\nos.system(q)\n",
        )
        .unwrap();
        d
    }

    fn claims_json(extra: &str) -> String {
        format!(
            r#"{{"schema":"vettalon.claims/1","claims":[{{"id":"c1","file":"src/app.py","line":3,"title":"CWE-78 OS command injection","cwe":"CWE-78","source":"sastbench","locations":[{{"file":"src/app.py","line":2,"scope":"main"}}]}}{extra}]}}"#
        )
    }

    #[test]
    fn claims_parse_and_bad_input_is_refused() {
        let VerifyInput::Claims(c) = VerifyInput::parse(&claims_json("")).unwrap() else {
            panic!("claims expected")
        };
        assert_eq!(c[0].id, "c1");
        let dup = claims_json(r#",{"id":"c1","file":"a","line":1,"title":"t"}"#);
        assert!(VerifyInput::parse(&dup).unwrap_err().contains("repeated"));
        let unknown = r#"{"schema":"vettalon.claims/1","claims":[{"id":"x","file":"a","title":"t","line":1,"ground_truth":"tp"}]}"#;
        assert!(VerifyInput::parse(unknown).is_err(), "unknown keys refused");
        assert!(VerifyInput::parse(r#"{"x":1}"#).is_err());
        assert!(VerifyInput::parse(r#"{"findings":[]}"#).is_ok());
    }

    #[test]
    fn claim_becomes_a_candidate_with_trace_steps() {
        let VerifyInput::Claims(c) = VerifyInput::parse(&claims_json("")).unwrap() else {
            panic!()
        };
        let (f, cut) = claim_to_finding(&c[0]);
        assert!(!cut);
        assert_eq!(f.status, FindingStatus::Candidate);
        assert_eq!(f.source_engine, EXTERNAL_ENGINE);
        assert_eq!(f.found_by, vec!["external:sastbench".to_string()]);
        assert_eq!(f.rule_id, "external/CWE-78");
        assert_eq!(f.trace.len(), 1);
        assert_eq!(f.trace[0].scope, "main");
    }

    #[tokio::test]
    async fn claims_are_reviewed_with_one_vote_per_call() {
        let d = repo();
        let fam = HashMap::new();
        let out = run_verify(
            d.path(),
            VerifyInput::parse(&claims_json("")).unwrap(),
            VerifyOptions {
                verifier: handle("g", "google", vec![Ok(REFUTED.into())]),
                families: &fam,
                refuter_runs: 1,
                deadline: None,
                parse_retries: 1,
                policy: Default::default(),
                score: false,
                score_threshold: None,
                joern: None,
                trace: TraceLog::recording(),
            },
        )
        .await;
        assert_eq!((out.reviewed, out.calls, out.unverified), (1, 1, 0));
        assert_eq!(out.claim_ids, vec!["c1".to_string()]);
        let f = &out.findings[0];
        assert_eq!(f.verification.len(), 1);
        assert!(
            !f.verification[0].cross_family,
            "claims have no finder family"
        );
        assert_ne!(f.status, FindingStatus::Candidate);
        assert!(out.joern_keep.is_none());
    }

    #[tokio::test]
    async fn source_unavailable_claims_count_as_unverified_and_do_not_stop_valid_reviews() {
        let d = repo();
        std::fs::create_dir(d.path().join("src/unreadable.py")).unwrap();
        std::fs::write(d.path().join("src/.env"), "UNIQUE_VERIFY_SECRET").unwrap();
        let mut claims: Vec<Claim> = [
            ("missing", "src/missing.py", 1),
            ("unreadable", "src/unreadable.py", 1),
            ("unsafe", "../outside.py", 1),
            ("line", "src/app.py", 99),
            ("secret", "src/.env", 1),
        ]
        .into_iter()
        .map(|(id, file, line)| Claim {
            id: id.into(),
            file: file.into(),
            line: Some(line),
            title: "A claim whose source cannot be reviewed".into(),
            severity: None,
            cwe: None,
            rule_id: None,
            source: Some("fixture".into()),
            locations: Vec::new(),
        })
        .collect();
        let VerifyInput::Claims(mut valid) = VerifyInput::parse(&claims_json("")).unwrap() else {
            panic!("claims expected")
        };
        claims.append(&mut valid);
        let fam = HashMap::new();
        let out = run_verify(
            d.path(),
            VerifyInput::Claims(claims),
            VerifyOptions {
                verifier: handle("g", "google", vec![Ok(REFUTED.into())]),
                families: &fam,
                refuter_runs: 1,
                deadline: None,
                parse_retries: 1,
                policy: Default::default(),
                score: false,
                score_threshold: None,
                joern: None,
                trace: TraceLog::default(),
            },
        )
        .await;
        assert_eq!((out.calls, out.reviewed, out.zero_llm), (1, 1, 5));
        assert_eq!(out.unverified, 5);
        assert!(out.incomplete);
        assert_eq!(out.passed_through, 0);
        for f in &out.findings[..5] {
            assert_eq!(f.status, FindingStatus::Candidate);
            assert!(f.verification.is_empty());
            assert!(
                f.evidence
                    .iter()
                    .any(|e| e.detail.starts_with("verify_error:"))
            );
            assert!(!format!("{:?}", f.evidence).contains("UNIQUE_VERIFY_SECRET"));
        }
        assert_eq!(out.findings[5].status, FindingStatus::Refuted);
        assert_eq!(out.findings[5].verification.len(), 1);
    }

    #[tokio::test]
    async fn joern_keep_without_an_image_records_the_error_and_closes_nothing_new() {
        let d = repo();
        let VerifyInput::Claims(mut claims) = VerifyInput::parse(&claims_json(
            r#",{"id":"c2","file":"src/app.py","line":3,"title":"CWE-78 again","cwe":"CWE-78","source":"sastbench"}"#,
        ))
        .unwrap() else {
            panic!()
        };
        claims[1].line = Some(99); // out of range: zero-call unverified source
        let fam = HashMap::new();
        let out = run_verify(
            d.path(),
            VerifyInput::Claims(claims),
            VerifyOptions {
                verifier: handle("g", "google", vec![Ok(REFUTED.into())]),
                families: &fam,
                refuter_runs: 1,
                deadline: None,
                parse_retries: 1,
                policy: Default::default(),
                score: false,
                score_threshold: None,
                joern: Some(crate::joern::JoernSettings {
                    image: "vettalon-joern:missing-in-tests".into(),
                    timeout_secs: 30,
                    rule: Default::default(),
                }),
                trace: TraceLog::default(),
            },
        )
        .await;
        let info = out.joern_keep.as_ref().unwrap();
        // Only the model-refuted finding is asked about; unavailable source
        // stays unverified and is not sent to Joern.
        assert_eq!((info.checked, info.kept), (1, 0));
        assert_eq!(out.findings[0].status, FindingStatus::Refuted);
        assert_eq!(out.findings[1].status, FindingStatus::Candidate);
        assert_eq!((out.zero_llm, out.unverified), (1, 1));
        assert!(out.incomplete);
        let joern_lines: Vec<&str> = out.findings[0]
            .evidence
            .iter()
            .filter(|e| e.source == "joern")
            .map(|e| e.detail.as_str())
            .collect();
        assert_eq!(joern_lines.len(), 1, "{joern_lines:?}");
        assert!(
            joern_lines[0].starts_with("joern: error"),
            "{joern_lines:?}"
        );
        assert!(!out.findings[1].evidence.iter().any(|e| e.source == "joern"));
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["joern_keep"]["rule"], "strict");
    }

    #[tokio::test]
    async fn report_mode_labels_votes_like_a_scan_and_skips_reviewed_rows() {
        let d = repo();
        let mut fresh = Finding::candidate(
            super::super::schema::AI_AUDIT_ENGINE_NAME,
            FindingKind::Other,
            Severity::Medium,
            "command injection",
            "src/app.py",
            Some(3),
            "",
            "ai-audit/command-injection",
            vec![],
        );
        fresh.found_by = vec!["claude".into()];
        let mut done = fresh.clone();
        done.line = Some(2);
        done.verification.push(VerifierVote {
            model: "x".into(),
            family: "x".into(),
            verdict: super::super::schema::VoteVerdict::Plausible,
            cross_family: true,
            same_model: false,
        });
        let fam: HashMap<String, String> = [("claude".to_string(), "anthropic".to_string())].into();
        let out = run_verify(
            d.path(),
            VerifyInput::Report(vec![fresh, done]),
            VerifyOptions {
                verifier: handle("grok", "xai", vec![Ok(REFUTED.into())]),
                families: &fam,
                refuter_runs: 3,
                deadline: None,
                parse_retries: 1,
                policy: Default::default(),
                score: false,
                score_threshold: None,
                joern: None,
                trace: TraceLog::default(),
            },
        )
        .await;
        assert_eq!((out.reviewed, out.passed_through, out.calls), (1, 1, 1));
        let v = &out.findings[0].verification[0];
        assert!(v.cross_family && !v.same_model);
        assert_eq!(out.findings[1].verification.len(), 1, "untouched");
    }

    #[tokio::test]
    async fn unreachable_verifier_trips_the_breaker() {
        let d = repo();
        let fam = HashMap::new();
        let two = claims_json(r#",{"id":"c2","file":"src/app.py","line":2,"title":"t"}"#);
        let out = run_verify(
            d.path(),
            VerifyInput::parse(&two).unwrap(),
            VerifyOptions {
                verifier: handle("g", "google", vec![Err(LlmError::Executor("down".into()))]),
                families: &fam,
                refuter_runs: 1,
                deadline: None,
                parse_retries: 1,
                policy: Default::default(),
                score: false,
                score_threshold: None,
                joern: None,
                trace: TraceLog::default(),
            },
        )
        .await;
        assert_eq!((out.calls, out.unverified), (1, 2));
        assert!(out.incomplete);
        assert_eq!(out.findings[0].status, FindingStatus::Candidate);
        assert_eq!(out.findings[1].status, FindingStatus::Candidate);
    }
}
