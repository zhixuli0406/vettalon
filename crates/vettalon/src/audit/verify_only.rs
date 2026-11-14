//! `vettalon verify`: run the refuter on findings that already exist,
//! without any finder call.
//!
//! Three inputs:
//! - a `vettalon scan --report` JSON (for example a finder-only scan): its
//!   unreviewed ai_audit candidates are reviewed exactly as `scan` would
//!   review them;
//! - a claims file (`{"schema": "vettalon.claims/1", "claims": [...]}`):
//!   findings from another tool (a SAST alert, a benchmark case), each
//!   turned into a candidate and reviewed;
//! - a SARIF 2.1.0 log (Semgrep, CodeQL, Codex Security, vettalon's own
//!   `--sarif` …), converted into the same claims by [`super::sarif_input`].
//!
//! Every input is untrusted: at most [`VERIFY_INPUT_MAX_BYTES`] and
//! [`MAX_JSON_DEPTH`] levels of `{`/`[` nesting, both checked on the raw
//! bytes before parsing, then UTF-8. The format is told from the top-level
//! `schema` / `runs` / `findings` keys by a pass that keeps nothing else,
//! and each format is then read straight into its typed structs (no
//! generic JSON tree is built); a claims file or a report holds at most
//! [`MAX_VERIFY_INPUT_ITEMS`] claims / findings, enforced while the array is
//! read. Every claim title (claims file or SARIF) is cleaned to one line of
//! visible text before it reaches the refuter prompt; a claims-file title
//! with no visible text is refused. At most `--max-claims` findings
//! ([`DEFAULT_MAX_CLAIMS`]) may be up for review in one run; more is an
//! error before any model call ([`check_max_claims`]).
//!
//! Every reviewed finding goes through [`adversarial::review_with`], the
//! same prompt, excerpts, pre-checks, refuter runs and settlement as in a
//! scan (including the per-CWE trust policy, [`super::trust_policy`]). Each
//! model call becomes one [`VerifierVote`]. Past `--time-budget`, no new
//! finding is started: the rest stay unverified `Candidate`s with a
//! `verify_error:` note, counted in `time_budget_skipped`, and the run is
//! incomplete. Nothing else in the input changes.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::adversarial;
use super::sarif_input::{self, Peek, SarifClaims, SarifNote};
use super::schema::{
    EvidenceItem, EvidenceKind, Finding, FindingKind, FindingStatus, Severity, TraceKind,
    TraceStep, VerifierVote,
};
use crate::llm::spend::SpendGuard;
use crate::llm::{ModelHandle, RefusalLog, StepCaller, TraceLog};
use std::sync::Arc;

pub const VERIFY_SCHEMA: &str = "vettalon.verify/1";
pub const CLAIMS_SCHEMA: &str = "vettalon.claims/1";
/// Engine name on findings built from claims.
pub const EXTERNAL_ENGINE: &str = "external";
/// Longest claim title kept (the rest is cut, never dropped silently: the
/// output records `title_truncated`).
pub const CLAIM_TITLE_MAX_BYTES: usize = 2000;
pub const MAX_CLAIM_LOCATIONS: usize = 10;
/// Largest verify input file (report, claims or SARIF).
pub const VERIFY_INPUT_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Deepest `{`/`[` nesting accepted in a verify input, checked on the raw
/// bytes before the JSON parser runs (stricter than serde_json's own 128).
pub const MAX_JSON_DEPTH: usize = 64;
/// Default `--max-claims`: findings one verify run may review.
pub const DEFAULT_MAX_CLAIMS: usize = 200;
/// `verify_error:` note on a finding not started because `--time-budget`
/// had run out.
pub const TIME_BUDGET_NOT_STARTED: &str =
    "time budget exhausted before this finding was reviewed; not attempted";

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
    /// SARIF only, never read from a claims file: every CWE the result
    /// named, when there was more than one (`cwe` is the first, or the
    /// first one the per-CWE trust policy caps). Recorded on the finding as
    /// a `sarif_cwes:` evidence line.
    #[serde(skip)]
    pub cwes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLocation {
    pub file: String,
    pub line: u32,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Most claims (claims/1) or report findings one verify input may hold, the
/// same cap as SARIF results. One more is a parse error raised while the
/// array is read, before the extra entry is kept.
pub const MAX_VERIFY_INPUT_ITEMS: usize = sarif_input::MAX_SARIF_RESULTS;

/// A JSON array of at most `N` entries; one more is an error.
struct BoundedVec<T, const N: usize>(Vec<T>);

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Vis<T, N> {
            type Value = Vec<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "an array of at most {N} entries")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Vec<T>, A::Error> {
                let mut out = Vec::new();
                loop {
                    if out.len() == N {
                        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(format!(
                                "more than {N} entries (the most one verify input may hold)"
                            )));
                        }
                        return Ok(out);
                    }
                    match seq.next_element::<T>()? {
                        Some(item) => out.push(item),
                        None => return Ok(out),
                    }
                }
            }
        }
        d.deserialize_seq(Vis::<T, N>(std::marker::PhantomData))
            .map(BoundedVec)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimsFile {
    schema: String,
    claims: BoundedVec<Claim, MAX_VERIFY_INPUT_ITEMS>,
}

/// The top-level keys that tell the formats apart; everything else is
/// skipped without being kept.
#[derive(Default, Deserialize)]
struct Probe {
    #[serde(default)]
    schema: Peek,
    #[serde(default)]
    runs: Peek,
    #[serde(default)]
    findings: Peek,
}

/// A scan report's findings; every other key is skipped.
#[derive(Deserialize)]
struct ReportFindings {
    findings: BoundedVec<Finding, MAX_VERIFY_INPUT_ITEMS>,
}

/// What a verify run reads.
#[derive(Debug)]
pub enum VerifyInput {
    /// Findings of a scan report; only unreviewed ai_audit candidates are
    /// reviewed, the rest pass through.
    Report(Vec<Finding>),
    /// Claims; every one becomes a candidate and is reviewed.
    Claims(Vec<Claim>),
    /// A SARIF 2.1.0 log as claims, reviewed like [`VerifyInput::Claims`],
    /// plus the results that were skipped or lost locations.
    Sarif(SarifClaims),
}

/// Read a verify input file, refusing one over [`VERIFY_INPUT_MAX_BYTES`]
/// without reading past the cap.
pub fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut buf = Vec::new();
    file.take(VERIFY_INPUT_MAX_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if buf.len() > VERIFY_INPUT_MAX_BYTES {
        return Err(format!(
            "{} is larger than {} MiB",
            path.display(),
            VERIFY_INPUT_MAX_BYTES / (1024 * 1024)
        ));
    }
    Ok(buf)
}

/// Refuse JSON nested deeper than `max` (`{` / `[` outside strings). A
/// linear scan over the raw bytes, so a nesting bomb never reaches the
/// parser; it does not validate the JSON (the parser does).
pub fn check_json_depth(bytes: &[u8], max: usize) -> Result<(), String> {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return Err(format!("input is nested deeper than {max} levels"));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

impl VerifyInput {
    /// A scan report (an object with `findings`), a claims file or a SARIF
    /// log, without a repository root (SARIF `file:` URIs are then dropped).
    pub fn parse(text: &str) -> Result<VerifyInput, String> {
        Self::parse_bytes(text.as_bytes(), None)
    }

    /// [`VerifyInput::parse`] on raw bytes, with the size and nesting
    /// limits checked first. `repo_root` maps SARIF `file:` URIs to
    /// repo-relative paths.
    pub fn parse_bytes(bytes: &[u8], repo_root: Option<&Path>) -> Result<VerifyInput, String> {
        if bytes.len() > VERIFY_INPUT_MAX_BYTES {
            return Err(format!(
                "input is larger than {} MiB",
                VERIFY_INPUT_MAX_BYTES / (1024 * 1024)
            ));
        }
        check_json_depth(bytes, MAX_JSON_DEPTH)?;
        let text = std::str::from_utf8(bytes).map_err(|e| format!("input is not JSON: {e}"))?;
        // Route on three top-level keys without building a JSON tree.
        let is_object = text.trim_start().starts_with('{');
        let probe: Probe = if is_object {
            serde_json::from_str(text).map_err(|e| format!("input is not JSON: {e}"))?
        } else {
            serde_json::from_str::<serde::de::IgnoredAny>(text)
                .map_err(|e| format!("input is not JSON: {e}"))?;
            Probe::default()
        };
        if probe.schema.as_str() == Some(CLAIMS_SCHEMA) {
            let f: ClaimsFile =
                serde_json::from_str(text).map_err(|e| format!("invalid claims file: {e}"))?;
            debug_assert_eq!(f.schema, CLAIMS_SCHEMA);
            let claims = f.claims.0;
            let mut seen = std::collections::HashSet::new();
            for c in &claims {
                if c.id.trim().is_empty() || !seen.insert(c.id.as_str()) {
                    return Err(format!("claim id {:?} is empty or repeated", c.id));
                }
                if c.file.trim().is_empty() || c.title.trim().is_empty() {
                    return Err(format!("claim {:?} needs a file and a title", c.id));
                }
                // The title reaches the refuter prompt: it must keep visible
                // text once control characters and line breaks are removed.
                if sarif_input::clean_title(&c.title).is_none() {
                    return Err(format!(
                        "claim {:?}: the title has no visible text once control characters, line breaks and invisible characters are removed",
                        c.id
                    ));
                }
                if c.locations.len() > MAX_CLAIM_LOCATIONS {
                    return Err(format!(
                        "claim {:?} has {} locations (max {MAX_CLAIM_LOCATIONS})",
                        c.id,
                        c.locations.len()
                    ));
                }
            }
            return Ok(VerifyInput::Claims(claims));
        }
        // A JSON object with `runs` and no `findings` is read as a SARIF log.
        if probe.runs.is_present() && !probe.findings.is_present() {
            return sarif_input::from_json(text, repo_root).map(VerifyInput::Sarif);
        }
        if probe.findings.is_present() {
            return serde_json::from_str::<ReportFindings>(text)
                .map(|r| VerifyInput::Report(r.findings.0))
                .map_err(|e| format!("report findings do not parse: {e}"));
        }
        Err(format!(
            "input is neither a scan report (no `findings`), a {CLAIMS_SCHEMA} file nor a SARIF {} log (no `runs`)",
            sarif_input::SARIF_VERSION
        ))
    }

    /// Findings this input puts up for review: every claim (SARIF: after
    /// skipped results and duplicates), or a report's unreviewed ai_audit
    /// candidates.
    pub fn review_count(&self) -> usize {
        match self {
            VerifyInput::Report(findings) => findings
                .iter()
                .filter(|f| adversarial::is_eligible(f) && f.verification.is_empty())
                .count(),
            VerifyInput::Claims(claims) => claims.len(),
            VerifyInput::Sarif(s) => s.claims.len(),
        }
    }
}

/// `--max-claims`: refuse an input with more than `max` findings up for
/// review, before any model call (each one costs up to `--refuter-runs`
/// calls).
pub fn check_max_claims(input: &VerifyInput, max: usize) -> Result<(), String> {
    let n = input.review_count();
    if n > max {
        return Err(format!(
            "the input has {n} findings to review, more than --max-claims {max}; no model was called. Raise --max-claims {n} to review them all, or split the input"
        ));
    }
    Ok(())
}

/// A claim as a candidate finding. The refuter sees file, line, title,
/// severity and the extra locations; nothing else from the claim.
pub fn claim_to_finding(c: &Claim) -> (Finding, bool) {
    // One line of visible text ([`sarif_input::clean_title`]) for every
    // input: control characters and line breaks never reach the prompt. A
    // claims file with a title that cleans to nothing is refused at parse
    // time; the fallback only covers a caller that built a `Claim` itself.
    let cleaned = sarif_input::clean_title(&c.title).unwrap_or_else(|| "(untitled claim)".into());
    let title = crate::util::truncate_bytes(&cleaned, CLAIM_TITLE_MAX_BYTES);
    let truncated = title.len() < cleaned.len();
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
    if c.cwes.len() > 1 {
        f.evidence.push(EvidenceItem {
            kind: EvidenceKind::StaticHit,
            source: "sarif".to_string(),
            detail: sarif_cwes_detail(&c.cwes),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        });
    }
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

/// Most CWE ids listed in one `sarif_cwes:` line; the rest are counted.
const SARIF_CWES_LISTED: usize = 16;

/// `sarif_cwes: CWE-319, CWE-614` (at most [`SARIF_CWES_LISTED`] ids).
fn sarif_cwes_detail(cwes: &[String]) -> String {
    let listed: Vec<&str> = cwes
        .iter()
        .take(SARIF_CWES_LISTED)
        .map(String::as_str)
        .collect();
    let mut detail = format!("{} {}", sarif_input::SARIF_CWES_PREFIX, listed.join(", "));
    if cwes.len() > SARIF_CWES_LISTED {
        detail.push_str(&format!(" and {} more", cwes.len() - SARIF_CWES_LISTED));
    }
    detail
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
    /// `--time-budget`: no finding is started after this (the rest are left
    /// unverified), and a started finding's extra refuter runs do not start
    /// after it either.
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
    /// `--spend-cap-usd` + `--price-table`: run-wide spend cap. `None` = no
    /// accounting (the default).
    pub spend: Option<Arc<SpendGuard>>,
    /// `--refuter-runs-all-severities`: `refuter_runs` applies to every
    /// claim, not only High and above.
    pub all_severities: bool,
    pub trace: TraceLog,
}

/// Why a spend guard cannot be used with this verifier; checked before any
/// model call.
pub fn check_spend_ready(verifier: &ModelHandle, guard: &SpendGuard) -> Result<(), String> {
    let Some(info) = verifier.caller.meter_info() else {
        return Err(format!(
            "--spend-cap-usd needs an HTTP verifier backend that reports usage; {:?} is not metered",
            verifier.id
        ));
    };
    guard
        .worst_case(&info.api_model, 0, info.max_output_tokens)
        .map_err(|_| {
            format!(
                "the price table has no price for model {:?} (verifier {:?})",
                info.api_model, verifier.id
            )
        })?;
    // Without a key every call would fail after its reservation and be
    // charged the worst case. This must match how the HTTP caller reads the
    // key (`std::env::var`, so a non-UTF-8 value counts as unusable). The
    // value is never printed.
    if let Some(var) = &info.api_key_env
        && std::env::var(var).map_or(true, |v| v.is_empty())
    {
        return Err(format!(
            "--spend-cap-usd: environment variable {var} (api_key_env of verifier {:?}) is not set or empty",
            verifier.id
        ));
    }
    Ok(())
}

/// What `--spend-cap-usd` did in one verify run (written only when set).
#[derive(Debug, Serialize)]
pub struct SpendSummary {
    pub cap_usd: f64,
    pub spent_usd: f64,
    pub calls_charged_worst_case: u64,
    /// Spend went past the cap: one call was billed above its expected
    /// maximum. The run made no further calls after it.
    pub exceeded_cap: bool,
    /// Calls billed above their reservation.
    pub over_reservation_calls: u64,
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
    /// `report`, `claims` or `sarif`.
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
    /// `--spend-cap-usd` accounting (written only when set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend: Option<SpendSummary>,
    /// `--refuter-runs-all-severities` (written only when set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refuter_runs_all_severities: Option<bool>,
    /// Every input finding in input order; reviewed ones carry their votes.
    pub findings: Vec<Finding>,
    /// Claims and SARIF mode: `claim_ids[i]` is the id of `findings[i]`
    /// (SARIF: `sarif-<run>-<result>`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claim_ids: Vec<String>,
    /// Claims and SARIF mode: ids whose title was cut to
    /// [`CLAIM_TITLE_MAX_BYTES`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub title_truncated: Vec<String>,
    /// SARIF mode: results that did not become a finding, with why (not a
    /// finding, suppressed in the log, a `duplicate` of an earlier result,
    /// or no usable location or title). Written only when non-empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sarif_skipped: Vec<SarifNote>,
    /// SARIF mode: of `sarif_skipped`, findings that could not be reviewed
    /// (no usable location or title). Non-zero marks the run incomplete.
    #[serde(skip_serializing_if = "is_zero")]
    pub sarif_unreviewable: usize,
    /// SARIF mode: reviewed results that lost some locations (unusable URI,
    /// outside the repository, over [`MAX_CLAIM_LOCATIONS`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sarif_dropped_locations: Vec<SarifNote>,
    /// SARIF mode: of `sarif_skipped`, repeats of an earlier result (same
    /// file, line, rule id and CWE), reason `duplicate`. Written only when
    /// non-zero.
    #[serde(skip_serializing_if = "is_zero")]
    pub sarif_duplicates: usize,
    /// Findings never started because `--time-budget` had run out; also
    /// counted in `unverified`. Written only when non-zero.
    #[serde(skip_serializing_if = "is_zero")]
    pub time_budget_skipped: usize,
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
    /// True when a finding meant for review was left unverified, or a SARIF
    /// result could not be turned into a reviewable finding.
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
    let mut sarif = SarifClaims::default();
    let (mut findings, claims, mode) = match input {
        VerifyInput::Report(f) => (f, Vec::new(), "report"),
        VerifyInput::Claims(claims) => (Vec::new(), claims, "claims"),
        VerifyInput::Sarif(mut s) => {
            let claims = std::mem::take(&mut s.claims);
            sarif = s;
            (Vec::new(), claims, "sarif")
        }
    };
    let (mut claim_ids, mut title_truncated) = (Vec::new(), Vec::new());
    for c in &claims {
        let (f, truncated) = claim_to_finding(c);
        if truncated {
            title_truncated.push(c.id.clone());
        }
        claim_ids.push(c.id.clone());
        findings.push(f);
    }
    let mut caller = StepCaller::new(o.verifier.clone(), "verify", RefusalLog::default())
        .with_trace(o.trace.clone());
    if let Some(g) = &o.spend {
        caller = caller.with_spend(g.clone());
    }
    let (mut reviewed, mut unverified, mut zero_llm, mut passed) = (0, 0, 0, 0);
    let mut time_budget_skipped = 0;
    let (mut answered_once, mut dead, mut capped) = (false, false, false);
    // Findings closed after a model reply: the only ones `--joern-keep` asks
    // about (a zero-call source failure is not a refutation).
    let mut model_refuted: Vec<usize> = Vec::new();
    for (idx, f) in findings.iter_mut().enumerate() {
        let eligible = match mode {
            "claims" | "sarif" => f.status == FindingStatus::Candidate,
            _ => adversarial::is_eligible(f) && f.verification.is_empty(),
        };
        if !eligible {
            passed += 1;
            continue;
        }
        if capped {
            adversarial::note_unverified(f, "spend cap reached earlier in this run; not attempted");
            unverified += 1;
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
        // `--time-budget`: no new finding starts once it has run out.
        if o.deadline.is_some_and(|d| Instant::now() >= d) {
            adversarial::note_unverified(f, TIME_BUDGET_NOT_STARTED);
            unverified += 1;
            time_budget_skipped += 1;
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
            runs: adversarial::runs_for_with(f, o.refuter_runs, o.all_severities),
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
                budget_refused,
            } => {
                answered_once |= answered;
                if budget_refused {
                    capped = true;
                } else if call_failed {
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
        spend: o.spend.as_ref().map(|g| SpendSummary {
            cap_usd: g.cap_usd(),
            spent_usd: g.spent_usd(),
            calls_charged_worst_case: g.calls_charged_worst_case(),
            exceeded_cap: g.exceeded_cap(),
            over_reservation_calls: g.over_reservation_calls(),
        }),
        refuter_runs_all_severities: o.all_severities.then_some(true),
        findings,
        claim_ids,
        title_truncated,
        sarif_skipped: sarif.skipped,
        sarif_unreviewable: sarif.unreviewable,
        sarif_dropped_locations: sarif.dropped_locations,
        sarif_duplicates: sarif.duplicates,
        time_budget_skipped,
        reviewed,
        unverified,
        zero_llm,
        passed_through: passed,
        calls: caller.call_count(),
        incomplete: unverified > 0 || sarif.unreviewable > 0,
    }
}

fn is_zero(n: &usize) -> bool {
    *n == 0
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

/// Largest file `check_claim_location` will read.
const CLAIM_FILE_CAP: u64 = 4 * 1024 * 1024;

/// A path component that names Git metadata on some file system: `.git` in
/// any letter case (case-insensitive file systems resolve `.GIT`), also with
/// trailing dots or spaces (Windows strips them), or the 8.3 short name
/// `GIT~1`.
fn is_git_metadata_component(c: &str) -> bool {
    let t = c.trim_end_matches(['.', ' ']);
    t.eq_ignore_ascii_case(".git") || t.eq_ignore_ascii_case("git~1")
}

/// `real` (already canonical) relative to the canonical `repo_root`, with
/// `/` separators. `None` when it is not strictly under the root or a
/// component is not UTF-8.
fn repo_relative(repo_root: &Path, real: &Path) -> Option<String> {
    let root = std::fs::canonicalize(repo_root).ok()?;
    let rel = real.strip_prefix(&root).ok()?;
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            std::path::Component::Normal(s) => parts.push(s.to_str()?),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Check that a claimed `file[:line]` is a real, readable, non-secret regular
/// file inside `repo_root` (and that `line` exists in it). Fails closed with
/// the first reason code: `unsafe_path`, `git_metadata`, `secret_file`,
/// `not_found`, `not_regular`, `too_large`, `line_out_of_range`.
pub(crate) fn check_claim_location(
    repo_root: &Path,
    file: &str,
    line: Option<u32>,
) -> Result<(), &'static str> {
    check_claim_location_resolved(repo_root, file, line).map(|_| ())
}

/// [`check_claim_location`], returning on success the repo-relative path
/// the claim resolves to after symlinks (`/`-separated). Callers that need
/// a tracked file check this path too, since a tracked name can be a
/// symlink (or sit under one) pointing at an ignored file.
pub(crate) fn check_claim_location_resolved(
    repo_root: &Path,
    file: &str,
    line: Option<u32>,
) -> Result<String, &'static str> {
    use crate::util::RegularFileError;
    use vettalon_contract::safe_path::SafeRepoPath;

    // Git internals (config with credentialed remotes, hooks, objects) are
    // never a claim location, under any alias a file system resolves to
    // `.git`. Checked before path syntax so `.git.` reports as metadata.
    if file.split('/').any(is_git_metadata_component) {
        return Err("git_metadata");
    }
    if SafeRepoPath::parse(file).is_err() {
        return Err("unsafe_path");
    }
    let real = crate::util::resolve_for_model(repo_root, file).map_err(|e| {
        if e.contains("holds secrets") {
            "secret_file"
        } else if e.contains("not a regular file") {
            "not_regular"
        } else if e.starts_with("cannot resolve") {
            "not_found"
        } else {
            "unsafe_path"
        }
    })?;
    // The literal path may be a symlink (or sit under one) into `.git`.
    let rel = repo_relative(repo_root, &real).ok_or("unsafe_path")?;
    if rel.split('/').any(is_git_metadata_component) {
        return Err("git_metadata");
    }
    let bytes = match crate::util::read_regular_file(&real, CLAIM_FILE_CAP) {
        Ok(b) => b,
        Err(RegularFileError::NotRegular) => return Err("not_regular"),
        Err(RegularFileError::TooLarge) => return Err("too_large"),
        Err(RegularFileError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("not_found");
        }
        Err(RegularFileError::Io(_)) => return Err("unsafe_path"),
    };
    if let Some(n) = line {
        let count = String::from_utf8_lossy(&bytes).lines().count();
        if n < 1 || n as usize > count {
            return Err("line_out_of_range");
        }
    }
    Ok(rel)
}

#[cfg(test)]
mod claim_location_tests {
    use super::check_claim_location;

    fn repo() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.rs"), "one\ntwo\nthree\n").unwrap();
        d
    }

    #[test]
    fn check_claim_location_ok_and_line_bounds() {
        let d = repo();
        assert_eq!(check_claim_location(d.path(), "a.rs", Some(1)), Ok(()));
        assert_eq!(check_claim_location(d.path(), "a.rs", Some(3)), Ok(()));
        assert_eq!(check_claim_location(d.path(), "a.rs", None), Ok(()));
        assert_eq!(
            check_claim_location(d.path(), "a.rs", Some(0)),
            Err("line_out_of_range")
        );
        assert_eq!(
            check_claim_location(d.path(), "a.rs", Some(4)),
            Err("line_out_of_range")
        );
    }

    #[test]
    fn check_claim_location_unsafe_paths() {
        let d = repo();
        for p in ["../x", "/etc/passwd", "C:\\x", "a\\b"] {
            assert_eq!(
                check_claim_location(d.path(), p, None),
                Err("unsafe_path"),
                "{p}"
            );
        }
    }

    #[test]
    fn check_claim_location_missing_and_secret() {
        let d = repo();
        assert_eq!(
            check_claim_location(d.path(), "nope.rs", None),
            Err("not_found")
        );
        std::fs::write(d.path().join(".env"), "K=v\n").unwrap();
        assert_eq!(
            check_claim_location(d.path(), ".env", Some(1)),
            Err("secret_file")
        );
    }

    #[test]
    fn check_claim_location_refuses_git_metadata_in_any_case() {
        let d = repo();
        std::fs::create_dir_all(d.path().join(".git")).unwrap();
        std::fs::write(d.path().join(".git/config"), "[core]\n").unwrap();
        std::fs::create_dir_all(d.path().join("sub/.git")).unwrap();
        std::fs::write(d.path().join("sub/.git/HEAD"), "ref: x\n").unwrap();
        for p in [
            ".git/config",
            ".GIT/config",
            "sub/.git/HEAD",
            "a/.Git/x",
            ".git",
        ] {
            assert_eq!(
                check_claim_location(d.path(), p, Some(1)),
                Err("git_metadata"),
                "{p}"
            );
        }
        // Only a whole `.git` component counts.
        std::fs::write(d.path().join(".gitignore"), "x\n").unwrap();
        assert_eq!(
            check_claim_location(d.path(), ".gitignore", Some(1)),
            Ok(())
        );
    }

    #[test]
    fn check_claim_location_refuses_windows_git_aliases() {
        let d = repo();
        for p in [
            ".git./config",
            ".git /config",
            ".GIT. ./config",
            "GIT~1/config",
            "sub/git~1/HEAD",
            "GIT~1./x",
        ] {
            assert_eq!(
                check_claim_location(d.path(), p, Some(1)),
                Err("git_metadata"),
                "{p}"
            );
        }
        // Lookalikes that are not aliases stay ordinary paths.
        assert_eq!(
            check_claim_location(d.path(), "git~2/x", None),
            Err("not_found")
        );
        assert_eq!(
            check_claim_location(d.path(), "a.git/x", None),
            Err("not_found")
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_claim_location_refuses_symlink_into_git_metadata() {
        let d = repo();
        std::fs::create_dir_all(d.path().join(".git")).unwrap();
        std::fs::write(d.path().join(".git/config"), "[core]\n").unwrap();
        std::fs::create_dir_all(d.path().join("docs")).unwrap();
        std::os::unix::fs::symlink("../.git/config", d.path().join("docs/sample.conf")).unwrap();
        std::os::unix::fs::symlink(".git", d.path().join("meta")).unwrap();
        assert_eq!(
            check_claim_location(d.path(), "docs/sample.conf", Some(1)),
            Err("git_metadata")
        );
        assert_eq!(
            check_claim_location(d.path(), "meta/config", Some(1)),
            Err("git_metadata")
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_claim_location_resolved_returns_the_symlink_target() {
        let d = repo();
        std::os::unix::fs::symlink("a.rs", d.path().join("b.rs")).unwrap();
        assert_eq!(
            super::check_claim_location_resolved(d.path(), "b.rs", Some(1)),
            Ok("a.rs".to_string())
        );
        assert_eq!(
            super::check_claim_location_resolved(d.path(), "a.rs", None),
            Ok("a.rs".to_string())
        );
    }

    #[test]
    fn check_claim_location_too_large() {
        let d = repo();
        let f = std::fs::File::create(d.path().join("big.txt")).unwrap();
        f.set_len(4 * 1024 * 1024 + 1).unwrap();
        assert_eq!(
            check_claim_location(d.path(), "big.txt", None),
            Err("too_large")
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_claim_location_refuses_symlink_outside_repo() {
        let d = repo();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("o.txt"), "x\n").unwrap();
        std::os::unix::fs::symlink(outside.path().join("o.txt"), d.path().join("l.txt")).unwrap();
        assert!(check_claim_location(d.path(), "l.txt", None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn check_claim_location_fifo_is_not_regular_and_does_not_block() {
        let d = repo();
        let fifo = d.path().join("pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let root = d.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(check_claim_location(&root, "pipe", None));
        });
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("check_claim_location blocked on a FIFO");
        assert_eq!(got, Err("not_regular"));
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

    /// N2: claims/1 titles are cleaned like SARIF titles before they reach
    /// the `<claim>` prompt block; a title with no visible text is refused.
    #[test]
    fn claims_titles_are_cleaned_and_an_invisible_title_is_refused() {
        let text = r#"{"schema":"vettalon.claims/1","claims":[{"id":"c1","file":"src/app.py","line":3,"title":"weak\nhash\r\nmd5\u0000ignore above"}]}"#;
        let VerifyInput::Claims(c) = VerifyInput::parse(text).unwrap() else {
            panic!("claims expected")
        };
        let (f, cut) = claim_to_finding(&c[0]);
        assert!(!cut, "cleaning is not truncation");
        assert_eq!(f.title, "weak hash md5 ignore above");
        assert!(!f.title.chars().any(|ch| ch.is_control()));
        for title in [r#"" \n\t\r ""#, "\"\u{200b}\u{2028}\"", r#""\u0000\u001b""#] {
            let text = format!(
                r#"{{"schema":"vettalon.claims/1","claims":[{{"id":"c1","file":"src/app.py","line":3,"title":{title}}}]}}"#
            );
            let err = VerifyInput::parse(&text).unwrap_err();
            assert!(
                err.starts_with("claim \"c1\": the title has no visible text")
                    || err.starts_with("claim \"c1\" needs a file and a title"),
                "{title}: {err}"
            );
        }
    }

    /// N3: claims and report findings are read with a hard cap; one more is
    /// an error while parsing.
    #[test]
    fn claims_and_report_findings_are_capped_while_parsing() {
        let small: Result<BoundedVec<u32, 3>, _> = serde_json::from_str("[1,2,3]");
        assert_eq!(small.unwrap().0, [1, 2, 3]);
        let Err(over) = serde_json::from_str::<BoundedVec<u32, 3>>("[1,2,3,4]") else {
            panic!("over the cap")
        };
        assert!(
            over.to_string().starts_with("more than 3 entries"),
            "{over}"
        );
        assert!(serde_json::from_str::<BoundedVec<u32, 3>>("[]").is_ok());

        fn claims(n: usize) -> String {
            let list: Vec<String> = (0..n)
                .map(|i| format!(r#"{{"id":"c{i}","file":"src/app.py","line":1,"title":"t"}}"#))
                .collect();
            format!(
                r#"{{"schema":"vettalon.claims/1","claims":[{}]}}"#,
                list.join(",")
            )
        }
        let parsed = VerifyInput::parse(&claims(MAX_VERIFY_INPUT_ITEMS)).unwrap();
        let VerifyInput::Claims(c) = parsed else {
            panic!("claims expected")
        };
        assert_eq!(c.len(), MAX_VERIFY_INPUT_ITEMS);
        let err = VerifyInput::parse(&claims(MAX_VERIFY_INPUT_ITEMS + 1)).unwrap_err();
        let want = format!("invalid claims file: more than {MAX_VERIFY_INPUT_ITEMS} entries");
        assert!(err.starts_with(&want), "{err}");

        let (one, _) = claim_to_finding(&c[0]);
        let finding = serde_json::to_string(&one).unwrap();
        let report = |n: usize| {
            let list = vec![finding.as_str(); n].join(",");
            format!(r#"{{"findings":[{list}]}}"#)
        };
        let parsed = VerifyInput::parse(&report(MAX_VERIFY_INPUT_ITEMS)).unwrap();
        let VerifyInput::Report(fs) = parsed else {
            panic!("report expected")
        };
        assert_eq!(fs.len(), MAX_VERIFY_INPUT_ITEMS);
        let err = VerifyInput::parse(&report(MAX_VERIFY_INPUT_ITEMS + 1)).unwrap_err();
        let want =
            format!("report findings do not parse: more than {MAX_VERIFY_INPUT_ITEMS} entries");
        assert!(err.starts_with(&want), "{err}");
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
                spend: None,
                all_severities: false,
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
        // `vettalon.verify/1` stays as it was for claims input.
        let json = serde_json::to_value(&out).unwrap();
        for key in [
            "sarif_skipped",
            "sarif_unreviewable",
            "sarif_dropped_locations",
            "sarif_duplicates",
            "time_budget_skipped",
        ] {
            assert!(json.get(key).is_none(), "{key}");
        }
        assert_eq!(json["input"], "claims");
    }

    fn sarif_log(results: &str) -> String {
        format!(
            r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"Semgrep OSS"}}}},"results":[{results}]}}]}}"#
        )
    }

    #[tokio::test]
    async fn sarif_results_are_reviewed_and_a_capped_cwe_needs_human() {
        let d = repo();
        std::fs::write(
            d.path().join("src/crypto.py"),
            "import hashlib\nh = hashlib.md5(pw)\n",
        )
        .unwrap();
        let results = r#"
          {"ruleId": "cmd", "level": "warning", "message": {"text": "os.system with input"},
           "properties": {"tags": ["CWE-78: OS Command Injection"]},
           "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"},
                                               "region": {"startLine": 3}}}]},
          {"ruleId": "md5", "level": "warning", "message": {"text": "weak hash"},
           "properties": {"tags": ["CWE-328: Use of Weak Hash"]},
           "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/crypto.py"},
                                               "region": {"startLine": 2}}}]},
          {"ruleId": "web", "message": {"text": "remote"},
           "locations": [{"physicalLocation": {"artifactLocation": {
             "uri": "https://example.com/a.py"}}}]}"#;
        let text = sarif_log(results);
        let input = VerifyInput::parse_bytes(text.as_bytes(), Some(d.path()));
        let fam = HashMap::new();
        let out = run_verify(
            d.path(),
            input.unwrap(),
            VerifyOptions {
                verifier: handle("g", "google", vec![Ok(REFUTED.into()), Ok(REFUTED.into())]),
                families: &fam,
                refuter_runs: 1,
                deadline: None,
                parse_retries: 1,
                policy: Default::default(),
                score: false,
                score_threshold: None,
                joern: None,
                spend: None,
                all_severities: false,
                trace: TraceLog::default(),
            },
        )
        .await;
        assert_eq!(out.input, "sarif");
        assert_eq!((out.reviewed, out.calls), (2, 2));
        assert_eq!(out.claim_ids, ["sarif-0-0", "sarif-0-1"]);
        assert_eq!(out.findings[0].status, FindingStatus::Refuted);
        let capped = &out.findings[1];
        assert_eq!(capped.status, FindingStatus::NeedsHuman);
        assert_eq!(capped.cwe.as_deref(), Some("CWE-328"));
        assert!(
            capped
                .evidence
                .iter()
                .any(|e| e.detail == "trust_policy: llm_refute_capped CWE-328")
        );
        assert_eq!(capped.found_by, vec!["external:Semgrep-OSS".to_string()]);
        // The https result cannot be reviewed: recorded, and incomplete.
        assert_eq!(out.sarif_unreviewable, 1);
        assert!(out.incomplete);
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["input"], "sarif");
        assert_eq!(json["sarif_skipped"][0]["result_id"], "sarif-0-2");
        assert_eq!(json["sarif_unreviewable"], 1);
        assert!(json.get("sarif_dropped_locations").is_none());
    }

    #[test]
    fn input_size_and_nesting_limits_apply_to_every_format() {
        let at_cap = [b'['; MAX_JSON_DEPTH];
        assert!(check_json_depth(&at_cap, MAX_JSON_DEPTH).is_ok());
        let deep = [b'{'; MAX_JSON_DEPTH + 1];
        let e = check_json_depth(&deep, MAX_JSON_DEPTH).unwrap_err();
        assert!(e.contains("deeper than 64"), "{e}");
        // Closing brackets inside a string do not lower the depth either.
        let tricky = format!(r#"["]]]]",{}"#, "[".repeat(MAX_JSON_DEPTH));
        assert!(check_json_depth(tricky.as_bytes(), MAX_JSON_DEPTH).is_err());
        let deep_claims = format!(
            r#"{{"schema":"vettalon.claims/1","claims":[],"x":{}{}}}"#,
            "[".repeat(100),
            "]".repeat(100)
        );
        assert!(
            VerifyInput::parse(&deep_claims)
                .unwrap_err()
                .contains("nested deeper")
        );
        let big = vec![b' '; VERIFY_INPUT_MAX_BYTES + 1];
        assert!(
            VerifyInput::parse_bytes(&big, None)
                .unwrap_err()
                .contains("larger than 32 MiB")
        );
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("big.json");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(VERIFY_INPUT_MAX_BYTES as u64 + 1).unwrap();
        assert!(read_input(&path).unwrap_err().contains("larger than"));
        std::fs::write(&path, claims_json("")).unwrap();
        let bytes = read_input(&path).unwrap();
        assert!(VerifyInput::parse_bytes(&bytes, None).is_ok());
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
            cwes: Vec::new(),
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
                spend: None,
                all_severities: false,
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
                spend: None,
                all_severities: false,
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
                spend: None,
                all_severities: false,
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
                spend: None,
                all_severities: false,
                trace: TraceLog::default(),
            },
        )
        .await;
        assert_eq!((out.calls, out.unverified), (1, 2));
        assert!(out.incomplete);
        assert_eq!(out.findings[0].status, FindingStatus::Candidate);
        assert_eq!(out.findings[1].status, FindingStatus::Candidate);
    }

    fn options<'a>(
        verifier: ModelHandle,
        families: &'a HashMap<String, String>,
        deadline: Option<Instant>,
    ) -> VerifyOptions<'a> {
        VerifyOptions {
            verifier,
            families,
            refuter_runs: 1,
            deadline,
            parse_retries: 1,
            policy: Default::default(),
            score: false,
            score_threshold: None,
            joern: None,
            spend: None,
            all_severities: false,
            trace: TraceLog::default(),
        }
    }

    /// M1 (b): past `--time-budget` no finding is started.
    #[tokio::test]
    async fn past_the_time_budget_no_further_finding_is_started() {
        let d = repo();
        let fam = HashMap::new();
        let two = claims_json(r#",{"id":"c2","file":"src/app.py","line":2,"title":"t"}"#);
        // An empty reply list: any call would panic.
        let out = run_verify(
            d.path(),
            VerifyInput::parse(&two).unwrap(),
            options(handle("g", "google", vec![]), &fam, Some(Instant::now())),
        )
        .await;
        assert_eq!((out.calls, out.reviewed), (0, 0));
        assert_eq!((out.unverified, out.time_budget_skipped), (2, 2));
        assert!(out.incomplete);
        for f in &out.findings {
            assert_eq!(f.status, FindingStatus::Candidate);
            assert!(
                f.evidence
                    .iter()
                    .any(|e| e.detail == format!("verify_error: {TIME_BUDGET_NOT_STARTED}")),
                "{:?}",
                f.evidence
            );
        }
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["time_budget_skipped"], 2);
        assert_eq!(json["incomplete"], true);
    }

    /// A reply that arrives after the deadline still counts; the next
    /// finding is not started.
    #[tokio::test]
    async fn the_deadline_is_checked_before_each_finding() {
        struct Slow;
        #[async_trait]
        impl LlmCaller for Slow {
            async fn complete(&self, _p: &str) -> crate::llm::Result<String> {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                Ok(REFUTED.to_string())
            }
        }
        let d = repo();
        let fam = HashMap::new();
        let two = claims_json(r#",{"id":"c2","file":"src/app.py","line":2,"title":"t"}"#);
        let slow = ModelHandle {
            id: "g".into(),
            family: "google".into(),
            caller: Arc::new(Slow),
        };
        let deadline = Instant::now() + std::time::Duration::from_millis(100);
        let out = run_verify(
            d.path(),
            VerifyInput::parse(&two).unwrap(),
            options(slow, &fam, Some(deadline)),
        )
        .await;
        assert_eq!((out.calls, out.reviewed), (1, 1));
        assert_eq!(out.findings[0].status, FindingStatus::Refuted);
        assert_eq!((out.unverified, out.time_budget_skipped), (1, 1));
        assert_eq!(out.findings[1].status, FindingStatus::Candidate);
        assert!(out.incomplete);
    }

    /// A fake that reports itself as a metered HTTP backend ("m", 1000 max
    /// output tokens). An empty reply list panics, so an unwanted call fails.
    struct MeteredReplies(Mutex<Vec<crate::llm::Result<String>>>, Option<String>);
    #[async_trait]
    impl LlmCaller for MeteredReplies {
        async fn complete(&self, _p: &str) -> crate::llm::Result<String> {
            self.0.lock().unwrap().remove(0)
        }
        fn meter_info(&self) -> Option<crate::llm::MeterInfo> {
            Some(crate::llm::MeterInfo {
                api_model: "m".into(),
                max_output_tokens: 1000,
                api_key_env: self.1.clone(),
            })
        }
    }

    fn metered_handle(replies: Vec<crate::llm::Result<String>>) -> ModelHandle {
        ModelHandle {
            id: "g".into(),
            family: "google".into(),
            caller: Arc::new(MeteredReplies(Mutex::new(replies), None)),
        }
    }

    fn guard(cap_usd: f64) -> Arc<SpendGuard> {
        let table = crate::llm::spend::PriceTable::parse(
            br#"{"schema":"vettalon.prices/1","retrieved":"2026-01-01","source":["test"],
                "models":{"m":{"input":1.0,"cached_input":0.1,"output":2.0}}}"#,
        )
        .unwrap();
        Arc::new(SpendGuard::new(cap_usd, table).unwrap())
    }

    /// `--refuter-runs-all-severities`: a Medium claim gets all configured
    /// runs; by default it gets one.
    #[tokio::test]
    async fn all_severities_applies_refuter_runs_to_a_medium_claim() {
        let d = repo();
        let fam = HashMap::new();
        for (all, want) in [(true, 3), (false, 1)] {
            let mut o = options(
                handle("g", "google", vec![Ok(REFUTED.into()); 3]),
                &fam,
                None,
            );
            o.refuter_runs = 3;
            o.all_severities = all;
            let out = run_verify(d.path(), VerifyInput::parse(&claims_json("")).unwrap(), o).await;
            assert_eq!(out.calls, want, "all_severities={all}");
            let json = serde_json::to_value(&out).unwrap();
            if all {
                assert_eq!(json["refuter_runs_all_severities"], true);
            } else {
                assert!(json.get("refuter_runs_all_severities").is_none());
            }
            assert!(json.get("spend").is_none());
            assert_eq!(out.findings[0].severity, Severity::Medium);
        }
    }

    /// A cap below one call's worst case: no model call, the claim stays
    /// unverified, and the output (with the spend summary) is still built.
    #[tokio::test]
    async fn a_tiny_spend_cap_stops_before_any_call_and_leaves_claims_unverified() {
        let d = repo();
        let fam = HashMap::new();
        let g = guard(0.000001);
        let mut o = options(metered_handle(vec![]), &fam, None);
        o.spend = Some(g.clone());
        let two = claims_json(r#",{"id":"c2","file":"src/app.py","line":2,"title":"t"}"#);
        let out = run_verify(d.path(), VerifyInput::parse(&two).unwrap(), o).await;
        assert_eq!(out.calls, 0);
        assert_eq!((out.reviewed, out.unverified), (1, 2));
        assert!(out.incomplete);
        for f in &out.findings {
            assert_eq!(f.status, FindingStatus::Candidate);
            assert!(f.verification.is_empty());
        }
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["spend"]["spent_usd"], 0.0);
        assert_eq!(json["spend"]["cap_usd"], 0.000001);
        assert_eq!(json["spend"]["calls_charged_worst_case"], 0);
    }

    /// A guarded run with a metered fake charges the call.
    #[tokio::test]
    async fn a_guarded_call_is_charged() {
        let d = repo();
        let fam = HashMap::new();
        let g = guard(1.0);
        let mut o = options(metered_handle(vec![Ok(REFUTED.into())]), &fam, None);
        o.spend = Some(g.clone());
        let out = run_verify(d.path(), VerifyInput::parse(&claims_json("")).unwrap(), o).await;
        assert_eq!(out.calls, 1);
        let s = out.spend.as_ref().unwrap();
        assert!(s.spent_usd > 0.0 && s.spent_usd <= 1.0);
        assert_eq!(s.calls_charged_worst_case, 1, "fake reports no usage");
    }

    /// A guard needs a metered verifier with a price; checked before any call.
    #[test]
    fn spend_guard_needs_a_metered_priced_verifier() {
        let g = guard(1.0);
        assert!(check_spend_ready(&metered_handle(vec![]), &g).is_ok());
        let e = check_spend_ready(&handle("g", "google", vec![]), &g).unwrap_err();
        assert!(e.contains("not metered"), "{e}");
        // Metered but unpriced: a table without model "m".
        let table = crate::llm::spend::PriceTable::parse(
            br#"{"schema":"vettalon.prices/1","retrieved":"2026-01-01","source":["t"],
                "models":{"other":{"input":1.0,"cached_input":0.1,"output":2.0}}}"#,
        )
        .unwrap();
        let other = SpendGuard::new(1.0, table).unwrap();
        let e = check_spend_ready(&metered_handle(vec![]), &other).unwrap_err();
        assert!(e.contains("no price"), "{e}");
    }

    /// Even if the early check were skipped, a non-metered caller under a
    /// guard makes zero calls.
    #[tokio::test]
    async fn a_non_metered_caller_under_a_guard_makes_no_call() {
        let d = repo();
        let fam = HashMap::new();
        let mut o = options(handle("g", "google", vec![]), &fam, None);
        o.spend = Some(guard(1.0));
        let out = run_verify(d.path(), VerifyInput::parse(&claims_json("")).unwrap(), o).await;
        assert_eq!((out.calls, out.unverified), (0, 1));
    }

    /// M1: a call billed far above its reservation pushes spend past the
    /// cap once; the summary says so and no further call goes out.
    #[tokio::test]
    async fn an_overbilled_call_trips_the_guard_and_is_reported() {
        struct OverBilled(std::sync::atomic::AtomicUsize);
        #[async_trait]
        impl LlmCaller for OverBilled {
            async fn complete(&self, p: &str) -> crate::llm::Result<String> {
                self.complete_metered(p).await.result
            }
            fn meter_info(&self) -> Option<crate::llm::MeterInfo> {
                Some(crate::llm::MeterInfo {
                    api_model: "m".into(),
                    max_output_tokens: 1000,
                    api_key_env: None,
                })
            }
            async fn complete_metered(&self, _p: &str) -> crate::llm::Metered {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                crate::llm::Metered {
                    result: Ok(REFUTED.into()),
                    // 1M output tokens at 2 USD/M = 2 USD, cap is 1 USD.
                    usage: Some(crate::llm::Usage {
                        input: 10,
                        cached_input: 0,
                        output: 1_000_000,
                        reasoning: Some(999_000),
                    }),
                    http_status: Some(200),
                }
            }
        }
        let d = repo();
        let fam = HashMap::new();
        let caller = Arc::new(OverBilled(std::sync::atomic::AtomicUsize::new(0)));
        let h = ModelHandle {
            id: "g".into(),
            family: "google".into(),
            caller: caller.clone(),
        };
        let mut o = options(h, &fam, None);
        let g = guard(1.0);
        o.spend = Some(g.clone());
        let two = claims_json(r#",{"id":"c2","file":"src/app.py","line":2,"title":"t"}"#);
        let out = run_verify(d.path(), VerifyInput::parse(&two).unwrap(), o).await;
        assert_eq!(caller.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(out.calls, 1);
        assert_eq!(out.findings[1].status, FindingStatus::Candidate);
        assert!(out.findings[1].verification.is_empty());
        assert!(out.incomplete);
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["spend"]["exceeded_cap"], true);
        assert_eq!(json["spend"]["over_reservation_calls"], 1);
        assert!(json["spend"]["spent_usd"].as_f64().unwrap() > 1.0);
    }

    /// The summary carries the new fields on an ordinary guarded run too.
    #[tokio::test]
    async fn spend_summary_reports_no_overshoot_by_default() {
        let d = repo();
        let fam = HashMap::new();
        let mut o = options(metered_handle(vec![Ok(REFUTED.into())]), &fam, None);
        o.spend = Some(guard(1.0));
        let out = run_verify(d.path(), VerifyInput::parse(&claims_json("")).unwrap(), o).await;
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["spend"]["exceeded_cap"], false);
        assert_eq!(json["spend"]["over_reservation_calls"], 0);
    }

    /// L6: a guard with a verifier whose key variable is unset is refused
    /// before any call; the message names the variable, never a value.
    #[test]
    fn spend_guard_needs_the_api_key_variable_set() {
        let g = guard(1.0);
        let var = "VETTALON_TEST_L6_KEY_DEFINITELY_UNSET";
        let h = ModelHandle {
            id: "g".into(),
            family: "google".into(),
            caller: Arc::new(MeteredReplies(Mutex::new(vec![]), Some(var.into()))),
        };
        let e = check_spend_ready(&h, &g).unwrap_err();
        assert!(e.contains(var) && e.contains("not set or empty"), "{e}");
        // No key variable configured (e.g. local server): fine.
        assert!(check_spend_ready(&metered_handle(vec![]), &g).is_ok());
    }

    /// M1 (c): `--max-claims` counts what would be reviewed, in every format.
    #[test]
    fn max_claims_counts_the_findings_up_for_review() {
        let two = VerifyInput::parse(&claims_json(
            r#",{"id":"c2","file":"src/app.py","line":2,"title":"t"}"#,
        ))
        .unwrap();
        assert_eq!(two.review_count(), 2);
        assert!(check_max_claims(&two, 2).is_ok());
        let e = check_max_claims(&two, 1).unwrap_err();
        assert!(e.contains("2 findings to review"), "{e}");
        assert!(e.contains("--max-claims 1"), "{e}");
        assert!(e.contains("no model was called"), "{e}");
        // SARIF: duplicates and skipped results do not count.
        let r = r#"{"ruleId": "r", "message": {"text": "m"},
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"},
                                              "region": {"startLine": 3}}}]}"#;
        let pass = r#"{"kind": "pass", "message": {"text": "m"}}"#;
        let sarif = VerifyInput::parse(&sarif_log(&format!("{r},{r},{r},{pass}"))).unwrap();
        assert_eq!(sarif.review_count(), 1);
        assert!(check_max_claims(&sarif, 1).is_ok());
        assert!(check_max_claims(&sarif, 0).is_err());
        // Report: only unreviewed ai_audit candidates.
        let mut fresh = Finding::candidate(
            super::super::schema::AI_AUDIT_ENGINE_NAME,
            FindingKind::Other,
            Severity::Medium,
            "x",
            "src/app.py",
            Some(3),
            "",
            "ai-audit/x",
            vec![],
        );
        let scanner = Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            Severity::High,
            "y",
            "src/app.py",
            Some(2),
            "",
            "r",
            vec![],
        );
        let mut refuted = fresh.clone();
        refuted.status = FindingStatus::Refuted;
        fresh.line = Some(1);
        let report = VerifyInput::Report(vec![fresh, scanner, refuted]);
        assert_eq!(report.review_count(), 1);
    }

    /// L2: the format is told from three top-level keys; each format is read
    /// straight into its typed structs.
    #[test]
    fn formats_are_routed_by_top_level_keys() {
        for not_an_object in ["[]", "\"x\"", "3", "null", " [{\"runs\": []}]"] {
            let e = VerifyInput::parse(not_an_object).unwrap_err();
            assert!(e.starts_with("input is neither"), "{not_an_object}: {e}");
        }
        for broken in ["{", "{\"runs\": [}", "[", ""] {
            let e = VerifyInput::parse(broken).unwrap_err();
            assert!(e.starts_with("input is not JSON"), "{broken:?}: {e}");
        }
        let both = VerifyInput::parse(r#"{"runs": [], "findings": []}"#).unwrap();
        assert!(matches!(both, VerifyInput::Report(ref f) if f.is_empty()));
        let e = VerifyInput::parse(r#"{"findings": null}"#).unwrap_err();
        assert!(e.starts_with("report findings do not parse"), "{e}");
        let e = VerifyInput::parse(r#"{"schema": "other/1", "runs": []}"#).unwrap_err();
        assert!(e.contains("no `version`"), "{e}");
        let e = VerifyInput::parse(r#"{"schema": 1, "claims": []}"#).unwrap_err();
        assert!(e.starts_with("input is neither"), "{e}");
        // A report keeps every finding; other keys are skipped.
        let report = format!(
            r#"{{"repo": "/r", "bulk": [{}], "findings": []}}"#,
            vec!["[]"; 10_000].join(",")
        );
        assert!(matches!(
            VerifyInput::parse(&report).unwrap(),
            VerifyInput::Report(_)
        ));
    }

    #[test]
    fn several_sarif_cwes_become_one_evidence_line() {
        let VerifyInput::Claims(mut c) = VerifyInput::parse(&claims_json("")).unwrap() else {
            panic!()
        };
        let (f, _) = claim_to_finding(&c[0]);
        assert!(f.evidence.is_empty(), "claims files never carry the list");
        c[0].cwes = vec!["CWE-319".into(), "CWE-614".into()];
        let (f, _) = claim_to_finding(&c[0]);
        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.evidence[0].kind, EvidenceKind::StaticHit);
        assert_eq!(f.evidence[0].detail, "sarif_cwes: CWE-319, CWE-614");
        c[0].cwes = (1..=20).map(|n| format!("CWE-{n}")).collect();
        let (f, _) = claim_to_finding(&c[0]);
        assert!(f.evidence[0].detail.ends_with("CWE-16 and 4 more"));
        // A claims file cannot set the list.
        let forged = r#"{"schema":"vettalon.claims/1","claims":[{"id":"x","file":"a","line":1,"title":"t","cwes":["CWE-327"]}]}"#;
        assert!(VerifyInput::parse(forged).is_err());
    }
}
