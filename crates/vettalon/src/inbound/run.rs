//! `run_intake`: extraction → claims/1 → refuter (verify) → optional
//! reproduction → optional duplicate lookups → one `vettalon.intake/1` value.
//!
//! Network use is limited to the model
//! provider inside `run_verify` and, with `check_duplicates`, the read-only
//! OSV / GitHub lookups of `disclose::dedupe`. The report text never reaches
//! a prompt, a container or the output (only its hash, size, format, the
//! masked one-line `report_summary` and terminal-safe location tokens do).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use super::extract::{self, Extraction, Overrides};
use crate::audit::schema::{Finding, FindingStatus};
use crate::audit::target_poc::{self, TargetPocOutcome};
use crate::audit::verify_only::{self, Claim, VerifyInput, VerifyOptions, VerifyOutput};
use crate::disclose::dedupe::{self, DedupeCheck, DedupeReport, DedupeSource};
use crate::disclose::scope::ScopeCheck;

pub(crate) const INTAKE_SCHEMA: &str = "vettalon.intake/1";
/// Largest operator TargetCall file read for `--target`.
const TARGET_FILE_MAX_BYTES: u64 = 8 * 1024;

/// Fixed text: what this output cannot be taken to mean.
pub(crate) const LIMITS: &[&str] = &[
    "refuted does not mean the report is false",
    "effect_absent or inconclusive does not mean not exploitable",
    "possibly_out_of_scope is a hint; a human decides",
    "no duplicate found does not mean novel",
    "pasted report text was not sent to the model provider or duplicate lookup services",
];

/// Operator `--target` reproduction settings.
#[derive(Debug)]
pub struct TargetSpec {
    pub target_path: PathBuf,
    pub receipt_out: crate::remediation::NewOutput,
    /// `None` = [`crate::sandbox::DEFAULT_POC_IMAGE`].
    pub poc_image: Option<String>,
    pub replays: u32,
}

pub struct IntakeRequest<'a> {
    pub repo_root: &'a Path,
    /// Already normalised by `extract::read_input` / `parse::normalize_input`.
    pub text: String,
    pub input_sha256: String,
    pub input_bytes: usize,
    pub overrides: Overrides,
    /// low|medium|high|critical; the reporter's stated severity is ignored.
    pub severity: String,
    pub claims_only: bool,
    /// `None` iff `claims_only`. Carries the verifier `ModelHandle`.
    pub verify_opts: Option<VerifyOptions<'a>>,
    pub target: Option<TargetSpec>,
    pub check_duplicates: bool,
}

#[derive(Debug, Serialize)]
pub struct InputInfo {
    pub sha256: String,
    pub bytes: usize,
    pub format: &'static str,
    pub sections: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct RepoInfo {
    pub commit: Option<String>,
    pub github: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reproduction {
    /// not_requested|unsupported_class|refused|effect_observed|effect_absent|inconclusive
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `observed/requested`.
    pub replays: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_sha256: Option<String>,
}

impl Reproduction {
    fn not_requested() -> Self {
        Self::not_run("not_requested", None, 0)
    }

    fn not_run(status: &'static str, reason: Option<&str>, requested: u32) -> Self {
        Reproduction {
            status,
            reason: reason.map(str::to_string),
            replays: format!("0/{requested}"),
            receipt_file: None,
            receipt_sha256: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Triage {
    pub located: bool,
    /// refuted|needs_human|unverified|not_run
    pub refuter: &'static str,
    pub trust_policy_capped: bool,
    /// Same value as `reproduction.status`.
    pub reproduction: &'static str,
    pub possibly_out_of_scope: bool,
    /// Any online lookup returned at least one result (a hint, not a match).
    pub possible_duplicates: bool,
}

#[derive(Debug, Serialize)]
pub struct IntakeOutput {
    pub schema: &'static str,
    pub vettalon_version: &'static str,
    pub created_at: String,
    pub input: InputInfo,
    pub repo: RepoInfo,
    pub report_summary: Option<String>,
    pub extraction: Extraction,
    /// The claims/1 document (its single claim carries the title).
    pub claims: Option<Value>,
    /// Filled by the CLI when `--claims-out` was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_file: Option<String>,
    /// The `vettalon.verify/1` output, embedded unchanged.
    pub verify: Option<VerifyOutput>,
    pub reproduction: Reproduction,
    pub scope_check: Option<ScopeCheck>,
    pub duplicates: DedupeReport,
    pub triage: Triage,
    pub files_sent_to_model: Vec<String>,
    pub limits: Vec<String>,
    pub incomplete: bool,
}

/// Run one intake. The verifier comes in `req.verify_opts` (the same
/// `VerifyOptions` `cmd_verify` builds). With `check_duplicates` the live
/// [`dedupe::HttpDedupeSource`] is used (read-only lookups).
///
/// Report-derived locations must be tracked by Git: the tracked set is read
/// once here (only when no operator `--location` was given) through the
/// validated read-only Git runner. Any failure leaves it `None`, which
/// refuses every report-derived location as `untracked`.
pub async fn run_intake(req: IntakeRequest<'_>) -> Result<IntakeOutput, String> {
    check_request(&req)?;
    let tracked = if req.overrides.locations.is_empty() {
        crate::audit::diff_scope::tracked_files(req.repo_root)
            .await
            .ok()
    } else {
        None
    };
    if req.check_duplicates {
        let src = dedupe::HttpDedupeSource::new();
        run_intake_with(req, Some(&src), tracked.as_ref()).await
    } else {
        run_intake_with(req, None, tracked.as_ref()).await
    }
}

/// Testable core: `dedupe_src` is used only when `req.check_duplicates`;
/// `tracked` is passed to [`extract::extract`].
pub(crate) async fn run_intake_with(
    req: IntakeRequest<'_>,
    dedupe_src: Option<&dyn DedupeSource>,
    tracked: Option<&HashSet<String>>,
) -> Result<IntakeOutput, String> {
    check_request(&req)?;
    let IntakeRequest {
        repo_root,
        text,
        input_sha256,
        input_bytes,
        overrides,
        severity,
        // Checked above: `verify_opts` is `None` exactly when claims-only.
        claims_only: _,
        verify_opts,
        target,
        check_duplicates,
    } = req;

    // 1. Local project facts only (git config / HEAD / policy files). The
    //    scope docs stay in `meta`; they never go into a prompt.
    let meta = crate::disclose::detect_project(repo_root);

    // 2. Deterministic extraction and the single claim.
    let ex = extract::extract(
        repo_root,
        meta.github.as_deref(),
        meta.commit.as_deref(),
        &text,
        &overrides,
        tracked,
    );
    // The raw text is not needed past this point.
    drop(text);
    let claims = extract::build_claims(&ex, &severity);

    let mut out = IntakeOutput {
        schema: INTAKE_SCHEMA,
        vettalon_version: env!("CARGO_PKG_VERSION"),
        created_at: chrono::Utc::now().to_rfc3339(),
        input: InputInfo {
            sha256: input_sha256,
            bytes: input_bytes,
            format: ex.format,
            sections: ex.sections.clone(),
        },
        repo: RepoInfo {
            commit: meta.commit.clone(),
            github: meta.github.clone(),
        },
        report_summary: ex.report_summary.clone(),
        extraction: ex,
        claims: None,
        claims_file: None,
        verify: None,
        reproduction: Reproduction::not_requested(),
        scope_check: None,
        duplicates: DedupeReport::not_requested(),
        triage: Triage {
            located: false,
            refuter: "not_run",
            trust_policy_capped: false,
            reproduction: "not_requested",
            possibly_out_of_scope: false,
            possible_duplicates: false,
        },
        files_sent_to_model: Vec::new(),
        limits: LIMITS.iter().map(|s| (*s).to_string()).collect(),
        incomplete: false,
    };

    let Some(claims) = claims else {
        // No accepted location: no claim, no model call, no container, no
        // lookup. The caller exits 1.
        if let Some(t) = &target {
            out.reproduction =
                Reproduction::not_run("refused", Some("no_verified_location"), t.replays);
            out.triage.reproduction = out.reproduction.status;
        }
        return Ok(out);
    };
    out.triage.located = true;

    // Same parse path as `claims_round_trip`.
    let bytes = serde_json::to_vec(&claims).map_err(|e| format!("cannot encode claims: {e}"))?;
    let input = VerifyInput::parse_bytes(&bytes, Some(repo_root))?;
    let claim: Claim = match &input {
        VerifyInput::Claims(c) if c.len() == 1 => c[0].clone(),
        _ => return Err("internal: claims did not round-trip to one claim".into()),
    };
    out.claims = Some(claims);

    // 3. `--claims-only` stops here.
    let Some(opts) = verify_opts else {
        return Ok(out);
    };

    // The claim as the candidate finding verify builds from it (unmodified:
    // used for scope, dedupe and reproduction, never written back).
    let (claim_finding, _) = verify_only::claim_to_finding(&claim);

    // 4. Scope hint (deterministic, local, never in a prompt).
    let scope = crate::disclose::scope::check(&meta.scope_docs, &claim_finding);
    out.triage.possibly_out_of_scope = scope.possibly_out_of_scope;
    out.scope_check = Some(scope);

    // 5. Refuter.
    let verify = verify_only::run_verify(repo_root, input, opts).await;
    if let Some(f) = verify.findings.first() {
        out.triage.refuter = refuter_label(f);
        out.triage.trust_policy_capped = crate::audit::trust_policy::capped_rule(f).is_some();
    }
    // `VerifyOutput` does not list the files whose excerpts went into the
    // prompt. `adversarial::review_with` reads the claim's file and each
    // trace step (= the claim's `locations`, all of which passed
    // `check_claim_location`), so that is the list, and only when at least
    // one model call was made. A model-corrected line or trace is re-read
    // after the reply for the finding's snippet; that text is not sent.
    if verify.calls > 0 {
        out.files_sent_to_model = claim_files(&claim);
        // Match the refuter: one primary window, plus unique (file, line)
        // windows for trace locations outside the primary file.
        let extra: HashSet<_> = claim
            .locations
            .iter()
            .filter(|l| l.file != claim.file)
            .map(|l| (&l.file, l.line))
            .collect();
        out.limits.push(format!(
            "{} source windows were sent to the configured model provider",
            1 + extra.len()
        ));
    }
    out.incomplete = verify.incomplete;
    out.verify = Some(verify);

    // 6. Reproduction (operator TargetCall only; never changes the status).
    if let Some(t) = target {
        out.reproduction = reproduce(repo_root, &claim_finding, t).await?;
        out.triage.reproduction = out.reproduction.status;
    }

    // 7. Duplicate lookups (read-only), only when asked for.
    if check_duplicates && let Some(src) = dedupe_src {
        let today = chrono::Local::now().date_naive();
        let cwe = crate::disclose::finding_cwe(&claim_finding);
        let report = dedupe::check(src, &meta, &claim_finding.file, cwe.as_deref(), today).await;
        out.triage.possible_duplicates = has_matches(&report);
        if let Some(limit) = duplicate_limit(&report) {
            out.limits.push(limit);
        }
        out.duplicates = report;
    }

    Ok(out)
}

fn duplicate_limit(report: &DedupeReport) -> Option<String> {
    let contacted = |check: &DedupeCheck| !matches!(check, DedupeCheck::NotChecked { .. });
    let mut services = Vec::new();
    if contacted(&report.osv) {
        services.push("OSV");
    }
    if contacted(&report.upstream_commits) || contacted(&report.open_issues_prs) {
        services.push("GitHub");
    }
    (!services.is_empty())
        .then(|| format!("duplicate lookups contacted {}", services.join(" and ")))
}

fn check_request(req: &IntakeRequest<'_>) -> Result<(), String> {
    extract::validate_overrides(&req.overrides)?;
    if !matches!(
        req.severity.as_str(),
        "low" | "medium" | "high" | "critical"
    ) {
        return Err("severity must be low, medium, high or critical".into());
    }
    match (req.claims_only, req.verify_opts.is_some()) {
        (true, true) => return Err("--claims-only does not take a verifier".into()),
        (false, false) => return Err("a verifier is required unless --claims-only".into()),
        _ => {}
    }
    if req.claims_only && (req.target.is_some() || req.check_duplicates) {
        return Err("--claims-only conflicts with --target and --check-duplicates".into());
    }
    Ok(())
}

fn refuter_label(f: &Finding) -> &'static str {
    match f.status {
        FindingStatus::Refuted => "refuted",
        FindingStatus::NeedsHuman => "needs_human",
        // Candidate with no verdict (zero-call refusal, failed call, time
        // budget); Confirmed/Suppressed never come out of verify.
        _ => "unverified",
    }
}

/// The claim's primary file then each location's file, deduplicated.
fn claim_files(c: &Claim) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in std::iter::once(&c.file).chain(c.locations.iter().map(|l| &l.file)) {
        if !out.contains(f) {
            out.push(f.clone());
        }
    }
    out
}

fn has_matches(r: &DedupeReport) -> bool {
    [&r.osv, &r.upstream_commits, &r.open_issues_prs]
        .iter()
        .any(|c| matches!(c, DedupeCheck::Checked { matches, .. } if !matches.is_empty()))
}

/// Reproduce with the operator's TargetCall. The report's PoC text is never
/// executed and never turned into a TargetCall. Pre-checks that fail start no
/// container. `finding` is the claim's candidate finding (status untouched).
async fn reproduce(
    repo_root: &Path,
    finding: &Finding,
    t: TargetSpec,
) -> Result<Reproduction, String> {
    use crate::audit::target_poc::{
        declares_top_level_async_function, declares_top_level_function, parse_target_call,
        read_target_source, validate_replays,
    };
    let n = t.replays;
    let refused = |reason: &str| -> Result<Reproduction, String> {
        Ok(Reproduction::not_run("refused", Some(reason), n))
    };
    let unsupported = |reason: &str| -> Result<Reproduction, String> {
        Ok(Reproduction::not_run("unsupported_class", Some(reason), n))
    };

    if validate_replays(n).is_err() {
        return refused("invalid_replay_count");
    }
    let raw = match crate::remediation::read_regular_capped(
        &t.target_path,
        TARGET_FILE_MAX_BYTES,
        "target",
    ) {
        Ok(raw) => raw,
        Err(_) => return refused("target_unreadable"),
    };
    let call = match parse_target_call(&raw) {
        Ok(call) => call,
        // Only Python targets can be reproduced.
        Err(code @ "unsupported_target_language") => return unsupported(code),
        Err(code) => return refused(code),
    };
    if call.file != finding.file {
        return refused("target_file_mismatch");
    }
    if crate::audit::poc_oracle::classify(finding).is_none() {
        return unsupported("unsupported_oracle_class");
    }
    if !finding.file.ends_with(".py") {
        return unsupported("unsupported_target_language");
    }
    // Rebind the source identity to the bytes on disk now (as `retest`
    // does): reproduce refuses with `stale_source` if they change before the
    // snapshot.
    let (source, hash) = match read_target_source(repo_root, &call.file) {
        Ok(v) => v,
        Err(code) => return refused(code),
    };
    if declares_top_level_async_function(&source, &call.function) {
        return refused("async_target_unsupported");
    }
    if !declares_top_level_function(&source, &call.function) {
        return refused("function_not_declared");
    }
    let mut bound = finding.clone();
    bound.file_hash = Some(hash);
    let image = t
        .poc_image
        .as_deref()
        .unwrap_or(crate::sandbox::DEFAULT_POC_IMAGE);
    let receipt = target_poc::run_target_poc_replayed(repo_root, &bound, &call, image, n, false)
        .await
        .receipt;
    // The container replay already ran (target_poc makes no model call). The
    // refuter result in `out.verify` is separate and unaffected. A receipt
    // that cannot be written is recorded, not an error that would drop the
    // whole result.
    let receipt_path = t.receipt_out.path().display().to_string();
    if t.receipt_out.write_json(&receipt).is_err() {
        return refused("receipt_write_failed");
    }
    // `write_new_remediation_output` writes exactly `to_vec_pretty(value)`.
    let Ok(encoded) = serde_json::to_vec_pretty(&receipt) else {
        return refused("receipt_write_failed");
    };
    let (outcome, reason) = receipt.derived_outcome();
    let summary = receipt.replay_summary();
    Ok(Reproduction {
        status: match outcome {
            TargetPocOutcome::EffectObserved => "effect_observed",
            TargetPocOutcome::EffectAbsent => "effect_absent",
            TargetPocOutcome::Inconclusive => "inconclusive",
        },
        reason,
        replays: format!("{}/{}", summary.observed, summary.requested),
        receipt_file: Some(receipt_path),
        receipt_sha256: Some(crate::audit::schema::sha256_hex(&encoded)),
    })
}

#[cfg(test)]
mod limits_tests {
    use super::*;

    #[test]
    fn duplicate_limits_distinguish_skipped_successful_and_failed_queries() {
        let mut report = DedupeReport::not_requested();
        assert_eq!(duplicate_limit(&report), None);
        report.osv = DedupeCheck::Checked {
            query: "package".into(),
            matches: vec![],
        };
        assert_eq!(
            duplicate_limit(&report).as_deref(),
            Some("duplicate lookups contacted OSV")
        );
        report.upstream_commits = DedupeCheck::Failed {
            query: "repo".into(),
            error: "timeout".into(),
        };
        assert_eq!(
            duplicate_limit(&report).as_deref(),
            Some("duplicate lookups contacted OSV and GitHub")
        );
        report.osv = DedupeReport::not_requested().osv;
        assert_eq!(
            duplicate_limit(&report).as_deref(),
            Some("duplicate lookups contacted GitHub")
        );
    }
}
