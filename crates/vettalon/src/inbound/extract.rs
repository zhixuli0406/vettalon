//! Report text → checked locations, CWE, neutral title and a claims/1 document.
//!
//! The report text is never used in the claim title; only operator input or a
//! fixed template built from verified facts is.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use serde::Serialize;

use super::parse::{self, INTAKE_INPUT_MAX_BYTES, LocationToken, Origin};
use crate::audit::verify_only::{self, VerifyInput};
use crate::audit::{cwe, sarif_input, trust_policy};

pub(crate) const MAX_LOCATIONS: usize = verify_only::MAX_CLAIM_LOCATIONS;
const TITLE_MAX_CHARS: usize = 200;
const SUMMARY_MAX_CHARS: usize = 300;
const TOKEN_MAX_BYTES: usize = 200;

pub enum InputSource<'a> {
    Path(&'a Path),
    Stdin,
}

/// Read, bound and normalise the report. Errors are short terminal-safe strings.
pub fn read_input(src: InputSource) -> Result<String, String> {
    use crate::util::RegularFileError;
    let cap = INTAKE_INPUT_MAX_BYTES as u64;
    let bytes = match src {
        InputSource::Path(p) => match crate::util::read_regular_file(p, cap + 1) {
            Ok(b) => b,
            Err(RegularFileError::NotRegular) => {
                return Err("input is not a regular file".to_string());
            }
            Err(RegularFileError::TooLarge) => {
                return Err(format!(
                    "input is larger than {INTAKE_INPUT_MAX_BYTES} bytes"
                ));
            }
            Err(RegularFileError::Io(e)) => {
                return Err(format!("cannot read input: {:?}", e.kind()));
            }
        },
        InputSource::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin()
                .take(cap + 1)
                .read_to_end(&mut buf)
                .map_err(|e| format!("cannot read stdin: {:?}", e.kind()))?;
            buf
        }
    };
    parse::normalize_input(&bytes).map_err(|code| match code {
        "too_large" => format!("input is larger than {INTAKE_INPUT_MAX_BYTES} bytes"),
        other => format!("input rejected: {other}"),
    })
}

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    /// From `--location FILE:LINE`, at most 10.
    pub locations: Vec<(String, Option<u32>)>,
    pub cwe: Option<String>,
    pub title: Option<String>,
    /// low|medium|high|critical (default medium).
    pub severity: Option<String>,
}

pub fn validate_overrides(ov: &Overrides) -> Result<(), String> {
    if ov.locations.len() > MAX_LOCATIONS {
        return Err(format!(
            "at most {MAX_LOCATIONS} --location values are allowed"
        ));
    }
    if let Some(c) = &ov.cwe
        && cwe::normalize(c).is_none()
    {
        return Err("--cwe is not a valid CWE id".to_string());
    }
    if let Some(t) = &ov.title {
        match sarif_input::clean_title(t) {
            None => return Err("--title has no visible text".to_string()),
            Some(c) if c.chars().count() > TITLE_MAX_CHARS => {
                return Err(format!(
                    "--title is longer than {TITLE_MAX_CHARS} characters"
                ));
            }
            Some(_) => {}
        }
    }
    if let Some(s) = &ov.severity
        && !matches!(s.as_str(), "low" | "medium" | "high" | "critical")
    {
        return Err("--severity must be low, medium, high or critical".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct LocationRecord {
    /// The checked repo path; `None` for every rejected record (its decoded
    /// path is report text).
    pub file: Option<String>,
    pub line: Option<u32>,
    /// "github_url" | "path_ref" | "operator"
    pub origin: &'static str,
    pub accepted: bool,
    pub reason: Option<&'static str>,
    /// Accepted records only: the checked `file[:line]`, rendered by us.
    /// Never raw report text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Rejected records only: hex SHA-256 of the raw candidate text, so a
    /// human can correlate it with the report without it being copied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_sha256: Option<String>,
}

impl LocationRecord {
    /// Build a record; `token` and `token_sha256` follow `reason`.
    fn new(
        file: &str,
        line: Option<u32>,
        origin: &'static str,
        reason: Option<&'static str>,
        raw: &str,
    ) -> Self {
        let accepted = reason.is_none();
        let rendered = match line {
            Some(n) => format!("{file}:{n}"),
            None => file.to_string(),
        };
        Self {
            file: accepted.then(|| file.to_string()),
            line,
            origin,
            accepted,
            reason,
            token: accepted.then(|| safe_token(&rendered)),
            token_sha256: (!accepted).then(|| crate::audit::schema::sha256_hex(raw.as_bytes())),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Extraction {
    pub format: &'static str,
    pub sections: Vec<&'static str>,
    pub cwe: Option<String>,
    /// "operator" | "single_mention" | "trust_policy_capped" | "first_mention" | "none"
    pub cwe_source: &'static str,
    pub cwe_mentions: Vec<String>,
    pub locations: Vec<LocationRecord>,
    pub candidates_truncated: bool,
    /// How report-derived locations were checked against the Git index:
    /// "git_index" (tracked set read), "git_unavailable" (no readable Git
    /// index, so every report-derived location is refused as `untracked`)
    /// or "not_used" (operator `--location` values only).
    pub tracked_check: &'static str,
    /// The first same-repository GitHub ref, only when it is short plain
    /// ASCII (`[A-Za-z0-9._/-]{1,100}`).
    pub report_ref: Option<String>,
    pub report_ref_differs: bool,
    /// Emitted in `claims`, not here.
    #[serde(skip)]
    pub title: String,
    /// "operator" | "neutral"
    pub title_source: &'static str,
    /// Emitted at the top level of the intake output, not here.
    #[serde(skip)]
    pub report_summary: Option<String>,
    /// Index into `locations` of the primary accepted location.
    #[serde(skip)]
    pub primary: Option<usize>,
}

fn safe_token(raw: &str) -> String {
    let s = crate::audit::retest::terminal_safe(raw);
    truncate_bytes(&s, TOKEN_MAX_BYTES)
}

fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn is_hex_ref(r: &str) -> bool {
    (7..=40).contains(&r.len()) && r.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `^[A-Za-z0-9._/-]{1,100}$`: the only ref form copied into the output.
fn is_plain_ref(r: &str) -> bool {
    (1..=100).contains(&r.len())
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

fn pick_cwe(ov: &Overrides, mentions: &[String]) -> (Option<String>, &'static str) {
    if let Some(c) = ov.cwe.as_deref().and_then(cwe::normalize) {
        return (Some(c), "operator");
    }
    if mentions.len() == 1 {
        return (Some(mentions[0].clone()), "single_mention");
    }
    if let Some(m) = mentions
        .iter()
        .find(|m| trust_policy::llm_refute_cap(Some(m.as_str())).is_some())
    {
        return (Some(m.clone()), "trust_policy_capped");
    }
    match mentions.first() {
        Some(m) => (Some(m.clone()), "first_mention"),
        None => (None, "none"),
    }
}

fn first_nonempty<'a>(lines: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    lines.map(str::trim).find(|l| !l.is_empty())
}

fn summary_of(text: &str, secs: &parse::Sections) -> Option<String> {
    let line = match secs.summary {
        Some((a, b)) => first_nonempty(text.lines().skip(a).take(b.saturating_sub(a))),
        None => first_nonempty(text.lines()),
    }?;
    let masked = crate::util::mask_sensitive_text(line);
    let shown = crate::disclose::show_invisible(&masked);
    Some(shown.chars().take(SUMMARY_MAX_CHARS).collect())
}

/// `tracked` is the Git index path set, read once per run. Report-derived
/// locations must be in it (else `untracked`); `None` (no readable Git
/// index) refuses every one of them. Operator `--location` values do not
/// need it.
pub(crate) fn extract(
    repo_root: &Path,
    repo_slug: Option<&str>,
    head_commit: Option<&str>,
    text: &str,
    ov: &Overrides,
    tracked: Option<&HashSet<String>>,
) -> Extraction {
    let (secs, fmt) = parse::sections(text);
    let mut present = Vec::new();
    if secs.summary.is_some() {
        present.push("summary");
    }
    if secs.details.is_some() {
        present.push("details");
    }
    if secs.poc.is_some() {
        present.push("poc");
    }
    if secs.impact.is_some() {
        present.push("impact");
    }
    let mentions = parse::cwe_mentions(text);
    let (cwe_id, cwe_source) = pick_cwe(ov, &mentions);

    let mut records: Vec<LocationRecord> = Vec::new();
    let mut line_idxs: Vec<Option<usize>> = Vec::new();
    let mut truncated = false;
    let mut report_ref: Option<String> = None;
    let mut report_ref_differs = false;
    let mut accepted = 0usize;
    let tracked_check = if !ov.locations.is_empty() {
        "not_used"
    } else if tracked.is_some() {
        "git_index"
    } else {
        "git_unavailable"
    };

    if !ov.locations.is_empty() {
        for (file, line) in ov.locations.iter().take(MAX_LOCATIONS) {
            let reason = verify_only::check_claim_location(repo_root, file, *line).err();
            let raw = match line {
                Some(n) => format!("{file}:{n}"),
                None => file.clone(),
            };
            records.push(LocationRecord::new(file, *line, "operator", reason, &raw));
            line_idxs.push(None);
        }
    } else {
        let (tokens, trunc) = parse::location_tokens(text);
        truncated = trunc;
        for t in &tokens {
            let (origin, res) = judge(
                repo_root,
                repo_slug,
                head_commit,
                t,
                &mut report_ref,
                &mut report_ref_differs,
            );
            let mut reason = res.as_ref().err().copied();
            if let Ok(resolved) = &res {
                // Only regular files Git tracks, both as named and after
                // symlinks: never a git-ignored local file, directly or
                // through a tracked link.
                let in_index = |p: &str| tracked.is_some_and(|set| set.contains(p));
                if !in_index(&t.file) || !in_index(resolved) {
                    reason = Some("untracked");
                }
            }
            if reason.is_none() {
                if accepted >= MAX_LOCATIONS {
                    reason = Some("over_cap");
                } else {
                    accepted += 1;
                }
            }
            // A rejected token's decoded path and raw text are report text:
            // neither is copied, only a digest of the raw text.
            records.push(LocationRecord::new(&t.file, t.line, origin, reason, &t.raw));
            line_idxs.push(Some(t.line_idx));
        }
    }

    let primary = if ov.locations.is_empty() {
        let in_details = |i: usize| {
            line_idxs[i]
                .zip(secs.details)
                .is_some_and(|(l, (a, b))| l >= a && l < b)
        };
        (0..records.len())
            .find(|&i| records[i].accepted && in_details(i))
            .or_else(|| (0..records.len()).find(|&i| records[i].accepted))
    } else {
        records.iter().position(|r| r.accepted)
    };

    let (title, title_source) = match ov.title.as_deref().and_then(sarif_input::clean_title) {
        Some(t) if t.chars().count() <= TITLE_MAX_CHARS => (t, "operator"),
        _ => (
            neutral_title(cwe_id.as_deref(), primary.map(|i| &records[i])),
            "neutral",
        ),
    };

    Extraction {
        format: fmt.as_str(),
        sections: present,
        cwe: cwe_id,
        cwe_source,
        cwe_mentions: mentions,
        locations: records,
        candidates_truncated: truncated,
        tracked_check,
        report_ref,
        report_ref_differs,
        title,
        title_source,
        report_summary: summary_of(text, &secs),
        primary,
    }
}

/// Returns (origin, resolved repo-relative path or rejection reason) for one
/// token.
fn judge(
    repo_root: &Path,
    repo_slug: Option<&str>,
    head_commit: Option<&str>,
    t: &LocationToken,
    report_ref: &mut Option<String>,
    differs: &mut bool,
) -> (&'static str, Result<String, &'static str>) {
    match t.origin {
        Origin::PathRef => (
            "path_ref",
            verify_only::check_claim_location_resolved(repo_root, &t.file, t.line),
        ),
        Origin::GithubUrl => {
            let same = match (t.github_slug.as_deref(), repo_slug) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => false,
            };
            if !same {
                return ("github_url", Err("foreign_repository"));
            }
            if let Some(r) = t.git_ref.as_deref() {
                if report_ref.is_none() && is_plain_ref(r) {
                    *report_ref = Some(r.to_string());
                }
                if is_hex_ref(r)
                    && let Some(h) = head_commit
                    && !h.to_ascii_lowercase().starts_with(&r.to_ascii_lowercase())
                {
                    *differs = true;
                }
            }
            (
                "github_url",
                verify_only::check_claim_location_resolved(repo_root, &t.file, t.line),
            )
        }
    }
}

fn neutral_title(cwe_id: Option<&str>, primary: Option<&LocationRecord>) -> String {
    let at = match primary {
        Some(LocationRecord {
            file: Some(f),
            line,
            ..
        }) => match line {
            Some(n) => format!(" reported at {f}:{n}"),
            None => format!(" reported at {f}"),
        },
        _ => " reported".to_string(),
    };
    match cwe_id {
        Some(c) => {
            let name = crate::kb::lookup(c).map(|e| e.name_en.as_str());
            match name {
                Some(n) => format!("{c} {n}{at}"),
                None => format!("{c}{at}"),
            }
        }
        None => format!("Unspecified weakness{at}"),
    }
}

pub(crate) fn build_claims(ex: &Extraction, severity: &str) -> Option<serde_json::Value> {
    let pi = ex.primary?;
    let p = ex.locations.get(pi)?;
    if !p.accepted {
        return None;
    }
    let file = p.file.as_ref()?;
    let extra: Vec<serde_json::Value> = ex
        .locations
        .iter()
        .enumerate()
        .filter(|(i, r)| *i != pi && r.accepted)
        .filter_map(|(_, r)| Some((r.file.as_ref()?, r.line?)))
        .take(MAX_LOCATIONS - 1)
        .map(|(f, l)| serde_json::json!({"file": f, "line": l}))
        .collect();
    let mut claim = serde_json::json!({
        "id": "intake-1",
        "file": file,
        "line": p.line,
        "title": ex.title,
        "severity": severity,
        "source": "intake",
    });
    let obj = claim.as_object_mut()?;
    if let Some(c) = &ex.cwe {
        obj.insert("cwe".into(), serde_json::json!(c));
    }
    if !extra.is_empty() {
        obj.insert("locations".into(), serde_json::Value::Array(extra));
    }
    let v = serde_json::json!({"schema": verify_only::CLAIMS_SCHEMA, "claims": [claim]});
    claims_round_trip(&v).ok()?;
    Some(v)
}

/// Serialise and parse with the real claims parser.
pub(crate) fn claims_round_trip(v: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    match VerifyInput::parse_bytes(&bytes, None)? {
        VerifyInput::Claims(c) if c.len() == 1 => Ok(()),
        _ => Err("not a single-claim claims/1 document".to_string()),
    }
}
