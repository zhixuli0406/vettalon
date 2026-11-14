//! SARIF 2.1.0 input for `vettalon verify`.
//!
//! A SARIF log from another scanner (Semgrep `--sarif`, CodeQL, gosec, Snyk
//! Code, an OpenAI Codex Security export, anthropics/claude-code-security-review,
//! or vettalon's own `scan --sarif`) becomes the same [`Claim`] list a
//! `vettalon.claims/1` file gives. Everything downstream is unchanged: each
//! claim is turned into a candidate by [`super::verify_only::claim_to_finding`]
//! and its file and line go through the non-LLM location check
//! (`SafeRepoPath`, the on-disk read and line-range check) before any model
//! call.
//!
//! The log is untrusted. Limits, all errors unless noted:
//! - the input size and JSON nesting depth checked for every verify input
//!   ([`super::verify_only::VERIFY_INPUT_MAX_BYTES`],
//!   [`super::verify_only::MAX_JSON_DEPTH`]);
//! - at most [`MAX_SARIF_RUNS`] runs and [`MAX_SARIF_RESULTS`] results,
//!   counted by a first pass that skips every value without keeping it;
//! - the log is then read into typed structs only (unknown fields are
//!   skipped, never kept; property bags keep only the keys read below), and
//!   every array or map that is kept is bounded: per run
//!   [`MAX_TOOL_EXTENSIONS`], [`MAX_TAXONOMIES`], [`MAX_COMPONENT_RULES`] per
//!   tool component, [`MAX_ARTIFACTS`], [`MAX_URI_BASES`]; per result
//!   [`MAX_RESULT_TAXA`], [`MAX_SUPPRESSIONS`]; per rule
//!   [`MAX_RULE_RELATIONSHIPS`]; per property list [`MAX_PROPERTY_LIST`];
//!   and [`MAX_SARIF_ENTRIES`] kept entries over the whole log;
//! - not errors, recorded as dropped locations: only the first
//!   [`READ_LOCATIONS`] `locations`, [`READ_CODE_FLOWS`] `codeFlows`,
//!   [`READ_THREAD_FLOWS`] `threadFlows` per flow and [`READ_FLOW_STEPS`]
//!   steps per thread flow are read (a claim keeps at most
//!   `MAX_CLAIM_LOCATIONS` trace locations anyway); the title is cut to
//!   `CLAIM_TITLE_MAX_BYTES` on a char boundary (`title_truncated`).
//!   `relatedLocations` and every other field are never read.
//!
//! Mapping per result (`runs[r].results[i]`):
//! - id `sarif-<r>-<i>`; title `message.text`, else the rule's
//!   `shortDescription.text`, else `ruleId`, with control characters,
//!   line breaks, U+2028/U+2029 and whitespace runs collapsed to one space;
//!   a candidate without visible characters (only U+200B, say) falls through
//!   to the next. `rule_id` = `ruleId`; source = `tool.driver.name` (ASCII
//!   letters, digits, `-`, `_`, `.`; at most [`SOURCE_NAME_MAX_CHARS`];
//!   other characters become `-`).
//! - vettalon's own export: a run whose `tool.driver.name` is exactly
//!   [`OWN_TOOL_NAME`]. Only there are `vettalon.*` result properties read
//!   (`vettalon.severity`, `vettalon.cwe`); another tool's log cannot set a
//!   severity or a CWE, or switch off a CWE source, through them.
//! - severity: vettalon's own `vettalon.severity`, else a CodeQL-style
//!   `security-severity` score on the result or its rule (≥ 9 critical, ≥ 7
//!   high, ≥ 4 medium, else low), else `level` (result, then the rule's
//!   `defaultConfiguration`): error → high, warning → medium, note / none →
//!   low.
//! - CWE: every CWE the result names is collected, in this order: result
//!   `taxa` of the `CWE` tool component, `vettalon.cwe` (own export only),
//!   result tags, then (not for the own export, whose rule tags are the
//!   union over every finding of the rule) rule tags, rule `relationships`
//!   whose target is in the `CWE` tool component (gosec) and the rule's
//!   `properties.cwe` string or list (Snyk Code). Tags are read only with an
//!   explicit marker (`external/cwe/cwe-079`, `CWE-79`, `CWE-89: …`); all
//!   ids are normalized by [`super::cwe`]. The claim's `cwe` is the first
//!   collected id, except that when any collected id is capped by the
//!   per-CWE trust policy ([`super::trust_policy`]) the first capped one is
//!   used, so the cap cannot be sidestepped by listing another CWE first.
//!   With more than one id, all of them are kept on the claim and recorded
//!   on the finding as a `sarif_cwes: CWE-a, CWE-b` evidence line.
//! - location: the first usable `locations[]` entry is the claimed file and
//!   line; further `locations[]` and `codeFlows[].threadFlows[].locations[]`
//!   become trace locations (deduplicated, at most `MAX_CLAIM_LOCATIONS`;
//!   once full, the rest are counted without being resolved).
//! - skipped, with a reason in `sarif_skipped`: `kind` pass / notApplicable /
//!   informational, a result suppressed in the log (a suppression with no
//!   status or `accepted`; `suppressed_in_source` for an `inSource` one), a
//!   result with the same file, line, rule id and CWE as an earlier one
//!   ([`DUPLICATE`], with `duplicate_of`), and a result with no usable
//!   location or title. The last group cannot be reviewed and makes the
//!   verify run incomplete.
//!
//! URIs (defence in depth; `SafeRepoPath` downstream stays the authority):
//! relative references are repo-relative after percent-decoding; `file:`
//! URIs (empty host or `localhost`) must name a file inside the repository
//! root given to `verify`; a `uriBaseId` is resolved only through
//! `originalUriBaseIds` entries that are `file:` URIs inside that root (each
//! resolved once per run), and is otherwise ignored (the uri is read as
//! repo-relative, which is how a `%SRCROOT%` from another checkout maps onto
//! this one). Paths from the log are compared by components with the root
//! as given and its canonical form only: they are never canonicalized or
//! otherwise looked up on the filesystem here, so a log cannot make the
//! reader touch (or automount) a path outside the repository. `file:` URIs
//! are mapped as Unix paths only. `..` segments, NUL, backslashes, queries,
//! fragments, absolute paths without `file:` and every other scheme
//! (`http:` …) are rejected for that location.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use vettalon_contract::safe_path::SafeRepoPath;
use vettalon_contract::visible_text::has_visible_content;

use super::schema::Severity;
use super::verify_only::{Claim, ClaimLocation, MAX_CLAIM_LOCATIONS};

/// The only SARIF version read.
pub const SARIF_VERSION: &str = "2.1.0";
/// Most `runs` in one log.
pub const MAX_SARIF_RUNS: usize = 32;
/// Most `results` across all runs of one log.
pub const MAX_SARIF_RESULTS: usize = 5_000;
/// Most entries kept over every bounded array and map of one log.
pub const MAX_SARIF_ENTRIES: usize = 500_000;
/// Most `tool.extensions` per run.
pub const MAX_TOOL_EXTENSIONS: usize = 64;
/// Most `taxonomies` per run.
pub const MAX_TAXONOMIES: usize = 64;
/// Most `rules` per tool component.
pub const MAX_COMPONENT_RULES: usize = 10_000;
/// Most `artifacts` per run.
pub const MAX_ARTIFACTS: usize = 50_000;
/// Most `originalUriBaseIds` entries per run.
pub const MAX_URI_BASES: usize = 64;
/// Most `taxa` per result.
pub const MAX_RESULT_TAXA: usize = 32;
/// Most `suppressions` per result.
pub const MAX_SUPPRESSIONS: usize = 16;
/// Most `relationships` per rule.
pub const MAX_RULE_RELATIONSHIPS: usize = 64;
/// Most items in a property list (`tags`, `cwe`).
pub const MAX_PROPERTY_LIST: usize = 256;
/// `locations` read per result; the rest are counted.
pub const READ_LOCATIONS: usize = 16;
/// `codeFlows` read per result; the rest are counted.
pub const READ_CODE_FLOWS: usize = 2;
/// `threadFlows` read per code flow; the rest are counted.
pub const READ_THREAD_FLOWS: usize = 2;
/// Steps read per thread flow; the rest are counted.
pub const READ_FLOW_STEPS: usize = 32;
/// Longest `source` (tool name) kept on a claim.
pub const SOURCE_NAME_MAX_CHARS: usize = 64;
/// `tool.driver.name` of vettalon's own SARIF export.
pub const OWN_TOOL_NAME: &str = "vettalon";
/// `sarif_skipped` reason of a result that repeats an earlier claim.
pub const DUPLICATE: &str = "duplicate";
/// `sarif_skipped` reason of a result with an accepted `inSource` suppression.
pub const SUPPRESSED_IN_SOURCE: &str = "suppressed_in_source";
/// Evidence `detail` prefix listing every CWE a SARIF result named.
pub const SARIF_CWES_PREFIX: &str = "sarif_cwes:";
/// `source` when the tool has no usable name.
const DEFAULT_SOURCE: &str = "sarif";
/// Reasons kept per note; the rest are counted.
const MAX_NOTE_REASONS: usize = 3;
/// Cap on untrusted text quoted in a reason.
const QUOTED_MAX_BYTES: usize = 40;

/// One SARIF result that was skipped or lost locations, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SarifNote {
    /// `sarif-<run>-<result>`, the id the claim has (or would have had).
    pub result_id: String,
    pub reason: String,
    /// [`DUPLICATE`] only: the id of the claim this result repeats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<String>,
}

impl SarifNote {
    fn new(result_id: String, reason: String) -> Self {
        SarifNote {
            result_id,
            reason,
            duplicate_of: None,
        }
    }
}

/// A SARIF log as claims.
#[derive(Debug, Default)]
pub struct SarifClaims {
    pub claims: Vec<Claim>,
    /// Results not turned into a claim, in log order.
    pub skipped: Vec<SarifNote>,
    /// Of `skipped`: findings that could not be reviewed (no usable location
    /// or title), as opposed to results that are not findings or repeats.
    pub unreviewable: usize,
    /// Of `skipped`: repeats of an earlier claim ([`DUPLICATE`]).
    pub duplicates: usize,
    /// Claims that lost some locations (unusable, or over the cap).
    pub dropped_locations: Vec<SarifNote>,
}

/// Convert a SARIF 2.1.0 log (`text` is already known to be UTF-8 JSON
/// within the verify input limits). `repo_root` is the directory `verify`
/// reviews; without it `file:` URIs cannot be mapped and are dropped.
pub fn from_json(text: &str, repo_root: Option<&Path>) -> Result<SarifClaims, String> {
    // Pass 1: version and counts, skipping every value without keeping it.
    let head: Head = serde_json::from_str(text).map_err(|e| format!("invalid SARIF log: {e}"))?;
    match &head.version {
        Peek::Str(s) if s == SARIF_VERSION => {}
        Peek::Absent => {
            return Err(format!(
                "the SARIF log has no `version`; `vettalon verify` reads SARIF {SARIF_VERSION} only"
            ));
        }
        other => {
            return Err(format!(
                "unsupported SARIF version {}; `vettalon verify` reads SARIF {SARIF_VERSION} only",
                other.describe()
            ));
        }
    }
    let RunsHead::Runs { runs, results } = head.runs else {
        return Err("SARIF `runs` is not an array".to_string());
    };
    if runs > MAX_SARIF_RUNS {
        return Err(format!(
            "the SARIF log has {runs} runs (max {MAX_SARIF_RUNS})"
        ));
    }
    if results > MAX_SARIF_RESULTS {
        return Err(format!(
            "the SARIF log has {results} results (max {MAX_SARIF_RESULTS})"
        ));
    }
    // Pass 2: the typed subset, every kept collection bounded.
    ENTRIES.with(|n| n.set(0));
    let log = serde_json::from_str::<Log>(text);
    ENTRIES.with(|n| n.set(0));
    let log = log.map_err(|e| format!("invalid SARIF log: {e}"))?;
    let canonical_root = repo_root.and_then(|r| r.canonicalize().ok());
    let mut out = SarifClaims::default();
    let mut seen: HashMap<DedupeKey, String> = HashMap::new();
    for (run_idx, run) in log.runs.iter().enumerate() {
        let ctx = RunCtx::new(run_idx, run, repo_root, canonical_root.as_deref());
        ctx.convert_all(&mut out, &mut seen);
    }
    Ok(out)
}

// ── bounded, lenient readers ────────────────────────────────────────────

thread_local! {
    /// Entries kept so far by the typed pass running on this thread
    /// ([`MAX_SARIF_ENTRIES`]); reset around every log.
    static ENTRIES: Cell<usize> = const { Cell::new(0) };
}

/// Count one kept entry against [`MAX_SARIF_ENTRIES`].
fn take_entry<E: de::Error>() -> Result<(), E> {
    ENTRIES.with(|n| {
        let next = n.get().saturating_add(1);
        if next > MAX_SARIF_ENTRIES {
            return Err(E::custom(format!(
                "the SARIF log has more than {MAX_SARIF_ENTRIES} array and map entries"
            )));
        }
        n.set(next);
        Ok(())
    })
}

/// `null` reads as the default (some producers write `"tool": null`).
fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A JSON value read only far enough to route or check an input: a string
/// is kept, a number / `true` / `false` / `null` is kept as its JSON text,
/// an array or object is skipped without being materialised.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Peek {
    /// The key is missing.
    #[default]
    Absent,
    Str(String),
    /// A number (floats in Rust `Debug` form, `3.0`), `true`, `false` or
    /// `null`.
    Scalar(String),
    Array,
    Object,
}

impl Peek {
    pub fn is_present(&self) -> bool {
        !matches!(self, Peek::Absent)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Peek::Str(s) => Some(s),
            _ => None,
        }
    }

    fn describe(&self) -> String {
        match self {
            Peek::Absent => "(none)".to_string(),
            Peek::Str(s) => format!("{:?}", crate::util::truncate_bytes(s, QUOTED_MAX_BYTES)),
            Peek::Scalar(s) => crate::util::truncate_bytes(s, QUOTED_MAX_BYTES).to_string(),
            Peek::Array => "(an array)".to_string(),
            Peek::Object => "(an object)".to_string(),
        }
    }
}

impl<'de> Deserialize<'de> for Peek {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis;
        impl<'de> Visitor<'de> for Vis {
            type Value = Peek;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Peek, E> {
                Ok(Peek::Scalar(v.to_string()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Peek, E> {
                Ok(Peek::Scalar(v.to_string()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Peek, E> {
                Ok(Peek::Scalar(v.to_string()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Peek, E> {
                Ok(Peek::Scalar(format!("{v:?}")))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Peek, E> {
                Ok(Peek::Str(v.to_owned()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Peek, E> {
                Ok(Peek::Scalar("null".to_string()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Peek, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Peek::Array)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Peek, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Peek::Object)
            }
        }
        d.deserialize_any(Vis)
    }
}

/// A SARIF array of at most `N` entries (`null` reads as empty); one more is
/// an error. Every kept entry counts against [`MAX_SARIF_ENTRIES`].
struct Capped<T, const N: usize>(Vec<T>);

/// A SARIF array of which the first `N` entries are read; the rest are
/// skipped without being kept and counted in `skipped`.
struct Kept<T, const N: usize> {
    items: Vec<T>,
    skipped: usize,
}

impl<T, const N: usize> Default for Capped<T, N> {
    fn default() -> Self {
        Capped(Vec::new())
    }
}

impl<T, const N: usize> Default for Kept<T, N> {
    fn default() -> Self {
        Kept {
            items: Vec::new(),
            skipped: 0,
        }
    }
}

impl<T, const N: usize> std::ops::Deref for Capped<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T, const N: usize> std::ops::Deref for Kept<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.items
    }
}

/// Reads `[...]` or `null` into at most `N` kept entries; past `N`, an error
/// when `STRICT`, else the rest are skipped and counted.
struct BoundedSeq<T, const N: usize, const STRICT: bool>(PhantomData<T>);

impl<'de, T: Deserialize<'de>, const N: usize, const STRICT: bool> Visitor<'de>
    for BoundedSeq<T, N, STRICT>
{
    type Value = (Vec<T>, usize);

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "an array (at most {N} entries) or null")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok((Vec::new(), 0))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok((Vec::new(), 0))
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        let mut skipped = 0usize;
        loop {
            if items.len() < N {
                match seq.next_element::<T>()? {
                    Some(item) => {
                        take_entry::<A::Error>()?;
                        items.push(item);
                    }
                    None => break,
                }
            } else if seq.next_element::<IgnoredAny>()?.is_some() {
                if STRICT {
                    return Err(de::Error::custom(format!(
                        "a SARIF array has more than {N} entries, the most read for this field"
                    )));
                }
                skipped += 1;
            } else {
                break;
            }
        }
        Ok((items, skipped))
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Capped<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (items, _) = d.deserialize_option(BoundedSeq::<T, N, true>(PhantomData))?;
        Ok(Capped(items))
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Kept<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (items, skipped) = d.deserialize_option(BoundedSeq::<T, N, false>(PhantomData))?;
        Ok(Kept { items, skipped })
    }
}

/// A SARIF object map of at most `N` keys (`null` reads as empty).
struct CappedMap<V, const N: usize>(HashMap<String, V>);

impl<V, const N: usize> Default for CappedMap<V, N> {
    fn default() -> Self {
        CappedMap(HashMap::new())
    }
}

impl<'de, V: Deserialize<'de>, const N: usize> Deserialize<'de> for CappedMap<V, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis<V, const N: usize>(PhantomData<V>);
        impl<'de, V: Deserialize<'de>, const N: usize> Visitor<'de> for Vis<V, N> {
            type Value = CappedMap<V, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an object (at most {N} keys) or null")
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(CappedMap::default())
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(CappedMap::default())
            }
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                d.deserialize_map(self)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out: HashMap<String, V> = HashMap::new();
                while let Some((k, v)) = map.next_entry::<String, V>()? {
                    if out.len() >= N && !out.contains_key(&k) {
                        return Err(de::Error::custom(format!(
                            "a SARIF object has more than {N} keys, the most read for this field"
                        )));
                    }
                    take_entry::<A::Error>()?;
                    out.insert(k, v);
                }
                Ok(CappedMap(out))
            }
        }
        d.deserialize_option(Vis::<V, N>(PhantomData))
    }
}

/// A producer-defined property bag: read as `T` when it is an object, as
/// `T::default()` otherwise (nothing in it is kept beyond `T`'s fields).
struct Bag<T>(T);

impl<T: Default> Default for Bag<T> {
    fn default() -> Self {
        Bag(T::default())
    }
}

impl<'de, T: Deserialize<'de> + Default> Deserialize<'de> for Bag<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de> + Default> Visitor<'de> for Vis<T> {
            type Value = Bag<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a property bag")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Bag<T>, A::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Bag)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Bag<T>, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Bag::default())
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Bag<T>, E> {
                Ok(Bag::default())
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Bag<T>, E> {
                Ok(Bag::default())
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Bag<T>, E> {
                Ok(Bag::default())
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Bag<T>, E> {
                Ok(Bag::default())
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Bag<T>, E> {
                Ok(Bag::default())
            }
            fn visit_unit<E: de::Error>(self) -> Result<Bag<T>, E> {
                Ok(Bag::default())
            }
        }
        d.deserialize_any(Vis::<T>(PhantomData))
    }
}

/// A property that is a string or a list (strings kept, anything else in it
/// skipped; at most [`MAX_PROPERTY_LIST`] items); other values read as empty.
#[derive(Default)]
struct LooseStrings(Vec<String>);

impl<'de> Deserialize<'de> for LooseStrings {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis;
        impl<'de> Visitor<'de> for Vis {
            type Value = LooseStrings;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string or a list of strings")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<LooseStrings, E> {
                take_entry::<E>()?;
                Ok(LooseStrings(vec![v.to_owned()]))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<LooseStrings, A::Error> {
                let mut out = Vec::new();
                let mut items = 0usize;
                while let Some(item) = seq.next_element::<Peek>()? {
                    items += 1;
                    if items > MAX_PROPERTY_LIST {
                        return Err(de::Error::custom(format!(
                            "a SARIF property list has more than {MAX_PROPERTY_LIST} items"
                        )));
                    }
                    if let Peek::Str(s) = item {
                        take_entry::<A::Error>()?;
                        out.push(s);
                    }
                }
                Ok(LooseStrings(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<LooseStrings, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(LooseStrings::default())
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<LooseStrings, E> {
                Ok(LooseStrings::default())
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<LooseStrings, E> {
                Ok(LooseStrings::default())
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<LooseStrings, E> {
                Ok(LooseStrings::default())
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<LooseStrings, E> {
                Ok(LooseStrings::default())
            }
            fn visit_unit<E: de::Error>(self) -> Result<LooseStrings, E> {
                Ok(LooseStrings::default())
            }
        }
        d.deserialize_any(Vis)
    }
}

// ── pass 1: version and counts ──────────────────────────────────────────

#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    version: Peek,
    #[serde(default)]
    runs: RunsHead,
}

#[derive(Default)]
enum RunsHead {
    #[default]
    Missing,
    NotArray,
    Runs {
        runs: usize,
        results: usize,
    },
}

impl<'de> Deserialize<'de> for RunsHead {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis;
        impl<'de> Visitor<'de> for Vis {
            type Value = RunsHead;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the SARIF `runs` array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<RunsHead, A::Error> {
                let (mut runs, mut results) = (0usize, 0usize);
                while let Some(run) = seq.next_element::<RunHead>()? {
                    runs += 1;
                    results = results.saturating_add(run.results.0);
                }
                Ok(RunsHead::Runs { runs, results })
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RunsHead, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(RunsHead::NotArray)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<RunsHead, E> {
                Ok(RunsHead::NotArray)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<RunsHead, E> {
                Ok(RunsHead::NotArray)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<RunsHead, E> {
                Ok(RunsHead::NotArray)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<RunsHead, E> {
                Ok(RunsHead::NotArray)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<RunsHead, E> {
                Ok(RunsHead::NotArray)
            }
            fn visit_unit<E: de::Error>(self) -> Result<RunsHead, E> {
                Ok(RunsHead::NotArray)
            }
        }
        d.deserialize_any(Vis)
    }
}

#[derive(Deserialize)]
struct RunHead {
    #[serde(default)]
    results: ResultCount,
}

/// Length of a `results` array (`null` is 0), elements skipped.
#[derive(Default)]
struct ResultCount(usize);

impl<'de> Deserialize<'de> for ResultCount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis;
        impl<'de> Visitor<'de> for Vis {
            type Value = ResultCount;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the SARIF `results` array or null")
            }
            fn visit_none<E: de::Error>(self) -> Result<ResultCount, E> {
                Ok(ResultCount(0))
            }
            fn visit_unit<E: de::Error>(self) -> Result<ResultCount, E> {
                Ok(ResultCount(0))
            }
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<ResultCount, D2::Error> {
                d.deserialize_seq(self)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ResultCount, A::Error> {
                let mut n = 0usize;
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    n += 1;
                }
                Ok(ResultCount(n))
            }
        }
        d.deserialize_option(Vis)
    }
}

// ── pass 2: typed subset of SARIF 2.1.0 (unknown fields skipped) ────────

#[derive(Deserialize)]
struct Log {
    #[serde(default)]
    runs: Capped<Run, MAX_SARIF_RUNS>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Run {
    #[serde(default, deserialize_with = "nullable")]
    tool: Tool,
    #[serde(default)]
    results: Capped<SarifResult, MAX_SARIF_RESULTS>,
    #[serde(default)]
    original_uri_base_ids: CappedMap<ArtifactLocation, MAX_URI_BASES>,
    #[serde(default)]
    artifacts: Capped<Artifact, MAX_ARTIFACTS>,
    #[serde(default)]
    taxonomies: Capped<ToolComponent, MAX_TAXONOMIES>,
}

#[derive(Deserialize, Default)]
struct Tool {
    #[serde(default, deserialize_with = "nullable")]
    driver: ToolComponent,
    #[serde(default)]
    extensions: Capped<ToolComponent, MAX_TOOL_EXTENSIONS>,
}

#[derive(Deserialize, Default)]
struct ToolComponent {
    name: Option<String>,
    #[serde(default)]
    rules: Capped<Rule, MAX_COMPONENT_RULES>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: Option<String>,
    short_description: Option<Message>,
    default_configuration: Option<ReportingConfiguration>,
    #[serde(default)]
    relationships: Capped<Relationship, MAX_RULE_RELATIONSHIPS>,
    #[serde(default)]
    properties: Bag<RuleProps>,
}

/// The rule property-bag keys read; everything else is skipped.
#[derive(Deserialize, Default)]
struct RuleProps {
    #[serde(default)]
    tags: LooseStrings,
    #[serde(default, rename = "security-severity")]
    security_severity: Option<Peek>,
    /// Snyk Code: `"cwe": ["CWE-916"]` (or one string).
    #[serde(default)]
    cwe: LooseStrings,
}

/// The result property-bag keys read; everything else is skipped.
#[derive(Deserialize, Default)]
struct ResultProps {
    #[serde(default)]
    tags: LooseStrings,
    #[serde(default, rename = "security-severity")]
    security_severity: Option<Peek>,
    /// Own export only.
    #[serde(default, rename = "vettalon.severity")]
    vettalon_severity: Option<Peek>,
    /// Own export only.
    #[serde(default, rename = "vettalon.cwe")]
    vettalon_cwe: Option<Peek>,
}

#[derive(Deserialize, Default)]
struct Relationship {
    target: Option<DescriptorRef>,
}

#[derive(Deserialize, Default)]
struct ReportingConfiguration {
    level: Option<Peek>,
}

#[derive(Deserialize, Default)]
struct Message {
    text: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: Option<String>,
    rule_index: Option<i64>,
    rule: Option<DescriptorRef>,
    kind: Option<Peek>,
    level: Option<Peek>,
    message: Option<Message>,
    #[serde(default)]
    locations: Kept<Location, READ_LOCATIONS>,
    #[serde(default)]
    code_flows: Kept<CodeFlow, READ_CODE_FLOWS>,
    #[serde(default)]
    taxa: Capped<DescriptorRef, MAX_RESULT_TAXA>,
    #[serde(default)]
    suppressions: Capped<Suppression, MAX_SUPPRESSIONS>,
    #[serde(default)]
    properties: Bag<ResultProps>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DescriptorRef {
    id: Option<String>,
    index: Option<i64>,
    tool_component: Option<ComponentRef>,
}

#[derive(Deserialize, Default)]
struct ComponentRef {
    name: Option<String>,
    index: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: Option<PhysicalLocation>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: Option<ArtifactLocation>,
    region: Option<Region>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: Option<String>,
    uri_base_id: Option<String>,
    index: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: Option<Peek>,
}

#[derive(Deserialize, Default)]
struct Artifact {
    location: Option<ArtifactLocation>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CodeFlow {
    #[serde(default)]
    thread_flows: Kept<ThreadFlow, READ_THREAD_FLOWS>,
}

#[derive(Deserialize, Default)]
struct ThreadFlow {
    #[serde(default)]
    locations: Kept<ThreadFlowLocation, READ_FLOW_STEPS>,
}

#[derive(Deserialize, Default)]
struct ThreadFlowLocation {
    location: Option<Location>,
}

#[derive(Deserialize, Default)]
struct Suppression {
    kind: Option<Peek>,
    status: Option<Peek>,
}

// ── conversion ──────────────────────────────────────────────────────────

/// What makes two claims the same review: file, line, rule id and CWE.
type DedupeKey = (String, Option<u32>, Option<String>, Option<String>);

/// Why a result did not become a claim.
enum Skip {
    /// Not a finding (passed check, suppressed in the log).
    NotAFinding(String),
    /// A finding that cannot be reviewed.
    Unreviewable(String),
}

/// Location reasons for one claim, capped.
#[derive(Default)]
struct Dropped {
    reasons: Vec<String>,
    more: usize,
}

impl Dropped {
    fn add(&mut self, reason: String) {
        if self.reasons.len() < MAX_NOTE_REASONS {
            self.reasons.push(reason);
        } else {
            self.more += 1;
        }
    }

    fn is_empty(&self) -> bool {
        self.reasons.is_empty() && self.more == 0
    }

    fn summary(&self) -> String {
        let mut s = self.reasons.join("; ");
        if self.more > 0 {
            s.push_str(&format!("; and {} more", self.more));
        }
        s
    }
}

struct RunCtx<'a> {
    run_idx: usize,
    run: &'a Run,
    repo_root: Option<&'a Path>,
    canonical_root: Option<&'a Path>,
    rules_by_id: HashMap<&'a str, &'a Rule>,
    /// `tool.extensions` by name, first one wins (built once per run).
    extensions_by_name: HashMap<&'a str, &'a ToolComponent>,
    /// Each `originalUriBaseIds` entry resolved once: the repo-relative
    /// directory (`""` for the root) of a `file:` base inside the root.
    base_prefixes: HashMap<&'a str, Option<String>>,
    source: String,
    /// The run is vettalon's own export ([`OWN_TOOL_NAME`]).
    own: bool,
}

impl<'a> RunCtx<'a> {
    fn new(
        run_idx: usize,
        run: &'a Run,
        repo_root: Option<&'a Path>,
        canonical_root: Option<&'a Path>,
    ) -> Self {
        let mut rules_by_id: HashMap<&'a str, &'a Rule> = HashMap::new();
        let extension_rules = run.tool.extensions.iter().flat_map(|e| e.rules.iter());
        for rule in run.tool.driver.rules.iter().chain(extension_rules) {
            if let Some(id) = rule.id.as_deref() {
                rules_by_id.entry(id).or_insert(rule);
            }
        }
        let mut extensions_by_name: HashMap<&'a str, &'a ToolComponent> = HashMap::new();
        for e in run.tool.extensions.iter() {
            if let Some(name) = e.name.as_deref() {
                extensions_by_name.entry(name).or_insert(e);
            }
        }
        let base_prefixes = run
            .original_uri_base_ids
            .0
            .iter()
            .map(|(name, entry)| {
                let prefix = base_dir(entry)
                    .and_then(|dir| relative_to_root(&dir, repo_root, canonical_root));
                (name.as_str(), prefix)
            })
            .collect();
        RunCtx {
            run_idx,
            run,
            repo_root,
            canonical_root,
            rules_by_id,
            extensions_by_name,
            base_prefixes,
            source: source_name(run.tool.driver.name.as_deref()),
            own: run.tool.driver.name.as_deref() == Some(OWN_TOOL_NAME),
        }
    }

    fn convert_all(&self, out: &mut SarifClaims, seen: &mut HashMap<DedupeKey, String>) {
        for (result_idx, r) in self.run.results.iter().enumerate() {
            let id = format!("sarif-{}-{result_idx}", self.run_idx);
            match self.convert(&id, r) {
                Ok((claim, dropped)) => {
                    let key = (
                        claim.file.clone(),
                        claim.line,
                        claim.rule_id.clone(),
                        claim.cwe.clone(),
                    );
                    if let Some(first) = seen.get(&key) {
                        out.duplicates += 1;
                        out.skipped.push(SarifNote {
                            result_id: id,
                            reason: DUPLICATE.to_string(),
                            duplicate_of: Some(first.clone()),
                        });
                        continue;
                    }
                    seen.insert(key, id.clone());
                    if !dropped.is_empty() {
                        out.dropped_locations
                            .push(SarifNote::new(id, dropped.summary()));
                    }
                    out.claims.push(claim);
                }
                Err(Skip::NotAFinding(reason)) => out.skipped.push(SarifNote::new(id, reason)),
                Err(Skip::Unreviewable(reason)) => {
                    out.unreviewable += 1;
                    out.skipped.push(SarifNote::new(id, reason));
                }
            }
        }
    }

    fn convert(&self, id: &str, r: &SarifResult) -> Result<(Claim, Dropped), Skip> {
        if let Some(kind) = r.kind.as_ref().and_then(Peek::as_str)
            && matches!(kind, "pass" | "notApplicable" | "informational")
        {
            return Err(Skip::NotAFinding(format!("kind {kind}: not a finding")));
        }
        // SARIF: a suppression without a status is accepted.
        let accepted = |s: &&Suppression| {
            s.status
                .as_ref()
                .is_none_or(|v| v.as_str() == Some("accepted"))
        };
        if let Some(s) = r.suppressions.iter().find(accepted) {
            let in_source = s.kind.as_ref().and_then(Peek::as_str) == Some("inSource");
            return Err(Skip::NotAFinding(if in_source {
                SUPPRESSED_IN_SOURCE.to_string()
            } else {
                "suppressed in the SARIF log".to_string()
            }));
        }
        let rule = self.rule_for(r);
        let rule_id = r
            .rule_id
            .as_deref()
            .or_else(|| r.rule.as_ref().and_then(|d| d.id.as_deref()))
            .filter(|s| !s.trim().is_empty());
        let title = message_title(r.message.as_ref())
            .or_else(|| message_title(rule.and_then(|x| x.short_description.as_ref())))
            .or_else(|| rule_id.and_then(clean_title))
            .ok_or_else(|| {
                Skip::Unreviewable(
                    "no message text, rule description or ruleId with visible characters".into(),
                )
            })?;

        let mut dropped = Dropped::default();
        let mut primary: Option<(String, Option<u32>)> = None;
        let mut extra: Vec<ClaimLocation> = Vec::new();
        // Locations past READ_LOCATIONS were never read.
        let mut over_cap = r.locations.skipped;
        for (i, loc) in r.locations.iter().enumerate() {
            if primary.is_some() && extra.len() >= MAX_CLAIM_LOCATIONS {
                // Full: count the rest without resolving them.
                over_cap += 1;
                continue;
            }
            match self.resolve(loc) {
                Ok(found) if primary.is_none() => primary = Some(found),
                Ok((file, Some(line))) => {
                    push_extra(&mut extra, &mut over_cap, primary.as_ref(), file, line)
                }
                Ok((_, None)) => dropped.add(format!("locations[{i}]: no startLine")),
                Err(e) => dropped.add(format!("locations[{i}]: {e}")),
            }
        }
        let Some((file, line)) = primary else {
            let why = if dropped.is_empty() {
                "no location".to_string()
            } else {
                format!("no usable location ({})", dropped.summary())
            };
            return Err(Skip::Unreviewable(why));
        };
        let primary = Some((file.clone(), line));
        let mut unread = r.code_flows.skipped;
        for (fi, flow) in r.code_flows.iter().enumerate() {
            unread += flow.thread_flows.skipped;
            for (ti, thread) in flow.thread_flows.iter().enumerate() {
                unread += thread.locations.skipped;
                for (li, step) in thread.locations.iter().enumerate() {
                    let Some(loc) = step.location.as_ref() else {
                        continue;
                    };
                    if extra.len() >= MAX_CLAIM_LOCATIONS {
                        // Full: count the rest without resolving them.
                        over_cap += 1;
                        continue;
                    }
                    let at = format!("codeFlows[{fi}].threadFlows[{ti}].locations[{li}]");
                    match self.resolve(loc) {
                        Ok((f, Some(l))) => {
                            push_extra(&mut extra, &mut over_cap, primary.as_ref(), f, l)
                        }
                        Ok((_, None)) => dropped.add(format!("{at}: no startLine")),
                        Err(e) => dropped.add(format!("{at}: {e}")),
                    }
                }
            }
        }
        if over_cap > 0 {
            dropped.add(format!(
                "{over_cap} further location(s) over the cap of {MAX_CLAIM_LOCATIONS}"
            ));
        }
        if unread > 0 {
            dropped.add(format!(
                "{unread} further codeFlows/threadFlows/steps not read (the first {READ_CODE_FLOWS} code flows, {READ_THREAD_FLOWS} thread flows each and {READ_FLOW_STEPS} steps each are read)"
            ));
        }
        let cwes = self.cwes_for(r, rule);
        let cwe = cwes
            .iter()
            .find(|c| super::trust_policy::llm_refute_cap(Some(c.as_str())).is_some())
            .or(cwes.first())
            .cloned();
        let claim = Claim {
            id: id.to_string(),
            file,
            line,
            title,
            severity: severity_for(r, rule, self.own),
            cwe,
            cwes: if cwes.len() > 1 { cwes } else { Vec::new() },
            rule_id: rule_id.map(str::to_string),
            source: Some(self.source.clone()),
            locations: extra,
        };
        Ok((claim, dropped))
    }

    /// The rule a result points at: `rule.index` / `ruleIndex` in its tool
    /// component (driver, or `rule.toolComponent`), if that rule has the
    /// same id; otherwise the first rule with the result's id.
    fn rule_for(&self, r: &SarifResult) -> Option<&'a Rule> {
        let tool = &self.run.tool;
        let rule_id = r
            .rule_id
            .as_deref()
            .or_else(|| r.rule.as_ref().and_then(|d| d.id.as_deref()));
        let component = match r.rule.as_ref().and_then(|d| d.tool_component.as_ref()) {
            Some(c) => match (c.index, c.name.as_deref()) {
                (Some(i), _) => usize::try_from(i).ok().and_then(|i| tool.extensions.get(i)),
                (None, Some(name)) => self
                    .extensions_by_name
                    .get(name)
                    .copied()
                    .or(Some(&tool.driver)),
                (None, None) => Some(&tool.driver),
            },
            None => Some(&tool.driver),
        };
        let index = r
            .rule
            .as_ref()
            .and_then(|d| d.index)
            .or(r.rule_index)
            .and_then(|i| usize::try_from(i).ok());
        if let (Some(c), Some(i)) = (component, index)
            && let Some(rule) = c.rules.get(i)
            && (rule_id.is_none() || rule.id.as_deref() == rule_id)
        {
            return Some(rule);
        }
        rule_id.and_then(|id| self.rules_by_id.get(id).copied())
    }

    /// Every CWE the result names, normalized and deduplicated, in the order
    /// of the module docs.
    fn cwes_for(&self, r: &SarifResult, rule: Option<&Rule>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut add = |c: Option<String>| {
            if let Some(c) = c
                && !out.contains(&c)
            {
                out.push(c);
            }
        };
        for t in r.taxa.iter() {
            if self.is_cwe_component(t.tool_component.as_ref()) {
                add(t.id.as_deref().and_then(super::cwe::normalize_tag));
            }
        }
        let props = &r.properties.0;
        if self.own {
            add(props
                .vettalon_cwe
                .as_ref()
                .and_then(Peek::as_str)
                .and_then(super::cwe::tag_cwe));
        }
        for tag in &props.tags.0 {
            add(super::cwe::tag_cwe(tag));
        }
        // vettalon's own export writes rule tags as the union over every
        // finding of the rule: they say nothing about this result.
        if !self.own
            && let Some(rule) = rule
        {
            let rule_props = &rule.properties.0;
            for tag in &rule_props.tags.0 {
                add(super::cwe::tag_cwe(tag));
            }
            for rel in rule.relationships.iter() {
                if let Some(target) = rel.target.as_ref()
                    && self.is_cwe_component(target.tool_component.as_ref())
                {
                    add(target.id.as_deref().and_then(super::cwe::normalize_tag));
                }
            }
            for c in &rule_props.cwe.0 {
                add(super::cwe::normalize_tag(c));
            }
        }
        out
    }

    fn is_cwe_component(&self, c: Option<&ComponentRef>) -> bool {
        let Some(c) = c else {
            return false;
        };
        let name = match c.name.as_deref() {
            Some(n) => Some(n),
            None => c
                .index
                .and_then(|i| usize::try_from(i).ok())
                .and_then(|i| self.run.taxonomies.get(i))
                .and_then(|t| t.name.as_deref()),
        };
        name.is_some_and(|n| n.eq_ignore_ascii_case("CWE"))
    }

    /// `(repo-relative file, line)` of one SARIF location.
    fn resolve(&self, loc: &Location) -> Result<(String, Option<u32>), String> {
        let phys = loc
            .physical_location
            .as_ref()
            .ok_or_else(|| "no physicalLocation".to_string())?;
        let art = phys
            .artifact_location
            .as_ref()
            .ok_or_else(|| "no artifactLocation".to_string())?;
        // An artifact location may name its file only through `index` into
        // `run.artifacts` (one hop, never followed further).
        let art = match art.uri {
            Some(_) => art,
            None => art
                .index
                .and_then(|i| usize::try_from(i).ok())
                .and_then(|i| self.run.artifacts.get(i))
                .and_then(|a| a.location.as_ref())
                .ok_or_else(|| "no artifact URI".to_string())?,
        };
        let uri = art
            .uri
            .as_deref()
            .ok_or_else(|| "no artifact URI".to_string())?;
        let file = self.resolve_uri(uri, art.uri_base_id.as_deref())?;
        let line = match phys.region.as_ref().and_then(|r| r.start_line.as_ref()) {
            None => None,
            Some(v) => Some(
                positive_line(v)
                    .ok_or_else(|| "startLine is not a positive line number".to_string())?,
            ),
        };
        Ok((file, line))
    }

    fn resolve_uri(&self, uri: &str, base: Option<&str>) -> Result<String, String> {
        if uri.chars().any(|c| matches!(c, '\0' | '?' | '#')) {
            return Err("URI has a NUL, a query or a fragment".into());
        }
        if let Some((scheme, rest)) = split_scheme(uri) {
            if !scheme.eq_ignore_ascii_case("file") {
                return Err(format!(
                    "URI scheme {:?} is not a local file",
                    crate::util::truncate_bytes(scheme, QUOTED_MAX_BYTES)
                ));
            }
            let abs = file_uri_path(rest)?;
            let rel =
                relative_to_root(&abs, self.repo_root, self.canonical_root).ok_or_else(|| {
                    if self.repo_root.is_some() {
                        "file URI outside the repository root".to_string()
                    } else {
                        "file URI without a repository root to map it to".to_string()
                    }
                })?;
            return safe(rel);
        }
        let rel = decode_relative(uri)?;
        let prefix = base
            .and_then(|b| self.base_prefixes.get(b))
            .and_then(|p| p.as_deref());
        match prefix {
            Some(p) if !p.is_empty() => safe(format!("{p}/{rel}")),
            _ => safe(rel),
        }
    }
}

/// An `originalUriBaseIds` entry that is a `file:` URI (no nested base).
fn base_dir(entry: &ArtifactLocation) -> Option<PathBuf> {
    if entry.uri_base_id.is_some() {
        return None;
    }
    let uri = entry.uri.as_deref()?;
    if uri.chars().any(|c| matches!(c, '\0' | '?' | '#')) {
        return None;
    }
    let (scheme, rest) = split_scheme(uri)?;
    if !scheme.eq_ignore_ascii_case("file") {
        return None;
    }
    file_uri_path(rest).ok()
}

/// `abs` relative to the repository root (`""` for the root itself), by
/// path components, against the root as given and its canonical form. `abs`
/// comes from the log and is never canonicalized or looked up on disk.
fn relative_to_root(
    abs: &Path,
    repo_root: Option<&Path>,
    canonical_root: Option<&Path>,
) -> Option<String> {
    let root = repo_root?;
    under(abs, root).or_else(|| canonical_root.and_then(|c| under(abs, c)))
}

/// Add one trace location unless it repeats the claimed one or another.
fn push_extra(
    extra: &mut Vec<ClaimLocation>,
    over_cap: &mut usize,
    primary: Option<&(String, Option<u32>)>,
    file: String,
    line: u32,
) {
    let is_primary = primary.is_some_and(|(f, l)| *f == file && *l == Some(line));
    if is_primary || extra.iter().any(|l| l.file == file && l.line == line) {
        return;
    }
    if extra.len() >= MAX_CLAIM_LOCATIONS {
        *over_cap += 1;
        return;
    }
    extra.push(ClaimLocation {
        file,
        line,
        scope: None,
    });
}

fn safe(rel: String) -> Result<String, String> {
    SafeRepoPath::parse(&rel).map_err(|e| format!("unsafe path: {e}"))?;
    Ok(rel)
}

/// `path` below `root` as `a/b/c`, only through normal components.
fn under(path: &Path, root: &Path) -> Option<String> {
    let rest = path.strip_prefix(root).ok()?;
    let parts: Option<Vec<&str>> = rest
        .components()
        .map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    Some(parts?.join("/"))
}

/// `scheme:rest` when `uri` starts with an RFC 3986 scheme.
fn split_scheme(uri: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = uri.split_once(':')?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then_some((scheme, rest))
}

/// The absolute path of a `file:` URI (`rest` follows `file:`), as a Unix
/// path. Only an empty host or `localhost`; `.` and empty segments are
/// dropped, `..` is refused.
fn file_uri_path(rest: &str) -> Result<PathBuf, String> {
    let path = match rest.strip_prefix("//") {
        Some(after) => {
            let (host, path) = after
                .split_once('/')
                .ok_or_else(|| "file URI has no path".to_string())?;
            if !(host.is_empty() || host.eq_ignore_ascii_case("localhost")) {
                return Err("file URI names a remote host".into());
            }
            path.to_string()
        }
        None => rest
            .strip_prefix('/')
            .ok_or_else(|| "file URI is not absolute".to_string())?
            .to_string(),
    };
    let decoded = percent_decode(&path)?;
    if decoded.chars().any(|c| matches!(c, '\0' | '\\')) {
        return Err("file URI has a NUL or a backslash".into());
    }
    let mut out = PathBuf::from("/");
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return Err("file URI has a `..` segment".into()),
            s => out.push(s),
        }
    }
    Ok(out)
}

/// A relative reference as a repo-relative path: percent-decoded, `.` and
/// empty segments dropped, `..` refused.
fn decode_relative(uri: &str) -> Result<String, String> {
    if uri.starts_with('/') {
        return Err("absolute path without a file: scheme".into());
    }
    let decoded = percent_decode(uri)?;
    if decoded.starts_with('/') {
        return Err("absolute path without a file: scheme".into());
    }
    if decoded.chars().any(|c| matches!(c, '\0' | '\\')) {
        return Err("path has a NUL or a backslash".into());
    }
    let mut parts: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return Err("path has a `..` segment".into()),
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        return Err("empty path".into());
    }
    Ok(parts.join("/"))
}

/// RFC 3986 percent-decoding; the result must be UTF-8.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = |at: usize| bytes.get(at).and_then(|x| char::from(*x).to_digit(16));
            let (Some(hi), Some(lo)) = (hex(i + 1), hex(i + 2)) else {
                return Err("bad percent-encoding in URI".into());
            };
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "percent-decoded URI is not UTF-8".to_string())
}

/// A JSON integer ≥ 1 that fits a `u32`.
fn positive_line(v: &Peek) -> Option<u32> {
    match v {
        Peek::Scalar(s) => s
            .parse::<u64>()
            .ok()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0),
        _ => None,
    }
}

/// One line of visible text: control characters, line and paragraph
/// separators and whitespace runs become one space, the ends are trimmed,
/// and at least one visible character must remain.
pub(crate) fn clean_title(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut gap = false;
    for c in raw.chars() {
        if c.is_control() || c.is_whitespace() || matches!(c, '\u{2028}' | '\u{2029}') {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push(' ');
        }
        gap = false;
        out.push(c);
    }
    has_visible_content(&out).then_some(out)
}

/// A message's `text` as a title ([`clean_title`]).
fn message_title(m: Option<&Message>) -> Option<String> {
    m?.text.as_deref().and_then(clean_title)
}

fn severity_for(r: &SarifResult, rule: Option<&Rule>, own: bool) -> Option<Severity> {
    // vettalon's own export carries the exact severity per result.
    if own
        && let Some(s) = r
            .properties
            .0
            .vettalon_severity
            .as_ref()
            .and_then(Peek::as_str)
            .and_then(parse_severity)
    {
        return Some(s);
    }
    let rule_score = rule.and_then(|x| x.properties.0.security_severity.as_ref());
    let score = r
        .properties
        .0
        .security_severity
        .as_ref()
        .and_then(security_score)
        .or_else(|| rule_score.and_then(security_score));
    if let Some(n) = score {
        return Some(if n >= 9.0 {
            Severity::Critical
        } else if n >= 7.0 {
            Severity::High
        } else if n >= 4.0 {
            Severity::Medium
        } else {
            Severity::Low
        });
    }
    let level = r.level.as_ref().and_then(Peek::as_str).or_else(|| {
        rule.and_then(|x| x.default_configuration.as_ref())
            .and_then(|c| c.level.as_ref())
            .and_then(Peek::as_str)
    });
    match level? {
        "error" => Some(Severity::High),
        "warning" => Some(Severity::Medium),
        "note" | "none" => Some(Severity::Low),
        _ => None,
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

/// A CodeQL-style `security-severity` (a string or number, 0.0 to 10.0).
fn security_score(v: &Peek) -> Option<f64> {
    let n = match v {
        Peek::Str(s) => s.trim().parse::<f64>().ok()?,
        Peek::Scalar(s) => s.parse::<f64>().ok()?,
        _ => return None,
    };
    (n.is_finite() && (0.0..=10.0).contains(&n)).then_some(n)
}

/// `tool.driver.name` as a claim source: ASCII letters, digits, `-`, `_`,
/// `.` (anything else becomes `-`), at most [`SOURCE_NAME_MAX_CHARS`].
fn source_name(name: Option<&str>) -> String {
    let mapped: String = name
        .unwrap_or_default()
        .chars()
        .take(SOURCE_NAME_MAX_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = mapped.trim_matches('-');
    if trimmed.is_empty() {
        DEFAULT_SOURCE.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests;
