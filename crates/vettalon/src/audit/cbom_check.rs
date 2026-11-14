//! `vettalon cbom-check` (experimental): label every crypto-asset occurrence in
//! a CycloneDX CBOM as `reachable`, `not_observed` or `unknown` with
//! [`py_usage`](super::py_usage), and emit a hashed, **unsigned** receipt.
//!
//! This is an independent second opinion on a CBOM tool's inventory: such tools
//! report what code *can* use, this checks whether the enclosing code is
//! observed to be reached. `not_observed` is never "unreachable" or "safe", and
//! no VEX is ever produced (see `docs/REACHABILITY.md`, `docs/CBOM-CHECK.md`).
//!
//! `receipt_sha256` is the SHA-256 of the canonical JSON of the receipt
//! without `receipt_sha256` and `generated_at`. Canonical JSON: the receipt as
//! a `serde_json::Value` with every object's keys sorted (recursively),
//! serialized compactly (no whitespace) by `serde_json::to_string`. It is
//! streamed into the hasher one top-level field or one row at a time
//! ([`Receipt::compute_hash`]); the bytes are the same.
//!
//! Memory is bounded by the CBOM caps (every CBOM string is at most 256
//! characters, at most 200 000 occurrences), a per-location mapping cache, a
//! global budget for CBOM strings copied into rows and one for `chain` text.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::cbom::{self, Component, MAX_STRING_CHARS, Mapped, PathError, clip_chars};
use super::java_crypto::{self, SweepContext};
use super::java_usage::JavaProject;
use super::py_usage::{Label, Project, Verdict};

pub const SCHEMA: &str = "vettalon.cbom-check/2";
pub const ANALYSIS: &str = "name-based static, over-approximate, not execution evidence";
pub const POLICY: &str = "not_observed is not proof of absence; no VEX is emitted";
/// Widest rendered table column (characters, including the `…`).
pub const MAX_COLUMN_CHARS: usize = 60;
/// Budget for `chain` text across all rows (bytes); past it a chain keeps
/// only its first and last entries (reason `chain_truncated`).
const MAX_CHAIN_BYTES: usize = 32 * 1024 * 1024;
/// Budget for CBOM strings (`bom_ref`, `name`, `asset_type`, `algorithm`,
/// `symbol`) copied into rows (bytes); past it every further copy is clipped
/// to [`BUDGET_CLIP_CHARS`] characters (reason `cbom_value_clipped:budget`).
const MAX_ROW_STRING_BYTES: usize = 64 * 1024 * 1024;
const BUDGET_CLIP_CHARS: usize = 32;
/// Document-level note: `dependencies` entries or refs were dropped by a cap.
pub const NOTE_DEPENDENCIES_TRUNCATED: &str = "cbom_dependencies_truncated";

#[derive(Debug, Clone, Serialize)]
pub struct CbomInfo {
    pub sha256: String,
    pub spec_version: String,
    pub tool: Option<String>,
    /// Document-level notes (e.g. `cbom_dependencies_truncated`); omitted
    /// from the receipt when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub bom_ref: Option<String>,
    pub name: Option<String>,
    pub asset_type: Option<String>,
    pub algorithm: Option<String>,
    pub quantum_vulnerable: Option<bool>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub symbol: Option<String>,
    pub enclosing_function: Option<String>,
    pub label: Label,
    pub reasons: Vec<String>,
    pub chain: Vec<String>,
    pub file_sha256: Option<String>,
}

/// Independent Java inventory. Every string (including file and reasons) shares
/// the occurrence row-string budget. File-level sweep reasons are stored once
/// as `sweep:<repo-relative file>:<reason>` in `cbom.notes`, even with no rows;
/// global notes are `sweep_truncated` and `sweep_java_only`.
#[derive(Debug, Clone, Serialize)]
pub struct SweepRow {
    pub file: String,
    pub line: u32,
    pub api: String,
    pub algorithm: Option<String>,
    pub mode: Option<String>,
    pub padding: Option<String>,
    pub key_bits: Option<u32>,
    pub provider: Option<String>,
    pub quantum_vulnerable: Option<bool>,
    pub in_cbom: bool,
    pub label: Label,
    pub reasons: Vec<String>,
}

const MAX_SWEEP_ROWS: usize = 50_000;

#[derive(Debug, Clone, Serialize)]
pub struct ProjectInfo {
    pub py_files: usize,
    pub java_files: usize,
    /// Languages with at least one analyzed file, sorted.
    pub languages: Vec<&'static str>,
    /// Python dynamic dispatch (`getattr`, `eval`, ...).
    pub dynamic_dispatch_detected: bool,
    /// Java reflection / dynamic loading.
    pub reflection_detected: bool,
    /// Per language (`python:<why>`, `java:<why>`), why `not_observed` is
    /// withheld for that language's files; only blocked languages appear.
    pub not_observed_blocked: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total_rows: usize,
    pub by_label: BTreeMap<String, usize>,
    /// Keys `true`, `false`, `null` (not classified).
    pub by_quantum_vulnerable: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Receipt {
    pub schema: &'static str,
    pub tool_version: &'static str,
    pub generated_at: String,
    pub cbom: CbomInfo,
    pub root_tree_sha256: String,
    pub analysis: &'static str,
    pub policy: &'static str,
    pub entries: Vec<String>,
    pub project: ProjectInfo,
    pub rows: Vec<Row>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sweep: Option<Vec<SweepRow>>,
    pub summary: Summary,
    pub receipt_sha256: String,
}

/// Recursively sort object keys (consumes `v`: no second copy of the tree).
fn sorted(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(String, Value)> = m.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// Compact JSON with recursively sorted object keys (the reference form the
/// streamed [`Receipt::compute_hash`] reproduces).
pub fn canonical_json(v: &Value) -> Result<String, serde_json::Error> {
    serde_json::to_string(&sorted(v.clone()))
}

/// `io::Write` adapter feeding a SHA-256.
struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Receipt {
    /// SHA-256 of the canonical JSON without `receipt_sha256`/`generated_at`.
    /// Serialization errors are returned, never hashed as null or empty.
    pub fn compute_hash(&self) -> Result<String, String> {
        let mut h = HashWriter(Sha256::new());
        self.write_canonical(&mut h)
            .map_err(|e| format!("cannot serialize the receipt for hashing: {e}"))?;
        Ok(hex::encode(h.0.finalize()))
    }

    /// Stream the canonical JSON: top-level keys sorted, each value (and each
    /// row of `rows`) turned into a small `Value`, key-sorted and written
    /// compactly. Byte-identical to [`canonical_json`] of the whole receipt.
    fn write_canonical<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        use serde_json::to_value as to;
        // Exhaustive on purpose: a new field does not compile until it is
        // hashed (or excluded) here.
        let Receipt {
            schema,
            tool_version,
            generated_at: _,
            cbom,
            root_tree_sha256,
            analysis,
            policy,
            entries,
            project,
            rows,
            sweep,
            summary,
            receipt_sha256: _,
        } = self;
        let mut fields: Vec<(&str, Option<Value>)> = vec![
            ("schema", Some(to(schema)?)),
            ("tool_version", Some(to(tool_version)?)),
            ("cbom", Some(to(cbom)?)),
            ("root_tree_sha256", Some(to(root_tree_sha256)?)),
            ("analysis", Some(to(analysis)?)),
            ("policy", Some(to(policy)?)),
            ("entries", Some(to(entries)?)),
            ("project", Some(to(project)?)),
            ("rows", None),
            ("summary", Some(to(summary)?)),
        ];
        if sweep.is_some() {
            fields.push(("sweep", None));
        }
        fields.sort_by_key(|f| f.0);
        w.write_all(b"{")?;
        for (i, (key, value)) in fields.into_iter().enumerate() {
            if i > 0 {
                w.write_all(b",")?;
            }
            serde_json::to_writer(&mut *w, key)?;
            w.write_all(b":")?;
            match value {
                Some(v) => serde_json::to_writer(&mut *w, &sorted(v))?,
                None => {
                    w.write_all(b"[")?;
                    let values: Box<dyn Iterator<Item = Result<Value, serde_json::Error>> + '_> =
                        if key == "sweep" {
                            Box::new(sweep.iter().flatten().map(serde_json::to_value))
                        } else {
                            Box::new(rows.iter().map(serde_json::to_value))
                        };
                    for (j, row) in values.enumerate() {
                        if j > 0 {
                            w.write_all(b",")?;
                        }
                        serde_json::to_writer(&mut *w, &sorted(row?))?;
                    }
                    w.write_all(b"]")?;
                }
            }
        }
        w.write_all(b"}")
    }
}

fn clip(s: &str) -> String {
    clip_chars(s, MAX_STRING_CHARS).0
}

fn unknown(reason: &str) -> Verdict {
    Verdict {
        label: Label::Unknown,
        reasons: vec![reason.to_string()],
        enclosing_function: None,
        chain: Vec::new(),
    }
}

/// Copy a CBOM string into a row, charged to `budget` (bytes). Once a copy
/// does not fit, the budget is spent and every further copy is clipped to
/// [`BUDGET_CLIP_CHARS`] characters (`*clipped` is set when that cut text).
fn budget_copy(s: Option<&str>, budget: &mut usize, clipped: &mut bool) -> Option<String> {
    let s = s?;
    if s.len() <= *budget {
        *budget -= s.len();
        return Some(s.to_string());
    }
    *budget = 0;
    let (out, cut) = clip_chars(s, BUDGET_CLIP_CHARS);
    *clipped |= cut;
    Some(out)
}

/// A fresh row for one occurrence (or a component without occurrences) of
/// `comp`; its CBOM strings are charged to `budget`. The flag is set when a
/// string was clipped because the budget ran out.
fn new_row(
    comp: &Component,
    algorithm: Option<&Component>,
    quantum_vulnerable: Option<bool>,
    symbol: Option<&str>,
    budget: &mut usize,
) -> (Row, bool) {
    let mut clipped = false;
    let mut copy = |s: Option<&str>| budget_copy(s, budget, &mut clipped);
    let row = Row {
        bom_ref: copy(comp.bom_ref.as_deref()),
        name: copy(comp.name.as_deref()),
        asset_type: copy(comp.asset_type.as_deref()),
        algorithm: copy(algorithm.and_then(|a| a.name.as_deref())),
        quantum_vulnerable,
        file: None,
        line: None,
        symbol: copy(symbol),
        enclosing_function: None,
        label: Label::Unknown,
        reasons: Vec::new(),
        chain: Vec::new(),
        file_sha256: None,
    };
    (row, clipped)
}

fn budget_note(clipped: bool) -> Option<String> {
    clipped.then(|| "cbom_value_clipped:budget".to_string())
}

/// Charge `chain` to the budget; past it keep only the endpoints.
fn budget_chain(chain: Vec<String>, budget: &mut usize, notes: &mut Vec<String>) -> Vec<String> {
    let bytes: usize = chain.iter().map(String::len).sum();
    if bytes <= *budget {
        *budget -= bytes;
        return chain;
    }
    notes.push("chain_truncated".into());
    let short = if chain.len() > 2 {
        vec![
            chain[0].clone(),
            "...".to_string(),
            chain[chain.len() - 1].clone(),
        ]
    } else {
        chain
    };
    *budget = budget.saturating_sub(short.iter().map(String::len).sum());
    short
}

/// `unsupported_language:<ext>` for a path that is neither `.py` nor `.java`
/// (extension lowercased, ASCII only, at most 16 characters; `none` if absent).
fn unsupported_language(rel: &str) -> String {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let ext = match name.rsplit_once('.') {
        Some((_, e)) if !e.is_empty() => e,
        _ => "none",
    };
    let ext: String = ext
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() {
                c.to_ascii_lowercase()
            } else {
                '?'
            }
        })
        .take(16)
        .collect();
    format!("unsupported_language:{ext}")
}

/// SHA-256 over the analyzed `.py` and `.java` files sorted together by
/// path: `"<rel>\0<file sha256 hex>\n"` per file.
fn tree_sha256(py: &Project, java: &JavaProject) -> String {
    let mut files: Vec<(&str, &str)> = py.file_hashes().chain(java.file_hashes()).collect();
    files.sort();
    let mut h = Sha256::new();
    for (rel, sha) in files {
        h.update(rel.as_bytes());
        h.update([0u8]);
        h.update(sha.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

/// Analyze `cbom_path` against the Python and Java sources under `root`.
pub fn run(cbom_path: &Path, root: &Path, entries: &[String]) -> Result<Receipt, String> {
    run_with_excludes(cbom_path, root, entries, &[])
}

/// Canonical form of a path that may not exist yet (the receipt output):
/// canonical parent joined with the file name.
fn canonical_maybe_new(p: &Path) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    match (
        abs.parent().and_then(|d| d.canonicalize().ok()),
        abs.file_name(),
    ) {
        (Some(d), Some(n)) => d.join(n),
        _ => abs,
    }
}

/// [`run`], additionally ignoring `extra_excludes` (e.g. the receipt output)
/// when the Java sources are scanned. The CBOM file itself is always ignored.
pub fn run_with_excludes(
    cbom_path: &Path,
    root: &Path,
    entries: &[String],
    extra_excludes: &[PathBuf],
) -> Result<Receipt, String> {
    run_with_sweep(cbom_path, root, entries, extra_excludes, false)
}

/// Analyze with the optional independent Java inventory enabled.
pub fn run_with_sweep(
    cbom_path: &Path,
    root: &Path,
    entries: &[String],
    extra_excludes: &[PathBuf],
    sweep_enabled: bool,
) -> Result<Receipt, String> {
    let root = root
        .canonicalize()
        .ok()
        .filter(|p| p.is_dir())
        .ok_or_else(|| format!("{} is not a directory", root.display()))?;
    let cbom = cbom::read_cbom(cbom_path).map_err(|e| e.to_string())?;
    let project = Project::load(&root);
    let mut excludes = vec![canonical_maybe_new(cbom_path)];
    excludes.extend(extra_excludes.iter().map(|p| canonical_maybe_new(p)));
    let java = if sweep_enabled {
        JavaProject::load_for_sweep(&root, &excludes, true)
    } else {
        JavaProject::load_with_excludes(&root, &excludes)
    };
    // Each spec must resolve in at least one language; Python's `reach`
    // only gets the specs that resolve there.
    let mut py_entries: Vec<String> = Vec::new();
    for spec in entries {
        let py = project.resolve_entry(spec);
        if py.is_ok() {
            py_entries.push(spec.clone());
        } else if let Err(java_err) = java.resolve_entry(spec) {
            let py_err = py.err().unwrap_or_default();
            return Err(format!("{py_err}; {java_err}"));
        }
    }
    let reach = project.reach(&py_entries)?;
    let java_reach = java.reach(entries);

    // One mapping per distinct location string (filesystem work is per
    // location, not per occurrence).
    let mut mapped: HashMap<&str, Result<Mapped, PathError>> = HashMap::new();
    let mut chain_budget = MAX_CHAIN_BYTES;
    let mut string_budget = MAX_ROW_STRING_BYTES;
    let mut rows = Vec::new();
    let mut locations = HashSet::new();
    for (ci, comp) in cbom.components.iter().enumerate() {
        let alg = cbom.algorithm_for(ci);
        let qv = alg.and_then(cbom::classify_quantum);
        let comp_notes: Vec<String> = comp
            .clipped
            .iter()
            .map(|f| format!("cbom_value_clipped:{f}"))
            .collect();
        if comp.occurrences.is_empty() {
            let (mut r, clipped) = new_row(comp, alg, qv, None, &mut string_budget);
            r.reasons.push("no_occurrence".into());
            r.reasons.extend(comp_notes.iter().cloned());
            r.reasons.extend(budget_note(clipped));
            rows.push(r);
        }
        for occ in &comp.occurrences {
            let symbol = occ.additional_context.as_deref();
            let (mut r, clipped) = new_row(comp, alg, qv, symbol, &mut string_budget);
            let mut notes: Vec<String> = Vec::new();
            r.line = occ.line.ok();
            let verdict = match &occ.location {
                Err(why) => unknown(why),
                Ok(loc) => match mapped
                    .entry(loc.as_str())
                    .or_insert_with(|| cbom::map_location(&root, loc))
                {
                    Err(e) => {
                        r.file = Some(clip(loc));
                        unknown(e.reason())
                    }
                    Ok(m) => {
                        if sweep_enabled && let Ok(line) = occ.line {
                            locations.insert((
                                m.rel.clone(),
                                line,
                                alg.and_then(|a| a.name.as_deref())
                                    .and_then(algorithm_family),
                                cbom_kind(alg.and_then(|a| a.primitive.as_deref())),
                            ));
                        }
                        if m.stripped > 1 {
                            notes.push(format!("path_suffix_stripped:{}", m.stripped));
                        }
                        let is_py = m.rel.ends_with(".py");
                        let is_java = m.rel.ends_with(".java");
                        r.file_sha256 = if is_py {
                            project.file_sha256(&m.rel)
                        } else if is_java {
                            java.file_sha256(&m.rel)
                        } else {
                            None
                        }
                        .map(str::to_string);
                        r.file = Some(m.rel.clone());
                        match occ.line {
                            Err(why) => unknown(why),
                            Ok(line) if is_py => project.classify(&reach, &m.rel, line),
                            Ok(line) if is_java => java.classify(&java_reach, &m.rel, line),
                            Ok(_) => unknown(&unsupported_language(&m.rel)),
                        }
                    }
                },
            };
            r.label = verdict.label;
            r.reasons = verdict.reasons;
            r.enclosing_function = verdict.enclosing_function;
            r.chain = budget_chain(verdict.chain, &mut chain_budget, &mut notes);
            r.reasons.extend(notes);
            r.reasons.extend(comp_notes.iter().cloned());
            r.reasons.extend(
                occ.clipped
                    .iter()
                    .map(|f| format!("cbom_value_clipped:{f}")),
            );
            r.reasons.extend(budget_note(clipped));
            rows.push(r);
        }
    }

    let mut sweep_notes = Vec::new();
    let sweep = sweep_enabled.then(|| {
        build_sweep(
            &java,
            &java_reach,
            &locations,
            &mut string_budget,
            MAX_SWEEP_ROWS,
            &mut sweep_notes,
        )
    });
    let mut by_label: BTreeMap<String, usize> = ["reachable", "not_observed", "unknown"]
        .iter()
        .map(|k| (k.to_string(), 0))
        .collect();
    let mut by_qv: BTreeMap<String, usize> = ["true", "false", "null"]
        .iter()
        .map(|k| (k.to_string(), 0))
        .collect();
    for r in &rows {
        *by_label.entry(r.label.as_str().to_string()).or_default() += 1;
        let k = match r.quantum_vulnerable {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        };
        *by_qv.entry(k.to_string()).or_default() += 1;
    }
    let mut receipt = Receipt {
        schema: SCHEMA,
        tool_version: env!("CARGO_PKG_VERSION"),
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        cbom: CbomInfo {
            sha256: cbom.sha256.clone(),
            spec_version: cbom.spec_version.clone(),
            tool: cbom.tool.clone(),
            notes: cbom
                .dependencies_truncated
                .then(|| NOTE_DEPENDENCIES_TRUNCATED.to_string())
                .into_iter()
                .chain(sweep_notes)
                .collect(),
        },
        root_tree_sha256: tree_sha256(&project, &java),
        analysis: ANALYSIS,
        policy: POLICY,
        entries: entries.to_vec(),
        project: ProjectInfo {
            py_files: project.file_count(),
            java_files: java.file_count(),
            languages: [
                ("java", java.file_count()),
                ("python", project.file_count()),
            ]
            .into_iter()
            .filter(|&(_, n)| n > 0)
            .map(|(l, _)| l)
            .collect(),
            dynamic_dispatch_detected: project.has_dynamic_dispatch(),
            reflection_detected: java.has_reflection(),
            not_observed_blocked: [
                ("python", project.incomplete_reason()),
                ("java", java.incomplete_reason()),
            ]
            .into_iter()
            .filter_map(|(l, why)| why.map(|w| format!("{l}:{w}")))
            .collect(),
        },
        summary: Summary {
            total_rows: rows.len(),
            by_label,
            by_quantum_vulnerable: by_qv,
        },
        rows,
        sweep,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt.compute_hash()?;
    Ok(receipt)
}

/// Match whole alphanumeric tokens or known prefixes followed by digits.
/// Hyphenated family names and JCA digest-with-signature names are handled
/// explicitly; unknown families retain the full trimmed uppercase name.
fn algorithm_family(name: &str) -> Option<String> {
    use std::sync::LazyLock;
    static TABLE: LazyLock<Vec<(regex::Regex, &'static str)>> = LazyLock::new(|| {
        [
            (r"PBKDF2(?:WITHHMACSHA[0-9]*)?", "PBKDF2"),
            (r"HMAC(?:SHA[0-9]*|MD5)?", "HMAC"),
            (r"(?:MLKEM|KYBER)[0-9]*", "ML-KEM"),
            (r"(?:MLDSA|DILITHIUM)[0-9]*", "ML-DSA"),
            (r"(?:SLHDSA|SPHINCS)[0-9]*", "SLH-DSA"),
            (r"3DES|TRIPLEDES|DESEDE|TDEA|TDES", "3DES"),
            (r"DES", "DES"),
            (r"(?:AES|RIJNDAEL)[0-9]*", "AES"),
            (r"CHACHA[0-9]*", "ChaCha20"),
            (r"RSA[0-9]*", "RSA"),
            (r"ECDSA[0-9]*", "ECDSA"),
            (r"ECDH[0-9]*", "ECDH"),
            (r"EDDSA|ED25519|ED448", "EdDSA"),
            (r"EC|(?:SECP|NISTP|PRIME)[0-9][A-Z0-9]*", "EC"),
            (r"DH|DIFFIEHELLMAN", "DH"),
            (r"DSA[0-9]*", "DSA"),
            (r"MD5", "MD5"),
            (r"SHA3|KECCAK[0-9]*", "SHA-3"),
            (r"SHA1", "SHA-1"),
            (r"SHA(?:2|224|256|384|512)", "SHA-2"),
        ]
        .into_iter()
        .map(|(pattern, family)| {
            (
                regex::Regex::new(&format!("^(?:{pattern})$")).unwrap(),
                family,
            )
        })
        .collect()
    });
    let text = name.trim();
    let text = if text
        .get(..6)
        .is_some_and(|s| s.eq_ignore_ascii_case("other:"))
    {
        &text[6..]
    } else {
        text
    };
    let upper = text.to_uppercase();
    if upper.is_empty() {
        return None;
    }
    if let Some((digest, signature)) = upper.split_once("WITH")
        && !signature.contains("WITH")
        && matches!(
            algorithm_family(digest).as_deref(),
            Some("SHA-1" | "SHA-2" | "SHA-3" | "MD5")
        )
    {
        let signature = signature.strip_suffix("ANDMGF1").unwrap_or(signature);
        let family = algorithm_family(signature);
        if matches!(family.as_deref(), Some("RSA" | "ECDSA" | "DSA" | "EdDSA")) {
            return family;
        }
    }
    let tokens: Vec<_> = upper
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let mut candidates: Vec<String> = tokens.iter().map(|s| (*s).to_string()).collect();
    for pair in tokens.windows(2) {
        if matches!(pair[0], "SHA" | "ML" | "SLH" | "TRIPLE") {
            candidates.push(format!("{}{}", pair[0], pair[1]));
        }
    }
    Some(
        TABLE
            .iter()
            .find(|(rx, _)| candidates.iter().any(|token| rx.is_match(token)))
            .map_or_else(
                || format!("other:{upper}"),
                |(_, family)| (*family).to_string(),
            ),
    )
}

fn sweep_kind(api: &str) -> &'static str {
    let class = api.strip_prefix("bc:").unwrap_or(api);
    let class = class.strip_suffix(".getInstance").unwrap_or(class);
    match class {
        "Cipher" => "cipher",
        "Signature" => "signature",
        "MessageDigest" => "digest",
        "Mac" | "HMac" | "CMac" => "mac",
        "KeyPairGenerator" | "KeyGenerator" | "KeyFactory" | "SecretKeyFactory" => "keygen",
        "KeyAgreement" => "key-agree",
        "KEM" => "kem",
        _ if api.starts_with("bc:") && class.ends_with("Signer") => "signature",
        _ if api.starts_with("bc:") && class.ends_with("Digest") => "digest",
        _ if api.starts_with("bc:") && class.ends_with("KeyPairGenerator") => "keygen",
        _ if api.starts_with("bc:") && class.ends_with("Agreement") => "key-agree",
        _ if class.starts_with("MLKEM") => "kem",
        _ => "other",
    }
}

fn cbom_kind(primitive: Option<&str>) -> &'static str {
    match primitive {
        Some("block-cipher" | "stream-cipher" | "ae" | "pke") => "cipher",
        Some("signature") => "signature",
        Some("hash") => "digest",
        Some("mac") => "mac",
        Some("key-agree") => "key-agree",
        Some("kem") => "kem",
        _ => "other",
    }
}

/// A match requires file, line, exact normalized family, and coarse kind.
/// If either kind is other/unknown, only a known (non-other:*) equal family
/// can match. Missing/unknown families then provide location-only evidence;
/// other:* families can match only by their full canonical name and known kinds.
fn sweep_matches(
    locations: &HashSet<(String, u32, Option<String>, &'static str)>,
    file: &str,
    line: u32,
    family: Option<String>,
    kind: &'static str,
) -> bool {
    let Some(family) = family else { return false };
    let known_family = !family.starts_with("other:");
    if kind == "other" {
        return known_family
            && [
                "cipher",
                "signature",
                "digest",
                "mac",
                "keygen",
                "key-agree",
                "kem",
                "other",
            ]
            .iter()
            .any(|kind| {
                locations.contains(&(file.to_string(), line, Some(family.clone()), *kind))
            });
    }
    locations.contains(&(file.to_string(), line, Some(family.clone()), kind))
        || (known_family && locations.contains(&(file.to_string(), line, Some(family), "other")))
}

/// Two passes over retained lexer/parser results; never reads source files.
fn build_sweep(
    java: &JavaProject,
    reach: &super::java_usage::Reach,
    locations: &HashSet<(String, u32, Option<String>, &'static str)>,
    budget: &mut usize,
    max_rows: usize,
    notes: &mut Vec<String>,
) -> Vec<SweepRow> {
    let mut ctx = SweepContext::default();
    'constants: for (_, lexed, parsed) in java.sweep_files() {
        for (ty, name, expr) in java_crypto::collect_constants(lexed, parsed) {
            if !ctx.insert(ty, name, expr) {
                notes.extend(budget_copy(
                    Some("sweep_constants_limit_exceeded"),
                    budget,
                    &mut false,
                ));
                break 'constants;
            }
        }
    }
    if java.file_count() == 0 {
        notes.extend(budget_copy(Some("sweep_java_only"), budget, &mut false));
    }
    let mut rows = Vec::new();
    let mut truncated = false;
    for (file, reason) in java.sweep_notes() {
        let note = format!("sweep:{file}:{reason}");
        notes.extend(budget_copy(Some(&clip(&note)), budget, &mut false));
        truncated |= *reason == "sweep_memory_limit_exceeded";
    }
    let location_only: HashSet<_> = locations
        .iter()
        .map(|(file, line, _, _)| (file.as_str(), *line))
        .collect();
    for (file, lexed, parsed) in java.sweep_files() {
        let result = java_crypto::sweep(lexed, parsed, &ctx, max_rows - rows.len());
        truncated |= result.truncated;
        let mut clipped = false;
        for reason in result.reasons {
            let note = format!("sweep:{file}:{reason}");
            notes.extend(budget_copy(Some(&clip(&note)), budget, &mut clipped));
        }
        if let Some(reason) = parsed.ambiguity {
            let note = format!("sweep:{file}:{reason}");
            notes.extend(budget_copy(Some(&clip(&note)), budget, &mut clipped));
        }
        for mut r in result.rows {
            let family = r.algorithm.as_deref().and_then(algorithm_family);
            let in_cbom = sweep_matches(locations, file, r.line, family, sweep_kind(&r.api));
            if !in_cbom && location_only.contains(&(file, r.line)) {
                r.reasons.push("cbom_location_only_match".into());
            }
            let component = Component {
                name: r.algorithm.clone(),
                mode: r.mode.clone(),
                primitive: match r.api.as_str() {
                    "MessageDigest.getInstance" => Some("hash".into()),
                    "Cipher.getInstance" => Some("block-cipher".into()),
                    _ => None,
                },
                parameter_set_identifier: r.key_bits.map(|n| n.to_string()),
                ..Component::default()
            };
            let quantum_vulnerable = r
                .algorithm
                .as_ref()
                .and_then(|_| cbom::classify_quantum(&component));
            let label = java.classify(reach, file, r.line).label;
            let _ = budget_copy(Some(label.as_str()), budget, &mut clipped);
            let mut copy = |s: &str| budget_copy(Some(&clip(s)), budget, &mut clipped).unwrap();
            let row = SweepRow {
                file: copy(file),
                line: r.line,
                api: copy(&r.api),
                algorithm: r.algorithm.as_deref().map(&mut copy),
                mode: r.mode.as_deref().map(&mut copy),
                padding: r.padding.as_deref().map(&mut copy),
                key_bits: r.key_bits,
                provider: r.provider.as_deref().map(&mut copy),
                quantum_vulnerable,
                in_cbom,
                label,
                reasons: r.reasons.iter().map(|r| copy(r)).collect(),
            };
            let mut row = row;
            if let Some(note) = budget_note(clipped) {
                // Charge the fixed clipping marker too, without recursive markers.
                row.reasons
                    .extend(budget_copy(Some(&note), budget, &mut false));
            }
            rows.push(row);
        }
        if clipped {
            notes.extend(budget_copy(
                Some("cbom_value_clipped:budget"),
                budget,
                &mut false,
            ));
        }
    }
    if truncated {
        notes.extend(budget_copy(Some("sweep_truncated"), budget, &mut false));
    }
    rows
}

/// Characters a terminal may use to reorder or hide text (bidi controls,
/// marks, isolates, BOM, line/paragraph separators).
fn is_bidi_or_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// A terminal cell: control and bidi/format characters become `?` (the
/// strings come from untrusted files) and the cell is at most
/// [`MAX_COLUMN_CHARS`] characters, clipped with `…`.
fn clean(s: &str) -> String {
    let mut out = String::new();
    for (n, c) in s.chars().enumerate() {
        if n + 1 == MAX_COLUMN_CHARS && s.chars().nth(n + 1).is_some() {
            out.push('…');
            break;
        }
        out.push(if c.is_control() || is_bidi_or_format(c) {
            '?'
        } else {
            c
        });
    }
    out
}

/// Terminal summary table plus the honesty notes.
pub fn render(r: &Receipt) -> String {
    let header = [
        "LABEL",
        "QV",
        "ALGORITHM / ASSET",
        "LOCATION",
        "FUNCTION",
        "REASON",
    ];
    let mut table: Vec<[String; 6]> = vec![header.map(String::from)];
    for row in &r.rows {
        let asset = match (&row.algorithm, &row.name) {
            (Some(a), Some(n)) if a != n => format!("{a} / {}", n.split('@').next().unwrap_or(n)),
            (Some(a), _) => a.clone(),
            (None, Some(n)) => n.clone(),
            (None, None) => "-".into(),
        };
        let loc = match (&row.file, row.line) {
            (Some(f), Some(l)) => format!("{f}:{l}"),
            (Some(f), None) => f.clone(),
            _ => "-".into(),
        };
        table.push([
            row.label.as_str().into(),
            match row.quantum_vulnerable {
                Some(true) => "yes".into(),
                Some(false) => "no".into(),
                None => "?".into(),
            },
            clean(&asset),
            clean(&loc),
            clean(row.enclosing_function.as_deref().unwrap_or("-")),
            clean(&row.reasons.join(",")),
        ]);
    }
    let mut widths = [0usize; 6];
    for line in &table {
        for (i, cell) in line.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = format!(
        "vettalon cbom-check (experimental): {} rows, CBOM sha256 {}\n\n",
        r.rows.len(),
        &r.cbom.sha256[..12.min(r.cbom.sha256.len())]
    );
    for line in &table {
        let cells: Vec<String> = line
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<w$}", w = widths[i]))
            .collect();
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
    }
    let l = &r.summary.by_label;
    let q = &r.summary.by_quantum_vulnerable;
    out.push_str(&format!(
        "\nlabels: reachable {}, not_observed {}, unknown {}\nquantum-vulnerable (NIST IR 8547): yes {}, no {}, not classified {}\n",
        l["reachable"], l["not_observed"], l["unknown"], q["true"], q["false"], q["null"]
    ));
    if let Some(rows) = &r.sweep {
        out.push_str(&clean(&format!(
            "sweep: {} rows, {} not_in_cbom, truncated {}",
            rows.len(),
            rows.iter().filter(|r| !r.in_cbom).count(),
            r.cbom.notes.iter().any(|n| n == "sweep_truncated"),
        )));
        out.push('\n');
    }
    for note in &r.cbom.notes {
        let what = if note == NOTE_DEPENDENCIES_TRUNCATED {
            " (some CBOM `dependencies` were dropped by caps; a row may lack its algorithm)"
        } else {
            ""
        };
        out.push_str(&format!("CBOM note: {}{what}\n", clean(note)));
    }
    out.push_str(&format!(
        "\nNOTE: analysis is {ANALYSIS}.\n\
         `not_observed` only means no name-based reference to the enclosing function was found: it is NOT proof that the code is unreachable or safe.\n\
         {POLICY}. The receipt is unsigned.\n"
    ));
    out
}

/// Write the receipt as pretty JSON; never overwrites an existing file. The
/// JSON is streamed into a fresh temp file in the same directory (exclusive
/// create, random name), fsynced, then hard-linked to `path` (which fails if
/// `path` exists, atomically). Where hard links are unavailable it falls back
/// to an atomic no-replace rename (macOS `renamex_np(RENAME_EXCL)`, Linux
/// `renameat2(RENAME_NOREPLACE)`); without one it fails. The directory is
/// then fsynced (best effort) and the temp name is removed in every case.
pub fn write_receipt(path: &Path, r: &Receipt) -> std::io::Result<()> {
    const TMP_NAME_MAX: usize = 255;
    const TMP_NAME_OVERHEAD: usize = 1 + 1 + 32 + 4;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    // `.` + name + `.` + 32 hex + `.tmp`: clip the name part so the temp name
    // stays within the usual 255-byte file name limit.
    let name = name.to_string_lossy();
    let mut cut = name.len().min(TMP_NAME_MAX - TMP_NAME_OVERHEAD);
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        &name[..cut],
        uuid::Uuid::new_v4().simple()
    ));
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let result = fill_and_link(f, r, &tmp, path);
    let _ = std::fs::remove_file(&tmp);
    if result.is_ok() {
        sync_dir(dir);
    }
    result
}

fn fill_and_link(f: std::fs::File, r: &Receipt, tmp: &Path, path: &Path) -> std::io::Result<()> {
    let mut w = std::io::BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, r)?;
    w.write_all(b"\n")?;
    let f = w.into_inner().map_err(|e| e.into_error())?;
    f.sync_all()?;
    drop(f);
    match std::fs::hard_link(tmp, path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => rename_no_replace(tmp, path)
            .map_err(|e2| match e2.kind() {
                std::io::ErrorKind::AlreadyExists => e2,
                kind => std::io::Error::new(
                    kind,
                    format!(
                        "hard link failed ({e}) and the atomic no-replace rename fallback failed \
                         ({e2}); nothing was overwritten"
                    ),
                ),
            }),
        other => other,
    }
}

/// Rename `from` to `to` atomically, failing with `AlreadyExists` if `to`
/// exists; never replaces. `Unsupported` where no such primitive exists.
#[cfg(target_os = "macos")]
fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    unsafe extern "C" {
        fn renamex_np(
            from: *const libc::c_char,
            to: *const libc::c_char,
            flags: libc::c_uint,
        ) -> libc::c_int;
    }
    const RENAME_EXCL: libc::c_uint = 0x0000_0004;
    let (from, to) = (c_path(from)?, c_path(to)?);
    // SAFETY: both pointers are valid NUL-terminated strings for the call.
    if unsafe { renamex_np(from.as_ptr(), to.as_ptr(), RENAME_EXCL) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    const RENAME_NOREPLACE: libc::c_uint = 1;
    let (from, to) = (c_path(from)?, c_path(to)?);
    // SAFETY: both pointers are valid NUL-terminated strings for the call;
    // AT_FDCWD resolves them like rename(2).
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD as libc::c_long,
            from.as_ptr(),
            libc::AT_FDCWD as libc::c_long,
            to.as_ptr(),
            RENAME_NOREPLACE as libc::c_long,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ENOSYS | libc::EINVAL) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("renameat2(RENAME_NOREPLACE) is not supported here: {e}"),
        )),
        _ => Err(e),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rename_no_replace(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no atomic no-replace rename on this platform",
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn c_path(p: &Path) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// fsync a directory so a new entry in it is durable (best effort; errors,
/// including platforms that cannot open a directory, are ignored).
fn sync_dir(dir: &Path) {
    if cfg!(unix)
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
}

/// CLI body: returns the process exit code (0 done, 2 error). The exit code
/// does not depend on the labels.
pub fn run_cli(
    cbom: &Path,
    root: &Path,
    entries: &[String],
    json: Option<&Path>,
    sweep: bool,
) -> i32 {
    let fail = |msg: String| {
        eprintln!("[vettalon] cbom-check: {msg}");
        2
    };
    let outs: Vec<PathBuf> = json.map(Path::to_path_buf).into_iter().collect();
    let receipt = match run_with_sweep(cbom, root, entries, &outs, sweep) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    // The hard link (or no-replace rename) inside `write_receipt` is the only
    // existence check, so there is no window between checking and writing.
    if let Some(p) = json
        && let Err(e) = write_receipt(p, &receipt)
    {
        return if e.kind() == std::io::ErrorKind::AlreadyExists {
            fail(format!(
                "{} already exists; refusing to overwrite",
                p.display()
            ))
        } else {
            fail(format!("cannot write {}: {e}", p.display()))
        };
    }
    print!("{}", render(&receipt));
    if let Some(p) = json {
        println!(
            "receipt written: {} (sha256 {})",
            p.display(),
            receipt.receipt_sha256
        );
    }
    0
}

#[cfg(test)]
#[path = "cbom_check_tests.rs"]
mod tests;
