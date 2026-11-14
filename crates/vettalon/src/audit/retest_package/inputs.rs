//! Package inputs: bounded reads, `attest::extract` on every receipt, and
//! the extra package rules of the A4 design ("Extra package rules"):
//!
//! 1. A `still_observed` / `not_observed` retest result carries a receipt.
//! 2. A retest result's `new_file_sha256` is its receipt's
//!    `target_file_sha256`; `old_file_sha256` is the report finding's
//!    `file_hash` when a report is given.
//! 3. A report given with a retest hashes to `old_report_sha256`.
//! 4. Reproduce and fix-check receipts bind to exactly one report finding
//!    (file, file hash, function when recorded, oracle class); without a
//!    report the row is keyed by the receipt's own target.
//! 5. A bundle decodes, its subject digest names one included receipt and its
//!    Statement matches that receipt's predicate. With `--key`, the exact
//!    accepted bytes must also pass the configured signature verifier.
//! 6. Any refusal stops the whole build ([`PackageRefusal`], no partial
//!    result).
//! 7. Repo-derived text is sanitised and labelled in [`super::record`].
//!
//! Inputs are read as regular, non-symlink files with size caps. Nothing is
//! inferred from free text: oracle classes come from validated verification
//! events or harness digests (or the report finding's CWE), variant sets from
//! their exact sha256.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::attest::predicate::{ExtractedReceipt, ReceiptKind};
use crate::attest::statement::{BUNDLE_MAX_BYTES, check_bundle, decode_bundle_statement};
use crate::audit::fix_check::FixCheckRun;
use crate::audit::poc_oracle::{OracleClass, classify_finding_target, oracle_classes};
use crate::audit::retest::{
    RetestReport, RetestStateError, TARGET_PLANS_MAX_BYTES, parse_target_plans,
    validate_retest_state,
};
use crate::audit::schema::{AuditReport, Finding, sha256_hex};
use crate::audit::target_poc::{Runtime, TargetCall, TargetPocOutcome, TargetPocReceipt};
use crate::audit::variants::{VariantSet, VariantSetStamp, variant_set_for};
use crate::disclose::receipt::{
    check_file_binding, check_file_path, check_function, shell_safe_name,
};

use super::token::*;
use super::{
    MAX_BUNDLES, MAX_RECEIPTS, MAX_REPORT_FINDINGS, MAX_RETEST_RESULTS, NAME_MAX_CHARS,
    PACKAGE_MAX_BYTES, PackageRefusal, RECEIPT_MAX_BYTES, REPORT_MAX_BYTES,
};

fn refuse(token: &'static str, message: impl Into<String>) -> PackageRefusal {
    PackageRefusal::new(token, message)
}

/// Paths of the package inputs, as given on the command line.
#[derive(Debug, Clone, Default)]
pub struct PackageRequest {
    pub retest: Option<PathBuf>,
    pub reproduce: Vec<PathBuf>,
    pub fix_check: Vec<PathBuf>,
    pub report: Option<PathBuf>,
    /// Copy the report into the package (`--include-report`); its sha256 is
    /// recorded either way.
    pub include_report: bool,
    pub targets: Option<PathBuf>,
    pub bundles: Vec<PathBuf>,
    pub pq_sigs: Vec<PathBuf>,
    pub pq_key: Option<PathBuf>,
    /// Local public key; requires signature verification before returning inputs.
    pub key: Option<PathBuf>,
}

/// What a file in the package is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Retest,
    Reproduce,
    FixCheck,
    Plans,
    Report,
    Signature,
    PqSignature,
}

impl SourceKind {
    fn dir(self) -> &'static str {
        match self {
            Self::Retest => "receipts/retest",
            Self::Reproduce => "receipts/reproduce",
            Self::FixCheck => "receipts/fix-check",
            Self::Plans => "receipts/plans",
            Self::Report => "report",
            Self::Signature => "signatures",
            Self::PqSignature => "signatures-pq",
        }
    }
}

/// One file that goes into the package, byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub kind: SourceKind,
    /// The input's original basename (already checked to be package-safe).
    pub name: String,
    /// Path inside the package (`receipts/retest/<name>`, ...).
    pub path: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
    /// For a signature: the package path of the receipt it covers.
    pub covers: Option<String>,
}

/// One input file as read: its basename and exact text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawInput {
    pub name: String,
    pub raw: String,
}

/// A scan report: its exact bytes and the report parsed and validated from
/// them by [`crate::audit::parse_report_for_delivery`].
#[derive(Debug, Clone)]
pub(crate) struct ReportInput {
    pub name: String,
    pub raw: Vec<u8>,
    pub report: AuditReport,
}

/// Every input already read into memory; [`check_inputs`] applies the rules.
#[derive(Debug, Clone, Default)]
pub(crate) struct RawInputs {
    pub retest: Option<RawInput>,
    pub reproduce: Vec<RawInput>,
    pub fix_check: Vec<RawInput>,
    pub report: Option<ReportInput>,
    pub include_report: bool,
    pub targets: Option<RawInput>,
    pub bundles: Vec<RawInput>,
    pub pq_sigs: Vec<RawInput>,
}

/// Where a row's id comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdSource {
    /// A finding of the supplied scan report.
    Report,
    /// A retest result's `finding_id` (no report supplied).
    Retest,
    /// A receipt's own `target_file#function` (no report supplied).
    Target,
}

/// Rows sort by id bytes, then by id source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RowKey {
    pub id: String,
    pub source: IdSource,
}

pub(crate) struct RetestInput {
    pub path: String,
    pub sha256: String,
    pub report: RetestReport,
    /// The document as JSON, for evidence pointers.
    pub value: Value,
    /// Oracle class per result (index-aligned with `report.results`).
    pub classes: Vec<Option<OracleClass>>,
}

pub(crate) struct ReproduceInput {
    pub path: String,
    pub sha256: String,
    pub value: Value,
    pub receipt: TargetPocReceipt,
    pub outcome: TargetPocOutcome,
    pub reason: Option<String>,
    pub class: Option<OracleClass>,
}

pub(crate) struct FixCheckInput {
    pub path: String,
    pub sha256: String,
    pub value: Value,
    pub run: FixCheckRun,
    /// The (class, runtime) set whose sha256 the receipt names; `None` when
    /// the receipt names no generated set (explicit fixture list).
    pub variant_set: Option<VariantSet>,
}

/// One record row: everything bound to one finding (or one target).
pub(crate) struct Row {
    pub key: RowKey,
    /// Index into the report's findings.
    pub finding: Option<usize>,
    pub file: Option<String>,
    pub function: Option<String>,
    /// Index into the retest report's results.
    pub retest: Option<usize>,
    pub reproduce: Option<usize>,
    /// Indices into the fix checks, sorted by `diff_sha256`.
    pub fix_checks: Vec<usize>,
    pub class: Option<OracleClass>,
    pub runtime: Option<Runtime>,
    /// The operator plan whose hash a receipt of this row records.
    pub plan: Option<TargetCall>,
    /// Distinct plan hashes the row's receipts record, sorted.
    pub plan_sha256s: Vec<String>,
}

/// Accepted package inputs. Built only by [`load_inputs`] (or the in-memory
/// [`check_inputs`]); every rule has already passed.
pub struct PackageInputs {
    /// Files to copy into the package, sorted by package path.
    pub sources: Vec<Source>,
    /// Original input directories remain untrusted after bytes are staged.
    pub(crate) tool_exclusions: Vec<PathBuf>,
    pub(crate) retest: Option<RetestInput>,
    pub(crate) reproduce: Vec<ReproduceInput>,
    pub(crate) fix_checks: Vec<FixCheckInput>,
    pub(crate) report: Option<AuditReport>,
    pub(crate) report_sha256: Option<String>,
    pub(crate) rows: Vec<Row>,
}

impl std::fmt::Debug for PackageInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let paths: Vec<&str> = self.sources.iter().map(|s| s.path.as_str()).collect();
        f.debug_struct("PackageInputs")
            .field("sources", &paths)
            .field("rows", &self.row_ids())
            .finish()
    }
}

impl PackageInputs {
    /// Row ids in record order (the engagement file may only name these).
    pub fn row_ids(&self) -> Vec<&str> {
        self.rows.iter().map(|row| row.key.id.as_str()).collect()
    }

    /// SHA-256 of the scan report's bytes, when one was given.
    pub fn report_sha256(&self) -> Option<&str> {
        self.report_sha256.as_deref()
    }
}

/// Read every input named in `request` and apply the package rules.
pub fn load_inputs(request: &PackageRequest) -> Result<PackageInputs, PackageRefusal> {
    load_inputs_with_verifier(request, &CosignBundleVerifier)
}

/// Rule 5 seam: implementations verify the exact accepted bytes, never reopen
/// the original receipt or bundle paths after validation.
pub trait BundleVerifier {
    fn verify(&self, key: &Path, receipt: &Source, bundle: &Source) -> Result<(), String>;

    fn verify_excluding(
        &self,
        key: &Path,
        receipt: &Source,
        bundle: &Source,
        _excluded: &[&Path],
    ) -> Result<(), String> {
        self.verify(key, receipt, bundle)
    }
}

pub struct CosignBundleVerifier;

impl BundleVerifier for CosignBundleVerifier {
    fn verify(&self, key: &Path, receipt: &Source, bundle: &Source) -> Result<(), String> {
        self.verify_excluding(key, receipt, bundle, &[])
    }

    fn verify_excluding(
        &self,
        key: &Path,
        receipt: &Source,
        bundle: &Source,
        excluded: &[&Path],
    ) -> Result<(), String> {
        // A separate thread permits this synchronous loader to be used from
        // either synchronous code or an existing Tokio runtime.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let stage = tempfile::Builder::new()
                        .prefix("vettalon-package-verify-")
                        .tempdir()
                        .map_err(|e| e.to_string())?;
                    let blob = stage.path().join(&receipt.name);
                    let signature_dir = stage.path().join("signatures");
                    std::fs::create_dir(&signature_dir).map_err(|e| e.to_string())?;
                    let signature = signature_dir.join(&bundle.name);
                    std::fs::write(&blob, &receipt.bytes).map_err(|e| e.to_string())?;
                    std::fs::write(&signature, &bundle.bytes).map_err(|e| e.to_string())?;
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| e.to_string())?;
                    runtime
                        .block_on(crate::attest::verify_receipt_excluding(
                            &blob, key, &signature, excluded,
                        ))
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                })
                .join()
                .map_err(|_| "cosign verification thread failed".to_owned())?
        })
    }
}

/// Load and validate content before invoking the selected signature verifier.
pub fn load_inputs_with_verifier(
    request: &PackageRequest,
    verifier: &dyn BundleVerifier,
) -> Result<PackageInputs, PackageRefusal> {
    let receipts =
        usize::from(request.retest.is_some()) + request.reproduce.len() + request.fix_check.len();
    check_counts(receipts, request.bundles.len())?;
    if request.pq_sigs.len() > MAX_BUNDLES {
        return Err(refuse(INPUT_COUNT_EXCEEDED, "too many PQ sidecars"));
    }
    if request.pq_key.is_some() && request.key.is_none() {
        return Err(refuse("pq_key_requires_key", "--pq-pub requires --key"));
    }
    let mut remaining = PACKAGE_MAX_BYTES;
    let mut read = |path: &Path, cap: u64, label: &str| -> Result<RawInput, PackageRefusal> {
        let name = base_name(path, label)?;
        let raw =
            crate::remediation::read_regular_capped_with_policy(path, cap, label, true, |size| {
                if size > remaining {
                    Err(PACKAGE_TOO_LARGE.into())
                } else {
                    Ok(remaining.min(cap))
                }
            })
            .map_err(|e| {
                refuse(
                    if e == PACKAGE_TOO_LARGE {
                        PACKAGE_TOO_LARGE
                    } else {
                        INPUT_UNREADABLE
                    },
                    e,
                )
            })?;
        remaining -= raw.len() as u64;
        Ok(RawInput { name, raw })
    };
    let retest = match &request.retest {
        Some(path) => Some(read(path, RECEIPT_MAX_BYTES, "retest report")?),
        None => None,
    };
    let reproduce = request
        .reproduce
        .iter()
        .map(|path| read(path, RECEIPT_MAX_BYTES, "reproduce receipt"))
        .collect::<Result<Vec<_>, _>>()?;
    let fix_check = request
        .fix_check
        .iter()
        .map(|path| read(path, RECEIPT_MAX_BYTES, "fix check receipt"))
        .collect::<Result<Vec<_>, _>>()?;
    let report = match &request.report {
        Some(path) => {
            let input = read(path, REPORT_MAX_BYTES, "scan report")?;
            let report = parse_report(input.raw.as_bytes())?;
            Some(ReportInput {
                name: input.name,
                raw: input.raw.into_bytes(),
                report,
            })
        }
        None => None,
    };
    let targets = match &request.targets {
        Some(path) => Some(read(path, TARGET_PLANS_MAX_BYTES as u64, "target plans")?),
        None => None,
    };
    let bundles = request
        .bundles
        .iter()
        .map(|path| read(path, BUNDLE_MAX_BYTES as u64, "bundle"))
        .collect::<Result<Vec<_>, _>>()?;
    let pq_sigs = request
        .pq_sigs
        .iter()
        .map(|path| {
            read(
                path,
                crate::attest::pq::SIDECAR_MAX_BYTES as u64,
                "PQ sidecar",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut inputs = check_inputs(RawInputs {
        retest,
        reproduce,
        fix_check,
        report,
        include_report: request.include_report,
        targets,
        bundles,
        pq_sigs,
    })?;
    for path in request
        .retest
        .iter()
        .chain(request.reproduce.iter())
        .chain(request.fix_check.iter())
        .chain(request.report.iter())
        .chain(request.targets.iter())
        .chain(request.bundles.iter())
        .chain(request.pq_sigs.iter())
    {
        inputs.tool_exclusions.extend(
            crate::attest::receipt_tool_exclusions(path)
                .map_err(|e| refuse(BUNDLE_SIGNATURE_INVALID, e))?,
        );
    }
    if let Some(key) = &request.key {
        let excluded: Vec<&Path> = inputs
            .tool_exclusions
            .iter()
            .map(PathBuf::as_path)
            .collect();
        let bundles: Vec<_> = inputs
            .sources
            .iter()
            .filter(|s| s.kind == SourceKind::Signature)
            .collect();
        if bundles.is_empty() {
            return Err(refuse(
                BUNDLE_SIGNATURE_INVALID,
                "a key requires at least one bundle to verify",
            ));
        }
        for bundle in bundles {
            let receipt = inputs
                .sources
                .iter()
                .find(|s| Some(&s.path) == bundle.covers.as_ref())
                .ok_or_else(|| {
                    refuse(BUNDLE_SIGNATURE_INVALID, "bundle has no accepted receipt")
                })?;
            verifier
                .verify_excluding(key, receipt, bundle, &excluded)
                .map_err(|e| refuse(BUNDLE_SIGNATURE_INVALID, e))?;
        }
    }
    if let Some(path) = &request.pq_key {
        let key = super::write::read_pq_key(path)?;
        super::write::verify_pq_signatures(&inputs, &key)?;
    }
    Ok(inputs)
}

fn base_name(path: &Path, label: &str) -> Result<String, PackageRefusal> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            refuse(
                NAME_INVALID,
                format!("the {label} path must end in a UTF-8 file name"),
            )
        })
}

fn check_row_count(count: usize, cap: usize, label: &str) -> Result<(), PackageRefusal> {
    if count > cap {
        Err(refuse(
            INPUT_COUNT_EXCEEDED,
            format!("{label} exceeds {cap}"),
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(field_identifier, rename_all = "snake_case")]
enum CountField {
    Findings,
    Results,
    #[serde(other)]
    Other,
}

struct RowLimit<'a> {
    cap: usize,
    exceeded: &'a mut bool,
}

impl<'de> DeserializeSeed<'de> for RowLimit<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for RowLimit<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a bounded array of report rows")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        for count in 0..=self.cap {
            if seq.next_element::<IgnoredAny>()?.is_none() {
                return Ok(());
            }
            if count == self.cap {
                *self.exceeded = true;
                return Err(serde::de::Error::custom("report row count exceeded"));
            }
        }
        unreachable!()
    }
}

struct ReportRowLimit<'a> {
    field: CountField,
    limit: RowLimit<'a>,
}

impl<'de> Visitor<'de> for ReportRowLimit<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a report object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(field) = map.next_key::<CountField>()? {
            if field == self.field {
                map.next_value_seed(RowLimit {
                    cap: self.limit.cap,
                    exceeded: self.limit.exceeded,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

/// Count only the top-level rows before any typed or Value deserialization.
/// IgnoredAny discards each value without building its strings or collections;
/// stop on row cap + 1, even if the rest of the document is malformed.
fn check_json_row_count(
    raw: &[u8],
    field: CountField,
    cap: usize,
    label: &str,
    invalid_token: &'static str,
) -> Result<(), PackageRefusal> {
    let mut exceeded = false;
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let result = deserializer
        .deserialize_map(ReportRowLimit {
            field,
            limit: RowLimit {
                cap,
                exceeded: &mut exceeded,
            },
        })
        .and_then(|()| deserializer.end());
    if exceeded {
        return Err(refuse(
            INPUT_COUNT_EXCEEDED,
            format!("{label} exceeds {cap}"),
        ));
    }
    result.map_err(|e| refuse(invalid_token, format!("{label} refused: {e}")))
}

/// Shared report entry point for package builds and verification. Bound the
/// findings before the delivery parser allocates any typed report data.
pub(super) fn parse_report(raw: &[u8]) -> Result<AuditReport, PackageRefusal> {
    check_json_row_count(
        raw,
        CountField::Findings,
        MAX_REPORT_FINDINGS,
        "report findings",
        REPORT_REFUSED,
    )?;
    crate::audit::parse_report_for_delivery(raw)
        .map_err(|e| refuse(REPORT_REFUSED, format!("scan report refused: {e}")))
}

fn check_counts(receipts: usize, bundles: usize) -> Result<(), PackageRefusal> {
    if receipts == 0 {
        return Err(refuse(
            NO_RECEIPTS,
            "give at least one of --retest, --reproduce or --fix-check",
        ));
    }
    if receipts > MAX_RECEIPTS {
        return Err(refuse(
            INPUT_COUNT_EXCEEDED,
            format!("{receipts} receipts given; a package holds at most {MAX_RECEIPTS}"),
        ));
    }
    if bundles > MAX_BUNDLES {
        return Err(refuse(
            INPUT_COUNT_EXCEEDED,
            format!("{bundles} bundles given; a package holds at most {MAX_BUNDLES}"),
        ));
    }
    Ok(())
}

/// `^[A-Za-z0-9._-]{1,100}$` (the disclose `shell_safe_name` rule, bounded),
/// not starting with `.` (no `.`/`..`, no hidden file) or `-` (never read as
/// an option in a printed command).
fn check_name(name: &str, label: &str) -> Result<(), PackageRefusal> {
    if name.chars().count() <= NAME_MAX_CHARS
        && shell_safe_name(name)
        && !name.starts_with(['.', '-'])
    {
        Ok(())
    } else {
        Err(refuse(
            NAME_INVALID,
            format!(
                "{label} file name {name:?} must match ^[A-Za-z0-9._-]{{1,{NAME_MAX_CHARS}}}$ and \
                 not start with '.' or '-'; rename the file before packaging"
            ),
        ))
    }
}

/// A receipt as accepted by `attest::extract`, with its kind checked.
struct Extracted<'a> {
    kind: ReceiptKind,
    name: String,
    path: String,
    raw: &'a str,
    sha256: String,
    predicate: Value,
    value: Value,
}

fn extract_as(
    input: &RawInput,
    kind: ReceiptKind,
    dir: SourceKind,
) -> Result<Extracted<'_>, PackageRefusal> {
    let ExtractedReceipt {
        kind: found,
        predicate,
    } = crate::attest::extract(&input.raw)
        .map_err(|e| refuse(RECEIPT_REFUSED, format!("{} refused: {e}", input.name)))?;
    if found != kind {
        return Err(refuse(
            RECEIPT_KIND_MISMATCH,
            format!(
                "{} is a {} receipt, not a {} receipt",
                input.name,
                found.key(),
                kind.key()
            ),
        ));
    }
    let value: Value = serde_json::from_str(&input.raw)
        .map_err(|e| refuse(RECEIPT_REFUSED, format!("{} is not JSON: {e}", input.name)))?;
    Ok(Extracted {
        kind,
        name: input.name.clone(),
        path: format!("{}/{}", dir.dir(), input.name),
        raw: &input.raw,
        sha256: sha256_hex(input.raw.as_bytes()),
        predicate,
        value,
    })
}

/// Apply every package rule to inputs already in memory.
pub(crate) fn check_inputs(raw: RawInputs) -> Result<PackageInputs, PackageRefusal> {
    let receipt_inputs: Vec<(&RawInput, &str)> = raw
        .retest
        .iter()
        .map(|input| (input, "retest report"))
        .chain(
            raw.reproduce
                .iter()
                .map(|input| (input, "reproduce receipt")),
        )
        .chain(
            raw.fix_check
                .iter()
                .map(|input| (input, "fix check receipt")),
        )
        .collect();
    check_counts(receipt_inputs.len(), raw.bundles.len())?;
    if raw.pq_sigs.len() > MAX_BUNDLES {
        return Err(refuse(INPUT_COUNT_EXCEEDED, "too many PQ sidecars"));
    }

    // Sizes: each input, then the package as a whole.
    let mut total: u64 = 0;
    for (input, label) in &receipt_inputs {
        let len = input.raw.len() as u64;
        if len > RECEIPT_MAX_BYTES {
            return Err(refuse(
                INPUT_UNREADABLE,
                format!(
                    "{label} {} is larger than {RECEIPT_MAX_BYTES} bytes",
                    input.name
                ),
            ));
        }
        total += len;
    }
    for sidecar in &raw.pq_sigs {
        if sidecar.raw.len() > crate::attest::pq::SIDECAR_MAX_BYTES {
            return Err(refuse(INPUT_UNREADABLE, "PQ sidecar exceeds 16 KiB"));
        }
        total += sidecar.raw.len() as u64;
    }
    for bundle in &raw.bundles {
        if bundle.raw.len() > BUNDLE_MAX_BYTES {
            return Err(refuse(
                INPUT_UNREADABLE,
                format!(
                    "bundle {} is larger than {BUNDLE_MAX_BYTES} bytes",
                    bundle.name
                ),
            ));
        }
        total += bundle.raw.len() as u64;
    }
    if let Some(targets) = &raw.targets {
        if targets.raw.len() > TARGET_PLANS_MAX_BYTES {
            return Err(refuse(
                INPUT_UNREADABLE,
                format!("target plans are larger than {TARGET_PLANS_MAX_BYTES} bytes"),
            ));
        }
        total += targets.raw.len() as u64;
    }
    if let Some(report) = &raw.report {
        if report.raw.len() as u64 > REPORT_MAX_BYTES {
            return Err(refuse(
                INPUT_UNREADABLE,
                format!("scan report is larger than {REPORT_MAX_BYTES} bytes"),
            ));
        }
        total += report.raw.len() as u64;
        check_row_count(
            report.report.findings.len(),
            MAX_REPORT_FINDINGS,
            "report findings",
        )?;
    }
    if total > PACKAGE_MAX_BYTES {
        return Err(refuse(
            PACKAGE_TOO_LARGE,
            format!("the package inputs total {total} bytes; the cap is {PACKAGE_MAX_BYTES}"),
        ));
    }

    // Names: package-safe, unique across all receipts (signatures share one
    // directory) without case (case-insensitive file systems).
    let mut names = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for (input, label) in &receipt_inputs {
        check_name(&input.name, label)?;
        if !names.insert(input.name.to_ascii_lowercase()) {
            return Err(refuse(
                NAME_DUPLICATE,
                format!(
                    "two receipts are named {:?} (names are compared without case); rename one",
                    input.name
                ),
            ));
        }
        if !digests.insert(sha256_hex(input.raw.as_bytes())) {
            return Err(refuse(
                RECEIPT_DUPLICATE,
                format!("{} repeats the bytes of another receipt", input.name),
            ));
        }
    }
    if let Some(targets) = &raw.targets {
        check_name(&targets.name, "target plans")?;
    }
    if let Some(report) = raw.report.as_ref().filter(|_| raw.include_report) {
        check_name(&report.name, "scan report")?;
    }

    let report_sha256 = raw.report.as_ref().map(|r| sha256_hex(&r.raw));
    let report = raw.report.as_ref().map(|r| &r.report);
    let index = FindingIndex::new(report);

    let mut extracted = Vec::new();
    let retest = match &raw.retest {
        Some(input) => {
            let (retest, ex) = load_retest(input, report, report_sha256.as_deref(), &index)?;
            extracted.push(ex);
            Some(retest)
        }
        None => None,
    };

    let mut rows: BTreeMap<RowKey, Row> = BTreeMap::new();
    if let Some(retest) = &retest {
        for (i, result) in retest.report.results.iter().enumerate() {
            let source = if report.is_some() {
                IdSource::Report
            } else {
                IdSource::Retest
            };
            let finding = index.get(&result.finding_id);
            let row = row_entry(
                &mut rows,
                result.finding_id.clone(),
                source,
                finding,
                report,
            );
            row.retest = Some(i);
            if let Some(receipt) = &result.receipt {
                row.file.get_or_insert_with(|| receipt.target_file.clone());
                row.function = Some(receipt.target_function.clone());
            }
        }
    }

    let mut reproduce = Vec::new();
    for input in &raw.reproduce {
        let ex = extract_as(input, ReceiptKind::Reproduce, SourceKind::Reproduce)?;
        let receipt: TargetPocReceipt = serde_json::from_str(&input.raw)
            .map_err(|e| refuse(RECEIPT_REFUSED, format!("{} refused: {e}", input.name)))?;
        check_receipt_fields(&receipt, &input.name)?;
        let (outcome, reason, own) = receipt
            .validate_stored_with_class(None)
            .map_err(|e| refuse(RECEIPT_REFUSED, format!("{} refused: {e}", input.name)))?;
        let (key, finding, class) = match report {
            Some(report) => {
                let identity_matches = |f: &Finding| {
                    check_file_binding(
                        &receipt.target_file,
                        receipt.target_file_sha256.as_deref(),
                        Some(&receipt.target_function),
                        f,
                    )
                    .is_ok()
                };
                let candidates: Vec<_> = report
                    .findings
                    .iter()
                    .filter(|f| identity_matches(f))
                    .collect();
                if let Some(own) = own
                    && !candidates.is_empty()
                    && candidates
                        .iter()
                        .all(|f| classify_finding_target(f).is_some_and(|class| class != own))
                {
                    return Err(refuse(
                        ORACLE_CLASS_CONFLICT,
                        "receipt class conflicts with the bound report findings",
                    ));
                }
                let found = bind_one(report, &input.name, |f| {
                    check_file_binding(
                        &receipt.target_file,
                        receipt.target_file_sha256.as_deref(),
                        Some(&receipt.target_function),
                        f,
                    )
                    .ok()?;
                    let class = classify_finding_target(f)?;
                    if own.is_some_and(|own| own != class) {
                        return None;
                    }
                    Some(Some(class))
                })?;
                let f = &report.findings[found.0];
                let class = resolve_class(&receipt, own, found.1, &input.name)?;
                (
                    RowKey {
                        id: f.id.clone(),
                        source: IdSource::Report,
                    },
                    Some(found.0),
                    class,
                )
            }
            None => (
                RowKey {
                    id: format!("{}#{}", receipt.target_file, receipt.target_function),
                    source: IdSource::Target,
                },
                None,
                own,
            ),
        };
        let row = row_entry(&mut rows, key.id.clone(), key.source, finding, report);
        if row.reproduce.is_some() {
            return Err(refuse(
                REPRODUCE_DUPLICATE_FOR_FINDING,
                format!(
                    "{} is a second reproduce receipt for finding row {:?}; give one",
                    input.name, key.id
                ),
            ));
        }
        row.reproduce = Some(reproduce.len());
        row.file.get_or_insert_with(|| receipt.target_file.clone());
        row.function = Some(receipt.target_function.clone());
        reproduce.push(ReproduceInput {
            path: ex.path.clone(),
            sha256: ex.sha256.clone(),
            value: ex.value.clone(),
            receipt,
            outcome,
            reason,
            class,
        });
        extracted.push(ex);
    }

    let mut fix_checks = Vec::new();
    for input in &raw.fix_check {
        let ex = extract_as(input, ReceiptKind::FixCheck, SourceKind::FixCheck)?;
        let run: FixCheckRun = serde_json::from_str(&input.raw)
            .map_err(|e| refuse(RECEIPT_REFUSED, format!("{} refused: {e}", input.name)))?;
        let binding = run.binding.as_ref().ok_or_else(|| {
            refuse(
                RECEIPT_UNBOUND,
                format!(
                    "{} has no fix_context_v1 binding, so it names no target file; it cannot be \
                     placed in a record",
                    input.name
                ),
            )
        })?;
        check_fix_fields(&run, &input.name)?;
        let runtime = Runtime::for_file(&binding.target_file).map_err(|e| {
            refuse(
                RECEIPT_FIELD_INVALID,
                format!("{} binding target_file refused: {e}", input.name),
            )
        })?;
        let variant_set = lookup_variant_set(&run, runtime, &input.name)?;
        let set_class = variant_set.map(|set| set.class);
        let (key, finding) = match report {
            Some(report) => {
                // A fix-check binding records no function, so the oracle
                // class of its variant set also has to fit the finding.
                let (found, _) = bind_one(report, &input.name, |f| {
                    check_file_binding(
                        &binding.target_file,
                        binding.finding_file_sha256.as_deref(),
                        None,
                        f,
                    )
                    .ok()?;
                    match (set_class, classify_finding_target(f)) {
                        (Some(a), Some(b)) if a != b => None,
                        (Some(_), None) => None,
                        (a, b) => Some(a.or(b)),
                    }
                })?;
                (
                    RowKey {
                        id: report.findings[found].id.clone(),
                        source: IdSource::Report,
                    },
                    Some(found),
                )
            }
            None => (
                RowKey {
                    id: binding.target_file.clone(),
                    source: IdSource::Target,
                },
                None,
            ),
        };
        let row = row_entry(&mut rows, key.id.clone(), key.source, finding, report);
        row.file.get_or_insert_with(|| binding.target_file.clone());
        row.fix_checks.push(fix_checks.len());
        fix_checks.push(FixCheckInput {
            path: ex.path.clone(),
            sha256: ex.sha256.clone(),
            value: ex.value.clone(),
            run,
            variant_set,
        });
        extracted.push(ex);
    }

    // Per row: one oracle class, runtime, sorted fix checks, plan hashes.
    for row in rows.values_mut() {
        // Report ids and `file#function` keys are repo-derived as well.
        check_finding_id(&row.key.id)?;
        let mut classes: BTreeSet<&'static str> = BTreeSet::new();
        let mut class = None;
        let mut note = |c: Option<OracleClass>| {
            if let Some(c) = c {
                classes.insert(class_key(c));
                class = Some(c);
            }
        };
        if let (Some(i), Some(retest)) = (row.retest, &retest) {
            note(retest.classes[i]);
        }
        if let Some(i) = row.reproduce {
            note(reproduce[i].class);
        }
        for &i in &row.fix_checks {
            note(fix_checks[i].variant_set.map(|set| set.class));
        }
        // The finding's own class only takes part in the conflict check: a
        // row whose receipts name no class (nothing ran) shows no inputs.
        if let (Some(i), Some(report)) = (row.finding, report)
            && class.is_some()
            && let Some(finding_class) = classify_finding_target(&report.findings[i])
        {
            classes.insert(class_key(finding_class));
        }
        if classes.len() > 1 {
            return Err(refuse(
                ORACLE_CLASS_CONFLICT,
                format!(
                    "finding row {:?} has receipts for different oracle classes ({})",
                    row.key.id,
                    classes.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        row.class = class;
        row.runtime = row
            .file
            .as_deref()
            .and_then(|file| Runtime::for_file(file).ok());
        row.fix_checks.sort_by(|a, b| {
            let (a, b) = (&fix_checks[*a], &fix_checks[*b]);
            (&a.run.check.diff_sha256, &a.path).cmp(&(&b.run.check.diff_sha256, &b.path))
        });
        let mut plans = BTreeSet::new();
        if let (Some(i), Some(retest)) = (row.retest, &retest)
            && let Some(receipt) = &retest.report.results[i].receipt
        {
            plans.extend(receipt.target_plan_sha256.clone());
        }
        if let Some(i) = row.reproduce {
            plans.extend(reproduce[i].receipt.target_plan_sha256.clone());
        }
        for &i in &row.fix_checks {
            if let Some(binding) = &fix_checks[i].run.binding {
                plans.extend(binding.target_plan_sha256.clone());
            }
        }
        row.plan_sha256s = plans.into_iter().collect();
    }

    let mut sources: Vec<Source> = extracted
        .iter()
        .map(|ex| Source {
            kind: match ex.kind {
                ReceiptKind::Retest => SourceKind::Retest,
                ReceiptKind::Reproduce => SourceKind::Reproduce,
                ReceiptKind::FixCheck => SourceKind::FixCheck,
            },
            name: ex.name.clone(),
            path: ex.path.clone(),
            sha256: ex.sha256.clone(),
            bytes: ex.raw.as_bytes().to_vec(),
            covers: None,
        })
        .collect();

    if let Some(targets) = &raw.targets {
        apply_plans(targets, &mut rows)?;
        sources.push(Source {
            kind: SourceKind::Plans,
            name: targets.name.clone(),
            path: format!("{}/{}", SourceKind::Plans.dir(), targets.name),
            sha256: sha256_hex(targets.raw.as_bytes()),
            bytes: targets.raw.as_bytes().to_vec(),
            covers: None,
        });
    }
    sources.extend(check_bundles(&raw.bundles, &extracted)?);
    let sidecars = check_pq_sidecars(&raw.pq_sigs, &sources)?;
    sources.extend(sidecars);
    if let Some(input) = raw.report.as_ref().filter(|_| raw.include_report) {
        sources.push(Source {
            kind: SourceKind::Report,
            name: input.name.clone(),
            path: format!("{}/{}", SourceKind::Report.dir(), input.name),
            sha256: sha256_hex(&input.raw),
            bytes: input.raw.clone(),
            covers: None,
        });
    }
    sources.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(PackageInputs {
        tool_exclusions: Vec::new(),
        sources,
        retest,
        reproduce,
        fix_checks,
        report: raw.report.map(|r| r.report),
        report_sha256,
        rows: rows.into_values().collect(),
    })
}

fn row_entry<'a>(
    rows: &'a mut BTreeMap<RowKey, Row>,
    id: String,
    source: IdSource,
    finding: Option<usize>,
    report: Option<&AuditReport>,
) -> &'a mut Row {
    let key = RowKey { id, source };
    rows.entry(key.clone()).or_insert_with(|| Row {
        file: finding.and_then(|i| report.map(|r| r.findings[i].file.clone())),
        key,
        finding,
        function: None,
        retest: None,
        reproduce: None,
        fix_checks: Vec::new(),
        class: None,
        runtime: None,
        plan: None,
        plan_sha256s: Vec::new(),
    })
}

/// Report findings by id. A repeated id is kept as ambiguous, never guessed.
struct FindingIndex {
    by_id: BTreeMap<String, Option<usize>>,
}

impl FindingIndex {
    fn new(report: Option<&AuditReport>) -> Self {
        let mut by_id = BTreeMap::new();
        for (i, f) in report
            .into_iter()
            .flat_map(|r| r.findings.iter())
            .enumerate()
        {
            by_id
                .entry(f.id.clone())
                .and_modify(|slot| *slot = None)
                .or_insert(Some(i));
        }
        Self { by_id }
    }

    fn get(&self, id: &str) -> Option<usize> {
        self.by_id.get(id).copied().flatten()
    }

    fn ambiguous(&self, id: &str) -> bool {
        matches!(self.by_id.get(id), Some(None))
    }
}

/// The single report finding `matches` accepts (with the class it yields).
/// None or several is a refusal.
fn bind_one(
    report: &AuditReport,
    name: &str,
    matches: impl Fn(&Finding) -> Option<Option<OracleClass>>,
) -> Result<(usize, Option<OracleClass>), PackageRefusal> {
    let mut found = report
        .findings
        .iter()
        .enumerate()
        .filter_map(|(i, f)| matches(f).map(|class| (i, class)));
    let Some(first) = found.next() else {
        return Err(refuse(
            RECEIPT_UNBOUND,
            format!(
                "{name} binds to no finding of the report (target file, file hash, function \
                 when recorded and oracle class must all match)"
            ),
        ));
    };
    if found.next().is_some() {
        return Err(refuse(
            RECEIPT_AMBIGUOUS,
            format!("{name} binds to more than one finding of the report"),
        ));
    }
    Ok(first)
}

/// The oracle class of a receipt checked against the finding's class:
/// a class the receipt itself proves (event or harness digest) must equal
/// the finding's, and the phases must re-derive under the finding's class.
fn resolve_class(
    receipt: &TargetPocReceipt,
    own: Option<OracleClass>,
    expected: Option<OracleClass>,
    label: &str,
) -> Result<Option<OracleClass>, PackageRefusal> {
    match (own, expected) {
        (Some(a), Some(b)) if a != b => Err(refuse(
            ORACLE_CLASS_CONFLICT,
            format!(
                "{label} proves oracle class {} but the finding is {}",
                class_key(a),
                class_key(b)
            ),
        )),
        (_, Some(b)) => {
            receipt
                .validate_stored_with_class(Some(b))
                .map_err(|e| refuse(RECEIPT_REFUSED, format!("{label} refused: {e}")))?;
            Ok(Some(b))
        }
        (own, None) => Ok(own),
    }
}

pub(crate) fn class_key(class: OracleClass) -> &'static str {
    match class {
        OracleClass::CommandInjection => "command_injection",
        OracleClass::PathTraversal => "path_traversal",
        OracleClass::Sqli => "sqli",
        OracleClass::Ssrf => "ssrf",
    }
}

fn load_retest<'a>(
    input: &'a RawInput,
    report: Option<&AuditReport>,
    report_sha256: Option<&str>,
    index: &FindingIndex,
) -> Result<(RetestInput, Extracted<'a>), PackageRefusal> {
    check_json_row_count(
        input.raw.as_bytes(),
        CountField::Results,
        MAX_RETEST_RESULTS,
        "retest results",
        RECEIPT_REFUSED,
    )?;
    let parsed: RetestReport = serde_json::from_str(&input.raw)
        .map_err(|e| refuse(RECEIPT_REFUSED, format!("{} refused: {e}", input.name)))?;
    check_row_count(parsed.results.len(), MAX_RETEST_RESULTS, "retest results")?;
    let mut classes = validate_retest_state(&parsed).map_err(|e| {
        let token = match e {
            RetestStateError::MissingReceipt => RETEST_RECEIPT_MISSING,
            RetestStateError::InvalidReportHash => RECEIPT_FIELD_INVALID,
            RetestStateError::InvalidRevision(_) => REVISION_INVALID,
            RetestStateError::FileHashMismatch(_) => RETEST_FILE_HASH_MISMATCH,
            RetestStateError::DuplicateFinding(_) => RETEST_RESULT_DUPLICATE,
            RetestStateError::InvalidFindingId(_) => FINDING_ID_INVALID,
            RetestStateError::InvalidField(_) => RECEIPT_FIELD_INVALID,
            RetestStateError::Invalid(_) => RECEIPT_REFUSED,
        };
        refuse(token, e.to_string())
    })?;
    let ex = extract_as(input, ReceiptKind::Retest, SourceKind::Retest)?;
    // Rule 3.
    if let Some(sha) = report_sha256
        && sha != parsed.old_report_sha256
    {
        return Err(refuse(
            REPORT_HASH_MISMATCH,
            format!(
                "the scan report hashes to {sha}, but the retest names old_report_sha256 {}",
                parsed.old_report_sha256
            ),
        ));
    }
    if report.is_some_and(|report| parsed.old_repo_commit != report.repo_commit) {
        return Err(refuse(
            RECEIPT_REFUSED,
            "old_repo_commit differs from the scan report",
        ));
    }
    for (result, class) in parsed.results.iter().zip(&mut classes) {
        let id = &result.finding_id;
        let label = format!("retest result {id:?}");
        let finding = match report {
            Some(report) => {
                if index.ambiguous(id) {
                    return Err(refuse(
                        RECEIPT_AMBIGUOUS,
                        format!("the report has more than one finding with id {id:?}"),
                    ));
                }
                let i = index.get(id).ok_or_else(|| {
                    refuse(
                        RETEST_FINDING_UNKNOWN,
                        format!("{label} names a finding the report does not have"),
                    )
                })?;
                Some(&report.findings[i])
            }
            None => None,
        };
        // Rule 2, old side.
        if let Some(f) = finding {
            if !match (&result.old_file_sha256, &f.file_hash) {
                (Some(a), Some(b)) => a.trim().eq_ignore_ascii_case(b.trim()),
                (None, None) => true,
                _ => false,
            } {
                return Err(refuse(
                    RETEST_FILE_HASH_MISMATCH,
                    format!("{label} old_file_sha256 is not the report finding's file_hash"),
                ));
            }
            if result.title != f.title || result.cwe != f.cwe {
                return Err(refuse(
                    RETEST_FINDING_MISMATCH,
                    format!("{label} title or CWE differs from the report finding"),
                ));
            }
        }
        if let Some(receipt) = &result.receipt {
            *class = resolve_class(
                receipt,
                *class,
                finding.and_then(classify_finding_target),
                &label,
            )?;
            // Rule 4 for the retest receipt: same file and function as the
            // finding (the file hash is the new one, checked above).
            if let Some(f) = finding {
                check_file_path(&receipt.target_file, f)
                    .and_then(|()| check_function(&receipt.target_function, f))
                    .map_err(|e| refuse(RECEIPT_UNBOUND, format!("{label}: {e}")))?;
            }
        }
    }
    Ok((
        RetestInput {
            path: ex.path.clone(),
            sha256: ex.sha256.clone(),
            report: parsed,
            value: ex.value.clone(),
            classes,
        },
        ex,
    ))
}

fn check_finding_id(id: &str) -> Result<(), PackageRefusal> {
    super::super::receipt_fields::check_finding_id(id).map_err(|e| refuse(FINDING_ID_INVALID, e))
}

fn check_hash(value: Option<&str>, label: &str) -> Result<(), PackageRefusal> {
    super::super::receipt_fields::check_hash(value, label)
        .map_err(|e| refuse(RECEIPT_FIELD_INVALID, e))
}

fn check_token(value: Option<&str>, label: &str) -> Result<(), PackageRefusal> {
    super::super::receipt_fields::check_token(value, label)
        .map_err(|e| refuse(RECEIPT_FIELD_INVALID, e))
}

fn check_receipt_fields(receipt: &TargetPocReceipt, label: &str) -> Result<(), PackageRefusal> {
    super::super::receipt_fields::check_receipt_fields(receipt, label)
        .map_err(|e| refuse(RECEIPT_FIELD_INVALID, e))
}

fn check_image(value: Option<&str>, label: &str) -> Result<(), PackageRefusal> {
    super::super::receipt_fields::check_image(value, label)
        .map_err(|e| refuse(RECEIPT_FIELD_INVALID, e))
}

/// Fix-check fields the record copies.
fn check_fix_fields(run: &FixCheckRun, label: &str) -> Result<(), PackageRefusal> {
    let check = &run.check;
    check_hash(
        Some(check.diff_sha256.as_str()),
        &format!("{label} diff_sha256"),
    )?;
    check_hash(
        check.variant_set_sha256.as_deref(),
        &format!("{label} variant_set_sha256"),
    )?;
    check_token(check.reason.as_deref(), &format!("{label} reason"))?;
    check_token(run.reason().as_deref(), &format!("{label} outcome reason"))?;
    check_token(
        check.variant_generator_version.as_deref(),
        &format!("{label} variant_generator_version"),
    )?;
    if let Some(binding) = &run.binding {
        for (what, value) in [
            (
                "binding target_file_sha256",
                Some(&binding.target_file_sha256),
            ),
            (
                "binding finding_file_sha256",
                binding.finding_file_sha256.as_ref(),
            ),
            ("binding adapter_sha256", Some(&binding.adapter_sha256)),
            ("binding harness_sha256", Some(&binding.harness_sha256)),
            (
                "binding target_plan_sha256",
                binding.target_plan_sha256.as_ref(),
            ),
            (
                "binding test_command_sha256",
                binding.test_command_sha256.as_ref(),
            ),
        ] {
            check_hash(value.map(String::as_str), &format!("{label} {what}"))?;
        }
        check_token(
            Some(binding.harness_version.as_str()),
            &format!("{label} harness_version"),
        )?;
        check_token(
            Some(binding.policy_version.as_str()),
            &format!("{label} policy_version"),
        )?;
        check_image(
            binding.image_identity.as_deref(),
            &format!("{label} image_identity"),
        )?;
    }
    if let Some(runtime) = &run.runtime {
        check_token(
            Some(runtime.node_version.as_str()),
            &format!("{label} node_version"),
        )?;
    }
    Ok(())
}

/// The current (class, runtime) set whose sha256 the fix check names, and a
/// stamp that agrees with it. A named set no current class has is
/// `variant_set_outdated`; one that belongs to the other runtime, or a stamp
/// that disagrees with its set, is `variant_set_inconsistent`.
fn lookup_variant_set(
    run: &FixCheckRun,
    runtime: Runtime,
    label: &str,
) -> Result<Option<VariantSet>, PackageRefusal> {
    let check = &run.check;
    let Some(sha) = check.variant_set_sha256.as_deref() else {
        if check.variant_set.is_some() || check.variant_generator_version.is_some() {
            return Err(refuse(
                VARIANT_SET_INCONSISTENT,
                format!("{label} has a variant stamp but names no variant_set_sha256"),
            ));
        }
        return Ok(None);
    };
    let set = oracle_classes(runtime)
        .iter()
        .copied()
        .map(|class| variant_set_for(class, runtime))
        .find(|set| set.sha256() == sha);
    let Some(set) = set else {
        let other = match runtime {
            Runtime::Python => Runtime::Node,
            Runtime::Node => Runtime::Python,
        };
        if oracle_classes(other)
            .iter()
            .copied()
            .any(|class| variant_set_for(class, other).sha256() == sha)
        {
            return Err(refuse(
                VARIANT_SET_INCONSISTENT,
                format!("{label} names a variant set of the other runtime than its target file"),
            ));
        }
        return Err(refuse(
            VARIANT_SET_OUTDATED,
            format!(
                "{label} names a variant set that no current oracle class has; rerun the fix check"
            ),
        ));
    };
    if check.variant_generator_version.as_deref() != Some(set.generator_version) {
        return Err(refuse(
            VARIANT_SET_INCONSISTENT,
            format!("{label} variant_generator_version does not match its variant set"),
        ));
    }
    if let Some(stamp) = &check.variant_set {
        check_stamp(stamp, set, check.inputs_blocked, check.inputs_total, label)?;
    }
    Ok(Some(set))
}

fn check_stamp(
    stamp: &VariantSetStamp,
    set: VariantSet,
    inputs_blocked: u32,
    inputs_total: u32,
    label: &str,
) -> Result<(), PackageRefusal> {
    let bad = |what: &str| {
        refuse(
            VARIANT_SET_INCONSISTENT,
            format!("{label} variant stamp: {what}"),
        )
    };
    if stamp.sha256 != set.sha256() || stamp.generator_version != set.generator_version {
        return Err(bad(
            "its sha256 or generator version is not the named set's",
        ));
    }
    if stamp.total as usize != set.len() {
        return Err(bad("its total is not the size of the set"));
    }
    let scoring: Vec<&str> = set
        .variants
        .iter()
        .filter(|v| !v.requires_decoding)
        .map(|v| v.id)
        .collect();
    let decoding: Vec<&str> = set
        .variants
        .iter()
        .filter(|v| v.requires_decoding)
        .map(|v| v.id)
        .collect();
    // Scoring ids not blocked: known scoring ids, unique, in set order.
    let mut last = None;
    for id in &stamp.ids_not_blocked {
        let position = scoring
            .iter()
            .position(|known| known == id)
            .ok_or_else(|| bad("ids_not_blocked names an id outside the scoring set"))?;
        if last.is_some_and(|last| position <= last) {
            return Err(bad("ids_not_blocked is not unique and in set order"));
        }
        last = Some(position);
    }
    if u64::from(inputs_blocked) + stamp.ids_not_blocked.len() as u64 > u64::from(inputs_total) {
        return Err(bad(
            "more inputs are blocked and not blocked than were checked",
        ));
    }
    let mut decoding_seen = BTreeSet::new();
    for id in stamp
        .decoding_ids_not_blocked
        .iter()
        .chain(&stamp.decoding_ids_not_applicable)
    {
        if !decoding.contains(&id.as_str()) {
            return Err(bad("a decoding list names an id outside the decoding set"));
        }
        if !decoding_seen.insert(id.as_str()) {
            return Err(bad("a decoding id is listed twice"));
        }
    }
    Ok(())
}

/// `--targets`: every plan names a package row and hashes to a plan sha256
/// that row's receipts record.
fn apply_plans(targets: &RawInput, rows: &mut BTreeMap<RowKey, Row>) -> Result<(), PackageRefusal> {
    let plans = parse_target_plans(&targets.raw)
        .map_err(|e| refuse(TARGET_PLANS_REFUSED, format!("target plans refused: {e}")))?;
    for (id, call) in plans {
        let row = rows
            .iter_mut()
            .find(|(key, _)| key.id == id && key.source != IdSource::Target)
            .map(|(_, row)| row)
            .ok_or_else(|| {
                refuse(
                    TARGET_PLAN_UNMATCHED,
                    format!("target plan {id:?} names no finding row of the package"),
                )
            })?;
        let bytes = serde_json::to_vec(&call).map_err(|e| {
            refuse(
                TARGET_PLANS_REFUSED,
                format!("target plan {id:?} cannot be encoded: {e}"),
            )
        })?;
        let sha = sha256_hex(&bytes);
        if !row.plan_sha256s.contains(&sha) {
            return Err(refuse(
                TARGET_PLAN_MISMATCH,
                format!(
                    "target plan {id:?} hashes to {sha}, which no receipt of that finding records"
                ),
            ));
        }
        row.plan = Some(call);
    }
    Ok(())
}

/// Rule 5 (content part): each bundle decodes, names one included receipt by
/// its bytes' sha256, and its Statement matches that receipt's predicate.
fn check_bundles(
    bundles: &[RawInput],
    receipts: &[Extracted],
) -> Result<Vec<Source>, PackageRefusal> {
    let mut covered = BTreeSet::new();
    let mut out = Vec::new();
    for bundle in bundles {
        let statement = decode_bundle_statement(bundle.raw.as_bytes()).map_err(|e| {
            refuse(
                BUNDLE_REFUSED,
                format!("bundle {:?} refused: {e}", bundle.name),
            )
        })?;
        let digest = statement
            .pointer("/subject/0/digest/sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                refuse(
                    BUNDLE_REFUSED,
                    format!("bundle {:?} Statement has no subject sha256", bundle.name),
                )
            })?;
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.sha256 == digest)
            .ok_or_else(|| {
                refuse(
                    BUNDLE_UNMATCHED,
                    format!("bundle {:?} signs no receipt of this package", bundle.name),
                )
            })?;
        check_bundle(
            bundle.raw.as_bytes(),
            receipt.raw.as_bytes(),
            receipt.kind,
            &receipt.predicate,
        )
        .map_err(|e| {
            refuse(
                BUNDLE_REFUSED,
                format!(
                    "bundle {:?} does not match {}: {e}",
                    bundle.name, receipt.name
                ),
            )
        })?;
        if !covered.insert(receipt.sha256.clone()) {
            return Err(refuse(
                BUNDLE_DUPLICATE,
                format!("two bundles sign {}", receipt.name),
            ));
        }
        out.push(Source {
            kind: SourceKind::Signature,
            name: bundle.name.clone(),
            path: format!(
                "{}/{}.sigstore.json",
                SourceKind::Signature.dir(),
                receipt.name
            ),
            sha256: sha256_hex(bundle.raw.as_bytes()),
            bytes: bundle.raw.as_bytes().to_vec(),
            covers: Some(receipt.path.clone()),
        });
    }
    Ok(out)
}

/// Match exact payload and receipt bytes using the same binding API as attestation.
fn check_pq_sidecars(raw: &[RawInput], sources: &[Source]) -> Result<Vec<Source>, PackageRefusal> {
    use crate::attest::{pq::Sidecar, statement::decode_bundle_payload};
    let mut covered = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut result = Vec::new();
    for input in raw {
        check_name(&input.name, "PQ sidecar")?;
        if !names.insert(input.name.to_ascii_lowercase()) {
            return Err(refuse(NAME_DUPLICATE, "duplicate PQ sidecar name"));
        }
        let sidecar =
            Sidecar::parse(input.raw.as_bytes()).map_err(|e| refuse("pq_signature_refused", e))?;
        let bundle = sources
            .iter()
            .filter(|s| s.kind == SourceKind::Signature)
            .find(|bundle| {
                let Some(receipt) = sources
                    .iter()
                    .find(|s| Some(&s.path) == bundle.covers.as_ref())
                else {
                    return false;
                };
                decode_bundle_payload(&bundle.bytes).is_ok_and(|payload| {
                    sidecar
                        .check_content_binding(&payload, &receipt.bytes)
                        .is_ok()
                })
            })
            .ok_or_else(|| {
                refuse(
                    "pq_signature_unmatched",
                    "sidecar has no matching receipt and bundle",
                )
            })?;
        if !covered.insert(bundle.path.clone()) {
            return Err(refuse(
                "pq_signature_duplicate",
                "two sidecars cover one bundle",
            ));
        }
        result.push(Source {
            kind: SourceKind::PqSignature,
            name: input.name.clone(),
            path: format!("signatures-pq/{}", input.name),
            sha256: sha256_hex(input.raw.as_bytes()),
            bytes: input.raw.as_bytes().to_vec(),
            covers: Some(bundle.path.clone()),
        });
    }
    Ok(result)
}
