//! A4: retest delivery package, input side.
//!
//! [`inputs`] reads the package inputs (a retest report, reproduce and fix
//! check receipts, an optional scan report, target plans and Sigstore
//! bundles), re-runs the stored-receipt validators ([`crate::attest::extract`])
//! and applies the package rules on top of them. Every input is untrusted:
//! any rule failure refuses the whole package with one specific token, there
//! is no partial package. [`record`] turns the accepted inputs into the
//! record view model the renderers consume. [`markdown`] renders deterministic
//! bilingual human records; optional signature verification stages private
//! copies and invokes cosign.
//!
//! The record never says that anything is fixed or secure. Outcome wording is
//! the existing "no effect observed at this revision, with these inputs and
//! variants" family, and fields the receipts do not record stay `None`.

pub mod engagement;
pub mod inputs;
pub mod markdown;
pub mod record;
pub mod text;
pub mod verify;
pub mod write;

#[cfg(test)]
mod tests;

pub use inputs::{PackageInputs, PackageRequest, Source, SourceKind, load_inputs};
pub use record::{Record, build_record};

/// Most receipts (retest + reproduce + fix check) one package holds.
pub const MAX_RECEIPTS: usize = 64;
/// Most Sigstore bundles one package holds.
pub const MAX_BUNDLES: usize = 64;
/// Largest single receipt read.
pub const RECEIPT_MAX_BYTES: u64 = crate::attest::RECEIPT_MAX_BYTES;
/// Largest scan report read.
pub const REPORT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum scan findings, bounding row binding work within the 64 MiB report cap.
pub const MAX_REPORT_FINDINGS: usize = 10_000;
/// Retest includes skipped findings too, so this is the report cap rather
/// than MAX_RETEST_FINDINGS (which limits only findings selected to execute).
pub const MAX_RETEST_RESULTS: usize = MAX_REPORT_FINDINGS;
/// Cap on every input read, including a scan report not copied into the package.
pub const PACKAGE_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Longest file name kept in the package.
pub const NAME_MAX_CHARS: usize = 100;

/// Refusal tokens. Each names one rule; the message says which input broke it.
pub mod token {
    /// An input is missing, a symlink, not a regular file, too large or not UTF-8.
    pub const INPUT_UNREADABLE: &str = "input_unreadable";
    /// More than [`super::MAX_RECEIPTS`] receipts or [`super::MAX_BUNDLES`] bundles.
    pub const INPUT_COUNT_EXCEEDED: &str = "input_count_exceeded";
    /// All input bytes, including an omitted report, exceed [`super::PACKAGE_MAX_BYTES`].
    pub const PACKAGE_TOO_LARGE: &str = "package_too_large";
    /// None of retest, reproduce or fix check was given.
    pub const NO_RECEIPTS: &str = "no_receipts";
    /// A file name is not `^[A-Za-z0-9._-]{1,100}$`, or starts with `.` or `-`.
    pub const NAME_INVALID: &str = "name_invalid";
    /// Two receipts share a file name (compared without case).
    pub const NAME_DUPLICATE: &str = "name_duplicate";
    /// The same receipt bytes were given twice.
    pub const RECEIPT_DUPLICATE: &str = "receipt_duplicate";
    /// `attest::extract` refused the receipt.
    pub const RECEIPT_REFUSED: &str = "receipt_refused";
    /// A receipt was given under the wrong flag (for example a fix check as
    /// `--reproduce`).
    pub const RECEIPT_KIND_MISMATCH: &str = "receipt_kind_mismatch";
    /// A hash, token or identity field copied into the record is malformed.
    pub const RECEIPT_FIELD_INVALID: &str = "receipt_field_invalid";
    /// Rule 1: a `still_observed` / `not_observed` retest result has no receipt.
    pub const RETEST_RECEIPT_MISSING: &str = "retest_receipt_missing";
    /// Rule 2: retest file hashes disagree with the receipt or the report.
    pub const RETEST_FILE_HASH_MISMATCH: &str = "retest_file_hash_mismatch";
    /// Rule 2: a retest result names a finding the report does not have.
    pub const RETEST_FINDING_UNKNOWN: &str = "retest_finding_unknown";
    /// A retest result's title or CWE differs from the report finding.
    pub const RETEST_FINDING_MISMATCH: &str = "retest_finding_mismatch";
    /// Two retest results name the same finding.
    pub const RETEST_RESULT_DUPLICATE: &str = "retest_result_duplicate";
    /// A finding id is empty, too long or has invisible/control characters.
    pub const FINDING_ID_INVALID: &str = "finding_id_invalid";
    /// A retest commit is not a full hex object id.
    pub const REVISION_INVALID: &str = "revision_invalid";
    /// The scan report failed to parse or validate.
    pub const REPORT_REFUSED: &str = "report_refused";
    /// Rule 3: the report does not hash to the retest's `old_report_sha256`.
    pub const REPORT_HASH_MISMATCH: &str = "report_hash_mismatch";
    /// Rule 4: a receipt binds to no finding of the report (or has no binding).
    pub const RECEIPT_UNBOUND: &str = "receipt_unbound";
    /// Rule 4: a receipt binds to more than one finding of the report.
    pub const RECEIPT_AMBIGUOUS: &str = "receipt_ambiguous";
    /// Two reproduce receipts for the same finding row.
    pub const REPRODUCE_DUPLICATE_FOR_FINDING: &str = "reproduce_duplicate_for_finding";
    /// The receipts or the finding of one row name different oracle classes.
    pub const ORACLE_CLASS_CONFLICT: &str = "oracle_class_conflict";
    /// A fix check names a variant set that no current (class, runtime) has
    /// (the existing fix-check reason token).
    pub const VARIANT_SET_OUTDATED: &str = crate::audit::fix_check::VARIANT_SET_OUTDATED;
    /// A fix check's variant stamp disagrees with the set it names.
    pub const VARIANT_SET_INCONSISTENT: &str = "variant_set_inconsistent";
    /// `--targets` is not a valid target plan file.
    pub const TARGET_PLANS_REFUSED: &str = "target_plans_refused";
    /// A target plan names a finding that is not a package row.
    pub const TARGET_PLAN_UNMATCHED: &str = "target_plan_unmatched";
    /// A target plan does not hash to any plan sha256 its row's receipts record.
    pub const TARGET_PLAN_MISMATCH: &str = "target_plan_mismatch";
    /// Rule 5: a bundle does not decode or its Statement does not match.
    pub const BUNDLE_REFUSED: &str = "bundle_refused";
    /// Rule 5: a bundle's subject digest matches no included receipt.
    pub const BUNDLE_UNMATCHED: &str = "bundle_unmatched";
    /// Rule 5: a requested cryptographic verification failed or was not run.
    pub const BUNDLE_SIGNATURE_INVALID: &str = "bundle_signature_invalid";
    /// Two bundles for the same receipt.
    pub const BUNDLE_DUPLICATE: &str = "bundle_duplicate";

    /// Every token, for tests and documentation.
    pub const ALL: &[&str] = &[
        INPUT_UNREADABLE,
        INPUT_COUNT_EXCEEDED,
        PACKAGE_TOO_LARGE,
        NO_RECEIPTS,
        NAME_INVALID,
        NAME_DUPLICATE,
        RECEIPT_DUPLICATE,
        RECEIPT_REFUSED,
        RECEIPT_KIND_MISMATCH,
        RECEIPT_FIELD_INVALID,
        RETEST_RECEIPT_MISSING,
        RETEST_FILE_HASH_MISMATCH,
        RETEST_FINDING_UNKNOWN,
        RETEST_FINDING_MISMATCH,
        RETEST_RESULT_DUPLICATE,
        FINDING_ID_INVALID,
        REVISION_INVALID,
        REPORT_REFUSED,
        REPORT_HASH_MISMATCH,
        RECEIPT_UNBOUND,
        RECEIPT_AMBIGUOUS,
        REPRODUCE_DUPLICATE_FOR_FINDING,
        ORACLE_CLASS_CONFLICT,
        VARIANT_SET_OUTDATED,
        VARIANT_SET_INCONSISTENT,
        TARGET_PLANS_REFUSED,
        TARGET_PLAN_UNMATCHED,
        TARGET_PLAN_MISMATCH,
        BUNDLE_REFUSED,
        BUNDLE_UNMATCHED,
        BUNDLE_DUPLICATE,
        BUNDLE_SIGNATURE_INVALID,
    ];
}

/// Why the package was not built. Displayed as `<token>: <message>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRefusal {
    pub token: &'static str,
    pub message: String,
}

impl PackageRefusal {
    pub fn new(token: &'static str, message: impl Into<String>) -> Self {
        Self {
            token,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PackageRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.token, self.message)
    }
}

impl std::error::Error for PackageRefusal {}
