//! Record view model (`record.json`, schema `vettalon.retest-record/1`)
//! built from accepted [`PackageInputs`]. No rendering here.
//!
//! - Labels are the existing honest wording ("no effect observed at this
//!   revision, with these inputs and variants"); none says fixed or secure.
//! - Attack inputs are recovered from the oracle class through the fixed
//!   tables in `poc_oracle` and `variants` (and, for a fix check, the exact
//!   set whose sha256 it names), never copied from free text.
//! - Fields the receipts do not record (timestamps, producing Vettalon
//!   version, per-run sandbox settings, per-variant original-copy results)
//!   are `None` / `not_recorded`; the renderer prints 「未記錄」/"not recorded".
//! - Repo-derived text (titles, CWE strings, paths, function names) is shown
//!   through `disclose::show_invisible` and `util::mask_sensitive_text`,
//!   bounded, and marked `origin: "report_text"`.
//!
//! Engagement fields, languages, mapping version and limit text keys are
//! populated by the writer from their own data files.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::audit::cbom_check::canonical_json;
use crate::audit::fix_check::{Blocker, CheckResult, FixCheckRun, FixOutcome};
use crate::audit::poc_oracle::{OracleClass, benign_input, fixture_inputs};
use crate::audit::report_evidence::{blocker_labels, fix_label_en};
use crate::audit::retest::{RetestStatus, RetestSummary};
use crate::audit::schema::sha256_hex;
use crate::audit::target_poc::{
    NodeDriver, Runtime, TargetArgument, TargetPocOutcome, TargetPocReceipt,
};
use crate::audit::variants::{VariantSet, variant_set_for};

use super::PackageRefusal;
use super::engagement::{Engagement, FindingEngagement};
use super::inputs::{FixCheckInput, IdSource, PackageInputs, Row, SourceKind, class_key};

/// `record.json` schema id.
pub const RECORD_SCHEMA: &str = "vettalon.retest-record/1";
/// Longest repo-derived text kept (characters).
pub const REPORT_TEXT_MAX_CHARS: usize = 512;
/// Longest attack input kept (characters).
pub const INPUT_MAX_CHARS: usize = 512;
/// Longest literal call argument kept (characters).
pub const LITERAL_MAX_CHARS: usize = 256;

/// A fixed text in both package languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Label {
    #[serde(rename = "zh-TW")]
    pub zh_tw: &'static str,
    pub en: &'static str,
}

const fn label(zh_tw: &'static str, en: &'static str) -> Label {
    Label { zh_tw, en }
}

// Display wording comes only from text.json; machine keys remain unchanged.
fn package_label(key: &str) -> Label {
    static TEXT: std::sync::LazyLock<super::text::Text> = std::sync::LazyLock::new(|| {
        serde_json::from_str(super::text::TEXT_JSON).expect("shipped package text is valid")
    });
    label(
        TEXT.get("zh-TW", key).expect("shipped zh-TW label exists"),
        TEXT.get("en", key).expect("shipped English label exists"),
    )
}

pub fn not_bound_label() -> Label {
    package_label("unbound")
}
pub fn inputs_not_determinable_label() -> Label {
    package_label("not_determinable")
}
pub fn call_not_supplied_label() -> Label {
    package_label("call_not_supplied")
}
pub fn tree_not_clean_label() -> Label {
    package_label("warning.tree")
}

/// Retest status wording from the shared package text.
pub fn retest_status_label(status: RetestStatus) -> Label {
    package_label(&format!("status.{}", status.key()))
}

/// Reproduce outcome wording.
pub fn reproduce_outcome_label(outcome: TargetPocOutcome) -> Label {
    match outcome {
        TargetPocOutcome::EffectObserved => label("觀察到效果", "effect observed"),
        TargetPocOutcome::EffectAbsent => label(
            "未觀察到效果（限此 revision、此組輸入）",
            "no effect observed at this revision, with these inputs",
        ),
        TargetPocOutcome::Inconclusive => label("無法判定", "inconclusive"),
    }
}

/// Fix outcome wording: exactly the report's (`FixOutcome::label_zh` and
/// the report's English text).
pub fn fix_outcome_label(outcome: FixOutcome) -> Label {
    label(outcome.label_zh(), fix_label_en(outcome))
}

/// Blocker wording of a `fix_unverified` check, exactly the report's.
pub fn blocker_label(blocker: Blocker) -> Option<Label> {
    blocker_labels(blocker).map(|(zh, en)| label(zh, en))
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub schema: &'static str,
    pub vettalon_version: &'static str,
    /// Populated by the package writer when render languages are chosen.
    pub languages: Vec<String>,
    pub mapping_version: Option<String>,
    /// Text keys for the limitations selected by the package writer.
    pub limits: Vec<String>,
    /// Receipts, plans and (when included) the report, sorted by path.
    pub sources: Vec<SourceRecord>,
    pub revisions: Revisions,
    pub summary: SummaryRecord,
    /// Operator statements, populated by the package writer.
    pub engagement: Engagement,
    /// Sorted by id bytes.
    pub findings: Vec<FindingRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRecord {
    pub kind: SourceKind,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub signature: Option<SignatureRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureRecord {
    pub path: String,
    pub sha256: String,
    /// The bundle's Statement names these receipt bytes and predicate.
    pub subject_ok: bool,
    /// Filled by the writer when `--key` is given; `None` means
    /// "content-matched, not cryptographically verified".
    pub cosign: Option<CosignRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mldsa: Option<MldsaSignatureRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MldsaSignatureRecord {
    pub path: String,
    pub sha256: String,
    pub binding_ok: bool,
    pub verified: Option<MldsaRecord>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MldsaRecord {
    pub verified: bool,
    pub key_sha256: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CosignRecord {
    pub verified: bool,
    pub key_sha256: String,
    pub cosign_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Revisions {
    /// What the retest names as its old report.
    pub old_report_sha256: Option<String>,
    /// SHA-256 of the scan report supplied to the package.
    pub report_sha256: Option<String>,
    pub report_included: bool,
    pub old_repo_commit: Option<String>,
    pub new_repo_commit: Option<String>,
    pub new_tree_clean: Option<bool>,
    pub tree_warning: Option<Label>,
    /// The report's `started_at`, as written in the report.
    pub old_scan_started_at: Option<ReportText>,
    /// Retest receipts record no time.
    pub retest_started_at: Option<String>,
    pub replays_requested: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryRecord {
    pub retest: Option<RetestSummary>,
    pub fix_outcomes: BTreeMap<&'static str, usize>,
}

/// Repo- or model-derived text, sanitised and bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportText {
    pub text: String,
    pub truncated: bool,
    /// SHA-256 of the full original text when it was truncated.
    pub full_sha256: Option<String>,
    pub origin: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    /// Package path of the receipt file.
    pub file: String,
    pub file_sha256: String,
    /// JSON pointer into that file (`""` is the whole document).
    pub pointer: String,
    /// SHA-256 of the canonical JSON of the object at `pointer`.
    pub object_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingRecord {
    pub id: String,
    pub id_source: IdSource,
    /// [`not_bound_label`] for a row not bound to a report finding.
    pub binding_note: Option<Label>,
    pub title: Option<ReportText>,
    pub cwe: Option<ReportText>,
    pub file: Option<ReportText>,
    pub function: Option<ReportText>,
    pub line: Option<u32>,
    /// `python` or `node`, from the target file's extension.
    pub runtime: Option<&'static str>,
    pub oracle_class: Option<&'static str>,
    pub original: Option<OriginalRecord>,
    pub retest: Option<RetestRecord>,
    /// Sorted by `diff_sha256`.
    pub fix_checks: Vec<FixCheckRecord>,
    pub inputs: InputsRecord,
    pub call: CallRecord,
    /// Operator statements for this finding, populated by the package writer.
    pub operator: FindingEngagement,
}

/// One reproduce run (a reproduce receipt or a retest result's receipt).
#[derive(Debug, Clone, Serialize)]
pub struct RunRecord {
    pub receipt_version: u32,
    pub outcome: TargetPocOutcome,
    pub label: Label,
    pub reason: Option<String>,
    pub replays: Replays,
    /// Phases of the first replay.
    pub phases: Vec<PhaseRecord>,
    pub environment: Environment,
    /// Receipts record no time.
    pub started_at: Option<String>,
    /// Receipts do not record the Vettalon version that wrote them.
    pub producer_version: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Replays {
    pub requested: u32,
    pub completed: u32,
    pub observed: u32,
    pub absent: u32,
    pub inconclusive: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PhaseRecord {
    pub name: String,
    pub effect: Option<bool>,
    pub functional: Option<bool>,
    pub reached: Option<bool>,
    /// Only the hash is kept; the transcript itself is not retained.
    pub transcript_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OriginalRecord {
    #[serde(flatten)]
    pub run: RunRecord,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetestRecord {
    pub status: RetestStatus,
    pub label: Label,
    pub reason: Option<String>,
    pub rebound: bool,
    pub old_file_sha256: Option<String>,
    pub new_file_sha256: Option<String>,
    pub run: Option<RunRecord>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct FixCheckRecord {
    pub outcome: FixOutcome,
    pub label: Label,
    pub original: CheckResult,
    pub variants: CheckResult,
    pub benign: CheckResult,
    pub tests: CheckResult,
    pub inputs: InputCounts,
    pub decoding: DecodingCounts,
    pub blocker: Blocker,
    pub blocker_label: Option<Label>,
    pub reason: Option<String>,
    pub legacy_format: bool,
    pub diff_sha256: String,
    pub variant_set_sha256: Option<String>,
    pub variant_generator_version: Option<String>,
    /// `None`: no project test command was configured.
    pub test_command_sha256: Option<String>,
    /// Per input of the named set; `not_recorded` when the receipt's counts
    /// do not cover every input.
    pub per_input: Vec<FixInputRecord>,
    pub environment: Environment,
    pub started_at: Option<String>,
    pub producer_version: Option<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct InputCounts {
    pub blocked: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DecodingCounts {
    pub blocked: u32,
    pub applicable: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FixInputRecord {
    pub id: &'static str,
    pub fixed_copy: FixedCopy,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Environment {
    pub image_id: Option<String>,
    pub harness_sha256: Option<String>,
    pub harness_version: Option<String>,
    pub policy_version: Option<String>,
    pub adapter_sha256: Option<String>,
    pub source_tree_sha256: Option<String>,
    pub node: Option<NodeEnvironment>,
    /// Network, capabilities, user and limits are what the harness version
    /// declares; receipts do not observe them per run.
    pub sandbox_settings: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeEnvironment {
    pub language: String,
    pub module_kind: String,
    pub version: String,
    pub lockfile_sha256: Option<String>,
    pub deps_sha256: Option<String>,
    pub fixture_sha256: Option<String>,
    pub driver: Option<NodeDriver>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InputsRecord {
    pub determinable: bool,
    pub note: Option<Label>,
    pub items: Vec<InputRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputRole {
    Base,
    Variant,
    Decoding,
    Benign,
}

/// Result of one input on the patched copy of a fix check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedCopy {
    Blocked,
    NotBlocked,
    NotApplicable,
    NotRecorded,
}

/// Result of one input on the original copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginalCopy {
    Effect,
    NoEffect,
    NotRecorded,
}

#[derive(Debug, Clone, Serialize)]
pub struct InputRecord {
    pub role: InputRole,
    pub id: &'static str,
    pub text: String,
    pub truncated: bool,
    pub text_sha256: Option<String>,
    pub fixed_copy: FixedCopy,
    pub original_copy: OriginalCopy,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallRecord {
    pub supplied: bool,
    pub note: Option<Label>,
    /// Plan hashes the row's receipts record.
    pub plan_sha256s: Vec<String>,
    pub file: Option<ReportText>,
    pub function: Option<ReportText>,
    pub args: Vec<ArgRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArgRecord {
    pub kind: &'static str,
    /// Compact JSON of a literal, sanitised and bounded.
    pub value: Option<String>,
    pub truncated: bool,
    pub value_sha256: Option<String>,
}

/// Paths addressable by package renderers, including operator statements.
/// Array elements use `[]`; keep this registry aligned with the serialized model.
pub fn record_field_paths() -> BTreeSet<String> {
    [
        "schema",
        "vettalon_version",
        "languages[]",
        "mapping_version",
        "limits[]",
        "sources[]",
        "sources[].kind",
        "sources[].path",
        "sources[].sha256",
        "sources[].bytes",
        "sources[].signature",
        "sources[].signature.path",
        "sources[].signature.sha256",
        "sources[].signature.subject_ok",
        "sources[].signature.mldsa",
        "sources[].signature.mldsa.path",
        "sources[].signature.mldsa.sha256",
        "sources[].signature.mldsa.binding_ok",
        "sources[].signature.mldsa.verified",
        "sources[].signature.mldsa.verified.verified",
        "sources[].signature.mldsa.verified.key_sha256",
        "sources[].signature.cosign",
        "sources[].signature.cosign.verified",
        "sources[].signature.cosign.key_sha256",
        "sources[].signature.cosign.cosign_version",
        "revisions",
        "revisions.old_report_sha256",
        "revisions.report_sha256",
        "revisions.report_included",
        "revisions.old_repo_commit",
        "revisions.new_repo_commit",
        "revisions.new_tree_clean",
        "revisions.tree_warning",
        "revisions.tree_warning.zh-TW",
        "revisions.tree_warning.en",
        "revisions.old_scan_started_at",
        "revisions.old_scan_started_at.text",
        "revisions.old_scan_started_at.truncated",
        "revisions.old_scan_started_at.full_sha256",
        "revisions.old_scan_started_at.origin",
        "revisions.retest_started_at",
        "revisions.replays_requested",
        "summary",
        "summary.retest",
        "summary.retest.still_observed",
        "summary.retest.not_observed",
        "summary.retest.inconclusive",
        "summary.retest.environment_unavailable",
        "summary.retest.target_missing",
        "summary.retest.not_reproducible_before",
        "summary.retest.retest_cap_reached",
        "summary.fix_outcomes",
        "engagement",
        "engagement.id",
        "engagement.client",
        "engagement.vendor",
        "engagement.tester",
        "engagement.reviewer",
        "engagement.scope",
        "engagement.scope_approval_ref",
        "engagement.method_note",
        "engagement.test_command_note",
        "engagement.original_test_start",
        "engagement.original_test_end",
        "engagement.retest_date",
        "findings[]",
        "findings[].id",
        "findings[].id_source",
        "findings[].binding_note",
        "findings[].binding_note.zh-TW",
        "findings[].binding_note.en",
        "findings[].title",
        "findings[].title.text",
        "findings[].title.truncated",
        "findings[].title.full_sha256",
        "findings[].title.origin",
        "findings[].cwe",
        "findings[].cwe.text",
        "findings[].cwe.truncated",
        "findings[].cwe.full_sha256",
        "findings[].cwe.origin",
        "findings[].file",
        "findings[].file.text",
        "findings[].file.truncated",
        "findings[].file.full_sha256",
        "findings[].file.origin",
        "findings[].function",
        "findings[].function.text",
        "findings[].function.truncated",
        "findings[].function.full_sha256",
        "findings[].function.origin",
        "findings[].line",
        "findings[].runtime",
        "findings[].oracle_class",
        "findings[].original",
        "findings[].original.receipt_version",
        "findings[].original.outcome",
        "findings[].original.label",
        "findings[].original.label.zh-TW",
        "findings[].original.label.en",
        "findings[].original.reason",
        "findings[].original.replays",
        "findings[].original.replays.requested",
        "findings[].original.replays.completed",
        "findings[].original.replays.observed",
        "findings[].original.replays.absent",
        "findings[].original.replays.inconclusive",
        "findings[].original.phases[]",
        "findings[].original.phases[].name",
        "findings[].original.phases[].effect",
        "findings[].original.phases[].functional",
        "findings[].original.phases[].reached",
        "findings[].original.phases[].transcript_sha256",
        "findings[].original.environment",
        "findings[].original.environment.image_id",
        "findings[].original.environment.harness_sha256",
        "findings[].original.environment.harness_version",
        "findings[].original.environment.policy_version",
        "findings[].original.environment.adapter_sha256",
        "findings[].original.environment.source_tree_sha256",
        "findings[].original.environment.node",
        "findings[].original.environment.node.language",
        "findings[].original.environment.node.module_kind",
        "findings[].original.environment.node.version",
        "findings[].original.environment.node.lockfile_sha256",
        "findings[].original.environment.node.deps_sha256",
        "findings[].original.environment.node.fixture_sha256",
        "findings[].original.environment.node.driver",
        "findings[].original.environment.sandbox_settings",
        "findings[].original.started_at",
        "findings[].original.producer_version",
        "findings[].original.evidence",
        "findings[].original.evidence.file",
        "findings[].original.evidence.file_sha256",
        "findings[].original.evidence.pointer",
        "findings[].original.evidence.object_sha256",
        "findings[].retest",
        "findings[].retest.status",
        "findings[].retest.label",
        "findings[].retest.label.zh-TW",
        "findings[].retest.label.en",
        "findings[].retest.reason",
        "findings[].retest.rebound",
        "findings[].retest.old_file_sha256",
        "findings[].retest.new_file_sha256",
        "findings[].retest.run",
        "findings[].retest.run.receipt_version",
        "findings[].retest.run.outcome",
        "findings[].retest.run.label",
        "findings[].retest.run.label.zh-TW",
        "findings[].retest.run.label.en",
        "findings[].retest.run.reason",
        "findings[].retest.run.replays",
        "findings[].retest.run.replays.requested",
        "findings[].retest.run.replays.completed",
        "findings[].retest.run.replays.observed",
        "findings[].retest.run.replays.absent",
        "findings[].retest.run.replays.inconclusive",
        "findings[].retest.run.phases[]",
        "findings[].retest.run.phases[].name",
        "findings[].retest.run.phases[].effect",
        "findings[].retest.run.phases[].functional",
        "findings[].retest.run.phases[].reached",
        "findings[].retest.run.phases[].transcript_sha256",
        "findings[].retest.run.environment",
        "findings[].retest.run.environment.image_id",
        "findings[].retest.run.environment.harness_sha256",
        "findings[].retest.run.environment.harness_version",
        "findings[].retest.run.environment.policy_version",
        "findings[].retest.run.environment.adapter_sha256",
        "findings[].retest.run.environment.source_tree_sha256",
        "findings[].retest.run.environment.node",
        "findings[].retest.run.environment.node.language",
        "findings[].retest.run.environment.node.module_kind",
        "findings[].retest.run.environment.node.version",
        "findings[].retest.run.environment.node.lockfile_sha256",
        "findings[].retest.run.environment.node.deps_sha256",
        "findings[].retest.run.environment.node.fixture_sha256",
        "findings[].retest.run.environment.node.driver",
        "findings[].retest.run.environment.sandbox_settings",
        "findings[].retest.run.started_at",
        "findings[].retest.run.producer_version",
        "findings[].retest.evidence",
        "findings[].retest.evidence.file",
        "findings[].retest.evidence.file_sha256",
        "findings[].retest.evidence.pointer",
        "findings[].retest.evidence.object_sha256",
        "findings[].fix_checks[]",
        "findings[].fix_checks[].outcome",
        "findings[].fix_checks[].label",
        "findings[].fix_checks[].label.zh-TW",
        "findings[].fix_checks[].label.en",
        "findings[].fix_checks[].original",
        "findings[].fix_checks[].variants",
        "findings[].fix_checks[].benign",
        "findings[].fix_checks[].tests",
        "findings[].fix_checks[].inputs",
        "findings[].fix_checks[].inputs.blocked",
        "findings[].fix_checks[].inputs.total",
        "findings[].fix_checks[].decoding",
        "findings[].fix_checks[].decoding.blocked",
        "findings[].fix_checks[].decoding.applicable",
        "findings[].fix_checks[].decoding.total",
        "findings[].fix_checks[].blocker",
        "findings[].fix_checks[].blocker_label",
        "findings[].fix_checks[].blocker_label.zh-TW",
        "findings[].fix_checks[].blocker_label.en",
        "findings[].fix_checks[].reason",
        "findings[].fix_checks[].legacy_format",
        "findings[].fix_checks[].diff_sha256",
        "findings[].fix_checks[].variant_set_sha256",
        "findings[].fix_checks[].variant_generator_version",
        "findings[].fix_checks[].test_command_sha256",
        "findings[].fix_checks[].per_input[]",
        "findings[].fix_checks[].per_input[].id",
        "findings[].fix_checks[].per_input[].fixed_copy",
        "findings[].fix_checks[].environment",
        "findings[].fix_checks[].environment.image_id",
        "findings[].fix_checks[].environment.harness_sha256",
        "findings[].fix_checks[].environment.harness_version",
        "findings[].fix_checks[].environment.policy_version",
        "findings[].fix_checks[].environment.adapter_sha256",
        "findings[].fix_checks[].environment.source_tree_sha256",
        "findings[].fix_checks[].environment.node",
        "findings[].fix_checks[].environment.node.language",
        "findings[].fix_checks[].environment.node.module_kind",
        "findings[].fix_checks[].environment.node.version",
        "findings[].fix_checks[].environment.node.lockfile_sha256",
        "findings[].fix_checks[].environment.node.deps_sha256",
        "findings[].fix_checks[].environment.node.fixture_sha256",
        "findings[].fix_checks[].environment.node.driver",
        "findings[].fix_checks[].environment.sandbox_settings",
        "findings[].fix_checks[].started_at",
        "findings[].fix_checks[].producer_version",
        "findings[].fix_checks[].evidence",
        "findings[].fix_checks[].evidence.file",
        "findings[].fix_checks[].evidence.file_sha256",
        "findings[].fix_checks[].evidence.pointer",
        "findings[].fix_checks[].evidence.object_sha256",
        "findings[].inputs",
        "findings[].inputs.determinable",
        "findings[].inputs.note",
        "findings[].inputs.note.zh-TW",
        "findings[].inputs.note.en",
        "findings[].inputs.items[]",
        "findings[].inputs.items[].role",
        "findings[].inputs.items[].id",
        "findings[].inputs.items[].text",
        "findings[].inputs.items[].truncated",
        "findings[].inputs.items[].text_sha256",
        "findings[].inputs.items[].fixed_copy",
        "findings[].inputs.items[].original_copy",
        "findings[].call",
        "findings[].call.supplied",
        "findings[].call.note",
        "findings[].call.note.zh-TW",
        "findings[].call.note.en",
        "findings[].call.plan_sha256s[]",
        "findings[].call.file",
        "findings[].call.file.text",
        "findings[].call.file.truncated",
        "findings[].call.file.full_sha256",
        "findings[].call.file.origin",
        "findings[].call.function",
        "findings[].call.function.text",
        "findings[].call.function.truncated",
        "findings[].call.function.full_sha256",
        "findings[].call.function.origin",
        "findings[].call.args[]",
        "findings[].call.args[].kind",
        "findings[].call.args[].value",
        "findings[].call.args[].truncated",
        "findings[].call.args[].value_sha256",
        "findings[].operator",
        "findings[].operator.id",
        "findings[].operator.original_test_ref",
        "findings[].operator.risk_rating",
        "findings[].operator.location",
        "findings[].operator.correction_summary",
        "findings[].operator.tester_conclusion",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn refuse(message: impl Into<String>) -> PackageRefusal {
    PackageRefusal::new(super::token::RECEIPT_FIELD_INVALID, message)
}

/// Build the record view model. Deterministic: same inputs, same record.
pub fn build_record(inputs: &PackageInputs) -> Result<Record, PackageRefusal> {
    let mut sources: Vec<SourceRecord> = inputs
        .sources
        .iter()
        .filter(|source| !matches!(source.kind, SourceKind::Signature | SourceKind::PqSignature))
        .map(|source| SourceRecord {
            kind: source.kind,
            path: source.path.clone(),
            sha256: source.sha256.clone(),
            bytes: source.bytes.len() as u64,
            signature: inputs
                .sources
                .iter()
                .find(|sig| sig.covers.as_deref() == Some(source.path.as_str()))
                .map(|sig| SignatureRecord {
                    path: sig.path.clone(),
                    sha256: sig.sha256.clone(),
                    subject_ok: true,
                    cosign: None,
                    mldsa: inputs
                        .sources
                        .iter()
                        .find(|pq| {
                            pq.kind == SourceKind::PqSignature
                                && pq.covers.as_ref() == Some(&sig.path)
                        })
                        .map(|pq| MldsaSignatureRecord {
                            path: pq.path.clone(),
                            sha256: pq.sha256.clone(),
                            binding_ok: true,
                            verified: None,
                        }),
                }),
        })
        .collect();
    sources.sort_by(|a, b| a.path.cmp(&b.path));

    let retest = inputs.retest.as_ref();
    let report_included = inputs
        .sources
        .iter()
        .any(|source| source.kind == SourceKind::Report);
    let revisions = Revisions {
        old_report_sha256: retest.map(|r| r.report.old_report_sha256.clone()),
        report_sha256: inputs.report_sha256.clone(),
        report_included,
        old_repo_commit: retest.and_then(|r| r.report.old_repo_commit.clone()),
        new_repo_commit: retest.and_then(|r| r.report.new_repo_commit.clone()),
        new_tree_clean: retest.and_then(|r| r.report.new_tree_clean),
        tree_warning: retest
            .filter(|r| r.report.new_tree_clean != Some(true))
            .map(|_| tree_not_clean_label()),
        old_scan_started_at: inputs
            .report
            .as_ref()
            .map(|report| report_text(&report.started_at)),
        retest_started_at: None,
        replays_requested: retest.map(|r| r.report.replays),
    };

    let mut fix_outcomes: BTreeMap<&'static str, usize> = [
        FixOutcome::FixVerified,
        FixOutcome::FixCheckPartial,
        FixOutcome::FixRejected,
        FixOutcome::FixUnverified,
    ]
    .into_iter()
    .map(|outcome| (outcome.key(), 0))
    .collect();
    for fix in &inputs.fix_checks {
        *fix_outcomes.entry(fix.run.outcome().key()).or_default() += 1;
    }
    let summary = SummaryRecord {
        retest: retest.map(|r| r.report.summary.clone()),
        fix_outcomes,
    };

    let findings = inputs
        .rows
        .iter()
        .map(|row| finding_record(inputs, row))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Record {
        schema: RECORD_SCHEMA,
        vettalon_version: env!("CARGO_PKG_VERSION"),
        languages: Vec::new(),
        mapping_version: None,
        limits: Vec::new(),
        sources,
        revisions,
        summary,
        engagement: Engagement::default(),
        findings,
    })
}

fn evidence(
    file: &str,
    file_sha256: &str,
    document: &Value,
    pointer: &str,
) -> Result<Evidence, PackageRefusal> {
    let object = document
        .pointer(pointer)
        .ok_or_else(|| refuse(format!("{file} has no object at {pointer:?}")))?;
    let canonical = canonical_json(object)
        .map_err(|e| refuse(format!("{file} cannot be encoded as canonical JSON: {e}")))?;
    Ok(Evidence {
        file: file.to_string(),
        file_sha256: file_sha256.to_string(),
        pointer: pointer.to_string(),
        object_sha256: sha256_hex(canonical.as_bytes()),
    })
}

fn finding_record(inputs: &PackageInputs, row: &Row) -> Result<FindingRecord, PackageRefusal> {
    let finding = row
        .finding
        .and_then(|i| inputs.report.as_ref().map(|r| &r.findings[i]));
    let retest_result = row
        .retest
        .and_then(|i| inputs.retest.as_ref().map(|r| (i, &r.report.results[i])));
    let title = finding
        .map(|f| f.title.as_str())
        .or(retest_result.map(|(_, r)| r.title.as_str()))
        .map(report_text);
    let cwe = finding
        .and_then(|f| f.cwe.as_deref())
        .or(retest_result.and_then(|(_, r)| r.cwe.as_deref()))
        .map(report_text);

    let original = match row.reproduce {
        Some(i) => {
            let input = &inputs.reproduce[i];
            Some(OriginalRecord {
                run: run_record(&input.receipt, input.outcome, input.reason.clone()),
                evidence: evidence(&input.path, &input.sha256, &input.value, "")?,
            })
        }
        None => None,
    };

    let retest = match (retest_result, inputs.retest.as_ref()) {
        (Some((i, result)), Some(doc)) => {
            let pointer = if result.receipt.is_some() {
                format!("/results/{i}/receipt")
            } else {
                format!("/results/{i}")
            };
            let run = result.receipt.as_ref().map(|receipt| {
                let (outcome, reason) = receipt.derived_outcome();
                run_record(receipt, outcome, reason)
            });
            Some(RetestRecord {
                status: result.status,
                label: retest_status_label(result.status),
                reason: result.reason.clone(),
                rebound: result.rebound,
                old_file_sha256: result.old_file_sha256.clone(),
                new_file_sha256: result.new_file_sha256.clone(),
                run,
                evidence: evidence(&doc.path, &doc.sha256, &doc.value, &pointer)?,
            })
        }
        _ => None,
    };

    let fix_checks = row
        .fix_checks
        .iter()
        .map(|&i| fix_check_record(&inputs.fix_checks[i]))
        .collect::<Result<Vec<_>, _>>()?;

    let original_outcome = row.reproduce.map(|i| inputs.reproduce[i].outcome);
    let single_fix = match row.fix_checks.as_slice() {
        [only] => Some(&inputs.fix_checks[*only]),
        _ => None,
    };
    let set = row
        .fix_checks
        .iter()
        .find_map(|&i| inputs.fix_checks[i].variant_set);
    let inputs_record = inputs_record(row.class, row.runtime, set, original_outcome, single_fix);

    Ok(FindingRecord {
        id: row.key.id.clone(),
        id_source: row.key.source,
        binding_note: (row.key.source != IdSource::Report).then_some(not_bound_label()),
        title,
        cwe,
        file: row.file.as_deref().map(report_text),
        function: row.function.as_deref().map(report_text),
        line: finding.and_then(|f| f.line),
        runtime: row.runtime.map(|runtime| match runtime {
            Runtime::Python => "python",
            Runtime::Node => "node",
        }),
        oracle_class: row.class.map(class_key),
        original,
        retest,
        fix_checks,
        inputs: inputs_record,
        call: call_record(row),
        operator: FindingEngagement::default(),
    })
}

fn run_record(
    receipt: &TargetPocReceipt,
    outcome: TargetPocOutcome,
    reason: Option<String>,
) -> RunRecord {
    let summary = receipt.replay_summary();
    RunRecord {
        receipt_version: receipt.version,
        outcome,
        label: reproduce_outcome_label(outcome),
        reason,
        replays: Replays {
            requested: summary.requested,
            completed: summary.completed,
            observed: summary.observed,
            absent: summary.absent,
            inconclusive: summary.inconclusive,
        },
        phases: receipt
            .phases
            .iter()
            .map(|phase| PhaseRecord {
                name: phase.name.clone(),
                effect: phase.effect,
                functional: phase.functional,
                reached: phase.reached,
                transcript_sha256: phase.transcript_sha256.clone(),
            })
            .collect(),
        environment: receipt_environment(receipt),
        started_at: None,
        producer_version: None,
    }
}

fn receipt_environment(receipt: &TargetPocReceipt) -> Environment {
    let event = receipt.verification_event.as_ref();
    Environment {
        image_id: receipt.image_id.clone(),
        harness_sha256: receipt
            .harness_sha256
            .clone()
            .or_else(|| event.map(|e| e.ir.binding.harness_sha256.clone())),
        // Reproduce receipts name the harness by digest only.
        harness_version: None,
        policy_version: event.map(|e| e.ir.binding.policy_version.clone()),
        adapter_sha256: receipt.adapter_sha256.clone(),
        source_tree_sha256: receipt.source_sha256.clone(),
        node: receipt.runtime.as_ref().map(|runtime| NodeEnvironment {
            language: runtime.language.clone(),
            module_kind: runtime.module_kind.clone(),
            version: runtime.node_version.clone(),
            lockfile_sha256: runtime.lockfile_sha256.clone(),
            deps_sha256: runtime.deps_sha256.clone(),
            fixture_sha256: runtime.fixture_sha256.clone(),
            driver: runtime.driver,
        }),
        sandbox_settings: None,
    }
}

fn fix_check_record(input: &FixCheckInput) -> Result<FixCheckRecord, PackageRefusal> {
    let run = &input.run;
    let check = &run.check;
    let outcome = run.outcome();
    let blocker = run.blocker();
    let binding = run.binding.as_ref();
    Ok(FixCheckRecord {
        outcome,
        label: fix_outcome_label(outcome),
        original: check.original,
        variants: check.variants,
        benign: check.benign,
        tests: check.tests,
        inputs: InputCounts {
            blocked: check.inputs_blocked,
            total: check.inputs_total,
        },
        decoding: DecodingCounts {
            blocked: check.decoding_blocked,
            applicable: check.decoding_applicable,
            total: check.decoding_total,
        },
        blocker,
        blocker_label: blocker_label(blocker),
        reason: run.reason(),
        legacy_format: check.legacy_format,
        diff_sha256: check.diff_sha256.clone(),
        variant_set_sha256: check.variant_set_sha256.clone(),
        variant_generator_version: check.variant_generator_version.clone(),
        test_command_sha256: binding.and_then(|b| b.test_command_sha256.clone()),
        per_input: input
            .variant_set
            .map(|set| {
                fixed_copy_marks(run, set)
                    .into_iter()
                    .map(|(id, fixed_copy)| FixInputRecord { id, fixed_copy })
                    .collect()
            })
            .unwrap_or_default(),
        environment: Environment {
            image_id: binding.and_then(|b| b.image_identity.clone()),
            harness_sha256: binding.map(|b| b.harness_sha256.clone()),
            harness_version: binding.map(|b| b.harness_version.clone()),
            policy_version: binding.map(|b| b.policy_version.clone()),
            adapter_sha256: binding.map(|b| b.adapter_sha256.clone()),
            source_tree_sha256: binding.map(|b| b.original.sha256.clone()),
            node: run.runtime.as_ref().map(|runtime| NodeEnvironment {
                language: runtime.language.clone(),
                module_kind: runtime.module_kind.clone(),
                version: runtime.node_version.clone(),
                lockfile_sha256: runtime.lockfile_sha256.clone(),
                deps_sha256: runtime.deps_sha256.clone(),
                fixture_sha256: runtime.fixture_sha256.clone(),
                driver: runtime.driver,
            }),
            sandbox_settings: None,
        },
        started_at: None,
        producer_version: None,
        evidence: evidence(&input.path, &input.sha256, &input.value, "")?,
    })
}

/// Patched-copy result per input of `set`, from the recorded lists only.
/// The scoring (or decoding) part is `not_recorded` unless the receipt's
/// counts account for every input of that part; an input is never marked
/// blocked just because it is missing from a not-blocked list.
fn fixed_copy_marks(run: &FixCheckRun, set: VariantSet) -> Vec<(&'static str, FixedCopy)> {
    let check = &run.check;
    let Some(stamp) = &check.variant_set else {
        return set
            .variants
            .iter()
            .map(|v| (v.id, FixedCopy::NotRecorded))
            .collect();
    };
    let scoring_total = set.scoring_len();
    let decoding_total = set.len() - scoring_total;
    let scoring_complete = check.inputs_total as usize == scoring_total
        && check.inputs_blocked as usize + stamp.ids_not_blocked.len() == scoring_total;
    let applicable = decoding_total.checked_sub(stamp.decoding_ids_not_applicable.len());
    let decoding_complete = check.decoding_total as usize == decoding_total
        && applicable == Some(check.decoding_applicable as usize)
        && check.decoding_blocked as usize + stamp.decoding_ids_not_blocked.len()
            == check.decoding_applicable as usize;
    let listed = |list: &[String], id: &str| list.iter().any(|item| item == id);
    set.variants
        .iter()
        .map(|v| {
            let mark = if !v.requires_decoding {
                match (scoring_complete, listed(&stamp.ids_not_blocked, v.id)) {
                    (false, _) => FixedCopy::NotRecorded,
                    (true, true) => FixedCopy::NotBlocked,
                    (true, false) => FixedCopy::Blocked,
                }
            } else if !decoding_complete {
                FixedCopy::NotRecorded
            } else if listed(&stamp.decoding_ids_not_applicable, v.id) {
                FixedCopy::NotApplicable
            } else if listed(&stamp.decoding_ids_not_blocked, v.id) {
                FixedCopy::NotBlocked
            } else {
                FixedCopy::Blocked
            };
            (v.id, mark)
        })
        .collect()
}

/// Attack inputs from the fixed tables. Base and benign inputs come from
/// `poc_oracle` for the class; variant and decoding inputs only from the set
/// a fix check of this row names.
fn inputs_record(
    class: Option<OracleClass>,
    runtime: Option<Runtime>,
    set: Option<VariantSet>,
    original: Option<TargetPocOutcome>,
    single_fix: Option<&FixCheckInput>,
) -> InputsRecord {
    let Some(class) = class else {
        return InputsRecord {
            determinable: false,
            note: Some(inputs_not_determinable_label()),
            items: Vec::new(),
        };
    };
    // Only one fix check gives one patched-copy column for the row; with
    // several, each check keeps its own `per_input` list.
    let marks: BTreeMap<&'static str, FixedCopy> = single_fix
        .and_then(|fix| fix.variant_set.map(|set| fixed_copy_marks(&fix.run, set)))
        .map(|marks| marks.into_iter().collect())
        .unwrap_or_default();
    let fixed = |id: &str| marks.get(id).copied().unwrap_or(FixedCopy::NotRecorded);
    let decoding_original = |id: &str| -> OriginalCopy {
        let Some(fix) = single_fix else {
            return OriginalCopy::NotRecorded;
        };
        match (&fix.run.check.variant_set, marks.get(id)) {
            (Some(stamp), Some(mark)) if *mark != FixedCopy::NotRecorded => {
                if stamp
                    .decoding_ids_not_applicable
                    .iter()
                    .any(|item| item == id)
                {
                    OriginalCopy::NoEffect
                } else {
                    OriginalCopy::Effect
                }
            }
            _ => OriginalCopy::NotRecorded,
        }
    };
    let (base_original, benign_original) = match original {
        Some(TargetPocOutcome::EffectObserved) => (OriginalCopy::Effect, OriginalCopy::NoEffect),
        // Both outcomes require a benign control without an effect.
        Some(TargetPocOutcome::EffectAbsent) => (OriginalCopy::NoEffect, OriginalCopy::NoEffect),
        _ => (OriginalCopy::NotRecorded, OriginalCopy::NotRecorded),
    };
    let base_text = fixture_inputs(class)[0];
    let base_id = set.map(|set| set.variants[0].id).unwrap_or_else(|| {
        variant_set_for(class, runtime.unwrap_or(Runtime::Python)).variants[0].id
    });
    let mut items = vec![input_item(
        InputRole::Base,
        base_id,
        base_text,
        fixed(base_id),
        base_original,
    )];
    if let Some(set) = set {
        for variant in set.variants.iter().skip(1) {
            let (role, original) = if variant.requires_decoding {
                (InputRole::Decoding, decoding_original(variant.id))
            } else {
                (InputRole::Variant, OriginalCopy::NotRecorded)
            };
            items.push(input_item(
                role,
                variant.id,
                variant.input,
                fixed(variant.id),
                original,
            ));
        }
    }
    items.push(input_item(
        InputRole::Benign,
        "benign",
        benign_input(class),
        FixedCopy::NotApplicable,
        benign_original,
    ));
    InputsRecord {
        determinable: true,
        note: None,
        items,
    }
}

fn input_item(
    role: InputRole,
    id: &'static str,
    text: &str,
    fixed_copy: FixedCopy,
    original_copy: OriginalCopy,
) -> InputRecord {
    let (text, truncated, text_sha256) = bounded(text, INPUT_MAX_CHARS);
    InputRecord {
        role,
        id,
        text,
        truncated,
        text_sha256,
        fixed_copy,
        original_copy,
    }
}

fn call_record(row: &Row) -> CallRecord {
    let Some(call) = &row.plan else {
        return CallRecord {
            supplied: false,
            note: Some(call_not_supplied_label()),
            plan_sha256s: row.plan_sha256s.clone(),
            file: None,
            function: None,
            args: Vec::new(),
        };
    };
    let args = call
        .args
        .iter()
        .map(|arg| match arg {
            TargetArgument::Payload => ArgRecord {
                kind: "payload",
                value: None,
                truncated: false,
                value_sha256: None,
            },
            TargetArgument::Callback => ArgRecord {
                kind: "callback",
                value: None,
                truncated: false,
                value_sha256: None,
            },
            TargetArgument::Literal { value } => {
                let original = value.to_string();
                let shown = sanitize(&original);
                let (value, truncated, _) = bounded(&shown, LITERAL_MAX_CHARS);
                // Hash original compact JSON bytes, never the masked display.
                let value_sha256 = truncated.then(|| sha256_hex(original.as_bytes()));
                ArgRecord {
                    kind: "literal",
                    value: Some(value),
                    truncated,
                    value_sha256,
                }
            }
        })
        .collect();
    CallRecord {
        supplied: true,
        note: None,
        plan_sha256s: row.plan_sha256s.clone(),
        file: Some(report_text(&call.file)),
        function: Some(report_text(&call.function)),
        args,
    }
}

/// Invisible and control characters shown as `[U+XXXX]`, then secrets
/// masked.
pub(super) fn sanitize(text: &str) -> String {
    let shown = crate::disclose::show_invisible(text);
    let mut out = String::with_capacity(shown.len());
    for c in shown.chars() {
        if c.is_control() {
            out.push_str(&format!("[U+{:04X}]", c as u32));
        } else {
            out.push(c);
        }
    }
    crate::util::mask_sensitive_text(&out)
}

/// At most `max` characters; when cut, the flag and the full text's sha256.
fn bounded(text: &str, max: usize) -> (String, bool, Option<String>) {
    if text.chars().count() <= max {
        (text.to_string(), false, None)
    } else {
        (
            text.chars().take(max).collect(),
            true,
            Some(sha256_hex(text.as_bytes())),
        )
    }
}

/// Repo- or model-derived text for the record.
pub fn report_text(text: &str) -> ReportText {
    let (shown, truncated, _) = bounded(&sanitize(text), REPORT_TEXT_MAX_CHARS);
    // Hash original literal bytes so masking cannot change evidence identity.
    let full_sha256 = truncated.then(|| sha256_hex(text.as_bytes()));
    ReportText {
        text: shown,
        truncated,
        full_sha256,
        origin: "report_text",
    }
}
