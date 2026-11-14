//! Receipt kind detection and predicate extraction.
//!
//! Only the two receipt types Vettalon writes are accepted, each parsed into
//! its own Rust type. Anything else is refused: Vettalon never signs an
//! arbitrary file. The predicate holds only fields copied from the receipt
//! plus the receipt kind and the Vettalon version that extracted them.

use serde::Serialize;
use serde_json::{Map, Value};

use crate::audit::fix_check::{FixCheck, FixCheckRun};
use crate::audit::retest::{RetestReport, validate_retest_state};
use crate::audit::target_poc::{NodeRuntime, TargetPocReceipt};
use crate::audit::verification_context::VerificationContext;

macro_rules! predicate_uri {
    ($kind:literal) => {
        concat!(
            "https://vettalon.dudustudio.monster/attestation/",
            $kind,
            "/v1"
        )
    };
}

/// Predicate type of a signed `vettalon reproduce` receipt.
pub const PREDICATE_TYPE_REPRODUCE: &str = predicate_uri!("reproduce");
/// Predicate type of a signed `vettalon fix check` receipt.
pub const PREDICATE_TYPE_FIX_CHECK: &str = predicate_uri!("fix-check");
/// Predicate type of a signed `vettalon retest --out` report.
pub const PREDICATE_TYPE_RETEST: &str = "https://vettalon.dudustudio.monster/attestation/retest/v2";

/// Top-level keys a `fix check --out` receipt may carry.
const FIX_RECEIPT_KEYS: &[&str] = &[
    "outcome",
    "check",
    "note",
    "binding",
    "variant_set",
    "runtime",
    "reach_summary",
];

/// The receipt types that can be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptKind {
    Reproduce,
    FixCheck,
    Retest,
}

impl ReceiptKind {
    pub fn key(self) -> &'static str {
        match self {
            Self::Reproduce => "reproduce",
            Self::FixCheck => "fix_check",
            Self::Retest => "retest",
        }
    }

    pub fn predicate_type(self) -> &'static str {
        match self {
            Self::Reproduce => PREDICATE_TYPE_REPRODUCE,
            Self::FixCheck => PREDICATE_TYPE_FIX_CHECK,
            Self::Retest => PREDICATE_TYPE_RETEST,
        }
    }
}

/// A recognised receipt and the predicate extracted from it.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedReceipt {
    pub kind: ReceiptKind,
    pub predicate: Value,
}

/// Detect the receipt kind and extract its predicate. Unknown or
/// inconsistent receipts are refused.
pub fn extract(raw: &str) -> Result<ExtractedReceipt, String> {
    let reproduce = serde_json::from_str::<TargetPocReceipt>(raw);
    let fix_check = parse_fix_check(raw);
    let retest = serde_json::from_str::<RetestReport>(raw);
    match (reproduce, fix_check, retest) {
        (Ok(receipt), Err(_), Err(_)) => Ok(ExtractedReceipt {
            kind: ReceiptKind::Reproduce,
            predicate: reproduce_predicate(&receipt)?,
        }),
        (Err(_), Ok(run), Err(_)) => Ok(ExtractedReceipt {
            kind: ReceiptKind::FixCheck,
            predicate: fix_check_predicate(&run)?,
        }),
        (Err(_), Err(_), Ok(report)) => Ok(ExtractedReceipt {
            kind: ReceiptKind::Retest,
            predicate: retest_predicate(&report)?,
        }),
        (Err(reproduce), Err(fix_check), Err(retest)) => Err(format!(
            "not a Vettalon reproduce, fix check or retest receipt; only those are signed \
             (as reproduce: {reproduce}; as fix check: {fix_check}; as retest: {retest})"
        )),
        _ => Err("the receipt matches more than one receipt type".into()),
    }
}

fn parse_fix_check(raw: &str) -> Result<FixCheckRun, String> {
    let value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let object = value.as_object().ok_or("not a JSON object")?;
    if let Some(key) = object
        .keys()
        .find(|key| !FIX_RECEIPT_KEYS.contains(&key.as_str()))
    {
        return Err(format!("unknown field {key:?}"));
    }
    let run: FixCheckRun = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let known = serde_json::to_value(&run.check).map_err(|e| e.to_string())?;
    let raw_check = object.get("check").and_then(Value::as_object);
    if let Some(key) = raw_check
        .into_iter()
        .flat_map(|check| check.keys())
        .find(|key| known.get(key.as_str()).is_none())
    {
        return Err(format!("unknown check field {key:?}"));
    }
    let recomputed = Value::from(run.outcome().key());
    match object.get("outcome") {
        Some(stored) if *stored == recomputed => Ok(run),
        Some(_) => Err("stored outcome does not match the check".into()),
        None => Err("missing field `outcome`".into()),
    }
}

fn header(kind: ReceiptKind) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("receipt_kind".into(), Value::from(kind.key()));
    map.insert(
        "vettalon_version".into(),
        Value::from(env!("CARGO_PKG_VERSION")),
    );
    map
}

/// Insert `value` unless it serializes to `null`.
fn put<T: Serialize + ?Sized>(
    map: &mut Map<String, Value>,
    key: &str,
    value: &T,
) -> Result<(), String> {
    let value = serde_json::to_value(value)
        .map_err(|e| format!("cannot encode predicate field {key}: {e}"))?;
    if !value.is_null() {
        map.insert(key.to_string(), value);
    }
    Ok(())
}

fn reproduce_predicate(receipt: &TargetPocReceipt) -> Result<Value, String> {
    receipt.validate_stored(None)?;
    let mut p = header(ReceiptKind::Reproduce);
    put(&mut p, "receipt_version", &receipt.version)?;
    put(&mut p, "outcome", &receipt.outcome)?;
    put(&mut p, "reason", &receipt.reason)?;
    put(&mut p, "target_file", &receipt.target_file)?;
    put(&mut p, "target_function", &receipt.target_function)?;
    put(&mut p, "target_file_sha256", &receipt.target_file_sha256)?;
    put(&mut p, "target_plan_sha256", &receipt.target_plan_sha256)?;
    put(&mut p, "source_sha256", &receipt.source_sha256)?;
    put(&mut p, "adapter_sha256", &receipt.adapter_sha256)?;
    put(&mut p, "image_id", &receipt.image_id)?;
    put(&mut p, "exclusions", &receipt.exclusions)?;
    match (receipt.version, &receipt.replays) {
        (1, None) => {}
        (2 | 3, Some(summary)) => {
            // The stored outcome must be the one the replays support.
            let (derived, _) = receipt.derived_outcome();
            if derived != receipt.outcome {
                return Err("the receipt's outcome disagrees with its replays".into());
            }
            put(&mut p, "replays_requested", &summary.requested)?;
            put(&mut p, "replays_completed", &summary.completed)?;
            put(&mut p, "replays_observed", &summary.observed)?;
        }
        _ => {
            return Err(
                "the receipt's version and replays record are not a supported combination".into(),
            );
        }
    }
    if let Some(runtime) = &receipt.runtime {
        if receipt.version != 3 {
            return Err("Node runtime requires a version-3 receipt".into());
        }
        put_node_runtime(&mut p, runtime)?;
        put(&mut p, "harness_sha256", &receipt.harness_sha256)?;
        put(&mut p, "reach_source", "in_process_hook")?;
        let reached: Vec<Value> = receipt.replay_summary().runs.iter().map(|run| {
            serde_json::json!({
                "index": run.index,
                "reached": run.phases.iter().filter(|phase| phase.reached == Some(true)).count(),
                "not_reached": run.phases.iter().filter(|phase| phase.reached == Some(false)).count(),
                "unknown": run.phases.iter().filter(|phase| phase.reached.is_none()).count(),
            })
        }).collect();
        put(&mut p, "replays_reached", &reached)?;
    }
    if let Some(event) = &receipt.verification_event {
        if let Some(runtime) = &receipt.runtime
            && (event.ir.binding.runtime.as_ref() != Some(&runtime.identity())
                || receipt.harness_sha256.as_deref()
                    != Some(event.ir.binding.harness_sha256.as_str()))
        {
            return Err("Node receipt and verification event identities disagree".into());
        }
        event
            .validate()
            .map_err(|e| format!("the receipt's verification event does not re-derive: {e}"))?;
        put(&mut p, "verdict", &event.decision.verdict)?;
        put(&mut p, "verdict_failures", &event.decision.failures)?;
        put(&mut p, "harness_sha256", &event.ir.binding.harness_sha256)?;
        put(&mut p, "policy_version", &event.ir.binding.policy_version)?;
    }
    Ok(Value::Object(p))
}

/// A `vettalon retest --out` report. Refused when its summary or any
/// result's status disagrees with what its receipts support, and when a
/// `still_observed` or `not_observed` result has no receipt. The predicate
/// carries hashes, commits, statuses, target files/functions and replay counts.
fn retest_predicate(report: &RetestReport) -> Result<Value, String> {
    validate_retest_state(report).map_err(|e| e.to_string())?;
    let mut results = Vec::with_capacity(report.results.len());
    for result in &report.results {
        let mut r = Map::new();
        put(&mut r, "finding_id", &result.finding_id)?;
        put(&mut r, "status", &result.status)?;
        put(&mut r, "reason", &result.reason)?;
        put(&mut r, "old_file_sha256", &result.old_file_sha256)?;
        put(&mut r, "new_file_sha256", &result.new_file_sha256)?;
        put(&mut r, "rebound", &result.rebound)?;
        if let Some(receipt) = &result.receipt {
            put(&mut r, "target_file", &receipt.target_file)?;
            put(&mut r, "target_function", &receipt.target_function)?;
            put(&mut r, "receipt_version", &receipt.version)?;
            put(&mut r, "receipt_outcome", &receipt.outcome)?;
            put(&mut r, "target_file_sha256", &receipt.target_file_sha256)?;
            put(&mut r, "adapter_sha256", &receipt.adapter_sha256)?;
            put(&mut r, "image_id", &receipt.image_id)?;
            if let Some(runtime) = &receipt.runtime {
                put_node_runtime(&mut r, runtime)?;
                put(&mut r, "harness_sha256", &receipt.harness_sha256)?;
            }
            if let Some(summary) = &receipt.replays {
                put(&mut r, "replays_requested", &summary.requested)?;
                put(&mut r, "replays_completed", &summary.completed)?;
                put(&mut r, "replays_observed", &summary.observed)?;
            }
        }
        results.push(Value::Object(r));
    }
    let mut p = header(ReceiptKind::Retest);
    put(&mut p, "report_version", &report.version)?;
    put(&mut p, "old_report_sha256", &report.old_report_sha256)?;
    put(&mut p, "old_repo_commit", &report.old_repo_commit)?;
    put(&mut p, "new_repo_commit", &report.new_repo_commit)?;
    put(&mut p, "new_tree_clean", &report.new_tree_clean)?;
    put(&mut p, "replays", &report.replays)?;
    put(&mut p, "summary", &report.summary)?;
    p.insert("results".into(), Value::Array(results));
    Ok(Value::Object(p))
}

/// Verdict fields go through the detail parser (`FixCheck::parse`), so a
/// receipt whose check would not be accepted as evidence is refused, and new
/// verdict fields are copied without changes here.
fn fix_check_predicate(run: &FixCheckRun) -> Result<Value, String> {
    let mut bare = run.check.clone();
    bare.variant_set = None;
    let parsed = FixCheck::parse(&bare.to_detail())
        .filter(|parsed| *parsed == bare)
        .ok_or("the fix check verdict is not internally consistent")?;
    let mut p = header(ReceiptKind::FixCheck);
    put(&mut p, "outcome", &run.outcome())?;
    put(&mut p, "check", &parsed)?;
    put(&mut p, "diff_sha256", &parsed.diff_sha256)?;
    put(&mut p, "reason", &parsed.reason)?;
    put(&mut p, "variant_set_sha256", &parsed.variant_set_sha256)?;
    put(
        &mut p,
        "variant_generator_version",
        &parsed.variant_generator_version,
    )?;
    if run.runtime.as_ref().map(NodeRuntime::identity)
        != run
            .binding
            .as_ref()
            .and_then(|binding| binding.runtime.clone())
    {
        return Err("receipt and fix binding runtime identities disagree".into());
    }
    if let Some(runtime) = &run.runtime {
        let binding = run
            .binding
            .as_ref()
            .ok_or("Node fix receipt requires a binding")?;
        if !binding.complete() || !runtime.matches_file(&binding.target_file) {
            return Err("Node fix receipt requires a complete matching binding".into());
        }
        put_node_runtime(&mut p, runtime)?;
        if run
            .binding
            .as_ref()
            .is_some_and(|binding| binding.runtime.as_ref() != Some(&runtime.identity()))
        {
            return Err("Node receipt and fix binding identities disagree".into());
        }
        if let Some(reach) = &run.reach_summary {
            if reach.reach_source != "in_process_hook" || !reach.diagnostic {
                return Err("Node reach must be labelled as untrusted diagnostics".into());
            }
            put(&mut p, "reach_summary", reach)?;
        }
    } else if run.reach_summary.is_some() {
        return Err("reach diagnostics require a Node runtime".into());
    }
    if let Some(binding) = &run.binding {
        let valid = VerificationContext::parse(&binding.to_detail())
            .filter(|valid| valid == binding && valid.diff_sha256 == parsed.diff_sha256)
            .ok_or("the receipt's fix_context_v1 binding is invalid or names another diff")?;
        put_binding(&mut p, &valid)?;
    }
    Ok(Value::Object(p))
}

fn put_node_runtime(p: &mut Map<String, Value>, runtime: &NodeRuntime) -> Result<(), String> {
    if !runtime.valid() {
        return Err("invalid Node runtime identity".into());
    }
    put(p, "language", &runtime.language)?;
    put(p, "module_kind", &runtime.module_kind)?;
    put(p, "export_kind", &runtime.export_kind)?;
    put(p, "node_version", &runtime.node_version)?;
    put(p, "lockfile_sha256", &runtime.lockfile_sha256)?;
    put(
        p,
        "lockfile_summary_sha256",
        &runtime.lockfile_summary_sha256,
    )?;
    put(p, "deps_sha256", &runtime.deps_sha256)?;
    put(p, "fixture_sha256", &runtime.fixture_sha256)?;
    put(p, "driver", &runtime.driver)?;
    put(p, "hook_bundle_sha256", &runtime.hook_bundle_sha256)
}

fn put_binding(p: &mut Map<String, Value>, b: &VerificationContext) -> Result<(), String> {
    if let Some(runtime) = &b.runtime {
        put(p, "node_version", &runtime.node_version)?;
        put(p, "lockfile_sha256", &runtime.lockfile_sha256)?;
        put(
            p,
            "lockfile_summary_sha256",
            &runtime.lockfile_summary_sha256,
        )?;
        put(p, "deps_sha256", &runtime.deps_sha256)?;
        put(p, "fixture_sha256", &runtime.fixture_sha256)?;
    }
    put(p, "source_scope", &b.source_scope)?;
    put(p, "check_sha256", &b.check_sha256)?;
    put(p, "target_file", &b.target_file)?;
    put(p, "target_file_sha256", &b.target_file_sha256)?;
    put(p, "finding_file_sha256", &b.finding_file_sha256)?;
    put(p, "original_tree_sha256", &b.original.sha256)?;
    put(p, "fixed_tree_sha256", &b.fixed.sha256)?;
    put(p, "exclusions", &b.exclusions)?;
    put(p, "adapter_sha256", &b.adapter_sha256)?;
    put(p, "fixed_adapter_sha256", &b.fixed_adapter_sha256)?;
    put(p, "target_plan_sha256", &b.target_plan_sha256)?;
    put(p, "test_command_sha256", &b.test_command_sha256)?;
    put(p, "image_identity", &b.image_identity)?;
    put(p, "harness_sha256", &b.harness_sha256)?;
    put(p, "harness_version", &b.harness_version)?;
    put(p, "policy_version", &b.policy_version)
}
