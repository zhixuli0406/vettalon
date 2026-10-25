//! Structured calls into the actual prepared Python source, never a rewritten sink.
//!
//! The call plan is data, not Python source.  Vettalon writes a fixed adapter
//! which hashes and compiles the selected source bytes inside a fresh,
//! network-disabled container.  Three independent containers run an attack,
//! a benign control, and an attack with fresh nonces.  A receipt remains
//! `Inconclusive` on stale/unsafe input, incomplete capture, a malformed
//! harness verdict, or any identity drift.  Nothing in this module changes a
//! finding's status.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::fix_diff;
use super::poc::{POC_TIMEOUT, PocBudget};
use super::poc_oracle::{
    OracleClass, OracleSecrets, benign_input, classify, fixture_inputs,
    target_runner as oracle_target_runner,
};
use super::schema::{Finding, sha256_hex};
use super::verification::{CompileInput, HostObservations, VerificationEvent, compile_ir};
use super::verification_context::{
    SnapshotExclusions, is_sha256, snapshot_digest, source_file_digest,
};
use vettalon_contract::verification::{
    BackendKind, CleanupState, DerivedVerdict, ReplayGrade, TamperSignal,
};

const TARGET_CALL_MAX_BYTES: usize = 8 * 1024;
const TARGET_MAX_ARGS: usize = 16;
const TARGET_LITERAL_MAX_DEPTH: usize = 8;
const TARGET_SOURCE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const TARGET_HARNESS_VERSION: &str = "vettalon-target-oracle-v1";

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetArgument {
    Payload,
    Literal { value: Value },
}

impl<'de> Deserialize<'de> for TargetArgument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Payload {},
            Literal { value: Value },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::Payload {} => TargetArgument::Payload,
            Wire::Literal { value } => TargetArgument::Literal { value },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCall {
    pub file: String,
    pub function: String,
    pub args: Vec<TargetArgument>,
}

impl TargetCall {
    pub fn validate(&self) -> Result<(), &'static str> {
        let safe = vettalon_contract::safe_path::SafeRepoPath::parse(&self.file)
            .map_err(|_| "unsafe_target_path")?;
        if !safe.as_str().ends_with(".py") {
            return Err("unsupported_target_language");
        }
        let basename = safe.as_str().rsplit('/').next().unwrap_or("");
        if crate::util::is_secret_file(basename) {
            return Err("unsafe_target_path");
        }
        if !valid_python_identifier(&self.function) {
            return Err("invalid_target_function");
        }
        if self.args.is_empty() || self.args.len() > TARGET_MAX_ARGS {
            return Err("invalid_target_arguments");
        }
        if self
            .args
            .iter()
            .filter(|arg| matches!(arg, TargetArgument::Payload))
            .count()
            != 1
        {
            return Err("invalid_target_arguments");
        }
        if self.args.iter().any(|arg| match arg {
            TargetArgument::Payload => false,
            TargetArgument::Literal { value } => json_depth(value) > TARGET_LITERAL_MAX_DEPTH,
        }) {
            return Err("target_literal_too_deep");
        }
        let encoded = serde_json::to_vec(self).map_err(|_| "invalid_target_arguments")?;
        if encoded.len() > TARGET_CALL_MAX_BYTES {
            return Err("target_call_too_large");
        }
        Ok(())
    }
}

pub fn parse_target_call(input: &str) -> Result<TargetCall, &'static str> {
    if input.len() > TARGET_CALL_MAX_BYTES {
        return Err("target_call_too_large");
    }
    let call: TargetCall =
        vettalon_contract::strict_json::parse_strict_with_limit(input, TARGET_CALL_MAX_BYTES)
            .map_err(|_| "invalid_target_call")?;
    call.validate()?;
    Ok(call)
}

fn valid_python_identifier(value: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
        "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global",
        "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield", "match", "case",
    ];
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
        && !value.starts_with("__")
        && !KEYWORDS.contains(&value)
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Build the only Python adapter accepted by the target-bound path.  The
/// complete plan is hex-encoded JSON data, so literals can never become code.
pub(crate) fn build_target_adapter(
    call: &TargetCall,
    target_file_sha256: &str,
) -> Result<String, &'static str> {
    call.validate()?;
    if !is_sha256(target_file_sha256) {
        return Err("invalid_target_hash");
    }
    let plan = serde_json::to_vec(call).map_err(|_| "invalid_target_call")?;
    let target = format!("/workspace/tree/{}", call.file);
    Ok(format!(
        r#"import hashlib
import importlib.machinery
import importlib.util
import inspect
import json
import os
import sys
import types
PLAN = json.loads(bytes.fromhex({plan_hex:?}).decode('utf-8'))
TARGET_PATH = {target:?}
EXPECTED_SHA256 = {expected:?}
def _load_target():
    loader = importlib.machinery.SourceFileLoader('_vettalon_target', TARGET_PATH)
    source = loader.get_data(TARGET_PATH)
    if hashlib.sha256(source).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError('target source identity mismatch')
    spec = importlib.util.spec_from_loader('_vettalon_target', loader, origin=TARGET_PATH)
    module = importlib.util.module_from_spec(spec) if spec is not None else types.ModuleType('_vettalon_target')
    module.__file__ = TARGET_PATH
    code = loader.source_to_code(source, TARGET_PATH)
    exec(code, module.__dict__)
    return module
def run(payload):
    module = _load_target()
    function = module.__dict__.get(PLAN['function'])
    if not callable(function):
        raise RuntimeError('target function unavailable')
    args = [payload if item['kind'] == 'payload' else item['value'] for item in PLAN['args']]
    result = function(*args)
    if inspect.isawaitable(result):
        raise RuntimeError('async target unsupported')
    return str(result)
def _main():
    if len(sys.argv) != 3:
        raise RuntimeError('invalid target invocation')
    try:
        payload = json.loads(bytes.fromhex(sys.argv[1]).decode('utf-8'))
    except Exception as exc:
        raise RuntimeError('invalid target payload') from exc
    if not isinstance(payload, str):
        raise RuntimeError('invalid target payload')
    encoded = json.dumps({{'result': run(payload)}}, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    if len(encoded) > 65536:
        raise RuntimeError('target result too large')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(sys.argv[2], flags, 0o600)
    with os.fdopen(fd, 'wb') as fh:
        fh.write(encoded)
if __name__ == '__main__':
    _main()
"#,
        plan_hex = hex::encode(plan),
        target = target,
        expected = target_file_sha256,
    ))
}

/// Shared by typed fix verification so both the PoC and the before/after
/// check use the same no-tree-on-`sys.path` harness policy.
pub(crate) fn target_runner(class: OracleClass, secrets: &OracleSecrets, payload: &str) -> String {
    oracle_target_runner(class, secrets, payload)
}

/// Bind the IR to the generated runner templates and the exact target adapter.
/// Fixed representative secrets keep this identity deterministic while still
/// changing whenever runner generation or adapter bytes change.
pub(crate) fn target_harness_sha256(class: OracleClass, adapter_sha256: &str) -> String {
    let class_id = match class {
        OracleClass::CommandInjection => "command_injection",
        OracleClass::PathTraversal => "path_traversal",
        OracleClass::Sqli => "sqli",
    };
    let secrets = OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    };
    let malicious = fixture_inputs(class)[0];
    let parts = [
        TARGET_HARNESS_VERSION.as_bytes().to_vec(),
        class_id.as_bytes().to_vec(),
        adapter_sha256.as_bytes().to_vec(),
        target_runner(class, &secrets, malicious).into_bytes(),
        target_runner(class, &secrets, benign_input(class)).into_bytes(),
        target_runner(class, &secrets, malicious).into_bytes(),
    ];
    let mut material = Vec::new();
    for part in parts {
        material.extend_from_slice(&(part.len() as u64).to_be_bytes());
        material.extend_from_slice(&part);
    }
    sha256_hex(&material)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetPocOutcome {
    EffectObserved,
    EffectAbsent,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPocPhase {
    pub name: String,
    pub nonce_commitment: String,
    pub effect: Option<bool>,
    pub functional: Option<bool>,
    pub exit_code: Option<i64>,
    pub transcript_sha256: Option<String>,
    pub elapsed_ms: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPocReceipt {
    pub version: u32,
    pub outcome: TargetPocOutcome,
    pub phases: Vec<TargetPocPhase>,
    pub target_file: String,
    pub target_function: String,
    pub target_plan_sha256: Option<String>,
    pub target_file_sha256: Option<String>,
    pub source_sha256: Option<String>,
    pub exclusions: Option<SnapshotExclusions>,
    pub adapter_sha256: Option<String>,
    pub image_id: Option<String>,
    pub reason: Option<String>,
    /// Language-neutral, host-derived execution event. Missing on legacy or
    /// pre-execution failures; stored verdicts are re-derived on validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_event: Option<VerificationEvent>,
}

impl TargetPocReceipt {
    fn inconclusive(call: &TargetCall, reason: &str) -> Self {
        Self {
            version: 1,
            outcome: TargetPocOutcome::Inconclusive,
            phases: Vec::new(),
            target_file: call.file.clone(),
            target_function: call.function.clone(),
            target_plan_sha256: serde_json::to_vec(call).ok().map(|v| sha256_hex(&v)),
            target_file_sha256: None,
            source_sha256: None,
            exclusions: None,
            adapter_sha256: None,
            image_id: None,
            reason: Some(reason.into()),
            verification_event: None,
        }
    }
}

#[async_trait::async_trait]
pub trait TargetSandbox: Send + Sync {
    fn image_id(&self) -> &str;
    async fn run(&self, tree: &Path, runner: &str, adapter: &str) -> Result<(i64, String), String>;
}

struct DockerTargetSandbox<'a> {
    sandbox: crate::sandbox::DockerSandbox,
    budget: &'a PocBudget,
}

#[async_trait::async_trait]
impl TargetSandbox for DockerTargetSandbox<'_> {
    fn image_id(&self) -> &str {
        &self.sandbox.image
    }

    async fn run(&self, tree: &Path, runner: &str, adapter: &str) -> Result<(i64, String), String> {
        if !self.budget.try_claim() {
            return Err("target_poc_budget_exhausted".into());
        }
        self.sandbox
            .run_workspace_with_tree(
                &[("runner.py", runner), ("sink.py", adapter)],
                tree,
                &[
                    "python3".into(),
                    "-I".into(),
                    "-B".into(),
                    "/workspace/runner.py".into(),
                ],
                POC_TIMEOUT,
            )
            .await
    }
}

/// Read-only source preflight shared by GUI transports. Does not execute source,
/// create containers, or claim that a function call will succeed at runtime.
pub fn preflight_source(repo_root: &Path, finding: &Finding) -> Result<String, &'static str> {
    TargetCall {
        file: finding.file.clone(),
        function: "target".into(),
        args: vec![TargetArgument::Payload],
    }
    .validate()?;
    if classify(finding).is_none() {
        return Err("unsupported_oracle_class");
    }
    let expected = finding
        .file_hash
        .as_deref()
        .filter(|hash| is_sha256(hash))
        .ok_or("missing_finding_source_identity")?;
    let (_, live_hash) = read_target_source(repo_root, &finding.file)?;
    if expected != live_hash {
        return Err("stale_source");
    }
    Ok(live_hash)
}

/// Docker detection binds the selected mutable tag to an immutable image ID.
pub async fn run_target_poc(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    image: &str,
) -> TargetPocReceipt {
    if let Err(reason) = call.validate() {
        return TargetPocReceipt::inconclusive(call, reason);
    }
    if finding.file != call.file {
        return TargetPocReceipt::inconclusive(call, "finding_target_mismatch");
    }
    if classify(finding).is_none() {
        return TargetPocReceipt::inconclusive(call, "unsupported_oracle_class");
    }
    let budget = PocBudget::with_image(3, image);
    let sandbox = match budget.sandbox().await {
        Ok(sandbox) => sandbox,
        Err(_) => return TargetPocReceipt::inconclusive(call, "sandbox_unavailable"),
    };
    let runner = DockerTargetSandbox {
        sandbox,
        budget: &budget,
    };
    run_target_poc_with_sandbox(repo_root, finding, call, &runner).await
}

/// Testable core.  The host only validates and copies bytes; target Python is
/// executed exclusively by `TargetSandbox`.
pub(crate) async fn run_target_poc_with_sandbox<S: TargetSandbox>(
    repo_root: &Path,
    finding: &Finding,
    call: &TargetCall,
    sandbox: &S,
) -> TargetPocReceipt {
    let mut receipt = TargetPocReceipt::inconclusive(call, "target_poc_incomplete");
    if let Err(reason) = call.validate() {
        receipt.reason = Some(reason.into());
        return receipt;
    }
    if finding.file != call.file {
        receipt.reason = Some("finding_target_mismatch".into());
        return receipt;
    }
    let Some(class) = classify(finding) else {
        receipt.reason = Some("unsupported_oracle_class".into());
        return receipt;
    };
    if !valid_image_id(sandbox.image_id()) {
        receipt.reason = Some("invalid_image_identity".into());
        return receipt;
    }
    let (source, live_hash) = match read_target_source(repo_root, &call.file) {
        Ok(value) => value,
        Err(reason) => {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    };
    if finding
        .file_hash
        .as_deref()
        .is_some_and(|expected| expected != live_hash)
    {
        receipt.reason = Some("stale_source".into());
        return receipt;
    }
    if finding.file_hash.is_none() {
        receipt.reason = Some("missing_finding_source_identity".into());
        return receipt;
    }
    if declares_top_level_async_function(&source, &call.function) {
        receipt.reason = Some("async_target_unsupported".into());
        return receipt;
    }
    if !declares_top_level_function(&source, &call.function) {
        receipt.reason = Some("function_not_declared".into());
        return receipt;
    }

    let snapshot = match fix_diff::snapshot(repo_root) {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    };
    let tree_digest = match snapshot_digest(&snapshot.path) {
        Ok(value) => value,
        Err(reason) => {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    };
    let copied_hash = match source_file_digest(&snapshot.path, &call.file) {
        Ok(value) => value,
        Err(_) => {
            receipt.reason = Some("unsafe_target_path".into());
            return receipt;
        }
    };
    if copied_hash != live_hash {
        receipt.reason = Some("source_changed_during_snapshot".into());
        return receipt;
    }
    let adapter = match build_target_adapter(call, &copied_hash) {
        Ok(adapter) => adapter,
        Err(reason) => {
            receipt.reason = Some(reason.into());
            return receipt;
        }
    };
    receipt.target_file_sha256 = Some(copied_hash);
    receipt.source_sha256 = Some(tree_digest.sha256.clone());
    receipt.exclusions = Some(snapshot.exclusions.clone());
    receipt.adapter_sha256 = Some(sha256_hex(adapter.as_bytes()));
    receipt.image_id = Some(sandbox.image_id().to_string());

    let malicious = fixture_inputs(class)[0];
    let plans = [
        ("target", malicious),
        ("benign_control", benign_input(class)),
        ("fresh_nonce_rerun", malicious),
    ];
    for (name, payload) in plans {
        let secrets = OracleSecrets::fresh();
        let runner = target_runner(class, &secrets, payload);
        let started = Instant::now();
        let result = sandbox.run(&snapshot.path, &runner, &adapter).await;
        let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let mut phase = TargetPocPhase {
            name: name.into(),
            nonce_commitment: sha256_hex(secrets.marker.as_bytes()),
            effect: None,
            functional: None,
            exit_code: None,
            transcript_sha256: None,
            elapsed_ms,
            reason: None,
        };
        match result {
            Ok((exit, output)) => {
                phase.exit_code = Some(exit);
                phase.transcript_sha256 = Some(sha256_hex(output.as_bytes()));
                match parse_verdict(&output, &secrets.marker) {
                    Ok((effect, functional, error)) if exit == 0 && !error => {
                        phase.effect = Some(effect);
                        phase.functional = functional;
                    }
                    Ok(_) => phase.reason = Some("target_execution_error".into()),
                    Err(reason) => phase.reason = Some(reason.into()),
                }
            }
            Err(_) => phase.reason = Some("incomplete_sandbox_capture".into()),
        }
        receipt.phases.push(phase);
    }

    if snapshot_digest(&snapshot.path).ok().as_ref() != Some(&tree_digest)
        || source_file_digest(&snapshot.path, &call.file)
            .ok()
            .as_deref()
            != receipt.target_file_sha256.as_deref()
    {
        receipt.reason = Some("snapshot_changed".into());
        attach_verification_event(&mut receipt, finding, call, class);
        return receipt;
    }
    if receipt
        .phases
        .iter()
        .any(|phase| phase.reason.is_some() || phase.effect.is_none())
    {
        receipt.reason = receipt
            .phases
            .iter()
            .find_map(|phase| phase.reason.clone())
            .or_else(|| Some("phase_incomplete".into()));
        attach_verification_event(&mut receipt, finding, call, class);
        return receipt;
    }
    let effects: Vec<bool> = receipt
        .phases
        .iter()
        .filter_map(|phase| phase.effect)
        .collect();
    let benign_healthy = match class {
        OracleClass::CommandInjection => receipt.phases[1].functional.is_none(),
        OracleClass::PathTraversal | OracleClass::Sqli => {
            receipt.phases[1].functional == Some(true)
        }
    };
    if effects == [true, false, true] && benign_healthy {
        receipt.outcome = TargetPocOutcome::EffectObserved;
        receipt.reason = None;
    } else if effects == [false, false, false] && benign_healthy {
        receipt.outcome = TargetPocOutcome::EffectAbsent;
        receipt.reason = None;
    } else {
        receipt.reason = Some("non_differential_result".into());
    }
    attach_verification_event(&mut receipt, finding, call, class);
    receipt
}

fn attach_verification_event(
    receipt: &mut TargetPocReceipt,
    finding: &Finding,
    call: &TargetCall,
    class: OracleClass,
) {
    let (
        Some(source_sha256),
        Some(target_file_sha256),
        Some(target_plan_sha256),
        Some(adapter_sha256),
        Some(image_id),
    ) = (
        receipt.source_sha256.clone(),
        receipt.target_file_sha256.clone(),
        receipt.target_plan_sha256.clone(),
        receipt.adapter_sha256.clone(),
        receipt.image_id.clone(),
    )
    else {
        return;
    };
    let cwe = match class {
        OracleClass::CommandInjection => "CWE-78",
        OracleClass::PathTraversal => "CWE-22",
        OracleClass::Sqli => "CWE-89",
    };
    let ir = match compile_ir(&CompileInput {
        finding_id: finding.id.clone(),
        file: call.file.clone(),
        line: finding.line,
        symbol: call.function.clone(),
        cwe: cwe.into(),
        source_sha256,
        target_file_sha256,
        target_plan_sha256,
        harness_sha256: target_harness_sha256(class, &adapter_sha256),
    }) {
        Ok(ir) => ir,
        Err(_) => return,
    };

    let reason = receipt.reason.as_deref();
    let mut tampering = Vec::new();
    if matches!(
        reason,
        Some("duplicate_target_verdict" | "invalid_target_verdict" | "target_verdict_missing")
    ) {
        tampering.push(TamperSignal::VerdictChannelForgery);
    }
    if reason == Some("snapshot_changed") {
        tampering.push(TamperSignal::SourceIdentityDrift);
    }
    let all_transcripts = !receipt.phases.is_empty()
        && receipt
            .phases
            .iter()
            .all(|phase| phase.transcript_sha256.is_some());
    let all_zero = !receipt.phases.is_empty()
        && receipt
            .phases
            .iter()
            .all(|phase| phase.exit_code == Some(0));
    let benign_healthy = receipt.phases.get(1).and_then(|phase| phase.effect) == Some(false)
        && match class {
            OracleClass::CommandInjection => true,
            OracleClass::PathTraversal | OracleClass::Sqli => {
                receipt.phases.get(1).and_then(|phase| phase.functional) == Some(true)
            }
        };
    let fresh_challenge = match (receipt.phases.first(), receipt.phases.get(2)) {
        (Some(first), Some(second)) => first
            .effect
            .zip(second.effect)
            .map(|(a, b)| a == b && first.nonce_commitment != second.nonce_commitment),
        _ => None,
    };
    let challenge_commitment = sha256_hex(
        serde_json::to_vec(
            &receipt
                .phases
                .iter()
                .map(|phase| &phase.nonce_commitment)
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default()
        .as_slice(),
    );
    let transcript_sha256 = all_transcripts.then(|| {
        sha256_hex(
            serde_json::to_vec(
                &receipt
                    .phases
                    .iter()
                    .filter_map(|phase| phase.transcript_sha256.as_deref())
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_default()
            .as_slice(),
        )
    });
    let effect_observed = match receipt.outcome {
        TargetPocOutcome::EffectObserved => Some(true),
        TargetPocOutcome::EffectAbsent => Some(false),
        TargetPocOutcome::Inconclusive => None,
    };
    let cleanup = if all_transcripts {
        // TargetSandbox returns Ok only after the backend has confirmed
        // cleanup. Err deliberately cannot distinguish capture from cleanup.
        CleanupState::Confirmed
    } else {
        CleanupState::Unknown
    };
    let observations = HostObservations {
        backend_kind: BackendKind::Docker,
        backend_identity: image_id,
        platform: "linux/container".into(),
        challenge_commitment,
        capture_complete: all_transcripts,
        cleanup,
        tampering,
        effect_observed,
        benign_control: all_transcripts.then_some(benign_healthy),
        fresh_challenge_control: fresh_challenge,
        exit_code: all_zero.then_some(0),
        transcript_sha256,
        replay_grade: ReplayGrade::Semantic,
    };
    if let Ok(event) = VerificationEvent::from_host_observations(ir, observations) {
        debug_assert_eq!(
            event.decision.verdict,
            match receipt.outcome {
                TargetPocOutcome::EffectObserved => DerivedVerdict::EffectObserved,
                TargetPocOutcome::EffectAbsent => DerivedVerdict::EffectAbsent,
                TargetPocOutcome::Inconclusive => DerivedVerdict::Inconclusive,
            }
        );
        receipt.verification_event = Some(event);
    }
}

fn valid_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_sha256)
}

fn read_target_source(root: &Path, file: &str) -> Result<(String, String), &'static str> {
    let safe = vettalon_contract::safe_path::SafeRepoPath::parse(file)
        .map_err(|_| "unsafe_target_path")?;
    let root = std::fs::canonicalize(root).map_err(|_| "unsafe_target_path")?;
    let mut path = PathBuf::from(&root);
    let parts: Vec<&str> = safe.as_str().split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        path.push(part);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| "unsafe_target_path")?;
        if meta.file_type().is_symlink()
            || (index + 1 < parts.len() && !meta.is_dir())
            || (index + 1 == parts.len()
                && (!meta.is_file() || meta.len() > TARGET_SOURCE_MAX_BYTES))
        {
            return Err("unsafe_target_path");
        }
    }
    let basename = parts.last().copied().unwrap_or("");
    if crate::util::is_secret_file(basename) {
        return Err("unsafe_target_path");
    }
    let before = std::fs::symlink_metadata(&path).map_err(|_| "unsafe_target_path")?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut input = options.open(&path).map_err(|_| "unsafe_target_path")?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut input)
        .take(TARGET_SOURCE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "unsafe_target_path")?;
    let after = input.metadata().map_err(|_| "unsafe_target_path")?;
    if bytes.len() as u64 > TARGET_SOURCE_MAX_BYTES
        || after.len() != before.len()
        || after.len() != bytes.len() as u64
    {
        return Err("source_changed_during_read");
    }
    let hash = sha256_hex(&bytes);
    let source = String::from_utf8(bytes).map_err(|_| "target_source_not_utf8")?;
    Ok((source, hash))
}

fn declares_top_level_function(source: &str, function: &str) -> bool {
    let direct = format!("def {function}(");
    source.lines().any(|line| line.starts_with(&direct))
}

fn declares_top_level_async_function(source: &str, function: &str) -> bool {
    let asynchronous = format!("async def {function}(");
    source.lines().any(|line| line.starts_with(&asynchronous))
}

pub(super) fn parse_verdict(
    output: &str,
    marker: &str,
) -> Result<(bool, Option<bool>, bool), &'static str> {
    let mut effect = None;
    let mut functional = None;
    let mut error = false;
    let mut marked = 0usize;
    for line in output.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("__VTL_ORACLE__ ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        if parts.next() != Some(marker) {
            continue;
        }
        marked += 1;
        for part in parts {
            let parse_bool = |raw: &str| match raw {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err("invalid_target_verdict"),
            };
            if let Some(raw) = part.strip_prefix("effect=") {
                if effect.is_some() {
                    return Err("duplicate_target_verdict");
                }
                effect = Some(parse_bool(raw)?);
            } else if let Some(raw) = part.strip_prefix("functional=") {
                if functional.is_some() {
                    return Err("duplicate_target_verdict");
                }
                functional = Some(parse_bool(raw)?);
            } else if let Some(raw) = part.strip_prefix("error=") {
                error |= parse_bool(raw)?;
            } else {
                return Err("invalid_target_verdict");
            }
        }
    }
    if marked == 0 || effect.is_none() {
        return Err("target_verdict_missing");
    }
    Ok((effect.unwrap_or(false), functional, error))
}

#[cfg(test)]
#[path = "target_poc_tests.rs"]
mod tests;
