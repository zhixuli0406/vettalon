//! Language-neutral verification contracts.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::safe_path::SafeRepoPath;

pub const VERIFICATION_IR_SCHEMA: &str = "vettalon.verification-ir/1";
pub const EXECUTION_ENVELOPE_SCHEMA: &str = "vettalon.execution-envelope/1";
pub const EVALUATION_CASE_SCHEMA: &str = "vettalon.evaluation-case/1";
pub const COUNTEREXAMPLE_CELL_SCHEMA: &str = "vettalon.counterexample-cell/1";
pub const ENGINEERING_MEASUREMENT_SCHEMA: &str = "vettalon.engineering-measurement/1";

const MAX_ID_BYTES: usize = 200;
const MAX_PLATFORM_BYTES: usize = 200;
const MAX_CONTROLS: usize = 64;
const MAX_CAPABILITIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractError {
    WrongSchema,
    UnsafeSubjectPath,
    InvalidIdentifier,
    InvalidDigest,
    InvalidBackendIdentity,
    InvalidPlatform,
    TooManyControls,
    DuplicateControl,
    TooManyCapabilities,
    DuplicateCapability,
    BindingMismatch,
    InvalidCase,
    InvalidAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Jvm,
    Native,
    Wasm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    CommandExecution,
    FileReadOutsideRoot,
    FileWriteOutsideRoot,
    SqlStateChange,
    NetworkEgress,
    ProcessSpawn,
    MemorySafetyViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlRelation {
    BenignMustSucceed,
    FreshChallengeMustMatch,
    ReferenceBehaviorMustMatch,
    ProjectTestsMustPass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadPreparedTree,
    WriteEphemeralTemp,
    SpawnBoundedProcess,
    LoopbackNetwork,
    ExternalNetwork,
    NativeSyscalls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRef {
    pub file: String,
    pub line: Option<u32>,
    pub symbol: Option<String>,
    pub language: Language,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectSpec {
    pub id: String,
    pub kind: EffectKind,
    pub nonce_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSpec {
    pub id: String,
    pub relation: ControlRelation,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingManifest {
    pub finding_id: String,
    pub source_sha256: String,
    pub target_file_sha256: String,
    pub target_plan_sha256: String,
    pub harness_sha256: String,
    pub policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationIr {
    pub schema: String,
    pub subject: SubjectRef,
    pub effect: EffectSpec,
    pub controls: Vec<ControlSpec>,
    pub capabilities: Vec<Capability>,
    pub binding: BindingManifest,
}

impl VerificationIr {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != VERIFICATION_IR_SCHEMA {
            return Err(ContractError::WrongSchema);
        }
        SafeRepoPath::parse(&self.subject.file).map_err(|_| ContractError::UnsafeSubjectPath)?;
        if self.subject.line == Some(0)
            || self
                .subject
                .symbol
                .as_deref()
                .is_some_and(|value| !valid_id(value))
            || !valid_id(&self.effect.id)
            || !valid_id(&self.binding.finding_id)
            || !valid_id(&self.binding.policy_version)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if [
            &self.binding.source_sha256,
            &self.binding.target_file_sha256,
            &self.binding.target_plan_sha256,
            &self.binding.harness_sha256,
        ]
        .iter()
        .any(|value| !is_sha256(value))
        {
            return Err(ContractError::InvalidDigest);
        }
        if self.controls.is_empty() || self.controls.len() > MAX_CONTROLS {
            return Err(ContractError::TooManyControls);
        }
        let mut ids = HashSet::new();
        if self
            .controls
            .iter()
            .any(|control| !valid_id(&control.id) || !ids.insert(control.id.as_str()))
        {
            return Err(ContractError::DuplicateControl);
        }
        if self.capabilities.is_empty() || self.capabilities.len() > MAX_CAPABILITIES {
            return Err(ContractError::TooManyCapabilities);
        }
        let mut capabilities = HashSet::new();
        if self
            .capabilities
            .iter()
            .any(|capability| !capabilities.insert(*capability))
        {
            return Err(ContractError::DuplicateCapability);
        }
        Ok(())
    }

    pub fn identity_sha256(&self) -> Result<String, ContractError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| ContractError::InvalidIdentifier)?;
        Ok(sha256_hex(&encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Docker,
    Wasm,
    Gvisor,
    Microvm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendIdentity {
    pub kind: BackendKind,
    pub immutable_identity: String,
    pub platform: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    Confirmed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperSignal {
    VerdictChannelForgery,
    StaleChallenge,
    PolicyLowering,
    SourceIdentityDrift,
    StateLeak,
    PathRace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayGrade {
    Exact,
    DeterministicComponent,
    Semantic,
    Unsupported,
    Diverged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlObservation {
    pub id: String,
    pub passed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvelope {
    pub schema: String,
    pub verification_ir_sha256: String,
    pub backend: BackendIdentity,
    pub challenge_commitment: String,
    pub capture_complete: bool,
    pub cleanup: CleanupState,
    pub tampering: Vec<TamperSignal>,
    pub effect_observed: Option<bool>,
    pub controls: Vec<ControlObservation>,
    pub exit_code: Option<i64>,
    pub transcript_sha256: Option<String>,
    pub replay_grade: ReplayGrade,
}

impl ExecutionEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != EXECUTION_ENVELOPE_SCHEMA {
            return Err(ContractError::WrongSchema);
        }
        if !is_sha256(&self.verification_ir_sha256)
            || !is_sha256(&self.challenge_commitment)
            || self
                .transcript_sha256
                .as_deref()
                .is_some_and(|v| !is_sha256(v))
        {
            return Err(ContractError::InvalidDigest);
        }
        if !self
            .backend
            .immutable_identity
            .strip_prefix("sha256:")
            .is_some_and(is_sha256)
        {
            return Err(ContractError::InvalidBackendIdentity);
        }
        if self.backend.platform.is_empty()
            || self.backend.platform.len() > MAX_PLATFORM_BYTES
            || self.backend.platform.chars().any(char::is_control)
        {
            return Err(ContractError::InvalidPlatform);
        }
        if self.controls.len() > MAX_CONTROLS {
            return Err(ContractError::TooManyControls);
        }
        let mut ids = HashSet::new();
        if self
            .controls
            .iter()
            .any(|control| !valid_id(&control.id) || !ids.insert(control.id.as_str()))
        {
            return Err(ContractError::DuplicateControl);
        }
        let mut signals = HashSet::new();
        if self.tampering.iter().any(|signal| !signals.insert(*signal)) {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedVerdict {
    EffectObserved,
    EffectAbsent,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    BindingMismatch,
    CaptureIncomplete,
    CleanupUnconfirmed,
    TamperingSuspected,
    ExecutionFailed,
    EffectUnknown,
    ControlMissing,
    ControlFailed,
    ReplayUnsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictDecision {
    pub verdict: DerivedVerdict,
    pub failures: Vec<FailureClass>,
}

pub fn derive_verdict(
    ir: &VerificationIr,
    envelope: &ExecutionEnvelope,
) -> Result<VerdictDecision, ContractError> {
    ir.validate()?;
    envelope.validate()?;
    if envelope.verification_ir_sha256 != ir.identity_sha256()? {
        return Err(ContractError::BindingMismatch);
    }
    let mut failures = Vec::new();
    if !envelope.capture_complete {
        failures.push(FailureClass::CaptureIncomplete);
    }
    if envelope.cleanup != CleanupState::Confirmed {
        failures.push(FailureClass::CleanupUnconfirmed);
    }
    if !envelope.tampering.is_empty() {
        failures.push(FailureClass::TamperingSuspected);
    }
    if envelope.exit_code != Some(0) {
        failures.push(FailureClass::ExecutionFailed);
    }
    if matches!(
        envelope.replay_grade,
        ReplayGrade::Unsupported | ReplayGrade::Diverged
    ) {
        failures.push(FailureClass::ReplayUnsupported);
    }
    if envelope.effect_observed.is_none() {
        failures.push(FailureClass::EffectUnknown);
    }
    for required in ir.controls.iter().filter(|control| control.required) {
        match envelope.controls.iter().find(|seen| seen.id == required.id) {
            None | Some(ControlObservation { passed: None, .. }) => {
                failures.push(FailureClass::ControlMissing)
            }
            Some(ControlObservation {
                passed: Some(false),
                ..
            }) => failures.push(FailureClass::ControlFailed),
            Some(ControlObservation {
                passed: Some(true), ..
            }) => {}
        }
    }
    failures.sort_by_key(|value| *value as u8);
    failures.dedup();
    let verdict = if failures.is_empty() {
        match envelope.effect_observed {
            Some(true) => DerivedVerdict::EffectObserved,
            Some(false) => DerivedVerdict::EffectAbsent,
            None => DerivedVerdict::Inconclusive,
        }
    } else {
        DerivedVerdict::Inconclusive
    };
    Ok(VerdictDecision { verdict, failures })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationSplit {
    Train,
    Development,
    SealedHoldout,
    Prospective,
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataRights {
    ServiceOnly,
    AggregateEvaluation,
    DeidentifiedLearning,
    Publishable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCase {
    pub schema: String,
    pub case_id: String,
    pub content_sha256: String,
    pub declared_split: EvaluationSplit,
    pub rights: DataRights,
    pub parents: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPurpose {
    Development,
    Evaluation,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseAccess {
    pub case_id: String,
    pub purpose: AccessPurpose,
    pub actor: String,
}

impl EvaluationCase {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != EVALUATION_CASE_SCHEMA {
            return Err(ContractError::WrongSchema);
        }
        if !valid_id(&self.case_id) || !is_sha256(&self.content_sha256) || self.parents.len() > 64 {
            return Err(ContractError::InvalidCase);
        }
        let mut parents = HashSet::new();
        if self.parents.iter().any(|parent| {
            !valid_id(parent) || parent == &self.case_id || !parents.insert(parent.as_str())
        }) {
            return Err(ContractError::InvalidCase);
        }
        Ok(())
    }

    pub fn effective_split(
        &self,
        accesses: &[CaseAccess],
    ) -> Result<EvaluationSplit, ContractError> {
        self.validate()?;
        for access in accesses
            .iter()
            .filter(|access| access.case_id == self.case_id)
        {
            if !valid_id(&access.actor) {
                return Err(ContractError::InvalidAccess);
            }
            if access.purpose == AccessPurpose::Development {
                return Ok(EvaluationSplit::Development);
            }
        }
        Ok(self.declared_split)
    }

    pub fn was_compromised(&self, accesses: &[CaseAccess]) -> Result<bool, ContractError> {
        Ok(matches!(
            self.declared_split,
            EvaluationSplit::SealedHoldout | EvaluationSplit::Prospective
        ) && self.effective_split(accesses)? == EvaluationSplit::Development)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterexampleKind {
    FalseProof,
    BenignBreak,
    Tampering,
    BindingDrift,
    CaptureFailure,
    CleanupFailure,
    ReplayDivergence,
    UnsupportedContext,
}

/// Content-addressed regression metadata. Payload bytes remain in the
/// authorized artifact store identified by the two content digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterexampleCell {
    pub schema: String,
    pub cell_id: String,
    pub verification_ir_sha256: String,
    pub triggering_event_sha256: String,
    pub kind: CounterexampleKind,
    pub original_content_sha256: String,
    pub minimized_content_sha256: String,
    /// Content identities of the complete verification events used to prove
    /// that the minimized counterexample reproduces under fresh challenges.
    pub replay_event_sha256: Vec<String>,
    pub replay_grade: ReplayGrade,
    pub split: EvaluationSplit,
    pub rights: DataRights,
    pub parents: Vec<String>,
}

impl CounterexampleCell {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != COUNTEREXAMPLE_CELL_SCHEMA {
            return Err(ContractError::WrongSchema);
        }
        if !valid_id(&self.cell_id)
            || [
                &self.verification_ir_sha256,
                &self.triggering_event_sha256,
                &self.original_content_sha256,
                &self.minimized_content_sha256,
            ]
            .iter()
            .any(|value| !is_sha256(value))
            || !(2..=10_000).contains(&self.replay_event_sha256.len())
            || self.replay_grade == ReplayGrade::Unsupported
            || self.parents.len() > 64
        {
            return Err(ContractError::InvalidCase);
        }
        let mut replay_events = HashSet::new();
        if self
            .replay_event_sha256
            .iter()
            .any(|event| !is_sha256(event) || !replay_events.insert(event.as_str()))
            || !replay_events.contains(self.triggering_event_sha256.as_str())
        {
            return Err(ContractError::InvalidCase);
        }
        let mut parents = HashSet::new();
        if self
            .parents
            .iter()
            .any(|parent| !valid_id(parent) || !parents.insert(parent.as_str()))
        {
            return Err(ContractError::InvalidCase);
        }
        Ok(())
    }

    pub fn identity_sha256(&self) -> Result<String, ContractError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| ContractError::InvalidCase)?;
        Ok(sha256_hex(&encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportOutcome {
    Supported,
    Unsupported,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayOutcome {
    NotAttempted,
    Equivalent,
    Diverged,
    Inconclusive,
}

/// One preregistered effect × language × framework measurement. Unsupported
/// and inconclusive samples are first-class rows, so dashboards cannot erase
/// them from denominators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineeringMeasurement {
    pub schema: String,
    pub measurement_id: String,
    pub cohort: String,
    pub project: String,
    pub effect: String,
    pub language: Language,
    pub framework: String,
    pub verifier_engineering_minutes: u64,
    pub manual_trusted_loc: u64,
    pub support: SupportOutcome,
    pub prospective: bool,
    pub false_proof: bool,
    pub replay: ReplayOutcome,
    pub tamper_attempt: bool,
    pub positive_forgery: bool,
    pub state_leak: bool,
    pub cleanup_residue: bool,
    pub build_ms: u64,
    pub execution_ms: u64,
    pub capture_ms: u64,
    pub cleanup_ms: u64,
    pub human_minutes: u64,
    pub direct_cost_microunits: u64,
    pub currency: String,
}

impl EngineeringMeasurement {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != ENGINEERING_MEASUREMENT_SCHEMA {
            return Err(ContractError::WrongSchema);
        }
        if [
            self.measurement_id.as_str(),
            self.cohort.as_str(),
            self.project.as_str(),
            self.effect.as_str(),
            self.framework.as_str(),
        ]
        .iter()
        .any(|value| !valid_id(value))
            || self.currency.len() != 3
            || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
            || (self.false_proof && !self.prospective)
            || (self.positive_forgery && !self.tamper_attempt)
            || ((self.state_leak || self.cleanup_residue) && !self.tamper_attempt)
            || (self.replay == ReplayOutcome::Equivalent
                && self.support != SupportOutcome::Supported)
        {
            return Err(ContractError::InvalidCase);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayComparison {
    Equivalent,
    Inconclusive,
    Diverged,
}

pub fn compare_replay(
    ir: &VerificationIr,
    first: &ExecutionEnvelope,
    second: &ExecutionEnvelope,
) -> Result<ReplayComparison, ContractError> {
    let expected = ir.identity_sha256()?;
    first.validate()?;
    second.validate()?;
    if first.verification_ir_sha256 != expected || second.verification_ir_sha256 != expected {
        return Err(ContractError::BindingMismatch);
    }
    let first_decision = derive_verdict(ir, first)?;
    let second_decision = derive_verdict(ir, second)?;
    if first_decision.verdict == DerivedVerdict::Inconclusive
        || second_decision.verdict == DerivedVerdict::Inconclusive
    {
        return Ok(ReplayComparison::Inconclusive);
    }
    if first_decision == second_decision
        && first.effect_observed == second.effect_observed
        && first.controls == second.controls
    {
        Ok(ReplayComparison::Equivalent)
    } else {
        Ok(ReplayComparison::Diverged)
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to a String is infallible");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn sample_ir() -> VerificationIr {
        VerificationIr {
            schema: VERIFICATION_IR_SCHEMA.into(),
            subject: SubjectRef {
                file: "src/app.py".into(),
                line: Some(7),
                symbol: Some("read_file".into()),
                language: Language::Python,
            },
            effect: EffectSpec {
                id: "path_read_outside_root".into(),
                kind: EffectKind::FileReadOutsideRoot,
                nonce_required: true,
            },
            controls: vec![ControlSpec {
                id: "benign_path_is_readable".into(),
                relation: ControlRelation::BenignMustSucceed,
                required: true,
            }],
            capabilities: vec![Capability::ReadPreparedTree, Capability::WriteEphemeralTemp],
            binding: BindingManifest {
                finding_id: "finding-1".into(),
                source_sha256: hash('a'),
                target_file_sha256: hash('b'),
                target_plan_sha256: hash('c'),
                harness_sha256: hash('d'),
                policy_version: "verification-policy-v1".into(),
            },
        }
    }

    fn sample_envelope() -> ExecutionEnvelope {
        let ir = sample_ir();
        ExecutionEnvelope {
            schema: EXECUTION_ENVELOPE_SCHEMA.into(),
            verification_ir_sha256: ir.identity_sha256().unwrap(),
            backend: BackendIdentity {
                kind: BackendKind::Docker,
                immutable_identity: format!("sha256:{}", hash('e')),
                platform: "linux/arm64".into(),
            },
            challenge_commitment: hash('f'),
            capture_complete: true,
            cleanup: CleanupState::Confirmed,
            tampering: Vec::new(),
            effect_observed: Some(true),
            controls: vec![ControlObservation {
                id: "benign_path_is_readable".into(),
                passed: Some(true),
            }],
            exit_code: Some(0),
            transcript_sha256: Some(hash('1')),
            replay_grade: ReplayGrade::Exact,
        }
    }

    #[test]
    fn valid_ir_round_trips_and_has_stable_identity() {
        let ir = sample_ir();
        ir.validate().unwrap();
        let encoded = serde_json::to_string(&ir).unwrap();
        let decoded: VerificationIr = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, ir);
        assert_eq!(decoded.identity_sha256(), ir.identity_sha256());
        assert_eq!(ir.identity_sha256().unwrap().len(), 64);
    }

    #[test]
    fn ir_rejects_unsafe_paths_bad_hashes_and_duplicate_controls() {
        let mut ir = sample_ir();
        ir.subject.file = "../secret".into();
        assert_eq!(ir.validate(), Err(ContractError::UnsafeSubjectPath));

        let mut ir = sample_ir();
        ir.binding.source_sha256 = "ABC".into();
        assert_eq!(ir.validate(), Err(ContractError::InvalidDigest));

        let mut ir = sample_ir();
        ir.controls.push(ir.controls[0].clone());
        assert_eq!(ir.validate(), Err(ContractError::DuplicateControl));
    }

    #[test]
    fn verdict_is_fail_closed_on_capture_cleanup_tamper_or_missing_control() {
        let ir = sample_ir();
        let ok = sample_envelope();
        assert_eq!(
            derive_verdict(&ir, &ok).unwrap().verdict,
            DerivedVerdict::EffectObserved
        );

        let mut broken = ok.clone();
        broken.capture_complete = false;
        assert_eq!(
            derive_verdict(&ir, &broken).unwrap().verdict,
            DerivedVerdict::Inconclusive
        );

        let mut broken = ok.clone();
        broken.cleanup = CleanupState::Unknown;
        assert_eq!(
            derive_verdict(&ir, &broken).unwrap().verdict,
            DerivedVerdict::Inconclusive
        );

        let mut broken = ok.clone();
        broken.tampering.push(TamperSignal::VerdictChannelForgery);
        assert_eq!(
            derive_verdict(&ir, &broken).unwrap().verdict,
            DerivedVerdict::Inconclusive
        );

        let mut broken = ok;
        broken.controls.clear();
        assert_eq!(
            derive_verdict(&ir, &broken).unwrap().verdict,
            DerivedVerdict::Inconclusive
        );
    }

    #[test]
    fn effective_split_never_treats_development_seen_case_as_hidden_again() {
        let case = EvaluationCase {
            schema: EVALUATION_CASE_SCHEMA.into(),
            case_id: "case-1".into(),
            content_sha256: hash('9'),
            declared_split: EvaluationSplit::SealedHoldout,
            rights: DataRights::ServiceOnly,
            parents: Vec::new(),
        };
        let access = vec![CaseAccess {
            case_id: "case-1".into(),
            purpose: AccessPurpose::Development,
            actor: "verifier-builder".into(),
        }];
        assert_eq!(
            case.effective_split(&access).unwrap(),
            EvaluationSplit::Development
        );
        assert!(case.was_compromised(&access).unwrap());
    }

    #[test]
    fn replay_comparison_refuses_identity_drift_and_compares_semantics() {
        let ir = sample_ir();
        let first = sample_envelope();
        let second = first.clone();
        assert_eq!(
            compare_replay(&ir, &first, &second).unwrap(),
            ReplayComparison::Equivalent
        );

        let mut drift = second.clone();
        drift.verification_ir_sha256 = hash('0');
        assert_eq!(
            compare_replay(&ir, &first, &drift),
            Err(ContractError::BindingMismatch)
        );

        let mut divergent = second;
        divergent.effect_observed = Some(false);
        assert_eq!(
            compare_replay(&ir, &first, &divergent).unwrap(),
            ReplayComparison::Diverged
        );

        let mut incomplete = first.clone();
        incomplete.cleanup = CleanupState::Unknown;
        assert_eq!(
            compare_replay(&ir, &incomplete, &incomplete).unwrap(),
            ReplayComparison::Inconclusive
        );
    }

    #[test]
    fn counterexample_cells_require_replayable_content_addressed_evidence() {
        let cell = CounterexampleCell {
            schema: COUNTEREXAMPLE_CELL_SCHEMA.into(),
            cell_id: "cell-1".into(),
            verification_ir_sha256: sample_ir().identity_sha256().unwrap(),
            triggering_event_sha256: hash('7'),
            kind: CounterexampleKind::FalseProof,
            original_content_sha256: hash('8'),
            minimized_content_sha256: hash('9'),
            replay_event_sha256: vec![hash('7'), hash('6'), hash('5')],
            replay_grade: ReplayGrade::Semantic,
            split: EvaluationSplit::Development,
            rights: DataRights::ServiceOnly,
            parents: vec!["parent-cell".into()],
        };
        cell.validate().unwrap();
        assert_eq!(cell.identity_sha256().unwrap().len(), 64);

        let mut unstable = cell.clone();
        unstable.replay_event_sha256.truncate(1);
        assert_eq!(unstable.validate(), Err(ContractError::InvalidCase));

        let mut duplicated = cell.clone();
        duplicated.replay_event_sha256[1] = duplicated.replay_event_sha256[0].clone();
        assert_eq!(duplicated.validate(), Err(ContractError::InvalidCase));

        let mut unsupported = cell;
        unsupported.replay_grade = ReplayGrade::Unsupported;
        assert_eq!(unsupported.validate(), Err(ContractError::InvalidCase));
    }

    #[test]
    fn engineering_measurements_keep_unknowns_in_the_denominator() {
        let sample = EngineeringMeasurement {
            schema: ENGINEERING_MEASUREMENT_SCHEMA.into(),
            measurement_id: "m-1".into(),
            cohort: "day-30".into(),
            project: "repo-a".into(),
            effect: "command_execution".into(),
            language: Language::Python,
            framework: "stdlib".into(),
            verifier_engineering_minutes: 90,
            manual_trusted_loc: 120,
            support: SupportOutcome::Inconclusive,
            prospective: true,
            false_proof: false,
            replay: ReplayOutcome::Inconclusive,
            tamper_attempt: true,
            positive_forgery: false,
            state_leak: false,
            cleanup_residue: false,
            build_ms: 10,
            execution_ms: 20,
            capture_ms: 30,
            cleanup_ms: 40,
            human_minutes: 5,
            direct_cost_microunits: 0,
            currency: "USD".into(),
        };
        sample.validate().unwrap();

        let mut impossible = sample.clone();
        impossible.positive_forgery = true;
        impossible.tamper_attempt = false;
        assert_eq!(impossible.validate(), Err(ContractError::InvalidCase));
    }
}
