//! Verification compiler, event derivation, counterexample minimization and
//! the local sealed-evaluation registry.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vettalon_contract::verification::{
    AccessPurpose, BackendIdentity, BackendKind, BindingManifest, COUNTEREXAMPLE_CELL_SCHEMA,
    Capability, CaseAccess, CleanupState, ControlObservation, ControlRelation, ControlSpec,
    CounterexampleCell, CounterexampleKind, DataRights, EXECUTION_ENVELOPE_SCHEMA, EffectKind,
    EffectSpec, EngineeringMeasurement, EvaluationCase, EvaluationSplit, ExecutionEnvelope,
    Language, ReplayGrade, ReplayOutcome, SubjectRef, SupportOutcome, TamperSignal,
    VERIFICATION_IR_SCHEMA, VerdictDecision, VerificationIr, derive_verdict,
};

use super::schema::sha256_hex;

pub const VERIFICATION_EVENT_SCHEMA: &str = "vettalon.verification-event/1";
pub const ENGINEERING_SCORECARD_SCHEMA: &str = "vettalon.engineering-scorecard/1";
const MAX_EVENT_TEXT_BYTES: usize = 16 * 1024;
const MAX_REGISTRY_FILE_BYTES: u64 = 128 * 1024;
const MAX_REGISTRY_FILES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileInput {
    pub finding_id: String,
    pub file: String,
    pub line: Option<u32>,
    pub symbol: String,
    pub cwe: String,
    pub source_sha256: String,
    pub target_file_sha256: String,
    pub target_plan_sha256: String,
    pub harness_sha256: String,
}

pub fn compile_ir(input: &CompileInput) -> Result<VerificationIr, &'static str> {
    if !input.file.ends_with(".py") {
        return Err("unsupported_verification_language");
    }
    let (effect_id, effect_kind) = match input.cwe.as_str() {
        "CWE-77" | "CWE-78" => ("command_execution", EffectKind::CommandExecution),
        "CWE-22" | "CWE-73" => ("file_read_outside_root", EffectKind::FileReadOutsideRoot),
        "CWE-89" => ("sql_state_change", EffectKind::SqlStateChange),
        _ => return Err("unsupported_effect_spec"),
    };
    let ir = VerificationIr {
        schema: VERIFICATION_IR_SCHEMA.into(),
        subject: SubjectRef {
            file: input.file.clone(),
            line: input.line,
            symbol: Some(input.symbol.clone()),
            language: Language::Python,
        },
        effect: EffectSpec {
            id: effect_id.into(),
            kind: effect_kind,
            nonce_required: true,
        },
        controls: vec![
            ControlSpec {
                id: "benign_control".into(),
                relation: ControlRelation::BenignMustSucceed,
                required: true,
            },
            ControlSpec {
                id: "fresh_challenge_control".into(),
                relation: ControlRelation::FreshChallengeMustMatch,
                required: true,
            },
        ],
        capabilities: vec![
            Capability::ReadPreparedTree,
            Capability::WriteEphemeralTemp,
            Capability::SpawnBoundedProcess,
        ],
        binding: BindingManifest {
            finding_id: input.finding_id.clone(),
            source_sha256: input.source_sha256.clone(),
            target_file_sha256: input.target_file_sha256.clone(),
            target_plan_sha256: input.target_plan_sha256.clone(),
            harness_sha256: input.harness_sha256.clone(),
            policy_version: "verification-policy-v1".into(),
        },
    };
    ir.validate().map_err(|_| "invalid_verification_ir")?;
    Ok(ir)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostObservations {
    pub backend_kind: BackendKind,
    pub backend_identity: String,
    pub platform: String,
    pub challenge_commitment: String,
    pub capture_complete: bool,
    pub cleanup: CleanupState,
    pub tampering: Vec<TamperSignal>,
    pub effect_observed: Option<bool>,
    pub benign_control: Option<bool>,
    pub fresh_challenge_control: Option<bool>,
    pub exit_code: Option<i64>,
    pub transcript_sha256: Option<String>,
    pub replay_grade: ReplayGrade,
}

impl HostObservations {
    pub fn into_envelope(self, ir: &VerificationIr) -> Result<ExecutionEnvelope, &'static str> {
        let envelope = ExecutionEnvelope {
            schema: EXECUTION_ENVELOPE_SCHEMA.into(),
            verification_ir_sha256: ir
                .identity_sha256()
                .map_err(|_| "invalid_verification_ir")?,
            backend: BackendIdentity {
                kind: self.backend_kind,
                immutable_identity: self.backend_identity,
                platform: self.platform,
            },
            challenge_commitment: self.challenge_commitment,
            capture_complete: self.capture_complete,
            cleanup: self.cleanup,
            tampering: self.tampering,
            effect_observed: self.effect_observed,
            controls: vec![
                ControlObservation {
                    id: "benign_control".into(),
                    passed: self.benign_control,
                },
                ControlObservation {
                    id: "fresh_challenge_control".into(),
                    passed: self.fresh_challenge_control,
                },
            ],
            exit_code: self.exit_code,
            transcript_sha256: self.transcript_sha256,
            replay_grade: self.replay_grade,
        };
        envelope
            .validate()
            .map_err(|_| "invalid_execution_envelope")?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEvent {
    pub schema: String,
    pub ir: VerificationIr,
    pub envelope: ExecutionEnvelope,
    pub decision: VerdictDecision,
    /// Untrusted explanatory text. It never participates in `decision`.
    pub model_claim: Option<String>,
    /// Human disposition kept separately from execution facts.
    pub human_adjudication: Option<String>,
}

impl VerificationEvent {
    pub fn new(
        ir: VerificationIr,
        envelope: ExecutionEnvelope,
        model_claim: Option<String>,
        human_adjudication: Option<String>,
    ) -> Result<Self, &'static str> {
        if model_claim
            .as_deref()
            .is_some_and(|value| value.len() > MAX_EVENT_TEXT_BYTES)
            || human_adjudication
                .as_deref()
                .is_some_and(|value| value.len() > MAX_EVENT_TEXT_BYTES)
        {
            return Err("verification_event_text_too_large");
        }
        let decision =
            derive_verdict(&ir, &envelope).map_err(|_| "verification_event_binding_invalid")?;
        Ok(Self {
            schema: VERIFICATION_EVENT_SCHEMA.into(),
            ir,
            envelope,
            decision,
            model_claim,
            human_adjudication,
        })
    }

    pub fn from_host_observations(
        ir: VerificationIr,
        observations: HostObservations,
    ) -> Result<Self, &'static str> {
        let envelope = observations.into_envelope(&ir)?;
        Self::new(ir, envelope, None, None)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != VERIFICATION_EVENT_SCHEMA {
            return Err("invalid_verification_event_schema");
        }
        let derived = derive_verdict(&self.ir, &self.envelope)
            .map_err(|_| "verification_event_binding_invalid")?;
        if derived != self.decision {
            return Err("stored_verdict_mismatch");
        }
        if self
            .model_claim
            .as_deref()
            .is_some_and(|value| value.len() > MAX_EVENT_TEXT_BYTES)
            || self
                .human_adjudication
                .as_deref()
                .is_some_and(|value| value.len() > MAX_EVENT_TEXT_BYTES)
        {
            return Err("verification_event_text_too_large");
        }
        Ok(())
    }

    pub fn identity_sha256(&self) -> Result<String, &'static str> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(|encoded| sha256_hex(&encoded))
            .map_err(|_| "verification_event_encode_failed")
    }
}

/// Deterministic delta minimization. The predicate is the trusted, executable
/// failure oracle; model text never decides whether a candidate is retained.
pub fn minimize_counterexample<F>(input: &[u8], mut still_fails: F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> bool,
{
    if input.is_empty() || !still_fails(input) {
        return input.to_vec();
    }
    let mut current = input.to_vec();
    let mut partitions = 2usize;
    while current.len() >= 2 {
        let chunk = current.len().div_ceil(partitions);
        let mut reduced = false;
        for start in (0..current.len()).step_by(chunk) {
            let end = (start + chunk).min(current.len());
            let mut candidate = Vec::with_capacity(current.len() - (end - start));
            candidate.extend_from_slice(&current[..start]);
            candidate.extend_from_slice(&current[end..]);
            if !candidate.is_empty() && still_fails(&candidate) {
                current = candidate;
                partitions = partitions.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
        }
        if !reduced {
            if partitions >= current.len() {
                break;
            }
            partitions = (partitions * 2).min(current.len());
        }
    }
    current
}

#[allow(clippy::too_many_arguments)]
pub fn promote_counterexample(
    events: &[VerificationEvent],
    cell_id: &str,
    kind: CounterexampleKind,
    original_content_sha256: &str,
    minimized_content_sha256: &str,
    split: EvaluationSplit,
    rights: DataRights,
    parents: Vec<String>,
) -> Result<CounterexampleCell, &'static str> {
    if split != EvaluationSplit::Development {
        return Err("counterexample_split_not_development");
    }
    if !(2..=10_000).contains(&events.len()) {
        return Err("invalid_counterexample_cell");
    }
    let first = events.first().ok_or("invalid_counterexample_cell")?;
    first.validate()?;
    let ir_sha256 = first
        .ir
        .identity_sha256()
        .map_err(|_| "invalid_verification_ir")?;
    let mut challenges = HashSet::new();
    let mut replay_event_sha256 = Vec::with_capacity(events.len());
    let mut event_ids = HashSet::new();
    for event in events {
        event.validate()?;
        if event
            .ir
            .identity_sha256()
            .map_err(|_| "invalid_verification_ir")?
            != ir_sha256
            || event.decision != first.decision
            || event.envelope.effect_observed != first.envelope.effect_observed
            || event.envelope.controls != first.envelope.controls
            || event.envelope.replay_grade != first.envelope.replay_grade
            || !challenges.insert(event.envelope.challenge_commitment.as_str())
        {
            return Err("counterexample_replay_mismatch");
        }
        let event_id = event.identity_sha256()?;
        if !event_ids.insert(event_id.clone()) {
            return Err("counterexample_replay_mismatch");
        }
        replay_event_sha256.push(event_id);
    }
    let cell = CounterexampleCell {
        schema: COUNTEREXAMPLE_CELL_SCHEMA.into(),
        cell_id: cell_id.into(),
        verification_ir_sha256: ir_sha256,
        triggering_event_sha256: replay_event_sha256[0].clone(),
        kind,
        original_content_sha256: original_content_sha256.into(),
        minimized_content_sha256: minimized_content_sha256.into(),
        replay_event_sha256,
        replay_grade: first.envelope.replay_grade,
        split,
        rights,
        parents,
    };
    cell.validate().map_err(|_| "invalid_counterexample_cell")?;
    Ok(cell)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineeringScorecard {
    pub schema: String,
    pub roster_total: u64,
    pub supported: u64,
    pub unsupported: u64,
    pub inconclusive: u64,
    pub median_verifier_engineering_minutes: Option<u64>,
    pub median_manual_trusted_loc: Option<u64>,
    pub prospective_total: u64,
    pub prospective_false_proofs: u64,
    pub prospective_unsupported: u64,
    pub prospective_inconclusive: u64,
    pub replay_attempted: u64,
    pub replay_equivalent: u64,
    pub replay_diverged: u64,
    pub replay_inconclusive: u64,
    pub tamper_attempts: u64,
    pub positive_forgeries: u64,
    pub state_leaks: u64,
    pub cleanup_residues: u64,
    pub conclusive_proofs: u64,
    pub work_ms_per_conclusive_proof: Option<u64>,
    pub cost_microunits_per_conclusive_proof: Option<u64>,
    pub currency: Option<String>,
}

pub fn build_scorecard(
    measurements: &[EngineeringMeasurement],
) -> Result<EngineeringScorecard, &'static str> {
    if measurements.is_empty() {
        return Err("empty_engineering_measurements");
    }
    let mut measurement_ids = HashSet::new();
    for measurement in measurements {
        measurement
            .validate()
            .map_err(|_| "invalid_engineering_measurement")?;
        if !measurement_ids.insert(measurement.measurement_id.as_str()) {
            return Err("duplicate_engineering_measurement");
        }
    }
    let currency = measurements.first().map(|sample| sample.currency.clone());
    if measurements
        .iter()
        .any(|sample| Some(&sample.currency) != currency.as_ref())
    {
        return Err("mixed_measurement_currency");
    }

    let count = |predicate: &dyn Fn(&EngineeringMeasurement) -> bool| -> u64 {
        measurements
            .iter()
            .filter(|sample| predicate(sample))
            .count() as u64
    };
    let supported = count(&|sample| sample.support == SupportOutcome::Supported);
    let unsupported = count(&|sample| sample.support == SupportOutcome::Unsupported);
    let inconclusive = count(&|sample| sample.support == SupportOutcome::Inconclusive);
    let prospective_total = count(&|sample| sample.prospective);
    let conclusive_proofs = count(&|sample| {
        sample.support == SupportOutcome::Supported
            && sample.replay == ReplayOutcome::Equivalent
            && !sample.false_proof
            && !sample.positive_forgery
            && !sample.state_leak
            && !sample.cleanup_residue
    });
    let total_work_ms = measurements
        .iter()
        .try_fold(0u64, |sum, sample| {
            sum.checked_add(sample.build_ms)
                .and_then(|value| value.checked_add(sample.execution_ms))
                .and_then(|value| value.checked_add(sample.capture_ms))
                .and_then(|value| value.checked_add(sample.cleanup_ms))
                .and_then(|value| value.checked_add(sample.human_minutes.checked_mul(60_000)?))
        })
        .ok_or("measurement_totals_overflow")?;
    let total_cost = measurements
        .iter()
        .try_fold(0u64, |sum, sample| {
            sum.checked_add(sample.direct_cost_microunits)
        })
        .ok_or("measurement_totals_overflow")?;
    let divisor = (conclusive_proofs > 0).then_some(conclusive_proofs);

    Ok(EngineeringScorecard {
        schema: ENGINEERING_SCORECARD_SCHEMA.into(),
        roster_total: measurements.len() as u64,
        supported,
        unsupported,
        inconclusive,
        median_verifier_engineering_minutes: median(
            measurements
                .iter()
                .map(|sample| sample.verifier_engineering_minutes)
                .collect(),
        ),
        median_manual_trusted_loc: median(
            measurements
                .iter()
                .map(|sample| sample.manual_trusted_loc)
                .collect(),
        ),
        prospective_total,
        prospective_false_proofs: count(&|sample| sample.prospective && sample.false_proof),
        prospective_unsupported: count(&|sample| {
            sample.prospective && sample.support == SupportOutcome::Unsupported
        }),
        prospective_inconclusive: count(&|sample| {
            sample.prospective && sample.support == SupportOutcome::Inconclusive
        }),
        replay_attempted: count(&|sample| sample.replay != ReplayOutcome::NotAttempted),
        replay_equivalent: count(&|sample| sample.replay == ReplayOutcome::Equivalent),
        replay_diverged: count(&|sample| sample.replay == ReplayOutcome::Diverged),
        replay_inconclusive: count(&|sample| sample.replay == ReplayOutcome::Inconclusive),
        tamper_attempts: count(&|sample| sample.tamper_attempt),
        positive_forgeries: count(&|sample| sample.positive_forgery),
        state_leaks: count(&|sample| sample.state_leak),
        cleanup_residues: count(&|sample| sample.cleanup_residue),
        conclusive_proofs,
        work_ms_per_conclusive_proof: divisor.map(|value| total_work_ms / value),
        cost_microunits_per_conclusive_proof: divisor.map(|value| total_cost / value),
        currency,
    })
}

fn median(mut values: Vec<u64>) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[middle])
    } else {
        let lower = values[middle - 1];
        let upper = values[middle];
        Some(lower + (upper - lower) / 2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseAudit {
    pub case: EvaluationCase,
    pub effective_split: EvaluationSplit,
    pub compromised: bool,
    pub lineage_case_ids: Vec<String>,
    pub accesses: Vec<CaseAccess>,
}

#[derive(Debug, Clone)]
pub struct RegistryStore {
    root: PathBuf,
}

impl RegistryStore {
    pub fn open(root: &Path) -> Result<Self, &'static str> {
        let root = checked_registry_path(root)?;
        match std::fs::symlink_metadata(&root) {
            Ok(meta) if meta.file_type().is_symlink() => return Err("registry_root_symlink"),
            Ok(meta) if !meta.is_dir() => return Err("registry_root_not_directory"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder
                    .create(&root)
                    .map_err(|_| "registry_create_failed")?;
            }
            Err(_) => return Err("registry_inspect_failed"),
        }
        let canonical = std::fs::canonicalize(&root).map_err(|_| "registry_resolve_failed")?;
        for child in ["cases", "access", "counterexamples"] {
            let path = canonical.join(child);
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                    return Err("registry_child_invalid");
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(&path).map_err(|_| "registry_create_failed")?;
                }
                Err(_) => return Err("registry_inspect_failed"),
            }
        }
        Ok(Self { root: canonical })
    }

    pub fn add_case(&self, case: &EvaluationCase) -> Result<(), &'static str> {
        case.validate().map_err(|_| "invalid_evaluation_case")?;
        let existing_cases = self.load_cases()?;
        if let Some(existing) = existing_cases
            .iter()
            .find(|existing| existing.case_id == case.case_id)
        {
            return if existing == case {
                Ok(())
            } else {
                Err("registry_case_id_collision")
            };
        }
        if existing_cases
            .iter()
            .any(|existing| existing.content_sha256 == case.content_sha256)
        {
            return Err("registry_content_alias");
        }
        let known_ids: HashSet<_> = existing_cases
            .iter()
            .map(|existing| existing.case_id.as_str())
            .collect();
        if case
            .parents
            .iter()
            .any(|parent| !known_ids.contains(parent.as_str()))
        {
            return Err("registry_parent_not_found");
        }
        let bytes = serde_json::to_vec_pretty(case).map_err(|_| "registry_encode_failed")?;
        let name = format!("{}.json", sha256_hex(&bytes));
        write_once_or_match(&self.root.join("cases").join(name), &bytes)
    }

    pub fn add_counterexample(&self, cell: &CounterexampleCell) -> Result<(), &'static str> {
        cell.validate().map_err(|_| "invalid_counterexample_cell")?;
        if let Some(existing) = self
            .load_counterexamples()?
            .into_iter()
            .find(|existing| existing.cell_id == cell.cell_id)
        {
            return if existing == *cell {
                Ok(())
            } else {
                Err("registry_cell_id_collision")
            };
        }
        let bytes = serde_json::to_vec_pretty(cell).map_err(|_| "registry_encode_failed")?;
        let name = format!("{}.json", sha256_hex(&bytes));
        write_once_or_match(&self.root.join("counterexamples").join(name), &bytes)
    }

    pub fn record_access(
        &self,
        case_id: &str,
        purpose: AccessPurpose,
        actor: &str,
    ) -> Result<(), &'static str> {
        if self.find_case(case_id)?.is_none() {
            return Err("registry_case_not_found");
        }
        let access = CaseAccess {
            case_id: case_id.into(),
            purpose,
            actor: actor.into(),
        };
        // Let the contract validate the actor and case linkage before storage.
        let case = self.find_case(case_id)?.ok_or("registry_case_not_found")?;
        case.effective_split(std::slice::from_ref(&access))
            .map_err(|_| "invalid_case_access")?;
        let bytes = serde_json::to_vec_pretty(&access).map_err(|_| "registry_encode_failed")?;
        let name = format!("{}.json", sha256_hex(&bytes));
        write_once_or_match(&self.root.join("access").join(name), &bytes)
    }

    pub fn load_cases(&self) -> Result<Vec<EvaluationCase>, &'static str> {
        let mut cases: Vec<EvaluationCase> = load_json_dir(&self.root.join("cases"))?;
        for case in &cases {
            case.validate().map_err(|_| "invalid_evaluation_case")?;
        }
        cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
        if cases
            .windows(2)
            .any(|pair| pair[0].case_id == pair[1].case_id)
        {
            return Err("registry_case_id_collision");
        }
        let mut content_ids = HashSet::new();
        if cases
            .iter()
            .any(|case| !content_ids.insert(case.content_sha256.as_str()))
        {
            return Err("registry_content_alias");
        }
        let by_id: HashMap<_, _> = cases
            .iter()
            .map(|case| (case.case_id.as_str(), case))
            .collect();
        if cases.iter().any(|case| {
            case.parents
                .iter()
                .any(|parent| !by_id.contains_key(parent.as_str()))
        }) {
            return Err("registry_parent_not_found");
        }
        validate_case_lineage(&cases)?;
        Ok(cases)
    }

    pub fn load_accesses(&self) -> Result<Vec<CaseAccess>, &'static str> {
        let mut accesses: Vec<CaseAccess> = load_json_dir(&self.root.join("access"))?;
        accesses.sort_by(|a, b| {
            a.case_id
                .cmp(&b.case_id)
                .then_with(|| a.actor.cmp(&b.actor))
                .then_with(|| (a.purpose as u8).cmp(&(b.purpose as u8)))
        });
        Ok(accesses)
    }

    pub fn load_counterexamples(&self) -> Result<Vec<CounterexampleCell>, &'static str> {
        let mut cells: Vec<CounterexampleCell> = load_json_dir(&self.root.join("counterexamples"))?;
        for cell in &cells {
            cell.validate().map_err(|_| "invalid_counterexample_cell")?;
        }
        cells.sort_by(|a, b| a.cell_id.cmp(&b.cell_id));
        if cells
            .windows(2)
            .any(|pair| pair[0].cell_id == pair[1].cell_id)
        {
            return Err("registry_cell_id_collision");
        }
        Ok(cells)
    }

    pub fn audit_case(&self, case_id: &str) -> Result<CaseAudit, &'static str> {
        let cases = self.load_cases()?;
        let by_id: HashMap<_, _> = cases
            .iter()
            .map(|case| (case.case_id.as_str(), case))
            .collect();
        let case = by_id
            .get(case_id)
            .copied()
            .cloned()
            .ok_or("registry_case_not_found")?;
        let mut lineage_case_ids = Vec::new();
        collect_case_lineage(
            &case.case_id,
            &by_id,
            &mut HashSet::new(),
            &mut lineage_case_ids,
        )?;
        let lineage_set: HashSet<_> = lineage_case_ids.iter().map(String::as_str).collect();
        let accesses: Vec<_> = self
            .load_accesses()?
            .into_iter()
            .filter(|access| lineage_set.contains(access.case_id.as_str()))
            .collect();
        for lineage_case in lineage_case_ids
            .iter()
            .filter_map(|id| by_id.get(id.as_str()).copied())
        {
            lineage_case
                .effective_split(&accesses)
                .map_err(|_| "invalid_case_access")?;
        }
        let development_seen = lineage_case_ids
            .iter()
            .filter_map(|id| by_id.get(id.as_str()).copied())
            .any(|lineage_case| {
                matches!(
                    lineage_case.declared_split,
                    EvaluationSplit::Development | EvaluationSplit::Train
                )
            })
            || accesses
                .iter()
                .any(|access| access.purpose == AccessPurpose::Development);
        let effective_split = if development_seen {
            EvaluationSplit::Development
        } else {
            case.declared_split
        };
        let compromised = matches!(
            case.declared_split,
            EvaluationSplit::SealedHoldout | EvaluationSplit::Prospective
        ) && effective_split == EvaluationSplit::Development;
        Ok(CaseAudit {
            case,
            effective_split,
            compromised,
            lineage_case_ids,
            accesses,
        })
    }

    fn find_case(&self, case_id: &str) -> Result<Option<EvaluationCase>, &'static str> {
        Ok(self
            .load_cases()?
            .into_iter()
            .find(|case| case.case_id == case_id))
    }
}

fn validate_case_lineage(cases: &[EvaluationCase]) -> Result<(), &'static str> {
    let by_id: HashMap<_, _> = cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for case in cases {
        visit_case_lineage(&case.case_id, &by_id, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit_case_lineage(
    case_id: &str,
    by_id: &HashMap<&str, &EvaluationCase>,
    visiting: &mut HashSet<String>,
    visited: &mut HashSet<String>,
) -> Result<(), &'static str> {
    if visited.contains(case_id) {
        return Ok(());
    }
    if !visiting.insert(case_id.to_string()) {
        return Err("registry_lineage_cycle");
    }
    let case = by_id.get(case_id).ok_or("registry_parent_not_found")?;
    for parent in &case.parents {
        visit_case_lineage(parent, by_id, visiting, visited)?;
    }
    visiting.remove(case_id);
    visited.insert(case_id.to_string());
    Ok(())
}

fn collect_case_lineage(
    case_id: &str,
    by_id: &HashMap<&str, &EvaluationCase>,
    seen: &mut HashSet<String>,
    lineage: &mut Vec<String>,
) -> Result<(), &'static str> {
    if !seen.insert(case_id.to_string()) {
        return Ok(());
    }
    let case = by_id.get(case_id).ok_or("registry_parent_not_found")?;
    lineage.push(case_id.to_string());
    for parent in &case.parents {
        collect_case_lineage(parent, by_id, seen, lineage)?;
    }
    Ok(())
}

fn checked_registry_path(root: &Path) -> Result<PathBuf, &'static str> {
    use std::path::Component;

    if root.file_name().is_none()
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("registry_path_invalid");
    }
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "registry_resolve_failed")?
            .join(root)
    };
    let parent = absolute.parent().ok_or("registry_path_invalid")?;
    let mut cursor = Some(parent);
    while let Some(path) = cursor {
        let meta = std::fs::symlink_metadata(path).map_err(|_| "registry_parent_invalid")?;
        if meta.file_type().is_symlink() {
            #[cfg(target_os = "macos")]
            let system_alias = matches!(path.to_str(), Some("/var" | "/tmp" | "/etc"));
            #[cfg(not(target_os = "macos"))]
            let system_alias = false;
            if !system_alias {
                return Err("registry_parent_invalid");
            }
        } else if !meta.is_dir() {
            return Err("registry_parent_invalid");
        }
        cursor = path.parent().filter(|next| *next != path);
    }
    Ok(absolute)
}

fn write_once_or_match(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(bytes).map_err(|_| "registry_write_failed")?;
            file.sync_all().map_err(|_| "registry_sync_failed")?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_regular_capped(path)?;
            if existing == bytes {
                Ok(())
            } else {
                Err("registry_content_collision")
            }
        }
        Err(_) => Err("registry_create_failed"),
    }
}

fn read_regular_capped(path: &Path) -> Result<Vec<u8>, &'static str> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "registry_read_failed")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_REGISTRY_FILE_BYTES {
        return Err("registry_file_invalid");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| "registry_read_failed")?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    (&mut file)
        .take(MAX_REGISTRY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "registry_read_failed")?;
    if bytes.len() as u64 > MAX_REGISTRY_FILE_BYTES
        || file.metadata().map(|current| current.len()).ok() != Some(meta.len())
    {
        return Err("registry_file_changed");
    }
    Ok(bytes)
}

fn load_json_dir<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>, &'static str> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "registry_read_failed")?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("registry_child_invalid");
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|_| "registry_read_failed")? {
        let entry = entry.map_err(|_| "registry_read_failed")?;
        let entry_path = entry.path();
        if entry_path.extension().and_then(|value| value.to_str()) != Some("json") {
            return Err("registry_file_invalid");
        }
        files.push(entry_path);
        if files.len() > MAX_REGISTRY_FILES {
            return Err("registry_too_large");
        }
    }
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let bytes = read_regular_capped(&file)?;
            let expected_name = format!("{}.json", sha256_hex(&bytes));
            if file.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
                return Err("registry_content_address_mismatch");
            }
            serde_json::from_slice(&bytes).map_err(|_| "registry_parse_failed")
        })
        .collect()
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
