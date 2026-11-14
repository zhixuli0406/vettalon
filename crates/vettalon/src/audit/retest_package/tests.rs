use serde_json::{Value, json};

use super::inputs::{RawInput, RawInputs, ReportInput, check_inputs};
use super::record::{
    FixedCopy, InputRole, OriginalCopy, Record, blocker_label, fix_outcome_label, not_bound_label,
    reproduce_outcome_label, retest_status_label,
};
use super::token::*;
use super::{PackageInputs, PackageRefusal, build_record};
use crate::attest::predicate::extract;
use crate::attest::statement::{BUNDLE_MEDIA_TYPE_V03, DSSE_PAYLOAD_TYPE, build_statement};
use crate::audit::cbom_check::canonical_json;
use crate::audit::fix_check::{Blocker, FixCheck, FixCheckRun, FixOutcome};
use crate::audit::poc_oracle::{OracleClass, benign_input, fixture_inputs};
use crate::audit::retest::RetestStatus;
use crate::audit::schema::*;
use crate::audit::target_poc::{
    Runtime, TargetArgument, TargetCall, TargetPocOutcome, TargetPocReceipt, target_harness_sha256,
};
use crate::audit::variants::{variant_set, variant_set_for};
use crate::audit::verification_context::{
    HARNESS_VERSION, POLICY_VERSION, SOURCE_SCOPE, SnapshotDigest, SnapshotExclusions,
    VerificationContext,
};

const FILE: &str = "src/app.py";
const TITLE: &str = "command run";

fn old_hash() -> String {
    sha256_hex(b"old source")
}

fn new_hash() -> String {
    sha256_hex(b"new source")
}

// ---- fixtures ------------------------------------------------------------

/// One replay of the three-phase protocol. `functional` is the benign
/// control's `functional` (None for command injection, Some(true) for the
/// path and SQL classes).
fn replay_run(index: u32, outcome: &str, functional: Option<bool>) -> Value {
    let phases: Vec<Value> = ["target", "benign_control", "fresh_nonce_rerun"]
        .into_iter()
        .enumerate()
        .map(|(i, name)| {
            json!({
                "name": name, "nonce_commitment": "a".repeat(64),
                "effect": outcome == "effect_observed" && i != 1,
                "functional": if i == 1 { json!(functional) } else { Value::Null },
                "exit_code": 0, "transcript_sha256": sha256_hex(name.as_bytes()),
                "elapsed_ms": 1, "reason": null,
            })
        })
        .collect();
    json!({"index": index, "outcome": outcome, "reason": null, "phases": phases})
}

fn add_event(receipt: &mut Value, cwe: &str) {
    add_event_for_finding(receipt, cwe, "F-1");
}

fn add_event_for_finding(receipt: &mut Value, cwe: &str, finding_id: &str) {
    use crate::audit::verification::{
        CompileInput, HostObservations, VerificationEvent, compile_ir,
    };
    use vettalon_contract::verification::{BackendKind, CleanupState, ReplayGrade};
    let class = match cwe {
        "CWE-78" => OracleClass::CommandInjection,
        "CWE-22" => OracleClass::PathTraversal,
        "CWE-89" => OracleClass::Sqli,
        "CWE-918" => OracleClass::Ssrf,
        _ => panic!("unsupported test CWE"),
    };
    let runtime: Option<crate::audit::target_poc::NodeRuntime> =
        serde_json::from_value(receipt["runtime"].clone()).unwrap();
    let adapter = receipt["adapter_sha256"].as_str().unwrap();
    let harness = if runtime.is_some() {
        crate::audit::target_poc::node_harness_sha256(class, adapter)
    } else {
        target_harness_sha256(class, adapter)
    };
    let ir = compile_ir(&CompileInput {
        runtime: runtime.as_ref().map(|runtime| runtime.identity()),
        finding_id: finding_id.into(),
        file: receipt["target_file"].as_str().unwrap().into(),
        line: None,
        symbol: receipt["target_function"].as_str().unwrap().into(),
        cwe: cwe.into(),
        source_sha256: receipt["source_sha256"].as_str().unwrap().into(),
        target_file_sha256: receipt["target_file_sha256"].as_str().unwrap().into(),
        target_plan_sha256: receipt["target_plan_sha256"].as_str().unwrap().into(),
        harness_sha256: harness,
    })
    .unwrap();
    let event = VerificationEvent::from_host_observations(
        ir,
        HostObservations {
            backend_kind: BackendKind::Docker,
            backend_identity: format!("sha256:{}", "e".repeat(64)),
            platform: "linux/arm64".into(),
            challenge_commitment: "d".repeat(64),
            capture_complete: true,
            cleanup: CleanupState::Confirmed,
            tampering: vec![],
            effect_observed: (receipt["outcome"] != "inconclusive")
                .then_some(receipt["outcome"] == "effect_observed"),
            benign_control: Some(true),
            fresh_challenge_control: Some(true),
            exit_code: Some(0),
            transcript_sha256: None,
            replay_grade: ReplayGrade::Semantic,
        },
    )
    .unwrap();
    receipt["verification_event"] = serde_json::to_value(event).unwrap();
}

/// A Python v2 reproduce receipt without class binding.
fn bare_receipt(outcome: &str, file_sha: &str, functional: Option<bool>) -> Value {
    let runs: Vec<Value> = (0..2).map(|i| replay_run(i, outcome, functional)).collect();
    let observed = u32::from(outcome == "effect_observed") * 2;
    let absent = u32::from(outcome == "effect_absent") * 2;
    json!({
        "version": 2,
        "outcome": outcome,
        "phases": runs[0]["phases"].clone(),
        "target_file": FILE,
        "target_function": "run",
        "target_plan_sha256": null,
        "target_file_sha256": file_sha,
        "source_sha256": "1".repeat(64),
        "exclusions": null,
        "adapter_sha256": "2".repeat(64),
        "image_id": "vettalon-poc:test",
        "reason": null,
        "replays": {
            "requested": 2, "completed": 2, "observed": observed, "absent": absent,
            "inconclusive": 0, "runs": runs
        }
    })
}

/// Command-injection receipt whose class comes from its verification event.
fn event_receipt(outcome: &str, file_sha: &str) -> Value {
    let mut receipt = bare_receipt(outcome, file_sha, None);
    receipt["target_plan_sha256"] = json!("c".repeat(64));
    add_event(&mut receipt, "CWE-78");
    receipt
}

/// Path-traversal receipt whose class comes from its harness digest only.
fn digest_receipt(outcome: &str, file_sha: &str) -> Value {
    let mut receipt = bare_receipt(outcome, file_sha, Some(true));
    let adapter = receipt["adapter_sha256"].as_str().unwrap().to_string();
    receipt["harness_sha256"] = json!(target_harness_sha256(OracleClass::PathTraversal, &adapter));
    receipt
}

fn summary_for(statuses: &[&str]) -> Value {
    let mut summary = json!({
        "still_observed": 0, "not_observed": 0, "inconclusive": 0,
        "environment_unavailable": 0, "target_missing": 0,
        "not_reproducible_before": 0, "retest_cap_reached": 0
    });
    for status in statuses {
        summary[*status] = json!(summary[*status].as_u64().unwrap() + 1);
    }
    summary
}

/// A retest report with one `not_observed` result for `F-1`, rebound from
/// the old to the new file bytes.
fn retest_report(old_report_sha256: &str) -> Value {
    json!({
        "version": 1,
        "repo": "/tmp/repo",
        "old_report_sha256": old_report_sha256,
        "old_repo_commit": "a".repeat(40),
        "new_repo_commit": "b".repeat(40),
        "new_tree_clean": true,
        "replays": 2,
        "results": [{
            "finding_id": "F-1",
            "title": TITLE,
            "cwe": "CWE-78",
            "status": "not_observed",
            "reason": null,
            "old_file_sha256": old_hash(),
            "new_file_sha256": new_hash(),
            "rebound": true,
            "receipt": event_receipt("effect_absent", &new_hash())
        }],
        "summary": summary_for(&["not_observed"])
    })
}

fn fix_check_receipt(class: OracleClass, set_sha: Option<String>, stamp: bool) -> Value {
    let set = variant_set_for(class, Runtime::Python);
    let scoring = set.scoring_len() as u32;
    let decoding = (set.len() - set.scoring_len()) as u32;
    // The last decoding input showed no effect on the original copy.
    let not_applicable: Vec<String> = set
        .variants
        .iter()
        .filter(|v| v.requires_decoding)
        .skip(1)
        .map(|v| v.id.to_string())
        .collect();
    let applicable = decoding - not_applicable.len() as u32;
    let generator = set_sha.as_ref().map(|_| set.generator_version);
    let mut check: FixCheck = serde_json::from_value(json!({
        "original": "pass", "variants": "pass", "benign": "pass",
        "regression": "pass", "tests": "not_run",
        "inputs_blocked": scoring, "inputs_total": scoring,
        "decoding_blocked": applicable, "decoding_applicable": applicable,
        "decoding_total": decoding,
        "diff_sha256": sha256_hex(b"diff"), "reason": null,
        "variant_set_sha256": set_sha,
        "variant_generator_version": generator,
    }))
    .unwrap();
    if stamp {
        check.variant_set = Some(set.stamp(&[], &[], &not_applicable));
    }
    let hash = "a".repeat(64);
    let digest = SnapshotDigest {
        sha256: hash.clone(),
        files: 1,
        entries: 1,
        bytes: 1,
    };
    let binding = VerificationContext {
        runtime: None,
        version: 1,
        source_scope: SOURCE_SCOPE.into(),
        check_sha256: sha256_hex(check.to_detail().as_bytes()),
        diff_sha256: check.diff_sha256.clone(),
        target_file: FILE.into(),
        target_file_sha256: old_hash(),
        finding_file_sha256: Some(old_hash()),
        original: digest.clone(),
        fixed: digest,
        exclusions: SnapshotExclusions::default(),
        adapter_sha256: hash.clone(),
        fixed_adapter_sha256: hash.clone(),
        target_plan_sha256: None,
        test_command_sha256: None,
        image_identity: Some(format!("sha256:{hash}")),
        harness_sha256: hash,
        harness_version: HARNESS_VERSION.into(),
        policy_version: POLICY_VERSION.into(),
    };
    serde_json::to_value(FixCheckRun {
        runtime: None,
        reach_summary: None,
        check,
        note: None,
        binding: Some(binding),
    })
    .unwrap()
}

fn current_fix_check(class: OracleClass) -> Value {
    let sha = variant_set_for(class, Runtime::Python).sha256();
    fix_check_receipt(class, Some(sha), true)
}

fn finding(id: &str, cwe: &str, file_hash: &str) -> Finding {
    let mut finding = Finding::candidate(
        "ai_audit",
        FindingKind::Other,
        Severity::High,
        TITLE,
        FILE,
        Some(3),
        "os.system(...)",
        "ai-audit/command-injection",
        vec![],
    );
    finding.id = id.into();
    finding.status = FindingStatus::NeedsHuman;
    finding.cwe = Some(cwe.into());
    finding.file_hash = Some(file_hash.into());
    finding
}

fn report(findings: Vec<Finding>) -> ReportInput {
    let report = AuditReport {
        repo_commit: Some("a".repeat(40)),
        repo_tree_clean: Some(true),
        since_last: None,
        attack_classes: None,
        schema_version: CURRENT_SCHEMA_VERSION,
        scope: None,
        repo: "/tmp/repo".into(),
        started_at: "2026-11-01T00:00:00Z".into(),
        profile: ScanProfile {
            mode: ProfileMode::Deep,
            intake: None,
        },
        engines_run: vec![],
        engines_missing: vec![],
        summary: Summary::from_findings(&[], 0, 0, GatePolicy::default(), &[]),
        findings,
        run_status: vettalon_contract::coverage::RunStatus::Complete,
        incomplete_reason: None,
        coverage: vec![],
        prior_run: None,
        verifier: Default::default(),
        ensemble: Default::default(),
    };
    ReportInput {
        name: "scan.json".into(),
        raw: serde_json::to_vec(&report).unwrap(),
        report,
    }
}

fn default_report() -> ReportInput {
    report(vec![finding("F-1", "CWE-78", &old_hash())])
}

fn raw(name: &str, value: &Value) -> RawInput {
    RawInput {
        name: name.into(),
        raw: value.to_string(),
    }
}

/// Report, retest, reproduce and fix check that all bind to `F-1`.
fn full_inputs() -> RawInputs {
    let report = default_report();
    let report_sha = sha256_hex(&report.raw);
    RawInputs {
        retest: Some(raw("retest.json", &retest_report(&report_sha))),
        reproduce: vec![raw(
            "reproduce.json",
            &event_receipt("effect_observed", &old_hash()),
        )],
        fix_check: vec![raw(
            "fix.json",
            &current_fix_check(OracleClass::CommandInjection),
        )],
        report: Some(report),
        ..Default::default()
    }
}

fn refused(inputs: RawInputs) -> PackageRefusal {
    check_inputs(inputs).unwrap_err()
}

fn assert_token(inputs: RawInputs, token: &str) {
    let error = refused(inputs);
    assert_eq!(error.token, token, "{error}");
}

fn record_of(inputs: RawInputs) -> (PackageInputs, Record) {
    let accepted = check_inputs(inputs).unwrap();
    let record = build_record(&accepted).unwrap();
    (accepted, record)
}

fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The bundle layout cosign v3 writes, for the Statement Vettalon would sign.
fn bundle_for(receipt: &str) -> RawInput {
    let extracted = extract(receipt).unwrap();
    let statement = build_statement(
        "reproduce.json",
        receipt.as_bytes(),
        extracted.kind,
        &extracted.predicate,
    );
    let bundle = json!({
        "mediaType": BUNDLE_MEDIA_TYPE_V03,
        "verificationMaterial": {"publicKey": {"hint": "test"}},
        "dsseEnvelope": {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": b64(statement.to_string().as_bytes()),
            "signatures": [{"sig": "AAAA"}]
        }
    });
    raw("reproduce.json.sigstore.json", &bundle)
}

// ---- the happy path ------------------------------------------------------

#[test]
fn full_package_binds_every_receipt_to_the_report_finding() {
    let (accepted, record) = record_of(full_inputs());
    assert_eq!(accepted.row_ids(), ["F-1"]);
    let paths: Vec<&str> = accepted.sources.iter().map(|s| s.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "receipts/fix-check/fix.json",
            "receipts/reproduce/reproduce.json",
            "receipts/retest/retest.json",
        ]
    );
    let row = &record.findings[0];
    assert_eq!(row.id, "F-1");
    assert!(row.binding_note.is_none());
    assert_eq!(row.oracle_class, Some("command_injection"));
    assert_eq!(row.line, Some(3));
    assert_eq!(row.title.as_ref().unwrap().text, TITLE);
    assert_eq!(row.title.as_ref().unwrap().origin, "report_text");
    let original = row.original.as_ref().unwrap();
    assert_eq!(original.run.outcome, TargetPocOutcome::EffectObserved);
    assert_eq!(original.evidence.pointer, "");
    let retest = row.retest.as_ref().unwrap();
    assert_eq!(retest.status, RetestStatus::NotObserved);
    assert_eq!(
        retest.label.en,
        super::text::load_text()
            .unwrap()
            .get("en", "status.not_observed")
            .unwrap()
    );
    // Claim link: canonical hash of the embedded receipt object.
    let doc = &full_inputs().retest.unwrap().raw;
    let value: Value = serde_json::from_str(doc).unwrap();
    assert_eq!(retest.evidence.pointer, "/results/0/receipt");
    assert_eq!(
        retest.evidence.object_sha256,
        sha256_hex(
            canonical_json(&value["results"][0]["receipt"])
                .unwrap()
                .as_bytes()
        )
    );
    assert_eq!(retest.evidence.file_sha256, sha256_hex(doc.as_bytes()));
    assert_eq!(row.fix_checks.len(), 1);
    assert_eq!(
        record.revisions.old_report_sha256,
        record.revisions.report_sha256
    );
    assert!(!record.revisions.report_included);
    assert!(record.revisions.tree_warning.is_none());
    assert_eq!(record.summary.fix_outcomes.values().sum::<usize>(), 1);
}

#[test]
fn fields_the_receipts_do_not_record_stay_none() {
    let (_, record) = record_of(full_inputs());
    let row = &record.findings[0];
    let original = &row.original.as_ref().unwrap().run;
    assert!(original.started_at.is_none());
    assert!(original.producer_version.is_none());
    assert!(original.environment.sandbox_settings.is_none());
    // Reproduce receipts name the harness by digest only.
    assert!(original.environment.harness_version.is_none());
    assert!(record.revisions.retest_started_at.is_none());
    let fix = &row.fix_checks[0];
    assert!(fix.started_at.is_none());
    assert!(fix.producer_version.is_none());
    assert!(fix.test_command_sha256.is_none());
    // Scoring variants on the original copy are not recorded (Q5).
    let variant = row
        .inputs
        .items
        .iter()
        .find(|item| item.role == InputRole::Variant)
        .unwrap();
    assert_eq!(variant.original_copy, OriginalCopy::NotRecorded);
    // Without a plan only the recorded hash is shown.
    assert!(!row.call.supplied);
    assert!(row.call.note.is_some());
}

#[test]
fn record_is_deterministic() {
    let (_, first) = record_of(full_inputs());
    let (_, second) = record_of(full_inputs());
    assert_eq!(
        serde_json::to_vec_pretty(&first).unwrap(),
        serde_json::to_vec_pretty(&second).unwrap()
    );
}

// ---- class recovery and attack inputs ------------------------------------

#[test]
fn class_is_recovered_from_the_verification_event() {
    let receipt: TargetPocReceipt =
        serde_json::from_value(event_receipt("effect_observed", &old_hash())).unwrap();
    let (outcome, _, class) = receipt.validate_stored_with_class(None).unwrap();
    assert_eq!(outcome, TargetPocOutcome::EffectObserved);
    assert_eq!(class, Some(OracleClass::CommandInjection));
    // The stored-receipt validator keeps its old shape.
    assert_eq!(
        receipt.validate_stored(None).unwrap(),
        (TargetPocOutcome::EffectObserved, None)
    );
    // No report: the row is keyed by the target and inputs come from the class.
    let (_, record) = record_of(RawInputs {
        reproduce: vec![raw(
            "r.json",
            &event_receipt("effect_observed", &old_hash()),
        )],
        ..Default::default()
    });
    let row = &record.findings[0];
    assert_eq!(row.id, "src/app.py#run");
    assert_eq!(row.binding_note, Some(not_bound_label()));
    assert_eq!(row.oracle_class, Some("command_injection"));
    let base = &row.inputs.items[0];
    assert_eq!(base.role, InputRole::Base);
    assert_eq!(base.text, fixture_inputs(OracleClass::CommandInjection)[0]);
    assert_eq!(
        base.id,
        variant_set(OracleClass::CommandInjection).variants[0].id
    );
    assert_eq!(base.original_copy, OriginalCopy::Effect);
    let benign = row.inputs.items.last().unwrap();
    assert_eq!(benign.role, InputRole::Benign);
    assert_eq!(benign.text, benign_input(OracleClass::CommandInjection));
    assert_eq!(benign.original_copy, OriginalCopy::NoEffect);
    // Without a fix check no variant is listed.
    assert_eq!(row.inputs.items.len(), 2);
}

#[test]
fn class_is_recovered_from_the_harness_digest() {
    let value = digest_receipt("effect_absent", &old_hash());
    assert!(value.get("verification_event").is_none());
    let receipt: TargetPocReceipt = serde_json::from_value(value.clone()).unwrap();
    let (outcome, _, class) = receipt.validate_stored_with_class(None).unwrap();
    assert_eq!(outcome, TargetPocOutcome::EffectAbsent);
    assert_eq!(class, Some(OracleClass::PathTraversal));
    let (_, record) = record_of(RawInputs {
        reproduce: vec![raw("r.json", &value)],
        ..Default::default()
    });
    let row = &record.findings[0];
    assert_eq!(row.oracle_class, Some("path_traversal"));
    assert_eq!(
        row.inputs.items[0].text,
        fixture_inputs(OracleClass::PathTraversal)[0]
    );
    assert_eq!(row.inputs.items[0].original_copy, OriginalCopy::NoEffect);
}

#[test]
fn legacy_receipt_without_a_class_shows_inputs_as_not_determinable() {
    let mut value = bare_receipt("effect_absent", &old_hash(), None);
    value["adapter_sha256"] = Value::Null;
    let receipt: TargetPocReceipt = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(receipt.validate_stored_with_class(None).unwrap().2, None);
    let (_, record) = record_of(RawInputs {
        reproduce: vec![raw("r.json", &value)],
        ..Default::default()
    });
    let inputs = &record.findings[0].inputs;
    assert!(!inputs.determinable);
    assert!(inputs.items.is_empty());
    assert!(inputs.note.is_some());
    assert!(record.findings[0].oracle_class.is_none());
}

#[test]
fn an_expected_class_that_disagrees_with_the_receipt_is_refused() {
    // The finding says SQL injection; the receipt's event says command injection.
    let mut inputs = full_inputs();
    inputs.retest = None;
    inputs.fix_check.clear();
    inputs.report = Some(report(vec![finding("F-1", "CWE-89", &old_hash())]));
    // Identity binds, but the proven class conflicts with the finding.
    assert_token(inputs, ORACLE_CLASS_CONFLICT);
    let receipt: TargetPocReceipt =
        serde_json::from_value(event_receipt("effect_observed", &old_hash())).unwrap();
    assert!(
        receipt
            .validate_stored_with_class(Some(OracleClass::Sqli))
            .is_err()
    );
}

#[test]
fn fix_check_variant_set_is_found_by_its_sha256() {
    let (accepted, record) = record_of(RawInputs {
        fix_check: vec![raw(
            "fix.json",
            &current_fix_check(OracleClass::PathTraversal),
        )],
        ..Default::default()
    });
    assert_eq!(accepted.row_ids(), ["src/app.py"]);
    let row = &record.findings[0];
    assert_eq!(row.oracle_class, Some("path_traversal"));
    let set = variant_set_for(OracleClass::PathTraversal, Runtime::Python);
    let fix = &row.fix_checks[0];
    assert_eq!(
        fix.variant_set_sha256.as_deref(),
        Some(set.sha256().as_str())
    );
    let marks: Vec<(&str, FixedCopy)> =
        fix.per_input.iter().map(|m| (m.id, m.fixed_copy)).collect();
    assert_eq!(marks.len(), set.len());
    for (id, mark) in &marks {
        let expected = match *id {
            "path-pct-slash" => FixedCopy::NotApplicable,
            _ => FixedCopy::Blocked,
        };
        assert_eq!(*mark, expected, "{id}");
    }
    // Row inputs: base, the other scoring variants, decoding, benign; texts
    // straight from the set.
    let items = &row.inputs.items;
    assert_eq!(items.len(), set.len() + 1);
    for (item, variant) in items.iter().zip(set.variants) {
        assert_eq!(item.id, variant.id);
        assert_eq!(item.text, variant.input);
    }
    let decoding: Vec<_> = items
        .iter()
        .filter(|item| item.role == InputRole::Decoding)
        .collect();
    assert_eq!(decoding.len(), 2);
    assert_eq!(decoding[0].original_copy, OriginalCopy::Effect);
    assert_eq!(decoding[1].original_copy, OriginalCopy::NoEffect);
}

#[test]
fn fix_check_counts_that_do_not_cover_every_input_are_not_recorded() {
    let mut value = current_fix_check(OracleClass::CommandInjection);
    // Without the stamp the receipt has counts only, so no input is marked
    // blocked or not blocked.
    value["check"]
        .as_object_mut()
        .unwrap()
        .remove("variant_set");
    value.as_object_mut().unwrap().remove("variant_set");
    let (_, record) = record_of(RawInputs {
        fix_check: vec![raw("fix.json", &value)],
        ..Default::default()
    });
    let fix = &record.findings[0].fix_checks[0];
    assert!(
        fix.per_input
            .iter()
            .all(|mark| mark.fixed_copy == FixedCopy::NotRecorded)
    );
}

#[test]
fn fix_check_with_an_unknown_variant_set_is_refused() {
    let outdated = fix_check_receipt(OracleClass::Sqli, Some("9".repeat(64)), false);
    assert!(extract(&outdated.to_string()).is_ok());
    assert_token(
        RawInputs {
            fix_check: vec![raw("fix.json", &outdated)],
            ..Default::default()
        },
        VARIANT_SET_OUTDATED,
    );
    // The Node set's sha256 on a Python target.
    let node = variant_set_for(OracleClass::Sqli, Runtime::Node).sha256();
    let other_runtime = fix_check_receipt(OracleClass::Sqli, Some(node), false);
    assert!(extract(&other_runtime.to_string()).is_ok());
    assert_token(
        RawInputs {
            fix_check: vec![raw("fix.json", &other_runtime)],
            ..Default::default()
        },
        VARIANT_SET_INCONSISTENT,
    );
}

#[test]
fn fix_check_stamp_naming_unknown_ids_is_refused() {
    let mut value = current_fix_check(OracleClass::Sqli);
    value["variant_set"]["ids_not_blocked"] = json!(["sql-made-up"]);
    value["check"]["variant_set"]["ids_not_blocked"] = json!(["sql-made-up"]);
    // The stamp is outside the verdict grammar, so `attest::extract` accepts
    // it; the package refuses it.
    assert!(extract(&value.to_string()).is_ok());
    assert_token(
        RawInputs {
            fix_check: vec![raw("fix.json", &value)],
            ..Default::default()
        },
        VARIANT_SET_INCONSISTENT,
    );
}

#[test]
fn fix_check_without_a_binding_is_refused() {
    let mut value = current_fix_check(OracleClass::CommandInjection);
    value["binding"] = Value::Null;
    value["outcome"] = json!("fix_unverified");
    assert!(extract(&value.to_string()).is_ok());
    assert_token(
        RawInputs {
            fix_check: vec![raw("fix.json", &value)],
            ..Default::default()
        },
        RECEIPT_UNBOUND,
    );
}

// ---- package rules -------------------------------------------------------

#[test]
fn rule_1_retest_run_status_without_a_receipt_is_refused() {
    for status in ["not_observed", "still_observed"] {
        let mut inputs = full_inputs();
        let mut retest: Value = serde_json::from_str(&inputs.retest.unwrap().raw).unwrap();
        retest["results"][0]["status"] = json!(status);
        retest["results"][0]["receipt"] = Value::Null;
        retest["summary"] = summary_for(&[status]);
        inputs.retest = Some(raw("retest.json", &retest));
        assert_token(inputs, RETEST_RECEIPT_MISSING);
        // The signing path refuses the same file.
        assert!(
            extract(&retest.to_string())
                .unwrap_err()
                .contains("carries no receipt")
        );
    }
}

#[test]
fn rule_2_retest_hashes_must_match_receipt_and_report() {
    // New side: new_file_sha256 is not the receipt's target_file_sha256.
    let mut inputs = full_inputs();
    let mut retest: Value = serde_json::from_str(&inputs.retest.unwrap().raw).unwrap();
    retest["results"][0]["new_file_sha256"] = json!(sha256_hex(b"other"));
    inputs.retest = Some(raw("retest.json", &retest));
    assert_token(inputs, RETEST_FILE_HASH_MISMATCH);
    // Old side: old_file_sha256 is not the report finding's file_hash.
    let mut inputs = full_inputs();
    let mut retest: Value = serde_json::from_str(&inputs.retest.unwrap().raw).unwrap();
    retest["results"][0]["old_file_sha256"] = json!(sha256_hex(b"older"));
    inputs.retest = Some(raw("retest.json", &retest));
    assert_token(inputs, RETEST_FILE_HASH_MISMATCH);
    // A rebound flag that contradicts the hashes.
    let mut inputs = full_inputs();
    let mut retest: Value = serde_json::from_str(&inputs.retest.unwrap().raw).unwrap();
    retest["results"][0]["rebound"] = json!(false);
    inputs.retest = Some(raw("retest.json", &retest));
    assert_token(inputs, RETEST_FILE_HASH_MISMATCH);
    // A result for a finding the report does not have.
    let mut inputs = full_inputs();
    let mut retest: Value = serde_json::from_str(&inputs.retest.unwrap().raw).unwrap();
    retest["results"][0]["finding_id"] = json!("F-9");
    // Keep the receipt valid on its own so this tests report membership.
    let receipt = &mut retest["results"][0]["receipt"];
    add_event_for_finding(receipt, "CWE-78", "F-9");
    inputs.retest = Some(raw("retest.json", &retest));
    assert_token(inputs, RETEST_FINDING_UNKNOWN);
}

#[test]
fn rule_3_report_must_hash_to_old_report_sha256() {
    let mut inputs = full_inputs();
    let retest = retest_report(&sha256_hex(b"another report"));
    inputs.retest = Some(raw("retest.json", &retest));
    assert_token(inputs, REPORT_HASH_MISMATCH);
}

#[test]
fn rule_4_receipts_bind_to_exactly_one_report_finding() {
    // File hash differs from every finding.
    let mut inputs = full_inputs();
    inputs.retest = None;
    inputs.fix_check.clear();
    inputs.report = Some(report(vec![finding("F-1", "CWE-78", &sha256_hex(b"x"))]));
    assert_token(inputs, RECEIPT_UNBOUND);
    // Two findings in the same file version and class: ambiguous.
    let mut inputs = full_inputs();
    inputs.retest = None;
    inputs.reproduce.clear();
    inputs.report = Some(report(vec![
        finding("F-1", "CWE-78", &old_hash()),
        finding("F-2", "CWE-78", &old_hash()),
    ]));
    assert_token(inputs, RECEIPT_AMBIGUOUS);
    // The oracle class tells them apart.
    let mut inputs = full_inputs();
    inputs.retest = None;
    inputs.report = Some(report(vec![
        finding("F-1", "CWE-78", &old_hash()),
        finding("F-2", "CWE-22", &old_hash()),
    ]));
    let (accepted, _) = record_of(inputs);
    assert_eq!(accepted.row_ids(), ["F-1"]);
    // Two reproduce receipts for one finding.
    let mut inputs = full_inputs();
    let mut second = event_receipt("effect_observed", &old_hash());
    second["image_id"] = json!("vettalon-poc:other");
    inputs.reproduce.push(raw("reproduce-2.json", &second));
    assert_token(inputs, REPRODUCE_DUPLICATE_FOR_FINDING);
}

#[test]
fn rule_4_without_a_report_rows_are_labelled_unbound() {
    let (_, record) = record_of(RawInputs {
        reproduce: vec![raw(
            "r.json",
            &event_receipt("effect_observed", &old_hash()),
        )],
        fix_check: vec![raw(
            "f.json",
            &current_fix_check(OracleClass::CommandInjection),
        )],
        ..Default::default()
    });
    let ids: Vec<&str> = record.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["src/app.py", "src/app.py#run"]);
    for row in &record.findings {
        assert_eq!(row.binding_note, Some(not_bound_label()));
    }
}

#[test]
fn rule_5_bundles_must_match_an_included_receipt() {
    let receipt = event_receipt("effect_observed", &old_hash()).to_string();
    let base = || RawInputs {
        reproduce: vec![RawInput {
            name: "reproduce.json".into(),
            raw: receipt.clone(),
        }],
        ..Default::default()
    };
    // Matching bundle: accepted and placed under the receipt's name.
    let mut inputs = base();
    inputs.bundles = vec![bundle_for(&receipt)];
    let (accepted, record) = record_of(inputs);
    let signature = accepted
        .sources
        .iter()
        .find(|s| s.kind == super::SourceKind::Signature)
        .unwrap();
    assert_eq!(signature.path, "signatures/reproduce.json.sigstore.json");
    assert_eq!(
        signature.covers.as_deref(),
        Some("receipts/reproduce/reproduce.json")
    );
    let source = &record.sources[0];
    let sig = source.signature.as_ref().unwrap();
    assert!(sig.subject_ok);
    assert!(sig.cosign.is_none(), "content-matched, not verified");
    // A bundle for a receipt that is not in the package.
    let other = event_receipt("effect_absent", &old_hash()).to_string();
    let mut inputs = base();
    inputs.bundles = vec![bundle_for(&other)];
    assert_token(inputs, BUNDLE_UNMATCHED);
    // A bundle that does not decode.
    let mut inputs = base();
    inputs.bundles = vec![raw("b.sigstore.json", &json!({"hello": "world"}))];
    assert_token(inputs, BUNDLE_REFUSED);
    // Two bundles for one receipt.
    let mut inputs = base();
    inputs.bundles = vec![bundle_for(&receipt), bundle_for(&receipt)];
    assert_token(inputs, BUNDLE_DUPLICATE);
}

#[test]
fn rule_6_one_bad_input_refuses_the_whole_package() {
    let mut inputs = full_inputs();
    inputs
        .reproduce
        .push(raw("garbage.json", &json!({"not": "a receipt"})));
    assert_token(inputs, RECEIPT_REFUSED);
    // Given under the wrong flag.
    let mut inputs = full_inputs();
    inputs.reproduce = vec![raw(
        "reproduce.json",
        &current_fix_check(OracleClass::CommandInjection),
    )];
    inputs.fix_check.clear();
    assert_token(inputs, RECEIPT_KIND_MISMATCH);
}

#[test]
fn rule_7_report_text_is_sanitised_and_labelled() {
    let mut f = finding("F-1", "CWE-78", &old_hash());
    f.title = "run\u{202E}txt.exe\nnext".into();
    let mut inputs = full_inputs();
    inputs.retest = None;
    inputs.report = Some(report(vec![f]));
    let (_, record) = record_of(inputs);
    let title = record.findings[0].title.as_ref().unwrap();
    assert_eq!(title.origin, "report_text");
    assert!(!title.text.contains('\u{202E}'), "{}", title.text);
    assert!(!title.text.contains('\n'), "{}", title.text);
    assert!(title.text.contains("[U+202E]"), "{}", title.text);
    assert!(title.text.contains("[U+000A]"), "{}", title.text);
    let long = super::record::report_text(&"x".repeat(2000));
    assert!(long.truncated);
    assert_eq!(
        long.text.chars().count(),
        super::record::REPORT_TEXT_MAX_CHARS
    );
    assert!(long.full_sha256.is_some());
}

// ---- input limits and names ----------------------------------------------

#[test]
fn counts_names_and_duplicates_are_checked() {
    assert_token(RawInputs::default(), NO_RECEIPTS);
    let many: Vec<RawInput> = (0..=super::MAX_RECEIPTS)
        .map(|i| RawInput {
            name: format!("r{i}.json"),
            raw: "{}".into(),
        })
        .collect();
    assert_token(
        RawInputs {
            reproduce: many,
            ..Default::default()
        },
        INPUT_COUNT_EXCEEDED,
    );
    let receipt = event_receipt("effect_observed", &old_hash());
    for name in [
        "..",
        ".hidden.json",
        "-r.json",
        "a b.json",
        "a/b.json",
        "",
        "é.json",
    ] {
        assert_token(
            RawInputs {
                reproduce: vec![raw(name, &receipt)],
                ..Default::default()
            },
            NAME_INVALID,
        );
    }
    assert_token(
        RawInputs {
            reproduce: vec![raw(&format!("{}.json", "a".repeat(100)), &receipt)],
            ..Default::default()
        },
        NAME_INVALID,
    );
    // Names collide without case, bytes collide exactly.
    let other = event_receipt("effect_absent", &old_hash());
    assert_token(
        RawInputs {
            reproduce: vec![raw("R.json", &receipt), raw("r.json", &other)],
            ..Default::default()
        },
        NAME_DUPLICATE,
    );
    assert_token(
        RawInputs {
            reproduce: vec![raw("a.json", &receipt), raw("b.json", &receipt)],
            ..Default::default()
        },
        RECEIPT_DUPLICATE,
    );
}

#[test]
fn malformed_copied_fields_are_refused() {
    let mut receipt = event_receipt("effect_observed", &old_hash());
    receipt["image_id"] = json!("image with spaces");
    assert!(extract(&receipt.to_string()).is_ok());
    assert_token(
        RawInputs {
            reproduce: vec![raw("r.json", &receipt)],
            ..Default::default()
        },
        RECEIPT_FIELD_INVALID,
    );
    let mut inputs = full_inputs();
    let mut retest: Value = serde_json::from_str(&inputs.retest.unwrap().raw).unwrap();
    retest["new_repo_commit"] = json!("main");
    inputs.retest = Some(raw("retest.json", &retest));
    assert_token(inputs, REVISION_INVALID);
}

#[cfg(unix)]
#[test]
fn load_inputs_refuses_a_symlinked_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.json");
    std::fs::write(
        &real,
        event_receipt("effect_observed", &old_hash()).to_string(),
    )
    .unwrap();
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let error = super::load_inputs(&super::PackageRequest {
        reproduce: vec![link],
        ..Default::default()
    })
    .unwrap_err();
    assert_eq!(error.token, INPUT_UNREADABLE, "{error}");
    let accepted = super::load_inputs(&super::PackageRequest {
        reproduce: vec![real],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(accepted.row_ids(), ["src/app.py#run"]);
}

// ---- target plans --------------------------------------------------------

fn plan_call(function: &str) -> TargetCall {
    TargetCall {
        file: FILE.into(),
        function: function.into(),
        args: vec![
            TargetArgument::Payload,
            TargetArgument::Literal {
                value: json!("r\u{202E}w"),
            },
        ],
    }
}

fn plan_inputs(recorded: &TargetCall, supplied: Value) -> RawInputs {
    let mut receipt = event_receipt("effect_observed", &old_hash());
    receipt["target_plan_sha256"] = json!(sha256_hex(&serde_json::to_vec(recorded).unwrap()));
    add_event(&mut receipt, "CWE-78");
    RawInputs {
        reproduce: vec![raw("reproduce.json", &receipt)],
        report: Some(default_report()),
        targets: Some(raw("targets.json", &supplied)),
        ..Default::default()
    }
}

#[test]
fn target_plans_are_shown_only_when_their_hash_matches() {
    let call = plan_call("run");
    let (accepted, record) = record_of(plan_inputs(&call, json!({"F-1": call})));
    assert!(
        accepted
            .sources
            .iter()
            .any(|s| s.path == "receipts/plans/targets.json")
    );
    let shown = &record.findings[0].call;
    assert!(shown.supplied);
    assert_eq!(shown.args[0].kind, "payload");
    let literal = shown.args[1].value.as_deref().unwrap();
    assert!(!literal.contains('\u{202E}'), "{literal}");
    assert!(literal.contains("[U+202E]"), "{literal}");
    // A plan that is not the one the receipt ran.
    assert_token(
        plan_inputs(&call, json!({"F-1": plan_call("other")})),
        TARGET_PLAN_MISMATCH,
    );
    // A plan for a finding that is not in the package.
    assert_token(
        plan_inputs(&call, json!({"F-9": call})),
        TARGET_PLAN_UNMATCHED,
    );
    assert_token(
        plan_inputs(&call, json!(["not", "a", "map"])),
        TARGET_PLANS_REFUSED,
    );
}

// ---- wording -------------------------------------------------------------

const FORBIDDEN_EN: [&str; 3] = ["fixed", "secure", "remediated"];
const FORBIDDEN_ZH: [&str; 4] = ["已修補", "已修復", "修補完成", "安全無虞"];

fn assert_honest(text: &str) {
    let lower = text.to_lowercase();
    for word in FORBIDDEN_EN {
        assert!(!lower.contains(word), "{text:?} contains {word:?}");
    }
    for word in FORBIDDEN_ZH {
        assert!(!text.contains(word), "{text:?} contains {word:?}");
    }
}

/// Every `zh-TW` / `en` string under any label of the record.
fn collect_labels(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let (Some(Value::String(zh)), Some(Value::String(en))) =
                (map.get("zh-TW"), map.get("en"))
            {
                out.push(zh.clone());
                out.push(en.clone());
            }
            for item in map.values() {
                collect_labels(item, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_labels(item, out)),
        _ => {}
    }
}

#[test]
fn record_labels_never_say_fixed_or_secure() {
    let mut labels = Vec::new();
    for status in RetestStatus::ALL {
        labels.push(retest_status_label(status));
    }
    for outcome in [
        TargetPocOutcome::EffectObserved,
        TargetPocOutcome::EffectAbsent,
        TargetPocOutcome::Inconclusive,
    ] {
        labels.push(reproduce_outcome_label(outcome));
    }
    for outcome in [
        FixOutcome::FixVerified,
        FixOutcome::FixCheckPartial,
        FixOutcome::FixRejected,
        FixOutcome::FixUnverified,
    ] {
        labels.push(fix_outcome_label(outcome));
    }
    for blocker in [Blocker::Environment, Blocker::Harness, Blocker::None] {
        labels.extend(blocker_label(blocker));
    }
    labels.extend([
        super::record::not_bound_label(),
        super::record::inputs_not_determinable_label(),
        super::record::call_not_supplied_label(),
        super::record::tree_not_clean_label(),
    ]);
    for label in labels {
        assert_honest(label.zh_tw);
        assert_honest(label.en);
    }
    // And every label that ends up in a built record.
    let (_, record) = record_of(full_inputs());
    let mut found = Vec::new();
    collect_labels(&serde_json::to_value(&record).unwrap(), &mut found);
    assert!(!found.is_empty());
    for text in found {
        assert_honest(&text);
    }
}

#[test]
fn fix_labels_are_the_report_wording() {
    assert_eq!(
        fix_outcome_label(FixOutcome::FixVerified).en,
        "no effect observed at this revision, with these inputs and variants (regression check and project tests passed)"
    );
    for outcome in [
        FixOutcome::FixVerified,
        FixOutcome::FixCheckPartial,
        FixOutcome::FixRejected,
        FixOutcome::FixUnverified,
    ] {
        assert_eq!(fix_outcome_label(outcome).zh_tw, outcome.label_zh());
    }
}

#[test]
fn every_token_is_distinct() {
    let mut seen = std::collections::BTreeSet::new();
    for token in ALL {
        assert!(seen.insert(*token), "{token}");
    }
}

#[test]
fn engagement_finding_ids_come_from_package_rows() {
    use super::engagement::{parse_engagement, validate_finding_ids};
    let (inputs, _) = record_of(full_inputs());
    let known = inputs.row_ids().into_iter().map(str::to_owned).collect();
    let sample =
        b"schema = \"vettalon.engagement/1\"\n[[finding]]\nid = \"F-1\"\nrisk_rating = \"high\"\n";
    let mut engagement = parse_engagement(sample).unwrap();
    validate_finding_ids(&engagement, &known).unwrap();
    engagement.finding[0].id = Some("unknown-finding".into());
    assert!(validate_finding_ids(&engagement, &known).is_err());
    let (unbound, _) = record_of(RawInputs {
        reproduce: vec![raw(
            "reproduce.json",
            &event_receipt("effect_observed", &old_hash()),
        )],
        ..Default::default()
    });
    let known = unbound.row_ids().into_iter().map(str::to_owned).collect();
    let mut engagement = parse_engagement(sample).unwrap();
    assert!(validate_finding_ids(&engagement, &known).is_err());
    engagement.finding[0].id = Some(unbound.row_ids()[0].to_owned());
    validate_finding_ids(&engagement, &known).unwrap();
}

#[test]
fn record_field_registry_matches_serialized_model() {
    use super::record::*;
    use std::collections::BTreeSet;

    // Populate optional objects and collections so every schema branch is visited.
    let (_, mut record) = record_of(full_inputs());
    record.languages = vec!["en".into(), "zh-TW".into()];
    record.mapping_version = Some("retest-mapping/1".into());
    record.limits = vec!["limit.outcome".into()];
    let node = NodeEnvironment {
        language: "javascript".into(),
        module_kind: "cjs".into(),
        version: "22".into(),
        lockfile_sha256: Some(old_hash()),
        deps_sha256: Some(old_hash()),
        fixture_sha256: Some(old_hash()),
        driver: Some(crate::audit::target_poc::NodeDriver::Sqlite3),
    };
    fn sample_text(text: &str) -> ReportText {
        ReportText {
            full_sha256: Some(old_hash()),
            ..report_text(text)
        }
    }
    let environment = Environment {
        image_id: Some("test-image".into()),
        harness_sha256: Some(old_hash()),
        harness_version: Some("test".into()),
        policy_version: Some("test".into()),
        adapter_sha256: Some(old_hash()),
        source_tree_sha256: Some(old_hash()),
        node: Some(node),
        sandbox_settings: Some("test settings".into()),
    };
    fn populate_run(run: &mut RunRecord, environment: &Environment) {
        run.environment = environment.clone();
        run.reason = Some("test_reason".into());
        run.started_at = Some("2026-11-13".into());
        run.producer_version = Some("test".into());
        for phase in &mut run.phases {
            phase.effect = Some(false);
            phase.functional = Some(true);
            phase.reached = Some(true);
            phase.transcript_sha256 = Some(old_hash());
        }
    }
    record.engagement = super::engagement::Engagement {
        id: Some("test".into()),
        client: Some("client".into()),
        vendor: Some("vendor".into()),
        tester: Some("tester".into()),
        reviewer: Some("reviewer".into()),
        scope: Some("scope".into()),
        scope_approval_ref: Some("approval".into()),
        method_note: Some("method".into()),
        test_command_note: Some("command".into()),
        original_test_start: Some("2026-11-12".into()),
        original_test_end: Some("2026-11-12".into()),
        retest_date: Some("2026-11-13".into()),
    };
    record.revisions.retest_started_at = Some("2026-11-13".into());
    for source in &mut record.sources {
        source.signature = Some(SignatureRecord {
            mldsa: Some(super::record::MldsaSignatureRecord {
                path: "signatures-pq/example.json".into(),
                sha256: old_hash(),
                binding_ok: true,
                verified: Some(super::record::MldsaRecord {
                    verified: true,
                    key_sha256: old_hash(),
                }),
            }),
            path: "signature.json".into(),
            sha256: old_hash(),
            subject_ok: true,
            cosign: Some(CosignRecord {
                verified: true,
                key_sha256: old_hash(),
                cosign_version: "test".into(),
            }),
        });
    }
    record.revisions.tree_warning = Some(tree_not_clean_label());
    record.revisions.old_scan_started_at = Some(sample_text("2026-11-13"));
    for finding in &mut record.findings {
        finding.operator = super::engagement::FindingEngagement {
            id: Some(finding.id.clone()),
            original_test_ref: Some("original".into()),
            risk_rating: Some("high".into()),
            location: Some("test location".into()),
            correction_summary: Some("test change".into()),
            tester_conclusion: Some("test conclusion".into()),
        };
        finding.line = Some(1);
        for input in &mut finding.inputs.items {
            input.text_sha256 = Some(old_hash());
        }
        finding.binding_note = Some(not_bound_label());
        finding.title = Some(sample_text("Test finding"));
        finding.cwe = Some(sample_text("CWE-78"));
        finding.file = Some(sample_text(FILE));
        finding.function = Some(sample_text("run"));
        finding.inputs.note = Some(inputs_not_determinable_label());
        finding.call.note = Some(call_not_supplied_label());
        finding.call.file = Some(sample_text(FILE));
        finding.call.function = Some(sample_text("run"));
        finding.call.plan_sha256s = vec![old_hash()];
        finding.call.args = vec![ArgRecord {
            kind: "literal",
            value: Some("test".into()),
            truncated: false,
            value_sha256: Some(old_hash()),
        }];
        populate_run(&mut finding.original.as_mut().unwrap().run, &environment);
        let retest = finding.retest.as_mut().unwrap();
        retest.reason = Some("test_reason".into());
        populate_run(retest.run.as_mut().unwrap(), &environment);
        for fix in &mut finding.fix_checks {
            fix.blocker_label = blocker_label(Blocker::Environment);
            fix.environment = environment.clone();
            fix.reason = Some("test_reason".into());
            fix.started_at = Some("2026-11-13".into());
            fix.producer_version = Some("test".into());
            fix.test_command_sha256 = Some(old_hash());
        }
    }
    let json = serde_json::to_value(&record).unwrap();
    fn collect(value: &Value, prefix: &str, paths: &mut BTreeSet<String>) {
        match value {
            Value::Object(fields) => {
                for (key, child) in fields {
                    let mut path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    if child.is_array() {
                        path.push_str("[]");
                    }
                    paths.insert(path.clone());
                    collect(child, &path, paths);
                }
            }
            Value::Array(items) => {
                assert!(!items.is_empty(), "sample must populate {prefix}");
                for item in items {
                    collect(item, prefix, paths);
                }
            }
            Value::Null => panic!("sample must populate {prefix}"),
            _ => {}
        }
    }
    let mut actual = BTreeSet::new();
    collect(&json, "", &mut actual);
    // Map keys are data, rather than fixed fields in the record schema.
    actual.retain(|path| !path.starts_with("summary.fix_outcomes."));
    let expected = record_field_paths();
    for path in &expected {
        assert!(
            actual.contains(path),
            "record field path does not exist: {path}"
        );
    }
    assert_eq!(
        expected, actual,
        "update the registry when record fields change"
    );
    let mapping = super::text::load_mapping(&expected).unwrap();
    super::text::validate_data(&mapping, &super::text::load_text().unwrap(), &expected).unwrap();
}

#[test]
fn retest_state_tampering_is_refused_by_signing_and_packaging() {
    for mutation in 0..6 {
        let mut inputs = full_inputs();
        let mut value: Value = serde_json::from_str(&inputs.retest.as_ref().unwrap().raw).unwrap();
        match mutation {
            0 | 1 => {
                value["results"][0]["receipt"] = event_receipt("effect_observed", &new_hash());
                value["results"][0]["status"] = json!("retest_cap_reached");
                value["results"][0]["reason"] = json!("deadline_exceeded");
                value["summary"] = summary_for(&["retest_cap_reached"]);
                if mutation == 1 {
                    value["results"][0]["receipt"]["reason"] = json!("deadline_exceeded");
                }
            }
            2 => value["results"][0]["reason"] = json!("invented"),
            3 => value["replays"] = json!(1),
            4 => value["replays"] = json!(0),
            _ => value["replays"] = json!(21),
        }
        assert!(extract(&value.to_string()).is_err(), "mutation {mutation}");
        inputs.retest = Some(raw("retest.json", &value));
        assert_token(inputs, RECEIPT_REFUSED);
    }
    let mut inputs = full_inputs();
    let mut value: Value = serde_json::from_str(&inputs.retest.as_ref().unwrap().raw).unwrap();
    value["old_repo_commit"] = json!("c".repeat(40));
    inputs.retest = Some(raw("retest.json", &value));
    assert_token(inputs, RECEIPT_REFUSED);
}

#[test]
fn retest_deadline_receipts_remain_accepted() {
    for completed in [0, 1] {
        let mut value = retest_report(&old_hash());
        let mut receipt = bare_receipt("effect_observed", &new_hash(), None);
        receipt["outcome"] = json!("inconclusive");
        receipt["reason"] = json!("deadline_exceeded");
        receipt["replays"]["completed"] = json!(completed);
        receipt["replays"]["observed"] = json!(completed);
        receipt["replays"]["runs"]
            .as_array_mut()
            .unwrap()
            .truncate(completed);
        if completed == 0 {
            receipt["phases"] = json!([]);
        }
        if completed == 0 {
            value["results"][0]["receipt"] = Value::Null;
        } else {
            receipt["target_plan_sha256"] = json!("c".repeat(64));
            add_event(&mut receipt, "CWE-78");
            value["results"][0]["receipt"] = receipt;
        }
        value["results"][0]["status"] = json!("retest_cap_reached");
        value["results"][0]["reason"] = json!("deadline_exceeded");
        value["summary"] = summary_for(&["retest_cap_reached"]);
        extract(&value.to_string()).unwrap();
        check_inputs(RawInputs {
            retest: Some(raw("retest.json", &value)),
            ..Default::default()
        })
        .unwrap();
    }
}

#[test]
fn receipt_less_and_environment_retest_rows_work_with_and_without_reports() {
    for with_report in [false, true] {
        for (status, reason) in [
            ("not_reproducible_before", "no_target_plan"),
            ("target_missing", "target_file_missing"),
            ("environment_unavailable", "sandbox_unavailable"),
        ] {
            let report = default_report();
            let mut value = retest_report(&sha256_hex(&report.raw));
            value["results"][0]["status"] = json!(status);
            value["results"][0]["reason"] = json!(reason);
            value["summary"] = summary_for(&[status]);
            value["results"][0]["receipt"] = Value::Null;
            if status != "environment_unavailable" {
                value["results"][0]["new_file_sha256"] = Value::Null;
                value["results"][0]["rebound"] = json!(false);
            }
            let (_, record) = record_of(RawInputs {
                retest: Some(raw("retest.json", &value)),
                report: with_report.then_some(report),
                ..Default::default()
            });
            let row = &record.findings[0];
            assert_eq!(
                row.id_source,
                if with_report {
                    super::inputs::IdSource::Report
                } else {
                    super::inputs::IdSource::Retest
                }
            );
            assert!(row.retest.as_ref().unwrap().run.is_none());
            assert_eq!(row.retest.as_ref().unwrap().status.key(), status);
        }
    }
}

#[test]
fn old_file_hash_comparison_is_trimmed_and_case_insensitive() {
    for change_result in [false, true] {
        let mut report = default_report();
        report.report.findings[0].file_hash =
            Some(format!(" {} ", old_hash().to_ascii_uppercase()));
        report.raw = serde_json::to_vec(&report.report).unwrap();
        let mut value = retest_report(&sha256_hex(&report.raw));
        if change_result {
            value["results"][0]["old_file_sha256"] =
                json!(format!(" {} ", old_hash().to_ascii_uppercase()));
        }
        check_inputs(RawInputs {
            report: Some(report),
            retest: Some(raw("retest.json", &value)),
            ..Default::default()
        })
        .unwrap();
    }
}

#[test]
fn rule_4_rejects_a_different_recorded_function() {
    let mut report = default_report();
    report.report.findings[0].trace.push(TraceStep {
        kind: TraceKind::Sink,
        file: FILE.into(),
        line: 3,
        scope: "other".into(),
        description: "sink".into(),
    });
    report.raw = serde_json::to_vec(&report.report).unwrap();
    for retest in [false, true] {
        let inputs = if retest {
            RawInputs {
                retest: Some(raw("retest.json", &retest_report(&sha256_hex(&report.raw)))),
                report: Some(report.clone()),
                ..Default::default()
            }
        } else {
            RawInputs {
                reproduce: vec![raw(
                    "reproduce.json",
                    &event_receipt("effect_observed", &old_hash()),
                )],
                report: Some(report.clone()),
                ..Default::default()
            }
        };
        assert_token(inputs, RECEIPT_UNBOUND);
    }
}

fn node_receipt(class: OracleClass) -> Value {
    let functional = (class == OracleClass::Ssrf).then_some(true);
    let mut receipt = bare_receipt("effect_absent", &old_hash(), functional);
    receipt["version"] = json!(3);
    receipt["target_file"] = json!("src/app.cjs");
    receipt["runtime"] = json!({
        "language": "javascript", "module_kind": "cjs", "export_kind": "named",
        "node_version": "v22.15.0", "lockfile_sha256": "a".repeat(64),
        "lockfile_summary_sha256": "b".repeat(64), "deps_sha256": "c".repeat(64),
        "fixture_sha256": null, "driver": null, "hook_bundle_sha256": "e".repeat(64)
    });
    receipt["harness_sha256"] = json!(crate::audit::target_poc::node_harness_sha256(
        class,
        receipt["adapter_sha256"].as_str().unwrap()
    ));
    receipt["image_id"] = json!(format!("sha256:{}", "e".repeat(64)));
    for run in receipt["replays"]["runs"].as_array_mut().unwrap() {
        for phase in run["phases"].as_array_mut().unwrap() {
            phase["reached"] = json!(true);
            phase["reach_source"] = json!("in_process_hook");
            phase["executable"] = json!(true);
        }
    }
    receipt["phases"] = receipt["replays"]["runs"][0]["phases"].clone();
    receipt
}

#[test]
fn node_runtime_receipt_builds_a_package_row() {
    let receipt = node_receipt(OracleClass::CommandInjection);
    let (_, record) = record_of(RawInputs {
        reproduce: vec![raw("node.json", &receipt)],
        ..Default::default()
    });
    let row = &record.findings[0];
    let node = row
        .original
        .as_ref()
        .unwrap()
        .run
        .environment
        .node
        .as_ref()
        .unwrap();
    assert_eq!(node.language, "javascript");
    assert_eq!(node.version, "v22.15.0");
    assert_eq!(row.oracle_class, Some("command_injection"));
}

#[test]
fn node_ssrf_reproduce_receipt_packages_successfully() {
    use super::PackageRequest;
    use super::verify::verify_package;
    use super::write::{WriteOptions, write_package};

    let mut receipt = node_receipt(OracleClass::Ssrf);
    receipt["target_plan_sha256"] = json!("c".repeat(64));
    add_event(&mut receipt, "CWE-918");
    let (_, record) = record_of(RawInputs {
        reproduce: vec![raw("ssrf.json", &receipt)],
        ..Default::default()
    });
    let row = &record.findings[0];
    assert_eq!(row.runtime, Some("node"));
    assert_eq!(row.oracle_class, Some("ssrf"));
    assert_eq!(
        row.inputs.items[0].text,
        fixture_inputs(OracleClass::Ssrf)[0]
    );
    assert_eq!(
        row.inputs.items[0].id,
        variant_set_for(OracleClass::Ssrf, Runtime::Node).variants[0].id
    );
    assert_eq!(row.inputs.items[1].text, benign_input(OracleClass::Ssrf));

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("ssrf.json");
    std::fs::write(&path, receipt.to_string()).unwrap();
    let options = WriteOptions {
        out: root.join("package"),
        zip: false,
        languages: vec!["zh-TW".into(), "en".into()],
        engagement: None,
    };
    let id = write_package(
        &PackageRequest {
            reproduce: vec![path],
            ..Default::default()
        },
        &options,
    )
    .unwrap();
    assert_eq!(verify_package(&options.out, None).unwrap().package_id, id);
    for (locale, label) in [
        ("zh-TW", "伺服器端請求偽造"),
        ("en", "server-side request forgery"),
    ] {
        let markdown =
            std::fs::read_to_string(options.out.join(format!("record.{locale}.md"))).unwrap();
        assert!(markdown.contains(label));
        assert!(markdown.contains(fixture_inputs(OracleClass::Ssrf)[0]));
    }
}

#[test]
fn truncated_hashes_use_original_bytes_while_display_stays_masked() {
    let literal = format!(
        "credential sk-super-secret-value {}\u{202e}",
        "a".repeat(600)
    );
    let shown = super::record::report_text(&literal);
    assert!(shown.truncated);
    assert_eq!(shown.full_sha256, Some(sha256_hex(literal.as_bytes())));
    assert!(!shown.text.contains("super-secret-value"));
    let mut call = plan_call("run");
    // Keep the validated plan small; exercise display bounds independently.
    call.args[1] = TargetArgument::Literal {
        value: json!("small"),
    };
    let mut inputs = check_inputs(plan_inputs(&call, json!({"F-1": call}))).unwrap();
    inputs.rows[0].plan.as_mut().unwrap().args[1] = TargetArgument::Literal {
        value: json!(literal),
    };
    let record = build_record(&inputs).unwrap();
    let arg = &record.findings[0].call.args[1];
    assert!(arg.truncated);
    assert_eq!(
        arg.value_sha256,
        Some(sha256_hex(json!(literal).to_string().as_bytes()))
    );
    assert!(!arg.value.as_deref().unwrap().contains("super-secret-value"));
}

#[cfg(unix)]
#[test]
fn package_refuses_hard_links_without_changing_the_shared_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    std::fs::write(
        &path,
        event_receipt("effect_observed", &old_hash()).to_string(),
    )
    .unwrap();
    std::fs::hard_link(&path, dir.path().join("linked.json")).unwrap();
    assert!(
        crate::remediation::read_regular_capped(&path, super::RECEIPT_MAX_BYTES, "receipt").is_ok()
    );
    let error = super::load_inputs(&super::PackageRequest {
        reproduce: vec![path],
        ..Default::default()
    })
    .unwrap_err();
    assert_eq!(error.token, INPUT_UNREADABLE);
    assert!(error.message.contains("hard link"));
}

#[test]
fn input_budget_stops_before_reading_a_report_even_when_not_included() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = dir.path().join("receipt.json");
    std::fs::write(
        &receipt,
        event_receipt("effect_observed", &old_hash()).to_string(),
    )
    .unwrap();
    let report = dir.path().join("report.json");
    // Sparse, invalid JSON: the metadata budget must refuse before parsing.
    std::fs::File::create(&report)
        .unwrap()
        .set_len(super::PACKAGE_MAX_BYTES)
        .unwrap();
    let error = super::load_inputs(&super::PackageRequest {
        reproduce: vec![receipt],
        report: Some(report),
        targets: Some(dir.path().join("never-read.json")),
        include_report: false,
        ..Default::default()
    })
    .unwrap_err();
    assert_eq!(error.token, PACKAGE_TOO_LARGE);
}

#[test]
fn report_and_retest_row_counts_are_bounded() {
    let mut inputs = full_inputs();
    inputs.report.as_mut().unwrap().report.findings =
        vec![finding("F", "CWE-78", &old_hash()); super::MAX_REPORT_FINDINGS + 1];
    assert_token(inputs, INPUT_COUNT_EXCEEDED);
    let mut value = retest_report(&old_hash());
    let mut result = value["results"][0].clone();
    result["receipt"] = Value::Null;
    result["status"] = json!("not_reproducible_before");
    result["reason"] = json!("no_target_plan");
    value["results"] = json!(vec![result; super::MAX_RETEST_RESULTS + 1]);
    assert_token(
        RawInputs {
            retest: Some(raw("retest.json", &value)),
            ..Default::default()
        },
        INPUT_COUNT_EXCEEDED,
    );
}

#[test]
fn row_limits_precede_typed_parsing_and_stop_at_the_first_excess_row() {
    let dir = tempfile::tempdir().unwrap();
    let retest = dir.path().join("retest.json");
    let report = dir.path().join("report.json");
    for (field, cap, invalid_token) in [
        ("findings", super::MAX_REPORT_FINDINGS, REPORT_REFUSED),
        ("results", super::MAX_RETEST_RESULTS, RECEIPT_REFUSED),
    ] {
        for key in [
            field.to_owned(),
            format!("\\u{:04x}{}", field.as_bytes()[0], &field[1..]),
        ] {
            for (count, tail, expected) in [
                (cap, "]}", invalid_token),
                (cap + 1, "]}", INPUT_COUNT_EXCEEDED),
                (
                    cap + 1,
                    ",THIS_TAIL_MUST_NOT_BE_PARSED",
                    INPUT_COUNT_EXCEEDED,
                ),
            ] {
                // Empty objects are deliberately invalid typed rows: a count
                // refusal proves no AuditReport / RetestReport was built.
                let rows = vec!["{}"; count].join(",");
                let bytes = format!("{{\"{key}\":[{rows}{tail}");
                std::fs::write(&retest, retest_report(&old_hash()).to_string()).unwrap();
                let mut request = super::PackageRequest {
                    retest: Some(retest.clone()),
                    ..Default::default()
                };
                if field == "findings" {
                    std::fs::write(&report, bytes).unwrap();
                    request.report = Some(report.clone());
                } else {
                    std::fs::write(&retest, bytes).unwrap();
                }
                let error = super::load_inputs(&request).unwrap_err();
                assert_eq!(error.token, expected, "{field}, {count}, {tail}");
            }
        }
    }
}

#[test]
fn shared_retest_format_errors_preserve_package_tokens() {
    for (field, token) in [
        ("old_report_sha256", RECEIPT_FIELD_INVALID),
        ("old_repo_commit", REVISION_INVALID),
        ("new_repo_commit", REVISION_INVALID),
    ] {
        for bad in [
            "".to_owned(),
            "a".repeat(39),
            "a".repeat(65),
            "g".repeat(64),
            "A".repeat(64),
        ] {
            let mut inputs = full_inputs();
            let mut value: Value =
                serde_json::from_str(&inputs.retest.as_ref().unwrap().raw).unwrap();
            value[field] = json!(bad);
            assert!(extract(&value.to_string()).unwrap_err().contains(field));
            inputs.retest = Some(raw("retest.json", &value));
            assert_token(inputs, token);
        }
    }
}

#[test]
fn rule_5_verifier_receives_exact_bytes_and_rejection_is_fatal() {
    use super::inputs::{BundleVerifier, Source, load_inputs_with_verifier};
    use std::cell::Cell;
    struct Fake {
        fail: bool,
        calls: Cell<usize>,
        receipt: Vec<u8>,
        bundle: Vec<u8>,
    }
    impl BundleVerifier for Fake {
        fn verify(
            &self,
            key: &std::path::Path,
            receipt: &Source,
            bundle: &Source,
        ) -> Result<(), String> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(key, std::path::Path::new("public.pem"));
            assert_eq!(receipt.bytes, self.receipt);
            assert_eq!(bundle.bytes, self.bundle);
            if self.fail {
                Err("fake signature rejected".into())
            } else {
                Ok(())
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let receipt = event_receipt("effect_observed", &old_hash()).to_string();
    let bundle = bundle_for(&receipt);
    let receipt_path = dir.path().join("reproduce.json");
    let bundle_path = dir.path().join(&bundle.name);
    std::fs::write(&receipt_path, &receipt).unwrap();
    std::fs::write(&bundle_path, &bundle.raw).unwrap();
    let mut request = super::PackageRequest {
        reproduce: vec![receipt_path],
        bundles: vec![bundle_path],
        key: Some("public.pem".into()),
        ..Default::default()
    };
    let mut verifier = Fake {
        fail: false,
        calls: Cell::new(0),
        receipt: receipt.into_bytes(),
        bundle: bundle.raw.into_bytes(),
    };
    load_inputs_with_verifier(&request, &verifier).unwrap();
    assert_eq!(verifier.calls.get(), 1);
    verifier.fail = true;
    assert_eq!(
        load_inputs_with_verifier(&request, &verifier)
            .unwrap_err()
            .token,
        BUNDLE_SIGNATURE_INVALID
    );
    request.key = None;
    load_inputs_with_verifier(&request, &verifier).unwrap();
    assert_eq!(verifier.calls.get(), 2);
    request.key = Some("public.pem".into());
    request.bundles.clear();
    assert_eq!(
        load_inputs_with_verifier(&request, &verifier)
            .unwrap_err()
            .token,
        BUNDLE_SIGNATURE_INVALID
    );
}

#[cfg(unix)]
#[test]
fn package_writer_and_verifier_roundtrip_and_refusals() {
    use super::PackageRequest;
    use super::verify::verify_package;
    use super::write::{WriteOptions, write_package};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let receipt = root.join("reproduce.json");
    let value = event_receipt("effect_observed", &old_hash());
    std::fs::write(&receipt, value.to_string()).unwrap();
    let request = PackageRequest {
        reproduce: vec![receipt.clone()],
        ..Default::default()
    };
    let mut options = WriteOptions {
        out: root.join("one"),
        zip: false,
        languages: vec!["zh-TW".into(), "en".into()],
        engagement: None,
    };
    let id = write_package(&request, &options).unwrap();
    assert_eq!(verify_package(&options.out, None).unwrap().package_id, id);
    assert_eq!(verify_package(&options.out, None).unwrap().exit_code, 0);
    assert_eq!(
        write_package(&request, &options).unwrap_err().token,
        "package_output_exists"
    );
    options.out = root.join("two");
    assert_eq!(write_package(&request, &options).unwrap(), id);
    let one = super::write::io::read_dir(std::fs::File::open(root.join("one")).unwrap()).unwrap();
    let two = super::write::io::read_dir(std::fs::File::open(root.join("two")).unwrap()).unwrap();
    assert_eq!(one, two);
    options.zip = true;
    options.out = root.join("one.zip");
    assert_eq!(write_package(&request, &options).unwrap(), id);
    assert_eq!(verify_package(&options.out, None).unwrap().exit_code, 0);
    options.out = root.join("two.zip");
    write_package(&request, &options).unwrap();
    assert_eq!(
        std::fs::read(root.join("one.zip")).unwrap(),
        std::fs::read(root.join("two.zip")).unwrap()
    );
    std::fs::write(root.join("one/extra"), "extra").unwrap();
    assert_eq!(
        verify_package(&root.join("one"), None)
            .unwrap_err()
            .exit_code,
        1
    );
    let md = root.join("two/record.en.md");
    let mut bytes = std::fs::read(&md).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&md, bytes).unwrap();
    assert_eq!(
        verify_package(&root.join("two"), None)
            .unwrap_err()
            .exit_code,
        1
    );
    std::os::unix::fs::symlink(&root, root.join("link")).unwrap();
    options.out = root.join("link/refused");
    assert_eq!(
        write_package(&request, &options).unwrap_err().token,
        "package_path_unsafe"
    );
    assert!(!root.join("refused").exists());
    let bundle = bundle_for(&event_receipt("effect_absent", &new_hash()).to_string());
    let bundle_path = root.join("bundle.json");
    std::fs::write(&bundle_path, bundle.raw).unwrap();
    let request = PackageRequest {
        bundles: vec![bundle_path],
        ..request
    };
    options.out = root.join("bad-bundle");
    assert_eq!(
        write_package(&request, &options).unwrap_err().token,
        BUNDLE_UNMATCHED
    );
    assert!(!options.out.exists());
}

#[test]
fn packaged_report_row_limit_precedes_typed_parsing() {
    use super::verify::{validated_inputs, verify_files};
    use super::write::{Signatures, render, seal};
    let inputs = check_inputs(RawInputs {
        reproduce: vec![raw(
            "reproduce.json",
            &event_receipt("effect_observed", &old_hash()),
        )],
        ..Default::default()
    })
    .unwrap();
    let engagement =
        super::engagement::parse_engagement(super::engagement::engagement_template().as_bytes())
            .unwrap();
    let files = render(&inputs, &engagement, &["en".into()], &Signatures::new()).unwrap();
    for (count, tail, expected) in [
        (super::MAX_REPORT_FINDINGS, "]}", REPORT_REFUSED),
        (super::MAX_REPORT_FINDINGS + 1, "]}", INPUT_COUNT_EXCEEDED),
        (
            super::MAX_REPORT_FINDINGS + 1,
            ",THIS_TAIL_MUST_NOT_BE_PARSED",
            INPUT_COUNT_EXCEEDED,
        ),
    ] {
        // Empty objects fail typed finding parsing. The malformed 10,002nd
        // element also proves that pre-scanning stops at the first excess row.
        let rows = vec!["{}"; count].join(",");
        let bytes = format!("{{\"findings\":[{rows}{tail}").into_bytes();
        let mut files = files.clone();
        files.insert("report/scan.json".into(), bytes);
        seal(&mut files).unwrap();
        let manifest = super::verify::parse(&files["manifest.json"]).unwrap();
        let error = validated_inputs(&files, &manifest).unwrap_err();
        assert_eq!(error.token, expected, "{count}, {tail}");
        if expected == INPUT_COUNT_EXCEEDED {
            assert_eq!(error.message, "report findings exceeds 10000");
        }
        let error = verify_files(&files, None).unwrap_err();
        assert_eq!(error.token, expected, "{count}, {tail}");
        assert_eq!(error.exit_code, 2);
    }
}

#[test]
fn package_verifier_checks_render_even_after_resealing() {
    use super::verify::verify_files;
    use super::write::{Signatures, canonical, render, seal};
    let inputs = check_inputs(RawInputs {
        reproduce: vec![raw(
            "reproduce.json",
            &event_receipt("effect_observed", &old_hash()),
        )],
        ..Default::default()
    })
    .unwrap();
    let engagement =
        super::engagement::parse_engagement(super::engagement::engagement_template().as_bytes())
            .unwrap();
    let mut files = render(&inputs, &engagement, &["en".into()], &Signatures::new()).unwrap();
    seal(&mut files).unwrap();
    assert_eq!(verify_files(&files, None).unwrap().exit_code, 0);
    let original = files.clone();
    files.get_mut("record.en.md").unwrap().push(b'!');
    files.remove("manifest.json");
    seal(&mut files).unwrap();
    assert_eq!(
        verify_files(&files, None).unwrap_err().token,
        "package_render_mismatch"
    );
    files = original;
    let mut manifest: super::write::Manifest =
        super::verify::parse(&files["manifest.json"]).unwrap();
    manifest.vettalon_version = "999.0.0".into();
    files.insert("manifest.json".into(), canonical(&manifest).unwrap());
    assert_eq!(verify_files(&files, None).unwrap().exit_code, 3);
    files.get_mut("record.en.md").unwrap().push(b'!');
    assert_eq!(verify_files(&files, None).unwrap_err().exit_code, 1);
}

#[test]
fn package_zip_refuses_parent_and_duplicate_entries() {
    use std::io::{Cursor, Write};
    fn archive(names: &[&str]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for name in names {
            zip.start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
            zip.write_all(b"x").unwrap();
        }
        zip.finish().unwrap().into_inner()
    }
    let bytes = archive(&["../escape"]);
    assert_eq!(
        super::verify::read_zip(&bytes).unwrap_err().token,
        "package_path_unsafe"
    );
    // Patch equal-length local and central names so the writer cannot reject duplicates first.
    let mut bytes = archive(&["aa", "bb"]);
    for i in 0..bytes.len() - 1 {
        if &bytes[i..i + 2] == b"bb" {
            bytes[i..i + 2].copy_from_slice(b"aa");
        }
    }
    assert_eq!(
        super::verify::read_zip(&bytes).unwrap_err().token,
        "package_duplicate"
    );
}

#[test]
fn package_included_report_signatures_and_engagement_rerender() {
    use super::write::{Signatures, render, seal};
    let mut raw = full_inputs();
    raw.include_report = true;
    let report = raw.report.as_mut().unwrap();
    report.report.findings[0].status = FindingStatus::Candidate;
    report.report.findings[0].trace = vec![TraceStep {
        kind: TraceKind::Sink,
        file: FILE.into(),
        line: 3,
        scope: "run".into(),
        description: "sink".into(),
    }];
    report.report.summary =
        Summary::from_findings(&report.report.findings, 0, 0, GatePolicy::default(), &[]);
    report.raw = serde_json::to_vec(&report.report).unwrap();
    crate::audit::parse_report_for_delivery(&report.raw).unwrap();
    raw.retest = Some(super::tests::raw(
        "retest.json",
        &retest_report(&sha256_hex(&report.raw)),
    ));
    raw.bundles.push(bundle_for(&raw.reproduce[0].raw));
    let inputs = check_inputs(raw).unwrap();
    let engagement = super::engagement::parse_engagement(
        br#"
schema = "vettalon.engagement/1"
[engagement]
client = "Example"
retest_date = "2026-11-13"
[[finding]]
id = "F-1"
tester_conclusion = "Operator statement"
"#,
    )
    .unwrap();
    let mut files = render(
        &inputs,
        &engagement,
        &["en".into(), "zh-TW".into()],
        &Signatures::new(),
    )
    .unwrap();
    seal(&mut files).unwrap();
    assert_eq!(
        super::verify::verify_files(&files, None).unwrap().exit_code,
        0
    );
}

#[test]
fn package_verified_claims_require_trusted_key_and_matching_fingerprint() {
    use super::record::CosignRecord;
    use super::verify::verify_files;
    use super::write::{Signatures, render, seal};
    let receipt = raw(
        "reproduce.json",
        &event_receipt("effect_observed", &old_hash()),
    );
    let inputs = check_inputs(RawInputs {
        bundles: vec![bundle_for(&receipt.raw)],
        reproduce: vec![receipt],
        ..Default::default()
    })
    .unwrap();
    let engagement =
        super::engagement::parse_engagement(super::engagement::engagement_template().as_bytes())
            .unwrap();
    let signature = inputs
        .sources
        .iter()
        .find(|s| s.kind == super::SourceKind::Signature)
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let key = temp.path().join("key.pub");
    let key_bytes = b"independently supplied key";
    std::fs::write(&key, key_bytes).unwrap();
    for (fingerprint, supplied, token) in [
        (
            sha256_hex(key_bytes),
            None,
            "package_signature_key_required",
        ),
        (
            "0".repeat(64),
            Some(key.as_path()),
            "package_signature_key_mismatch",
        ),
    ] {
        // Even a fully re-rendered and re-sealed claim is not trusted evidence.
        let claims = Signatures::from([(
            signature.path.clone(),
            CosignRecord {
                verified: true,
                key_sha256: fingerprint,
                cosign_version: "v3.0.4".into(),
            },
        )]);
        let mut files = render(&inputs, &engagement, &["en".into()], &claims).unwrap();
        files.insert("keys/cosign.pub".into(), key_bytes.to_vec());
        seal(&mut files).unwrap();
        let error = verify_files(&files, supplied).unwrap_err();
        assert_eq!(error.exit_code, 2);
        assert_eq!(error.token, token);
    }
}

#[cfg(unix)]
#[test]
fn package_output_and_zip_members_have_private_modes() {
    use super::write::{Files, io, zip_bytes};
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let files = Files::from([("receipts/retest/test.json".into(), b"test".to_vec())]);
    let directory = root.join("package");
    io::publish(&directory, &files, None).unwrap();
    for path in [
        "",
        "receipts",
        "receipts/retest",
        "receipts/retest/test.json",
    ] {
        let metadata = std::fs::metadata(directory.join(path)).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        let maximum = if metadata.is_dir() { 0o700 } else { 0o600 };
        assert_eq!(mode & !maximum, 0, "{path}: {mode:o}");
    }
    let bytes = zip_bytes(&files).unwrap();
    let zip = root.join("package.zip");
    io::publish(&zip, &files, Some(&bytes)).unwrap();
    assert_eq!(
        std::fs::metadata(zip).unwrap().permissions().mode() & 0o177,
        0
    );
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(
        archive.by_index(0).unwrap().unix_mode().unwrap() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn retest_binding_tampering_is_refused_before_signing_and_packaging() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("retest.json");
    let key = dir.path().join("cosign.key");
    std::fs::write(&key, "placeholder").unwrap();
    for mutation in 0..9 {
        let mut value = retest_report(&old_hash());
        let token = match mutation {
            0 => {
                let legacy = bare_receipt("effect_absent", &new_hash(), None);
                // Still a valid standalone legacy reproduce receipt.
                extract(&legacy.to_string()).unwrap();
                value["results"][0]["receipt"] = legacy;
                value["results"][0]["finding_id"] = json!("invented-finding");
                value["results"][0]["old_file_sha256"] = json!("f".repeat(64));
                RECEIPT_REFUSED
            }
            1 => {
                value["results"][0]["new_file_sha256"] = json!("f".repeat(64));
                RETEST_FILE_HASH_MISMATCH
            }
            2 => {
                value["results"][0]["rebound"] = json!(false);
                RETEST_FILE_HASH_MISMATCH
            }
            3 => {
                value["results"][0]["old_file_sha256"] = json!(new_hash());
                RETEST_FILE_HASH_MISMATCH
            }
            4 => {
                let duplicate = value["results"][0].clone();
                value["results"].as_array_mut().unwrap().push(duplicate);
                value["summary"] = summary_for(&["not_observed", "not_observed"]);
                RETEST_RESULT_DUPLICATE
            }
            5 => {
                value["results"][0]["receipt"]["target_function"] = json!("other");
                RECEIPT_REFUSED
            }
            6 => {
                value["results"][0]["receipt"]["target_file"] = json!("other.py");
                RECEIPT_REFUSED
            }
            7 => {
                value["results"][0]["finding_id"] = json!("F-2");
                RECEIPT_REFUSED
            }
            _ => {
                value["results"][0]["receipt"] = Value::Null;
                value["results"][0]["status"] = json!("target_missing");
                value["results"][0]["reason"] = json!("target_file_missing");
                value["results"][0]["new_file_sha256"] = Value::Null;
                value["summary"] = summary_for(&["target_missing"]);
                RETEST_FILE_HASH_MISMATCH
            }
        };
        let raw_text = value.to_string();
        let error = extract(&raw_text).unwrap_err();
        if mutation == 0 {
            assert!(error.contains("no verification event"), "{error}");
        }
        std::fs::write(&file, &raw_text).unwrap();
        let error = crate::attest::sign_receipt(&file, &key, None)
            .await
            .unwrap_err();
        assert!(
            error.contains("receipt refused"),
            "mutation {mutation}: {error}"
        );
        assert!(!crate::attest::default_bundle_path(&file).exists());
        for with_report in [false, true] {
            assert_token(
                RawInputs {
                    retest: Some(raw("retest.json", &value)),
                    report: with_report.then(default_report),
                    ..Default::default()
                },
                token,
            );
        }
    }
}

#[test]
fn pq_sidecars_require_unique_exact_content_binding_and_obey_input_caps() {
    use crate::attest::{pq, statement::decode_bundle_payload};
    let receipt = raw(
        "reproduce.json",
        &event_receipt("effect_observed", &old_hash()),
    );
    let bundle = bundle_for(&receipt.raw);
    let mut sidecar = pq::Sidecar {
        algorithm: "ML-DSA-65".into(),
        message: "dsse-pae-v1".into(),
        schema: "vettalon.receipt-mldsa/1".into(),
        openssl_version: "OpenSSL 3.6.4".into(),
        public_key_sha256: old_hash(),
        receipt_sha256: sha256_hex(receipt.raw.as_bytes()),
        statement_sha256: sha256_hex(&decode_bundle_payload(bundle.raw.as_bytes()).unwrap()),
        signature: b64(&vec![0x42; pq::SIGNATURE_BYTES]),
    };
    let pq_input = |name: &str, value: &pq::Sidecar| RawInput {
        name: name.into(),
        raw: String::from_utf8(value.canonical_bytes().unwrap()).unwrap(),
    };
    let mut inputs = RawInputs {
        reproduce: vec![receipt],
        bundles: vec![bundle],
        pq_sigs: vec![pq_input("pq.json", &sidecar)],
        ..Default::default()
    };
    let accepted = check_inputs(inputs.clone()).unwrap();
    let record = build_record(&accepted).unwrap();
    let pq_record = record.sources[0]
        .signature
        .as_ref()
        .unwrap()
        .mldsa
        .as_ref()
        .unwrap();
    assert!(pq_record.binding_ok);
    assert!(pq_record.verified.is_none());
    inputs.pq_sigs.push(pq_input("second.json", &sidecar));
    assert_token(inputs.clone(), "pq_signature_duplicate");
    inputs.pq_sigs.pop();
    sidecar.receipt_sha256 = new_hash();
    inputs.pq_sigs[0] = pq_input("pq.json", &sidecar);
    assert_token(inputs.clone(), "pq_signature_unmatched");
    inputs.pq_sigs[0].raw = "x".repeat(pq::SIDECAR_MAX_BYTES + 1);
    assert_token(inputs.clone(), INPUT_UNREADABLE);
    inputs.pq_sigs = vec![pq_input("pq.json", &sidecar); super::MAX_BUNDLES + 1];
    assert_token(inputs, INPUT_COUNT_EXCEEDED);
}
