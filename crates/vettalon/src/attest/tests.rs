use serde_json::{Value, json};

use super::cosign::{CosignError, require_supported_version};
use super::statement::{
    BUNDLE_MAX_BYTES, BUNDLE_MEDIA_TYPE_V03, DSSE_PAYLOAD_TYPE, STATEMENT_TYPE_V1, build_statement,
    canonical_bytes, check_bundle, check_statement, decode_base64_strict,
};
use super::{
    AttestError, PASSWORD_HINT, ReceiptKind, default_bundle_path, extract, key_argument,
    sign_failure, sign_receipt, verify_receipt,
};
use crate::audit::schema::sha256_hex;

fn reproduce_receipt() -> String {
    json!({
        "version": 1,
        "outcome": "inconclusive",
        "phases": [],
        "target_file": "src/app.py",
        "target_function": "run",
        "target_plan_sha256": sha256_hex(b"plan"),
        "target_file_sha256": null,
        "source_sha256": null,
        "exclusions": null,
        "adapter_sha256": null,
        "image_id": null,
        "reason": "sandbox_unavailable"
    })
    .to_string()
}

fn fix_check_receipt() -> String {
    let raw = json!({
        "check": {
            "regression": "pass",
            "tests": "not_run",
            "inputs_blocked": 1,
            "inputs_total": 1,
            "diff_sha256": sha256_hex(b"diff")
        },
        "note": null,
        "binding": null
    });
    let run: crate::audit::fix_check::FixCheckRun = serde_json::from_value(raw).unwrap();
    serde_json::to_string(&run).unwrap()
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

/// The top-level layout cosign v3 writes with `--bundle`.
fn bundle_value(payload: &str) -> Value {
    json!({
        "mediaType": BUNDLE_MEDIA_TYPE_V03,
        "verificationMaterial": {"publicKey": {"hint": "test"}},
        "dsseEnvelope": {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": payload,
            "signatures": [{"sig": "AAAA"}]
        }
    })
}

fn bundle_with_payload(payload: &str) -> Vec<u8> {
    bundle_value(payload).to_string().into_bytes()
}

fn bundle_for(statement: &Value) -> Vec<u8> {
    bundle_with_payload(&b64(statement.to_string().as_bytes()))
}

struct Fixture {
    receipt: String,
    predicate: Value,
    statement: Value,
}

fn fixture() -> Fixture {
    let receipt = reproduce_receipt();
    let extracted = extract(&receipt).unwrap();
    let statement = build_statement(
        "receipt.json",
        receipt.as_bytes(),
        extracted.kind,
        &extracted.predicate,
    );
    Fixture {
        receipt,
        predicate: extracted.predicate,
        statement,
    }
}

impl Fixture {
    fn check(&self, statement: &Value) -> Result<(), String> {
        check_statement(
            statement,
            self.receipt.as_bytes(),
            ReceiptKind::Reproduce,
            &self.predicate,
        )
    }

    fn check_raw_bundle(&self, bundle: &[u8]) -> Result<(), String> {
        check_bundle(
            bundle,
            self.receipt.as_bytes(),
            ReceiptKind::Reproduce,
            &self.predicate,
        )
    }

    fn check_value(&self, bundle: &Value) -> Result<(), String> {
        self.check_raw_bundle(bundle.to_string().as_bytes())
    }

    fn valid_bundle(&self) -> Value {
        bundle_value(&b64(self.statement.to_string().as_bytes()))
    }
}

#[test]
fn detects_reproduce_receipt() {
    let extracted = extract(&reproduce_receipt()).unwrap();
    assert_eq!(extracted.kind, ReceiptKind::Reproduce);
}

#[test]
fn detects_fix_check_receipt() {
    let extracted = extract(&fix_check_receipt()).unwrap();
    assert_eq!(extracted.kind, ReceiptKind::FixCheck);
}

#[test]
fn refuses_unknown_json_and_garbage() {
    assert!(extract(r#"{"hello":"world"}"#).is_err());
    assert!(extract("[]").is_err());
    assert!(extract("not json at all").is_err());
    assert!(extract("").is_err());
}

#[test]
fn refuses_a_fix_check_receipt_with_an_unknown_field() {
    let mut value: Value = serde_json::from_str(&fix_check_receipt()).unwrap();
    value["extra"] = json!(1);
    assert!(extract(&value.to_string()).is_err());
}

#[test]
fn refuses_a_fix_check_receipt_with_a_wrong_outcome() {
    let mut value: Value = serde_json::from_str(&fix_check_receipt()).unwrap();
    value["outcome"] = json!("fix_verified");
    assert!(extract(&value.to_string()).is_err());
}

#[test]
fn reproduce_predicate_copies_receipt_fields() {
    let extracted = extract(&reproduce_receipt()).unwrap();
    let p = &extracted.predicate;
    assert_eq!(p["receipt_kind"], "reproduce");
    assert_eq!(p["vettalon_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(p["receipt_version"], 1);
    assert_eq!(p["outcome"], "inconclusive");
    assert_eq!(p["reason"], "sandbox_unavailable");
    assert_eq!(p["target_file"], "src/app.py");
    assert_eq!(p["target_function"], "run");
    assert_eq!(p["target_plan_sha256"], sha256_hex(b"plan"));
    assert!(p.get("image_id").is_none(), "null fields are left out");
    assert!(p.get("verdict").is_none());
}

fn replay_run(index: u32, outcome: &str) -> Value {
    let phases: Vec<Value> = ["target", "benign_control", "fresh_nonce_rerun"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            json!({
                "name": name, "nonce_commitment": "a".repeat(64),
                "effect": outcome == "effect_observed" && index != 1,
                "functional": null, "exit_code": 0, "transcript_sha256": null,
                "elapsed_ms": 1,
                "reason": if outcome == "inconclusive" { Some("phase_incomplete") } else { None },
            })
        })
        .collect();
    json!({"index": index, "outcome": outcome, "reason": null, "phases": phases})
}

fn add_verification_event(receipt: &mut Value) {
    use crate::audit::verification::{
        CompileInput, HostObservations, VerificationEvent, compile_ir,
    };
    use vettalon_contract::verification::{BackendKind, CleanupState, ReplayGrade};
    let runtime = receipt.get("runtime").map(|value| {
        serde_json::from_value::<crate::audit::target_poc::NodeRuntime>(value.clone())
            .unwrap()
            .identity()
    });
    for (key, value) in [
        ("source_sha256", "a".repeat(64)),
        ("target_file_sha256", "b".repeat(64)),
        ("target_plan_sha256", "c".repeat(64)),
        ("adapter_sha256", "d".repeat(64)),
    ] {
        if receipt[key].is_null() {
            receipt[key] = json!(value);
        }
    }
    let adapter = receipt["adapter_sha256"].as_str().unwrap();
    let harness = if runtime.is_some() {
        crate::audit::target_poc::node_harness_sha256(
            crate::audit::poc_oracle::OracleClass::CommandInjection,
            adapter,
        )
    } else {
        crate::audit::target_poc::target_harness_sha256(
            crate::audit::poc_oracle::OracleClass::CommandInjection,
            adapter,
        )
    };
    if runtime.is_some() {
        receipt["harness_sha256"] = json!(harness);
    }
    let ir = compile_ir(&CompileInput {
        runtime,
        finding_id: "F-1".into(),
        file: receipt["target_file"].as_str().unwrap().into(),
        line: None,
        symbol: "run".into(),
        cwe: "CWE-78".into(),
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
            effect_observed: Some(receipt["outcome"] == "effect_observed"),
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

fn reproduce_v2_receipt(outcome: &str, run_outcomes: &[&str]) -> String {
    let runs: Vec<Value> = run_outcomes
        .iter()
        .enumerate()
        .map(|(i, o)| replay_run(i as u32, o))
        .collect();
    let count = |o: &str| run_outcomes.iter().filter(|x| **x == o).count();
    let receipt = json!({
        "version": 2,
        "outcome": outcome,
        "phases": runs.first().map(|run| run["phases"].clone()).unwrap_or(json!([])),
        "target_file": "src/app.py",
        "target_function": "run",
        "target_plan_sha256": null,
        "target_file_sha256": null,
        "source_sha256": null,
        "exclusions": null,
        "adapter_sha256": null,
        "image_id": null,
        "reason": null,
        "replays": {
            "requested": run_outcomes.len(),
            "completed": run_outcomes.len(),
            "observed": count("effect_observed"),
            "absent": count("effect_absent"),
            "inconclusive": count("inconclusive"),
            "runs": runs
        }
    });
    receipt.to_string()
}

#[test]
fn reproduce_v2_predicate_carries_the_replay_counts() {
    let raw = reproduce_v2_receipt("effect_absent", &["effect_absent"; 3]);
    let extracted = extract(&raw).unwrap();
    let p = &extracted.predicate;
    assert_eq!(extracted.kind, ReceiptKind::Reproduce);
    assert_eq!(p["receipt_version"], 2);
    assert_eq!(p["replays_requested"], 3);
    assert_eq!(p["replays_completed"], 3);
    assert_eq!(p["replays_observed"], 0);
    // v1 predicates have no replay fields.
    let v1 = extract(&reproduce_receipt()).unwrap().predicate;
    assert!(v1.get("replays_requested").is_none());
    // A changed count in the predicate no longer matches a fresh extraction.
    let mut altered = extracted.predicate.clone();
    altered["replays_observed"] = json!(3);
    assert_ne!(altered, extract(&raw).unwrap().predicate);
}

#[test]
fn reproduce_v2_receipt_whose_replays_disagree_with_its_outcome_is_refused() {
    let lie = reproduce_v2_receipt("effect_observed", &["effect_observed", "effect_absent"]);
    assert!(extract(&lie).is_err());
    let ok = reproduce_v2_receipt("inconclusive", &["effect_observed", "effect_absent"]);
    assert!(extract(&ok).is_ok());
}

fn retest_report(status: &str, receipt_outcome: &str) -> String {
    let mut summary = json!({
        "still_observed": 0, "not_observed": 0, "inconclusive": 0,
        "environment_unavailable": 0, "target_missing": 0,
        "not_reproducible_before": 0, "retest_cap_reached": 0
    });
    summary[status] = json!(1);
    let mut receipt: Value = serde_json::from_str(&reproduce_v2_receipt(
        receipt_outcome,
        &[receipt_outcome; 2],
    ))
    .unwrap();
    add_verification_event(&mut receipt);
    json!({
        "version": 1,
        "repo": "/tmp/repo",
        "old_report_sha256": sha256_hex(b"old"),
        "old_repo_commit": null,
        "new_repo_commit": null,
        "new_tree_clean": null,
        "replays": 2,
        "results": [{
            "finding_id": "F-1",
            "title": "t",
            "cwe": null,
            "status": status,
            "reason": null,
            "old_file_sha256": receipt["target_file_sha256"],
            "new_file_sha256": receipt["target_file_sha256"],
            "rebound": false,
            "receipt": receipt
        }],
        "summary": summary
    })
    .to_string()
}

#[test]
fn detects_a_retest_report_and_checks_it_against_its_receipts() {
    let raw = retest_report("still_observed", "effect_observed");
    let extracted = extract(&raw).unwrap();
    assert_eq!(extracted.kind, ReceiptKind::Retest);
    assert_eq!(
        extracted.kind.predicate_type(),
        "https://vettalon.dudustudio.monster/attestation/retest/v2"
    );
    let p = &extracted.predicate;
    assert_eq!(p["receipt_kind"], "retest");
    assert_eq!(p["summary"]["still_observed"], 1);
    assert_eq!(p["results"][0]["replays_observed"], 2);
    // Status that its receipt does not support: refused.
    assert!(extract(&retest_report("not_observed", "effect_observed")).is_err());
    // Summary that does not match the results: refused.
    let mut value: Value = serde_json::from_str(&raw).unwrap();
    value["summary"]["still_observed"] = json!(0);
    assert!(extract(&value.to_string()).is_err());
}

/// Package rule 1: a run status without the receipt it claims is refused.
#[test]
fn retest_run_status_without_a_receipt_is_refused() {
    for (status, outcome) in [
        ("still_observed", "effect_observed"),
        ("not_observed", "effect_absent"),
    ] {
        let mut value: Value = serde_json::from_str(&retest_report(status, outcome)).unwrap();
        assert!(extract(&value.to_string()).is_ok(), "{status}");
        value["results"][0]["receipt"] = Value::Null;
        let error = extract(&value.to_string()).unwrap_err();
        assert!(error.contains("carries no receipt"), "{status}: {error}");
    }
    // Statuses that never ran keep accepting a missing receipt.
    let mut value: Value =
        serde_json::from_str(&retest_report("not_observed", "effect_absent")).unwrap();
    value["results"][0]["status"] = json!("not_reproducible_before");
    value["results"][0]["reason"] = json!("no_target_plan");
    value["results"][0]["receipt"] = Value::Null;
    value["summary"]["not_observed"] = json!(0);
    value["summary"]["not_reproducible_before"] = json!(1);
    assert!(extract(&value.to_string()).is_ok());
}

#[tokio::test]
async fn sign_refuses_malformed_retest_hash_and_revision_fields() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("cosign.key");
    let file = dir.path().join("retest.json");
    std::fs::write(&key, "placeholder").unwrap();
    for field in ["old_report_sha256", "old_repo_commit", "new_repo_commit"] {
        for bad in [
            "".to_owned(),
            "a".repeat(39),
            "a".repeat(65),
            "g".repeat(64),
            "A".repeat(64),
        ] {
            let mut value: Value =
                serde_json::from_str(&retest_report("not_observed", "effect_absent")).unwrap();
            value[field] = json!(bad);
            let raw = value.to_string();
            let error = extract(&raw).unwrap_err();
            assert!(error.contains(field), "{field}: {error}");
            std::fs::write(&file, raw).unwrap();
            let error = sign_receipt(&file, &key, None).await.unwrap_err();
            assert!(error.contains("receipt refused"), "{field}: {error}");
            assert!(error.contains(field), "{field}: {error}");
            assert!(!default_bundle_path(&file).exists());
        }
    }
}

#[test]
fn retest_signing_accepts_full_revision_formats_and_absent_revisions() {
    for commit in [Value::Null, json!("a".repeat(40)), json!("b".repeat(64))] {
        let mut value: Value =
            serde_json::from_str(&retest_report("not_observed", "effect_absent")).unwrap();
        value["old_repo_commit"] = commit.clone();
        value["new_repo_commit"] = commit;
        assert!(extract(&value.to_string()).is_ok());
    }
}

#[tokio::test]
async fn sign_refuses_a_retest_run_status_without_a_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("cosign.key");
    std::fs::write(&key, "placeholder").unwrap();
    let mut value: Value =
        serde_json::from_str(&retest_report("not_observed", "effect_absent")).unwrap();
    value["results"][0]["receipt"] = Value::Null;
    let file = dir.path().join("retest.json");
    std::fs::write(&file, value.to_string()).unwrap();
    let error = sign_receipt(&file, &key, None).await.unwrap_err();
    assert!(error.contains("receipt refused"), "{error}");
    assert!(error.contains("carries no receipt"), "{error}");
    assert!(!default_bundle_path(&file).exists());
}

#[tokio::test]
async fn sign_refuses_a_completed_retest_relabelled_as_cap_reached() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("cosign.key");
    std::fs::write(&key, "placeholder").unwrap();
    let mut value: Value =
        serde_json::from_str(&retest_report("still_observed", "effect_observed")).unwrap();
    value["results"][0]["status"] = json!("retest_cap_reached");
    value["results"][0]["reason"] = json!("deadline_exceeded");
    value["summary"]["still_observed"] = json!(0);
    value["summary"]["retest_cap_reached"] = json!(1);
    let file = dir.path().join("retest.json");
    std::fs::write(&file, value.to_string()).unwrap();
    let error = sign_receipt(&file, &key, None).await.unwrap_err();
    assert!(error.contains("receipt refused"), "{error}");
    assert!(error.contains("status or reason"), "{error}");
    assert!(!default_bundle_path(&file).exists());
}

#[test]
fn fix_check_predicate_copies_receipt_fields() {
    let raw = fix_check_receipt();
    let receipt: Value = serde_json::from_str(&raw).unwrap();
    let extracted = extract(&raw).unwrap();
    let p = &extracted.predicate;
    assert_eq!(p["receipt_kind"], "fix_check");
    assert_eq!(p["vettalon_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(p["outcome"], receipt["outcome"]);
    assert_eq!(p["diff_sha256"], sha256_hex(b"diff"));
    assert_eq!(p["check"]["regression"], "pass");
    assert_eq!(p["check"]["inputs_total"], 1);
    assert!(p.get("variant_set_sha256").is_none());
}

#[test]
fn predicate_types_follow_the_kind() {
    assert_eq!(
        ReceiptKind::Reproduce.predicate_type(),
        "https://vettalon.dudustudio.monster/attestation/reproduce/v1"
    );
    assert_eq!(
        ReceiptKind::FixCheck.predicate_type(),
        "https://vettalon.dudustudio.monster/attestation/fix-check/v1"
    );
}

#[test]
fn canonical_bytes_are_sorted_compact_and_deterministic() {
    let a = json!({"b": 1, "a": {"d": [2, 1], "c": "x"}});
    let b: Value = serde_json::from_str(r#"{"a":{"c":"x","d":[2,1]},"b":1}"#).unwrap();
    let bytes = canonical_bytes(&a).unwrap();
    assert_eq!(bytes, canonical_bytes(&b).unwrap());
    assert_eq!(bytes, br#"{"a":{"c":"x","d":[2,1]},"b":1}"#);
}

#[test]
fn statement_is_v1_with_one_subject_over_the_receipt_bytes() {
    let f = fixture();
    let s = &f.statement;
    assert_eq!(s["_type"], STATEMENT_TYPE_V1);
    assert_eq!(s["subject"].as_array().unwrap().len(), 1);
    assert_eq!(s["subject"][0]["name"], "receipt.json");
    assert_eq!(
        s["subject"][0]["digest"]["sha256"],
        sha256_hex(f.receipt.as_bytes())
    );
    assert_eq!(s["predicateType"], ReceiptKind::Reproduce.predicate_type());
    let again = fixture();
    assert_eq!(
        canonical_bytes(&f.statement).unwrap(),
        canonical_bytes(&again.statement).unwrap()
    );
}

#[test]
fn accepts_the_statement_it_built() {
    let f = fixture();
    f.check(&f.statement).unwrap();
    check_bundle(
        &bundle_for(&f.statement),
        f.receipt.as_bytes(),
        ReceiptKind::Reproduce,
        &f.predicate,
    )
    .unwrap();
}

#[test]
fn accepts_a_different_vettalon_version_only() {
    let f = fixture();
    let mut statement = f.statement.clone();
    statement["predicate"]["vettalon_version"] = json!("0.0.1");
    f.check(&statement).unwrap();
    statement["predicate"]["vettalon_version"] = json!("");
    assert!(f.check(&statement).is_err());
}

#[test]
fn rejects_a_wrong_subject_digest() {
    let f = fixture();
    let mut statement = f.statement.clone();
    statement["subject"][0]["digest"]["sha256"] = json!(sha256_hex(b"other"));
    assert!(f.check(&statement).unwrap_err().contains("sha256"));
    let changed = check_statement(
        &f.statement,
        b"changed receipt bytes",
        ReceiptKind::Reproduce,
        &f.predicate,
    );
    assert!(changed.is_err());
}

#[test]
fn rejects_two_subjects() {
    let f = fixture();
    let mut statement = f.statement.clone();
    let entry = statement["subject"][0].clone();
    statement["subject"].as_array_mut().unwrap().push(entry);
    assert!(
        f.check(&statement)
            .unwrap_err()
            .contains("exactly one subject")
    );
}

#[test]
fn rejects_zero_subjects() {
    let f = fixture();
    let mut statement = f.statement.clone();
    statement["subject"] = json!([]);
    assert!(
        f.check(&statement)
            .unwrap_err()
            .contains("exactly one subject")
    );
}

#[test]
fn rejects_a_wrong_predicate_type() {
    let f = fixture();
    let mut statement = f.statement.clone();
    statement["predicateType"] = json!(ReceiptKind::FixCheck.predicate_type());
    assert!(f.check(&statement).unwrap_err().contains("predicateType"));
}

#[test]
fn rejects_an_altered_predicate() {
    let f = fixture();
    let mut statement = f.statement.clone();
    statement["predicate"]["outcome"] = json!("effect_observed");
    assert!(f.check(&statement).unwrap_err().contains("predicate"));
    let mut extra = f.statement.clone();
    extra["predicate"]["extra"] = json!(true);
    assert!(f.check(&extra).is_err());
}

#[test]
fn rejects_a_wrong_statement_type() {
    let f = fixture();
    let mut statement = f.statement.clone();
    statement["_type"] = json!("https://example.com/Statement/v1");
    assert!(f.check(&statement).unwrap_err().contains("_type"));
}

#[test]
fn rejects_a_statement_with_extra_or_missing_top_level_fields() {
    let f = fixture();
    let mut extra = f.statement.clone();
    extra["extra"] = json!(1);
    assert!(f.check(&extra).is_err());
    let mut missing = f.statement.clone();
    missing.as_object_mut().unwrap().remove("predicate");
    assert!(f.check(&missing).is_err());
    assert!(f.check(&json!([])).is_err());
}

#[test]
fn rejects_an_oversized_bundle() {
    let f = fixture();
    let big = vec![b' '; BUNDLE_MAX_BYTES + 1];
    let error = check_bundle(
        &big,
        f.receipt.as_bytes(),
        ReceiptKind::Reproduce,
        &f.predicate,
    )
    .unwrap_err();
    assert!(error.contains("larger"), "{error}");
}

#[test]
fn rejects_a_non_base64_payload() {
    let f = fixture();
    for payload in ["not base64!!", "abc", "ab=c", "_-_-", ""] {
        let error = check_bundle(
            &bundle_with_payload(payload),
            f.receipt.as_bytes(),
            ReceiptKind::Reproduce,
            &f.predicate,
        )
        .unwrap_err();
        assert!(error.contains("base64"), "{payload:?}: {error}");
    }
}

#[test]
fn rejects_a_payload_that_is_not_json() {
    let f = fixture();
    let error = check_bundle(
        &bundle_with_payload(&b64(b"hello")),
        f.receipt.as_bytes(),
        ReceiptKind::Reproduce,
        &f.predicate,
    )
    .unwrap_err();
    assert!(error.contains("not JSON"), "{error}");
}

#[test]
fn rejects_bundles_without_a_dsse_envelope_or_with_another_payload_type() {
    let f = fixture();
    let check = |bundle: Value| {
        check_bundle(
            bundle.to_string().as_bytes(),
            f.receipt.as_bytes(),
            ReceiptKind::Reproduce,
            &f.predicate,
        )
    };
    assert!(check(json!({"messageSignature": {}})).is_err());
    let mut other_type = f.valid_bundle();
    other_type["dsseEnvelope"]["payloadType"] = json!("text/plain");
    assert!(check(other_type).unwrap_err().contains("payloadType"));
    let mut no_payload = f.valid_bundle();
    no_payload["dsseEnvelope"]
        .as_object_mut()
        .unwrap()
        .remove("payload");
    assert!(check(no_payload).unwrap_err().contains("no payload"));
    let mut no_envelope = f.valid_bundle();
    no_envelope.as_object_mut().unwrap().remove("dsseEnvelope");
    assert!(check(no_envelope).unwrap_err().contains("no dsseEnvelope"));
    assert!(
        check_bundle(
            b"garbage",
            f.receipt.as_bytes(),
            ReceiptKind::Reproduce,
            &f.predicate
        )
        .is_err()
    );
}

#[test]
fn strict_base64_round_trips_and_rejects_loose_input() {
    for sample in [&b"f"[..], b"fo", b"foo", b"foob", b"\xff\xfe\x00"] {
        assert_eq!(decode_base64_strict(&b64(sample)).unwrap(), sample);
    }
    assert!(decode_base64_strict("Zm9v\n").is_none());
    assert!(
        decode_base64_strict("Zm9=").is_none(),
        "non-zero trailing bits"
    );
    assert!(
        decode_base64_strict("Zg==Zg==").is_none(),
        "padding in the middle"
    );
    assert!(decode_base64_strict("Zm-_").is_none(), "URL alphabet");
}

#[test]
fn cosign_version_parsing() {
    for (version, images, receipts) in [
        ("v2.6.1", false, false),
        ("v2.6.2", true, false),
        ("v3.0.3", false, false),
        ("v3.0.4", true, true),
        ("v3.1.3", true, true),
        ("v4.0.0", false, false),
        ("v3.0.4-rc.1", false, false),
        ("v3.0.4+build", false, false),
        ("v3.00.4", false, false),
        ("v3.0.4294967296", false, false),
    ] {
        let output = format!("GitVersion: {version}\n");
        assert_eq!(
            super::cosign::require_image_version(&output).is_ok(),
            images,
            "{version}"
        );
        assert_eq!(
            require_supported_version(&output).is_ok(),
            receipts,
            "{version}"
        );
        assert_eq!(
            super::cosign::require_release_version(version).is_ok(),
            receipts,
            "stored {version}"
        );
    }
    for version in ["v3.0.4", "v3.1.3", "v3.12.123"] {
        assert_eq!(
            require_supported_version(&format!("GitVersion:    {version}\n")),
            Ok(version.into())
        );
        assert_eq!(
            super::cosign::require_release_version(version),
            Ok(version.into())
        );
    }
    for version in [
        "v2.6.1",
        "v2.6.2",
        "v2.6.5",
        "v3.0.3",
        "v3",
        "v3.foo",
        "v3.0.0-rc.1",
        "v30.0.0",
        "v3.0.0+build",
        "v3.1",
        "v3..0",
        "v3.1.2.3",
        "v3.01.0",
        "v03.1.0",
        "v3.0.00",
        "v3.1.+1",
        "v3.１.0",
        "3.1.3",
        "v3.0.0 trailing",
        "",
    ] {
        assert!(
            require_supported_version(&format!("GitVersion: {version}\n")).is_err(),
            "{version:?}"
        );
        assert!(
            super::cosign::require_release_version(version).is_err(),
            "{version:?}"
        );
    }
    for version in ["v3.0.0\nextra", "v3.0.0\r", " v3.0.0", "v3.0.0 "] {
        assert!(
            super::cosign::require_release_version(version).is_err(),
            "{version:?}"
        );
    }
    for garbage in ["", "hello", "GitVersion:\n", "GitVersion: vX.1\n"] {
        assert!(require_supported_version(garbage).is_err(), "{garbage:?}");
    }
}

#[test]
fn default_bundle_path_appends_a_suffix() {
    let path = default_bundle_path(std::path::Path::new("dir/receipt.json"));
    assert_eq!(
        path,
        std::path::PathBuf::from("dir/receipt.json.sigstore.json")
    );
}

#[tokio::test]
async fn sign_refuses_to_overwrite_an_existing_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let receipt = root.join("receipt.json");
    std::fs::write(&receipt, reproduce_receipt()).unwrap();
    let bundle = root.join("receipt.json.sigstore.json");
    std::fs::write(&bundle, "existing").unwrap();
    let key = root.join("cosign.key");
    std::fs::write(&key, "placeholder").unwrap();
    let shown = bundle.display().to_string();
    let error = sign_receipt(&receipt, &key, None).await.unwrap_err();
    assert!(error.contains("already exists"), "{error}");
    assert!(error.contains(&shown), "{error}");
    assert_eq!(std::fs::read_to_string(&bundle).unwrap(), "existing");
    let explicit = sign_receipt(&receipt, &key, Some(&bundle))
        .await
        .unwrap_err();
    assert!(explicit.contains("already exists"), "{explicit}");
    assert!(explicit.contains(&shown), "{explicit}");
    assert_eq!(std::fs::read_to_string(&bundle).unwrap(), "existing");
}

#[tokio::test]
async fn sign_refuses_a_file_that_is_not_a_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("other.json");
    std::fs::write(&file, r#"{"hello":"world"}"#).unwrap();
    let key = dir.path().join("cosign.key");
    std::fs::write(&key, "placeholder").unwrap();
    let error = sign_receipt(&file, &key, None).await.unwrap_err();
    assert!(error.contains("receipt refused"), "{error}");
    assert!(!dir.path().join("other.json.sigstore.json").exists());
}

#[test]
fn accepts_the_cosign_v3_bundle_layout() {
    let f = fixture();
    f.check_value(&f.valid_bundle()).unwrap();
}

#[test]
fn rejects_a_bundle_with_an_unknown_top_level_key() {
    let f = fixture();
    let mut bundle = f.valid_bundle();
    bundle["timestampVerificationData"] = json!({});
    let error = f.check_value(&bundle).unwrap_err();
    assert!(error.contains("unknown field"), "{error}");
}

#[test]
fn rejects_a_bundle_with_a_wrong_or_missing_media_type() {
    let f = fixture();
    for media_type in [
        json!("application/vnd.dev.sigstore.bundle+json;version=0.2"),
        json!("application/vnd.dev.sigstore.bundle+json;version=0.1"),
        json!("application/vnd.dev.sigstore.bundle.v0.4+json"),
        json!("application/vnd.dev.sigstore.bundle.v0.3+json "),
        json!(""),
        json!(3),
    ] {
        let mut bundle = f.valid_bundle();
        bundle["mediaType"] = media_type.clone();
        assert!(f.check_value(&bundle).is_err(), "{media_type}");
    }
    let mut missing = f.valid_bundle();
    missing.as_object_mut().unwrap().remove("mediaType");
    assert!(f.check_value(&missing).is_err());
}

#[test]
fn rejects_a_bundle_without_verification_material() {
    let f = fixture();
    let mut bundle = f.valid_bundle();
    let object = bundle.as_object_mut().unwrap();
    object.remove("verificationMaterial");
    assert!(f.check_value(&bundle).is_err());
    bundle["verificationMaterial"] = json!(null);
    assert!(f.check_value(&bundle).is_err());
}

#[test]
fn rejects_a_bundle_with_two_dsse_envelopes() {
    let f = fixture();
    let valid = f.valid_bundle();
    let envelope = valid["dsseEnvelope"].to_string();
    let material = valid["verificationMaterial"].to_string();
    let media = BUNDLE_MEDIA_TYPE_V03;
    let head = format!(r#""mediaType":"{media}","verificationMaterial":{material}"#);
    let raw = format!(r#"{{{head},"dsseEnvelope":{envelope},"dsseEnvelope":{envelope}}}"#);
    let error = f.check_raw_bundle(raw.as_bytes()).unwrap_err();
    assert!(error.contains("duplicate"), "{error}");
}

#[test]
fn rejects_a_duplicate_key_inside_the_envelope_or_verification_material() {
    let f = fixture();
    let valid = f.valid_bundle();
    let payload = valid["dsseEnvelope"]["payload"].as_str().unwrap();
    let media = BUNDLE_MEDIA_TYPE_V03;
    let material = valid["verificationMaterial"].to_string();
    let envelope = format!(
        r#"{{"payloadType":"text/plain","payload":"{payload}","payloadType":"{DSSE_PAYLOAD_TYPE}","signatures":[{{"sig":"AAAA"}}]}}"#
    );
    let raw = format!(
        r#"{{"mediaType":"{media}","verificationMaterial":{material},"dsseEnvelope":{envelope}}}"#
    );
    let error = f.check_raw_bundle(raw.as_bytes()).unwrap_err();
    assert!(error.contains("duplicate"), "{error}");
    // Nested, in verificationMaterial.
    let envelope = valid["dsseEnvelope"].to_string();
    let raw = format!(
        r#"{{"mediaType":"{media}","verificationMaterial":{{"publicKey":{{"hint":"a","hint":"b"}}}},"dsseEnvelope":{envelope}}}"#
    );
    let error = f.check_raw_bundle(raw.as_bytes()).unwrap_err();
    assert!(error.contains("duplicate"), "{error}");
}

/// The Statement inside the DSSE payload is parsed as strictly as the
/// envelope: a repeated key is refused, even when the last copy (the one a
/// last-key-wins parser keeps) is valid.
#[test]
fn rejects_a_duplicate_key_inside_the_dsse_payload_statement() {
    let f = fixture();
    let statement = f.statement.to_string();
    f.check_raw_bundle(&bundle_with_payload(&b64(statement.as_bytes())))
        .unwrap();
    let top = statement.replacen('{', r#"{"predicateType":"https://example.com/other","#, 1);
    let (digest_key, _) = f.statement["subject"][0]["digest"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap();
    let nested = statement.replacen(
        r#""digest":{"#,
        &format!(r#""digest":{{"{digest_key}":"00","#),
        1,
    );
    assert_ne!(nested, statement);
    for tampered in [top, nested] {
        let bundle = bundle_with_payload(&b64(tampered.as_bytes()));
        let error = f.check_raw_bundle(&bundle).unwrap_err();
        assert!(error.contains("duplicate"), "{error}");
    }
}

#[tokio::test]
async fn verify_refuses_a_malformed_bundle_before_running_cosign() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = dir.path().join("receipt.json");
    std::fs::write(&receipt, reproduce_receipt()).unwrap();
    let key = dir.path().join("cosign.pub");
    std::fs::write(&key, "placeholder").unwrap();
    let bundle = dir.path().join("receipt.json.sigstore.json");
    std::fs::write(&bundle, "{}").unwrap();
    match verify_receipt(&receipt, &key, &bundle).await {
        Err(AttestError::Refused(error)) => assert!(error.contains("bundle refused"), "{error}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn rejects_a_bundle_with_a_message_signature() {
    let f = fixture();
    let mut bundle = f.valid_bundle();
    bundle["messageSignature"] = json!({"messageDigest": {}, "signature": "AAAA"});
    let error = f.check_value(&bundle).unwrap_err();
    assert!(error.contains("messageSignature"), "{error}");
    let mut only = f.valid_bundle();
    only.as_object_mut().unwrap().remove("dsseEnvelope");
    only["messageSignature"] = json!(null);
    let error = f.check_value(&only).unwrap_err();
    assert!(error.contains("messageSignature"), "{error}");
}

#[test]
fn rejects_a_bundle_that_is_not_an_object() {
    let f = fixture();
    assert!(f.check_raw_bundle(b"[]").is_err());
    assert!(f.check_raw_bundle(b"\"bundle\"").is_err());
}

#[test]
fn password_hint_only_for_a_decryption_problem() {
    for stderr in [
        "cosign attest-blob failed (exit Some(1)): reading key: decrypt: decryption failed",
        "cosign attest-blob failed (exit Some(1)): error reading password: no tty",
        "cosign attest-blob failed (exit Some(1)): incorrect Passphrase",
    ] {
        let message = sign_failure(CosignError::Rejected(stderr.into()));
        assert!(message.contains(PASSWORD_HINT), "{message}");
        assert!(message.starts_with(stderr));
    }
    // A path that merely contains "password" is not a password problem.
    for stderr in [
        "cosign attest-blob failed (exit Some(1)): open /home/u/passwords/cosign.key: no such file",
        "cosign attest-blob failed (exit Some(1)): open /home/u/.passphrase/key: permission denied",
    ] {
        let message = sign_failure(CosignError::Rejected(stderr.into()));
        assert_eq!(message, stderr);
    }
    let other = "cosign attest-blob failed (exit Some(1)): open predicate: no such file";
    let message = sign_failure(CosignError::Rejected(other.into()));
    assert_eq!(message, other);
    assert!(!message.contains("COSIGN_PASSWORD"));
    let unavailable = sign_failure(CosignError::Unavailable("cosign was not found".into()));
    assert_eq!(unavailable, "cosign was not found");
}

const REMOTE_KEYS: [&str; 14] = [
    "https://example.com/cosign.pub",
    "http://127.0.0.1:9/cosign.key",
    "evil://x",
    "env://COSIGN_KEY",
    "k8s://ns/secret",
    "hashivault://key",
    "awskms:///arn:aws:kms:us-east-1:1:key/1",
    "gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k",
    "azurekms://vault.vault.azure.net/key",
    "pkcs11:token=t;object=o",
    "PKCS11:token=t",
    "env:COSIGN_KEY",
    "awskms:alias",
    "custom+scheme:anything",
];

#[test]
fn key_argument_refuses_remote_kms_and_token_references() {
    for key in REMOTE_KEYS {
        let path = std::path::Path::new(key);
        let error = key_argument(path, "private key").unwrap_err();
        assert!(error.contains("must be a local key file"), "{key}: {error}");
    }
    assert!(key_argument(std::path::Path::new(""), "public key").is_err());
}

#[test]
fn key_argument_requires_an_existing_regular_file_and_returns_an_absolute_path() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.key");
    let error = key_argument(&missing, "private key").unwrap_err();
    assert!(error.contains("cannot be resolved"), "{error}");
    let error = key_argument(dir.path(), "private key").unwrap_err();
    assert!(error.contains("regular file"), "{error}");
    let key = dir.path().join("cosign.key");
    std::fs::write(&key, "not read").unwrap();
    let resolved = key_argument(&key, "private key").unwrap();
    let expected = std::fs::canonicalize(&key).unwrap();
    assert_eq!(std::path::Path::new(&resolved), expected);
    assert!(std::path::Path::new(&resolved).is_absolute());
}

#[cfg(unix)]
#[test]
fn key_argument_resolves_a_symlink_to_a_regular_file_but_not_to_a_fifo() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("cosign.key");
    std::fs::write(&key, "not read").unwrap();
    let link = dir.path().join("link.key");
    std::os::unix::fs::symlink(&key, &link).unwrap();
    let resolved = key_argument(&link, "private key").unwrap();
    assert_eq!(
        std::path::Path::new(&resolved),
        std::fs::canonicalize(&key).unwrap()
    );
    let fifo = dir.path().join("fifo.key");
    make_fifo(&fifo);
    let error = key_argument(&fifo, "private key").unwrap_err();
    assert!(error.contains("regular file"), "{error}");
    let fifo_link = dir.path().join("fifo-link.key");
    std::os::unix::fs::symlink(&fifo, &fifo_link).unwrap();
    let error = key_argument(&fifo_link, "public key").unwrap_err();
    assert!(error.contains("regular file"), "{error}");
}

#[cfg(unix)]
fn make_fifo(path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `path` is a valid NUL-terminated string for the whole call.
    let rc = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
}

#[cfg(unix)]
#[test]
fn read_regular_capped_refuses_a_fifo_and_a_symlink_without_blocking() {
    use crate::remediation::read_regular_capped;

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("receipt.json");
    make_fifo(&fifo);
    let error = read_regular_capped(&fifo, 1024, "receipt").unwrap_err();
    assert!(error.contains("regular non-symlink file"), "{error}");
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&fifo, &link).unwrap();
    assert!(read_regular_capped(&link, 1024, "receipt").is_err());
    let file = dir.path().join("real.json");
    std::fs::write(&file, "{}").unwrap();
    assert_eq!(read_regular_capped(&file, 1024, "receipt").unwrap(), "{}");
    assert!(read_regular_capped(&file, 1, "receipt").is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn sign_and_verify_refuse_a_fifo_receipt_or_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("receipt.json");
    make_fifo(&fifo);
    let key = dir.path().join("cosign.key");
    std::fs::write(&key, "not read").unwrap();
    let out = dir.path().join("out.sigstore.json");
    assert!(sign_receipt(&fifo, &key, Some(&out)).await.is_err());
    let receipt = dir.path().join("real.json");
    std::fs::write(&receipt, reproduce_receipt()).unwrap();
    let bundle_fifo = dir.path().join("bundle.json");
    make_fifo(&bundle_fifo);
    let result = verify_receipt(&receipt, &key, &bundle_fifo).await;
    assert!(matches!(result, Err(AttestError::Refused(_))), "{result:?}");
}

#[tokio::test]
async fn sign_refuses_remote_keys_before_running_cosign() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = dir.path().join("receipt.json");
    std::fs::write(&receipt, reproduce_receipt()).unwrap();
    for key in REMOTE_KEYS {
        let path = std::path::Path::new(key);
        let error = sign_receipt(&receipt, path, None).await.unwrap_err();
        assert!(error.contains("must be a local key file"), "{key}: {error}");
    }
    let missing = dir.path().join("missing.key");
    let error = sign_receipt(&receipt, &missing, None).await.unwrap_err();
    assert!(error.contains("cannot be resolved"), "{error}");
    assert!(!dir.path().join("receipt.json.sigstore.json").exists());
}

#[tokio::test]
async fn verify_refuses_remote_or_missing_keys_before_running_cosign() {
    let dir = tempfile::tempdir().unwrap();
    let receipt = dir.path().join("receipt.json");
    std::fs::write(&receipt, reproduce_receipt()).unwrap();
    let bundle = dir.path().join("receipt.json.sigstore.json");
    std::fs::write(&bundle, "{}").unwrap();
    for key in REMOTE_KEYS {
        let path = std::path::Path::new(key);
        match verify_receipt(&receipt, path, &bundle).await {
            Err(AttestError::Refused(error)) => {
                assert!(error.contains("must be a local key file"), "{key}: {error}");
            }
            other => panic!("{key}: expected a refusal, got {other:?}"),
        }
    }
    let missing = dir.path().join("missing.pub");
    match verify_receipt(&receipt, &missing, &bundle).await {
        Err(AttestError::Refused(error)) => assert!(error.contains("cannot be resolved")),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn node_runtime_metadata() -> Value {
    json!({
        "language": "javascript", "module_kind": "cjs", "export_kind": "named",
        "node_version": "v22.15.0", "lockfile_sha256": "a".repeat(64),
        "lockfile_summary_sha256": "b".repeat(64), "deps_sha256": "c".repeat(64),
        "fixture_sha256": "d".repeat(64), "driver": "sqlite3",
        "hook_bundle_sha256": "e".repeat(64)
    })
}

#[test]
fn python_predicate_bytes_remain_identical_for_both_receipt_kinds() {
    let version = env!("CARGO_PKG_VERSION");
    // The old fixture claimed effect_absent with empty phases and no oracle.
    // Use a valid event-bearing Python receipt; these event keys were already
    // emitted by the pre-validation predicate extractor.
    let adapter = "d".repeat(64);
    let source = "a".repeat(64);
    let file = "b".repeat(64);
    let plan = "c".repeat(64);
    let harness = crate::audit::target_poc::target_harness_sha256(
        crate::audit::poc_oracle::OracleClass::CommandInjection,
        &adapter,
    );
    let expected = format!(
        r#"{{"adapter_sha256":"{adapter}","harness_sha256":"{harness}","outcome":"effect_absent","policy_version":"verification-policy-v1","receipt_kind":"reproduce","receipt_version":2,"replays_completed":2,"replays_observed":0,"replays_requested":2,"source_sha256":"{source}","target_file":"src/app.py","target_file_sha256":"{file}","target_function":"run","target_plan_sha256":"{plan}","verdict":"effect_absent","verdict_failures":[],"vettalon_version":"{version}"}}"#
    );
    let mut receipt: Value = serde_json::from_str(&reproduce_v2_receipt(
        "effect_absent",
        &["effect_absent"; 2],
    ))
    .unwrap();
    add_verification_event(&mut receipt);
    let predicate = extract(&receipt.to_string()).unwrap().predicate;
    assert_eq!(canonical_bytes(&predicate).unwrap(), expected.as_bytes());
    let diff = sha256_hex(b"diff");
    let expected = format!(
        r#"{{"check":{{"blocker":"none","decoding_applicable":0,"decoding_blocked":0,"decoding_total":0,"diff_sha256":"{diff}","inputs_blocked":1,"inputs_total":1,"reason":null,"regression":"pass","tests":"not_run"}},"diff_sha256":"{diff}","outcome":"fix_unverified","receipt_kind":"fix_check","vettalon_version":"{version}"}}"#
    );
    assert_eq!(
        canonical_bytes(&extract(&fix_check_receipt()).unwrap().predicate).unwrap(),
        expected.as_bytes()
    );
}

#[test]
fn node_v3_predicate_carries_runtime_harness_and_per_replay_hook_counts() {
    let mut receipt: Value =
        serde_json::from_str(&reproduce_v2_receipt("inconclusive", &["inconclusive"; 2])).unwrap();
    receipt["version"] = json!(3);
    receipt["target_file"] = json!("src/app.js");
    receipt["runtime"] = node_runtime_metadata();
    receipt["harness_sha256"] = json!("f".repeat(64));
    let phases: Vec<Value> = [Some(true), Some(false), None]
        .into_iter()
        .enumerate()
        .map(|(index, reached)| {
            json!({
                "name": (["target", "benign_control", "fresh_nonce_rerun"][index]),
                "nonce_commitment": "a".repeat(64), "effect": false, "functional": null,
                "exit_code": 0, "transcript_sha256": null, "elapsed_ms": 1,
                "reason": "sink_not_reached", "reached": reached,
                "reach_source": "in_process_hook", "executable": true
            })
        })
        .collect();
    receipt["phases"] = json!(phases);
    for run in receipt["replays"]["runs"].as_array_mut().unwrap() {
        run["phases"] = json!(phases);
    }
    add_verification_event(&mut receipt);
    let extracted = extract(&receipt.to_string()).unwrap();
    let p = extracted.predicate;
    for key in [
        "language",
        "node_version",
        "lockfile_sha256",
        "lockfile_summary_sha256",
        "deps_sha256",
        "fixture_sha256",
        "hook_bundle_sha256",
    ] {
        assert_eq!(p[key], receipt["runtime"][key]);
    }
    assert_eq!(p["harness_sha256"], receipt["harness_sha256"]);
    assert_eq!(p["reach_source"], "in_process_hook");
    assert_eq!(
        p["replays_reached"],
        json!([
            {"index":0,"reached":1,"not_reached":1,"unknown":1},
            {"index":1,"reached":1,"not_reached":1,"unknown":1}
        ])
    );
    assert!(!p.to_string().contains("fixture_values"));
    assert_eq!(
        extracted.kind.predicate_type(),
        "https://vettalon.dudustudio.monster/attestation/reproduce/v1"
    );
    receipt["runtime"]["fixture_sha256"] = json!("1".repeat(64));
    add_verification_event(&mut receipt);
    assert_ne!(p, extract(&receipt.to_string()).unwrap().predicate);
    receipt["version"] = json!(2);
    assert!(extract(&receipt.to_string()).is_err());
}

#[test]
fn node_fix_predicate_carries_digests_and_diagnostic_reach_outside_check_hash() {
    let mut receipt: Value = serde_json::from_str(&fix_check_receipt()).unwrap();
    receipt["runtime"] = node_runtime_metadata();
    add_node_fix_binding(&mut receipt);
    receipt["reach_summary"] = json!({
        "reach_source":"in_process_hook", "diagnostic":true,
        "blocked_before_sink":2, "blocked_at_sink":3
    });
    let before = extract(&receipt.to_string()).unwrap().predicate;
    assert_eq!(
        before["fixture_sha256"],
        receipt["runtime"]["fixture_sha256"]
    );
    assert_eq!(
        before["hook_bundle_sha256"],
        receipt["runtime"]["hook_bundle_sha256"]
    );
    assert_eq!(before["reach_summary"], receipt["reach_summary"]);
    let run: crate::audit::fix_check::FixCheckRun =
        serde_json::from_value(receipt.clone()).unwrap();
    let check_sha256 = sha256_hex(run.check.to_detail().as_bytes());
    receipt["reach_summary"]["blocked_at_sink"] = json!(4);
    let after = extract(&receipt.to_string()).unwrap().predicate;
    assert_ne!(before, after);
    assert_eq!(before["check"], after["check"]);
    let run: crate::audit::fix_check::FixCheckRun =
        serde_json::from_value(receipt.clone()).unwrap();
    assert_eq!(check_sha256, sha256_hex(run.check.to_detail().as_bytes()));
    receipt["reach_summary"]["diagnostic"] = json!(false);
    assert!(extract(&receipt.to_string()).is_err());
}

fn add_node_fix_binding(receipt: &mut Value) {
    use crate::audit::verification_context::{
        NODE_HARNESS_VERSION, POLICY_VERSION, SOURCE_SCOPE, SnapshotDigest, SnapshotExclusions,
        VerificationContext,
    };
    let runtime: crate::audit::target_poc::NodeRuntime =
        serde_json::from_value(receipt["runtime"].clone()).unwrap();
    let check: crate::audit::fix_check::FixCheck =
        serde_json::from_value(receipt["check"].clone()).unwrap();
    let hash = "a".repeat(64);
    let digest = SnapshotDigest {
        sha256: hash.clone(),
        files: 1,
        entries: 1,
        bytes: 1,
    };
    receipt["binding"] = serde_json::to_value(VerificationContext {
        runtime: Some(runtime.identity()),
        version: 1,
        source_scope: SOURCE_SCOPE.into(),
        check_sha256: sha256_hex(check.to_detail().as_bytes()),
        diff_sha256: check.diff_sha256,
        target_file: "app.js".into(),
        target_file_sha256: hash.clone(),
        finding_file_sha256: Some(hash.clone()),
        original: digest.clone(),
        fixed: digest,
        exclusions: SnapshotExclusions::default(),
        adapter_sha256: hash.clone(),
        fixed_adapter_sha256: hash.clone(),
        target_plan_sha256: None,
        test_command_sha256: None,
        image_identity: Some(format!("sha256:{hash}")),
        harness_sha256: hash,
        harness_version: NODE_HARNESS_VERSION.into(),
        policy_version: POLICY_VERSION.into(),
    })
    .unwrap();
}

fn valid_node_receipt(outcome: &str) -> Value {
    let mut receipt: Value =
        serde_json::from_str(&reproduce_v2_receipt(outcome, &[outcome; 2])).unwrap();
    receipt["version"] = json!(3);
    receipt["target_file"] = json!("app.js");
    receipt["runtime"] = node_runtime_metadata();
    receipt["harness_sha256"] = json!("f".repeat(64));
    receipt["image_id"] = json!(format!("sha256:{}", "e".repeat(64)));
    for run in receipt["replays"]["runs"].as_array_mut().unwrap() {
        for phase in run["phases"].as_array_mut().unwrap() {
            phase["reached"] = json!(true);
            phase["reach_source"] = json!("in_process_hook");
            phase["executable"] = json!(true);
        }
    }
    receipt["phases"] = receipt["replays"]["runs"][0]["phases"].clone();
    add_verification_event(&mut receipt);
    receipt
}

#[test]
fn signing_rederives_every_replay_for_both_runtimes() {
    for good in [
        serde_json::from_str::<Value>(&reproduce_v2_receipt(
            "effect_absent",
            &["effect_absent"; 2],
        ))
        .unwrap(),
        valid_node_receipt("effect_absent"),
    ] {
        assert!(extract(&good.to_string()).is_ok());
        for mutation in 0..6 {
            let mut forged = good.clone();
            let run = &mut forged["replays"]["runs"][1];
            match mutation {
                0 => run["phases"] = json!([]),
                1 => run["phases"][1]["name"] = json!("target"),
                2 => run["phases"][1]["effect"] = json!(true),
                3 => run["phases"][2]["reason"] = json!("sink_not_reached"),
                4 => run["outcome"] = json!("inconclusive"),
                _ => {
                    forged["verification_event"] = Value::Null;
                    // Keep this a modern, unbound receipt. A Python receipt
                    // without either field is the supported legacy shape.
                    forged["harness_sha256"] = json!("f".repeat(64));
                }
            }
            assert!(extract(&forged.to_string()).is_err(), "mutation {mutation}");
            let mut report: Value =
                serde_json::from_str(&retest_report("not_observed", "effect_absent")).unwrap();
            report["results"][0]["receipt"] = forged;
            assert!(
                extract(&report.to_string()).is_err(),
                "retest mutation {mutation}"
            );
            report["results"][0]["status"] = json!("retest_cap_reached");
            report["summary"]["not_observed"] = json!(0);
            report["summary"]["retest_cap_reached"] = json!(1);
            assert!(
                extract(&report.to_string()).is_err(),
                "capped retest mutation {mutation}"
            );
        }
    }
}

#[test]
fn node_signing_rejects_unreached_phases_and_reach_only_sql_drivers() {
    for mutation in 0..5 {
        let mut receipt = valid_node_receipt("effect_absent");
        match mutation {
            0 => receipt["replays"]["runs"][1]["phases"][0]["reached"] = json!(false),
            1 => receipt["replays"]["runs"][1]["phases"][0]["reached"] = Value::Null,
            2 => receipt["runtime"]["driver"] = json!("pg"),
            3 => receipt["runtime"]["driver"] = json!("mysql2"),
            _ => receipt["replays"]["runs"][1]["phases"][1]["functional"] = json!(true),
        }
        assert!(
            extract(&receipt.to_string()).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn node_signing_requires_runtime_language_and_complete_execution_identity() {
    let good = valid_node_receipt("effect_absent");
    for mutation in 0..11 {
        let mut receipt = good.clone();
        match mutation {
            0 => receipt["runtime"] = Value::Null,
            1 => receipt["target_file"] = json!("app.py"),
            2 => receipt["runtime"]["language"] = json!("typescript"),
            3 => receipt["target_file"] = json!("app.ts"),
            4 => receipt["runtime"]["lockfile_sha256"] = Value::Null,
            5 => receipt["runtime"]["lockfile_summary_sha256"] = Value::Null,
            6 => receipt["image_id"] = Value::Null,
            7 => receipt["image_id"] = json!("node:latest"),
            8 => receipt["harness_sha256"] = Value::Null,
            9 => receipt["verification_event"]["ir"]["binding"]["runtime"] = Value::Null,
            _ => receipt["runtime"]["fixture_sha256"] = json!("1".repeat(64)),
        }
        assert!(
            extract(&receipt.to_string()).is_err(),
            "mutation {mutation}"
        );
    }
    let mut no_deps = good.clone();
    no_deps["runtime"]["deps_sha256"] = Value::Null;
    add_verification_event(&mut no_deps);
    assert!(extract(&no_deps.to_string()).is_ok());
    no_deps["runtime"]["lockfile_sha256"] = Value::Null;
    no_deps["runtime"]["lockfile_summary_sha256"] = Value::Null;
    add_verification_event(&mut no_deps);
    assert!(extract(&no_deps.to_string()).is_err());
    let mut python: Value = serde_json::from_str(&reproduce_v2_receipt(
        "effect_absent",
        &["effect_absent"; 2],
    ))
    .unwrap();
    python["runtime"] = node_runtime_metadata();
    assert!(extract(&python.to_string()).is_err());
}

#[test]
fn node_fix_predicate_requires_both_runtime_identities_and_the_matching_extension() {
    let mut good: Value = serde_json::from_str(&fix_check_receipt()).unwrap();
    good["runtime"] = node_runtime_metadata();
    add_node_fix_binding(&mut good);
    assert!(extract(&good.to_string()).is_ok());
    for mutation in 0..8 {
        let mut receipt = good.clone();
        match mutation {
            0 => receipt["runtime"] = Value::Null,
            1 => receipt["binding"] = Value::Null,
            2 => receipt["binding"]["runtime"] = Value::Null,
            3 => receipt["binding"]["runtime"]["node_version"] = json!("v1"),
            4 => receipt["binding"]["target_file"] = json!("app.py"),
            5 => receipt["binding"]["target_file"] = json!("app.ts"),
            6 => {
                receipt["binding"]["harness_version"] =
                    json!(crate::audit::verification_context::HARNESS_VERSION)
            }
            _ => receipt["runtime"]["language"] = json!("typescript"),
        }
        assert!(
            extract(&receipt.to_string()).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn node_retest_predicate_binds_each_result_runtime() {
    let mut report: Value =
        serde_json::from_str(&retest_report("not_observed", "effect_absent")).unwrap();
    let receipt = valid_node_receipt("effect_absent");
    report["results"][0]["receipt"] = receipt.clone();
    let predicate = extract(&report.to_string()).unwrap().predicate;
    let result = &predicate["results"][0];
    for key in [
        "node_version",
        "lockfile_sha256",
        "lockfile_summary_sha256",
        "deps_sha256",
        "fixture_sha256",
        "hook_bundle_sha256",
    ] {
        assert_eq!(result[key], receipt["runtime"][key], "{key}");
        let mut changed = report.clone();
        changed["results"][0]["receipt"]["runtime"][key] = if key == "node_version" {
            json!("v26.1.0")
        } else {
            json!("9".repeat(64))
        };
        add_verification_event(&mut changed["results"][0]["receipt"]);
        assert_ne!(
            predicate,
            extract(&changed.to_string()).unwrap().predicate,
            "{key}"
        );
    }
    for key in ["image_id", "harness_sha256"] {
        assert_eq!(result[key], receipt[key]);
        let mut changed = report.clone();
        changed["results"][0]["receipt"][key] = if key == "image_id" {
            json!(format!("sha256:{}", "9".repeat(64)))
        } else {
            json!("9".repeat(64))
        };
        if key == "harness_sha256" {
            changed["results"][0]["receipt"]["adapter_sha256"] = json!("9".repeat(64));
        }
        add_verification_event(&mut changed["results"][0]["receipt"]);
        assert_ne!(
            predicate,
            extract(&changed.to_string()).unwrap().predicate,
            "{key}"
        );
    }
}

#[test]
fn python_retest_predicate_covers_target_and_hashes() {
    let raw = retest_report("not_observed", "effect_absent");
    let report: Value = serde_json::from_str(&raw).unwrap();
    let predicate = extract(&raw).unwrap().predicate;
    let result = &predicate["results"][0];
    for key in ["target_file", "target_function", "target_file_sha256"] {
        assert_eq!(result[key], report["results"][0]["receipt"][key]);
    }
    assert_eq!(result["new_file_sha256"], result["target_file_sha256"]);
    assert_eq!(result["replays_completed"], 2);
}

#[test]
fn even_inconclusive_replays_must_match_their_phases() {
    let mut receipt = valid_node_receipt("inconclusive");
    let mut run = replay_run(1, "effect_absent");
    for phase in run["phases"].as_array_mut().unwrap() {
        phase["reached"] = json!(true);
        phase["reach_source"] = json!("in_process_hook");
        phase["executable"] = json!(true);
    }
    // Keep the counts and aggregate internally consistent with the forged
    // inconclusive outcome, while the second replay's phases prove absence.
    run["outcome"] = json!("inconclusive");
    receipt["replays"]["runs"][1] = run;
    assert!(
        extract(&receipt.to_string())
            .unwrap_err()
            .contains("disagrees with its phases")
    );
}

#[tokio::test]
async fn forged_python_and_node_receipts_are_refused_before_signing_any_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key");
    std::fs::write(&key, "placeholder").unwrap();
    for (name, mut receipt) in [
        (
            "python.json",
            serde_json::from_str::<Value>(&reproduce_v2_receipt(
                "effect_absent",
                &["effect_absent"; 2],
            ))
            .unwrap(),
        ),
        ("node.json", valid_node_receipt("effect_absent")),
    ] {
        receipt["replays"]["runs"][1]["phases"] = json!([]);
        let file = dir.path().join(name);
        std::fs::write(&file, receipt.to_string()).unwrap();
        let error = sign_receipt(&file, &key, None).await.unwrap_err();
        assert!(error.contains("receipt refused"), "{error}");
        assert!(!default_bundle_path(&file).exists());
    }
}

// Match the fields released Python writers stored, with no event, runtime,
// receipt-level harness hash, or Node phase metadata.
fn legacy_python_receipt(version: u32, outcome: &str, functional: Value) -> Value {
    let mut receipt: Value = serde_json::from_str(&reproduce_receipt()).unwrap();
    receipt["version"] = json!(version);
    receipt["outcome"] = json!(outcome);
    receipt["reason"] = Value::Null;
    let mut run = replay_run(0, outcome);
    run["phases"][1]["functional"] = functional;
    receipt["phases"] = run["phases"].clone();
    if version == 2 {
        receipt["replays"] = json!({
            "requested": 1, "completed": 1,
            "observed": u32::from(outcome == "effect_observed"),
            "absent": u32::from(outcome == "effect_absent"),
            "inconclusive": u32::from(outcome == "inconclusive"),
            "runs": [run]
        });
    }
    receipt
}

fn checked_signing_predicate(receipt: &Value) -> Value {
    let raw = receipt.to_string();
    let extracted = extract(&raw).unwrap();
    let statement = build_statement(
        "receipt.json",
        raw.as_bytes(),
        extracted.kind,
        &extracted.predicate,
    );
    check_statement(
        &statement,
        raw.as_bytes(),
        extracted.kind,
        &extracted.predicate,
    )
    .unwrap();
    extracted.predicate
}

#[test]
fn legacy_python_completed_receipts_keep_their_signing_predicate_bytes() {
    let version = env!("CARGO_PKG_VERSION");
    let plan = sha256_hex(b"plan");
    for receipt_version in [1, 2] {
        for outcome in ["effect_absent", "effect_observed"] {
            // Command injection and both functional-control classes are accepted.
            for functional in [Value::Null, json!(true)] {
                let receipt = legacy_python_receipt(receipt_version, outcome, functional);
                let replay_fields = if receipt_version == 2 {
                    format!(
                        r#","replays_completed":1,"replays_observed":{},"replays_requested":1"#,
                        u32::from(outcome == "effect_observed")
                    )
                } else {
                    String::new()
                };
                let expected = format!(
                    r#"{{"outcome":"{outcome}","receipt_kind":"reproduce","receipt_version":{receipt_version}{replay_fields},"target_file":"src/app.py","target_function":"run","target_plan_sha256":"{plan}","vettalon_version":"{version}"}}"#
                );
                assert_eq!(
                    canonical_bytes(&checked_signing_predicate(&receipt)).unwrap(),
                    expected.as_bytes()
                );
                if receipt_version == 2 {
                    let status = if outcome == "effect_absent" {
                        "not_observed"
                    } else {
                        "still_observed"
                    };
                    let mut report: Value =
                        serde_json::from_str(&retest_report(status, outcome)).unwrap();
                    report["replays"] = json!(1);
                    report["results"][0]["receipt"] = receipt;
                    assert!(extract(&report.to_string()).is_err());
                }
            }
        }
    }
}

#[test]
fn legacy_python_forged_outcomes_and_unbound_modern_receipts_are_refused() {
    for version in [1, 2] {
        for functional in [Value::Null, json!(true)] {
            let healthy = legacy_python_receipt(version, "effect_absent", functional.clone());
            for claimed in ["effect_observed", "inconclusive"] {
                let mut forged = legacy_python_receipt(version, claimed, functional.clone());
                forged["phases"] = healthy["phases"].clone();
                if version == 2 {
                    forged["replays"]["runs"][0]["phases"] = healthy["phases"].clone();
                }
                assert!(extract(&forged.to_string()).is_err());
            }
        }
        let incompatible = legacy_python_receipt(version, "effect_absent", json!(false));
        assert!(extract(&incompatible.to_string()).is_err());
        let mut modern = legacy_python_receipt(version, "effect_absent", Value::Null);
        modern["harness_sha256"] = json!("f".repeat(64));
        assert!(extract(&modern.to_string()).is_err());
    }
}

fn empty_phase_receipt(node: bool, completed: u32) -> Value {
    let mut receipt: Value = serde_json::from_str(&reproduce_receipt()).unwrap();
    receipt["version"] = json!(if node { 3 } else { 2 });
    receipt["target_file"] = json!(if node { "src/app.js" } else { "src/app.py" });
    receipt["reason"] = json!("stale_source");
    let runs: Vec<Value> = (0..completed)
        .map(|index| {
            json!({
                "index": index, "outcome": "inconclusive", "reason": "stale_source", "phases": []
            })
        })
        .collect();
    receipt["replays"] = json!({
        "requested": 3, "completed": completed, "observed": 0, "absent": 0,
        "inconclusive": completed, "runs": runs
    });
    receipt
}

#[test]
fn empty_phase_refusals_have_inconclusive_signing_predicates() {
    for node in [false, true] {
        for completed in [0, 1] {
            let receipt = empty_phase_receipt(node, completed);
            let predicate = checked_signing_predicate(&receipt);
            assert_eq!(predicate["outcome"], "inconclusive");
            assert_eq!(predicate["reason"], "stale_source");
            assert_eq!(predicate["replays_completed"], completed);
            let mut report: Value =
                serde_json::from_str(&retest_report("inconclusive", "inconclusive")).unwrap();
            report["replays"] = json!(3);
            report["results"][0]["reason"] = json!("stale_source");
            report["results"][0]["receipt"] = receipt;
            assert!(extract(&report.to_string()).is_err());
        }
    }
    // Infrastructure can also fail after the Node runtime has been selected.
    let mut receipt = empty_phase_receipt(true, 1);
    receipt["runtime"] = node_runtime_metadata();
    assert_eq!(
        checked_signing_predicate(&receipt)["outcome"],
        "inconclusive"
    );
}

#[test]
fn empty_phase_exceptions_require_reasons_and_consistent_replays() {
    for node in [false, true] {
        for mutation in 0..11 {
            let mut receipt = empty_phase_receipt(node, 1);
            match mutation {
                0 => receipt["reason"] = Value::Null,
                1 => receipt["reason"] = json!("  "),
                2 => receipt["replays"]["runs"][0]["reason"] = Value::Null,
                3 => receipt["replays"]["runs"][0]["reason"] = json!(""),
                4 => receipt["replays"]["completed"] = json!(0),
                5 => receipt["replays"]["runs"][0]["index"] = json!(1),
                6 => receipt["replays"]["requested"] = json!(0),
                7 => receipt["outcome"] = json!("effect_observed"),
                8 | 9 => {
                    let outcome = if mutation == 8 {
                        "effect_absent"
                    } else {
                        "effect_observed"
                    };
                    receipt["outcome"] = json!(outcome);
                    receipt["replays"]["runs"][0]["outcome"] = json!(outcome);
                    receipt["replays"]["inconclusive"] = json!(0);
                    receipt["replays"][if mutation == 8 { "absent" } else { "observed" }] =
                        json!(1);
                }
                _ => {
                    receipt["replays"]["runs"][0]["phases"] =
                        replay_run(0, "inconclusive")["phases"].clone()
                }
            }
            assert!(
                extract(&receipt.to_string()).is_err(),
                "node={node}, mutation={mutation}"
            );
        }
    }
    // No Node replay may use the Python rule when runtime identity is absent.
    let mut mixed = empty_phase_receipt(true, 1);
    mixed["replays"]["completed"] = json!(2);
    mixed["replays"]["inconclusive"] = json!(2);
    mixed["replays"]["runs"]
        .as_array_mut()
        .unwrap()
        .push(replay_run(1, "inconclusive"));
    assert!(extract(&mixed.to_string()).is_err());
}
