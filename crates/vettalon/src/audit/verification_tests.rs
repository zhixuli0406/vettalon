use std::path::Path;

use vettalon_contract::verification::{
    AccessPurpose, BackendKind, CleanupState, CounterexampleKind, DataRights, DerivedVerdict,
    ENGINEERING_MEASUREMENT_SCHEMA, EVALUATION_CASE_SCHEMA, EffectKind, EngineeringMeasurement,
    EvaluationCase, EvaluationSplit, FailureClass, Language, ReplayGrade, ReplayOutcome,
    SupportOutcome,
};

use super::*;

fn hash(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn input() -> CompileInput {
    CompileInput {
        runtime: None,
        finding_id: "finding-1".into(),
        file: "app.py".into(),
        line: Some(8),
        symbol: "read_file".into(),
        cwe: "CWE-22".into(),
        source_sha256: hash('a'),
        target_file_sha256: hash('b'),
        target_plan_sha256: hash('c'),
        harness_sha256: hash('d'),
    }
}

#[test]
fn compiler_maps_supported_cwes_to_effects_and_stable_controls() {
    let path = compile_ir(&input()).unwrap();
    assert_eq!(path.effect.kind, EffectKind::FileReadOutsideRoot);
    assert_eq!(path.controls.len(), 2);
    assert!(path.controls.iter().all(|control| control.required));

    let mut command = input();
    command.cwe = "CWE-78".into();
    assert_eq!(
        compile_ir(&command).unwrap().effect.kind,
        EffectKind::CommandExecution
    );

    let mut sql = input();
    sql.cwe = "CWE-89".into();
    assert_eq!(
        compile_ir(&sql).unwrap().effect.kind,
        EffectKind::SqlStateChange
    );

    let mut unsupported = input();
    unsupported.cwe = "CWE-79".into();
    assert_eq!(compile_ir(&unsupported), Err("unsupported_effect_spec"));
}

#[test]
fn envelope_builder_derives_only_from_host_observations() {
    let ir = compile_ir(&input()).unwrap();
    let observations = HostObservations {
        backend_kind: BackendKind::Docker,
        backend_identity: format!("sha256:{}", hash('e')),
        platform: "linux/arm64".into(),
        challenge_commitment: hash('f'),
        capture_complete: true,
        cleanup: CleanupState::Confirmed,
        tampering: Vec::new(),
        effect_observed: Some(true),
        benign_control: Some(true),
        fresh_challenge_control: Some(true),
        exit_code: Some(0),
        transcript_sha256: Some(hash('1')),
        replay_grade: ReplayGrade::Semantic,
    };
    let event = VerificationEvent::from_host_observations(ir, observations).unwrap();
    assert_eq!(event.decision.verdict, DerivedVerdict::EffectObserved);
    assert!(event.model_claim.is_none());
    assert!(event.human_adjudication.is_none());

    let mut forged = event.envelope.clone();
    forged
        .tampering
        .push(vettalon_contract::verification::TamperSignal::VerdictChannelForgery);
    let event =
        VerificationEvent::new(event.ir, forged, Some("model says pass".into()), None).unwrap();
    assert_eq!(event.decision.verdict, DerivedVerdict::Inconclusive);
    assert!(
        event
            .decision
            .failures
            .contains(&FailureClass::TamperingSuspected)
    );
}

#[test]
fn counterexample_minimizer_keeps_the_failure_and_drops_noise() {
    let input = b"prefix---BAD---suffix";
    let minimized = minimize_counterexample(input, |candidate| {
        candidate.windows(3).any(|window| window == b"BAD")
    });
    assert_eq!(minimized, b"BAD");
}

#[test]
fn registry_is_content_addressed_and_records_contamination() {
    let temp = tempfile::tempdir().unwrap();
    let store = RegistryStore::open(temp.path()).unwrap();
    let case = EvaluationCase {
        schema: EVALUATION_CASE_SCHEMA.into(),
        case_id: "hidden-case".into(),
        content_sha256: hash('9'),
        declared_split: EvaluationSplit::SealedHoldout,
        rights: DataRights::ServiceOnly,
        parents: Vec::new(),
    };
    store.add_case(&case).unwrap();
    store.add_case(&case).unwrap();
    let mut conflicting = case.clone();
    conflicting.content_sha256 = hash('8');
    assert_eq!(
        store.add_case(&conflicting),
        Err("registry_case_id_collision")
    );
    let mut alias = case.clone();
    alias.case_id = "hidden-alias".into();
    assert_eq!(store.add_case(&alias), Err("registry_content_alias"));
    let mut orphan = case.clone();
    orphan.case_id = "orphan".into();
    orphan.content_sha256 = hash('7');
    orphan.parents = vec!["missing-parent".into()];
    assert_eq!(store.add_case(&orphan), Err("registry_parent_not_found"));
    assert_eq!(store.load_cases().unwrap(), vec![case.clone()]);

    let audit = store.audit_case("hidden-case").unwrap();
    assert_eq!(audit.effective_split, EvaluationSplit::SealedHoldout);
    assert!(!audit.compromised);

    store
        .record_access("hidden-case", AccessPurpose::Development, "compiler-worker")
        .unwrap();
    let audit = store.audit_case("hidden-case").unwrap();
    assert_eq!(audit.effective_split, EvaluationSplit::Development);
    assert!(audit.compromised);

    let derived = EvaluationCase {
        schema: EVALUATION_CASE_SCHEMA.into(),
        case_id: "derived-hidden".into(),
        content_sha256: hash('6'),
        declared_split: EvaluationSplit::Prospective,
        rights: DataRights::ServiceOnly,
        parents: vec!["hidden-case".into()],
    };
    store.add_case(&derived).unwrap();
    let audit = store.audit_case("derived-hidden").unwrap();
    assert_eq!(audit.effective_split, EvaluationSplit::Development);
    assert!(audit.compromised);
    assert_eq!(
        audit.lineage_case_ids,
        vec!["derived-hidden".to_string(), "hidden-case".to_string()]
    );
}

#[test]
fn registry_refuses_content_address_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let store = RegistryStore::open(temp.path()).unwrap();
    let case = EvaluationCase {
        schema: EVALUATION_CASE_SCHEMA.into(),
        case_id: "hidden-case".into(),
        content_sha256: hash('9'),
        declared_split: EvaluationSplit::SealedHoldout,
        rights: DataRights::ServiceOnly,
        parents: Vec::new(),
    };
    store.add_case(&case).unwrap();
    store
        .record_access("hidden-case", AccessPurpose::Development, "builder")
        .unwrap();
    let access_file = std::fs::read_dir(store.root.join("access"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(&access_file).unwrap();
    let tampered = String::from_utf8(bytes)
        .unwrap()
        .replace("development", "audit");
    std::fs::write(access_file, tampered).unwrap();
    assert_eq!(
        store.audit_case("hidden-case"),
        Err("registry_content_address_mismatch")
    );
}

#[test]
fn registry_refuses_a_preexisting_lineage_cycle() {
    let temp = tempfile::tempdir().unwrap();
    let store = RegistryStore::open(temp.path()).unwrap();
    let cases = [
        EvaluationCase {
            schema: EVALUATION_CASE_SCHEMA.into(),
            case_id: "case-a".into(),
            content_sha256: hash('8'),
            declared_split: EvaluationSplit::Development,
            rights: DataRights::ServiceOnly,
            parents: vec!["case-b".into()],
        },
        EvaluationCase {
            schema: EVALUATION_CASE_SCHEMA.into(),
            case_id: "case-b".into(),
            content_sha256: hash('9'),
            declared_split: EvaluationSplit::Development,
            rights: DataRights::ServiceOnly,
            parents: vec!["case-a".into()],
        },
    ];
    for case in cases {
        let bytes = serde_json::to_vec_pretty(&case).unwrap();
        std::fs::write(
            store
                .root
                .join("cases")
                .join(format!("{}.json", sha256_hex(&bytes))),
            bytes,
        )
        .unwrap();
    }
    assert_eq!(store.load_cases(), Err("registry_lineage_cycle"));
}

#[cfg(unix)]
#[test]
fn registry_refuses_a_symlink_root() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let actual = temp.path().join("actual");
    std::fs::create_dir(&actual).unwrap();
    let link = temp.path().join("registry");
    symlink(&actual, &link).unwrap();
    assert_eq!(
        RegistryStore::open(Path::new(&link)).unwrap_err(),
        "registry_root_symlink"
    );
}

#[cfg(unix)]
#[test]
fn registry_refuses_a_symlink_in_a_new_roots_parent_chain() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let actual = temp.path().join("actual");
    std::fs::create_dir(&actual).unwrap();
    let link = temp.path().join("alias");
    symlink(&actual, &link).unwrap();
    assert_eq!(
        RegistryStore::open(&link.join("registry")).unwrap_err(),
        "registry_parent_invalid"
    );
}

#[test]
fn foundry_promotes_only_stable_events_and_registry_round_trips_cells() {
    let ir = compile_ir(&input()).unwrap();
    let event = VerificationEvent::from_host_observations(
        ir,
        HostObservations {
            backend_kind: BackendKind::Docker,
            backend_identity: format!("sha256:{}", hash('e')),
            platform: "linux/arm64".into(),
            challenge_commitment: hash('f'),
            capture_complete: true,
            cleanup: CleanupState::Confirmed,
            tampering: Vec::new(),
            effect_observed: Some(true),
            benign_control: Some(true),
            fresh_challenge_control: Some(true),
            exit_code: Some(0),
            transcript_sha256: Some(hash('1')),
            replay_grade: ReplayGrade::Semantic,
        },
    )
    .unwrap();
    let mut second_envelope = event.envelope.clone();
    second_envelope.challenge_commitment = hash('2');
    second_envelope.transcript_sha256 = Some(hash('2'));
    let second = VerificationEvent::new(event.ir.clone(), second_envelope, None, None).unwrap();
    let mut third_envelope = event.envelope.clone();
    third_envelope.challenge_commitment = hash('3');
    third_envelope.transcript_sha256 = Some(hash('3'));
    let third = VerificationEvent::new(event.ir.clone(), third_envelope, None, None).unwrap();
    let replay_events = vec![event.clone(), second, third];
    assert_eq!(
        promote_counterexample(
            &replay_events[..1],
            "cell-1",
            CounterexampleKind::FalseProof,
            &hash('7'),
            &hash('8'),
            EvaluationSplit::Development,
            DataRights::ServiceOnly,
            Vec::new(),
        ),
        Err("invalid_counterexample_cell")
    );
    let cell = promote_counterexample(
        &replay_events,
        "cell-1",
        CounterexampleKind::FalseProof,
        &hash('7'),
        &hash('8'),
        EvaluationSplit::Development,
        DataRights::ServiceOnly,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        cell.triggering_event_sha256,
        event.identity_sha256().unwrap()
    );
    assert_eq!(cell.replay_event_sha256.len(), replay_events.len());
    let mut repeated_challenge = replay_events.clone();
    repeated_challenge[1].envelope.challenge_commitment =
        repeated_challenge[0].envelope.challenge_commitment.clone();
    assert_eq!(
        promote_counterexample(
            &repeated_challenge,
            "repeated-challenge",
            CounterexampleKind::FalseProof,
            &hash('7'),
            &hash('8'),
            EvaluationSplit::Development,
            DataRights::ServiceOnly,
            Vec::new(),
        ),
        Err("counterexample_replay_mismatch")
    );
    assert_eq!(
        promote_counterexample(
            &replay_events,
            "hidden-cell",
            CounterexampleKind::FalseProof,
            &hash('7'),
            &hash('8'),
            EvaluationSplit::SealedHoldout,
            DataRights::ServiceOnly,
            Vec::new(),
        ),
        Err("counterexample_split_not_development")
    );

    let temp = tempfile::tempdir().unwrap();
    let store = RegistryStore::open(temp.path()).unwrap();
    store.add_counterexample(&cell).unwrap();
    store.add_counterexample(&cell).unwrap();
    let mut conflicting = cell.clone();
    conflicting.original_content_sha256 = hash('6');
    assert_eq!(
        store.add_counterexample(&conflicting),
        Err("registry_cell_id_collision")
    );
    assert_eq!(store.load_counterexamples().unwrap(), vec![cell]);
}

fn measurement(id: &str, support: SupportOutcome) -> EngineeringMeasurement {
    EngineeringMeasurement {
        schema: ENGINEERING_MEASUREMENT_SCHEMA.into(),
        measurement_id: id.into(),
        cohort: "prospective-1".into(),
        project: "repo-a".into(),
        effect: "command_execution".into(),
        language: Language::Python,
        framework: "stdlib".into(),
        verifier_engineering_minutes: 60,
        manual_trusted_loc: 100,
        support,
        prospective: true,
        false_proof: false,
        replay: ReplayOutcome::NotAttempted,
        tamper_attempt: false,
        positive_forgery: false,
        state_leak: false,
        cleanup_residue: false,
        build_ms: 10,
        execution_ms: 20,
        capture_ms: 30,
        cleanup_ms: 40,
        human_minutes: 5,
        direct_cost_microunits: 1_000,
        currency: "USD".into(),
    }
}

#[test]
fn scorecard_keeps_unsupported_inconclusive_and_tamper_denominators() {
    let mut valid = measurement("supported", SupportOutcome::Supported);
    valid.replay = ReplayOutcome::Equivalent;
    valid.tamper_attempt = true;

    let unsupported = measurement("unsupported", SupportOutcome::Unsupported);

    let mut false_proof = measurement("false-proof", SupportOutcome::Supported);
    false_proof.false_proof = true;
    false_proof.replay = ReplayOutcome::Inconclusive;
    false_proof.tamper_attempt = true;
    false_proof.positive_forgery = true;

    let card = build_scorecard(&[valid, unsupported, false_proof]).unwrap();
    assert_eq!(card.roster_total, 3);
    assert_eq!(card.supported, 2);
    assert_eq!(card.unsupported, 1);
    assert_eq!(card.prospective_total, 3);
    assert_eq!(card.prospective_false_proofs, 1);
    assert_eq!(card.replay_attempted, 2);
    assert_eq!(card.replay_equivalent, 1);
    assert_eq!(card.replay_inconclusive, 1);
    assert_eq!(card.tamper_attempts, 2);
    assert_eq!(card.positive_forgeries, 1);
    assert_eq!(card.conclusive_proofs, 1);
    assert_eq!(card.cost_microunits_per_conclusive_proof, Some(3_000));
    assert_eq!(build_scorecard(&[]), Err("empty_engineering_measurements"));
    let duplicate = measurement("same-id", SupportOutcome::Supported);
    assert_eq!(
        build_scorecard(&[duplicate.clone(), duplicate]),
        Err("duplicate_engineering_measurement")
    );

    let mut huge_a = measurement("huge-a", SupportOutcome::Supported);
    huge_a.verifier_engineering_minutes = u64::MAX;
    huge_a.manual_trusted_loc = u64::MAX;
    let mut huge_b = huge_a.clone();
    huge_b.measurement_id = "huge-b".into();
    let card = build_scorecard(&[huge_a, huge_b]).unwrap();
    assert_eq!(card.median_verifier_engineering_minutes, Some(u64::MAX));
    assert_eq!(card.median_manual_trusted_loc, Some(u64::MAX));
}

#[test]
fn python_ir_bytes_remain_identical() {
    assert_eq!(
        compile_ir(&input()).unwrap().identity_sha256().unwrap(),
        "2c083e2e58867ccf7d8254418afa8b842ce39e6bd56ed218155bad82c2ee7b40"
    );
}

#[test]
fn d11a_pin_existing_ir_identities_for_python_and_node() {
    use super::super::verification_context::RuntimeIdentity;
    let runtime = RuntimeIdentity {
        node_version: "v22.15.0".into(),
        lockfile_sha256: Some(hash('1')),
        lockfile_summary_sha256: Some(hash('2')),
        deps_sha256: Some(hash('3')),
        fixture_sha256: Some(hash('4')),
    };
    let cases = [
        (
            "CWE-78",
            "09f5bc51096ba1b43adf0cf9eb5ab4561d7787a42debe6b786f0617fc6524245",
            "4b33e5ea548abde92905b4c07d65abc18478e2134fa0ad023fa6746669da6402",
        ),
        (
            "CWE-22",
            "2c083e2e58867ccf7d8254418afa8b842ce39e6bd56ed218155bad82c2ee7b40",
            "2ee692ce07c1e34f743f522216f4b8994249bb816279616996c277010b9ca42c",
        ),
        (
            "CWE-89",
            "8fa991ea54515d587bc1f1146ca69f511da41f699fa3d1998b66a67d77753d36",
            "b0c2e38695f45e584511a36ee19c6425a4057ec5fb1414b44e438b4f5f911660",
        ),
    ];
    for (cwe, py_expected, mjs_expected) in cases {
        let mut py = input();
        py.cwe = cwe.into();
        // D11a pin: must not change when SSRF is added
        let py_hash = compile_ir(&py).unwrap().identity_sha256().unwrap();
        assert_eq!(py_hash, py_expected);
        let mut mjs = py;
        mjs.file = "app.mjs".into();
        mjs.runtime = Some(runtime.clone());
        // D11a pin: must not change when SSRF is added
        let mjs_hash = compile_ir(&mjs).unwrap().identity_sha256().unwrap();
        assert_eq!(mjs_hash, mjs_expected);
    }
}

#[test]
fn node_ir_binds_runtime_and_each_execution_digest() {
    use super::super::verification_context::RuntimeIdentity;
    let runtime = RuntimeIdentity {
        node_version: "v22.15.0".into(),
        lockfile_sha256: Some(hash('1')),
        lockfile_summary_sha256: Some(hash('2')),
        deps_sha256: Some(hash('3')),
        fixture_sha256: Some(hash('4')),
    };
    for (extension, language) in [
        ("js", Language::JavaScript),
        ("mjs", Language::JavaScript),
        ("cjs", Language::JavaScript),
        ("ts", Language::TypeScript),
        ("mts", Language::TypeScript),
        ("cts", Language::TypeScript),
    ] {
        let mut node = input();
        node.file = format!("app.{extension}");
        assert_eq!(compile_ir(&node), Err("invalid_verification_runtime"));
        node.runtime = Some(runtime.clone());
        let original = compile_ir(&node).unwrap();
        assert_eq!(original.subject.language, language);
        assert_eq!(
            original.capabilities,
            compile_ir(&input()).unwrap().capabilities
        );
        for field in 0..5 {
            let mut changed = node.clone();
            let identity = changed.runtime.as_mut().unwrap();
            match field {
                0 => identity.node_version = "v22.16.0".into(),
                1 => identity.lockfile_sha256 = Some(hash('5')),
                2 => identity.lockfile_summary_sha256 = Some(hash('5')),
                3 => identity.deps_sha256 = Some(hash('5')),
                _ => identity.fixture_sha256 = Some(hash('5')),
            }
            assert_ne!(
                original.identity_sha256().unwrap(),
                compile_ir(&changed).unwrap().identity_sha256().unwrap()
            );
        }
        node.runtime.as_mut().unwrap().fixture_sha256 = Some("invalid".into());
        assert_eq!(compile_ir(&node), Err("invalid_verification_runtime"));
    }
    let mut python = input();
    python.runtime = Some(runtime);
    assert_eq!(compile_ir(&python), Err("invalid_verification_runtime"));
}

#[test]
fn ssrf_ir_has_only_the_loopback_network_capability_extension() {
    let mut ssrf = input();
    ssrf.file = "app.mjs".into();
    ssrf.cwe = "CWE-918".into();
    ssrf.runtime = Some(super::super::verification_context::RuntimeIdentity {
        node_version: "v22.15.0".into(),
        lockfile_sha256: Some(hash('1')),
        lockfile_summary_sha256: Some(hash('2')),
        deps_sha256: Some(hash('3')),
        fixture_sha256: None,
    });
    let ir = compile_ir(&ssrf).unwrap();
    assert_eq!(ir.effect.kind, EffectKind::NetworkEgress);
    assert_eq!(ir.effect.id, "loopback_http_request");
    assert_eq!(
        ir.capabilities,
        vec![
            Capability::ReadPreparedTree,
            Capability::WriteEphemeralTemp,
            Capability::SpawnBoundedProcess,
            Capability::LoopbackNetwork,
        ]
    );
    for cwe in ["CWE-77", "CWE-78", "CWE-22", "CWE-73", "CWE-89"] {
        ssrf.cwe = cwe.into();
        let existing = compile_ir(&ssrf).unwrap();
        assert!(!existing.capabilities.contains(&Capability::LoopbackNetwork));
        assert_eq!(existing.controls, ir.controls);
        assert_eq!(existing.binding.policy_version, ir.binding.policy_version);
    }
}
