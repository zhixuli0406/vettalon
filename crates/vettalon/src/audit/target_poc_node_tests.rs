use super::super::poc_oracle::{NodeSqlDriver, node_target_runners};
use super::*;
use serde_json::json;

#[test]
fn d11a_pin_harness_and_hook_bundle_hashes() {
    let adapter = "ab".repeat(32);
    let classes = [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ];
    let expected_node = [
        "32522ef7df86d8afe68ab50bf0ab42de45faee7598887efe8d70dd9e352a2889",
        "fa2be862519c3da89f6dcf5cb9ef4ed15acb1f1061ddd709836e5c04921a189b",
        "1d65045ee43c201e1d41e719ec1507e46bb54d909724b2279ea123e3b7a58d1c",
    ];
    let expected_python = [
        "b910e312bd74eb548ac4daaca07b9c54ca954158481a0361900e6d72ccfefa20",
        "f377f8fc220dd004dd81f7ddd0ded46b6f09b97cefa766f320227ead3747db6c",
        "6c0c79ac769e9090a8535eb0589e1db54b4452e61b3f456b37d7f19109670b4b",
    ];
    for ((class, node), python) in classes.into_iter().zip(expected_node).zip(expected_python) {
        // D11a pin: must not change when SSRF is added
        let node_actual = node_harness_sha256(class, &adapter);
        let python_actual = target_harness_sha256(class, &adapter);
        assert_eq!(node_actual, node);
        assert_eq!(python_actual, python);
    }
    for class in classes {
        // D11a pin: must not change when SSRF is added
        let bundle = sha256_hex(
            node_assets_for(class)
                .iter()
                .flat_map(|(_, text)| text.as_bytes().iter().copied())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        assert_eq!(
            bundle,
            "39f02d61c5180218907f2b4d6ff76f2deda9acd46fa2ac487013f26fbdc65fa5"
        );
    }
}

#[test]
fn node_host_runner_cjs_end_to_end() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    for program in ["python3", "node"] {
        match Command::new(program).arg("--version").output() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("SKIP node_host_runner_cjs_end_to_end: {program} is not on PATH");
                return;
            }
            result => assert!(
                result.unwrap().status.success(),
                "{program} --version failed"
            ),
        }
    }
    let node = Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    assert!(node.status.success());
    let node = String::from_utf8(node.stdout).unwrap().trim().to_string();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_str().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(workspace.join("tree")).unwrap();
    std::fs::create_dir(dir.path().join("tmp")).unwrap();
    let target = include_str!("../../tests/fixtures/node-e2e/cjs-command/app.cjs");
    let call: TargetCall = serde_json::from_str(include_str!(
        "../../tests/fixtures/node-e2e/cjs-command/target.json"
    ))
    .unwrap();
    std::fs::write(workspace.join("tree/app.cjs"), target).unwrap();
    for (name, source) in NODE_ASSETS {
        std::fs::write(workspace.join(name), source).unwrap();
    }
    let adapter = build_node_adapter(
        &call,
        &sha256_hex(target.as_bytes()),
        OracleClass::CommandInjection,
    )
    .unwrap()
    .replace("/workspace", workspace.to_str().unwrap());
    std::fs::write(workspace.join("sink.mjs"), adapter).unwrap();
    let secrets = OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    };
    let class = OracleClass::CommandInjection;
    let runtime = receipt_runtime();
    for configured in [true, false] {
        let mut phases = Vec::new();
        for (name, runner) in PHASE_NAMES
            .into_iter()
            .zip(node_target_runners(class, &secrets, None))
        {
            // Only container isolation and mount locations are replaced on the host.
            // Never execute PID-1's kill(-1) reaper outside its container.
            let runner = runner.replace(
                "os.getpid() == 1 and libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0",
                "True",
            );
            let start = runner.find("def reap():").unwrap();
            let end = runner.find("def read_result(path):").unwrap();
            let mut runner = format!(
                "{}def reap():\n    pass\n{}",
                &runner[..start],
                &runner[end..]
            )
            .replace("/tmp", &format!("{root}/tmp"))
            .replace("/workspace", workspace.to_str().unwrap())
            .replace(
                "'/usr/local/bin/node'",
                &serde_json::to_string(&node).unwrap(),
            );
            if !configured {
                // The real hook stays inert and the real adapter refuses to import.
                runner = runner.replace(
                    "child_env['VTL_EVENT_FD'] = str(write_fd)",
                    "child_env['VTL_EVENT_FD'] = '-1'",
                );
            }
            let mut child = Command::new("python3")
                .args(["-I", "-B", "-c", &runner])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(
                    super::super::node::dispatch::runner_envelope(&secrets.marker, None).as_bytes(),
                )
                .unwrap();
            let output = child.wait_with_output().unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{name}: {stderr}");
            let verdict =
                parse_node_verdict(&stdout, &secrets.marker, OracleClass::CommandInjection)
                    .unwrap();
            let mut phase = receipt_phase(name);
            phase.record_node_verdict(&verdict, &runtime);
            if configured {
                assert_eq!(
                    verdict.base.effect,
                    name != "benign_control",
                    "{name}: {stdout} {stderr}"
                );
                assert!(verdict.reach.events_total > 0, "{name}: {stdout} {stderr}");
                assert_eq!(verdict.reached, Some(true), "{name}: {stdout} {stderr}");
                assert_eq!(phase.reason, None, "{name}: {stdout} {stderr}");
            } else {
                assert_eq!(verdict.reach.events_total, 0);
                assert_eq!(verdict.reached, None);
                assert!(verdict.base.error);
                assert_eq!(phase.reason.as_deref(), Some("target_execution_error"));
            }
            phases.push(phase);
        }
        let expected = if configured {
            TargetPocOutcome::EffectObserved
        } else {
            TargetPocOutcome::Inconclusive
        };
        assert_eq!(derive_outcome(&phases, class, Some(&runtime)), expected);
    }
}

fn summary(reached: Option<bool>) -> Value {
    json!({
        "reach_source":"in_process_hook", "events_total":if reached.is_some() {1} else {0},
        "first_match":if reached == Some(true) {
            json!({"api":"child_process.exec","field":"file","display":"vtl_secret","payload_in_text":null})
        } else { Value::Null }
    })
}

fn wire(effect: bool, reached: Option<bool>) -> String {
    let state = match reached {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    };
    format!(
        "__VTL_ORACLE__ marker effect={effect} reached={state} reach={}",
        hex::encode(summary(reached).to_string())
    )
}

#[test]
fn node_verdict_grammar_accepts_bounded_diagnostics_and_flags() {
    for effect in [true, false] {
        for reached in [Some(true), Some(false), None] {
            let text = wire(effect, reached)
                + " functional=true raised=true error=true timeout=true missing=true executable=false";
            let verdict =
                parse_node_verdict(&text, "marker", OracleClass::CommandInjection).unwrap();
            assert_eq!(
                verdict.base,
                HarnessVerdict {
                    surfaced: None,
                    effect,
                    functional: Some(true),
                    error: true,
                    raised: true,
                    timeout: true
                }
            );
            assert_eq!(verdict.reached, reached);
            assert!(verdict.missing);
            assert!(!verdict.executable);
            assert_eq!(verdict.reach.reach_source, "in_process_hook");
            // Python keeps its old, closed grammar.
            assert_eq!(
                parse_verdict(&text, "marker"),
                Err("invalid_target_verdict")
            );
        }
    }
}

#[test]
fn node_verdict_grammar_refuses_invalid_duplicate_and_oversized_fields() {
    let valid = wire(false, Some(true));
    let mut invalid = vec![
        "__VTL_ORACLE__ marker effect=true".to_string(),
        valid.replace("reached=true", "reached=maybe"),
        valid.replace("effect=false", "effect=unknown"),
        valid.replace("effect=false ", ""),
        valid.replace("reached=true ", ""),
        format!("{valid}\n{valid}"),
        format!("{valid}\n__VTL_ORACLE__ marker"),
    ];
    for extra in [
        "effect=true",
        "reached=unknown",
        "reach=7b7d",
        "functional=true functional=false",
        "error=true error=false",
        "raised=true raised=false",
        "timeout=true timeout=false",
        "missing=false",
        "executable=true",
        "garbage=true",
        "missing=true missing=true",
        "executable=false executable=false",
    ] {
        invalid.push(format!("{valid} {extra}"));
    }
    for raw in [
        "0".into(),
        "zz".into(),
        "AA".into(),
        hex::encode("{}"),
        hex::encode("[]"),
        "20".repeat(2049),
    ] {
        invalid.push(format!(
            "__VTL_ORACLE__ marker effect=false reached=unknown reach={raw}"
        ));
    }
    let mut tampered = summary(Some(true));
    tampered["reach_source"] = json!("trusted");
    invalid.push(format!(
        "__VTL_ORACLE__ marker effect=false reached=true reach={}",
        hex::encode(tampered.to_string())
    ));
    for field in ["display", "api"] {
        let mut oversized = summary(Some(true));
        oversized["first_match"][field] = json!("x".repeat(513));
        invalid.push(format!(
            "__VTL_ORACLE__ marker effect=false reached=true reach={}",
            hex::encode(oversized.to_string())
        ));
    }
    let duplicate = summary(None)
        .to_string()
        .replacen('{', "{\"events_total\":0,", 1);
    invalid.push(format!(
        "__VTL_ORACLE__ marker effect=false reached=unknown reach={}",
        hex::encode(duplicate)
    ));
    invalid.push(valid.replace("reached=true", "reached=false"));
    for text in invalid {
        assert!(
            parse_node_verdict(&text, "marker", OracleClass::CommandInjection).is_err(),
            "{text}"
        );
    }
    assert!(
        parse_node_verdict(
            &format!("noise\n__VTL_ORACLE__ other effect=true\n{valid}"),
            "marker",
            OracleClass::CommandInjection,
        )
        .is_ok()
    );
}

#[test]
fn node_phase_table_uses_host_driver_and_preserves_execution_failures() {
    for effect in [false, true] {
        for reached in [Some(true), Some(false), None] {
            for benign in [false, true] {
                let verdict = parse_node_verdict(
                    &wire(effect, reached),
                    "marker",
                    OracleClass::CommandInjection,
                )
                .unwrap();
                let want = match (effect, reached, benign) {
                    (effect, Some(true), _) => Ok(effect),
                    (true, _, _) => Err("effect_without_reach"),
                    (false, _, true) => Err("benign_not_reached"),
                    (false, _, false) => Err("sink_not_reached"),
                };
                for driver in [None, Some(NodeSqlDriver::Sqlite3)] {
                    assert_eq!(node_phase_result(&verdict, driver, benign), want);
                    let mut forged = verdict.clone();
                    forged.executable = false;
                    assert_eq!(node_phase_result(&forged, driver, benign), want);
                }
                for driver in [NodeSqlDriver::Pg, NodeSqlDriver::Mysql2] {
                    assert_eq!(
                        node_phase_result(&verdict, Some(driver), benign),
                        Err("sql_dialect_not_executable")
                    );
                }
            }
        }
    }
    for (flag, reason) in [
        ("error=true", "target_execution_error"),
        ("raised=true", "target_execution_error"),
        ("timeout=true error=true", "target_timeout"),
        ("missing=true", "target_missing"),
    ] {
        let verdict = parse_node_verdict(
            &(wire(false, Some(true)) + " " + flag),
            "marker",
            OracleClass::CommandInjection,
        )
        .unwrap();
        assert_eq!(node_phase_result(&verdict, None, false), Err(reason));
    }
}

#[test]
fn forged_reach_never_upgrades_the_python_benign_health_rule() {
    for class in [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ] {
        let verdict = parse_node_verdict(
            &wire(false, Some(true)),
            "marker",
            OracleClass::CommandInjection,
        )
        .unwrap();
        assert_eq!(node_phase_result(&verdict, None, true), Ok(false));
        let mut phases: Vec<_> = PHASE_NAMES
            .iter()
            .map(|name| TargetPocPhase {
                surfaced: None,
                reached: None,
                reach_source: None,
                reach_sha256: None,
                reach: None,
                executable: None,
                name: (*name).into(),
                nonce_commitment: "test".into(),
                effect: Some(false),
                functional: None,
                exit_code: Some(0),
                transcript_sha256: None,
                elapsed_ms: 0,
                reason: None,
            })
            .collect();
        phases[1].functional = Some(false);
        assert_eq!(
            derive_outcome(&phases, class, None),
            TargetPocOutcome::Inconclusive
        );
        phases[1].functional = if class == OracleClass::CommandInjection {
            None
        } else {
            Some(true)
        };
        assert_eq!(
            derive_outcome(&phases, class, None),
            TargetPocOutcome::EffectAbsent
        );
    }
}

#[test]
fn node_adapter_plan_is_hex_data_and_configures_identity_before_import() {
    let call = TargetCall {
        file: "src/quote'測試.mjs".into(),
        function: "default".into(),
        args: vec![
            TargetArgument::Payload,
            TargetArgument::Literal {
                value: json!("'; process.exit(0); //\n"),
            },
            TargetArgument::Callback,
        ],
    };
    let hash = "ab".repeat(32);
    let adapter = build_node_adapter(&call, &hash, OracleClass::CommandInjection).unwrap();
    let encoded = adapter
        .split("Buffer.from('")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    let plan: Value = serde_json::from_slice(&hex::decode(encoded).unwrap()).unwrap();
    assert_eq!(plan["call"], serde_json::to_value(&call).unwrap());
    assert_eq!(plan["target_file_sha256"], hash);
    assert!(!adapter.contains("process.exit(0)"));
    assert!(!adapter.contains(&call.file));
    assert!(
        adapter.find("hook.configureTarget({").unwrap()
            < adapter.find("await import(targetUrl)").unwrap()
    );
    assert_eq!(adapter.matches("hook.configureTarget({").count(), 1);
    assert!(adapter.contains("hasOwn(ns, name)"));
    assert!(adapter.contains("hasOwn(ns.default, name)"));
    assert!(adapter.contains("callbackResolve(value) : callbackReject(err)"));
    assert!(adapter.contains("25000"));
    assert!(adapter.contains("encoded.length > 65536"));
    assert_eq!(
        build_node_adapter(&call, "bad", OracleClass::CommandInjection),
        Err("invalid_target_hash")
    );
    let python = TargetCall {
        file: "app.py".into(),
        function: "run".into(),
        args: vec![TargetArgument::Payload],
    };
    assert_eq!(
        build_node_adapter(&python, &hash, OracleClass::CommandInjection),
        Err("unsupported_target_language")
    );
}

#[test]
fn node_harness_hash_binds_ordered_runner_adapter_and_four_assets() {
    let s = OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    };
    let class = OracleClass::PathTraversal;
    let adapter = "ab".repeat(32);
    let runners = node_target_runners(class, &s, None);
    let parts = [NODE_HARNESS_VERSION, "path_traversal", &adapter];
    let mut components: Vec<Vec<u8>> = parts.iter().map(|part| part.as_bytes().to_vec()).collect();
    components.extend(runners.iter().map(|runner| runner.as_bytes().to_vec()));
    components.extend(
        NODE_ASSETS
            .iter()
            .flat_map(|(basename, text)| [basename.as_bytes().to_vec(), text.as_bytes().to_vec()]),
    );
    let digest = |parts: &[Vec<u8>]| {
        let mut bytes = Vec::new();
        for part in parts {
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        sha256_hex(&bytes)
    };
    let expected = node_harness_sha256(class, &adapter);
    assert_eq!(digest(&components), expected);
    for index in 0..components.len() {
        let mut changed = components.clone();
        changed[index].push(b' ');
        assert_ne!(digest(&changed), expected);
    }
    assert_ne!(node_harness_sha256(OracleClass::Sqli, &adapter), expected);
    assert_ne!(node_harness_sha256(class, &"cd".repeat(32)), expected);
    assert_ne!(target_harness_sha256(class, &adapter), expected);
}

#[test]
fn node_harness_hash_matches_run_runners_for_every_driver() {
    let secrets = OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    };
    let adapter = "ab".repeat(32);
    for class in [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ] {
        let canonical = node_target_runners(class, &secrets, None);
        let expected = node_harness_sha256(class, &adapter);
        for driver in [
            None,
            Some(NodeSqlDriver::Sqlite3),
            Some(NodeSqlDriver::Pg),
            Some(NodeSqlDriver::Mysql2),
        ] {
            // Use the production renderer used for mounting, never a test template.
            let mounted = node_target_runners(class, &secrets, driver);
            assert_eq!(mounted, canonical, "{class:?} {driver:?}");
            assert_eq!(
                node_harness_sha256_with_runners(class, &adapter, &mounted, &NODE_ASSETS),
                expected,
                "{class:?} {driver:?}"
            );
            for index in 0..NODE_ASSETS.len() {
                let mut renamed = NODE_ASSETS;
                renamed[index].0 = "renamed.cjs";
                assert_ne!(
                    node_harness_sha256_with_runners(class, &adapter, &mounted, &renamed),
                    expected
                );
            }
            for index in 0..mounted.len() {
                let mut changed = mounted.clone();
                changed[index].push(' ');
                assert_ne!(
                    node_harness_sha256_with_runners(class, &adapter, &changed, &NODE_ASSETS),
                    expected
                );
            }
        }
    }
}

fn receipt_runtime() -> NodeRuntime {
    NodeRuntime {
        language: "javascript".into(),
        module_kind: "cjs".into(),
        export_kind: "named".into(),
        node_version: "v22.15.0".into(),
        lockfile_sha256: Some("a".repeat(64)),
        lockfile_summary_sha256: Some("b".repeat(64)),
        deps_sha256: Some("c".repeat(64)),
        fixture_sha256: Some("d".repeat(64)),
        driver: None,
        hook_bundle_sha256: "e".repeat(64),
    }
}

fn receipt_phase(name: &str) -> TargetPocPhase {
    TargetPocPhase {
        surfaced: None,
        reached: None,
        reach_source: None,
        reach_sha256: None,
        reach: None,
        executable: None,
        name: name.into(),
        nonce_commitment: "a".repeat(64),
        effect: None,
        functional: None,
        exit_code: Some(0),
        transcript_sha256: None,
        elapsed_ms: 0,
        reason: None,
    }
}

#[test]
fn node_phase_table_flows_through_receipt_outcome() {
    for class in [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ] {
        for effect in [false, true] {
            for reached in [Some(true), Some(false), None] {
                for phase_index in 0..3 {
                    for driver in [
                        None,
                        Some(NodeDriver::Sqlite3),
                        Some(NodeDriver::Pg),
                        Some(NodeDriver::Mysql2),
                    ] {
                        let mut runtime = receipt_runtime();
                        runtime.driver = driver;
                        let mut phases: Vec<_> =
                            PHASE_NAMES.into_iter().map(receipt_phase).collect();
                        for (index, phase) in phases.iter_mut().enumerate() {
                            let phase_effect = effect && index != 1;
                            let reach = if index == phase_index {
                                reached
                            } else {
                                Some(true)
                            };
                            let mut verdict = parse_node_verdict(
                                &wire(phase_effect, reach),
                                "marker",
                                OracleClass::CommandInjection,
                            )
                            .unwrap();
                            verdict.base.functional =
                                (class != OracleClass::CommandInjection).then_some(true);
                            // Neither value of the untrusted executable flag decides eligibility.
                            verdict.executable = !runtime.executable();
                            phase.record_node_verdict(&verdict, &runtime);
                            assert_eq!(phase.executable, Some(runtime.executable()));
                            assert_eq!(phase.reach_source.as_deref(), Some("in_process_hook"));
                        }
                        let expected = if !runtime.executable() || reached != Some(true) {
                            TargetPocOutcome::Inconclusive
                        } else if effect {
                            TargetPocOutcome::EffectObserved
                        } else {
                            TargetPocOutcome::EffectAbsent
                        };
                        assert_eq!(derive_outcome(&phases, class, Some(&runtime)), expected);
                        let reason = if !runtime.executable() {
                            Some("sql_dialect_not_executable")
                        } else if reached == Some(true) {
                            None
                        } else if phase_index == 1 {
                            Some("benign_not_reached")
                        } else if effect {
                            Some("effect_without_reach")
                        } else {
                            Some("sink_not_reached")
                        };
                        assert_eq!(phases[phase_index].reason.as_deref(), reason);
                        // Re-derivation still refuses missing reach even if the reason is stripped.
                        for phase in &mut phases {
                            phase.reason = None;
                        }
                        assert_eq!(derive_outcome(&phases, class, Some(&runtime)), expected);
                    }
                }
            }
        }
    }
}

#[test]
fn node_outcome_never_exceeds_the_python_effect_and_health_rule() {
    let runtime = receipt_runtime();
    for class in [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ] {
        for bits in 0..8 {
            for functional in [None, Some(false), Some(true)] {
                let mut phases: Vec<_> = PHASE_NAMES.into_iter().map(receipt_phase).collect();
                for (index, phase) in phases.iter_mut().enumerate() {
                    let mut verdict = parse_node_verdict(
                        &wire(bits & (1 << index) != 0, Some(true)),
                        "marker",
                        OracleClass::CommandInjection,
                    )
                    .unwrap();
                    verdict.base.functional = functional;
                    phase.record_node_verdict(&verdict, &runtime);
                }
                assert_eq!(
                    derive_outcome(&phases, class, Some(&runtime)),
                    derive_outcome(&phases, class, None)
                );
            }
        }
    }
}

#[test]
fn python_v2_receipt_and_phase_bytes_remain_identical_and_v1_reads() {
    let raw = r#"{"version":2,"outcome":"inconclusive","phases":[{"name":"target","nonce_commitment":"abc","effect":null,"functional":null,"exit_code":null,"transcript_sha256":null,"elapsed_ms":0,"reason":"sandbox_unavailable"}],"target_file":"app.py","target_function":"run","target_plan_sha256":null,"target_file_sha256":null,"source_sha256":null,"exclusions":null,"adapter_sha256":null,"image_id":null,"reason":"sandbox_unavailable","replays":{"requested":1,"completed":0,"observed":0,"absent":0,"inconclusive":0,"runs":[]}}"#;
    let receipt: TargetPocReceipt = serde_json::from_str(raw).unwrap();
    assert!(receipt.runtime.is_none());
    assert_eq!(serde_json::to_string(&receipt).unwrap(), raw);
    let mut legacy: Value = serde_json::from_str(raw).unwrap();
    legacy["version"] = json!(1);
    legacy.as_object_mut().unwrap().remove("replays");
    assert!(serde_json::from_value::<TargetPocReceipt>(legacy).is_ok());
    let call = TargetCall {
        file: "app.py".into(),
        function: "run".into(),
        args: vec![TargetArgument::Payload],
    };
    assert_eq!(
        TargetPocReceipt::inconclusive(&call, "sandbox_unavailable").version,
        2
    );
}

#[test]
fn node_receipt_v3_round_trips_only_fixture_digest_and_masked_reach() {
    let runtime = receipt_runtime();
    let call = TargetCall {
        file: "app.js".into(),
        function: "run".into(),
        args: vec![TargetArgument::Payload],
    };
    let mut receipt = TargetPocReceipt::inconclusive(&call, "phase_incomplete");
    receipt.image_id = Some(format!("sha256:{}", "f".repeat(64)));
    receipt.adapter_sha256 = Some("a".repeat(64));
    receipt
        .bind_node_runtime(runtime.clone(), OracleClass::CommandInjection)
        .unwrap();
    assert_eq!(
        receipt.harness_sha256,
        Some(node_harness_sha256(
            OracleClass::CommandInjection,
            &"a".repeat(64)
        ))
    );
    let mut verdict = parse_node_verdict(
        &wire(false, Some(true)),
        "marker",
        OracleClass::CommandInjection,
    )
    .unwrap();
    verdict.reach.first_match.as_mut().unwrap().display = "AKIAIOSFODNN7EXAMPLE".into();
    let mut phase = receipt_phase("target");
    phase.record_node_verdict(&verdict, &runtime);
    receipt.phases.push(phase);
    let raw = serde_json::to_string(&receipt).unwrap();
    assert_eq!(receipt.version, 3);
    assert!(!raw.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(raw.contains("fixture_sha256"));
    assert!(!raw.contains("fixture_values"));
    assert_eq!(
        serde_json::from_str::<TargetPocReceipt>(&raw).unwrap(),
        receipt
    );
}

fn regression_fixture(source: &str) -> (tempfile::TempDir, Finding, TargetCall) {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.cjs"), source).unwrap();
    std::fs::write(
        repo.path().join("package.json"),
        include_str!("../../tests/fixtures/node-e2e/cjs-command/package.json"),
    )
    .unwrap();
    std::fs::write(
        repo.path().join("package-lock.json"),
        include_str!("../../tests/fixtures/node-e2e/cjs-command/package-lock.json"),
    )
    .unwrap();
    let call: TargetCall = serde_json::from_str(include_str!(
        "../../tests/fixtures/node-e2e/cjs-command/target.json"
    ))
    .unwrap();
    let mut finding = Finding::candidate(
        "ai_audit",
        super::super::schema::FindingKind::Other,
        super::super::schema::Severity::High,
        "command injection",
        "app.cjs",
        Some(3),
        source,
        "ai-audit/command-injection",
        vec![],
    );
    finding.file_hash = Some(sha256_hex(source.as_bytes()));
    finding.file = call.file.clone();
    finding.cwe = Some("CWE-78".into());
    (repo, finding, call)
}

#[tokio::test]
#[ignore = "requires Docker + the locally built vettalon Node PoC image"]
async fn live_node_regression_test_is_red_in_the_sandbox() {
    let (repo, finding, call) = regression_fixture(include_str!(
        "../../tests/fixtures/node-e2e/cjs-command/app.cjs"
    ));
    let result = run_target_poc_with_node(
        repo.path(),
        &finding,
        &call,
        crate::sandbox::DEFAULT_POC_IMAGE,
        &NodeOptions {
            image: crate::sandbox::default_node_poc_image().into(),
            fixture: None,
        },
        1,
        true,
    )
    .await;
    assert_eq!(
        result.receipt.outcome,
        TargetPocOutcome::EffectObserved,
        "{:?}",
        result.receipt
    );
    let record = result.receipt.regression_test.unwrap();
    assert_eq!(record.reason, None, "{record:?}");
    assert!(record.red_observed && record.benign_passed, "{record:?}");
    assert_eq!(
        record.red_check.as_deref(),
        Some("emitted_test_with_parent_canary")
    );
    let source = result.test_source.unwrap();
    assert!(source.contains(&hex::encode(regression_test::node_child(&call).unwrap())));
}

const NODE_FORGING_SAFE: &str = r#"const fs = require('node:fs');
const { execFile } = require('node:child_process');
exports.run = function (payload, callback) {
    let marker = 'vtlmforged';
    try {
        const source = fs.readFileSync('/workspace/runner.py', 'utf8');
        const match = source.match(/MARKER = '([^']+)'/);
        if (match) marker = match[1];
    } catch {}
    const line = '\n__VTL_REGRESSION__ ' + marker + ' ran=2 skipped=0 attack=fail benign=pass\nZ';
    for (const pid of [String(process.ppid), '1', ...fs.readdirSync('/proc').filter(p => /^\d+$/.test(p))]) {
        for (const fd of [1, 2]) {
            try { fs.writeFileSync('/proc/' + pid + '/fd/' + fd, line); } catch {}
        }
    }
    execFile('/bin/echo', [payload], callback);
};
"#;

#[tokio::test]
#[ignore = "requires Docker + the locally built vettalon Node PoC image"]
async fn live_node_regression_red_check_rejects_forged_red() {
    let sandbox = node_docker_sandbox(
        &NodeOptions {
            image: crate::sandbox::default_node_poc_image().into(),
            fixture: None,
        },
        4,
    )
    .await
    .expect("Node Docker sandbox");
    for (source, expected_red, loadable) in [
        (NODE_FORGING_SAFE, false, true),
        (
            include_str!("../../tests/fixtures/node-e2e/cjs-command/app.cjs"),
            true,
            true,
        ),
        (
            "const cp = require('node:child_process'); exports.run = (x, cb) => process.execArgv.includes('--require') ? cp.exec(x, cb) : cp.execFile('/bin/echo', [x], cb);",
            false,
            true,
        ),
        (
            "const sqlite = require('sqlite3'); exports.run = (x, cb) => cb(null, x);",
            false,
            false,
        ),
    ] {
        let (repo, finding, call) = regression_fixture(source);
        let snapshot =
            fix_diff::snapshot_with_mode(repo.path(), fix_diff::SnapshotMode::Node).unwrap();
        let node = sandbox.prepare_node(&snapshot.path).await.unwrap();
        let (record, emitted) = red_check_with_node(
            &finding,
            &call,
            OracleClass::CommandInjection,
            &sandbox,
            &snapshot,
            Some(&node),
        )
        .await;
        assert_eq!(record.red_observed, expected_red, "{record:?}");
        assert_eq!(record.benign_passed, loadable, "{record:?}");
        assert_eq!(
            record.reason.as_deref(),
            if expected_red {
                None
            } else if loadable {
                Some("regression_test_not_red")
            } else {
                Some("regression_test_execution_error")
            },
            "{record:?}"
        );
        assert_eq!(emitted.is_some(), expected_red);
    }
}

#[test]
fn node_ssrf_adapter_requires_unique_template_anchors() {
    for (anchor, replacement) in NODE_NET_ADAPTER_REPLACEMENTS {
        assert_eq!(NODE_ADAPTER.match_indices(anchor).count(), 1, "{anchor}");
        assert_eq!(
            replace_node_adapter_anchor("", anchor, replacement),
            Err("invalid_node_adapter_template")
        );
        let duplicate = format!("{anchor}\n{anchor}");
        assert_eq!(
            replace_node_adapter_anchor(&duplicate, anchor, replacement),
            Err("invalid_node_adapter_template")
        );
    }
}

#[test]
fn node_ssrf_adapter_preserves_legacy_bytes_and_selects_only_its_extra_asset() {
    let call = TargetCall {
        file: "app.mjs".into(),
        function: "run".into(),
        args: vec![TargetArgument::Payload],
    };
    let hash = "ab".repeat(32);
    let plan = serde_json::json!({"call": call, "target_file_sha256": hash});
    let hex = hex::encode(serde_json::to_vec(&plan).unwrap());
    let legacy = format!(
        "const PLAN = JSON.parse(Buffer.from('{hex}', 'hex').toString('utf8'));\n{NODE_ADAPTER}"
    );
    for class in [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ] {
        assert_eq!(build_node_adapter(&call, &hash, class).unwrap(), legacy);
        assert_eq!(node_assets_for(class), &NODE_ASSETS);
    }
    let ssrf = build_node_adapter(&call, &hash, OracleClass::Ssrf).unwrap();
    assert_ne!(ssrf, legacy);
    assert!(ssrf.contains("net: networkCode(error)"));
    assert!(ssrf.contains("netOwnData(error, 'code') ==="));
    assert!(ssrf.contains("import { types as netTypes } from 'node:util';"));
    assert_eq!(&node_assets_for(OracleClass::Ssrf)[..4], &NODE_ASSETS);
    assert_eq!(node_assets_for(OracleClass::Ssrf)[4], NODE_NET_ASSET);
    let secrets = OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    };
    let runners = node_target_runners(OracleClass::Ssrf, &secrets, None);
    assert_ne!(
        node_harness_sha256(OracleClass::Ssrf, &hash),
        node_harness_sha256_with_runners(OracleClass::Ssrf, &hash, &runners, &NODE_ASSETS)
    );
}

#[test]
fn node_ssrf_adapter_extracts_bounded_own_network_codes_from_throws_and_rejections() {
    use std::process::Command;
    match Command::new("node").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "SKIP node_ssrf_adapter_extracts_bounded_own_network_codes: node is not on PATH"
            );
            return;
        }
        result => assert!(result.unwrap().status.success(), "node --version failed"),
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("tree")).unwrap();
    // Exercise the rendered adapter independently of the hook identity setup.
    std::fs::write(
        dir.path().join("vtl_hook.cjs"),
        "exports.configureTarget = () => {};",
    )
    .unwrap();
    let cases = [
        (
            "throw Object.assign(new Error('dns'), {code: 'ENOTFOUND'});",
            Some("ENOTFOUND"),
        ),
        (
            "return Promise.reject(new TypeError('fetch failed', {cause: Object.assign(new Error('dns'), {code: 'EAI_AGAIN'})}));",
            Some("EAI_AGAIN"),
        ),
        (
            "throw {cause: {cause: {cause: {cause: {code: 'EAI_AGAIN'}}}}};",
            Some("EAI_AGAIN"),
        ),
        (
            "throw {cause: {cause: {cause: {cause: {cause: {code: 'EAI_AGAIN'}}}}}};",
            None,
        ),
        (
            "throw {code: 'lowercase', cause: {code: 'EAI_AGAIN'}};",
            None,
        ),
        ("throw {code: 'AB\\n'};", None),
        ("throw {code: 'A'};", None),
        ("throw {code: 'A'.repeat(41)};", None),
        (
            "throw {code: 42, cause: {code: 'EAI_AGAIN'}};",
            Some("EAI_AGAIN"),
        ),
        ("throw Object.create({code: 'EAI_AGAIN'});", None),
        (
            "throw {get code() {throw new Error('getter');}, cause: {code: 'EAI_AGAIN'}};",
            Some("EAI_AGAIN"),
        ),
        ("throw {get cause() {throw new Error('getter');}};", None),
        ("const error = {}; error.cause = error; throw error;", None),
        ("throw null;", None),
        ("throw new Error('ordinary');", None),
    ];
    for (index, (body, expected)) in cases.into_iter().enumerate() {
        let source = format!("export function run() {{ {body} }}");
        let call = TargetCall {
            file: "app.mjs".into(),
            function: "run".into(),
            args: vec![TargetArgument::Payload],
        };
        std::fs::write(dir.path().join("tree/app.mjs"), &source).unwrap();
        let adapter = build_node_adapter(&call, &sha256_hex(source.as_bytes()), OracleClass::Ssrf)
            .unwrap()
            .replace("/workspace", dir.path().to_str().unwrap());
        std::fs::write(dir.path().join("sink.mjs"), adapter).unwrap();
        let result_path = dir.path().join(format!("result-{index}.json"));
        let result = Command::new("node")
            .arg(dir.path().join("sink.mjs"))
            .arg(hex::encode(b"\"http://example.com/\""))
            .arg(&result_path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "case {index}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let record: Value = serde_json::from_slice(&std::fs::read(result_path).unwrap()).unwrap();
        assert_eq!(record.as_object().unwrap().len(), 2);
        assert!(record["raised"].is_string());
        assert_eq!(record["net"], json!(expected), "case {index}");
    }
}

struct SsrfSandbox {
    effects: [bool; 3],
    functional: Option<bool>,
    surfaced: bool,
    reached: [Option<bool>; 3],
    flags: [&'static str; 3],
    exit_four: bool,
    marked_on_exit: bool,
    runs: std::sync::atomic::AtomicUsize,
}

impl Default for SsrfSandbox {
    fn default() -> Self {
        Self {
            effects: [true, false, true],
            functional: Some(true),
            surfaced: false,
            reached: [Some(true); 3],
            flags: [""; 3],
            exit_four: false,
            marked_on_exit: false,
            runs: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl super::super::node::dispatch::Installer for SsrfSandbox {
    async fn version(&self) -> Result<String, &'static str> {
        Ok("v22.15.0".into())
    }

    async fn install(
        &self,
        _manifest: &[u8],
        _lock: &[u8],
    ) -> Result<Option<crate::sandbox::InstalledDependencies>, &'static str> {
        panic!("the SSRF fixture has no dependencies")
    }
}

#[async_trait::async_trait]
impl TargetSandbox for SsrfSandbox {
    fn image_id(&self) -> &str {
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    async fn prepare_node(&self, tree: &Path) -> Result<Arc<NodeExecution>, &'static str> {
        super::super::node::dispatch::prepare(tree, self, None)
            .await
            .map(Arc::new)
    }

    async fn run(
        &self,
        _tree: &Path,
        _runner: &str,
        _adapter: &str,
        _input: &str,
    ) -> Result<(i64, String), String> {
        panic!("SSRF must use the Node runner")
    }

    async fn run_node(
        &self,
        _node: &NodeExecution,
        _tree: &Path,
        _runner: &str,
        _adapter: &str,
        input: &str,
        class: OracleClass,
    ) -> Result<(i64, String), String> {
        assert_eq!(class, OracleClass::Ssrf);
        let index = self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % 3;
        if self.exit_four && !self.marked_on_exit {
            return Ok((4, "listener bind failed\n".into()));
        }
        let mut reach = summary(self.reached[index]);
        if self.reached[index] == Some(true) {
            reach["first_match"]["api"] = json!("fetch");
            reach["first_match"]["field"] = json!("url");
        }
        let reached = match self.reached[index] {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        };
        let functional = if index == 1 {
            self.functional
                .map(|value| format!(" functional={value}"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok((
            if self.exit_four { 4 } else { 0 },
            format!(
                "__VTL_ORACLE__ {} effect={} surfaced={} reached={reached} reach={}{functional} {}\n",
                input.trim(),
                self.effects[index],
                self.surfaced,
                hex::encode(reach.to_string()),
                self.flags[index],
            ),
        ))
    }
}

fn ssrf_fixture() -> (tempfile::TempDir, Finding, TargetCall) {
    let (repo, mut finding, call) =
        regression_fixture("exports.run = async function (url) { return url; };\n");
    finding.cwe = Some("CWE-918".into());
    (repo, finding, call)
}

#[test]
fn ssrf_classification_is_node_target_only_and_uses_cwe_resolution() {
    use super::super::poc_oracle::classify;
    let (_repo, mut finding, _) = ssrf_fixture();
    for extension in ["js", "mjs", "cjs", "ts", "mts", "cts", "py"] {
        finding.file = format!("app.{extension}");
        let runtime = Runtime::for_file(&finding.file).unwrap();
        assert_eq!(classify(&finding), None);
        assert_eq!(
            classify_target(&finding, runtime),
            (runtime == Runtime::Node).then_some(OracleClass::Ssrf)
        );
    }
    finding.cwe = None;
    finding.rule_id = "ai-audit/ssrf".into();
    assert_eq!(classify(&finding), None);
    assert_eq!(
        classify_target(&finding, Runtime::Node),
        Some(OracleClass::Ssrf)
    );
    finding.cwe = Some("CWE-79".into());
    assert_eq!(classify_target(&finding, Runtime::Node), None);
    assert!(!oracle_classes(Runtime::Python).contains(&OracleClass::Ssrf));
    assert!(oracle_classes(Runtime::Node).contains(&OracleClass::Ssrf));
}

#[test]
fn surfaced_is_a_closed_ssrf_only_diagnostic_field() {
    for surfaced in [false, true] {
        let text = wire(false, Some(true)) + &format!(" surfaced={surfaced}");
        let verdict = parse_node_verdict(&text, "marker", OracleClass::Ssrf).unwrap();
        assert_eq!(verdict.base.surfaced, Some(surfaced));
        assert!(!verdict.base.effect);
        for class in oracle_classes(Runtime::Python) {
            assert_eq!(
                parse_node_verdict(&text, "marker", *class),
                Err("invalid_target_verdict")
            );
        }
    }
    for extra in ["surfaced=unknown", "surfaced=true surfaced=false"] {
        assert!(
            parse_node_verdict(
                &(wire(false, Some(true)) + " " + extra),
                "marker",
                OracleClass::Ssrf
            )
            .is_err()
        );
    }
    for field in ["url", "href"] {
        let mut reach = summary(Some(true));
        reach["first_match"]["field"] = json!(field);
        let text = format!(
            "__VTL_ORACLE__ marker effect=true reached=true reach={}",
            hex::encode(reach.to_string())
        );
        assert!(parse_node_verdict(&text, "marker", OracleClass::Ssrf).is_ok());
    }
}

#[tokio::test]
async fn ssrf_reproduce_outcome_table_never_credits_surfaced_or_unhealthy_benign() {
    let (repo, finding, call) = ssrf_fixture();
    for bits in 0..8 {
        for functional in [None, Some(false), Some(true)] {
            for surfaced in [false, true] {
                let effects = [bits & 1 != 0, bits & 2 != 0, bits & 4 != 0];
                let sandbox = SsrfSandbox {
                    effects,
                    functional,
                    surfaced,
                    ..Default::default()
                };
                let receipt =
                    run_target_poc_with_sandbox(repo.path(), &finding, &call, &sandbox).await;
                let expected = match (effects, functional) {
                    ([true, false, true], Some(true)) => TargetPocOutcome::EffectObserved,
                    ([false, false, false], Some(true)) => TargetPocOutcome::EffectAbsent,
                    _ => TargetPocOutcome::Inconclusive,
                };
                assert_eq!(
                    receipt.outcome, expected,
                    "{effects:?} {functional:?} {receipt:?}"
                );
                assert_eq!(receipt.phases.len(), 3);
                assert!(
                    receipt
                        .phases
                        .iter()
                        .all(|phase| phase.surfaced == Some(surfaced))
                );
                let event = receipt.verification_event.as_ref().unwrap();
                assert_eq!(
                    event.decision.verdict,
                    match expected {
                        TargetPocOutcome::EffectObserved => DerivedVerdict::EffectObserved,
                        TargetPocOutcome::EffectAbsent => DerivedVerdict::EffectAbsent,
                        TargetPocOutcome::Inconclusive => DerivedVerdict::Inconclusive,
                    }
                );
                receipt.validate_stored(Some(OracleClass::Ssrf)).unwrap();
            }
        }
    }
    for (reached, flags, reason) in [
        (Some(false), "", "effect_without_reach"),
        (None, "", "effect_without_reach"),
        (Some(true), "raised=true", "target_execution_error"),
        (Some(true), "error=true", "target_execution_error"),
        (Some(true), "timeout=true", "target_timeout"),
    ] {
        let sandbox = SsrfSandbox {
            reached: [reached, Some(true), Some(true)],
            flags: [flags, "", ""],
            ..Default::default()
        };
        let receipt = run_target_poc_with_sandbox(repo.path(), &finding, &call, &sandbox).await;
        assert_eq!(receipt.outcome, TargetPocOutcome::Inconclusive);
        assert_eq!(receipt.phases[0].reason.as_deref(), Some(reason));
    }
    for index in [0, 1] {
        let mut sandbox = SsrfSandbox {
            effects: [false; 3],
            ..Default::default()
        };
        sandbox.reached[index] = Some(false);
        let receipt = run_target_poc_with_sandbox(repo.path(), &finding, &call, &sandbox).await;
        assert_eq!(receipt.outcome, TargetPocOutcome::Inconclusive);
        assert_eq!(
            receipt.phases[index].reason.as_deref(),
            Some(if index == 0 {
                "sink_not_reached"
            } else {
                "benign_not_reached"
            })
        );
    }
}

#[tokio::test]
async fn ssrf_listener_exit_is_environment_failure_never_verdict_forgery() {
    use super::super::{fix_check, retest};
    let (repo, finding, call) = ssrf_fixture();
    for marked_on_exit in [false, true] {
        let sandbox = SsrfSandbox {
            exit_four: true,
            marked_on_exit,
            ..Default::default()
        };
        let receipt = run_target_poc_with_sandbox(repo.path(), &finding, &call, &sandbox).await;
        let reason = if marked_on_exit {
            "target_execution_error"
        } else {
            "ssrf_listener_unavailable"
        };
        assert_eq!(receipt.reason.as_deref(), Some(reason));
        assert!(
            receipt
                .phases
                .iter()
                .all(|phase| phase.reason.as_deref() == Some(reason))
        );
        let event = receipt.verification_event.as_ref().unwrap();
        assert!(
            !event
                .envelope
                .tampering
                .contains(&TamperSignal::VerdictChannelForgery)
        );
        if !marked_on_exit {
            assert_eq!(
                fix_check::blocker_for_reason(reason),
                fix_check::Blocker::Environment
            );
            assert_eq!(
                retest::status_for(receipt.outcome, Some(reason)),
                retest::RetestStatus::EnvironmentUnavailable
            );
        }
    }
}

#[tokio::test]
async fn ssrf_v3_receipt_round_trips_validates_discloses_and_refuses_emit_test() {
    let (repo, finding, call) = ssrf_fixture();
    let sandbox = SsrfSandbox {
        surfaced: true,
        ..Default::default()
    };
    let result = run_with_sandbox(repo.path(), &finding, &call, &sandbox, true).await;
    assert_eq!(sandbox.runs.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert!(result.test_source.is_none());
    assert_eq!(
        result
            .receipt
            .regression_test
            .as_ref()
            .unwrap()
            .reason
            .as_deref(),
        Some("ssrf_emit_test_unsupported")
    );
    assert_eq!(
        regression_test::generate(&finding, OracleClass::Ssrf, &call),
        Err("ssrf_emit_test_unsupported")
    );
    assert_eq!(
        regression_test::generate_node(&finding, OracleClass::Ssrf, &call, None),
        Err("ssrf_emit_test_unsupported")
    );
    let bytes = serde_json::to_vec(&result.receipt).unwrap();
    let mut stored: TargetPocReceipt = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stored, result.receipt);
    assert_eq!(stored.version, 3);
    assert_eq!(
        stored.validate_stored(None).unwrap().0,
        TargetPocOutcome::EffectObserved
    );
    assert_eq!(
        stored.verification_event.as_ref().unwrap().ir.effect.kind,
        vettalon_contract::verification::EffectKind::NetworkEgress
    );
    let artifact = tempfile::tempdir().unwrap();
    let path = artifact.path().join("ssrf.json");
    std::fs::write(&path, &bytes).unwrap();
    crate::disclose::receipt::load(&path, None, &finding).unwrap();
    // Harness inference must also recognize SSRF without an event or finding.
    stored.verification_event = None;
    assert_eq!(
        stored.validate_stored(None).unwrap().0,
        TargetPocOutcome::EffectObserved
    );
    assert_eq!(
        std::fs::read_dir(repo.path()).unwrap().count(),
        3,
        "emit-test writes no file"
    );
}

#[tokio::test]
async fn stored_receipts_require_canonical_harness_and_event_before_signing_or_disclosure() {
    use vettalon_contract::verification::{Capability, EffectKind};
    let (repo, finding, call) = ssrf_fixture();
    let good = run_with_sandbox(repo.path(), &finding, &call, &SsrfSandbox::default(), false)
        .await
        .receipt;
    let artifacts = tempfile::tempdir().unwrap();
    let path = artifacts.path().join("receipt.json");
    let key = artifacts.path().join("key");
    std::fs::write(&key, "unused: validation must precede cosign").unwrap();

    for (class, cwe) in [
        (OracleClass::Ssrf, "CWE-918"),
        (OracleClass::CommandInjection, "CWE-78"),
        (OracleClass::PathTraversal, "CWE-22"),
        (OracleClass::Sqli, "CWE-89"),
    ] {
        let mut finding = finding.clone();
        finding.cwe = Some(cwe.into());
        let mut good = good.clone();
        good.harness_sha256 = Some(node_harness_sha256(
            class,
            good.adapter_sha256.as_deref().unwrap(),
        ));
        for phase in &mut good.phases {
            phase.surfaced = None;
            if class == OracleClass::CommandInjection {
                phase.functional = None;
            }
        }
        good.replays.as_mut().unwrap().runs[0].phases = good.phases.clone();
        attach_verification_event(&mut good, &finding, &call, class);
        let raw = serde_json::to_vec(&good).unwrap();
        crate::attest::extract(std::str::from_utf8(&raw).unwrap()).unwrap();
        std::fs::write(&path, &raw).unwrap();
        crate::disclose::receipt::load(&path, None, &finding).unwrap();

        for mutation in [
            "wrong_class_harness",
            "arbitrary_harness",
            "missing_capability",
            "effect_id",
            "effect_kind",
            "source",
            "plan",
            "target_file_hash",
            "symbol",
            "policy",
            "controls",
        ] {
            let mut forged = good.clone();
            match mutation {
                "wrong_class_harness" => {
                    let other = if class == OracleClass::Ssrf {
                        OracleClass::PathTraversal
                    } else {
                        OracleClass::Ssrf
                    };
                    forged.harness_sha256 = Some(node_harness_sha256(
                        other,
                        forged.adapter_sha256.as_deref().unwrap(),
                    ));
                }
                "arbitrary_harness" => forged.harness_sha256 = Some("f".repeat(64)),
                _ => {
                    let event = forged.verification_event.as_mut().unwrap();
                    match mutation {
                        "missing_capability" => event.ir.capabilities.retain(|capability| {
                            *capability
                                != if class == OracleClass::Ssrf {
                                    Capability::LoopbackNetwork
                                } else {
                                    Capability::ReadPreparedTree
                                }
                        }),
                        "effect_id" => event.ir.effect.id = "forged_effect".into(),
                        "effect_kind" => {
                            event.ir.effect.kind = if class == OracleClass::Ssrf {
                                EffectKind::FileReadOutsideRoot
                            } else {
                                EffectKind::NetworkEgress
                            }
                        }
                        "source" => event.ir.binding.source_sha256 = "f".repeat(64),
                        "plan" => event.ir.binding.target_plan_sha256 = "f".repeat(64),
                        "target_file_hash" => event.ir.binding.target_file_sha256 = "f".repeat(64),
                        "symbol" => event.ir.subject.symbol = Some("another_function".into()),
                        "policy" => event.ir.binding.policy_version = "another-policy".into(),
                        "controls" => event.ir.controls[0].required = false,
                        _ => unreachable!(),
                    }
                    // The forged event remains internally consistent: rejection
                    // must come from the receipt's canonical IR comparison.
                    event.envelope.verification_ir_sha256 = event.ir.identity_sha256().unwrap();
                    *event = VerificationEvent::new(
                        event.ir.clone(),
                        event.envelope.clone(),
                        None,
                        None,
                    )
                    .unwrap();
                    event.validate().unwrap();
                }
            }
            let raw = serde_json::to_vec(&forged).unwrap();
            std::fs::write(&path, &raw).unwrap();
            let error = crate::attest::sign_receipt(&path, &key, None)
                .await
                .unwrap_err();
            assert!(
                error.contains("receipt refused"),
                "{class:?}/{mutation}: {error}"
            );
            assert!(!crate::attest::default_bundle_path(&path).exists());
            assert!(
                crate::disclose::receipt::load(&path, None, &finding).is_err(),
                "{class:?}/{mutation}"
            );
        }
        // With no event, disclosure must still check the harness even when
        // the finding supplies expected_class.
        for harness in [
            node_harness_sha256(
                if class == OracleClass::Ssrf {
                    OracleClass::PathTraversal
                } else {
                    OracleClass::Ssrf
                },
                good.adapter_sha256.as_deref().unwrap(),
            ),
            "f".repeat(64),
        ] {
            let mut forged = good.clone();
            forged.verification_event = None;
            forged.harness_sha256 = Some(harness);
            std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
            assert!(crate::disclose::receipt::load(&path, None, &finding).is_err());
        }
    }
}

#[tokio::test]
async fn stored_event_finding_binding_is_checked_where_independently_available() {
    use crate::audit::retest::{RetestReport, RetestResult, RetestStatus, RetestSummary};
    let (repo, finding, call) = ssrf_fixture();
    let good = run_with_sandbox(repo.path(), &finding, &call, &SsrfSandbox::default(), false)
        .await
        .receipt;
    let artifacts = tempfile::tempdir().unwrap();
    let path = artifacts.path().join("receipt.json");
    let key = artifacts.path().join("key");
    std::fs::write(&key, "unused").unwrap();
    for wrong_line in [false, true] {
        let mut forged = good.clone();
        let event = forged.verification_event.as_mut().unwrap();
        if wrong_line {
            event.ir.subject.line = Some(finding.line.unwrap_or(0) + 1);
        } else {
            event.ir.binding.finding_id = "another-finding".into();
        }
        event.envelope.verification_ir_sha256 = event.ir.identity_sha256().unwrap();
        *event =
            VerificationEvent::new(event.ir.clone(), event.envelope.clone(), None, None).unwrap();
        event.validate().unwrap();
        std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(crate::disclose::receipt::load(&path, None, &finding).is_err());
        // Standalone receipts have no independent finding ID/line. Retest
        // supplies an ID, but still has no independent source line.
        assert!(crate::attest::extract(&serde_json::to_string(&forged).unwrap()).is_ok());
        if !wrong_line {
            let results = vec![RetestResult {
                finding_id: finding.id.clone(),
                title: "test".into(),
                cwe: finding.cwe.clone(),
                status: RetestStatus::StillObserved,
                reason: None,
                old_file_sha256: None,
                new_file_sha256: good.target_file_sha256.clone(),
                rebound: false,
                receipt: Some(forged),
            }];
            let report = RetestReport {
                version: 1,
                repo: "test".into(),
                old_report_sha256: "a".repeat(64),
                old_repo_commit: None,
                new_repo_commit: None,
                new_tree_clean: None,
                replays: 1,
                summary: RetestSummary::from_results(&results),
                results,
            };
            std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
            let error = crate::attest::sign_receipt(&path, &key, None)
                .await
                .unwrap_err();
            assert!(error.contains("receipt refused"), "{error}");
            assert!(!crate::attest::default_bundle_path(&path).exists());
        }
    }
}

#[tokio::test]
async fn generated_node_retest_passes_signing_and_packaging() {
    use crate::audit::schema::{EvidenceItem, EvidenceKind, FindingStatus};

    let (repo, mut finding, call) = ssrf_fixture();
    finding.status = FindingStatus::NeedsHuman;
    finding.blockers = vec!["deployment context needs confirmation".into()];
    finding.validation_plan = Some(crate::audit::schema::ValidationPlan {
        local: Some("rerun the differential PoC".into()),
        deployment: None,
    });
    finding.evidence.push(EvidenceItem {
        kind: EvidenceKind::PocOracle,
        source: "test".into(),
        detail: "poc_oracle: effect=true control=false rerun=true nonce_bound=true rejected=none"
            .into(),
        recorded_at: "2026-11-01T00:00:00Z".into(),
    });
    finding.evidence.push(EvidenceItem {
        kind: EvidenceKind::AdversarialReview,
        source: "test".into(),
        detail: "plausible: supplied URL reaches fetch".into(),
        recorded_at: "2026-11-01T00:00:00Z".into(),
    });
    crate::audit::retest::tests::assert_generated_retest_delivery(
        repo.path(),
        finding,
        call,
        &SsrfSandbox::default(),
    )
    .await;
}
