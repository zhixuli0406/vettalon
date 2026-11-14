use super::super::engagement::{Engagement, FindingEngagement};
use super::super::inputs::{IdSource, SourceKind};
use super::super::text::{load_mapping, load_text};
use super::*;
use crate::audit::fix_check::{Blocker, CheckResult, FixOutcome};
use crate::audit::retest::{RetestStatus, RetestSummary};
use crate::audit::target_poc::TargetPocOutcome;

fn sample() -> Record {
    let evidence = Evidence {
        file: "receipts/retest/sample.json".into(),
        file_sha256: "a".repeat(64),
        pointer: "/results/0/receipt".into(),
        object_sha256: "b".repeat(64),
    };
    let report_text = |text: &str| ReportText {
        text: text.into(),
        truncated: false,
        full_sha256: None,
        origin: "report_text",
    };
    let run = RunRecord {
        receipt_version: 3,
        outcome: TargetPocOutcome::EffectAbsent,
        label: reproduce_outcome_label(TargetPocOutcome::EffectAbsent),
        reason: None,
        replays: Replays {
            requested: 2,
            completed: 2,
            observed: 0,
            absent: 2,
            inconclusive: 0,
        },
        phases: vec![PhaseRecord {
            name: "probe".into(),
            effect: Some(false),
            functional: Some(true),
            reached: None,
            transcript_sha256: Some("c".repeat(64)),
        }],
        environment: Environment {
            image_id: Some("sha256:sample".into()),
            ..Environment::default()
        },
        started_at: None,
        producer_version: None,
    };
    let original_evidence = Evidence {
        file: "receipts/reproduce/original.json".into(),
        file_sha256: "d".repeat(64),
        pointer: String::new(),
        object_sha256: "d".repeat(64),
    };
    let fix_evidence = Evidence {
        file: "receipts/fix-check/check.json".into(),
        file_sha256: "e".repeat(64),
        pointer: String::new(),
        object_sha256: "e".repeat(64),
    };
    let sources = [
        (&evidence, SourceKind::Retest),
        (&original_evidence, SourceKind::Reproduce),
        (&fix_evidence, SourceKind::FixCheck),
    ]
    .into_iter()
    .map(|(e, kind)| SourceRecord {
        kind,
        path: e.file.clone(),
        sha256: e.file_sha256.clone(),
        bytes: 100,
        signature: None,
    })
    .collect();
    Record {
        schema: RECORD_SCHEMA,
        vettalon_version: "sample-version",
        languages: vec!["zh-TW".into(), "en".into()],
        mapping_version: Some("retest-mapping/1".into()),
        limits: vec!["limit.outcome".into()],
        sources,
        engagement: Engagement {
            client: Some("Example <script>alert(1)</script>".into()),
            ..Engagement::default()
        },
        revisions: Revisions {
            old_report_sha256: None,
            report_sha256: None,
            report_included: false,
            old_repo_commit: Some("1".repeat(40)),
            new_repo_commit: Some("2".repeat(40)),
            new_tree_clean: None,
            tree_warning: Some(tree_not_clean_label()),
            old_scan_started_at: None,
            retest_started_at: None,
            replays_requested: Some(2),
        },
        summary: SummaryRecord {
            retest: Some(RetestSummary {
                not_observed: 1,
                ..RetestSummary::default()
            }),
            fix_outcomes: BTreeMap::from([("fix_check_partial", 1)]),
        },
        findings: vec![FindingRecord {
            id: "F-1\u{202e}".into(),
            id_source: IdSource::Retest,
            binding_note: None,
            title: Some(report_text("Example finding")),
            cwe: Some(report_text("CWE-22")),
            file: Some(report_text("src/a|b.py")),
            function: Some(report_text("lookup`name")),
            line: Some(7),
            runtime: Some("python"),
            oracle_class: Some("file_read"),
            original: Some(OriginalRecord {
                run: RunRecord {
                    outcome: TargetPocOutcome::EffectObserved,
                    label: reproduce_outcome_label(TargetPocOutcome::EffectObserved),
                    replays: Replays {
                        requested: 2,
                        completed: 2,
                        observed: 2,
                        absent: 0,
                        inconclusive: 0,
                    },
                    ..run.clone()
                },
                evidence: original_evidence,
            }),
            retest: Some(RetestRecord {
                status: RetestStatus::NotObserved,
                label: retest_status_label(RetestStatus::NotObserved),
                reason: None,
                rebound: true,
                old_file_sha256: Some("3".repeat(64)),
                new_file_sha256: Some("4".repeat(64)),
                run: Some(run),
                evidence,
            }),
            fix_checks: vec![FixCheckRecord {
                outcome: FixOutcome::FixCheckPartial,
                label: fix_outcome_label(FixOutcome::FixCheckPartial),
                original: CheckResult::Pass,
                variants: CheckResult::Pass,
                benign: CheckResult::Pass,
                tests: CheckResult::NotRun,
                inputs: InputCounts {
                    blocked: 1,
                    total: 1,
                },
                decoding: DecodingCounts {
                    blocked: 0,
                    applicable: 0,
                    total: 0,
                },
                blocker: Blocker::None,
                blocker_label: None,
                reason: None,
                legacy_format: false,
                diff_sha256: "5".repeat(64),
                variant_set_sha256: Some("6".repeat(64)),
                variant_generator_version: None,
                test_command_sha256: None,
                per_input: vec![FixInputRecord {
                    id: "base",
                    fixed_copy: FixedCopy::Blocked,
                }],
                environment: Environment::default(),
                started_at: None,
                producer_version: None,
                evidence: fix_evidence,
            }],
            inputs: InputsRecord {
                determinable: true,
                note: None,
                items: vec![InputRecord {
                    role: InputRole::Base,
                    id: "base",
                    text: "<script>```payload````</script>".into(),
                    truncated: false,
                    text_sha256: None,
                    fixed_copy: FixedCopy::Blocked,
                    original_copy: OriginalCopy::Effect,
                }],
            },
            call: CallRecord {
                supplied: true,
                note: None,
                plan_sha256s: vec!["7".repeat(64)],
                file: Some(report_text("src/a|b.py")),
                function: Some(report_text("lookup`name")),
                args: vec![ArgRecord {
                    kind: "payload",
                    value: None,
                    truncated: false,
                    value_sha256: None,
                }],
            },
            operator: FindingEngagement {
                tester_conclusion: Some("fixed / secure / 已修補 — tester statement".into()),
                ..FindingEngagement::default()
            },
        }],
    }
}

fn render(record: &Record, lang: Lang) -> String {
    render_markdown(
        record,
        lang,
        &load_text().unwrap(),
        &load_mapping(&record_field_paths()).unwrap(),
    )
    .unwrap()
}

#[test]
fn golden_records_are_byte_identical() {
    let record = sample();
    let expected_json: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/retest-package/sample-record.json"
    ))
    .unwrap();
    assert_eq!(serde_json::to_value(&record).unwrap(), expected_json);
    for (lang, expected) in [
        (
            Lang::ZhTw,
            include_str!("../../../../tests/fixtures/retest-package/record.zh-TW.md"),
        ),
        (
            Lang::En,
            include_str!("../../../../tests/fixtures/retest-package/record.en.md"),
        ),
    ] {
        let actual = render(&record, lang);
        assert_eq!(actual.as_bytes(), expected.as_bytes());
        assert!(actual.ends_with('\n'));
        assert!(!actual.contains('\r'));
    }
}

#[test]
fn untrusted_text_cannot_inject_markdown_or_html() {
    let mut record = sample();
    record.findings[0].operator.location =
        Some("[link](javascript:alert(1))\r\n# injected\u{0007}".into());
    for lang in [Lang::ZhTw, Lang::En] {
        let output = render(&record, lang);
        assert!(output.contains(&code("src/a|b.py:7")));
        assert!(output.contains(&code("lookup`name")));
        assert!(output.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(output.contains(&code("F-1\u{202e}")));
        assert!(!output.contains('\u{202e}'));
        assert!(output.contains(&md("[link](javascript:alert(1))\r\n# injected\u{0007}")));
        assert!(output.contains(&code("<script>```payload````</script>")));
        let without_input = output.replace(&code("<script>```payload````</script>"), "");
        assert!(!without_input.contains('<'));
        assert!(!without_input.contains('>'));
    }
}

#[test]
fn machine_output_has_no_forbidden_claims() {
    let record = sample();
    for lang in [Lang::ZhTw, Lang::En] {
        let mut output = render(&record, lang);
        output = output.replace(
            &sanitize(
                record.findings[0]
                    .operator
                    .tester_conclusion
                    .as_deref()
                    .unwrap(),
            ),
            "",
        );
        output = output.replace(&sanitize(&record.findings[0].inputs.items[0].text), "");
        for word in [
            "fixed",
            "secure",
            "remediated",
            "已修補",
            "已修復",
            "修補完成",
            "安全無虞",
        ] {
            assert!(
                !output.to_lowercase().contains(word),
                "forbidden wording: {word}"
            );
        }
    }
}

#[test]
fn explicit_locale_sorted_rows_and_missing_text() {
    let record = sample();
    let mut shuffled = record.clone();
    shuffled.sources.reverse();
    let mut mapping = load_mapping(&record_field_paths()).unwrap();
    mapping.frameworks.reverse();
    for framework in &mut mapping.frameworks {
        framework.rows.reverse();
    }
    let text = load_text().unwrap();
    for lang in [Lang::ZhTw, Lang::En] {
        assert_eq!(
            render(&record, lang),
            render_markdown(&shuffled, lang, &text, &mapping).unwrap()
        );
        crate::lang::with(
            if lang == Lang::ZhTw {
                Lang::En
            } else {
                Lang::ZhTw
            },
            || {
                assert_eq!(
                    render(&record, lang),
                    render_markdown(&record, lang, &text, &mapping).unwrap()
                );
            },
        );
    }
    let mut text = text;
    text.locales
        .get_mut("en")
        .unwrap()
        .remove("status.not_observed");
    assert!(render_markdown(&record, Lang::En, &text, &mapping).is_err());
}

#[test]
fn unchecked_rows_missing_receipts_and_operator_blanks() {
    let mut record = sample();
    record.findings[0].original = None;
    record.findings[0].retest = None;
    record.findings[0].fix_checks.clear();
    record.findings[0].operator.tester_conclusion = None;
    record.findings[0].inputs.determinable = false;
    record.findings[0].inputs.items.clear();
    record.findings[0].call.supplied = false;
    let mut mapping = load_mapping(&record_field_paths()).unwrap();
    for framework in &mut mapping.frameworks {
        framework.source_checked = true;
    }
    let text = load_text().unwrap();
    for (lang, locale) in [(Lang::ZhTw, "zh-TW"), (Lang::En, "en")] {
        let output = render_markdown(&record, lang, &text, &mapping).unwrap();
        assert_eq!(output.matches("PCI SSC").count(), 1);
        assert!(output.contains(&md(text.get(locale, "not_recorded").unwrap())));

        assert!(output.contains(&md(text.get(locale, "not_determinable").unwrap())));
    }
}

#[test]
fn standalone_text_and_all_fence_lengths_are_escaped() {
    for value in ["[x](https://example.test)", "# title", "&lt;script&gt;"] {
        assert_ne!(md(value), value);
    }
    for value in ["---", "- item", "+ item", "1. item", "foo(a-b.py)"] {
        assert_eq!(md(value), value);
    }
    for size in 0..32 {
        let input = format!("{}x{}", "`".repeat(size), "`".repeat(size + 1));
        assert!(fence_for(&input).len() > size + 1);
        let span = code(&input);
        let fence = "`".repeat(size + 2);
        assert!(span.starts_with(&format!("{fence} ")));
        assert!(span.ends_with(&format!(" {fence}")));
        let mut record = sample();
        record.findings[0].inputs.items[0].text = format!("{input}\nsecond line");
        let shown = block_text(&record.findings[0].inputs.items[0].text);
        assert!(render(&record, Lang::En).contains(&format!(
            "{}\n{}\n{}",
            fence_for(&shown),
            shown,
            fence_for(&shown)
        )));
    }
}

#[test]
fn machine_labels_always_use_text_keys() {
    let text = load_text().unwrap();
    let mut record = sample();
    // Deliberately incorrect embedded labels must never leak into Markdown.
    let wrong = Label {
        zh_tw: "WRONG LABEL",
        en: "WRONG LABEL",
    };
    record.findings[0].original.as_mut().unwrap().run.label = wrong;
    record.findings[0].retest.as_mut().unwrap().label = wrong;
    record.findings[0].fix_checks[0].label = wrong;
    for status in RetestStatus::ALL {
        record.findings[0].retest.as_mut().unwrap().status = status;
        for (lang, locale) in [(Lang::ZhTw, "zh-TW"), (Lang::En, "en")] {
            let output = render(&record, lang);
            assert!(
                output.contains(&md(text
                    .get(locale, &format!("status.{}", status.key()))
                    .unwrap()))
            );
            assert!(!output.contains("WRONG LABEL"));
        }
    }
    for outcome in [
        FixOutcome::FixVerified,
        FixOutcome::FixCheckPartial,
        FixOutcome::FixRejected,
        FixOutcome::FixUnverified,
    ] {
        record.findings[0].fix_checks[0].outcome = outcome;
        for (lang, locale) in [(Lang::ZhTw, "zh-TW"), (Lang::En, "en")] {
            assert!(
                render(&record, lang).contains(&md(text
                    .get(locale, &format!("outcome.{}", outcome.key()))
                    .unwrap()))
            );
        }
    }
}

#[test]
fn evidence_ids_resolve_and_no_appendix_entry_is_unused() {
    for lang in [Lang::ZhTw, Lang::En] {
        let output = render(&sample(), lang);
        let title = if lang == Lang::ZhTw {
            "## 7. 佐證"
        } else {
            "## 7. Evidence appendix"
        };
        let (body, appendix) = output.split_once(title).unwrap();
        let ids = |text: &str| -> BTreeSet<String> {
            text.split('`')
                .filter(|v| {
                    v.strip_prefix('E')
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                })
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(ids(body), ids(appendix));
        assert_eq!(ids(appendix).len(), sample().sources.len());
        for source in sample().sources {
            assert_eq!(output.matches(&source.sha256).count(), 1);
        }
    }
}

#[test]
fn compact_layout_uses_fixed_order_and_deduplicates_environments() {
    let mut record = sample();
    record.findings.push(record.findings[0].clone());
    let output = render(&record, Lang::En);
    assert!(output.find("| Client |").unwrap() < output.find("| Identifier |").unwrap());
    assert_eq!(output.matches("### `python`").count(), 2);
    assert!(output.contains("### `python` (`E2`, `E3`)"));
    assert!(output.contains("### `python` (`E1`)"));
    assert!(!output.contains("| Evidence |"));
    assert_eq!(output.matches("`sha256:sample`").count(), 1);
    assert!(!output.contains("pci-dss-4.0.1-11.4.4"));
    assert!(output.contains("### PCI DSS v4.0.1 11.4.4"));
}

#[test]
fn input_rows_cite_only_supporting_receipts_and_use_safe_spans() {
    let mut record = sample();
    record.findings[0].inputs.items.push(InputRecord {
        id: "variant",
        role: InputRole::Variant,
        text: "a|b.py(1)".into(),
        truncated: false,
        text_sha256: None,
        original_copy: OriginalCopy::NotRecorded,
        fixed_copy: FixedCopy::NotRecorded,
    });
    let output = render(&record, Lang::En);
    let base = output.lines().find(|v| v.starts_with("| `base`")).unwrap();
    assert!(base.contains("`E1`"));
    assert!(base.contains("`E2`"));
    assert!(!base.contains("`E3`"));
    let variant = output
        .lines()
        .find(|v| v.starts_with("| `variant`"))
        .unwrap();
    assert!(variant.contains(&code("a|b.py(1)")));
    assert!(!variant.contains("`E"));
    assert!(output.contains("## 1. Basic information"));
    assert!(!output.contains("| 0 |"));
}

#[test]
fn signature_files_get_stable_appendix_ids_and_status() {
    let mut record = sample();
    record.sources[0].signature = Some(SignatureRecord {
        mldsa: None,
        path: "signatures/sample.sigstore.json".into(),
        sha256: "f".repeat(64),
        subject_ok: true,
        cosign: None,
    });
    let output = render(&record, Lang::En);
    assert!(output.contains("Content matched; cryptographic signature unverified (`E4`)"));
    assert!(output.contains("| `E4` | Signature | `signatures/sample.sigstore.json` |"));
    assert_eq!(output.matches(&"f".repeat(64)).count(), 1);
}

#[test]
fn input_roles_preserve_variant_order_and_put_benign_last() {
    let mut record = sample();
    let base = record.findings[0].inputs.items[0].clone();
    let item = |id, role| InputRecord {
        id,
        role,
        ..base.clone()
    };
    record.findings[0].inputs.items = vec![
        item("benign", InputRole::Benign),
        item("decode-z", InputRole::Decoding),
        item("variant-z", InputRole::Variant),
        item("base", InputRole::Base),
        item("variant-a", InputRole::Variant),
        item("decode-a", InputRole::Decoding),
    ];
    for lang in [Lang::ZhTw, Lang::En] {
        let output = render(&record, lang);
        let positions = [
            "base",
            "variant-z",
            "variant-a",
            "decode-z",
            "decode-a",
            "benign",
        ]
        .map(|id| output.find(&format!("| `{id}` (")).unwrap());
        assert!(positions.windows(2).all(|p| p[0] < p[1]));
    }
}

#[test]
fn absent_judgement_is_plain_and_mapping_uses_labels() {
    let mut record = sample();
    record.findings[0].operator.tester_conclusion = None;
    for (lang, missing) in [(Lang::ZhTw, "未記錄"), (Lang::En, "not recorded")] {
        let output = render(&record, lang);
        assert!(output.contains(&format!("\n\n{missing}\n\n")));
        assert!(!output.contains(&format!("```\n{missing}\n```")));
        assert!(!output.contains("findings[]"));
        assert!(!output.contains("engagement."));
        assert!(!output.contains("revisions."));
    }
}

#[test]
fn report_citation_is_a_fact_instead_of_a_dangling_line() {
    let mut record = sample();
    record.sources.push(SourceRecord {
        kind: SourceKind::Report,
        path: "report/report.json".into(),
        sha256: "9".repeat(64),
        bytes: 100,
        signature: None,
    });
    for (lang, label) in [(Lang::ZhTw, "報告佐證"), (Lang::En, "Report evidence")] {
        let output = render(&record, lang);
        assert!(output.contains(&format!("| {label} | `E4` |")));
        assert!(!output.contains("\n\n`E4`\n\n"));
    }
}

#[test]
fn hybrid_status_uses_only_verification_stamps_and_localized_text() {
    use crate::audit::retest_package::record::{MldsaRecord, MldsaSignatureRecord};
    let mut record = sample();
    record.sources[0].signature = Some(SignatureRecord {
        path: "signatures/sample.json".into(),
        sha256: "f".repeat(64),
        subject_ok: true,
        cosign: None,
        mldsa: Some(MldsaSignatureRecord {
            path: "signatures-pq/sample.json".into(),
            sha256: "e".repeat(64),
            binding_ok: true,
            verified: None,
        }),
    });
    for lang in [Lang::En, Lang::ZhTw] {
        let output = render(&record, lang);
        assert!(output.contains("signatures-pq/sample.json"));
        assert!(output.contains(if lang == Lang::En {
            "content-matched, not verified"
        } else {
            "內容相符，未驗證簽章"
        }));
    }
    record.sources[0]
        .signature
        .as_mut()
        .unwrap()
        .mldsa
        .as_mut()
        .unwrap()
        .verified = Some(MldsaRecord {
        verified: true,
        key_sha256: "a".repeat(64),
    });
    assert!(
        render(&record, Lang::En)
            .contains("ML-DSA-65 layer cryptographically verified with supplied key")
    );
}
