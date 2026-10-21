//! Per-finding evidence block of the terminal summary.
//!
//! Terminal text only. SARIF (`vettalon.proof_limits`) and the
//! `evidence attach` command keep printing [`Finding::proof_summary`], and
//! [`Finding::evidence_summary`] keeps its key=value line; neither changes.

use crate::audit::evidence_level::{EvidenceLevel, ProofGap};
use crate::audit::fix_check::FixOutcome;
use crate::audit::schema::{
    AuditReport, EvidenceKind, Finding, ProofEvidence, ProofLevel, ProofOrigin,
};
use crate::lang::pick;
use crate::tr;

/// Appends one block per finding plus the shared proof caveat, then a blank
/// line. Appends nothing when the report has no findings.
pub(super) fn render_finding_evidence(report: &AuditReport, out: &mut String) {
    if report.findings.is_empty() {
        return;
    }
    out.push_str(pick("各項發現的證據：\n", "Evidence per finding:\n"));
    for finding in &report.findings {
        render_finding(finding, out);
    }
    out.push('\n');
    out.push_str(pick(
        "  注意：結束碼 0、連結或檔案雜湊本身都不能證明漏洞存在。手動附上的實證只照原樣記錄，vettalon 不查核它的來源，也不會自己重跑驗證。\n",
        "  Note: an exit code of 0, a link or a file hash does not confirm a vulnerability on its own. Proof attached by hand is recorded as given; vettalon does not check where it came from or re-run it.\n",
    ));
    out.push('\n');
}

fn render_finding(finding: &Finding, out: &mut String) {
    out.push_str(&format!("  {}\n", finding.id));
    let level = finding.evidence_level();
    out.push_str(&tr!(
        "    證據等級：{}（{}）\n",
        "    Evidence level: {} ({})\n",
        level_label(level),
        level.key()
    ));
    let gaps: Vec<&str> = finding.proof_gaps().into_iter().map(gap_label).collect();
    out.push_str(&tr!(
        "    尚缺：{}\n",
        "    Still missing: {}\n",
        if gaps.is_empty() {
            pick("無", "nothing").to_string()
        } else {
            gaps.join(pick("、", ", "))
        }
    ));
    if let Some(c) = finding.strongest_counterevidence() {
        out.push_str(&tr!(
            "    最強反證：{c:?}\n",
            "    Strongest counter-evidence: {c:?}\n"
        ));
    }
    if let Some(fix) = finding.fix_check() {
        out.push_str(&tr!(
            "    建議修補：{}\n",
            "    Suggested fix: {}\n",
            fix_label(fix.outcome)
        ));
    }
    render_proofs(finding, out);
}

fn render_proofs(finding: &Finding, out: &mut String) {
    if finding.proof_evidence.is_empty() {
        let legacy = finding
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::PocTranscript);
        out.push_str(if legacy {
            pick(
                "    實證：尚無紀錄（保留了舊版的 PoC 執行紀錄，但不算實證）\n",
                "    Proof: none recorded (an older PoC run log is kept, but it does not count as proof)\n",
            )
        } else {
            pick("    實證：尚無紀錄\n", "    Proof: none recorded\n")
        });
        return;
    }
    let numbered = finding.proof_evidence.len() > 1;
    for (i, proof) in finding.proof_evidence.iter().enumerate() {
        render_proof(proof, numbered.then_some(i + 1), out);
    }
}

fn render_proof(proof: &ProofEvidence, number: Option<usize>, out: &mut String) {
    let head = match number {
        Some(n) => tr!("    實證 {n}：", "    Proof {n}: "),
        None => pick("    實證：", "    Proof: ").to_string(),
    };
    out.push_str(&tr!(
        "{head}{}，{}（run id {}）\n",
        "{head}{}, {} (run id {})\n",
        proof_level_label(proof.level),
        origin_label(proof.origin),
        proof.run_id
    ));
    if let Some(pair) = &proof.pair_id {
        out.push_str(&tr!("      配對 id：{pair}\n", "      Pair id: {pair}\n"));
    }
    if let Some(digest) = &proof.manifest_sha256 {
        out.push_str(&tr!(
            "      清單 sha256：{digest}（檔案雜湊只在附上時核對過一次）\n",
            "      Manifest sha256: {digest} (file hashes were checked only when attached)\n"
        ));
    }
    if let Some(digest) = &proof.transcript_sha256 {
        out.push_str(&tr!(
            "      執行紀錄 sha256：{digest}\n",
            "      Run log sha256: {digest}\n"
        ));
    }
    for a in &proof.artifacts {
        out.push_str(&tr!(
            "      檔案（{}）：{}，sha256 {}，{} 位元組\n",
            "      File ({}): {}, sha256 {}, {} bytes\n",
            a.role,
            a.path,
            a.sha256,
            a.bytes
        ));
    }
    if let Some(h) = &proof.human_decision {
        let (actor, at, decision) = (&h.actor, &h.recorded_at, &h.decision);
        out.push_str(&tr!(
            "      附上的人工判斷：{actor} 於 {at} 記為「{decision}」；發現狀態不會因此改變\n",
            "      Recorded human decision: \"{decision}\" by {actor} at {at}; the finding status is not changed by it\n"
        ));
    }
}

fn level_label(level: EvidenceLevel) -> &'static str {
    use EvidenceLevel as L;
    pick(
        level.label_zh(),
        match level {
            L::StaticOnly => "static / model analysis only",
            L::RefuterSurvived => "survived one refutation review",
            L::RefuterConsistent => "consistent across repeated refutation reviews",
            L::PocEffectNoControl => "PoC effect observed (no control or re-run)",
            L::PocDifferential => "PoC differential (control and re-run)",
            L::MaintainerConfirmed => "confirmed by a person",
        },
    )
}

fn gap_label(gap: ProofGap) -> &'static str {
    use ProofGap as G;
    pick(
        gap.label_zh(),
        match gap {
            G::NoRefuter => "no refutation review",
            G::RefuterInconsistent => "repeated reviews disagree",
            G::NoPoc => "no PoC executed",
            G::PocNotHarnessJudged => "PoC effect not judged by the harness",
            G::NoControl => "no control run",
            G::NoFreshRerun => "not re-run in a fresh container",
            G::ReachabilityUnknown => "reachability not shown by execution",
            G::NoMaintainerConfirmation => "not confirmed by a person",
        },
    )
}

fn fix_label(outcome: FixOutcome) -> &'static str {
    use FixOutcome as F;
    pick(
        outcome.label_zh(),
        match outcome {
            F::FixVerified => "fix verified (regression check and project tests passed)",
            F::FixCheckPartial => {
                "fix partly verified (regression check passed, project tests not run)"
            }
            F::FixRejected => "fix failed verification",
            F::FixUnverified => "fix not verified",
        },
    )
}

fn proof_level_label(level: ProofLevel) -> &'static str {
    use ProofLevel as P;
    match level {
        P::Unknown => pick("等級不明", "level unknown"),
        P::PatternDemo => pick(
            "獨立示範腳本，沒有在目標程式上執行",
            "standalone demo script, not run against the target",
        ),
        P::TargetExecution => pick("在目標程式上執行", "run against the target"),
        P::DifferentialOracle => pick(
            "差分驗證（有漏洞版與修補版對照）",
            "differential check (vulnerable vs patched)",
        ),
    }
}

fn origin_label(origin: ProofOrigin) -> &'static str {
    match origin {
        ProofOrigin::GeneratedPattern => pick("由 vettalon 產生", "generated by vettalon"),
        ProofOrigin::OperatorSupplied => pick("手動附上", "attached by hand"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{
        CURRENT_SCHEMA_VERSION, EvidenceItem, FindingKind, GatePolicy, ProofArtifact,
        ProofHumanDecision, ScanProfile, Severity, Summary, VerifierInfo,
    };
    use crate::lang::{Lang, with};
    use vettalon_contract::coverage::RunStatus;

    fn finding() -> Finding {
        Finding::candidate(
            "cargo-audit",
            FindingKind::DependencyVulnerability,
            Severity::High,
            "t",
            "Cargo.lock",
            None,
            "s",
            "RUSTSEC-2021-0003",
            vec![],
        )
    }

    fn report(findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            repo: "/tmp/repo".into(),
            started_at: "2026-10-21T00:00:00Z".into(),
            profile: ScanProfile {
                mode: crate::audit::schema::ProfileMode::Quick,
                intake: None,
            },
            engines_run: vec![],
            engines_missing: vec![],
            summary: Summary::from_findings(&findings, 0, 0, GatePolicy::default(), &[]),
            findings,
            schema_version: CURRENT_SCHEMA_VERSION,
            run_status: RunStatus::Complete,
            incomplete_reason: None,
            coverage: vec![],
            prior_run: None,
            verifier: VerifierInfo::default(),
            ensemble: Default::default(),
        }
    }

    fn render(lang: Lang, r: &AuditReport) -> String {
        with(lang, || {
            let mut out = String::new();
            render_finding_evidence(r, &mut out);
            out
        })
    }

    fn operator_proof() -> ProofEvidence {
        ProofEvidence {
            level: ProofLevel::TargetExecution,
            origin: ProofOrigin::OperatorSupplied,
            run_id: "run-1".into(),
            pair_id: Some("pair-1".into()),
            manifest_sha256: Some("ab".repeat(32)),
            transcript_sha256: None,
            artifacts: vec![ProofArtifact {
                role: "target_execution".into(),
                path: "logs/run.txt".into(),
                sha256: "cd".repeat(32),
                bytes: 42,
            }],
            human_decision: Some(ProofHumanDecision {
                actor: "alice".into(),
                decision: "confirmed".into(),
                recorded_at: "2026-10-21T00:00:00Z".into(),
            }),
        }
    }

    #[test]
    fn no_findings_renders_nothing() {
        assert_eq!(render(Lang::En, &report(vec![])), "");
        assert_eq!(render(Lang::ZhTw, &report(vec![])), "");
    }

    #[test]
    fn static_finding_renders_an_indented_block_in_english() {
        let f = finding();
        let id = f.id.clone();
        let text = render(Lang::En, &report(vec![f]));
        let expected = format!(
            "Evidence per finding:\n  {id}\n    Evidence level: static / model analysis only (static_only)\n    Still missing: no refutation review, no PoC executed, reachability not shown by execution, not confirmed by a person\n    Proof: none recorded\n\n  Note: an exit code of 0, a link or a file hash does not confirm a vulnerability on its own. Proof attached by hand is recorded as given; vettalon does not check where it came from or re-run it.\n\n"
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn static_finding_renders_an_indented_block_in_zh_tw() {
        let f = finding();
        let id = f.id.clone();
        let text = render(Lang::ZhTw, &report(vec![f]));
        let expected = format!(
            "各項發現的證據：\n  {id}\n    證據等級：僅靜態／模型分析（static_only）\n    尚缺：未經反駁覆核、未執行 PoC、可達性未經執行證實、未經人工確認\n    實證：尚無紀錄\n\n  注意：結束碼 0、連結或檔案雜湊本身都不能證明漏洞存在。手動附上的實證只照原樣記錄，vettalon 不查核它的來源，也不會自己重跑驗證。\n\n"
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn caveat_is_printed_once_and_every_line_is_indented() {
        let mut second = finding();
        second.line = Some(7);
        second.id = format!("{}-2", second.id);
        let r = report(vec![finding(), second]);
        for lang in [Lang::En, Lang::ZhTw] {
            let text = render(lang, &r);
            let caveats = text
                .lines()
                .filter(|l| l.contains("Note:") || l.contains("注意："))
                .count();
            assert_eq!(caveats, 1, "{text}");
            assert_eq!(
                text.lines()
                    .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
                    .count(),
                3,
                "two ids and one caveat at indent 2:\n{text}"
            );
            for line in text.lines().skip(1).filter(|l| !l.is_empty()) {
                assert!(line.starts_with("  "), "unindented line {line:?}");
            }
        }
    }

    #[test]
    fn legacy_poc_transcript_is_called_out() {
        let mut f = finding();
        f.evidence.push(EvidenceItem {
            kind: EvidenceKind::PocTranscript,
            source: "legacy".into(),
            detail: "exit_code=0".into(),
            recorded_at: "2026-10-16T00:00:00Z".into(),
        });
        let r = report(vec![f]);
        assert!(render(Lang::En, &r).contains(
            "    Proof: none recorded (an older PoC run log is kept, but it does not count as proof)\n"
        ));
        assert!(
            render(Lang::ZhTw, &r)
                .contains("    實證：尚無紀錄（保留了舊版的 PoC 執行紀錄，但不算實證）\n")
        );
    }

    #[test]
    fn attached_proof_lists_every_recorded_field() {
        let mut f = finding();
        f.proof_evidence.push(operator_proof());
        let r = report(vec![f]);
        let en = render(Lang::En, &r);
        assert!(
            en.contains("    Proof: run against the target, attached by hand (run id run-1)\n"),
            "{en}"
        );
        assert!(en.contains("      Pair id: pair-1\n"));
        assert!(en.contains(&format!(
            "      Manifest sha256: {} (file hashes were checked only when attached)\n",
            "ab".repeat(32)
        )));
        assert!(en.contains(&format!(
            "      File (target_execution): logs/run.txt, sha256 {}, 42 bytes\n",
            "cd".repeat(32)
        )));
        assert!(en.contains("      Recorded human decision: \"confirmed\" by alice at 2026-10-21T00:00:00Z; the finding status is not changed by it\n"));
        let zh = render(Lang::ZhTw, &r);
        assert!(
            zh.contains("    實證：在目標程式上執行，手動附上（run id run-1）\n"),
            "{zh}"
        );
        assert!(zh.contains("      附上的人工判斷：alice 於 2026-10-21T00:00:00Z 記為「confirmed」；發現狀態不會因此改變\n"));
    }

    #[test]
    fn several_proofs_are_numbered_and_pattern_demo_says_target_not_run() {
        let mut f = finding();
        f.proof_evidence.push(ProofEvidence {
            level: ProofLevel::PatternDemo,
            origin: ProofOrigin::GeneratedPattern,
            run_id: "run-0".into(),
            pair_id: None,
            manifest_sha256: None,
            transcript_sha256: Some("ef".repeat(32)),
            artifacts: vec![],
            human_decision: None,
        });
        f.proof_evidence.push(operator_proof());
        let en = render(Lang::En, &report(vec![f]));
        assert!(en.contains("    Proof 1: standalone demo script, not run against the target, generated by vettalon (run id run-0)\n"), "{en}");
        assert!(en.contains(&format!("      Run log sha256: {}\n", "ef".repeat(32))));
        assert!(en.contains("    Proof 2: run against the target"));
    }

    #[test]
    fn english_block_has_no_chinese_for_any_label() {
        for level in EvidenceLevel::ALL {
            let label = with(Lang::En, || level_label(level));
            assert!(label.is_ascii(), "{label}");
        }
        let mut f = finding();
        f.proof_evidence.push(operator_proof());
        assert!(render(Lang::En, &report(vec![f])).is_ascii());
    }
}
