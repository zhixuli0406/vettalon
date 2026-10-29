//! SARIF 2.1.0 export (GitHub code scanning, IDE viewers).
//!
//! Derived from a validated [`AuditReport`]; it never changes a verdict.
//! `Refuted` / `Suppressed` findings are emitted with a SARIF suppression
//! (so a viewer hides them but the record stays), and the vettalon status,
//! finder and verifier votes travel in `properties`.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use vettalon_contract::safe_path::SafeRepoPath;

use super::schema::{AuditReport, EvidenceKind, Finding, FindingStatus, Severity};

/// OASIS SARIF 2.1.0 (Errata 01) schema.
const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn severity_key(s: Severity) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Why a rule does or does not carry GitHub's `security-severity`.
///
/// GitHub reads `security-severity` as a CVSS-style 0.1–10.0 score. vettalon
/// only emits one when every finding of the rule has a source-supplied CVSS
/// vector (the value is their highest score); a qualitative severity is
/// never turned into a CVSS-looking number. Without it GitHub falls back to
/// the SARIF `level` (error / warning / note).
const BASIS_CVSS_MAX: &str = "cvss_max";
const BASIS_NO_CVSS: &str = "omitted_no_cvss";
const BASIS_PARTIAL_CVSS: &str = "omitted_partial_cvss";
const BASIS_ZERO_CVSS: &str = "omitted_cvss_zero";

/// Index of the CWE taxonomy in `runs[0].taxonomies`.
const CWE_TAXONOMY_INDEX: usize = 0;

fn status_str(s: FindingStatus) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Percent-encode a path for a `file://` URI (keeps `/` and unreserved).
fn uri_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Class metadata is attached only when the module selection supports it.
/// Exact evidence-path membership also covers findings from static scanners.
fn result_attack_class(report: &AuditReport, finding: &Finding) -> Option<&'static str> {
    let class = finding
        .cwe
        .as_deref()
        .and_then(super::attack_classes::class_for_cwe)?;
    report
        .coverage
        .iter()
        .any(|module| {
            (module.candidate_ids.contains(&finding.id)
                || module.scope_paths.contains(&finding.file)
                || module.reviewed_paths.contains(&finding.file))
                && module.attack_classes.as_ref().is_some_and(|classes| {
                    classes.mode != super::attack_classes::AttackClassMode::Off
                        && classes.selected.iter().any(|selected| selected == class)
                })
        })
        .then_some(class)
}

fn result(f: &Finding, taxa: &[String]) -> Value {
    // A pre-check-refuted finding keeps the model's claimed path verbatim,
    // which may be absolute or escape the repo: never emit it as a location.
    let location = SafeRepoPath::parse(&f.file).ok().map(|_| {
        let mut loc = json!({
            "physicalLocation": {
                "artifactLocation": { "uri": uri_path(&f.file), "uriBaseId": "SRCROOT" }
            }
        });
        if let Some(line) = f.line.filter(|l| *l > 0) {
            loc["physicalLocation"]["region"] = json!({ "startLine": line });
        }
        loc
    });
    let mut r = json!({
        "ruleId": f.rule_id,
        "level": level(f.severity),
        "message": { "text": f.title },
        "locations": location.into_iter().collect::<Vec<_>>(),
        "partialFingerprints": { "vettalonRootCause/v1": f.root_fingerprint },
        "properties": {
            "vettalon.status": status_str(f.status),
            "vettalon.engine": f.source_engine,
            "vettalon.found_by": f.found_by,
            "vettalon.verification": f.verification,
            "vettalon.blockers": f.blockers,
            "vettalon.proof_level": f.proof_evidence.last().map(|proof| proof.level.key()).unwrap_or("unknown"),
            "vettalon.proof_evidence": f.proof_evidence,
            "vettalon.proof_limits": f.proof_summary(),
            "vettalon.evidence_level": f.evidence_level(),
            "vettalon.proof_gaps": f.proof_gaps(),
            "vettalon.explain_uri": explanation_uris(f),
        }
    });
    if let Some(counter) = f.strongest_counterevidence() {
        r["properties"]["vettalon.strongest_counterevidence"] = json!(counter);
    }
    // O19: a suggested fix is labelled with its derived check outcome.
    if let Some(fix) = f.fix_check() {
        r["properties"]["vettalon.fix_check"] = json!(fix);
    }
    if let Some(cwe) = &f.cwe {
        r["properties"]["vettalon.cwe"] = json!(cwe);
        // CWE List version + MITRE mapping usage; Discouraged / Prohibited
        // ids carry a warning and the more specific ids vettalon knows.
        if let Some(m) = f.cwe_mapping() {
            if let Some(warning) = m.warning() {
                r["properties"]["vettalon.cwe_mapping_warning"] = json!(warning);
            }
            r["properties"]["vettalon.cwe_mapping"] = json!(m);
        }
        if let Some(original) = &f.cwe_replaced {
            r["properties"]["vettalon.cwe_replaced"] = json!(original);
        }
        if let Some(n) = cwe_number(cwe)
            && let Some(index) = taxa.iter().position(|t| *t == n)
        {
            r["taxa"] = json!([{
                "id": n,
                "index": index,
                "toolComponent": { "name": "CWE", "index": CWE_TAXONOMY_INDEX }
            }]);
        }
        // P0-3: the CAPEC attack patterns mapped to this CWE, machine-readable
        // alongside the weakness id.
        let capec: Vec<&str> = crate::kb::lookup(cwe)
            .map(|e| e.capec.iter().map(|c| c.id.as_str()).collect())
            .unwrap_or_default();
        if !capec.is_empty() {
            r["properties"]["vettalon.capec"] = json!(capec);
        }
    }
    if !f.cve.is_empty() {
        r["properties"]["vettalon.cve"] = json!(f.cve);
        r["properties"]["vettalon.cve_refs"] = json!(f.cve_refs());
    }
    if let Some(cvss) = &f.cvss {
        r["properties"]["vettalon.cvss"] = json!(cvss);
        r["properties"]["vettalon.cvss_label"] = json!(cvss.label());
    }
    r["properties"]["vettalon.severity"] = json!(severity_key(f.severity));
    r["properties"]["vettalon.severity_basis"] = json!(f.severity_basis);
    if f.evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::SeverityDisagreement)
    {
        r["properties"]["vettalon.severity_disagreement"] = json!(true);
    }
    // P1-2: deterministic exploitability tier from the finding's
    // preconditions; O11: the higher-friction of finder and refuter.
    let ex = crate::audit::exploitability::assess_finding(f);
    r["properties"]["vettalon.exploitability"] = json!(ex.effective.tier.key());
    if let Some(refuter) = &ex.refuter {
        r["properties"]["vettalon.exploitability_finder"] = json!(ex.finder.tier.key());
        r["properties"]["vettalon.exploitability_refuter"] = json!(refuter.tier.key());
        if ex.disagreement() {
            r["properties"][format!(
                "vettalon.{}",
                crate::audit::exploitability::TIER_DISAGREEMENT_KEY
            )] = json!(true);
        }
    }
    // O10: the verdict flipped between reading the code with and without
    // its comments.
    if f.evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::CommentSensitivity)
    {
        r["properties"]["vettalon.comment_sensitivity"] = json!(true);
    }
    if matches!(f.status, FindingStatus::Refuted | FindingStatus::Suppressed) {
        let why = f
            .evidence
            .iter()
            .rev()
            .find(|e| {
                matches!(
                    e.kind,
                    EvidenceKind::AdversarialReview | EvidenceKind::OperatorReview
                )
            })
            .map(|e| crate::util::truncate_bytes(&e.detail, 500).to_string())
            .unwrap_or_else(|| status_str(f.status));
        r["suppressions"] = json!([{ "kind": "external", "justification": why }]);
    }
    r
}

/// A finding has several codes at once. Preserve each link by code, rather
/// than choosing one explanation and losing the remaining evidence context.
fn explanation_uris(f: &Finding) -> BTreeMap<String, String> {
    let mut links = BTreeMap::new();
    let mut add = |code: &str| {
        if let Some(uri) = crate::explain::uri(code) {
            links.insert(code.to_string(), uri);
        }
    };
    add(f.evidence_level().key());
    for gap in f.proof_gaps() {
        add(gap.key());
    }
    add(&f.rule_id);
    for evidence in &f.evidence {
        if let Ok(Value::String(kind)) = serde_json::to_value(evidence.kind) {
            add(&kind);
        }
        // Evidence details start with a machine code followed by a colon,
        // whitespace or end-of-string. Never search arbitrary prose for codes.
        if let Some(code) = evidence.detail.split([':', ' ', '\n', '\t']).next() {
            add(code);
            if code == "refuter_run"
                && let Some((_, verdict)) = evidence.detail.split_once(": ")
                && let Some(verdict_code) = verdict.split([':', ' ', '\n', '\t']).next()
            {
                add(verdict_code);
            }
        }
    }
    if crate::audit::exploitability::assess_finding(f).disagreement() {
        add("tier_disagreement");
    }
    links
}

/// `CWE-89` → `"89"` (SARIF taxon ids use the bare number, as in the spec's
/// CWE taxonomy example).
fn cwe_number(cwe: &str) -> Option<String> {
    crate::audit::cwe::normalize(cwe).map(|id| id.trim_start_matches("CWE-").to_string())
}

/// `runs[0].taxonomies[0]`: the CWE List the bundled mapping table comes
/// from, with one taxon per CWE id the report's findings carry.
fn cwe_taxonomy(taxa: &[String]) -> Value {
    let (version, date, _) = crate::audit::cwe::catalog().unwrap_or(("unknown", "", ""));
    let taxa: Vec<Value> = taxa
        .iter()
        .map(|n| {
            let id = format!("CWE-{n}");
            let m = crate::audit::cwe::mapping(&id);
            let mut t = json!({
                "id": n,
                "helpUri": crate::kb::cwe_url(&id),
                "properties": {
                    "vettalon.mapping_usage": m.as_ref().map(|m| m.usage.key()),
                    "vettalon.abstraction": m.as_ref().and_then(|m| m.abstraction),
                }
            });
            if let Some(name) = m.as_ref().and_then(|m| m.name) {
                t["name"] = json!(name);
                t["shortDescription"] = json!({ "text": name });
            }
            t
        })
        .collect();
    let mut tax = json!({
        "name": "CWE",
        "version": version,
        "organization": "MITRE",
        "shortDescription": { "text": "The MITRE Common Weakness Enumeration" },
        "informationUri": "https://cwe.mitre.org/",
        "downloadUri": format!("https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip"),
        "isComprehensive": false,
        "taxa": taxa,
    });
    if !date.is_empty() {
        tax["releaseDateUtc"] = json!(date);
    }
    tax
}

pub fn to_sarif(report: &AuditReport) -> Value {
    // One rule per rule id, at the highest severity seen for it, tagged with
    // every CWE its findings carry (GitHub's `external/cwe/cwe-NNN` form).
    // `security-severity` only from source-supplied CVSS vectors.
    struct RuleAgg {
        severity: Severity,
        explain_uris: BTreeMap<String, String>,
        tags: std::collections::BTreeSet<String>,
        max: Option<crate::audit::cvss::CvssScore>,
        findings: usize,
        scored: usize,
    }
    let mut rules: BTreeMap<&str, RuleAgg> = BTreeMap::new();
    let mut taxa: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for f in &report.findings {
        let e = rules.entry(f.rule_id.as_str()).or_insert_with(|| RuleAgg {
            severity: f.severity,
            explain_uris: BTreeMap::new(),
            tags: std::collections::BTreeSet::new(),
            max: None,
            findings: 0,
            scored: 0,
        });
        e.findings += 1;
        e.explain_uris.extend(explanation_uris(f));
        if f.severity > e.severity {
            e.severity = f.severity;
        }
        if let Some(tag) = f.cwe.as_deref().and_then(crate::audit::cwe::sarif_tag) {
            e.tags.insert(tag);
        }
        // Only ids that exist in the bundled CWE List become taxa of the
        // versioned taxonomy; others keep their warning property only.
        let in_catalog = f
            .cwe_mapping()
            .is_some_and(|m| m.usage != crate::audit::cwe::MappingUsage::NotInCatalog);
        if in_catalog && let Some(n) = f.cwe.as_deref().and_then(cwe_number) {
            taxa.extend(n.parse::<u32>().ok());
        }
        if let Some(c) = &f.cvss {
            e.scored += 1;
            if e.max.as_ref().is_none_or(|m| c.base_score > m.base_score) {
                e.max = Some(c.clone());
            }
        }
    }
    let taxa: Vec<String> = taxa.into_iter().map(|n| n.to_string()).collect();
    let rules: Vec<Value> = rules
        .into_iter()
        .map(|(id, agg)| {
            let mut tags = vec!["security".to_string()];
            tags.extend(agg.tags);
            let mut props = json!({
                "tags": tags,
                "vettalon.severity": severity_key(agg.severity),
                "vettalon.explain_uri": agg.explain_uris,
            });
            match (&agg.max, agg.scored == agg.findings) {
                // GitHub's range is >0.0–10.0: a 0.0 CVSS score has no
                // security-severity, but the vector still travels.
                (Some(max), true) if max.base_score <= 0.0 => {
                    props["vettalon.security_severity_basis"] = json!(BASIS_ZERO_CVSS);
                    props["vettalon.cvss_version"] = json!(max.cvss_version);
                    props["vettalon.cvss_vector"] = json!(max.cvss_vector);
                }
                (Some(max), true) => {
                    props["security-severity"] = json!(format!("{:.1}", max.base_score));
                    props["vettalon.security_severity_basis"] = json!(BASIS_CVSS_MAX);
                    props["vettalon.cvss_version"] = json!(max.cvss_version);
                    props["vettalon.cvss_vector"] = json!(max.cvss_vector);
                    if let Some(n) = max.nomenclature() {
                        props["vettalon.cvss_nomenclature"] = json!(n);
                    }
                }
                (Some(_), false) => {
                    props["vettalon.security_severity_basis"] = json!(BASIS_PARTIAL_CVSS);
                }
                (None, _) => {
                    props["vettalon.security_severity_basis"] = json!(BASIS_NO_CVSS);
                }
            }
            json!({
                "id": id,
                "shortDescription": { "text": id },
                "defaultConfiguration": { "level": level(agg.severity) },
                "properties": props
            })
        })
        .collect();
    let mut driver = json!({
        "name": "vettalon",
        "version": env!("CARGO_PKG_VERSION"),
        "rules": rules,
    });
    let mut run_taxonomies = Vec::new();
    if !taxa.is_empty() {
        driver["supportedTaxonomies"] = json!([{ "name": "CWE", "index": CWE_TAXONOMY_INDEX }]);
        run_taxonomies.push(cwe_taxonomy(&taxa));
    }
    let mut out = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": driver },
            "results": report.findings.iter().map(|f| {
                let mut output = result(f, &taxa);
                if let Some(class) = result_attack_class(report, f) {
                    output["properties"]["vettalon.attack_class"] = json!(class);
                }
                output
            }).collect::<Vec<_>>(),
            "properties": {
                "vettalon.run_status": report.run_status,
                "vettalon.incomplete_reason": report.incomplete_reason,
                "vettalon.coverage": report.coverage,
                "vettalon.coverage_summary": report.summary.coverage,
                "vettalon.verifier_independence": report.verifier.independence,
                "vettalon.refusals": report.ensemble.refusals,
            }
        }]
    });
    if let Some(scope) = &report.scope {
        out["runs"][0]["properties"]["vettalon.scope"] = json!(scope);
    }
    if !run_taxonomies.is_empty() {
        out["runs"][0]["taxonomies"] = json!(run_taxonomies);
    }
    out
}

pub fn write_sarif(report: &AuditReport, path: &Path) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(&to_sarif(report)).map_err(std::io::Error::other)?;
    crate::util::write_private(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{
        FindingKind, GatePolicy, ProfileMode, ScanProfile, Summary, VerifierInfo,
    };

    fn finding(sev: Severity, status: FindingStatus, line: Option<u32>) -> Finding {
        let mut f = Finding::candidate(
            "semgrep",
            FindingKind::StaticAnalysis,
            sev,
            "t",
            "src/a.py",
            line,
            "s",
            "rule/x",
            vec![],
        );
        f.status = status;
        f
    }

    fn report(findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            schema_version: 2,
            scope: None,
            repo: "/r".into(),
            started_at: "2026-10-12T00:00:00Z".into(),
            profile: ScanProfile {
                mode: ProfileMode::Quick,
                intake: None,
            },
            engines_run: vec![],
            engines_missing: vec![],
            summary: Summary::from_findings(&findings, 0, 0, GatePolicy::default(), &[]),
            findings,
            run_status: vettalon_contract::coverage::RunStatus::Complete,
            incomplete_reason: None,
            coverage: vec![],
            prior_run: None,
            verifier: VerifierInfo::default(),
            ensemble: Default::default(),
        }
    }

    #[test]
    fn explanation_links_cover_each_result_and_the_union_for_a_shared_rule() {
        use crate::audit::schema::EvidenceItem;
        let mut a = finding(Severity::High, FindingStatus::Candidate, Some(1));
        a.evidence.push(EvidenceItem {
            kind: EvidenceKind::AdversarialReview,
            detail: "verify_error: unavailable".into(),
            source: "adversarial".into(),
            recorded_at: String::new(),
        });
        let mut b = finding(Severity::High, FindingStatus::Candidate, Some(2));
        b.evidence.push(EvidenceItem {
            kind: EvidenceKind::ScopeNote,
            detail: "outside_diff_scope".into(),
            source: "scope".into(),
            recorded_at: String::new(),
        });
        b.evidence.push(EvidenceItem {
            kind: EvidenceKind::AdversarialReview,
            detail: "refuter_run 1/2: refuted: input is escaped".into(),
            source: "adversarial".into(),
            recorded_at: String::new(),
        });
        let s = to_sarif(&report(vec![a, b]));
        let first = &s["runs"][0]["results"][0]["properties"]["vettalon.explain_uri"];
        let second = &s["runs"][0]["results"][1]["properties"]["vettalon.explain_uri"];
        for code in [
            "static_only",
            "no_control",
            "verify_error",
            "outside_diff_scope",
        ] {
            // no_control requires an accepted PoC effect; these static findings
            // have no_poc instead, so no unrelated page should be attached.
            if code == "no_control" {
                assert!(first.get(code).is_none());
                continue;
            }
            let expected = crate::explain::uri(code).unwrap();
            let rule =
                &s["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["vettalon.explain_uri"];
            assert_eq!(rule[code], expected);
        }
        assert_eq!(
            first["verify_error"],
            crate::explain::uri("verify_error").unwrap()
        );
        assert!(first.get("outside_diff_scope").is_none());
        assert_eq!(
            second["outside_diff_scope"],
            crate::explain::uri("outside_diff_scope").unwrap()
        );
        assert!(second.get("verify_error").is_none());
        assert_eq!(second["refuted"], crate::explain::uri("refuted").unwrap());
        assert_eq!(
            second["refuter_run"],
            crate::explain::uri("refuter_run").unwrap()
        );
        assert_eq!(first["no_poc"], crate::explain::uri("no_poc").unwrap());
    }

    #[test]
    fn attack_class_property_requires_selected_module_and_known_cwe() {
        use crate::audit::attack_classes::{AttackClassMode, select};
        let mut finding = finding(Severity::High, FindingStatus::Candidate, Some(1));
        finding.cwe = Some("CWE-89".into());
        let mut report = report(vec![finding]);
        let property = |report: &AuditReport| {
            to_sarif(report)["runs"][0]["results"][0]["properties"]
                .get("vettalon.attack_class")
                .cloned()
        };
        assert_eq!(property(&report), None);
        let mut module: super::super::schema::ModuleCoverage = serde_json::from_value(json!({
            "module_path": "src", "status": "candidate", "reason": null,
            "scope_paths": ["src/a.py"]
        }))
        .unwrap();
        module.attack_classes = select(
            AttackClassMode::Auto,
            &[("src/a.py".into(), "eval(".into())],
        );
        report.coverage.push(module);
        assert_eq!(property(&report), Some(json!("injection")));
        report.findings[0].cwe = Some("CWE-918".into());
        assert_eq!(property(&report), None);
        report.findings[0].cwe = Some("CWE-999999".into());
        assert_eq!(property(&report), None);
        report.findings[0].cwe = Some("CWE-89".into());
        report.findings[0].file = "src/unrelated.py".into();
        assert_eq!(property(&report), None);
        report.coverage[0]
            .candidate_ids
            .push(report.findings[0].id.clone());
        assert_eq!(property(&report), Some(json!("injection")));
        report.coverage[0].attack_classes = None;
        assert_eq!(property(&report), None);
    }

    #[test]
    fn incomplete_scope_and_unknown_proof_survive_sarif_export() {
        let mut report = report(vec![finding(
            Severity::High,
            FindingStatus::Candidate,
            Some(1),
        )]);
        report.run_status = vettalon_contract::coverage::RunStatus::Incomplete;
        report.incomplete_reason =
            Some(vettalon_contract::coverage::IncompleteReason::ScopeNotFullyReviewed);
        let sarif = to_sarif(&report);
        let props = &sarif["runs"][0]["properties"];
        assert_eq!(
            props["vettalon.incomplete_reason"],
            "scope_not_fully_reviewed"
        );
        assert_eq!(props["vettalon.coverage"], serde_json::json!([]));
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["vettalon.proof_level"],
            "unknown"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["properties"]["vettalon.status"],
            "candidate"
        );
    }

    #[test]
    fn cwe_becomes_github_tag_and_cvss_drives_security_severity() {
        let mut a = finding(Severity::High, FindingStatus::Candidate, Some(3));
        a.cwe = Some("CWE-89".into());
        a.cvss = crate::audit::cvss::CvssScore::from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        );
        a.cve = vec!["CVE-1900-9999".into()];
        let sarif = to_sarif(&report(vec![a]));
        let rule = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(
            rule["properties"]["vettalon.security_severity_basis"],
            "cvss_max"
        );
        assert_eq!(
            rule["properties"]["vettalon.cvss_vector"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        );
        let tags: Vec<&str> = rule["properties"]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t.as_str())
            .collect();
        assert!(tags.contains(&"security"));
        assert!(tags.contains(&"external/cwe/cwe-089"), "{tags:?}");
        assert_eq!(
            rule["properties"]["security-severity"], "9.8",
            "real CVSS beats the severity default"
        );
        let res = &sarif["runs"][0]["results"][0];
        assert_eq!(res["properties"]["vettalon.cwe"], "CWE-89");
        assert_eq!(res["properties"]["vettalon.cve"][0], "CVE-1900-9999");
        assert_eq!(
            res["properties"]["vettalon.cve_refs"][0]["state"],
            "unverified"
        );
        assert_eq!(res["properties"]["vettalon.cvss"]["rating"], "critical");
        assert_eq!(
            res["properties"]["vettalon.cvss_label"],
            "CVSS v3.1 9.8 Critical"
        );
        // CWE as a SARIF taxonomy (CWE List 4.20), referenced by the result.
        let tax = &sarif["runs"][0]["taxonomies"][0];
        assert_eq!(tax["name"], "CWE");
        assert_eq!(tax["version"], "4.20");
        assert_eq!(tax["releaseDateUtc"], "2026-04-30");
        assert_eq!(tax["taxa"][0]["id"], "89");
        assert_eq!(
            tax["taxa"][0]["properties"]["vettalon.mapping_usage"],
            "allowed"
        );
        assert_eq!(res["taxa"][0]["id"], "89");
        assert_eq!(res["taxa"][0]["toolComponent"]["name"], "CWE");
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["supportedTaxonomies"][0]["name"],
            "CWE"
        );
        assert_eq!(
            res["properties"]["vettalon.cwe_mapping"]["cwe_version"],
            "4.20"
        );
        assert!(
            res["properties"]
                .get("vettalon.cwe_mapping_warning")
                .is_none()
        );
    }

    #[test]
    fn no_cvss_means_no_security_severity_number() {
        // Qualitative severity never becomes a CVSS-looking number.
        let s = to_sarif(&report(vec![finding(
            Severity::Critical,
            FindingStatus::Candidate,
            Some(1),
        )]));
        let rule = &s["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule["properties"].get("security-severity").is_none());
        assert_eq!(
            rule["properties"]["vettalon.security_severity_basis"],
            "omitted_no_cvss"
        );
        assert_eq!(rule["properties"]["vettalon.severity"], "critical");
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
        assert!(
            s["runs"][0].get("taxonomies").is_none(),
            "no CWE, no taxonomy"
        );
        // One scored and one unscored finding under the same rule: a max of
        // the scored one would understate the other, so no number at all.
        let mut a = finding(Severity::Critical, FindingStatus::Candidate, Some(1));
        let mut b = finding(Severity::Low, FindingStatus::Candidate, Some(2));
        b.cvss = crate::audit::cvss::CvssScore::from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        );
        a.cwe = Some("CWE-20".into());
        let s = to_sarif(&report(vec![a, b]));
        let rule = &s["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule["properties"].get("security-severity").is_none());
        assert_eq!(
            rule["properties"]["vettalon.security_severity_basis"],
            "omitted_partial_cvss"
        );
        // The Discouraged CWE-20 is flagged, with its CWE List version.
        let res = &s["runs"][0]["results"][0];
        assert_eq!(
            res["properties"]["vettalon.cwe_mapping"]["usage"],
            "discouraged"
        );
        assert!(
            res["properties"]["vettalon.cwe_mapping_warning"]
                .as_str()
                .unwrap()
                .contains("CWE-20 is discouraged")
        );
        let v4 = &s["runs"][0]["results"][1]["properties"];
        assert_eq!(v4["vettalon.cvss"]["nomenclature"], "CVSS-B");
        assert_eq!(v4["vettalon.cvss_label"], "CVSS v4.0 6.9 Medium (CVSS-B)");
    }

    #[test]
    fn zero_cvss_and_unknown_cwe_stay_out_of_github_fields() {
        let mut a = finding(Severity::Low, FindingStatus::Candidate, Some(3));
        a.cvss = crate::audit::cvss::CvssScore::from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        );
        a.cwe = Some("CWE-99999".into());
        let s = to_sarif(&report(vec![a]));
        let rule = &s["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule["properties"].get("security-severity").is_none());
        assert_eq!(
            rule["properties"]["vettalon.security_severity_basis"],
            "omitted_cvss_zero"
        );
        assert!(s["runs"][0].get("taxonomies").is_none());
        let res = &s["runs"][0]["results"][0];
        assert!(res.get("taxa").is_none());
        assert_eq!(
            res["properties"]["vettalon.cwe_mapping"]["usage"],
            "not-in-catalog"
        );
    }

    #[test]
    fn v40_cvss_drives_security_severity_with_its_nomenclature() {
        let mut a = finding(Severity::High, FindingStatus::Candidate, Some(3));
        a.cvss = crate::audit::cvss::CvssScore::from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        );
        let s = to_sarif(&report(vec![a]));
        let rule = &s["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["properties"]["security-severity"], "8.7");
        assert_eq!(rule["properties"]["vettalon.cvss_version"], "4.0");
        assert_eq!(rule["properties"]["vettalon.cvss_nomenclature"], "CVSS-B");
        assert_eq!(s["$schema"], SARIF_SCHEMA);
    }

    #[test]
    fn levels_locations_and_rules() {
        let r = report(vec![
            finding(Severity::Medium, FindingStatus::Candidate, Some(3)),
            finding(Severity::Critical, FindingStatus::Candidate, None),
        ]);
        let s = to_sarif(&r);
        assert_eq!(s["version"], "2.1.0");
        let res = s["runs"][0]["results"].as_array().unwrap();
        assert_eq!(res[0]["level"], "warning");
        assert_eq!(
            res[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            3
        );
        assert!(
            res[1]["locations"][0]["physicalLocation"]
                .get("region")
                .is_none()
        );
        let rules = s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0]["properties"].get("security-severity").is_none());
        assert_eq!(rules[0]["defaultConfiguration"]["level"], "error");
    }

    #[test]
    fn unsafe_claimed_paths_get_no_location_and_uris_are_encoded() {
        let mut f = finding(Severity::High, FindingStatus::Refuted, Some(1));
        f.file = "/etc/passwd".into();
        let mut r = report(vec![
            f,
            finding(Severity::Low, FindingStatus::Candidate, Some(2)),
        ]);
        r.findings[1].file = "src/中 文.py".into();
        r.repo = "/home/a b".into();
        let s = to_sarif(&r);
        assert!(
            s["runs"][0]["results"][0]["locations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/%E4%B8%AD%20%E6%96%87.py"
        );
        // The local absolute path never leaves the machine in SARIF.
        assert!(s["runs"][0].get("originalUriBaseIds").is_none());
        assert!(!s.to_string().contains("/home/a"));
    }

    #[test]
    fn refuted_is_suppressed_not_dropped() {
        let s = to_sarif(&report(vec![finding(
            Severity::High,
            FindingStatus::Refuted,
            Some(1),
        )]));
        let res = &s["runs"][0]["results"][0];
        assert_eq!(res["suppressions"][0]["kind"], "external");
        assert_eq!(res["properties"]["vettalon.status"], "refuted");
    }

    #[test]
    fn evidence_level_and_proof_gaps_are_sarif_properties() {
        let mut f = finding(Severity::High, FindingStatus::Refuted, Some(1));
        f.evidence.push(crate::audit::schema::EvidenceItem {
            kind: EvidenceKind::AdversarialReview,
            source: "adversarial".into(),
            detail: "refuted: input is escaped".into(),
            recorded_at: String::new(),
        });
        let s = to_sarif(&report(vec![f]));
        let props = &s["runs"][0]["results"][0]["properties"];
        assert_eq!(props["vettalon.evidence_level"], "static_only");
        assert_eq!(props["vettalon.proof_gaps"][0], "no_poc");
        assert_eq!(
            props["vettalon.strongest_counterevidence"],
            "refuter: input is escaped"
        );
        let clean = to_sarif(&report(vec![finding(
            Severity::Low,
            FindingStatus::Candidate,
            None,
        )]));
        let props = &clean["runs"][0]["results"][0]["properties"];
        assert_eq!(props["vettalon.proof_gaps"][0], "no_refuter");
        assert!(props.get("vettalon.strongest_counterevidence").is_none());
    }

    #[test]
    fn a_suggested_fix_carries_its_derived_label() {
        let mut f = finding(Severity::High, FindingStatus::NeedsHuman, Some(1));
        let props = |f: &Finding| {
            to_sarif(&report(vec![f.clone()]))["runs"][0]["results"][0]["properties"].clone()
        };
        assert!(props(&f).get("vettalon.fix_check").is_none());
        f.suggested_fix = Some("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n".to_string());
        let p = props(&f);
        assert_eq!(p["vettalon.fix_check"]["outcome"], "fix_unverified");
        assert_eq!(p["vettalon.fix_check"]["reason"], "not_checked");
    }

    #[test]
    fn tier_disagreement_and_comment_sensitivity_are_sarif_properties() {
        use crate::audit::schema::{Condition, ConditionKind};
        let mut f = finding(Severity::High, FindingStatus::NeedsHuman, Some(1));
        f.refuter_conditions = Some(vec![Condition {
            kind: ConditionKind::TimingDependency,
            description: "race".into(),
        }]);
        f.evidence.push(crate::audit::schema::EvidenceItem {
            kind: EvidenceKind::CommentSensitivity,
            source: "adversarial".into(),
            detail: "comment_sensitivity: with_comments=refuted without_comments=plausible (2/2 stripped runs)".into(),
            recorded_at: String::new(),
        });
        let s = to_sarif(&report(vec![f]));
        let props = &s["runs"][0]["results"][0]["properties"];
        assert_eq!(props["vettalon.exploitability"], "conditional");
        assert_eq!(props["vettalon.exploitability_finder"], "direct");
        assert_eq!(props["vettalon.exploitability_refuter"], "conditional");
        assert_eq!(props["vettalon.tier_disagreement"], true);
        assert_eq!(props["vettalon.comment_sensitivity"], true);
        // Without refuter preconditions nothing new appears.
        let plain = to_sarif(&report(vec![finding(
            Severity::Low,
            FindingStatus::Candidate,
            None,
        )]));
        let props = &plain["runs"][0]["results"][0]["properties"];
        assert_eq!(props["vettalon.exploitability"], "direct");
        assert!(props.get("vettalon.exploitability_refuter").is_none());
        assert!(props.get("vettalon.tier_disagreement").is_none());
        assert!(props.get("vettalon.comment_sensitivity").is_none());
    }

    #[test]
    fn severity_disagreement_is_a_result_property_and_keeps_effective_level() {
        let mut f = finding(Severity::Medium, FindingStatus::Candidate, Some(1));
        f.evidence.push(crate::audit::schema::EvidenceItem {
            kind: EvidenceKind::SeverityDisagreement,
            source: "adversarial".into(),
            detail: "severity_disagreement: finder impact=medium, refuter impact=high (runs 1,3 of 3), low (run 2 of 3)".into(),
            recorded_at: String::new(),
        });
        let s = to_sarif(&report(vec![f]));
        let props = &s["runs"][0]["results"][0]["properties"];
        assert_eq!(props["vettalon.severity_disagreement"], true);
        assert_eq!(props["vettalon.severity"], "medium");
        let plain = to_sarif(&report(vec![finding(
            Severity::Medium,
            FindingStatus::Candidate,
            Some(1),
        )]));
        assert!(
            plain["runs"][0]["results"][0]["properties"]
                .get("vettalon.severity_disagreement")
                .is_none()
        );
    }

    #[test]
    fn coverage_hardening_and_leads_never_become_sarif_results() {
        let mut r = report(vec![]);
        r.coverage = serde_json::from_value(json!([{
            "module_path": "src", "status": "covered", "reason": null,
            "hardening": [{"file": "src/a.py", "line": 1, "note": "harden"}],
            "leads": [{"path": "other/b.py", "reason": "follow"}]
        }]))
        .unwrap();
        let s = to_sarif(&r);
        assert_eq!(s["runs"][0]["results"], json!([]));
        assert_eq!(
            s["runs"][0]["properties"]["vettalon.coverage"][0]["hardening"][0]["note"],
            "harden"
        );
    }
}
