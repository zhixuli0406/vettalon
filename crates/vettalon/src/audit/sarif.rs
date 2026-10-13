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

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub's `security-severity` (CVSS-like 0.0–10.0 string).
fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

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

fn result(f: &Finding) -> Value {
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
        }
    });
    if let Some(cwe) = &f.cwe {
        r["properties"]["vettalon.cwe"] = json!(cwe);
    }
    if !f.cve.is_empty() {
        r["properties"]["vettalon.cve"] = json!(f.cve);
    }
    if let Some(cvss) = &f.cvss {
        r["properties"]["vettalon.cvss"] = json!(cvss);
    }
    if matches!(f.status, FindingStatus::Refuted | FindingStatus::Suppressed) {
        let why = f
            .evidence
            .iter()
            .rev()
            .find(|e| matches!(e.kind, EvidenceKind::AdversarialReview | EvidenceKind::OperatorReview))
            .map(|e| crate::util::truncate_bytes(&e.detail, 500).to_string())
            .unwrap_or_else(|| status_str(f.status));
        r["suppressions"] = json!([{ "kind": "external", "justification": why }]);
    }
    r
}

pub fn to_sarif(report: &AuditReport) -> Value {
    // One rule per rule id, at the highest severity seen for it, tagged with
    // every CWE its findings carry (GitHub's `external/cwe/cwe-NNN` form) and
    // scored from a source-supplied CVSS vector when one exists.
    struct RuleAgg {
        severity: Severity,
        tags: std::collections::BTreeSet<String>,
        max_cvss: Option<f64>,
    }
    let mut rules: BTreeMap<&str, RuleAgg> = BTreeMap::new();
    for f in &report.findings {
        let e = rules.entry(f.rule_id.as_str()).or_insert_with(|| RuleAgg {
            severity: f.severity,
            tags: std::collections::BTreeSet::new(),
            max_cvss: None,
        });
        if f.severity > e.severity {
            e.severity = f.severity;
        }
        if let Some(tag) = f.cwe.as_deref().and_then(crate::audit::cwe::sarif_tag) {
            e.tags.insert(tag);
        }
        if let Some(score) = f.cvss.as_ref().map(|c| c.base_score) {
            e.max_cvss = Some(e.max_cvss.map_or(score, |m: f64| m.max(score)));
        }
    }
    let rules: Vec<Value> = rules
        .into_iter()
        .map(|(id, agg)| {
            let mut tags = vec!["security".to_string()];
            tags.extend(agg.tags);
            let sec_sev = agg
                .max_cvss
                .map(|s| format!("{s:.1}"))
                .unwrap_or_else(|| security_severity(agg.severity).to_string());
            json!({
                "id": id,
                "shortDescription": { "text": id },
                "defaultConfiguration": { "level": level(agg.severity) },
                "properties": { "security-severity": sec_sev, "tags": tags }
            })
        })
        .collect();
    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "vettalon",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            }},
            "results": report.findings.iter().map(result).collect::<Vec<_>>(),
            "properties": {
                "vettalon.run_status": report.run_status,
                "vettalon.verifier_independence": report.verifier.independence,
                "vettalon.refusals": report.ensemble.refusals,
            }
        }]
    })
}

pub fn write_sarif(report: &AuditReport, path: &Path) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(&to_sarif(report)).map_err(std::io::Error::other)?;
    crate::util::write_private(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, GatePolicy, ProfileMode, ScanProfile, Summary, VerifierInfo};

    fn finding(sev: Severity, status: FindingStatus, line: Option<u32>) -> Finding {
        let mut f = Finding::candidate("semgrep", FindingKind::StaticAnalysis, sev, "t", "src/a.py", line, "s", "rule/x", vec![]);
        f.status = status;
        f
    }

    fn report(findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            schema_version: 2,
            repo: "/r".into(),
            started_at: "2026-10-12T00:00:00Z".into(),
            profile: ScanProfile { mode: ProfileMode::Quick, intake: None },
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
    fn cwe_becomes_github_tag_and_cvss_drives_security_severity() {
        let mut a = finding(Severity::High, FindingStatus::Candidate, Some(3));
        a.cwe = Some("CWE-89".into());
        a.cvss = crate::audit::cvss::CvssScore::from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        a.cve = vec!["CVE-2021-9999".into()];
        let sarif = to_sarif(&report(vec![a]));
        let rule = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
        let tags: Vec<&str> = rule["properties"]["tags"].as_array().unwrap().iter().filter_map(|t| t.as_str()).collect();
        assert!(tags.contains(&"security"));
        assert!(tags.contains(&"external/cwe/cwe-089"), "{tags:?}");
        assert_eq!(rule["properties"]["security-severity"], "9.8", "real CVSS beats the severity default");
        let res = &sarif["runs"][0]["results"][0];
        assert_eq!(res["properties"]["vettalon.cwe"], "CWE-89");
        assert_eq!(res["properties"]["vettalon.cve"][0], "CVE-2021-9999");
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
        assert_eq!(res[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3);
        assert!(res[1]["locations"][0]["physicalLocation"].get("region").is_none());
        let rules = s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["properties"]["security-severity"], "9.5");
    }

    #[test]
    fn unsafe_claimed_paths_get_no_location_and_uris_are_encoded() {
        let mut f = finding(Severity::High, FindingStatus::Refuted, Some(1));
        f.file = "/etc/passwd".into();
        let mut r = report(vec![f, finding(Severity::Low, FindingStatus::Candidate, Some(2))]);
        r.findings[1].file = "src/中 文.py".into();
        r.repo = "/home/a b".into();
        let s = to_sarif(&r);
        assert!(s["runs"][0]["results"][0]["locations"].as_array().unwrap().is_empty());
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
        let s = to_sarif(&report(vec![finding(Severity::High, FindingStatus::Refuted, Some(1))]));
        let res = &s["runs"][0]["results"][0];
        assert_eq!(res["suppressions"][0]["kind"], "external");
        assert_eq!(res["properties"]["vettalon.status"], "refuted");
    }
}
