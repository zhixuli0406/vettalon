//! CycloneDX 1.6 VDR / VEX export (JSON) for dependency findings
//! (`vettalon scan --cyclonedx <path>`).
//!
//! Derived from a validated [`AuditReport`]; it never changes a verdict.
//! Only `dependency_vulnerability` findings are exported (code findings
//! belong in SARIF). Each becomes a `vulnerabilities[]` entry that names the
//! advisory, the affected component (Package URL), the source's CVSS rating
//! (v3.x or v4.0, vector included) and vettalon's qualitative severity as a
//! separate `method: "other"` rating that never carries a number.
//!
//! VEX `analysis.state` comes only from recorded evidence:
//! - operator `confirmed` → `exploitable`;
//! - operator `refuted` (a human said "not a vulnerability") → `false_positive`;
//! - everything else — scanner hits, model refutations, operator
//!   suppressions — → `in_triage`, with the reason in `detail`.
//!
//! `not_affected` is never emitted: it is a statement about the deploying
//! product that needs an explicit operator VEX justification, which vettalon
//! does not collect yet. A model saying "unreachable" is not such a statement.

use std::path::Path;

use serde_json::{Value, json};

use super::schema::{
    AuditReport, EvidenceKind, Finding, FindingKind, FindingStatus, PackageRef, Severity,
};

pub const SPEC_VERSION: &str = "1.6";
const SCHEMA: &str = "http://cyclonedx.org/schema/bom-1.6.schema.json";

/// The dependency a finding is about: the recorded coordinates, or for a
/// pre-0.2 cargo-audit finding the `Cargo.lock (name version)` location.
fn package_of(f: &Finding) -> Option<PackageRef> {
    if let Some(p) = &f.package {
        return Some(p.clone());
    }
    if f.source_engine != super::scanners::cargo_audit::ENGINE_NAME {
        return None;
    }
    let inner = f.file.strip_prefix("Cargo.lock (")?.strip_suffix(')')?;
    let (name, version) = inner.split_once(' ')?;
    (!name.is_empty() && !version.is_empty() && !version.contains(' ')).then(|| PackageRef {
        ecosystem: "cargo".into(),
        name: name.into(),
        version: version.into(),
    })
}

fn severity_key(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// The latest operator decision word and reason, if a human decided.
fn operator_decision(f: &Finding) -> Option<(String, String)> {
    let e = f
        .evidence
        .iter()
        .rev()
        .find(|e| e.kind == EvidenceKind::OperatorReview)?;
    let rest = e.detail.strip_prefix("operator_decision:")?.trim_start();
    let (word, reason) = rest
        .split_once(super::triage::REASON_MARKER)
        .unwrap_or((rest, ""));
    Some((word.trim().to_string(), reason.trim().to_string()))
}

fn analysis(f: &Finding) -> Value {
    let op = operator_decision(f);
    let with_reason = |lead: &str, reason: &str| {
        if reason.is_empty() {
            lead.to_string()
        } else {
            format!("{lead}: {reason}")
        }
    };
    let (state, detail) = match (f.status, op.as_ref()) {
        (FindingStatus::Confirmed, Some((w, r))) if w == "confirmed" => (
            "exploitable",
            with_reason("Operator confirmed the finding", r),
        ),
        (FindingStatus::Refuted, Some((w, r))) if w == "refuted" => (
            "false_positive",
            with_reason("Operator judged it not a vulnerability", r),
        ),
        (FindingStatus::Suppressed, Some((_, r))) => (
            "in_triage",
            with_reason(
                "Operator excluded it from the fix list (accepted or out of scope); no affectedness statement",
                r,
            ),
        ),
        (FindingStatus::Refuted, None) => (
            "in_triage",
            "An automated refuter disputed this finding; that is not a not_affected statement. Operator review required.".to_string(),
        ),
        // An operator decision that does not match the current status (e.g.
        // a later automated change): state it, claim nothing more.
        (_, Some((w, r))) => (
            "in_triage",
            with_reason(&format!("Latest operator decision: {w}; status since changed"), r),
        ),
        _ => (
            "in_triage",
            "The advisory matches the resolved dependency version; reachability in this product was not analysed.".to_string(),
        ),
    };
    json!({ "state": state, "detail": detail })
}

fn advisory_source(f: &Finding) -> Value {
    let id = f.rule_id.as_str();
    if id.starts_with("RUSTSEC-") {
        json!({ "name": "RustSec", "url": format!("https://rustsec.org/advisories/{id}.html") })
    } else {
        json!({ "name": f.source_engine })
    }
}

fn ratings(f: &Finding) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(c) = &f.cvss {
        let method = match c.cvss_version.as_str() {
            "4.0" => "CVSSv4",
            "3.1" => "CVSSv31",
            _ => "CVSSv3",
        };
        let mut r = json!({
            "source": advisory_source(f),
            "score": c.base_score,
            "severity": c.rating(),
            "method": method,
            "vector": c.cvss_vector,
        });
        if let Some(n) = c.nomenclature() {
            r["justification"] = json!(format!("{n}, as supplied by the advisory"));
        }
        out.push(r);
    }
    let basis = serde_json::to_value(f.severity_basis)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    out.push(json!({
        "source": { "name": "vettalon" },
        "severity": severity_key(f.severity),
        "method": "other",
        "justification": format!("vettalon qualitative severity (basis: {basis}); not a CVSS score"),
    }));
    out
}

fn vulnerability(f: &Finding, pkg: Option<&PackageRef>) -> Value {
    let mut v = json!({
        "bom-ref": format!("vettalon:{}", f.id),
        "id": f.rule_id,
        "source": advisory_source(f),
        "ratings": ratings(f),
        "description": f.title,
        "detail": f.snippet,
        "analysis": analysis(f),
        "tools": { "components": [{ "type": "application", "name": "vettalon", "version": env!("CARGO_PKG_VERSION") }] },
    });
    let refs: Vec<Value> = f
        .cve_refs()
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "source": { "name": "CVE", "url": super::cve::record_url(&r.id) },
            })
        })
        .collect();
    if !refs.is_empty() {
        v["references"] = json!(refs);
    }
    if let Some(n) = f
        .cwe
        .as_deref()
        .and_then(super::cwe::normalize)
        .and_then(|id| id.trim_start_matches("CWE-").parse::<u32>().ok())
    {
        v["cwes"] = json!([n]);
    }
    if let Some(p) = pkg {
        v["affects"] = json!([{
            "ref": p.purl(),
            "versions": [{ "version": p.version, "status": "affected" }],
        }]);
    }
    let status = serde_json::to_value(f.status)
        .ok()
        .and_then(|s| s.as_str().map(str::to_string))
        .unwrap_or_default();
    let mut props = vec![
        json!({ "name": "vettalon:status", "value": status }),
        json!({ "name": "vettalon:evidence_level", "value": f.evidence_level().key() }),
        json!({ "name": "vettalon:engine", "value": f.source_engine }),
    ];
    for r in f.cve_refs() {
        let state = serde_json::to_value(r.state)
            .ok()
            .and_then(|s| s.as_str().map(str::to_string))
            .unwrap_or_default();
        props.push(json!({ "name": format!("vettalon:cve_state:{}", r.id), "value": state }));
    }
    if let Some(m) = f.cwe_mapping() {
        props.push(json!({ "name": "vettalon:cwe_version", "value": m.cwe_version }));
        props.push(json!({ "name": "vettalon:cwe_mapping_usage", "value": m.usage.key() }));
    }
    if pkg.is_none() {
        props.push(json!({ "name": "vettalon:package", "value": "unknown" }));
    }
    v["properties"] = json!(props);
    v
}

/// The CycloneDX 1.6 BOM (VDR + VEX analysis) for the report's dependency
/// findings. An empty `vulnerabilities` array means no dependency finding,
/// not that dependencies are safe.
pub fn to_cyclonedx(report: &AuditReport) -> Value {
    let deps: Vec<(&Finding, Option<PackageRef>)> = report
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::DependencyVulnerability)
        .map(|f| (f, package_of(f)))
        .collect();
    let mut components: Vec<Value> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for p in deps.iter().filter_map(|(_, p)| p.as_ref()) {
        let purl = p.purl();
        if seen.insert(purl.clone()) {
            components.push(json!({
                "type": "library",
                "bom-ref": purl,
                "name": p.name,
                "version": p.version,
                "purl": purl,
            }));
        }
    }
    let vulnerabilities: Vec<Value> = deps
        .iter()
        .map(|(f, p)| vulnerability(f, p.as_ref()))
        .collect();
    let run_status = serde_json::to_value(report.run_status)
        .ok()
        .and_then(|s| s.as_str().map(str::to_string))
        .unwrap_or_default();
    json!({
        "$schema": SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "version": 1,
        "metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "tools": { "components": [{
                "type": "application",
                "name": "vettalon",
                "version": env!("CARGO_PKG_VERSION"),
            }]},
            "properties": [
                { "name": "vettalon:scan_started_at", "value": report.started_at },
                { "name": "vettalon:run_status", "value": run_status },
                { "name": "vettalon:scope", "value": "dependency advisory findings only; code findings are exported as SARIF" },
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    })
}

pub fn write_cyclonedx(report: &AuditReport, path: &Path) -> std::io::Result<()> {
    let text =
        serde_json::to_string_pretty(&to_cyclonedx(report)).map_err(std::io::Error::other)?;
    crate::util::write_private(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{
        EvidenceItem, GatePolicy, ProfileMode, ScanProfile, Summary, VerifierInfo,
    };

    fn dep(status: FindingStatus) -> Finding {
        let mut f = Finding::candidate(
            "cargo-audit",
            FindingKind::DependencyVulnerability,
            Severity::High,
            "RUSTSEC-1900-0001: test advisory",
            "Cargo.lock (somepkg 1.0.0)",
            None,
            "somepkg 1.0.0 — d",
            "RUSTSEC-1900-0001",
            vec![],
        );
        f.status = status;
        f.cve = vec!["CVE-1900-0001".into()];
        f.cwe = Some("CWE-416".into());
        f.package = Some(PackageRef {
            ecosystem: "cargo".into(),
            name: "somepkg".into(),
            version: "1.0.0".into(),
        });
        f
    }

    fn report(findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            schema_version: 2,
            scope: None,
            repo: "/r".into(),
            started_at: "2026-10-20T00:00:00Z".into(),
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

    fn operator(f: &mut Finding, decision: &str, reason: &str) {
        f.evidence.push(EvidenceItem {
            kind: EvidenceKind::OperatorReview,
            source: "dashboard".into(),
            detail: format!("operator_decision: {decision}; reason: {reason}"),
            recorded_at: "2026-10-20T00:00:00Z".into(),
        });
    }

    #[test]
    fn dependency_finding_becomes_vdr_entry_with_cvss_and_qualitative_ratings() {
        let mut f = dep(FindingStatus::Candidate);
        f.cvss = crate::audit::cvss::CvssScore::from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        );
        let mut code = dep(FindingStatus::Candidate);
        code.kind = FindingKind::StaticAnalysis;
        let bom = to_cyclonedx(&report(vec![f, code]));
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.6");
        assert!(
            bom["serialNumber"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );
        assert_eq!(bom["components"][0]["purl"], "pkg:cargo/somepkg@1.0.0");
        let vulns = bom["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1, "code findings are not exported");
        let v = &vulns[0];
        assert_eq!(v["id"], "RUSTSEC-1900-0001");
        assert_eq!(v["source"]["name"], "RustSec");
        assert_eq!(v["references"][0]["id"], "CVE-1900-0001");
        assert_eq!(v["cwes"], json!([416]));
        assert_eq!(v["affects"][0]["ref"], "pkg:cargo/somepkg@1.0.0");
        assert_eq!(v["affects"][0]["versions"][0]["status"], "affected");
        let ratings = v["ratings"].as_array().unwrap();
        assert_eq!(ratings[0]["method"], "CVSSv4");
        assert_eq!(ratings[0]["score"], 8.7);
        assert_eq!(ratings[0]["severity"], "high");
        assert_eq!(
            ratings[0]["vector"],
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
        );
        assert_eq!(ratings[1]["method"], "other");
        assert!(
            ratings[1].get("score").is_none(),
            "qualitative rating has no number"
        );
        assert_eq!(v["analysis"]["state"], "in_triage");
        let props = v["properties"].as_array().unwrap();
        assert!(
            props.contains(
                &json!({"name": "vettalon:cve_state:CVE-1900-0001", "value": "unverified"})
            )
        );
        assert!(props.contains(&json!({"name": "vettalon:cwe_version", "value": "4.20"})));
    }

    #[test]
    fn vex_state_comes_only_from_evidence_and_never_not_affected() {
        let mut confirmed = dep(FindingStatus::Confirmed);
        operator(&mut confirmed, "confirmed", "reachable from the API");
        let mut refuted_by_human = dep(FindingStatus::Refuted);
        operator(&mut refuted_by_human, "refuted", "feature not compiled in");
        let refuted_by_model = dep(FindingStatus::Refuted);
        let mut suppressed = dep(FindingStatus::Suppressed);
        operator(&mut suppressed, "suppressed", "accepted risk");
        let bom = to_cyclonedx(&report(vec![
            confirmed,
            refuted_by_human,
            refuted_by_model,
            suppressed,
            dep(FindingStatus::NeedsHuman),
            dep(FindingStatus::Candidate),
        ]));
        let states: Vec<&str> = bom["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["analysis"]["state"].as_str().unwrap())
            .collect();
        assert_eq!(
            states,
            vec![
                "exploitable",
                "false_positive",
                "in_triage",
                "in_triage",
                "in_triage",
                "in_triage"
            ]
        );
        assert!(
            !bom.to_string().contains("not_affected\""),
            "never emitted as a state"
        );
        let v = &bom["vulnerabilities"][1]["analysis"]["detail"];
        assert!(v.as_str().unwrap().contains("feature not compiled in"));
        // One component for six findings on the same package.
        assert_eq!(bom["components"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn legacy_cargo_audit_location_still_yields_a_component() {
        let mut f = dep(FindingStatus::Candidate);
        f.package = None;
        assert_eq!(
            package_of(&f).map(|p| p.purl()).as_deref(),
            Some("pkg:cargo/somepkg@1.0.0")
        );
        f.file = "Cargo.lock".into();
        let bom = to_cyclonedx(&report(vec![f]));
        let v = &bom["vulnerabilities"][0];
        assert!(v.get("affects").is_none());
        assert!(
            v["properties"]
                .as_array()
                .unwrap()
                .contains(&json!({"name": "vettalon:package", "value": "unknown"}))
        );
    }
}
