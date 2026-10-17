//! `cargo audit --json` normalizer.
//!
//! **Offline note**: cargo-audit's advisory database is a local clone of the
//! RustSec `advisory-db` git repo (usually `~/.cargo/advisory-db`, or
//! `CARGO_HOME`-relative). We invoke `cargo audit --json --no-fetch` so it
//! never attempts a network update — using whatever is already cached
//! locally. If no cache exists at all, the command fails outright (no crash
//! on our side — that failure surfaces as a normal `EngineRun.parse_error`,
//! same as any other malformed/empty scanner output).
//!
//! **Severity known limitation**: cargo-audit's JSON does not ship a
//! first-class severity field. We use a coarse heuristic — see
//! [`map_severity`] — documented as best-effort, not a scored CVSS mapping.

use serde::Deserialize;

use crate::audit::schema::{EvidenceItem, EvidenceKind, Finding, FindingKind, Severity};

pub const ENGINE_NAME: &str = "cargo-audit";

#[derive(Debug, Deserialize)]
struct CargoAuditReport {
    #[serde(default)]
    error: Option<serde_json::Value>,
    vulnerabilities: VulnerabilitiesBlock,
}

#[derive(Debug, Deserialize)]
struct VulnerabilitiesBlock {
    found: bool,
    count: usize,
    list: Vec<VulnEntry>,
}

#[derive(Debug, Deserialize)]
struct VulnEntry {
    advisory: Advisory,
    package: Package,
}

#[derive(Debug, Deserialize)]
struct Advisory {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    cvss: Option<serde_json::Value>,
    #[serde(default)]
    informational: Option<serde_json::Value>,
    /// Other ids for the same advisory (`CVE-…`, `GHSA-…`).
    #[serde(default)]
    aliases: Vec<String>,
    // Real cargo-audit output ships explicit `"url": null` for advisories
    // without a canonical link (verified live 2026-08-18 — a bare `String`
    // here made the whole report unparseable and silently zeroed 4 real
    // findings on this repo's own Cargo.lock).
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Package {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

/// Best-effort severity heuristic (documented limitation — cargo-audit's
/// JSON has no first-class severity field):
/// - `informational` present (e.g. "unmaintained", "unsound") → Low: a real
///   signal, but not an exploitable vulnerability by itself.
/// - `cvss` present (any non-null value) → High: a scored advisory matched
///   the lockfile, worth immediate attention.
/// - neither present → Medium: a confirmed RUSTSEC match with no further
///   signal either way — the deliberately-in-the-middle default so this
///   alone won't trip a `--fail-on high` gate but still shows up in the report.
fn map_severity(advisory: &Advisory) -> Severity {
    if advisory.informational.is_some() {
        Severity::Low
    } else if advisory.cvss.is_some() {
        Severity::High
    } else {
        Severity::Medium
    }
}

/// Parse `cargo audit --json` output. Malformed top-level JSON is an `Err`;
/// missing/inconsistent vulnerability fields are errors, never a clean scan.
pub fn parse(raw: &str) -> Result<Vec<Finding>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("cargo-audit returned empty stdout".to_string());
    }
    let report: CargoAuditReport =
        serde_json::from_str(trimmed).map_err(|e| format!("cargo-audit JSON parse failed: {e}"))?;

    if report.error.is_some() {
        return Err("cargo-audit reported an execution error".to_string());
    }
    let block = report.vulnerabilities;
    if block.count != block.list.len() || block.found != !block.list.is_empty() {
        return Err("cargo-audit vulnerabilities found/count/list disagree".to_string());
    }
    if block.list.iter().any(|entry| {
        entry.advisory.id.trim().is_empty()
            || entry.package.name.trim().is_empty()
            || entry.package.version.trim().is_empty()
    }) {
        return Err("cargo-audit vulnerability entry lacks advisory/package identity".to_string());
    }
    let list = block.list;

    Ok(list
        .into_iter()
        .map(|entry| {
            let advisory = entry.advisory;
            let package = entry.package;
            let severity = map_severity(&advisory);
            let title = if advisory.title.is_empty() {
                format!("{} (unscored advisory)", advisory.id)
            } else {
                format!("{}: {}", advisory.id, advisory.title)
            };
            let snippet = format!(
                "{} {} — {}",
                package.name,
                package.version,
                crate::util::truncate_bytes(&advisory.description, 300)
            );
            let evidence = vec![EvidenceItem {
                kind: EvidenceKind::StaticHit,
                source: ENGINE_NAME.to_string(),
                detail: crate::util::truncate_bytes(
                    advisory.url.as_deref().unwrap_or(""),
                    crate::audit::schema::SNIPPET_MAX_BYTES,
                )
                .to_string(),
                recorded_at: chrono::Utc::now().to_rfc3339(),
            }];
            // Dependency findings have no line number — the "location" is
            // the resolved package, not a code line.
            let file = if package.name.is_empty() {
                "Cargo.lock".to_string()
            } else {
                format!("Cargo.lock ({} {})", package.name, package.version)
            };
            let cve: Vec<String> = advisory
                .aliases
                .iter()
                .filter(|a| a.starts_with("CVE-"))
                .cloned()
                .collect();
            // RustSec ships the CVSS vector as a string; score it only when it
            // parses (a malformed vector is dropped, never guessed).
            let cvss = advisory
                .cvss
                .as_ref()
                .and_then(|v| v.as_str())
                .and_then(crate::audit::cvss::CvssScore::from_vector);
            let mut f = Finding::candidate(
                ENGINE_NAME,
                FindingKind::DependencyVulnerability,
                severity,
                title,
                file,
                None,
                &snippet,
                advisory.id,
                evidence,
            );
            f.cve = cve;
            f.cvss = cvss;
            f
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "database": {"advisory-count": 700, "last-commit": "abc", "last-updated": "2026-08-01"},
      "lockfile": {"dependency-count": 250},
      "settings": {},
      "vulnerabilities": {
        "found": true,
        "count": 1,
        "list": [
          {
            "advisory": {
              "id": "RUSTSEC-2021-0001",
              "package": "somepkg",
              "title": "Use-after-free in somepkg",
              "description": "A use-after-free bug can be triggered by...",
              "date": "2021-01-01",
              "aliases": ["CVE-2021-9999"],
              "categories": ["memory-corruption"],
              "keywords": [],
              "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "informational": null,
              "references": [],
              "url": "https://rustsec.org/advisories/RUSTSEC-2021-0001"
            },
            "versions": {"patched": [">=1.2.3"], "unaffected": []},
            "package": {"name": "somepkg", "version": "1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index"}
          }
        ]
      },
      "warnings": {}
    }"#;

    #[test]
    fn parses_realistic_fixture_into_one_finding() {
        let findings = parse(FIXTURE).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.source_engine, "cargo-audit");
        assert_eq!(f.kind, FindingKind::DependencyVulnerability);
        assert_eq!(f.severity, Severity::High); // has cvss
        assert_eq!(f.rule_id, "RUSTSEC-2021-0001");
        assert!(f.title.contains("Use-after-free"));
        assert!(f.file.contains("somepkg"));
        assert!(f.line.is_none());
        assert_eq!(f.cve, vec!["CVE-2021-9999".to_string()]);
        let cvss = f.cvss.as_ref().expect("source-supplied vector is scored");
        assert_eq!(cvss.base_score, 9.8);
        assert_eq!(cvss.cvss_version, "3.1");
    }

    #[test]
    fn informational_advisory_maps_to_low() {
        let raw = r#"{
          "vulnerabilities": {"found": true, "count": 1, "list": [
            {
              "advisory": {"id": "RUSTSEC-2022-0002", "title": "unmaintained", "informational": "unmaintained", "cvss": null},
              "package": {"name": "oldcrate", "version": "0.1.0"}
            }
          ]}
        }"#;
        let findings = parse(raw).unwrap();
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn unscored_no_informational_advisory_maps_to_medium() {
        let raw = r#"{
          "vulnerabilities": {"found": true, "count": 1, "list": [
            {"advisory": {"id": "RUSTSEC-2023-0003"}, "package": {"name": "pkg", "version": "1.0.0"}}
          ]}
        }"#;
        let findings = parse(raw).unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn explicit_null_fields_from_real_output_still_parse() {
        // Regression (2026-08-18 dogfood on this repo): live `cargo audit
        // --json` emits explicit nulls (`url`/`cvss`/`informational`/
        // `withdrawn`/`source`: null) rather than omitting the keys; the
        // parser must not reject the whole report over them.
        let raw = r#"{
          "vulnerabilities": {"found": true, "count": 1, "list": [
            {
              "advisory": {"id": "RUSTSEC-2026-0104", "title": "Reachable panic",
                           "description": "d", "cvss": null, "informational": null,
                           "url": null, "withdrawn": null, "source": null},
              "package": {"name": "rustls-webpki", "version": "0.102.0"}
            }
          ]}
        }"#;
        let findings = parse(raw).expect("null-bearing advisory must parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium); // no cvss, not informational
    }

    #[test]
    fn no_vulnerabilities_found_is_zero_findings() {
        let raw = r#"{"vulnerabilities": {"found": false, "count": 0, "list": []}}"#;
        assert!(parse(raw).unwrap().is_empty());
    }

    #[test]
    fn missing_vulnerabilities_block_is_an_error() {
        let raw = r#"{"database": {}}"#;
        assert!(parse(raw).is_err());
    }

    #[test]
    fn empty_stdout_is_an_error() {
        assert!(parse("").is_err());
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        assert!(parse("{not json").is_err());
    }

    #[test]
    fn entry_without_advisory_is_an_error() {
        let raw = r#"{"vulnerabilities": {"found": true, "count": 1, "list": [{"package": {"name": "x", "version": "1"}}]}}"#;
        assert!(parse(raw).is_err());
    }

    #[test]
    fn error_json_and_incomplete_or_inconsistent_blocks_are_not_clean() {
        for raw in [
            r#"{"error":"database unavailable"}"#,
            r#"{"vulnerabilities":{}}"#,
            r#"{"vulnerabilities":{"list":[]}}"#,
            r#"{"vulnerabilities":{"found":true,"count":0,"list":[]}}"#,
            r#"{"vulnerabilities":{"found":false,"count":1,"list":[]}}"#,
        ] {
            assert!(parse(raw).is_err(), "{raw}");
        }
    }
}
