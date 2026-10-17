//! semgrep JSON normalizer + bundled offline ruleset.
//!
//! **Known limitation (documented per task instruction, not silently
//! worked around)**: semgrep's usual `--config auto` / `--config p/<pack>`
//! shortcuts fetch rules from the semgrep registry over the network (or
//! require `semgrep login`). This adapter uses a bundled rule file and
//! disables Semgrep metrics and version checks; other scan engines and configured models have
//! their own network boundaries. Instead of registry shortcuts,
//! this module writes a small **bundled, local** rule file
//! ([`BUNDLED_RULES_YAML`]) to a temp path and invokes
//! `semgrep scan --json --metrics=off --disable-version-check --config <local-path>`.
//! The local config avoids registry rule downloads. These flags are not an OS
//! network firewall or live proof of all third-party network behavior. We omit
//! `--error`, so every nonzero exit is a failed invocation even if candidates
//! are present; those candidates are retained. The bundled ruleset is intentionally
//! minimal (six generic-security rules, not a registry-grade ruleset).
//! Local acceptance on 2026-10-16 used Semgrep 1.181.0 under an OS deny-egress
//! policy: self-authored Python/JavaScript/TypeScript positive fixtures hit all
//! six rule IDs (eight results), while selected safe fixtures produced zero
//! results; both had no Semgrep errors. This validates only those rules,
//! fixtures, version and environment, not arbitrary source or all scanners.
//! Private raw evidence: reports/evidence-acceptance/root/semgrep-live-20261016/.
//! Deeper coverage requires a separately selected and validated ruleset.

use std::path::PathBuf;

use serde::Deserialize;

use crate::audit::schema::{EvidenceItem, EvidenceKind, Finding, FindingKind, Severity};

pub const ENGINE_NAME: &str = "semgrep";

/// Use bundled local rules and disable telemetry and server version checks.
pub fn args(rules_path: &str) -> Vec<String> {
    [
        "scan",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--config",
        rules_path,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Minimal offline ruleset. Kept intentionally small —
/// generic cross-language `eval`/shell-injection/unsafe-deserialization
/// patterns that don't require semgrep's typed dataflow engine to catch.
pub const BUNDLED_RULES_YAML: &str = r#"rules:
  - id: python-eval-exec-usage
    languages: [python]
    message: "Use of eval()/exec() on dynamic input can lead to arbitrary code execution."
    severity: ERROR
    patterns:
      - pattern-either:
          - pattern: eval(...)
          - pattern: exec(...)

  - id: python-subprocess-shell-true
    languages: [python]
    message: "subprocess call with shell=True can lead to command injection if input is not sanitized."
    severity: ERROR
    pattern: subprocess.$FUNC(..., shell=True, ...)

  - id: python-yaml-load-unsafe
    languages: [python]
    message: "yaml.load without a safe Loader can execute arbitrary code from untrusted YAML."
    severity: ERROR
    pattern: yaml.load($DATA)

  - id: javascript-eval-usage
    languages: [javascript, typescript]
    message: "Use of eval() can lead to arbitrary code execution."
    severity: ERROR
    pattern: eval(...)

  - id: javascript-child-process-exec
    languages: [javascript, typescript]
    message: "child_process.exec with dynamic input can lead to command injection; prefer execFile with an argument array."
    severity: WARNING
    pattern: require('child_process').exec(...)

  - id: generic-hardcoded-private-key
    languages: [generic]
    message: "Hardcoded private key material found in source."
    severity: ERROR
    pattern-regex: '-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----'
"#;

/// Temp-file guard for the bundled ruleset (mirrors `eval::runner::TempPromptFile`'s
/// convention: `std::env::temp_dir()` + a uuid-suffixed filename + best-effort
/// cleanup on drop). Not a secret, but shouldn't accumulate in tmp.
pub struct TempRulesFile(pub PathBuf);

impl TempRulesFile {
    pub fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "vettalon-semgrep-rules-{}.yml",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, BUNDLED_RULES_YAML)
            .map_err(|e| format!("cannot write bundled semgrep rules to temp file: {e}"))?;
        Ok(TempRulesFile(path))
    }
}

impl Drop for TempRulesFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// IDs of the bundled rules (the `- id:` lines of [`BUNDLED_RULES_YAML`]).
fn bundled_rule_ids() -> impl Iterator<Item = &'static str> {
    BUNDLED_RULES_YAML
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("- id:"))
        .map(str::trim)
}

/// semgrep prefixes the rule id with the config file's directory, dot-joined
/// (`var.folders.….T.python-eval-exec-usage` on macOS, `tmp.…` on Linux). The
/// temp directory changes every run, which would make SARIF consumers such as
/// GitHub code scanning treat each run's alerts as new rules. Map such ids
/// back to the bundled id; leave any other id as semgrep reported it.
fn normalize_check_id(raw: &str) -> String {
    bundled_rule_ids()
        .find(|id| raw == *id || raw.strip_suffix(id).is_some_and(|p| p.ends_with('.')))
        .map(str::to_string)
        .unwrap_or_else(|| raw.to_string())
}

/// semgrep `--json` top-level shape (subset — only what we use).
#[derive(Debug, Deserialize)]
struct SemgrepReport {
    results: Vec<SemgrepResult>,
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SemgrepResult {
    #[serde(default)]
    check_id: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    start: Option<SemgrepPos>,
    #[serde(default)]
    extra: Option<SemgrepExtra>,
}

#[derive(Debug, Deserialize)]
struct SemgrepPos {
    #[serde(default)]
    line: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SemgrepExtra {
    #[serde(default)]
    message: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    lines: String,
    /// Rule metadata; only `cwe` is read (registry rules carry it).
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

/// semgrep's `extra.severity` is one of `ERROR`/`WARNING`/`INFO` (not the
/// CRITICAL/HIGH/MEDIUM/LOW/INFO scale some registry rule metadata uses).
/// Mapped conservatively: ERROR→High, WARNING→Medium, INFO→Low, anything
/// else (unrecognized/absent) → Info, fail-open toward under- rather than
/// over-alarming for an unrecognized value.
fn map_severity(raw: &str) -> Severity {
    match raw.to_ascii_uppercase().as_str() {
        "ERROR" => Severity::High,
        "WARNING" => Severity::Medium,
        "INFO" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse `semgrep scan --json` output. Malformed top-level JSON is an
/// `Err`; missing results/errors or reported scanner errors cannot be clean.
#[cfg(test)]
pub fn parse(raw: &str) -> Result<Vec<Finding>, String> {
    let (findings, diagnostic) = parse_with_diagnostics(raw)?;
    match diagnostic {
        Some(error) => Err(error),
        None => Ok(findings),
    }
}

/// Keep usable candidates from a partial scan while recording every scanner error.
pub(super) fn parse_with_diagnostics(raw: &str) -> Result<(Vec<Finding>, Option<String>), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("semgrep returned empty stdout".to_string());
    }
    let report: SemgrepReport =
        serde_json::from_str(trimmed).map_err(|e| format!("semgrep JSON parse failed: {e}"))?;

    if report
        .results
        .iter()
        .any(|r| r.check_id.trim().is_empty() || r.path.trim().is_empty())
    {
        return Err("semgrep result lacks rule/path identity".to_string());
    }
    let diagnostic = (!report.errors.is_empty()).then(|| {
        format!(
            "semgrep reported {} scanner error(s): {}",
            report.errors.len(),
            crate::util::truncate_bytes(
                &serde_json::to_string(&report.errors).unwrap_or_default(),
                300
            )
        )
    });
    let findings = report
        .results
        .into_iter()
        .map(|r| {
            let check_id = normalize_check_id(&r.check_id);
            let extra = r.extra.unwrap_or(SemgrepExtra {
                message: String::new(),
                severity: String::new(),
                lines: String::new(),
                metadata: None,
            });
            let cwe = extra
                .metadata
                .as_ref()
                .and_then(crate::audit::cwe::from_semgrep_metadata);
            let severity = map_severity(&extra.severity);
            let line = r.start.and_then(|s| s.line);
            let title = if extra.message.is_empty() {
                format!("semgrep rule {check_id}")
            } else {
                extra.message.clone()
            };
            let evidence = vec![EvidenceItem {
                kind: EvidenceKind::StaticHit,
                source: ENGINE_NAME.to_string(),
                detail: crate::util::truncate_bytes(
                    &extra.message,
                    crate::audit::schema::SNIPPET_MAX_BYTES,
                )
                .to_string(),
                recorded_at: chrono::Utc::now().to_rfc3339(),
            }];
            let mut f = Finding::candidate(
                ENGINE_NAME,
                FindingKind::StaticAnalysis,
                severity,
                title,
                r.path,
                line,
                &extra.lines,
                check_id,
                evidence,
            );
            f.cwe = cwe;
            f
        })
        .collect();
    Ok((findings, diagnostic))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_disables_metrics_and_keeps_a_local_rules_path() {
        let args = args("/tmp/vettalon-local.yml");
        assert_eq!(
            args,
            [
                "scan",
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--config",
                "/tmp/vettalon-local.yml"
            ]
        );
    }

    #[test]
    fn bundled_rule_ids_lose_the_temp_dir_prefix_semgrep_adds() {
        // semgrep prefixes a local config's directory, dot-joined; on macOS
        // that directory changes every run, so code scanning would see a new
        // rule each time.
        assert_eq!(
            normalize_check_id("var.folders.n5.abc123.T.python-eval-exec-usage"),
            "python-eval-exec-usage"
        );
        assert_eq!(
            normalize_check_id("tmp.python-yaml-load-unsafe"),
            "python-yaml-load-unsafe"
        );
        assert_eq!(
            normalize_check_id("python-eval-exec-usage"),
            "python-eval-exec-usage"
        );
        // Anything that is not a bundled rule is left untouched.
        assert_eq!(
            normalize_check_id("custom.rules.my-check"),
            "custom.rules.my-check"
        );
        assert_eq!(
            normalize_check_id("xpython-eval-exec-usage"),
            "xpython-eval-exec-usage"
        );
    }

    const FIXTURE: &str = r#"{
      "results": [
        {
          "check_id": "python-eval-exec-usage",
          "path": "app.py",
          "start": {"line": 10, "col": 1, "offset": 100},
          "end": {"line": 10, "col": 20, "offset": 120},
          "extra": {
            "message": "Use of eval()/exec() on dynamic input can lead to arbitrary code execution.",
            "severity": "ERROR",
            "lines": "eval(user_input)",
            "metadata": {"cwe": ["CWE-95"]}
          }
        },
        {
          "check_id": "javascript-child-process-exec",
          "path": "server.js",
          "start": {"line": 42},
          "extra": {
            "message": "child_process.exec with dynamic input.",
            "severity": "WARNING",
            "lines": "exec(cmd)"
          }
        }
      ],
      "errors": [],
      "paths": {"scanned": ["app.py", "server.js"], "skipped": []}
    }"#;

    #[test]
    fn parses_realistic_fixture_into_findings() {
        let findings = parse(FIXTURE).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].file, "app.py");
        assert_eq!(findings[0].line, Some(10));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule_id, "python-eval-exec-usage");
        assert_eq!(
            findings[0].cwe.as_deref(),
            Some("CWE-95"),
            "CWE read from rule metadata"
        );
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn severity_mapping_covers_all_three_levels_and_unknown() {
        assert_eq!(map_severity("ERROR"), Severity::High);
        assert_eq!(map_severity("error"), Severity::High);
        assert_eq!(map_severity("WARNING"), Severity::Medium);
        assert_eq!(map_severity("INFO"), Severity::Low);
        assert_eq!(map_severity("SOMETHING_NEW"), Severity::Info);
        assert_eq!(map_severity(""), Severity::Info);
    }

    #[test]
    fn empty_results_is_zero_findings() {
        let findings = parse(r#"{"results": [], "errors": []}"#).unwrap();
        assert!(findings.is_empty());
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
    fn missing_extra_block_degrades_gracefully() {
        let raw = r#"{"results": [{"check_id": "x", "path": "a.py"}], "errors": []}"#;
        let findings = parse(raw).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].line.is_none());
        assert!(findings[0].title.contains('x'));
    }

    #[test]
    fn bundled_ruleset_is_syntactically_valid_yaml() {
        // Sanity check only — this does NOT confirm semgrep accepts the
        // rule schema (that needs a live semgrep run, out of scope here).
        let parsed: serde_yaml::Value = serde_yaml::from_str(BUNDLED_RULES_YAML)
            .expect("bundled semgrep ruleset must be valid YAML");
        let rules = parsed
            .get("rules")
            .expect("must have a top-level `rules` key");
        assert!(rules.as_sequence().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn temp_rules_file_writes_and_cleans_up() {
        let guard = TempRulesFile::create().unwrap();
        let path = guard.0.clone();
        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, BUNDLED_RULES_YAML);
        drop(guard);
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn missing_results_or_errors_is_not_clean() {
        for raw in [
            "{}",
            r#"{"results":[]}"#,
            r#"{"errors":[]}"#,
            r#"{"results":[],"errors":null}"#,
            r#"{"results":[{}],"errors":[]}"#,
        ] {
            assert!(parse(raw).is_err(), "{raw}");
        }
    }
}
