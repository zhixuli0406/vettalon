//! SARIF 2.1.0 for `vettalon toolchain audit --format sarif`: one rule per
//! rule id, `~`-relative artifact URIs.

use serde_json::{Value, json};

use super::report::{ReportFinding, ToolchainReport};
use crate::audit::schema::Severity;

/// `(id, name, short description)` for every rule in `tc-rules-2`.
pub const RULES: &[(&str, &str, &str)] = &[
    (
        "TC001",
        "fetch-and-execute",
        "Download piped or substituted into an interpreter",
    ),
    (
        "TC002",
        "encoded-payload",
        "Encoded payload decoded and executed, or long base64 in instructions",
    ),
    (
        "TC003",
        "exfiltration-endpoint",
        "Known exfiltration, paste or tunnel endpoint, or raw IPv4 URL",
    ),
    (
        "TC004",
        "persistence",
        "Installs persistence (cron, launchd, systemd, shell rc, SSH keys)",
    ),
    (
        "TC005",
        "credential-access",
        "Reads credentials, tokens, cookies or the keychain",
    ),
    (
        "TC006",
        "oversized-content",
        "File above --max-file-bytes or a very long line",
    ),
    (
        "TC007",
        "hidden-characters",
        "Invisible, bidi, ANSI or mixed-script characters",
    ),
    (
        "TC008",
        "prompt-injection",
        "Prompt-injection signals in skill text or tool descriptions",
    ),
    (
        "TC009",
        "prerequisite-trap",
        "Requires running an external command or download before use",
    ),
    (
        "TC010",
        "bundled-executable",
        "Bundled native executable or executable bit outside scripts/",
    ),
    (
        "TC011",
        "bundled-dependency-tree",
        "Bundled dependency tree; metadata hashed, contents not scanned",
    ),
    (
        "TC012",
        "secret-bearing-file",
        "Secret-bearing file bundled (.env, keys, credential stores); excerpts withheld",
    ),
    (
        "TC013",
        "remote-self-overwrite",
        "Downloads content over the skill's own instruction files",
    ),
    (
        "MC001",
        "unpinned-launcher-package",
        "npx/bunx/pnpm dlx/uvx/pipx run without an exact version",
    ),
    (
        "MC002",
        "npm-malicious-signal",
        "npm malicious-package signal (MAL index, typosquat, registry)",
    ),
    (
        "MC003",
        "insecure-remote",
        "MCP server over http:// to a non-loopback host",
    ),
    (
        "MC004",
        "inline-secret",
        "Literal secret in MCP env, headers or args (value redacted)",
    ),
    (
        "MC005",
        "risky-command-path",
        "MCP command in a temporary, world-writable or relative path",
    ),
    (
        "MC006",
        "unparseable-package-spec",
        "npm package spec that is not a valid name[@version]; not looked up",
    ),
    (
        "PN001",
        "changed-since-pin",
        "Item content differs from its pin",
    ),
    ("PN002", "unpinned-item", "Discovered item without a pin"),
    (
        "PN003",
        "pinned-item-missing",
        "Pinned item no longer discovered",
    ),
];

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Percent-encode what is not allowed in a URI reference; `~` and `/` stay.
fn uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:@!$&'()*+,;=".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn result(f: &ReportFinding) -> Value {
    let mut r = json!({
        "ruleId": f.rule,
        "level": level(f.severity),
        "message": {"text": f.message},
        "properties": {"item": f.item, "severity": f.severity.as_str(), "finding_id": f.id},
    });
    if let Some(file) = &f.file {
        let mut loc = json!({"physicalLocation": {"artifactLocation": {"uri": uri(file)}}});
        if let Some(line) = f.line {
            loc["physicalLocation"]["region"] = json!({"startLine": line});
        }
        r["locations"] = json!([loc]);
    }
    if !f.excerpt.is_empty() {
        r["properties"]["excerpt"] = json!(f.excerpt);
    }
    r
}

pub fn render(report: &ToolchainReport) -> String {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|(id, name, desc)| json!({"id": id, "name": name, "shortDescription": {"text": desc}}))
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vettalon-toolchain",
                "version": report.vettalon_version,
                "informationUri": "https://github.com/zhixuli0406/vettalon",
                "rules": rules,
            }},
            "results": report.findings.iter().map(result).collect::<Vec<_>>(),
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "rules_version": report.rules_version,
                    "complete": report.summary.complete,
                    "incomplete_reasons": report.summary.incomplete_reasons,
                },
            }],
        }],
    });
    let mut s = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_keeps_tilde_and_escapes_spaces() {
        assert_eq!(
            uri("~/.claude/skills/a b/SKILL.md"),
            "~/.claude/skills/a%20b/SKILL.md"
        );
        assert_eq!(uri("~/x#y"), "~/x%23y");
    }

    #[test]
    fn every_rule_id_is_unique() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.0).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
    }
}
