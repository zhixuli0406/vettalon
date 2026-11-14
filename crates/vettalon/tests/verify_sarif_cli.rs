#![cfg(unix)]
//! `vettalon verify --input <log.sarif>` end to end. The verifier is a shell
//! script that prints a fixed refutation; no real model is called.

use std::path::PathBuf;
use std::process::{Command, Output};

const REFUTED: &str = r#"{"verdict":"refuted","reason":"not reachable","blockers":[],"validation_plan":{"local":null,"deployment":null},"refute_basis":"unreachable"}"#;

/// Semgrep-style log: one CWE-78 result, one CWE-327 result (capped by the
/// per-CWE trust policy), one `https:` location and one `../` escape.
const SARIF: &str = r#"{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Semgrep OSS", "rules": [
      {"id": "cmd", "properties": {"tags": ["CWE-78: OS Command Injection"]}},
      {"id": "des", "properties": {"tags": ["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"]}}
    ]}},
    "results": [
      {"ruleId": "cmd", "level": "warning", "message": {"text": "os.system with user input"},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
                                           "region": {"startLine": 3}}}]},
      {"ruleId": "des", "level": "warning", "message": {"text": "DES cipher"},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/crypto.py"},
                                           "region": {"startLine": 2}}}]},
      {"ruleId": "cmd", "level": "warning", "message": {"text": "remote"},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://example.com/a.py"},
                                           "region": {"startLine": 1}}}]},
      {"ruleId": "cmd", "level": "warning", "message": {"text": "escape"},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "../outside.py"},
                                           "region": {"startLine": 1}}}]}
    ]
  }]
}"#;

struct Fixture {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    empty_path: PathBuf,
    calls: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let home = dir.path().join("home");
        let empty_path = dir.path().join("empty-path");
        for d in [&repo, &home, &empty_path] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir(repo.join("src")).unwrap();
        std::fs::write(
            repo.join("src/app.py"),
            "import os\nq = input()\nos.system(q)\n",
        )
        .unwrap();
        std::fs::write(
            repo.join("src/crypto.py"),
            "from Crypto.Cipher import DES\nc = DES.new(key, DES.MODE_ECB)\n",
        )
        .unwrap();
        let script = dir.path().join("verifier.sh");
        std::fs::write(
            &script,
            format!(
                "/bin/cat > /dev/null\nprintf 'called\\n' >> \"$0.called\"\nprintf '%s' '{REFUTED}'\n"
            ),
        )
        .unwrap();
        std::fs::write(
            home.join("config.toml"),
            format!(
                "[[model]]\nid = \"checker\"\nbackend = \"cli\"\nfamily = \"test\"\nroles = [\"verifier\"]\nprogram = \"/bin/sh\"\nargs = [{}]\nprompt_via = \"stdin\"\nallow_agent_tools = true\n",
                serde_json::to_string(&script).unwrap()
            ),
        )
        .unwrap();
        Self {
            calls: script.with_extension("sh.called"),
            _dir: dir,
            repo,
            home,
            empty_path,
        }
    }

    fn verify(&self, input_name: &str, input: &str) -> (Output, Option<serde_json::Value>) {
        self.verify_with(input_name, input, &[])
    }

    fn verify_with(
        &self,
        input_name: &str,
        input: &str,
        extra: &[&str],
    ) -> (Output, Option<serde_json::Value>) {
        let input_path = self.home.join(input_name);
        std::fs::write(&input_path, input).unwrap();
        let out_path = self.home.join("verify.json");
        let _ = std::fs::remove_file(&out_path);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vettalon"));
        cmd.env("VETTALON_HOME", &self.home)
            .env("PATH", &self.empty_path)
            .args(["--lang", "en", "verify"])
            .arg(&self.repo)
            .arg("--input")
            .arg(&input_path)
            .args(["--verifier", "checker", "--config"])
            .arg(self.home.join("config.toml"))
            .arg("--out")
            .arg(&out_path);
        if !extra.contains(&"--refuter-runs") {
            cmd.args(["--refuter-runs", "1"]);
        }
        let output = cmd.args(extra).output().unwrap();
        let json = std::fs::read(&out_path)
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap());
        (output, json)
    }

    fn call_count(&self) -> usize {
        std::fs::read_to_string(&self.calls)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }
}

#[test]
fn sarif_input_is_reviewed_and_a_crypto_cwe_is_not_closed_by_the_model() {
    let fx = Fixture::new();
    let (output, json) = fx.verify("semgrep.sarif", SARIF);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let out = json.expect("verify.json written");
    assert_eq!(out["schema"], "vettalon.verify/1");
    assert_eq!(out["input"], "sarif");
    let ids = serde_json::json!(["sarif-0-0", "sarif-0-1"]);
    assert_eq!(out["claim_ids"], ids);
    assert_eq!(out["calls"], 2);
    // Only the two usable results reach the model.
    assert_eq!(fx.call_count(), 2);
    let findings = out["findings"].as_array().unwrap();
    assert_eq!(findings[0]["status"], "refuted");
    assert_eq!(findings[0]["cwe"], "CWE-78");
    assert_eq!(findings[1]["status"], "needs_human");
    assert_eq!(findings[1]["cwe"], "CWE-327");
    let details: Vec<&str> = findings[1]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["detail"].as_str())
        .collect();
    assert!(
        details.contains(&"trust_policy: llm_refute_capped CWE-327"),
        "{details:?}"
    );
    assert_eq!(findings[1]["found_by"][0], "external:Semgrep-OSS");
    let skipped: Vec<&str> = out["sarif_skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["result_id"].as_str())
        .collect();
    assert_eq!(skipped, ["sarif-0-2", "sarif-0-3"]);
    assert_eq!(out["sarif_unreviewable"], 2);
    assert_eq!(out["incomplete"], true);
    assert!(
        stderr.contains("SARIF: 2 results became findings, 2 skipped (2 could not be reviewed"),
        "{stderr}"
    );
}

#[test]
fn unsupported_sarif_versions_and_nesting_bombs_fail_before_any_model_call() {
    let fx = Fixture::new();
    let old = SARIF.replace("\"2.1.0\"", "\"2.0.0\"");
    let (output, json) = fx.verify("old.sarif", &old);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("unsupported SARIF version"), "{stderr}");
    assert!(json.is_none());
    let bomb = format!(
        r#"{{"version":"2.1.0","runs":{}{}}}"#,
        "[".repeat(1000),
        "]".repeat(1000)
    );
    let (output, json) = fx.verify("bomb.sarif", &bomb);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("nested deeper than 64"), "{stderr}");
    assert!(json.is_none());
    assert_eq!(fx.call_count(), 0);
}

/// One result repeated `n` times at `src/app.py:3`, claiming critical
/// through vettalon's own property from a foreign tool.
fn repeated(n: usize) -> String {
    let result = r#"{"ruleId": "cmd", "level": "warning", "message": {"text": "os.system"},
      "properties": {"vettalon.severity": "critical", "tags": ["CWE-78"]},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"},
                                          "region": {"startLine": 3}}}]}"#;
    format!(
        r#"{{"version": "2.1.0", "runs": [{{"tool": {{"driver": {{"name": "scanner"}}}},
            "results": [{}]}}]}}"#,
        vec![result; n].join(",")
    )
}

/// M1: thousands of identical results cost one review, and a foreign
/// `vettalon.severity` does not buy extra refuter runs.
#[test]
fn identical_results_are_reviewed_once_at_their_own_severity() {
    let fx = Fixture::new();
    let (output, json) = fx.verify_with("dup.sarif", &repeated(5_000), &["--refuter-runs", "5"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let out = json.expect("verify.json written");
    assert_eq!(out["claim_ids"], serde_json::json!(["sarif-0-0"]));
    assert_eq!(out["sarif_duplicates"], 4_999);
    assert_eq!(out["sarif_skipped"][0]["reason"], "duplicate");
    assert_eq!(out["sarif_skipped"][0]["duplicate_of"], "sarif-0-0");
    assert_eq!(
        out["findings"][0]["severity"], "medium",
        "level, not vettalon.severity"
    );
    // Medium gets one refuter run whatever --refuter-runs says.
    assert_eq!(out["calls"], 1);
    assert_eq!(fx.call_count(), 1);
    assert_eq!(out["incomplete"], false);
    assert!(stderr.contains("4999 duplicates"), "{stderr}");
}

/// M1 (c): more findings than `--max-claims` is an error before any call.
#[test]
fn max_claims_is_enforced_before_any_model_call() {
    let fx = Fixture::new();
    let lines: Vec<String> = (1..=201).map(|i| format!("x{i} = {i}")).collect();
    std::fs::write(fx.repo.join("src/many.py"), lines.join("\n")).unwrap();
    let results: Vec<String> = (1..=201)
        .map(|i| {
            format!(
                r#"{{"ruleId": "r", "message": {{"text": "m"}}, "locations": [{{"physicalLocation":
                  {{"artifactLocation": {{"uri": "src/many.py"}}, "region": {{"startLine": {i}}}}}}}]}}"#
            )
        })
        .collect();
    let log = format!(
        r#"{{"version": "2.1.0", "runs": [{{"tool": {{"driver": {{"name": "t"}}}}, "results": [{}]}}]}}"#,
        results.join(",")
    );
    let (output, json) = fx.verify("many.sarif", &log);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("the input has 201 findings to review, more than --max-claims 200"),
        "{stderr}"
    );
    assert!(json.is_none());
    assert_eq!(fx.call_count(), 0);
    // The same limit for a claims file, with the flag lowered.
    let claims = r#"{"schema": "vettalon.claims/1", "claims": [
      {"id": "a", "file": "src/app.py", "line": 3, "title": "t"},
      {"id": "b", "file": "src/app.py", "line": 2, "title": "t"}]}"#;
    let (output, _) = fx.verify_with("claims.json", claims, &["--max-claims", "1"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--max-claims 1"), "{stderr}");
    assert_eq!(fx.call_count(), 0);
    // Raised, it runs.
    let (output, json) = fx.verify_with("claims.json", claims, &["--max-claims", "2"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(json.unwrap()["calls"], 2);
}

#[test]
fn joern_check_refuses_sarif_input() {
    let fx = Fixture::new();
    let input = fx.home.join("x.sarif");
    std::fs::write(&input, SARIF).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vettalon"))
        .env("VETTALON_HOME", &fx.home)
        .env("PATH", &fx.empty_path)
        .args(["--lang", "en", "joern", "check"])
        .arg(&fx.repo)
        .arg("--claims")
        .arg(&input)
        .arg("--out")
        .arg(fx.home.join("joern.json"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("SARIF input is read by `vettalon verify` only"),
        "{stderr}"
    );
}
