//! Real stdio transport and human-only triage entry points.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};
use vettalon::audit::schema::{
    CURRENT_SCHEMA_VERSION, Finding, FindingKind, GatePolicy, Severity, Summary,
};

struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    report: PathBuf,
    finding: String,
}

impl Fixture {
    fn new() -> Self {
        // Output helpers reject symlink parents, including macOS /var.
        let root = std::env::temp_dir().canonicalize().unwrap();
        let temp = tempfile::tempdir_in(root).unwrap();
        let repo = temp.path().join("repo");
        let home = temp.path().join("home");
        std::fs::create_dir(&repo).unwrap();
        std::fs::create_dir(&home).unwrap();
        let findings: Vec<_> = ["a.py", "b.py"]
            .into_iter()
            .map(|file| {
                Finding::candidate(
                    "semgrep",
                    FindingKind::StaticAnalysis,
                    Severity::High,
                    "Fixture finding",
                    file,
                    Some(1),
                    "danger(value)",
                    "fixture-rule",
                    vec![],
                )
            })
            .collect();
        let finding = findings[0].id.clone();
        let report = temp.path().join("report.json");
        let value = json!({
            "schema_version": CURRENT_SCHEMA_VERSION,
            "repo": repo,
            "started_at": "2026-11-02T00:00:00Z",
            "profile": {"mode": "quick", "intake": null},
            "engines_run": [], "engines_missing": [],
            "summary": Summary::from_findings(&findings, 0, 0, GatePolicy::default(), &[]),
            "findings": findings
        });
        std::fs::write(&report, value.to_string()).unwrap();
        vettalon::audit::load_report_for_delivery(&report).unwrap();
        Self {
            _temp: temp,
            repo,
            home,
            report,
            finding,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vettalon"));
        command.env("VETTALON_HOME", &self.home);
        command.args(["--lang", "en"]);
        command
    }

    fn mcp(&self, with_report: bool, messages: &[Value]) -> (Output, Vec<Value>) {
        let mut command = self.command();
        command.args(["mcp", "--repo"]).arg(&self.repo);
        if with_report {
            command.arg("--report").arg(&self.report);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        for message in messages {
            writeln!(input, "{message}").unwrap();
        }
        drop(input);
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = std::str::from_utf8(&output.stdout).unwrap();
        let replies = stdout
            .lines()
            .map(|line| serde_json::from_str(line).expect("stdout contains only JSON lines"))
            .collect();
        (output, replies)
    }

    fn triage(&self, finding: &str, out: &std::path::Path) -> Output {
        self.command()
            .arg("triage")
            .arg("--report")
            .arg(&self.report)
            .args(["--finding", finding, "--decision", "confirmed"])
            .args(["--reason", "Human fixture verification", "--out"])
            .arg(out)
            .output()
            .unwrap()
    }
}

fn initialize() -> Value {
    json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
        "protocolVersion":"2025-11-25", "capabilities":{},
        "clientInfo":{"name":"fixture", "version":"1"}
    }})
}

#[test]
fn stdio_initialize_list_call_and_eof_are_protocol_only() {
    let fixture = Fixture::new();
    let before = std::fs::read(&fixture.report).unwrap();
    let (_, replies) = fixture.mcp(
        true,
        &[
            initialize(),
            json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0", "id":2, "method":"tools/list"}),
            json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{
                "name":"vettalon_report_summary", "arguments":{}
            }}),
        ],
    );
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(replies[1]["result"]["tools"].as_array().unwrap().len(), 7);
    assert_ne!(replies[2]["result"]["isError"], true);
    let payload: Value =
        serde_json::from_str(replies[2]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["untrusted_data"], true);
    assert_eq!(std::fs::read(&fixture.report).unwrap(), before);
}

#[test]
fn no_saved_report_still_starts_and_requests_scan_save() {
    let fixture = Fixture::new();
    let (_, replies) = fixture.mcp(
        false,
        &[
            initialize(),
            json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{
                "name":"vettalon_report_summary", "arguments":{}
            }}),
        ],
    );
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[1]["result"]["isError"], true);
    let text = replies[1]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("scan --save"), "{text}");
    let payload: Value = serde_json::from_str(text).unwrap();
    assert_eq!(payload["untrusted_data"], true);
}

#[test]
fn triage_writes_new_valid_report_and_preserves_input() {
    let fixture = Fixture::new();
    let before = std::fs::read(&fixture.report).unwrap();
    let out = fixture.home.join("triaged.json");
    let result = triage_pty(&fixture, &out, &fixture.finding);
    let Some(result) = result else { return };
    assert!(result.status.success(), "{result:?}");
    let report = vettalon::audit::load_report_for_delivery(&out).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == fixture.finding)
        .unwrap();
    assert_eq!(
        finding.status,
        vettalon::audit::schema::FindingStatus::Confirmed
    );
    assert_eq!(std::fs::read(&fixture.report).unwrap(), before);
    let written = std::fs::read(&out).unwrap();
    assert!(!fixture.triage(&fixture.finding, &out).status.success());
    assert_eq!(std::fs::read(&out).unwrap(), written);
    assert_eq!(std::fs::read(&fixture.report).unwrap(), before);
}

#[test]
fn triage_refuses_missing_and_ambiguous_findings_and_input_overwrite() {
    let fixture = Fixture::new();
    let before = std::fs::read(&fixture.report).unwrap();
    for finding in ["missing", "semgrep-"] {
        let out = fixture.home.join("refused.json");
        let result = fixture.triage(finding, &out);
        assert!(!result.status.success(), "{result:?}");
        assert!(!out.exists());
        assert_eq!(std::fs::read(&fixture.report).unwrap(), before);
    }
    assert!(
        !fixture
            .triage(&fixture.finding, &fixture.report)
            .status
            .success()
    );
    assert_eq!(std::fs::read(&fixture.report).unwrap(), before);
}

#[test]
fn triage_non_tty_refused_without_output() {
    let f = Fixture::new();
    let out = f.home.join("refused.json");
    let result = f.triage(&f.finding, &out);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("person at a terminal"));
    assert!(!out.exists());
}

#[cfg(unix)]
fn triage_pty(f: &Fixture, out: &std::path::Path, answer: &str) -> Option<Output> {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 unavailable; skipping pty check");
        return None;
    }
    triage_pty_streams(f, out, answer, "both")
}

#[cfg(unix)]
fn triage_pty_streams(
    f: &Fixture,
    out: &std::path::Path,
    answer: &str,
    streams: &str,
) -> Option<Output> {
    let script = r#"
import os, pty, select, subprocess, sys, time
master, slave = pty.openpty()
env = os.environ.copy()
env['VETTALON_HOME'] = sys.argv[2]
p = subprocess.Popen([sys.argv[1], '--lang', 'en', 'triage', '--report', sys.argv[3],
    '--finding', sys.argv[4], '--decision', 'confirmed', '--reason', 'Human verification',
    '--out', sys.argv[5]], stdin=(subprocess.DEVNULL if sys.argv[7] == 'stdin_pipe' else slave),
    stdout=(subprocess.DEVNULL if sys.argv[7] == 'stdout_pipe' else slave), stderr=slave, env=env)
os.close(slave)
data = b''
sent = False
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    if select.select([master], [], [], 0.1)[0]:
        try:
            chunk = os.read(master, 65536)
        except OSError:
            break
        if not chunk: break
        data += chunk
        if b'Type the full finding id' in data and not sent:
            os.write(master, (sys.argv[6] + '\n').encode())
            sent = True
    if p.poll() is not None: break
try:
    p.wait(timeout=2)
except subprocess.TimeoutExpired:
    p.kill()
    p.wait()
    raise RuntimeError('triage pty timed out: ' + repr(data))
os.close(master)
sys.stdout.buffer.write(data)
sys.exit(p.returncode)
"#;
    Some(
        Command::new("python3")
            .args(["-c", script])
            .arg(env!("CARGO_BIN_EXE_vettalon"))
            .arg(&f.home)
            .arg(&f.report)
            .arg(&f.finding)
            .arg(out)
            .arg(answer)
            .arg(streams)
            .output()
            .unwrap(),
    )
}

#[cfg(not(unix))]
fn triage_pty(_: &Fixture, _: &std::path::Path, _: &str) -> Option<Output> {
    None
}

#[cfg(unix)]
#[test]
fn triage_wrong_id_aborts_at_terminal() {
    let f = Fixture::new();
    for answer in [
        "wrong",
        &f.finding[..f.finding.len() - 1],
        "",
        &format!("{} ", f.finding),
    ] {
        let out = f.home.join("wrong.json");
        let Some(result) = triage_pty(&f, &out, answer) else {
            return;
        };
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(!out.exists());
    }
}

#[cfg(unix)]
#[test]
fn triage_requires_both_terminal_streams() {
    let f = Fixture::new();
    if Command::new("python3").arg("--version").output().is_err() {
        return;
    }
    for mode in ["stdin_pipe", "stdout_pipe"] {
        let out = f.home.join("refused-stream.json");
        let result = triage_pty_streams(&f, &out, &f.finding, mode).unwrap();
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(String::from_utf8_lossy(&result.stdout).contains("person at a terminal"));
        assert!(!out.exists());
    }
}

#[test]
fn triage_proposals_is_noninteractive_and_does_not_create_state() {
    let f = Fixture::new();
    let out = f
        .command()
        .args(["triage", "--report"])
        .arg(&f.report)
        .arg("--proposals")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(!f.home.join("mcp").exists());
}

#[cfg(unix)]
#[test]
fn triage_terminal_escapes_untrusted_title() {
    let f = Fixture::new();
    let mut report: Value = serde_json::from_slice(&std::fs::read(&f.report).unwrap()).unwrap();
    report["findings"][0]["title"] = "\u{1b}[2J\u{1b}[Hfake\rtitle\n".into();
    std::fs::write(&f.report, report.to_string()).unwrap();
    let Some(result) = triage_pty(&f, &f.home.join("safe-display.json"), &f.finding) else {
        return;
    };
    assert!(result.status.success(), "{result:?}");
    let text = String::from_utf8_lossy(&result.stdout);
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("\\u{1b}[2J"), "{text}");
    for field in ["Finding:", "Current status:", "Decision:"] {
        assert!(text.contains(field));
    }
}
