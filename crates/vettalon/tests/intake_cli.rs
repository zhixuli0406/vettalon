#![cfg(unix)]
//! `vettalon intake` end to end. The verifier is a shell script that prints a
//! fixed refutation and records every prompt it receives; no real model is
//! called.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const REFUTED: &str = r#"{"verdict":"refuted","reason":"not reachable","blockers":[],"validation_plan":{"local":null,"deployment":null},"refute_basis":"unreachable"}"#;

const MARKER: &str = "IGNORE-PREVIOUS-INSTRUCTIONS-XYZ";

fn ghsa_report(summary: &str, details: &str, poc: &str) -> String {
    format!(
        "## Summary\n{summary}\n\n## Details\n{details}\n\n## PoC\n{poc}\n\n## Impact\nCommand execution.\n\nCWE-78\n"
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    repo: PathBuf,
    home: PathBuf,
    /// The child's whole `PATH`: holds only a `git` link.
    bin: PathBuf,
    calls: PathBuf,
    prompts: PathBuf,
}

struct Run {
    output: Output,
    out_path: PathBuf,
}

impl Run {
    fn code(&self) -> Option<i32> {
        self.output.status.code()
    }
    fn stdout(&self) -> Vec<u8> {
        self.output.stdout.clone()
    }
    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }
    fn json(&self) -> serde_json::Value {
        let bytes = std::fs::read(&self.out_path)
            .unwrap_or_else(|e| panic!("intake.json missing: {e}\n{}", self.stderr()));
        serde_json::from_slice(&bytes).unwrap()
    }
}

/// Fixture-only Git (setup, not the code under test): isolated from the
/// user's and system config.
fn git(git_bin: &str, repo: &std::path::Path, args: &[&str]) {
    let out = Command::new(git_bin)
        .args([
            "-c",
            "user.name=Intake Test",
            "-c",
            "user.email=intake@example.invalid",
        ])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

/// Report-derived locations must be tracked by Git, so every fixture is a
/// real repository. `None` (the test is skipped) when git is not installed.
macro_rules! fixture {
    () => {
        match Fixture::new() {
            Some(fx) => fx,
            None => {
                eprintln!("skipping: git is not installed; intake needs a Git index");
                return;
            }
        }
    };
}

impl Fixture {
    fn new() -> Option<Self> {
        let dir = tempfile::tempdir().unwrap();
        // macOS /var is a symlink and output preflight refuses symlinked parents.
        let root = dir.path().canonicalize().unwrap();
        let repo = root.join("repo");
        let home = root.join("home");
        let bin = root.join("bin");
        let work = root.join("work");
        for d in [&repo, &home, &bin, &work] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir(repo.join("src")).unwrap();
        std::fs::write(
            repo.join("src/app.py"),
            "import os\nq = input()\nos.system(q)\n",
        )
        .unwrap();
        let git_bin = vettalon::util::which_cli_for_scan("git", &repo)?;
        git(&git_bin, &repo, &["init", "-q"]);
        git(&git_bin, &repo, &["add", "--all"]);
        git(&git_bin, &repo, &["commit", "-qm", "fixture"]);
        // `which_cli` does not search /usr/bin; give the binary under test
        // this git and nothing else.
        std::os::unix::fs::symlink(&git_bin, bin.join("git")).unwrap();
        let script = root.join("verifier.sh");
        std::fs::write(
            &script,
            format!(
                "/bin/cat >> \"$0.prompts\"\nprintf '\\n=====END-PROMPT=====\\n' >> \"$0.prompts\"\nprintf 'called\\n' >> \"$0.called\"\nprintf '%s' '{REFUTED}'\n"
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
        Some(Self {
            calls: script.with_extension("sh.called"),
            prompts: script.with_extension("sh.prompts"),
            _dir: dir,
            root,
            repo,
            home,
            bin,
        })
    }

    fn work(&self, name: &str) -> PathBuf {
        self.root.join("work").join(name)
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vettalon"));
        cmd.env("VETTALON_HOME", &self.home)
            .env("PATH", &self.bin)
            .args(["--lang", "en", "intake"])
            .arg(&self.repo);
        cmd
    }

    /// Run with the report on stdin (`--input -`).
    fn intake_stdin(&self, report: &str, extra: &[&str]) -> Run {
        let out_path = self.work("intake.json");
        let mut cmd = self.command();
        cmd.args(["--input", "-", "--out"]).arg(&out_path);
        if !extra.contains(&"--claims-only") {
            cmd.args(["--verifier", "checker", "--config"])
                .arg(self.home.join("config.toml"))
                .args(["--refuter-runs", "1"]);
        }
        cmd.args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(report.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        Run { output, out_path }
    }

    fn call_count(&self) -> usize {
        std::fs::read_to_string(&self.calls)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    fn prompts(&self) -> String {
        std::fs::read_to_string(&self.prompts).unwrap_or_default()
    }
}

#[test]
fn stdin_report_is_located_and_reviewed() {
    let fx = fixture!();
    let report = ghsa_report(
        "Command injection in the app",
        "The handler in `src/app.py:2` passes user input to a shell.",
        "Send a crafted value.",
    );
    let run = fx.intake_stdin(&report, &[]);
    assert_eq!(run.code(), Some(0), "{}", run.stderr());
    let out = run.json();
    assert_eq!(out["schema"], "vettalon.intake/1");
    assert_eq!(out["triage"]["located"], true);
    assert!(fx.call_count() >= 1, "verifier was not called");
}

#[test]
fn claims_only_writes_claims_and_never_calls_the_verifier() {
    let fx = fixture!();
    let report = ghsa_report("Injection", "See src/app.py:3.", "n/a");
    let claims_path = fx.work("c.json");
    let run = fx.intake_stdin(
        &report,
        &[
            "--claims-only",
            "--claims-out",
            claims_path.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code(), Some(0), "{}", run.stderr());
    let claims: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&claims_path).expect("claims written")).unwrap();
    assert_eq!(claims["schema"], "vettalon.claims/1");
    assert_eq!(fx.call_count(), 0);
}

#[test]
fn report_without_a_location_exits_1_without_a_model_call() {
    let fx = fixture!();
    let report = ghsa_report(
        "Something is wrong",
        "There is a problem somewhere in the program.",
        "Run it.",
    );
    let run = fx.intake_stdin(&report, &[]);
    assert_eq!(run.code(), Some(1), "{}", run.stderr());
    assert_eq!(fx.call_count(), 0);
    assert_eq!(run.json()["triage"]["located"], false);
}

#[test]
fn report_text_never_reaches_a_prompt_or_the_result() {
    let fx = fixture!();
    let report = ghsa_report(
        "Command injection",
        &format!("See `src/app.py:3`. {MARKER}"),
        &format!("echo {MARKER}"),
    );
    let run = fx.intake_stdin(&report, &[]);
    assert_eq!(run.code(), Some(0), "{}", run.stderr());
    assert!(fx.call_count() >= 1);
    let prompts = fx.prompts();
    assert!(!prompts.is_empty(), "no prompt recorded");
    assert!(!prompts.contains(MARKER), "marker reached a prompt");
    let raw = std::fs::read_to_string(&run.out_path).unwrap();
    assert!(!raw.contains(MARKER), "marker reached intake.json");
}

#[test]
fn existing_out_file_is_refused_and_left_unchanged() {
    let fx = fixture!();
    let out_path = fx.work("intake.json");
    std::fs::write(&out_path, "precious").unwrap();
    let report = ghsa_report("Injection", "See src/app.py:3.", "n/a");
    let run = fx.intake_stdin(&report, &[]);
    assert_eq!(run.code(), Some(2), "{}", run.stderr());
    assert_eq!(std::fs::read_to_string(&out_path).unwrap(), "precious");
    assert_eq!(fx.call_count(), 0);
}

#[test]
fn target_for_an_unsupported_class_runs_no_container() {
    let fx = fixture!();
    let target = fx.work("t.json");
    std::fs::write(
        &target,
        r#"{"file":"src/app.py","function":"run","args":[{"kind":"payload"}]}"#,
    )
    .unwrap();
    let receipt = fx.work("r.json");
    let report = ghsa_report("XSS", "See src/app.py:3.", "n/a");
    let run = fx.intake_stdin(
        &report,
        &[
            "--cwe",
            "CWE-79",
            "--target",
            target.to_str().unwrap(),
            "--receipt-out",
            receipt.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code(), Some(0), "{}", run.stderr());
    assert_eq!(run.json()["reproduction"]["status"], "unsupported_class");
    assert!(!receipt.exists(), "receipt must not be written");
}

#[test]
fn terminal_escapes_in_the_report_do_not_reach_stdout() {
    let fx = fixture!();
    let report = ghsa_report(
        "Bad \x1b[2J screen \u{202e}gnp.exe",
        "See `src/app.py:3`.",
        "n/a",
    );
    let run = fx.intake_stdin(&report, &[]);
    assert_eq!(run.code(), Some(0), "{}", run.stderr());
    let stdout = run.stdout();
    assert!(!stdout.is_empty(), "no summary printed");
    assert!(!stdout.contains(&0x1b), "raw ESC in stdout");
    let text = String::from_utf8_lossy(&stdout);
    assert!(!text.contains('\u{202e}'), "U+202E in stdout");
}

/// M1: `.git` internals are refused (any case), from the report and from
/// `--location`; nothing of them reaches a prompt.
#[test]
fn git_metadata_is_never_a_location() {
    let fx = fixture!();
    let report = ghsa_report(
        "Leak",
        "See .git/config:1 and .GIT/config:1 and sub/.git/HEAD:1.",
        "n/a",
    );
    let run = fx.intake_stdin(&report, &[]);
    assert_eq!(run.code(), Some(1), "{}", run.stderr());
    assert_eq!(fx.call_count(), 0);
    let out = run.json();
    assert_eq!(out["triage"]["located"], false);
    let locs = out["extraction"]["locations"].as_array().unwrap();
    assert_eq!(locs.len(), 3, "{locs:?}");
    for l in locs {
        assert_eq!(l["reason"], "git_metadata", "{l}");
        assert!(l["file"].is_null(), "{l}");
    }

    for loc in [".git/config:1", ".GIT/config:1", "sub/.git/HEAD:1"] {
        let fx = fixture!();
        let run = fx.intake_stdin(&report, &["--claims-only", "--location", loc]);
        assert_eq!(run.code(), Some(1), "{loc}: {}", run.stderr());
        let out = run.json();
        assert_eq!(
            out["extraction"]["locations"][0]["reason"], "git_metadata",
            "{loc}"
        );
        assert!(out["claims"].is_null());
    }
}

/// M1: an existing file Git does not track (here git-ignored) is refused
/// when the report names it; a tracked one is accepted.
#[test]
fn report_locations_must_be_tracked_by_git() {
    let fx = fixture!();
    std::fs::write(fx.repo.join(".gitignore"), "local.py\n").unwrap();
    std::fs::write(fx.repo.join("local.py"), "TOKEN = 'x'\n").unwrap();
    let report = ghsa_report("Leak", "See local.py:1 and src/app.py:3.", "n/a");
    let run = fx.intake_stdin(&report, &["--claims-only"]);
    assert_eq!(run.code(), Some(0), "{}", run.stderr());
    let out = run.json();
    assert_eq!(out["extraction"]["tracked_check"], "git_index");
    let locs = out["extraction"]["locations"].as_array().unwrap();
    assert_eq!(locs.len(), 2, "{locs:?}");
    // Rejected records carry no token text, only its digest.
    let local = locs.iter().find(|l| l["accepted"] == false).unwrap();
    assert_eq!(local["reason"], "untracked");
    assert!(local["file"].is_null());
    assert!(local.get("token").is_none(), "{local}");
    assert_eq!(local["token_sha256"].as_str().unwrap().len(), 64);
    let app = locs.iter().find(|l| l["accepted"] == true).unwrap();
    assert_eq!(app["token"], "src/app.py:3");
    assert!(app.get("token_sha256").is_none(), "{app}");
    assert_eq!(out["claims"]["claims"][0]["file"], "src/app.py");
}

/// L3: `--trace` is preflighted with the other outputs and is a new file.
#[test]
fn trace_is_preflighted_and_written_as_a_new_private_file() {
    use std::os::unix::fs::PermissionsExt;
    let report = ghsa_report("Injection", "See src/app.py:3.", "n/a");

    let fx = fixture!();
    let same = fx.work("intake.json");
    let run = fx.intake_stdin(&report, &["--trace", same.to_str().unwrap()]);
    assert_eq!(run.code(), Some(2), "{}", run.stderr());
    assert!(
        run.stderr().contains("must be different files"),
        "{}",
        run.stderr()
    );
    assert!(!same.exists());
    assert_eq!(fx.call_count(), 0);

    let fx = fixture!();
    let trace = fx.work("trace.jsonl");
    std::fs::write(&trace, "precious").unwrap();
    let run = fx.intake_stdin(&report, &["--trace", trace.to_str().unwrap()]);
    assert_eq!(run.code(), Some(2), "{}", run.stderr());
    assert_eq!(std::fs::read_to_string(&trace).unwrap(), "precious");
    assert!(!fx.work("intake.json").exists());
    assert_eq!(fx.call_count(), 0);

    let fx = fixture!();
    let trace = fx.work("trace.jsonl");
    let run = fx.intake_stdin(&report, &["--trace", trace.to_str().unwrap()]);
    assert_eq!(run.code(), Some(0), "{}", run.stderr());
    let meta = std::fs::symlink_metadata(&trace).expect("trace written");
    assert!(meta.file_type().is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}
