#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use vettalon::audit::{SubprocessLimits, run_bounded_subprocess};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    config: PathBuf,
}

async fn git(root: &Path, args: &[&str]) {
    let bin = vettalon::util::which_cli_for_scan("git", root).unwrap();
    let mut command = vec![
        "-c",
        "user.name=Scope Test",
        "-c",
        "user.email=scope@example.invalid",
        "-c",
        "commit.gpgsign=false",
    ];
    command.extend_from_slice(args);
    let out = run_bounded_subprocess(
        &bin,
        &command,
        root,
        &SubprocessLimits {
            timeout: std::time::Duration::from_secs(10),
            max_output_bytes: 4096,
        },
    )
    .await;
    assert_eq!(out.exit_code, Some(0), "{out:?}");
    assert!(out.cleanup_error.is_none());
}

impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        let home = temp.path().join("home");
        let bin = temp.path().join("bin");
        for path in [&root, &home, &bin] {
            std::fs::create_dir(path).unwrap();
        }
        let git_bin = vettalon::util::which_cli_for_scan("git", &root).unwrap();
        std::os::unix::fs::symlink(git_bin, bin.join("git")).unwrap();
        std::fs::create_dir(root.join("old")).unwrap();
        std::fs::create_dir(root.join("new")).unwrap();
        std::fs::write(root.join("old/a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(root.join("new/b.rs"), "fn b() {}\n").unwrap();
        git(&root, &["init", "-q"]).await;
        git(&root, &["add", "--all"]).await;
        git(&root, &["commit", "-qm", "base"]).await;
        git(&root, &["tag", "base"]).await;
        std::fs::write(root.join("new/b.rs"), "fn b() { changed(); }\n").unwrap();
        git(&root, &["add", "--all"]).await;
        git(&root, &["commit", "-qm", "head"]).await;
        let finder = temp.path().join("finder.sh");
        std::fs::write(&finder, "/bin/cat > /dev/null\nprintf '%s' '[]'\n").unwrap();
        let config = home.join("config.toml");
        std::fs::write(&config, format!("[[model]]\nid = 'mock'\nbackend = 'cli'\nfamily = 'test'\nroles = ['finder']\nprogram = '/bin/sh'\nargs = [{}]\nprompt_via = 'stdin'\nallow_agent_tools = true\n", serde_json::to_string(&finder).unwrap())).unwrap();
        let fixture = Self {
            _temp: temp,
            root,
            home,
            bin,
            config,
        };
        fixture.scanner_raw("[]");
        fixture
    }

    fn scan(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vettalon"))
            .env("VETTALON_HOME", &self.home)
            .env("PATH", &self.bin)
            .args(["--lang", "en", "scan"])
            .arg(&self.root)
            .arg("--config")
            .arg(&self.config)
            .args(["--no-prior", "--report"])
            .arg(self.home.join("out.json"))
            .args(args)
            .output()
            .unwrap()
    }

    fn report(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.home.join("out.json")).unwrap()).unwrap()
    }

    fn scanner(&self, file: &str) {
        self.scanner_raw(&serde_json::json!([{"File":file,"StartLine":1,"RuleID":"fixture","Description":"fixture secret"}]).to_string());
    }

    fn scanner_raw(&self, payload: &str) {
        let scanner = self.bin.join("gitleaks");
        std::fs::write(&scanner, format!("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n if [ \"$1\" = '--report-path' ]; then shift; printf '%s' '{payload}' > \"$1\"; exit 0; fi\n shift\ndone\nexit 1\n")).unwrap();
        std::fs::set_permissions(scanner, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[tokio::test]
async fn unknown_ref_exits_two_without_falling_back_or_writing_report() {
    let f = Fixture::new().await;
    let output = f.scan(&["--profile", "deep", "--diff-base", "unknown-ref"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fetch-depth: 0"),
        "{output:?}"
    );
    assert!(!f.home.join("out.json").exists());
}

#[tokio::test]
async fn invalid_refs_exit_two_and_quick_ignores_a_valid_ref_with_a_note() {
    let f = Fixture::new().await;
    for value in ["-x", "a b", "HEAD..main", "a\nb"] {
        let output = f.scan(&[&format!("--diff-base={value}")]);
        assert_eq!(output.status.code(), Some(2));
        assert!(!f.home.join("out.json").exists());
    }
    let full = f.scan(&[]);
    assert_eq!(full.status.code(), Some(0), "{full:?}");
    let mut baseline = f.report();
    assert!(baseline.get("scope").is_none());
    let quick = f.scan(&["--diff-base", "unknown-but-valid-ref"]);
    assert_eq!(quick.status.code(), Some(0), "{quick:?}");
    assert!(
        String::from_utf8_lossy(&quick.stderr).contains("--diff-base ignored with --profile quick")
    );
    let mut ignored = f.report();
    assert!(ignored.get("scope").is_none());
    // Compare the full JSON shape, excluding timestamps and scanner durations.
    baseline.as_object_mut().unwrap().remove("started_at");
    ignored.as_object_mut().unwrap().remove("started_at");
    for report in [&mut baseline, &mut ignored] {
        for engine in report["engines_run"].as_array_mut().unwrap() {
            engine.as_object_mut().unwrap().remove("duration_ms");
        }
    }
    assert_eq!(baseline, ignored);
}

#[tokio::test]
async fn scanner_outside_diff_does_not_fail_cli_gate_but_in_scope_and_full_scan_do() {
    let f = Fixture::new().await;
    f.scanner("old/a.rs");
    let diff = f.scan(&[
        "--profile",
        "deep",
        "--diff-base",
        "base",
        "--gate",
        "severity>=high count>0",
        "--fail-on",
        "high",
    ]);
    assert_eq!(diff.status.code(), Some(0), "{diff:?}");
    let report = f.report();
    assert_eq!(report["scope"]["mode"], "diff");
    assert_eq!(report["scope"]["base"], "base");
    assert_eq!(report["scope"]["changed_files"], 1);
    assert_eq!(report["run_status"], "partial_by_design");
    assert_eq!(report["summary"]["policy"][0]["count"], 0);
    assert!(
        report["findings"][0]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["detail"] == "outside_diff_scope")
    );
    let full = f.scan(&["--gate", "severity>=high count>0"]);
    assert_eq!(full.status.code(), Some(1), "{full:?}");
    assert!(f.report().get("scope").is_none());
    f.scanner("new/b.rs");
    let diff = f.scan(&[
        "--profile",
        "deep",
        "--diff-base",
        "base",
        "--gate",
        "severity>=high count>0",
    ]);
    assert_eq!(diff.status.code(), Some(1), "{diff:?}");
    assert_eq!(f.report()["summary"]["policy"][0]["count"], 1);
}

#[tokio::test]
async fn files_changed_by_finder_are_in_scope_for_final_cli_gates() {
    let f = Fixture::new().await;
    f.scanner("old/a.rs");
    let target = f.root.join("old/a.rs");
    let quoted_target = format!("'{}'", target.display().to_string().replace('\'', "'\\''"));
    std::fs::write(
        f._temp.path().join("finder.sh"),
        format!("/bin/cat > /dev/null\nprintf '%s' 'fn changed() {{}}' > {quoted_target}\nprintf '%s' '[]'\n"),
    ).unwrap();
    let output = f.scan(&[
        "--profile",
        "deep",
        "--diff-base",
        "base",
        "--gate",
        "severity>=high count>0",
        "--fail-on",
        "high",
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = f.report();
    assert_eq!(report["scope"]["changed_files"], 2);
    assert_eq!(report["scope"]["changed_during_scan"], 1);
    assert_eq!(report["summary"]["policy"][0]["count"], 1);
    assert!(
        !report["findings"][0]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["detail"] == "outside_diff_scope")
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("1 files changed during the scan were treated as in scope")
            .count(),
        1
    );
    assert!(
        report["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["module_path"] == "old" && m["status"] == "out_of_scope")
    );
}

#[tokio::test]
async fn moved_revisions_or_failed_recompute_exit_two_without_report() {
    for scenario in ["HEAD moved", "base moved", "recompute failed"] {
        let f = Fixture::new().await;
        let root = format!("'{}'", f.root.display().to_string().replace('\'', "'\\''"));
        let mutation = match scenario {
            "HEAD moved" => format!("git -C {root} update-ref HEAD base"),
            "base moved" => format!("git -C {root} update-ref refs/tags/base HEAD"),
            _ => format!("printf '%s' '' > {root}/.git/info/grafts"),
        };
        std::fs::write(
            f._temp.path().join("finder.sh"),
            format!("/bin/cat > /dev/null\n{mutation}\nprintf '%s' '[]'\n"),
        )
        .unwrap();
        let output = f.scan(&[
            "--profile",
            "deep",
            "--diff-base",
            "base",
            "--allow-incomplete",
        ]);
        assert_eq!(output.status.code(), Some(2), "{scenario}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "diff scope changed during the scan ({scenario}); rerun"
            )),
            "{stderr}"
        );
        assert!(!f.home.join("out.json").exists());
    }
}

#[tokio::test]
async fn grafts_exit_two_even_with_allow_incomplete_and_write_no_report() {
    let f = Fixture::new().await;
    std::fs::write(f.root.join(".git/info/grafts"), "").unwrap();
    let output = f.scan(&[
        "--profile",
        "deep",
        "--diff-base",
        "base",
        "--allow-incomplete",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("info/grafts"));
    assert!(!f.home.join("out.json").exists());
}

fn create_non_utf8_file_if_supported(path: &Path) -> bool {
    // APFS and some sandboxes reject non-UTF-8 names, even in a writable directory.
    match std::fs::write(path, "unsafe\n") {
        Ok(()) => true,
        Err(error)
            if error.kind() == std::io::ErrorKind::InvalidInput
                || matches!(error.raw_os_error(), Some(libc::EILSEQ | libc::EPERM)) =>
        {
            false
        }
        Err(error) => panic!("unexpected non-UTF-8 filename probe error: {error}"),
    }
}

#[tokio::test]
async fn unsafe_and_non_utf8_paths_exit_two_without_echoing_names_or_writing_report() {
    use std::os::unix::ffi::OsStrExt;
    let f = Fixture::new().await;
    std::fs::write(f.root.join("private-name\n.rs"), "unsafe\n").unwrap();
    let mut names = vec!["private-name"];
    if create_non_utf8_file_if_supported(
        &f.root
            .join(std::ffi::OsStr::from_bytes(b"secret-name-\xff.rs")),
    ) {
        names.push("secret-name");
    }
    let output = f.scan(&[
        "--profile",
        "deep",
        "--diff-base",
        "base",
        "--allow-incomplete",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "{} invalid repo-relative changed paths",
            names.len()
        )),
        "{stderr}"
    );
    for raw_name in names {
        assert!(!stdout.contains(raw_name));
        assert!(!stderr.contains(raw_name));
    }
    assert!(!f.home.join("out.json").exists());
}
