//! PR scope resolved through intake's restricted Git metadata and runner.
use std::collections::BTreeSet;
use std::path::Path;

use super::ai_audit::ModuleTarget;
use super::scanners::{SubprocessLimits, run_bounded_subprocess};
use super::schema::{DiffScope, DiffScopeMode, EvidenceItem, EvidenceKind, Finding, FindingKind};

/// Conservative revision syntax. Validate before even checking Git metadata.
pub fn validate_ref(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 200
        || value.starts_with('-')
        || value.contains("..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/@~^-".contains(&b))
    {
        return Err("expected a nonempty Git ref of at most 200 ASCII characters (letters, digits, ._/@~^-); no leading '-', whitespace, controls or '..' ranges".into());
    }
    Ok(value.to_owned())
}

#[derive(Debug)]
pub(super) struct DiffSelection {
    pub scope: DiffScope,
    pub changed: BTreeSet<String>,
    pub tracked_dependencies: BTreeSet<String>,
}

impl DiffSelection {
    /// Preserve both snapshots' scope; module selection still describes the start.
    pub fn reconcile(&mut self, final_selection: Self) -> Result<(), String> {
        if self.scope.head != final_selection.scope.head {
            return Err("diff scope changed during the scan (HEAD moved); rerun".into());
        }
        if self.scope.base_oid != final_selection.scope.base_oid {
            return Err("diff scope changed during the scan (base moved); rerun".into());
        }
        if self.scope.merge_base != final_selection.scope.merge_base {
            return Err("diff scope changed during the scan (merge-base changed); rerun".into());
        }
        self.scope.changed_during_scan = final_selection.changed.difference(&self.changed).count();
        self.changed.extend(final_selection.changed);
        self.scope.changed_files = self.changed.len();
        self.scope.worktree_changes = final_selection.scope.worktree_changes;
        self.scope.untracked = final_selection.scope.untracked;
        // A dependency untracked in either snapshot must remain in scope.
        self.tracked_dependencies
            .retain(|path| final_selection.tracked_dependencies.contains(path));
        Ok(())
    }

    pub fn contains_module(&self, module: &ModuleTarget) -> bool {
        module.files.iter().any(|file| self.changed.contains(file))
    }

    pub fn annotate_findings(&self, findings: &mut [Finding]) {
        for finding in findings {
            // Scope evidence is derived from this selection, never inherited.
            finding.evidence.retain(|e| {
                !(e.kind == EvidenceKind::ScopeNote
                    && e.source == "diff_scope"
                    && e.detail == "outside_diff_scope")
            });
            if !self.contains_finding(finding) {
                finding.evidence.push(EvidenceItem {
                    kind: EvidenceKind::ScopeNote,
                    source: "diff_scope".into(),
                    detail: "outside_diff_scope".into(),
                    recorded_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    fn contains_finding(&self, finding: &Finding) -> bool {
        if !is_scanner(finding) {
            return true;
        }
        // Workspace manifests can affect a lockfile elsewhere in the tree.
        // Conservatively include all dependency advisories on such changes.
        if (finding.kind == FindingKind::DependencyVulnerability
            || finding.source_engine == "cargo-audit")
            && (self.changed.iter().any(|path| is_dependency_file(path))
                || scope_path(finding).is_none_or(|path| !self.tracked_dependencies.contains(path)))
        {
            return true;
        }
        scope_path(finding).is_none_or(|path| self.changed.contains(path))
    }
}

fn is_scanner(finding: &Finding) -> bool {
    matches!(
        finding.source_engine.as_str(),
        "semgrep" | "gitleaks" | "cargo-audit" | "osv-scanner"
    )
}

fn is_dependency_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "Cargo.toml"
            | "Cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "bun.lock"
            | "bun.lockb"
            | "go.mod"
            | "go.sum"
            | "Pipfile"
            | "Pipfile.lock"
            | "pyproject.toml"
            | "poetry.lock"
            | "uv.lock"
            | "Gemfile"
            | "Gemfile.lock"
            | "composer.json"
            | "composer.lock"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "gradle.lockfile"
            | "packages.lock.json"
            | "packages.config"
    ) || (name.starts_with("requirements") && name.ends_with(".txt"))
}

/// Preserve finding identity: this path is used only to decide scope.
/// Semgrep and gitleaks already supply paths. Cargo-audit adds a package /
/// version suffix. OSV is disabled today; only plain known manifests are
/// interpretable for imported OSV findings. Unknown shapes stay in scope.
fn scope_path(finding: &Finding) -> Option<&str> {
    let mut path = finding.file.as_str();
    while let Some(relative) = path.strip_prefix("./") {
        path = relative;
    }
    if finding.source_engine == "cargo-audit" {
        if let Some((file, package)) = path.rsplit_once(" (") {
            let package = package.strip_suffix(')')?;
            let (name, version) = package.split_once(' ')?;
            if name.is_empty()
                || version.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || !version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            {
                return None;
            }
            path = file;
        }
        if path.rsplit('/').next() != Some("Cargo.lock") {
            return None;
        }
    } else if finding.kind == FindingKind::DependencyVulnerability && !is_dependency_file(path) {
        return None;
    }
    (!path.contains('\u{fffd}') && vettalon_contract::safe_path::SafeRepoPath::parse(path).is_ok())
        .then_some(path)
}

/// Shared by severity buckets and policy gates, including saved-report review.
pub(super) fn outside_diff_scope(finding: &Finding) -> bool {
    is_scanner(finding)
        && finding.evidence.iter().any(|e| {
            e.kind == EvidenceKind::ScopeNote
                && e.source == "diff_scope"
                && e.detail == "outside_diff_scope"
        })
}

fn parse_paths(output: &str) -> (BTreeSet<String>, usize) {
    let mut paths = BTreeSet::new();
    let mut invalid = 0;
    for path in output.split_terminator('\0') {
        // The runner captures UTF-8 lossily; reject replacement characters so
        // undecodable names cannot alias a different source path.
        if !path.contains('\u{fffd}')
            && vettalon_contract::safe_path::SafeRepoPath::parse(path).is_ok()
        {
            paths.insert(path.to_owned());
        } else {
            invalid += 1;
        }
    }
    (paths, invalid)
}

async fn git_read(git: &str, git_dir: &Path, root: &Path, args: &[&str]) -> Result<String, String> {
    let dir = format!("--git-dir={}", git_dir.display());
    let mut command = vec!["--no-pager", "--no-replace-objects", dir.as_str()];
    command.extend_from_slice(args);
    let out = run_bounded_subprocess(
        git,
        &command,
        root,
        &SubprocessLimits {
            timeout: std::time::Duration::from_secs(30),
            max_output_bytes: 4 * 1024 * 1024,
        },
    )
    .await;
    if out.exit_code != Some(0)
        || out.timed_out
        || out.stdout_truncated
        || out.spawn_error.is_some()
        || out.cleanup_error.is_some()
    {
        // Avoid echoing arbitrary Git stderr, ref names or filenames to a terminal.
        return Err(
            "Git read failed, timed out, exceeded its output cap or could not be cleaned up".into(),
        );
    }
    Ok(out.stdout)
}

fn parse_changed_paths(output: &str) -> Result<BTreeSet<String>, String> {
    if !output.is_empty() && !output.ends_with('\0') {
        return Err("Git returned an unterminated changed-file list".into());
    }
    let (paths, invalid) = parse_paths(output);
    if invalid != 0 {
        return Err(format!(
            "diff scope refused: {invalid} invalid repo-relative changed paths"
        ));
    }
    Ok(paths)
}

fn parse_oid(output: &str) -> Result<String, String> {
    let oid = output.trim();
    if ![40, 64].contains(&oid.len()) || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Git returned an invalid commit OID".into());
    }
    Ok(oid.into())
}

pub(super) async fn compute(root: &Path, base: &str) -> Result<DiffSelection, String> {
    validate_ref(base)?;
    let (git, git_dir) = super::intake::prepare_readonly_git(root).await?;
    // Even an empty file or dangling symlink must not silently alter ancestry.
    match std::fs::symlink_metadata(git_dir.join("info/grafts")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => {
            return Err("diff scope refused: Git info/grafts exists or cannot be inspected".into());
        }
    }
    let head = parse_oid(
        &git_read(
            &git,
            &git_dir,
            root,
            &["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"],
        )
        .await?,
    )?;
    let base_commit = format!("{base}^{{commit}}");
    let base_oid = parse_oid(
        &git_read(
            &git,
            &git_dir,
            root,
            &["rev-parse", "--verify", "--end-of-options", &base_commit],
        )
        .await
        .map_err(|reason| {
            format!("cannot resolve base ref: {reason}; fetch the base ref and use fetch-depth: 0")
        })?,
    )?;
    let merge_base = parse_oid(&git_read(&git, &git_dir, root,
        &["merge-base", "--end-of-options", &base_oid, &head]).await
        .map_err(|reason| format!("cannot find merge-base (shallow or unrelated history): {reason}; fetch the base ref and use fetch-depth: 0"))?)?;
    // Disable rename collapsing so both the deleted and added paths stay in
    // scope. Read index and worktree separately: their changes can cancel.
    let diff_args = [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--name-only",
        "-z",
        "--no-renames",
    ];
    let mut committed_args = diff_args.to_vec();
    committed_args.extend(["--end-of-options", &merge_base, &head, "--"]);
    let mut staged_args = diff_args.to_vec();
    staged_args.extend(["--cached", "--end-of-options", &head, "--"]);
    let mut unstaged_args = diff_args.to_vec();
    unstaged_args.push("--");
    let committed = git_read(&git, &git_dir, root, &committed_args).await?;
    let staged = git_read(&git, &git_dir, root, &staged_args).await?;
    let unstaged = git_read(&git, &git_dir, root, &unstaged_args).await?;
    let untracked = git_read(
        &git,
        &git_dir,
        root,
        &["ls-files", "--others", "--exclude-standard", "-z", "--"],
    )
    .await?;
    let tracked = git_read(&git, &git_dir, root, &["ls-files", "-z", "--"]).await?;
    let tracked_dependencies = parse_changed_paths(&tracked)?
        .into_iter()
        .filter(|path| is_dependency_file(path))
        .collect();
    // Validate the entire input before accepting any subset; never print names.
    for output in [&committed, &staged, &unstaged, &untracked] {
        if !output.is_empty() && !output.ends_with('\0') {
            return Err("Git returned an unterminated changed-file list".into());
        }
    }
    let mut changed = parse_changed_paths(&format!("{committed}{staged}{unstaged}{untracked}"))?;
    let worktree = parse_changed_paths(&format!("{staged}{unstaged}"))?;
    let untracked = parse_changed_paths(&untracked)?;
    // Keep a union explicitly; counts are distinct paths per category, so a
    // path may be counted in both committed changes and worktree changes.
    changed.extend(worktree.iter().cloned());
    changed.extend(untracked.iter().cloned());
    Ok(DiffSelection {
        scope: DiffScope {
            mode: DiffScopeMode::Diff,
            base: base.into(),
            merge_base,
            head,
            base_oid,
            worktree_changes: worktree.len(),
            untracked: untracked.len(),
            changed_files: changed.len(),
            invalid_paths: 0,
            changed_during_scan: 0,
        },
        changed,
        tracked_dependencies,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Fixture setup also uses the bounded, sanitized subprocess runner.
    pub async fn git(root: &Path, args: &[&str]) -> String {
        let binary = crate::util::which_cli_for_scan("git", root).unwrap();
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
            &binary,
            &command,
            root,
            &SubprocessLimits {
                timeout: std::time::Duration::from_secs(10),
                max_output_bytes: 1024 * 1024,
            },
        )
        .await;
        assert_eq!(out.exit_code, Some(0), "{args:?}: {out:?}");
        assert!(!out.timed_out && !out.stdout_truncated && out.cleanup_error.is_none());
        out.stdout
    }

    pub async fn commit(root: &Path) {
        git(root, &["add", "--all"]).await;
        git(root, &["commit", "-qm", "fixture"]).await;
    }

    #[test]
    fn ref_validation_is_strict() {
        for bad in [
            "",
            "-x",
            "a b",
            "HEAD..main",
            "HEAD...main",
            "a\nb",
            "a\0b",
            "a\tb",
            "é",
            "HEAD^{commit}",
            "$(x)",
            "a:b",
        ] {
            assert!(validate_ref(bad).is_err(), "{bad:?}");
        }
        assert!(validate_ref(&"a".repeat(201)).is_err());
        for good in [
            "HEAD",
            "main~1",
            "HEAD^",
            "refs/remotes/origin/main",
            "release-1.2",
            "foo@bar",
        ] {
            assert_eq!(validate_ref(good).unwrap(), good);
        }
    }

    #[test]
    fn paths_are_nul_delimited_and_validated() {
        let (paths, invalid) = parse_paths(
            "src/hello world.rs\0src/測試.rs\0../bad\0/a\0src/control\n.rs\0src/\u{fffd}.rs\0",
        );
        assert_eq!(
            paths,
            BTreeSet::from(["src/hello world.rs".into(), "src/測試.rs".into()])
        );
        assert_eq!(invalid, 4);
    }

    #[tokio::test]
    async fn merge_base_rename_unicode_and_spaces() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        git(root, &["init", "-q"]).await;
        std::fs::write(root.join("old.rs"), "fn a() {}\n").unwrap();
        commit(root).await;
        let base = git(root, &["rev-parse", "HEAD"]).await.trim().to_owned();
        git(root, &["mv", "old.rs", "new name 測試.rs"]).await;
        commit(root).await;
        let selection = compute(root, &base).await.unwrap();
        assert_eq!(selection.scope.merge_base, base);
        assert_eq!(selection.scope.changed_files, 2);
        assert_eq!(selection.scope.invalid_paths, 0);
        assert_eq!(
            selection.changed,
            BTreeSet::from(["old.rs".into(), "new name 測試.rs".into()])
        );
        let error = compute(root, "unknown-ref").await.unwrap_err();
        assert!(error.contains("fetch-depth: 0"), "{error}");
    }

    #[tokio::test]
    async fn refuses_external_metadata_and_config_helpers() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::write(root.join(".git"), "gitdir: /tmp/external\n").unwrap();
        assert!(compute(root, "HEAD").await.is_err());
        std::fs::remove_file(root.join(".git")).unwrap();
        git(root, &["init", "-q"]).await;
        for key in [
            "include.path",
            "gpg.program",
            "diff.external",
            "core.fsmonitor",
        ] {
            git(root, &["config", key, "/tmp/must-not-run"]).await;
            assert!(
                compute(root, "HEAD")
                    .await
                    .unwrap_err()
                    .contains("unsafe Git config")
            );
            git(root, &["config", "--unset", key]).await;
        }
    }

    fn selection(paths: &[&str]) -> DiffSelection {
        DiffSelection {
            scope: DiffScope {
                mode: DiffScopeMode::Diff,
                base: "main".into(),
                merge_base: "a".repeat(40),
                head: "b".repeat(40),
                base_oid: "a".repeat(40),
                changed_files: paths.len(),
                worktree_changes: 0,
                untracked: 0,
                invalid_paths: 0,
                changed_during_scan: 0,
            },
            changed: paths.iter().map(|p| (*p).into()).collect(),
            tracked_dependencies: BTreeSet::from(["Cargo.lock".into()]),
        }
    }

    fn finding(engine: &str, kind: FindingKind, file: &str) -> Finding {
        Finding::candidate(
            engine,
            kind,
            super::super::schema::Severity::High,
            "fixture",
            file,
            None,
            "fixture",
            "rule",
            vec![],
        )
    }

    #[test]
    fn reconcile_unions_changes_and_reapplies_scope_idempotently() {
        let mut initial = selection(&["initial.rs", "both.rs"]);
        let mut final_selection = selection(&["late.rs", "both.rs"]);
        final_selection.scope.worktree_changes = 1;
        final_selection.scope.untracked = 1;
        let mut findings = vec![finding("semgrep", FindingKind::StaticAnalysis, "late.rs")];
        initial.annotate_findings(&mut findings);
        assert!(outside_diff_scope(&findings[0]));
        initial.reconcile(final_selection).unwrap();
        assert_eq!(
            initial.changed,
            BTreeSet::from(["initial.rs".into(), "both.rs".into(), "late.rs".into()])
        );
        assert_eq!(initial.scope.changed_during_scan, 1);
        assert_eq!(initial.scope.changed_files, 3);
        assert_eq!(initial.scope.worktree_changes, 1);
        assert_eq!(initial.scope.untracked, 1);
        initial.annotate_findings(&mut findings);
        initial.annotate_findings(&mut findings);
        assert!(!outside_diff_scope(&findings[0]));
        assert!(findings[0].evidence.is_empty());
        assert_eq!(
            serde_json::to_value(&initial.scope).unwrap()["changed_during_scan"],
            1
        );
        let old_json = serde_json::to_value(selection(&[]).scope).unwrap();
        assert!(old_json.get("changed_during_scan").is_none());
        assert_eq!(
            serde_json::from_value::<DiffScope>(old_json)
                .unwrap()
                .changed_during_scan,
            0
        );
    }

    #[test]
    fn reconcile_refuses_moved_revisions_without_mutating_scope() {
        for field in ["HEAD", "base", "merge-base"] {
            let mut initial = selection(&["initial.rs"]);
            let original_scope = initial.scope.clone();
            let mut final_selection = selection(&["late.rs"]);
            match field {
                "HEAD" => final_selection.scope.head = "c".repeat(40),
                "base" => final_selection.scope.base_oid = "c".repeat(40),
                _ => final_selection.scope.merge_base = "c".repeat(40),
            }
            let error = initial.reconcile(final_selection).unwrap_err();
            assert!(error.contains(field));
            assert!(!error.contains(".rs"));
            assert_eq!(initial.scope, original_scope);
            assert_eq!(initial.changed, BTreeSet::from(["initial.rs".into()]));
        }
    }

    #[test]
    fn reconcile_keeps_dependencies_untracked_in_either_snapshot_in_scope() {
        let advisory = finding(
            "cargo-audit",
            FindingKind::StaticAnalysis,
            "Cargo.lock (vulnerable 1.2.3)",
        );
        for initially_tracked in [false, true] {
            let mut initial = selection(&[]);
            let mut final_selection = selection(&[]);
            if initially_tracked {
                final_selection.tracked_dependencies.clear();
            } else {
                initial.tracked_dependencies.clear();
            }
            initial.reconcile(final_selection).unwrap();
            assert!(initial.contains_finding(&advisory));
        }
    }

    #[tokio::test]
    async fn ignored_lockfile_is_in_scope_but_tracked_unchanged_lockfile_is_not() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        git(root, &["init", "-q"]).await;
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(root.join(".gitignore"), "Cargo.lock\n").unwrap();
        std::fs::write(root.join("lib.rs"), "fn old() {}\n").unwrap();
        commit(root).await;
        std::fs::write(root.join("Cargo.lock"), "# generated lockfile\n").unwrap();
        std::fs::write(root.join("lib.rs"), "fn changed() {}\n").unwrap();
        let ignored = compute(root, "HEAD").await.unwrap();
        assert_eq!(ignored.changed, BTreeSet::from(["lib.rs".into()]));
        assert_eq!(
            ignored.tracked_dependencies,
            BTreeSet::from(["Cargo.toml".into()])
        );
        for (engine, kind, path) in [
            (
                "cargo-audit",
                FindingKind::DependencyVulnerability,
                "Cargo.lock (vulnerable 1.2.3)",
            ),
            (
                "cargo-audit",
                FindingKind::StaticAnalysis,
                "Cargo.lock (vulnerable 1.2.3)",
            ),
            (
                "osv-scanner",
                FindingKind::DependencyVulnerability,
                "Cargo.lock",
            ),
        ] {
            assert!(ignored.contains_finding(&finding(engine, kind, path)));
        }
        git(root, &["add", "-f", "Cargo.lock"]).await;
        commit(root).await;
        std::fs::write(root.join("lib.rs"), "fn changed_again() {}\n").unwrap();
        let tracked = compute(root, "HEAD").await.unwrap();
        assert_eq!(tracked.changed, BTreeSet::from(["lib.rs".into()]));
        assert!(tracked.tracked_dependencies.contains("Cargo.lock"));
        assert!(!tracked.contains_finding(&finding(
            "cargo-audit",
            FindingKind::DependencyVulnerability,
            "Cargo.lock (vulnerable 1.2.3)"
        )));
    }

    #[test]
    fn cargo_advisories_gate_on_lockfile_and_manifest_changes_without_changing_identity() {
        let original = finding(
            "cargo-audit",
            FindingKind::DependencyVulnerability,
            "Cargo.lock (vulnerable 1.2.3)",
        );
        assert_eq!(scope_path(&original), Some("Cargo.lock"));
        for path in ["Cargo.lock", "Cargo.toml", "workspace/member/Cargo.toml"] {
            let mut findings = vec![original.clone()];
            // A previous annotation must not survive a newly in-scope selection.
            selection(&["unrelated.rs"]).annotate_findings(&mut findings);
            assert!(outside_diff_scope(&findings[0]));
            selection(&[path]).annotate_findings(&mut findings);
            let f = &findings[0];
            assert!(!outside_diff_scope(f));
            assert_eq!(f.file, original.file);
            assert_eq!(f.id, original.id);
            assert_eq!(f.root_fingerprint, original.root_fingerprint);
            let gate: super::super::gate::GateCondition = "severity>=high count>0".parse().unwrap();
            assert!(gate.evaluate(&findings).failed);
            let summary = super::super::schema::Summary::from_findings(
                &findings,
                1,
                0,
                super::super::schema::GatePolicy::default(),
                &[],
            );
            assert_eq!(summary.gate_counts().high, 1);
        }
    }

    #[test]
    fn scanner_scope_paths_and_unknown_shapes_are_conservative() {
        for (engine, kind) in [
            ("semgrep", FindingKind::StaticAnalysis),
            ("gitleaks", FindingKind::Secret),
        ] {
            for path in ["src/a.rs", "./src/a.rs", "src/my file.rs"] {
                let f = finding(engine, kind, path);
                let canonical = path.trim_start_matches("./");
                assert_eq!(scope_path(&f), Some(canonical));
                assert!(selection(&[canonical]).contains_finding(&f));
                assert!(!selection(&["unrelated.rs"]).contains_finding(&f));
            }
            for path in [
                "",
                "/repo/src/a.rs",
                "../a.rs",
                "src/\u{fffd}.rs",
                "C:\\a.rs",
            ] {
                assert!(selection(&[]).contains_finding(&finding(engine, kind, path)));
            }
        }
        for path in ["package-lock.json", "sub/poetry.lock"] {
            let f = finding("osv-scanner", FindingKind::DependencyVulnerability, path);
            assert_eq!(scope_path(&f), Some(path));
            assert!(selection(&[path]).contains_finding(&f));
        }
        for engine in ["cargo-audit", "osv-scanner"] {
            for path in [
                "unknown package",
                "Cargo.lock (broken",
                "Cargo.lock (bad)",
                "Cargo.lock (name version extra)",
                "pkg@1.2.3",
                "../Cargo.lock",
            ] {
                let f = finding(engine, FindingKind::DependencyVulnerability, path);
                assert!(scope_path(&f).is_none());
                assert!(selection(&[]).contains_finding(&f));
            }
        }
    }

    #[tokio::test]
    async fn includes_staged_unstaged_cancelled_and_untracked_but_not_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        git(root, &["init", "-q"]).await;
        for file in ["staged.rs", "unstaged.rs", "cancelled.rs", "clean.rs"] {
            std::fs::write(root.join(file), "old\n").unwrap();
        }
        std::fs::write(root.join(".gitignore"), "ignored.rs\n").unwrap();
        commit(root).await;
        let head = git(root, &["rev-parse", "HEAD"]).await.trim().to_owned();
        for file in ["staged.rs", "cancelled.rs"] {
            std::fs::write(root.join(file), "new\n").unwrap();
        }
        git(root, &["add", "staged.rs", "cancelled.rs"]).await;
        std::fs::write(root.join("cancelled.rs"), "old\n").unwrap();
        std::fs::write(root.join("unstaged.rs"), "new\n").unwrap();
        std::fs::write(root.join("untracked 測試.rs"), "new\n").unwrap();
        std::fs::write(root.join("ignored.rs"), "new\n").unwrap();
        let result = compute(root, &head).await.unwrap();
        assert_eq!(result.scope.head, head);
        assert_eq!(result.scope.base_oid, head);
        assert_eq!(result.scope.worktree_changes, 3);
        assert_eq!(result.scope.untracked, 1);
        assert_eq!(
            result.changed,
            BTreeSet::from([
                "staged.rs".into(),
                "unstaged.rs".into(),
                "cancelled.rs".into(),
                "untracked 測試.rs".into(),
            ])
        );
        let json = serde_json::to_value(&result.scope).unwrap();
        assert_eq!(json["head"], head);
        assert_eq!(json["worktree_changes"], 3);
        assert_eq!(json["untracked"], 1);
    }

    #[tokio::test]
    async fn ignores_replace_objects_and_refuses_grafts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        git(root, &["init", "-q"]).await;
        std::fs::write(root.join("a.rs"), "old\n").unwrap();
        commit(root).await;
        let base = git(root, &["rev-parse", "HEAD"]).await.trim().to_owned();
        std::fs::write(root.join("Cargo.lock"), "vulnerable\n").unwrap();
        commit(root).await;
        let expected = compute(root, &base).await.unwrap();
        git(root, &["replace", "HEAD", &base]).await;
        let actual = compute(root, &base).await.unwrap();
        assert_eq!(actual.changed, expected.changed);
        assert!(actual.changed.contains("Cargo.lock"));
        assert_eq!(actual.scope.head, expected.scope.head);
        assert_eq!(actual.scope.merge_base, expected.scope.merge_base);
        std::fs::write(root.join(".git/info/grafts"), "").unwrap();
        assert!(
            compute(root, &base)
                .await
                .unwrap_err()
                .contains("info/grafts")
        );
    }

    #[test]
    fn invalid_path_error_only_reports_count() {
        let error =
            parse_changed_paths("../private\0src/control\n.rs\0src/\u{fffd}.rs\0").unwrap_err();
        assert_eq!(
            error,
            "diff scope refused: 3 invalid repo-relative changed paths"
        );
        assert!(parse_changed_paths("unterminated").is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_unsafe_and_non_utf8_names_in_every_change_source() {
        use std::os::unix::ffi::OsStrExt;
        let mut names = vec![std::ffi::OsStr::new("private\nname.rs")];
        let non_utf8_name = std::ffi::OsStr::from_bytes(b"secret-\xff.rs");
        let probe = tempfile::tempdir().unwrap();
        std::fs::write(probe.path().join(names[0]), "probe\n").unwrap();
        // APFS and some sandboxes reject non-UTF-8 names, even in a writable directory.
        match std::fs::write(probe.path().join(non_utf8_name), "probe\n") {
            Ok(()) => names.push(non_utf8_name),
            Err(error)
                if error.kind() == std::io::ErrorKind::InvalidInput
                    || matches!(error.raw_os_error(), Some(libc::EILSEQ | libc::EPERM)) => {}
            Err(error) => panic!("unexpected non-UTF-8 filename probe error: {error}"),
        }
        for source in ["committed", "staged", "unstaged", "untracked"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            git(root, &["init", "-q"]).await;
            std::fs::write(root.join("ok.rs"), "ok\n").unwrap();
            if source == "unstaged" {
                for name in &names {
                    std::fs::write(root.join(name), "old\n").unwrap();
                }
            }
            commit(root).await;
            let base = git(root, &["rev-parse", "HEAD"]).await.trim().to_owned();
            for name in &names {
                std::fs::write(root.join(name), "new\n").unwrap();
            }
            if source == "committed" {
                commit(root).await;
            }
            if source == "staged" {
                git(root, &["add", "--all"]).await;
            }
            let error = compute(root, &base).await.unwrap_err();
            assert_eq!(
                error,
                format!(
                    "diff scope refused: {} invalid repo-relative changed paths",
                    names.len()
                ),
                "{source}"
            );
        }
    }
}
