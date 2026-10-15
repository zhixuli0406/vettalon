//! Deterministic repo intake / threat-modeling signals.
//!
//! Everything here is zero-LLM and zero-network: a language census by file
//! extension, an entry-point heuristic, and a git-history hotspot scan
//! (high-churn files whose commit messages carry a security-flavored
//! keyword). All content read here (file paths, commit subjects) is DATA —
//! it is only ever counted/matched by fixed keyword lists, never executed or
//! fed to an LLM in this wave.
//!
//! No `walkdir` dependency — plain `std::fs` recursion (same convention as
//! `expert/safe_zip.rs`), with a fixed skip-list for vendor/build
//! directories and a symlink guard against cycles.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Directory names never descended into — either huge generated trees or
/// irrelevant to a security intake pass. Matched by exact basename.
const SKIP_DIR_NAMES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".cargo",
    ".idea",
    ".vscode",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".gradle",
    ".terraform",
];

/// Safety valve against pathological trees (not a normal-repo limit — a
/// healthy repo is nowhere near this).
const MAX_WALK_FILES: usize = 200_000;
const MAX_WALK_DEPTH: usize = 16;

/// Recursively list repo-relative file paths (POSIX separators) under
/// `root`, skipping [`SKIP_DIR_NAMES`] and symlinks (cycle guard). The only
/// filesystem-touching function in this module — `census_languages` and
/// `detect_entry_points` are pure functions over the returned list so they
/// can be unit-tested with literal fixture data.
///
/// Also skipped, so audit slots go to the project's own code:
/// - nested independent clones (a subdirectory whose `.git` is a directory —
///   another project checked out inside this one; a submodule's `.git` is a
///   file and is kept, it is part of the product);
/// - directories the root `.gitignore` excludes with a plain, glob-free
///   directory pattern (only when the root is a git work tree; git cannot
///   re-include anything under an excluded directory, so this is exact).
pub fn walk_repo_files(root: &Path) -> Vec<String> {
    let ignored = RootIgnoredDirs::load(root);
    let mut out = Vec::new();
    walk_dir(root, root, 0, &ignored, &mut out);
    out
}

/// The glob-free directory patterns of the root `.gitignore`. A deliberate
/// subset of gitignore: patterns with wildcards or negation are not
/// interpreted (they only ever skip less, never more).
#[derive(Debug, Default)]
struct RootIgnoredDirs {
    /// Patterns containing a `/`: relative to the root.
    anchored: Vec<String>,
    /// Bare names: match a directory of that name at any depth.
    names: Vec<String>,
}

impl RootIgnoredDirs {
    fn load(root: &Path) -> Self {
        if !root.join(".git").exists() {
            return Self::default();
        }
        match std::fs::read_to_string(root.join(".gitignore")) {
            Ok(text) => Self::parse(&text),
            Err(_) => Self::default(),
        }
    }

    fn parse(text: &str) -> Self {
        let mut out = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with('#')
                || line.starts_with('!')
                || line.contains(['*', '?', '[', '\\'])
            {
                continue;
            }
            let pat = line.trim_end_matches('/');
            if pat.is_empty() {
                continue;
            }
            if pat.contains('/') {
                out.anchored.push(pat.trim_start_matches('/').to_string());
            } else {
                out.names.push(pat.to_string());
            }
        }
        out
    }

    /// `rel` is the directory's repo-relative POSIX path.
    fn matches(&self, rel: &str) -> bool {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        self.anchored.iter().any(|a| a == rel) || self.names.iter().any(|n| n == name)
    }
}

fn walk_dir(
    root: &Path,
    dir: &Path,
    depth: usize,
    ignored: &RootIgnoredDirs,
    out: &mut Vec<String>,
) {
    if depth > MAX_WALK_DEPTH || out.len() >= MAX_WALK_FILES {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_WALK_FILES {
            return;
        }
        let path = entry.path();
        // symlink_metadata does not follow symlinks — used to detect (and
        // skip) them without risking a cycle via a followed metadata() call.
        let is_symlink = std::fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if is_symlink {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if SKIP_DIR_NAMES.contains(&name.as_ref()) || path.join(".git").is_dir() {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(root)
                && ignored.matches(&rel.to_string_lossy().replace('\\', "/"))
            {
                continue;
            }
            walk_dir(root, &path, depth + 1, ignored, out);
        } else if file_type.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanguageStat {
    /// Lowercased extension without the leading dot, or `"(no-ext)"`.
    pub extension: String,
    pub file_count: usize,
}

/// Cap on how many language buckets ship in the report (long-tail noise cut).
const MAX_LANGUAGE_BUCKETS: usize = 25;

/// Group `files` (repo-relative paths) by lowercased extension, sorted by
/// count descending then extension ascending for a stable order.
pub fn census_languages(files: &[String]) -> Vec<LanguageStat> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for f in files {
        let ext = Path::new(f)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_else(|| "(no-ext)".to_string());
        *counts.entry(ext).or_insert(0) += 1;
    }
    let mut stats: Vec<LanguageStat> = counts
        .into_iter()
        .map(|(extension, file_count)| LanguageStat {
            extension,
            file_count,
        })
        .collect();
    stats.sort_by(|a, b| {
        b.file_count
            .cmp(&a.file_count)
            .then_with(|| a.extension.cmp(&b.extension))
    });
    stats.truncate(MAX_LANGUAGE_BUCKETS);
    stats
}

/// Fixed basename candidates for the entry-point heuristic (task spec:
/// "main.rs/index.ts/app.py 等"). Exact basename match, case-sensitive
/// (these are conventional names; case-insensitive matching would add noise
/// without adding real coverage).
const ENTRY_POINT_BASENAMES: &[&str] = &[
    "main.rs",
    "main.go",
    "index.ts",
    "index.js",
    "index.mjs",
    "main.ts",
    "main.js",
    "main.mjs",
    "app.ts",
    "app.js",
    "server.ts",
    "server.js",
    "app.py",
    "main.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "Main.java",
    "Application.java",
    "main.c",
    "main.cpp",
    "Program.cs",
    "main.rb",
];

const MAX_ENTRY_POINTS: usize = 50;

/// Filter `files` for basenames matching [`ENTRY_POINT_BASENAMES`], sorted
/// for a stable order and capped at [`MAX_ENTRY_POINTS`].
pub fn detect_entry_points(files: &[String]) -> Vec<String> {
    let mut hits: Vec<String> = files
        .iter()
        .filter(|f| {
            Path::new(f)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| ENTRY_POINT_BASENAMES.contains(&n))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    hits.sort();
    hits.truncate(MAX_ENTRY_POINTS);
    hits
}

/// Commit-subject keywords that mark a commit as security-flavored (task
/// spec: "fix/security/vuln/CVE/injection/auth/overflow 等"). Matched via
/// `word_contains_ci` (whole-word, case-insensitive) so e.g. "auth" does not
/// false-positive inside "author".
pub const SECURITY_COMMIT_KEYWORDS: &[&str] = &[
    "fix",
    "security",
    "vuln",
    "vulnerability",
    "cve",
    "injection",
    "auth",
    "overflow",
    "xss",
    "csrf",
    "sqli",
    "rce",
    "exploit",
    "secret",
    "leak",
    "credential",
    "password",
    "unsafe",
    "sanitize",
    "backdoor",
    "bypass",
    "privilege",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HotspotFile {
    pub file: String,
    /// Times this file was touched by ANY commit in the scan window.
    pub total_touches: usize,
    /// Times this file was touched by a commit whose subject matched a
    /// [`SECURITY_COMMIT_KEYWORDS`] entry — the ranking key.
    pub security_touches: usize,
}

const MAX_HOTSPOTS: usize = 20;

/// One-record-per-commit marker this module's `git log` invocation uses to
/// delimit commit boundaries in `--name-only` output. `\x01` (SOH) never
/// appears in a commit subject in practice and is never treated specially by
/// the shell, so no quoting concerns at the call site.
pub const GIT_LOG_COMMIT_MARKER: &str = "\u{1}COMMIT\u{1}";

/// Parse `git log --name-only --pretty=format:<GIT_LOG_COMMIT_MARKER>%s`
/// output into per-file touch/security-touch counts, then rank into the top
/// [`MAX_HOTSPOTS`] files that have at least one security-flavored touch.
/// Pure function — testable with literal fixture text, no real git needed.
pub fn parse_git_log_hotspots(raw: &str) -> Vec<HotspotFile> {
    let mut totals: HashMap<String, usize> = HashMap::new();
    let mut security: HashMap<String, usize> = HashMap::new();
    let mut current_is_security = false;
    let mut in_commit = false;

    for line in raw.lines() {
        if let Some(subject) = line.strip_prefix(GIT_LOG_COMMIT_MARKER) {
            in_commit = true;
            current_is_security = SECURITY_COMMIT_KEYWORDS
                .iter()
                .any(|kw| crate::util::word_contains_ci(subject, kw));
            continue;
        }
        let file = line.trim();
        if !in_commit || file.is_empty() {
            continue;
        }
        *totals.entry(file.to_string()).or_insert(0) += 1;
        if current_is_security {
            *security.entry(file.to_string()).or_insert(0) += 1;
        }
    }

    let mut hotspots: Vec<HotspotFile> = security
        .into_iter()
        .map(|(file, security_touches)| {
            let total_touches = totals.get(&file).copied().unwrap_or(security_touches);
            HotspotFile {
                file,
                total_touches,
                security_touches,
            }
        })
        .collect();
    hotspots.sort_by(|a, b| {
        b.security_touches
            .cmp(&a.security_touches)
            .then_with(|| b.total_touches.cmp(&a.total_touches))
            .then_with(|| a.file.cmp(&b.file))
    });
    hotspots.truncate(MAX_HOTSPOTS);
    hotspots
}

/// Git history availability. Honest-degradation per task spec: "git 不可用
/// 或非 git repo → 誠實降級，不失敗". Internally tagged (`status` field) so
/// the JSON shape is a flat, stable object instead of the default
/// externally-tagged `{"unavailable": {...}}` nesting — easier for report
/// consumers to pattern-match on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GitHistoryStatus {
    Available { hotspots: Vec<HotspotFile> },
    Unavailable { reason: String },
}

/// Hotspot look-back window. Anchored to the HEAD commit rather than today,
/// so an old checkout (benchmark fixtures, vendored snapshots, a repo nobody
/// has touched in a year) still yields its security-fix history.
const HOTSPOT_WINDOW_SECS: i64 = 365 * 24 * 60 * 60;

/// `--since` argument for the hotspot window ending at `head_epoch`. Falls
/// back to the wall-clock window when the HEAD date is unknown or too small
/// to subtract from (git treats `@0` as no lower bound at all).
fn hotspot_since_arg(head_epoch: Option<i64>) -> String {
    match head_epoch {
        Some(ts) if ts > HOTSPOT_WINDOW_SECS => format!("--since=@{}", ts - HOTSPOT_WINDOW_SECS),
        _ => "--since=1.year.ago".to_string(),
    }
}

/// Committer date of HEAD as a unix timestamp, or `None` on any failure.
async fn head_commit_epoch(repo_root_str: &str) -> Option<i64> {
    let out = tokio::process::Command::new("git")
        .args(["-C", repo_root_str, "log", "-1", "--format=%ct", "HEAD"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Run `git log --since=<HEAD - 1 year> --no-merges --name-only` against
/// `repo_root` and reduce it to hotspots. Any failure (git missing, not a
/// repo, empty history) degrades to `Unavailable { reason }` — never an
/// `Err` that would abort the whole intake pass.
pub async fn compute_git_history(repo_root: &Path) -> GitHistoryStatus {
    if crate::util::which_cli("git").is_none() {
        return GitHistoryStatus::Unavailable {
            reason: "git not found on PATH or common install locations".to_string(),
        };
    }
    if !repo_root.join(".git").exists() {
        return GitHistoryStatus::Unavailable {
            reason: "not a git repository (no .git found at repo root)".to_string(),
        };
    }

    // Bound to locals first so every element of the `.args([...])` array
    // literal is a plain `&str` — mixing `&str` literals with a `&Cow<str>`
    // (from `to_string_lossy()`) or an inline `&format!(...)` temporary
    // directly in the array does not type-unify.
    let repo_root_str = repo_root.to_string_lossy().into_owned();
    let pretty_arg = format!("--pretty=format:{GIT_LOG_COMMIT_MARKER}%s");
    let since_arg = hotspot_since_arg(head_commit_epoch(&repo_root_str).await);
    let output = tokio::process::Command::new("git")
        .args([
            "-C",
            repo_root_str.as_str(),
            "log",
            since_arg.as_str(),
            "--no-merges",
            "--name-only",
            pretty_arg.as_str(),
        ])
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            let raw = String::from_utf8_lossy(&out.stdout);
            GitHistoryStatus::Available {
                hotspots: parse_git_log_hotspots(&raw),
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            GitHistoryStatus::Unavailable {
                reason: format!(
                    "git log exited with {}: {}",
                    out.status,
                    crate::util::truncate_bytes(stderr.trim(), 300)
                ),
            }
        }
        Err(e) => GitHistoryStatus::Unavailable {
            reason: format!("failed to spawn git: {e}"),
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoProfile {
    pub language_census: Vec<LanguageStat>,
    pub entry_points: Vec<String>,
    pub git_history: GitHistoryStatus,
}

/// Build the full intake profile (`--profile deep` only — quick profile
/// skips this entirely per task spec).
pub async fn build_profile(repo_root: &Path) -> RepoProfile {
    let files = walk_repo_files(repo_root);
    let language_census = census_languages(&files);
    let entry_points = detect_entry_points(&files);
    let git_history = compute_git_history(repo_root).await;
    RepoProfile {
        language_census,
        entry_points,
        git_history,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── walk_repo_files ──────────────────────────────────────────────

    #[test]
    fn walk_skips_nested_clones_and_root_gitignored_dirs_but_keeps_submodules() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mk = |p: &str, body: &str| {
            let full = root.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, body).unwrap();
        };
        std::fs::create_dir(root.join(".git")).unwrap();
        mk(
            ".gitignore",
            "# comment\n/third_party/\nartifacts/\ncrates/app/gen\n*.log\n!keep/\n",
        );
        mk("src/main.rs", "fn main() {}");
        // A nested independent clone (its .git is a directory): skipped.
        mk("upstream-layer/.git/HEAD", "ref");
        mk("upstream-layer/recipe.py", "x");
        // A submodule (.git is a file): part of the product, kept.
        mk("libs/own/.git", "gitdir: ../../.git/modules/own");
        mk("libs/own/lib.rs", "x");
        mk("third_party/a.c", "x"); // anchored pattern
        mk("crates/app/artifacts/out.rs", "x"); // bare name, any depth
        mk("crates/app/gen/x.rs", "x"); // anchored, no trailing slash
        mk("crates/app/src/ok.rs", "x");
        mk("app.log", "x"); // glob patterns are not interpreted (kept)

        let files = walk_repo_files(root);
        for kept in [
            "src/main.rs",
            "libs/own/lib.rs",
            "crates/app/src/ok.rs",
            "app.log",
        ] {
            assert!(
                files.contains(&kept.to_string()),
                "{kept} missing: {files:?}"
            );
        }
        for gone in [
            "upstream-layer",
            "third_party",
            "artifacts",
            "crates/app/gen",
        ] {
            assert!(
                !files.iter().any(|f| f.contains(gone)),
                "{gone} not skipped: {files:?}"
            );
        }
    }

    #[test]
    fn root_gitignore_applies_only_inside_a_git_work_tree() {
        // An extracted package tarball (hunt) has no .git: its .gitignore
        // describes the author's repo, not what was shipped, so it is ignored.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "dist/\nlib/\n").unwrap();
        std::fs::create_dir(dir.path().join("lib")).unwrap();
        std::fs::write(dir.path().join("lib/index.js"), "x").unwrap();
        assert!(walk_repo_files(dir.path()).contains(&"lib/index.js".to_string()));
    }

    #[test]
    fn walk_skips_vendor_dirs_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::create_dir(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules/pkg.js"), "//").unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "//").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            // A symlink cycle back to root — must not hang or recurse forever.
            let _ = symlink(dir.path(), dir.path().join("src/loop"));
        }

        let files = walk_repo_files(dir.path());
        assert!(files.contains(&"main.rs".to_string()));
        assert!(files.contains(&"src/lib.rs".to_string()));
        assert!(!files.iter().any(|f| f.contains("node_modules")));
        assert!(!files.iter().any(|f| f.contains("loop")));
    }

    #[test]
    fn walk_uses_posix_separators() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        std::fs::write(dir.path().join("a/b.txt"), "x").unwrap();
        let files = walk_repo_files(dir.path());
        assert_eq!(files, vec!["a/b.txt".to_string()]);
    }

    // ── census_languages ─────────────────────────────────────────────

    #[test]
    fn census_counts_by_lowercased_extension() {
        let files = vec![
            "a.rs".to_string(),
            "b.RS".to_string(),
            "c.py".to_string(),
            "README".to_string(),
        ];
        let stats = census_languages(&files);
        let rs = stats.iter().find(|s| s.extension == "rs").unwrap();
        assert_eq!(rs.file_count, 2);
        let noext = stats.iter().find(|s| s.extension == "(no-ext)").unwrap();
        assert_eq!(noext.file_count, 1);
    }

    #[test]
    fn census_sorts_descending_by_count() {
        let files = vec!["a.rs".to_string(), "b.rs".to_string(), "c.py".to_string()];
        let stats = census_languages(&files);
        assert_eq!(stats[0].extension, "rs");
        assert_eq!(stats[0].file_count, 2);
    }

    // ── detect_entry_points ──────────────────────────────────────────

    #[test]
    fn entry_points_match_known_basenames_only() {
        let files = vec![
            "src/main.rs".to_string(),
            "crates/foo/src/main.rs".to_string(),
            "src/other.rs".to_string(),
            "web/src/index.ts".to_string(),
            "app.py".to_string(),
            "not_an_entry.py".to_string(),
        ];
        let hits = detect_entry_points(&files);
        assert!(hits.contains(&"src/main.rs".to_string()));
        assert!(hits.contains(&"crates/foo/src/main.rs".to_string()));
        assert!(hits.contains(&"web/src/index.ts".to_string()));
        assert!(hits.contains(&"app.py".to_string()));
        assert!(!hits.contains(&"src/other.rs".to_string()));
        assert!(!hits.contains(&"not_an_entry.py".to_string()));
    }

    // ── parse_git_log_hotspots ───────────────────────────────────────

    fn commit(subject: &str, files: &[&str]) -> String {
        let mut s = format!("{GIT_LOG_COMMIT_MARKER}{subject}\n");
        for f in files {
            s.push_str(f);
            s.push('\n');
        }
        s.push('\n');
        s
    }

    #[test]
    fn hotspots_only_include_files_touched_by_security_commits() {
        let raw = commit("chore: bump deps", &["package.json"])
            + &commit(
                "fix: auth bypass in login",
                &["src/auth.rs", "src/login.rs"],
            )
            + &commit("docs: typo", &["README.md"]);
        let hotspots = parse_git_log_hotspots(&raw);
        let files: Vec<&str> = hotspots.iter().map(|h| h.file.as_str()).collect();
        assert!(files.contains(&"src/auth.rs"));
        assert!(files.contains(&"src/login.rs"));
        assert!(!files.contains(&"package.json"));
        assert!(!files.contains(&"README.md"));
    }

    #[test]
    fn hotspots_rank_by_security_touch_count_desc() {
        let raw = commit("fix: sql injection", &["db.py"])
            + &commit("fix: another injection path", &["db.py"])
            + &commit("security: patch overflow", &["parser.c"]);
        let hotspots = parse_git_log_hotspots(&raw);
        assert_eq!(hotspots[0].file, "db.py");
        assert_eq!(hotspots[0].security_touches, 2);
        assert_eq!(hotspots[1].file, "parser.c");
        assert_eq!(hotspots[1].security_touches, 1);
    }

    #[test]
    fn hotspots_word_boundary_avoids_author_false_positive() {
        // "author" contains "auth" as a substring but must not match the
        // whole-word "auth" keyword (word_contains_ci discipline).
        let raw = commit("chore: update author list", &["AUTHORS.md"]);
        let hotspots = parse_git_log_hotspots(&raw);
        assert!(hotspots.is_empty());
    }

    #[test]
    fn hotspots_handles_empty_log() {
        assert!(parse_git_log_hotspots("").is_empty());
    }

    #[test]
    fn hotspots_ignore_stray_lines_before_first_commit_marker() {
        // Defensive: malformed/truncated output must not panic or misattribute.
        let raw = format!(
            "garbage-line-with-no-marker\n{}",
            commit("fix: x", &["a.rs"])
        );
        let hotspots = parse_git_log_hotspots(&raw);
        assert_eq!(hotspots.len(), 1);
        assert_eq!(hotspots[0].file, "a.rs");
    }

    // ── compute_git_history (async, touches real git/fs) ────────────

    #[tokio::test]
    async fn git_history_unavailable_when_not_a_repo() {
        let dir = tempfile::tempdir().unwrap();
        let status = compute_git_history(dir.path()).await;
        match status {
            GitHistoryStatus::Unavailable { reason } => {
                assert!(
                    reason.contains("not a git repository") || reason.contains("git not found")
                );
            }
            GitHistoryStatus::Available { .. } => panic!("expected Unavailable for a non-git dir"),
        }
    }

    #[test]
    fn hotspot_window_is_anchored_to_head_commit() {
        let head = 1_792_036_661; // 2026-10-15
        assert_eq!(
            hotspot_since_arg(Some(head)),
            format!("--since=@{}", head - HOTSPOT_WINDOW_SECS)
        );
        // Unknown or implausible HEAD date falls back to the wall-clock window.
        assert_eq!(hotspot_since_arg(None), "--since=1.year.ago");
        assert_eq!(hotspot_since_arg(Some(0)), "--since=1.year.ago");
    }

    #[tokio::test]
    async fn old_checkout_still_gets_hotspots() {
        if crate::util::which_cli("git").is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Every commit is two years old: a now-anchored window sees nothing.
        let old = "2024-06-01T12:00:00+00:00";
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .env("GIT_AUTHOR_DATE", old)
                .env("GIT_COMMITTER_DATE", old)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@example.com"]);
        git(&["config", "user.name", "t"]);
        std::fs::write(root.join("auth.rs"), "fn a() {}").unwrap();
        git(&["add", "auth.rs"]);
        git(&["commit", "-q", "-m", "fix: sql injection in login"]);

        match compute_git_history(root).await {
            GitHistoryStatus::Available { hotspots } => {
                assert_eq!(hotspots.len(), 1, "expected the old security fix to count");
                assert_eq!(hotspots[0].file, "auth.rs");
            }
            GitHistoryStatus::Unavailable { reason } => panic!("unexpected: {reason}"),
        }
    }

    #[test]
    fn git_history_status_serializes_with_tag() {
        let status = GitHistoryStatus::Unavailable {
            reason: "no git".to_string(),
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["reason"], serde_json::json!("no git"));
    }
}
