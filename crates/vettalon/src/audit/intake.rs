//! Deterministic repo intake / threat-modeling signals.
//!
//! Everything here is zero-LLM and zero-network: a language census by file
//! extension, an entry-point heuristic, and a git-history hotspot scan
//! (high-churn files whose commit messages carry a security-flavored
//! keyword). All content read here (file paths, commit subjects) is DATA —
//! it is only ever counted/matched by fixed keyword lists, never executed or
//! fed to an LLM in this wave.
//!
//! No `walkdir` dependency — plain `std::fs` recursion, with a fixed
//! skip-list for vendor/build
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

/// Files the operating system drops into folders (Finder, Explorer). Never
/// project content, usually binary, and usually gitignored. Matched by exact
/// basename; macOS AppleDouble files (`._name`) are matched by prefix.
const SKIP_FILE_NAMES: &[&str] = &[".DS_Store", "Thumbs.db", "ehthumbs.db", "desktop.ini"];

fn is_os_metadata_file(name: &str) -> bool {
    SKIP_FILE_NAMES.contains(&name) || name.starts_with("._")
}

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
/// - operating-system metadata files ([`SKIP_FILE_NAMES`], `._*`);
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
pub(super) struct RootIgnoredDirs {
    /// Patterns containing a `/`: relative to the root.
    anchored: Vec<String>,
    /// Bare names: match a directory of that name at any depth.
    names: Vec<String>,
}

impl RootIgnoredDirs {
    pub(super) fn load(root: &Path) -> Self {
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

    fn reads_dir(&self, root: &Path, rel: &str) -> bool {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        !SKIP_DIR_NAMES.contains(&name)
            && !root.join(rel).join(".git").is_dir()
            && !self.matches(rel)
    }

    /// The same path predicate used by intake, independent of Git's ignore rules.
    pub(super) fn reads_file(&self, root: &Path, rel: &str) -> bool {
        let parts: Vec<_> = rel.split('/').collect();
        if parts.len() > MAX_WALK_DEPTH + 1
            || parts.is_empty()
            || is_os_metadata_file(parts.last().unwrap())
        {
            return false;
        }
        let mut path = String::new();
        for (index, part) in parts.iter().enumerate() {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(part);
            let Ok(meta) = std::fs::symlink_metadata(root.join(&path)) else {
                return false;
            };
            if index + 1 == parts.len() {
                return meta.is_file();
            }
            if !meta.is_dir() || !self.reads_dir(root, &path) {
                return false;
            }
        }
        false
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
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            if !ignored.reads_dir(root, &rel.to_string_lossy().replace('\\', "/")) {
                continue;
            }
            walk_dir(root, &path, depth + 1, ignored, out);
        } else if file_type.is_file()
            && let Ok(rel) = path.strip_prefix(root)
            && ignored.reads_file(root, &rel.to_string_lossy().replace('\\', "/"))
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
const GIT_HISTORY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const GIT_HISTORY_OUTPUT_CAP: usize = 4 * 1024 * 1024;
const GIT_HISTORY_MAX_COMMITS: &str = "--max-count=10000";

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
async fn head_commit_epoch(git_bin: &str, git_dir: &Path, repo_root: &Path) -> Option<i64> {
    let git_dir_arg = format!("--git-dir={}", git_dir.display());
    let out = crate::audit::scanners::run_bounded_subprocess(
        git_bin,
        &[
            "--no-pager",
            git_dir_arg.as_str(),
            "log",
            "--no-show-signature",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "-1",
            "--format=%ct",
            "HEAD",
        ],
        repo_root,
        &crate::audit::scanners::SubprocessLimits {
            timeout: std::time::Duration::from_secs(5),
            max_output_bytes: 4096,
        },
    )
    .await;
    if out.exit_code != Some(0)
        || out.timed_out
        || out.stdout_truncated
        || out.spawn_error.is_some()
        || out.cleanup_error.is_some()
    {
        return None;
    }
    out.stdout.trim().parse().ok()
}

/// Extensions that only select an on-disk format (objects, refs, per-worktree
/// config, which is validated below like the main config, relative worktree
/// paths) or mark a partial clone (`git clone --filter`, actions/checkout
/// `filter:`). A partial clone may try to fetch a missing object lazily, but
/// every scanner Git process blocks lazy fetches and all transports, and the
/// keys that would choose a transport command stay refused. Every other
/// extension, including any this list does not know yet, is refused.
const ALLOWED_GIT_EXTENSIONS: &[&str] = &[
    "extensions.objectformat",
    "extensions.compatobjectformat",
    "extensions.refstorage",
    "extensions.worktreeconfig",
    "extensions.partialclone",
    "extensions.relativeworktrees",
];

/// Per-remote variables naming the command a transport runs. Matched on the
/// last segment because remote names may contain dots. `promisor` and
/// `partialclonefilter` are allowed for partial clones.
const FORBIDDEN_REMOTE_VARS: &[&str] = &["uploadpack", "receivepack", "vcs"];

/// `ext::<command>` and other `<helper>::<address>` URLs run a transport
/// helper: a scheme-like prefix (`[A-Za-z0-9][A-Za-z0-9+.-]*`) directly
/// followed by `::` at the start. Leading whitespace is skipped to stay
/// conservative. An IPv6 literal such as `ssh://[::1]/repo` is not a helper.
fn is_transport_helper_url(value: &str) -> bool {
    let value = value.trim_start().as_bytes();
    let Some((first, rest)) = value.split_first() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let scheme_len = rest
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || b"+.-".contains(*b))
        .count();
    rest[scheme_len..].starts_with(b"::")
}

/// The `<base>` of a `url.<base>.insteadOf` / `url.<base>.pushInsteadOf`
/// key, which is the rewrite target. Expects a lowercased, trimmed key.
fn url_rewrite_base(key: &str) -> Option<&str> {
    key.strip_prefix("url.")
        .and_then(|rest| rest.rsplit_once('.'))
        .filter(|(_, var)| *var == "insteadof" || *var == "pushinsteadof")
        .map(|(base, _)| base)
}

/// Value-dependent refusals, applied after [`forbidden_git_config_key`].
fn forbidden_git_config_value(key: &str, value: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    let remote_url = key
        .strip_prefix("remote.")
        .and_then(|rest| rest.rsplit_once('.'))
        .is_some_and(|(_, var)| var == "url" || var == "pushurl");
    let url_rewrite = url_rewrite_base(&key).is_some();
    (remote_url || url_rewrite) && is_transport_helper_url(value)
}

fn forbidden_git_config_key(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    let remote_var = key
        .strip_prefix("remote.")
        .and_then(|rest| rest.rsplit_once('.'))
        .map(|(_, var)| var);
    let rewrite_base = url_rewrite_base(&key);
    key == "include.path"
        || (key.starts_with("includeif.") && key.ends_with(".path"))
        || key == "core.worktree"
        || key == "core.fsmonitor"
        || key == "core.hookspath"
        || key == "core.sshcommand"
        || key == "core.gitproxy"
        || (key.starts_with("extensions.") && !ALLOWED_GIT_EXTENSIONS.contains(&key.as_str()))
        || remote_var.is_some_and(|var| FORBIDDEN_REMOTE_VARS.contains(&var))
        || rewrite_base.is_some_and(is_transport_helper_url)
        || key.starts_with("protocol.")
        || key.starts_with("credential.")
        || key.starts_with("uploadpack.")
        || key == "log.showsignature"
        || key == "gpg.program"
        || key == "gpg.openpgp.program"
        || key == "gpg.x509.program"
        || key == "gpg.ssh.program"
        || key == "diff.external"
        || (key.starts_with("diff.") && (key.ends_with(".command") || key.ends_with(".textconv")))
        || (key.starts_with("filter.")
            && (key.ends_with(".clean") || key.ends_with(".smudge") || key.ends_with(".process")))
}

/// Each legacy remote file is read up to this size; a larger one is refused.
const MAX_LEGACY_REMOTE_BYTES: u64 = 64 * 1024;
const MAX_LEGACY_REMOTE_ENTRIES: usize = 4096;
const MAX_LEGACY_REMOTE_DEPTH: usize = 16;

/// Git still reads a remote from `$GIT_DIR/remotes/<name>` (`URL:` lines)
/// and `$GIT_DIR/branches/<name>` (a bare URL); names may contain `/`.
/// Refuse a transport-helper URL in any such file, and any symlink or
/// special file there. Links are never followed and names never printed.
fn validate_legacy_remotes(git_dir: &Path) -> Result<(), String> {
    let mut visited = 0usize;
    for top in ["remotes", "branches"] {
        let mut stack = vec![(git_dir.join(top), 0usize)];
        while let Some((path, depth)) = stack.pop() {
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(format!("cannot inspect legacy remote files in {top}/")),
            };
            let kind = metadata.file_type();
            if kind.is_symlink() {
                return Err(format!("legacy remote symlink is not allowed in {top}/"));
            }
            if kind.is_dir() {
                if depth >= MAX_LEGACY_REMOTE_DEPTH {
                    return Err(format!(
                        "legacy remote files in {top}/ exceed the depth limit"
                    ));
                }
                let entries = std::fs::read_dir(&path)
                    .map_err(|_| format!("cannot inspect legacy remote files in {top}/"))?;
                for entry in entries {
                    let entry = entry
                        .map_err(|_| format!("cannot inspect legacy remote files in {top}/"))?;
                    visited += 1;
                    if visited > MAX_LEGACY_REMOTE_ENTRIES {
                        return Err("legacy remote files exceed the validation entry limit".into());
                    }
                    stack.push((entry.path(), depth + 1));
                }
                continue;
            }
            if depth == 0 {
                // Not a directory, so Git cannot read any remote from it.
                continue;
            }
            if !kind.is_file() {
                return Err(format!("special file is not allowed in {top}/"));
            }
            let text = read_legacy_remote(&path)
                .map_err(|reason| format!("legacy remote file in {top}/ {reason}"))?;
            if legacy_remote_has_helper(&text) {
                return Err(format!(
                    "transport-helper URL is not allowed in a legacy remote file in {top}/"
                ));
            }
        }
    }
    Ok(())
}

/// Bounded read that never follows a symlink and never blocks on a FIFO.
fn read_legacy_remote(path: &Path) -> Result<String, &'static str> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "cannot be read")?;
    if !file.metadata().map_err(|_| "cannot be read")?.is_file() {
        return Err("is not a regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_LEGACY_REMOTE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot be read")?;
    if bytes.len() as u64 > MAX_LEGACY_REMOTE_BYTES {
        return Err("exceeds the validation limit");
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Check every line, with or without a `URL:` prefix (case-insensitive), so
/// both the `remotes/` and the `branches/` formats are covered.
fn legacy_remote_has_helper(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        let url = match line.get(..4) {
            Some(prefix) if prefix.eq_ignore_ascii_case("url:") => &line[4..],
            _ => line,
        };
        is_transport_helper_url(url)
    })
}

/// Parse repository config with Git itself, but explicitly disable includes
/// while parsing. This catches BOM, quoting, whitespace, case and includeIf
/// variants without first following attacker-selected external paths.
async fn validate_git_configs(
    git_bin: &str,
    git_dir: &Path,
    repo_root: &Path,
) -> Result<(), String> {
    validate_legacy_remotes(git_dir)?;
    for config in [git_dir.join("config"), git_dir.join("config.worktree")] {
        if !config.is_file() {
            continue;
        }
        let config_arg = config.to_string_lossy().into_owned();
        let out = crate::audit::scanners::run_bounded_subprocess(
            git_bin,
            &[
                "config",
                "--file",
                config_arg.as_str(),
                "--null",
                "--list",
                "--no-includes",
            ],
            repo_root,
            &crate::audit::scanners::SubprocessLimits {
                timeout: std::time::Duration::from_secs(5),
                max_output_bytes: 1024 * 1024,
            },
        )
        .await;
        if out.exit_code != Some(0)
            || out.timed_out
            || out.stdout_truncated
            || out.spawn_error.is_some()
            || out.cleanup_error.is_some()
        {
            return Err(format!(
                "cannot safely parse {}",
                config.strip_prefix(git_dir).unwrap_or(&config).display()
            ));
        }
        // `--null` prints `key\nvalue\0`, or just `key\0` for a bare boolean.
        // Only the key is reported; values may hold arbitrary text.
        for entry in out.stdout.split('\0') {
            let (key, value) = entry.split_once('\n').unwrap_or((entry, ""));
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            if forbidden_git_config_key(key) {
                return Err(format!("unsafe Git config key is not allowed: {key}"));
            }
            if forbidden_git_config_value(key, value) {
                return Err(format!("unsafe Git config value is not allowed for {key}"));
            }
        }
    }
    Ok(())
}

/// Resolve only a trusted executable and self-contained metadata, refusing
/// includes and executable helpers before any repository read command.
pub(super) async fn prepare_readonly_git(
    repo_root: &Path,
) -> Result<(String, std::path::PathBuf), String> {
    let git_bin = crate::util::which_cli_for_scan("git", repo_root)
        .ok_or("git not found on absolute PATH or common install locations")?;
    let git_dir = crate::util::validate_local_git_metadata(repo_root)
        .map_err(|reason| format!("Git metadata is not self-contained: {reason}"))?;
    validate_git_configs(&git_bin, &git_dir, repo_root)
        .await
        .map_err(|reason| format!("Git metadata is not self-contained: {reason}"))?;
    Ok((git_bin, git_dir))
}

fn git_history_from_outcome(out: crate::audit::scanners::SubprocessOutcome) -> GitHistoryStatus {
    let unavailable = |reason: String| GitHistoryStatus::Unavailable { reason };
    if let Some(error) = out.spawn_error {
        return unavailable(format!("failed to spawn git: {error}"));
    }
    if out.timed_out {
        return unavailable(format!("git log timed out after {GIT_HISTORY_TIMEOUT:?}"));
    }
    if let Some(error) = out.cleanup_error {
        return unavailable(format!("git log cleanup failed: {error}"));
    }
    if out.stdout_truncated {
        return unavailable(format!(
            "git log exceeded the {GIT_HISTORY_OUTPUT_CAP}-byte output cap"
        ));
    }
    if out.exit_code != Some(0) {
        return unavailable(format!(
            "git log exited with {:?}: {}",
            out.exit_code,
            crate::util::truncate_bytes(out.stderr_tail.trim(), 300)
        ));
    }
    GitHistoryStatus::Available {
        hotspots: parse_git_log_hotspots(&out.stdout),
    }
}

/// Run `git log --since=<HEAD - 1 year> --no-merges --name-only` against
/// `repo_root` and reduce it to hotspots. Any failure (git missing, not a
/// repo, empty history) degrades to `Unavailable { reason }` — never an
/// `Err` that would abort the whole intake pass.
pub async fn compute_git_history(repo_root: &Path) -> GitHistoryStatus {
    let (git_bin, git_dir) = match prepare_readonly_git(repo_root).await {
        Ok(git) => git,
        Err(reason) => return GitHistoryStatus::Unavailable { reason },
    };
    git_history_with(&git_bin, &git_dir, repo_root).await
}

/// [`compute_git_history`] after metadata validation; tests call it directly
/// to prove the reads stay safe even when validation is bypassed.
async fn git_history_with(git_bin: &str, git_dir: &Path, repo_root: &Path) -> GitHistoryStatus {
    // Bound to locals first so every element of the `.args([...])` array
    // literal is a plain `&str` — mixing `&str` literals with a `&Cow<str>`
    // (from `to_string_lossy()`) or an inline `&format!(...)` temporary
    // directly in the array does not type-unify.
    let pretty_arg = format!("--pretty=format:{GIT_LOG_COMMIT_MARKER}%s");
    let since_arg = hotspot_since_arg(head_commit_epoch(git_bin, git_dir, repo_root).await);
    let git_dir_arg = format!("--git-dir={}", git_dir.display());
    let args = [
        "--no-pager",
        git_dir_arg.as_str(),
        "log",
        // Defense in depth: even if Git learns another signature-related
        // config key, history inspection must never invoke a GPG helper.
        "--no-show-signature",
        "--no-ext-diff",
        "--no-textconv",
        // Rename detection would read blob contents, which a partial clone
        // may lack; a renamed file is listed under both of its paths instead.
        "--no-renames",
        since_arg.as_str(),
        GIT_HISTORY_MAX_COMMITS,
        "--no-merges",
        "--name-only",
        pretty_arg.as_str(),
    ];
    let output = crate::audit::scanners::run_bounded_subprocess(
        git_bin,
        &args,
        repo_root,
        &crate::audit::scanners::SubprocessLimits {
            timeout: GIT_HISTORY_TIMEOUT,
            max_output_bytes: GIT_HISTORY_OUTPUT_CAP,
        },
    )
    .await;
    git_history_from_outcome(output)
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
    fn walk_skips_os_metadata_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/app.py"), "print(1)").unwrap();
        for junk in [".DS_Store", "src/._app.py", "Thumbs.db", "src/desktop.ini"] {
            std::fs::write(root.join(junk), [0u8, 1, 2, 3]).unwrap();
        }
        let mut files = walk_repo_files(root);
        files.sort();
        assert_eq!(files, vec!["src/app.py".to_string()]);
    }

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
                assert!(reason.contains("self-contained") || reason.contains("git not found"));
            }
            GitHistoryStatus::Available { .. } => panic!("expected Unavailable for a non-git dir"),
        }
    }

    #[tokio::test]
    async fn git_history_refuses_external_gitdir_files_before_invoking_git() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".git"), "gitdir: /outside/repository\n").unwrap();
        let status = compute_git_history(dir.path()).await;
        match status {
            GitHistoryStatus::Unavailable { reason } => {
                assert!(reason.contains("self-contained"), "{reason}");
            }
            GitHistoryStatus::Available { .. } => panic!("external gitdir must be refused"),
        }
    }

    #[tokio::test]
    async fn git_history_refuses_bom_prefixed_include_config() {
        let dir = tempfile::tempdir().unwrap();
        if crate::audit::scanners::git_for_security_test(dir.path()).is_none() {
            return;
        }
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git/config"),
            "\u{feff}[include]\n\tpath = /outside/attacker-config\n",
        )
        .unwrap();
        let status = compute_git_history(dir.path()).await;
        match status {
            GitHistoryStatus::Unavailable { reason } => {
                assert!(reason.contains("self-contained"), "{reason}");
            }
            GitHistoryStatus::Available { .. } => panic!("BOM include config must be refused"),
        }
    }

    #[tokio::test]
    async fn git_history_refuses_signature_helper_config() {
        let dir = tempfile::tempdir().unwrap();
        if crate::audit::scanners::git_for_security_test(dir.path()).is_none() {
            return;
        }
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git/config"),
            "[log]\n\tshowSignature = true\n[gpg]\n\tprogram = /tmp/attacker-gpg\n",
        )
        .unwrap();
        let status = compute_git_history(dir.path()).await;
        match status {
            GitHistoryStatus::Unavailable { reason } => {
                assert!(reason.contains("unsafe Git config key"), "{reason}");
            }
            GitHistoryStatus::Available { .. } => panic!("signature helper config must be refused"),
        }
    }

    #[test]
    fn executable_git_config_keys_are_rejected_structurally() {
        for key in [
            "include.path",
            "includeIf.gitdir:/tmp.path",
            "diff.owned.textconv",
            "filter.owned.process",
            "core.fsmonitor",
            "log.showSignature",
            "gpg.program",
            "gpg.openpgp.program",
            "gpg.x509.program",
            "gpg.ssh.program",
        ] {
            assert!(forbidden_git_config_key(key), "missed {key}");
        }
        assert!(!forbidden_git_config_key("remote.origin.url"));
        assert!(!forbidden_git_config_key("branch.main.merge"));
    }

    #[test]
    fn transport_and_credential_git_config_keys_are_rejected() {
        for key in [
            "extensions.preciousObjects",
            "extensions.noop",
            "extensions.someFutureExtension",
            "remote.origin.uploadpack",
            "remote.origin.uploadPack",
            "remote.origin.receivepack",
            "remote.origin.receivePack",
            "remote.origin.vcs",
            "REMOTE.ORIGIN.VCS",
            "protocol.allow",
            "protocol.version",
            "protocol.ext.allow",
            "Protocol.File.Allow",
            "credential.helper",
            "credential.https://example.com.helper",
            "Credential.UseHttpPath",
            "core.sshCommand",
            "core.gitProxy",
            "CORE.GITPROXY",
            "uploadpack.packObjectsHook",
            "uploadPack.allowFilter",
            " remote.x.uploadpack ",
        ] {
            assert!(forbidden_git_config_key(key), "missed {key}");
        }
        for key in [
            "extensions.objectFormat",
            "EXTENSIONS.OBJECTFORMAT",
            "extensions.compatObjectFormat",
            "extensions.refStorage",
            "extensions.worktreeConfig",
            "extensions.relativeWorktrees",
            // Partial clones (`git clone --filter`, actions/checkout `filter:`).
            "extensions.partialClone",
            "EXTENSIONS.PARTIALCLONE",
            "remote.x.promisor",
            "Remote.Origin.Promisor",
            "remote.a.b.promisor",
            "remote.origin.partialCloneFilter",
            "remote.origin.partialclonefilter",
            "core.repositoryformatversion",
            "remote.origin.url",
            "remote.origin.pushurl",
            "remote.origin.fetch",
            "remote.promisor.url",
            "remote.pushDefault",
            "fetch.prune",
            "branch.main.remote",
            "url.https://mirror.example/.insteadOf",
        ] {
            assert!(!forbidden_git_config_key(key), "wrongly refused {key}");
        }
    }

    #[test]
    fn transport_helper_urls_and_rewrites_are_rejected() {
        for (key, value) in [
            ("remote.origin.url", "ext::sh -c touch% /tmp/x"),
            ("remote.origin.url", " EXT::sh"),
            ("Remote.Origin.PushURL", "ext::sh"),
            ("remote.a.b.url", "fd::17"),
            ("remote.origin.url", "custom::https://example.com/r"),
        ] {
            assert!(
                forbidden_git_config_value(key, value),
                "missed {key}={value}"
            );
        }
        for key in [
            "url.ext::sh -c touch.insteadOf",
            "url.custom::x.pushInsteadOf",
        ] {
            assert!(forbidden_git_config_key(key), "missed {key}");
        }
        for (key, value) in [
            ("remote.origin.url", "https://github.com/o/r.git"),
            ("remote.origin.url", "git@github.com:o/r.git"),
            ("remote.origin.url", "/srv/repo.git"),
            ("remote.origin.pushurl", "ssh://git@example.com/r"),
            ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
            ("branch.main.description", "a::b"),
        ] {
            assert!(
                !forbidden_git_config_value(key, value),
                "wrongly refused {key}"
            );
        }
    }

    /// `url.<base>.insteadOf` rewrites a matching remote into `<base>`, so a
    /// helper form is refused in the key's base and in the value. Nothing
    /// here runs Git; the helper commands are only inspected.
    #[test]
    fn url_rewrites_with_transport_helpers_are_rejected() {
        for key in [
            "url.ext::sh -c touch% /tmp/x.insteadOf",
            "URL.EXT::sh.InsteadOf",
            "url.fd::17.pushInsteadOf",
            "url.custom::https://example.com/.PUSHINSTEADOF",
        ] {
            assert!(forbidden_git_config_key(key), "missed {key}");
        }
        for (key, value) in [
            ("url.https://mirror.example/.insteadOf", "ext::sh -c x"),
            ("url.https://mirror.example/.pushInsteadOf", " Custom::x"),
            ("URL.https://m/.PushInsteadOf", "fd::17"),
        ] {
            assert!(
                forbidden_git_config_value(key, value),
                "missed {key}={value}"
            );
        }
        for (key, value) in [
            (
                "url.https://mirror.example/.insteadOf",
                "https://github.com/",
            ),
            ("url.https://mirror.example/.pushInsteadOf", "ssh://[::1]/x"),
            ("url.ssh://[::1]/x.insteadOf", "https://example.com/"),
        ] {
            assert!(!forbidden_git_config_key(key), "wrongly refused {key}");
            assert!(
                !forbidden_git_config_value(key, value),
                "wrongly refused {key}={value}"
            );
        }
    }

    #[test]
    fn ipv6_remote_urls_are_not_transport_helpers() {
        for value in [
            "ssh://[::1]/x",
            "ssh://git@[::1]:2222/repo.git",
            "https://[fe80::1%25en0]/r.git",
            "git://[::ffff:127.0.0.1]/r",
            "[::1]:repo.git",
        ] {
            assert!(!is_transport_helper_url(value), "wrongly refused {value}");
            for key in ["remote.origin.url", "remote.origin.pushurl"] {
                assert!(!forbidden_git_config_value(key, value), "{key}={value}");
            }
        }
        for value in [
            "ext::sh",
            "fd::17",
            "a::b",
            "9p::x",
            "git+ssh.v2-x::y",
            "\tEXT::sh",
        ] {
            assert!(is_transport_helper_url(value), "missed {value}");
        }
        for value in ["", "::", "-x::y", "+x::y", "a:b::c", "a/b::c", "a b::c"] {
            assert!(!is_transport_helper_url(value), "wrongly refused {value}");
        }
    }

    /// Legacy `remotes/` and `branches/` files are inspected, never used.
    #[test]
    fn legacy_remote_files_with_transport_helpers_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(git_dir.join("remotes")).unwrap();
        std::fs::create_dir_all(git_dir.join("branches")).unwrap();
        validate_legacy_remotes(&git_dir).unwrap();
        let remote = git_dir.join("remotes/origin");
        let branch = git_dir.join("branches/x");
        std::fs::write(
            &remote,
            "URL: https://example.com/r.git\nPull: refs/heads/main:refs/heads/origin\n",
        )
        .unwrap();
        std::fs::write(&branch, "ssh://[::1]/repo#main\n").unwrap();
        validate_legacy_remotes(&git_dir).unwrap();

        std::fs::write(&remote, "URL: ext::sh -c x\n").unwrap();
        let error = validate_legacy_remotes(&git_dir).unwrap_err();
        assert!(
            error.contains("transport-helper") && error.contains("remotes/"),
            "{error}"
        );
        assert!(!error.contains("origin"), "{error}");
        std::fs::write(&remote, "URL: https://example.com/r.git\nurl:fd::17\n").unwrap();
        assert!(validate_legacy_remotes(&git_dir).is_err());
        std::fs::write(&remote, "URL: https://example.com/r.git\n").unwrap();

        std::fs::write(&branch, "ext::sh -c x#main\n").unwrap();
        let error = validate_legacy_remotes(&git_dir).unwrap_err();
        assert!(
            error.contains("transport-helper") && error.contains("branches/"),
            "{error}"
        );
        std::fs::write(&branch, "https://example.com/r.git#main\n").unwrap();
        validate_legacy_remotes(&git_dir).unwrap();

        // Remote names may contain '/', so nested files count too.
        std::fs::create_dir(git_dir.join("remotes/team")).unwrap();
        std::fs::write(git_dir.join("remotes/team/origin"), "URL: custom::x\n").unwrap();
        assert!(validate_legacy_remotes(&git_dir).is_err());
        std::fs::remove_dir_all(git_dir.join("remotes/team")).unwrap();

        // Oversized files fail closed instead of being partly inspected.
        let big = git_dir.join("remotes/big");
        std::fs::write(&big, vec![b'a'; MAX_LEGACY_REMOTE_BYTES as usize + 1]).unwrap();
        assert!(
            validate_legacy_remotes(&git_dir)
                .unwrap_err()
                .contains("validation limit")
        );
        std::fs::remove_file(&big).unwrap();
        validate_legacy_remotes(&git_dir).unwrap();

        #[cfg(unix)]
        {
            let target = dir.path().join("target");
            std::fs::write(&target, "URL: https://example.com/r.git\n").unwrap();
            std::os::unix::fs::symlink(&target, git_dir.join("branches/link")).unwrap();
            assert!(
                validate_legacy_remotes(&git_dir)
                    .unwrap_err()
                    .contains("symlink")
            );
            std::fs::remove_file(git_dir.join("branches/link")).unwrap();
            std::fs::remove_dir_all(git_dir.join("branches")).unwrap();
            std::os::unix::fs::symlink(dir.path(), git_dir.join("branches")).unwrap();
            assert!(
                validate_legacy_remotes(&git_dir)
                    .unwrap_err()
                    .contains("symlink")
            );
        }
    }

    /// The production entry point refuses a legacy remote helper too.
    #[tokio::test]
    async fn prepare_readonly_git_refuses_legacy_remote_helpers() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if crate::audit::scanners::git_for_security_test(root).is_none() {
            return;
        }
        crate::audit::diff_scope::tests::git(root, &["init", "-q"]).await;
        prepare_readonly_git(root).await.unwrap();
        for (path, content) in [
            ("remotes/origin", "URL: ext::sh -c x\n"),
            ("branches/x", "ext::sh -c x\n"),
        ] {
            let file = root.join(".git").join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, content).unwrap();
            let error = prepare_readonly_git(root).await.unwrap_err();
            assert!(error.contains("transport-helper"), "{error}");
            std::fs::remove_file(&file).unwrap();
        }
        prepare_readonly_git(root).await.unwrap();
    }

    #[tokio::test]
    async fn sha256_object_format_extension_is_still_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let Some(git) = crate::audit::scanners::git_for_security_test(dir.path()) else {
            return;
        };
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectFormat = sha256\n",
        )
        .unwrap();
        validate_git_configs(&git, &dir.path().join(".git"), dir.path())
            .await
            .unwrap();
    }

    /// A partial clone (`git clone --filter`) is accepted. One whose promisor
    /// upload-pack is a shell command is refused, and with validation bypassed
    /// neither a raw object read nor the production history/diff reads may
    /// run that command for a missing blob or tree.
    #[cfg(unix)]
    #[tokio::test]
    async fn partial_clone_is_accepted_but_never_lazily_fetches() {
        use crate::audit::diff_scope;
        use crate::audit::scanners::{GIT_SAFE_ENV, git_test_command, git_test_command_bare};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let Some(git) = crate::audit::scanners::git_for_security_test(&root) else {
            return;
        };
        let marker = dir.path().join("marker");
        let fixture = |args: &[&str]| {
            let out = git_test_command(&git)
                .arg("-C")
                .arg(&root)
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        fixture(&["init", "-q"]);
        std::fs::write(root.join("secret.txt"), "only in the promisor\n").unwrap();
        fixture(&["add", "secret.txt"]);
        fixture(&["commit", "-qm", "base"]);
        std::fs::write(root.join("secret.txt"), "still only in the promisor\n").unwrap();
        fixture(&["commit", "-qam", "fix: auth bypass"]);
        let blob = fixture(&["rev-parse", "HEAD:secret.txt"]);
        let blob = blob.trim();
        let tree = fixture(&["rev-parse", "HEAD^{tree}"]);
        let tree = tree.trim();
        let remote_url = dir.path().display().to_string();
        for (key, value) in [
            ("core.repositoryformatversion", "1"),
            ("extensions.partialClone", "x"),
            ("remote.x.promisor", "true"),
            ("remote.x.partialclonefilter", "blob:none"),
            ("remote.x.url", remote_url.as_str()),
        ] {
            fixture(&["config", key, value]);
        }

        // (a) A plain partial clone is accepted and its history is readable.
        prepare_readonly_git(&root).await.unwrap();
        match compute_git_history(&root).await {
            GitHistoryStatus::Available { hotspots } => {
                assert_eq!(hotspots.len(), 1, "{hotspots:?}");
                assert_eq!(hotspots[0].file, "secret.txt");
            }
            GitHistoryStatus::Unavailable { reason } => panic!("partial clone refused: {reason}"),
        }

        // (b) A promisor transport command is refused before any object read.
        let upload_pack = format!("sh -c 'touch {}; exit 1' #", marker.display());
        fixture(&["config", "remote.x.uploadpack", &upload_pack]);
        let refused = prepare_readonly_git(&root).await.unwrap_err();
        assert!(refused.contains("unsafe Git config key"), "{refused}");
        assert!(!marker.exists(), "config validation triggered a fetch");
        for oid in [blob, tree] {
            let loose = root.join(".git/objects").join(&oid[..2]).join(&oid[2..]);
            std::fs::remove_file(loose).unwrap();
        }

        // (c) Bypass validation: the production reads must not lazily fetch
        // the missing tree (`git log --name-only`, `git diff`).
        let git_dir = root.join(".git");
        let history = git_history_with(&git, &git_dir, &root).await;
        assert!(
            matches!(history, GitHistoryStatus::Unavailable { .. }),
            "{history:?}"
        );
        let state = diff_scope::repo_state_with(&git, &git_dir, &root).await;
        assert!(state.is_err());
        let scope = diff_scope::compute_with(&git, &git_dir, &root, "HEAD~1").await;
        assert!(scope.is_err(), "{scope:?}");
        assert!(!marker.exists(), "production Git reads ran the upload-pack");

        // (d) Bypass validation: a raw blob read must not lazily fetch either.
        let git_dir_arg = format!("--git-dir={}", root.join(".git").display());
        let read_blob = [
            "--no-pager",
            "--no-replace-objects",
            git_dir_arg.as_str(),
            "cat-file",
            "-p",
            blob,
        ];
        let out = crate::audit::scanners::run_bounded_subprocess(
            &git,
            &read_blob,
            &root,
            &crate::audit::scanners::SubprocessLimits {
                timeout: std::time::Duration::from_secs(20),
                max_output_bytes: 64 * 1024,
            },
        )
        .await;
        assert!(out.spawn_error.is_none() && !out.timed_out, "{out:?}");
        assert_ne!(out.exit_code, Some(0), "missing blob was read: {out:?}");
        assert!(
            !marker.exists(),
            "sanitized git ran the repository's upload-pack"
        );

        // Direct reads start from no inherited GIT_* at all, so each layer is
        // tested alone (no command-scoped config override either).
        let direct_read = |env: &[(&str, &str)]| {
            git_test_command_bare(&git)
                .args(read_blob)
                .current_dir(&root)
                .envs(env.iter().copied())
                .output()
                .unwrap()
        };
        // Git older than 2.44 ignores GIT_NO_LAZY_FETCH; the protocol
        // allow-list alone must still refuse the promisor transport.
        let without_lazy_flag: Vec<_> = GIT_SAFE_ENV
            .iter()
            .copied()
            .filter(|(name, _)| *name != "GIT_NO_LAZY_FETCH")
            .collect();
        direct_read(&without_lazy_flag);
        assert!(
            !marker.exists(),
            "GIT_ALLOW_PROTOCOL did not block the fetch"
        );
        // On Git 2.44+, GIT_NO_LAZY_FETCH alone must also prevent the fetch.
        if crate::audit::scanners::git_version(&git).is_some_and(|v| v >= (2, 44)) {
            let without_protocol_block: Vec<_> = GIT_SAFE_ENV
                .iter()
                .copied()
                .filter(|(name, _)| *name != "GIT_ALLOW_PROTOCOL")
                .collect();
            direct_read(&without_protocol_block);
            assert!(
                !marker.exists(),
                "GIT_NO_LAZY_FETCH did not block the fetch"
            );
        }

        // Control: the previous environment really runs the command, so the
        // assertions above are not vacuous for this Git and fixture.
        direct_read(&[
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_OPTIONAL_LOCKS", "0"),
        ]);
        assert!(marker.exists(), "fixture did not reproduce the lazy fetch");
    }

    #[test]
    fn truncated_or_timed_out_git_history_is_never_treated_as_complete() {
        let base = crate::audit::scanners::SubprocessOutcome {
            stdout: format!("{GIT_LOG_COMMIT_MARKER}fix: auth\nsrc/auth.rs\n"),
            stdout_truncated: true,
            stderr_tail: String::new(),
            exit_code: Some(0),
            duration: std::time::Duration::from_secs(1),
            timed_out: false,
            spawn_error: None,
            cleanup_error: None,
        };
        assert!(matches!(
            git_history_from_outcome(base.clone()),
            GitHistoryStatus::Unavailable { .. }
        ));
        let mut timed_out = base;
        timed_out.stdout_truncated = false;
        timed_out.timed_out = true;
        assert!(matches!(
            git_history_from_outcome(timed_out),
            GitHistoryStatus::Unavailable { .. }
        ));
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
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let Some(binary) = crate::util::which_cli_for_scan("git", root) else {
            return;
        };
        // Every commit is two years old: a now-anchored window sees nothing.
        let old = "2024-06-01T12:00:00+00:00";
        let git = |args: &[&str]| {
            let out = crate::audit::scanners::git_test_command(&binary)
                .arg("-C")
                .arg(root)
                .args(args)
                .env("GIT_AUTHOR_DATE", old)
                .env("GIT_COMMITTER_DATE", old)
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
