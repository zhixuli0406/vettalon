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
        // Only a regular `.gitignore` of at most 1 MiB is read (a FIFO would
        // block the scan; Git itself does not follow a symlinked one).
        // Anything else is ignored, which only skips fewer directories.
        const MAX_GITIGNORE_BYTES: u64 = 1024 * 1024;
        if !root.join(".git").exists() {
            return Self::default();
        }
        match crate::util::read_regular_file(&root.join(".gitignore"), MAX_GITIGNORE_BYTES) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => Self::parse(&text),
                Err(_) => Self::default(),
            },
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

/// `git log` reads the mailmap by default since Git 2.29 (`log.mailmap`),
/// opening `.mailmap` and the file `mailmap.file` names. `--no-use-mailmap`
/// is the spelling every Git since 1.8.2 accepts (`--no-mailmap` is only an
/// alias since 2.29); `log.mailmap=false` and `mailmap.file` are also
/// overridden for every Git process (`scanners/exec.rs`).
const GIT_LOG_NO_MAILMAP: &str = "--no-use-mailmap";

/// Committer date of HEAD as a unix timestamp, or `None` on any failure.
async fn head_commit_epoch(git_bin: &str, git_dir: &Path, repo_root: &Path) -> Option<i64> {
    let git_dir_arg = format!("--git-dir={}", git_dir.display());
    let out = crate::audit::scanners::run_bounded_subprocess(
        git_bin,
        &[
            "--no-pager",
            git_dir_arg.as_str(),
            "log",
            GIT_LOG_NO_MAILMAP,
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

fn is_url_scheme_byte(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || b"+.-".contains(byte)
}

/// `ext::<command>` and other `<helper>::<address>` URLs run a transport
/// helper: a scheme-like prefix (`[A-Za-z0-9+.-]*`, possibly empty, so `::x`
/// selects the helper named "") directly followed by `::` at the start.
/// Git itself wants an alphanumeric first byte; accepting `+`, `.` and `-`
/// there too only refuses more. Leading whitespace is skipped to stay
/// conservative. An IPv6 literal such as `ssh://[::1]/repo` is not a helper.
fn is_transport_helper_url(value: &str) -> bool {
    let value = value.trim_start().as_bytes();
    let scheme_len = value.iter().take_while(|b| is_url_scheme_byte(b)).count();
    value[scheme_len..].starts_with(b"::")
}

/// Schemes Git handles without an external `git-remote-<scheme>` helper of
/// the repository's choosing (http(s)/ftp(s) use Git's bundled curl helper).
const ALLOWED_URL_SCHEMES: &[&str] = &[
    "http", "https", "ftp", "ftps", "ssh", "git", "file", "git+ssh", "ssh+git",
];

/// The scheme of a `<scheme>://` URL as Git recognises one
/// (`[A-Za-z0-9][A-Za-z0-9+.-]*://`), or `None` for scp-like addresses and
/// local paths.
fn url_scheme(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if !bytes.first()?.is_ascii_alphanumeric() {
        return None;
    }
    let len = 1 + bytes[1..]
        .iter()
        .take_while(|b| is_url_scheme_byte(b))
        .count();
    value[len..].starts_with("://").then_some(&value[..len])
}

/// A URL Git would hand to a transport helper: a `<helper>::<address>` form,
/// or a `<scheme>://` URL whose scheme is not in [`ALLOWED_URL_SCHEMES`]
/// (Git runs `git-remote-<scheme>` for those, e.g. `ext://…`). Git's
/// built-in transports match the scheme case-sensitively (`FILE://` runs
/// `git-remote-FILE`), so only the lowercase spellings are accepted. scp-like
/// `user@host:path` addresses and local paths are accepted.
fn is_unsafe_remote_url(value: &str) -> bool {
    let value = value.trim_start();
    is_transport_helper_url(value)
        || url_scheme(value).is_some_and(|scheme| !ALLOWED_URL_SCHEMES.contains(&scheme))
}

/// The `<base>` of a `url.<base>.insteadOf` / `url.<base>.pushInsteadOf`
/// key, which is the rewrite target. Expects a lowercased, trimmed key.
fn url_rewrite_base(key: &str) -> Option<&str> {
    key.strip_prefix("url.")
        .and_then(|rest| rest.rsplit_once('.'))
        .filter(|(_, var)| *var == "insteadof" || *var == "pushinsteadof")
        .map(|(base, _)| base)
}

/// Split `<section>.<subsection>.<var>` as `git config --list` prints it:
/// section and variable lowercased, the subsection kept verbatim (Git keeps
/// its case, and it may contain dots). `None` without a subsection.
fn split_config_key(key: &str) -> Option<(String, &str, String)> {
    let (section, rest) = key.trim().split_once('.')?;
    let (subsection, var) = rest.rsplit_once('.')?;
    Some((
        section.to_ascii_lowercase(),
        subsection,
        var.to_ascii_lowercase(),
    ))
}

/// Value-dependent refusals, applied after [`forbidden_git_config_key`].
fn forbidden_git_config_value(key: &str, value: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    let remote_url = key
        .strip_prefix("remote.")
        .and_then(|rest| rest.rsplit_once('.'))
        .is_some_and(|(_, var)| var == "url" || var == "pushurl");
    if remote_url {
        return is_unsafe_remote_url(value);
    }
    url_rewrite_base(&key).is_some() && is_transport_helper_url(value)
}

/// The repository's `url.<base>.insteadOf` / `pushInsteadOf` rules, in
/// config order, plus the bytes the rewrite checks have read so far.
#[derive(Debug, Default)]
struct UrlRewrites {
    instead_of: Vec<RewriteRule>,
    push_instead_of: Vec<RewriteRule>,
    /// Charged by [`UrlRewrites::any_rewrite_unsafe`]; one `UrlRewrites`
    /// is built per `validate_git_configs` run, so this is a per-run total.
    checked_bytes: std::cell::Cell<usize>,
}

/// One `url.<base>.insteadOf` / `pushInsteadOf` rule: `prefix` is the
/// config value, `base` the rewrite target.
#[derive(Debug)]
struct RewriteRule {
    prefix: String,
    base: String,
    shape: BaseShape,
}

impl RewriteRule {
    fn new(prefix: String, base: String) -> Self {
        let shape = BaseShape::of(&base);
        Self {
            prefix,
            base,
            shape,
        }
    }
}

/// Every checked value is matched against every rewrite rule, so both are
/// capped; a repository above a cap is refused instead of being checked
/// for an unbounded time.
const MAX_URL_REWRITE_RULES: usize = 256;
/// Remote URLs, push URLs and remote-name values combined.
const MAX_REMOTE_REF_VALUES: usize = 1024;
/// Defense in depth on top of the count caps: bytes the rewrite checks may
/// read in one `validate_git_configs` run (prefix comparisons plus the
/// URL tail after the matched prefix). Each tied base is then decided in
/// constant time, independent of its length. A repository above this is
/// refused.
const MAX_URL_REWRITE_CHECK_BYTES: usize = 16 * 1024 * 1024;

/// What [`is_unsafe_remote_url`] can see of a rewrite base, computed once
/// per rule so that checking `base + rest` never builds or rescans the base.
///
/// `is_unsafe_remote_url(v)` depends only on `t = v.trim_start()`: it
/// takes the maximal leading run of scheme bytes (`[A-Za-z0-9+.-]*`) of
/// `t`, and refuses if the bytes after that run start with `::`, or if `t`
/// starts with an ASCII alphanumeric, the bytes after the run start with
/// `://` and the run is not an allowed scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseShape {
    /// `base.trim_start()` is empty (Unicode whitespace or nothing), so
    /// trimming `base + rest` continues into `rest` and the check sees
    /// exactly `rest.trim_start()`.
    Blank,
    /// The trimmed base contains a non-scheme byte at `base[tail]`, so the
    /// run ends inside the base. The decision then needs only the at most
    /// three bytes after the run (from `base[tail..]`, then `rest`), and
    /// `scheme_unsafe` = the trimmed base starts with an ASCII alphanumeric
    /// and its run is not an allowed scheme.
    Closed { tail: usize, scheme_unsafe: bool },
    /// The trimmed base `base[start..]` is non-empty and all scheme bytes,
    /// so the run continues through the leading scheme bytes of `rest`.
    Open { start: usize },
}

impl BaseShape {
    fn of(base: &str) -> Self {
        let trimmed = base.trim_start();
        let start = base.len() - trimmed.len();
        let bytes = trimmed.as_bytes();
        let Some(first) = bytes.first() else {
            return Self::Blank;
        };
        let run = bytes.iter().take_while(|b| is_url_scheme_byte(b)).count();
        if run == bytes.len() {
            return Self::Open { start };
        }
        // With an alphanumeric first byte `url_scheme`'s scheme is exactly
        // this run; otherwise it returns `None`.
        let scheme_unsafe =
            first.is_ascii_alphanumeric() && !ALLOWED_URL_SCHEMES.contains(&&trimmed[..run]);
        Self::Closed {
            tail: start + run,
            scheme_unsafe,
        }
    }
}

/// What [`is_unsafe_remote_url`] can see of the URL tail after a matched
/// prefix, computed once per checked value and rule set.
struct RestShape<'a> {
    rest: &'a str,
    /// Leading scheme bytes of `rest`, untrimmed (ASCII, so a char boundary).
    run: usize,
    /// `is_unsafe_remote_url(rest)`, the answer for a [`BaseShape::Blank`].
    unsafe_alone: bool,
}

impl<'a> RestShape<'a> {
    fn of(rest: &'a str) -> Self {
        Self {
            rest,
            run: rest
                .as_bytes()
                .iter()
                .take_while(|b| is_url_scheme_byte(b))
                .count(),
            unsafe_alone: is_unsafe_remote_url(rest),
        }
    }
}

/// Whether `head + rest` starts with `pattern`, reading at most
/// `pattern.len()` bytes and without joining the two.
fn joined_starts_with(head: &[u8], rest: &[u8], pattern: &[u8]) -> bool {
    let split = head.len().min(pattern.len());
    head[..split] == pattern[..split] && rest.starts_with(&pattern[split..])
}

/// Whether `head + tail` is an allowed scheme, without joining the two.
/// The length test comes first, so at most one allowed scheme's length
/// worth of bytes is compared per entry.
fn is_allowed_joined_scheme(head: &str, tail: &str) -> bool {
    ALLOWED_URL_SCHEMES.iter().any(|scheme| {
        scheme.len() == head.len() + tail.len()
            && scheme.starts_with(head)
            && scheme.ends_with(tail)
    })
}

/// Exactly `is_unsafe_remote_url(&format!("{base}{rest}"))`, in constant
/// time once `shape` (of `base`) and `rest` are precomputed:
///
/// - `Blank`: `(base + rest).trim_start() == rest.trim_start()`, and the
///   check only sees the trimmed value, so the answer is `rest`'s own.
/// - `Closed`: trimming stops inside the base, at the same byte as for the
///   base alone. The run is `base[start..tail]`, and the bytes after it are
///   `base[tail..] + rest`; both tests (`::`, and `://` for an alphanumeric
///   first byte and a disallowed scheme, which is `scheme_unsafe`) read at
///   most three of those bytes.
/// - `Open`: trimming stops inside the base, and the base after it is all
///   scheme bytes, so the run is `base[start..] + rest[..run]` and the
///   bytes after it are `rest[run..]`. The first byte is the base's, and
///   the scheme is compared against the allow-list without joining it.
fn rewrite_unsafe(base: &str, shape: BaseShape, rest: &RestShape) -> bool {
    match shape {
        BaseShape::Blank => rest.unsafe_alone,
        BaseShape::Closed {
            tail,
            scheme_unsafe,
        } => {
            let head = &base.as_bytes()[tail..];
            let rest = rest.rest.as_bytes();
            joined_starts_with(head, rest, b"::")
                || (scheme_unsafe && joined_starts_with(head, rest, b"://"))
        }
        BaseShape::Open { start } => {
            let trimmed = &base[start..];
            let after = &rest.rest.as_bytes()[rest.run..];
            after.starts_with(b"::")
                || (trimmed.as_bytes()[0].is_ascii_alphanumeric()
                    && after.starts_with(b"://")
                    && !is_allowed_joined_scheme(trimmed, &rest.rest[..rest.run]))
        }
    }
}

impl UrlRewrites {
    /// Refused above [`MAX_URL_REWRITE_RULES`] rules (`insteadOf` and
    /// `pushInsteadOf` together).
    fn from_entries(entries: &[(String, String)]) -> Result<Self, String> {
        let mut out = Self::default();
        for (key, value) in entries {
            let Some((section, base, var)) = split_config_key(key) else {
                continue;
            };
            if section != "url" {
                continue;
            }
            let rule = || RewriteRule::new(value.clone(), base.to_string());
            match var.as_str() {
                "insteadof" => out.instead_of.push(rule()),
                "pushinsteadof" => out.push_instead_of.push(rule()),
                _ => continue,
            }
            if out.instead_of.len() + out.push_instead_of.len() > MAX_URL_REWRITE_RULES {
                return Err(format!(
                    "URL rewrite rules exceed the validation limit of {MAX_URL_REWRITE_RULES}"
                ));
            }
        }
        Ok(out)
    }

    /// Whether any URL Git may rewrite `url` into is unsafe
    /// ([`is_unsafe_remote_url`]). Git applies one rewrite, the longest
    /// matching prefix: `insteadOf` for fetch URLs and push URLs, and
    /// `pushInsteadOf` (falling back to `insteadOf`) when a remote's fetch
    /// URL doubles as its push URL. Both rule sets are applied to every
    /// value, which covers each of those paths; every base tied on the
    /// longest prefix is checked rather than guessing Git's tie-break.
    ///
    /// No rewritten URL is built: each tied base is decided by
    /// [`rewrite_unsafe`] in constant time, so the cost per value is the
    /// prefix comparisons plus one scan of the tail after the prefix,
    /// whatever the bases' lengths. Those bytes are charged against
    /// [`MAX_URL_REWRITE_CHECK_BYTES`]; above it this is an error.
    fn any_rewrite_unsafe(&self, url: &str) -> Result<bool, String> {
        Ok(self.longest_prefix_rewrite_unsafe(&self.instead_of, url)?
            || self.longest_prefix_rewrite_unsafe(&self.push_instead_of, url)?)
    }

    /// [`Self::any_rewrite_unsafe`] for one rule set.
    fn longest_prefix_rewrite_unsafe(
        &self,
        rules: &[RewriteRule],
        url: &str,
    ) -> Result<bool, String> {
        if rules.is_empty() {
            return Ok(false);
        }
        // `starts_with` reads at most this much per rule; there are two
        // passes over the rules.
        let compared = rules
            .iter()
            .map(|rule| rule.prefix.len().min(url.len()))
            .fold(0usize, usize::saturating_add);
        self.charge(compared.saturating_mul(2))?;
        let Some(longest) = rules
            .iter()
            .filter(|rule| url.starts_with(rule.prefix.as_str()))
            .map(|rule| rule.prefix.len())
            .max()
        else {
            return Ok(false);
        };
        let rest = &url[longest..];
        self.charge(rest.len())?;
        let rest = RestShape::of(rest);
        Ok(rules
            .iter()
            .filter(|rule| rule.prefix.len() == longest && url.starts_with(rule.prefix.as_str()))
            .any(|rule| rewrite_unsafe(&rule.base, rule.shape, &rest)))
    }

    fn charge(&self, bytes: usize) -> Result<(), String> {
        let used = self.checked_bytes.get().saturating_add(bytes);
        self.checked_bytes.set(used);
        if used > MAX_URL_REWRITE_CHECK_BYTES {
            return Err(format!(
                "URL rewrite checks exceed the validation limit of {MAX_URL_REWRITE_CHECK_BYTES} bytes"
            ));
        }
        Ok(())
    }
}

/// A config value Git may use as a remote URL: `remote.<n>.url`,
/// `remote.<n>.pushurl` and `submodule.<n>.url` are URLs;
/// `branch.<b>.remote`, `branch.<b>.pushRemote`, `remote.pushDefault` and
/// `extensions.partialClone` name a remote, which Git uses as a URL when it
/// does not count that remote as configured.
fn is_remote_ref(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    if lower == "remote.pushdefault" || lower == "extensions.partialclone" {
        return true;
    }
    let Some((section, _, var)) = split_config_key(key) else {
        return false;
    };
    matches!(
        (section.as_str(), var.as_str()),
        ("remote", "url" | "pushurl") | ("submodule", "url") | ("branch", "remote" | "pushremote")
    )
}

/// Refuse every config value Git may use as a remote URL if it, or what a
/// `url.<base>.insteadOf` / `pushInsteadOf` rule rewrites it into, would
/// start a transport helper. Remote names are always checked as URLs too,
/// even when a `remote.<name>.url` exists: whether Git counts that remote
/// as configured depends on more than its presence here (`config.worktree`
/// only counts with `extensions.worktreeConfig`, an empty `url` clears the
/// list). `.` and plain names such as `origin` contain no scheme and pass
/// unless a rewrite turns them into a helper URL. Refused above
/// [`MAX_REMOTE_REF_VALUES`] values. Only the key is reported.
fn validate_remote_refs(
    entries: &[(String, String)],
    rewrites: &UrlRewrites,
) -> Result<(), String> {
    let refs: Vec<(&str, &str)> = entries
        .iter()
        .filter(|(key, _)| is_remote_ref(key))
        .map(|(key, value)| (key.trim(), value.as_str()))
        .collect();
    if refs.len() > MAX_REMOTE_REF_VALUES {
        return Err(format!(
            "remote URL and remote name values exceed the validation limit of {MAX_REMOTE_REF_VALUES}"
        ));
    }
    for (key, value) in refs {
        if is_unsafe_remote_url(value) {
            return Err(format!("unsafe Git config value is not allowed for {key}"));
        }
        if rewrites.any_rewrite_unsafe(value)? {
            return Err(format!(
                "unsafe Git config value is not allowed for {key} after a URL rewrite"
            ));
        }
    }
    Ok(())
}

/// Keys that name a file Git may open while it reads a repository (a FIFO
/// there blocks the read; on Windows a `//host/share` path makes Git
/// contact an SMB server). `mailmap.blob` names a blob and is allowed.
const FORBIDDEN_FILE_KEYS: &[&str] = &[
    "mailmap.file",
    "diff.orderfile",
    "core.excludesfile",
    "core.attributesfile",
    "init.templatedir",
];

/// Keys that name a program Git may run (an editor, pager, prompt or
/// browser helper).
const FORBIDDEN_PROGRAM_KEYS: &[&str] = &[
    "core.askpass",
    "core.editor",
    "sequence.editor",
    "core.pager",
    "web.browser",
    "interactive.difffilter",
];

/// `http.<var>` / `http.<url>.<var>` variables that name a file Git opens
/// for a transport (certificates, keys, cookies). `extraheader` is not one
/// of them: actions/checkout's credentials file sets it.
const FORBIDDEN_HTTP_FILE_VARS: &[&str] = &[
    "cookiefile",
    "sslcert",
    "sslkey",
    "sslcainfo",
    "sslcapath",
    "proxysslcert",
    "proxysslkey",
    "proxysslcainfo",
];

fn forbidden_git_config_key(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    let remote_var = key
        .strip_prefix("remote.")
        .and_then(|rest| rest.rsplit_once('.'))
        .map(|(_, var)| var);
    let rewrite_base = url_rewrite_base(&key);
    // `http.<var>` or `http.<url>.<var>`; the URL may contain dots.
    let http_var = key
        .strip_prefix("http.")
        .map(|rest| rest.rsplit_once('.').map_or(rest, |(_, var)| var));
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
        // Names a file or program Git may open or run: path-valued settings.
        || FORBIDDEN_FILE_KEYS.contains(&key.as_str())
        // Names a file or program Git may open or run: helper programs.
        || FORBIDDEN_PROGRAM_KEYS.contains(&key.as_str())
        || key.starts_with("pager.")
        || (key.starts_with("merge.") && key.ends_with(".driver"))
        // Names a file or program Git may open or run: transport files.
        || http_var.is_some_and(|var| FORBIDDEN_HTTP_FILE_VARS.contains(&var))
}

/// Each legacy remote file is read up to this size; a larger one is refused.
const MAX_LEGACY_REMOTE_BYTES: u64 = 64 * 1024;
const MAX_LEGACY_REMOTE_ENTRIES: usize = 4096;
const MAX_LEGACY_REMOTE_DEPTH: usize = 16;
/// Bytes read across all legacy remote files (`remotes/` and `branches/`
/// together); more is refused.
const MAX_LEGACY_REMOTE_TOTAL_BYTES: u64 = 256 * 1024;
/// Lines checked across all legacy remote files (one per 64 bytes of the
/// total budget); every line is matched against every rewrite rule, so more
/// is refused.
const MAX_LEGACY_REMOTE_LINES: usize = 4096;

/// Git still reads a remote from `$GIT_DIR/remotes/<name>` (`URL:` lines)
/// and `$GIT_DIR/branches/<name>` (a bare URL). Git refuses a remote name
/// containing `/`, so it never reads a nested file; nested files are still
/// inspected so the check fails closed. Refuse a transport-helper URL in any
/// such file, before or after a `url.<base>.insteadOf` rewrite, and any
/// symlink or special file there, and fail closed above
/// [`MAX_LEGACY_REMOTE_TOTAL_BYTES`] or [`MAX_LEGACY_REMOTE_LINES`]. Links
/// are never followed and names never printed.
fn validate_legacy_remotes(git_dir: &Path, rewrites: &UrlRewrites) -> Result<(), String> {
    let mut visited = 0usize;
    let mut total_bytes = 0u64;
    let mut total_lines = 0usize;
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
            total_bytes += text.len() as u64;
            if total_bytes > MAX_LEGACY_REMOTE_TOTAL_BYTES {
                return Err(format!(
                    "legacy remote files exceed the total validation size limit of {MAX_LEGACY_REMOTE_TOTAL_BYTES} bytes"
                ));
            }
            total_lines += text.lines().count();
            if total_lines > MAX_LEGACY_REMOTE_LINES {
                return Err(format!(
                    "legacy remote files exceed the validation line limit of {MAX_LEGACY_REMOTE_LINES}"
                ));
            }
            if let Some(found) = legacy_remote_unsafe_url(&text, rewrites)? {
                let rewrite = match found {
                    UnsafeUrl::AsWritten => "",
                    UnsafeUrl::AfterRewrite => " after a URL rewrite",
                };
                return Err(format!(
                    "transport-helper URL is not allowed in a legacy remote file in {top}/{rewrite}"
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnsafeUrl {
    AsWritten,
    AfterRewrite,
}

/// Check every line, with or without a `URL:` prefix (case-insensitive), so
/// both the `remotes/` and the `branches/` formats are covered. A
/// `branches/` URL may end in `#<branch>`, so the part before `#` is
/// checked (and rewritten) too. Only the bytes Git's `isspace` skips (space,
/// `\t`, `\n`, `\r`) are trimmed: Rust's Unicode `trim` would also drop
/// e.g. U+000C, which Git keeps and an `insteadOf` prefix can match. An
/// error means the rewrite checks went over their byte budget.
fn legacy_remote_unsafe_url(
    text: &str,
    rewrites: &UrlRewrites,
) -> Result<Option<UnsafeUrl>, String> {
    let is_git_space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r');
    let mut found = None;
    for line in text.lines() {
        let line = line.trim_matches(is_git_space);
        let url = match line.get(..4) {
            Some(prefix) if prefix.eq_ignore_ascii_case("url:") => {
                line[4..].trim_start_matches(is_git_space)
            }
            _ => line,
        };
        let without_fragment = url.split_once('#').map_or(url, |(url, _)| url);
        // Without a `#` both candidates are the same string.
        let candidates = [
            Some(url),
            (without_fragment.len() != url.len()).then_some(without_fragment),
        ];
        for candidate in candidates.into_iter().flatten() {
            if is_unsafe_remote_url(candidate) {
                return Ok(Some(UnsafeUrl::AsWritten));
            }
            if found.is_none() && rewrites.any_rewrite_unsafe(candidate)? {
                found = Some(UnsafeUrl::AfterRewrite);
            }
        }
    }
    Ok(found)
}

/// Why [`list_git_config_file`] produced no listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigListingError {
    /// The system temp dir, where the empty `--git-dir` is created, lies
    /// inside the scanned repository.
    TempDirInsideRepository,
    /// Anything else: the empty directory or an absolute UTF-8 path could
    /// not be had, or Git failed, timed out or truncated its output.
    Failed,
}

/// Reported (failing closed) for [`ConfigListingError::TempDirInsideRepository`].
const TEMP_DIR_INSIDE_REPOSITORY: &str = if cfg!(windows) {
    "the system temporary directory is inside the scanned repository; set TMP to a directory outside it"
} else {
    "the system temporary directory is inside the scanned repository; set TMPDIR to a directory outside it"
};

/// A fresh, empty, private directory for [`list_git_config_file`] to use as
/// both `--git-dir` and working directory, removed when dropped. Created
/// under the system temp dir with a new random name (an existing directory
/// is never reused) and owner-only permissions on Unix. Fails with
/// [`ConfigListingError::TempDirInsideRepository`] when it would lie inside
/// `repo_root`, and [`ConfigListingError::Failed`] when it cannot be created
/// or resolved.
fn no_repository_dir(repo_root: &Path) -> Result<tempfile::TempDir, ConfigListingError> {
    no_repository_dir_in(&std::env::temp_dir(), repo_root)
}

/// [`no_repository_dir`] under an explicit base directory (tests).
fn no_repository_dir_in(
    base: &Path,
    repo_root: &Path,
) -> Result<tempfile::TempDir, ConfigListingError> {
    let root = std::fs::canonicalize(repo_root).map_err(|_| ConfigListingError::Failed)?;
    // Checked before creating anything, so nothing is written into the
    // scanned repository, and again on the created directory below.
    if std::fs::canonicalize(base).is_ok_and(|base| base.starts_with(&root)) {
        return Err(ConfigListingError::TempDirInsideRepository);
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix("vettalon-nogit-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let dir = builder
        .tempdir_in(base)
        .map_err(|_| ConfigListingError::Failed)?;
    let canonical = std::fs::canonicalize(dir.path()).map_err(|_| ConfigListingError::Failed)?;
    if canonical.starts_with(&root) {
        return Err(ConfigListingError::TempDirInsideRepository);
    }
    Ok(dir)
}

/// Bounded `git --no-pager --git-dir=<empty dir> config --file <absolute
/// config> --null --list --no-includes`, run from that empty directory.
/// [`ConfigListingError::Failed`] on a non-zero exit, timeout, truncated
/// output, spawn or cleanup error, or when the empty directory or an
/// absolute UTF-8 path cannot be had;
/// [`ConfigListingError::TempDirInsideRepository`] when the empty directory
/// would lie inside the scanned repository. Git's stderr is never returned:
/// it may quote the file's contents.
///
/// `--no-includes` only covers the file named by `--file`. Without the two
/// global options, Git would first look for a repository by walking up
/// from its working directory, and read that repository's config *with*
/// includes: to decide whether to start a pager (`pager.config`) and, on
/// macOS, whether to precompose a non-ASCII argument
/// (`core.precomposeunicode`). An `[include]` in the untrusted `.git/config`
/// would then be opened before it is validated (a FIFO hangs the check, an
/// invalid file fails it, a `//host/share` path on Windows touches SMB),
/// and the walk itself opens `HEAD`/`commondir` of any repository-looking
/// directory above the working directory (e.g. another user's `/tmp/HEAD`
/// FIFO, or `C:\.git`). Both protections apply independently:
/// - `--git-dir=<fresh empty dir>` turns repository discovery off: Git
///   finds no repository there and runs `config --file` without one, so no
///   repository config is read and no directory is walked;
/// - `--no-pager` skips the pager decision altogether (defense in depth).
///
/// The `--file` path is made absolute so it does not depend on the working
/// directory.
async fn list_git_config_file(
    git_bin: &str,
    config: &Path,
    repo_root: &Path,
) -> Result<String, ConfigListingError> {
    let config = std::path::absolute(config).map_err(|_| ConfigListingError::Failed)?;
    let config_arg = config.to_str().ok_or(ConfigListingError::Failed)?;
    let empty = no_repository_dir(repo_root)?;
    let empty_arg = empty.path().to_str().ok_or(ConfigListingError::Failed)?;
    let git_dir_arg = format!("--git-dir={empty_arg}");
    run_git_config_listing(
        git_bin,
        &["--no-pager", git_dir_arg.as_str()],
        config_arg,
        empty.path(),
    )
    .await
    .ok_or(ConfigListingError::Failed)
}

/// The command of [`list_git_config_file`] with the given global options
/// and working directory; tests call it to check each protection alone.
async fn run_git_config_listing(
    git_bin: &str,
    global_options: &[&str],
    config_arg: &str,
    cwd: &Path,
) -> Option<String> {
    let mut args: Vec<&str> = global_options.to_vec();
    args.extend([
        "config",
        "--file",
        config_arg,
        "--null",
        "--list",
        "--no-includes",
    ]);
    let out = crate::audit::scanners::run_bounded_subprocess(
        git_bin,
        &args,
        cwd,
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
        return None;
    }
    Some(out.stdout)
}

/// `(key, value)` pairs of [`list_git_config_file`] output. `--null`
/// prints `key\nvalue\0`, or just `key\0` for a bare boolean; a key never
/// contains a newline. Keys are trimmed and empty keys skipped.
fn git_config_entries(stdout: &str) -> impl Iterator<Item = (&str, &str)> {
    stdout.split('\0').filter_map(|entry| {
        let (key, value) = entry.split_once('\n').unwrap_or((entry, ""));
        let key = key.trim();
        (!key.is_empty()).then_some((key, value))
    })
}

/// Where actions/checkout (v6+, `persist-credentials: true`, the default)
/// may point its credential includes besides the runner temp dir: the
/// runner temp dir as mounted into a container job.
const CHECKOUT_CONTAINER_TEMP: &[&str] = &["", "github", "runner_temp"];
/// actions/checkout writes four includes per repository (host and container
/// path, each for the repository and its worktrees); more is refused.
const MAX_CHECKOUT_CREDENTIAL_INCLUDES: usize = 16;
/// A checkout credentials file holds one `http.<origin>/.extraheader`.
const MAX_CHECKOUT_CREDENTIAL_BYTES: u64 = 64 * 1024;

/// The CI context in which actions/checkout's credential includes are
/// accepted. Read once from the environment by [`prepare_readonly_git`] and
/// passed down explicitly, so tests never mutate the process environment.
/// The default (no runner temp dir) refuses every include, as outside
/// GitHub Actions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CheckoutCredentialContext {
    /// `RUNNER_TEMP`, only when `GITHUB_ACTIONS == "true"` and it is set,
    /// non-empty, valid UTF-8 and absolute.
    runner_temp: Option<String>,
}

impl CheckoutCredentialContext {
    fn from_env() -> Self {
        Self::from_vars(
            std::env::var_os("GITHUB_ACTIONS"),
            std::env::var_os("RUNNER_TEMP"),
        )
    }

    fn from_vars(
        github_actions: Option<std::ffi::OsString>,
        runner_temp: Option<std::ffi::OsString>,
    ) -> Self {
        if github_actions.as_deref() != Some(std::ffi::OsStr::new("true")) {
            return Self::default();
        }
        let runner_temp = runner_temp
            .and_then(|temp| temp.into_string().ok())
            .filter(|temp| !temp.is_empty() && Path::new(temp).is_absolute());
        Self { runner_temp }
    }
}

/// An absolute path split on its separators (`/`, plus `\` for Windows),
/// or `None` when it is not absolute or not plain. The first component is
/// empty for a leading separator, or a drive (`D:`) on Windows; every later
/// component must be non-empty (no doubled or trailing separator), not `.`
/// or `..`, and not start with `~`. On other hosts a `\` is refused outright:
/// Git would read it as part of a relative file name, which it resolves
/// against the config file's directory, not as a separator.
fn plain_absolute_components(path: &str, windows: bool) -> Option<Vec<&str>> {
    let parts: Vec<&str> = if windows {
        path.split(['/', '\\']).collect()
    } else if path.contains('\\') {
        return None;
    } else {
        path.split('/').collect()
    };
    let first = parts[0].as_bytes();
    let absolute = first.is_empty()
        || (windows && first.len() == 2 && first[0].is_ascii_alphabetic() && first[1] == b':');
    let plain = parts[1..]
        .iter()
        .all(|part| !part.is_empty() && *part != "." && *part != ".." && !part.starts_with('~'));
    (absolute && parts.len() >= 2 && plain).then_some(parts)
}

/// `git-credentials-<uuid>.config` exactly, the uuid being Node's
/// `randomUUID()` (lowercase 8-4-4-4-12 hex).
fn is_checkout_credential_file_name(name: &str) -> bool {
    let Some(uuid) = name
        .strip_prefix("git-credentials-")
        .and_then(|rest| rest.strip_suffix(".config"))
    else {
        return false;
    };
    let groups: Vec<&str> = uuid.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, len)| {
            group.len() == len
                && group
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// Which directory a checkout credentials file path is in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CheckoutCredentialPath {
    /// The parent is exactly `RUNNER_TEMP`.
    host: bool,
    /// The parent is exactly the container dir `/github/runner_temp`.
    container: bool,
}

/// Classify `value` as a checkout credentials file: an absolute, plain path
/// whose file name is [`is_checkout_credential_file_name`] and whose parent
/// is exactly `runner_temp` (compared component-wise, so `/` and `\` match
/// on Windows) and/or exactly the container dir `/github/runner_temp`.
/// Both flags are false for any other value.
fn checkout_credential_path(
    value: &str,
    runner_temp: &str,
    windows: bool,
) -> CheckoutCredentialPath {
    let Some(parts) = plain_absolute_components(value, windows) else {
        return CheckoutCredentialPath::default();
    };
    let Some((name, parent)) = parts.split_last() else {
        return CheckoutCredentialPath::default();
    };
    if !is_checkout_credential_file_name(name) {
        return CheckoutCredentialPath::default();
    }
    // `path.join` drops a trailing separator of RUNNER_TEMP; so does this.
    let temp = runner_temp.trim_end_matches(|c: char| c == '/' || (windows && c == '\\'));
    CheckoutCredentialPath {
        host: plain_absolute_components(temp, windows).is_some_and(|temp| temp == parent),
        container: parent == CHECKOUT_CONTAINER_TEMP,
    }
}

/// The repository's own `.git` directory spelled as actions/checkout writes
/// it into an include condition (`path.join(workingDirectory, '.git')` with
/// `\` replaced by `/`): `repo_root/.git` as given (if absolute) and
/// canonicalized (without a Windows `\\?\` prefix), both with forward
/// slashes. Checkout may have been given a path through a symlink, or this
/// scan a different spelling of the same directory, so both are accepted.
fn repo_gitdir_spellings(repo_root: &Path) -> Vec<String> {
    let given = repo_root.join(".git");
    let canonical = std::fs::canonicalize(&given).ok();
    let mut spellings: Vec<String> = Vec::new();
    for path in std::iter::once(given).chain(canonical) {
        if !path.is_absolute() {
            continue;
        }
        let Some(text) = path.to_str() else {
            continue;
        };
        let text = if cfg!(windows) {
            strip_windows_verbatim_prefix(text)
        } else {
            text.to_owned()
        };
        let text = text.replace('\\', "/");
        if !spellings.contains(&text) {
            spellings.push(text);
        }
    }
    spellings
}

/// `\\?\C:\x` → `C:\x` and `\\?\UNC\host\share\x` → `\\host\share\x`, the
/// spellings `canonicalize` returns on Windows and checkout never writes.
fn strip_windows_verbatim_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
}

/// A host include condition exactly as checkout writes it for this
/// repository: `gitdir:<repo .git dir>` or `gitdir:<repo .git dir>/worktrees/*`,
/// `<repo .git dir>` being one of [`repo_gitdir_spellings`]. On Windows the
/// comparison ignores ASCII case (so the drive letter may be either case).
/// Anything broader (`gitdir:**`, another repository) is refused.
fn is_host_checkout_condition(condition: &str, gitdirs: &[String], windows: bool) -> bool {
    let Some(pattern) = condition.strip_prefix("gitdir:") else {
        return false;
    };
    let candidates = [Some(pattern), pattern.strip_suffix("/worktrees/*")];
    candidates.into_iter().flatten().any(|dir| {
        gitdirs.iter().any(|gitdir| {
            if windows {
                gitdir.eq_ignore_ascii_case(dir)
            } else {
                gitdir == dir
            }
        })
    })
}

/// A container include condition exactly as checkout writes it inside a
/// container: `gitdir:/github/workspace/<path>/.git` or
/// `gitdir:/github/workspace/<path>/.git/worktrees/*`, `<path>` possibly
/// empty, with no wildcard (`*`, `?`, `[`, `\`) and no empty, `.` or `..`
/// component. Such an include fires only for a repository that really
/// lives under `/github/workspace` (a container job or action), never on a
/// Windows host or a non-container Linux host.
fn is_container_checkout_condition(condition: &str) -> bool {
    let Some(rest) = condition.strip_prefix("gitdir:/github/workspace") else {
        return false;
    };
    let Some(path) = rest
        .strip_suffix("/.git/worktrees/*")
        .or_else(|| rest.strip_suffix("/.git"))
    else {
        return false;
    };
    if path.is_empty() {
        return true;
    }
    let Some(path) = path.strip_prefix('/') else {
        return false;
    };
    path.split('/').all(|part| {
        !part.is_empty() && part != "." && part != ".." && !part.contains(['*', '?', '[', '\\'])
    })
}

/// Which of checkout's credential includes a config entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckoutCredentialInclude {
    /// `<RUNNER_TEMP>/git-credentials-<uuid>.config` under a
    /// [`is_host_checkout_condition`].
    Host,
    /// `/github/runner_temp/git-credentials-<uuid>.config` under a
    /// [`is_container_checkout_condition`].
    Container,
}

/// One of actions/checkout's credential includes, which it writes into the
/// checked-out repository's own `.git/config`:
/// `includeIf.gitdir:<…>.path = <RUNNER_TEMP>/git-credentials-<uuid>.config`
/// (or the container path). Only on GitHub Actions; only the
/// `includeif.gitdir:` form as `git config --list` prints it (section and
/// variable lowercased, condition verbatim and case-sensitive like Git's
/// own match), never `include.path`, `gitdir/i:`, `onbranch:` or
/// `hasconfig:`. The condition must be exactly checkout's for the path it
/// names: this repository's own `.git` for a host path
/// ([`is_host_checkout_condition`], `gitdirs` from [`repo_gitdir_spellings`]),
/// a plain `/github/workspace/…/.git` for the container path
/// ([`is_container_checkout_condition`]). The target is validated
/// separately by [`validate_checkout_credential_target`].
fn checkout_credential_include(
    key: &str,
    value: &str,
    ctx: &CheckoutCredentialContext,
    gitdirs: &[String],
    windows: bool,
) -> Option<CheckoutCredentialInclude> {
    let runner_temp = ctx.runner_temp.as_deref()?;
    let (section, condition, var) = split_config_key(key)?;
    if section != "includeif" || var != "path" {
        return None;
    }
    let path = checkout_credential_path(value, runner_temp, windows);
    if path.container && is_container_checkout_condition(condition) {
        return Some(CheckoutCredentialInclude::Container);
    }
    if path.host && is_host_checkout_condition(condition, gitdirs, windows) {
        return Some(CheckoutCredentialInclude::Host);
    }
    None
}

/// The only key a checkout credentials file may set:
/// `http.<https URL>.extraheader` (the subsection is printed verbatim, so
/// the scheme must be lowercase `https://`). It sets an HTTP header and
/// rewrites nothing.
fn is_checkout_credential_entry(key: &str) -> bool {
    let Some((section, url, var)) = split_config_key(key) else {
        return false;
    };
    section == "http"
        && var == "extraheader"
        && url
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_graphic()))
}

/// Whether a missing host credentials file may be trusted to stay missing:
/// its directory (`RUNNER_TEMP`, followed if it is a symlink, as checkout
/// resolves it) must exist, be a directory owned by the current user and
/// not be group- or world-writable, so no other local user can plant a
/// file there between this check and a later Git read.
#[cfg(unix)]
fn missing_host_credentials_trusted(target: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(dir) = target.parent() else {
        return false;
    };
    // SAFETY: geteuid has no arguments and only reads process identity.
    let euid = unsafe { libc::geteuid() };
    std::fs::metadata(dir)
        .is_ok_and(|meta| meta.is_dir() && meta.uid() == euid && meta.mode() & 0o022 == 0)
}

/// On Windows a missing host credentials file is accepted: on hosted
/// runners `RUNNER_TEMP` lies under the runner's own work directory, which
/// other users cannot write. Self-hosted Windows runners whose temp dir is
/// shared with other local users are out of scope (see SECURITY.md).
#[cfg(not(unix))]
fn missing_host_credentials_trusted(_target: &Path) -> bool {
    true
}

/// Validate the file a checkout credential include names. Git silently
/// skips a missing include, so a missing file is accepted for the
/// container path (which normally does not exist on the host), and for a
/// host path only when [`missing_host_credentials_trusted`]. Residual
/// TOCTOU: the file could appear, or change, between this check and a
/// later Git read, but only a process that can already write the runner's
/// temp dir could do that, and such a process already runs code on the
/// runner. An existing file (host or container path, checked at the path
/// as written) must be a regular file (not a symlink or directory) of at
/// most [`MAX_CHECKOUT_CREDENTIAL_BYTES`], parse with Git (includes
/// disabled) and set only [`is_checkout_credential_entry`] keys, which also
/// pass the general key and value checks.
///
/// The file holds the GITHUB_TOKEN: no value, no file content and no key
/// of the file is ever put in an error; errors name only the include key.
/// Its entries are not added to the remote/rewrite validation (an
/// extraheader is not a URL).
///
/// Git follows the include in vettalon's later read-only Git commands. That
/// is safe: every Git process vettalon starts gets `GIT_SAFE_ENV`
/// (`GIT_ALLOW_PROTOCOL` naming no real protocol, `GIT_NO_LAZY_FETCH`, see
/// `scanners/exec.rs`), so no transport ever runs and the header is never
/// sent.
async fn validate_checkout_credential_target(
    git_bin: &str,
    repo_root: &Path,
    include_key: &str,
    value: &str,
    kind: CheckoutCredentialInclude,
) -> Result<(), String> {
    let target = Path::new(value);
    let metadata = match std::fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match kind {
                CheckoutCredentialInclude::Container => Ok(()),
                CheckoutCredentialInclude::Host if missing_host_credentials_trusted(target) => {
                    Ok(())
                }
                CheckoutCredentialInclude::Host => Err(format!(
                    "actions/checkout credential include for {include_key} names a missing file in a runner temp dir that is not an existing directory owned by this user and writable only by it"
                )),
            };
        }
        Err(_) => {
            return Err(format!(
                "cannot inspect the actions/checkout credential include for {include_key}"
            ));
        }
    };
    if !metadata.file_type().is_file() {
        return Err(format!(
            "actions/checkout credential include for {include_key} is not a regular file"
        ));
    }
    if metadata.len() > MAX_CHECKOUT_CREDENTIAL_BYTES {
        return Err(format!(
            "actions/checkout credential include for {include_key} exceeds the validation limit of {MAX_CHECKOUT_CREDENTIAL_BYTES} bytes"
        ));
    }
    let stdout = list_git_config_file(git_bin, target, repo_root)
        .await
        .map_err(|error| match error {
            ConfigListingError::TempDirInsideRepository => TEMP_DIR_INSIDE_REPOSITORY.to_string(),
            ConfigListingError::Failed => format!(
                "cannot safely parse the actions/checkout credential include for {include_key}"
            ),
        })?;
    for (key, value) in git_config_entries(&stdout) {
        if !is_checkout_credential_entry(key)
            || forbidden_git_config_key(key)
            || forbidden_git_config_value(key, value)
        {
            return Err(format!(
                "actions/checkout credential include for {include_key} may only set http.<https URL>.extraheader"
            ));
        }
    }
    Ok(())
}

/// Parse repository config with Git itself, but explicitly disable includes
/// while parsing. This catches BOM, quoting, whitespace, case and includeIf
/// variants without first following attacker-selected external paths. The
/// one exception is actions/checkout's credential include on GitHub Actions
/// ([`checkout_credential_include`]), accepted only in `.git/config` (where
/// checkout writes it, never in `config.worktree`) and only after its
/// target is validated; every other include is refused.
async fn validate_git_configs(
    git_bin: &str,
    git_dir: &Path,
    repo_root: &Path,
    ctx: &CheckoutCredentialContext,
) -> Result<(), String> {
    // Entries of both files, kept so URL rewrites defined in one file are
    // applied to remotes defined in either (Git merges them).
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut credential_includes = 0usize;
    let mut validated_targets: Vec<(String, CheckoutCredentialInclude)> = Vec::new();
    // Only needed (and only touches the file system) on GitHub Actions.
    let gitdirs = if ctx.runner_temp.is_some() {
        repo_gitdir_spellings(repo_root)
    } else {
        Vec::new()
    };
    let main_config = git_dir.join("config");
    for config in [main_config.clone(), git_dir.join("config.worktree")] {
        if !config.is_file() {
            continue;
        }
        let stdout = list_git_config_file(git_bin, &config, repo_root)
            .await
            .map_err(|error| match error {
                ConfigListingError::TempDirInsideRepository => {
                    TEMP_DIR_INSIDE_REPOSITORY.to_string()
                }
                ConfigListingError::Failed => format!(
                    "cannot safely parse {}",
                    config.strip_prefix(git_dir).unwrap_or(&config).display()
                ),
            })?;
        let is_main_config = config == main_config;
        // Only the key is reported; values may hold arbitrary text.
        for (key, value) in git_config_entries(&stdout) {
            let include = if is_main_config {
                checkout_credential_include(key, value, ctx, &gitdirs, cfg!(windows))
            } else {
                None
            };
            if let Some(kind) = include {
                credential_includes += 1;
                if credential_includes > MAX_CHECKOUT_CREDENTIAL_INCLUDES {
                    return Err(format!(
                        "actions/checkout credential includes exceed the validation limit of {MAX_CHECKOUT_CREDENTIAL_INCLUDES}"
                    ));
                }
                if !validated_targets
                    .iter()
                    .any(|(target, seen)| target == value && *seen == kind)
                {
                    validate_checkout_credential_target(git_bin, repo_root, key, value, kind)
                        .await?;
                    validated_targets.push((value.to_string(), kind));
                }
                continue;
            }
            if forbidden_git_config_key(key) {
                return Err(format!("unsafe Git config key is not allowed: {key}"));
            }
            if forbidden_git_config_value(key, value) {
                return Err(format!("unsafe Git config value is not allowed for {key}"));
            }
            entries.push((key.to_string(), value.to_string()));
        }
    }
    let rewrites = UrlRewrites::from_entries(&entries)?;
    validate_remote_refs(&entries, &rewrites)?;
    validate_legacy_remotes(git_dir, &rewrites)
}

/// Resolve only a trusted executable and self-contained metadata, refusing
/// includes (except actions/checkout's credential includes on GitHub
/// Actions) and executable helpers before any repository read command.
pub(super) async fn prepare_readonly_git(
    repo_root: &Path,
) -> Result<(String, std::path::PathBuf), String> {
    prepare_readonly_git_with(repo_root, &CheckoutCredentialContext::from_env()).await
}

/// [`prepare_readonly_git`] with an explicit CI context.
async fn prepare_readonly_git_with(
    repo_root: &Path,
    ctx: &CheckoutCredentialContext,
) -> Result<(String, std::path::PathBuf), String> {
    let git_bin = crate::util::which_cli_for_scan("git", repo_root)
        .ok_or("git not found on absolute PATH or common install locations")?;
    let git_dir = crate::util::validate_local_git_metadata(repo_root)
        .map_err(|reason| format!("Git metadata is not self-contained: {reason}"))?;
    crate::util::validate_git_input_files(repo_root)
        .map_err(|reason| format!("Git input file would block Git: {reason}"))?;
    validate_git_configs(&git_bin, &git_dir, repo_root, ctx)
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
        GIT_LOG_NO_MAILMAP,
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

    /// Keys that name a file or program Git may open or run are refused in
    /// every spelling; `mailmap.blob` and `http.<url>.extraheader` are not.
    #[test]
    fn file_and_program_git_config_keys_are_rejected() {
        for key in [
            "mailmap.file",
            "MailMap.File",
            "diff.orderFile",
            "core.excludesFile",
            " core.excludesfile ",
            "core.attributesFile",
            "CORE.ATTRIBUTESFILE",
            "init.templateDir",
            "core.askPass",
            "core.editor",
            "sequence.editor",
            "core.pager",
            "pager.log",
            "pager.diff",
            "Pager.Config",
            "web.browser",
            "http.cookieFile",
            "http.sslCert",
            "http.sslKey",
            "http.sslCAInfo",
            "http.sslCAPath",
            "http.https://example.com/.sslCert",
            "http.https://example.com/.cookiefile",
            "http.https://a.b.example/x.y/.sslKey",
            "http.https://github.com/.sslCAInfo",
            "http.https://github.com/.sslCAPath",
            "http.proxySSLCert",
            "core.sshCommand",
            "interactive.diffFilter",
            "diff.external",
            "diff.owned.command",
            "diff.owned.textconv",
            "merge.owned.driver",
            "merge.a.b.driver",
        ] {
            assert!(forbidden_git_config_key(key), "missed {key}");
        }
        for key in [
            "mailmap.blob",
            "blame.ignoreRevsFile",
            "commit.template",
            "http.https://github.com/.extraheader",
            "http.https://ghes.example:8443/.extraHeader",
            "http.extraheader",
            "http.sslVerify",
            "http.postBuffer",
            "diff.renames",
            "diff.algorithm",
            "merge.conflictStyle",
            "merge.ff",
            "core.autocrlf",
            "core.ignorecase",
            "log.date",
        ] {
            assert!(!forbidden_git_config_key(key), "wrongly refused {key}");
        }
        // actions/checkout's credentials file still passes both checks.
        let header = "http.https://github.com/.extraheader";
        assert!(is_checkout_credential_entry(header));
        assert!(!forbidden_git_config_value(
            header,
            "AUTHORIZATION: basic x"
        ));
    }

    /// The four path-valued keys Git opens during vettalon's own reads
    /// (`log`, `diff`, `ls-files`) are refused by the real config check.
    #[tokio::test]
    async fn config_validation_refuses_read_time_path_keys() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let Some(git) = crate::audit::scanners::git_for_security_test(&root) else {
            return;
        };
        crate::audit::diff_scope::tests::git(&root, &["init", "-q"]).await;
        let git_dir = root.join(".git");
        let ctx = CheckoutCredentialContext::default();
        for key in crate::audit::diff_scope::tests::READ_TIME_PATH_KEYS {
            let set = ["config", key, "/tmp/must-not-open"];
            crate::audit::diff_scope::tests::git(&root, &set).await;
            let error = validate_git_configs(&git, &git_dir, &root, &ctx)
                .await
                .unwrap_err();
            let expected = format!(
                "unsafe Git config key is not allowed: {}",
                key.to_ascii_lowercase()
            );
            assert!(error.contains(&expected), "{key}: {error}");
            crate::audit::diff_scope::tests::git(&root, &["config", "--unset", key]).await;
        }
        // The same repository without them passes.
        validate_git_configs(&git, &git_dir, &root, &ctx)
            .await
            .unwrap();
    }

    /// Even with config validation bypassed, `git log` (history and the
    /// HEAD date) never opens a FIFO named by `mailmap.file`,
    /// `diff.orderFile`, `core.excludesFile` or `core.attributesFile`:
    /// `--no-use-mailmap` plus the command-scoped overrides. Cancelling the
    /// read kills its process group, so a regression fails here after 5 s
    /// instead of hanging.
    #[cfg(unix)]
    #[tokio::test]
    async fn git_history_never_opens_fifo_path_keys_when_validation_is_bypassed() {
        use crate::audit::diff_scope::tests::{
            FIFO_READ_BOUND, READ_TIME_PATH_KEYS, repo_with_fifo_config,
        };
        let ctx = CheckoutCredentialContext::default();
        for key in READ_TIME_PATH_KEYS {
            let Some((_dir, root, git)) = repo_with_fifo_config(key).await else {
                return;
            };
            let git_dir = root.join(".git");
            let refused = validate_git_configs(&git, &git_dir, &root, &ctx).await;
            assert!(refused.is_err(), "{key} must be refused by validation");

            let epoch = head_commit_epoch(&git, &git_dir, &root);
            let epoch = tokio::time::timeout(FIFO_READ_BOUND, epoch)
                .await
                .unwrap_or_else(|_| panic!("{key}: git log -1 blocked on a FIFO"));
            assert!(epoch.is_some(), "{key}");

            let history = git_history_with(&git, &git_dir, &root);
            let history = tokio::time::timeout(FIFO_READ_BOUND, history)
                .await
                .unwrap_or_else(|_| panic!("{key}: git log --name-only blocked on a FIFO"));
            if let GitHistoryStatus::Unavailable { reason } = history {
                panic!("{key}: {reason}");
            }
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
            // An empty helper name (`::x` selects helper "") and a leading
            // `+`, `.` or `-` are refused too.
            "::",
            "::x",
            " ::sh -c x",
            "-x::y",
            "+x::y",
            ".x::y",
        ] {
            assert!(is_transport_helper_url(value), "missed {value}");
            assert!(is_unsafe_remote_url(value), "missed {value}");
        }
        for value in ["", ":", ":x", "a:b::c", "a/b::c", "a b::c", "[::1]::x"] {
            assert!(!is_transport_helper_url(value), "wrongly refused {value}");
        }
    }

    /// Git runs `git-remote-<scheme>` for any `<scheme>://` URL it does not
    /// handle itself, so only an allow-list of schemes is accepted.
    #[test]
    fn unknown_url_schemes_are_refused() {
        for value in [
            "ext://sh -c x",
            "EXT://sh",
            "fd://17",
            "codecommit://repo",
            "foo+bar://x",
            "a.b-c://x",
            "9p://x",
            " ext://x",
            "httpx://example.com/r",
            "https+x://example.com/r",
            // Built-in transports are matched case-sensitively by Git;
            // other spellings run `git-remote-<scheme>`.
            "FILE:///srv/repo.git",
            "SSH://git@example.com/r.git",
            "Https://github.com/o/r.git",
            "HTTPS://github.com/o/r.git",
            "Git+SSH://git@example.com/r",
            "gIt://example.com/r.git",
        ] {
            assert!(is_unsafe_remote_url(value), "missed {value}");
            for key in ["remote.origin.url", "Remote.Origin.PushURL"] {
                assert!(
                    forbidden_git_config_value(key, value),
                    "missed {key}={value}"
                );
            }
        }
        for value in [
            "http://example.com/r.git",
            "https://github.com/o/r.git",
            "ftp://example.com/r.git",
            "ftps://example.com/r.git",
            "ssh://git@example.com/r.git",
            "git://example.com/r.git",
            "file:///srv/repo.git",
            "git+ssh://git@example.com/r",
            "ssh+git://git@example.com/r",
            "ssh://[::1]/repo",
            "git@github.com:o/r.git",
            "example.com:o/r.git",
            "/srv/repo.git",
            "../sibling.git",
            "./x",
            ".",
            "origin",
            "C:\\repo",
            "c:/repo",
            "dir/a://b",
            "_x://y",
            "",
        ] {
            assert!(!is_unsafe_remote_url(value), "wrongly refused {value}");
            assert!(
                !forbidden_git_config_value("remote.origin.url", value),
                "wrongly refused {value}"
            );
        }
        // Only remote URLs get the scheme allow-list; rewrite prefixes keep
        // the helper-only check.
        assert!(!forbidden_git_config_value(
            "url.https://m/.insteadOf",
            "ext://x"
        ));
        assert!(!forbidden_git_config_key("url.ext://x.insteadOf"));
    }

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    fn check_remote_refs(pairs: &[(&str, &str)]) -> Result<(), String> {
        let entries = entries(pairs);
        validate_remote_refs(&entries, &UrlRewrites::from_entries(&entries)?)
    }

    /// `insteadOf` rewrites can assemble a helper URL from a prefix and a
    /// remote URL that each pass on their own; the rewritten URL is checked.
    #[test]
    fn remote_urls_are_checked_after_url_rewrites() {
        for pairs in [
            // `foo:sh -c x` becomes `ext::sh -c x`.
            &[
                ("url.ext:.insteadOf", "foo"),
                ("remote.origin.url", "foo:sh -c x"),
            ][..],
            // An empty base strips the prefix.
            &[
                ("url..insteadOf", "https://x/"),
                ("remote.origin.url", "https://x/ext::sh"),
            ],
            // An empty insteadOf matches every URL.
            &[("url.ext:.insteadOf", ""), ("remote.origin.url", ":sh")],
            // Unknown schemes count after a rewrite too.
            &[
                ("url.ext:.insteadOf", "https:"),
                ("remote.origin.url", "https://sh -c x"),
            ],
            // Push URLs are rewritten by insteadOf.
            &[
                ("url.ext:.insteadOf", "foo"),
                ("remote.origin.pushurl", "foo:sh"),
            ],
            // A fetch URL doubles as the push URL through pushInsteadOf.
            &[
                ("url.ext:.pushInsteadOf", "foo"),
                ("remote.origin.url", "foo:sh"),
            ],
            &[
                ("URL.fd:.PUSHINSTEADOF", "foo"),
                ("Remote.Origin.PushURL", "foo:17"),
            ],
            // The base keeps its case.
            &[
                ("url.EXT:.insteadOf", "foo"),
                ("remote.origin.url", "foo:sh"),
            ],
            // Rewrites in either config file apply to every remote.
            &[
                ("remote.origin.url", "foo:sh"),
                ("url.ext:.insteadOf", "foo"),
            ],
            // Equally long prefixes: every candidate is checked.
            &[
                ("url.https://m/.insteadOf", "foo"),
                ("url.ext:.insteadOf", "foo"),
                ("remote.origin.url", "foo:sh"),
            ],
            &[
                ("url.ext:.insteadOf", "foo"),
                ("submodule.lib.url", "foo:sh"),
            ],
        ] {
            let error = check_remote_refs(pairs).unwrap_err();
            assert!(
                error.contains("unsafe Git config value") && error.contains("URL rewrite"),
                "{pairs:?}: {error}"
            );
            for (_, value) in pairs.iter().filter(|(_, value)| !value.is_empty()) {
                assert!(!error.contains(*value), "value leaked: {error}");
            }
        }

        for pairs in [
            // actions/checkout writes rewrites like these into local config.
            &[
                (
                    "url.https://x-access-token:t@github.com/.insteadOf",
                    "https://github.com/",
                ),
                (
                    "url.https://x-access-token:t@github.com/.insteadOf",
                    "git@github.com:",
                ),
                (
                    "url.https://x-access-token:t@github.com/.pushInsteadOf",
                    "ssh://git@github.com/",
                ),
                ("remote.origin.url", "https://github.com/o/r"),
                ("remote.origin.pushurl", "git@github.com:o/r.git"),
                ("submodule.lib.url", "https://github.com/o/lib"),
            ][..],
            // The longest matching prefix wins, as in Git.
            &[
                ("url.ext:.insteadOf", "foo"),
                ("url.https://mirror/.insteadOf", "foo:sh"),
                ("remote.origin.url", "foo:sh -c x"),
            ],
            // A non-matching prefix leaves the URL alone.
            &[
                ("url.ext:.insteadOf", "bar"),
                ("remote.origin.url", "foo:sh"),
            ],
            &[
                ("url.ssh://[::1]/.insteadOf", "local:"),
                ("remote.origin.url", "local:repo"),
            ],
        ] {
            check_remote_refs(pairs).unwrap_or_else(|error| panic!("{pairs:?}: {error}"));
        }
    }

    /// Git uses a remote name that names no configured remote as a URL.
    #[test]
    fn remote_name_values_are_checked_as_urls() {
        for (key, value) in [
            ("branch.main.remote", "ext::sh -c x"),
            ("branch.feature.x.remote", "ext://sh"),
            ("Branch.Main.PushRemote", "fd::17"),
            ("remote.pushDefault", "::x"),
            ("REMOTE.PUSHDEFAULT", "custom::x"),
            ("submodule.lib.url", "ext::sh -c x"),
            ("submodule.lib.url", "ext://sh"),
            ("extensions.partialClone", "ext::sh -c x"),
        ] {
            let error = check_remote_refs(&[
                ("remote.origin.url", "https://example.com/r.git"),
                (key, value),
            ])
            .unwrap_err();
            assert!(
                error.contains("unsafe Git config value") && error.contains(key.trim()),
                "{key}: {error}"
            );
        }
        // After a rewrite, too.
        for key in [
            "branch.main.remote",
            "branch.main.pushRemote",
            "remote.pushDefault",
            "extensions.partialClone",
        ] {
            assert!(
                check_remote_refs(&[("url.ext:.insteadOf", "up"), (key, "up:sh")]).is_err(),
                "missed {key}"
            );
            // `.` is used as a URL too, so a rewrite applies to it.
            assert!(
                check_remote_refs(&[("url.ext://x.insteadOf", "."), (key, ".")]).is_err(),
                "missed {key}"
            );
        }

        // Configured remote names, `.` and plain names are fine.
        check_remote_refs(&[
            ("remote.origin.url", "https://example.com/r.git"),
            ("remote.up.stream.url", "git@example.com:r.git"),
            ("branch.main.remote", "origin"),
            ("branch.main.pushRemote", "up.stream"),
            ("branch.dev.remote", "."),
            ("branch.old.remote", "gone"),
            ("remote.pushDefault", "origin"),
            ("extensions.partialClone", "origin"),
            ("branch.main.merge", "refs/heads/main"),
            ("branch.main.description", "ext::sh"),
        ])
        .unwrap();
        // Remote names are checked as URLs even when a `remote.<name>.url`
        // exists: Git may still not count that remote as configured (a
        // `config.worktree` without `extensions.worktreeConfig`, an empty
        // `url` that clears the list), and then uses the name as a URL.
        for pairs in [
            &[
                ("remote.weird::name.url", "https://example.com/r.git"),
                ("branch.main.remote", "weird::name"),
            ][..],
            &[
                ("url.ext:.insteadOf", "up"),
                ("remote.up:sh.url", "https://example.com/r.git"),
                ("branch.dev.remote", "up:sh"),
            ],
            &[
                ("remote.ext::sh.url", "https://example.com/r.git"),
                ("remote.ext::sh.url", ""),
                ("remote.pushDefault", "ext::sh"),
            ],
            &[
                ("remote.weird::name.fetch", "+refs/heads/*:refs/remotes/w/*"),
                ("branch.main.remote", "weird::name"),
            ],
            &[
                ("remote.Weird::Name.url", "https://example.com/r.git"),
                ("branch.main.remote", "weird::name"),
            ],
        ] {
            let error = check_remote_refs(pairs).unwrap_err();
            assert!(
                error.contains("unsafe Git config value"),
                "{pairs:?}: {error}"
            );
        }
        // Plain configured names still pass with unrelated rewrites, as
        // actions/checkout configures them.
        check_remote_refs(&[
            (
                "url.https://x-access-token:t@github.com/.insteadOf",
                "https://github.com/",
            ),
            ("remote.origin.url", "https://github.com/o/r"),
            ("branch.main.remote", "origin"),
            ("branch.main.pushRemote", "origin"),
            ("remote.pushDefault", "origin"),
            ("branch.dev.remote", "."),
        ])
        .unwrap();
    }

    /// Above the rewrite-rule and value caps the repository is refused
    /// rather than checked in quadratic time.
    #[test]
    fn url_rewrite_checks_are_capped() {
        let rules: Vec<(String, String)> = (0..MAX_URL_REWRITE_RULES)
            .map(|i| {
                let var = if i % 2 == 0 {
                    "insteadOf"
                } else {
                    "pushInsteadOf"
                };
                (
                    format!("url.https://mirror{i}.example/.{var}"),
                    format!("https://host{i}.example/"),
                )
            })
            .collect();
        let rewrites = UrlRewrites::from_entries(&rules).unwrap();
        assert_eq!(
            rewrites.instead_of.len() + rewrites.push_instead_of.len(),
            MAX_URL_REWRITE_RULES
        );
        let mut over = rules.clone();
        over.push(("url.https://m/.pushInsteadOf".into(), "x".into()));
        let error = UrlRewrites::from_entries(&over).unwrap_err();
        assert!(error.contains("URL rewrite rules exceed"), "{error}");
        // Other `url.*` variables do not count.
        let mut other = rules.clone();
        other.push(("url.https://m/.foo".into(), "x".into()));
        UrlRewrites::from_entries(&other).unwrap();

        let values: Vec<(String, String)> = (0..MAX_REMOTE_REF_VALUES)
            .map(|i| match i % 3 {
                0 => (
                    format!("remote.r{i}.url"),
                    "https://example.com/r".to_string(),
                ),
                1 => (
                    format!("remote.r{i}.pushurl"),
                    "git@example.com:r".to_string(),
                ),
                _ => (format!("branch.b{i}.remote"), "origin".to_string()),
            })
            .collect();
        validate_remote_refs(&values, &rewrites).unwrap();
        for extra in [
            ("remote.pushDefault", "origin"),
            ("submodule.lib.url", "https://example.com/lib"),
            ("branch.x.pushRemote", "origin"),
        ] {
            let mut over = values.clone();
            over.push((extra.0.into(), extra.1.into()));
            let error = validate_remote_refs(&over, &rewrites).unwrap_err();
            assert!(error.contains("exceed the validation limit"), "{error}");
        }
        // Keys that are not remote references do not count.
        let mut other = values.clone();
        other.push(("branch.x.merge".into(), "refs/heads/x".into()));
        validate_remote_refs(&other, &rewrites).unwrap();
    }

    /// The previous check: build every rewritten URL (longest prefix, all
    /// tied bases, both rule sets) and test each one. The bounded check
    /// must agree with it.
    fn reference_rewrite_unsafe(rewrites: &UrlRewrites, url: &str) -> bool {
        [&rewrites.instead_of, &rewrites.push_instead_of]
            .into_iter()
            .any(|rules| {
                let Some(longest) = rules
                    .iter()
                    .filter(|rule| url.starts_with(rule.prefix.as_str()))
                    .map(|rule| rule.prefix.len())
                    .max()
                else {
                    return false;
                };
                let rest = &url[longest..];
                rules
                    .iter()
                    .filter(|rule| {
                        rule.prefix.len() == longest && url.starts_with(rule.prefix.as_str())
                    })
                    .any(|rule| is_unsafe_remote_url(&format!("{}{rest}", rule.base)))
            })
    }

    /// The constant-time per-base decision equals checking the joined URL,
    /// including bases that are blank, end mid-scheme or mid-`::`, and
    /// Unicode whitespace that `trim_start` skips.
    #[test]
    fn bounded_rewrite_check_matches_the_joined_url() {
        let long_run = "a".repeat(40);
        let long_run_sep = format!("{long_run}://x");
        let bases = [
            "",
            " ",
            "\t",
            "\x0c",
            "\u{a0}",
            "\u{3000}",
            " \u{3000}\t",
            "e",
            "ex",
            "ext",
            "ext:",
            "ext::",
            "ext://",
            "EXT",
            "EXT:",
            " ext",
            " \u{3000}ext:",
            ":",
            "::",
            "-",
            "+",
            ".",
            "-x",
            "9",
            "h",
            "ht",
            "http",
            "https",
            "https:",
            "https:/",
            "https://",
            "https://m/",
            "HTTPS",
            "git",
            "git+",
            "git+ssh",
            "git+ssh:/",
            "ssh",
            "ssh+",
            "ssh+git",
            "file",
            "FILE",
            "a b",
            "x/",
            "é",
            "aé",
            "a\u{3000}",
            "https://[::1]/",
            long_run.as_str(),
        ];
        let rests = [
            "",
            ":",
            "::",
            ":/",
            ":x",
            "::x",
            "://x",
            ":://x",
            "t::foo",
            "t://x",
            "s://x",
            "ps://x",
            "tps://h",
            "ttps://h",
            "+ssh://x",
            "ssh://x",
            "+git://x",
            "git://x",
            "ile://x",
            "ILE://x",
            "it+ssh://x",
            "x",
            "x::y",
            "x://y",
            " ext::x",
            "\u{3000}ext::x",
            "\u{3000}ext://x",
            "/x",
            "/::x",
            "é::x",
            "-x://y",
            "foo:sh",
            "ext::sh",
            "https://ok/",
            long_run_sep.as_str(),
        ];
        for base in bases {
            let shape = BaseShape::of(base);
            for rest in rests {
                assert_eq!(
                    rewrite_unsafe(base, shape, &RestShape::of(rest)),
                    is_unsafe_remote_url(&format!("{base}{rest}")),
                    "{base:?} + {rest:?}"
                );
            }
        }
        // The cases the review named, spelled out.
        for (base, rest, expected) in [
            ("ex", "t::foo", true),
            ("ext:", ":x", true),
            ("", "ext::x", true),
            (" \u{3000}", "ext::x", true),
            ("\u{3000}", "https://ok/", false),
            ("EXT", "://x", true),
            ("ext", "://x", true),
            ("FILE", ":///srv/r", true),
            ("ht", "tps://h/", false),
            ("git+", "ssh://h/", false),
            ("ssh", "+git://h/", false),
            ("https://m/", "ext::x", false),
            ("https", "x://h/", true),
        ] {
            let shape = BaseShape::of(base);
            assert_eq!(
                rewrite_unsafe(base, shape, &RestShape::of(rest)),
                expected,
                "{base:?} + {rest:?}"
            );
        }

        // The whole check, with longest-prefix matching, ties and both rule
        // sets, agrees with building every rewritten URL.
        for base in bases {
            for var in ["insteadOf", "pushInsteadOf"] {
                let rules = vec![
                    (format!("url.{base}.{var}"), "foo".to_string()),
                    (format!("url.https://m/.{var}"), "foo".to_string()),
                    (format!("url.{base}x.insteadOf"), "fo".to_string()),
                    (format!("url.{base}.pushInsteadOf"), String::new()),
                ];
                let rewrites = UrlRewrites::from_entries(&rules).unwrap();
                for rest in rests {
                    for url in [format!("foo{rest}"), format!("fo{rest}"), rest.to_string()] {
                        assert_eq!(
                            rewrites.any_rewrite_unsafe(&url).unwrap(),
                            reference_rewrite_unsafe(&rewrites, &url),
                            "{base:?} {var} {url:?}"
                        );
                    }
                }
            }
        }
    }

    /// The worst case of the old string-building check (tens of seconds):
    /// the most rules, all with the empty prefix and distinct 4 KiB bases,
    /// against the most remote values and legacy remote lines. No rewritten
    /// URL is built now, so the cost no longer scales with base length.
    /// Release builds take milliseconds; the bound leaves room for debug
    /// builds on slow CI runners.
    #[test]
    fn url_rewrite_checks_do_not_scale_with_base_length() {
        let rules: Vec<(String, String)> = (0..MAX_URL_REWRITE_RULES)
            .map(|i| {
                // Alternate the base shapes: all scheme bytes (the run
                // continues into the URL) and a run that ends in the base.
                let base = if i % 2 == 0 {
                    format!("{i:03}{}", "a".repeat(4093))
                } else {
                    format!("https://h{i:03}/{}", "a".repeat(4083))
                };
                assert_eq!(base.len(), 4096);
                (format!("url.{base}.insteadOf"), String::new())
            })
            .collect();
        let rewrites = UrlRewrites::from_entries(&rules).unwrap();
        let values: Vec<(String, String)> = (0..MAX_REMOTE_REF_VALUES)
            .map(|i| (format!("remote.r{i}.url"), "x".repeat(4096)))
            .collect();

        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(git_dir.join("remotes")).unwrap();
        std::fs::create_dir_all(git_dir.join("branches")).unwrap();
        // Four maximal files: every line has a `#`, so both candidates of
        // each line are checked.
        let per_file = MAX_LEGACY_REMOTE_LINES / 4;
        for (n, name) in ["remotes/a", "remotes/b", "branches/c", "branches/d"]
            .into_iter()
            .enumerate()
        {
            let text: String = (0..per_file)
                .map(|i| format!("{:058}#main\n", n * per_file + i))
                .collect();
            assert_eq!(text.len() as u64, MAX_LEGACY_REMOTE_BYTES);
            std::fs::write(git_dir.join(name), text).unwrap();
        }

        let started = std::time::Instant::now();
        validate_remote_refs(&values, &rewrites).unwrap();
        validate_legacy_remotes(&git_dir, &rewrites).unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "rewrite checks took {elapsed:?}"
        );
        assert!(rewrites.checked_bytes.get() <= MAX_URL_REWRITE_CHECK_BYTES);
    }

    /// Bytes read by the rewrite checks are capped per run; a repository
    /// above the budget is refused.
    #[test]
    fn url_rewrite_checks_are_capped_in_bytes() {
        let prefix = "a".repeat(4096);
        let rules: Vec<(String, String)> = (0..MAX_URL_REWRITE_RULES)
            .map(|i| (format!("url.https://h{i}/.insteadOf"), prefix.clone()))
            .collect();
        let values: Vec<(String, String)> = (0..MAX_REMOTE_REF_VALUES)
            .map(|i| (format!("remote.r{i}.url"), format!("{prefix}/r")))
            .collect();
        // Each value compares every 4 KiB prefix twice: 2 MiB per value.
        let rewrites = UrlRewrites::from_entries(&rules).unwrap();
        let error = validate_remote_refs(&values, &rewrites).unwrap_err();
        assert!(
            error.contains("URL rewrite checks exceed the validation limit"),
            "{error}"
        );
        // A few values fit, and a fresh run starts with a fresh budget.
        let rewrites = UrlRewrites::from_entries(&rules).unwrap();
        validate_remote_refs(&values[..4], &rewrites).unwrap();

        // Legacy remote lines draw on the same budget.
        let rewrites =
            UrlRewrites::from_entries(&entries(&[("url.https://m/.insteadOf", "")])).unwrap();
        assert_eq!(legacy_remote_unsafe_url("abc\n", &rewrites), Ok(None));
        // Without a `#` the line is checked once (3 bytes of tail), with one
        // the part before it is checked too (5 + 3 bytes).
        assert_eq!(rewrites.checked_bytes.get(), 3);
        assert_eq!(legacy_remote_unsafe_url("abc#d\n", &rewrites), Ok(None));
        assert_eq!(rewrites.checked_bytes.get(), 3 + 5 + 3);
        rewrites.checked_bytes.set(MAX_URL_REWRITE_CHECK_BYTES);
        let error = legacy_remote_unsafe_url("abc\n", &rewrites).unwrap_err();
        assert!(error.contains("URL rewrite checks exceed"), "{error}");
    }

    /// Legacy `remotes/` and `branches/` files are inspected, never used.
    #[test]
    fn legacy_remote_files_with_transport_helpers_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        let no_rewrites = UrlRewrites::default();
        std::fs::create_dir_all(git_dir.join("remotes")).unwrap();
        std::fs::create_dir_all(git_dir.join("branches")).unwrap();
        validate_legacy_remotes(&git_dir, &no_rewrites).unwrap();
        let remote = git_dir.join("remotes/origin");
        let branch = git_dir.join("branches/x");
        std::fs::write(
            &remote,
            "URL: https://example.com/r.git\nPull: refs/heads/main:refs/heads/origin\n",
        )
        .unwrap();
        std::fs::write(&branch, "ssh://[::1]/repo#main\n").unwrap();
        validate_legacy_remotes(&git_dir, &no_rewrites).unwrap();

        std::fs::write(&remote, "URL: ext::sh -c x\n").unwrap();
        let error = validate_legacy_remotes(&git_dir, &no_rewrites).unwrap_err();
        assert!(
            error.contains("transport-helper") && error.contains("remotes/"),
            "{error}"
        );
        assert!(!error.contains("origin"), "{error}");
        std::fs::write(&remote, "URL: https://example.com/r.git\nurl:fd::17\n").unwrap();
        assert!(validate_legacy_remotes(&git_dir, &no_rewrites).is_err());
        std::fs::write(&remote, "URL: https://example.com/r.git\n").unwrap();

        std::fs::write(&branch, "ext::sh -c x#main\n").unwrap();
        let error = validate_legacy_remotes(&git_dir, &no_rewrites).unwrap_err();
        assert!(
            error.contains("transport-helper") && error.contains("branches/"),
            "{error}"
        );
        std::fs::write(&branch, "https://example.com/r.git#main\n").unwrap();
        validate_legacy_remotes(&git_dir, &no_rewrites).unwrap();

        // Unknown `<scheme>://` URLs and empty helper names start a helper.
        for (file, content) in [
            (&remote, "URL: ext://sh -c x\n"),
            (&remote, "URL:   ::sh\n"),
            (&branch, "fd://17#main\n"),
        ] {
            let original = std::fs::read(file).unwrap();
            std::fs::write(file, content).unwrap();
            let error = validate_legacy_remotes(&git_dir, &no_rewrites).unwrap_err();
            assert!(error.contains("transport-helper"), "{content}: {error}");
            std::fs::write(file, original).unwrap();
        }
        validate_legacy_remotes(&git_dir, &no_rewrites).unwrap();

        // Legacy URLs are rewritten by `url.<base>.insteadOf` like any other.
        let rewrite_entries = entries(&[
            ("url.ext:.insteadOf", "foo"),
            ("url.fd:.pushInsteadOf", "bar"),
            (
                "url.https://x-access-token:t@github.com/.insteadOf",
                "https://github.com/",
            ),
        ]);
        let rewrites = UrlRewrites::from_entries(&rewrite_entries).unwrap();
        validate_legacy_remotes(&git_dir, &rewrites).unwrap();
        for (file, content) in [
            (&remote, "URL: foo:sh -c x\n"),
            (&remote, "URL: https://example.com/r.git\nURL: bar:17\n"),
            (&branch, "foo:sh -c x#main\n"),
        ] {
            let original = std::fs::read(file).unwrap();
            std::fs::write(file, content).unwrap();
            validate_legacy_remotes(&git_dir, &no_rewrites).unwrap();
            let error = validate_legacy_remotes(&git_dir, &rewrites).unwrap_err();
            assert!(
                error.contains("transport-helper") && error.contains("URL rewrite"),
                "{content}: {error}"
            );
            std::fs::write(file, original).unwrap();
        }
        std::fs::write(&remote, "URL: https://github.com/o/r.git\n").unwrap();
        validate_legacy_remotes(&git_dir, &rewrites).unwrap();
        std::fs::write(&remote, "URL: https://example.com/r.git\n").unwrap();

        // Git never reads a legacy remote whose name contains '/', but
        // nested files are inspected anyway so the check fails closed.
        std::fs::create_dir(git_dir.join("remotes/team")).unwrap();
        std::fs::write(git_dir.join("remotes/team/origin"), "URL: custom::x\n").unwrap();
        assert!(validate_legacy_remotes(&git_dir, &no_rewrites).is_err());
        std::fs::remove_dir_all(git_dir.join("remotes/team")).unwrap();

        // Oversized files fail closed instead of being partly inspected.
        let big = git_dir.join("remotes/big");
        std::fs::write(&big, vec![b'a'; MAX_LEGACY_REMOTE_BYTES as usize + 1]).unwrap();
        assert!(
            validate_legacy_remotes(&git_dir, &no_rewrites)
                .unwrap_err()
                .contains("validation limit")
        );
        std::fs::remove_file(&big).unwrap();
        validate_legacy_remotes(&git_dir, &no_rewrites).unwrap();

        #[cfg(unix)]
        {
            let target = dir.path().join("target");
            std::fs::write(&target, "URL: https://example.com/r.git\n").unwrap();
            std::os::unix::fs::symlink(&target, git_dir.join("branches/link")).unwrap();
            assert!(
                validate_legacy_remotes(&git_dir, &no_rewrites)
                    .unwrap_err()
                    .contains("symlink")
            );
            std::fs::remove_file(git_dir.join("branches/link")).unwrap();
            std::fs::remove_dir_all(git_dir.join("branches")).unwrap();
            std::os::unix::fs::symlink(dir.path(), git_dir.join("branches")).unwrap();
            assert!(
                validate_legacy_remotes(&git_dir, &no_rewrites)
                    .unwrap_err()
                    .contains("symlink")
            );
        }
    }

    /// Git trims only space, `\t`, `\n` and `\r`; a U+000C it keeps can
    /// match an `insteadOf` prefix, so it must not be trimmed away here.
    #[test]
    fn legacy_remote_lines_trim_only_git_whitespace() {
        let rewrites =
            UrlRewrites::from_entries(&entries(&[("url.ext://.insteadOf", "\x0c")])).unwrap();
        for text in ["URL:\x0cfoo\n", "\x0cfoo#main\n", "URL: \x0cfoo\r\n"] {
            assert_eq!(
                legacy_remote_unsafe_url(text, &rewrites),
                Ok(Some(UnsafeUrl::AfterRewrite)),
                "{text:?}"
            );
            assert_eq!(
                legacy_remote_unsafe_url(text, &UrlRewrites::default()),
                Ok(None)
            );
        }
        // Git's own whitespace is still skipped.
        assert_eq!(
            legacy_remote_unsafe_url("URL: \t foo\r\n", &rewrites),
            Ok(None)
        );
        let rewrites =
            UrlRewrites::from_entries(&entries(&[("url.ext:.insteadOf", "foo")])).unwrap();
        assert_eq!(
            legacy_remote_unsafe_url(" \tURL: \t foo:sh \r\n", &rewrites),
            Ok(Some(UnsafeUrl::AfterRewrite))
        );
    }

    /// Legacy remote files are capped in total bytes and lines across
    /// `remotes/` and `branches/`, refusing the repository above either.
    #[test]
    fn legacy_remote_files_are_capped_in_total() {
        let no_rewrites = UrlRewrites::default();
        let setup = || {
            let dir = tempfile::tempdir().unwrap();
            let git_dir = dir.path().join(".git");
            std::fs::create_dir_all(git_dir.join("remotes")).unwrap();
            std::fs::create_dir_all(git_dir.join("branches")).unwrap();
            (dir, git_dir)
        };

        // Bytes: four maximal files fill the total budget exactly.
        let (_dir, git_dir) = setup();
        let file = vec![b'a'; MAX_LEGACY_REMOTE_BYTES as usize];
        for name in ["remotes/a", "remotes/b", "branches/c", "branches/d"] {
            std::fs::write(git_dir.join(name), &file).unwrap();
        }
        validate_legacy_remotes(&git_dir, &no_rewrites).unwrap();
        std::fs::write(git_dir.join("branches/e"), "x").unwrap();
        let error = validate_legacy_remotes(&git_dir, &no_rewrites).unwrap_err();
        assert!(error.contains("total validation size limit"), "{error}");
        assert!(!error.contains("branches/e"), "{error}");

        // Lines.
        let (_dir, git_dir) = setup();
        std::fs::write(
            git_dir.join("remotes/a"),
            "x\n".repeat(MAX_LEGACY_REMOTE_LINES - 96),
        )
        .unwrap();
        std::fs::write(git_dir.join("branches/b"), "x\n".repeat(96)).unwrap();
        validate_legacy_remotes(&git_dir, &no_rewrites).unwrap();
        std::fs::write(git_dir.join("branches/c"), "x\n").unwrap();
        let error = validate_legacy_remotes(&git_dir, &no_rewrites).unwrap_err();
        assert!(error.contains("line limit"), "{error}");
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

    /// The production entry point refuses a FIFO Git input file (which would
    /// block `git status`/`diff`/`log` until the timeout) before any Git
    /// command reads the repository.
    #[cfg(unix)]
    #[tokio::test]
    async fn prepare_readonly_git_refuses_validate_git_input_fifos() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if crate::audit::scanners::git_for_security_test(root).is_none() {
            return;
        }
        crate::audit::diff_scope::tests::git(root, &["init", "-q"]).await;
        prepare_readonly_git(root).await.unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        let fifo = root.join("sub/.gitattributes");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            prepare_readonly_git(root),
        )
        .await
        .expect("prepare_readonly_git blocked on a FIFO")
        .unwrap_err();
        assert!(
            error.contains("\"sub/.gitattributes\" is not a regular file"),
            "{error}"
        );

        // A FIFO inside `.git` (here HEAD, which even `git config --file`
        // would read) is refused by the metadata walk.
        std::fs::remove_file(&fifo).unwrap();
        let head = root.join(".git/HEAD");
        std::fs::remove_file(&head).unwrap();
        let head_c = std::ffi::CString::new(head.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(head_c.as_ptr(), 0o600) }, 0);
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            prepare_readonly_git(root),
        )
        .await
        .expect("prepare_readonly_git blocked on a FIFO HEAD")
        .unwrap_err();
        assert!(
            error.contains("Git metadata is not self-contained: \"HEAD\" is not a regular file"),
            "{error}"
        );
    }

    /// The production entry point applies the repository's URL rewrites to
    /// remote URLs and remote names, and still accepts the rewrites
    /// actions/checkout writes. Nothing here fetches.
    #[tokio::test]
    async fn prepare_readonly_git_checks_rewritten_remote_urls() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if crate::audit::scanners::git_for_security_test(root).is_none() {
            return;
        }
        crate::audit::diff_scope::tests::git(root, &["init", "-q"]).await;
        let config = root.join(".git/config");
        let base = std::fs::read_to_string(&config).unwrap();
        let checkout = "[remote \"origin\"]\n\turl = https://github.com/o/r\n\
            [branch \"main\"]\n\tremote = origin\n\
            [url \"https://x-access-token:t@github.com/\"]\n\
            \tinsteadOf = https://github.com/\n\tinsteadOf = git@github.com:\n";
        std::fs::write(&config, format!("{base}{checkout}")).unwrap();
        prepare_readonly_git(root).await.unwrap();

        for (extra, key) in [
            (
                "[url \"ext:\"]\n\tinsteadOf = foo\n[remote \"evil\"]\n\turl = foo:sh -c x\n",
                "remote.evil.url",
            ),
            (
                "[url \"\"]\n\tinsteadOf = https://x/\n[remote \"evil\"]\n\turl = https://x/ext::sh\n",
                "remote.evil.url",
            ),
            (
                "[remote \"evil\"]\n\turl = ext://sh -c x\n",
                "remote.evil.url",
            ),
            (
                "[remote \"evil\"]\n\turl = \"::sh -c x\"\n",
                "remote.evil.url",
            ),
            (
                "[branch \"dev\"]\n\tremote = ext::sh -c x\n",
                "branch.dev.remote",
            ),
            ("[remote]\n\tpushDefault = ext://x\n", "remote.pushdefault"),
            (
                "[submodule \"lib\"]\n\turl = ext::sh -c x\n",
                "submodule.lib.url",
            ),
        ] {
            std::fs::write(&config, format!("{base}{checkout}{extra}")).unwrap();
            let error = prepare_readonly_git(root).await.unwrap_err();
            assert!(
                error.contains("unsafe Git config value") && error.contains(key),
                "{extra}: {error}"
            );
        }
        std::fs::write(&config, format!("{base}{checkout}")).unwrap();
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
        validate_git_configs(
            &git,
            &dir.path().join(".git"),
            dir.path(),
            &CheckoutCredentialContext::default(),
        )
        .await
        .unwrap();
    }

    // ── actions/checkout credential includes ─────────────────────────

    const CHECKOUT_UUID: &str = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0";
    /// Recognisable fake token; it must never appear in an error.
    const FAKE_TOKEN: &str = "eC1hY2Nlc3MtdG9rZW46RkFLRS1WRVRUQUxPTi1UT0tFTg";

    fn checkout_credential_name() -> String {
        format!("git-credentials-{CHECKOUT_UUID}.config")
    }

    fn checkout_container_value() -> String {
        format!("/github/runner_temp/{}", checkout_credential_name())
    }

    /// Whether `value` names a checkout credentials file in either the
    /// runner temp dir or the container dir.
    fn is_checkout_credential_path(value: &str, runner_temp: &str, windows: bool) -> bool {
        let path = checkout_credential_path(value, runner_temp, windows);
        path.host || path.container
    }

    /// What actions/checkout writes into the credentials file, plus `extra`.
    fn checkout_credentials(extra: &str) -> String {
        format!(
            "[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic {FAKE_TOKEN}\n{extra}"
        )
    }

    /// Quote a value or subsection for a Git config file.
    fn git_config_quote(value: &str) -> String {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }

    fn include_if(condition: &str, value: &str) -> String {
        format!(
            "[includeIf {}]\n\tpath = {}\n",
            git_config_quote(&format!("gitdir:{condition}")),
            git_config_quote(value)
        )
    }

    fn assert_no_token(error: &str) {
        assert!(!error.contains(FAKE_TOKEN), "token leaked: {error}");
        assert!(!error.contains("AUTHORIZATION"), "header leaked: {error}");
    }

    /// A fresh repository plus a sibling directory standing in for
    /// `RUNNER_TEMP`.
    struct CheckoutFixture {
        _dir: tempfile::TempDir,
        git: String,
        root: std::path::PathBuf,
        runner_temp: std::path::PathBuf,
        base_config: String,
    }

    impl CheckoutFixture {
        async fn new() -> Option<Self> {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("repo");
            let runner_temp = dir.path().join("_temp");
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(&runner_temp).unwrap();
            // Like the runner's own temp dir: owner-only writable, so a
            // missing credentials file is trusted (whatever the umask).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&runner_temp, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            let git = crate::audit::scanners::git_for_security_test(&root)?;
            crate::audit::diff_scope::tests::git(&root, &["init", "-q"]).await;
            let base_config = std::fs::read_to_string(root.join(".git/config")).unwrap();
            Some(Self {
                _dir: dir,
                git,
                root,
                runner_temp,
                base_config,
            })
        }

        fn ctx(&self) -> CheckoutCredentialContext {
            CheckoutCredentialContext {
                runner_temp: Some(self.runner_temp.to_str().unwrap().to_owned()),
            }
        }

        fn host_value(&self) -> String {
            self.runner_temp
                .join(checkout_credential_name())
                .to_str()
                .unwrap()
                .to_owned()
        }

        /// The repository's gitdir with forward slashes, as checkout writes
        /// it into the condition.
        fn gitdir_condition(&self) -> String {
            self.root.join(".git").to_str().unwrap().replace('\\', "/")
        }

        /// The canonical (symlink-resolved) gitdir. Git compares `gitdir:`
        /// conditions against the `--git-dir` it was given, which is canonical
        /// (e.g. `/private/var` rather than the `/var` symlink on macOS).
        fn canonical_gitdir_condition(&self) -> String {
            std::fs::canonicalize(self.root.join(".git"))
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/")
        }

        fn set_config(&self, extra: &str) {
            std::fs::write(
                self.root.join(".git/config"),
                format!("{}{extra}", self.base_config),
            )
            .unwrap();
        }

        fn write_credentials(&self, content: &str) {
            std::fs::write(self.host_value(), content).unwrap();
        }

        async fn validate(&self, ctx: &CheckoutCredentialContext) -> Result<(), String> {
            validate_git_configs(&self.git, &self.root.join(".git"), &self.root, ctx).await
        }
    }

    #[test]
    fn checkout_credential_context_needs_github_actions_and_an_absolute_runner_temp() {
        let temp = std::env::temp_dir();
        let os = |value: &str| Some(std::ffi::OsString::from(value));
        let ctx =
            CheckoutCredentialContext::from_vars(os("true"), Some(temp.clone().into_os_string()));
        assert_eq!(ctx.runner_temp.as_deref(), temp.to_str());
        for (actions, runner_temp) in [
            (None, Some(temp.clone().into_os_string())),
            (os("false"), Some(temp.clone().into_os_string())),
            (os("TRUE"), Some(temp.clone().into_os_string())),
            (os("1"), Some(temp.clone().into_os_string())),
            (os("true"), None),
            (os("true"), os("")),
            (os("true"), os("relative/_temp")),
        ] {
            assert_eq!(
                CheckoutCredentialContext::from_vars(actions, runner_temp),
                CheckoutCredentialContext::default()
            );
        }
        // A RUNNER_TEMP that is not valid UTF-8 gives no context.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let non_utf8 = std::ffi::OsStr::from_bytes(b"/home/runner/work/_temp\xff");
            assert_eq!(
                CheckoutCredentialContext::from_vars(os("true"), Some(non_utf8.to_os_string())),
                CheckoutCredentialContext::default()
            );
        }
    }

    #[test]
    fn checkout_credential_file_names_are_exact() {
        assert!(is_checkout_credential_file_name(&checkout_credential_name()));
        for name in [
            "git-credentials-0F1E2D3C-4B5A-4968-8776-A5B4C3D2E1F0.config",
            "git-credentials-0f1e2d3c-4b5a-4968-8776-a5b4c3d2E1f0.config",
            "git-credentials-0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0",
            "git-credentials-0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0.config.bak",
            "git-credentials-0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0.configx",
            "git-credentials-0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0.CONFIG",
            "git-credentials-x.config",
            "git-credentials-.config",
            "git-credentials-0f1e2d3c4b5a49688776a5b4c3d2e1f0.config",
            "git-credentials-0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f.config",
            "git-credentials-0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0-0.config",
            "git-credentials-0f1e2d3g-4b5a-4968-8776-a5b4c3d2e1f0.config",
            "x-git-credentials-0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0.config",
        ] {
            assert!(!is_checkout_credential_file_name(name), "{name}");
        }
    }

    #[test]
    fn checkout_credential_paths_need_the_runner_temp_parent() {
        let name = checkout_credential_name();

        // Unix host.
        let temp = "/home/runner/work/_temp";
        assert_eq!(
            checkout_credential_path(&format!("{temp}/{name}"), temp, false),
            CheckoutCredentialPath {
                host: true,
                container: false,
            }
        );
        assert_eq!(
            checkout_credential_path(&checkout_container_value(), temp, false),
            CheckoutCredentialPath {
                host: false,
                container: true,
            }
        );
        for value in [format!("{temp}/{name}"), checkout_container_value()] {
            assert!(is_checkout_credential_path(&value, temp, false), "{value}");
            // `path.join` drops a trailing separator of RUNNER_TEMP.
            assert!(
                is_checkout_credential_path(&value, "/home/runner/work/_temp/", false),
                "{value}"
            );
        }
        for value in [
            format!("{temp}/sub/{name}"),
            format!("{temp}/sub/../{name}"),
            format!("{temp}/../_temp/{name}"),
            format!("/home/runner/work/x/../_temp/{name}"),
            format!("{temp}/./{name}"),
            format!("/home/runner/work//_temp/{name}"),
            format!("//home/runner/work/_temp/{name}"),
            format!("{temp}/{name}/"),
            format!("home/runner/work/_temp/{name}"),
            format!("~/work/_temp/{name}"),
            format!("/home/runner/~/_temp/{name}"),
            format!("{temp}\\{name}"),
            format!("\\home\\runner\\work\\_temp\\{name}"),
            format!("/home/runner/work/{name}"),
            format!("/github/runner_temp/sub/{name}"),
            format!("/github/{name}"),
            format!("/github/workspace/{name}"),
            format!("{temp}/git-credentials-x.config"),
            name.clone(),
            String::new(),
        ] {
            assert!(!is_checkout_credential_path(&value, temp, false), "{value}");
        }

        // Windows host: `path.join` writes backslashes.
        let temp = "D:\\a\\_temp";
        for value in [
            format!("{temp}\\{name}"),
            format!("D:/a/_temp/{name}"),
            format!("{temp}/{name}"),
            checkout_container_value(),
        ] {
            assert!(is_checkout_credential_path(&value, temp, true), "{value}");
        }
        for value in [
            format!("{temp}\\sub\\{name}"),
            format!("{temp}\\..\\_temp\\{name}"),
            format!("{temp}\\.\\{name}"),
            format!("D:a\\_temp\\{name}"),
            format!("C:\\a\\_temp\\{name}"),
            format!("\\\\?\\D:\\a\\_temp\\{name}"),
            format!("\\\\server\\a\\_temp\\{name}"),
            format!("{temp}\\{name}\\"),
            format!("{temp}\\{name}."),
            format!("{temp}\\\\{name}"),
        ] {
            assert!(!is_checkout_credential_path(&value, temp, true), "{value}");
        }
        // On a non-Windows host a backslash is never a separator.
        assert!(!is_checkout_credential_path(
            &format!("{temp}\\{name}"),
            temp,
            false
        ));
    }

    #[test]
    fn checkout_credential_include_keys_are_exact() {
        use CheckoutCredentialInclude::{Container, Host};
        let name = checkout_credential_name();
        let container = checkout_container_value();
        let no_ctx = CheckoutCredentialContext::default();
        for (windows, temp, host, gitdir) in [
            (
                false,
                "/home/runner/work/_temp",
                format!("/home/runner/work/_temp/{name}"),
                "/home/runner/work/r/r/.git",
            ),
            (
                true,
                "D:\\a\\_temp",
                format!("D:\\a\\_temp\\{name}"),
                "D:/a/r/r/.git",
            ),
        ] {
            let ctx = CheckoutCredentialContext {
                runner_temp: Some(temp.into()),
            };
            let gitdirs = [gitdir.to_owned()];
            let include = |key: &str, value: &str, ctx: &CheckoutCredentialContext| {
                checkout_credential_include(key, value, ctx, &gitdirs, windows)
            };
            let host_keys = [
                format!("includeif.gitdir:{gitdir}.path"),
                format!("includeif.gitdir:{gitdir}/worktrees/*.path"),
            ];
            let container_keys = [
                "includeif.gitdir:/github/workspace/.git.path".to_string(),
                "includeif.gitdir:/github/workspace/.git/worktrees/*.path".to_string(),
                "includeif.gitdir:/github/workspace/o/r/.git.path".to_string(),
            ];
            for key in &host_keys {
                assert_eq!(include(key, &host, &ctx), Some(Host), "{key}");
                assert_eq!(include(key, &host, &no_ctx), None, "{key}");
                // A host condition does not cover the container path.
                assert_eq!(include(key, &container, &ctx), None, "{key}");
                // The general check is unchanged and still refuses the key.
                assert!(forbidden_git_config_key(key), "{key}");
            }
            for key in &container_keys {
                assert_eq!(include(key, &container, &ctx), Some(Container), "{key}");
                assert_eq!(include(key, &container, &no_ctx), None, "{key}");
                // A container condition does not cover the host path.
                assert_eq!(include(key, &host, &ctx), None, "{key}");
                assert!(forbidden_git_config_key(key), "{key}");
            }
            for key in [
                "include.path".to_string(),
                format!("includeif.gitdir/i:{gitdir}.path"),
                "includeif.onbranch:main.path".to_string(),
                "includeif.hasconfig:remote.*.url:https://github.com/**.path".to_string(),
                format!("includeif.GitDir:{gitdir}.path"),
                format!("includeif.gitdir:{gitdir}.other"),
                "includeif.path".to_string(),
                "includeifx.gitdir:/x/.git.path".to_string(),
                "include.gitdir:/x/.git.path".to_string(),
                "http.gitdir:/x/.git.path".to_string(),
                "includeif.gitdir:**.path".to_string(),
                "includeif.gitdir:/home/runner/work/other/other/.git.path".to_string(),
            ] {
                assert_eq!(include(&key, &host, &ctx), None, "{key}");
                assert_eq!(include(&key, &container, &ctx), None, "{key}");
            }
        }
    }

    #[test]
    fn host_checkout_conditions_name_this_repository_only() {
        let unix = ["/home/runner/work/r/r/.git".to_string()];
        for condition in [
            "gitdir:/home/runner/work/r/r/.git",
            "gitdir:/home/runner/work/r/r/.git/worktrees/*",
        ] {
            assert!(
                is_host_checkout_condition(condition, &unix, false),
                "{condition}"
            );
        }
        for condition in [
            "gitdir:**",
            "gitdir:**/.git",
            "gitdir:/home/runner/work/r/r/",
            "gitdir:/home/runner/work/r/r",
            "gitdir:/home/runner/work/*/r/.git",
            "gitdir:/home/runner/work/r/r/.git/",
            "gitdir:/home/runner/work/r/r/.git/worktrees/**",
            "gitdir:/home/runner/work/r/r/.git/worktrees/x",
            "gitdir:/home/runner/work/R/r/.git",
            "gitdir:/home/runner/work/other/other/.git",
            "gitdir/i:/home/runner/work/r/r/.git",
            "/home/runner/work/r/r/.git",
            "gitdir:",
        ] {
            assert!(
                !is_host_checkout_condition(condition, &unix, false),
                "{condition}"
            );
        }
        // No spelling of the repository: nothing matches.
        assert!(!is_host_checkout_condition(
            "gitdir:/home/runner/work/r/r/.git",
            &[],
            false
        ));

        // Windows: case-insensitive, so either drive letter case matches.
        let windows = ["D:/a/r/r/.git".to_string()];
        for condition in [
            "gitdir:D:/a/r/r/.git",
            "gitdir:d:/a/r/r/.git",
            "gitdir:d:/A/R/r/.git/worktrees/*",
        ] {
            assert!(
                is_host_checkout_condition(condition, &windows, true),
                "{condition}"
            );
        }
        for condition in [
            "gitdir:C:/a/r/r/.git",
            "gitdir:**",
            "gitdir:D:\\a\\r\\r\\.git",
        ] {
            assert!(
                !is_host_checkout_condition(condition, &windows, true),
                "{condition}"
            );
        }
        assert!(!is_host_checkout_condition(
            "gitdir:d:/a/r/r/.git",
            &windows,
            false
        ));

        assert_eq!(
            strip_windows_verbatim_prefix(r"\\?\D:\a\r\.git"),
            r"D:\a\r\.git"
        );
        assert_eq!(
            strip_windows_verbatim_prefix(r"\\?\UNC\host\share\r\.git"),
            r"\\host\share\r\.git"
        );
        assert_eq!(
            strip_windows_verbatim_prefix(r"D:\a\r\.git"),
            r"D:\a\r\.git"
        );
    }

    #[test]
    fn container_checkout_conditions_are_plain_workspace_paths() {
        for condition in [
            "gitdir:/github/workspace/.git",
            "gitdir:/github/workspace/.git/worktrees/*",
            "gitdir:/github/workspace/x/.git",
            "gitdir:/github/workspace/o/r/.git/worktrees/*",
            "gitdir:/github/workspace/a-b_c.d/.git",
        ] {
            assert!(is_container_checkout_condition(condition), "{condition}");
        }
        for condition in [
            "gitdir:/github/workspace/*/.git",
            "gitdir:/github/workspace/**/.git",
            "gitdir:/github/workspace/x?/.git",
            "gitdir:/github/workspace/[x]/.git",
            "gitdir:/github/workspace/x\\y/.git",
            "gitdir:/github/workspace/../x/.git",
            "gitdir:/github/workspace/./.git",
            "gitdir:/github/workspace//.git",
            "gitdir:/github/workspace/x//.git",
            "gitdir:/github/workspacex/.git",
            "gitdir:/github/workspace",
            "gitdir:/github/workspace/",
            "gitdir:/github/workspace/.git/",
            "gitdir:/github/workspace/.git/worktrees/x",
            "gitdir:/github/workspace/.git/worktrees/**",
            "gitdir:/tmp/x/.git",
            "gitdir:**/.git",
            "gitdir/i:/github/workspace/.git",
            "gitdir:/GITHUB/workspace/.git",
        ] {
            assert!(!is_container_checkout_condition(condition), "{condition}");
        }
    }

    #[test]
    fn checkout_credential_entries_are_https_extraheaders_only() {
        for key in [
            "http.https://github.com/.extraheader",
            "http.https://ghes.example:8443/.extraHeader",
        ] {
            assert!(is_checkout_credential_entry(key), "{key}");
        }
        for key in [
            "http.extraheader",
            "http.http://github.com/.extraheader",
            "http.HTTPS://github.com/.extraheader",
            "http.https://.extraheader",
            "http.https://git hub.com/.extraheader",
            "http.https://github.com/.proxy",
            "http.https://github.com/.sslverify",
            "url.https://github.com/.extraheader",
            "core.fsmonitor",
            "credential.helper",
            "include.path",
        ] {
            assert!(!is_checkout_credential_entry(key), "{key}");
        }
    }

    /// Each of checkout's include shapes is accepted with the CI context
    /// and refused without it.
    #[tokio::test]
    async fn checkout_credential_includes_are_accepted_on_github_actions() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let ctx = fx.ctx();
        let host = fx.host_value();
        let gitdir = fx.gitdir_condition();
        let container = checkout_container_value();
        fx.write_credentials(&checkout_credentials(""));
        for config in [
            include_if(&gitdir, &host),
            include_if(&format!("{gitdir}/worktrees/*"), &host),
            include_if("/github/workspace/.git", &container),
            include_if("/github/workspace/.git/worktrees/*", &container),
        ] {
            fx.set_config(&config);
            if let Err(error) = fx.validate(&ctx).await {
                panic!("{config}: {error}");
            }
            let refused = fx
                .validate(&CheckoutCredentialContext::default())
                .await
                .unwrap_err();
            assert!(refused.contains("unsafe Git config key"), "{refused}");
            assert_no_token(&refused);
        }

        // Git skips a missing include file, so a missing host file passes.
        fx.set_config(&include_if(&gitdir, &host));
        std::fs::remove_file(&host).unwrap();
        fx.validate(&ctx).await.unwrap();
        // A GHES origin with a port is just another https extraheader.
        fx.write_credentials(
            "[http \"https://ghes.example:8443/\"]\n\textraheader = AUTHORIZATION: basic x\n",
        );
        fx.validate(&ctx).await.unwrap();
    }

    /// Includes that are not exactly checkout's still hit the general
    /// refusal, even on GitHub Actions with a valid credentials file.
    #[tokio::test]
    async fn non_checkout_includes_are_still_refused_on_github_actions() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let ctx = fx.ctx();
        let host = fx.host_value();
        let gitdir = fx.gitdir_condition();
        let temp = fx.runner_temp.to_str().unwrap();
        let name = checkout_credential_name();
        let valid = checkout_credentials("");
        fx.write_credentials(&valid);
        std::fs::create_dir(fx.runner_temp.join("sub")).unwrap();
        std::fs::write(fx.runner_temp.join("sub").join(&name), &valid).unwrap();

        let quoted = git_config_quote(&host);
        let mut configs = vec![
            format!("[include]\n\tpath = {quoted}\n"),
            format!(
                "[includeIf {}]\n\tpath = {quoted}\n",
                git_config_quote(&format!("gitdir/i:{gitdir}"))
            ),
            format!("[includeIf \"onbranch:main\"]\n\tpath = {quoted}\n"),
            format!(
                "[includeIf \"hasconfig:remote.*.url:https://github.com/**\"]\n\tpath = {quoted}\n"
            ),
        ];
        let upper = CHECKOUT_UUID.to_ascii_uppercase();
        for value in [
            format!("{temp}/git-credentials-{upper}.config"),
            format!("{temp}/git-credentials-{CHECKOUT_UUID}"),
            format!("{temp}/git-credentials-{CHECKOUT_UUID}.config.bak"),
            format!("{temp}/git-credentials-x.config"),
            format!("{temp}/sub/{name}"),
            format!("{temp}/sub/../{name}"),
            format!("/github/runner_temp/sub/{name}"),
            name.clone(),
        ] {
            configs.push(include_if(&gitdir, &value));
        }
        for config in configs {
            fx.set_config(&config);
            let error = fx.validate(&ctx).await.unwrap_err();
            assert!(error.contains("unsafe Git config key"), "{config}: {error}");
            assert_no_token(&error);
        }
    }

    /// An existing credentials file must be a small regular file that sets
    /// only an https extraheader; the token never reaches an error.
    #[tokio::test]
    async fn checkout_credential_targets_must_only_set_an_https_extraheader() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let ctx = fx.ctx();
        let host = fx.host_value();
        fx.set_config(&include_if(&fx.gitdir_condition(), &host));
        let valid = checkout_credentials("");
        fx.write_credentials(&valid);
        fx.validate(&ctx).await.unwrap();

        for extra in [
            "[core]\n\tfsmonitor = /tmp/x\n".to_string(),
            "[url \"ext::x\"]\n\tinsteadOf = https://github.com/\n".to_string(),
            "[http \"https://x/\"]\n\tproxy = http://proxy.invalid\n".to_string(),
            "[credential]\n\thelper = !sh -c x\n".to_string(),
            "[include]\n\tpath = /tmp/other\n".to_string(),
            "[includeIf \"gitdir:/\"]\n\tpath = /tmp/other\n".to_string(),
            "[http]\n\textraheader = X: y\n".to_string(),
            format!(
                "[http \"http://github.com/\"]\n\textraheader = AUTHORIZATION: basic {FAKE_TOKEN}\n"
            ),
            format!(
                "[http \"HTTPS://github.com/\"]\n\textraheader = AUTHORIZATION: basic {FAKE_TOKEN}\n"
            ),
            "[http \"https://github.com/\"]\n\tsslVerify = false\n".to_string(),
            "[http \"https://github.com/\"]\n\tsslCert = /tmp/x\n".to_string(),
            "[http \"https://github.com/\"]\n\tcookieFile = /tmp/x\n".to_string(),
            "[http]\n\tsslCAInfo = /tmp/x\n".to_string(),
            "[core]\n\texcludesFile = /tmp/x\n".to_string(),
            "[mailmap]\n\tfile = /tmp/x\n".to_string(),
        ] {
            fx.write_credentials(&format!("{valid}{extra}"));
            let error = fx.validate(&ctx).await.unwrap_err();
            assert!(
                error.contains("may only set http.<https URL>.extraheader"),
                "{extra}: {error}"
            );
            assert_no_token(&error);
        }
        // Only a non-https extraheader, without the valid one.
        fx.write_credentials(&format!(
            "[http \"http://github.com/\"]\n\textraheader = AUTHORIZATION: basic {FAKE_TOKEN}\n"
        ));
        let error = fx.validate(&ctx).await.unwrap_err();
        assert!(error.contains("may only set"), "{error}");
        assert_no_token(&error);

        // A file Git cannot parse.
        fx.write_credentials(&format!("{valid}[http\n"));
        let error = fx.validate(&ctx).await.unwrap_err();
        assert!(error.contains("cannot safely parse"), "{error}");
        assert_no_token(&error);

        // Over 64 KiB.
        let padding = "x".repeat(MAX_CHECKOUT_CREDENTIAL_BYTES as usize);
        fx.write_credentials(&format!("{valid}# {padding}\n"));
        let error = fx.validate(&ctx).await.unwrap_err();
        assert!(error.contains("exceeds the validation limit"), "{error}");
        assert_no_token(&error);

        // A directory.
        std::fs::remove_file(&host).unwrap();
        std::fs::create_dir(&host).unwrap();
        let error = fx.validate(&ctx).await.unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
        std::fs::remove_dir(&host).unwrap();

        // A symlink, even to a valid credentials file.
        #[cfg(unix)]
        {
            let real = fx.runner_temp.join("real.config");
            std::fs::write(&real, &valid).unwrap();
            std::os::unix::fs::symlink(&real, &host).unwrap();
            let error = fx.validate(&ctx).await.unwrap_err();
            assert!(error.contains("not a regular file"), "{error}");
            assert_no_token(&error);
            std::fs::remove_file(&host).unwrap();
        }

        fx.write_credentials(&valid);
        fx.validate(&ctx).await.unwrap();
    }

    #[tokio::test]
    async fn checkout_credential_includes_are_capped() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let ctx = fx.ctx();
        let container = checkout_container_value();
        let config = |count: usize| {
            (0..count)
                .map(|i| include_if(&format!("/github/workspace/r{i}/.git"), &container))
                .collect::<String>()
        };
        fx.set_config(&config(MAX_CHECKOUT_CREDENTIAL_INCLUDES));
        fx.validate(&ctx).await.unwrap();
        fx.set_config(&config(MAX_CHECKOUT_CREDENTIAL_INCLUDES + 1));
        let error = fx.validate(&ctx).await.unwrap_err();
        assert!(
            error.contains(&format!(
                "validation limit of {MAX_CHECKOUT_CREDENTIAL_INCLUDES}"
            )),
            "{error}"
        );
    }

    /// A host include is accepted only under a condition naming this
    /// repository's own `.git` (as given or canonical), never a broader or
    /// another repository's condition.
    #[tokio::test]
    async fn host_checkout_includes_need_this_repositorys_gitdir() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let ctx = fx.ctx();
        let host = fx.host_value();
        let gitdir = fx.gitdir_condition();
        fx.write_credentials(&checkout_credentials(""));
        let canonical = repo_gitdir_spellings(&fx.root).last().cloned().unwrap();
        for condition in [
            gitdir.clone(),
            format!("{gitdir}/worktrees/*"),
            canonical.clone(),
            format!("{canonical}/worktrees/*"),
        ] {
            fx.set_config(&include_if(&condition, &host));
            if let Err(error) = fx.validate(&ctx).await {
                panic!("{condition}: {error}");
            }
        }
        for condition in [
            "**".to_string(),
            "**/.git".to_string(),
            "/home/runner/work/other/other/.git".to_string(),
            format!("{gitdir}/"),
            format!("{gitdir}/worktrees/**"),
            gitdir.trim_end_matches("/.git").to_string(),
            "/github/workspace/.git".to_string(),
        ] {
            fx.set_config(&include_if(&condition, &host));
            let error = fx.validate(&ctx).await.unwrap_err();
            assert!(
                error.contains("unsafe Git config key"),
                "{condition}: {error}"
            );
            assert_no_token(&error);
        }
    }

    /// A container include is accepted only under a plain
    /// `/github/workspace/…/.git` condition.
    #[tokio::test]
    async fn container_checkout_includes_need_a_plain_workspace_gitdir() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let ctx = fx.ctx();
        let container = checkout_container_value();
        for condition in [
            "/github/workspace/x/.git",
            "/github/workspace/x/.git/worktrees/*",
        ] {
            fx.set_config(&include_if(condition, &container));
            if let Err(error) = fx.validate(&ctx).await {
                panic!("{condition}: {error}");
            }
        }
        let gitdir = fx.gitdir_condition();
        for condition in [
            "/github/workspace/*/.git",
            "/github/workspace/**",
            "/tmp/x/.git",
            "**",
            gitdir.as_str(),
        ] {
            fx.set_config(&include_if(condition, &container));
            let error = fx.validate(&ctx).await.unwrap_err();
            assert!(
                error.contains("unsafe Git config key"),
                "{condition}: {error}"
            );
        }
    }

    /// checkout writes its includes only into `.git/config`; the same
    /// include in `config.worktree` is refused.
    #[tokio::test]
    async fn checkout_credential_includes_in_config_worktree_are_refused() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let ctx = fx.ctx();
        let host = fx.host_value();
        let include = include_if(&fx.gitdir_condition(), &host);
        fx.write_credentials(&checkout_credentials(""));
        fx.set_config(&include);
        fx.validate(&ctx).await.unwrap();

        fx.set_config("");
        let worktree_config = fx.root.join(".git/config.worktree");
        std::fs::write(&worktree_config, &include).unwrap();
        let error = fx.validate(&ctx).await.unwrap_err();
        assert!(error.contains("unsafe Git config key"), "{error}");
        assert_no_token(&error);
        let container = include_if("/github/workspace/.git", &checkout_container_value());
        std::fs::write(&worktree_config, container).unwrap();
        let error = fx.validate(&ctx).await.unwrap_err();
        assert!(error.contains("unsafe Git config key"), "{error}");
    }

    /// A missing host credentials file is trusted only in an existing,
    /// owner-only-writable RUNNER_TEMP on Unix. A missing container file is
    /// always accepted.
    #[cfg(unix)]
    #[tokio::test]
    async fn missing_host_credentials_need_a_private_runner_temp() {
        use std::os::unix::fs::PermissionsExt;
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let gitdir = fx.gitdir_condition();
        let set_mode = |mode: u32| {
            std::fs::set_permissions(&fx.runner_temp, std::fs::Permissions::from_mode(mode))
                .unwrap();
        };

        // RUNNER_TEMP does not exist.
        let gone = fx.runner_temp.join("gone");
        let ctx = CheckoutCredentialContext {
            runner_temp: Some(gone.to_str().unwrap().to_owned()),
        };
        let value = gone.join(checkout_credential_name());
        fx.set_config(&include_if(&gitdir, value.to_str().unwrap()));
        let error = fx.validate(&ctx).await.unwrap_err();
        assert!(error.contains("names a missing file"), "{error}");

        // RUNNER_TEMP exists but is group- or world-writable.
        let ctx = fx.ctx();
        fx.set_config(&include_if(&gitdir, &fx.host_value()));
        fx.validate(&ctx).await.unwrap();
        for mode in [0o770, 0o707, 0o777] {
            set_mode(mode);
            let error = fx.validate(&ctx).await.unwrap_err();
            assert!(error.contains("names a missing file"), "{mode:o}: {error}");
        }
        // Group/other read and search bits alone are fine.
        set_mode(0o755);
        fx.validate(&ctx).await.unwrap();

        // RUNNER_TEMP is a regular file.
        let file_temp = fx.runner_temp.join("file");
        std::fs::write(&file_temp, "").unwrap();
        let ctx = CheckoutCredentialContext {
            runner_temp: Some(file_temp.to_str().unwrap().to_owned()),
        };
        let value = file_temp.join(checkout_credential_name());
        fx.set_config(&include_if(&gitdir, value.to_str().unwrap()));
        assert!(fx.validate(&ctx).await.is_err());

        // A symlinked RUNNER_TEMP is judged by its target.
        let link = fx.runner_temp.join("link");
        let real = fx.runner_temp.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let ctx = CheckoutCredentialContext {
            runner_temp: Some(link.to_str().unwrap().to_owned()),
        };
        let value = link.join(checkout_credential_name());
        fx.set_config(&include_if(&gitdir, value.to_str().unwrap()));
        fx.validate(&ctx).await.unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(fx.validate(&ctx).await.is_err());

        // The container path is accepted when missing, whatever RUNNER_TEMP.
        set_mode(0o777);
        fx.set_config(&include_if(
            "/github/workspace/.git",
            &checkout_container_value(),
        ));
        fx.validate(&fx.ctx()).await.unwrap();
        set_mode(0o700);
    }

    /// When `git log` fails after a credential include was accepted (here
    /// the credentials file breaks after validation), the Unavailable reason,
    /// which quotes Git's stderr, never carries the token.
    #[tokio::test]
    async fn git_history_failure_never_reports_the_token() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        // Canonical form so Git matches the include against its `--git-dir`.
        fx.set_config(&include_if(
            &fx.canonical_gitdir_condition(),
            &fx.host_value(),
        ));
        fx.write_credentials(&checkout_credentials(""));
        std::fs::write(fx.root.join("a.txt"), "a\n").unwrap();
        crate::audit::diff_scope::tests::git(&fx.root, &["add", "a.txt"]).await;
        crate::audit::diff_scope::tests::git(&fx.root, &["commit", "-qm", "base"]).await;
        let (git, git_dir) = prepare_readonly_git_with(&fx.root, &fx.ctx())
            .await
            .unwrap();

        // The token sits on and around the line Git cannot parse.
        fx.write_credentials(&checkout_credentials(&format!(
            "[http \"https://github.com/{FAKE_TOKEN}\n\textraheader = AUTHORIZATION: basic {FAKE_TOKEN}\n"
        )));
        match git_history_with(&git, &git_dir, &fx.root).await {
            GitHistoryStatus::Unavailable { reason } => {
                assert!(reason.contains("git log exited"), "{reason}");
                assert_no_token(&reason);
            }
            available => panic!("Git did not follow the include: {available:?}"),
        }
    }

    /// The config check must not let Git open a file named by the scanned
    /// repository's `[include]` (Git reads a discovered repository's config
    /// with includes to decide on a pager, unless `--no-pager` or an empty
    /// `--git-dir` prevents it): the include is refused by key, not by a
    /// parse failure of its target.
    #[tokio::test]
    async fn config_validation_never_opens_repository_includes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let Some(git) = crate::audit::scanners::git_for_security_test(&root) else {
            return;
        };
        crate::audit::diff_scope::tests::git(&root, &["init", "-q"]).await;
        let bad = dir.path().join("bad.cfg");
        std::fs::write(&bad, "this is [ not valid\n").unwrap();
        let config = root.join(".git/config");
        let base = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            format!(
                "{base}[include]\n\tpath = {}\n",
                git_config_quote(bad.to_str().unwrap())
            ),
        )
        .unwrap();
        let error = validate_git_configs(
            &git,
            &root.join(".git"),
            &root,
            &CheckoutCredentialContext::default(),
        )
        .await
        .unwrap_err();
        assert!(
            error.contains("unsafe Git config key is not allowed: include.path"),
            "{error}"
        );
    }

    /// Same with a FIFO as the include target: opening it would block until
    /// the 5 s timeout, so the check must come back quickly.
    #[cfg(unix)]
    #[tokio::test]
    async fn config_validation_never_blocks_on_a_fifo_include() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let Some(git) = crate::audit::scanners::git_for_security_test(&root) else {
            return;
        };
        crate::audit::diff_scope::tests::git(&root, &["init", "-q"]).await;
        let fifo = dir.path().join("fifo.cfg");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let config = root.join(".git/config");
        let base = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            format!(
                "{base}[include]\n\tpath = {}\n",
                git_config_quote(fifo.to_str().unwrap())
            ),
        )
        .unwrap();
        let started = std::time::Instant::now();
        let error = validate_git_configs(
            &git,
            &root.join(".git"),
            &root,
            &CheckoutCredentialContext::default(),
        )
        .await
        .unwrap_err();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
        assert!(
            error.contains("unsafe Git config key is not allowed: include.path"),
            "{error}"
        );
    }

    /// A repository in a directory with a non-ASCII name (`倉庫`) whose
    /// `.git/config` includes a file Git cannot parse. Returns the temp dir
    /// guard, the repository root and Git.
    async fn non_ascii_repo_with_bad_include()
    -> Option<(tempfile::TempDir, std::path::PathBuf, String)> {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("倉庫");
        std::fs::create_dir(&root).unwrap();
        let git = crate::audit::scanners::git_for_security_test(&root)?;
        crate::audit::diff_scope::tests::git(&root, &["init", "-q"]).await;
        let bad = dir.path().join("bad.cfg");
        std::fs::write(&bad, "this is [ not valid\n").unwrap();
        let config = root.join(".git/config");
        let base = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            format!(
                "{base}[include]\n\tpath = {}\n",
                git_config_quote(bad.to_str().unwrap())
            ),
        )
        .unwrap();
        Some((dir, root, git))
    }

    /// The production check on a repository with a non-ASCII path (which on
    /// macOS makes Git consult `core.precomposeunicode` of a discovered
    /// repository) refuses the include by key and never fails to parse.
    #[tokio::test]
    async fn config_validation_refuses_includes_by_key_in_a_non_ascii_repo() {
        let Some((_dir, root, git)) = non_ascii_repo_with_bad_include().await else {
            return;
        };
        let error = validate_git_configs(
            &git,
            &root.join(".git"),
            &root,
            &CheckoutCredentialContext::default(),
        )
        .await
        .unwrap_err();
        assert!(
            error.contains("unsafe Git config key is not allowed: include.path"),
            "{error}"
        );
        assert!(!error.contains("cannot safely parse"), "{error}");
    }

    /// `--no-pager` matters on its own: run inside the repository (so Git
    /// discovers it) with a relative ASCII `--file` path, the listing works
    /// with `--no-pager` alone and lists the include key, while without any
    /// protection Git reads the repository config with includes for the
    /// pager decision and fails on the bad include.
    #[tokio::test]
    async fn config_listing_no_pager_alone_skips_the_pager_config_read() {
        let Some((_dir, root, git)) = non_ascii_repo_with_bad_include().await else {
            return;
        };
        let listed = run_git_config_listing(&git, &["--no-pager"], ".git/config", &root)
            .await
            .expect("--no-pager alone must not read repository includes");
        assert!(
            git_config_entries(&listed).any(|(key, _)| key == "include.path"),
            "{listed:?}"
        );
        assert!(forbidden_git_config_key("include.path"));
        // Control: with discovery and the pager decision both on, Git opens
        // the include before listing, which is what the options prevent.
        assert!(
            run_git_config_listing(&git, &[], ".git/config", &root)
                .await
                .is_none(),
            "Git no longer reads repository includes for the pager decision"
        );
    }

    /// `--git-dir=<fresh empty dir>` turns repository discovery off on its
    /// own: without `--no-pager`, run from inside the repository with a
    /// non-ASCII absolute `--file` path, Git reads no repository config (for
    /// neither the pager decision nor `core.precomposeunicode`) and lists the
    /// include key instead of failing on the bad include.
    #[tokio::test]
    async fn config_listing_git_dir_alone_disables_repository_discovery() {
        let Some((_dir, root, git)) = non_ascii_repo_with_bad_include().await else {
            return;
        };
        let empty = no_repository_dir(&root).expect("empty dir outside the repository");
        assert!(std::fs::read_dir(empty.path()).unwrap().next().is_none());
        let git_dir_arg = format!("--git-dir={}", empty.path().to_str().unwrap());
        let config = root.join(".git/config");
        let listed = run_git_config_listing(
            &git,
            &[git_dir_arg.as_str()],
            config.to_str().unwrap(),
            &root,
        )
        .await
        .expect("an explicit empty --git-dir must not read repository includes");
        assert!(
            git_config_entries(&listed).any(|(key, _)| key == "include.path"),
            "{listed:?}"
        );
        // Git created nothing in the empty directory.
        assert!(std::fs::read_dir(empty.path()).unwrap().next().is_none());
    }

    /// The empty directory is never inside the scanned repository, and is
    /// removed after use.
    #[test]
    fn no_repository_dir_is_fresh_private_and_outside_the_repo() {
        let repo = tempfile::tempdir().unwrap();
        let empty = no_repository_dir(repo.path()).unwrap();
        let path = empty.path().to_path_buf();
        assert!(std::fs::read_dir(&path).unwrap().next().is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{mode:o}");
        }
        let other = no_repository_dir(repo.path()).unwrap();
        assert_ne!(other.path(), path.as_path());
        drop(empty);
        assert!(!path.exists());
        // A repository root that contains the temp dir is refused.
        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert_eq!(
            no_repository_dir(&temp).unwrap_err(),
            ConfigListingError::TempDirInsideRepository
        );
    }

    /// A temp dir inside the scanned repository is reported as such (with
    /// how to fix it), not as a config parse failure, still failing closed,
    /// and nothing is created inside the repository.
    #[tokio::test]
    async fn temp_dir_inside_the_repository_has_its_own_reason() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        let inner_temp = root.join("tmp");
        std::fs::create_dir_all(&inner_temp).unwrap();
        for base in [root.as_path(), inner_temp.as_path()] {
            assert_eq!(
                no_repository_dir_in(base, &root).unwrap_err(),
                ConfigListingError::TempDirInsideRepository,
                "{}",
                base.display()
            );
        }
        assert_eq!(std::fs::read_dir(&inner_temp).unwrap().count(), 0);
        // A base outside the repository works.
        let outside = no_repository_dir_in(dir.path(), &root).unwrap();
        assert!(!outside.path().starts_with(&root));
        // A base that does not exist is a plain failure.
        assert_eq!(
            no_repository_dir_in(&dir.path().join("missing"), &root).unwrap_err(),
            ConfigListingError::Failed
        );
        assert!(TEMP_DIR_INSIDE_REPOSITORY.contains("inside the scanned repository"));
        assert!(!TEMP_DIR_INSIDE_REPOSITORY.contains("cannot safely parse"));

        // End to end: the production check, given the system temp dir itself
        // as the scanned repository root (so its empty `--git-dir` would
        // land inside it), reports the distinct reason.
        let Some(git) = crate::audit::scanners::git_for_security_test(&root) else {
            return;
        };
        crate::audit::diff_scope::tests::git(&root, &["init", "-q"]).await;
        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let error = validate_git_configs(
            &git,
            &root.join(".git"),
            &temp,
            &CheckoutCredentialContext::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error, TEMP_DIR_INSIDE_REPOSITORY, "{error}");
    }

    /// End to end: the config actions/checkout writes (host and container
    /// includes, each for the repository and its worktrees) with a real
    /// credentials file passes the production entry point with the CI
    /// context, Git still reads history through the include, and the same
    /// repository is refused without the context.
    #[tokio::test]
    async fn prepare_readonly_git_accepts_actions_checkout_credentials() {
        let Some(fx) = CheckoutFixture::new().await else {
            return;
        };
        let host = fx.host_value();
        // Canonical form so Git matches the include against its `--git-dir`.
        let gitdir = fx.canonical_gitdir_condition();
        let container = checkout_container_value();
        fx.set_config(&format!(
            "[remote \"origin\"]\n\turl = https://github.com/o/r\n{}{}{}{}",
            include_if(&gitdir, &host),
            include_if(&format!("{gitdir}/worktrees/*"), &host),
            include_if("/github/workspace/.git", &container),
            include_if("/github/workspace/.git/worktrees/*", &container),
        ));
        fx.write_credentials(&checkout_credentials(""));
        std::fs::write(fx.root.join("a.txt"), "a\n").unwrap();
        crate::audit::diff_scope::tests::git(&fx.root, &["add", "a.txt"]).await;
        crate::audit::diff_scope::tests::git(&fx.root, &["commit", "-qm", "base"]).await;

        let (git, git_dir) = prepare_readonly_git_with(&fx.root, &fx.ctx())
            .await
            .unwrap();
        let history = git_history_with(&git, &git_dir, &fx.root).await;
        assert!(
            matches!(history, GitHistoryStatus::Available { .. }),
            "{history:?}"
        );

        let refused = prepare_readonly_git_with(&fx.root, &CheckoutCredentialContext::default())
            .await
            .unwrap_err();
        assert!(refused.contains("unsafe Git config key"), "{refused}");
        assert_no_token(&refused);
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
