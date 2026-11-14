//! v0.8 B4 (part 1): find the first first-parent commit where a regression
//! test fails, i.e. where the vulnerable behaviour first appears.
//!
//! Git access is read-only and goes through intake's restricted metadata
//! checks (`intake::prepare_readonly_git`) and diff scope's bounded runner
//! (`diff_scope::git_read`). Trees are exported from raw objects: `git
//! ls-tree` lists the entries and one `git cat-file --batch` returns the blob
//! bytes, so no attributes, filters or `$Format:...$` expansion apply. Only
//! regular files are written; symlinks and submodules are skipped, and a
//! finding whose file is (or lies under) one is [`TARGET_NOT_REGULAR`], not
//! [`TARGET_MISSING`]. Ancestry reads ignore commit-graph files. The user's
//! working tree and index are never touched.
//!
//! The search itself ([`bisect`]) is generic over a [`StepRunner`], so it is
//! tested without Git or a sandbox.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use super::diff_scope;
use super::poc_oracle::{OracleSecrets, runner_input};
use super::regression_test::{self, RedState};
use super::scanners::SubprocessLimits;
use super::target_poc::TargetSandbox;

/// Refuse first-parent ranges longer than this.
pub const MAX_COMMITS: usize = 10_000;
/// Default `--max-steps`.
pub const DEFAULT_MAX_STEPS: usize = 20;
/// Largest accepted `--max-steps`.
pub const MAX_STEPS_LIMIT: usize = 40;
/// Consecutive non-`target_missing` unrunnable results before giving up.
pub const MAX_SKIPS: usize = 3;
/// The only [`StepResult::Unrunnable`] reason read as "behaviour absent":
/// the vulnerable code does not exist yet at that commit.
pub const TARGET_MISSING: &str = "target_missing";
/// The finding's file is a symlink, lies inside a submodule or under a
/// symlinked directory at that commit, so it was not exported. An ordinary
/// skip, never read as "behaviour absent".
pub const TARGET_NOT_REGULAR: &str = "target_not_regular";
/// The target is absent but more entries were skipped than
/// [`MAX_SKIPPED_PATHS`], so it cannot be told apart from
/// [`TARGET_NOT_REGULAR`]. An ordinary skip.
pub const TARGET_UNVERIFIED: &str = "target_unverified";
/// Receipt schema version.
pub const RECEIPT_VERSION: u32 = 1;

/// A full 40- (SHA-1) or 64-hex (SHA-256) commit id, stored lowercase.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommitId(String);

impl CommitId {
    pub fn parse(value: &str) -> Result<Self, String> {
        if ![40, 64].contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("expected a 40- or 64-hex commit id".into());
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CommitId {
    type Error = String;
    fn try_from(value: String) -> Result<Self, String> {
        Self::parse(&value)
    }
}

impl From<CommitId> for String {
    fn from(value: CommitId) -> Self {
        value.0
    }
}

impl std::fmt::Display for CommitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Git access
// ---------------------------------------------------------------------------

/// A user-supplied revision: diff scope's conservative syntax (no leading
/// '-', no ranges, no whitespace or controls).
pub fn validate_rev(rev: &str) -> Result<(), String> {
    diff_scope::validate_ref(rev).map(|_| ())
}

/// Parse `git rev-list` output: newline-terminated commit ids only, at most
/// `max_commits` of them.
pub fn parse_rev_list(output: &str, max_commits: usize) -> Result<Vec<CommitId>, String> {
    if !output.is_empty() && !output.ends_with('\n') {
        return Err("Git returned an unterminated commit list".into());
    }
    let mut commits = Vec::new();
    for line in output.split_terminator('\n') {
        if commits.len() == max_commits {
            return Err(format!(
                "first-parent range exceeds {max_commits} commits; pass a closer good revision"
            ));
        }
        let Ok(id) = CommitId::parse(line) else {
            return Err("Git returned an invalid commit id".into());
        };
        commits.push(id);
    }
    Ok(commits)
}

/// Global Git options for ancestry reads: a commit-graph file is a cache that
/// can misreport parents, so ancestry is read from the commit objects.
const NO_COMMIT_GRAPH: [&str; 2] = ["-c", "core.commitGraph=false"];

async fn resolve_commit(
    git: &str,
    git_dir: &Path,
    repo: &Path,
    rev: &str,
) -> Result<CommitId, String> {
    validate_rev(rev)?;
    let spec = format!("{rev}^{{commit}}");
    let out = diff_scope::git_read(
        git,
        git_dir,
        repo,
        &[
            NO_COMMIT_GRAPH[0],
            NO_COMMIT_GRAPH[1],
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &spec,
        ],
    )
    .await
    .map_err(|_| "revision does not resolve to a commit".to_string())?;
    CommitId::parse(&diff_scope::parse_oid(&out)?)
}

/// A first-parent range and the commit ids its bounds resolved to. The ids
/// are resolved once, so the receipt names exactly the commits searched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstParentRange {
    /// Oldest first; the last element is always `bad`.
    pub commits: Vec<CommitId>,
    /// The resolved good revision (exclusive lower bound), when given.
    pub good: Option<CommitId>,
    /// The resolved bad revision.
    pub bad: CommitId,
}

/// First-parent commits after `good` (exclusive) up to `bad` (inclusive),
/// oldest first; from the root when `good` is `None`. The last commit is
/// always `bad`. Refuses more than `max_commits` (capped at [`MAX_COMMITS`]).
/// Commit-graph files are ignored for every ancestry read.
pub async fn first_parent_range(
    repo: &Path,
    good: Option<&str>,
    bad: &str,
    max_commits: usize,
) -> Result<FirstParentRange, String> {
    validate_rev(bad)?;
    if let Some(good) = good {
        validate_rev(good)?;
    }
    let max_commits = max_commits.clamp(1, MAX_COMMITS);
    let (git, git_dir) = super::intake::prepare_readonly_git(repo).await?;
    diff_scope::refuse_grafts(&git_dir)?;
    let bad_id = resolve_commit(&git, &git_dir, repo, bad)
        .await
        .map_err(|e| format!("bad revision: {e}"))?;
    let (range, good_id) = match good {
        Some(good) => {
            let good_id = resolve_commit(&git, &git_dir, repo, good)
                .await
                .map_err(|e| format!("good revision: {e}"))?;
            diff_scope::git_read(
                &git,
                &git_dir,
                repo,
                &[
                    NO_COMMIT_GRAPH[0],
                    NO_COMMIT_GRAPH[1],
                    "merge-base",
                    "--is-ancestor",
                    "--end-of-options",
                    good_id.as_str(),
                    bad_id.as_str(),
                ],
            )
            .await
            .map_err(|_| "good revision is not an ancestor of the bad revision".to_string())?;
            (format!("{good_id}..{bad_id}"), Some(good_id))
        }
        None => {
            // A shallow boundary would masquerade as the root commit.
            if std::fs::symlink_metadata(git_dir.join("shallow")).is_ok() {
                return Err("shallow clone: fetch full history or pass a good revision".into());
            }
            (bad_id.to_string(), None)
        }
    };
    let max_count = format!("--max-count={}", max_commits + 1);
    let out = diff_scope::git_read(
        &git,
        &git_dir,
        repo,
        &[
            NO_COMMIT_GRAPH[0],
            NO_COMMIT_GRAPH[1],
            "rev-list",
            "--first-parent",
            "--reverse",
            &max_count,
            "--end-of-options",
            &range,
            "--",
        ],
    )
    .await?;
    let commits = parse_rev_list(&out, max_commits)?;
    match commits.last() {
        None => return Err("empty range: the good revision already contains the bad one".into()),
        Some(last) if *last != bad_id => {
            return Err("Git returned an inconsistent first-parent range".into());
        }
        Some(_) => {}
    }
    Ok(FirstParentRange {
        commits,
        good: good_id,
        bad: bad_id,
    })
}

/// Fail early when the repository cannot be read through the restricted
/// Git metadata checks.
pub async fn check_git(repo: &Path) -> Result<(), String> {
    super::intake::prepare_readonly_git(repo).await?;
    Ok(())
}

/// Largest `git ls-tree` listing read for one commit.
const LS_TREE_MAX_BYTES: usize = 64 * 1024 * 1024;
/// `git cat-file --batch` header allowance per object, beyond the OID.
const CAT_FILE_HEADER_SLACK: usize = 32;

/// Bounds for [`export_tree_with`].
#[derive(Debug, Clone, Copy)]
pub struct ExtractLimits {
    pub max_total_bytes: u64,
    pub max_entries: usize,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: 512 * 1024 * 1024,
            max_entries: 200_000,
        }
    }
}

/// Most skipped (symlink or submodule) paths [`ExtractStats`] records.
pub const MAX_SKIPPED_PATHS: usize = 10_000;

/// What [`write_tree`] wrote, and the tree entries it deliberately skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractStats {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
    /// Symbolic links (mode 120000); never created.
    pub skipped_symlinks: usize,
    /// Submodules (gitlinks, mode 160000); never fetched.
    pub skipped_submodules: usize,
    /// Paths of skipped symlinks and submodules, in tree order, at most
    /// [`MAX_SKIPPED_PATHS`].
    pub skipped_paths: Vec<String>,
    /// More entries were skipped than [`MAX_SKIPPED_PATHS`].
    pub skipped_paths_truncated: bool,
    /// Exact '/'-separated tree paths written as a regular file (`File` or
    /// `Executable` entries). Presence is decided from this set, never from
    /// the exported directory: on a case-insensitive (or 8.3-aliasing) file
    /// system `src/Foo.py` would otherwise find `src/foo.py`.
    pub written_files: BTreeSet<String>,
}

impl ExtractStats {
    fn record_skipped(&mut self, path: &str) {
        if self.skipped_paths.len() < MAX_SKIPPED_PATHS {
            self.skipped_paths.push(path.to_owned());
        } else {
            self.skipped_paths_truncated = true;
        }
    }

    /// Whether the '/'-separated `path` is a skipped entry or lies under one
    /// (inside a submodule, or under a symlinked directory).
    pub fn skipped_covers(&self, path: &str) -> bool {
        self.skipped_paths.iter().any(|skipped| {
            path.strip_prefix(skipped.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    }
}

fn safe_relative(path: &Path) -> Result<std::path::PathBuf, String> {
    let mut out = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err("path is absolute or contains '..'".into()),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("path is empty".into());
    }
    Ok(out)
}

/// The tree entry kinds `git ls-tree -r` may list for a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// `100644 blob`
    File,
    /// `100755 blob`
    Executable,
    /// `120000 blob`: skipped.
    Symlink,
    /// `160000 commit`: skipped.
    Submodule,
}

/// One validated `git ls-tree -r -z` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub kind: EntryKind,
    /// Lowercase 40- or 64-hex object id.
    pub oid: String,
    /// Validated repo-relative path, '/'-separated.
    pub path: String,
}

/// A tree path is UTF-8, relative, '/'-separated, with no empty, `.`, `..`
/// or `.git` (any case) component. On Windows, components that Windows
/// would reinterpret ([`is_windows_reserved_component`]) are refused too.
pub fn validate_tree_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.starts_with('/') {
        return Err("tree entry path is empty or absolute".into());
    }
    if path.contains('\0') || (cfg!(windows) && path.contains(['\\', ':'])) {
        return Err("tree entry path has an unsafe character".into());
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err("tree entry path has an empty, '.' or '..' component".into());
        }
        if part.eq_ignore_ascii_case(".git") {
            return Err("tree entry path has a .git component".into());
        }
        if cfg!(windows) && is_windows_reserved_component(part) {
            return Err("tree entry path has a Windows device name or trailing '.' or ' '".into());
        }
    }
    Ok(())
}

/// Whether Windows would not create `part` as an ordinary file name: it ends
/// in '.' or ' ' (Windows strips those, aliasing another name), or its stem
/// (before the first '.', trailing spaces ignored) is a DOS device name in
/// any case: CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM0-COM9, LPT0-LPT9, or COM/LPT followed by
/// a superscript 1, 2 or 3. Platform-independent so it is tested everywhere.
pub fn is_windows_reserved_component(part: &str) -> bool {
    if part.ends_with(['.', ' ']) {
        return true;
    }
    let stem = part.split_once('.').map_or(part, |(stem, _)| stem);
    let stem = stem.trim_end_matches(' ').to_ascii_uppercase();
    // CONIN$ and CONOUT$ are console handles; the `$` is part of the stem.
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let Some(suffix) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    else {
        return false;
    };
    let mut chars = suffix.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
    )
}

fn parse_ls_tree_record(record: &[u8]) -> Result<TreeEntry, String> {
    let malformed = || "Git returned a malformed tree entry".to_string();
    let tab = record
        .iter()
        .position(|b| *b == b'\t')
        .ok_or_else(malformed)?;
    let Ok(meta) = std::str::from_utf8(&record[..tab]) else {
        return Err(malformed());
    };
    let mut fields = meta.split(' ');
    let (Some(mode), Some(kind), Some(oid), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(malformed());
    };
    if ![40, 64].contains(&oid.len())
        || !oid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("Git returned an invalid object id in the tree listing".into());
    }
    let kind = match (mode, kind) {
        ("100644", "blob") => EntryKind::File,
        ("100755", "blob") => EntryKind::Executable,
        ("120000", "blob") => EntryKind::Symlink,
        ("160000", "commit") => EntryKind::Submodule,
        _ => return Err("tree entry has an unsupported mode or type".into()),
    };
    let path = std::str::from_utf8(&record[tab + 1..])
        .map_err(|_| "tree entry path is not UTF-8".to_string())?;
    validate_tree_path(path)?;
    Ok(TreeEntry {
        kind,
        oid: oid.to_owned(),
        path: path.to_owned(),
    })
}

/// Parse `git ls-tree -r -z` output: NUL-terminated `<mode> SP <type> SP
/// <oid> TAB <path>` records, at most `max_entries` of them. Unknown modes,
/// malformed records and unsafe or non-UTF-8 paths are refused.
pub fn parse_ls_tree(output: &[u8], max_entries: usize) -> Result<Vec<TreeEntry>, String> {
    let Some(body) = output.strip_suffix(b"\0") else {
        if output.is_empty() {
            return Ok(Vec::new());
        }
        return Err("Git returned an unterminated tree listing".into());
    };
    let mut entries = Vec::new();
    for record in body.split(|b| *b == 0) {
        if entries.len() == max_entries {
            return Err(format!("tree exceeds {max_entries} entries"));
        }
        entries.push(parse_ls_tree_record(record)?);
    }
    Ok(entries)
}

/// Parse `git cat-file --batch` output for exactly `oids`, in order: each
/// object is `<oid> blob <size>\n<size bytes>\n`. A missing object, another
/// object type, a size mismatch, trailing data or more than
/// `max_total_bytes` in total is refused. Returns each blob's bytes.
pub fn parse_cat_file_batch<'a>(
    output: &'a [u8],
    oids: &[&str],
    max_total_bytes: u64,
) -> Result<Vec<&'a [u8]>, String> {
    let mut rest = output;
    let mut blobs = Vec::with_capacity(oids.len());
    let mut total = 0u64;
    for oid in oids {
        let Some(newline) = rest.iter().position(|b| *b == b'\n') else {
            return Err("Git returned a truncated object header".into());
        };
        let size = std::str::from_utf8(&rest[..newline])
            .ok()
            .and_then(|header| header.strip_prefix(*oid))
            .and_then(|header| header.strip_prefix(" blob "))
            .filter(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("Git returned an unexpected object header (missing object or not a blob)")?;
        total = total.saturating_add(size);
        if total > max_total_bytes {
            return Err(format!("tree exceeds {max_total_bytes} bytes"));
        }
        let body = &rest[newline + 1..];
        let Ok(size) = usize::try_from(size) else {
            return Err("object is too large".into());
        };
        if body.len() <= size || body[size] != b'\n' {
            return Err("Git returned an object whose size does not match its header".into());
        }
        blobs.push(&body[..size]);
        rest = &body[size + 1..];
    }
    if !rest.is_empty() {
        return Err("Git returned unexpected extra object data".into());
    }
    Ok(blobs)
}

/// Write regular files from `entries` into the empty directory `dest`,
/// creating parent directories. Symlinks and submodules are counted and
/// skipped. The total written size is checked against `limits` before any
/// file is created; duplicate paths and paths nested under a written file are
/// refused. The caller discards `dest` on error.
pub fn write_tree(
    entries: &[TreeEntry],
    blobs: &BTreeMap<&str, &[u8]>,
    dest: &Path,
    limits: &ExtractLimits,
) -> Result<ExtractStats, String> {
    use std::io::Write;
    if entries.len() > limits.max_entries {
        return Err(format!("tree exceeds {} entries", limits.max_entries));
    }
    let mut stats = ExtractStats::default();
    for entry in entries {
        if !matches!(entry.kind, EntryKind::File | EntryKind::Executable) {
            continue;
        }
        let blob = blobs
            .get(entry.oid.as_str())
            .ok_or("Git did not return a listed blob")?;
        stats.bytes = stats.bytes.saturating_add(blob.len() as u64);
        if stats.bytes > limits.max_total_bytes {
            return Err(format!("tree exceeds {} bytes", limits.max_total_bytes));
        }
    }
    let under = |rel: &str| {
        let mut path = dest.to_path_buf();
        path.extend(rel.split('/'));
        path
    };
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    let mut files: BTreeSet<&str> = BTreeSet::new();
    for entry in entries {
        let executable = match entry.kind {
            EntryKind::Symlink => {
                stats.skipped_symlinks += 1;
                stats.record_skipped(&entry.path);
                continue;
            }
            EntryKind::Submodule => {
                stats.skipped_submodules += 1;
                stats.record_skipped(&entry.path);
                continue;
            }
            EntryKind::File => false,
            EntryKind::Executable => true,
        };
        validate_tree_path(&entry.path)?;
        if let Some((parent, _)) = entry.path.rsplit_once('/') {
            let mut prefix = String::new();
            for part in parent.split('/') {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                if files.contains(prefix.as_str()) {
                    return Err("tree entry is nested under a file".into());
                }
                if dirs.insert(prefix.clone()) {
                    std::fs::create_dir(under(&prefix))
                        .map_err(|e| format!("cannot create an exported directory: {e}"))?;
                    stats.dirs += 1;
                }
            }
        }
        let blob = blobs
            .get(entry.oid.as_str())
            .ok_or("Git did not return a listed blob")?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if executable { 0o755 } else { 0o644 });
        }
        #[cfg(not(unix))]
        let _ = executable;
        let mut file = options
            .open(under(&entry.path))
            .map_err(|e| format!("cannot create an exported file (duplicate path?): {e}"))?;
        file.write_all(blob)
            .map_err(|e| format!("cannot write an exported file: {e}"))?;
        files.insert(entry.path.as_str());
        stats.written_files.insert(entry.path.clone());
        stats.files += 1;
    }
    Ok(stats)
}

/// Export `commit`'s tree into the existing, empty directory `dest_dir`.
/// Entries come from `git ls-tree` and blob bytes from one `git cat-file
/// --batch`, so no attributes (`export-subst`, `export-ignore`), filters or
/// `$Format:...$` expansion apply. Symlinks and submodules are skipped.
/// Never checks out, and never touches the user's working tree or index.
pub async fn export_tree(
    repo: &Path,
    commit: &CommitId,
    dest_dir: &Path,
) -> Result<ExtractStats, String> {
    export_tree_with(repo, commit, dest_dir, &ExtractLimits::default()).await
}

/// [`export_tree`] with explicit limits.
pub async fn export_tree_with(
    repo: &Path,
    commit: &CommitId,
    dest_dir: &Path,
    limits: &ExtractLimits,
) -> Result<ExtractStats, String> {
    let meta = std::fs::symlink_metadata(dest_dir)
        .map_err(|e| format!("export destination is unavailable: {e}"))?;
    if !meta.is_dir() {
        return Err("export destination is not a directory".into());
    }
    if std::fs::read_dir(dest_dir)
        .map_err(|e| format!("cannot read the export destination: {e}"))?
        .next()
        .is_some()
    {
        return Err("export destination is not empty".into());
    }
    let (git, git_dir) = super::intake::prepare_readonly_git(repo).await?;
    let spec = format!("{commit}^{{commit}}");
    let resolved = diff_scope::git_read(
        &git,
        &git_dir,
        repo,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &spec,
        ],
    )
    .await
    .map_err(|_| "commit is not present in the repository".to_string())?;
    if CommitId::parse(resolved.trim())? != *commit {
        return Err("commit id resolved to a different object".into());
    }
    // The repository is untrusted. `git archive` would honour the tree's own
    // `.gitattributes` (`export-subst` may expand `$Format:...$`, which can
    // invoke gpg; `export-ignore` hides files), so read raw objects instead.
    let listing = diff_scope::git_read_bytes_with(
        &git,
        &git_dir,
        repo,
        &[
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            "--end-of-options",
            commit.as_str(),
        ],
        &SubprocessLimits {
            timeout: std::time::Duration::from_secs(60),
            max_output_bytes: LS_TREE_MAX_BYTES,
        },
        None,
    )
    .await?;
    let entries = parse_ls_tree(&listing, limits.max_entries)?;
    drop(listing);
    if entries.iter().any(|e| e.oid.len() != commit.as_str().len()) {
        return Err("tree listing mixes object id formats".into());
    }
    // Each distinct blob is read once; the written total is checked later.
    let oids: Vec<String> = {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        entries
            .iter()
            .filter(|e| matches!(e.kind, EntryKind::File | EntryKind::Executable))
            .filter(|e| seen.insert(e.oid.as_str()))
            .map(|e| e.oid.clone())
            .collect()
    };
    let objects = if oids.is_empty() {
        Vec::new()
    } else {
        read_blobs(&git, &git_dir, repo, &oids, limits).await?
    };
    let dest = dest_dir.to_path_buf();
    let limits = *limits;
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = oids.iter().map(String::as_str).collect();
        let contents = parse_cat_file_batch(&objects, &refs, limits.max_total_bytes)?;
        let blobs: BTreeMap<&str, &[u8]> = refs.into_iter().zip(contents).collect();
        write_tree(&entries, &blobs, &dest, &limits)
    })
    .await
    .map_err(|e| format!("tree export task failed: {e}"))?
}

/// Run one bounded `git cat-file --batch` for `oids`. The OID list is
/// written to an anonymous private temporary file connected as Git's stdin;
/// the raw (binary-safe) output is returned for [`parse_cat_file_batch`].
async fn read_blobs(
    git: &str,
    git_dir: &Path,
    repo: &Path,
    oids: &[String],
    limits: &ExtractLimits,
) -> Result<Vec<u8>, String> {
    use std::io::{Seek, Write};
    let mut request = String::with_capacity(oids.len() * 65);
    for oid in oids {
        request.push_str(oid);
        request.push('\n');
    }
    let io = |e: std::io::Error| format!("cannot prepare the object request: {e}");
    let mut stdin = tempfile::tempfile().map_err(io)?;
    stdin.write_all(request.as_bytes()).map_err(io)?;
    stdin.seek(std::io::SeekFrom::Start(0)).map_err(io)?;
    let per_object = oids.first().map_or(0, String::len) + CAT_FILE_HEADER_SLACK;
    let headers = oids.len().saturating_mul(per_object);
    let max_output_bytes = usize::try_from(limits.max_total_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(headers);
    diff_scope::git_read_bytes_with(
        git,
        git_dir,
        repo,
        &["cat-file", "--batch"],
        &SubprocessLimits {
            timeout: std::time::Duration::from_secs(300),
            max_output_bytes,
        },
        Some(stdin),
    )
    .await
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/// One test run at one commit. `Fails` means the vulnerable behaviour is
/// present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum StepResult {
    Fails,
    Passes,
    /// The test could not run; [`TARGET_MISSING`] means the vulnerable code
    /// does not exist yet.
    Unrunnable(String),
}

/// Runs the regression test at one commit (part 2: export + sandbox).
#[async_trait::async_trait]
pub trait StepRunner: Send {
    async fn run(&mut self, commit: &CommitId) -> StepResult;
}

/// One logged runner call; `index` is the position in the commit range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BisectStep {
    pub index: usize,
    pub commit: CommitId,
    pub result: StepResult,
}

/// How the search ended. `lo` is the newest commit known to lack the
/// behaviour (the good revision when given; `None` when neither is known),
/// `hi` the oldest known to fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BisectOutcome {
    IntroducedIn {
        commit: CommitId,
        last_passing: Option<CommitId>,
    },
    /// Without a good revision, the oldest commit already fails.
    PresentSinceOldest,
    /// The test does not fail at the bad revision.
    NotReproducibleAtBad,
    Inconclusive {
        lo: Option<CommitId>,
        hi: CommitId,
        reason: String,
    },
    StepCapReached {
        lo: Option<CommitId>,
        hi: CommitId,
    },
    /// No commits to test.
    EmptyRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BisectResult {
    pub outcome: BisectOutcome,
    pub steps: Vec<BisectStep>,
    /// A commit lacking the behaviour was seen after one that has it, so the
    /// answer is one transition, not necessarily the first introduction.
    pub non_monotonic: bool,
}

/// Validate a `--max-steps` value.
pub fn validate_max_steps(value: usize) -> Result<usize, String> {
    if (1..=MAX_STEPS_LIMIT).contains(&value) {
        Ok(value)
    } else {
        Err(format!("--max-steps must be 1..={MAX_STEPS_LIMIT}"))
    }
}

#[derive(Clone)]
enum Observed {
    Fails,
    Absent,
    Skipped(String),
}

struct Search<'a, R: StepRunner + ?Sized> {
    commits: &'a [CommitId],
    good: Option<&'a CommitId>,
    runner: &'a mut R,
    max_steps: usize,
    steps: Vec<BisectStep>,
    seen: BTreeMap<usize, Observed>,
}

impl<R: StepRunner + ?Sized> Search<'_, R> {
    fn budget_left(&self) -> bool {
        self.steps.len() < self.max_steps
    }

    async fn probe(&mut self, index: usize) -> Observed {
        let commit = &self.commits[index];
        let result = self.runner.run(commit).await;
        let observed = match &result {
            StepResult::Fails => Observed::Fails,
            StepResult::Passes => Observed::Absent,
            StepResult::Unrunnable(reason) if reason == TARGET_MISSING => Observed::Absent,
            StepResult::Unrunnable(reason) => Observed::Skipped(reason.clone()),
        };
        self.steps.push(BisectStep {
            index,
            commit: commit.clone(),
            result,
        });
        self.seen.insert(index, observed.clone());
        observed
    }

    fn boundary(&self, lo: Option<usize>) -> Option<CommitId> {
        lo.map(|i| self.commits[i].clone())
            .or_else(|| self.good.cloned())
    }

    /// The untested index nearest the midpoint of the open interval (lo, hi).
    fn next_candidate(&self, lo: isize, hi: usize) -> Option<usize> {
        let hi = hi as isize;
        let mid = (lo + hi).div_euclid(2);
        (0..hi - lo)
            .flat_map(|d| [mid + d, mid - d])
            .filter(|i| *i > lo && *i < hi)
            .map(|i| i as usize)
            .find(|i| !self.seen.contains_key(i))
    }

    fn untested_middle(&self, from: usize, to: usize) -> Option<usize> {
        let free: Vec<usize> = (from..to).filter(|i| !self.seen.contains_key(i)).collect();
        free.get(free.len() / 2).copied()
    }

    fn non_monotonic(&self) -> bool {
        let first_fail = self
            .seen
            .iter()
            .find(|(_, o)| matches!(o, Observed::Fails))
            .map(|(i, _)| *i);
        first_fail.is_some_and(|f| {
            self.seen
                .range(f..)
                .any(|(_, o)| matches!(o, Observed::Absent))
        })
    }

    async fn search(&mut self) -> BisectOutcome {
        let n = self.commits.len();
        if n == 0 {
            return BisectOutcome::EmptyRange;
        }
        let bad = n - 1;
        if !matches!(self.probe(bad).await, Observed::Fails) {
            return BisectOutcome::NotReproducibleAtBad;
        }
        let mut hi = bad;
        let mut lo: Option<usize> = None;
        let mut skips = 0usize;
        let mut last_skip = String::new();
        if self.good.is_none() {
            if n == 1 {
                return BisectOutcome::PresentSinceOldest;
            }
            if !self.budget_left() {
                return BisectOutcome::StepCapReached {
                    lo: None,
                    hi: self.commits[hi].clone(),
                };
            }
            match self.probe(0).await {
                Observed::Fails => return BisectOutcome::PresentSinceOldest,
                Observed::Absent => lo = Some(0),
                Observed::Skipped(reason) => {
                    skips = 1;
                    last_skip = reason;
                }
            }
        }
        loop {
            let lo_i = lo.map_or(-1, |l| l as isize);
            if hi as isize - lo_i <= 1 {
                return BisectOutcome::IntroducedIn {
                    commit: self.commits[hi].clone(),
                    last_passing: self.boundary(lo),
                };
            }
            if skips >= MAX_SKIPS {
                return BisectOutcome::Inconclusive {
                    lo: self.boundary(lo),
                    hi: self.commits[hi].clone(),
                    reason: format!("{skips} consecutive unrunnable commits: {last_skip}"),
                };
            }
            let Some(candidate) = self.next_candidate(lo_i, hi) else {
                return BisectOutcome::Inconclusive {
                    lo: self.boundary(lo),
                    hi: self.commits[hi].clone(),
                    reason: format!("every commit between the bounds is unrunnable: {last_skip}"),
                };
            };
            if !self.budget_left() {
                return BisectOutcome::StepCapReached {
                    lo: self.boundary(lo),
                    hi: self.commits[hi].clone(),
                };
            }
            match self.probe(candidate).await {
                Observed::Fails => {
                    hi = candidate;
                    skips = 0;
                }
                Observed::Absent => {
                    lo = Some(candidate);
                    skips = 0;
                }
                Observed::Skipped(reason) => {
                    skips += 1;
                    last_skip = reason;
                }
            }
        }
    }

    /// Spare budget only: sample one untested commit on each side of the
    /// answer. A pass after `hi` or a failure before `lo` is non-monotonic.
    async fn consistency_probes(&mut self, outcome: &BisectOutcome) {
        let BisectOutcome::IntroducedIn { commit, .. } = outcome else {
            return;
        };
        let Some(hi) = self.commits.iter().position(|c| c == commit) else {
            return;
        };
        let bad = self.commits.len() - 1;
        if self.budget_left()
            && let Some(i) = self.untested_middle(hi + 1, bad)
        {
            self.probe(i).await;
        }
        if self.budget_left()
            && hi > 0
            && let Some(i) = self.untested_middle(0, hi - 1)
        {
            self.probe(i).await;
        }
    }
}

/// Binary-search `commits` (oldest first; the last is the bad revision) for
/// the first commit where the test fails, assuming Passes…Fails. `good` is the
/// exclusive lower bound when the caller supplied one (assumed passing, not
/// re-run); without it the oldest commit is tested. `max_steps` (clamped to
/// 1..=[`MAX_STEPS_LIMIT`]) bounds every runner call, including up to two
/// consistency probes run only from spare budget after a converged answer.
pub async fn bisect<R: StepRunner + ?Sized>(
    commits: &[CommitId],
    good: Option<&CommitId>,
    runner: &mut R,
    max_steps: usize,
) -> BisectResult {
    let mut search = Search {
        commits,
        good,
        runner,
        max_steps: max_steps.clamp(1, MAX_STEPS_LIMIT),
        steps: Vec::new(),
        seen: BTreeMap::new(),
    };
    let outcome = search.search().await;
    search.consistency_probes(&outcome).await;
    BisectResult {
        non_monotonic: search.non_monotonic(),
        outcome,
        steps: search.steps,
    }
}

// ---------------------------------------------------------------------------
// Sandbox runner
// ---------------------------------------------------------------------------

/// Longest stored [`StepResult::Unrunnable`] reason.
pub const MAX_REASON_LEN: usize = 64;
/// Largest accepted `--test` file.
pub const MAX_TEST_BYTES: u64 = 1024 * 1024;
/// Hard container cap for one run: `max_steps` plus two consistency probes
/// plus one spare. [`bisect`] itself never exceeds `max_steps` runner calls,
/// and each runner call starts at most one container.
pub fn container_cap(max_steps: usize) -> usize {
    max_steps.clamp(1, MAX_STEPS_LIMIT) + 2 + 1
}

/// Lowercase ASCII `[a-z0-9_:-]`, other characters folded to `_`, at most
/// [`MAX_REASON_LEN`] bytes; never empty.
pub fn sanitize_reason(reason: &str) -> String {
    let mut out = String::new();
    for c in reason.chars() {
        let c = c.to_ascii_lowercase();
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, ':' | '-') {
            c
        } else {
            '_'
        };
        if c == '_' && (out.is_empty() || out.ends_with('_')) {
            continue;
        }
        out.push(c);
        if out.len() == MAX_REASON_LEN {
            break;
        }
    }
    let out = out.trim_end_matches('_');
    if out.is_empty() {
        "unrunnable".into()
    } else {
        out.into()
    }
}

fn unrunnable(reason: &str) -> StepResult {
    StepResult::Unrunnable(sanitize_reason(reason))
}

/// Make an exported tree readable by the sandbox user (nobody): directories
/// 0755, files 0644 or 0755. Only regular files and directories are expected.
fn open_for_sandbox(root: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let set = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        };
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            set(&dir, 0o755)?;
            for entry in std::fs::read_dir(&dir)? {
                let path = entry?.path();
                let meta = std::fs::symlink_metadata(&path)?;
                if meta.is_dir() {
                    stack.push(path);
                } else if meta.is_file() {
                    let exec = meta.permissions().mode() & 0o100 != 0;
                    set(&path, if exec { 0o755 } else { 0o644 })?;
                } else {
                    return Err(std::io::Error::other("unexpected special file in export"));
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}

/// Runs a `vettalon reproduce --emit-test` regression test at each commit:
/// exports the commit's tree into a fresh private temporary directory and runs
/// the test with the reproduce red-check runner in a [`TargetSandbox`].
pub struct SandboxStepRunner<S: TargetSandbox> {
    repo: std::path::PathBuf,
    /// The finding's repo-relative file as a '/'-separated tree path.
    target_tree_path: String,
    test_source: String,
    sandbox: S,
}

impl<S: TargetSandbox> SandboxStepRunner<S> {
    /// `target_file` is the finding's repo-relative file; when it is absent
    /// from a commit's tree the step is [`TARGET_MISSING`], and when it is a
    /// skipped symlink or submodule entry (or under one) it is
    /// [`TARGET_NOT_REGULAR`].
    pub fn new(
        repo: &Path,
        target_file: &str,
        test_source: String,
        sandbox: S,
    ) -> Result<Self, String> {
        let target_file = safe_relative(Path::new(target_file))
            .map_err(|_| "the finding's file must be a repo-relative path".to_string())?;
        let mut parts = Vec::new();
        for part in target_file.components() {
            let Some(part) = part.as_os_str().to_str() else {
                return Err("the finding's file must be a UTF-8 path".into());
            };
            parts.push(part);
        }
        let target_tree_path = parts.join("/");
        if test_source.len() as u64 > MAX_TEST_BYTES {
            return Err(format!("the test exceeds {MAX_TEST_BYTES} bytes"));
        }
        Ok(Self {
            repo: repo.to_path_buf(),
            target_tree_path,
            test_source,
            sandbox,
        })
    }

    /// Run the test against an already exported tree; `stats` is what the
    /// export wrote and skipped.
    pub(crate) async fn evaluate(&self, tree: &Path, stats: &ExtractStats) -> StepResult {
        // Presence comes from the exact tree entries that were written, not
        // from the exported directory (case-insensitive or 8.3 aliasing).
        if !stats.written_files.contains(&self.target_tree_path) {
            return StepResult::Unrunnable(if stats.skipped_covers(&self.target_tree_path) {
                // Present in the tree but not exported: not "behaviour absent".
                TARGET_NOT_REGULAR.into()
            } else if stats.skipped_paths_truncated {
                TARGET_UNVERIFIED.into()
            } else {
                TARGET_MISSING.into()
            });
        }
        let secrets = OracleSecrets::fresh();
        // The red runner holds no marker; it reads it from stdin, and only a
        // run that exits 0 with exactly one marked line counts.
        let runner = regression_test::red_runner();
        let input = runner_input(&secrets);
        let (exit, output) = match self
            .sandbox
            .run(tree, &runner, &self.test_source, &input)
            .await
        {
            Ok(run) => run,
            Err(error) => return unrunnable(&format!("sandbox:{error}")),
        };
        match regression_test::parse_red_states(exit, &output, &secrets.marker) {
            Ok((RedState::Fail, RedState::Pass)) => StepResult::Fails,
            Ok((RedState::Pass, RedState::Pass)) => StepResult::Passes,
            Ok((RedState::Error, RedState::Pass)) => unrunnable("attack_test_error"),
            Ok(_) => unrunnable("benign_not_passing"),
            Err(reason) => unrunnable(reason),
        }
    }
}

#[async_trait::async_trait]
impl<S: TargetSandbox> StepRunner for SandboxStepRunner<S> {
    async fn run(&mut self, commit: &CommitId) -> StepResult {
        // tempfile creates the directory owner-only; only `tree` is opened up.
        let Ok(scratch) = tempfile::Builder::new()
            .prefix("vettalon-bisect-step-")
            .tempdir()
        else {
            return unrunnable("export_tempdir_failed");
        };
        let tree = scratch.path().join("tree");
        if std::fs::create_dir(&tree).is_err() {
            return unrunnable("export_tempdir_failed");
        }
        let Ok(stats) = export_tree(&self.repo, commit, &tree).await else {
            return unrunnable("export_failed");
        };
        let opened = tree.clone();
        let task = tokio::task::spawn_blocking(move || open_for_sandbox(&opened));
        match task.await {
            Ok(Ok(())) => {}
            _ => return unrunnable("export_permissions_failed"),
        }
        self.evaluate(&tree, &stats).await
    }
}

/// [`SandboxStepRunner`] over the hardened Docker sandbox `reproduce` uses
/// (`--network=none`, read-only root, all capabilities dropped, nobody user,
/// memory/CPU limits, image never pulled), capped at [`container_cap`].
pub async fn docker_step_runner(
    repo: &Path,
    target_file: &str,
    test_source: String,
    image: &str,
    max_steps: usize,
) -> Result<SandboxStepRunner<impl TargetSandbox>, String> {
    let sandbox = super::target_poc::docker_target_sandbox(image, container_cap(max_steps))
        .await
        .map_err(|e| format!("sandbox unavailable: {e}"))?;
    SandboxStepRunner::new(repo, target_file, test_source, sandbox)
}

/// Machine-readable record of one bisect run, written by `vettalon bisect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BisectReceipt {
    pub version: u32,
    pub repo_commit_bad: CommitId,
    pub good: Option<CommitId>,
    pub outcome: BisectOutcome,
    pub non_monotonic: bool,
    pub steps: Vec<BisectStep>,
    pub max_steps: usize,
    /// SHA-256 (lowercase hex) of the regression test file's bytes.
    pub test_sha256: String,
}

impl BisectReceipt {
    pub fn new(
        repo_commit_bad: CommitId,
        good: Option<CommitId>,
        result: BisectResult,
        max_steps: usize,
        test_bytes: &[u8],
    ) -> Self {
        use sha2::Digest;
        Self {
            version: RECEIPT_VERSION,
            repo_commit_bad,
            good,
            outcome: result.outcome,
            non_monotonic: result.non_monotonic,
            steps: result.steps,
            max_steps,
            test_sha256: hex::encode(sha2::Sha256::digest(test_bytes)),
        }
    }
}

#[cfg(test)]
#[path = "bisect_tests.rs"]
mod tests;
