//! O19: strict unified-diff handling for suggested-fix checks.
//!
//! A suggested fix is untrusted text. Before anything runs it is parsed with
//! a deliberately small grammar and refused, with a single `[a-z_]` reason
//! token, when it touches a path outside the scanned tree, a binary file or a
//! symlink, or uses a git feature this checker does not model (renames,
//! copies, mode changes, deletions). Application is exact: every hunk must
//! match at its stated line, with no fuzz and no offset search, so the fixed
//! copy holds exactly what the diff says.
//!
//! The user's files are only ever read: [`prepare`] copies the scanned tree
//! into a temporary directory twice (original and fixed) and applies the
//! diff to the fixed copy alone.

use std::io::Read;
use std::path::{Path, PathBuf};

use super::verification_context::SnapshotExclusions;
use vettalon_contract::safe_path::SafeRepoPath;

/// Cap on a `suggested_fix` (unified diff text), on write and on read.
pub const SUGGESTED_FIX_MAX_BYTES: usize = 64 * 1024;
/// Cap on files copied from the scanned tree into one temporary copy.
const MAX_TREE_FILES: usize = 20_000;
/// Cap on bytes copied from the scanned tree into one temporary copy.
const MAX_TREE_BYTES: u64 = 256 * 1024 * 1024;
/// Cap on a single file the diff patches.
const MAX_PATCHED_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// `deserialize_with` for `Finding::suggested_fix`: a value larger than
/// [`SUGGESTED_FIX_MAX_BYTES`] is an error, never silently truncated (a cut
/// diff would be a different fix).
pub fn deserialize_suggested_fix<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    let v: Option<String> = serde::Deserialize::deserialize(d)?;
    match v {
        Some(s) if s.len() > SUGGESTED_FIX_MAX_BYTES => Err(serde::de::Error::custom(format!(
            "suggested_fix is {} bytes, over the {SUGGESTED_FIX_MAX_BYTES}-byte cap",
            s.len()
        ))),
        other => Ok(other),
    }
}

/// One diff line. The text keeps its `\n` terminator unless a
/// `\ No newline at end of file` marker followed it, so matching is exact.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Context(String),
    Remove(String),
    Add(String),
}

impl Line {
    fn text_mut(&mut self) -> &mut String {
        match self {
            Line::Context(t) | Line::Remove(t) | Line::Add(t) => t,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hunk {
    old_start: usize,
    old_len: usize,
    lines: Vec<Line>,
}

/// The changes the diff makes to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatch {
    pub path: SafeRepoPath,
    /// `--- /dev/null`: the diff creates this file.
    pub create: bool,
    hunks: Vec<Hunk>,
}

fn strip_nl(raw: &str) -> &str {
    raw.strip_suffix('\n').unwrap_or(raw)
}

/// Parse a unified diff. `Err` is a refusal token.
pub fn parse(diff: &str) -> Result<Vec<FilePatch>, &'static str> {
    if diff.len() > SUGGESTED_FIX_MAX_BYTES {
        return Err("diff_too_large");
    }
    if diff.contains('\0') {
        return Err("binary_file");
    }
    let lines: Vec<&str> = diff.split_inclusive('\n').collect();
    let mut patches: Vec<FilePatch> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = strip_nl(lines[i]);
        if line.starts_with("old mode ") || line.starts_with("new mode ") {
            // A mode pair: either side being a symlink is a symlink change.
            let next = lines.get(i + 1).map_or("", |l| strip_nl(l));
            let symlink = [line, next]
                .iter()
                .any(|l| l.contains(" mode ") && l.trim_end().ends_with("120000"));
            return Err(if symlink { "symlink" } else { "mode_change" });
        }
        if let Some(reason) = refused_header(line) {
            return Err(reason);
        }
        if let Some(old) = line.strip_prefix("--- ") {
            let new = lines
                .get(i + 1)
                .map(|l| strip_nl(l))
                .and_then(|l| l.strip_prefix("+++ "))
                .ok_or("malformed_diff")?;
            let path_old = header_path(old, "a/")?;
            let path_new = header_path(new, "b/")?;
            let (path, create) = match (path_old, path_new) {
                (None, None) => return Err("malformed_diff"),
                (_, None) => return Err("file_deletion"),
                (None, Some(n)) => (n, true),
                (Some(o), Some(n)) if o == n => (n, false),
                (Some(_), Some(_)) => return Err("rename_or_copy"),
            };
            // Both checks fold case: on a case-insensitive file system
            // (macOS, Windows) `a.py` and `A.py` are one file, and `X.py`
            // and `x.py/y.py` collide just like `x.py` and `x.py/y.py`.
            let folded = fold_path_case(&path);
            let others: Vec<String> = patches.iter().map(|p| fold_path_case(&p.path)).collect();
            if others.contains(&folded) {
                return Err("malformed_diff");
            }
            // One path a file, the other inside it as a directory (`x.py`
            // and `x.py/y.py`): no tree holds both, so the diff cannot apply.
            // Refused here as content, never left to fail while the fixed
            // copy is written (a host-side `tree_copy_failed`).
            if others
                .iter()
                .any(|other| is_dir_prefix(other, &folded) || is_dir_prefix(&folded, other))
            {
                return Err("diff_does_not_apply");
            }
            i += 2;
            let mut hunks = Vec::new();
            while i < lines.len() && strip_nl(lines[i]).starts_with("@@ ") {
                let (hunk, next) = parse_hunk(&lines, i)?;
                hunks.push(hunk);
                i = next;
            }
            if hunks.is_empty() {
                return Err("malformed_diff");
            }
            patches.push(FilePatch {
                path,
                create,
                hunks,
            });
            continue;
        }
        if line.starts_with("@@ ") {
            // A hunk without a file header.
            return Err("malformed_diff");
        }
        // Preamble (`diff --git`, `index …`) or commentary between files.
        i += 1;
    }
    if patches.is_empty() {
        return Err("not_a_unified_diff");
    }
    Ok(patches)
}

/// The key under which two paths name one file on a case-insensitive or
/// normalizing file system (macOS, Windows): `path` NFC-normalized (so
/// `é` and `e` + U+0301 agree), every character lowercased, uppercased, then
/// lowercased again per character (so the result does not depend on
/// context), and NFC again because case mapping can leave a base letter and
/// a combining mark that now compose (`ǰ` → `J` + U+030C → `ǰ`).
///
/// The first lowercasing makes the round trip stable for capital sharp s
/// `ẞ` (U+1E9E): upper-then-lower alone would give `ẞ` → `ẞ` → `ß` but
/// `ß` → `SS` → `ss`, so `straẞe` and `straße` would get different keys;
/// lowercase first gives `ẞ` → `ß` → `SS` → `ss` for both.
///
/// Uppercasing then folds the characters that lowercasing alone keeps
/// apart but Unicode case folding (and APFS/NTFS) treat as one: final sigma
/// `ς` and `σ` (both `Σ`), long s `ſ` and `s`, micro sign `µ` and `μ`, the
/// Greek symbol variants `ϐ ϑ ϕ ϖ ϰ ϱ ϵ`, `ẛ`, U+1FBE and U+0345 (`ι`), and
/// the Cyrillic variants U+1C80–U+1C88. Full mappings also fold `ß` to
/// `ss`, which can only refuse a diff some file system would accept (a
/// false positive, never a missed collision). Still an approximation: no
/// file system's exact folding table is used.
fn fold_path_case(path: &SafeRepoPath) -> String {
    use unicode_normalization::UnicodeNormalization;
    path.as_str()
        .nfc()
        .flat_map(char::to_lowercase)
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .nfc()
        .collect()
}

/// Whether `inner` lies under `outer` taken as a directory (`outer` is a
/// whole-component prefix of `inner`).
fn is_dir_prefix(outer: &str, inner: &str) -> bool {
    inner
        .strip_prefix(outer)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Extended git headers this checker refuses.
fn refused_header(line: &str) -> Option<&'static str> {
    if line.starts_with("GIT binary patch") || line.starts_with("Binary files ") {
        return Some("binary_file");
    }
    if let Some(mode) = line.strip_prefix("new file mode ") {
        return (mode.trim() == "120000").then_some("symlink");
    }
    if line.starts_with("deleted file mode") {
        return Some("file_deletion");
    }
    const RENAME: &[&str] = &[
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
        "similarity index ",
        "dissimilarity index ",
    ];
    RENAME
        .iter()
        .any(|p| line.starts_with(p))
        .then_some("rename_or_copy")
}

/// The path of a `---`/`+++` header: `None` for `/dev/null`, else a
/// validated repo-relative path. Absolute paths, `..`, quoted names and
/// anything under `.git` are refused as outside the tree.
fn header_path(field: &str, prefix: &str) -> Result<Option<SafeRepoPath>, &'static str> {
    let field = field.split('\t').next().unwrap_or(field);
    let field = field.strip_suffix('\r').unwrap_or(field);
    if field == "/dev/null" {
        return Ok(None);
    }
    if field.starts_with('"') {
        return Err("path_outside_tree");
    }
    let rel = field.strip_prefix(prefix).unwrap_or(field);
    let safe = SafeRepoPath::parse(rel).map_err(|_| "path_outside_tree")?;
    if safe
        .as_str()
        .split('/')
        .any(|c| c.eq_ignore_ascii_case(".git"))
    {
        return Err("path_outside_tree");
    }
    Ok(Some(safe))
}

/// `@@ -a[,b] +c[,d] @@…` → `(a, b, c, d)`.
fn parse_hunk_header(line: &str) -> Option<(usize, usize, usize, usize)> {
    let rest = line.strip_prefix("@@ -")?;
    let (old, rest) = rest.split_once(" +")?;
    let (new, _) = rest.split_once(" @@")?;
    let range = |r: &str| -> Option<(usize, usize)> {
        let (start, len) = match r.split_once(',') {
            Some((s, l)) => (s, l),
            None => (r, "1"),
        };
        let digits = |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit());
        if !digits(start) || !digits(len) {
            return None;
        }
        Some((start.parse().ok()?, len.parse().ok()?))
    };
    let (a, b) = range(old)?;
    let (c, d) = range(new)?;
    Some((a, b, c, d))
}

fn parse_hunk(lines: &[&str], start: usize) -> Result<(Hunk, usize), &'static str> {
    let (old_start, old_len, _new_start, new_len) =
        parse_hunk_header(strip_nl(lines[start])).ok_or("malformed_diff")?;
    let (mut old_seen, mut new_seen) = (0usize, 0usize);
    let mut out: Vec<Line> = Vec::new();
    let mut i = start + 1;
    let ensure_nl = |t: &str| {
        let mut t = t.to_string();
        if !t.ends_with('\n') {
            t.push('\n');
        }
        t
    };
    while old_seen < old_len || new_seen < new_len {
        let raw = *lines.get(i).ok_or("malformed_diff")?;
        match raw.as_bytes().first() {
            Some(b' ') => {
                out.push(Line::Context(ensure_nl(&raw[1..])));
                old_seen += 1;
                new_seen += 1;
            }
            Some(b'\n') => {
                // Some tools drop the space of an empty context line.
                out.push(Line::Context("\n".to_string()));
                old_seen += 1;
                new_seen += 1;
            }
            Some(b'-') => {
                out.push(Line::Remove(ensure_nl(&raw[1..])));
                old_seen += 1;
            }
            Some(b'+') => {
                out.push(Line::Add(ensure_nl(&raw[1..])));
                new_seen += 1;
            }
            Some(b'\\') => no_newline(&mut out)?,
            _ => return Err("malformed_diff"),
        }
        if old_seen > old_len || new_seen > new_len {
            return Err("malformed_diff");
        }
        i += 1;
    }
    if lines.get(i).is_some_and(|l| l.starts_with('\\')) {
        no_newline(&mut out)?;
        i += 1;
    }
    Ok((
        Hunk {
            old_start,
            old_len,
            lines: out,
        },
        i,
    ))
}

/// `\ No newline at end of file`: the previous line has no terminator.
fn no_newline(out: &mut [Line]) -> Result<(), &'static str> {
    let last = out.last_mut().ok_or("malformed_diff")?;
    let t = last.text_mut();
    if t.pop() != Some('\n') {
        return Err("malformed_diff");
    }
    Ok(())
}

/// Apply one file's hunks to `original` exactly (no fuzz, no offsets).
fn apply_hunks(original: &str, hunks: &[Hunk]) -> Result<String, &'static str> {
    const NO_APPLY: &str = "diff_does_not_apply";
    let old: Vec<&str> = original.split_inclusive('\n').collect();
    let mut out = String::with_capacity(original.len());
    let mut cursor = 0usize;
    for h in hunks {
        let at = if h.old_len == 0 {
            h.old_start
        } else {
            h.old_start.checked_sub(1).ok_or(NO_APPLY)?
        };
        if at < cursor || at + h.old_len > old.len() {
            return Err(NO_APPLY);
        }
        old[cursor..at].iter().for_each(|l| out.push_str(l));
        let mut k = at;
        for line in &h.lines {
            match line {
                Line::Context(t) | Line::Remove(t) => {
                    if old.get(k) != Some(&t.as_str()) {
                        return Err(NO_APPLY);
                    }
                    if matches!(line, Line::Context(_)) {
                        out.push_str(t);
                    }
                    k += 1;
                }
                Line::Add(t) => out.push_str(t),
            }
        }
        cursor = k;
    }
    old[cursor..].iter().for_each(|l| out.push_str(l));
    Ok(out)
}

/// Check every patched path against the scanned tree without following any
/// symlink: every existing component must be a plain directory / file.
fn check_paths(repo_root: &Path, patches: &[FilePatch]) -> Result<(), &'static str> {
    for p in patches {
        let rel = p.path.as_str();
        let name = rel.rsplit('/').next().unwrap_or(rel);
        if crate::util::is_secret_file(name) {
            return Err("secret_file");
        }
        let parts: Vec<&str> = rel.split('/').collect();
        let mut cur = repo_root.to_path_buf();
        for (idx, part) in parts.iter().enumerate() {
            cur.push(part);
            let last = idx + 1 == parts.len();
            match std::fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_symlink() => return Err("symlink"),
                Ok(m) if !last => {
                    if !m.is_dir() {
                        return Err("target_missing");
                    }
                }
                Ok(m) => {
                    if p.create {
                        return Err("target_exists");
                    }
                    if !m.is_file() {
                        return Err("target_missing");
                    }
                    if m.len() > MAX_PATCHED_FILE_BYTES {
                        return Err("file_too_large");
                    }
                }
                Err(_) if p.create => break,
                Err(_) => return Err("target_missing"),
            }
        }
    }
    Ok(())
}

/// Two temporary copies of the scanned tree: `original` as scanned and
/// `fixed` with the diff applied. Removed when dropped.
pub struct TreeCopies {
    _dir: tempfile::TempDir,
    pub original: PathBuf,
    pub fixed: PathBuf,
    pub exclusions: SnapshotExclusions,
}

/// A single prepared source copy, removed on drop. Its path is only valid
/// while this owner lives; excluded source is explicitly outside its scope.
pub struct SourceSnapshot {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub exclusions: SnapshotExclusions,
}

/// Source-copy policy. Existing callers retain the Python policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SnapshotMode {
    #[default]
    Python,
    #[allow(dead_code)] // Node callers arrive in D8/D9.
    Node,
}

pub fn snapshot(repo_root: &Path) -> Result<SourceSnapshot, &'static str> {
    snapshot_with_mode(repo_root, SnapshotMode::default())
}

/// Node copies omit dependency directories at every depth (case-insensitive
/// to protect macOS/Windows mountpoints) and reserve an empty top-level mount.
/// A regular file at that mountpoint is refused as `tree_copy_failed`.
pub fn snapshot_with_mode(
    repo_root: &Path,
    mode: SnapshotMode,
) -> Result<SourceSnapshot, &'static str> {
    let root = std::fs::canonicalize(repo_root).map_err(|_| "tree_copy_failed")?;
    let dir = tempfile::Builder::new()
        .prefix("vettalon-source-")
        .tempdir()
        .map_err(|_| "tree_copy_failed")?;
    let path = dir.path().join("source");
    let mut stats = CopyStats::default();
    copy_dir(&root, &path, &mut stats, mode)?;
    dependency_mountpoint(&path, mode)?;
    Ok(SourceSnapshot {
        _dir: dir,
        path,
        exclusions: stats.exclusions,
    })
}

#[derive(Default)]
struct CopyStats {
    files: usize,
    bytes: u64,
    entries: usize,
    depth: usize,
    exclusions: SnapshotExclusions,
}

/// Validate the patched paths against `repo_root`, copy the tree twice into
/// a fresh temporary directory and apply the diff to the fixed copy. The
/// copies leave out `.git`, symlinks, special files and secret files
/// ([`crate::util::is_secret_file`]). `Err` is a refusal token.
pub fn prepare(repo_root: &Path, patches: &[FilePatch]) -> Result<TreeCopies, &'static str> {
    prepare_with_mode(repo_root, patches, SnapshotMode::default())
}

/// Prepare both sides with the same source-copy policy.
pub fn prepare_with_mode(
    repo_root: &Path,
    patches: &[FilePatch],
    mode: SnapshotMode,
) -> Result<TreeCopies, &'static str> {
    // Patches must never populate the reserved dependency mountpoint.
    if mode == SnapshotMode::Node
        && patches.iter().any(|p| {
            p.path
                .as_str()
                .split('/')
                .any(|part| part.eq_ignore_ascii_case("node_modules"))
        })
    {
        return Err("diff_changes_dependencies");
    }
    let root = std::fs::canonicalize(repo_root).map_err(|_| "tree_copy_failed")?;
    check_paths(&root, patches)?;
    let dir = tempfile::Builder::new()
        .prefix("vettalon-fix-")
        .tempdir()
        .map_err(|_| "tree_copy_failed")?;
    let original = dir.path().join("original");
    let fixed = dir.path().join("fixed");
    let mut stats = CopyStats::default();
    copy_dir(&root, &original, &mut stats, mode)?;
    dependency_mountpoint(&original, mode)?;
    // Copy the copy, so both sides hold the same bytes even if the user's
    // tree changes meanwhile.
    copy_dir(&original, &fixed, &mut CopyStats::default(), mode)?;
    dependency_mountpoint(&fixed, mode)?;
    for p in patches {
        let target = p.path.join_under(&fixed);
        let before = if p.create {
            if std::fs::symlink_metadata(&target).is_ok() {
                return Err("target_exists");
            }
            String::new()
        } else {
            let bytes = read_regular(&target)?;
            if bytes.contains(&0) {
                return Err("binary_file");
            }
            String::from_utf8(bytes).map_err(|_| "binary_file")?
        };
        let after = apply_hunks(&before, &p.hunks)?;
        if let Some(parent) = target.parent() {
            create_dirs(&fixed, parent)?;
        }
        std::fs::write(&target, after).map_err(|_| "tree_copy_failed")?;
        set_mode(&target, 0o644);
    }
    Ok(TreeCopies {
        _dir: dir,
        original,
        fixed,
        exclusions: stats.exclusions,
    })
}

/// Read a regular file without following a symlink at its last component.
fn read_regular(path: &Path) -> Result<Vec<u8>, &'static str> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "target_missing")?;
    if meta.file_type().is_symlink() {
        return Err("symlink");
    }
    if !meta.is_file() {
        return Err("target_missing");
    }
    if meta.len() > MAX_PATCHED_FILE_BYTES {
        return Err("file_too_large");
    }
    let mut buf = Vec::new();
    open_nofollow(path)
        .and_then(|mut f| f.read_to_end(&mut buf))
        .map_err(|_| "tree_copy_failed")?;
    Ok(buf)
}

fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// Create `dir` and its missing parents inside `root`, world-readable.
fn create_dirs(root: &Path, dir: &Path) -> Result<(), &'static str> {
    std::fs::create_dir_all(dir).map_err(|_| "tree_copy_failed")?;
    let mut cur = dir;
    while cur != root {
        set_mode(cur, 0o755);
        match cur.parent() {
            Some(p) => cur = p,
            None => break,
        }
    }
    Ok(())
}

fn dependency_mountpoint(root: &Path, mode: SnapshotMode) -> Result<(), &'static str> {
    if mode == SnapshotMode::Node {
        let path = root.join("node_modules");
        std::fs::create_dir(&path).map_err(|_| "tree_copy_failed")?;
        set_mode(&path, 0o755);
    }
    Ok(())
}

fn copy_dir(
    src: &Path,
    dst: &Path,
    stats: &mut CopyStats,
    mode: SnapshotMode,
) -> Result<(), &'static str> {
    const FAIL: &str = "tree_copy_failed";
    // Re-check right before listing: a directory swapped for a symlink after
    // its parent was listed is never followed. (A narrower race remains; the
    // copy only ever reaches the no-network sandbox, never a report.)
    let meta = std::fs::symlink_metadata(src).map_err(|_| FAIL)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(FAIL);
    }
    if stats.depth >= 128 {
        return Err("tree_too_deep");
    }
    stats.depth += 1;
    std::fs::create_dir(dst).map_err(|_| FAIL)?;
    // The sandbox runs as nobody: the copy must be world-readable.
    set_mode(dst, 0o755);
    for entry in std::fs::read_dir(src).map_err(|_| FAIL)? {
        let entry = entry.map_err(|_| FAIL)?;
        let name = entry.file_name();
        let ty = entry.file_type().map_err(|_| FAIL)?;
        // Excluded dependency subtrees do not consume the source entry cap.
        if mode == SnapshotMode::Node
            && ty.is_dir()
            && name.to_string_lossy().eq_ignore_ascii_case("node_modules")
        {
            stats.exclusions.node_modules += 1;
            continue;
        }
        stats.entries += 1;
        if stats.entries > 40_000 {
            return Err("tree_too_large");
        }
        let (from, to) = (entry.path(), dst.join(&name));
        if ty.is_symlink() {
            stats.exclusions.symlinks += 1;
            continue;
        }
        if ty.is_dir() {
            if name.to_string_lossy().eq_ignore_ascii_case(".git") {
                stats.exclusions.git_directories += 1;
                continue;
            }
            copy_dir(&from, &to, stats, mode)?;
        } else if ty.is_file() {
            if crate::util::is_secret_file(&name.to_string_lossy()) {
                stats.exclusions.secret_files += 1;
                continue;
            }
            let meta = entry.metadata().map_err(|_| FAIL)?;
            stats.files += 1;
            stats.bytes += meta.len();
            if stats.files > MAX_TREE_FILES || stats.bytes > MAX_TREE_BYTES {
                return Err("tree_too_large");
            }
            let input = open_nofollow(&from).map_err(|_| FAIL)?;
            let mut output = std::fs::File::create(&to).map_err(|_| FAIL)?;
            let copied = std::io::copy(&mut input.take(meta.len().saturating_add(1)), &mut output)
                .map_err(|_| FAIL)?;
            if copied != meta.len() {
                return Err("tree_changed_during_copy");
            }
            set_mode(&to, if is_executable(&meta) { 0o755 } else { 0o644 });
        } else {
            stats.exclusions.special_files += 1;
        }
    }
    stats.depth -= 1;
    Ok(())
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    false
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "import os\n\ndef run(cmd):\n    os.system('echo ' + cmd)\n";

    fn fix_diff() -> String {
        "diff --git a/app.py b/app.py\n\
         index 1111111..2222222 100644\n\
         --- a/app.py\n\
         +++ b/app.py\n\
         @@ -1,4 +1,5 @@\n \
         import os\n\
         +import shlex\n \n \
         def run(cmd):\n\
         -    os.system('echo ' + cmd)\n\
         +    os.system('echo ' + shlex.quote(cmd))\n"
            .to_string()
    }

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in files {
            let p = dir.path().join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        dir
    }

    #[test]
    fn parses_and_applies_a_git_diff_exactly() {
        let patches = parse(&fix_diff()).unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].path.as_str(), "app.py");
        let out = apply_hunks(APP, &patches[0].hunks).unwrap();
        assert_eq!(
            out,
            "import os\nimport shlex\n\ndef run(cmd):\n    os.system('echo ' + shlex.quote(cmd))\n"
        );
        // Context that does not match at the stated line is refused.
        assert_eq!(
            apply_hunks("x\n", &patches[0].hunks),
            Err("diff_does_not_apply")
        );
    }

    #[test]
    fn no_newline_marker_and_file_creation() {
        let d = "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n";
        let p = parse(d).unwrap();
        assert_eq!(apply_hunks("old", &p[0].hunks).unwrap(), "new");
        let d = "--- /dev/null\n+++ b/pkg/new.py\n@@ -0,0 +1,2 @@\n+a\n+b\n";
        let p = parse(d).unwrap();
        assert!(p[0].create);
        assert_eq!(apply_hunks("", &p[0].hunks).unwrap(), "a\nb\n");
    }

    /// A file and a path inside it as a directory (`x.py`, `x.py/y.py`) can
    /// never both exist: a content refusal at parse time, in either order,
    /// never a copy failure (an environment blocker) while the fixed copy is
    /// written. Duplicate paths stay refused too.
    #[test]
    fn refuses_a_path_nested_under_another_patched_file() {
        let create = |path: &str| format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        let modify = |path: &str| format!("--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-x\n+y\n");
        for (first, second) in [
            (create("x.py"), create("x.py/y.py")),
            (create("x.py/y.py"), create("x.py")),
            (modify("pkg/x.py"), create("pkg/x.py/deep/y.py")),
            (create("pkg/x.py/deep/y.py"), modify("pkg/x.py")),
        ] {
            let d = format!("{first}{second}");
            assert_eq!(parse(&d).map(|_| ()), Err("diff_does_not_apply"), "{d}");
        }
        // Only whole components count: siblings sharing a name prefix pass.
        for (first, second) in [
            (create("x.py"), create("x.pyc/y.py")),
            (create("x"), create("xy/z.py")),
            (create("pkg/a.py"), create("pkg/b.py")),
        ] {
            let d = format!("{first}{second}");
            assert_eq!(parse(&d).map(|p| p.len()), Ok(2), "{d}");
        }
        let dup = format!("{}{}", modify("x.py"), modify("x.py"));
        assert_eq!(parse(&dup).map(|_| ()), Err("malformed_diff"));
        // Case folds, as on macOS and Windows file systems.
        for (first, second) in [
            (create("X.py"), create("x.py/y.py")),
            (create("x.py/y.py"), create("X.PY")),
            (modify("Pkg/x.py"), create("pkg/X.py/deep/y.py")),
            (create("ÄB/x.py"), create("äb")),
        ] {
            let d = format!("{first}{second}");
            assert_eq!(parse(&d).map(|_| ()), Err("diff_does_not_apply"), "{d}");
        }
        for (first, second) in [
            (modify("a.py"), modify("A.py")),
            (create("src/App.py"), modify("SRC/app.PY")),
            (create("Äb.py"), create("äb.py")),
        ] {
            let d = format!("{first}{second}");
            assert_eq!(parse(&d).map(|_| ()), Err("malformed_diff"), "{d}");
        }
        let d = format!("{}{}", create("X.py"), create("x.pyc/y.py"));
        assert_eq!(parse(&d).map(|p| p.len()), Ok(2), "{d}");
        // Unicode normalization and final sigma fold too.
        for (first, second) in [
            (create("Café.txt"), create("Cafe\u{301}.txt")),
            (create("cafe\u{301}.txt"), modify("CAFÉ.txt")),
            (create("ΟΔΟΣ"), create("οδος")),
            (create("οδος"), create("οδοσ")),
            (create("ΟΔΟΣ.md"), create("οδοσ.md")),
        ] {
            let d = format!("{first}{second}");
            assert_eq!(parse(&d).map(|_| ()), Err("malformed_diff"), "{d}");
        }
        for (first, second) in [
            (create("Cafe\u{301}"), create("café/x.txt")),
            (create("οδος/x.txt"), create("ΟΔΟΣ")),
        ] {
            let d = format!("{first}{second}");
            assert_eq!(parse(&d).map(|_| ()), Err("diff_does_not_apply"), "{d}");
        }
        // A content refusal: no environment or harness blocker.
        assert_eq!(
            super::super::fix_check::blocker_for_reason("diff_does_not_apply"),
            super::super::fix_check::Blocker::None
        );
    }

    /// Characters that lowercasing alone keeps apart but Unicode case
    /// folding (and APFS/NTFS) treat as one letter collide too.
    #[test]
    fn path_case_folding_covers_special_case_folds() {
        let create = |path: &str| format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        let modify = |path: &str| format!("--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-x\n+y\n");
        for (first, second) in [
            // Long s, micro sign.
            (create("src/a.py"), create("\u{017F}rc/a.py")),
            (modify("src/a.py"), modify("\u{017F}rc/a.py")),
            (create("\u{00B5}/x"), create("\u{03BC}/x")),
            // Greek symbol variants: beta, theta, phi, pi, kappa, rho,
            // epsilon.
            (create("\u{03D0}.txt"), create("\u{03B2}.txt")),
            (create("\u{03D1}.txt"), create("\u{0398}.txt")),
            (create("\u{03D5}.txt"), create("\u{03C6}.txt")),
            (create("\u{03D6}.txt"), create("\u{03C0}.txt")),
            (create("\u{03F0}.txt"), create("\u{039A}.txt")),
            (create("\u{03F1}.txt"), create("\u{03C1}.txt")),
            (create("\u{03F5}.txt"), create("\u{0395}.txt")),
            // Long s with dot above, Greek prosgegrammeni and iota
            // subscript, Cyrillic rounded ve.
            (create("\u{1E9B}"), create("\u{1E61}")),
            (create("\u{1FBE}"), create("\u{03B9}")),
            (create("\u{0345}x"), create("\u{0399}x")),
            (create("\u{1C80}"), create("\u{0432}")),
            // ß folds to ss (a false positive at worst).
            (create("stra\u{00DF}e"), create("STRASSE")),
            // Capital sharp s is the same name as ß and ss.
            (create("stra\u{1E9E}e"), create("stra\u{00DF}e")),
            (create("stra\u{1E9E}e"), create("strasse")),
        ] {
            let d = format!("{first}{second}");
            assert_eq!(parse(&d).map(|_| ()), Err("malformed_diff"), "{d}");
        }
        for (first, second) in [
            (create("\u{017F}rc"), create("src/a.py")),
            (create("src/a.py"), create("\u{017F}RC")),
            (create("\u{00B5}"), create("\u{039C}/x")),
            (create("\u{1E9E}/x"), create("\u{00DF}")),
        ] {
            let d = format!("{first}{second}");
            assert_eq!(parse(&d).map(|_| ()), Err("diff_does_not_apply"), "{d}");
        }
        // Distinct letters still pass.
        let d = format!("{}{}", create("src/a.py"), create("arc/a.py"));
        assert_eq!(parse(&d).map(|p| p.len()), Ok(2), "{d}");
    }

    #[test]
    fn refuses_paths_outside_the_tree() {
        for d in [
            "--- a/../etc/passwd\n+++ b/../etc/passwd\n@@ -1 +1 @@\n-x\n+y\n",
            "--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-x\n+y\n",
            "--- a/src/../../x\n+++ b/src/../../x\n@@ -1 +1 @@\n-x\n+y\n",
            "--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-x\n+y\n",
            "--- \"a/q\\tx\"\n+++ \"b/q\\tx\"\n@@ -1 +1 @@\n-x\n+y\n",
            "--- a/~/x\n+++ b/~/x\n@@ -1 +1 @@\n-x\n+y\n",
        ] {
            assert_eq!(parse(d), Err("path_outside_tree"), "{d}");
        }
    }

    #[test]
    fn refuses_binary_symlink_and_unmodelled_git_features() {
        let cases = [
            (
                "diff --git a/x.png b/x.png\nBinary files a/x.png and b/x.png differ\n",
                "binary_file",
            ),
            (
                "diff --git a/x b/x\nGIT binary patch\nliteral 1\n",
                "binary_file",
            ),
            ("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-\0\n+y\n", "binary_file"),
            (
                "diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+/etc/passwd\n",
                "symlink",
            ),
            (
                "diff --git a/l b/l\nold mode 100644\nnew mode 120000\n",
                "symlink",
            ),
            (
                "diff --git a/x b/x\nold mode 100644\nnew mode 100755\n",
                "mode_change",
            ),
            (
                "diff --git a/x b/y\nrename from x\nrename to y\n",
                "rename_or_copy",
            ),
            ("--- a/x\n+++ b/y\n@@ -1 +1 @@\n-x\n+y\n", "rename_or_copy"),
            (
                "diff --git a/x b/x\ndeleted file mode 100644\n",
                "file_deletion",
            ),
            (
                "--- a/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n",
                "file_deletion",
            ),
            ("just prose, no diff\n", "not_a_unified_diff"),
            ("", "not_a_unified_diff"),
            (
                "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-x\n+y\n",
                "malformed_diff",
            ),
            ("@@ -1 +1 @@\n-x\n+y\n", "malformed_diff"),
        ];
        for (d, want) in cases {
            assert_eq!(parse(d).map(|_| ()), Err(want), "{d:?}");
        }
        let big = format!(
            "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-x\n+{}\n",
            "y".repeat(SUGGESTED_FIX_MAX_BYTES)
        );
        assert_eq!(parse(&big).map(|_| ()), Err("diff_too_large"));
    }

    #[test]
    fn prepare_patches_only_the_fixed_copy_and_never_the_user_tree() {
        let t = tree(&[
            ("app.py", APP),
            (".env", "TOKEN=x\n"),
            (".git/HEAD", "ref\n"),
        ]);
        let patches = parse(&fix_diff()).unwrap();
        let copies = prepare(t.path(), &patches).unwrap();
        let read = |p: &Path| std::fs::read_to_string(p).unwrap();
        assert_eq!(read(&copies.original.join("app.py")), APP);
        assert!(read(&copies.fixed.join("app.py")).contains("shlex.quote"));
        // The user's file is untouched.
        assert_eq!(read(&t.path().join("app.py")), APP);
        // Secret files and .git never enter the copies.
        assert!(!copies.original.join(".env").exists());
        assert!(!copies.original.join(".git").exists());
        let dir = copies.original.parent().unwrap().to_path_buf();
        drop(copies);
        assert!(!dir.exists(), "temporary copies are removed on drop");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_refuses_symlinks_secret_files_and_binary_targets() {
        let t = tree(&[("app.py", APP), ("bin.dat", "a\0b\n"), ("real/x.py", "x\n")]);
        std::os::unix::fs::symlink(t.path().join("app.py"), t.path().join("link.py")).unwrap();
        std::os::unix::fs::symlink(t.path().join("real"), t.path().join("dir")).unwrap();
        let one = |path: &str| format!("--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-x\n+y\n");
        let refuse = |d: &str| {
            prepare(t.path(), &parse(d).unwrap())
                .map(|_| ())
                .unwrap_err()
        };
        assert_eq!(refuse(&one("link.py")), "symlink");
        assert_eq!(refuse(&one("dir/x.py")), "symlink");
        assert_eq!(refuse(&one(".env")), "secret_file");
        assert_eq!(refuse(&one("missing.py")), "target_missing");
        assert_eq!(refuse(&one("bin.dat")), "binary_file");
        assert_eq!(refuse(&one("app.py")), "diff_does_not_apply");
        let create = "--- /dev/null\n+++ b/app.py\n@@ -0,0 +1 @@\n+y\n";
        assert_eq!(refuse(create), "target_exists");
        // The symlinked file is never copied, the real one is.
        let ok = prepare(t.path(), &parse(&one("real/x.py")).unwrap()).unwrap();
        assert!(!ok.original.join("link.py").exists());
        assert_eq!(
            std::fs::read_to_string(ok.fixed.join("real/x.py")).unwrap(),
            "y\n"
        );
    }

    #[test]
    fn node_snapshot_skips_nested_dependencies_and_reserves_mountpoint() {
        let source = tree(&[
            ("app.js", "hello\n"),
            ("node_modules/pkg/index.js", "dependency"),
            ("nested/node_modules/pkg/index.js", "nested dependency"),
        ]);
        let copy = snapshot_with_mode(source.path(), SnapshotMode::Node).unwrap();
        assert_eq!(copy.exclusions.node_modules, 2);
        assert!(copy.path.join("node_modules").is_dir());
        assert_eq!(
            std::fs::read_dir(copy.path.join("node_modules"))
                .unwrap()
                .count(),
            0
        );
        assert!(!copy.path.join("nested/node_modules").exists());
        let before = super::super::verification_context::snapshot_digest(&copy.path).unwrap();
        std::fs::write(source.path().join("node_modules/pkg/index.js"), "changed").unwrap();
        assert_eq!(
            before,
            super::super::verification_context::snapshot_digest(&copy.path).unwrap()
        );
        let again = snapshot_with_mode(source.path(), SnapshotMode::Node).unwrap();
        assert_eq!(
            before,
            super::super::verification_context::snapshot_digest(&again.path).unwrap()
        );
        let copies = prepare_with_mode(source.path(), &[], SnapshotMode::Node).unwrap();
        assert_eq!(copies.exclusions.node_modules, 2);
        for path in [&copies.original, &copies.fixed] {
            assert_eq!(
                before,
                super::super::verification_context::snapshot_digest(path).unwrap()
            );
        }
        let patches =
            parse("--- /dev/null\n+++ b/node_modules/new.js\n@@ -0,0 +1 @@\n+x\n").unwrap();
        assert_eq!(
            prepare_with_mode(source.path(), &patches, SnapshotMode::Node).err(),
            Some("diff_changes_dependencies")
        );
    }

    #[test]
    fn node_snapshot_without_dependencies_has_stable_empty_mountpoint() {
        let source = tree(&[("app.js", "hello\n")]);
        let copy = snapshot_with_mode(source.path(), SnapshotMode::Node).unwrap();
        assert_eq!(copy.exclusions.node_modules, 0);
        assert!(copy.path.join("node_modules").is_dir());
        let before = super::super::verification_context::snapshot_digest(&copy.path).unwrap();
        assert_eq!(before.entries, 2);
        assert_eq!(
            before,
            super::super::verification_context::snapshot_digest(&copy.path).unwrap()
        );
    }

    #[test]
    fn python_snapshot_keeps_legacy_bytes_and_dependency_sources() {
        let source = tree(&[("app.py", "print(1)\n")]);
        set_mode(&source.path().join("app.py"), 0o644);
        let copy = snapshot(source.path()).unwrap();
        assert_eq!(
            std::fs::read(copy.path.join("app.py")).unwrap(),
            b"print(1)\n"
        );
        assert!(!copy.path.join("node_modules").exists());
        assert_eq!(
            super::super::verification_context::snapshot_digest(&copy.path)
                .unwrap()
                .sha256,
            "9065ade483bb587acda9a2649465973ed8294b7271509113286dc2326f5ec6d3"
        );
        assert_eq!(
            serde_json::to_string(&copy.exclusions).unwrap(),
            r#"{"git_directories":0,"symlinks":0,"secret_files":0,"special_files":0}"#
        );
        std::fs::create_dir_all(source.path().join("node_modules/pkg")).unwrap();
        std::fs::write(source.path().join("node_modules/pkg/index.js"), "kept").unwrap();
        let copy = snapshot(source.path()).unwrap();
        assert_eq!(
            std::fs::read(copy.path.join("node_modules/pkg/index.js")).unwrap(),
            b"kept"
        );
        assert_eq!(copy.exclusions.node_modules, 0);
        let copies = prepare(source.path(), &[]).unwrap();
        let explicit = prepare_with_mode(source.path(), &[], SnapshotMode::Python).unwrap();
        assert_eq!(
            super::super::verification_context::snapshot_digest(&copies.fixed).unwrap(),
            super::super::verification_context::snapshot_digest(&explicit.fixed).unwrap()
        );
    }

    #[test]
    fn oversize_suggested_fix_is_refused_on_read() {
        #[derive(serde::Deserialize)]
        struct W {
            #[serde(default, deserialize_with = "deserialize_suggested_fix")]
            f: Option<String>,
        }
        let ok: W = serde_json::from_str(r#"{"f":"--- a/x"}"#).unwrap();
        assert_eq!(ok.f.as_deref(), Some("--- a/x"));
        let absent: W = serde_json::from_str("{}").unwrap();
        assert!(absent.f.is_none());
        let big = format!(r#"{{"f":"{}"}}"#, "x".repeat(SUGGESTED_FIX_MAX_BYTES + 1));
        assert!(serde_json::from_str::<W>(&big).is_err());
    }
}
