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
            if patches.iter().any(|p| p.path == path) {
                return Err("malformed_diff");
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

pub fn snapshot(repo_root: &Path) -> Result<SourceSnapshot, &'static str> {
    let root = std::fs::canonicalize(repo_root).map_err(|_| "tree_copy_failed")?;
    let dir = tempfile::Builder::new()
        .prefix("vettalon-source-")
        .tempdir()
        .map_err(|_| "tree_copy_failed")?;
    let path = dir.path().join("source");
    let mut stats = CopyStats::default();
    copy_dir(&root, &path, &mut stats)?;
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
    let root = std::fs::canonicalize(repo_root).map_err(|_| "tree_copy_failed")?;
    check_paths(&root, patches)?;
    let dir = tempfile::Builder::new()
        .prefix("vettalon-fix-")
        .tempdir()
        .map_err(|_| "tree_copy_failed")?;
    let original = dir.path().join("original");
    let fixed = dir.path().join("fixed");
    let mut stats = CopyStats::default();
    copy_dir(&root, &original, &mut stats)?;
    // Copy the copy, so both sides hold the same bytes even if the user's
    // tree changes meanwhile.
    copy_dir(&original, &fixed, &mut CopyStats::default())?;
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

fn copy_dir(src: &Path, dst: &Path, stats: &mut CopyStats) -> Result<(), &'static str> {
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
        stats.entries += 1;
        if stats.entries > 40_000 {
            return Err("tree_too_large");
        }
        let name = entry.file_name();
        let ty = entry.file_type().map_err(|_| FAIL)?;
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
            copy_dir(&from, &to, stats)?;
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
