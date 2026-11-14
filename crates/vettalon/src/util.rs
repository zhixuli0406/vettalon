//! Small helpers ported from DuDuClaw (`duduclaw-core` text/match utils and
//! `duduclaw-security::audit::mask_sensitive_text`) so vettalon has no
//! dependency on the DuDuClaw workspace.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

/// vettalon's state directory: `$VETTALON_HOME`, else `~/.vettalon`
/// (`%USERPROFILE%` on Windows). Shared by the CLI and every front end so
/// they read the same roster and saved reports.
///
/// The tool was called polyaudit before its first public release: an
/// existing `$POLYAUDIT_HOME` or `~/.polyaudit` is still used when the new
/// location does not exist yet, so a renamed install keeps its roster.
pub fn vettalon_home() -> std::path::PathBuf {
    if let Ok(h) = std::env::var("VETTALON_HOME") {
        return std::path::PathBuf::from(h);
    }
    if let Ok(h) = std::env::var("POLYAUDIT_HOME") {
        return std::path::PathBuf::from(h);
    }
    let home = std::path::PathBuf::from(
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into()),
    );
    resolve_home(&home)
}

fn resolve_home(home: &Path) -> std::path::PathBuf {
    let current = home.join(".vettalon");
    let legacy = home.join(".polyaudit");
    if !current.exists() && legacy.is_dir() {
        legacy
    } else {
        current
    }
}

/// Truncate `s` to at most `max_bytes` bytes, walking back to a char
/// boundary so multi-byte UTF-8 (CJK, emoji) never panics.
pub fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Case-insensitive ASCII keyword match on word boundaries (`hi` never
/// matches inside `this`).
pub fn word_contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hay = haystack.as_bytes();
    let need = needle.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric();
    let eq_ci = |a: u8, b: u8| a.eq_ignore_ascii_case(&b);
    if need.len() > hay.len() {
        return false;
    }
    let last_start = hay.len() - need.len();
    for start in 0..=last_start {
        // Match the needle bytes case-insensitively.
        if !(0..need.len()).all(|i| eq_ci(hay[start + i], need[i])) {
            continue;
        }
        let before_ok = start == 0 || !is_word(hay[start - 1]);
        let after_idx = start + need.len();
        let after_ok = after_idx == hay.len() || !is_word(hay[after_idx]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Resolve a CLI without executing a search helper. Only absolute `PATH`
/// entries are considered, so a repository-controlled current directory or
/// relative entry can never supply `where`, `which`, or the requested tool.
pub fn which_cli(bin: &str) -> Option<String> {
    if bin.is_empty() {
        return None;
    }
    let requested = Path::new(bin);
    if requested.is_absolute() {
        return canonical_executable(requested);
    }
    if bin.contains('/') || bin.contains('\\') {
        return None;
    }
    let dirs = cli_search_dirs();
    which_cli_in_dirs(bin, &dirs)
}

fn cli_search_dirs() -> Vec<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect())
        .unwrap_or_default();
    dirs.extend([
        PathBuf::from(&home).join(".local/bin"),
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from(&home).join(".bun/bin"),
        PathBuf::from(&home).join(".volta/bin"),
        PathBuf::from(&home).join(".npm-global/bin"),
        PathBuf::from(&home).join(".cargo/bin"),
    ]);
    dirs
}

/// Build a child-process `PATH` containing only existing absolute directories
/// outside the untrusted scan root. Canonical paths also prevent a symlinked
/// PATH directory from pointing back into the repository. Absolute tool
/// directories below the caller's home remain valid when that home happens to
/// be the process current directory.
pub fn trusted_path_for_scan(repo_root: &Path) -> OsString {
    let root = std::fs::canonicalize(repo_root).ok();
    let safe = trusted_path_dirs(cli_search_dirs(), root.as_deref());
    std::env::join_paths(safe).unwrap_or_default()
}

fn trusted_path_dirs(dirs: Vec<PathBuf>, repo_root: Option<&Path>) -> Vec<PathBuf> {
    let repo_root = repo_root.and_then(|path| std::fs::canonicalize(path).ok());
    let mut safe = Vec::<PathBuf>::new();
    for dir in dirs.into_iter().filter(|dir| dir.is_absolute()) {
        let Ok(dir) = std::fs::canonicalize(dir) else {
            continue;
        };
        if !dir.is_dir()
            || repo_root.as_ref().is_some_and(|root| dir.starts_with(root))
            || safe.contains(&dir)
        {
            continue;
        }
        safe.push(dir);
    }
    safe
}

/// Resolve a scanner dependency and additionally reject any executable stored
/// inside the untrusted scan root, even when `PATH` names that directory with
/// an absolute entry.
pub fn which_cli_for_scan(bin: &str, repo_root: &Path) -> Option<String> {
    let resolved = which_cli(bin)?;
    let root = std::fs::canonicalize(repo_root).ok()?;
    (!Path::new(&resolved).starts_with(root)).then_some(resolved)
}

fn which_cli_in_dirs(bin: &str, dirs: &[PathBuf]) -> Option<String> {
    let names = cli_candidate_names(bin);
    for dir in dirs.iter().filter(|dir| dir.is_absolute()) {
        for name in &names {
            let candidate = dir.join(name);
            if !is_executable_file(&candidate) {
                continue;
            }
            if let Some(canonical) = canonical_executable(&candidate) {
                return Some(canonical);
            }
        }
    }
    None
}

fn canonical_executable(path: &Path) -> Option<String> {
    if !is_executable_file(path) {
        return None;
    }
    std::fs::canonicalize(path)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn cli_candidate_names(bin: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        if Path::new(bin).extension().is_some() {
            return vec![bin.to_string()];
        }
        let extensions =
            std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        extensions
            .split(';')
            .filter(|ext| !ext.is_empty())
            .map(|ext| format!("{bin}{ext}"))
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![bin.to_string()]
    }
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Require Git metadata to be physically contained by the selected root.
/// Linked worktrees and submodule roots intentionally fail closed to ordinary
/// directory scanning because their `.git` control file points elsewhere.
pub fn validate_local_git_metadata(repo_root: &Path) -> Result<PathBuf, String> {
    let root = std::fs::canonicalize(repo_root)
        .map_err(|e| format!("cannot canonicalize repository root: {e}"))?;
    let dot_git = repo_root.join(".git");
    let metadata = std::fs::symlink_metadata(&dot_git)
        .map_err(|e| format!("no self-contained .git directory: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(".git is not a self-contained directory".to_string());
    }
    let git_dir = std::fs::canonicalize(&dot_git)
        .map_err(|e| format!("cannot canonicalize .git directory: {e}"))?;
    if !git_dir.starts_with(&root) {
        return Err(".git resolves outside the repository".to_string());
    }

    for redirect in [
        git_dir.join("commondir"),
        git_dir.join("objects/info/alternates"),
        git_dir.join("objects/info/http-alternates"),
    ] {
        if redirect.exists() {
            return Err(format!(
                "Git metadata redirection is not allowed: {}",
                redirect
                    .strip_prefix(&git_dir)
                    .unwrap_or(&redirect)
                    .display()
            ));
        }
    }

    validate_git_tree_entries(&git_dir)?;

    // Only a regular file is read: a FIFO (possible in a directory unpacked
    // from an archive) would block the read, and so the scan, forever. The
    // tree walk above already refuses one; this re-check covers a swap.
    const MAX_GIT_CONFIG_BYTES: u64 = 1024 * 1024;
    for config in [git_dir.join("config"), git_dir.join("config.worktree")] {
        let name = config.strip_prefix(&git_dir).unwrap_or(&config);
        match read_regular_file(&config, MAX_GIT_CONFIG_BYTES) {
            Ok(_) => {}
            Err(RegularFileError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(RegularFileError::NotRegular) => {
                return Err(format!("{name:?} is not a regular file"));
            }
            Err(RegularFileError::TooLarge) => {
                return Err(format!("{} exceeds the validation limit", name.display()));
            }
            Err(RegularFileError::Io(e)) => {
                return Err(format!("cannot read {}: {e}", config.display()));
            }
        }
    }
    Ok(git_dir)
}

/// Working-tree files Git opens without checking their type.
#[cfg(unix)]
const GIT_WORKTREE_INPUT_FILES: [&str; 3] = [".gitignore", ".gitattributes", ".gitmodules"];

/// Refuse a repository whose working-tree Git input files would make a
/// read-only Git command block. Git opens in-tree `.gitignore` /
/// `.gitattributes` (and, for `git diff` with a gitlink, the root
/// `.gitmodules`) without checking their type, so a FIFO there (possible in
/// a directory unpacked from an archive) stalls every
/// `git status`/`diff`/`log`/`ls-files` until the command timeout. A FIFO or
/// device inside `.git` itself is refused by [`validate_local_git_metadata`].
///
/// Only `lstat` is used: none of these files is opened, and a symlink's
/// target is never inspected (a `stat` of an attacker-chosen target could
/// reach an automounted network path). Git >= 2.32 does not follow symlinked
/// `.gitignore` / `.gitattributes`; any other read is still bounded by the
/// per-command Git timeout. A FIFO or device is refused; regular files,
/// directories, sockets, symlinks and missing paths are accepted. The
/// root-level files are checked first, then the working tree is walked: the
/// walk skips entries named exactly `.git`, never follows directory symlinks
/// and is bounded; when a bound is hit, checking stops without refusing.
/// Call it after [`validate_local_git_metadata`] succeeds. On non-Unix
/// platforms it does nothing.
pub fn validate_git_input_files(repo_root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        // Checked explicitly so the walk's bounds can never skip them.
        for name in GIT_WORKTREE_INPUT_FILES {
            if let Ok(metadata) = std::fs::symlink_metadata(repo_root.join(name))
                && is_fifo_or_device(&metadata.file_type())
            {
                return Err(format!("{name:?} is not a regular file"));
            }
        }
        validate_in_tree_git_input_files(repo_root)?;
    }
    #[cfg(not(unix))]
    let _ = repo_root;
    Ok(())
}

/// Whether opening a file of this type can block (a FIFO) or reaches a
/// device. Sockets are not included: opening one fails with `ENXIO` instead
/// of blocking, and macOS Git's builtin fsmonitor keeps
/// `.git/fsmonitor--daemon.ipc`.
#[cfg(unix)]
fn is_fifo_or_device(file_type: &std::fs::FileType) -> bool {
    use std::os::unix::fs::FileTypeExt;
    file_type.is_fifo() || file_type.is_block_device() || file_type.is_char_device()
}

#[cfg(not(unix))]
fn is_fifo_or_device(_file_type: &std::fs::FileType) -> bool {
    false
}

/// Walk the working tree for `.gitignore` / `.gitattributes` /
/// `.gitmodules` that are a FIFO or device. Names are matched
/// ASCII-case-insensitively (Git opens them so on case-insensitive file
/// systems; elsewhere this only over-refuses), but only an entry named
/// exactly `.git` is skipped, since on a case-sensitive file system Git
/// treats `.GIT` as an ordinary directory and descends into it.
#[cfg(unix)]
fn validate_in_tree_git_input_files(repo_root: &Path) -> Result<(), String> {
    // When a bound is hit, the walk stops without refusing: the root-level
    // files were already checked, and any remaining FIFO only stalls a Git
    // command until its per-command timeout. MAX_DIRS bounds the memory of
    // the pending-directory stack.
    const MAX_ENTRIES: usize = 200_000;
    const MAX_DIRS: usize = 50_000;
    const MAX_DEPTH: usize = 256;
    let mut stack = vec![(repo_root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    let mut dirs = 1usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            visited += 1;
            if visited > MAX_ENTRIES {
                return Ok(());
            }
            let name = entry.file_name();
            if name.as_os_str() == std::ffi::OsStr::new(".git") {
                continue;
            }
            // `DirEntry::file_type` does not follow symlinks.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if depth < MAX_DEPTH && dirs < MAX_DIRS {
                    dirs += 1;
                    stack.push((entry.path(), depth + 1));
                }
                continue;
            }
            if !GIT_WORKTREE_INPUT_FILES
                .iter()
                .any(|input| name.eq_ignore_ascii_case(input))
            {
                continue;
            }
            // A symlink is accepted without inspecting its target.
            if is_fifo_or_device(&file_type) {
                let path = entry.path();
                let rel = path.strip_prefix(repo_root).unwrap_or(&path);
                return Err(format!("{rel:?} is not a regular file"));
            }
        }
    }
    Ok(())
}

/// Why [`read_regular_file`] refused a path.
#[derive(Debug)]
pub enum RegularFileError {
    /// A FIFO, socket, device, directory or symlink.
    NotRegular,
    /// Larger than the cap.
    TooLarge,
    /// Could not be inspected, opened or read (`NotFound` when missing).
    Io(std::io::Error),
}

/// Read at most `cap` bytes of `path`, only when it is a regular file. The
/// type is checked with `symlink_metadata` before opening (a symlink, FIFO,
/// socket, device or directory is refused) and again on the opened file, so
/// a swap in between is caught. On Unix the open uses `O_NOFOLLOW |
/// O_NONBLOCK`, so it neither follows a symlink nor blocks on a FIFO.
pub fn read_regular_file(path: &Path, cap: u64) -> Result<Vec<u8>, RegularFileError> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path).map_err(RegularFileError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(RegularFileError::NotRegular);
    }
    if metadata.len() > cap {
        return Err(RegularFileError::TooLarge);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(RegularFileError::Io)?;
    if !file.metadata().map_err(RegularFileError::Io)?.is_file() {
        return Err(RegularFileError::NotRegular);
    }
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(RegularFileError::Io)?;
    if bytes.len() as u64 > cap {
        return Err(RegularFileError::TooLarge);
    }
    Ok(bytes)
}

/// `lstat` every entry under `git_dir` and refuse symlinks, FIFOs and
/// devices. Git opens files there (HEAD, index, refs, packed-refs, shallow,
/// info/*, objects, packs, commit-graph, ...) without checking their type,
/// so a FIFO anywhere in `.git` (possible in a directory unpacked from an
/// archive) would stall every Git command, even `git config --file`.
/// Sockets are allowed (see [`is_fifo_or_device`]).
fn validate_git_tree_entries(git_dir: &Path) -> Result<(), String> {
    const MAX_GIT_METADATA_ENTRIES: usize = 250_000;
    const MAX_GIT_METADATA_DEPTH: usize = 64;
    let mut stack = vec![(git_dir.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_GIT_METADATA_DEPTH {
            return Err("Git metadata exceeds the validation depth limit".to_string());
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && depth > 0 => continue,
            Err(error) => {
                return Err(format!(
                    "cannot inspect Git metadata {}: {error}",
                    dir.display()
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot inspect Git metadata entry: {e}"))?;
            visited += 1;
            if visited > MAX_GIT_METADATA_ENTRIES {
                return Err("Git metadata exceeds the validation entry limit".to_string());
            }
            let path = entry.path();
            let Some(metadata) = inspect_entry(&path)? else {
                continue;
            };
            let rel = path.strip_prefix(git_dir).unwrap_or(&path);
            if metadata.file_type().is_symlink() {
                return Err(format!("Git metadata symlink is not allowed: {rel:?}"));
            }
            if is_fifo_or_device(&metadata.file_type()) {
                return Err(format!("{rel:?} is not a regular file"));
            }
            if metadata.is_dir() {
                stack.push((path, depth + 1));
            }
        }
    }
    Ok(())
}

fn inspect_entry(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot inspect Git metadata {}: {error}",
            path.display()
        )),
    }
}

/// Read `r` to EOF, keeping at most `cap` bytes and discarding the rest, so
/// a child that prints without end neither fills our memory nor blocks on a
/// full pipe. Returns `(kept, truncated)`.
pub async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    mut r: R,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    use tokio::io::AsyncReadExt;
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok((kept, truncated));
        }
        let room = cap.saturating_sub(kept.len());
        if n > room {
            truncated = true;
        }
        kept.extend_from_slice(&buf[..n.min(room)]);
    }
}

/// Resolve a repo-relative `path` to a regular file that really lives under
/// `repo_root`: rejects unsafe paths, and resolves symlinks (in the file or
/// any parent directory) before checking the result is still inside the
/// canonical repo root. Every read of a model-supplied path goes through
/// this, so a planted `docs/x -> ~/.ssh/id_ed25519` is never read.
pub fn resolve_in_repo(repo_root: &Path, path: &str) -> Result<std::path::PathBuf, String> {
    let safe = vettalon_contract::safe_path::SafeRepoPath::parse(path)
        .map_err(|e| format!("unsafe path {path:?}: {e}"))?;
    let root = std::fs::canonicalize(repo_root).map_err(|e| format!("repo root: {e}"))?;
    let real = std::fs::canonicalize(safe.join_under(repo_root))
        .map_err(|e| format!("cannot resolve {path:?}: {e}"))?;
    if !real.starts_with(&root) {
        return Err(format!("{path:?} resolves outside the repository"));
    }
    if !real.is_file() {
        return Err(format!("{path:?} is not a regular file"));
    }
    Ok(real)
}

/// Read a repo file through [`resolve_in_repo`]. No secret-file check: for
/// text that goes into a model prompt, or a path a model named, resolve with
/// [`resolve_for_model`] instead.
pub fn read_repo_file(repo_root: &Path, path: &str) -> Result<String, String> {
    let real = resolve_in_repo(repo_root, path)?;
    std::fs::read_to_string(real).map_err(|e| format!("could not read {path:?}: {e}"))
}

/// Files whose job is to hold secrets: dotenv files, private keys and
/// certificates, credential and state files of common tools. Their text must
/// never reach a model (a cloud one would take it off the machine); gitleaks
/// still scans them locally. `name` is a basename. The list covers common
/// conventions, it is not a guarantee: a secret hard-coded in source code is
/// sent with that source.
pub fn is_secret_file(name: &str) -> bool {
    const SECRET_NAMES: &[&str] = &[
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        ".htpasswd",
        ".dockercfg",
        "credentials",
        "credentials.json",
        "secrets.yaml",
        "secrets.yml",
        "terraform.tfstate",
        "terraform.tfstate.backup",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_ecdsa_sk",
        "id_ed25519_sk",
    ];
    const SECRET_EXT: &[&str] = &[
        "pem", "key", "p12", "pfx", "jks", "keystore", "p8", "ppk", "tfvars", "tfstate",
    ];
    let lower = name.to_ascii_lowercase();
    if lower == ".env"
        || lower.starts_with(".env.")
        || SECRET_NAMES.contains(&lower.as_str())
        || (lower.starts_with("service-account") && lower.ends_with(".json"))
    {
        return true;
    }
    lower
        .rsplit_once('.')
        .is_some_and(|(stem, ext)| !stem.is_empty() && SECRET_EXT.contains(&ext))
}

/// Why a resolved repo file must not be shown to a model, if it must not:
/// either the name the model gave or the real file it resolves to (a symlink
/// such as `app.conf -> .env`) is a secret file.
pub fn secret_file_reason(path: &str, real: &Path) -> Option<String> {
    let given = path.rsplit('/').next().unwrap_or(path);
    let target = real.file_name().map(|n| n.to_string_lossy().into_owned());
    (is_secret_file(given) || target.as_deref().is_some_and(is_secret_file))
        .then(|| format!("{path:?} holds secrets and is never sent to a model"))
}

/// [`resolve_in_repo`] for a path whose text is about to go into a model
/// prompt: also refuses secret files ([`secret_file_reason`]).
pub fn resolve_for_model(repo_root: &Path, path: &str) -> Result<std::path::PathBuf, String> {
    let real = resolve_in_repo(repo_root, path)?;
    match secret_file_reason(path, &real) {
        Some(reason) => Err(reason),
        None => Ok(real),
    }
}

/// Write `contents` to a file created owner-only (0600) from the start, so
/// a report holding code excerpts is never briefly world-readable.
pub fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents)?;
    // An existing file keeps its old mode on open; tighten it.
    set_owner_only(path)
}

/// Owner read/write only (0o600). No-op on non-Unix.
pub fn set_owner_only(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Key names whose values are treated as secrets.
const SENSITIVE_KEYS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "client_secret",
    "corpsecret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "cookie",
    "session_key",
    "private_key",
    "signing_key",
    "webhook_secret",
    "secret_access_key",
    "access_key",
    "secret_key",
];

/// Value prefixes that mark a string as a credential regardless of its key
/// (well-known secret formats). Anchored `starts_with`, never substring.
const SENSITIVE_VALUE_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "xai-",
    "AIza",
    "ASIA",
    "ghs_",
    "ghu_",
    "ghr_",
    "hf_",
    "gsk_",
    "eyJ",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "ghp_",
    "gho_",
    "github_pat_",
    "AKIA",
    "Bearer ",
    "Basic ",
    "Token ",
    "glpat-",
];

/// Regex alternation of [`SENSITIVE_KEYS`], tolerating `-`/`_` interchange.
fn sensitive_keys_pattern() -> String {
    SENSITIVE_KEYS
        .iter()
        .map(|k| regex::escape(k).replace('_', "[-_]"))
        .collect::<Vec<_>>()
        .join("|")
}

static SENSITIVE_TEXT_JSON_KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    let keys = sensitive_keys_pattern();
    Regex::new(&format!(
        r#"(?i)"([A-Za-z0-9_-]*?(?:{keys}))"\s*:\s*"((?:[^"\\]|\\.)*)""#
    ))
    .expect("static SENSITIVE_TEXT_JSON_KV_RE must compile")
});

/// Plain `key: value` lines; consumes the rest of the line (over-masking is
/// the accepted trade-off). Left boundary is not `\b` so CJK↔ASCII seams match.
static SENSITIVE_TEXT_PLAIN_KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    let keys = sensitive_keys_pattern();
    Regex::new(&format!(
        r#"(?i)(^|[^A-Za-z0-9_])([A-Za-z0-9_]*?(?:{keys}))\b\s*[:=]\s*([^\n]+)"#
    ))
    .expect("static SENSITIVE_TEXT_PLAIN_KV_RE must compile")
});

static SENSITIVE_TEXT_VALUE_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    let alts: Vec<String> = SENSITIVE_VALUE_PREFIXES
        .iter()
        .map(|p| regex::escape(p))
        .collect();
    // Left boundary so `sk-` never fires inside a word like `desk-lamp`.
    Regex::new(&format!(
        r#"(^|[^A-Za-z0-9_-])(?:{})[^\s"')\]}}]*"#,
        alts.join("|")
    ))
    .expect("static SENSITIVE_TEXT_VALUE_TOKEN_RE must compile")
});

/// A PEM private key block (multi-line).
static SENSITIVE_TEXT_PEM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .expect("static SENSITIVE_TEXT_PEM_RE must compile")
});

static SENSITIVE_TEXT_CONN_STRING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s]+(@)"#)
        .expect("static SENSITIVE_TEXT_CONN_STRING_RE must compile")
});

static SENSITIVE_TEXT_TELEGRAM_BOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(/bot\d+:)[A-Za-z0-9_-]+"#)
        .expect("static SENSITIVE_TEXT_TELEGRAM_BOT_RE must compile")
});

static SENSITIVE_TEXT_SLACK_WEBHOOK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(hooks\.slack\.com/services/)[A-Za-z0-9/]+"#)
        .expect("static SENSITIVE_TEXT_SLACK_WEBHOOK_RE must compile")
});

/// Best-effort masking of secret-shaped substrings in free text. Six passes,
/// shape-based first, then `key: value`. Over-masking is acceptable,
/// under-masking is not.
pub fn mask_sensitive_text(text: &str) -> String {
    let masked = SENSITIVE_TEXT_JSON_KV_RE.replace_all(text, |caps: &regex::Captures| {
        format!("\"{}\":\"***\"", &caps[1])
    });
    let masked = SENSITIVE_TEXT_PEM_RE.replace_all(
        &masked,
        "-----BEGIN PRIVATE KEY----- *** -----END PRIVATE KEY-----",
    ); // gitleaks:allow (fake test value)
    let masked = SENSITIVE_TEXT_VALUE_TOKEN_RE.replace_all(&masked, "${1}***");
    let masked = SENSITIVE_TEXT_CONN_STRING_RE.replace_all(&masked, "${1}***${2}");
    let masked = SENSITIVE_TEXT_TELEGRAM_BOT_RE.replace_all(&masked, "${1}***");
    let masked = SENSITIVE_TEXT_SLACK_WEBHOOK_RE.replace_all(&masked, "${1}***");
    let masked = SENSITIVE_TEXT_PLAIN_KV_RE.replace_all(&masked, |caps: &regex::Captures| {
        format!("{}{}: ***", &caps[1], &caps[2])
    });
    masked.into_owned()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn inspect_entry_skips_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            super::inspect_entry(&dir.path().join("gone"))
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn git_metadata_walk_rejects_an_existing_symlink() {
        let git_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), git_dir.path().join("objects-link")).unwrap();
        assert!(
            super::validate_git_tree_entries(git_dir.path())
                .unwrap_err()
                .contains("symlink")
        );
    }

    #[test]
    fn git_metadata_walk_errors_when_root_is_missing() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("missing-git-dir");
        let error = super::validate_git_tree_entries(&missing).unwrap_err();
        assert!(error.contains("cannot inspect Git metadata"));
        assert!(Path::new(&missing).is_absolute() || error.contains("missing-git-dir"));
    }

    #[test]
    fn secret_files_cover_cloud_and_infra_credentials() {
        for s in [
            ".env",
            ".env.local",
            "terraform.tfvars",
            "prod.auto.tfvars",
            "terraform.tfstate",
            "terraform.tfstate.backup",
            "AuthKey_ABC.p8",
            "deploy.ppk",
            "credentials.json",
            "service-account-prod.json",
            ".htpasswd",
            ".dockercfg",
            "secrets.yaml",
            "secrets.yml",
            "credentials",
            "id_ed25519_sk",
            "server.pem",
            ".npmrc",
        ] {
            assert!(super::is_secret_file(s), "{s}");
        }
        for ok in [
            "main.tf",
            "variables.tf",
            "package.json",
            "secrets.py",
            "credentials.rs",
            "id.rs",
            "key.go",
        ] {
            assert!(!super::is_secret_file(ok), "{ok}");
        }
    }

    use super::*;

    #[test]
    fn home_prefers_new_dir_and_falls_back_to_legacy() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(resolve_home(t.path()), t.path().join(".vettalon"));
        std::fs::create_dir(t.path().join(".polyaudit")).unwrap();
        assert_eq!(resolve_home(t.path()), t.path().join(".polyaudit"));
        std::fs::create_dir(t.path().join(".vettalon")).unwrap();
        assert_eq!(resolve_home(t.path()), t.path().join(".vettalon"));
    }

    #[test]
    fn truncate_bytes_never_splits_a_char() {
        assert_eq!(truncate_bytes("hello", 10), "hello");
        assert_eq!(truncate_bytes("中文字", 4), "中");
    }

    /// Security review M1 samples: env-style names, common prefixes, PEM.
    #[test]
    fn mask_text_catches_env_style_names_prefixes_and_pem() {
        for sample in [
            "OPENAI_API_KEY=sk-abcdef123456", // gitleaks:allow (fake test value)
            "DB_PASSWORD=hunter2hunter2",
            "GITHUB_TOKEN=ghs_abcdefghijklmnop",
            "aws_secret_access_key = wJalrXUtnFEMIabcdef",
            "XAI_API_KEY: xai-abcdef123456", // gitleaks:allow (fake test value)
            "key AIzaSyD-abcdefghijklmnop here",
            "creds ASIAABCDEFGHIJKLMNOP x", // gitleaks:allow (fake test value)
            "stripe sk_live_abcdef123456",  // gitleaks:allow (fake test value)
            "openrouter sk-or-v1-abcdef123456",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
            r#"{"OPENAI_API_KEY":"sk-zzz999"}"#,
        ] {
            let m = mask_sensitive_text(sample);
            for secret in [
                "sk-abcdef123456",
                "hunter2hunter2",
                "ghs_abcdefghijklmnop",
                "wJalrXUtnFEMIabcdef",
                "xai-abcdef123456",
                "AIzaSyD",
                "ASIAABCDEFGHIJKLMNOP", // gitleaks:allow (fake test value)
                "sk_live_abcdef",
                "sk-or-v1",
                "eyJhbGci",
                "sk-zzz999",
            ] {
                // gitleaks:allow (fake test value)
                assert!(!m.contains(secret), "{sample:?} → {m:?}");
            }
        }
        let pem = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nxyz\n-----END RSA PRIVATE KEY-----\nb";
        let m = mask_sensitive_text(pem);
        assert!(!m.contains("MIIEowIBAAKCAQEA"), "{m}");
        assert!(m.starts_with("a\n") && m.ends_with("\nb"));
    }

    #[test]
    fn mask_text_prefixes_need_a_word_boundary() {
        let t = "put the desk-lamp next to the task-list";
        assert_eq!(mask_sensitive_text(t), t);
        assert_eq!(mask_sensitive_text("token_count: 5"), "token_count: 5");
    }

    #[tokio::test]
    async fn read_capped_keeps_cap_and_drains_the_rest() {
        let data = vec![b'x'; 50_000];
        let (kept, truncated) = read_capped(&data[..], 1000).await.unwrap();
        assert_eq!(kept.len(), 1000);
        assert!(truncated);
        let (kept, truncated) = read_capped(&b"short"[..], 1000).await.unwrap();
        assert_eq!(kept, b"short");
        assert!(!truncated);
    }

    #[cfg(unix)]
    #[test]
    fn repo_reads_refuse_symlinks_that_escape() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "KEY").unwrap();
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("docs")).unwrap();
        std::fs::write(repo.path().join("docs/ok.txt"), "fine").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            repo.path().join("docs/notes.txt"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.path().join("linkdir")).unwrap();
        assert_eq!(read_repo_file(repo.path(), "docs/ok.txt").unwrap(), "fine");
        assert!(
            read_repo_file(repo.path(), "docs/notes.txt")
                .unwrap_err()
                .contains("outside")
        );
        assert!(
            read_repo_file(repo.path(), "linkdir/secret")
                .unwrap_err()
                .contains("outside")
        );
        assert!(read_repo_file(repo.path(), "../x").is_err());
        assert!(read_repo_file(repo.path(), "docs").is_err());
    }

    #[test]
    fn word_contains_ci_is_word_bounded() {
        assert!(word_contains_ci("Fix XSS in login", "xss"));
        assert!(!word_contains_ci("this", "hi"));
    }

    #[cfg(unix)]
    #[test]
    fn cli_resolution_uses_absolute_executable_paths_and_skips_relative_dirs() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let trusted = root.path().join("trusted");
        let relative = std::path::PathBuf::from("repo-controlled-bin");
        std::fs::create_dir(&trusted).unwrap();
        let tool = trusted.join("fixture-tool");
        std::fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

        let resolved = which_cli_in_dirs("fixture-tool", &[relative, trusted]).unwrap();
        assert!(std::path::Path::new(&resolved).is_absolute());
        assert_eq!(
            std::fs::canonicalize(resolved).unwrap(),
            tool.canonicalize().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn cli_resolution_rejects_non_executable_files() {
        let root = tempfile::tempdir().unwrap();
        let tool = root.path().join("fixture-tool");
        std::fs::write(&tool, "not executable").unwrap();
        assert!(which_cli_in_dirs("fixture-tool", &[root.path().to_path_buf()]).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cli_resolution_accepts_a_pinned_absolute_executable() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let tool = root.path().join("fixture-tool");
        std::fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            which_cli(tool.to_str().unwrap()).unwrap(),
            tool.canonicalize().unwrap().to_string_lossy()
        );
    }

    #[cfg(unix)]
    #[test]
    fn scan_tool_resolution_rejects_executables_inside_the_untrusted_root() {
        use std::os::unix::fs::PermissionsExt;
        let repo = tempfile::tempdir().unwrap();
        let tool = repo.path().join("git");
        std::fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(which_cli_for_scan(tool.to_str().unwrap(), repo.path()).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_scan_tool_resolution_rejects_executables_inside_the_untrusted_root() {
        let repo = tempfile::tempdir().unwrap();
        let tool = repo.path().join("git.exe");
        std::fs::write(&tool, b"not executed").unwrap();
        assert!(which_cli_for_scan(tool.to_str().unwrap(), repo.path()).is_none());
    }

    #[test]
    fn scanner_child_path_excludes_relative_and_scan_root_directories_only() {
        let repo = tempfile::tempdir().unwrap();
        let trusted = tempfile::tempdir().unwrap();
        let repo_bin = repo.path().join("bin");
        let trusted_bin = trusted.path().join("bin");
        std::fs::create_dir(&repo_bin).unwrap();
        std::fs::create_dir(&trusted_bin).unwrap();
        let dirs = vec![
            PathBuf::from("."),
            repo_bin,
            trusted_bin.clone(),
            trusted_bin.clone(),
        ];
        assert_eq!(
            trusted_path_dirs(dirs, Some(repo.path())),
            vec![trusted_bin.canonicalize().unwrap()]
        );
    }

    #[test]
    fn git_metadata_must_be_an_in_root_directory_without_redirections() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join(".git")).unwrap();
        std::fs::create_dir_all(repo.path().join(".git/objects/info")).unwrap();
        assert!(validate_local_git_metadata(repo.path()).is_ok());

        std::fs::write(repo.path().join(".git/commondir"), "../outside\n").unwrap();
        assert!(
            validate_local_git_metadata(repo.path())
                .unwrap_err()
                .contains("commondir")
        );
        std::fs::remove_file(repo.path().join(".git/commondir")).unwrap();

        std::fs::write(
            repo.path().join(".git/objects/info/alternates"),
            "/outside/objects\n",
        )
        .unwrap();
        assert!(
            validate_local_git_metadata(repo.path())
                .unwrap_err()
                .contains("alternates")
        );
    }

    #[cfg(unix)]
    #[test]
    fn git_metadata_refuses_git_files_and_symlinked_object_stores() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join(".git"), "gitdir: /outside\n").unwrap();
        assert!(validate_local_git_metadata(repo.path()).is_err());

        std::fs::remove_file(repo.path().join(".git")).unwrap();
        std::fs::create_dir(repo.path().join(".git")).unwrap();
        std::fs::create_dir(repo.path().join(".git/objects")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.path().join(".git/objects/ab")).unwrap();
        assert!(
            validate_local_git_metadata(repo.path())
                .unwrap_err()
                .contains("symlink")
        );
    }

    /// A FIFO as `.git/config` or `.git/config.worktree` (possible in a
    /// directory unpacked from an archive) is refused quickly instead of
    /// blocking the read forever. Run on a thread so a regression fails the
    /// test instead of hanging it.
    #[cfg(unix)]
    #[test]
    fn git_metadata_refuses_a_fifo_config_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        for name in ["config", "config.worktree"] {
            let repo = tempfile::tempdir().unwrap();
            std::fs::create_dir(repo.path().join(".git")).unwrap();
            let fifo = repo.path().join(".git").join(name);
            let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
            // SAFETY: a valid NUL-terminated path; mkfifo only creates a node.
            assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
            let root = repo.path().to_path_buf();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(validate_local_git_metadata(&root));
            });
            let error = rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap_or_else(|_| panic!("validation blocked on a FIFO {name}"))
                .unwrap_err();
            assert!(
                error.contains(&format!("{name:?} is not a regular file")),
                "{error}"
            );
        }
    }

    /// Run [`validate_local_git_metadata`] on a thread so a regression that
    /// opens a FIFO fails the test instead of hanging it.
    #[cfg(unix)]
    fn validate_local_git_metadata_bounded(root: &std::path::Path) -> Result<PathBuf, String> {
        let root = root.to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(validate_local_git_metadata(&root));
        });
        rx.recv_timeout(std::time::Duration::from_secs(3))
            .expect("validate_local_git_metadata blocked")
    }

    /// A FIFO anywhere in `.git` (HEAD, index, refs, info files, object
    /// metadata) would block every Git command, so it is refused by the
    /// metadata walk without being opened.
    #[cfg(unix)]
    #[test]
    fn git_metadata_refuses_fifos_anywhere_in_git_dir_without_blocking() {
        for rel in [
            "HEAD",
            "index",
            "packed-refs",
            "refs/heads/main",
            "info/attributes",
            "info/exclude",
            "info/sparse-checkout",
            "objects/info/commit-graph",
        ] {
            let repo = git_input_fixture();
            let fifo = repo.path().join(".git").join(rel);
            std::fs::create_dir_all(fifo.parent().unwrap()).unwrap();
            make_fifo(&fifo);
            let error = validate_local_git_metadata_bounded(repo.path()).unwrap_err();
            assert!(
                error.contains(&format!("{rel:?} is not a regular file")),
                "{rel}: {error}"
            );
        }
    }

    /// A symlinked `.git/info/exclude` is refused like any symlink in `.git`,
    /// so its target (here a FIFO) is never opened.
    #[cfg(unix)]
    #[test]
    fn git_metadata_refuses_symlinked_info_file_to_fifo() {
        let repo = git_input_fixture();
        let outside = tempfile::tempdir().unwrap();
        let fifo = outside.path().join("pipe");
        make_fifo(&fifo);
        std::os::unix::fs::symlink(&fifo, repo.path().join(".git/info/exclude")).unwrap();
        let error = validate_local_git_metadata_bounded(repo.path()).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(error.contains("info/exclude"), "{error}");
    }

    /// macOS Git's builtin fsmonitor keeps a socket in `.git`; opening a
    /// socket fails instead of blocking, so it is accepted.
    #[cfg(unix)]
    #[test]
    fn git_metadata_accepts_a_socket_in_git_dir() {
        let repo = git_input_fixture();
        // A short name keeps the path under the `sun_path` limit.
        let _listener =
            std::os::unix::net::UnixListener::bind(repo.path().join(".git/ipc")).unwrap();
        assert!(validate_local_git_metadata_bounded(repo.path()).is_ok());
    }

    #[cfg(unix)]
    fn make_fifo(path: &std::path::Path) {
        use std::os::unix::ffi::OsStrExt;
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
    }

    /// Run [`validate_git_input_files`] on a thread so a regression that
    /// opens a FIFO fails the test instead of hanging it.
    #[cfg(unix)]
    fn validate_git_input_files_bounded(root: &std::path::Path) -> Result<(), String> {
        let root = root.to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(validate_git_input_files(&root));
        });
        rx.recv_timeout(std::time::Duration::from_secs(3))
            .expect("validate_git_input_files blocked")
    }

    #[cfg(unix)]
    fn git_input_fixture() -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git/info")).unwrap();
        repo
    }

    #[cfg(unix)]
    #[test]
    fn validate_git_input_files_refuses_in_tree_fifos() {
        for name in [".gitattributes", ".gitignore", ".gitmodules"] {
            let repo = git_input_fixture();
            std::fs::create_dir_all(repo.path().join("subdir/deeper")).unwrap();
            make_fifo(&repo.path().join("subdir/deeper").join(name));
            let error = validate_git_input_files_bounded(repo.path()).unwrap_err();
            assert!(
                error.contains(&format!("\"subdir/deeper/{name}\" is not a regular file")),
                "{error}"
            );
        }
        for name in [".gitattributes", ".gitignore", ".gitmodules"] {
            let repo = git_input_fixture();
            make_fifo(&repo.path().join(name));
            let error = validate_git_input_files_bounded(repo.path()).unwrap_err();
            assert!(
                error.starts_with(&format!("\"{name}\" is not a regular file")),
                "{error}"
            );
        }
    }

    /// Attacker-chosen names are escaped in the message, so a newline or an
    /// ANSI escape cannot reach a report or terminal raw.
    #[cfg(unix)]
    #[test]
    fn validate_git_input_files_escapes_the_reported_path() {
        let repo = git_input_fixture();
        let dir = repo.path().join("evil\n\u{1b}[31mname");
        std::fs::create_dir(&dir).unwrap();
        make_fifo(&dir.join(".gitignore"));
        let error = validate_git_input_files_bounded(repo.path()).unwrap_err();
        assert!(
            !error.contains('\n') && !error.contains('\u{1b}'),
            "{error:?}"
        );
        assert!(error.contains("\\n"), "{error:?}");
    }

    /// Only an entry named exactly `.git` is skipped: on a case-sensitive
    /// file system Git descends into `.GIT` like any directory.
    #[cfg(unix)]
    #[test]
    fn validate_git_input_files_walks_differently_cased_git_dirs() {
        // No `.git` here: on a case-insensitive file system `.GIT` would
        // collide with it.
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join(".GIT")).unwrap();
        make_fifo(&repo.path().join(".GIT/.gitignore"));
        let error = validate_git_input_files_bounded(repo.path()).unwrap_err();
        assert!(
            error.contains("\".GIT/.gitignore\" is not a regular file"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_git_input_files_does_not_walk_symlinked_directories_or_git_dirs() {
        let repo = git_input_fixture();
        let outside = tempfile::tempdir().unwrap();
        make_fifo(&outside.path().join(".gitignore"));
        std::os::unix::fs::symlink(outside.path(), repo.path().join("linked")).unwrap();
        // A nested `.git` directory is Git metadata, not working-tree input.
        std::fs::create_dir_all(repo.path().join("nested/.git")).unwrap();
        make_fifo(&repo.path().join("nested/.git/.gitattributes"));
        assert_eq!(validate_git_input_files_bounded(repo.path()), Ok(()));
    }

    /// A symlinked input file is accepted without inspecting its target
    /// (which could be an automounted network path); Git >= 2.32 does not
    /// follow it, and older Git is bounded by the per-command timeout.
    #[cfg(unix)]
    #[test]
    fn validate_git_input_files_does_not_follow_symlinked_input_files() {
        let repo = git_input_fixture();
        let outside = tempfile::tempdir().unwrap();
        let fifo = outside.path().join("pipe");
        make_fifo(&fifo);
        std::fs::create_dir(repo.path().join("sub")).unwrap();
        for rel in [".gitignore", ".gitmodules", "sub/.gitattributes"] {
            std::os::unix::fs::symlink(&fifo, repo.path().join(rel)).unwrap();
        }
        assert_eq!(validate_git_input_files_bounded(repo.path()), Ok(()));
    }

    #[cfg(unix)]
    #[test]
    fn validate_git_input_files_accepts_regular_and_missing_files() {
        let repo = git_input_fixture();
        assert_eq!(validate_git_input_files_bounded(repo.path()), Ok(()));
        std::fs::write(repo.path().join(".git/info/exclude"), "*.log\n").unwrap();
        std::fs::write(repo.path().join(".git/info/attributes"), "* text\n").unwrap();
        std::fs::write(repo.path().join(".gitignore"), "target/\n").unwrap();
        std::fs::create_dir(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/.gitattributes"), "*.rs diff\n").unwrap();
        // A directory named like an input file is left to Git.
        std::fs::create_dir(repo.path().join("src/.gitignore")).unwrap();
        assert_eq!(validate_git_input_files_bounded(repo.path()), Ok(()));
        // No `.git` at all: the function still only inspects.
        let plain = tempfile::tempdir().unwrap();
        assert_eq!(validate_git_input_files_bounded(plain.path()), Ok(()));
    }

    #[test]
    fn read_regular_file_refuses_directories_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_regular_file(dir.path(), 16),
            Err(RegularFileError::NotRegular)
        ));
        let file = dir.path().join("f");
        std::fs::write(&file, b"0123456789").unwrap();
        assert_eq!(read_regular_file(&file, 10).unwrap(), b"0123456789");
        assert!(matches!(
            read_regular_file(&file, 9),
            Err(RegularFileError::TooLarge)
        ));
        assert!(matches!(
            read_regular_file(&dir.path().join("missing"), 16),
            Err(RegularFileError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(matches!(
                read_regular_file(&link, 16),
                Err(RegularFileError::NotRegular)
            ));
        }
    }

    // ── B3b: result-text masking ─────────────────────────

    #[test]
    fn mask_text_masks_json_kv_pairs_embedded_in_free_text() {
        let text = r#"Connected. {"api_key":"sk-live-abcdef","status":"ok"}"#;
        let masked = mask_sensitive_text(text);
        assert!(masked.contains(r#""api_key":"***""#));
        assert!(!masked.contains("sk-live-abcdef"));
        assert!(
            masked.contains(r#""status":"ok""#),
            "non-secret key untouched"
        );
    }

    #[test]
    fn mask_text_masks_plain_key_value_lines() {
        let text = "Login succeeded.\ntoken: abc.def.ghi\nuser: agnes";
        let masked = mask_sensitive_text(text);
        assert!(masked.contains("token: ***"));
        assert!(!masked.contains("abc.def.ghi"));
        assert!(masked.contains("user: agnes"), "non-secret key untouched");
    }

    #[test]
    fn mask_text_masks_bare_value_prefix_tokens_mid_sentence() {
        let text =
            "here is the token you asked for: sk-ant-api03-verylongsecrettoken, keep it safe";
        let masked = mask_sensitive_text(text);
        assert!(!masked.contains("verylongsecrettoken"));
        assert!(masked.contains("***"));
    }

    #[test]
    fn mask_text_key_match_is_word_boundary_not_substring() {
        // `author` must survive even though it contains the letters of `auth`.
        let text = "author: agnes, authorization: Bearer xyz123";
        let masked = mask_sensitive_text(text);
        assert!(
            masked.contains("author: agnes"),
            "author must not be masked"
        );
        assert!(!masked.contains("xyz123"));
    }

    #[test]
    fn mask_text_is_cjk_safe() {
        let text = "查詢結果：password: 憑證繁體中文密碼內容 完成";
        let masked = mask_sensitive_text(text); // must not panic on multi-byte content
        assert!(masked.contains("password: ***"));
        assert!(!masked.contains("憑證繁體中文密碼內容"));
    }

    #[test]
    fn mask_text_leaves_plain_prose_untouched() {
        let text = "Refund policy: 30 days from purchase, receipt required.";
        assert_eq!(mask_sensitive_text(text), text);
    }
}
