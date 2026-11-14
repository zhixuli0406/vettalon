//! Shared remediation input and create-new output protections.

use crate::audit;
use crate::audit::schema::{AuditReport, Finding};
use std::path::{Path, PathBuf};

/// Read a regular, non-symlink UTF-8 file of at most `cap` bytes.
///
/// On unix the file is opened with `O_NOFOLLOW | O_NONBLOCK`, so a path
/// swapped for a symlink or a FIFO after the first check neither follows the
/// link nor blocks in `open`; the opened handle is then `fstat`ed and must be
/// the same regular file. Regular files ignore `O_NONBLOCK` for reads.
pub fn read_regular_capped(path: &Path, cap: u64, label: &str) -> Result<String, String> {
    read_regular_capped_with_policy(path, cap, label, false, |_| Ok(cap))
}

/// Package-only policies are checked on the opened handle before allocation.
pub(crate) fn read_regular_capped_with_policy(
    path: &Path,
    cap: u64,
    label: &str,
    single_link: bool,
    check_size: impl Fn(u64) -> Result<u64, String>,
) -> Result<String, String> {
    use std::io::Read;
    let refused =
        || format!("{label} must be a regular non-symlink file no larger than {cap} bytes");
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect {label} {}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > cap {
        return Err(refused());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot open {label} {}: {e}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("cannot inspect {label} {}: {e}", path.display()))?;
    if !opened.is_file() || opened.len() > cap {
        return Err(refused());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if single_link && opened.nlink() != 1 {
            return Err(format!("{label} must have exactly one hard link"));
        }
        if (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino()) {
            return Err(format!("{label} changed while it was read"));
        }
    }
    #[cfg(not(unix))]
    let _ = single_link;
    let read_cap = check_size(opened.len())?.min(cap);
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&mut file)
        .take(read_cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {label} {}: {e}", path.display()))?;
    let unchanged = opened.len() == metadata.len()
        && file.metadata().map(|m| m.len()).ok() == Some(opened.len());
    if bytes.len() as u64 > read_cap || !unchanged {
        return Err(format!("{label} changed while it was read"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{label} must be UTF-8"))
}

/// Canonicalize the command's repository and require it to be the report's
/// own repository (reproduce, fix-check, retest and bisect). Returns the
/// canonical path.
pub fn check_report_repository(
    repo: &Path,
    report: &crate::audit::schema::AuditReport,
) -> Result<PathBuf, String> {
    let repo = std::fs::canonicalize(repo).map_err(|e| {
        format!(
            "cannot resolve repository {}: {e}",
            audit::retest::terminal_safe(&repo.to_string_lossy())
        )
    })?;
    if !repo.is_dir() {
        return Err("repository path is not a directory".into());
    }
    let reported_repo = std::fs::canonicalize(&report.repo).map_err(|e| {
        format!(
            "cannot resolve the report repository {:?}: {e}; reproduce/fix-check/retest refuses a moved or unavailable tree",
            report.repo
        )
    })?;
    if repo != reported_repo {
        return Err(format!(
            "repository identity mismatch: report names {}, command names {}",
            audit::retest::terminal_safe(&reported_repo.to_string_lossy()),
            audit::retest::terminal_safe(&repo.to_string_lossy())
        ));
    }
    Ok(repo)
}

pub fn remediation_context(
    repo: &Path,
    report_path: &Path,
    finding_id: &str,
    target_path: &Path,
) -> Result<
    (
        PathBuf,
        crate::audit::schema::AuditReport,
        crate::audit::schema::Finding,
        crate::audit::target_poc::TargetCall,
    ),
    String,
> {
    let (repo, report, finding) = remediation_finding(repo, report_path, finding_id)?;
    let target_raw = read_regular_capped(target_path, 8 * 1024, "target call")?;
    let target = crate::audit::target_poc::parse_target_call(&target_raw)
        .map_err(|reason| format!("target call refused: {reason}"))?;
    if target.file != finding.file {
        return Err(format!(
            "target file {:?} does not match finding file {:?}",
            target.file, finding.file
        ));
    }
    Ok((repo, report, finding, target))
}

/// Repository identity and finding selection shared by `reproduce`,
/// `fix check` and `bisect`: the canonical repository must be the report's.
pub fn remediation_finding(
    repo: &Path,
    report_path: &Path,
    finding_id: &str,
) -> Result<(PathBuf, AuditReport, Finding), String> {
    let report = audit::load_report_for_delivery(report_path)?;
    let repo = check_report_repository(repo, &report)?;
    let exact: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.id == finding_id)
        .collect();
    let matches = if exact.is_empty() {
        report
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with(finding_id))
            .collect::<Vec<_>>()
    } else {
        exact
    };
    let finding = match matches.as_slice() {
        [finding] => (*finding).clone(),
        [] => return Err(format!("finding {finding_id:?} is not in the report")),
        _ => return Err(format!("finding prefix {finding_id:?} is ambiguous")),
    };
    Ok((repo, report, finding))
}

fn encode_remediation_output<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value)
        .map_err(|e| format!("cannot serialize remediation output: {e}"))
}

/// Resolve a brand-new output without following a symlink in its parent
/// chain. Remediation outputs contain source evidence and must never replace
/// an operator-owned file, symlink target or hardlink.
pub fn preflight_new_output(path: &Path) -> Result<NewOutput, String> {
    use std::path::Component;

    if path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!(
            "unsafe output path {}; '..' is refused",
            path.display()
        ));
    }
    let raw_absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot resolve current directory: {e}"))?
            .join(path)
    };
    let mut absolute = PathBuf::new();
    for component in raw_absolute.components() {
        if !matches!(component, Component::CurDir) {
            absolute.push(component.as_os_str());
        }
    }
    let _parent = absolute
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    #[cfg(unix)]
    {
        let (dir, name) = absolute_output_parent(&absolute)?;
        use std::os::fd::AsRawFd;
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: dir is live, name is NUL-terminated, info is writable.
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                info.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Err(format!(
                "output already exists and will not be replaced: {}",
                absolute.display()
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(format!(
                "cannot inspect output {}: {error}",
                absolute.display()
            ));
        }
        Ok(NewOutput {
            path: absolute,
            dir,
            name,
        })
    }
    #[cfg(not(unix))]
    {
        // Windows retains path-based checks and create_new. Parent replacement
        // between preflight and creation/cleanup is not prevented on Windows.
        let mut cursor = PathBuf::new();
        for component in _parent.components() {
            cursor.push(component.as_os_str());
            let metadata = std::fs::symlink_metadata(&cursor)
                .map_err(|e| format!("cannot inspect output parent {}: {e}", cursor.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "output parent must be a real directory, not a symlink: {}",
                    cursor.display()
                ));
            }
        }
        match std::fs::symlink_metadata(&absolute) {
            Ok(_) => Err(format!(
                "output already exists and will not be replaced: {}",
                absolute.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(NewOutput { path: absolute })
            }
            Err(error) => Err(format!(
                "cannot inspect output {}: {error}",
                absolute.display()
            )),
        }
    }
}

/// A preflighted destination. Keep this handle across model/container calls;
/// writing consumes it so the pinned parent is never re-resolved by path.
#[derive(Debug)]
pub struct NewOutput {
    path: PathBuf,
    #[cfg(unix)]
    dir: std::fs::File,
    #[cfg(unix)]
    name: std::ffi::CString,
}

impl NewOutput {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_json<T: serde::Serialize>(self, value: &T) -> Result<(), String> {
        self.write_bytes(&encode_remediation_output(value)?)
    }

    pub fn write_text(self, text: &str) -> Result<(), String> {
        self.write_bytes(text.as_bytes())
    }

    pub fn write_bytes(self, bytes: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let mut file = create_new_private_output(&self)?;
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            self.cleanup(&file);
            return Err(format!(
                "cannot write output {}: {error}",
                self.path.display()
            ));
        }
        Ok(())
    }

    fn cleanup(&self, file: &std::fs::File) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let mut created = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: file is live and created points to writable stat storage.
            if unsafe { libc::fstat(file.as_raw_fd(), created.as_mut_ptr()) } != 0 {
                return;
            }
            let created = unsafe { created.assume_init() };
            let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
            // Keep the created file open so its inode cannot be recycled.
            // Resolve both inspection and unlink relative to the pinned parent.
            if unsafe {
                libc::fstatat(
                    self.dir.as_raw_fd(),
                    self.name.as_ptr(),
                    info.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                let info = unsafe { info.assume_init() };
                if (created.st_dev, created.st_ino) == (info.st_dev, info.st_ino) {
                    unsafe {
                        libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Start at the filesystem root, then open every parent component without
/// following links. Shared by general outputs and repository test outputs.
#[cfg(unix)]
fn absolute_output_parent(path: &Path) -> Result<(std::fs::File, std::ffi::CString), String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open("/")
        .map_err(|e| format!("cannot open output root: {e}"))?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| "output must be absolute")?;
    let mut parts = relative.components().peekable();
    while let Some(part) = parts.next() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return Err("output path contains an unsafe component".into());
        }
        let name = std::ffi::CString::new(part.as_os_str().as_bytes())
            .map_err(|_| "output path contains NUL")?;
        if parts.peek().is_none() {
            return Ok((dir, name));
        }
        // SAFETY: dir is live and name is NUL-terminated. Own each fd immediately.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(format!(
                "output parent must be a real directory, not a symlink: {}",
                std::io::Error::last_os_error()
            ));
        }
        dir = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    Err("output has no file name".into())
}

const EMIT_PATH_RULE: &str = "--emit-test requires a safe repo-relative path inside the canonical repository; symlinks are refused";

fn repo_output_path(repo: &Path, path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(EMIT_PATH_RULE.into());
    }
    let root = repo
        .canonicalize()
        .map_err(|e| format!("{EMIT_PATH_RULE}: {e}"))?;
    let absolute = root.join(path);
    let parent = absolute.parent().ok_or(EMIT_PATH_RULE)?;
    let resolved = parent
        .canonicalize()
        .map_err(|e| format!("{EMIT_PATH_RULE}: {e}"))?;
    if !resolved.starts_with(&root) {
        return Err(EMIT_PATH_RULE.into());
    }
    Ok(absolute)
}

#[cfg(unix)]
pub(crate) fn repo_output_parent(
    repo: &Path,
    path: &Path,
) -> Result<(std::fs::File, std::ffi::CString), String> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(EMIT_PATH_RULE.into());
    }
    let root = repo
        .canonicalize()
        .map_err(|e| format!("{EMIT_PATH_RULE}: {e}"))?;
    absolute_output_parent(&root.join(path)).map_err(|e| format!("{EMIT_PATH_RULE}: {e}"))
}

/// Preflight for --emit-test only; other remediation outputs keep their contract.
pub fn preflight_repo_test_output(repo: &Path, path: &Path) -> Result<PathBuf, String> {
    let absolute = repo_output_path(repo, path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let (dir, name) = repo_output_parent(repo, path)?;
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                info.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Err(format!("{EMIT_PATH_RULE}: output already exists"));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("{EMIT_PATH_RULE}: {error}"));
        }
        Ok(absolute)
    }
    #[cfg(not(unix))]
    preflight_new_output(&absolute)
        .map(|out| out.path)
        .map_err(|e| format!("{EMIT_PATH_RULE}: {e}"))
}

pub fn write_new_repo_test_output(repo: &Path, path: &Path, text: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd};
        let (dir, name) = repo_output_parent(repo, path)?;
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return Err(format!(
                "{EMIT_PATH_RULE}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("cannot write --emit-test output: {e}"))
    }
    #[cfg(not(unix))]
    {
        let absolute = repo_output_path(repo, path)?;
        write_new_text_output(&absolute, text).map_err(|e| format!("{EMIT_PATH_RULE}: {e}"))
    }
}

fn create_new_private_output(output: &NewOutput) -> Result<std::fs::File, String> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: the preflight handle owns dir and the NUL-terminated name.
        let fd =
            unsafe { libc::openat(output.dir.as_raw_fd(), output.name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return Err(format!(
                "cannot create new output {}: {}",
                output.path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
    #[cfg(not(unix))]
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output.path)
        .map_err(|e| format!("cannot create new output {}: {e}", output.path.display()))
}

/// Convenience for immediate writes. Delayed writers must retain NewOutput.
pub fn write_new_remediation_output<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), String> {
    preflight_new_output(path)?.write_json(value)
}

pub fn write_new_text_output(path: &Path, text: &str) -> Result<(), String> {
    preflight_new_output(path)?.write_text(text)
}

pub fn write_new_remediation_pair<A: serde::Serialize, B: serde::Serialize>(
    first_path: &Path,
    first: &A,
    second_path: &Path,
    second: &B,
) -> Result<(), String> {
    write_preflighted_remediation_pair(
        preflight_new_output(first_path)?,
        first,
        preflight_new_output(second_path)?,
        second,
    )
}

pub fn write_preflighted_remediation_pair<A: serde::Serialize, B: serde::Serialize>(
    first_output: NewOutput,
    first: &A,
    second_output: NewOutput,
    second: &B,
) -> Result<(), String> {
    let first_bytes = encode_remediation_output(first)?;
    let second_bytes = encode_remediation_output(second)?;
    write_preflighted_output_pair(first_output, &first_bytes, second_output, &second_bytes)
}

/// Write exact bytes to two pinned, create-new destinations. On failure,
/// remove only files whose identities still match the open created handles.
pub fn write_preflighted_output_pair(
    first_output: NewOutput,
    first_bytes: &[u8],
    second_output: NewOutput,
    second_bytes: &[u8],
) -> Result<(), String> {
    use std::io::Write;
    if first_output.path == second_output.path {
        return Err("--out and --report-out must be different paths".into());
    }
    let mut first_file = create_new_private_output(&first_output)?;
    let mut second_file = match create_new_private_output(&second_output) {
        Ok(file) => file,
        Err(error) => {
            first_output.cleanup(&first_file);
            return Err(error);
        }
    };
    let write_result = first_file
        .write_all(first_bytes)
        .and_then(|()| first_file.sync_all())
        .and_then(|()| second_file.write_all(second_bytes))
        .and_then(|()| second_file.sync_all());
    if let Err(error) = write_result {
        first_output.cleanup(&first_file);
        second_output.cleanup(&second_file);
        return Err(format!("cannot write remediation outputs: {error}"));
    }
    Ok(())
}

#[cfg(test)]
mod repo_test_output_tests {
    use super::*;

    #[test]
    fn emitted_tests_require_a_new_repo_relative_file() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join("tests")).unwrap();
        for path in [
            Path::new("../escape"),
            Path::new("/tmp/escape"),
            Path::new(""),
            Path::new("tests/../../escape"),
        ] {
            assert!(
                preflight_repo_test_output(repo.path(), path)
                    .unwrap_err()
                    .contains(EMIT_PATH_RULE)
            );
            assert!(write_new_repo_test_output(repo.path(), path, "bad").is_err());
        }
        let path = Path::new("tests/regression.test.mjs");
        assert_eq!(
            preflight_repo_test_output(repo.path(), path).unwrap(),
            repo.path().canonicalize().unwrap().join(path)
        );
        write_new_repo_test_output(repo.path(), path, "original").unwrap();
        assert!(write_new_repo_test_output(repo.path(), path, "replacement").is_err());
        assert_eq!(
            std::fs::read_to_string(repo.path().join(path)).unwrap(),
            "original"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(repo.path().join(path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn emitted_test_writer_rejects_parent_swaps_and_leaf_symlinks() {
        use std::os::unix::fs::symlink;
        let repo = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join("tests")).unwrap();
        let path = Path::new("tests/generated.py");
        preflight_repo_test_output(repo.path(), path).unwrap();
        std::fs::rename(repo.path().join("tests"), repo.path().join("original")).unwrap();
        symlink(outside.path(), repo.path().join("tests")).unwrap();
        assert!(
            write_new_repo_test_output(repo.path(), path, "bad")
                .unwrap_err()
                .contains(EMIT_PATH_RULE)
        );
        assert!(!outside.path().join("generated.py").exists());
        symlink(repo.path().join("original"), repo.path().join("internal")).unwrap();
        assert!(
            write_new_repo_test_output(repo.path(), Path::new("internal/generated.py"), "bad")
                .is_err()
        );
        symlink(outside.path().join("victim"), repo.path().join("leaf")).unwrap();
        assert!(write_new_repo_test_output(repo.path(), Path::new("leaf"), "bad").is_err());
        std::fs::write(repo.path().join("file"), "keep").unwrap();
        assert!(write_new_repo_test_output(repo.path(), Path::new("file/child"), "bad").is_err());
        assert!(!outside.path().join("victim").exists());
    }
}

#[cfg(all(test, unix))]
mod pinned_output_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn parent_swap_after_preflight_writes_only_in_original_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("parent")).unwrap();
        std::fs::create_dir(root.join("outside")).unwrap();
        let output = preflight_new_output(&root.join("parent/result")).unwrap();
        std::fs::rename(root.join("parent"), root.join("original")).unwrap();
        symlink(root.join("outside"), root.join("parent")).unwrap();
        output.write_text("private").unwrap();
        assert!(!root.join("outside/result").exists());
        let result = root.join("original/result");
        assert_eq!(std::fs::read_to_string(&result).unwrap(), "private");
        assert_eq!(
            std::fs::metadata(result).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(preflight_new_output(&root.join("parent/other")).is_err());
    }

    #[test]
    fn cleanup_preserves_replacement_files_and_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for link in [false, true] {
            let path = root.join(if link { "link" } else { "file" });
            let output = preflight_new_output(&path).unwrap();
            let created = create_new_private_output(&output).unwrap();
            std::fs::rename(&path, path.with_extension("original")).unwrap();
            if link {
                let victim = root.join("victim");
                std::fs::write(&victim, "preserve").unwrap();
                symlink(victim, &path).unwrap();
            } else {
                std::fs::write(&path, "preserve").unwrap();
            }
            output.cleanup(&created);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "preserve");
            assert!(path.with_extension("original").exists());
        }
    }

    #[test]
    fn cleanup_after_parent_swap_unlinks_only_owned_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("parent")).unwrap();
        std::fs::create_dir(root.join("outside")).unwrap();
        let output = preflight_new_output(&root.join("parent/result")).unwrap();
        let created = create_new_private_output(&output).unwrap();
        std::fs::write(root.join("outside/result"), "preserve").unwrap();
        std::fs::rename(root.join("parent"), root.join("original")).unwrap();
        symlink(root.join("outside"), root.join("parent")).unwrap();
        output.cleanup(&created);
        assert!(!root.join("original/result").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("outside/result")).unwrap(),
            "preserve"
        );
    }

    #[test]
    fn pair_second_creation_failure_cleans_only_first_owned_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = preflight_new_output(&root.join("first")).unwrap();
        let second = preflight_new_output(&root.join("second")).unwrap();
        std::fs::write(root.join("second"), "preserve").unwrap();
        assert!(write_preflighted_remediation_pair(first, &1, second, &2).is_err());
        assert!(!root.join("first").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("second")).unwrap(),
            "preserve"
        );
    }
}
