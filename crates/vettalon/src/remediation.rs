//! Shared remediation input and create-new output protections.

use crate::audit;
use std::path::{Path, PathBuf};

pub fn read_regular_capped(path: &Path, cap: u64, label: &str) -> Result<String, String> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect {label} {}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > cap {
        return Err(format!(
            "{label} must be a regular non-symlink file no larger than {cap} bytes"
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot open {label} {}: {e}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {label} {}: {e}", path.display()))?;
    if bytes.len() as u64 > cap || file.metadata().map(|m| m.len()).ok() != Some(metadata.len()) {
        return Err(format!("{label} changed while it was read"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{label} must be UTF-8"))
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
    let repo = std::fs::canonicalize(repo)
        .map_err(|e| format!("cannot resolve repository {}: {e}", repo.display()))?;
    if !repo.is_dir() {
        return Err("repository path is not a directory".into());
    }
    let report = audit::load_report_for_delivery(report_path)?;
    let reported_repo = std::fs::canonicalize(&report.repo).map_err(|e| {
        format!(
            "cannot resolve the report repository {:?}: {e}; reproduce/fix-check refuses a moved or unavailable tree",
            report.repo
        )
    })?;
    if repo != reported_repo {
        return Err(format!(
            "repository identity mismatch: report names {}, command names {}",
            reported_repo.display(),
            repo.display()
        ));
    }
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

fn encode_remediation_output<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value)
        .map_err(|e| format!("cannot serialize remediation output: {e}"))
}

/// Resolve a brand-new output without following a symlink in its parent
/// chain. Remediation outputs contain source evidence and must never replace
/// an operator-owned file, symlink target or hardlink.
pub fn preflight_new_output(path: &Path) -> Result<PathBuf, String> {
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
    let parent = absolute
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::CurDir) {
            continue;
        }
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(absolute),
        Err(error) => Err(format!(
            "cannot inspect output {}: {error}",
            absolute.display()
        )),
    }
}

fn create_new_private_output(path: &Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|e| format!("cannot create new output {}: {e}", path.display()))
}

pub fn write_new_remediation_output<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), String> {
    use std::io::Write;

    let encoded = encode_remediation_output(value)?;
    let path = preflight_new_output(path)?;
    let mut file = create_new_private_output(&path)?;
    if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(format!("cannot write output {}: {error}", path.display()));
    }
    Ok(())
}

pub fn write_new_text_output(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;

    let path = preflight_new_output(path)?;
    let mut file = create_new_private_output(&path)?;
    if let Err(error) = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(format!("cannot write output {}: {error}", path.display()));
    }
    Ok(())
}

pub fn write_new_remediation_pair<A: serde::Serialize, B: serde::Serialize>(
    first_path: &Path,
    first: &A,
    second_path: &Path,
    second: &B,
) -> Result<(), String> {
    use std::io::Write;

    let first_bytes = encode_remediation_output(first)?;
    let second_bytes = encode_remediation_output(second)?;
    let first_path = preflight_new_output(first_path)?;
    let second_path = preflight_new_output(second_path)?;
    if first_path == second_path {
        return Err("--out and --report-out must be different paths".into());
    }
    let mut first_file = create_new_private_output(&first_path)?;
    let mut second_file = match create_new_private_output(&second_path) {
        Ok(file) => file,
        Err(error) => {
            drop(first_file);
            let _ = std::fs::remove_file(&first_path);
            return Err(error);
        }
    };
    let write_result = first_file
        .write_all(&first_bytes)
        .and_then(|()| first_file.sync_all())
        .and_then(|()| second_file.write_all(&second_bytes))
        .and_then(|()| second_file.sync_all());
    if let Err(error) = write_result {
        drop(first_file);
        drop(second_file);
        let _ = std::fs::remove_file(&first_path);
        let _ = std::fs::remove_file(&second_path);
        return Err(format!("cannot write remediation outputs: {error}"));
    }
    Ok(())
}
