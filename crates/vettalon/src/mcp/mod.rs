//! Local, serial stdio MCP tools over a startup-bound repository and report.
pub mod protocol;
pub mod tools;
use crate::audit::{
    self,
    fix_check::FixCheckRun,
    schema::{AuditReport, Finding, sha256_hex},
    target_poc::{TargetCall, TargetPocWithTest},
};
use crate::remediation::{
    preflight_new_output, read_regular_capped, write_new_remediation_output,
    write_new_remediation_pair,
};
pub use protocol::{Backend, State, handle_message, serve};
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};

const PROPOSALS_CAP: u64 = 1024 * 1024;

/// Execution seam for tests. The production executor invokes only existing sandbox paths.
pub trait Executor {
    fn reproduce(
        &mut self,
        repo: &Path,
        finding: &Finding,
        target: &TargetCall,
        image: &str,
        emit: bool,
    ) -> TargetPocWithTest;
    fn check_fix(
        &mut self,
        repo: &Path,
        finding: &Finding,
        target: &TargetCall,
        diff: &str,
        command: Option<&str>,
        image: &str,
    ) -> FixCheckRun;
}

pub struct DockerExecutor(tokio::runtime::Runtime);
impl DockerExecutor {
    fn new() -> Result<Self, String> {
        tokio::runtime::Runtime::new()
            .map(Self)
            .map_err(|_| "cannot start sandbox runtime".into())
    }
}
impl Executor for DockerExecutor {
    fn reproduce(
        &mut self,
        repo: &Path,
        finding: &Finding,
        target: &TargetCall,
        image: &str,
        emit: bool,
    ) -> TargetPocWithTest {
        if emit {
            self.0.block_on(audit::target_poc::run_target_poc_with_test(
                repo, finding, target, image,
            ))
        } else {
            TargetPocWithTest {
                receipt: self.0.block_on(audit::target_poc::run_target_poc(
                    repo, finding, target, image,
                )),
                test_source: None,
            }
        }
    }
    fn check_fix(
        &mut self,
        repo: &Path,
        finding: &Finding,
        target: &TargetCall,
        diff: &str,
        command: Option<&str>,
        image: &str,
    ) -> FixCheckRun {
        self.0.block_on(audit::fix_check::run_target_fix(
            repo, finding, target, diff, command, image,
        ))
    }
}

pub struct LocalBackend<E = DockerExecutor> {
    repo: PathBuf,
    report: Option<PathBuf>,
    state_dir: PathBuf,
    test_command: Option<String>,
    image: String,
    executor: E,
}
impl LocalBackend {
    pub fn new(
        repo: &Path,
        report: Option<PathBuf>,
        home: &Path,
        test_command: Option<String>,
        image: String,
    ) -> Result<Self, String> {
        Self::with_executor(
            repo,
            report,
            home,
            test_command,
            image,
            DockerExecutor::new()?,
        )
    }
}
impl<E: Executor> LocalBackend<E> {
    pub fn with_executor(
        repo: &Path,
        report: Option<PathBuf>,
        home: &Path,
        test_command: Option<String>,
        image: String,
        executor: E,
    ) -> Result<Self, String> {
        let repo = std::fs::canonicalize(repo).map_err(|_| "cannot resolve repository")?;
        if !repo.is_dir() {
            return Err("repository must be a directory".into());
        }
        if let Some(command) = test_command.as_deref() {
            audit::fix_check::validate_test_command(command)?;
        }
        let state_dir = state_dir(home, &repo)?;
        let report = report.or_else(|| newest_report(home, &repo));
        Ok(Self {
            repo,
            report,
            state_dir,
            test_command,
            image,
            executor,
        })
    }
    fn load(&self) -> Result<(AuditReport, String), String> {
        let path = self
            .report
            .as_deref()
            .ok_or("No saved report. Run vettalon scan --save first.")?;
        let (report, digest) = audit::load_report_for_delivery_with_sha256(path)
            .map_err(|_| "Saved report is unavailable or invalid. Run vettalon scan --save.")?;
        if std::fs::canonicalize(&report.repo).ok().as_deref() != Some(&self.repo) {
            return Err("report repository identity mismatch".into());
        }
        Ok((report, digest))
    }
    fn output(&self, kind: &str) -> PathBuf {
        self.state_dir
            .join(format!("{kind}-{}.json", uuid::Uuid::new_v4()))
    }
    fn execute(
        &mut self,
        name: &str,
        args: &Value,
        mut report: AuditReport,
        digest: &str,
    ) -> Result<Value, String> {
        if name == "vettalon_report_summary" {
            return Ok(
                json!({"run_status":report.run_status,"incomplete_reason":report.incomplete_reason,"funnel":audit::funnel::derive(&report),"modules_total":report.coverage.len(),"summary":report.summary}),
            );
        }
        if name == "vettalon_list_findings" {
            return Ok(list_findings(&report, args));
        }
        let finding =
            select_finding(&report, args["finding"].as_str().ok_or("finding required")?)?.clone();
        match name {
            "vettalon_get_finding" => Ok(json!({"finding":finding})),
            "vettalon_fix_brief" => Ok(json!({
                "what":{"title":finding.title,"snippet":finding.snippet},
                "where":{"file":finding.file,"line":finding.line},"status":finding.status,
                "evidence_level":finding.evidence_level(),"proof_gaps":finding.proof_gaps(),
                "how_to_check":"Use vettalon_reproduce, then vettalon_check_fix with the same target call.",
                "instructions":["Change the source code.","Do not edit tests or the harness to make a check pass.","A passing check does not change the finding status."]})),
            "vettalon_suggest_noise" => {
                let row = json!({"finding":finding.id,"reason":crate::util::mask_sensitive_text(args["reason"].as_str().unwrap()),"created_at":chrono::Utc::now().to_rfc3339(),"report_sha256":digest});
                append_proposal(&self.state_dir, &row)?;
                Ok(json!({"proposed":true,"status_unchanged":true}))
            }
            "vettalon_reproduce" | "vettalon_check_fix" => {
                let target = bound_target(&finding, args)?;
                if name == "vettalon_reproduce" {
                    self.reproduce_tool(
                        &finding,
                        &target,
                        args["emit_test"].as_bool().unwrap_or(false),
                    )
                } else {
                    self.check_fix_tool(
                        &finding,
                        &target,
                        args["diff"].as_str().unwrap(),
                        &mut report,
                    )
                }
            }
            _ => Err("unknown tool".into()),
        }
    }
    fn reproduce_tool(
        &mut self,
        finding: &Finding,
        target: &TargetCall,
        emit: bool,
    ) -> Result<Value, String> {
        let result = self
            .executor
            .reproduce(&self.repo, finding, target, &self.image, emit);
        prune_outputs(&self.state_dir, "reproduce")?;
        write_new_remediation_output(&self.output("reproduce"), &result.receipt)
            .map_err(|_| "cannot save reproduction receipt")?;
        Ok(
            json!({"outcome":result.receipt.outcome,"phases":result.receipt.phases,"test":result.test_source,"receipt":result.receipt,"status_unchanged":true}),
        )
    }
    fn check_fix_tool(
        &mut self,
        finding: &Finding,
        target: &TargetCall,
        diff: &str,
        report: &mut AuditReport,
    ) -> Result<Value, String> {
        let patches = audit::fix_diff::parse(diff).map_err(|reason| format!(
            "MCP single-file check_fix rule: {reason}; multi-file fixes go through vettalon fix check by a person."
        ))?;
        let touched_paths: Vec<_> = patches.iter().map(|p| p.path.as_str()).collect();
        if touched_paths != [finding.file.as_str()] {
            return Err(format!(
                "MCP single-file check_fix rule: only the finding's file may be touched; multi-file fixes go through vettalon fix check by a person. touched file count: {}",
                touched_paths.len()
            ));
        }
        let run = self.executor.check_fix(
            &self.repo,
            finding,
            target,
            diff,
            self.test_command.as_deref(),
            &self.image,
        );
        let updated = report
            .findings
            .iter_mut()
            .find(|f| f.id == finding.id)
            .ok_or("finding disappeared")?;
        updated.suggested_fix = Some(diff.into());
        audit::fix_check::record_fix_run(updated, &run);
        if !audit::validation_errors(report).is_empty() {
            return Err("updated report failed validation".into());
        }
        prune_outputs(&self.state_dir, "fix-receipt")?;
        prune_outputs(&self.state_dir, "fix-report")?;
        write_new_remediation_pair(
            &self.output("fix-receipt"),
            &run,
            &self.output("fix-report"),
            report,
        )
        .map_err(|_| "cannot save fix-check outputs")?;
        Ok(
            json!({"touched_paths":touched_paths,"outcome":run.outcome(),"phases":{"regression":run.check.regression,"tests":run.check.tests},"receipt":run,"nothing_applied":true,"notice_applied":"Nothing was applied to the repository. Finding status is unchanged."}),
        )
    }
}
fn bound_target(finding: &Finding, args: &Value) -> Result<TargetCall, String> {
    let target = audit::target_poc::parse_target_call(&args["target"].to_string())
        .map_err(|_| "invalid target call")?;
    if target.file != finding.file {
        return Err("target does not match finding".into());
    }
    if audit::poc_oracle::classify(finding).is_none() || !finding.file.ends_with(".py") {
        return Err("unsupported finding class or language".into());
    }
    Ok(target)
}
impl<E: Executor> Backend for LocalBackend<E> {
    fn call(&mut self, name: &str, args: Value) -> Result<Value, String> {
        tools::validate_args(name, &args)?;
        let (report, digest) = self.load()?;
        let mut value = self.execute(name, &args, report, &digest)?;
        // The generated artifact embeds call data as hex JSON and masks its display ID. Prose
        // masking would corrupt fixed Python identifiers such as SECRET.
        let test = value.as_object_mut().and_then(|o| o.remove("test"));
        tools::sanitize(&mut value);
        if let Some(test) = test {
            if test.as_str().is_some_and(|s| s.len() > 128 * 1024) {
                return Err("generated test exceeds 128 KiB; no test returned".into());
            }
            value["test"] = test;
        }
        Ok(tools::envelope(value))
    }
}

pub fn select_finding<'a>(report: &'a AuditReport, id: &str) -> Result<&'a Finding, String> {
    if id.is_empty() {
        return Err("finding required".into());
    }
    let exact: Vec<_> = report.findings.iter().filter(|f| f.id == id).collect();
    let matches = if exact.is_empty() {
        report
            .findings
            .iter()
            .filter(|f| f.id.starts_with(id))
            .collect()
    } else {
        exact
    };
    match matches.as_slice() {
        [f] => Ok(f),
        [] => Err("finding is missing".into()),
        _ => Err("finding is ambiguous".into()),
    }
}
fn severity_rank(s: &str) -> usize {
    ["info", "low", "medium", "high", "critical"]
        .iter()
        .position(|v| *v == s)
        .unwrap_or(0)
}
fn list_findings(report: &AuditReport, args: &Value) -> Value {
    let min = severity_rank(args["min_severity"].as_str().unwrap_or("info"));
    let findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            let status = serde_json::to_value(f.status).unwrap();
            let severity = serde_json::to_value(f.severity).unwrap();
            (args.get("status").is_none_or(|s| *s == status))
                && severity_rank(severity.as_str().unwrap()) >= min
        })
        .collect();
    let offset = args["offset"].as_u64().unwrap_or(0).min(usize::MAX as u64) as usize;
    let limit = args["limit"].as_u64().unwrap_or(50).min(100) as usize;
    let rows: Vec<_> = findings.iter().skip(offset).take(limit).map(|f| json!({"id":f.id,"title":f.title,"file":f.file,"line":f.line,"status":f.status,"severity":f.severity,"reproducible":f.file.ends_with(".py") && audit::poc_oracle::classify(f).is_some()})).collect();
    json!({"findings":rows,"total":findings.len(),"offset":offset,"limit":limit})
}

fn newest_report(home: &Path, repo: &Path) -> Option<PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(home.join("reports"))
        .ok()?
        .flatten()
        .filter(|e| {
            e.file_type().is_ok_and(|t| t.is_file())
                && e.path().extension().is_some_and(|s| s == "json")
        })
        .map(|e| e.path())
        .collect();
    paths.sort_by(|a, b| {
        audit::report::saved_report_sort_key(&b.file_name().unwrap().to_string_lossy()).cmp(
            &audit::report::saved_report_sort_key(&a.file_name().unwrap().to_string_lossy()),
        )
    });
    paths.into_iter().find(|p| {
        audit::load_report_for_delivery(p)
            .is_ok_and(|r| std::fs::canonicalize(r.repo).ok().as_deref() == Some(repo))
    })
}

/// Resolve the trusted operator home, then reject symlinks below it.
pub fn state_dir(home: &Path, repo: &Path) -> Result<PathBuf, String> {
    resolve_state_dir(home, repo, true)
}

fn resolve_state_dir(home: &Path, repo: &Path, create: bool) -> Result<PathBuf, String> {
    let repo = std::fs::canonicalize(repo).map_err(|_| "cannot resolve repository")?;
    let home = if home.is_absolute() {
        home.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "cannot resolve home")?
            .join(home)
    };
    // Walk prefixes in order so unresolved dot/parent components cannot be
    // discarded by file_name/parent before the existing ancestor is resolved.
    let mut resolved = PathBuf::new();
    let mut missing = false;
    // Track normalized-away CurDir segments by their lexical component index.
    // Dots within an existing prefix remain valid; unresolved suffixes cannot
    // contain them. Encoded-byte inspection preserves non-UTF-8 path names.
    let mut lexical_count = 0;
    let mut last_cur_dir = None;
    for part in home
        .as_os_str()
        .as_encoded_bytes()
        .split(|b| *b == b'/' || (cfg!(windows) && *b == b'\\'))
    {
        if part == b"." {
            last_cur_dir = Some(lexical_count);
        } else if !part.is_empty() {
            lexical_count += 1;
        }
    }
    let mut component_count = 0;
    for component in home.components() {
        match component {
            std::path::Component::Prefix(prefix) => {
                // UNC and verbatim prefixes occupy multiple lexical segments.
                component_count += prefix
                    .as_os_str()
                    .as_encoded_bytes()
                    .split(|b| *b == b'/' || *b == b'\\')
                    .filter(|part| !part.is_empty())
                    .count();
            }
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            _ => component_count += 1,
        }
        if missing {
            let std::path::Component::Normal(name) = component else {
                return Err("unsafe home directory component".into());
            };
            resolved.push(name);
            continue;
        }
        resolved.push(component);
        match std::fs::symlink_metadata(&resolved) {
            Ok(_) => {
                resolved =
                    std::fs::canonicalize(&resolved).map_err(|_| "cannot resolve home ancestor")?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if last_cur_dir.is_some_and(|index| index >= component_count) {
                    return Err("unsafe home directory component".into());
                }
                missing = true;
            }
            Err(_) => return Err("cannot inspect home".into()),
        }
    }
    if resolved.starts_with(&repo) || home.starts_with(&repo) {
        return Err("MCP state directory must be outside repository".into());
    }
    if create {
        std::fs::create_dir_all(&resolved).map_err(|_| "cannot create home directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&resolved, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "cannot protect home directory")?;
        }
    }
    let home = resolved;
    if home.starts_with(&repo) {
        return Err("MCP state directory must be outside repository".into());
    }
    let hash = sha256_hex(repo.as_os_str().as_encoded_bytes());
    let relative = PathBuf::from("mcp").join(&hash[..16]);
    let mut cursor = home.clone();
    for component in relative.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err("unsafe state directory".into());
        }
        cursor.push(component);
        match std::fs::symlink_metadata(&cursor) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Ok(_) => return Err("state directory contains a symlink or non-directory".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    continue;
                }
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder
                    .create(&cursor)
                    .map_err(|_| "cannot create private state directory")?;
            }
            Err(_) => return Err("cannot inspect state directory".into()),
        }
    }
    let path = if create {
        std::fs::canonicalize(&cursor).map_err(|_| "cannot resolve state directory")?
    } else {
        cursor
    };
    if path.starts_with(&repo) {
        return Err("MCP state directory must be outside repository".into());
    }
    #[cfg(unix)]
    if create {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot protect state directory")?;
    }
    Ok(path)
}
/// Reserve one slot per artifact prefix, inspecting entries without following symlinks.
fn prune_outputs(dir: &Path, prefix: &str) -> Result<(), String> {
    preflight_new_output(&dir.join(format!("probe-{}", uuid::Uuid::new_v4())))
        .map_err(|_| "unsafe receipt directory")?;
    let prefix = format!("{prefix}-");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|_| "cannot enumerate receipts")? {
        let entry = entry.map_err(|_| "cannot inspect receipt entry")?;
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|_| "cannot inspect receipt")?;
        if meta.is_file() {
            files.push((
                meta.modified().map_err(|_| "cannot read receipt mtime")?,
                entry.path(),
            ));
        }
    }
    files.sort();
    let remove = files.len().saturating_sub(99);
    for (_, path) in files.into_iter().take(remove) {
        // Recheck type before unlinking; never follow a replaced entry.
        let meta = std::fs::symlink_metadata(&path).map_err(|_| "cannot inspect old receipt")?;
        if meta.is_file() {
            std::fs::remove_file(path).map_err(|_| "cannot remove old receipt")?;
        }
    }
    Ok(())
}

fn append_proposal(dir: &Path, row: &Value) -> Result<(), String> {
    let path = dir.join("proposals.jsonl");
    // Also validate the existing parent chain before opening an append-only file.
    preflight_new_output(&dir.join(format!("probe-{}", uuid::Uuid::new_v4())))
        .map_err(|_| "unsafe proposal directory")?;
    if let Ok(m) = std::fs::symlink_metadata(&path)
        && (!m.is_file() || m.file_type().is_symlink())
    {
        return Err("unsafe proposals file".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(&path)
        .map_err(|_| "cannot open proposals file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect proposals file")?;
    if !metadata.is_file() {
        return Err("unsafe proposals file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 {
            return Err("hardlinked proposals file refused".into());
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot protect proposals file")?;
    }
    let line = format!("{row}\n");
    if metadata.len().saturating_add(line.len() as u64) > PROPOSALS_CAP {
        return Err("proposals file reached 1 MiB cap".into());
    }
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot append proposal".into())
}

pub fn print_proposals(report_path: &Path, home: &Path) -> Result<String, String> {
    let report = audit::load_report_for_delivery(report_path)?;
    let dir = resolve_state_dir(home, Path::new(&report.repo), false)?;
    let path = dir.join("proposals.jsonl");
    if !path.try_exists().map_err(|_| "cannot inspect proposals")? {
        return Ok(String::new());
    }
    let raw = read_regular_capped(&path, PROPOSALS_CAP, "proposals")?;
    let mut lines = Vec::new();
    for line in raw.lines() {
        let mut value: Value = serde_json::from_str(line).map_err(|_| "invalid proposal data")?;
        tools::sanitize(&mut value);
        let encoded = tools::envelope(json!({"proposal":value})).to_string();
        let escaped = encoded
            .chars()
            .map(|c| {
                if c.is_control() {
                    format!("\\u{:04x}", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect::<String>();
        lines.push(escaped);
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests;
