//! Command-scoped Node installation and offline execution context.
use std::{path::Path, sync::Arc};

use super::{fixture, lockfile};
use crate::audit::{
    schema::sha256_hex,
    target_poc::{NodeDriver, NodeRuntime, TargetCall, node_assets_for},
};
use crate::sandbox::{DockerSandbox, InstalledDependencies};

pub const RUNTIME_HELP: &str = "Node runtime unavailable; run `vettalon poc-node build` (images are never pulled automatically)";

/// Only the digest of this private fixture is exported to receipts.
#[derive(Clone, Default)]
pub struct NodeOptions {
    pub image: String,
    pub fixture: Option<fixture::NodeFixture>,
}

impl NodeOptions {
    pub fn read(image: String, path: Option<&Path>, repo: &Path) -> Result<Self, String> {
        let fixture = path
            .map(|path| {
                // Resolve the repository before touching the private fixture. Resolve
                // parent aliases too, but never accept a symlink as the input file.
                let repo = repo
                    .canonicalize()
                    .map_err(|_| "cannot resolve repository for --fixture".to_string())?;
                let metadata = std::fs::symlink_metadata(path)
                    .map_err(|_| "node_fixture_refused".to_string())?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(
                        "node_fixture_refused: --fixture must be a regular non-symlink file".into(),
                    );
                }
                // Canonicalize only the parent: resolving the final component
                // here would defeat O_NOFOLLOW if it were swapped for a symlink.
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let path = parent
                    .canonicalize()
                    .map_err(|_| "node_fixture_refused".to_string())?
                    .join(
                        path.file_name()
                            .ok_or_else(|| "node_fixture_refused".to_string())?,
                    );
                if path.starts_with(&repo) {
                    return Err(
                        "node_fixture_refused: --fixture must be outside the repository".into(),
                    );
                }
                // The bounded reader opens with O_NOFOLLOW and verifies the handle.
                let bytes = read_bounded(&path, fixture::FIXTURE_MAX_BYTES)
                    .map_err(|_| "node_fixture_refused".to_string())?;
                fixture::validate_fixture(&bytes).map_err(|_| "node_fixture_refused".to_string())
            })
            .transpose()?;
        Ok(Self { image, fixture })
    }
}

fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>, &'static str> {
    crate::remediation::read_regular_capped(path, cap as u64, "Node input")
        .map(String::into_bytes)
        .map_err(|_| "node_lockfile_refused")
}

struct Inputs {
    manifest: Vec<u8>,
    lock: Vec<u8>,
    summary: lockfile::LockfileSummary,
}

fn inputs(tree: &Path) -> Result<Inputs, &'static str> {
    let manifest = match std::fs::symlink_metadata(tree.join("package.json")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => b"{}".to_vec(),
        _ => read_bounded(&tree.join("package.json"), lockfile::PACKAGE_JSON_MAX_BYTES)?,
    };
    lockfile::validate_package_json(&manifest).map_err(|_| "node_lockfile_refused")?;
    let value: serde_json::Value =
        serde_json::from_slice(&manifest).map_err(|_| "node_lockfile_refused")?;
    let has_deps = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .iter()
    .any(|key| value[*key].as_object().is_some_and(|map| !map.is_empty()));
    // npm gives shrinkwrap precedence, so validate that exact input when present.
    let mut lock_path = None;
    for name in ["npm-shrinkwrap.json", "package-lock.json"] {
        match std::fs::symlink_metadata(tree.join(name)) {
            Ok(_) => {
                lock_path = Some(name);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("node_lockfile_refused"),
        }
    }
    let lock = match lock_path {
        Some(name) => read_bounded(&tree.join(name), lockfile::LOCKFILE_MAX_BYTES)?,
        None if has_deps => return Err("node_lockfile_missing"),
        // Bind a deterministic empty lock to dependency-free projects, including
        // bare .cjs/.mjs files. No network/install is necessary.
        None => serde_json::to_vec(&serde_json::json!({"lockfileVersion":3,"packages":{"":value}}))
            .map_err(|_| "node_lockfile_refused")?,
    };
    let summary =
        lockfile::validate_install_inputs(&manifest, &lock).map_err(|_| "node_lockfile_refused")?;
    let locked: serde_json::Value =
        serde_json::from_slice(&lock).map_err(|_| "node_lockfile_refused")?;
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "peerDependenciesMeta",
    ] {
        let empty = serde_json::json!({});
        if value.get(key).unwrap_or(&empty) != locked["packages"][""].get(key).unwrap_or(&empty) {
            return Err("node_lockfile_refused");
        }
    }
    Ok(Inputs {
        manifest,
        lock,
        summary,
    })
}

/// Shared by all phases, variants, replays and retest findings at one revision.
/// Fixture values and installed paths deliberately have no Serialize/Debug impl.
pub struct NodeExecution {
    installed: Option<InstalledDependencies>,
    summary: lockfile::LockfileSummary,
    manifest: Vec<u8>,
    fixture: Option<fixture::NodeFixture>,
    version: String,
}

#[async_trait::async_trait]
pub(crate) trait Installer: Send + Sync {
    async fn version(&self) -> Result<String, &'static str>;
    async fn install(
        &self,
        manifest: &[u8],
        lock: &[u8],
    ) -> Result<Option<InstalledDependencies>, &'static str>;
}

#[async_trait::async_trait]
impl Installer for DockerSandbox {
    async fn version(&self) -> Result<String, &'static str> {
        let (code, output) = self
            .run_workspace(
                &[],
                &["/usr/local/bin/node".into(), "--version".into()],
                None,
                std::time::Duration::from_secs(30),
            )
            .await
            .map_err(|_| "node_runtime_unavailable")?;
        let version = output.trim();
        if code != 0
            || version.len() > 64
            || !version.starts_with('v')
            || !version[1..]
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err("node_runtime_unavailable");
        }
        Ok(version.into())
    }
    async fn install(
        &self,
        manifest: &[u8],
        lock: &[u8],
    ) -> Result<Option<InstalledDependencies>, &'static str> {
        self.run_install(manifest, lock).await
    }
}

pub(crate) async fn prepare<I: Installer>(
    tree: &Path,
    installer: &I,
    fixture: Option<fixture::NodeFixture>,
) -> Result<NodeExecution, &'static str> {
    let input = inputs(tree)?;
    let version = installer.version().await?;
    let installed = if input.summary.needs_install() {
        installer.install(&input.manifest, &input.lock).await?
    } else {
        None
    };
    Ok(NodeExecution {
        installed,
        summary: input.summary,
        manifest: input.manifest,
        fixture,
        version,
    })
}

/// A failed preparation is also cached: never retry a network install in one command.
#[derive(Default)]
pub(crate) struct Session(tokio::sync::OnceCell<Result<Arc<NodeExecution>, &'static str>>);

impl Session {
    pub(crate) async fn prepare<I: Installer>(
        &self,
        tree: &Path,
        sb: &I,
        fixture: Option<fixture::NodeFixture>,
    ) -> Result<Arc<NodeExecution>, &'static str> {
        let execution = self
            .0
            .get_or_init(|| async { prepare(tree, sb, fixture).await.map(Arc::new) })
            .await
            .clone()?;
        execution.check_inputs(tree)?;
        Ok(execution)
    }
}

impl NodeExecution {
    pub(crate) fn fixture_sha256(&self) -> Option<&str> {
        self.fixture.as_ref().map(|fixture| fixture.sha256())
    }

    pub(crate) fn check_inputs(&self, tree: &Path) -> Result<(), &'static str> {
        let input = inputs(tree)?;
        if input.manifest != self.manifest || input.summary != self.summary {
            return Err("diff_changes_dependencies");
        }
        Ok(())
    }

    pub(crate) fn runtime(
        &self,
        tree: &Path,
        call: &TargetCall,
        source: &str,
        class: crate::audit::poc_oracle::OracleClass,
    ) -> NodeRuntime {
        let manifest: serde_json::Value =
            serde_json::from_slice(&self.manifest).unwrap_or_default();
        let mut module_type = manifest["type"].as_str().unwrap_or("commonjs").to_string();
        // Node uses the nearest package scope for .js/.ts.
        if let Some(parent) = Path::new(&call.file).parent() {
            let mut scope = tree.join(parent);
            while scope != tree {
                if let Ok(bytes) = read_bounded(
                    &scope.join("package.json"),
                    lockfile::PACKAGE_JSON_MAX_BYTES,
                ) {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        module_type = value["type"].as_str().unwrap_or("commonjs").into();
                    }
                    break;
                }
                if !scope.pop() {
                    break;
                }
            }
        }
        let ext = call.file.rsplit('.').next().unwrap_or("");
        let esm = matches!(ext, "mjs" | "mts")
            || (!matches!(ext, "cjs" | "cts") && module_type == "module");
        // Host-selected driver, never a child event's executable claim. Server
        // drivers take precedence if a project imports more than one driver.
        let has = |name: &str| {
            self.summary.packages.iter().any(|p| p.name == name)
                || source.contains(&format!("'{name}'"))
                || source.contains(&format!("\"{name}\""))
        };
        let driver = if class != crate::audit::poc_oracle::OracleClass::Sqli {
            None
        } else if has("pg") {
            Some(NodeDriver::Pg)
        } else if has("mysql2") || has("mysql2/promise") {
            Some(NodeDriver::Mysql2)
        } else if has("sqlite3") {
            Some(NodeDriver::Sqlite3)
        } else {
            None
        };
        NodeRuntime {
            language: if matches!(ext, "ts" | "mts" | "cts") {
                "typescript"
            } else {
                "javascript"
            }
            .into(),
            module_kind: if esm { "esm" } else { "cjs" }.into(),
            export_kind: if call.function == "default" {
                "default"
            } else {
                "named"
            }
            .into(),
            node_version: self.version.clone(),
            lockfile_sha256: Some(self.summary.lockfile_sha256.clone()),
            lockfile_summary_sha256: Some(self.summary.packages_sha256.clone()),
            deps_sha256: self
                .installed
                .as_ref()
                .map(|deps| deps.digest.sha256.clone()),
            fixture_sha256: self.fixture.as_ref().map(|f| f.sha256().into()),
            driver,
            hook_bundle_sha256: sha256_hex(
                node_assets_for(class)
                    .iter()
                    .flat_map(|(_, text)| text.as_bytes().iter().copied())
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        }
    }

    /// Drop all untrusted display text when a secret fixture is supplied.
    /// Pattern masking cannot guarantee that arbitrary auth values stay private.
    pub(in crate::audit) fn redact(
        &self,
        verdict: &mut crate::audit::target_poc::NodeHarnessVerdict,
    ) {
        if self.fixture.is_some()
            && let Some(first) = &mut verdict.reach.first_match
        {
            first.display = "[fixture redacted]".into();
            first.api = "[redacted]".into();
        }
    }

    pub(crate) async fn run_tests(
        &self,
        sb: &DockerSandbox,
        tree: &Path,
        command: &str,
    ) -> Result<i64, String> {
        let cmd = vec![
            "sh".into(),
            "-c".into(),
            format!("cd /workspace/tree && {command}"),
        ];
        let result = match &self.installed {
            Some(deps) => {
                sb.run_workspace_with_tree_and_deps(
                    &[],
                    tree,
                    &deps.path,
                    &cmd,
                    None,
                    crate::audit::poc::POC_TIMEOUT,
                )
                .await
            }
            None => {
                sb.run_workspace_with_tree(&[], tree, &cmd, None, crate::audit::poc::POC_TIMEOUT)
                    .await
            }
        };
        result
            .map(|(code, _)| code)
            .map_err(|_| "node_test_execution_failed".into())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run(
        &self,
        sb: &DockerSandbox,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
        class: crate::audit::poc_oracle::OracleClass,
    ) -> Result<(i64, String), String> {
        let mut files = vec![("runner.py", runner), ("sink.mjs", adapter)];
        files.extend_from_slice(node_assets_for(class));
        self.run_files(sb, tree, &files, input).await
    }

    pub(crate) async fn run_regression(
        &self,
        sb: &DockerSandbox,
        tree: &Path,
        runner: &str,
        source: &str,
        input: &str,
    ) -> Result<(i64, String), String> {
        self.run_files(
            sb,
            tree,
            &[("runner.py", runner), ("sink.mjs", source)],
            input,
        )
        .await
    }

    async fn run_files(
        &self,
        sb: &DockerSandbox,
        tree: &Path,
        files: &[(&str, &str)],
        input: &str,
    ) -> Result<(i64, String), String> {
        let input = runner_envelope(input, self.fixture.as_ref());
        let cmd = crate::audit::poc_oracle::runner_command();
        let timeout = crate::audit::poc::POC_TIMEOUT;
        let result = match &self.installed {
            Some(deps) => {
                sb.run_workspace_with_tree_and_deps(
                    files,
                    tree,
                    &deps.path,
                    &cmd,
                    Some(&input),
                    timeout,
                )
                .await
            }
            None => {
                sb.run_workspace_with_tree(files, tree, &cmd, Some(&input), timeout)
                    .await
            }
        };
        // Docker errors may include child output: never expose them with a fixture.
        result.map_err(|error| {
            if self.fixture.is_some() {
                "incomplete_sandbox_capture".into()
            } else {
                error
            }
        })
    }
}

/// Node-only stdin: decimal marker byte length, LF, marker bytes, decimal
/// fixture byte length, LF, canonical UTF-8 JSON (zero bytes means no fixture).
/// Neither secret is rendered into a file, argv, or the runner environment.
pub(crate) fn runner_envelope(marker: &str, fixture: Option<&fixture::NodeFixture>) -> String {
    let marker = marker.trim_end_matches('\n');
    let fixture = fixture.map_or("", |value| {
        std::str::from_utf8(value.canonical_json()).expect("validated fixture is UTF-8")
    });
    format!("{}\n{}{}\n{}", marker.len(), marker, fixture.len(), fixture)
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;
