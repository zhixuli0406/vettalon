//! Docker-CLI sandbox for PoC scripts.
//!
//! Hard rule: a PoC never runs on the host. Every path that cannot get a
//! real, isolated container returns `Err`, and the caller records the PoC as
//! skipped. The container gets no network, a read-only root filesystem, no
//! Linux capabilities, `no-new-privileges`, a non-root uid, memory/pid/CPU
//! caps. Direct model-generated scripts are streamed over stdin and never
//! written to a host scratch directory or bind-mounted into the container.
//! Harness-authored multi-file checks use fresh temporary copies mounted
//! read-only; the user's original tree is never mounted directly. The sole
//! networked exception installs validated npm inputs without running scripts;
//! only its private dependency output is writable.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{Mutex, OnceCell};

/// Default image: small, has `python3` and `bash`. Never pulled
/// automatically (pulling needs the network); the operator runs
/// `docker pull` once.
pub const DEFAULT_POC_IMAGE: &str = "python:3.12-slim";
/// Locally built Node image for JS/TS execution proof. Never pulled
/// automatically; run `vettalon poc-node build` before use.
pub fn default_node_poc_image() -> &'static str {
    crate::llm::container::poc_node_image()
}
/// Start of the error a container run returns when it hit the host-side
/// hard timeout (and was killed). Callers match on it to tell a hanging
/// target from a backend failure.
pub const EXECUTION_TIMEOUT_PREFIX: &str = "container execution exceeded the ";

/// Label on every PoC container, used to clean up leftovers.
const POC_LABEL: &str = "vettalon.poc=1";
/// Label key holding the pid of the vettalon process that started the
/// container. Leftover cleanup only removes containers whose owner is gone:
/// several PoCs can run at once (a hunt audits dependencies in parallel, a
/// dashboard scan can run next to a CLI one), and one run must never remove
/// another's live container.
const POC_OWNER_KEY: &str = "vettalon.poc.owner";
/// `timeout` inside the container: a little over the host-side limit.
const IN_CONTAINER_LIMIT_SECS: &str = "125";

/// What runs as PID 1 inside a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pid1 {
    /// coreutils `timeout -s KILL 125` is PID 1 and runs `cmd` as its child
    /// (direct PoC scripts, test commands in a tree copy).
    Timeout,
    /// `cmd` itself is PID 1 and enforces its own in-container hard limit.
    /// Used for the harness runner (`poc_oracle::runner_source`), which makes
    /// itself non-dumpable before any checked code starts: wrapping it in
    /// `timeout` would leave a dumpable, same-uid PID 1 that checked code
    /// could ptrace where the host allows it, and exec-ing through `timeout`
    /// would reset the dumpable flag. `--init=false` keeps a daemon-default
    /// init process from becoming PID 1 instead. The host-side timeout and
    /// the container guard stay the outer bound.
    Command,
}
/// Cap on any single `docker` housekeeping call.
const DOCKER_CALL_LIMIT: Duration = Duration::from_secs(30);

/// Combined stdout+stderr cap kept from one PoC run.
const OUTPUT_CAP_BYTES: usize = 64 * 1024;
const METADATA_CAP_BYTES: usize = 16 * 1024;
const CLIENT_REAP_LIMIT: Duration = Duration::from_secs(1);

const NODE_INSTALL_LIMIT: Duration = Duration::from_secs(300);
const NODE_INSTALL_FAILED: &str = "node_deps_install_failed";
const NODE_DEPS_MOUNT: &str = "/workspace/tree/node_modules";
const NODE_INSTALL_ENV: &[&str] = &[
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "HOME=/tmp",
    "npm_config_userconfig=/tmp/npmrc-user",
    "npm_config_globalconfig=/tmp/npmrc-global",
    "npm_config_registry=https://registry.npmjs.org/",
    "npm_config_cache=/tmp/npm-cache",
    "npm_config_ignore_scripts=true",
    "npm_config_audit=false",
    "npm_config_fund=false",
    "npm_config_update_notifier=false",
];
// Only trusted harness commands run while networking is enabled. Install on
// bounded tmpfs first; the host remains authoritative when importing output.
const NODE_INSTALL_TOO_LARGE_EXIT: i64 = 86;
const NODE_INSTALL_TMPFS_BYTES: u64 = crate::audit::node::deps::MAX_BYTES + 64 * 1024 * 1024;
const NODE_INSTALL_TMPFS_INODES: u32 = crate::audit::node::deps::MAX_ENTRIES + 1_000;

/// Only Node install inputs use this in-memory transport. Private manifests
/// never enter host scratch or mounts (uid 65534 cannot read host 0600 binds).
fn node_install_input(package_json: &[u8], lockfile: &[u8]) -> Result<String, &'static str> {
    let manifest = std::str::from_utf8(package_json).map_err(|_| NODE_INSTALL_FAILED)?;
    let lock = std::str::from_utf8(lockfile).map_err(|_| NODE_INSTALL_FAILED)?;
    Ok(format!(
        "{}\n{}{}\n{}",
        manifest.len(),
        manifest,
        lock.len(),
        lock
    ))
}

// Run as uid 65534 on private /work tmpfs, under umask 077. Read both frames
// and EOF before writing anything; fixed names and O_EXCL prevent substitution.
const NODE_INSTALL_STAGE: &str = r#"import os, sys
os.umask(0o077)
os.chmod(".", 0o700)
def frame(cap):
    header = sys.stdin.buffer.readline(12)
    if not header.endswith(b"\n") or not header[:-1].isdigit():
        raise ValueError("invalid install envelope")
    size = int(header)
    if size > cap:
        raise ValueError("invalid install envelope")
    data = sys.stdin.buffer.read(size)
    if len(data) != size:
        raise ValueError("invalid install envelope")
    return data
try:
    manifest = frame(1048576)
    lock = frame(33554432)
    if sys.stdin.buffer.read(1):
        raise ValueError("trailing input")
    for name, data in (("package.json", manifest), ("package-lock.json", lock)):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
except Exception:
    sys.exit(1)
"#;

fn node_install_command() -> String {
    use crate::audit::node::deps::{MAX_BYTES, MAX_ENTRIES, MAX_FILES};
    // Count constant markers rather than filenames (which may contain newlines).
    // Check each producer before consuming its output; /work includes inputs and
    // directory metadata, so this pre-check is conservative relative to the host.
    format!(
        concat!(
            "umask 077; : > /tmp/npmrc-user; : > /tmp/npmrc-global; ",
            "python3 -I -B -c '{stage}' && cd /work && ",
            "npm ci --ignore-scripts --no-audit --no-fund --bin-links=false --prefer-online; ",
            "status=$?; [ \"$status\" -eq 0 ] || exit \"$status\"; ",
            "find /work -xdev -printf '.' > /tmp/install-entries || exit 1; ",
            "entries=$(wc -c < /tmp/install-entries) || exit 1; ",
            "find /work -xdev -type f -printf '.' > /tmp/install-files || exit 1; ",
            "files=$(wc -c < /tmp/install-files) || exit 1; ",
            "du -sbl /work > /tmp/install-bytes || exit 1; ",
            "read -r bytes path < /tmp/install-bytes || exit 1; ",
            "[ \"$entries\" -le {} ] && [ \"$files\" -le {} ] && ",
            "[ \"$bytes\" -le {} ] || exit {}; ",
            "cp -RP /work/node_modules /deps/ && ",
            "find /deps -mindepth 1 -type d -exec chmod 0777 {{}} + && ",
            "find /deps -mindepth 1 -type f -exec chmod 0644 {{}} + || exit 1"
        ),
        MAX_ENTRIES,
        MAX_FILES,
        MAX_BYTES,
        NODE_INSTALL_TOO_LARGE_EXIT,
        stage = NODE_INSTALL_STAGE,
    )
}

/// Keep the private, normalized dependency tree alive across all offline
/// phases. No target path or mutable caller-owned install output is retained.
#[derive(Debug)]
#[allow(dead_code)] // D9 consumes the installation result.
pub(crate) struct InstalledDependencies {
    _dir: tempfile::TempDir,
    pub path: std::path::PathBuf,
    pub digest: crate::audit::node::deps::DependencyDigest,
    pub lockfile: crate::audit::node::lockfile::LockfileSummary,
}

#[derive(Debug, Clone)]
pub struct DockerSandbox {
    pub docker_bin: String,
    /// Immutable `sha256:` image ID after successful detection. Keeping the
    /// resolved ID prevents a mutable tag from changing within one operation.
    pub image: String,
}

/// One operation's successful Docker preflight, shared across its PoCs.
///
/// This caches metadata only. Every execution still creates a new container;
/// no guest process, filesystem, or output is reused. Construct a new session
/// for a later scan or another image. Failed probes are not cached.
#[derive(Debug, Default)]
pub struct SandboxSession {
    requested_image: Mutex<Option<String>>,
    ready: OnceCell<DockerSandbox>,
    // Private injection seam: production always discovers the trusted CLI.
    docker_bin: Option<String>,
}

impl SandboxSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn sandbox(&self, image: &str) -> Result<DockerSandbox, String> {
        validate_image_name(image)?;
        {
            let mut requested = self.requested_image.lock().await;
            match requested.as_deref() {
                Some(bound) if bound != image => {
                    return Err(
                        "sandbox session is bound to another image; create a new session".into(),
                    );
                }
                None => *requested = Some(image.to_owned()),
                _ => {}
            }
        }
        self.ready
            .get_or_try_init(|| async {
                match self.docker_bin.as_deref() {
                    Some(bin) => {
                        DockerSandbox::detect_with_bin(image, bin, DOCKER_CALL_LIMIT).await
                    }
                    None => DockerSandbox::detect(image).await,
                }
            })
            .await
            .cloned()
    }
}

impl DockerSandbox {
    /// Check the daemon and bind the requested tag to its local immutable ID.
    /// The complete probe, including leftover cleanup, has one finite budget.
    pub async fn detect(image: &str) -> Result<Self, String> {
        validate_image_name(image)?;
        let docker_bin = crate::util::which_cli("docker")
            .ok_or_else(|| "docker CLI not found on PATH".to_string())?;
        Self::detect_with_bin(image, &docker_bin, DOCKER_CALL_LIMIT).await
    }

    async fn detect_with_bin(
        image: &str,
        docker_bin: &str,
        limit: Duration,
    ) -> Result<Self, String> {
        validate_image_name(image)?;
        let docker_bin = std::fs::canonicalize(docker_bin)
            .map_err(|e| format!("cannot resolve docker CLI: {e}"))?
            .to_str()
            .ok_or_else(|| "docker CLI path is not valid UTF-8".to_string())?
            .to_string();
        let probe = async {
            let ping =
                docker_metadata(&docker_bin, &["version", "--format", "{{.Server.Version}}"])
                    .await?;
            if !ping.status.success() || ping.stdout.trim().is_empty() {
                return Err("docker daemon is not reachable".to_string());
            }
            let inspect = docker_metadata(
                &docker_bin,
                &["image", "inspect", "--format", "{{.Id}}", image],
            )
            .await?;
            if !inspect.status.success() {
                return Err(format!(
                    "sandbox image {image} is not present locally (run `docker pull {image}` once)"
                ));
            }
            let resolved = inspect.stdout.trim();
            if !valid_image_id(resolved) {
                return Err(
                    "docker image inspect did not return one immutable sha256 image ID".into(),
                );
            }
            let sb = Self {
                docker_bin,
                image: resolved.to_owned(),
            };
            sb.remove_leftovers().await?;
            Ok(sb)
        };
        tokio::time::timeout(limit, probe)
            .await
            .map_err(|_| "docker preflight exceeded its hard timeout".to_string())?
    }

    /// Remove only containers whose owning process no longer exists. Our own
    /// process can have multiple concurrent operations; never sweep its runs.
    async fn remove_leftovers(&self) -> Result<(), String> {
        let list = docker_metadata(
            &self.docker_bin,
            &[
                "ps",
                "-a",
                "--filter",
                &format!("label={POC_LABEL}"),
                "--format",
                &format!("{{{{.ID}}}} {{{{.Label \"{POC_OWNER_KEY}\"}}}}"),
            ],
        )
        .await?;
        if !list.status.success() {
            return Err("sandbox leftover inventory could not be read".into());
        }
        let me = std::process::id();
        for (id, owner) in parse_poc_listing(&list.stdout) {
            let alive = match owner {
                Some(pid) if pid != me => process_alive(pid).await,
                _ => false,
            };
            if is_leftover(owner, me, alive) {
                self.force_remove(&id).await?;
            }
        }
        Ok(())
    }

    /// Removal plus a successful daemon inventory proves this exact container
    /// is absent. A lost connection or an ambiguous client exit proves nothing.
    async fn force_remove(&self, name: &str) -> Result<(), String> {
        confirm_container_removed(&self.docker_bin, name).await
    }

    /// The unmounted `docker run` argument vector for a direct PoC. Pure, so
    /// the isolation flags and absence of host mounts are unit-tested.
    pub fn run_args(&self, name: &str, cmd: &[String]) -> Vec<String> {
        self.build_run_args(name, &[], "/tmp", true, Pid1::Timeout, cmd)
    }

    /// Build an invocation with explicit read-only mounts. Only harness-owned
    /// scratch data or a prepared temporary copy of the scanned tree may be
    /// passed here.
    pub fn run_args_mounted(
        &self,
        name: &str,
        mounts: &[(&Path, &str)],
        workdir: &str,
        cmd: &[String],
    ) -> Vec<String> {
        self.build_run_args(name, mounts, workdir, false, Pid1::Timeout, cmd)
    }

    /// Pure argv builder for the sole networked container. Validated manifest
    /// bytes arrive on stdin; `output` is a fresh private directory.
    pub(crate) fn install_run_args(
        &self,
        name: &str,
        output: &Path,
    ) -> Result<Vec<String>, &'static str> {
        if !output.is_absolute() || output.to_str().is_none_or(|s| s.contains([',', '\0'])) {
            return Err(NODE_INSTALL_FAILED);
        }
        let mut args: Vec<String> = [
            "run",
            "--rm",
            "--interactive",
            "--name",
            name,
            "--label",
            POC_LABEL,
            "--label",
            &format!("{POC_OWNER_KEY}={}", std::process::id()),
            "--pull=never",
            "--network=bridge",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m",
            "--tmpfs",
            &format!(
                "/work:rw,nosuid,nodev,noexec,size={NODE_INSTALL_TMPFS_BYTES},nr_inodes={NODE_INSTALL_TMPFS_INODES},mode=0700,uid=65534,gid=65534"
            ),
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            "65534:65534",
            "--pids-limit=128",
            "--memory=1792m",
            "--memory-swap=1792m",
            "--cpus=2",
            "--ulimit",
            "nofile=256:256",
            "--ulimit",
            "fsize=67108864:67108864",
            "--workdir",
            "/work",
            "--init=false",
            // Bypass image entrypoints and discard image-provided env too.
            "--entrypoint",
            "/usr/bin/env",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        for env in NODE_INSTALL_ENV {
            args.extend(["--env".into(), (*env).into()]);
        }
        args.extend([
            "--mount".into(),
            format!("type=bind,source={},target=/deps", output.display()),
            self.image.clone(),
            "-i".into(),
        ]);
        args.extend(NODE_INSTALL_ENV.iter().map(|s| (*s).into()));
        args.extend(
            [
                "timeout",
                "-s",
                "KILL",
                "300",
                "/bin/sh",
                "-c",
                &node_install_command(),
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        Ok(args)
    }

    /// Validate the exact bytes being staged, install once, then import and
    /// digest the stopped container's output. A caller-supplied summary alone
    /// cannot authorize network fetches. Shrinkwrap bytes may be passed as the
    /// lockfile; the private input always uses the name `package-lock.json`.
    /// No dependencies returns `None` without invoking Docker. All npm/runner
    /// failures are environment blockers, never an observed target verdict.
    #[allow(dead_code)] // CLI orchestration is D9.
    pub(crate) async fn run_install(
        &self,
        package_json: &[u8],
        lockfile: &[u8],
    ) -> Result<Option<InstalledDependencies>, &'static str> {
        use crate::audit::node::{deps, lockfile::validate_install_inputs};
        let summary =
            validate_install_inputs(package_json, lockfile).map_err(|_| "node_lockfile_refused")?;
        // npm ci may resolve missing manifest edges before reporting an
        // out-of-sync lock. Require matching root maps before enabling network.
        let manifest: serde_json::Value =
            serde_json::from_slice(package_json).map_err(|_| "node_lockfile_refused")?;
        let locked: serde_json::Value =
            serde_json::from_slice(lockfile).map_err(|_| "node_lockfile_refused")?;
        for key in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
            "peerDependenciesMeta",
        ] {
            let empty = serde_json::json!({});
            if manifest.get(key).unwrap_or(&empty)
                != locked["packages"][""].get(key).unwrap_or(&empty)
            {
                return Err("node_lockfile_refused");
            }
        }
        if !summary.needs_install() {
            return Ok(None);
        }
        let input = node_install_input(package_json, lockfile)?;
        let output = tempfile::Builder::new()
            .prefix("vettalon-node-install-")
            .tempdir()
            .map_err(|_| NODE_INSTALL_FAILED)?;
        let output_path = output.path().join("deps");
        std::fs::create_dir(&output_path).map_err(|_| NODE_INSTALL_FAILED)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o700))
                .map_err(|_| NODE_INSTALL_FAILED)?;
            std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o733))
                .map_err(|_| NODE_INSTALL_FAILED)?;
        }
        let name = format!("vettalon-poc-{}", uuid::Uuid::new_v4().simple());
        let args = self.install_run_args(&name, &output_path)?;
        // Preserve the output scratch and any caller's cleanup hold if
        // cancellation hands removal to the existing container guard.
        let prior = CLEANUP_HOLD.try_with(Clone::clone).ok();
        let hold: CleanupHold = std::sync::Arc::new((output, prior));
        let (code, _) = with_cleanup_hold(
            hold.clone(),
            self.run_container(&name, &args, Some(&input), NODE_INSTALL_LIMIT),
        )
        .await
        .map_err(|_| NODE_INSTALL_FAILED)?;
        if code == NODE_INSTALL_TOO_LARGE_EXIT {
            return Err("node_deps_too_large");
        }
        if code != 0 {
            return Err(NODE_INSTALL_FAILED);
        }
        let dir = tempfile::Builder::new()
            .prefix("vettalon-node-deps-")
            .tempdir()
            .map_err(|_| NODE_INSTALL_FAILED)?;
        let path = dir.path().join("node_modules");
        let digest =
            deps::copy_and_digest(&output_path.join("node_modules"), &path).map_err(|reason| {
                if reason == "node_deps_too_large" {
                    reason
                } else {
                    NODE_INSTALL_FAILED
                }
            })?;
        Ok(Some(InstalledDependencies {
            _dir: dir,
            path,
            digest,
            lockfile: summary,
        }))
    }

    fn build_run_args(
        &self,
        name: &str,
        mounts: &[(&Path, &str)],
        workdir: &str,
        interactive: bool,
        pid1: Pid1,
        cmd: &[String],
    ) -> Vec<String> {
        let owner_label = format!("{POC_OWNER_KEY}={}", std::process::id());
        let mut args: Vec<String> = [
            "run",
            "--rm",
            "--name",
            name,
            "--label",
            POC_LABEL,
            "--label",
            &owner_label,
            "--pull=never",
            "--network=none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            "65534:65534",
            "--pids-limit=128",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=1",
            "--ulimit",
            "nofile=256:256",
            "--ulimit",
            "fsize=67108864:67108864",
            "--env",
            "HOME=/tmp",
            "--workdir",
            workdir,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if interactive {
            args.insert(2, "-i".to_string());
        }
        for (source, target) in mounts {
            args.push("--mount".to_string());
            args.push(format!(
                "type=bind,source={},target={target},readonly",
                source.display()
            ));
        }
        match pid1 {
            Pid1::Timeout => {
                args.push(self.image.clone());
                // In-container hard limit too, so the PoC dies even if
                // vettalon is killed before its own timeout fires.
                args.extend(
                    ["timeout", "-s", "KILL", IN_CONTAINER_LIMIT_SECS]
                        .iter()
                        .map(|s| s.to_string()),
                );
            }
            Pid1::Command => {
                // `cmd` is PID 1 and carries its own hard limit; no init.
                args.push("--init=false".to_string());
                args.push(self.image.clone());
            }
        }
        args.extend(cmd.iter().cloned());
        args
    }

    /// Run `script` (`"python"` or `"bash"`) with a hard `timeout`. Returns
    /// `(exit_code, combined_output)`. A timeout force-removes the container.
    pub async fn run_script(
        &self,
        script: &str,
        language: &str,
        timeout: Duration,
    ) -> Result<(i64, String), String> {
        let cmd = script_command(language)?;
        let name = format!("vettalon-poc-{}", uuid::Uuid::new_v4().simple());
        let args = self.run_args(&name, &cmd);
        self.run_container(&name, &args, Some(script), timeout)
            .await
    }

    /// Run a multi-file workspace: each `(name, contents)` pair is written into
    /// a fresh scratch dir mounted read-only at `/workspace`, then `cmd` runs
    /// inside the same isolated container as [`run_script`]. The PoC-oracle
    /// harness uses this to mount a harness-authored runner next to the
    /// model-authored PoC. Same isolation, same hard `timeout`, same host rule:
    /// any failure to get a real container returns `Err`.
    ///
    /// `input`, when given, is streamed to the command's stdin and never
    /// written to a file: the oracle passes its per-run verdict marker this
    /// way so it is not on disk where checked code could read it.
    ///
    /// `cmd` runs as PID 1 with no `timeout` wrapper (see `Pid1::Command`),
    /// so it must enforce its own in-container hard limit, as the harness
    /// runner does. The host-side `timeout` still applies.
    pub async fn run_workspace(
        &self,
        files: &[(&str, &str)],
        cmd: &[String],
        input: Option<&str>,
        timeout: Duration,
    ) -> Result<(i64, String), String> {
        let scratch = write_scratch(files, false)?;
        self.run_mounted(
            &[(scratch.path(), "/workspace")],
            "/tmp",
            Pid1::Command,
            cmd,
            input,
            timeout,
        )
        .await
    }

    /// O19: [`run_workspace`](Self::run_workspace) plus a prepared directory
    /// (a temporary copy of the scanned tree, never the user's own files)
    /// mounted read-only at `/workspace/tree`. Same isolation, same timeout,
    /// same stdin `input` handling, and `cmd` is likewise PID 1 and must
    /// enforce its own in-container hard limit.
    pub async fn run_workspace_with_tree(
        &self,
        files: &[(&str, &str)],
        tree: &Path,
        cmd: &[String],
        input: Option<&str>,
        timeout: Duration,
    ) -> Result<(i64, String), String> {
        let scratch = write_scratch(files, true)?;
        self.run_mounted(
            &[(scratch.path(), "/workspace"), (tree, "/workspace/tree")],
            "/tmp",
            Pid1::Command,
            cmd,
            input,
            timeout,
        )
        .await
    }

    /// Node offline phase: the prepared tree already has an empty, stable
    /// `node_modules` mountpoint. All three mounts remain read-only; deps are
    /// shared from one installation for every replay and both fix-check trees.
    #[allow(dead_code)] // CLI orchestration is D9.
    pub(crate) async fn run_workspace_with_tree_and_deps(
        &self,
        files: &[(&str, &str)],
        tree: &Path,
        deps: &Path,
        cmd: &[String],
        input: Option<&str>,
        timeout: Duration,
    ) -> Result<(i64, String), String> {
        let scratch = write_scratch(files, true)?;
        self.run_mounted(
            &[
                (scratch.path(), "/workspace"),
                (tree, "/workspace/tree"),
                (deps, NODE_DEPS_MOUNT),
            ],
            "/tmp",
            Pid1::Command,
            cmd,
            input,
            timeout,
        )
        .await
    }

    /// O19: run `cmd` with a prepared directory (a temporary copy of the
    /// scanned tree) mounted read-only at `/workspace` as the working
    /// directory. Same isolation, same timeout: only `/tmp` is writable.
    pub async fn run_in_tree(
        &self,
        tree: &Path,
        cmd: &[String],
        timeout: Duration,
    ) -> Result<(i64, String), String> {
        self.run_mounted(
            &[(tree, "/workspace")],
            "/workspace",
            Pid1::Timeout,
            cmd,
            None,
            timeout,
        )
        .await
    }

    async fn run_mounted(
        &self,
        mounts: &[(&Path, &str)],
        workdir: &str,
        pid1: Pid1,
        cmd: &[String],
        input: Option<&str>,
        timeout: Duration,
    ) -> Result<(i64, String), String> {
        // `--mount` is comma-separated key=value: a source path holding a
        // comma could smuggle extra mount options.
        if let Some((bad, _)) = mounts
            .iter()
            .find(|(p, _)| p.to_string_lossy().contains(','))
        {
            return Err(format!("unsupported mount path {}", bad.display()));
        }
        let name = format!("vettalon-poc-{}", uuid::Uuid::new_v4().simple());
        let args = self.build_run_args(&name, mounts, workdir, input.is_some(), pid1, cmd);
        self.run_container(&name, &args, input, timeout).await
    }

    async fn run_container(
        &self,
        name: &str,
        args: &[String],
        input: Option<&str>,
        timeout: Duration,
    ) -> Result<(i64, String), String> {
        let mut child = Command::new(&self.docker_bin)
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("container create failed: {e}"))?;

        // If this future is dropped mid-run (the scan was cancelled), killing
        // the `docker run` client does not stop the container; the guard
        // removes it. Only a successful daemon absence check disarms it.
        let mut guard = ContainerGuard::new(&self.docker_bin, name);

        let mut stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let collect = async {
            let write = async {
                if let Some(data) = input {
                    let mut pipe = stdin
                        .take()
                        .ok_or_else(|| std::io::Error::other("missing container stdin"))?;
                    pipe.write_all(data.as_bytes()).await?;
                    drop(pipe);
                }
                Ok::<(), std::io::Error>(())
            };
            let (write, out, err) = tokio::join!(
                write,
                crate::util::read_capped(stdout, OUTPUT_CAP_BYTES),
                crate::util::read_capped(stderr, OUTPUT_CAP_BYTES)
            );
            let status = child.wait().await;
            (write, status, out, err)
        };
        let collected = tokio::time::timeout(timeout, collect).await;
        let execution = match collected {
            Ok((Ok(()), Ok(status), out, err)) => {
                complete_output(out, err).and_then(|combined| match status.code() {
                    Some(c) if is_docker_failure(c, &combined) => Err(format!(
                        "container start failed (docker exit {c}): {}",
                        crate::util::truncate_bytes(combined.trim(), 300)
                    )),
                    Some(c) => Ok((c as i64, combined)),
                    None => Err("container terminated by a signal".to_string()),
                })
            }
            Ok((Err(error), _, _, _)) => Err(format!("cannot stream PoC script: {error}")),
            Ok((_, Err(error), _, _)) => Err(format!("container wait failed: {error}")),
            Err(_) => {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(CLIENT_REAP_LIMIT, child.wait()).await;
                Err(format!(
                    "{EXECUTION_TIMEOUT_PREFIX}{}ms hard timeout",
                    timeout.as_millis()
                ))
            }
        };
        let cleanup = if execution.is_ok() {
            // `--rm` normally removed the container already. A successful
            // empty daemon inventory is sufficient; avoid a redundant rm.
            match container_is_absent(&self.docker_bin, name).await {
                Ok(true) => Ok(()),
                Ok(false) | Err(_) => self.force_remove(name).await,
            }
        } else {
            self.force_remove(name).await
        };
        if cleanup.is_ok() {
            guard.disarm();
        }
        match (execution, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(format!("sandbox cleanup unconfirmed: {cleanup}")),
            (Err(error), Err(cleanup)) => {
                Err(format!("{error}; sandbox cleanup unconfirmed: {cleanup}"))
            }
        }
    }
}

fn validate_image_name(image: &str) -> Result<(), String> {
    if image.is_empty()
        || image.starts_with('-')
        || image.chars().any(char::is_whitespace)
        || image.chars().any(char::is_control)
    {
        return Err("invalid sandbox image name".into());
    }
    Ok(())
}

fn valid_image_id(image: &str) -> bool {
    image
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

type CapturedBytes = std::io::Result<(Vec<u8>, bool)>;

fn complete_output(stdout: CapturedBytes, stderr: CapturedBytes) -> Result<String, String> {
    let (out, out_truncated) = stdout.map_err(|e| format!("stdout capture failed: {e}"))?;
    let (err, err_truncated) = stderr.map_err(|e| format!("stderr capture failed: {e}"))?;
    if out_truncated || err_truncated || out.len().saturating_add(err.len()) > OUTPUT_CAP_BYTES {
        return Err(format!(
            "container output capture truncated (stdout_truncated={out_truncated}, stderr_truncated={err_truncated}, retained_bytes={})",
            out.len().saturating_add(err.len())
        ));
    }
    let mut combined =
        String::from_utf8(out).map_err(|_| "container stdout is not valid UTF-8".to_string())?;
    combined.push_str(
        &String::from_utf8(err).map_err(|_| "container stderr is not valid UTF-8".to_string())?,
    );
    Ok(combined)
}

struct DockerMetadata {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

/// The CLI is trusted machinery, not a PoC backend. Still bound both pipes,
/// lifetime, and reaping so a stalled daemon cannot hang preflight or cleanup.
async fn docker_metadata(docker_bin: &str, args: &[&str]) -> Result<DockerMetadata, String> {
    let mut child = Command::new(docker_bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("cannot run docker metadata command: {e}"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let capture = async {
        let (out, err) = tokio::join!(
            crate::util::read_capped(stdout, METADATA_CAP_BYTES),
            crate::util::read_capped(stderr, METADATA_CAP_BYTES),
        );
        let status = child
            .wait()
            .await
            .map_err(|e| format!("docker metadata wait failed: {e}"))?;
        let (out, out_truncated) =
            out.map_err(|e| format!("docker metadata stdout read failed: {e}"))?;
        let (err, err_truncated) =
            err.map_err(|e| format!("docker metadata stderr read failed: {e}"))?;
        if out_truncated || err_truncated {
            return Err("docker metadata output capture truncated".to_string());
        }
        Ok(DockerMetadata {
            status,
            stdout: String::from_utf8(out)
                .map_err(|_| "docker metadata stdout is not valid UTF-8".to_string())?,
            stderr: String::from_utf8(err)
                .map_err(|_| "docker metadata stderr is not valid UTF-8".to_string())?,
        })
    };
    match tokio::time::timeout(DOCKER_CALL_LIMIT, capture).await {
        Ok(result) => result,
        Err(_) => {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(CLIENT_REAP_LIMIT, child.wait()).await;
            Err("docker metadata command exceeded its hard timeout".into())
        }
    }
}

/// A successful empty inventory is an observation of absence at this
/// instant. It does not prove that an earlier cancelled create cannot finish
/// later; cancellation therefore never returns a successful proof receipt.
async fn container_is_absent(docker_bin: &str, name: &str) -> Result<bool, String> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid cleanup container identity".into());
    }
    let selector = if name.starts_with("vettalon-poc-") {
        format!("name=^/{name}$")
    } else {
        format!("id={name}")
    };
    let inventory = docker_metadata(docker_bin, &["ps", "-aq", "--filter", &selector]).await?;
    if !inventory.status.success() {
        return Err("docker cleanup inventory failed".into());
    }
    Ok(inventory.stdout.trim().is_empty())
}

async fn confirm_container_removed(docker_bin: &str, name: &str) -> Result<(), String> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("invalid cleanup container identity".into());
    }
    let cleanup = async {
        let removed = docker_metadata(docker_bin, &["rm", "-f", name]).await?;
        let already_absent = (removed.stderr.contains("No such container")
            || removed.stderr.contains("No such object"))
            && removed.stderr.contains(name);
        if !removed.status.success() && !already_absent {
            return Err("docker container removal failed".into());
        }
        if !container_is_absent(docker_bin, name).await? {
            return Err("container remains after removal".into());
        }
        Ok(())
    };
    tokio::time::timeout(DOCKER_CALL_LIMIT, cleanup)
        .await
        .map_err(|_| "docker cleanup exceeded its hard timeout".to_string())?
}

/// Write each `(name, contents)` pair into a fresh, world-readable scratch
/// dir. With `tree_mountpoint`, also create an empty `tree/` directory so a
/// read-only bind mount can be placed on it.
fn write_scratch(
    files: &[(&str, &str)],
    tree_mountpoint: bool,
) -> Result<tempfile::TempDir, String> {
    let scratch = tempfile::Builder::new()
        .prefix("vettalon-poc-")
        .tempdir()
        .map_err(|e| format!("cannot create temp workspace: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o755));
    }
    for (name, contents) in files {
        // Files are harness/model PoC text only; a bare basename is all the
        // caller ever passes. Refuse anything with a separator so a crafted
        // name can never escape the scratch dir (`tree` is the mountpoint).
        if name.contains('/') || name.contains('\\') || name.is_empty() || *name == "tree" {
            return Err(format!("invalid workspace file name {name:?}"));
        }
        let path = scratch.path().join(name);
        std::fs::write(&path, contents).map_err(|e| format!("cannot write poc file: {e}"))?;
        // The container runs as nobody; the mounted dir and files must be
        // world-readable (they hold only generated PoC text).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        }
    }
    if tree_mountpoint {
        let dir = scratch.path().join("tree");
        std::fs::create_dir(&dir).map_err(|e| format!("cannot create tree mountpoint: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        }
    }
    Ok(scratch)
}

fn script_command(language: &str) -> Result<Vec<String>, String> {
    match language {
        "python" => Ok(vec!["python3".into(), "-".into()]),
        "bash" => Ok(vec!["bash".into(), "-s".into()]),
        other => Err(format!("unsupported PoC language {other:?}")),
    }
}

/// A value an operation keeps alive until every container it started has
/// finished its removal, including removal that a cancelled run hands to a
/// background thread. See [`with_cleanup_hold`].
pub type CleanupHold = std::sync::Arc<dyn std::any::Any + Send + Sync>;

tokio::task_local! {
    static CLEANUP_HOLD: CleanupHold;
}

/// Run `future` so that every container it starts keeps a clone of `hold`
/// until that container's removal has returned, also when `future` is dropped
/// mid-run (for example a client disconnect) and the removal continues on a
/// background thread. Whatever `hold` guards (such as a concurrency slot) is
/// therefore released only after the last such removal ends, so a
/// cancel-and-retry loop cannot keep several containers alive at once.
/// Containers started from tasks spawned inside `future` are not covered.
pub async fn with_cleanup_hold<F: std::future::Future>(hold: CleanupHold, future: F) -> F::Output {
    CLEANUP_HOLD.scope(hold, future).await
}

/// Removes a PoC container when dropped while still armed, i.e. when the run
/// that owns it was cancelled before the container exited. `Drop` cannot
/// await, so a detached thread performs bounded removal and confirmation.
/// Cancellation never returns a successful proof receipt.
struct ContainerGuard {
    docker_bin: String,
    name: String,
    armed: bool,
    /// The [`with_cleanup_hold`] value in scope when the container was
    /// started, kept until the container's removal has returned.
    hold: Option<CleanupHold>,
}

impl ContainerGuard {
    fn new(docker_bin: &str, name: &str) -> Self {
        ContainerGuard {
            docker_bin: docker_bin.to_string(),
            name: name.to_string(),
            armed: true,
            hold: CLEANUP_HOLD.try_with(CleanupHold::clone).ok(),
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let docker_bin = self.docker_bin.clone();
        let name = self.name.clone();
        // Moved into the thread: the operation's hold (e.g. a request slot)
        // stays taken until the removal below has returned.
        let hold = self.hold.take();
        // No successful execution receipt is returned on cancellation. This
        // bounded cleanup is best effort and reports its independent failure.
        let spawned = std::thread::Builder::new()
            .name("vettalon-poc-cleanup".into())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("cannot start cleanup runtime: {e}"))
                    .and_then(|runtime| {
                        runtime.block_on(confirm_container_removed(&docker_bin, &name))
                    });
                if let Err(error) = result {
                    eprintln!("sandbox cancellation cleanup unconfirmed: {error}");
                }
                drop(hold);
            });
        if spawned.is_err() {
            eprintln!("sandbox cancellation cleanup could not start");
        }
    }
}

/// `docker run` exits 125 when docker itself fails, and 126/127 when the
/// container command cannot be run. The container's own command can exit
/// with any of these codes too (`os._exit(125)`, a shell's "not executable"
/// / "command not found"), so each counts as docker's only when docker's own
/// error text is present; otherwise it is the target's ordinary exit.
fn is_docker_failure(code: i32, output: &str) -> bool {
    match code {
        125 => {
            output.trim_start().starts_with("docker:")
                || output.contains("Error response from daemon")
                || output.contains("OCI runtime")
                || output.contains("'docker run --help'")
        }
        126 | 127 => {
            output.contains("OCI runtime")
                || output.contains("docker: Error response from daemon")
                || output.contains("executable file not found in $PATH")
        }
        _ => false,
    }
}

/// `<id> <owner pid>` lines from `docker ps --format`. A missing or
/// malformed owner (a container made by an older vettalon) parses as `None`.
fn parse_poc_listing(listing: &str) -> Vec<(String, Option<u32>)> {
    listing
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let id = parts.next()?.to_string();
            let owner = parts.next().and_then(|p| p.parse().ok());
            Some((id, owner))
        })
        .collect()
}

/// Whether a PoC container is safe to remove. `owner_alive` is only
/// meaningful for another process's container.
fn is_leftover(owner: Option<u32>, me: u32, owner_alive: bool) -> bool {
    match owner {
        None => true,
        Some(pid) if pid == me => false,
        Some(_) => !owner_alive,
    }
}

/// Whether `pid` is a running process. `kill -0` sends no signal; "not
/// permitted" means it exists under another user. Where this cannot be
/// checked (non-Unix) the container is kept: its in-container `timeout`
/// plus `--rm` remove it on their own.
async fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return true;
        };
        if pid <= 1 {
            return true;
        }
        // SAFETY: signal 0 only checks existence/permission and never signals.
        let result = unsafe { libc::kill(pid, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("sandbox_node_tests.rs");

    #[test]
    fn default_node_poc_image_is_versioned_local_tag() {
        let image = default_node_poc_image();
        assert_eq!(image, crate::llm::container::poc_node_image());
        let tag = image.strip_prefix("vettalon-poc-node:").unwrap();
        assert_eq!(tag.len(), 12);
        assert!(
            tag.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert!(!image.contains('/'));
        assert!(!image.ends_with(":latest"));
    }

    #[cfg(unix)]
    struct FakeDocker {
        dir: tempfile::TempDir,
        bin: String,
    }

    #[cfg(unix)]
    impl FakeDocker {
        fn new(behavior: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("docker");
            let script = format!(
                "#!/bin/sh\ncd '{}' || exit 97\nprintf '%s\\n' \"$*\" >> calls\n{}\n",
                dir.path().display(),
                behavior
            );
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                bin: path.display().to_string(),
                dir,
            }
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("calls")).unwrap_or_default()
        }

        fn session(&self) -> SandboxSession {
            SandboxSession {
                docker_bin: Some(self.bin.clone()),
                ..SandboxSession::default()
            }
        }
    }

    #[cfg(unix)]
    const FAKE_DOCKER_OK: &str = r#"
case "$1" in
version) printf '29.0.0\n' ;;
image) printf 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' ;;
ps) ;;
rm) ;;
run) cat >/dev/null; printf 'proof-output\n' ;;
*) exit 99 ;;
esac
"#;

    #[cfg(unix)]
    #[tokio::test]
    async fn invalid_image_is_rejected_before_any_docker_command() {
        let fake = FakeDocker::new(FAKE_DOCKER_OK);
        for image in ["", " ", "-bad", "bad\nimage", "bad\timage", "bad\0image"] {
            let result =
                DockerSandbox::detect_with_bin(image, &fake.bin, Duration::from_secs(1)).await;
            assert!(
                result.unwrap_err().contains("invalid sandbox image"),
                "{image:?}"
            );
        }
        assert!(fake.calls().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_preflight_is_once_for_concurrent_callers_and_pins_image() {
        let fake = FakeDocker::new(FAKE_DOCKER_OK);
        let session = fake.session();
        let (left, right) = tokio::join!(
            session.sandbox("python:test"),
            session.sandbox("python:test")
        );
        let left = left.unwrap();
        let right = right.unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(left.image, digest);
        assert_eq!(right.image, digest);
        let calls = fake.calls();
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.starts_with("version "))
                .count(),
            1,
            "{calls}"
        );
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.starts_with("image inspect "))
                .count(),
            1,
            "{calls}"
        );
        assert!(
            session
                .sandbox("python:other")
                .await
                .unwrap_err()
                .contains("image")
        );
        assert_eq!(fake.calls(), calls);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_does_not_cache_a_failed_preflight_or_a_mutable_tag() {
        let fake = FakeDocker::new(
            r#"
case "$1" in
version) printf '29.0.0\n' ;;
image)
  if [ ! -f available ]; then exit 1; fi
  cat digest ;;
ps|rm) ;;
*) exit 99 ;;
esac
"#,
        );
        let session = fake.session();
        assert!(session.sandbox("python:test").await.is_err());
        std::fs::write(fake.dir.path().join("available"), "yes").unwrap();
        let first = format!("sha256:{}", "a".repeat(64));
        let second = format!("sha256:{}", "b".repeat(64));
        std::fs::write(fake.dir.path().join("digest"), &first).unwrap();
        assert_eq!(session.sandbox("python:test").await.unwrap().image, first);
        std::fs::write(fake.dir.path().join("digest"), &second).unwrap();
        assert_eq!(session.sandbox("python:test").await.unwrap().image, first);
        assert_eq!(
            fake.session().sandbox("python:test").await.unwrap().image,
            second
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn preflight_is_bounded_and_rejects_oversized_or_invalid_identity() {
        for behavior in [
            "exec sleep 5",
            "case \"$1\" in version) echo 29;; image) printf not-an-image-id;; esac",
            "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done",
        ] {
            let fake = FakeDocker::new(behavior);
            let started = std::time::Instant::now();
            assert!(
                DockerSandbox::detect_with_bin(
                    "python:test",
                    &fake.bin,
                    Duration::from_millis(100)
                )
                .await
                .is_err()
            );
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_runs_use_fresh_containers_and_confirm_cleanup() {
        let fake = FakeDocker::new(FAKE_DOCKER_OK);
        let sb = fake.session().sandbox("python:test").await.unwrap();
        for _ in 0..2 {
            assert_eq!(
                sb.run_script("print(1)", "python", Duration::from_secs(1))
                    .await
                    .unwrap(),
                (0, "proof-output\n".to_string())
            );
        }
        let calls = fake.calls();
        let names: Vec<_> = calls
            .lines()
            .filter(|line| line.starts_with("run "))
            .map(|line| {
                let args: Vec<_> = line.split_whitespace().collect();
                args[args.iter().position(|arg| *arg == "--name").unwrap() + 1]
            })
            .collect();
        assert_eq!(names.len(), 2, "{calls}");
        assert_ne!(names[0], names[1]);
        for name in names {
            assert!(
                !calls.contains(&format!("rm -f {name}")),
                "already absent containers need no removal: {calls}"
            );
            assert!(
                calls.contains(&format!("name=^/{name}$")),
                "missing daemon cleanup observation: {calls}"
            );
        }
        assert!(!calls.contains("exec "));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn completed_but_present_container_is_removed_and_rechecked() {
        let fake = FakeDocker::new(
            r#"
case "$1" in
run) cat >/dev/null; touch present; printf ok ;;
rm) rm -f present ;;
ps) if [ -f present ]; then printf 'still-present\n'; fi ;;
*) exit 99 ;;
esac
"#,
        );
        let sb = DockerSandbox {
            docker_bin: fake.bin.clone(),
            image: "img".into(),
        };
        assert_eq!(
            sb.run_script("print(1)", "python", Duration::from_secs(2))
                .await
                .unwrap(),
            (0, "ok".into())
        );
        let calls = fake.calls();
        let steps: Vec<_> = calls
            .lines()
            .filter(|line| line.starts_with("ps ") || line.starts_with("rm "))
            .collect();
        assert_eq!(steps.len(), 3, "{calls}");
        assert!(steps[0].starts_with("ps -aq "), "{calls}");
        assert!(steps[1].starts_with("rm -f "), "{calls}");
        assert!(steps[2].starts_with("ps -aq "), "{calls}");
        assert!(!fake.dir.path().join("present").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn absent_observation_failure_still_attempts_bounded_removal() {
        let fake = FakeDocker::new(
            r#"
case "$1" in
run) cat >/dev/null; printf ok ;;
rm) touch removed ;;
ps) if [ ! -f removed ]; then exit 1; fi ;;
*) exit 99 ;;
esac
"#,
        );
        let sb = DockerSandbox {
            docker_bin: fake.bin.clone(),
            image: "img".into(),
        };
        assert_eq!(
            sb.run_script("print(1)", "python", Duration::from_secs(2))
                .await
                .unwrap(),
            (0, "ok".into())
        );
        assert!(fake.dir.path().join("removed").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_is_not_a_zero_residue_guarantee_for_a_delayed_create() {
        let fake = FakeDocker::new(
            r#"
case "$1" in
run)
  cat >/dev/null
  (i=0; while [ ! -f observed-absent ] && [ $i -lt 200 ]; do sleep 0.01; i=$((i+1)); done
   if [ -f observed-absent ]; then sleep 0.15; touch late-created; fi) </dev/null >/dev/null 2>&1 &
  touch dispatch-started
  exec sleep 5 ;;
rm) ;;
ps) touch observed-absent ;;
*) exit 99 ;;
esac
"#,
        );
        let sb = DockerSandbox {
            docker_bin: fake.bin.clone(),
            image: "img".into(),
        };
        let task = tokio::spawn(async move {
            sb.run_script("print(1)", "python", Duration::from_secs(5))
                .await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !fake.dir.path().join("dispatch-started").exists() {
            assert!(tokio::time::Instant::now() < deadline, "{}", fake.calls());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        while !fake.dir.path().join("late-created").exists() {
            assert!(tokio::time::Instant::now() < deadline, "{}", fake.calls());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The fake daemon accepted a create before cancellation and completed
        // it after the cleanup inventory. This is deliberately retained as a
        // limitation test: cancellation returns no successful proof receipt.
        assert!(fake.dir.path().join("observed-absent").exists());
        assert!(fake.calls().contains("rm -f vettalon-poc-"));
    }

    #[test]
    fn output_capture_read_failure_and_combined_limit_are_not_complete() {
        let error = complete_output(
            Err(std::io::Error::other("fixture read failed")),
            Ok((Vec::new(), false)),
        )
        .unwrap_err();
        assert!(error.contains("stdout capture failed"));
        let error = complete_output(
            Ok((vec![b'a'; OUTPUT_CAP_BYTES / 2 + 1], false)),
            Ok((vec![b'b'; OUTPUT_CAP_BYTES / 2], false)),
        )
        .unwrap_err();
        assert!(error.contains("truncated"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn truncated_invalid_or_unconfirmed_execution_never_returns_proof() {
        for (run, cleanup, expected) in [
            (
                "i=0; while [ $i -lt 70000 ]; do printf x; i=$((i+1)); done",
                ":",
                "truncated",
            ),
            ("printf '\\377'", ":", "UTF-8"),
            ("printf ok", "exit 1", "cleanup"),
            (
                "printf ok",
                "printf 'container-still-present\\n'",
                "cleanup",
            ),
        ] {
            let fake = FakeDocker::new(&format!(
                r#"
case "$1" in
run) cat >/dev/null; {run} ;;
rm) ;;
ps) {cleanup} ;;
*) exit 99 ;;
esac
"#
            ));
            let sb = DockerSandbox {
                docker_bin: fake.bin.clone(),
                image: "img".into(),
            };
            let error = sb
                .run_script("print(1)", "python", Duration::from_secs(3))
                .await
                .unwrap_err();
            assert!(error.contains(expected), "expected {expected}, got {error}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_and_cancellation_cleanup_do_not_trust_client_exit() {
        let fake = FakeDocker::new(
            r#"
case "$1" in
run) cat >/dev/null; exec sleep 5 ;;
rm) ;;
ps) ;;
*) exit 99 ;;
esac
"#,
        );
        let sb = DockerSandbox {
            docker_bin: fake.bin.clone(),
            image: "img".into(),
        };
        let error = sb
            .run_script("print(1)", "python", Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(error.contains("timeout"), "{error}");
        assert!(fake.calls().contains("rm -f vettalon-poc-"));
        // A 100ms deadline can expire before the dispatcher starts. Observe
        // the new run itself rather than assuming the timed-out one logged.
        let prior_runs = fake
            .calls()
            .lines()
            .filter(|line| line.starts_with("run "))
            .count();
        let prior_removals = fake
            .calls()
            .lines()
            .filter(|line| line.starts_with("rm -f "))
            .count();
        let prior_confirmations = fake
            .calls()
            .lines()
            .filter(|line| line.starts_with("ps -aq "))
            .count();
        let task_sb = sb.clone();
        let task = tokio::spawn(async move {
            task_sb
                .run_script("print(2)", "python", Duration::from_secs(5))
                .await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while fake
            .calls()
            .lines()
            .filter(|line| line.starts_with("run "))
            .count()
            <= prior_runs
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "task_finished={} calls={}",
                task.is_finished(),
                fake.calls()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while fake
            .calls()
            .lines()
            .filter(|line| line.starts_with("rm -f "))
            .count()
            <= prior_removals
            || fake
                .calls()
                .lines()
                .filter(|line| line.starts_with("ps -aq "))
                .count()
                <= prior_confirmations
        {
            assert!(tokio::time::Instant::now() < deadline, "{}", fake.calls());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn run_args_label_the_owning_process() {
        let sb = DockerSandbox {
            docker_bin: "docker".into(),
            image: "img".into(),
        };
        let a = sb.run_args("n", &["true".into()]);
        let owner = format!("{POC_OWNER_KEY}={}", std::process::id());
        assert!(a.contains(&owner), "missing {owner}: {a:?}");
    }

    #[test]
    fn leftover_listing_parses_owner_labels() {
        let listing = "abc123 4242
def456 
  
ghi789 notapid
";
        assert_eq!(
            parse_poc_listing(listing),
            vec![
                ("abc123".to_string(), Some(4242)),
                ("def456".to_string(), None),
                ("ghi789".to_string(), None),
            ]
        );
    }

    #[test]
    fn only_containers_of_dead_or_unknown_owners_are_leftovers() {
        let me = 100;
        // Our own container: another dependency of this same run is using it.
        assert!(!is_leftover(Some(me), me, false));
        // Another live process (a dashboard scan next to a CLI hunt).
        assert!(!is_leftover(Some(200), me, true));
        // Owner exited without cleaning up.
        assert!(is_leftover(Some(200), me, false));
        // No owner label: made by an older vettalon, keep the old behaviour.
        assert!(is_leftover(None, me, false));
    }

    #[test]
    fn run_args_carry_every_isolation_flag() {
        let sb = DockerSandbox {
            docker_bin: "docker".into(),
            image: "img".into(),
        };
        let a = sb.run_args("n", &["python3".into(), "-".into()]);
        for flag in [
            "-i",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--rm",
        ] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}: {a:?}");
        }
        assert!(
            !a.iter().any(|x| x == "--mount"),
            "host mounts are forbidden: {a:?}"
        );
        for flag in ["--pull=never", "--memory-swap=512m", "vettalon.poc=1"] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}");
        }
        let user = a.iter().position(|x| x == "--user").unwrap();
        assert_eq!(a[user + 1], "65534:65534");
        // The image comes right before the command.
        let img = a.iter().position(|x| x == "img").unwrap();
        assert_eq!(
            &a[img + 1..],
            &["timeout", "-s", "KILL", "125", "python3", "-"]
        );
    }

    #[test]
    fn mounted_run_args_keep_every_flag_and_mount_read_only() {
        let sb = DockerSandbox {
            docker_bin: "docker".into(),
            image: "img".into(),
        };
        let a = sb.run_args_mounted(
            "n",
            &[
                (Path::new("/tmp/h"), "/workspace"),
                (Path::new("/tmp/t"), "/workspace/tree"),
            ],
            "/workspace",
            &["sh".into(), "-c".into(), "pytest".into()],
        );
        for flag in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--rm",
            "--pull=never",
        ] {
            assert!(a.iter().any(|value| value == flag), "missing {flag}");
        }
        assert!(
            a.iter()
                .any(|x| x == "type=bind,source=/tmp/t,target=/workspace/tree,readonly")
        );
        assert!(
            a.iter()
                .filter(|x| x.starts_with("type=bind"))
                .all(|x| x.ends_with(",readonly"))
        );
        let wd = a.iter().position(|x| x == "--workdir").unwrap();
        assert_eq!(a[wd + 1], "/workspace");
        assert!(!a.iter().any(|x| x == "-i"));
        // A mounted run with stdin input (the oracle marker) is interactive
        // and keeps the same mounts and flags.
        let b = sb.build_run_args(
            "n",
            &[(Path::new("/tmp/h"), "/workspace")],
            "/tmp",
            true,
            Pid1::Timeout,
            &["python3".into()],
        );
        assert_eq!(b[2], "-i");
        assert!(b.iter().any(|x| x == "--network=none"));
        assert!(
            b.iter()
                .any(|x| x == "type=bind,source=/tmp/h,target=/workspace,readonly")
        );
        // A test command in a tree copy keeps the `timeout` wrapper.
        let img = a.iter().position(|x| x == "img").unwrap();
        assert_eq!(
            &a[img + 1..],
            &["timeout", "-s", "KILL", "125", "sh", "-c", "pytest"]
        );
        assert!(!a.iter().any(|x| x == "--init=false"));
    }

    /// Harness runs (scan oracle, raw and typed fix check) put the runner
    /// itself at PID 1: no `timeout` wrapper and no init, with every
    /// isolation flag and the read-only mounts unchanged.
    #[test]
    fn harness_run_args_make_the_command_pid_1() {
        let sb = DockerSandbox {
            docker_bin: "docker".into(),
            image: "img".into(),
        };
        let cmd: Vec<String> = ["python3", "-I", "-B", "/workspace/runner.py"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = sb.build_run_args(
            "n",
            &[
                (Path::new("/tmp/h"), "/workspace"),
                (Path::new("/tmp/t"), "/workspace/tree"),
            ],
            "/tmp",
            true,
            Pid1::Command,
            &cmd,
        );
        assert_eq!(a[2], "-i");
        for flag in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--rm",
            "--pull=never",
            "--pids-limit=128",
            "--memory-swap=512m",
        ] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}: {a:?}");
        }
        assert!(
            a.iter()
                .filter(|x| x.starts_with("type=bind"))
                .all(|x| x.ends_with(",readonly"))
        );
        assert!(!a.iter().any(|x| x == "timeout"), "{a:?}");
        assert!(!a.iter().any(|x| x == IN_CONTAINER_LIMIT_SECS), "{a:?}");
        let img = a.iter().position(|x| x == "img").unwrap();
        assert_eq!(a[img - 1], "--init=false");
        assert_eq!(&a[img + 1..], cmd.as_slice());
    }

    #[tokio::test]
    async fn tree_mount_refuses_a_comma_path_and_the_tree_file_name() {
        let sb = DockerSandbox {
            docker_bin: "/nonexistent/docker".into(),
            image: "img".into(),
        };
        let e = sb
            .run_in_tree(
                Path::new("/tmp/a,b"),
                &["true".into()],
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(e.contains("unsupported mount path"), "{e}");
        let e = sb
            .run_workspace(
                &[("tree", "x")],
                &["true".into()],
                None,
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(e.contains("invalid workspace file name"), "{e}");
    }

    #[test]
    fn poc_commands_read_scripts_from_stdin_without_host_files() {
        let python = script_command("python").unwrap();
        let bash = script_command("bash").unwrap();
        assert_eq!(python, ["python3", "-"]);
        assert_eq!(bash, ["bash", "-s"]);
        assert!(script_command("ruby").is_err());
    }

    #[test]
    fn exit_125_is_docker_failure_only_with_docker_error_text() {
        for docker_error in [
            "docker: Error response from daemon: No such image: sha256:aa.\n",
            "\ndocker: invalid reference format.\nSee 'docker run --help'.\n",
            "Error response from daemon: conflict: name already in use\n",
            "docker: failed to create task: OCI runtime create failed\n",
            "unknown flag: --bogus\nSee 'docker run --help'.\n",
        ] {
            assert!(is_docker_failure(125, docker_error), "{docker_error:?}");
        }
    }

    #[test]
    fn exit_125_without_docker_error_text_is_the_targets_own_exit() {
        // A target that calls os._exit(125) is an ordinary non-zero exit,
        // not an unavailable environment.
        assert!(!is_docker_failure(125, ""));
        assert!(!is_docker_failure(125, "__VTL_ORACLE__ m effect=false\n"));
        assert!(!is_docker_failure(
            125,
            "Traceback (most recent call last):\n"
        ));
    }

    #[test]
    fn script_exit_127_is_the_scripts_own_result() {
        assert!(!is_docker_failure(127, "bash: curl: command not found"));
        assert!(is_docker_failure(
            127,
            "docker: Error response from daemon: OCI runtime create failed"
        ));
        assert!(!is_docker_failure(1, "OCI runtime"));
    }

    #[tokio::test]
    async fn run_workspace_refuses_file_names_with_separators() {
        let sb = DockerSandbox {
            docker_bin: "/nonexistent/docker".into(),
            image: "img".into(),
        };
        for bad in ["../escape.py", "sub/dir.py", "a\\b.py", ""] {
            let e = sb
                .run_workspace(
                    &[(bad, "print(1)")],
                    &["python3".into()],
                    Some("input"),
                    Duration::from_secs(1),
                )
                .await
                .unwrap_err();
            assert!(e.contains("invalid workspace file name"), "{bad}: {e}");
        }
    }

    #[tokio::test]
    async fn unsupported_language_is_refused_before_docker() {
        let sb = DockerSandbox {
            docker_bin: "/nonexistent/docker".into(),
            image: "img".into(),
        };
        let e = sb
            .run_script("x", "ruby", Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(e.contains("unsupported"));
    }

    /// Real Docker: offline, non-root, read-only root and workspace, a
    /// writable but `noexec` `/tmp`, no capabilities. Needs the default
    /// image pulled.
    #[tokio::test]
    #[ignore = "requires a Docker daemon + python:3.12-slim present locally"]
    async fn docker_sandbox_runs_python_offline_as_non_root() {
        let sb = DockerSandbox::detect(DEFAULT_POC_IMAGE)
            .await
            .expect("docker + image");
        let script = r#"import os, socket, subprocess
print('SANDBOX_OK', 6 * 7)
print('UID', os.getuid())
try:
    socket.create_connection(('1.1.1.1', 53), timeout=1)
    print('NET_OPEN')
except OSError:
    print('NET_BLOCKED')
for path in ('/vtl_probe', '/workspace/vtl_probe'):
    try:
        open(path, 'w').close()
        print('WRITABLE', path)
    except OSError:
        print('READONLY', path)
open('/tmp/vtl_probe.sh', 'w').write('#!/bin/sh\necho EXEC_RAN\n')
os.chmod('/tmp/vtl_probe.sh', 0o755)
try:
    subprocess.run(['/tmp/vtl_probe.sh'], check=True)
except (OSError, subprocess.CalledProcessError):
    print('TMP_NOEXEC')
for line in open('/proc/self/status'):
    if line.startswith(('CapEff', 'NoNewPrivs')):
        print(line.split()[0], line.split()[1])
"#;
        let (code, out) = sb
            .run_script(script, "python", Duration::from_secs(60))
            .await
            .unwrap();
        eprintln!("{out}");
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("SANDBOX_OK 42"), "{out}");
        assert!(out.contains("NET_BLOCKED"), "{out}");
        assert!(out.contains("UID 65534\n"), "{out}");
        assert!(out.contains("READONLY /vtl_probe\n"), "{out}");
        assert!(out.contains("READONLY /workspace/vtl_probe\n"), "{out}");
        assert!(out.contains("TMP_NOEXEC"), "{out}");
        assert!(!out.contains("EXEC_RAN"), "{out}");
        assert!(out.contains("CapEff: 0000000000000000\n"), "{out}");
        assert!(out.contains("NoNewPrivs: 1\n"), "{out}");
    }

    #[cfg(unix)]
    #[test]
    fn container_guard_removes_only_while_armed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("calls");
        let fake = dir.path().join("docker");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\necho \"$@\" >> {}\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = fake.display().to_string();

        let mut done = ContainerGuard::new(&bin, "finished");
        done.disarm();
        drop(done);
        drop(ContainerGuard::new(&bin, "cancelled"));

        // The removal runs on a detached thread; wait for it briefly.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let calls = loop {
            let calls = std::fs::read_to_string(&log).unwrap_or_default();
            if !calls.is_empty() || std::time::Instant::now() > deadline {
                break calls;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            calls.lines().any(|line| line == "rm -f cancelled"),
            "{calls}"
        );
        assert!(!calls.contains("finished"));
    }

    /// A cancelled run's hold is released only after its container removal
    /// has returned, not when the run's future is dropped.
    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_container_keeps_the_cleanup_hold_until_removal_returns() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let gate = dir.path().join("gate");
        let fake = dir.path().join("docker");
        // `rm` blocks until the gate file exists; `ps` reports absence.
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\ncase \"$1\" in\nrm) while [ ! -f '{}' ]; do sleep 0.02; done ;;\nesac\n",
                gate.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = fake.display().to_string();

        let hold: CleanupHold = std::sync::Arc::new(());
        let weak = std::sync::Arc::downgrade(&hold);
        with_cleanup_hold(hold, async {
            // Dropped while armed, as when the request future is cancelled.
            drop(ContainerGuard::new(&bin, "cancelled"));
        })
        .await;
        // Without a scope, a guard carries no hold.
        let mut unscoped = ContainerGuard::new(&bin, "unscoped");
        assert!(unscoped.hold.is_none());
        unscoped.disarm();
        drop(unscoped);

        std::thread::sleep(Duration::from_millis(200));
        assert!(
            weak.upgrade().is_some(),
            "hold released while removal is still running"
        );
        std::fs::write(&gate, "").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while weak.upgrade().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "hold never released after removal returned"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
