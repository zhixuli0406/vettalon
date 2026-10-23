//! Container isolation for agent CLIs whose tools cannot be switched off
//! (codex, grok).
//!
//! Each call runs in a fresh `vettalon-agents` container that sees only a
//! credential-free, owner-only per-call HOME and an empty work dir; nothing
//! from the host filesystem or ambient environment. The container
//! sits on an `--internal` Docker network with no route out; the only way
//! out is the `vettalon-egress` proxy, which forwards CONNECT tunnels to
//! the model vendors' domains and refuses everything else. A CLI that
//! ignores the proxy simply cannot connect (fails closed).
//!
//! Reusable auth files and environment passthrough are rejected before Docker
//! starts. A future credential-brokered backend may provide non-exportable,
//! short-lived access without weakening this boundary.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::cli::{CliSpec, OutputMode, PromptVia};
use super::{LlmCaller, LlmError};

mod images;
use images::missing_image_error;
pub use images::{
    REGISTRY_PREFIX, SIGNER_IDENTITY_REGEXP, SIGNER_ISSUER, agents_base_image, agents_image,
    build_images, build_joern_image, egress_image, joern_image, pull_images,
};

/// The prompt file and final-message file, as seen inside the container.
const CONTAINER_PROMPT_FILE: &str = "/home/agent/work/prompt.txt";
const CONTAINER_OUT_FILE: &str = "/home/agent/work/last-message.txt";
/// Their names under the per-call work dir on the host.
const WORK_PROMPT_FILE: &str = "prompt.txt";
const WORK_OUT_FILE: &str = "last-message.txt";
/// Cap on output read back from a container run.
const OUTPUT_CAP_BYTES: usize = 4 * 1024 * 1024;

pub const NETWORK: &str = "vettalon-int";
pub const EGRESS_CONTAINER: &str = "vettalon-egress";
pub const PROXY_URL: &str = "http://vettalon-egress:8888";
const AGENT_OWNER_KEY: &str = "vettalon.agent.owner";
const MAX_AGENT_TIMEOUT_SECS: u64 = 30 * 60;
/// HOME inside the agent container.
pub const CONTAINER_HOME: &str = "/home/agent";
pub const CONTAINER_WORK: &str = "/home/agent/work";
/// Label on every agent container, for cleanup.
pub const AGENT_LABEL: &str = "vettalon.agent=1";

const DOCKER_CALL_LIMIT: Duration = Duration::from_secs(60);

/// How one CLI model is run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolation {
    /// Directly on the host (only for CLIs whose tools are really off, or
    /// with an explicit `allow_agent_tools` opt-in).
    Host,
    Container(ContainerSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSpec {
    pub image: String,
    /// `(host file, path relative to the container HOME)`, copied per call.
    pub auth_files: Vec<(PathBuf, String)>,
}

/// Auth files a preset needs inside the container, relative to HOME.
pub fn preset_auth_files(preset: &str) -> Vec<String> {
    match preset {
        "codex" => vec![".codex/auth.json".into()],
        "grok" => vec![".grok/auth.json".into()],
        _ => Vec::new(),
    }
}

pub fn host_home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
}

/// The `docker run` prefix for one agent call (everything before the CLI's
/// own argv). Pure, so the isolation flags are unit-tested.
pub fn run_args(name: &str, image: &str, home_mount: &Path) -> Vec<String> {
    let owner_label = format!("{AGENT_OWNER_KEY}={}", std::process::id());
    #[cfg(unix)]
    let container_user = {
        // SAFETY: geteuid/getegid have no arguments and only read process identity.
        format!("{}:{}", unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        })
    };
    #[cfg(not(unix))]
    let container_user = "10001:10001".to_string();
    let mut a: Vec<String> = [
        "run",
        "--rm",
        "-i",
        "--name",
        name,
        "--label",
        AGENT_LABEL,
        "--label",
        owner_label.as_str(),
        "--pull=never",
        "--network",
        NETWORK,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,size=256m",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        container_user.as_str(),
        "--pids-limit=512",
        "--memory=2g",
        "--memory-swap=2g",
        "--workdir",
        CONTAINER_WORK,
        "--env",
        &format!("HOME={CONTAINER_HOME}"),
        "--env",
        &format!("HTTPS_PROXY={PROXY_URL}"),
        "--env",
        &format!("https_proxy={PROXY_URL}"),
        "--env",
        &format!("HTTP_PROXY={PROXY_URL}"),
        "--env",
        &format!("http_proxy={PROXY_URL}"),
        "--env",
        "NO_PROXY=",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.push("--mount".into());
    a.push(format!(
        "type=bind,source={},target={CONTAINER_HOME}",
        home_mount.display()
    ));
    a.push(image.to_string());
    a
}

/// Lay out a credential-free per-call HOME under `root`.
pub fn prepare_home(root: &Path, auth_files: &[(PathBuf, String)]) -> Result<PathBuf, String> {
    if !auth_files.is_empty() {
        return Err(
            "reusable CLI credentials are forbidden in tool-capable model containers".into(),
        );
    }
    let home = root.join("home");
    let work = home.join("work");
    std::fs::create_dir_all(&work).map_err(|e| format!("cannot create container home: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot protect container home: {e}"))?;
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot protect container work dir: {e}"))?;
    }
    Ok(home)
}

async fn docker(docker_bin: &str, args: &[&str]) -> Result<std::process::Output, String> {
    tokio::time::timeout(
        DOCKER_CALL_LIMIT,
        Command::new(docker_bin)
            .args(args)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| format!("docker {} timed out", args.first().unwrap_or(&"")))?
    .map_err(|e| format!("cannot run docker: {e}"))
}

pub fn docker_bin() -> Result<String, String> {
    crate::util::which_cli("docker").ok_or_else(|| "docker CLI not found on PATH".to_string())
}

async fn image_present(docker_bin: &str, image: &str) -> bool {
    docker(
        docker_bin,
        &["image", "inspect", "--format", "{{.Id}}", image],
    )
    .await
    .map(|o| o.status.success())
    .unwrap_or(false)
}

/// Whether the agent image exists locally (for auto-detection).
pub async fn agents_image_present() -> bool {
    match docker_bin() {
        Ok(bin) => image_present(&bin, agents_image()).await,
        Err(_) => false,
    }
}

/// Both images this binary needs exist locally. Only `docker image
/// inspect` runs here, so a missing image stops a call before any container.
async fn check_images(docker_bin: &str) -> Result<(), String> {
    for image in [agents_image(), egress_image()] {
        if !image_present(docker_bin, image).await {
            return Err(missing_image_error(image));
        }
    }
    Ok(())
}

/// Make sure the internal network and the egress proxy are up. Idempotent.
pub async fn ensure_infra() -> Result<(), String> {
    let bin = docker_bin()?;
    check_images(&bin).await?;
    remove_agent_leftovers(&bin).await;
    let net = docker(
        &bin,
        &["network", "inspect", "--format", "{{.Internal}}", NETWORK],
    )
    .await?;
    if !net.status.success() {
        let c = docker(&bin, &["network", "create", "--internal", NETWORK]).await?;
        if !c.status.success() {
            return Err(format!(
                "cannot create network {NETWORK}: {}",
                String::from_utf8_lossy(&c.stderr).trim()
            ));
        }
    } else if String::from_utf8_lossy(&net.stdout).trim() != "true" {
        return Err(format!(
            "docker network {NETWORK} exists but is not --internal; remove it (`docker network rm {NETWORK}`)"
        ));
    }
    let running = docker(
        &bin,
        &[
            "inspect",
            "--format",
            "{{.State.Running}}",
            EGRESS_CONTAINER,
        ],
    )
    .await?;
    if running.status.success() && String::from_utf8_lossy(&running.stdout).trim() == "true" {
        return Ok(());
    }
    let _ = docker(&bin, &["rm", "-f", EGRESS_CONTAINER]).await;
    let start = docker(
        &bin,
        &[
            "run",
            "-d",
            "--name",
            EGRESS_CONTAINER,
            "--restart",
            "unless-stopped",
            "--network",
            "bridge",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=128m",
            "--pids-limit=64",
            egress_image(),
        ],
    )
    .await?;
    if !start.status.success() {
        return Err(format!(
            "cannot start egress proxy: {}",
            String::from_utf8_lossy(&start.stderr).trim()
        ));
    }
    let connect = docker(
        &bin,
        &[
            "network",
            "connect",
            "--alias",
            EGRESS_CONTAINER,
            NETWORK,
            EGRESS_CONTAINER,
        ],
    )
    .await?;
    if !connect.status.success() {
        return Err(format!(
            "cannot attach egress proxy to {NETWORK}: {}",
            String::from_utf8_lossy(&connect.stderr).trim()
        ));
    }
    Ok(())
}

async fn remove_agent_leftovers(docker_bin: &str) {
    let format = format!("{{{{.ID}}}} {{{{.Label \"{AGENT_OWNER_KEY}\"}}}}");
    let Ok(output) = docker(
        docker_bin,
        &[
            "ps",
            "-a",
            "--filter",
            &format!("label={AGENT_LABEL}"),
            "--format",
            &format,
        ],
    )
    .await
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let me = std::process::id();
    for (id, owner) in parse_agent_listing(&String::from_utf8_lossy(&output.stdout)) {
        if agent_is_leftover(owner, me) {
            let _ = docker(docker_bin, &["rm", "-f", &id]).await;
        }
    }
}

fn parse_agent_listing(listing: &str) -> Vec<(String, Option<u32>)> {
    listing
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let id = parts.next()?.to_string();
            let owner = parts.next().and_then(|part| part.parse().ok());
            Some((id, owner))
        })
        .collect()
}

fn agent_is_leftover(owner: Option<u32>, current: u32) -> bool {
    match owner {
        None => true,
        Some(owner) if owner == current => false,
        Some(owner) => !process_is_alive(owner),
    }
}

fn process_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        // SAFETY: signal 0 performs an existence/permission check only.
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        use std::ffi::c_void;

        type Handle = *mut c_void;
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        const STILL_ACTIVE: u32 = 259;
        const ERROR_ACCESS_DENIED: u32 = 5;
        const ERROR_INVALID_PARAMETER: u32 = 87;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
            fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
            fn CloseHandle(object: Handle) -> i32;
            fn GetLastError() -> u32;
        }

        // SAFETY: the handle is queried read-only and closed on every success
        // path. Access-denied means the process exists but is protected.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return match GetLastError() {
                    ERROR_INVALID_PARAMETER => false,
                    ERROR_ACCESS_DENIED => true,
                    _ => true,
                };
            }
            let mut exit_code = 0u32;
            let queried = GetExitCodeProcess(process, &mut exit_code);
            let _ = CloseHandle(process);
            queried != 0 && exit_code == STILL_ACTIVE
        }
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = pid;
        true
    }
}

/// Force-remove a (possibly still running) agent container.
pub async fn force_remove(name: &str) {
    if let Ok(bin) = docker_bin() {
        let _ = docker(&bin, &["rm", "-f", name]).await;
    }
}

/// `vettalon agents stop`: remove the proxy and the network.
pub async fn teardown() -> Result<(), String> {
    let bin = docker_bin()?;
    let _ = docker(&bin, &["rm", "-f", EGRESS_CONTAINER]).await;
    let _ = docker(&bin, &["network", "rm", NETWORK]).await;
    Ok(())
}

/// Full `docker` argv for one call: the isolation flags, then the CLI's
/// program and its arguments rendered with the in-container prompt/output
/// paths. Pure, so the whole command line is unit-testable without docker.
pub fn docker_argv(name: &str, image: &str, home_mount: &Path, spec: &CliSpec) -> Vec<String> {
    let mut argv = run_args(name, image, home_mount);
    argv.extend([
        "timeout".to_string(),
        "-s".to_string(),
        "KILL".to_string(),
        spec.timeout
            .as_secs()
            .clamp(1, MAX_AGENT_TIMEOUT_SECS)
            .to_string(),
    ]);
    argv.push(spec.program.clone());
    // Inside the container the prompt file and output file are at fixed
    // paths under the mounted work dir; an `arg` prompt is passed inline.
    argv.extend(spec.render_args_with("", CONTAINER_OUT_FILE, CONTAINER_PROMPT_FILE));
    argv
}

/// Cancellation-safe ownership of a named agent container. Killing the
/// `docker run` client does not guarantee daemon-side container removal.
struct AgentContainerGuard {
    docker_bin: String,
    name: String,
    armed: bool,
}

impl AgentContainerGuard {
    fn new(docker_bin: &str, name: &str) -> Self {
        Self {
            docker_bin: docker_bin.to_string(),
            name: name.to_string(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AgentContainerGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut command = std::process::Command::new(&self.docker_bin);
        command
            .args(["rm", "-f", &self.name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        std::thread::spawn(move || {
            let _ = command.status();
        });
    }
}

/// A [`CliSpec`] whose tools stay on, run inside the agents container.
/// `CliCaller` on the host is never touched; this is a separate backend.
pub struct ContainerCliCaller {
    pub spec: CliSpec,
    pub container: ContainerSpec,
}

#[async_trait]
impl LlmCaller for ContainerCliCaller {
    async fn complete(&self, prompt: &str) -> super::Result<String> {
        if !self.container.auth_files.is_empty() || !self.spec.env_passthrough.is_empty() {
            return Err(LlmError::Executor(
                "tool-capable model containers refuse reusable credentials and environment passthrough; use a tool-disabled or credential-brokered backend"
                    .into(),
            ));
        }
        if self.spec.prompt_via == PromptVia::Arg {
            // The container passes the prompt by file or stdin, never argv
            // (argv would appear in `docker inspect`); presets never use Arg
            // here, so this is a configuration mistake, not a runtime path.
            return Err(LlmError::Executor(
                "container backend does not support prompt_via = arg".into(),
            ));
        }
        ensure_infra().await.map_err(LlmError::Executor)?;
        let docker_bin = docker_bin().map_err(LlmError::Executor)?;

        let root = tempfile::Builder::new()
            .prefix("vettalon-ctr-")
            .tempdir()
            .map_err(|e| LlmError::Executor(format!("cannot create temp dir: {e}")))?;
        let home =
            prepare_home(root.path(), &self.container.auth_files).map_err(LlmError::Executor)?;
        let work = home.join("work");
        crate::util::write_private(&work.join(WORK_PROMPT_FILE), prompt.as_bytes())
            .map_err(|e| LlmError::Executor(format!("cannot write prompt: {e}")))?;
        let name = format!("vettalon-agent-{}", uuid::Uuid::new_v4().simple());
        let argv = docker_argv(&name, &self.container.image, &home, &self.spec);

        let mut child = Command::new(&docker_bin)
            .args(&argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| LlmError::Executor(format!("cannot start docker: {e}")))?;
        let mut guard = AgentContainerGuard::new(&docker_bin, &name);

        let feed: Vec<u8> = self.spec.stdin_payload(prompt);
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let run = async {
            let w = async {
                let r = stdin.write_all(&feed).await;
                drop(stdin);
                r
            };
            let (w, out, err) = tokio::join!(
                w,
                crate::util::read_capped(stdout, OUTPUT_CAP_BYTES),
                crate::util::read_capped(stderr, OUTPUT_CAP_BYTES)
            );
            let status = child.wait().await;
            (
                w,
                status,
                out.map(|(b, _)| b).unwrap_or_default(),
                err.map(|(b, _)| b).unwrap_or_default(),
            )
        };
        let (_w, status, out, err) = match tokio::time::timeout(self.spec.timeout, run).await {
            Ok(r) => r,
            Err(_) => {
                force_remove(&name).await;
                guard.disarm();
                return Err(LlmError::Executor(format!(
                    "{} in container timed out after {}s",
                    self.spec.program,
                    self.spec.timeout.as_secs()
                )));
            }
        };
        let status = match status {
            Ok(status) => {
                guard.disarm();
                status
            }
            Err(error) => return Err(LlmError::Executor(format!("wait failed: {error}"))),
        };
        if !status.success() {
            let tail = crate::util::mask_sensitive_text(String::from_utf8_lossy(&err).trim());
            return Err(LlmError::Executor(format!(
                "{} in container exited with {}: {}",
                self.spec.program,
                status,
                crate::util::truncate_bytes(&tail, 400)
            )));
        }
        let stdout_text = String::from_utf8_lossy(&out).to_string();
        let reply = match &self.spec.output {
            OutputMode::Stdout => Ok(stdout_text),
            OutputMode::AgyStreamJson => super::cli::parse_agy_stream(&stdout_text),
            OutputMode::File => {
                let p = work.join(WORK_OUT_FILE);
                let len = std::fs::metadata(&p)
                    .map_err(|e| LlmError::Executor(format!("CLI wrote no final message: {e}")))?
                    .len();
                if len > OUTPUT_CAP_BYTES as u64 {
                    return Err(LlmError::Executor(format!(
                        "CLI final message too large ({len} bytes)"
                    )));
                }
                std::fs::read_to_string(&p)
                    .map_err(|e| LlmError::Executor(format!("CLI wrote no final message: {e}")))
            }
            OutputMode::JsonField(field) => {
                let v: serde_json::Value =
                    serde_json::from_str(stdout_text.trim()).map_err(|e| {
                        LlmError::Executor(format!(
                            "CLI stdout is not the expected JSON envelope: {e}"
                        ))
                    })?;
                v.get(field)
                    .and_then(|x| x.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        LlmError::Executor(format!("CLI JSON envelope has no {field:?} string"))
                    })
            }
        }?;
        self.spec.check_output_cap(&reply)?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_args_isolate_network_fs_and_privileges() {
        let a = run_args("n", "img", Path::new("/tmp/h"));
        for flag in [
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pull=never",
            AGENT_LABEL,
        ] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}");
        }
        assert!(
            a.iter()
                .any(|value| value == &format!("{AGENT_OWNER_KEY}={}", std::process::id()))
        );
        let n = a.iter().position(|x| x == "--network").unwrap();
        assert_eq!(a[n + 1], NETWORK);
        assert!(
            a.iter()
                .any(|x| x == &format!("type=bind,source=/tmp/h,target={CONTAINER_HOME}"))
        );
        assert!(a.iter().any(|x| x == &format!("HTTPS_PROXY={PROXY_URL}")));
        assert!(!a.iter().any(|x| x.starts_with("OPENAI_API_KEY=")));
        assert_eq!(a.last().unwrap(), "img");
        // The host HOME is never mounted.
        assert!(
            !a.iter()
                .any(|x| x.contains(&host_home().display().to_string()) && !x.contains("/tmp/h"))
        );
    }

    #[test]
    fn agent_listing_and_owner_policy_preserve_live_current_containers() {
        assert_eq!(
            parse_agent_listing("abc 42\ndef\nghi nope\n"),
            vec![
                ("abc".to_string(), Some(42)),
                ("def".to_string(), None),
                ("ghi".to_string(), None),
            ]
        );
        let me = std::process::id();
        assert!(!agent_is_leftover(Some(me), me));
        assert!(agent_is_leftover(None, me));
    }

    #[cfg(windows)]
    #[test]
    fn windows_agent_owner_probe_distinguishes_live_and_absent_processes() {
        let me = std::process::id();
        assert!(process_is_alive(me));
        assert!(!process_is_alive(u32::MAX));
        assert!(!agent_is_leftover(Some(me), me));
        assert!(agent_is_leftover(Some(u32::MAX), me));
    }

    #[test]
    fn prepare_home_refuses_auth_files_and_keeps_the_mount_private() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::tempdir().unwrap();
        let auth = src.path().join("auth.json");
        std::fs::write(&auth, "{}").unwrap();
        let root = tempfile::tempdir().unwrap();
        let error = prepare_home(root.path(), &[(auth, ".codex/auth.json".into())]).unwrap_err();
        assert!(error.contains("credentials"), "{error}");

        let home = prepare_home(root.path(), &[]).unwrap();
        assert!(home.join("work").is_dir());
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn missing_auth_file_says_how_to_fix_it() {
        let root = tempfile::tempdir().unwrap();
        let e = prepare_home(
            root.path(),
            &[(
                PathBuf::from("/nonexistent/auth.json"),
                ".grok/auth.json".into(),
            )],
        )
        .unwrap_err();
        assert!(e.contains("credentials"));
    }

    fn codex_container_spec() -> (CliSpec, ContainerSpec) {
        let spec = CliSpec::preset("codex", None, Duration::from_secs(60)).unwrap();
        let cspec = ContainerSpec {
            image: agents_image().to_string(),
            auth_files: vec![(
                PathBuf::from("/host/.codex/auth.json"),
                ".codex/auth.json".into(),
            )],
        };
        (spec, cspec)
    }

    #[test]
    fn docker_argv_appends_program_and_container_paths() {
        let (spec, cspec) = codex_container_spec();
        let a = docker_argv("n", &cspec.image, Path::new("/tmp/home"), &spec);
        let prog = a
            .iter()
            .position(|x| x == "codex")
            .expect("program present");
        assert!(a[..prog].iter().any(|x| x == &cspec.image));
        assert_eq!(&a[prog - 4..prog], ["timeout", "-s", "KILL", "60"]);
        let rest = &a[prog + 1..];
        assert!(rest.iter().any(|x| x == CONTAINER_OUT_FILE), "{rest:?}");
        assert!(rest.iter().any(|x| x == "--sandbox"));
        // No host path leaks into the argv except the mount source.
        assert!(!a.iter().any(|x| x.contains("/host/.codex")));
    }

    #[cfg(unix)]
    #[test]
    fn run_args_uses_the_private_home_owner_instead_of_a_shared_uid() {
        use std::os::unix::fs::MetadataExt;
        let home = tempfile::tempdir().unwrap();
        let a = run_args("n", "img", home.path());
        let user = a.iter().position(|x| x == "--user").unwrap();
        let meta = std::fs::metadata(home.path()).unwrap();
        assert_eq!(a[user + 1], format!("{}:{}", meta.uid(), meta.gid()));
    }

    #[cfg(unix)]
    #[test]
    fn agent_container_guard_removes_only_while_armed() {
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

        let mut done = AgentContainerGuard::new(&bin, "finished");
        done.disarm();
        drop(done);
        drop(AgentContainerGuard::new(&bin, "cancelled"));

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let calls = loop {
            let calls = std::fs::read_to_string(&log).unwrap_or_default();
            if !calls.is_empty() || std::time::Instant::now() > deadline {
                break calls;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(calls.trim(), "rm -f cancelled");
    }

    #[test]
    fn grok_container_argv_uses_the_prompt_file() {
        let spec = CliSpec::preset("grok", None, Duration::from_secs(60)).unwrap();
        let a = docker_argv("n", "img", Path::new("/tmp/home"), &spec);
        let prog = a.iter().position(|x| x == "grok").unwrap();
        assert!(a[prog + 1..].iter().any(|x| x == CONTAINER_PROMPT_FILE));
    }

    #[test]
    fn in_container_timeout_has_a_hard_upper_bound() {
        let mut spec = CliSpec::preset("grok", None, Duration::from_secs(60)).unwrap();
        spec.timeout = Duration::from_secs(999_999);
        let a = docker_argv("n", "img", Path::new("/tmp/home"), &spec);
        let prog = a.iter().position(|x| x == "grok").unwrap();
        assert_eq!(&a[prog - 4..prog], ["timeout", "-s", "KILL", "1800"]);
    }

    #[tokio::test]
    async fn arg_prompt_is_refused_by_the_container_backend() {
        let mut spec = CliSpec::preset("grok", None, Duration::from_secs(1)).unwrap();
        spec.prompt_via = PromptVia::Arg;
        spec.env_passthrough.clear();
        let caller = ContainerCliCaller {
            spec,
            container: ContainerSpec {
                image: "img".into(),
                auth_files: vec![],
            },
        };
        let e = caller.complete("p").await.unwrap_err();
        assert!(e.to_string().contains("prompt_via = arg"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_image_fails_before_any_container_starts() {
        // A fake `docker` that records its argv and reports every image as
        // absent: ensure_infra must stop at `image inspect`, never `run`.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        let fake = dir.path().join("docker");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 1\n", log.display()),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let e = check_images(fake.to_str().unwrap()).await.unwrap_err();
        assert_eq!(e, missing_image_error(agents_image()));
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(
            calls.lines().all(|l| l.starts_with("image inspect")),
            "{calls}"
        );
    }

    #[tokio::test]
    async fn credential_environment_is_refused_before_docker_startup() {
        let spec = CliSpec::preset("codex", None, Duration::from_secs(1)).unwrap();
        let caller = ContainerCliCaller {
            spec,
            container: ContainerSpec {
                image: "img".into(),
                auth_files: vec![],
            },
        };
        let error = caller.complete("untrusted source").await.unwrap_err();
        assert!(error.to_string().contains("credentials"), "{error}");
    }
}
