//! Container isolation for agent CLIs whose tools cannot be switched off
//! (codex, grok).
//!
//! Each call runs in a fresh `vettalon-agents` container that sees only a
//! per-call temp HOME holding a copy of the CLI's auth file and an empty
//! work dir; nothing from the host filesystem or environment. The container
//! sits on an `--internal` Docker network with no route out; the only way
//! out is the `vettalon-egress` proxy, which forwards CONNECT tunnels to
//! the model vendors' domains and refuses everything else. A CLI that
//! ignores the proxy simply cannot connect (fails closed).
//!
//! Residual risk: the model's tools can read the copied auth file and could
//! send it to an allowlisted vendor domain.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::cli::{CliSpec, OutputMode, PromptVia};
use super::{LlmCaller, LlmError};

/// The prompt file and final-message file, as seen inside the container.
const CONTAINER_PROMPT_FILE: &str = "/home/agent/work/prompt.txt";
const CONTAINER_OUT_FILE: &str = "/home/agent/work/last-message.txt";
/// Their names under the per-call work dir on the host.
const WORK_PROMPT_FILE: &str = "prompt.txt";
const WORK_OUT_FILE: &str = "last-message.txt";
/// Cap on output read back from a container run.
const OUTPUT_CAP_BYTES: usize = 4 * 1024 * 1024;

/// Image tags are tied to the vettalon version so a rebuild is explicit.
pub const AGENTS_IMAGE: &str = concat!("vettalon-agents:", env!("CARGO_PKG_VERSION"));
pub const EGRESS_IMAGE: &str = concat!("vettalon-egress:", env!("CARGO_PKG_VERSION"));
pub const NETWORK: &str = "vettalon-int";
pub const EGRESS_CONTAINER: &str = "vettalon-egress";
pub const PROXY_URL: &str = "http://vettalon-egress:8888";
/// HOME inside the agent container.
pub const CONTAINER_HOME: &str = "/home/agent";
pub const CONTAINER_WORK: &str = "/home/agent/work";
/// Label on every agent container, for cleanup.
pub const AGENT_LABEL: &str = "vettalon.agent=1";

const AGENTS_DOCKERFILE: &str = include_str!("../../../../docker/agents/Dockerfile");
const EGRESS_DOCKERFILE: &str = include_str!("../../../../docker/egress/Dockerfile");
const EGRESS_CONF: &str = include_str!("../../../../docker/egress/tinyproxy.conf");
const EGRESS_ALLOWLIST: &str = include_str!("../../../../docker/egress/allowlist");

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
pub fn run_args(
    name: &str,
    image: &str,
    home_mount: &Path,
    env: &[(String, String)],
) -> Vec<String> {
    let mut a: Vec<String> = [
        "run",
        "--rm",
        "-i",
        "--name",
        name,
        "--label",
        AGENT_LABEL,
        "--pull=never",
        "--network",
        NETWORK,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,size=256m",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
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
    for (k, v) in env {
        a.push("--env".into());
        a.push(format!("{k}={v}"));
    }
    a.push("--mount".into());
    a.push(format!(
        "type=bind,source={},target={CONTAINER_HOME}",
        home_mount.display()
    ));
    a.push(image.to_string());
    a
}

/// Lay out a per-call HOME under `root`: `home/<auth files>` and
/// `home/work/`. Returns the host path to mount as the container HOME.
pub fn prepare_home(root: &Path, auth_files: &[(PathBuf, String)]) -> Result<PathBuf, String> {
    let home = root.join("home");
    let work = home.join("work");
    std::fs::create_dir_all(&work).map_err(|e| format!("cannot create container home: {e}"))?;
    for (src, rel) in auth_files {
        if rel.contains("..") || rel.starts_with('/') {
            return Err(format!("invalid auth file target {rel:?}"));
        }
        let dst = home.join(rel);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::copy(src, &dst).map_err(|e| {
            format!(
                "cannot copy auth file {} (log in to the CLI on this machine first): {e}",
                src.display()
            )
        })?;
    }
    // The container user (uid 10001) must be able to write its HOME (token
    // refresh, session files). The enclosing temp dir stays 0700 on the host.
    #[cfg(unix)]
    chmod_tree_open(&home);
    Ok(home)
}

#[cfg(unix)]
fn chmod_tree_open(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o777));
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                chmod_tree_open(&p);
            } else {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666));
            }
        }
    }
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
        Ok(bin) => image_present(&bin, AGENTS_IMAGE).await,
        Err(_) => false,
    }
}

/// Make sure the internal network and the egress proxy are up. Idempotent.
pub async fn ensure_infra() -> Result<(), String> {
    let bin = docker_bin()?;
    for image in [AGENTS_IMAGE, EGRESS_IMAGE] {
        if !image_present(&bin, image).await {
            return Err(format!(
                "container image {image} is missing; run `vettalon agents build` once"
            ));
        }
    }
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
            EGRESS_IMAGE,
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

/// Force-remove a (possibly still running) agent container.
pub async fn force_remove(name: &str) {
    if let Ok(bin) = docker_bin() {
        let _ = docker(&bin, &["rm", "-f", name]).await;
    }
}

/// `vettalon agents build`: build both images from the definitions
/// embedded in this binary. Needs network access (package downloads).
pub async fn build_images() -> Result<(), String> {
    let bin = docker_bin()?;
    let ctx = tempfile::Builder::new()
        .prefix("vettalon-build-")
        .tempdir()
        .map_err(|e| format!("cannot create build dir: {e}"))?;
    let write = |rel: &str, body: &str| -> Result<(), String> {
        let p = ctx.path().join(rel);
        std::fs::create_dir_all(p.parent().expect("has parent")).map_err(|e| e.to_string())?;
        std::fs::write(&p, body).map_err(|e| e.to_string())
    };
    write("agents/Dockerfile", AGENTS_DOCKERFILE)?;
    write("egress/Dockerfile", EGRESS_DOCKERFILE)?;
    write("egress/tinyproxy.conf", EGRESS_CONF)?;
    write("egress/allowlist", EGRESS_ALLOWLIST)?;
    for (tag, dir) in [(EGRESS_IMAGE, "egress"), (AGENTS_IMAGE, "agents")] {
        eprintln!(
            "[vettalon] {}",
            crate::tr!("建置 {tag}…", "building {tag}…")
        );
        let status = Command::new(&bin)
            .args(["build", "-t", tag])
            .arg(ctx.path().join(dir))
            .stdin(Stdio::null())
            .status()
            .await
            .map_err(|e| format!("cannot run docker build: {e}"))?;
        if !status.success() {
            return Err(format!("docker build {tag} failed"));
        }
    }
    Ok(())
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
pub fn docker_argv(
    name: &str,
    image: &str,
    home_mount: &Path,
    env: &[(String, String)],
    spec: &CliSpec,
) -> Vec<String> {
    let mut argv = run_args(name, image, home_mount, env);
    argv.push(spec.program.clone());
    // Inside the container the prompt file and output file are at fixed
    // paths under the mounted work dir; an `arg` prompt is passed inline.
    argv.extend(spec.render_args_with("", CONTAINER_OUT_FILE, CONTAINER_PROMPT_FILE));
    argv
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
        std::fs::write(work.join(WORK_PROMPT_FILE), prompt)
            .map_err(|e| LlmError::Executor(format!("cannot write prompt: {e}")))?;
        // The container user (uid 10001) must read the prompt and write the
        // output; prepare_home already opened the tree, re-apply to the new file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                work.join(WORK_PROMPT_FILE),
                std::fs::Permissions::from_mode(0o666),
            );
        }

        let env: Vec<(String, String)> = self
            .spec
            .env_passthrough
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.clone(), v)))
            .collect();
        let name = format!("vettalon-agent-{}", uuid::Uuid::new_v4().simple());
        let argv = docker_argv(&name, &self.container.image, &home, &env, &self.spec);

        let mut child = Command::new(&docker_bin)
            .args(&argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| LlmError::Executor(format!("cannot start docker: {e}")))?;

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
                return Err(LlmError::Executor(format!(
                    "{} in container timed out after {}s",
                    self.spec.program,
                    self.spec.timeout.as_secs()
                )));
            }
        };
        let status = status.map_err(|e| LlmError::Executor(format!("wait failed: {e}")))?;
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
        let a = run_args(
            "n",
            "img",
            Path::new("/tmp/h"),
            &[("OPENAI_API_KEY".into(), "k".into())],
        );
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
        let n = a.iter().position(|x| x == "--network").unwrap();
        assert_eq!(a[n + 1], NETWORK);
        assert!(
            a.iter()
                .any(|x| x == &format!("type=bind,source=/tmp/h,target={CONTAINER_HOME}"))
        );
        assert!(a.iter().any(|x| x == &format!("HTTPS_PROXY={PROXY_URL}")));
        assert!(a.iter().any(|x| x == "OPENAI_API_KEY=k"));
        assert_eq!(a.last().unwrap(), "img");
        // The host HOME is never mounted.
        assert!(
            !a.iter()
                .any(|x| x.contains(&host_home().display().to_string()) && !x.contains("/tmp/h"))
        );
    }

    #[test]
    fn prepare_home_copies_only_the_auth_files() {
        let src = tempfile::tempdir().unwrap();
        let auth = src.path().join("auth.json");
        std::fs::write(&auth, "{}").unwrap();
        std::fs::write(src.path().join("other-secret"), "x").unwrap();
        let root = tempfile::tempdir().unwrap();
        let home = prepare_home(root.path(), &[(auth, ".codex/auth.json".into())]).unwrap();
        assert!(home.join(".codex/auth.json").is_file());
        assert!(home.join("work").is_dir());
        let names: Vec<_> = std::fs::read_dir(&home)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(
            prepare_home(
                root.path(),
                &[(src.path().join("auth.json"), "../x".into())]
            )
            .is_err()
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
        assert!(e.contains("log in"));
    }

    fn codex_container_spec() -> (CliSpec, ContainerSpec) {
        let spec = CliSpec::preset("codex", None, Duration::from_secs(60)).unwrap();
        let cspec = ContainerSpec {
            image: AGENTS_IMAGE.to_string(),
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
        let a = docker_argv("n", &cspec.image, Path::new("/tmp/home"), &[], &spec);
        let prog = a
            .iter()
            .position(|x| x == "codex")
            .expect("program present");
        // Everything before the program is docker isolation; the image is last.
        assert_eq!(a[prog - 1], cspec.image);
        let rest = &a[prog + 1..];
        assert!(rest.iter().any(|x| x == CONTAINER_OUT_FILE), "{rest:?}");
        assert!(rest.iter().any(|x| x == "--sandbox"));
        // No host path leaks into the argv except the mount source.
        assert!(!a.iter().any(|x| x.contains("/host/.codex")));
    }

    #[test]
    fn grok_container_argv_uses_the_prompt_file() {
        let spec = CliSpec::preset("grok", None, Duration::from_secs(60)).unwrap();
        let a = docker_argv("n", "img", Path::new("/tmp/home"), &[], &spec);
        let prog = a.iter().position(|x| x == "grok").unwrap();
        assert!(a[prog + 1..].iter().any(|x| x == CONTAINER_PROMPT_FILE));
    }

    #[tokio::test]
    async fn arg_prompt_is_refused_by_the_container_backend() {
        let mut spec = CliSpec::preset("grok", None, Duration::from_secs(1)).unwrap();
        spec.prompt_via = PromptVia::Arg;
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

    #[test]
    fn embedded_definitions_are_the_repo_files() {
        assert!(AGENTS_DOCKERFILE.contains("@openai/codex"));
        assert!(EGRESS_CONF.contains("FilterDefaultDeny Yes"));
        assert!(EGRESS_ALLOWLIST.lines().all(|l| l.ends_with('$')));
    }
}
