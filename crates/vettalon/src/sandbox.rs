//! Docker-CLI sandbox for PoC scripts.
//!
//! Hard rule: a PoC never runs on the host. Every path that cannot get a
//! real, isolated container returns `Err`, and the caller records the PoC as
//! skipped. The container gets no network, a read-only root filesystem, no
//! Linux capabilities, `no-new-privileges`, a non-root uid, memory/pid/CPU
//! caps, and only the script directory mounted read-only.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

/// Default image: small, has `python3` and `bash`. Never pulled
/// automatically (pulling needs the network); the operator runs
/// `docker pull` once.
pub const DEFAULT_POC_IMAGE: &str = "python:3.12-slim";

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
/// Cap on any single `docker` housekeeping call.
const DOCKER_CALL_LIMIT: Duration = Duration::from_secs(30);

/// Combined stdout+stderr cap kept from one PoC run.
const OUTPUT_CAP_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct DockerSandbox {
    pub docker_bin: String,
    pub image: String,
}

impl DockerSandbox {
    /// Locate `docker` and check the daemon answers and `image` is present.
    pub async fn detect(image: &str) -> Result<Self, String> {
        let docker_bin = crate::util::which_cli("docker")
            .ok_or_else(|| "docker CLI not found on PATH".to_string())?;
        let sb = DockerSandbox {
            docker_bin,
            image: image.to_string(),
        };
        let ping = Command::new(&sb.docker_bin)
            .args(["version", "--format", "{{.Server.Version}}"])
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| format!("cannot run docker: {e}"))?;
        if !ping.status.success() {
            return Err("docker daemon is not reachable".to_string());
        }
        let inspect = Command::new(&sb.docker_bin)
            .args(["image", "inspect", "--format", "{{.Id}}", image])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| format!("cannot run docker: {e}"))?;
        if !inspect.success() {
            return Err(format!(
                "sandbox image {image} is not present locally (run `docker pull {image}` once)"
            ));
        }
        if image.starts_with('-') {
            return Err(format!("invalid sandbox image name {image:?}"));
        }
        sb.remove_leftovers().await;
        Ok(sb)
    }

    /// Force-remove PoC containers left by an earlier, killed run: ones
    /// whose owning process no longer exists, or that carry no owner label.
    async fn remove_leftovers(&self) {
        let list = tokio::time::timeout(
            DOCKER_CALL_LIMIT,
            Command::new(&self.docker_bin)
                .args([
                    "ps",
                    "-a",
                    "--filter",
                    &format!("label={POC_LABEL}"),
                    "--format",
                    &format!("{{{{.ID}}}} {{{{.Label \"{POC_OWNER_KEY}\"}}}}"),
                ])
                .stdin(Stdio::null())
                .output(),
        )
        .await;
        let Ok(Ok(out)) = list else { return };
        let me = std::process::id();
        for (id, owner) in parse_poc_listing(&String::from_utf8_lossy(&out.stdout)) {
            let alive = match owner {
                Some(pid) if pid != me => process_alive(pid).await,
                _ => false,
            };
            if is_leftover(owner, me, alive) {
                self.force_remove(&id).await;
            }
        }
    }

    async fn force_remove(&self, name: &str) {
        let _ = tokio::time::timeout(
            DOCKER_CALL_LIMIT,
            Command::new(&self.docker_bin)
                .args(["rm", "-f", name])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        )
        .await;
    }

    /// The `docker run` argument vector for one PoC. Pure, so the isolation
    /// flags are unit-tested.
    pub fn run_args(&self, name: &str, workspace: &Path, cmd: &[String]) -> Vec<String> {
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
            "/tmp",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.push("--mount".to_string());
        args.push(format!(
            "type=bind,source={},target=/workspace,readonly",
            workspace.display()
        ));
        args.push(self.image.clone());
        // In-container hard limit too, so the PoC dies even if vettalon is
        // killed before its own timeout fires.
        args.extend(
            ["timeout", "-s", "KILL", IN_CONTAINER_LIMIT_SECS]
                .iter()
                .map(|s| s.to_string()),
        );
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
        let (file, cmd) = match language {
            "python" => (
                "poc.py",
                vec!["python3".to_string(), "/workspace/poc.py".to_string()],
            ),
            "bash" => (
                "poc.sh",
                vec!["bash".to_string(), "/workspace/poc.sh".to_string()],
            ),
            other => return Err(format!("unsupported PoC language {other:?}")),
        };
        let scratch = tempfile::Builder::new()
            .prefix("vettalon-poc-")
            .tempdir()
            .map_err(|e| format!("cannot create temp workspace: {e}"))?;
        let path = scratch.path().join(file);
        std::fs::write(&path, script).map_err(|e| format!("cannot write poc script: {e}"))?;
        // The container runs as nobody; the mounted dir and script must be
        // world-readable (they hold only the generated PoC).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        }

        let name = format!("vettalon-poc-{}", uuid::Uuid::new_v4().simple());
        let args = self.run_args(&name, scratch.path(), &cmd);
        let mut child = Command::new(&self.docker_bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("container create failed: {e}"))?;

        // If this future is dropped mid-run (the scan was cancelled), killing
        // the `docker run` client does not stop the container; the guard
        // removes it. Disarmed once the run has finished on its own.
        let mut guard = ContainerGuard::new(&self.docker_bin, &name);

        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let collect = async {
            let (out, err) = tokio::join!(
                crate::util::read_capped(stdout, OUTPUT_CAP_BYTES),
                crate::util::read_capped(stderr, OUTPUT_CAP_BYTES)
            );
            let status = child.wait().await;
            (
                status,
                out.map(|(b, _)| b).unwrap_or_default(),
                err.map(|(b, _)| b).unwrap_or_default(),
            )
        };
        let collected = tokio::time::timeout(timeout, collect).await;
        guard.disarm();
        match collected {
            Ok((Ok(status), out, err)) => {
                let mut combined = String::from_utf8_lossy(&out).to_string();
                combined.push_str(&String::from_utf8_lossy(&err));
                let combined = crate::util::truncate_bytes(&combined, OUTPUT_CAP_BYTES).to_string();
                match status.code() {
                    Some(c) if is_docker_failure(c, &combined) => Err(format!(
                        "container start failed (docker exit {c}): {}",
                        crate::util::truncate_bytes(combined.trim(), 300)
                    )),
                    Some(c) => Ok((c as i64, combined)),
                    None => Err("container terminated by a signal".to_string()),
                }
            }
            Ok((Err(e), _, _)) => Err(format!("container wait failed: {e}")),
            Err(_) => {
                self.force_remove(&name).await;
                Err(format!(
                    "container execution exceeded the {}s hard timeout",
                    timeout.as_secs()
                ))
            }
        }
    }
}

/// Removes a PoC container when dropped while still armed, i.e. when the run
/// that owns it was cancelled before the container exited. `Drop` cannot
/// await, so `docker rm -f` runs on a detached thread that reaps it.
struct ContainerGuard {
    docker_bin: String,
    name: String,
    armed: bool,
}

impl ContainerGuard {
    fn new(docker_bin: &str, name: &str) -> Self {
        ContainerGuard {
            docker_bin: docker_bin.to_string(),
            name: name.to_string(),
            armed: true,
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
        let mut cmd = std::process::Command::new(&self.docker_bin);
        cmd.args(["rm", "-f", &self.name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        std::thread::spawn(move || {
            let _ = cmd.status();
        });
    }
}

/// `docker run` exits 125 when docker itself fails; 126/127 are also what a
/// script's own shell returns for "not executable" / "command not found",
/// so those count as docker's only when docker's own error text is present.
fn is_docker_failure(code: i32, output: &str) -> bool {
    match code {
        125 => true,
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
    if !cfg!(unix) {
        return true;
    }
    match Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .output()
        .await
    {
        Ok(out) => {
            out.status.success() || String::from_utf8_lossy(&out.stderr).contains("not permitted")
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_args_label_the_owning_process() {
        let sb = DockerSandbox {
            docker_bin: "docker".into(),
            image: "img".into(),
        };
        let a = sb.run_args("n", Path::new("/tmp/x"), &["true".into()]);
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
        let a = sb.run_args(
            "n",
            Path::new("/tmp/x"),
            &["python3".into(), "/workspace/poc.py".into()],
        );
        for flag in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--rm",
        ] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}: {a:?}");
        }
        assert!(
            a.iter()
                .any(|x| x == "type=bind,source=/tmp/x,target=/workspace,readonly")
        );
        for flag in ["--pull=never", "--memory-swap=512m", "vettalon.poc=1"] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}");
        }
        let user = a.iter().position(|x| x == "--user").unwrap();
        assert_ne!(a[user + 1], "0");
        // The image comes right before the command.
        let img = a.iter().position(|x| x == "img").unwrap();
        assert_eq!(
            &a[img + 1..],
            &[
                "timeout",
                "-s",
                "KILL",
                "125",
                "python3",
                "/workspace/poc.py"
            ]
        );
    }

    #[test]
    fn script_exit_127_is_the_scripts_own_result() {
        assert!(is_docker_failure(125, ""));
        assert!(!is_docker_failure(127, "bash: curl: command not found"));
        assert!(is_docker_failure(
            127,
            "docker: Error response from daemon: OCI runtime create failed"
        ));
        assert!(!is_docker_failure(1, "OCI runtime"));
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

    /// Real Docker: offline, non-root. Needs the default image pulled.
    #[tokio::test]
    #[ignore = "requires a Docker daemon + python:3.12-slim present locally"]
    async fn docker_sandbox_runs_python_offline_as_non_root() {
        let sb = DockerSandbox::detect(DEFAULT_POC_IMAGE)
            .await
            .expect("docker + image");
        let script = r#"import os, socket
print('SANDBOX_OK', 6 * 7)
print('UID', os.getuid())
try:
    socket.create_connection(('1.1.1.1', 53), timeout=1)
    print('NET_OPEN')
except OSError:
    print('NET_BLOCKED')
"#;
        let (code, out) = sb
            .run_script(script, "python", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("SANDBOX_OK 42"), "{out}");
        assert!(out.contains("NET_BLOCKED"), "{out}");
        assert!(!out.contains("UID 0\n"), "{out}");
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
        assert_eq!(calls.trim(), "rm -f cancelled");
    }
}
