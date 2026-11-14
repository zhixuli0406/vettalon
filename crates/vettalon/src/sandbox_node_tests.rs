fn node_sandbox() -> DockerSandbox {
    DockerSandbox {
        docker_bin: "docker".into(),
        image: "node-image".into(),
    }
}

fn node_install_inputs() -> (Vec<u8>, Vec<u8>) {
    let manifest = serde_json::json!({"dependencies": {"is-number": "7.0.0"}});
    let lock = serde_json::json!({
        "lockfileVersion": 3,
        "packages": {
            "": manifest,
            "node_modules/is-number": {
                "version": "7.0.0",
                "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
                // Syntactically valid test-only integrity; never used live.
                "integrity": format!("sha512-{}==", "A".repeat(86))
            }
        }
    });
    (
        serde_json::to_vec(&manifest).unwrap(),
        serde_json::to_vec(&lock).unwrap(),
    )
}

#[test]
fn node_install_argv_has_exact_mounts_environment_and_limits() {
    let args = node_sandbox()
        .install_run_args("n", Path::new("/private/deps"))
        .unwrap();
    let mounts: Vec<_> = args
        .windows(2)
        .filter(|w| w[0] == "--mount")
        .map(|w| w[1].as_str())
        .collect();
    assert_eq!(mounts, ["type=bind,source=/private/deps,target=/deps",]);
    assert_eq!(
        mounts.iter().filter(|m| !m.ends_with(",readonly")).count(),
        1
    );
    assert!(
        !args
            .iter()
            .any(|a| a.contains(".npmrc") || a.contains("/workspace"))
    );
    let env: Vec<_> = args
        .windows(2)
        .filter(|w| w[0] == "--env")
        .map(|w| w[1].as_str())
        .collect();
    let expected_env = [
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
    assert_eq!(env, expected_env);
    let image = args.iter().position(|a| a == "node-image").unwrap();
    assert_eq!(args[image + 1], "-i");
    assert_eq!(
        &args[image + 2..image + 2 + expected_env.len()],
        expected_env
    );
    assert_eq!(
        &args[image + 2 + expected_env.len()..],
        [
            "timeout",
            "-s",
            "KILL",
            "300",
            "/bin/sh",
            "-c",
            &node_install_command(),
        ]
    );
    assert!(
        args.windows(2)
            .any(|w| w == ["--entrypoint", "/usr/bin/env"])
    );
    for flag in [
        "--pull=never",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--memory=1792m",
        "--memory-swap=1792m",
        "--cpus=2",
        "--init=false",
        "--rm",
    ] {
        assert!(args.iter().any(|a| a == flag), "{flag}");
    }
    for pair in [
        ["--user", "65534:65534"],
        ["--tmpfs", "/tmp:rw,noexec,nosuid,size=256m"],
        ["--ulimit", "nofile=256:256"],
        ["--ulimit", "fsize=67108864:67108864"],
    ] {
        assert!(args.windows(2).any(|w| w == pair));
    }
    assert_eq!(NODE_INSTALL_LIMIT, Duration::from_secs(300));
    assert!(node_install_command().contains(
        "npm ci --ignore-scripts --no-audit --no-fund --bin-links=false --prefer-online"
    ));
    assert!(!node_install_command().contains("--omit"));
}

#[test]
fn node_install_work_tmpfs_has_byte_inode_and_owner_limits() {
    use crate::audit::node::deps::{MAX_BYTES, MAX_ENTRIES};
    let args = node_sandbox()
        .install_run_args("n", Path::new("/deps"))
        .unwrap();
    let tmpfs: Vec<_> = args
        .windows(2)
        .filter(|w| w[0] == "--tmpfs")
        .map(|w| w[1].as_str())
        .collect();
    assert_eq!(
        tmpfs,
        [
            "/tmp:rw,noexec,nosuid,size=256m",
            "/work:rw,nosuid,nodev,noexec,size=603979776,nr_inodes=121000,mode=0700,uid=65534,gid=65534",
        ]
    );
    assert_eq!(NODE_INSTALL_TMPFS_BYTES, MAX_BYTES + 64 * 1024 * 1024);
    assert_eq!(NODE_INSTALL_TMPFS_INODES, MAX_ENTRIES + 1_000);
    assert!(args.windows(2).any(|w| w == ["--workdir", "/work"]));
}

#[test]
fn node_install_shell_checks_before_copy_and_never_chmods_deps_root() {
    use crate::audit::node::deps::{MAX_BYTES, MAX_ENTRIES, MAX_FILES};
    let command = node_install_command();
    assert!(command.starts_with("umask 077; : > /tmp/npmrc-user; : > /tmp/npmrc-global; "));
    assert!(!command.contains("umask 000"));
    assert!(command.contains("find /deps -mindepth 1 -type d -exec chmod 0777"));
    let steps = [
        "python3 -I -B -c",
        "npm ci --ignore-scripts --no-audit --no-fund --bin-links=false --prefer-online",
        "status=$?; [ \"$status\" -eq 0 ] || exit \"$status\";",
        "find /work -xdev -printf '.' > /tmp/install-entries || exit 1;",
        "entries=$(wc -c < /tmp/install-entries) || exit 1;",
        "find /work -xdev -type f -printf '.' > /tmp/install-files || exit 1;",
        "files=$(wc -c < /tmp/install-files) || exit 1;",
        "du -sbl /work > /tmp/install-bytes || exit 1;",
        "read -r bytes path < /tmp/install-bytes || exit 1;",
    ];
    let mut remaining = command.as_str();
    for step in steps {
        remaining = remaining
            .split_once(step)
            .expect("missing or reordered step")
            .1;
    }
    assert_eq!(
        remaining,
        format!(
            " [ \"$entries\" -le {MAX_ENTRIES} ] && [ \"$files\" -le {MAX_FILES} ] && \
             [ \"$bytes\" -le {MAX_BYTES} ] || exit 86; \
             cp -RP /work/node_modules /deps/ && \
             find /deps -mindepth 1 -type d -exec chmod 0777 {{}} + && \
             find /deps -mindepth 1 -type f -exec chmod 0644 {{}} + || exit 1"
        )
    );
    // Every dependency chmod is anchored below /deps, never at its host-owned root.
    let chmods: Vec<_> = command
        .split(" && ")
        .filter(|s| s.contains("-exec chmod "))
        .collect();
    assert_eq!(chmods.len(), 2);
    assert!(
        chmods
            .iter()
            .all(|s| s.starts_with("find /deps -mindepth 1 -type "))
    );
}

#[test]
fn node_install_shell_counts_hardlinks_and_preserves_them_on_copy() {
    let command = node_install_command();
    assert!(command.contains("du -sbl /work"));
    assert!(command.contains("cp -RP /work/node_modules /deps/"));
    assert!(!command.contains("du -sb "));
    assert!(!command.contains("cp -R "));
}

#[test]
fn node_install_is_the_only_networked_argv_builder() {
    let sb = node_sandbox();
    let cmd = vec!["python3".into(), "/workspace/runner.py".into()];
    let mounts = [
        (Path::new("/scratch"), "/workspace"),
        (Path::new("/tree"), "/workspace/tree"),
        (Path::new("/deps"), NODE_DEPS_MOUNT),
    ];
    let mut builders = vec![
        sb.run_args("n", &cmd),
        sb.run_args_mounted("n", &mounts, "/workspace", &cmd),
    ];
    // Cover every mode of the shared builder, including each workspace form,
    // tree execution, both PID-1 modes and stdin/no stdin.
    for count in 0..=mounts.len() {
        for pid1 in [Pid1::Timeout, Pid1::Command] {
            for interactive in [false, true] {
                builders.push(sb.build_run_args(
                    "n",
                    &mounts[..count],
                    "/tmp",
                    interactive,
                    pid1,
                    &cmd,
                ));
            }
        }
    }
    builders.push(sb.install_run_args("n", Path::new("/deps")).unwrap());
    for (index, args) in builders.iter().enumerate() {
        let network: Vec<_> = args.iter().filter(|a| a.starts_with("--network")).collect();
        assert_eq!(
            network,
            vec![if index + 1 == builders.len() {
                "--network=bridge"
            } else {
                "--network=none"
            }]
        );
    }
}

#[test]
fn node_install_refuses_ambiguous_mount_paths() {
    let sb = node_sandbox();
    for bad in ["/tmp/a,readonly", "relative", "/tmp/a\0b"] {
        assert_eq!(
            sb.install_run_args("n", Path::new(bad)),
            Err(NODE_INSTALL_FAILED)
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn node_install_validates_exact_bytes_and_skips_empty_deps_before_docker() {
    let fake = FakeDocker::new(FAKE_DOCKER_OK);
    let sb = DockerSandbox {
        docker_bin: fake.bin.clone(),
        ..node_sandbox()
    };
    let (manifest, lock) = node_install_inputs();
    let refused = sb.run_install(b"not json", &lock).await.unwrap_err();
    assert_eq!(refused, "node_lockfile_refused");
    let bad_url = String::from_utf8(lock.clone())
        .unwrap()
        .replace("registry.npmjs.org", "169.254.169.254");
    assert_eq!(
        sb.run_install(&manifest, bad_url.as_bytes())
            .await
            .unwrap_err(),
        "node_lockfile_refused"
    );
    assert_eq!(
        sb.run_install(br#"{"dependencies":{"unlocked":"1.0.0"}}"#, &lock)
            .await
            .unwrap_err(),
        "node_lockfile_refused"
    );
    let empty = br#"{"lockfileVersion":3,"packages":{"":{}}}"#;
    assert_eq!(
        sb.run_install(&manifest, empty).await.unwrap_err(),
        "node_lockfile_refused"
    );
    assert!(sb.run_install(b"{}", empty).await.unwrap().is_none());
    assert!(fake.calls().is_empty());
}

#[cfg(unix)]
const FAKE_NODE_INSTALL: &str = r#"
case "$1" in
run)
  for arg do
    case "$arg" in
      type=bind,source=*,target=/deps) output=${arg#type=bind,source=}; output=${output%,target=/deps} ;;
    esac
  done
  printf '%s' "$output" > output-path
  python3 -I -B -c '
import os, sys
os.umask(0o077)
for name in ("manifest-seen", "lock-seen"):
    size = int(sys.stdin.buffer.readline())
    with open(name, "wb") as output:
        output.write(sys.stdin.buffer.read(size))
assert not sys.stdin.buffer.read(1)
' || exit 98
  ls -ld "$output" | cut -c1-10 > output-mode
  ls -ld "${output%/*}" | cut -c1-10 > parent-mode
  mkdir -p "$output/node_modules/is-number"
  printf 'module.exports = () => true;\n' > "$output/node_modules/is-number/index.js"
  ;;
ps|rm) ;;
*) exit 99 ;;
esac
"#;

#[cfg(unix)]
#[tokio::test]
async fn node_install_uses_private_validated_inputs_and_returns_owned_digest() {
    let fake = FakeDocker::new(FAKE_NODE_INSTALL);
    let sb = DockerSandbox {
        docker_bin: fake.bin.clone(),
        ..node_sandbox()
    };
    let (manifest, lock) = node_install_inputs();
    let installed = sb.run_install(&manifest, &lock).await.unwrap().unwrap();
    assert_eq!(
        std::fs::read(fake.dir.path().join("manifest-seen")).unwrap(),
        manifest
    );
    assert_eq!(
        std::fs::read(fake.dir.path().join("lock-seen")).unwrap(),
        lock
    );
    use std::os::unix::fs::PermissionsExt;
    for name in ["manifest-seen", "lock-seen"] {
        assert_eq!(
            std::fs::metadata(fake.dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(!fake.calls().contains("target=/input/"));
    assert_eq!(
        std::fs::read_to_string(fake.dir.path().join("output-mode"))
            .unwrap()
            .trim(),
        "drwx-wx-wx"
    );
    assert_eq!(
        std::fs::read_to_string(fake.dir.path().join("parent-mode"))
            .unwrap()
            .trim(),
        "drwx------"
    );
    assert_eq!(
        installed.digest,
        crate::audit::node::deps::digest(&installed.path).unwrap()
    );
    assert_eq!(
        installed.lockfile.lockfile_sha256,
        crate::audit::schema::sha256_hex(&lock)
    );
    assert_eq!(installed.digest.files, 1);
    assert_eq!(
        fake.calls()
            .lines()
            .filter(|l| l.starts_with("run "))
            .count(),
        1
    );
    let output = std::fs::read_to_string(fake.dir.path().join("output-path")).unwrap();
    assert!(!Path::new(&output).exists(), "raw install scratch leaked");
    let path = installed.path.clone();
    drop(installed);
    assert!(!path.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn node_install_maps_npm_runner_and_poisoned_deps_failures_to_environment() {
    let (manifest, lock) = node_install_inputs();
    for behavior in [
        "case \"$1\" in run) printf 'npm failure with secret'; exit 1 ;; ps|rm) ;; esac"
            .to_string(),
        "case \"$1\" in run) exit 125 ;; ps|rm) ;; esac".to_string(),
        FAKE_NODE_INSTALL.replace(
            "printf 'module.exports",
            "ln -s /etc/passwd \"$output/node_modules/escape\"\n  printf 'module.exports",
        ),
        FAKE_NODE_INSTALL.replace(
            "printf 'module.exports",
            "mkfifo \"$output/node_modules/pipe\"\n  printf 'module.exports",
        ),
        "case \"$1\" in run|ps|rm) ;; esac".to_string(),
    ] {
        let fake = FakeDocker::new(&behavior);
        let sb = DockerSandbox {
            docker_bin: fake.bin.clone(),
            ..node_sandbox()
        };
        assert_eq!(
            sb.run_install(&manifest, &lock).await.unwrap_err(),
            NODE_INSTALL_FAILED
        );
    }
    let fake = FakeDocker::new(&FAKE_NODE_INSTALL.replace(
        "printf 'module.exports", "dd if=/dev/zero of=\"$output/node_modules/huge\" bs=1 count=0 seek=536870913 2>/dev/null\n  printf 'module.exports"));
    let sb = DockerSandbox {
        docker_bin: fake.bin.clone(),
        ..node_sandbox()
    };
    assert_eq!(
        sb.run_install(&manifest, &lock).await.unwrap_err(),
        "node_deps_too_large"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn node_install_maps_container_quota_refusal_to_too_large() {
    // The installer consumes both input frames before checking quotas. Drain
    // stdin here too, so an early fake exit cannot race the writer with EPIPE.
    let fake = FakeDocker::new("case \"$1\" in run) cat >/dev/null; exit 86 ;; ps|rm) ;; esac");
    let sb = DockerSandbox {
        docker_bin: fake.bin.clone(),
        ..node_sandbox()
    };
    let (manifest, lock) = node_install_inputs();
    assert_eq!(
        sb.run_install(&manifest, &lock).await.unwrap_err(),
        "node_deps_too_large"
    );
    assert_eq!(
        fake.calls()
            .lines()
            .filter(|l| l.starts_with("run "))
            .count(),
        1
    );
}

#[cfg(unix)]
#[tokio::test]
async fn node_workspace_mounts_deps_readonly_and_rejects_comma_before_runner() {
    let fake = FakeDocker::new(FAKE_DOCKER_OK);
    let sb = DockerSandbox {
        docker_bin: fake.bin.clone(),
        ..node_sandbox()
    };
    let cmd = vec!["python3".into(), "/workspace/runner.py".into()];
    let result = sb
        .run_workspace_with_tree_and_deps(
            &[("runner.py", "print('ok')")],
            Path::new("/tree"),
            Path::new("/deps"),
            &cmd,
            Some("marker"),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(result.0, 0);
    let calls = fake.calls();
    assert!(calls.contains("type=bind,source=/deps,target=/workspace/tree/node_modules,readonly"));
    assert!(calls.contains("type=bind,source=/tree,target=/workspace/tree,readonly"));
    assert!(calls.contains("--network=none"));
    assert!(!calls.contains("--network=bridge"));
    assert!(calls.contains("--init=false node-image python3"));
    assert!(
        sb.run_workspace_with_tree_and_deps(
            &[],
            Path::new("/tree"),
            Path::new("/deps,readonly=false"),
            &cmd,
            None,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err()
        .contains("unsupported mount path")
    );
    assert_eq!(fake.calls(), calls);
}

/// Reviewer command and fixture generation: tests/fixtures/node-install/README.md.
#[tokio::test]
#[ignore = "requires `vettalon poc-node build`, Docker, network and real fixture lockfile"]
async fn docker_node_install_then_offline_exec() {
    use crate::audit::{
        fix_diff::{SnapshotMode, snapshot_with_mode},
        node::deps,
    };
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/node-install");
    let manifest = std::fs::read(fixture.join("package.json")).unwrap();
    let lock = std::fs::read(fixture.join("package-lock.json"))
        .expect("generate the real lockfile using tests/fixtures/node-install/README.md first");
    let sb = DockerSandbox::detect(default_node_poc_image())
        .await
        .unwrap();
    let installed = sb.run_install(&manifest, &lock).await.unwrap().unwrap();
    let snapshot = snapshot_with_mode(&fixture, SnapshotMode::Node).unwrap();
    let before = crate::audit::verification_context::snapshot_digest(&snapshot.path).unwrap();
    let probe = r#"import os, socket, subprocess
assert os.getuid() == 65534
for path in ('/workspace/tree/node_modules/probe', '/workspace/tree/probe', '/probe'):
    try:
        open(path, 'w').close()
    except OSError:
        pass
    else:
        raise AssertionError('writable: ' + path)
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    with socket.create_connection(listener.getsockname(), timeout=2):
        conn, _ = listener.accept()
        conn.close()
try:
    socket.create_connection(('1.1.1.1', 443), timeout=2).close()
except OSError:
    pass
else:
    raise AssertionError('external network available')
subprocess.run(['node', '--no-addons', '-e', "const assert=require('node:assert/strict'); const n=require('/workspace/tree/node_modules/is-number'); assert.equal(n(42),true); assert.equal(n('no'),false)"], check=True)
assert not os.path.exists('/workspace/tree/node_modules/.script-ran')
print('NODE_OFFLINE_OK')
"#;
    let (code, output) = sb
        .run_workspace_with_tree_and_deps(
            &[("runner.py", probe)],
            &snapshot.path,
            &installed.path,
            &[
                "python3".into(),
                "-I".into(),
                "-B".into(),
                "/workspace/runner.py".into(),
            ],
            None,
            Duration::from_secs(120),
        )
        .await
        .unwrap();
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("NODE_OFFLINE_OK"), "{output}");
    assert_eq!(installed.digest, deps::digest(&installed.path).unwrap());
    assert_eq!(
        before,
        crate::audit::verification_context::snapshot_digest(&snapshot.path).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn node_install_stdin_stage_creates_only_private_files() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (manifest, lock) = node_install_inputs();
    let mut child = std::process::Command::new("python3")
        .args(["-I", "-B", "-c", NODE_INSTALL_STAGE])
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(node_install_input(&manifest, &lock).unwrap().as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(entries.len(), 2);
    for entry in entries {
        assert_eq!(
            entry.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        let expected = match entry.file_name().to_str().unwrap() {
            "package.json" => &manifest,
            "package-lock.json" => &lock,
            other => panic!("unexpected staged file: {other}"),
        };
        assert_eq!(&std::fs::read(entry.path()).unwrap(), expected);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn node_fixture_is_stdin_only_during_fake_container_run() {
    use crate::audit::{
        node::{dispatch, fixture},
        poc_oracle::{OracleClass, OracleSecrets, node_target_runners},
        target_poc::{TargetCall, build_node_adapter},
    };
    const SECRET: &str = "private-token-never-on-disk-測試";
    let fake = FakeDocker::new(
        r#"
case "$1" in
run)
  case "$*" in *--version*) printf 'v22.14.0\n'; exit 0 ;; esac
  python3 -I -B -c '
import json, os, pathlib, stat, sys
args = sys.argv[1:]
secret = "private-token-never-on-disk-測試"
assert secret not in " ".join(args)
assert "fixture.json" not in " ".join(args)
marker = sys.stdin.buffer.read(int(sys.stdin.buffer.readline()))
fixture = sys.stdin.buffer.read(int(sys.stdin.buffer.readline()))
assert marker == b"vtlm11111111111111111111111111111111"
assert json.loads(fixture)["env"]["TOKEN"] == secret
assert not sys.stdin.buffer.read(1)
roots = []
for arg in args:
    if arg.startswith("type=bind,source="):
        source, target = arg[len("type=bind,source="):].split(",target=", 1)
        roots.append(pathlib.Path(source))
assert roots
for root in roots:
    for path in [root, *root.rglob("*")]:
        info = path.lstat()
        assert not path.is_symlink()
        if stat.S_ISREG(info.st_mode):
            assert path.name != "fixture.json"
            data = path.read_bytes()
            assert secret.encode() not in data
            if path.name in ("package.json", "package-lock.json"):
                assert info.st_mode & 0o077 == 0
        elif stat.S_ISDIR(info.st_mode):
            assert info.st_mode & 0o002 == 0
        else:
            raise AssertionError("unexpected scratch entry")
' "$@" || exit 98
  ;;
ps|rm) ;;
*) exit 99 ;;
esac
"#,
    );
    let sb = DockerSandbox {
        docker_bin: fake.bin.clone(),
        ..node_sandbox()
    };
    let tree = tempfile::tempdir().unwrap();
    let source = "module.exports.run = value => value;";
    std::fs::write(tree.path().join("app.cjs"), source).unwrap();
    let fixture = fixture::validate_fixture(
        serde_json::json!({
            "schema": fixture::FIXTURE_SCHEMA, "env": {"TOKEN": SECRET},
            "sql_setup": "CREATE TABLE private_setup(value TEXT);"
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let execution = dispatch::prepare(tree.path(), &sb, Some(fixture))
        .await
        .unwrap();
    let secrets = OracleSecrets {
        canary: "vtlc00000000000000000000000000000000".into(),
        marker: "vtlm11111111111111111111111111111111".into(),
    };
    let call: TargetCall = serde_json::from_value(
        serde_json::json!({"file":"app.cjs","function":"run","args":[{"kind":"payload"}]}),
    )
    .unwrap();
    let adapter = build_node_adapter(
        &call,
        &crate::audit::schema::sha256_hex(source.as_bytes()),
        OracleClass::CommandInjection,
    )
    .unwrap();
    for runner in node_target_runners(OracleClass::CommandInjection, &secrets, None) {
        assert!(!runner.contains(SECRET));
        assert!(!adapter.contains(SECRET));
        assert!(!runner.contains("fixture.json"));
        let (code, output) = execution
            .run(
                &sb,
                tree.path(),
                &runner,
                &adapter,
                &format!("{}\n", secrets.marker),
                OracleClass::CommandInjection,
            )
            .await
            .unwrap();
        assert_eq!(code, 0, "{output}");
    }
    assert!(!fake.calls().contains(SECRET));
}
