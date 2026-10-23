//! Running the fixed template in the Joern container: one run per
//! (source tree, frontend), every claimed location of that frontend asked
//! in the same run.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::process::Command;

use super::keep::{JoernVerdict, KeepRule};
use super::query::{self, KeepQuery, QueryOutcome, RunResult};
use super::{JoernLang, TEMPLATE};

pub const DEFAULT_TIMEOUT_SECS: u64 = 900;
pub const MIN_TIMEOUT_SECS: u64 = 30;
pub const MAX_TIMEOUT_SECS: u64 = 7200;

/// Label on every Joern container, so an operator can find leftovers of a
/// killed run (`docker ps -a --filter label=vettalon.joern=1`). The
/// in-container `timeout` ends each one anyway.
const JOERN_LABEL: &str = "vettalon.joern=1";
/// Container memory (RAM and swap together) and the JVM heap inside it. The
/// frontend runs as a second JVM next to the console (Joern starts it with
/// its own -Xmx1536m), so the console heap leaves room for it.
const MEMORY_LIMIT: &str = "6g";
const JAVA_OPTS: &str = "JAVA_OPTS=-Xmx3g";
const CPUS: &str = "2";
const PIDS_LIMIT: &str = "--pids-limit=1024";
/// The container's /tmp. `exec` is required: Joern's storage loads a JNI
/// library (zstd) it unpacks there, and the frontends unpack helpers there.
const TMPFS: &str = "/tmp:rw,exec,nosuid,nodev,size=2g";
/// Result file and log are read back at most this large.
const RESULT_CAP_BYTES: u64 = 1024 * 1024;
const LOG_TAIL_BYTES: u64 = 2048;
const DOCKER_CALL_LIMIT: Duration = Duration::from_secs(60);
/// Shell run inside the container: no value is interpolated into it; the
/// timeout arrives as `$1`. It records the cgroup's peak memory for the
/// resource estimate. `umask 000` keeps what Joern writes under /work
/// removable by the host user on Linux (the files belong to uid 10002), so
/// the temp dir and its CPG are cleaned up after the run.
const INNER_SCRIPT: &str = "umask 000; timeout -s KILL \"$1\" /opt/joern-cli/joern --script /in/keep_path.sc \
> /work/joern.log 2>&1; rc=$?; cat /sys/fs/cgroup/memory.peak > /work/memory.peak 2>/dev/null; exit $rc";

/// Settings of one `--joern-keep` / `joern check` run.
#[derive(Debug, Clone)]
pub struct JoernSettings {
    pub image: String,
    pub timeout_secs: u64,
    pub rule: KeepRule,
}

impl JoernSettings {
    pub fn new(timeout_secs: u64) -> Self {
        JoernSettings {
            image: crate::llm::container::joern_image().to_string(),
            timeout_secs: timeout_secs.clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS),
            rule: KeepRule::default(),
        }
    }
}

/// What one container run cost (for the S3 resource estimate).
#[derive(Debug, Clone, Default, Serialize)]
pub struct RunStats {
    pub wall_secs: f64,
    /// cgroup v2 `memory.peak` of the container (includes page cache).
    pub peak_memory_bytes: Option<u64>,
}

/// One container run, as reported by `joern check`.
#[derive(Debug, Clone, Serialize)]
pub struct LangRun {
    pub lang: JoernLang,
    pub queries: usize,
    /// `ok`, or why the run gave no answers.
    pub status: String,
    pub source_nodes: Option<usize>,
    #[serde(flatten)]
    pub stats: RunStats,
}

/// One claimed location to check.
#[derive(Debug, Clone)]
pub struct ItemCheck {
    pub file: String,
    pub line: Option<u32>,
}

/// The `docker run` argv for one template run. Pure, so the isolation flags
/// are unit-tested.
pub fn run_args(
    name: &str,
    image: &str,
    src: &Path,
    input: &Path,
    work: &Path,
    timeout_secs: u64,
) -> Vec<String> {
    let mut a: Vec<String> = [
        "run",
        "--rm",
        "--name",
        name,
        "--label",
        JOERN_LABEL,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--tmpfs",
        TMPFS,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        "10002:10002",
        PIDS_LIMIT,
        &format!("--memory={MEMORY_LIMIT}"),
        &format!("--memory-swap={MEMORY_LIMIT}"),
        &format!("--cpus={CPUS}"),
        "--env",
        "HOME=/tmp",
        "--env",
        JAVA_OPTS,
        "--workdir",
        "/work",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (source, target, ro) in [
        (src, "/src", true),
        (input, "/in", true),
        (work, "/work", false),
    ] {
        a.push("--mount".into());
        a.push(format!(
            "type=bind,source={},target={target}{}",
            source.display(),
            if ro { ",readonly" } else { "" }
        ));
    }
    a.push(image.to_string());
    a.extend(
        ["sh", "-c", INNER_SCRIPT, "sh"]
            .iter()
            .map(|s| s.to_string()),
    );
    a.push(timeout_secs.to_string());
    a
}

/// A host path is passed inside `--mount type=bind,source=...`; a comma,
/// `=` or control character could add mount options. Refuse those.
fn mount_safe(p: &Path) -> Result<(), String> {
    let s = p.to_str().ok_or("path is not UTF-8")?;
    if !p.is_absolute() || s.chars().any(|c| c == ',' || c == '=' || c.is_control()) {
        return Err(format!(
            "cannot mount {s:?} safely (absolute path without `,` or `=` required)"
        ));
    }
    Ok(())
}

async fn docker_quiet(bin: &str, args: &[&str]) -> bool {
    matches!(
        tokio::time::timeout(
            DOCKER_CALL_LIMIT,
            Command::new(bin)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        )
        .await,
        Ok(Ok(s)) if s.success()
    )
}

/// Docker and the image are both here, or why not.
async fn preflight(image: &str) -> Result<String, String> {
    let bin = crate::util::which_cli("docker").ok_or("docker CLI not found on PATH")?;
    if !docker_quiet(&bin, &["image", "inspect", "--format", "{{.Id}}", image]).await {
        return Err(format!(
            "Joern image {image} is not built (run `vettalon joern build`)"
        ));
    }
    Ok(bin)
}

/// Read a file the container wrote. Only called after the container has
/// exited and been removed, so nothing can swap the path afterwards; a
/// symlink, FIFO or other non-regular file (a compromised container could
/// leave one to make the host read its own files or block) is refused.
fn read_capped(p: &Path, cap: u64) -> Result<String, String> {
    use std::io::{Read, Seek, SeekFrom};
    let meta = std::fs::symlink_metadata(p).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", p.display()));
    }
    let mut f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    if !f.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("{} is not a regular file", p.display()));
    }
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    if len > cap {
        f.seek(SeekFrom::Start(len - cap))
            .map_err(|e| e.to_string())?;
    }
    let mut buf = Vec::new();
    f.take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn log_hint(work: &Path) -> String {
    read_capped(&work.join("joern.log"), LOG_TAIL_BYTES)
        .ok()
        .and_then(|t| {
            t.lines()
                .rev()
                .find(|l| l.contains("Exception") || l.contains("rror"))
                .map(query::clean_text)
        })
        .unwrap_or_default()
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
}
#[cfg(not(unix))]
fn set_mode(_p: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

/// Ask one frontend's queries about `src` in one container run.
pub async fn run_template(
    src: &Path,
    lang: JoernLang,
    queries: &[KeepQuery],
    s: &JoernSettings,
) -> (Result<RunResult, String>, RunStats) {
    let mut stats = RunStats::default();
    let r = run_template_inner(src, lang, queries, s, &mut stats).await;
    (r, stats)
}

async fn run_template_inner(
    src: &Path,
    lang: JoernLang,
    queries: &[KeepQuery],
    s: &JoernSettings,
    stats: &mut RunStats,
) -> Result<RunResult, String> {
    let params = query::render_params(lang, queries)?;
    mount_safe(src)?;
    let bin = preflight(&s.image).await?;
    let tmp = tempfile::Builder::new()
        .prefix("vettalon-joern-")
        .tempdir()
        .map_err(|e| format!("cannot create a temp dir: {e}"))?;
    let input = tmp.path().join("in");
    let work = tmp.path().join("work");
    for d in [&input, &work] {
        std::fs::create_dir(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    }
    std::fs::write(input.join("keep_path.sc"), TEMPLATE).map_err(|e| e.to_string())?;
    std::fs::write(input.join("params.tsv"), params).map_err(|e| e.to_string())?;
    // The container user (uid 10002) reads in/ and writes work/.
    set_mode(&input, 0o755)?;
    set_mode(&input.join("keep_path.sc"), 0o644)?;
    set_mode(&input.join("params.tsv"), 0o644)?;
    set_mode(&work, 0o777)?;
    mount_safe(&input)?;
    mount_safe(&work)?;
    let name = format!(
        "vettalon-joern-{}-{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let args = run_args(&name, &s.image, src, &input, &work, s.timeout_secs);
    let started = Instant::now();
    let child = Command::new(&bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status();
    // Host-side limit a little above the in-container one (JVM shutdown).
    let outer = Duration::from_secs(s.timeout_secs + 60);
    let status = tokio::time::timeout(outer, child).await;
    stats.wall_secs = started.elapsed().as_secs_f64();
    if !matches!(status, Ok(Ok(_))) {
        // Stop the container before reading anything it wrote.
        let _ = docker_quiet(&bin, &["rm", "-f", &name]).await;
    }
    stats.peak_memory_bytes = read_capped(&work.join("memory.peak"), 64)
        .ok()
        .and_then(|t| t.trim().parse().ok());
    let status = match status {
        Ok(Ok(st)) => st,
        Ok(Err(e)) => return Err(format!("cannot run docker: {e}")),
        Err(_) => return Err(format!("timed out after {} s", s.timeout_secs)),
    };
    if status.code() == Some(137) {
        return Err(format!(
            "killed (timeout {} s or memory limit {MEMORY_LIMIT})",
            s.timeout_secs
        ));
    }
    if !status.success() {
        return Err(format!(
            "Joern exited with {}: {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or("a signal".into()),
            log_hint(&work)
        ));
    }
    let result_path = work.join("result.tsv");
    let len = std::fs::symlink_metadata(&result_path)
        .map_err(|_| format!("Joern wrote no result: {}", log_hint(&work)))?
        .len();
    if len > RESULT_CAP_BYTES {
        return Err("Joern result is too large".into());
    }
    let text = read_capped(&result_path, RESULT_CAP_BYTES)?;
    let ids: Vec<usize> = queries.iter().map(|q| q.id).collect();
    query::parse_result(&text, &ids)
}

/// Check every item against `src`: group by frontend, one run per frontend,
/// in a fixed order. Returns one verdict per item (same order) and one
/// report per run.
pub async fn check_items(
    src: &Path,
    items: &[ItemCheck],
    s: &JoernSettings,
) -> (Vec<JoernVerdict>, Vec<LangRun>) {
    let mut verdicts: Vec<Option<JoernVerdict>> = vec![None; items.len()];
    let mut groups: BTreeMap<JoernLang, Vec<KeepQuery>> = BTreeMap::new();
    for (i, it) in items.iter().enumerate() {
        let Some(lang) = JoernLang::from_path(&it.file) else {
            verdicts[i] = Some(JoernVerdict::Skipped(
                "no Joern frontend for this file type".into(),
            ));
            continue;
        };
        match query::query(i, &it.file, it.line) {
            Ok(q) => groups.entry(lang).or_default().push(q),
            Err(e) => verdicts[i] = Some(JoernVerdict::Skipped(e)),
        }
    }
    let mut runs = Vec::new();
    for (lang, qs) in groups {
        let (r, stats) = run_template(src, lang, &qs, s).await;
        let (status, source_nodes) = match &r {
            Ok(res) => ("ok".to_string(), Some(res.source_nodes)),
            Err(e) => (e.clone(), None),
        };
        runs.push(LangRun {
            lang,
            queries: qs.len(),
            status,
            source_nodes,
            stats,
        });
        for q in &qs {
            verdicts[q.id] = Some(match &r {
                Ok(res) => match res.outcomes.get(&q.id) {
                    Some(QueryOutcome::NoFile) => JoernVerdict::Error(
                        "claimed file is not in the CPG (missing, unreadable or not parsed)".into(),
                    ),
                    Some(o) => JoernVerdict::Answered(o.clone()),
                    None => JoernVerdict::Error("no answer for this query".into()),
                },
                Err(e) => JoernVerdict::Error(e.clone()),
            });
        }
    }
    let verdicts = verdicts
        .into_iter()
        .map(|v| v.unwrap_or_else(|| JoernVerdict::Error("not checked".into())))
        .collect();
    (verdicts, runs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn args() -> Vec<String> {
        run_args(
            "vettalon-joern-1-abc",
            "vettalon-joern:0123456789ab",
            &PathBuf::from("/repo"),
            &PathBuf::from("/tmp/x/in"),
            &PathBuf::from("/tmp/x/work"),
            900,
        )
    }

    #[test]
    fn analysis_runs_isolated() {
        let a = args();
        for flag in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pull=never",
            "--pids-limit=1024",
            "--memory=6g",
            "--memory-swap=6g",
            "--cpus=2",
            "--rm",
        ] {
            assert!(a.iter().any(|x| x == flag), "{flag}");
        }
        let user = a.iter().position(|x| x == "--user").unwrap();
        assert_eq!(a[user + 1], "10002:10002");
        assert!(a.contains(&"type=bind,source=/repo,target=/src,readonly".to_string()));
        assert!(a.contains(&"type=bind,source=/tmp/x/in,target=/in,readonly".to_string()));
        assert!(a.contains(&"type=bind,source=/tmp/x/work,target=/work".to_string()));
        // Exactly three mounts, no network flag other than none, no privileged.
        assert_eq!(a.iter().filter(|x| *x == "--mount").count(), 3);
        assert!(
            !a.iter()
                .any(|x| x.starts_with("--network") && x != "--network=none")
        );
        assert!(
            !a.iter()
                .any(|x| x.contains("privileged") || x.contains("docker.sock"))
        );
        // The in-container script is constant; the timeout is its argument.
        let image = a
            .iter()
            .position(|x| x == "vettalon-joern:0123456789ab")
            .unwrap();
        assert_eq!(&a[image + 1..image + 3], ["sh", "-c"]);
        assert_eq!(a[image + 3], INNER_SCRIPT);
        assert_eq!(a.last().unwrap(), "900");
    }

    #[cfg(unix)]
    #[test]
    fn container_written_symlinks_and_fifos_are_not_read() {
        let d = tempfile::tempdir().unwrap();
        let secret = d.path().join("host-secret");
        std::fs::write(&secret, "token Error here\n").unwrap();
        let link = d.path().join("joern.log");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(read_capped(&link, 100).is_err());
        let fifo = d.path().join("memory.peak");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if made.map(|s| s.success()).unwrap_or(false) {
            // Must return at once, not block on the FIFO.
            assert!(read_capped(&fifo, 64).is_err());
        }
        let plain = d.path().join("result.tsv");
        std::fs::write(&plain, "abc").unwrap();
        assert_eq!(read_capped(&plain, 2).unwrap(), "bc");
    }

    #[test]
    fn mount_sources_with_option_characters_are_refused() {
        assert!(mount_safe(Path::new("/repo/a")).is_ok());
        for bad in ["/a,readonly=false", "/a=b", "relative", "/a\nb"] {
            assert!(mount_safe(Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn unsupported_or_unusable_items_are_skipped_without_docker() {
        let s = JoernSettings {
            image: "vettalon-joern:does-not-exist".into(),
            timeout_secs: 30,
            rule: KeepRule::Strict,
        };
        let items = vec![
            ItemCheck {
                file: "README.md".into(),
                line: Some(1),
            },
            ItemCheck {
                file: "../x.php".into(),
                line: Some(1),
            },
            ItemCheck {
                file: "a.php".into(),
                line: None,
            },
        ];
        let (v, runs) = check_items(Path::new("/nonexistent"), &items, &s).await;
        assert!(runs.is_empty());
        assert!(
            v.iter().all(|x| matches!(x, JoernVerdict::Skipped(_))),
            "{v:?}"
        );
    }

    #[tokio::test]
    async fn a_missing_image_is_an_error_with_no_answers() {
        let s = JoernSettings {
            image: "vettalon-joern:does-not-exist-000".into(),
            timeout_secs: 30,
            rule: KeepRule::Strict,
        };
        let d = tempfile::tempdir().unwrap();
        let items = vec![ItemCheck {
            file: "a.php".into(),
            line: Some(1),
        }];
        let (v, runs) = check_items(d.path(), &items, &s).await;
        assert_eq!(runs.len(), 1);
        assert_ne!(runs[0].status, "ok");
        assert!(matches!(v[0], JoernVerdict::Error(_)), "{v:?}");
    }
}
