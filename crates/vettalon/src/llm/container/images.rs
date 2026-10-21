//! The container images: their definitions (embedded from `docker/`), the
//! tags derived from them, and how they get onto this machine
//! (`vettalon agents build` locally, or `vettalon agents pull` from GHCR with
//! signature verification). Only the grok-free base and the egress proxy
//! are ever published; grok is proprietary and always added locally.

use std::path::Path;
use std::process::Stdio;
use std::sync::LazyLock;

use tokio::process::Command;

use super::{docker, docker_bin};

const AGENTS_REPO: &str = "vettalon-agents";
const AGENTS_BASE_REPO: &str = "vettalon-agents-base";
const EGRESS_REPO: &str = "vettalon-egress";
/// Hex digits of the build-context digest used as the image tag.
const IMAGE_TAG_HEX_LEN: usize = 12;

/// Where `vettalon agents pull` gets the published images. Only the
/// grok-free base and the egress proxy are published; grok is proprietary
/// and always added locally.
pub const REGISTRY_PREFIX: &str = "ghcr.io/zhixuli0406/";
/// Keyless signer the published images must carry: the public repo's image
/// workflow, run from `main` (workflow_dispatch) or a release tag.
pub const SIGNER_IDENTITY_REGEXP: &str = r"^https://github\.com/zhixuli0406/vettalon/\.github/workflows/images\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$";
pub const SIGNER_ISSUER: &str = "https://token.actions.githubusercontent.com";

const AGENTS_DOCKERFILE: &str = include_str!("../../../../../docker/agents/Dockerfile");
const BASE_DOCKERFILE: &str = include_str!("../../../../../docker/agents-base/Dockerfile");
const BASE_INVENTORY: &str = include_str!("../../../../../docker/agents-base/inventory.js");
const EGRESS_DOCKERFILE: &str = include_str!("../../../../../docker/egress/Dockerfile");
const EGRESS_CONF: &str = include_str!("../../../../../docker/egress/tinyproxy.conf");
const EGRESS_ALLOWLIST: &str = include_str!("../../../../../docker/egress/allowlist");

macro_rules! base_license {
    ($rel:literal) => {
        (
            concat!("licenses/", $rel),
            include_str!(concat!("../../../../../docker/agents-base/licenses/", $rel)),
        )
    };
}

/// Build context of each image: `(path, contents)`, exactly what
/// [`build_images`] writes to disk. Every file under `docker/` belongs to
/// exactly one of these (a test checks it).
const BASE_CONTEXT: &[(&str, &str)] = &[
    ("Dockerfile", BASE_DOCKERFILE),
    ("inventory.js", BASE_INVENTORY),
    base_license!("codex/LICENSE"),
    base_license!("codex/NOTICE"),
    base_license!("codex/VERSION"),
    base_license!("codex-bwrap/COPYING"),
    base_license!("codex-zsh/LICENCE"),
    base_license!("node/LICENSE"),
    base_license!("node/VERSION"),
];
/// The local layer (grok on top of the base).
const AGENTS_CONTEXT: &[(&str, &str)] = &[("Dockerfile", AGENTS_DOCKERFILE)];
const EGRESS_CONTEXT: &[(&str, &str)] = &[
    ("Dockerfile", EGRESS_DOCKERFILE),
    ("tinyproxy.conf", EGRESS_CONF),
    ("allowlist", EGRESS_ALLOWLIST),
];

/// First [`IMAGE_TAG_HEX_LEN`] hex digits of a SHA-256 over every
/// `(name, body)` of a context.
fn context_digest(context: &[(&str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for (name, body) in context {
        // Length-prefixed so no two different contexts hash the same input.
        h.update((name.len() as u64).to_le_bytes());
        h.update(name.as_bytes());
        h.update((body.len() as u64).to_le_bytes());
        h.update(body.as_bytes());
    }
    hex::encode(h.finalize())[..IMAGE_TAG_HEX_LEN].to_string()
}

/// `repo:<digest>` where the digest covers every file of the build
/// context. The tag changes exactly when the image definition changes, so
/// a CLI upgrade that leaves `docker/` alone keeps using the built image,
/// and one that changes it can never run a stale image under the new tag.
fn image_ref(repo: &str, context: &[(&str, &str)]) -> String {
    format!("{repo}:{}", context_digest(context))
}

/// The local agents image is the base plus a local layer, so its tag covers
/// the base's tag as well as the layer's own files.
fn layered_image_ref(repo: &str, base_tag: &str, layer: &[(&str, &str)]) -> String {
    let mut ctx: Vec<(&str, &str)> = vec![("@base", base_tag)];
    ctx.extend_from_slice(layer);
    image_ref(repo, &ctx)
}

fn tag_of(image: &str) -> &str {
    image.rsplit_once(':').map(|(_, t)| t).unwrap_or(image)
}

static BASE_IMAGE: LazyLock<String> = LazyLock::new(|| image_ref(AGENTS_BASE_REPO, BASE_CONTEXT));
static AGENTS_IMAGE: LazyLock<String> =
    LazyLock::new(|| layered_image_ref(AGENTS_REPO, tag_of(&BASE_IMAGE), AGENTS_CONTEXT));
static EGRESS_IMAGE: LazyLock<String> = LazyLock::new(|| image_ref(EGRESS_REPO, EGRESS_CONTEXT));

/// The agents image this binary runs (`vettalon-agents:<definition digest>`).
pub fn agents_image() -> &'static str {
    &AGENTS_IMAGE
}

/// The grok-free base the agents image is built on (published to GHCR).
pub fn agents_base_image() -> &'static str {
    &BASE_IMAGE
}

/// The egress-proxy image this binary runs.
pub fn egress_image() -> &'static str {
    &EGRESS_IMAGE
}

/// What the user sees when an image this binary needs is not built yet.
/// Short enough to survive the 160-byte cut in `vettalon models --probe`.
pub(super) fn missing_image_error(image: &str) -> String {
    format!(
        "container image {image} is missing; run `vettalon agents pull` (or `agents build`); \
         needs Docker and network access"
    )
}

/// Write the three build contexts (`base/`, `agents/`, `egress/`) under a
/// temp dir: the same file lists the tags are derived from, so a tag always
/// names exactly what was built.
fn write_contexts() -> Result<tempfile::TempDir, String> {
    let ctx = tempfile::Builder::new()
        .prefix("vettalon-build-")
        .tempdir()
        .map_err(|e| format!("cannot create build dir: {e}"))?;
    for (dir, context) in [
        ("base", BASE_CONTEXT),
        ("agents", AGENTS_CONTEXT),
        ("egress", EGRESS_CONTEXT),
    ] {
        for (name, body) in context {
            let p = ctx.path().join(dir).join(name);
            std::fs::create_dir_all(p.parent().expect("has parent")).map_err(|e| e.to_string())?;
            std::fs::write(&p, body).map_err(|e| e.to_string())?;
        }
    }
    Ok(ctx)
}

/// `docker build` argv for one image. The local agents layer gets the base
/// it builds on as `BASE_IMAGE`.
fn build_args(tag: &str, base: Option<&str>, dir: &Path) -> Vec<String> {
    let mut a = vec!["build".to_string(), "-t".into(), tag.to_string()];
    if let Some(base) = base {
        a.push("--build-arg".into());
        a.push(format!("BASE_IMAGE={base}"));
    }
    a.push(dir.display().to_string());
    a
}

/// A long-running docker command (build, pull) with its output shown.
async fn docker_visible(docker_bin: &str, args: &[String]) -> Result<(), String> {
    let status = Command::new(docker_bin)
        .args(args)
        .stdin(Stdio::null())
        .status()
        .await
        .map_err(|e| format!("cannot run docker: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "docker {} failed",
            args.iter().take(3).cloned().collect::<Vec<_>>().join(" ")
        ))
    }
}

async fn build_local_layer(docker_bin: &str, base: &str, ctx: &Path) -> Result<(), String> {
    eprintln!(
        "[vettalon] {}",
        crate::tr!(
            "建置 {}（在 {base} 上加入 grok）…",
            "building {} (grok on top of {base})…",
            agents_image()
        )
    );
    docker_visible(
        docker_bin,
        &build_args(agents_image(), Some(base), &ctx.join("agents")),
    )
    .await
}

/// `vettalon agents build`: build every image from the definitions embedded
/// in this binary, nothing pulled from GHCR. Needs network access (package
/// downloads).
pub async fn build_images() -> Result<(), String> {
    let bin = docker_bin()?;
    let ctx = write_contexts()?;
    for (tag, dir) in [(egress_image(), "egress"), (agents_base_image(), "base")] {
        eprintln!(
            "[vettalon] {}",
            crate::tr!("建置 {tag}…", "building {tag}…")
        );
        docker_visible(&bin, &build_args(tag, None, &ctx.path().join(dir))).await?;
    }
    build_local_layer(&bin, agents_base_image(), ctx.path()).await
}

/// `ghcr.io/zhixuli0406/<repo>:<tag>` for a local `<repo>:<tag>`.
fn registry_ref(local: &str) -> String {
    format!("{REGISTRY_PREFIX}{local}")
}

fn registry_repo(local: &str) -> String {
    registry_ref(local)
        .rsplit_once(':')
        .map(|(r, _)| r.to_string())
        .unwrap_or_default()
}

/// What `vettalon agents pull` says when it cannot verify. Kept here so the
/// tests pin the wording users act on.
fn no_cosign_error() -> String {
    crate::tr!(
        "找不到 cosign，無法驗證映像簽章。請安裝 cosign（https://docs.sigstore.dev/cosign/system_config/installation/）後重試，\
         或改用 `vettalon agents build` 在本機建置。`--no-verify` 會略過驗證（不安全）。",
        "cosign not found, so the image signatures cannot be verified. Install cosign \
         (https://docs.sigstore.dev/cosign/system_config/installation/) and retry, or run \
         `vettalon agents build` to build the images locally. `--no-verify` skips the check (insecure)."
    )
}

/// `cosign verify` argv: the signature must come from the public repo's
/// image workflow on `main` or a release tag, via GitHub's OIDC issuer.
fn cosign_verify_args(remote: &str) -> Vec<String> {
    [
        "verify",
        "--certificate-identity-regexp",
        SIGNER_IDENTITY_REGEXP,
        "--certificate-oidc-issuer",
        SIGNER_ISSUER,
        "--certificate-github-workflow-repository",
        "zhixuli0406/vettalon",
        remote,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// The one manifest digest `cosign verify` vouched for. Every verified
/// signature must name the expected repository and the same digest.
fn verified_digest(cosign_stdout: &str, repo: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(cosign_stdout.trim())
        .map_err(|e| format!("unexpected cosign output: {e}"))?;
    let sigs = v
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("cosign verified no signature")?;
    let mut digest: Option<String> = None;
    for sig in sigs {
        let c = &sig["critical"];
        let reference = c["identity"]["docker-reference"]
            .as_str()
            .unwrap_or_default();
        if reference != repo {
            return Err(format!("signature is for {reference:?}, not {repo}"));
        }
        let d = c["image"]["docker-manifest-digest"]
            .as_str()
            .ok_or("signature names no digest")?;
        if !is_sha256_digest(d) {
            return Err(format!("bad digest {d:?}"));
        }
        match &digest {
            Some(prev) if prev != d => return Err("signatures disagree on the digest".into()),
            _ => digest = Some(d.to_string()),
        }
    }
    digest.ok_or_else(|| "cosign verified no signature".into())
}

fn is_sha256_digest(d: &str) -> bool {
    d.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// Resolve one published image to a digest: verified with cosign, or (with
/// `--no-verify`) whatever the tag points at, read back after the pull.
async fn pull_one(docker_bin: &str, cosign: Option<&str>, local: &str) -> Result<String, String> {
    let remote = registry_ref(local);
    let repo = registry_repo(local);
    let digest = match cosign {
        Some(cosign) => {
            eprintln!(
                "[vettalon] {}",
                crate::tr!(
                    "驗證 {remote} 的簽章…",
                    "verifying the signature of {remote}…"
                )
            );
            let out = Command::new(cosign)
                .args(cosign_verify_args(&remote))
                .stdin(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("cannot run cosign: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "signature check failed for {remote}: {}",
                    crate::util::truncate_bytes(String::from_utf8_lossy(&out.stderr).trim(), 600)
                ));
            }
            let d = verified_digest(&String::from_utf8_lossy(&out.stdout), &repo)?;
            docker_visible(docker_bin, &["pull".into(), format!("{repo}@{d}")]).await?;
            d
        }
        None => {
            docker_visible(docker_bin, &["pull".into(), remote.clone()]).await?;
            let out = docker(
                docker_bin,
                &[
                    "image",
                    "inspect",
                    "--format",
                    "{{json .RepoDigests}}",
                    &remote,
                ],
            )
            .await?;
            let digests: Vec<String> =
                serde_json::from_slice(&out.stdout).map_err(|e| format!("docker inspect: {e}"))?;
            digests
                .iter()
                .filter_map(|r| r.strip_prefix(&format!("{repo}@")))
                .find(|d| is_sha256_digest(d))
                .map(str::to_string)
                .ok_or_else(|| format!("no digest for {remote} after pull"))?
        }
    };
    let pinned = format!("{repo}@{digest}");
    let tag = docker(docker_bin, &["tag", &pinned, local]).await?;
    if !tag.status.success() {
        return Err(format!(
            "cannot tag {pinned} as {local}: {}",
            String::from_utf8_lossy(&tag.stderr).trim()
        ));
    }
    eprintln!("[vettalon] {local} = {pinned}");
    Ok(pinned)
}

/// `vettalon agents pull`: fetch the egress proxy and the grok-free base
/// from GHCR, verify their keyless signatures, pin them by digest under the
/// local tags, then build the local grok layer on top of the verified base.
/// Never called during a scan.
pub async fn pull_images(verify: bool) -> Result<(), String> {
    let bin = docker_bin()?;
    let cosign = if verify {
        Some(crate::util::which_cli("cosign").ok_or_else(no_cosign_error)?)
    } else {
        None
    };
    pull_images_with(&bin, cosign.as_deref()).await
}

async fn pull_images_with(docker_bin: &str, cosign: Option<&str>) -> Result<(), String> {
    if cosign.is_none() {
        eprintln!(
            "[vettalon] {}",
            crate::tr!(
                "警告：--no-verify 未驗證映像簽章（不安全）",
                "warning: --no-verify skips the signature check (insecure)"
            )
        );
    }
    pull_one(docker_bin, cosign, egress_image()).await?;
    let base = pull_one(docker_bin, cosign, agents_base_image()).await?;
    let ctx = write_contexts()?;
    build_local_layer(docker_bin, &base, ctx.path()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_tags_follow_the_definition_not_the_cli_version() {
        for (img, repo) in [
            (agents_image(), AGENTS_REPO),
            (agents_base_image(), AGENTS_BASE_REPO),
            (egress_image(), EGRESS_REPO),
        ] {
            let tag = img
                .strip_prefix(repo)
                .and_then(|t| t.strip_prefix(':'))
                .expect("repo:tag");
            assert_eq!(tag.len(), IMAGE_TAG_HEX_LEN, "{img}");
            assert!(
                tag.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
            assert!(!img.contains(env!("CARGO_PKG_VERSION")), "{img}");
        }
        // Deterministic, and any change to any file of the context (or to
        // which file a body belongs to) yields a different tag.
        let base = image_ref("r", &[("Dockerfile", "FROM a"), ("conf", "x")]);
        assert_eq!(
            base,
            image_ref("r", &[("Dockerfile", "FROM a"), ("conf", "x")])
        );
        for other in [
            image_ref("r", &[("Dockerfile", "FROM b"), ("conf", "x")]),
            image_ref("r", &[("Dockerfile", "FROM a"), ("conf", "y")]),
            image_ref("r", &[("Dockerfile", "FROM a"), ("conf", "x"), ("z", "")]),
            image_ref("r", &[("Dockerfil", "eFROM a"), ("conf", "x")]),
        ] {
            assert_ne!(base, other);
        }
        // The real tags are pinned to the embedded definitions.
        assert_eq!(
            agents_base_image(),
            image_ref(AGENTS_BASE_REPO, BASE_CONTEXT)
        );
        assert_eq!(egress_image(), image_ref(EGRESS_REPO, EGRESS_CONTEXT));
        assert_eq!(
            agents_image(),
            layered_image_ref(AGENTS_REPO, tag_of(agents_base_image()), AGENTS_CONTEXT)
        );
        // Three distinct tags.
        let tags = [
            tag_of(agents_image()),
            tag_of(agents_base_image()),
            tag_of(egress_image()),
        ];
        assert!(tags[0] != tags[1] && tags[1] != tags[2] && tags[0] != tags[2]);
    }

    #[test]
    fn local_agents_tag_follows_both_the_base_and_the_layer() {
        let layer: &[(&str, &str)] = &[("Dockerfile", "FROM ${BASE_IMAGE}")];
        let t = layered_image_ref("a", "0123456789ab", layer);
        assert_eq!(t, layered_image_ref("a", "0123456789ab", layer));
        // A base change (any base file) changes the local tag ...
        assert_ne!(t, layered_image_ref("a", "0123456789ac", layer));
        // ... and so does a change to the local layer.
        assert_ne!(
            t,
            layered_image_ref(
                "a",
                "0123456789ab",
                &[("Dockerfile", "FROM ${BASE_IMAGE} ")]
            )
        );
        // Changing one byte of a real base file changes both tags.
        let mut ctx: Vec<(&str, &str)> = BASE_CONTEXT.to_vec();
        ctx[0].1 = "changed";
        let changed_base = image_ref(AGENTS_BASE_REPO, &ctx);
        assert_ne!(changed_base, agents_base_image());
        assert_ne!(
            layered_image_ref(AGENTS_REPO, tag_of(&changed_base), AGENTS_CONTEXT),
            agents_image()
        );
    }

    /// Every file under docker/, with its path relative to docker/.
    fn files_under(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if e.file_type().unwrap().is_dir() {
                files_under(&e.path(), &rel, out);
            } else {
                out.push(rel);
            }
        }
    }

    #[test]
    fn every_file_under_docker_is_in_exactly_one_tag() {
        // A new file under docker/ must join exactly one context (and so its
        // tag); otherwise it could change without any tag changing.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker");
        let mut on_disk = Vec::new();
        files_under(&root, "", &mut on_disk);
        on_disk.sort();
        let mut listed: Vec<String> = Vec::new();
        for (dir, context) in [
            ("agents-base", BASE_CONTEXT),
            ("agents", AGENTS_CONTEXT),
            ("egress", EGRESS_CONTEXT),
        ] {
            for (name, body) in context {
                let rel = format!("{dir}/{name}");
                let disk = std::fs::read_to_string(root.join(&rel)).unwrap();
                assert_eq!(&disk, body, "docker/{rel}");
                listed.push(rel);
            }
        }
        listed.sort();
        let mut dedup = listed.clone();
        dedup.dedup();
        assert_eq!(dedup, listed, "a file is in two contexts");
        assert_eq!(on_disk, listed);
    }

    #[test]
    fn grok_is_never_in_the_published_base() {
        for (name, body) in BASE_CONTEXT {
            if *name == "Dockerfile" {
                let code: String = body
                    .lines()
                    .filter(|l| !l.trim_start().starts_with('#'))
                    .collect();
                assert!(!code.contains("grok") && !code.contains("x.ai"), "{code}");
            }
        }
        assert!(AGENTS_DOCKERFILE.contains("x.ai/cli/grok-"));
        assert!(AGENTS_DOCKERFILE.contains("FROM ${BASE_IMAGE}"));
    }

    #[test]
    fn missing_image_error_names_the_image_and_the_fix() {
        let e = missing_image_error(agents_image());
        assert!(e.contains(agents_image()), "{e}");
        assert!(missing_image_error(agents_base_image()).len() <= 160);
        assert!(e.contains("vettalon agents pull"), "{e}");
        assert!(e.contains("agents build"), "{e}");
        // `vettalon models --probe` cuts details at 160 bytes.
        assert!(e.len() <= 160, "{} bytes: {e}", e.len());
    }

    #[test]
    fn embedded_definitions_are_the_repo_files() {
        assert!(BASE_DOCKERFILE.contains("@openai/codex"));
        assert!(EGRESS_CONF.contains("FilterDefaultDeny Yes"));
        assert!(EGRESS_ALLOWLIST.lines().all(|l| l.ends_with('$')));
    }

    const FAKE_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A fake executable that appends its argv to `log` and runs `body`.
    #[cfg(unix)]
    fn fake_bin(dir: &Path, name: &str, log: &Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"{name} $*\" >> '{}'\n{body}\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.display().to_string()
    }

    #[cfg(unix)]
    fn fake_docker(dir: &Path, log: &Path) -> String {
        // `image inspect` answers RepoDigests for the --no-verify path.
        let body = format!(
            r#"case "$1 $2" in
  "image inspect") for a; do last="$a"; done; printf '["%s@{FAKE_DIGEST}"]\n' "${{last%:*}}" ;;
esac
exit 0"#
        );
        fake_bin(dir, "docker", log, &body)
    }

    #[cfg(unix)]
    fn fake_cosign(dir: &Path, log: &Path, ok: bool) -> String {
        let body = if ok {
            format!(
                r#"for a; do last="$a"; done
printf '[{{"critical":{{"identity":{{"docker-reference":"%s"}},"image":{{"docker-manifest-digest":"{FAKE_DIGEST}"}},"type":"cosign container image signature"}}}}]\n' "${{last%:*}}"
exit 0"#
            )
        } else {
            "echo 'no matching signatures' >&2; exit 1".to_string()
        };
        fake_bin(dir, "cosign", log, &body)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pull_verifies_pins_by_digest_then_builds_grok_locally() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        let docker = fake_docker(dir.path(), &log);
        let cosign = fake_cosign(dir.path(), &log, true);
        pull_images_with(&docker, Some(&cosign)).await.unwrap();
        let calls: Vec<String> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let base_repo = registry_repo(agents_base_image());
        let egress_repo = registry_repo(egress_image());
        let expect = [
            format!(
                "cosign {}",
                cosign_verify_args(&registry_ref(egress_image())).join(" ")
            ),
            format!("docker pull {egress_repo}@{FAKE_DIGEST}"),
            format!("docker tag {egress_repo}@{FAKE_DIGEST} {}", egress_image()),
            format!(
                "cosign {}",
                cosign_verify_args(&registry_ref(agents_base_image())).join(" ")
            ),
            format!("docker pull {base_repo}@{FAKE_DIGEST}"),
            format!(
                "docker tag {base_repo}@{FAKE_DIGEST} {}",
                agents_base_image()
            ),
        ];
        assert_eq!(&calls[..expect.len()], &expect[..], "{calls:#?}");
        // The local layer is built on the verified base, by digest.
        let build = &calls[expect.len()];
        assert!(
            build.starts_with(&format!("docker build -t {} ", agents_image())),
            "{build}"
        );
        assert!(
            build.contains(&format!("--build-arg BASE_IMAGE={base_repo}@{FAKE_DIGEST}")),
            "{build}"
        );
        assert_eq!(calls.len(), expect.len() + 1, "{calls:#?}");
        // Nothing is ever pulled by tag or run.
        assert!(!calls.iter().any(|c| c.starts_with("docker run")));
        assert!(
            !calls
                .iter()
                .any(|c| c.starts_with("docker pull") && !c.contains("@sha256:"))
        );
        // The signer is the public repo's image workflow via GitHub OIDC.
        let v = cosign_verify_args("x");
        assert!(
            v.windows(2)
                .any(|w| w[0] == "--certificate-oidc-issuer" && w[1] == SIGNER_ISSUER)
        );
        assert!(
            v.windows(2)
                .any(|w| w[0] == "--certificate-identity-regexp" && w[1] == SIGNER_IDENTITY_REGEXP)
        );
        assert!(SIGNER_IDENTITY_REGEXP.starts_with("^https://github\\.com/zhixuli0406/vettalon/"));
        assert!(SIGNER_IDENTITY_REGEXP.ends_with('$'));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_signature_stops_before_any_pull() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        let docker = fake_docker(dir.path(), &log);
        let cosign = fake_cosign(dir.path(), &log, false);
        let e = pull_images_with(&docker, Some(&cosign)).await.unwrap_err();
        assert!(e.contains("signature check failed"), "{e}");
        assert!(e.contains("no matching signatures"), "{e}");
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(
            calls.lines().all(|l| l.starts_with("cosign verify")),
            "{calls}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn no_verify_pulls_by_tag_but_still_pins_the_digest() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        let docker = fake_docker(dir.path(), &log);
        pull_images_with(&docker, None).await.unwrap();
        let calls = std::fs::read_to_string(&log).unwrap();
        let base_repo = registry_repo(agents_base_image());
        assert!(calls.contains(&format!(
            "docker pull {}",
            registry_ref(agents_base_image())
        )));
        assert!(calls.contains(&format!(
            "docker tag {base_repo}@{FAKE_DIGEST} {}",
            agents_base_image()
        )));
        assert!(calls.contains(&format!("BASE_IMAGE={base_repo}@{FAKE_DIGEST}")));
        assert!(!calls.contains("cosign"));
    }

    #[test]
    fn verified_digest_rejects_mismatches() {
        let sig = |repo: &str, d: &str| {
            format!(
                r#"{{"critical":{{"identity":{{"docker-reference":"{repo}"}},"image":{{"docker-manifest-digest":"{d}"}}}}}}"#
            )
        };
        let repo = "ghcr.io/zhixuli0406/vettalon-egress";
        let other = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            verified_digest(&format!("[{}]", sig(repo, FAKE_DIGEST)), repo).unwrap(),
            FAKE_DIGEST
        );
        for bad in [
            "[]".to_string(),
            "not json".to_string(),
            format!("[{}]", sig("ghcr.io/evil/vettalon-egress", FAKE_DIGEST)),
            format!("[{},{}]", sig(repo, FAKE_DIGEST), sig(repo, &other)),
            format!("[{}]", sig(repo, "sha256:XYZ")),
        ] {
            assert!(verified_digest(&bad, repo).is_err(), "{bad}");
        }
    }

    #[test]
    fn no_cosign_error_says_what_to_do() {
        let e = no_cosign_error();
        assert!(e.contains("cosign"), "{e}");
        assert!(e.contains("vettalon agents build"), "{e}");
        assert!(e.contains("--no-verify"), "{e}");
    }

    #[test]
    fn registry_refs_point_at_ghcr() {
        assert_eq!(
            registry_ref(egress_image()),
            format!("ghcr.io/zhixuli0406/{}", egress_image())
        );
        assert_eq!(
            registry_repo(egress_image()),
            "ghcr.io/zhixuli0406/vettalon-egress"
        );
        // Only the base and the egress proxy are ever pulled.
        assert!(!registry_ref(agents_base_image()).contains("vettalon-agents:"));
    }
}
