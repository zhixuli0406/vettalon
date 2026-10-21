//! Local project detection and channel ranking (no network): the repo's git
//! remote (or, without a GitHub one, the repository URL the package metadata
//! declares), SECURITY.md and package manifest.

use std::path::Path;

use super::upstream::{MetadataUpstream, UpstreamOrigin, pkg_info_field};
use super::{Channel, ChannelOption, ProjectMeta};
use crate::lang::pick;

const META_MAX_BYTES: u64 = 256 * 1024;

/// Read a small regular file inside the repo (no symlinks, size-capped).
fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > META_MAX_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// `owner/repo` from a GitHub repository URL (https, ssh, scp-style,
/// `git+` forms); see [`super::upstream::normalize_github`].
pub fn github_slug(url: &str) -> Option<String> {
    super::upstream::normalize_github(url)
}

fn origin_url(git_config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in git_config.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_origin = l == r#"[remote "origin"]"#;
        } else if in_origin && let Some(v) = l.strip_prefix("url") {
            return Some(v.trim_start().trim_start_matches('=').trim().to_string());
        }
    }
    None
}

fn head_commit(git_dir: &Path) -> Option<String> {
    let head = read_small(&git_dir.join("HEAD"))?;
    let head = head.trim();
    let sha = match head.strip_prefix("ref: ") {
        Some(r) if !r.contains("..") => read_small(&git_dir.join(r))
            .map(|s| s.trim().to_string())
            .or_else(|| {
                // Packed refs: `<sha> <ref>` lines.
                read_small(&git_dir.join("packed-refs"))?
                    .lines()
                    .find_map(|l| l.strip_suffix(r).map(|s| s.trim().to_string()))
            })?,
        Some(_) => return None,
        None => head.to_string(),
    };
    (sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| sha[..12.min(sha.len())].to_string())
}

fn emails_in(text: &str) -> Vec<String> {
    let re =
        regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").expect("static regex");
    let mut out: Vec<String> = Vec::new();
    for m in re.find_iter(text) {
        let e = m.as_str().trim_end_matches('.').to_ascii_lowercase();
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out.truncate(5);
    out
}

fn toml_field(text: &str, section: &str, key: &str) -> Option<String> {
    let v: toml::Value = toml::from_str(text).ok()?;
    let mut cur = &v;
    for part in section.split('.') {
        cur = cur.get(part)?;
    }
    cur.get(key)?.as_str().map(str::to_string)
}

/// Everything the repo says about where to report (local reads only).
pub fn detect_project(repo: &Path) -> ProjectMeta {
    detect_project_as(repo, None)
}

/// [`detect_project`] for a package whose ecosystem is already known
/// (`Rust` | `npm` | `pip` | `Go`, e.g. a fetched dependency): that
/// ecosystem's metadata files are read first for the upstream repository,
/// whatever other manifests the package ships.
pub fn detect_project_as(repo: &Path, ecosystem: Option<&str>) -> ProjectMeta {
    let mut m = ProjectMeta::default();
    if !repo.is_dir() {
        return m;
    }
    let git = repo.join(".git");
    if let Some(cfg) = read_small(&git.join("config")) {
        m.github = origin_url(&cfg).as_deref().and_then(github_slug);
        if m.github.is_some() {
            m.github_source = Some(UpstreamOrigin::GitRemote);
        }
    }
    m.commit = head_commit(&git);
    for rel in [
        "SECURITY.md",
        ".github/SECURITY.md",
        "docs/SECURITY.md",
        "security.md",
    ] {
        if let Some(t) = read_small(&repo.join(rel)) {
            m.security_policy = Some(rel.to_string());
            m.security_emails = emails_in(&t);
            // DATA only: listed for the human, never acted on.
            m.policy_requirements = super::policy::extract_requirements(&t);
            break;
        }
    }
    read_manifest(repo, &mut m);
    // No GitHub origin remote (an unpacked registry tarball has no `.git`):
    // fall back to the repository URL the package metadata declares.
    if m.github.is_none() {
        let eco = ecosystem.or(m.ecosystem.as_deref());
        match super::upstream::from_metadata(repo, eco, read_small) {
            MetadataUpstream::Github { slug, origin } => {
                m.github = Some(slug);
                m.github_source = Some(origin);
            }
            MetadataUpstream::NonGithub(desc) => m.non_github_upstream = Some(desc),
            MetadataUpstream::None => {}
        }
    }
    if m.name.is_none() {
        m.name = repo.file_name().map(|n| n.to_string_lossy().to_string());
    }
    m
}

/// Name, version and ecosystem from the package manifest.
fn read_manifest(repo: &Path, m: &mut ProjectMeta) {
    if let Some(t) = read_small(&repo.join("Cargo.toml")) {
        m.name = toml_field(&t, "package", "name");
        m.version = toml_field(&t, "package", "version");
        m.ecosystem = Some("Rust".into());
    } else if let Some(t) = read_small(&repo.join("package.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
            m.name = v.get("name").and_then(|x| x.as_str()).map(str::to_string);
            m.version = v
                .get("version")
                .and_then(|x| x.as_str())
                .map(str::to_string);
        }
        m.ecosystem = Some("npm".into());
    } else if let Some(t) = read_small(&repo.join("pyproject.toml")) {
        m.name =
            toml_field(&t, "project", "name").or_else(|| toml_field(&t, "tool.poetry", "name"));
        m.version = toml_field(&t, "project", "version")
            .or_else(|| toml_field(&t, "tool.poetry", "version"));
        m.ecosystem = Some("pip".into());
    } else if let Some(t) = read_small(&repo.join("go.mod")) {
        m.name = t
            .lines()
            .find_map(|l| l.trim().strip_prefix("module "))
            .map(|s| s.trim().to_string());
        m.ecosystem = Some("Go".into());
    } else if read_small(&repo.join("PKG-INFO")).is_some() {
        // A legacy sdist (setup.py, no pyproject). A bare setup.cfg is not
        // enough: many non-Python repos keep tool settings in one.
        m.ecosystem = Some("pip".into());
    }
    // An sdist's PKG-INFO carries the resolved name and version (pyproject
    // often leaves the version dynamic).
    if m.ecosystem.as_deref() == Some("pip")
        && let Some(t) = read_small(&repo.join("PKG-INFO"))
    {
        m.name = m.name.take().or_else(|| pkg_info_field(&t, "Name"));
        m.version = m.version.take().or_else(|| pkg_info_field(&t, "Version"));
    }
}

/// Ranked channel options for this project.
pub fn recommend(meta: &ProjectMeta) -> Vec<ChannelOption> {
    let mut out = Vec::new();
    // Terminal/dashboard text: follows `crate::lang` (the library default is
    // zh-TW; the CLI switches to English for an English locale).
    if let Some(slug) = &meta.github {
        let from_metadata = matches!(
            meta.github_source,
            Some(UpstreamOrigin::PackageMetadata { .. })
        );
        let reason = if from_metadata {
            crate::tr!(
                "套件中繼資料指出上游在 GitHub（{slug}，送出前請確認），可優先核對維護者的私密回報設定與安全政策，經核准後私下通報。",
                "The package metadata names a GitHub upstream ({slug}; confirm it before sending). Check the maintainers' private reporting settings and security policy first, and report privately once approved.",
            )
        } else {
            crate::tr!(
                "專案託管於 GitHub（{slug}），可優先核對維護者的私密回報設定與安全政策，經核准後私下通報。",
                "Hosted on GitHub ({slug}). Check the maintainers' private reporting settings and security policy first, and report privately once approved.",
            )
        };
        out.push(ChannelOption {
            channel: Channel::GithubAdvisory,
            label: pick(
                "GitHub 私密漏洞回報",
                "GitHub private vulnerability reporting",
            )
            .into(),
            reason,
            submit: Some(format!("https://github.com/{slug}/security/advisories/new")),
            window_days: Channel::GithubAdvisory.window_days(),
        });
    }
    if let Some(email) = meta.security_emails.first() {
        let file = meta
            .security_policy
            .as_deref()
            .unwrap_or(pick("專案文件", "the project files"));
        out.push(ChannelOption {
            channel: Channel::VendorEmail,
            label: pick("專案安全聯絡窗口", "Project security contact").into(),
            reason: crate::tr!(
                "{file} 指定的安全聯絡信箱。",
                "Security contact address given in {file}."
            ),
            submit: Some(format!("mailto:{email}")),
            window_days: Channel::VendorEmail.window_days(),
        });
    }
    out.push(ChannelOption {
        channel: Channel::Twcert,
        label: pick(
            "TWCERT/CC（台灣漏洞通報，可申請 CVE）",
            "TWCERT/CC (Taiwan vulnerability coordination, can assign CVEs)",
        )
        .into(),
        reason: pick(
            "軟體／韌體產品漏洞的協調管道候選；送出前須核對受理範圍、現行政策與聯絡方式。建議日期不代表公開授權。",
            "Candidate coordination channel for software / firmware product vulnerabilities; check its scope, current policy and contact details before sending. A suggested date does not authorize publication.",
        )
        .into(),
        submit: Some("mailto:cve@cert.org.tw".into()),
        window_days: Channel::Twcert.window_days(),
    });
    out.push(ChannelOption {
        channel: Channel::HitconZeroday,
        label: pick(
            "HITCON ZeroDay（網站／服務漏洞）",
            "HITCON ZeroDay (websites / online services)",
        )
        .into(),
        reason: pick(
            "網站與線上服務的協調管道候選；送出前須核對受理範圍、現行政策與公開設定。建議日期不代表公開授權。",
            "Candidate coordination channel for websites and online services; check its scope, current policy and publication settings before sending. A suggested date does not authorize publication.",
        )
        .into(),
        submit: Some("https://zeroday.hitcon.org/".into()),
        window_days: Channel::HitconZeroday.window_days(),
    });
    out
}
