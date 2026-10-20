//! Local project detection and channel ranking (no network): the repo's git
//! remote, SECURITY.md and package manifest.

use std::path::Path;

use super::{Channel, ChannelOption, ProjectMeta};

const META_MAX_BYTES: u64 = 256 * 1024;

/// Read a small regular file inside the repo (no symlinks, size-capped).
fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > META_MAX_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// `owner/repo` from a GitHub remote URL (https or scp-style ssh).
pub fn github_slug(url: &str) -> Option<String> {
    let u = url.trim();
    let rest = u
        .strip_prefix("https://github.com/")
        .or_else(|| u.strip_prefix("http://github.com/"))
        .or_else(|| u.strip_prefix("ssh://git@github.com/"))
        .or_else(|| u.strip_prefix("git@github.com:"))?;
    let rest = rest.trim_end_matches('/').trim_end_matches(".git");
    let mut parts = rest.split('/');
    let (owner, repo) = (parts.next()?, parts.next()?);
    let ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    };
    (ok(owner) && ok(repo) && parts.next().is_none()).then(|| format!("{owner}/{repo}"))
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
    let mut m = ProjectMeta::default();
    if !repo.is_dir() {
        return m;
    }
    let git = repo.join(".git");
    if let Some(cfg) = read_small(&git.join("config")) {
        m.github = origin_url(&cfg).as_deref().and_then(github_slug);
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
    }
    if m.name.is_none() {
        m.name = repo.file_name().map(|n| n.to_string_lossy().to_string());
    }
    m
}

/// Ranked channel options for this project.
pub fn recommend(meta: &ProjectMeta) -> Vec<ChannelOption> {
    let mut out = Vec::new();
    if let Some(slug) = &meta.github {
        out.push(ChannelOption {
            channel: Channel::GithubAdvisory,
            label: "GitHub 私密漏洞回報".into(),
            reason: format!("專案託管於 GitHub（{slug}），可優先核對維護者的私密回報設定與安全政策，經核准後私下通報。"),
            submit: Some(format!("https://github.com/{slug}/security/advisories/new")),
            window_days: Channel::GithubAdvisory.window_days(),
        });
    }
    if let Some(email) = meta.security_emails.first() {
        out.push(ChannelOption {
            channel: Channel::VendorEmail,
            label: "專案安全聯絡窗口".into(),
            reason: format!(
                "{} 指定的安全聯絡信箱。",
                meta.security_policy.as_deref().unwrap_or("專案文件")
            ),
            submit: Some(format!("mailto:{email}")),
            window_days: Channel::VendorEmail.window_days(),
        });
    }
    out.push(ChannelOption {
        channel: Channel::Twcert,
        label: "TWCERT/CC（台灣漏洞通報，可申請 CVE）".into(),
        reason: "軟體／韌體產品漏洞的協調管道候選；送出前須核對受理範圍、現行政策與聯絡方式。建議日期不代表公開授權。".into(),
        submit: Some("mailto:cve@cert.org.tw".into()),
        window_days: Channel::Twcert.window_days(),
    });
    out.push(ChannelOption {
        channel: Channel::HitconZeroday,
        label: "HITCON ZeroDay（網站／服務漏洞）".into(),
        reason: "網站與線上服務的協調管道候選；送出前須核對受理範圍、現行政策與公開設定。建議日期不代表公開授權。".into(),
        submit: Some("https://zeroday.hitcon.org/".into()),
        window_days: Channel::HitconZeroday.window_days(),
    });
    out
}
