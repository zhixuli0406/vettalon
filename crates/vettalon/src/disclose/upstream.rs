//! Upstream repository from package metadata, for trees with no git remote
//! (an unpacked crates.io `.crate`, PyPI sdist or npm tarball).
//!
//! Every value read here was written by the package author, so it is
//! untrusted DATA: only a URL that normalizes to `github.com/<owner>/<repo>`
//! with a strict owner/repo charset becomes a GitHub slug. Anything else is
//! recorded as a non-GitHub upstream (host only) or ignored. Nothing read
//! here is ever executed or passed to a shell.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Where the upstream repository came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum UpstreamOrigin {
    /// The scanned tree's own `origin` remote (`.git/config`).
    GitRemote,
    /// A package metadata file in the scanned tree.
    PackageMetadata {
        /// `Cargo.toml`, `pyproject.toml`, `setup.cfg`, `PKG-INFO`, `package.json`.
        file: String,
        /// The field, e.g. `[package] repository` or `Project-URL Source`.
        field: String,
    },
}

impl UpstreamOrigin {
    pub fn render(&self, zh: bool) -> String {
        match (self, zh) {
            (UpstreamOrigin::GitRemote, false) => "git remote origin (.git/config)".into(),
            (UpstreamOrigin::GitRemote, true) => "git remote origin（.git/config）".into(),
            (UpstreamOrigin::PackageMetadata { file, field }, false) => {
                format!("package metadata ({file} {field})")
            }
            (UpstreamOrigin::PackageMetadata { file, field }, true) => {
                format!("套件中繼資料（{file} {field}）")
            }
        }
    }
}

/// Result of reading the package metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MetadataUpstream {
    Github {
        slug: String,
        origin: UpstreamOrigin,
    },
    /// A repository field that is not a usable github.com repo URL:
    /// `<host> (<file> <field>)`, or `unrecognized URL (...)`.
    NonGithub(String),
    None,
}

/// One URL value found in a metadata file.
struct Candidate {
    url: String,
    file: &'static str,
    field: String,
    /// A repository/source field (vs. a homepage, used only when it is a
    /// GitHub repo URL and no repository field exists).
    repo_field: bool,
    /// npm `repository` shorthand (`owner/repo`, `github:owner/repo`).
    npm_shorthand: bool,
    /// Order within one file (lower first): `Repository` before `Source`
    /// before `Code`, whatever order the table iterates in.
    rank: u8,
}

const LABEL_MAX: usize = 40;
const URL_MAX: usize = 512;

/// PEP 753 label normalization: lowercase, keep ASCII alphanumerics only.
fn norm_label(label: &str) -> String {
    label
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// `(true, rank)` = repository field, `(false, rank)` = homepage, `None` =
/// not a URL we use.
fn label_kind(label: &str) -> Option<(bool, u8)> {
    match norm_label(label).as_str() {
        "repository" | "repo" => Some((true, 0)),
        "source" | "sourcecode" => Some((true, 1)),
        "code" | "github" | "git" => Some((true, 2)),
        "homepage" | "home" => Some((false, 3)),
        _ => None,
    }
}

/// A label shown in the draft: printable ASCII subset, bounded.
fn safe_label(label: &str) -> String {
    label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || " -_.".contains(*c))
        .take(LABEL_MAX)
        .collect::<String>()
        .trim()
        .to_string()
}

/// First path segments on github.com that are site pages, not users.
const RESERVED_OWNERS: &[&str] = &[
    "about",
    "apps",
    "collections",
    "enterprise",
    "explore",
    "features",
    "login",
    "marketplace",
    "notifications",
    "orgs",
    "pricing",
    "pulls",
    "issues",
    "search",
    "security",
    "settings",
    "site",
    "sponsors",
    "topics",
    "users",
];

fn ok_owner(s: &str) -> bool {
    !RESERVED_OWNERS.contains(&s.to_ascii_lowercase().as_str())
        && (1..=39).contains(&s.len())
        && !s.starts_with(['-', '_', '.'])
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn ok_repo(s: &str) -> bool {
    (1..=100).contains(&s.len())
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// Strip a case-insensitive ASCII prefix.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// `owner/repo` from a github.com repository URL: https, http, git,
/// `git+https`, `git+ssh`, `ssh://git@`, scp-style `git@github.com:`, with
/// an optional `.git` suffix, trailing slash, query or fragment, and a
/// `/tree/...` or `/blob/...` deep link. Anything else (other hosts, ports,
/// user info, `..`, percent-escapes, whitespace) is rejected.
pub fn normalize_github(raw: &str) -> Option<String> {
    let u = raw.trim();
    if u.is_empty() || u.len() > URL_MAX || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let u = strip_prefix_ci(u, "git+").unwrap_or(u);
    let rest = [
        "https://github.com/",
        "http://github.com/",
        "https://www.github.com/",
        "http://www.github.com/",
        "git://github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    ]
    .iter()
    .find_map(|p| strip_prefix_ci(u, p))?;
    slug_from_path(rest)
}

/// `owner/repo[.git][/][/tree|blob/...][?..][#..]` → `owner/repo`.
fn slug_from_path(path: &str) -> Option<String> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let path = path.trim_end_matches('/');
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let rest: Vec<&str> = parts.collect();
    if let Some(first) = rest.first()
        && !matches!(*first, "tree" | "blob")
    {
        return None;
    }
    if rest.iter().any(|p| p.is_empty() || *p == "." || *p == "..") {
        return None;
    }
    (ok_owner(owner) && ok_repo(repo)).then(|| format!("{owner}/{repo}"))
}

/// npm `repository` shorthand: `github:owner/repo` or bare `owner/repo`.
fn npm_shorthand(raw: &str) -> Option<String> {
    let u = raw.trim();
    let rest = strip_prefix_ci(u, "github:").unwrap_or(u);
    if rest.contains(':') || rest.split('/').count() != 2 {
        return None;
    }
    slug_from_path(rest)
}

/// Host of a non-GitHub repository URL, for the record (never fetched).
fn foreign_host(raw: &str, npm: bool) -> Option<String> {
    let u = raw.trim();
    if npm {
        for (p, host) in [
            ("gitlab:", "gitlab.com"),
            ("bitbucket:", "bitbucket.org"),
            ("gist:", "gist.github.com"),
        ] {
            if strip_prefix_ci(u, p).is_some() {
                return Some(host.into());
            }
        }
    }
    let u = strip_prefix_ci(u, "git+").unwrap_or(u);
    let url = reqwest::Url::parse(u).ok()?;
    if !matches!(url.scheme(), "http" | "https" | "git" | "ssh") {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    // A github.com URL that failed normalization is malformed, not foreign.
    if host == "github.com" || host == "www.github.com" {
        return None;
    }
    (host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-.".contains(c)))
    .then_some(host)
}

fn toml_str(v: &toml::Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_str().map(str::to_string)
}

fn cand(url: String, file: &'static str, field: String, repo_field: bool) -> Candidate {
    Candidate {
        url,
        file,
        field,
        repo_field,
        npm_shorthand: false,
        rank: if repo_field { 0 } else { 3 },
    }
}

fn cargo(text: &str, out: &mut Vec<Candidate>) {
    let Ok(v) = toml::from_str::<toml::Value>(text) else {
        return;
    };
    for (key, repo_field) in [("repository", true), ("homepage", false)] {
        // `repository.workspace = true` is a table, not a URL: skipped.
        if let Some(url) = toml_str(&v, &["package", key]) {
            out.push(cand(
                url,
                "Cargo.toml",
                format!("[package] {key}"),
                repo_field,
            ));
        }
    }
}

fn package_json(text: &str, out: &mut Vec<Candidate>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let repo = match v.get("repository") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(obj) => obj.get("url").and_then(|u| u.as_str()).map(str::to_string),
        None => None,
    };
    if let Some(url) = repo {
        out.push(Candidate {
            npm_shorthand: true,
            ..cand(url, "package.json", "repository".into(), true)
        });
    }
    if let Some(url) = v.get("homepage").and_then(|u| u.as_str()) {
        out.push(cand(
            url.to_string(),
            "package.json",
            "homepage".into(),
            false,
        ));
    }
}

/// A Go module path as a repository URL. On github.com the repository is
/// the first two path segments (`github.com/o/r/v2`, `github.com/o/r/sub`
/// are modules inside `o/r`).
pub fn go_module_url(path: &str) -> String {
    let path = path.trim().trim_matches('"');
    match path.strip_prefix("github.com/") {
        Some(rest) => {
            let repo: Vec<&str> = rest.splitn(3, '/').take(2).collect();
            format!("https://github.com/{}", repo.join("/"))
        }
        None => format!("https://{path}"),
    }
}

/// `module <path>` in `go.mod` names the repository.
fn go_mod(text: &str, out: &mut Vec<Candidate>) {
    if let Some(path) = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("module "))
        .filter(|s| !s.trim().is_empty())
    {
        out.push(cand(go_module_url(path), "go.mod", "module".into(), true));
    }
}

fn labelled(file: &'static str, section: &str, label: &str, url: &str, out: &mut Vec<Candidate>) {
    if let Some((repo_field, rank)) = label_kind(label) {
        out.push(Candidate {
            rank,
            ..cand(
                url.to_string(),
                file,
                format!("{section} {}", safe_label(label)),
                repo_field,
            )
        });
    }
}

fn pyproject(text: &str, out: &mut Vec<Candidate>) {
    let Ok(v) = toml::from_str::<toml::Value>(text) else {
        return;
    };
    if let Some(urls) = v
        .get("project")
        .and_then(|p| p.get("urls"))
        .and_then(|u| u.as_table())
    {
        for (label, url) in urls {
            if let Some(url) = url.as_str() {
                labelled("pyproject.toml", "[project.urls]", label, url, out);
            }
        }
    }
    for (key, repo_field) in [("repository", true), ("homepage", false)] {
        if let Some(url) = toml_str(&v, &["tool", "poetry", key]) {
            out.push(cand(
                url,
                "pyproject.toml",
                format!("[tool.poetry] {key}"),
                repo_field,
            ));
        }
    }
}

/// `setup.cfg` `[metadata]`: `url` / `home_page` and the multi-line
/// `project_urls = Label = URL` list. Indented lines are continuations of
/// the previous key and only read inside `project_urls`.
fn setup_cfg(text: &str, out: &mut Vec<Candidate>) {
    let mut in_meta = false;
    let mut in_urls = false;
    for line in text.lines() {
        let indented = line.starts_with([' ', '\t']);
        let l = line.trim();
        if l.is_empty() || l.starts_with(['#', ';']) {
            continue;
        }
        if indented {
            if in_meta
                && in_urls
                && let Some((label, url)) = l.split_once('=')
            {
                labelled("setup.cfg", "project_urls", label.trim(), url.trim(), out);
            }
            continue;
        }
        in_urls = false;
        if l.starts_with('[') {
            in_meta = l.eq_ignore_ascii_case("[metadata]");
            continue;
        }
        if !in_meta {
            continue;
        }
        let Some((key, value)) = l.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase().replace('-', "_");
        match key.as_str() {
            "project_urls" => in_urls = true,
            "url" | "home_page" => out.push(cand(
                value.trim().to_string(),
                "setup.cfg",
                format!("[metadata] {key}"),
                false,
            )),
            _ => {}
        }
    }
}

/// The `PKG-INFO` header lines (RFC 822 style): up to the first empty line,
/// skipping folded continuation lines (which start with whitespace).
fn pkg_info_headers(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines()
        .map(|l| l.trim_end_matches('\r'))
        .take_while(|l| !l.is_empty())
        .filter(|l| !l.starts_with([' ', '\t']))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
}

/// `PKG-INFO` header block: `Project-URL: Label, URL` and `Home-page: URL`.
fn pkg_info(text: &str, out: &mut Vec<Candidate>) {
    for (key, value) in pkg_info_headers(text) {
        if key.eq_ignore_ascii_case("Project-URL") {
            if let Some((label, url)) = value.split_once(',') {
                labelled("PKG-INFO", "Project-URL", label.trim(), url.trim(), out);
            }
        } else if key.eq_ignore_ascii_case("Home-page") {
            out.push(cand(
                value.to_string(),
                "PKG-INFO",
                "Home-page".into(),
                false,
            ));
        }
    }
}

/// `PKG-INFO` `Name:` / `Version:` headers (an sdist whose pyproject leaves
/// the version dynamic still records it here).
pub(super) fn pkg_info_field(text: &str, name: &str) -> Option<String> {
    pkg_info_headers(text)
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| {
            (!v.is_empty() && v.len() <= 200 && !v.chars().any(char::is_control))
                .then(|| v.to_string())
        })
}

type Parser = fn(&str, &mut Vec<Candidate>);

/// Metadata files in default order, with the ecosystem each belongs to
/// (the GitHub advisory ecosystem labels used by `ProjectMeta`).
const PARSERS: [(&str, &str, Parser); 6] = [
    ("Cargo.toml", "Rust", cargo),
    ("package.json", "npm", package_json),
    ("pyproject.toml", "pip", pyproject),
    ("setup.cfg", "pip", setup_cfg),
    ("PKG-INFO", "pip", pkg_info),
    ("go.mod", "Go", go_mod),
];

/// The upstream repository from the package metadata files in `repo`,
/// read with `read` (size-capped, no symlinks). The files of `ecosystem`
/// (the package's own manifest) are read first, so an npm package that also
/// ships a `Cargo.toml` resolves from `package.json`. Repository fields win
/// over homepages; a homepage counts only when it is a github.com repo URL
/// and no repository field exists.
pub(super) fn from_metadata(
    repo: &Path,
    ecosystem: Option<&str>,
    read: impl Fn(&Path) -> Option<String>,
) -> MetadataUpstream {
    let mut parsers = PARSERS;
    // Stable: the package's own files first, default order otherwise.
    parsers.sort_by_key(|(_, eco, _)| Some(*eco) != ecosystem);
    let mut cands = Vec::new();
    for (file, _, parse) in parsers {
        if let Some(t) = read(&repo.join(file)) {
            let start = cands.len();
            parse(&t, &mut cands);
            cands[start..].sort_by_key(|c| c.rank);
        }
    }
    let slug_of = |c: &Candidate| {
        normalize_github(&c.url)
            .or_else(|| c.npm_shorthand.then(|| npm_shorthand(&c.url)).flatten())
    };
    let origin_of = |c: &Candidate| UpstreamOrigin::PackageMetadata {
        file: c.file.to_string(),
        field: c.field.clone(),
    };
    let repo_fields: Vec<&Candidate> = cands
        .iter()
        .filter(|c| c.repo_field && !c.url.trim().is_empty())
        .collect();
    if let Some((c, slug)) = repo_fields.iter().find_map(|c| slug_of(c).map(|s| (c, s))) {
        return MetadataUpstream::Github {
            slug,
            origin: origin_of(c),
        };
    }
    if let Some(c) = repo_fields.first() {
        let place = format!("{} {}", c.file, c.field);
        return MetadataUpstream::NonGithub(match foreign_host(&c.url, c.npm_shorthand) {
            Some(host) => format!("{host} ({place})"),
            None => format!("unrecognized URL ({place})"),
        });
    }
    cands
        .iter()
        .filter(|c| !c.repo_field)
        .find_map(|c| {
            normalize_github(&c.url).map(|slug| MetadataUpstream::Github {
                slug,
                origin: origin_of(c),
            })
        })
        .unwrap_or(MetadataUpstream::None)
}
