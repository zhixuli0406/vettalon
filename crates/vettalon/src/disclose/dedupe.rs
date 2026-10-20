//! Pre-send duplicate checklist.
//!
//! Before a report goes out the human should know whether the issue is
//! already public or already being fixed: OSV (which includes the GitHub
//! Advisory Database), upstream commits touching the file in the last 90
//! days, and open issues/PRs that mention the file. The online checks run
//! only when asked (`--check-duplicates`) and only through the hunt egress
//! allowlist (`api.osv.dev` via the OSV client; `api.github.com` via
//! [`crate::hunt::fetch::UPSTREAM_CHECK_HOSTS`]). What leaves the machine:
//! the package `name@version`, the GitHub `owner/repo`, the finding's file
//! path and its base name as a search term. Never the finding text.
//!
//! A check that did not run says "not checked"; a check that ran and found
//! nothing says how it searched. Neither ever says "no duplicates": private
//! reports are invisible to every public query.

use async_trait::async_trait;
use serde::Serialize;

use crate::hunt::{DependencyTarget, Ecosystem};

/// How far back the upstream commit check looks.
pub const RECENT_COMMIT_DAYS: i64 = 90;
const MAX_ITEMS: usize = 10;
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DedupeCheck {
    NotChecked { reason: String },
    Checked { query: String, matches: Vec<String> },
    Failed { query: String, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DedupeReport {
    pub osv: DedupeCheck,
    pub upstream_commits: DedupeCheck,
    pub open_issues_prs: DedupeCheck,
}

impl DedupeReport {
    /// Every check "not checked" with the same reason.
    pub fn not_checked(reason: &str) -> DedupeReport {
        let n = || DedupeCheck::NotChecked {
            reason: reason.to_string(),
        };
        DedupeReport {
            osv: n(),
            upstream_commits: n(),
            open_issues_prs: n(),
        }
    }

    /// The default when the operator did not ask for the online checks.
    pub fn not_requested() -> DedupeReport {
        Self::not_checked("online check not requested (--check-duplicates)")
    }

    fn line(label: &str, c: &DedupeCheck) -> String {
        match c {
            DedupeCheck::NotChecked { reason } => format!("- [ ] {label}: NOT CHECKED ({reason})"),
            DedupeCheck::Failed { query, error } => {
                format!("- [ ] {label}: NOT CHECKED, query failed ({query}): {error}")
            }
            DedupeCheck::Checked { query, matches } if matches.is_empty() => format!(
                "- [ ] {label}: checked {query}: 0 results. This does not rule out a duplicate (private reports are not visible)."
            ),
            DedupeCheck::Checked { query, matches } => {
                let mut s = format!(
                    "- [ ] {label}: checked {query}: {} result(s), review each before sending:",
                    matches.len()
                );
                for m in matches {
                    s.push_str(&format!("\n    - {m}"));
                }
                s
            }
        }
    }

    /// Checklist lines for the reviewer-notes block.
    pub fn render(&self) -> String {
        [
            Self::line("OSV / GitHub advisories", &self.osv),
            Self::line(
                &format!("Upstream commits touching the file (last {RECENT_COMMIT_DAYS} days)"),
                &self.upstream_commits,
            ),
            Self::line(
                "Open issues / PRs mentioning the file",
                &self.open_issues_prs,
            ),
        ]
        .join("\n")
    }
}

/// The three lookups, behind a trait so drafting is testable offline.
#[async_trait]
pub trait DedupeSource: Send + Sync {
    async fn osv(&self, target: &DependencyTarget) -> Result<Vec<String>, String>;
    async fn recent_commits(
        &self,
        slug: &str,
        path: &str,
        since: chrono::NaiveDate,
    ) -> Result<Vec<String>, String>;
    async fn open_issues_prs(&self, slug: &str, term: &str) -> Result<Vec<String>, String>;
}

fn ecosystem_of(label: &str) -> Option<Ecosystem> {
    match label {
        "Rust" => Some(Ecosystem::Cargo),
        "npm" => Some(Ecosystem::Npm),
        "pip" => Some(Ecosystem::PyPi),
        "Go" => Some(Ecosystem::Go),
        _ => None,
    }
}

/// A repo-relative path safe to put in an API query.
fn safe_path(p: &str) -> Option<String> {
    let p = p.trim().trim_start_matches("./");
    let ok = !p.is_empty()
        && p.len() <= 300
        && !p.starts_with('/')
        && !p.split('/').any(|seg| seg.is_empty() || seg == "..")
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./+@".contains(c));
    ok.then(|| p.to_string())
}

/// Run the checks for one finding. `slug` must already be a validated
/// GitHub `owner/repo` (see [`super::github_slug`]).
pub async fn check(
    src: &dyn DedupeSource,
    meta: &super::ProjectMeta,
    file: &str,
    today: chrono::NaiveDate,
) -> DedupeReport {
    let osv = match (
        meta.ecosystem.as_deref().and_then(ecosystem_of),
        &meta.name,
        &meta.version,
    ) {
        (Some(ecosystem), Some(name), Some(version)) => {
            let query = format!("OSV {name}@{version}");
            let target = DependencyTarget {
                ecosystem,
                name: name.clone(),
                version: version.clone(),
                direct: true,
            };
            match src.osv(&target).await {
                Ok(m) => DedupeCheck::Checked { query, matches: m },
                Err(error) => DedupeCheck::Failed { query, error },
            }
        }
        _ => DedupeCheck::NotChecked {
            reason: "package ecosystem, name or version unknown".into(),
        },
    };
    let slug = meta
        .github
        .as_deref()
        .and_then(|s| super::github_slug(&format!("https://github.com/{s}")));
    let path = safe_path(file);
    let (upstream_commits, open_issues_prs) = match (slug, path) {
        (None, _) => {
            let n = || DedupeCheck::NotChecked {
                reason: "no GitHub upstream detected".into(),
            };
            (n(), n())
        }
        (Some(_), None) => {
            let n = || DedupeCheck::NotChecked {
                reason: "file path not usable in a query".into(),
            };
            (n(), n())
        }
        (Some(slug), Some(path)) => {
            let since = today - chrono::Duration::days(RECENT_COMMIT_DAYS);
            let q1 = format!("GitHub {slug} commits path={path} since={since}");
            let commits = match src.recent_commits(&slug, &path, since).await {
                Ok(m) => DedupeCheck::Checked {
                    query: q1,
                    matches: m,
                },
                Err(error) => DedupeCheck::Failed { query: q1, error },
            };
            let term = path.rsplit('/').next().unwrap_or(&path).to_string();
            let q2 = format!("GitHub search repo:{slug} is:open {term}");
            let issues = match src.open_issues_prs(&slug, &term).await {
                Ok(m) => DedupeCheck::Checked {
                    query: q2,
                    matches: m,
                },
                Err(error) => DedupeCheck::Failed { query: q2, error },
            };
            (commits, issues)
        }
    };
    DedupeReport {
        osv,
        upstream_commits,
        open_issues_prs,
    }
}

/// External text (commit messages, issue titles) shown to the human: one
/// line, bounded, invisible characters made visible.
fn external_line(s: &str) -> String {
    let first = s.lines().next().unwrap_or("").trim();
    let mut out = String::new();
    for c in first.chars().take(120) {
        let cp = c as u32;
        if c.is_control() {
            continue;
        }
        if matches!(cp, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF) {
            out.push_str(&format!("[U+{cp:04X}]"));
        } else {
            out.push(c);
        }
    }
    out
}

/// Live lookups: the existing OSV client plus a GitHub REST client that can
/// only reach [`crate::hunt::fetch::UPSTREAM_CHECK_HOSTS`]. Unauthenticated
/// (no token leaves the machine); a rate-limit answer is a failed check.
pub struct HttpDedupeSource {
    osv: crate::hunt::osv::HttpOsvClient,
    http: reqwest::Client,
}

impl Default for HttpDedupeSource {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpDedupeSource {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::custom(|a| {
                if a.previous().len() <= 3
                    && crate::hunt::fetch::upstream_check_host_allowed(a.url().as_str())
                {
                    a.follow()
                } else {
                    a.error("redirect outside the upstream-check allowlist")
                }
            }))
            .timeout(std::time::Duration::from_secs(20))
            .retry(reqwest::retry::never())
            .user_agent(concat!("vettalon/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("static upstream-check HTTP client configuration");
        HttpDedupeSource {
            osv: crate::hunt::osv::HttpOsvClient::new(),
            http,
        }
    }

    async fn get_json(&self, url: reqwest::Url) -> Result<serde_json::Value, String> {
        if !crate::hunt::fetch::upstream_check_host_allowed(url.as_str()) {
            return Err(format!("refusing a non-allowlisted host: {url}"));
        }
        let mut resp = self
            .http
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            buf.extend_from_slice(&chunk);
            if buf.len() > MAX_BODY_BYTES {
                return Err("response exceeds the size cap".into());
            }
        }
        serde_json::from_slice(&buf).map_err(|e| format!("not JSON: {e}"))
    }
}

pub fn commits_url(slug: &str, path: &str, since: chrono::NaiveDate) -> reqwest::Url {
    let mut u = reqwest::Url::parse(&format!("https://api.github.com/repos/{slug}/commits"))
        .expect("validated slug");
    u.query_pairs_mut()
        .append_pair("path", path)
        .append_pair("since", &format!("{since}T00:00:00Z"))
        .append_pair("per_page", &MAX_ITEMS.to_string());
    u
}

pub fn issues_url(slug: &str, term: &str) -> reqwest::Url {
    let mut u = reqwest::Url::parse("https://api.github.com/search/issues").expect("static");
    u.query_pairs_mut()
        .append_pair("q", &format!("repo:{slug} is:open {term}"))
        .append_pair("per_page", &MAX_ITEMS.to_string());
    u
}

#[async_trait]
impl DedupeSource for HttpDedupeSource {
    async fn osv(&self, target: &DependencyTarget) -> Result<Vec<String>, String> {
        use crate::hunt::osv::OsvClient;
        let v = self.osv.known_vulns(target).await?;
        Ok(v.into_iter()
            .take(MAX_ITEMS)
            .map(|k| {
                if k.aliases.is_empty() {
                    external_line(&k.id)
                } else {
                    external_line(&format!("{} ({})", k.id, k.aliases.join(", ")))
                }
            })
            .collect())
    }

    async fn recent_commits(
        &self,
        slug: &str,
        path: &str,
        since: chrono::NaiveDate,
    ) -> Result<Vec<String>, String> {
        let v = self.get_json(commits_url(slug, path, since)).await?;
        let arr = v.as_array().ok_or("unexpected commits response")?;
        Ok(arr
            .iter()
            .take(MAX_ITEMS)
            .map(|c| {
                let sha = c.get("sha").and_then(|s| s.as_str()).unwrap_or("");
                let msg = c
                    .pointer("/commit/message")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                external_line(&format!(
                    "{} {msg}",
                    sha.chars().take(12).collect::<String>()
                ))
            })
            .collect())
    }

    async fn open_issues_prs(&self, slug: &str, term: &str) -> Result<Vec<String>, String> {
        let v = self.get_json(issues_url(slug, term)).await?;
        let arr = v
            .get("items")
            .and_then(|i| i.as_array())
            .ok_or("unexpected search response")?;
        Ok(arr
            .iter()
            .take(MAX_ITEMS)
            .map(|i| {
                let n = i.get("number").and_then(|n| n.as_u64()).unwrap_or(0);
                let kind = if i.get("pull_request").is_some() {
                    "PR"
                } else {
                    "issue"
                };
                let title = i.get("title").and_then(|s| s.as_str()).unwrap_or("");
                external_line(&format!("{kind} #{n} {title}"))
            })
            .collect())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Scripted offline source.
    pub(crate) struct Fake {
        pub osv: Result<Vec<String>, String>,
        pub commits: Result<Vec<String>, String>,
        pub issues: Result<Vec<String>, String>,
    }

    #[async_trait]
    impl DedupeSource for Fake {
        async fn osv(&self, _: &DependencyTarget) -> Result<Vec<String>, String> {
            self.osv.clone()
        }
        async fn recent_commits(
            &self,
            _: &str,
            _: &str,
            _: chrono::NaiveDate,
        ) -> Result<Vec<String>, String> {
            self.commits.clone()
        }
        async fn open_issues_prs(&self, _: &str, _: &str) -> Result<Vec<String>, String> {
            self.issues.clone()
        }
    }

    fn meta() -> super::super::ProjectMeta {
        super::super::ProjectMeta {
            name: Some("shop".into()),
            version: Some("1.2.3".into()),
            ecosystem: Some("Rust".into()),
            github: Some("acme/shop".into()),
            ..Default::default()
        }
    }

    fn day() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 20).unwrap()
    }

    #[tokio::test]
    async fn offline_failure_says_not_checked_never_no_duplicates() {
        let fake = Fake {
            osv: Err("offline".into()),
            commits: Err("offline".into()),
            issues: Err("offline".into()),
        };
        let r = check(&fake, &meta(), "src/db.rs", day()).await;
        let text = r.render();
        assert_eq!(text.matches("NOT CHECKED").count(), 3, "{text}");
        assert!(!text.to_lowercase().contains("no duplicate"));
        let text = DedupeReport::not_requested().render();
        assert_eq!(text.matches("NOT CHECKED").count(), 3);
    }

    #[tokio::test]
    async fn empty_results_are_reported_with_their_limits() {
        let fake = Fake {
            osv: Ok(vec![]),
            commits: Ok(vec!["abc123 fix bounds in db.rs".into()]),
            issues: Ok(vec![]),
        };
        let r = check(&fake, &meta(), "src/db.rs", day()).await;
        let text = r.render();
        assert!(text.contains("checked OSV shop@1.2.3: 0 results"), "{text}");
        assert!(text.contains("does not rule out a duplicate"));
        assert!(text.contains("since=2026-07-22"));
        assert!(text.contains("abc123 fix bounds"));
        assert!(text.contains("is:open db.rs"));
    }

    #[tokio::test]
    async fn unusable_inputs_are_not_checked() {
        let fake = Fake {
            osv: Ok(vec![]),
            commits: Ok(vec![]),
            issues: Ok(vec![]),
        };
        let mut m = meta();
        m.github = None;
        m.version = None;
        let r = check(&fake, &m, "src/db.rs", day()).await;
        assert!(matches!(r.osv, DedupeCheck::NotChecked { .. }));
        assert!(matches!(r.upstream_commits, DedupeCheck::NotChecked { .. }));
        let r = check(&fake, &meta(), "../etc/passwd", day()).await;
        assert!(matches!(r.upstream_commits, DedupeCheck::NotChecked { .. }));
    }

    #[test]
    fn urls_stay_on_the_allowlist_and_encode_inputs() {
        let since = day();
        let u = commits_url("acme/shop", "src/a b.rs", since);
        assert!(crate::hunt::fetch::upstream_check_host_allowed(u.as_str()));
        assert!(u.as_str().contains("path=src%2Fa+b.rs"), "{u}");
        let u = issues_url("acme/shop", "db.rs");
        assert!(crate::hunt::fetch::upstream_check_host_allowed(u.as_str()));
        assert!(
            u.as_str().contains("repo%3Aacme%2Fshop+is%3Aopen+db.rs"),
            "{u}"
        );
    }

    #[test]
    fn external_text_is_one_bounded_visible_line() {
        let s = external_line(&format!("title\u{202E}x\nsecond line{}", "y".repeat(500)));
        assert_eq!(s, "title[U+202E]x");
        assert!(external_line(&"z".repeat(500)).chars().count() == 120);
    }
}
