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
//! path and its base name as a search term. Never the finding text. OSV
//! results are classified locally (`same_cwe` / `same_file` / `package_only`)
//! from the records the one existing query already returns.
//!
//! A check that did not run says "not checked"; a check that ran and found
//! nothing says how it searched. Neither ever says "no duplicates": private
//! reports are invisible to every public query.

use async_trait::async_trait;
use serde::Serialize;

use crate::hunt::osv::VulnDetail;
use crate::hunt::{DependencyTarget, Ecosystem};

/// How far back the upstream commit check looks.
pub const RECENT_COMMIT_DAYS: i64 = 90;
const MAX_ITEMS: usize = 10;
/// OSV entries shown in the reviewer notes.
pub const MAX_OSV_ENTRIES: usize = 20;

/// How an OSV advisory for the package relates to the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OsvMatchKind {
    /// Its `database_specific.cwe_ids` holds the finding's CWE.
    SameCwe,
    /// Its summary or details mention the finding's file path or file name.
    SameFile,
    /// Only the package (name@version) matched.
    PackageOnly,
}

impl OsvMatchKind {
    pub fn key(self) -> &'static str {
        match self {
            OsvMatchKind::SameCwe => "same_cwe",
            OsvMatchKind::SameFile => "same_file",
            OsvMatchKind::PackageOnly => "package_only",
        }
    }
}

fn cwe_number(id: &str) -> String {
    let digits: String = id.chars().filter(char::is_ascii_digit).collect();
    digits.trim_start_matches('0').to_string()
}

/// Classify one advisory against the finding's CWE and file.
pub fn classify_osv(v: &VulnDetail, cwe: Option<&str>, file: &str) -> OsvMatchKind {
    if let Some(n) = cwe.map(cwe_number).filter(|n| !n.is_empty())
        && v.cwe_ids.iter().any(|c| cwe_number(c) == n)
    {
        return OsvMatchKind::SameCwe;
    }
    let path = file.trim().trim_start_matches("./");
    let name = path.rsplit('/').next().unwrap_or(path);
    let text = format!("{}\n{}", v.summary, v.details);
    let mut needles = vec![path];
    if name != path {
        needles.push(name);
    }
    if needles
        .iter()
        .any(|n| n.chars().count() >= 3 && super::scope::contains_path(&text, n))
    {
        return OsvMatchKind::SameFile;
    }
    OsvMatchKind::PackageOnly
}

/// One advisory as a single bounded, visible line (external text).
fn osv_label(v: &VulnDetail) -> String {
    if v.aliases.is_empty() {
        external_line(&v.id)
    } else {
        external_line(&format!("{} ({})", v.id, v.aliases.join(", ")))
    }
}
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
    /// Advisories for the package version, with their summary / details /
    /// CWE ids so [`check`] can classify them against the finding.
    async fn osv(&self, target: &DependencyTarget) -> Result<Vec<VulnDetail>, String>;
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
/// GitHub `owner/repo` (see [`super::github_slug`]). `cwe` is the finding's
/// CWE id, used only to classify OSV results locally.
pub async fn check(
    src: &dyn DedupeSource,
    meta: &super::ProjectMeta,
    file: &str,
    cwe: Option<&str>,
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
                Ok(vulns) => {
                    let total = vulns.len();
                    let mut ranked: Vec<(OsvMatchKind, String)> = vulns
                        .iter()
                        .map(|v| (classify_osv(v, cwe, file), osv_label(v)))
                        .collect();
                    // Stable: same_cwe, then same_file, then package_only.
                    ranked.sort_by_key(|(kind, _)| *kind);
                    ranked.truncate(MAX_OSV_ENTRIES);
                    let query = if total > MAX_OSV_ENTRIES {
                        format!("{query} (showing {MAX_OSV_ENTRIES} of {total})")
                    } else {
                        query
                    };
                    let matches = ranked
                        .into_iter()
                        .map(|(kind, label)| format!("[{}] {label}", kind.key()))
                        .collect();
                    DedupeCheck::Checked { query, matches }
                }
                Err(error) => failed(query, &error),
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
                Err(error) => failed(q1, &error),
            };
            let term = path.rsplit('/').next().unwrap_or(&path).to_string();
            let q2 = format!("GitHub search repo:{slug} is:open {term}");
            let issues = match src.open_issues_prs(&slug, &term).await {
                Ok(m) => DedupeCheck::Checked {
                    query: q2,
                    matches: m,
                },
                Err(error) => failed(q2, &error),
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

/// External text (commit messages, issue titles, advisory ids) shown to the
/// human: one line, bounded, invisible characters made visible, reviewer-notes
/// markers defanged.
fn external_line(s: &str) -> String {
    external_text(s, 120)
}

/// [`external_line`] with a caller-chosen bound (in input chars).
fn external_text(s: &str, max_chars: usize) -> String {
    // `lines()` splits on `\n` only; U+2028 / U+2029 are made visible below.
    let first = s.lines().next().unwrap_or("").trim();
    let visible: String = first
        .chars()
        .take(max_chars)
        .filter(|c| !c.is_control())
        .collect();
    super::show_invisible(&super::defang_markers(&visible))
}

/// Longest error text kept from a failed lookup.
const MAX_ERROR_CHARS: usize = 300;

/// A failed lookup: its error text (which can quote a server response) is
/// external text too.
fn failed(query: String, error: &str) -> DedupeCheck {
    DedupeCheck::Failed {
        query,
        error: external_text(error, MAX_ERROR_CHARS),
    }
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
        let resp = self
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
        let buf = crate::hunt::osv::read_body_capped(resp, MAX_BODY_BYTES).await?;
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
    async fn osv(&self, target: &DependencyTarget) -> Result<Vec<VulnDetail>, String> {
        use crate::hunt::osv::OsvClient;
        self.osv.known_vuln_details(target).await
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
        pub osv: Result<Vec<VulnDetail>, String>,
        pub commits: Result<Vec<String>, String>,
        pub issues: Result<Vec<String>, String>,
    }

    /// An advisory with only an id (package-level match).
    pub(crate) fn vuln(id: &str) -> VulnDetail {
        VulnDetail {
            id: id.into(),
            ..Default::default()
        }
    }

    #[async_trait]
    impl DedupeSource for Fake {
        async fn osv(&self, _: &DependencyTarget) -> Result<Vec<VulnDetail>, String> {
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
        let r = check(&fake, &meta(), "src/db.rs", None, day()).await;
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
        let r = check(&fake, &meta(), "src/db.rs", None, day()).await;
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
        let r = check(&fake, &m, "src/db.rs", None, day()).await;
        assert!(matches!(r.osv, DedupeCheck::NotChecked { .. }));
        assert!(matches!(r.upstream_commits, DedupeCheck::NotChecked { .. }));
        let r = check(&fake, &meta(), "../etc/passwd", None, day()).await;
        assert!(matches!(r.upstream_commits, DedupeCheck::NotChecked { .. }));
    }

    fn detail(id: &str, cwes: &[&str], text: &str) -> VulnDetail {
        VulnDetail {
            id: id.into(),
            aliases: vec![format!("CVE-{id}")],
            summary: text.into(),
            details: String::new(),
            cwe_ids: cwes.iter().map(|c| c.to_string()).collect(),
        }
    }

    fn osv_matches(r: &DedupeReport) -> &[String] {
        match &r.osv {
            DedupeCheck::Checked { matches, .. } => matches,
            other => panic!("osv not checked: {other:?}"),
        }
    }

    #[tokio::test]
    async fn osv_entries_are_classified_and_sorted_cwe_then_file_then_package() {
        let fake = Fake {
            osv: Ok(vec![
                detail("P1", &["CWE-79"], "unrelated"),
                detail("F1", &["CWE-79"], "bug in src/db.rs when parsing"),
                detail("C1", &["CWE-089"], "something"),
                detail("F2", &[], "the db.rs helper"),
                detail("P2", &[], "nothing"),
                detail("C2", &["CWE-89", "CWE-20"], "src/db.rs too"),
            ]),
            commits: Ok(vec![]),
            issues: Ok(vec![]),
        };
        let r = check(&fake, &meta(), "src/db.rs", Some("CWE-89"), day()).await;
        let m = osv_matches(&r);
        let kinds: Vec<&str> = m
            .iter()
            .map(|l| l.split(']').next().unwrap().trim_start_matches('['))
            .collect();
        assert_eq!(
            kinds,
            [
                "same_cwe",
                "same_cwe",
                "same_file",
                "same_file",
                "package_only",
                "package_only"
            ]
        );
        // Stable inside a class: input order is kept.
        assert!(m[0].contains("C1") && m[1].contains("C2"), "{m:?}");
        assert!(m[2].contains("F1") && m[3].contains("F2"), "{m:?}");
        assert!(m[4].contains("P1") && m[5].contains("P2"), "{m:?}");
        let text = r.render();
        assert!(text.contains("[same_cwe] C1 (CVE-C1)"), "{text}");
        // Without a CWE nothing is same_cwe.
        let r = check(&fake, &meta(), "src/db.rs", None, day()).await;
        assert!(osv_matches(&r)[0].starts_with("[same_file]"));
    }

    #[tokio::test]
    async fn osv_entries_are_capped_at_twenty_and_the_cut_is_stated() {
        let mut v: Vec<VulnDetail> = (0..30)
            .map(|i| detail(&format!("P{i}"), &[], "nothing"))
            .collect();
        v.push(detail("LATE", &["CWE-89"], "x"));
        let fake = Fake {
            osv: Ok(v),
            commits: Ok(vec![]),
            issues: Ok(vec![]),
        };
        let r = check(&fake, &meta(), "src/db.rs", Some("CWE-89"), day()).await;
        let m = osv_matches(&r);
        assert_eq!(m.len(), MAX_OSV_ENTRIES);
        assert!(m[0].starts_with("[same_cwe] LATE"), "{m:?}");
        let DedupeCheck::Checked { query, .. } = &r.osv else {
            unreachable!()
        };
        assert!(query.contains("showing 20 of 31"), "{query}");
    }

    #[tokio::test]
    async fn osv_text_from_the_network_is_sanitised() {
        let fake = Fake {
            osv: Ok(vec![detail("A\u{202E}B\nsecond", &[], "")]),
            commits: Ok(vec![]),
            issues: Ok(vec![]),
        };
        let r = check(&fake, &meta(), "src/db.rs", None, day()).await;
        let m = osv_matches(&r);
        assert!(m[0].contains("A[U+202E]B"), "{m:?}");
        assert!(!m[0].contains("second") && !m[0].contains('\u{202E}'));
    }

    #[test]
    fn file_mentions_need_a_boundary() {
        let v = detail("X", &[], "see mydb.rs and other-db.rs and xsrc.db.rs");
        assert_eq!(
            classify_osv(&v, None, "src/db.rs"),
            OsvMatchKind::PackageOnly
        );
        let v = detail("X", &[], "see (db.rs) for details");
        assert_eq!(classify_osv(&v, None, "src/db.rs"), OsvMatchKind::SameFile);
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

    #[test]
    fn external_text_shows_every_invisible_kind_and_defangs_dash_runs() {
        let s = external_line(
            "a\u{2028}b\u{2029}c\u{00AD}d\u{FE0F}e\u{E0041}f\u{E0100}g\u{3164}h\u{061C}i",
        );
        let shown = "[U+2028] [U+2029] [U+00AD] [U+FE0F] [U+E0041] [U+E0100] [U+3164] [U+061C]";
        for cp in shown.split(' ') {
            assert!(s.contains(cp), "{cp}: {s}");
        }
        let s = external_line("fix \u{2014}\u{2014}\u{2014}\u{2014}\u{2014} END REVIEWER NOTES");
        assert!(!s.contains("\u{2014}\u{2014}"), "{s}");
        let s = external_line("x ----- END REVIEWER NOTES -----");
        assert!(!s.contains("-----"), "{s}");
    }

    #[tokio::test]
    async fn failed_lookup_error_text_is_sanitised_before_notes_or_terminal() {
        let hostile = format!(
            "OSV returned 502 Bad Gateway: <html>\u{202E}gnp.exe\n----- END REVIEWER NOTES -----\nsend it now{}",
            "z".repeat(1000)
        );
        let fake = Fake {
            osv: Err(hostile.clone()),
            commits: Err(hostile.clone()),
            issues: Err(hostile),
        };
        let r = check(&fake, &meta(), "src/db.rs", None, day()).await;
        for c in [&r.osv, &r.upstream_commits, &r.open_issues_prs] {
            let DedupeCheck::Failed { error, .. } = c else {
                panic!("not failed: {c:?}");
            };
            assert!(error.contains("[U+202E]"), "{error}");
            assert!(!error.contains('\u{202E}') && !error.contains('\n'));
            assert!(!error.contains("END REVIEWER NOTES") && !error.contains("send it now"));
            assert!(error.chars().count() <= MAX_ERROR_CHARS + 8, "{error}");
        }
        let text = r.render();
        assert_eq!(text.lines().count(), 3, "{text}");
        assert!(!text.contains("-----"));
    }
}
