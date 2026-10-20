//! Supply-chain hunt: OSV novelty check (phase 1b).
//!
//! Classifies a dependency against OSV's known-vulnerability database so the
//! hunt can separate "already disclosed" from "potentially new". The network
//! call is isolated behind [`OsvClient`], so the parsing and classification are
//! unit-tested offline; the live HTTP path is an `#[ignore]`d test (run with
//! `--ignored`), matching the sandbox live-test convention.
//!
//! Network boundary of this lookup client: only dependency `name@version`
//! coordinates are sent to `api.osv.dev`. Other hunt stages fetch registry
//! archives and send dependency source/context to configured model providers;
//! this lookup policy is not a global egress allowlist.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{DependencyTarget, Ecosystem};

/// OSV host. A const so the only reachable endpoint is auditable in one place.
pub const OSV_API_BASE: &str = "https://api.osv.dev";

/// One known advisory for a dependency version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownVuln {
    /// OSV id (often a GHSA), e.g. `GHSA-xxxx-xxxx-xxxx`.
    pub id: String,
    /// Cross-references, typically the CVE id(s).
    pub aliases: Vec<String>,
}

/// The OSV ecosystem string for an [`Ecosystem`].
pub fn osv_ecosystem(e: Ecosystem) -> &'static str {
    match e {
        Ecosystem::Cargo => "crates.io",
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "PyPI",
        Ecosystem::Go => "Go",
    }
}

/// Parse an OSV `/v1/query` response body into its known advisories. An empty
/// body (`{}`) or a missing `vulns` array means "none known", not an error.
pub fn parse_osv_response(body: &str) -> Result<Vec<KnownVuln>, String> {
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        vulns: Vec<Vuln>,
    }
    #[derive(Deserialize)]
    struct Vuln {
        id: String,
        #[serde(default)]
        aliases: Vec<String>,
    }
    let r: Resp =
        serde_json::from_str(body).map_err(|e| format!("OSV response is not valid JSON: {e}"))?;
    Ok(r.vulns
        .into_iter()
        .map(|v| KnownVuln {
            id: v.id,
            aliases: v.aliases,
        })
        .collect())
}

/// Parse an OSV `/v1/querybatch` response: `{"results":[{"vulns":[...]}, ...]}`,
/// one entry per query in the same order. Batch results carry ids (and
/// sometimes modified dates), enough to classify known vs not.
pub fn parse_osv_batch_response(body: &str) -> Result<Vec<Vec<KnownVuln>>, String> {
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        results: Vec<ResultEntry>,
    }
    #[derive(Deserialize)]
    struct ResultEntry {
        #[serde(default)]
        vulns: Vec<Vuln>,
    }
    #[derive(Deserialize)]
    struct Vuln {
        id: String,
        #[serde(default)]
        aliases: Vec<String>,
    }
    let r: Resp = serde_json::from_str(body)
        .map_err(|e| format!("OSV batch response is not valid JSON: {e}"))?;
    Ok(r.results
        .into_iter()
        .map(|res| {
            res.vulns
                .into_iter()
                .map(|v| KnownVuln {
                    id: v.id,
                    aliases: v.aliases,
                })
                .collect()
        })
        .collect())
}

/// Looks up known advisories for a dependency. Behind a trait so the hunt
/// logic is testable without the network.
#[async_trait]
pub trait OsvClient: Send + Sync {
    async fn known_vulns(&self, target: &DependencyTarget) -> Result<Vec<KnownVuln>, String>;

    /// Classify many dependencies at once. The default loops [`Self::known_vulns`]
    /// (what a test mock needs); [`HttpOsvClient`] overrides it with OSV's
    /// batch endpoint so a large `--include-transitive` hunt makes a handful
    /// of requests, not hundreds. Returns one entry per input, in order.
    async fn known_vulns_batch(
        &self,
        targets: &[DependencyTarget],
    ) -> Result<Vec<Vec<KnownVuln>>, String> {
        let mut out = Vec::with_capacity(targets.len());
        for t in targets {
            out.push(self.known_vulns(t).await?);
        }
        Ok(out)
    }
}

/// The live OSV client. Talks only to [`OSV_API_BASE`].
pub struct HttpOsvClient {
    base: String,
    http: reqwest::Client,
}

const MAX_OSV_REDIRECTS: usize = 3;

fn osv_redirect_allowed(url: &reqwest::Url, previous: usize) -> bool {
    previous <= MAX_OSV_REDIRECTS
        && url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.host_str() == Some("api.osv.dev")
        && url.username().is_empty()
        && url.password().is_none()
}

pub(super) fn osv_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if osv_redirect_allowed(attempt.url(), attempt.previous().len()) {
            attempt.follow()
        } else {
            attempt.error("OSV redirect outside HTTPS origin/port or hop limit")
        }
    })
}

pub(super) fn osv_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(osv_redirect_policy())
        .timeout(std::time::Duration::from_secs(30))
        .retry(reqwest::retry::never())
}

impl Default for HttpOsvClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpOsvClient {
    #[cfg(test)]
    pub(super) fn for_transport_test(http: reqwest::Client) -> Self {
        Self {
            base: OSV_API_BASE.to_string(),
            http,
        }
    }

    pub fn new() -> Self {
        HttpOsvClient {
            base: OSV_API_BASE.to_string(),
            http: osv_client_builder()
                .build()
                .expect("static OSV HTTP client configuration"),
        }
    }
}

#[async_trait]
impl OsvClient for HttpOsvClient {
    async fn known_vulns(&self, target: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
        let body = serde_json::json!({
            "version": target.version,
            "package": { "name": target.name, "ecosystem": osv_ecosystem(target.ecosystem) },
        });
        let resp = self
            .http
            .post(format!("{}/v1/query", self.base))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("OSV request failed: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("OSV read failed: {e}"))?;
        if !status.is_success() {
            return Err(format!(
                "OSV returned {status}: {}",
                crate::util::truncate_bytes(&text, 200)
            ));
        }
        parse_osv_response(&text)
    }

    async fn known_vulns_batch(
        &self,
        targets: &[DependencyTarget],
    ) -> Result<Vec<Vec<KnownVuln>>, String> {
        // OSV caps batch size. A failed or malformed chunk fails the batch;
        // scan_known keeps every dependency with explicit failed query evidence.
        const CHUNK: usize = 256;
        let mut out: Vec<Vec<KnownVuln>> = Vec::with_capacity(targets.len());
        for chunk in targets.chunks(CHUNK) {
            let queries: Vec<serde_json::Value> = chunk
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "version": t.version,
                        "package": { "name": t.name, "ecosystem": osv_ecosystem(t.ecosystem) },
                    })
                })
                .collect();
            let body = serde_json::json!({ "queries": queries });
            let parsed = async {
                let resp = self
                    .http
                    .post(format!("{}/v1/querybatch", self.base))
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| format!("OSV batch request failed: {e}"))?;
                let status = resp.status();
                let text = resp
                    .text()
                    .await
                    .map_err(|e| format!("OSV batch read failed: {e}"))?;
                if !status.is_success() {
                    return Err(format!("OSV batch returned {status}"));
                }
                parse_osv_batch_response(&text)
            }
            .await;
            let mut rows = parsed?;
            if rows.len() != chunk.len() {
                return Err("OSV batch reply has the wrong row count".into());
            }
            out.append(&mut rows);
        }
        Ok(out)
    }
}

/// Result of the advisory query, independent of the code audit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsvStatus {
    #[default]
    Unknown,
    Matched,
    Unmatched,
    Failed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvEvidence {
    pub status: OsvStatus,
    pub error: Option<String>,
    /// Elapsed batch classification time, shared by its dependency rows.
    pub duration_ms: u64,
}

/// A dependency paired with its advisory-query evidence. An empty advisory
/// array is not evidence of a successful query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyAdvisories {
    pub target: DependencyTarget,
    pub known: Vec<KnownVuln>,
    #[serde(default)]
    pub osv: OsvEvidence,
}

impl DependencyAdvisories {
    /// Compatibility name: true only for a successful query with no matches.
    /// It is not a claim that the dependency is safe or the finding is novel.
    pub fn is_clean(&self) -> bool {
        self.osv.status == OsvStatus::Unmatched && self.known.is_empty()
    }
}

/// Keep every target on a failed or malformed batch. Do not retry queries or
/// turn unknown advisory state into a novelty candidate.
pub async fn scan_known<C: OsvClient>(
    targets: &[DependencyTarget],
    client: &C,
) -> Vec<DependencyAdvisories> {
    let started = std::time::Instant::now();
    let batch = match client.known_vulns_batch(targets).await {
        Ok(rows) if rows.len() == targets.len() => Ok(rows),
        Ok(_) => Err("OSV batch reply has the wrong row count".to_string()),
        Err(error) => Err(crate::util::mask_sensitive_text(
            crate::util::truncate_bytes(&error, 300),
        )),
    };
    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    targets
        .iter()
        .enumerate()
        .map(|(i, target)| {
            let (known, status, error) = match &batch {
                Ok(rows) => {
                    let known = rows[i].clone();
                    let status = if known.is_empty() {
                        OsvStatus::Unmatched
                    } else {
                        OsvStatus::Matched
                    };
                    (known, status, None)
                }
                Err(error) => (Vec::new(), OsvStatus::Failed, Some(error.clone())),
            };
            DependencyAdvisories {
                target: target.clone(),
                known,
                osv: OsvEvidence {
                    status,
                    error,
                    duration_ms,
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str, version: &str) -> DependencyTarget {
        DependencyTarget {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            direct: true,
        }
    }

    #[test]
    fn parse_osv_response_extracts_ids_and_aliases() {
        let body =
            r#"{"vulns":[{"id":"GHSA-aaaa","aliases":["CVE-1900-0001"]},{"id":"GHSA-bbbb"}]}"#;
        let v = parse_osv_response(body).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, "GHSA-aaaa");
        assert_eq!(v[0].aliases, vec!["CVE-1900-0001"]);
        assert!(v[1].aliases.is_empty());
    }

    #[test]
    fn parse_osv_response_empty_body_is_no_vulns_not_an_error() {
        assert!(parse_osv_response("{}").unwrap().is_empty());
    }

    #[test]
    fn parse_osv_response_malformed_is_an_error() {
        assert!(parse_osv_response("not json").is_err());
    }

    #[test]
    fn osv_ecosystem_strings() {
        assert_eq!(osv_ecosystem(Ecosystem::Cargo), "crates.io");
        assert_eq!(osv_ecosystem(Ecosystem::Npm), "npm");
        assert_eq!(osv_ecosystem(Ecosystem::PyPi), "PyPI");
        assert_eq!(osv_ecosystem(Ecosystem::Go), "Go");
    }

    struct MockClient(Vec<KnownVuln>);
    #[async_trait]
    impl OsvClient for MockClient {
        async fn known_vulns(&self, _t: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn parse_osv_batch_preserves_order_and_empties() {
        let body = r#"{"results":[{"vulns":[{"id":"GHSA-a"}]},{},{"vulns":[{"id":"GHSA-b","aliases":["CVE-1"]}]}]}"#;
        let rows = parse_osv_batch_response(body).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0][0].id, "GHSA-a");
        assert!(rows[1].is_empty());
        assert_eq!(rows[2][0].aliases, vec!["CVE-1"]);
    }

    #[tokio::test]
    async fn scan_known_uses_the_batch_path() {
        // The default known_vulns_batch loops known_vulns, so the mock works
        // unchanged and scan_known still pairs each target correctly.
        let targets = vec![target("a", "1.0.0"), target("b", "2.0.0")];
        let rows = scan_known(&targets, &MockClient(vec![])).await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].target.name, "b");
    }

    #[tokio::test]
    async fn scan_known_pairs_each_target_with_its_advisories() {
        let targets = vec![target("a", "1.0.0"), target("b", "2.0.0")];
        let client = MockClient(vec![KnownVuln {
            id: "GHSA-x".into(),
            aliases: vec![],
        }]);
        let rows = scan_known(&targets, &client).await;
        assert_eq!(rows.len(), 2);
        assert!(!rows[0].is_clean());
        assert_eq!(rows[0].target.name, "a");
    }

    struct FailingClient;
    #[async_trait]
    impl OsvClient for FailingClient {
        async fn known_vulns(&self, _t: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
            Err("transient".into())
        }
    }

    #[tokio::test]
    async fn scan_known_keeps_failed_lookup_unknown_not_unmatched() {
        let targets = vec![target("a", "1.0.0")];
        let rows = scan_known(&targets, &FailingClient).await;
        assert_eq!(rows.len(), 1, "a failed lookup still yields a row");
        assert!(
            !rows[0].is_clean(),
            "failed OSV query must not be classified as unmatched"
        );
    }

    struct WrongCountClient;
    #[async_trait]
    impl OsvClient for WrongCountClient {
        async fn known_vulns(&self, _: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
            panic!("batch only")
        }
        async fn known_vulns_batch(
            &self,
            _: &[DependencyTarget],
        ) -> Result<Vec<Vec<KnownVuln>>, String> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn malformed_batch_count_is_failed_not_an_unmatched_default() {
        let rows = scan_known(&[target("a", "1")], &WrongCountClient).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].osv.status, OsvStatus::Failed);
        assert!(!rows[0].is_clean());
        assert!(rows[0].osv.error.as_deref().unwrap().contains("row count"));
    }

    #[test]
    fn legacy_advisory_row_stays_unknown() {
        let row: DependencyAdvisories = serde_json::from_str(
            r#"{"target":{"ecosystem":"npm","name":"x","version":"1","direct":true},"known":[]}"#,
        )
        .unwrap();
        assert_eq!(row.osv.status, OsvStatus::Unknown);
        assert!(!row.is_clean());
    }

    #[test]
    fn osv_transport_redirects_stay_on_https_standard_origin_and_are_bounded() {
        assert!(osv_redirect_allowed(
            &reqwest::Url::parse("https://api.osv.dev/v1/final").unwrap(),
            1
        ));
        assert!(osv_redirect_allowed(
            &reqwest::Url::parse("https://api.osv.dev:443/v1/final").unwrap(),
            3
        ));
        for url in [
            "http://api.osv.dev/x",
            "https://api.osv.dev:444/x",
            "https://evil.invalid/x",
            "https://user@api.osv.dev/x",
        ] {
            assert!(
                !osv_redirect_allowed(&reqwest::Url::parse(url).unwrap(), 1),
                "{url}"
            );
        }
        assert!(!osv_redirect_allowed(
            &reqwest::Url::parse("https://api.osv.dev/x").unwrap(),
            4
        ));
    }

    /// Live OSV check. Ignored by default (needs the network); run with
    /// `cargo test -p vettalon --lib hunt::osv -- --ignored`. lodash 4.17.11
    /// has long-standing advisories, so the lookup must come back non-empty.
    #[tokio::test]
    #[ignore = "hits api.osv.dev"]
    async fn live_osv_knows_a_vulnerable_lodash() {
        let client = HttpOsvClient::new();
        let t = target("lodash", "4.17.11");
        let known = client.known_vulns(&t).await.expect("OSV reachable");
        assert!(
            !known.is_empty(),
            "lodash 4.17.11 should have OSV advisories"
        );
    }
}
