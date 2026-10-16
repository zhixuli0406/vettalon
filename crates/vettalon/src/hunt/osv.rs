//! Supply-chain hunt: OSV novelty check (phase 1b).
//!
//! Classifies a dependency against OSV's known-vulnerability database so the
//! hunt can separate "already disclosed" from "potentially new". The network
//! call is isolated behind [`OsvClient`], so the parsing and classification are
//! unit-tested offline; the live HTTP path is an `#[ignore]`d test (run with
//! `--ignored`), matching the sandbox live-test convention.
//!
//! Network boundary: this is
//! the hunt-mode egress exception. The client talks ONLY to `api.osv.dev`; the
//! project's own code never leaves the machine — only the public `name@version`
//! coordinate is sent.

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
            out.push(self.known_vulns(t).await.unwrap_or_default());
        }
        Ok(out)
    }
}

/// The live OSV client. Talks only to [`OSV_API_BASE`].
pub struct HttpOsvClient {
    base: String,
    http: reqwest::Client,
}

impl Default for HttpOsvClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpOsvClient {
    pub fn new() -> Self {
        HttpOsvClient {
            base: OSV_API_BASE.to_string(),
            http: reqwest::Client::new(),
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
        // OSV caps batch size; chunk well under it. A failed chunk degrades to
        // empties for that chunk (honest: never silently hide a dependency),
        // so one bad request does not sink the whole classification.
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
            match parsed {
                Ok(mut rows) if rows.len() == chunk.len() => out.append(&mut rows),
                Ok(_) => {
                    eprintln!(
                        "[vettalon] {}",
                        crate::lang::pick(
                            "OSV 批次回應筆數不符，該批視為查無",
                            "OSV batch reply has the wrong row count; treating the batch as no known vulnerabilities",
                        )
                    );
                    out.extend(chunk.iter().map(|_| Vec::new()));
                }
                Err(e) => {
                    eprintln!(
                        "[vettalon] {}",
                        crate::tr!(
                            "OSV 批次查詢失敗（該批視為查無）：{e}",
                            "OSV batch query failed (treating the batch as no known vulnerabilities): {e}"
                        )
                    );
                    out.extend(chunk.iter().map(|_| Vec::new()));
                }
            }
        }
        Ok(out)
    }
}

/// A dependency paired with its known advisories (empty = clean per OSV).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyAdvisories {
    pub target: DependencyTarget,
    pub known: Vec<KnownVuln>,
}

impl DependencyAdvisories {
    /// No OSV advisory for this version: a finding here is a novelty candidate.
    pub fn is_clean(&self) -> bool {
        self.known.is_empty()
    }
}

/// Look up known advisories for every target. A per-target failure is recorded
/// as `known: []` with the error on stderr (honest degradation: a transient
/// OSV failure must not silently hide a dependency), so the caller still gets a
/// row for every target. Sequential by design — OSV rate-limits and a hunt's
/// target list is already capped.
pub async fn scan_known<C: OsvClient>(
    targets: &[DependencyTarget],
    client: &C,
) -> Vec<DependencyAdvisories> {
    // One batch request where the client supports it; a whole-batch failure
    // degrades every row to "none known" rather than dropping dependencies.
    let batch = client.known_vulns_batch(targets).await.unwrap_or_else(|e| {
        eprintln!(
            "[vettalon] {}",
            crate::tr!(
                "OSV 批次查詢失敗，全部視為查無：{e}",
                "OSV batch query failed; treating everything as no known vulnerabilities: {e}"
            )
        );
        Vec::new()
    });
    targets
        .iter()
        .enumerate()
        .map(|(i, t)| DependencyAdvisories {
            target: t.clone(),
            known: batch.get(i).cloned().unwrap_or_default(),
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
            r#"{"vulns":[{"id":"GHSA-aaaa","aliases":["CVE-2020-0001"]},{"id":"GHSA-bbbb"}]}"#;
        let v = parse_osv_response(body).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].id, "GHSA-aaaa");
        assert_eq!(v[0].aliases, vec!["CVE-2020-0001"]);
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
    async fn scan_known_degrades_a_failed_lookup_to_empty_not_dropped() {
        let targets = vec![target("a", "1.0.0")];
        let rows = scan_known(&targets, &FailingClient).await;
        assert_eq!(rows.len(), 1, "a failed lookup still yields a row");
        assert!(rows[0].is_clean());
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
