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

/// Longest `summary` / `details` text kept from an OSV record.
const MAX_DETAIL_CHARS: usize = 4096;
const MAX_ID_CHARS: usize = 128;
const MAX_ALIASES: usize = 10;
const MAX_CWE_IDS: usize = 20;
const MAX_CWE_ID_CHARS: usize = 32;
/// Advisories kept from one `/v1/query` response for the duplicate check.
pub const MAX_DETAIL_VULNS: usize = 200;
/// Largest `/v1/query` response body read.
pub const MAX_QUERY_BODY_BYTES: usize = 1024 * 1024;

/// Read a response body, refusing one larger than `cap` bytes (checked on
/// the declared length and again while streaming).
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, String> {
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err("response exceeds the size cap".into());
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if buf.len() + chunk.len() > cap {
            return Err("response exceeds the size cap".into());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Visitor methods that read any scalar as `Default::default()` (an oddly
/// shaped optional OSV field is empty, never an error).
macro_rules! scalars_as_default {
    () => {
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
    };
}

/// Skip every element of a sequence without keeping it.
fn skip_seq<'de, A: serde::de::SeqAccess<'de>>(mut seq: A) -> Result<(), A::Error> {
    while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
    Ok(())
}

/// Skip every entry of a map without keeping it.
fn skip_map<'de, A: serde::de::MapAccess<'de>>(mut map: A) -> Result<(), A::Error> {
    while map
        .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
        .is_some()
    {}
    Ok(())
}

/// One `cwe_ids` element: kept (bounded) when it is a string.
#[derive(Default)]
struct CweItem(Option<String>);

impl<'de> Deserialize<'de> for CweItem {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CweItem;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a CWE id")
            }
            scalars_as_default!();
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<CweItem, E> {
                Ok(CweItem(Some(bounded(s, MAX_CWE_ID_CHARS))))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, seq: A) -> Result<CweItem, A::Error> {
                skip_seq(seq).map(|_| CweItem(None))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<CweItem, A::Error> {
                skip_map(map).map(|_| CweItem(None))
            }
        }
        d.deserialize_any(V)
    }
}

/// `database_specific.cwe_ids`: string elements only, at most
/// [`MAX_CWE_IDS`] of them, each bounded; anything else is empty.
#[derive(Default)]
struct CweIds(Vec<String>);

impl<'de> Deserialize<'de> for CweIds {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CweIds;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a list of CWE ids")
            }
            scalars_as_default!();
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<CweIds, E> {
                Ok(CweIds::default())
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<CweIds, A::Error> {
                let mut out = Vec::new();
                while out.len() < MAX_CWE_IDS {
                    match seq.next_element::<CweItem>()? {
                        Some(CweItem(Some(id))) => out.push(id),
                        Some(CweItem(None)) => {}
                        None => return Ok(CweIds(out)),
                    }
                }
                skip_seq(seq)?;
                Ok(CweIds(out))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<CweIds, A::Error> {
                skip_map(map).map(|_| CweIds::default())
            }
        }
        d.deserialize_any(V)
    }
}

/// An OSV record's `database_specific`, keeping only `cwe_ids`; every other
/// key is skipped without being kept, and a value that is not an object is
/// empty, not an error.
#[derive(Default)]
struct DatabaseSpecific {
    cwe_ids: Vec<String>,
}

impl<'de> Deserialize<'de> for DatabaseSpecific {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = DatabaseSpecific;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an OSV database_specific object")
            }
            scalars_as_default!();
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<DatabaseSpecific, E> {
                Ok(DatabaseSpecific::default())
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                seq: A,
            ) -> Result<DatabaseSpecific, A::Error> {
                skip_seq(seq).map(|_| DatabaseSpecific::default())
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<DatabaseSpecific, A::Error> {
                let mut out = DatabaseSpecific::default();
                while let Some(key) = map.next_key::<String>()? {
                    if key == "cwe_ids" {
                        out.cwe_ids = map.next_value::<CweIds>()?.0;
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_any(V)
    }
}

/// One advisory with the descriptive fields the pre-send duplicate check
/// compares against a finding. All text is bounded; the fields are optional
/// in OSV (a missing one stays empty).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnDetail {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub details: String,
    /// `database_specific.cwe_ids` (GitHub advisory records carry it).
    pub cwe_ids: Vec<String>,
}

fn bounded(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Parse an OSV `/v1/query` response keeping `summary`, `details` and
/// `database_specific.cwe_ids`. A missing or oddly shaped optional field is
/// left empty, never an error. At most [`MAX_DETAIL_VULNS`] records are
/// kept, each with bounded text.
pub fn parse_osv_details_response(body: &str) -> Result<Vec<VulnDetail>, String> {
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
        #[serde(default)]
        summary: Option<String>,
        #[serde(default)]
        details: Option<String>,
        #[serde(default)]
        database_specific: Option<DatabaseSpecific>,
    }
    let r: Resp =
        serde_json::from_str(body).map_err(|e| format!("OSV response is not valid JSON: {e}"))?;
    Ok(r.vulns
        .into_iter()
        .take(MAX_DETAIL_VULNS)
        .map(|v| {
            let cwe_ids = v.database_specific.map(|d| d.cwe_ids).unwrap_or_default();
            VulnDetail {
                id: bounded(&v.id, MAX_ID_CHARS),
                aliases: v
                    .aliases
                    .iter()
                    .take(MAX_ALIASES)
                    .map(|a| bounded(a, MAX_ID_CHARS))
                    .collect(),
                summary: bounded(v.summary.as_deref().unwrap_or(""), MAX_DETAIL_CHARS),
                details: bounded(v.details.as_deref().unwrap_or(""), MAX_DETAIL_CHARS),
                cwe_ids,
            }
        })
        .collect())
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

    /// Like [`Self::known_vulns`] but keeping each record's summary, details
    /// and CWE ids (for the pre-send duplicate check). The default has only
    /// ids and aliases to offer; [`HttpOsvClient`] overrides it. Same single
    /// request to the same host, nothing more.
    async fn known_vuln_details(
        &self,
        target: &DependencyTarget,
    ) -> Result<Vec<VulnDetail>, String> {
        Ok(self
            .known_vulns(target)
            .await?
            .into_iter()
            .map(|k| VulnDetail {
                id: k.id,
                aliases: k.aliases,
                ..Default::default()
            })
            .collect())
    }

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

    /// The raw `/v1/query` response body for one dependency, at most
    /// [`MAX_QUERY_BODY_BYTES`].
    async fn query_text(&self, target: &DependencyTarget) -> Result<String, String> {
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
        let body = read_body_capped(resp, MAX_QUERY_BODY_BYTES).await;
        if !status.is_success() {
            let text = body
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            return Err(format!(
                "OSV returned {status}: {}",
                crate::util::truncate_bytes(&text, 200)
            ));
        }
        let body = body.map_err(|e| format!("OSV read failed: {e}"))?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

#[async_trait]
impl OsvClient for HttpOsvClient {
    async fn known_vulns(&self, target: &DependencyTarget) -> Result<Vec<KnownVuln>, String> {
        parse_osv_response(&self.query_text(target).await?)
    }

    async fn known_vuln_details(
        &self,
        target: &DependencyTarget,
    ) -> Result<Vec<VulnDetail>, String> {
        parse_osv_details_response(&self.query_text(target).await?)
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
                let bytes = read_body_capped(resp, MAX_QUERY_BODY_BYTES).await;
                if !status.is_success() {
                    return Err(format!("OSV batch returned {status}"));
                }
                let bytes = bytes.map_err(|e| format!("OSV batch read failed: {e}"))?;
                parse_osv_batch_response(&String::from_utf8_lossy(&bytes))
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
    fn parse_osv_details_keeps_summary_details_and_cwe_ids_bounded() {
        let long = "x".repeat(10_000);
        let body = serde_json::json!({"vulns": [
            {"id": "GHSA-a", "aliases": ["CVE-1"], "summary": "SQLi in db.py",
             "details": long, "database_specific": {"cwe_ids": ["CWE-89", 7]}},
            {"id": "GHSA-b", "database_specific": {"cwe_ids": "odd"}},
            {"id": "GHSA-c", "database_specific": 5},
        ]})
        .to_string();
        let v = parse_osv_details_response(&body).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].summary, "SQLi in db.py");
        assert_eq!(v[0].details.chars().count(), MAX_DETAIL_CHARS);
        assert_eq!(v[0].cwe_ids, ["CWE-89"]);
        assert_eq!(v[0].aliases, ["CVE-1"]);
        assert!(v[1].cwe_ids.is_empty() && v[1].summary.is_empty());
        assert!(v[2].cwe_ids.is_empty());
        assert!(parse_osv_details_response("{}").unwrap().is_empty());
        assert!(parse_osv_details_response("nope").is_err());
    }

    #[test]
    fn parse_osv_details_caps_vulns_cwe_ids_and_skips_other_database_specific_keys() {
        // `database_specific` keeps only bounded string cwe_ids; other keys
        // (however large or nested) and other shapes are skipped.
        let many: Vec<String> = (0..50).map(|i| format!("CWE-{i}")).collect();
        let body = serde_json::json!({"vulns": [
            {"id": "A", "database_specific": {
                "severity": "HIGH",
                "nested": {"deep": [[[{"x": 1}]]], "big": "y".repeat(50_000)},
                "cwe_ids": many,
                "github_reviewed": true}},
            {"id": "B", "database_specific": {"cwe_ids": [
                format!("CWE-{}", "9".repeat(100)), null, {"o": 1}, ["CWE-1"], "CWE-79"]}},
            {"id": "C", "database_specific": ["CWE-89"]},
            {"id": "D", "database_specific": "CWE-89"},
            {"id": "E", "database_specific": null},
            {"id": "F", "database_specific": {"cwe_ids": {"0": "CWE-89"}}},
        ]})
        .to_string();
        let v = parse_osv_details_response(&body).unwrap();
        assert_eq!(v.len(), 6);
        assert_eq!(v[0].cwe_ids.len(), MAX_CWE_IDS);
        assert_eq!(v[0].cwe_ids[0], "CWE-0");
        assert_eq!(v[1].cwe_ids.len(), 2, "{:?}", v[1].cwe_ids);
        assert_eq!(v[1].cwe_ids[0].chars().count(), MAX_CWE_ID_CHARS);
        assert_eq!(v[1].cwe_ids[1], "CWE-79");
        for d in &v[2..] {
            assert!(d.cwe_ids.is_empty(), "{d:?}");
        }
        // Record count is capped before classification.
        let vulns: Vec<serde_json::Value> = (0..MAX_DETAIL_VULNS + 50)
            .map(|i| serde_json::json!({"id": format!("V{i}"), "summary": "s"}))
            .collect();
        let body = serde_json::json!({ "vulns": vulns }).to_string();
        let v = parse_osv_details_response(&body).unwrap();
        assert_eq!(v.len(), MAX_DETAIL_VULNS);
        assert_eq!(v[0].id, "V0");
    }

    /// One plain-HTTP reply on loopback with a body of `len` bytes, with or
    /// without a declared length.
    async fn serve_once(len: usize, declare_len: bool) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 4096];
            let _ = s.read(&mut req).await;
            let head = if declare_len {
                format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n")
            } else {
                "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".to_string()
            };
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&vec![b'x'; len]).await;
            let _ = s.shutdown().await;
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn response_bodies_are_read_with_a_cap() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let get = |url: String| {
            let client = client.clone();
            async move { client.get(url).send().await.unwrap() }
        };
        let ok = read_body_capped(get(serve_once(1000, true).await).await, 1000).await;
        assert_eq!(ok.unwrap().len(), 1000);
        for declare_len in [true, false] {
            let resp = get(serve_once(1001, declare_len).await).await;
            let err = read_body_capped(resp, 1000).await.unwrap_err();
            assert!(err.contains("size cap"), "{declare_len}: {err}");
        }
    }

    #[tokio::test]
    async fn the_batch_response_is_read_with_the_same_cap() {
        let url = serve_once(MAX_QUERY_BODY_BYTES + 1, true).await;
        let client = HttpOsvClient {
            base: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
        };
        let err = client
            .known_vulns_batch(&[target("a", "1.0.0")])
            .await
            .unwrap_err();
        assert!(err.contains("size cap"), "{err}");
    }

    #[tokio::test]
    async fn details_default_falls_back_to_ids_and_aliases() {
        let client = MockClient(vec![KnownVuln {
            id: "GHSA-x".into(),
            aliases: vec!["CVE-2".into()],
        }]);
        let v = client
            .known_vuln_details(&target("a", "1.0.0"))
            .await
            .unwrap();
        assert_eq!(v[0].id, "GHSA-x");
        assert_eq!(v[0].aliases, ["CVE-2"]);
        assert!(v[0].cwe_ids.is_empty());
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
