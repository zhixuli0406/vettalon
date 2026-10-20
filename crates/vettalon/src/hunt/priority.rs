//! Dependency priority for `hunt --dep-priority risk` (O8).
//!
//! `score = exposure × reach × criticality`, every factor in `0..=1` with the
//! signals that produced it, so the plan output can show *why* a dependency
//! ranks where it does. All inputs are offline: package-name tokens and a small
//! curated table (exposure), lockfile graph depth plus optional reachability
//! evidence (reach), and the shipped popularity snapshot plus local fan-in
//! (criticality). Download counts, deps.dev and OpenSSF criticality scores are
//! not queried; an absent signal is labelled `unknown`, never treated as safe.
//! Scorecard is not a risk input (its link to security outcomes is unstable);
//! it is not queried here at all, so ties fall back to direct-first, then name.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::graph::DepGraph;
use super::{DependencyTarget, Ecosystem, popular};

/// How `partition` orders candidates before the `--max-deps` cap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepPriority {
    /// Existing order: direct first, then name, then version.
    #[default]
    Default,
    /// `exposure × reach × criticality`, highest first.
    Risk,
}

/// Untrusted-input surface categories (the exposure table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Deserialization,
    Parser,
    Network,
    Compression,
    Crypto,
}

impl Exposure {
    /// Fixed weights. Documented in DATA-FLOW / README; change both together.
    pub fn weight(self) -> f64 {
        match self {
            Exposure::Deserialization | Exposure::Parser => 1.0,
            Exposure::Network | Exposure::Compression => 0.9,
            Exposure::Crypto => 0.8,
        }
    }
}

/// Exposure when no signal matched: not "safe", just no offline evidence.
pub const EXPOSURE_NO_SIGNAL: f64 = 0.3;
/// A one-hop signal (the package depends on an exposed package) is discounted.
pub const INDIRECT_DISCOUNT: f64 = 0.8;
/// Neutral value used for ordering when a factor is unknown.
pub const UNKNOWN_FACTOR: f64 = 0.6;

/// Exact name tokens (split on non-alphanumerics) → category.
const TOKENS: &[(&str, Exposure)] = &[
    ("serde", Exposure::Deserialization),
    ("bincode", Exposure::Deserialization),
    ("pickle", Exposure::Deserialization),
    ("msgpack", Exposure::Deserialization),
    ("rmp", Exposure::Deserialization),
    ("cbor", Exposure::Deserialization),
    ("protobuf", Exposure::Deserialization),
    ("prost", Exposure::Deserialization),
    ("avro", Exposure::Deserialization),
    ("bson", Exposure::Deserialization),
    ("marshal", Exposure::Deserialization),
    ("unmarshal", Exposure::Deserialization),
    ("deserialize", Exposure::Deserialization),
    ("serialize", Exposure::Deserialization),
    ("parse", Exposure::Parser),
    ("parser", Exposure::Parser),
    ("xml", Exposure::Parser),
    ("yaml", Exposure::Parser),
    ("yml", Exposure::Parser),
    ("toml", Exposure::Parser),
    ("json", Exposure::Parser),
    ("json5", Exposure::Parser),
    ("csv", Exposure::Parser),
    ("html", Exposure::Parser),
    ("markdown", Exposure::Parser),
    ("commonmark", Exposure::Parser),
    ("url", Exposure::Parser),
    ("uri", Exposure::Parser),
    ("multipart", Exposure::Parser),
    ("mime", Exposure::Parser),
    ("sql", Exposure::Parser),
    ("regex", Exposure::Parser),
    ("image", Exposure::Parser),
    ("pdf", Exposure::Parser),
    ("http", Exposure::Network),
    ("https", Exposure::Network),
    ("h2", Exposure::Network),
    ("h3", Exposure::Network),
    ("quic", Exposure::Network),
    ("socket", Exposure::Network),
    ("websocket", Exposure::Network),
    ("ws", Exposure::Network),
    ("tcp", Exposure::Network),
    ("udp", Exposure::Network),
    ("dns", Exposure::Network),
    ("grpc", Exposure::Network),
    ("smtp", Exposure::Network),
    ("proxy", Exposure::Network),
    ("zip", Exposure::Compression),
    ("gzip", Exposure::Compression),
    ("zlib", Exposure::Compression),
    ("flate", Exposure::Compression),
    ("flate2", Exposure::Compression),
    ("deflate", Exposure::Compression),
    ("inflate", Exposure::Compression),
    ("brotli", Exposure::Compression),
    ("zstd", Exposure::Compression),
    ("lz4", Exposure::Compression),
    ("xz", Exposure::Compression),
    ("lzma", Exposure::Compression),
    ("bzip2", Exposure::Compression),
    ("tar", Exposure::Compression),
    ("snappy", Exposure::Compression),
    ("compress", Exposure::Compression),
    ("decompress", Exposure::Compression),
    ("archive", Exposure::Compression),
    ("crypto", Exposure::Crypto),
    ("cryptography", Exposure::Crypto),
    ("cipher", Exposure::Crypto),
    ("aes", Exposure::Crypto),
    ("rsa", Exposure::Crypto),
    ("ecdsa", Exposure::Crypto),
    ("ed25519", Exposure::Crypto),
    ("x509", Exposure::Crypto),
    ("tls", Exposure::Crypto),
    ("ssl", Exposure::Crypto),
    ("rustls", Exposure::Crypto),
    ("openssl", Exposure::Crypto),
    ("hmac", Exposure::Crypto),
    ("jwt", Exposure::Crypto),
    ("jose", Exposure::Crypto),
    ("pem", Exposure::Crypto),
    ("pkcs8", Exposure::Crypto),
    ("bcrypt", Exposure::Crypto),
    ("argon2", Exposure::Crypto),
];

/// Well-known packages whose names carry no category token.
const KNOWN: &[(&str, Exposure)] = &[
    ("hyper", Exposure::Network),
    ("reqwest", Exposure::Network),
    ("tokio-tungstenite", Exposure::Network),
    ("tungstenite", Exposure::Network),
    ("axum", Exposure::Network),
    ("actix-web", Exposure::Network),
    ("ring", Exposure::Crypto),
    ("nom", Exposure::Parser),
    ("pest", Exposure::Parser),
    ("syn", Exposure::Parser),
    ("goblin", Exposure::Parser),
    ("object", Exposure::Parser),
    ("express", Exposure::Network),
    ("axios", Exposure::Network),
    ("undici", Exposure::Network),
    ("got", Exposure::Network),
    ("node-fetch", Exposure::Network),
    ("qs", Exposure::Parser),
    ("body-parser", Exposure::Parser),
    ("marked", Exposure::Parser),
    ("dompurify", Exposure::Parser),
    ("sanitize-html", Exposure::Parser),
    ("sharp", Exposure::Parser),
    ("jszip", Exposure::Compression),
    ("adm-zip", Exposure::Compression),
    ("requests", Exposure::Network),
    ("urllib3", Exposure::Network),
    ("httpx", Exposure::Network),
    ("aiohttp", Exposure::Network),
    ("paramiko", Exposure::Network),
    ("lxml", Exposure::Parser),
    ("pillow", Exposure::Parser),
    ("jinja2", Exposure::Parser),
    ("pyjwt", Exposure::Crypto),
    ("bleach", Exposure::Parser),
];

/// One factor with the signals behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Factor {
    pub value: f64,
    /// True when no signal was available and `value` is the neutral default.
    pub unknown: bool,
    pub basis: Vec<String>,
}

/// Score breakdown for one dependency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyPriority {
    pub target: DependencyTarget,
    pub score: f64,
    pub exposure: Factor,
    pub reach: Factor,
    pub criticality: Factor,
    /// Communication hint only; never part of the score. `not_queried` offline.
    pub scorecard: String,
}

/// Operator-supplied reachability verdict (e.g. wrapped adapter output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachRecord {
    pub ecosystem: Ecosystem,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    /// `reachable` | `not-observed` | `unknown` (adapter vocabulary).
    pub status: String,
    #[serde(default)]
    pub source: Option<String>,
}

/// Parse a reach-evidence file: a JSON array of [`ReachRecord`].
pub fn parse_reach_evidence(text: &str) -> Result<Vec<ReachRecord>, String> {
    let records: Vec<ReachRecord> = serde_json::from_str(text)
        .map_err(|e| format!("reach evidence is not a JSON array of records: {e}"))?;
    for r in &records {
        if !matches!(r.status.as_str(), "reachable" | "not-observed" | "unknown") {
            return Err(format!(
                "reach evidence status must be reachable|not-observed|unknown, got {:?}",
                r.status
            ));
        }
    }
    Ok(records)
}

fn tokens(name: &str) -> Vec<String> {
    name.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Direct exposure signals of a package name (no graph).
pub fn name_exposure(name: &str) -> Vec<(Exposure, String)> {
    let lower = name.to_ascii_lowercase();
    let mut out = Vec::new();
    let bare = lower.rsplit('/').next().unwrap_or(&lower).replace('_', "-");
    if let Some((_, e)) = KNOWN.iter().find(|(n, _)| *n == bare) {
        out.push((*e, format!("known package '{bare}'")));
    }
    for tok in tokens(&lower) {
        if let Some((_, e)) = TOKENS.iter().find(|(t, _)| *t == tok) {
            out.push((*e, format!("name token '{tok}'")));
        }
    }
    out
}

fn exposure_factor(t: &DependencyTarget, graph: &DepGraph) -> Factor {
    let mut best: Option<(f64, String)> = None;
    let mut consider = |value: f64, why: String| {
        if best.as_ref().is_none_or(|(v, _)| value > *v) {
            best = Some((value, why));
        }
    };
    for (e, why) in name_exposure(&t.name) {
        consider(e.weight(), format!("{e:?} via {why}").to_lowercase());
    }
    for dep in graph.deps_of(t) {
        for (e, why) in name_exposure(dep) {
            consider(
                e.weight() * INDIRECT_DISCOUNT,
                format!("{e:?} via dependency '{dep}' ({why})").to_lowercase(),
            );
        }
    }
    match best {
        Some((value, why)) => Factor {
            value,
            unknown: false,
            basis: vec![why],
        },
        None => Factor {
            value: EXPOSURE_NO_SIGNAL,
            unknown: false,
            basis: vec!["no offline untrusted-input signal (not evidence of safety)".into()],
        },
    }
}

fn reach_factor(t: &DependencyTarget, graph: &DepGraph, reach: &[ReachRecord]) -> Factor {
    let evidence = reach.iter().find(|r| {
        r.ecosystem == t.ecosystem
            && popular::normalize(t.ecosystem, &r.name) == popular::normalize(t.ecosystem, &t.name)
            && r.version.as_deref().is_none_or(|v| v == t.version)
    });
    if let Some(r) = evidence
        && r.status == "reachable"
    {
        return Factor {
            value: 1.0,
            unknown: false,
            basis: vec![format!(
                "reachability evidence: reachable ({})",
                r.source.as_deref().unwrap_or("operator file")
            )],
        };
    }
    let mut basis = Vec::new();
    let depth = if t.direct { Some(1) } else { graph.depth_of(t) };
    let (value, unknown) = match depth {
        Some(1) => {
            basis.push("direct dependency (graph depth 1)".into());
            (1.0, false)
        }
        Some(2) => {
            basis.push("transitive, graph depth 2".into());
            (0.7, false)
        }
        Some(d) => {
            basis.push(format!("transitive, graph depth {d}"));
            (0.5, false)
        }
        None => {
            basis.push("unknown: no lockfile edge graph for this dependency".into());
            (UNKNOWN_FACTOR, true)
        }
    };
    if let Some(r) = evidence {
        // Absence of an observed path is not evidence of non-reachability.
        basis.push(format!(
            "reachability evidence: {} (not used to lower reach)",
            r.status
        ));
    }
    Factor {
        value,
        unknown,
        basis,
    }
}

fn criticality_factor(t: &DependencyTarget, graph: &DepGraph) -> Factor {
    let mut signals: Vec<(f64, String)> = Vec::new();
    if let Some(rank) = popular::rank(t.ecosystem, &t.name) {
        let v = if rank <= 100 { 1.0 } else { 0.8 };
        signals.push((v, format!("popularity snapshot rank {rank}")));
    }
    match graph.dependents_of(t) {
        Some(n) if n >= 5 => signals.push((0.7, format!("{n} local dependents in lockfile"))),
        Some(n) if n >= 2 => signals.push((0.6, format!("{n} local dependents in lockfile"))),
        _ => {}
    }
    signals.sort_by(|a, b| b.0.total_cmp(&a.0));
    match signals.first() {
        Some((v, _)) => Factor {
            value: *v,
            unknown: false,
            basis: signals.iter().map(|(_, w)| w.clone()).collect(),
        },
        None => Factor {
            value: UNKNOWN_FACTOR,
            unknown: true,
            basis: vec![
                "unknown: not in the shipped popularity snapshot; download counts and \
                 dependents are not available offline"
                    .into(),
            ],
        },
    }
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Score one dependency.
pub fn score(t: &DependencyTarget, graph: &DepGraph, reach: &[ReachRecord]) -> DependencyPriority {
    let exposure = exposure_factor(t, graph);
    let reach = reach_factor(t, graph, reach);
    let criticality = criticality_factor(t, graph);
    DependencyPriority {
        target: t.clone(),
        score: round3(exposure.value * reach.value * criticality.value),
        exposure,
        reach,
        criticality,
        scorecard: "not_queried".into(),
    }
}

/// Score every target; the map is keyed by `(ecosystem, name, version)`.
pub fn score_all(
    targets: &[DependencyTarget],
    graph: &DepGraph,
    reach: &[ReachRecord],
) -> HashMap<(Ecosystem, String, String), DependencyPriority> {
    targets
        .iter()
        .map(|t| {
            (
                (t.ecosystem, t.name.clone(), t.version.clone()),
                score(t, graph, reach),
            )
        })
        .collect()
}

/// Deterministic risk order: score desc, then direct first, then name/version.
pub fn risk_cmp(a: (&DependencyTarget, f64), b: (&DependencyTarget, f64)) -> std::cmp::Ordering {
    b.1.total_cmp(&a.1)
        .then_with(|| b.0.direct.cmp(&a.0.direct))
        .then_with(|| a.0.name.cmp(&b.0.name))
        .then_with(|| a.0.version.cmp(&b.0.version))
}

/// One plan line: `score 0.720 = exposure 0.90 (…) × reach 1.00 (…) × criticality 0.80 (…)`.
pub fn render_breakdown(p: &DependencyPriority) -> String {
    let f = |x: &Factor| {
        format!(
            "{:.2}{} ({})",
            x.value,
            if x.unknown { "?" } else { "" },
            x.basis.join("; ")
        )
    };
    format!(
        "score {:.3} = exposure {} × reach {} × criticality {}",
        p.score,
        f(&p.exposure),
        f(&p.reach),
        f(&p.criticality)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(name: &str, direct: bool) -> DependencyTarget {
        DependencyTarget {
            ecosystem: Ecosystem::Cargo,
            name: name.into(),
            version: "1.0.0".into(),
            direct,
        }
    }

    #[test]
    fn exposure_table_is_transparent_and_name_based() {
        let g = DepGraph::default();
        let p = score(&t("quick-xml", true), &g, &[]);
        assert_eq!(p.exposure.value, 1.0);
        assert!(p.exposure.basis[0].contains("xml"), "{:?}", p.exposure);
        let plain = score(&t("itoa", true), &g, &[]);
        assert_eq!(plain.exposure.value, EXPOSURE_NO_SIGNAL);
        assert!(plain.exposure.basis[0].contains("not evidence of safety"));
        assert_eq!(score(&t("hyper", true), &g, &[]).exposure.value, 0.9);
    }

    #[test]
    fn indirect_exposure_is_discounted_and_named() {
        let mut g = DepGraph::default();
        g.edges.insert(
            (Ecosystem::Cargo, "wrapper".into(), "1.0.0".into()),
            vec!["flate2".into()],
        );
        let p = score(&t("wrapper", true), &g, &[]);
        assert!((p.exposure.value - 0.9 * INDIRECT_DISCOUNT).abs() < 1e-9);
        assert!(p.exposure.basis[0].contains("flate2"));
    }

    #[test]
    fn reach_uses_depth_unknown_and_never_lowers_on_not_observed() {
        let mut g = DepGraph::default();
        g.depth
            .insert((Ecosystem::Cargo, "deep".into(), "1.0.0".into()), 3);
        assert_eq!(score(&t("direct", true), &g, &[]).reach.value, 1.0);
        assert_eq!(score(&t("deep", false), &g, &[]).reach.value, 0.5);
        let unknown = score(&t("nowhere", false), &g, &[]);
        assert!(unknown.reach.unknown);
        assert_eq!(unknown.reach.value, UNKNOWN_FACTOR);
        let ev = |status: &str| ReachRecord {
            ecosystem: Ecosystem::Cargo,
            name: "deep".into(),
            version: None,
            status: status.into(),
            source: Some("adapter 0.2.0".into()),
        };
        assert_eq!(
            score(&t("deep", false), &g, &[ev("reachable")]).reach.value,
            1.0
        );
        let not_obs = score(&t("deep", false), &g, &[ev("not-observed")]);
        assert_eq!(not_obs.reach.value, 0.5, "absence does not lower reach");
        assert!(
            not_obs
                .reach
                .basis
                .iter()
                .any(|b| b.contains("not used to lower"))
        );
    }

    #[test]
    fn criticality_uses_snapshot_rank_or_unknown() {
        let g = DepGraph::default();
        let popular = score(&t("serde", true), &g, &[]);
        assert!(!popular.criticality.unknown);
        assert!(popular.criticality.basis[0].contains("rank"));
        let obscure = score(&t("zz-not-a-real-crate-name", true), &g, &[]);
        assert!(obscure.criticality.unknown);
        assert!(obscure.criticality.basis[0].contains("not available offline"));
    }

    #[test]
    fn score_is_the_product_and_order_is_deterministic() {
        let g = DepGraph::default();
        let p = score(&t("serde_json", true), &g, &[]);
        let product = p.exposure.value * p.reach.value * p.criticality.value;
        assert!((p.score - round3(product)).abs() < 1e-9);
        let a = t("a", false);
        let b = t("b", true);
        assert_eq!(risk_cmp((&a, 0.5), (&b, 0.5)), std::cmp::Ordering::Greater);
        assert_eq!(risk_cmp((&a, 0.9), (&b, 0.5)), std::cmp::Ordering::Less);
        assert!(render_breakdown(&p).starts_with("score "));
    }

    #[test]
    fn reach_evidence_file_is_validated() {
        let ok = r#"[{"ecosystem":"go","name":"golang.org/x/text","version":"v0.3.5","status":"reachable"}]"#;
        assert_eq!(parse_reach_evidence(ok).unwrap().len(), 1);
        assert!(
            parse_reach_evidence(r#"[{"ecosystem":"go","name":"x","status":"safe"}]"#).is_err()
        );
        assert!(parse_reach_evidence("{}").is_err());
    }
}
