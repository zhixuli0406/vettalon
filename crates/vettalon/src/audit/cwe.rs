//! CWE identifiers: normalization from the many shapes sources emit.
//!
//! A CWE is advisory classification, not a security decision: an
//! unrecognizable value is dropped (`None`), never guessed or repaired into a
//! different id.
//!
//! [`mapping`] adds MITRE's mapping guidance from a bundled CWE List table
//! (version and date recorded in `cwe_usage.json`): Discouraged / Prohibited
//! ids (Pillars, Categories, Views, CWE-20/200/284, CWE-1426 …) are flagged,
//! with more specific knowledge-base ids suggested where one exists.

use serde::{Deserialize, Serialize};

/// Normalize a CWE reference to `CWE-<n>`.
///
/// Accepts `CWE-89`, `cwe-89`, `CWE 89`, `CWE:89`, `89`, zero-padded ids
/// (`CWE-000089`), and the semgrep registry form `CWE-89: Improper
/// Neutralization of …`. Rejects anything else, including id 0 (`CWE-0`,
/// `CWE-000`), more than 5 significant digits and non-ASCII separators.
pub fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim();
    let rest = match (s.get(..3), s.get(3..)) {
        (Some(p), Some(tail)) if p.eq_ignore_ascii_case("cwe") => {
            tail.trim_start_matches(['-', ' ', '_', ':'])
        }
        _ => s,
    };
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let (digits, after) = rest.split_at_checked(digits_end)?;
    // Leading zeros are padding (`cwe-079`, `CWE-000327`); the length cap
    // applies to the significant digits only.
    let significant = digits.trim_start_matches('0');
    if digits.is_empty() || significant.is_empty() || significant.len() > 5 {
        return None;
    }
    // After the number only a separator (or nothing) may follow: `89abc`
    // is not CWE-89.
    if after
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }
    let n: u32 = significant.parse().ok()?;
    (n > 0).then(|| format!("CWE-{n}"))
}

/// GitHub's SARIF tag prefix (`external/cwe/cwe-079`), see [`sarif_tag`].
const SARIF_TAG_PREFIX: &str = "external/cwe/";

/// [`normalize`], plus GitHub's SARIF tag form `external/cwe/cwe-079`
/// (prefix matched case-insensitively at the start only).
pub fn normalize_tag(raw: &str) -> Option<String> {
    let s = raw.trim();
    match s.get(..SARIF_TAG_PREFIX.len()) {
        Some(p) if p.eq_ignore_ascii_case(SARIF_TAG_PREFIX) => {
            normalize(s.get(SARIF_TAG_PREFIX.len()..)?)
        }
        _ => normalize(s),
    }
}

/// A free-form tag that names a CWE explicitly: it must start with `CWE`
/// (`CWE-79`, `cwe-79: …`) or with `external/cwe/`. A bare number tag
/// (`"2021"`, `"89"`) is never read as an id.
pub fn tag_cwe(tag: &str) -> Option<String> {
    let t = tag.trim();
    let marked = |prefix: &str| {
        t.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    };
    if marked("cwe") || marked(SARIF_TAG_PREFIX) {
        normalize_tag(t)
    } else {
        None
    }
}

/// First CWE in a semgrep rule's `metadata.cwe` (a string or a list).
pub fn from_semgrep_metadata(meta: &serde_json::Value) -> Option<String> {
    match meta.get("cwe")? {
        serde_json::Value::String(s) => normalize(s),
        serde_json::Value::Array(items) => {
            items.iter().filter_map(|v| v.as_str()).find_map(normalize)
        }
        _ => None,
    }
}

/// The CWE number for SARIF's GitHub tag convention (`external/cwe/cwe-079`).
pub fn sarif_tag(cwe: &str) -> Option<String> {
    let n: u32 = normalize(cwe)?.strip_prefix("CWE-")?.parse().ok()?;
    Some(format!("external/cwe/cwe-{n:03}"))
}

// ── mapping usage (MITRE CWE List, Mapping_Notes/Usage) ─────────────────

/// Bundled table generated from the CWE List XML by
/// `scripts/standards/gen_cwe_usage.py` (source, version and date inside).
const USAGE_JSON: &str = include_str!("../cwe_usage.json");

/// MITRE's guidance on whether an id may be used to map a vulnerability's
/// root cause (CWE `Mapping_Notes/Usage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MappingUsage {
    Allowed,
    AllowedWithReview,
    /// Pillars, many Classes (CWE-20, CWE-200, CWE-284 …), CWE-1426.
    Discouraged,
    /// Every Category and View, and deprecated entries.
    Prohibited,
    /// Not an id in the bundled CWE List version at all.
    NotInCatalog,
}

impl MappingUsage {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "allowed" => Self::Allowed,
            "allowed-with-review" => Self::AllowedWithReview,
            "discouraged" => Self::Discouraged,
            "prohibited" => Self::Prohibited,
            _ => return None,
        })
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::AllowedWithReview => "allowed-with-review",
            Self::Discouraged => "discouraged",
            Self::Prohibited => "prohibited",
            Self::NotInCatalog => "not-in-catalog",
        }
    }

    /// Ids MITRE says not to map to (or that do not exist): flag them.
    pub fn flagged(self) -> bool {
        matches!(
            self,
            Self::Discouraged | Self::Prohibited | Self::NotInCatalog
        )
    }
}

/// What the bundled CWE List says about one id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CweMapping {
    pub id: String,
    /// CWE List version the usage was read from (e.g. `"4.20"`).
    pub cwe_version: &'static str,
    pub usage: MappingUsage,
    /// `Pillar` / `Class` / `Base` / `Variant` / `Compound` / `Category` / `View`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abstraction: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'static str>,
    /// Flagged ids only: more specific Allowed ids from vettalon's knowledge
    /// base (MITRE's own suggestions first, then descendants). Advisory.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggested: Vec<&'static str>,
}

impl CweMapping {
    /// A short English warning for a flagged id, `None` otherwise.
    pub fn warning(&self) -> Option<String> {
        if !self.usage.flagged() {
            return None;
        }
        let what = match self.usage {
            MappingUsage::NotInCatalog => format!("{} is not in CWE {}", self.id, self.cwe_version),
            _ => format!(
                "{} is {} for vulnerability mapping (CWE {}{})",
                self.id,
                self.usage.key(),
                self.cwe_version,
                self.abstraction
                    .map(|a| format!(", {a}"))
                    .unwrap_or_default()
            ),
        };
        Some(if self.suggested.is_empty() {
            format!("{what}; map to a more specific Base/Variant weakness")
        } else {
            format!("{what}; consider {}", self.suggested.join(", "))
        })
    }
}

#[derive(Deserialize)]
struct UsageTable {
    source: String,
    cwe_version: String,
    catalog_date: String,
    entries: Vec<UsageEntry>,
    restricted: std::collections::HashMap<String, (String, String)>,
    allowed: Vec<u32>,
    suggest: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct UsageEntry {
    id: String,
    name: String,
    abstraction: String,
    usage: String,
}

fn table() -> Option<&'static UsageTable> {
    static TABLE: std::sync::OnceLock<Option<UsageTable>> = std::sync::OnceLock::new();
    // A malformed file degrades to "no usage data" (mapping() → None);
    // `tests::usage_table_parses` keeps it from shipping.
    TABLE
        .get_or_init(|| serde_json::from_str(USAGE_JSON).ok())
        .as_ref()
}

/// `(version, release date, source)` of the bundled CWE List table.
pub fn catalog() -> Option<(&'static str, &'static str, &'static str)> {
    table().map(|t| {
        (
            t.cwe_version.as_str(),
            t.catalog_date.as_str(),
            t.source.as_str(),
        )
    })
}

/// Mapping usage of a CWE reference. `None` when `cwe` is not a CWE id or
/// the bundled table is unavailable.
pub fn mapping(cwe: &str) -> Option<CweMapping> {
    let id = normalize(cwe)?;
    let t = table()?;
    let n: u32 = id.strip_prefix("CWE-")?.parse().ok()?;
    let (usage, abstraction, name) = if let Some(e) = t.entries.iter().find(|e| e.id == id) {
        (
            MappingUsage::parse(&e.usage)?,
            Some(e.abstraction.as_str()),
            Some(e.name.as_str()),
        )
    } else if let Some((abstraction, usage)) = t.restricted.get(&id) {
        (
            MappingUsage::parse(usage)?,
            Some(abstraction.as_str()),
            None,
        )
    } else if t.allowed.binary_search(&n).is_ok() {
        (MappingUsage::Allowed, None, None)
    } else {
        (MappingUsage::NotInCatalog, None, None)
    };
    let suggested = if usage.flagged() {
        t.suggest
            .get(&id)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Some(CweMapping {
        id,
        cwe_version: t.cwe_version.as_str(),
        usage,
        abstraction,
        name,
        suggested,
    })
}

/// Prefer a more specific weakness for an ai_audit finding: when the model's
/// CWE is Discouraged/Prohibited and the model's OWN category (`kind`, via
/// the knowledge base) names one of that id's suggested Allowed children,
/// use the child. Returns `(cwe, replaced)`; `replaced` is the original id
/// when a swap happened. Anything else keeps the model's id (still flagged by
/// [`mapping`]) — vettalon never guesses a CWE the evidence doesn't name.
pub fn prefer_specific(cwe: Option<String>, kind: &str) -> (Option<String>, Option<String>) {
    let Some(original) = cwe else {
        return (None, None);
    };
    let child = mapping(&original)
        .filter(|m| {
            matches!(
                m.usage,
                MappingUsage::Discouraged | MappingUsage::Prohibited
            )
        })
        .and_then(|m| {
            let from_kind = crate::kb::for_kind(kind)?.id.as_str();
            m.suggested.contains(&from_kind).then_some(from_kind)
        });
    match child {
        Some(child) => (Some(child.to_string()), Some(original)),
        None => (Some(original), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_common_shapes() {
        assert_eq!(normalize("CWE-89").as_deref(), Some("CWE-89"));
        assert_eq!(normalize("cwe-079").as_deref(), Some("CWE-79"));
        assert_eq!(normalize("CWE 22").as_deref(), Some("CWE-22"));
        assert_eq!(normalize("918").as_deref(), Some("CWE-918"));
        assert_eq!(
            normalize(
                "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
            )
            .as_deref(),
            Some("CWE-95")
        );
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "CWE-",
            "CWE-0",
            "abc",
            "89abc",
            "CWE-123456",
            "null",
            "N/A",
        ] {
            assert!(normalize(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn zero_padding_and_colon_separators_are_read_whole() {
        for (raw, want) in [
            ("CWE-000327", "CWE-327"),
            ("cwe-0000079", "CWE-79"),
            ("000327", "CWE-327"),
            ("CWE:327", "CWE-327"),
            ("cwe: 327", "CWE-327"),
            ("CWE:0614: Sensitive Cookie", "CWE-614"),
            ("CWE-0000012345", "CWE-12345"),
        ] {
            assert_eq!(normalize(raw).as_deref(), Some(want), "{raw:?}");
        }
        // Padding never merges digits into another id, and zero is no id.
        assert_eq!(normalize("CWE-3270").as_deref(), Some("CWE-3270"));
        assert_eq!(normalize("CWE-0003270").as_deref(), Some("CWE-3270"));
        for bad in [
            "CWE-0",
            "CWE-000",
            "0000",
            "CWE:0",
            "CWE-0000123456",
            "CWE\u{2011}327",
            "CWE\u{2013}327",
            "CWE-０327",
        ] {
            assert!(normalize(bad).is_none(), "{bad:?}");
        }
        assert_eq!(
            normalize_tag("external/cwe/cwe-000327").as_deref(),
            Some("CWE-327")
        );
        assert_eq!(tag_cwe("CWE:614").as_deref(), Some("CWE-614"));
    }

    #[test]
    fn semgrep_metadata_string_or_list() {
        let list = serde_json::json!({"cwe": ["CWE-95: Eval injection", "CWE-94"]});
        assert_eq!(from_semgrep_metadata(&list).as_deref(), Some("CWE-95"));
        let single = serde_json::json!({"cwe": "CWE-79: Cross-site Scripting"});
        assert_eq!(from_semgrep_metadata(&single).as_deref(), Some("CWE-79"));
        assert!(from_semgrep_metadata(&serde_json::json!({})).is_none());
    }

    #[test]
    fn usage_table_parses_and_records_its_source() {
        let t = table().expect("cwe_usage.json must parse");
        assert_eq!(t.cwe_version, "4.20");
        assert_eq!(t.catalog_date, "2026-04-30");
        assert!(t.source.contains("cwec_v4.20.xml"), "{}", t.source);
        assert!(t.allowed.windows(2).all(|w| w[0] < w[1]), "allowed sorted");
        for e in &t.entries {
            assert!(MappingUsage::parse(&e.usage).is_some(), "{}", e.id);
        }
        for (id, (_, usage)) in &t.restricted {
            assert!(MappingUsage::parse(usage).is_some(), "{id}");
        }
        // Every knowledge-base id has an exact entry (the ids vettalon emits).
        for id in ["CWE-79", "CWE-89", "CWE-798", "CWE-20", "CWE-1321"] {
            assert!(t.entries.iter().any(|e| e.id == id), "{id}");
        }
        // Suggestions only ever point at usable ids.
        for (from, to) in &t.suggest {
            for id in to {
                let m = mapping(id).unwrap();
                assert!(!m.usage.flagged(), "{from} → {id} is {:?}", m.usage);
            }
        }
    }

    #[test]
    fn mapping_flags_discouraged_and_prohibited_ids() {
        let base = mapping("CWE-89").unwrap();
        assert_eq!(base.usage, MappingUsage::Allowed);
        assert_eq!(base.cwe_version, "4.20");
        assert_eq!(base.abstraction, Some("Base"));
        assert!(base.warning().is_none() && base.suggested.is_empty());
        for (id, usage) in [
            ("CWE-20", MappingUsage::Discouraged),   // Class
            ("CWE-200", MappingUsage::Discouraged),  // Class
            ("CWE-284", MappingUsage::Discouraged),  // Pillar
            ("CWE-707", MappingUsage::Discouraged),  // Pillar
            ("CWE-1426", MappingUsage::Discouraged), // GenAI output validation
            ("CWE-1000", MappingUsage::Prohibited),  // View
            ("CWE-1347", MappingUsage::Prohibited),  // Category
        ] {
            let m = mapping(id).unwrap();
            assert_eq!(m.usage, usage, "{id}");
            assert!(m.warning().unwrap().contains(id), "{id}");
        }
        assert_eq!(
            mapping("CWE-22").unwrap().usage,
            MappingUsage::AllowedWithReview
        );
        assert_eq!(mapping("CWE-1004").unwrap().usage, MappingUsage::Allowed);
        let missing = mapping("CWE-99999").unwrap();
        assert_eq!(missing.usage, MappingUsage::NotInCatalog);
        assert!(missing.warning().unwrap().contains("not in CWE 4.20"));
        assert!(mapping("not a cwe").is_none());
        assert!(mapping("CWE-284").unwrap().suggested.contains(&"CWE-862"));
        assert!(mapping("CWE-1426").unwrap().suggested.contains(&"CWE-77"));
    }

    #[test]
    fn prefer_specific_only_swaps_to_a_child_the_category_names() {
        // Model said the Pillar, its own category says SQL injection (a
        // descendant of CWE-707): use the child, keep the original.
        assert_eq!(
            prefer_specific(Some("CWE-707".into()), "sql_injection"),
            (Some("CWE-89".into()), Some("CWE-707".into()))
        );
        // Category unrelated to the flagged id: keep the model's id.
        assert_eq!(
            prefer_specific(Some("CWE-284".into()), "sql_injection"),
            (Some("CWE-284".into()), None)
        );
        // Allowed ids and missing ids are never touched.
        assert_eq!(
            prefer_specific(Some("CWE-79".into()), "sql_injection"),
            (Some("CWE-79".into()), None)
        );
        assert_eq!(prefer_specific(None, "sql_injection"), (None, None));
    }

    #[test]
    fn normalize_tag_reads_the_github_sarif_form_and_plain_shapes() {
        assert_eq!(
            normalize_tag("external/cwe/cwe-079").as_deref(),
            Some("CWE-79")
        );
        assert_eq!(
            normalize_tag("External/CWE/CWE-1321").as_deref(),
            Some("CWE-1321")
        );
        assert_eq!(normalize_tag("CWE-89: SQLi").as_deref(), Some("CWE-89"));
        for bad in [
            "external/cwe/",
            "external/cwe/cwe-79x",
            "x/external/cwe/cwe-79",
            "external/owasp/a03",
            "security",
        ] {
            assert!(normalize_tag(bad).is_none(), "{bad:?}");
        }
        assert_eq!(tag_cwe("CWE-89: SQLi").as_deref(), Some("CWE-89"));
        assert_eq!(tag_cwe("external/cwe/cwe-079").as_deref(), Some("CWE-79"));
        for unmarked in ["89", "2021", "security", "OWASP-A03", "a CWE-79"] {
            assert!(tag_cwe(unmarked).is_none(), "{unmarked:?}");
        }
        // Round trip with the exporter's tag.
        assert_eq!(
            normalize_tag(&sarif_tag("CWE-614").unwrap()).as_deref(),
            Some("CWE-614")
        );
    }

    #[test]
    fn sarif_tag_is_zero_padded() {
        assert_eq!(sarif_tag("CWE-79").as_deref(), Some("external/cwe/cwe-079"));
        assert_eq!(
            sarif_tag("CWE-1321").as_deref(),
            Some("external/cwe/cwe-1321")
        );
    }
}
