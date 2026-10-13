//! zh-TW CWE knowledge base for report enrichment (`cwe_kb.json`).
//!
//! 58 curated entries built from MITRE's CWE catalogue (v4.20 XML) and
//! cross-checked against the OWASP Top 10 2021 mapped-CWE lists. A report
//! looks up the standard description / mitigations by id instead of having a
//! model rewrite them every time.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CweEntry {
    pub id: String,
    pub name_en: String,
    pub name_zh: String,
    pub summary_zh: String,
    pub consequences_zh: Vec<String>,
    pub mitigations_zh: Vec<String>,
    /// `"A03:2021-Injection"`, or `None` when the CWE is in no 2021 category.
    pub owasp_top10_2021: Option<String>,
    pub kind_aliases: Vec<String>,
}

const KB_JSON: &str = include_str!("cwe_kb.json");

struct Kb {
    by_id: HashMap<String, CweEntry>,
    by_alias: HashMap<String, String>,
}

fn kb() -> &'static Kb {
    static KB: OnceLock<Kb> = OnceLock::new();
    KB.get_or_init(|| {
        // A malformed file degrades to an empty KB (reports still render,
        // just without enrichment); `tests::kb_parses` keeps it from shipping.
        let entries: Vec<CweEntry> = serde_json::from_str(KB_JSON).unwrap_or_default();
        let mut by_alias = HashMap::new();
        for e in &entries {
            for a in &e.kind_aliases {
                by_alias.insert(a.clone(), e.id.clone());
            }
        }
        let by_id = entries.into_iter().map(|e| (e.id.clone(), e)).collect();
        Kb { by_id, by_alias }
    })
}

/// Entry for a normalized `CWE-<n>` id.
pub fn lookup(cwe: &str) -> Option<&'static CweEntry> {
    let id = crate::audit::cwe::normalize(cwe)?;
    kb().by_id.get(&id)
}

/// Entry for a model's free-text category (`sql_injection`, `xss`, …), used
/// only as a labelled fallback when no source gave a CWE.
pub fn for_kind(kind: &str) -> Option<&'static CweEntry> {
    let key: String = kind
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let id = kb().by_alias.get(key.trim_matches('_'))?;
    kb().by_id.get(id)
}

/// Official OWASP Top 10 2021 page and title. zh-TW titles are the OWASP
/// project's own Traditional Chinese translation (OWASP/Top10 repo,
/// `2021/docs/zh-TW`); A08–A10 are untranslated there, so they stay English.
pub fn owasp_info(category: &str) -> Option<(&'static str, &'static str)> {
    let code = category.get(..3)?;
    Some(match code {
        "A01" => (
            "A01:2021 權限控制失效",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ),
        "A02" => (
            "A02:2021 加密機制失效",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ),
        "A03" => (
            "A03:2021 注入式攻擊",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ),
        "A04" => (
            "A04:2021 不安全設計",
            "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        ),
        "A05" => (
            "A05:2021 安全設定缺陷",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ),
        "A06" => (
            "A06:2021 易受攻擊和已淘汰的組件",
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        ),
        "A07" => (
            "A07:2021 認證及驗證機制失效",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        ),
        "A08" => (
            "A08:2021 Software and Data Integrity Failures",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        ),
        "A09" => (
            "A09:2021 Security Logging and Monitoring Failures",
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        ),
        "A10" => (
            "A10:2021 Server-Side Request Forgery (SSRF)",
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        ),
        _ => return None,
    })
}

/// MITRE definition page for a CWE id.
pub fn cwe_url(cwe: &str) -> Option<String> {
    let id = crate::audit::cwe::normalize(cwe)?;
    Some(format!(
        "https://cwe.mitre.org/data/definitions/{}.html",
        id.trim_start_matches("CWE-")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kb_parses_with_strict_schema() {
        let entries: Vec<CweEntry> =
            serde_json::from_str(KB_JSON).expect("cwe_kb.json must match CweEntry");
        assert!(entries.len() >= 50, "{}", entries.len());
        for e in &entries {
            assert!(
                crate::audit::cwe::normalize(&e.id).as_deref() == Some(e.id.as_str()),
                "{}",
                e.id
            );
            assert!(
                !e.name_zh.is_empty() && !e.mitigations_zh.is_empty(),
                "{}",
                e.id
            );
            if let Some(o) = &e.owasp_top10_2021 {
                assert!(owasp_info(o).is_some(), "{} → {o}", e.id);
            }
        }
    }

    #[test]
    fn lookup_by_id_and_kind() {
        assert_eq!(lookup("cwe-89").unwrap().id, "CWE-89");
        assert_eq!(for_kind("sql_injection").unwrap().id, "CWE-89");
        assert_eq!(for_kind("SQL Injection").unwrap().id, "CWE-89");
        assert_eq!(for_kind("xss").unwrap().id, "CWE-79");
        assert!(for_kind("definitely_not_a_kind").is_none());
        assert!(lookup("CWE-999999").is_none());
    }

    #[test]
    fn owasp_and_cwe_links() {
        let (title, url) = owasp_info("A03:2021-Injection").unwrap();
        assert!(title.contains("注入"));
        assert!(url.ends_with("A03_2021-Injection/"));
        assert_eq!(
            cwe_url("CWE-79").unwrap(),
            "https://cwe.mitre.org/data/definitions/79.html"
        );
    }
}
