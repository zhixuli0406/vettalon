//! CWE knowledge base for report enrichment: zh-TW (`cwe_kb.json`) plus
//! en / ja / ko report text (`cwe_kb_<lang>.json`, see [`localized`]).
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
    /// P0-3: MITRE CAPEC attack patterns this weakness is exploited through.
    /// Optional — only the OWASP Top 10-mapped entries carry it so far; a
    /// `#[serde(default)]` empty list keeps the other entries parsing
    /// unchanged. The report turns these into reference links so a reader
    /// sees the concrete attack pattern, not just the weakness class.
    #[serde(default)]
    pub capec: Vec<CapecPattern>,
    /// P0-3: a one-paragraph zh-TW attacker's-eye narrative — entry point,
    /// preconditions, what the attacker can chain to. Knowledge for the
    /// report, NOT an operational exploit (the PoC sandbox is the only place
    /// that actually exercises anything, and only against the user's own
    /// code). `None` for entries not yet enriched.
    #[serde(default)]
    pub attack_scenario_zh: Option<String>,
}

/// A MITRE CAPEC attack pattern reference (`CAPEC-66`, "SQL 注入").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapecPattern {
    /// Canonical id, `CAPEC-<n>`.
    pub id: String,
    pub name_zh: String,
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

/// Report text for one CWE in a non-Chinese report language. Written in our
/// own words from the zh-TW entry (not copied from MITRE's descriptions);
/// one file per language with the same ids and order as `cwe_kb.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedCwe {
    pub id: String,
    /// Short name in the report language (MITRE's full name is `name_en`).
    pub name: String,
    pub summary: String,
    pub mitigations: Vec<String>,
    pub attack_scenario: Option<String>,
    pub capec: Vec<LocalizedCapec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedCapec {
    pub id: String,
    pub name: String,
}

const KB_EN: &str = include_str!("cwe_kb_en.json");
const KB_JA: &str = include_str!("cwe_kb_ja.json");
const KB_KO: &str = include_str!("cwe_kb_ko.json");

fn localized_kb(lang: &str) -> Option<&'static HashMap<String, LocalizedCwe>> {
    static EN: OnceLock<HashMap<String, LocalizedCwe>> = OnceLock::new();
    static JA: OnceLock<HashMap<String, LocalizedCwe>> = OnceLock::new();
    static KO: OnceLock<HashMap<String, LocalizedCwe>> = OnceLock::new();
    let (cell, src) = match lang {
        "en" => (&EN, KB_EN),
        "ja" => (&JA, KB_JA),
        "ko" => (&KO, KB_KO),
        _ => return None,
    };
    Some(cell.get_or_init(|| {
        // Same degrade-to-empty policy as the zh-TW KB (reports fall back to
        // MITRE's name); tests keep it valid, and a broken file says so.
        let v: Vec<LocalizedCwe> = serde_json::from_str(src).unwrap_or_else(|e| {
            eprintln!(
                "[vettalon] cwe_kb_{lang}.json is invalid ({e}); CWE text falls back to names"
            );
            Vec::new()
        });
        v.into_iter().map(|e| (e.id.clone(), e)).collect()
    }))
}

/// Localized entry for a `CWE-<n>` id in `lang` (`en` | `ja` | `ko`).
pub fn localized(cwe: &str, lang: &str) -> Option<&'static LocalizedCwe> {
    let id = crate::audit::cwe::normalize(cwe)?;
    localized_kb(lang)?.get(&id)
}

/// OWASP Top 10 2021 title in `lang` plus the official page. English titles
/// are the project's own; Japanese titles are the OWASP project's Japanese
/// translation (OWASP/Top10 repo, `2021/docs/ja`). There is no Korean
/// translation of the 2021 list, so `ko` uses the English title. `zh-TW`
/// (or anything else) falls back to [`owasp_info`].
pub fn owasp_info_lang(category: &str, lang: &str) -> Option<(&'static str, &'static str)> {
    let (zh, url) = owasp_info(category)?;
    let code = category.get(..3)?;
    let en = match code {
        "A01" => "A01:2021 Broken Access Control",
        "A02" => "A02:2021 Cryptographic Failures",
        "A03" => "A03:2021 Injection",
        "A04" => "A04:2021 Insecure Design",
        "A05" => "A05:2021 Security Misconfiguration",
        "A06" => "A06:2021 Vulnerable and Outdated Components",
        "A07" => "A07:2021 Identification and Authentication Failures",
        "A08" => "A08:2021 Software and Data Integrity Failures",
        "A09" => "A09:2021 Security Logging and Monitoring Failures",
        "A10" => "A10:2021 Server-Side Request Forgery (SSRF)",
        _ => return None,
    };
    let ja = match code {
        "A01" => "A01:2021 アクセス制御の不備",
        "A02" => "A02:2021 暗号化の失敗",
        "A03" => "A03:2021 インジェクション",
        "A04" => "A04:2021 安全が確認されない不安な設計",
        "A05" => "A05:2021 セキュリティの設定ミス",
        "A06" => "A06:2021 脆弱で古くなったコンポーネント",
        "A07" => "A07:2021 識別と認証の失敗",
        "A08" => "A08:2021 ソフトウェアとデータの整合性の不具合",
        "A09" => "A09:2021 セキュリティログとモニタリングの失敗",
        _ => "A10:2021 サーバーサイドリクエストフォージェリ (SSRF)",
    };
    Some(match lang {
        "en" | "ko" => (en, url),
        "ja" => (ja, url),
        _ => (zh, url),
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

/// P0-3: MITRE CAPEC definition page for a `CAPEC-<n>` id. Returns `None` for
/// an id that isn't `CAPEC-<digits>`, so a malformed id never yields a link.
pub fn capec_url(capec_id: &str) -> Option<String> {
    let n = capec_id.trim().strip_prefix("CAPEC-")?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("https://capec.mitre.org/data/definitions/{n}.html"))
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
            // P0-3: every CAPEC id that ships must yield a MITRE link, and
            // carry a zh-TW name, so the report never renders a dead ref.
            for c in &e.capec {
                assert!(capec_url(&c.id).is_some(), "{} → {}", e.id, c.id);
                assert!(!c.name_zh.is_empty(), "{} → {}", e.id, c.id);
            }
        }
    }

    #[test]
    fn capec_url_only_accepts_well_formed_ids() {
        assert_eq!(
            capec_url("CAPEC-66").unwrap(),
            "https://capec.mitre.org/data/definitions/66.html"
        );
        assert!(capec_url("CAPEC-").is_none());
        assert!(capec_url("66").is_none());
        assert!(capec_url("CAPEC-6a").is_none());
    }

    #[test]
    fn cwe_295_carries_an_ssh_specific_mitigation() {
        // A hunt finding in an SSH library (ssh-exec) surfaced that the generic
        // CWE-295 mitigations read as TLS-only; this guards the SSH line.
        let e = lookup("CWE-295").unwrap();
        assert!(
            e.mitigations_zh
                .iter()
                .any(|m| m.contains("SSH") && m.contains("主機金鑰")),
            "{:?}",
            e.mitigations_zh
        );
    }

    #[test]
    fn at_least_the_injection_classes_carry_capec_and_scenario() {
        // P0-3 ships enrichment for the OWASP Top 10-mapped classes; SQLi is
        // the canonical one and must be populated.
        let sqli = lookup("CWE-89").unwrap();
        assert!(!sqli.capec.is_empty(), "CWE-89 should carry CAPEC patterns");
        assert!(sqli.attack_scenario_zh.is_some());
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
    fn localized_kbs_cover_every_entry_in_order() {
        let zh: Vec<CweEntry> = serde_json::from_str(KB_JSON).unwrap();
        for (lang, src) in [("en", KB_EN), ("ja", KB_JA), ("ko", KB_KO)] {
            let loc: Vec<LocalizedCwe> = serde_json::from_str(src)
                .unwrap_or_else(|e| panic!("cwe_kb_{lang}.json must match LocalizedCwe: {e}"));
            assert_eq!(loc.len(), zh.len(), "{lang}");
            for (z, l) in zh.iter().zip(&loc) {
                assert_eq!(z.id, l.id, "{lang}: order");
                assert!(
                    !l.name.is_empty() && !l.summary.is_empty(),
                    "{lang} {}",
                    l.id
                );
                assert_eq!(
                    z.mitigations_zh.len(),
                    l.mitigations.len(),
                    "{lang} {}",
                    l.id
                );
                assert_eq!(
                    z.attack_scenario_zh.is_some(),
                    l.attack_scenario.is_some(),
                    "{lang} {}",
                    l.id
                );
                let ids = |v: Vec<&str>| v.join(",");
                assert_eq!(
                    ids(z.capec.iter().map(|c| c.id.as_str()).collect()),
                    ids(l.capec.iter().map(|c| c.id.as_str()).collect()),
                    "{lang} {}",
                    l.id
                );
            }
            assert!(localized("cwe-89", lang).is_some());
        }
        // Script hygiene over every entry: no Han characters in Korean text,
        // no CJK at all in English text.
        let han = |s: &str| s.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c));
        let cjk = |s: &str| {
            s.chars()
                .any(|c| matches!(c as u32, 0x3040..=0x30FF | 0x4E00..=0x9FFF | 0xAC00..=0xD7AF))
        };
        for (lang, bad) in [("ko", &han as &dyn Fn(&str) -> bool), ("en", &cjk)] {
            let src = if lang == "ko" { KB_KO } else { KB_EN };
            let entries: Vec<LocalizedCwe> = serde_json::from_str(src).unwrap();
            for e in &entries {
                let mut texts = vec![e.name.as_str(), e.summary.as_str()];
                texts.extend(e.mitigations.iter().map(String::as_str));
                texts.extend(e.attack_scenario.as_deref());
                texts.extend(e.capec.iter().map(|c| c.name.as_str()));
                for t in texts {
                    assert!(!bad(t), "{lang} {}: {t}", e.id);
                }
            }
        }
        assert!(localized("CWE-79", "zh-TW").is_none());
    }

    #[test]
    fn owasp_titles_per_language() {
        let c = "A03:2021-Injection";
        assert_eq!(owasp_info_lang(c, "en").unwrap().0, "A03:2021 Injection");
        assert_eq!(
            owasp_info_lang(c, "ja").unwrap().0,
            "A03:2021 インジェクション"
        );
        assert_eq!(owasp_info_lang(c, "ko").unwrap().0, "A03:2021 Injection");
        assert_eq!(owasp_info_lang(c, "zh-TW"), owasp_info(c));
        assert!(owasp_info_lang("A99", "en").is_none());
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
