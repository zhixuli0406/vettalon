//! CWE identifiers: normalization from the many shapes sources emit.
//!
//! A CWE is advisory classification, not a security decision: an
//! unrecognizable value is dropped (`None`), never guessed or repaired into a
//! different id.

/// Normalize a CWE reference to `CWE-<n>`.
///
/// Accepts `CWE-89`, `cwe-89`, `CWE 89`, `89`, and the semgrep registry form
/// `CWE-89: Improper Neutralization of …`. Rejects anything else, including
/// id 0 and over-long numbers.
pub fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim();
    let rest = match s.get(..3) {
        Some(p) if p.eq_ignore_ascii_case("cwe") => s[3..].trim_start_matches(['-', ' ', '_']),
        _ => s,
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || digits.len() > 5 {
        return None;
    }
    // After the number only a separator (or nothing) may follow: `89abc`
    // is not CWE-89.
    let after = &rest[digits.len()..];
    if after
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }
    let n: u32 = digits.parse().ok()?;
    (n > 0).then(|| format!("CWE-{n}"))
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
    fn semgrep_metadata_string_or_list() {
        let list = serde_json::json!({"cwe": ["CWE-95: Eval injection", "CWE-94"]});
        assert_eq!(from_semgrep_metadata(&list).as_deref(), Some("CWE-95"));
        let single = serde_json::json!({"cwe": "CWE-79: Cross-site Scripting"});
        assert_eq!(from_semgrep_metadata(&single).as_deref(), Some("CWE-79"));
        assert!(from_semgrep_metadata(&serde_json::json!({})).is_none());
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
