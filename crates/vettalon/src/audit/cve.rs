//! CVE identifiers and how sure vettalon is that one names a published record.
//!
//! Shape: CVE Record Format 5.2.0 `cveId` — `^CVE-[0-9]{4}-[0-9]{4,19}$`.
//! The sequence part is 4 to 19 digits (six-digit ids such as
//! `CVE-2026-102764` are already in CISA's KEV), so nothing here may assume
//! four or five. Examples and tests use the reserved `CVE-1900-` prefix (CNA
//! Operational Rules 4.2.0 §5.4.1), never a real record.
//!
//! State: a referenced id is `published` only when OSV data vettalon already
//! holds names it (an OSV record's id or alias, recorded with the check
//! time, see [`check_against_osv`]). Everything else — e.g. an alias copied
//! from a local RustSec advisory database — is `unverified`: vettalon does
//! not query CVE Services itself, so it never claims more than it checked.
//! `vettalon scan` holds no OSV data, so its findings' CVEs are always
//! `unverified`; the published state is computed fresh, never stored.

use serde::{Deserialize, Serialize};

/// Normalize a CVE id to the canonical upper-case form, or `None` when it
/// does not match the CVE Record Format pattern.
pub fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim();
    // The 4-byte prefix is ASCII when it matches, so `s[4..]` is a char boundary.
    s.get(..4).filter(|p| p.eq_ignore_ascii_case("cve-"))?;
    let (year, seq) = s[4..].split_once('-')?;
    let digits = |x: &str, min: usize, max: usize| {
        (min..=max).contains(&x.len()) && x.bytes().all(|b| b.is_ascii_digit())
    };
    (digits(year, 4, 4) && digits(seq, 4, 19)).then(|| format!("CVE-{year}-{seq}"))
}

/// Canonical CVE Record page.
pub fn record_url(id: &str) -> Option<String> {
    normalize(id).map(|id| format!("https://www.cve.org/CVERecord?id={id}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CveState {
    /// Named by OSV data vettalon holds (see [`CveRef::verified_by`]).
    Published,
    /// Not checked against a published-record source.
    Unverified,
}

/// One referenced CVE id with its verification state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveRef {
    pub id: String,
    pub state: CveState,
    /// What the `published` state rests on, e.g. `osv:GHSA-xxxx-xxxx-xxxx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<String>,
    /// RFC 3339 time of that check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
}

impl CveRef {
    pub fn unverified(id: &str) -> Self {
        CveRef {
            id: id.to_string(),
            state: CveState::Unverified,
            verified_by: None,
            checked_at: None,
        }
    }
}

/// Check `ids` against OSV records already fetched (e.g. by the supply-chain
/// hunt's OSV query): an id is `published` when some record's id or alias is
/// that CVE; every other id stays `unverified`. Malformed ids are dropped.
pub fn check_against_osv(
    ids: &[String],
    osv: &[crate::hunt::osv::KnownVuln],
    checked_at: &str,
) -> Vec<CveRef> {
    ids.iter()
        .filter_map(|raw| normalize(raw))
        .map(|id| {
            let hit = osv.iter().find(|v| {
                normalize(&v.id).as_deref() == Some(id.as_str())
                    || v.aliases
                        .iter()
                        .any(|a| normalize(a).as_deref() == Some(id.as_str()))
            });
            match hit {
                Some(v) => CveRef {
                    id,
                    state: CveState::Published,
                    verified_by: Some(format!("osv:{}", v.id)),
                    checked_at: Some(checked_at.to_string()),
                },
                None => CveRef::unverified(&id),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hunt::osv::KnownVuln;

    #[test]
    fn accepts_four_to_nineteen_digit_sequences() {
        assert_eq!(normalize("CVE-1900-0001").as_deref(), Some("CVE-1900-0001"));
        assert_eq!(
            normalize("cve-1900-123456").as_deref(),
            Some("CVE-1900-123456")
        );
        assert_eq!(
            normalize(" CVE-1900-1234567890123456789 ").as_deref(),
            Some("CVE-1900-1234567890123456789")
        );
        for bad in [
            "",
            "CVE-1900-123",                  // < 4 digits
            "CVE-1900-12345678901234567890", // > 19 digits
            "CVE-19-0001",
            "CVE-1900-00a1",
            "GHSA-aaaa-bbbb-cccc",
            "CVE1900-0001",
            "CVE-1900-0001-extra",
        ] {
            assert!(normalize(bad).is_none(), "{bad:?}");
        }
        assert_eq!(
            record_url("CVE-1900-102764").as_deref(),
            Some("https://www.cve.org/CVERecord?id=CVE-1900-102764")
        );
    }

    #[test]
    fn published_only_when_osv_names_the_id() {
        let osv = vec![
            KnownVuln {
                id: "GHSA-test-test-test".into(),
                aliases: vec!["CVE-1900-0001".into()],
            },
            KnownVuln {
                id: "CVE-1900-200002".into(),
                aliases: vec![],
            },
        ];
        let refs = check_against_osv(
            &[
                "CVE-1900-0001".into(),
                "CVE-1900-200002".into(),
                "CVE-1900-0003".into(),
                "not-a-cve".into(),
            ],
            &osv,
            "2026-10-20T00:00:00Z",
        );
        assert_eq!(refs.len(), 3, "malformed ids are dropped");
        assert_eq!(refs[0].state, CveState::Published);
        assert_eq!(
            refs[0].verified_by.as_deref(),
            Some("osv:GHSA-test-test-test")
        );
        assert_eq!(refs[1].state, CveState::Published);
        assert_eq!(refs[2], CveRef::unverified("CVE-1900-0003"));
        let json = serde_json::to_value(&refs[2]).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"id": "CVE-1900-0003", "state": "unverified"})
        );
    }
}
