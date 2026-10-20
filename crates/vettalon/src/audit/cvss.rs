//! CVSS scores from SOURCE-supplied vectors (FIRST CVSS v3.0/v3.1 §7.1 base
//! formula; CVSS v4.0 MacroVector method in [`super::cvss4`]).
//!
//! vettalon never invents a CVSS vector: a score exists only when a source
//! (a scanner advisory — never the auditing model) supplied a vector string.
//! This module parses that vector and computes the score so a report can show
//! version, score, rating, vector and (v4.0) nomenclature together.
//!
//! - v3.x: base score only; temporal/environmental metrics in the vector are
//!   tolerated but ignored.
//! - v4.0: the single v4.0 score over every metric the vector carries, named
//!   CVSS-B / CVSS-BT / CVSS-BE / CVSS-BTE. vettalon never adds Threat or
//!   Environmental metrics to a source's vector: Environmental values belong
//!   to the deploying organisation, and vettalon's own PoC runs are private,
//!   so if Threat metrics are ever emitted they must be `E:U` (FIRST FAQ:
//!   exploit code that will never become public is "Unreported/Unproven").

use serde::{Deserialize, Serialize};

/// A parsed CVSS vector and its computed score.
///
/// Serialized with derived, write-only fields (`rating`, and for v4.0
/// `nomenclature`) recomputed from the vector at write time. A finding's
/// stored score is read back through [`deserialize_rescored`], which keeps
/// only the vector and scores it again.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CvssScore {
    /// `"4.0"`, `"3.1"` or `"3.0"`.
    pub cvss_version: String,
    /// The vector exactly as the source supplied it.
    pub cvss_vector: String,
    /// Score, one decimal (0.0–10.0). v3.x: the Base score. v4.0: the v4.0
    /// score of the metrics present (see [`CvssScore::nomenclature`]); the
    /// field keeps its historical name for report compatibility.
    pub base_score: f64,
}

impl Serialize for CvssScore {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let nomenclature = self.nomenclature();
        let mut s =
            serializer.serialize_struct("CvssScore", 4 + usize::from(nomenclature.is_some()))?;
        s.serialize_field("cvss_version", &self.cvss_version)?;
        s.serialize_field("cvss_vector", &self.cvss_vector)?;
        s.serialize_field("base_score", &self.base_score)?;
        s.serialize_field("rating", self.rating())?;
        if let Some(n) = nomenclature {
            s.serialize_field("nomenclature", n)?;
        }
        s.end()
    }
}

/// Serde helper for a stored `Option<CvssScore>`: keep only the vector and
/// recompute everything else, so a hand-edited score (or version) in a report
/// file never reaches SARIF, CycloneDX or the Pro report. An entry whose
/// vector no longer scores is dropped (`None`), never kept on trust.
pub fn deserialize_rescored<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<CvssScore>, D::Error> {
    #[derive(Deserialize)]
    struct Stored {
        cvss_vector: String,
    }
    let stored: Option<Stored> = Option::deserialize(deserializer)?;
    Ok(stored.and_then(|s| CvssScore::from_vector(&s.cvss_vector)))
}

impl CvssScore {
    /// Parse a `CVSS:3.x/…` or `CVSS:4.0/…` vector. `None` when the prefix,
    /// a mandatory metric or a metric value is missing, duplicated, unknown
    /// or (v4.0) out of the specification's order — a malformed vector is
    /// dropped, never guessed.
    pub fn from_vector(vector: &str) -> Option<Self> {
        let vector = vector.trim();
        if vector.starts_with("CVSS:4.0/") {
            let score = super::cvss4::Vector4::parse(vector)?.score()?;
            return Some(CvssScore {
                cvss_version: "4.0".to_string(),
                cvss_vector: vector.to_string(),
                base_score: score,
            });
        }
        let (version, rest) = vector
            .strip_prefix("CVSS:3.1/")
            .map(|r| ("3.1", r))
            .or_else(|| vector.strip_prefix("CVSS:3.0/").map(|r| ("3.0", r)))?;
        let base = BaseMetrics::parse(rest)?;
        Some(CvssScore {
            cvss_version: version.to_string(),
            cvss_vector: vector.to_string(),
            base_score: base.score(version == "3.1"),
        })
    }

    /// Qualitative severity rating (FIRST v3.1 Table 14 / v4.0 Table 22):
    /// none/low/medium/high/critical.
    pub fn rating(&self) -> &'static str {
        rating(self.base_score)
    }

    /// FIRST's capitalised rating name (`None` … `Critical`).
    pub fn rating_label(&self) -> &'static str {
        match self.rating() {
            "none" => "None",
            "low" => "Low",
            "medium" => "Medium",
            "high" => "High",
            _ => "Critical",
        }
    }

    /// v4.0 nomenclature (`CVSS-B`, `CVSS-BT`, `CVSS-BE`, `CVSS-BTE`) for the
    /// metrics the vector carries; `None` for v3.x, which has no such names.
    pub fn nomenclature(&self) -> Option<&'static str> {
        if self.cvss_version != "4.0" {
            return None;
        }
        super::cvss4::Vector4::parse(&self.cvss_vector).map(|v| super::cvss4::nomenclature(&v))
    }

    /// One line carrying version, score, rating and (v4.0) nomenclature, e.g.
    /// `CVSS v4.0 8.7 High (CVSS-B)` or `CVSS v3.1 9.8 Critical`. FIRST asks
    /// that a score always travel with its vector: show `cvss_vector` next to
    /// it.
    pub fn label(&self) -> String {
        let mut out = format!(
            "CVSS v{} {:.1} {}",
            self.cvss_version,
            self.base_score,
            self.rating_label()
        );
        if let Some(n) = self.nomenclature() {
            out.push_str(&format!(" ({n})"));
        }
        out
    }
}

/// Qualitative rating for a base score (identical bands in v3.1 and v4.0).
pub fn rating(score: f64) -> &'static str {
    if score <= 0.0 {
        "none"
    } else if score < 4.0 {
        "low"
    } else if score < 7.0 {
        "medium"
    } else if score < 9.0 {
        "high"
    } else {
        "critical"
    }
}

#[derive(Debug, Clone, Copy)]
struct BaseMetrics {
    av: f64,
    ac: f64,
    pr: char,
    ui: f64,
    scope_changed: bool,
    c: f64,
    i: f64,
    a: f64,
}

impl BaseMetrics {
    fn parse(rest: &str) -> Option<Self> {
        let (mut av, mut ac, mut pr, mut ui, mut s, mut c, mut i, mut a) =
            (None, None, None, None, None, None, None, None);
        for part in rest.split('/') {
            let (key, val) = part.split_once(':')?;
            let slot = match key {
                "AV" => &mut av,
                "AC" => &mut ac,
                "PR" => &mut pr,
                "UI" => &mut ui,
                "S" => &mut s,
                "C" => &mut c,
                "I" => &mut i,
                "A" => &mut a,
                // Temporal / environmental metrics: allowed, not scored here.
                _ => continue,
            };
            let mut chars = val.chars();
            let ch = chars.next()?;
            if chars.next().is_some() || slot.replace(ch).is_some() {
                return None; // multi-char value or duplicated metric
            }
        }
        let cia = |v: char| match v {
            'H' => Some(0.56),
            'L' => Some(0.22),
            'N' => Some(0.0),
            _ => None,
        };
        Some(BaseMetrics {
            av: match av? {
                'N' => 0.85,
                'A' => 0.62,
                'L' => 0.55,
                'P' => 0.2,
                _ => return None,
            },
            ac: match ac? {
                'L' => 0.77,
                'H' => 0.44,
                _ => return None,
            },
            pr: match pr? {
                p @ ('N' | 'L' | 'H') => p,
                _ => return None,
            },
            ui: match ui? {
                'N' => 0.85,
                'R' => 0.62,
                _ => return None,
            },
            scope_changed: match s? {
                'U' => false,
                'C' => true,
                _ => return None,
            },
            c: cia(c?)?,
            i: cia(i?)?,
            a: cia(a?)?,
        })
    }

    fn score(&self, v31: bool) -> f64 {
        let pr = match (self.pr, self.scope_changed) {
            ('N', _) => 0.85,
            ('L', false) => 0.62,
            ('L', true) => 0.68,
            ('H', false) => 0.27,
            _ => 0.5, // H with scope changed
        };
        let iss = 1.0 - (1.0 - self.c) * (1.0 - self.i) * (1.0 - self.a);
        let impact = if self.scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
        } else {
            6.42 * iss
        };
        if impact <= 0.0 {
            return 0.0;
        }
        let exploitability = 8.22 * self.av * self.ac * pr * self.ui;
        let raw = if self.scope_changed {
            (1.08 * (impact + exploitability)).min(10.0)
        } else {
            (impact + exploitability).min(10.0)
        };
        if v31 {
            roundup_31(raw)
        } else {
            roundup_30(raw)
        }
    }
}

/// CVSS v3.1 Appendix A `Roundup`: the smallest one-decimal number ≥ input,
/// computed on integers to avoid floating-point artifacts (e.g. 4.000001).
fn roundup_31(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) as f64 + 1.0) / 10.0
    }
}

/// CVSS v3.0 `Roundup`: plain ceiling to one decimal.
fn roundup_30(x: f64) -> f64 {
    (x * 10.0).ceil() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(v: &str) -> f64 {
        CvssScore::from_vector(v).expect(v).base_score
    }

    #[test]
    fn known_v31_vectors_match_first_calculator() {
        // Reference values from the FIRST CVSS v3.1 calculator.
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 8.8);
        assert_eq!(score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), 7.5);
        assert_eq!(score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"), 5.9);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
    }

    #[test]
    fn ratings_follow_first_bands() {
        assert_eq!(rating(0.0), "none");
        assert_eq!(rating(3.9), "low");
        assert_eq!(rating(4.0), "medium");
        assert_eq!(rating(6.9), "medium");
        assert_eq!(rating(7.0), "high");
        assert_eq!(rating(9.0), "critical");
        let s = CvssScore::from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(s.rating(), "critical");
        assert_eq!(s.cvss_version, "3.1");
    }

    #[test]
    fn temporal_metrics_are_tolerated_and_v30_parses() {
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C";
        assert_eq!(score(v), 9.8, "base score ignores temporal metrics");
        assert_eq!(score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), 7.5);
    }

    #[test]
    fn malformed_vectors_are_rejected_not_guessed() {
        for bad in [
            "",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // no prefix
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", // v4 missing SC/SI/SA
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", // missing A
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // unknown value
            "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // duplicate
            "CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // multi-char
            "CVSS:3.1/garbage",
        ] {
            assert!(CvssScore::from_vector(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn v40_vectors_score_with_nomenclature_and_label() {
        let b = CvssScore::from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        )
        .expect("valid v4.0 base vector");
        assert_eq!(b.cvss_version, "4.0");
        assert_eq!(b.base_score, 8.7);
        assert_eq!(b.nomenclature(), Some("CVSS-B"));
        assert_eq!(b.label(), "CVSS v4.0 8.7 High (CVSS-B)");
        let bt = CvssScore::from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
        )
        .unwrap();
        assert_eq!((bt.base_score, bt.nomenclature()), (5.2, Some("CVSS-BT")));
        let v31 = CvssScore::from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(v31.nomenclature(), None);
        assert_eq!(v31.label(), "CVSS v3.1 9.8 Critical");
    }

    #[test]
    fn derived_fields_are_written_but_never_trusted_on_read() {
        let s = CvssScore::from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        )
        .unwrap();
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["rating"], "high");
        assert_eq!(v["nomenclature"], "CVSS-B");
        // An old report (three fields) reads back unchanged.
        let old: CvssScore = serde_json::from_value(serde_json::json!({
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8
        }))
        .unwrap();
        assert_eq!(old.rating(), "critical");
        assert!(
            serde_json::to_value(&old)
                .unwrap()
                .get("nomenclature")
                .is_none()
        );
        // Forged derived fields are ignored and recomputed on write.
        let forged: CvssScore = serde_json::from_value(serde_json::json!({
            "cvss_version": "4.0",
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "base_score": 8.7, "rating": "low", "nomenclature": "CVSS-BTE"
        }))
        .unwrap();
        let again = serde_json::to_value(&forged).unwrap();
        assert_eq!(again["rating"], "high");
        assert_eq!(again["nomenclature"], "CVSS-B");
    }

    #[test]
    fn stored_scores_are_recomputed_from_the_vector_on_read() {
        #[derive(Deserialize)]
        struct Holder {
            #[serde(default, deserialize_with = "deserialize_rescored")]
            cvss: Option<CvssScore>,
        }
        let forged: Holder = serde_json::from_value(serde_json::json!({"cvss": {
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "base_score": 99.0
        }}))
        .unwrap();
        let c = forged.cvss.unwrap();
        assert_eq!((c.cvss_version.as_str(), c.base_score), ("4.0", 8.7));
        let garbage: Holder = serde_json::from_value(serde_json::json!({"cvss": {
            "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/garbage", "base_score": 9.9
        }}))
        .unwrap();
        assert!(garbage.cvss.is_none(), "unscorable vector dropped");
        let none: Holder = serde_json::from_value(serde_json::json!({"cvss": null})).unwrap();
        assert!(none.cvss.is_none());
        let absent: Holder = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(absent.cvss.is_none());
    }
}
