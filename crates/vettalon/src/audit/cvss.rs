//! CVSS v3.x base-score calculator (FIRST CVSS v3.1 specification §7.1).
//!
//! vettalon never invents a CVSS vector: a score exists only when a source
//! (a scanner advisory — never the auditing model) supplied a vector string.
//! This module parses that vector and computes the base score so a report can
//! show it next to the qualitative rating. Temporal/environmental metrics in
//! the vector are tolerated but ignored (base score only).

use serde::{Deserialize, Serialize};

/// A parsed CVSS v3.x vector and its computed base score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CvssScore {
    /// `"3.1"` or `"3.0"`.
    pub cvss_version: String,
    /// The vector exactly as the source supplied it.
    pub cvss_vector: String,
    /// Base score, one decimal (0.0–10.0).
    pub base_score: f64,
}

impl CvssScore {
    /// Parse a `CVSS:3.x/…` vector. `None` when the prefix, a base metric or a
    /// metric value is missing, duplicated or unknown — a malformed vector is
    /// dropped, never guessed.
    pub fn from_vector(vector: &str) -> Option<Self> {
        let vector = vector.trim();
        let (version, rest) = if let Some(r) = vector.strip_prefix("CVSS:3.1/") {
            ("3.1", r)
        } else if let Some(r) = vector.strip_prefix("CVSS:3.0/") {
            ("3.0", r)
        } else {
            return None;
        };
        let base = BaseMetrics::parse(rest)?;
        Some(CvssScore {
            cvss_version: version.to_string(),
            cvss_vector: vector.to_string(),
            base_score: base.score(version == "3.1"),
        })
    }

    /// Qualitative severity rating (FIRST §5): none/low/medium/high/critical.
    pub fn rating(&self) -> &'static str {
        rating(self.base_score)
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
        if v31 { roundup_31(raw) } else { roundup_30(raw) }
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
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",           // no prefix
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", // v4 not scored here
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",       // missing A
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   // unknown value
            "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // duplicate
            "CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // multi-char
            "CVSS:3.1/garbage",
        ] {
            assert!(CvssScore::from_vector(bad).is_none(), "{bad:?}");
        }
    }
}
