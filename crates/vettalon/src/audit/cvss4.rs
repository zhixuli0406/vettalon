//! CVSS v4.0 scoring (FIRST CVSS v4.0 Specification Document v1.2, §8:
//! "CVSS v4.0 Scoring using MacroVectors and Interpolation").
//!
//! v4.0 is not a formula: a vector maps to one of 270 MacroVectors whose
//! score comes from an expert-derived lookup table, then is interpolated by
//! the vector's severity distance inside that MacroVector. This module is a
//! line-by-line port of FIRST's reference calculator, and the tables below
//! are copied verbatim from it:
//!
//! - source: FIRSTdotorg/cvss-v4-calculator, commit
//!   `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a` (2024-08-19), files
//!   `cvss_lookup.js`, `max_composed.js`, `max_severity.js`, `metrics.js`,
//!   `cvss_score.js`;
//! - licence: BSD-2-Clause, "Copyright (c) 2023 FIRST.ORG, Inc., Red Hat,
//!   and contributors" (reproduced in the repository NOTICE file).
//!
//! `audit/testdata/cvss4_reference.tsv` pins the port: FIRST's published
//! examples plus 300 vectors scored by running that calculator code itself
//! (`scripts/standards/gen_cvss4_reference.js`).
//!
//! The vector must follow the spec's Table 23 order ("every other ordering
//! is invalid"), contain every Base metric exactly once and use only defined
//! values; anything else is rejected, never repaired.

/// Metric order and allowed values (metrics.js / spec Table 23). The first
/// [`BASE_COUNT`] are the mandatory Base metrics.
const ORDER: [(&str, &[&str]); 32] = [
    ("AV", &["N", "A", "L", "P"]),
    ("AC", &["L", "H"]),
    ("AT", &["N", "P"]),
    ("PR", &["N", "L", "H"]),
    ("UI", &["N", "P", "A"]),
    ("VC", &["H", "L", "N"]),
    ("VI", &["H", "L", "N"]),
    ("VA", &["H", "L", "N"]),
    ("SC", &["H", "L", "N"]),
    ("SI", &["H", "L", "N"]),
    ("SA", &["H", "L", "N"]),
    // Threat
    ("E", &["X", "A", "P", "U"]),
    // Environmental
    ("CR", &["X", "H", "M", "L"]),
    ("IR", &["X", "H", "M", "L"]),
    ("AR", &["X", "H", "M", "L"]),
    ("MAV", &["X", "N", "A", "L", "P"]),
    ("MAC", &["X", "L", "H"]),
    ("MAT", &["X", "N", "P"]),
    ("MPR", &["X", "N", "L", "H"]),
    ("MUI", &["X", "N", "P", "A"]),
    ("MVC", &["X", "H", "L", "N"]),
    ("MVI", &["X", "H", "L", "N"]),
    ("MVA", &["X", "H", "L", "N"]),
    ("MSC", &["X", "H", "L", "N"]),
    ("MSI", &["X", "S", "H", "L", "N"]),
    ("MSA", &["X", "S", "H", "L", "N"]),
    // Supplemental (never affect the score)
    ("S", &["X", "N", "P"]),
    ("AU", &["X", "N", "Y"]),
    ("R", &["X", "A", "U", "I"]),
    ("V", &["X", "D", "C"]),
    ("RE", &["X", "L", "M", "H"]),
    ("U", &["X", "Clear", "Green", "Amber", "Red"]),
];
const BASE_COUNT: usize = 11;
const THREAT: &[&str] = &["E"];
const ENVIRONMENTAL: &[&str] = &[
    "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
];

/// MacroVector → score (cvss_lookup.js, all 270 entries, sorted by key).
const LOOKUP: [(&str, f64); 270] = [
    ("000000", 10.0),
    ("000001", 9.9),
    ("000010", 9.8),
    ("000011", 9.5),
    ("000020", 9.5),
    ("000021", 9.2),
    ("000100", 10.0),
    ("000101", 9.6),
    ("000110", 9.3),
    ("000111", 8.7),
    ("000120", 9.1),
    ("000121", 8.1),
    ("000200", 9.3),
    ("000201", 9.0),
    ("000210", 8.9),
    ("000211", 8.0),
    ("000220", 8.1),
    ("000221", 6.8),
    ("001000", 9.8),
    ("001001", 9.5),
    ("001010", 9.5),
    ("001011", 9.2),
    ("001020", 9.0),
    ("001021", 8.4),
    ("001100", 9.3),
    ("001101", 9.2),
    ("001110", 8.9),
    ("001111", 8.1),
    ("001120", 8.1),
    ("001121", 6.5),
    ("001200", 8.8),
    ("001201", 8.0),
    ("001210", 7.8),
    ("001211", 7.0),
    ("001220", 6.9),
    ("001221", 4.8),
    ("002001", 9.2),
    ("002011", 8.2),
    ("002021", 7.2),
    ("002101", 7.9),
    ("002111", 6.9),
    ("002121", 5.0),
    ("002201", 6.9),
    ("002211", 5.5),
    ("002221", 2.7),
    ("010000", 9.9),
    ("010001", 9.7),
    ("010010", 9.5),
    ("010011", 9.2),
    ("010020", 9.2),
    ("010021", 8.5),
    ("010100", 9.5),
    ("010101", 9.1),
    ("010110", 9.0),
    ("010111", 8.3),
    ("010120", 8.4),
    ("010121", 7.1),
    ("010200", 9.2),
    ("010201", 8.1),
    ("010210", 8.2),
    ("010211", 7.1),
    ("010220", 7.2),
    ("010221", 5.3),
    ("011000", 9.5),
    ("011001", 9.3),
    ("011010", 9.2),
    ("011011", 8.5),
    ("011020", 8.5),
    ("011021", 7.3),
    ("011100", 9.2),
    ("011101", 8.2),
    ("011110", 8.0),
    ("011111", 7.2),
    ("011120", 7.0),
    ("011121", 5.9),
    ("011200", 8.4),
    ("011201", 7.0),
    ("011210", 7.1),
    ("011211", 5.2),
    ("011220", 5.0),
    ("011221", 3.0),
    ("012001", 8.6),
    ("012011", 7.5),
    ("012021", 5.2),
    ("012101", 7.1),
    ("012111", 5.2),
    ("012121", 2.9),
    ("012201", 6.3),
    ("012211", 2.9),
    ("012221", 1.7),
    ("100000", 9.8),
    ("100001", 9.5),
    ("100010", 9.4),
    ("100011", 8.7),
    ("100020", 9.1),
    ("100021", 8.1),
    ("100100", 9.4),
    ("100101", 8.9),
    ("100110", 8.6),
    ("100111", 7.4),
    ("100120", 7.7),
    ("100121", 6.4),
    ("100200", 8.7),
    ("100201", 7.5),
    ("100210", 7.4),
    ("100211", 6.3),
    ("100220", 6.3),
    ("100221", 4.9),
    ("101000", 9.4),
    ("101001", 8.9),
    ("101010", 8.8),
    ("101011", 7.7),
    ("101020", 7.6),
    ("101021", 6.7),
    ("101100", 8.6),
    ("101101", 7.6),
    ("101110", 7.4),
    ("101111", 5.8),
    ("101120", 5.9),
    ("101121", 5.0),
    ("101200", 7.2),
    ("101201", 5.7),
    ("101210", 5.7),
    ("101211", 5.2),
    ("101220", 5.2),
    ("101221", 2.5),
    ("102001", 8.3),
    ("102011", 7.0),
    ("102021", 5.4),
    ("102101", 6.5),
    ("102111", 5.8),
    ("102121", 2.6),
    ("102201", 5.3),
    ("102211", 2.1),
    ("102221", 1.3),
    ("110000", 9.5),
    ("110001", 9.0),
    ("110010", 8.8),
    ("110011", 7.6),
    ("110020", 7.6),
    ("110021", 7.0),
    ("110100", 9.0),
    ("110101", 7.7),
    ("110110", 7.5),
    ("110111", 6.2),
    ("110120", 6.1),
    ("110121", 5.3),
    ("110200", 7.7),
    ("110201", 6.6),
    ("110210", 6.8),
    ("110211", 5.9),
    ("110220", 5.2),
    ("110221", 3.0),
    ("111000", 8.9),
    ("111001", 7.8),
    ("111010", 7.6),
    ("111011", 6.7),
    ("111020", 6.2),
    ("111021", 5.8),
    ("111100", 7.4),
    ("111101", 5.9),
    ("111110", 5.7),
    ("111111", 5.7),
    ("111120", 4.7),
    ("111121", 2.3),
    ("111200", 6.1),
    ("111201", 5.2),
    ("111210", 5.7),
    ("111211", 2.9),
    ("111220", 2.4),
    ("111221", 1.6),
    ("112001", 7.1),
    ("112011", 5.9),
    ("112021", 3.0),
    ("112101", 5.8),
    ("112111", 2.6),
    ("112121", 1.5),
    ("112201", 2.3),
    ("112211", 1.3),
    ("112221", 0.6),
    ("200000", 9.3),
    ("200001", 8.7),
    ("200010", 8.6),
    ("200011", 7.2),
    ("200020", 7.5),
    ("200021", 5.8),
    ("200100", 8.6),
    ("200101", 7.4),
    ("200110", 7.4),
    ("200111", 6.1),
    ("200120", 5.6),
    ("200121", 3.4),
    ("200200", 7.0),
    ("200201", 5.4),
    ("200210", 5.2),
    ("200211", 4.0),
    ("200220", 4.0),
    ("200221", 2.2),
    ("201000", 8.5),
    ("201001", 7.5),
    ("201010", 7.4),
    ("201011", 5.5),
    ("201020", 6.2),
    ("201021", 5.1),
    ("201100", 7.2),
    ("201101", 5.7),
    ("201110", 5.5),
    ("201111", 4.1),
    ("201120", 4.6),
    ("201121", 1.9),
    ("201200", 5.3),
    ("201201", 3.6),
    ("201210", 3.4),
    ("201211", 1.9),
    ("201220", 1.9),
    ("201221", 0.8),
    ("202001", 6.4),
    ("202011", 5.1),
    ("202021", 2.0),
    ("202101", 4.7),
    ("202111", 2.1),
    ("202121", 1.1),
    ("202201", 2.4),
    ("202211", 0.9),
    ("202221", 0.4),
    ("210000", 8.8),
    ("210001", 7.5),
    ("210010", 7.3),
    ("210011", 5.3),
    ("210020", 6.0),
    ("210021", 5.0),
    ("210100", 7.3),
    ("210101", 5.5),
    ("210110", 5.9),
    ("210111", 4.0),
    ("210120", 4.1),
    ("210121", 2.0),
    ("210200", 5.4),
    ("210201", 4.3),
    ("210210", 4.5),
    ("210211", 2.2),
    ("210220", 2.0),
    ("210221", 1.1),
    ("211000", 7.5),
    ("211001", 5.5),
    ("211010", 5.8),
    ("211011", 4.5),
    ("211020", 4.0),
    ("211021", 2.1),
    ("211100", 6.1),
    ("211101", 5.1),
    ("211110", 4.8),
    ("211111", 1.8),
    ("211120", 2.0),
    ("211121", 0.9),
    ("211200", 4.6),
    ("211201", 1.8),
    ("211210", 1.7),
    ("211211", 0.7),
    ("211220", 0.8),
    ("211221", 0.2),
    ("212001", 5.3),
    ("212011", 2.4),
    ("212021", 1.4),
    ("212101", 2.4),
    ("212111", 1.2),
    ("212121", 0.5),
    ("212201", 1.0),
    ("212211", 0.3),
    ("212221", 0.1),
];

// Highest-severity vectors per EQ level (max_composed.js).
const MAX_EQ1: [&[&str]; 3] = [
    &["AV:N/PR:N/UI:N/"],
    &["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    &["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
];
const MAX_EQ2: [&[&str]; 2] = [&["AC:L/AT:N/"], &["AC:H/AT:N/", "AC:L/AT:P/"]];
fn max_eq3_eq6(eq3: u8, eq6: u8) -> &'static [&'static str] {
    match (eq3, eq6) {
        (0, 0) => &["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
        (0, 1) => &[
            "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
            "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
        ],
        (1, 0) => &[
            "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
            "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
        ],
        (1, 1) => &[
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ],
        (2, 1) => &["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        _ => &[],
    }
}
const MAX_EQ4: [&[&str]; 3] = [
    &["SC:H/SI:S/SA:S/"],
    &["SC:H/SI:H/SA:H/"],
    &["SC:L/SI:L/SA:L/"],
];
const MAX_EQ5: [&[&str]; 3] = [&["E:A/"], &["E:P/"], &["E:U/"]];

// Max severity distances per EQ level, +1 (max_severity.js).
const MAX_SEVERITY_EQ1: [f64; 3] = [1.0, 4.0, 5.0];
const MAX_SEVERITY_EQ2: [f64; 2] = [1.0, 2.0];
fn max_severity_eq3_eq6(eq3: u8, eq6: u8) -> f64 {
    match (eq3, eq6) {
        (0, 0) => 7.0,
        (0, 1) => 6.0,
        (1, 0) | (1, 1) => 8.0,
        (2, 1) => 10.0,
        _ => f64::NAN,
    }
}
const MAX_SEVERITY_EQ4: [f64; 3] = [6.0, 5.0, 4.0];

/// Which optional metric groups a vector actually uses — the v4.0
/// nomenclature (spec §1.3): CVSS-B, CVSS-BT, CVSS-BE or CVSS-BTE.
pub fn nomenclature(vector: &Vector4) -> &'static str {
    let set = |names: &[&str]| names.iter().any(|n| vector.raw(n) != "X");
    match (set(THREAT), set(ENVIRONMENTAL)) {
        (false, false) => "CVSS-B",
        (true, false) => "CVSS-BT",
        (false, true) => "CVSS-BE",
        (true, true) => "CVSS-BTE",
    }
}

/// A syntactically valid CVSS v4.0 vector (every value is one of the
/// defined abbreviations; omitted optional metrics read as `X`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector4 {
    vals: [&'static str; 32],
}

impl Vector4 {
    /// Parse `CVSS:4.0/…` strictly (order, completeness, values, no
    /// duplicates). `None` for anything the spec calls invalid.
    pub fn parse(vector: &str) -> Option<Self> {
        let rest = vector.strip_prefix("CVSS:4.0/")?;
        let mut vals: [&'static str; 32] = [""; 32];
        for v in vals.iter_mut().skip(BASE_COUNT) {
            *v = "X";
        }
        let mut oi = 0;
        for part in rest.split('/') {
            let (key, val) = part.split_once(':')?;
            loop {
                let (name, allowed) = ORDER.get(oi)?;
                oi += 1;
                if *name == key {
                    vals[oi - 1] = allowed.iter().find(|a| **a == val)?;
                    break;
                }
                // Skipping a mandatory Base metric makes the vector invalid.
                if oi <= BASE_COUNT {
                    return None;
                }
            }
        }
        if vals[..BASE_COUNT].iter().any(|v| v.is_empty()) {
            return None;
        }
        Some(Vector4 { vals })
    }

    /// The value as written (`X` when an optional metric is omitted).
    fn raw(&self, metric: &str) -> &'static str {
        ORDER
            .iter()
            .position(|(n, _)| *n == metric)
            .map_or("X", |i| self.vals[i])
    }

    /// The effective value used in scoring (cvss_score.js `m`): E:X counts as
    /// Attacked, CR/IR/AR:X as High, and a defined Modified metric replaces
    /// its Base metric.
    fn m(&self, metric: &str) -> &'static str {
        let selected = self.raw(metric);
        match (metric, selected) {
            ("E", "X") => return "A",
            ("CR" | "IR" | "AR", "X") => return "H",
            _ => {}
        }
        let modified = ORDER
            .iter()
            .position(|(n, _)| n.strip_prefix('M') == Some(metric));
        if let Some(i) = modified
            && self.vals[i] != "X"
        {
            return self.vals[i];
        }
        selected
    }

    /// The six-digit MacroVector (EQ1..EQ6).
    fn macro_vector(&self) -> [u8; 6] {
        let m = |k| self.m(k);
        let eq1 = if m("AV") == "N" && m("PR") == "N" && m("UI") == "N" {
            0
        } else if (m("AV") == "N" || m("PR") == "N" || m("UI") == "N") && m("AV") != "P" {
            1
        } else {
            2
        };
        let eq2 = if m("AC") == "L" && m("AT") == "N" {
            0
        } else {
            1
        };
        let eq3 = if m("VC") == "H" && m("VI") == "H" {
            0
        } else if m("VC") == "H" || m("VI") == "H" || m("VA") == "H" {
            1
        } else {
            2
        };
        let eq4 = if m("MSI") == "S" || m("MSA") == "S" {
            0
        } else if m("SC") == "H" || m("SI") == "H" || m("SA") == "H" {
            1
        } else {
            2
        };
        let eq5 = match m("E") {
            "A" => 0,
            "P" => 1,
            _ => 2,
        };
        let eq6 = if (m("CR") == "H" && m("VC") == "H")
            || (m("IR") == "H" && m("VI") == "H")
            || (m("AR") == "H" && m("VA") == "H")
        {
            0
        } else {
            1
        };
        [eq1, eq2, eq3, eq4, eq5, eq6]
    }

    /// The CVSS v4.0 score (one decimal), exactly as FIRST's calculator.
    /// `None` only if the tables have no entry (unreachable for a parsed
    /// vector; kept total instead of panicking).
    pub fn score(&self) -> Option<f64> {
        if ["VC", "VI", "VA", "SC", "SI", "SA"]
            .iter()
            .all(|k| self.m(k) == "N")
        {
            return Some(0.0);
        }
        let mv = self.macro_vector();
        let mut value = lookup(mv)?;
        let [eq1, eq2, eq3, eq4, eq5, eq6] = mv;
        let lower = |d: [u8; 6]| lookup(d);
        let score_eq1_next = lower([eq1 + 1, eq2, eq3, eq4, eq5, eq6]);
        let score_eq2_next = lower([eq1, eq2 + 1, eq3, eq4, eq5, eq6]);
        let score_eq3eq6_next = match (eq3, eq6) {
            (1, 1) | (0, 1) => lower([eq1, eq2, eq3 + 1, eq4, eq5, eq6]),
            (1, 0) => lower([eq1, eq2, eq3, eq4, eq5, eq6 + 1]),
            (0, 0) => {
                let left = lower([eq1, eq2, eq3, eq4, eq5, eq6 + 1]);
                let right = lower([eq1, eq2, eq3 + 1, eq4, eq5, eq6]);
                match (left, right) {
                    (Some(l), Some(r)) if l > r => Some(l),
                    _ => right,
                }
            }
            _ => lower([eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1]),
        };
        let score_eq4_next = lower([eq1, eq2, eq3, eq4 + 1, eq5, eq6]);
        let score_eq5_next = lower([eq1, eq2, eq3, eq4, eq5 + 1, eq6]);

        // Find the first highest-severity vector of this MacroVector that the
        // scored vector does not exceed in any metric.
        let mut found: Option<Distances> = None;
        'search: for a in MAX_EQ1[eq1 as usize] {
            for b in MAX_EQ2[eq2 as usize] {
                for c in max_eq3_eq6(eq3, eq6) {
                    for d in MAX_EQ4[eq4 as usize] {
                        for e in MAX_EQ5[eq5 as usize] {
                            let max = format!("{a}{b}{c}{d}{e}");
                            let dist = self.distances(&max);
                            let negative = dist.any_negative();
                            found = Some(dist);
                            if !negative {
                                break 'search;
                            }
                        }
                    }
                }
            }
        }
        let d = found?;
        let current_eq1 = d.av + d.pr + d.ui;
        let current_eq2 = d.ac + d.at;
        let current_eq3eq6 = d.vc + d.vi + d.va + d.cr + d.ir + d.ar;
        let current_eq4 = d.sc + d.si + d.sa;

        let step = 0.1;
        let max_sev_eq1 = MAX_SEVERITY_EQ1[eq1 as usize] * step;
        let max_sev_eq2 = MAX_SEVERITY_EQ2[eq2 as usize] * step;
        let max_sev_eq3eq6 = max_severity_eq3_eq6(eq3, eq6) * step;
        let max_sev_eq4 = MAX_SEVERITY_EQ4[eq4 as usize] * step;

        let mut n_existing_lower = 0u32;
        let mut normalized = [0.0f64; 5];
        let parts = [
            (score_eq1_next, current_eq1, max_sev_eq1),
            (score_eq2_next, current_eq2, max_sev_eq2),
            (score_eq3eq6_next, current_eq3eq6, max_sev_eq3eq6),
            (score_eq4_next, current_eq4, max_sev_eq4),
        ];
        for (i, (next, current, max_sev)) in parts.into_iter().enumerate() {
            if let Some(next) = next {
                n_existing_lower += 1;
                let available = value - next;
                normalized[i] = available * (current / max_sev);
            }
        }
        if score_eq5_next.is_some() {
            // EQ5 has no intra-MacroVector distance: its proportion is always
            // 0 (normalized[4] stays 0.0), but it still counts in the mean.
            n_existing_lower += 1;
        }
        let mean_distance = if n_existing_lower == 0 {
            0.0
        } else {
            (normalized[0] + normalized[1] + normalized[2] + normalized[3] + normalized[4])
                / f64::from(n_existing_lower)
        };
        value -= mean_distance;
        let value = value.clamp(0.0, 10.0);
        Some((value * 10.0).round() / 10.0)
    }

    fn distances(&self, max: &str) -> Distances {
        let max_of = |metric: &str| -> &str {
            max.split('/')
                .filter_map(|p| p.split_once(':'))
                .find(|(k, _)| *k == metric)
                .map_or("", |(_, v)| v)
        };
        let d = |metric: &str| level(metric, self.m(metric)) - level(metric, max_of(metric));
        Distances {
            av: d("AV"),
            pr: d("PR"),
            ui: d("UI"),
            ac: d("AC"),
            at: d("AT"),
            vc: d("VC"),
            vi: d("VI"),
            va: d("VA"),
            sc: d("SC"),
            si: d("SI"),
            sa: d("SA"),
            cr: d("CR"),
            ir: d("IR"),
            ar: d("AR"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Distances {
    av: f64,
    pr: f64,
    ui: f64,
    ac: f64,
    at: f64,
    vc: f64,
    vi: f64,
    va: f64,
    sc: f64,
    si: f64,
    sa: f64,
    cr: f64,
    ir: f64,
    ar: f64,
}

impl Distances {
    fn any_negative(&self) -> bool {
        [
            self.av, self.pr, self.ui, self.ac, self.at, self.vc, self.vi, self.va, self.sc,
            self.si, self.sa, self.cr, self.ir, self.ar,
        ]
        .iter()
        .any(|v| *v < 0.0)
    }
}

/// Severity level of a metric value (cvss_score.js `*_levels`).
fn level(metric: &str, value: &str) -> f64 {
    match (metric, value) {
        ("AV", "N") | ("PR", "N") | ("UI", "N") | ("AC", "L") | ("AT", "N") => 0.0,
        ("AV", "A") | ("PR", "L") | ("UI", "P") | ("AC", "H") | ("AT", "P") => 0.1,
        ("AV", "L") | ("PR", "H") | ("UI", "A") => 0.2,
        ("AV", "P") => 0.3,
        ("VC" | "VI" | "VA", "H") => 0.0,
        ("VC" | "VI" | "VA", "L") => 0.1,
        ("VC" | "VI" | "VA", "N") => 0.2,
        ("SC", "H") => 0.1,
        ("SC", "L") => 0.2,
        ("SC", "N") => 0.3,
        ("SI" | "SA", "S") => 0.0,
        ("SI" | "SA", "H") => 0.1,
        ("SI" | "SA", "L") => 0.2,
        ("SI" | "SA", "N") => 0.3,
        ("CR" | "IR" | "AR", "H") => 0.0,
        ("CR" | "IR" | "AR", "M") => 0.1,
        ("CR" | "IR" | "AR", "L") => 0.2,
        _ => f64::NAN,
    }
}

fn lookup(mv: [u8; 6]) -> Option<f64> {
    let key: String = mv.iter().map(|d| char::from(b'0' + d)).collect();
    LOOKUP
        .binary_search_by(|(k, _)| (*k).cmp(key.as_str()))
        .ok()
        .map(|i| LOOKUP[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFERENCE: &str = include_str!("testdata/cvss4_reference.tsv");

    fn score(v: &str) -> Option<f64> {
        Vector4::parse(v)?.score()
    }

    #[test]
    fn lookup_table_is_sorted_and_complete() {
        assert!(LOOKUP.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(lookup([0, 0, 0, 0, 0, 0]), Some(10.0));
        assert_eq!(lookup([2, 1, 2, 2, 2, 1]), Some(0.1));
        assert_eq!(lookup([3, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn matches_first_examples_and_official_calculator() {
        let mut checked = (0, 0, 0);
        for line in REFERENCE
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let cols: Vec<&str> = line.split('\t').collect();
            assert_eq!(cols.len(), 3, "{line}");
            match cols[0] {
                "invalid" => {
                    assert!(Vector4::parse(cols[1]).is_none(), "{line}");
                    checked.2 += 1;
                }
                kind => {
                    let want: f64 = cols[2].parse().unwrap();
                    assert_eq!(score(cols[1]), Some(want), "{kind}: {}", cols[1]);
                    if kind == "example" {
                        checked.0 += 1;
                    } else {
                        checked.1 += 1;
                    }
                }
            }
        }
        assert!(
            checked.0 >= 50 && checked.1 == 300 && checked.2 == 2,
            "{checked:?}"
        );
    }

    /// Bulk check against a larger calculator dump (`vector<TAB>score` per
    /// line, e.g. from `scripts/standards/gen_cvss4_reference.js` with bigger
    /// counts): `VETTALON_CVSS4_BULK=/path/bulk.tsv cargo test -- --ignored`.
    #[test]
    #[ignore = "needs a generated calculator dump; see doc comment"]
    fn bulk_matches_official_calculator_dump() {
        let path = std::env::var("VETTALON_CVSS4_BULK").expect("VETTALON_CVSS4_BULK");
        let text = std::fs::read_to_string(path).unwrap();
        let mut n = 0;
        for line in text.lines().filter(|l| !l.is_empty()) {
            let (v, s) = line.split_once('\t').unwrap();
            assert_eq!(score(v), Some(s.parse().unwrap()), "{v}");
            n += 1;
        }
        assert!(n > 0);
        eprintln!("{n} vectors match");
    }

    #[test]
    fn spec_examples_by_hand() {
        // FIRST v4.0 examples table: base, base+threat, base+environmental.
        let base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
        assert_eq!(score(base), Some(8.7));
        let bt = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U";
        assert_eq!(score(bt), Some(5.2));
        assert_eq!(
            score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
            Some(10.0)
        );
        assert_eq!(
            score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"),
            Some(0.0)
        );
    }

    #[test]
    fn nomenclature_follows_the_metrics_present() {
        let b = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
        let n = |v: &str| nomenclature(&Vector4::parse(v).unwrap());
        assert_eq!(n(b), "CVSS-B");
        assert_eq!(
            n(&format!("{b}/E:X")),
            "CVSS-B",
            "explicit X is not a threat metric"
        );
        assert_eq!(n(&format!("{b}/E:U")), "CVSS-BT");
        assert_eq!(n(&format!("{b}/CR:H")), "CVSS-BE");
        assert_eq!(n(&format!("{b}/E:P/MAV:L")), "CVSS-BTE");
        assert_eq!(
            n(&format!("{b}/S:P/AU:Y/U:Red")),
            "CVSS-B",
            "supplemental never scores"
        );
        // Supplemental metrics never change the score.
        assert_eq!(score(&format!("{b}/S:P/AU:Y/R:I/V:C/RE:H/U:Red")), score(b));
    }

    #[test]
    fn invalid_vectors_are_rejected_not_repaired() {
        let b = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
        for bad in [
            "",
            "CVSS:4.0/",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N", // missing SA
            "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", // order
            "CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", // dup
            "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", // base X
            "CVSS:4.0/AV:n/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", // case
        ] {
            assert!(Vector4::parse(bad).is_none(), "{bad:?}");
        }
        for bad in ["/E:Z", "/MSC:S", "/CR:H/E:A", "/E:A/E:A", "/", "/U:red"] {
            let v = format!("{b}{bad}");
            assert!(Vector4::parse(&v).is_none(), "{v:?}");
        }
    }
}
