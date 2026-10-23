//! `--refuter-score` (opt-in, default off): the refuter also states how
//! likely it finds the claim to be real (`p_real`, 0-100) and what the
//! excerpts show (`evidence_level`, five levels), in the same reply.
//!
//! With `--refuter-score` alone the scores are recorded only; no code reads
//! them to decide. `--refuter-score-threshold T` (opt-in) is the one reader:
//! a refutation closes only when its own `p_real` is below `T`, and a
//! higher, missing or invalid score keeps the finding open
//! ([`gate_refutation`]); it never turns a non-refutation into a closure.
//!
//! With either flag, the two keys are taken out of the reply before the
//! usual strict parser sees it, so a given reply gets the verdict it would
//! get without them. The prompt does gain a section, so whether the model
//! answers differently is an empirical question, measured separately. A
//! missing or malformed score is recorded as such. With neither flag nothing
//! here runs: the prompt carries no score text and a reply with these keys
//! still breaks the contract, as before.
//!
//! Verbalized scores only: no token log-probabilities, which most providers
//! do not return, so any roster model can answer them.

use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use vettalon_contract::strict_json;

use super::adversarial::{RunVerdict, UnresolvedRun};

/// Decode without silently collapsing duplicate fields before the verdict
/// parser sees them. This applies recursively, including nested citations.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::from(value)))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::from(value)))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::from(value)))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(UniqueValue(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some((key, UniqueValue(value))) = map.next_entry::<String, UniqueValue>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate field {key}")));
            }
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

/// Evidence prefix of the per-run score line.
pub const SCORE_PREFIX: &str = "refuter_score:";
/// Reply keys the score adds.
pub const P_REAL_KEY: &str = "p_real";
pub const EVIDENCE_LEVEL_KEY: &str = "evidence_level";

/// What the excerpts show, from proven safe to a proven unguarded flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceLevel {
    /// The excerpts show the code is safe: an effective guard on every
    /// path, a constant or non-attacker value at the sink, dead code, or the
    /// claimed defect is not in this code.
    SafeShown,
    /// The visible code points to safe, but one needed fact is not shown.
    SafeLikely,
    /// The excerpts do not show enough either way.
    Undetermined,
    /// Most of an attacker-input-to-sink flow is visible and unguarded; one
    /// link is not in the excerpts.
    FlowLikely,
    /// The whole flow from attacker-controllable input to the sink is
    /// visible with no effective guard.
    FlowShown,
}

impl EvidenceLevel {
    pub const ALL: [EvidenceLevel; 5] = [
        EvidenceLevel::SafeShown,
        EvidenceLevel::SafeLikely,
        EvidenceLevel::Undetermined,
        EvidenceLevel::FlowLikely,
        EvidenceLevel::FlowShown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceLevel::SafeShown => "safe_shown",
            EvidenceLevel::SafeLikely => "safe_likely",
            EvidenceLevel::Undetermined => "undetermined",
            EvidenceLevel::FlowLikely => "flow_likely",
            EvidenceLevel::FlowShown => "flow_shown",
        }
    }

    fn parse(s: &str) -> Option<EvidenceLevel> {
        EvidenceLevel::ALL.into_iter().find(|l| l.as_str() == s)
    }
}

/// One run's score, as read from its reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoreRead {
    Given {
        p_real: u8,
        level: EvidenceLevel,
    },
    /// Neither key was in the reply (or the reply was not a JSON object).
    Missing,
    /// At least one key was there but unusable; the reason is ours, never
    /// the model's text.
    Invalid(&'static str),
}

/// Appended to the refuter prompt when the flag is on.
pub const SCORE_INSTRUCTIONS: &str = "\n\n## Score (recorded only)\n\
In this run the reply object has exactly two more keys besides the ones above (for these two keys \
only, this overrides \"no extra keys\"):\n\
- \"p_real\": an integer from 0 to 100, your probability in percent that the claimed vulnerability \
is real in this code, meaning attacker-controllable input reaches the claimed dangerous operation \
with no effective guard. Give it with every verdict, \"refuted\" included, and use the whole range.\n\
- \"evidence_level\": what the excerpts show, exactly one of \"safe_shown\" (the excerpts show the \
code is safe: an effective guard on every path, a constant or non-attacker value at the sink, dead \
code, or the claimed defect is not in this code), \"safe_likely\" (the visible code points to safe, \
but one needed fact is not in the excerpts), \"undetermined\" (the excerpts do not show enough \
either way), \"flow_likely\" (most of a flow from attacker-controllable input to the sink is \
visible and unguarded; one link is not in the excerpts), \"flow_shown\" (the whole flow from \
attacker-controllable input to the sink is visible with no effective guard).\n\
These two keys are recorded only. Choose the verdict and every other key exactly as you would \
without them.\n";

/// The prompt with the score instructions appended.
pub fn with_score_instructions(prompt: &str) -> String {
    format!("{prompt}{SCORE_INSTRUCTIONS}")
}

fn read_p_real(v: &Value) -> Option<u8> {
    let n = v.as_u64()?;
    u8::try_from(n).ok().filter(|n| *n <= 100)
}

/// Take the score keys out of a reply. Returns the text the verdict parser
/// should see and the score. A reply that is not one JSON object, or holds
/// neither key, is passed on unchanged, so the verdict parser sees exactly
/// what it would have seen without the flag.
pub fn split_reply(raw: &str) -> (String, ScoreRead) {
    let Ok(UniqueValue(Value::Object(mut map))) = strict_json::parse_strict::<UniqueValue>(raw)
    else {
        return (raw.to_string(), ScoreRead::Missing);
    };
    let p = map.remove(P_REAL_KEY);
    let level = map.remove(EVIDENCE_LEVEL_KEY);
    if p.is_none() && level.is_none() {
        return (raw.to_string(), ScoreRead::Missing);
    }
    let rest = Value::Object(map).to_string();
    let read = match (p, level) {
        (Some(p), Some(l)) => match (read_p_real(&p), l.as_str().and_then(EvidenceLevel::parse)) {
            (Some(p_real), Some(level)) => ScoreRead::Given { p_real, level },
            (None, _) => ScoreRead::Invalid("p_real is not an integer from 0 to 100"),
            (_, None) => ScoreRead::Invalid("evidence_level is not one of the five levels"),
        },
        (None, _) => ScoreRead::Invalid("p_real missing"),
        (_, None) => ScoreRead::Invalid("evidence_level missing"),
    };
    (rest, read)
}

/// `--refuter-score-threshold`: `Some(kept-open run)` when a refutation must
/// not close because its score is not a usable value below `threshold`;
/// `None` when the run stands as it is (not a refutation, or a refutation
/// with `p_real < threshold`). A missing or invalid score never closes.
pub fn gate_refutation(run: &RunVerdict, read: &ScoreRead, threshold: u8) -> Option<RunVerdict> {
    let RunVerdict::Refuted { reason } = run else {
        return None;
    };
    let why = match read {
        ScoreRead::Given { p_real, .. } if *p_real < threshold => return None,
        ScoreRead::Given { p_real, .. } => {
            format!("p_real {p_real} is not below the closing threshold {threshold}")
        }
        ScoreRead::Missing => format!("no score; closing needs p_real below {threshold}"),
        ScoreRead::Invalid(w) => {
            format!("score invalid ({w}); closing needs p_real below {threshold}")
        }
    };
    Some(RunVerdict::Unresolved(Box::new(UnresolvedRun {
        reason: reason.clone(),
        blockers: Vec::new(),
        missing_code: Vec::new(),
        downgraded: Some(why),
    })))
}

/// The per-run evidence line, e.g.
/// `refuter_score: run 1/3 p_real=35 evidence=safe_likely; verdict=refuted`.
pub fn evidence_line(run: usize, n: usize, read: &ScoreRead, verdict: &str) -> String {
    let body = match read {
        ScoreRead::Given { p_real, level } => {
            format!("p_real={p_real} evidence={}", level.as_str())
        }
        ScoreRead::Missing => "missing".to_string(),
        ScoreRead::Invalid(why) => format!("invalid ({why})"),
    };
    format!("{SCORE_PREFIX} run {run}/{n} {body}; verdict={verdict}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_with_both_keys_is_split_and_the_rest_is_the_plain_reply() {
        let raw = r#"{"verdict": "refuted", "reason": "r", "p_real": 12, "evidence_level": "safe_shown", "blockers": []}"#;
        let (rest, read) = split_reply(raw);
        assert_eq!(
            read,
            ScoreRead::Given {
                p_real: 12,
                level: EvidenceLevel::SafeShown
            }
        );
        let v: Value = serde_json::from_str(&rest).unwrap();
        assert!(v.get("p_real").is_none() && v.get("evidence_level").is_none());
        assert_eq!(v["verdict"], "refuted");
        assert_eq!(v["blockers"], serde_json::json!([]));
    }

    #[test]
    fn a_fenced_reply_is_split_like_the_strict_parser_reads_it() {
        let raw = "```json\n{\"verdict\": \"plausible\", \"p_real\": 80, \"evidence_level\": \"flow_shown\"}\n```";
        let (rest, read) = split_reply(raw);
        assert!(matches!(read, ScoreRead::Given { p_real: 80, .. }));
        assert_eq!(rest, r#"{"verdict":"plausible"}"#);
    }

    #[test]
    fn a_reply_without_score_keys_passes_unchanged() {
        let raw = r#"{"verdict": "refuted",  "reason": "x"}"#;
        assert_eq!(split_reply(raw), (raw.to_string(), ScoreRead::Missing));
    }

    #[test]
    fn prose_or_a_non_object_passes_unchanged_for_the_verdict_parser_to_reject() {
        for raw in [
            "I think it is refuted",
            "[1, 2]",
            "{\"p_real\": 5} trailing",
            "",
        ] {
            assert_eq!(
                split_reply(raw),
                (raw.to_string(), ScoreRead::Missing),
                "{raw}"
            );
        }
    }

    #[test]
    fn duplicate_keys_do_not_get_normalized_into_a_valid_verdict() {
        for raw in [
            r#"{"verdict":"refuted","verdict":"plausible","p_real":3,"evidence_level":"safe_shown"}"#,
            r#"{"verdict":"refuted","guard":{"file":"a","line":1,"line":2},"p_real":3,"evidence_level":"safe_shown"}"#,
            r#"{"verdict":"refuted","p_real":3,"p_real":99,"evidence_level":"safe_shown"}"#,
        ] {
            assert_eq!(split_reply(raw), (raw.to_string(), ScoreRead::Missing));
        }
    }

    #[test]
    fn bad_scores_are_invalid_never_a_number() {
        for (p, l, why) in [
            (
                "101",
                "\"flow_shown\"",
                "p_real is not an integer from 0 to 100",
            ),
            (
                "-1",
                "\"flow_shown\"",
                "p_real is not an integer from 0 to 100",
            ),
            (
                "55.5",
                "\"flow_shown\"",
                "p_real is not an integer from 0 to 100",
            ),
            (
                "\"high\"",
                "\"flow_shown\"",
                "p_real is not an integer from 0 to 100",
            ),
            (
                "40",
                "\"likely\"",
                "evidence_level is not one of the five levels",
            ),
            ("40", "3", "evidence_level is not one of the five levels"),
        ] {
            let raw = format!(r#"{{"verdict": "refuted", "p_real": {p}, "evidence_level": {l}}}"#);
            assert_eq!(split_reply(&raw).1, ScoreRead::Invalid(why), "{raw}");
        }
        let only_p = r#"{"verdict": "refuted", "p_real": 40}"#;
        assert_eq!(
            split_reply(only_p).1,
            ScoreRead::Invalid("evidence_level missing")
        );
        let only_l = r#"{"verdict": "refuted", "evidence_level": "undetermined"}"#;
        assert_eq!(split_reply(only_l).1, ScoreRead::Invalid("p_real missing"));
        // The keys are removed even when unusable, so the verdict parser
        // judges the rest exactly as a reply without them.
        assert_eq!(split_reply(only_p).0, r#"{"verdict":"refuted"}"#);
    }

    #[test]
    fn evidence_lines_name_the_run_score_and_verdict() {
        let g = ScoreRead::Given {
            p_real: 0,
            level: EvidenceLevel::Undetermined,
        };
        assert_eq!(
            evidence_line(2, 3, &g, "plausible"),
            "refuter_score: run 2/3 p_real=0 evidence=undetermined; verdict=plausible"
        );
        assert_eq!(
            evidence_line(1, 1, &ScoreRead::Missing, "contract break"),
            "refuter_score: run 1/1 missing; verdict=contract break"
        );
        assert!(
            evidence_line(1, 1, &ScoreRead::Invalid("p_real missing"), "refuted")
                .contains("invalid (p_real missing)")
        );
    }

    #[test]
    fn instructions_define_all_five_levels_and_say_the_verdict_is_unchanged() {
        for l in EvidenceLevel::ALL {
            assert!(SCORE_INSTRUCTIONS.contains(&format!("\"{}\"", l.as_str())));
        }
        assert!(SCORE_INSTRUCTIONS.contains("\"p_real\""));
        assert!(SCORE_INSTRUCTIONS.contains("recorded only"));
        assert!(with_score_instructions("BASE").starts_with("BASE\n\n## Score"));
    }
}
