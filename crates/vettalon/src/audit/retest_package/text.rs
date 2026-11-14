//! Versioned package text and framework mapping, independent of terminal locale.
use super::record::{blocker_label, fix_outcome_label};
use crate::audit::fix_check::{Blocker, FixOutcome};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAPPING_JSON: &str = include_str!("mapping.json");
pub const TEXT_JSON: &str = include_str!("text.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Localized {
    #[serde(rename = "zh-TW")]
    pub zh_tw: String,
    pub en: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub version: String,
    pub frameworks: Vec<Framework>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Framework {
    pub name: Localized,
    pub id: String,
    pub source_checked: bool,
    pub source_note: Localized,
    pub rows: Vec<MappingRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingRow {
    pub id: String,
    pub source_checked: bool,
    pub requirement: Localized,
    pub record_fields: Vec<String>,
    pub operator_fields: Vec<String>,
    pub gap: Option<Localized>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    pub version: String,
    pub locales: BTreeMap<String, BTreeMap<String, String>>,
}

impl Text {
    /// Explicit language lookup; unsupported languages and missing keys are errors.
    pub fn get(&self, locale: &str, key: &str) -> Result<&str, String> {
        self.locales
            .get(locale)
            .and_then(|values| values.get(key))
            .map(String::as_str)
            .ok_or_else(|| format!("missing package text: {locale}/{key}"))
    }
}

/// Supply paths from the record schema, including operator paths. No path is inferred
/// from prose or accepted merely because it looks like a dotted path.
pub fn load_mapping(known_field_paths: &BTreeSet<String>) -> Result<Mapping, String> {
    let mapping: Mapping = serde_json::from_str(MAPPING_JSON).map_err(|e| e.to_string())?;
    validate_mapping(&mapping, known_field_paths)?;
    Ok(mapping)
}

pub fn load_text() -> Result<Text, String> {
    let text: Text = serde_json::from_str(TEXT_JSON).map_err(|e| e.to_string())?;
    validate_text(&text)?;
    Ok(text)
}

pub fn validate_data(
    mapping: &Mapping,
    text: &Text,
    known_field_paths: &BTreeSet<String>,
) -> Result<(), String> {
    validate_mapping(mapping, known_field_paths)?;
    validate_text(text)
}

fn validate_localized(value: &Localized) -> Result<(), String> {
    if value.zh_tw.trim().is_empty() || value.en.trim().is_empty() {
        return Err("mapping requires nonempty zh-TW and en text".into());
    }
    Ok(())
}

fn validate_mapping(mapping: &Mapping, paths: &BTreeSet<String>) -> Result<(), String> {
    if mapping.version != "retest-mapping/1" || mapping.frameworks.is_empty() {
        return Err("unsupported or empty mapping".into());
    }
    let mut frameworks = BTreeSet::new();
    for framework in &mapping.frameworks {
        if framework.id.is_empty() || !frameworks.insert(&framework.id) {
            return Err("mapping framework id must be unique".into());
        }
        validate_localized(&framework.name)?;
        validate_localized(&framework.source_note)?;
        let mut rows = BTreeSet::new();
        if framework.rows.is_empty() {
            return Err("mapping framework has no rows".into());
        }
        for row in &framework.rows {
            if row.id.is_empty() || !rows.insert(&row.id) {
                return Err("mapping row id must be unique".into());
            }
            validate_localized(&row.requirement)?;
            if let Some(gap) = &row.gap {
                validate_localized(gap)?;
            }
            if row.record_fields.is_empty() && row.operator_fields.is_empty() {
                return Err(format!("mapping row {} has no field paths", row.id));
            }
            for path in &row.record_fields {
                if !paths.contains(path) || is_operator_path(path) {
                    return Err(format!("unknown record field path: {path}"));
                }
            }
            for path in &row.operator_fields {
                if !paths.contains(path) || !is_operator_path(path) {
                    return Err(format!("unknown operator field path: {path}"));
                }
            }
        }
    }
    Ok(())
}

fn is_operator_path(path: &str) -> bool {
    path.starts_with("engagement.") || path.starts_with("findings[].operator.")
}

fn outcomes() -> [FixOutcome; 4] {
    [
        FixOutcome::FixVerified,
        FixOutcome::FixCheckPartial,
        FixOutcome::FixRejected,
        FixOutcome::FixUnverified,
    ]
}

fn machine_key(key: &str) -> bool {
    [
        "status.",
        "outcome.",
        "blocker.",
        "verdict.",
        "observation.",
        "input_verdict.",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
}

fn validate_text(text: &Text) -> Result<(), String> {
    if text.version != "retest-text/1"
        || text.locales.len() != 2
        || !text.locales.contains_key("zh-TW")
        || !text.locales.contains_key("en")
    {
        return Err("package text supports exactly zh-TW and en".into());
    }
    let zh = &text.locales["zh-TW"];
    let en = &text.locales["en"];
    if zh.is_empty() || zh.keys().ne(en.keys()) {
        return Err("every locale must contain every text key".into());
    }
    for (locale, values) in &text.locales {
        for (key, value) in values {
            if value.trim().is_empty() {
                return Err(format!("empty package text: {locale}/{key}"));
            }
            if machine_key(key) {
                let lower = value.to_lowercase();
                for word in [
                    "fixed",
                    "secure",
                    "remediated",
                    "已修補",
                    "已修復",
                    "修補完成",
                    "安全無虞",
                ] {
                    if lower.contains(word) {
                        return Err(format!("forbidden machine wording: {locale}/{key}"));
                    }
                }
            }
        }
    }
    for key in [
        "label_value",
        "engagement_intro",
        "input_verdict.blocked",
        "input_verdict.observed",
        "heading.engagement",
        "heading.summary",
        "heading.findings",
        "heading.environment",
        "heading.limits",
        "heading.mapping",
        "heading.appendix",
        "heading.verify",
        "heading.inputs",
        "column.content",
        "column.syntax",
        "column.original",
        "column.fixed_copy",
        "column.verdict",
        "field.vendor",
        "field.id",
        "package_sources",
        "summary_source",
        "summary_totals",
        "finding_sources",
        "retest_conclusion",
        "fix_check_conclusion",
        "field.report_evidence",
        "call_label",
        "call_summary",
        "call_missing",
        "signature.absent",
        "signature.matched",
        "signature.verified",
        "signature.unverified",
    ] {
        text.get("zh-TW", key)?;
        text.get("en", key)?;
    }
    for outcome in outcomes() {
        let key = format!("outcome.{}", outcome.key());
        if text.get("zh-TW", &key)? != outcome.label_zh()
            || text.get("en", &key)? != fix_outcome_label(outcome).en
        {
            return Err(format!("outcome label differs from existing label: {key}"));
        }
    }
    for (blocker, key) in [
        (Blocker::Environment, "blocker.environment"),
        (Blocker::Harness, "blocker.harness"),
    ] {
        let label = blocker_label(blocker).expect("named blockers have labels");
        if text.get("zh-TW", key)? != label.zh_tw || text.get("en", key)? != label.en {
            return Err(format!("blocker label differs from existing label: {key}"));
        }
    }
    Ok(())
}

/// Fill named placeholders once. Inserted values are never interpreted as templates.
/// Output-format escaping is the renderer's responsibility.
pub fn fill(template: &str, values: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        let end = tail.find('}').ok_or("unclosed text placeholder")?;
        let name = &tail[..end];
        out.push_str(
            values
                .get(name)
                .ok_or_else(|| format!("missing text placeholder: {name}"))?,
        );
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::record::record_field_paths;

    #[test]
    fn every_locale_has_every_key() {
        let mut text = load_text().unwrap();
        text.locales.get_mut("en").unwrap().remove("blank");
        assert!(validate_text(&text).is_err());
        text.locales.insert("ja".into(), BTreeMap::new());
        assert!(validate_text(&text).is_err());
    }

    #[test]
    fn mapping_paths_exist_in_record_schema() {
        let paths = record_field_paths();
        let mut mapping = load_mapping(&paths).unwrap();
        validate_data(&mapping, &load_text().unwrap(), &paths).unwrap();
        mapping.frameworks[0].rows[0]
            .record_fields
            .push("findings[].invented".into());
        assert!(validate_mapping(&mapping, &paths).is_err());
    }

    #[test]
    fn mapping_sources_remain_unchecked() {
        let mut mapping = load_mapping(&record_field_paths()).unwrap();
        assert!(
            mapping
                .frameworks
                .iter()
                .all(|f| !f.source_checked && f.rows.iter().all(|r| !r.source_checked))
        );
        mapping.frameworks[0].source_checked = true;
        mapping.frameworks[0].rows[0].source_checked = true;
        validate_mapping(&mapping, &record_field_paths()).unwrap();
    }

    #[test]
    fn outcomes_equal_existing_labels() {
        let mut text = load_text().unwrap();
        for outcome in outcomes() {
            let key = format!("outcome.{}", outcome.key());
            assert_eq!(text.get("zh-TW", &key).unwrap(), outcome.label_zh());
            assert_eq!(text.get("en", &key).unwrap(), fix_outcome_label(outcome).en);
        }
        text.locales
            .get_mut("en")
            .unwrap()
            .insert("outcome.fix_verified".into(), "Different label".into());
        assert!(validate_text(&text).is_err());
    }

    #[test]
    fn statuses_and_notes_equal_the_single_text_source() {
        use super::super::record::{
            call_not_supplied_label, inputs_not_determinable_label, retest_status_label,
        };
        let text = load_text().unwrap();
        let mut labels: Vec<_> = crate::audit::retest::RetestStatus::ALL
            .into_iter()
            .map(|status| {
                (
                    format!("status.{}", status.key()),
                    retest_status_label(status),
                )
            })
            .collect();
        labels.push(("call_not_supplied".into(), call_not_supplied_label()));
        labels.push(("not_determinable".into(), inputs_not_determinable_label()));
        for (key, label) in labels {
            assert_eq!(text.get("zh-TW", &key).unwrap(), label.zh_tw);
            assert_eq!(text.get("en", &key).unwrap(), label.en);
        }
    }

    #[test]
    fn forbidden_words_refused_in_machine_text() {
        for word in [
            "fixed",
            "SECURE",
            "remediated",
            "已修補",
            "已修復",
            "修補完成",
            "安全無虞",
        ] {
            let mut text = load_text().unwrap();
            text.locales
                .get_mut("en")
                .unwrap()
                .insert("status.inconclusive".into(), word.into());
            assert!(validate_text(&text).is_err());
        }
    }

    #[test]
    fn closed_mapping_and_text_schemas() {
        assert!(
            serde_json::from_str::<Mapping>(&MAPPING_JSON.replacen(
                "\"version\":",
                "\"unknown\": 1, \"version\":",
                1
            ))
            .is_err()
        );
        assert!(
            serde_json::from_str::<Text>(&TEXT_JSON.replacen(
                "\"version\":",
                "\"unknown\": 1, \"version\":",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn explicit_locale_and_single_pass_placeholders() {
        let text = load_text().unwrap();
        assert!(text.get("ja", "blank").is_err());
        assert!(text.get("en", "missing").is_err());
        let values = BTreeMap::from([("sha256".into(), "{other}".into())]);
        assert_eq!(
            fill(text.get("en", "call_not_supplied").unwrap(), &values).unwrap(),
            "Call plan not supplied, sha256 {other}"
        );
        assert!(fill("{missing}", &values).is_err());
        assert!(fill("{unclosed", &values).is_err());
    }
}
