//! Operator-supplied engagement metadata. No ambient defaults are consulted.
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_ENGAGEMENT_BYTES: usize = 64 * 1024;
pub const ENGAGEMENT_SCHEMA: &str = "vettalon.engagement/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementFile {
    pub schema: String,
    #[serde(default)]
    pub engagement: Engagement,
    #[serde(default)]
    pub finding: Vec<FindingEngagement>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engagement {
    pub id: Option<String>,
    pub client: Option<String>,
    pub vendor: Option<String>,
    pub tester: Option<String>,
    pub reviewer: Option<String>,
    pub scope: Option<String>,
    pub scope_approval_ref: Option<String>,
    pub method_note: Option<String>,
    pub test_command_note: Option<String>,
    pub original_test_start: Option<String>,
    pub original_test_end: Option<String>,
    pub retest_date: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingEngagement {
    pub id: Option<String>,
    pub original_test_ref: Option<String>,
    pub risk_rating: Option<String>,
    pub location: Option<String>,
    pub correction_summary: Option<String>,
    pub tester_conclusion: Option<String>,
}

fn normalize(value: &mut Option<String>, name: &str, limit: usize) -> Result<(), String> {
    if let Some(text) = value {
        // Validate decoded values as TOML escapes can hide forbidden characters.
        if text.chars().any(|c| {
            c.is_control() || crate::disclose::is_invisible(c)
                || matches!(c as u32, 0x17B4..=0x17B5 | 0x180B..=0x180F | 0xFFF0..=0xFFF8 | 0xE0000..=0xE0FFF)
        }) {
            return Err(format!("forbidden character in {name}"));
        }
        if text.chars().count() > limit {
            return Err(format!("{name} exceeds {limit} characters"));
        }
        let trimmed = text.trim();
        if trimmed.is_empty() {
            *value = None;
        } else if !vettalon_contract::visible_text::is_visible_text(trimmed, limit) {
            return Err(format!("{name} must contain visible text"));
        } else {
            *text = trimmed.to_owned();
        }
    }
    Ok(())
}

fn validate_date(value: &Option<String>, name: &str) -> Result<(), String> {
    if let Some(date) = value {
        let bytes = date.as_bytes();
        if bytes.len() != 10
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || !bytes
                .iter()
                .enumerate()
                .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
            || NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err()
        {
            return Err(format!("{name} must be a valid YYYY-MM-DD date"));
        }
    }
    Ok(())
}

// Only static error categories and positions are exposed, never TOML values.
fn toml_diagnostic(text: &str, error: &toml::de::Error) -> String {
    let mut offset = error.span().map_or(0, |span| span.start).min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    let prefix = &text[..offset];
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let column = prefix.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    let message = error.message();
    let kind = if message.starts_with("unknown field") {
        "unknown field"
    } else if message.starts_with("missing field") {
        "missing field"
    } else if message.starts_with("invalid type") {
        "invalid type"
    } else if message.starts_with("duplicate") {
        "duplicate field"
    } else {
        "syntax error"
    };
    format!("invalid engagement TOML: {kind} at line {line}, column {column}")
}

/// Parse bounded UTF-8 TOML, normalize blanks to None, and validate all values.
/// Finding binding must additionally be checked with validate_finding_ids.
pub fn parse_engagement(input: &[u8]) -> Result<EngagementFile, String> {
    if input.len() > MAX_ENGAGEMENT_BYTES {
        return Err("engagement exceeds 64 KiB".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| "engagement must be UTF-8".to_owned())?;
    // TOML structural newlines/tabs are allowed; decoded field values allow no controls.
    if text.chars().any(|c| {
        matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            || (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    }) {
        return Err("forbidden character in engagement TOML".into());
    }
    let mut file: EngagementFile = toml::from_str(text).map_err(|e| toml_diagnostic(text, &e))?;
    if file.schema != ENGAGEMENT_SCHEMA {
        return Err("unsupported engagement schema".into());
    }
    normalize(&mut file.engagement.id, "engagement.id", 200)?;
    normalize(&mut file.engagement.client, "engagement.client", 200)?;
    normalize(&mut file.engagement.vendor, "engagement.vendor", 200)?;
    normalize(&mut file.engagement.tester, "engagement.tester", 200)?;
    normalize(&mut file.engagement.reviewer, "engagement.reviewer", 200)?;
    normalize(&mut file.engagement.scope, "engagement.scope", 200)?;
    normalize(
        &mut file.engagement.scope_approval_ref,
        "engagement.scope_approval_ref",
        200,
    )?;
    normalize(
        &mut file.engagement.method_note,
        "engagement.method_note",
        2000,
    )?;
    normalize(
        &mut file.engagement.test_command_note,
        "engagement.test_command_note",
        2000,
    )?;
    normalize(
        &mut file.engagement.original_test_start,
        "engagement.original_test_start",
        200,
    )?;
    normalize(
        &mut file.engagement.original_test_end,
        "engagement.original_test_end",
        200,
    )?;
    normalize(
        &mut file.engagement.retest_date,
        "engagement.retest_date",
        200,
    )?;
    validate_date(
        &file.engagement.original_test_start,
        "engagement.original_test_start",
    )?;
    validate_date(
        &file.engagement.original_test_end,
        "engagement.original_test_end",
    )?;
    validate_date(&file.engagement.retest_date, "engagement.retest_date")?;
    for row in &mut file.finding {
        normalize(&mut row.id, "finding.id", 200)?;
        normalize(&mut row.original_test_ref, "finding.original_test_ref", 200)?;
        normalize(&mut row.risk_rating, "finding.risk_rating", 200)?;
        normalize(&mut row.location, "finding.location", 200)?;
        normalize(
            &mut row.correction_summary,
            "finding.correction_summary",
            2000,
        )?;
        normalize(
            &mut row.tester_conclusion,
            "finding.tester_conclusion",
            2000,
        )?;
    }
    // An entirely blank template row carries no operator statement.
    file.finding
        .retain(|row| row != &FindingEngagement::default());
    if file.finding.iter().any(|row| row.id.is_none()) {
        return Err("nonempty finding row requires an id".into());
    }
    let mut seen = BTreeSet::new();
    for row in &file.finding {
        if !seen.insert(row.id.as_deref()) {
            return Err("duplicate finding id".into());
        }
    }
    Ok(file)
}

/// Reject every finding reference that does not name a package row.
pub fn validate_finding_ids(
    file: &EngagementFile,
    known_ids: &BTreeSet<String>,
) -> Result<(), String> {
    for row in &file.finding {
        match &row.id {
            Some(id) if known_ids.contains(id) => {}
            _ => return Err("unknown or missing engagement finding id".into()),
        }
    }
    Ok(())
}

/// Editable metadata starts blank; the schema declaration is ready to parse.
pub fn engagement_template() -> String {
    let mut out = String::from(
        "# Operator statements only. Blank values remain absent.\nschema = \"vettalon.engagement/1\"\n\n[engagement]\n",
    );
    out.push_str("# operator supplied.\nid = \"\"\n");
    out.push_str("# operator supplied.\nclient = \"\"\n");
    out.push_str("# operator supplied.\nvendor = \"\"\n");
    out.push_str("# operator supplied.\ntester = \"\"\n");
    out.push_str("# operator supplied.\nreviewer = \"\"\n");
    out.push_str("# operator supplied.\nscope = \"\"\n");
    out.push_str("# operator supplied.\nscope_approval_ref = \"\"\n");
    out.push_str("# operator supplied.\nmethod_note = \"\"\n");
    out.push_str("# operator supplied.\ntest_command_note = \"\"\n");
    out.push_str("# Valid YYYY-MM-DD date; operator supplied.\noriginal_test_start = \"\"\n");
    out.push_str("# Valid YYYY-MM-DD date; operator supplied.\noriginal_test_end = \"\"\n");
    out.push_str("# Valid YYYY-MM-DD date; operator supplied.\nretest_date = \"\"\n");
    out.push_str("\n# Repeat this table for each known package finding id.\n[[finding]]\n");
    out.push_str("# Operator supplied.\nid = \"\"\n");
    out.push_str("# Operator supplied.\noriginal_test_ref = \"\"\n");
    out.push_str("# Operator supplied.\nrisk_rating = \"\"\n");
    out.push_str("# Operator supplied.\nlocation = \"\"\n");
    out.push_str("# Operator supplied.\ncorrection_summary = \"\"\n");
    out.push_str("# Operator supplied.\ntester_conclusion = \"\"\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(body: &str) -> Result<EngagementFile, String> {
        parse_engagement(format!("schema = \"{ENGAGEMENT_SCHEMA}\"\n{body}").as_bytes())
    }
    #[test]
    fn unknown_keys_refused_at_every_level() {
        for body in [
            "extra = 1",
            "[engagement]\nextra = 1",
            "[[finding]]\nid = \"A\"\nextra = 1",
        ] {
            assert!(parse(body).is_err());
        }
    }
    #[test]
    fn dates_are_strict_calendar_dates() {
        for value in [
            "2025-02-29",
            "2024-2-01",
            "2024-04-31",
            "2024-01-01T00:00:00",
            "0000-00-00",
        ] {
            assert!(parse(&format!("[engagement]\nretest_date = {value:?}")).is_err());
        }
        assert!(parse("[engagement]\nretest_date = \"2024-02-29\"").is_ok());
    }
    #[test]
    fn bidi_and_all_controls_refused_in_values() {
        for c in (0..=31).chain(0x202a..=0x202e).chain(0x2066..=0x2069) {
            let body = format!("[engagement]\nclient = \"a\\u{c:04X}b\"");
            assert!(parse(&body).is_err(), "U+{c:04X}");
        }
    }
    #[test]
    fn invisible_characters_are_refused_even_between_visible_characters() {
        for c in [
            0x00ad, 0x0600, 0x200b, 0x200f, 0x2060, 0x2064, 0xfe00, 0xfe0f, 0xfeff, 0x034f, 0x17b4,
            0x180b, 0xfff0, 0xe0fff,
        ] {
            assert!(
                parse(&format!("[engagement]\nclient = \"a\\U{c:08X}b\"")).is_err(),
                "U+{c:04X}"
            );
        }
    }

    #[test]
    fn scope_and_redacted_parse_diagnostics() {
        assert!(parse(&format!("[engagement]\nscope = {:?}", "字".repeat(200))).is_ok());
        assert!(parse(&format!("[engagement]\nscope = {:?}", "字".repeat(201))).is_err());
        for (body, kind) in [
            ("[engagement]\nclient = 123456789", "invalid type"),
            (
                "[engagement]\nsecret_field = \"secret-value\"",
                "unknown field",
            ),
            ("[engagement]\nclient = \"secret-value", "syntax error"),
        ] {
            let error = parse(body).unwrap_err();
            assert!(error.contains(kind) && error.contains("line"), "{error}");
            assert!(
                !error.contains("secret") && !error.contains("123456789"),
                "{error}"
            );
        }
    }

    #[test]
    fn unknown_and_duplicate_finding_ids_refused() {
        let file = parse("[[finding]]\nid = \"A\"").unwrap();
        assert!(validate_finding_ids(&file, &BTreeSet::new()).is_err());
        assert!(validate_finding_ids(&file, &BTreeSet::from(["A".into()])).is_ok());
        assert!(parse("[[finding]]\nid = \"A\"\n[[finding]]\nid = \"A\"").is_err());
        assert!(parse("[[finding]]\nrisk_rating = \"high\"").is_err());
    }
    #[test]
    fn blanks_and_missing_values_stay_null() {
        let file = parse("[engagement]\nclient = \"  \"\n[[finding]]\nid = \"\"").unwrap();
        assert_eq!(file.engagement, Engagement::default());
        assert!(file.finding.is_empty());
        assert!(serde_json::to_value(file.engagement).unwrap()["client"].is_null());
    }
    #[test]
    fn size_and_character_limits_enforced() {
        assert!(parse_engagement(&vec![b' '; MAX_ENGAGEMENT_BYTES + 1]).is_err());
        assert!(parse(&format!("[engagement]\nclient = {:?}", "字".repeat(201))).is_err());
        assert!(
            parse(&format!(
                "[engagement]\nmethod_note = {:?}",
                "字".repeat(2000)
            ))
            .is_ok()
        );
        assert!(
            parse(&format!(
                "[engagement]\nmethod_note = {:?}",
                "字".repeat(2001)
            ))
            .is_err()
        );
    }
    #[test]
    fn template_has_every_blank_key() {
        let template = engagement_template();
        let file = parse_engagement(template.as_bytes()).unwrap();
        assert_eq!(file.engagement, Engagement::default());
        assert!(file.finding.is_empty());
    }
}
