//! Deterministic client-facing records with a shared evidence appendix.
use super::record::*;
use super::text::{Mapping, Text, fill};
use crate::disclose::formats::fence_for;
use crate::lang::Lang;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn md(value: &str) -> String {
    escape(&sanitize(value))
}

// Package translations are trusted text; do not run secret masking on labels.
fn escape(value: &str) -> String {
    let mut out = String::new();
    for (i, c) in value.chars().enumerate() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' => {
                out.push('\\');
                out.push(c);
            }
            '#' if i == 0 => out.push_str("\\#"),
            _ => out.push(c),
        }
    }
    out
}

// HTML is inert in code spans. Pipes still need escaping for Markdown tables.
fn code(value: &str) -> String {
    let value = sanitize(value).replace('|', "\\|");
    let longest = value.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let pad = if value.starts_with('`')
        || value.ends_with('`')
        || (value.starts_with(' ') && value.ends_with(' '))
    {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{value}{pad}{fence}")
}

// Newlines are meaningful inside fenced input and tester quotations.
fn block_text(value: &str) -> String {
    value
        .split('\n')
        .map(sanitize)
        .collect::<Vec<_>>()
        .join("\n")
}

fn localized_name(value: &super::text::Localized, lang: Lang) -> &str {
    match lang {
        Lang::ZhTw => &value.zh_tw,
        Lang::En => &value.en,
    }
}

type EvidenceIndex = BTreeMap<(String, String), (String, String, String)>;
struct Renderer<'a> {
    locale: &'static str,
    text: &'a Text,
    out: String,
    evidence: EvidenceIndex,
}
impl Renderer<'_> {
    fn t(&self, key: &str) -> Result<&str, String> {
        self.text.get(self.locale, key)
    }
    fn heading(&mut self, level: usize, key: &str) -> Result<(), String> {
        self.out.push_str(&format!(
            "{} {}\n\n",
            "#".repeat(level),
            escape(self.t(key)?)
        ));
        Ok(())
    }
    fn paragraph(&mut self, key: &str) -> Result<(), String> {
        self.out.push_str(&format!("{}\n\n", escape(self.t(key)?)));
        Ok(())
    }
    fn row(&mut self, cells: &[String]) {
        self.out.push_str(&format!("| {} |\n", cells.join(" | ")));
    }
    fn header(&mut self, keys: &[&str]) -> Result<(), String> {
        self.row(
            &keys
                .iter()
                .map(|k| self.t(k).map(escape))
                .collect::<Result<Vec<_>, _>>()?,
        );
        self.row(&vec!["---".into(); keys.len()]);
        Ok(())
    }
    fn label(&self, key: &str) -> Result<String, String> {
        self.t(&format!("field.{key}")).map(escape)
    }
    fn optional(&self, value: Option<&str>, technical: bool) -> Result<String, String> {
        Ok(match value.filter(|v| !v.trim().is_empty()) {
            Some(v) if technical => code(v),
            Some(v) => md(v),
            None => escape(self.t("not_recorded")?),
        })
    }
    fn fact(&mut self, key: &str, value: String) -> Result<(), String> {
        self.row(&[self.label(key)?, value]);
        Ok(())
    }
    fn cite(&self, e: &Evidence) -> Result<String, String> {
        self.evidence
            .get(&(e.file.clone(), e.file_sha256.clone()))
            .map(|v| code(&v.0))
            .ok_or_else(|| "receipt missing from evidence index".into())
    }
    fn source_refs(&self, kind: &str) -> String {
        self.evidence
            .values()
            .filter(|v| v.1 == kind)
            .map(|v| code(&v.0))
            .collect::<Vec<_>>()
            .join(", ")
    }
    fn line(&mut self, label: &str, value: String) -> Result<(), String> {
        let line = fill(
            self.t("label_value")?,
            &BTreeMap::from([
                ("label".into(), escape(self.t(label)?)),
                ("value".into(), value),
            ]),
        )?;
        self.out.push_str(&format!("{line}\n\n"));
        Ok(())
    }
    fn benign_result(&self, checks: &[FixCheckRecord]) -> Result<String, String> {
        let mut values = Vec::new();
        for check in checks {
            let key = serde_json::to_value(check.benign).map_err(|e| e.to_string())?;
            values.push(format!(
                "{} ({})",
                escape(self.t(&format!(
                    "verdict.{}",
                    key.as_str().ok_or("invalid benign verdict")?
                ))?),
                self.cite(&check.evidence)?
            ));
        }
        if values.is_empty() {
            Ok(escape(self.t("not_recorded")?))
        } else {
            Ok(values.join("; "))
        }
    }
    fn observation(&self, value: &impl serde::Serialize) -> Result<String, String> {
        let key = serde_json::to_value(value).map_err(|e| e.to_string())?;
        self.t(&format!(
            "observation.{}",
            key.as_str().ok_or("invalid observation")?
        ))
        .map(escape)
    }
    fn environment_fields(&mut self, value: &Value, prefix: &str) -> Result<(), String> {
        if let Value::Object(map) = value {
            for (key, value) in map {
                let label = if prefix.is_empty() {
                    self.label(key)?
                } else {
                    format!("{prefix} / {}", self.label(key)?)
                };
                if value.is_object() {
                    self.environment_fields(value, &label)?;
                } else {
                    self.row(&[label, self.optional(value.as_str(), true)?]);
                }
            }
        }
        Ok(())
    }
}

pub fn render_markdown(
    record: &Record,
    lang: Lang,
    text: &Text,
    mapping: &Mapping,
) -> Result<String, String> {
    let mut index = BTreeMap::new();
    // Cosign stamps come only from package-time verification or this verifier run.
    // verify-package must reject stored verified claims without a trusted key.
    for source in &record.sources {
        let kind = serde_json::to_value(source.kind).map_err(|e| e.to_string())?;
        let signature = match &source.signature {
            None => "signature.absent",
            Some(s) if s.cosign.as_ref().is_some_and(|c| c.verified) => "signature.verified",
            Some(s) if s.subject_ok => "signature.matched",
            Some(_) => "signature.unverified",
        };
        index.insert(
            (source.path.clone(), source.sha256.clone()),
            (
                String::new(),
                format!("kind.{}", kind.as_str().ok_or("invalid source kind")?),
                signature.into(),
            ),
        );
    }
    for source in &record.sources {
        if let Some(signature) = &source.signature {
            if let Some(pq) = &signature.mldsa {
                index
                    .entry((pq.path.clone(), pq.sha256.clone()))
                    .or_insert((
                        String::new(),
                        "kind.pq_signature".into(),
                        if pq.verified.as_ref().is_some_and(|s| s.verified) {
                            "signature.pq_verified"
                        } else {
                            "signature.pq_matched"
                        }
                        .into(),
                    ));
            }
            index
                .entry((signature.path.clone(), signature.sha256.clone()))
                .or_insert((
                    String::new(),
                    "kind.signature".into(),
                    "signature.unverified".into(),
                ));
        }
    }
    for f in &record.findings {
        let receipts = f
            .original
            .iter()
            .map(|v| (&v.evidence, "kind.reproduce"))
            .chain(f.retest.iter().map(|v| (&v.evidence, "kind.retest")))
            .chain(f.fix_checks.iter().map(|v| (&v.evidence, "kind.fix_check")));
        for (e, kind) in receipts {
            index
                .entry((e.file.clone(), e.file_sha256.clone()))
                .or_insert((String::new(), kind.into(), "signature.absent".into()));
        }
    }
    for (i, entry) in index.values_mut().enumerate() {
        entry.0 = format!("E{}", i + 1);
    }
    let mut r = Renderer {
        locale: match lang {
            Lang::ZhTw => "zh-TW",
            Lang::En => "en",
        },
        text,
        out: String::new(),
        evidence: index,
    };
    r.heading(1, "heading.title")?;
    r.heading(2, "heading.engagement")?;
    r.paragraph("engagement_intro")?;
    r.header(&["column.field", "column.content"])?;
    let engagement = serde_json::to_value(&record.engagement).map_err(|e| e.to_string())?;
    for key in [
        "client",
        "id",
        "scope",
        "scope_approval_ref",
        "original_test_start",
        "original_test_end",
        "retest_date",
        "tester",
        "reviewer",
        "vendor",
        "method_note",
        "test_command_note",
    ] {
        r.fact(
            key,
            r.optional(
                engagement[key].as_str(),
                key == "id" || key == "scope_approval_ref",
            )?,
        )?;
    }
    let retest_refs = r.source_refs("kind.retest");
    for (key, value) in [
        (
            "old_repo_commit",
            record.revisions.old_repo_commit.as_deref(),
        ),
        (
            "new_repo_commit",
            record.revisions.new_repo_commit.as_deref(),
        ),
        (
            "old_report_sha256",
            record.revisions.old_report_sha256.as_deref(),
        ),
    ] {
        r.fact(key, format!("{} {}", r.optional(value, true)?, retest_refs))?;
    }
    r.fact(
        "replays_requested",
        format!(
            "{} {}",
            record
                .revisions
                .replays_requested
                .map(|v| v.to_string())
                .unwrap_or(r.t("not_recorded")?.into()),
            retest_refs
        ),
    )?;
    r.fact("vettalon_version", code(record.vettalon_version))?;
    r.out.push('\n');
    r.paragraph("performer")?;
    if record.revisions.new_tree_clean != Some(true) {
        r.paragraph("warning.tree")?;
    }
    let all_refs = r
        .evidence
        .values()
        .map(|v| code(&v.0))
        .collect::<Vec<_>>()
        .join(", ");
    r.line("package_sources", all_refs)?;
    r.heading(2, "heading.summary")?;
    r.header(&["column.outcome", "column.count"])?;
    let mut retest_total = 0;
    if let Some(summary) = &record.summary.retest {
        let counts = serde_json::to_value(summary).map_err(|e| e.to_string())?;
        for (status, count) in counts.as_object().ok_or("invalid summary")? {
            let count = count.as_u64().ok_or("invalid count")?;
            retest_total += count;
            if count > 0 {
                r.row(&[escape(r.t(&format!("status.{status}"))?), count.to_string()]);
            }
        }
    }
    let mut check_total = 0;
    for (outcome, count) in &record.summary.fix_outcomes {
        check_total += count;
        if *count > 0 {
            r.row(&[
                escape(r.t(&format!("outcome.{outcome}"))?),
                count.to_string(),
            ]);
        }
    }
    r.out.push('\n');
    r.out.push_str(&format!(
        "{}\n\n",
        fill(
            r.t("summary_totals")?,
            &BTreeMap::from([
                ("findings".into(), record.findings.len().to_string()),
                ("retests".into(), retest_total.to_string()),
                ("checks".into(), check_total.to_string())
            ])
        )?
    ));
    r.line(
        "summary_source",
        [retest_refs, r.source_refs("kind.fix_check")]
            .into_iter()
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
    )?;
    r.heading(2, "heading.findings")?;
    let mut findings = record.findings.iter().collect::<Vec<_>>();
    findings.sort_by(|a, b| (&a.id, &a.id_source).cmp(&(&b.id, &b.id_source)));
    let mut environments: BTreeMap<String, BTreeMap<String, (Value, BTreeSet<String>)>> =
        BTreeMap::new();
    for f in findings {
        r.out.push_str(&format!("### {}\n\n", code(&f.id)));
        if f.binding_note.is_some() {
            r.paragraph("unbound")?;
        }
        r.paragraph("finding_sources")?;
        let report_refs = r.source_refs("kind.report");
        r.header(&["column.field", "column.content"])?;
        r.fact("id", code(&f.id))?;
        if !report_refs.is_empty() {
            r.fact("report_evidence", report_refs)?;
        }
        let line = f
            .line
            .map(|n| n.to_string())
            .unwrap_or(r.t("not_recorded")?.into());
        let location = f.file.as_ref().map(|v| format!("{}:{line}", v.text));
        r.fact("location", r.optional(location.as_deref(), true)?)?;
        for (key, value) in [
            ("function", f.function.as_ref().map(|v| v.text.as_str())),
            ("cwe", f.cwe.as_ref().map(|v| v.text.as_str())),
            ("oracle_class", f.oracle_class),
            ("runtime", f.runtime),
        ] {
            let shown = if key == "oracle_class" && value == Some("ssrf") {
                escape(r.t("class.ssrf")?)
            } else {
                r.optional(value, true)?
            };
            r.fact(key, shown)?;
        }
        r.out.push('\n');
        let operator = serde_json::to_value(&f.operator).map_err(|e| e.to_string())?;
        let operator_keys = [
            "original_test_ref",
            "risk_rating",
            "location",
            "correction_summary",
        ];
        if operator_keys
            .iter()
            .any(|key| operator[key].as_str().is_some_and(|v| !v.trim().is_empty()))
        {
            r.paragraph("operator_statement")?;
            r.header(&["column.field", "column.content"])?;
            for key in operator_keys {
                r.fact(key, r.optional(operator[key].as_str(), false)?)?;
            }
            r.out.push('\n');
        }
        r.heading(4, "heading.inputs")?;
        if !f.inputs.determinable {
            r.paragraph("not_determinable")?;
        }
        r.header(&[
            "column.input",
            "column.syntax",
            "column.original",
            "column.fixed_copy",
            "column.verdict",
        ])?;
        let mut inputs = f.inputs.items.iter().collect::<Vec<_>>();
        // Stable sorting preserves the receipt's variant-set order within each role.
        inputs.sort_by_key(|i| match i.role {
            InputRole::Base => 0,
            InputRole::Variant => 1,
            InputRole::Decoding => 2,
            InputRole::Benign => 3,
        });
        let mut blocks = Vec::new();
        for input in &inputs {
            let role = serde_json::to_value(input.role).map_err(|e| e.to_string())?;
            let syntax = if input.text.chars().count() <= 80 && !input.text.contains(['\n', '\r']) {
                code(&input.text)
            } else {
                blocks.push(*input);
                code(input.id)
            };
            let original = if f.original.is_some() || input.role == InputRole::Decoding {
                r.observation(&input.original_copy)?
            } else {
                escape(r.t("not_recorded")?)
            };
            let mut original_refs = Vec::new();
            if matches!(input.role, InputRole::Base | InputRole::Benign)
                && input.original_copy != OriginalCopy::NotRecorded
                && let Some(v) = &f.original
            {
                original_refs.push(r.cite(&v.evidence)?);
            }
            let mut checks = f
                .fix_checks
                .iter()
                .filter(|c| c.per_input.iter().any(|v| v.id == input.id))
                .collect::<Vec<_>>();
            checks.sort_by(|a, b| a.evidence.file.cmp(&b.evidence.file));
            let observations = checks
                .iter()
                .map(|c| {
                    let v = c
                        .per_input
                        .iter()
                        .find(|v| v.id == input.id)
                        .ok_or("missing input")?;
                    Ok(format!(
                        "{} ({})",
                        r.observation(&v.fixed_copy)?,
                        r.cite(&c.evidence)?
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            if input.role == InputRole::Decoding && input.original_copy != OriginalCopy::NotRecorded
            {
                for c in &checks {
                    original_refs.push(r.cite(&c.evidence)?);
                }
            }
            let retest = if input.role == InputRole::Benign {
                r.benign_result(&f.fix_checks)?
            } else if observations.is_empty() {
                escape(r.t("not_recorded")?)
            } else {
                observations.join("; ")
            };
            let mut verdict = checks
                .iter()
                .map(|c| {
                    let mark = c
                        .per_input
                        .iter()
                        .find(|v| v.id == input.id)
                        .ok_or("missing input")?
                        .fixed_copy;
                    let key = match mark {
                        FixedCopy::Blocked => "input_verdict.blocked",
                        FixedCopy::NotBlocked => "input_verdict.observed",
                        FixedCopy::NotApplicable => "observation.not_applicable",
                        FixedCopy::NotRecorded => "not_recorded",
                    };
                    Ok(format!("{} ({})", escape(r.t(key)?), r.cite(&c.evidence)?))
                })
                .collect::<Result<Vec<_>, String>>()?;
            if input.role == InputRole::Benign {
                verdict = vec![r.benign_result(&f.fix_checks)?];
            }
            let verdict = if verdict.is_empty() {
                escape(r.t("not_recorded")?)
            } else {
                verdict.join("; ")
            };
            r.row(&[
                format!(
                    "{} ({})",
                    code(input.id),
                    escape(r.t(&format!("role.{}", role.as_str().ok_or("invalid role")?))?)
                ),
                syntax,
                format!("{} {}", original, original_refs.join(", "))
                    .trim()
                    .into(),
                retest,
                verdict,
            ]);
        }
        if !inputs.iter().any(|i| i.role == InputRole::Benign) {
            let benign = r.benign_result(&f.fix_checks)?;
            r.row(&[
                escape(r.t("role.benign")?),
                escape(r.t("not_recorded")?),
                escape(r.t("not_recorded")?),
                benign.clone(),
                benign,
            ]);
        }
        r.out.push('\n');
        for input in blocks {
            r.out.push_str(&format!("{}\n\n", code(input.id)));
            let shown = block_text(&input.text);
            let fence = fence_for(&shown);
            r.out.push_str(&format!("{fence}\n{shown}\n{fence}\n\n"));
        }
        for input in &inputs {
            if input.truncated {
                r.out.push_str(&format!(
                    "{}: {}\n\n",
                    code(input.id),
                    fill(
                        r.t("input_truncated")?,
                        &BTreeMap::from([(
                            "sha256".into(),
                            code(input.text_sha256.as_deref().unwrap_or(r.t("not_recorded")?))
                        )])
                    )?
                ));
            }
        }
        let mut hashes = f.call.plan_sha256s.iter().collect::<Vec<_>>();
        hashes.sort();
        if hashes.is_empty() {
            r.line("call_label", escape(r.t("not_recorded")?))?;
        }
        for hash in hashes {
            let mut refs = r
                .evidence
                .iter()
                .filter(|((_, sha), (_, kind, _))| kind == "kind.plans" && sha == hash)
                .map(|(_, v)| code(&v.0))
                .collect::<Vec<_>>()
                .join(", ");
            if refs.is_empty() && f.call.supplied {
                refs = r.source_refs("kind.plans");
            }
            if refs.is_empty() {
                let receipts = f
                    .original
                    .iter()
                    .map(|v| &v.evidence)
                    .chain(f.retest.iter().map(|v| &v.evidence))
                    .chain(f.fix_checks.iter().map(|v| &v.evidence));
                refs = receipts
                    .map(|e| r.cite(e))
                    .collect::<Result<BTreeSet<_>, _>>()?
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ");
            }
            let template = if f.call.supplied {
                "call_summary"
            } else {
                "call_missing"
            };
            r.out.push_str(&format!(
                "{}\n\n",
                fill(
                    r.t(template)?,
                    &BTreeMap::from([
                        ("count".into(), f.call.args.len().to_string()),
                        ("sha256".into(), code(hash)),
                        ("evidence".into(), refs)
                    ])
                )?
            ));
        }
        let mut cited = BTreeSet::new();
        if let Some(v) = &f.original {
            let cite = r.cite(&v.evidence)?;
            cited.insert(cite.clone());
            let key = serde_json::to_value(v.run.outcome).map_err(|e| e.to_string())?;
            r.line(
                "column.original",
                format!(
                    "{} ({cite})",
                    escape(r.t(&format!(
                        "reproduce.{}",
                        key.as_str().ok_or("invalid outcome")?
                    ))?)
                ),
            )?;
        }
        if let Some(v) = &f.retest {
            let cite = r.cite(&v.evidence)?;
            cited.insert(cite.clone());
            r.line(
                "retest_conclusion",
                format!(
                    "{} ({cite})",
                    escape(r.t(&format!("status.{}", v.status.key()))?)
                ),
            )?;
        }
        let mut checks = f.fix_checks.iter().collect::<Vec<_>>();
        checks.sort_by(|a, b| a.diff_sha256.cmp(&b.diff_sha256));
        for c in checks {
            let cite = r.cite(&c.evidence)?;
            cited.insert(cite.clone());
            r.line(
                "fix_check_conclusion",
                format!(
                    "{} ({cite})",
                    escape(r.t(&format!("outcome.{}", c.outcome.key()))?)
                ),
            )?;
        }
        r.heading(4, "heading.tester_conclusion")?;
        if let Some(conclusion) = f
            .operator
            .tester_conclusion
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            // A fenced quotation preserves the tester's words without interpreting Markdown.
            let shown = block_text(conclusion);
            let fence = fence_for(&shown);
            r.out.push_str(&format!("{fence}\n{shown}\n{fence}\n\n"));
        } else {
            r.paragraph("not_recorded")?;
        }
        r.line(
            "heading.evidence",
            cited.into_iter().collect::<Vec<_>>().join(", "),
        )?;
        let runs = f
            .original
            .iter()
            .map(|v| (&v.run.environment, &v.evidence))
            .chain(
                f.retest
                    .iter()
                    .filter_map(|v| v.run.as_ref().map(|run| (&run.environment, &v.evidence))),
            )
            .chain(f.fix_checks.iter().map(|v| (&v.environment, &v.evidence)));
        for (environment, evidence) in runs {
            let value = serde_json::to_value(environment).map_err(|e| e.to_string())?;
            let key = serde_json::to_string(&value).map_err(|e| e.to_string())?;
            environments
                .entry(f.runtime.unwrap_or(r.t("not_recorded")?).into())
                .or_default()
                .entry(key)
                .or_insert_with(|| (value, BTreeSet::new()))
                .1
                .insert(r.cite(evidence)?);
        }
    }
    r.heading(2, "heading.environment")?;
    if environments.is_empty() {
        r.paragraph("not_recorded")?;
    }
    for (runtime, entries) in environments {
        for (_, (value, citations)) in entries {
            r.out.push_str(&format!(
                "### {} ({})\n\n",
                code(&runtime),
                citations.into_iter().collect::<Vec<_>>().join(", "),
            ));
            r.header(&["column.field", "column.content"])?;
            r.environment_fields(&value, "")?;
            r.out.push('\n');
        }
    }
    r.heading(2, "heading.limits")?;
    // Always include the shipped limitations, even before a package writer has
    // populated Record.limits. Additional selected keys still fail closed.
    let mut limits = text
        .locales
        .get(r.locale)
        .ok_or("missing locale")?
        .keys()
        .filter(|k| k.starts_with("limit."))
        .cloned()
        .collect::<Vec<_>>();
    limits.extend(record.limits.iter().cloned());
    limits.sort();
    limits.dedup();
    for key in limits {
        r.out.push_str(&format!("- {}\n", escape(r.t(&key)?)));
    }
    r.out.push('\n');
    r.heading(2, "heading.mapping")?;
    let mut frameworks = mapping.frameworks.iter().collect::<Vec<_>>();
    frameworks.sort_by(|a, b| a.id.cmp(&b.id));
    for framework in frameworks {
        r.out.push_str(&format!(
            "### {}\n\n",
            escape(localized_name(&framework.name, lang))
        ));
        let localized = |v: &super::text::Localized| match lang {
            Lang::ZhTw => v.zh_tw.clone(),
            Lang::En => v.en.clone(),
        };
        r.out.push_str(&format!(
            "{}\n\n",
            escape(&localized(&framework.source_note))
        ));
        r.header(&[
            "column.requirement",
            "column.record",
            "column.operator",
            "column.gap",
        ])?;
        let mut rows = framework.rows.iter().collect::<Vec<_>>();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        for row in rows {
            let mut record_fields = row.record_fields.clone();
            record_fields.sort();
            let mut operator_fields = row.operator_fields.clone();
            operator_fields.sort();
            let gap = row.gap.as_ref().map(localized).unwrap_or_default();
            r.row(&[
                escape(&localized(&row.requirement)),
                record_fields
                    .iter()
                    .map(|v| {
                        r.t(&format!(
                            "mapping.{}",
                            v.replace("[]", "").replace('.', "_")
                        ))
                        .map(escape)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .join(", "),
                operator_fields
                    .iter()
                    .map(|v| {
                        r.t(&format!(
                            "mapping.{}",
                            v.replace("[]", "").replace('.', "_")
                        ))
                        .map(escape)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .join(", "),
                md(&gap),
            ]);
        }
        r.out.push('\n');
    }
    r.heading(2, "heading.appendix")?;
    r.header(&[
        "field.id",
        "field.kind",
        "field.path",
        "column.hash",
        "field.signature",
    ])?;
    for ((path, hash), (id, kind, signature)) in &r.evidence {
        let signature_ref = record
            .sources
            .iter()
            .find(|v| v.path == *path && v.sha256 == *hash)
            .and_then(|v| v.signature.as_ref())
            .and_then(|v| r.evidence.get(&(v.path.clone(), v.sha256.clone())))
            .map(|v| format!(" ({})", code(&v.0)))
            .unwrap_or_default();
        let mut status = format!("{}{signature_ref}", escape(r.t(signature)?));
        if let Some(pq) = record
            .sources
            .iter()
            .find(|s| s.path == *path)
            .and_then(|s| s.signature.as_ref())
            .and_then(|s| s.mldsa.as_ref())
        {
            let label = if pq.verified.as_ref().is_some_and(|s| s.verified) {
                "signature.pq_verified"
            } else {
                "signature.pq_matched"
            };
            status.push_str(&format!("; {} ({})", escape(r.t(label)?), code(&pq.path)));
        }
        r.out.push_str(&format!(
            "| {} | {} | {} | {} | {status} |\n",
            code(id),
            escape(r.t(kind)?),
            code(path),
            code(hash)
        ));
    }
    r.out.push('\n');
    r.heading(2, "heading.verify")?;
    r.out.push_str(&format!(
        "{}\n",
        fill(
            r.t("verify_command")?,
            &BTreeMap::from([("command".into(), code("vettalon receipt verify-package ."))])
        )?
    ));
    Ok(r.out)
}

#[cfg(test)]
mod tests;
