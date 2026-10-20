//! Semgrep rule *draft* from a human-confirmed finding (O7 follow-up).
//!
//! The draft copies the finding's sink line as a starting pattern so a reviewer
//! can generalise it and scan sibling dependencies. It is never loaded or run by
//! vettalon: the file carries `review_required: true`, a header saying so, and
//! is written create-new (an existing draft is never overwritten).

use crate::audit::schema::{Finding, FindingStatus};

fn language(file: &str) -> &'static str {
    let ext = file.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "rs" => "rust",
        "py" => "python",
        "js" | "mjs" | "cjs" | "jsx" => "javascript",
        "ts" | "tsx" | "mts" | "cts" => "typescript",
        "go" => "go",
        "java" => "java",
        "rb" => "ruby",
        "php" => "php",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" => "cpp",
        "cs" => "csharp",
        "kt" => "kotlin",
        "swift" => "swift",
        _ => "generic",
    }
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').chars().take(48).collect()
}

/// String literals become `"..."` so the pattern matches other values.
fn generalise(line: &str) -> String {
    let re = regex::Regex::new(r#""(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'"#).expect("static regex");
    re.replace_all(line.trim(), "\"...\"").into_owned()
}

/// The most specific snippet line: one containing a call, preferring the
/// reported line when the snippet is short.
fn sink_line(f: &Finding) -> Option<String> {
    let lines: Vec<&str> = f
        .snippet
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with('#'))
        .collect();
    lines
        .iter()
        .find(|l| l.contains('('))
        .or_else(|| lines.first())
        .map(|l| generalise(l))
}

/// Build the YAML draft. Only `confirmed` findings (a human triage) qualify.
pub fn draft(f: &Finding, origin: &str, today: chrono::NaiveDate) -> Result<String, String> {
    if f.status != FindingStatus::Confirmed {
        return Err(crate::tr!(
            "只有人工確認（confirmed）的 finding 能轉成規則草稿；{} 目前是 {:?}",
            "only a human-confirmed finding can become a rule draft; {} is {:?}",
            f.id,
            f.status
        ));
    }
    let pattern = sink_line(f).ok_or_else(|| {
        crate::tr!(
            "finding {} 沒有可用的程式片段",
            "finding {} has no usable code snippet",
            f.id
        )
    })?;
    let q = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into());
    let severity = match f.severity.as_str() {
        "critical" | "high" => "ERROR",
        "medium" => "WARNING",
        _ => "INFO",
    };
    let id = format!("vettalon-draft-{}-{}", slug(&f.title), slug(&f.id));
    let mut yaml = String::new();
    yaml.push_str("# VETTALON SEMGREP RULE DRAFT - HUMAN REVIEW REQUIRED BEFORE USE.\n");
    let one_line = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    };
    yaml.push_str(&format!(
        "# Generated {today} from confirmed finding {} ({}).\n",
        one_line(&f.id),
        one_line(origin)
    ));
    yaml.push_str(
        "# The pattern is the finding's sink line with string literals generalised.\n\
         # It is probably too narrow (or too broad): rewrite it with metavariables,\n\
         # add pattern-inside / pattern-not for the guard the fix introduced, and test\n\
         # it on the vulnerable and fixed versions. vettalon never loads this file.\n",
    );
    yaml.push_str("rules:\n");
    yaml.push_str(&format!("  - id: {id}\n"));
    yaml.push_str(&format!(
        "    message: {}\n",
        q(&format!(
            "Possible variant of {} ({}). Draft rule: review before use.",
            f.title,
            f.cwe.as_deref().unwrap_or("no CWE")
        ))
    ));
    yaml.push_str(&format!("    severity: {severity}\n"));
    yaml.push_str(&format!("    languages: [{}]\n", language(&f.file)));
    yaml.push_str("    metadata:\n");
    yaml.push_str("      vettalon_draft: true\n");
    yaml.push_str("      review_required: true\n");
    yaml.push_str(&format!("      source_finding: {}\n", q(&f.id)));
    yaml.push_str(&format!("      source_origin: {}\n", q(origin)));
    yaml.push_str(&format!(
        "      source_location: {}\n",
        q(&format!(
            "{}{}",
            f.file,
            f.line.map(|l| format!(":{l}")).unwrap_or_default()
        ))
    ));
    if let Some(cwe) = &f.cwe {
        yaml.push_str(&format!("      cwe: {}\n", q(cwe)));
    }
    yaml.push_str("    pattern: |\n");
    yaml.push_str(&format!("      {pattern}\n"));
    Ok(yaml)
}

/// Write a draft create-new (never overwrite) with private permissions.
pub fn write_new(path: &std::path::Path, yaml: &str) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| {
        crate::tr!(
            "無法建立 {}（不覆寫既有檔案）：{e}",
            "cannot create {} (existing files are never overwritten): {e}",
            path.display()
        )
    })?;
    file.write_all(yaml.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, Severity};

    fn confirmed() -> Finding {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "Unescaped attribute in clean_html",
            "src/lib.rs",
            Some(42),
            "// sink\nlet out = builder.attr(\"href\", value);\n",
            "ai-audit/xss",
            vec![],
        );
        f.status = FindingStatus::Confirmed;
        f.cwe = Some("CWE-79".into());
        f
    }

    #[test]
    fn draft_is_valid_yaml_flagged_for_review_and_generalised() {
        let f = confirmed();
        let y = draft(
            &f,
            "ammonia@4.0.0",
            chrono::NaiveDate::from_ymd_opt(2026, 10, 20).unwrap(),
        )
        .unwrap();
        let docs = yaml_rust2::YamlLoader::load_from_str(&y).unwrap();
        let rule = &docs[0]["rules"][0];
        assert_eq!(rule["languages"][0].as_str(), Some("rust"));
        assert_eq!(rule["severity"].as_str(), Some("ERROR"));
        assert_eq!(rule["metadata"]["review_required"].as_bool(), Some(true));
        assert_eq!(rule["metadata"]["cwe"].as_str(), Some("CWE-79"));
        assert_eq!(
            rule["pattern"].as_str().unwrap().trim(),
            "let out = builder.attr(\"...\", value);"
        );
        assert!(y.starts_with("# VETTALON SEMGREP RULE DRAFT - HUMAN REVIEW REQUIRED"));
    }

    #[test]
    fn only_confirmed_findings_qualify_and_injection_cannot_break_yaml() {
        let mut f = confirmed();
        f.status = FindingStatus::NeedsHuman;
        assert!(
            draft(
                &f,
                "x",
                chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()
            )
            .is_err()
        );
        let mut f = confirmed();
        f.title = "x\"\nrules: []\n# ".into();
        let y = draft(
            &f,
            "x",
            chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
        )
        .unwrap();
        let docs = yaml_rust2::YamlLoader::load_from_str(&y).unwrap();
        assert_eq!(docs[0]["rules"].as_vec().unwrap().len(), 1);
    }

    #[test]
    fn write_new_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("d/rule.yaml");
        write_new(&p, "a").unwrap();
        assert!(write_new(&p, "b").is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "a");
    }
}
