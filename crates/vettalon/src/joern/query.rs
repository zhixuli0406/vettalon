//! Parameters in, results out: the only data that crosses into and out of
//! the Joern container. Pure, so the injection rules are unit-tested.
//!
//! Nothing here builds Scala. The template ([`super::TEMPLATE`]) is fixed;
//! parameters go into a separate tab-separated file the template reads as
//! data. Every parameter is still checked against a whitelist before it is
//! written, so a hostile claim cannot add a line, a field or a path outside
//! the mounted source tree.

use std::collections::BTreeMap;

use serde::Serialize;

use super::JoernLang;
use super::sources::{SourcePattern, sources_for};

pub const PARAMS_HEADER: &str = "vettalon-joern-params\t1";
pub const RESULT_HEADER: &str = "vettalon-joern-result\t1";
/// Longest claimed path accepted (bytes).
pub const MAX_FILE_BYTES: usize = 512;
/// Highest claimed line accepted.
pub const MAX_LINE: u32 = 9_999_999;
/// Most queries in one container run.
pub const MAX_QUERIES: usize = 10_000;
/// Path steps kept per query (the template writes at most 12).
pub const MAX_STEPS: usize = 12;
/// Longest code/file text kept from one step (bytes).
pub const MAX_STEP_TEXT: usize = 160;

/// One validated "is there a source→sink path to this line" question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepQuery {
    pub id: usize,
    pub file: String,
    pub line: u32,
}

fn file_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._/@+~ ()[]-".contains(c)
}

/// A claimed file is accepted only as a plain relative path under the
/// source root, made of a small character whitelist (no tab, newline,
/// quote, `$`, backtick, `;`, `\`, `..` component or leading `/`).
pub fn validate_file(file: &str) -> Result<String, String> {
    if file.is_empty() || file.len() > MAX_FILE_BYTES {
        return Err("claimed file is empty or too long".into());
    }
    if let Some(c) = file.chars().find(|c| !file_char_ok(*c)) {
        return Err(format!(
            "claimed file has a character outside the whitelist (U+{:04X})",
            c as u32
        ));
    }
    if file.starts_with('/') {
        return Err("claimed file is absolute".into());
    }
    if file.split('/').any(|p| p == ".." || p.is_empty()) {
        return Err("claimed file has an empty or `..` component".into());
    }
    let trimmed = file.strip_prefix("./").unwrap_or(file);
    Ok(trimmed.to_string())
}

pub fn validate_line(line: u32) -> Result<u32, String> {
    if line == 0 || line > MAX_LINE {
        return Err(format!("claimed line {line} is out of range"));
    }
    Ok(line)
}

/// Build a query from a claim's raw location, or say why it cannot be asked.
pub fn query(id: usize, file: &str, line: Option<u32>) -> Result<KeepQuery, String> {
    let file = validate_file(file)?;
    let line = validate_line(line.ok_or("claim has no line")?)?;
    Ok(KeepQuery { id, file, line })
}

fn source_line(s: &SourcePattern) -> String {
    format!("source\t{}\t{}", s.kind.token(), s.pattern)
}

/// The params file for one run. Rechecks every query (a [`KeepQuery`] built
/// by hand bypasses [`query`]).
pub fn render_params(lang: JoernLang, queries: &[KeepQuery]) -> Result<String, String> {
    if queries.is_empty() || queries.len() > MAX_QUERIES {
        return Err(format!(
            "{} queries (1-{MAX_QUERIES} allowed)",
            queries.len()
        ));
    }
    let mut out = String::new();
    out.push_str(PARAMS_HEADER);
    out.push('\n');
    out.push_str(&format!("lang\t{}\n", lang.token()));
    for s in sources_for(lang) {
        out.push_str(&source_line(s));
        out.push('\n');
    }
    for q in queries {
        let file = validate_file(&q.file)?;
        let line = validate_line(q.line)?;
        out.push_str(&format!("query\t{}\t{file}\t{line}\n", q.id));
    }
    Ok(out)
}

/// One step of a reported path (untrusted text from the analysed code,
/// sanitized and capped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathStep {
    pub file: String,
    pub line: Option<u32>,
    pub code: String,
}

/// What the template reported for one query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QueryOutcome {
    /// At least one data-flow path from a fixed source to a call on the
    /// claimed line. `strict_flows` counts the paths with no hop between two
    /// arguments of the same non-operator call; `steps` is the shortest
    /// strict path when there is one, else the shortest path, capped.
    Path {
        flows: usize,
        strict_flows: usize,
        steps: Vec<PathStep>,
    },
    /// The claimed line has calls, and no path reaches them.
    NoPath,
    /// No call on the claimed line in the CPG (nothing to ask about).
    NoSink,
    /// The claimed file is not in the CPG (missing, unreadable, not
    /// parsed). Callers treat it as an error, never as an answer.
    NoFile,
}

/// Parsed result file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    /// Source nodes the patterns matched in the whole CPG.
    pub source_nodes: usize,
    pub outcomes: BTreeMap<usize, QueryOutcome>,
}

/// Untrusted text from the container: control characters become spaces,
/// capped at [`MAX_STEP_TEXT`] bytes.
pub fn clean_text(s: &str) -> String {
    let flat: String = s
        .chars()
        .map(|c| {
            if c.is_control() || invisible_format(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    crate::util::truncate_bytes(&flat, MAX_STEP_TEXT).to_string()
}

/// Bidi controls and zero-width characters (Trojan Source style) that could
/// make a reported path read differently from what it is.
fn invisible_format(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{061C}')
}

fn num<T: std::str::FromStr>(s: &str, what: &str) -> Result<T, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || s.len() > 9 {
        return Err(format!("bad {what} in Joern result"));
    }
    s.parse().map_err(|_| format!("bad {what} in Joern result"))
}

/// Strictly parse the template's result file. Every expected query must be
/// answered exactly once and nothing else may appear; any deviation is an
/// error (which the caller turns into "no effect").
pub fn parse_result(text: &str, expected: &[usize]) -> Result<RunResult, String> {
    let mut lines = text.lines();
    if lines.next() != Some(RESULT_HEADER) {
        return Err("Joern result has no header".into());
    }
    let mut source_nodes = None;
    let mut outcomes: BTreeMap<usize, QueryOutcome> = BTreeMap::new();
    let mut done = false;
    for line in lines {
        if done {
            return Err("Joern result has lines after `done`".into());
        }
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["sources", n] if source_nodes.is_none() && outcomes.is_empty() => {
                source_nodes = Some(num::<usize>(n, "source count")?);
            }
            ["query", id, status, flows, strict] => {
                let id = num::<usize>(id, "query id")?;
                if !expected.contains(&id) || outcomes.contains_key(&id) {
                    return Err(format!("unexpected or repeated query {id} in Joern result"));
                }
                let flows = num::<usize>(flows, "flow count")?;
                let strict_flows = num::<usize>(strict, "strict flow count")?;
                let o = match *status {
                    "path" if flows > 0 && strict_flows <= flows => QueryOutcome::Path {
                        flows,
                        strict_flows,
                        steps: Vec::new(),
                    },
                    "no_path" if flows == 0 && strict_flows == 0 => QueryOutcome::NoPath,
                    "no_sink" if flows == 0 && strict_flows == 0 => QueryOutcome::NoSink,
                    "no_file" if flows == 0 && strict_flows == 0 => QueryOutcome::NoFile,
                    _ => return Err("bad query status in Joern result".into()),
                };
                outcomes.insert(id, o);
            }
            ["step", id, k, file, line, code] => {
                let id = num::<usize>(id, "query id")?;
                let k = num::<usize>(k, "step index")?;
                let line = match *line {
                    "-" => None,
                    l => Some(num::<u32>(l, "step line")?),
                };
                match outcomes.get_mut(&id) {
                    Some(QueryOutcome::Path { steps, .. }) if steps.len() == k && k < MAX_STEPS => {
                        steps.push(PathStep {
                            file: clean_text(file),
                            line,
                            code: clean_text(code),
                        })
                    }
                    _ => return Err("step out of order in Joern result".into()),
                }
            }
            ["done"] => done = true,
            _ => return Err("unrecognized line in Joern result".into()),
        }
    }
    if !done {
        return Err("Joern result is truncated (no `done`)".into());
    }
    if let Some(missing) = expected.iter().find(|id| !outcomes.contains_key(id)) {
        return Err(format!("Joern result misses query {missing}"));
    }
    for o in outcomes.values() {
        if let QueryOutcome::Path { steps, .. } = o
            && steps.is_empty()
        {
            return Err("Joern path without steps".into());
        }
    }
    Ok(RunResult {
        source_nodes: source_nodes.ok_or("Joern result has no source count")?,
        outcomes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_relative_paths_are_accepted() {
        for ok in [
            "src/app.php",
            "./web/index.php",
            "app/[id]/page.tsx",
            "a b/c-d_e.f+g@h~(i).js",
        ] {
            assert!(validate_file(ok).is_ok(), "{ok}");
        }
        assert_eq!(validate_file("./x/y.py").unwrap(), "x/y.py");
    }

    #[test]
    fn injection_attempts_in_the_file_are_refused() {
        for bad in [
            "",
            "/etc/passwd",
            "../outside.php",
            "a/../../b.php",
            "a//b.php",
            "a\tb.php",
            "a.php\nquery\t9\tx.php\t1",
            "a.php\rsource\tcall_name\t.*",
            "x\"; sys.exit(1); \".php",
            "x$(id).php",
            "x`id`.php",
            "x;rm -rf.php",
            "x\\y.php",
            "x'.php",
            "x{}.scala",
            "日本語.php",
            "x\u{0}.php",
            &"a".repeat(MAX_FILE_BYTES + 1),
        ] {
            assert!(validate_file(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn lines_are_range_checked() {
        assert!(validate_line(0).is_err());
        assert!(validate_line(MAX_LINE + 1).is_err());
        assert_eq!(validate_line(42).unwrap(), 42);
        assert!(query(0, "a.php", None).is_err());
    }

    #[test]
    fn params_hold_fixed_sources_and_validated_queries_only() {
        let qs = vec![query(0, "src/a.php", Some(3)).unwrap()];
        let text = render_params(JoernLang::Php, &qs).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some(PARAMS_HEADER));
        assert_eq!(lines.next(), Some("lang\tphp"));
        let rest: Vec<&str> = lines.collect();
        assert_eq!(rest.last(), Some(&"query\t0\tsrc/a.php\t3"));
        assert_eq!(
            rest.iter().filter(|l| l.starts_with("source\t")).count(),
            sources_for(JoernLang::Php).len()
        );
        // Every line has the field count the template expects.
        for l in rest {
            let n = l.split('\t').count();
            assert!(
                (l.starts_with("source\t") && n == 3) || (l.starts_with("query\t") && n == 4),
                "{l:?}"
            );
        }
    }

    #[test]
    fn hand_built_hostile_queries_are_refused_at_render() {
        let hostile = KeepQuery {
            id: 0,
            file: "a.php\nlang\tjava".into(),
            line: 1,
        };
        assert!(render_params(JoernLang::Php, &[hostile]).is_err());
        let zero = KeepQuery {
            id: 0,
            file: "a.php".into(),
            line: 0,
        };
        assert!(render_params(JoernLang::Php, &[zero]).is_err());
        assert!(render_params(JoernLang::Php, &[]).is_err());
    }

    fn ok_result() -> String {
        format!(
            "{RESULT_HEADER}\nsources\t4\nquery\t0\tpath\t2\t1\nstep\t0\t0\tsrc/a.php\t2\t$_GET['q']\nstep\t0\t1\tsrc/a.php\t3\tmysqli_query($c, $q)\nquery\t1\tno_path\t0\t0\nquery\t2\tno_sink\t0\t0\ndone\n"
        )
    }

    #[test]
    fn result_is_parsed_strictly() {
        let r = parse_result(&ok_result(), &[0, 1, 2]).unwrap();
        assert_eq!(r.source_nodes, 4);
        match &r.outcomes[&0] {
            QueryOutcome::Path {
                flows,
                strict_flows,
                steps,
            } => {
                assert_eq!((*flows, *strict_flows), (2, 1));
                assert_eq!(steps.len(), 2);
                assert_eq!(steps[1].line, Some(3));
            }
            o => panic!("{o:?}"),
        }
        assert_eq!(r.outcomes[&1], QueryOutcome::NoPath);
        assert_eq!(r.outcomes[&2], QueryOutcome::NoSink);
        let nf = ok_result().replace("query\t2\tno_sink", "query\t2\tno_file");
        assert_eq!(
            parse_result(&nf, &[0, 1, 2]).unwrap().outcomes[&2],
            QueryOutcome::NoFile
        );
    }

    #[test]
    fn malformed_results_are_errors() {
        let good = ok_result();
        let cases = [
            good.replace(RESULT_HEADER, "x"),
            good.replace("done\n", ""),
            good.clone() + "query\t3\tpath\t1\t1\n",
            good.replace("query\t1\tno_path\t0\t0", "query\t1\tpath\t0\t0"),
            good.replace("query\t2\tno_sink\t0\t0\n", ""),
            good.replace("step\t0\t1", "step\t0\t5"),
            good.replace("query\t1\tno_path\t0\t0", "query\t0\tno_path\t0\t0"),
            good.replace("sources\t4", "sources\t-1"),
            good.replace("\tpath\t2\t1\n", "\tpath\t2\t1\textra\n"),
            good.replace("\tpath\t2\t1\n", "\tpath\t2\t3\n"),
            good.replace("\tpath\t2\t1\n", "\tpath\t2\n"),
        ];
        for c in cases {
            assert!(parse_result(&c, &[0, 1, 2]).is_err(), "{c:?}");
        }
        // A query id the run was not asked about.
        assert!(parse_result(&good, &[0, 1]).is_err());
    }

    #[test]
    fn untrusted_step_text_is_flattened_and_capped() {
        assert_eq!(clean_text("a\u{1b}[31mb\u{7}"), "a [31mb ");
        assert!(clean_text(&"x".repeat(1000)).len() <= MAX_STEP_TEXT);
        assert_eq!(clean_text("a\u{202E}b\u{2066}c\u{200B}"), "a b c ");
    }
}
