//! Pure, filesystem-free parsing of a pasted vulnerability report.
//!
//! Every function here is bounded: input size, line count, per-line scan
//! window and candidate count are all capped, and all regexes are linear-time.

use std::sync::OnceLock;

use regex::Regex;

use crate::audit::cwe;

pub(crate) const INTAKE_INPUT_MAX_BYTES: usize = 256 * 1024;
pub(crate) const MAX_LINES: usize = 10_000;
pub(crate) const LINE_SCAN_BYTES: usize = 4096;
pub(crate) const MAX_CANDIDATES: usize = 50;
pub(crate) const MAX_CWES: usize = 16;

const RAW_MAX_BYTES: usize = 200;
const MAX_LINE_NO: u32 = 10_000_000;

/// Validate and normalise raw report bytes (CRLF / lone CR → LF).
pub(crate) fn normalize_input(bytes: &[u8]) -> Result<String, &'static str> {
    if bytes.len() > INTAKE_INPUT_MAX_BYTES {
        return Err("too_large");
    }
    if bytes.contains(&0) {
        return Err("nul_byte");
    }
    let s = std::str::from_utf8(bytes).map_err(|_| "not_utf8")?;
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    // A trailing newline ends the last line; it does not start another.
    if s.lines().count() > MAX_LINES {
        return Err("too_many_lines");
    }
    Ok(s)
}

/// Line ranges `(first body line idx, end exclusive)` of the recognised sections.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Sections {
    pub summary: Option<(usize, usize)>,
    pub details: Option<(usize, usize)>,
    pub poc: Option<(usize, usize)>,
    pub impact: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportFormat {
    GhsaForm,
    Markdown,
    Plain,
}

impl ReportFormat {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ReportFormat::GhsaForm => "ghsa_form",
            ReportFormat::Markdown => "markdown",
            ReportFormat::Plain => "plain",
        }
    }
}

fn heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$").expect("static regex"))
}

fn bold_heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s{0,3}\*\*([^*]+)\*\*\s*:?\s*$").expect("static regex"))
}

#[derive(Clone, Copy)]
enum Kind {
    Summary,
    Details,
    Poc,
    Impact,
}

fn classify(title: &str) -> Option<Kind> {
    let t = title
        .trim()
        .trim_matches(|c: char| c == ':' || c == '*' || c == '_' || c.is_whitespace())
        .to_ascii_lowercase();
    match t.as_str() {
        "summary" => Some(Kind::Summary),
        "details" => Some(Kind::Details),
        "poc" | "proof of concept" | "steps to reproduce" | "reproduction" => Some(Kind::Poc),
        "impact" => Some(Kind::Impact),
        _ => None,
    }
}

/// Locate report sections and classify the overall format.
pub(crate) fn sections(text: &str) -> (Sections, ReportFormat) {
    let lines: Vec<&str> = text.lines().collect();
    let mut headings: Vec<(usize, Option<Kind>)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let l = clip(line);
        let title = heading_re()
            .captures(l)
            .or_else(|| bold_heading_re().captures(l))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        if let Some(t) = title {
            headings.push((i, classify(&t)));
        }
    }
    let mut out = Sections::default();
    for (n, (idx, kind)) in headings.iter().enumerate() {
        let Some(kind) = kind else { continue };
        let end = headings.get(n + 1).map_or(lines.len(), |h| h.0);
        let range = Some((idx + 1, end));
        let slot = match kind {
            Kind::Summary => &mut out.summary,
            Kind::Details => &mut out.details,
            Kind::Poc => &mut out.poc,
            Kind::Impact => &mut out.impact,
        };
        if slot.is_none() {
            *slot = range;
        }
    }
    let present = [out.summary, out.details, out.poc, out.impact]
        .iter()
        .filter(|s| s.is_some())
        .count();
    let fmt = if present >= 3 {
        ReportFormat::GhsaForm
    } else if !headings.is_empty() {
        ReportFormat::Markdown
    } else {
        ReportFormat::Plain
    };
    (out, fmt)
}

fn cwe_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bCWE[\s:_-]?(\d{1,5})\b").expect("static regex"))
}

/// CWE ids mentioned in the text, normalised, deduped, first-seen order.
pub(crate) fn cwe_mentions(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        for m in cwe_re().find_iter(clip(line)) {
            if let Some(id) = cwe::normalize(m.as_str())
                && !out.contains(&id)
            {
                out.push(id);
                if out.len() >= MAX_CWES {
                    return out;
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    GithubUrl,
    PathRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocationToken {
    pub file: String,
    pub line: Option<u32>,
    pub origin: Origin,
    pub github_slug: Option<String>,
    pub git_ref: Option<String>,
    pub raw: String,
    pub line_idx: usize,
}

/// The match stops at a query string (`?…` may carry tokens), so a `#L`
/// fragment after a query is not read either.
fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)https://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)/blob/([^/\s#?]+)/([^\s#?)>\]'"`]+)(?:#L(\d{1,10})(?:-L?(\d{1,10}))?)?"#,
        )
        .expect("static regex")
    })
}

fn path_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)([A-Za-z0-9._/-]+)(?::(\d{1,10})|#L(\d{1,10})|,?\s+line\s+(\d{1,10}))\b")
            .expect("static regex")
    })
}

fn backtick_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"`([A-Za-z0-9._/-]+)`").expect("static regex"))
}

/// Clip to the per-line scan window on a char boundary.
fn clip(line: &str) -> &str {
    if line.len() <= LINE_SCAN_BYTES {
        return line;
    }
    let mut end = LINE_SCAN_BYTES;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    &line[..end]
}

fn truncate_raw(s: &str) -> String {
    if s.len() <= RAW_MAX_BYTES {
        return s.to_string();
    }
    let mut end = RAW_MAX_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn parse_line_no(s: &str) -> Option<u32> {
    let n: u32 = s.parse().ok()?;
    (1..=MAX_LINE_NO).contains(&n).then_some(n)
}

/// Decode `%XX` exactly once. Invalid sequences or non-UTF-8 results → None.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hi = (*b.get(i + 1)? as char).to_digit(16)?;
            let lo = (*b.get(i + 2)? as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A path-like token has a `/` (with an alphanumeric somewhere), or a final
/// segment containing a `.` followed by a non-empty part with a letter in it.
/// The part before the last `.` may be empty, so dotfiles like `.env` qualify.
fn path_like(p: &str) -> bool {
    if p.contains('/') {
        return p.chars().any(|c| c.is_ascii_alphanumeric());
    }
    match p.rsplit_once('.') {
        Some((_stem, ext)) => !ext.is_empty() && ext.chars().any(|c| c.is_ascii_alphabetic()),
        None => false,
    }
}

/// Strip only a literal leading `./`; a leading `.` of a dotfile is kept.
fn strip_dot_slash(p: &str) -> &str {
    p.strip_prefix("./").unwrap_or(p)
}

/// Extract candidate code locations. Returns `(tokens, truncated)`.
pub(crate) fn location_tokens(text: &str) -> (Vec<LocationToken>, bool) {
    let mut out: Vec<LocationToken> = Vec::new();
    let mut truncated = false;
    'lines: for (line_idx, line) in text.lines().enumerate() {
        let scan = clip(line);
        // (start, token) for this line, ordered by position afterwards.
        let mut found: Vec<(usize, LocationToken)> = Vec::new();

        for c in url_re().captures_iter(scan) {
            let whole = c.get(0).expect("group 0");
            let Some(file) = percent_decode(&c[4]) else {
                continue;
            };
            let line_no = match c.get(5) {
                Some(m) => match parse_line_no(m.as_str()) {
                    Some(n) => Some(n),
                    None => continue,
                },
                None => None,
            };
            found.push((
                whole.start(),
                LocationToken {
                    file,
                    line: line_no,
                    origin: Origin::GithubUrl,
                    github_slug: Some(format!("{}/{}", &c[1], &c[2])),
                    git_ref: Some(c[3].to_string()),
                    raw: truncate_raw(whole.as_str()),
                    line_idx,
                },
            ));
        }

        // Blank out URL matches so their paths aren't re-scanned.
        let mut masked = scan.to_string();
        for m in url_re().find_iter(scan) {
            let blank = " ".repeat(m.len());
            masked.replace_range(m.range(), &blank);
        }

        for c in path_line_re().captures_iter(&masked) {
            let whole = c.get(0).expect("group 0");
            let path = strip_dot_slash(&c[1]);
            if !path_like(path) {
                continue;
            }
            let Some(n) = c
                .get(2)
                .or_else(|| c.get(3))
                .or_else(|| c.get(4))
                .and_then(|m| parse_line_no(m.as_str()))
            else {
                continue;
            };
            found.push((
                whole.start(),
                LocationToken {
                    file: path.to_string(),
                    line: Some(n),
                    origin: Origin::PathRef,
                    github_slug: None,
                    git_ref: None,
                    raw: truncate_raw(whole.as_str()),
                    line_idx,
                },
            ));
        }

        for c in backtick_path_re().captures_iter(&masked) {
            let whole = c.get(0).expect("group 0");
            let path = strip_dot_slash(&c[1]);
            if !path_like(path) {
                continue;
            }
            found.push((
                whole.start(),
                LocationToken {
                    file: path.to_string(),
                    line: None,
                    origin: Origin::PathRef,
                    github_slug: None,
                    git_ref: None,
                    raw: truncate_raw(whole.as_str()),
                    line_idx,
                },
            ));
        }

        found.sort_by_key(|(s, _)| *s);
        for (_, tok) in found {
            if out.iter().any(|t| t.file == tok.file && t.line == tok.line) {
                continue;
            }
            if out.len() >= MAX_CANDIDATES {
                truncated = true;
                break 'lines;
            }
            out.push(tok);
        }
    }
    (out, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghsa_form_sections_and_ranges() {
        let t = "### Summary\nfoo\n### Details\nbar\nbaz\n### PoC\nrun it\n### Impact\nbad\n";
        let (s, f) = sections(t);
        assert_eq!(f, ReportFormat::GhsaForm);
        assert_eq!(f.as_str(), "ghsa_form");
        assert_eq!(s.summary, Some((1, 2)));
        assert_eq!(s.details, Some((3, 5)));
        assert_eq!(s.poc, Some((6, 7)));
        assert_eq!(s.impact, Some((8, 9)));
    }

    #[test]
    fn bold_headings_and_markdown() {
        let (s, f) = sections("**Summary**\nx\n## Other\ny\n");
        assert_eq!(f, ReportFormat::Markdown);
        assert_eq!(f.as_str(), "markdown");
        assert_eq!(s.summary, Some((1, 2)));
        assert!(s.details.is_none());
    }

    #[test]
    fn plain_text() {
        let (_, f) = sections("just some words\nand more\n");
        assert_eq!(f, ReportFormat::Plain);
        assert_eq!(f.as_str(), "plain");
    }

    #[test]
    fn normalizes_line_endings() {
        assert_eq!(normalize_input(b"a\r\nb\rc\n").unwrap(), "a\nb\nc\n");
    }

    #[test]
    fn refuses_bad_input() {
        assert_eq!(normalize_input(b"a\0b"), Err("nul_byte"));
        assert_eq!(normalize_input(&[0xff, 0xfe, b'a']), Err("not_utf8"));
        let big = vec![b'a'; INTAKE_INPUT_MAX_BYTES + 1];
        assert_eq!(normalize_input(&big), Err("too_large"));
        assert!(normalize_input(&big[..INTAKE_INPUT_MAX_BYTES]).is_ok());
        let many = "\n".repeat(MAX_LINES + 1);
        assert_eq!(normalize_input(many.as_bytes()), Err("too_many_lines"));
    }

    #[test]
    fn line_cap_ignores_a_trailing_newline() {
        let exact = "x\n".repeat(MAX_LINES);
        assert!(normalize_input(exact.as_bytes()).is_ok());
        let no_trailing = exact.trim_end_matches('\n');
        assert!(normalize_input(no_trailing.as_bytes()).is_ok());
        let crlf = "x\r\n".repeat(MAX_LINES);
        assert!(normalize_input(crlf.as_bytes()).is_ok());
        let over = "x\n".repeat(MAX_LINES + 1);
        assert_eq!(normalize_input(over.as_bytes()), Err("too_many_lines"));
        let over_unterminated = format!("{exact}x");
        assert_eq!(
            normalize_input(over_unterminated.as_bytes()),
            Err("too_many_lines")
        );
    }

    #[test]
    fn cwe_dedupe_order_cap() {
        assert_eq!(
            cwe_mentions("CWE-78 and cwe 89, CWE:78 again, CWE_22"),
            vec!["CWE-78", "CWE-89", "CWE-22"]
        );
        let many: String = (1..=20).map(|n| format!("CWE-{n} ")).collect();
        let got = cwe_mentions(&many);
        assert_eq!(got.len(), MAX_CWES);
        assert_eq!(got[0], "CWE-1");
        assert_eq!(got[15], "CWE-16");
    }

    #[test]
    fn github_url_with_range() {
        let t = "see https://github.com/acme/widget/blob/main/src/a.rs#L10-L12 now";
        let (v, tr) = location_tokens(t);
        assert!(!tr);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].file, "src/a.rs");
        assert_eq!(v[0].line, Some(10));
        assert_eq!(v[0].origin, Origin::GithubUrl);
        assert_eq!(v[0].github_slug.as_deref(), Some("acme/widget"));
        assert_eq!(v[0].git_ref.as_deref(), Some("main"));
    }

    #[test]
    fn github_url_no_line_and_percent_decode_once() {
        let (v, _) = location_tokens("https://github.com/a/b/blob/v1/lib/x.py");
        assert_eq!(v[0].line, None);
        let (v, _) = location_tokens("https://github.com/a/b/blob/v1/%2e%2e/etc/passwd#L3");
        assert_eq!(v[0].file, "../etc/passwd");
        assert_eq!(v[0].line, Some(3));
        let (v, _) = location_tokens("https://github.com/a/b/blob/v1/%252e/x.py#L3");
        assert_eq!(v[0].file, "%2e/x.py");
        let (v, _) = location_tokens("https://github.com/a/b/blob/v1/%zz/x.py#L3");
        assert!(v.is_empty());
    }

    #[test]
    fn path_shapes() {
        let (v, _) = location_tokens("src/app.py:42");
        assert_eq!((v[0].file.as_str(), v[0].line), ("src/app.py", Some(42)));
        let (v, _) = location_tokens("src/app.py#L7");
        assert_eq!(v[0].line, Some(7));
        let (v, _) = location_tokens("in ./src/app.py, line 9.");
        assert_eq!((v[0].file.as_str(), v[0].line), ("src/app.py", Some(9)));
        let (v, _) = location_tokens("at src/app.py Line 11");
        assert_eq!(v[0].line, Some(11));
        let (v, _) = location_tokens("see `lib/util.rs` here");
        assert_eq!((v[0].file.as_str(), v[0].line), ("lib/util.rs", None));
        assert_eq!(v[0].origin, Origin::PathRef);
    }

    #[test]
    fn dotfile_and_dot_dir_tokens() {
        let (v, _) = location_tokens(".env:1");
        assert_eq!((v[0].file.as_str(), v[0].line), (".env", Some(1)));
        let (v, _) = location_tokens(".npmrc:3");
        assert_eq!((v[0].file.as_str(), v[0].line), (".npmrc", Some(3)));
        let (v, _) = location_tokens("config/.env#L2");
        assert_eq!((v[0].file.as_str(), v[0].line), ("config/.env", Some(2)));
        let (v, _) = location_tokens(".github/workflows/ci.yml:5");
        assert_eq!(
            (v[0].file.as_str(), v[0].line),
            (".github/workflows/ci.yml", Some(5))
        );
    }

    #[test]
    fn line_zero_skipped() {
        let (v, _) = location_tokens("src/app.py:0 and src/b.py:10000001");
        assert!(v.is_empty());
    }

    #[test]
    fn dedupe_and_cap() {
        let (v, _) = location_tokens("a/x.py:1 a/x.py:1 a/x.py:2");
        assert_eq!(v.len(), 2);
        let t: String = (1..=51).map(|n| format!("src/f{n}.py:1\n")).collect();
        let (v, tr) = location_tokens(&t);
        assert_eq!(v.len(), MAX_CANDIDATES);
        assert!(tr);
        let t: String = (1..=50).map(|n| format!("src/f{n}.py:1\n")).collect();
        let (v, tr) = location_tokens(&t);
        assert_eq!(v.len(), 50);
        assert!(!tr);
    }

    #[test]
    fn long_line_window() {
        let line = format!("{}src/late.py:3", " ".repeat(5000));
        let (v, _) = location_tokens(&line);
        assert!(v.is_empty());
        let line = format!("src/early.py:3{}src/late.py:3", " ".repeat(5000));
        let (v, _) = location_tokens(&line);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].file, "src/early.py");
    }
}
