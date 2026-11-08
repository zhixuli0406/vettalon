//! Static text rules TC001–TC005, TC007–TC009 and TC013 (`tc-rules-2`).
//!
//! Regex and structure based, deliberately conservative. A clean result
//! means "no rule matched", not "safe". TC006, TC010, TC011 and TC012 come
//! from [`super::content`]; MC rules from [`super::mcp`] and [`super::npm`].

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::RawFinding;
use crate::audit::schema::Severity;
use crate::guard::input_guard::{DEFAULT_BLOCK_THRESHOLD, scan_input};
use crate::guard::unicode_normalizer::UnicodeNormalizer;

/// At most this many findings of one rule per file.
const MAX_PER_RULE_FILE: usize = 25;
/// Lines inspected when locating a whole-text injection match.
const MAX_LOCATE_LINES: usize = 5_000;

struct LineRule {
    rule: &'static str,
    severity: Severity,
    message: &'static str,
    re: Regex,
    keep: fn(&str, &regex::Match<'_>) -> bool,
}

fn always(_: &str, _: &regex::Match<'_>) -> bool {
    true
}

const SHELLS: &str = r"(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+)?(?:/usr/bin/|/bin/|/usr/local/bin/)?(?:ba|z|k|da|fi|c|tc)?sh|python[0-9.]*|node|perl|ruby|php|pwsh|powershell";

static LINE_RULES: LazyLock<Vec<LineRule>> = LazyLock::new(|| {
    let r = |p: &str| Regex::new(p).expect("static toolchain rule");
    vec![
        // TC001 fetch-and-execute
        LineRule {
            rule: "TC001",
            severity: Severity::High,
            message: "download piped into an interpreter (fetch-and-execute)",
            re: r(&format!(
                r"(?i)\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:{SHELLS})\b"
            )),
            keep: executes_download,
        },
        LineRule {
            rule: "TC001",
            severity: Severity::High,
            message: "download substituted into an interpreter (fetch-and-execute)",
            re: r(
                r#"(?i)(?:\b(?:ba|z|k)?sh|\bsource|(?:^|[\s;&|])\.)\s+(?:-s\s+)?<\(\s*(?:curl|wget)\b"#,
            ),
            keep: always,
        },
        LineRule {
            rule: "TC001",
            severity: Severity::High,
            message: "download substituted into an interpreter (fetch-and-execute)",
            re: r(
                r#"(?i)\b(?:eval|(?:ba|z|k)?sh\s+-c|python[0-9.]*\s+-c|node\s+-e|perl\s+-e|ruby\s+-e)\s+["']?(?:\$\(|`)\s*(?:curl|wget)\b"#,
            ),
            keep: always,
        },
        LineRule {
            rule: "TC001",
            severity: Severity::High,
            message: "PowerShell download executed with Invoke-Expression",
            re: r(
                r"(?i)\b(?:iex|invoke-expression)\b\s*\(?\s*\(?\s*(?:iwr|irm|invoke-webrequest|invoke-restmethod|new-object\s+(?:system\.)?net\.webclient)\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*(?:iex|invoke-expression)\b",
            ),
            keep: always,
        },
        // TC002 encoded payload executed
        LineRule {
            rule: "TC002",
            severity: Severity::High,
            message: "base64-decoded data is executed",
            re: r(&format!(
                r"(?i)\bbase64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*(?:{SHELLS})\b"
            )),
            keep: always,
        },
        LineRule {
            rule: "TC002",
            severity: Severity::High,
            message: "base64-decoded data is executed",
            re: r(
                r#"(?i)(?:\beval\b|\bexec\b|\bnew\s+Function\b|\b(?:ba|z)?sh\s+-c\b)[^\n]{0,80}(?:\batob\s*\(|\bbase64\s+(?:-d|--decode)\b|\bb64decode\s*\(|Buffer\.from\([^)]*['"]base64['"])"#,
            ),
            keep: always,
        },
        // TC003 exfiltration endpoint
        LineRule {
            rule: "TC003",
            severity: Severity::High,
            message: "known exfiltration / paste / tunnel endpoint",
            re: r(
                r"(?i)(?:api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|\bwebhook\.site\b|\brequestbin\b|\bpipedream\.net\b|\bngrok(?:-free)?\.(?:io|app|dev)\b|\bpastebin\.com\b|\bpaste\.ee\b|\bhastebin\.com\b|\bghostbin\.|\brentry\.co\b|\b0x0\.st\b|\btransfer\.sh\b|\btermbin\.com\b|\bdpaste\.(?:org|com)\b)",
            ),
            keep: always,
        },
        LineRule {
            rule: "TC003",
            severity: Severity::High,
            message: "URL to a raw public IPv4 address",
            re: r(r"(?i)\b(?:https?|ftp|wss?)://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"),
            keep: public_ipv4,
        },
        // TC004 persistence
        LineRule {
            rule: "TC004",
            severity: Severity::High,
            message: "installs persistence (cron / launchd / systemd / shell rc / SSH keys)",
            re: r(
                r#"(?i)(?:\bcrontab\s+(?:-[elr]\b|["']?(?:[~./\w-]+\.(?:cron|txt)|[~./\w-]+)(?:["']?)(?:\s|$))|\|\s*crontab\s+-|\blaunchctl\s+(?:load|bootstrap|enable)\b|\bsystemctl\s+--user\s+enable\b|(?:>>|\btee\s+-a)\s*["']?(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|bash_profile|profile|zshrc)\b|(?:>>?|\btee(?:\s+-a)?|\bcp|\bmv|\binstall)\s+[^\n;|]*(?:Library/Launch(?:Agents|Daemons)/|authorized_keys\b))"#,
            ),
            keep: always,
        },
        // TC005 credential access
        LineRule {
            rule: "TC005",
            severity: Severity::High,
            message: "reads credentials (SSH keys, cloud/agent tokens, browser cookies, keychain)",
            re: r(
                r#"(?i)(?:~[/\\]\.ssh[/\\]id_[a-z0-9_*?-]+|\.ssh[/\\]id_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials\b|\.config/gcloud/[^\s"'`]+|\.claude/\.credentials\b|\.codex/auth\.json\b|Library/Cookies/Cookies\.binarycookies\b|\bcookies\.sqlite\b|(?:Google/Chrome|BraveSoftware|Microsoft Edge|Chromium)/[^\n"'`]{0,160}/Cookies\b|\bLogin Data\b|\bkey4\.db\b|\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain)\b)"#,
            ),
            keep: always,
        },
        // TC013 remote self-overwrite
        LineRule {
            rule: "TC013",
            severity: Severity::Medium,
            message: "downloads content over the skill's own instruction files (publisher can change instructions outside marketplace review; pin the skill to detect changes)",
            re: r(
                r#"(?i)\b(?:curl|wget)\b[^\n]*?(?:>>?|\|\s*tee(?:\s+-a)?|\s(?:-o|-O|--output|--output-document)[\s=])\s*["']?(?:[^\s"'|;&:]*SKILL\.md\b|\$\{?SKILL_DIR\b|(?:[^\s"'|;&:]*/)?references/[^\s"'|;&:]*\.md\b)"#,
            ),
            keep: always,
        },
    ]
});

/// Interpreter flags that make the piped download *data* for inline code
/// (`curl … | python3 -c "…"`, `| node -e '…'`), not the program itself.
static INLINE_CODE_FLAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s+(?:-c|-e|-E|-pe|-ne|-m\s+json\.tool)(?:\s|$|[\x22'])").expect("static flag")
});

/// TC001 pipe rule: `curl … | python3 -c '…'` and friends parse data.
fn executes_download(line: &str, m: &regex::Match<'_>) -> bool {
    let word = m
        .as_str()
        .rsplit(|c: char| c.is_whitespace() || c == '|' || c == '/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let scripting =
        word.starts_with("python") || matches!(word.as_str(), "node" | "perl" | "ruby" | "php");
    !(scripting && INLINE_CODE_FLAG_RE.is_match(&line[m.end()..]))
}

fn public_ipv4(_: &str, m: &regex::Match<'_>) -> bool {
    let digits = m
        .as_str()
        .rsplit("//")
        .next()
        .unwrap_or("")
        .split('.')
        .map(|o| o.parse::<u16>().unwrap_or(999))
        .collect::<Vec<_>>();
    let [a, b, ..] = digits[..] else {
        return false;
    };
    if digits.iter().any(|o| *o > 255) {
        return false;
    }
    let local =
        matches!(a, 0 | 10 | 127) || (a == 192 && b == 168) || (a == 172 && (16..=31).contains(&b));
    !local
}

fn path_in(file: &Path, dirs: &[&str]) -> bool {
    file.parent().is_some_and(|p| {
        p.components().any(|c| {
            dirs.iter()
                .any(|d| c.as_os_str().to_string_lossy().eq_ignore_ascii_case(d))
        })
    })
}

const TEST_DIRS: &[&str] = &[
    "evals",
    "eval",
    "tests",
    "test",
    "__tests__",
    "fixtures",
    "examples",
];

fn file_name_lower(file: &Path) -> String {
    file.file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Test, eval, fixture and example material: findings are informational.
fn is_test_path(file: &Path) -> bool {
    let name = file_name_lower(file);
    path_in(file, TEST_DIRS)
        || name.contains(".test.")
        || name.contains("_test.")
        || name.starts_with("test_")
}

/// Reference documentation: findings are at most medium.
fn is_doc_path(file: &Path) -> bool {
    let name = file_name_lower(file);
    path_in(file, &["references", "docs"])
        || name.starts_with("readme")
        || name.starts_with("changelog")
}

fn is_comment_in_source(file: &Path, line: &str) -> bool {
    let source = file.extension().is_some_and(|e| {
        matches!(
            e.to_string_lossy().to_ascii_lowercase().as_str(),
            "js" | "mjs" | "ts" | "py" | "rs" | "go" | "sh"
        )
    });
    let t = line.trim();
    source
        && (t.starts_with("//") || t.starts_with('#') || (t.starts_with("/*") && t.ends_with("*/")))
}

static NEGATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:\b(?:never|don['’]t|do not|avoid|must not|should not)\b|(?:^|[\s*_(>])no\s|不要|不得|禁止|切勿|避免|絕不|绝不|不可)",
    )
    .expect("static negation marker")
});

static EXAMPLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:\bexamples?\b|red flags?|malicious patterns?|dangerous|範例|示例|危險|恶意|惡意)",
    )
    .expect("static example marker")
});

fn is_list_item(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("- ")
        || t.starts_with("* ")
        || t.starts_with("+ ")
        || t.split_once(['.', ')']).is_some_and(|(n, rest)| {
            !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && rest.starts_with(' ')
        })
}

/// The line, or for a list item the introducing (non-list) line above it,
/// carries a negation / defensive marker.
fn is_negated(lines: &[&str], i: usize) -> bool {
    NEGATION_RE.is_match(lines[i])
        || (i > 0
            && is_list_item(lines[i])
            && !is_list_item(lines[i - 1])
            && NEGATION_RE.is_match(lines[i - 1]))
}

/// Per line: inside a fenced block opened within 3 lines after an
/// "example" / "red flag" / "dangerous" heading or line.
fn example_fences(lines: &[&str]) -> Vec<bool> {
    let mut out = vec![false; lines.len()];
    let mut open: Option<bool> = None;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            open = match open {
                Some(_) => None,
                None => Some(
                    lines[i.saturating_sub(3)..i]
                        .iter()
                        .any(|l| EXAMPLE_RE.is_match(l)),
                ),
            };
        } else if open == Some(true) {
            out[i] = true;
        }
    }
    out
}

/// Octets of the host of an `http(s)://a.b.c.d` match.
fn url_octets(m: &str) -> Vec<u16> {
    m.rsplit("//")
        .next()
        .unwrap_or("")
        .split('.')
        .map(|o| o.parse::<u16>().unwrap_or(999))
        .collect()
}

static PLACEHOLDER_HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:abc\d*|x{3,}|1234\w*|example\w*|your[-_]?\w*|my[-_]?\w*|foo|bar|demo|sample|test\w*|subdomain|random\w*|[a-f0-9]{0,2}x{3,}\w*)$",
    )
    .expect("static placeholder host")
});

/// TC003 matches that are documentation / placeholder values: documentation
/// and shared-address-space IPv4 anywhere, the cloud metadata address and
/// example ngrok hosts in reference documentation.
fn tc003_low(line: &str, m: &regex::Match<'_>, docs: bool) -> bool {
    let text = m.as_str();
    if text.contains("://") {
        let o = url_octets(text);
        return match o[..] {
            [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => true,
            [100, b, _, _] => (64..=127).contains(&b),
            [169, 254, 169, 254] => docs,
            _ => false,
        };
    }
    if !docs || !text.to_ascii_lowercase().starts_with("ngrok") {
        return false;
    }
    let before = line[..m.start()].strip_suffix('.').unwrap_or("");
    let label: String = before
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    !label.is_empty() && PLACEHOLDER_HOST_RE.is_match(&label)
}

/// `None` when the rule does not fire on `line`; otherwise whether every
/// kept match is a documentation / placeholder value.
fn rule_hit(rule: &LineRule, line: &str, docs: bool) -> Option<bool> {
    let mut hit = false;
    let mut all_low = true;
    for m in rule.re.find_iter(line) {
        if !(rule.keep)(line, &m) {
            continue;
        }
        hit = true;
        all_low &= rule.rule == "TC003" && tc003_low(line, &m, docs);
    }
    hit.then_some(all_low)
}

/// Collects findings with per-file dedupe and caps.
pub struct Sink<'a> {
    pub out: &'a mut Vec<RawFinding>,
    seen: HashSet<(&'static str, Option<usize>)>,
    counts: std::collections::HashMap<&'static str, usize>,
}

impl<'a> Sink<'a> {
    pub fn new(out: &'a mut Vec<RawFinding>) -> Self {
        Sink {
            out,
            seen: HashSet::new(),
            counts: Default::default(),
        }
    }

    fn push(&mut self, f: RawFinding) {
        let n = self.counts.entry(f.rule).or_default();
        if *n >= MAX_PER_RULE_FILE || !self.seen.insert((f.rule, f.line)) {
            return;
        }
        *n += 1;
        self.out.push(f);
    }
}

/// TC001–TC005 over each line of `text` (line numbers start at `first_line`).
fn line_rules(
    file: Option<&Path>,
    ctx: Option<&Path>,
    first_line: usize,
    text: &str,
    sink: &mut Sink<'_>,
) {
    let lines: Vec<&str> = text.lines().collect();
    let example = example_fences(&lines);
    let docs = ctx.is_some_and(is_doc_path);
    for (i, line) in lines.iter().enumerate() {
        for rule in LINE_RULES.iter() {
            let Some(low) = rule_hit(rule, line, docs) else {
                continue;
            };
            let mut severity = rule.severity;
            if low {
                severity = severity.min(Severity::Low);
            }
            if let Some(f) = ctx {
                if is_test_path(f) || is_negated(&lines, i) {
                    severity = Severity::Info;
                } else {
                    if docs || is_comment_in_source(f, line) {
                        severity = severity.min(Severity::Medium);
                    }
                    if example[i] && matches!(rule.rule, "TC002" | "TC005") {
                        severity = severity.min(Severity::Medium);
                    }
                }
            }
            sink.push(RawFinding::new(
                rule.rule,
                severity,
                file,
                Some(first_line + i),
                rule.message,
                line,
            ));
        }
    }
}

/// Every text rule for one skill/plugin file.
pub fn scan_text(file: &Path, text: &str, instruction: bool, out: &mut Vec<RawFinding>) {
    scan_text_in(file, file, text, instruction, out);
}

/// Like [`scan_text`], but path-based severity context (tests, docs, source
/// comments) is judged on `rel`, the path inside the item, so directories
/// above the item cannot change a severity.
pub fn scan_text_in(
    file: &Path,
    rel: &Path,
    text: &str,
    instruction: bool,
    out: &mut Vec<RawFinding>,
) {
    let mut sink = Sink::new(out);
    line_rules(Some(file), Some(rel), 1, text, &mut sink);
    hidden_chars(file, text, &mut sink);
    if instruction {
        base64_runs(file, text, &mut sink);
        prerequisite_trap(file, text, &mut sink);
        let (front, body_start) = split_frontmatter(text);
        if let Some(desc) = front.as_ref().and_then(|f| f.description.as_ref()) {
            injection(Some(file), desc.1, &desc.0, true, &mut sink);
        }
        let body: String = text
            .lines()
            .skip(body_start.saturating_sub(1))
            .collect::<Vec<_>>()
            .join("\n");
        injection(Some(file), body_start, &body, true, &mut sink);
    }
}

/// TC001–TC005 for a hook command or an MCP command line (already redacted).
pub fn scan_command(
    file: Option<&Path>,
    line: Option<usize>,
    command: &str,
    out: &mut Vec<RawFinding>,
) {
    let mut sink = Sink::new(out);
    let flat = command.replace(['\n', '\r'], " ");
    for rule in LINE_RULES.iter() {
        if let Some(low) = rule_hit(rule, &flat, false) {
            sink.push(RawFinding::new(
                rule.rule,
                if low {
                    rule.severity.min(Severity::Low)
                } else {
                    rule.severity
                },
                file,
                line,
                rule.message,
                &flat,
            ));
        }
    }
}

/// TC007 only, for manifests whose strings are checked structurally.
pub fn scan_hidden(file: &Path, text: &str, out: &mut Vec<RawFinding>) {
    let mut sink = Sink::new(out);
    hidden_chars(file, text, &mut sink);
}

/// TC008 for a tool/plugin description from a manifest.
pub fn scan_description(file: &Path, line: Option<usize>, text: &str, out: &mut Vec<RawFinding>) {
    let mut sink = Sink::new(out);
    injection(Some(file), line.unwrap_or(1), text, false, &mut sink);
}

// ── TC002 base64 runs ────────────────────────────────────────────────────

static BASE64_RUN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{200,}={0,2}").expect("static base64 run"));

fn base64_runs(file: &Path, text: &str, sink: &mut Sink<'_>) {
    for (i, line) in text.lines().enumerate() {
        let Some(m) = BASE64_RUN_RE.find(line) else {
            continue;
        };
        let before = &line[..m.start()];
        let mixed = m.as_str().bytes().any(|b| b.is_ascii_digit())
            && m.as_str().bytes().any(|b| b.is_ascii_uppercase())
            && m.as_str().bytes().any(|b| b.is_ascii_lowercase());
        if !mixed || before.to_ascii_lowercase().contains("data:image/") {
            continue;
        }
        sink.push(RawFinding::new(
            "TC002",
            Severity::Medium,
            Some(file),
            Some(i + 1),
            &format!("base64 run of {} characters in instruction text", m.len()),
            &format!("{}…", &m.as_str()[..24]),
        ));
    }
}

// ── TC007 hidden characters ──────────────────────────────────────────────

fn is_bidi(c: char) -> bool {
    matches!(c as u32, 0x202A..=0x202E | 0x2066..=0x2069)
}

/// Drop emoji presentation selectors / joiners (ordinary in Markdown) and a
/// leading BOM before counting invisible characters.
fn without_benign_invisibles(line: &str, first: bool) -> String {
    let mut out = String::with_capacity(line.len());
    let mut prev: Option<char> = None;
    for (i, c) in line.chars().enumerate() {
        let emoji_prev = prev.is_some_and(|p| (p as u32) >= 0x2190 && !p.is_alphanumeric());
        let skip = matches!(c, '\u{FE0E}' | '\u{FE0F}')
            || (c == '\u{200D}' && emoji_prev)
            || (c == '\u{FEFF}' && first && i == 0);
        if !skip {
            out.push(c);
        }
        prev = Some(c);
    }
    out
}

fn hidden_chars(file: &Path, text: &str, sink: &mut Sink<'_>) {
    let (mut bidi, mut invisible, mut ansi, mut mixed) = (false, false, false, false);
    for (i, line) in text.lines().enumerate() {
        let n = Some(i + 1);
        if !bidi && line.chars().any(is_bidi) {
            bidi = true;
            sink.push(RawFinding::new(
                "TC007",
                Severity::High,
                Some(file),
                n,
                "bidirectional control character (text may display differently than it reads)",
                line,
            ));
        }
        let probe = without_benign_invisibles(line, i == 0);
        if !invisible
            && UnicodeNormalizer::strip_invisible_chars(&probe).1 > 0
            && !line.chars().any(is_bidi)
        {
            invisible = true;
            sink.push(RawFinding::new(
                "TC007",
                Severity::Medium,
                Some(file),
                n,
                "invisible / zero-width characters",
                line,
            ));
        }
        if !ansi && UnicodeNormalizer::strip_ansi_escapes(line).1 > 0 {
            ansi = true;
            sink.push(RawFinding::new(
                "TC007",
                Severity::Medium,
                Some(file),
                n,
                "ANSI escape sequence",
                line,
            ));
        }
        if !mixed && let Some(word) = mixed_script_word(line) {
            mixed = true;
            sink.push(RawFinding::new(
                "TC007",
                Severity::Medium,
                Some(file),
                n,
                &format!("mixed-script identifier {word:?} (possible homoglyph)"),
                line,
            ));
        }
    }
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-')
}

static LATIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\p{Latin}").expect("static Latin script"));

fn mixed_script_word(line: &str) -> Option<String> {
    line.split(|c: char| !is_word_char(c))
        .find(|w| {
            LATIN_RE.is_match(w)
                && w.chars()
                    .any(|c| "авсекмнортухіјѕԁӏАВСЕНКМОРТУХІЈЅοαρνικτυχΑΒΕΖΗΙΚΜΝΟΡΤΥΧ".contains(c))
        })
        .map(str::to_string)
}

// ── TC008 prompt injection ───────────────────────────────────────────────

/// `scan_input` rules that are about code/commands rather than steering
/// the model; TC001–TC005 cover those precisely.
const NON_INJECTION_RULES: &[&str] = &["tool_abuse", "data_exfiltration", "encoding_bypass"];
const BLOCKING_RULES: &[&str] = &["instruction_override", "role_hijack"];

struct InjectionHit {
    signals: Vec<String>,
    high: bool,
}

fn injection_hit(text: &str) -> Option<InjectionHit> {
    let g = scan_input(text, DEFAULT_BLOCK_THRESHOLD);
    let mut signals: Vec<String> = g
        .matched_rules
        .iter()
        .filter(|r| !NON_INJECTION_RULES.contains(&r.as_str()))
        .cloned()
        .collect();
    let high = g.blocked && signals.iter().any(|r| BLOCKING_RULES.contains(&r.as_str()));
    if let Some(sig) =
        crate::audit::injection::scan_module("", &[(String::new(), text.to_string())])
    {
        let own: Vec<String> = sig
            .signals
            .into_iter()
            .filter(|s| !s.starts_with("generic_injection"))
            .collect();
        if own.iter().any(|s| s != "addresses_model") {
            signals.extend(own);
        }
    }
    signals.dedup();
    (!signals.is_empty()).then_some(InjectionHit { signals, high })
}

static DEFENSIVE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"(?i)\b(?:not|never|must not|don't|do not|ignore any)\b|不得|不要|不代表|不能|不可|禁止|切勿|並非"
).expect("static defensive marker")
});
static QUOTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"「[^」]*」|『[^』]*』|“[^”]*”|"[^"
]*"|'[^'
]*'|`[^`
]*`"#,
    )
    .expect("static quoted text")
});

fn defensive_injection(line: &str) -> bool {
    DEFENSIVE_RE.is_match(line)
        && QUOTED_RE
            .find_iter(line)
            .any(|m| injection_hit(m.as_str()).is_some())
        && injection_hit(&QUOTED_RE.replace_all(line, "")).is_none()
}

fn injection(
    file: Option<&Path>,
    first_line: usize,
    text: &str,
    markdown: bool,
    sink: &mut Sink<'_>,
) {
    if text.trim().is_empty() {
        return;
    }
    let Some(hit) = injection_hit(text) else {
        return;
    };
    let located = text
        .lines()
        .enumerate()
        .take(MAX_LOCATE_LINES)
        .find(|(_, l)| injection_hit(l).is_some());
    let (line, excerpt) = match located {
        Some((i, l)) => (Some(first_line + i), l),
        None => (None, ""),
    };
    sink.push(RawFinding::new(
        "TC008",
        if markdown {
            if file.is_some_and(|p| {
                path_in(
                    p,
                    &["evals", "eval", "tests", "test", "fixtures", "examples"],
                )
            }) || (located.is_some()
                && text
                    .lines()
                    .filter(|l| injection_hit(l).is_some())
                    .all(defensive_injection))
            {
                Severity::Info
            } else {
                Severity::Medium
            }
        } else if hit.high {
            Severity::High
        } else {
            Severity::Medium
        },
        file,
        line,
        &format!("prompt-injection signals: {}", hit.signals.join(", ")),
        excerpt,
    ));
}

// ── TC009 prerequisite trap ──────────────────────────────────────────────

static PREREQ_TRIGGER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:\bbefore (?:using|use|you (?:use|start|begin|continue)|running|proceeding|anything else|first use)\b|\bfirst(?:,)? (?:run|install|download|execute)\b|\bprerequisites?\b|\bsetup step\b|\byou must (?:first )?(?:run|install|download|execute)\b|\brequired:? (?:run|install|download)\b|\bon first run\b|使用前|使用之前|開始前|开始前|第一步|首先|請先|请先|必須先|必须先|務必先|务必先|先執行|先执行|先運行|先运行|先安裝|先安装|先下載|先下载|安裝步驟|安装步骤|前置|安裝前|前置作業|前置步驟|前置步骤|前置條件|前置条件)",
    )
    .expect("static prerequisite trigger")
});

static PREREQ_ACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:\b(?:curl|wget|iwr)\b|\bnpm\s+(?:i|install)\b|\bpnpm\s+add\b|\bpip3?\s+install\b|\buv\s+pip\b|\bbrew\s+install\b|\bgit\s+clone\b|\b(?:bash|sh|python[0-9.]*)\s+["']?(?:[\w./~][\w./~-]*)|\bchmod\s+\+x\b|https?://[^\s<>`"']+\.(?:sh|ps1|py|exe|pkg|dmg|zip|tar\.gz)\b)"#,
    )
    .expect("static prerequisite action")
});

fn prerequisite_trap(file: &Path, text: &str, sink: &mut Sink<'_>) {
    let lines: Vec<&str> = text.lines().collect();
    let (_, body_start) = split_frontmatter(text);
    for (i, line) in lines.iter().enumerate().skip(body_start.saturating_sub(1)) {
        let Some(_) = PREREQ_TRIGGER_RE.find(line) else {
            continue;
        };
        let window = std::iter::once(*line)
            .chain(lines.iter().skip(i + 1).take(3).copied())
            .any(|l| PREREQ_ACTION_RE.is_match(l));
        if window {
            sink.push(RawFinding::new(
                "TC009",
                Severity::Medium,
                Some(file),
                Some(i + 1),
                "instructions require running an external command or download before use",
                line,
            ));
        }
    }
}

// ── SKILL.md frontmatter ─────────────────────────────────────────────────

/// `name` / `description` from a leading `---` block, with the line number
/// of the description.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frontmatter {
    pub name: Option<String>,
    pub description: Option<(String, usize)>,
}

/// Parse the leading frontmatter; returns it and the 1-based line where the
/// body starts. Only `name` and `description` are read; anything else is
/// ignored. No YAML library: scalars, quoted scalars and `>`/`|` blocks.
pub fn split_frontmatter(text: &str) -> (Option<Frontmatter>, usize) {
    let lines: Vec<&str> = text.lines().collect();
    if lines
        .first()
        .map(|l| l.trim_start_matches('\u{FEFF}').trim_end())
        != Some("---")
    {
        return (None, 1);
    }
    let Some(end) = lines.iter().skip(1).position(|l| l.trim_end() == "---") else {
        return (None, 1);
    };
    let end = end + 1; // index of the closing line
    let mut fm = Frontmatter::default();
    let mut i = 1;
    while i < end {
        let line = lines[i];
        let Some((key, value)) = line.split_once(':') else {
            i += 1;
            continue;
        };
        if line.starts_with([' ', '\t']) {
            i += 1;
            continue;
        }
        let value = value.trim();
        let (text, consumed) = if matches!(value, ">" | "|" | ">-" | "|-" | ">+" | "|+") {
            let block: Vec<&str> = lines[i + 1..end]
                .iter()
                .take_while(|l| l.starts_with([' ', '\t']) || l.trim().is_empty())
                .map(|l| l.trim())
                .collect();
            (block.join(" ").trim().to_string(), block.len())
        } else {
            (unquote(value), 0)
        };
        match key.trim() {
            "name" => fm.name = Some(text),
            "description" => fm.description = Some((text, i + 1)),
            _ => {}
        }
        i += 1 + consumed;
    }
    (Some(fm), end + 2)
}

fn unquote(v: &str) -> String {
    let t = v.trim();
    for q in ['"', '\''] {
        if t.len() >= 2 && t.starts_with(q) && t.ends_with(q) {
            return t[1..t.len() - 1].to_string();
        }
    }
    t.to_string()
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
