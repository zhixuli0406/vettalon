//! Java lexer for the `cbom-check` Java analyzer. The input is untrusted
//! source: every step is a single linear pass with explicit indices (no
//! recursion over the input, no regex, no backtracking) and never panics.
//!
//! Steps:
//! 0. One leading BOM (U+FEFF) is dropped (the caller hashes the raw bytes
//!    first). Any other U+FEFF is an ordinary character.
//! 1. Unicode escapes are translated first, per JLS 3.3: a `\` preceded by an
//!    even number of contiguous raw backslashes, then one or more `u`, then
//!    exactly four hex digits. Anything else after `\u` makes the file
//!    ambiguous (`unicode_escape_invalid`; javac rejects it too, even inside a
//!    comment). An escape that yields CR, LF, `"`, `'`, `\`, `/` or `*` makes
//!    the file ambiguous (`unicode_escape_structural`), so `// \u000a code()`
//!    and similar tricks never hide code from the lexer. Because escapes can
//!    never produce a line break, translation keeps every line number.
//!    A high/low surrogate escape pair becomes one character; a lone
//!    surrogate becomes U+FFFD.
//! 2. The translated text is lexed: `//` and `/* */` comments (non-nesting),
//!    string literals, char literals and text blocks (Java 15+).
//!
//! Output ([`JavaLexed`]): a `code` view in which comments and literal
//! contents are blanked to spaces (delimiters kept, every CR and LF kept
//! verbatim, so the line count equals the source's), plus a side table of
//! decoded string / text-block literals with their 1-based start lines.
//! Line numbers count CR, LF and CRLF each as one line terminator (JLS 3.4).
//! Anything that does not lex sets `ambiguity` and the caller fails closed.

/// Longest decoded literal kept in [`JavaLexed::literals`], in characters.
pub(super) const MAX_LITERAL_CHARS: usize = 256;
/// Most literals recorded per file; later ones set `literals_truncated`.
pub(super) const MAX_LITERALS: usize = 100_000;

/// The lexed views of one Java source file.
///
/// When `ambiguity` is `Some`, every other field is empty / `false`: the
/// file must be treated as not analyzable.
#[derive(Debug, Default)]
pub(super) struct JavaLexed {
    /// The translated source with comments and the contents of string, char
    /// and text-block literals replaced by spaces (quotes kept, so tokens stay
    /// separated). Every CR and LF of the source is kept, so the line count
    /// equals the source's; columns may differ where unicode escapes were
    /// translated.
    pub(super) code: String,
    /// `(1-based line of the opening quote, decoded value)` of every string
    /// literal and text block, in source order; values clipped to
    /// [`MAX_LITERAL_CHARS`] characters. Char literals are not recorded.
    pub(super) literals: Vec<(u32, String)>,
    /// More than [`MAX_LITERALS`] literals: the rest were not recorded.
    pub(super) literals_truncated: bool,
    /// Why the file does not lex (`unicode_escape_invalid`,
    /// `unicode_escape_structural`, `unterminated_comment`,
    /// `unterminated_string`, `unterminated_char`, `unterminated_text_block`,
    /// `text_block_invalid_open`).
    pub(super) ambiguity: Option<&'static str>,
    /// A character in code (outside comments and literals, after escape
    /// translation) that is not printable ASCII, tab, form feed, CR or LF:
    /// any non-ASCII character, and ASCII control characters, which javac
    /// skips inside identifiers (JLS 3.8 "ignorable"). Such a file may name a
    /// method in a way a byte comparison cannot see.
    pub(super) non_ascii_in_code: bool,
}

type Lex<T> = Result<T, &'static str>;

fn is_line_end(c: char) -> bool {
    c == '\n' || c == '\r'
}

/// Characters that may not come out of a unicode escape.
fn is_structural(c: char) -> bool {
    matches!(c, '\r' | '\n' | '"' | '\'' | '\\' | '/' | '*')
}

/// `c` may change what an identifier means or is not plain ASCII.
fn is_suspicious_code_char(c: char) -> bool {
    !(c == ' ' || c.is_ascii_graphic() || matches!(c, '\t' | '\n' | '\r' | '\u{c}'))
}

/// `Character.isWhitespace` (used for text-block indentation stripping).
fn is_java_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | '\u{1c}'..='\u{1f}'
    ) || (c.is_whitespace() && !matches!(c, '\u{85}' | '\u{a0}' | '\u{2007}' | '\u{202f}'))
}

/// The UTF-16 unit of the unicode escape whose backslash is at `i` (the
/// caller checked backslash parity and that `s[i + 1]` is `u`), and the index
/// just past it.
fn escape_at(s: &[char], i: usize) -> Lex<(u32, usize)> {
    let mut j = i + 1;
    while s.get(j) == Some(&'u') {
        j += 1;
    }
    let mut v = 0u32;
    for k in 0..4 {
        let d = s
            .get(j + k)
            .and_then(|c| c.to_digit(16))
            .ok_or("unicode_escape_invalid")?;
        v = v * 16 + d;
    }
    Ok((v, j + 4))
}

/// JLS 3.3 unicode escape translation, linear in the input length (each
/// escape is parsed at most twice: once as a surrogate-pair look-ahead).
fn translate_unicode(src: &str) -> Lex<Vec<char>> {
    let s: Vec<char> = src.chars().collect();
    let mut out = Vec::with_capacity(s.len());
    // Contiguous raw backslashes just before `i`.
    let mut run = 0usize;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == '\\' && run.is_multiple_of(2) && s.get(i + 1) == Some(&'u') {
            let (unit, end) = escape_at(&s, i)?;
            let mut next = end;
            let mut decoded = char::from_u32(unit);
            if (0xD800..0xDC00).contains(&unit)
                && s.get(end) == Some(&'\\')
                && s.get(end + 1) == Some(&'u')
            {
                let (lo, end2) = escape_at(&s, end)?;
                if (0xDC00..0xE000).contains(&lo) {
                    decoded = char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (lo - 0xDC00));
                    next = end2;
                }
            }
            // A lone surrogate is not a `char`.
            let ch = decoded.unwrap_or('\u{fffd}');
            if is_structural(ch) {
                return Err("unicode_escape_structural");
            }
            out.push(ch);
            run = 0;
            i = next;
            continue;
        }
        run = if c == '\\' { run + 1 } else { 0 };
        out.push(c);
        i += 1;
    }
    Ok(out)
}

/// The `code` view under construction plus the current line number.
struct Out {
    code: String,
    line: u32,
    prev_cr: bool,
}

impl Out {
    /// Emit `c` (kept when `keep`, else blanked; CR / LF always kept).
    fn put(&mut self, c: char, keep: bool) {
        if c == '\r' || (c == '\n' && !self.prev_cr) {
            self.line = self.line.saturating_add(1);
        }
        self.prev_cr = c == '\r';
        self.code.push(if keep || is_line_end(c) { c } else { ' ' });
    }
}

#[derive(Default)]
struct Literals {
    list: Vec<(u32, String)>,
    truncated: bool,
}

impl Literals {
    fn record(&mut self, line: u32, decode: impl FnOnce() -> String) {
        if self.list.len() >= MAX_LITERALS {
            self.truncated = true;
        } else {
            self.list.push((line, decode()));
        }
    }
}

/// Interpret the escape sequences of literal content `s` (JLS 3.10.7),
/// stopping after [`MAX_LITERAL_CHARS`] output characters. `\<line end>`
/// (text blocks only) produces nothing; an unknown escape keeps its character.
fn decode_escapes(s: &[char]) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut k = 0;
    while k < s.len() && count < MAX_LITERAL_CHARS {
        let c = s[k];
        k += 1;
        if c != '\\' {
            out.push(c);
            count += 1;
            continue;
        }
        let Some(&e) = s.get(k) else {
            out.push('\\');
            break;
        };
        k += 1;
        let d = match e {
            'b' => '\u{8}',
            's' => ' ',
            't' => '\t',
            'n' => '\n',
            'f' => '\u{c}',
            'r' => '\r',
            '\n' => continue,
            '\r' => {
                if s.get(k) == Some(&'\n') {
                    k += 1;
                }
                continue;
            }
            '0'..='7' => {
                let max = if e <= '3' { 3 } else { 2 };
                let mut v = e.to_digit(8).unwrap_or(0);
                let mut len = 1;
                while len < max
                    && let Some(d) = s.get(k).and_then(|c| c.to_digit(8))
                {
                    v = v * 8 + d;
                    k += 1;
                    len += 1;
                }
                char::from_u32(v).unwrap_or('\u{fffd}')
            }
            other => other,
        };
        out.push(d);
        count += 1;
    }
    out
}

fn blank(l: &[char]) -> bool {
    l.iter().all(|&c| is_java_ws(c))
}

/// Decoded value of a text block whose raw content (after the opening line
/// terminator, before the closing `"""`) is `content`: line terminators
/// normalised to LF, incidental indentation and trailing whitespace stripped
/// (`String.stripIndent`), then escapes interpreted (JLS 3.10.6).
fn decode_text_block(content: &[char]) -> String {
    let mut lines: Vec<&[char]> = Vec::new();
    let mut start = 0;
    let mut k = 0;
    while k < content.len() {
        match content[k] {
            '\r' => {
                lines.push(&content[start..k]);
                if content.get(k + 1) == Some(&'\n') {
                    k += 1;
                }
                start = k + 1;
            }
            '\n' => {
                lines.push(&content[start..k]);
                start = k + 1;
            }
            _ => {}
        }
        k += 1;
    }
    // The line holding the closing delimiter always counts for indentation.
    lines.push(&content[start..]);
    let last = lines.len() - 1;
    let indent = lines
        .iter()
        .enumerate()
        .filter(|&(ix, l)| ix == last || !blank(l))
        .map(|(_, l)| l.iter().take_while(|&&c| is_java_ws(c)).count())
        .min()
        .unwrap_or(0);
    let mut joined: Vec<char> = Vec::with_capacity(content.len());
    for (ix, l) in lines.iter().enumerate() {
        if ix > 0 {
            joined.push('\n');
        }
        if blank(l) {
            continue;
        }
        let body = &l[indent.min(l.len())..];
        let end = body.len() - body.iter().rev().take_while(|&&c| is_java_ws(c)).count();
        joined.extend_from_slice(&body[..end]);
    }
    decode_escapes(&joined)
}

/// Lex the string or char literal whose opening quote is at `i`; returns the
/// index just past the closing quote.
fn quoted(t: &[char], i: usize, o: &mut Out, lits: &mut Literals) -> Lex<usize> {
    let q = t[i];
    let reason = if q == '"' {
        "unterminated_string"
    } else {
        "unterminated_char"
    };
    let line = o.line;
    o.put(q, true);
    let mut j = i + 1;
    loop {
        let c = t
            .get(j)
            .copied()
            .filter(|&c| !is_line_end(c))
            .ok_or(reason)?;
        if c == q {
            break;
        }
        o.put(c, false);
        j += 1;
        if c == '\\' {
            let e = t
                .get(j)
                .copied()
                .filter(|&c| !is_line_end(c))
                .ok_or(reason)?;
            o.put(e, false);
            j += 1;
        }
    }
    if q == '"' {
        lits.record(line, || decode_escapes(&t[i + 1..j]));
    }
    o.put(q, true);
    Ok(j + 1)
}

/// Lex the text block whose opening `"""` is at `i`; returns the index just
/// past the closing `"""`.
fn text_block(t: &[char], i: usize, o: &mut Out, lits: &mut Literals) -> Lex<usize> {
    let line = o.line;
    for _ in 0..3 {
        o.put('"', true);
    }
    let mut j = i + 3;
    loop {
        match t.get(j).copied() {
            Some(c @ (' ' | '\t' | '\u{c}')) => {
                o.put(c, false);
                j += 1;
            }
            Some('\r') => {
                o.put('\r', false);
                j += 1;
                if t.get(j) == Some(&'\n') {
                    o.put('\n', false);
                    j += 1;
                }
                break;
            }
            Some('\n') => {
                o.put('\n', false);
                j += 1;
                break;
            }
            _ => return Err("text_block_invalid_open"),
        }
    }
    let start = j;
    loop {
        let c = t.get(j).copied().ok_or("unterminated_text_block")?;
        if c == '"' && t.get(j + 1) == Some(&'"') && t.get(j + 2) == Some(&'"') {
            break;
        }
        o.put(c, false);
        j += 1;
        if c == '\\' {
            let e = t.get(j).copied().ok_or("unterminated_text_block")?;
            o.put(e, false);
            j += 1;
        }
    }
    lits.record(line, || decode_text_block(&t[start..j]));
    for _ in 0..3 {
        o.put('"', true);
    }
    Ok(j + 3)
}

/// Lex one Java source file. Never panics; linear in `src.len()`.
pub(super) fn lex(src: &str) -> JavaLexed {
    lex_inner(src).unwrap_or_else(|reason| JavaLexed {
        ambiguity: Some(reason),
        ..JavaLexed::default()
    })
}

fn lex_inner(src: &str) -> Lex<JavaLexed> {
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let t = translate_unicode(src)?;
    let n = t.len();
    let mut o = Out {
        code: String::with_capacity(src.len()),
        line: 1,
        prev_cr: false,
    };
    let mut lits = Literals::default();
    let mut non_ascii = false;
    let mut i = 0;
    while i < n {
        let c = t[i];
        let next = t.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < n && !is_line_end(t[i]) {
                o.put(t[i], false);
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            o.put('/', false);
            o.put('*', false);
            i += 2;
            loop {
                let ch = t.get(i).copied().ok_or("unterminated_comment")?;
                if ch == '*' && t.get(i + 1) == Some(&'/') {
                    o.put('*', false);
                    o.put('/', false);
                    i += 2;
                    break;
                }
                o.put(ch, false);
                i += 1;
            }
        } else if c == '"' && next == Some('"') && t.get(i + 2) == Some(&'"') {
            i = text_block(&t, i, &mut o, &mut lits)?;
        } else if c == '"' || c == '\'' {
            i = quoted(&t, i, &mut o, &mut lits)?;
        } else {
            if is_suspicious_code_char(c) {
                non_ascii = true;
            }
            o.put(c, true);
            i += 1;
        }
    }
    Ok(JavaLexed {
        code: o.code,
        literals: lits.list,
        literals_truncated: lits.truncated,
        ambiguity: None,
        non_ascii_in_code: non_ascii,
    })
}

#[cfg(test)]
#[path = "java_lex_tests.rs"]
mod tests;
