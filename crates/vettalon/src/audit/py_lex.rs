//! Python lexer for `py_usage` (a child module of it, declared with `#[path]`).
//!
//! One pass over the source yields three views of the same length (every
//! character is replaced one-for-one, `\n` / `\r` are always kept, so line
//! numbers and columns never move):
//! * `code`: `#` comments blanked, string literals verbatim;
//! * `structure`: comments blanked and the content of **every** string literal
//!   blanked (delimiters kept) — used for indentation, brackets and headers;
//! * `refs`: comments blanked, plain string contents blanked, but the full
//!   content of f-/t-strings kept verbatim, because their replacement fields
//!   are code (over-approximation: literal text may add references, which is
//!   always acceptable).
//!
//! Docstrings are ordinary strings here (no special case), so an f-string can
//! never be mistaken for a docstring and hidden. f-/t-strings follow the
//! Python 3.12 (PEP 701) grammar: replacement fields may hold nested strings
//! with the same quote, nested replacement fields and format specs. Anything
//! that does not lex (an unterminated literal, nesting deeper than
//! [`MAX_NEST`]) returns `None` and the caller fails closed.

/// Deepest f-string nesting accepted before the file is ambiguous.
const MAX_NEST: u32 = 32;

pub(super) struct Lexed {
    pub(super) code: String,
    pub(super) structure: String,
    pub(super) refs: String,
    /// Per physical line (0-based): the line break ending it is inside a
    /// string literal (a multi-line string or a continued literal).
    pub(super) in_string_eol: Vec<bool>,
    /// A non-ASCII character outside comments and plain string literal
    /// content (in code or an f-/t-string replacement field). Python
    /// NFKC-normalises identifiers, so such a file may name a function in a
    /// way a byte comparison cannot see.
    pub(super) non_ascii_code: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct Prefix {
    raw: bool,
    fmt: bool,
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_quote(c: char) -> bool {
    c == '"' || c == '\''
}

/// The string prefix (`r`, `b`, `f`, `t`, `rb`, `fr`, `tr`, ...) spelled by
/// `p`, case-insensitively.
fn prefix_of(p: &[char]) -> Option<Prefix> {
    if p.is_empty() || p.len() > 2 {
        return None;
    }
    let s: String = p.iter().map(|c| c.to_ascii_lowercase()).collect();
    let (raw, fmt) = match s.as_str() {
        "u" | "b" => (false, false),
        "r" | "br" | "rb" => (true, false),
        "f" | "t" => (false, true),
        "fr" | "rf" | "tr" | "rt" => (true, true),
        _ => return None,
    };
    Some(Prefix { raw, fmt })
}

/// End (exclusive) of a `\N{NAME}` escape whose name starts at `k`.
fn named_escape_end(s: &[char], k: usize) -> Option<usize> {
    let mut j = k;
    while j < s.len() && j - k < 128 && (s[j].is_ascii_alphanumeric() || s[j] == ' ' || s[j] == '-')
    {
        j += 1;
    }
    (s.get(j) == Some(&'}')).then_some(j + 1)
}

struct Scan<'a> {
    s: &'a [char],
    non_ascii: bool,
}

impl Scan<'_> {
    /// End (exclusive) of the string literal whose opening quote is at `q`.
    fn string_end(&mut self, q: usize, p: Prefix, depth: u32) -> Option<usize> {
        let s = self.s;
        let quote = s[q];
        let triple = s.get(q + 1) == Some(&quote) && s.get(q + 2) == Some(&quote);
        let ql = if triple { 3 } else { 1 };
        let mut j = q + ql;
        loop {
            let c = *s.get(j)?;
            if c == '\\' {
                let next = s.get(j + 1).copied();
                if p.fmt && matches!(next, Some('{' | '}')) {
                    // A backslash does not escape a brace in an f-string.
                    j += 1;
                } else if p.fmt && !p.raw && next == Some('N') && s.get(j + 2) == Some(&'{') {
                    j = named_escape_end(s, j + 3).unwrap_or(j + 2);
                } else if next == Some('\r') && s.get(j + 2) == Some(&'\n') {
                    j += 3;
                } else {
                    j += 2;
                }
                continue;
            }
            if c == quote
                && (!triple || (s.get(j + 1) == Some(&quote) && s.get(j + 2) == Some(&quote)))
            {
                return Some(j + ql);
            }
            if c == '\n' && !triple {
                return None;
            }
            if p.fmt && c == '{' {
                if s.get(j + 1) == Some(&'{') {
                    j += 2;
                } else {
                    j = self.field_end(j + 1, depth + 1)?;
                }
                continue;
            }
            if p.fmt && c == '}' && s.get(j + 1) == Some(&'}') {
                j += 2;
                continue;
            }
            j += 1;
        }
    }

    /// End (exclusive, after `}`) of a replacement field starting at `start`.
    fn field_end(&mut self, start: usize, depth: u32) -> Option<usize> {
        if depth > MAX_NEST {
            return None;
        }
        let s = self.s;
        let mut brackets = 0usize;
        let mut j = start;
        loop {
            let c = *s.get(j)?;
            match c {
                '\'' | '"' => {
                    j = self.string_end(j, Prefix::default(), depth)?;
                    continue;
                }
                '#' => {
                    // PEP 701: a comment runs to the end of the line.
                    while j < s.len() && s[j] != '\n' {
                        j += 1;
                    }
                    continue;
                }
                '\\' => {
                    j += 2;
                    continue;
                }
                '(' | '[' | '{' => brackets += 1,
                ')' | ']' => brackets = brackets.saturating_sub(1),
                '}' if brackets == 0 => return Some(j + 1),
                '}' => brackets -= 1,
                ':' if brackets == 0 => return self.spec_end(j + 1, depth),
                c if is_ident(c) => {
                    let st = j;
                    while j < s.len() && is_ident(s[j]) {
                        if !s[j].is_ascii() {
                            self.non_ascii = true;
                        }
                        j += 1;
                    }
                    if j - st <= 2
                        && j < s.len()
                        && is_quote(s[j])
                        && let Some(p) = prefix_of(&s[st..j])
                    {
                        j = self.string_end(j, p, depth)?;
                    }
                    continue;
                }
                c if !c.is_ascii() => self.non_ascii = true,
                _ => {}
            }
            j += 1;
        }
    }

    /// End (exclusive, after `}`) of a format spec starting at `start`;
    /// quotes are literal text here, `{` opens a nested field.
    fn spec_end(&mut self, start: usize, depth: u32) -> Option<usize> {
        let s = self.s;
        let mut j = start;
        loop {
            match *s.get(j)? {
                '{' => {
                    j = self.field_end(j + 1, depth + 1)?;
                    continue;
                }
                '}' => return Some(j + 1),
                '\\' => {
                    j += 2;
                    continue;
                }
                _ => {}
            }
            j += 1;
        }
    }
}

fn blank(c: char) -> char {
    if c == '\n' || c == '\r' { c } else { ' ' }
}

/// Lex `src`; `None` when a literal never closes or nesting is too deep.
pub(super) fn lex(src: &str) -> Option<Lexed> {
    let s: Vec<char> = src.chars().collect();
    let n = s.len();
    let mut sc = Scan {
        s: &s,
        non_ascii: false,
    };
    let mut code = String::with_capacity(src.len());
    let mut structure = String::with_capacity(src.len());
    let mut refs = String::with_capacity(src.len());
    let mut in_string_eol = Vec::new();
    let mut push = |code_c: char, structure_c: char, refs_c: char| {
        code.push(code_c);
        structure.push(structure_c);
        refs.push(refs_c);
    };
    let mut i = 0;
    while i < n {
        let c = s[i];
        if c == '#' {
            while i < n && s[i] != '\n' {
                let b = blank(s[i]);
                push(b, b, b);
                i += 1;
            }
            continue;
        }
        let (q, p) = if is_quote(c) {
            (i, Prefix::default())
        } else if is_ident(c) {
            let mut j = i;
            while j < n && is_ident(s[j]) {
                j += 1;
            }
            let prefix = if j - i <= 2 && j < n && is_quote(s[j]) {
                prefix_of(&s[i..j])
            } else {
                None
            };
            match prefix {
                Some(p) => (j, p),
                None => {
                    for &ch in &s[i..j] {
                        if !ch.is_ascii() {
                            sc.non_ascii = true;
                        }
                        push(ch, ch, ch);
                    }
                    i = j;
                    continue;
                }
            }
        } else {
            if c == '\n' {
                in_string_eol.push(false);
            } else if !c.is_ascii() {
                // The caller strips one leading BOM; any other U+FEFF counts.
                sc.non_ascii = true;
            }
            push(c, c, c);
            i += 1;
            continue;
        };
        let end = sc.string_end(q, p, 0)?;
        let quote = s[q];
        let ql = if s.get(q + 1) == Some(&quote) && s.get(q + 2) == Some(&quote) {
            3
        } else {
            1
        };
        for (k, &ch) in s.iter().enumerate().take(end).skip(i) {
            let in_prefix = k < q;
            let delim = !in_prefix && (k < q + ql || k >= end - ql);
            let b = blank(ch);
            let structure_c = if delim { ch } else { b };
            let refs_c = if delim || (p.fmt && !in_prefix) {
                ch
            } else {
                b
            };
            push(ch, structure_c, refs_c);
            if ch == '\n' {
                in_string_eol.push(true);
            }
        }
        i = end;
    }
    Some(Lexed {
        code,
        structure,
        refs,
        in_string_eol,
        non_ascii_code: sc.non_ascii,
    })
}
