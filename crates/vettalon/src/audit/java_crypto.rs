//! Bounded inventory of JCA call sites in one lexed file. No Java is executed.
//! Tokenization, group indexing and extraction are linear passes. All storage
//! is bounded by 2 MiB of source, 200,000 tokens, 256 nesting levels and
//! 50,000 rows. Constant expansion permits four references and 16 literal parts.
use std::collections::HashMap;

use super::java_lex::JavaLexed;
use super::java_parse::{self, MemberKind};

const MAX_BYTES: usize = 2 * 1024 * 1024;
// At most 200,000 tokens: bounds token/group storage independently of source bytes.
const MAX_TOKENS: usize = 200_000;
const MAX_ROWS: usize = 50_000;
const APIS: &[&str] = &[
    "Cipher",
    "MessageDigest",
    "Signature",
    "KeyPairGenerator",
    "KeyGenerator",
    "SecretKeyFactory",
    "Mac",
    "KeyAgreement",
    "KeyFactory",
    "KEM",
    "AlgorithmParameters",
    "AlgorithmParameterGenerator",
    "SecureRandom",
    "KeyStore",
];
const SPECS: &[&str] = &[
    "SecretKeySpec",
    "GCMParameterSpec",
    "IvParameterSpec",
    "PBEKeySpec",
    "ECGenParameterSpec",
    "RSAKeyGenParameterSpec",
];

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct SweepRow {
    pub(super) line: u32,
    pub(super) api: String,
    pub(super) algorithm: Option<String>,
    pub(super) mode: Option<String>,
    pub(super) padding: Option<String>,
    pub(super) key_bits: Option<u32>,
    pub(super) provider: Option<String>,
    pub(super) reasons: Vec<String>,
}

#[derive(Debug, Default)]
pub(super) struct SweepResult {
    pub(super) rows: Vec<SweepRow>,
    pub(super) truncated: bool,
    pub(super) reasons: Vec<String>,
}

struct Token<'a> {
    text: &'a str,
    byte: usize,
    line: u32,
    literal: Option<usize>,
}

fn clip(s: &str) -> String {
    s.chars().take(256).collect()
}
fn ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Quotes in the blanked view delimit whole tokens, including text blocks.
fn tokens(lexed: &JavaLexed) -> Option<Vec<Token<'_>>> {
    let code = lexed.code.as_bytes();
    let (mut i, mut line, mut literal) = (0, 1u32, 0);
    let mut out = Vec::new();
    while i < code.len() {
        let start = i;
        let start_line = line;
        let b = code[i];
        if b == b'\r' || (b == b'\n' && (i == 0 || code[i - 1] != b'\r')) {
            line = line.saturating_add(1);
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let mut value = None;
        if b == b'"' || b == b'\'' {
            let width = if code.get(i..i + 3) == Some(b"\"\"\"") {
                3
            } else {
                1
            };
            i += width;
            while i < code.len() && code.get(i..i + width) != code.get(start..start + width) {
                if code[i] == b'\r' || (code[i] == b'\n' && code[i - 1] != b'\r') {
                    line = line.saturating_add(1);
                }
                i += 1;
            }
            i = (i + width).min(code.len());
            if b == b'"' {
                if lexed
                    .literals
                    .get(literal)
                    .is_some_and(|v| v.0 == start_line)
                {
                    value = Some(literal);
                }
                literal += 1;
            }
        } else if ident(b) {
            i += 1;
            while i < code.len() && ident(code[i]) {
                i += 1;
            }
        } else {
            // Non-ASCII code is opaque, but must be sliced at UTF-8 boundaries.
            i += lexed.code[i..].chars().next().map_or(1, char::len_utf8);
        }
        if out.len() == MAX_TOKENS {
            return None;
        }
        out.push(Token {
            text: &lexed.code[start..i],
            byte: start,
            line: start_line,
            literal: value,
        });
    }
    Some(out)
}

#[derive(Clone, Copy, Default)]
struct Args {
    ranges: [(usize, usize); 4],
    count: usize,
}
struct Frame {
    open: usize,
    closer: &'static str,
    start: usize,
    args: Args,
}

fn groups(ts: &[Token<'_>]) -> Result<Vec<Option<Args>>, &'static str> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut result = vec![None; ts.len()];
    for (i, t) in ts.iter().enumerate() {
        match t.text {
            "(" | "[" | "{" => {
                if stack.len() == 256 {
                    return Err("nesting_too_deep");
                }
                let closer = match t.text {
                    "(" => ")",
                    "[" => "]",
                    _ => "}",
                };
                stack.push(Frame {
                    open: i,
                    closer,
                    start: i + 1,
                    args: Args::default(),
                });
            }
            "," => {
                if let Some(f) = stack.last_mut() {
                    if f.args.count < 4 {
                        f.args.ranges[f.args.count] = (f.start, i);
                    }
                    f.args.count = (f.args.count + 1).min(5);
                    f.start = i + 1;
                }
            }
            ")" | "]" | "}" => {
                let Some(mut f) = stack.pop() else {
                    return Err("unbalanced_braces");
                };
                if f.closer != t.text {
                    return Err("unbalanced_braces");
                }
                if f.args.count < 4 {
                    f.args.ranges[f.args.count] = (f.start, i);
                }
                f.args.count = (f.args.count + 1).min(5);
                if t.text == ")" {
                    if f.start == i && f.args.count == 1 {
                        f.args.count = 0;
                    }
                    result[f.open] = Some(f.args);
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err("unbalanced_braces");
    }
    Ok(result)
}

fn single<'a>(ts: &'a [Token<'a>], args: Args, n: usize) -> Option<&'a Token<'a>> {
    let &(a, b) = args.ranges.get(n)?;
    if n < args.count && b == a + 1 {
        ts.get(a)
    } else {
        None
    }
}

/// A bounded concatenation; `None` is an unsupported expression.
#[derive(Debug, Clone)]
pub(super) struct ConstExpr(Option<Vec<ConstPart>>);
#[derive(Debug, Clone)]
enum ConstPart {
    Literal(String),
    Reference(Option<String>, String),
}

/// The caller merges all project files here; duplicate (type, name) entries
/// must be stored as None, including collisions of simple type names.
#[derive(Debug, Default)]
pub(super) struct SweepContext {
    pub(super) constants: HashMap<String, HashMap<String, Option<ConstExpr>>>,
    entries: usize,
    bytes: usize,
    pub(super) limit_exceeded: bool,
}

/// Project constant budget: at most 200,000 declarations and 16 MiB of
/// type/name bytes, expression part storage and owned literal/reference bytes.
/// Charge duplicate declarations too. On overflow all reference resolution
/// fails closed, since a skipped declaration might duplicate an earlier one.
const MAX_SWEEP_CONSTANTS: usize = 200_000;
const MAX_SWEEP_CONSTANT_BYTES: usize = 16 * 1024 * 1024;

impl SweepContext {
    pub(super) fn insert(&mut self, ty: String, name: String, expr: ConstExpr) -> bool {
        self.insert_with_limits(
            ty,
            name,
            expr,
            MAX_SWEEP_CONSTANTS,
            MAX_SWEEP_CONSTANT_BYTES,
        )
    }

    fn insert_with_limits(
        &mut self,
        ty: String,
        name: String,
        expr: ConstExpr,
        max_entries: usize,
        max_bytes: usize,
    ) -> bool {
        let parts = expr.0.as_ref().map_or(0, |parts| {
            parts.iter().fold(
                parts.capacity() * std::mem::size_of::<ConstPart>(),
                |n, part| {
                    n.saturating_add(match part {
                        ConstPart::Literal(s) => s.capacity(),
                        ConstPart::Reference(ty, name) => {
                            ty.as_ref().map_or(0, String::capacity) + name.capacity()
                        }
                    })
                },
            )
        });
        let bytes = ty
            .capacity()
            .saturating_add(name.capacity())
            .saturating_add(parts)
            .saturating_add(std::mem::size_of::<(String, Option<ConstExpr>)>());
        if self.limit_exceeded
            || self.entries >= max_entries
            || bytes > max_bytes.saturating_sub(self.bytes)
        {
            self.limit_exceeded = true;
            return false;
        }
        self.entries += 1;
        self.bytes += bytes;
        self.constants
            .entry(ty)
            .or_default()
            .entry(name)
            .and_modify(|v| *v = None)
            .or_insert(Some(expr));
        true
    }
}

fn expression(ts: &[Token<'_>], lexed: &JavaLexed) -> ConstExpr {
    let mut parts = Vec::new();
    let mut i = 0;
    while i < ts.len() {
        if parts.len() == 16 {
            return ConstExpr(None);
        }
        if let Some(n) = ts[i].literal {
            let Some(v) = lexed.literals.get(n) else {
                return ConstExpr(None);
            };
            parts.push(ConstPart::Literal(clip(&v.1)));
            i += 1;
        } else {
            let mut previous = None;
            let mut name = ts[i].text;
            if !identifier(name) {
                return ConstExpr(None);
            }
            i += 1;
            while i + 1 < ts.len() && ts[i].text == "." {
                previous = Some(name);
                name = ts[i + 1].text;
                if !identifier(name) {
                    return ConstExpr(None);
                }
                i += 2;
            }
            if name.len() > 256 || previous.is_some_and(|p| p.len() > 256) {
                return ConstExpr(None);
            }
            parts.push(ConstPart::Reference(
                previous.map(str::to_owned),
                name.into(),
            ));
        }
        if i < ts.len() {
            if ts[i].text != "+" || i + 1 == ts.len() {
                return ConstExpr(None);
            }
            i += 1;
        }
    }
    ConstExpr((!parts.is_empty()).then_some(parts))
}

fn identifier(s: &str) -> bool {
    s.as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'$'))
        && s.bytes().all(ident)
}

/// Collect field constants using already parsed member spans, in one pass.
pub(super) fn collect_constants(
    lexed: &JavaLexed,
    parsed: &java_parse::JavaFile,
) -> Vec<(String, String, ConstExpr)> {
    if lexed.ambiguity.is_some() || parsed.ambiguity.is_some() || lexed.code.len() > MAX_BYTES {
        return Vec::new();
    }
    let Some(ts) = tokens(lexed) else {
        return Vec::new();
    };
    constants_from_tokens(&ts, lexed, parsed)
}

fn constants_from_tokens(
    ts: &[Token<'_>],
    lexed: &JavaLexed,
    parsed: &java_parse::JavaFile,
) -> Vec<(String, String, ConstExpr)> {
    let mut out = Vec::new();
    let mut cursor = 0;
    for m in &parsed.members {
        if m.kind != MemberKind::FieldInit {
            continue;
        }
        while cursor < ts.len() && ts[cursor].byte < m.start_byte {
            cursor += 1;
        }
        let start = cursor;
        while cursor < ts.len() && ts[cursor].byte < m.end_byte {
            cursor += 1;
        }
        let field = &ts[start..cursor];
        let Some(eq) = field.iter().position(|t| t.text == "=") else {
            continue;
        };
        let header = &field[..eq];
        if eq < 2
            || !header.iter().any(|t| t.text == "static")
            || !header.iter().any(|t| t.text == "final")
            || header[eq - 2].text != "String"
            || !identifier(header[eq - 1].text)
            || header[eq - 1].text.len() > 256
        {
            continue;
        }
        let Some(ty) = parsed.types.get(m.type_idx) else {
            continue;
        };
        if ty.name.len() > 256 {
            continue;
        }
        let end = field.len().saturating_sub(1);
        out.push((
            ty.name.clone(),
            header[eq - 1].text.into(),
            expression(&field[eq + 1..end], lexed),
        ));
    }
    out
}

fn evaluate(
    expr: &ConstExpr,
    ctx: &SweepContext,
    local: &HashMap<String, Option<(String, ConstExpr)>>,
    owner: Option<&str>,
    depth: usize,
    budget: &mut usize,
) -> Option<String> {
    let mut out = String::new();
    for part in expr.0.as_ref()? {
        if *budget == 0 {
            return None;
        }

        let value = match part {
            ConstPart::Literal(s) => {
                *budget -= 1;
                s.clone()
            }
            ConstPart::Reference(ty, name) => {
                if ctx.limit_exceeded || depth == 4 {
                    return None;
                }
                let (ty, expr) = if let Some(ty) = ty.as_deref().or(owner) {
                    (
                        ty,
                        if let Some(entry) = ctx.constants.get(ty).and_then(|table| table.get(name))
                        {
                            entry.as_ref()?
                        } else {
                            let (local_ty, expr) = local.get(name)?.as_ref()?;
                            if local_ty != ty {
                                return None;
                            }
                            expr
                        },
                    )
                } else {
                    let (ty, expr) = local.get(name)?.as_ref()?;
                    (ty.as_str(), expr)
                };
                // Same-file constants need not have been merged by the caller.
                evaluate(expr, ctx, local, Some(ty), depth + 1, budget)?
            }
        };
        if out.chars().count() + value.chars().count() > 256 {
            return None;
        }
        out.push_str(&value);
    }
    Some(out)
}

fn resolve(
    ts: &[Token<'_>],
    args: Args,
    n: usize,
    lexed: &JavaLexed,
    ctx: &SweepContext,
    local: &HashMap<String, Option<(String, ConstExpr)>>,
) -> Option<String> {
    if n >= args.count || n >= args.ranges.len() {
        return None;
    }
    let (a, b) = args.ranges[n];
    evaluate(&expression(&ts[a..b], lexed), ctx, local, None, 0, &mut 16)
}

fn integer(t: Option<&Token<'_>>) -> Option<u32> {
    let text = t?.text;
    if text.len() > 256 {
        return None;
    }
    let digits: String = text.chars().filter(|c| *c != '_').collect();
    let (digits, radix) = if let Some(s) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (s, 16)
    } else if let Some(s) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        (s, 2)
    } else if digits.starts_with('0') && digits.len() > 1 {
        (&digits[1..], 8)
    } else {
        (digits.as_str(), 10)
    };
    u32::from_str_radix(digits, radix).ok()
}

fn transformation(row: &mut SweepRow, value: String) {
    if row.api != "Cipher.getInstance" {
        row.algorithm = Some(value);
        return;
    }
    let mut parts = value.splitn(3, '/');
    row.algorithm = parts.next().map(clip);
    row.mode = parts.next().map(clip);
    row.padding = parts.next().map(clip);
    if row.api == "Cipher.getInstance"
        && row.mode.is_none()
        && row.algorithm.as_deref().is_some_and(|a| {
            ["AES", "DES", "DESede"]
                .iter()
                .any(|b| a.eq_ignore_ascii_case(b))
        })
    {
        row.reasons.push("jca_default_mode_ecb_possible".into());
    }
}

/// Sweep one lexed file, independently of reachability and CBOM labels.
/// Spec numeric parameters are not inferred to be key sizes except RSA's
/// modulus size and PBEKeySpec's explicit keyLength (fourth argument).
pub(super) fn sweep(
    lexed: &JavaLexed,
    parsed: &java_parse::JavaFile,
    ctx: &SweepContext,
    max_rows: usize,
) -> SweepResult {
    let mut out = SweepResult::default();
    if let Some(reason) = lexed.ambiguity {
        out.reasons.push(clip(reason));
        return out;
    }
    if lexed.code.len() > MAX_BYTES {
        out.truncated = true;
        out.reasons.push("source_size_limit_exceeded".into());
        return out;
    }
    let Some(ts) = tokens(lexed) else {
        out.truncated = true;
        out.reasons = vec![
            "sweep_token_limit_exceeded".into(),
            "sweep_truncated".into(),
        ];
        return out;
    };
    let groups = match groups(&ts) {
        Ok(g) => g,
        Err(reason) => {
            out.truncated = reason == "nesting_too_deep";
            out.reasons.push(reason.into());
            return out;
        }
    };
    let text = |i: usize| ts.get(i).map_or("", |t| t.text);
    let mut local = HashMap::new();
    for (ty, name, expr) in constants_from_tokens(&ts, lexed, parsed)
        .into_iter()
        .filter(|_| !ctx.limit_exceeded)
    {
        local
            .entry(name)
            .and_modify(|v| *v = None)
            .or_insert(Some((ty, expr)));
    }
    let bc_imported = parsed
        .imports
        .iter()
        .any(|s| s.starts_with("org.bouncycastle."));
    let mut starts = HashMap::new();
    if parsed.ambiguity.is_none() {
        for (id, m) in parsed.members.iter().enumerate() {
            starts.insert(m.start_byte, (id, m.end_byte, m.kind));
        }
    }
    let mut members = Vec::new();
    let mut nearest: HashMap<(usize, &str), usize> = HashMap::new();
    for (i, t) in ts.iter().enumerate() {
        while members.last().is_some_and(|&(_, end, _)| end <= t.byte) {
            members.pop();
        }
        if let Some(&m) = starts.get(&t.byte) {
            members.push(m);
        }
        let member = members
            .last()
            .filter(|m| matches!(m.2, MemberKind::Method | MemberKind::Constructor));
        if t.text != "(" {
            continue;
        }
        let Some(&args) = groups[i].as_ref() else {
            continue;
        };
        let name = i.checked_sub(1).map_or("", text);
        if matches!(name, "initialize" | "init") && i >= 2 && text(i - 2) == "." {
            if (1..=2).contains(&args.count)
                && i >= 3
                && identifier(text(i - 3))
                && let Some(bits) = integer(single(&ts, args, 0))
                && let Some(&(id, _, _)) = member
                && let Some(&row) = nearest.get(&(id, text(i - 3)))
            {
                out.rows[row].key_bits = Some(bits);
            }
            continue;
        }
        let factory =
            name == "getInstance" && i >= 3 && text(i - 2) == "." && APIS.contains(&text(i - 3));
        let constructor = i >= 2 && {
            let mut j = i - 1;
            // Qualified constructor names have a fixed, bounded look-back.
            for _ in 0..8 {
                if j >= 2 && text(j - 1) == "." {
                    j -= 2;
                } else {
                    break;
                }
            }
            j > 0 && text(j - 1) == "new"
        };
        let spec = constructor && SPECS.contains(&name);
        let bc_name = if constructor {
            name
        } else if name == "newInstance" && i >= 3 && text(i - 2) == "." {
            text(i - 3)
        } else {
            ""
        };
        let bc = bc_imported
            .then(|| super::java_crypto_bc::lookup(bc_name))
            .flatten();
        if name == "addProvider"
            && i >= 3
            && text(i - 3) == "Security"
            && text(i - 2) == "."
            && args.count == 1
        {
            let (a, b) = args.ranges[0];
            if b == a + 4
                && text(a) == "new"
                && text(a + 1) == "BouncyCastleProvider"
                && text(a + 2) == "("
                && text(a + 3) == ")"
                && !out
                    .reasons
                    .iter()
                    .any(|s| s == "bouncycastle_provider_registered")
            {
                out.reasons.push("bouncycastle_provider_registered".into());
            }
        }
        if !factory && !spec && bc.is_none() {
            continue;
        }
        if out.rows.len() >= max_rows.min(MAX_ROWS) {
            out.truncated = true;
            break;
        }
        let mut row = SweepRow {
            line: if factory {
                ts[i - 3].line
            } else {
                ts[i - 1].line
            },
            api: if factory {
                format!("{}.getInstance", text(i - 3))
            } else {
                format!("new {name}")
            },
            ..SweepRow::default()
        };
        if let Some((algorithm, mode)) = bc {
            row.api = format!("bc:{bc_name}");
            row.algorithm = algorithm.map(str::to_owned);
            row.mode = mode.map(str::to_owned);
        }
        let algorithm_arg = if factory || name == "ECGenParameterSpec" {
            Some(0)
        } else if name == "SecretKeySpec" {
            Some(1)
        } else {
            None
        };
        if let Some(n) = algorithm_arg {
            if let Some(value) = resolve(&ts, args, n, lexed, ctx, &local) {
                if factory {
                    transformation(&mut row, value);
                } else {
                    row.algorithm = Some(value);
                }
            } else {
                row.reasons.push("algorithm_not_constant".into());
            }
        }
        if factory {
            row.provider = resolve(&ts, args, 1, lexed, ctx, &local);
        }
        match name {
            "GCMParameterSpec" => row.mode = Some("GCM".into()),
            "RSAKeyGenParameterSpec" => {
                row.algorithm = Some("RSA".into());
                row.key_bits = integer(single(&ts, args, 0));
            }
            "PBEKeySpec" => row.key_bits = integer(single(&ts, args, 3)),
            _ => {}
        }
        if factory
            && matches!(text(i - 3), "KeyPairGenerator" | "KeyGenerator")
            && let Some(&(id, _, _)) = member
        {
            let mut start = i - 3;
            while start >= 2 && text(start - 1) == "." {
                start -= 2;
            }
            if start >= 2 && text(start - 1) == "=" && identifier(text(start - 2)) {
                nearest.insert((id, text(start - 2)), out.rows.len());
            }
        }
        out.rows.push(row);
    }
    if lexed.literals_truncated {
        out.truncated = true;
        out.reasons.push("literals_truncated".into());
    }
    if out.truncated {
        out.reasons.push("sweep_truncated".into());
    }
    out
}

#[cfg(test)]
#[path = "java_crypto_tests.rs"]
mod tests;
