//! Python source intake and parsing for `py_usage`: bounded reads, file-level
//! ambiguity checks, logical lines and reference scanning. This is a child
//! module of `py_usage` (declared there with `#[path]`), so it uses the
//! parent's private types directly. Split out only to keep `py_usage.rs` under
//! the file-size cap. Lexing (comments, strings, f-strings) is in `py_lex`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use super::{Counts, NONE, Project, PyFile, Ref};

pub(super) static DEF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:async\s+)?def\s+([^\W\d]\w*)").unwrap());
pub(super) static CLASS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^class\s+([^\W\d]\w*)").unwrap());
pub(super) static MAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^if\s+__name__\s*==\s*(?:"__main__"|'__main__')\s*:"#).unwrap());
pub(super) static IMPORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:import|from)\s").unwrap());
pub(super) static FROM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^from\s+([.\w]+)\s+import\s+(.*)$").unwrap());
pub(super) static WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^\W\d]\w*").unwrap());
/// Dynamic dispatch that can reach a function without naming it. Bare words
/// (no `(` needed: `ga = getattr` aliases it), matched on the reference view
/// (comments and plain string contents blanked, f-/t-string contents kept).
/// `compile` is handled by [`has_dynamic_dispatch`]. Attribute position counts
/// (`len.__self__` is the builtins module; `f.__globals__[...]`,
/// `sys._getframe().f_globals[...]` reach functions by computed name).
static DYNAMIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:getattr|setattr|__import__|importlib|eval|exec|globals|locals|vars|__dict__|attrgetter|methodcaller|getmembers|__getattribute__|__getattr__|__builtins__|builtins|__self__|__globals__|__code__|__closure__|__func__|__wrapped__|f_globals|f_locals|f_builtins|_getframe|currentframe|FunctionType|CodeType|MethodType|LambdaType|__subclasses__|__init_subclass__|__class_getitem__|metaclass|__set_name__|__prepare__|__mro_entries__|get_objects|get_referrers|get_referents|pickle|_pickle|cloudpickle|dill|marshal|shelve|copyreg|__reduce__|__reduce_ex__|get_type_hints|__annotations__|__annotate__|annotationlib|ForwardRef|resolve_name|pkgutil|pkg_resources|runpy|dictConfig|fileConfig|ctypes)\b|\bsys(?:\s|\\)*\.(?:\s|\\)*modules\b",
    )
    .unwrap()
});
static COMPILE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bcompile\b").unwrap());
/// PEP 263 encoding declaration.
static CODING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[ \t\x0c]*#.*?coding[:=][ \t]*([-\w.]+)").unwrap());

/// Whether the reference view `refs` holds a dynamic-dispatch word. `compile`
/// counts only when it is not an attribute: `re.compile` / `p . compile`
/// (a `.` before it, whitespace and line continuations allowed) do not;
/// bare `compile` (the builtin, `from re import compile`) does.
pub(super) fn has_dynamic_dispatch(refs: &str) -> bool {
    DYNAMIC_RE.is_match(refs)
        || COMPILE_RE.find_iter(refs).any(|m| {
            !refs[..m.start()]
                .trim_end_matches(|c: char| c.is_whitespace() || c == '\\')
                .ends_with('.')
        })
}

/// File-level reasons Python may see different text than we do: a lone CR
/// (Python ends a line there, `str::lines` does not) or a PEP 263 cookie
/// naming an encoding other than UTF-8. The caller has already dropped one
/// leading BOM; any further BOM before a cookie is ignored here too, which
/// can only add ambiguity.
pub(super) fn file_ambiguity(text: &str) -> Option<&'static str> {
    let b = text.as_bytes();
    if b.iter()
        .enumerate()
        .any(|(i, &c)| c == b'\r' && b.get(i + 1) != Some(&b'\n'))
    {
        return Some("lone_cr_line_ending");
    }
    for line in text.split('\n').take(2) {
        if let Some(c) = CODING_RE.captures(line.trim_start_matches('\u{feff}')) {
            let name = c[1].to_ascii_lowercase().replace('_', "-");
            if !matches!(name.as_str(), "utf-8" | "utf8" | "utf-8-sig" | "utf8-sig") {
                return Some("non_utf8_coding_cookie");
            }
            // Python honours the first declaration only.
            break;
        }
    }
    None
}

// ---- logical lines ---------------------------------------------------------

pub(super) struct Logical {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) indent: usize,
    pub(super) text: String,
    pub(super) code: String,
}

fn indent_of(s: &str) -> usize {
    let mut w = 0;
    for c in s.chars() {
        match c {
            ' ' => w += 1,
            '\t' => w = (w / 8 + 1) * 8,
            '\u{c}' => w = 0,
            _ => break,
        }
    }
    w
}

/// Join physical lines into logical lines: open brackets, trailing
/// backslashes and line breaks inside a string literal (`in_string_eol`)
/// continue a line. `structure` has every string's content blanked, so
/// brackets and backslashes inside literals do not count. `None` when a
/// logical line never ends.
pub(super) fn logical_lines(
    structure: &[&str],
    code: &[&str],
    in_string_eol: &[bool],
) -> Option<Vec<Logical>> {
    let n = structure.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if structure[i].trim().is_empty() && !in_string_eol.get(i).copied().unwrap_or(false) {
            i += 1;
            continue;
        }
        let start = i;
        let indent = indent_of(structure[i]);
        let (mut text, mut src) = (String::new(), String::new());
        let mut depth = 0i32;
        loop {
            let l = structure[i];
            text.push_str(l);
            text.push(' ');
            src.push_str(code[i]);
            src.push(' ');
            for c in l.chars() {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth = (depth - 1).max(0),
                    _ => {}
                }
            }
            let cont = l.trim_end().ends_with('\\')
                || depth > 0
                || in_string_eol.get(i).copied().unwrap_or(false);
            i += 1;
            if !cont {
                break;
            }
            if i >= n {
                return None;
            }
        }
        out.push(Logical {
            start,
            end: i - 1,
            indent,
            text,
            code: src,
        });
    }
    Some(out)
}

/// Whether the header has a body on the same line (`def f(): return 1`).
pub(super) fn has_inline_body(text: &str) -> bool {
    let mut depth = 0i32;
    for (i, c) in text.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ':' if depth == 0 => {
                let rest = text[i + 1..].trim().trim_end_matches('\\').trim();
                return !rest.is_empty();
            }
            _ => {}
        }
    }
    false
}

// ---- entry points ----------------------------------------------------------

impl Project {
    /// Resolve `module.path:func` to non-method defs. Errors are for the CLI.
    pub(in crate::audit) fn resolve_entry(
        &self,
        spec: &str,
    ) -> Result<Vec<(usize, usize)>, String> {
        let bad = |why: &str| format!("--entry {spec:?}: {why}");
        let (module, func) = spec
            .split_once(':')
            .ok_or_else(|| bad("expected module.path:func"))?;
        let ident = |s: &str| {
            !s.is_empty()
                && !s.starts_with(|c: char| c.is_ascii_digit())
                && s.chars().all(|c| c.is_alphanumeric() || c == '_')
        };
        if !ident(func) || module.is_empty() || !module.split('.').all(ident) {
            return Err(bad("expected module.path:func with plain identifiers"));
        }
        let path = module.replace('.', "/");
        let wanted = [format!("{path}.py"), format!("{path}/__init__.py")];
        let mut out = Vec::new();
        for (fi, f) in self.files.iter().enumerate() {
            let hit = wanted
                .iter()
                .any(|w| f.rel == *w || f.rel.ends_with(&format!("/{w}")));
            if !hit {
                continue;
            }
            for (bi, b) in f.blocks.iter().enumerate() {
                if !b.is_class && b.name == func && !self.is_method(fi, bi) {
                    out.push((fi, bi));
                }
            }
        }
        if out.is_empty() {
            return Err(bad("no such function found in the analyzed files"));
        }
        Ok(out)
    }

    /// Whether a `from m import *` may expose the module at `rel`.
    pub(super) fn star_import_covers(&self, rel: &str) -> bool {
        if self.star.is_empty() {
            return false;
        }
        if self.star.contains("*") {
            return true;
        }
        let mut parts: Vec<&str> = rel.split('/').collect();
        let file = parts.pop().unwrap_or("");
        let stem = file.strip_suffix(".py").unwrap_or(file);
        let name = if stem == "__init__" {
            parts.last().copied().unwrap_or("")
        } else {
            stem
        };
        self.star.contains(name)
    }
}

// ---- references ------------------------------------------------------------

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Nearest enclosing `def` of `line` (`NONE` for module level).
fn scope_of(f: &PyFile, line: u32) -> u32 {
    let owner = f.line_owner.get(line as usize).copied().unwrap_or(NONE);
    let mut cur = (owner != NONE).then_some(owner as usize);
    while let Some(b) = cur {
        if !f.blocks[b].is_class {
            return b as u32;
        }
        cur = f.blocks[b].parent;
    }
    NONE
}

pub(super) fn scan_refs(
    f: &mut PyFile,
    blank: &str,
    relevant: &HashSet<String>,
    alias: &HashMap<String, BTreeSet<String>>,
    import_bound: &HashSet<String>,
    counts: &mut HashMap<String, Counts>,
) {
    let chars: Vec<char> = blank.chars().collect();
    let n = chars.len();
    let mut import_line = vec![false; f.nlines as usize + 2];
    for &(s, e) in &f.import_spans {
        for l in s..=e.min(f.nlines) {
            import_line[l as usize] = true;
        }
    }
    let mut line = 1u32;
    // (line, scope) of the last reference, so the parent walk runs once per line.
    let mut scope_cache: Option<(u32, u32)> = None;
    let mut last: Option<(String, usize)> = None;
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_ascii_digit() {
            while i < n && is_ident(chars[i]) {
                i += 1;
            }
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < n && is_ident(chars[i]) {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            let prev = last.replace((tok.clone(), i));
            if let Some((p, end)) = prev
                && (p == "def" || p == "class")
                && chars[end..start].iter().all(|c| c.is_whitespace())
            {
                continue; // the defined name is not a reference
            }
            let mut targets: Vec<&str> = Vec::new();
            if relevant.contains(&tok) {
                targets.push(&tok);
            }
            if let Some(set) = alias.get(&tok) {
                for o in set {
                    if *o != tok && relevant.contains(o) {
                        targets.push(o);
                    }
                }
            }
            if targets.is_empty() {
                continue;
            }
            let mut p = start;
            while p > 0 && chars[p - 1].is_whitespace() {
                p -= 1;
            }
            let attr = p > 0 && chars[p - 1] == '.';
            let mut recv_import = false;
            if attr {
                let mut q = p - 1;
                while q > 0 && chars[q - 1].is_whitespace() {
                    q -= 1;
                }
                let mut s = q;
                while s > 0 && is_ident(chars[s - 1]) {
                    s -= 1;
                }
                if s < q {
                    let recv: String = chars[s..q].iter().collect();
                    recv_import = import_bound.contains(&recv);
                }
            }
            let in_import = import_line.get(line as usize).copied().unwrap_or(false);
            let in_main = f.main_line.get(line as usize).copied().unwrap_or(false);
            let scope = match scope_cache {
                Some((l, s)) if l == line => s,
                _ => {
                    let s = scope_of(f, line);
                    scope_cache = Some((line, s));
                    s
                }
            };
            for t in targets {
                let cnt = counts.entry(t.to_string()).or_default();
                if in_import || !attr {
                    cnt.bare += 1;
                } else if recv_import {
                    cnt.attr_import += 1;
                } else {
                    cnt.attr_other += 1;
                }
                f.refs.entry(scope).or_default().push(Ref {
                    name: t.to_string(),
                    attr,
                    recv_import,
                    in_import,
                    in_main,
                });
            }
        } else {
            i += 1;
        }
    }
}
