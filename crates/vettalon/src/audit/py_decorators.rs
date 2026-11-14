//! Decorator allowlist for `py_usage`. This is a child module of `py_usage`
//! (declared there with `#[path]`), so it uses the parent's private types
//! directly. Split out only to keep `py_usage.rs` under the file-size cap.
//!
//! Parsing only records each block's decorator expressions (and, for a
//! property accessor, the `def` it extends). Whether a decorator is benign is
//! decided at classification time, once every file's bindings are known:
//! - a bare allowlisted name `X` is benign only if nothing in the project
//!   binds `X` other than `from <canonical module> import X` (`def cache`,
//!   `cache = registry.register`, `from app import register as cache`,
//!   `for X in`, `with ... as X`, a parameter `X`, `X := ...` all disable it);
//! - `head.X` is benign only if `head` is bound solely by
//!   `import <canonical module>` (optionally `as head`);
//! - `<n>.setter` / `.getter` / `.deleter` is benign only on a def in a class
//!   body whose nearest earlier `def n` in that body is an allowlisted
//!   `@property` (or an accessor of one) and nothing in between rebinds `n`.
//!
//! Any `from m import *` with `m` not a canonical module, and any analyzed
//! file or directory named like a canonical module, disable the allowlist.
//! Binding detection over-approximates: any doubt disables an entry.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use super::Project;
use super::py_parse::{CLASS_RE, DEF_RE, Logical, WORD_RE};

/// `<name>.setter` / `.getter` / `.deleter` (property accessors).
static ACCESSOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^\W\d]\w*)\.(?:setter|getter|deleter)$").unwrap());
/// `callee(args)` where the arguments hold no call, subscript, string,
/// lambda or operator: names, numbers, dots, commas and `=` only.
static PLAIN_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([\w.]+)\(([\w.,=]*)\)$").unwrap());
/// `name` or `head.name`.
static CALLEE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:([^\W\d]\w*)\.)?([^\W\d]\w*)$").unwrap());
static WALRUS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([^\W\d]\w*)\s*:=").unwrap());
static FROM_IMPORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfrom\s+([.\w]+)\s+import\b(.*)$").unwrap());
static IMPORT_KW_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bimport\b(.*)$").unwrap());
static FOR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bfor\b(.*?)\bin\b").unwrap());
static AS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bas\b").unwrap());
/// Statements where every word may be a binding: `def` headers (parameters),
/// `global` / `nonlocal`, `match` `case` patterns.
static ALL_WORDS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:def|global|nonlocal)\b|^\s*case\b").unwrap());
static CLASS_ANY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bclass\s+([^\W\d]\w*)").unwrap());

const DECORATED: &str = "enclosing_decorated";
/// Longest `@property` -> `.setter` -> `.deleter` ... chain followed.
const MAX_ACCESSOR_CHAIN: usize = 64;
/// Furthest back (in logical lines) the accessor base search looks; beyond it
/// the accessor is treated as non-benign. Bounds the work on crafted input.
const MAX_ACCESSOR_SCAN: usize = 2_000;

const FUNCTOOLS: &[&str] = &["functools"];
const TYPING: &[&str] = &["typing", "typing_extensions"];
const BUILTINS: &[&str] = &["builtins"];
/// Every module named in [`ALLOW`].
const CANONICAL: &[&str] = &[
    "abc",
    "builtins",
    "dataclasses",
    "functools",
    "typing",
    "typing_extensions",
];

#[cfg(test)]
#[path = "py_decorators_tests.rs"]
mod tests;

/// One allowlisted decorator: its name, the modules that canonically provide
/// it, whether it may be used bare and / or called with plain arguments, and
/// whether it is allowed on classes only.
struct Allow {
    name: &'static str,
    modules: &'static [&'static str],
    bare: bool,
    called: bool,
    class_only: bool,
}

const fn allow(
    name: &'static str,
    modules: &'static [&'static str],
    bare: bool,
    called: bool,
) -> Allow {
    Allow {
        name,
        modules,
        bare,
        called,
        class_only: false,
    }
}

/// Built-in / stdlib decorators that do not register the function anywhere,
/// so a decorated function keeps the normal rules.
const ALLOW: &[Allow] = &[
    allow("staticmethod", BUILTINS, true, false),
    allow("classmethod", BUILTINS, true, false),
    allow("property", BUILTINS, true, false),
    allow("abstractmethod", &["abc"], true, false),
    allow("cache", FUNCTOOLS, true, false),
    allow("lru_cache", FUNCTOOLS, true, true),
    allow("cached_property", FUNCTOOLS, true, false),
    allow("wraps", FUNCTOOLS, false, true),
    allow("override", TYPING, true, false),
    allow("overload", TYPING, true, false),
    Allow {
        name: "dataclass",
        modules: &["dataclasses"],
        bare: true,
        called: true,
        class_only: true,
    },
];

/// One decorator of a block.
#[derive(Debug, Clone)]
pub(super) struct Deco {
    /// The expression after `@`, all whitespace removed.
    pub(super) expr: String,
    /// For `<n>.setter` / `.getter` / `.deleter` in a class body: the block
    /// of the nearest earlier `def n` in the same body, when nothing in
    /// between rebinds `n`.
    pub(super) base: Option<usize>,
}

/// How a name is bound.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Bind {
    /// `import m` (binds `m`'s first component) / `import m as x`.
    Module(String),
    /// `from m import orig` / `from m import orig as x`.
    From(String, String),
    /// `from m import *`.
    Star(String),
    /// Anything else: def, class, assignment, for, `as`, parameter, ...
    Other,
}

/// Project-wide name bindings that can disable allowlist entries.
#[derive(Debug, Default)]
pub(super) struct Bindings {
    /// Names bound by an import (`Module` / `From`).
    imports: HashMap<String, BTreeSet<Bind>>,
    /// Names bound any other way.
    other: HashSet<String>,
    /// Modules star-imported from.
    star: BTreeSet<String>,
    /// Canonical module names an analyzed file or directory may shadow.
    local: BTreeSet<String>,
}

impl Bindings {
    fn add(&mut self, name: String, b: Bind) {
        match b {
            Bind::Other => {
                self.other.insert(name);
            }
            Bind::Star(m) => {
                self.star.insert(m);
            }
            b => {
                self.imports.entry(name).or_default().insert(b);
            }
        }
    }

    /// Note a project file path: a file or directory named like a canonical
    /// module may shadow it.
    pub(super) fn note_path(&mut self, rel: &str) {
        for comp in rel.split('/') {
            let stem = comp.strip_suffix(".py").unwrap_or(comp);
            if CANONICAL.contains(&stem) {
                self.local.insert(stem.to_string());
            }
        }
    }

    /// Record every name a parsed file may bind. `lgs` are its logical lines
    /// (structure view); `refs` is its reference view, where f-/t-string
    /// expressions are kept, for `:=` inside them.
    pub(super) fn scan(&mut self, lgs: &[Logical], refs: &str) {
        for c in WALRUS_RE.captures_iter(refs) {
            self.add(c[1].to_string(), Bind::Other);
        }
        for lg in lgs {
            for (name, b) in line_binds(&lg.text) {
                self.add(name, b);
            }
        }
    }

    fn canonical(&self, module: &str, a: &Allow) -> bool {
        a.modules.contains(&module) && !self.local.contains(module)
    }

    /// Whether a star import may have bound an allowlisted name.
    fn star_shadows(&self) -> bool {
        self.star
            .iter()
            .any(|m| !CANONICAL.contains(&m.as_str()) || self.local.contains(m))
    }

    /// Bare `@name`: unbound, or bound only by `from <canonical> import name`.
    fn bare_ok(&self, name: &str, a: &Allow) -> bool {
        !self.star_shadows()
            && !self.other.contains(name)
            && self.imports.get(name).is_none_or(|set| {
                set.iter().all(|b| match b {
                    Bind::From(m, orig) => orig == name && self.canonical(m, a),
                    _ => false,
                })
            })
    }

    /// `@head.name`: `head` bound only by `import <canonical> [as head]`.
    fn dotted_ok(&self, head: &str, a: &Allow) -> bool {
        !self.star_shadows()
            && !self.other.contains(head)
            && self.imports.get(head).is_some_and(|set| {
                set.iter().all(|b| match b {
                    Bind::Module(m) => self.canonical(m, a),
                    _ => false,
                })
            })
    }
}

fn words(s: &str, out: &mut Vec<(String, Bind)>) {
    out.extend(
        WORD_RE
            .find_iter(s)
            .map(|w| (w.as_str().to_string(), Bind::Other)),
    );
}

/// Every name a logical line (structure view: string contents blanked) may
/// bind, with how. Over-approximate.
fn line_binds(text: &str) -> Vec<(String, Bind)> {
    let mut out = Vec::new();
    for seg in text.split(';') {
        segment_binds(seg, &mut out);
    }
    out
}

fn segment_binds(seg: &str, out: &mut Vec<(String, Bind)>) {
    if let Some(c) = FROM_IMPORT_RE.captures(seg) {
        from_import(&c[1], &c[2], out);
        return;
    }
    if let Some(c) = IMPORT_KW_RE.captures(seg) {
        plain_import(&c[1], out);
        return;
    }
    if ALL_WORDS_RE.is_match(seg) {
        words(seg, out);
        return;
    }
    if let Some(c) = CLASS_ANY_RE.captures(seg) {
        out.push((c[1].to_string(), Bind::Other));
    }
    for c in FOR_RE.captures_iter(seg) {
        words(&c[1], out);
    }
    for m in AS_RE.find_iter(seg) {
        let rest = seg[m.end()..].trim_start();
        if rest.starts_with(['(', '[']) {
            words(rest, out);
        } else if let Some(w) = WORD_RE.find(rest).filter(|w| w.start() == 0) {
            out.push((w.as_str().to_string(), Bind::Other));
        }
    }
    // Every word left of the last assignment: tuple / starred / chained /
    // annotated targets (attributes and subscripts over-approximate).
    if let Some(end) = last_assignment(seg) {
        words(&seg[..end], out);
    }
}

/// Byte index of the last assignment `=` at bracket depth 0: `=`, `:=` and
/// augmented forms (`+=`, `<<=`, ...), not `==`, `!=`, `<=`, `>=`.
fn last_assignment(seg: &str) -> Option<usize> {
    let b = seg.as_bytes();
    let mut depth = 0i32;
    let mut last = None;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = (depth - 1).max(0),
            b'=' if depth == 0 => {
                if b.get(i + 1) == Some(&b'=') {
                    i += 2;
                    continue;
                }
                let comparison = match i.checked_sub(1).map(|j| b[j]) {
                    Some(b'!') => true,
                    Some(c @ (b'<' | b'>')) => i < 2 || b[i - 2] != c,
                    _ => false,
                };
                if !comparison {
                    last = Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    last
}

fn plain_import(rest: &str, out: &mut Vec<(String, Bind)>) {
    let rest = rest.replace(['\\', '(', ')'], " ");
    for part in rest.split(',') {
        let toks: Vec<&str> = part.split_whitespace().collect();
        match toks[..] {
            [] => {}
            [path] => {
                let head = path.split('.').next().unwrap_or(path).to_string();
                out.push((head.clone(), Bind::Module(head)));
            }
            [path, "as", alias] => out.push((alias.to_string(), Bind::Module(path.to_string()))),
            _ => words(part, out),
        }
    }
}

fn from_import(module: &str, names: &str, out: &mut Vec<(String, Bind)>) {
    let names = names.replace(['\\', '(', ')'], " ");
    for part in names.split(',') {
        let toks: Vec<&str> = part.split_whitespace().collect();
        let bind = |orig: &str| Bind::From(module.to_string(), orig.to_string());
        match toks[..] {
            [] => {}
            ["*"] => out.push(("*".to_string(), Bind::Star(module.to_string()))),
            [orig] => out.push((orig.to_string(), bind(orig))),
            [orig, "as", alias] => out.push((alias.to_string(), bind(orig))),
            _ => words(part, out),
        }
    }
}

/// Whether the logical line may bind `n` (`:=` checked on the code view, so
/// f-string expressions count too).
fn binds_name(lg: &Logical, n: &str) -> bool {
    line_binds(&lg.text).iter().any(|(w, _)| w == n)
        || WALRUS_RE.captures_iter(&lg.code).any(|c| &c[1] == n)
}

/// The decorators stacked directly above the `def` / `class` header
/// `lgs[k]` (same indentation, starting with `@`), top to bottom.
/// `in_class`: the header is in a class body. `header` maps earlier header
/// lines (logical line index) to their block index in the same file.
pub(super) fn decorators_of(
    lgs: &[Logical],
    k: usize,
    in_class: bool,
    header: &HashMap<usize, usize>,
) -> Vec<Deco> {
    let indent = lgs[k].indent;
    let mut j = k;
    while j > 0 && lgs[j - 1].indent == indent && lgs[j - 1].text.trim_start().starts_with('@') {
        j -= 1;
    }
    (j..k)
        .map(|i| {
            let text = lgs[i].text.trim_start();
            let expr: String = text[1..].chars().filter(|c| !c.is_whitespace()).collect();
            let base = ACCESSOR_RE
                .captures(&expr)
                .filter(|_| in_class)
                .and_then(|c| accessor_base(lgs, j, &c[1], header));
            Deco { expr, base }
        })
        .collect()
}

/// The block of the nearest `def n` before line `j` at the same indentation
/// (stopping at a dedent), provided no line in between binds `n` in that
/// scope (def / class bodies are their own scopes and are skipped).
fn accessor_base(
    lgs: &[Logical],
    j: usize,
    n: &str,
    header: &HashMap<usize, usize>,
) -> Option<usize> {
    let indent = lgs[j].indent;
    let mut i = j;
    let base = loop {
        i = i.checked_sub(1)?;
        if j - i > MAX_ACCESSOR_SCAN {
            return None;
        }
        let lg = &lgs[i];
        if lg.indent < indent {
            return None;
        }
        if lg.indent > indent {
            continue;
        }
        let t = lg.text.trim_start();
        if let Some(c) = DEF_RE.captures(t) {
            if &c[1] == n {
                break i;
            }
        } else if CLASS_RE.captures(t).is_some_and(|c| &c[1] == n) {
            return None;
        }
    };
    let mut body = Some(indent);
    for lg in &lgs[base + 1..j] {
        if body.is_some_and(|d| lg.indent > d) {
            continue;
        }
        body = None;
        let t = lg.text.trim_start();
        if let Some(c) = DEF_RE.captures(t).or_else(|| CLASS_RE.captures(t)) {
            if &c[1] == n {
                return None;
            }
            body = Some(lg.indent);
        } else if binds_name(lg, n) {
            return None;
        }
    }
    header.get(&base).copied()
}

impl Project {
    /// Why block `bi` of file `fi` counts as decorated, or `None` when it has
    /// no decorator or only allowlisted ones. The first offending decorator
    /// (top to bottom) gives the reason: `enclosing_decorated`, or
    /// `enclosing_decorated:shadowed_allowlist:<name>` when an allowlisted
    /// decorator is disabled by a project binding.
    pub(super) fn decoration(&self, fi: usize, bi: usize) -> Option<String> {
        let b = &self.files[fi].blocks[bi];
        b.decorators.iter().find_map(|d| {
            if ACCESSOR_RE.is_match(&d.expr) {
                let ok = d.base.is_some_and(|base| self.is_property(fi, base));
                (!ok).then(|| DECORATED.to_string())
            } else {
                self.check_decorator(&d.expr, b.is_class).err()
            }
        })
    }

    /// `Some(enclosing_decorated)` when any of the `blocks` (a block and its
    /// ancestors) has a decorator at all. Such a block is never `not_observed`:
    /// the allowlist cannot be proven unspoofable.
    pub(super) fn any_decorated(&self, fi: usize, blocks: &[usize]) -> Option<&'static str> {
        let f = &self.files[fi];
        blocks
            .iter()
            .any(|&b| !f.blocks[b].decorators.is_empty())
            .then_some(DECORATED)
    }

    /// A non-accessor decorator: `Ok(true)` for an allowlisted `property`,
    /// `Ok(false)` for any other allowlisted one, else the reason.
    fn check_decorator(&self, expr: &str, is_class: bool) -> Result<bool, String> {
        let plain = || DECORATED.to_string();
        let (callee, called) = match PLAIN_CALL_RE.captures(expr) {
            Some(c) => (c.get(1).map_or("", |m| m.as_str()), true),
            None => (expr, false),
        };
        let c = CALLEE_RE.captures(callee).ok_or_else(plain)?;
        let name = c.get(2).map_or("", |m| m.as_str());
        let a = ALLOW.iter().find(|a| a.name == name).ok_or_else(plain)?;
        let shape_ok = if called { a.called } else { a.bare };
        if !shape_ok || (a.class_only && !is_class) {
            return Err(plain());
        }
        let ok = match c.get(1) {
            None => self.deco.bare_ok(name, a),
            Some(head) => self.deco.dotted_ok(head.as_str(), a),
        };
        if ok {
            Ok(name == "property")
        } else {
            Err(format!("{DECORATED}:shadowed_allowlist:{callee}"))
        }
    }

    /// Whether block `bi` is a property: a def whose decorators are all
    /// allowlisted and include `property`, or an accessor of one (followed
    /// iteratively, at most [`MAX_ACCESSOR_CHAIN`] steps).
    fn is_property(&self, fi: usize, mut bi: usize) -> bool {
        for _ in 0..MAX_ACCESSOR_CHAIN {
            let b = &self.files[fi].blocks[bi];
            if b.is_class {
                return false;
            }
            let (mut prop, mut next) = (false, None);
            for d in &b.decorators {
                if ACCESSOR_RE.is_match(&d.expr) {
                    match d.base {
                        Some(x) if next.is_none() => next = Some(x),
                        _ => return false,
                    }
                } else {
                    match self.check_decorator(&d.expr, false) {
                        Ok(p) => prop |= p,
                        Err(_) => return false,
                    }
                }
            }
            match (prop, next) {
                (true, None) => return true,
                (false, Some(x)) => bi = x,
                _ => return false,
            }
        }
        false
    }
}
