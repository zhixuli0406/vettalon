//! Experimental, name-based static usage analysis of a Python project, for
//! `vettalon cbom-check`.
//!
//! Honesty policy (mirrors `docs/REACHABILITY.md`): this is **not** execution
//! evidence and `not_observed` is **never** proof of absence or safety. Edges
//! are name-based and over-approximate; anything that cannot be decided fails
//! closed to `unknown`.
//!
//! What it does, per `.py` file (no new dependencies, no real parser):
//! 0. Files Python may read differently fail closed (`not_observed` withheld
//!    project-wide): a lone CR line ending or a non-UTF-8 PEP 263 cookie make
//!    the file ambiguous; a non-ASCII character in code (Python NFKC-normalises
//!    identifiers) marks the project incomplete. One leading UTF-8 BOM is
//!    dropped after hashing, as Python does.
//! 1. [`lex`] blanks comments and the contents of plain string literals
//!    (docstrings included) so a name inside a string never counts. f-/t-string
//!    contents are kept verbatim because their `{...}` parts are code
//!    (over-approximation: more references).
//! 2. Logical lines (bracket / backslash / multi-line string continuation
//!    joined) are cut into `def` / `async def` / `class` blocks by indentation,
//!    with spans, decorators and the `if __name__ == "__main__":` span.
//! 3. Imports build an alias map (`from a import f as g`: `g` refers to `f`)
//!    and the set of import-bound names (valid receivers of `recv.name`).
//! 4. Identifier tokens that name a defined function (or an alias of one) are
//!    kept as references, each owned by its nearest enclosing `def` (or the
//!    module top level; class bodies run when their enclosing scope runs).
//!
//! Reachability is a BFS from entry points over those references. Entry
//! points are all module top-level code, the `__main__` block, and
//! user-supplied `module.path:func` specs. Methods (defs directly inside a
//! class) are never labelled `reachable`: attribute dispatch is not modelled,
//! and an attribute reference `x.name` on a receiver that is not an import
//! makes no edge, but it still counts as a textual reference (so the function
//! is `unknown`, never `not_observed`).

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::schema::sha256_hex;

#[path = "py_lex.rs"]
mod py_lex;
use py_lex::lex;

#[path = "py_parse.rs"]
mod py_parse;
use super::src_io::{clip_label, file_id, read_capped};
use py_parse::*;

#[path = "py_decorators.rs"]
mod py_decorators;
use py_decorators::{Bindings, Deco, decorators_of};

/// Cap on the total analyzed source (bytes).
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Cap on the number of analyzed `.py` files.
pub const MAX_FILES: usize = 20_000;
/// Cap on one analyzed file (bytes); also the cap for an occurrence's file.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Directories never walked. Skipping any of them except
/// [`SILENT_SKIP_DIRS`] marks the project not fully analyzed
/// (`skipped_directory`): code there could reference a function.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "site-packages",
];
/// Skipped directories that never hold source Python imports.
pub const SILENT_SKIP_DIRS: &[&str] = &[".git", "__pycache__"];
const MAX_DEPTH: usize = 64;
const MAX_CHAIN: usize = 50;
const NONE: u32 = u32::MAX;

/// The label of one occurrence. `NotObserved` is not "unreachable".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Reachable,
    NotObserved,
    Unknown,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Reachable => "reachable",
            Label::NotObserved => "not_observed",
            Label::Unknown => "unknown",
        }
    }
}

/// The result for one occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub label: Label,
    pub reasons: Vec<String>,
    /// Dotted qualified name of the enclosing function (`Class.method`).
    pub enclosing_function: Option<String>,
    /// Name-based path from an entry point (only for `reachable`).
    pub chain: Vec<String>,
}

impl Verdict {
    fn unknown(reason: &str) -> Verdict {
        Verdict {
            label: Label::Unknown,
            reasons: vec![reason.to_string()],
            enclosing_function: None,
            chain: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct Block {
    is_class: bool,
    name: String,
    qual: String,
    /// First line that belongs to the body (header lines belong to the parent).
    body_start: u32,
    end: u32,
    /// Judged at classification time (`Project::decoration`).
    decorators: Vec<Deco>,
    parent: Option<usize>,
}

#[derive(Debug, Clone)]
struct Ref {
    name: String,
    attr: bool,
    recv_import: bool,
    in_import: bool,
    in_main: bool,
}

#[derive(Debug, Default)]
struct PyFile {
    rel: String,
    sha256: String,
    nlines: u32,
    ambiguous: bool,
    blank: String,
    blocks: Vec<Block>,
    /// Innermost block whose body holds the line (index `nlines + 1`).
    line_owner: Vec<u32>,
    main_spans: Vec<(u32, u32)>,
    /// Whether a line (index `nlines + 1`) is inside a `__main__` block body.
    main_line: Vec<bool>,
    import_spans: Vec<(u32, u32)>,
    /// Nearest enclosing def (or `NONE` for module level) -> references.
    refs: HashMap<u32, Vec<Ref>>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    bare: usize,
    attr_import: usize,
    attr_other: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Node {
    Root(usize, bool),
    Def(usize, usize),
    Entry(usize),
}

/// BFS result from the entry points; see [`Project::reach`].
#[derive(Debug)]
pub struct Reach {
    parent: HashMap<Node, Option<Node>>,
    entries: Vec<String>,
}

/// A loaded Python project.
#[derive(Debug, Default)]
pub struct Project {
    files: Vec<PyFile>,
    index: HashMap<String, usize>,
    skipped: BTreeMap<String, &'static str>,
    limit: Option<&'static str>,
    incomplete: Option<&'static str>,
    dynamic: bool,
    all_names: HashSet<String>,
    star: HashSet<String>,
    import_bound: HashSet<String>,
    alias: HashMap<String, BTreeSet<String>>,
    defs: HashMap<String, Vec<(usize, usize)>>,
    counts: HashMap<String, Counts>,
    /// Project-wide bindings that can disable decorator allowlist entries.
    deco: Bindings,
}

impl Project {
    /// Walk `root` (symlinks are never followed) and analyze every `.py`.
    pub fn load(root: &Path) -> Project {
        let mut p = Project::default();
        // (relative path, path, walk-time (length, (dev, ino)))
        type Found = (
            String,
            std::path::PathBuf,
            Option<(u64, Option<(u64, u64)>)>,
        );
        let mut found: Vec<Found> = Vec::new();
        let mut stack = vec![(root.to_path_buf(), 0usize)];
        'walk: while let Some((dir, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                p.note_incomplete("directory_too_deep");
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&dir) else {
                p.note_incomplete("directory_unreadable");
                continue;
            };
            for entry in rd {
                let Ok(entry) = entry else {
                    p.note_incomplete("directory_unreadable");
                    continue;
                };
                let name = entry.file_name();
                let Some(nm) = name.to_str() else {
                    p.note_incomplete("non_utf8_path");
                    continue;
                };
                let path = entry.path();
                let Ok(ft) = entry.file_type() else {
                    p.note_incomplete("directory_unreadable");
                    continue;
                };
                if ft.is_symlink() {
                    let to_dir = std::fs::metadata(&path).is_ok_and(|m| m.is_dir());
                    if nm.ends_with(".py") || (to_dir && !SILENT_SKIP_DIRS.contains(&nm)) {
                        p.note_incomplete("symlink_not_followed");
                    }
                } else if ft.is_dir() {
                    if !SKIP_DIRS.contains(&nm) {
                        stack.push((path, depth + 1));
                    } else if !SILENT_SKIP_DIRS.contains(&nm) {
                        p.note_incomplete("skipped_directory");
                    }
                } else if ft.is_file() && nm.ends_with(".py") {
                    let Ok(rel) = path.strip_prefix(root) else {
                        continue;
                    };
                    let rel = rel
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/");
                    // `DirEntry::metadata` does not follow symlinks.
                    let meta = entry.metadata().ok().map(|m| (m.len(), file_id(&m)));
                    found.push((rel, path, meta));
                    if found.len() > MAX_FILES {
                        p.limit = Some("file_count_limit_exceeded");
                        break 'walk;
                    }
                }
            }
        }
        if p.limit.is_some() {
            return p;
        }
        found.sort();
        let mut total = 0u64;
        for (rel, path, meta) in found {
            let Some((len, id)) = meta else {
                p.skip(&rel, "file_unreadable");
                continue;
            };
            if len > MAX_FILE_BYTES {
                p.skip(&rel, "file_too_large");
                continue;
            }
            total += len;
            if total > MAX_TOTAL_BYTES {
                p.limit = Some("source_size_limit_exceeded");
                return p;
            }
            // Capped read: a file that grew after the metadata check still stops at the cap.
            match read_capped(&path, MAX_FILE_BYTES, id) {
                Err(_) => p.skip(&rel, "file_unreadable"),
                Ok(None) => p.skip(&rel, "file_too_large"),
                Ok(Some(bytes)) => match String::from_utf8(bytes) {
                    Err(_) => p.skip(&rel, "file_not_utf8"),
                    Ok(text) => p.add_source(&rel, &text),
                },
            }
        }
        p.finalize();
        p
    }

    /// Build a project from in-memory sources (`(relative path, text)`).
    pub fn from_sources(sources: &[(&str, &str)]) -> Project {
        let mut p = Project::default();
        let mut sorted: Vec<_> = sources.to_vec();
        sorted.sort();
        for (rel, text) in sorted {
            p.add_source(rel, text);
        }
        p.finalize();
        p
    }

    fn note_incomplete(&mut self, why: &'static str) {
        self.incomplete.get_or_insert(why);
    }

    fn skip(&mut self, rel: &str, why: &'static str) {
        self.skipped.insert(rel.to_string(), why);
        self.deco.note_path(rel);
        self.note_incomplete(why);
    }

    /// Number of analyzed files.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Why this project cannot support `not_observed`, if so.
    pub fn incomplete_reason(&self) -> Option<&'static str> {
        self.limit.or(self.incomplete)
    }

    /// Whether a dynamic-dispatch word (`getattr`, `eval`, `sys.modules`, ...)
    /// occurs anywhere in code or an f-/t-string.
    pub fn has_dynamic_dispatch(&self) -> bool {
        self.dynamic
    }

    /// SHA-256 of the analyzed files: for each file sorted by relative path,
    /// `"<rel>\0<file sha256 hex>\n"`.
    pub fn tree_sha256(&self) -> String {
        let mut h = Sha256::new();
        for f in &self.files {
            h.update(f.rel.as_bytes());
            h.update([0u8]);
            h.update(f.sha256.as_bytes());
            h.update(b"\n");
        }
        hex::encode(h.finalize())
    }

    /// `(relative path, file sha256 hex)` of every analyzed file.
    pub fn file_hashes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.files
            .iter()
            .map(|f| (f.rel.as_str(), f.sha256.as_str()))
    }

    /// SHA-256 of an analyzed file.
    pub fn file_sha256(&self, rel: &str) -> Option<&str> {
        self.index.get(rel).map(|&i| self.files[i].sha256.as_str())
    }

    // ---- pass 1: structure -------------------------------------------------

    fn add_source(&mut self, rel: &str, text: &str) {
        let sha256 = sha256_hex(text.as_bytes());
        // Python drops one leading BOM; so does every later step (line-1
        // headers and decorators must match). Line numbers are unchanged.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut f = PyFile {
            rel: rel.to_string(),
            sha256,
            nlines: text.lines().count() as u32,
            ..PyFile::default()
        };
        let idx = self.files.len();
        self.index.insert(rel.to_string(), idx);
        self.deco.note_path(rel);
        if let Some(why) = file_ambiguity(text) {
            f.ambiguous = true;
            self.note_incomplete(why);
            self.files.push(f);
            return;
        }
        let lexed = lex(text);
        let parsed = lexed.as_ref().and_then(|lx| {
            let sl: Vec<&str> = lx.structure.lines().collect();
            let cl: Vec<&str> = lx.code.lines().collect();
            if sl.len() == cl.len() && sl.len() == f.nlines as usize {
                logical_lines(&sl, &cl, &lx.in_string_eol)
            } else {
                None
            }
        });
        let (Some(lx), Some(lgs)) = (lexed, parsed) else {
            f.ambiguous = true;
            self.note_incomplete("file_parse_ambiguity");
            self.files.push(f);
            return;
        };
        if lx.non_ascii_code {
            self.note_incomplete("non_ascii_identifier_possible");
        }
        if has_dynamic_dispatch(&lx.refs) {
            self.dynamic = true;
        }
        self.structure(&mut f, &lgs);
        self.deco.scan(&lgs, &lx.refs);
        f.blank = lx.refs;
        self.files.push(f);
    }

    fn structure(&mut self, f: &mut PyFile, lgs: &[Logical]) {
        let mut stack: Vec<usize> = Vec::new();
        // Header logical line -> block index (resolves property accessors).
        let mut header: HashMap<usize, usize> = HashMap::new();
        for (k, lg) in lgs.iter().enumerate() {
            let text = lg.text.trim_start();
            let start_line = lg.start as u32 + 1;
            if IMPORT_RE.is_match(text) {
                f.import_spans.push((start_line, lg.end as u32 + 1));
                self.parse_import(text);
            }
            if lg.text.contains("__all__") {
                for w in WORD_RE.find_iter(&lg.code) {
                    self.all_names.insert(w.as_str().to_string());
                }
            }
            let span_end = |k: usize| -> u32 {
                let mut j = k;
                while j + 1 < lgs.len() && lgs[j + 1].indent > lgs[k].indent {
                    j += 1;
                }
                lgs[j].end as u32 + 1
            };
            if MAIN_RE.is_match(lg.code.trim_start()) {
                f.main_spans.push((start_line, span_end(k)));
            }
            let (is_class, name) = if let Some(c) = DEF_RE.captures(text) {
                (false, c[1].to_string())
            } else if let Some(c) = CLASS_RE.captures(text) {
                (true, c[1].to_string())
            } else {
                continue;
            };
            let end = span_end(k);
            while let Some(&top) = stack.last() {
                if f.blocks[top].end < start_line {
                    stack.pop();
                } else {
                    break;
                }
            }
            let parent = stack.last().copied();
            let qual = clip_label(match parent {
                Some(p) => format!("{}.{}", f.blocks[p].qual, name),
                None => name.clone(),
            });
            // Benign-ness needs project-wide bindings: decided in `classify`.
            let in_class = parent.is_some_and(|p| f.blocks[p].is_class);
            let decorators = decorators_of(lgs, k, in_class, &header);
            let body_start = if has_inline_body(text) {
                start_line
            } else {
                lg.end as u32 + 2
            };
            if !is_class {
                self.defs
                    .entry(name.clone())
                    .or_default()
                    .push((self.files.len(), f.blocks.len()));
            }
            f.blocks.push(Block {
                is_class,
                name,
                qual,
                body_start,
                end: end.max(lg.end as u32 + 1),
                decorators,
                parent,
            });
            header.insert(k, f.blocks.len() - 1);
            stack.push(f.blocks.len() - 1);
        }
        f.line_owner = vec![NONE; f.nlines as usize + 2];
        for (bi, b) in f.blocks.iter().enumerate() {
            for l in b.body_start..=b.end.min(f.nlines) {
                f.line_owner[l as usize] = bi as u32;
            }
        }
        f.main_line = vec![false; f.nlines as usize + 2];
        for &(s, e) in &f.main_spans {
            for l in s + 1..=e.min(f.nlines) {
                f.main_line[l as usize] = true;
            }
        }
    }

    fn parse_import(&mut self, text: &str) {
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if let Some(rest) = flat.strip_prefix("import ") {
            for part in rest.split(',') {
                let toks: Vec<&str> = part.split_whitespace().collect();
                if let Some(first) = toks.first() {
                    for comp in first.split('.').filter(|c| !c.is_empty()) {
                        self.import_bound.insert(comp.to_string());
                    }
                }
                if let [_, "as", alias] = toks[..] {
                    self.import_bound.insert(alias.to_string());
                }
            }
        } else if let Some(c) = FROM_RE.captures(&flat) {
            let module = &c[1];
            for comp in module.split('.').filter(|c| !c.is_empty()) {
                self.import_bound.insert(comp.to_string());
            }
            let names = c[2]
                .trim()
                .trim_matches(|ch: char| ch == '(' || ch == ')')
                .trim();
            if names == "*" {
                let last = module.rsplit('.').find(|c| !c.is_empty()).unwrap_or("*");
                self.star.insert(last.to_string());
                return;
            }
            for part in names.split(',') {
                let toks: Vec<&str> = part.split_whitespace().collect();
                match toks[..] {
                    [orig] => {
                        self.import_bound.insert(orig.to_string());
                    }
                    [orig, "as", alias] => {
                        self.import_bound.insert(orig.to_string());
                        self.import_bound.insert(alias.to_string());
                        self.alias
                            .entry(alias.to_string())
                            .or_default()
                            .insert(orig.to_string());
                    }
                    _ => {}
                }
            }
        }
    }

    // ---- pass 2: references ------------------------------------------------

    fn finalize(&mut self) {
        let mut relevant: HashSet<String> = self.defs.keys().cloned().collect();
        relevant.extend(self.alias.keys().cloned());
        let mut counts: HashMap<String, Counts> = HashMap::new();
        for f in &mut self.files {
            if f.ambiguous {
                continue;
            }
            let blank = std::mem::take(&mut f.blank);
            scan_refs(
                f,
                &blank,
                &relevant,
                &self.alias,
                &self.import_bound,
                &mut counts,
            );
        }
        self.counts = counts;
    }

    // ---- reachability ------------------------------------------------------

    fn is_method(&self, fi: usize, bi: usize) -> bool {
        let f = &self.files[fi];
        f.blocks[bi].parent.is_some_and(|p| f.blocks[p].is_class)
    }

    /// Defs named by `n`'s references. Each name is expanded at most once per
    /// BFS (`expanded`): its first expansion reaches every def of that name.
    fn successors<'a>(&'a self, n: Node, expanded: &mut HashSet<&'a str>, out: &mut Vec<Node>) {
        let (fi, key, main) = match n {
            Node::Root(fi, main) => (fi, NONE, Some(main)),
            Node::Def(fi, bi) => (fi, bi as u32, None),
            Node::Entry(_) => return,
        };
        let Some(refs) = self.files[fi].refs.get(&key) else {
            return;
        };
        for r in refs {
            if r.in_import || (r.attr && !r.recv_import) || main.is_some_and(|m| m != r.in_main) {
                continue;
            }
            if !expanded.insert(r.name.as_str()) {
                continue;
            }
            for &(fj, bj) in self.defs.get(&r.name).into_iter().flatten() {
                if !self.is_method(fj, bj) {
                    out.push(Node::Def(fj, bj));
                }
            }
        }
    }

    /// BFS from every module top level, every `__main__` block and `entries`.
    pub fn reach(&self, entries: &[String]) -> Result<Reach, String> {
        let mut parent: HashMap<Node, Option<Node>> = HashMap::new();
        let mut queue: VecDeque<Node> = VecDeque::new();
        for (fi, f) in self.files.iter().enumerate() {
            if f.ambiguous {
                continue;
            }
            for main in [false, true] {
                if main && f.main_spans.is_empty() {
                    continue;
                }
                parent.insert(Node::Root(fi, main), None);
                queue.push_back(Node::Root(fi, main));
            }
        }
        for (i, spec) in entries.iter().enumerate() {
            let targets = self.resolve_entry(spec)?;
            parent.insert(Node::Entry(i), None);
            for (fi, bi) in targets {
                let n = Node::Def(fi, bi);
                if let Entry::Vacant(e) = parent.entry(n) {
                    e.insert(Some(Node::Entry(i)));
                    queue.push_back(n);
                }
            }
        }
        let mut succ = Vec::new();
        let mut expanded: HashSet<&str> = HashSet::new();
        while let Some(n) = queue.pop_front() {
            succ.clear();
            self.successors(n, &mut expanded, &mut succ);
            for &s in &succ {
                if let Entry::Vacant(e) = parent.entry(s) {
                    e.insert(Some(n));
                    queue.push_back(s);
                }
            }
        }
        Ok(Reach {
            parent,
            entries: entries.to_vec(),
        })
    }

    fn node_label(&self, n: Node, reach: &Reach) -> String {
        clip_label(match n {
            Node::Root(fi, false) => format!("{}:<module>", self.files[fi].rel),
            Node::Root(fi, true) => format!("{}:<__main__>", self.files[fi].rel),
            Node::Def(fi, bi) => {
                let f = &self.files[fi];
                format!("{}:{}", f.rel, f.blocks[bi].qual)
            }
            Node::Entry(i) => format!("--entry {}", reach.entries[i]),
        })
    }

    fn chain_to(&self, target: Node, reach: &Reach) -> Vec<String> {
        let mut nodes = vec![target];
        let mut cur = target;
        while let Some(Some(p)) = reach.parent.get(&cur) {
            nodes.push(*p);
            cur = *p;
        }
        nodes.reverse();
        let mut labels: Vec<String> = nodes.iter().map(|&n| self.node_label(n, reach)).collect();
        if labels.len() > MAX_CHAIN {
            let tail = labels.split_off(labels.len() - (MAX_CHAIN / 2 - 1));
            labels.truncate(MAX_CHAIN / 2);
            labels.push("...".to_string());
            labels.extend(tail);
        }
        labels
    }

    // ---- classification ----------------------------------------------------

    /// Label one occurrence at `rel:line` (1-based, `rel` uses `/`).
    pub fn classify(&self, reach: &Reach, rel: &str, line: u32) -> Verdict {
        // The caller (cbom_check) dispatches by extension; a non-`.py` path is
        // simply not an analyzed file here.
        if let Some(why) = self.limit {
            return Verdict::unknown(why);
        }
        let Some(&fi) = self.index.get(rel) else {
            return Verdict::unknown(
                self.skipped
                    .get(rel)
                    .copied()
                    .unwrap_or("file_not_analyzed"),
            );
        };
        let f = &self.files[fi];
        if f.ambiguous {
            return Verdict::unknown("parse_ambiguity");
        }
        if line == 0 || line > f.nlines {
            return Verdict::unknown("line_out_of_range");
        }
        let owner = f.line_owner[line as usize];
        // The innermost block, then the nearest enclosing def (class bodies
        // run when their enclosing scope runs).
        let mut cur = (owner != NONE).then_some(owner as usize);
        let mut ancestors = Vec::new();
        while let Some(b) = cur {
            ancestors.push(b);
            cur = f.blocks[b].parent;
        }
        // The innermost block with a non-allowlisted decorator gives the reason.
        let decorated = ancestors.iter().find_map(|&b| self.decoration(fi, b));
        let scope = ancestors.iter().copied().find(|&b| !f.blocks[b].is_class);
        let Some(bi) = scope else {
            if let Some(why) = decorated {
                return Verdict::unknown(&why);
            }
            let in_main = f.main_line.get(line as usize).copied().unwrap_or(false);
            let (node, reason) = if in_main {
                (Node::Root(fi, true), "main_block")
            } else {
                (Node::Root(fi, false), "module_top_level")
            };
            return Verdict {
                label: Label::Reachable,
                reasons: vec![reason.to_string()],
                enclosing_function: None,
                chain: vec![self.node_label(node, reach)],
            };
        };
        let b = &f.blocks[bi];
        let mut v = Verdict {
            label: Label::Unknown,
            reasons: Vec::new(),
            enclosing_function: Some(b.qual.clone()),
            chain: Vec::new(),
        };
        if let Some(why) = decorated {
            v.reasons.push(why);
            return v;
        }
        if b.name.starts_with("__") && b.name.ends_with("__") && b.name.len() > 4 {
            v.reasons.push("dunder_name_implicit_call".into());
            return v;
        }
        let method = self.is_method(fi, bi);
        let c = self.counts.get(&b.name).copied().unwrap_or_default();
        if method {
            if c.attr_import + c.attr_other > 0 {
                v.reasons.push("method_attribute_call_exists".into());
                return v;
            }
            if c.bare > 0 {
                v.reasons.push("method_referenced_not_modeled".into());
                return v;
            }
        } else {
            let node = Node::Def(fi, bi);
            if reach.parent.contains_key(&node) {
                v.label = Label::Reachable;
                v.reasons.push("name_based_chain_from_entry".into());
                v.chain = self.chain_to(node, reach);
                return v;
            }
        }
        // From here only `not_observed` or `unknown` remain.
        if let Some(why) = self.incomplete {
            v.reasons.push(format!("project_not_fully_analyzed:{why}"));
            return v;
        }
        if self.dynamic {
            v.reasons.push("dynamic_dispatch_in_project".into());
            return v;
        }
        if self.all_names.contains(&b.name) {
            v.reasons.push("name_in_dunder_all".into());
            return v;
        }
        if !method && self.star_import_covers(&f.rel) {
            v.reasons.push("star_import_may_expose".into());
            return v;
        }
        // Any textual reference counts, including `x.name` on a receiver that
        // is not an import (`m = keys; m.name()`): no edge, but not absent.
        if !method && c.bare + c.attr_import + c.attr_other > 0 {
            v.reasons.push("referenced_but_no_entry_path".into());
            return v;
        }
        // A decorated block is never `not_observed`, benign decorator or not.
        if let Some(why) = self.any_decorated(fi, &ancestors) {
            v.reasons.push(why.into());
            return v;
        }
        v.label = Label::NotObserved;
        v.reasons.push("no_textual_reference".into());
        v
    }
}

#[cfg(test)]
#[path = "py_usage_tests.rs"]
mod tests;
