//! Experimental, name-based static usage analysis of a Java project, for
//! `vettalon cbom-check`. The Java counterpart of [`super::py_usage`]: the
//! same [`Label`] / [`Verdict`] types, the same reason-string style and the
//! same fail-closed policy.
//!
//! Honesty policy (mirrors `docs/REACHABILITY.md`): this is **not** execution
//! evidence and `not_observed` is **never** proof of absence or safety. Edges
//! are name-based and over-approximate; anything that cannot be decided fails
//! closed to `unknown`.
//!
//! What it does (no new dependencies, no real parser):
//! 0. The walk ([`JavaProject::load`]) never follows symlinks and collects
//!    `.java` sources plus config files (`CONFIG_EXTS` and every file below
//!    a `META-INF/` directory); the identifiers of `module-info.java`
//!    `provides` / `uses` directives count as config words too. Other JVM
//!    sources and templates (`.html` with
//!    a Thymeleaf attribute included), compiled code, archives and native
//!    libraries inside the root, a nested `.git` directory and imports of
//!    reflective libraries (`REFLECTIVE_LIBRARIES`) mark the project not
//!    fully analyzed.
//! 1. Each `.java` file goes through [`super::java_lex`] (comments and literal
//!    contents blanked) and [`super::java_parse`] (types and members with line
//!    ranges and byte spans). A lexer or parser ambiguity makes that file's
//!    lines `unknown` and the project incomplete.
//! 2. The identifier tokens of the blanked code are attributed to the
//!    innermost member whose byte span holds them and become edges:
//!    `name(` (any receiver) and `X::name` → every method named `name`;
//!    `new X(` / `X::new` → an instance of every type named `X`; `super(` →
//!    an instance of the supertype; `this(` → an instance of the own type.
//!    An instance reaches every constructor, instance initializer and
//!    instance field initializer of its type; any reached member initializes
//!    its declaring type, which reaches the static initializers and static
//!    field initializers (JLS 12.4.1).
//! 3. Reachability is a BFS (explicit queue) from every launcher `main` and
//!    from `--entry package.Class:method` specs. Each called name, each
//!    instantiated type name and each initialized supertype name is
//!    expanded once.
//!
//! `not_observed` needs a complete project, no unknown trigger, and the
//! method name appearing as an identifier token nowhere except as its own
//! declaration. A line held by several members that do not enclose one
//! another is `reachable` when any of them is, else `unknown`
//! (`line_shared_by_members`). A supertype counts as a project type only
//! when it resolves to exactly one (see `resolve_super`).
//!
//! Untrusted input: every pass is linear or `n log n` in the input (members
//! per file are capped by the parser), the per-row work of
//! [`JavaProject::classify`] does not grow with the project, and a worklist
//! over [`MAX_WORKLIST`] entries makes the affected labels `unknown`
//! (`analysis_limit`). The type names kept for the whole project (qualified
//! and `package.`-qualified names, map keys) share one budget,
//! [`MAX_PROJECT_NAME_BYTES`]: a file that would exceed it is not analyzed
//! and the project is incomplete (`analysis_limit`). Chains are computed
//! from per-node links recorded by the BFS, in at most [`MAX_CHAIN`] steps.
//!
//! Known gap (fails toward `unknown`, never toward `not_observed`): lambda /
//! anonymous-class bodies belong to their enclosing member (extra edges).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::bytes::Regex;

use super::java_lex::{JavaLexed, lex};
use super::java_parse::{JavaFile, Member, MemberKind, TypeKind, parse};
pub use super::py_usage::{Label, Verdict};
use super::py_usage::{MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES};
use super::schema::sha256_hex;
use super::src_io::{MAX_LABEL_CHARS, clip_label, file_id, read_capped};

/// Directories never walked. Skipping any of them except a
/// [`SILENT_SKIP_DIRS`] entry directly under the root marks the project not
/// fully analyzed (`skipped_directory`). `target/` and `build/` are walked.
pub const SKIP_DIRS: &[&str] = &[".git", "node_modules", ".gradle", ".idea"];
/// Skipped directories that never hold project sources, silent only directly
/// under the root (a nested `.git` may be a vendored repository whose
/// sources are not walked).
pub const SILENT_SKIP_DIRS: &[&str] = &[".git"];
/// Cap on one config file read for `named_in_config_file` (bytes).
pub const MAX_CONFIG_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Cap on all config files read (bytes).
pub const MAX_CONFIG_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
/// Cap on the number of config files read.
pub const MAX_CONFIG_FILES: usize = 20_000;
const MAX_DEPTH: usize = 64;
const MAX_CHAIN: usize = 50;
/// Most pending entries of a worklist (the reachability queue, the
/// external-supertype propagation); more makes the labels that depend on it
/// `unknown` (`analysis_limit`).
const MAX_WORKLIST: usize = 100_000;
const ANALYSIS_LIMIT: &str = "analysis_limit";
/// Most bytes of type names held for the whole project: every type's
/// qualified name and simple name, and for each non-local type its
/// `package.Outer.Inner` key and its simple-name key once more (see
/// [`name_bytes`]). A file that would exceed it is skipped
/// (`analysis_limit`); the per-file parser budgets alone would allow
/// thousands of files times their maximum.
const MAX_PROJECT_NAME_BYTES: usize = 64 * 1024 * 1024;
/// Tokens skipped over the type arguments of `new X<…>(`.
const MAX_TYPE_ARG_TOKENS: usize = 64;

/// Source of other JVM languages, aspects and templates: may call any Java
/// method. Compared lowercase.
const OTHER_JVM_EXTS: &[&str] = &[
    "kt", "kts", "scala", "groovy", "clj", "jsp", "aj", "jsh", "gvy", "gy", "gsh", "sc", "cljs",
    "cljc", "jspx", "jspf", "tag", "tagx", "ftl", "vm", "jte", "mustache", "hbs", "peb", "ftlh",
    "ftlx",
];
/// Compiled JVM code, archives and native libraries. Compared lowercase.
const COMPILED_EXTS: &[&str] = &[
    "jar", "class", "war", "ear", "jmod", "zip", "so", "dll", "dylib", "jnilib", "aar", "dex",
    "apk",
];
/// Compared lowercase (`.MF` included).
const CONFIG_EXTS: &[&str] = &[
    "xml",
    "properties",
    "yml",
    "yaml",
    "json",
    "factories",
    "imports",
    "conf",
    "toml",
    "ini",
    "mf",
];
/// Every file below a directory of this name is a config file (compared
/// ASCII case-insensitively).
const META_INF: &str = "meta-inf";
/// A Thymeleaf attribute in an `.html` template: `th:` or HTML5 `data-th-`
/// after the start, whitespace or a quote, then a name starting with a
/// letter and `=` (`th:text="…"`, `data-th-each = "…"`); or a `<th:…>`
/// element. Not `width:` / `max-width:` in CSS, nor a CSS `th:hover`
/// selector. Case-insensitive; the `regex` crate runs in linear time.
static THYMELEAF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:^|[\s"'])(?:th:|data-th-)[a-z][a-z0-9_:.\-]*\s*=|<th:[a-z])"#)
        .expect("static thymeleaf pattern")
});

/// Package prefixes (whole dot-separated segments) of libraries that call
/// project methods, constructors and accessors reflectively: any import or
/// qualified use marks the project not fully analyzed
/// (`reflective_library_import`).
const REFLECTIVE_LIBRARIES: &[&str] = &[
    "com.fasterxml.jackson",
    "com.google.gson",
    "org.springframework",
    "org.hibernate",
    "jakarta.persistence",
    "javax.persistence",
    "org.mapstruct",
    "jakarta.el",
    "javax.el",
    "ognl",
    "org.thymeleaf",
    "freemarker",
    "org.apache.velocity",
    "com.google.inject",
    "dagger",
    "jakarta.inject",
    "javax.inject",
    "jakarta.ws.rs",
    "javax.ws.rs",
    "org.junit",
    "picocli",
    "io.micronaut",
    "io.quarkus",
    "jakarta.enterprise",
    "javax.enterprise",
    "jakarta.xml.bind",
    "javax.xml.bind",
    "jakarta.json.bind",
    "javax.json.bind",
    "org.yaml.snakeyaml",
    "com.github.mustachejava",
    "com.samskivert",
    "com.github.jknack",
    "io.pebbletemplates",
    "org.mockito",
    "org.testng",
    "javax.management",
];
/// Most dot-separated segments of a [`REFLECTIVE_LIBRARIES`] entry.
const MAX_LIBRARY_SEGMENTS: usize = 3;

/// Words that make any unreached member `unknown` (`reflection_in_project`).
const REFLECTION_WORDS: &[&str] = &[
    "forName",
    "getMethod",
    "getDeclaredMethod",
    "getMethods",
    "getDeclaredMethods",
    "getConstructor",
    "getConstructors",
    "getDeclaredConstructor",
    "getDeclaredConstructors",
    "newInstance",
    "invoke",
    "MethodHandles",
    "MethodHandle",
    "VarHandle",
    "LambdaMetafactory",
    "ServiceLoader",
    "Proxy",
    "InvocationHandler",
    "loadClass",
    "defineClass",
    "ClassLoader",
    "URLClassLoader",
    "Unsafe",
    "ObjectInputStream",
    "readObject",
    "readResolve",
    "Instrumentation",
    "JNI",
    "native",
    "loadLibrary",
    // java.beans: invoke methods named by strings or by bean properties.
    "Statement",
    "Expression",
    "EventHandler",
    "XMLDecoder",
    "XMLEncoder",
    "Introspector",
    "PropertyDescriptor",
    "BeanInfo",
    "JShell",
    // Apache Commons reflection helpers.
    "MethodUtils",
    "PropertyUtils",
    "BeanUtils",
    // JMX: an MBean server calls the management interface's methods by
    // name (default methods included).
    "registerMBean",
    "StandardMBean",
    "MBeanServer",
    "MXBean",
];

/// Identifier prefixes that count as [`REFLECTION_WORDS`] (`ScriptEngine`,
/// `ScriptEngineManager`, `ScriptEngineFactory`, …).
const REFLECTION_PREFIXES: &[&str] = &["ScriptEngine"];

/// Method names the JDK or the language may call without a textual call.
const JDK_IMPLICIT_NAMES: &[&str] = &[
    "run",
    "call",
    "close",
    "toString",
    "equals",
    "hashCode",
    "compareTo",
    "compare",
    "accept",
    "apply",
    "get",
    "test",
    "iterator",
    "finalize",
    "clone",
    "readObject",
    "writeObject",
    "main",
    "values",
    "valueOf",
    // `java.lang.instrument` agent entry points (named in the manifest).
    "premain",
    "agentmain",
    // JPMS service provider factory (`ServiceLoader`, `provides … with`).
    "provider",
];

/// Annotations that do not by themselves imply a framework caller. They
/// still never allow `not_observed`.
const BENIGN_ANNOTATIONS: &[&str] = &[
    "Override",
    "Deprecated",
    "SuppressWarnings",
    "SafeVarargs",
    "FunctionalInterface",
];

/// Keywords that look like calls (`if (`) but never name a method.
const NOT_CALLS: &[&str] = &[
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "synchronized",
    "try",
    "return",
    "assert",
    "throw",
    "new",
    "super",
    "this",
];

const CLASS_INIT: &str = "class_initialized_by_reachable_member";
const CTOR_REACHABLE: &str = "constructor_reachable";
const ANNOTATED: &str = "enclosing_annotated";

/// An entry target: one member of one analyzed file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberId {
    file: usize,
    member: usize,
}

/// One edge source in a member body.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Ref {
    /// `name(` or `X::name`: every method named `name`.
    Call(String),
    /// `new X(` or `X::new`: an instance of every type named `X`.
    New(String),
    /// `super(`: an instance of the declaring type's supertypes.
    Super,
    /// `this(`: an instance of the declaring type.
    This,
}

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    /// Identifier occurrences outside the declarations of that name.
    any: u64,
    /// Of those, call-shaped ones (`name(`, `::name`).
    call: u64,
}

#[derive(Debug, Default)]
struct JFile {
    rel: String,
    sha256: String,
    nlines: u32,
    ambiguous: bool,
    parsed: JavaFile,
    /// Blanked code, kept until [`JavaProject::finalize`].
    code: String,
    sweep_lexed: Option<JavaLexed>,
    /// Edge sources per member (index into `parsed.members`).
    refs: Vec<Vec<Ref>>,
    /// Which members may hold a line; see [`LineIndex::candidates`].
    lines: LineIndex,
    /// Single-type imports by their last segment, sorted and deduplicated.
    imports_by_name: HashMap<String, Vec<String>>,
    /// The interned package (index into the project's package table, set
    /// in [`JavaProject::finalize`]); `None` for the default package.
    pkg_id: Option<usize>,
}

/// Bytes of type names a parsed file adds to the project (see
/// [`MAX_PROJECT_NAME_BYTES`]).
fn name_bytes(parsed: &JavaFile) -> usize {
    let pkg = parsed
        .package
        .as_ref()
        .map_or(0, |p| p.len().saturating_add(1));
    parsed.types.iter().fold(0usize, |acc, t| {
        let mut n = t.qualified.len().saturating_add(t.name.len());
        if !t.local {
            n = n
                .saturating_add(pkg)
                .saturating_add(t.qualified.len())
                .saturating_add(t.name.len());
        }
        acc.saturating_add(n)
    })
}

/// No member (in [`LineIndex::inner`]).
const NO_MEMBER: usize = usize::MAX;

/// Per-file index from a line to the members whose line range holds it,
/// built once so that a row costs `O(log members + members touching the
/// line)` instead of a scan of every member.
#[derive(Debug, Default)]
struct LineIndex {
    /// `(line, member)` for the first and the last line of every member,
    /// sorted.
    edges: Vec<(u32, usize)>,
    /// Sorted runs `(first line, member)`: from that line on, the innermost
    /// member whose line range strictly encloses the line (starts above and
    /// ends below it), or [`NO_MEMBER`].
    inner: Vec<(u32, usize)>,
    /// The innermost member enclosing each member, by byte span.
    parent: Vec<Option<usize>>,
}

/// `(start_byte, end_byte)` of member `m`.
fn byte_span(members: &[Member], m: usize) -> (usize, usize) {
    members
        .get(m)
        .map_or((0, 0), |x| (x.start_byte, x.end_byte))
}

/// Member indices by span start, outer before inner (spans are properly
/// nested or disjoint).
fn span_order(members: &[Member]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by_key(|&m| {
        let (s, e) = byte_span(members, m);
        (s, Reverse(e), m)
    });
    order
}

/// Append a run starting at `from`; a run already starting there is
/// replaced (its owner is out of date).
fn push_run(runs: &mut Vec<(u32, usize)>, from: u32, owner: usize) {
    if let Some(last) = runs.last_mut() {
        if last.0 == from {
            last.1 = owner;
            return;
        }
        if last.1 == owner {
            return;
        }
    }
    runs.push((from, owner));
}

impl LineIndex {
    /// One pass over the members sorted by span (explicit stacks, no
    /// recursion).
    fn build(members: &[Member]) -> LineIndex {
        let mut edges = Vec::with_capacity(members.len().saturating_mul(2));
        for (i, m) in members.iter().enumerate() {
            edges.push((m.line_start, i));
            if m.line_end != m.line_start {
                edges.push((m.line_end, i));
            }
        }
        edges.sort_unstable();
        let mut parent = vec![None; members.len()];
        let mut stack: Vec<usize> = Vec::new();
        for m in span_order(members) {
            let (start, _) = byte_span(members, m);
            while stack
                .last()
                .is_some_and(|&s| byte_span(members, s).1 <= start)
            {
                stack.pop();
            }
            if let Some(slot) = parent.get_mut(m) {
                *slot = stack.last().copied();
            }
            stack.push(m);
        }
        // Interiors `[line_start + 1, line_end - 1]` of nested spans are
        // nested, of disjoint spans disjoint: a sweep with a stack of open
        // interiors gives the innermost one at each line.
        let mut interiors: Vec<(u32, Reverse<u32>, usize, usize)> = members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.line_end.saturating_sub(m.line_start) >= 2)
            .map(|(i, m)| (m.line_start + 1, Reverse(m.line_end - 1), m.start_byte, i))
            .collect();
        interiors.sort_unstable();
        let mut inner = vec![(0u32, NO_MEMBER)];
        let mut open: Vec<(u32, usize)> = Vec::new();
        for (first, Reverse(last), _, m) in interiors {
            while let Some(&(end, _)) = open.last()
                && end < first
            {
                open.pop();
                let owner = open.last().map_or(NO_MEMBER, |o| o.1);
                push_run(&mut inner, end.saturating_add(1), owner);
            }
            push_run(&mut inner, first, m);
            open.push((last, m));
        }
        while let Some((end, _)) = open.pop() {
            let owner = open.last().map_or(NO_MEMBER, |o| o.1);
            push_run(&mut inner, end.saturating_add(1), owner);
        }
        LineIndex {
            edges,
            inner,
            parent,
        }
    }

    /// The members whose line range holds `line`, minus every one that
    /// strictly contains (by line range) a holder spanning the whole line:
    /// the members that may own code on `line`, sorted.
    ///
    /// Spans are nested or disjoint, so the holders that start above and end
    /// below `line` form one chain, of which only those with the smallest
    /// range stay; a holder starting or ending on `line` always stays.
    fn candidates(&self, members: &[Member], line: u32) -> Vec<usize> {
        let lo = self.edges.partition_point(|&(l, _)| l < line);
        let hi = self.edges.partition_point(|&(l, _)| l <= line);
        let mut out: Vec<usize> = self
            .edges
            .get(lo..hi)
            .unwrap_or(&[])
            .iter()
            .map(|&(_, m)| m)
            .collect();
        let k = self.inner.partition_point(|&(l, _)| l <= line);
        let owner = k
            .checked_sub(1)
            .and_then(|k| self.inner.get(k))
            .map_or(NO_MEMBER, |r| r.1);
        if let Some(m) = members.get(owner) {
            let range = (m.line_start, m.line_end);
            let mut cur = Some(owner);
            let mut steps = 0usize;
            while let Some(c) = cur
                && steps <= members.len()
            {
                steps += 1;
                if members.get(c).map(|x| (x.line_start, x.line_end)) != Some(range) {
                    break;
                }
                out.push(c);
                cur = self.parent.get(c).copied().flatten();
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// The first [`MAX_LABEL_CHARS`] characters of `s`: a label built from it
/// clips (see [`clip_label`]) exactly like one built from all of `s`.
fn label_part(s: &str) -> &str {
    match s.char_indices().nth(MAX_LABEL_CHARS) {
        Some((i, _)) => s.get(..i).unwrap_or(s),
        None => s,
    }
}

/// Names already expanded by the BFS (see [`JavaProject::successors`]).
#[derive(Default)]
struct Expanded<'a> {
    /// Called method names: every method of the name is queued.
    called: HashSet<&'a str>,
    /// Instantiated type names (`new X(`, `X::new`, a supertype of an
    /// instance): an instance of every type of the name is queued.
    newed: HashSet<&'a str>,
    /// Initialized supertype names: every type of the name is initialized.
    inited: HashSet<&'a str>,
}

/// Whether a node appears in chains (see [`JavaProject::node_label`]).
fn is_labeled(n: Node) -> bool {
    matches!(n, Node::Member(..) | Node::Entry(_))
}

/// Where a reached node sits in the BFS tree, recorded once when it is
/// first reached so that a chain costs at most [`MAX_CHAIN`] steps.
#[derive(Debug, Clone, Copy)]
struct Link {
    /// Labeled nodes on the tree path from its root to this node, both
    /// included.
    depth: usize,
    /// The nearest labeled strict ancestor.
    up: Option<Node>,
    /// The deepest labeled node, this one included, on that path whose
    /// `depth` is at most `MAX_CHAIN / 2`: where the head of the chain ends.
    anchor: Option<Node>,
}

impl Link {
    /// The link of `n` reached from `from`, whose link is `from_link`.
    fn new(n: Node, from: Option<Node>, from_link: Option<&Link>) -> Link {
        let labeled = is_labeled(n);
        let depth = from_link
            .map_or(0, |l| l.depth)
            .saturating_add(usize::from(labeled));
        let up = match from {
            Some(f) if is_labeled(f) => Some(f),
            _ => from_link.and_then(|l| l.up),
        };
        let anchor = if labeled && depth <= MAX_CHAIN / 2 {
            Some(n)
        } else {
            from_link.and_then(|l| l.anchor)
        };
        Link { depth, up, anchor }
    }
}

/// Record `n` as reached from `from` and queue it; `false` when the queue
/// already holds [`MAX_WORKLIST`] entries (`n` is then not recorded).
fn visit(
    links: &mut HashMap<Node, Link>,
    queue: &mut VecDeque<Node>,
    n: Node,
    from: Option<Node>,
) -> bool {
    if links.contains_key(&n) {
        return true;
    }
    if queue.len() >= MAX_WORKLIST {
        return false;
    }
    let link = Link::new(n, from, from.and_then(|f| links.get(&f)));
    links.insert(n, link);
    queue.push_back(n);
    true
}

/// (relative path, path, walk-time (length, (dev, ino)))
type Found = (String, PathBuf, Option<(u64, Option<(u64, u64)>)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Node {
    Member(usize, usize),
    /// The type `(file, type)` is initialized.
    Init(usize, usize),
    /// An instance of the type `(file, type)` is created.
    Instance(usize, usize),
    Entry(usize),
}

/// BFS result from the entry points; see [`JavaProject::reach`].
#[derive(Debug)]
pub struct Reach {
    /// Every reached node (and each resolved `--entry` spec).
    links: HashMap<Node, Link>,
    entries: Vec<String>,
    /// The queue hit [`MAX_WORKLIST`]: unreached members may be reachable.
    truncated: bool,
}

/// Top-level types: simple type name -> interned package id
/// ([`JFile::pkg_id`], `None` for the default package) -> the
/// `(file, type)` index pairs declaring that name in that package.
type TopLevelTypes = HashMap<String, HashMap<Option<usize>, Vec<(usize, usize)>>>;

/// A loaded Java project.
#[derive(Debug, Default)]
pub struct JavaProject {
    retain_sweep: bool,
    sweep_retained_bytes: usize,
    sweep_budget: usize,
    sweep_notes: Vec<(String, &'static str)>,
    files: Vec<JFile>,
    index: HashMap<String, usize>,
    skipped: BTreeMap<String, &'static str>,
    limit: Option<&'static str>,
    /// Every reason the project is not fully analyzed; the first (sorted)
    /// one is reported, so the result does not depend on walk order.
    incomplete: BTreeSet<&'static str>,
    reflection: bool,
    types_by_name: HashMap<String, Vec<(usize, usize)>>,
    /// Non-local types by `package.Outer.Inner` (`Outer.Inner` in the
    /// default package).
    types_by_full: HashMap<String, Vec<(usize, usize)>>,
    /// Non-local member types of `(file, type)` by simple name.
    nested_named: HashMap<(usize, usize), HashMap<String, Vec<usize>>>,
    /// Non-local top-level types by simple name, then interned package
    /// ([`JFile::pkg_id`]).
    top_level: TopLevelTypes,
    /// Type-name bytes held so far (see [`MAX_PROJECT_NAME_BYTES`]).
    name_bytes: usize,
    /// Test-only override of [`MAX_PROJECT_NAME_BYTES`] (also set by the
    /// `fuzzing` feature through [`JavaProject::from_sources_with_name_budget`]).
    #[cfg(any(test, feature = "fuzzing"))]
    name_budget: Option<usize>,
    /// Index of each file's first type in `external`.
    type_base: Vec<usize>,
    /// Per type: [`JavaProject::external_supertype`], computed once.
    external: Vec<bool>,
    /// The propagation of `external` hit [`MAX_WORKLIST`].
    external_limit: bool,
    methods: HashMap<String, Vec<(usize, usize)>>,
    type_members: HashMap<(usize, usize), Vec<usize>>,
    ref_counts: HashMap<String, Counts>,
    config_words: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathKind {
    Java,
    Config,
    /// An `.html` file outside `META-INF/`: only scanned for Thymeleaf.
    Html,
    OtherJvm,
    Compiled,
    Other,
}

fn path_kind(rel: &str) -> PathKind {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if name.ends_with(".java") {
        return PathKind::Java;
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    // Every directory component, not the file name.
    let under_meta_inf = rel
        .rsplit_once('/')
        .is_some_and(|(dirs, _)| dirs.split('/').any(|d| d.eq_ignore_ascii_case(META_INF)));
    if OTHER_JVM_EXTS.contains(&ext.as_str()) {
        PathKind::OtherJvm
    } else if COMPILED_EXTS.contains(&ext.as_str()) {
        PathKind::Compiled
    } else if CONFIG_EXTS.contains(&ext.as_str()) || under_meta_inf {
        PathKind::Config
    } else if ext == "html" {
        PathKind::Html
    } else {
        PathKind::Other
    }
}

fn is_html(rel: &str) -> bool {
    rel.rsplit_once('.')
        .is_some_and(|(_, e)| e.eq_ignore_ascii_case("html"))
}

fn has_thymeleaf(bytes: &[u8]) -> bool {
    THYMELEAF_RE.is_match(bytes)
}

/// `name` is `prefix` or starts with `prefix.` (whole segments).
fn is_library_name(name: &str) -> bool {
    REFLECTIVE_LIBRARIES.iter().any(|p| {
        name.strip_prefix(p)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
    })
}

/// A JavaBeans accessor name: `get`, `is` or `set` and an uppercase letter.
fn is_bean_accessor(name: &str) -> bool {
    ["get", "is", "set"].iter().any(|p| {
        name.strip_prefix(p)
            .is_some_and(|rest| rest.bytes().next().is_some_and(|c| c.is_ascii_uppercase()))
    })
}

fn rel_of(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    Some(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

/// Lines of `s`, counting CR, LF and CRLF each as one terminator (JLS 3.4).
fn count_lines(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut n: u32 = 0;
    let mut pending = false;
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'\r' => {
                n = n.saturating_add(1);
                if b.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
                pending = false;
            }
            b'\n' => {
                n = n.saturating_add(1);
                pending = false;
            }
            _ => pending = true,
        }
        i += 1;
    }
    n.saturating_add(u32::from(pending))
}

fn simple_name(written: &str) -> &str {
    written.rsplit('.').next().unwrap_or(written)
}

/// The innermost of `ids`: the latest start, then the shortest span, then
/// the lowest index.
fn innermost(members: &[Member], ids: impl Iterator<Item = usize>) -> Option<usize> {
    let range = |i: usize| {
        members
            .get(i)
            .map_or((0, 0), |m| (m.line_start, m.line_end))
    };
    ids.max_by_key(|&i| (range(i).0, Reverse(range(i).1), Reverse(i)))
}

fn unknown(reason: &str) -> Verdict {
    Verdict {
        label: Label::Unknown,
        reasons: vec![reason.to_string()],
        enclosing_function: None,
        chain: Vec::new(),
    }
}

/// Project-wide sweep retention cap: 64 MiB, charged for blanked code,
/// literal table capacity times `size_of::<(u32, String)>()`, and decoded
/// string capacities (including empty literals' entry overhead).
pub(super) const MAX_SWEEP_RETAINED_BYTES: usize = 64 * 1024 * 1024;

impl JavaProject {
    /// Walk `root` (symlinks are never followed) and analyze every `.java`.
    #[cfg(test)]
    pub fn load(root: &Path) -> JavaProject {
        Self::load_with_excludes(root, &[])
    }

    /// Like [`JavaProject::load`], but files whose canonical path is in
    /// `excludes` (e.g. the CBOM under check or the receipt output, which name
    /// the very classes being looked for) are ignored entirely.
    pub fn load_with_excludes(root: &Path, excludes: &[PathBuf]) -> JavaProject {
        Self::load_for_sweep(root, excludes, false)
    }

    /// Retain the original lexer output only when the optional sweep needs it.
    pub(super) fn load_for_sweep(root: &Path, excludes: &[PathBuf], sweep: bool) -> JavaProject {
        Self::load_for_sweep_with_budget(root, excludes, sweep, MAX_SWEEP_RETAINED_BYTES)
    }

    pub(super) fn load_for_sweep_with_budget(
        root: &Path,
        excludes: &[PathBuf],
        sweep: bool,
        sweep_budget: usize,
    ) -> JavaProject {
        let excludes: Vec<PathBuf> = excludes
            .iter()
            .map(|e| e.canonicalize().unwrap_or_else(|_| e.clone()))
            .collect();
        let mut p = JavaProject {
            retain_sweep: sweep,
            sweep_budget,
            ..JavaProject::default()
        };
        let mut java: Vec<Found> = Vec::new();
        let mut config: Vec<Found> = Vec::new();
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
                let Some(rel) = rel_of(root, &path) else {
                    continue;
                };
                // Only `<root>/.git` is skipped silently.
                let silent = depth == 0 && SILENT_SKIP_DIRS.contains(&nm);
                if ft.is_symlink() {
                    let to_dir = std::fs::metadata(&path).is_ok_and(|m| m.is_dir());
                    if (to_dir && !silent) || path_kind(&rel) != PathKind::Other {
                        p.note_incomplete("symlink_not_followed");
                    }
                } else if ft.is_dir() {
                    if !SKIP_DIRS.contains(&nm) {
                        stack.push((path, depth + 1));
                    } else if !silent {
                        p.note_incomplete("skipped_directory");
                    }
                } else if ft.is_file() {
                    if !excludes.is_empty()
                        && path.canonicalize().is_ok_and(|c| excludes.contains(&c))
                    {
                        continue;
                    }
                    let kind = path_kind(&rel);
                    // `DirEntry::metadata` does not follow symlinks.
                    let meta = || entry.metadata().ok().map(|m| (m.len(), file_id(&m)));
                    match kind {
                        PathKind::Java => {
                            java.push((rel, path, meta()));
                            if java.len() > MAX_FILES {
                                p.limit = Some("file_count_limit_exceeded");
                                break 'walk;
                            }
                        }
                        // Templates share the config caps.
                        PathKind::Config | PathKind::Html => {
                            if config.len() >= MAX_CONFIG_FILES {
                                p.note_incomplete("config_file_count_limit_exceeded");
                            } else {
                                config.push((rel, path, meta()));
                            }
                        }
                        PathKind::OtherJvm => p.note_incomplete("other_jvm_source"),
                        PathKind::Compiled => p.note_incomplete("compiled_jvm_code"),
                        PathKind::Other => {}
                    }
                } else if path_kind(&rel) != PathKind::Other {
                    // A FIFO, socket or device with a relevant name.
                    p.note_incomplete("file_unreadable");
                }
            }
        }
        if p.limit.is_some() || !p.read_java(java, MAX_TOTAL_BYTES) {
            return p;
        }
        p.read_config(config, MAX_CONFIG_TOTAL_BYTES);
        p.finalize();
        p
    }

    /// Read and add the `.java` files found by the walk, in path order. The
    /// bytes actually read count toward `total_cap` (walk-time sizes can
    /// lie: a file may grow after the walk); each read is capped at what is
    /// left. A file that does not fit sets `source_size_limit_exceeded` and
    /// returns `false`.
    fn read_java(&mut self, mut java: Vec<Found>, total_cap: u64) -> bool {
        java.sort();
        let mut total = 0u64;
        for (rel, path, meta) in java {
            let Some((len, id)) = meta else {
                self.skip(&rel, "file_unreadable");
                continue;
            };
            if len > MAX_FILE_BYTES {
                self.skip(&rel, "file_too_large");
                continue;
            }
            let cap = MAX_FILE_BYTES.min(total_cap.saturating_sub(total));
            match read_capped(&path, cap, id) {
                Err(_) => self.skip(&rel, "file_unreadable"),
                // More than is left of the total (whether or not it is also
                // over the per-file cap).
                Ok(None) if cap < MAX_FILE_BYTES => {
                    self.limit = Some("source_size_limit_exceeded");
                    return false;
                }
                Ok(None) => self.skip(&rel, "file_too_large"),
                Ok(Some(bytes)) => {
                    total = total.saturating_add(bytes.len() as u64);
                    match String::from_utf8(bytes) {
                        Err(_) => self.skip(&rel, "file_not_utf8"),
                        Ok(text) => self.add_java(&rel, &text),
                    }
                }
            }
        }
        true
    }

    /// Read the config and template files found by the walk, in path order,
    /// counting the bytes actually read toward `total_cap` like
    /// [`JavaProject::read_java`]; over it, the rest is not read
    /// (`config_size_limit_exceeded`).
    fn read_config(&mut self, mut config: Vec<Found>, total_cap: u64) {
        config.sort();
        let mut total = 0u64;
        for (rel, path, meta) in config {
            let Some((len, id)) = meta else {
                self.note_incomplete("config_file_unreadable");
                continue;
            };
            if len > MAX_CONFIG_FILE_BYTES {
                self.note_incomplete("config_file_too_large");
                continue;
            }
            let cap = MAX_CONFIG_FILE_BYTES.min(total_cap.saturating_sub(total));
            match read_capped(&path, cap, id) {
                Err(_) => self.note_incomplete("config_file_unreadable"),
                Ok(None) if cap < MAX_CONFIG_FILE_BYTES => {
                    self.note_incomplete("config_size_limit_exceeded");
                    break;
                }
                Ok(None) => self.note_incomplete("config_file_too_large"),
                Ok(Some(bytes)) => {
                    total = total.saturating_add(bytes.len() as u64);
                    self.add_config_file(&rel, &bytes);
                }
            }
        }
    }

    /// One config or `.html` file: config files feed `named_in_config_file`;
    /// an `.html` file with a Thymeleaf attribute marks the project
    /// incomplete (its expressions call getters and methods by name).
    fn add_config_file(&mut self, rel: &str, bytes: &[u8]) {
        if is_html(rel) && has_thymeleaf(bytes) {
            self.note_incomplete("other_jvm_source");
        }
        if path_kind(rel) == PathKind::Config {
            self.add_config_bytes(bytes);
        }
    }

    /// Build a project from in-memory sources (`(relative path, text)`).
    /// Paths are classified as in [`JavaProject::load`]: `.java` is analyzed,
    /// config files feed `named_in_config_file`, other JVM sources and
    /// compiled code mark the project incomplete.
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn from_sources(sources: Vec<(String, String)>) -> JavaProject {
        Self::from_sources_with_name_budget(sources, MAX_PROJECT_NAME_BYTES)
    }

    /// [`JavaProject::from_sources`] with `name_budget` in place of
    /// [`MAX_PROJECT_NAME_BYTES`].
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn from_sources_with_name_budget(
        sources: Vec<(String, String)>,
        name_budget: usize,
    ) -> JavaProject {
        let mut p = JavaProject {
            name_budget: Some(name_budget),
            ..JavaProject::default()
        };
        let mut sorted = sources;
        sorted.sort();
        for (rel, text) in &sorted {
            match path_kind(rel) {
                PathKind::Java => p.add_java(rel, text),
                PathKind::Config | PathKind::Html => p.add_config_file(rel, text.as_bytes()),
                PathKind::OtherJvm => p.note_incomplete("other_jvm_source"),
                PathKind::Compiled => p.note_incomplete("compiled_jvm_code"),
                PathKind::Other => {}
            }
        }
        p.finalize();
        p
    }

    #[cfg(not(any(test, feature = "fuzzing")))]
    fn name_budget(&self) -> usize {
        MAX_PROJECT_NAME_BYTES
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn name_budget(&self) -> usize {
        self.name_budget.unwrap_or(MAX_PROJECT_NAME_BYTES)
    }

    fn note_incomplete(&mut self, why: &'static str) {
        self.incomplete.insert(why);
    }

    fn skip(&mut self, rel: &str, why: &'static str) {
        self.skipped.insert(rel.to_string(), why);
        self.note_incomplete(why);
    }

    /// Number of analyzed `.java` files (ambiguous ones included).
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Why this project cannot support `not_observed`, if so.
    pub fn incomplete_reason(&self) -> Option<&'static str> {
        self.limit.or_else(|| self.incomplete.first().copied())
    }

    /// Whether a reflection / dynamic-loading word occurs anywhere in code.
    pub fn has_reflection(&self) -> bool {
        self.reflection
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

    /// Already loaded, lexed and parsed files, in the walk's sorted order.
    pub(super) fn sweep_files(&self) -> impl Iterator<Item = (&str, &JavaLexed, &JavaFile)> {
        self.files.iter().filter_map(|f| {
            f.sweep_lexed
                .as_ref()
                .map(|l| (f.rel.as_str(), l, &f.parsed))
        })
    }

    /// Reasons for files whose sweep data was deliberately not retained.
    pub(super) fn sweep_notes(&self) -> &[(String, &'static str)] {
        &self.sweep_notes
    }

    // ---- pass 1: structure -------------------------------------------------

    fn add_java(&mut self, rel: &str, text: &str) {
        let sha256 = sha256_hex(text.as_bytes());
        // The lexer drops one leading BOM; line numbers are unchanged.
        let body = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut lexed = lex(text);
        if lexed.non_ascii_in_code {
            self.note_incomplete("non_ascii_identifier_possible");
        }
        let parsed = parse(&lexed);
        // Over the project-wide name budget: the file is not analyzed (its
        // names are dropped here, before `finalize` copies them into keys).
        let names = self.name_bytes.saturating_add(name_bytes(&parsed));
        if names > self.name_budget() {
            self.skip(rel, ANALYSIS_LIMIT);
            return;
        }
        self.name_bytes = names;
        let ambiguous = parsed.ambiguity.is_some();
        if ambiguous {
            self.note_incomplete("file_parse_ambiguity");
        }
        // JPMS `provides … with …;` / `uses …;` name service providers the
        // JDK instantiates (or whose `provider()` it calls): config words.
        for w in &parsed.module_names {
            if !self.config_words.contains(w) {
                self.config_words.insert(w.clone());
            }
        }
        let mut retain = self.retain_sweep && !ambiguous;
        if self.retain_sweep {
            if let Some(reason) = parsed.ambiguity {
                self.sweep_notes.push((rel.to_string(), reason));
            } else {
                let bytes = lexed.literals.iter().fold(
                    lexed.code.capacity().saturating_add(
                        lexed
                            .literals
                            .capacity()
                            .saturating_mul(std::mem::size_of::<(u32, String)>()),
                    ),
                    |n, (_, value)| n.saturating_add(value.capacity()),
                );
                if bytes > self.sweep_budget.saturating_sub(self.sweep_retained_bytes) {
                    retain = false;
                    self.sweep_notes
                        .push((rel.to_string(), "sweep_memory_limit_exceeded"));
                } else {
                    self.sweep_retained_bytes += bytes;
                }
            }
        }
        let f = JFile {
            rel: rel.to_string(),
            sha256,
            nlines: count_lines(body),
            ambiguous,
            parsed,
            code: if ambiguous {
                String::new()
            } else {
                std::mem::take(&mut lexed.code)
            },
            sweep_lexed: retain.then_some(lexed),
            refs: Vec::new(),
            // Both built in `finalize` once the refs are scanned.
            lines: LineIndex::default(),
            imports_by_name: HashMap::new(),
            pkg_id: None,
        };
        self.index.insert(rel.to_string(), self.files.len());
        self.files.push(f);
    }

    /// One config file's bytes: every identifier-like word (after decoding
    /// numeric escapes) may name a class or method.
    fn add_config_bytes(&mut self, bytes: &[u8]) {
        // UTF-16 and other NUL-padded encodings would split every word.
        if bytes.contains(&0) {
            self.note_incomplete("config_file_not_text");
            return;
        }
        // Names are ASCII (non-ASCII identifiers mark the project
        // incomplete), so a lossy decode keeps every name intact.
        let text = String::from_utf8_lossy(bytes);
        // Over-approximate the decoded text: the words of every variant.
        for variant in [
            decode_numeric_escapes(&text),
            decode_backslashes(&text, false),
            decode_backslashes(&text, true),
        ] {
            self.add_words(&variant);
        }
    }

    fn add_words(&mut self, s: &str) {
        let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
        for w in s.split(|c: char| !is_word(c)) {
            if w.is_empty() {
                continue;
            }
            if !self.config_words.contains(w) {
                self.config_words.insert(w.to_string());
            }
            // `Outer$Inner` binary names.
            if w.contains('$') {
                for part in w.split('$') {
                    if !part.is_empty() && !self.config_words.contains(part) {
                        self.config_words.insert(part.to_string());
                    }
                }
            }
        }
    }

    // ---- pass 2: references ------------------------------------------------

    fn finalize(&mut self) {
        // Intern packages: `top_level` keys on the index, not a copy of the
        // package per type.
        let mut packages: HashMap<String, usize> = HashMap::new();
        for f in &mut self.files {
            f.pkg_id = f.parsed.package.as_ref().map(|p| match packages.get(p) {
                Some(&id) => id,
                None => {
                    let id = packages.len();
                    packages.insert(p.clone(), id);
                    id
                }
            });
        }
        drop(packages);
        let mut relevant: HashSet<String> = HashSet::new();
        let mut library = false;
        for (fi, f) in self.files.iter().enumerate() {
            if f.ambiguous {
                continue;
            }
            library |= f.parsed.imports.iter().any(|i| is_library_name(i));
            for (ti, t) in f.parsed.types.iter().enumerate() {
                self.types_by_name
                    .entry(t.name.clone())
                    .or_default()
                    .push((fi, ti));
                if t.local {
                    continue;
                }
                // Built once per type, counted by `name_bytes`.
                let full = match &f.parsed.package {
                    Some(pkg) => {
                        let mut s = String::with_capacity(pkg.len() + 1 + t.qualified.len());
                        s.push_str(pkg);
                        s.push('.');
                        s.push_str(&t.qualified);
                        s
                    }
                    None => t.qualified.clone(),
                };
                self.types_by_full.entry(full).or_default().push((fi, ti));
                match t.parent {
                    Some(parent) => self
                        .nested_named
                        .entry((fi, parent))
                        .or_default()
                        .entry(t.name.clone())
                        .or_default()
                        .push(ti),
                    None => self
                        .top_level
                        .entry(t.name.clone())
                        .or_default()
                        .entry(f.pkg_id)
                        .or_default()
                        .push((fi, ti)),
                }
            }
            for (mi, m) in f.parsed.members.iter().enumerate() {
                self.type_members
                    .entry((fi, m.type_idx))
                    .or_default()
                    .push(mi);
                match m.kind {
                    MemberKind::Method => {
                        self.methods
                            .entry(m.name.clone())
                            .or_default()
                            .push((fi, mi));
                        relevant.insert(m.name.clone());
                    }
                    MemberKind::Constructor => {
                        relevant.insert(m.name.clone());
                    }
                    _ => {}
                }
            }
        }
        for fi in 0..self.files.len() {
            if self.files[fi].ambiguous {
                continue;
            }
            let code = std::mem::take(&mut self.files[fi].code);
            let scan = scan_file(&code, &self.files[fi].parsed, &relevant);
            self.reflection |= scan.reflection;
            library |= scan.library;
            for (name, c) in scan.counts {
                let e = self.ref_counts.entry(name).or_default();
                e.any = e.any.saturating_add(c.any);
                e.call = e.call.saturating_add(c.call);
            }
            let f = &mut self.files[fi];
            f.refs = scan.refs;
            f.lines = LineIndex::build(&f.parsed.members);
            if let Some(lexed) = &mut f.sweep_lexed {
                lexed.code = code;
            }
            let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
            for i in &f.parsed.imports {
                if let Some((_, last)) = i.rsplit_once('.') {
                    by_name.entry(last.to_string()).or_default().push(i.clone());
                }
            }
            for v in by_name.values_mut() {
                v.sort_unstable();
                v.dedup();
            }
            f.imports_by_name = by_name;
        }
        if library {
            self.note_incomplete("reflective_library_import");
        }
        let (base, external, limit) = self.compute_external();
        self.type_base = base;
        self.external = external;
        self.external_limit = limit;
    }

    /// [`JavaProject::external_supertype`] of every type, computed once: a
    /// type with a written supertype that does not resolve to exactly one
    /// project type is external, and so is every type that resolves to an
    /// external one (propagated down the resolved edges with an explicit
    /// worklist). Returns the per-file base index, the flags, and whether
    /// the worklist hit [`MAX_WORKLIST`].
    fn compute_external(&self) -> (Vec<usize>, Vec<bool>, bool) {
        let mut base = Vec::with_capacity(self.files.len());
        let mut total = 0usize;
        for f in &self.files {
            base.push(total);
            total = total.saturating_add(f.parsed.types.len());
        }
        let mut external = vec![false; total];
        // (supertype, subtype) of every resolved edge.
        let mut edges: Vec<(usize, usize)> = Vec::new();
        for (fi, f) in self.files.iter().enumerate() {
            if f.ambiguous {
                continue;
            }
            let b = base.get(fi).copied().unwrap_or(0);
            for (ti, t) in f.parsed.types.iter().enumerate() {
                for name in t.extends.iter().chain(&t.implements) {
                    match self.resolve_super(fi, ti, name) {
                        None => {
                            if let Some(x) = external.get_mut(b + ti) {
                                *x = true;
                            }
                        }
                        Some((fj, tj)) => {
                            if let Some(&bj) = base.get(fj) {
                                edges.push((bj + tj, b + ti));
                            }
                        }
                    }
                }
            }
        }
        edges.sort_unstable();
        edges.dedup();
        let subs = |x: usize| {
            let lo = edges.partition_point(|e| e.0 < x);
            let hi = edges.partition_point(|e| e.0 <= x);
            edges.get(lo..hi).unwrap_or(&[])
        };
        let mut todo: Vec<usize> = Vec::new();
        for x in 0..total {
            if external.get(x) != Some(&true) || subs(x).is_empty() {
                continue;
            }
            todo.push(x);
            while let Some(y) = todo.pop() {
                for &(_, s) in subs(y) {
                    let Some(flag) = external.get_mut(s) else {
                        continue;
                    };
                    if *flag {
                        continue;
                    }
                    *flag = true;
                    if !subs(s).is_empty() {
                        if todo.len() >= MAX_WORKLIST {
                            return (base, external, true);
                        }
                        todo.push(s);
                    }
                }
            }
        }
        (base, external, false)
    }

    // ---- entries and reachability ------------------------------------------

    /// Resolve `package.Class:method`: files whose path ends with
    /// `package/Class.java` (any prefix), top-level type `Class`, every
    /// method or constructor named `method`. `Err` when nothing matches (the
    /// caller exits 2).
    pub fn resolve_entry(&self, spec: &str) -> Result<Vec<MemberId>, String> {
        let bad = |why: &str| format!("--entry {spec:?}: {why}");
        let (class, method) = spec
            .split_once(':')
            .ok_or_else(|| bad("expected package.Class:method"))?;
        let ident = |s: &str| {
            s.bytes()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_' || c == b'$')
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'$')
        };
        if !ident(method) || class.is_empty() || !class.split('.').all(ident) {
            return Err(bad(
                "expected package.Class:method with plain ASCII identifiers",
            ));
        }
        let path = format!("{}.java", class.replace('.', "/"));
        let suffix = format!("/{path}");
        let simple = simple_name(class);
        let mut out = Vec::new();
        for (fi, f) in self.files.iter().enumerate() {
            if f.ambiguous || !(f.rel == path || f.rel.ends_with(&suffix)) {
                continue;
            }
            for (mi, m) in f.parsed.members.iter().enumerate() {
                let top_level = f
                    .parsed
                    .types
                    .get(m.type_idx)
                    .is_some_and(|t| t.parent.is_none() && t.name == simple);
                if top_level
                    && m.name == method
                    && matches!(m.kind, MemberKind::Method | MemberKind::Constructor)
                {
                    out.push(MemberId {
                        file: fi,
                        member: mi,
                    });
                }
            }
        }
        if out.is_empty() {
            return Err(bad("no such method found in the analyzed .java files"));
        }
        Ok(out)
    }

    /// `node` of every project type whose simple name matches a written
    /// supertype of `(fi, ti)` (`extends`, and `implements` too with
    /// `interfaces`). Used for edges only, so the over-approximation (a
    /// same-named unrelated type) adds edges and never hides one; whether a
    /// supertype is external is decided by [`JavaProject::resolve_super`].
    /// A name already in `seen` is skipped: its types were queued by its
    /// first expansion (N same-named types would otherwise give N² edges).
    fn push_supers<'a>(
        &'a self,
        (fi, ti): (usize, usize),
        interfaces: bool,
        seen: &mut HashSet<&'a str>,
        node: fn(usize, usize) -> Node,
        out: &mut Vec<Node>,
    ) {
        let Some(t) = self.files.get(fi).and_then(|f| f.parsed.types.get(ti)) else {
            return;
        };
        let implements: &[String] = if interfaces { &t.implements } else { &[] };
        for name in t.extends.iter().chain(implements) {
            let simple = simple_name(name);
            if seen.insert(simple) {
                for &(fj, tj) in self.types_by_name.get(simple).into_iter().flatten() {
                    out.push(node(fj, tj));
                }
            }
        }
    }

    fn members_of(&self, fi: usize, ti: usize) -> impl Iterator<Item = (usize, &Member)> {
        let f = self.files.get(fi);
        self.type_members
            .get(&(fi, ti))
            .into_iter()
            .flatten()
            .filter_map(move |&mi| f.and_then(|f| f.parsed.members.get(mi)).map(|m| (mi, m)))
    }

    /// Successors of `n`. Each called name, each instantiated type name
    /// (`new`, supertypes of an instance) and each initialized supertype
    /// name is expanded at most once per BFS: its first expansion reaches
    /// every target of that name.
    fn successors<'a>(&'a self, n: Node, seen: &mut Expanded<'a>, out: &mut Vec<Node>) {
        match n {
            Node::Entry(_) => {}
            Node::Member(fi, mi) => {
                let Some(f) = self.files.get(fi) else {
                    return;
                };
                let Some(m) = f.parsed.members.get(mi) else {
                    return;
                };
                let ti = m.type_idx;
                out.push(Node::Init(fi, ti));
                if m.kind == MemberKind::Constructor {
                    out.push(Node::Instance(fi, ti));
                }
                for r in f.refs.get(mi).into_iter().flatten() {
                    match r {
                        Ref::Call(name) => {
                            if seen.called.insert(name.as_str()) {
                                for &(fj, mj) in self.methods.get(name).into_iter().flatten() {
                                    out.push(Node::Member(fj, mj));
                                }
                            }
                        }
                        Ref::New(name) => {
                            if seen.newed.insert(name.as_str()) {
                                for &(fj, tj) in self.types_by_name.get(name).into_iter().flatten()
                                {
                                    out.push(Node::Instance(fj, tj));
                                }
                            }
                        }
                        Ref::Super => {
                            self.push_supers((fi, ti), false, &mut seen.newed, Node::Instance, out);
                        }
                        Ref::This => out.push(Node::Instance(fi, ti)),
                    }
                }
            }
            Node::Init(fi, ti) => {
                for (mi, m) in self.members_of(fi, ti) {
                    let is_static_init = m.kind == MemberKind::StaticInit
                        || (m.kind == MemberKind::FieldInit && m.is_static);
                    if is_static_init {
                        out.push(Node::Member(fi, mi));
                    }
                }
                self.push_supers((fi, ti), true, &mut seen.inited, Node::Init, out);
                // Initializing an enum creates its constants.
                let is_enum = self
                    .files
                    .get(fi)
                    .and_then(|f| f.parsed.types.get(ti))
                    .is_some_and(|t| t.kind == TypeKind::Enum);
                if is_enum {
                    out.push(Node::Instance(fi, ti));
                }
            }
            Node::Instance(fi, ti) => {
                out.push(Node::Init(fi, ti));
                for (mi, m) in self.members_of(fi, ti) {
                    let instance_code =
                        matches!(m.kind, MemberKind::Constructor | MemberKind::InstanceInit)
                            || (m.kind == MemberKind::FieldInit && !m.is_static);
                    if instance_code {
                        out.push(Node::Member(fi, mi));
                    }
                }
                // Every constructor runs a superclass constructor.
                self.push_supers((fi, ti), false, &mut seen.newed, Node::Instance, out);
            }
        }
    }

    /// BFS from every launcher `main` and from the `entries` specs. A spec
    /// that does not resolve in this project is ignored here: the caller
    /// checks every spec with [`JavaProject::resolve_entry`] (and the Python
    /// project) first, and exits 2 when none resolves it.
    pub fn reach(&self, entries: &[String]) -> Reach {
        let mut links: HashMap<Node, Link> = HashMap::new();
        let mut queue: VecDeque<Node> = VecDeque::new();
        let mut truncated = false;
        for (fi, f) in self.files.iter().enumerate() {
            if f.ambiguous {
                continue;
            }
            for (mi, m) in f.parsed.members.iter().enumerate() {
                if m.is_main_entry {
                    truncated |= !visit(&mut links, &mut queue, Node::Member(fi, mi), None);
                }
            }
        }
        for (i, spec) in entries.iter().enumerate() {
            let Ok(targets) = self.resolve_entry(spec) else {
                continue;
            };
            let e = Node::Entry(i);
            links.insert(e, Link::new(e, None, None));
            for id in targets {
                let n = Node::Member(id.file, id.member);
                truncated |= !visit(&mut links, &mut queue, n, Some(e));
            }
        }
        let mut succ = Vec::new();
        let mut seen = Expanded::default();
        'bfs: while let Some(n) = queue.pop_front() {
            succ.clear();
            self.successors(n, &mut seen, &mut succ);
            for &s in &succ {
                if !visit(&mut links, &mut queue, s, Some(n)) {
                    truncated = true;
                    break 'bfs;
                }
            }
        }
        Reach {
            links,
            entries: entries.to_vec(),
            truncated,
        }
    }

    /// `Outer.Inner.method`, `Type.<init>`, `Type.<clinit>`,
    /// `Type.<field-init>`, `Type.<init-block>`.
    fn member_label(&self, fi: usize, mi: usize) -> String {
        let Some(f) = self.files.get(fi) else {
            return String::new();
        };
        let Some(m) = f.parsed.members.get(mi) else {
            return String::new();
        };
        let qual = f
            .parsed
            .types
            .get(m.type_idx)
            .map_or("?", |t| t.qualified.as_str());
        let name = match m.kind {
            MemberKind::Constructor => "<init>",
            _ => m.name.as_str(),
        };
        // Clipped before formatting: a name may be megabytes long.
        clip_label(format!("{}.{}", label_part(qual), label_part(name)))
    }

    /// Chain label of a node; `None` for the internal type nodes.
    fn node_label(&self, n: Node, reach: &Reach) -> Option<String> {
        match n {
            Node::Member(fi, mi) => Some(clip_label(format!(
                "{}:{}",
                self.files.get(fi).map_or("", |f| f.rel.as_str()),
                self.member_label(fi, mi)
            ))),
            Node::Entry(i) => Some(clip_label(format!(
                "--entry {}",
                reach.entries.get(i).map_or("", String::as_str)
            ))),
            Node::Init(..) | Node::Instance(..) => None,
        }
    }

    /// Labels of the chain from an entry to `target`: all of them up to
    /// [`MAX_CHAIN`], else the first `MAX_CHAIN / 2`, `…` and the last
    /// `MAX_CHAIN / 2`. Only those are formatted, and at most `MAX_CHAIN`
    /// links are followed: the tail walks up from `target`, the head from
    /// its [`Link::anchor`].
    fn chain_to(&self, target: Node, reach: &Reach) -> Vec<String> {
        let Some(link) = reach.links.get(&target) else {
            return Vec::new();
        };
        let last = if is_labeled(target) {
            Some(target)
        } else {
            link.up
        };
        // Up to `n` labeled nodes ending at `from`, root side first.
        let walk = |from: Option<Node>, n: usize| -> Vec<Node> {
            let mut out: Vec<Node> = Vec::new();
            let mut cur = from;
            while let Some(x) = cur
                && out.len() < n
            {
                out.push(x);
                cur = reach.links.get(&x).and_then(|l| l.up);
            }
            out.reverse();
            out
        };
        let fmt = |n: &Node| self.node_label(*n, reach).unwrap_or_default();
        if link.depth <= MAX_CHAIN {
            return walk(last, MAX_CHAIN).iter().map(fmt).collect();
        }
        let mut labels: Vec<String> = walk(link.anchor, MAX_CHAIN / 2).iter().map(fmt).collect();
        labels.push("…".to_string());
        labels.extend(walk(last, MAX_CHAIN / 2).iter().map(fmt));
        labels
    }

    // ---- classification ----------------------------------------------------

    /// The one project type that the supertype `written` in the header of
    /// `(fi, ti)` names, or `None` when it may be external or is ambiguous.
    ///
    /// - A qualified name `A.B.C` resolves when its first segment `A`
    ///   resolves by the simple-name rules below and `B.C` are the member
    ///   types of that project type (a type obscures a package, JLS 6.4.2);
    ///   otherwise only when `A` is no single-type import's name and the
    ///   whole name equals exactly one project type's `package.Outer.Inner`
    ///   with a non-empty package (a default-package `A.B.C` cannot be
    ///   named from elsewhere, and `A` may be an imported or `java.lang`
    ///   type).
    /// - A simple name of a local type (or a type nested in one) is never
    ///   resolved: local classes and inherited members of anonymous classes
    ///   are in scope there.
    /// - Otherwise, innermost first, each enclosing type: its one member type
    ///   of that name; none, but it has a supertype that could supply an
    ///   inherited member type → `None`.
    /// - Then the file's single-type imports of that name (exactly one, which
    ///   must be a project type), then exactly one top-level type of the
    ///   same package. Anything else (on-demand imports, `java.lang`) →
    ///   `None`.
    fn resolve_super(&self, fi: usize, ti: usize, written: &str) -> Option<(usize, usize)> {
        let f = self.files.get(fi)?;
        let one = |v: Option<&Vec<(usize, usize)>>| match v.map(Vec::as_slice) {
            Some([x]) => Some(*x),
            _ => None,
        };
        if let Some((first, rest)) = written.split_once('.') {
            // `first` has no `.`: one level of recursion at most.
            if let Some((fj, tj)) = self.resolve_super(fi, ti, first) {
                return self.nested_path(fj, tj, rest);
            }
            if f.imports_by_name.contains_key(first) {
                return None;
            }
            let (fj, tj) = one(self.types_by_full.get(written))?;
            let packaged = self
                .files
                .get(fj)?
                .parsed
                .package
                .as_deref()
                .is_some_and(|p| !p.is_empty());
            return packaged.then_some((fj, tj));
        }
        let types = &f.parsed.types;
        let mut cur = Some(ti);
        let mut steps = 0usize;
        while let Some(c) = cur {
            steps += 1;
            let t = types.get(c)?;
            if t.local || steps > types.len() {
                return None;
            }
            cur = t.parent;
            let Some(enc) = cur else {
                break;
            };
            let et = types.get(enc)?;
            let declared = self
                .nested_named
                .get(&(fi, enc))
                .and_then(|by_name| by_name.get(written))
                .map(Vec::as_slice);
            match declared {
                Some([n]) => return Some((fi, *n)),
                Some([_, _, ..]) => return None,
                _ => {}
            }
            if !et.extends.is_empty() || !et.implements.is_empty() {
                return None;
            }
        }
        // Single-type imports whose last segment is `written`.
        match f.imports_by_name.get(written).map(Vec::as_slice) {
            None | Some([]) => {}
            Some([one_import]) => return one(self.types_by_full.get(one_import)),
            Some(_) => return None,
        }
        let same_package = self
            .top_level
            .get(written)
            .and_then(|by_pkg| by_pkg.get(&f.pkg_id))
            .map(Vec::as_slice);
        match same_package {
            Some([x]) => Some(*x),
            _ => None,
        }
    }

    /// The member type `(fi, ti).B.C` for `path` = `B.C`: at each step
    /// exactly one non-local member type of that name, else `None` (an
    /// inherited member type is not followed: it may be external).
    fn nested_path(&self, fi: usize, ti: usize, path: &str) -> Option<(usize, usize)> {
        let mut cur = ti;
        for seg in path.split('.') {
            match self
                .nested_named
                .get(&(fi, cur))
                .and_then(|by_name| by_name.get(seg))
                .map(Vec::as_slice)
            {
                Some([n]) => cur = *n,
                _ => return None,
            }
        }
        Some((fi, cur))
    }

    /// Whether `(fi, ti)` or any project supertype of it extends or
    /// implements a type that does not resolve to exactly one project type
    /// (see [`JavaProject::resolve_super`]); precomputed by
    /// [`JavaProject::compute_external`]. `None` when that hit
    /// [`MAX_WORKLIST`].
    fn external_supertype(&self, fi: usize, ti: usize) -> Option<bool> {
        if self.external_limit {
            return None;
        }
        let b = self.type_base.get(fi)?;
        Some(self.external.get(b + ti).copied().unwrap_or(true))
    }

    /// Label one occurrence at `rel:line` (1-based, `rel` uses `/`).
    pub fn classify(&self, reach: &Reach, rel: &str, line: u32) -> Verdict {
        if !rel.ends_with(".java") {
            return unknown("not_java_file");
        }
        if let Some(why) = self.limit {
            return unknown(why);
        }
        let Some(&fi) = self.index.get(rel) else {
            return unknown(
                self.skipped
                    .get(rel)
                    .copied()
                    .unwrap_or("file_not_analyzed"),
            );
        };
        let f = &self.files[fi];
        if f.ambiguous {
            return unknown("file_parse_ambiguity");
        }
        if line == 0 || line > f.nlines {
            return unknown("line_out_of_range");
        }
        let members = &f.parsed.members;
        // Members are nested or disjoint and every holder has code on
        // `line`, so a holder whose line range strictly contains another's
        // encloses it. The encloser is ruled out only when the inner member
        // spans the whole line (it starts above and ends below): otherwise
        // the line may also hold the encloser's own code.
        let candidates = f.lines.candidates(members, line);
        let Some(mut mi) = innermost(members, candidates.iter().copied()) else {
            return unknown("outside_member");
        };
        if candidates.len() > 1 {
            // Several members share the line: reachable if any is.
            let reached = candidates
                .iter()
                .copied()
                .filter(|&i| reach.links.contains_key(&Node::Member(fi, i)));
            match innermost(members, reached) {
                Some(r) => mi = r,
                None => return unknown("line_shared_by_members"),
            }
        }
        let Some(m) = members.get(mi) else {
            return unknown("outside_member");
        };
        let mut v = Verdict {
            label: Label::Unknown,
            reasons: Vec::new(),
            enclosing_function: Some(self.member_label(fi, mi)),
            chain: Vec::new(),
        };
        let node = Node::Member(fi, mi);
        if reach.links.contains_key(&node) {
            let reason = match m.kind {
                MemberKind::StaticInit => CLASS_INIT,
                MemberKind::FieldInit if m.is_static => CLASS_INIT,
                MemberKind::InstanceInit | MemberKind::FieldInit => CTOR_REACHABLE,
                MemberKind::Method | MemberKind::Constructor => "name_based_chain_from_entry",
            };
            v.label = Label::Reachable;
            v.reasons.push(reason.into());
            v.chain = self.chain_to(node, reach);
            return v;
        }
        // From here only `not_observed` or `unknown` remain.
        if reach.truncated {
            v.reasons.push(ANALYSIS_LIMIT.into());
            return v;
        }
        if let Some(why) = self.incomplete.first() {
            v.reasons.push(format!("project_not_fully_analyzed:{why}"));
            return v;
        }
        if !matches!(m.kind, MemberKind::Method | MemberKind::Constructor) {
            v.reasons.push("initializer_not_modeled".into());
            return v;
        }
        // Annotations of the member and of every enclosing type, and the
        // simple names of those types.
        let mut annotations: Vec<&str> = m.annotations.iter().map(String::as_str).collect();
        let mut type_names: Vec<&str> = Vec::new();
        let mut cur = Some(m.type_idx);
        let mut steps = 0usize;
        while let Some(ti) = cur {
            steps += 1;
            let Some(t) = f.parsed.types.get(ti) else {
                break;
            };
            if steps > f.parsed.types.len() {
                break;
            }
            annotations.extend(t.annotations.iter().map(String::as_str));
            type_names.push(t.name.as_str());
            cur = t.parent;
        }
        if annotations.iter().any(|a| !BENIGN_ANNOTATIONS.contains(a)) {
            v.reasons.push(ANNOTATED.into());
            return v;
        }
        if self.reflection {
            v.reasons.push("reflection_in_project".into());
            return v;
        }
        match self.external_supertype(fi, m.type_idx) {
            None => {
                v.reasons.push(ANALYSIS_LIMIT.into());
                return v;
            }
            Some(true) => {
                v.reasons.push("overrides_external_type_possible".into());
                return v;
            }
            Some(false) => {}
        }
        if JDK_IMPLICIT_NAMES.contains(&m.name.as_str()) {
            v.reasons.push("jdk_implicit_name".into());
            return v;
        }
        // Serializers, mappers, templates and `java.beans` call accessors by
        // property name.
        if m.kind == MemberKind::Method && is_bean_accessor(&m.name) {
            v.reasons.push("bean_accessor_possible".into());
            return v;
        }
        if self.config_words.contains(&m.name)
            || type_names.iter().any(|t| self.config_words.contains(*t))
        {
            v.reasons.push("named_in_config_file".into());
            return v;
        }
        let c = self.ref_counts.get(&m.name).copied().unwrap_or_default();
        if c.call > 0 {
            v.reasons.push("referenced_but_no_entry_path".into());
            return v;
        }
        if c.any > 0 {
            v.reasons.push("method_referenced_not_modeled".into());
            return v;
        }
        // An annotated member is never `not_observed`, benign annotation or not.
        if !annotations.is_empty() {
            v.reasons.push(ANNOTATED.into());
            return v;
        }
        v.label = Label::NotObserved;
        v.reasons.push("no_textual_reference".into());
        v
    }
}

// ---- token scan --------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Tok {
    start: usize,
    end: usize,
    ident: bool,
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c == b'$'
}

fn is_ident_part(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// Identifier and single-character punctuation tokens of the blanked code,
/// with byte offsets (the parser's offsets: both read the same `code`).
/// Numbers, quotes and whitespace are dropped.
fn tokenize(code: &str) -> Vec<Tok> {
    let b = code.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c.is_ascii_whitespace() || c == 0x0c || c == b'"' || c == b'\'' {
            i += 1;
            continue;
        }
        let start = i;
        let ident = if is_ident_start(c) {
            i += 1;
            while b.get(i).is_some_and(|&d| is_ident_part(d)) {
                i += 1;
            }
            true
        } else if c.is_ascii_digit() {
            i += 1;
            while b
                .get(i)
                .is_some_and(|&d| d.is_ascii_alphanumeric() || d == b'_' || d == b'.')
            {
                i += 1;
            }
            continue;
        } else {
            i += code
                .get(i..)
                .and_then(|s| s.chars().next())
                .map_or(1, char::len_utf8);
            false
        };
        toks.push(Tok {
            start,
            end: i,
            ident,
        });
    }
    toks
}

struct FileScan {
    refs: Vec<Vec<Ref>>,
    counts: HashMap<String, Counts>,
    reflection: bool,
    /// A qualified name (import, package or use) of a
    /// [`REFLECTIVE_LIBRARIES`] package.
    library: bool,
}

/// One pass over the tokens of a parsed file: edge sources per member,
/// reference counts of `relevant` names, and the reflection flag.
fn scan_file(code: &str, parsed: &JavaFile, relevant: &HashSet<String>) -> FileScan {
    let toks = tokenize(code);
    let text = |i: usize| {
        toks.get(i)
            .and_then(|t| code.get(t.start..t.end))
            .unwrap_or("")
    };
    let is_ident = |i: usize| toks.get(i).is_some_and(|t| t.ident);
    let members = &parsed.members;
    let order = span_order(members);
    let mut stack: Vec<usize> = Vec::new();
    let mut next = 0usize;
    let mut sets: Vec<BTreeSet<Ref>> = vec![BTreeSet::new(); members.len()];
    let mut by_name: HashMap<&str, Counts> = HashMap::new();
    let mut reflection = false;
    let mut library = false;
    // Each declaration's own name token is not a reference (else a method
    // would reach every method of its own name).
    let decls: HashSet<usize> = members
        .iter()
        .filter(|m| matches!(m.kind, MemberKind::Method | MemberKind::Constructor))
        .filter_map(|m| m.name_byte)
        .collect();
    for (i, t) in toks.iter().enumerate() {
        if !t.ident {
            continue;
        }
        let is_decl = decls.contains(&t.start);
        let name = text(i);
        let prev = |k: usize| i.checked_sub(k).map_or("", text);
        let after_ref = prev(1) == ":" && prev(2) == ":";
        let call = text(i + 1) == "(";
        // `x.load(…)` / `X::load` may load a native library
        // (`System.load`, `Runtime.load`).
        let load =
            name == "load" && (after_ref || (prev(1) == "." && (call || prev(2) == "System")));
        if REFLECTION_WORDS.contains(&name)
            || REFLECTION_PREFIXES.iter().any(|p| name.starts_with(p))
            || load
        {
            reflection = true;
        }
        // The start of a qualified name: its first few segments.
        if !library && prev(1) != "." {
            let mut q = String::new();
            let mut k = i;
            for _ in 0..MAX_LIBRARY_SEGMENTS {
                if !is_ident(k) {
                    break;
                }
                if !q.is_empty() {
                    q.push('.');
                }
                q.push_str(text(k));
                // A package prefix is followed by `.` (a variable named
                // `dagger` alone is not).
                if text(k + 1) != "." {
                    break;
                }
                if REFLECTIVE_LIBRARIES.contains(&q.as_str()) {
                    library = true;
                    break;
                }
                k += 2;
            }
        }
        let r = if is_decl {
            None
        } else if after_ref {
            if name == "new" {
                i.checked_sub(3)
                    .filter(|&j| is_ident(j))
                    .map(|j| Ref::New(text(j).to_string()))
            } else {
                Some(Ref::Call(name.to_string()))
            }
        } else if name == "new" {
            new_target(&toks, code, i).map(Ref::New)
        } else if call && name == "super" {
            Some(Ref::Super)
        } else if call && name == "this" {
            Some(Ref::This)
        } else if call && !NOT_CALLS.contains(&name) {
            Some(Ref::Call(name.to_string()))
        } else {
            None
        };
        // Member byte spans are properly nested or disjoint: keep the stack
        // of those holding this token, innermost on top. Each member is
        // pushed and popped once, and the token goes to the top only.
        let pos = t.start;
        while let Some(&m) = order.get(next) {
            let (start, _) = byte_span(members, m);
            if start > pos {
                break;
            }
            while stack
                .last()
                .is_some_and(|&s| byte_span(members, s).1 <= start)
            {
                stack.pop();
            }
            stack.push(m);
            next += 1;
        }
        while stack
            .last()
            .is_some_and(|&s| byte_span(members, s).1 <= pos)
        {
            stack.pop();
        }
        if let (Some(r), Some(&top)) = (r, stack.last())
            && let Some(set) = sets.get_mut(top)
        {
            set.insert(r);
        }
        if !is_decl && relevant.contains(name) {
            let c = by_name.entry(name).or_default();
            c.any = c.any.saturating_add(1);
            if call || after_ref {
                c.call = c.call.saturating_add(1);
            }
        }
    }
    let counts: HashMap<String, Counts> = by_name
        .into_iter()
        .map(|(name, c)| (name.to_string(), c))
        .collect();
    FileScan {
        refs: sets.into_iter().map(|s| s.into_iter().collect()).collect(),
        counts,
        reflection,
        library,
    }
}

/// The simple type name of `new a.b.X<…>(` whose `new` is token `i`.
fn new_target(toks: &[Tok], code: &str, i: usize) -> Option<String> {
    let text = |k: usize| {
        toks.get(k)
            .and_then(|t| code.get(t.start..t.end))
            .unwrap_or("")
    };
    let is_ident = |k: usize| toks.get(k).is_some_and(|t| t.ident);
    let mut j = i + 1;
    let mut last = None;
    while is_ident(j) {
        last = Some(text(j));
        j += 1;
        if text(j) == "." && is_ident(j + 1) {
            j += 1;
        } else {
            break;
        }
    }
    let last = last?;
    if text(j) == "<" {
        let mut depth = 0usize;
        let limit = j + MAX_TYPE_ARG_TOKENS;
        loop {
            if j >= limit || j >= toks.len() {
                return None;
            }
            match text(j) {
                "<" => depth += 1,
                ">" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        j += 1;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
    }
    (text(j) == "(").then(|| last.to_string())
}

// ---- config-file decoding ----------------------------------------------------

/// A numeric escape at byte `i`: `\uXXXX` (one or more `u`), `\xHH`,
/// `\UXXXXXXXX`, `&#NNN;` or `&#xHH;`. Returns the character (U+0020 for a
/// value that is not a `char`) and the byte index after the escape.
fn numeric_escape_at(s: &str, i: usize) -> Option<(char, usize)> {
    let b = s.as_bytes();
    let hex = |from: usize, n: usize| -> Option<u32> {
        let d = s.get(from..from.checked_add(n)?)?;
        if d.bytes().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(d, 16).ok()
        } else {
            None
        }
    };
    let as_char = |v: u32| char::from_u32(v).unwrap_or(' ');
    match (b.get(i), b.get(i + 1)) {
        (Some(b'\\'), Some(b'u')) => {
            let mut j = i + 1;
            while b.get(j) == Some(&b'u') {
                j += 1;
            }
            Some((as_char(hex(j, 4)?), j + 4))
        }
        (Some(b'\\'), Some(b'x')) => Some((as_char(hex(i + 2, 2)?), i + 4)),
        (Some(b'\\'), Some(b'U')) => Some((as_char(hex(i + 2, 8)?), i + 10)),
        (Some(b'&'), Some(b'#')) => {
            let (radix, start) = if matches!(b.get(i + 2), Some(b'x' | b'X')) {
                (16, i + 3)
            } else {
                (10, i + 2)
            };
            let mut j = start;
            while j - start < 8 && b.get(j).is_some_and(|&c| char::from(c).is_digit(radix)) {
                j += 1;
            }
            if j == start || b.get(j) != Some(&b';') {
                return None;
            }
            let v = u32::from_str_radix(s.get(start..j)?, radix).ok()?;
            Some((as_char(v), j + 1))
        }
        _ => None,
    }
}

fn push_char_at(s: &str, i: &mut usize, out: &mut String) {
    match s.get(*i..).and_then(|r| r.chars().next()) {
        Some(c) => {
            out.push(c);
            *i += c.len_utf8();
        }
        None => *i += 1,
    }
}

/// `s` with every numeric escape decoded (XML, JSON, YAML).
fn decode_numeric_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if let Some((c, next)) = numeric_escape_at(s, i) {
            out.push(c);
            i = next;
            continue;
        }
        push_char_at(s, &mut i, &mut out);
    }
    out
}

/// `s` with backslash escapes decoded: numeric escapes, `\\` → `\`,
/// `\<line end>` joins the next line without its leading whitespace
/// (`.properties` continuation, YAML escaped line break). Any other `\c`
/// becomes `c` (`Properties.load`) or, with `drop_escaped`, a space (`\n`,
/// `\t`, YAML `\N`, …). The caller takes the words of both variants.
fn decode_backslashes(s: &str, drop_escaped: bool) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            if let Some((c, next)) = numeric_escape_at(s, i) {
                out.push(c);
                i = next;
                continue;
            }
            match b.get(i + 1).copied() {
                Some(b'\\') => {
                    out.push('\\');
                    i += 2;
                }
                Some(e) if e == b'\r' || e == b'\n' => {
                    i += 2;
                    if e == b'\r' && b.get(i) == Some(&b'\n') {
                        i += 1;
                    }
                    while matches!(b.get(i), Some(b' ' | b'\t' | 0x0c)) {
                        i += 1;
                    }
                }
                Some(_) if drop_escaped => {
                    out.push(' ');
                    i += 1;
                    i += s
                        .get(i..)
                        .and_then(|r| r.chars().next())
                        .map_or(1, char::len_utf8);
                }
                _ => i += 1,
            }
            continue;
        }
        push_char_at(s, &mut i, &mut out);
    }
    out
}

/// Whether blanked `code` (see [`super::java_lex`]: comments and literal
/// contents are blank) holds a [`REFLECTION_WORDS`] entry as a whole
/// identifier token, or an identifier starting with a [`REFLECTION_PREFIXES`]
/// entry. The analyzer applies this rule project-wide (`reflection_in_project`).
/// Annotations are not part of it: the per-member rule is checked separately
/// (see [`annotation_rule_ok`]). A reflection word inside a string or comment
/// does not trigger it.
#[cfg(any(test, feature = "fuzzing"))]
pub fn code_guard_triggered(code: &str) -> bool {
    // Non-ASCII bytes count as identifier bytes: a token next to them is
    // not a whole reflection word.
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 0x80;
    code.as_bytes().split(|&c| !is_ident(c)).any(|tok| {
        REFLECTION_WORDS.iter().any(|w| w.as_bytes() == tok)
            || REFLECTION_PREFIXES
                .iter()
                .any(|p| tok.starts_with(p.as_bytes()))
    })
}

/// The fuzz invariant behind the per-member annotation rule: every line
/// labelled `not_observed` in `rows` (of the one-file project at `rel`) has,
/// as its innermost member (the one [`JavaProject::classify`] picks: the sole
/// candidate of the line), a member and enclosing types without any
/// annotation. Computed from the parsed member and type annotation lists.
#[cfg(feature = "fuzzing")]
fn annotation_rule_ok(project: &JavaProject, rel: &str, rows: &[(u32, &str)]) -> bool {
    let Some(&fi) = project.index.get(rel) else {
        return rows.iter().all(|(_, label)| *label != "not_observed");
    };
    let f = &project.files[fi];
    let members = &f.parsed.members;
    rows.iter()
        .filter(|(_, label)| *label == "not_observed")
        .all(|&(line, _)| {
            let candidates = f.lines.candidates(members, line);
            let Some(m) =
                innermost(members, candidates.iter().copied()).and_then(|mi| members.get(mi))
            else {
                return false;
            };
            if !m.annotations.is_empty() {
                return false;
            }
            let mut cur = Some(m.type_idx);
            let mut steps = 0usize;
            while let Some(ti) = cur {
                steps += 1;
                let Some(t) = f.parsed.types.get(ti) else {
                    return false;
                };
                if steps > f.parsed.types.len() || !t.annotations.is_empty() {
                    return false;
                }
                cur = t.parent;
            }
            true
        })
}

/// Fuzz entry (feature `fuzzing`, see `audit::fuzzing`): build a one-file
/// project from `src` as `src/main/java/com/ex/Main.java`, reach from the
/// default `main` entries and classify every line `1..=lines + 1`. Returns
/// `(line, label)` pairs (empty when `src` is not UTF-8) and whether the
/// lexer's code view of `src` triggers the reflection guard (see
/// [`code_guard_triggered`]), and whether every `not_observed` row satisfies
/// the per-member annotation rule (see [`annotation_rule_ok`]).
#[cfg(feature = "fuzzing")]
pub fn java_usage_one(src: &[u8]) -> (Vec<(u32, &'static str)>, bool, bool) {
    let Ok(text) = std::str::from_utf8(src) else {
        return (Vec::new(), false, true);
    };
    let guarded = code_guard_triggered(&lex(text).code);
    const REL: &str = "src/main/java/com/ex/Main.java";
    let project = JavaProject::from_sources(vec![(REL.to_string(), text.to_string())]);
    let reach = project.reach(&[]);
    let lines = count_lines(text);
    let rows: Vec<(u32, &'static str)> = (1..=lines.saturating_add(1))
        .map(|line| {
            let verdict = project.classify(&reach, REL, line);
            (line, verdict.label.as_str())
        })
        .collect();
    let annotation_ok = annotation_rule_ok(&project, REL, &rows);
    (rows, guarded, annotation_ok)
}

#[cfg(test)]
#[path = "java_usage_tests.rs"]
mod tests;
