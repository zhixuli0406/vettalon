//! Token and brace structure of one Java source file for the `cbom-check`
//! Java analyzer. The input is the `code` view from [`super::java_lex`]
//! (comments and literal contents already blanked to spaces), so every token
//! seen here is real code. The input is untrusted: one linear pass over the
//! tokens with an explicit frame stack capped at [`MAX_DEPTH`] (no recursion
//! over the input, no regex, no backtracking); never panics.
//!
//! This is not a Java parser. It finds:
//! - the `package` and `import` declarations;
//! - type declarations (`class`, `interface`, `enum`, `record`,
//!   `@interface`), nested, inner and local ones included, with their
//!   annotations and `extends` / `implements` lists;
//! - members with a body: methods, constructors (record compact
//!   constructors included), static and instance initializers, field
//!   declarations with an initializer (`=`), and an enum's constant list
//!   (as one static field initializer).
//!
//! Lambda bodies, anonymous-class bodies (and the methods in them) and enum
//! constant bodies are plain nested braces of the member or field
//! initializer that contains them. Classes declared inside a member body are
//! types of their own (parent = the enclosing type) with their own members.
//!
//! How: every brace frame (file level, type body, member body, block) keeps
//! the tokens of its current *segment*: what it has seen at its own level
//! since its last `;`, `{` or `}`, with each balanced `( … )` / `[ … ]` /
//! `{ … }` kept as one entry. A `{` is classified from that segment. Inside a
//! field initializer or the enum constant list the segment runs on to the
//! closing `;`, across the braces of lambdas, anonymous classes and constant
//! bodies. Anything at type-body level that fits no known shape makes the
//! file ambiguous, and the caller fails closed.

use super::java_lex::JavaLexed;

/// Deepest nesting of `{`, `(` and `[` together; deeper is ambiguous
/// (`nesting_too_deep`).
pub(super) const MAX_DEPTH: usize = 256;
/// How many segment entries (a balanced `( … )` or `[ … ]` counts as one)
/// the method-header match looks back from a `{` in a type body.
pub(super) const MAX_HEADER_LOOKBACK: usize = 64;
/// Longest qualified type name (`Outer.Inner`), in bytes; longer is
/// ambiguous (`name_too_long`). Bounds the memory a deep chain of nested
/// types with long names can make the parser allocate.
pub(super) const MAX_QUALIFIED_BYTES: usize = 4096;
/// Total bytes of all qualified type names of one file; more is ambiguous
/// (`name_budget_exceeded`). Many sibling types under a deep chain of long
/// names would otherwise copy up to [`MAX_QUALIFIED_BYTES`] each.
pub(super) const MAX_QUALIFIED_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// Longest package name and longest imported name, in bytes; longer is
/// ambiguous (`name_too_long`). The package is copied into the full name of
/// every type of the file.
pub(super) const MAX_PACKAGE_IMPORT_BYTES: usize = 1024;
/// Most members (methods, constructors, initializers, field initializers)
/// in one file; more is ambiguous (`too_many_members`).
pub(super) const MAX_MEMBERS: usize = 50_000;

const UNBALANCED: &str = "unbalanced_braces";
const TOO_DEEP: &str = "nesting_too_deep";
const UNPARSED: &str = "unparsed_member_header";
const NAME_TOO_LONG: &str = "name_too_long";
const NAME_BUDGET: &str = "name_budget_exceeded";
const TOO_MANY_MEMBERS: &str = "too_many_members";

/// Java reserved words (never a method or type name).
const RESERVED: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
    "_",
];

/// Declaration modifiers (`non-sealed` is matched as three tokens).
const MODIFIERS: &[&str] = &[
    "public",
    "protected",
    "private",
    "static",
    "final",
    "abstract",
    "native",
    "synchronized",
    "transient",
    "volatile",
    "strictfp",
    "default",
    "sealed",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TypeKind {
    Class,
    Interface,
    Enum,
    Record,
    /// `@interface`.
    Annotation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MemberKind {
    Method,
    Constructor,
    /// `static { … }` (`<clinit>`).
    StaticInit,
    /// A bare `{ … }` in a type body (`<init-block>`).
    InstanceInit,
    /// A field declaration with an initializer, or an enum's constant list
    /// (`<field-init>`).
    FieldInit,
}

/// One type declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TypeDecl {
    pub(super) name: String,
    /// Enclosing types' names joined with `.` (`Outer.Inner`); a local class
    /// is qualified by the type whose member declares it (`Outer.Local`).
    pub(super) qualified: String,
    pub(super) kind: TypeKind,
    /// Supertypes as written, without type arguments (`Base`,
    /// `java.util.AbstractList`).
    pub(super) extends: Vec<String>,
    pub(super) implements: Vec<String>,
    /// Simple names of the annotations before the type keyword.
    pub(super) annotations: Vec<String>,
    /// First line of the header (annotations included).
    pub(super) line_start: u32,
    /// Line of the closing `}`.
    pub(super) line_end: u32,
    /// Index of the enclosing type in [`JavaFile::types`].
    pub(super) parent: Option<usize>,
    /// Declared inside a member body, a lambda, an anonymous class, an
    /// enum constant body or a field initializer (not a member type of
    /// `parent`): its name is not in scope in `parent`'s body.
    pub(super) local: bool,
}

/// One member with code: a body, or an initializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Member {
    /// Index of the declaring type in [`JavaFile::types`].
    pub(super) type_idx: usize,
    pub(super) kind: MemberKind,
    /// The method name; the type's simple name for constructors;
    /// `<clinit>`, `<init-block>` or `<field-init>` otherwise.
    pub(super) name: String,
    /// Simple names of the annotations in the header (`Override`, `Bean`),
    /// then those in a method's or constructor's parameter list
    /// (`@Observes`: a framework may call the member).
    pub(super) annotations: Vec<String>,
    /// First line of the header (annotations and modifiers included).
    pub(super) line_start: u32,
    /// Line of the closing `}` (`;` for field initializers).
    pub(super) line_end: u32,
    /// Line of the name (the variable before the first `=` for a field
    /// initializer; `static` / `{` for initializers).
    pub(super) header_line: u32,
    /// Byte offset (in the lexed `code`) of the header's first token, as
    /// for `line_start`.
    pub(super) start_byte: usize,
    /// Byte offset just past the closing `}` (`;`, or the last token of an
    /// enum constant list ended by the enum body). Members' byte spans are
    /// properly nested or disjoint.
    pub(super) end_byte: usize,
    /// Byte offset of the name token of a method or constructor.
    pub(super) name_byte: Option<usize>,
    pub(super) is_static: bool,
    /// `void main(String[] a)` / `(String... a)` / `(String a[])` or
    /// `void main()`, not `private` (JDK 21+ launch protocol; covers
    /// `public static void main(String[] args)`).
    pub(super) is_main_entry: bool,
}

/// The structure model of one Java source file.
///
/// When `ambiguity` is `Some`, every other field is empty: the file must be
/// treated as not analyzable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct JavaFile {
    pub(super) package: Option<String>,
    /// Imported names as written, `static` dropped (`java.util.List`,
    /// `java.util.*`, `java.lang.Math.max`).
    pub(super) imports: Vec<String>,
    /// In order of their header's `{`.
    pub(super) types: Vec<TypeDecl>,
    /// In order of their opening `{` (field initializers: closing `;`).
    pub(super) members: Vec<Member>,
    /// Every identifier of the `provides … with …;` and `uses …;`
    /// directives of a module declaration (`module-info.java`), in order:
    /// the JDK's `ServiceLoader` instantiates those providers (or calls
    /// their `provider()` method) without a textual call.
    pub(super) module_names: Vec<String>,
    /// The lexer's reason, or `unbalanced_braces`, `nesting_too_deep`,
    /// `unparsed_member_header`, `name_too_long`, `name_budget_exceeded`,
    /// `too_many_members`.
    pub(super) ambiguity: Option<&'static str>,
}

impl JavaFile {
    fn ambiguous(reason: &'static str) -> Self {
        JavaFile {
            ambiguity: Some(reason),
            ..JavaFile::default()
        }
    }
}

/// Parse the structure of one lexed file. Never panics; linear in the
/// length of `lexed.code`.
pub(super) fn parse(lexed: &JavaLexed) -> JavaFile {
    if let Some(reason) = lexed.ambiguity {
        return JavaFile::ambiguous(reason);
    }
    let mut p = Parser {
        src: Src {
            code: &lexed.code,
            toks: tokenize(&lexed.code),
        },
        stack: vec![Frame::new(FrameKind::Root, None)],
        package: None,
        imports: Vec::new(),
        types: Vec::new(),
        members: Vec::new(),
        module_names: Vec::new(),
        qualified_bytes: 0,
    };
    match p.run() {
        Ok(()) => JavaFile {
            package: p.package,
            imports: p.imports,
            types: p.types,
            members: p.members,
            module_names: p.module_names,
            ambiguity: None,
        },
        Err(reason) => JavaFile::ambiguous(reason),
    }
}

// ---- tokens ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokKind {
    Ident,
    Number,
    /// One character (any character that is not part of an identifier, a
    /// number or whitespace, non-ASCII included).
    Punct,
}

#[derive(Debug, Clone, Copy)]
struct Tok {
    start: usize,
    end: usize,
    line: u32,
    kind: TokKind,
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c == b'$'
}

fn is_ident_part(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// Split the blanked code into tokens with 1-based lines (CR, LF and CRLF
/// each end one line, as in the lexer). Quotes are skipped: their contents
/// are already blank.
fn tokenize(code: &str) -> Vec<Tok> {
    let b = code.as_bytes();
    let mut toks = Vec::new();
    let mut line: u32 = 1;
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        let start = i;
        let kind = if c == b'\r' || c == b'\n' {
            line = line.saturating_add(1);
            i += if c == b'\r' && b.get(i + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
            continue;
        } else if matches!(c, b' ' | b'\t' | 0x0c | b'"' | b'\'') {
            i += 1;
            continue;
        } else if is_ident_start(c) {
            i += 1;
            while b.get(i).is_some_and(|&d| is_ident_part(d)) {
                i += 1;
            }
            TokKind::Ident
        } else if c.is_ascii_digit() {
            let hex = c == b'0' && matches!(b.get(i + 1), Some(b'x' | b'X'));
            i += 1;
            while let Some(&d) = b.get(i) {
                let prev = b.get(i - 1).copied().unwrap_or(0);
                let sign = matches!(d, b'+' | b'-')
                    && matches!((prev, hex), (b'e' | b'E', false) | (b'p' | b'P', true));
                if d.is_ascii_alphanumeric() || d == b'_' || d == b'.' || sign {
                    i += 1;
                } else {
                    break;
                }
            }
            TokKind::Number
        } else {
            i += code
                .get(i..)
                .and_then(|s| s.chars().next())
                .map_or(1, char::len_utf8);
            TokKind::Punct
        };
        toks.push(Tok {
            start,
            end: i,
            line,
            kind,
        });
    }
    toks
}

/// A segment entry: `(first, last)` token index. A single token has
/// `first == last`; a balanced group spans its opener and closer.
type Ent = (usize, usize);

struct Src<'a> {
    code: &'a str,
    toks: Vec<Tok>,
}

/// A type header found by [`Src::type_head`].
struct Head {
    kind: TypeKind,
    name: String,
    annotations: Vec<String>,
    extends: Vec<String>,
    implements: Vec<String>,
    line_start: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Clause {
    None,
    Extends,
    Implements,
    Permits,
}

fn flush(clause: Clause, cur: &mut String, ext: &mut Vec<String>, imp: &mut Vec<String>) {
    let name = std::mem::take(cur);
    if name.is_empty() {
        return;
    }
    match clause {
        Clause::Extends => ext.push(name),
        Clause::Implements => imp.push(name),
        Clause::None | Clause::Permits => {}
    }
}

impl<'a> Src<'a> {
    fn text(&self, i: usize) -> &'a str {
        self.toks
            .get(i)
            .and_then(|t| self.code.get(t.start..t.end))
            .unwrap_or("")
    }

    fn line(&self, i: usize) -> u32 {
        self.toks.get(i).map_or(0, |t| t.line)
    }

    /// Byte offset of token `i`.
    fn start(&self, i: usize) -> usize {
        self.toks.get(i).map_or(0, |t| t.start)
    }

    /// Byte offset just past token `i`.
    fn end(&self, i: usize) -> usize {
        self.toks.get(i).map_or(0, |t| t.end)
    }

    fn is_ident(&self, i: usize) -> bool {
        self.toks.get(i).is_some_and(|t| t.kind == TokKind::Ident)
    }

    /// Text of a single-token entry; `""` for a group or no entry.
    fn word(&self, e: Option<&Ent>) -> &'a str {
        e.filter(|e| e.0 == e.1).map_or("", |e| self.text(e.0))
    }

    fn is(&self, e: Option<&Ent>, s: &str) -> bool {
        e.is_some_and(|e| e.0 == e.1 && self.text(e.0) == s)
    }

    fn ident(&self, e: Option<&Ent>) -> bool {
        e.is_some_and(|e| e.0 == e.1 && self.is_ident(e.0))
    }

    /// A balanced group opened by `open`.
    fn group(&self, e: Option<&Ent>, open: &str) -> bool {
        e.is_some_and(|e| e.0 != e.1 && self.text(e.0) == open)
    }

    /// The annotation `@a.b.Name(…)` starting at `lv[k]`: the index after it
    /// and its simple name. `@interface` is not an annotation.
    fn annotation(&self, lv: &[Ent], k: usize) -> Option<(usize, &'a str)> {
        if !self.is(lv.get(k), "@") || !self.ident(lv.get(k + 1)) {
            return None;
        }
        let mut name = self.word(lv.get(k + 1));
        if name == "interface" {
            return None;
        }
        let mut j = k + 2;
        while self.is(lv.get(j), ".") && self.ident(lv.get(j + 1)) {
            name = self.word(lv.get(j + 1));
            j += 2;
        }
        if self.group(lv.get(j), "(") {
            j += 1;
        }
        Some((j, name))
    }

    /// Simple names of every annotation in `lv`.
    fn annotations(&self, lv: &[Ent]) -> Vec<String> {
        let mut out = Vec::new();
        let mut k = 0;
        while k < lv.len() {
            match self.annotation(lv, k) {
                Some((j, name)) => {
                    out.push(name.to_string());
                    k = j;
                }
                None => k += 1,
            }
        }
        out
    }

    /// Simple names of every annotation inside the balanced group `e` (a
    /// parameter list), nested ones included: `@a.b.Name` → `Name`.
    /// `@interface` is not an annotation. Linear in the group's tokens.
    fn group_annotations(&self, e: Option<&Ent>) -> Vec<String> {
        let mut out = Vec::new();
        let Some(&(open, close)) = e.filter(|e| e.0 != e.1) else {
            return out;
        };
        let mut j = open + 1;
        while j < close {
            if self.text(j) != "@" || !self.is_ident(j + 1) || self.text(j + 1) == "interface" {
                j += 1;
                continue;
            }
            let mut name = self.text(j + 1);
            j += 2;
            while j + 1 < close && self.text(j) == "." && self.is_ident(j + 1) {
                name = self.text(j + 1);
                j += 2;
            }
            out.push(name.to_string());
        }
        out
    }

    /// The index after the annotations and modifiers starting at `lv[k]`.
    fn skip_mods(&self, lv: &[Ent], mut k: usize) -> usize {
        loop {
            if let Some((j, _)) = self.annotation(lv, k) {
                k = j;
                continue;
            }
            let w = self.word(lv.get(k));
            if MODIFIERS.contains(&w) {
                k += 1;
            } else if w == "non" && self.is(lv.get(k + 1), "-") && self.is(lv.get(k + 2), "sealed")
            {
                k += 3;
            } else {
                return k;
            }
        }
    }

    /// `(annotations | modifiers)* (class | interface | enum | record |
    /// @interface) Name …`.
    fn type_head(&self, lv: &[Ent]) -> Option<Head> {
        let mut k = 0;
        let mut annotations = Vec::new();
        let kind = loop {
            if let Some((j, name)) = self.annotation(lv, k) {
                annotations.push(name.to_string());
                k = j;
                continue;
            }
            if self.is(lv.get(k), "@") && self.is(lv.get(k + 1), "interface") {
                k += 2;
                break TypeKind::Annotation;
            }
            let w = self.word(lv.get(k));
            match w {
                "class" => {
                    k += 1;
                    break TypeKind::Class;
                }
                "interface" => {
                    k += 1;
                    break TypeKind::Interface;
                }
                "enum" => {
                    k += 1;
                    break TypeKind::Enum;
                }
                "record"
                    if self.ident(lv.get(k + 1))
                        && (self.group(lv.get(k + 2), "(") || self.is(lv.get(k + 2), "<")) =>
                {
                    k += 1;
                    break TypeKind::Record;
                }
                "non" if self.is(lv.get(k + 1), "-") && self.is(lv.get(k + 2), "sealed") => {
                    k += 3;
                }
                _ if MODIFIERS.contains(&w) => k += 1,
                _ => return None,
            }
        };
        let name = self.word(lv.get(k));
        if !self.ident(lv.get(k)) || RESERVED.contains(&name) {
            return None;
        }
        let line_start = self.line(lv.first()?.0);
        let (mut extends, mut implements) = (Vec::new(), Vec::new());
        let mut clause = Clause::None;
        let mut cur = String::new();
        let mut dot = false;
        let mut angle = 0usize;
        let mut j = k + 1;
        while j < lv.len() {
            if angle == 0
                && let Some((next, _)) = self.annotation(lv, j)
            {
                j = next;
                continue;
            }
            let e = lv.get(j);
            j += 1;
            let w = self.word(e);
            match w {
                "<" => {
                    angle += 1;
                    continue;
                }
                ">" => {
                    angle = angle.saturating_sub(1);
                    continue;
                }
                _ if angle > 0 => continue,
                "." => {
                    dot = true;
                    continue;
                }
                "extends" | "implements" | "permits" | "," => {
                    flush(clause, &mut cur, &mut extends, &mut implements);
                    match w {
                        "extends" => clause = Clause::Extends,
                        "implements" => clause = Clause::Implements,
                        "permits" => clause = Clause::Permits,
                        _ => {}
                    }
                }
                _ if self.ident(e) => {
                    if dot && !cur.is_empty() {
                        cur.push('.');
                    } else {
                        flush(clause, &mut cur, &mut extends, &mut implements);
                    }
                    cur.push_str(w);
                }
                _ => {}
            }
            dot = false;
        }
        flush(clause, &mut cur, &mut extends, &mut implements);
        Some(Head {
            kind,
            name: name.to_string(),
            annotations,
            extends,
            implements,
            line_start,
        })
    }

    /// A method or constructor header `… name ( … ) [[]…] [throws A, B]`
    /// ending the segment: `(index of name, index of the parameter group)`.
    /// Looks back at most [`MAX_HEADER_LOOKBACK`] entries for the group.
    fn method_head(&self, lv: &[Ent]) -> Option<(usize, usize)> {
        let n = lv.len();
        let lo = n.saturating_sub(MAX_HEADER_LOOKBACK);
        let mut g = n;
        loop {
            if g <= lo {
                return None;
            }
            g -= 1;
            if self.group(lv.get(g), "(") {
                break;
            }
        }
        let mut j = g + 1;
        while self.group(lv.get(j), "[") {
            j += 1;
        }
        if j < n && (!self.is(lv.get(j), "throws") || j + 1 >= n) {
            return None;
        }
        let name_k = g.checked_sub(1)?;
        if !self.ident(lv.get(name_k)) || RESERVED.contains(&self.word(lv.get(name_k))) {
            return None;
        }
        // `@A(…) {` is an annotation, `new X() {` an anonymous class.
        if let Some(p) = name_k.checked_sub(1)
            && matches!(self.word(lv.get(p)), "@" | "." | "new")
        {
            return None;
        }
        Some((name_k, g))
    }

    /// A record compact constructor header: `(annotations | modifiers)* Name`.
    fn compact_ctor(&self, lv: &[Ent], type_name: &str) -> bool {
        let k = self.skip_mods(lv, 0);
        lv.len() == k + 1 && self.ident(lv.get(k)) && self.word(lv.get(k)) == type_name
    }

    /// `[annotations] [open] module a.b` (module-info.java).
    fn module_head(&self, lv: &[Ent]) -> bool {
        let mut k = self.skip_mods(lv, 0);
        if self.is(lv.get(k), "open") {
            k += 1;
        }
        self.is(lv.get(k), "module")
    }

    /// The launcher would start the method named at `lv[name_k]` with
    /// parameter group `lv[g]`: named `main`, returns `void`, not `private`,
    /// and takes nothing or one `String[]` / `String...` / `String a[]`.
    fn is_main(&self, lv: &[Ent], name_k: usize, g: usize) -> bool {
        if self.word(lv.get(name_k)) != "main"
            || !name_k
                .checked_sub(1)
                .is_some_and(|p| self.is(lv.get(p), "void"))
            || lv[..name_k.min(lv.len())]
                .iter()
                .any(|e| self.is(Some(e), "private"))
        {
            return false;
        }
        let Some(&(open, close)) = lv.get(g) else {
            return false;
        };
        let mut ps: Vec<&str> = Vec::new();
        let mut j = open + 1;
        while j < close {
            let t = self.text(j);
            if t == "@" && self.is_ident(j + 1) {
                j += 2;
                while j + 1 < close && self.text(j) == "." && self.is_ident(j + 1) {
                    j += 2;
                }
                if j < close && self.text(j) == "(" {
                    let mut depth = 0usize;
                    while j < close {
                        let x = self.text(j);
                        j += 1;
                        if x == "(" {
                            depth += 1;
                        } else if x == ")" {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                break;
                            }
                        }
                    }
                }
                continue;
            }
            j += 1;
            if t == "final" {
                continue;
            }
            ps.push(t);
            if ps.len() > 8 {
                return false;
            }
        }
        let ps: &[&str] = ps
            .strip_prefix(&["java", ".", "lang", "."][..])
            .unwrap_or(&ps[..]);
        let is_name = |s: &str| s.bytes().next().is_some_and(is_ident_start);
        match ps {
            [] => true,
            ["String", "[", "]", n] | ["String", ".", ".", ".", n] | ["String", n, "[", "]"] => {
                is_name(n)
            }
            _ => false,
        }
    }
}

// ---- frames ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    /// File level (always at the bottom of the stack).
    Root,
    /// `(` or `[`; holds the expected closer.
    Group(u8),
    /// A type body; index into `types`.
    Type(usize),
    /// A member body; index into `members`.
    Member(usize),
    /// Any other brace: a statement block, lambda, anonymous class, array
    /// initializer, enum constant body, module body.
    Block,
}

struct Frame {
    kind: FrameKind,
    /// The type whose code this frame is in (for local classes).
    owner: Option<usize>,
    /// The current segment (unused in groups).
    level: Vec<Ent>,
    /// Type body: a field initializer (or annotation default) is open; its
    /// segment runs on to the next `;`.
    cont: bool,
    /// Enum body: the constant list (up to the first `;`) is open.
    enum_pending: bool,
    /// The body of a module declaration (a [`FrameKind::Block`]).
    module: bool,
}

impl Frame {
    fn new(kind: FrameKind, owner: Option<usize>) -> Self {
        Frame {
            kind,
            owner,
            level: Vec::new(),
            cont: false,
            enum_pending: false,
            module: false,
        }
    }
}

/// What a `{` in a type body opens.
enum BodyBrace {
    /// A brace inside an open field initializer or enum constant list.
    Block,
    /// The first brace of a field initializer / annotation default.
    Expr,
    Nested(Head),
    Member(Member),
}

struct Parser<'a> {
    src: Src<'a>,
    stack: Vec<Frame>,
    package: Option<String>,
    imports: Vec<String>,
    types: Vec<TypeDecl>,
    members: Vec<Member>,
    module_names: Vec<String>,
    /// Sum of the lengths of every `types[..].qualified`.
    qualified_bytes: usize,
}

type Step = Result<(), &'static str>;

impl Parser<'_> {
    fn run(&mut self) -> Step {
        for i in 0..self.src.toks.len() {
            if self.src.toks[i].kind != TokKind::Punct {
                self.push_level(i);
                continue;
            }
            match self.src.text(i).as_bytes().first().copied().unwrap_or(0) {
                b'(' => self.open_group(i, b')')?,
                b'[' => self.open_group(i, b']')?,
                c @ (b')' | b']') => self.close_group(i, c)?,
                b'{' => self.open_brace(i)?,
                b'}' => self.close_brace(i)?,
                b';' => self.semicolon(i)?,
                _ => self.push_level(i),
            }
        }
        if self.stack.len() != 1 {
            return Err(UNBALANCED);
        }
        Ok(())
    }

    fn top(&self) -> usize {
        self.stack.len().saturating_sub(1)
    }

    /// Add token `i` to the current segment (groups keep none).
    fn push_level(&mut self, i: usize) {
        if let Some(f) = self.stack.last_mut()
            && !matches!(f.kind, FrameKind::Group(_))
        {
            f.level.push((i, i));
        }
    }

    /// A group or brace that the current frame opened closes at `i`.
    fn close_level(&mut self, i: usize) {
        if let Some(f) = self.stack.last_mut()
            && !matches!(f.kind, FrameKind::Group(_))
            && let Some(e) = f.level.last_mut()
        {
            e.1 = i;
        }
    }

    /// Record a member; more than [`MAX_MEMBERS`] is ambiguous.
    fn push_member(&mut self, m: Member) -> Result<usize, &'static str> {
        if self.members.len() >= MAX_MEMBERS {
            return Err(TOO_MANY_MEMBERS);
        }
        self.members.push(m);
        Ok(self.members.len() - 1)
    }

    fn check_depth(&self) -> Step {
        // The root frame does not count.
        if self.stack.len() > MAX_DEPTH {
            return Err(TOO_DEEP);
        }
        Ok(())
    }

    fn open_group(&mut self, i: usize, closer: u8) -> Step {
        self.check_depth()?;
        self.push_level(i);
        let owner = self.stack.last().and_then(|f| f.owner);
        self.stack.push(Frame::new(FrameKind::Group(closer), owner));
        Ok(())
    }

    fn close_group(&mut self, i: usize, closer: u8) -> Step {
        if self.stack.last().map(|f| f.kind) != Some(FrameKind::Group(closer)) {
            return Err(UNBALANCED);
        }
        self.stack.pop();
        self.close_level(i);
        Ok(())
    }

    fn open_brace(&mut self, i: usize) -> Step {
        self.check_depth()?;
        let top = self.top();
        let Some(fr) = self.stack.get(top) else {
            return Err(UNBALANCED);
        };
        let (kind, owner) = (fr.kind, fr.owner);
        let frame = match kind {
            FrameKind::Group(_) => Frame::new(FrameKind::Block, owner),
            FrameKind::Root => {
                if let Some(h) = self.src.type_head(&fr.level) {
                    self.new_type(h, None, false)?
                } else if self.src.module_head(&fr.level) {
                    let mut f = Frame::new(FrameKind::Block, None);
                    f.module = true;
                    f
                } else {
                    return Err(UNPARSED);
                }
            }
            FrameKind::Member(_) | FrameKind::Block => match self.src.type_head(&fr.level) {
                Some(h) => self.new_type(h, owner, true)?,
                None => Frame::new(FrameKind::Block, owner),
            },
            FrameKind::Type(t) => self.type_body_brace(i, top, t)?,
        };
        self.push_level(i);
        self.stack.push(frame);
        Ok(())
    }

    fn new_type(
        &mut self,
        h: Head,
        parent: Option<usize>,
        local: bool,
    ) -> Result<Frame, &'static str> {
        let qualified = match parent.and_then(|p| self.types.get(p)) {
            Some(p) => {
                if p.qualified.len() + 1 + h.name.len() > MAX_QUALIFIED_BYTES {
                    return Err(NAME_TOO_LONG);
                }
                format!("{}.{}", p.qualified, h.name)
            }
            None => h.name.clone(),
        };
        if qualified.len() > MAX_QUALIFIED_BYTES {
            return Err(NAME_TOO_LONG);
        }
        self.qualified_bytes = self.qualified_bytes.saturating_add(qualified.len());
        if self.qualified_bytes > MAX_QUALIFIED_TOTAL_BYTES {
            return Err(NAME_BUDGET);
        }
        let idx = self.types.len();
        let mut frame = Frame::new(FrameKind::Type(idx), Some(idx));
        frame.enum_pending = h.kind == TypeKind::Enum;
        self.types.push(TypeDecl {
            name: h.name,
            qualified,
            kind: h.kind,
            extends: h.extends,
            implements: h.implements,
            annotations: h.annotations,
            line_start: h.line_start,
            line_end: h.line_start,
            parent,
            local,
        });
        Ok(frame)
    }

    /// Classify a `{` whose enclosing frame is the body of type `t`.
    fn type_body_brace(&mut self, i: usize, top: usize, t: usize) -> Result<Frame, &'static str> {
        let (Some(fr), Some(ty)) = (self.stack.get(top), self.types.get(t)) else {
            return Err(UNPARSED);
        };
        let src = &self.src;
        let lv = fr.level.as_slice();
        let line_start = lv.first().map_or(src.line(i), |e| src.line(e.0));
        let start_byte = lv.first().map_or(src.start(i), |e| src.start(e.0));
        let member =
            |kind, name: String, annotations, header_line, name_byte, is_static, main| Member {
                type_idx: t,
                kind,
                name,
                annotations,
                line_start,
                line_end: line_start,
                header_line,
                start_byte,
                end_byte: start_byte,
                name_byte,
                is_static,
                is_main_entry: main,
            };
        let decision = if fr.enum_pending || fr.cont {
            BodyBrace::Block
        } else if lv.iter().any(|e| src.is(Some(e), "=")) {
            BodyBrace::Expr
        } else if let Some(h) = src.type_head(lv) {
            BodyBrace::Nested(h)
        } else if lv.is_empty() {
            BodyBrace::Member(member(
                MemberKind::InstanceInit,
                "<init-block>".into(),
                Vec::new(),
                src.line(i),
                None,
                false,
                false,
            ))
        } else if lv.len() == 1 && src.is(lv.first(), "static") {
            BodyBrace::Member(member(
                MemberKind::StaticInit,
                "<clinit>".into(),
                Vec::new(),
                line_start,
                None,
                true,
                false,
            ))
        } else if src.is(lv.last(), "default") {
            BodyBrace::Expr
        } else if let Some((name_k, g)) = src.method_head(lv) {
            let name = src.word(lv.get(name_k));
            let before = &lv[..name_k.min(lv.len())];
            let ctor = name == ty.name;
            let kind = if ctor {
                MemberKind::Constructor
            } else {
                MemberKind::Method
            };
            let mut annotations = src.annotations(before);
            annotations.extend(src.group_annotations(lv.get(g)));
            BodyBrace::Member(member(
                kind,
                name.to_string(),
                annotations,
                lv.get(name_k).map_or(line_start, |e| src.line(e.0)),
                lv.get(name_k).map(|e| src.start(e.0)),
                !ctor && before.iter().any(|e| src.is(Some(e), "static")),
                !ctor && src.is_main(lv, name_k, g),
            ))
        } else if ty.kind == TypeKind::Record && src.compact_ctor(lv, &ty.name) {
            let k = src.skip_mods(lv, 0);
            BodyBrace::Member(member(
                MemberKind::Constructor,
                ty.name.clone(),
                src.annotations(&lv[..k.min(lv.len())]),
                lv.get(k).map_or(line_start, |e| src.line(e.0)),
                lv.get(k).map(|e| src.start(e.0)),
                false,
                false,
            ))
        } else {
            return Err(UNPARSED);
        };
        match decision {
            BodyBrace::Block => Ok(Frame::new(FrameKind::Block, Some(t))),
            BodyBrace::Expr => {
                if let Some(f) = self.stack.get_mut(top) {
                    f.cont = true;
                }
                Ok(Frame::new(FrameKind::Block, Some(t)))
            }
            BodyBrace::Nested(h) => self.new_type(h, Some(t), false),
            BodyBrace::Member(m) => {
                let idx = self.push_member(m)?;
                Ok(Frame::new(FrameKind::Member(idx), Some(t)))
            }
        }
    }

    /// The enum constant list of type `t`, ending with token `end`, as one
    /// static field initializer.
    fn enum_constants(&self, t: usize, lv: &[Ent], end: usize) -> Option<Member> {
        let first_tok = lv.first()?.0;
        let first = self.src.line(first_tok);
        Some(Member {
            type_idx: t,
            kind: MemberKind::FieldInit,
            name: "<field-init>".into(),
            annotations: self.src.annotations(lv),
            line_start: first,
            line_end: self.src.line(end),
            header_line: first,
            start_byte: self.src.start(first_tok),
            end_byte: self.src.end(end),
            name_byte: None,
            is_static: true,
            is_main_entry: false,
        })
    }

    /// A field declaration `… name = …` of type `t` ending at `;` token `i`.
    fn field_init(&self, t: usize, lv: &[Ent], i: usize) -> Option<Member> {
        let src = &self.src;
        let eq = lv.iter().position(|e| src.is(Some(e), "="))?;
        let before = &lv[..eq];
        let first_tok = lv.first()?.0;
        let line_start = src.line(first_tok);
        let implicit_static = self.types.get(t).is_some_and(|ty| {
            matches!(
                ty.kind,
                TypeKind::Interface | TypeKind::Annotation | TypeKind::Record
            )
        });
        Some(Member {
            type_idx: t,
            kind: MemberKind::FieldInit,
            name: "<field-init>".into(),
            annotations: src.annotations(before),
            line_start,
            line_end: src.line(i),
            header_line: eq
                .checked_sub(1)
                .and_then(|p| lv.get(p))
                .map_or(line_start, |e| src.line(e.0)),
            start_byte: src.start(first_tok),
            end_byte: src.end(i),
            name_byte: None,
            is_static: implicit_static || before.iter().any(|e| src.is(Some(e), "static")),
            is_main_entry: false,
        })
    }

    fn semicolon(&mut self, i: usize) -> Step {
        let top = self.top();
        let Some(kind) = self.stack.get(top).map(|f| f.kind) else {
            return Ok(());
        };
        match kind {
            FrameKind::Group(_) => return Ok(()),
            FrameKind::Root => self.package_or_import(top)?,
            FrameKind::Type(t) => {
                let Some(fr) = self.stack.get(top) else {
                    return Ok(());
                };
                let m = if fr.enum_pending {
                    self.enum_constants(t, &fr.level, i)
                } else {
                    self.field_init(t, &fr.level, i)
                };
                if let Some(m) = m {
                    self.push_member(m)?;
                }
            }
            FrameKind::Member(_) | FrameKind::Block => self.module_directive(top),
        }
        if let Some(f) = self.stack.get_mut(top) {
            f.level.clear();
            f.cont = false;
            f.enum_pending = false;
        }
        Ok(())
    }

    /// In a module body, `provides a.S with b.I, c.J;` or `uses a.S;`: push
    /// every identifier but the directive keywords to `module_names`.
    fn module_directive(&mut self, top: usize) {
        let Some(fr) = self.stack.get(top) else {
            return;
        };
        if !fr.module {
            return;
        }
        let (src, lv) = (&self.src, fr.level.as_slice());
        if !matches!(src.word(lv.first()), "provides" | "uses") {
            return;
        }
        for e in lv.get(1..).unwrap_or(&[]) {
            let w = src.word(Some(e));
            if src.ident(Some(e)) && w != "with" {
                self.module_names.push(w.to_string());
            }
        }
    }

    /// `[annotations] package a.b;` or `import [static] a.b.C[.*];`. A name
    /// over [`MAX_PACKAGE_IMPORT_BYTES`] is `name_too_long`.
    fn package_or_import(&mut self, top: usize) -> Step {
        let Some(fr) = self.stack.get(top) else {
            return Ok(());
        };
        let (src, lv) = (&self.src, fr.level.as_slice());
        let mut k = src.skip_mods(lv, 0);
        let kw = src.word(lv.get(k));
        if kw != "package" && kw != "import" {
            return Ok(());
        }
        k += 1;
        if kw == "import" && src.is(lv.get(k), "static") {
            k += 1;
        }
        let mut name = String::new();
        for e in lv.get(k..).unwrap_or(&[]) {
            let w = src.word(Some(e));
            if !(src.ident(Some(e)) || w == "." || w == "*") {
                return Ok(());
            }
            if name.len().saturating_add(w.len()) > MAX_PACKAGE_IMPORT_BYTES {
                return Err(NAME_TOO_LONG);
            }
            name.push_str(w);
        }
        if name.is_empty() {
            return Ok(());
        }
        if kw == "import" {
            self.imports.push(name);
        } else if self.package.is_none() {
            self.package = Some(name);
        }
        Ok(())
    }

    fn close_brace(&mut self, i: usize) -> Step {
        let top = self.top();
        let Some(fr) = self.stack.get(top) else {
            return Err(UNBALANCED);
        };
        let is_brace = matches!(
            fr.kind,
            FrameKind::Type(_) | FrameKind::Member(_) | FrameKind::Block
        );
        if top == 0 || !is_brace {
            return Err(UNBALANCED);
        }
        // An enum constant list not ended by `;` ends with the enum body.
        if let FrameKind::Type(t) = fr.kind
            && fr.enum_pending
        {
            let end = fr.level.last().map_or(0, |e| e.1);
            if let Some(m) = self.enum_constants(t, &fr.level, end) {
                self.push_member(m)?;
            }
        }
        let line = self.src.line(i);
        let end_byte = self.src.end(i);
        match self.stack.pop().map(|f| f.kind) {
            Some(FrameKind::Type(t)) => {
                if let Some(ty) = self.types.get_mut(t) {
                    ty.line_end = line;
                }
            }
            Some(FrameKind::Member(m)) => {
                if let Some(mb) = self.members.get_mut(m) {
                    mb.line_end = line;
                    mb.end_byte = end_byte;
                }
            }
            _ => {}
        }
        self.close_level(i);
        if let Some(p) = self.stack.last_mut()
            && !matches!(p.kind, FrameKind::Group(_))
            && !p.cont
            && !p.enum_pending
        {
            p.level.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "java_parse_tests.rs"]
mod tests;
