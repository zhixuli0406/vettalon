use super::super::java_lex::{JavaLexed, lex};
use super::*;

fn src(lines: &[&str]) -> String {
    lines.join("\n")
}

fn ok(src: &str) -> JavaFile {
    let l = lex(src);
    assert_eq!(l.ambiguity, None, "lexer rejected {src:?}");
    let f = parse(&l);
    assert_eq!(f.ambiguity, None, "parser rejected {src:?}");
    f
}

fn ambiguity(src: &str) -> Option<&'static str> {
    let f = parse(&lex(src));
    if f.ambiguity.is_some() {
        assert!(f.types.is_empty() && f.members.is_empty() && f.imports.is_empty());
        assert!(f.package.is_none());
    }
    f.ambiguity
}

fn member<'a>(f: &'a JavaFile, name: &str) -> &'a Member {
    let found: Vec<&Member> = f.members.iter().filter(|m| m.name == name).collect();
    assert_eq!(
        found.len(),
        1,
        "expected one member {name}: {:#?}",
        f.members
    );
    found[0]
}

fn names(f: &JavaFile) -> Vec<(MemberKind, &str)> {
    f.members
        .iter()
        .map(|m| (m.kind, m.name.as_str()))
        .collect()
}

fn lines(m: &Member) -> (u32, u32, u32) {
    (m.line_start, m.header_line, m.line_end)
}

#[test]
fn class_with_main_package_and_imports() {
    let f = ok(&src(&[
        "package com.ex;",
        "",
        "import java.util.List;",
        "import static java.lang.Math.max;",
        "import java.util.*;",
        "",
        "public class App {",
        "    public static void main(String[] args) {",
        "        run();",
        "    }",
        "    static void run() {}",
        "}",
    ]));
    assert_eq!(f.package.as_deref(), Some("com.ex"));
    assert_eq!(
        f.imports,
        ["java.util.List", "java.lang.Math.max", "java.util.*"]
    );
    assert_eq!(f.types.len(), 1);
    let t = &f.types[0];
    assert_eq!((t.name.as_str(), t.qualified.as_str()), ("App", "App"));
    assert_eq!(t.kind, TypeKind::Class);
    assert_eq!((t.line_start, t.line_end, t.parent), (7, 12, None));
    let main = member(&f, "main");
    assert_eq!(main.kind, MemberKind::Method);
    assert!(main.is_main_entry && main.is_static);
    assert_eq!(lines(main), (8, 8, 10));
    let run = member(&f, "run");
    assert!(!run.is_main_entry && run.is_static);
    assert_eq!(lines(run), (11, 11, 11));
}

fn main_entry(header: &str) -> bool {
    let f = ok(&format!("class A {{\n    {header} {{ }}\n}}\n"));
    member(&f, "main").is_main_entry
}

#[test]
fn main_entry_shapes() {
    for yes in [
        "public static void main(String[] args)",
        "public static void main(final String... args)",
        "public static void main(java.lang.String args[])",
        "public static void main(@NotNull String[] a)",
        "static void main(String[] a)",
        "void main()",
        "static void main()",
    ] {
        assert!(main_entry(yes), "{yes}");
    }
    for no in [
        "private static void main(String[] a)",
        "public static int main(String[] a)",
        "public static void main(String a)",
        "public static void main(String[] a, int b)",
        "public static void main(int[] a)",
    ] {
        assert!(!main_entry(no), "{no}");
    }
}

#[test]
fn methods_constructors_initializers_and_fields() {
    let f = ok(&src(&[
        "class A {",
        "    static int S = init();",
        "    int i = 1,",
        "        j = 2;",
        "    int k;",
        "    static { s(); }",
        "    {",
        "        inst();",
        "    }",
        "    A() { }",
        "    A(int x) throws E, F { this(); }",
        "    void m() { }",
        "    abstract void n();",
        "}",
    ]));
    assert_eq!(
        names(&f),
        [
            (MemberKind::FieldInit, "<field-init>"),
            (MemberKind::FieldInit, "<field-init>"),
            (MemberKind::StaticInit, "<clinit>"),
            (MemberKind::InstanceInit, "<init-block>"),
            (MemberKind::Constructor, "A"),
            (MemberKind::Constructor, "A"),
            (MemberKind::Method, "m"),
        ]
    );
    let m = &f.members;
    assert!(m[0].is_static && !m[1].is_static && m[2].is_static && !m[3].is_static);
    assert!(!m[4].is_static && !m[6].is_static);
    assert_eq!(lines(&m[0]), (2, 2, 2));
    assert_eq!(lines(&m[1]), (3, 3, 4));
    assert_eq!(lines(&m[2]), (6, 6, 6));
    assert_eq!(lines(&m[3]), (7, 7, 9));
    assert_eq!(lines(&m[4]), (10, 10, 10));
    assert_eq!(lines(&m[5]), (11, 11, 11));
    assert_eq!(lines(&m[6]), (12, 12, 12));
    assert!(m.iter().all(|x| x.type_idx == 0 && !x.is_main_entry));
    assert_eq!((f.types[0].line_start, f.types[0].line_end), (1, 14));
}

#[test]
fn nested_inner_and_local_types() {
    let f = ok(&src(&[
        "class Outer {",
        "    static class Nested { void a() {} }",
        "    class Inner {",
        "        class Deep { void b() {} }",
        "    }",
        "    void m() {",
        "        class Local { void c() {} }",
        "        Runnable r = new Runnable() { public void run() { } };",
        "        record P(int v) { P { } }",
        "    }",
        "}",
    ]));
    let types: Vec<(&str, Option<usize>)> = f
        .types
        .iter()
        .map(|t| (t.qualified.as_str(), t.parent))
        .collect();
    assert_eq!(
        types,
        [
            ("Outer", None),
            ("Outer.Nested", Some(0)),
            ("Outer.Inner", Some(0)),
            ("Outer.Inner.Deep", Some(2)),
            ("Outer.Local", Some(0)),
            ("Outer.P", Some(0)),
        ]
    );
    assert_eq!(f.types[5].kind, TypeKind::Record);
    assert_eq!((f.types[2].line_start, f.types[2].line_end), (3, 5));
    let owners: Vec<(&str, usize)> = f
        .members
        .iter()
        .map(|m| (m.name.as_str(), m.type_idx))
        .collect();
    assert_eq!(owners, [("a", 1), ("b", 3), ("m", 0), ("c", 4), ("P", 5)]);
    assert_eq!(member(&f, "P").kind, MemberKind::Constructor);
    assert_eq!(lines(member(&f, "m")), (6, 6, 10));
}

#[test]
fn interface_default_and_static_methods() {
    let f = ok(&src(&[
        "public interface Shape extends Comparable<Shape>, java.io.Serializable {",
        "    int SIDES = 4;",
        "    double area();",
        "    default String name() { return \"s\"; }",
        "    static Shape unit() { return null; }",
        "}",
    ]));
    let t = &f.types[0];
    assert_eq!(t.kind, TypeKind::Interface);
    assert_eq!(t.extends, ["Comparable", "java.io.Serializable"]);
    assert!(t.implements.is_empty());
    assert_eq!(
        names(&f),
        [
            (MemberKind::FieldInit, "<field-init>"),
            (MemberKind::Method, "name"),
            (MemberKind::Method, "unit"),
        ]
    );
    assert!(f.members[0].is_static, "interface fields are static");
    assert!(!member(&f, "name").is_static);
    assert!(member(&f, "unit").is_static);
}

#[test]
fn enum_constant_bodies_and_methods() {
    let f = ok(&src(&[
        "enum Op {",
        "    PLUS(\"+\") {",
        "        int apply(int a, int b) { return a + b; }",
        "    },",
        "    MINUS(\"-\");",
        "    private final String sym;",
        "    Op(String s) { sym = s; }",
        "    int apply(int a, int b) { return 0; }",
        "}",
    ]));
    assert_eq!(f.types[0].kind, TypeKind::Enum);
    assert_eq!(
        names(&f),
        [
            (MemberKind::FieldInit, "<field-init>"),
            (MemberKind::Constructor, "Op"),
            (MemberKind::Method, "apply"),
        ]
    );
    let consts = &f.members[0];
    assert!(consts.is_static);
    assert_eq!(lines(consts), (2, 2, 5));
    assert_eq!(lines(member(&f, "apply")), (8, 8, 8));

    // Without `;` the constant list ends with the body.
    let f = ok("enum E {\n  A { void f() {} },\n  B\n}\n");
    assert_eq!(names(&f), [(MemberKind::FieldInit, "<field-init>")]);
    assert_eq!(lines(&f.members[0]), (2, 2, 3));
    // An empty constant list makes no member.
    let f = ok("enum E { ; void f() {} }");
    assert_eq!(names(&f), [(MemberKind::Method, "f")]);
}

#[test]
fn record_with_compact_constructor() {
    let f = ok(&src(&[
        "record Point(int x, int y) implements Comparable<Point> {",
        "    public Point {",
        "        if (x < 0) throw new IllegalArgumentException();",
        "    }",
        "    Point(int x) { this(x, 0); }",
        "    static Point origin() { return new Point(0, 0); }",
        "    public int compareTo(Point o) { return 0; }",
        "}",
    ]));
    let t = &f.types[0];
    assert_eq!(t.kind, TypeKind::Record);
    assert_eq!(t.implements, ["Comparable"]);
    assert_eq!(
        names(&f),
        [
            (MemberKind::Constructor, "Point"),
            (MemberKind::Constructor, "Point"),
            (MemberKind::Method, "origin"),
            (MemberKind::Method, "compareTo"),
        ]
    );
    assert_eq!(lines(&f.members[0]), (2, 2, 4));
    assert!(f.members[2].is_static);
}

#[test]
fn annotations_on_types_methods_and_fields() {
    let f = ok(&src(&[
        "@Configuration",
        "@org.x.Y(a = \"b\")",
        "public class Cfg {",
        "    @Bean",
        "    @org.x.Y(a = \"b\", c = {1, 2})",
        "    public Foo foo(@Qualifier(\"q\") Bar bar) { return null; }",
        "    @Override public String toString() { return \"\"; }",
        "    @Inject Foo f = null;",
        "}",
    ]));
    let t = &f.types[0];
    assert_eq!(t.annotations, ["Configuration", "Y"]);
    assert_eq!((t.line_start, t.line_end), (1, 9));
    let foo = member(&f, "foo");
    assert_eq!(foo.annotations, ["Bean", "Y", "Qualifier"]);
    assert_eq!(lines(foo), (4, 6, 6));
    assert_eq!(member(&f, "toString").annotations, ["Override"]);
    let field = member(&f, "<field-init>");
    assert_eq!(field.annotations, ["Inject"]);
    assert_eq!(lines(field), (8, 8, 8));
}

#[test]
fn parameter_annotations_are_member_annotations() {
    let f = ok(&src(&[
        "class Boot {",
        "    void boot(@Observes @Initialized(ApplicationScoped.class) Object e) { }",
        "    Boot(final @javax.inject.Named(\"n\") String s, int[] a) { }",
        "    void plain(Object e) { }",
        "}",
    ]));
    assert_eq!(member(&f, "boot").annotations, ["Observes", "Initialized"]);
    assert_eq!(member(&f, "Boot").annotations, ["Named"]);
    assert!(member(&f, "plain").annotations.is_empty());
}

#[test]
fn annotation_type_declaration() {
    let f = ok(&src(&[
        "public @interface Marker {",
        "    String value() default \"\";",
        "    String[] tags() default {};",
        "    int MAX = 3;",
        "}",
    ]));
    assert_eq!(f.types[0].kind, TypeKind::Annotation);
    assert_eq!(f.types[0].name, "Marker");
    assert_eq!(names(&f), [(MemberKind::FieldInit, "<field-init>")]);
    assert!(f.members[0].is_static);
    assert_eq!(lines(&f.members[0]), (4, 4, 4));
}

#[test]
fn extends_and_implements_lists() {
    let f = ok(&src(&[
        "public final class Foo<T extends Comparable<T>> extends Base<T> implements Comparable<Foo>, Runnable {",
        "    public void run() {}",
        "}",
        "sealed interface S permits A, B {}",
        "non-sealed class A extends java.util.AbstractList<String> implements S {}",
        "class B extends Outer<String>.Inner implements @Ann S {}",
    ]));
    let t = &f.types[0];
    assert_eq!(t.extends, ["Base"]);
    assert_eq!(t.implements, ["Comparable", "Runnable"]);
    assert!(f.types[1].extends.is_empty() && f.types[1].implements.is_empty());
    assert_eq!(f.types[2].extends, ["java.util.AbstractList"]);
    assert_eq!(f.types[2].implements, ["S"]);
    assert_eq!(f.types[3].extends, ["Outer.Inner"]);
    assert_eq!(f.types[3].implements, ["S"]);
}

#[test]
fn lambdas_and_anonymous_classes_stay_in_their_member() {
    let f = ok(&src(&[
        "class L {",
        "    void m() {",
        "        Runnable r = () -> {",
        "            System.out.println(\"x\");",
        "        };",
        "        Object o = new Object() {",
        "            @Override public String toString() { return \"{\"; }",
        "        };",
        "        list.forEach(x -> { use(x); });",
        "    }",
        "    void after() {}",
        "}",
    ]));
    assert_eq!(
        names(&f),
        [(MemberKind::Method, "m"), (MemberKind::Method, "after")]
    );
    assert_eq!(lines(&f.members[0]), (2, 2, 10));
    assert_eq!(lines(&f.members[1]), (11, 11, 11));
    assert_eq!(f.types.len(), 1);
}

#[test]
fn field_initializers_with_lambda_and_anonymous_class() {
    let f = ok(&src(&[
        "class F {",
        "    Runnable r = () -> {",
        "        go();",
        "    };",
        "    Comparator<String> c = new Comparator<String>() {",
        "        public int compare(String a, String b) { return 0; }",
        "    };",
        "    void after() {}",
        "}",
    ]));
    assert_eq!(
        names(&f),
        [
            (MemberKind::FieldInit, "<field-init>"),
            (MemberKind::FieldInit, "<field-init>"),
            (MemberKind::Method, "after"),
        ]
    );
    assert_eq!(lines(&f.members[0]), (2, 2, 4));
    assert_eq!(lines(&f.members[1]), (5, 5, 7));
}

#[test]
fn generic_method_header() {
    let f = ok(&src(&[
        "class G {",
        "    public <T> List<T> f(Map<String, T> m) throws IOException, java.sql.SQLException {",
        "        return null;",
        "    }",
        "    int[] h()[] { return null; }",
        "}",
    ]));
    assert_eq!(
        names(&f),
        [(MemberKind::Method, "f"), (MemberKind::Method, "h")]
    );
    assert_eq!(lines(member(&f, "f")), (2, 2, 4));
    assert!(!member(&f, "f").is_static);
}

#[test]
fn control_flow_blocks_are_not_members() {
    let f = ok(&src(&[
        "class C {",
        "    void m(boolean x) {",
        "        if (x) {",
        "            for (int i = 0; i < 3; i++) { }",
        "        } else { while (x) { } }",
        "        synchronized (this) { }",
        "        try { } catch (Exception e) { } finally { }",
        "        switch (1) { case 1 -> { } default -> { } }",
        "    }",
        "}",
    ]));
    assert_eq!(names(&f), [(MemberKind::Method, "m")]);
    assert_eq!(lines(&f.members[0]), (2, 2, 9));
}

#[test]
fn long_parameter_list_is_one_lookback_entry() {
    let params: Vec<String> = (0..100).map(|n| format!("int a{n}")).collect();
    let f = ok(&format!(
        "class P {{ void f({}) {{ }} }}",
        params.join(", ")
    ));
    assert_eq!(names(&f), [(MemberKind::Method, "f")]);
}

#[test]
fn header_lookback_exceeded_is_ambiguous() {
    let throws: Vec<String> = (0..40).map(|n| format!("E{n}")).collect();
    let src = format!("class P {{ void f() throws {} {{ }} }}", throws.join(", "));
    assert_eq!(ambiguity(&src), Some("unparsed_member_header"));
}

#[test]
fn unclassifiable_headers_are_ambiguous() {
    assert_eq!(
        ambiguity("class A { foo bar { } }"),
        Some("unparsed_member_header")
    );
    assert_eq!(ambiguity("{ }"), Some("unparsed_member_header"));
    assert_eq!(
        ambiguity("class A { @Ann(x) { } }"),
        Some("unparsed_member_header")
    );
}

#[test]
fn unbalanced_braces_are_ambiguous() {
    for bad in [
        "class A { void f() { }",
        "class A { } }",
        "class A { void f( { } }",
        "class A { void f() ) }",
        "class A { int[] a = new int[3; }",
        "class A { void f() { g(); }",
        "}",
        ")",
        "(",
    ] {
        assert_eq!(ambiguity(bad), Some("unbalanced_braces"), "{bad}");
    }
}

fn deep(blocks: usize) -> String {
    format!(
        "class A {{ void f() {{ {}{} }} }}",
        "{".repeat(blocks),
        "}".repeat(blocks)
    )
}

#[test]
fn nesting_depth_cap() {
    // Type body + member body + 254 blocks = 256 frames: allowed.
    assert_eq!(ambiguity(&deep(254)), None);
    assert_eq!(ambiguity(&deep(255)), Some("nesting_too_deep"));
    assert_eq!(ambiguity(&deep(300)), Some("nesting_too_deep"));
    let parens = format!(
        "class A {{ int x = {}1{}; }}",
        "(".repeat(300),
        ")".repeat(300)
    );
    assert_eq!(ambiguity(&parens), Some("nesting_too_deep"));
}

#[test]
fn lexer_ambiguity_propagates() {
    assert_eq!(
        ambiguity("class A { String s = \"open; }"),
        Some("unterminated_string")
    );
    let lexed = JavaLexed {
        ambiguity: Some("unicode_escape_structural"),
        ..JavaLexed::default()
    };
    assert_eq!(parse(&lexed).ambiguity, Some("unicode_escape_structural"));
}

#[test]
fn line_numbers_with_cr_crlf_comments_and_text_blocks() {
    let f = ok(
        "/* a\n b */ class A {\r\n  void f() {\r\n  }\r  // x }\n  String t = \"\"\"\n    {\n    \"\"\";\n  void g() { }\n}\n",
    );
    assert_eq!((f.types[0].line_start, f.types[0].line_end), (2, 10));
    assert_eq!(lines(member(&f, "f")), (3, 3, 4));
    assert_eq!(lines(member(&f, "<field-init>")), (6, 6, 8));
    assert_eq!(lines(member(&f, "g")), (9, 9, 9));
}

#[test]
fn module_info_and_empty_files() {
    let f = ok("@Deprecated open module com.ex {\n  requires java.base;\n  exports com.ex;\n}\n");
    assert!(f.types.is_empty() && f.members.is_empty());
    assert!(f.module_names.is_empty());
    let f = ok(&src(&[
        "module m {",
        "  requires transitive a.b;",
        "  uses ext.Spi;",
        "  provides ext.Spi with com.ex.Impl, Other;",
        "  opens x.y to z;",
        "}",
    ]));
    assert_eq!(
        f.module_names,
        ["ext", "Spi", "ext", "Spi", "com", "ex", "Impl", "Other"]
    );
    // Not in a module body: no directive.
    let f = ok("class A { void f() { uses x; } }");
    assert!(f.module_names.is_empty());
    let f = ok("");
    assert_eq!(f, JavaFile::default());
    let f = ok("package a.b;\n;\n");
    assert_eq!(f.package.as_deref(), Some("a.b"));
}

#[test]
fn qualified_name_cap() {
    let long = "N".repeat(1500);
    let src = format!("class {long} {{ class {long}x {{ class {long}y {{ }} }} }}");
    assert_eq!(ambiguity(&src), Some("name_too_long"));
}

/// `package a.a.a…;` (or `import …;`) of `bytes` name bytes, then a class.
fn long_header_name(kw: &str, bytes: usize) -> String {
    let mut s = format!("{kw} a");
    while s.len() - kw.len() - 1 < bytes {
        s.push_str(".a");
    }
    s.push_str(";\nclass A { }\n");
    s
}

#[test]
fn package_and_import_name_cap() {
    // At the cap: accepted unchanged.
    let at_cap = MAX_PACKAGE_IMPORT_BYTES - 1;
    let f = ok(&long_header_name("package", at_cap));
    assert_eq!(f.package.as_ref().map(String::len), Some(at_cap));
    let f = ok(&long_header_name("import", at_cap));
    assert_eq!(f.imports.first().map(String::len), Some(at_cap));
    assert_eq!(
        ambiguity(&long_header_name("package", MAX_PACKAGE_IMPORT_BYTES + 1)),
        Some("name_too_long")
    );
    assert_eq!(
        ambiguity(&long_header_name(
            "import static",
            MAX_PACKAGE_IMPORT_BYTES + 1
        )),
        Some("name_too_long")
    );
    // A 2 MiB package line is rejected quickly.
    let t = std::time::Instant::now();
    assert_eq!(
        ambiguity(&long_header_name("package", 2 * 1024 * 1024)),
        Some("name_too_long")
    );
    assert!(
        t.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        t.elapsed()
    );
}

/// `depth` nested types with 121-byte names, `siblings` small types in the
/// innermost one: every sibling's qualified name is ~3.7 KB.
fn deep_qualified(depth: usize, siblings: usize) -> String {
    let mut s = String::new();
    for i in 0..depth {
        s.push_str(&format!("class N{i:02}{} {{ ", "x".repeat(118)));
    }
    for j in 0..siblings {
        s.push_str(&format!("class S{j} {{ }} "));
    }
    s.push_str(&"} ".repeat(depth));
    s
}

#[test]
fn qualified_name_total_budget() {
    // ~1.8 MB of qualified names: under the budget.
    let f = ok(&deep_qualified(30, 500));
    assert_eq!(f.types.len(), 530);
    assert!(f.types[529].qualified.len() <= MAX_QUALIFIED_BYTES);
    // ~5.5 MB from a ~25 KB file: over it.
    assert_eq!(
        ambiguity(&deep_qualified(30, 1500)),
        Some("name_budget_exceeded")
    );
}

fn one_line_methods(n: usize) -> String {
    let mut s = String::from("class A {");
    for i in 0..n {
        s.push_str(&format!("void a{i}(){{a{i}();}}"));
    }
    s.push('}');
    s
}

#[test]
fn member_count_cap() {
    let f = ok(&one_line_methods(MAX_MEMBERS));
    assert_eq!(f.members.len(), MAX_MEMBERS);
    assert_eq!(
        ambiguity(&one_line_methods(MAX_MEMBERS + 1)),
        Some("too_many_members")
    );
    // Field initializers and enum constant lists count too.
    let mut fields = String::from("class F {");
    for i in 0..=MAX_MEMBERS {
        fields.push_str(&format!("int f{i}=1;"));
    }
    fields.push('}');
    assert_eq!(ambiguity(&fields), Some("too_many_members"));
}

#[test]
fn member_byte_spans_and_name_offsets() {
    let code = "class A { @Ann int x = f(); void m(int a) { g(); } static { } { }\n  A() { }\n  enum E { P, Q }\n  record R(int v) { R { } }\n}\n";
    let f = ok(code);
    let span = |m: &Member| &code[m.start_byte..m.end_byte];
    let spans: Vec<&str> = f.members.iter().map(span).collect();
    assert_eq!(
        spans,
        [
            "@Ann int x = f();",
            "void m(int a) { g(); }",
            "static { }",
            "{ }",
            "A() { }",
            "P, Q",
            "R { }",
        ]
    );
    let names: Vec<Option<&str>> = f
        .members
        .iter()
        .map(|m| m.name_byte.map(|b| &code[b..b + m.name.len()]))
        .collect();
    assert_eq!(
        names,
        [None, Some("m"), None, None, Some("A"), None, Some("R")]
    );
    // Spans are nested or disjoint, also with local classes.
    let code = "class B { void m() { class L { void n() { } } } int y = new Object() { int z = 1; }.hashCode(); }";
    let f = ok(code);
    let spans: Vec<(usize, usize)> = f
        .members
        .iter()
        .map(|m| (m.start_byte, m.end_byte))
        .collect();
    for (i, a) in spans.iter().enumerate() {
        for b in &spans[i + 1..] {
            let disjoint = a.1 <= b.0 || b.1 <= a.0;
            let nested = (a.0 <= b.0 && b.1 <= a.1) || (b.0 <= a.0 && a.1 <= b.1);
            assert!(disjoint || nested, "{a:?} {b:?}");
        }
    }
    assert_eq!(
        &code[spans[0].0..spans[0].1],
        "void m() { class L { void n() { } } }"
    );
}

const SAMPLE: &str = "package p;\nimport a.b.C;\n@A(x = {1, 2})\npublic class S<T extends U<T>> extends B implements I, J {\n  static int X = 1;\n  static { init(); }\n  { go(); }\n  S() { super(); }\n  @Override public <R> R m(T t) throws E {\n    Runnable r = () -> { new Object() { void q() {} }; };\n    class Loc { void w() {} }\n    return null;\n  }\n  enum K { A(1) { void z() {} }, B; K(int i) {} }\n  record Rec(int a) { Rec { } }\n  interface In { default void d() {} }\n  @interface An { int[] v() default {}; }\n  public static void main(String... a) {}\n}\n";

#[test]
fn sample_parses() {
    let f = ok(SAMPLE);
    let types: Vec<&str> = f.types.iter().map(|t| t.qualified.as_str()).collect();
    assert_eq!(types, ["S", "S.Loc", "S.K", "S.Rec", "S.In", "S.An"]);
    assert_eq!(f.types[0].annotations, ["A"]);
    assert_eq!(f.types[0].extends, ["B"]);
    assert_eq!(f.types[0].implements, ["I", "J"]);
    assert!(member(&f, "main").is_main_entry);
    assert!(f.members.iter().all(|m| m.name != "q" && m.name != "z"));
    assert_eq!(member(&f, "w").type_idx, 1);
}

#[test]
fn no_panic_on_prefixes_and_garbage() {
    let mut cut = 0;
    while cut <= SAMPLE.len() {
        let _ = parse(&lex(&SAMPLE[..cut]));
        // Also with the tail only (unbalanced closers first).
        let _ = parse(&lex(&SAMPLE[cut..]));
        cut += 1;
    }
    for junk in [
        "@",
        "@interface",
        "class",
        "class {",
        "enum E {",
        "record R(",
        "record R(int a) {",
        "((((",
        "))))",
        "a<b>c{",
        "\u{0}é{}",
        "class é { void ü() {} }",
        "import ;",
        "package",
        "class A { void main( }",
        "class A { void main(@ }",
        "class A { void main(@x( }",
        "class A { non - }",
        "class A { static }",
        "class A { = { } }",
        "class A { default { } }",
        "class A extends implements , < > . { }",
        "0x1e+2 1.5e-3 ... :: -> {",
    ] {
        let _ = parse(&lex(junk));
    }
}
