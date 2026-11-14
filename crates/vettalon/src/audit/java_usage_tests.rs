use super::*;

const APP: &str = "src/main/java/com/ex/App.java";
const BOX: &str = "src/main/java/com/ex/Box.java";
const CRYPTO: &str = "        javax.crypto.Cipher.getInstance(\"AES\");";

fn src(lines: &[&str]) -> String {
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

fn project(srcs: &[(&str, &str)]) -> JavaProject {
    JavaProject::from_sources(
        srcs.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
    )
}

fn verdict(srcs: &[(&str, &str)], rel: &str, line: u32) -> Verdict {
    let p = project(srcs);
    let r = p.reach(&[]);
    p.classify(&r, rel, line)
}

fn reasons(v: &Verdict) -> Vec<&str> {
    v.reasons.iter().map(String::as_str).collect()
}

/// `com.ex.App` whose `main` runs `body` (line 4).
fn app(body: &str) -> String {
    src(&[
        "package com.ex;",
        "public class App {",
        "    public static void main(String[] args) {",
        body,
        "    }",
        "}",
    ])
}

/// `com.ex.Box` with an unreferenced static method; the crypto call is line 4.
fn unused_box() -> String {
    src(&[
        "package com.ex;",
        "class Box {",
        "    static void zzSealUnused() {",
        CRYPTO,
        "    }",
        "}",
    ])
}

fn not_observed_box(extra: &[(&str, &str)]) -> Verdict {
    let a = app("");
    let b = unused_box();
    let mut srcs = vec![(APP, a.as_str()), (BOX, b.as_str())];
    srcs.extend_from_slice(extra);
    verdict(&srcs, BOX, 4)
}

#[test]
fn main_helper_crypto_is_reachable_with_chain() {
    let a = src(&[
        "package com.ex;",
        "public class App {",
        "    public static void main(String[] args) {",
        "        helper();",
        "    }",
        "    static void helper() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let v = verdict(&[(APP, &a)], APP, 7);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(reasons(&v), ["name_based_chain_from_entry"]);
    assert_eq!(v.enclosing_function.as_deref(), Some("App.helper"));
    assert_eq!(
        v.chain,
        [format!("{APP}:App.main"), format!("{APP}:App.helper")]
    );
    let v = verdict(&[(APP, &a)], APP, 4);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.chain, [format!("{APP}:App.main")]);
}

#[test]
fn unused_unique_method_is_not_observed() {
    let v = not_observed_box(&[]);
    assert_eq!(v.label, Label::NotObserved);
    assert_eq!(reasons(&v), ["no_textual_reference"]);
    assert_eq!(v.enclosing_function.as_deref(), Some("Box.zzSealUnused"));
    assert!(v.chain.is_empty());
}

#[test]
fn receiver_call_constructor_and_instance_field_init_are_reachable() {
    let a = app("        Svc s = new Svc(); s.seal();");
    let svc = src(&[
        "package com.ex;",
        "class Svc {",
        "    private final Object key = makeKey();",
        "    Svc() {",
        "        warmUp();",
        "    }",
        "    void seal() {",
        CRYPTO,
        "    }",
        "    static Object makeKey() { return null; }",
        "    void warmUp() {}",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Svc.java";
    let srcs = [(APP, a.as_str()), (rel, svc.as_str())];
    let v = verdict(&srcs, rel, 8);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(
        v.chain,
        [format!("{APP}:App.main"), format!("{rel}:Svc.seal")]
    );
    let v = verdict(&srcs, rel, 5);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.enclosing_function.as_deref(), Some("Svc.<init>"));
    let v = verdict(&srcs, rel, 3);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(reasons(&v), ["constructor_reachable"]);
    assert_eq!(v.enclosing_function.as_deref(), Some("Svc.<field-init>"));
    // Called from the reachable field initializer.
    assert_eq!(verdict(&srcs, rel, 10).label, Label::Reachable);
}

#[test]
fn new_without_explicit_constructor_reaches_instance_field_init() {
    let holder = src(&[
        "package com.ex;",
        "class Holder {",
        "    final Object c = javax.crypto.Cipher.getInstance(\"AES\");",
        "    static void touch() {}",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Holder.java";
    let a = app("        new Holder();");
    let v = verdict(&[(APP, &a), (rel, &holder)], rel, 3);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(reasons(&v), ["constructor_reachable"]);
    // Only a static method reached: the instance initializer is not modelled.
    let a = app("        Holder.touch();");
    let v = verdict(&[(APP, &a), (rel, &holder)], rel, 3);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["initializer_not_modeled"]);
}

#[test]
fn method_reference_is_reachable() {
    let util = src(&[
        "package com.ex;",
        "final class Util {",
        "    static void seal() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Util.java";
    let a = app("        Runnable r = Util::seal; r.run();");
    let v = verdict(&[(APP, &a), (rel, &util)], rel, 4);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(
        v.chain,
        [format!("{APP}:App.main"), format!("{rel}:Util.seal")]
    );
}

#[test]
fn constructor_reference_reaches_constructor() {
    let svc = src(&[
        "package com.ex;",
        "class Maker {",
        "    Maker() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Maker.java";
    let a = app("        java.util.function.Supplier<Maker> s = Maker::new;");
    let v = verdict(&[(APP, &a), (rel, &svc)], rel, 4);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.enclosing_function.as_deref(), Some("Maker.<init>"));
}

#[test]
fn super_and_this_constructor_calls() {
    let base = src(&[
        "package com.ex;",
        "class Base {",
        "    Base(int x) {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let sub = src(&[
        "package com.ex;",
        "class Child extends Base {",
        "    Child() {",
        "        this(1);",
        "    }",
        "    Child(int x) {",
        "        super(x);",
        "    }",
        "}",
    ]);
    let (rb, rs) = (
        "src/main/java/com/ex/Base.java",
        "src/main/java/com/ex/Child.java",
    );
    let a = app("        new Child();");
    let v = verdict(&[(APP, &a), (rb, &base), (rs, &sub)], rb, 4);
    assert_eq!(v.label, Label::Reachable);
}

#[test]
fn static_init_reachable_when_a_static_method_is_reachable() {
    let cfg = src(&[
        "package com.ex;",
        "class Cfg {",
        "    static final Object K = build();",
        "    static {",
        CRYPTO,
        "    }",
        "    static void warm() {}",
        "    static Object build() { return null; }",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Cfg.java";
    let a = app("        Cfg.warm();");
    let srcs = [(APP, a.as_str()), (rel, cfg.as_str())];
    let v = verdict(&srcs, rel, 5);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(reasons(&v), ["class_initialized_by_reachable_member"]);
    assert_eq!(v.enclosing_function.as_deref(), Some("Cfg.<clinit>"));
    assert_eq!(
        v.chain,
        [
            format!("{APP}:App.main"),
            format!("{rel}:Cfg.warm"),
            format!("{rel}:Cfg.<clinit>")
        ]
    );
    let v = verdict(&srcs, rel, 3);
    assert_eq!(reasons(&v), ["class_initialized_by_reachable_member"]);
    assert_eq!(v.enclosing_function.as_deref(), Some("Cfg.<field-init>"));
    assert_eq!(verdict(&srcs, rel, 8).label, Label::Reachable);
    // Nothing reaches Cfg: the static initializer is unknown, never not_observed.
    let a = app("");
    let v = verdict(&[(APP, &a), (rel, &cfg)], rel, 5);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["initializer_not_modeled"]);
}

#[test]
fn framework_annotation_is_unknown() {
    let conf = src(&[
        "package com.ex;",
        "class Conf {",
        "    @Bean",
        "    Object zzBeanCipher() throws Exception {",
        "        return javax.crypto.Cipher.getInstance(\"AES\");",
        "    }",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Conf.java";
    let a = app("");
    let v = verdict(&[(APP, &a), (rel, &conf)], rel, 5);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["enclosing_annotated"]);
    // On an enclosing type.
    let conf2 = src(&[
        "package com.ex;",
        "@Configuration",
        "class Conf {",
        "    Object zzPlain() throws Exception {",
        "        return javax.crypto.Cipher.getInstance(\"AES\");",
        "    }",
        "}",
    ]);
    let v = verdict(&[(APP, &a), (rel, &conf2)], rel, 5);
    assert_eq!(reasons(&v), ["enclosing_annotated"]);
    // Reachable wins over every trigger.
    let a = app("        new Conf().zzBeanCipher();");
    let v = verdict(&[(APP, &a), (rel, &conf)], rel, 5);
    assert_eq!(v.label, Label::Reachable);
}

#[test]
fn benign_annotation_never_not_observed() {
    let base = src(&[
        "package com.ex;",
        "class Base {",
        "    void zzHook() {}",
        "}",
    ]);
    let sub = |ann: &str| {
        src(&[
            "package com.ex;",
            "class Sub extends Base {",
            ann,
            "    void zzHook() {",
            CRYPTO,
            "    }",
            "}",
        ])
    };
    let (rb, rs) = (
        "src/main/java/com/ex/Base.java",
        "src/main/java/com/ex/Sub.java",
    );
    let a = app("");
    for ann in [
        "    @Override",
        "    @Deprecated",
        "    @SuppressWarnings(\"x\")",
    ] {
        let s = sub(ann);
        let v = verdict(&[(APP, &a), (rb, &base), (rs, &s)], rs, 5);
        assert_eq!(v.label, Label::Unknown, "{ann}");
        assert_eq!(reasons(&v), ["enclosing_annotated"], "{ann}");
    }
    // The same member without the annotation is not_observed.
    let s = sub("");
    let v = verdict(&[(APP, &a), (rb, &base), (rs, &s)], rs, 5);
    assert_eq!(v.label, Label::NotObserved);
}

#[test]
fn reflection_anywhere_is_unknown_for_unreached_members() {
    let loader = src(&[
        "package com.ex;",
        "class Loader {",
        "    static Object make(String n) throws Exception {",
        "        return Class.forName(n).getDeclaredConstructor().newInstance();",
        "    }",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Loader.java";
    let v = not_observed_box(&[(rel, &loader)]);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["reflection_in_project"]);
    let a = app("");
    assert!(project(&[(APP, &a), (rel, &loader)]).has_reflection());
    for code in [
        "class R { native void zzNat(); }",
        "class R { Object s = java.util.ServiceLoader.class; }",
        "class R { static { System.load(\"x\"); } }",
        "class R { Object p = java.lang.reflect.Proxy.class; }",
    ] {
        let v = not_observed_box(&[("src/main/java/com/ex/R.java", code)]);
        assert_eq!(reasons(&v), ["reflection_in_project"], "{code}");
    }
    // Reachable members stay reachable.
    let a = app("        Box.zzSealUnused();");
    let b = unused_box();
    let v = verdict(&[(APP, &a), (BOX, &b), (rel, &loader)], BOX, 4);
    assert_eq!(v.label, Label::Reachable);
}

#[test]
fn external_supertype_is_unknown() {
    let task = src(&[
        "package com.ex;",
        "class Task implements Runnable {",
        "    public void run() {}",
        "    void zzWork() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Task.java";
    let a = app("");
    let v = verdict(&[(APP, &a), (rel, &task)], rel, 5);
    assert_eq!(reasons(&v), ["overrides_external_type_possible"]);
    // Through a project supertype.
    let more = src(&[
        "package com.ex;",
        "class More extends Task {",
        "    void zzMore() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let rm = "src/main/java/com/ex/More.java";
    let v = verdict(&[(APP, &a), (rel, &task), (rm, &more)], rm, 4);
    assert_eq!(reasons(&v), ["overrides_external_type_possible"]);
}

#[test]
fn jdk_implicit_name_is_unknown() {
    let job = src(&[
        "package com.ex;",
        "class Job {",
        "    public void run() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Job.java";
    let a = app("");
    let v = verdict(&[(APP, &a), (rel, &job)], rel, 4);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["jdk_implicit_name"]);
}

#[test]
fn name_in_config_file_is_unknown() {
    let props = "src/main/resources/application.properties";
    for (path, text) in [
        (props, "crypto.handler=zzSealUnused\n"),
        (props, "bean.class=com.ex.Box\n"),
        (props, "bean.class=com.ex.\\u0042ox\n"),
        (props, "bean.class=com.ex.B\\\n    ox\n"),
        (
            "src/main/resources/beans.xml",
            "<bean class=\"com.ex.&#66;ox\"/>\n",
        ),
        ("src/main/resources/app.yml", "h: \"\\tzzSealUnused\"\n"),
        (
            "src/main/resources/META-INF/services/com.ex.Spi",
            "com.ex.Box\n",
        ),
        ("src/main/resources/x.json", "{\"c\": \"com.ex.Outer$Box\"}"),
    ] {
        let v = not_observed_box(&[(path, text)]);
        assert_eq!(v.label, Label::Unknown, "{path}: {text}");
        assert_eq!(reasons(&v), ["named_in_config_file"], "{path}: {text}");
    }
    // An unrelated config file changes nothing; neither does a README.
    let v = not_observed_box(&[(props, "a=b\n"), ("README.md", "zzSealUnused Box")]);
    assert_eq!(v.label, Label::NotObserved);
}

#[test]
fn other_jvm_source_and_compiled_code_mark_project_incomplete() {
    let v = not_observed_box(&[("src/main/kotlin/K.kt", "fun zz() {}")]);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["project_not_fully_analyzed:other_jvm_source"]);
    let v = not_observed_box(&[("lib/x.jar", "")]);
    assert_eq!(
        reasons(&v),
        ["project_not_fully_analyzed:compiled_jvm_code"]
    );
    let a = app("");
    let p = project(&[(APP, &a), ("Build.groovy", "")]);
    assert_eq!(p.incomplete_reason(), Some("other_jvm_source"));
}

#[test]
fn non_ascii_in_code_marks_project_incomplete() {
    let u = "class U { int \u{e9} = 1; }";
    let v = not_observed_box(&[("src/main/java/com/ex/U.java", u)]);
    assert_eq!(
        reasons(&v),
        ["project_not_fully_analyzed:non_ascii_identifier_possible"]
    );
}

#[test]
fn parse_ambiguity_is_unknown() {
    let bad = "package com.ex;\nclass Bad {\n    void f() {\n        int x = 1;\n";
    let rel = "src/main/java/com/ex/Bad.java";
    let a = app("");
    let b = unused_box();
    let srcs = [(APP, a.as_str()), (BOX, b.as_str()), (rel, bad)];
    let v = verdict(&srcs, rel, 4);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["file_parse_ambiguity"]);
    let v = verdict(&srcs, BOX, 4);
    assert_eq!(
        reasons(&v),
        ["project_not_fully_analyzed:file_parse_ambiguity"]
    );
    // Brace nesting over the parser cap.
    let deep = format!(
        "class D {{ void f() {{ {} {} }} }}\n",
        "{".repeat(300),
        "}".repeat(300)
    );
    let v = verdict(&[(rel, &deep)], rel, 1);
    assert_eq!(reasons(&v), ["file_parse_ambiguity"]);
}

#[test]
fn referenced_but_unreached() {
    let chain = src(&[
        "package com.ex;",
        "class Chain {",
        "    static void zzA() {",
        "        zzB();",
        "    }",
        "    static void zzB() {",
        CRYPTO,
        "    }",
        "    static int zzC() {",
        "        return 1;",
        "    }",
        "    int zzC = 0;",
        "    static void zzP() { zzQ(); } static void zzQ() { zzP(); }",
        "}",
    ]);
    let rel = "src/main/java/com/ex/Chain.java";
    let a = app("");
    let srcs = [(APP, a.as_str()), (rel, chain.as_str())];
    assert_eq!(verdict(&srcs, rel, 4).label, Label::NotObserved);
    assert_eq!(
        reasons(&verdict(&srcs, rel, 7)),
        ["referenced_but_no_entry_path"]
    );
    assert_eq!(
        reasons(&verdict(&srcs, rel, 10)),
        ["method_referenced_not_modeled"]
    );
    assert_eq!(
        reasons(&verdict(&srcs, rel, 12)),
        ["initializer_not_modeled"]
    );
    assert_eq!(verdict(&srcs, rel, 13).label, Label::Unknown);
}

#[test]
fn outside_member_and_bad_locations() {
    let b = src(&[
        "package com.ex;",
        "class Box {",
        "    static Object k;",
        "    static void zz() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let srcs = [(BOX, b.as_str())];
    for line in [1, 2, 3] {
        let v = verdict(&srcs, BOX, line);
        assert_eq!(reasons(&v), ["outside_member"], "line {line}");
        assert_eq!(v.enclosing_function, None);
    }
    assert_eq!(reasons(&verdict(&srcs, BOX, 0)), ["line_out_of_range"]);
    assert_eq!(reasons(&verdict(&srcs, BOX, 99)), ["line_out_of_range"]);
    assert_eq!(reasons(&verdict(&srcs, "a.py", 1)), ["not_java_file"]);
    assert_eq!(
        reasons(&verdict(&srcs, "src/Other.java", 1)),
        ["file_not_analyzed"]
    );
}

#[test]
fn entry_spec_resolves_and_unknown_spec_errors() {
    let a = src(&[
        "package com.ex;",
        "public class App {",
        "    public void start() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let p = project(&[(APP, &a)]);
    assert_eq!(p.resolve_entry("com.ex.App:start").map(|v| v.len()), Ok(1));
    let r = p.reach(&["com.ex.App:start".to_string()]);
    let v = p.classify(&r, APP, 4);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(
        v.chain,
        [
            "--entry com.ex.App:start".to_string(),
            format!("{APP}:App.start")
        ]
    );
    // Without the entry nothing reaches `start`.
    assert_eq!(p.classify(&p.reach(&[]), APP, 4).label, Label::NotObserved);
    for bad in [
        "com.ex.Nope:start",
        "com.ex.App:nope",
        "org.ex.App:start",
        "com.ex.App",
        "com.ex.App:st art",
        ":start",
        "com..App:start",
    ] {
        assert!(p.resolve_entry(bad).is_err(), "{bad}");
    }
}

#[test]
fn same_class_name_in_two_packages_resolves_by_path() {
    let body = |pkg: &str| {
        src(&[
            &format!("package {pkg};"),
            "public class App {",
            "    public void start() {",
            CRYPTO,
            "    }",
            "}",
        ])
    };
    let (a, b) = (body("com.ex"), body("org.other"));
    let other = "src/main/java/org/other/App.java";
    let p = project(&[(APP, &a), (other, &b)]);
    let ra = p.resolve_entry("com.ex.App:start").unwrap();
    let rb = p.resolve_entry("org.other.App:start").unwrap();
    assert_eq!((ra.len(), rb.len()), (1, 1));
    assert_ne!(ra, rb);
    let r = p.reach(&["com.ex.App:start".to_string()]);
    assert_eq!(p.classify(&r, APP, 4).label, Label::Reachable);
    assert_ne!(p.classify(&r, other, 4).label, Label::Reachable);
    let r = p.reach(&["org.other.App:start".to_string()]);
    assert_eq!(p.classify(&r, other, 4).label, Label::Reachable);
    assert_ne!(p.classify(&r, APP, 4).label, Label::Reachable);
}

#[test]
fn load_walks_build_dirs_and_marks_skips() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    let a = src(&[
        "package com.ex;",
        "public class App {",
        "    public static void main(String[] args) {",
        "        helper();",
        "    }",
        "    static void helper() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    write(APP, &a);
    write(
        "build/gen/Gen.java",
        "class Gen {\n  static void zzGen() {\n  }\n}\n",
    );
    write(".git/hooks/x.kt", "fun x() {}");
    let p = JavaProject::load(root);
    assert_eq!(p.file_count(), 2);
    assert_eq!(p.incomplete_reason(), None);
    let r = p.reach(&[]);
    assert_eq!(p.classify(&r, APP, 7).label, Label::Reachable);
    assert_eq!(
        p.classify(&r, "build/gen/Gen.java", 2).label,
        Label::NotObserved
    );

    write("src/main/resources/application.yml", "handler: zzGen\n");
    let p = JavaProject::load(root);
    let v = p.classify(&p.reach(&[]), "build/gen/Gen.java", 2);
    assert_eq!(reasons(&v), ["named_in_config_file"]);

    write("node_modules/x/index.js", "");
    assert_eq!(
        JavaProject::load(root).incomplete_reason(),
        Some("skipped_directory")
    );
    write("target/classes/com/ex/App.class", "");
    assert_eq!(
        JavaProject::load(root).incomplete_reason(),
        Some("compiled_jvm_code")
    );
}

#[test]
fn load_with_excludes_ignores_listed_config_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write(
        "build/gen/Gen.java",
        "class Gen {\n  static void zzGen() {\n  }\n}\n",
    );
    write("hand.cbom.json", "{\"method\": \"zzGen\"}\n");
    let p = JavaProject::load(root);
    let v = p.classify(&p.reach(&[]), "build/gen/Gen.java", 2);
    assert_eq!(reasons(&v), ["named_in_config_file"]);
    let ex = [root.join("hand.cbom.json")];
    let p = JavaProject::load_with_excludes(root, &ex);
    let v = p.classify(&p.reach(&[]), "build/gen/Gen.java", 2);
    assert_eq!(v.label, Label::NotObserved);
    assert_eq!(reasons(&v), ["no_textual_reference"], "{:?}", reasons(&v));
}

// ---- security review fixes ---------------------------------------------------

const MAIN: &str = "src/main/java/com/ex/Main.java";
const DES: &str = "javax.crypto.Cipher.getInstance(\"DES\");";

/// `com.ex.Main` whose `main` (line 3) calls `live()`; `rest` from line 4.
fn main_calling_live(rest: &[&str]) -> String {
    let mut lines = vec![
        "package com.ex;",
        "public class Main {",
        "    public static void main(String[] args) throws Exception { live(); }",
    ];
    lines.extend_from_slice(rest);
    lines.push("}");
    src(&lines)
}

#[test]
fn line_shared_by_members_is_never_not_observed() {
    let shared = [
        // Two one-line members.
        format!("    static void dead() {{}} static void live() throws Exception {{ {DES} }}"),
        // The crypto member ends on the line where the next one opens.
        format!("    static void live() throws Exception {{ {DES} }} static void dead() {{"),
        // The crypto member opens after a one-line member and goes on.
        format!("    static void dead() {{}} static void live() throws Exception {{ {DES}"),
        // A local class opened on the crypto line.
        format!("    static void live() throws Exception {{ {DES} class L {{ void zzLocal() {{"),
    ];
    let tails: [&[&str]; 4] = [&[], &["    }"], &["    }"], &["    }}", "    }"]];
    for (line4, tail) in shared.iter().zip(tails) {
        let mut rest = vec![line4.as_str()];
        rest.extend_from_slice(tail);
        let m = main_calling_live(&rest);
        let v = verdict(&[(MAIN, &m)], MAIN, 4);
        assert_eq!(v.label, Label::Reachable, "{line4}: {:?}", v.reasons);
        assert_eq!(
            v.enclosing_function.as_deref(),
            Some("Main.live"),
            "{line4}"
        );
    }
    // Nothing reaches either member: unknown, not not_observed.
    let m = src(&[
        "package com.ex;",
        "public class Main {",
        "    public static void main(String[] args) {}",
        &format!("    static void zzA() {{}} static void zzB() throws Exception {{ {DES} }}"),
        "}",
    ]);
    let v = verdict(&[(MAIN, &m)], MAIN, 4);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["line_shared_by_members"]);
    assert_eq!(v.enclosing_function, None);
    // A line wholly inside a local class method belongs to that method only.
    let m = main_calling_live(&[
        "    static void live() throws Exception { class L { void zzLocal() throws Exception {",
        &format!("        {DES}"),
        "    }}",
        "    }",
    ]);
    let v = verdict(&[(MAIN, &m)], MAIN, 5);
    assert_eq!(v.label, Label::NotObserved, "{:?}", v.reasons);
    assert_eq!(v.enclosing_function.as_deref(), Some("Main.L.zzLocal"));
}

#[test]
fn same_named_project_type_does_not_hide_external_supertype() {
    let main = src(&[
        "package com.ex;",
        "public class Main {",
        "    public static void main(String[] args) {}",
        "    static class Handler {}",
        "}",
    ]);
    let rs = "src/main/java/com/ex/Sink.java";
    let sink = |import: &str, sup: &str| {
        src(&[
            "package com.ex;",
            import,
            &format!("class Sink extends {sup} {{"),
            "    public void publish(java.util.logging.LogRecord r) {",
            CRYPTO,
            "    }",
            "}",
        ])
    };
    let other = "src/main/java/org/other/Handler.java";
    let other_src = "package org.other;\npublic class Handler {}\n";
    let same = "src/main/java/com/ex/Handler.java";
    let same_src = "package com.ex;\npublic class Handler {}\n";
    let external = [
        // The review's case: a qualified JDK name.
        ("", "java.util.logging.Handler", None),
        // Single-type import from outside the project.
        ("import java.util.logging.Handler;", "Handler", None),
        // Wildcard import, the only project `Handler` in another package.
        (
            "import java.util.logging.*;",
            "Handler",
            Some((other, other_src)),
        ),
        // Unqualified, no project type in scope (`Main.Handler` is not).
        ("", "Handler", None),
        // Qualified through a type imported from outside the project.
        ("import lib.Main;", "Main.Handler", None),
        // Duplicate same-package types.
        ("", "Handler", Some((same, same_src))),
    ];
    for (import, sup, extra) in external {
        let s = sink(import, sup);
        let mut srcs = vec![(MAIN, main.as_str()), (rs, s.as_str())];
        srcs.extend(extra);
        if sup == "Handler" && extra.is_some_and(|(p, _)| p == same) {
            let dup = "src/test/java/com/ex/Handler.java";
            srcs.push((dup, same_src));
        }
        let v = verdict(&srcs, rs, 5);
        assert_eq!(v.label, Label::Unknown, "{import} {sup}");
        assert_eq!(
            reasons(&v),
            ["overrides_external_type_possible"],
            "{import} {sup}"
        );
    }
    let internal = [
        ("", "com.ex.Main.Handler", None),
        // The same-package type `Main`, then its member type.
        ("", "Main.Handler", None),
        ("import com.ex.Main.Handler;", "Handler", None),
        // A same-package type shadows an on-demand import.
        (
            "import java.util.logging.*;",
            "Handler",
            Some((same, same_src)),
        ),
        ("", "org.other.Handler", Some((other, other_src))),
    ];
    for (import, sup, extra) in internal {
        let s = sink(import, sup);
        let mut srcs = vec![(MAIN, main.as_str()), (rs, s.as_str())];
        srcs.extend(extra);
        let v = verdict(&srcs, rs, 5);
        assert_eq!(
            v.label,
            Label::NotObserved,
            "{import} {sup}: {:?}",
            v.reasons
        );
    }
    // Nested in the type that declares `Handler`: that member type.
    let nested = src(&[
        "package com.ex;",
        "public class Main {",
        "    public static void main(String[] args) {}",
        "    static class Handler {}",
        "    static class Sink extends Handler {",
        "        void publish() {",
        CRYPTO,
        "        }",
        "    }",
        "}",
    ]);
    let v = verdict(&[(MAIN, &nested)], MAIN, 7);
    assert_eq!(v.label, Label::NotObserved, "{:?}", v.reasons);
    // The enclosing type has a supertype that may supply an inherited
    // `Handler`: only a declared member type counts.
    let inherited = nested.replace("public class Main {", "public class Main extends Base {");
    let inherited = inherited.replace("    static class Handler {}\n", "");
    let base = "package com.ex;\nclass Base {}\n";
    let rb = "src/main/java/com/ex/Base.java";
    let v = verdict(&[(MAIN, &inherited), (rb, base), (same, same_src)], MAIN, 6);
    assert_eq!(reasons(&v), ["overrides_external_type_possible"]);
    // A local class's supertype is never resolved.
    let local = src(&[
        "package com.ex;",
        "public class Main {",
        "    public static void main(String[] args) {}",
        "    static void zzOuter() {",
        "        class Sink extends Base {",
        "            void publish() {",
        CRYPTO,
        "            }",
        "        }",
        "    }",
        "}",
    ]);
    let v = verdict(&[(MAIN, &local), (rb, base)], MAIN, 7);
    assert_eq!(reasons(&v), ["overrides_external_type_possible"]);
}

#[test]
fn java_beans_and_other_reflection_words() {
    let m = src(&[
        "package com.ex;",
        "public class Main {",
        "    public static void main(String[] args) throws Exception {",
        "        new java.beans.Statement(new Main(), \"seal\", new Object[0]).execute();",
        "    }",
        "    public void seal() throws Exception {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let v = verdict(&[(MAIN, &m)], MAIN, 7);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["reflection_in_project"]);
    for code in [
        "class R { Object x = java.beans.Expression.class; }",
        "class R { Object x = java.beans.EventHandler.class; }",
        "class R { Object x = java.beans.XMLDecoder.class; }",
        "class R { Object x = java.beans.Introspector.class; }",
        "class R { Object x = java.beans.PropertyDescriptor.class; }",
        "class R { Object x = java.beans.BeanInfo.class; }",
        "class R { Object x = jdk.jshell.JShell.class; }",
        "class R { Object x = org.apache.commons.lang3.reflect.MethodUtils.class; }",
        "class R { Object x = org.apache.commons.beanutils.PropertyUtils.class; }",
        "class R { Object x = org.apache.commons.beanutils.BeanUtils.class; }",
        "class R { Object x = javax.script.ScriptEngine.class; }",
        "class R { Object x = javax.script.ScriptEngineManager.class; }",
        "class R { static { Runtime.getRuntime().load(\"x\"); } }",
        "class R { static { lib.load(\"x\"); } }",
        "class R { java.util.function.Consumer<String> c = System::load; }",
    ] {
        let v = not_observed_box(&[("src/main/java/com/ex/R.java", code)]);
        assert_eq!(reasons(&v), ["reflection_in_project"], "{code}");
    }
    // `load` that is not a call on a receiver is not a trigger.
    let v = not_observed_box(&[("src/main/java/com/ex/R.java", "class R { int load = 1; }")]);
    assert_eq!(v.label, Label::NotObserved);
}

#[test]
fn bean_accessors_and_reflective_libraries() {
    let dto = src(&[
        "package com.ex;",
        "public class Dto {",
        "    public String getKey() throws Exception {",
        CRYPTO,
        "        return \"\";",
        "    }",
        "}",
    ]);
    let rd = "src/main/java/com/ex/Dto.java";
    let m = app("        new java.beans.XMLEncoder(System.out).writeObject(new Dto());");
    let v = verdict(&[(APP, &m), (rd, &dto)], rd, 4);
    assert_ne!(v.label, Label::NotObserved);
    assert_eq!(reasons(&v), ["reflection_in_project"]);
    // Without any reflection word the accessor name alone blocks not_observed.
    let a = app("");
    for name in ["getKey", "isOn", "setKey", "getURL"] {
        let d = dto.replace("getKey", name);
        let v = verdict(&[(APP, &a), (rd, &d)], rd, 4);
        assert_eq!(reasons(&v), ["bean_accessor_possible"], "{name}");
    }
    for name in ["getaway", "issue", "settle", "zzGetKey"] {
        let d = dto.replace("getKey", name);
        let v = verdict(&[(APP, &a), (rd, &d)], rd, 4);
        assert_eq!(v.label, Label::NotObserved, "{name}");
    }
    // Reflective libraries, imported or used by qualified name.
    let rj = "src/main/java/com/ex/J.java";
    for code in [
        "package com.ex;\nimport com.fasterxml.jackson.databind.ObjectMapper;\nclass J {}\n",
        "package com.ex;\nimport static org.junit.Assert.*;\nclass J {}\n",
        "package com.ex;\nimport dagger.Module;\nclass J {}\n",
        "package com.ex;\nclass J { Object g = new com.google.gson.Gson(); }\n",
        "package com.ex;\n@org.springframework.stereotype.Component class J {}\n",
        "package com.ex;\nimport jakarta.enterprise.event.Observes;\nclass J {}\n",
        "package com.ex;\nimport javax.enterprise.context.ApplicationScoped;\nclass J {}\n",
        "package com.ex;\nimport jakarta.xml.bind.JAXB;\nclass J {}\n",
        "package com.ex;\nimport javax.xml.bind.JAXB;\nclass J {}\n",
        "package com.ex;\nimport jakarta.json.bind.Jsonb;\nclass J {}\n",
        "package com.ex;\nimport javax.json.bind.Jsonb;\nclass J {}\n",
        "package com.ex;\nimport org.yaml.snakeyaml.Yaml;\nclass J {}\n",
        "package com.ex;\nimport com.github.mustachejava.Mustache;\nclass J {}\n",
        "package com.ex;\nimport com.samskivert.mustache.Mustache;\nclass J {}\n",
        "package com.ex;\nimport com.github.jknack.handlebars.Handlebars;\nclass J {}\n",
        "package com.ex;\nimport io.pebbletemplates.pebble.PebbleEngine;\nclass J {}\n",
        "package com.ex;\nimport static org.mockito.Mockito.*;\nclass J {}\n",
        "package com.ex;\nimport org.testng.annotations.Test;\nclass J {}\n",
        "package com.ex;\nimport javax.management.ObjectName;\nclass J {}\n",
    ] {
        let v = not_observed_box(&[(rj, code)]);
        assert_eq!(
            reasons(&v),
            ["project_not_fully_analyzed:reflective_library_import"],
            "{code}"
        );
    }
    for code in [
        "package com.ex;\nimport com.fasterxmlx.Foo;\nclass J {}\n",
        "package com.ex;\nclass J { int dagger = 1; int x = dagger + 1; }\n",
    ] {
        let v = not_observed_box(&[(rj, code)]);
        assert_eq!(v.label, Label::NotObserved, "{code}");
    }
}

#[test]
fn agent_entry_points_and_more_config_and_jvm_files() {
    for name in ["premain", "agentmain"] {
        let b = unused_box().replace("zzSealUnused", name);
        let a = app("");
        let v = verdict(&[(APP, &a), (BOX, &b)], BOX, 4);
        assert_eq!(reasons(&v), ["jdk_implicit_name"], "{name}");
    }
    for path in [
        "src/main/resources/META-INF/MANIFEST.MF",
        "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports",
        "src/main/resources/META-INF/x/no_extension",
        "src/main/resources/meta-inf/handlers.txt",
        "src/main/resources/spring.factories",
        "src/main/resources/application.conf",
        "config.toml",
        "setup.ini",
    ] {
        let v = not_observed_box(&[(path, "Premain-Class: com.ex.Box\n")]);
        assert_eq!(reasons(&v), ["named_in_config_file"], "{path}");
    }
    for ext in [
        "aj", "jsh", "gvy", "gy", "gsh", "sc", "cljs", "cljc", "jspx", "jspf", "tag", "tagx",
        "ftl", "vm", "jte", "mustache", "hbs", "peb", "ftlh", "ftlx",
    ] {
        let path = format!("src/main/x/File.{ext}");
        let v = not_observed_box(&[(path.as_str(), "")]);
        assert_eq!(
            reasons(&v),
            ["project_not_fully_analyzed:other_jvm_source"],
            "{ext}"
        );
    }
    let tpl = "src/main/resources/templates/index.html";
    for html in [
        "<p th:text=\"${k}\">x</p>",
        "<p data-th-text=\"${k}\">x</p>",
    ] {
        let v = not_observed_box(&[(tpl, html)]);
        assert_eq!(
            reasons(&v),
            ["project_not_fully_analyzed:other_jvm_source"],
            "{html}"
        );
    }
    // Plain HTML: neither a trigger nor a config file.
    let v = not_observed_box(&[(tpl, "<p>zzSealUnused Box</p>")]);
    assert_eq!(v.label, Label::NotObserved);
}

#[test]
fn archives_and_native_libraries_are_compiled_code() {
    for ext in [
        "war", "ear", "jmod", "zip", "so", "dll", "dylib", "jnilib", "JAR", "aar", "dex", "apk",
    ] {
        let path = format!("lib/x.{ext}");
        let v = not_observed_box(&[(path.as_str(), "")]);
        assert_eq!(
            reasons(&v),
            ["project_not_fully_analyzed:compiled_jvm_code"],
            "{ext}"
        );
    }
}

#[test]
fn load_marks_nested_git_and_scans_meta_inf_and_templates() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write(
        "build/gen/Gen.java",
        "class Gen {\n  static void zzGen() {\n  }\n}\n",
    );
    write(".git/HEAD", "ref: refs/heads/main\n");
    let p = JavaProject::load(root);
    assert_eq!(p.incomplete_reason(), None);
    assert_eq!(
        p.classify(&p.reach(&[]), "build/gen/Gen.java", 2).label,
        Label::NotObserved
    );
    // Any file below META-INF/ is a config file, whatever its name.
    write("src/main/resources/META-INF/x/handlers", "zzGen\n");
    let p = JavaProject::load(root);
    let v = p.classify(&p.reach(&[]), "build/gen/Gen.java", 2);
    assert_eq!(reasons(&v), ["named_in_config_file"]);
    std::fs::remove_dir_all(root.join("src")).unwrap();
    // A Thymeleaf template.
    write("templates/a.html", "<p th:text=\"${x}\"></p>\n");
    assert_eq!(
        JavaProject::load(root).incomplete_reason(),
        Some("other_jvm_source")
    );
    std::fs::remove_dir_all(root.join("templates")).unwrap();
    assert_eq!(JavaProject::load(root).incomplete_reason(), None);
    // A nested repository is not walked and marks the project incomplete.
    write("vendor/lib/.git/HEAD", "ref: refs/heads/main\n");
    assert_eq!(
        JavaProject::load(root).incomplete_reason(),
        Some("skipped_directory")
    );
}

// ---- untrusted-input bounds ----------------------------------------------------

const BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// `void a0(){a0();}void a1(){a1();}…` (`n` methods, one line).
fn tiny_methods(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!("void a{i}(){{a{i}();}}"));
    }
    s
}

#[test]
fn too_many_members_on_one_line_is_ambiguous_and_fast() {
    let t = std::time::Instant::now();
    let code = format!("class A {{{}}}\n", tiny_methods(60_000));
    let p = project(&[(APP, &code)]);
    let r = p.reach(&[]);
    let v = p.classify(&r, APP, 1);
    assert!(t.elapsed() < BUDGET, "{:?}", t.elapsed());
    assert_eq!(p.files[0].parsed.ambiguity, Some("too_many_members"));
    assert_eq!(reasons(&v), ["file_parse_ambiguity"]);
    assert_eq!(p.incomplete_reason(), Some("file_parse_ambiguity"));
}

/// `com.ex.App`: `main` (line 3) runs `body`; 20k tiny methods on line 4;
/// an unreferenced `zzLone` whose crypto call is line 6.
fn many_members_app(body: &str) -> String {
    let methods = format!("    {}", tiny_methods(20_000));
    src(&[
        "package com.ex;",
        "public class App {",
        &format!("    public static void main(String[] args) {{ {body} }}"),
        &methods,
        "    static void zzLone() {",
        CRYPTO,
        "    }",
        "}",
    ])
}

#[test]
fn many_members_on_one_line_label_correctly_and_fast() {
    let t = std::time::Instant::now();
    let a = many_members_app("a7();");
    let p = project(&[(APP, &a)]);
    let r = p.reach(&[]);
    let shared = p.classify(&r, APP, 4);
    let lone = p.classify(&r, APP, 6);
    let main = p.classify(&r, APP, 3);
    assert!(t.elapsed() < BUDGET, "{:?}", t.elapsed());
    assert_eq!(p.files[0].parsed.ambiguity, None);
    assert_eq!(p.files[0].parsed.members.len(), 20_002);
    assert_eq!(shared.label, Label::Reachable);
    assert_eq!(shared.enclosing_function.as_deref(), Some("App.a7"));
    assert_eq!(
        shared.chain,
        [format!("{APP}:App.main"), format!("{APP}:App.a7")]
    );
    assert_eq!(lone.label, Label::NotObserved);
    assert_eq!(reasons(&lone), ["no_textual_reference"]);
    assert_eq!(main.label, Label::Reachable);
    assert_eq!(main.enclosing_function.as_deref(), Some("App.main"));

    // None of the line's members reached: never `not_observed`.
    let t = std::time::Instant::now();
    let a = many_members_app("");
    let p = project(&[(APP, &a)]);
    let r = p.reach(&[]);
    let shared = p.classify(&r, APP, 4);
    assert!(t.elapsed() < BUDGET, "{:?}", t.elapsed());
    assert_eq!(shared.label, Label::Unknown);
    assert_eq!(reasons(&shared), ["line_shared_by_members"]);
}

#[test]
fn many_same_named_self_extending_types_are_fast() {
    let t = std::time::Instant::now();
    let mut x = String::from("package com.ex;\n");
    for _ in 0..5_000 {
        x.push_str("class X extends X {}\n");
    }
    let a = app("        new X();");
    let b = unused_box();
    let p = project(&[
        (APP, a.as_str()),
        (BOX, b.as_str()),
        ("src/main/java/com/ex/X.java", x.as_str()),
    ]);
    let r = p.reach(&[]);
    let main = p.classify(&r, APP, 4);
    let unused = p.classify(&r, BOX, 4);
    assert!(t.elapsed() < BUDGET, "{:?}", t.elapsed());
    assert_eq!(main.label, Label::Reachable);
    assert!(!r.truncated);
    // `Box` has no supertype: the ambiguous `X` does not leak into it.
    assert_eq!(unused.label, Label::NotObserved);
    assert_eq!(reasons(&unused), ["no_textual_reference"]);
}

#[test]
fn qualified_name_budget_makes_the_file_ambiguous() {
    // 30 nested 121-byte names, 1500 siblings: ~5.5 MB of qualified names
    // from a ~25 KB file.
    let mut s = String::new();
    for i in 0..30 {
        s.push_str(&format!("class N{i:02}{} {{ ", "x".repeat(118)));
    }
    for j in 0..1500 {
        s.push_str(&format!("class S{j} {{ void m{j}() {{ }} }} "));
    }
    s.push_str(&"} ".repeat(30));
    s.push('\n');
    let p = project(&[(APP, &s)]);
    assert_eq!(p.files[0].parsed.ambiguity, Some("name_budget_exceeded"));
    let v = p.classify(&p.reach(&[]), APP, 1);
    assert_eq!(reasons(&v), ["file_parse_ambiguity"]);
}

#[test]
fn chain_length_is_bounded() {
    // main -> m0 -> m1 -> … -> m99: 101 labeled nodes.
    let mut lines = vec![
        "package com.ex;".to_string(),
        "public class App {".to_string(),
        "    public static void main(String[] args) { m0(); }".to_string(),
    ];
    for i in 0..99 {
        lines.push(format!("    static void m{i}() {{ m{}(); }}", i + 1));
    }
    lines.push("    static void m99() {".to_string());
    lines.push(CRYPTO.to_string());
    lines.push("    }".to_string());
    lines.push("}".to_string());
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let a = src(&refs);
    let v = verdict(&[(APP, &a)], APP, 104);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.enclosing_function.as_deref(), Some("App.m99"));
    assert_eq!(v.chain.len(), 51, "{:?}", v.chain);
    assert_eq!(v.chain[0], format!("{APP}:App.main"));
    assert_eq!(v.chain[24], format!("{APP}:App.m23"));
    assert_eq!(v.chain[25], "…");
    assert_eq!(v.chain[26], format!("{APP}:App.m75"));
    assert_eq!(v.chain[50], format!("{APP}:App.m99"));
    // Exactly MAX_CHAIN labeled nodes: nothing elided.
    let v = verdict(&[(APP, &a)], APP, 3 + 49);
    assert_eq!(v.enclosing_function.as_deref(), Some("App.m48"));
    assert_eq!(v.chain.len(), 50);
    assert!(!v.chain.iter().any(|c| c == "…"));
}

#[test]
fn chain_through_constructors_keeps_the_head_and_tail() {
    // main -> new K0() -> K0() -> new K1() -> … -> K59(): the instance
    // nodes between the constructors are not labeled.
    let rel = "src/main/java/com/ex/K.java";
    let mut lines = vec!["package com.ex;".to_string()];
    for i in 0..59 {
        lines.push(format!("class K{i} {{ K{i}() {{ new K{}(); }} }}", i + 1));
    }
    lines.push("class K59 { K59() { } }".to_string());
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let k = src(&refs);
    let a = app("        new K0();");
    let srcs = [(APP, a.as_str()), (rel, k.as_str())];
    let v = verdict(&srcs, rel, 61);
    assert_eq!(v.enclosing_function.as_deref(), Some("K59.<init>"));
    assert_eq!(v.label, Label::Reachable);
    let mut want = vec![format!("{APP}:App.main")];
    want.extend((0..24).map(|i| format!("{rel}:K{i}.<init>")));
    want.push("…".to_string());
    want.extend((35..60).map(|i| format!("{rel}:K{i}.<init>")));
    assert_eq!(v.chain, want);
    // 42 labeled nodes: the whole chain.
    let v = verdict(&srcs, rel, 42);
    let mut want = vec![format!("{APP}:App.main")];
    want.extend((0..41).map(|i| format!("{rel}:K{i}.<init>")));
    assert_eq!(v.chain, want);
}

#[test]
fn deep_chain_rows_are_fast() {
    // main -> m0 -> m1 -> … -> m199999 over 5 files of 40k methods (one
    // per line); 1000 rows on the deepest line. Walking the whole parent
    // chain per row would be 2·10^8 steps.
    const PER_FILE: usize = 40_000;
    const FILES: usize = 5;
    let last = PER_FILE * FILES - 1;
    let a = app("        m0();");
    let mut files: Vec<(String, String)> = vec![(APP.to_string(), a)];
    for j in 0..FILES {
        let mut s = format!("package com.ex;\nclass C{j} {{\n");
        for k in 0..PER_FILE {
            let i = j * PER_FILE + k;
            if i == last {
                s.push_str(&format!("    static void m{i}() {{ }}\n"));
            } else {
                s.push_str(&format!("    static void m{i}() {{ m{}(); }}\n", i + 1));
            }
        }
        s.push_str("}\n");
        files.push((format!("src/main/java/com/ex/C{j}.java"), s));
    }
    let p = JavaProject::from_sources(files);
    let r = p.reach(&[]);
    assert!(!r.truncated);
    let rel = format!("src/main/java/com/ex/C{}.java", FILES - 1);
    let line = u32::try_from(PER_FILE + 2).unwrap();
    let t = std::time::Instant::now();
    let mut v = p.classify(&r, &rel, line);
    for _ in 1..1000 {
        v = p.classify(&r, &rel, line);
    }
    let took = t.elapsed();
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(
        v.enclosing_function,
        Some(format!("C{}.m{last}", FILES - 1))
    );
    assert_eq!(v.chain.len(), 51, "{:?}", v.chain);
    assert_eq!(v.chain[0], format!("{APP}:App.main"));
    assert_eq!(v.chain[1], "src/main/java/com/ex/C0.java:C0.m0");
    assert_eq!(v.chain[24], "src/main/java/com/ex/C0.java:C0.m23");
    assert_eq!(v.chain[25], "…");
    assert_eq!(v.chain[26], format!("{rel}:C{}.m{}", FILES - 1, last - 24));
    assert_eq!(v.chain[50], format!("{rel}:C{}.m{last}", FILES - 1));
}

#[test]
fn long_package_name_makes_the_file_ambiguous() {
    let t = std::time::Instant::now();
    let mut s = String::from("package a");
    while s.len() < 2 * 1024 * 1024 {
        s.push_str(".a");
    }
    s.push_str(";\n");
    for _ in 0..1000 {
        s.push_str("enum a{}\n");
    }
    let p = project(&[(APP, &s)]);
    assert_eq!(p.files[0].parsed.ambiguity, Some("name_too_long"));
    let v = p.classify(&p.reach(&[]), APP, 1);
    assert_eq!(reasons(&v), ["file_parse_ambiguity"]);
    assert!(t.elapsed() < BUDGET, "{:?}", t.elapsed());
}

/// `n` files, each `com.ex.F<j><x…>` with a member type `I<y…>` (~10 KB of
/// name bytes per file) and an unreferenced method on line 3.
fn long_named_files(n: usize) -> Vec<(String, String)> {
    let (x, y) = ("x".repeat(1000), "y".repeat(1000));
    (0..n)
        .map(|j| {
            let rel = format!("src/main/java/com/ex/F{j:04}.java");
            let code = src(&[
                "package com.ex;",
                &format!("class F{j:04}{x} {{ class I{y} {{ }}"),
                "    static void zzUnused() { }",
                "}",
            ]);
            (rel, code)
        })
        .collect()
}

#[test]
fn project_name_budget_marks_the_project_incomplete() {
    let t = std::time::Instant::now();
    let budget = 1024 * 1024;
    let p = JavaProject::from_sources_with_name_budget(long_named_files(300), budget);
    assert!(t.elapsed() < BUDGET, "{:?}", t.elapsed());
    assert!(p.name_bytes <= budget);
    assert!(
        p.file_count() > 0 && p.file_count() < 300,
        "{}",
        p.file_count()
    );
    assert_eq!(p.incomplete_reason(), Some(ANALYSIS_LIMIT));
    let r = p.reach(&[]);
    // A skipped file and an analyzed one: both fail closed.
    let v = p.classify(&r, "src/main/java/com/ex/F0299.java", 3);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), [ANALYSIS_LIMIT]);
    let v = p.classify(&r, "src/main/java/com/ex/F0000.java", 3);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["project_not_fully_analyzed:analysis_limit"]);
    // Under the default budget the same project is complete.
    let p = JavaProject::from_sources(long_named_files(300));
    assert_eq!(p.file_count(), 300);
    assert_eq!(p.incomplete_reason(), None);
    let v = p.classify(&p.reach(&[]), "src/main/java/com/ex/F0000.java", 3);
    assert_eq!(v.label, Label::NotObserved);
}

#[test]
fn long_member_names_are_clipped() {
    let long = "z".repeat(5_000);
    let b = unused_box().replace("zzSealUnused", &long);
    let a = app("");
    let v = verdict(&[(APP, &a), (BOX, &b)], BOX, 4);
    assert_eq!(v.label, Label::NotObserved);
    let ef = v.enclosing_function.unwrap();
    assert_eq!(ef.chars().count(), MAX_LABEL_CHARS + 1);
    assert!(ef.starts_with("Box.zzz"));
    assert!(ef.ends_with('…'));
}

#[test]
fn thymeleaf_attribute_pattern() {
    for html in [
        "<p th:text=\"${x}\">",
        "<p data-th-text=\"${x}\">",
        "<li\tth:each = \"i : ${xs}\">",
        "th:text=\"x\"",
        "<th:block>",
    ] {
        assert!(has_thymeleaf(html.as_bytes()), "{html}");
    }
    for html in [
        "<div style=\"width:10px\">",
        "<div style=\"max-width:10px\">",
        "<style>th:hover { color: red }</style>",
        "<th>Header</th>",
        "<p>month:10</p>",
    ] {
        assert!(!has_thymeleaf(html.as_bytes()), "{html}");
    }
    let tpl = "src/main/resources/templates/index.html";
    let v = not_observed_box(&[(tpl, "<div style=\"width:10px\">x</div>")]);
    assert_eq!(v.label, Label::NotObserved);
    for html in [
        "<p th:text=\"${x}\">x</p>",
        "<p data-th-text=\"${x}\">x</p>",
    ] {
        let v = not_observed_box(&[(tpl, html)]);
        assert_eq!(
            reasons(&v),
            ["project_not_fully_analyzed:other_jvm_source"],
            "{html}"
        );
    }
}

#[cfg(unix)]
#[test]
fn load_does_not_follow_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join("Real.java"), "class Real {}\n").unwrap();
    std::os::unix::fs::symlink(root.join("Real.java"), root.join("Link.java")).unwrap();
    let p = JavaProject::load(root);
    assert_eq!(p.file_count(), 1);
    assert_eq!(p.incomplete_reason(), Some("symlink_not_followed"));
}

#[test]
fn jpms_provider_and_module_directives_are_never_not_observed() {
    let module = "src/main/java/module-info.java";
    let module_src = "module com.ex {\n  provides ext.Spi with com.ex.Impl;\n}\n";
    let ri = "src/main/java/com/ex/Impl.java";
    // `ServiceLoader` calls a provider's `public static provider()`.
    let impl_src = src(&[
        "package com.ex;",
        "public class Impl {",
        "    public static ext.Spi provider() {",
        CRYPTO,
        "        return null;",
        "    }",
        "}",
    ]);
    let a = app("");
    let v = verdict(&[(APP, &a), (module, module_src), (ri, &impl_src)], ri, 4);
    assert_ne!(v.label, Label::NotObserved, "{:?}", v.reasons);
    assert_eq!(reasons(&v), ["jdk_implicit_name"]);
    // Any member of a type named in `provides … with` / `uses`.
    let other = impl_src.replace("provider()", "zzMake()");
    let v = verdict(&[(APP, &a), (module, module_src), (ri, &other)], ri, 4);
    assert_eq!(reasons(&v), ["named_in_config_file"]);
    let uses = "module com.ex {\n  uses com.ex.Impl;\n}\n";
    let v = verdict(&[(APP, &a), (module, uses), (ri, &other)], ri, 4);
    assert_eq!(reasons(&v), ["named_in_config_file"]);
    // Other directives name nothing.
    let requires = "module com.ex {\n  requires ext;\n  exports com.ex;\n}\n";
    let v = verdict(&[(APP, &a), (module, requires), (ri, &other)], ri, 4);
    assert_eq!(v.label, Label::NotObserved, "{:?}", v.reasons);
}

#[test]
fn parameter_annotation_makes_the_member_annotated() {
    let boot = src(&[
        "package com.ex;",
        "class Boot {",
        "    void boot(@Observes @Initialized(ApplicationScoped.class) Object e) {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let rb = "src/main/java/com/ex/Boot.java";
    let a = app("");
    let v = verdict(&[(APP, &a), (rb, &boot)], rb, 4);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["enclosing_annotated"]);
}

#[test]
fn jmx_registration_is_reflection() {
    let mbean = src(&[
        "package com.ex;",
        "public interface KeyAdminMBean {",
        "    default void zzRotate() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let rm = "src/main/java/com/ex/KeyAdminMBean.java";
    let admin = "package com.ex;\npublic class KeyAdmin implements KeyAdminMBean {}\n";
    let ra = "src/main/java/com/ex/KeyAdmin.java";
    let register = app(
        "        java.lang.management.ManagementFactory.getPlatformMBeanServer()\
         .registerMBean(new KeyAdmin(), null);",
    );
    let v = verdict(&[(APP, &register), (rm, &mbean), (ra, admin)], rm, 4);
    assert_ne!(v.label, Label::NotObserved, "{:?}", v.reasons);
    assert_eq!(reasons(&v), ["reflection_in_project"]);
    for code in [
        "class R { Object x = javax.management.StandardMBean.class; }",
        "class R { Object x = javax.management.MXBean.class; }",
        "import javax.management.*;\nclass R {}",
    ] {
        let a = app("");
        let rr = "src/main/java/com/ex/R.java";
        let v = verdict(&[(APP, &a), (rm, &mbean), (ra, admin), (rr, code)], rm, 4);
        assert_ne!(v.label, Label::NotObserved, "{code}: {:?}", v.reasons);
    }
    // Without any JMX use the default method is not observed.
    let a = app("        new KeyAdmin();");
    let v = verdict(&[(APP, &a), (rm, &mbean), (ra, admin)], rm, 4);
    assert_eq!(v.label, Label::NotObserved, "{:?}", v.reasons);
}

#[test]
fn qualified_supertype_through_an_imported_type_is_external() {
    let base = "class Base {\n    static class Callback {}\n}\n";
    let rb = "src/main/java/Base.java";
    let packaged = src(&[
        "package com.ex;",
        "import lib.Base;",
        "class C extends Base.Callback {",
        "    void zzOnEvent() {",
        CRYPTO,
        "    }",
        "}",
    ]);
    let rc = "src/main/java/com/ex/C.java";
    let a = app("");
    let v = verdict(&[(APP, &a), (rb, base), (rc, &packaged)], rc, 5);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["overrides_external_type_possible"]);
    // Not imported, but a default-package type cannot be named from a
    // package.
    let no_import = packaged.replace("import lib.Base;", "");
    let v = verdict(&[(APP, &a), (rb, base), (rc, &no_import)], rc, 5);
    assert_eq!(reasons(&v), ["overrides_external_type_possible"]);
    // In the default package too: the import names `Base`.
    let default_pkg = packaged.replace("package com.ex;", "");
    let rd = "src/main/java/C.java";
    let v = verdict(&[(APP, &a), (rb, base), (rd, &default_pkg)], rd, 5);
    assert_eq!(reasons(&v), ["overrides_external_type_possible"]);
    // Without the import the same-package `Base` is the one in scope.
    let local = default_pkg.replace("import lib.Base;", "");
    let v = verdict(&[(APP, &a), (rb, base), (rd, &local)], rd, 5);
    assert_eq!(v.label, Label::NotObserved, "{:?}", v.reasons);
    // `Callback` is not a member type of the resolved `Base`.
    let missing = "class Base {}\n";
    let v = verdict(&[(APP, &a), (rb, missing), (rd, &local)], rd, 5);
    assert_eq!(reasons(&v), ["overrides_external_type_possible"]);
}

// ---- fuzzer regression: `@` only inside a string literal ------------------

#[test]
fn fuzz_guard_reflection_words_only() {
    let code = src(&[
        "package com.ex;",
        "",
        "import javax.crypto.Cipher;",
        "",
        "public class Sealer {",
        "  static void seal() throws Exception {",
        "        Cipher.getInstance(\"AES/CBC/PKCS3@adding\");",
        "    }",
        "}",
    ]);
    // The guard reads the code view, where the literal is blank.
    assert!(!code_guard_triggered(&lex(&code).code));
    // An annotation alone is not a trigger: the per-member rule covers it.
    assert!(!code_guard_triggered("@Bean class C {}"));
    assert!(code_guard_triggered(
        &lex("class C { Object o = Class.forName(\"x\"); }").code
    ));
    // Comments and literals do not trigger; neither does a longer identifier.
    assert!(!code_guard_triggered(&lex("// @Bean forName\n").code));
    assert!(!code_guard_triggered(
        &lex("class C { String s = \"forName\"; }").code
    ));
    assert!(!code_guard_triggered("class C { int myforName = 1; }"));
    // Identifiers starting with `ScriptEngine` count.
    assert!(code_guard_triggered(
        "class C { Object m = new ScriptEngineManager(); }"
    ));

    let rel = "src/main/java/com/ex/Sealer.java";
    let p = project(&[(rel, &code)]);
    let r = p.reach(&[]);
    // No launcher `main` and no reference: the crypto line is not_observed.
    let v = p.classify(&r, rel, 7);
    assert_eq!(v.label, Label::NotObserved, "{:?}", v.reasons);
    assert_eq!(reasons(&v), ["no_textual_reference"]);
    assert_eq!(v.enclosing_function.as_deref(), Some("Sealer.seal"));
    // Every row stays within the rules: no panic, lines in range.
    let line_count = 10;
    for line in 1..=line_count {
        let label = p.classify(&r, rel, line).label;
        assert!(
            matches!(
                label,
                Label::Reachable | Label::NotObserved | Label::Unknown
            ),
            "line {line}"
        );
    }
}
