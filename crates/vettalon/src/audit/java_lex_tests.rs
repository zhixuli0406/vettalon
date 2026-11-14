use super::*;

/// The CR / LF characters of `s`, in order (line structure fingerprint).
fn breaks(s: &str) -> String {
    s.chars().filter(|&c| c == '\r' || c == '\n').collect()
}

fn ok(src: &str) -> JavaLexed {
    let l = lex(src);
    assert_eq!(l.ambiguity, None, "unexpected ambiguity for {src:?}");
    assert_eq!(
        breaks(&l.code),
        breaks(src),
        "line structure changed for {src:?}"
    );
    l
}

fn lits(l: &JavaLexed) -> Vec<(u32, &str)> {
    l.literals.iter().map(|(n, s)| (*n, s.as_str())).collect()
}

fn ambiguity(src: &str) -> Option<&'static str> {
    let l = lex(src);
    if l.ambiguity.is_some() {
        assert!(l.code.is_empty() && l.literals.is_empty() && !l.non_ascii_in_code);
    }
    l.ambiguity
}

#[test]
fn empty_input() {
    let l = ok("");
    assert_eq!(l.code, "");
    assert!(l.literals.is_empty());
}

#[test]
fn comments_blanked_and_lines_preserved() {
    let src = "int a; // hi\n/* x\r\n y */ int b;\r\nint c;\rint d; /*/ e */ f();\n";
    let l = ok(src);
    assert_eq!(l.code.chars().count(), src.chars().count());
    for kept in ["int a;", "int b;", "int c;", "int d;", "f();"] {
        assert!(l.code.contains(kept), "{kept} missing from {:?}", l.code);
    }
    assert!(!l.code.contains("hi") && !l.code.contains('x') && !l.code.contains('e'));
    assert!(!l.code.contains("//") && !l.code.contains("/*") && !l.code.contains("*/"));
    assert!(!l.non_ascii_in_code);
}

#[test]
fn string_with_escaped_quote() {
    let l = ok(r#"String s = "a\"b"; foo();"#);
    assert_eq!(l.code, r#"String s = "    "; foo();"#);
    assert_eq!(lits(&l), [(1, "a\"b")]);
}

#[test]
fn char_literal_escaped_quote() {
    let l = ok(r"char c = '\''; bar('x'); baz('/');");
    assert_eq!(l.code, "char c = '  '; bar(' '); baz(' ');");
    // char literals are not recorded
    assert!(l.literals.is_empty());
}

#[test]
fn comment_markers_inside_literals_are_content() {
    let l = ok("String s = \"// not a comment /* \"; g(); char c = '*'; h();");
    assert!(l.code.contains("g();") && l.code.contains("h();"));
    assert_eq!(lits(&l), [(1, "// not a comment /* ")]);
}

#[test]
fn text_block_multiline_with_escapes() {
    let src = r#"String t = """
    first \"""
    second \
    third
    """; x();
String u = "after";
"#;
    let l = ok(src);
    assert!(l.code.starts_with("String t = \"\"\"\n"));
    assert!(l.code.contains("    \"\"\"; x();\n"));
    assert!(!l.code.contains("first") && !l.code.contains("second") && !l.code.contains("third"));
    assert_eq!(
        lits(&l),
        [(1, "first \"\"\"\nsecond third\n"), (6, "after")]
    );
}

#[test]
fn text_block_crlf_and_close_on_content_line() {
    let l = ok("var a = \"\"\"  \r\n  abc  \r\n    def\"\"\"; y();");
    assert_eq!(lits(&l), [(1, "abc\n  def")]);
    assert!(l.code.ends_with("\"\"\"; y();"));
}

#[test]
fn text_block_must_open_with_line_terminator() {
    assert_eq!(
        ambiguity(r#"String s = """abc""";"#),
        Some("text_block_invalid_open")
    );
    assert_eq!(
        ambiguity(r#"String s = """"#),
        Some("text_block_invalid_open")
    );
}

#[test]
fn literal_table_lines_and_decoded_values() {
    let src = "class A {\n  void f() throws Exception {\n    Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n    String o = \"\\t\\101\\0\\377\\s\";\n  }\n}\n";
    let l = ok(src);
    assert_eq!(lits(&l), [(3, "AES/GCM/NoPadding"), (4, "\tA\0\u{ff} ")]);
    let blanked = format!(
        "Cipher.getInstance(\"{}\");",
        " ".repeat("AES/GCM/NoPadding".len())
    );
    assert!(l.code.contains(&blanked));
}

#[test]
fn literal_lines_count_cr_lf_and_crlf() {
    let src = "a\r\"one\";\r\n\"two\";\n/*\n*/\"three\";\r\r\"four\";";
    let l = ok(src);
    assert_eq!(
        lits(&l),
        [(2, "one"), (3, "two"), (5, "three"), (7, "four")]
    );
}

#[test]
fn unicode_escape_newline_in_comment_is_structural() {
    assert_eq!(
        ambiguity("// \\u000a evil();\nclass A {}\n"),
        Some("unicode_escape_structural")
    );
}

#[test]
fn every_structural_escape_is_refused() {
    for esc in [
        "000a", "000d", "0022", "0027", "005c", "002f", "002a", "005C", "002F",
    ] {
        let src = format!("int a = 1; /* \\u{esc} */\n");
        assert_eq!(ambiguity(&src), Some("unicode_escape_structural"), "{esc}");
        let src = format!("x\\uuu{esc}");
        assert_eq!(ambiguity(&src), Some("unicode_escape_structural"), "{esc}");
    }
}

#[test]
fn even_backslash_run_is_not_an_escape() {
    // Two backslashes: the second is not eligible, so no escape.
    let l = ok(r#"String s = "\\u0041";"#);
    assert_eq!(lits(&l), [(1, r"\u0041")]);
    // Three: the third is preceded by two, so it starts an escape.
    let l = ok(r#"String s = "\\\u0041";"#);
    assert_eq!(lits(&l), [(1, r"\A")]);
    // Two backslashes before `\u000a` in a comment: not an escape, not structural.
    ok("// \\\\u000a\nint a;\n");
}

#[test]
fn escapes_translated_in_code_and_literals() {
    let l = ok(r"int \uuuu0041 = 1; void m\u0061in() {}");
    assert_eq!(l.code, "int A = 1; void main() {}");
    assert!(!l.non_ascii_in_code);
    let l = ok(r#"String s = "\u0041\u0042";"#);
    assert_eq!(lits(&l), [(1, "AB")]);
}

#[test]
fn surrogate_escapes() {
    let l = ok(r#"String s = "\uD83D\uDE00"; String t = "\uD800x";"#);
    assert_eq!(lits(&l), [(1, "\u{1F600}"), (1, "\u{fffd}x")]);
    assert!(!l.non_ascii_in_code);
}

#[test]
fn invalid_unicode_escapes() {
    for src in [
        r"int \u00G1;",
        r"// C:\users\x",
        r"x\u",
        r"x\uuu",
        r"x\u004",
        r"x\u004 1",
    ] {
        assert_eq!(ambiguity(src), Some("unicode_escape_invalid"), "{src}");
    }
}

#[test]
fn unterminated_constructs_are_ambiguous() {
    assert_eq!(ambiguity("int a; /* abc"), Some("unterminated_comment"));
    assert_eq!(ambiguity("int a; /*/"), Some("unterminated_comment"));
    assert_eq!(
        ambiguity("String s = \"abc\nfoo\";"),
        Some("unterminated_string")
    );
    assert_eq!(
        ambiguity("String s = \"abc\rfoo\";"),
        Some("unterminated_string")
    );
    assert_eq!(ambiguity("String s = \"abc\\"), Some("unterminated_string"));
    assert_eq!(
        ambiguity("String s = \"abc\\\nx\";"),
        Some("unterminated_string")
    );
    assert_eq!(ambiguity("char c = 'a"), Some("unterminated_char"));
    assert_eq!(ambiguity("char c = '\n';"), Some("unterminated_char"));
    assert_eq!(
        ambiguity("String t = \"\"\"\nabc\n"),
        Some("unterminated_text_block")
    );
    assert_eq!(
        ambiguity("String t = \"\"\"\nabc\\\"\"\""),
        Some("unterminated_text_block")
    );
    assert_eq!(
        ambiguity("String t = \"\"\"\nabc\\"),
        Some("unterminated_text_block")
    );
}

#[test]
fn leading_bom_dropped_once() {
    let l = ok("\u{feff}class A {}");
    assert_eq!(l.code, "class A {}");
    assert!(!l.non_ascii_in_code);
    let l = ok("\u{feff}\u{feff}class A {}");
    assert_eq!(l.code, "\u{feff}class A {}");
    assert!(l.non_ascii_in_code);
}

#[test]
fn non_ascii_flag_only_for_code() {
    assert!(ok("int café = 1;").non_ascii_in_code);
    assert!(ok(r"int caf\u00e9 = 1;").non_ascii_in_code);
    // JLS 3.8 ignorable control characters inside an identifier
    assert!(ok("void ma\u{0}in() {}").non_ascii_in_code);
    assert!(ok("void ma\u{7f}in() {}").non_ascii_in_code);
    let quiet = "int a = 1; // café\n/* ü */ String s = \"naïve\"; char c = 'é';\nString t = \"\"\"\n  ç\n  \"\"\";\tint\u{c}b;\r\n";
    let l = ok(quiet);
    assert!(!l.non_ascii_in_code);
    assert_eq!(lits(&l), [(2, "naïve"), (3, "ç\n")]);
}

#[test]
fn long_u_runs_are_linear() {
    let unit = format!("\\{}0041", "u".repeat(1000));
    let count = (1 << 20) / unit.len() + 1;
    let src = unit.repeat(count);
    let start = std::time::Instant::now();
    let l = ok(&src);
    assert_eq!(l.code, "A".repeat(count));
    // The same runs without hex digits fail fast.
    let bad = format!("\\{}", "u".repeat(1000)).repeat(count);
    assert_eq!(ambiguity(&bad), Some("unicode_escape_invalid"));
    // Long backslash runs.
    let slashes = format!("String s = \"{}\";", "\\\\".repeat(500_000));
    assert_eq!(ok(&slashes).literals[0].1, "\\".repeat(MAX_LITERAL_CHARS));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(2),
        "took {:?}",
        start.elapsed()
    );
}

#[test]
fn literals_clipped_on_char_boundary() {
    let l = ok(&format!("String s = \"{}\";", "x".repeat(300)));
    assert_eq!(l.literals[0].1, "x".repeat(MAX_LITERAL_CHARS));
    let l = ok(&format!("String s = \"{}\";", "é".repeat(300)));
    assert_eq!(l.literals[0].1, "é".repeat(MAX_LITERAL_CHARS));
    let l = ok(&format!("String t = \"\"\"\n{}\"\"\";", "ab\n".repeat(300)));
    assert_eq!(l.literals[0].1.chars().count(), MAX_LITERAL_CHARS);
}

#[test]
fn literal_count_capped() {
    let l = ok(&"\"a\";".repeat(MAX_LITERALS));
    assert_eq!(l.literals.len(), MAX_LITERALS);
    assert!(!l.literals_truncated);
    let l = ok(&"\"a\";".repeat(MAX_LITERALS + 1));
    assert_eq!(l.literals.len(), MAX_LITERALS);
    assert!(l.literals_truncated);
}
