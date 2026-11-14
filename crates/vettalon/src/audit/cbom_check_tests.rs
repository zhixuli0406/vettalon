use super::*;

fn fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/cbom");
    (base.join("sample-py.cbomkit.json"), base.join("sample-py"))
}

/// Write a CBOM with one algorithm component and the given occurrences
/// (JSON objects) into `dir`.
fn cbom_with(dir: &Path, name: &str, occurrences: &str) -> std::path::PathBuf {
    let p = dir.join("cbom.json");
    let doc = format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{{"bom-ref":"x","name":"{name}","cryptoProperties":{{"assetType":"algorithm"}},"evidence":{{"occurrences":[{occurrences}]}}}}]}}"#
    );
    std::fs::write(&p, doc).unwrap();
    p
}

#[test]
fn fixture_labels() {
    let (cbom, root) = fixture();
    let r = run(&cbom, &root, &[]).unwrap();
    let row = |name: &str, line: u32| {
        r.rows
            .iter()
            .find(|x| {
                x.line == Some(line) && x.name.as_deref().is_some_and(|n| n.starts_with(name))
            })
            .unwrap_or_else(|| panic!("{name}:{line}"))
    };
    assert_eq!(row("RSA-2048", 8).label, Label::Reachable);
    assert_eq!(row("private-key@c20c", 8).label, Label::Reachable);
    assert_eq!(row("EC-secp256r1", 13).label, Label::NotObserved);
    assert_eq!(row("private-key@2a81", 13).label, Label::NotObserved);
    // `encrypt` is never called, but `AESGCM(key).encrypt(...)` is a textual
    // reference to the name: `unknown`, never `not_observed`.
    for name in ["AES-256-GCM", "secret-key@6385"] {
        let aes = row(name, 17);
        assert_eq!(aes.label, Label::Unknown, "{name}");
        assert_eq!(aes.reasons, ["referenced_but_no_entry_path"], "{name}");
        assert_eq!(aes.enclosing_function.as_deref(), Some("encrypt"));
    }
    assert_eq!(r.summary.total_rows, 6);
    assert_eq!(r.summary.by_label["not_observed"], 2);
    assert_eq!(r.summary.by_label["unknown"], 2);
    assert!(r.project.not_observed_blocked.is_empty());
    assert_eq!(r.project.languages, ["python"]);
    assert_eq!((r.project.py_files, r.project.java_files), (3, 0));
    assert!(!r.project.reflection_detected);
    assert!(!r.project.dynamic_dispatch_detected);
    let rsa = r
        .rows
        .iter()
        .find(|x| x.name.as_deref() == Some("RSA-2048"))
        .unwrap();
    assert_eq!(
        rsa.chain,
        [
            "app/main.py:<__main__>",
            "app/main.py:main",
            "app/keys.py:make_signing_key"
        ]
    );
    // CBOMkit's single `ws/` prefix needs no reason
    assert_eq!(rsa.reasons, ["name_based_chain_from_entry"]);
    assert_eq!(rsa.quantum_vulnerable, Some(true));
    assert_eq!(r.compute_hash().unwrap(), r.receipt_sha256);
    assert!(r.cbom.notes.is_empty());
}

#[test]
fn hash_ignores_timestamp_only() {
    let (cbom, root) = fixture();
    let mut a = run(&cbom, &root, &[]).unwrap();
    let b = run(&cbom, &root, &[]).unwrap();
    a.generated_at = "2000-01-01T00:00:00Z".into();
    assert_eq!(a.compute_hash().unwrap(), b.receipt_sha256);
    a.rows[0].label = Label::Unknown;
    a.rows[0].reasons.push("x".into());
    assert_ne!(a.compute_hash().unwrap(), b.receipt_sha256);
}

#[test]
fn canonical_json_sorts_keys() {
    let src = r#"{"b":1,"a":{"d":[{"z":1,"y":2}],"c":null}}"#;
    let v: Value = serde_json::from_str(src).unwrap();
    assert_eq!(
        canonical_json(&v).unwrap(),
        r#"{"a":{"c":null,"d":[{"y":2,"z":1}]},"b":1}"#
    );
}

/// The streamed hash is the SHA-256 of the documented canonical form (the
/// whole receipt as a key-sorted `Value`), with and without optional parts.
#[test]
fn streamed_hash_matches_the_value_canonical_form() {
    let (cbom, root) = fixture();
    let mut r = run(&cbom, &root, &[]).unwrap();
    let reference = |r: &Receipt| {
        let mut v = serde_json::to_value(r).unwrap();
        let m = v.as_object_mut().unwrap();
        m.remove("receipt_sha256");
        m.remove("generated_at");
        hex::encode(Sha256::digest(canonical_json(&v).unwrap().as_bytes()))
    };
    assert_eq!(r.compute_hash().unwrap(), reference(&r));
    r.cbom.notes = vec![NOTE_DEPENDENCIES_TRUNCATED.into()];
    r.entries = vec!["a.b:c".into(), "\"quoted\"\u{1}".into()];
    r.rows[0].chain = vec!["é\u{2028}".into()];
    assert_eq!(r.compute_hash().unwrap(), reference(&r));
    r.rows.clear();
    assert_eq!(r.compute_hash().unwrap(), reference(&r));
}

#[test]
fn row_string_budget_clips_further_copies() {
    let (mut budget, mut clipped) = (10usize, false);
    let long = "x".repeat(40);
    assert_eq!(
        budget_copy(Some("abcd"), &mut budget, &mut clipped).as_deref(),
        Some("abcd")
    );
    assert_eq!((budget, clipped), (6, false));
    assert_eq!(budget_copy(None, &mut budget, &mut clipped), None);
    // does not fit: the budget is spent and the copy clipped
    let c = budget_copy(Some(&long), &mut budget, &mut clipped).unwrap();
    assert_eq!(c.chars().count(), BUDGET_CLIP_CHARS + 1);
    assert!(c.ends_with('…'));
    assert_eq!((budget, clipped), (0, true));
    // a short value after that is kept whole and is not "clipped"
    let mut later = false;
    assert_eq!(
        budget_copy(Some("RSA"), &mut budget, &mut later).as_deref(),
        Some("RSA")
    );
    assert!(!later);
    // a row records the reason
    let comp = cbom::Component {
        name: Some(long.clone()),
        ..cbom::Component::default()
    };
    let (row, clipped) = new_row(&comp, None, None, Some("ctx"), &mut 4);
    assert!(clipped);
    assert_eq!(row.symbol.as_deref(), Some("ctx"));
    assert_eq!(
        row.name.as_deref().unwrap().chars().count(),
        BUDGET_CLIP_CHARS + 1
    );
    assert_eq!(
        budget_note(clipped).as_deref(),
        Some("cbom_value_clipped:budget")
    );
}

#[test]
fn truncated_dependencies_are_a_document_note() {
    let (_, root) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let refs = vec![r#""a""#; 1025].join(",");
    let doc = format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{{"bom-ref":"x","name":"RSA","cryptoProperties":{{"assetType":"algorithm"}},"evidence":{{"occurrences":[{{"location":"ws/app/keys.py","line":8}}]}}}}],"dependencies":[{{"ref":"x","dependsOn":[{refs}]}}]}}"#
    );
    let p = dir.path().join("cbom.json");
    std::fs::write(&p, doc).unwrap();
    let r = run(&p, &root, &[]).unwrap();
    assert_eq!(r.cbom.notes, [NOTE_DEPENDENCIES_TRUNCATED]);
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["cbom"]["notes"][0], NOTE_DEPENDENCIES_TRUNCATED);
    assert!(render(&r).contains("CBOM note: cbom_dependencies_truncated"));
    // without truncation the key is absent (the receipt shape is unchanged)
    let (cbom, root) = fixture();
    let v = serde_json::to_value(run(&cbom, &root, &[]).unwrap()).unwrap();
    assert!(v["cbom"].get("notes").is_none());
}

#[test]
fn render_carries_the_honesty_note() {
    let (cbom, root) = fixture();
    let text = render(&run(&cbom, &root, &[]).unwrap());
    assert!(text.contains("NOT proof"));
    assert!(text.contains("no VEX is emitted"));
    assert!(text.contains("experimental"));
}

#[test]
fn render_neutralises_bidi_and_caps_columns() {
    let (cbom, root) = fixture();
    let mut r = run(&cbom, &root, &[]).unwrap();
    let hostile = "a\u{202E}b\u{2066}c\u{200F}d\u{061C}e\u{FEFF}f\u{1b}g";
    r.rows[0].enclosing_function = Some(hostile.into());
    r.rows[1].enclosing_function = Some("w".repeat(500));
    let text = render(&r);
    assert!(text.contains("a?b?c?d?e?f?g"), "{text}");
    for bad in [
        '\u{202E}', '\u{2066}', '\u{200F}', '\u{061C}', '\u{FEFF}', '\u{1b}',
    ] {
        assert!(!text.contains(bad), "{bad:?}");
    }
    let clipped = format!("{}…", "w".repeat(MAX_COLUMN_CHARS - 1));
    assert!(text.contains(&clipped));
    assert!(!text.contains(&"w".repeat(MAX_COLUMN_CHARS)));
    assert_eq!(
        clean(&"x".repeat(MAX_COLUMN_CHARS)).chars().count(),
        MAX_COLUMN_CHARS
    );
    assert_eq!(clean("short"), "short");
}

#[test]
fn location_too_long_is_unknown() {
    let (_, root) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let long = format!("{}app/keys.py", "a/".repeat(2100));
    let deep = format!("{}app/keys.py", "a/".repeat(70));
    let p = cbom_with(
        dir.path(),
        "RSA",
        &format!(r#"{{"location":"{long}","line":8}},{{"location":"{deep}","line":8}}"#),
    );
    let r = run(&p, &root, &[]).unwrap();
    assert_eq!(r.rows.len(), 2);
    for row in &r.rows {
        assert_eq!(row.label, Label::Unknown);
        assert_eq!(row.reasons, ["location_too_long"]);
    }
    // the shown location is clipped
    assert!(r.rows[1].file.as_ref().unwrap().chars().count() <= MAX_STRING_CHARS + 1);
}

#[test]
fn deep_suffix_stripping_is_reported() {
    let (_, root) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let p = cbom_with(
        dir.path(),
        "RSA",
        r#"{"location":"x/y/app/keys.py","line":8},{"location":"ws/app/keys.py","line":8},{"location":"x/y/app/keys.py","line":8}"#,
    );
    let r = run(&p, &root, &[]).unwrap();
    assert_eq!(r.rows[0].file.as_deref(), Some("app/keys.py"));
    assert_eq!(r.rows[0].label, Label::Reachable);
    assert!(
        r.rows[0]
            .reasons
            .contains(&"path_suffix_stripped:2".to_string())
    );
    assert!(
        !r.rows[1]
            .reasons
            .iter()
            .any(|x| x.starts_with("path_suffix"))
    );
    // the cached mapping gives the same answer
    assert_eq!(r.rows[2].reasons, r.rows[0].reasons);
}

#[test]
fn clipped_cbom_values_are_reported() {
    let (_, root) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let long = "N".repeat(1000);
    let p = cbom_with(
        dir.path(),
        &long,
        r#"{"location":"ws/app/keys.py","line":8}"#,
    );
    let r = run(&p, &root, &[]).unwrap();
    let row = &r.rows[0];
    assert_eq!(
        row.name.as_deref().unwrap().chars().count(),
        MAX_STRING_CHARS + 1
    );
    assert!(row.reasons.contains(&"cbom_value_clipped:name".to_string()));
    assert_eq!(row.label, Label::Reachable);
}

#[test]
fn total_occurrence_cap_is_an_error() {
    let (_, root) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let occ = r#"{"location":"a.py","line":1}"#;
    let occs = vec![occ; cbom::MAX_OCCURRENCES].join(",");
    let comp = format!(r#"{{"cryptoProperties":{{}},"evidence":{{"occurrences":[{occs}]}}}}"#);
    let n = cbom::MAX_TOTAL_OCCURRENCES / cbom::MAX_OCCURRENCES + 1;
    let doc = format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{}]}}"#,
        vec![comp; n].join(",")
    );
    let p = dir.path().join("big.json");
    std::fs::write(&p, doc).unwrap();
    let e = run(&p, &root, &[]).unwrap_err();
    assert!(e.contains("200000 occurrences"), "{e}");
}

#[test]
fn write_receipt_refuses_to_overwrite_and_leaves_no_temp_file() {
    let (cbom, root) = fixture();
    let r = run(&cbom, &root, &[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("receipt.json");
    write_receipt(&out, &r).unwrap();
    let first = std::fs::read_to_string(&out).unwrap();
    assert!(first.ends_with("}\n"));
    let e = write_receipt(&out, &r).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), first);
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["receipt.json"]);
    // a missing directory is an error, not a panic
    assert!(write_receipt(&dir.path().join("nope/r.json"), &r).is_err());
    // the streamed file is the pretty JSON of the receipt
    let parsed: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(parsed, serde_json::to_value(&r).unwrap());
}

#[test]
fn write_receipt_clips_the_temp_name_for_long_output_names() {
    let (cbom, root) = fixture();
    let r = run(&cbom, &root, &[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    // 240 bytes, with a multi-byte character straddling the clip point
    let name = format!("{}\u{e9}{}.json", "a".repeat(216), "b".repeat(17));
    assert_eq!(name.len(), 240);
    let out = dir.path().join(&name);
    // skip on filesystems that reject a 240-byte name outright
    if std::fs::write(&out, "probe").is_err() {
        return;
    }
    std::fs::remove_file(&out).unwrap();
    write_receipt(&out, &r).unwrap();
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, [name]);
    assert!(std::fs::read_to_string(&out).unwrap().ends_with("}\n"));
}

/// The fallback used where hard links fail: atomic, never replaces.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn rename_no_replace_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    let c = dir.path().join("c");
    std::fs::write(&a, "new").unwrap();
    std::fs::write(&b, "keep").unwrap();
    match rename_no_replace(&a, &b) {
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return,
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
        Ok(()) => panic!("replaced an existing file"),
    }
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "keep");
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "new");
    rename_no_replace(&a, &c).unwrap();
    assert_eq!(std::fs::read_to_string(&c).unwrap(), "new");
    assert!(!a.exists());
}

// ---- Java / mixed projects ----------------------------------------------------

fn write_tree(dir: &Path, files: &[(&str, &str)]) {
    for (rel, text) in files {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
}

const MAIN_JAVA: &str = "package com.ex;\n\npublic class Main {\n    public static void main(String[] a) throws Exception {\n        new Crypto().seal(null);\n    }\n}\n";
const CRYPTO_JAVA: &str = "package com.ex;\n\npublic class Crypto {\n    public byte[] seal(byte[] d) throws Exception {\n        Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n        return c.doFinal(d);\n    }\n}\n";
const UNUSED_JAVA: &str = "package com.ex;\n\npublic class Unused {\n    public void legacy() throws Exception {\n        MessageDigest.getInstance(\"MD5\");\n    }\n}\n";
const APP_PY: &str = "import hashlib\n\ndef used():\n    hashlib.sha256()\n\nused()\n";

fn occ(file: &str, line: u32) -> String {
    format!(r#"{{"location":"{file}","line":{line}}}"#)
}

#[test]
fn mixed_python_and_java_project() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("proj");
    write_tree(
        &root,
        &[
            ("app.py", APP_PY),
            ("src/main/java/com/ex/Main.java", MAIN_JAVA),
            ("src/main/java/com/ex/Crypto.java", CRYPTO_JAVA),
            ("src/main/java/com/ex/Unused.java", UNUSED_JAVA),
        ],
    );
    let occs = [
        occ("app.py", 4),
        occ("src/main/java/com/ex/Crypto.java", 5),
        occ("src/main/java/com/ex/Unused.java", 5),
    ]
    .join(",");
    let cbom = cbom_with(dir.path(), "X", &occs);
    let r = run(&cbom, &root, &[]).unwrap();
    assert_eq!(r.schema, "vettalon.cbom-check/2");
    assert_eq!(r.project.languages, ["java", "python"]);
    assert_eq!((r.project.py_files, r.project.java_files), (1, 3));
    assert!(r.project.not_observed_blocked.is_empty());
    let labels: Vec<Label> = r.rows.iter().map(|x| x.label).collect();
    assert_eq!(
        labels,
        [Label::Reachable, Label::Reachable, Label::NotObserved]
    );
    assert!(r.rows.iter().all(|x| x.file_sha256.is_some()));
    assert_eq!(
        r.rows[1].chain,
        [
            "src/main/java/com/ex/Main.java:Main.main",
            "src/main/java/com/ex/Crypto.java:Crypto.seal"
        ]
    );
    assert_eq!(r.compute_hash().unwrap(), r.receipt_sha256);

    // the tree hash covers .java files
    std::fs::write(
        root.join("src/main/java/com/ex/Unused.java"),
        UNUSED_JAVA.replace("MD5", "SHA-1"),
    )
    .unwrap();
    let r2 = run(&cbom, &root, &[]).unwrap();
    assert_ne!(r.root_tree_sha256, r2.root_tree_sha256);
    assert_ne!(r.receipt_sha256, r2.receipt_sha256);
}

#[test]
fn unsupported_languages_are_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("proj");
    write_tree(
        &root,
        &[
            ("src/A.kt", "fun main() {}\n"),
            ("README", "x\n"),
            ("b.TXT", "x\n"),
        ],
    );
    let occs = [occ("src/A.kt", 1), occ("README", 1), occ("b.TXT", 1)].join(",");
    let cbom = cbom_with(dir.path(), "X", &occs);
    let r = run(&cbom, &root, &[]).unwrap();
    let reasons: Vec<&str> = r.rows.iter().map(|x| x.reasons[0].as_str()).collect();
    assert_eq!(
        reasons,
        [
            "unsupported_language:kt",
            "unsupported_language:none",
            "unsupported_language:txt"
        ]
    );
    assert!(r.rows.iter().all(|x| x.label == Label::Unknown));
    assert!(r.project.languages.is_empty());
}

#[test]
fn unsupported_language_ext_is_ascii_and_clipped() {
    assert_eq!(
        unsupported_language("a/b.ÄBCdefghijklmnopqrstuvwxyz"),
        "unsupported_language:?bcdefghijklmnop"
    );
    assert_eq!(unsupported_language("a.d/b"), "unsupported_language:none");
    assert_eq!(unsupported_language("b."), "unsupported_language:none");
}

#[test]
fn entries_resolve_in_either_language() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("proj");
    write_tree(
        &root,
        &[
            ("src/main/java/com/ex/Crypto.java", CRYPTO_JAVA),
            ("src/main/java/com/ex/Unused.java", UNUSED_JAVA),
            ("app.py", "def f():\n    pass\n"),
        ],
    );
    let cbom = cbom_with(dir.path(), "X", &occ("src/main/java/com/ex/Unused.java", 5));
    // no entry: Unused.legacy is not observed
    let r = run(&cbom, &root, &[]).unwrap();
    assert_eq!(r.rows[0].label, Label::NotObserved);
    // a Java entry makes it reachable; a Python entry resolves in Python only
    let specs = ["com.ex.Unused:legacy".to_string(), "app:f".to_string()];
    let r = run(&cbom, &root, &specs).unwrap();
    assert_eq!(r.rows[0].label, Label::Reachable);
    assert_eq!(r.rows[0].chain[0], "--entry com.ex.Unused:legacy");
    // a spec that resolves in neither is an error
    let err = run(&cbom, &root, &["com.ex.Nope:main".to_string()]).unwrap_err();
    assert!(err.contains("--entry"), "{err}");
}

#[test]
fn sweep_off_is_absent_and_python_only_is_explicit() {
    let (cbom, root) = fixture();
    let off = run(&cbom, &root, &[]).unwrap();
    let on = run_with_sweep(&cbom, &root, &[], &[], true).unwrap();
    assert!(serde_json::to_value(&off).unwrap().get("sweep").is_none());
    assert!(!render(&off).contains("sweep:"));
    assert!(on.sweep.as_ref().unwrap().is_empty());
    assert!(on.cbom.notes.iter().any(|n| n == "sweep_java_only"));
    assert_eq!(
        serde_json::to_value(&off.rows).unwrap(),
        serde_json::to_value(&on.rows).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&off.project).unwrap(),
        serde_json::to_value(&on.project).unwrap()
    );
}

#[test]
fn sweep_cross_file_constants_duplicates_mapping_labels_and_hash() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("src");
    write_tree(
        &root,
        &[
            (
                "Constants.java",
                "class Constants { static final String ALG = \"RSA\"; }",
            ),
            (
                "Main.java",
                "class Main { public static void main(String[] args) {\nCipher.getInstance(Constants.ALG);\n} }",
            ),
        ],
    );
    let cbom = cbom_with(dir.path(), "RSA", &occ("ws/Main.java", 2));
    let off = run(&cbom, &root, &[]).unwrap();
    let mut on = run_with_sweep(&cbom, &root, &[], &[], true).unwrap();
    let rows = on.sweep.as_ref().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].algorithm.as_deref(), Some("RSA"));
    assert_eq!(rows[0].quantum_vulnerable, Some(true));
    assert!(rows[0].in_cbom);
    assert_eq!(rows[0].label, off.rows[0].label);
    assert_eq!(
        serde_json::to_value(&off.rows).unwrap(),
        serde_json::to_value(&on.rows).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&off.project).unwrap(),
        serde_json::to_value(&on.project).unwrap()
    );
    let mut v = serde_json::to_value(&on).unwrap();
    v.as_object_mut().unwrap().remove("generated_at");
    v.as_object_mut().unwrap().remove("receipt_sha256");
    assert_eq!(
        hex::encode(Sha256::digest(canonical_json(&v).unwrap())),
        on.receipt_sha256
    );
    let hash = on.receipt_sha256.clone();
    on.sweep.as_mut().unwrap()[0].in_cbom = false;
    assert_ne!(on.compute_hash().unwrap(), hash);
    std::fs::write(
        root.join("Duplicate.java"),
        "class Constants { static final String ALG = \"AES\"; }",
    )
    .unwrap();
    let duplicate = run_with_sweep(&cbom, &root, &[], &[], true).unwrap();
    let row = &duplicate.sweep.as_ref().unwrap()[0];
    assert_eq!(row.algorithm, None);
    assert!(row.reasons.iter().any(|r| r == "algorithm_not_constant"));
}

#[test]
fn sweep_global_cap_across_files() {
    let dir = tempfile::tempdir().unwrap();
    let calls = "Cipher.getInstance(\"AES\");\n".repeat(17_000);
    for name in ["A", "B", "C"] {
        std::fs::write(
            dir.path().join(format!("{name}.java")),
            format!("class {name} {{ void crypto() {{\n{calls}}} }}"),
        )
        .unwrap();
    }
    let cbom = cbom_with(dir.path(), "X", "");
    let r = run_with_sweep(&cbom, dir.path(), &[], &[], true).unwrap();
    let rows = r.sweep.as_ref().unwrap();
    assert_eq!(rows.len(), MAX_SWEEP_ROWS);
    assert_eq!(
        rows.iter()
            .map(|r| r.file.as_str())
            .collect::<HashSet<_>>()
            .len(),
        3
    );
    assert!(r.cbom.notes.iter().any(|n| n == "sweep_truncated"));
}

#[test]
fn sweep_budget_clips_all_strings_and_keeps_file_notes() {
    let dir = tempfile::tempdir().unwrap();
    let file = format!("{}.java", "F".repeat(80));
    std::fs::write(dir.path().join(&file), format!(
        "import org.bouncycastle.jce.provider.BouncyCastleProvider; class F {{ void crypto() {{ Security.addProvider(new BouncyCastleProvider()); Cipher.getInstance(\"{}\", \"{}\"); }} }}",
        "A".repeat(100), "P".repeat(100),
    )).unwrap();
    let java = JavaProject::load_for_sweep(dir.path(), &[], true);
    let mut budget = 0;
    let mut notes = Vec::new();
    let rows = build_sweep(
        &java,
        &java.reach(&[]),
        &HashSet::new(),
        &mut budget,
        MAX_SWEEP_ROWS,
        &mut notes,
    );
    assert_eq!(rows.len(), 1);
    assert!(rows[0].file.chars().count() <= BUDGET_CLIP_CHARS + 1);
    assert!(rows[0].algorithm.as_ref().unwrap().chars().count() <= BUDGET_CLIP_CHARS + 1);
    assert!(rows[0].provider.as_ref().unwrap().chars().count() <= BUDGET_CLIP_CHARS + 1);
    assert!(
        rows[0]
            .reasons
            .iter()
            .any(|r| r == "cbom_value_clipped:budget")
    );
    assert!(!notes.is_empty());
}

#[test]
fn sweep_file_reason_survives_zero_rows() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Broken.java"), "class Broken { /*").unwrap();
    let cbom = cbom_with(dir.path(), "X", "");
    let r = run_with_sweep(&cbom, dir.path(), &[], &[], true).unwrap();
    assert!(r.sweep.as_ref().unwrap().is_empty());
    assert!(
        r.cbom
            .notes
            .iter()
            .any(|n| n.contains("Broken.java:unterminated_comment"))
    );
}

#[test]
fn sweep_family_normalizer_requires_token_boundaries() {
    for (name, expected) in [
        ("PBKDF2WithHmacSHA256", "PBKDF2"),
        ("HmacSHA3-256", "HMAC"),
        ("Kyber768", "ML-KEM"),
        ("MLKEM", "ML-KEM"),
        ("Dilithium", "ML-DSA"),
        ("SLHDSA", "SLH-DSA"),
        ("SPHINCS+", "SLH-DSA"),
        ("Triple-DES", "3DES"),
        ("DESede", "3DES"),
        ("TDEA", "3DES"),
        ("DES/CBC", "DES"),
        ("DESIGN", "other:DESIGN"),
        ("Rijndael", "AES"),
        ("ChaCha20-Poly1305", "ChaCha20"),
        ("SHA256withRSA", "RSA"),
        ("SHA256withECDSA", "ECDSA"),
        ("ECDH", "ECDH"),
        ("EC", "EC"),
        ("secp256r1", "EC"),
        ("ECC", "other:ECC"),
        ("DH", "DH"),
        ("DiffieHellman", "DH"),
        ("DHE", "other:DHE"),
        ("DSA", "DSA"),
        ("Ed25519", "EdDSA"),
        ("MD5", "MD5"),
        ("SHA1", "SHA-1"),
        ("SHA-1", "SHA-1"),
        ("SHA128", "other:SHA128"),
        ("SHA256", "SHA-2"),
        ("SHA-384", "SHA-2"),
        ("SHA384", "SHA-2"),
        ("SHA-512/256", "SHA-2"),
        ("SHA3_384", "SHA-3"),
        ("NOTRSA", "other:NOTRSA"),
        ("FAKEAES", "other:FAKEAES"),
        ("SHA256withNOTRSA", "other:SHA256WITHNOTRSA"),
        ("SHA3FAKE", "other:SHA3FAKE"),
        ("SHA256withRSA", "RSA"),
        ("SHA-256withRSA", "RSA"),
        ("SHA512", "SHA-2"),
        ("SHA3-256", "SHA-3"),
        ("Keccak256", "SHA-3"),
        (" other:aes ", "AES"),
        ("unknown", "other:UNKNOWN"),
    ] {
        assert_eq!(algorithm_family(name).as_deref(), Some(expected), "{name}");
    }
    assert_eq!(algorithm_family("  "), None);
}

#[test]
fn sweep_cbom_matching_requires_location_and_family() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Main.java"), "class Main { void f() { Cipher.getInstance(\"AES/GCM/NoPadding\"); MessageDigest.getInstance(\"SHA-256\"); Cipher.getInstance(dynamic); } }").unwrap();
    let cbom = cbom_with(dir.path(), "Rijndael", &occ("Main.java", 1));
    let receipt = run_with_sweep(&cbom, dir.path(), &[], &[], true).unwrap();
    let rows = receipt.sweep.unwrap();
    assert!(rows[0].in_cbom);
    for row in &rows[1..] {
        assert!(!row.in_cbom);
        assert!(row.reasons.iter().any(|r| r == "cbom_location_only_match"));
    }
    let cbom = cbom_with(dir.path(), "", &occ("Main.java", 1));
    let receipt = run_with_sweep(&cbom, dir.path(), &[], &[], true).unwrap();
    for row in receipt.sweep.unwrap() {
        assert!(!row.in_cbom);
        assert!(row.reasons.iter().any(|r| r == "cbom_location_only_match"));
    }
}

#[test]
fn sweep_retention_budget_counts_empty_literal_entries_and_keeps_ambiguity_notes() {
    let dir = tempfile::tempdir().unwrap();
    let source = format!("class A {{ void f() {{ {} }} }}", "\"\";".repeat(100));
    std::fs::write(dir.path().join("A.java"), &source).unwrap();
    std::fs::write(
        dir.path().join("B.java"),
        source.replace("class A", "class B"),
    )
    .unwrap();
    std::fs::write(dir.path().join("Broken.java"), "class Broken { /*").unwrap();
    std::fs::write(dir.path().join("Parser.java"), "class Parser {").unwrap();
    let lexed = super::super::java_lex::lex(&source);
    let cost = lexed.code.capacity()
        + lexed.literals.capacity() * std::mem::size_of::<(u32, String)>()
        + lexed
            .literals
            .iter()
            .map(|(_, s)| s.capacity())
            .sum::<usize>();
    assert!(cost > source.len() * 2);
    let java = JavaProject::load_for_sweep_with_budget(dir.path(), &[], true, cost);
    assert_eq!(java.file_count(), 4);
    assert_eq!(java.sweep_files().count(), 1);
    assert_eq!(java.sweep_files().next().unwrap().0, "A.java");
    let mut notes = Vec::new();
    let mut budget = usize::MAX;
    build_sweep(
        &java,
        &java.reach(&[]),
        &HashSet::new(),
        &mut budget,
        MAX_SWEEP_ROWS,
        &mut notes,
    );
    assert!(
        notes
            .iter()
            .any(|s| s == "sweep:B.java:sweep_memory_limit_exceeded")
    );
    assert!(
        notes
            .iter()
            .any(|s| s == "sweep:Broken.java:unterminated_comment")
    );
    assert!(
        notes
            .iter()
            .any(|s| s == "sweep:Parser.java:unbalanced_braces")
    );
    assert!(notes.iter().any(|s| s == "sweep_truncated"));
    let java = JavaProject::load_for_sweep_with_budget(dir.path(), &[], true, cost - 1);
    assert_eq!(java.sweep_files().count(), 0);
}

#[test]
fn sweep_exact_global_cap_is_not_truncated_without_another_match() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["A", "B"] {
        std::fs::write(
            dir.path().join(format!("{name}.java")),
            format!(
                "class {name} {{ void f() {{ {} }} }}",
                "Cipher.getInstance(\"AES\");".repeat(MAX_SWEEP_ROWS / 2),
            ),
        )
        .unwrap();
    }
    std::fs::write(
        dir.path().join("Z.java"),
        "class Z { void f() { harmless(); } }",
    )
    .unwrap();
    let cbom = cbom_with(dir.path(), "X", "");
    let receipt = run_with_sweep(&cbom, dir.path(), &[], &[], true).unwrap();
    assert_eq!(receipt.sweep.unwrap().len(), MAX_SWEEP_ROWS);
    assert!(!receipt.cbom.notes.iter().any(|n| n == "sweep_truncated"));
    std::fs::write(
        dir.path().join("Z.java"),
        "class Z { void f() { Cipher.getInstance(\"AES\"); } }",
    )
    .unwrap();
    let receipt = run_with_sweep(&cbom, dir.path(), &[], &[], true).unwrap();
    assert_eq!(receipt.sweep.unwrap().len(), MAX_SWEEP_ROWS);
    assert!(receipt.cbom.notes.iter().any(|n| n == "sweep_truncated"));
}

fn sweep_with_primitive(source: &str, name: &str, primitive: &str) -> Vec<SweepRow> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Main.java"), source).unwrap();
    let path = cbom_with(dir.path(), name, &occ("Main.java", 1));
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    doc["components"][0]["cryptoProperties"]["algorithmProperties"] =
        serde_json::json!({ "primitive": primitive });
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
    run_with_sweep(&path, dir.path(), &[], &[], true)
        .unwrap()
        .sweep
        .unwrap()
}

#[test]
fn sweep_signature_cannot_mask_cipher_on_same_line() {
    let rows = sweep_with_primitive(
        r#"class Main { void f() { Signature.getInstance("SHA256withRSA"); Cipher.getInstance("RSA"); } }"#,
        "SHA256withRSA",
        "signature",
    );
    assert_eq!(rows.len(), 2);
    assert!(rows[0].in_cbom);
    assert!(!rows[1].in_cbom);
    assert!(
        rows[1]
            .reasons
            .iter()
            .any(|r| r == "cbom_location_only_match")
    );
}

#[test]
fn sweep_sha3_cannot_mask_sha384_on_same_line() {
    let rows = sweep_with_primitive(
        r#"class Main { void f() { MessageDigest.getInstance("SHA3-256"); MessageDigest.getInstance("SHA-384"); } }"#,
        "SHA3-256",
        "hash",
    );
    assert_eq!(rows.len(), 2);
    assert!(rows[0].in_cbom);
    assert!(!rows[1].in_cbom);
    assert!(
        rows[1]
            .reasons
            .iter()
            .any(|r| r == "cbom_location_only_match")
    );
}

#[test]
fn sweep_aes_block_cipher_matches_transformation() {
    let rows = sweep_with_primitive(
        r#"class Main { void f() { Cipher.getInstance("AES/GCM/NoPadding"); } }"#,
        "AES-128-GCM",
        "block-cipher",
    );
    assert_eq!(rows.len(), 1);
    assert!(rows[0].in_cbom);
}

#[test]
fn sweep_unknown_family_requires_exact_name_and_known_kinds() {
    let source = r#"class Main { void f() { Cipher.getInstance("FAKEAES"); Cipher.getInstance("NOTRSA"); } }"#;
    let rows = sweep_with_primitive(source, "fakeaes", "block-cipher");
    assert_eq!(rows.len(), 2);
    assert!(rows[0].in_cbom);
    assert!(!rows[1].in_cbom);
    for primitive in ["other", "unknown", "keygen"] {
        let rows = sweep_with_primitive(source, "FAKEAES", primitive);
        for row in rows {
            assert!(!row.in_cbom);
            assert!(row.reasons.iter().any(|r| r == "cbom_location_only_match"));
        }
    }
    let rows = sweep_with_primitive(source, "AES", "block-cipher");
    assert!(rows.iter().all(|r| !r.in_cbom));
}

#[test]
fn sweep_kind_mapping_and_unknown_kind_fallback() {
    for (api, kind) in [
        ("Cipher.getInstance", "cipher"),
        ("Signature.getInstance", "signature"),
        ("bc:RSADigestSigner", "signature"),
        ("MessageDigest.getInstance", "digest"),
        ("bc:SHA384Digest", "digest"),
        ("Mac.getInstance", "mac"),
        ("bc:HMac", "mac"),
        ("bc:CMac", "mac"),
        ("KeyPairGenerator.getInstance", "keygen"),
        ("KeyGenerator.getInstance", "keygen"),
        ("KeyFactory.getInstance", "keygen"),
        ("SecretKeyFactory.getInstance", "keygen"),
        ("bc:MLKEMKeyPairGenerator", "keygen"),
        ("KeyAgreement.getInstance", "key-agree"),
        ("bc:ECDHBasicAgreement", "key-agree"),
        ("KEM.getInstance", "kem"),
        ("bc:MLKEMGenerator", "kem"),
        ("IvParameterSpec", "other"),
    ] {
        assert_eq!(sweep_kind(api), kind, "{api}");
    }
    for primitive in ["block-cipher", "stream-cipher", "ae", "pke"] {
        assert_eq!(cbom_kind(Some(primitive)), "cipher");
    }
    for (primitive, kind) in [
        ("signature", "signature"),
        ("hash", "digest"),
        ("mac", "mac"),
        ("key-agree", "key-agree"),
        ("kem", "kem"),
        ("keygen", "other"),
        ("unknown", "other"),
    ] {
        assert_eq!(cbom_kind(Some(primitive)), kind);
    }
    assert_eq!(cbom_kind(None), "other");
    for (row_kind, listed_kind, name, expected) in [
        ("other", "cipher", "AES", true),
        ("cipher", "other", "AES", true),
        ("other", "other", "AES", true),
        ("other", "cipher", "other:FAKEAES", false),
        ("cipher", "other", "other:FAKEAES", false),
        ("other", "other", "other:FAKEAES", false),
        ("cipher", "cipher", "other:FAKEAES", true),
    ] {
        let family = Some(name.to_string());
        let locations = HashSet::from([("Main.java".to_string(), 1, family.clone(), listed_kind)]);
        assert_eq!(
            sweep_matches(&locations, "Main.java", 1, family, row_kind),
            expected
        );
    }
}
