use super::*;

fn doc(extra: &str) -> String {
    format!(r#"{{"bomFormat":"CycloneDX","specVersion":"1.6"{extra}}}"#)
}

#[test]
fn rejects_wrong_format_and_version() {
    let e = parse_cbom(br#"{"bomFormat":"SPDX","specVersion":"1.6"}"#).unwrap_err();
    assert_eq!(e, CbomError::BadFormat);
    assert_eq!(parse_cbom(b"{}").unwrap_err(), CbomError::BadFormat);
    // a top-level array is not a CBOM, even with the right values in order
    assert_eq!(
        parse_cbom(br#"["CycloneDX","1.6"]"#).unwrap_err(),
        CbomError::BadFormat
    );
    for v in ["1.5", "1.4", "2.0", ""] {
        let d = format!(r#"{{"bomFormat":"CycloneDX","specVersion":"{v}"}}"#);
        assert!(matches!(
            parse_cbom(d.as_bytes()),
            Err(CbomError::UnsupportedVersion(_))
        ));
    }
    // a number is not a version string
    let d = r#"{"bomFormat":"CycloneDX","specVersion":1.6}"#;
    assert!(matches!(
        parse_cbom(d.as_bytes()),
        Err(CbomError::UnsupportedVersion(_))
    ));
    assert!(matches!(parse_cbom(b"not json"), Err(CbomError::Json(_))));
    assert!(parse_cbom(doc("").as_bytes()).is_ok());
    let d = r#"{"bomFormat":"CycloneDX","specVersion":"1.7"}"#;
    assert_eq!(parse_cbom(d.as_bytes()).unwrap().spec_version, "1.7");
}

#[test]
fn enforces_size_caps() {
    let big = vec![b' '; MAX_CBOM_BYTES as usize + 1];
    assert_eq!(parse_cbom(&big).unwrap_err(), CbomError::TooLarge);

    let comp = r#"{"cryptoProperties":{"assetType":"algorithm"}}"#;
    let many = vec![comp; MAX_COMPONENTS + 1].join(",");
    let d = doc(&format!(r#","components":[{many}]"#));
    assert_eq!(
        parse_cbom(d.as_bytes()).unwrap_err(),
        CbomError::TooManyComponents
    );
    // components without cryptoProperties count towards the cap too
    let many = vec!["{}"; MAX_COMPONENTS + 1].join(",");
    let d = doc(&format!(r#","components":[{many}]"#));
    assert_eq!(
        parse_cbom(d.as_bytes()).unwrap_err(),
        CbomError::TooManyComponents
    );
    let ok = [comp; 3].join(",");
    let d = doc(&format!(r#","components":[{ok}]"#));
    assert_eq!(parse_cbom(d.as_bytes()).unwrap().components.len(), 3);

    let occ = r#"{"location":"a.py","line":1}"#;
    let occs = vec![occ; MAX_OCCURRENCES + 1].join(",");
    let d = doc(&format!(
        r#","components":[{{"cryptoProperties":{{}},"evidence":{{"occurrences":[{occs}]}}}}]"#
    ));
    assert_eq!(
        parse_cbom(d.as_bytes()).unwrap_err(),
        CbomError::TooManyOccurrences
    );
    let occs = vec![occ; MAX_OCCURRENCES].join(",");
    let d = doc(&format!(
        r#","components":[{{"cryptoProperties":{{}},"evidence":{{"occurrences":[{occs}]}}}}]"#
    ));
    assert_eq!(
        parse_cbom(d.as_bytes()).unwrap().components[0]
            .occurrences
            .len(),
        MAX_OCCURRENCES
    );
}

/// `n` components with `MAX_OCCURRENCES` occurrences each.
fn many_occurrences(n: usize) -> String {
    let occs = vec![r#"{"location":"a.py","line":1}"#; MAX_OCCURRENCES].join(",");
    let comp = format!(r#"{{"cryptoProperties":{{}},"evidence":{{"occurrences":[{occs}]}}}}"#);
    doc(&format!(r#","components":[{}]"#, vec![comp; n].join(",")))
}

#[test]
fn enforces_the_total_occurrence_cap() {
    let n = MAX_TOTAL_OCCURRENCES / MAX_OCCURRENCES;
    let ok = parse_cbom(many_occurrences(n).as_bytes()).unwrap();
    let total: usize = ok.components.iter().map(|c| c.occurrences.len()).sum();
    assert_eq!(total, MAX_TOTAL_OCCURRENCES);
    let e = parse_cbom(many_occurrences(n + 1).as_bytes()).unwrap_err();
    assert_eq!(e, CbomError::TooManyTotalOccurrences);
    assert!(e.to_string().contains("200000"));
}

#[test]
fn long_strings_are_clipped_and_recorded() {
    let long = "N".repeat(1000);
    let ctx = "\u{e9}".repeat(300);
    let d = doc(&format!(
        r#","components":[{{"name":"{long}","bom-ref":"{long}","cryptoProperties":{{"assetType":"algorithm"}},"evidence":{{"occurrences":[{{"location":"a.py","line":1,"additionalContext":"{ctx}"}}]}}}}]"#
    ));
    let c = parse_cbom(d.as_bytes()).unwrap();
    let comp = &c.components[0];
    let name = comp.name.as_deref().unwrap();
    assert_eq!(name.chars().count(), MAX_STRING_CHARS + 1);
    assert!(name.ends_with('…'));
    assert_eq!(comp.clipped, ["bom-ref", "name"]);
    let occ = &comp.occurrences[0];
    assert_eq!(
        occ.additional_context.as_deref().unwrap().chars().count(),
        MAX_STRING_CHARS + 1
    );
    assert_eq!(occ.clipped, ["additionalContext"]);
    // a string of exactly the cap is not clipped
    assert_eq!(clip_chars(&"x".repeat(256), 256), ("x".repeat(256), false));
}

#[test]
fn long_locations_are_refused() {
    let loc = format!("{}keys.py", "a/".repeat(2100));
    let d = doc(&format!(
        r#","components":[{{"cryptoProperties":{{}},"evidence":{{"occurrences":[{{"location":"{loc}","line":1}},{{"location":"{}","line":1}}]}}}}]"#,
        "b".repeat(MAX_LOCATION_BYTES)
    ));
    let c = parse_cbom(d.as_bytes()).unwrap();
    assert_eq!(
        c.components[0].occurrences[0].location,
        Err("location_too_long")
    );
    // exactly the cap is kept whole (not clipped to 256 characters)
    assert_eq!(
        c.components[0].occurrences[1]
            .location
            .as_ref()
            .unwrap()
            .len(),
        MAX_LOCATION_BYTES
    );
    let (_t, root) = tree();
    assert_eq!(map_location(&root, &loc), Err(PathError::TooLong));
    assert_eq!(PathError::TooLong.reason(), "location_too_long");
    let deep = format!("{}keys.py", "a/".repeat(MAX_LOCATION_COMPONENTS));
    assert_eq!(map_location(&root, &deep), Err(PathError::TooLong));
    let ok = format!("{}app/keys.py", "a/".repeat(MAX_LOCATION_COMPONENTS - 2));
    let m = map_location(&root, &ok).unwrap();
    assert_eq!(m.rel, "app/keys.py");
    assert_eq!(m.stripped, MAX_LOCATION_COMPONENTS - 2);
}

#[test]
fn malformed_line_values_become_reasons() {
    let cases = [
        ("5", Ok(5)),
        ("0", Ok(0)),
        ("-3", Err("line_negative")),
        ("\"7\"", Err("line_invalid")),
        ("1.5", Err("line_invalid")),
        ("5.0", Err("line_invalid")),
        ("true", Err("line_invalid")),
        ("[1]", Err("line_invalid")),
        ("{\"a\":[1,{}]}", Err("line_invalid")),
        ("null", Err("line_missing")),
        ("99999999999999999999", Err("line_invalid")),
        ("4294967296", Err("line_invalid")),
    ];
    for (raw, want) in cases {
        let d = doc(&format!(
            r#","components":[{{"cryptoProperties":{{}},"evidence":{{"occurrences":[{{"location":"a.py","line":{raw}}}]}}}}]"#
        ));
        let c = parse_cbom(d.as_bytes()).unwrap();
        assert_eq!(c.components[0].occurrences[0].line, want, "{raw}");
    }
    // missing line, bad location types, wrong-typed leaves: no panic
    let d = doc(
        r#","components":[{"name":5,"bom-ref":[1],"cryptoProperties":{"assetType":3,"algorithmProperties":"x"},"evidence":{"occurrences":[{"location":7},{"line":1},{},"x"]}}]"#,
    );
    let c = parse_cbom(d.as_bytes()).unwrap();
    let o = &c.components[0].occurrences;
    assert_eq!(o[0].location, Err("location_invalid"));
    assert_eq!(o[1].location, Err("location_missing"));
    assert_eq!(o[1].line, Ok(1));
    assert_eq!(o[2].line, Err("line_missing"));
    // a non-object occurrence is kept as an empty one (an unknown row)
    assert_eq!(o[3].location, Err("location_missing"));
    assert_eq!(c.components[0].name, None);
    // wrong-typed containers are "missing", not a parse error
    let d = doc(r#","components":{"a":1},"dependencies":"x","metadata":[1]"#);
    assert!(parse_cbom(d.as_bytes()).unwrap().components.is_empty());
}

#[test]
fn reads_fixture_and_links_material_to_algorithm() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/cbom/sample-py.cbomkit.json");
    let cbom = read_cbom(&path).unwrap();
    assert_eq!(cbom.spec_version, "1.6");
    assert_eq!(cbom.tool.as_deref(), Some("PQCA CBOMkit"));
    assert_eq!(cbom.components.len(), 6);
    let idx = cbom
        .components
        .iter()
        .position(|c| {
            c.name
                .as_deref()
                .is_some_and(|n| n.starts_with("secret-key@"))
        })
        .unwrap();
    let alg = cbom.algorithm_for(idx).unwrap();
    assert_eq!(alg.name.as_deref(), Some("AES-256-GCM"));
    assert_eq!(classify_quantum(alg), Some(false));
    // a directory is not a CBOM file
    assert!(matches!(
        read_cbom(path.parent().unwrap()),
        Err(CbomError::Io(_))
    ));
}

#[test]
fn algorithm_links_match_a_naive_search() {
    let comps = r#"[
        {"bom-ref":"a","name":"A1","cryptoProperties":{"assetType":"algorithm"}},
        {"bom-ref":"b","name":"B","cryptoProperties":{"assetType":"algorithm"}},
        {"bom-ref":"a","name":"A2","cryptoProperties":{"assetType":"algorithm"}},
        {"bom-ref":"k","name":"K","cryptoProperties":{"assetType":"related-crypto-material"}},
        {"bom-ref":"k","name":"K-again","cryptoProperties":{"assetType":"related-crypto-material"}},
        {"bom-ref":"m","name":"M","cryptoProperties":{"assetType":"related-crypto-material"}},
        {"bom-ref":"p","name":"P","cryptoProperties":{"assetType":"protocol"}},
        {"name":"no-ref","cryptoProperties":{"assetType":"related-crypto-material"}},
        {"bom-ref":"q","name":"Q","cryptoProperties":{"assetType":"protocol"}}
    ]"#;
    let deps = r#"[
        {"ref":"k","dependsOn":["missing","m","b","a"]},
        {"ref":"m","dependsOn":["k"]},
        {"ref":"q","dependsOn":["missing"]},
        {"ref":"q","dependsOn":["a"]}
    ]"#;
    let d = doc(&format!(r#","components":{comps},"dependencies":{deps}"#));
    let cbom = parse_cbom(d.as_bytes()).unwrap();
    // the pre-index O(deps × components) search, as reference
    let naive = |idx: usize| -> Option<usize> {
        let c = &cbom.components[idx];
        if c.asset_type.as_deref() == Some("algorithm") {
            return Some(idx);
        }
        let deps = cbom.dependencies.get(c.bom_ref.as_deref()?)?;
        deps.iter().find_map(|d| {
            cbom.components.iter().position(|o| {
                o.bom_ref.as_deref() == Some(d.as_str())
                    && o.asset_type.as_deref() == Some("algorithm")
            })
        })
    };
    let name = |i: Option<usize>| i.and_then(|i| cbom.components[i].name.clone());
    for i in 0..cbom.components.len() {
        let got = cbom.algorithm_for(i).and_then(|c| c.name.clone());
        assert_eq!(got, name(naive(i)), "component {i}");
    }
    let by_name = |n: &str| {
        let i = cbom
            .components
            .iter()
            .position(|c| c.name.as_deref() == Some(n))
            .unwrap();
        cbom.algorithm_for(i).and_then(|c| c.name.clone())
    };
    assert_eq!(by_name("K").as_deref(), Some("B"));
    assert_eq!(by_name("K-again").as_deref(), Some("B"));
    assert_eq!(by_name("A2").as_deref(), Some("A2"));
    assert_eq!(by_name("M"), None);
    assert_eq!(by_name("P"), None);
    assert_eq!(by_name("no-ref"), None);
    // repeated `ref` entries are merged in order
    assert_eq!(by_name("Q").as_deref(), Some("A1"));
    assert_eq!(cbom.algorithm_for(99), None);
}

#[test]
fn dependencies_dropped_by_caps_are_recorded() {
    let d = doc(r#","dependencies":[{"ref":"k","dependsOn":["a"]}]"#);
    assert!(!parse_cbom(d.as_bytes()).unwrap().dependencies_truncated);
    let refs = vec![r#""a""#; 1025].join(",");
    let d = doc(&format!(
        r#","dependencies":[{{"ref":"k","dependsOn":[{refs}]}}]"#
    ));
    let c = parse_cbom(d.as_bytes()).unwrap();
    assert!(c.dependencies_truncated);
    assert_eq!(c.dependencies["k"].len(), 1024);
}

#[test]
fn quantum_classification() {
    // (name, primitive, parameterSetIdentifier, curve, expected)
    type Case = (
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<bool>,
    );
    let cases: [Case; 14] = [
        ("RSA-2048", Some("pke"), Some("2048"), None, Some(true)),
        ("SHA256withRSA", Some("signature"), None, None, Some(true)),
        (
            "EC-secp256r1",
            Some("pke"),
            None,
            Some("secp256r1"),
            Some(true),
        ),
        ("ECDSA", Some("signature"), None, None, Some(true)),
        ("Ed25519", Some("signature"), None, None, Some(true)),
        ("DSA", None, None, None, Some(true)),
        ("ECDH", Some("key-agree"), None, None, Some(true)),
        ("AES-256-GCM", Some("ae"), Some("256"), None, Some(false)),
        ("AES-128-CBC", Some("block-cipher"), None, None, Some(false)),
        ("SHA-256", Some("hash"), None, None, Some(false)),
        ("DES", Some("block-cipher"), Some("56"), None, None),
        ("ML-DSA-65", Some("signature"), None, None, None),
        ("ML-KEM-768", Some("kem"), None, None, None),
        ("mystery", None, None, None, None),
    ];
    for (name, primitive, param, curve, want) in cases {
        let c = Component {
            name: Some(name.into()),
            primitive: primitive.map(Into::into),
            parameter_set_identifier: param.map(Into::into),
            curve: curve.map(Into::into),
            ..Component::default()
        };
        assert_eq!(classify_quantum(&c), want, "{name}");
    }
}

fn tree() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::write(root.join("app/keys.py"), "x = 1\n").unwrap();
    std::fs::write(root.join("top.py"), "x = 1\n").unwrap();
    (t, root)
}

#[test]
fn maps_plain_and_workspace_prefixed_paths() {
    let (_t, root) = tree();
    let m = map_location(&root, "app/keys.py").unwrap();
    assert_eq!((m.rel.as_str(), m.stripped), ("app/keys.py", 0));
    // CBOMkit prefixes the scanner's workspace dir name
    let m = map_location(&root, "ws/app/keys.py").unwrap();
    assert_eq!(m.rel, "app/keys.py");
    assert_eq!(m.abs, root.join("app/keys.py"));
    assert_eq!(m.stripped, 1);
    let m = map_location(&root, "a/b/c/top.py").unwrap();
    assert_eq!((m.rel.as_str(), m.stripped), ("top.py", 3));
    assert_eq!(
        map_location(&root, "./ws//app/./keys.py").unwrap().rel,
        "app/keys.py"
    );
    assert_eq!(
        map_location(&root, "ws\\app\\keys.py").unwrap().rel,
        "app/keys.py"
    );
    assert_eq!(
        map_location(&root, "ws/app/nope.py"),
        Err(PathError::Missing)
    );
    // a directory is not a file
    assert_eq!(map_location(&root, "ws/app"), Err(PathError::Missing));
}

#[test]
fn rejects_unsafe_locations() {
    let (_t, root) = tree();
    assert_eq!(map_location(&root, "/etc/passwd"), Err(PathError::Absolute));
    assert_eq!(
        map_location(&root, "C:/x/keys.py"),
        Err(PathError::Absolute)
    );
    assert_eq!(map_location(&root, "\\\\host\\x"), Err(PathError::Absolute));
    assert_eq!(
        map_location(&root, "ws/../app/keys.py"),
        Err(PathError::ParentComponent)
    );
    assert_eq!(
        map_location(&root, "../top.py"),
        Err(PathError::ParentComponent)
    );
    assert_eq!(map_location(&root, ""), Err(PathError::Invalid));
    assert_eq!(map_location(&root, "a\0b"), Err(PathError::Invalid));
    assert_eq!(map_location(&root, "./."), Err(PathError::Invalid));
}

#[test]
fn oversized_source_file_is_rejected() {
    let (_t, root) = tree();
    let f = std::fs::File::create(root.join("big.py")).unwrap();
    f.set_len(MAX_SOURCE_FILE_BYTES + 1).unwrap();
    assert_eq!(map_location(&root, "ws/big.py"), Err(PathError::TooLarge));
}

#[cfg(unix)]
#[test]
fn symlink_escaping_root_is_rejected() {
    let (_t, root) = tree();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.py"), "x = 1\n").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret.py"), root.join("link.py")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.join("dir")).unwrap();
    assert_eq!(map_location(&root, "link.py"), Err(PathError::OutsideRoot));
    assert_eq!(
        map_location(&root, "ws/link.py"),
        Err(PathError::OutsideRoot)
    );
    assert_eq!(
        map_location(&root, "dir/secret.py"),
        Err(PathError::OutsideRoot)
    );
    // a symlink that stays inside the root resolves to the real file
    std::os::unix::fs::symlink(root.join("top.py"), root.join("alias.py")).unwrap();
    assert_eq!(map_location(&root, "alias.py").unwrap().rel, "top.py");
}
