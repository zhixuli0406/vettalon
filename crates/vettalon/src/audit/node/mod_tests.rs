use super::*;

#[test]
fn strict_parse_accepts_plain_json() {
    let v = parse_strict(br#"{"a":[1,2,{"b":null}],"c":"x"}"#, 1024, 8).unwrap();
    assert_eq!(v["c"], "x");
}

#[test]
fn strict_parse_faults() {
    assert_eq!(parse_strict(b"{}", 1, 8), Err(JsonFault::TooLarge));
    assert_eq!(
        parse_strict(b"{\"a\":\"\xff\"}", 64, 8),
        Err(JsonFault::NotUtf8)
    );
    assert_eq!(parse_strict(b"[[[[1]]]]", 64, 3), Err(JsonFault::TooDeep));
    assert_eq!(parse_strict(b"{\"a\":", 64, 8), Err(JsonFault::Malformed));
    assert_eq!(parse_strict(b"", 64, 8), Err(JsonFault::Malformed));
    assert_eq!(parse_strict(b"{} {}", 64, 8), Err(JsonFault::Malformed));
    assert_eq!(
        parse_strict(b"{\"a\":1,}", 64, 8),
        Err(JsonFault::Malformed)
    );
    assert_eq!(
        parse_strict(br#"{"a":1,"a":2}"#, 64, 8),
        Err(JsonFault::DuplicateKey)
    );
    // Escapes are compared after decoding.
    assert_eq!(
        parse_strict(br#"{"x":{"a":1,"a":2}}"#, 64, 8),
        Err(JsonFault::DuplicateKey)
    );
    // Same key in sibling objects is fine.
    assert!(parse_strict(br#"[{"a":1},{"a":2}]"#, 64, 8).is_ok());
}

#[test]
fn strict_parse_never_panics_on_odd_numbers() {
    for input in [
        &b"1e400"[..],
        b"-1e400",
        b"123456789012345678901234567890123456789012345678901234567890",
        b"{\"n\":-0.0000000000000000000000000000000000000001e-400}",
        b"NaN",
        b"Infinity",
    ] {
        let _ = parse_strict(input, 1024, 8);
    }
}

#[test]
fn deep_nesting_is_refused_before_the_parser() {
    let mut bomb = vec![b'['; 100_000];
    bomb.extend(vec![b']'; 100_000]);
    assert_eq!(parse_strict(&bomb, 1 << 20, 64), Err(JsonFault::TooDeep));
}

#[test]
fn bounded_detail_strips_controls_and_truncates() {
    let d = bounded_detail("a\nb\u{1b}[31m");
    assert_eq!(d, "a?b?[31m");
    let long = "x".repeat(1000);
    let d = bounded_detail(&long);
    assert_eq!(d.chars().count(), DETAIL_MAX_CHARS + 1);
    assert!(d.ends_with('…'));
}

fn member_object(count: usize) -> String {
    let fields: Vec<String> = (0..count).map(|i| format!("\"k{i}\":0")).collect();
    format!("{{{}}}", fields.join(","))
}

#[test]
fn streaming_object_cap_accepts_boundary_and_refuses_before_excess_value() {
    let boundary = member_object(JSON_MAX_MEMBERS);
    assert!(parse_strict(boundary.as_bytes(), 1 << 20, 8).is_ok());
    let excess = format!("{},\"excess\":INVALID}}", &boundary[..boundary.len() - 1]);
    assert_eq!(
        parse_strict(excess.as_bytes(), 1 << 20, 8),
        Err(JsonFault::TooManyMembers)
    );
}

#[test]
fn streaming_total_key_cap_counts_across_sibling_objects() {
    let object = member_object(JSON_MAX_MEMBERS);
    let objects = [object.as_str(); JSON_MAX_TOTAL_KEYS / JSON_MAX_MEMBERS];
    let boundary = format!("[{}]", objects.join(","));
    assert!(parse_strict(boundary.as_bytes(), 16 << 20, 8).is_ok());
    let excess = format!(
        "{},{{\"excess\":INVALID}}]",
        &boundary[..boundary.len() - 1]
    );
    assert_eq!(
        parse_strict(excess.as_bytes(), 16 << 20, 8),
        Err(JsonFault::TooManyMembers)
    );
}

#[test]
fn streaming_duplicates_are_decoded_and_scoped_to_each_object() {
    assert_eq!(
        parse_strict(br#"{"packages":{"x":{},"\u0078":{}}}"#, 1024, 8),
        Err(JsonFault::DuplicateKey)
    );
    assert!(parse_strict(br#"[{"a":{"a":1}},{"a":2}]"#, 1024, 8).is_ok());
}

#[test]
fn packages_member_cap_only_applies_to_the_top_level_packages_object() {
    assert!(parse_strict_limited(br#"{"packages":{"":{},"x":{}}}"#, 1024, 8, Some(2)).is_ok());
    assert_eq!(
        parse_strict_limited(
            br#"{"packa\u0067es":{"":{},"x":{},"y":INVALID}}"#,
            1024,
            8,
            Some(2)
        ),
        Err(JsonFault::TooManyPackages)
    );
    assert!(
        parse_strict_limited(
            br#"{"metadata":{"packages":{"a":0,"b":0,"c":0}}}"#,
            1024,
            8,
            Some(2)
        )
        .is_ok()
    );
}
