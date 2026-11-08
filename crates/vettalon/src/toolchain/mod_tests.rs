use super::*;

#[test]
fn home_paths_display_as_tilde() {
    let d = PathDisplay::new(Path::new("/Users/x"));
    assert_eq!(
        d.show(Path::new("/Users/x/.claude/skills/a")),
        "~/.claude/skills/a"
    );
    assert_eq!(d.show(Path::new("/Users/x")), "~");
    assert_eq!(d.show(Path::new("/opt/elsewhere")), "/opt/elsewhere");
}

#[test]
fn redaction_shows_only_a_hash_prefix() {
    let secret = "sk-test-AAAAAAAAAAAAAAAAAAAAAAAA"; // gitleaks:allow (fake test value)
    let r = redacted(secret);
    assert!(r.starts_with("<redacted:") && r.ends_with('>'));
    assert_eq!(r.len(), "<redacted:>".len() + 8);
    assert!(!r.contains("AAAA"));
}

#[test]
fn excerpts_are_masked_escaped_and_capped() {
    let e = excerpt("\u{202e} run token: hunter2hunter2");
    assert!(!e.contains("hunter2"), "{e}");
    assert!(e.starts_with("\\u{202e}"), "{e}");
    assert_eq!(excerpt(&"x".repeat(400)).chars().count(), EXCERPT_CHARS);
}

#[test]
fn secret_names_and_shapes() {
    assert!(is_secret_name("GITHUB_TOKEN"));
    assert!(is_secret_name("Authorization"));
    assert!(!is_secret_name("PATH"));
    assert!(is_secret_shaped("ghp_AAAAAAAAAAAAAAAAAAAA")); // gitleaks:allow (fake test value)
    assert!(is_secret_shaped("--api-key=abc123"));
    assert!(!is_secret_shaped("@scope/server"));
    assert!(!is_secret_shaped("-y"));
}

// L11: path display is reversible and keeps raw names distinct.
#[test]
fn path_encoding_is_reversible_and_distinct() {
    assert_eq!(encode_bytes(b"a\xffb"), "a%FFb");
    assert_eq!(encode_bytes(b"a%FFb"), "a%25FFb");
    assert_eq!(encode_bytes(b"x\x1b[2J\n"), "x%1B[2J%0A");
    assert_eq!(encode_bytes("é\u{202e}".as_bytes()), "é%E2%80%AE");
    let raws: [&[u8]; 6] = [
        b"a\xffb",
        b"a%FFb",
        b"a%25b",
        b"plain/name.md",
        b"%",
        b"\xc3",
    ];
    for raw in raws {
        assert_eq!(decode_rel(&encode_bytes(raw)), raw, "{raw:?}");
    }
    assert_ne!(encode_bytes(b"a\xffb"), encode_bytes(b"a\xfeb"));
}

#[cfg(unix)]
#[test]
fn path_display_percent_encodes_invalid_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let d = PathDisplay::new(Path::new("/home/u"));
    let p = Path::new("/home/u").join(OsStr::from_bytes(b"skills/a\xffb"));
    assert_eq!(d.show(&p), "~/skills/a%FFb");
    let p = Path::new("/srv").join(OsStr::from_bytes(b"a\xfeb"));
    assert_eq!(d.show(&p), "/srv/a%FEb");
}

#[test]
fn display_url_redacts_userinfo_query_and_fragment() {
    assert_eq!(
        display_url("https://user:pw@h.invalid:8443/p/q?a=1&b=&c#frag=x"),
        "https://<redacted>@h.invalid:8443/p/q?a=<redacted>&b=&<redacted>#frag=<redacted>"
    );
    assert_eq!(display_url("https://h.invalid/p"), "https://h.invalid/p");
    assert_eq!(
        redact_urls_in_text("see https://h.invalid/x?sig=abc and http://o.invalid/?code=9."),
        "see https://h.invalid/x?sig=<redacted> and http://o.invalid/?code=<redacted>"
    );
}

#[test]
fn agent_and_scope_flags_parse() {
    assert_eq!(parse_agents("all").unwrap(), [Agent::Claude, Agent::Codex]);
    assert_eq!(parse_scopes("project").unwrap(), [Scope::Project]);
    assert!(parse_agents("cursor").is_err());
    assert!(parse_scopes("system").is_err());
}
