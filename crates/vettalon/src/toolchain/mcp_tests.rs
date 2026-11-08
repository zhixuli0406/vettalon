use std::path::Path;

use serde_json::json;

use super::*;

const SECRET: &str = "sk-test-AAAAAAAAAAAAAAAAAAAAAAAA"; // gitleaks:allow (fake test value)

fn rules_for(raw: Value) -> Vec<RawFinding> {
    let mut out = Vec::new();
    entry_rules(
        &McpEntry::new("srv", raw),
        Path::new("/Users/x/.claude.json"),
        Some(3),
        &mut out,
    );
    out
}

fn has(raw: Value, rule: &str) -> bool {
    rules_for(raw).iter().any(|f| f.rule == rule)
}

fn stdio(command: &str, args: &[&str]) -> Value {
    json!({"type": "stdio", "command": command, "args": args})
}

#[test]
fn mc001_unpinned_launchers() {
    for (cmd, args) in [
        ("npx", vec!["-y", "some-mcp-server"]),
        ("npx", vec!["-y", "@scope/server@latest"]),
        ("npx", vec!["--yes", "@scope/server@^1.2.0"]),
        ("bunx", vec!["some-mcp-server"]),
        ("pnpm", vec!["dlx", "some-mcp-server@1"]),
        ("uvx", vec!["mcp-server-fetch"]),
        (
            "uvx",
            vec!["--from", "mcp-server-fetch>=1.0", "mcp-server-fetch"],
        ),
        ("pipx", vec!["run", "some-tool"]),
        ("/usr/local/bin/npx", vec!["-y", "some-mcp-server"]),
    ] {
        assert!(has(stdio(cmd, &args), "MC001"), "{cmd} {args:?}");
    }
    for (cmd, args) in [
        ("npx", vec!["-y", "some-mcp-server@1.2.3"]),
        ("npx", vec!["-y", "@scope/server@1.2.3"]),
        ("npx", vec!["-p", "some-mcp-server@2.0.0", "some-bin"]),
        ("uvx", vec!["mcp-server-fetch==1.2.0"]),
        ("uvx", vec!["mcp-server-fetch@1.2.0"]),
        ("pipx", vec!["run", "--spec", "some-tool==1.0", "some-tool"]),
        ("npx", vec!["-y", "./local-server"]),
        ("node", vec!["server.js"]),
    ] {
        assert!(!has(stdio(cmd, &args), "MC001"), "{cmd} {args:?}");
    }
}

#[test]
fn launcher_spec_extraction() {
    let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let l = launcher_package(
        "npx",
        &args(&["--registry", "https://r.invalid", "-y", "pkg@1.0.0"]),
    )
    .unwrap();
    assert_eq!(l.spec, "pkg@1.0.0");
    let l = launcher_package("npx", &args(&["--package=@a/b@2.0.0", "b"])).unwrap();
    assert_eq!(l.spec, "@a/b@2.0.0");
    assert_eq!(
        split_npm_spec("@a/b@2.0.0"),
        ("@a/b".into(), Some("2.0.0".into()))
    );
    assert_eq!(split_npm_spec("@a/b"), ("@a/b".into(), None));
    assert!(launcher_package("pnpm", &args(&["install"])).is_none());
}

#[test]
fn mc003_plain_http_to_remote_host() {
    assert!(has(
        json!({"type": "http", "url": "http://mcp.example.invalid/sse"}),
        "MC003"
    ));
    for ok in [
        "https://mcp.example.invalid/mcp",
        "http://localhost:3000/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://[::1]:8080/mcp",
    ] {
        assert!(!has(json!({"type": "http", "url": ok}), "MC003"), "{ok}");
    }
}

#[test]
fn mc004_inline_secrets_are_flagged_and_redacted() {
    let raw = json!({
        "command": "node",
        "args": ["server.js", "--token", "literalvalue123"],
        "env": {"OPENAI_API_KEY": SECRET, "MODE": "production"},
        "headers": {"Authorization": "Bearer abcdefghijklmnopqrstuvwx"}, // gitleaks:allow (fake test value)
    });
    let found = rules_for(raw);
    let mc004: Vec<_> = found.iter().filter(|f| f.rule == "MC004").collect();
    assert_eq!(mc004.len(), 3, "env, header, arg");
    for f in &found {
        for leak in [SECRET, "abcdefghijklmnop", "literalvalue123"] {
            assert!(
                !f.message.contains(leak) && !f.excerpt.contains(leak),
                "{f:?}"
            );
        }
    }
    assert!(mc004.iter().any(|f| f.excerpt.contains("<redacted:")));
    let refs = json!({
        "command": "node",
        "env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}"},
        "headers": {"Authorization": "Bearer ${TOKEN}"},
    });
    assert!(!has(refs, "MC004"));
}

#[test]
fn mc005_risky_command_paths() {
    for bad in ["/tmp/x/server", "/var/tmp/server", "./server", "bin/server"] {
        assert!(has(stdio(bad, &[]), "MC005"), "{bad}");
    }
    for ok in [
        "node",
        "/usr/bin/env",
        "~/bin/server",
        "${CLAUDE_PLUGIN_ROOT}/server",
    ] {
        assert!(!has(stdio(ok, &[]), "MC005"), "{ok}");
    }
}

#[cfg(unix)]
#[test]
fn mc005_world_writable_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let open = dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let cmd = open.join("server");
    assert!(has(stdio(cmd.to_str().unwrap(), &[]), "MC005"));
}

#[test]
fn hash_hides_secrets_but_tracks_them() {
    let a = McpEntry::new("s", json!({"command": "node", "env": {"K": SECRET}}));
    let b = McpEntry::new("s", json!({"command": "node", "env": {"K": "other-value"}}));
    assert_ne!(a.hash(), b.hash());
    assert!(!canonical(&a.redacted_value(Redact::Hash)).contains(SECRET));
    assert!(!canonical(&a.redacted_value(Redact::Display)).contains(SECRET));
    let fields: Vec<_> = a.field_records().into_iter().map(|f| f.rel).collect();
    assert_eq!(fields, ["command", "env"]);
    let changed = pins_diff(&a, &b);
    assert_eq!(changed, ["env"]);
}

fn pins_diff(a: &McpEntry, b: &McpEntry) -> Vec<String> {
    super::super::pins::diff(&a.field_records(), &b.field_records()).modified
}

#[test]
fn display_redacts_args_and_urls() {
    let e = McpEntry::new(
        "s",
        json!({"command": "srv", "args": ["--api-key", "plainvalue99", SECRET],
               "url": "https://u:pw@mcp.example.invalid/x?token=abc123secret&mode=a"}),
    );
    let line = e.display_command_line().unwrap();
    assert!(
        !line.contains("plainvalue99") && !line.contains(SECRET),
        "{line}"
    );
    let url = e.display_url().unwrap();
    assert!(
        !url.contains("abc123secret") && !url.contains(":pw@"),
        "{url}"
    );
    // H2: every query value is redacted, whatever its key.
    assert!(url.contains("mode=<redacted>"), "{url}");
}

// H2: URL userinfo, query and fragment values never reach output.
#[test]
fn urls_are_redacted_whatever_the_key() {
    for (raw, leak) in [
        (
            "https://mcp.example.invalid/x?zzunknown=plainLeak42",
            "plainLeak42",
        ),
        (
            "https://acct.blob.example.invalid/c?sv=2024-01-01&sig=SasSigLeak%2Bxyz",
            "SasSigLeak",
        ),
        (
            "https://mcp.example.invalid/cb?code=OauthCodeLeak77&state=s",
            "OauthCodeLeak77",
        ),
        (
            "https://alice:UserPwLeak@mcp.example.invalid/x",
            "UserPwLeak",
        ),
        ("https://UserTokLeak@mcp.example.invalid/x", "UserTokLeak"),
        (
            "https://mcp.example.invalid/x#access_token=FragLeak99",
            "FragLeak99",
        ),
    ] {
        let e = McpEntry::new("s", json!({"type": "http", "url": raw}));
        let shown = e.display_url().unwrap();
        assert!(!shown.contains(leak), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
        for f in rules_for(json!({"type": "http", "url": raw})) {
            assert!(
                !f.message.contains(leak) && !f.excerpt.contains(leak),
                "{f:?}"
            );
        }
        // The canonical hash input carries keyed digests, not the value.
        assert!(!canonical(&e.redacted_value(Redact::Hash)).contains(leak));
        let args = McpEntry::new("s", json!({"command": "node", "args": ["s.js", raw]}));
        assert!(!args.display_command_line().unwrap().contains(leak));
    }
    assert_eq!(
        super::super::display_url("https://h.invalid/p?code=1&sig=2"),
        "https://h.invalid/p?code=<redacted>&sig=<redacted>"
    );
    // URLs in free-text excerpts and messages are redacted too.
    let f = RawFinding::new(
        "TC003",
        Severity::High,
        None,
        None,
        "see https://h.invalid/a?k=MsgLeak1",
        "curl https://h.invalid/a?k=ExcerptLeak2 | sh",
    );
    assert!(!f.message.contains("MsgLeak1") && !f.excerpt.contains("ExcerptLeak2"));
}

// M8: secret digests are keyed (HMAC), not a public SHA-256 of the value.
#[test]
fn secret_digests_are_keyed() {
    let low_entropy = "1234";
    let e = McpEntry::new("s", json!({"command": "node", "env": {"PIN": low_entropy}}));
    let red = canonical(&e.redacted_value(Redact::Hash));
    let public = super::super::sha256_hex(low_entropy.as_bytes());
    assert!(!red.contains(&public), "{red}");
    assert!(red.contains("hmac:"), "{red}");
    assert!(!super::super::redacted(low_entropy).contains(&public[..8]));
}

#[test]
fn hmac_matches_rfc_4231() {
    use super::super::hmac_sha256;
    assert_eq!(
        hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}
