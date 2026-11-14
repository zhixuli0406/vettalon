use super::*;
use serde_json::{Map, json};

use super::FixtureReason as R;

const SECRET: &str = "s3cr3t-fixture-value";

fn bytes(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap()
}

fn with_env(env: Value) -> Vec<u8> {
    bytes(json!({"schema": FIXTURE_SCHEMA, "env": env}))
}

fn reason(input: &[u8]) -> FixtureReason {
    let err = validate_fixture(input).unwrap_err();
    // No refusal ever echoes a value.
    assert!(!err.detail.contains(SECRET), "{}", err.detail);
    assert!(!err.to_string().contains(SECRET));
    err.reason
}

// ---------------------------------------------------------------- accept

#[test]
fn minimal_fixture_is_valid() {
    let fx = validate_fixture(&bytes(json!({"schema": FIXTURE_SCHEMA}))).unwrap();
    assert!(fx.env().is_empty());
    assert_eq!(fx.sql_setup(), None);
    assert_eq!(
        fx.canonical_json(),
        br#"{"schema":"vettalon.node-fixture/1","env":{}}"#
    );
    assert_eq!(
        fx.sha256(),
        crate::audit::schema::sha256_hex(fx.canonical_json())
    );
}

#[test]
fn full_fixture_is_valid_and_sorted() {
    let fx = validate_fixture(&bytes(json!({
        "schema": FIXTURE_SCHEMA,
        "sql_setup": "CREATE TABLE users(id INTEGER, name TEXT);",
        "env": {"DB_USER": "alice", "API_TOKEN": SECRET, "EMPTY": "", "MULTI": "a\nb", "NODEJS_X": "1", "MY_PATH": "/x", "LDAP_URL": "ldap://x", "A": "1"},
    })))
    .unwrap();
    let names: Vec<&str> = fx.env().keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "A",
            "API_TOKEN",
            "DB_USER",
            "EMPTY",
            "LDAP_URL",
            "MULTI",
            "MY_PATH",
            "NODEJS_X"
        ]
    );
    assert_eq!(fx.env()["API_TOKEN"], SECRET);
    assert_eq!(
        fx.sql_setup(),
        Some("CREATE TABLE users(id INTEGER, name TEXT);")
    );
}

#[test]
fn digest_ignores_layout_but_binds_values() {
    let a = br#"{"schema":"vettalon.node-fixture/1","env":{"B":"2","A":"1"},"sql_setup":"x"}"#;
    let b = br#"
        { "sql_setup" : "x",
          "env" : { "A" : "1", "B" : "2" },
          "schema" : "vettalon.node-fixture/1" }
    "#;
    let fa = validate_fixture(a).unwrap();
    let fb = validate_fixture(b).unwrap();
    assert_eq!(fa.canonical_json(), fb.canonical_json());
    assert_eq!(fa.sha256(), fb.sha256());
    assert_eq!(
        fa.canonical_json(),
        br#"{"schema":"vettalon.node-fixture/1","env":{"A":"1","B":"2"},"sql_setup":"x"}"#
    );

    let c = br#"{"schema":"vettalon.node-fixture/1","env":{"A":"1","B":"3"},"sql_setup":"x"}"#;
    assert_ne!(validate_fixture(c).unwrap().sha256(), fa.sha256());
    let d = br#"{"schema":"vettalon.node-fixture/1","env":{"A":"1","B":"2"}}"#;
    assert_ne!(validate_fixture(d).unwrap().sha256(), fa.sha256());
}

#[test]
fn debug_output_redacts_values() {
    let fx = validate_fixture(&bytes(json!({
        "schema": FIXTURE_SCHEMA,
        "env": {"API_TOKEN": SECRET},
        "sql_setup": format!("INSERT INTO users VALUES ('{SECRET}');"),
    })))
    .unwrap();
    let shown = format!("{fx:?}");
    assert!(!shown.contains(SECRET), "{shown}");
    assert!(shown.contains("API_TOKEN"));
    assert!(shown.contains("<redacted"));
    assert!(shown.contains(fx.sha256()));
}

// ---------------------------------------------------------------- env names

#[test]
fn denied_env_names_are_refused() {
    for name in [
        "PATH",
        "HOME",
        "LANG",
        "NODE_OPTIONS",
        "NODE_PATH",
        "NODE_EXTRA_CA_CERTS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "NPM_CONFIG_REGISTRY",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "VTL_BASE",
        "VTL_DB",
        "VTL_EVENT_FD",
        "UV_THREADPOOL_SIZE",
        "SSL_CERT_FILE",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LC_ALL",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "GLIBC_TUNABLES",
        "GCONV_PATH",
        "MALLOC_ARENA_MAX",
        "BASH_ENV",
        "ENV",
        "IFS",
        "SHELL",
        "TMPDIR",
        "COREPACK_HOME",
    ] {
        assert_eq!(
            reason(&with_env(json!({name: SECRET}))),
            R::EnvDenied,
            "{name}"
        );
    }
}

#[test]
fn denylist_ignores_case() {
    for name in [
        "node_options",
        "Node_Options",
        "nOdE_pAtH",
        "npm_config_registry",
        "npm_config_userconfig",
        "Npm_Config_Cache",
        "ld_preload",
        "Ld_Preload",
        "dyld_insert_libraries",
        "path",
        "Path",
        "home",
        "lang",
        "vtl_event_fd",
        "uv_threadpool_size",
        "ssl_cert_file",
        "openssl_conf",
    ] {
        let err = validate_fixture(&with_env(json!({name: "x"}))).unwrap_err();
        assert_eq!(err.reason, R::EnvDenied, "{name}");
    }
}

#[test]
fn env_name_charset_and_length() {
    let max = "A".repeat(ENV_NAME_MAX);
    assert!(validate_fixture(&with_env(json!({max: "x"}))).is_ok());
    let names = [
        String::new(),
        "1ABC".into(),
        "_ABC".into(),
        "A-B".into(),
        "A B".into(),
        "A=B".into(),
        "A\u{0}B".into(),
        "ÄBC".into(),
        "lowercase".into(),
        "Mixed".into(),
        "A.B".into(),
        "A".repeat(ENV_NAME_MAX + 1),
        "a".repeat(ENV_NAME_MAX + 1),
    ];
    for name in names {
        assert_eq!(
            reason(&with_env(json!({name.clone(): SECRET}))),
            R::EnvName,
            "{name:?}"
        );
    }
}

#[test]
fn env_count_is_capped() {
    let env = |n: usize| {
        let mut m = Map::new();
        for i in 0..n {
            m.insert(format!("K{i}"), json!("v"));
        }
        Value::Object(m)
    };
    assert_eq!(
        validate_fixture(&with_env(env(ENV_MAX_ENTRIES)))
            .unwrap()
            .env()
            .len(),
        ENV_MAX_ENTRIES
    );
    assert_eq!(reason(&with_env(env(ENV_MAX_ENTRIES + 1))), R::TooManyEnv);
}

// ---------------------------------------------------------------- env values

#[test]
fn env_values_are_bounded_strings_without_nul() {
    let max = "v".repeat(ENV_VALUE_MAX_BYTES);
    assert!(validate_fixture(&with_env(json!({"K": max}))).is_ok());
    let over = format!("{SECRET}{}", "v".repeat(ENV_VALUE_MAX_BYTES));
    assert_eq!(reason(&with_env(json!({"K": over}))), R::EnvValueTooLarge);
    // Multi-byte characters count in bytes.
    let wide = "é".repeat(ENV_VALUE_MAX_BYTES / 2 + 1);
    assert_eq!(reason(&with_env(json!({"K": wide}))), R::EnvValueTooLarge);
    assert_eq!(
        reason(&with_env(json!({"K": format!("{SECRET}\u{0}x")}))),
        R::EnvValueNul
    );
    for v in [
        json!(1),
        json!(null),
        json!(true),
        json!([SECRET]),
        json!({"x": SECRET}),
    ] {
        assert_eq!(reason(&with_env(json!({"K": v}))), R::FieldType);
    }
}

#[test]
fn value_refusals_name_the_variable_only() {
    let err =
        validate_fixture(&with_env(json!({"API_TOKEN": format!("{SECRET}\u{0}")}))).unwrap_err();
    assert_eq!(err.reason, R::EnvValueNul);
    assert_eq!(err.detail, "API_TOKEN");
    assert_eq!(
        err.to_string(),
        "invalid --fixture: env_value_nul: API_TOKEN"
    );
}

// ---------------------------------------------------------------- schema

#[test]
fn schema_is_closed() {
    assert_eq!(reason(&bytes(json!({}))), R::Schema);
    assert_eq!(reason(&bytes(json!({"env": {}}))), R::Schema);
    assert_eq!(
        reason(&bytes(json!({"schema": "vettalon.node-fixture/2"}))),
        R::Schema
    );
    assert_eq!(reason(&bytes(json!({"schema": 1}))), R::Schema);
    for key in ["envs", "SQL_SETUP", "__proto__", "fixture", ""] {
        assert_eq!(
            reason(&bytes(json!({"schema": FIXTURE_SCHEMA, key: SECRET}))),
            R::UnknownField,
            "{key:?}"
        );
    }
    assert_eq!(
        reason(&bytes(json!({"schema": FIXTURE_SCHEMA, "env": ["A=1"]}))),
        R::FieldType
    );
    assert_eq!(
        reason(&bytes(json!({"schema": FIXTURE_SCHEMA, "env": null}))),
        R::FieldType
    );
    assert_eq!(
        reason(&bytes(
            json!({"schema": FIXTURE_SCHEMA, "sql_setup": ["x"]})
        )),
        R::FieldType
    );
    for top in [json!([]), json!("x"), json!(null), json!(1)] {
        assert_eq!(reason(&bytes(top)), R::NotObject);
    }
}

#[test]
fn sql_setup_is_bounded_and_nul_free() {
    assert_eq!(
        reason(&bytes(
            json!({"schema": FIXTURE_SCHEMA, "sql_setup": format!("SELECT 1;\u{0}{SECRET}")})
        )),
        R::SqlNul
    );
    assert_eq!(check_sql(&"x".repeat(SQL_SETUP_MAX_BYTES)), Ok(()));
    assert_eq!(
        check_sql(&"x".repeat(SQL_SETUP_MAX_BYTES + 1)),
        Err(R::SqlTooLarge)
    );
}

// ---------------------------------------------------------------- caps and malformed input

#[test]
fn byte_cap() {
    let mut ok = bytes(json!({"schema": FIXTURE_SCHEMA}));
    ok.resize(FIXTURE_MAX_BYTES, b' ');
    assert!(validate_fixture(&ok).is_ok());
    ok.push(b' ');
    assert_eq!(reason(&ok), R::TooLarge);
    // A big sql_setup trips the file cap first.
    let big =
        bytes(json!({"schema": FIXTURE_SCHEMA, "sql_setup": "x".repeat(SQL_SETUP_MAX_BYTES)}));
    assert_eq!(reason(&big), R::TooLarge);
}

#[test]
fn depth_cap() {
    let fits = bytes(json!({"schema": FIXTURE_SCHEMA, "env": {"K": [["x"]]}}));
    assert_eq!(reason(&fits), R::FieldType);
    let deep = bytes(json!({"schema": FIXTURE_SCHEMA, "env": {"K": [[["x"]]]}}));
    assert_eq!(reason(&deep), R::TooDeep);
    assert_eq!(reason("[".repeat(50_000).as_bytes()), R::TooDeep);
}

#[test]
fn duplicate_keys_are_refused() {
    let dup_env = br#"{"schema":"vettalon.node-fixture/1","env":{"API":"a","API":"b"}}"#;
    assert_eq!(reason(dup_env), R::DuplicateKey);
    let escaped = br#"{"schema":"vettalon.node-fixture/1","env":{"API":"a","API":"b"}}"#;
    assert_eq!(reason(escaped), R::DuplicateKey);
    // A later `env` would otherwise silently replace a denied one.
    let dup_field = br#"{"schema":"vettalon.node-fixture/1","env":{"NODE_OPTIONS":"x"},"env":{}}"#;
    assert_eq!(reason(dup_field), R::DuplicateKey);
}

#[test]
fn malformed_inputs_are_refused() {
    for text in [
        "",
        "{",
        r#"{"schema":"vettalon.node-fixture/1""#,
        r#"{"schema":"vettalon.node-fixture/1",}"#,
        r#"{"schema":"vettalon.node-fixture/1"} x"#,
        r#"{"schema":'vettalon.node-fixture/1'}"#,
        r#"{"schema":"vettalon.node-fixture/1","env":{"K":"\ud800"}}"#,
        r#"{"schema":"vettalon.node-fixture/1","env":{"K":1e999}}"#,
    ] {
        assert_eq!(reason(text.as_bytes()), R::MalformedJson, "{text:?}");
    }
    let not_utf8: [&[u8]; 2] = [
        b"{\"schema\":\"vettalon.node-fixture/1\",\"env\":{\"K\":\"\xff\"}}",
        b"\xfe\xff\x00{",
    ];
    for input in not_utf8 {
        assert_eq!(reason(input), R::NotUtf8);
    }
}

#[test]
fn truncations_and_mutations_never_panic() {
    let valid = bytes(json!({
        "schema": FIXTURE_SCHEMA,
        "env": {"API_TOKEN": "abc", "DB_USER": "alice"},
        "sql_setup": "CREATE TABLE t(x);",
    }));
    assert!(validate_fixture(&valid).is_ok());
    for n in 0..valid.len() {
        assert!(validate_fixture(&valid[..n]).is_err(), "prefix {n}");
    }
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as usize
    };
    for _ in 0..3000 {
        let mut m = valid.clone();
        for _ in 0..1 + next() % 3 {
            let i = next() % m.len();
            m[i] = next() as u8;
        }
        // Whatever passes still satisfies every invariant.
        if let Ok(fx) = validate_fixture(&m) {
            assert!(fx.env().len() <= ENV_MAX_ENTRIES);
            for (k, v) in fx.env() {
                assert_eq!(check_env_name(k), Ok(()));
                assert_eq!(check_env_value(v), Ok(()));
            }
        }
    }
}

#[test]
fn reason_tokens_are_stable_and_unique() {
    let all = [
        R::TooLarge,
        R::NotUtf8,
        R::TooDeep,
        R::MalformedJson,
        R::DuplicateKey,
        R::NotObject,
        R::Schema,
        R::UnknownField,
        R::FieldType,
        R::TooManyEnv,
        R::TooManyMembers,
        R::EnvName,
        R::EnvDenied,
        R::EnvValueTooLarge,
        R::EnvValueNul,
        R::SqlTooLarge,
        R::SqlNul,
    ];
    let tokens: std::collections::BTreeSet<&str> = all.iter().map(|r| r.as_str()).collect();
    assert_eq!(tokens.len(), all.len());
    // `[a-z][a-z0-9_]*` (digits allowed after the first byte: `not_utf8`).
    fn token_byte(b: u8) -> bool {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
    }
    for t in &tokens {
        let first_ok = t.starts_with(|c: char| c.is_ascii_lowercase());
        assert!(first_ok && t.bytes().all(token_byte), "{t}");
    }
    assert_eq!(R::NotUtf8.as_str(), "not_utf8");
    assert_eq!(R::EnvDenied.as_str(), "env_denied");
}

#[test]
fn child_tool_environment_controls_are_denied_in_any_case() {
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "XDG_CONFIG_HOME",
        "XDG_DATA_DIRS",
        "GIT_CONFIG",
        "GIT_SSH_COMMAND",
        "SSH_AUTH_SOCK",
        "SSH_ASKPASS",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "PERL5OPT",
        "PERL5LIB",
        "RUBYOPT",
        "RUBYLIB",
        "PYTHONPATH",
        "PYTHONHOME",
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "TMPDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
    ] {
        let mixed: String = name
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_lowercase()
                } else {
                    c
                }
            })
            .collect();
        for spelling in [name.to_string(), name.to_ascii_lowercase(), mixed] {
            assert_eq!(
                reason(&with_env(json!({spelling.clone(): SECRET}))),
                R::EnvDenied,
                "{spelling}"
            );
        }
    }
    for name in [
        "API_TOKEN",
        "DB_PASSWORD",
        "MY_HTTP_PROXY",
        "GITHUB_TOKEN",
        "SSHKEY",
        "JAVA_APP_TOKEN",
    ] {
        assert!(
            validate_fixture(&with_env(json!({name: SECRET}))).is_ok(),
            "{name}"
        );
    }
}
