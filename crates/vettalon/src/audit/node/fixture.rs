//! `--fixture <JSON>`: operator-supplied auth fixtures for Node targets
//! (design §3.5). Closed schema [`FIXTURE_SCHEMA`]:
//!
//! ```json
//! {"schema": "vettalon.node-fixture/1",
//!  "env": {"API_TOKEN": "…"},
//!  "sql_setup": "CREATE TABLE users(…);"}
//! ```
//!
//! `env` and `sql_setup` are optional; no other key is allowed. Only `env`
//! reaches the target's child process; `sql_setup` runs on the fixture DB.
//! Values are secrets: they are never logged, never part of an error
//! message (errors name the env variable at most, masked and bounded) and
//! never written to a receipt. Receipts bind [`NodeFixture::sha256`] only.
//!
//! Env names must match `[A-Z][A-Z0-9_]{0,63}`. The case-insensitive
//! denylist includes proxy controls (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
//! `NO_PROXY`), `XDG_*`, `GIT_*`, `SSH_*`, Java options (`JAVA_TOOL_OPTIONS`,
//! `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`), `PERL*`, `RUBY*`, `PYTHON*`, shell
//! controls (`BASH_ENV`, `ENV`, `SHELLOPTS`), `TMPDIR`, `SSL_CERT_FILE`,
//! `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS`, and the existing loader, locale,
//! npm and harness controls in [`DENIED_ENV_NAMES`] / [`DENIED_ENV_PREFIXES`].
//!
//! Refusal reason tokens ([`FixtureReason::as_str`], matching
//! `[a-z][a-z0-9_]*`):
//!
//! | Token | Meaning |
//! |---|---|
//! | `too_large` | over [`FIXTURE_MAX_BYTES`] |
//! | `not_utf8` | bytes are not UTF-8 |
//! | `too_deep` | JSON nested deeper than [`FIXTURE_MAX_DEPTH`] |
//! | `malformed_json` | not strict JSON |
//! | `too_many_members` | JSON object or total key count exceeds the parser limits |
//! | `duplicate_key` | an object repeats a key (incl. an env name) |
//! | `not_object` | top level is not an object |
//! | `schema` | `schema` missing or not [`FIXTURE_SCHEMA`] |
//! | `unknown_field` | a top-level key other than `schema`, `env`, `sql_setup` |
//! | `field_type` | `env` not an object, a value or `sql_setup` not a string |
//! | `too_many_env` | more than [`ENV_MAX_ENTRIES`] env entries |
//! | `env_name` | name not `[A-Z][A-Z0-9_]{0,63}` |
//! | `env_denied` | name on the denylist (checked case-insensitively) |
//! | `env_value_too_large` | value over [`ENV_VALUE_MAX_BYTES`] |
//! | `env_value_nul` | value contains NUL |
//! | `sql_too_large` | `sql_setup` over [`SQL_SETUP_MAX_BYTES`] |
//! | `sql_nul` | `sql_setup` contains NUL |

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;

use super::{JsonFault, bounded_detail, parse_strict};

pub const FIXTURE_SCHEMA: &str = "vettalon.node-fixture/1";
pub const FIXTURE_MAX_BYTES: usize = 64 * 1024;
/// The schema is two levels deep; a little slack, nothing more.
pub const FIXTURE_MAX_DEPTH: usize = 4;
pub const ENV_MAX_ENTRIES: usize = 32;
pub const ENV_NAME_MAX: usize = 64;
pub const ENV_VALUE_MAX_BYTES: usize = 4 * 1024;
pub const SQL_SETUP_MAX_BYTES: usize = 64 * 1024;

/// Exact env names refused. The design's list (`PATH`, `HOME`, `LANG`) plus
/// names that change how a shell, the dynamic loader, libc or the C library's
/// locale/charset code behave in a child the target may spawn.
pub const DENIED_ENV_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LANGUAGE",
    "SHELL",
    "USER",
    "LOGNAME",
    "PWD",
    "TMPDIR",
    "IFS",
    "ENV",
    "BASH_ENV",
    "CDPATH",
    "PS4",
    "SHELLOPTS",
    "BASHOPTS",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
];

/// Env name prefixes refused. The design's list (`NODE_*`, `NPM_*`/`npm_*`,
/// `LD_*`, `VTL_*`, `UV_*`, `SSL_*`) plus the macOS loader (`DYLD_*`), locale
/// (`LC_*`), Python (`PYTHON*`, the runner is Python), OpenSSL config and
/// engines (`OPENSSL_*`, loads native code into Node), glibc malloc tuning,
/// Corepack, exported bash functions, tool configuration and language runtimes.
pub const DENIED_ENV_PREFIXES: &[&str] = &[
    "NODE_",
    "NPM_",
    "LD_",
    "VTL_",
    "UV_",
    "SSL_",
    "DYLD_",
    "LC_",
    "PYTHON",
    "OPENSSL_",
    "MALLOC_",
    "COREPACK_",
    "BASH_FUNC_",
    "XDG_",
    "GIT_",
    "SSH_",
    "PERL",
    "RUBY",
];

/// Stable reason token of a refusal (table in the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureReason {
    TooLarge,
    NotUtf8,
    TooDeep,
    MalformedJson,
    DuplicateKey,
    NotObject,
    Schema,
    UnknownField,
    FieldType,
    TooManyEnv,
    TooManyMembers,
    EnvName,
    EnvDenied,
    EnvValueTooLarge,
    EnvValueNul,
    SqlTooLarge,
    SqlNul,
}

impl FixtureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            FixtureReason::TooLarge => "too_large",
            FixtureReason::NotUtf8 => "not_utf8",
            FixtureReason::TooDeep => "too_deep",
            FixtureReason::MalformedJson => "malformed_json",
            FixtureReason::DuplicateKey => "duplicate_key",
            FixtureReason::NotObject => "not_object",
            FixtureReason::Schema => "schema",
            FixtureReason::UnknownField => "unknown_field",
            FixtureReason::FieldType => "field_type",
            FixtureReason::TooManyMembers => "too_many_members",
            FixtureReason::TooManyEnv => "too_many_env",
            FixtureReason::EnvName => "env_name",
            FixtureReason::EnvDenied => "env_denied",
            FixtureReason::EnvValueTooLarge => "env_value_too_large",
            FixtureReason::EnvValueNul => "env_value_nul",
            FixtureReason::SqlTooLarge => "sql_too_large",
            FixtureReason::SqlNul => "sql_nul",
        }
    }

    fn from_json(fault: JsonFault) -> Self {
        match fault {
            JsonFault::TooLarge => FixtureReason::TooLarge,
            JsonFault::NotUtf8 => FixtureReason::NotUtf8,
            JsonFault::TooDeep => FixtureReason::TooDeep,
            JsonFault::Malformed => FixtureReason::MalformedJson,
            JsonFault::DuplicateKey => FixtureReason::DuplicateKey,
            JsonFault::TooManyPackages | JsonFault::TooManyMembers => FixtureReason::TooManyMembers,
        }
    }
}

/// Why a fixture was refused. `detail` names a field or env variable
/// (masked, bounded), never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureError {
    pub reason: FixtureReason,
    pub detail: String,
}

impl FixtureError {
    fn new(reason: FixtureReason, at: &str) -> Self {
        FixtureError {
            reason,
            detail: bounded_detail(at),
        }
    }
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid --fixture: {}", self.reason.as_str())?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

impl std::error::Error for FixtureError {}

/// A validated fixture. `Debug` redacts every value; there is no
/// `Serialize` or `Display`, so values cannot end up in a report by accident.
#[derive(Clone)]
pub struct NodeFixture {
    env: BTreeMap<String, String>,
    sql_setup: Option<String>,
    canonical: Vec<u8>,
    sha256: String,
}

impl NodeFixture {
    /// Env for the target's child, sorted by name.
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    pub fn sql_setup(&self) -> Option<&str> {
        self.sql_setup.as_deref()
    }

    /// Deterministic re-rendering (`schema`, `env` sorted, `sql_setup`),
    /// independent of the operator's whitespace and key order. This is what
    /// the harness sends over its private stdin envelope, so the digest binds
    /// exactly what the runner reads.
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical
    }

    /// SHA-256 of [`NodeFixture::canonical_json`]: receipt `fixture_sha256`.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl fmt::Debug for NodeFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Redacted(usize);
        impl fmt::Debug for Redacted {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "<redacted {} bytes>", self.0)
            }
        }
        let env: Vec<(&str, Redacted)> = self
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), Redacted(v.len())))
            .collect();
        f.debug_struct("NodeFixture")
            .field("env", &env)
            .field(
                "sql_setup",
                &self.sql_setup.as_ref().map(|s| Redacted(s.len())),
            )
            .field("sha256", &self.sha256)
            .finish()
    }
}

#[derive(serde::Serialize)]
struct Canonical<'a> {
    schema: &'a str,
    env: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql_setup: Option<&'a str>,
}

/// Validate fixture bytes the caller read with a bounded read.
pub fn validate_fixture(bytes: &[u8]) -> Result<NodeFixture, FixtureError> {
    let value = parse_strict(bytes, FIXTURE_MAX_BYTES, FIXTURE_MAX_DEPTH)
        .map_err(|e| FixtureError::new(FixtureReason::from_json(e), ""))?;
    let obj = value
        .as_object()
        .ok_or_else(|| FixtureError::new(FixtureReason::NotObject, ""))?;
    if let Some(key) = obj
        .keys()
        .find(|k| !matches!(k.as_str(), "schema" | "env" | "sql_setup"))
    {
        return Err(FixtureError::new(FixtureReason::UnknownField, key));
    }
    if obj.get("schema").and_then(Value::as_str) != Some(FIXTURE_SCHEMA) {
        return Err(FixtureError::new(FixtureReason::Schema, "schema"));
    }
    let env = match obj.get("env") {
        None => BTreeMap::new(),
        Some(Value::Object(map)) => {
            if map.len() > ENV_MAX_ENTRIES {
                return Err(FixtureError::new(
                    FixtureReason::TooManyEnv,
                    &format!("{} > {ENV_MAX_ENTRIES}", map.len()),
                ));
            }
            let mut env = BTreeMap::new();
            for (name, value) in map {
                check_env_name(name).map_err(|r| FixtureError::new(r, name))?;
                let value = value
                    .as_str()
                    .ok_or_else(|| FixtureError::new(FixtureReason::FieldType, name))?;
                check_env_value(value).map_err(|r| FixtureError::new(r, name))?;
                env.insert(name.clone(), value.to_string());
            }
            env
        }
        Some(_) => return Err(FixtureError::new(FixtureReason::FieldType, "env")),
    };
    let sql_setup = match obj.get("sql_setup") {
        None => None,
        Some(Value::String(sql)) => {
            check_sql(sql).map_err(|r| FixtureError::new(r, "sql_setup"))?;
            Some(sql.clone())
        }
        Some(_) => return Err(FixtureError::new(FixtureReason::FieldType, "sql_setup")),
    };
    let canonical = serde_json::to_vec(&Canonical {
        schema: FIXTURE_SCHEMA,
        env: &env,
        sql_setup: sql_setup.as_deref(),
    })
    .map_err(|_| FixtureError::new(FixtureReason::MalformedJson, ""))?;
    let sha256 = crate::audit::schema::sha256_hex(&canonical);
    Ok(NodeFixture {
        env,
        sql_setup,
        canonical,
        sha256,
    })
}

/// Length, then the denylist on the ASCII-upper-cased name (so `npm_config_x`
/// and `node_options` are `env_denied`, not just `env_name`), then the charset.
fn check_env_name(name: &str) -> Result<(), FixtureReason> {
    if name.is_empty() || name.len() > ENV_NAME_MAX {
        return Err(FixtureReason::EnvName);
    }
    let upper = name.to_ascii_uppercase();
    if DENIED_ENV_NAMES.contains(&upper.as_str())
        || DENIED_ENV_PREFIXES.iter().any(|p| upper.starts_with(p))
    {
        return Err(FixtureReason::EnvDenied);
    }
    let mut bytes = name.bytes();
    let first_ok = bytes.next().is_some_and(|b| b.is_ascii_uppercase());
    if first_ok && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
        Ok(())
    } else {
        Err(FixtureReason::EnvName)
    }
}

fn check_env_value(value: &str) -> Result<(), FixtureReason> {
    if value.len() > ENV_VALUE_MAX_BYTES {
        Err(FixtureReason::EnvValueTooLarge)
    } else if value.contains('\0') {
        Err(FixtureReason::EnvValueNul)
    } else {
        Ok(())
    }
}

/// Defence in depth: the whole file is already ≤ 64 KiB and JSON unescaping
/// never grows a string.
fn check_sql(sql: &str) -> Result<(), FixtureReason> {
    if sql.len() > SQL_SETUP_MAX_BYTES {
        Err(FixtureReason::SqlTooLarge)
    } else if sql.contains('\0') {
        Err(FixtureReason::SqlNul)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "fixture_tests.rs"]
mod tests;
