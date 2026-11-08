//! `vettalon toolchain`: a local, offline audit of what coding agents have
//! installed (Claude Code skills, plugins, hooks and MCP servers; Codex MCP
//! servers and skills). Behaviour contract: `docs/TOOLCHAIN-AUDIT.md`.
//!
//! Audited content is untrusted data. Nothing here executes it, passes it to
//! a shell, or sends it to a model. Unknown, unreadable or over-limit input
//! makes the audit incomplete; it is never reported as clean. Secret values
//! (MCP env, headers, secret-named keys, secret-shaped arguments) never reach
//! output or the pin store: only `<redacted:` + 8 hex of their HMAC-SHA256
//! under the local key (`$VETTALON_HOME/toolchain/key`) + `>`.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::schema::Severity;

mod cli;
pub mod content;
pub mod discover;
pub mod mcp;
mod npm;
pub mod pins;
pub mod report;
pub mod rules;
pub mod sarif;

pub use cli::{AuditOptions, Format, cmd_audit, cmd_pin, cmd_pins, parse_fail_on};

/// Exit code of `audit` when the audit is incomplete (without
/// `--allow-incomplete`) and no finding reached `--fail-on`.
pub const EXIT_INCOMPLETE: i32 = 2;

/// Version of the static rule set; recorded in every report.
pub const RULES_VERSION: &str = "tc-rules-1";
/// JSON schema id of the audit report.
pub const SCHEMA: &str = "vettalon.toolchain/1";
/// Hidden override of the user's home directory (tests only).
pub const HOME_ENV: &str = "VETTALON_TOOLCHAIN_HOME";
/// Default `--max-file-bytes`.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024;
/// A file is scanned up to this many bytes; the rest is unscanned.
pub const SCAN_CAP_BYTES: u64 = 8 * 1024 * 1024;
/// Per-item read limits.
pub const MAX_FILES: usize = 5_000;
pub const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
/// Audit-wide safety limits.
pub const GLOBAL_MAX_FILES: usize = 200_000;
pub const GLOBAL_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
/// Directory entries (files, directories and anything else) listed per item
/// or per discovery root, and directories entered per item.
pub const MAX_ENTRIES: usize = 20_000;
pub const MAX_DIRS: usize = 5_000;
/// Directory entries listed audit-wide.
pub const GLOBAL_MAX_ENTRIES: usize = 500_000;
/// Lines longer than this trigger TC006.
pub const MAX_LINE_CHARS: usize = 10_000;
/// `SKILL.md` search depth below a `skills/` root.
pub const SKILL_DEPTH: usize = 4;
/// Excerpt length cap (characters).
pub const EXCERPT_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    pub fn as_str(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Skill,
    Plugin,
    Mcp,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Skill => "skill",
            Kind::Plugin => "plugin",
            Kind::Mcp => "mcp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Project,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Project => "project",
        }
    }
}

/// `--agent claude|codex|all`.
pub fn parse_agents(value: &str) -> Result<Vec<Agent>, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "claude" => Ok(vec![Agent::Claude]),
        "codex" => Ok(vec![Agent::Codex]),
        "all" => Ok(vec![Agent::Claude, Agent::Codex]),
        other => Err(format!(
            "--agent must be claude, codex or all (got {other:?})"
        )),
    }
}

/// `--scope user|project|all`.
pub fn parse_scopes(value: &str) -> Result<Vec<Scope>, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "user" => Ok(vec![Scope::User]),
        "project" => Ok(vec![Scope::Project]),
        "all" => Ok(vec![Scope::User, Scope::Project]),
        other => Err(format!(
            "--scope must be user, project or all (got {other:?})"
        )),
    }
}

/// What to discover.
#[derive(Debug, Clone)]
pub struct Selection {
    /// The user's home (or `VETTALON_TOOLCHAIN_HOME`).
    pub home: PathBuf,
    /// Project root for project-level locations.
    pub project: PathBuf,
    pub agents: Vec<Agent>,
    pub scopes: Vec<Scope>,
}

impl Selection {
    pub fn wants(&self, agent: Agent, scope: Scope) -> bool {
        self.agents.contains(&agent) && self.scopes.contains(&scope)
    }

    pub fn wants_agent(&self, agent: Agent) -> bool {
        self.agents.contains(&agent)
    }
}

/// The home directory discovery starts from.
pub fn toolchain_home() -> PathBuf {
    for key in [HOME_ENV, "HOME", "USERPROFILE"] {
        if let Ok(v) = std::env::var(key)
            && !v.is_empty()
        {
            return PathBuf::from(v);
        }
    }
    PathBuf::from(".")
}

/// Renders paths for output: the home prefix becomes `~`, control and
/// invisible characters are escaped.
#[derive(Debug, Clone)]
pub struct PathDisplay {
    prefixes: Vec<PathBuf>,
}

impl PathDisplay {
    pub fn new(home: &Path) -> Self {
        let mut prefixes = vec![home.to_path_buf()];
        if let Ok(c) = home.canonicalize()
            && c != home
        {
            prefixes.push(c);
        }
        // Longest first so a canonical form that extends the raw one wins.
        prefixes.sort_by_key(|p| std::cmp::Reverse(p.as_os_str().len()));
        PathDisplay { prefixes }
    }

    pub fn show(&self, path: &Path) -> String {
        for prefix in &self.prefixes {
            if let Ok(rest) = path.strip_prefix(prefix) {
                let rest = encode_path(rest);
                let shown = if rest.is_empty() {
                    "~".to_string()
                } else {
                    format!("~/{rest}")
                };
                return clean_text(&shown);
            }
        }
        clean_text(&encode_path(path))
    }
}

/// A path with every component passed through [`os_display`], joined by `/`.
pub(crate) fn encode_path(path: &Path) -> String {
    let mut out = String::new();
    for c in path.components() {
        match c {
            Component::RootDir => out.push('/'),
            Component::Prefix(p) => out.push_str(&encode_text(&p.as_os_str().to_string_lossy())),
            other => {
                if !out.is_empty() && !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str(&os_display(other.as_os_str()));
            }
        }
    }
    out
}

/// Reversible display form of one file name: invalid UTF-8 bytes, `%` and
/// unsafe characters ([`is_unsafe_char`]) become `%XX`, so distinct raw names
/// stay distinct and no control character reaches a report or the pin store.
pub(crate) fn os_display(name: &OsStr) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        encode_bytes(name.as_bytes())
    }
    #[cfg(not(unix))]
    {
        encode_text(&name.to_string_lossy())
    }
}

pub(crate) fn encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(&encode_text(chunk.valid()));
        for b in chunk.invalid() {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn encode_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '%' || is_unsafe_char(c) {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Inverse of [`encode_bytes`]: the raw bytes a relative path stands for.
pub(crate) fn decode_rel(rel: &str) -> Vec<u8> {
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let b = rel.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Characters that must not reach a terminal or report unescaped:
/// controls, bidi controls and zero-width/format characters.
pub(crate) fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c as u32,
            0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF | 0x00AD | 0xFFF9..=0xFFFB
        )
        || (0xE0000..=0xE007F).contains(&(c as u32))
}

/// Escape unsafe characters as `\u{..}` (tab stays a space).
pub(crate) fn clean_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\t' {
            out.push(' ');
        } else if is_unsafe_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// URLs, masked, escaped, at most [`EXCERPT_CHARS`] characters.
pub(crate) fn excerpt(text: &str) -> String {
    let masked = crate::util::mask_sensitive_text(&redact_urls_in_text(text.trim()));
    let cleaned = clean_text(&masked);
    cleaned.chars().take(EXCERPT_CHARS).collect()
}

/// Masked, escaped message text with URLs redacted.
pub(crate) fn message(text: &str) -> String {
    clean_text(&crate::util::mask_sensitive_text(&redact_urls_in_text(
        text,
    )))
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ── local HMAC key ────────────────────────────────────────────────────────

static HASH_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Install the key loaded from the pin store directory. Must run before any
/// discovery; a second, different key is an error.
pub(crate) fn set_hash_key(key: [u8; 32]) -> Result<(), String> {
    match HASH_KEY.set(key) {
        Ok(()) => Ok(()),
        Err(_) if HASH_KEY.get() == Some(&key) => Ok(()),
        Err(_) => Err("the toolchain hash key was already initialised".into()),
    }
}

/// The installed key, or (unit tests, library use without the CLI) a random
/// per-process key. Never a constant.
fn hash_key() -> &'static [u8; 32] {
    HASH_KEY.get_or_init(random_key)
}

/// 32 random bytes: `/dev/urandom` (Unix) and three v4 UUIDs, mixed with
/// SHA-256 so either source alone suffices.
pub(crate) fn random_key() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vettalon-toolchain-key/1\0");
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut buf = [0u8; 32];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom")
            && f.read_exact(&mut buf).is_ok()
        {
            h.update(buf);
        }
    }
    for _ in 0..3 {
        h.update(uuid::Uuid::new_v4().as_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}

/// HMAC-SHA256 (RFC 2104) over the `sha2` crate.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key)[..]);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner[..]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize()[..]);
    out
}

/// Hex HMAC-SHA256 of `data` under the local key.
pub(crate) fn keyed_hex(data: &[u8]) -> String {
    hex::encode(hmac_sha256(hash_key(), data))
}

/// `<redacted:` + the first 8 hex digits of the value's keyed HMAC + `>`.
pub fn redacted(value: &str) -> String {
    format!("<redacted:{}>", &keyed_hex(value.as_bytes())[..8])
}

// ── URL redaction ─────────────────────────────────────────────────────────

/// Fixed replacement for URL userinfo, query and fragment values on display.
pub const URL_REDACTED: &str = "<redacted>";

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>`]+"#).expect("static URL pattern")
});

/// `u` with its userinfo and every query / fragment value (whatever the key)
/// passed through `replace`; scheme, host, port, path and keys stay. Purely
/// textual, so unparseable URLs are handled the same way.
pub(crate) fn redact_url_with(u: &str, replace: &dyn Fn(&str) -> String) -> String {
    let Some(sep) = u.find("://") else {
        return u.to_string();
    };
    let (scheme, rest) = u.split_at(sep + 3);
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    let mut out = String::from(scheme);
    match authority.rfind('@') {
        Some(at) => {
            out.push_str(&replace(&authority[..at]));
            out.push('@');
            out.push_str(&authority[at + 1..]);
        }
        None => out.push_str(authority),
    }
    let (before_fragment, fragment) = match tail.split_once('#') {
        Some((a, f)) => (a, Some(f)),
        None => (tail, None),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (before_fragment, None),
    };
    out.push_str(path);
    if let Some(q) = query {
        out.push('?');
        out.push_str(&redact_pairs(q, replace));
    }
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(&redact_pairs(f, replace));
    }
    out
}

fn redact_pairs(s: &str, replace: &dyn Fn(&str) -> String) -> String {
    s.split('&')
        .map(|part| match part.split_once('=') {
            Some((k, v)) if !v.is_empty() => format!("{k}={}", replace(v)),
            Some((k, _)) => format!("{k}="),
            None if part.is_empty() => String::new(),
            None => replace(part),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Display form of a URL: userinfo, query and fragment values → `<redacted>`.
pub fn display_url(u: &str) -> String {
    redact_url_with(u, &|_| URL_REDACTED.to_string())
}

/// Every `scheme://…` URL in free text in its [`display_url`] form.
pub(crate) fn redact_urls_in_text(text: &str) -> String {
    if !text.contains("://") {
        return text.to_string();
    }
    URL_RE
        .replace_all(text, |c: &regex::Captures<'_>| display_url(&c[0]))
        .into_owned()
}

// ── secret-bearing files ──────────────────────────────────────────────────

/// Excerpt of every finding in a secret-bearing file.
pub const SECRET_EXCERPT: &str = "<excerpt omitted: secret-bearing file>";

/// A file that holds secrets by its name (`.env`, keys, credential stores).
/// Rules still run on it; its excerpts are withheld and its content hash is
/// keyed.
///
/// Fixed names (`.env`, keys, credential stores) always count, except
/// `.env.<example|sample|template|dist|defaults>` and `*.pub`. A name that
/// merely contains `secret` or `token` counts only for extension-less files
/// and data/config extensions, and not for example/sample/template names, so
/// `refresh_token.sh` or `tokens.css` are not flagged (`tokens.json` still is).
pub fn is_secret_bearing(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if let Some(suffix) = n.strip_prefix(".env.") {
        return !["example", "sample", "template", "dist", "defaults"].contains(&suffix);
    }
    if n == ".env" {
        return true;
    }
    if n.ends_with(".pub") {
        return false;
    }
    if [".pem", ".key", ".p12", ".pfx"]
        .iter()
        .any(|ext| n.ends_with(ext))
        || n.starts_with("id_rsa")
        || n.starts_with("id_ed25519")
        || n.starts_with("id_ecdsa")
        || n == "credentials"
        || [".npmrc", ".pypirc", ".netrc", "auth.json"].contains(&n.as_str())
    {
        return true;
    }
    if let Some(ext) = n.strip_prefix("credentials.") {
        return ["json", "ini", "toml", "yaml", "yml"].contains(&ext);
    }
    if n.contains("secret") || n.contains("token") {
        let (stem, ext) = match n.rsplit_once('.') {
            Some((s, e)) if !s.is_empty() => (s, Some(e)),
            _ => (n.as_str(), None),
        };
        let data_ext = ext.is_none_or(|e| {
            [
                "txt", "json", "yaml", "yml", "toml", "ini", "conf", "cfg", "dat", "key",
            ]
            .contains(&e)
        });
        let template = ["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|m| stem.ends_with(m));
        return data_ext && !template;
    }
    false
}

static SECRET_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(token|secret|passw(or)?d|pwd|api[-_]?key|apikey|auth|credential|cookie|private[-_]?key|session|bearer|access[-_]?key|signature|signing)",
    )
    .expect("static secret-name pattern")
});

/// A key whose value is treated as a secret (env/header/config keys).
pub fn is_secret_name(key: &str) -> bool {
    SECRET_NAME_RE.is_match(key)
}

/// A literal value shaped like a credential: a well-known token prefix, a
/// `key=value` with a secret-named key, a URL with a password, ...
/// (anything [`crate::util::mask_sensitive_text`] would mask).
pub fn is_secret_shaped(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty() && crate::util::mask_sensitive_text(v) != v
}

/// One finding before ids are assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFinding {
    pub rule: &'static str,
    pub severity: Severity,
    pub file: Option<PathBuf>,
    pub line: Option<usize>,
    /// Already masked and escaped.
    pub message: String,
    /// Already masked, escaped and capped.
    pub excerpt: String,
}

impl RawFinding {
    pub fn new(
        rule: &'static str,
        severity: Severity,
        file: Option<&Path>,
        line: Option<usize>,
        msg: &str,
        excerpt_text: &str,
    ) -> Self {
        RawFinding {
            rule,
            severity,
            file: file.map(Path::to_path_buf),
            line,
            message: message(msg),
            excerpt: excerpt(excerpt_text),
        }
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
