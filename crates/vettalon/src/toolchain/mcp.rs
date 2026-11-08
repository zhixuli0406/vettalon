//! MCP server entries: redaction, canonical hash and rules MC001, MC003,
//! MC004, MC005 (MC002 lives in [`super::npm`]).
//!
//! An entry holds raw config values, secrets included, so it has no
//! `Debug`/`Serialize`: everything that leaves this module is redacted.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::content::FileRecord;
use super::{
    RawFinding, URL_REDACTED, clean_text, is_secret_name, is_secret_shaped, keyed_hex,
    redact_url_with, redacted, rules, sha256_hex,
};
use crate::audit::schema::Severity;

/// Keys whose every value is a secret.
const SECRET_CONTAINERS: &[&str] = &["env", "headers", "http_headers"];

/// One configured MCP server.
#[derive(Clone)]
pub struct McpEntry {
    pub name: String,
    raw: Value,
}

/// How a secret value is replaced.
#[derive(Clone, Copy)]
enum Redact {
    /// `hmac:<hex>` under the local key (hash input only, never stored or
    /// shown, so a low-entropy secret cannot be guessed offline from a hash).
    Hash,
    /// `<redacted:8hex>` of the keyed HMAC (display).
    Display,
}

impl Redact {
    fn apply(self, value: &str) -> String {
        match self {
            Redact::Hash => format!("hmac:{}", keyed_hex(value.as_bytes())),
            Redact::Display => redacted(value),
        }
    }

    /// Replacement for URL userinfo / query / fragment values.
    fn url_value(self, value: &str) -> String {
        match self {
            Redact::Hash => self.apply(value),
            Redact::Display => URL_REDACTED.to_string(),
        }
    }
}

impl McpEntry {
    pub fn new(name: &str, raw: Value) -> Self {
        McpEntry {
            name: name.to_string(),
            raw,
        }
    }

    pub fn command(&self) -> Option<&str> {
        self.raw.get("command").and_then(Value::as_str)
    }

    pub fn args(&self) -> Vec<String> {
        self.raw
            .get("args")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(value_text).collect())
            .unwrap_or_default()
    }

    pub fn url(&self) -> Option<&str> {
        self.raw.get("url").and_then(Value::as_str)
    }

    fn redacted_value(&self, mode: Redact) -> Value {
        redact_value(&self.raw, false, mode)
    }

    /// `sha256:` over the canonical JSON with secrets replaced by their hash.
    pub fn hash(&self) -> String {
        format!(
            "sha256:{}",
            sha256_hex(canonical(&self.redacted_value(Redact::Hash)).as_bytes())
        )
    }

    /// Per-field hashes (field name, hash of the redacted field) so a
    /// changed pin can name the fields that changed.
    pub fn field_records(&self) -> Vec<FileRecord> {
        let red = self.redacted_value(Redact::Hash);
        let mut out: Vec<FileRecord> = red
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| FileRecord {
                        rel: clean_text(k),
                        sha256: sha256_hex(canonical(v).as_bytes()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    /// Redacted args for display.
    pub fn display_args(&self) -> Vec<String> {
        redact_args(&self.args(), Redact::Display)
    }

    /// `command arg…` with secret-shaped arguments redacted.
    pub fn display_command_line(&self) -> Option<String> {
        let cmd = self.command()?;
        let mut parts = vec![cmd.to_string()];
        parts.extend(self.display_args());
        Some(parts.join(" "))
    }

    pub fn display_url(&self) -> Option<String> {
        self.url().map(|u| redact_url(u, Redact::Display))
    }
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn secret_arg(prev: Option<&str>, arg: &str) -> bool {
    is_secret_shaped(arg)
        || prev.is_some_and(|p| p.starts_with('-') && !p.contains('=') && is_secret_name(p))
}

fn redact_args(args: &[String], mode: Redact) -> Vec<String> {
    args.iter()
        .enumerate()
        .map(|(i, a)| {
            let prev = i.checked_sub(1).map(|j| args[j].as_str());
            if secret_arg(prev, a) {
                mode.apply(a)
            } else if a.contains("://") {
                redact_url(a, mode)
            } else {
                a.clone()
            }
        })
        .collect()
}

/// Userinfo and every query / fragment value are replaced whatever their
/// key name (`?code=<redacted>&sig=<redacted>`).
fn redact_url(u: &str, mode: Redact) -> String {
    if !u.contains("://") {
        return if is_secret_shaped(u) {
            mode.apply(u)
        } else {
            u.to_string()
        };
    }
    redact_url_with(u, &|v| mode.url_value(v))
}

/// A launcher package spec as shown in messages (secret-shaped → redacted).
pub(super) fn display_spec(spec: &str) -> String {
    redact_args(&[spec.to_string()], Redact::Display)
        .pop()
        .unwrap_or_default()
}

fn redact_value(v: &Value, secret: bool, mode: Redact) -> Value {
    if secret {
        return Value::String(mode.apply(&match v {
            Value::String(s) => s.clone(),
            other => canonical(other),
        }));
    }
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| {
                    let red = if SECRET_CONTAINERS.contains(&k.as_str()) && val.is_object() {
                        redact_container(val, mode)
                    } else if is_secret_name(k) {
                        redact_value(val, true, mode)
                    } else if k == "args" && val.is_array() {
                        let args: Vec<String> = val
                            .as_array()
                            .map(|a| a.iter().map(value_text).collect())
                            .unwrap_or_default();
                        Value::Array(
                            redact_args(&args, mode)
                                .into_iter()
                                .map(Value::String)
                                .collect(),
                        )
                    } else if k == "url" && val.is_string() {
                        Value::String(redact_url(val.as_str().unwrap_or_default(), mode))
                    } else {
                        redact_value(val, false, mode)
                    };
                    (k.clone(), red)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|x| redact_value(x, false, mode)).collect()),
        Value::String(s) if is_secret_shaped(s) => Value::String(mode.apply(s)),
        other => other.clone(),
    }
}

/// `env` / `headers`: keys stay, every value is replaced.
fn redact_container(v: &Value, mode: Redact) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| (k.clone(), redact_value(val, true, mode)))
                .collect(),
        ),
        other => redact_value(other, true, mode),
    }
}

/// Canonical JSON: sorted keys, no whitespace.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&m[k.as_str()], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

// ── launchers (MC001 / MC002) ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registry {
    Npm,
    PyPi,
}

/// A package a launcher fetches and runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub launcher: &'static str,
    pub registry: Registry,
    pub spec: String,
}

const NPX_VALUE_FLAGS: &[&str] = &[
    "--registry",
    "--cache",
    "--userconfig",
    "--prefix",
    "-c",
    "--call",
    "--node-options",
    "-w",
    "--workspace",
];
const UVX_VALUE_FLAGS: &[&str] = &[
    "--with",
    "--with-editable",
    "--with-requirements",
    "--python",
    "-p",
    "--index",
    "--index-url",
    "--extra-index-url",
    "--default-index",
    "--constraint",
    "-c",
    "--override",
    "--cache-dir",
    "--directory",
    "--project",
    "--config-file",
    "--env-file",
    "--exclude-newer",
    "--index-strategy",
    "--resolution",
    "--prerelease",
    "--python-preference",
];
const PIPX_VALUE_FLAGS: &[&str] = &["--python", "--pip-args", "--index-url"];

/// Package spec: the value of a package flag, else the first positional.
fn pick_spec(args: &[String], value_flags: &[&str], package_flags: &[&str]) -> Option<String> {
    let mut first_positional = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            first_positional = first_positional.or_else(|| args.get(i + 1).cloned());
            break;
        }
        if let Some((flag, value)) = a.split_once('=')
            && flag.starts_with('-')
        {
            if package_flags.contains(&flag) {
                return Some(value.to_string());
            }
        } else if package_flags.contains(&a) {
            return args.get(i + 1).cloned();
        } else if value_flags.contains(&a) {
            i += 1;
        } else if !a.starts_with('-') && first_positional.is_none() {
            first_positional = Some(a.to_string());
            break;
        }
        i += 1;
    }
    first_positional
}

/// Skip leading flags and require `word` as the first positional.
fn after_subcommand<'a>(args: &'a [String], words: &[&str]) -> Option<&'a [String]> {
    let pos = args.iter().position(|a| !a.starts_with('-'))?;
    words
        .contains(&args[pos].as_str())
        .then(|| &args[pos + 1..])
}

fn base_name(command: &str) -> String {
    let base = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    for ext in [".cmd", ".exe", ".ps1", ".bat"] {
        if let Some(s) = base.strip_suffix(ext) {
            return s.to_string();
        }
    }
    base
}

/// The package a launcher command would fetch, if it is one.
pub fn launcher_package(command: &str, args: &[String]) -> Option<Launch> {
    let npm = |launcher: &'static str, spec: String| Launch {
        launcher,
        registry: Registry::Npm,
        spec,
    };
    let pypi = |launcher: &'static str, spec: String| Launch {
        launcher,
        registry: Registry::PyPi,
        spec,
    };
    match base_name(command).as_str() {
        "npx" => pick_spec(args, NPX_VALUE_FLAGS, &["-p", "--package"]).map(|s| npm("npx", s)),
        "bunx" => pick_spec(args, &[], &["-p", "--package"]).map(|s| npm("bunx", s)),
        "pnpx" => pick_spec(args, &[], &["--package"]).map(|s| npm("pnpm dlx", s)),
        "pnpm" => after_subcommand(args, &["dlx"])
            .and_then(|rest| pick_spec(rest, &["--registry"], &["--package"]))
            .map(|s| npm("pnpm dlx", s)),
        "yarn" => after_subcommand(args, &["dlx"])
            .and_then(|rest| pick_spec(rest, &[], &["-p", "--package"]))
            .map(|s| npm("yarn dlx", s)),
        "npm" => after_subcommand(args, &["exec", "x"])
            .and_then(|rest| pick_spec(rest, NPX_VALUE_FLAGS, &["-p", "--package"]))
            .map(|s| npm("npm exec", s)),
        "uvx" => pick_spec(args, UVX_VALUE_FLAGS, &["--from"]).map(|s| pypi("uvx", s)),
        "uv" => after_subcommand(args, &["tool"])
            .and_then(|rest| after_subcommand(rest, &["run"]))
            .and_then(|rest| pick_spec(rest, UVX_VALUE_FLAGS, &["--from"]))
            .map(|s| pypi("uv tool run", s)),
        "pipx" => after_subcommand(args, &["run"])
            .and_then(|rest| pick_spec(rest, PIPX_VALUE_FLAGS, &["--spec"]))
            .map(|s| pypi("pipx run", s)),
        _ => None,
    }
}

static SEMVER_EXACT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$").expect("static semver")
});
static PEP440_EXACT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^v?\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*(?:\+[a-z0-9.]+)?$")
        .expect("static pep440")
});
static GIT_PINNED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[#@][0-9a-f]{7,40}$").expect("static git pin"));

fn is_local(spec: &str) -> bool {
    spec.starts_with(['.', '/', '~']) || spec.starts_with("file:") || spec.contains('\\')
}

fn is_remote(spec: &str) -> bool {
    spec.contains("://") || spec.starts_with("git+") || spec.starts_with("github:")
}

/// npm `name[@version]` (scoped names keep their leading `@`).
pub fn split_npm_spec(spec: &str) -> (String, Option<String>) {
    let at = if let Some(rest) = spec.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        spec.find('@')
    };
    match at {
        Some(i) => (spec[..i].to_string(), Some(spec[i + 1..].to_string())),
        None => (spec.to_string(), None),
    }
}

/// `Some(true)` exact, `Some(false)` unpinned, `None` not a registry
/// package (local path).
pub fn spec_is_exact(launch: &Launch) -> Option<bool> {
    let spec = launch.spec.as_str();
    if is_local(spec) {
        return None;
    }
    if is_remote(spec) {
        return Some(GIT_PINNED_RE.is_match(spec));
    }
    Some(match launch.registry {
        Registry::Npm => split_npm_spec(spec)
            .1
            .is_some_and(|v| SEMVER_EXACT_RE.is_match(&v)),
        Registry::PyPi => {
            if let Some((_, v)) = spec.split_once("===").or_else(|| spec.split_once("==")) {
                !v.contains([',', '*']) && PEP440_EXACT_RE.is_match(v.trim())
            } else if let Some((_, v)) = spec.split_once('@') {
                PEP440_EXACT_RE.is_match(v.trim())
            } else {
                false
            }
        }
    })
}

// ── rules ────────────────────────────────────────────────────────────────

static ENV_REF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{?(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}?|\{env:[A-Za-z_][A-Za-z0-9_]*\}")
        .expect("static env reference")
});

/// A literal (not `${VAR}`-style) value that looks like a credential.
fn literal_secret(key: &str, value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || ENV_REF_RE.is_match(v) {
        return false;
    }
    is_secret_shaped(v) || (is_secret_name(key) && v.chars().count() >= 8)
}

fn object_pairs<'a>(raw: &'a Value, key: &str) -> Vec<(&'a str, String)> {
    raw.get(key)
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.as_str(), value_text(v))).collect())
        .unwrap_or_default()
}

/// Every MCP rule except MC002 for one entry.
pub fn entry_rules(entry: &McpEntry, file: &Path, line: Option<usize>, out: &mut Vec<RawFinding>) {
    if let Some(cl) = entry.display_command_line() {
        rules::scan_command(Some(file), line, &cl, out);
    }
    if let Some(u) = entry.display_url() {
        rules::scan_command(Some(file), line, &u, out);
    }
    mc001(entry, file, line, out);
    mc003(entry, file, line, out);
    mc004(entry, file, line, out);
    mc005(entry, file, line, out);
}

fn mc001(entry: &McpEntry, file: &Path, line: Option<usize>, out: &mut Vec<RawFinding>) {
    let Some(cmd) = entry.command() else { return };
    let Some(launch) = launcher_package(cmd, &entry.args()) else {
        return;
    };
    if spec_is_exact(&launch) == Some(false) {
        out.push(RawFinding::new(
            "MC001",
            Severity::Medium,
            Some(file),
            line,
            &format!(
                "`{}` runs {} without an exact version (missing, latest or a range); every start may fetch different code",
                launch.launcher,
                redact_args(std::slice::from_ref(&launch.spec), Redact::Display)[0]
            ),
            &entry.display_command_line().unwrap_or_default(),
        ));
    }
}

fn loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost")
        || h.to_ascii_lowercase().ends_with(".localhost")
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn mc003(entry: &McpEntry, file: &Path, line: Option<usize>, out: &mut Vec<RawFinding>) {
    let Some(u) = entry.url() else { return };
    let Ok(url) = reqwest::Url::parse(u) else {
        return;
    };
    if url.scheme() == "http" && !url.host_str().is_some_and(loopback) {
        out.push(RawFinding::new(
            "MC003",
            Severity::High,
            Some(file),
            line,
            "MCP server reached over plain http:// to a non-loopback host (traffic and tokens are readable and modifiable on the network)",
            &entry.display_url().unwrap_or_default(),
        ));
    }
}

fn mc004(entry: &McpEntry, file: &Path, line: Option<usize>, out: &mut Vec<RawFinding>) {
    let mut hits: Vec<String> = Vec::new();
    for container in SECRET_CONTAINERS {
        for (k, v) in object_pairs(&entry.raw, container) {
            if literal_secret(k, &v) {
                hits.push(format!("{container} {k} {}", redacted(&v)));
            }
        }
    }
    let args = entry.args();
    for (i, a) in args.iter().enumerate() {
        let prev = i.checked_sub(1).map(|j| args[j].as_str());
        if secret_arg(prev, a) && !ENV_REF_RE.is_match(a) {
            hits.push(format!("args[{i}] {}", redacted(a)));
        }
    }
    for h in hits {
        out.push(RawFinding::new(
            "MC004",
            Severity::Medium,
            Some(file),
            line,
            "literal secret in the MCP entry (value redacted); prefer an environment reference",
            &h,
        ));
    }
}

const TEMP_DIRS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "/private/var/tmp/",
    "/dev/shm/",
];

fn risky_command(cmd: &str) -> Option<&'static str> {
    if !cmd.contains(['/', '\\']) || cmd.starts_with('$') || cmd.starts_with("~/") {
        return None;
    }
    let windows_abs = cmd.len() > 2 && cmd.as_bytes()[1] == b':';
    if !cmd.starts_with('/') && !windows_abs {
        return Some(
            "relative command path (resolved against whatever directory the agent starts in)",
        );
    }
    if TEMP_DIRS.iter().any(|t| cmd.starts_with(t)) {
        return Some("command under a temporary directory");
    }
    if world_writable_parent(Path::new(cmd)) {
        return Some("command in a world-writable directory");
    }
    None
}

fn world_writable_parent(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.parent()
            .and_then(|p| std::fs::metadata(p).ok())
            .is_some_and(|m| m.permissions().mode() & 0o002 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn mc005(entry: &McpEntry, file: &Path, line: Option<usize>, out: &mut Vec<RawFinding>) {
    let Some(cmd) = entry.command() else { return };
    if let Some(why) = risky_command(cmd) {
        out.push(RawFinding::new(
            "MC005",
            Severity::Medium,
            Some(file),
            line,
            why,
            &entry.display_command_line().unwrap_or_default(),
        ));
    }
}

#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;
