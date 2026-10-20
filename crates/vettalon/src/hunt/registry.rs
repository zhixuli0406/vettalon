//! Registry release facts for malicious-package signals (O18).
//!
//! Per dependency: does the name exist, when was the locked version published,
//! which version preceded it, which install-time hooks each of the two versions
//! carries, and (npm) whether build provenance changed. Parsers are pure and
//! tested on fixtures; HTTP goes through [`HttpGet`] so tests use a fake, and
//! the live client reuses the hunt registry allowlist (`fetch::ALLOWED_HOSTS`):
//! new paths on already-allowlisted hosts, documented in DATA-FLOW.md.
//! Nothing here executes package code; archives are only extracted and read.

use std::path::Path;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::fetch::{SourceFetcher, escape_go_module, host_allowed};
use super::{DependencyTarget, Ecosystem};

/// Install-time hooks found in one version, with a digest to detect changes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptFacts {
    pub hooks: Vec<String>,
    pub digest: Option<String>,
}

/// Build provenance of one version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Provenance {
    #[default]
    Unknown,
    Absent,
    /// Attestation present; workflow fields are `None` when not fetched/parsed.
    Present {
        repository: Option<String>,
        workflow: Option<String>,
        /// `tags` | `heads` | `other`, from the workflow ref.
        ref_kind: Option<String>,
    },
}

/// What the registry says about the locked version and its predecessor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseFacts {
    /// `Some(false)` when the registry has no such package/version.
    pub exists: Option<bool>,
    /// npm security holding package (`0.0.1-security`): the name was taken down.
    pub placeholder: bool,
    pub published_at: Option<DateTime<Utc>>,
    pub previous_version: Option<String>,
    pub scripts: Option<ScriptFacts>,
    pub previous_scripts: Option<ScriptFacts>,
    pub provenance: Provenance,
    pub previous_provenance: Provenance,
    /// Rules that could not be evaluated, with a reason (never silently clean).
    pub notes: Vec<String>,
}

/// Minimal GET abstraction: `(status, body)`. Live code enforces host + caps.
#[async_trait]
pub trait HttpGet: Send + Sync {
    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String>;
}

/// Source of [`ReleaseFacts`].
#[async_trait]
pub trait RegistryProbe: Send + Sync {
    async fn release_facts(&self, target: &DependencyTarget) -> Result<ReleaseFacts, String>;
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// The version published most recently before `current` (by registry time).
fn previous_by_time<'a>(
    times: impl Iterator<Item = (&'a str, DateTime<Utc>)>,
    current: DateTime<Utc>,
) -> Option<String> {
    times
        .filter(|(_, t)| *t < current)
        .max_by_key(|(_, t)| *t)
        .map(|(v, _)| v.to_string())
}

// ── npm ──────────────────────────────────────────────────────────────────

const NPM_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

fn npm_scripts(version_doc: &serde_json::Value) -> ScriptFacts {
    let mut hooks = Vec::new();
    let mut material = String::new();
    if let Some(scripts) = version_doc.get("scripts").and_then(|s| s.as_object()) {
        for hook in NPM_HOOKS {
            if let Some(cmd) = scripts.get(*hook).and_then(|c| c.as_str()) {
                hooks.push((*hook).to_string());
                material.push_str(&format!("{hook}={cmd}\n"));
            }
        }
    }
    // A binding.gyp without an explicit install script runs `node-gyp rebuild`.
    if version_doc.get("gypfile").and_then(|g| g.as_bool()) == Some(true)
        && !hooks.iter().any(|h| h == "install" || h == "preinstall")
    {
        hooks.push("install (implicit node-gyp)".into());
        material.push_str("gypfile\n");
    }
    ScriptFacts {
        digest: (!material.is_empty()).then(|| sha256_hex(material.as_bytes())),
        hooks,
    }
}

fn npm_provenance(version_doc: &serde_json::Value) -> Provenance {
    if version_doc
        .pointer("/dist/attestations/provenance")
        .is_some()
    {
        Provenance::Present {
            repository: None,
            workflow: None,
            ref_kind: None,
        }
    } else {
        Provenance::Absent
    }
}

/// Facts from a full npm packument (`GET registry.npmjs.org/<name>`).
pub fn npm_facts(packument: &serde_json::Value, version: &str) -> ReleaseFacts {
    let mut facts = ReleaseFacts::default();
    let versions = packument.get("versions").and_then(|v| v.as_object());
    facts.placeholder = versions.is_some_and(|v| v.keys().any(|k| k.ends_with("-security")))
        && packument
            .pointer("/dist-tags/latest")
            .and_then(|l| l.as_str())
            .is_some_and(|l| l.ends_with("-security"));
    let Some(doc) = versions.and_then(|v| v.get(version)) else {
        facts.exists = Some(false);
        facts
            .notes
            .push("locked version is not in the registry packument".into());
        return facts;
    };
    facts.exists = Some(true);
    let times = packument.get("time").and_then(|t| t.as_object());
    facts.published_at = times
        .and_then(|t| t.get(version))
        .and_then(|t| t.as_str())
        .and_then(parse_time);
    if let (Some(times), Some(current)) = (times, facts.published_at) {
        facts.previous_version = previous_by_time(
            times
                .iter()
                .filter(|(k, _)| versions.is_some_and(|v| v.contains_key(*k)))
                .filter_map(|(k, v)| Some((k.as_str(), parse_time(v.as_str()?)?))),
            current,
        );
    }
    facts.scripts = Some(npm_scripts(doc));
    facts.provenance = npm_provenance(doc);
    match facts
        .previous_version
        .as_ref()
        .and_then(|p| versions.and_then(|v| v.get(p)))
    {
        Some(prev) => {
            facts.previous_scripts = Some(npm_scripts(prev));
            facts.previous_provenance = npm_provenance(prev);
        }
        None => facts
            .notes
            .push("no earlier version to compare install scripts/provenance".into()),
    }
    facts
}

/// Standard base64 (RFC 4648) decoder for DSSE payloads; no new dependency.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Workflow identity from an npm attestations reply
/// (`GET registry.npmjs.org/-/npm/v1/attestations/<name>@<version>`).
pub fn parse_npm_attestation(body: &str) -> Option<Provenance> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let att = v.get("attestations")?.as_array()?.iter().find(|a| {
        a.get("predicateType")
            .and_then(|p| p.as_str())
            .is_some_and(|p| p.contains("slsa.dev/provenance"))
    })?;
    let payload = att.pointer("/bundle/dsseEnvelope/payload")?.as_str()?;
    let statement: serde_json::Value = serde_json::from_slice(&base64_decode(payload)?).ok()?;
    let wf = statement.pointer("/predicate/buildDefinition/externalParameters/workflow")?;
    let s = |k: &str| wf.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let ref_kind = s("ref").map(|r| {
        if r.starts_with("refs/tags/") {
            "tags".to_string()
        } else if r.starts_with("refs/heads/") {
            "heads".to_string()
        } else {
            "other".to_string()
        }
    });
    Some(Provenance::Present {
        repository: s("repository"),
        workflow: s("path"),
        ref_kind,
    })
}

// ── crates.io ────────────────────────────────────────────────────────────

/// Facts from `GET crates.io/api/v1/crates/<name>` (scripts filled separately).
pub fn crates_facts(body: &serde_json::Value, version: &str) -> ReleaseFacts {
    let mut facts = ReleaseFacts::default();
    let versions: Vec<(&str, Option<DateTime<Utc>>, bool)> = body
        .get("versions")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| {
            Some((
                v.get("num")?.as_str()?,
                v.get("created_at")
                    .and_then(|c| c.as_str())
                    .and_then(parse_time),
                v.get("yanked").and_then(|y| y.as_bool()).unwrap_or(false),
            ))
        })
        .collect();
    let Some((_, created, _)) = versions.iter().find(|(n, _, _)| *n == version) else {
        facts.exists = Some(false);
        facts
            .notes
            .push("locked version is not listed on crates.io".into());
        return facts;
    };
    facts.exists = Some(true);
    facts.published_at = *created;
    if let Some(current) = facts.published_at {
        facts.previous_version = previous_by_time(
            versions
                .iter()
                .filter(|(_, _, yanked)| !yanked)
                .filter_map(|(n, t, _)| Some((*n, (*t)?))),
            current,
        );
    }
    facts.provenance = Provenance::Unknown;
    facts
        .notes
        .push("provenance: not published by crates.io (not evaluated)".into());
    facts
}

/// Build-script facts of an extracted crate (`build.rs` or `package.build`).
pub fn cargo_build_script(extracted: &Path) -> ScriptFacts {
    let root = package_root(extracted);
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    let declared = toml::from_str::<toml::Value>(&manifest)
        .ok()
        .and_then(|m| m.get("package")?.get("build").cloned());
    let path = match declared {
        Some(toml::Value::Boolean(false)) => None,
        Some(toml::Value::String(p)) => Some(p),
        _ => Some("build.rs".to_string()),
    };
    match path.and_then(|p| read_inside(&root, &p).map(|b| (p, b))) {
        Some((p, bytes)) => ScriptFacts {
            hooks: vec![format!("build script {p}")],
            digest: Some(sha256_hex(&bytes)),
        },
        None => ScriptFacts::default(),
    }
}

/// Upper bound for a single file read out of an extracted archive.
const MAX_INSIDE_READ: u64 = 4 * 1024 * 1024;

/// Read `rel` (named by the untrusted package) only when it is a relative path
/// inside `root` that resolves to a regular file; bounded in size.
fn read_inside(root: &Path, rel: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    if !super::fetch::is_safe_relative(Path::new(rel)) {
        return None;
    }
    let path = root.join(rel);
    if !std::fs::symlink_metadata(&path).ok()?.file_type().is_file() {
        return None;
    }
    let mut out = Vec::new();
    std::fs::File::open(&path)
        .ok()?
        .take(MAX_INSIDE_READ)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

// ── PyPI ────────────────────────────────────────────────────────────────

/// Facts from `GET pypi.org/pypi/<name>/json` (scripts filled separately).
pub fn pypi_facts(body: &serde_json::Value, version: &str) -> ReleaseFacts {
    let mut facts = ReleaseFacts::default();
    let Some(releases) = body.get("releases").and_then(|r| r.as_object()) else {
        // An unexpected body shape proves nothing about the name.
        facts
            .notes
            .push("existence: PyPI response has no releases object".into());
        return facts;
    };
    let first_upload = |files: &serde_json::Value| -> Option<DateTime<Utc>> {
        files
            .as_array()?
            .iter()
            .filter_map(|f| f.get("upload_time_iso_8601")?.as_str().and_then(parse_time))
            .min()
    };
    let Some(files) = releases.get(version) else {
        facts.exists = Some(false);
        facts
            .notes
            .push("locked version is not listed on PyPI".into());
        return facts;
    };
    facts.exists = Some(true);
    facts.published_at = first_upload(files);
    if let Some(current) = facts.published_at {
        facts.previous_version = previous_by_time(
            releases
                .iter()
                .filter_map(|(v, f)| Some((v.as_str(), first_upload(f)?))),
            current,
        );
    }
    facts
        .notes
        .push("provenance: PyPI attestations not evaluated".into());
    facts
}

/// Install-time hooks in an extracted sdist/wheel: `setup.py` `cmdclass`
/// overrides of install-ish commands, and `.pth` files (run at interpreter start).
pub fn python_install_hooks(extracted: &Path) -> ScriptFacts {
    const COMMANDS: &[&str] = &[
        "install",
        "develop",
        "egg_info",
        "build_py",
        "build_ext",
        "bdist_egg",
        "bdist_wheel",
    ];
    let root = package_root(extracted);
    let mut hooks = Vec::new();
    let mut material = Vec::new();
    if let Ok(setup) = std::fs::read_to_string(root.join("setup.py"))
        && setup.contains("cmdclass")
    {
        let re = regex::Regex::new(r#"['"]([a-z_]+)['"]\s*:"#).expect("static regex");
        let mut found: Vec<String> = re
            .captures_iter(&setup)
            .map(|c| c[1].to_string())
            .filter(|c| COMMANDS.contains(&c.as_str()))
            .collect();
        found.sort();
        found.dedup();
        if found.is_empty() {
            found.push("cmdclass (commands not parsed)".into());
        }
        hooks.extend(found.into_iter().map(|c| format!("setup.py cmdclass {c}")));
        material.extend_from_slice(setup.as_bytes());
    }
    let mut pth: Vec<_> = walk_files(&root, 4)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "pth"))
        .collect();
    pth.sort();
    for p in pth {
        if let Ok(bytes) = std::fs::read(&p) {
            hooks.push(format!(
                ".pth file {}",
                p.file_name().unwrap_or_default().to_string_lossy()
            ));
            material.extend_from_slice(&bytes);
        }
    }
    ScriptFacts {
        digest: (!material.is_empty()).then(|| sha256_hex(&material)),
        hooks,
    }
}

// ── Go ─────────────────────────────────────────────────────────────────

fn semver_key(v: &str) -> Option<(u64, u64, u64, bool)> {
    let core = v.strip_prefix('v')?;
    let (core, pre) = match core.split_once(['-', '+']) {
        Some((c, _)) => (c, true),
        None => (core, false),
    };
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??, !pre))
}

/// Facts from the Go proxy `@v/<ver>.info` and `@v/list` bodies.
pub fn go_facts(info: &serde_json::Value, list: &str, version: &str) -> ReleaseFacts {
    let mut facts = ReleaseFacts {
        exists: Some(true),
        published_at: info
            .get("Time")
            .and_then(|t| t.as_str())
            .and_then(parse_time),
        ..Default::default()
    };
    if let Some(cur) = semver_key(version) {
        facts.previous_version = list
            .lines()
            .map(str::trim)
            .filter_map(|v| Some((v, semver_key(v)?)))
            .filter(|(_, k)| *k < cur)
            .max_by_key(|(_, k)| *k)
            .map(|(v, _)| v.to_string());
    }
    facts
        .notes
        .push("install scripts: Go modules have no install hooks (not applicable)".into());
    facts
        .notes
        .push("provenance: not published by the Go proxy (not evaluated)".into());
    facts
}

// ── helpers ──────────────────────────────────────────────────────────────

/// npm registry path form of a name: `@scope/pkg` → `@scope%2fpkg`.
pub fn npm_escape(name: &str) -> String {
    match name.strip_prefix('@') {
        Some(rest) => format!("@{}", rest.replacen('/', "%2f", 1)),
        None => name.to_string(),
    }
}

fn package_root(extracted: &Path) -> std::path::PathBuf {
    let dirs: Vec<_> = std::fs::read_dir(extracted)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    match dirs.as_slice() {
        [only] if only.is_dir() => only.clone(),
        _ => extracted.to_path_buf(),
    }
}

fn walk_files(root: &Path, depth: usize) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else {
        return out;
    };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_file() {
            out.push(e.path());
        } else if ft.is_dir() && depth > 0 {
            out.extend(walk_files(&e.path(), depth - 1));
        }
    }
    out
}

// ── live probe ───────────────────────────────────────────────────────────

/// Max registry metadata body (large npm packuments are several MiB).
pub const MAX_META_BYTES: usize = 32 * 1024 * 1024;

/// Live GET restricted to the hunt registry allowlist.
pub struct HttpRegistryGet {
    http: reqwest::Client,
}

impl Default for HttpRegistryGet {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpRegistryGet {
    pub fn new() -> Self {
        HttpRegistryGet {
            http: super::fetch::fetch_client_builder()
                .user_agent(concat!(
                    "vettalon/",
                    env!("CARGO_PKG_VERSION"),
                    " (+https://github.com/zhixuli0406/vettalon)"
                ))
                .build()
                .expect("static registry HTTP client configuration"),
        }
    }
}

#[async_trait]
impl HttpGet for HttpRegistryGet {
    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String> {
        if !host_allowed(url) {
            return Err(format!("refusing a non-allowlisted host: {url}"));
        }
        let mut resp = self
            .http
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("registry request failed: {e}"))?;
        let status = resp.status().as_u16();
        let mut buf = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("registry read failed: {e}"))?
        {
            buf.extend_from_slice(&chunk);
            if buf.len() > MAX_META_BYTES {
                return Err("registry metadata exceeds the size cap".into());
            }
        }
        Ok((status, buf))
    }
}

/// Composes [`HttpGet`] (metadata) and [`SourceFetcher`] (archives for
/// build.rs / setup.py comparison). Both are injectable for offline tests.
pub struct LiveRegistryProbe<H: HttpGet, F: SourceFetcher> {
    pub http: H,
    pub fetcher: F,
}

impl<H: HttpGet, F: SourceFetcher> LiveRegistryProbe<H, F> {
    async fn json(&self, url: &str) -> Result<Option<serde_json::Value>, String> {
        let (status, body) = self.http.get(url).await?;
        match status {
            404 | 410 => Ok(None),
            200..=299 => serde_json::from_slice(&body)
                .map(Some)
                .map_err(|e| format!("{url}: not JSON: {e}")),
            s => Err(format!("{url} returned {s}")),
        }
    }

    async fn archive_scripts(
        &self,
        target: &DependencyTarget,
        version: &str,
        inspect: fn(&Path) -> ScriptFacts,
    ) -> Result<ScriptFacts, String> {
        let dir = tempfile::tempdir().map_err(|e| format!("scratch dir failed: {e}"))?;
        let t = DependencyTarget {
            version: version.to_string(),
            ..target.clone()
        };
        self.fetcher.fetch_into(&t, dir.path()).await?;
        Ok(inspect(dir.path()))
    }

    async fn fill_archive_scripts(
        &self,
        target: &DependencyTarget,
        facts: &mut ReleaseFacts,
        inspect: fn(&Path) -> ScriptFacts,
    ) {
        match self.archive_scripts(target, &target.version, inspect).await {
            Ok(s) => facts.scripts = Some(s),
            Err(e) => facts.notes.push(format!("install scripts (locked): {e}")),
        }
        if let Some(prev) = facts.previous_version.clone() {
            match self.archive_scripts(target, &prev, inspect).await {
                Ok(s) => facts.previous_scripts = Some(s),
                Err(e) => facts.notes.push(format!("install scripts (previous): {e}")),
            }
        }
    }
}

#[async_trait]
impl<H: HttpGet, F: SourceFetcher> RegistryProbe for LiveRegistryProbe<H, F> {
    async fn release_facts(&self, t: &DependencyTarget) -> Result<ReleaseFacts, String> {
        match t.ecosystem {
            Ecosystem::Npm => {
                let Some(doc) = self
                    .json(&format!(
                        "https://registry.npmjs.org/{}",
                        npm_escape(&t.name)
                    ))
                    .await?
                else {
                    return Ok(ReleaseFacts {
                        exists: Some(false),
                        ..Default::default()
                    });
                };
                let mut facts = npm_facts(&doc, &t.version);
                // Workflow identity only matters when both versions attest.
                if matches!(facts.provenance, Provenance::Present { .. })
                    && matches!(facts.previous_provenance, Provenance::Present { .. })
                    && let Some(prev) = facts.previous_version.clone()
                {
                    for (version, slot) in [(t.version.clone(), 0), (prev, 1)] {
                        let url = format!(
                            "https://registry.npmjs.org/-/npm/v1/attestations/{}@{version}",
                            npm_escape(&t.name)
                        );
                        match self.http.get(&url).await {
                            Ok((200, body)) => {
                                if let Some(p) =
                                    parse_npm_attestation(&String::from_utf8_lossy(&body))
                                {
                                    if slot == 0 {
                                        facts.provenance = p;
                                    } else {
                                        facts.previous_provenance = p;
                                    }
                                }
                            }
                            Ok((s, _)) => facts.notes.push(format!("attestations {version}: {s}")),
                            Err(e) => facts.notes.push(format!("attestations {version}: {e}")),
                        }
                    }
                }
                Ok(facts)
            }
            Ecosystem::Cargo => {
                let Some(doc) = self
                    .json(&format!("https://crates.io/api/v1/crates/{}", t.name))
                    .await?
                else {
                    return Ok(ReleaseFacts {
                        exists: Some(false),
                        ..Default::default()
                    });
                };
                let mut facts = crates_facts(&doc, &t.version);
                if facts.exists == Some(true) {
                    self.fill_archive_scripts(t, &mut facts, cargo_build_script)
                        .await;
                }
                Ok(facts)
            }
            Ecosystem::PyPi => {
                let Some(doc) = self
                    .json(&format!("https://pypi.org/pypi/{}/json", t.name))
                    .await?
                else {
                    return Ok(ReleaseFacts {
                        exists: Some(false),
                        ..Default::default()
                    });
                };
                let mut facts = pypi_facts(&doc, &t.version);
                if facts.exists == Some(true) {
                    self.fill_archive_scripts(t, &mut facts, python_install_hooks)
                        .await;
                }
                Ok(facts)
            }
            Ecosystem::Go => {
                let base = format!("https://proxy.golang.org/{}/@v", escape_go_module(&t.name));
                let Some(info) = self.json(&format!("{base}/{}.info", t.version)).await? else {
                    return Ok(ReleaseFacts {
                        exists: Some(false),
                        ..Default::default()
                    });
                };
                let (list, note) = match self.http.get(&format!("{base}/list")).await {
                    Ok((200, body)) => (String::from_utf8_lossy(&body).into_owned(), None),
                    Ok((status, _)) => {
                        (String::new(), Some(format!("version list: HTTP {status}")))
                    }
                    Err(e) => (String::new(), Some(format!("version list: {e}"))),
                };
                let mut facts = go_facts(&info, &list, &t.version);
                facts.notes.extend(note);
                Ok(facts)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn sha256_hex_is_pinned() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    pub(crate) fn npm_packument() -> serde_json::Value {
        // Modelled on the 2025 npm worm pattern: a patch release adds a
        // postinstall hook and drops provenance. Metadata only, no payload.
        serde_json::json!({
            "dist-tags": {"latest": "4.2.1"},
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "4.1.0": "2025-01-10T00:00:00.000Z",
                "4.2.0": "2025-06-01T00:00:00.000Z",
                "4.2.1": "2026-10-19T22:00:00.000Z"
            },
            "versions": {
                "4.1.0": {"scripts": {"test": "jest"}},
                "4.2.0": {"scripts": {"test": "jest"}, "dist": {"attestations": {"provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}}},
                "4.2.1": {"scripts": {"test": "jest", "postinstall": "node bundle.js"}}
            }
        })
    }

    #[test]
    fn npm_facts_compare_scripts_time_and_provenance_with_previous() {
        let f = npm_facts(&npm_packument(), "4.2.1");
        assert_eq!(f.exists, Some(true));
        assert_eq!(f.previous_version.as_deref(), Some("4.2.0"));
        assert_eq!(f.scripts.as_ref().unwrap().hooks, vec!["postinstall"]);
        assert!(f.previous_scripts.as_ref().unwrap().hooks.is_empty());
        assert_eq!(f.provenance, Provenance::Absent);
        assert!(matches!(f.previous_provenance, Provenance::Present { .. }));
        assert_eq!(
            f.published_at.unwrap().to_rfc3339(),
            "2026-10-19T22:00:00+00:00"
        );
        let missing = npm_facts(&npm_packument(), "9.9.9");
        assert_eq!(missing.exists, Some(false));
    }

    #[test]
    fn npm_security_placeholder_and_implicit_gyp_install_are_detected() {
        let doc = serde_json::json!({
            "dist-tags": {"latest": "0.0.1-security"},
            "time": {"0.0.1-security": "2026-01-01T00:00:00Z"},
            "versions": {"0.0.1-security": {"description": "security holding package"}}
        });
        assert!(npm_facts(&doc, "1.0.0").placeholder);
        let gyp = npm_scripts(&serde_json::json!({"gypfile": true}));
        assert_eq!(gyp.hooks, vec!["install (implicit node-gyp)"]);
    }

    #[test]
    fn npm_attestation_workflow_is_decoded() {
        let statement = serde_json::json!({"predicate":{"buildDefinition":{"externalParameters":{
            "workflow":{"ref":"refs/heads/main","repository":"https://github.com/o/r","path":".github/workflows/release.yml"}}}}});
        let payload = b64(&serde_json::to_vec(&statement).unwrap());
        let body = serde_json::json!({"attestations":[
            {"predicateType":"https://github.com/npm/attestation/tree/main/specs/publish/v0.1","bundle":{}},
            {"predicateType":"https://slsa.dev/provenance/v1","bundle":{"dsseEnvelope":{"payload":payload}}}
        ]});
        let p = parse_npm_attestation(&body.to_string()).unwrap();
        assert_eq!(
            p,
            Provenance::Present {
                repository: Some("https://github.com/o/r".into()),
                workflow: Some(".github/workflows/release.yml".into()),
                ref_kind: Some("heads".into()),
            }
        );
        assert!(parse_npm_attestation("{}").is_none());
    }

    fn b64(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = chunk.len();
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= n {
                    out.push(A[((v >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn base64_round_trips_all_lengths() {
        for s in ["", "a", "ab", "abc", "abcd", "{\"x\":1}"] {
            assert_eq!(base64_decode(&b64(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert!(base64_decode("@@").is_none());
    }

    #[test]
    fn crates_and_pypi_and_go_facts_pick_previous_by_time() {
        let crates = serde_json::json!({"versions":[
            {"num":"0.3.0","created_at":"2026-10-20T00:00:00Z","yanked":false},
            {"num":"0.2.9","created_at":"2026-09-01T00:00:00Z","yanked":true},
            {"num":"0.2.8","created_at":"2026-08-01T00:00:00Z","yanked":false}
        ]});
        let c = crates_facts(&crates, "0.3.0");
        assert_eq!(
            c.previous_version.as_deref(),
            Some("0.2.8"),
            "yanked skipped"
        );
        assert_eq!(crates_facts(&crates, "1.0.0").exists, Some(false));
        let pypi = serde_json::json!({"releases":{
            "1.0.0":[{"upload_time_iso_8601":"2024-01-01T00:00:00Z"}],
            "1.0.1":[{"upload_time_iso_8601":"2026-10-19T00:00:00Z"},{"upload_time_iso_8601":"2026-10-19T01:00:00Z"}]
        }});
        let p = pypi_facts(&pypi, "1.0.1");
        assert_eq!(p.previous_version.as_deref(), Some("1.0.0"));
        assert_eq!(
            p.published_at.unwrap().to_rfc3339(),
            "2026-10-19T00:00:00+00:00"
        );
        let g = go_facts(
            &serde_json::json!({"Version":"v1.2.0","Time":"2026-10-01T00:00:00Z"}),
            "v1.0.0\nv1.1.9\nv1.2.0\nv1.3.0-rc.1\n",
            "v1.2.0",
        );
        assert_eq!(g.previous_version.as_deref(), Some("v1.1.9"));
        assert!(g.notes.iter().any(|n| n.contains("not applicable")));
    }

    #[test]
    fn archive_inspectors_find_build_rs_setup_hooks_and_pth() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("crate-1.0.0");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='c'\nversion='1.0.0'\n",
        )
        .unwrap();
        assert!(cargo_build_script(dir.path()).hooks.is_empty());
        std::fs::write(root.join("build.rs"), "fn main(){}").unwrap();
        let b = cargo_build_script(dir.path());
        assert_eq!(b.hooks, vec!["build script build.rs"]);
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='c'\nversion='1.0.0'\nbuild=false\n",
        )
        .unwrap();
        assert!(cargo_build_script(dir.path()).hooks.is_empty());

        let py = tempfile::tempdir().unwrap();
        let root = py.path().join("pkg-1.0");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("setup.py"),
            "from setuptools import setup\nsetup(name='p', cmdclass={'install': Hook, \"egg_info\": E})\n",
        )
        .unwrap();
        std::fs::write(root.join("evil.pth"), "import os").unwrap();
        let h = python_install_hooks(py.path());
        assert_eq!(
            h.hooks,
            vec![
                "setup.py cmdclass egg_info",
                "setup.py cmdclass install",
                ".pth file evil.pth"
            ]
        );
        assert!(h.digest.is_some());
    }

    struct FakeHttp(HashMap<String, (u16, String)>);
    #[async_trait]
    impl HttpGet for FakeHttp {
        async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String> {
            self.0
                .get(url)
                .map(|(s, b)| (*s, b.clone().into_bytes()))
                .ok_or_else(|| format!("unexpected URL in test: {url}"))
        }
    }

    struct FakeFetch;
    #[async_trait]
    impl SourceFetcher for FakeFetch {
        async fn fetch_into(
            &self,
            t: &DependencyTarget,
            dest: &Path,
        ) -> Result<super::super::fetch::ExtractStats, String> {
            let root = dest.join(format!("{}-{}", t.name, t.version));
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
            if t.version == "0.3.0" {
                std::fs::write(root.join("build.rs"), "fn main(){}").unwrap();
            }
            Ok(super::super::fetch::ExtractStats { files: 1, bytes: 1 })
        }
    }

    #[tokio::test]
    async fn live_probe_composes_metadata_and_archives_offline() {
        let mut routes = HashMap::new();
        routes.insert(
            "https://crates.io/api/v1/crates/evil".to_string(),
            (
                200,
                serde_json::json!({"versions":[
                    {"num":"0.3.0","created_at":"2026-10-19T00:00:00Z"},
                    {"num":"0.2.8","created_at":"2026-08-01T00:00:00Z"}]})
                .to_string(),
            ),
        );
        routes.insert(
            "https://registry.npmjs.org/ghost".to_string(),
            (404, "{}".to_string()),
        );
        let probe = LiveRegistryProbe {
            http: FakeHttp(routes),
            fetcher: FakeFetch,
        };
        let t = |eco, name: &str, v: &str| DependencyTarget {
            ecosystem: eco,
            name: name.into(),
            version: v.into(),
            direct: true,
        };
        let f = probe
            .release_facts(&t(Ecosystem::Cargo, "evil", "0.3.0"))
            .await
            .unwrap();
        assert_eq!(f.scripts.unwrap().hooks, vec!["build script build.rs"]);
        assert!(f.previous_scripts.unwrap().hooks.is_empty());
        let ghost = probe
            .release_facts(&t(Ecosystem::Npm, "ghost", "1.0.0"))
            .await
            .unwrap();
        assert_eq!(ghost.exists, Some(false));
    }
}
