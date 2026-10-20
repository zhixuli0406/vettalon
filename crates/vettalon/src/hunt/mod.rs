//! Supply-chain hunt: offline dependency intake for Cargo, npm, PyPI and Go.
//!
//! Resolve a project's third-party OSS dependencies from its lockfile into
//! audit targets. This phase is OFFLINE and pure: fetching each dependency's
//! source, the OSV novelty check, and the hunt orchestration live in sibling
//! modules (`osv`, `fetch`, `run`). Intake itself is offline; subsequent
//! OSV/registry lookups and selected model providers have separate network flows.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub mod fetch;
pub mod graph;
pub mod mal_index;
pub mod malicious;
pub mod osv;
pub mod popular;
pub mod priority;
pub mod registry;
pub mod rule_draft;
pub mod run;
pub mod seeds;

/// The package ecosystem a dependency comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Cargo,
    Npm,
    PyPi,
    Go,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
            Ecosystem::Go => "go",
        }
    }
}

/// One third-party dependency to hunt in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyTarget {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// A direct (first-level) dependency of the project, vs a transitive one.
    /// Direct dependencies are hunted first: the largest blast radius, and the
    /// ones the project can actually act on (pin, patch, replace).
    pub direct: bool,
}

// ── Cargo ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    /// Registry / git origin. Local workspace members have no `source`, so
    /// this separates third-party crates from the project's own.
    #[serde(default)]
    source: Option<String>,
    /// `"name"`, `"name version"` or `"name version (source)"` entries.
    #[serde(default)]
    dependencies: Vec<String>,
}

/// The direct dependency names declared in a `Cargo.toml` — the keys of
/// `[dependencies]`, `[build-dependencies]` and `[dev-dependencies]`. Build
/// dependencies run at build time, so they are a supply-chain surface too.
/// A malformed manifest yields an empty set (every target is then treated as
/// transitive) rather than an error: intake must still produce targets.
pub fn cargo_direct_deps(manifest_text: &str) -> HashSet<String> {
    #[derive(Deserialize)]
    struct Manifest {
        #[serde(default)]
        dependencies: toml::Table,
        #[serde(default, rename = "build-dependencies")]
        build_dependencies: toml::Table,
        #[serde(default, rename = "dev-dependencies")]
        dev_dependencies: toml::Table,
    }
    let Ok(m) = toml::from_str::<Manifest>(manifest_text) else {
        return HashSet::new();
    };
    m.dependencies
        .keys()
        .chain(m.build_dependencies.keys())
        .chain(m.dev_dependencies.keys())
        .cloned()
        .collect()
}

/// Parse a `Cargo.lock` into hunt targets. Only third-party crates (those with
/// a `source`) are returned; the project's own workspace members (no `source`)
/// are excluded — we hunt in OSS we depend on, not our own code. `direct_names`
/// (from [`cargo_direct_deps`], empty if unknown) marks first-level deps.
///
/// Targets are de-duplicated on `(name, version)` and ordered deterministically:
/// direct dependencies first, then by name, then by version.
pub fn parse_cargo_lock(
    lock_text: &str,
    direct_names: &HashSet<String>,
) -> Result<Vec<DependencyTarget>, String> {
    let lock: CargoLock =
        toml::from_str(lock_text).map_err(|e| format!("Cargo.lock is not valid TOML: {e}"))?;
    // What the project's own packages (no `source`: the root crate or every
    // workspace member) depend on is the direct set. This also covers a
    // virtual workspace manifest, whose root Cargo.toml has no [dependencies].
    let mut direct_exact: HashSet<(String, String)> = HashSet::new();
    let mut direct_any: HashSet<String> = HashSet::new();
    for p in lock.package.iter().filter(|p| p.source.is_none()) {
        for dep in &p.dependencies {
            let mut parts = dep.split_whitespace();
            let Some(name) = parts.next() else { continue };
            match parts.next() {
                Some(version) => direct_exact.insert((name.to_string(), version.to_string())),
                None => direct_any.insert(name.to_string()),
            };
        }
    }
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut targets: Vec<DependencyTarget> = Vec::new();
    for p in lock.package {
        // No source = a local workspace member, not a third-party dependency.
        // An empty name or version names nothing that can be fetched.
        if p.source.is_none() || p.name.is_empty() || p.version.is_empty() {
            continue;
        }
        if !seen.insert((p.name.clone(), p.version.clone())) {
            continue;
        }
        let direct = direct_names.contains(&p.name)
            || direct_any.contains(&p.name)
            || direct_exact.contains(&(p.name.clone(), p.version.clone()));
        targets.push(DependencyTarget {
            ecosystem: Ecosystem::Cargo,
            name: p.name,
            version: p.version,
            direct,
        });
    }
    targets.sort_by(|a, b| {
        b.direct
            .cmp(&a.direct)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
    Ok(targets)
}

/// Read a project's `Cargo.lock` (+ `Cargo.toml` for direct-dep marking, if
/// present) from disk into hunt targets. Phase 0 convenience over
/// [`parse_cargo_lock]; higher phases add fetching and the novelty check.
pub fn cargo_targets_from_dir(project: &std::path::Path) -> Result<Vec<DependencyTarget>, String> {
    let lock_path = project.join("Cargo.lock");
    let lock_text = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("cannot read {}: {e}", lock_path.display()))?;
    let direct = std::fs::read_to_string(project.join("Cargo.toml"))
        .map(|t| cargo_direct_deps(&t))
        .unwrap_or_default();
    parse_cargo_lock(&lock_text, &direct)
}

// ── npm ────────────────────────────────────────────────────────────────

/// Parse an npm `package-lock.json` (v2/v3 `packages`, with a v1
/// `dependencies` fallback) into hunt targets. Direct dependencies are those
/// declared in the root package's `dependencies` / `devDependencies`.
pub fn parse_npm_lock(text: &str) -> Result<Vec<DependencyTarget>, String> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("package-lock.json is not valid JSON: {e}"))?;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<DependencyTarget> = Vec::new();

    if let Some(pkgs) = v.get("packages").and_then(|p| p.as_object()) {
        // v2/v3: the root package is the "" key; it and any workspace
        // members (keys outside node_modules/, e.g. "packages/api") are the
        // project's own code, and what they declare is the direct set.
        let is_own = |path: &str| !path.contains("node_modules/");
        let mut direct: HashSet<String> = HashSet::new();
        for (_, own) in pkgs.iter().filter(|(path, _)| is_own(path)) {
            for field in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(obj) = own.get(field).and_then(|d| d.as_object()) {
                    direct.extend(obj.keys().cloned());
                }
            }
        }
        for (path, meta) in pkgs {
            if is_own(path) {
                continue; // the root project or a workspace member, not a dependency
            }
            let name = match path.rsplit_once("node_modules/") {
                Some((_, n)) => n,
                None => continue,
            };
            let Some(version) = meta.get("version").and_then(|x| x.as_str()) else {
                continue; // link/workspace entries carry no concrete version
            };
            if name.is_empty()
                || version.is_empty()
                || !seen.insert((name.to_string(), version.to_string()))
            {
                continue;
            }
            out.push(DependencyTarget {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                version: version.to_string(),
                direct: direct.contains(name),
            });
        }
    } else if let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) {
        // v1: nested `dependencies`; top level is direct.
        collect_npm_v1(deps, true, &mut seen, &mut out);
    }
    sort_targets(&mut out);
    Ok(out)
}

fn collect_npm_v1(
    deps: &serde_json::Map<String, serde_json::Value>,
    direct: bool,
    seen: &mut HashSet<(String, String)>,
    out: &mut Vec<DependencyTarget>,
) {
    for (name, meta) in deps {
        if let Some(version) = meta.get("version").and_then(|x| x.as_str())
            && !name.is_empty()
            && !version.is_empty()
            && seen.insert((name.clone(), version.to_string()))
        {
            out.push(DependencyTarget {
                ecosystem: Ecosystem::Npm,
                name: name.clone(),
                version: version.to_string(),
                direct,
            });
        }
        if let Some(nested) = meta.get("dependencies").and_then(|d| d.as_object()) {
            collect_npm_v1(nested, false, seen, out);
        }
    }
}

// ── PyPI ───────────────────────────────────────────────────────────────

/// Parse a pip `requirements.txt` into hunt targets. Only exactly-pinned
/// (`name==version`) lines yield a target (a range has no single source to
/// fetch). Comments, options (`-r`, `-e`, `--hash`) and environment markers
/// are skipped. Entries are treated as direct (a requirements file is usually
/// the first-level set).
pub fn parse_requirements_txt(text: &str) -> Vec<DependencyTarget> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<DependencyTarget> = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        let spec = line.split(';').next().unwrap_or("").trim(); // drop markers
        let Some((name_part, rest)) = spec.split_once("==") else {
            continue; // only pinned deps
        };
        let name = name_part
            .split(['[', ' ', '<', '>', '!', '~', '='])
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let version = rest
            .trim()
            .split([' ', ',', ';'])
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if name.is_empty() || version.is_empty() || !seen.insert((name.clone(), version.clone())) {
            continue;
        }
        out.push(DependencyTarget {
            ecosystem: Ecosystem::PyPi,
            name,
            version,
            direct: true,
        });
    }
    sort_targets(&mut out);
    out
}

// ── Go ───────────────────────────────────────────────────────────────────

/// Module paths a `go.mod` requires directly (not marked `// indirect`).
pub fn go_direct_deps(gomod_text: &str) -> HashSet<String> {
    let mut direct = HashSet::new();
    let mut in_block = false;
    for raw in gomod_text.lines() {
        let line = raw.trim();
        if line.starts_with("require (") {
            in_block = true;
            continue;
        }
        if in_block && line == ")" {
            in_block = false;
            continue;
        }
        let body = if let Some(single) = line.strip_prefix("require ") {
            single.trim()
        } else if in_block {
            line
        } else {
            continue;
        };
        if body.is_empty() || body.contains("// indirect") {
            continue;
        }
        if let Some(module) = body.split_whitespace().next() {
            direct.insert(module.to_string());
        }
    }
    direct
}

/// Parse a `go.sum` into hunt targets. Each module appears on a zip-hash line
/// and a `/go.mod`-hash line; both collapse to one `(module, version)`.
/// `direct_modules` (from [`go_direct_deps`], empty if unknown) marks
/// first-level requires.
pub fn parse_go_sum(sum_text: &str, direct_modules: &HashSet<String>) -> Vec<DependencyTarget> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<DependencyTarget> = Vec::new();
    for line in sum_text.lines() {
        let mut it = line.split_whitespace();
        let (Some(module), Some(raw_version)) = (it.next(), it.next()) else {
            continue;
        };
        let version = raw_version.trim_end_matches("/go.mod");
        // A bare `/go.mod` field leaves no version to fetch.
        if version.is_empty() || !seen.insert((module.to_string(), version.to_string())) {
            continue;
        }
        out.push(DependencyTarget {
            ecosystem: Ecosystem::Go,
            name: module.to_string(),
            version: version.to_string(),
            direct: direct_modules.contains(module),
        });
    }
    sort_targets(&mut out);
    out
}

// ── dispatch ───────────────────────────────────────────────────────────

/// Deterministic order shared by every parser: direct dependencies first,
/// then by name, then by version.
fn sort_targets(targets: &mut [DependencyTarget]) {
    targets.sort_by(|a, b| {
        b.direct
            .cmp(&a.direct)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
}

/// Status of reading and interpreting one fixed dependency input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntakeSourceStatus {
    #[default]
    Unknown,
    Absent,
    Parsed,
    Partial,
    ReadFailed,
    ParseFailed,
    Unsupported,
}

impl IntakeSourceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Absent => "absent",
            Self::Parsed => "parsed",
            Self::Partial => "partial",
            Self::ReadFailed => "read_failed",
            Self::ParseFailed => "parse_failed",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IntakeSource {
    /// Always one of the six fixed relative input names, never a repository path.
    pub file: String,
    pub status: IntakeSourceStatus,
    /// Fixed codes only. Parser messages/raw lines are not persisted.
    pub reason_codes: Vec<String>,
    pub selection_scope: String,
    /// Set only after a complete byte read, including invalid UTF-8 input.
    pub bytes: Option<u64>,
    pub sha256: Option<String>,
    /// None when parsing/format recognition failed, not an invented zero.
    pub parsed_targets: Option<usize>,
    /// Ignored entries/conditions are not a count of missing dependencies.
    pub ignored_entries: usize,
}

impl IntakeSource {
    fn issue(&mut self, status: IntakeSourceStatus, code: &'static str) {
        self.status = status;
        if !self.reason_codes.iter().any(|v| v == code) {
            self.reason_codes.push(code.into());
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IntakeEvidence {
    pub schema_version: u32,
    pub sources: Vec<IntakeSource>,
    /// Count of successfully resolved targets only. Failed-source denominator is unknown.
    pub resolved_targets: usize,
    pub denominator_scope: String,
    /// False direct flags from these targets are not evidence of transitivity.
    pub directness_unknown: Vec<DependencyTarget>,
}

impl IntakeEvidence {
    pub fn is_complete(&self) -> bool {
        let locks = [
            "Cargo.lock",
            "package-lock.json",
            "requirements.txt",
            "go.sum",
        ];
        let allowed = [
            "Cargo.lock",
            "Cargo.toml",
            "package-lock.json",
            "requirements.txt",
            "go.sum",
            "go.mod",
        ];
        let mut names = HashSet::new();
        self.schema_version == 1
            && self.denominator_scope == "successfully_resolved_locked_targets"
            && self.directness_unknown.is_empty()
            && self.sources.iter().all(|s| {
                names.insert(s.file.as_str())
                    && allowed.contains(&s.file.as_str())
                    && match s.status {
                        IntakeSourceStatus::Absent => {
                            s.bytes.is_none()
                                && s.sha256.is_none()
                                && s.parsed_targets.is_none()
                                && s.reason_codes.is_empty()
                                && s.ignored_entries == 0
                        }
                        IntakeSourceStatus::Parsed => {
                            s.bytes.is_some()
                                && s.sha256.as_ref().is_some_and(|v| {
                                    v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit())
                                })
                                && s.ignored_entries == 0
                                && s.reason_codes.is_empty()
                                && (!locks.contains(&s.file.as_str()) || s.parsed_targets.is_some())
                        }
                        _ => false,
                    }
            })
            && locks.iter().all(|name| names.contains(name))
            && self
                .sources
                .iter()
                .any(|s| locks.contains(&s.file.as_str()) && s.status == IntakeSourceStatus::Parsed)
            && self
                .sources
                .iter()
                .filter_map(|s| s.parsed_targets)
                .try_fold(0usize, |sum, n| sum.checked_add(n))
                == Some(self.resolved_targets)
    }

    pub fn directness_is_unknown(&self, target: &DependencyTarget) -> bool {
        self.directness_unknown.iter().any(|t| {
            t.ecosystem == target.ecosystem && t.name == target.name && t.version == target.version
        })
    }
}

pub struct DependencyIntake {
    pub targets: Vec<DependencyTarget>,
    pub evidence: IntakeEvidence,
}

fn read_intake_source(
    project: &std::path::Path,
    file: &'static str,
) -> (IntakeSource, Option<String>) {
    let mut source = IntakeSource {
        file: file.into(),
        ..Default::default()
    };
    let path = project.join(file);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            source.status = IntakeSourceStatus::Absent;
            return (source, None);
        }
        Err(error) => {
            source.issue(
                IntakeSourceStatus::ReadFailed,
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    "permission_denied"
                } else {
                    "metadata_failed"
                },
            );
            return (source, None);
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            source.issue(IntakeSourceStatus::Unsupported, "non_regular_file");
            return (source, None);
        }
        Ok(_) => {}
    }
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(error) => {
            source.issue(
                IntakeSourceStatus::ReadFailed,
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    "permission_denied"
                } else {
                    "read_failed"
                },
            );
            return (source, None);
        }
    };
    use sha2::{Digest, Sha256};
    source.bytes = Some(raw.len().min(u64::MAX as usize) as u64);
    source.sha256 = Some(hex::encode(Sha256::digest(&raw)));
    match String::from_utf8(raw) {
        Ok(text) => {
            source.status = IntakeSourceStatus::Parsed;
            (source, Some(text))
        }
        Err(_) => {
            source.issue(IntakeSourceStatus::ReadFailed, "invalid_utf8");
            (source, None)
        }
    }
}

fn cargo_intake(
    text: &str,
    source: &mut IntakeSource,
    auxiliary: &mut IntakeSource,
    manifest: Option<&str>,
) -> Vec<DependencyTarget> {
    source.selection_scope = "lock-resolved third-party packages; local packages excluded".into();
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            source.issue(IntakeSourceStatus::ParseFailed, "invalid_toml");
            return vec![];
        }
    };
    if !value.get("package").is_some_and(toml::Value::is_array) {
        source.issue(IntakeSourceStatus::Unsupported, "unsupported_lock_shape");
        return vec![];
    }
    if value
        .get("version")
        .is_some_and(|v| !matches!(v.as_integer(), Some(2..=4)))
    {
        source.issue(IntakeSourceStatus::Unsupported, "unsupported_lock_version");
        return vec![];
    }
    let mut direct = HashSet::new();
    if let Some(manifest) = manifest {
        match toml::from_str::<toml::Value>(manifest) {
            Err(_) => auxiliary.issue(IntakeSourceStatus::ParseFailed, "invalid_toml"),
            Ok(value) => {
                if !["package", "workspace", "dependencies"]
                    .iter()
                    .any(|key| value.get(key).is_some())
                    || ["package", "workspace"]
                        .iter()
                        .any(|key| value.get(key).is_some_and(|v| !v.is_table()))
                    || ["dependencies", "build-dependencies", "dev-dependencies"]
                        .iter()
                        .any(|key| value.get(key).is_some_and(|v| !v.is_table()))
                {
                    auxiliary.issue(IntakeSourceStatus::Unsupported, "unsupported_manifest");
                } else {
                    direct = cargo_direct_deps(manifest);
                    if value.get("target").is_some() {
                        auxiliary.issue(
                            IntakeSourceStatus::Partial,
                            "conditional_directness_unsupported",
                        );
                    }
                }
            }
        }
    }
    match parse_cargo_lock(text, &direct) {
        Ok(targets) => {
            source.parsed_targets = Some(targets.len());
            targets
        }
        Err(_) => {
            source.issue(IntakeSourceStatus::ParseFailed, "invalid_lock_entries");
            vec![]
        }
    }
}

fn npm_intake(text: &str, source: &mut IntakeSource) -> (Vec<DependencyTarget>, bool) {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            source.issue(IntakeSourceStatus::ParseFailed, "invalid_json");
            return (vec![], false);
        }
    };
    if value
        .get("lockfileVersion")
        .is_some_and(|v| !matches!(v.as_u64(), Some(1..=3)))
    {
        source.issue(IntakeSourceStatus::Unsupported, "unsupported_lock_version");
        return (vec![], false);
    }
    let mut directness_known = true;
    if value.get("packages").is_some_and(|v| !v.is_object()) {
        source.issue(IntakeSourceStatus::Partial, "invalid_packages_map");
    }
    let concrete = |v: &serde_json::Value| v.as_str().is_some_and(|v| !v.trim().is_empty());
    if let Some(packages) = value.get("packages").and_then(serde_json::Value::as_object) {
        directness_known =
            packages.is_empty() || packages.keys().any(|p| !p.contains("node_modules/"));
        for (path, meta) in packages {
            if !meta.is_object() {
                source.ignored_entries += 1;
                source.issue(IntakeSourceStatus::Partial, "invalid_package_metadata");
                if !path.contains("node_modules/") {
                    directness_known = false;
                }
                continue;
            }
            if !path.contains("node_modules/") {
                for key in ["dependencies", "devDependencies", "optionalDependencies"] {
                    if meta.get(key).is_some_and(|v| {
                        !v.as_object()
                            .is_some_and(|map| map.values().all(serde_json::Value::is_string))
                    }) {
                        directness_known = false;
                        source.issue(IntakeSourceStatus::Partial, "unsupported_directness");
                    }
                }
            } else if !meta.get("version").is_some_and(concrete)
                && meta.get("link").and_then(serde_json::Value::as_bool) != Some(true)
            {
                source.ignored_entries += 1;
                source.issue(IntakeSourceStatus::Partial, "missing_concrete_version");
            }
        }
    } else if let Some(dependencies) = value
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
    {
        fn recognise(deps: &serde_json::Map<String, serde_json::Value>, source: &mut IntakeSource) {
            for meta in deps.values() {
                if !meta.is_object() {
                    source.ignored_entries += 1;
                    source.issue(IntakeSourceStatus::Partial, "invalid_package_metadata");
                    continue;
                }
                if !meta
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| !v.trim().is_empty())
                {
                    source.ignored_entries += 1;
                    source.issue(IntakeSourceStatus::Partial, "missing_concrete_version");
                }
                if let Some(nested) = meta.get("dependencies") {
                    if let Some(map) = nested.as_object() {
                        recognise(map, source);
                    } else {
                        source.ignored_entries += 1;
                        source.issue(IntakeSourceStatus::Partial, "invalid_nested_dependencies");
                    }
                }
            }
        }
        recognise(dependencies, source);
    } else {
        source.issue(IntakeSourceStatus::Unsupported, "unsupported_lock_shape");
        return (vec![], false);
    }
    let mut targets = match parse_npm_lock(text) {
        Ok(targets) => targets,
        Err(_) => {
            source.issue(IntakeSourceStatus::ParseFailed, "invalid_json");
            return (vec![], false);
        }
    };
    targets.retain(|target| !target.version.trim().is_empty());
    source.parsed_targets = Some(targets.len());
    source.selection_scope = "concrete lock versions; local workspace links excluded".into();
    (targets, directness_known)
}

fn requirements_intake(text: &str, source: &mut IntakeSource) -> Vec<DependencyTarget> {
    let mut accepted = Vec::new();
    source.selection_scope = "exact pins only; no include/range/marker evaluation".into();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('-') {
            source.ignored_entries += 1;
            source.issue(IntakeSourceStatus::Partial, "requirements_option_ignored");
            continue;
        }
        let Some((_, version)) = line.split(';').next().unwrap_or("").split_once("==") else {
            source.ignored_entries += 1;
            source.issue(IntakeSourceStatus::Partial, "unpinned_requirement");
            continue;
        };
        if version.trim().is_empty()
            || version.contains(['*', '\\', '/', '='])
            || parse_requirements_txt(line).is_empty()
        {
            source.ignored_entries += 1;
            source.issue(IntakeSourceStatus::Partial, "unsupported_requirement");
            continue;
        }
        if line.contains(';') {
            source.ignored_entries += 1;
            source.issue(IntakeSourceStatus::Partial, "environment_marker_ignored");
        }
        accepted.push(line);
    }
    let targets = parse_requirements_txt(&accepted.join("\n"));
    source.parsed_targets = Some(targets.len());
    targets
}

fn go_manifest_supported(text: &str) -> bool {
    let mut module = false;
    let mut block = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if block {
            if line == ")" {
                block = false;
            } else if parts.len() != 2 || !parts[1].starts_with('v') {
                return false;
            }
        } else if line == "require (" {
            block = true;
        } else if parts.first() == Some(&"module") && parts.len() == 2 {
            module = true;
        } else if (parts.first() == Some(&"require")
            && parts.len() == 3
            && parts[2].starts_with('v'))
            || (matches!(parts.first(), Some(&"go" | &"toolchain")) && parts.len() == 2)
        {
        } else {
            return false;
        }
    }
    module && !block
}

fn go_intake(
    text: &str,
    source: &mut IntakeSource,
    auxiliary: &mut IntakeSource,
    manifest: Option<&str>,
) -> Vec<DependencyTarget> {
    let mut direct = HashSet::new();
    if let Some(manifest) = manifest {
        if go_manifest_supported(manifest) {
            direct = go_direct_deps(manifest);
        } else {
            auxiliary.issue(IntakeSourceStatus::Unsupported, "unsupported_manifest");
        }
    }
    let mut accepted = Vec::new();
    source.selection_scope = "recognised module checksum rows; no go.mod resolution".into();
    for line in text.lines().filter(|v| !v.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let valid = fields.len() == 3
            && fields[1].starts_with('v')
            && fields[2].strip_prefix("h1:").is_some_and(|v| {
                v.len() == 44
                    && v.ends_with('=')
                    && v.as_bytes()[..43]
                        .iter()
                        .copied()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
            });
        if valid {
            accepted.push(line);
        } else {
            source.ignored_entries += 1;
            source.issue(IntakeSourceStatus::Partial, "invalid_go_sum_row");
        }
    }
    let targets = parse_go_sum(&accepted.join("\n"), &direct);
    source.parsed_targets = Some(targets.len());
    targets
}

/// Offline intake with explicit failures, supported scope and unknown directness.
/// Metadata is checked before reading, so directories/FIFOs/symlinks are not opened.
/// This does not promise safety against concurrent mutation by the same UID.
pub fn intake_from_dir(project: &std::path::Path) -> Result<DependencyIntake, String> {
    let mut evidence = IntakeEvidence {
        schema_version: 1,
        denominator_scope: "successfully_resolved_locked_targets".into(),
        ..Default::default()
    };
    let mut targets = Vec::new();
    let mut found = false;
    for file in [
        "Cargo.lock",
        "package-lock.json",
        "requirements.txt",
        "go.sum",
    ] {
        let (mut source, text) = read_intake_source(project, file);
        found |= source.status != IntakeSourceStatus::Absent;
        if let Some(text) = text {
            let (parsed, directness_known) = match file {
                "Cargo.lock" | "go.sum" => {
                    let aux = if file == "Cargo.lock" {
                        "Cargo.toml"
                    } else {
                        "go.mod"
                    };
                    let (mut auxiliary, manifest) = read_intake_source(project, aux);
                    let parsed = if file == "Cargo.lock" {
                        cargo_intake(&text, &mut source, &mut auxiliary, manifest.as_deref())
                    } else {
                        go_intake(&text, &mut source, &mut auxiliary, manifest.as_deref())
                    };
                    let known = auxiliary.status == IntakeSourceStatus::Parsed;
                    evidence.sources.push(auxiliary);
                    (parsed, known)
                }
                "package-lock.json" => npm_intake(&text, &mut source),
                _ => (requirements_intake(&text, &mut source), true),
            };
            if !directness_known {
                for target in parsed.iter().filter(|t| !t.direct) {
                    evidence.directness_unknown.push(target.clone());
                    source.issue(IntakeSourceStatus::Partial, "directness_unknown");
                }
            }
            targets.extend(parsed);
        }
        evidence.sources.push(source);
    }
    if !found {
        return Err(
            "no supported lockfile found (Cargo.lock, package-lock.json, requirements.txt, go.sum)"
                .into(),
        );
    }
    evidence.resolved_targets = targets.len();
    Ok(DependencyIntake { targets, evidence })
}

/// Compatibility API: partial input cannot be represented by a Vec alone.
/// Call intake_from_dir to retain usable targets together with failure evidence.
pub fn targets_from_dir(project: &std::path::Path) -> Result<Vec<DependencyTarget>, String> {
    let intake = intake_from_dir(project)?;
    if !intake.evidence.is_complete() {
        return Err(
            "dependency intake incomplete; use intake_from_dir for per-source evidence".into(),
        );
    }
    Ok(intake.targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression tests from the `lockfiles` fuzz target (fuzz/): an entry
    // with an empty name or version names nothing fetchable and must never
    // become a hunt target.
    #[test]
    fn go_sum_bare_go_mod_field_is_not_a_target() {
        // Minimised fuzz input: go.sum row `\u{fffd}\t/go.mod`.
        assert!(parse_go_sum("\u{fffd}\t/go.mod", &HashSet::new()).is_empty());
        assert!(parse_go_sum("example.com/m /go.mod h1:x=", &HashSet::new()).is_empty());
    }

    #[test]
    fn npm_lock_entries_without_name_or_version_are_not_targets() {
        let v3 = r#"{"packages": {"": {}, "node_modules/a": {"version": ""}, "node_modules/": {"version": "1.0.0"}}}"#;
        assert!(parse_npm_lock(v3).unwrap().is_empty());
        let v1 = r#"{"dependencies": {"": {"version": "1.0.0"}, "b": {"version": "", "dependencies": {"c": {"version": "2.0.0"}}}}}"#;
        let t = parse_npm_lock(v1).unwrap();
        assert_eq!(t.len(), 1, "{t:?}");
        assert_eq!((t[0].name.as_str(), t[0].version.as_str()), ("c", "2.0.0"));
    }

    #[test]
    fn cargo_lock_entries_without_name_or_version_are_not_targets() {
        let lock = r#"
[[package]]
name = ""
version = "1.0.0"
source = "registry+https://example.invalid/index"

[[package]]
name = "serde"
version = ""
source = "registry+https://example.invalid/index"
"#;
        assert!(parse_cargo_lock(lock, &HashSet::new()).unwrap().is_empty());
    }

    #[test]
    fn npm_workspace_members_are_own_code_and_their_deps_direct() {
        let lock = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "mono", "workspaces": ["packages/*"] },
            "packages/api": { "name": "api", "version": "1.0.0", "dependencies": { "express": "^4" } },
            "node_modules/api": { "resolved": "packages/api", "link": true },
            "node_modules/express": { "version": "4.19.2" },
            "node_modules/express/node_modules/qs": { "version": "6.11.0" }
          }
        }"#;
        let t = parse_npm_lock(lock).unwrap();
        assert!(
            !t.iter()
                .any(|d| d.name.contains("packages/") || d.name == "api"),
            "{t:?}"
        );
        let express = t.iter().find(|d| d.name == "express").unwrap();
        assert!(express.direct);
        assert!(!t.iter().find(|d| d.name == "qs").unwrap().direct);
    }

    #[test]
    fn cargo_workspace_members_dependencies_are_direct() {
        // A virtual workspace: no root package, two members. Their lock
        // `dependencies` decide what is direct, version-exact when two
        // versions of one crate are present.
        let lock = r#"
version = 3

[[package]]
name = "app-core"
version = "0.1.0"
dependencies = ["serde", "rand 0.8.5", "app-util"]

[[package]]
name = "app-util"
version = "0.1.0"
dependencies = ["tokio"]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "rand"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.40.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["mio"]

[[package]]
name = "mio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let targets = parse_cargo_lock(lock, &HashSet::new()).unwrap();
        let direct = |n: &str, v: &str| {
            targets
                .iter()
                .find(|t| t.name == n && t.version == v)
                .map(|t| t.direct)
                .unwrap()
        };
        assert!(direct("serde", "1.0.200"));
        assert!(direct("tokio", "1.40.0"));
        assert!(direct("rand", "0.8.5"));
        assert!(!direct("rand", "0.9.0"), "only the version a member uses");
        assert!(!direct("mio", "1.0.0"), "a dependency of a dependency");
        assert!(
            !targets.iter().any(|t| t.name.starts_with("app-")),
            "own members excluded"
        );
    }

    const LOCK: &str = r#"
version = 3

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "libc"
version = "0.2.155"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "anyhow"
version = "1.0.86"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    #[test]
    fn parse_cargo_lock_excludes_local_members_and_keeps_third_party() {
        let direct = HashSet::new();
        let t = parse_cargo_lock(LOCK, &direct).unwrap();
        // my-app has no source → excluded. Three third-party crates remain.
        assert_eq!(t.len(), 3);
        assert!(t.iter().all(|d| d.ecosystem == Ecosystem::Cargo));
        assert!(!t.iter().any(|d| d.name == "my-app"));
        assert!(
            t.iter()
                .any(|d| d.name == "serde" && d.version == "1.0.200")
        );
    }

    #[test]
    fn direct_dependencies_are_marked_and_sorted_first() {
        let mut direct = HashSet::new();
        direct.insert("serde".to_string());
        let t = parse_cargo_lock(LOCK, &direct).unwrap();
        // serde is direct → first; the rest are transitive, name-sorted.
        assert_eq!(t[0].name, "serde");
        assert!(t[0].direct);
        assert_eq!(t[1].name, "anyhow");
        assert_eq!(t[2].name, "libc");
        assert!(!t[1].direct && !t[2].direct);
    }

    #[test]
    fn duplicate_name_version_pairs_are_deduped() {
        let lock = format!(
            "{LOCK}\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+x\"\n"
        );
        let t = parse_cargo_lock(&lock, &HashSet::new()).unwrap();
        assert_eq!(t.iter().filter(|d| d.name == "serde").count(), 1);
    }

    #[test]
    fn malformed_lock_is_an_error_not_a_panic() {
        assert!(parse_cargo_lock("this is not toml : : :", &HashSet::new()).is_err());
    }

    #[test]
    fn cargo_direct_deps_reads_all_three_tables() {
        let manifest = r#"
[package]
name = "x"
version = "0.1.0"

[dependencies]
serde = "1"

[build-dependencies]
cc = "1"

[dev-dependencies]
tempfile = "3"
"#;
        let d = cargo_direct_deps(manifest);
        assert!(d.contains("serde"));
        assert!(d.contains("cc"));
        assert!(d.contains("tempfile"));
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn cargo_direct_deps_malformed_manifest_is_empty_not_a_panic() {
        assert!(cargo_direct_deps(": : not toml").is_empty());
    }

    // ── npm ──────────────────────────────────────────────────────────
    #[test]
    fn npm_v3_packages_parse_with_scoped_and_nested_names_and_direct_marking() {
        let lock = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "app", "dependencies": { "lodash": "^4", "@scope/ui": "^1" } },
            "node_modules/lodash": { "version": "4.17.21" },
            "node_modules/@scope/ui": { "version": "1.2.0" },
            "node_modules/lodash/node_modules/nested": { "version": "0.0.1" }
          }
        }"#;
        let t = parse_npm_lock(lock).unwrap();
        assert_eq!(t.len(), 3);
        let by = |n: &str| t.iter().find(|d| d.name == n).unwrap();
        assert_eq!(by("lodash").version, "4.17.21");
        assert!(by("lodash").direct);
        assert_eq!(by("@scope/ui").version, "1.2.0");
        assert!(by("@scope/ui").direct);
        assert_eq!(by("nested").name, "nested"); // stripped from the nested path
        assert!(!by("nested").direct);
        assert!(t.iter().all(|d| d.ecosystem == Ecosystem::Npm));
    }

    #[test]
    fn npm_v1_dependencies_fallback_marks_top_level_direct() {
        let lock = r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "a": { "version": "1.0.0", "dependencies": { "b": { "version": "2.0.0" } } }
          }
        }"#;
        let t = parse_npm_lock(lock).unwrap();
        let a = t.iter().find(|d| d.name == "a").unwrap();
        let b = t.iter().find(|d| d.name == "b").unwrap();
        assert!(a.direct && !b.direct);
    }

    #[test]
    fn npm_malformed_is_an_error() {
        assert!(parse_npm_lock("not json").is_err());
    }

    // ── PyPI ─────────────────────────────────────────────────────────
    #[test]
    fn requirements_keeps_only_pinned_and_strips_extras_and_markers() {
        let req = "\
# a comment\n\
-r other.txt\n\
Flask==2.3.3\n\
requests[security]==2.31.0 ; python_version >= '3.8'\n\
django>=4.0\n\
numpy\n";
        let t = parse_requirements_txt(req);
        assert_eq!(t.len(), 2, "{t:?}");
        assert!(t.iter().any(|d| d.name == "Flask" && d.version == "2.3.3"));
        assert!(
            t.iter()
                .any(|d| d.name == "requests" && d.version == "2.31.0")
        );
        assert!(t.iter().all(|d| d.ecosystem == Ecosystem::PyPi && d.direct));
    }

    // ── Go ───────────────────────────────────────────────────────────
    #[test]
    fn go_sum_collapses_gomod_hash_lines_and_marks_direct() {
        let gosum = "\
github.com/pkg/errors v0.9.1 h1:abc=\n\
github.com/pkg/errors v0.9.1/go.mod h1:def=\n\
golang.org/x/sys v0.1.0 h1:ghi=\n\
golang.org/x/sys v0.1.0/go.mod h1:jkl=\n";
        let gomod = "\
module example.com/app\n\
go 1.22\n\
require (\n\
    github.com/pkg/errors v0.9.1\n\
    golang.org/x/sys v0.1.0 // indirect\n\
)\n";
        let direct = go_direct_deps(gomod);
        let t = parse_go_sum(gosum, &direct);
        assert_eq!(
            t.len(),
            2,
            "two modules, go.mod hash lines collapsed: {t:?}"
        );
        let pkg = t
            .iter()
            .find(|d| d.name == "github.com/pkg/errors")
            .unwrap();
        assert_eq!(pkg.version, "v0.9.1");
        assert!(pkg.direct);
        let sys = t.iter().find(|d| d.name == "golang.org/x/sys").unwrap();
        assert!(!sys.direct, "marked // indirect");
    }

    // ── dispatch ─────────────────────────────────────────────────────
    #[test]
    fn targets_from_dir_errors_when_no_lockfile_present() {
        let dir = tempfile::tempdir().unwrap();
        assert!(targets_from_dir(dir.path()).is_err());
    }

    #[test]
    fn targets_from_dir_reads_a_requirements_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "flask==2.3.3\n").unwrap();
        let t = targets_from_dir(dir.path()).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].ecosystem, Ecosystem::PyPi);
    }
}

#[cfg(test)]
mod intake_regression_tests {
    use super::*;

    fn pinned(dir: &std::path::Path) {
        std::fs::write(dir.join("requirements.txt"), "flask==2.3.3\n").unwrap();
    }

    #[test]
    fn intake_wrapper_rejects_malformed_only_and_mixed_sources() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "[ secret_marker = 'never-copy-this'",
        )
        .unwrap();
        assert!(targets_from_dir(dir.path()).is_err());
        pinned(dir.path());
        assert!(targets_from_dir(dir.path()).is_err());
    }

    #[test]
    fn intake_wrapper_rejects_unsupported_npm_shapes() {
        let dir = tempfile::tempdir().unwrap();
        for input in ["{}", "[]"] {
            std::fs::write(dir.path().join("package-lock.json"), input).unwrap();
            assert!(targets_from_dir(dir.path()).is_err(), "{input}");
        }
    }

    #[test]
    fn npm_semantic_shape_failures_preserve_valid_targets_but_never_complete() {
        let dir = tempfile::tempdir().unwrap();
        for input in [
            r#"{"packages":{"":42}}"#,
            r#"{"packages":42,"dependencies":{}}"#,
            r#"{"packages":{"":{"dependencies":[]}}}"#,
            r#"{"packages":{"":{},"node_modules/bad":{"version":""},"node_modules/good":{"version":"1.0.0"}}}"#,
            r#"{"dependencies":{"bad":42,"good":{"version":"1.0.0"}}}"#,
            r#"{"dependencies":{"bad":{"version":"1.0.0","dependencies":[]}}}"#,
        ] {
            std::fs::write(dir.path().join("package-lock.json"), input).unwrap();
            let intake = intake_from_dir(dir.path()).unwrap();
            assert!(!intake.evidence.is_complete(), "{input}");
            assert!(targets_from_dir(dir.path()).is_err());
            assert!(!intake.targets.iter().any(|t| t.version.is_empty()));
            if input.contains("good") {
                assert!(intake.targets.iter().any(|t| t.name == "good"));
            }
        }
    }

    #[test]
    fn intake_wrapper_does_not_ignore_invalid_utf8_or_directory() {
        let dir = tempfile::tempdir().unwrap();
        pinned(dir.path());
        std::fs::write(dir.path().join("package-lock.json"), [0xff]).unwrap();
        assert!(targets_from_dir(dir.path()).is_err());
        std::fs::remove_file(dir.path().join("package-lock.json")).unwrap();
        std::fs::create_dir(dir.path().join("Cargo.lock")).unwrap();
        assert!(targets_from_dir(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn intake_wrapper_rejects_fifo_without_reading_it() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        pinned(dir.path());
        let path =
            std::ffi::CString::new(dir.path().join("Cargo.lock").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert!(targets_from_dir(dir.path()).is_err());
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }

    #[cfg(unix)]
    #[test]
    fn intake_wrapper_retains_permission_failure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        pinned(dir.path());
        let path = dir.path().join("Cargo.lock");
        std::fs::write(&path, "version=3\npackage=[]\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0)).unwrap();
        let read = std::fs::read(&path);
        let result = targets_from_dir(dir.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "requires a non-root test user"
        );
        assert!(result.is_err());
    }

    #[test]
    fn invalid_auxiliary_manifest_shape_does_not_prove_transitivity() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "version=3\n[[package]]\nname='dep'\nversion='1.0.0'\nsource='registry+https://example.invalid'\n").unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "package=42\n").unwrap();
        let intake = intake_from_dir(dir.path()).unwrap();
        assert!(!intake.evidence.is_complete());
        assert_eq!(intake.evidence.directness_unknown.len(), 1);
    }

    #[test]
    fn mixed_intake_retains_good_targets_and_never_leaks_parser_lines() {
        let dir = tempfile::tempdir().unwrap();
        pinned(dir.path());
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "[ secret_marker = 'never-copy-this'",
        )
        .unwrap();
        let intake = intake_from_dir(dir.path()).unwrap();
        assert_eq!(intake.targets.len(), 1);
        assert_eq!(intake.evidence.resolved_targets, 1);
        let bad = intake
            .evidence
            .sources
            .iter()
            .find(|v| v.file == "Cargo.lock")
            .unwrap();
        assert_eq!(bad.status, IntakeSourceStatus::ParseFailed);
        assert_eq!(bad.parsed_targets, None);
        assert!(bad.sha256.is_some());
        assert!(
            !serde_json::to_string(&intake.evidence)
                .unwrap()
                .contains("secret_marker")
        );
    }

    #[test]
    fn unsupported_requirements_and_go_rows_remain_visible() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("requirements.txt"),
            "flask==2.3.3\nrequests>=2\n-r missing.txt\npinned==1.0; python_version>'3'\n",
        )
        .unwrap();
        let intake = intake_from_dir(dir.path()).unwrap();
        assert_eq!(intake.targets.len(), 2);
        assert!(!intake.evidence.is_complete());
        assert!(intake.evidence.sources.iter().any(|v| {
            v.reason_codes
                .iter()
                .any(|c| c == "requirements_option_ignored")
        }));
        std::fs::write(
            dir.path().join("go.sum"),
            format!("example.org/m v1.0.0 h1:{}=\nbad row\n", "A".repeat(43)),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            "module own\nrequire example.org/m v1.0.0\n",
        )
        .unwrap();
        let intake = intake_from_dir(dir.path()).unwrap();
        assert!(
            intake
                .targets
                .iter()
                .any(|t| t.name == "example.org/m" && t.direct)
        );
        let go = intake
            .evidence
            .sources
            .iter()
            .find(|v| v.file == "go.sum")
            .unwrap();
        assert_eq!(go.status, IntakeSourceStatus::Partial);
        assert_eq!(go.parsed_targets, Some(1));
    }

    #[test]
    fn missing_auxiliary_is_unknown_directness_and_empty_npm_is_supported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "version=3\n[[package]]\nname='dep'\nversion='1.0.0'\nsource='registry+https://example.invalid'\n").unwrap();
        let intake = intake_from_dir(dir.path()).unwrap();
        assert_eq!(intake.evidence.directness_unknown.len(), 1);
        assert!(!intake.evidence.is_complete());
        std::fs::remove_file(dir.path().join("Cargo.lock")).unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{}}}"#,
        )
        .unwrap();
        assert!(intake_from_dir(dir.path()).unwrap().evidence.is_complete());
    }

    #[test]
    fn intake_valid_empty_cargo_is_distinct_from_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "version=3\n[[package]]\nname='own'\nversion='0.0.0'\n",
        )
        .unwrap();
        assert!(targets_from_dir(dir.path()).unwrap().is_empty());
    }
}

#[cfg(test)]
mod transport_tests;
