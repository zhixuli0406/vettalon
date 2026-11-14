//! Host-side check of `package.json` + `package-lock.json` (or
//! `npm-shrinkwrap.json`) before the networked install container starts
//! (design §3.3 step 1). The lockfile is untrusted input that decides what
//! that container fetches, so only one form passes: a package under
//! `node_modules/`, fetched from `https://registry.npmjs.org/` at exactly the
//! canonical tarball URL of its own name and version, pinned by one
//! `sha512` integrity. Everything else is refused before any container runs.
//! Install scripts are never run (`--ignore-scripts` always), so
//! `hasInstallScript` is accepted; it changes nothing.
//!
//! Every refusal maps to the blocker [`REFUSED_BLOCKER`]
//! (`node_lockfile_refused`) with one stable reason token
//! ([`LockfileReason::as_str`]) and a bounded, masked detail (the package
//! path and field, never a URL or other value). Tokens match
//! `[a-z][a-z0-9_]*`:
//!
//! | Token | Meaning |
//! |---|---|
//! | `too_large` | over [`LOCKFILE_MAX_BYTES`] / [`PACKAGE_JSON_MAX_BYTES`] |
//! | `not_utf8` | bytes are not UTF-8 |
//! | `too_deep` | JSON nested deeper than [`JSON_MAX_DEPTH`] |
//! | `malformed_json` | not strict JSON (truncated, trailing data, comments, NaN, out-of-range number …) |
//! | `duplicate_key` | an object repeats a key, at any depth |
//! | `not_object` | top level is not an object |
//! | `lockfile_version` | `lockfileVersion` is not the integer 2 or 3 |
//! | `packages_missing` | no `packages` section |
//! | `too_many_members` | over 50,000 members in one object or 500,000 keys overall |
//! | `too_many_dependency_edges` | more than [`MAX_DEPENDENCY_EDGES`] closure dependency keys |
//! | `dependency_unresolved` | a required dependency has no validated Node lookup target |
//! | `legacy_tree_in_v3` | a v3 lockfile contains top-level `dependencies` |
//! | `legacy_tree_mismatch` | a v2 legacy entry lacks an identical validated package |
//! | `too_many_packages` | more than [`MAX_PACKAGES`] non-root entries |
//! | `package_path` | entry key is not `node_modules/<name>(/node_modules/<name>)*` |
//! | `nesting_too_deep` | more than [`MAX_NESTING`] nested `node_modules` levels |
//! | `name` | invalid package name (charset, length, leading `.`/`_`) |
//! | `version` | missing or not `MAJOR.MINOR.PATCH[-pre][+build]` |
//! | `alias` | `npm:` spec, or an entry whose `name` differs from its path |
//! | `link` | `link: true` entry or `link:` spec |
//! | `git` | git URL, `github:`-style or `user/repo` shorthand |
//! | `file` | `file:` or a path |
//! | `http` | plain `http:` |
//! | `remote_url` | an `https:` tarball spec, or `resolved` on any other host |
//! | `resolved_mismatch` | registry host, but not the entry's canonical tarball URL |
//! | `resolved_missing` | entry without `resolved` |
//! | `integrity_missing` | entry without `integrity` |
//! | `integrity` | `integrity` is not exactly one well-formed `sha512-` hash |
//! | `bundled` | `inBundle: true` (no `resolved`/`integrity` of its own) |
//! | `shrinkwrap` | `hasShrinkwrap: true` (a nested lockfile npm would honour) |
//! | `workspace` | `workspaces`, a `workspace:` spec, or a non-`node_modules/` entry |
//! | `spec` | a dependency spec that is not a plain semver range or tag |
//! | `field_type` | a known field has the wrong JSON type |

use std::collections::HashMap;
use std::fmt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{JsonFault, bounded_detail, parse_strict, parse_strict_limited};

/// Blocker token for every refusal here (design §4.2, environment class).
pub const REFUSED_BLOCKER: &str = "node_lockfile_refused";
/// The only registry a `resolved` URL may point at.
pub const REGISTRY: &str = "https://registry.npmjs.org/";
/// Lockfile byte cap (design §3.3).
pub const LOCKFILE_MAX_BYTES: usize = 32 * 1024 * 1024;
/// `package.json` byte cap. The design gives none; 1 MiB is far above any
/// real manifest.
pub const PACKAGE_JSON_MAX_BYTES: usize = 1024 * 1024;
/// JSON nesting cap for both files (design §3.3).
pub const JSON_MAX_DEPTH: usize = 64;
/// Non-root `packages` entries (design §3.3).
pub const MAX_PACKAGES: usize = 20_000;
/// Closure keys: dependencies, peers, and root devDependencies. Optional
/// keys in these maps count even when their resolution will be skipped.
pub const MAX_DEPENDENCY_EDGES: usize = 200_000;
/// Nested `node_modules` levels in one entry path.
pub const MAX_NESTING: usize = 32;
/// npm's package-name length limit.
pub const PACKAGE_NAME_MAX: usize = 214;
/// node-semver's version length limit.
pub const VERSION_MAX: usize = 256;
/// Longest dependency spec accepted.
pub const SPEC_MAX: usize = 256;
/// Longest `packages` key accepted.
pub const PACKAGE_PATH_MAX: usize = 4096;
/// Domain tag of [`LockfileSummary::packages_sha256`].
pub const SUMMARY_DOMAIN: &str = "vettalon-node-lockfile/1";

const DEPENDENCY_FIELDS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

/// Stable reason token of a refusal (table in the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileReason {
    TooLarge,
    NotUtf8,
    TooDeep,
    MalformedJson,
    DuplicateKey,
    NotObject,
    LockfileVersion,
    PackagesMissing,
    TooManyPackages,
    TooManyMembers,
    TooManyDependencyEdges,
    DependencyUnresolved,
    LegacyTreeInV3,
    LegacyTreeMismatch,
    PackagePath,
    NestingTooDeep,
    Name,
    Version,
    Alias,
    Link,
    Git,
    File,
    Http,
    RemoteUrl,
    ResolvedMismatch,
    ResolvedMissing,
    IntegrityMissing,
    Integrity,
    Bundled,
    Shrinkwrap,
    Workspace,
    Spec,
    FieldType,
}

impl LockfileReason {
    pub fn as_str(self) -> &'static str {
        match self {
            LockfileReason::TooLarge => "too_large",
            LockfileReason::NotUtf8 => "not_utf8",
            LockfileReason::TooDeep => "too_deep",
            LockfileReason::MalformedJson => "malformed_json",
            LockfileReason::DuplicateKey => "duplicate_key",
            LockfileReason::NotObject => "not_object",
            LockfileReason::LockfileVersion => "lockfile_version",
            LockfileReason::PackagesMissing => "packages_missing",
            LockfileReason::TooManyPackages => "too_many_packages",
            LockfileReason::TooManyMembers => "too_many_members",
            LockfileReason::TooManyDependencyEdges => "too_many_dependency_edges",
            LockfileReason::DependencyUnresolved => "dependency_unresolved",
            LockfileReason::LegacyTreeInV3 => "legacy_tree_in_v3",
            LockfileReason::LegacyTreeMismatch => "legacy_tree_mismatch",
            LockfileReason::PackagePath => "package_path",
            LockfileReason::NestingTooDeep => "nesting_too_deep",
            LockfileReason::Name => "name",
            LockfileReason::Version => "version",
            LockfileReason::Alias => "alias",
            LockfileReason::Link => "link",
            LockfileReason::Git => "git",
            LockfileReason::File => "file",
            LockfileReason::Http => "http",
            LockfileReason::RemoteUrl => "remote_url",
            LockfileReason::ResolvedMismatch => "resolved_mismatch",
            LockfileReason::ResolvedMissing => "resolved_missing",
            LockfileReason::IntegrityMissing => "integrity_missing",
            LockfileReason::Integrity => "integrity",
            LockfileReason::Bundled => "bundled",
            LockfileReason::Shrinkwrap => "shrinkwrap",
            LockfileReason::Workspace => "workspace",
            LockfileReason::Spec => "spec",
            LockfileReason::FieldType => "field_type",
        }
    }

    fn from_json(fault: JsonFault) -> Self {
        match fault {
            JsonFault::TooLarge => LockfileReason::TooLarge,
            JsonFault::NotUtf8 => LockfileReason::NotUtf8,
            JsonFault::TooDeep => LockfileReason::TooDeep,
            JsonFault::Malformed => LockfileReason::MalformedJson,
            JsonFault::DuplicateKey => LockfileReason::DuplicateKey,
            JsonFault::TooManyPackages => LockfileReason::TooManyPackages,
            JsonFault::TooManyMembers => LockfileReason::TooManyMembers,
        }
    }
}

/// Which input file a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallInput {
    PackageJson,
    Lockfile,
}

impl InstallInput {
    pub fn as_str(self) -> &'static str {
        match self {
            InstallInput::PackageJson => "package.json",
            InstallInput::Lockfile => "lockfile",
        }
    }
}

/// Why the install inputs were refused. `detail` is bounded and masked
/// (an entry path and field name); it never carries a URL or value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileRefusal {
    pub input: InstallInput,
    pub reason: LockfileReason,
    pub detail: String,
}

impl LockfileRefusal {
    /// Always [`REFUSED_BLOCKER`].
    pub fn blocker(&self) -> &'static str {
        REFUSED_BLOCKER
    }
}

impl fmt::Display for LockfileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{REFUSED_BLOCKER}: {}: {}",
            self.input.as_str(),
            self.reason.as_str()
        )?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

impl std::error::Error for LockfileRefusal {}

/// One package the install may fetch. Orders by `path` first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct LockedPackage {
    /// `packages` key, e.g. `node_modules/a/node_modules/@s/b`.
    pub path: String,
    pub name: String,
    pub version: String,
    /// `sha512-…`; npm checks every tarball against it.
    pub integrity: String,
}

/// Deterministic result bound into receipts by later tasks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LockfileSummary {
    pub lockfile_version: u8,
    /// SHA-256 of the raw lockfile bytes (receipt `lockfile_sha256`).
    pub lockfile_sha256: String,
    /// Sorted by `path` (unique: duplicate keys are refused).
    pub packages: Vec<LockedPackage>,
    /// SHA-256 over [`SUMMARY_DOMAIN`], the version and every package's
    /// path, name, version and integrity, each length-prefixed (u64 BE).
    pub packages_sha256: String,
}

impl LockfileSummary {
    /// False for a project with no dependencies: the install is skipped
    /// (design §3.3).
    pub fn needs_install(&self) -> bool {
        !self.packages.is_empty()
    }
}

/// Check both install inputs; the summary is only returned when both pass.
pub fn validate_install_inputs(
    package_json: &[u8],
    lockfile: &[u8],
) -> Result<LockfileSummary, LockfileRefusal> {
    validate_package_json(package_json)?;
    validate_lockfile(lockfile)
}

/// `package.json`: no `workspaces`, every dependency spec a plain range or
/// tag (no git, file, link, URL, alias or workspace forms), `overrides` too.
pub fn validate_package_json(bytes: &[u8]) -> Result<(), LockfileRefusal> {
    let input = InstallInput::PackageJson;
    let value = parse_strict(bytes, PACKAGE_JSON_MAX_BYTES, JSON_MAX_DEPTH)
        .map_err(|e| Fault::new(LockfileReason::from_json(e), "").into_refusal(input))?;
    check_manifest(&value).map_err(|f| f.into_refusal(input))
}

/// A lockfile v2/v3: see the module doc for what passes.
pub fn validate_lockfile(bytes: &[u8]) -> Result<LockfileSummary, LockfileRefusal> {
    let input = InstallInput::Lockfile;
    let value = parse_strict_limited(
        bytes,
        LOCKFILE_MAX_BYTES,
        JSON_MAX_DEPTH,
        Some(MAX_PACKAGES + 1),
    )
    .map_err(|e| Fault::new(LockfileReason::from_json(e), "").into_refusal(input))?;
    let (lockfile_version, packages) = check_lockfile(&value).map_err(|f| f.into_refusal(input))?;
    let packages_sha256 = packages_digest(lockfile_version, &packages);
    Ok(LockfileSummary {
        lockfile_version,
        lockfile_sha256: crate::audit::schema::sha256_hex(bytes),
        packages,
        packages_sha256,
    })
}

/// A refusal before it is tied to an input file; `at` is raw, untrusted.
struct Fault {
    reason: LockfileReason,
    at: String,
}

impl Fault {
    fn new(reason: LockfileReason, at: impl Into<String>) -> Self {
        Fault {
            reason,
            at: at.into(),
        }
    }

    fn into_refusal(self, input: InstallInput) -> LockfileRefusal {
        LockfileRefusal {
            input,
            reason: self.reason,
            detail: bounded_detail(&self.at),
        }
    }
}

type Check<T> = Result<T, Fault>;

fn check_manifest(value: &Value) -> Check<()> {
    let obj = value
        .as_object()
        .ok_or_else(|| Fault::new(LockfileReason::NotObject, ""))?;
    if obj.contains_key("workspaces") {
        return Err(Fault::new(LockfileReason::Workspace, "workspaces"));
    }
    check_dependency_maps(obj, "")?;
    if let Some(overrides) = obj.get("overrides") {
        check_overrides(overrides, "overrides")?;
    }
    Ok(())
}

/// `overrides` values: a range/tag, or `$name` (a reference to a direct
/// dependency's spec, which is checked on its own). Nested objects recurse;
/// recursion is bounded by [`JSON_MAX_DEPTH`].
fn check_overrides(value: &Value, at: &str) -> Check<()> {
    match value {
        Value::String(spec) => {
            let checked = match spec.strip_prefix('$') {
                Some(name) => check_name(name),
                None => check_spec(spec),
            };
            checked.map_err(|r| Fault::new(r, at))
        }
        Value::Object(map) => {
            for (key, inner) in map {
                if key.len() > PACKAGE_NAME_MAX + SPEC_MAX {
                    return Err(Fault::new(LockfileReason::Spec, at));
                }
                check_overrides(inner, &format!("{at}.{key}"))?;
            }
            Ok(())
        }
        _ => Err(Fault::new(LockfileReason::FieldType, at)),
    }
}

/// The four dependency maps of a manifest or lockfile entry: names valid,
/// specs plain ranges or tags.
fn check_dependency_maps(obj: &Map<String, Value>, at: &str) -> Check<()> {
    for field in DEPENDENCY_FIELDS {
        let Some(map) = obj.get(field) else {
            continue;
        };
        let map = map
            .as_object()
            .ok_or_else(|| Fault::new(LockfileReason::FieldType, format!("{at}{field}")))?;
        for (name, spec) in map {
            let here = || format!("{at}{field}.{name}");
            check_name(name).map_err(|r| Fault::new(r, here()))?;
            let spec = spec
                .as_str()
                .ok_or_else(|| Fault::new(LockfileReason::FieldType, here()))?;
            check_spec(spec).map_err(|r| Fault::new(r, here()))?;
        }
    }
    Ok(())
}

fn check_lockfile(value: &Value) -> Check<(u8, Vec<LockedPackage>)> {
    let obj = value
        .as_object()
        .ok_or_else(|| Fault::new(LockfileReason::NotObject, ""))?;
    let version = match obj.get("lockfileVersion").and_then(Value::as_u64) {
        Some(2) => 2,
        Some(3) => 3,
        _ => {
            return Err(Fault::new(
                LockfileReason::LockfileVersion,
                "lockfileVersion",
            ));
        }
    };
    if version == 3 && obj.contains_key("dependencies") {
        return Err(Fault::new(LockfileReason::LegacyTreeInV3, "dependencies"));
    }
    let packages = obj
        .get("packages")
        .ok_or_else(|| Fault::new(LockfileReason::PackagesMissing, "packages"))?
        .as_object()
        .ok_or_else(|| Fault::new(LockfileReason::FieldType, "packages"))?;
    let count = packages.keys().filter(|k| !k.is_empty()).count();
    if count > MAX_PACKAGES {
        return Err(Fault::new(
            LockfileReason::TooManyPackages,
            format!("{count} > {MAX_PACKAGES}"),
        ));
    }
    let mut locked = Vec::with_capacity(count);
    let mut closure_entries = Vec::with_capacity(packages.len());
    let mut dependency_edges = 0;
    for (path, entry) in packages {
        let entry = entry
            .as_object()
            .ok_or_else(|| Fault::new(LockfileReason::FieldType, path.as_str()))?;
        if path.is_empty() {
            check_root_entry(entry)?;
        } else {
            locked.push(check_package(path, entry)?);
        }
        for field in closure_dependency_fields(path) {
            dependency_edges += entry
                .get(field)
                .and_then(Value::as_object)
                .map_or(0, Map::len);
        }
        if dependency_edges > MAX_DEPENDENCY_EDGES {
            return Err(Fault::new(
                LockfileReason::TooManyDependencyEdges,
                "packages",
            ));
        }
        closure_entries.push((path.as_str(), entry, package_ancestors(path)));
    }
    // Resolve only after every candidate has passed the fetch allowlist and
    // the total edge budget has passed. Borrow canonical paths for the index.
    let package_index: HashMap<&str, &Value> = packages
        .iter()
        .map(|(path, entry)| (path.as_str(), entry))
        .collect();
    let mut candidate = String::with_capacity(PACKAGE_PATH_MAX + 14 + PACKAGE_NAME_MAX);
    for (path, entry, ancestors) in closure_entries {
        check_dependency_closure(entry, path, &package_index, &ancestors, &mut candidate)?;
    }
    if let Some(legacy) = obj.get("dependencies") {
        check_legacy(legacy, "", packages)?;
    }
    // Paths are unique, so this is the order by path.
    locked.sort();
    Ok((version, locked))
}

fn check_root_entry(entry: &Map<String, Value>) -> Check<()> {
    if entry.contains_key("workspaces") {
        return Err(Fault::new(
            LockfileReason::Workspace,
            "packages[\"\"].workspaces",
        ));
    }
    check_dependency_maps(entry, "packages[\"\"].")
}

fn check_package(path: &str, entry: &Map<String, Value>) -> Check<LockedPackage> {
    let name = package_path_name(path)?;
    let at = |field: &str| format!("{path}: {field}");
    let flag = |field: &str| entry_flag(entry, path, field);
    let text = |field: &'static str| entry_text(entry, path, field);
    if flag("link")? {
        return Err(Fault::new(LockfileReason::Link, at("link")));
    }
    if flag("inBundle")? {
        return Err(Fault::new(LockfileReason::Bundled, at("inBundle")));
    }
    if flag("hasShrinkwrap")? {
        return Err(Fault::new(LockfileReason::Shrinkwrap, at("hasShrinkwrap")));
    }
    if text("name")?.is_some_and(|n| n != name) {
        return Err(Fault::new(LockfileReason::Alias, at("name")));
    }
    let resolved = text("resolved")?
        .ok_or_else(|| Fault::new(LockfileReason::ResolvedMissing, at("resolved")))?;
    check_resolved_form(resolved).map_err(|r| Fault::new(r, at("resolved")))?;
    let version =
        text("version")?.ok_or_else(|| Fault::new(LockfileReason::Version, at("version")))?;
    check_version(version).map_err(|r| Fault::new(r, at("version")))?;
    if resolved != canonical_tarball_url(&name, version) {
        return Err(Fault::new(LockfileReason::ResolvedMismatch, at("resolved")));
    }
    let integrity = text("integrity")?
        .ok_or_else(|| Fault::new(LockfileReason::IntegrityMissing, at("integrity")))?;
    if !is_sha512_integrity(integrity) {
        return Err(Fault::new(LockfileReason::Integrity, at("integrity")));
    }
    check_dependency_maps(entry, &format!("{path}: "))?;
    Ok(LockedPackage {
        path: path.to_string(),
        name,
        version: version.to_string(),
        integrity: integrity.to_string(),
    })
}

fn entry_flag(entry: &Map<String, Value>, path: &str, field: &str) -> Check<bool> {
    match entry.get(field) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(Fault::new(
            LockfileReason::FieldType,
            format!("{path}: {field}"),
        )),
    }
}

fn entry_text<'a>(
    entry: &'a Map<String, Value>,
    path: &str,
    field: &str,
) -> Check<Option<&'a str>> {
    match entry.get(field) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(Fault::new(
            LockfileReason::FieldType,
            format!("{path}: {field}"),
        )),
    }
}

/// Only complete package directories can lead to validated package paths.
/// Parse each canonical path once, retaining borrowed prefixes nearest first.
fn package_ancestors(path: &str) -> Vec<&str> {
    let mut ancestors = vec![""];
    if path.is_empty() {
        return ancestors;
    }
    let mut segments = path.split('/');
    let mut end = 0;
    while segments.next().is_some() {
        end += "node_modules/".len();
        let mut name = segments.next().expect("validated package path");
        end += name.len();
        if name.starts_with('@') {
            name = segments.next().expect("validated scoped package path");
            end += 1 + name.len();
        }
        // Node skips directories named node_modules, including a scoped
        // package whose basename is node_modules.
        if name != "node_modules" {
            ancestors.push(&path[..end]);
        }
        end += 1;
    }
    ancestors.reverse();
    ancestors
}

fn resolve_dependency<'a>(
    packages: &HashMap<&str, &'a Value>,
    ancestors: &[&str],
    name: &str,
    candidate: &mut String,
) -> Option<&'a Value> {
    for ancestor in ancestors {
        candidate.clear();
        candidate.push_str(ancestor);
        if !ancestor.is_empty() {
            candidate.push('/');
        }
        candidate.push_str("node_modules/");
        candidate.push_str(name);
        if let Some(entry) = packages.get(candidate.as_str()) {
            return Some(*entry);
        }
    }
    None
}

fn closure_dependency_fields(path: &str) -> impl Iterator<Item = &'static str> + '_ {
    ["dependencies", "peerDependencies", "devDependencies"]
        .into_iter()
        // Published packages' development dependencies are not installed.
        .filter(move |field| *field != "devDependencies" || path.is_empty())
}

fn check_dependency_closure(
    entry: &Map<String, Value>,
    path: &str,
    packages: &HashMap<&str, &Value>,
    ancestors: &[&str],
    candidate: &mut String,
) -> Check<()> {
    let peer_meta = match entry.get("peerDependenciesMeta") {
        None => None,
        Some(Value::Object(meta)) => {
            for (name, value) in meta {
                let at = format!("{path}: peerDependenciesMeta.{name}");
                let obj = value
                    .as_object()
                    .ok_or_else(|| Fault::new(LockfileReason::FieldType, &at))?;
                entry_flag(obj, &at, "optional")?;
            }
            Some(meta)
        }
        Some(_) => return Err(Fault::new(LockfileReason::FieldType, path)),
    };
    for field in closure_dependency_fields(path) {
        let Some(map) = entry.get(field).and_then(Value::as_object) else {
            continue;
        };
        for name in map.keys() {
            let optional = if field == "peerDependencies" {
                peer_meta
                    .and_then(|meta| meta.get(name))
                    .and_then(|meta| meta.get("optional"))
                    == Some(&Value::Bool(true))
            } else {
                // npm optionalDependencies overrides dependencies of the same name.
                entry
                    .get("optionalDependencies")
                    .and_then(Value::as_object)
                    .is_some_and(|map| map.contains_key(name))
            };
            if !optional && resolve_dependency(packages, ancestors, name, candidate).is_none() {
                return Err(Fault::new(
                    LockfileReason::DependencyUnresolved,
                    format!("{path}: {field}.{name}"),
                ));
            }
        }
    }
    Ok(())
}

/// A v2 legacy tree describes physical install paths, not lookup aliases.
/// Every entry must carry the exact validated version, URL and integrity.
fn check_legacy(value: &Value, parent: &str, packages: &Map<String, Value>) -> Check<()> {
    let map = value
        .as_object()
        .ok_or_else(|| Fault::new(LockfileReason::FieldType, parent))?;
    for (name, dep) in map {
        let path = if parent.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{parent}/node_modules/{name}")
        };
        check_name(name).map_err(|r| Fault::new(r, &path))?;
        let package = packages
            .get(&path)
            .ok_or_else(|| Fault::new(LockfileReason::LegacyTreeMismatch, &path))?;
        let dep = dep
            .as_object()
            .ok_or_else(|| Fault::new(LockfileReason::FieldType, &path))?;
        if dep.get("bundled").is_some_and(|b| b != &Value::Bool(false)) {
            return Err(Fault::new(LockfileReason::Bundled, &path));
        }
        if let Some(version) = entry_text(dep, &path, "version")? {
            check_version(version).map_err(|r| Fault::new(r, &path))?;
        }
        if let Some(resolved) = entry_text(dep, &path, "resolved")? {
            check_resolved_form(resolved).map_err(|r| Fault::new(r, &path))?;
        }
        for field in ["version", "resolved", "integrity"] {
            if dep.get(field).is_none() || dep.get(field) != package.get(field) {
                return Err(Fault::new(LockfileReason::LegacyTreeMismatch, &path));
            }
        }
        if let Some(nested) = dep.get("dependencies") {
            check_legacy(nested, &path, packages)?;
        }
    }
    Ok(())
}

/// `node_modules/<name>(/node_modules/<name>)*` → the last `<name>`.
fn package_path_name(path: &str) -> Check<String> {
    if path.len() > PACKAGE_PATH_MAX {
        return Err(Fault::new(LockfileReason::PackagePath, ""));
    }
    if !path.starts_with("node_modules/") {
        // npm keys workspace members and linked folders by their own path.
        return Err(Fault::new(LockfileReason::Workspace, path));
    }
    let segments: Vec<&str> = path.split('/').collect();
    let mut i = 0;
    let mut levels = 0;
    loop {
        if segments.get(i) != Some(&"node_modules") {
            return Err(Fault::new(LockfileReason::PackagePath, path));
        }
        i += 1;
        let width = match segments.get(i) {
            Some(s) if s.starts_with('@') => 2,
            Some(_) => 1,
            None => return Err(Fault::new(LockfileReason::PackagePath, path)),
        };
        if i + width > segments.len() {
            return Err(Fault::new(LockfileReason::PackagePath, path));
        }
        let name = segments[i..i + width].join("/");
        i += width;
        levels += 1;
        if levels > MAX_NESTING {
            return Err(Fault::new(LockfileReason::NestingTooDeep, path));
        }
        check_name(&name).map_err(|r| Fault::new(r, path))?;
        if i == segments.len() {
            return Ok(name);
        }
    }
}

/// npm package name: `name` or `@scope/name`, each part from
/// `[A-Za-z0-9._~-]` not starting with `.` or `_`, ≤ 214 bytes in total.
/// Upper case is allowed for legacy packages. `node_modules` is refused
/// (npm's blocklist), so paths parse unambiguously.
fn check_name(name: &str) -> Result<(), LockfileReason> {
    fn part_ok(part: &str) -> bool {
        !part.is_empty()
            && !part.starts_with(['.', '_'])
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
    }
    if name.is_empty() || name.len() > PACKAGE_NAME_MAX || name == "node_modules" {
        return Err(LockfileReason::Name);
    }
    let ok = match name.strip_prefix('@') {
        Some(rest) => rest
            .split_once('/')
            .is_some_and(|(scope, base)| part_ok(scope) && part_ok(base)),
        None => part_ok(name),
    };
    if ok {
        Ok(())
    } else {
        Err(LockfileReason::Name)
    }
}

/// Exact semver `MAJOR.MINOR.PATCH[-pre][+build]`; a remote form in a
/// version field (v1-style lockfiles put git URLs there) gets its own token.
fn check_version(version: &str) -> Result<(), LockfileReason> {
    if let Some(form) = remote_form(version) {
        return Err(form);
    }
    if version.is_empty() || version.len() > VERSION_MAX {
        return Err(LockfileReason::Version);
    }
    let core_end = version.find(['-', '+']).unwrap_or(version.len());
    let (core, rest) = version.split_at(core_end);
    let mut parts = 0;
    for part in core.split('.') {
        parts += 1;
        if part.is_empty() || part.len() > 16 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(LockfileReason::Version);
        }
    }
    let rest_ok = rest.is_empty()
        || (rest.len() > 1
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+')));
    if parts == 3 && rest_ok {
        Ok(())
    } else {
        Err(LockfileReason::Version)
    }
}

/// Plain semver range or dist-tag. Remote/local forms get their own token.
fn check_spec(spec: &str) -> Result<(), LockfileReason> {
    if let Some(form) = remote_form(spec) {
        return Err(form);
    }
    if spec.len() > SPEC_MAX {
        return Err(LockfileReason::Spec);
    }
    if spec.starts_with(['.', '/']) || spec.starts_with("~/") {
        return Err(LockfileReason::File);
    }
    if spec.contains('/') {
        // `user/repo[#ref]`: npm reads it as a GitHub repository.
        return Err(LockfileReason::Git);
    }
    let plain = spec.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b' ' | b'.' | b'+' | b'-' | b'<' | b'>' | b'=' | b'~' | b'^' | b'|' | b'*'
            )
    });
    if plain {
        Ok(())
    } else {
        Err(LockfileReason::Spec)
    }
}

/// `resolved` must start with [`REGISTRY`] (exact case); any other value
/// is classified. The exact tarball URL is compared separately.
fn check_resolved_form(resolved: &str) -> Result<(), LockfileReason> {
    if resolved.starts_with(REGISTRY) {
        return Ok(());
    }
    Err(remote_form(resolved).unwrap_or(
        if resolved.starts_with(['.', '/']) || resolved.starts_with("~/") {
            LockfileReason::File
        } else {
            LockfileReason::RemoteUrl
        },
    ))
}

/// A non-registry source form by its (case-insensitive) prefix.
fn remote_form(s: &str) -> Option<LockfileReason> {
    const FORMS: [(&str, LockfileReason); 14] = [
        ("git+", LockfileReason::Git),
        ("git:", LockfileReason::Git),
        ("git@", LockfileReason::Git),
        ("ssh:", LockfileReason::Git),
        ("github:", LockfileReason::Git),
        ("gitlab:", LockfileReason::Git),
        ("bitbucket:", LockfileReason::Git),
        ("gist:", LockfileReason::Git),
        ("file:", LockfileReason::File),
        ("link:", LockfileReason::Link),
        ("npm:", LockfileReason::Alias),
        ("workspace:", LockfileReason::Workspace),
        ("http:", LockfileReason::Http),
        ("https:", LockfileReason::RemoteUrl),
    ];
    let s = s.trim_start();
    FORMS.iter().find_map(|(prefix, reason)| {
        s.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            .then_some(*reason)
    })
}

/// `https://registry.npmjs.org/<name>/-/<unscoped>-<version>.tgz`.
fn canonical_tarball_url(name: &str, version: &str) -> String {
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    format!("{REGISTRY}{name}/-/{unscoped}-{version}.tgz")
}

/// Decode one 64-byte SHA-512 digest and require its canonical base64 spelling.
fn is_sha512_integrity(integrity: &str) -> bool {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let Some(b64) = integrity.strip_prefix("sha512-") else {
        return false;
    };
    if b64.len() != 88 || !b64.ends_with("==") {
        return false;
    }
    let mut sextets = [0u8; 86];
    for (out, byte) in sextets.iter_mut().zip(b64.bytes()) {
        *out = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return false,
        };
    }
    // The final sextet carries only two data bits; four unused bits must be zero.
    if sextets[85] & 0x0f != 0 {
        return false;
    }
    let mut digest = [0u8; 64];
    for (out, chunk) in digest[..63]
        .as_chunks_mut::<3>()
        .0
        .iter_mut()
        .zip(sextets[..84].as_chunks::<4>().0)
    {
        out[0] = (chunk[0] << 2) | (chunk[1] >> 4);
        out[1] = (chunk[1] << 4) | (chunk[2] >> 2);
        out[2] = (chunk[2] << 6) | chunk[3];
    }
    digest[63] = (sextets[84] << 2) | (sextets[85] >> 4);
    let mut encoded = [b'='; 88];
    for (out, chunk) in encoded[..84]
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(digest[..63].as_chunks::<3>().0)
    {
        out[0] = ALPHABET[(chunk[0] >> 2) as usize];
        out[1] = ALPHABET[(((chunk[0] & 3) << 4) | (chunk[1] >> 4)) as usize];
        out[2] = ALPHABET[(((chunk[1] & 15) << 2) | (chunk[2] >> 6)) as usize];
        out[3] = ALPHABET[(chunk[2] & 63) as usize];
    }
    encoded[84] = ALPHABET[(digest[63] >> 2) as usize];
    encoded[85] = ALPHABET[((digest[63] & 3) << 4) as usize];
    b64.as_bytes() == encoded
}

fn packages_digest(version: u8, packages: &[LockedPackage]) -> String {
    fn put(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let mut hasher = Sha256::new();
    put(&mut hasher, SUMMARY_DOMAIN.as_bytes());
    put(&mut hasher, &[version]);
    hasher.update((packages.len() as u64).to_be_bytes());
    for p in packages {
        put(&mut hasher, p.path.as_bytes());
        put(&mut hasher, p.name.as_bytes());
        put(&mut hasher, p.version.as_bytes());
        put(&mut hasher, p.integrity.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[path = "lockfile_tests.rs"]
mod tests;
