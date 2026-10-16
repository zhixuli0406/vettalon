//! Supply-chain hunt (option A): intake.
//!
//! Resolve a project's third-party OSS dependencies from its lockfile into
//! audit targets. This phase is OFFLINE and pure: fetching each dependency's
//! source, the OSV novelty check, and the hunt orchestration live in sibling
//! modules (`osv`, `fetch`, `run`). Nothing here touches
//! the network, so it does not change `scan`'s zero-network posture.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub mod fetch;
pub mod osv;
pub mod run;

/// The package ecosystem a dependency comes from. Only Cargo is parsed in
/// phase 0; the others are the planned phase-1 intake surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        if p.source.is_none() {
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
            if name.is_empty() || !seen.insert((name.to_string(), version.to_string())) {
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
        if !seen.insert((module.to_string(), version.to_string())) {
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

/// Resolve every supported lockfile present under `project` into one target
/// list. Supports Cargo, npm, pip (`requirements.txt`) and Go. Errors only
/// when no supported lockfile is found; an unreadable or malformed one is
/// reported on stderr and skipped so the others still produce targets.
pub fn targets_from_dir(project: &std::path::Path) -> Result<Vec<DependencyTarget>, String> {
    let mut all: Vec<DependencyTarget> = Vec::new();
    let mut found = false;

    if project.join("Cargo.lock").is_file() {
        found = true;
        match cargo_targets_from_dir(project) {
            Ok(t) => all.extend(t),
            Err(e) => eprintln!(
                "[vettalon] {}",
                crate::tr!("略過 Cargo.lock：{e}", "skipping Cargo.lock: {e}")
            ),
        }
    }
    if let Ok(text) = std::fs::read_to_string(project.join("package-lock.json")) {
        found = true;
        match parse_npm_lock(&text) {
            Ok(t) => all.extend(t),
            Err(e) => eprintln!(
                "[vettalon] {}",
                crate::tr!(
                    "略過 package-lock.json：{e}",
                    "skipping package-lock.json: {e}"
                )
            ),
        }
    }
    if let Ok(text) = std::fs::read_to_string(project.join("requirements.txt")) {
        found = true;
        all.extend(parse_requirements_txt(&text));
    }
    if let Ok(text) = std::fs::read_to_string(project.join("go.sum")) {
        found = true;
        let direct = std::fs::read_to_string(project.join("go.mod"))
            .map(|t| go_direct_deps(&t))
            .unwrap_or_default();
        all.extend(parse_go_sum(&text, &direct));
    }

    if !found {
        return Err(
            "no supported lockfile found (Cargo.lock, package-lock.json, requirements.txt, go.sum)"
                .to_string(),
        );
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

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
