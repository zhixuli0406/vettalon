//! Offline lockfile dependency graph for hunt prioritisation (O8 `reach`).
//!
//! Only lockfiles that record edges are used: `Cargo.lock` (per-package
//! `dependencies`) and npm `package-lock.json` v2/v3 (`packages` map with
//! node-style resolution). `requirements.txt` and `go.sum` carry no edges, so
//! depth there is unknown except for dependencies already marked direct.
//! Nothing here touches the network or executes package tooling.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use super::{DependencyTarget, Ecosystem};

/// `(ecosystem, name, version)` key for one resolved package.
pub type NodeKey = (Ecosystem, String, String);

/// Depth and local fan-in for each package the lockfiles describe.
#[derive(Debug, Clone, Default)]
pub struct DepGraph {
    /// Shortest edge distance from the project's own packages (direct = 1).
    pub depth: HashMap<NodeKey, u32>,
    /// How many distinct packages in this lockfile depend on a package name.
    pub dependents: HashMap<(Ecosystem, String), usize>,
    /// Outgoing dependency names per package (one hop, for exposure hints).
    pub edges: HashMap<NodeKey, Vec<String>>,
    /// Ecosystems whose lockfile carried an edge graph that parsed.
    pub ecosystems: HashSet<Ecosystem>,
}

impl DepGraph {
    pub fn depth_of(&self, t: &DependencyTarget) -> Option<u32> {
        self.depth
            .get(&(t.ecosystem, t.name.clone(), t.version.clone()))
            .copied()
    }

    pub fn dependents_of(&self, t: &DependencyTarget) -> Option<usize> {
        if !self.ecosystems.contains(&t.ecosystem) {
            return None;
        }
        Some(
            self.dependents
                .get(&(t.ecosystem, t.name.clone()))
                .copied()
                .unwrap_or(0),
        )
    }

    pub fn deps_of(&self, t: &DependencyTarget) -> &[String] {
        self.edges
            .get(&(t.ecosystem, t.name.clone(), t.version.clone()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Build the graph from the fixed lockfile names in `project`. Unreadable or
/// malformed files simply contribute nothing (intake already records why).
pub fn graph_from_dir(project: &Path) -> DepGraph {
    let mut graph = DepGraph::default();
    let (_, cargo) = super::read_intake_source(project, "Cargo.lock");
    if let Some(text) = cargo {
        add_cargo(&mut graph, &text);
    }
    let (_, npm) = super::read_intake_source(project, "package-lock.json");
    if let Some(text) = npm {
        add_npm(&mut graph, &text);
    }
    graph
}

fn bfs(graph: &mut DepGraph, roots: Vec<NodeKey>, children: &HashMap<NodeKey, Vec<NodeKey>>) {
    let mut queue: VecDeque<(NodeKey, u32)> = roots.into_iter().map(|k| (k, 0)).collect();
    let mut seen: HashSet<NodeKey> = HashSet::new();
    while let Some((node, d)) = queue.pop_front() {
        if !seen.insert(node.clone()) {
            continue;
        }
        if d > 0 {
            let slot = graph.depth.entry(node.clone()).or_insert(d);
            *slot = (*slot).min(d);
        }
        for child in children.get(&node).into_iter().flatten() {
            if !seen.contains(child) {
                queue.push_back((child.clone(), d + 1));
            }
        }
    }
}

pub(crate) fn add_cargo(graph: &mut DepGraph, text: &str) {
    #[derive(serde::Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Pkg>,
    }
    #[derive(serde::Deserialize)]
    struct Pkg {
        name: String,
        version: String,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        dependencies: Vec<String>,
    }
    let Ok(lock) = toml::from_str::<Lock>(text) else {
        return;
    };
    let by_name: HashMap<&str, Vec<&str>> =
        lock.package
            .iter()
            .fold(HashMap::new(), |mut acc: HashMap<&str, Vec<&str>>, p| {
                acc.entry(p.name.as_str())
                    .or_default()
                    .push(p.version.as_str());
                acc
            });
    let key = |n: &str, v: &str| (Ecosystem::Cargo, n.to_string(), v.to_string());
    let mut children: HashMap<NodeKey, Vec<NodeKey>> = HashMap::new();
    let mut roots = Vec::new();
    for p in &lock.package {
        let me = key(&p.name, &p.version);
        if p.source.is_none() {
            roots.push(me.clone());
        }
        let mut names = Vec::new();
        for dep in &p.dependencies {
            let mut parts = dep.split_whitespace();
            let Some(name) = parts.next() else { continue };
            // "name" alone means the only version in the lock.
            let version = match parts.next() {
                Some(v) => v.to_string(),
                None => match by_name.get(name).map(Vec::as_slice) {
                    Some([only]) => (*only).to_string(),
                    _ => continue,
                },
            };
            names.push(name.to_string());
            children
                .entry(me.clone())
                .or_default()
                .push(key(name, &version));
        }
        let unique: HashSet<&String> = names.iter().collect();
        for name in unique {
            *graph
                .dependents
                .entry((Ecosystem::Cargo, name.clone()))
                .or_insert(0) += 1;
        }
        graph.edges.insert(me, names);
    }
    graph.ecosystems.insert(Ecosystem::Cargo);
    bfs(graph, roots, &children);
}

/// Resolve `name` required from `path` the way Node does: nearest
/// `node_modules/<name>` walking up from the requiring package.
fn npm_resolve<'a>(
    packages: &'a serde_json::Map<String, serde_json::Value>,
    from: &str,
    name: &str,
) -> Option<&'a str> {
    let mut base = from.to_string();
    loop {
        let candidate = if base.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{base}/node_modules/{name}")
        };
        if let Some((k, _)) = packages.get_key_value(&candidate) {
            return Some(k.as_str());
        }
        if base.is_empty() {
            return None;
        }
        base = match base.rfind("/node_modules/") {
            Some(i) => base[..i].to_string(),
            None => String::new(),
        };
    }
}

pub(crate) fn add_npm(graph: &mut DepGraph, text: &str) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let Some(packages) = v.get("packages").and_then(|p| p.as_object()) else {
        return; // v1 lockfiles have no per-package edge lists we rely on
    };
    let name_of = |path: &str| {
        path.rsplit_once("node_modules/")
            .map(|(_, n)| n.to_string())
    };
    let node = |path: &str| -> Option<NodeKey> {
        let name = name_of(path)?;
        let version = packages.get(path)?.get("version")?.as_str()?.to_string();
        Some((Ecosystem::Npm, name, version))
    };
    let mut children: HashMap<NodeKey, Vec<NodeKey>> = HashMap::new();
    let mut roots = Vec::new();
    for (path, meta) in packages {
        let own = !path.contains("node_modules/");
        let me = if own {
            (Ecosystem::Npm, format!("\0own:{path}"), String::new())
        } else {
            match node(path) {
                Some(k) => k,
                None => continue,
            }
        };
        if own {
            roots.push(me.clone());
        }
        let mut names = Vec::new();
        for field in [
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "devDependencies",
        ] {
            if field == "devDependencies" && !own {
                continue; // a dependency's dev deps are never installed
            }
            for dep in meta
                .get(field)
                .and_then(|d| d.as_object())
                .into_iter()
                .flat_map(|o| o.keys())
            {
                if let Some(child) = npm_resolve(packages, path, dep).and_then(node) {
                    names.push(dep.clone());
                    children.entry(me.clone()).or_default().push(child);
                }
            }
        }
        if !own {
            let unique: HashSet<&String> = names.iter().collect();
            for name in unique {
                *graph
                    .dependents
                    .entry((Ecosystem::Npm, name.clone()))
                    .or_insert(0) += 1;
            }
            graph.edges.insert(me, names);
        }
    }
    graph.ecosystems.insert(Ecosystem::Npm);
    bfs(graph, roots, &children);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(eco: Ecosystem, n: &str, v: &str) -> DependencyTarget {
        DependencyTarget {
            ecosystem: eco,
            name: n.into(),
            version: v.into(),
            direct: false,
        }
    }

    #[test]
    fn cargo_depth_and_dependents_follow_lock_edges() {
        let mut g = DepGraph::default();
        add_cargo(
            &mut g,
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["hyper", "serde"]

[[package]]
name = "hyper"
version = "1.0.0"
source = "registry+x"
dependencies = ["h2", "bytes"]

[[package]]
name = "h2"
version = "0.4.0"
source = "registry+x"
dependencies = ["bytes"]

[[package]]
name = "bytes"
version = "1.5.0"
source = "registry+x"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+x"
"#,
        );
        assert_eq!(g.depth_of(&t(Ecosystem::Cargo, "hyper", "1.0.0")), Some(1));
        assert_eq!(g.depth_of(&t(Ecosystem::Cargo, "h2", "0.4.0")), Some(2));
        assert_eq!(g.depth_of(&t(Ecosystem::Cargo, "bytes", "1.5.0")), Some(2));
        assert_eq!(
            g.dependents_of(&t(Ecosystem::Cargo, "bytes", "1.5.0")),
            Some(2)
        );
        assert_eq!(
            g.deps_of(&t(Ecosystem::Cargo, "hyper", "1.0.0")),
            ["h2", "bytes"]
        );
        // No graph for an ecosystem that was not parsed: unknown, not zero.
        assert_eq!(g.dependents_of(&t(Ecosystem::Go, "x", "v1")), None);
    }

    #[test]
    fn npm_resolution_prefers_nested_copy_and_tracks_depth() {
        let mut g = DepGraph::default();
        add_npm(
            &mut g,
            r#"{"lockfileVersion":3,"packages":{
              "": {"dependencies":{"express":"^4"}},
              "node_modules/express": {"version":"4.19.2","dependencies":{"qs":"6"}},
              "node_modules/express/node_modules/qs": {"version":"6.11.0"},
              "node_modules/qs": {"version":"6.13.0"}
            }}"#,
        );
        assert_eq!(g.depth_of(&t(Ecosystem::Npm, "express", "4.19.2")), Some(1));
        assert_eq!(g.depth_of(&t(Ecosystem::Npm, "qs", "6.11.0")), Some(2));
        // The hoisted copy is not required by anything: no depth.
        assert_eq!(g.depth_of(&t(Ecosystem::Npm, "qs", "6.13.0")), None);
    }

    #[test]
    fn malformed_lockfiles_contribute_nothing() {
        let mut g = DepGraph::default();
        add_cargo(&mut g, "not toml : :");
        add_npm(&mut g, "not json");
        assert!(g.depth.is_empty() && g.ecosystems.is_empty());
    }
}
