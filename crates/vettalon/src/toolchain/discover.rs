//! Discovery of agent toolchain items (see the table in
//! `docs/TOOLCHAIN-AUDIT.md`). Reads only; nothing found is executed.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::content::{
    Budget, DirContent, FileRecord, ReadCtx, Stop, TextFile, list_dir, read_capped_to, read_tree,
    tree_hash,
};
use super::mcp::McpEntry;
use super::{
    Agent, Kind, PathDisplay, RawFinding, SKILL_DEPTH, Scope, Selection, clean_text, os_display,
};

/// Config files (`~/.claude.json`, `config.toml`, manifests) are read up to this.
const CONFIG_CAP: u64 = 32 * 1024 * 1024;
/// Parts of a plugin install that are content.
const PLUGIN_PARTS: &[&str] = &["skills", "hooks", ".claude-plugin", ".mcp.json"];
/// Plugin files that are parsed structurally instead of scanned line by line.
pub const STRUCTURED: &[&str] = &[
    "hooks/hooks.json",
    ".mcp.json",
    ".claude-plugin/plugin.json",
];
const MAX_JSON_DEPTH: usize = 32;

/// An MCP entry with where it was configured.
#[derive(Clone)]
pub struct McpSite {
    pub entry: McpEntry,
    pub file: PathBuf,
    pub line: Option<usize>,
}

/// A string found in a manifest (hook command, description).
#[derive(Debug, Clone)]
pub struct Located {
    pub text: String,
    pub file: PathBuf,
    pub line: Option<usize>,
}

/// One discovered item with the content the rules need.
#[derive(Clone)]
pub struct Discovered {
    pub id: String,
    pub agent: Agent,
    pub kind: Kind,
    pub scope: Scope,
    pub name: String,
    pub path: PathBuf,
    pub files: Vec<FileRecord>,
    pub hash: String,
    pub incomplete: Vec<String>,
    /// Findings produced while reading (TC006, TC010, TC011, TC012).
    pub read_findings: Vec<RawFinding>,
    pub texts: Vec<TextFile>,
    pub mcp: Vec<McpSite>,
    pub hooks: Vec<Located>,
    pub descriptions: Vec<Located>,
}

impl Discovered {
    fn new(agent: Agent, kind: Kind, scope: Scope, name: &str, path: &Path) -> Self {
        Discovered {
            id: String::new(),
            agent,
            kind,
            scope,
            name: clean_text(name),
            path: path.to_path_buf(),
            files: Vec::new(),
            hash: tree_hash(&[]),
            incomplete: Vec::new(),
            read_findings: Vec::new(),
            texts: Vec::new(),
            mcp: Vec::new(),
            hooks: Vec::new(),
            descriptions: Vec::new(),
        }
    }

    fn with_content(mut self, content: DirContent) -> Self {
        self.hash = tree_hash(&content.files);
        self.files = content.files;
        self.texts = content.texts;
        self.read_findings = content.findings;
        self.incomplete = content.incomplete;
        self
    }

    /// Whether a text file is a structured manifest of this item.
    pub fn is_structured(&self, t: &TextFile) -> bool {
        self.kind == Kind::Plugin && STRUCTURED.contains(&t.rel.as_str())
    }
}

#[derive(Default)]
pub struct Discovery {
    pub items: Vec<Discovered>,
    /// Audit-level reasons (`symlink_not_followed:…`, `parse_error:…`, …).
    pub incomplete: Vec<String>,
}

pub fn discover(sel: &Selection, max_file_bytes: u64, display: &PathDisplay) -> Discovery {
    let mut d = Discoverer::new(sel, max_file_bytes, display, Budget::default());
    d.run();
    let mut out = d.out;
    assign_ids(&mut out.items);
    out
}

struct Discoverer<'a> {
    sel: &'a Selection,
    display: &'a PathDisplay,
    max_file_bytes: u64,
    budget: Budget,
    out: Discovery,
    /// Canonical `~/.claude`, `~/.codex`, `~/.agents` (those that exist).
    home_roots: Vec<PathBuf>,
    project_canon: Option<PathBuf>,
    /// Canonical `~/.claude/plugins`.
    plugins_canon: Option<PathBuf>,
}

enum ReadErr {
    Missing,
    Bad(String),
}

/// Entry and directory counters of one discovery-root walk.
#[derive(Default)]
struct RootWalk {
    entries: usize,
    dirs: usize,
    stopped: bool,
}

impl<'a> Discoverer<'a> {
    fn new(
        sel: &'a Selection,
        max_file_bytes: u64,
        display: &'a PathDisplay,
        budget: Budget,
    ) -> Self {
        let home_roots = [".claude", ".codex", ".agents"]
            .iter()
            .filter_map(|d| sel.home.join(d).canonicalize().ok())
            .collect();
        Discoverer {
            sel,
            display,
            max_file_bytes,
            budget,
            out: Discovery::default(),
            home_roots,
            project_canon: sel.project.canonicalize().ok(),
            plugins_canon: sel.home.join(".claude/plugins").canonicalize().ok(),
        }
    }
}

impl Discoverer<'_> {
    fn run(&mut self) {
        let home = self.sel.home.clone();
        let project = self.sel.project.clone();
        let same_root = same_dir(&home, &project);
        if self.sel.wants(Agent::Claude, Scope::User) {
            self.skills(Agent::Claude, Scope::User, &home.join(".claude/skills"));
        }
        if self.sel.wants(Agent::Claude, Scope::Project) && !same_root {
            self.skills(
                Agent::Claude,
                Scope::Project,
                &project.join(".claude/skills"),
            );
        }
        if self.sel.wants_agent(Agent::Claude) {
            self.plugins(&home.join(".claude/plugins"));
            self.claude_json(&home.join(".claude.json"));
        }
        if self.sel.wants(Agent::Claude, Scope::Project) {
            let path = project.join(".mcp.json");
            if self.inside_project(&path)
                && let Some((v, text)) = self.config_json(&path)
            {
                self.mcp_servers_in(Agent::Claude, Scope::Project, &path, &v, &text);
            }
        }
        if self.sel.wants(Agent::Codex, Scope::User) {
            self.codex_config(&home.join(".codex/config.toml"));
            self.skills(Agent::Codex, Scope::User, &home.join(".codex/skills"));
            self.skills(Agent::Codex, Scope::User, &home.join(".agents/skills"));
        }
    }

    fn note(&mut self, reason: &str, path: &Path) {
        let shown = self.display.show(path);
        self.out.incomplete.push(format!("{reason}:{shown}"));
    }

    fn read(&mut self, root: &Path, top_level: Option<&[&str]>) -> DirContent {
        let mut ctx = ReadCtx {
            max_file_bytes: self.max_file_bytes,
            budget: &mut self.budget,
            display: self.display,
        };
        read_tree(root, top_level, &mut ctx)
    }

    /// `path` exists and resolves inside the canonical project (project
    /// configs); a resolution outside it is noted and refused.
    fn inside_project(&mut self, path: &Path) -> bool {
        if std::fs::symlink_metadata(path).is_err() {
            return false;
        }
        match (path.canonicalize(), &self.project_canon) {
            (Ok(c), Some(p)) if c.starts_with(p) => true,
            (Ok(_), _) => {
                self.note("symlink_outside_trusted_roots", path);
                false
            }
            (Err(_), _) => {
                self.note("unreadable", path);
                false
            }
        }
    }

    // ── skills ──────────────────────────────────────────────────────────

    fn skills(&mut self, agent: Agent, scope: Scope, root: &Path) {
        let meta = match std::fs::symlink_metadata(root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => return self.note("unreadable", root),
            Ok(m) => m,
        };
        if scope == Scope::Project && meta.file_type().is_symlink() {
            // `<project>/.claude/skills` must be a real directory.
            return self.note("symlink_not_followed", root);
        }
        let Ok(root_canon) = root.canonicalize() else {
            return self.note("unreadable", root);
        };
        if scope == Scope::Project
            && !self
                .project_canon
                .as_ref()
                .is_some_and(|p| root_canon.starts_with(p))
        {
            // e.g. `<project>/.claude` itself is a symlink out of the project.
            return self.note("symlink_outside_trusted_roots", root);
        }
        let mut trusted: Vec<PathBuf> = vec![root_canon.clone()];
        trusted.extend(self.project_canon.clone());
        if scope == Scope::User {
            trusted.extend(self.home_roots.iter().cloned());
        }
        let mut found = Vec::new();
        let mut visited = HashSet::from([root_canon.clone()]);
        let mut walk = RootWalk::default();
        self.walk_skills(
            &root_canon,
            &trusted,
            1,
            &mut visited,
            &mut found,
            &mut walk,
        );
        for (name, dir) in found {
            let content = self.read(&dir, None);
            let item =
                Discovered::new(agent, Kind::Skill, scope, &name, &dir).with_content(content);
            self.out.items.push(item);
        }
    }

    fn walk_skills(
        &mut self,
        dir: &Path,
        trusted: &[PathBuf],
        depth: usize,
        visited: &mut HashSet<PathBuf>,
        found: &mut Vec<(String, PathBuf)>,
        walk: &mut RootWalk,
    ) {
        if walk.stopped {
            return;
        }
        let max = self.budget.item_max_entries;
        let listing = match list_dir(dir, &mut self.budget, &mut walk.entries, max) {
            Ok(l) => l,
            Err(_) => return self.note("unreadable", dir),
        };
        if listing.entry_errors {
            self.note("unreadable", dir);
        }
        match listing.stop {
            Some(Stop::Item) => {
                walk.stopped = true;
                return self.note("limit_reached", dir);
            }
            Some(Stop::Global) => {
                walk.stopped = true;
                return self.out.incomplete.push("global_limit_reached".into());
            }
            None => {}
        }
        for name in listing.names {
            if walk.stopped {
                return;
            }
            let path = dir.join(&name);
            let Some(target) = self.skill_dir_target(&path, trusted) else {
                continue;
            };
            if !visited.insert(target.clone()) {
                continue;
            }
            if target.join("SKILL.md").is_file() {
                found.push((os_display(&name), target));
            } else if depth < SKILL_DEPTH {
                if walk.dirs >= self.budget.item_max_dirs {
                    walk.stopped = true;
                    return self.note("limit_reached", &path);
                }
                walk.dirs += 1;
                self.walk_skills(&target, trusted, depth + 1, visited, found, walk);
            }
        }
    }

    /// The directory an entry under a skills root stands for. A symlink is
    /// followed only when its target is inside one of the `trusted` roots
    /// (the same skills root, the project, and for user roots the canonical
    /// `~/.claude`, `~/.codex`, `~/.agents`); otherwise it is not read.
    fn skill_dir_target(&mut self, path: &Path, trusted: &[PathBuf]) -> Option<PathBuf> {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            self.note("unreadable", path);
            return None;
        };
        if !meta.file_type().is_symlink() {
            return meta
                .is_dir()
                .then(|| path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
        }
        match path.canonicalize() {
            Ok(t) if t.is_dir() => {
                if trusted.iter().any(|r| t.starts_with(r)) {
                    Some(t)
                } else {
                    self.note("symlink_outside_trusted_roots", path);
                    None
                }
            }
            Ok(_) => None,
            Err(_) => {
                self.note("unreadable", path);
                None
            }
        }
    }

    // ── plugins ─────────────────────────────────────────────────────────

    fn plugins(&mut self, dir: &Path) {
        if !dir.is_dir() {
            return;
        }
        let manifest = dir.join("installed_plugins.json");
        let installs = match self.read_config(&manifest) {
            Ok(text) => match serde_json::from_str::<Value>(&text) {
                Ok(v) => self.parse_installs(&v, &manifest),
                Err(_) => {
                    self.note("parse_error", &manifest);
                    None
                }
            },
            Err(ReadErr::Missing) => {
                self.note("plugin_manifest_missing", &manifest);
                None
            }
            Err(ReadErr::Bad(reason)) => {
                self.out.incomplete.push(reason);
                None
            }
        };
        let installs = match installs {
            Some(list) => list,
            None => {
                self.note("plugin_manifest_fallback", &dir.join("cache"));
                self.fallback_installs(&dir.join("cache"))
            }
        };
        for inst in installs {
            if self.sel.wants(Agent::Claude, inst.scope) {
                self.plugin_item(&inst);
            }
        }
    }

    fn parse_installs(&mut self, v: &Value, manifest: &Path) -> Option<Vec<Install>> {
        let Some(plugins) = v.get("plugins").and_then(Value::as_object) else {
            self.note("parse_error", manifest);
            return None;
        };
        let mut out = Vec::new();
        for (key, val) in plugins {
            let entries: Vec<&Value> = match val {
                Value::Array(a) => a.iter().collect(),
                Value::Object(_) => vec![val],
                _ => {
                    self.note("parse_error", manifest);
                    continue;
                }
            };
            for e in entries {
                let Some(path) = e.get("installPath").and_then(Value::as_str) else {
                    self.note("parse_error", manifest);
                    continue;
                };
                let path = PathBuf::from(path);
                let scope = match e.get("scope").and_then(Value::as_str).unwrap_or("user") {
                    "user" => Scope::User,
                    _ => Scope::Project,
                };
                if scope == Scope::Project
                    && !e
                        .get("projectPath")
                        .and_then(Value::as_str)
                        .is_some_and(|p| same_dir(Path::new(p), &self.sel.project))
                {
                    continue;
                }
                let version = e
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| path.file_name().map(os_display))
                    .unwrap_or_else(|| "unknown".into());
                out.push(Install {
                    key: key.clone(),
                    version,
                    path,
                    scope,
                });
            }
        }
        Some(out)
    }

    fn plugin_item(&mut self, inst: &Install) {
        let name = format!("{}/{}", inst.key, inst.version);
        let canon = inst.path.canonicalize();
        let content = match &canon {
            // `installPath` comes from a config file: only read it when it
            // resolves strictly inside `~/.claude/plugins/`.
            Ok(c)
                if !self
                    .plugins_canon
                    .as_ref()
                    .is_some_and(|root| c.starts_with(root) && c != root) =>
            {
                DirContent {
                    incomplete: vec!["install_path_outside_plugins_root".into()],
                    ..Default::default()
                }
            }
            Ok(c) if c.is_dir() => {
                let c = c.clone();
                self.read(&c, Some(PLUGIN_PARTS))
            }
            _ => DirContent {
                incomplete: vec![format!("unreadable:{}", self.display.show(&inst.path))],
                ..Default::default()
            },
        };
        let path = canon.unwrap_or_else(|_| inst.path.clone());
        let mut item = Discovered::new(Agent::Claude, Kind::Plugin, inst.scope, &name, &path)
            .with_content(content);
        let texts = item.texts.clone();
        for t in texts
            .iter()
            .filter(|t| STRUCTURED.contains(&t.rel.as_str()))
        {
            self.plugin_manifest(&mut item, t);
        }
        self.out.items.push(item);
    }

    fn plugin_manifest(&mut self, item: &mut Discovered, t: &TextFile) {
        let Ok(v) = serde_json::from_str::<Value>(&t.text) else {
            let shown = self.display.show(&t.path);
            item.incomplete.push(format!("parse_error:{shown}"));
            return;
        };
        match t.rel.as_str() {
            "hooks/hooks.json" => {
                let mut cmds = Vec::new();
                collect_key_strings(&v, "command", &mut cmds, 0);
                for c in cmds {
                    let line = line_of_string(&t.text, &c);
                    item.hooks.push(Located {
                        text: c,
                        file: t.path.clone(),
                        line,
                    });
                }
            }
            ".mcp.json" => {
                let servers = v.get("mcpServers").unwrap_or(&v);
                if let Some(map) = servers.as_object() {
                    for (name, entry) in map.iter().filter(|(_, e)| e.is_object()) {
                        item.mcp.push(McpSite {
                            entry: McpEntry::new(name, entry.clone()),
                            file: t.path.clone(),
                            line: line_of_key(&t.text, name),
                        });
                    }
                }
            }
            _ => {
                let mut descs = Vec::new();
                collect_key_strings(&v, "description", &mut descs, 0);
                for d in descs {
                    let line = line_of_string(&t.text, &d);
                    item.descriptions.push(Located {
                        text: d,
                        file: t.path.clone(),
                        line,
                    });
                }
            }
        }
    }

    // ── MCP configs ─────────────────────────────────────────────────────

    fn read_config(&mut self, path: &Path) -> Result<String, ReadErr> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReadErr::Missing),
            Err(_) => {
                return Err(ReadErr::Bad(format!(
                    "unreadable:{}",
                    self.display.show(path)
                )));
            }
            Ok(_) => {}
        }
        let bytes = read_capped_to(path, CONFIG_CAP + 1)
            .map_err(|_| ReadErr::Bad(format!("unreadable:{}", self.display.show(path))))?;
        if bytes.len() as u64 > CONFIG_CAP {
            return Err(ReadErr::Bad(format!(
                "limit_reached:{}",
                self.display.show(path)
            )));
        }
        String::from_utf8(bytes)
            .map_err(|_| ReadErr::Bad(format!("parse_error:{}", self.display.show(path))))
    }

    /// A JSON config; `None` when missing (silently) or broken (noted).
    fn config_json(&mut self, path: &Path) -> Option<(Value, String)> {
        match self.read_config(path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(v) => Some((v, text)),
                Err(_) => {
                    self.note("parse_error", path);
                    None
                }
            },
            Err(ReadErr::Missing) => None,
            Err(ReadErr::Bad(reason)) => {
                self.out.incomplete.push(reason);
                None
            }
        }
    }

    fn claude_json(&mut self, path: &Path) {
        let Some((v, text)) = self.config_json(path) else {
            return;
        };
        if self.sel.wants(Agent::Claude, Scope::User)
            && let Some(servers) = v.get("mcpServers")
        {
            self.mcp_servers(Agent::Claude, Scope::User, path, servers, &text);
        }
        if !self.sel.wants(Agent::Claude, Scope::Project) {
            return;
        }
        let Some(projects) = v.get("projects").and_then(Value::as_object) else {
            return;
        };
        for (p, pv) in projects {
            if same_dir(Path::new(p), &self.sel.project)
                && let Some(servers) = pv.get("mcpServers")
            {
                self.mcp_servers(Agent::Claude, Scope::Project, path, servers, &text);
            }
        }
    }

    /// `{"mcpServers": {...}}` in a project `.mcp.json`.
    fn mcp_servers_in(&mut self, agent: Agent, scope: Scope, path: &Path, v: &Value, text: &str) {
        match v.get("mcpServers") {
            Some(servers) => self.mcp_servers(agent, scope, path, servers, text),
            None => self.note("parse_error", path),
        }
    }

    fn mcp_servers(
        &mut self,
        agent: Agent,
        scope: Scope,
        path: &Path,
        servers: &Value,
        text: &str,
    ) {
        let Some(map) = servers.as_object() else {
            return self.note("parse_error", path);
        };
        for (name, entry) in map {
            if !entry.is_object() {
                self.note("parse_error", path);
                continue;
            }
            let line = line_of_key(text, name);
            self.push_mcp(agent, scope, path, McpEntry::new(name, entry.clone()), line);
        }
    }

    fn push_mcp(
        &mut self,
        agent: Agent,
        scope: Scope,
        path: &Path,
        entry: McpEntry,
        line: Option<usize>,
    ) {
        let mut item = Discovered::new(agent, Kind::Mcp, scope, &entry.name, path);
        item.files = entry.field_records();
        item.hash = entry.hash();
        item.mcp.push(McpSite {
            entry,
            file: path.to_path_buf(),
            line,
        });
        self.out.items.push(item);
    }

    fn codex_config(&mut self, path: &Path) {
        let text = match self.read_config(path) {
            Ok(t) => t,
            Err(ReadErr::Missing) => return,
            Err(ReadErr::Bad(reason)) => return self.out.incomplete.push(reason),
        };
        let table: toml::Table = match toml::from_str(&text) {
            Ok(t) => t,
            Err(_) => return self.note("parse_error", path),
        };
        let Some(servers) = table.get("mcp_servers") else {
            return;
        };
        let Some(servers) = servers.as_table() else {
            return self.note("parse_error", path);
        };
        for (name, v) in servers {
            match serde_json::to_value(v) {
                Ok(json) if json.is_object() => {
                    let line = line_of_toml_table(&text, name);
                    self.push_mcp(
                        Agent::Codex,
                        Scope::User,
                        path,
                        McpEntry::new(name, json),
                        line,
                    );
                }
                _ => self.note("parse_error", path),
            }
        }
    }
}

struct Install {
    key: String,
    version: String,
    path: PathBuf,
    scope: Scope,
}

impl Discoverer<'_> {
    /// `cache/<marketplace>/<plugin>/<version>/` when the manifest is unusable.
    fn fallback_installs(&mut self, cache: &Path) -> Vec<Install> {
        let mut walk = RootWalk::default();
        let mut out = Vec::new();
        let name = |p: &Path| p.file_name().map(os_display).unwrap_or_default();
        for mkt in self.sorted_dirs(cache, &mut walk) {
            for plugin in self.sorted_dirs(&mkt, &mut walk) {
                for ver in self.sorted_dirs(&plugin, &mut walk) {
                    out.push(Install {
                        key: format!("{}@{}", name(&plugin), name(&mkt)),
                        version: name(&ver),
                        path: ver,
                        scope: Scope::User,
                    });
                }
            }
        }
        out
    }

    /// Real (non-symlink) subdirectories of `dir`, sorted; the listing is
    /// streamed and counted like any other directory walk.
    fn sorted_dirs(&mut self, dir: &Path, walk: &mut RootWalk) -> Vec<PathBuf> {
        if walk.stopped {
            return Vec::new();
        }
        let max = self.budget.item_max_entries;
        let listing = match list_dir(dir, &mut self.budget, &mut walk.entries, max) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(_) => {
                self.note("unreadable", dir);
                return Vec::new();
            }
        };
        if listing.entry_errors {
            self.note("unreadable", dir);
        }
        match listing.stop {
            Some(Stop::Item) => {
                walk.stopped = true;
                self.note("limit_reached", dir);
            }
            Some(Stop::Global) => {
                walk.stopped = true;
                self.out.incomplete.push("global_limit_reached".into());
            }
            None => {}
        }
        listing
            .names
            .iter()
            .map(|n| dir.join(n))
            .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
            .collect()
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn collect_key_strings(v: &Value, key: &str, out: &mut Vec<String>, depth: usize) {
    if depth > MAX_JSON_DEPTH {
        return;
    }
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match x.as_str() {
                    Some(s) if k == key => out.push(s.to_string()),
                    _ => collect_key_strings(x, key, out, depth + 1),
                }
            }
        }
        Value::Array(a) => {
            for x in a {
                collect_key_strings(x, key, out, depth + 1);
            }
        }
        _ => {}
    }
}

/// 1-based line of the first occurrence of `s` as a JSON string literal.
fn line_of_string(text: &str, s: &str) -> Option<usize> {
    let encoded = serde_json::to_string(s).ok()?;
    let inner = &encoded[1..encoded.len() - 1];
    let probe: String = inner.chars().take(60).collect();
    if probe.is_empty() {
        return None;
    }
    text.lines().position(|l| l.contains(&probe)).map(|i| i + 1)
}

fn line_of_key(text: &str, key: &str) -> Option<usize> {
    let encoded = serde_json::to_string(key).ok()?;
    text.lines()
        .position(|l| {
            l.find(&encoded)
                .is_some_and(|i| l[i + encoded.len()..].trim_start().starts_with(':'))
        })
        .map(|i| i + 1)
}

fn line_of_toml_table(text: &str, name: &str) -> Option<usize> {
    let bare = format!("[mcp_servers.{name}]");
    let quoted = format!("[mcp_servers.\"{name}\"]");
    text.lines()
        .position(|l| {
            let t = l.trim();
            t == bare || t == quoted
        })
        .map(|i| i + 1)
}

fn assign_ids(items: &mut [Discovered]) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for it in items {
        let base = format!(
            "{}:{}:{}:{}",
            it.agent.as_str(),
            it.kind.as_str(),
            it.scope.as_str(),
            it.name
        );
        let n = seen.entry(base.clone()).or_insert(0);
        *n += 1;
        it.id = if *n == 1 { base } else { format!("{base}#{n}") };
    }
}

#[cfg(test)]
#[path = "discover_tests.rs"]
mod tests;
