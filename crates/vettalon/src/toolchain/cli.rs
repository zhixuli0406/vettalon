//! `vettalon toolchain audit | pin | pins`. Exit codes of `audit`: `0` no
//! finding at or above `--fail-on` and the audit is complete, `1` at least
//! one such finding, `2` the audit is incomplete (unless
//! `--allow-incomplete`), or an argument, I/O or pin-store error. `pin`:
//! `1` when refused.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::discover::{Discovered, Discovery, discover};
use super::npm::{self, NpmSpec, NpmUse};
use super::pins::{self, PinRecord, PinStore};
use super::report::{
    PinState, ReportFinding, ReportItem, ReportScope, ReportSummary, ToolchainReport, render_text,
    severity_counts,
};
use super::{
    DEFAULT_MAX_FILE_BYTES, Kind, PathDisplay, RULES_VERSION, RawFinding, SCHEMA, SECRET_EXCERPT,
    Scope, Selection, clean_text, mcp, rules, sarif,
};
use crate::audit::schema::Severity;
use crate::tr;

/// Paths listed per category in a PN001 message.
const MAX_LISTED_PATHS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

impl Format {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            other => Err(format!(
                "--format must be text, json or sarif (got {other:?})"
            )),
        }
    }
}

/// `--fail-on`: `none` disables the gate.
pub fn parse_fail_on(value: &str) -> Result<Option<Severity>, String> {
    if value.trim().eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    value.parse::<Severity>().map(Some)
}

pub struct AuditOptions {
    pub selection: Selection,
    pub format: Format,
    pub out: Option<PathBuf>,
    pub fail_on: Option<Severity>,
    /// Exit by `--fail-on` alone, even when the audit is incomplete.
    pub allow_incomplete: bool,
    pub online: bool,
    pub max_file_bytes: u64,
}

/// Discovery plus every rule except the pin rules.
struct Analysis {
    disc: Discovery,
    /// `(item index, finding)`.
    findings: Vec<(usize, RawFinding)>,
    incomplete: Vec<String>,
}

/// Findings in a secret-bearing file keep their rule, severity and location;
/// the excerpt is a fixed placeholder and the content-derived message is
/// replaced by the rule's description.
fn withhold(findings: &mut [RawFinding]) {
    for f in findings {
        f.excerpt = SECRET_EXCERPT.to_string();
        if let Some((_, _, desc)) = sarif::RULES.iter().find(|r| r.0 == f.rule) {
            f.message = format!("{desc} (secret-bearing file; details withheld)");
        }
    }
}

fn item_findings(item: &Discovered) -> Vec<RawFinding> {
    let mut out = item.read_findings.clone();
    for t in &item.texts {
        let mut found = Vec::new();
        if item.is_structured(t) {
            rules::scan_hidden(&t.path, &t.text, &mut found);
        } else {
            rules::scan_text_in(
                &t.path,
                std::path::Path::new(&t.rel),
                &t.text,
                t.is_instruction(),
                &mut found,
            );
        }
        if t.secret {
            withhold(&mut found);
        }
        out.append(&mut found);
    }
    for h in &item.hooks {
        rules::scan_command(Some(h.file.as_path()), h.line, &h.text, &mut out);
    }
    for d in &item.descriptions {
        rules::scan_description(&d.file, d.line, &d.text, &mut out);
    }
    for s in &item.mcp {
        mcp::entry_rules(&s.entry, &s.file, s.line, &mut out);
    }
    out
}

async fn analyze(
    sel: &Selection,
    max_file_bytes: u64,
    online: bool,
    display: &PathDisplay,
) -> Analysis {
    let disc = discover(sel, max_file_bytes, display);
    let mut findings = Vec::new();
    let mut uses = Vec::new();
    for (i, item) in disc.items.iter().enumerate() {
        findings.extend(item_findings(item).into_iter().map(|f| (i, f)));
        for s in &item.mcp {
            match npm::npm_package(&s.entry) {
                Some(NpmSpec::Package { name, version }) => uses.push(NpmUse {
                    item: i,
                    file: s.file.clone(),
                    line: s.line,
                    name,
                    version,
                }),
                Some(NpmSpec::Invalid(spec)) => {
                    findings.push((i, npm::unparseable(&s.file, s.line, &spec)));
                }
                None => {}
            }
        }
    }
    let mal_dir = crate::util::vettalon_home().join("mal-index");
    let mc002 = npm::check(&uses, online, &mal_dir).await;
    findings.extend(mc002.findings);
    let mut incomplete = disc.incomplete.clone();
    incomplete.extend(mc002.incomplete);
    for item in &disc.items {
        incomplete.extend(item.incomplete.iter().map(|r| format!("{}: {r}", item.id)));
    }
    incomplete.dedup();
    Analysis {
        disc,
        findings,
        incomplete,
    }
}

/// Display path of the project, the pin key of project-scope items.
fn project_key(item: &Discovered, project: &str) -> Option<String> {
    (item.scope == Scope::Project).then(|| project.to_string())
}

fn project_display(sel: &Selection, display: &PathDisplay) -> String {
    display.show(
        &sel.project
            .canonicalize()
            .unwrap_or_else(|_| sel.project.clone()),
    )
}

fn listed(label: &str, paths: &[String]) -> Option<String> {
    if paths.is_empty() {
        return None;
    }
    let mut shown: Vec<&str> = paths
        .iter()
        .take(MAX_LISTED_PATHS)
        .map(String::as_str)
        .collect();
    let more = paths.len().saturating_sub(MAX_LISTED_PATHS);
    let extra = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    shown.sort();
    Some(format!("{label}: {}{extra}", shown.join(", ")))
}

fn pn001(item: &Discovered, pin: &PinRecord) -> RawFinding {
    let d = pins::diff(&pin.files, &item.files);
    let what = if item.kind == Kind::Mcp {
        "fields"
    } else {
        "files"
    };
    let parts: Vec<String> = [
        listed("modified", &d.modified),
        listed("added", &d.added),
        listed("removed", &d.removed),
    ]
    .into_iter()
    .flatten()
    .collect();
    let detail = if parts.is_empty() {
        "hash differs".to_string()
    } else {
        format!("changed {what}: {}", parts.join("; "))
    };
    RawFinding::new(
        "PN001",
        Severity::Medium,
        Some(item.path.as_path()),
        None,
        &format!("changed since pin ({}): {detail}", pin.pinned_at),
        "",
    )
}

/// Pin state of an item and its PN001 / PN002 finding, if any.
fn pin_state(item: &Discovered, store: &PinStore, project: &str) -> (PinState, Option<RawFinding>) {
    let key = project_key(item, project);
    match store.find(&item.id, key.as_deref()) {
        Some(pin) if pin.hash == item.hash => (PinState::Match, None),
        Some(pin) => (PinState::Changed, Some(pn001(item, pin))),
        None => (
            PinState::Unpinned,
            Some(RawFinding::new(
                "PN002",
                Severity::Info,
                Some(item.path.as_path()),
                None,
                "not pinned (record it with `vettalon toolchain pin`)",
                "",
            )),
        ),
    }
}

/// Whether a pin belongs to what this run discovers.
fn pin_in_selection(pin: &PinRecord, sel: &Selection, project: &str) -> bool {
    sel.wants(pin.agent, pin.scope)
        && (pin.scope == Scope::User || pin.project.as_deref() == Some(project))
}

fn build_report(
    sel: &Selection,
    a: Analysis,
    store: &PinStore,
    online: bool,
    display: &PathDisplay,
) -> ToolchainReport {
    let project = project_display(sel, display);
    let mut raw: Vec<(usize, RawFinding)> = a.findings;
    let mut items = Vec::new();
    for (i, item) in a.disc.items.iter().enumerate() {
        let (pin, f) = pin_state(item, store, &project);
        if let Some(f) = f {
            raw.push((i, f));
        }
        items.push(ReportItem {
            id: item.id.clone(),
            agent: item.agent,
            kind: item.kind,
            scope: item.scope,
            path: display.show(&item.path),
            hash: item.hash.clone(),
            pin,
            files: if item.kind == Kind::Mcp {
                1
            } else {
                item.files.len()
            },
            complete: item.incomplete.is_empty(),
            incomplete_reasons: item.incomplete.clone(),
        });
    }
    raw.sort_by(|(ia, fa), (ib, fb)| {
        ia.cmp(ib)
            .then(fb.severity.cmp(&fa.severity))
            .then(fa.rule.cmp(fb.rule))
            .then(fa.file.cmp(&fb.file))
            .then(fa.line.cmp(&fb.line))
    });
    let mut counters: HashMap<(String, String), usize> = HashMap::new();
    let mut findings: Vec<ReportFinding> = Vec::new();
    let mut push = |item_id: &str, f: RawFinding, file: Option<String>| {
        let n = counters
            .entry((f.rule.to_string(), item_id.to_string()))
            .or_insert(0);
        *n += 1;
        findings.push(ReportFinding {
            id: format!("{}:{item_id}:{n}", f.rule),
            rule: f.rule.to_string(),
            severity: f.severity,
            item: item_id.to_string(),
            file,
            line: f.line,
            message: f.message,
            excerpt: f.excerpt,
        });
    };
    for (i, f) in raw {
        let file = f.file.as_deref().map(|p| display.show(p));
        push(a.disc.items[i].id.as_str(), f, file);
    }
    for pin in store
        .pins
        .iter()
        .filter(|p| pin_in_selection(p, sel, &project))
    {
        let present = a
            .disc
            .items
            .iter()
            .any(|it| pin.matches(&it.id, project_key(it, &project).as_deref()));
        if !present {
            // Pin fields come from a file on disk: validated on load and
            // cleaned again here before they reach any output.
            let f = RawFinding::new(
                "PN003",
                Severity::Info,
                None,
                None,
                &format!(
                    "pinned item no longer discovered (pinned {})",
                    pin.pinned_at
                ),
                "",
            );
            push(&clean_text(&pin.id), f, Some(clean_text(&pin.path)));
        }
    }
    let summary = ReportSummary {
        items: items.len(),
        findings_by_severity: severity_counts(&findings),
        complete: a.incomplete.is_empty(),
        incomplete_reasons: a.incomplete,
    };
    ToolchainReport {
        schema: SCHEMA.into(),
        vettalon_version: env!("CARGO_PKG_VERSION").into(),
        rules_version: RULES_VERSION.into(),
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        scope: ReportScope {
            agents: sel.agents.clone(),
            scopes: sel.scopes.clone(),
            project,
        },
        online,
        items,
        findings,
        summary,
    }
}

/// The checked pin store directory (not a symlink, not inside the project,
/// owner/mode checked) with the local HMAC key loaded or created.
fn open_store(sel: &Selection) -> Result<PathBuf, String> {
    let dir = pins::checked_store_dir(&crate::util::vettalon_home(), &sel.project, &sel.home)?;
    let key = pins::load_or_create_key(&dir)?;
    super::set_hash_key(key)?;
    Ok(dir)
}

fn fail(msg: &str) -> i32 {
    eprintln!("[vettalon] {}", super::clean_text(msg));
    2
}

fn emit(text: &str, out: Option<&Path>) -> i32 {
    match out {
        Some(p) => match crate::remediation::write_new_text_output(p, text) {
            Ok(()) => {
                eprintln!("[vettalon] {}", tr!("已寫入 {}", "wrote {}", p.display()));
                0
            }
            Err(e) => fail(&e),
        },
        None => {
            print!("{text}");
            0
        }
    }
}

/// `vettalon toolchain audit`.
pub async fn cmd_audit(opts: AuditOptions) -> i32 {
    if opts.max_file_bytes == 0 {
        return fail("--max-file-bytes must be at least 1");
    }
    if let Some(p) = &opts.out
        && let Err(e) = crate::remediation::preflight_new_output(p)
    {
        return fail(&e);
    }
    let store = match open_store(&opts.selection).and_then(|dir| pins::load(&dir)) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let display = PathDisplay::new(&opts.selection.home);
    let a = analyze(&opts.selection, opts.max_file_bytes, opts.online, &display).await;
    let report = build_report(&opts.selection, a, &store, opts.online, &display);
    let text = match opts.format {
        Format::Text => render_text(&report, opts.fail_on, opts.allow_incomplete),
        Format::Json => match serde_json::to_string_pretty(&report) {
            Ok(s) => s + "\n",
            Err(e) => return fail(&e.to_string()),
        },
        Format::Sarif => sarif::render(&report),
    };
    // The report is printed or written first; the exit code then reflects
    // the gate and, unless --allow-incomplete, completeness.
    match emit(&text, opts.out.as_deref()) {
        0 => report.exit_code(opts.fail_on, opts.allow_incomplete),
        code => code,
    }
}

/// `vettalon toolchain pin`.
pub async fn cmd_pin(sel: Selection, ids: Vec<String>, accept_risk: bool) -> i32 {
    let dir = match open_store(&sel) {
        Ok(d) => d,
        Err(e) => return fail(&e),
    };
    let mut store = match pins::load(&dir) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let display = PathDisplay::new(&sel.home);
    let a = analyze(&sel, DEFAULT_MAX_FILE_BYTES, false, &display).await;
    let items = &a.disc.items;
    let selected: Vec<usize> = if ids.is_empty() {
        (0..items.len()).collect()
    } else {
        let mut out = Vec::new();
        for id in &ids {
            match items.iter().position(|it| &it.id == id) {
                Some(i) => out.push(i),
                None => return fail(&format!("no discovered item has id {id:?}")),
            }
        }
        out
    };
    let risky: Vec<&str> = selected
        .iter()
        .filter(|&&i| {
            !items[i].incomplete.is_empty()
                || a.findings
                    .iter()
                    .any(|(j, f)| *j == i && f.severity >= Severity::High)
        })
        .map(|&i| items[i].id.as_str())
        .collect();
    // TC011: dependency trees are hashed by size/mode only, so a same-size
    // replacement inside one would never be detected.
    let dep_trees: Vec<&str> = selected
        .iter()
        .filter(|&&i| {
            !risky.contains(&items[i].id.as_str())
                && a.findings.iter().any(|(j, f)| *j == i && f.rule == "TC011")
        })
        .map(|&i| items[i].id.as_str())
        .collect();
    if (!risky.is_empty() || !dep_trees.is_empty()) && !accept_risk {
        if !risky.is_empty() {
            eprintln!(
                "[vettalon] {}",
                tr!(
                    "拒絕釘選（有 high/critical 發現或內容不完整；確認後可加 --accept-risk）：",
                    "refusing to pin (high/critical finding or incomplete content; add --accept-risk after review):"
                )
            );
            for id in risky {
                eprintln!("  - {}", super::clean_text(id));
            }
        }
        if !dep_trees.is_empty() {
            eprintln!(
                "[vettalon] {}",
                tr!(
                    "拒絕釘選（相依目錄僅以大小/權限追蹤，同大小的內容替換不會被偵測；確認後可加 --accept-risk）：",
                    "refusing to pin (dependency trees are tracked by size/mode only, so same-size replacements are not detected; add --accept-risk after review):"
                )
            );
            for id in dep_trees {
                eprintln!("  - {}", super::clean_text(id));
            }
        }
        return 1;
    }
    let project = project_display(&sel, &display);
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    for &i in &selected {
        let it = &items[i];
        store.upsert(PinRecord {
            id: it.id.clone(),
            agent: it.agent,
            kind: it.kind,
            scope: it.scope,
            project: project_key(it, &project),
            path: display.show(&it.path),
            hash: it.hash.clone(),
            pinned_at: now.clone(),
            files: it.files.clone(),
        });
    }
    if let Err(e) = pins::save(&dir, &store) {
        return fail(&e);
    }
    println!(
        "{}",
        tr!("已釘選 {} 個項目", "pinned {} items", selected.len())
    );
    0
}

#[derive(Serialize)]
struct PinsListing<'a> {
    schema: &'static str,
    pins: Vec<PinListed<'a>>,
}

/// One pin as listed: item hash, counts and timestamps only. Per-file
/// (and per-field) hashes stay in the store.
#[derive(Serialize)]
struct PinListed<'a> {
    id: &'a str,
    agent: super::Agent,
    kind: Kind,
    scope: Scope,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<&'a str>,
    path: &'a str,
    hash: &'a str,
    pinned_at: &'a str,
    /// Number of file (or field) records.
    files: usize,
    /// `null` when the pin belongs to another project (not checked).
    present: Option<bool>,
}

/// `vettalon toolchain pins`.
pub fn cmd_pins(sel: Selection, format: Format) -> i32 {
    if format == Format::Sarif {
        return fail("--format for pins must be text or json");
    }
    let store = match open_store(&sel).and_then(|dir| pins::load(&dir)) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let display = PathDisplay::new(&sel.home);
    let project = project_display(&sel, &display);
    let disc = discover(&sel, DEFAULT_MAX_FILE_BYTES, &display);
    let listed: Vec<PinListed<'_>> = store
        .pins
        .iter()
        .map(|pin| PinListed {
            id: &pin.id,
            agent: pin.agent,
            kind: pin.kind,
            scope: pin.scope,
            project: pin.project.as_deref(),
            path: &pin.path,
            hash: &pin.hash,
            pinned_at: &pin.pinned_at,
            files: pin.files.len(),
            present: pin_in_selection(pin, &sel, &project).then(|| {
                disc.items
                    .iter()
                    .any(|it| pin.matches(&it.id, project_key(it, &project).as_deref()))
            }),
        })
        .collect();
    let text = match format {
        Format::Json => {
            let doc = PinsListing {
                schema: "vettalon.toolchain-pins-list/1",
                pins: listed,
            };
            match serde_json::to_string_pretty(&doc) {
                Ok(s) => s + "\n",
                Err(e) => return fail(&e.to_string()),
            }
        }
        _ => render_pins(&listed),
    };
    print!("{text}");
    0
}

fn render_pins(listed: &[PinListed<'_>]) -> String {
    if listed.is_empty() {
        return tr!("沒有釘選的項目\n", "no pinned items\n");
    }
    let mut out = String::new();
    for l in listed {
        let present = match l.present {
            Some(true) => tr!("存在", "present"),
            Some(false) => tr!("找不到", "missing"),
            None => tr!("未檢查（其他專案）", "not checked (other project)"),
        };
        // Every field comes from the store on disk: clean all of them.
        out.push_str(&format!(
            "{}  {}  {}  {}  [{present}]\n",
            clean_text(l.id),
            clean_text(l.hash),
            clean_text(l.pinned_at),
            clean_text(l.path),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_parses_none_and_severities() {
        assert_eq!(parse_fail_on("none").unwrap(), None);
        assert_eq!(parse_fail_on("HIGH").unwrap(), Some(Severity::High));
        assert!(parse_fail_on("loud").is_err());
        assert!(Format::parse("xml").is_err());
    }

    // L10: every pin field is cleaned before text rendering.
    #[test]
    fn pin_listing_cleans_every_field() {
        let l = PinListed {
            id: "a\u{1b}[2Jb",
            agent: super::super::Agent::Claude,
            kind: Kind::Skill,
            scope: Scope::User,
            project: None,
            path: "~/x\u{7}\u{202e}",
            hash: "sha256:\u{1b}]0;t\u{7}",
            pinned_at: "2026\u{9b}",
            files: 0,
            present: Some(true),
        };
        let out = render_pins(&[l]);
        assert!(
            !out.chars()
                .any(|c| c != '\n' && super::super::is_unsafe_char(c)),
            "{out:?}"
        );
        assert!(out.contains("\\u{1b}"), "{out:?}");
    }

    #[test]
    fn incomplete_audits_exit_2_unless_allowed() {
        let report = ToolchainReport {
            schema: SCHEMA.into(),
            vettalon_version: "0".into(),
            rules_version: RULES_VERSION.into(),
            generated_at: "2026-11-08T00:00:00Z".into(),
            scope: ReportScope {
                agents: vec![],
                scopes: vec![],
                project: "~".into(),
            },
            online: false,
            items: vec![],
            findings: vec![],
            summary: ReportSummary {
                items: 0,
                findings_by_severity: Default::default(),
                complete: false,
                incomplete_reasons: vec!["unreadable:~/x".into()],
            },
        };
        assert_eq!(report.exit_code(Some(Severity::High), false), 2);
        assert_eq!(report.exit_code(None, false), 2);
        assert_eq!(report.exit_code(Some(Severity::High), true), 0);
        let text = render_text(&report, Some(Severity::High), false);
        assert!(
            text.contains("Exit 2") || text.contains("結束碼 2"),
            "{text}"
        );
    }

    #[test]
    fn listed_caps_paths() {
        let paths: Vec<String> = (0..25).map(|i| format!("f{i:02}")).collect();
        let s = listed("modified", &paths).unwrap();
        assert!(s.contains("(+5 more)"));
        assert!(listed("added", &[]).is_none());
    }
}
