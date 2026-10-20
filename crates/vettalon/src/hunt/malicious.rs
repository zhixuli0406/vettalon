//! Rule-based malicious-package signals for `hunt --malicious-signals` (O18).
//!
//! Signals are computed by fixed rules from registry metadata, OSV / local
//! `MAL-*` reports and the shipped popularity snapshot. No model is involved:
//! an LLM may at most review a finding later, never create or confirm one. A
//! finding is emitted only for one strong signal or two medium ones of
//! different kinds; every signal (including single weak ones) stays visible in
//! `checks`. Findings are a distinct kind and are always `needs_human`.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::mal_index::{MalIndex, MalIndexInfo};
use super::osv::{DependencyAdvisories, KnownVuln};
use super::registry::{Provenance, RegistryProbe, ReleaseFacts};
use super::{DependencyTarget, Ecosystem, popular};

pub const RULES_VERSION: &str = "o18-rules-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    MalIdMatch,
    SecurityPlaceholder,
    NonexistentName,
    YoungRelease,
    InstallScriptAdded,
    InstallScriptChanged,
    ProvenanceChanged,
    ProvenanceDropped,
    Typosquat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    Weak,
    Medium,
    Strong,
}

impl SignalKind {
    pub fn strength(self) -> Strength {
        match self {
            SignalKind::MalIdMatch | SignalKind::SecurityPlaceholder => Strength::Strong,
            SignalKind::InstallScriptChanged => Strength::Weak,
            _ => Strength::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub kind: SignalKind,
    pub strength: Strength,
    pub evidence: String,
    /// Where the fact came from (`osv`, `mal-index`, `registry`, `snapshot`).
    pub source: String,
}

impl Signal {
    fn new(kind: SignalKind, evidence: String, source: &str) -> Self {
        Signal {
            kind,
            strength: kind.strength(),
            evidence,
            source: source.to_string(),
        }
    }
}

/// Rule results for one dependency.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageCheck {
    pub target: Option<DependencyTarget>,
    pub signals: Vec<Signal>,
    /// Rules that ran to a result (a "no signal" result included).
    pub rules_evaluated: Vec<String>,
    /// Rules that could not run, with the reason; never read as clean.
    pub rules_unknown: Vec<String>,
}

/// Only state a malicious-signal finding can have. There is no confirmed
/// variant: a human decides outside the tool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaliciousStatus {
    #[default]
    NeedsHuman,
}

/// A hunt finding of the distinct `malicious_package_signal` kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousFinding {
    pub kind: String,
    pub target: DependencyTarget,
    pub status: MaliciousStatus,
    pub signals: Vec<Signal>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousOptions {
    pub cooldown_hours: u32,
    /// Names exempt from the release-age rule (normalised per ecosystem).
    pub cooldown_exclude: Vec<String>,
    /// Registry lookups are network calls; the rest are offline.
    pub max_registry_checks: usize,
}

impl Default for MaliciousOptions {
    fn default() -> Self {
        MaliciousOptions {
            cooldown_hours: 72,
            cooldown_exclude: Vec::new(),
            max_registry_checks: 100,
        }
    }
}

/// Whole-hunt malicious-signal ledger.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaliciousReport {
    pub rules: String,
    pub cooldown_hours: u32,
    pub checks: Vec<PackageCheck>,
    pub findings: Vec<MaliciousFinding>,
    pub mal_index: Vec<MalIndexInfo>,
    pub complete: bool,
    pub incomplete_reasons: Vec<String>,
}

// ── offline rules ────────────────────────────────────────────────────────

/// Optimal-string-alignment distance, giving up above `max`.
pub fn edit_distance(a: &str, b: &str, max: usize) -> Option<usize> {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let mut prev2: Vec<usize> = vec![0; b.len() + 1];
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        let mut row_min = cur[0];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                cur[j] = cur[j].min(prev2[j - 2] + 1);
            }
            row_min = row_min.min(cur[j]);
        }
        if row_min > max {
            return None;
        }
        prev2 = std::mem::replace(&mut prev, cur);
    }
    (prev[b.len()] <= max).then_some(prev[b.len()])
}

/// Name close to a popular package but not itself listed.
pub fn typosquat(ecosystem: Ecosystem, name: &str) -> Result<Option<Signal>, String> {
    let Some(list) = popular::top_list(ecosystem) else {
        return Err("typosquat: no popularity snapshot for this ecosystem".into());
    };
    let n = popular::normalize(ecosystem, name);
    if list.rank_of(&n).is_some() || n.chars().count() < 5 {
        return Ok(None);
    }
    let mut best: Option<(usize, usize, &str)> = None;
    for (i, top) in list.names.iter().enumerate() {
        let len = top.chars().count();
        if len < 5 {
            continue;
        }
        let max = if len >= 10 { 2 } else { 1 };
        if let Some(d) = edit_distance(&n, top, max)
            && d > 0
            && best.is_none_or(|(bd, br, _)| (d, i) < (bd, br))
        {
            best = Some((d, i, top));
        }
    }
    Ok(best.map(|(d, i, top)| {
        Signal::new(
            SignalKind::Typosquat,
            format!(
                "edit distance {d} to popular '{top}' (snapshot rank {}); not itself in the snapshot",
                i + 1
            ),
            "snapshot",
        )
    }))
}

fn osv_mal_ids(known: &[KnownVuln]) -> Vec<&str> {
    known
        .iter()
        .filter(|k| k.id.starts_with("MAL-") || k.aliases.iter().any(|a| a.starts_with("MAL-")))
        .map(|k| k.id.as_str())
        .collect()
}

fn excluded(opts: &MaliciousOptions, t: &DependencyTarget) -> bool {
    let n = popular::normalize(t.ecosystem, &t.name);
    opts.cooldown_exclude
        .iter()
        .any(|e| popular::normalize(t.ecosystem, e) == n)
}

fn describe(p: &Provenance) -> String {
    match p {
        Provenance::Present {
            repository,
            workflow,
            ref_kind,
        } => format!(
            "{} {} ({})",
            repository.as_deref().unwrap_or("?"),
            workflow.as_deref().unwrap_or("?"),
            ref_kind.as_deref().unwrap_or("?")
        ),
        Provenance::Absent => "none".into(),
        Provenance::Unknown => "unknown".into(),
    }
}

/// Registry-fact rules (age, install hooks, provenance, existence).
pub fn registry_signals(
    t: &DependencyTarget,
    facts: &ReleaseFacts,
    opts: &MaliciousOptions,
    now: DateTime<Utc>,
    check: &mut PackageCheck,
) {
    let mut push = |s: Signal| check.signals.push(s);
    if facts.placeholder {
        push(Signal::new(
            SignalKind::SecurityPlaceholder,
            "registry serves a security holding package for this name (taken down)".into(),
            "registry",
        ));
    }
    match facts.exists {
        Some(false) => push(Signal::new(
            SignalKind::NonexistentName,
            format!(
                "{}@{} is not published in the public registry (removed, private, or never existed)",
                t.name, t.version
            ),
            "registry",
        )),
        Some(true) => {}
        None => check.rules_unknown.push("existence: unknown".into()),
    }
    check.rules_evaluated.push("existence".into());
    if facts.exists != Some(true) {
        return;
    }
    if excluded(opts, t) {
        check
            .rules_evaluated
            .push("release_age: skipped (cooldown allowlist)".into());
    } else if let Some(published) = facts.published_at {
        check.rules_evaluated.push("release_age".into());
        let age = now.signed_duration_since(published);
        if age < chrono::Duration::hours(i64::from(opts.cooldown_hours)) {
            push(Signal::new(
                SignalKind::YoungRelease,
                format!(
                    "published {} ({}h before this check; cooldown {}h)",
                    published.to_rfc3339(),
                    age.num_hours().max(0),
                    opts.cooldown_hours
                ),
                "registry",
            ));
        }
    } else {
        check
            .rules_unknown
            .push("release_age: publish time unknown".into());
    }
    match (&facts.scripts, &facts.previous_scripts) {
        (Some(cur), Some(prev)) => {
            check.rules_evaluated.push("install_scripts".into());
            let added: Vec<&String> = cur
                .hooks
                .iter()
                .filter(|h| !prev.hooks.contains(h))
                .collect();
            if !added.is_empty() {
                push(Signal::new(
                    SignalKind::InstallScriptAdded,
                    format!(
                        "install-time hook(s) {} new since {}",
                        added
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        facts
                            .previous_version
                            .as_deref()
                            .unwrap_or("the previous version")
                    ),
                    "registry",
                ));
            } else if !cur.hooks.is_empty() && cur.digest != prev.digest {
                push(Signal::new(
                    SignalKind::InstallScriptChanged,
                    format!(
                        "install-time hook content changed since {}",
                        facts
                            .previous_version
                            .as_deref()
                            .unwrap_or("the previous version")
                    ),
                    "registry",
                ));
            }
        }
        (Some(cur), None) if !cur.hooks.is_empty() => check.rules_unknown.push(format!(
            "install_scripts: hooks present ({}) but no earlier version to compare",
            cur.hooks.join(", ")
        )),
        (Some(_), None) => check.rules_evaluated.push("install_scripts".into()),
        _ => check
            .rules_unknown
            .push("install_scripts: not determined".into()),
    }
    match (&facts.provenance, &facts.previous_provenance) {
        (Provenance::Absent, Provenance::Present { .. }) => {
            check.rules_evaluated.push("provenance".into());
            push(Signal::new(
                SignalKind::ProvenanceDropped,
                format!(
                    "previous version {} had build provenance; this version has none",
                    facts.previous_version.as_deref().unwrap_or("?")
                ),
                "registry",
            ));
        }
        (
            cur @ Provenance::Present {
                repository: r1,
                workflow: w1,
                ref_kind: k1,
            },
            prev @ Provenance::Present {
                repository: r2,
                workflow: w2,
                ref_kind: k2,
            },
        ) => {
            check.rules_evaluated.push("provenance".into());
            let known = |a: &Option<String>, b: &Option<String>| a.is_some() && b.is_some();
            if (known(r1, r2) && r1 != r2)
                || (known(w1, w2) && w1 != w2)
                || (known(k1, k2) && k1 != k2)
            {
                push(Signal::new(
                    SignalKind::ProvenanceChanged,
                    format!("provenance {} → {}", describe(prev), describe(cur)),
                    "registry",
                ));
            }
        }
        (Provenance::Unknown, _) | (_, Provenance::Unknown) => {
            check.rules_unknown.push("provenance: unknown".into())
        }
        _ => check.rules_evaluated.push("provenance".into()),
    }
}

/// Emit a finding for one strong signal, or two medium signals of different kinds.
pub fn finding_for(check: &PackageCheck) -> Option<MaliciousFinding> {
    let target = check.target.clone()?;
    let strong = check.signals.iter().any(|s| s.strength == Strength::Strong);
    let mut medium: Vec<SignalKind> = check
        .signals
        .iter()
        .filter(|s| s.strength == Strength::Medium)
        .map(|s| s.kind)
        .collect();
    medium.sort_by_key(|k| *k as u8);
    medium.dedup();
    if !strong && medium.len() < 2 {
        return None;
    }
    Some(MaliciousFinding {
        kind: "malicious_package_signal".into(),
        target,
        status: MaliciousStatus::NeedsHuman,
        signals: check.signals.clone(),
        rationale: if strong {
            "strong rule signal; needs human review before any action".into()
        } else {
            format!(
                "{} independent medium rule signals; needs human review before any action",
                medium.len()
            )
        },
    })
}

/// Offline rules for one target: OSV `MAL-*` ids, local index, typosquat.
pub fn offline_check(
    t: &DependencyTarget,
    osv_known: Option<&[KnownVuln]>,
    indexes: &[MalIndex],
) -> PackageCheck {
    let mut check = PackageCheck {
        target: Some(t.clone()),
        ..Default::default()
    };
    match osv_known {
        Some(known) => {
            check.rules_evaluated.push("osv_mal_id".into());
            for id in osv_mal_ids(known) {
                check.signals.push(Signal::new(
                    SignalKind::MalIdMatch,
                    format!("OSV lists {id} for {}@{}", t.name, t.version),
                    "osv",
                ));
            }
        }
        None => check
            .rules_unknown
            .push("osv_mal_id: not queried for this dependency".into()),
    }
    if indexes.is_empty() {
        check
            .rules_unknown
            .push("mal_index: no local index (run `vettalon mal-index update`)".into());
    } else {
        let mut covered = false;
        for idx in indexes {
            if super::mal_index::ecosystem_of(&idx.ecosystem) == Some(t.ecosystem) {
                covered = true;
                for e in idx.matches(t.ecosystem, &t.name, &t.version) {
                    if !check.signals.iter().any(|s| s.evidence.contains(&e.id)) {
                        check.signals.push(Signal::new(
                            SignalKind::MalIdMatch,
                            format!(
                                "local index lists {} for {}@{} (index sha256 {})",
                                e.id,
                                t.name,
                                t.version,
                                &idx.archive_sha256[..idx.archive_sha256.len().min(12)]
                            ),
                            "mal-index",
                        ));
                    }
                }
            }
        }
        if covered {
            check.rules_evaluated.push("mal_index".into());
        } else {
            check
                .rules_unknown
                .push("mal_index: no local index for this ecosystem".into());
        }
    }
    match typosquat(t.ecosystem, &t.name) {
        Ok(signal) => {
            check.rules_evaluated.push("typosquat".into());
            check.signals.extend(signal);
        }
        Err(e) => check.rules_unknown.push(e),
    }
    check
}

/// Run every rule over `targets`. `osv_rows` carry plan-time OSV results;
/// registry rules run for at most `max_registry_checks` targets.
pub async fn check_all(
    targets: &[DependencyTarget],
    osv_rows: &[DependencyAdvisories],
    probe: Option<&dyn RegistryProbe>,
    indexes: &[MalIndex],
    opts: &MaliciousOptions,
    now: DateTime<Utc>,
) -> MaliciousReport {
    let osv: HashMap<(Ecosystem, &str, &str), &DependencyAdvisories> = osv_rows
        .iter()
        .map(|r| {
            (
                (
                    r.target.ecosystem,
                    r.target.name.as_str(),
                    r.target.version.as_str(),
                ),
                r,
            )
        })
        .collect();
    let mut report = MaliciousReport {
        rules: RULES_VERSION.into(),
        cooldown_hours: opts.cooldown_hours,
        mal_index: indexes.iter().map(MalIndex::info).collect(),
        ..Default::default()
    };
    let mut probed = 0usize;
    for t in targets {
        let row = osv.get(&(t.ecosystem, t.name.as_str(), t.version.as_str()));
        let osv_failed = row.is_some_and(|r| {
            !matches!(
                r.osv.status,
                super::osv::OsvStatus::Matched | super::osv::OsvStatus::Unmatched
            )
        });
        let known = row
            .filter(|r| {
                matches!(
                    r.osv.status,
                    super::osv::OsvStatus::Matched | super::osv::OsvStatus::Unmatched
                )
            })
            .map(|r| r.known.as_slice());
        let mut check = offline_check(t, known, indexes);
        if osv_failed {
            for r in check.rules_unknown.iter_mut() {
                if r.starts_with("osv_mal_id:") {
                    *r = "osv_mal_id: OSV query failed for this dependency".into();
                }
            }
        }
        match probe {
            Some(p) if probed < opts.max_registry_checks => {
                probed += 1;
                match p.release_facts(t).await {
                    Ok(facts) => {
                        registry_signals(t, &facts, opts, now, &mut check);
                        check.rules_unknown.extend(facts.notes.iter().cloned());
                    }
                    Err(e) => check.rules_unknown.push(format!(
                        "registry: {}",
                        crate::util::mask_sensitive_text(crate::util::truncate_bytes(&e, 200))
                    )),
                }
            }
            Some(_) => check
                .rules_unknown
                .push("registry: over --malicious-max-registry budget".into()),
            None => check.rules_unknown.push("registry: not queried".into()),
        }
        if let Some(f) = finding_for(&check) {
            report.findings.push(f);
        }
        report.checks.push(check);
    }
    if probe.is_some() && targets.len() > opts.max_registry_checks {
        report
            .incomplete_reasons
            .push("registry_check_budget_exhausted".into());
    }
    if indexes.is_empty() {
        report.incomplete_reasons.push("mal_index_absent".into());
    }
    // Any rule that could not be evaluated for any target leaves the report
    // incomplete: an unknown is never reported as "no signal".
    for c in &report.checks {
        for r in &c.rules_unknown {
            let reason = unknown_reason(r);
            if (reason == "mal_index_unavailable" && indexes.is_empty())
                || report.incomplete_reasons.iter().any(|x| x == reason)
            {
                continue;
            }
            report.incomplete_reasons.push(reason.into());
        }
    }
    report.complete = report.incomplete_reasons.is_empty();
    report
}

/// Report-level reason for one per-target unknown rule.
fn unknown_reason(rule: &str) -> &'static str {
    if rule.starts_with("osv_mal_id") {
        "osv_mal_id_unknown"
    } else if rule.starts_with("mal_index") {
        "mal_index_unavailable"
    } else if rule.starts_with("typosquat") {
        "typosquat_unavailable"
    } else {
        // registry budget/errors and registry-derived rules (existence,
        // release age, install scripts, provenance, attestations)
        "registry_rules_unknown"
    }
}

/// Text summary for the CLI.
pub fn render(report: &MaliciousReport) -> String {
    let with_signals = report
        .checks
        .iter()
        .filter(|c| !c.signals.is_empty())
        .count();
    let mut out = crate::tr!(
        "  惡意套件訊號（規則判定，未經模型，全部待人工）：檢查 {}、有訊號 {}、發出 finding {}{}\n",
        "  Malicious-package signals (rule-based, no model, all need human review): checked {}, with signals {}, findings {}{}\n",
        report.checks.len(),
        with_signals,
        report.findings.len(),
        if report.complete {
            String::new()
        } else {
            format!(" [incomplete: {}]", report.incomplete_reasons.join(", "))
        }
    );
    for f in &report.findings {
        out.push_str(&format!(
            "    - [{}] {} {}@{}: {}\n",
            "needs_human",
            f.target.ecosystem.as_str(),
            f.target.name,
            f.target.version,
            f.signals
                .iter()
                .map(|s| format!("{:?}: {}", s.kind, s.evidence))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    for c in report.checks.iter().filter(|c| !c.signals.is_empty()) {
        let Some(t) = &c.target else { continue };
        if report.findings.iter().any(|f| f.target == *t) {
            continue;
        }
        out.push_str(&format!(
            "    · {} {}@{} (signal below finding threshold): {}\n",
            t.ecosystem.as_str(),
            t.name,
            t.version,
            c.signals
                .iter()
                .map(|s| format!("{:?}", s.kind))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out
}

#[cfg(test)]
#[path = "malicious_tests.rs"]
mod tests;
