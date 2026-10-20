//! O9 (`--dual-finder-top N`, default off): the top N ranked modules are
//! audited by two finder families independently, the two candidate lists
//! are merged by root cause, and each surviving candidate is reviewed by a
//! refuter from a third family when the roster has one.
//!
//! Why: NOVA and the AIxCC teams found that bugs found by different model
//! families barely overlap, so a second family on the riskiest modules may
//! find root causes the first missed. It doubles the finder cost on those
//! modules, so the report records what the second family actually added
//! ([`DualFinderReport`]) and the operator can turn it back off when the
//! marginal yield is low.
//!
//! Dedupe ("the same patch fixes both", Codex Security / Team Atlanta):
//! - each finder may propose a fix for a candidate on dual modules (one
//!   line-range replacement, at most [`MAX_FIX_LINES`] lines). A fix is
//!   *usable* when it is well-formed and, applied to an in-memory copy of
//!   the file, changes its own candidate's sink line;
//! - when a usable fix exists for either candidate of a pair, the pair is
//!   merged only if one fix also changes the other candidate's sink line
//!   (`dedupe_basis = same_patch`) and the two CWEs do not conflict; a
//!   usable fix that leaves the other sink untouched, or two different
//!   CWEs, means two root causes;
//! - with no usable fix, the fallback is location + CWE: same sink file,
//!   sink lines at most [`LOCATION_WINDOW`] apart, same CWE on both
//!   (`dedupe_basis = location_cwe`); a missing CWE never merges;
//! - two candidates with the same id (same kind, file, line, snippet) are
//!   the same claim (`dedupe_basis = identical_claim`); this is checked
//!   before any patch or location match.
//!
//! The check is deliberately conservative: a fix that adds a guard above an
//! unchanged sink line does not count as fixing that sink, so such a pair
//! stays two rows. Splitting costs a reviewer a duplicate; merging wrongly
//! would hide a root cause. Nothing is written to disk.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::ai_audit::{ModuleAuditReport, ModuleOutcome};
use super::schema::{
    DUAL_FINDER_MERGE_PREFIX, EvidenceItem, EvidenceKind, Finding, FindingStatus, ProposedFix,
    TraceKind,
};

/// Largest proposed fix used for dedupe (lines replaced).
pub const MAX_FIX_LINES: u32 = 10;
/// Largest replacement text kept (bytes).
pub const MAX_FIX_BYTES: usize = 4 * 1024;
/// Sink lines at most this far apart count as one location (fallback).
pub const LOCATION_WINDOW: u32 = 3;

/// Extra finder instructions for dual-finder modules: ask for an optional
/// fix per candidate, used only to dedupe.
pub const FIX_REQUEST: &str = "\n\nThis module is also audited independently by another \
reviewer. To let duplicates be merged, each element MAY carry one extra key, \"fix\": the \
smallest edit that removes the root cause, as {\"file\": \"<repo-relative path shown \
above>\", \"start_line\": <first line replaced>, \"end_line\": <last line replaced>, \
\"replacement\": \"<new text for exactly those lines>\"} (at most 10 lines), or null when you \
cannot give one. It is never applied to the repository.\n";

/// How two candidates were judged to share a root cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupeBasis {
    SamePatch,
    LocationCwe,
    IdenticalClaim,
}

impl DedupeBasis {
    pub fn key(self) -> &'static str {
        match self {
            DedupeBasis::SamePatch => "same_patch",
            DedupeBasis::LocationCwe => "location_cwe",
            DedupeBasis::IdenticalClaim => "identical_claim",
        }
    }
}

/// One finder on a dual module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinderSide {
    pub model: String,
    pub family: String,
}

/// A module audited by two families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualModule {
    pub module_path: String,
    /// The finder the round-robin dealt the module to.
    pub primary: FinderSide,
    /// The added finder of another family (the marginal one).
    pub second: FinderSide,
}

/// What one family added on the dual modules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyYield {
    pub family: String,
    /// Live candidates it reported there (pre-check refutations excluded).
    pub candidates: usize,
    /// Merged root causes only this family found that the refuter did not
    /// refute.
    pub unique_root_causes: usize,
    /// Of those, how many ended `needs_human` (or confirmed).
    pub unique_needs_human: usize,
}

/// The marginal finder: on each dual module, the family added on top of
/// the round-robin one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginalYield {
    /// Module audit calls the added finders made (deferred modules excluded).
    pub calls: usize,
    /// Source bytes those calls sent (prompt size without the instructions).
    pub prompt_bytes: usize,
    /// Root causes only the added finder found (not refuted).
    pub extra_root_causes: usize,
    /// Of those, `needs_human` (or confirmed).
    pub extra_needs_human: usize,
    /// `ceil(calls / extra_needs_human)`; `None` when nothing was added.
    pub calls_per_extra_needs_human: Option<usize>,
    /// `ceil(prompt KiB / extra_needs_human)`; `None` when nothing was added.
    pub prompt_kib_per_extra_needs_human: Option<usize>,
}

/// Report record of a `--dual-finder-top` run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualFinderReport {
    /// The N requested.
    pub top: usize,
    pub modules: Vec<DualModule>,
    /// Why no module got two families (single-family roster), if so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    pub families: Vec<FamilyYield>,
    /// Root causes both families found (merged, not refuted).
    pub shared_root_causes: usize,
    /// Candidates merged into another, by basis.
    pub merged_same_patch: usize,
    pub merged_location_cwe: usize,
    pub merged_identical_claim: usize,
    /// Candidates whose proposed fix was usable for dedupe.
    pub usable_fixes: usize,
    pub marginal: MarginalYield,
}

/// Run state carried from the audit step to the report.
#[derive(Debug, Clone, Default)]
pub struct DualRun {
    pub top: usize,
    pub modules: Vec<DualModule>,
    pub skipped: Option<String>,
    /// Finding id → the two finder families of its dual module (the
    /// refuter must come from neither).
    pub families_by_id: HashMap<String, Vec<String>>,
    /// Live candidates per family, counted before the merge.
    candidates: HashMap<String, usize>,
    /// Ids the added (second) finder reported that the primary did not.
    from_second: HashSet<String>,
    merged_same_patch: usize,
    merged_location_cwe: usize,
    merged_identical_claim: usize,
    usable_fixes: usize,
    marginal_calls: usize,
    marginal_prompt_bytes: usize,
}

impl DualRun {
    pub fn new(top: usize) -> Self {
        DualRun {
            top,
            ..DualRun::default()
        }
    }

    fn count(&mut self, basis: DedupeBasis) {
        match basis {
            DedupeBasis::SamePatch => self.merged_same_patch += 1,
            DedupeBasis::LocationCwe => self.merged_location_cwe += 1,
            DedupeBasis::IdenticalClaim => self.merged_identical_claim += 1,
        }
    }

    /// Merge the two families' candidates on every dual module, in place,
    /// and count what the added finders cost. `reports` are the module
    /// reports with `model` set.
    pub fn merge(
        &mut self,
        repo_root: &Path,
        findings: &mut Vec<Finding>,
        reports: &mut [ModuleAuditReport],
    ) {
        let cache: RefCell<HashMap<String, Option<String>>> = RefCell::new(HashMap::new());
        let file_text = |p: &str| -> Option<String> {
            cache
                .borrow_mut()
                .entry(p.to_string())
                .or_insert_with(|| crate::util::read_repo_file(repo_root, p).ok())
                .clone()
        };
        // Merged-away id → the surviving id, and the merged-away rows.
        let mut drop_ids: HashMap<String, String> = HashMap::new();
        let mut drop_rows: HashSet<usize> = HashSet::new();
        let modules = self.modules.clone();
        for m in &modules {
            let ids_of = |side: &FinderSide| -> Vec<String> {
                reports
                    .iter()
                    .filter(|r| r.module_path == m.module_path && r.model == side.model)
                    .flat_map(|r| r.candidate_ids.iter().cloned())
                    .collect()
            };
            let (a_ids, b_ids) = (ids_of(&m.primary), ids_of(&m.second));
            let families = vec![m.primary.family.clone(), m.second.family.clone()];
            let live = |id: &str, fs: &[Finding]| {
                fs.iter()
                    .position(|f| f.id == id && f.status == FindingStatus::Candidate)
            };
            // Candidates count per family (an identical claim from both
            // families counts once for each); usable fixes count per row.
            let mut fix_rows: HashSet<usize> = HashSet::new();
            for (ids, side) in [(&a_ids, &m.primary), (&b_ids, &m.second)] {
                for id in ids {
                    self.families_by_id.insert(id.clone(), families.clone());
                    if let Some(i) = live(id, findings) {
                        *self.candidates.entry(side.family.clone()).or_default() += 1;
                        if fix_rows.insert(i) && usable_fix(&findings[i], &file_text).is_some() {
                            self.usable_fixes += 1;
                        }
                    }
                }
            }
            for id in &b_ids {
                if !a_ids.contains(id) {
                    self.from_second.insert(id.clone());
                }
            }
            for b_id in &b_ids {
                if drop_ids.contains_key(b_id) {
                    continue;
                }
                let Some(bi) = live(b_id, findings) else {
                    continue;
                };
                // The same id from both finders first: it is already one row
                // here (`dedup_by_id` drops the copy later) and must not be
                // merged into some other primary candidate.
                let identical = a_ids
                    .iter()
                    .any(|a_id| live(a_id, findings) == Some(bi))
                    .then_some((bi, DedupeBasis::IdenticalClaim));
                let hit = identical.or_else(|| {
                    a_ids.iter().find_map(|a_id| {
                        let ai = live(a_id, findings)?;
                        if drop_rows.contains(&ai) {
                            return None;
                        }
                        same_root(&findings[ai], &findings[bi], &file_text).map(|basis| (ai, basis))
                    })
                });
                let Some((ai, basis)) = hit else {
                    continue;
                };
                self.count(basis);
                if ai == bi {
                    let f = &mut findings[ai];
                    if !f.found_by.contains(&m.second.model) {
                        f.found_by.push(m.second.model.clone());
                    }
                    push_merge(f, b_id, &m.second, basis);
                    continue;
                }
                let b = findings[bi].clone();
                let a = &mut findings[ai];
                for model in &b.found_by {
                    if !a.found_by.contains(model) {
                        a.found_by.push(model.clone());
                    }
                }
                // Review depth follows the higher self-reported severity.
                a.severity = a.severity.max(b.severity);
                a.evidence.extend(
                    b.evidence
                        .iter()
                        .filter(|e| e.kind == EvidenceKind::AiAnalysis)
                        .cloned(),
                );
                push_merge(a, &b.id, &m.second, basis);
                let survivor = a.id.clone();
                drop_ids.insert(b.id.clone(), survivor);
                drop_rows.insert(bi);
            }
            for r in reports
                .iter()
                .filter(|r| r.module_path == m.module_path && r.model == m.second.model)
            {
                if matches!(
                    r.outcome,
                    ModuleOutcome::Deferred { .. } | ModuleOutcome::Unreadable { .. }
                ) {
                    continue;
                }
                self.marginal_calls += 1;
                self.marginal_prompt_bytes +=
                    r.files.iter().map(|f| f.submitted_bytes).sum::<usize>();
            }
        }
        if drop_ids.is_empty() {
            return;
        }
        // Remove exactly the merged-away rows, never another row that
        // happens to share an id.
        let mut row = 0usize;
        findings.retain(|_| {
            let keep = !drop_rows.contains(&row);
            row += 1;
            keep
        });
        // Coverage must only cite findings that exist: a merged-away id now
        // points at the row it was merged into.
        for r in reports.iter_mut() {
            let mut ids: Vec<String> = Vec::with_capacity(r.candidate_ids.len());
            for id in &r.candidate_ids {
                let id = drop_ids.get(id).unwrap_or(id);
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
            r.candidate_ids = ids;
        }
    }

    /// The report record, from the findings after review. `family_of` maps
    /// a finder model id to its family.
    pub fn report(
        &self,
        findings: &[Finding],
        family_of: impl Fn(&str) -> Option<String>,
    ) -> DualFinderReport {
        let mut yields: Vec<FamilyYield> = Vec::new();
        for m in &self.modules {
            for fam in [&m.primary.family, &m.second.family] {
                if !yields.iter().any(|y| &y.family == fam) {
                    yields.push(FamilyYield {
                        family: fam.clone(),
                        candidates: self.candidates.get(fam).copied().unwrap_or(0),
                        ..FamilyYield::default()
                    });
                }
            }
        }
        let mut shared = 0usize;
        let mut marginal = MarginalYield {
            calls: self.marginal_calls,
            prompt_bytes: self.marginal_prompt_bytes,
            ..MarginalYield::default()
        };
        let mut seen: HashSet<&str> = HashSet::new();
        for f in findings {
            if !self.families_by_id.contains_key(&f.id)
                || !seen.insert(f.id.as_str())
                || matches!(f.status, FindingStatus::Refuted | FindingStatus::Suppressed)
            {
                continue;
            }
            let mut fams: Vec<String> = f.found_by.iter().filter_map(|m| family_of(m)).collect();
            fams.sort();
            fams.dedup();
            if fams.len() > 1 {
                shared += 1;
                continue;
            }
            let needs_human = matches!(
                f.status,
                FindingStatus::NeedsHuman | FindingStatus::Confirmed
            );
            if let Some(y) = fams
                .first()
                .and_then(|fam| yields.iter_mut().find(|y| &y.family == fam))
            {
                y.unique_root_causes += 1;
                y.unique_needs_human += usize::from(needs_human);
            }
            if self.from_second.contains(&f.id) {
                marginal.extra_root_causes += 1;
                marginal.extra_needs_human += usize::from(needs_human);
            }
        }
        if marginal.extra_needs_human > 0 {
            let n = marginal.extra_needs_human;
            marginal.calls_per_extra_needs_human = Some(marginal.calls.div_ceil(n));
            marginal.prompt_kib_per_extra_needs_human =
                Some(marginal.prompt_bytes.div_ceil(1024).div_ceil(n));
        }
        DualFinderReport {
            top: self.top,
            modules: self.modules.clone(),
            skipped: self.skipped.clone(),
            families: yields,
            shared_root_causes: shared,
            merged_same_patch: self.merged_same_patch,
            merged_location_cwe: self.merged_location_cwe,
            merged_identical_claim: self.merged_identical_claim,
            usable_fixes: self.usable_fixes,
            marginal,
        }
    }
}

/// Validate a model-supplied fix: safe path the finder was shown, a range
/// inside the file, at most [`MAX_FIX_LINES`] lines and [`MAX_FIX_BYTES`].
pub fn clean_fix(
    raw: Option<&serde_json::Value>,
    prompt_paths: &HashSet<String>,
    line_count: impl Fn(&str) -> Option<usize>,
) -> Option<ProposedFix> {
    let fix: ProposedFix = serde_json::from_value(raw?.clone()).ok()?;
    let safe = vettalon_contract::safe_path::SafeRepoPath::parse(&fix.file).ok()?;
    if !prompt_paths.contains(safe.as_str()) {
        return None;
    }
    let count = line_count(safe.as_str())?;
    let ok_range = fix.start_line >= 1
        && fix.start_line <= fix.end_line
        && fix.end_line as usize <= count
        && fix.end_line - fix.start_line < MAX_FIX_LINES;
    (ok_range && fix.replacement.len() <= MAX_FIX_BYTES).then(|| ProposedFix {
        file: safe.as_str().to_string(),
        ..fix
    })
}

/// The sink a candidate claims: its last `sink` trace step, else its own
/// file and line.
fn sink_of(f: &Finding) -> Option<(&str, u32)> {
    f.trace
        .iter()
        .rev()
        .find(|s| s.kind == TraceKind::Sink)
        .map(|s| (s.file.as_str(), s.line))
        .or_else(|| f.line.map(|l| (f.file.as_str(), l)))
}

/// Whether applying `fix` to an in-memory copy of its file changes the
/// sink line of `f`: the sink line is inside the replaced range and its
/// text (trimmed) does not survive in the replacement.
fn fix_changes_sink(
    fix: &ProposedFix,
    f: &Finding,
    file_text: &dyn Fn(&str) -> Option<String>,
) -> bool {
    let Some((file, line)) = sink_of(f) else {
        return false;
    };
    if file != fix.file || line < fix.start_line || line > fix.end_line {
        return false;
    }
    let Some(text) = file_text(file) else {
        return false;
    };
    let Some(original) = text.lines().nth(line as usize - 1).map(str::trim) else {
        return false;
    };
    if original.is_empty() {
        return false;
    }
    !fix.replacement.lines().any(|l| l.trim() == original)
}

/// A fix that changes its own candidate's sink line, else `None`.
fn usable_fix<'a>(
    f: &'a Finding,
    file_text: &dyn Fn(&str) -> Option<String>,
) -> Option<&'a ProposedFix> {
    f.proposed_fix
        .as_ref()
        .filter(|p| fix_changes_sink(p, f, file_text))
}

/// Whether `a` and `b` share a root cause, and on what basis.
pub fn same_root(
    a: &Finding,
    b: &Finding,
    file_text: &dyn Fn(&str) -> Option<String>,
) -> Option<DedupeBasis> {
    if a.id == b.id {
        return Some(DedupeBasis::IdenticalClaim);
    }
    let fixes: Vec<&ProposedFix> = [usable_fix(a, file_text), usable_fix(b, file_text)]
        .into_iter()
        .flatten()
        .collect();
    if !fixes.is_empty() {
        // Two classified candidates of different weakness classes are two
        // root causes even when one wide fix touches both sinks.
        if let (Some(x), Some(y)) = (&a.cwe, &b.cwe)
            && x != y
        {
            return None;
        }
        let both = fixes
            .iter()
            .any(|p| fix_changes_sink(p, a, file_text) && fix_changes_sink(p, b, file_text));
        return both.then_some(DedupeBasis::SamePatch);
    }
    let (fa, la) = sink_of(a)?;
    let (fb, lb) = sink_of(b)?;
    let same_cwe = matches!((&a.cwe, &b.cwe), (Some(x), Some(y)) if x == y);
    (fa == fb && la.abs_diff(lb) <= LOCATION_WINDOW && same_cwe).then_some(DedupeBasis::LocationCwe)
}

fn push_merge(f: &mut Finding, merged_id: &str, side: &FinderSide, basis: DedupeBasis) {
    f.evidence.push(EvidenceItem {
        kind: EvidenceKind::DualFinderMerge,
        source: "dual_finder".to_string(),
        detail: format!(
            "{DUAL_FINDER_MERGE_PREFIX} merged {merged_id} from {} ({}) dedupe_basis={}",
            side.model,
            side.family,
            basis.key()
        ),
        recorded_at: chrono::Utc::now().to_rfc3339(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::schema::{FindingKind, Severity, TraceStep};

    const MAIN: &str = "fn main() {\n    let q = read();\n    db.execute(q);\n    let p = read();\n    shell.run(p);\n}\n";

    fn text(p: &str) -> Option<String> {
        (p == "a/main.rs").then(|| MAIN.to_string())
    }

    fn cand(rule: &str, sink: u32, cwe: Option<&str>) -> Finding {
        let mut f = Finding::candidate(
            "ai_audit",
            FindingKind::Other,
            Severity::High,
            "t",
            "a/main.rs",
            Some(sink),
            "s",
            format!("ai-audit/{rule}"),
            vec![],
        );
        f.trace = vec![
            TraceStep {
                kind: TraceKind::Entrypoint,
                file: "a/main.rs".into(),
                line: 1,
                scope: "main".into(),
                description: String::new(),
            },
            TraceStep {
                kind: TraceKind::Sink,
                file: "a/main.rs".into(),
                line: sink,
                scope: "main".into(),
                description: String::new(),
            },
        ];
        f.cwe = cwe.map(str::to_string);
        f
    }

    fn fix(start: u32, end: u32, replacement: &str) -> Option<ProposedFix> {
        Some(ProposedFix {
            file: "a/main.rs".into(),
            start_line: start,
            end_line: end,
            replacement: replacement.into(),
        })
    }

    #[test]
    fn one_patch_that_changes_both_sinks_merges() {
        let mut a = cand("sql-injection", 3, None);
        a.proposed_fix = fix(
            2,
            3,
            "    let q = read_checked();\n    db.execute_prepared(&[q]);",
        );
        let b = cand("sqli", 3, Some("CWE-89"));
        assert_eq!(same_root(&a, &b, &text), Some(DedupeBasis::SamePatch));
    }

    #[test]
    fn a_patch_that_misses_the_other_sink_keeps_two_root_causes() {
        let mut a = cand("sql-injection", 3, Some("CWE-78"));
        a.proposed_fix = fix(3, 3, "    db.execute_prepared(&[q]);");
        // Same CWE and only two lines apart, but a's own fix leaves line 5
        // as it is: the patch evidence wins over the location fallback.
        let b = cand("command-injection", 5, Some("CWE-78"));
        assert_eq!(same_root(&a, &b, &text), None);
    }

    #[test]
    fn a_guard_added_above_an_unchanged_sink_is_not_a_usable_patch() {
        let mut a = cand("sql-injection", 3, Some("CWE-89"));
        a.proposed_fix = fix(3, 3, "    if !valid(&q) { return; }\n    db.execute(q);");
        let b = cand("sqli", 4, Some("CWE-89"));
        // Not usable ⇒ location + CWE fallback (same file, 1 line apart).
        assert_eq!(same_root(&a, &b, &text), Some(DedupeBasis::LocationCwe));
    }

    #[test]
    fn location_fallback_needs_the_same_cwe_on_both() {
        let a = cand("sql-injection", 3, Some("CWE-89"));
        assert_eq!(same_root(&a, &cand("x", 3, None), &text), None);
        assert_eq!(same_root(&a, &cand("x", 3, Some("CWE-78")), &text), None);
        assert_eq!(
            same_root(
                &a,
                &cand("x", 3 + LOCATION_WINDOW + 1, Some("CWE-89")),
                &text
            ),
            None
        );
        let mut other_file = cand("x", 3, Some("CWE-89"));
        other_file.trace[1].file = "b/lib.rs".into();
        assert_eq!(same_root(&a, &other_file, &text), None);
        let same = cand("sql-injection", 3, Some("CWE-89"));
        assert_eq!(same.id, a.id);
        assert_eq!(
            same_root(&a, &same, &text),
            Some(DedupeBasis::IdenticalClaim)
        );
    }

    #[test]
    fn a_wide_patch_never_merges_two_weakness_classes() {
        let mut a = cand("sql-injection", 3, Some("CWE-89"));
        a.proposed_fix = fix(2, 5, "    run_safely();");
        let b = cand("command-injection", 5, Some("CWE-78"));
        assert_eq!(same_root(&a, &b, &text), None);
    }

    fn report(model: &str, ids: &[&str]) -> ModuleAuditReport {
        ModuleAuditReport {
            module_path: "a".into(),
            outcome: ModuleOutcome::Reviewed { note: None },
            reviewed_paths: vec!["a/main.rs".into()],
            truncated_paths: Vec::new(),
            candidate_ids: ids.iter().map(|s| s.to_string()).collect(),
            model: model.into(),
            family: String::new(),
            files: Vec::new(),
            duration_ms: 0,
            timed_out: false,
            source_receipt: None,
        }
    }

    #[test]
    fn an_identical_claim_wins_over_a_patch_match_and_no_other_row_is_removed() {
        let mut a1 = cand("sql-injection", 3, Some("CWE-89"));
        a1.found_by = vec!["claude".into()];
        // A2 comes first and its fix would also cover the shared sink.
        let mut a2 = cand("sqli", 3, Some("CWE-89"));
        a2.found_by = vec!["claude".into()];
        a2.proposed_fix = fix(3, 3, "    db.execute_prepared(&[q]);");
        let mut b = a1.clone();
        b.found_by = vec!["codex".into()];
        let ids = [a2.id.clone(), a1.id.clone()];
        let mut findings = vec![a1.clone(), a2.clone(), b];
        let mut reports = vec![
            report("claude", &[ids[0].as_str(), ids[1].as_str()]),
            report("codex", &[a1.id.as_str()]),
        ];
        let mut run = DualRun::new(1);
        run.modules.push(DualModule {
            module_path: "a".into(),
            primary: FinderSide {
                model: "claude".into(),
                family: "anthropic".into(),
            },
            second: FinderSide {
                model: "codex".into(),
                family: "openai".into(),
            },
        });
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::write(dir.path().join("a/main.rs"), MAIN).unwrap();
        run.merge(dir.path(), &mut findings, &mut reports);
        assert_eq!(findings.len(), 3, "rows are only removed by dedup_by_id");
        assert_eq!(findings[0].found_by, vec!["claude", "codex"]);
        assert_eq!(findings[1].found_by, vec!["claude"]);
        assert_eq!(run.merged_identical_claim, 1);
        assert_eq!(run.merged_same_patch, 0);
        assert_eq!(run.usable_fixes, 1);
    }

    #[test]
    fn clean_fix_rejects_unsafe_unknown_or_oversized_fixes() {
        let shown: HashSet<String> = ["a/main.rs".to_string()].into();
        let lines = |p: &str| (p == "a/main.rs").then_some(6usize);
        let ok =
            serde_json::json!({"file":"a/main.rs","start_line":3,"end_line":3,"replacement":"x"});
        assert!(clean_fix(Some(&ok), &shown, lines).is_some());
        for bad in [
            serde_json::json!({"file":"/etc/passwd","start_line":1,"end_line":1,"replacement":"x"}),
            serde_json::json!({"file":"b/other.rs","start_line":1,"end_line":1,"replacement":"x"}),
            serde_json::json!({"file":"a/main.rs","start_line":4,"end_line":3,"replacement":"x"}),
            serde_json::json!({"file":"a/main.rs","start_line":0,"end_line":1,"replacement":"x"}),
            serde_json::json!({"file":"a/main.rs","start_line":1,"end_line":7,"replacement":"x"}),
            serde_json::json!({"file":"a/main.rs","start_line":1,"end_line":1,"replacement":"x".repeat(MAX_FIX_BYTES + 1)}),
            serde_json::json!({"file":"a/main.rs","start_line":1,"end_line":1}),
            serde_json::json!({"file":"a/main.rs","start_line":1,"end_line":1,"replacement":"x","extra":1}),
            serde_json::json!("rewrite everything"),
        ] {
            assert!(clean_fix(Some(&bad), &shown, lines).is_none(), "{bad}");
        }
        let many: HashSet<String> = ["big.rs".to_string()].into();
        let big = serde_json::json!({"file":"big.rs","start_line":1,"end_line":MAX_FIX_LINES + 1,"replacement":"x"});
        assert!(clean_fix(Some(&big), &many, |_| Some(1000)).is_none());
        assert!(clean_fix(None, &shown, lines).is_none());
    }
}
