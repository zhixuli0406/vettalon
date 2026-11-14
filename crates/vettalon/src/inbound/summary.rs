//! Human summary of one intake run (stdout, at most 12 lines).
//!
//! Every line goes through `terminal_safe`, so a path or CWE string taken from
//! a report cannot drive the terminal (ESC / CSI / OSC / C1 / bidi controls
//! are shown escaped). Nothing here quotes the report text.

use super::run::IntakeOutput;
use crate::audit::retest::terminal_safe;
use crate::disclose::dedupe::DedupeCheck;

pub const MAX_SUMMARY_LINES: usize = 12;

/// The fixed closing line.
pub const FIXED_LINE: &str =
    "Pasted report text was not sent. Refuted is not proof the report is wrong.";

pub fn render_summary(out: &IntakeOutput) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();

    // 1. Location.
    lines.push(location_line(out));
    if out.extraction.report_ref_differs {
        lines.push(
            "report ref: the report links a revision other than HEAD; the working tree was checked"
                .to_string(),
        );
    }

    // 2. CWE.
    lines.push(cwe_line(out));

    // 3. Refuter.
    lines.push(format!("refuter: {}", out.triage.refuter));

    // 4. Reproduction.
    let r = &out.reproduction;
    let mut repro = format!("reproduction: {} (replays {})", r.status, r.replays);
    if let Some(reason) = &r.reason {
        repro.push_str(&format!(", {reason}"));
    }
    lines.push(repro);

    // 5. Scope hint.
    lines.push(if out.scope_check.is_none() {
        "scope: not checked".to_string()
    } else if out.triage.possibly_out_of_scope {
        "scope: possibly out of scope (a hint; a human decides)".to_string()
    } else {
        "scope: no out-of-scope hint (not a guarantee)".to_string()
    });

    // 6. Duplicates.
    lines.push(duplicates_line(out));

    // 7. Incomplete.
    if out.incomplete {
        lines.push("run incomplete: not every step finished".to_string());
    }

    // 8. Next step.
    lines.push(next_step(out));

    // Data sharing depends on the calls that actually ran.
    let sharing = out
        .limits
        .iter()
        .skip(super::run::LIMITS.len())
        .cloned()
        .collect::<Vec<_>>();
    if !sharing.is_empty() {
        lines.push(sharing.join("; "));
    }

    // 9. Fixed line.
    lines.push(FIXED_LINE.to_string());

    // Keep the fixed line last if the cap ever bites.
    while lines.len() > MAX_SUMMARY_LINES {
        lines.remove(lines.len() - 2);
    }
    lines.iter().map(|l| terminal_safe(l)).collect()
}

fn location_line(out: &IntakeOutput) -> String {
    if out.triage.located {
        if let Some(rec) = out
            .extraction
            .primary
            .and_then(|i| out.extraction.locations.get(i))
        {
            let file = rec.file.as_deref().unwrap_or("?");
            return match rec.line {
                Some(n) => format!("location: {file}:{n}"),
                None => format!("location: {file}"),
            };
        }
        return "location: verified".to_string();
    }
    let rejected = out
        .extraction
        .locations
        .iter()
        .filter(|l| !l.accepted)
        .count();
    if rejected > 0 && out.extraction.tracked_check == "git_unavailable" {
        format!(
            "location: no verified location ({rejected} candidate(s) rejected; no readable Git index, so report locations count as untracked)"
        )
    } else if rejected > 0 {
        format!("location: no verified location ({rejected} candidate(s) rejected)")
    } else {
        "location: no verified location".to_string()
    }
}

fn cwe_line(out: &IntakeOutput) -> String {
    match &out.extraction.cwe {
        Some(c) => {
            let mut s = format!("CWE: {c} ({})", out.extraction.cwe_source);
            if out.triage.trust_policy_capped {
                s.push_str(", trust-policy capped");
            }
            s
        }
        None => "CWE: none found".to_string(),
    }
}

fn duplicates_line(out: &IntakeOutput) -> String {
    let d = &out.duplicates;
    let checks = [&d.osv, &d.upstream_commits, &d.open_issues_prs];
    let mut matches = 0usize;
    let mut checked = 0usize;
    let mut failed = 0usize;
    for c in checks {
        match c {
            DedupeCheck::Checked { matches: m, .. } => {
                checked += 1;
                matches += m.len();
            }
            DedupeCheck::Failed { .. } => failed += 1,
            DedupeCheck::NotChecked { .. } => {}
        }
    }
    if checked == 0 && failed == 0 {
        "duplicates: not checked (use --check-duplicates)".to_string()
    } else if matches > 0 {
        format!(
            "duplicates: {matches} possible result(s), see the output file (a hint, not a match)"
        )
    } else if failed > 0 {
        format!("duplicates: none found; {failed} lookup(s) failed (not a novelty check)")
    } else {
        "duplicates: none found (not proof of novelty)".to_string()
    }
}

fn next_step(out: &IntakeOutput) -> String {
    if !out.triage.located {
        return "next: no verified location: rerun with --location FILE:LINE".to_string();
    }
    if out.verify.is_none() {
        return "next: claims only; rerun with --verifier to run the refuter".to_string();
    }
    if out.incomplete {
        return "next: incomplete: rerun, or review the claim by hand".to_string();
    }
    match out.triage.refuter {
        "refuted" => "next: refuted: a human should still read the report".to_string(),
        "needs_human" => "next: needs_human: review the claim".to_string(),
        _ => "next: no refuter verdict: review the claim".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclose::dedupe::DedupeReport;
    use crate::inbound::extract::{Extraction, LocationRecord};
    use crate::inbound::run::{InputInfo, RepoInfo, Reproduction, Triage};

    fn base(file: &str, located: bool) -> IntakeOutput {
        let rec = LocationRecord {
            file: Some(file.to_string()),
            line: Some(7),
            origin: "operator",
            accepted: located,
            reason: None,
            token: None,
            token_sha256: None,
        };
        IntakeOutput {
            schema: "vettalon.intake/1",
            vettalon_version: "0",
            created_at: String::new(),
            input: InputInfo {
                sha256: String::new(),
                bytes: 0,
                format: "plain",
                sections: vec![],
            },
            repo: RepoInfo {
                commit: None,
                github: None,
            },
            report_summary: None,
            extraction: Extraction {
                format: "plain",
                sections: vec![],
                cwe: Some("CWE-22".to_string()),
                cwe_source: "operator",
                cwe_mentions: vec![],
                locations: vec![rec],
                candidates_truncated: false,
                tracked_check: "not_used",
                report_ref: None,
                report_ref_differs: false,
                title: "t".to_string(),
                title_source: "neutral",
                report_summary: None,
                primary: located.then_some(0),
            },
            claims: None,
            claims_file: None,
            verify: None,
            reproduction: Reproduction {
                status: "not_requested",
                reason: None,
                replays: "0/0".to_string(),
                receipt_file: None,
                receipt_sha256: None,
            },
            scope_check: None,
            duplicates: DedupeReport::not_checked("not requested"),
            triage: Triage {
                located,
                refuter: "not_run",
                trust_policy_capped: false,
                reproduction: "not_requested",
                possibly_out_of_scope: false,
                possible_duplicates: false,
            },
            files_sent_to_model: vec![],
            limits: vec![],
            incomplete: false,
        }
    }

    fn assert_clean(lines: &[String]) {
        assert!(lines.len() <= MAX_SUMMARY_LINES);
        for l in lines {
            for c in l.chars() {
                assert!(
                    !c.is_control() && c != '\u{202e}',
                    "unescaped {:?} in {l:?}",
                    c
                );
            }
        }
    }

    #[test]
    fn hostile_file_path_is_escaped() {
        for evil in [
            "a\u{1b}[2Jb.py",
            "a\u{1b}]8;;http://x\u{7}link\u{1b}]8;;\u{7}.py",
            "a\u{202e}gnp.py",
            "a\u{85}b.py",
        ] {
            let out = base(evil, true);
            let lines = render_summary(&out);
            assert_clean(&lines);
            assert!(lines[0].starts_with("location: a"), "{:?}", lines[0]);
        }
    }

    #[test]
    fn hostile_cwe_is_escaped() {
        let mut out = base("a.py", true);
        out.extraction.cwe = Some("CWE-1\u{1b}[2J".to_string());
        assert_clean(&render_summary(&out));
    }

    #[test]
    fn no_location_points_at_the_location_flag() {
        let out = base("x.py", false);
        let lines = render_summary(&out);
        assert!(lines[0].contains("no verified location"));
        assert!(lines.iter().any(|l| l.contains("--location FILE:LINE")));
        assert_eq!(lines.last().unwrap(), FIXED_LINE);
        assert!(lines.len() <= MAX_SUMMARY_LINES);
    }

    #[test]
    fn verdict_next_steps_and_cap() {
        let mut out = base("a.py", true);
        out.triage.refuter = "refuted";
        out.triage.trust_policy_capped = true;
        out.incomplete = true;
        out.extraction.report_ref_differs = true;
        let lines = render_summary(&out);
        assert!(lines.iter().any(|l| l.contains("trust-policy capped")));
        assert!(lines.len() <= MAX_SUMMARY_LINES);
        assert_eq!(lines.last().unwrap(), FIXED_LINE);
    }
}
