//! Offline reference pages for Vettalon's report codes.

/// One page embedded at compile time. Page text and summaries stay English.
pub struct Page {
    pub code: &'static str,
    pub text: &'static str,
}

impl Page {
    pub fn summary(&self) -> &'static str {
        self.text
            .lines()
            .next()
            .and_then(|title| title.split_once(": "))
            .map_or("", |(_, summary)| summary)
    }
}

macro_rules! page {
    ($code:literal) => {
        Page {
            code: $code,
            text: include_str!(concat!("../../../docs/explain/", $code, ".md")),
        }
    };
}

/// Keep this table sorted. The catalog tests check both directions against
/// the page directory, serialized enum variants and evidence prefixes.
pub const PAGES: &[Page] = &[
    page!("adversarial_review"),
    page!("ai_analysis"),
    page!("budget_cannot_fund_reserves"),
    page!("candidate"),
    page!("candidate_cap"),
    page!("carried_from_prior"),
    page!("comment_sensitivity"),
    page!("complete"),
    page!("covered"),
    page!("critic_budget_exhausted"),
    page!("deferred"),
    page!("diff_scope"),
    page!("dual_finder_merge"),
    page!("engine_unavailable"),
    page!("fix_check"),
    page!("fix_check_skipped"),
    page!("fix_context_v1"),
    page!("hash_budget_exhausted"),
    page!("incomplete"),
    page!("injection_uncrosschecked"),
    page!("interrupted"),
    page!("llm_failed"),
    page!("maintainer_confirmed"),
    page!("max_modules"),
    page!("model_refused"),
    page!("no_control"),
    page!("no_fresh_rerun"),
    page!("no_maintainer_confirmation"),
    page!("no_poc"),
    page!("no_refuter"),
    page!("operator_decision"),
    page!("operator_review"),
    page!("out_of_scope"),
    page!("outside_diff_scope"),
    page!("parse_failed"),
    page!("partial_by_design"),
    page!("partially_reviewed"),
    page!("plausible"),
    page!("poc_differential"),
    page!("poc_effect_no_control"),
    page!("poc_generation_failed"),
    page!("poc_not_demonstrable"),
    page!("poc_not_harness_judged"),
    page!("poc_oracle"),
    page!("poc_skipped"),
    page!("poc_transcript"),
    page!("precheck"),
    page!("prescreen_cut"),
    page!("prior_changed_source"),
    page!("prior_confirmed_same_source"),
    page!("prior_gap"),
    page!("prior_not_rediscovered"),
    page!("prompt_byte_budget"),
    page!("prompt_byte_budget_utf8_boundary"),
    page!("prosecutor"),
    page!("quick_profile_not_rechecked"),
    page!("reachability_unknown"),
    page!("read_failed_or_outside_repository"),
    page!("reasoning"),
    page!("refute_basis"),
    page!("refuted"),
    page!("refuter_consistent"),
    page!("refuter_impact_missing"),
    page!("refuter_inconsistent"),
    page!("refuter_run"),
    page!("refuter_score"),
    page!("refuter_survived"),
    page!("retrieval"),
    page!("reviewed_no_checks"),
    page!("scope_not_fully_reviewed"),
    page!("scope_note"),
    page!("severity_cap_proposed"),
    page!("severity_cap_unconfirmed"),
    page!("severity_capped"),
    page!("severity_disagreement"),
    page!("shallow_missing_class_checks"),
    page!("shallow_no_checks"),
    page!("static_hit"),
    page!("static_only"),
    page!("tier_disagreement"),
    page!("time_budget"),
    page!("time_budget_exhausted"),
    page!("units_failed"),
    page!("unreadable"),
    page!("unresolved"),
    page!("validation_budget_exhausted"),
    page!("verifier_corrected"),
    page!("verifier_reflector"),
    page!("verify_error"),
    page!("verify_uncertain"),
];

pub fn lookup(code: &str) -> Option<&'static Page> {
    PAGES.iter().find(|page| page.code == code)
}

/// Only known codes become URLs; caller-provided text cannot alter the path.
pub fn uri(code: &str) -> Option<String> {
    lookup(code).map(|page| {
        format!(
            "https://github.com/zhixuli0406/vettalon/blob/main/docs/explain/{}.md",
            page.code
        )
    })
}

fn edit_distance(left: &[char], right: &str) -> usize {
    let mut row: Vec<usize> = (0..=left.len()).collect();
    for (i, b) in right.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, a) in left.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = (diagonal + usize::from(*a != b))
                .min(row[j] + 1)
                .min(above + 1);
            diagonal = above;
        }
    }
    row[left.len()]
}

pub fn closest(code: &str) -> Vec<&'static str> {
    let input: Vec<char> = code.chars().collect();
    let mut matches: Vec<_> = PAGES
        .iter()
        .map(|page| (edit_distance(&input, page.code), page.code))
        .collect();
    matches.sort_unstable();
    matches.into_iter().take(3).map(|(_, code)| code).collect()
}

/// Print an embedded page or index. Clap enforces exactly one input mode.
pub fn run(code: Option<&str>, list: bool) -> i32 {
    if list {
        println!(
            "{}",
            crate::lang::pick(
                "說明代碼（頁面與摘要為英文）：",
                "Explanation codes (pages and summaries are in English):"
            )
        );
        for page in PAGES {
            println!("{}  {}", page.code, page.summary());
        }
        return 0;
    }
    let Some(code) = code else {
        return 2;
    };
    if let Some(page) = lookup(code) {
        print!("{}", page.text);
        return 0;
    }
    eprintln!(
        "{}: {code:?}",
        crate::lang::pick("未知的說明代碼", "Unknown explanation code")
    );
    eprintln!(
        "{}: {}",
        crate::lang::pick("最接近的代碼", "Closest matches"),
        closest(code).join(", ")
    );
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_handles_empty_strings_edits_and_unicode() {
        for (left, right, expected) in [
            ("", "", 0),
            ("", "abc", 3),
            ("abc", "", 3),
            ("no_contrl", "no_control", 1),
            ("abc", "axc", 1),
            ("café", "cafe", 1),
        ] {
            assert_eq!(
                edit_distance(&left.chars().collect::<Vec<_>>(), right),
                expected
            );
        }
    }

    #[test]
    fn suggestions_are_ranked_deterministic_and_limited() {
        assert_eq!(closest("no_contrl")[0], "no_control");
        assert_eq!(closest("no_control")[0], "no_control");
        assert_eq!(closest("").len(), 3);
        assert_eq!(closest(&"字".repeat(512)).len(), 3);
        assert_eq!(closest(""), closest(""));
        assert!(uri("../README").is_none());
        assert_eq!(run(None, false), 2);
    }
}
