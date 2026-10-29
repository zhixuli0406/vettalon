use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;
use serde::de::{DeserializeOwned, Error, value::StrDeserializer};
use vettalon::audit::evidence_level::{EvidenceLevel, ProofGap};
use vettalon::audit::schema::{EvidenceKind, ModuleCoverageStatus};
use vettalon::explain::{PAGES, lookup};
use vettalon_contract::coverage::{IncompleteReason, RunStatus};

// Serde's generated enum visitor supplies its complete variant list to
// unknown_variant. This cannot silently drift like a manually maintained ALL.
#[derive(Debug)]
struct VariantNames(Vec<&'static str>);

impl std::fmt::Display for VariantNames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("collect serialized enum variants")
    }
}

impl std::error::Error for VariantNames {}

impl Error for VariantNames {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        Self(Vec::new())
    }

    fn unknown_variant(_: &str, expected: &'static [&'static str]) -> Self {
        Self(expected.to_vec())
    }
}

fn assert_enum_pages<T: DeserializeOwned + Serialize>() {
    let variants = T::deserialize(StrDeserializer::<VariantNames>::new(
        "__collect_explanation_variants__",
    ))
    .err()
    .unwrap()
    .0;
    assert!(!variants.is_empty(), "enum did not expose its variants");
    for variant in variants {
        // Aliases (e.g. legacy `partial`) resolve to their canonical page.
        let value: T = serde_json::from_value(serde_json::json!(variant)).unwrap();
        let canonical = serde_json::to_value(value).unwrap();
        let code = canonical.as_str().unwrap();
        assert!(lookup(code).is_some(), "missing embedded page: {code}");
    }
}

#[test]
fn every_serialized_enum_variant_has_an_embedded_page() {
    assert_enum_pages::<EvidenceLevel>();
    assert_enum_pages::<ProofGap>();
    assert_enum_pages::<ModuleCoverageStatus>();
    assert_enum_pages::<IncompleteReason>();
    assert_enum_pages::<RunStatus>();
    assert_enum_pages::<EvidenceKind>();
}

fn assert_prefix_pages(dir: &Path, prefix: &regex::Regex) -> usize {
    let mut count = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            count += assert_prefix_pages(&path, prefix);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source = std::fs::read_to_string(path).unwrap();
            for capture in prefix.captures_iter(&source) {
                let code = capture[1].trim_end_matches(':');
                assert!(lookup(code).is_some(), "missing prefix page: {code}");
                count += 1;
            }
        }
    }
    count
}

#[test]
fn every_public_evidence_prefix_and_fixed_reason_has_an_embedded_page() {
    let prefix =
        regex::Regex::new(r#"pub const (?:\w*PREFIX|DEFER_\w+): &str\s*=\s*"([^"]+)""#).unwrap();
    let count = assert_prefix_pages(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/audit"),
        &prefix,
    );
    assert!(count >= 28, "prefix scan stopped seeing the source");
    for code in [
        "shallow_no_checks",
        "shallow_missing_class_checks",
        "diff_scope",
        "max_modules",
        "prescreen_cut",
        "candidate_cap",
        "time_budget",
        "engine_unavailable",
        "refuter_impact_missing",
        "prior_gap",
        "prior_not_rediscovered",
        "quick_profile_not_rechecked",
        "outside_diff_scope",
        "poc_generation_failed",
        "poc_not_demonstrable",
        "fix_check_skipped",
        "refuted",
        "unresolved",
        "refuter_run",
        "operator_decision",
        "reasoning",
    ] {
        assert!(lookup(code).is_some(), "missing reason page: {code}");
    }
}

#[test]
fn page_files_and_embedded_table_are_identical_and_well_formed() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/explain");
    let mut files = BTreeSet::new();
    let links = regex::Regex::new(r"\]\(([^)]+)\.md\)").unwrap();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "md") || path.file_stem().unwrap() == "README" {
            continue;
        }
        let code = path.file_stem().unwrap().to_str().unwrap();
        let page = lookup(code).unwrap_or_else(|| panic!("page not embedded: {code}"));
        assert_eq!(page.text, std::fs::read_to_string(&path).unwrap());
        assert!(page.text.starts_with(&format!("# {code}: ")));
        assert!(!page.summary().is_empty());
        for section in ["What it means", "Why you see it", "What to do", "Related"] {
            assert!(
                page.text.contains(&format!("\n## {section}\n")),
                "{code}: {section}"
            );
        }
        for capture in links.captures_iter(page.text) {
            assert!(
                lookup(&capture[1]).is_some(),
                "{code}: broken related link {capture:?}"
            );
        }
        files.insert(code.to_string());
    }
    let embedded: BTreeSet<_> = PAGES.iter().map(|page| page.code.to_string()).collect();
    assert_eq!(embedded.len(), PAGES.len(), "duplicate table entries");
    assert_eq!(files, embedded);
}
