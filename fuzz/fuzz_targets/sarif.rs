//! The SARIF 2.1.0 reader behind `vettalon verify --input <log.sarif>`. A
//! SARIF log is untrusted input: it names files, lines, URIs and URI bases.
//!
//! Input: the raw bytes, read exactly as `verify` reads them (size and
//! nesting limits first, then the format), against the fixed repository
//! root [`ROOT`]. The reader never looks paths from the log up on disk (nor
//! the root beyond one `canonicalize`, which fails for this path), so the
//! root need not exist, and `file:` URIs and `originalUriBaseIds` under
//! `file:///vettalon-fuzz-root/` reach the inside-the-root branches (the
//! `root_uris` seed names it).
//!
//! Invariants checked beyond "no panic":
//! - claims plus skip notes never exceed 5 000 results; every id is unique
//!   and has the `sarif-` prefix; the unreviewable and duplicate counts
//!   never exceed the skip notes, and a duplicate names a kept claim;
//! - no two claims share file, line, rule id and CWE;
//! - every claimed file and trace location passes `SafeRepoPath` (relative,
//!   no `..`, nothing absolute), every line is at least 1 and a claim has at
//!   most 10 trace locations;
//! - a title is one line of visible text (no control characters, no
//!   U+2028/U+2029); a source is 1 to 64 characters of `[A-Za-z0-9._-]`;
//! - a CWE is already in the `CWE-<n>` form `cwe::normalize` returns, and
//!   when the claim lists several, `cwe` is one of them;
//! - `claim_to_finding` and the refuter's `<claim>` text builder accept
//!   every claim, and nothing in that text can close the `<claim>` fence.

#![no_main]

use std::collections::HashSet;
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use vettalon::audit::fuzzing::{VerifyInput, claim_text, escape_xml_tag};
use vettalon::audit::sarif_input::{DUPLICATE, MAX_SARIF_RESULTS, SOURCE_NAME_MAX_CHARS};
use vettalon::audit::verify_only::{MAX_CLAIM_LOCATIONS, claim_to_finding};
use vettalon_contract::safe_path::SafeRepoPath;
use vettalon_contract::visible_text::has_visible_content;

/// Fixed repository root; it does not have to exist.
const ROOT: &str = "/vettalon-fuzz-root";

fuzz_target!(|data: &[u8]| {
    let Ok(VerifyInput::Sarif(s)) = VerifyInput::parse_bytes(data, Some(Path::new(ROOT))) else {
        return;
    };
    assert!(s.claims.len() + s.skipped.len() <= MAX_SARIF_RESULTS);
    assert!(s.unreviewable + s.duplicates <= s.skipped.len());
    let mut ids = HashSet::new();
    let claim_ids = s.claims.iter().map(|c| c.id.as_str());
    for id in claim_ids.chain(s.skipped.iter().map(|n| n.result_id.as_str())) {
        assert!(id.starts_with("sarif-"), "{id}");
        assert!(ids.insert(id.to_string()), "duplicate id {id}");
    }
    let kept: HashSet<&str> = s.claims.iter().map(|c| c.id.as_str()).collect();
    for n in &s.skipped {
        assert_eq!(n.reason == DUPLICATE, n.duplicate_of.is_some());
        if let Some(first) = &n.duplicate_of {
            assert!(kept.contains(first.as_str()), "{first}");
        }
    }
    let mut keys = HashSet::new();
    for c in &s.claims {
        assert!(
            keys.insert((&c.file, c.line, &c.rule_id, &c.cwe)),
            "two claims for one review: {}",
            c.id
        );
        assert!(SafeRepoPath::parse(&c.file).is_ok(), "{:?}", c.file);
        assert!(c.line.is_none_or(|l| l >= 1));
        assert!(c.locations.len() <= MAX_CLAIM_LOCATIONS);
        for l in &c.locations {
            assert!(SafeRepoPath::parse(&l.file).is_ok(), "{:?}", l.file);
            assert!(l.line >= 1);
        }
        assert!(has_visible_content(&c.title), "{:?}", c.title);
        assert!(
            !c.title
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}')),
            "{:?}",
            c.title
        );
        assert_eq!(c.title.trim(), c.title);
        let source = c.source.as_deref().expect("SARIF claims name their tool");
        assert!(!source.is_empty());
        assert!(source.chars().count() <= SOURCE_NAME_MAX_CHARS);
        assert!(
            source
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        );
        for cwe in c.cwe.iter().chain(&c.cwes) {
            assert_eq!(
                vettalon::audit::cwe::normalize(cwe).as_deref(),
                Some(cwe.as_str())
            );
        }
        if !c.cwes.is_empty() {
            assert!(c.cwes.len() > 1);
            assert!(c.cwe.as_ref().is_some_and(|w| c.cwes.contains(w)));
        }

        let (finding, _) = claim_to_finding(c);
        assert_eq!(finding.cwe, c.cwe);
        let claim = claim_text(&finding);
        assert_eq!(
            escape_xml_tag(&claim, "claim"),
            claim,
            "an unescaped closing tag in the claim text"
        );
    }
});
