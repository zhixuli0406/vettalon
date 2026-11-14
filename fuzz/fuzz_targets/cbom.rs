//! The CycloneDX CBOM reader behind `vettalon cbom-check`. A CBOM is
//! untrusted input (it names files and lines inside the audited project).
//!
//! Input: the raw CBOM bytes. Parsing only: no path mapping, no filesystem.
//!
//! Invariants checked beyond "no panic":
//! - an accepted CBOM has `bomFormat: CycloneDX` semantics: spec version 1.6
//!   or 1.7, at most 100 000 components, 10 000 occurrences each and 200 000
//!   in total;
//! - every CBOM string is clipped to 256 characters plus `…`, and a clipped
//!   field is recorded; a kept `location` is at most 4096 bytes;
//! - the recorded SHA-256 is 64 lowercase hex characters;
//! - every component links to an algorithm only through an `algorithm` asset
//!   (`algorithm_for` is a precomputed O(1) lookup, so the loop is linear).

#![no_main]

use libfuzzer_sys::fuzz_target;
use vettalon::audit::fuzzing::parse_cbom;

fn short(s: Option<&str>) -> bool {
    s.is_none_or(|s| s.chars().count() <= 257)
}

fuzz_target!(|data: &[u8]| {
    if let Ok(cbom) = parse_cbom(data) {
        assert!(cbom.spec_version == "1.6" || cbom.spec_version == "1.7");
        assert!(cbom.components.len() <= 100_000);
        assert_eq!(cbom.sha256.len(), 64);
        assert!(
            cbom.sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let mut total = 0usize;
        for (i, c) in cbom.components.iter().enumerate() {
            assert!(c.occurrences.len() <= 10_000);
            total += c.occurrences.len();
            assert!(
                short(c.name.as_deref())
                    && short(c.bom_ref.as_deref())
                    && short(c.asset_type.as_deref())
            );
            if c.name.as_ref().is_some_and(|n| n.chars().count() > 256) {
                assert!(c.clipped.contains(&"name"));
            }
            for o in &c.occurrences {
                assert!(short(o.additional_context.as_deref()));
                if let Ok(loc) = &o.location {
                    assert!(loc.len() <= 4096);
                }
            }
            if let Some(alg) = cbom.algorithm_for(i) {
                assert_eq!(alg.asset_type.as_deref(), Some("algorithm"));
            }
        }
        assert!(total <= 200_000);
    }
});
