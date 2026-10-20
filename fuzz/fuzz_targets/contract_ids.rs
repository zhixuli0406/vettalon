//! Identity and path primitives of `vettalon-contract` fed with model- or
//! repository-supplied strings: `SafeRepoPath`, `Fingerprint` and
//! `canonical_id`.
//!
//! Input: UTF-8-lossy text, split at NUL into up to 8 parts.
//!
//! Invariants checked beyond "no panic":
//! - an accepted `SafeRepoPath` has only normal path components, so joining
//!   it to a root can never leave the root (no `..`, root, prefix or `.`);
//! - `Fingerprint::derive` always yields a value `Fingerprint::parse`
//!   accepts, and is deterministic;
//! - `canonical_id` is lossless: splitting on `::` and percent-decoding
//!   gives back exactly the NFC form of every input ref.

#![no_main]

use std::path::{Component, Path};

use libfuzzer_sys::fuzz_target;
use percent_encoding::percent_decode_str;
use unicode_normalization::UnicodeNormalization;
use vettalon_contract::fingerprint::{Fingerprint, canonical_id};
use vettalon_contract::safe_path::SafeRepoPath;

const MAX_PARTS: usize = 8;

fn check_safe_path(s: &str) {
    let Ok(path) = SafeRepoPath::parse(s) else {
        return;
    };
    assert_eq!(path.as_str(), s);
    for component in Path::new(s).components() {
        assert!(
            matches!(component, Component::Normal(_)),
            "accepted path has a non-normal component {component:?}: {s:?}"
        );
    }
    let root = Path::new("/fuzz-root");
    let joined = path.join_under(root);
    assert!(joined.starts_with(root));
    assert!(joined.components().count() > root.components().count());
}

fn check_fingerprint(parts: &[&str]) {
    let derived = Fingerprint::derive(parts);
    assert_eq!(Fingerprint::derive(parts), derived);
    assert!(
        Fingerprint::parse(derived.as_str()).is_ok(),
        "derived fingerprint does not parse: {derived}"
    );
    if let Some(first) = parts.first()
        && let Ok(parsed) = Fingerprint::parse(first)
    {
        assert!(parsed.as_str().is_ascii());
        assert!(parsed.as_str().len() <= vettalon_contract::fingerprint::MAX_LEN);
    }
}

fn check_canonical_id(parts: &[&str]) {
    let Ok(id) = canonical_id(parts) else {
        return;
    };
    let decoded: Vec<String> = id
        .split("::")
        .map(|piece| {
            percent_decode_str(piece)
                .decode_utf8()
                .expect("canonical id piece must decode to UTF-8")
                .into_owned()
        })
        .collect();
    let expected: Vec<String> = parts.iter().map(|p| p.nfc().collect()).collect();
    assert_eq!(decoded, expected, "canonical id is not lossless: {id}");
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let parts: Vec<&str> = text.splitn(MAX_PARTS, '\0').collect();
    for part in &parts {
        check_safe_path(part);
    }
    check_fingerprint(&parts);
    check_canonical_id(&parts);
});
