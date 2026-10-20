//! Lockfile intake used by `vettalon hunt`: Cargo.lock / Cargo.toml,
//! package-lock.json, requirements.txt, go.sum / go.mod and the PyPI metadata
//! reply. All of it is attacker-controlled (a cloned repository or a
//! registry response).
//!
//! Input: one selector byte, then UTF-8-lossy text. Where a parser takes two
//! files, they are split at the first NUL.
//!
//! Invariants checked beyond "no panic":
//! - every target has the parser's ecosystem, a non-empty name and version,
//!   and `(name, version)` appears once;
//! - targets are ordered direct-first, then by name, then by version;
//! - the registry URL built from any parsed target stays on the fetcher's
//!   host allowlist, so lockfile content can never steer the download;
//! - a PyPI archive URL picked from metadata is returned verbatim from the
//!   input (the fetcher re-checks its host before use).

#![no_main]

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use vettalon::hunt::fetch::{
    cargo_url, go_url, host_allowed, npm_url, pick_pypi_sdist, pypi_metadata_url,
};
use vettalon::hunt::{
    DependencyTarget, Ecosystem, cargo_direct_deps, go_direct_deps, parse_cargo_lock, parse_go_sum,
    parse_npm_lock, parse_requirements_txt,
};

fn check_targets(targets: &[DependencyTarget], ecosystem: Ecosystem) {
    let mut seen = HashSet::new();
    for t in targets {
        assert_eq!(t.ecosystem, ecosystem);
        assert!(!t.name.is_empty(), "empty name: {t:?}");
        assert!(!t.version.is_empty(), "empty version: {t:?}");
        assert!(
            seen.insert((t.name.as_str(), t.version.as_str())),
            "duplicate target: {t:?}"
        );
        let url = match ecosystem {
            Ecosystem::Cargo => cargo_url(&t.name, &t.version),
            Ecosystem::Npm => npm_url(&t.name, &t.version),
            Ecosystem::PyPi => pypi_metadata_url(&t.name, &t.version),
            Ecosystem::Go => go_url(&t.name, &t.version),
        };
        assert!(
            host_allowed(&url),
            "target escapes the host allowlist: {url}"
        );
    }
    let key = |t: &DependencyTarget| (!t.direct, t.name.clone(), t.version.clone());
    for pair in targets.windows(2) {
        assert!(
            key(&pair[0]) <= key(&pair[1]),
            "targets out of order: {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(rest);
    let (first, second) = text.split_once('\0').unwrap_or((&text, ""));
    match selector % 5 {
        0 => {
            // Cargo.toml \0 Cargo.lock
            let direct = cargo_direct_deps(first);
            if let Ok(targets) = parse_cargo_lock(second, &direct) {
                check_targets(&targets, Ecosystem::Cargo);
            }
        }
        1 => {
            if let Ok(targets) = parse_npm_lock(&text) {
                check_targets(&targets, Ecosystem::Npm);
            }
        }
        2 => {
            let targets = parse_requirements_txt(&text);
            check_targets(&targets, Ecosystem::PyPi);
            assert!(targets.iter().all(|t| t.direct));
        }
        3 => {
            // go.mod \0 go.sum
            let direct = go_direct_deps(first);
            let targets = parse_go_sum(second, &direct);
            check_targets(&targets, Ecosystem::Go);
            assert!(targets.iter().all(|t| !t.version.ends_with("/go.mod")));
        }
        _ => {
            if let Some((url, _kind)) = pick_pypi_sdist(&text) {
                assert!(text.contains(url.as_str()) || text.contains('\\'));
            }
        }
    }
});
