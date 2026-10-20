//! Shipped, offline snapshot of popular package names per ecosystem.
//!
//! Used for two things only: the typosquat edit-distance rule (O18) and a
//! local criticality proxy in dependency prioritisation (O8). It is a ranking
//! snapshot by downloads, never a safety judgement. Go has no comparable public
//! ranking source, so it is unsupported (callers record `unknown`).
//! Provenance is the header of each `data/top-*.txt` file.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::Ecosystem;

const CRATES: &str = include_str!("data/top-crates.txt");
const NPM: &str = include_str!("data/top-npm.txt");
const PYPI: &str = include_str!("data/top-pypi.txt");

/// One ecosystem's popular-name list.
pub struct TopList {
    /// The `# Source:` header line, for report provenance.
    pub source: String,
    /// Normalised names in rank order (rank 1 = first).
    pub names: Vec<String>,
    rank: HashMap<String, usize>,
}

impl TopList {
    fn parse(text: &str, ecosystem: Ecosystem) -> Self {
        let mut source = String::new();
        let mut names = Vec::new();
        let mut rank = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(src) = line.strip_prefix("# Source:") {
                source = src.trim().to_string();
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let n = normalize(ecosystem, line);
            rank.entry(n.clone()).or_insert(names.len() + 1);
            names.push(n);
        }
        TopList {
            source,
            names,
            rank,
        }
    }

    /// 1-based rank of `name` (already normalised), if listed.
    pub fn rank_of(&self, normalized: &str) -> Option<usize> {
        self.rank.get(normalized).copied()
    }
}

/// Registry-equivalent spelling: crates.io treats `-`/`_` alike, PyPI applies
/// PEP 503 (`[-_.]+` → `-`), npm names are case-insensitive in practice.
pub fn normalize(ecosystem: Ecosystem, name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    match ecosystem {
        Ecosystem::Cargo => lower.replace('_', "-"),
        Ecosystem::PyPi => {
            let mut out = String::with_capacity(lower.len());
            let mut prev_sep = false;
            for c in lower.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !prev_sep {
                        out.push('-');
                    }
                    prev_sep = true;
                } else {
                    out.push(c);
                    prev_sep = false;
                }
            }
            out
        }
        Ecosystem::Npm | Ecosystem::Go => lower,
    }
}

/// The shipped list for `ecosystem`, or `None` where no snapshot exists (Go).
pub fn top_list(ecosystem: Ecosystem) -> Option<&'static TopList> {
    static LISTS: OnceLock<[TopList; 3]> = OnceLock::new();
    let lists = LISTS.get_or_init(|| {
        [
            TopList::parse(CRATES, Ecosystem::Cargo),
            TopList::parse(NPM, Ecosystem::Npm),
            TopList::parse(PYPI, Ecosystem::PyPi),
        ]
    });
    match ecosystem {
        Ecosystem::Cargo => Some(&lists[0]),
        Ecosystem::Npm => Some(&lists[1]),
        Ecosystem::PyPi => Some(&lists[2]),
        Ecosystem::Go => None,
    }
}

/// 1-based popularity rank of `name` in the shipped snapshot.
pub fn rank(ecosystem: Ecosystem, name: &str) -> Option<usize> {
    top_list(ecosystem)?.rank_of(&normalize(ecosystem, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_lists_load_with_provenance_and_1000_names() {
        for eco in [Ecosystem::Cargo, Ecosystem::Npm, Ecosystem::PyPi] {
            let list = top_list(eco).unwrap();
            assert_eq!(list.names.len(), 1000, "{eco:?}");
            assert!(!list.source.is_empty(), "{eco:?} provenance header");
        }
        assert!(top_list(Ecosystem::Go).is_none());
    }

    #[test]
    fn normalisation_matches_registry_equivalence() {
        assert_eq!(
            normalize(Ecosystem::PyPi, "Python_Dateutil"),
            "python-dateutil"
        );
        assert_eq!(
            normalize(Ecosystem::PyPi, "zope..interface"),
            "zope-interface"
        );
        assert_eq!(normalize(Ecosystem::Cargo, "serde_json"), "serde-json");
        assert_eq!(
            rank(Ecosystem::Cargo, "serde_json"),
            rank(Ecosystem::Cargo, "serde-json")
        );
        assert!(rank(Ecosystem::Npm, "semver").is_some_and(|r| r <= 10));
        assert!(rank(Ecosystem::PyPi, "requests").is_some());
    }
}
