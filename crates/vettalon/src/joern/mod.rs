//! Experimental, opt-in: Joern source→sink paths as one-way "keep" evidence
//! for refuter closures (`verify --joern-keep`, `vettalon joern check`).
//!
//! What it does: for a finding the refuter closed, ask Joern whether data
//! flows from a fixed source pattern (request parameters, argv, ...) to a
//! call on the claimed line. A path keeps the finding open (`Candidate`,
//! `verify_uncertain: joern path`) and records a `joern_path:` evidence
//! line. Nothing else changes a verdict: no path, no call on the line, an
//! unsupported language, a missing image, a timeout or any error leaves the
//! refutation standing and only records why. Absence of a path is never
//! evidence that a finding is false.
//!
//! Safety rules (network boundaries: docs/DATA-FLOW.md):
//! - Joern runs only inside the `vettalon-joern:<definition digest>` image,
//!   built locally from `docker/joern/Dockerfile` (Joern pinned to one
//!   release, checked against two hashes). Never pulled, never published.
//! - Each run: `--network=none`, read-only root, the source tree mounted
//!   read-only, non-root, no capabilities, memory/CPU/pid limits, and a
//!   timeout inside and outside the container.
//! - No model ever writes a query. The Scala template ([`TEMPLATE`]) is
//!   fixed and compiled into this binary; the claimed file and line and the
//!   fixed source patterns reach it only as data in a separate file, after a
//!   whitelist check ([`query`]).

mod check;
mod keep;
mod query;
mod run;
mod sources;

pub use check::{CHECK_SCHEMA, CheckOutput, CheckResult, ClaimRef, MAX_CHECK_CLAIMS, check_claims};
pub use keep::{
    JOERN_EVIDENCE_PREFIX, JOERN_PATH_PREFIX, JOERN_UNCERTAIN, JoernVerdict, KeepRule, apply_keep,
};
pub use query::{KeepQuery, PathStep, QueryOutcome, RunResult, validate_file, validate_line};
pub use run::{
    DEFAULT_TIMEOUT_SECS, ItemCheck, JoernSettings, LangRun, MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS,
    RunStats, check_items, run_args,
};
pub use sources::{SOURCES_VERSION, SourceKind, SourcePattern, sources_for};

/// The Joern release the image pins (see `docker/joern/Dockerfile`).
pub const JOERN_VERSION: &str = "v4.0.663";
/// Identifies the fixed Scala template; recorded on every evidence line.
pub const TEMPLATE_ID: &str = "keep-path-v1";
/// The fixed query template, mounted read-only into the container as is.
pub const TEMPLATE: &str = include_str!("keep_path.sc");

/// Joern frontends this integration uses, picked from the claimed file's
/// extension. Anything else is "unsupported" (recorded, no effect).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JoernLang {
    Php,
    Python,
    JsSrc,
    Golang,
    Java,
    C,
    Ruby,
    CSharpSrc,
}

impl JoernLang {
    pub const ALL: [JoernLang; 8] = [
        JoernLang::Php,
        JoernLang::Python,
        JoernLang::JsSrc,
        JoernLang::Golang,
        JoernLang::Java,
        JoernLang::C,
        JoernLang::Ruby,
        JoernLang::CSharpSrc,
    ];

    /// The `lang` value the template accepts.
    pub fn token(self) -> &'static str {
        match self {
            JoernLang::Php => "php",
            JoernLang::Python => "python",
            JoernLang::JsSrc => "jssrc",
            JoernLang::Golang => "golang",
            JoernLang::Java => "java",
            JoernLang::C => "c",
            JoernLang::Ruby => "ruby",
            JoernLang::CSharpSrc => "csharpsrc",
        }
    }

    /// Frontend for a claimed file, by extension (case-insensitive).
    pub fn from_path(file: &str) -> Option<JoernLang> {
        let name = file.rsplit('/').next().unwrap_or(file);
        let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
        Some(match ext.as_str() {
            "php" | "phtml" | "inc" => JoernLang::Php,
            "py" => JoernLang::Python,
            "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" => JoernLang::JsSrc,
            "go" => JoernLang::Golang,
            "java" => JoernLang::Java,
            "c" | "h" | "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => JoernLang::C,
            "rb" => JoernLang::Ruby,
            "cs" => JoernLang::CSharpSrc,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_follow_the_extension() {
        assert_eq!(JoernLang::from_path("a/b.PHP"), Some(JoernLang::Php));
        assert_eq!(JoernLang::from_path("x.tsx"), Some(JoernLang::JsSrc));
        assert_eq!(JoernLang::from_path("lib/x.hpp"), Some(JoernLang::C));
        assert_eq!(JoernLang::from_path("Makefile"), None);
        assert_eq!(JoernLang::from_path("a.rs"), None);
        assert_eq!(JoernLang::from_path("dir.php/readme"), None);
    }

    #[test]
    fn the_template_is_fixed_and_reads_parameters_only_as_data() {
        // The template has no placeholder vettalon could fill in: it reads
        // its parameters from /in/params.tsv and writes /work/result.tsv.
        assert!(TEMPLATE.contains("/in/params.tsv"));
        assert!(TEMPLATE.contains("/work/result.tsv"));
        for marker in ["{{", "}}", "%s", "${file", "${line", "@@"] {
            assert!(!TEMPLATE.contains(marker), "{marker}");
        }
        // Every language token the Rust side can send, the template accepts.
        for l in JoernLang::ALL {
            assert!(TEMPLATE.contains(&format!("\"{}\"", l.token())), "{l:?}");
        }
        assert!(TEMPLATE.contains(query::PARAMS_HEADER.split('\t').next().unwrap()));
        assert!(TEMPLATE.contains(query::RESULT_HEADER.split('\t').next().unwrap()));
    }
}
