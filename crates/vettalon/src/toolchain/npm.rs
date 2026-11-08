//! MC002: npm malicious-package signals for MCP servers launched through
//! `npx` / `bunx` / `pnpm dlx` / `yarn dlx` / `npm exec`.
//!
//! Offline: `hunt::malicious::offline_check` (local MAL index + typosquat).
//! With `--online`: also OSV and the registry rules through the existing
//! allowlisted hunt clients. A missing or unusable MAL index makes the
//! audit incomplete, never clean.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use super::RawFinding;
use super::mcp::{
    McpEntry, Registry, display_spec, launcher_package, spec_is_exact, split_npm_spec,
};
use crate::audit::schema::Severity;
use crate::hunt::mal_index::{self, MalIndex};
use crate::hunt::malicious::{self, PackageCheck, Strength};
use crate::hunt::{DependencyTarget, Ecosystem, popular};

/// One npm package an MCP entry runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmUse {
    /// Index of the owning item.
    pub item: usize,
    pub file: PathBuf,
    pub line: Option<usize>,
    pub name: String,
    /// Exact version, when pinned.
    pub version: Option<String>,
}

/// The npm package an entry launches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpmSpec {
    /// A valid registry name with its exact version, when pinned.
    Package {
        name: String,
        version: Option<String>,
    },
    /// Not a valid npm `name[@version]`: never looked up (MC006).
    Invalid(String),
}

/// Max length of an npm package name.
const MAX_NAME_LEN: usize = 214;

static NPM_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$").expect("static npm name")
});
static NPM_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9.+_-]{1,64}$").expect("static npm version"));

/// npm package-name grammar: lowercase ASCII, optional single scope, no
/// `%`, `?`, `#`, `..` or extra `/`, at most 214 characters.
pub fn valid_npm_name(name: &str) -> bool {
    name.len() <= MAX_NAME_LEN && !name.contains("..") && NPM_NAME_RE.is_match(name)
}

/// A plain exact version or dist-tag token.
pub fn valid_npm_version(version: &str) -> bool {
    NPM_VERSION_RE.is_match(version)
}

/// The npm package an entry launches, validated before any lookup.
pub fn npm_package(entry: &McpEntry) -> Option<NpmSpec> {
    let launch = launcher_package(entry.command()?, &entry.args())?;
    let spec = launch.spec.as_str();
    if launch.registry != Registry::Npm
        || spec.contains("://")
        || spec.starts_with("git+")
        || spec.starts_with("github:")
        || spec.starts_with("npm:")
    {
        return None;
    }
    let exact = spec_is_exact(&launch)?;
    let (name, version) = split_npm_spec(spec);
    if !valid_npm_name(&name) || version.as_deref().is_some_and(|v| !valid_npm_version(v)) {
        return Some(NpmSpec::Invalid(spec.to_string()));
    }
    Some(NpmSpec::Package {
        name,
        version: if exact { version } else { None },
    })
}

/// MC006 for a spec that failed validation (shown redacted).
pub fn unparseable(file: &Path, line: Option<usize>, spec: &str) -> RawFinding {
    let shown = display_spec(spec);
    RawFinding::new(
        "MC006",
        Severity::Medium,
        Some(file),
        line,
        &format!(
            "unparseable npm package spec {shown:?}; not looked up, so MC002 was not evaluated for it"
        ),
        &shown,
    )
}

#[derive(Default)]
pub struct Outcome {
    pub findings: Vec<(usize, RawFinding)>,
    pub incomplete: Vec<String>,
}

fn push_reason(reasons: &mut Vec<String>, reason: String) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// Run MC002 over every npm use.
pub async fn check(uses: &[NpmUse], online: bool, mal_dir: &Path) -> Outcome {
    let mut out = Outcome::default();
    if uses.is_empty() {
        return out;
    }
    let (indexes, errors) = mal_index::load_dir(mal_dir);
    if !errors.is_empty() {
        push_reason(&mut out.incomplete, "mc002:mal_index_unusable".into());
    }
    let npm_indexed = indexes
        .iter()
        .any(|i| mal_index::ecosystem_of(&i.ecosystem) == Some(Ecosystem::Npm));
    if !npm_indexed {
        push_reason(&mut out.incomplete, "mc002:mal_index_absent".into());
    }
    let targets: Vec<DependencyTarget> = uses
        .iter()
        .map(|u| DependencyTarget {
            ecosystem: Ecosystem::Npm,
            name: u.name.clone(),
            version: u.version.clone().unwrap_or_default(),
            direct: true,
        })
        .collect();
    let checks = if online {
        online_checks(&targets, &indexes, &mut out.incomplete).await
    } else {
        targets
            .iter()
            .map(|t| malicious::offline_check(t, None, &indexes))
            .collect()
    };
    for (u, check) in uses.iter().zip(checks) {
        if check
            .rules_unknown
            .iter()
            .any(|r| r.starts_with("typosquat"))
        {
            push_reason(&mut out.incomplete, "mc002:typosquat_unavailable".into());
        }
        if let Some(f) = to_finding(u, &check) {
            out.findings.push((u.item, f));
        } else if u.version.is_none() && name_listed(&indexes, &u.name) {
            out.findings.push((u.item, unpinned_listed(u)));
        }
    }
    out
}

async fn online_checks(
    targets: &[DependencyTarget],
    indexes: &[MalIndex],
    incomplete: &mut Vec<String>,
) -> Vec<PackageCheck> {
    use crate::hunt::{fetch::HttpSourceFetcher, osv, registry};
    let exact: Vec<DependencyTarget> = targets
        .iter()
        .filter(|t| !t.version.is_empty())
        .cloned()
        .collect();
    let mut online = Vec::new();
    if !exact.is_empty() {
        let rows = osv::scan_known(&exact, &osv::HttpOsvClient::new()).await;
        let probe = registry::LiveRegistryProbe {
            http: registry::HttpRegistryGet::new(),
            fetcher: HttpSourceFetcher::new(),
        };
        let report = malicious::check_all(
            &exact,
            &rows,
            Some(&probe as &dyn registry::RegistryProbe),
            indexes,
            &malicious::MaliciousOptions::default(),
            chrono::Utc::now(),
        )
        .await;
        for r in report.incomplete_reasons {
            if r != "mal_index_absent" && r != "mal_index_unavailable" {
                push_reason(incomplete, format!("mc002:{r}"));
            }
        }
        online = report.checks;
    }
    let mut online = online.into_iter();
    targets
        .iter()
        .map(|t| {
            if t.version.is_empty() {
                malicious::offline_check(t, None, indexes)
            } else {
                online.next().unwrap_or_default()
            }
        })
        .collect()
}

fn label(u: &NpmUse) -> String {
    match &u.version {
        Some(v) => format!("{}@{v}", u.name),
        None => u.name.clone(),
    }
}

fn to_finding(u: &NpmUse, check: &PackageCheck) -> Option<RawFinding> {
    if check.signals.is_empty() {
        return None;
    }
    let evidence = check
        .signals
        .iter()
        .map(|s| format!("{:?}: {}", s.kind, s.evidence))
        .collect::<Vec<_>>()
        .join("; ");
    let (severity, why) = match malicious::finding_for(check) {
        Some(f) if f.signals.iter().any(|s| s.strength == Strength::Strong) => {
            (Severity::Critical, f.rationale)
        }
        Some(f) => (Severity::High, f.rationale),
        None => (
            Severity::Medium,
            "one signal below the hunt finding threshold; needs human review".to_string(),
        ),
    };
    Some(RawFinding::new(
        "MC002",
        severity,
        Some(u.file.as_path()),
        u.line,
        &format!("npm package {}: {why}; {evidence}", label(u)),
        &label(u),
    ))
}

fn name_listed(indexes: &[MalIndex], name: &str) -> bool {
    let n = popular::normalize(Ecosystem::Npm, name);
    indexes
        .iter()
        .filter(|i| mal_index::ecosystem_of(&i.ecosystem) == Some(Ecosystem::Npm))
        .flat_map(|i| i.entries.iter())
        .any(|e| popular::normalize(Ecosystem::Npm, &e.name) == n)
}

fn unpinned_listed(u: &NpmUse) -> RawFinding {
    RawFinding::new(
        "MC002",
        Severity::High,
        Some(u.file.as_path()),
        u.line,
        &format!(
            "npm package {} has versions listed in the local MAL index and the launcher is unpinned",
            u.name
        ),
        &u.name,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec_of(args: &[&str]) -> Option<NpmSpec> {
        npm_package(&McpEntry::new("s", json!({"command": "npx", "args": args})))
    }

    // M9: names and versions are validated before any URL is built.
    #[test]
    fn npm_specs_are_validated_before_lookup() {
        for (spec, name, version) in [
            ("some-mcp-server", "some-mcp-server", None),
            ("some-mcp-server@1.2.3", "some-mcp-server", Some("1.2.3")),
            ("@scope/server@1.2.3", "@scope/server", Some("1.2.3")),
            ("@scope/server@latest", "@scope/server", None),
            ("a.b_c~d-e", "a.b_c~d-e", None),
        ] {
            assert_eq!(
                spec_of(&["-y", spec]),
                Some(NpmSpec::Package {
                    name: name.into(),
                    version: version.map(str::to_string)
                }),
                "{spec}"
            );
        }
        let long = "a".repeat(215);
        for bad in [
            "Upper-Case",
            "pkg%2f..%2fadmin",
            "pkg?x=1",
            "pkg#frag",
            "a..b",
            "@scope/sub/extra",
            "@scope",
            "pkg-ü",
            "_leading",
            long.as_str(),
            "pkg@^1.2.0",
            "pkg@1.0.0?x",
            "pkg@1/../2",
        ] {
            assert!(
                matches!(spec_of(&["-y", bad]), Some(NpmSpec::Invalid(_))),
                "{bad}"
            );
        }
        assert!(valid_npm_name(&"a".repeat(214)));
        // Local paths are not registry packages at all.
        assert_eq!(spec_of(&["-y", "./local"]), None);
    }

    #[test]
    fn mc006_redacts_the_spec() {
        let secret = "sk-test-AAAAAAAAAAAAAAAAAAAAAAAA"; // gitleaks:allow (fake test value)
        let f = unparseable(Path::new("cfg.json"), Some(1), secret);
        assert_eq!(f.rule, "MC006");
        assert_eq!(f.severity, Severity::Medium);
        assert!(!f.message.contains("AAAAAAAA") && !f.excerpt.contains("AAAAAAAA"));
    }
}
