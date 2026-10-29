//! Facade crates: a direct dependency whose own source is a thin shell that
//! re-exports another crate (xml-rs 1.0 is `pub use xml1::*;` over `xml`;
//! liquid re-exports `liquid_core`). Auditing only the shell reports
//! "complete" while the parser that handles untrusted input sits in a
//! transitive dependency the hunt skipped (hunt batch 3, 2026-10-28). The hunt
//! uses [`cargo_implementation_crates`] to promote those crates into the audit.

use std::collections::BTreeMap;
use std::path::Path;

/// A crate with more non-blank, non-comment Rust lines than this is treated
/// as real code, not a shell, even if it re-exports a dependency.
pub const FACADE_MAX_CODE_LINES: usize = 500;

/// At most this many implementation crates are promoted per facade, so one
/// re-export-heavy crate cannot multiply the hunt's cost.
pub const MAX_IMPLEMENTATIONS_PER_FACADE: usize = 3;

/// Package names of the crates a small Cargo package re-exports wholesale
/// (`pub use <dep>::*;`, `pub use <dep>::module::*;`, `pub extern crate
/// <dep>;`), resolved through `package =` renames. Re-exporting a single item
/// (`pub use serde::Serialize;`) does not make a crate a facade. Empty when
/// the package is not a facade (too much own code, no wholesale re-export,
/// no readable manifest). Proc-macro helpers (`*-derive`, `*-macros`) are
/// left out: they generate code, they do not parse input.
pub fn cargo_implementation_crates(package_root: &Path) -> Vec<String> {
    let Some(deps) = manifest_dependencies(&package_root.join("Cargo.toml")) else {
        return Vec::new();
    };
    let src = package_root.join("src");
    let mut sources = Vec::new();
    if !collect_rust_sources(&src, &mut sources, 0) {
        return Vec::new();
    }
    let code_lines: usize = sources.iter().map(|s| count_code_lines(s)).sum();
    if sources.is_empty() || code_lines > FACADE_MAX_CODE_LINES {
        return Vec::new();
    }
    let mut found: Vec<String> = Vec::new();
    for text in &sources {
        for ident in reexported_idents(text) {
            let Some(package) = deps.get(&ident) else {
                continue;
            };
            if is_macro_helper(package) || found.contains(package) {
                continue;
            }
            found.push(package.clone());
        }
    }
    found.truncate(MAX_IMPLEMENTATIONS_PER_FACADE);
    found
}

/// `[dependencies]` of a manifest as code identifier (`-` → `_`) → package
/// name, honouring `package = "..."` renames.
fn manifest_dependencies(manifest: &Path) -> Option<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(manifest).ok()?;
    let value: toml::Table = toml::from_str(&text).ok()?;
    let deps = value.get("dependencies")?.as_table()?;
    Some(
        deps.iter()
            .map(|(key, spec)| {
                let package = spec
                    .get("package")
                    .and_then(|p| p.as_str())
                    .unwrap_or(key)
                    .to_string();
                (key.replace('-', "_"), package)
            })
            .collect(),
    )
}

/// A shell crate is small and shallow. Returns false as soon as the tree is
/// too deep, has too many Rust files, or one file is too large to be a shell,
/// so a hostile or simply large tree is never read in full.
fn collect_rust_sources(dir: &Path, out: &mut Vec<String>, depth: usize) -> bool {
    const MAX_DEPTH: usize = 4;
    const MAX_FILES: usize = 64;
    const MAX_FILE_BYTES: u64 = 256 * 1024;
    if depth > MAX_DEPTH {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if !collect_rust_sources(&path, out, depth + 1) {
                return false;
            }
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
            if out.len() >= MAX_FILES || entry.metadata().map_or(true, |m| m.len() > MAX_FILE_BYTES)
            {
                return false;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                out.push(text);
            }
        }
    }
    true
}

fn count_code_lines(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .count()
}

/// First path segment of every wholesale re-export: a `pub use` glob
/// (`pub use dep::*;`, `pub use dep::model::*;`) or `pub extern crate dep;`.
fn reexported_idents(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        let rest = if let Some(r) = line.strip_prefix("pub use ") {
            if !r.trim_end().ends_with("::*;") {
                continue;
            }
            r
        } else if let Some(r) = line.strip_prefix("pub extern crate ") {
            r
        } else {
            continue;
        };
        let rest = rest.trim_start_matches("::");
        let ident: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() && !matches!(ident.as_str(), "crate" | "self" | "super") {
            out.push(ident);
        }
    }
    out
}

fn is_macro_helper(package: &str) -> bool {
    [
        "-derive", "_derive", "-macros", "_macros", "-macro", "_macro",
    ]
    .iter()
    .any(|suffix| package.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(manifest: &str, files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), manifest).unwrap();
        for (path, body) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        dir
    }

    #[test]
    fn glob_reexport_through_a_package_rename_is_a_facade() {
        // xml-rs 1.0.0, verbatim shape.
        let dir = package(
            "[package]\nname = \"xml-rs\"\nversion = \"1.0.0\"\n\
             [dependencies.xml1]\nversion = \"1.0.0\"\npackage = \"xml\"\n",
            &[("src/lib.rs", "//! Deprecated name.\n\npub use xml1::*;\n")],
        );
        assert_eq!(cargo_implementation_crates(dir.path()), vec!["xml"]);
    }

    #[test]
    fn thin_wrapper_promotes_its_core_but_not_the_derive_helper() {
        // liquid 0.26: re-exports liquid_core items and the derive macros.
        let dir = package(
            "[package]\nname = \"liquid\"\nversion = \"0.26.11\"\n\
             [dependencies]\nliquid-core = \"0.26\"\nliquid-derive = \"0.26\"\nserde = \"1\"\n",
            &[
                (
                    "src/lib.rs",
                    "mod parser;\npub use crate::parser::*;\npub use liquid_core::Error;\n\
                     pub mod model {\n    pub use liquid_core::model::*;\n}\n\
                     pub use liquid_derive::{ObjectView};\n",
                ),
                (
                    "src/parser.rs",
                    "pub struct Parser;\nimpl Parser { pub fn new() -> Self { Parser } }\n",
                ),
            ],
        );
        assert_eq!(cargo_implementation_crates(dir.path()), vec!["liquid-core"]);
    }

    #[test]
    fn a_crate_with_real_code_is_not_a_facade() {
        let body = "fn f() { let x = 1; }\n".repeat(FACADE_MAX_CODE_LINES + 1);
        let dir = package(
            "[package]\nname = \"big\"\nversion = \"1.0.0\"\n[dependencies]\nhelper = \"1\"\n",
            &[("src/lib.rs", &format!("pub use helper::*;\n{body}"))],
        );
        assert!(cargo_implementation_crates(dir.path()).is_empty());
    }

    #[test]
    fn re_exporting_one_item_is_not_a_facade() {
        // A small crate that re-exports a type from serde is real code.
        let dir = package(
            "[package]\nname = \"small\"\nversion = \"1.0.0\"\n[dependencies]\nserde = \"1\"\n",
            &[(
                "src/lib.rs",
                "pub use serde::Serialize;\npub fn f() -> u8 { 1 }\n",
            )],
        );
        assert!(cargo_implementation_crates(dir.path()).is_empty());
    }

    #[test]
    fn an_oversized_source_file_is_not_read_as_a_shell() {
        let big = "// x\n".repeat(80 * 1024); // > 256 KiB
        let dir = package(
            "[package]\nname = \"p\"\nversion = \"1.0.0\"\n[dependencies]\ninner = \"1\"\n",
            &[("src/lib.rs", "pub use inner::*;\n"), ("src/blob.rs", &big)],
        );
        assert!(cargo_implementation_crates(dir.path()).is_empty());
    }

    #[test]
    fn reexports_of_non_dependencies_are_ignored() {
        let dir = package(
            "[package]\nname = \"p\"\nversion = \"1.0.0\"\n",
            &[(
                "src/lib.rs",
                "pub use std::io::Read;\npub use self::x::*;\nmod x {}\n",
            )],
        );
        assert!(cargo_implementation_crates(dir.path()).is_empty());
    }

    #[test]
    fn missing_or_broken_manifest_is_not_a_facade() {
        let dir = tempfile::tempdir().unwrap();
        assert!(cargo_implementation_crates(dir.path()).is_empty());
        std::fs::write(dir.path().join("Cargo.toml"), "[ broken =").unwrap();
        assert!(cargo_implementation_crates(dir.path()).is_empty());
    }
}
