//! Read-only, deterministic dump of how a deep scan would rank and page a
//! repo's modules — with the metadata features behind that ranking — WITHOUT
//! calling any model. Dev/benchmark hook (module-ranking benchmark): it lets a
//! ranking experiment measure where a known-vulnerable file lands in the audit
//! order at zero audit cost.
//!
//! The snapshot is metadata only: repo-relative paths, extensions, byte sizes,
//! entry-point flags and git hotspot counts. It never carries file contents, so
//! it is safe to hand to an external metadata-only ranker. The test module
//! below fails if any source text leaks into the serialized form.
//!
//! [`ranked_modules`] is the single place the scan's ranking inputs are
//! assembled, shared with `run_audit_step`, so this dump cannot drift from what
//! a real scan audits.

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use super::ai_audit::{self, ModuleTarget};
use super::intake::{self, GitHistoryStatus, HotspotFile, RepoProfile};

/// Schema tag of the JSON this module emits; bump when a field changes meaning.
pub const RANK_SNAPSHOT_SCHEMA: &str = "vettalon.rank_snapshot/1";

/// Rank every code module of `repo_root` exactly as a deep scan does
/// (pre-pagination). Reads the directory walk plus the first
/// [`SNIFF_BYTES`] of each code-looking file: binaries that slipped past the
/// extension list are dropped here, so a module made only of them never
/// becomes an audit target (it used to be audited, read as empty and
/// counted as a failed module).
pub(crate) fn ranked_modules(repo_root: &Path, profile: &RepoProfile) -> Vec<ModuleTarget> {
    let all_files: Vec<String> = intake::walk_repo_files(repo_root)
        .into_iter()
        .filter(|f| ai_audit::is_non_code_file(f) || !looks_binary(repo_root, f))
        .collect();
    ai_audit::rank_modules(&all_files, hotspots_of(profile), &profile.entry_points)
}

/// Bytes read from the head of a file to decide whether it is text.
const SNIFF_BYTES: usize = 8192;

/// True when the head of `rel` holds a NUL byte and no UTF-16 byte-order
/// mark. Text that is merely not UTF-8 (Big5, Latin-1, UTF-16 with a BOM) is
/// kept: the audit cannot read it, and it must show up as unreadable in the
/// coverage instead of silently vanishing. A file that cannot be opened is
/// kept for the same reason.
fn looks_binary(repo_root: &Path, rel: &str) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(repo_root.join(rel)) else {
        return false;
    };
    let mut head = Vec::with_capacity(SNIFF_BYTES);
    if file
        .take(SNIFF_BYTES as u64)
        .read_to_end(&mut head)
        .is_err()
    {
        return false;
    }
    let utf16_bom = head.starts_with(&[0xff, 0xfe]) || head.starts_with(&[0xfe, 0xff]);
    !utf16_bom && head.contains(&0)
}

fn hotspots_of(profile: &RepoProfile) -> &[HotspotFile] {
    match &profile.git_history {
        GitHistoryStatus::Available { hotspots } => hotspots,
        GitHistoryStatus::Unavailable { .. } => &[],
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LanguageCount {
    pub extension: String,
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GitSignal {
    pub available: bool,
    /// Why history is unavailable (git missing, not a repo, ...).
    pub reason: Option<String>,
    /// Files with at least one security-flavored touch in the scan window.
    pub hotspot_count: usize,
}

/// Per-file metadata feature row. No content, by construction.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FileFeatures {
    pub path: String,
    pub ext: String,
    pub bytes: u64,
    pub is_entry_point: bool,
    pub security_touches: u64,
    pub total_touches: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RankedModule {
    /// 1-based position in the baseline module order.
    pub rank: usize,
    pub module_path: String,
    pub score: u64,
    pub high_risk: bool,
    /// Files in the order the scan would read them (highest signal first).
    pub files: Vec<FileFeatures>,
}

/// One audit unit (a module, or one page of an oversized module) in the order
/// the scan dispatches them; the first `--max-modules` (≤ the ceiling) are
/// audited, the rest deferred.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RankedPage {
    /// 1-based position in the audit order.
    pub rank: usize,
    pub page_path: String,
    pub module_path: String,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RankSnapshot {
    pub schema: &'static str,
    pub module_prompt_budget_bytes: usize,
    pub max_pages_per_module: usize,
    pub max_audit_modules_ceiling: usize,
    pub language_census: Vec<LanguageCount>,
    pub git: GitSignal,
    pub modules: Vec<RankedModule>,
    pub pages: Vec<RankedPage>,
}

/// Build the snapshot for `repo_root` (runs the same intake a deep scan runs:
/// directory walk + `git log`; no network, no model).
pub async fn rank_snapshot(repo_root: &Path) -> RankSnapshot {
    let profile = intake::build_profile(repo_root).await;
    let modules = ranked_modules(repo_root, &profile);
    snapshot_from(repo_root, &profile, modules)
}

/// The metadata feature row for one repo-relative file. The single source of
/// truth for what a metadata-only ranker (benchmark snapshot or Jev) is shown
/// — no file contents, by construction. Shared so the two cannot drift.
pub(crate) fn file_features(
    repo_root: &Path,
    profile: &RepoProfile,
    hotspots: &HashMap<&str, &HotspotFile>,
    path: &str,
) -> FileFeatures {
    let hs = hotspots.get(path);
    FileFeatures {
        path: path.to_string(),
        ext: Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default(),
        bytes: std::fs::metadata(repo_root.join(path))
            .map(|m| m.len())
            .unwrap_or(0),
        is_entry_point: profile.entry_points.iter().any(|e| e == path),
        security_touches: hs.map(|h| h.security_touches as u64).unwrap_or(0),
        total_touches: hs.map(|h| h.total_touches as u64).unwrap_or(0),
    }
}

/// Index a profile's hotspot files by path, for repeated `file_features` calls.
pub(crate) fn hotspot_index(profile: &RepoProfile) -> HashMap<&str, &HotspotFile> {
    hotspots_of(profile)
        .iter()
        .map(|h| (h.file.as_str(), h))
        .collect()
}

fn snapshot_from(
    repo_root: &Path,
    profile: &RepoProfile,
    modules: Vec<ModuleTarget>,
) -> RankSnapshot {
    let hotspots = hotspot_index(profile);
    let file_features =
        |path: &str| -> FileFeatures { file_features(repo_root, profile, &hotspots, path) };

    let mut ranked = Vec::with_capacity(modules.len());
    let mut pages = Vec::new();
    for (i, m) in modules.into_iter().enumerate() {
        // Paging is per-module and order-preserving, so paging one module at
        // a time yields exactly the scan's page list while keeping the parent.
        for p in ai_audit::paginate_modules(
            repo_root,
            vec![m.clone()],
            ai_audit::MODULE_PROMPT_BUDGET_BYTES,
        ) {
            pages.push(RankedPage {
                rank: pages.len() + 1,
                page_path: p.module_path,
                module_path: m.module_path.clone(),
                files: p.files,
            });
        }
        ranked.push(RankedModule {
            rank: i + 1,
            files: m.files.iter().map(|f| file_features(f)).collect(),
            module_path: m.module_path,
            score: m.score,
            high_risk: m.high_risk,
        });
    }

    let git = match &profile.git_history {
        GitHistoryStatus::Available { hotspots } => GitSignal {
            available: true,
            reason: None,
            hotspot_count: hotspots.len(),
        },
        GitHistoryStatus::Unavailable { reason } => GitSignal {
            available: false,
            reason: Some(reason.clone()),
            hotspot_count: 0,
        },
    };
    RankSnapshot {
        schema: RANK_SNAPSHOT_SCHEMA,
        module_prompt_budget_bytes: ai_audit::MODULE_PROMPT_BUDGET_BYTES,
        max_pages_per_module: ai_audit::MAX_PAGES_PER_MODULE,
        max_audit_modules_ceiling: ai_audit::MAX_AUDIT_MODULES_CEILING,
        language_census: profile
            .language_census
            .iter()
            .map(|l| LanguageCount {
                extension: l.extension.clone(),
                file_count: l.file_count,
            })
            .collect(),
        git,
        modules: ranked,
        pages,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "SECRET_SOURCE_MARKER_do_not_leak";

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src/api")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(
            root.join("src/api/handler.py"),
            format!("def handle(req):\n    eval(req.body)  # {MARKER}\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.rs"),
            format!("fn main() {{}} // {MARKER}\n"),
        )
        .unwrap();
        std::fs::write(root.join("docs/guide.md"), format!("# {MARKER}\n")).unwrap();
        dir
    }

    #[tokio::test]
    async fn binary_files_never_become_audit_targets() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::create_dir_all(root.join("blobs")).unwrap();
        std::fs::write(root.join("app/main.py"), "print('hi')\n").unwrap();
        // A binary with no extension next to code, and a directory of nothing
        // but binaries (NUL bytes in the head).
        std::fs::write(root.join("app/payload"), [0x7f, b'E', b'L', b'F', 0, 0, 1]).unwrap();
        std::fs::write(root.join("blobs/cache"), [0x00, 0xff, 0xfe, 0x41]).unwrap();
        std::fs::write(root.join("blobs/state"), [0x01, 0x00, 0x02, 0x00]).unwrap();
        // Not UTF-8 but text: legacy encodings (Big5 here) and UTF-16 with a
        // BOM stay targets, so they surface as unreadable instead of
        // vanishing from coverage. A NUL past the sniff window is not seen.
        std::fs::write(
            root.join("app/legacy.php"),
            [b'<', b'?', 0xa4, 0xa4, 0xa4, 0xe5, b';'],
        )
        .unwrap();
        std::fs::write(
            root.join("app/win.ps1"),
            [0xff, 0xfe, b'a', 0x00, b'b', 0x00],
        )
        .unwrap();
        let mut late_nul = "y".repeat(SNIFF_BYTES).into_bytes();
        late_nul.push(0);
        std::fs::write(root.join("app/late_nul.py"), &late_nul).unwrap();
        // UTF-8 text cut in the middle of a character is still text.
        let mut text = "x".repeat(SNIFF_BYTES - 1).into_bytes();
        text.extend("é".as_bytes());
        std::fs::write(root.join("app/long_script"), &text).unwrap();
        let profile = intake::build_profile(root).await;
        let modules = ranked_modules(root, &profile);
        let paths: Vec<&str> = modules.iter().map(|m| m.module_path.as_str()).collect();
        assert_eq!(paths, vec!["app"], "binary-only module must not be ranked");
        let mut files = modules[0].files.clone();
        files.sort();
        assert_eq!(
            files,
            [
                "app/late_nul.py",
                "app/legacy.php",
                "app/long_script",
                "app/main.py",
                "app/win.ps1"
            ]
            .map(String::from)
            .to_vec()
        );
    }

    #[tokio::test]
    async fn snapshot_is_metadata_only() {
        let dir = fixture();
        let snap = rank_snapshot(dir.path()).await;
        let json = serde_json::to_string(&snap).unwrap();
        assert!(!json.contains(MARKER), "file content leaked: {json}");
        assert!(!json.contains("eval(req.body)"));
        // Every string field is a short identifier (path / ext / module).
        fn walk(v: &serde_json::Value) {
            match v {
                serde_json::Value::String(s) => assert!(s.len() <= 512, "long field: {s}"),
                serde_json::Value::Array(a) => a.iter().for_each(walk),
                serde_json::Value::Object(o) => o.values().for_each(walk),
                _ => {}
            }
        }
        walk(&serde_json::from_str(&json).unwrap());
    }

    #[tokio::test]
    async fn snapshot_matches_scan_ranking_and_paging() {
        let dir = fixture();
        let profile = intake::build_profile(dir.path()).await;
        let modules = ranked_modules(dir.path(), &profile);
        let scan_pages = ai_audit::paginate_modules(
            dir.path(),
            modules.clone(),
            ai_audit::MODULE_PROMPT_BUDGET_BYTES,
        );
        let snap = snapshot_from(dir.path(), &profile, modules);
        let snap_pages: Vec<(&str, &Vec<String>)> = snap
            .pages
            .iter()
            .map(|p| (p.page_path.as_str(), &p.files))
            .collect();
        let want: Vec<(&str, &Vec<String>)> = scan_pages
            .iter()
            .map(|p| (p.module_path.as_str(), &p.files))
            .collect();
        assert_eq!(snap_pages, want);
        // docs/ is non-code: never a module.
        assert!(snap.modules.iter().all(|m| m.module_path != "docs"));
        let main = snap
            .modules
            .iter()
            .flat_map(|m| &m.files)
            .find(|f| f.path == "src/main.rs")
            .unwrap();
        assert!(main.is_entry_point);
        assert_eq!(main.ext, "rs");
        assert!(main.bytes > 0);
        assert_eq!(snap.pages.first().map(|p| p.rank), Some(1));
    }
}
