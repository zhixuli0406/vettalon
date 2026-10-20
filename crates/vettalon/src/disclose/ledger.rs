//! Per-project disclosure throttle.
//!
//! Maintainers are flooded with near-duplicate AI-assisted reports. The
//! ledger is a local file under the Vettalon home that records each drafted
//! report per project; a new draft for a project that still has an
//! unanswered one is refused unless the operator passes `--force-throttle`
//! with a reason. The human closes an entry (`answered` / `withdrawn`) with
//! `vettalon disclose-ledger close`. Nothing here contacts anyone.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const LEDGER_FILE: &str = "disclosure-ledger.json";
const LEDGER_MAX_BYTES: u64 = 4 * 1024 * 1024;
const REASON_MAX_CHARS: usize = 300;

pub fn default_path(home: &Path) -> PathBuf {
    home.join(LEDGER_FILE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerState {
    /// Drafted; no maintainer answer recorded yet.
    Open,
    /// The maintainer answered (acknowledged, fixed, rejected, ...).
    Answered,
    /// Never sent, or withdrawn by the reporter.
    Withdrawn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub project: String,
    pub finding_id: String,
    pub drafted_on: String,
    pub state: LedgerState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forced_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default)]
    pub entries: Vec<LedgerEntry>,
}

/// The throttle outcome attached to a disclosure package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThrottleStatus {
    pub project: String,
    /// Other unanswered drafts for this project (finding ids).
    pub open_for_project: Vec<String>,
    /// Set when the operator overrode the throttle.
    pub forced_reason: Option<String>,
}

/// Stable per-project key: the GitHub slug, else `ecosystem:name`, else name.
pub fn project_key(meta: &super::ProjectMeta) -> String {
    if let Some(slug) = &meta.github {
        return format!("github:{}", slug.to_ascii_lowercase());
    }
    match (&meta.ecosystem, &meta.name) {
        (Some(e), Some(n)) => format!("{}:{}", e.to_ascii_lowercase(), n.to_ascii_lowercase()),
        (None, Some(n)) => n.to_ascii_lowercase(),
        _ => "unknown-project".into(),
    }
}

/// Load the ledger. A missing file is empty; an unreadable or corrupt one is
/// an error (the throttle must not silently reset).
pub fn load(path: &Path) -> Result<Ledger, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Ledger::default()),
        Err(e) => {
            return Err(crate::tr!(
                "無法讀取揭露節流紀錄 {}：{e}",
                "cannot read the disclosure ledger {}: {e}",
                path.display()
            ));
        }
    };
    if !meta.is_file() || meta.len() > LEDGER_MAX_BYTES {
        return Err(crate::tr!(
            "揭露節流紀錄 {} 不是一般檔案或過大",
            "the disclosure ledger {} is not a regular file or is too large",
            path.display()
        ));
    }
    let raw = std::fs::read(path).map_err(|e| {
        crate::tr!(
            "無法讀取揭露節流紀錄 {}：{e}",
            "cannot read the disclosure ledger {}: {e}",
            path.display()
        )
    })?;
    serde_json::from_slice(&raw).map_err(|e| {
        crate::tr!(
            "揭露節流紀錄 {} 格式錯誤（不會自動重設）：{e}",
            "the disclosure ledger {} is malformed (it is never reset automatically): {e}",
            path.display()
        )
    })
}

fn save(path: &Path, ledger: &Ledger) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(ledger).map_err(|e| e.to_string())?;
    // Write a sibling temp file, then rename: a crash mid-write never leaves
    // a truncated ledger (which `load` would then refuse).
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let fail = |e: std::io::Error| {
        crate::tr!(
            "無法寫入揭露節流紀錄 {}：{e}",
            "cannot write the disclosure ledger {}: {e}",
            path.display()
        )
    };
    crate::util::write_private(&tmp, &json).map_err(fail)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        fail(e)
    })
}

/// Serialises read-modify-write of the ledger inside one process (the Pro
/// server and desktop app draft from concurrent requests). Separate processes
/// writing at the same instant remain a documented residual risk.
static LEDGER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn normalized_reason(force: Option<&str>) -> Option<String> {
    force.map(str::trim).filter(|s| !s.is_empty()).map(|s| {
        s.chars()
            .filter(|c| !c.is_control())
            .take(REASON_MAX_CHARS)
            .collect()
    })
}

/// Refuse a new draft for `project` while another finding's draft is open,
/// unless `force` carries a non-empty reason. Re-drafting the same finding
/// is always allowed.
pub fn check(
    ledger: &Ledger,
    project: &str,
    finding_id: &str,
    force: Option<&str>,
) -> Result<ThrottleStatus, String> {
    let open: Vec<String> = ledger
        .entries
        .iter()
        .filter(|e| {
            e.project == project && e.state == LedgerState::Open && e.finding_id != finding_id
        })
        .map(|e| e.finding_id.clone())
        .collect();
    let forced_reason = normalized_reason(force);
    if !open.is_empty() && forced_reason.is_none() {
        return Err(crate::tr!(
            "節流：{project} 已有尚未獲回覆的草稿（{}）。一次只送一份，等維護者回覆後用 `vettalon disclose-ledger close` 結案；確有必要時用 --force-throttle <理由>。",
            "throttled: {project} already has an unanswered draft ({}). Send one at a time; after the maintainer answers, close it with `vettalon disclose-ledger close`, or pass --force-throttle <reason> if this one cannot wait.",
            open.join(", ")
        ));
    }
    Ok(ThrottleStatus {
        project: project.to_string(),
        open_for_project: open,
        forced_reason,
    })
}

/// Record (or refresh) an open draft for `project` / `finding_id`.
pub fn record(
    path: &Path,
    status: &ThrottleStatus,
    finding_id: &str,
    today: chrono::NaiveDate,
) -> Result<(), String> {
    let _guard = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut ledger = load(path)?;
    // Re-check under the lock: another draft for this project may have been
    // recorded since `check` ran.
    check(
        &ledger,
        &status.project,
        finding_id,
        status.forced_reason.as_deref(),
    )?;
    let entry = LedgerEntry {
        project: status.project.clone(),
        finding_id: finding_id.to_string(),
        drafted_on: today.to_string(),
        state: LedgerState::Open,
        forced_reason: status.forced_reason.clone(),
        closed_on: None,
        note: None,
    };
    match ledger.entries.iter_mut().find(|e| {
        e.project == entry.project && e.finding_id == finding_id && e.state == LedgerState::Open
    }) {
        Some(existing) => *existing = entry,
        None => ledger.entries.push(entry),
    }
    save(path, &ledger)
}

/// Close every open entry of `project` (optionally one finding) as `state`.
pub fn close(
    path: &Path,
    project: &str,
    finding_id: Option<&str>,
    state: LedgerState,
    note: Option<&str>,
    today: chrono::NaiveDate,
) -> Result<usize, String> {
    if state == LedgerState::Open {
        return Err("closing state must be answered or withdrawn".into());
    }
    let _guard = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut ledger = load(path)?;
    let mut n = 0;
    for e in ledger.entries.iter_mut().filter(|e| {
        e.project == project
            && e.state == LedgerState::Open
            && finding_id.is_none_or(|id| e.finding_id == id)
    }) {
        e.state = state;
        e.closed_on = Some(today.to_string());
        e.note = normalized_reason(note);
        n += 1;
    }
    if n > 0 {
        save(path, &ledger)?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 20).unwrap()
    }

    #[test]
    fn second_open_draft_for_a_project_is_refused_until_answered() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(LEDGER_FILE);
        let s = check(&load(&p).unwrap(), "github:a/b", "f1", None).unwrap();
        record(&p, &s, "f1", day()).unwrap();
        // Same finding again: allowed (re-draft).
        assert!(check(&load(&p).unwrap(), "github:a/b", "f1", None).is_ok());
        // Different finding, same project: refused.
        let err = check(&load(&p).unwrap(), "github:a/b", "f2", None).unwrap_err();
        assert!(err.contains("--force-throttle"), "{err}");
        // Another project is unaffected.
        assert!(check(&load(&p).unwrap(), "github:c/d", "f2", None).is_ok());
        // Closing the first one releases the project.
        assert_eq!(
            close(
                &p,
                "github:a/b",
                None,
                LedgerState::Answered,
                Some("ack"),
                day()
            )
            .unwrap(),
            1
        );
        assert!(check(&load(&p).unwrap(), "github:a/b", "f2", None).is_ok());
    }

    #[test]
    fn force_needs_a_reason_and_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(LEDGER_FILE);
        let s = check(&Ledger::default(), "x", "f1", None).unwrap();
        record(&p, &s, "f1", day()).unwrap();
        assert!(check(&load(&p).unwrap(), "x", "f2", Some("   ")).is_err());
        let forced = check(&load(&p).unwrap(), "x", "f2", Some("actively exploited")).unwrap();
        assert_eq!(forced.forced_reason.as_deref(), Some("actively exploited"));
        record(&p, &forced, "f2", day()).unwrap();
        let l = load(&p).unwrap();
        assert_eq!(l.entries.len(), 2);
        assert_eq!(
            l.entries[1].forced_reason.as_deref(),
            Some("actively exploited")
        );
    }

    #[test]
    fn record_rechecks_the_throttle_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(LEDGER_FILE);
        // Two drafts passed `check` against the same empty ledger.
        let a = check(&Ledger::default(), "x", "f1", None).unwrap();
        let b = check(&Ledger::default(), "x", "f2", None).unwrap();
        record(&p, &a, "f1", day()).unwrap();
        assert!(
            record(&p, &b, "f2", day()).is_err(),
            "second record must lose"
        );
        assert_eq!(load(&p).unwrap().entries.len(), 1);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(LEDGER_FILE)]);
    }

    #[test]
    fn corrupt_ledger_is_an_error_not_a_reset() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(LEDGER_FILE);
        std::fs::write(&p, b"not json").unwrap();
        assert!(load(&p).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"not json");
    }

    #[test]
    fn project_key_prefers_github_slug() {
        let mut m = super::super::ProjectMeta {
            github: Some("Acme/Shop".into()),
            name: Some("shop".into()),
            ecosystem: Some("Rust".into()),
            ..Default::default()
        };
        assert_eq!(project_key(&m), "github:acme/shop");
        m.github = None;
        assert_eq!(project_key(&m), "rust:shop");
    }
}
