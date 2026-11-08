//! Pin store: `$VETTALON_HOME/toolchain/pins.json` plus a
//! `pins.json.sha256` sidecar and the local HMAC key `key`. Directory
//! `0700`, files `0600`, atomic replace. Every component from
//! `$VETTALON_HOME` down is refused when it is a symlink; files are opened
//! with `O_NOFOLLOW`, checked on the opened descriptor (regular file, owner,
//! mode, size) and read with a hard cap. The store must not live inside the
//! audited project.
//!
//! The sidecar is a corruption checksum, not tamper-proofing: anyone who
//! can write the store can rewrite both files. A sidecar mismatch is an
//! integrity error (exit 2); the store is never silently trusted or reset.
//!
//! Pins hold hashes and relative paths only, never content or secret
//! values (MCP entries are hashed after their secrets are replaced by
//! keyed digests).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::content::FileRecord;
use super::{Agent, Kind, Scope, is_unsafe_char, random_key, sha256_hex};

pub const PINS_SCHEMA: &str = "vettalon.toolchain-pins/1";
const PINS_FILE: &str = "pins.json";
const SIDECAR_FILE: &str = "pins.json.sha256";
const KEY_FILE: &str = "key";
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SIDECAR_BYTES: u64 = 128;
const KEY_BYTES: usize = 32;
/// Permission bits that must be clear: store directory and pin files.
const NOT_WRITABLE_BY_OTHERS: u32 = 0o022;
/// The key must not be readable or writable by anyone else.
const PRIVATE_ONLY: u32 = 0o077;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinRecord {
    pub id: String,
    pub agent: Agent,
    pub kind: Kind,
    pub scope: Scope,
    /// Display path of the project, for project-scope items.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Display path (`~/…`).
    pub path: String,
    pub hash: String,
    pub pinned_at: String,
    /// Per-file (skills, plugins) or per-field (MCP) hashes.
    pub files: Vec<FileRecord>,
}

impl PinRecord {
    pub fn matches(&self, id: &str, project: Option<&str>) -> bool {
        self.id == id && self.project.as_deref() == project
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinStore {
    pub schema: String,
    pub pins: Vec<PinRecord>,
}

impl Default for PinStore {
    fn default() -> Self {
        PinStore {
            schema: PINS_SCHEMA.into(),
            pins: Vec::new(),
        }
    }
}

impl PinStore {
    pub fn find(&self, id: &str, project: Option<&str>) -> Option<&PinRecord> {
        self.pins.iter().find(|p| p.matches(id, project))
    }

    /// Insert or replace the pin with the same id and project.
    pub fn upsert(&mut self, pin: PinRecord) {
        match self
            .pins
            .iter_mut()
            .find(|p| p.matches(&pin.id, pin.project.as_deref()))
        {
            Some(slot) => *slot = pin,
            None => self.pins.push(pin),
        }
        self.pins
            .sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.project.cmp(&b.project)));
    }
}

pub fn store_dir(vettalon_home: &Path) -> PathBuf {
    vettalon_home.join("toolchain")
}

/// The store directory for `vettalon_home`, refused when `$VETTALON_HOME`
/// or the store directory is a symlink (or not a directory), or when the
/// canonical store lies inside the canonical `project` (a project could
/// otherwise plant or rewrite its own pins and key). The inside-project
/// refusal does not apply when the canonical project is the canonical
/// `user_home` or one of its ancestors: that is the user's own directory (the
/// default `--project` is the current directory), not a repository planting
/// a store.
pub fn checked_store_dir(
    vettalon_home: &Path,
    project: &Path,
    user_home: &Path,
) -> Result<PathBuf, String> {
    let home = std::path::absolute(vettalon_home)
        .map_err(|e| format!("cannot resolve {}: {e}", vettalon_home.display()))?;
    let dir = store_dir(&home);
    for p in [home.as_path(), dir.as_path()] {
        inspect_dir_entry(p)?;
    }
    let store = canonical_or_nearest(&dir)?;
    let project = project
        .canonicalize()
        .map_err(|e| format!("cannot resolve the project {}: {e}", project.display()))?;
    let project_is_user_home_or_ancestor = user_home
        .canonicalize()
        .is_ok_and(|h| h.starts_with(&project));
    if store.starts_with(&project) && !project_is_user_home_or_ancestor {
        return Err(format!(
            "the pin store {} is inside the audited project {}; refusing to read or write it \
             (a project could plant its own pins). Set VETTALON_HOME to a directory outside the project",
            store.display(),
            project.display()
        ));
    }
    Ok(dir)
}

/// Canonical form of `p`, resolving the deepest existing ancestor.
fn canonical_or_nearest(p: &Path) -> Result<PathBuf, String> {
    let mut existing = p.to_path_buf();
    let mut rest = Vec::new();
    loop {
        if let Ok(c) = existing.canonicalize() {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return Ok(out);
        }
        match existing.file_name() {
            Some(name) => rest.push(name.to_os_string()),
            None => return Err(format!("cannot resolve {}", p.display())),
        }
        if !existing.pop() {
            return Err(format!("cannot resolve {}", p.display()));
        }
    }
}

/// A path component that must be a real directory when it exists.
fn inspect_dir_entry(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(format!(
            "pin store path is a symlink and is refused: {}",
            path.display()
        )),
        Ok(m) if !m.is_dir() => Err(format!(
            "pin store path is not a directory: {}",
            path.display()
        )),
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot inspect {}: {e}", path.display())),
    }
}

/// Owner must be the current user and `forbidden` mode bits clear.
#[cfg(unix)]
fn check_owner_mode(meta: &std::fs::Metadata, path: &Path, forbidden: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no arguments and only reads process identity.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        return Err(format!(
            "pin store path {} is not owned by the current user; refusing to trust it",
            path.display()
        ));
    }
    if meta.mode() & forbidden != 0 {
        return Err(format!(
            "pin store path {} has mode {:o} (group/world access); refusing to trust it. \
             Restrict it (chmod go-rwx) after checking its content",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_mode(_: &std::fs::Metadata, _: &Path, _: u32) -> Result<(), String> {
    Ok(())
}

/// Whether the store directory exists; a symlink, a non-directory, a
/// foreign owner or group/world-writable mode is an error.
fn store_dir_exists(dir: &Path) -> Result<bool, String> {
    match inspect_dir_entry(dir)? {
        Some(m) => {
            check_owner_mode(&m, dir, NOT_WRITABLE_BY_OTHERS)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Open a store file without following a symlink and check the opened
/// descriptor: regular file, owner, `forbidden` mode bits clear.
fn open_store_file(
    path: &Path,
    forbidden: u32,
) -> Result<Option<(std::fs::File, std::fs::Metadata)>, String> {
    let refused = || {
        format!(
            "pin store path is a symlink and is refused: {}",
            path.display()
        )
    };
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(refused());
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(refused()),
        Err(e) => return Err(format!("cannot open {}: {e}", path.display())),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "pin store path is not a regular file: {}",
            path.display()
        ));
    }
    check_owner_mode(&meta, path, forbidden)?;
    Ok(Some((file, meta)))
}

/// At most `cap` bytes from an opened store file; more is an error.
fn read_bounded(
    file: std::fs::File,
    meta: &std::fs::Metadata,
    path: &Path,
    cap: u64,
) -> Result<Vec<u8>, String> {
    let too_big = || format!("{} is larger than its {cap}-byte limit", path.display());
    if meta.len() > cap {
        return Err(too_big());
    }
    let mut buf = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if buf.len() as u64 > cap {
        return Err(too_big());
    }
    Ok(buf)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The sidecar: exactly 64 lowercase hex digits and an optional newline.
fn parse_sidecar(bytes: &[u8], path: &Path) -> Result<String, String> {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    match std::str::from_utf8(body) {
        Ok(s) if is_hex64(s) => Ok(s.to_string()),
        _ => Err(format!(
            "{} is malformed (expected 64 hex digits); the pin store is not trusted",
            path.display()
        )),
    }
}

/// Load and verify the store. Missing store and sidecar → empty store.
pub fn load(dir: &Path) -> Result<PinStore, String> {
    if !store_dir_exists(dir)? {
        return Ok(PinStore::default());
    }
    let path = dir.join(PINS_FILE);
    let side = dir.join(SIDECAR_FILE);
    let store_file = open_store_file(&path, NOT_WRITABLE_BY_OTHERS)?;
    let side_file = open_store_file(&side, NOT_WRITABLE_BY_OTHERS)?;
    let Some((file, meta)) = store_file else {
        return match side_file {
            None => Ok(PinStore::default()),
            Some(_) => Err(format!(
                "{} exists without {}; refusing to trust the pin store",
                side.display(),
                path.display()
            )),
        };
    };
    let bytes = read_bounded(file, &meta, &path, MAX_STORE_BYTES)?;
    let expected = match side_file {
        Some((f, m)) => Some(parse_sidecar(
            &read_bounded(f, &m, &side, MAX_SIDECAR_BYTES)?,
            &side,
        )?),
        None => None,
    };
    if expected.as_deref() != Some(sha256_hex(&bytes).as_str()) {
        return Err(format!(
            "{} does not match {} (modified outside vettalon, or the sidecar is missing); \
             the pin store is not trusted. Inspect it, then remove both files to start over",
            path.display(),
            side.display()
        ));
    }
    let store: PinStore = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is malformed: {e}", path.display()))?;
    if store.schema != PINS_SCHEMA {
        return Err(format!(
            "{} has schema {:?}, expected {PINS_SCHEMA}",
            path.display(),
            store.schema
        ));
    }
    validate(&store, &path)?;
    Ok(store)
}

fn plain_text(s: &str) -> bool {
    !s.chars().any(is_unsafe_char)
}

fn valid_item_hash(h: &str) -> bool {
    h.strip_prefix("sha256:")
        .or_else(|| h.strip_prefix("hmac:"))
        .is_some_and(is_hex64)
}

fn valid_file_hash(h: &str) -> bool {
    is_hex64(h) || h.strip_prefix("hmac:").is_some_and(is_hex64)
}

/// Schema check of every pin: hashes, RFC 3339 timestamps, and ids / paths
/// without control or invisible characters.
fn validate(store: &PinStore, path: &Path) -> Result<(), String> {
    for (i, p) in store.pins.iter().enumerate() {
        let what = if p.id.is_empty() || !plain_text(&p.id) {
            Some("id")
        } else if !plain_text(&p.path) {
            Some("path")
        } else if p.project.as_deref().is_some_and(|x| !plain_text(x)) {
            Some("project")
        } else if !valid_item_hash(&p.hash) {
            Some("hash")
        } else if chrono::DateTime::parse_from_rfc3339(&p.pinned_at).is_err() {
            Some("pinned_at")
        } else if p
            .files
            .iter()
            .any(|f| !plain_text(&f.rel) || !valid_file_hash(&f.sha256))
        {
            Some("file record")
        } else {
            None
        };
        if let Some(what) = what {
            return Err(format!(
                "{} is malformed: pin #{i} has an invalid {what}; the pin store is not trusted",
                path.display()
            ));
        }
    }
    Ok(())
}

fn ensure_dir(dir: &Path) -> Result<(), String> {
    if !store_dir_exists(dir)? {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot restrict {}: {e}", dir.display()))?;
    }
    if store_dir_exists(dir)? {
        Ok(())
    } else {
        Err(format!("cannot create {}", dir.display()))
    }
}

/// Write `bytes` to `dir/name` through a private temp file and rename.
fn replace_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let target = dir.join(name);
    match std::fs::symlink_metadata(&target) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!(
                "pin store path is a symlink and is refused: {}",
                target.display()
            ));
        }
        Ok(m) if !m.is_file() => {
            return Err(format!(
                "pin store path is not a regular file: {}",
                target.display()
            ));
        }
        _ => {}
    }
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    crate::util::write_private(&tmp, bytes)
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", target.display())
    })
}

/// Save the store and its sidecar.
pub fn save(dir: &Path, store: &PinStore) -> Result<(), String> {
    ensure_dir(dir)?;
    let mut json =
        serde_json::to_vec_pretty(store).map_err(|e| format!("cannot encode pins: {e}"))?;
    json.push(b'\n');
    replace_atomic(dir, PINS_FILE, &json)?;
    replace_atomic(
        dir,
        SIDECAR_FILE,
        format!("{}\n", sha256_hex(&json)).as_bytes(),
    )
}

/// The local HMAC key `dir/key` (32 random bytes, mode `0600`), created
/// with `create_new` on first use. Same directory, symlink, owner and mode
/// checks as the store; the key itself must have no group/world access.
pub fn load_or_create_key(dir: &Path) -> Result<[u8; KEY_BYTES], String> {
    ensure_dir(dir)?;
    let path = dir.join(KEY_FILE);
    for _ in 0..2 {
        if let Some((file, meta)) = open_store_file(&path, PRIVATE_ONLY)? {
            let bytes = read_bounded(file, &meta, &path, KEY_BYTES as u64)?;
            return <[u8; KEY_BYTES]>::try_from(bytes.as_slice()).map_err(|_| {
                format!(
                    "{} is not a {KEY_BYTES}-byte key; remove it to create a new one (existing pins of MCP entries with secrets and of secret-bearing files will then show as changed)",
                    path.display()
                )
            });
        }
        let key = random_key();
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        match opts.open(&path) {
            Ok(mut f) => {
                f.write_all(&key)
                    .and_then(|()| f.sync_all())
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                return Ok(key);
            }
            // Another process created it first: read theirs.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create {}: {e}", path.display())),
        }
    }
    Err(format!("cannot create or read {}", path.display()))
}

/// Paths added, removed and modified between a pin and the current files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
}

pub fn diff(pinned: &[FileRecord], current: &[FileRecord]) -> FileDiff {
    use std::collections::BTreeMap;
    let old: BTreeMap<&str, &str> = pinned
        .iter()
        .map(|f| (f.rel.as_str(), f.sha256.as_str()))
        .collect();
    let new: BTreeMap<&str, &str> = current
        .iter()
        .map(|f| (f.rel.as_str(), f.sha256.as_str()))
        .collect();
    let mut d = FileDiff::default();
    for (rel, h) in &new {
        match old.get(rel) {
            None => d.added.push(rel.to_string()),
            Some(o) if o != h => d.modified.push(rel.to_string()),
            Some(_) => {}
        }
    }
    d.removed = old
        .keys()
        .filter(|rel| !new.contains_key(*rel))
        .map(|r| r.to_string())
        .collect();
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str) -> PinRecord {
        PinRecord {
            id: id.into(),
            agent: Agent::Claude,
            kind: Kind::Skill,
            scope: Scope::User,
            project: None,
            path: "~/.claude/skills/x".into(),
            hash: format!("sha256:{}", "0".repeat(64)),
            pinned_at: "2026-11-08T00:00:00Z".into(),
            files: vec![FileRecord {
                rel: "SKILL.md".into(),
                sha256: "a".repeat(64),
            }],
        }
    }

    /// Replace pins.json with `bytes` and a matching sidecar.
    fn write_raw(dir: &Path, bytes: &[u8]) {
        save(dir, &PinStore::default()).unwrap();
        std::fs::write(dir.join(PINS_FILE), bytes).unwrap();
        std::fs::write(dir.join(SIDECAR_FILE), format!("{}\n", sha256_hex(bytes))).unwrap();
    }

    #[test]
    fn round_trip_and_tamper_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let dir = store_dir(home.path());
        assert_eq!(load(&dir).unwrap(), PinStore::default());
        let mut store = PinStore::default();
        store.upsert(rec("claude:skill:user:x"));
        save(&dir, &store).unwrap();
        assert_eq!(load(&dir).unwrap(), store);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join(PINS_FILE)), 0o600);
            assert_eq!(mode(&dir.join(SIDECAR_FILE)), 0o600);
        }
        let mut bytes = std::fs::read(dir.join(PINS_FILE)).unwrap();
        bytes.extend_from_slice(b" ");
        std::fs::write(dir.join(PINS_FILE), bytes).unwrap();
        assert!(load(&dir).unwrap_err().contains("does not match"));
    }

    #[test]
    fn missing_sidecar_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let dir = store_dir(home.path());
        save(&dir, &PinStore::default()).unwrap();
        std::fs::remove_file(dir.join(SIDECAR_FILE)).unwrap();
        assert!(load(&dir).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_store_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), store_dir(home.path())).unwrap();
        assert!(
            load(&store_dir(home.path()))
                .unwrap_err()
                .contains("symlink")
        );
        assert!(save(&store_dir(home.path()), &PinStore::default()).is_err());
    }

    // H4: symlinked files are refused on open; the sidecar is size- and
    // format-checked; reads are capped.
    #[cfg(unix)]
    #[test]
    fn symlinked_pin_files_are_refused() {
        let home = tempfile::tempdir().unwrap();
        let dir = store_dir(home.path());
        save(&dir, &PinStore::default()).unwrap();
        let real = home.path().join("real.json");
        std::fs::rename(dir.join(PINS_FILE), &real).unwrap();
        std::os::unix::fs::symlink(&real, dir.join(PINS_FILE)).unwrap();
        assert!(load(&dir).unwrap_err().contains("symlink"));
    }

    #[test]
    fn sidecar_must_be_64_hex_and_small() {
        let home = tempfile::tempdir().unwrap();
        let dir = store_dir(home.path());
        save(&dir, &PinStore::default()).unwrap();
        let bytes = std::fs::read(dir.join(PINS_FILE)).unwrap();
        let good = sha256_hex(&bytes);
        for bad in [
            format!("{good}\n\n"),
            format!(" {good}"),
            good.to_ascii_uppercase(),
            good[..63].to_string(),
            "x".repeat(4096),
        ] {
            std::fs::write(dir.join(SIDECAR_FILE), &bad).unwrap();
            let err = load(&dir).unwrap_err();
            assert!(
                err.contains("malformed") || err.contains("limit"),
                "{bad:?}: {err}"
            );
        }
        std::fs::write(dir.join(SIDECAR_FILE), &good).unwrap();
        assert!(load(&dir).is_ok(), "no trailing newline is fine");
    }

    #[test]
    fn bounded_reads_refuse_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, "0123456789").unwrap();
        let open = || open_store_file(&p, 0).unwrap().unwrap();
        let (f, m) = open();
        assert!(read_bounded(f, &m, &p, 5).unwrap_err().contains("limit"));
        let (f, m) = open();
        assert_eq!(read_bounded(f, &m, &p, 10).unwrap(), b"0123456789");
    }

    // H5: owner/mode and location checks.
    #[cfg(unix)]
    #[test]
    fn group_writable_store_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let dir = store_dir(home.path());
        save(&dir, &PinStore::default()).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(load(&dir).unwrap_err().contains("mode"));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(dir.join(PINS_FILE), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(load(&dir).unwrap_err().contains("mode"));
    }

    #[test]
    fn store_inside_the_project_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let inside = project.join(".vh");
        let user = tmp.path().join("user");
        std::fs::create_dir_all(&user).unwrap();
        let err = checked_store_dir(&inside, &project, &user).unwrap_err();
        assert!(err.contains("inside the audited project"), "{err}");
        let outside = tmp.path().join("vh");
        assert_eq!(
            checked_store_dir(&outside, &project, &user).unwrap(),
            store_dir(&std::path::absolute(&outside).unwrap())
        );
        // The project being the store's ancestor via VETTALON_HOME == project.
        assert!(checked_store_dir(&project, &project, &user).is_err());
    }

    #[test]
    fn project_that_is_the_user_home_or_its_ancestor_may_hold_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = home.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        // project == home, store at home/.vettalon
        let vh = home.join(".vettalon");
        assert_eq!(
            checked_store_dir(&vh, &home, &home).unwrap(),
            store_dir(&std::path::absolute(&vh).unwrap())
        );
        // project is an ancestor of home
        assert!(checked_store_dir(&vh, tmp.path(), &home).is_ok());
        // project is a repo below home: still refused
        let planted = repo.join(".v");
        let err = checked_store_dir(&planted, &repo, &home).unwrap_err();
        assert!(err.contains("inside the audited project"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_vettalon_home_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("proj");
        let real = tmp.path().join("real-home");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        let link = tmp.path().join("vh");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            checked_store_dir(&link, &project, tmp.path())
                .unwrap_err()
                .contains("symlink")
        );
        // A symlinked home pointing into the project is refused either way.
        let into = tmp.path().join("vh2");
        std::os::unix::fs::symlink(&project, &into).unwrap();
        assert!(checked_store_dir(&into, &project, tmp.path()).is_err());
    }

    // L10: externally sourced pin fields are validated on load.
    #[test]
    fn malformed_pin_fields_are_refused() {
        let home = tempfile::tempdir().unwrap();
        let dir = store_dir(home.path());
        let mut cases: Vec<PinRecord> = Vec::new();
        let mut r = rec("claude:skill:user:x\u{1b}[2J");
        cases.push(r.clone());
        r = rec("ok");
        r.path = "~/x\u{202e}y".into();
        cases.push(r.clone());
        r = rec("ok");
        r.hash = "sha256:zz".into();
        cases.push(r.clone());
        r = rec("ok");
        r.pinned_at = "yesterday".into();
        cases.push(r.clone());
        r = rec("ok");
        r.files[0].rel = "a\nb".into();
        cases.push(r.clone());
        r = rec("ok");
        r.files[0].sha256 = "nothex".into();
        cases.push(r);
        for bad in cases {
            let store = PinStore {
                schema: PINS_SCHEMA.into(),
                pins: vec![bad.clone()],
            };
            write_raw(&dir, &serde_json::to_vec(&store).unwrap());
            let err = load(&dir).unwrap_err();
            assert!(err.contains("invalid"), "{bad:?}: {err}");
        }
        let mut ok = rec("ok");
        ok.files.push(FileRecord {
            rel: ".env".into(),
            sha256: format!("hmac:{}", "b".repeat(64)),
        });
        let store = PinStore {
            schema: PINS_SCHEMA.into(),
            pins: vec![ok],
        };
        write_raw(&dir, &serde_json::to_vec(&store).unwrap());
        assert!(load(&dir).is_ok());
    }

    // M8: the key is created once, private, and reused.
    #[test]
    fn key_is_created_private_and_stable() {
        let home = tempfile::tempdir().unwrap();
        let dir = store_dir(home.path());
        let a = load_or_create_key(&dir).unwrap();
        let b = load_or_create_key(&dir).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; KEY_BYTES]);
        assert_eq!(std::fs::read(dir.join(KEY_FILE)).unwrap(), a);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o640))
                .unwrap();
            assert!(load_or_create_key(&dir).unwrap_err().contains("mode"));
            std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        std::fs::write(dir.join(KEY_FILE), b"short").unwrap();
        assert!(load_or_create_key(&dir).is_err());
        let other = tempfile::tempdir().unwrap();
        assert_ne!(load_or_create_key(&store_dir(other.path())).unwrap(), a);
    }

    #[test]
    fn upsert_replaces_same_key_only() {
        let mut store = PinStore::default();
        store.upsert(rec("a"));
        let mut other = rec("a");
        other.project = Some("~/p".into());
        store.upsert(other);
        let mut newer = rec("a");
        newer.hash = "sha256:11".into();
        store.upsert(newer);
        assert_eq!(store.pins.len(), 2);
        assert_eq!(store.find("a", None).unwrap().hash, "sha256:11");
    }

    #[test]
    fn diff_names_added_removed_modified() {
        let f = |r: &str, h: &str| FileRecord {
            rel: r.into(),
            sha256: h.into(),
        };
        let d = diff(&[f("a", "1"), f("b", "2")], &[f("a", "9"), f("c", "3")]);
        assert_eq!(d.modified, ["a"]);
        assert_eq!(d.added, ["c"]);
        assert_eq!(d.removed, ["b"]);
    }
}
