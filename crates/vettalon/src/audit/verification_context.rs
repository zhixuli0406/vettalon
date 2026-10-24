//! Versioned context for historical target/fix verification receipts.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::schema::sha256_hex;

pub const CONTEXT_PREFIX: &str = "fix_context_v1:";
pub const POLICY_VERSION: &str = "vettalon-fix-check-v2";
pub const HARNESS_VERSION: &str = "vettalon-three-class-oracle-v1";
pub const SOURCE_SCOPE: &str = "prepared_tree_only";
const MAX_FILES: usize = 20_000;
const MAX_ENTRIES: usize = 40_000;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 8 * 1024;

/// The finding's pinned file identity. Missing hashes remain unknown.
#[derive(Clone, Copy)]
pub struct VerificationTarget<'a> {
    pub file: &'a str,
    pub file_hash: Option<&'a str>,
}

/// Deliberate exclusions while preparing a copied tree. Counts do not
/// reveal secret filenames and do not describe an atomic live snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotExclusions {
    pub git_directories: u64,
    pub symlinks: u64,
    pub secret_files: u64,
    pub special_files: u64,
}

/// Digest of the prepared tree's sorted directory/file entries, exact file
/// bytes and executable bits. Excluded source is outside this digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDigest {
    pub sha256: String,
    pub files: u32,
    pub entries: u32,
    pub bytes: u64,
}

#[derive(Serialize)]
struct Entry {
    path: String,
    kind: &'static str,
    executable: bool,
    size: u64,
    sha256: Option<String>,
}

fn file_digest(path: &Path, max_bytes: u64) -> Result<(String, u64), &'static str> {
    let before = std::fs::symlink_metadata(path).map_err(|_| "snapshot_read_failed")?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > max_bytes {
        return Err("snapshot_invalid_file");
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| "snapshot_read_failed")?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|_| "snapshot_read_failed")?;
        if n == 0 {
            break;
        }
        bytes = bytes.checked_add(n as u64).ok_or("snapshot_too_large")?;
        if bytes > max_bytes {
            return Err("snapshot_too_large");
        }
        hash.update(&buffer[..n]);
    }
    if bytes != before.len() {
        return Err("snapshot_changed");
    }
    Ok((hex::encode(hash.finalize()), bytes))
}

#[cfg(unix)]
fn executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn executable(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Hash an already prepared private copy. Refuses unexpected symlinks,
/// special files, unsupported path encoding and exceeded resource bounds.
/// It makes no claim about files excluded before the copy was prepared.
pub fn snapshot_digest(root: &Path) -> Result<SnapshotDigest, &'static str> {
    fn walk(
        root: &Path,
        dir: &Path,
        entries: &mut Vec<Entry>,
        bytes: &mut u64,
        files: &mut usize,
        path_bytes: &mut usize,
    ) -> Result<(), &'static str> {
        let meta = std::fs::symlink_metadata(dir).map_err(|_| "snapshot_read_failed")?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("snapshot_invalid_directory");
        }
        for item in std::fs::read_dir(dir).map_err(|_| "snapshot_read_failed")? {
            let item = item.map_err(|_| "snapshot_read_failed")?;
            let full = item.path();
            let relative = full
                .strip_prefix(root)
                .map_err(|_| "snapshot_invalid_path")?;
            if relative.components().count() > 128 {
                return Err("snapshot_too_deep");
            }
            let raw_path = relative.to_str().ok_or("snapshot_path_encoding")?;
            if !cfg!(windows) && raw_path.contains('\\') {
                return Err("snapshot_invalid_path");
            }
            let path = raw_path.replace('\\', "/");
            if path.len() > 4096 {
                return Err("snapshot_path_too_long");
            }
            *path_bytes = path_bytes
                .checked_add(path.len())
                .ok_or("snapshot_too_large")?;
            if *path_bytes > MAX_PATH_BYTES || entries.len() >= MAX_ENTRIES {
                return Err("snapshot_too_large");
            }
            let meta = std::fs::symlink_metadata(&full).map_err(|_| "snapshot_read_failed")?;
            if meta.file_type().is_symlink() {
                return Err("snapshot_symlink");
            }
            if meta.is_dir() {
                entries.push(Entry {
                    path,
                    kind: "directory",
                    executable: executable(&meta),
                    size: 0,
                    sha256: None,
                });
                walk(root, &full, entries, bytes, files, path_bytes)?;
            } else if meta.is_file() {
                *files += 1;
                if *files > MAX_FILES {
                    return Err("snapshot_too_large");
                }
                let (sha256, size) = file_digest(&full, MAX_BYTES.saturating_sub(*bytes))?;
                *bytes += size;
                entries.push(Entry {
                    path,
                    kind: "file",
                    executable: executable(&meta),
                    size,
                    sha256: Some(sha256),
                });
            } else {
                return Err("snapshot_special_file");
            }
        }
        Ok(())
    }
    let (mut entries, mut bytes, mut files, mut path_bytes) = (Vec::new(), 0, 0, 0);
    walk(
        root,
        root,
        &mut entries,
        &mut bytes,
        &mut files,
        &mut path_bytes,
    )?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let encoded = serde_json::to_vec(&entries).map_err(|_| "snapshot_encode_failed")?;
    let mut hash = Sha256::new();
    hash.update(b"vettalon-prepared-tree-v1\0");
    hash.update(encoded);
    Ok(SnapshotDigest {
        sha256: hex::encode(hash.finalize()),
        files: files as u32,
        entries: entries.len() as u32,
        bytes,
    })
}

pub fn source_file_digest(root: &Path, file: &str) -> Result<String, &'static str> {
    let path =
        crate::util::resolve_for_model(root, file).map_err(|_| "target_source_unavailable")?;
    file_digest(&path, 4 * 1024 * 1024).map(|(hash, _)| hash)
}

/// Execution context of a recorded snapshot, not an assertion that today's
/// live repository/configuration still matches it or trusted provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationContext {
    pub version: u32,
    pub source_scope: String,
    pub check_sha256: String,
    pub diff_sha256: String,
    pub target_file: String,
    pub target_file_sha256: String,
    pub finding_file_sha256: Option<String>,
    pub original: SnapshotDigest,
    pub fixed: SnapshotDigest,
    pub exclusions: SnapshotExclusions,
    pub adapter_sha256: String,
    pub fixed_adapter_sha256: String,
    /// Present only for a validated structured call, shared by both sides.
    pub target_plan_sha256: Option<String>,
    /// None explicitly means no project test command was configured.
    pub test_command_sha256: Option<String>,
    /// None is unknown, never sufficient for positive verification.
    pub image_identity: Option<String>,
    pub harness_sha256: String,
    pub harness_version: String,
    pub policy_version: String,
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl VerificationContext {
    pub fn identity_sha256(&self) -> String {
        // Only primitive/struct fields, so serialization is infallible.
        sha256_hex(&serde_json::to_vec(self).expect("verification context is serializable"))
    }

    pub fn matches(&self, expected: &Self) -> bool {
        self == expected
    }

    pub fn complete(&self) -> bool {
        self.valid()
            && self.finding_file_sha256.as_deref() == Some(self.target_file_sha256.as_str())
            && self.image_identity.is_some()
    }

    fn valid(&self) -> bool {
        let digest_ok = |d: &SnapshotDigest| {
            is_sha256(&d.sha256)
                && d.files <= MAX_FILES as u32
                && d.entries <= MAX_ENTRIES as u32
                && d.files <= d.entries
                && d.bytes <= MAX_BYTES
        };
        self.version == 1
            && self.source_scope == SOURCE_SCOPE
            && self.policy_version == POLICY_VERSION
            && self.harness_version == HARNESS_VERSION
            && self.target_file.len() <= 4096
            && vettalon_contract::safe_path::SafeRepoPath::parse(&self.target_file).is_ok()
            && [
                &self.check_sha256,
                &self.diff_sha256,
                &self.target_file_sha256,
                &self.adapter_sha256,
                &self.fixed_adapter_sha256,
                &self.harness_sha256,
            ]
            .iter()
            .all(|v| is_sha256(v))
            && self.target_plan_sha256.as_deref().is_none_or(is_sha256)
            && self.finding_file_sha256.as_deref().is_none_or(is_sha256)
            && self.test_command_sha256.as_deref().is_none_or(is_sha256)
            && self
                .image_identity
                .as_deref()
                .is_none_or(|v| v.strip_prefix("sha256:").is_some_and(is_sha256))
            && digest_ok(&self.original)
            && digest_ok(&self.fixed)
    }

    pub fn to_detail(&self) -> String {
        format!(
            "{CONTEXT_PREFIX} {}",
            serde_json::to_string(self).expect("verification context is serializable")
        )
    }

    pub fn parse(detail: &str) -> Option<Self> {
        if detail.len() > MAX_CONTEXT_BYTES {
            return None;
        }
        let raw = detail.strip_prefix(CONTEXT_PREFIX)?.strip_prefix(' ')?;
        let value: Self = vettalon_contract::strict_json::parse_strict(raw).ok()?;
        value.valid().then_some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_binding_snapshot_is_stable_and_covers_prepared_bytes() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("app.py"), "print(1)\n").unwrap();
        std::fs::write(source.path().join(".env"), "DO_NOT_COPY_SECRET").unwrap();
        std::fs::create_dir(source.path().join(".git")).unwrap();
        std::fs::write(source.path().join(".git/config"), "private git data").unwrap();
        let copy = crate::audit::fix_diff::snapshot(source.path()).unwrap();
        assert!(!copy.path.join(".env").exists());
        assert!(!copy.path.join(".git").exists());
        assert_eq!(copy.exclusions.secret_files, 1);
        assert_eq!(copy.exclusions.git_directories, 1);
        let before = snapshot_digest(&copy.path).unwrap();
        assert_eq!(before, snapshot_digest(&copy.path).unwrap());
        assert_eq!(before.files, 1);
        std::fs::write(source.path().join("app.py"), "print(2)\n").unwrap();
        assert_eq!(before, snapshot_digest(&copy.path).unwrap());
        std::fs::write(copy.path.join("app.py"), "print(3)\n").unwrap();
        assert_ne!(before.sha256, snapshot_digest(&copy.path).unwrap().sha256);
    }

    #[test]
    fn verification_binding_snapshot_includes_empty_directories_and_rejects_symlinks() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("app.py"), "x\n").unwrap();
        let before = snapshot_digest(source.path()).unwrap();
        std::fs::create_dir(source.path().join("empty")).unwrap();
        assert_ne!(
            before.sha256,
            snapshot_digest(source.path()).unwrap().sha256
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("app.py", source.path().join("alias.py")).unwrap();
            assert!(snapshot_digest(source.path()).is_err());
        }
    }

    #[test]
    fn verification_binding_target_hash_refuses_unsafe_and_secret_paths() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("app.py"), "x\n").unwrap();
        std::fs::write(source.path().join(".env"), "secret").unwrap();
        assert_eq!(
            source_file_digest(source.path(), "app.py").unwrap(),
            crate::audit::schema::sha256_hex(b"x\n")
        );
        for path in ["../outside.py", "/etc/passwd", ".env"] {
            assert!(source_file_digest(source.path(), path).is_err());
        }
    }
}
