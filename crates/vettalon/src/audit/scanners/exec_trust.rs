//! Executable trust for local attestation tools, shared by OpenSSL and cosign.
//! Executables and ancestors must be owned by root or the current uid; these
//! paths must not be group- or world-writable, except for root-owned sticky
//! ancestor directories. A sticky executable is never exempt. Tools must
//! remain outside cwd, receipt directories and their repositories. Ownership,
//! permissions and the executable's device/inode are rechecked before spawn.
//! Dynamic libraries are NOT checked. For example, `otool -L` on Homebrew's
//! OpenSSL 3.6.4 shows absolute libssl/libcrypto install names under
//! /opt/homebrew/Cellar/openssl@3/3.6.4/lib. Copying that executable to a private
//! directory still loads those libraries; their installation remains trusted.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct TrustedExecutable {
    path: String,
    excluded: Vec<PathBuf>,
    identity: (u64, u64),
}

impl TrustedExecutable {
    pub(crate) fn resolve(program: &str, excluded: &[&Path]) -> Result<Self, String> {
        if !Path::new(program).is_absolute() {
            return Err("attestation executable must have an absolute path".into());
        }
        let path = std::fs::canonicalize(program)
            .map_err(|e| format!("cannot resolve attestation executable: {e}"))?;
        let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
        let mut roots = Vec::new();
        for dir in std::iter::once(cwd.as_path()).chain(excluded.iter().copied()) {
            let dir = dir.canonicalize().map_err(|e| e.to_string())?;
            // A receipt may be below the repository root; sibling bin directories
            // are just as untrusted. A .git file also identifies a worktree.
            for ancestor in dir.ancestors() {
                if ancestor.join(".git").symlink_metadata().is_ok() {
                    roots.push(ancestor.to_path_buf());
                }
            }
            roots.push(dir);
        }
        let mut tool = Self {
            path: path.to_str().ok_or("executable path must be UTF-8")?.into(),
            excluded: roots,
            identity: (0, 0),
        };
        tool.identity = tool.check()?;
        Ok(tool)
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn recheck(&self) -> Result<(), String> {
        if self.check()? != self.identity {
            return Err("attestation executable identity changed since resolution".into());
        }
        Ok(())
    }

    fn check(&self) -> Result<(u64, u64), String> {
        let path = Path::new(&self.path);
        if path.canonicalize().map_err(|e| e.to_string())? != path {
            return Err("attestation executable canonical path changed".into());
        }
        let cwd = std::env::current_dir()
            .and_then(|dir| dir.canonicalize())
            .map_err(|e| e.to_string())?;
        if path.starts_with(cwd) || self.excluded.iter().any(|root| path.starts_with(root)) {
            return Err(
                "attestation executable is inside the working, receipt or repository directory"
                    .into(),
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no preconditions and does not modify memory.
            let uid = unsafe { libc::geteuid() };
            let file = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if !file.is_file() || file.mode() & 0o111 == 0 {
                return Err("attestation executable must be an executable regular file".into());
            }
            for entry in path.ancestors() {
                let meta = std::fs::symlink_metadata(entry).map_err(|e| e.to_string())?;
                if entry != path && !meta.is_dir() {
                    return Err("attestation executable ancestor is not a directory".into());
                }
                check_path_permissions(meta.uid(), meta.mode(), meta.is_dir(), uid)
                    .map_err(|reason| format!(
                        "{reason}: {} (mode {:04o}, uid {}); copy the tool into a directory only you can write, e.g. `install -d -m 0700 ~/.local/vettalon-tools && install -m 0500 \"$(command -v cosign)\" ~/.local/vettalon-tools/` (replace cosign with openssl for OpenSSL), then set VETTALON_COSIGN or VETTALON_OPENSSL to the copied tool's absolute path",
                        entry.display(), meta.mode() & 0o7777, meta.uid()
                    ))?;
            }
            Ok((file.dev(), file.ino()))
        }
        #[cfg(not(unix))]
        Err("attestation executable ownership and identity checks require Unix".into())
    }
}

#[cfg(unix)]
fn check_path_permissions(
    owner: u32,
    mode: u32,
    is_dir: bool,
    uid: u32,
) -> Result<(), &'static str> {
    if owner != 0 && owner != uid {
        return Err("untrusted owner of attestation executable path");
    }
    // Only root-owned sticky ancestors protect entries from other writers.
    // A sticky regular file cannot protect its contents.
    if !(is_dir && owner == 0 && mode & 0o1000 != 0) {
        if mode & 0o002 != 0 {
            return Err("world-writable attestation executable path");
        }
        if mode & 0o020 != 0 {
            return Err("group-writable attestation executable path");
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::check_path_permissions;

    #[test]
    fn pq_path_permissions_enforce_owner_and_write_policy() {
        let uid = 1000;
        for is_dir in [false, true] {
            for owner in [0, uid] {
                assert!(check_path_permissions(owner, 0o755, is_dir, uid).is_ok());
                assert!(check_path_permissions(owner, 0o775, is_dir, uid).is_err());
                assert!(check_path_permissions(owner, 0o1775, false, uid).is_err());
                assert!(check_path_permissions(owner, 0o777, is_dir, uid).is_err());
            }
            // Simulate foreign ownership without requiring chown privileges.
            for mode in [0o755, 0o775, 0o1777] {
                assert!(check_path_permissions(uid + 1, mode, is_dir, uid).is_err());
            }
        }
        assert!(check_path_permissions(uid, 0o1777, true, uid).is_err());
        assert!(check_path_permissions(uid, 0o1775, true, uid).is_err());
        assert!(check_path_permissions(0, 0o1777, true, uid).is_ok());
        assert!(check_path_permissions(0, 0o1775, true, uid).is_ok());
        assert!(check_path_permissions(0, 0o1777, false, uid).is_err());
        assert!(check_path_permissions(uid, 0o1777, false, uid).is_err());
    }
}
