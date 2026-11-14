//! Validate and digest the private installed `node_modules` tree (D4).
//!
//! Call only after the install container has stopped, with no concurrent
//! writers to this private tree. No symlinks are followed, including the root.
//! Unix modes are normalized to directories 0755 / regular files 0644 after
//! validation. The root's location and original permissions are not hashed.
//!
//! Stable refusal tokens: `node_deps_symlink`, `node_deps_special_file`,
//! `node_deps_invalid_directory`, `node_deps_invalid_path` (non-UTF-8 or an
//! ambiguous separator), `node_deps_changed`, `node_deps_install_failed`
//! (I/O or permission failure), and `node_deps_too_large` (any resource cap).
//! D5 maps structural/I/O refusals to its install-failed receipt reason.
//!
//! Unlike the legacy JSON source digest, this version uses domain-tagged,
//! u64 big-endian length-prefixed fields, as required by D4. Entries use
//! sorted sibling traversal; relative UTF-8 paths use `/`. Empty directories,
//! entry kinds, normalized modes, lengths and content hashes are bound.

use std::fs::{self, Metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const FAIL: &str = "node_deps_install_failed";
const LARGE: &str = "node_deps_too_large";

#[derive(Clone, Copy)]
struct Limits {
    files: u32,
    bytes: u64,
    depth: usize,
    path: usize,
    entries: u32,
    path_bytes: usize,
}

pub(crate) const MAX_FILES: u32 = 60_000;
pub(crate) const MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_ENTRIES: u32 = 120_000;

const LIMITS: Limits = Limits {
    files: MAX_FILES,
    bytes: MAX_BYTES,
    depth: 128,
    path: 4096,
    // Bound empty-directory and directory-listing memory as well as files.
    entries: MAX_ENTRIES,
    path_bytes: 32 * 1024 * 1024,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DependencyDigest {
    pub sha256: String,
    pub files: u32,
    pub entries: u32,
    pub bytes: u64,
}

struct Walk {
    hash: Sha256,
    digest: DependencyDigest,
    path_bytes: usize,
    modes: Vec<(PathBuf, bool)>,
    limits: Limits,
    destination: Option<PathBuf>,
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn metadata(path: &Path) -> Result<Metadata, &'static str> {
    let meta = fs::symlink_metadata(path).map_err(|_| FAIL)?;
    let ty = meta.file_type();
    if ty.is_symlink() {
        return Err("node_deps_symlink");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ty.is_fifo() || ty.is_block_device() || ty.is_char_device() || ty.is_socket() {
            return Err("node_deps_special_file");
        }
    }
    if !ty.is_dir() && !ty.is_file() {
        return Err("node_deps_special_file");
    }
    Ok(meta)
}

impl Walk {
    fn directory(&mut self, root: &Path, dir: &Path) -> Result<(), &'static str> {
        if !metadata(dir)?.is_dir() {
            return Err("node_deps_invalid_directory");
        }
        // Do not collect an unbounded read_dir before checking the entry cap.
        let mut children = Vec::new();
        for child in fs::read_dir(dir).map_err(|_| FAIL)? {
            if children.len() >= (self.limits.entries - self.digest.entries) as usize {
                return Err(LARGE);
            }
            children.push(child.map_err(|_| FAIL)?.path());
        }
        children.sort();
        for path in children {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "node_deps_invalid_path")?;
            if relative.components().count() > self.limits.depth {
                return Err(LARGE);
            }
            let raw = relative.to_str().ok_or("node_deps_invalid_path")?;
            if !cfg!(windows) && raw.contains('\\') {
                return Err("node_deps_invalid_path");
            }
            let name = raw.replace('\\', "/");
            self.path_bytes = self.path_bytes.checked_add(name.len()).ok_or(LARGE)?;
            if name.len() > self.limits.path
                || self.path_bytes > self.limits.path_bytes
                || self.digest.entries >= self.limits.entries
            {
                return Err(LARGE);
            }
            let meta = metadata(&path)?;
            self.digest.entries += 1;
            field(&mut self.hash, b"entry");
            field(&mut self.hash, name.as_bytes());
            if meta.is_dir() {
                field(&mut self.hash, b"directory");
                field(&mut self.hash, &0o755u32.to_be_bytes());
                let normalized = match &self.destination {
                    Some(root) => {
                        let target = root.join(relative);
                        fs::create_dir(&target).map_err(|_| FAIL)?;
                        target
                    }
                    None => path.clone(),
                };
                self.modes.push((normalized, true));
                self.directory(root, &path)?;
            } else {
                if self.digest.files >= self.limits.files
                    || meta.len() > self.limits.bytes - self.digest.bytes
                {
                    return Err(LARGE);
                }
                let mut options = fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                }
                let mut file = options.open(&path).map_err(|_| FAIL)?;
                let opened = file.metadata().map_err(|_| FAIL)?;
                if !opened.is_file() || opened.len() != meta.len() {
                    return Err("node_deps_changed");
                }
                let mut content = Sha256::new();
                let normalized = self
                    .destination
                    .as_ref()
                    .map_or_else(|| path.clone(), |root| root.join(relative));
                let mut copied = if self.destination.is_some() {
                    Some(
                        fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&normalized)
                            .map_err(|_| FAIL)?,
                    )
                } else {
                    None
                };
                field(&mut content, b"vettalon-node-deps-file-v1");
                content.update(meta.len().to_be_bytes());
                let mut bytes = 0u64;
                let mut buffer = [0u8; 32 * 1024];
                loop {
                    let n = file.read(&mut buffer).map_err(|_| FAIL)?;
                    if n == 0 {
                        break;
                    }
                    bytes = bytes.checked_add(n as u64).ok_or(LARGE)?;
                    if bytes > self.limits.bytes - self.digest.bytes {
                        return Err(LARGE);
                    }
                    content.update(&buffer[..n]);
                    if let Some(copy) = &mut copied {
                        copy.write_all(&buffer[..n]).map_err(|_| FAIL)?;
                    }
                }
                if bytes != meta.len() {
                    return Err("node_deps_changed");
                }
                field(&mut self.hash, b"file");
                field(&mut self.hash, &0o644u32.to_be_bytes());
                field(&mut self.hash, &bytes.to_be_bytes());
                field(&mut self.hash, &content.finalize());
                self.digest.files += 1;
                self.digest.bytes += bytes;
                self.modes.push((normalized, false));
            }
        }
        Ok(())
    }
}

/// Validate the stopped install container's output, normalize modes, and bind
/// the dependency bytes. The returned digest is shared by all offline phases.
#[allow(dead_code)] // Consumed by D5 install and D8/D9 execution wiring.
pub(crate) fn digest(root: &Path) -> Result<DependencyDigest, &'static str> {
    digest_with_limits(root, LIMITS)
}

/// Import stopped uid-65534 install output without following links. Linux
/// hosts cannot chmod another uid's files: copying during the same bounded
/// walk gives the host ownership and binds precisely the bytes copied. The
/// destination must not exist and must have a private, host-owned parent.
pub(crate) fn copy_and_digest(
    root: &Path,
    destination: &Path,
) -> Result<DependencyDigest, &'static str> {
    fs::create_dir(destination).map_err(|_| FAIL)?;
    walk_and_digest(root, LIMITS, Some(destination))
}

fn digest_with_limits(root: &Path, limits: Limits) -> Result<DependencyDigest, &'static str> {
    walk_and_digest(root, limits, None)
}

fn walk_and_digest(
    root: &Path,
    limits: Limits,
    destination: Option<&Path>,
) -> Result<DependencyDigest, &'static str> {
    let mut walk = Walk {
        hash: Sha256::new(),
        digest: DependencyDigest {
            sha256: String::new(),
            files: 0,
            entries: 0,
            bytes: 0,
        },
        path_bytes: 0,
        modes: vec![(destination.unwrap_or(root).to_path_buf(), true)],
        limits,
        destination: destination.map(Path::to_path_buf),
    };
    field(&mut walk.hash, b"vettalon-node-deps-tree-v1");
    walk.directory(root, root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (path, directory) in &walk.modes {
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(if *directory { 0o755 } else { 0o644 }),
            )
            .map_err(|_| FAIL)?;
        }
    }
    walk.digest.sha256 = hex::encode(walk.hash.finalize());
    Ok(walk.digest)
}

#[cfg(test)]
#[path = "deps_tests.rs"]
mod tests;
