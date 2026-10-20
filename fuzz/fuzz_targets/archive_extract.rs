//! Safe extraction of a downloaded dependency archive (`hunt::fetch::extract`):
//! crates.io / npm / PyPI sdist `.tar.gz` and Go / wheel `.zip`. The archive
//! bytes come from a registry and are untrusted (tar-slip, zip-slip, links,
//! special files, decompression bombs).
//!
//! Input: one selector byte (even = tar.gz, odd = zip), then the archive.
//!
//! Invariants checked beyond "no panic", whether extraction succeeds or not:
//! - nothing is written next to the destination (a `..` escape would land
//!   in the scratch parent, which must hold only the destination);
//! - the destination holds no symlinks, and every entry resolves inside it;
//! - on success, the reported counts match what is on disk.

#![no_main]

use std::fs;
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use vettalon::hunt::fetch::{ArchiveKind, extract};

/// Walk `dir`; return (regular files, total bytes). Panics on a symlink or an
/// entry that resolves outside `root`.
fn walk(root: &Path, dir: &Path) -> (usize, u64) {
    let mut files = 0;
    let mut bytes = 0;
    for entry in fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).expect("symlink_metadata");
        assert!(
            !meta.file_type().is_symlink(),
            "extraction created a symlink: {}",
            path.display()
        );
        let real = fs::canonicalize(&path).expect("canonicalize");
        assert!(
            real.starts_with(root),
            "entry escapes the destination: {}",
            real.display()
        );
        if meta.is_dir() {
            let (f, b) = walk(root, &path);
            files += f;
            bytes += b;
        } else {
            assert!(meta.is_file(), "special file created: {}", path.display());
            files += 1;
            bytes += meta.len();
        }
    }
    (files, bytes)
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, archive)) = data.split_first() else {
        return;
    };
    let kind = if selector % 2 == 0 {
        ArchiveKind::TarGz
    } else {
        ArchiveKind::Zip
    };
    let scratch = tempfile::tempdir().expect("tempdir");
    let dest = scratch.path().join("out");
    fs::create_dir(&dest).expect("create dest");
    let result = extract(archive, kind, &dest);

    let siblings: Vec<_> = fs::read_dir(scratch.path())
        .expect("read scratch")
        .map(|e| e.expect("scratch entry").file_name())
        .collect();
    assert_eq!(
        siblings,
        ["out"],
        "extraction wrote outside the destination"
    );

    let root = fs::canonicalize(&dest).expect("canonicalize dest");
    let (files, bytes) = walk(&root, &root);
    if let Ok(stats) = result {
        // Duplicate member names overwrite one file, so disk can hold fewer.
        assert!(files <= stats.files, "{files} files on disk, {stats:?}");
        assert!(bytes <= stats.bytes, "{bytes} bytes on disk, {stats:?}");
    }
});
