use super::*;

fn tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("pkg")).unwrap();
    fs::write(dir.path().join("pkg/index.js"), b"export default 1;\n").unwrap();
    dir
}

#[test]
fn deterministic_sorted_digest_binds_paths_bytes_and_empty_directories() {
    let a = tree();
    let b = tempfile::tempdir().unwrap();
    fs::write(a.path().join("z"), b"last").unwrap();
    fs::write(b.path().join("z"), b"last").unwrap();
    fs::create_dir(b.path().join("pkg")).unwrap();
    fs::write(b.path().join("pkg/index.js"), b"export default 1;\n").unwrap();
    let before = digest(a.path()).unwrap();
    assert_eq!(before, digest(b.path()).unwrap());
    assert_eq!((before.files, before.entries, before.bytes), (2, 3, 22));
    fs::create_dir(a.path().join("empty")).unwrap();
    assert_ne!(before.sha256, digest(a.path()).unwrap().sha256);
    fs::remove_dir(a.path().join("empty")).unwrap();
    fs::rename(a.path().join("z"), a.path().join("zz")).unwrap();
    assert_ne!(before.sha256, digest(a.path()).unwrap().sha256);
    fs::rename(a.path().join("zz"), a.path().join("z")).unwrap();
    fs::write(a.path().join("z"), b"LAST").unwrap();
    assert_ne!(before.sha256, digest(a.path()).unwrap().sha256);
}

#[test]
fn refuses_each_resource_cap_and_accepts_exact_limits() {
    let dir = tree();
    let exact = Limits {
        files: 1,
        bytes: 18,
        depth: 2,
        path: 12,
        entries: 2,
        path_bytes: 15,
    };
    assert!(digest_with_limits(dir.path(), exact).is_ok());
    for limits in [
        Limits { files: 0, ..exact },
        Limits { bytes: 17, ..exact },
        Limits { depth: 1, ..exact },
        Limits { path: 11, ..exact },
        Limits {
            entries: 1,
            ..exact
        },
        Limits {
            path_bytes: 14,
            ..exact
        },
    ] {
        assert_eq!(digest_with_limits(dir.path(), limits), Err(LARGE));
    }
    assert_eq!(LIMITS.files, 60_000);
    assert_eq!(LIMITS.bytes, 512 * 1024 * 1024);
    assert_eq!(LIMITS.depth, 128);
    assert_eq!(LIMITS.path, 4096);
}

#[test]
fn refuses_non_directory_root() {
    let dir = tree();
    assert_eq!(
        digest(&dir.path().join("pkg/index.js")),
        Err("node_deps_invalid_directory")
    );
    assert_eq!(digest(&dir.path().join("missing")), Err(FAIL));
}

#[test]
fn imported_copy_has_the_same_digest_and_outlives_install_output() {
    let source = tree();
    let destination = tempfile::tempdir().unwrap();
    let path = destination.path().join("node_modules");
    let imported = copy_and_digest(source.path(), &path).unwrap();
    assert_eq!(imported, digest(source.path()).unwrap());
    drop(source);
    assert_eq!(imported, digest(&path).unwrap());
    assert_eq!(copy_and_digest(&path, &path), Err(FAIL));
}

#[cfg(unix)]
#[test]
fn importing_does_not_chmod_source_and_refuses_links_and_caps() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let source = tree();
    let destination = tempfile::tempdir().unwrap();
    fs::set_permissions(source.path().join("pkg"), fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(
        source.path().join("pkg/index.js"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let path = destination.path().join("imported");
    copy_and_digest(source.path(), &path).unwrap();
    for (relative, original, normalized) in [("pkg", 0o777, 0o755), ("pkg/index.js", 0o755, 0o644)]
    {
        assert_eq!(
            fs::metadata(source.path().join(relative))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            original
        );
        assert_eq!(
            fs::metadata(path.join(relative))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            normalized
        );
    }
    symlink("/etc/passwd", source.path().join("escape")).unwrap();
    assert_eq!(
        copy_and_digest(source.path(), &destination.path().join("refused")),
        Err("node_deps_symlink")
    );
    fs::remove_file(source.path().join("escape")).unwrap();
    let capped = destination.path().join("capped");
    fs::create_dir(&capped).unwrap();
    assert_eq!(
        walk_and_digest(source.path(), Limits { bytes: 1, ..LIMITS }, Some(&capped)),
        Err(LARGE)
    );
}

#[cfg(unix)]
#[test]
fn refuses_symlinks_including_root_and_dangling_links() {
    use std::os::unix::fs::symlink;
    let dir = tree();
    let outside = tempfile::tempdir().unwrap();
    symlink(dir.path(), outside.path().join("root")).unwrap();
    assert_eq!(
        digest(&outside.path().join("root")),
        Err("node_deps_symlink")
    );
    for target in ["pkg/index.js", "pkg", "missing", "/etc/passwd"] {
        symlink(target, dir.path().join("link")).unwrap();
        assert_eq!(digest(dir.path()), Err("node_deps_symlink"));
        fs::remove_file(dir.path().join("link")).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn refuses_fifo_and_socket_without_opening_them() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fifo");
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: cpath is a valid, NUL-terminated path owned by this test.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert_eq!(digest(dir.path()), Err("node_deps_special_file"));
    fs::remove_file(path).unwrap();
    match UnixListener::bind(dir.path().join("socket")) {
        Ok(_listener) => assert_eq!(digest(dir.path()), Err("node_deps_special_file")),
        Err(error) => eprintln!("skipping socket assertion: {error}"),
    }
}

#[cfg(unix)]
#[test]
fn normalizes_modes_and_ignores_original_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tree();
    let before = digest(dir.path()).unwrap();
    fs::set_permissions(
        dir.path().join("pkg/index.js"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(dir.path().join("pkg"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(before, digest(dir.path()).unwrap());
    assert_eq!(
        fs::metadata(dir.path().join("pkg/index.js"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(dir.path().join("pkg"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn refuses_non_utf8_and_ambiguous_paths() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(std::ffi::OsString::from_vec(vec![0xff]));
    match fs::write(&path, b"") {
        Ok(()) => {
            assert_eq!(digest(dir.path()), Err("node_deps_invalid_path"));
            fs::remove_file(path).unwrap();
        }
        Err(error) => eprintln!("skipping non-UTF-8 filename assertion: {error}"),
    }
    fs::write(dir.path().join("a\\b"), b"").unwrap();
    assert_eq!(digest(dir.path()), Err("node_deps_invalid_path"));
}
