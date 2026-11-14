use super::*;
use serde_json::json;

use super::LockfileReason as R;

fn integrity() -> String {
    format!("sha512-{}==", "A".repeat(86))
}

fn tarball(name: &str, version: &str) -> String {
    let unscoped = name.rsplit('/').next().unwrap();
    format!("{REGISTRY}{name}/-/{unscoped}-{version}.tgz")
}

fn entry(name: &str, version: &str) -> Value {
    json!({
        "version": version,
        "resolved": tarball(name, version),
        "integrity": integrity(),
        "license": "MIT",
    })
}

fn base_packages() -> Map<String, Value> {
    let mut p = Map::new();
    p.insert(
        String::new(),
        json!({
            "name": "app",
            "version": "1.0.0",
            "dependencies": {"left-pad": "^1.3.0", "@types/node": "^20.0.0", "a": "~1.0.0"},
            "devDependencies": {"JSONStream": "1.x || 2.x"},
        }),
    );
    p.insert("node_modules/left-pad".into(), entry("left-pad", "1.3.0"));
    p.insert(
        "node_modules/@types/node".into(),
        entry("@types/node", "20.1.0"),
    );
    p.insert("node_modules/a".into(), entry("a", "1.0.0"));
    p.insert(
        "node_modules/a/node_modules/b".into(),
        entry("b", "2.0.0-beta.1+build.5"),
    );
    p.insert(
        "node_modules/JSONStream".into(),
        entry("JSONStream", "1.3.5"),
    );
    p
}

fn lock_with_version(version: Value, packages: Map<String, Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": version,
        "requires": true,
        "packages": packages,
    }))
    .unwrap()
}

fn lock(packages: Map<String, Value>) -> Vec<u8> {
    lock_with_version(json!(3), packages)
}

fn reason(bytes: &[u8]) -> LockfileReason {
    let err = validate_lockfile(bytes).unwrap_err();
    assert_eq!(err.input, InstallInput::Lockfile);
    assert_eq!(err.blocker(), "node_lockfile_refused");
    err.reason
}

/// The base lockfile with `node_modules/left-pad` edited by `f`.
fn with_left_pad(f: impl FnOnce(&mut Map<String, Value>)) -> Vec<u8> {
    let mut p = base_packages();
    f(p.get_mut("node_modules/left-pad")
        .unwrap()
        .as_object_mut()
        .unwrap());
    lock(p)
}

fn manifest_reason(v: Value) -> LockfileReason {
    let err = validate_package_json(&serde_json::to_vec(&v).unwrap()).unwrap_err();
    assert_eq!(err.input, InstallInput::PackageJson);
    err.reason
}

// ---------------------------------------------------------------- accept

#[test]
fn accepts_registry_lockfile_v3() {
    let bytes = lock(base_packages());
    let s = validate_lockfile(&bytes).unwrap();
    assert_eq!(s.lockfile_version, 3);
    assert!(s.needs_install());
    assert_eq!(s.lockfile_sha256, crate::audit::schema::sha256_hex(&bytes));
    assert_eq!(s.packages_sha256.len(), 64);
    let paths: Vec<&str> = s.packages.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "node_modules/@types/node",
            "node_modules/JSONStream",
            "node_modules/a",
            "node_modules/a/node_modules/b",
            "node_modules/left-pad",
        ]
    );
    let b = &s.packages[3];
    assert_eq!(b.name, "b");
    assert_eq!(b.version, "2.0.0-beta.1+build.5");
    assert_eq!(b.integrity, integrity());
    assert_eq!(s.packages[0].name, "@types/node");
}

#[test]
fn accepts_v2_with_clean_legacy_section() {
    let doc = json!({
        "lockfileVersion": 2,
        "packages": base_packages(),
        "dependencies": {
            "left-pad": {"version": "1.3.0", "resolved": tarball("left-pad", "1.3.0"), "integrity": integrity()},
            "a": {"version": "1.0.0", "resolved": tarball("a", "1.0.0"), "integrity": integrity(), "requires": {"b": "^2.0.0-beta"}, "dependencies": {"b": entry("b", "2.0.0-beta.1+build.5")}},
        },
    });
    let s = validate_lockfile(&serde_json::to_vec(&doc).unwrap()).unwrap();
    assert_eq!(s.lockfile_version, 2);
}

#[test]
fn install_scripts_flag_is_accepted_because_scripts_never_run() {
    let bytes = with_left_pad(|e| {
        e.insert("hasInstallScript".into(), json!(true));
        e.insert("dev".into(), json!(true));
        e.insert("optional".into(), json!(false));
        e.insert("engines".into(), json!({"node": ">=18"}));
    });
    assert!(validate_lockfile(&bytes).is_ok());
}

#[test]
fn project_without_dependencies_skips_install() {
    let mut p = Map::new();
    p.insert(String::new(), json!({"name": "app", "version": "1.0.0"}));
    let s = validate_lockfile(&lock(p)).unwrap();
    assert!(!s.needs_install());
    assert!(s.packages.is_empty());
}

#[test]
fn summary_is_independent_of_layout_but_bound_to_content() {
    let compact = lock(base_packages());
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&compact).unwrap()).unwrap();
    let a = validate_lockfile(&compact).unwrap();
    let b = validate_lockfile(&pretty).unwrap();
    assert_eq!(a.packages, b.packages);
    assert_eq!(a.packages_sha256, b.packages_sha256);
    assert_ne!(a.lockfile_sha256, b.lockfile_sha256);

    // Key order in the source does not matter.
    let x = entry("x", "1.0.0").to_string();
    let y = entry("y", "1.0.0").to_string();
    let xy = format!(
        r#"{{"lockfileVersion":3,"packages":{{"node_modules/x":{x},"node_modules/y":{y}}}}}"#
    );
    let yx = format!(
        r#"{{"packages":{{"node_modules/y":{y},"node_modules/x":{x}}},"lockfileVersion":3}}"#
    );
    let sxy = validate_lockfile(xy.as_bytes()).unwrap();
    let syx = validate_lockfile(yx.as_bytes()).unwrap();
    assert_eq!(sxy.packages, syx.packages);
    assert_eq!(sxy.packages_sha256, syx.packages_sha256);

    // Any bound field changes the digest.
    let other_integrity = with_left_pad(|e| {
        e.insert(
            "integrity".into(),
            json!(format!("sha512-{}A==", "B".repeat(85))),
        );
    });
    assert_ne!(
        validate_lockfile(&other_integrity).unwrap().packages_sha256,
        a.packages_sha256
    );
    let v2 = lock_with_version(json!(2), base_packages());
    assert_ne!(
        validate_lockfile(&v2).unwrap().packages_sha256,
        a.packages_sha256
    );
}

#[test]
fn install_inputs_check_both_files() {
    let manifest = serde_json::to_vec(&json!({
        "name": "app",
        "dependencies": {"left-pad": "^1.3.0"},
        "overrides": {"a": {"b": "2.0.0-beta.1", ".": "1.0.0"}, "left-pad": "$left-pad"},
        "scripts": {"postinstall": "node evil.js"},
    }))
    .unwrap();
    let s = validate_install_inputs(&manifest, &lock(base_packages())).unwrap();
    assert_eq!(s.packages.len(), 5);

    let bad = serde_json::to_vec(&json!({"workspaces": ["packages/*"]})).unwrap();
    let err = validate_install_inputs(&bad, &lock(base_packages())).unwrap_err();
    assert_eq!(err.input, InstallInput::PackageJson);
    assert_eq!(err.reason, R::Workspace);
}

// ---------------------------------------------------------------- refused forms

#[test]
fn resolved_forms_are_refused() {
    let canonical = tarball("left-pad", "1.3.0");
    let cases: Vec<(String, LockfileReason)> = vec![
        ("git+ssh://git@github.com/x/left-pad.git#abc".into(), R::Git),
        ("git://github.com/x/left-pad.git".into(), R::Git),
        ("git@github.com:x/left-pad.git".into(), R::Git),
        ("ssh://git@github.com/x/left-pad.git".into(), R::Git),
        ("github:x/left-pad".into(), R::Git),
        ("GIT+https://github.com/x/left-pad.git".into(), R::Git),
        ("file:../left-pad-1.3.0.tgz".into(), R::File),
        ("../left-pad".into(), R::File),
        ("/abs/left-pad".into(), R::File),
        ("link:../left-pad".into(), R::Link),
        ("npm:other@1.0.0".into(), R::Alias),
        ("workspace:*".into(), R::Workspace),
        (
            "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into(),
            R::Http,
        ),
        (
            "https://evil.example/left-pad-1.3.0.tgz".into(),
            R::RemoteUrl,
        ),
        (
            "https://registry.npmjs.org.evil.example/left-pad/-/left-pad-1.3.0.tgz".into(),
            R::RemoteUrl,
        ),
        (
            "https://user:secret@registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into(),
            R::RemoteUrl,
        ),
        (
            "https://169.254.169.254/latest/meta-data/".into(),
            R::RemoteUrl,
        ),
        ("https://127.0.0.1:4873/left-pad".into(), R::RemoteUrl),
        (
            "HTTPS://REGISTRY.NPMJS.ORG/left-pad/-/left-pad-1.3.0.tgz".into(),
            R::RemoteUrl,
        ),
        (
            "https://registry.npmjs.org:443/left-pad/-/left-pad-1.3.0.tgz".into(),
            R::RemoteUrl,
        ),
        (String::new(), R::RemoteUrl),
        ("left-pad-1.3.0.tgz".into(), R::RemoteUrl),
        (tarball("left-pad", "9.9.9"), R::ResolvedMismatch),
        (tarball("other", "1.3.0"), R::ResolvedMismatch),
        (format!("{canonical}?x=1"), R::ResolvedMismatch),
        (format!("{canonical}#frag"), R::ResolvedMismatch),
        (
            format!("{REGISTRY}left-pad/-/../../evil/-/left-pad-1.3.0.tgz"),
            R::ResolvedMismatch,
        ),
        (format!("{REGISTRY}left-pad"), R::ResolvedMismatch),
    ];
    for (resolved, want) in cases {
        let bytes = with_left_pad(|e| {
            e.insert("resolved".into(), json!(resolved));
        });
        assert_eq!(reason(&bytes), want, "resolved = {resolved:?}");
    }
}

#[test]
fn refusal_detail_names_the_entry_not_the_url() {
    let bytes = with_left_pad(|e| {
        e.insert(
            "resolved".into(),
            json!("https://user:hunter2@internal.example/x.tgz"),
        );
    });
    let err = validate_lockfile(&bytes).unwrap_err();
    assert!(
        err.detail.contains("node_modules/left-pad"),
        "{}",
        err.detail
    );
    assert!(!err.detail.contains("hunter2"));
    assert!(!err.detail.contains("internal.example"));
    let shown = err.to_string();
    assert!(shown.starts_with("node_lockfile_refused: lockfile: remote_url"));
    assert!(!shown.contains("hunter2"));
}

#[test]
fn link_alias_bundle_and_shrinkwrap_entries_are_refused() {
    let link = with_left_pad(|e| {
        e.clear();
        e.insert("resolved".into(), json!("packages/left-pad"));
        e.insert("link".into(), json!(true));
    });
    assert_eq!(reason(&link), R::Link);

    let alias = with_left_pad(|e| {
        e.insert("name".into(), json!("other"));
    });
    assert_eq!(reason(&alias), R::Alias);
    let same_name = with_left_pad(|e| {
        e.insert("name".into(), json!("left-pad"));
    });
    assert!(validate_lockfile(&same_name).is_ok());

    let bundled = with_left_pad(|e| {
        e.insert("inBundle".into(), json!(true));
    });
    assert_eq!(reason(&bundled), R::Bundled);

    let shrinkwrap = with_left_pad(|e| {
        e.insert("hasShrinkwrap".into(), json!(true));
    });
    assert_eq!(reason(&shrinkwrap), R::Shrinkwrap);
}

#[test]
fn workspace_forms_are_refused() {
    let mut p = base_packages();
    p.insert("packages/member".into(), json!({"version": "1.0.0"}));
    assert_eq!(reason(&lock(p)), R::Workspace);

    let mut p = base_packages();
    p.get_mut("")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("workspaces".into(), json!(["packages/*"]));
    assert_eq!(reason(&lock(p)), R::Workspace);

    assert_eq!(
        manifest_reason(json!({"workspaces": {"packages": ["a"]}})),
        R::Workspace
    );
}

#[test]
fn missing_and_malformed_integrity_is_refused() {
    let missing = with_left_pad(|e| {
        e.remove("integrity");
    });
    assert_eq!(reason(&missing), R::IntegrityMissing);
    let no_resolved = with_left_pad(|e| {
        e.remove("resolved");
    });
    assert_eq!(reason(&no_resolved), R::ResolvedMissing);

    for bad in [
        "sha1-abc".to_string(),
        format!("sha256-{}=", "A".repeat(43)),
        format!("{} sha1-xyz", integrity()),
        format!("sha1-xyz {}", integrity()),
        format!("sha512-{}=", "A".repeat(87)),
        format!("sha512-{}", "A".repeat(88)),
        format!("sha512-{}==", "*".repeat(86)),
        format!("sha512-{}é==", "A".repeat(84)),
        format!("SHA512-{}==", "A".repeat(86)),
        format!(" sha512-{}==", "A".repeat(86)),
        String::new(),
    ] {
        let bytes = with_left_pad(|e| {
            e.insert("integrity".into(), json!(bad));
        });
        assert_eq!(reason(&bytes), R::Integrity, "integrity = {bad:?}");
    }
}

#[test]
fn wrong_field_types_are_refused() {
    for (field, value) in [
        ("resolved", json!(1)),
        ("integrity", json!(null)),
        ("version", json!(1.3)),
        ("link", json!("yes")),
        ("inBundle", json!(1)),
        ("name", json!(["left-pad"])),
        ("dependencies", json!(["x"])),
    ] {
        let bytes = with_left_pad(|e| {
            e.insert(field.into(), value.clone());
        });
        assert_eq!(reason(&bytes), R::FieldType, "{field} = {value}");
    }
    let dep_number = with_left_pad(|e| {
        e.insert("dependencies".into(), json!({"x": 1}));
    });
    assert_eq!(reason(&dep_number), R::FieldType);

    let mut p = base_packages();
    p.insert("node_modules/left-pad".into(), json!("1.3.0"));
    assert_eq!(reason(&lock(p)), R::FieldType);

    let bytes = br#"{"lockfileVersion":3,"packages":[]}"#;
    assert_eq!(reason(bytes), R::FieldType);
    let bytes = br#"{"lockfileVersion":3}"#;
    assert_eq!(reason(bytes), R::PackagesMissing);
}

#[test]
fn lockfile_version_must_be_2_or_3() {
    for v in [
        json!(1),
        json!(4),
        json!(0),
        json!(-3),
        json!("3"),
        json!(3.0),
        json!(3.5),
        json!(null),
        json!(18446744073709551615u64),
    ] {
        assert_eq!(
            reason(&lock_with_version(v.clone(), base_packages())),
            R::LockfileVersion,
            "lockfileVersion = {v}"
        );
    }
    assert_eq!(reason(br#"{"packages":{}}"#), R::LockfileVersion);
}

#[test]
fn entry_versions_are_strict_semver() {
    for bad in [
        "1.0",
        "v1.3.0",
        "1.3.0-",
        "1.3.0+",
        "01.x.0",
        "1.3.0 ",
        "",
        "1.3.0.0",
        "1.3.0-a b",
    ] {
        let bytes = with_left_pad(|e| {
            e.insert("version".into(), json!(bad));
        });
        assert_eq!(reason(&bytes), R::Version, "version = {bad:?}");
    }
    let missing = with_left_pad(|e| {
        e.remove("version");
    });
    assert_eq!(reason(&missing), R::Version);
    assert_eq!(check_version(&"1".repeat(300)), Err(R::Version));
    assert_eq!(check_version("git+ssh://git@x/y.git"), Err(R::Git));
    assert_eq!(check_version("npm:other@1.0.0"), Err(R::Alias));
    assert_eq!(check_version("file:../x"), Err(R::File));
    assert_eq!(check_version("1.2.3-rc.1+sha.abc"), Ok(()));
    assert_eq!(check_version("0.0.0"), Ok(()));
}

#[test]
fn dependency_specs_are_plain_ranges_or_tags() {
    for ok in [
        "^1.2.3",
        "~1.2.3",
        ">=1 <2",
        "1.x || 2.x",
        "*",
        "",
        "latest",
        "next",
        "1.2.3 - 2.3.4",
        "=1.0.0",
        "X",
    ] {
        assert_eq!(check_spec(ok), Ok(()), "spec = {ok:?}");
    }
    let long = "1".repeat(SPEC_MAX + 1);
    for (bad, want) in [
        ("git+https://github.com/a/b.git", R::Git),
        ("github:a/b", R::Git),
        ("gitlab:a/b", R::Git),
        ("bitbucket:a/b", R::Git),
        ("gist:abc", R::Git),
        ("a/b", R::Git),
        ("a/b#main", R::Git),
        ("file:../x", R::File),
        ("./x", R::File),
        ("../x", R::File),
        ("/abs/x", R::File),
        ("~/x", R::File),
        ("link:../x", R::Link),
        ("npm:other@1", R::Alias),
        ("NPM:other@1", R::Alias),
        ("workspace:*", R::Workspace),
        ("http://x/y.tgz", R::Http),
        ("https://x/y.tgz", R::RemoteUrl),
        ("  https://x/y.tgz", R::RemoteUrl),
        ("1.0.0 || $(id)", R::Spec),
        ("^1;rm -rf", R::Spec),
        ("1.0.0\n", R::Spec),
        ("c:\\x", R::Spec),
        ("1#x", R::Spec),
        (long.as_str(), R::Spec),
    ] {
        assert_eq!(check_spec(bad), Err(want), "spec = {bad:?}");
    }
}

#[test]
fn specs_are_checked_in_manifest_root_entry_and_entries() {
    assert_eq!(
        manifest_reason(json!({"dependencies": {"x": "git+ssh://git@github.com/a/x.git"}})),
        R::Git
    );
    assert_eq!(
        manifest_reason(json!({"devDependencies": {"x": "file:../x"}})),
        R::File
    );
    assert_eq!(
        manifest_reason(json!({"optionalDependencies": {"x": "https://e.example/x.tgz"}})),
        R::RemoteUrl
    );
    assert_eq!(
        manifest_reason(json!({"peerDependencies": {"x": "npm:y@1"}})),
        R::Alias
    );
    assert_eq!(
        manifest_reason(json!({"dependencies": {"../evil": "1.0.0"}})),
        R::Name
    );
    assert_eq!(
        manifest_reason(json!({"dependencies": ["x"]})),
        R::FieldType
    );
    assert_eq!(
        manifest_reason(json!({"overrides": {"a": {"b": "npm:evil@1"}}})),
        R::Alias
    );
    assert_eq!(
        manifest_reason(json!({"overrides": {"a": "$../x"}})),
        R::Name
    );
    assert_eq!(
        manifest_reason(json!({"overrides": {"a": 1}})),
        R::FieldType
    );
    assert_eq!(manifest_reason(json!(["x"])), R::NotObject);

    let mut p = base_packages();
    p.get_mut("")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("dependencies".into(), json!({"x": "link:../x"}));
    assert_eq!(reason(&lock(p)), R::Link);

    let bytes = with_left_pad(|e| {
        e.insert("dependencies".into(), json!({"y": "github:a/y"}));
    });
    assert_eq!(reason(&bytes), R::Git);
}

#[test]
fn legacy_section_cannot_smuggle_remote_sources() {
    let doc = |dependencies: Value| {
        serde_json::to_vec(&json!({
            "lockfileVersion": 2,
            "packages": base_packages(),
            "dependencies": dependencies,
        }))
        .unwrap()
    };
    assert_eq!(
        reason(&doc(
            json!({"a": {"version": "1.0.0", "resolved": tarball("a", "1.0.0"), "integrity": integrity(), "dependencies": {"b": {"version": "git+ssh://git@github.com/x/b.git"}}}})
        )),
        R::Git
    );
    assert_eq!(
        reason(&doc(
            json!({"left-pad": {"version": "1.3.0", "resolved": "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}})
        )),
        R::Http
    );
    assert_eq!(
        reason(&doc(
            json!({"left-pad": {"version": "1.3.0", "resolved": "https://10.0.0.1/x.tgz"}})
        )),
        R::RemoteUrl
    );
    assert_eq!(
        reason(&doc(
            json!({"left-pad": {"version": "1.3.0", "bundled": true}})
        )),
        R::Bundled
    );
    assert_eq!(
        reason(&doc(json!({"left-pad": {"version": "npm:left-pad@1.3.0"}}))),
        R::Alias
    );
    assert_eq!(reason(&doc(json!({"a": 1}))), R::FieldType);
    assert_eq!(reason(&doc(json!(["x"]))), R::FieldType);
}

// ---------------------------------------------------------------- names and paths

#[test]
fn package_paths_must_be_node_modules_chains() {
    for (path, want) in [
        ("node_modules/a/b", R::PackagePath),
        ("node_modules/@scope", R::PackagePath),
        ("node_modules/a/node_modules", R::PackagePath),
        ("node_modules/a/node_modules/", R::Name),
        ("node_modules/", R::Name),
        ("node_modules//a", R::Name),
        ("node_modules/../etc", R::Name),
        ("node_modules/.bin", R::Name),
        ("node_modules/_hidden", R::Name),
        ("node_modules/a\\b", R::Name),
        ("node_modules/a b", R::Name),
        ("node_modules/node_modules", R::Name),
        ("node_modules/@/a", R::Name),
        ("node_modules/@scope/", R::Name),
        ("node_modules/é", R::Name),
        ("lib/node_modules/a", R::Workspace),
        ("../node_modules/a", R::Workspace),
    ] {
        let mut p = base_packages();
        p.insert(path.into(), entry("a", "1.0.0"));
        assert_eq!(reason(&lock(p)), want, "path = {path:?}");
    }
    let mut p = base_packages();
    p.insert(
        format!("node_modules/{}", "a".repeat(PACKAGE_PATH_MAX)),
        entry("a", "1.0.0"),
    );
    assert_eq!(reason(&lock(p)), R::PackagePath);
}

#[test]
fn name_charset_and_length_caps() {
    let max = "a".repeat(PACKAGE_NAME_MAX);
    let mut p = base_packages();
    p.insert(format!("node_modules/{max}"), entry(&max, "1.0.0"));
    assert!(validate_lockfile(&lock(p)).is_ok());

    let over = "a".repeat(PACKAGE_NAME_MAX + 1);
    let mut p = base_packages();
    p.insert(format!("node_modules/{over}"), entry(&over, "1.0.0"));
    assert_eq!(reason(&lock(p)), R::Name);

    let scope_over = format!("@s/{}", "a".repeat(PACKAGE_NAME_MAX - 2));
    assert_eq!(check_name(&scope_over), Err(R::Name));
    assert_eq!(check_name(&scope_over[..PACKAGE_NAME_MAX]), Ok(()));
    for ok in [
        "a",
        "a.b",
        "a-b",
        "a_b",
        "a~b",
        "JSONStream",
        "@s/a",
        "@types/node",
        "0x",
    ] {
        assert_eq!(check_name(ok), Ok(()), "{ok}");
    }
    for bad in [
        "", ".a", "_a", "@s", "@s/", "@/a", "@.s/a", "@s/.a", "a/b", "a@1", "a!", "a'", "a(b)",
        "a*", "a%2f",
    ] {
        assert_eq!(check_name(bad), Err(R::Name), "{bad}");
    }
}

#[test]
fn nesting_is_capped() {
    let deep = |levels: usize| {
        let mut s = "node_modules/a".to_string();
        for _ in 1..levels {
            s.push_str("/node_modules/a");
        }
        s
    };
    let mut p = base_packages();
    p.insert(deep(MAX_NESTING), entry("a", "1.0.0"));
    assert!(validate_lockfile(&lock(p)).is_ok());

    let mut p = base_packages();
    p.insert(deep(MAX_NESTING + 1), entry("a", "1.0.0"));
    assert_eq!(reason(&lock(p)), R::NestingTooDeep);
}

// ---------------------------------------------------------------- caps

#[test]
fn package_count_is_capped() {
    let mut p = Map::new();
    for i in 0..=MAX_PACKAGES {
        p.insert(format!("node_modules/p{i}"), json!({}));
    }
    assert_eq!(reason(&lock(p)), R::TooManyPackages);

    // Exactly the cap passes the count check (then fails on content).
    let mut p = Map::new();
    p.insert(String::new(), json!({}));
    for i in 0..MAX_PACKAGES {
        p.insert(format!("node_modules/p{i}"), json!({}));
    }
    assert_eq!(reason(&lock(p)), R::ResolvedMissing);
}

#[test]
fn byte_caps() {
    let mut big = lock(base_packages());
    big.resize(LOCKFILE_MAX_BYTES + 1, b' ');
    assert_eq!(reason(&big), R::TooLarge);

    let mut manifest = b"{}".to_vec();
    manifest.resize(PACKAGE_JSON_MAX_BYTES, b' ');
    assert!(validate_package_json(&manifest).is_ok());
    manifest.push(b' ');
    let err = validate_package_json(&manifest).unwrap_err();
    assert_eq!(err.reason, R::TooLarge);
}

#[test]
fn depth_cap_is_enforced_before_parsing() {
    let nested = |n: usize| {
        format!(
            r#"{{"lockfileVersion":3,"packages":{{}},"x":{}{}}}"#,
            "[".repeat(n),
            "]".repeat(n)
        )
    };
    assert!(validate_lockfile(nested(JSON_MAX_DEPTH - 1).as_bytes()).is_ok());
    assert_eq!(reason(nested(JSON_MAX_DEPTH).as_bytes()), R::TooDeep);
    // Far beyond serde_json's own recursion limit, and unbalanced.
    let bomb = "[".repeat(1_000_000);
    assert_eq!(reason(bomb.as_bytes()), R::TooDeep);
    let obj_bomb = r#"{"a":"#.repeat(10_000);
    assert_eq!(reason(obj_bomb.as_bytes()), R::TooDeep);
}

// ---------------------------------------------------------------- malformed input

#[test]
fn duplicate_keys_are_refused() {
    let e = entry("left-pad", "1.3.0").to_string();
    let dup_path = format!(
        r#"{{"lockfileVersion":3,"packages":{{"node_modules/left-pad":{e},"node_modules/left-pad":{e}}}}}"#
    );
    assert_eq!(reason(dup_path.as_bytes()), R::DuplicateKey);

    // serde_json alone would keep the second, registry `resolved`.
    let i = integrity();
    let dup_field = format!(
        r#"{{"lockfileVersion":3,"packages":{{"node_modules/left-pad":{{"version":"1.3.0","resolved":"https://evil.example/x.tgz","resolved":"{}","integrity":"{i}"}}}}}}"#,
        tarball("left-pad", "1.3.0")
    );
    assert_eq!(reason(dup_field.as_bytes()), R::DuplicateKey);

    let dup_top = r#"{"lockfileVersion":1,"lockfileVersion":3,"packages":{}}"#;
    assert_eq!(reason(dup_top.as_bytes()), R::DuplicateKey);
}

#[test]
fn malformed_inputs_are_refused() {
    for (text, want) in [
        ("", R::MalformedJson),
        ("   ", R::MalformedJson),
        ("{", R::MalformedJson),
        (r#"{"lockfileVersion":3,"packages":{}"#, R::MalformedJson),
        (r#"{"lockfileVersion":3,"packages":{}}{}"#, R::MalformedJson),
        (r#"{"lockfileVersion":3,"packages":{},}"#, R::MalformedJson),
        (
            r#"{"lockfileVersion":3,/*c*/"packages":{}}"#,
            R::MalformedJson,
        ),
        ("{'lockfileVersion':3}", R::MalformedJson),
        (r#"{"lockfileVersion":NaN,"packages":{}}"#, R::MalformedJson),
        (
            r#"{"lockfileVersion":1e400,"packages":{}}"#,
            R::MalformedJson,
        ),
        (
            "\u{feff}{\"lockfileVersion\":3,\"packages\":{}}",
            R::MalformedJson,
        ),
        (r#"{"a":"\ud800"}"#, R::MalformedJson),
        (
            "{\"lockfileVersion\":3,\"packages\":{}}\u{0}",
            R::MalformedJson,
        ),
        ("null", R::NotObject),
        ("[]", R::NotObject),
        ("\"x\"", R::NotObject),
        ("0", R::NotObject),
    ] {
        assert_eq!(reason(text.as_bytes()), want, "input = {text:?}");
    }
    let not_utf8: [&[u8]; 3] = [
        b"{\"lockfileVersion\":3,\"packages\":{\"\xff\":{}}}",
        b"\xff\xfe{\x00}\x00",
        b"{\"lockfileVersion\":3,\"packages\":{}}\xc3",
    ];
    for bytes in not_utf8 {
        assert_eq!(reason(bytes), R::NotUtf8);
    }
    // Huge integers are numbers, just not 2 or 3.
    let huge = format!(
        r#"{{"lockfileVersion":{},"packages":{{}}}}"#,
        "9".repeat(5000)
    );
    assert!(matches!(
        reason(huge.as_bytes()),
        R::LockfileVersion | R::MalformedJson
    ));
}

#[test]
fn every_truncation_is_an_error() {
    let valid = lock(base_packages());
    assert!(validate_lockfile(&valid).is_ok());
    for n in 0..valid.len() {
        assert!(validate_lockfile(&valid[..n]).is_err(), "prefix {n}");
    }
}

#[test]
fn random_mutations_never_panic() {
    let valid = lock(base_packages());
    let manifest = serde_json::to_vec(&json!({"dependencies": {"left-pad": "^1.3.0"}})).unwrap();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as usize
    };
    for _ in 0..3000 {
        let mut m = valid.clone();
        for _ in 0..1 + next() % 4 {
            let i = next() % m.len();
            m[i] = next() as u8;
        }
        if next() % 8 == 0 {
            let cut = next() % m.len();
            m.truncate(cut);
        }
        let _ = validate_lockfile(&m);
        let mut pm = manifest.clone();
        let i = next() % pm.len();
        pm[i] = next() as u8;
        let _ = validate_package_json(&pm);
    }
    for _ in 0..500 {
        let len = next() % 256;
        let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        assert!(validate_lockfile(&junk).is_err());
        let _ = validate_package_json(&junk);
    }
}

#[test]
fn reason_tokens_are_stable_and_unique() {
    let all = [
        R::TooLarge,
        R::NotUtf8,
        R::TooDeep,
        R::MalformedJson,
        R::DuplicateKey,
        R::NotObject,
        R::LockfileVersion,
        R::PackagesMissing,
        R::TooManyPackages,
        R::TooManyMembers,
        R::TooManyDependencyEdges,
        R::DependencyUnresolved,
        R::LegacyTreeInV3,
        R::LegacyTreeMismatch,
        R::PackagePath,
        R::NestingTooDeep,
        R::Name,
        R::Version,
        R::Alias,
        R::Link,
        R::Git,
        R::File,
        R::Http,
        R::RemoteUrl,
        R::ResolvedMismatch,
        R::ResolvedMissing,
        R::IntegrityMissing,
        R::Integrity,
        R::Bundled,
        R::Shrinkwrap,
        R::Workspace,
        R::Spec,
        R::FieldType,
    ];
    let tokens: std::collections::BTreeSet<&str> = all.iter().map(|r| r.as_str()).collect();
    assert_eq!(tokens.len(), all.len());
    // `[a-z][a-z0-9_]*` (digits allowed after the first byte: `not_utf8`).
    fn token_byte(b: u8) -> bool {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
    }
    for t in &tokens {
        let first_ok = t.starts_with(|c: char| c.is_ascii_lowercase());
        assert!(first_ok && t.bytes().all(token_byte), "{t}");
    }
    assert_eq!(R::NotUtf8.as_str(), "not_utf8");
    assert_eq!(R::RemoteUrl.as_str(), "remote_url");
    assert_eq!(R::ResolvedMismatch.as_str(), "resolved_mismatch");
    assert_eq!(
        R::TooManyDependencyEdges.as_str(),
        "too_many_dependency_edges"
    );
}

#[test]
fn required_dependencies_must_resolve_from_root_and_every_package() {
    for path in ["", "node_modules/a", "node_modules/a/node_modules/b"] {
        for field in ["dependencies", "peerDependencies"] {
            let mut packages = base_packages();
            packages[path][field] = json!({"ghost": "^1.0.0"});
            assert_eq!(
                reason(&lock(packages)),
                R::DependencyUnresolved,
                "{path}: {field}"
            );
        }
    }
    let mut packages = base_packages();
    packages[""]["devDependencies"] = json!({"ghost": "*"});
    assert_eq!(reason(&lock(packages)), R::DependencyUnresolved);
}

#[test]
fn closure_uses_nearest_node_lookup_including_scopes_and_hoisting() {
    let mut packages = base_packages();
    let parent = "node_modules/a/node_modules/@s/child";
    packages.insert(parent.into(), entry("@s/child", "1.0.0"));
    packages[parent]["dependencies"] = json!({"@s/dep": "*", "left-pad": "*", "a": "*"});
    let local = format!("{parent}/node_modules/@s/dep");
    let ancestor = "node_modules/a/node_modules/@s/dep";
    let root = "node_modules/@s/dep";
    for (path, version) in [(&*local, "3.0.0"), (ancestor, "2.0.0"), (root, "1.0.0")] {
        packages.insert(path.into(), entry("@s/dep", version));
    }
    for (path, version) in [(&*local, "3.0.0"), (ancestor, "2.0.0"), (root, "1.0.0")] {
        assert!(validate_lockfile(&lock(packages.clone())).is_ok());
        let index = packages
            .iter()
            .map(|(path, value)| (path.as_str(), value))
            .collect();
        assert_eq!(
            resolve_dependency(
                &index,
                &package_ancestors(parent),
                "@s/dep",
                &mut String::new()
            )
            .unwrap()["version"],
            version
        );
        packages.remove(path);
    }
    // An entry under a sibling is not reachable through Node's lookup.
    packages.insert(
        "node_modules/left-pad/node_modules/@s/dep".into(),
        entry("@s/dep", "1.0.0"),
    );
    assert_eq!(reason(&lock(packages)), R::DependencyUnresolved);
}

#[test]
fn closure_unscoped_shadowing_and_scoped_node_modules_basename() {
    let mut packages = base_packages();
    let parent = "node_modules/a/node_modules/@s/node_modules";
    packages.insert(parent.into(), entry("@s/node_modules", "1.0.0"));
    packages[parent]["dependencies"] = json!({"left-pad": "*"});
    let nested = "node_modules/a/node_modules/left-pad";
    packages.insert(nested.into(), entry("left-pad", "2.0.0"));
    // The old Node lookup skips any directory named node_modules.
    packages.insert(
        format!("{parent}/node_modules/left-pad"),
        entry("left-pad", "3.0.0"),
    );
    let ancestors = package_ancestors(parent);
    assert_eq!(ancestors, ["node_modules/a", ""]);
    let mut candidate = String::new();
    for version in ["2.0.0", "1.3.0"] {
        assert!(validate_lockfile(&lock(packages.clone())).is_ok());
        let index = packages
            .iter()
            .map(|(path, value)| (path.as_str(), value))
            .collect();
        assert_eq!(
            resolve_dependency(&index, &ancestors, "left-pad", &mut candidate).unwrap()["version"],
            version
        );
        packages.remove(nested);
    }
}

#[test]
fn large_hoisted_lockfile_with_deep_dependency_chains_is_valid() {
    let mut packages = Map::new();
    packages.insert(String::new(), json!({}));
    for i in 0..MAX_PACKAGES - MAX_NESTING {
        let name = format!("p{i}");
        packages.insert(format!("node_modules/{name}"), entry(&name, "1.0.0"));
    }
    let dependencies: Map<String, Value> =
        (0..2048).map(|i| (format!("p{i}"), json!("*"))).collect();
    let mut path = String::new();
    for depth in 0..MAX_NESTING {
        if !path.is_empty() {
            path.push('/');
        }
        let name = format!("{}{:02}", "d".repeat(112), depth);
        path.push_str("node_modules/");
        path.push_str(&name);
        let mut package = entry(&name, "1.0.0");
        if depth >= MAX_NESTING - 8 {
            package["dependencies"] = Value::Object(dependencies.clone());
        }
        packages.insert(path.clone(), package);
    }
    assert_eq!(path.len(), PACKAGE_PATH_MAX - 1);
    let bytes = lock(packages);
    assert!(bytes.len() < LOCKFILE_MAX_BYTES);
    // Exercise the full validator in debug and release without a flaky
    // wall-clock assertion on shared CI machines.
    assert_eq!(
        validate_lockfile(&bytes).unwrap().packages.len(),
        MAX_PACKAGES
    );
}

#[test]
fn dependency_edge_cap_is_checked_before_any_resolution() {
    let mut packages = Map::new();
    let dependencies: Map<String, Value> =
        (0..1000).map(|i| (format!("p{i}"), json!("*"))).collect();
    packages.insert(
        String::new(),
        json!({"devDependencies": dependencies.clone()}),
    );
    for i in 0..1000 {
        let name = format!("p{i}");
        let mut package = entry(&name, "1.0.0");
        if i < MAX_DEPENDENCY_EDGES / 1000 - 1 {
            let field = if i % 2 == 0 {
                "dependencies"
            } else {
                "peerDependencies"
            };
            package[field] = Value::Object(dependencies.clone());
        }
        packages.insert(format!("node_modules/{name}"), package);
    }
    // Exactly 200,000 edges, including root devDependencies and package peers.
    assert!(validate_lockfile(&lock(packages.clone())).is_ok());
    // The first entry now has an unresolved edge, but the global budget must
    // refuse before attempting even that first lookup.
    packages[""]["dependencies"] = json!({"missing": "*"});
    let bytes = lock(packages);
    assert!(bytes.len() < LOCKFILE_MAX_BYTES);
    assert_eq!(reason(&bytes), R::TooManyDependencyEdges);
}

#[test]
fn optional_dependencies_and_optional_peers_may_be_absent() {
    for path in ["", "node_modules/a"] {
        let mut packages = base_packages();
        packages[path]["optionalDependencies"] = json!({"missing": "*"});
        packages[path]["dependencies"] = json!({"missing": "*"});
        packages[path]["peerDependencies"] = json!({"peer": "*"});
        packages[path]["peerDependenciesMeta"] = json!({"peer": {"optional": true}});
        assert!(validate_lockfile(&lock(packages.clone())).is_ok());
        packages[path]["peerDependenciesMeta"] = json!({"peer": {"optional": false}});
        assert_eq!(reason(&lock(packages.clone())), R::DependencyUnresolved);
        packages[path]["peerDependenciesMeta"] = json!({"other": {"optional": true}});
        assert_eq!(reason(&lock(packages.clone())), R::DependencyUnresolved);
        for meta in [
            json!(true),
            json!({"peer": true}),
            json!({"peer": {"optional": "true"}}),
        ] {
            packages[path]["peerDependenciesMeta"] = meta;
            assert_eq!(reason(&lock(packages.clone())), R::FieldType);
        }
    }
    let mut packages = base_packages();
    packages["node_modules/a"]["devDependencies"] = json!({"not-installed": "*"});
    assert!(validate_lockfile(&lock(packages)).is_ok());
}

#[test]
fn v3_refuses_any_legacy_dependencies_section() {
    for legacy in [json!({}), json!(null), json!({"a": entry("a", "1.0.0")})] {
        let bytes = serde_json::to_vec(&json!({
            "lockfileVersion": 3, "packages": base_packages(), "dependencies": legacy,
        }))
        .unwrap();
        assert_eq!(reason(&bytes), R::LegacyTreeInV3);
    }
}

#[test]
fn v2_legacy_entries_must_match_validated_physical_paths() {
    let mut doc = json!({
        "lockfileVersion": 2,
        "packages": base_packages(),
        "dependencies": {"a": entry("a", "1.0.0")},
    });
    doc["dependencies"]["a"]["dependencies"] = json!({"b": entry("b", "2.0.0-beta.1+build.5")});
    assert!(validate_lockfile(&serde_json::to_vec(&doc).unwrap()).is_ok());
    for path in ["/dependencies/a", "/dependencies/a/dependencies/b"] {
        for field in ["version", "resolved", "integrity"] {
            let mut missing = doc.clone();
            missing
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_eq!(
                reason(&serde_json::to_vec(&missing).unwrap()),
                R::LegacyTreeMismatch
            );
        }
        for (field, value) in [
            ("version", json!("9.9.9")),
            ("resolved", json!(tarball("other", "9.9.9"))),
            ("integrity", json!(format!("sha512-{}Q==", "A".repeat(85)))),
            ("integrity", json!(format!("sha512-{}B==", "A".repeat(85)))),
            (
                "integrity",
                json!(format!("{} {}", integrity(), integrity())),
            ),
        ] {
            let mut mismatch = doc.clone();
            mismatch.pointer_mut(path).unwrap()[field] = value;
            assert_eq!(
                reason(&serde_json::to_vec(&mismatch).unwrap()),
                R::LegacyTreeMismatch
            );
        }
    }
    // A hoisted package is not a counterpart for a nested legacy entry.
    doc["dependencies"]["a"]["dependencies"]["left-pad"] = entry("left-pad", "1.3.0");
    assert_eq!(
        reason(&serde_json::to_vec(&doc).unwrap()),
        R::LegacyTreeMismatch
    );
}

#[test]
fn v2_ghost_bypass_is_refused_with_and_without_a_dependency_edge() {
    let mut doc = json!({
        "lockfileVersion": 2,
        "packages": {"": {}, "node_modules/x": entry("x", "1.0.0")},
        "dependencies": {"x": entry("x", "1.0.0")},
    });
    doc["dependencies"]["x"]["dependencies"] = json!({
        "ghost": {"version": "9.9.9", "resolved": tarball("other", "9.9.9")},
    });
    assert_eq!(
        reason(&serde_json::to_vec(&doc).unwrap()),
        R::LegacyTreeMismatch
    );
    doc["packages"]["node_modules/x"]["dependencies"] = json!({"ghost": "*"});
    assert_eq!(
        reason(&serde_json::to_vec(&doc).unwrap()),
        R::DependencyUnresolved
    );
}

#[test]
fn sha512_requires_zero_padding_bits_and_exact_digest_length() {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (index, last) in alphabet.iter().enumerate() {
        let hash = format!("sha512-{}{}==", "A".repeat(85), *last as char);
        let bytes = with_left_pad(|entry| {
            entry.insert("integrity".into(), json!(hash));
        });
        if index % 16 == 0 {
            assert!(validate_lockfile(&bytes).is_ok(), "{index}");
        } else {
            assert_eq!(reason(&bytes), R::Integrity, "{index}");
        }
    }
    // Canonical encodings of 63 zero bytes and 65 zero bytes are not SHA-512.
    for hash in [
        format!("sha512-{}", "A".repeat(84)),
        format!("sha512-{}=", "A".repeat(87)),
    ] {
        assert!(!is_sha512_integrity(&hash));
    }
    assert!(is_sha512_integrity(&format!(
        "sha512-{}w==",
        "/".repeat(85)
    )));
}

#[test]
fn package_member_cap_stops_before_reading_excess_value() {
    let mut text = String::from(r#"{"lockfileVersion":3,"packages":{"":{}"#);
    for i in 0..MAX_PACKAGES {
        text.push_str(&format!(r#", "p{i}":{{}}"#));
    }
    // Malformed value proves the streaming cap fires before the Value parse.
    text.push_str(r#", "excess":INVALID}}"#);
    assert_eq!(reason(text.as_bytes()), R::TooManyPackages);
}

#[test]
fn lockfile_general_member_cap_has_a_stable_reason() {
    let mut text = String::from(r#"{"lockfileVersion":3,"packages":{},"metadata":{"#);
    for i in 0..super::super::JSON_MAX_MEMBERS {
        text.push_str(&format!(r#""k{i}":0,"#));
    }
    text.push_str(r#""excess":INVALID}}"#);
    assert_eq!(reason(text.as_bytes()), R::TooManyMembers);
    assert_eq!(R::TooManyMembers.as_str(), "too_many_members");
    assert_eq!(R::DependencyUnresolved.as_str(), "dependency_unresolved");
    assert_eq!(R::LegacyTreeInV3.as_str(), "legacy_tree_in_v3");
    assert_eq!(R::LegacyTreeMismatch.as_str(), "legacy_tree_mismatch");
}
