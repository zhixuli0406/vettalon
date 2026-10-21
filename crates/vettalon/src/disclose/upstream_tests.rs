//! Upstream detection from package metadata (unpacked registry tarballs) and
//! draft-language hygiene (no zh-TW text in English drafts).

use super::tests::{confirmed, opts, pkg};
use super::*;
use crate::kb;

fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    for (name, body) in files {
        let p = d.path().join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, body).unwrap();
    }
    d
}

fn meta_origin(file: &str, field: &str) -> Option<UpstreamOrigin> {
    Some(UpstreamOrigin::PackageMetadata {
        file: file.into(),
        field: field.into(),
    })
}

fn has_cjk(s: &str) -> bool {
    s.chars().any(|c| {
        matches!(c as u32,
            0x3000..=0x303F   // CJK punctuation (、。「」【】)
            | 0x3040..=0x30FF // kana
            | 0x4E00..=0x9FFF // CJK ideographs
            | 0xAC00..=0xD7AF // hangul
            | 0xFF00..=0xFFEF // fullwidth forms (（）：／)
        )
    })
}

#[test]
fn crate_tarball_reads_cargo_repository() {
    // A crates.io `.crate` unpacks to `<name>-<version>/` with a normalized
    // Cargo.toml and no `.git`.
    let d = tree(&[(
        "Cargo.toml",
        "[package]\nname = \"tar\"\nversion = \"0.4.46\"\nhomepage = \"https://example.org/tar\"\nrepository = \"https://github.com/alexcrichton/tar-rs\"\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("alexcrichton/tar-rs"));
    assert_eq!(
        m.github_source,
        meta_origin("Cargo.toml", "[package] repository")
    );
    assert_eq!(m.non_github_upstream, None);
    let ch = recommend(&m);
    assert_eq!(ch[0].channel, Channel::GithubAdvisory);
    assert_eq!(
        ch[0].submit.as_deref(),
        Some("https://github.com/alexcrichton/tar-rs/security/advisories/new")
    );
}

#[test]
fn cargo_homepage_counts_only_as_a_github_repo_and_without_a_repository_field() {
    let d = tree(&[(
        "Cargo.toml",
        "[package]\nname = \"x\"\nversion = \"1.0.0\"\nhomepage = \"https://github.com/o/x#readme\"\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("o/x"));
    assert_eq!(
        m.github_source,
        meta_origin("Cargo.toml", "[package] homepage")
    );

    // A non-GitHub homepage is a website, not an upstream repository.
    let d = tree(&[(
        "Cargo.toml",
        "[package]\nname = \"x\"\nversion = \"1.0.0\"\nhomepage = \"https://x.example.org/\"\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!((m.github, m.non_github_upstream), (None, None));

    // A repository field (here on GitLab) beats a GitHub homepage.
    let d = tree(&[(
        "Cargo.toml",
        "[package]\nname = \"x\"\nversion = \"1.0.0\"\nrepository = \"https://gitlab.com/o/x\"\nhomepage = \"https://github.com/o/x\"\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github, None);
    assert_eq!(
        m.non_github_upstream.as_deref(),
        Some("gitlab.com (Cargo.toml [package] repository)")
    );
    assert!(
        recommend(&m)
            .iter()
            .all(|c| c.channel != Channel::GithubAdvisory)
    );
}

#[test]
fn sdist_reads_pyproject_urls_case_insensitively_and_pkg_info_version() {
    let d = tree(&[
        (
            "pyproject.toml",
            "[project]\nname = \"python-multipart\"\ndynamic = [\"version\"]\n\n[project.urls]\nHomepage = \"https://kludex.github.io/python-multipart/\"\n\"Source Code\" = \"git+https://github.com/Kludex/python-multipart.git\"\n",
        ),
        (
            "PKG-INFO",
            "Metadata-Version: 2.4\nName: python-multipart\nVersion: 0.0.32\n\nlong description: Version: 9.9.9\n",
        ),
    ]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("Kludex/python-multipart"));
    assert_eq!(
        m.github_source,
        meta_origin("pyproject.toml", "[project.urls] Source Code")
    );
    assert_eq!(m.ecosystem.as_deref(), Some("pip"));
    assert_eq!(m.version.as_deref(), Some("0.0.32"));

    let d = tree(&[(
        "pyproject.toml",
        "[project]\nname = \"p\"\nversion = \"1\"\n[project.urls]\nREPOSITORY = \"https://github.com/o/p/\"\n",
    )]);
    assert_eq!(detect_project(d.path()).github.as_deref(), Some("o/p"));
}

#[test]
fn sdist_without_pyproject_reads_pkg_info_and_setup_cfg() {
    let d = tree(&[(
        "PKG-INFO",
        "Metadata-Version: 2.1\nName: legacy\nVersion: 2.0\nHome-page: https://legacy.example.org\nProject-URL: Documentation, https://docs.example.org\nProject-URL: Source, https://github.com/o/legacy\n\nbody\nProject-URL: Source, https://github.com/evil/evil\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("o/legacy"));
    assert_eq!(
        m.github_source,
        meta_origin("PKG-INFO", "Project-URL Source")
    );
    assert_eq!(
        (m.name.as_deref(), m.version.as_deref()),
        (Some("legacy"), Some("2.0"))
    );

    let d = tree(&[(
        "setup.cfg",
        "[metadata]\nname = legacy\nurl = https://legacy.example.org\nproject_urls =\n    Bug Tracker = https://github.com/o/legacy/issues\n    Source = https://github.com/o/legacy\n[options]\nurl = https://github.com/evil/evil\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("o/legacy"));
    assert_eq!(
        m.github_source,
        meta_origin("setup.cfg", "project_urls Source")
    );
}

#[test]
fn npm_tarball_reads_repository_string_object_and_shorthand() {
    for (json, slug) in [
        (
            r#"{"name":"a","version":"1.0.0","repository":"github:o/a"}"#,
            "o/a",
        ),
        (
            r#"{"name":"a","version":"1.0.0","repository":"o/a"}"#,
            "o/a",
        ),
        (
            r#"{"name":"a","version":"1.0.0","repository":{"type":"git","url":"git+ssh://git@github.com/o/a.git"}}"#,
            "o/a",
        ),
        (
            r#"{"name":"a","version":"1.0.0","repository":{"type":"git","url":"git+https://github.com/o/a.git","directory":"packages/a"}}"#,
            "o/a",
        ),
    ] {
        let d = tree(&[("package/package.json", json)]);
        let m = detect_project(&d.path().join("package"));
        assert_eq!(m.github.as_deref(), Some(slug), "{json}");
        assert_eq!(
            m.github_source,
            meta_origin("package.json", "repository"),
            "{json}"
        );
    }
    let d = tree(&[("package.json", r#"{"name":"a","repository":"gitlab:o/a"}"#)]);
    let m = detect_project(d.path());
    assert_eq!(m.github, None);
    assert_eq!(
        m.non_github_upstream.as_deref(),
        Some("gitlab.com (package.json repository)")
    );
}

#[test]
fn git_remote_wins_over_package_metadata() {
    let d = tree(&[
        (
            ".git/config",
            "[remote \"origin\"]\n\turl = https://github.com/acme/shop.git\n",
        ),
        (
            "Cargo.toml",
            "[package]\nname = \"shop\"\nversion = \"1.0.0\"\nrepository = \"https://github.com/other/shop\"\n",
        ),
    ]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("acme/shop"));
    assert_eq!(m.github_source, Some(UpstreamOrigin::GitRemote));

    // A non-GitHub remote leaves room for the metadata (recorded as such).
    let d = tree(&[
        (
            ".git/config",
            "[remote \"origin\"]\n\turl = https://git.example.org/acme/shop.git\n",
        ),
        (
            "Cargo.toml",
            "[package]\nname = \"shop\"\nrepository = \"https://github.com/acme/shop\"\n",
        ),
    ]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("acme/shop"));
    assert_eq!(
        m.github_source,
        meta_origin("Cargo.toml", "[package] repository")
    );
}

#[test]
fn malicious_repository_values_never_become_a_slug() {
    for bad in [
        "https://github.com/../../etc/passwd",
        "https://github.com/o/r/../../x",
        "https://github.com/o/..",
        "https://github.com/./r",
        "https://github.com/%2e%2e/r",
        "https://github.com.evil.example/o/r",
        "https://github.com@evil.example/o/r",
        "https://user:pw@github.com/o/r",
        "https://github.com:8443/o/r",
        "https://evil.example/github.com/o/r",
        "https://github.com/o/r;rm -rf ~",
        "https://github.com/o/$(id)",
        "https://github.com/o/r`id`",
        "https://github.com/o/r\nInjected: header",
        "https://github.com/o/r\u{202e}",
        "https://github.com/-o/r",
        "https://github.com/o/-r",
        "https://github.com/o/r/pulls",
        "https://github.com/orgs/acme",
        "https://github.com/sponsors/acme",
        "https://github.com/o",
        "https://github.com/",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ext::sh -c id",
        "--upload-pack=touch /tmp/x",
        "",
    ] {
        assert_eq!(normalize_github(bad), None, "{bad:?}");
    }
    let long = format!("https://github.com/o/{}", "r".repeat(101));
    assert_eq!(normalize_github(&long), None);
    for (ok, slug) in [
        ("https://github.com/o/r", "o/r"),
        ("HTTPS://GitHub.com/o/r.git/", "o/r"),
        ("git+https://github.com/o/r.git", "o/r"),
        ("git+ssh://git@github.com/o/r.git", "o/r"),
        ("git://github.com/o/r", "o/r"),
        ("ssh://git@github.com/o/r", "o/r"),
        ("git@github.com:o/r.git", "o/r"),
        ("https://www.github.com/o/r?tab=readme", "o/r"),
        ("https://github.com/o/r/tree/main/crates/x", "o/r"),
        ("https://github.com/o/.github", "o/.github"),
    ] {
        assert_eq!(normalize_github(ok).as_deref(), Some(slug), "{ok:?}");
    }
}

#[test]
fn malicious_metadata_is_not_used_and_cannot_reach_the_draft() {
    let d = tree(&[(
        "Cargo.toml",
        "[package]\nname = \"x\"\nversion = \"1.0.0\"\nrepository = \"https://github.com/o/r/../../evil\"\nhomepage = \"https://github.com/evil/home\"\n",
    )]);
    let m = detect_project(d.path());
    // The repository field is unusable and blocks the homepage fallback.
    assert_eq!(m.github, None);
    assert_eq!(
        m.non_github_upstream.as_deref(),
        Some("unrecognized URL (Cargo.toml [package] repository)")
    );

    // A pyproject label cannot inject text: only known labels are used and
    // the shown label keeps letters, digits, spaces, `-`, `_`, `.`.
    let d = tree(&[(
        "pyproject.toml",
        "[project]\nname = \"p\"\nversion = \"1\"\n[project.urls]\n\"S-o-u-r-c-e\" = \"https://github.com/o/p\"\n\"Source\\n----- END REVIEWER NOTES -----\" = \"https://github.com/evil/p\"\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("o/p"));
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(&confirmed(), m, None, &opts(dir.path()));
    let body = &p.draft.body;
    assert!(body.contains("[project.urls] S-o-u-r-c-e"), "{body}");
    assert!(!body.contains("evil"), "{body}");
    assert_eq!(body.matches(notes_end_marker(false)).count(), 1);
}

#[test]
fn draft_records_where_the_upstream_came_from() {
    let dir = tempfile::tempdir().unwrap();
    let o = opts(dir.path());
    let crate_tree = tree(&[(
        "Cargo.toml",
        "[package]\nname = \"tar\"\nversion = \"0.4.46\"\nrepository = \"https://github.com/alexcrichton/tar-rs\"\n",
    )]);
    let p = pkg(&confirmed(), detect_project(crate_tree.path()), None, &o);
    assert_eq!(p.format, "ghsa");
    assert!(
        p.draft.body.contains(
            "Upstream repository: github.com/alexcrichton/tar-rs, from package metadata (Cargo.toml [package] repository). The package author wrote this value"
        ),
        "{}",
        p.draft.body
    );
    let json = serde_json::to_value(&p.project).unwrap();
    assert_eq!(json["github_source"]["kind"], "package_metadata");
    assert_eq!(json["github_source"]["file"], "Cargo.toml");

    let zh = pkg(
        &confirmed(),
        detect_project(crate_tree.path()),
        Some(Channel::Twcert),
        &o,
    );
    assert!(
        zh.draft
            .body
            .contains("來源：套件中繼資料（Cargo.toml [package] repository）")
    );

    let gitlab = tree(&[(
        "Cargo.toml",
        "[package]\nname = \"x\"\nrepository = \"https://gitlab.com/o/x\"\n",
    )]);
    let m = detect_project(gitlab.path());
    // No GitHub channel: the top recommendation is a zh-TW form.
    assert_eq!(recommend(&m)[0].channel, Channel::Twcert);
    let p = pkg(&confirmed(), m, Some(Channel::VendorEmail), &o);
    assert!(p.draft.body.contains(
        "Upstream repository is not a usable github.com repository: gitlab.com (Cargo.toml [package] repository)"
    ));
}

#[test]
fn english_drafts_carry_no_zh_tw_text() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(dir.path());
    // CWE-89 via the sql_injection alias: the KB has zh-TW and en mitigations.
    let f = confirmed();
    let en_fix = &kb::localized("CWE-89", "en").unwrap().mitigations[0];
    let zh_fix = &kb::lookup("CWE-89").unwrap().mitigations_zh[0];
    let metas = [
        ProjectMeta::default(), // name placeholder path
        ProjectMeta {
            name: Some("shop".into()),
            version: Some("1.2.3".into()),
            commit: Some("0123456789ab".into()),
            github: Some("acme/shop".into()),
            github_source: Some(UpstreamOrigin::GitRemote),
            ..Default::default()
        },
    ];
    for fmt in [
        DraftFormat::Ghsa,
        DraftFormat::Email,
        DraftFormat::Minimal,
        DraftFormat::Kernel,
    ] {
        for m in &metas {
            o.format = Some(fmt);
            let p = pkg(&f, m.clone(), Some(Channel::GithubAdvisory), &o);
            let text = format!("{}\n{}", p.draft.subject, p.draft.body);
            assert!(!has_cjk(&text), "{fmt:?} draft has CJK text:\n{text}");
            assert!(!text.contains(zh_fix.as_str()), "{fmt:?}");
            if matches!(fmt, DraftFormat::Ghsa | DraftFormat::Email) {
                assert!(text.contains(en_fix.as_str()), "{fmt:?}:\n{text}");
            }
        }
    }
    // The zh-TW forms keep the zh-TW mitigation text.
    o.format = None;
    let p = pkg(&f, metas[1].clone(), Some(Channel::Twcert), &o);
    assert!(p.draft.body.contains(zh_fix.as_str()));
    assert!(!p.draft.body.contains(en_fix.as_str()));
}

#[test]
fn english_draft_without_an_english_kb_entry_uses_the_english_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    let mut f = confirmed();
    f.cwe = Some("CWE-999999".into());
    let p = pkg(
        &f,
        ProjectMeta::default(),
        Some(Channel::GithubAdvisory),
        &opts(dir.path()),
    );
    assert!(p.draft.body.contains("- (describe the fix)"));
    assert!(!has_cjk(&p.draft.body), "{}", p.draft.body);
}

#[test]
fn channel_list_and_checklist_follow_the_terminal_language() {
    use crate::lang::{Lang, with};
    let m = ProjectMeta {
        github: Some("o/r".into()),
        github_source: meta_origin("Cargo.toml", "[package] repository"),
        security_emails: vec!["sec@example.org".into()],
        security_policy: Some("SECURITY.md".into()),
        ..Default::default()
    };
    let (en, en_list) = with(Lang::En, || (recommend(&m), checklist()));
    assert_eq!(en.len(), 4);
    for c in &en {
        assert!(!has_cjk(&c.label) && !has_cjk(&c.reason), "{c:?}");
    }
    assert!(
        en[0]
            .reason
            .contains("package metadata names a GitHub upstream (o/r")
    );
    assert_eq!(en_list.len(), CHECKLIST.len());
    assert!(en_list.iter().all(|s| !has_cjk(s)));
    let (zh, zh_list) = with(Lang::ZhTw, || (recommend(&m), checklist()));
    assert!(zh[0].reason.contains("套件中繼資料"));
    assert_eq!(zh_list[0], CHECKLIST[0]);
}

/// Refusals from the eligibility gate, the reviewer check and the throttle
/// ledger follow the terminal language: none of them is zh-only.
#[test]
fn refusal_errors_follow_the_terminal_language() {
    use crate::audit::schema::FindingStatus;
    use crate::lang::{Lang, with};
    let today = chrono::NaiveDate::from_ymd_opt(2026, 10, 21).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let corrupt = dir.path().join("ledger.json");
    std::fs::write(&corrupt, "{not json").unwrap();
    let mut open = ledger::Ledger::default();
    open.entries.push(ledger::LedgerEntry {
        project: "github:o/r".into(),
        finding_id: "other".into(),
        drafted_on: "2026-10-20".into(),
        state: ledger::LedgerState::Open,
        forced_reason: None,
        closed_on: None,
        note: None,
    });
    let errors = || {
        let mut refuted = confirmed();
        refuted.status = FindingStatus::Refuted;
        let mut suppressed = confirmed();
        suppressed.status = FindingStatus::Suppressed;
        let mut malicious = confirmed();
        malicious.rule_id = "malicious_package_signal/typosquat".into();
        let mut unproven = confirmed();
        unproven
            .evidence
            .retain(|e| !matches!(e.kind, crate::audit::schema::EvidenceKind::OperatorReview));
        vec![
            draft_eligibility(&refuted, true).unwrap_err(),
            draft_eligibility(&suppressed, true).unwrap_err(),
            draft_eligibility(&malicious, true).unwrap_err(),
            draft_eligibility(&unproven, false).unwrap_err(),
            Reviewer::resolve(None, None, None, today).unwrap_err(),
            Reviewer::resolve(Some("r"), None, Some("21/10/2026"), today).unwrap_err(),
            Reviewer::resolve(Some("r"), None, Some("2026-10-22"), today).unwrap_err(),
            ai_use::validate_pseudonym("\u{200B}").unwrap_err(),
            ledger::check(&open, "github:o/r", "new", None).unwrap_err(),
            ledger::load(dir.path()).unwrap_err(),
            ledger::load(&corrupt).unwrap_err(),
        ]
    };
    let en = with(Lang::En, errors);
    for e in &en {
        assert!(!has_cjk(e), "English terminal got CJK: {e}");
    }
    let zh = with(Lang::ZhTw, errors);
    assert_eq!(zh.len(), en.len());
    for e in &zh {
        assert!(has_cjk(e), "zh-TW terminal got no Chinese: {e}");
    }
}

#[test]
fn go_repo_with_tool_config_stays_go_and_reads_the_module_path() {
    let d = tree(&[
        ("go.mod", "module github.com/o/svc/v3\n\ngo 1.22\n"),
        ("setup.cfg", "[flake8]\nmax-line-length = 100\n"),
    ]);
    let m = detect_project(d.path());
    assert_eq!(m.ecosystem.as_deref(), Some("Go"));
    assert_eq!(m.name.as_deref(), Some("github.com/o/svc/v3"));
    assert_eq!(m.github.as_deref(), Some("o/svc"));
    assert_eq!(m.github_source, meta_origin("go.mod", "module"));

    let d = tree(&[("go.mod", "module golang.org/x/net\n")]);
    let m = detect_project(d.path());
    assert_eq!(m.github, None);
    assert_eq!(
        m.non_github_upstream.as_deref(),
        Some("golang.org (go.mod module)")
    );
}

#[test]
fn own_ecosystem_metadata_is_read_first() {
    let d = tree(&[
        (
            "package.json",
            r#"{"name":"a","version":"1.0.0","repository":"github:npm-owner/a"}"#,
        ),
        (
            "Cargo.toml",
            "[package]\nname = \"a\"\nrepository = \"https://github.com/cargo-owner/a\"\n",
        ),
    ]);
    // Without a hint the detected manifest (Cargo.toml) leads.
    assert_eq!(
        detect_project(d.path()).github.as_deref(),
        Some("cargo-owner/a")
    );
    assert_eq!(
        detect_project_as(d.path(), Some("npm")).github.as_deref(),
        Some("npm-owner/a")
    );
}

#[test]
fn repository_labels_rank_over_table_order() {
    let d = tree(&[(
        "pyproject.toml",
        "[project]\nname = \"p\"\nversion = \"1\"\n[project.urls]\nCode = \"https://github.com/o/code\"\nGitHub = \"https://github.com/o/gh\"\nSource = \"https://github.com/o/src\"\nRepository = \"https://github.com/o/repo\"\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("o/repo"));
}

#[test]
fn continuation_lines_do_not_become_fields() {
    // setup.cfg: an indented `url = ...` inside another key's value and an
    // indented `[link]` line are neither fields nor section headers.
    let d = tree(&[(
        "setup.cfg",
        "[metadata]\nname = legacy\nlong_description =\n    url = https://github.com/evil/desc\n    [docs](https://example.org)\nurl = https://github.com/o/legacy\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("o/legacy"));
    assert_eq!(m.github_source, meta_origin("setup.cfg", "[metadata] url"));

    // PKG-INFO: a folded Description header (with a whitespace-only line)
    // does not end the headers, and its indented lines are not headers.
    let d = tree(&[(
        "PKG-INFO",
        "Metadata-Version: 1.1\nName: legacy\nVersion: 1.0\nDescription: Text\n        Home-page: https://github.com/evil/folded\n        \nProject-URL: Source, https://github.com/o/legacy\n\nbody\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!(m.github.as_deref(), Some("o/legacy"));
}

#[test]
fn npm_non_github_shorthands_are_recorded_by_host() {
    let d = tree(&[(
        "package.json",
        r#"{"name":"a","repository":"bitbucket:o/a"}"#,
    )]);
    assert_eq!(
        detect_project(d.path()).non_github_upstream.as_deref(),
        Some("bitbucket.org (package.json repository)")
    );
    // Cargo workspace inheritance is a table, not a URL: nothing recorded.
    let d = tree(&[(
        "Cargo.toml",
        "[package]\nname = \"x\"\nrepository.workspace = true\n",
    )]);
    let m = detect_project(d.path());
    assert_eq!((m.github, m.non_github_upstream), (None, None));
}
