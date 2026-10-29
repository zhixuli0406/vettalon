use std::process::{Command, Output};

fn explain(args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_vettalon"))
        .args(args)
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("VETTALON_LANG", "en")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap()
}

#[test]
fn embedded_page_is_available_without_checkout_or_config_in_both_languages() {
    for lang in ["en", "zh-TW"] {
        let output = explain(&["--lang", lang, "explain", "no_control"]);
        assert!(output.status.success(), "{output:?}");
        let page = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            page,
            std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/explain/no_control.md"
            ))
            .unwrap()
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn list_has_summaries_and_localized_chrome() {
    for (lang, heading) in [("en", "Explanation codes"), ("zh-TW", "說明代碼")] {
        let output = explain(&["explain", "--list", "--lang", lang]);
        assert!(output.status.success(), "{output:?}");
        let list = String::from_utf8(output.stdout).unwrap();
        assert!(list.starts_with(heading), "{list}");
        for code in [
            "no_control",
            "partial_by_design",
            "shallow_missing_class_checks",
        ] {
            let line = list.lines().find(|line| line.starts_with(code)).unwrap();
            assert!(!line[code.len()..].trim().is_empty());
        }
    }
}

#[test]
fn unknown_code_exits_two_with_nearest_matches_in_both_languages() {
    for (lang, unknown, closest) in [
        ("en", "Unknown explanation code", "Closest matches"),
        ("zh-TW", "未知的說明代碼", "最接近的代碼"),
    ] {
        let output = explain(&["--lang", lang, "explain", "no_contrl"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(unknown), "{error}");
        assert!(error.contains(closest), "{error}");
        assert!(error.contains("no_control"), "{error}");
    }
}

#[test]
fn code_and_list_are_mutually_exclusive_and_one_is_required() {
    for args in [vec!["explain"], vec!["explain", "no_control", "--list"]] {
        let output = explain(&args);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
    }
}
