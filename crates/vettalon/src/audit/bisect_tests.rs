use super::StepResult::{Fails as F, Passes as P};
use super::*;

fn cid(i: usize) -> CommitId {
    CommitId::parse(&format!("{i:040x}")).unwrap()
}

fn range(n: usize) -> Vec<CommitId> {
    (0..n).map(cid).collect()
}

fn u(reason: &str) -> StepResult {
    StepResult::Unrunnable(reason.into())
}

/// Answers by commit index (the fake ids encode their index).
struct Fake(Vec<StepResult>);

#[async_trait::async_trait]
impl StepRunner for Fake {
    async fn run(&mut self, commit: &CommitId) -> StepResult {
        let index = usize::from_str_radix(commit.as_str(), 16).unwrap();
        self.0[index].clone()
    }
}

async fn run(results: Vec<StepResult>, good: Option<&CommitId>, max: usize) -> BisectResult {
    let commits = range(results.len());
    bisect(&commits, good, &mut Fake(results), max).await
}

fn indices(result: &BisectResult) -> Vec<usize> {
    result.steps.iter().map(|s| s.index).collect()
}

fn introduced(commit: usize, last: Option<usize>) -> BisectOutcome {
    BisectOutcome::IntroducedIn {
        commit: cid(commit),
        last_passing: last.map(cid),
    }
}

#[tokio::test]
async fn introduced_in_the_middle() {
    let r = run(vec![P, P, P, P, F, F, F, F], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, introduced(4, Some(3)));
    assert_eq!(&indices(&r)[..5], &[7, 0, 3, 5, 4]);
    assert!(!r.non_monotonic);
    assert!(r.steps.iter().all(|s| s.commit == cid(s.index)));
}

#[tokio::test]
async fn introduced_at_the_second_commit() {
    let r = run(vec![P, F, F, F, F, F], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, introduced(1, Some(0)));
    assert!(!r.non_monotonic);
}

#[tokio::test]
async fn present_since_oldest() {
    let r = run(vec![F, F, F, F], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, BisectOutcome::PresentSinceOldest);
    assert_eq!(indices(&r), vec![3, 0]);
}

#[tokio::test]
async fn not_reproducible_at_bad() {
    let r = run(vec![F, F, P], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, BisectOutcome::NotReproducibleAtBad);
    assert_eq!(indices(&r), vec![2]);
    let r = run(vec![F, u("docker")], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, BisectOutcome::NotReproducibleAtBad);
    let r = run(vec![F, u(TARGET_MISSING)], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, BisectOutcome::NotReproducibleAtBad);
}

#[tokio::test]
async fn target_missing_counts_as_absent() {
    let tm = || u(TARGET_MISSING);
    let r = run(vec![tm(), tm(), tm(), F, F, F], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, introduced(3, Some(2)));
    assert!(!r.non_monotonic);
}

#[tokio::test]
async fn target_not_regular_is_skipped_not_absent() {
    // Same shape as `target_missing_counts_as_absent`, but a symlinked or
    // submodule target says nothing about the behaviour.
    let tnr = || u(TARGET_NOT_REGULAR);
    let r = run(vec![tnr(), tnr(), tnr(), F, F, F], None, DEFAULT_MAX_STEPS).await;
    match &r.outcome {
        BisectOutcome::Inconclusive { lo, hi, reason } => {
            assert_eq!(lo, &None);
            assert_eq!(hi, &cid(3));
            assert!(reason.contains(TARGET_NOT_REGULAR), "{reason}");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!r.non_monotonic);
}

#[tokio::test]
async fn other_unrunnable_is_skipped_then_neighbour_decides() {
    let r = run(
        vec![P, P, P, u("syntax error"), P, F, F, F],
        None,
        DEFAULT_MAX_STEPS,
    )
    .await;
    assert_eq!(r.outcome, introduced(5, Some(4)));
    assert_eq!(&indices(&r)[..5], &[7, 0, 3, 4, 5]);
    assert_eq!(r.steps[2].result, u("syntax error"));
}

#[tokio::test]
async fn three_consecutive_unrunnable_is_inconclusive() {
    let mut results = vec![P];
    results.extend((0..8).map(|_| u("build failed")));
    results.push(F);
    let r = run(results, None, DEFAULT_MAX_STEPS).await;
    match &r.outcome {
        BisectOutcome::Inconclusive { lo, hi, reason } => {
            assert_eq!(lo.as_ref(), Some(&cid(0)));
            assert_eq!(hi, &cid(9));
            assert!(reason.contains("build failed"), "{reason}");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(indices(&r), vec![9, 0, 4, 5, 3]);
}

#[tokio::test]
async fn unrunnable_skips_reset_after_a_runnable_result() {
    // 4 skipped, 5 passes; 6 skipped, 7 fails: isolated skips never reach
    // MAX_SKIPS, but the only commit between 5 and 7 is unrunnable.
    let r = run(
        vec![P, P, P, P, u("x"), P, u("x"), F, F],
        None,
        DEFAULT_MAX_STEPS,
    )
    .await;
    assert_eq!(&indices(&r)[..6], &[8, 0, 4, 5, 6, 7]);
    match &r.outcome {
        BisectOutcome::Inconclusive { lo, hi, reason } => {
            assert_eq!(lo.as_ref(), Some(&cid(5)));
            assert_eq!(hi, &cid(7));
            assert!(reason.contains("every commit"), "{reason}");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!r.non_monotonic);
}

#[tokio::test]
async fn step_cap_reached_reports_the_narrowed_range() {
    let results: Vec<_> = (0..1000).map(|i| if i < 700 { P } else { F }).collect();
    let r = run(results, None, 4).await;
    assert_eq!(
        r.outcome,
        BisectOutcome::StepCapReached {
            lo: Some(cid(499)),
            hi: cid(749),
        }
    );
    assert_eq!(r.steps.len(), 4);
}

#[tokio::test]
async fn max_steps_is_clamped() {
    let results: Vec<_> = (0..1000).map(|i| if i < 700 { P } else { F }).collect();
    let r = run(results.clone(), None, 0).await;
    assert_eq!(r.steps.len(), 1);
    assert!(matches!(r.outcome, BisectOutcome::StepCapReached { .. }));
    let r = run(results, None, 1000).await;
    assert!(r.steps.len() <= MAX_STEPS_LIMIT);
    assert_eq!(r.outcome, introduced(700, Some(699)));
}

#[tokio::test]
async fn non_monotonic_history_is_flagged_without_changing_the_answer() {
    let r = run(vec![P, F, F, P, P, F, F], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, introduced(5, Some(4)));
    assert!(r.non_monotonic);
}

#[tokio::test]
async fn non_monotonic_tail_is_flagged() {
    // Converges on 2; the tail probe samples 5, which passes again.
    let r = run(vec![P, P, F, F, P, P, F], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, introduced(2, Some(1)));
    assert!(r.non_monotonic);
}

#[tokio::test]
async fn consistency_probes_never_exceed_the_cap() {
    // Exactly enough budget to converge: no probes.
    let r = run(vec![P, P, P, P, F, F, F, F], None, 5).await;
    assert_eq!(r.outcome, introduced(4, Some(3)));
    assert_eq!(r.steps.len(), 5);
}

#[tokio::test]
async fn single_commit_range() {
    let r = run(vec![F], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, BisectOutcome::PresentSinceOldest);
    assert_eq!(r.steps.len(), 1);

    let good = cid(0xabc);
    let r = run(vec![F], Some(&good), DEFAULT_MAX_STEPS).await;
    assert_eq!(
        r.outcome,
        BisectOutcome::IntroducedIn {
            commit: cid(0),
            last_passing: Some(good),
        }
    );
    assert_eq!(r.steps.len(), 1);
}

#[tokio::test]
async fn good_bound_is_not_retested() {
    let good = cid(0xabc);
    let r = run(vec![P, P, F, F], Some(&good), DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, introduced(2, Some(1)));
    assert_eq!(&indices(&r)[..3], &[3, 1, 2]);

    let r = run(vec![F, F, F, F], Some(&good), DEFAULT_MAX_STEPS).await;
    assert_eq!(
        r.outcome,
        BisectOutcome::IntroducedIn {
            commit: cid(0),
            last_passing: Some(good),
        }
    );
}

#[tokio::test]
async fn empty_range() {
    let r = run(vec![], None, DEFAULT_MAX_STEPS).await;
    assert_eq!(r.outcome, BisectOutcome::EmptyRange);
    assert!(r.steps.is_empty());
}

#[test]
fn max_steps_validation() {
    assert!(validate_max_steps(0).is_err());
    assert_eq!(validate_max_steps(1), Ok(1));
    assert_eq!(validate_max_steps(40), Ok(40));
    assert!(validate_max_steps(41).is_err());
}

#[test]
fn commit_id_parsing() {
    assert!(CommitId::parse(&"a".repeat(40)).is_ok());
    assert!(CommitId::parse(&"b".repeat(64)).is_ok());
    let upper = CommitId::parse(&"A".repeat(40)).unwrap();
    assert_eq!(upper.as_str(), "a".repeat(40));
    let bad = [
        String::new(),
        "abc".into(),
        "g".repeat(40),
        "a".repeat(41),
        format!("-{}", "a".repeat(39)),
    ];
    for bad in &bad {
        assert!(CommitId::parse(bad).is_err(), "{bad}");
    }
    assert!(serde_json::from_str::<CommitId>("\"--output=x\"").is_err());
}

#[tokio::test]
async fn receipt_serializes_in_snake_case_and_round_trips() {
    let result = run(vec![P, u("syntax"), F, F], None, DEFAULT_MAX_STEPS).await;
    let receipt = BisectReceipt::new(cid(3), None, result, DEFAULT_MAX_STEPS, b"test body");
    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["outcome"]["kind"], "inconclusive");
    assert_eq!(json["outcome"]["hi"], cid(2).as_str());
    assert_eq!(json["non_monotonic"], false);
    assert_eq!(json["steps"][0]["result"]["status"], "fails");
    assert_eq!(json["test_sha256"].as_str().unwrap().len(), 64);
    assert!(
        json["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["result"] == serde_json::json!({"status": "unrunnable", "reason": "syntax"}))
    );
    let back: BisectReceipt = serde_json::from_value(json).unwrap();
    assert_eq!(back, receipt);

    let intro = serde_json::to_value(introduced(2, None)).unwrap();
    assert_eq!(intro["kind"], "introduced_in");
    assert_eq!(intro["commit"], cid(2).as_str());
    assert!(intro["last_passing"].is_null());
    let cap = serde_json::to_value(BisectOutcome::StepCapReached {
        lo: None,
        hi: cid(1),
    })
    .unwrap();
    assert_eq!(cap["kind"], "step_cap_reached");
    assert_eq!(
        serde_json::to_value(BisectOutcome::NotReproducibleAtBad).unwrap()["kind"],
        "not_reproducible_at_bad"
    );
}

// --- Git input validation ----------------------------------------------------

#[test]
fn rev_validation_rejects_options_and_ranges() {
    for bad in [
        "-x",
        "--output=/tmp/x",
        "--all",
        "a..b",
        "a...b",
        "",
        "a b",
        "a\nb",
    ] {
        assert!(validate_rev(bad).is_err(), "{bad:?}");
    }
    for ok in ["HEAD", "HEAD~3", "HEAD^", "main", "v1.2.3", "origin/main"] {
        assert!(validate_rev(ok).is_ok(), "{ok:?}");
    }
    assert!(validate_rev(&"a".repeat(40)).is_ok());
}

#[test]
fn rev_list_lines_must_be_commit_ids() {
    let a = "a".repeat(40);
    let b = "b".repeat(64);
    assert_eq!(
        parse_rev_list(&format!("{a}\n{b}\n"), 10).unwrap(),
        vec![CommitId::parse(&a).unwrap(), CommitId::parse(&b).unwrap()]
    );
    assert_eq!(parse_rev_list("", 10).unwrap(), vec![]);
    assert!(parse_rev_list(&a, 10).is_err(), "unterminated");
    assert!(parse_rev_list(&format!("{a}\r\n"), 10).is_err());
    assert!(parse_rev_list("--output=x\n", 10).is_err());
    assert!(parse_rev_list(&format!("{}\n", "a".repeat(39)), 10).is_err());
    assert!(parse_rev_list(&format!("{a}\n\n"), 10).is_err());
    assert!(parse_rev_list(&format!("{a}\n{a}\n{a}\n"), 2).is_err());
    assert!(parse_rev_list(&format!("{a}\n{a}\n"), 2).is_ok());
}

// --- Tree export: ls-tree / cat-file parsing and writing -----------------------

fn oid(n: u8) -> String {
    format!("{n:02x}").repeat(20)
}

/// One `git ls-tree -r -z` record.
fn rec(mode: &str, kind: &str, oid: &str, path: &str) -> Vec<u8> {
    let mut out = format!("{mode} {kind} {oid}\t{path}").into_bytes();
    out.push(0);
    out
}

fn listing(records: &[Vec<u8>]) -> Vec<u8> {
    records.concat()
}

/// `git cat-file --batch` output for `(oid, bytes)` pairs.
fn batch(objects: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (oid, bytes) in objects {
        let header = format!("{oid} blob {}\n", bytes.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(bytes);
        out.push(b'\n');
    }
    out
}

fn entry(kind: EntryKind, oid: &str, path: &str) -> TreeEntry {
    TreeEntry {
        kind,
        oid: oid.into(),
        path: path.into(),
    }
}

fn write(
    entries: &[TreeEntry],
    objects: &[(&str, &[u8])],
    limits: &ExtractLimits,
) -> (tempfile::TempDir, Result<ExtractStats, String>) {
    let dest = tempfile::tempdir().unwrap();
    let blobs: BTreeMap<&str, &[u8]> = objects.iter().copied().collect();
    let result = write_tree(entries, &blobs, dest.path(), limits);
    (dest, result)
}

#[test]
fn ls_tree_parses_files_symlinks_and_submodules() {
    let out = listing(&[
        rec("100644", "blob", &oid(1), "src/lib.py"),
        rec("100755", "blob", &oid(2), "run.sh"),
        rec("120000", "blob", &oid(3), "link"),
        rec("160000", "commit", &oid(4), "vendor/sub"),
        rec("100644", "blob", &oid(5), "name with\ttab and spaces"),
    ]);
    let entries = parse_ls_tree(&out, 100).unwrap();
    assert_eq!(
        entries,
        vec![
            entry(EntryKind::File, &oid(1), "src/lib.py"),
            entry(EntryKind::Executable, &oid(2), "run.sh"),
            entry(EntryKind::Symlink, &oid(3), "link"),
            entry(EntryKind::Submodule, &oid(4), "vendor/sub"),
            entry(EntryKind::File, &oid(5), "name with\ttab and spaces"),
        ]
    );
    assert_eq!(parse_ls_tree(b"", 100).unwrap(), vec![]);
    let sha256 = "ab".repeat(32);
    let out = rec("100644", "blob", &sha256, "a");
    assert_eq!(parse_ls_tree(&out, 1).unwrap()[0].oid, sha256);
}

#[test]
fn ls_tree_rejects_malformed_records() {
    let good = rec("100644", "blob", &oid(1), "a");
    let unterminated = &good[..good.len() - 1];
    let no_tab = format!("100644 blob {}a\0", oid(1));
    let two_fields = format!("100644 {}\ta\0", oid(1));
    let four_fields = format!("100644 blob {} x\ta\0", oid(1));
    let double_space = format!("100644  blob {}\ta\0", oid(1));
    let cases: Vec<Vec<u8>> = vec![
        unterminated.to_vec(),
        no_tab.into_bytes(),
        two_fields.into_bytes(),
        four_fields.into_bytes(),
        double_space.into_bytes(),
        b"\0".to_vec(),
        [good.clone(), b"\0".to_vec()].concat(),
    ];
    for case in cases {
        assert!(
            parse_ls_tree(&case, 100).is_err(),
            "{}",
            String::from_utf8_lossy(&case)
        );
    }
}

#[test]
fn ls_tree_rejects_bad_object_ids() {
    for bad in [
        "a".repeat(39),
        "a".repeat(41),
        "A".repeat(40),
        "g".repeat(40),
        "a".repeat(63),
        format!("-{}", "a".repeat(39)),
        String::new(),
    ] {
        let out = rec("100644", "blob", &bad, "a");
        assert!(parse_ls_tree(&out, 100).is_err(), "{bad:?}");
    }
}

#[test]
fn ls_tree_rejects_unsafe_paths() {
    for bad in [
        "",
        "..",
        "../evil",
        "a/../../evil",
        "a/..",
        "/abs",
        "/tmp/vettalon-bisect-evil",
        "a//b",
        "a/",
        "./a",
        "a/./b",
        ".git",
        ".git/x",
        "sub/.git/config",
        ".GIT/hooks/x",
    ] {
        let out = rec("100644", "blob", &oid(1), bad);
        assert!(parse_ls_tree(&out, 100).is_err(), "{bad:?}");
        assert!(validate_tree_path(bad).is_err(), "{bad:?}");
    }
    for ok in [".gitignore", "a/.github/x", "x.git", "a b/ü.txt"] {
        assert!(validate_tree_path(ok).is_ok(), "{ok:?}");
    }
    // Device names and trailing '.' or ' ' are refused only on Windows.
    for windows_only in ["...", "a/CON", "a/nul.txt", "x/com1.py", "dir./a", "a "] {
        assert_eq!(
            validate_tree_path(windows_only).is_err(),
            cfg!(windows),
            "{windows_only:?}"
        );
    }
    let mut non_utf8 = format!("100644 blob {}\t", oid(1)).into_bytes();
    non_utf8.extend_from_slice(b"bad\xff.txt\0");
    let error = parse_ls_tree(&non_utf8, 100).unwrap_err();
    assert!(error.contains("UTF-8"), "{error}");
}

#[test]
fn windows_reserved_components_are_detected_on_every_platform() {
    for reserved in [
        "CON",
        "con",
        "Prn",
        "aux",
        "NUL",
        "nul.txt",
        "NUL.tar.gz",
        "CONIN$",
        "conout$",
        "CONOUT$.txt",
        "ConIn$ .log",
        "CON .txt",
        "com0",
        "COM1",
        "com9.py",
        "LPT0",
        "lpt5.log",
        "COM\u{b9}",
        "lpt\u{b2}.txt",
        "LPT\u{b3}",
        "trailing.",
        "trailing ",
        "...",
        "a.b.",
        " ",
    ] {
        assert!(is_windows_reserved_component(reserved), "{reserved:?}");
    }
    for ordinary in [
        "console",
        "CONFIG",
        "con_",
        "nul_device.txt",
        "auxiliary.py",
        "COM",
        "COM10",
        "LPT",
        "lpt12.txt",
        "COMx",
        "CONIN",
        "CONOUT",
        "CONIN$x",
        "x.CONIN$",
        "COM\u{b4}",
        "COM\u{2074}",
        ".gitignore",
        ".con",
        "x.CON",
        "a b.txt",
        "ü.txt",
        "com1x.py",
    ] {
        assert!(!is_windows_reserved_component(ordinary), "{ordinary:?}");
    }
}

#[test]
fn ls_tree_rejects_unknown_modes() {
    for (mode, kind) in [
        ("040000", "tree"),
        ("100664", "blob"),
        ("100600", "blob"),
        ("100644", "commit"),
        ("160000", "blob"),
        ("120000", "tree"),
        ("644", "blob"),
        ("", "blob"),
    ] {
        let out = rec(mode, kind, &oid(1), "a");
        assert!(parse_ls_tree(&out, 100).is_err(), "{mode} {kind}");
    }
}

#[test]
fn ls_tree_enforces_the_entry_cap() {
    let out = listing(&[
        rec("100644", "blob", &oid(1), "a"),
        rec("120000", "blob", &oid(2), "b"),
        rec("160000", "commit", &oid(3), "c"),
    ]);
    assert_eq!(parse_ls_tree(&out, 3).unwrap().len(), 3);
    assert!(parse_ls_tree(&out, 2).unwrap_err().contains("entries"));
    assert_eq!(ExtractLimits::default().max_entries, 200_000);
    assert_eq!(ExtractLimits::default().max_total_bytes, 512 * 1024 * 1024);
}

#[test]
fn cat_file_batch_parses_binary_blobs() {
    let (a, b, c) = (oid(1), oid(2), oid(3));
    let binary: &[u8] = b"\0\xff\n\r\nblob 3\n";
    let out = batch(&[(&a, b"hello"), (&b, binary), (&c, b"")]);
    let blobs = parse_cat_file_batch(&out, &[&a, &b, &c], 1024).unwrap();
    assert_eq!(blobs, vec![&b"hello"[..], binary, &b""[..]]);
    assert!(parse_cat_file_batch(b"", &[], 0).unwrap().is_empty());
}

#[test]
fn cat_file_batch_rejects_framing_errors() {
    let (a, b) = (oid(1), oid(2));
    let good = batch(&[(&a, b"hello")]);
    let huge = format!("{a} blob 99999999999999999999999\nhello\n");
    let cases: Vec<(Vec<u8>, &str)> = vec![
        // Missing object line.
        (format!("{a} missing\n").into_bytes(), "missing"),
        (Vec::new(), "empty output"),
        // Header for another object.
        (batch(&[(&b, b"hello")]), "wrong oid"),
        (format!("{a} tree 5\nhello\n").into_bytes(), "not a blob"),
        // Size mismatch, both ways.
        (
            format!("{a} blob 6\nhello\n").into_bytes(),
            "size too large",
        ),
        (
            format!("{a} blob 4\nhello\n").into_bytes(),
            "size too small",
        ),
        (
            format!("{a} blob 5\nhello").into_bytes(),
            "no trailing newline",
        ),
        (format!("{a} blob \nhello\n").into_bytes(), "empty size"),
        (format!("{a} blob +5\nhello\n").into_bytes(), "signed size"),
        (
            format!("{a} blob 5 \nhello\n").into_bytes(),
            "trailing space",
        ),
        (format!("{a} blob 5").into_bytes(), "unterminated header"),
        (huge.into_bytes(), "overflowing size"),
        ([good.clone(), b"extra".to_vec()].concat(), "trailing data"),
    ];
    for (out, why) in cases {
        assert!(parse_cat_file_batch(&out, &[&a], 1024).is_err(), "{why}");
    }
    assert!(parse_cat_file_batch(&good, &[&a, &b], 1024).is_err());
    assert!(parse_cat_file_batch(&good, &[&a], 1024).is_ok());
}

#[test]
fn cat_file_batch_enforces_the_size_cap() {
    let (a, b) = (oid(1), oid(2));
    let out = batch(&[(&a, &[b'a'; 6]), (&b, &[b'b'; 6])]);
    assert!(
        parse_cat_file_batch(&out, &[&a, &b], 11)
            .unwrap_err()
            .contains("bytes")
    );
    let blobs = parse_cat_file_batch(&out, &[&a, &b], 12).unwrap();
    assert_eq!(blobs, vec![&[b'a'; 6][..], &[b'b'; 6][..]]);
}

#[test]
fn writes_regular_files_and_skips_links_and_submodules() {
    let (a, b, c, s, g) = (oid(1), oid(2), oid(3), oid(4), oid(5));
    let entries = [
        entry(EntryKind::File, &a, "src/lib.py"),
        entry(EntryKind::Executable, &b, "run.sh"),
        entry(EntryKind::File, &c, "deep/nested/x.txt"),
        entry(EntryKind::File, &a, "deep/copy.py"),
        entry(EntryKind::Symlink, &s, "link"),
        entry(EntryKind::Submodule, &g, "vendor/sub"),
    ];
    let objects: [(&str, &[u8]); 3] = [(&a, b"print(1)\n"), (&b, b"#!/bin/sh\n"), (&c, b"x")];
    let (dest, result) = write(&entries, &objects, &ExtractLimits::default());
    let stats = result.unwrap();
    assert_eq!(stats.files, 4);
    assert_eq!(stats.dirs, 3);
    assert_eq!(stats.bytes, 9 + 10 + 1 + 9);
    assert_eq!(stats.skipped_symlinks, 1);
    assert_eq!(stats.skipped_submodules, 1);
    assert_eq!(stats.skipped_paths, vec!["link", "vendor/sub"]);
    assert!(!stats.skipped_paths_truncated);
    let root = dest.path();
    assert_eq!(
        std::fs::read(root.join("src/lib.py")).unwrap(),
        b"print(1)\n"
    );
    assert_eq!(
        std::fs::read(root.join("deep/copy.py")).unwrap(),
        b"print(1)\n"
    );
    assert_eq!(std::fs::read(root.join("deep/nested/x.txt")).unwrap(), b"x");
    assert!(std::fs::symlink_metadata(root.join("link")).is_err());
    assert!(!root.join("vendor").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &str| {
            std::fs::metadata(root.join(p))
                .unwrap()
                .permissions()
                .mode()
        };
        assert_ne!(mode("run.sh") & 0o100, 0);
        assert_eq!(mode("src/lib.py") & 0o111, 0);
    }
}

#[test]
fn skipped_paths_are_bounded_and_matched_by_component() {
    let a = oid(1);
    let mut entries: Vec<TreeEntry> = (0..MAX_SKIPPED_PATHS + 2)
        .map(|i| entry(EntryKind::Symlink, &a, &format!("l{i}")))
        .collect();
    entries.push(entry(EntryKind::Submodule, &oid(2), "vendor/sub"));
    let limits = ExtractLimits {
        max_total_bytes: 0,
        max_entries: entries.len(),
    };
    let (_dest, result) = write(&entries, &[], &limits);
    let stats = result.unwrap();
    assert_eq!(stats.skipped_symlinks, MAX_SKIPPED_PATHS + 2);
    assert_eq!(stats.skipped_submodules, 1);
    assert_eq!(stats.skipped_paths.len(), MAX_SKIPPED_PATHS);
    assert!(stats.skipped_paths_truncated);
    assert!(stats.skipped_covers("l0"));
    assert!(!stats.skipped_covers("vendor/sub"), "beyond the cap");

    let stats = ExtractStats {
        skipped_paths: vec!["app.py".into(), "vendor/sub".into()],
        ..ExtractStats::default()
    };
    for covered in ["app.py", "vendor/sub", "vendor/sub/x.py", "vendor/sub/a"] {
        assert!(stats.skipped_covers(covered), "{covered:?}");
    }
    for not_covered in ["app.py.bak", "vendor", "vendor/subx", "x/app.py"] {
        assert!(!stats.skipped_covers(not_covered), "{not_covered:?}");
    }
}

#[test]
fn write_refuses_duplicates_nesting_under_files_and_missing_blobs() {
    let a = oid(1);
    let objects: [(&str, &[u8]); 1] = [(&a, b"x")];
    let cases = [
        vec![
            entry(EntryKind::File, &a, "a.txt"),
            entry(EntryKind::File, &a, "a.txt"),
        ],
        vec![
            entry(EntryKind::File, &a, "a"),
            entry(EntryKind::File, &a, "a/b"),
        ],
        vec![
            entry(EntryKind::File, &a, "a/b"),
            entry(EntryKind::File, &a, "a"),
        ],
        vec![entry(EntryKind::File, &oid(9), "missing.txt")],
        vec![entry(EntryKind::File, &a, "../evil")],
    ];
    for entries in cases {
        let (dest, result) = write(&entries, &objects, &ExtractLimits::default());
        assert!(result.is_err(), "{entries:?}");
        assert!(!dest.path().parent().unwrap().join("evil").exists());
    }
}

#[test]
fn write_enforces_caps_before_creating_files() {
    let a = oid(1);
    let objects: [(&str, &[u8]); 1] = [(&a, &[b'a'; 6])];
    // One 6-byte blob written twice is 12 bytes on disk.
    let entries = [
        entry(EntryKind::File, &a, "a.txt"),
        entry(EntryKind::File, &a, "b.txt"),
    ];
    let small = ExtractLimits {
        max_total_bytes: 11,
        max_entries: 100,
    };
    let (dest, result) = write(&entries, &objects, &small);
    assert!(result.unwrap_err().contains("bytes"));
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);

    let few = ExtractLimits {
        max_total_bytes: 1024,
        max_entries: 1,
    };
    let (_dest, result) = write(&entries, &objects, &few);
    assert!(result.unwrap_err().contains("entries"));

    let enough = ExtractLimits {
        max_total_bytes: 12,
        max_entries: 2,
    };
    let (_dest, result) = write(&entries, &objects, &enough);
    assert_eq!(result.unwrap().bytes, 12);
}

// --- Sandbox runner ----------------------------------------------------------------

const TEST_SOURCE: &str = "# regression test body\n";

type Reply = fn(&Path) -> Result<(i64, String), String>;

/// Replays a canned answer; `@M@` in the output becomes the run's marker.
struct FakeSandbox {
    reply: Reply,
    runs: std::sync::Mutex<usize>,
}

impl FakeSandbox {
    fn new(reply: Reply) -> Self {
        Self {
            reply,
            runs: std::sync::Mutex::new(0),
        }
    }
}

#[async_trait::async_trait]
impl TargetSandbox for FakeSandbox {
    fn image_id(&self) -> &str {
        "sha256:fake"
    }

    async fn run(
        &self,
        tree: &Path,
        runner: &str,
        adapter: &str,
        input: &str,
    ) -> Result<(i64, String), String> {
        assert_eq!(adapter, TEST_SOURCE);
        assert!(runner.contains("/workspace/tree"));
        assert!(runner.contains("__VTL_REGRESSION__"));
        *self.runs.lock().unwrap() += 1;
        // The marker arrives on stdin only; the runner text never holds it.
        let marker = input.strip_suffix('\n').expect("one line on stdin");
        assert!(marker.starts_with("vtlm") && !marker.contains('\n'));
        assert!(!runner.contains(marker), "marker leaked into the runner");
        let (code, output) = (self.reply)(tree)?;
        Ok((code, output.replace("@M@", marker)))
    }
}

fn verdict(attack: &str, benign: &str) -> Result<(i64, String), String> {
    Ok((
        0,
        format!("\n__VTL_REGRESSION__ @M@ ran=2 skipped=0 attack={attack} benign={benign}\n"),
    ))
}

async fn evaluate_with(reply: Reply, with_target: bool) -> (StepResult, usize) {
    evaluate_with_stats(reply, with_target, &ExtractStats::default()).await
}

async fn evaluate_with_stats(
    reply: Reply,
    with_target: bool,
    stats: &ExtractStats,
) -> (StepResult, usize) {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir(tree.path().join("pkg")).unwrap();
    let mut stats = stats.clone();
    if with_target {
        std::fs::write(tree.path().join("pkg/app.py"), "def target(x): pass\n").unwrap();
        stats.written_files.insert("pkg/app.py".into());
    }
    let stats = &stats;
    let runner = SandboxStepRunner::new(
        tree.path(),
        "pkg/app.py",
        TEST_SOURCE.into(),
        FakeSandbox::new(reply),
    )
    .unwrap();
    let result = runner.evaluate(tree.path(), stats).await;
    let runs = *runner.sandbox.runs.lock().unwrap();
    (result, runs)
}

#[tokio::test]
async fn sandbox_runner_maps_verdicts() {
    const FORGED: &str = "__VTL_REGRESSION__ forged ran=2 skipped=0 attack=fail benign=pass\n";
    let cases: [(Reply, StepResult); 11] = [
        // A valid marked line from a run that did not exit 0 is no verdict.
        (
            |_| Ok((3, verdict("fail", "pass")?.1)),
            u("regression_test_execution_error"),
        ),
        // A forged line glued in front of the real one: two marked prefixes.
        (
            |_| {
                let real = verdict("pass", "pass")?.1;
                let forged = "\n__VTL_REGRESSION__ @M@ ran=2 skipped=0 attack=fail benign=pass\nZ";
                Ok((0, format!("{forged}{}", real.trim_start())))
            },
            u("duplicate_regression_verdict"),
        ),
        (|_| verdict("fail", "pass"), F),
        (|_| verdict("pass", "pass"), P),
        (|_| verdict("error", "pass"), u("attack_test_error")),
        (|_| verdict("fail", "fail"), u("benign_not_passing")),
        (|_| verdict("pass", "error"), u("benign_not_passing")),
        (
            |_| Ok((0, "no verdict\n".into())),
            u("regression_verdict_missing"),
        ),
        (|_| Ok((0, FORGED.into())), u("regression_verdict_missing")),
        (
            |_| Ok((1, "Traceback\n".into())),
            u("regression_test_execution_error"),
        ),
        (
            |_| Err("target_poc_budget_exhausted".into()),
            u("sandbox:target_poc_budget_exhausted"),
        ),
    ];
    for (reply, expected) in cases {
        let (result, runs) = evaluate_with(reply, true).await;
        assert_eq!(result, expected);
        assert_eq!(runs, 1);
    }
}

#[tokio::test]
async fn sandbox_runner_reports_a_missing_target_without_running() {
    let (result, runs) = evaluate_with(|_| verdict("fail", "pass"), false).await;
    assert_eq!(result, u(TARGET_MISSING));
    assert_eq!(runs, 0);
    // Other skipped entries that do not cover the target change nothing.
    let unrelated = ExtractStats {
        skipped_paths: vec!["pkg/app.py.bak".into(), "pkg/app".into(), "vendor".into()],
        ..ExtractStats::default()
    };
    let (result, runs) = evaluate_with_stats(attack_fails, false, &unrelated).await;
    assert_eq!(result, u(TARGET_MISSING));
    assert_eq!(runs, 0);
}

#[tokio::test]
async fn target_presence_is_decided_from_exact_tree_entries_not_the_file_system() {
    let a = oid(1);
    let objects: [(&str, &[u8]); 1] = [(&a, b"def target(x): pass\n")];
    let entries = [entry(EntryKind::File, &a, "src/foo.py")];
    let (dest, result) = write(&entries, &objects, &ExtractLimits::default());
    let stats = result.unwrap();
    assert_eq!(
        stats.written_files.iter().collect::<Vec<_>>(),
        ["src/foo.py"]
    );
    // The target differs from the tree entry only by case: whether or not
    // the host file system aliases the two names, the target is missing.
    let runner = SandboxStepRunner::new(
        dest.path(),
        "src/Foo.py",
        TEST_SOURCE.into(),
        FakeSandbox::new(attack_fails),
    )
    .unwrap();
    let result = runner.evaluate(dest.path(), &stats).await;
    assert_eq!(result, u(TARGET_MISSING));
    assert_eq!(*runner.sandbox.runs.lock().unwrap(), 0);
    // The exact name runs.
    let runner = SandboxStepRunner::new(
        dest.path(),
        "src/foo.py",
        TEST_SOURCE.into(),
        FakeSandbox::new(attack_fails),
    )
    .unwrap();
    assert_eq!(runner.evaluate(dest.path(), &stats).await, F);
    assert_eq!(*runner.sandbox.runs.lock().unwrap(), 1);
}

fn attack_fails(_: &Path) -> Result<(i64, String), String> {
    verdict("fail", "pass")
}

#[tokio::test]
async fn sandbox_runner_reports_a_symlink_or_submodule_target_as_not_regular() {
    // The target itself is a skipped symlink; or `pkg` is a submodule (or a
    // symlinked directory) containing it.
    for skipped in ["pkg/app.py", "pkg"] {
        let stats = ExtractStats {
            skipped_paths: vec![skipped.into()],
            ..ExtractStats::default()
        };
        let (result, runs) = evaluate_with_stats(attack_fails, false, &stats).await;
        assert_eq!(result, u(TARGET_NOT_REGULAR), "{skipped:?}");
        assert_eq!(runs, 0);
    }
    // Past the skipped-path cap a missing target cannot be classified.
    let truncated = ExtractStats {
        skipped_paths_truncated: true,
        ..ExtractStats::default()
    };
    let (result, runs) = evaluate_with_stats(attack_fails, false, &truncated).await;
    assert_eq!(result, u(TARGET_UNVERIFIED));
    assert_eq!(runs, 0);
    // A regular target runs regardless of what else was skipped.
    let (result, runs) = evaluate_with_stats(attack_fails, true, &truncated).await;
    assert_eq!(result, F);
    assert_eq!(runs, 1);
}

#[tokio::test]
async fn sandbox_errors_are_sanitized_and_truncated() {
    let (result, _) = evaluate_with(
        |_| {
            Err(format!(
                "Docker said: /Users/x/\u{1b}[31mBOOM\n{}",
                "z".repeat(200)
            ))
        },
        true,
    )
    .await;
    let StepResult::Unrunnable(reason) = result else {
        panic!("expected unrunnable");
    };
    assert!(reason.len() <= MAX_REASON_LEN, "{reason}");
    assert!(
        reason.starts_with("sandbox:docker_said:_users_x_"),
        "{reason}"
    );
    assert!(
        reason
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_:-".contains(&b)),
        "{reason}"
    );
}

#[test]
fn reason_sanitizer() {
    assert_eq!(sanitize_reason("target_missing"), TARGET_MISSING);
    assert_eq!(sanitize_reason("Syntax Error!"), "syntax_error");
    assert_eq!(sanitize_reason("  a\n\tb  "), "a_b");
    assert_eq!(sanitize_reason(""), "unrunnable");
    assert_eq!(sanitize_reason("日本語"), "unrunnable");
    assert_eq!(sanitize_reason(&"x".repeat(100)).len(), MAX_REASON_LEN);
}

#[test]
fn runner_construction_and_container_cap() {
    let ok = |file: &str| {
        SandboxStepRunner::new(
            Path::new("/r"),
            file,
            TEST_SOURCE.into(),
            FakeSandbox::new(|_| verdict("fail", "pass")),
        )
        .is_ok()
    };
    assert!(ok("app.py") && ok("pkg/app.py"));
    assert!(!ok("../app.py") && !ok("/etc/passwd") && !ok(""));
    let huge = "x".repeat(MAX_TEST_BYTES as usize + 1);
    assert!(
        SandboxStepRunner::new(
            Path::new("/r"),
            "app.py",
            huge,
            FakeSandbox::new(|_| verdict("fail", "pass")),
        )
        .is_err()
    );
    assert_eq!(container_cap(DEFAULT_MAX_STEPS), DEFAULT_MAX_STEPS + 3);
    assert_eq!(container_cap(0), 4);
    assert_eq!(container_cap(1000), MAX_STEPS_LIMIT + 3);
}

// --- Real Git --------------------------------------------------------------------

fn git_in(repo: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[tokio::test]
#[ignore = "needs the git binary"]
async fn sandbox_runner_bisects_a_real_repo_with_a_fake_sandbox() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = std::fs::canonicalize(tmp.path()).unwrap();
    git_in(&repo, &["init", "-q"]);
    // c0: no target; c1, c2: safe; c3, c4: vulnerable.
    for i in 0..5 {
        std::fs::write(repo.join("README"), format!("r{i}")).unwrap();
        if i >= 1 {
            let body = if i >= 3 { "VULN\n" } else { "safe\n" };
            std::fs::write(repo.join("app.py"), body).unwrap();
        }
        git_in(&repo, &["add", "-A"]);
        let message = format!("c{i}");
        git_in(&repo, &["commit", "-q", "-m", message.as_str()]);
    }
    let commits = first_parent_range(&repo, None, "HEAD", MAX_COMMITS)
        .await
        .unwrap()
        .commits;
    let sandbox = FakeSandbox::new(|tree| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(tree).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        let body = std::fs::read_to_string(tree.join("app.py")).unwrap();
        if body.contains("VULN") {
            verdict("fail", "pass")
        } else {
            verdict("pass", "pass")
        }
    });
    let runner = SandboxStepRunner::new(&repo, "app.py", TEST_SOURCE.into(), sandbox);
    let mut runner = runner.unwrap();
    let result = bisect(&commits, None, &mut runner, DEFAULT_MAX_STEPS).await;
    assert_eq!(
        result.outcome,
        BisectOutcome::IntroducedIn {
            commit: commits[3].clone(),
            last_passing: Some(commits[2].clone()),
        }
    );
    assert!(!result.non_monotonic);
    assert!(
        result
            .steps
            .iter()
            .any(|s| s.index == 0 && s.result == u(TARGET_MISSING))
    );
    assert!(*runner.sandbox.runs.lock().unwrap() <= container_cap(DEFAULT_MAX_STEPS));
    assert_eq!(git_in(&repo, &["status", "--porcelain"]), "");
}

#[tokio::test]
#[ignore = "needs the git binary"]
async fn symlink_and_submodule_targets_are_not_regular_on_a_real_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = std::fs::canonicalize(tmp.path()).unwrap();
    git_in(&repo, &["init", "-q"]);
    // c0: app.py is a symlink (120000) and vendor is a gitlink (160000),
    // both written straight to the index so no real link or submodule is
    // needed. c1: app.py becomes a regular file.
    std::fs::write(repo.join("real.py"), "VULN\n").unwrap();
    git_in(&repo, &["add", "real.py"]);
    let blob = git_in(&repo, &["rev-parse", ":real.py"]);
    let symlink = format!("120000,{},app.py", blob.trim());
    let gitlink = format!("160000,{},vendor", "a".repeat(40));
    git_in(&repo, &["update-index", "--add", "--cacheinfo", &symlink]);
    git_in(&repo, &["update-index", "--add", "--cacheinfo", &gitlink]);
    git_in(&repo, &["commit", "-q", "-m", "c0"]);
    git_in(&repo, &["rm", "-q", "--cached", "app.py"]);
    std::fs::write(repo.join("app.py"), "VULN\n").unwrap();
    git_in(&repo, &["add", "app.py"]);
    git_in(&repo, &["commit", "-q", "-m", "c1"]);
    let range = first_parent_range(&repo, None, "HEAD", MAX_COMMITS)
        .await
        .unwrap();
    let commits = range.commits;
    assert_eq!(commits.len(), 2);

    let dest = tempfile::tempdir().unwrap();
    let stats = export_tree(&repo, &commits[0], dest.path()).await.unwrap();
    assert_eq!(stats.skipped_paths, vec!["app.py", "vendor"]);

    let step = |target: &str| {
        let sandbox = FakeSandbox::new(|_| verdict("fail", "pass"));
        SandboxStepRunner::new(&repo, target, TEST_SOURCE.into(), sandbox).unwrap()
    };
    let mut runner = step("app.py");
    assert_eq!(runner.run(&commits[0]).await, u(TARGET_NOT_REGULAR));
    assert_eq!(runner.run(&commits[1]).await, F);
    assert_eq!(*runner.sandbox.runs.lock().unwrap(), 1);
    let mut runner = step("vendor/lib/x.py");
    assert_eq!(runner.run(&commits[0]).await, u(TARGET_NOT_REGULAR));
    let mut runner = step("absent.py");
    assert_eq!(runner.run(&commits[0]).await, u(TARGET_MISSING));
    assert_eq!(*runner.sandbox.runs.lock().unwrap(), 0);
}

#[tokio::test]
#[ignore = "needs the git binary"]
async fn first_parent_range_and_export_tree_on_a_real_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = std::fs::canonicalize(tmp.path()).unwrap();
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    };
    git(&["init", "-q"]);
    for i in 0..5 {
        std::fs::write(repo.join("f.txt"), format!("v{i}")).unwrap();
        if i == 2 {
            std::fs::create_dir_all(repo.join("sub")).unwrap();
            std::fs::write(repo.join("sub/new.txt"), "new").unwrap();
        }
        git(&["add", "-A"]);
        let message = format!("c{i}");
        git(&["commit", "-q", "-m", message.as_str()]);
    }

    let full = first_parent_range(&repo, None, "HEAD", MAX_COMMITS)
        .await
        .unwrap();
    let all = full.commits;
    assert_eq!(all.len(), 5);
    assert_eq!(all[4].as_str(), git(&["rev-parse", "HEAD"]).trim());
    assert_eq!(full.bad, all[4]);
    assert_eq!(full.good, None);
    assert_eq!(
        all[0].as_str(),
        git(&["rev-list", "--max-parents=0", "HEAD"]).trim()
    );
    let tail = first_parent_range(&repo, Some("HEAD~3"), "HEAD", MAX_COMMITS)
        .await
        .unwrap();
    assert_eq!(tail.commits, all[2..].to_vec());
    // The bounds the range used are the ids reported back (resolved once).
    assert_eq!(tail.good.as_ref(), Some(&all[1]));
    assert_eq!(tail.bad, all[4]);
    assert!(first_parent_range(&repo, None, "HEAD", 4).await.is_err());
    assert!(
        first_parent_range(&repo, Some("-x"), "HEAD", 10)
            .await
            .is_err()
    );
    assert!(
        first_parent_range(&repo, Some("HEAD"), "HEAD~1", 10)
            .await
            .is_err()
    );
    assert!(
        first_parent_range(&repo, Some("HEAD"), "HEAD", 10)
            .await
            .is_err()
    );
    assert!(
        first_parent_range(&repo, None, "no-such-ref", 10)
            .await
            .is_err()
    );

    let dest = tempfile::tempdir().unwrap();
    export_tree(&repo, &all[1], dest.path()).await.unwrap();
    assert_eq!(
        std::fs::read_to_string(dest.path().join("f.txt")).unwrap(),
        "v1"
    );
    assert!(!dest.path().join("sub").exists());
    assert!(!dest.path().join(".git").exists());
    // A used destination is refused; the working tree and index are untouched.
    assert!(export_tree(&repo, &all[3], dest.path()).await.is_err());
    let fresh = tempfile::tempdir().unwrap();
    export_tree(&repo, &all[3], fresh.path()).await.unwrap();
    assert_eq!(
        std::fs::read_to_string(fresh.path().join("sub/new.txt")).unwrap(),
        "new"
    );
    assert_eq!(std::fs::read_to_string(repo.join("f.txt")).unwrap(), "v4");
    assert_eq!(git(&["status", "--porcelain"]), "");

    // In-tree .gitattributes are ignored: no `$Format$` expansion, no hiding,
    // no filters. Symlinks are skipped, never created.
    std::fs::write(
        repo.join(".gitattributes"),
        "* export-subst\nhidden.txt export-ignore\n",
    )
    .unwrap();
    std::fs::write(repo.join("subst.txt"), "$Format:%H$\n").unwrap();
    std::fs::write(repo.join("hidden.txt"), "still here").unwrap();
    std::fs::write(repo.join("bin.dat"), b"\0\xff\r\n\x80raw").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", repo.join("escape")).unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "attrs"]);
    let head = CommitId::parse(git(&["rev-parse", "HEAD"]).trim()).unwrap();
    let attrs = tempfile::tempdir().unwrap();
    let stats = export_tree(&repo, &head, attrs.path()).await.unwrap();
    assert_eq!(
        std::fs::read_to_string(attrs.path().join("subst.txt")).unwrap(),
        "$Format:%H$\n"
    );
    assert_eq!(
        std::fs::read_to_string(attrs.path().join("hidden.txt")).unwrap(),
        "still here"
    );
    assert_eq!(
        std::fs::read(attrs.path().join("bin.dat")).unwrap(),
        b"\0\xff\r\n\x80raw"
    );
    assert!(attrs.path().join(".gitattributes").is_file());
    assert!(std::fs::symlink_metadata(attrs.path().join("escape")).is_err());
    #[cfg(unix)]
    assert_eq!(stats.skipped_symlinks, 1);
    assert_eq!(stats.skipped_submodules, 0);
    // .gitattributes, bin.dat, f.txt, hidden.txt, sub/new.txt, subst.txt
    assert_eq!(stats.files, 6);
    assert_eq!(stats.dirs, 1);
    assert_eq!(git(&["status", "--porcelain"]), "");
}
