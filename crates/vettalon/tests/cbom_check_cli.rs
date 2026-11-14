//! `vettalon cbom-check` end to end on the checked-in CBOMkit fixture.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/cbom")
}

fn run(extra: &[&str]) -> Output {
    let base = fixtures();
    Command::new(env!("CARGO_BIN_EXE_vettalon"))
        .arg("cbom-check")
        .arg("--cbom")
        .arg(base.join("sample-py.cbomkit.json"))
        .arg("--root")
        .arg(base.join("sample-py"))
        .args(extra)
        .output()
        .expect("run vettalon")
}

fn receipt(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn labels_match_the_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("receipt.json");
    let o = run(&["--json", out.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("NOT proof"), "{text}");
    assert!(text.contains("no VEX is emitted"), "{text}");

    let r = receipt(&out);
    assert_eq!(r["schema"], "vettalon.cbom-check/2");
    assert_eq!(r["project"]["languages"], serde_json::json!(["python"]));
    assert_eq!(r["project"]["java_files"], 0);
    assert_eq!(
        r["analysis"],
        "name-based static, over-approximate, not execution evidence"
    );
    assert_eq!(r["cbom"]["spec_version"], "1.6");
    let rows = r["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    let want = [
        ("RSA-2048", 8, "reachable"),
        ("private-key@c20c7e7b", 8, "reachable"),
        ("EC-secp256r1", 13, "not_observed"),
        ("private-key@2a817308", 13, "not_observed"),
        // `encrypt` is never called, but `AESGCM(key).encrypt(...)` is a
        // textual reference to the name: unknown, never not_observed
        ("AES-256-GCM", 17, "unknown"),
        ("secret-key@6385bfb6", 17, "unknown"),
    ];
    for (name, line, label) in want {
        let row = rows
            .iter()
            .find(|x| x["name"].as_str().unwrap().starts_with(name))
            .unwrap_or_else(|| panic!("no row {name}"));
        assert_eq!(row["line"], line, "{name}");
        assert_eq!(row["label"], label, "{name}");
        assert_eq!(row["file"], "app/keys.py", "{name}");
    }
    // material rows name their algorithm through `dependencies`
    let key = rows
        .iter()
        .find(|x| x["name"].as_str().unwrap().starts_with("secret-key@"))
        .unwrap();
    assert_eq!(key["algorithm"], "AES-256-GCM");
    assert_eq!(key["quantum_vulnerable"], false);
    let aes = rows.iter().find(|x| x["name"] == "AES-256-GCM").unwrap();
    assert_eq!(aes["reasons"][0], "referenced_but_no_entry_path");
    assert_eq!(r["summary"]["by_label"]["reachable"], 2);
    assert_eq!(r["summary"]["by_label"]["not_observed"], 2);
    assert_eq!(r["summary"]["by_label"]["unknown"], 2);
    assert_eq!(r["project"]["not_observed_blocked"], serde_json::json!([]));
    assert!(r.get("vex").is_none());
    assert!(!String::from_utf8_lossy(&std::fs::read(&out).unwrap()).contains("not_affected"));
}

fn run_java(extra: &[&str]) -> Output {
    let base = fixtures().join("sample-java");
    Command::new(env!("CARGO_BIN_EXE_vettalon"))
        .arg("cbom-check")
        .arg("--cbom")
        .arg(base.join("hand.cbom.json"))
        .arg("--root")
        .arg(&base)
        .args(extra)
        .output()
        .expect("run vettalon")
}

fn java_labels(r: &serde_json::Value) -> Vec<(String, String)> {
    r["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["name"].as_str().unwrap().to_string(),
                x["label"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn java_fixture_labels() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("receipt.json");
    let o = run_java(&["--json", out.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let r = receipt(&out);
    assert_eq!(r["schema"], "vettalon.cbom-check/2");
    assert_eq!(r["project"]["languages"], serde_json::json!(["java"]));
    assert_eq!(r["project"]["java_files"], 4);
    assert_eq!(r["project"]["py_files"], 0);
    assert_eq!(r["project"]["not_observed_blocked"], serde_json::json!([]));
    assert_eq!(
        java_labels(&r),
        [
            ("AES-GCM".to_string(), "reachable".to_string()),
            ("MD5".to_string(), "not_observed".to_string())
        ],
        "reasons: {:?}",
        r["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["reasons"].clone())
            .collect::<Vec<_>>()
    );
    let rows = r["rows"].as_array().unwrap();
    assert_eq!(rows[0]["file"], "src/main/java/com/ex/Crypto.java");
    assert_eq!(rows[0]["line"], 7);
    assert_eq!(rows[1]["file"], "src/main/java/com/ex/Unused.java");
}

#[test]
fn java_entry_specs() {
    let o = run_java(&["--entry", "com.ex.Nope:main"]);
    assert_eq!(o.status.code(), Some(2));
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("entry.json");
    let o = run_java(&[
        "--entry",
        "com.ex.Main:main",
        "--json",
        out.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let r = receipt(&out);
    assert_eq!(r["entries"][0], "com.ex.Main:main");
    assert_eq!(java_labels(&r)[0].1, "reachable");
    // an entry makes an otherwise unreferenced method reachable
    let out = dir.path().join("legacy.json");
    let o = run_java(&[
        "--entry",
        "com.ex.Unused:legacy",
        "--json",
        out.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(java_labels(&receipt(&out))[1].1, "reachable");
}

#[test]
fn json_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("receipt.json");
    std::fs::write(&out, "keep me").unwrap();
    let o = run(&["--json", out.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "keep me");
    // the temp file used for the atomic write is gone
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn too_many_occurrences_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let occs = vec![r#"{"location":"a.py","line":1}"#; 10_000].join(",");
    let comp = format!(r#"{{"cryptoProperties":{{}},"evidence":{{"occurrences":[{occs}]}}}}"#);
    let doc = format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{}]}}"#,
        vec![comp; 21].join(",")
    );
    let p = dir.path().join("big.json");
    std::fs::write(&p, doc).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_vettalon"))
        .args(["cbom-check", "--cbom"])
        .arg(&p)
        .arg("--root")
        .arg(fixtures().join("sample-py"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("more than 200000 occurrences"), "{err}");
}

#[test]
fn receipt_hash_is_stable_across_runs() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a.json"), dir.path().join("b.json"));
    assert!(run(&["--json", a.to_str().unwrap()]).status.success());
    assert!(run(&["--json", b.to_str().unwrap()]).status.success());
    let (ra, rb) = (receipt(&a), receipt(&b));
    let hash = ra["receipt_sha256"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert_eq!(ra["receipt_sha256"], rb["receipt_sha256"]);
    assert_eq!(ra["root_tree_sha256"], rb["root_tree_sha256"]);
}

#[test]
fn bad_inputs_exit_2() {
    let base = fixtures();
    let o = Command::new(env!("CARGO_BIN_EXE_vettalon"))
        .args(["cbom-check", "--cbom"])
        .arg(base.join("sample-py/requirements.txt"))
        .arg("--root")
        .arg(base.join("sample-py"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["--entry", "app.nothing:missing"]);
    assert_eq!(o.status.code(), Some(2));
    // an entry point turns an unreferenced function reachable
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("entry.json");
    let o = run(&[
        "--entry",
        "app.keys:legacy_ecdsa_key",
        "--json",
        out.to_str().unwrap(),
    ]);
    assert!(o.status.success());
    let r = receipt(&out);
    let ec = r["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "EC-secp256r1")
        .unwrap();
    assert_eq!(ec["label"], "reachable");
    assert_eq!(ec["chain"][0], "--entry app.keys:legacy_ecdsa_key");
    assert_eq!(r["entries"][0], "app.keys:legacy_ecdsa_key");
}

#[test]
fn java_sweep_lists_missing_and_listed_calls() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("sweep.json");
    let o = run_java(&["--sweep", "--json", out.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let r = receipt(&out);
    let rows = r["sweep"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let unlisted = rows
        .iter()
        .find(|r| r["file"].as_str().unwrap().ends_with("/Unlisted.java"))
        .unwrap();
    assert_eq!(unlisted["in_cbom"], false);
    assert_eq!(unlisted["algorithm"], "SHA-256");
    assert_eq!(unlisted["label"], "not_observed");
    let listed = rows
        .iter()
        .find(|r| r["file"].as_str().unwrap().ends_with("/Crypto.java"))
        .unwrap();
    assert_eq!(listed["in_cbom"], true);
    assert_eq!(listed["label"], "reachable");
    assert_eq!(listed["mode"], "GCM");
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(
        text.contains("sweep: 3 rows, 1 not_in_cbom, truncated false"),
        "{text}"
    );
    let off = dir.path().join("off.json");
    assert!(
        run_java(&["--json", off.to_str().unwrap()])
            .status
            .success()
    );
    let off = receipt(&off);
    assert!(off.get("sweep").is_none());
    assert_eq!(r["rows"], off["rows"]);
    assert_eq!(r["project"], off["project"]);
}
