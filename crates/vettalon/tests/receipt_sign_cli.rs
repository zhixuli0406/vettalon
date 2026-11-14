//! `vettalon receipt sign` / `receipt verify` end to end with a real cosign v3
//! and a throwaway local key. Run with `cargo test -- --ignored`.
//!
//! The key refusal tests are not ignored: a remote, KMS or missing key is
//! refused (exit 2) before cosign is looked up, so they need no cosign.

use std::path::Path;
use std::process::{Command, Output};

/// A minimal `reproduce --out` receipt (inconclusive, nothing executed).
const RECEIPT: &str = r#"{"version":1,"outcome":"inconclusive","phases":[],"target_file":"src/app.py","target_function":"run","target_plan_sha256":null,"target_file_sha256":null,"source_sha256":null,"exclusions":null,"adapter_sha256":null,"image_id":null,"reason":"sandbox_unavailable"}"#;

fn vettalon(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vettalon"))
        .current_dir(dir)
        .env("COSIGN_PASSWORD", "")
        .args(args)
        .output()
        .unwrap()
}

const REMOTE_KEYS: [&str; 6] = [
    "https://example.com/cosign.pub",
    "evil://x",
    "env://COSIGN_KEY",
    "awskms:///alias/key",
    "pkcs11:token=t",
    "hashivault:key",
];

fn refused_before_cosign(output: &Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(expected), "{stderr}");
    assert!(!stderr.contains("FAILED"), "{stderr}");
}

#[test]
fn sign_refuses_remote_and_missing_keys_with_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path();
    std::fs::write(work.join("receipt.json"), RECEIPT).unwrap();
    for key in REMOTE_KEYS {
        let out = vettalon(work, &["receipt", "sign", "receipt.json", "--key", key]);
        refused_before_cosign(&out, "must be a local key file");
    }
    let out = vettalon(
        work,
        &["receipt", "sign", "receipt.json", "--key", "missing.key"],
    );
    refused_before_cosign(&out, "cannot be resolved");
    assert!(!work.join("receipt.json.sigstore.json").exists());
}

#[test]
fn verify_refuses_remote_and_missing_keys_with_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path();
    std::fs::write(work.join("receipt.json"), RECEIPT).unwrap();
    std::fs::write(work.join("bundle.json"), "{}").unwrap();
    for key in REMOTE_KEYS.into_iter().chain(["missing.pub"]) {
        let args = [
            "receipt",
            "verify",
            "receipt.json",
            "--key",
            key,
            "--bundle",
            "bundle.json",
        ];
        let expected = if key == "missing.pub" {
            "cannot be resolved"
        } else {
            "must be a local key file"
        };
        refused_before_cosign(&vettalon(work, &args), expected);
    }
}

#[tokio::test]
#[ignore = "needs cosign v3 on PATH"]
async fn sign_then_verify_detects_a_changed_receipt() {
    if std::env::var_os("VETTALON_RECEIPT_LIVE_CHILD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sign_then_verify_detects_a_changed_receipt",
                "--ignored",
                "--nocapture",
            ])
            .env("VETTALON_RECEIPT_LIVE_CHILD", "1")
            .env("COSIGN_PASSWORD", "")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path();
    let Ok(tool) = vettalon::attest::cosign::Cosign::locate(work, &[]).await else {
        eprintln!("skipping: trusted cosign v3 is not available");
        return;
    };
    tool.run(&["generate-key-pair"], work).await.unwrap();
    assert!(work.join("cosign.key").exists() && work.join("cosign.pub").exists());

    let receipt = work.join("receipt.json");
    std::fs::write(&receipt, RECEIPT).unwrap();

    let sign = vettalon(
        work,
        &["receipt", "sign", "receipt.json", "--key", "cosign.key"],
    );
    let stderr = String::from_utf8_lossy(&sign.stderr);
    assert_eq!(sign.status.code(), Some(0), "{stderr}");
    let bundle = work.join("receipt.json.sigstore.json");
    assert!(bundle.exists(), "{stderr}");

    let verify_args = [
        "receipt",
        "verify",
        "receipt.json",
        "--key",
        "cosign.pub",
        "--bundle",
        "receipt.json.sigstore.json",
    ];
    let verify = vettalon(work, &verify_args);
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert_eq!(verify.status.code(), Some(0), "{stderr}");
    assert!(String::from_utf8_lossy(&verify.stdout).contains("verified"));

    let again = vettalon(
        work,
        &["receipt", "sign", "receipt.json", "--key", "cosign.key"],
    );
    assert_ne!(
        again.status.code(),
        Some(0),
        "a second sign must not overwrite"
    );
    assert!(bundle.exists());

    let mut bytes = std::fs::read(&receipt).unwrap();
    let index = bytes.iter().position(|b| *b == b'1').unwrap();
    bytes[index] = b'2';
    std::fs::write(&receipt, bytes).unwrap();
    let tampered = vettalon(work, &verify_args);
    assert_ne!(
        tampered.status.code(),
        Some(0),
        "a changed receipt must not verify"
    );
}
