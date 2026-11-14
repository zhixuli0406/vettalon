//! Offline package CLI acceptance; no Docker, network or cosign required.
#![cfg(unix)]
use std::path::Path;
use std::process::{Command, Output};
use vettalon::audit::retest_package::engagement::parse_engagement;

const RECEIPT: &str = r#"{"version":1,"outcome":"inconclusive","phases":[],"target_file":"src/app.py","target_function":"run","target_plan_sha256":null,"target_file_sha256":null,"source_sha256":null,"exclusions":null,"adapter_sha256":null,"image_id":null,"reason":"sandbox_unavailable"}"#;

fn cli(dir: &Path, args: &[&str], code: i32) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_vettalon"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn package_cli_build_verify_tamper_and_template() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join("receipt.json"), RECEIPT).unwrap();
    for lang in ["zh-TW", "en"] {
        let template = cli(
            &root,
            &["receipt", "engagement-template", "--lang", lang],
            0,
        );
        let parsed = parse_engagement(&template.stdout).unwrap();
        assert!(parsed.finding.is_empty());
        std::fs::write(root.join("engagement.toml"), template.stdout).unwrap();
    }
    let built = cli(
        &root,
        &[
            "receipt",
            "package",
            "--reproduce",
            "receipt.json",
            "--out",
            "package",
            "--engagement",
            "engagement.toml",
            "--lang",
            "both",
        ],
        0,
    );
    assert!(String::from_utf8_lossy(&built.stdout).contains("sha256:"));
    let verified = cli(&root, &["receipt", "verify-package", "package"], 0);
    assert!(String::from_utf8_lossy(&verified.stdout).contains("re-render checked"));
    cli(
        &root,
        &[
            "receipt",
            "package",
            "--reproduce",
            "receipt.json",
            "--out",
            "package",
        ],
        2,
    );
    for zip in ["first.zip", "second.zip"] {
        cli(
            &root,
            &[
                "receipt",
                "package",
                "--reproduce",
                "receipt.json",
                "--out",
                zip,
                "--zip",
            ],
            0,
        );
        cli(&root, &["receipt", "verify-package", zip], 0);
    }
    assert_eq!(
        std::fs::read(root.join("first.zip")).unwrap(),
        std::fs::read(root.join("second.zip")).unwrap()
    );
    std::fs::write(root.join("package/extra"), "x").unwrap();
    cli(&root, &["receipt", "verify-package", "package"], 1);
    std::fs::remove_file(root.join("package/extra")).unwrap();
    let manifest_path = root.join("package/manifest.json");
    let original = std::fs::read(&manifest_path).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_slice(&original).unwrap();
    manifest["vettalon_version"] = "999.0.0".into();
    let bytes = format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap());
    std::fs::write(&manifest_path, bytes).unwrap();
    cli(&root, &["receipt", "verify-package", "package"], 3);
    std::fs::write(&manifest_path, original).unwrap();
    let md = root.join("package/record.en.md");
    let mut bytes = std::fs::read(&md).unwrap();
    bytes[0] ^= 1;
    std::fs::write(md, bytes).unwrap();
    cli(&root, &["receipt", "verify-package", "package"], 1);
    std::os::unix::fs::symlink(&root, root.join("alias")).unwrap();
    cli(
        &root,
        &[
            "receipt",
            "package",
            "--reproduce",
            "receipt.json",
            "--out",
            "alias/nope",
        ],
        2,
    );
    assert!(!root.join("nope").exists());
    let receipt = root.join("package/receipts/reproduce/receipt.json");
    std::fs::remove_file(&receipt).unwrap();
    std::os::unix::fs::symlink(root.join("receipt.json"), receipt).unwrap();
    cli(&root, &["receipt", "verify-package", "package"], 2);
}

#[test]
fn package_cli_refuses_unsafe_zip_members() {
    use std::io::{Cursor, Write};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for (filename, names) in [
        ("parent.zip", vec!["../escape"]),
        ("duplicate.zip", vec!["aa", "bb"]),
    ] {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for name in names {
            zip.start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
            zip.write_all(b"x").unwrap();
        }
        let mut bytes = zip.finish().unwrap().into_inner();
        if filename == "duplicate.zip" {
            for i in 0..bytes.len() - 1 {
                if &bytes[i..i + 2] == b"bb" {
                    bytes[i..i + 2].copy_from_slice(b"aa");
                }
            }
        }
        std::fs::write(root.join(filename), bytes).unwrap();
        cli(&root, &["receipt", "verify-package", filename], 2);
    }
    assert!(!root.join("escape").exists());
}

#[test]
fn package_cli_refuses_forged_verified_claim_without_a_key() {
    use vettalon::audit::schema::sha256_hex;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join("receipt.json"), RECEIPT).unwrap();
    cli(
        &root,
        &[
            "receipt",
            "package",
            "--reproduce",
            "receipt.json",
            "--out",
            "package",
        ],
        0,
    );
    cli(&root, &["receipt", "verify-package", "package"], 0);
    let record_path = root.join("package/record.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    record["sources"][0]["signature"] = serde_json::json!({
        "path": "signatures/forged.json",
        "sha256": "0".repeat(64),
        "subject_ok": true,
        "cosign": { "verified": true, "key_sha256": "0".repeat(64), "cosign_version": "v3.0.4" }
    });
    let record = format!("{}\n", serde_json::to_string_pretty(&record).unwrap());
    std::fs::write(&record_path, &record).unwrap();
    let manifest_path = root.join("package/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let entry = manifest["files"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["path"] == "record.json")
        .unwrap();
    entry["sha256"] = sha256_hex(record.as_bytes()).into();
    entry["bytes"] = record.len().into();
    std::fs::write(
        &manifest_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
    )
    .unwrap();
    let refused = cli(&root, &["receipt", "verify-package", "package"], 2);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("package_signature_key_required"));
    std::fs::write(root.join("key.pub"), "trusted public key").unwrap();
    let refused = cli(
        &root,
        &["receipt", "verify-package", "package", "--key", "key.pub"],
        2,
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("package_signature_key_mismatch"));
}

#[test]
fn hybrid_package_cli_verifies_both_layers_and_refuses_false_claims() {
    use std::os::unix::fs::PermissionsExt;
    use vettalon::attest::{extract, pq, statement};
    use vettalon::audit::{
        retest_package::{verify, write},
        schema::sha256_hex,
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let tools = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tools.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let fake = |name: &str, body: &str| {
        let path = tools.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    };
    fake(
        "cosign",
        &format!(
            "case \"$1\" in version) printf 'GitVersion: '; cat '{}' ;; verify-blob-attestation) exit 0 ;; *) exit 9 ;; esac",
            root.join("version").display()
        ),
    );
    let openssl = fake(
        "openssl",
        &format!(
            "case \"$1\" in version) echo 'OpenSSL 3.6.4 date' ;; list) echo ML-DSA-65 ;; pkeyutl) if [ -f '{}' ]; then echo 'Signature Verification Failure'; exit 1; fi; echo 'Signature Verified Successfully' ;; *) exit 9 ;; esac",
            root.join("openssl-fail").display()
        ),
    );
    std::fs::write(root.join("version"), "v3.1.3\n").unwrap();
    std::fs::write(root.join("receipt.json"), RECEIPT).unwrap();
    std::fs::write(root.join("cosign.pub"), "trusted cosign key").unwrap();
    let extracted = extract(RECEIPT).unwrap();
    let payload = statement::build_statement(
        "receipt.json",
        RECEIPT.as_bytes(),
        extracted.kind,
        &extracted.predicate,
    )
    .to_string();
    let bundle = serde_json::json!({
        "mediaType": statement::BUNDLE_MEDIA_TYPE_V03,
        "verificationMaterial": {"publicKey": {"hint": "test"}},
        "dsseEnvelope": {"payloadType": statement::DSSE_PAYLOAD_TYPE,
            "payload": statement::encode_base64_std(payload.as_bytes()), "signatures": [{"sig":"AAAA"}]}
    });
    std::fs::write(root.join("bundle.json"), bundle.to_string()).unwrap();
    let mut der = vec![
        0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
    ];
    der.resize(1974, 0x42);
    let pem = |bytes: &[u8]| {
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            statement::encode_base64_std(bytes)
        )
    };
    std::fs::write(root.join("mldsa.pub"), pem(&der)).unwrap();
    let sidecar = pq::Sidecar {
        algorithm: "ML-DSA-65".into(),
        message: "dsse-pae-v1".into(),
        schema: "vettalon.receipt-mldsa/1".into(),
        openssl_version: "OpenSSL 3.6.4".into(),
        public_key_sha256: sha256_hex(&der),
        receipt_sha256: sha256_hex(RECEIPT.as_bytes()),
        statement_sha256: sha256_hex(payload.as_bytes()),
        signature: statement::encode_base64_std(&vec![0x42; pq::SIGNATURE_BYTES]),
    };
    std::fs::write(root.join("pq.json"), sidecar.canonical_bytes().unwrap()).unwrap();
    let run = |args: &[&str], code: i32| {
        let output = Command::new(env!("CARGO_BIN_EXE_vettalon"))
            .current_dir(&root)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    tools.path().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("VETTALON_OPENSSL", &openssl)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    run(
        &[
            "receipt",
            "package",
            "--reproduce",
            "receipt.json",
            "--pq-sig",
            "pq.json",
            "--pq-pub",
            "mldsa.pub",
            "--out",
            "requires-key",
        ],
        2,
    );
    let build = [
        "receipt",
        "package",
        "--reproduce",
        "receipt.json",
        "--bundle",
        "bundle.json",
        "--pq-sig",
        "pq.json",
        "--key",
        "cosign.pub",
        "--pq-pub",
        "mldsa.pub",
        "--out",
        "hybrid",
    ];
    run(&build, 0);
    let verify_args = [
        "receipt",
        "verify-package",
        "hybrid",
        "--key",
        "cosign.pub",
        "--pq-pub",
        "mldsa.pub",
    ];
    run(&verify_args, 0);
    for lang in ["en", "zh-TW"] {
        let md = std::fs::read_to_string(root.join(format!("hybrid/record.{lang}.md"))).unwrap();
        assert!(md.contains("ML-DSA-65"));
    }
    assert!(root.join("hybrid/signatures-pq/pq.json").is_file());
    assert!(root.join("hybrid/keys/mldsa.pub").is_file());
    let missing_key = run(
        &["receipt", "verify-package", "hybrid", "--key", "cosign.pub"],
        2,
    );
    assert!(String::from_utf8_lossy(&missing_key.stderr).contains("package_pq_key_required"));
    // Auditor tool patch/minor versions may differ; stored producer version stays intact.
    std::fs::write(root.join("version"), "v3.2.0\n").unwrap();
    run(&verify_args, 0);
    let original = verify::read_package(&root.join("hybrid")).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&original["record.json"]).unwrap();
    assert_eq!(
        record["sources"][0]["signature"]["cosign"]["cosign_version"],
        "v3.1.3"
    );
    for version in [
        "v2.9.0",
        "v3.0.3",
        "v3",
        "v3.foo",
        "v3.0.0-rc.1",
        "v30.0.0",
        "v3.0.0+build",
    ] {
        std::fs::write(root.join("version"), format!("{version}\n")).unwrap();
        run(&verify_args, 2);
    }
    std::fs::write(root.join("version"), "v3.2.0\n").unwrap();
    der[100] ^= 1;
    std::fs::write(root.join("wrong.pub"), pem(&der)).unwrap();
    let wrong = run(
        &[
            "receipt",
            "verify-package",
            "hybrid",
            "--key",
            "cosign.pub",
            "--pq-pub",
            "wrong.pub",
        ],
        2,
    );
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("package_pq_key_mismatch"));
    // Verification failure from OpenSSL is never replaced with the stored claim.
    std::fs::write(root.join("openssl-fail"), "fail").unwrap();
    let failed = run(&verify_args, 2);
    assert!(String::from_utf8_lossy(&failed.stderr).contains("package_pq_claim_mismatch"));
    std::fs::remove_file(root.join("openssl-fail")).unwrap();
    let mut no_sidecar = build.to_vec();
    no_sidecar.drain(6..8);
    no_sidecar[11] = "missing";
    run(&no_sidecar, 2);
    assert!(!root.join("missing").exists());
    let missing = run(
        &[
            "receipt",
            "package",
            "--reproduce",
            "receipt.json",
            "--bundle",
            "bundle.json",
            "--key",
            "cosign.pub",
            "--out",
            "no-pq",
        ],
        0,
    );
    assert!(missing.status.success());
    // A supplied PQ key requires coverage of every bundle, including unsigned gaps.
    let other = RECEIPT.replace("src/app.py", "src/other.py");
    std::fs::write(root.join("other.json"), &other).unwrap();
    let extracted = extract(&other).unwrap();
    let payload = statement::build_statement(
        "other.json",
        other.as_bytes(),
        extracted.kind,
        &extracted.predicate,
    )
    .to_string();
    let mut other_bundle = bundle.clone();
    other_bundle["dsseEnvelope"]["payload"] =
        statement::encode_base64_std(payload.as_bytes()).into();
    std::fs::write(root.join("other-bundle.json"), other_bundle.to_string()).unwrap();
    let partial = run(
        &[
            "receipt",
            "package",
            "--reproduce",
            "receipt.json",
            "--reproduce",
            "other.json",
            "--bundle",
            "bundle.json",
            "--bundle",
            "other-bundle.json",
            "--pq-sig",
            "pq.json",
            "--key",
            "cosign.pub",
            "--pq-pub",
            "mldsa.pub",
            "--out",
            "partial",
        ],
        2,
    );
    assert!(String::from_utf8_lossy(&partial.stderr).contains("pq_signature_missing"));
    assert!(!root.join("partial").exists());

    // Change a claim, reseal, and ensure semantic checks still refuse it.
    let mut files = original.clone();
    let mut forged = record.clone();
    forged["sources"][0]["signature"]["mldsa"]["verified"]["verified"] = false.into();
    let mut bytes = serde_json::to_vec_pretty(&forged).unwrap();
    bytes.push(b'\n');
    files.insert("record.json".into(), bytes);
    // Update only manifest hashes using the same external-tamper helper below.
    let reseal = |files: &mut write::Files| {
        let mut manifest: write::Manifest =
            serde_json::from_slice(&files["manifest.json"]).unwrap();
        for entry in &mut manifest.files {
            entry.sha256 = sha256_hex(&files[&entry.path]);
            entry.bytes = files[&entry.path].len() as u64;
        }
        let mut bytes =
            serde_json::to_vec_pretty(&serde_json::to_value(manifest).unwrap()).unwrap();
        bytes.push(b'\n');
        files.insert("manifest.json".into(), bytes);
    };
    reseal(&mut files);
    let write_dir = |name: &str, files: &write::Files| {
        let dest = root.join(name);
        std::fs::create_dir(&dest).unwrap();
        for (path, bytes) in files {
            let path = dest.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
    };
    write_dir("forged", &files);
    run(
        &[
            "receipt",
            "verify-package",
            "forged",
            "--key",
            "cosign.pub",
            "--pq-pub",
            "mldsa.pub",
        ],
        2,
    );
    for field in ["binding_ok", "sha256", "path"] {
        let mut files = original.clone();
        let mut forged = record.clone();
        forged["sources"][0]["signature"]["mldsa"][field] = match field {
            "binding_ok" => false.into(),
            "sha256" => "0".repeat(64).into(),
            _ => "signatures-pq/forged.json".into(),
        };
        let mut bytes = serde_json::to_vec_pretty(&forged).unwrap();
        bytes.push(b'\n');
        files.insert("record.json".into(), bytes);
        reseal(&mut files);
        let name = format!("forged-{field}");
        write_dir(&name, &files);
        let refused = run(
            &[
                "receipt",
                "verify-package",
                &name,
                "--key",
                "cosign.pub",
                "--pq-pub",
                "mldsa.pub",
            ],
            2,
        );
        assert!(String::from_utf8_lossy(&refused.stderr).contains("package_pq_claim_mismatch"));
    }
    let mut files = original.clone();
    let mut forged = record.clone();
    forged["sources"][0]["signature"]["cosign"] = serde_json::Value::Null;
    let mut bytes = serde_json::to_vec_pretty(&forged).unwrap();
    bytes.push(b'\n');
    files.insert("record.json".into(), bytes);
    reseal(&mut files);
    write_dir("pq-only-claim", &files);
    let forged = run(&["receipt", "verify-package", "pq-only-claim"], 2);
    assert!(String::from_utf8_lossy(&forged.stderr).contains("package_pq_key_required"));
    std::fs::write(root.join("hybrid/signatures-pq/pq.json"), "tampered").unwrap();
    let tampered = run(&verify_args, 1);
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("package_hash_mismatch"));
}
