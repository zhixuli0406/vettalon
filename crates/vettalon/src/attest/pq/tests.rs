use super::super::statement::{BUNDLE_MEDIA_TYPE_V03, DSSE_PAYLOAD_TYPE, build_statement};
use super::*;
use serde_json::json;

fn public_der() -> Vec<u8> {
    let mut der = SPKI_PREFIX.to_vec();
    der.resize(SPKI_BYTES, 0x42);
    der
}

fn public_pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        encode_base64_std(der)
    )
}

fn receipt() -> String {
    json!({"version":1,"outcome":"inconclusive","phases":[],"target_file":"src/app.py",
        "target_function":"run","target_plan_sha256":null,"target_file_sha256":null,
        "source_sha256":null,"exclusions":null,"adapter_sha256":null,"image_id":null,
        "reason":"sandbox_unavailable"})
    .to_string()
}

fn bundle(receipt: &str) -> Vec<u8> {
    let extracted = super::super::extract(receipt).unwrap();
    let statement = build_statement(
        "receipt.json",
        receipt.as_bytes(),
        extracted.kind,
        &extracted.predicate,
    );
    json!({"mediaType":BUNDLE_MEDIA_TYPE_V03,"verificationMaterial":{"publicKey":{"hint":"test"}},
        "dsseEnvelope":{"payloadType":DSSE_PAYLOAD_TYPE,"payload":encode_base64_std(statement.to_string().as_bytes()),
        "signatures":[{"sig":"AAAA"}]}}).to_string().into_bytes()
}

fn sidecar() -> Sidecar {
    Sidecar {
        algorithm: "ML-DSA-65".into(),
        message: "dsse-pae-v1".into(),
        schema: "vettalon.receipt-mldsa/1".into(),
        openssl_version: "OpenSSL 3.6.4".into(),
        public_key_sha256: sha256_hex(&public_der()),
        receipt_sha256: sha256_hex(receipt().as_bytes()),
        statement_sha256: sha256_hex(&decode_bundle_payload(&bundle(&receipt())).unwrap()),
        signature: encode_base64_std(&vec![0; SIGNATURE_BYTES]),
    }
}

#[test]
fn pq_version_and_capability_are_exact() {
    for version in ["3.5.0", "3.6.4", "4.0.3", "3.5.0a"] {
        assert_eq!(
            require_supported_version(&format!("OpenSSL {version} date\n")),
            Ok(format!("OpenSSL {version}"))
        );
    }
    for version in [
        "OpenSSL 3.4.0",
        "OpenSSL 5.0.0",
        "LibreSSL 3.3.6",
        "",
        "garbage",
        "OpenSSL 3.5",
        "OpenSSL 3.5.x",
        "OpenSSL 3.5.0.1",
        "OpenSSL 3.5.0\u{1b}",
    ] {
        assert!(require_supported_version(version).is_err(), "{version}");
    }
    assert!(has_mldsa65(
        "{ 2.16.840.1.101.3.4.3.18, id-ml-dsa-65, ML-DSA-65, MLDSA65 } @ fips"
    ));
    for caps in ["ML-DSA-65X", "id-ml-dsa-65", "MLDSA65", "ML-DSA-44"] {
        assert!(!has_mldsa65(caps));
    }
    assert!(resolve_program(Some(std::ffi::OsStr::new("relative/openssl"))).is_err());
    assert!(
        resolve_program(Some(std::ffi::OsStr::new("/nonexistent/vettalon-openssl")))
            .unwrap_err()
            .contains(MISSING)
    );
    assert!(resolve_on_path(None).is_err());
    assert!(
        resolve_on_path(Some(std::ffi::OsStr::new(
            "relative:/nonexistent/vettalon-bin"
        )))
        .is_err()
    );
    assert_eq!(OPENSSL_TIMEOUT.as_secs(), 60);
}

#[test]
fn pq_pae_golden_and_base64_roundtrip() {
    assert_eq!(
        dsse_pae(b"{}"),
        b"DSSEv1 28 application/vnd.in-toto+json 2 {}"
    );
    assert_eq!(
        dsse_pae("台".as_bytes()),
        "DSSEv1 28 application/vnd.in-toto+json 3 台".as_bytes()
    );
    assert_eq!(dsse_pae(b""), b"DSSEv1 28 application/vnd.in-toto+json 0 ");
    for sample in [&b"f"[..], b"fo", b"foo", b"foob", b"\xff\xfe\0"] {
        assert_eq!(
            decode_base64_strict(&encode_base64_std(sample)).unwrap(),
            sample
        );
    }
    assert_eq!(encode_base64_std(b""), "");
    assert_eq!(encode_base64_std(b"foobar"), "Zm9vYmFy");
}

#[test]
fn pq_public_pem_shape_and_line_endings() {
    let der = public_der();
    let pem = public_pem(&der);
    assert_eq!(parse_mldsa65_pub_pem(pem.as_bytes()).unwrap(), der);
    assert_eq!(
        parse_mldsa65_pub_pem(pem.trim_end().as_bytes()).unwrap(),
        der
    );
    assert_eq!(
        parse_mldsa65_pub_pem(pem.replace('\n', "\r\n").as_bytes()).unwrap(),
        der
    );
    for invalid in [
        format!("{pem}{pem}"),
        format!("{pem}junk"),
        format!("\n{pem}"),
        format!("{pem}\n"),
        pem.replacen('\n', "\r\n", 1),
        public_pem(&der[..1973]),
        public_pem(&[0x30; 44]),
        "x".repeat(8193),
    ] {
        assert!(parse_mldsa65_pub_pem(invalid.as_bytes()).is_err());
    }
    assert!(parse_mldsa65_pub_pem(pem.replacen("\nM", "\n M", 1).as_bytes()).is_err());
    for oid in [0x11, 0x13, 0x70] {
        let mut wrong = der.clone();
        wrong[16] = oid;
        assert!(parse_mldsa65_pub_pem(public_pem(&wrong).as_bytes()).is_err());
    }
    let mut trailing = der;
    trailing.push(0);
    assert!(check_public_der(&trailing).is_err());
}

#[test]
fn pq_sidecar_closed_canonical_schema() {
    let good = sidecar();
    let bytes = good.canonical_bytes().unwrap();
    assert!(bytes.len() < SIDECAR_MAX_BYTES);
    Sidecar::parse(&bytes).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["signature"]
            .as_str()
            .unwrap()
            .len(),
        4412
    );
    let raw = String::from_utf8(bytes.clone()).unwrap();
    for invalid in [
        raw.trim_end().to_owned(),
        raw.replace("  ", "    "),
        raw.replacen('{', "{\n  \"extra\": true,", 1),
        raw.replacen('{', "{\n  \"algorithm\": \"ML-DSA-65\",", 1),
        raw.replace("ML-DSA-65", "ML-DSA-44"),
        raw.replace("dsse-pae-v1", "statement-v1"),
        raw.replace("vettalon.receipt-mldsa/1", "vettalon.receipt-mldsa/2"),
        raw.replace(
            &good.public_key_sha256,
            &good.public_key_sha256.to_uppercase(),
        ),
        " ".repeat(SIDECAR_MAX_BYTES + 1),
    ] {
        assert!(Sidecar::parse(invalid.as_bytes()).is_err());
    }
    for len in [3308, 3310] {
        let mut bad = good.clone();
        bad.signature = encode_base64_std(&vec![0; len]);
        assert!(bad.canonical_bytes().is_err());
    }
    for label in ["\n", "é", &"a".repeat(65)] {
        let mut bad = good.clone();
        bad.openssl_version = label.into();
        assert!(bad.canonical_bytes().is_err());
    }
    let mut informational = good.clone();
    informational.openssl_version = "another printable version".into();
    Sidecar::parse(&informational.canonical_bytes().unwrap()).unwrap();
}

#[test]
fn pq_fixed_argv_and_password_source_only() {
    for (present, source) in [(true, "env:VETTALON_PQ_KEY_PASSWORD"), (false, "pass:")] {
        assert_eq!(passin_for(present), source);
        assert_eq!(
            derive_args("/key", source),
            [
                "pkey", "-inform", "PEM", "-in", "/key", "-passin", source, "-pubout", "-outform",
                "DER"
            ]
        );
        assert_eq!(
            sign_args("/key", source, "/pae", "/sig"),
            [
                "pkeyutl", "-sign", "-inkey", "/key", "-keyform", "PEM", "-passin", source,
                "-rawin", "-in", "/pae", "-out", "/sig"
            ]
        );
    }
    assert_eq!(
        verify_args("/pub", "/pae", "/sig"),
        [
            "pkeyutl", "-verify", "-pubin", "-inkey", "/pub", "-keyform", "DER", "-rawin", "-in",
            "/pae", "-sigfile", "/sig"
        ]
    );
}

#[cfg(unix)]
mod subprocess {
    use super::super::super::{sign_receipt_with_tools, verify_receipt_with_tools};
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    fn fake_bin(bin_dir: &Path, root: &Path, name: &str, body: &str) -> String {
        std::fs::set_permissions(bin_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = bin_dir.join(name);
        let log = root.join(format!("{name}.log"));
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\nprintf '%s\\n' --END-- >> {}\n{body}\n",
                quote(&log),
                quote(&log)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().into()
    }

    struct Fixture {
        dir: tempfile::TempDir,
        _tools: tempfile::TempDir,
        root: PathBuf,
        openssl: String,
        cosign: String,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let tools = tempfile::tempdir().unwrap();
            for (name, bytes) in [
                ("public.der", public_der()),
                ("public.pem", public_pem(&public_der()).into_bytes()),
                ("signature", vec![0; SIGNATURE_BYTES]),
                ("receipt.json", receipt().into_bytes()),
                ("fixture.bundle", bundle(&receipt())),
                ("key.pem", b"private-placeholder".to_vec()),
            ] {
                std::fs::write(root.join(name), bytes).unwrap();
            }
            let openssl = fake_bin(
                tools.path(),
                &root,
                "openssl",
                &format!(
                    r#"
r={root}
/usr/bin/env > "$r/env-$1-$2"
case "$1" in
 version) if [ -f "$r/version" ]; then cat "$r/version"; else echo 'OpenSSL 3.6.4 date'; fi ;;
 list) if [ -f "$r/no-caps" ]; then echo ML-DSA-65X; else echo '{{ ML-DSA-65 }} @ default'; fi ;;
 pkey) cat "$r/public.der" ;;
 pkeyutl)
  mode=$2
  while [ "$#" -gt 0 ]; do
   case "$1" in -in) input=$2; shift ;; -out) output=$2; shift ;; -inkey) key=$2; shift ;; -sigfile) sig=$2; shift ;; esac
   shift
  done
  cp "$input" "$r/observed.pae"
  if [ "$mode" = -sign ]; then cp "$r/signature" "$output"; exit 0; fi
  cp "$key" "$r/observed.der"
  cp "$sig" "$r/observed.sig"
  if [ -f "$r/block-sidecar" ]; then echo occupied > "$r/receipt.json.mldsa.json"; fi
  if [ -f "$r/oversized" ]; then head -c 262145 /dev/zero; exit 0; fi
  if [ -f "$r/unexpected" ]; then echo unexpected; exit 1; fi
  if [ -f "$r/exit3" ]; then echo 'Signature Verification Failure'; exit 3; fi
  if [ -f "$r/verify-fail" ]; then echo 'Signature Verification Failure'; exit 1; fi
  echo 'Signature Verified Successfully' ;;
 *) exit 9 ;;
esac
"#,
                    root = quote(&root)
                ),
            );
            let cosign = fake_bin(
                tools.path(),
                &root,
                "cosign",
                &format!(
                    r#"
r={root}
/usr/bin/env > "$r/cosign-env-$1"
/usr/bin/stat -c '%a' "$HOME" > "$r/cosign-home-mode-$1" 2>/dev/null || /usr/bin/stat -f '%Lp' "$HOME" > "$r/cosign-home-mode-$1"
case "$1" in
 version) echo 'GitVersion: v3.1.3' ;;
 attest-blob)
  while [ "$#" -gt 0 ]; do
   if [ "$1" = --bundle ]; then cp "$r/fixture.bundle" "$2"; exit 0; fi
   shift
  done
  exit 8 ;;
 verify-blob-attestation) if [ -f "$r/cosign-fail" ]; then exit 1; fi ;;
 *) exit 9 ;;
esac
"#,
                    root = quote(&root)
                ),
            );
            Self {
                dir,
                _tools: tools,
                root,
                openssl,
                cosign,
            }
        }
        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }
        fn mark(&self, name: &str) {
            std::fs::write(self.path(name), "x").unwrap();
        }
        async fn sign(&self) -> Result<super::super::super::Signed, String> {
            sign_receipt_with_tools(
                &self.path("receipt.json"),
                &self.path("key.pem"),
                None,
                Some((&self.path("key.pem"), None)),
                Some((&self.cosign, &self.openssl)),
            )
            .await
        }
        async fn verify(&self) -> Result<super::super::super::Verified, AttestError> {
            verify_receipt_with_tools(
                &self.path("receipt.json"),
                &self.path("key.pem"),
                &self.path("receipt.json.sigstore.json"),
                Some((
                    &self.path("public.pem"),
                    &self.path("receipt.json.mldsa.json"),
                )),
                Some((&self.cosign, &self.openssl)),
            )
            .await
        }
        fn calls(&self, tool: &str) -> Vec<Vec<String>> {
            std::fs::read_to_string(self.path(&format!("{tool}.log")))
                .unwrap_or_default()
                .split("--END--\n")
                .filter(|s| !s.is_empty())
                .map(|s| s.lines().map(str::to_owned).collect())
                .collect()
        }
    }

    #[tokio::test]
    async fn pq_refuses_writable_executable_and_ancestors() {
        for (file_mode, dir_mode) in [
            (0o755, 0o775),
            (0o775, 0o700),
            (0o1775, 0o700),
            (0o755, 0o777),
            (0o777, 0o700),
            (0o1777, 0o700),
        ] {
            let f = Fixture::new();
            std::fs::set_permissions(&f.openssl, std::fs::Permissions::from_mode(file_mode))
                .unwrap();
            std::fs::set_permissions(f._tools.path(), std::fs::Permissions::from_mode(dir_mode))
                .unwrap();
            let error = Openssl::probe(&f.openssl, &f.root, &[]).await.unwrap_err();
            let message = error.to_string();
            let mode = if file_mode == 0o755 {
                dir_mode
            } else {
                file_mode
            };
            let path = if file_mode == 0o755 {
                f._tools.path()
            } else {
                Path::new(&f.openssl)
            };
            let permission = if mode & 0o002 != 0 {
                "world-writable"
            } else {
                "group-writable"
            };
            assert!(message.contains(permission), "{message}");
            assert!(message.contains(path.to_str().unwrap()), "{message}");
            assert!(message.contains(&format!("mode {mode:04o}")), "{message}");
            assert!(message.contains("install -d -m 0700"), "{message}");
            assert!(
                message.contains("VETTALON_COSIGN or VETTALON_OPENSSL"),
                "{message}"
            );
            assert!(f.calls("openssl").is_empty());
            assert!(
                super::super::super::cosign::Cosign::probe(&f.openssl, &f.root, &[])
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn pq_refuses_executable_in_cwd_receipt_and_repository() {
        let f = Fixture::new();
        let cwd = std::env::current_dir().unwrap();
        let local = tempfile::tempdir_in(&cwd).unwrap();
        let program = fake_bin(local.path(), &f.root, "openssl", "echo 'OpenSSL 3.6.4'");
        let error = Openssl::probe(&program, &f.root, &[]).await.unwrap_err();
        assert!(error.to_string().contains("inside the working"), "{error}");
        assert!(f.calls("openssl").is_empty());

        let program = fake_bin(&f.root, &f.root, "openssl", "echo 'OpenSSL 3.6.4'");
        let error = Openssl::probe(&program, f._tools.path(), &[&f.root])
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("receipt or repository"),
            "{error}"
        );
        // A sibling of the receipt directory inside a worktree is also refused.
        std::fs::write(f.path(".git"), "gitdir: /unused").unwrap();
        let receipts = f.path("receipts");
        std::fs::create_dir(&receipts).unwrap();
        let error = Openssl::probe(&program, f._tools.path(), &[&receipts])
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("receipt or repository"),
            "{error}"
        );
        assert!(f.calls("openssl").is_empty());

        // Exercise the receipt entry point, including cosign's identical policy.
        let mut f = Fixture::new();
        f.openssl = fake_bin(&f.root, &f.root, "openssl", "echo 'OpenSSL 3.6.4'");
        assert!(
            f.sign()
                .await
                .unwrap_err()
                .contains("receipt or repository")
        );
        assert!(f.calls("openssl").is_empty());
        let mut f = Fixture::new();
        f.cosign = fake_bin(&f.root, &f.root, "cosign", "echo 'GitVersion: v3.1.3'");
        assert!(
            f.sign()
                .await
                .unwrap_err()
                .contains("receipt or repository")
        );
        assert!(f.calls("cosign").is_empty());
    }

    #[tokio::test]
    async fn pq_refuses_inode_swap_before_invocation() {
        let f = Fixture::new();
        let tool = Openssl::probe(&f.openssl, &f.root, &[]).await.unwrap();
        assert_eq!(f.calls("openssl").len(), 2);
        let replacement = fake_bin(
            f._tools.path(),
            &f.root,
            "replacement",
            "echo 'Signature Verified Successfully'",
        );
        std::fs::rename(replacement, &f.openssl).unwrap();
        let out = run_attestation_subprocess(
            &tool.program,
            &["pkeyutl", "-verify"],
            &f.root,
            &SubprocessLimits::default(),
            AttestationEnv::Openssl { private_key: false },
        )
        .await;
        assert!(out.spawn_error.unwrap().contains("identity changed"));
        assert!(f.calls("replacement").is_empty());
        assert_eq!(f.calls("openssl").len(), 2);

        let cosign = super::super::super::cosign::Cosign::probe(&f.cosign, &f.root, &[])
            .await
            .unwrap();
        let replacement = fake_bin(f._tools.path(), &f.root, "replacement", "exit 0");
        std::fs::rename(replacement, &f.cosign).unwrap();
        let error = cosign
            .run(&["verify-blob-attestation"], &f.root)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("identity changed"));
        assert!(f.calls("replacement").is_empty());
    }

    #[test]
    fn pq_poisoned_environment_is_not_inherited() {
        // A separate test process supplies hostile environment values without
        // mutating the multithreaded test runner's process-global environment.
        let f = Fixture::new();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env("VETTALON_COSIGN", &f.cosign)
            .args([
                "--exact",
                "attest::pq::tests::subprocess::pq_environment_child",
                "--nocapture",
            ])
            .env("VETTALON_PQ_ENV_TEST", "1")
            .env("VETTALON_PQ_KEY_PASSWORD", "pq-test-password")
            .env("COSIGN_PASSWORD", "cosign-test-password")
            .env("HOME", "/untrusted/home")
            .env("SIGSTORE_ROOT_FILE", "/untrusted/root.json")
            .env("TUF_ROOT", "/untrusted/tuf")
            .env("OPENSSL_CONF", "/untrusted/openssl.cnf")
            .env("OPENSSL_CONF_INCLUDE", "/untrusted")
            .env("OPENSSL_MODULES", "/untrusted")
            .env("OPENSSL_ENGINES", "/untrusted")
            .env("OPENSSL_TEST_UNKNOWN", "poison")
            .env("LD_PRELOAD", "")
            .env("LD_LIBRARY_PATH", "/untrusted")
            .env("DYLD_INSERT_LIBRARIES", "")
            .env("DYLD_LIBRARY_PATH", "/untrusted")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[tokio::test]
    async fn pq_environment_child() {
        if std::env::var_os("VETTALON_PQ_ENV_TEST").is_none() {
            return;
        }
        let f = Fixture::new();
        let located = super::super::super::cosign::Cosign::locate(&f.root, &[])
            .await
            .unwrap();
        assert_eq!(located.version, "v3.1.3");
        f.sign().await.unwrap();
        f.verify().await.unwrap();
        for (name, private) in [
            ("version-", false),
            ("list--signature-algorithms", false),
            ("pkey--inform", true),
            ("pkeyutl--sign", true),
            ("pkeyutl--verify", false),
        ] {
            let env = std::fs::read_to_string(f.path(&format!("env-{name}"))).unwrap();
            assert!(
                env.lines().any(|line| line == "OPENSSL_CONF="),
                "{name}: {env}"
            );
            assert!(env.lines().any(|line| line == "PATH=/usr/bin:/bin"));
            assert!(env.lines().any(|line| line == "LANG=C"));
            assert!(env.lines().any(|line| line == "LC_ALL=C"));
            for line in env.lines() {
                let (key, value) = line.split_once('=').unwrap();
                assert!(
                    !key.starts_with("LD_") && !key.starts_with("DYLD_"),
                    "{name}: {key}"
                );
                assert!(
                    !key.starts_with("OPENSSL_") || (key == "OPENSSL_CONF" && value.is_empty())
                );
                assert_ne!(key, "HOME");
                assert_ne!(key, "COSIGN_PASSWORD");
            }
            assert_eq!(
                env.lines()
                    .any(|line| line == "VETTALON_PQ_KEY_PASSWORD=pq-test-password"),
                private,
                "{name}"
            );
        }
        for (name, private) in [
            ("version", false),
            ("attest-blob", true),
            ("verify-blob-attestation", false),
        ] {
            let env = std::fs::read_to_string(f.path(&format!("cosign-env-{name}"))).unwrap();
            for line in env.lines() {
                let (key, _) = line.split_once('=').unwrap();
                assert!(
                    matches!(
                        key,
                        "PATH"
                            | "LANG"
                            | "LC_ALL"
                            | "HOME"
                            | "PWD"
                            | "SHLVL"
                            | "_"
                            | "COSIGN_PASSWORD"
                    ),
                    "{key}"
                );
                assert!(!key.starts_with("LD_") && !key.starts_with("DYLD_"));
            }
            for expected in ["PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"] {
                assert!(env.lines().any(|line| line == expected));
            }
            assert_eq!(
                env.lines()
                    .any(|line| line == "COSIGN_PASSWORD=cosign-test-password"),
                private
            );
            let home = env
                .lines()
                .find_map(|line| line.strip_prefix("HOME="))
                .unwrap();
            assert!(home.contains("vettalon-cosign-home-"));
            assert!(!Path::new(home).exists(), "private HOME must be cleaned up");
            assert_eq!(
                std::fs::read_to_string(f.path(&format!("cosign-home-mode-{name}")))
                    .unwrap()
                    .trim(),
                "700"
            );
        }
    }

    #[tokio::test]
    async fn pq_fake_sign_verify_fixed_argv_staged_bytes_and_permissions() {
        let f = Fixture::new();
        let signed = f.sign().await.unwrap();
        assert!(signed.pq.is_some());
        assert!(f.verify().await.unwrap().pq_verified);
        let pae = dsse_pae(&decode_bundle_payload(&bundle(&receipt())).unwrap());
        assert_eq!(std::fs::read(f.path("observed.pae")).unwrap(), pae);
        assert_eq!(std::fs::read(f.path("observed.der")).unwrap(), public_der());
        assert_eq!(
            std::fs::read(f.path("observed.sig")).unwrap(),
            vec![0; SIGNATURE_BYTES]
        );
        for name in ["receipt.json.sigstore.json", "receipt.json.mldsa.json"] {
            assert_eq!(
                std::fs::metadata(f.path(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let calls = f.calls("openssl");
        assert_eq!(calls.len(), 8);
        assert_eq!(calls[0], ["version"]);
        assert_eq!(calls[1], ["list", "-signature-algorithms"]);
        assert_eq!(
            calls[2],
            derive_args(f.path("key.pem").to_str().unwrap(), passin())
        );
        let sign = &calls[3];
        assert_eq!(
            *sign,
            sign_args(
                f.path("key.pem").to_str().unwrap(),
                passin(),
                &sign[10],
                &sign[12]
            )
        );
        for call in [&calls[4], &calls[7]] {
            assert_eq!(**call, verify_args(&call[4], &call[9], &call[11]));
            assert_ne!(Path::new(&call[4]), f.path("public.pem"));
            assert!(Path::new(&call[4]).is_absolute());
            assert!(!Path::new(&call[4]).exists(), "private stage is removed");
        }
        assert!(
            !std::fs::read_to_string(f.path("openssl.log"))
                .unwrap()
                .contains("private-placeholder")
        );
        let classical = verify_receipt_with_tools(
            &f.path("receipt.json"),
            &f.path("key.pem"),
            &signed.bundle,
            None,
            Some((&f.cosign, "/missing/openssl")),
        )
        .await
        .unwrap();
        assert!(!classical.pq_verified);
        assert!(f.dir.path().exists());
    }

    #[tokio::test]
    async fn pq_refuses_tools_and_wrong_keys_before_any_cosign_call() {
        let missing = Fixture::new();
        assert!(matches!(
            Openssl::probe("/nonexistent/vettalon-openssl", &missing.root, &[]).await,
            Err(AttestError::Refused(_))
        ));
        for version in [
            "LibreSSL 3.3.6",
            "OpenSSL 3.4.0",
            "OpenSSL 5.0.0",
            "garbage",
        ] {
            let f = Fixture::new();
            std::fs::write(f.path("version"), version).unwrap();
            assert!(f.sign().await.is_err());
            assert!(f.calls("cosign").is_empty());
            assert!(!f.path("receipt.json.sigstore.json").exists());
        }
        for marker in ["no-caps", "wrong-key", "oversized-key"] {
            let f = Fixture::new();
            match marker {
                "wrong-key" => std::fs::write(f.path("public.der"), [0x30; 44]).unwrap(),
                "oversized-key" => std::fs::write(f.path("public.der"), vec![0; 4097]).unwrap(),
                _ => f.mark(marker),
            }
            assert!(f.sign().await.is_err());
            assert!(f.calls("cosign").is_empty());
        }
    }

    #[tokio::test]
    async fn pq_failures_leave_no_partial_outputs() {
        for marker in ["short-sig", "long-sig", "verify-fail", "block-sidecar"] {
            let f = Fixture::new();
            if marker == "short-sig" || marker == "long-sig" {
                std::fs::write(
                    f.path("signature"),
                    vec![0; if marker == "short-sig" { 3308 } else { 3310 }],
                )
                .unwrap();
            } else {
                f.mark(marker);
            }
            assert!(f.sign().await.is_err(), "{marker}");
            assert!(!f.path("receipt.json.sigstore.json").exists(), "{marker}");
            if marker == "block-sidecar" {
                assert_eq!(
                    std::fs::read_to_string(f.path("receipt.json.mldsa.json")).unwrap(),
                    "occupied\n"
                );
            } else {
                assert!(!f.path("receipt.json.mldsa.json").exists());
            }
        }
        let f = Fixture::new();
        f.mark("receipt.json.mldsa.json");
        assert!(f.sign().await.is_err());
        assert_eq!(
            std::fs::read_to_string(f.path("receipt.json.mldsa.json")).unwrap(),
            "x"
        );
        assert!(f.calls("openssl").is_empty());
        assert!(
            sign_receipt_with_tools(
                &f.path("receipt.json"),
                &f.path("key.pem"),
                Some(&f.path("same")),
                Some((&f.path("key.pem"), Some(&f.path("same")))),
                Some((&f.cosign, &f.openssl))
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn pq_hybrid_and_semantics_and_result_classification() {
        for marker in [
            "cosign-fail",
            "verify-fail",
            "unexpected",
            "exit3",
            "oversized",
        ] {
            let f = Fixture::new();
            f.sign().await.unwrap();
            f.mark(marker);
            let error = f.verify().await.unwrap_err();
            if matches!(marker, "cosign-fail" | "verify-fail") {
                assert!(matches!(error, AttestError::Failed(_)), "{error}");
            } else {
                assert!(matches!(error, AttestError::Refused(_)), "{error}");
            }
            if marker == "cosign-fail" {
                assert_eq!(
                    f.calls("openssl")
                        .iter()
                        .filter(|c| c.get(1).is_some_and(|s| s == "-verify"))
                        .count(),
                    1
                );
            }
        }
        for field in ["receipt_sha256", "statement_sha256", "public_key_sha256"] {
            let f = Fixture::new();
            f.sign().await.unwrap();
            let mut value: Sidecar =
                Sidecar::parse(&std::fs::read(f.path("receipt.json.mldsa.json")).unwrap()).unwrap();
            match field {
                "receipt_sha256" => value.receipt_sha256 = "0".repeat(64),
                "statement_sha256" => value.statement_sha256 = "0".repeat(64),
                _ => value.public_key_sha256 = "0".repeat(64),
            }
            std::fs::write(
                f.path("receipt.json.mldsa.json"),
                value.canonical_bytes().unwrap(),
            )
            .unwrap();
            assert!(matches!(f.verify().await, Err(AttestError::Failed(_))));
        }
        let f = Fixture::new();
        f.sign().await.unwrap();
        std::fs::write(f.path("receipt.json.mldsa.json"), "{}").unwrap();
        let before = f.calls("cosign").len();
        assert!(matches!(f.verify().await, Err(AttestError::Refused(_))));
        assert_eq!(f.calls("cosign").len(), before);
    }
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "needs OpenSSL >=3.5, cosign v3 and COSIGN_PASSWORD set; optional VETTALON_LIVE_OPENSSL"]
async fn pq_live_hybrid_sign_verify_and_tamper() {
    use super::super::{sign_receipt_with_tools, verify_receipt_with_tools};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    if std::env::var_os("VETTALON_PQ_LIVE_CHILD").is_none() {
        let tools = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let openssl = std::env::var("VETTALON_LIVE_OPENSSL")
            .ok()
            .unwrap_or_else(|| {
                resolve_program(std::env::var_os("VETTALON_OPENSSL").as_deref()).unwrap()
            });
        let cosign = std::env::var("VETTALON_COSIGN")
            .ok()
            .unwrap_or_else(|| crate::util::which_cli("cosign").expect("cosign on PATH"));
        for (name, source) in [("openssl", openssl), ("cosign", cosign)] {
            let target = tools.path().join(name);
            std::fs::copy(source, &target).unwrap();
            std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "attest::pq::tests::pq_live_hybrid_sign_verify_and_tamper",
                "--ignored",
                "--nocapture",
            ])
            .env("VETTALON_PQ_LIVE_CHILD", "1")
            .env("VETTALON_OPENSSL", tools.path().join("openssl"))
            .env("VETTALON_COSIGN", tools.path().join("cosign"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let openssl = resolve_program(std::env::var_os("VETTALON_OPENSSL").as_deref()).unwrap();
    let cosign = std::env::var("VETTALON_COSIGN").unwrap();
    let run = async |program: &str, args: &[&str]| {
        let is_cosign = program == cosign;
        let program = crate::audit::TrustedExecutable::resolve(program, &[]).unwrap();
        let home = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let env = if is_cosign {
            crate::audit::AttestationEnv::Cosign {
                private_key: args.first() == Some(&"generate-key-pair"),
                home: home.path(),
            }
        } else {
            crate::audit::AttestationEnv::Openssl {
                private_key: args.contains(&"env:VETTALON_PQ_KEY_PASSWORD"),
            }
        };
        let out = crate::audit::run_attestation_subprocess(
            &program,
            args,
            &root,
            &crate::audit::SubprocessLimits::default(),
            env,
        )
        .await;
        assert!(
            out.spawn_error.is_none()
                && out.cleanup_error.is_none()
                && !out.timed_out
                && !out.stdout_truncated
                && out.exit_code == Some(0),
            "{out:?}"
        );
        out.stdout
    };
    Openssl::probe(&openssl, &root, &[]).await.unwrap();
    run(&cosign, &["generate-key-pair"]).await;
    run(
        &openssl,
        &["genpkey", "-algorithm", "ML-DSA-65", "-out", "mldsa.key"],
    )
    .await;
    run(
        &openssl,
        &[
            "pkey",
            "-in",
            "mldsa.key",
            "-pubout",
            "-out",
            "mldsa.pub",
            "-passin",
            passin(),
        ],
    )
    .await;
    let r = root.join("receipt.json");
    let key = root.join("cosign.key");
    let public = root.join("cosign.pub");
    let pq_key = root.join("mldsa.key");
    let pq_public = root.join("mldsa.pub");
    std::fs::write(&r, receipt()).unwrap();
    // Exercise both blob and attestation commands with fresh HOME directories.
    let tool = super::super::cosign::Cosign::locate(&root, &[])
        .await
        .unwrap();
    let blob_bundle = root.join("blob.sigstore.json");
    tool.run(
        &[
            "sign-blob",
            "--key",
            key.to_str().unwrap(),
            "--use-signing-config=false",
            "--tlog-upload=false",
            "--bundle",
            blob_bundle.to_str().unwrap(),
            "-y",
            r.to_str().unwrap(),
        ],
        &root,
    )
    .await
    .unwrap();
    tool.run(
        &[
            "verify-blob",
            "--key",
            public.to_str().unwrap(),
            "--bundle",
            blob_bundle.to_str().unwrap(),
            "--insecure-ignore-tlog",
            r.to_str().unwrap(),
        ],
        &root,
    )
    .await
    .unwrap();
    let signed = sign_receipt_with_tools(&r, &key, None, Some((&pq_key, None)), None)
        .await
        .unwrap();
    let sidecar_path = signed.pq.unwrap().sidecar;
    let verify = || {
        verify_receipt_with_tools(
            &r,
            &public,
            &signed.bundle,
            Some((&pq_public, &sidecar_path)),
            None,
        )
    };
    assert!(verify().await.unwrap().pq_verified);
    // Independent classical verification over exactly the ML-DSA message.
    let bundle_bytes = std::fs::read(&signed.bundle).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bundle_bytes).unwrap();
    let ec_signature = decode_base64_strict(
        value["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("ec.sig"), ec_signature).unwrap();
    std::fs::write(
        root.join("pae.bin"),
        dsse_pae(&decode_bundle_payload(&bundle_bytes).unwrap()),
    )
    .unwrap();
    run(
        &openssl,
        &[
            "dgst",
            "-sha256",
            "-verify",
            "cosign.pub",
            "-signature",
            "ec.sig",
            "pae.bin",
        ],
    )
    .await;
    // One byte changed, still a valid receipt.
    std::fs::write(&r, receipt().replace("app.py", "apq.py")).unwrap();
    assert!(matches!(verify().await, Err(AttestError::Failed(_))));
    std::fs::write(&r, receipt()).unwrap();
    let original = std::fs::read(&sidecar_path).unwrap();
    let mut sidecar = Sidecar::parse(&original).unwrap();
    let mut sig = sidecar.signature_bytes().unwrap();
    sig[0] ^= 1;
    sidecar.signature = encode_base64_std(&sig);
    std::fs::write(&sidecar_path, sidecar.canonical_bytes().unwrap()).unwrap();
    assert!(matches!(verify().await, Err(AttestError::Failed(_))));
    std::fs::write(&sidecar_path, original).unwrap();
    run(
        &openssl,
        &["genpkey", "-algorithm", "ML-DSA-65", "-out", "other.key"],
    )
    .await;
    run(
        &openssl,
        &[
            "pkey",
            "-in",
            "other.key",
            "-pubout",
            "-out",
            "mldsa.pub",
            "-passin",
            passin(),
        ],
    )
    .await;
    assert!(matches!(verify().await, Err(AttestError::Failed(_))));
    run(
        &openssl,
        &["genpkey", "-algorithm", "ML-DSA-44", "-out", "wrong.key"],
    )
    .await;
    let wrong = sign_receipt_with_tools(
        &r,
        &key,
        Some(&root.join("wrong.bundle")),
        Some((&root.join("wrong.key"), Some(&root.join("wrong.sidecar")))),
        None,
    )
    .await;
    assert!(wrong.unwrap_err().contains("ML-DSA-65 SPKI"));
    assert!(!root.join("wrong.bundle").exists());
    if std::env::var_os("VETTALON_PQ_KEY_PASSWORD").is_some() {
        run(
            &openssl,
            &[
                "genpkey",
                "-algorithm",
                "ML-DSA-65",
                "-aes-256-cbc",
                "-pass",
                "env:VETTALON_PQ_KEY_PASSWORD",
                "-out",
                "encrypted.key",
            ],
        )
        .await;
        sign_receipt_with_tools(
            &r,
            &key,
            Some(&root.join("encrypted.bundle")),
            Some((
                &root.join("encrypted.key"),
                Some(&root.join("encrypted.sidecar")),
            )),
            None,
        )
        .await
        .unwrap();
    }
}
