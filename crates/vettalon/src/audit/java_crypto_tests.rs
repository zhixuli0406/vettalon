use super::*;
use crate::audit::java_lex::lex;

fn sweep_test(lexed: &JavaLexed, max_rows: usize) -> SweepResult {
    let parsed = java_parse::parse(lexed);
    sweep(lexed, &parsed, &SweepContext::default(), max_rows)
}

fn scan(body: &str) -> SweepResult {
    sweep_test(
        &lex(&format!("class Test {{ void run() {{ {body} }} }}")),
        100,
    )
}
fn row(body: &str) -> SweepRow {
    let mut result = scan(body);
    assert_eq!(result.rows.len(), 1, "{result:?}");
    result.rows.remove(0)
}

macro_rules! family {
    ($test:ident, $api:literal, $alg:literal) => {
        #[test]
        fn $test() {
            let r = row(concat!($api, ".getInstance(\"", $alg, "\");"));
            assert_eq!(r.api, concat!($api, ".getInstance"));
            assert_eq!(r.algorithm.as_deref(), Some($alg));
        }
    };
}
family!(cipher, "Cipher", "AES");
family!(digest, "MessageDigest", "SHA-256");
family!(signature, "Signature", "SHA256withRSAandMGF1");
family!(key_pair_generator, "KeyPairGenerator", "RSA");
family!(key_generator, "KeyGenerator", "AES");
family!(
    secret_key_factory,
    "SecretKeyFactory",
    "PBKDF2WithHmacSHA256"
);
family!(mac, "Mac", "HmacSHA256");
family!(key_agreement, "KeyAgreement", "ECDH");
family!(key_factory, "KeyFactory", "RSA");
family!(kem, "KEM", "ML-KEM-768");
family!(algorithm_parameters, "AlgorithmParameters", "EC");
family!(
    algorithm_parameter_generator,
    "AlgorithmParameterGenerator",
    "DH"
);
family!(secure_random, "SecureRandom", "DRBG");
family!(key_store, "KeyStore", "PKCS12");

#[test]
fn qualified_factories() {
    let r = scan(
        "javax.crypto.Cipher.getInstance(\"AES\"); java.security.MessageDigest.getInstance(\"SHA-1\");",
    );
    assert_eq!(r.rows.len(), 2);
    assert_eq!(r.rows[0].api, "Cipher.getInstance");
    assert_eq!(r.rows[1].api, "MessageDigest.getInstance");
}
#[test]
fn providers_and_literal_order() {
    let r = scan(
        "log(\"decoy\"); Cipher.getInstance(\"AES\", \"SunJCE\"); Signature.getInstance(\"EdDSA\", provider);",
    );
    assert_eq!(r.rows[0].algorithm.as_deref(), Some("AES"));
    assert_eq!(r.rows[0].provider.as_deref(), Some("SunJCE"));
    assert_eq!(r.rows[1].provider, None);
}
#[test]
fn forward_same_file_constants() {
    let r = sweep_test(
        &lex(r#"class Test {
        void run() { Cipher.getInstance(ALG, PROVIDER); }
        static final String ALG = "AES/GCM/NoPadding";
        final static String PROVIDER = "SunJCE";
    }"#),
        10,
    );
    assert_eq!(r.rows[0].algorithm.as_deref(), Some("AES"));
    assert_eq!(r.rows[0].provider.as_deref(), Some("SunJCE"));
}
#[test]
fn unresolved_expressions() {
    for arg in [
        "dynamic",
        "getName()",
        "Other.NAME",
        "flag ? \"AES\" : \"RSA\"",
    ] {
        let r = row(&format!("Cipher.getInstance({arg});"));
        assert_eq!(r.algorithm, None);
        assert_eq!(r.reasons, ["algorithm_not_constant"]);
    }
}
#[test]
fn non_static_or_non_final_is_not_constant() {
    let r = sweep_test(
        &lex(
            r#"class Test { final String A = "AES"; static String B = "RSA";
        void run() { Cipher.getInstance(A); Cipher.getInstance(B); } }"#,
        ),
        10,
    );
    assert!(r.rows.iter().all(|r| r.algorithm.is_none()));
}
#[test]
fn duplicate_constants_fail_closed() {
    let r = sweep_test(
        &lex(r#"class A { static final String ALG = "AES"; }
        class B { static final String ALG = "DES"; void run() { Cipher.getInstance(ALG); } }"#),
        10,
    );
    assert_eq!(r.rows[0].algorithm, None);
}
#[test]
fn transformation_case_and_unknown_parts() {
    let r = row("Cipher.getInstance(\"aEs/gCm/nOpAdDiNg\");");
    assert_eq!(r.algorithm.as_deref(), Some("aEs"));
    assert_eq!(r.mode.as_deref(), Some("gCm"));
    assert_eq!(r.padding.as_deref(), Some("nOpAdDiNg"));
    let r = row("Cipher.getInstance(\"NewAlg/WeirdMode/OddPadding\");");
    assert_eq!(r.mode.as_deref(), Some("WeirdMode"));
    assert_eq!(r.padding.as_deref(), Some("OddPadding"));
}
#[test]
fn two_part_transformation() {
    let r = row("Cipher.getInstance(\"AES/CBC\");");
    assert_eq!(r.mode.as_deref(), Some("CBC"));
    assert_eq!(r.padding, None);
}
#[test]
fn bare_block_ciphers_have_ecb_note() {
    for alg in ["AES", "des", "DeSeDe"] {
        assert_eq!(
            row(&format!("Cipher.getInstance(\"{alg}\");")).reasons,
            ["jca_default_mode_ecb_possible"]
        );
    }
    assert!(
        row("Cipher.getInstance(\"AES/GCM/NoPadding\");")
            .reasons
            .is_empty()
    );
    assert!(
        row("k = KeyGenerator.getInstance(\"AES\");")
            .reasons
            .is_empty()
    );
}
#[test]
fn signature_and_pqc_names_are_preserved() {
    for alg in [
        "SHA256withRSA",
        "SHA384withECDSA",
        "SHA1withDSA",
        "SHA256withRSAandMGF1",
        "RSASSA-PSS",
        "Ed25519",
        "EdDSA",
        "ML-DSA-65",
        "ML-KEM-1024",
    ] {
        assert_eq!(
            row(&format!("Signature.getInstance(\"{alg}\");"))
                .algorithm
                .as_deref(),
            Some(alg)
        );
    }
}
#[test]
fn secret_key_spec() {
    assert_eq!(
        row("new javax.crypto.spec.SecretKeySpec(bytes, \"AES\");")
            .algorithm
            .as_deref(),
        Some("AES")
    );
    assert_eq!(
        row("new SecretKeySpec(bytes, dynamic);").reasons,
        ["algorithm_not_constant"]
    );
}
#[test]
fn gcm_and_iv_specs() {
    let r = scan("new GCMParameterSpec(128, iv); new IvParameterSpec(iv);");
    assert_eq!(r.rows.len(), 2);
    assert_eq!(r.rows[0].mode.as_deref(), Some("GCM"));
    assert_eq!(r.rows[0].key_bits, None); // Tag length is not key length.
    assert_eq!(r.rows[1].api, "new IvParameterSpec");
}
#[test]
fn pbe_key_spec() {
    assert_eq!(
        row("new PBEKeySpec(password, salt, 100000, 256);").key_bits,
        Some(256)
    );
    assert_eq!(
        row("new PBEKeySpec(password, salt, 100000);").key_bits,
        None
    );
}
#[test]
fn ec_and_rsa_specs() {
    let r = scan("new ECGenParameterSpec(\"secp256r1\"); new RSAKeyGenParameterSpec(3072, F4);");
    assert_eq!(r.rows[0].algorithm.as_deref(), Some("secp256r1"));
    assert_eq!(r.rows[1].algorithm.as_deref(), Some("RSA"));
    assert_eq!(r.rows[1].key_bits, Some(3072));
}
#[test]
fn key_size_nearest_preceding_generator() {
    let r = scan(
        "k = KeyPairGenerator.getInstance(\"RSA\"); k.initialize(2048); k = KeyGenerator.getInstance(\"AES\"); k.init(256);",
    );
    assert_eq!(r.rows[0].key_bits, Some(2048));
    assert_eq!(r.rows[1].key_bits, Some(256));
}
#[test]
fn intervening_non_generator_does_not_steal_size() {
    let r =
        scan("k = KeyGenerator.getInstance(\"AES\"); Cipher.getInstance(\"AES\"); k.init(128);");
    assert_eq!(r.rows[0].key_bits, Some(128));
    assert_eq!(r.rows[1].key_bits, None);
}
#[test]
fn key_size_does_not_cross_methods_even_on_same_line() {
    let r = sweep_test(
        &lex(
            "class A { void a() { k = KeyGenerator.getInstance(\"AES\"); } void b() { k.init(256); } }",
        ),
        10,
    );
    assert_eq!(r.rows[0].key_bits, None);
}
#[test]
fn key_size_does_not_flow_backwards_or_from_fields() {
    let r = sweep_test(
        &lex(
            "class A { Object k = KeyGenerator.getInstance(\"AES\"); void a() { k.init(128); k = KeyGenerator.getInstance(\"AES\"); } }",
        ),
        10,
    );
    assert!(r.rows.iter().all(|r| r.key_bits.is_none()));
}
#[test]
fn only_integer_literals_set_key_sizes() {
    for arg in ["size", "128 + 128", "-1", "4294967296", "256L"] {
        assert_eq!(
            scan(&format!(
                "k = KeyGenerator.getInstance(\"AES\"); k.init({arg});"
            ))
            .rows[0]
                .key_bits,
            None
        );
    }
    assert_eq!(
        scan("k = KeyGenerator.getInstance(\"AES\"); k.init(0x100);").rows[0].key_bits,
        Some(256)
    );
}
#[test]
fn comments_strings_chars_and_text_blocks_are_ignored() {
    let r = scan(
        r#"// Cipher.getInstance("DES");
        /* new IvParameterSpec(iv); */
        log("Cipher.getInstance(\"AES\")"); char q = '"';
        log("""
        KeyGenerator.getInstance("AES");
        """);
        Cipher.getInstance("AES", "provider");"#,
    );
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.rows[0].provider.as_deref(), Some("provider"));
}
#[test]
fn line_numbers_crlf_and_multiline_literals() {
    let r = sweep_test(
        &lex("class A {\r\nvoid a() {\rCipher.getInstance(\n\"AES\");\n} }"),
        10,
    );
    assert_eq!(r.rows[0].line, 3);
    assert_eq!(r.rows[0].algorithm.as_deref(), Some("AES"));
}
#[test]
fn clips_copied_strings() {
    let r = row(&format!(
        "Cipher.getInstance(\"{}\", \"{}\");",
        "界".repeat(300),
        "p".repeat(300)
    ));
    assert_eq!(r.algorithm.unwrap().chars().count(), 256);
    assert_eq!(r.provider.unwrap().len(), 256);
}
#[test]
fn row_cap_and_zero_cap() {
    let l =
        lex("class A { void a() { Cipher.getInstance(\"AES\"); Cipher.getInstance(\"DES\"); } }");
    let r = sweep_test(&l, 1);
    assert_eq!(r.rows.len(), 1);
    assert!(r.truncated);
    assert_eq!(sweep_test(&l, 0).rows.len(), 0);
    assert!(sweep_test(&l, 0).truncated);
    assert!(!sweep_test(&l, 2).truncated);
}
#[test]
fn pathological_calls_and_deep_groups_are_bounded() {
    let start = std::time::Instant::now();
    let l = lex(&"getInstance(".repeat(200_000));
    assert!(sweep_test(&l, 2).truncated);
    let l = lex(&format!("{}{}", "(".repeat(200_000), ")".repeat(200_000)));
    let r = sweep_test(&l, 2);
    assert!(r.truncated);
    assert!(r.rows.is_empty());
    let l = lex(&format!(
        "class A {{ void a() {{ {} }} }}",
        "Cipher.getInstance(\"AES\");".repeat(5_000)
    ));
    let r = sweep_test(&l, 2);
    assert_eq!(r.rows.len(), 2);
    assert!(r.truncated);
    assert!(start.elapsed().as_secs() < 10);
}
#[test]
fn ambiguity_returns_only_reason() {
    let r = sweep_test(&lex("Cipher.getInstance(\"unterminated"), 10);
    assert!(r.rows.is_empty());
    assert_eq!(r.reasons, ["unterminated_string"]);
}
#[test]
fn literal_table_truncation_is_reported() {
    let mut l = lex("Cipher.getInstance(\"AES\");");
    l.literals_truncated = true;
    let r = sweep_test(&l, 10);
    assert!(r.truncated);
    assert!(r.reasons.iter().any(|r| r == "literals_truncated"));
}
#[test]
fn unrelated_calls_and_bc_are_not_swept() {
    assert!(scan("Other.getInstance(\"AES\"); new AESEngine(); engine.initialize(128); getInstance(\"AES\");").rows.is_empty());
}

#[test]
fn digest_slash_is_not_transformation() {
    let r = row("MessageDigest.getInstance(\"SHA-512/256\");");
    assert_eq!(r.algorithm.as_deref(), Some("SHA-512/256"));
    assert_eq!((r.mode, r.padding), (None, None));
}
#[test]
fn cipher_receiver_cannot_set_generator_bits() {
    let r = scan("KeyGenerator k = KeyGenerator.getInstance(\"AES\"); cipher.init(1, key);");
    assert_eq!(r.rows[0].key_bits, None);
}
#[test]
fn unassigned_generator_has_no_bits() {
    assert_eq!(
        row("KeyGenerator.getInstance(\"AES\"); k.init(128);").key_bits,
        None
    );
}
#[test]
fn generator_receivers_are_independent() {
    let r = scan(
        "a = KeyGenerator.getInstance(\"AES\"); b = KeyPairGenerator.getInstance(\"RSA\"); a.init(256, random); b.initialize(2048);",
    );
    assert_eq!(r.rows[0].key_bits, Some(256));
    assert_eq!(r.rows[1].key_bits, Some(2048));
}
#[test]
fn generator_latest_assignment_wins() {
    let r = scan(
        "k = KeyGenerator.getInstance(\"AES\"); k = KeyGenerator.getInstance(\"DES\"); k.init(56);",
    );
    assert_eq!(r.rows[0].key_bits, None);
    assert_eq!(r.rows[1].key_bits, Some(56));
}
#[test]
fn generator_init_arity_is_bounded() {
    for args in ["", "128, random, extra"] {
        assert_eq!(
            row(&format!(
                "k = KeyGenerator.getInstance(\"AES\"); k.init({args});"
            ))
            .key_bits,
            None
        );
    }
}
fn bc_scan(body: &str) -> SweepResult {
    sweep_test(
        &lex(&format!(
            "import org.bouncycastle.crypto.*; class Test {{ void run() {{ {body} }} }}"
        )),
        100,
    )
}
#[test]
fn bc_requires_import() {
    assert!(scan("new AESEngine();").rows.is_empty());
    let r = bc_scan("new AESEngine();");
    assert_eq!(r.rows[0].api, "bc:AESEngine");
    assert_eq!(r.rows[0].algorithm.as_deref(), Some("AES"));
}
#[test]
fn bc_new_instance_and_modes() {
    let r = bc_scan("GCMBlockCipher.newInstance(new AESEngine()); new SICBlockCipher(engine);");
    assert_eq!(r.rows.len(), 3);
    assert_eq!(r.rows[0].mode.as_deref(), Some("GCM"));
    assert_eq!(r.rows[2].mode.as_deref(), Some("CTR"));
}
#[test]
fn bc_fixed_digest_and_pqc_mapping() {
    let r = bc_scan(
        "new SHA256Digest(); new Ed25519Signer(); new MLKEMGenerator(random); new MLDSASigner(); new SLHDSASigner();",
    );
    let algorithms: Vec<_> = r
        .rows
        .iter()
        .map(|r| r.algorithm.as_deref().unwrap())
        .collect();
    assert_eq!(
        algorithms,
        ["SHA-256", "Ed25519", "ML-KEM", "ML-DSA", "SLH-DSA"]
    );
}
#[test]
fn provider_registration_is_one_file_note() {
    let r = bc_scan(
        "Security.addProvider(new BouncyCastleProvider()); Security.addProvider(new BouncyCastleProvider());",
    );
    assert!(r.rows.is_empty());
    assert_eq!(r.reasons, ["bouncycastle_provider_registered"]);
    assert!(
        bc_scan("Other.addProvider(new BouncyCastleProvider());")
            .reasons
            .is_empty()
    );
}
fn project_scan(sources: &[&str], use_source: &str) -> SweepResult {
    let mut ctx = SweepContext::default();
    for source in sources {
        let l = lex(source);
        for (ty, name, expr) in collect_constants(&l, &java_parse::parse(&l)) {
            ctx.constants
                .entry(ty)
                .or_default()
                .entry(name)
                .and_modify(|v| *v = None)
                .or_insert(Some(expr));
        }
    }
    let l = lex(use_source);
    sweep(&l, &java_parse::parse(&l), &ctx, 100)
}
#[test]
fn cross_file_constants() {
    let r = project_scan(
        &["class Algorithms { static final String ALG = \"AES\"; }"],
        "class Use { void run() { Cipher.getInstance(Algorithms.ALG); } }",
    );
    assert_eq!(r.rows[0].algorithm.as_deref(), Some("AES"));
}
#[test]
fn package_qualified_constant() {
    let r = project_scan(
        &["package p; class Algorithms { static final String ALG = \"SHA-256\"; }"],
        "class Use { void run() { MessageDigest.getInstance(p.Algorithms.ALG); } }",
    );
    assert_eq!(r.rows[0].algorithm.as_deref(), Some("SHA-256"));
}
fn chain_scan(extra: &str, arg: &str) -> SweepResult {
    sweep_test(
        &lex(&format!(
            r#"class C {{
        static final String A = "AES";
        static final String B = A;
        static final String C = B;
        static final String D = C;
        {extra}
        void run() {{ Cipher.getInstance({arg}); }}
    }}"#
        )),
        10,
    )
}
#[test]
fn four_constant_levels_resolve() {
    assert_eq!(
        chain_scan("", "D").rows[0].algorithm.as_deref(),
        Some("AES")
    );
}
#[test]
fn five_constant_levels_fail_closed() {
    assert_eq!(
        chain_scan("static final String E = D;", "E").rows[0].reasons,
        ["algorithm_not_constant"]
    );
}
#[test]
fn constant_cycle_fails_closed() {
    let r = sweep_test(
        &lex(
            "class C { static final String A = B; static final String B = A; void run() { Cipher.getInstance(A); } }",
        ),
        10,
    );
    assert_eq!(r.rows[0].reasons, ["algorithm_not_constant"]);
}
#[test]
fn concatenation_of_literals_and_constants() {
    let r = chain_scan(
        "static final String MODE = \"G\" + \"CM\";",
        "A + \"/\" + MODE + \"/NoPadding\"",
    );
    assert_eq!(r.rows[0].algorithm.as_deref(), Some("AES"));
    assert_eq!(r.rows[0].mode.as_deref(), Some("GCM"));
}
#[test]
fn folding_part_limit() {
    for (count, resolved) in [(16, true), (17, false)] {
        let arg = vec!["\"a\""; count].join(" + ");
        assert_eq!(
            row(&format!("MessageDigest.getInstance({arg});"))
                .algorithm
                .is_some(),
            resolved
        );
    }
}
#[test]
fn folding_character_limit() {
    let arg = format!("\"{}\" + \"b\"", "a".repeat(256));
    assert_eq!(row(&format!("Cipher.getInstance({arg});")).algorithm, None);
}
#[test]
fn project_duplicate_constants_are_ambiguous() {
    let r = project_scan(
        &[
            "class C { static final String A = \"AES\"; }",
            "class C { static final String A = \"DES\"; }",
        ],
        "class Use { void run() { Cipher.getInstance(C.A); } }",
    );
    assert_eq!(r.rows[0].algorithm, None);
}
#[test]
fn token_cap_returns_no_rows() {
    let l = lex(&format!(
        "class C {{ void run() {{ Cipher.getInstance(\"AES\"); {} }} }}",
        ";".repeat(MAX_TOKENS)
    ));
    let r = sweep_test(&l, 10);
    assert!(r.rows.is_empty());
    assert!(r.truncated);
    assert_eq!(r.reasons, ["sweep_token_limit_exceeded", "sweep_truncated"]);
}

#[test]
fn constant_budgets_fail_closed_for_local_and_project_references() {
    let l = lex(
        "class C { static final String ALG = \"AES\"; void f() { Cipher.getInstance(ALG); Cipher.getInstance(C.ALG); Cipher.getInstance(\"RSA\"); } }",
    );
    let parsed = java_parse::parse(&l);
    for byte_limit in [false, true] {
        let mut ctx = SweepContext::default();
        assert!(ctx.insert_with_limits(
            "C".into(),
            "ALG".into(),
            ConstExpr(Some(vec![ConstPart::Literal("AES".into())])),
            1,
            usize::MAX
        ));
        let bytes = ctx.bytes;
        assert!(!ctx.insert_with_limits(
            "D".into(),
            "OTHER".into(),
            ConstExpr(None),
            if byte_limit { usize::MAX } else { 1 },
            if byte_limit { bytes } else { usize::MAX }
        ));
        assert_eq!(ctx.entries, 1);
        assert_eq!(ctx.bytes, bytes);
        assert!(ctx.limit_exceeded);
        let result = sweep(&l, &parsed, &ctx, 100);
        assert_eq!(result.rows.len(), 3);
        for row in &result.rows[..2] {
            assert_eq!(row.algorithm, None);
            assert!(row.reasons.iter().any(|s| s == "algorithm_not_constant"));
        }
        assert_eq!(result.rows[2].algorithm.as_deref(), Some("RSA"));
    }
}

#[test]
fn zero_row_capacity_only_truncates_on_a_match() {
    let empty = sweep_test(&lex("class C { void f() { harmless(); } }"), 0);
    assert!(!empty.truncated);
    let matched = sweep_test(
        &lex("class C { void f() { Cipher.getInstance(\"AES\"); } }"),
        0,
    );
    assert!(matched.rows.is_empty());
    assert!(matched.truncated);
}
