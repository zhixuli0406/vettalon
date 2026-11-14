//! Deterministic fix-check inputs for the three harness oracle classes.
//!
//! The set is a function of [`OracleClass`] and [`Runtime`]. It does not read the clock,
//! the environment, or a model. Scan-time PoC and `vettalon reproduce` stay on
//! the first input; fix check runs the whole set.
//!
//! Every scoring input is chosen so the unpatched harness sink shows the same
//! canary effect as the base fixture: command variants copy `/tmp/vtl_secret`
//! onto `/tmp/vtl_out` for both bare `os.system(payload)` and
//! `os.system('echo ' + payload)`; path variants read that file through
//! `open(os.path.join(VTL_BASE, payload))`; SQL variants return the canary
//! from the sqlite `vtl_secret` table through a concatenated `items` query.
//!
//! Dropped because they do not show that canary: `sub/../../vtl_secret`
//! (a missing `sub` is ENOENT before `..` is applied), SQLite `#` comments,
//! stacked queries, and tautologies that only return the `apple` row.
//! Percent-encoded paths stay, with `requires_decoding`, because
//! `os.path.join` does not decode them.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::poc_oracle::OracleClass;
use super::target_poc::Runtime;

/// Canonical-JSON version mixed into [`VariantSet::sha256`].
pub const GENERATOR_VERSION: &str = "variants/1";

/// Node sets bind the runtime and use the canonical Node sink inputs.
pub const NODE_GENERATOR_VERSION: &str = "variants-node/1";

/// One input in a class variant set.
///
/// `requires_decoding` inputs are executed and reported. One that shows the
/// effect on the original and still on the fixed copy caps a verified fix at
/// partial. One that never shows the effect on the original does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Variant {
    /// Stable id. It does not change within `variants/1`.
    pub id: &'static str,
    /// Bytes the harness passes to `sink.run`.
    pub input: &'static str,
    /// The canonical harness sink does not decode this input. It counts only
    /// when the original copy shows the effect.
    pub requires_decoding: bool,
}

/// The ordered variant set for one oracle class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariantSet {
    pub class: OracleClass,
    pub runtime: Runtime,
    pub generator_version: &'static str,
    pub variants: &'static [Variant],
}

/// Receipt stamp for the set that a fix check actually used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariantSetStamp {
    pub generator_version: String,
    pub sha256: String,
    pub total: u32,
    /// Every scoring id that was not blocked on the fixed copy, in set order.
    /// Checking runs through the whole set and does not stop at the first one.
    pub ids_not_blocked: Vec<String>,
    /// Decoding ids that were applicable and still showed an effect on the fixed copy.
    #[serde(default)]
    pub decoding_ids_not_blocked: Vec<String>,
    /// Decoding ids that showed no effect on the original copy.
    #[serde(default)]
    pub decoding_ids_not_applicable: Vec<String>,
}

/// `;` runs the canary copy even when the prefix command fails.
const COMMAND_INJECTION: &[Variant] = &[
    Variant {
        id: "cmd-semicolon",
        input: "vtlbenign; cat /tmp/vtl_secret > /tmp/vtl_out",
        requires_decoding: false,
    },
    // `true` succeeds with or without an `echo ` prefix, so `&&` runs the copy.
    Variant {
        id: "cmd-and",
        input: "true && cat /tmp/vtl_secret > /tmp/vtl_out",
        requires_decoding: false,
    },
    // The pipeline status is `false`, so `||` runs the copy for bare `system`
    // and for an `echo ` prefix. A bare `false` would not, because `echo false`
    // succeeds.
    Variant {
        id: "cmd-or",
        input: "true | false || cat /tmp/vtl_secret > /tmp/vtl_out",
        requires_decoding: false,
    },
    // `cat` reads the canary file and ignores the pipe's stdin.
    Variant {
        id: "cmd-pipe",
        input: "true | cat /tmp/vtl_secret > /tmp/vtl_out",
        requires_decoding: false,
    },
    // Command substitution runs the copy before the outer command.
    Variant {
        id: "cmd-subst",
        input: "$(cat /tmp/vtl_secret > /tmp/vtl_out)",
        requires_decoding: false,
    },
    // Same copy via backticks.
    Variant {
        id: "cmd-backtick",
        input: "`cat /tmp/vtl_secret > /tmp/vtl_out`",
        requires_decoding: false,
    },
    // A newline is a command separator the prefix cannot swallow.
    Variant {
        id: "cmd-newline",
        input: "\ncat /tmp/vtl_secret > /tmp/vtl_out",
        requires_decoding: false,
    },
];

const PATH_TRAVERSAL: &[Variant] = &[
    // Base fixture. One `..` leaves `/tmp/vtl_base`.
    Variant {
        id: "path-dotdot",
        input: "../vtl_secret",
        requires_decoding: false,
    },
    // `./` then the same `..`.
    Variant {
        id: "path-dot-slash",
        input: "./../vtl_secret",
        requires_decoding: false,
    },
    // Empty segment between `..` and the canary name.
    Variant {
        id: "path-double-slash",
        input: "..//vtl_secret",
        requires_decoding: false,
    },
    // Walks `/tmp/vtl_base`, which the harness creates, then back out.
    // `sub/../../vtl_secret` does not: `sub` is never created.
    Variant {
        id: "path-via-base",
        input: "../vtl_base/../vtl_secret",
        requires_decoding: false,
    },
    // Two levels up to `/`, then `/tmp/vtl_secret`.
    Variant {
        id: "path-two-up",
        input: "../../tmp/vtl_secret",
        requires_decoding: false,
    },
    // `os.path.join` drops the base when the next component is absolute.
    Variant {
        id: "path-absolute",
        input: "/tmp/vtl_secret",
        requires_decoding: false,
    },
    // Percent-encoded `..`. The join sink does not decode this.
    Variant {
        id: "path-pct-dot",
        input: "%2e%2e/vtl_secret",
        requires_decoding: true,
    },
    // Percent-encoded slash. Informational, same as `path-pct-dot`.
    Variant {
        id: "path-pct-slash",
        input: "..%2fvtl_secret",
        requires_decoding: true,
    },
];

// Node's path.join retains the base for an absolute second component.
// Preserve Python's exact ordering and bytes, omitting only path-absolute.
const NODE_PATH_TRAVERSAL: &[Variant] = &[
    PATH_TRAVERSAL[0],
    PATH_TRAVERSAL[1],
    PATH_TRAVERSAL[2],
    PATH_TRAVERSAL[3],
    PATH_TRAVERSAL[4],
    PATH_TRAVERSAL[6],
    PATH_TRAVERSAL[7],
];

const SQLI: &[Variant] = &[
    // Base fixture. Closes the quote, unions the canary, comments out the rest.
    Variant {
        id: "sql-union",
        input: "' UNION SELECT token FROM vtl_secret --",
        requires_decoding: false,
    },
    // SQLite keywords are case-insensitive. Identifiers stay lowercase.
    Variant {
        id: "sql-mixed-case",
        input: "' UnIoN SeLeCt token FrOm vtl_secret --",
        requires_decoding: false,
    },
    // `/**/` is whitespace. The space before `--` matches the base form.
    Variant {
        id: "sql-comment-ws",
        input: "'/**/UNION/**/SELECT/**/token/**/FROM/**/vtl_secret --",
        requires_decoding: false,
    },
    // `UNION ALL` still returns the canary row.
    Variant {
        id: "sql-union-all",
        input: "' UNION ALL SELECT token FROM vtl_secret --",
        requires_decoding: false,
    },
    // An unclosed `/*` comments out the trailing quote through EOF.
    Variant {
        id: "sql-block-tail",
        input: "' UNION SELECT token FROM vtl_secret /*",
        requires_decoding: false,
    },
    // Closes the quote, then continues the union on the next line.
    Variant {
        id: "sql-newline",
        input: "'\nUNION SELECT token FROM vtl_secret --",
        requires_decoding: false,
    },
];

const NODE_SSRF: &[Variant] = &[
    // Base fixture: direct IPv4 loopback.
    Variant {
        id: "ssrf-loopback",
        input: "http://127.0.0.1/vtl_ssrf",
        requires_decoding: false,
    },
    // Localhost resolves to a loopback listener on both hosts.
    Variant {
        id: "ssrf-localhost",
        input: "http://localhost/vtl_ssrf",
        requires_decoding: false,
    },
    // WHATWG normalizes the hostname to lowercase.
    Variant {
        id: "ssrf-localhost-upper",
        input: "http://LOCALHOST/vtl_ssrf",
        requires_decoding: false,
    },
    // Single decimal IPv4 address normalizes to 127.0.0.1.
    Variant {
        id: "ssrf-decimal",
        input: "http://2130706433/vtl_ssrf",
        requires_decoding: false,
    },
    // Hexadecimal IPv4 address normalizes to 127.0.0.1.
    Variant {
        id: "ssrf-hex",
        input: "http://0x7f000001/vtl_ssrf",
        requires_decoding: false,
    },
    // Octal IPv4 component normalizes to 127.0.0.1.
    Variant {
        id: "ssrf-octal",
        input: "http://0177.0.0.1/vtl_ssrf",
        requires_decoding: false,
    },
    // Short IPv4 address normalizes to 127.0.0.1.
    Variant {
        id: "ssrf-short",
        input: "http://127.1/vtl_ssrf",
        requires_decoding: false,
    },
    // The wildcard IPv4 listener also accepts other 127/8 addresses.
    Variant {
        id: "ssrf-other-loopback",
        input: "http://127.42.0.1/vtl_ssrf",
        requires_decoding: false,
    },
    // The kernel routes the unspecified IPv4 address to loopback.
    Variant {
        id: "ssrf-unspecified",
        input: "http://0.0.0.0/vtl_ssrf",
        requires_decoding: false,
    },
    // WHATWG normalizes zero to 0.0.0.0.
    Variant {
        id: "ssrf-zero",
        input: "http://0/vtl_ssrf",
        requires_decoding: false,
    },
    // WHATWG strips the trailing dot from the IPv4 address.
    Variant {
        id: "ssrf-trailing-dot",
        input: "http://127.0.0.1./vtl_ssrf",
        requires_decoding: false,
    },
    // WHATWG percent-decodes the hostname before parsing IPv4.
    Variant {
        id: "ssrf-pct-host",
        input: "http://%31%32%37%2e0.0.1/vtl_ssrf",
        requires_decoding: false,
    },
    // A TLS ClientHello reaches the listener on port 443.
    Variant {
        id: "ssrf-tls",
        input: "https://127.0.0.1/vtl_ssrf",
        requires_decoding: false,
    },
    // IPv4-mapped IPv6 reaches the IPv4 listener on both hosts.
    Variant {
        id: "ssrf-v4mapped",
        input: "http://[::ffff:127.0.0.1]/vtl_ssrf",
        requires_decoding: false,
    },
    // Informational: IPv6 loopback is unavailable on the Linux host.
    Variant {
        id: "ssrf-ipv6-loopback",
        input: "http://[::1]/vtl_ssrf",
        requires_decoding: true,
    },
    // Informational: http.get accepts credentials, but fetch rejects them.
    Variant {
        id: "ssrf-userinfo",
        input: "http://example.com@127.0.0.1/vtl_ssrf",
        requires_decoding: true,
    },
];

/// The variant set for `class`. The base fixture is first. Fully deterministic.
pub fn variant_set(class: OracleClass) -> VariantSet {
    let variants = match class {
        OracleClass::CommandInjection => COMMAND_INJECTION,
        OracleClass::PathTraversal => PATH_TRAVERSAL,
        OracleClass::Sqli => SQLI,
        OracleClass::Ssrf => &[],
    };
    VariantSet {
        class,
        runtime: Runtime::Python,
        generator_version: GENERATOR_VERSION,
        variants,
    }
}

/// Select the deterministic set for the target runtime without changing Python identity.
#[allow(dead_code)] // D8 wires runtime-aware variant identity into fix check.
pub fn variant_set_for(class: OracleClass, runtime: Runtime) -> VariantSet {
    if runtime == Runtime::Python {
        return variant_set(class);
    }
    VariantSet {
        class,
        runtime,
        generator_version: NODE_GENERATOR_VERSION,
        variants: match class {
            OracleClass::CommandInjection => COMMAND_INJECTION,
            OracleClass::PathTraversal => NODE_PATH_TRAVERSAL,
            OracleClass::Sqli => SQLI,
            OracleClass::Ssrf => NODE_SSRF,
        },
    }
}

impl VariantSet {
    pub fn len(self) -> usize {
        self.variants.len()
    }

    pub fn is_empty(self) -> bool {
        self.variants.is_empty()
    }

    /// Inputs that decide check A. Decoding inputs are excluded.
    pub fn scoring_len(self) -> usize {
        self.variants
            .iter()
            .filter(|variant| !variant.requires_decoding)
            .count()
    }

    /// SHA-256 of the canonical JSON document for this set.
    ///
    /// Keys are sorted: `class`, `generator_version`, optional `runtime`,
    /// `variants`, then each variant's
    /// `id`, `input`, `requires_decoding`, in set order.
    pub fn sha256(self) -> String {
        hex::encode(Sha256::digest(self.canonical_json()))
    }

    /// `ids_not_blocked` lists every scoring id that was not blocked, in set order.
    /// The decoding lists are applicable-and-still-effective, and not applicable.
    pub fn stamp(
        self,
        ids_not_blocked: &[String],
        decoding_ids_not_blocked: &[String],
        decoding_ids_not_applicable: &[String],
    ) -> VariantSetStamp {
        VariantSetStamp {
            generator_version: self.generator_version.to_string(),
            sha256: self.sha256(),
            total: self.len() as u32,
            ids_not_blocked: ids_not_blocked.to_vec(),
            decoding_ids_not_blocked: decoding_ids_not_blocked.to_vec(),
            decoding_ids_not_applicable: decoding_ids_not_applicable.to_vec(),
        }
    }

    fn canonical_json(self) -> Vec<u8> {
        let body = CanonicalSet {
            class: class_id(self.class),
            generator_version: self.generator_version,
            runtime: (self.runtime == Runtime::Node).then_some("node"),
            variants: self
                .variants
                .iter()
                .map(|variant| CanonicalVariant {
                    id: variant.id,
                    input: variant.input,
                    requires_decoding: variant.requires_decoding,
                })
                .collect(),
        };
        serde_json::to_vec(&body).expect("variant set is static JSON")
    }
}

fn class_id(class: OracleClass) -> &'static str {
    match class {
        OracleClass::CommandInjection => "command_injection",
        OracleClass::PathTraversal => "path_traversal",
        OracleClass::Sqli => "sqli",
        OracleClass::Ssrf => "ssrf",
    }
}

#[derive(Serialize)]
struct CanonicalSet<'a> {
    class: &'a str,
    generator_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<&'a str>,
    variants: Vec<CanonicalVariant<'a>>,
}

#[derive(Serialize)]
struct CanonicalVariant<'a> {
    id: &'a str,
    input: &'a str,
    requires_decoding: bool,
}

#[cfg(test)]
mod tests {
    use super::super::poc_oracle::{OracleClass, fixture_inputs};
    use super::{GENERATOR_VERSION, variant_set};

    const CLASSES: [OracleClass; 3] = [
        OracleClass::CommandInjection,
        OracleClass::PathTraversal,
        OracleClass::Sqli,
    ];

    // Filled from `cargo test -p vettalon --lib audit::variants`.
    const COMMAND_INJECTION_SHA256: &str =
        "db3a39b2639983ad72afd5870ea95aeecc2b45d0d30a83d052aea8942fd3af12";
    const PATH_TRAVERSAL_SHA256: &str =
        "d016a8e070a885460762418a26a7b61677958050f020ea7655849c018d375b48";
    const SQLI_SHA256: &str = "a58dfe0cf69028994f13715490530ad98f0f761da0fe6982c4cdea7c9663b0d0";

    #[test]
    fn variant_set_is_deterministic_and_pins_its_hash() {
        for class in CLASSES {
            let first = variant_set(class);
            let second = variant_set(class);
            assert_eq!(first, second);
            assert_eq!(first.sha256(), second.sha256());
            assert_eq!(first.generator_version, GENERATOR_VERSION);
        }
        expect_sha(OracleClass::CommandInjection, COMMAND_INJECTION_SHA256);
        expect_sha(OracleClass::PathTraversal, PATH_TRAVERSAL_SHA256);
        expect_sha(OracleClass::Sqli, SQLI_SHA256);
    }

    #[test]
    fn canonical_json_uses_sorted_keys() {
        for class in CLASSES {
            let raw = variant_set(class).canonical_json();
            let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            let again = serde_json::to_vec(&value).unwrap();
            assert_eq!(raw, again, "{class:?}");
            let text = std::str::from_utf8(&raw).unwrap();
            assert!(text.contains("\"generator_version\":\"variants/1\""));
            assert!(text.starts_with("{\"class\":"));
        }
    }

    #[test]
    fn variant_inputs_have_no_ascii_controls_except_newline() {
        for class in CLASSES {
            for variant in variant_set(class).variants {
                assert!(
                    variant
                        .input
                        .chars()
                        .all(|ch| ch == '\n' || !ch.is_ascii_control()),
                    "{}",
                    variant.id
                );
            }
        }
    }

    #[test]
    fn every_class_starts_with_the_base_fixture_and_stays_bounded() {
        let mut ids = std::collections::BTreeSet::new();
        for class in CLASSES {
            let set = variant_set(class);
            assert!(!set.variants.is_empty(), "{class:?}");
            assert!(set.scoring_len() > 0, "{class:?}");
            assert!(set.scoring_len() <= set.len());
            for (index, variant) in set.variants.iter().enumerate() {
                assert!(ids.insert(variant.id), "duplicate id {}", variant.id);
                assert!(!variant.id.is_empty());
                assert!(!variant.input.is_empty());
                assert!(!variant.input.contains('\0'));
                assert!(variant.input.len() <= 512, "{}", variant.id);
                assert!(variant.input.is_ascii(), "{}", variant.id);
                // Rust {:?} embeds these into Python. `\n` is a Python escape.
                // Other ASCII controls, including `\u{7f}`, are not.
                assert!(
                    variant
                        .input
                        .chars()
                        .all(|ch| ch == '\n' || !ch.is_ascii_control()),
                    "{}",
                    variant.id
                );
                if index == 0 {
                    assert!(!variant.requires_decoding, "{}", variant.id);
                    assert_eq!(variant.input, fixture_inputs(class)[0]);
                }
            }
        }
    }

    #[test]
    fn only_path_variants_require_decoding_and_payloads_match_the_canary() {
        let command = variant_set(OracleClass::CommandInjection);
        assert!(command.variants.iter().all(|v| !v.requires_decoding));
        assert!(
            command
                .variants
                .iter()
                .all(|v| { v.input.contains("cat /tmp/vtl_secret > /tmp/vtl_out") })
        );

        let path = variant_set(OracleClass::PathTraversal);
        let decoding: Vec<_> = path
            .variants
            .iter()
            .filter(|v| v.requires_decoding)
            .collect();
        assert!(!decoding.is_empty());
        assert!(decoding.iter().all(|v| v.input.contains('%')));
        assert_eq!(path.scoring_len() + decoding.len(), path.len());

        let sql = variant_set(OracleClass::Sqli);
        assert!(sql.variants.iter().all(|v| !v.requires_decoding));
        assert!(sql.variants.iter().all(|v| !v.input.contains('#')));
        assert!(sql.variants.iter().all(|v| {
            let lower = v.input.to_ascii_lowercase();
            lower.contains("union") && lower.contains("select") && lower.contains("vtl_secret")
        }));
    }

    #[test]
    fn runtime_variant_sets_preserve_python_and_pin_node_hashes() {
        use super::super::target_poc::Runtime;
        use super::variant_set_for;

        let pins = [
            "5d35b4cb9ab19b654cde00eb837343461cda22fcc1de0f833d060fd30070a135",
            "601d225bc6f3880498828783f29475afaaec3b76c8528de55a01f70c1648e7a0",
            "684a972c5a2a9f56692575461af0e73a94fac39a965cf4193a4219823685d884",
        ];
        for (class, pinned) in CLASSES.into_iter().zip(pins) {
            let python = variant_set(class);
            assert_eq!(variant_set_for(class, Runtime::Python), python);
            let node = variant_set_for(class, Runtime::Node);
            assert_eq!(node, variant_set_for(class, Runtime::Node));
            assert_eq!(node.generator_version, "variants-node/1");
            assert_eq!(node.sha256(), pinned, "{class:?}");
            assert_ne!(node.sha256(), python.sha256());
            let expected: Vec<_> = python
                .variants
                .iter()
                .filter(|v| v.id != "path-absolute")
                .copied()
                .collect();
            assert_eq!(node.variants, expected);
            assert_eq!(
                node.scoring_len(),
                python.scoring_len() - usize::from(class == OracleClass::PathTraversal)
            );
            let raw = node.canonical_json();
            let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(value["runtime"], "node");
            assert_eq!(raw, serde_json::to_vec(&value).unwrap());
            assert!(
                !serde_json::from_slice::<serde_json::Value>(&python.canonical_json())
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .contains_key("runtime")
            );
            let stamp = node.stamp(&[], &[], &[]);
            assert_eq!(stamp.sha256, pinned);
            assert_eq!(stamp.generator_version, "variants-node/1");
            assert_eq!(stamp.total as usize, node.len());
        }
    }

    #[test]
    fn node_ssrf_variants_match_fixture_and_stay_bounded() {
        use super::super::target_poc::Runtime;
        use super::variant_set_for;

        let set = variant_set_for(OracleClass::Ssrf, Runtime::Node);
        assert_eq!(set.len(), 16);
        assert_eq!(set.variants[0].id, "ssrf-loopback");
        assert_eq!(set.variants[0].input, fixture_inputs(OracleClass::Ssrf)[0]);
        assert!(!set.variants[0].requires_decoding);
        assert_eq!(set.scoring_len(), 14);
        let decoding: Vec<_> = set
            .variants
            .iter()
            .filter(|v| v.requires_decoding)
            .map(|v| v.id)
            .collect();
        assert_eq!(decoding, ["ssrf-ipv6-loopback", "ssrf-userinfo"]);

        let mut ids = std::collections::BTreeSet::new();
        for variant in set.variants {
            assert!(variant.id.starts_with("ssrf-"), "{}", variant.id);
            assert!(ids.insert(variant.id), "duplicate id {}", variant.id);
            assert!(variant.input.is_ascii(), "{}", variant.id);
            // Rust {:?} embeds the input in the runner; no controls are allowed.
            assert!(
                !variant.input.chars().any(|ch| ch.is_ascii_control()),
                "{}",
                variant.id
            );
        }
        // fix_check.rs: fix_check_run_budget uses 2N + 4 + margin 4, capped at 48.
        assert!(2 * set.len() + 8 <= 48);

        let python = variant_set(OracleClass::Ssrf);
        assert!(python.is_empty());
        assert_eq!(python.generator_version, GENERATOR_VERSION);
        assert_eq!(variant_set_for(OracleClass::Ssrf, Runtime::Python), python);
    }

    #[test]
    fn node_ssrf_variants_pin_stamp() {
        use super::super::target_poc::Runtime;
        use super::variant_set_for;

        // D11d pin
        const SSRF_SHA256: &str =
            "db25cd08104cf40cf99b5338a521b0cb519bde0092f3c9471067e8603a16b5de";
        let set = variant_set_for(OracleClass::Ssrf, Runtime::Node);
        let stamp = set.stamp(&[], &[], &[]);
        assert_eq!(stamp.sha256, SSRF_SHA256);
        assert_eq!(stamp.generator_version, "variants-node/1");
        assert_eq!(stamp.total, 16);
    }

    fn expect_sha(class: OracleClass, pinned: &str) {
        let got = variant_set(class).sha256();
        assert_eq!(got, pinned, "update the pin for {class:?} to {got}");
    }
}
