//! Secret redaction (`util::mask_sensitive_text`), applied to text that leaves
//! the machine or lands in a report (model output, scanner messages, logs).
//! Over-masking is accepted; under-masking is a leak.
//!
//! Input: one selector byte choosing a well-known credential prefix, then
//! UTF-8-lossy text split at the first NUL into `before` and `after`. The
//! target masks `before + " " + <prefix><body> + " " + after`.
//!
//! Invariants checked beyond "no panic":
//! - the credential body never survives masking, whatever text surrounds
//!   it (the surrounding text is attacker-shaped: JSON fragments, `key:`
//!   lines, PEM armour, URLs);
//! - masking is total: it never panics and returns valid UTF-8.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vettalon::util::mask_sensitive_text;

/// Credential prefixes the value-token pass promises to catch regardless of
/// the surrounding key (see `SENSITIVE_VALUE_PREFIXES` in `util.rs`).
const PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "xai-",
    "AIza",
    "ASIA",
    "ghs_",
    "ghu_",
    "ghr_",
    "hf_",
    "gsk_",
    "eyJ",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "ghp_",
    "gho_",
    "github_pat_",
    "AKIA",
    "Bearer ",
    "Basic ",
    "Token ",
    "glpat-",
];

/// Synthetic credential body (not a real secret).
const BODY: &str = "Zq7Xw2Lk9Pr4Tm8Nv3Hb";

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let prefix = PREFIXES[usize::from(selector) % PREFIXES.len()];
    let text = String::from_utf8_lossy(rest);
    let (before, after) = text.split_once('\0').unwrap_or((&text, ""));
    if before.contains(BODY) || after.contains(BODY) {
        return; // the body must only come from the planted credential
    }
    let input = format!("{before} {prefix}{BODY} {after}");
    let masked = mask_sensitive_text(&input);
    assert!(
        !masked.contains(BODY),
        "credential survived masking\ninput:  {input:?}\noutput: {masked:?}"
    );
});
