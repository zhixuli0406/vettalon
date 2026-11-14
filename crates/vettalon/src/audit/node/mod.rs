//! Untrusted Node/npm inputs to JavaScript/TypeScript execution proof
//! (design `docs/v08-batch4/d-js-exec-design.md`, task D3).
//!
//! - [`lockfile`]: decides what the networked install container may fetch
//!   (§3.3 step 1). Only registry tarballs pinned by `sha512` pass.
//! - [`fixture`]: the operator's `--fixture` file (§3.5). Its values reach
//!   the target's child environment and are never logged or put in receipts.
//!
//! Both are pure: they validate bytes the caller has already read with a
//! bounded read (the caller should read at most `cap + 1` bytes, e.g. with
//! `toolchain::content::read_capped_to`, so an oversized file is reported
//! as too large rather than silently truncated). Consumers arrive in D5
//! (install container) and D9 (CLI wiring).

pub(crate) mod deps;
pub mod dispatch;
pub mod fixture;
pub mod lockfile;

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

/// Why a strict JSON parse failed. Mapped onto each validator's own tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonFault {
    TooLarge,
    NotUtf8,
    TooDeep,
    Malformed,
    DuplicateKey,
    TooManyPackages,
    TooManyMembers,
}

/// Prefix of the custom error raised on a repeated object key. serde_json's
/// own messages never start with it.
const DUPLICATE_KEY_SENTINEL: &str = "vettalon-duplicate-key";
const PACKAGES_SENTINEL: &str = "vettalon-too-many-packages";
const MEMBERS_SENTINEL: &str = "vettalon-too-many-members";
pub(crate) const JSON_MAX_MEMBERS: usize = 50_000;
pub(crate) const JSON_MAX_TOTAL_KEYS: usize = 500_000;

/// Parse untrusted JSON with every cap enforced before the value tree is
/// built: byte size first, then UTF-8, then a linear nesting scan (so a
/// nesting bomb never reaches the recursive parser), then a streaming pass
/// that bounds object members and total keys while refusing duplicates at
/// any depth (serde_json keeps the last one silently), then the real parse.
pub(crate) fn parse_strict(
    bytes: &[u8],
    max_bytes: usize,
    max_depth: usize,
) -> Result<serde_json::Value, JsonFault> {
    parse_strict_limited(bytes, max_bytes, max_depth, None)
}

/// Optionally cap the top-level `packages` object's members in the same pass.
pub(crate) fn parse_strict_limited(
    bytes: &[u8],
    max_bytes: usize,
    max_depth: usize,
    packages_cap: Option<usize>,
) -> Result<serde_json::Value, JsonFault> {
    if bytes.len() > max_bytes {
        return Err(JsonFault::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| JsonFault::NotUtf8)?;
    crate::audit::verify_only::check_json_depth(bytes, max_depth)
        .map_err(|_| JsonFault::TooDeep)?;
    let mut de = serde_json::Deserializer::from_str(text);
    let mut total_keys = 0;
    let checked = CheckedJson {
        total_keys: &mut total_keys,
        packages_cap,
        root: true,
        members_cap: None,
    }
    .deserialize(&mut de)
    .and_then(|_| de.end());
    if let Err(e) = checked {
        return Err(if e.to_string().starts_with(DUPLICATE_KEY_SENTINEL) {
            JsonFault::DuplicateKey
        } else if e.to_string().starts_with(PACKAGES_SENTINEL) {
            JsonFault::TooManyPackages
        } else if e.to_string().starts_with(MEMBERS_SENTINEL) {
            JsonFault::TooManyMembers
        } else {
            JsonFault::Malformed
        });
    }
    serde_json::from_str(text).map_err(|_| JsonFault::Malformed)
}

/// Only open objects retain key sets; siblings share the total counter alone.
struct CheckedJson<'a> {
    total_keys: &'a mut usize,
    packages_cap: Option<usize>,
    root: bool,
    members_cap: Option<usize>,
}

impl<'de> DeserializeSeed<'de> for CheckedJson<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for CheckedJson<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_i128<E: de::Error>(self, _: i128) -> Result<(), E> {
        Ok(())
    }

    fn visit_u128<E: de::Error>(self, _: u128) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(CheckedJson {
                total_keys: self.total_keys,
                packages_cap: self.packages_cap,
                root: false,
                members_cap: None,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            // Refuse before retaining the excess key or reading its value.
            if self.members_cap.is_some_and(|cap| seen.len() >= cap) {
                return Err(de::Error::custom(PACKAGES_SENTINEL));
            }
            if seen.len() >= JSON_MAX_MEMBERS || *self.total_keys >= JSON_MAX_TOTAL_KEYS {
                return Err(de::Error::custom(MEMBERS_SENTINEL));
            }
            *self.total_keys += 1;
            let members_cap = if self.root && key == "packages" {
                self.packages_cap
            } else {
                None
            };
            if !seen.insert(key) {
                return Err(de::Error::custom(DUPLICATE_KEY_SENTINEL));
            }
            map.next_value_seed(CheckedJson {
                total_keys: self.total_keys,
                packages_cap: self.packages_cap,
                root: false,
                members_cap,
            })?;
        }
        Ok(())
    }
}

/// Longest detail text (in chars) attached to a refusal.
pub(crate) const DETAIL_MAX_CHARS: usize = 160;

/// Untrusted text made safe for an error message: secret-shaped substrings
/// masked, control characters replaced, length bounded.
pub(crate) fn bounded_detail(text: &str) -> String {
    let masked = crate::util::mask_sensitive_text(text);
    let mut out = String::new();
    for (i, c) in masked.chars().enumerate() {
        if i == DETAIL_MAX_CHARS {
            out.push('…');
            break;
        }
        out.push(if c.is_control() { '?' } else { c });
    }
    out
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
