//! in-toto Statement v1 for a Vettalon receipt, and the checks run on the
//! Statement decoded from a Sigstore bundle.
//!
//! cosign builds the signed Statement itself from `--predicate`, `--type`
//! and the blob digest. These checks make sure that what it signed is
//! exactly one subject (the receipt bytes), the expected predicate type and
//! the predicate Vettalon extracts from the receipt again.

use serde_json::{Value, json};

use crate::audit::cbom_check::canonical_json;
use crate::audit::schema::sha256_hex;

use super::predicate::ReceiptKind;

/// The Statement type Vettalon writes.
pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";
/// Older in-toto Go libraries label the same layout v0.1. Accepted on read so
/// a cosign build that still emits it is not refused; never written.
pub const STATEMENT_TYPE_V01: &str = "https://in-toto.io/Statement/v0.1";
/// DSSE payload type of an in-toto Statement.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// Largest Sigstore bundle read.
pub const BUNDLE_MAX_BYTES: usize = 1024 * 1024;
/// The only accepted bundle media type: Sigstore bundle v0.3, which cosign
/// v3 writes with `--bundle`.
pub const BUNDLE_MEDIA_TYPE_V03: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
const STATEMENT_KEYS: [&str; 4] = ["_type", "predicate", "predicateType", "subject"];
const VERSION_MAX_BYTES: usize = 64;

/// Top-level fields of a Sigstore v0.3 DSSE bundle. serde refuses unknown
/// fields (including `messageSignature`) and any field given twice.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleLayout {
    #[serde(rename = "mediaType")]
    media_type: String,
    /// Required to be an object; its contents are cosign's to check.
    #[serde(rename = "verificationMaterial")]
    #[allow(dead_code)]
    #[serde(deserialize_with = "strict_object")]
    verification_material: serde_json::Map<String, Value>,
    #[serde(rename = "dsseEnvelope", deserialize_with = "strict_object")]
    dsse_envelope: serde_json::Map<String, Value>,
}

/// A JSON value read like `Value`, except that an object with a repeated key
/// (at any depth) is an error instead of keeping the last value.
struct StrictValue(Value);

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictValue;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v.to_string())))
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v)))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictValue(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(StrictValue(Value::Array(items)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!("duplicate key `{key}`")));
                    }
                    let StrictValue(value) = map.next_value()?;
                    object.insert(key, value);
                }
                Ok(StrictValue(Value::Object(object)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// A JSON object with no repeated key at any depth.
fn strict_object<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<serde_json::Map<String, Value>, D::Error> {
    match <StrictValue as serde::Deserialize>::deserialize(deserializer)?.0 {
        Value::Object(map) => Ok(map),
        _ => Err(serde::de::Error::custom("expected a JSON object")),
    }
}

/// The in-toto Statement v1 for these receipt bytes.
pub fn build_statement(
    subject_name: &str,
    receipt: &[u8],
    kind: ReceiptKind,
    predicate: &Value,
) -> Value {
    json!({
        "_type": STATEMENT_TYPE_V1,
        "subject": [{"name": subject_name, "digest": {"sha256": sha256_hex(receipt)}}],
        "predicateType": kind.predicate_type(),
        "predicate": predicate,
    })
}

/// Compact JSON with recursively sorted keys.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    canonical_json(value)
        .map(String::into_bytes)
        .map_err(|e| format!("cannot encode canonical JSON: {e}"))
}

/// Decode the bundle's Statement and run [`check_statement`] on it.
pub fn check_bundle(
    bundle: &[u8],
    receipt: &[u8],
    kind: ReceiptKind,
    expected: &Value,
) -> Result<(), String> {
    let statement = decode_bundle_statement(bundle)?;
    check_statement(&statement, receipt, kind, expected)
}

/// The Statement inside a Sigstore bundle's DSSE envelope.
///
/// The bundle must be exactly a v0.3 bundle as cosign v3 writes it: the
/// fields `mediaType`, `verificationMaterial` and one `dsseEnvelope`, nothing
/// else. Unknown, duplicate and `messageSignature` fields are refused.
pub fn decode_bundle_payload(bundle: &[u8]) -> Result<Vec<u8>, String> {
    if bundle.len() > BUNDLE_MAX_BYTES {
        return Err(format!("bundle is larger than {BUNDLE_MAX_BYTES} bytes"));
    }
    let value: Value =
        serde_json::from_slice(bundle).map_err(|e| format!("bundle is not JSON: {e}"))?;
    let object = value.as_object().ok_or("bundle is not a JSON object")?;
    if object.contains_key("messageSignature") {
        return Err("bundle has a messageSignature; only a DSSE attestation is accepted".into());
    }
    if !object.contains_key("dsseEnvelope") {
        return Err(
            "bundle has no dsseEnvelope (a Sigstore bundle from cosign v3 is required)".into(),
        );
    }
    // Parsed again from the bytes: serde_json's `Value` keeps the last of
    // duplicate keys, the derived struct refuses duplicates and unknown keys.
    let layout: BundleLayout = serde_json::from_slice(bundle)
        .map_err(|e| format!("bundle is not a Sigstore v0.3 bundle with one DSSE envelope: {e}"))?;
    if layout.media_type != BUNDLE_MEDIA_TYPE_V03 {
        return Err(format!("bundle mediaType is not {BUNDLE_MEDIA_TYPE_V03}"));
    }
    let envelope = &layout.dsse_envelope;
    if envelope.get("payloadType").and_then(Value::as_str) != Some(DSSE_PAYLOAD_TYPE) {
        return Err(format!("DSSE payloadType is not {DSSE_PAYLOAD_TYPE}"));
    }
    let payload = envelope
        .get("payload")
        .and_then(Value::as_str)
        .ok_or("DSSE envelope has no payload")?;
    let Some(bytes) = decode_base64_strict(payload) else {
        return Err("DSSE payload is not standard base64".into());
    };
    Ok(bytes)
}

/// Parse the original DSSE payload without reserializing its signed bytes.
pub fn decode_bundle_statement(bundle: &[u8]) -> Result<Value, String> {
    let bytes = decode_bundle_payload(bundle)?;
    // Strict like the envelope: a repeated key (at any depth) is refused
    // instead of letting the last value win.
    serde_json::from_slice::<StrictValue>(&bytes)
        .map(|StrictValue(value)| value)
        .map_err(|e| format!("DSSE payload is not JSON without duplicate keys: {e}"))
}

/// Check `_type`, the single subject digest, the predicate type and the
/// predicate. Only `vettalon_version` may differ from `expected`: a newer
/// Vettalon can verify a receipt signed by an older one.
pub fn check_statement(
    statement: &Value,
    receipt: &[u8],
    kind: ReceiptKind,
    expected: &Value,
) -> Result<(), String> {
    let Some(object) = statement.as_object() else {
        return Err("Statement is not a JSON object".into());
    };
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != STATEMENT_KEYS {
        return Err("Statement has unexpected or missing top-level fields".into());
    }
    match object["_type"].as_str() {
        Some(STATEMENT_TYPE_V1 | STATEMENT_TYPE_V01) => {}
        _ => return Err("Statement _type is not an in-toto Statement".into()),
    }
    check_subject(&object["subject"], receipt)?;
    if object["predicateType"].as_str() != Some(kind.predicate_type()) {
        return Err(format!(
            "predicateType does not match a {} receipt",
            kind.key()
        ));
    }
    check_predicate(&object["predicate"], expected)
}

fn check_subject(subject: &Value, receipt: &[u8]) -> Result<(), String> {
    let Some([entry]) = subject.as_array().map(Vec::as_slice) else {
        return Err("Statement must have exactly one subject".into());
    };
    if !entry.get("name").is_some_and(Value::is_string) {
        return Err("Statement subject has no name".into());
    }
    let digest = entry
        .get("digest")
        .and_then(Value::as_object)
        .ok_or("Statement subject has no digest")?;
    if digest.len() != 1 {
        return Err("Statement subject digest must be exactly one sha256".into());
    }
    match digest.get("sha256").and_then(Value::as_str) {
        Some(signed) if signed == sha256_hex(receipt) => Ok(()),
        _ => Err("Statement subject sha256 does not match the receipt bytes".into()),
    }
}

fn check_predicate(signed: &Value, expected: &Value) -> Result<(), String> {
    let version = signed
        .get("vettalon_version")
        .and_then(Value::as_str)
        .filter(|v| valid_version(v))
        .ok_or("signed predicate has no valid vettalon_version")?;
    let mut expected = expected.clone();
    let slot = expected
        .as_object_mut()
        .ok_or("expected predicate is not a JSON object")?;
    slot.insert("vettalon_version".into(), Value::from(version));
    if canonical_bytes(signed)? != canonical_bytes(&expected)? {
        return Err("signed predicate differs from the one extracted from the receipt".into());
    }
    Ok(())
}

fn valid_version(version: &str) -> bool {
    let bounded = (1..=VERSION_MAX_BYTES).contains(&version.len());
    bounded && version.bytes().all(|b| b.is_ascii_graphic())
}

fn sextet(byte: u8) -> Option<u32> {
    let value = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// RFC 4648 standard base64 with padding. No whitespace, no URL alphabet,
/// padding only at the end, unused trailing bits must be zero.
pub fn decode_base64_strict(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.len() / 4;
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let pad = chunk.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 || (pad > 0 && index + 1 != chunks) {
            return None;
        }
        let mut acc = 0u32;
        for byte in &chunk[..4 - pad] {
            acc = (acc << 6) | sextet(*byte)?;
        }
        acc <<= 6 * pad;
        let unused = (1u32 << (8 * pad)) - 1;
        if (acc & unused) != 0 {
            return None;
        }
        out.extend_from_slice(&acc.to_be_bytes()[1..4 - pad]);
    }
    Some(out)
}

/// DSSE pre-authentication encoding; lengths count bytes, not characters.
pub fn dsse_pae(payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "DSSEv1 {} {} {} ",
        DSSE_PAYLOAD_TYPE.len(),
        DSSE_PAYLOAD_TYPE,
        payload.len()
    )
    .into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}

/// RFC 4648 standard base64, with padding and no line wrapping.
pub fn encode_base64_std(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}
