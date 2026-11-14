//! Bounded, no-extraction verification of package evidence and rendered bytes.
use super::engagement::{EngagementFile, parse_engagement};
use super::inputs::{RawInput, RawInputs, ReportInput, check_inputs, parse_report};
use super::write::{
    self, Files, MAX_ENTRIES, Manifest, PACKAGE_SCHEMA, Signatures, canonical, refusal,
};
use super::{PACKAGE_MAX_BYTES, PackageInputs, PackageRefusal, RECEIPT_MAX_BYTES};
use crate::audit::schema::sha256_hex;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use std::path::Path;

#[derive(Debug)]
pub struct Verification {
    pub exit_code: i32,
    pub package_id: String,
    pub checked: &'static str,
}

#[derive(Debug)]
pub struct VerifyError {
    pub exit_code: i32,
    pub token: &'static str,
}
impl From<PackageRefusal> for VerifyError {
    fn from(error: PackageRefusal) -> Self {
        Self {
            exit_code: if error.token == "package_extra_directory" {
                1
            } else {
                2
            },
            token: error.token,
        }
    }
}
fn mismatch(token: &'static str) -> VerifyError {
    VerifyError {
        exit_code: 1,
        token,
    }
}

pub(crate) fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, PackageRefusal> {
    let raw = std::str::from_utf8(bytes).map_err(|_| refusal("package_json_invalid"))?;
    vettalon_contract::strict_json::parse_strict_with_limit(raw, PACKAGE_MAX_BYTES as usize)
        .map_err(|_| refusal("package_json_invalid"))
}

pub fn verify_package(path: &Path, key: Option<&Path>) -> Result<Verification, VerifyError> {
    verify_package_with_pq(path, key, None)
}

pub fn verify_package_with_pq(
    path: &Path,
    key: Option<&Path>,
    pq_key: Option<&Path>,
) -> Result<Verification, VerifyError> {
    let files = read_package(path)?;
    let canonical = path
        .canonicalize()
        .map_err(|_| refusal("package_path_unsafe"))?;
    let excluded = if canonical.is_dir() {
        canonical
    } else {
        canonical
            .parent()
            .ok_or_else(|| refusal("package_path_unsafe"))?
            .to_path_buf()
    };
    verify_files_excluding(&files, key, pq_key, &[excluded])
}

#[cfg(unix)]
pub fn read_package(path: &Path) -> Result<Files, PackageRefusal> {
    use std::os::fd::AsRawFd;
    let (parent, name) = write::io::parent(path)?;
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            info.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(refusal("package_unreadable"));
    }
    let info = unsafe { info.assume_init() };
    match info.st_mode & libc::S_IFMT {
        libc::S_IFDIR => write::io::read_dir(write::io::open(&parent, &name, true)?),
        libc::S_IFREG => {
            // ZIP headers are bounded separately from total uncompressed bytes.
            let bytes = write::io::read_file(
                write::io::open(&parent, &name, false)?,
                PACKAGE_MAX_BYTES + 1024 * 1024,
            )?;
            read_zip(&bytes)
        }
        _ => Err(refusal("package_path_unsafe")),
    }
}
#[cfg(windows)]
pub fn read_package(path: &Path) -> Result<Files, PackageRefusal> {
    write::io::read_package(path)
}
#[cfg(not(any(unix, windows)))]
pub fn read_package(_: &Path) -> Result<Files, PackageRefusal> {
    Err(refusal("package_safe_input_unsupported"))
}

pub(crate) fn read_zip(bytes: &[u8]) -> Result<Files, PackageRefusal> {
    // Bound central-directory allocation before the ZIP library parses it.
    // Packages this small never need ZIP64 or multi-disk extensions.
    if bytes.len() as u64 > PACKAGE_MAX_BYTES + 1024 * 1024 {
        return Err(refusal("package_too_large"));
    }
    let start = bytes.len().saturating_sub(65_557);
    let end = (start..bytes.len().saturating_sub(21))
        .rev()
        .find(|&i| {
            bytes.get(i..i + 4) == Some(b"PK\x05\x06")
                && i + 22 <= bytes.len()
                && i + 22 + u16::from_le_bytes([bytes[i + 20], bytes[i + 21]]) as usize
                    == bytes.len()
        })
        .ok_or_else(|| refusal("package_zip_invalid"))?;
    if end >= 20 && bytes.get(end - 20..end - 16) == Some(b"PK\x06\x07") {
        return Err(refusal("package_zip_invalid"));
    }
    let word = |offset| u16::from_le_bytes([bytes[end + offset], bytes[end + offset + 1]]);
    if word(4) != 0 || word(6) != 0 || word(8) != word(10) || word(10) as usize > MAX_ENTRIES {
        return Err(refusal("package_zip_invalid"));
    }
    let mut zip =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| refusal("package_zip_invalid"))?;
    if zip.has_duplicate_names() {
        return Err(refusal("package_duplicate"));
    }
    zip.validate_header_consistency()
        .map_err(|_| refusal("package_zip_invalid"))?;
    if zip.len() > MAX_ENTRIES {
        return Err(refusal("package_too_large"));
    }
    let mut files = Files::new();
    let mut names = BTreeSet::new();
    let mut remaining = PACKAGE_MAX_BYTES;
    for i in 0..zip.len() {
        let mut member = zip
            .by_index(i)
            .map_err(|_| refusal("package_zip_invalid"))?;
        let path = member
            .name()
            .map_err(|_| refusal("package_zip_invalid"))?
            .into_owned();
        write::safe_name(&path)?;
        if member.is_dir()
            || member.is_symlink()
            || member.encrypted()
            || member
                .unix_mode()
                .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000))
        {
            return Err(refusal("package_path_unsafe"));
        }
        if !names.insert(path.to_ascii_lowercase()) {
            return Err(refusal("package_duplicate"));
        }
        if member.size() > remaining {
            return Err(refusal("package_too_large"));
        }
        let mut data = Vec::new();
        (&mut member)
            .take(remaining + 1)
            .read_to_end(&mut data)
            .map_err(|_| refusal("package_zip_invalid"))?;
        if data.len() as u64 > remaining || data.len() as u64 != member.size() {
            return Err(refusal("package_too_large"));
        }
        remaining -= data.len() as u64;
        files.insert(path, data);
    }
    Ok(files)
}

fn validate_manifest(files: &Files) -> Result<Manifest, VerifyError> {
    write::check_size(files)?;
    let bytes = files
        .get("manifest.json")
        .ok_or_else(|| mismatch("package_manifest_missing"))?;
    let manifest: Manifest = parse(bytes)?;
    if manifest.schema != PACKAGE_SCHEMA
        || manifest.vettalon_version.is_empty()
        || manifest.vettalon_version.len() > 128
        || !manifest
            .vettalon_version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return Err(refusal("package_manifest_invalid").into());
    }
    if canonical(&manifest)? != *bytes {
        return Err(mismatch("package_manifest_noncanonical"));
    }
    let mut names = BTreeSet::new();
    let mut previous = "";
    for entry in &manifest.files {
        write::safe_name(&entry.path)?;
        if entry.path == "manifest.json" || !names.insert(entry.path.to_ascii_lowercase()) {
            return Err(refusal("package_duplicate").into());
        }
        if entry.path.as_str() <= previous
            || write::role(&entry.path) != Some(entry.role.as_str())
            || !crate::audit::verification_context::is_sha256(&entry.sha256)
        {
            return Err(refusal("package_manifest_invalid").into());
        }
        previous = &entry.path;
        let bytes = files
            .get(&entry.path)
            .ok_or_else(|| mismatch("package_file_set_mismatch"))?;
        if bytes.len() as u64 != entry.bytes || sha256_hex(bytes) != entry.sha256 {
            return Err(mismatch("package_hash_mismatch"));
        }
    }
    if files.len() != manifest.files.len() + 1 {
        return Err(mismatch("package_file_set_mismatch"));
    }
    Ok(manifest)
}

pub fn validated_inputs(
    files: &Files,
    manifest: &Manifest,
) -> Result<PackageInputs, PackageRefusal> {
    let mut raw = RawInputs::default();
    for entry in &manifest.files {
        let bytes = &files[&entry.path];
        let raw_input = || -> Result<RawInput, PackageRefusal> {
            if bytes.len() as u64 > RECEIPT_MAX_BYTES {
                return Err(refusal("package_too_large"));
            }
            let mut name = entry
                .path
                .rsplit('/')
                .next()
                .ok_or_else(|| refusal("package_path_unsafe"))?
                .to_owned();
            // The staged bundle name adds a suffix to the original receipt name.
            // Input validation only needs a safe unique bundle basename.
            if entry.role == "signature" {
                name = format!("bundle-{}.json", &entry.sha256[..32]);
            }
            Ok(RawInput {
                name,
                raw: String::from_utf8(bytes.clone())
                    .map_err(|_| refusal("package_input_invalid"))?,
            })
        };
        match entry.role.as_str() {
            "retest" => {
                if raw.retest.replace(raw_input()?).is_some() {
                    return Err(refusal("package_duplicate"));
                }
            }
            "reproduce" => raw.reproduce.push(raw_input()?),
            "fix_check" => raw.fix_check.push(raw_input()?),
            "plans" => {
                if raw.targets.replace(raw_input()?).is_some() {
                    return Err(refusal("package_duplicate"));
                }
            }
            "signature" => raw.bundles.push(raw_input()?),
            "pq_signature" => raw.pq_sigs.push(raw_input()?),
            "report" => {
                let report = parse_report(bytes)?;
                let name = entry
                    .path
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refusal("package_path_unsafe"))?
                    .into();
                if raw
                    .report
                    .replace(ReportInput {
                        name,
                        raw: bytes.clone(),
                        report,
                    })
                    .is_some()
                {
                    return Err(refusal("package_duplicate"));
                }
                raw.include_report = true;
            }
            _ => (),
        }
    }
    check_inputs(raw)
}

/// Stored claims are never verification results. Exit 2 means refused/invalid:
/// a verified claim requires an independently supplied trusted key on every run.
fn checked_signatures(
    value: &Value,
    inputs: &PackageInputs,
    files: &Files,
    key: Option<&Path>,
) -> Result<Signatures, PackageRefusal> {
    let key = key.map(write::read_key).transpose()?;
    let mut claims = Signatures::new();
    let sources = value["sources"]
        .as_array()
        .ok_or_else(|| refusal("package_record_invalid"))?;
    for source in sources {
        let sig = &source["signature"];
        if sig.is_null() || sig["cosign"].is_null() {
            continue;
        }
        let path = sig["path"]
            .as_str()
            .ok_or_else(|| refusal("package_record_invalid"))?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stamp {
            verified: bool,
            key_sha256: String,
            cosign_version: String,
        }
        let stamp: Stamp = serde_json::from_value(sig["cosign"].clone())
            .map_err(|_| refusal("package_record_invalid"))?;
        if stamp.verified && key.is_none() {
            return Err(refusal("package_signature_key_required"));
        }
        let trusted = key
            .as_ref()
            .ok_or_else(|| refusal("package_record_invalid"))?;
        if stamp.key_sha256 != sha256_hex(trusted) || files.get("keys/cosign.pub") != Some(trusted)
        {
            return Err(refusal("package_signature_key_mismatch"));
        }
        if claims
            .insert(
                path.into(),
                super::record::CosignRecord {
                    verified: stamp.verified,
                    key_sha256: stamp.key_sha256,
                    cosign_version: stamp.cosign_version,
                },
            )
            .is_some()
        {
            return Err(refusal("package_duplicate"));
        }
    }
    let mut actual = match key {
        Some(key) => write::verify_signatures(inputs, &key)?,
        None => Signatures::new(),
    };
    // Both runs must use cosign v3.0.4 or later (v3); keep the producer's version for re-rendering.
    for (path, stamp) in &mut actual {
        if let Some(claim) = claims.get(path) {
            for version in [&claim.cosign_version, &stamp.cosign_version] {
                crate::attest::cosign::require_release_version(version)
                    .map_err(|_| refusal("package_signature_claim_mismatch"))?;
            }
            stamp.cosign_version = claim.cosign_version.clone();
        }
    }
    if canonical(&claims)? != canonical(&actual)? {
        return Err(refusal("package_signature_claim_mismatch"));
    }
    Ok(actual)
}

pub fn verify_files(files: &Files, key: Option<&Path>) -> Result<Verification, VerifyError> {
    verify_files_with_pq(files, key, None)
}

pub fn verify_files_with_pq(
    files: &Files,
    key: Option<&Path>,
    pq_key: Option<&Path>,
) -> Result<Verification, VerifyError> {
    verify_files_excluding(files, key, pq_key, &[])
}

fn verify_files_excluding(
    files: &Files,
    key: Option<&Path>,
    pq_key: Option<&Path>,
    excluded: &[std::path::PathBuf],
) -> Result<Verification, VerifyError> {
    if pq_key.is_some() && key.is_none() {
        return Err(refusal("pq_key_requires_key").into());
    }
    let manifest = validate_manifest(files)?;
    let package_id = sha256_hex(&files["manifest.json"]);
    // A different producer may use validators or rendering data unknown here.
    if manifest.vettalon_version != env!("CARGO_PKG_VERSION") {
        return Ok(Verification {
            exit_code: 3,
            package_id,
            checked: "file set and SHA-256 checked; different Vettalon version: input validation, signatures and re-render skipped",
        });
    }
    let mut inputs = validated_inputs(files, &manifest)?;
    inputs.tool_exclusions = excluded.to_vec();
    let record_bytes = files
        .get("record.json")
        .ok_or_else(|| mismatch("package_record_missing"))?;
    let record: Value = parse(record_bytes)?;
    let langs: Vec<String> = serde_json::from_value(record["languages"].clone())
        .map_err(|_| refusal("package_language_invalid"))?;
    let engagement_bytes = files
        .get("engagement.json")
        .ok_or_else(|| mismatch("package_engagement_missing"))?;
    let engagement: EngagementFile = parse(engagement_bytes)?;
    // Reuse the closed TOML parser's normalization, date, character and id rules.
    let toml = toml::to_string(&engagement).map_err(|_| refusal("engagement_refused"))?;
    let engagement =
        parse_engagement(toml.as_bytes()).map_err(|_| refusal("engagement_refused"))?;
    let signatures = checked_signatures(&record, &inputs, files, key)?;
    let pq = checked_pq_signatures(&record, &inputs, files, pq_key)?;
    let mut expected = write::render_with_pq(&inputs, &engagement, &langs, &signatures, &pq)?;
    if let Some(bytes) = files.get("keys/mldsa.pub") {
        expected.insert("keys/mldsa.pub".into(), bytes.clone());
    }
    if let Some(bytes) = files.get("keys/cosign.pub") {
        expected.insert("keys/cosign.pub".into(), bytes.clone());
    }
    expected.insert("manifest.json".into(), files["manifest.json"].clone());
    if &expected != files {
        return Err(mismatch("package_render_mismatch"));
    }
    Ok(Verification {
        exit_code: 0,
        package_id,
        checked: if pq_key.is_some() {
            "file set, SHA-256, input rules, record and Markdown re-render checked; cosign and ML-DSA-65 layer cryptographically verified with supplied keys"
        } else if key.is_some() {
            "file set, SHA-256, input rules, record and Markdown re-render checked; signatures cryptographically verified with supplied key; ML-DSA-65 layer content-matched, not verified"
        } else {
            "file set, SHA-256, input rules, record and Markdown re-render checked; signatures content-matched, not cryptographically verified; ML-DSA-65 layer content-matched, not verified"
        },
    })
}

fn checked_pq_signatures(
    value: &Value,
    inputs: &PackageInputs,
    files: &Files,
    key: Option<&Path>,
) -> Result<write::PqSignatures, PackageRefusal> {
    let key = key.map(write::read_pq_key).transpose()?;
    let mut claims = write::PqSignatures::new();
    for source in value["sources"]
        .as_array()
        .ok_or_else(|| refusal("package_record_invalid"))?
    {
        let sig = &source["signature"];
        let pq = &sig["mldsa"];
        if pq.is_null() || pq["verified"].is_null() {
            continue;
        }
        let stamp: super::record::MldsaRecord = serde_json::from_value(pq["verified"].clone())
            .map_err(|_| refusal("package_record_invalid"))?;
        if stamp.verified && key.is_none() {
            return Err(refusal("package_pq_key_required"));
        }
        if stamp.verified && sig["cosign"]["verified"] != true {
            return Err(refusal("package_record_invalid"));
        }
        let trusted = key
            .as_ref()
            .ok_or_else(|| refusal("package_record_invalid"))?;
        let der = crate::attest::pq::parse_mldsa65_pub_pem(trusted)
            .map_err(|_| refusal("package_pq_key_mismatch"))?;
        if stamp.key_sha256 != sha256_hex(&der) || files.get("keys/mldsa.pub") != Some(trusted) {
            return Err(refusal("package_pq_key_mismatch"));
        }
        let path = pq["path"]
            .as_str()
            .ok_or_else(|| refusal("package_record_invalid"))?;
        if claims.insert(path.into(), stamp).is_some() {
            return Err(refusal("package_duplicate"));
        }
    }
    if let Some(key) = &key
        && files.get("keys/mldsa.pub") != Some(key)
    {
        return Err(refusal("package_pq_key_mismatch"));
    }
    let actual = match key {
        Some(key) => write::verify_pq_signatures(inputs, &key)
            .map_err(|_| refusal("package_pq_claim_mismatch"))?,
        None => write::PqSignatures::new(),
    };
    if canonical(&claims)? != canonical(&actual)? {
        return Err(refusal("package_pq_claim_mismatch"));
    }
    // Binding metadata is also a claim: compare it against validated inputs,
    // including missing, extra, or altered sidecar paths and hashes.
    let mut expected = super::record::build_record(inputs)?;
    let mut expected_pq = std::collections::BTreeMap::new();
    for source in &mut expected.sources {
        if let Some(pq) = source.signature.as_mut().and_then(|s| s.mldsa.as_mut()) {
            pq.verified = actual.get(&pq.path).cloned();
            expected_pq.insert(
                source.path.clone(),
                serde_json::to_value(pq).map_err(|_| refusal("package_record_invalid"))?,
            );
        }
    }
    let mut stored_pq = std::collections::BTreeMap::new();
    for source in value["sources"]
        .as_array()
        .ok_or_else(|| refusal("package_record_invalid"))?
    {
        let pq = &source["signature"]["mldsa"];
        if !pq.is_null() {
            let path = source["path"]
                .as_str()
                .ok_or_else(|| refusal("package_record_invalid"))?;
            if stored_pq.insert(path.to_owned(), pq.clone()).is_some() {
                return Err(refusal("package_duplicate"));
            }
        }
    }
    if canonical(&stored_pq)? != canonical(&expected_pq)? {
        return Err(refusal("package_pq_claim_mismatch"));
    }
    Ok(actual)
}
