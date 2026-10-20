//! Local cached index of OpenSSF malicious-package (`MAL-*`) reports (O18).
//!
//! Source: the OSV per-ecosystem export
//! `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`,
//! keeping only `MAL-*` records. Those records are imported from
//! `ossf/malicious-packages` (Apache-2.0; licence checked via the GitHub API on
//! 2026-10-20) and each one links its source file there. The downloader only
//! reaches that one host, caps the size, records the archive SHA-256, and
//! refuses to install when `--expect-sha256` is given and differs. The saved
//! compact index has a `.sha256` sidecar that the loader verifies, so a
//! modified index is reported as unusable instead of silently matching.
//! Matching is metadata only: package name + version, never package code.

use std::collections::HashMap;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{Ecosystem, popular};

/// The only host the index downloader may reach.
pub const MAL_INDEX_HOST: &str = "osv-vulnerabilities.storage.googleapis.com";
/// Archive cap (the npm export is ~220 MB in 2026-10).
pub const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
/// One OSV record cap inside the archive.
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_RECORDS: usize = 2_000_000;
pub const LICENCE_NOTE: &str =
    "MAL-* records from ossf/malicious-packages (Apache-2.0), via the OSV export";

/// One malicious-package report for one package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalEntry {
    pub id: String,
    pub name: String,
    /// Explicitly listed affected versions.
    pub versions: Vec<String>,
    /// Ranges without an explicit version list: treat every version as affected.
    pub all_versions: bool,
}

/// Compact per-ecosystem index with provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalIndex {
    pub schema: u32,
    /// OSV ecosystem string (`npm`, `PyPI`, `crates.io`, `Go`).
    pub ecosystem: String,
    pub source_url: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    /// Whether the operator pinned the archive hash (`--expect-sha256`).
    pub sha256_pinned: bool,
    pub fetched_at: String,
    pub licence: String,
    pub entries: Vec<MalEntry>,
    #[serde(skip)]
    by_name: HashMap<String, Vec<usize>>,
}

/// Provenance summary for reports (no entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalIndexInfo {
    pub ecosystem: String,
    pub entries: usize,
    pub archive_sha256: String,
    pub sha256_pinned: bool,
    pub fetched_at: String,
    pub source_url: String,
}

pub fn ecosystem_of(osv: &str) -> Option<Ecosystem> {
    match osv {
        "npm" => Some(Ecosystem::Npm),
        "PyPI" => Some(Ecosystem::PyPi),
        "crates.io" => Some(Ecosystem::Cargo),
        "Go" => Some(Ecosystem::Go),
        _ => None,
    }
}

pub fn archive_url(osv_ecosystem: &str) -> Result<String, String> {
    ecosystem_of(osv_ecosystem)
        .map(|_| format!("https://{MAL_INDEX_HOST}/{osv_ecosystem}/all.zip"))
        .ok_or_else(|| {
            format!("unsupported ecosystem {osv_ecosystem:?} (npm, PyPI, crates.io, Go)")
        })
}

impl MalIndex {
    fn reindex(&mut self) {
        let eco = ecosystem_of(&self.ecosystem).unwrap_or(Ecosystem::Npm);
        self.by_name.clear();
        for (i, e) in self.entries.iter().enumerate() {
            self.by_name
                .entry(popular::normalize(eco, &e.name))
                .or_default()
                .push(i);
        }
    }

    pub fn info(&self) -> MalIndexInfo {
        MalIndexInfo {
            ecosystem: self.ecosystem.clone(),
            entries: self.entries.len(),
            archive_sha256: self.archive_sha256.clone(),
            sha256_pinned: self.sha256_pinned,
            fetched_at: self.fetched_at.clone(),
            source_url: self.source_url.clone(),
        }
    }

    /// Reports matching `name@version` in this index's ecosystem.
    pub fn matches(&self, ecosystem: Ecosystem, name: &str, version: &str) -> Vec<&MalEntry> {
        if ecosystem_of(&self.ecosystem) != Some(ecosystem) {
            return Vec::new();
        }
        self.by_name
            .get(&popular::normalize(ecosystem, name))
            .into_iter()
            .flatten()
            .map(|&i| &self.entries[i])
            .filter(|e| {
                let same = |v: &String| {
                    v == version
                        || (ecosystem == Ecosystem::Go
                            && v.trim_start_matches('v') == version.trim_start_matches('v'))
                };
                e.all_versions || e.versions.iter().any(same)
            })
            .collect()
    }
}

/// Build an index from an OSV `all.zip`, keeping only `MAL-*` records.
pub fn build_from_zip<R: Read + Seek>(
    reader: R,
    osv_ecosystem: &str,
    provenance: (&str, &str, u64, bool, &str),
) -> Result<MalIndex, String> {
    let (source_url, sha256, bytes, pinned, fetched_at) = provenance;
    ecosystem_of(osv_ecosystem).ok_or("unsupported ecosystem")?;
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| format!("zip open: {e}"))?;
    if zip.len() > MAX_RECORDS {
        return Err("archive has too many records".into());
    }
    let mut entries = Vec::new();
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).map_err(|e| format!("zip entry: {e}"))?;
        let Some(path) = file.enclosed_name() else {
            continue; // never trust an escaping name, even though nothing is written
        };
        let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !(base.starts_with("MAL-") && base.ends_with(".json")) || file.is_dir() {
            continue;
        }
        let mut raw = Vec::new();
        (&mut file)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|e| format!("zip read: {e}"))?;
        if raw.len() as u64 > MAX_RECORD_BYTES {
            continue;
        }
        let Ok(rec) = serde_json::from_slice::<serde_json::Value>(&raw) else {
            continue;
        };
        entries.extend(entries_from_record(&rec, osv_ecosystem));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    let mut index = MalIndex {
        schema: 1,
        ecosystem: osv_ecosystem.to_string(),
        source_url: source_url.to_string(),
        archive_sha256: sha256.to_string(),
        archive_bytes: bytes,
        sha256_pinned: pinned,
        fetched_at: fetched_at.to_string(),
        licence: LICENCE_NOTE.to_string(),
        entries,
        by_name: HashMap::new(),
    };
    index.reindex();
    Ok(index)
}

/// `MalEntry` rows from one OSV record (withdrawn records are skipped).
pub fn entries_from_record(rec: &serde_json::Value, osv_ecosystem: &str) -> Vec<MalEntry> {
    let Some(id) = rec.get("id").and_then(|x| x.as_str()) else {
        return Vec::new();
    };
    if !id.starts_with("MAL-") || rec.get("withdrawn").is_some() {
        return Vec::new();
    }
    rec.get("affected")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .filter(|a| a.pointer("/package/ecosystem").and_then(|e| e.as_str()) == Some(osv_ecosystem))
        .filter_map(|a| {
            let name = a.pointer("/package/name")?.as_str()?.to_string();
            let versions: Vec<String> = a
                .get("versions")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .take(1000)
                .collect();
            let ranged = a
                .get("ranges")
                .and_then(|r| r.as_array())
                .is_some_and(|r| !r.is_empty());
            Some(MalEntry {
                id: id.to_string(),
                name,
                all_versions: versions.is_empty() && ranged,
                versions,
            })
        })
        .collect()
}

fn index_path(dir: &Path, osv_ecosystem: &str) -> PathBuf {
    let safe: String = osv_ecosystem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    dir.join(format!("{safe}.json"))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Save `index` and its `.sha256` sidecar (private files).
pub fn save(dir: &Path, index: &MalIndex) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let path = index_path(dir, &index.ecosystem);
    let json = serde_json::to_vec(index).map_err(|e| format!("serialise index: {e}"))?;
    crate::util::write_private(&path, &json)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    let side = path.with_extension("json.sha256");
    crate::util::write_private(&side, format!("{}\n", sha256_hex(&json)).as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", side.display()))?;
    Ok(path)
}

/// Load every saved index in `dir`, verifying each sidecar. Returns the usable
/// indexes and one error per file that failed (never silently skipped).
pub fn load_dir(dir: &Path) -> (Vec<MalIndex>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for eco in ["npm", "PyPI", "crates.io", "Go"] {
        let path = index_path(dir, eco);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let side = std::fs::read_to_string(path.with_extension("json.sha256")).unwrap_or_default();
        if side.trim() != sha256_hex(&bytes) {
            errors.push(format!(
                "{}: SHA-256 sidecar mismatch or missing; index not used",
                path.display()
            ));
            continue;
        }
        match serde_json::from_slice::<MalIndex>(&bytes) {
            Ok(mut index) if index.schema == 1 && index.ecosystem == eco => {
                index.reindex();
                out.push(index);
            }
            Ok(_) => errors.push(format!("{}: unexpected schema/ecosystem", path.display())),
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }
    (out, errors)
}

/// `true` when `url` is the HTTPS index host on the standard port.
pub fn index_url_allowed(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            && u.port_or_known_default() == Some(443)
            && u.host_str() == Some(MAL_INDEX_HOST)
            && u.username().is_empty()
            && u.password().is_none()
    })
}

/// Download `url` into `dest` (streamed, capped), returning `(sha256, bytes)`.
pub async fn download(url: &str, dest: &Path) -> Result<(String, u64), String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    if !index_url_allowed(url) {
        return Err(format!("refusing a non-allowlisted index URL: {url}"));
    }
    let http = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(600))
        .retry(reqwest::retry::never())
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;
    let mut resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("index download failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("index download returned {}", resp.status()));
    }
    let mut file = std::fs::File::create(dest)
        .map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("index read failed: {e}"))?
    {
        total += chunk.len() as u64;
        if total > MAX_ARCHIVE_BYTES {
            return Err("index archive exceeds the size cap".into());
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .map_err(|e| format!("write {}: {e}", dest.display()))?;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Hash a local archive (for `--from-file`).
pub fn hash_file(path: &Path) -> Result<(String, u64), String> {
    use sha2::{Digest, Sha256};
    let mut f =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_ARCHIVE_BYTES {
            return Err("index archive exceeds the size cap".into());
        }
        hasher.update(&buf[..n]);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Verify an optional pinned hash, then build and save the index.
pub fn install(
    archive: &Path,
    osv_ecosystem: &str,
    source_url: &str,
    (sha256, bytes): (String, u64),
    expect_sha256: Option<&str>,
    dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(PathBuf, MalIndex), String> {
    if let Some(expected) = expect_sha256
        && !expected.trim().eq_ignore_ascii_case(&sha256)
    {
        return Err(format!(
            "archive SHA-256 {sha256} does not match --expect-sha256 {expected}; not installed"
        ));
    }
    let file = std::fs::File::open(archive)
        .map_err(|e| format!("cannot open {}: {e}", archive.display()))?;
    let index = build_from_zip(
        std::io::BufReader::new(file),
        osv_ecosystem,
        (
            source_url,
            &sha256,
            bytes,
            expect_sha256.is_some(),
            &now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
    )?;
    let path = save(dir, &index)?;
    Ok((path, index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Pinned FIPS 180-2 vectors: the sidecar and `--expect-sha256` compare
    // these lowercase hex strings, so they must not change across sha2 bumps.
    #[test]
    fn hashes_are_pinned_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Spans many read-buffer chunks.
        f.write_all(&vec![b'a'; 1_000_000]).unwrap();
        f.flush().unwrap();
        assert_eq!(
            hash_file(f.path()).unwrap(),
            (
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0".to_string(),
                1_000_000
            )
        );
    }

    fn record(id: &str, name: &str, versions: &[&str], ranged: bool) -> String {
        serde_json::json!({
            "id": id,
            "affected": [{
                "package": {"ecosystem": "crates.io", "name": name},
                "versions": versions,
                "ranges": if ranged { serde_json::json!([{"type":"SEMVER","events":[{"introduced":"0"}]}]) } else { serde_json::json!([]) }
            }]
        })
        .to_string()
    }

    fn zip_of(files: &[(&str, String)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (name, body) in files {
            w.start_file(*name, opts).unwrap();
            w.write_all(body.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn sample_zip() -> Vec<u8> {
        zip_of(&[
            ("MAL-2026-6959.json", record("MAL-2026-6959", "proton-pfff", &["99.99.5"], false)),
            ("MAL-2026-1.json", record("MAL-2026-1", "evil_crate", &[], true)),
            ("RUSTSEC-2026-0001.json", record("RUSTSEC-2026-0001", "serde", &["1.0.0"], false)),
            ("MAL-2026-2.json", "not json".to_string()),
            (
                "MAL-2026-3.json",
                serde_json::json!({"id":"MAL-2026-3","withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"gone"},"versions":["1.0.0"]}]}).to_string(),
            ),
        ])
    }

    fn provenance() -> (&'static str, &'static str, u64, bool, &'static str) {
        (
            "https://example.invalid/all.zip",
            "abc",
            3,
            false,
            "2026-10-20T00:00:00Z",
        )
    }

    #[test]
    fn index_keeps_only_mal_records_and_matches_versions() {
        let idx = build_from_zip(
            std::io::Cursor::new(sample_zip()),
            "crates.io",
            provenance(),
        )
        .unwrap();
        assert_eq!(
            idx.entries.len(),
            2,
            "RUSTSEC, malformed and withdrawn are excluded"
        );
        assert_eq!(
            idx.matches(Ecosystem::Cargo, "proton_pfff", "99.99.5")
                .len(),
            1
        );
        assert!(
            idx.matches(Ecosystem::Cargo, "proton-pfff", "1.0.0")
                .is_empty()
        );
        assert_eq!(
            idx.matches(Ecosystem::Cargo, "evil-crate", "7.0.0").len(),
            1
        );
        assert!(
            idx.matches(Ecosystem::Npm, "proton-pfff", "99.99.5")
                .is_empty()
        );
        assert!(idx.matches(Ecosystem::Cargo, "serde", "1.0.0").is_empty());
    }

    #[test]
    fn saved_index_round_trips_and_tamper_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let idx = build_from_zip(
            std::io::Cursor::new(sample_zip()),
            "crates.io",
            provenance(),
        )
        .unwrap();
        let path = save(dir.path(), &idx).unwrap();
        let (loaded, errors) = load_dir(dir.path());
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            loaded[0]
                .matches(Ecosystem::Cargo, "proton-pfff", "99.99.5")
                .len(),
            1
        );
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b" ");
        std::fs::write(&path, bytes).unwrap();
        let (loaded, errors) = load_dir(dir.path());
        assert!(loaded.is_empty());
        assert!(errors[0].contains("sidecar mismatch"));
    }

    #[test]
    fn install_refuses_a_pinned_hash_mismatch_and_records_pinning() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("all.zip");
        std::fs::write(&archive, sample_zip()).unwrap();
        let hashed = hash_file(&archive).unwrap();
        let now = chrono::Utc::now();
        let err = install(
            &archive,
            "crates.io",
            "u",
            hashed.clone(),
            Some("00"),
            dir.path(),
            now,
        )
        .unwrap_err();
        assert!(err.contains("does not match"));
        assert!(
            load_dir(dir.path()).0.is_empty(),
            "nothing installed on mismatch"
        );
        let (_, idx) = install(
            &archive,
            "crates.io",
            "u",
            hashed.clone(),
            Some(&hashed.0.to_uppercase()),
            dir.path(),
            now,
        )
        .unwrap();
        assert!(idx.sha256_pinned);
        assert_eq!(idx.archive_sha256, hashed.0);
    }

    #[test]
    fn downloader_only_reaches_the_osv_export_host() {
        assert!(index_url_allowed(
            "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
        ));
        for bad in [
            "http://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
            "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip",
            "https://osv-vulnerabilities.storage.googleapis.com:8443/npm/all.zip",
            "https://evil.invalid/all.zip",
        ] {
            assert!(!index_url_allowed(bad), "{bad}");
        }
        assert_eq!(
            archive_url("PyPI").unwrap(),
            "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
        );
        assert!(archive_url("Maven").is_err());
    }
}
