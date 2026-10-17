//! Supply-chain hunt: source fetch + safe extraction (phase 1c).
//!
//! Downloads a dependency's canonical published artifact (crates.io `.crate`,
//! npm `.tgz`, PyPI sdist/wheel, Go module `.zip`) and extracts it into a
//! scratch directory for the audit engine to read. URL construction and the
//! extraction are pure and unit-tested; the network is isolated behind
//! [`SourceFetcher`], with the live path in an `#[ignore]`d test.
//!
//! The extracted archive is UNTRUSTED. Extraction therefore refuses absolute
//! and `..` paths (tar-slip / zip-slip), never creates links or special files,
//! and enforces per-file, total-size and file-count caps (decompression-bomb
//! guard).
//!
//! Network boundary: the HTTP
//! fetcher reaches only [`ALLOWED_HOSTS`], and a redirect to any other host is
//! refused. Only the public `name@version` coordinate leaves the machine.

use std::io::Read;
use std::path::{Component, Path};

use async_trait::async_trait;

use super::{DependencyTarget, Ecosystem};

/// Hosts the hunt fetcher may reach (origin + known redirect / CDN targets).
pub const ALLOWED_HOSTS: &[&str] = &[
    "crates.io",
    "static.crates.io",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "proxy.golang.org",
];

/// Compressed download cap (the artifact itself).
pub const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Total uncompressed cap across all entries (bomb guard).
pub const MAX_TOTAL_BYTES: u64 = 192 * 1024 * 1024;
/// Per-file uncompressed cap.
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Entry-count cap.
pub const MAX_FILES: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    TarGz,
    Zip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractStats {
    pub files: usize,
    pub bytes: u64,
}

// ── URL construction (pure) ──────────────────────────────────────────────

pub fn cargo_url(name: &str, version: &str) -> String {
    format!("https://crates.io/api/v1/crates/{name}/{version}/download")
}

/// npm tarball URL. For a scoped name `@scope/pkg` the basename is the
/// unscoped `pkg`: `https://registry.npmjs.org/@scope/pkg/-/pkg-<v>.tgz`.
pub fn npm_url(name: &str, version: &str) -> String {
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    format!("https://registry.npmjs.org/{name}/-/{unscoped}-{version}.tgz")
}

/// Go proxy escapes uppercase letters as `!<lower>` so module paths are
/// case-insensitive on disk.
pub fn escape_go_module(module: &str) -> String {
    let mut s = String::with_capacity(module.len());
    for c in module.chars() {
        if c.is_ascii_uppercase() {
            s.push('!');
            s.push(c.to_ascii_lowercase());
        } else {
            s.push(c);
        }
    }
    s
}

pub fn go_url(module: &str, version: &str) -> String {
    format!(
        "https://proxy.golang.org/{}/@v/{version}.zip",
        escape_go_module(module)
    )
}

pub fn pypi_metadata_url(name: &str, version: &str) -> String {
    format!("https://pypi.org/pypi/{name}/{version}/json")
}

/// Pick the source archive from a PyPI `/pypi/<name>/<version>/json` body:
/// an sdist (`.tar.gz`) if present, else a wheel (`.whl`, a zip).
pub fn pick_pypi_sdist(metadata_json: &str) -> Option<(String, ArchiveKind)> {
    let v: serde_json::Value = serde_json::from_str(metadata_json).ok()?;
    let urls = v.get("urls")?.as_array()?;
    let find = |kind: &str| {
        urls.iter().find_map(|u| {
            (u.get("packagetype").and_then(|p| p.as_str()) == Some(kind))
                .then(|| u.get("url").and_then(|x| x.as_str()).map(str::to_string))
                .flatten()
        })
    };
    if let Some(url) = find("sdist") {
        return Some((url, ArchiveKind::TarGz));
    }
    find("bdist_wheel").map(|url| (url, ArchiveKind::Zip))
}

/// The host component of a URL, lowercased (no scheme, port or path).
pub fn url_host(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    let authority = after.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?; // drop userinfo
    let host = host.split(':').next()?; // drop port
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

pub fn host_allowed(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|url| {
        url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url
                .host_str()
                .is_some_and(|host| ALLOWED_HOSTS.contains(&host))
    })
}

// ── safe extraction (pure over bytes) ────────────────────────────────────

/// A relative path with only normal / `.` components — no `/`, `..` or prefix.
fn is_safe_relative(p: &Path) -> bool {
    let mut any = false;
    for c in p.components() {
        match c {
            Component::Normal(_) => any = true,
            Component::CurDir => {}
            _ => return false, // RootDir, ParentDir, Prefix
        }
    }
    any
}

/// Extract `bytes` of `kind` into `dest`. Refuses unsafe paths, links and
/// special files, and enforces the size / count caps.
pub fn extract(bytes: &[u8], kind: ArchiveKind, dest: &Path) -> Result<ExtractStats, String> {
    match kind {
        ArchiveKind::TarGz => extract_targz(bytes, dest),
        ArchiveKind::Zip => extract_zip(bytes, dest),
    }
}

fn extract_targz(bytes: &[u8], dest: &Path) -> Result<ExtractStats, String> {
    let dec = flate2::read::GzDecoder::new(bytes);
    let mut ar = tar::Archive::new(dec);
    let mut total: u64 = 0;
    let mut files = 0usize;
    for entry in ar.entries().map_err(|e| format!("tar open: {e}"))? {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("tar path: {e}"))?
            .into_owned();
        let etype = entry.header().entry_type();
        if etype.is_dir() {
            if is_safe_relative(&path) {
                let _ = std::fs::create_dir_all(dest.join(&path));
            }
            continue;
        }
        // Only regular files are ever written: never symlinks/hardlinks/devices.
        if !etype.is_file() {
            continue;
        }
        if !is_safe_relative(&path) {
            return Err(format!("unsafe path in archive: {}", path.display()));
        }
        files += 1;
        if files > MAX_FILES {
            return Err("archive has too many files".into());
        }
        total = write_capped(&mut entry, &dest.join(&path), total)?;
    }
    Ok(ExtractStats {
        files,
        bytes: total,
    })
}

fn extract_zip(bytes: &[u8], dest: &Path) -> Result<ExtractStats, String> {
    let mut ar =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| format!("zip open: {e}"))?;
    let mut total: u64 = 0;
    let mut files = 0usize;
    for i in 0..ar.len() {
        let mut file = ar.by_index(i).map_err(|e| format!("zip entry: {e}"))?;
        // enclosed_name is None for an unsafe (escaping) path.
        let Some(path) = file.enclosed_name() else {
            return Err(format!("unsafe path in archive: {}", file.name()));
        };
        if file.is_dir() {
            let _ = std::fs::create_dir_all(dest.join(&path));
            continue;
        }
        files += 1;
        if files > MAX_FILES {
            return Err("archive has too many files".into());
        }
        total = write_capped(&mut file, &dest.join(&path), total)?;
    }
    Ok(ExtractStats {
        files,
        bytes: total,
    })
}

/// Write one entry to `out`, enforcing the per-file and running total caps by
/// reading at most `MAX_FILE_BYTES + 1` (so a lying header can't exceed it).
fn write_capped<R: Read>(reader: &mut R, out: &Path, running_total: u64) -> Result<u64, String> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    let mut limited = reader.take(MAX_FILE_BYTES + 1);
    let mut f = std::fs::File::create(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    let n = std::io::copy(&mut limited, &mut f).map_err(|e| format!("write: {e}"))?;
    if n > MAX_FILE_BYTES {
        return Err("archive file exceeds the per-file cap".into());
    }
    let total = running_total + n;
    if total > MAX_TOTAL_BYTES {
        return Err("archive exceeds the total-size cap".into());
    }
    Ok(total)
}

// ── network (behind a trait) ─────────────────────────────────────────────

/// Fetches and extracts a dependency's source into a directory.
#[async_trait]
pub trait SourceFetcher: Send + Sync {
    async fn fetch_into(
        &self,
        target: &DependencyTarget,
        dest: &Path,
    ) -> Result<ExtractStats, String>;
}

/// Live fetcher. Reaches only [`ALLOWED_HOSTS`]; a redirect elsewhere is
/// refused by the client's redirect policy.
pub struct HttpSourceFetcher {
    http: reqwest::Client,
    max_download_bytes: u64,
    #[cfg(test)]
    observer: Option<ArchiveObserver>,
}

#[cfg(test)]
pub(super) type ArchiveObserver =
    std::sync::Arc<dyn Fn(&str, &str, &[u8]) -> Result<(), String> + Send + Sync>;

const MAX_REGISTRY_REDIRECTS: usize = 3;

fn fetch_redirect_allowed(url: &reqwest::Url, previous: usize) -> bool {
    previous <= MAX_REGISTRY_REDIRECTS && host_allowed(url.as_str())
}

pub(super) fn fetch_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if fetch_redirect_allowed(attempt.url(), attempt.previous().len()) {
            attempt.follow()
        } else {
            attempt.error("registry redirect outside HTTPS allowlist/port or hop limit")
        }
    })
}

pub(super) fn fetch_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(fetch_redirect_policy())
        .timeout(std::time::Duration::from_secs(30))
        .retry(reqwest::retry::never())
}

impl Default for HttpSourceFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpSourceFetcher {
    pub fn new() -> Self {
        let http = fetch_client_builder()
            .build()
            .expect("static registry HTTP client configuration");
        HttpSourceFetcher {
            http,
            max_download_bytes: MAX_DOWNLOAD_BYTES,
            #[cfg(test)]
            observer: None,
        }
    }

    #[cfg(test)]
    pub(super) fn for_transport_test(
        http: reqwest::Client,
        max_download_bytes: u64,
        observer: Option<ArchiveObserver>,
    ) -> Self {
        Self {
            http,
            max_download_bytes,
            observer,
        }
    }

    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, String> {
        if !host_allowed(url) {
            return Err(format!("refusing a non-allowlisted host: {url}"));
        }
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("fetch failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("fetch {url} returned {}", resp.status()));
        }
        #[cfg(test)]
        let final_url = resp.url().to_string();
        // Stream with a hard cap so a huge body cannot exhaust memory.
        let mut resp = resp;
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("read failed: {e}"))?
        {
            buf.extend_from_slice(&chunk);
            if buf.len() as u64 > self.max_download_bytes {
                return Err("download exceeds the size cap".into());
            }
        }
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(url, &final_url, &buf)?;
        }
        Ok(buf)
    }

    async fn plan(&self, t: &DependencyTarget) -> Result<(String, ArchiveKind), String> {
        match t.ecosystem {
            Ecosystem::Cargo => Ok((cargo_url(&t.name, &t.version), ArchiveKind::TarGz)),
            Ecosystem::Npm => Ok((npm_url(&t.name, &t.version), ArchiveKind::TarGz)),
            Ecosystem::Go => Ok((go_url(&t.name, &t.version), ArchiveKind::Zip)),
            Ecosystem::PyPi => {
                let meta = self
                    .get_bytes(&pypi_metadata_url(&t.name, &t.version))
                    .await?;
                let meta = String::from_utf8_lossy(&meta);
                pick_pypi_sdist(&meta)
                    .ok_or_else(|| format!("no source archive for {}@{}", t.name, t.version))
            }
        }
    }
}

#[async_trait]
impl SourceFetcher for HttpSourceFetcher {
    async fn fetch_into(
        &self,
        target: &DependencyTarget,
        dest: &Path,
    ) -> Result<ExtractStats, String> {
        let (url, kind) = self.plan(target).await?;
        let bytes = self.get_bytes(&url).await?;
        // Decompression and file writes are synchronous. Run them off the
        // async task so dependencies audited alongside this one (and their
        // timeouts) keep making progress meanwhile.
        let dest = dest.to_path_buf();
        tokio::task::spawn_blocking(move || extract(&bytes, kind, &dest))
            .await
            .map_err(|e| format!("extraction task failed: {e}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn urls_are_constructed_per_ecosystem() {
        assert_eq!(
            cargo_url("serde", "1.0.200"),
            "https://crates.io/api/v1/crates/serde/1.0.200/download"
        );
        assert_eq!(
            npm_url("lodash", "4.17.21"),
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        );
        assert_eq!(
            npm_url("@scope/ui", "1.2.0"),
            "https://registry.npmjs.org/@scope/ui/-/ui-1.2.0.tgz"
        );
    }

    #[test]
    fn go_module_escaping_lowercases_with_bang() {
        assert_eq!(
            escape_go_module("github.com/Masterminds/semver"),
            "github.com/!masterminds/semver"
        );
        assert_eq!(
            go_url("github.com/pkg/errors", "v0.9.1"),
            "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip"
        );
    }

    #[test]
    fn host_allowlist_accepts_registries_and_rejects_others() {
        assert!(host_allowed("https://crates.io/api/v1/crates/x/1/download"));
        assert!(host_allowed(
            "https://files.pythonhosted.org/packages/x.tar.gz"
        ));
        assert!(!host_allowed("https://evil.example.com/x.tgz"));
        assert!(!host_allowed("https://crates.io.evil.com/x"));
        assert_eq!(
            url_host("https://crates.io:443/x"),
            Some("crates.io".into())
        );
    }

    #[test]
    fn registry_transport_rejects_downgrade_ports_and_redirect_escape() {
        for url in [
            "https://crates.io/x",
            "https://static.crates.io:443/x",
            "https://registry.npmjs.org/x",
        ] {
            assert!(host_allowed(url), "{url}");
            assert!(fetch_redirect_allowed(
                &reqwest::Url::parse(url).unwrap(),
                1
            ));
        }
        for url in [
            "http://crates.io/x",
            "https://crates.io:444/x",
            "https://evil.invalid/x",
            "https://user@crates.io/x",
        ] {
            assert!(!host_allowed(url), "{url}");
            assert!(!fetch_redirect_allowed(
                &reqwest::Url::parse(url).unwrap(),
                1
            ));
        }
        assert!(!fetch_redirect_allowed(
            &reqwest::Url::parse("https://static.crates.io/x").unwrap(),
            4
        ));
    }

    #[test]
    fn pick_pypi_prefers_sdist_then_wheel() {
        let meta = r#"{"urls":[
            {"packagetype":"bdist_wheel","url":"https://files.pythonhosted.org/x.whl"},
            {"packagetype":"sdist","url":"https://files.pythonhosted.org/x.tar.gz"}
        ]}"#;
        assert_eq!(
            pick_pypi_sdist(meta),
            Some((
                "https://files.pythonhosted.org/x.tar.gz".into(),
                ArchiveKind::TarGz
            ))
        );
        let wheel_only = r#"{"urls":[{"packagetype":"bdist_wheel","url":"https://files.pythonhosted.org/x.whl"}]}"#;
        assert_eq!(
            pick_pypi_sdist(wheel_only),
            Some((
                "https://files.pythonhosted.org/x.whl".into(),
                ArchiveKind::Zip
            ))
        );
        assert!(pick_pypi_sdist("{}").is_none());
    }

    fn targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extract_targz_writes_safe_files() {
        let bytes = targz(&[
            ("pkg/src/lib.rs", b"fn main(){}"),
            ("pkg/Cargo.toml", b"[package]"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let stats = extract(&bytes, ArchiveKind::TarGz, dir.path()).unwrap();
        assert_eq!(stats.files, 2);
        assert!(dir.path().join("pkg/src/lib.rs").is_file());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("pkg/Cargo.toml")).unwrap(),
            "[package]"
        );
    }

    #[test]
    fn is_safe_relative_accepts_normal_rejects_escapes() {
        assert!(is_safe_relative(Path::new("pkg/src/lib.rs")));
        assert!(is_safe_relative(Path::new("./a/b")));
        assert!(!is_safe_relative(Path::new("../escape")));
        assert!(!is_safe_relative(Path::new("/etc/passwd")));
        assert!(!is_safe_relative(Path::new("a/../../b")));
        assert!(!is_safe_relative(Path::new(""))); // no normal component
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn extract_zip_writes_safe_files() {
        let bytes = zip_bytes(&[
            ("mod/go.mod", b"module x"),
            ("mod/main.go", b"package main"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let stats = extract(&bytes, ArchiveKind::Zip, dir.path()).unwrap();
        assert_eq!(stats.files, 2);
        assert!(dir.path().join("mod/main.go").is_file());
    }

    #[test]
    fn extract_zip_refuses_path_traversal() {
        // zip's writer permits a `..` name (that is the zip-slip risk); the
        // extractor must reject it via enclosed_name().
        let bytes = zip_bytes(&[("../escape.txt", b"pwn")]);
        let dir = tempfile::tempdir().unwrap();
        let err = extract(&bytes, ArchiveKind::Zip, dir.path()).unwrap_err();
        assert!(err.contains("unsafe path"), "{err}");
        assert!(!dir.path().parent().unwrap().join("escape.txt").exists());
    }

    /// Live fetch. Ignored by default; run with
    /// `cargo test -p vettalon --lib hunt::fetch -- --ignored`. cfg-if is a
    /// tiny, stable crate.
    #[tokio::test]
    #[ignore = "hits crates.io"]
    async fn live_fetch_a_small_crate() {
        let dir = tempfile::tempdir().unwrap();
        let t = DependencyTarget {
            ecosystem: Ecosystem::Cargo,
            name: "cfg-if".into(),
            version: "1.0.0".into(),
            direct: true,
        };
        let stats = HttpSourceFetcher::new()
            .fetch_into(&t, dir.path())
            .await
            .expect("fetch cfg-if");
        assert!(stats.files > 0);
        // crates.io tarballs are `<name>-<version>/…`.
        assert!(dir.path().join("cfg-if-1.0.0/Cargo.toml").is_file());
    }
}
