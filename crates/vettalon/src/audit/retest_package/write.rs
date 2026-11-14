//! Deterministic package assembly and exclusive, descriptor-relative publication.
use super::engagement::{
    EngagementFile, engagement_template, parse_engagement, validate_finding_ids,
};
use super::record::{CosignRecord, Record, build_record, record_field_paths};
use super::text::{load_mapping, load_text};
use super::{PACKAGE_MAX_BYTES, PackageInputs, PackageRefusal, PackageRequest};
use crate::audit::schema::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

pub use io::publish;

pub const PACKAGE_SCHEMA: &str = "vettalon.retest-package/1";
pub(crate) const MAX_ENTRIES: usize = 512;
pub type Files = BTreeMap<String, Vec<u8>>;
pub(crate) type Signatures = BTreeMap<String, CosignRecord>;
pub(crate) type PqSignatures = BTreeMap<String, super::record::MldsaRecord>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub vettalon_version: String,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub path: String,
    pub role: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct WriteOptions {
    pub out: PathBuf,
    /// Write a ZIP at `out` instead of a directory.
    pub zip: bool,
    pub languages: Vec<String>,
    pub engagement: Option<PathBuf>,
}

pub(crate) fn refusal(token: &'static str) -> PackageRefusal {
    PackageRefusal::new(token, "package operation refused")
}

/// Pretty, sorted-key JSON with exactly one trailing newline.
pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, PackageRefusal> {
    let value = serde_json::to_value(value).map_err(|_| refusal("package_json_invalid"))?;
    let mut bytes =
        serde_json::to_vec_pretty(&value).map_err(|_| refusal("package_json_invalid"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn safe_name(path: &str) -> Result<(), PackageRefusal> {
    vettalon_contract::safe_path::SafeRepoPath::parse(path)
        .map_err(|_| refusal("package_path_unsafe"))?;
    if path.split('/').count() > 3 {
        return Err(refusal("package_depth_exceeded"));
    }
    Ok(())
}

pub(crate) fn languages(values: &[String]) -> Result<Vec<String>, PackageRefusal> {
    if values.is_empty() || values.iter().any(|s| s != "zh-TW" && s != "en") {
        return Err(refusal("package_language_invalid"));
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != values.len() {
        return Err(refusal("package_language_invalid"));
    }
    Ok(sorted)
}

pub(crate) fn role(path: &str) -> Option<&'static str> {
    match path {
        "record.json" => Some("record"),
        "record.zh-TW.md" | "record.en.md" => Some("markdown"),
        "mapping.json" => Some("mapping"),
        "text.json" => Some("text"),
        "engagement.json" => Some("engagement"),
        "keys/cosign.pub" => Some("key"),
        "keys/mldsa.pub" => Some("pq_key"),
        _ => {
            let (dir, name) = path.rsplit_once('/')?;
            if name.is_empty() {
                return None;
            }
            match dir {
                "receipts/retest" => Some("retest"),
                "receipts/reproduce" => Some("reproduce"),
                "receipts/fix-check" => Some("fix_check"),
                "receipts/plans" => Some("plans"),
                "signatures" => Some("signature"),
                "signatures-pq" => Some("pq_signature"),
                "report" => Some("report"),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn render(
    inputs: &PackageInputs,
    engagement: &EngagementFile,
    langs: &[String],
    signatures: &Signatures,
) -> Result<Files, PackageRefusal> {
    render_with_pq(inputs, engagement, langs, signatures, &PqSignatures::new())
}

pub(crate) fn render_with_pq(
    inputs: &PackageInputs,
    engagement: &EngagementFile,
    langs: &[String],
    signatures: &Signatures,
    pq: &PqSignatures,
) -> Result<Files, PackageRefusal> {
    validate_finding_ids(
        engagement,
        &inputs.row_ids().into_iter().map(str::to_owned).collect(),
    )
    .map_err(|_| refusal("engagement_refused"))?;
    let mapping = load_mapping(&record_field_paths()).map_err(|_| refusal("mapping_invalid"))?;
    let text = load_text().map_err(|_| refusal("text_invalid"))?;
    let mut record: Record = build_record(inputs)?;
    record.languages = languages(langs)?;
    record.mapping_version = Some(mapping.version.clone());
    record.limits = text.locales["en"]
        .keys()
        .filter(|k| k.starts_with("limit."))
        .cloned()
        .collect();
    record.engagement = engagement.engagement.clone();
    for finding in &mut record.findings {
        if let Some(operator) = engagement
            .finding
            .iter()
            .find(|f| f.id.as_deref() == Some(&finding.id))
        {
            finding.operator = operator.clone();
        }
    }
    for source in &mut record.sources {
        if let Some(signature) = &mut source.signature {
            signature.cosign = signatures.get(&signature.path).cloned();
            if let Some(mldsa) = &mut signature.mldsa {
                mldsa.verified = pq.get(&mldsa.path).cloned();
            }
        }
    }
    let mut files = Files::new();
    for source in &inputs.sources {
        safe_name(&source.path)?;
        if files
            .insert(source.path.clone(), source.bytes.clone())
            .is_some()
        {
            return Err(refusal("package_duplicate"));
        }
    }
    files.insert("record.json".into(), canonical(&record)?);
    files.insert("engagement.json".into(), canonical(engagement)?);
    files.insert("mapping.json".into(), canonical(&mapping)?);
    // Keep the exact versioned wording available to offline readers.
    files.insert("text.json".into(), canonical(&text)?);
    for locale in &record.languages {
        let lang = if locale == "en" {
            crate::lang::Lang::En
        } else {
            crate::lang::Lang::ZhTw
        };
        let md = super::markdown::render_markdown(&record, lang, &text, &mapping)
            .map_err(|_| refusal("render_failed"))?;
        files.insert(format!("record.{locale}.md"), md.into_bytes());
    }
    Ok(files)
}

pub(crate) fn seal(files: &mut Files) -> Result<String, PackageRefusal> {
    let manifest = Manifest {
        schema: PACKAGE_SCHEMA.into(),
        vettalon_version: env!("CARGO_PKG_VERSION").into(),
        files: files
            .iter()
            .map(|(path, bytes)| {
                Ok(ManifestFile {
                    path: path.clone(),
                    role: role(path)
                        .ok_or_else(|| refusal("package_role_invalid"))?
                        .into(),
                    sha256: sha256_hex(bytes),
                    bytes: bytes.len() as u64,
                })
            })
            .collect::<Result<_, PackageRefusal>>()?,
    };
    let bytes = canonical(&manifest)?;
    let id = sha256_hex(&bytes);
    files.insert("manifest.json".into(), bytes);
    check_size(files)?;
    Ok(id)
}

pub(crate) fn check_size(files: &Files) -> Result<(), PackageRefusal> {
    if files.len() > MAX_ENTRIES
        || files.values().map(|b| b.len() as u64).sum::<u64>() > PACKAGE_MAX_BYTES
    {
        return Err(refusal("package_too_large"));
    }
    Ok(())
}

/// Validate all evidence before creating any output. Keys are snapshotted once.
pub fn write_package(
    request: &PackageRequest,
    options: &WriteOptions,
) -> Result<String, PackageRefusal> {
    if request.report.is_some() && !request.include_report {
        return Err(PackageRefusal::new(
            "report_required_for_verification",
            "use --include-report to permit deterministic verification",
        ));
    }
    if request.include_report && request.report.is_none() {
        return Err(refusal("report_missing"));
    }
    let mut content_request = request.clone();
    if request.pq_key.is_some() && request.key.is_none() {
        return Err(refusal("pq_key_requires_key"));
    }
    content_request.key = None;
    content_request.pq_key = None;
    let inputs = super::load_inputs(&content_request)?;
    let engagement = match &options.engagement {
        Some(path) => {
            let raw = crate::remediation::read_regular_capped(
                path,
                super::engagement::MAX_ENGAGEMENT_BYTES as u64,
                "engagement",
            )
            .map_err(|_| refusal("engagement_unreadable"))?;
            parse_engagement(raw.as_bytes()).map_err(|_| refusal("engagement_refused"))?
        }
        None => parse_engagement(engagement_template().as_bytes())
            .map_err(|_| refusal("engagement_refused"))?,
    };
    let (key, signatures) = match &request.key {
        Some(path) => {
            let bytes = read_key(path)?;
            let signatures = verify_signatures(&inputs, &bytes)?;
            (Some(bytes), signatures)
        }
        None => (None, Signatures::new()),
    };
    let pq_key = request.pq_key.as_deref().map(read_pq_key).transpose()?;
    let pq = match &pq_key {
        Some(key) => verify_pq_signatures(&inputs, key)?,
        None => PqSignatures::new(),
    };
    let mut files = render_with_pq(&inputs, &engagement, &options.languages, &signatures, &pq)?;
    if let Some(key) = pq_key {
        files.insert("keys/mldsa.pub".into(), key);
    }
    if let Some(key) = key {
        files.insert("keys/cosign.pub".into(), key);
    }
    let id = seal(&mut files)?;
    if options.zip {
        let bytes = zip_bytes(&files)?;
        io::publish(&options.out, &files, Some(&bytes))?;
    } else {
        io::publish(&options.out, &files, None)?;
    }
    Ok(id)
}

pub(crate) fn read_key(path: &Path) -> Result<Vec<u8>, PackageRefusal> {
    crate::remediation::read_regular_capped(path, 64 * 1024, "public key")
        .map(String::into_bytes)
        .map_err(|_| refusal("key_unreadable"))
}

pub(crate) fn verify_signatures(
    inputs: &PackageInputs,
    key: &[u8],
) -> Result<Signatures, PackageRefusal> {
    if !inputs
        .sources
        .iter()
        .any(|s| s.kind == super::SourceKind::Signature)
    {
        return Err(refusal("bundle_signature_invalid"));
    }
    let excluded: Vec<&Path> = inputs
        .tool_exclusions
        .iter()
        .map(PathBuf::as_path)
        .collect();
    // This is the existing A5 staging model. Archive paths are never extracted.
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let stage = tempfile::tempdir().map_err(|_| refusal("signature_staging_failed"))?;
                let key_path = stage.path().join("cosign.pub");
                std::fs::write(&key_path, key).map_err(|_| refusal("signature_staging_failed"))?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| refusal("signature_staging_failed"))?;
                let mut results = Signatures::new();
                for bundle in inputs
                    .sources
                    .iter()
                    .filter(|s| s.kind == super::SourceKind::Signature)
                {
                    let receipt = inputs
                        .sources
                        .iter()
                        .find(|s| Some(&s.path) == bundle.covers.as_ref())
                        .ok_or_else(|| refusal("bundle_signature_invalid"))?;
                    let run = tempfile::tempdir_in(stage.path())
                        .map_err(|_| refusal("signature_staging_failed"))?;
                    let blob = run.path().join(&receipt.name);
                    let sig = run.path().join("bundle.sigstore.json");
                    std::fs::write(&blob, &receipt.bytes)
                        .and_then(|()| std::fs::write(&sig, &bundle.bytes))
                        .map_err(|_| refusal("signature_staging_failed"))?;
                    let verified = runtime
                        .block_on(crate::attest::verify_receipt_excluding(
                            &blob, &key_path, &sig, &excluded,
                        ))
                        .map_err(|_| refusal("bundle_signature_invalid"))?;
                    results.insert(
                        bundle.path.clone(),
                        CosignRecord {
                            verified: true,
                            key_sha256: sha256_hex(key),
                            cosign_version: verified.cosign_version,
                        },
                    );
                }
                Ok(results)
            })
            .join()
            .map_err(|_| refusal("signature_staging_failed"))?
    })
}

pub(crate) fn zip_bytes(files: &Files) -> Result<Vec<u8>, PackageRefusal> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o600);
    for (path, bytes) in files {
        safe_name(path)?;
        zip.start_file(path, options)
            .map_err(|_| refusal("zip_write_failed"))?;
        zip.write_all(bytes)
            .map_err(|_| refusal("zip_write_failed"))?;
    }
    Ok(zip
        .finish()
        .map_err(|_| refusal("zip_write_failed"))?
        .into_inner())
}

#[cfg(unix)]
pub(crate) mod io {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    fn name(value: &str) -> Result<CString, PackageRefusal> {
        CString::new(value).map_err(|_| refusal("package_path_unsafe"))
    }
    pub(crate) fn parent(path: &Path) -> Result<(File, CString), PackageRefusal> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|_| refusal("package_path_unsafe"))?
                .join(path)
        };
        let relative = absolute
            .strip_prefix("/")
            .map_err(|_| refusal("package_path_unsafe"))?;
        crate::remediation::repo_output_parent(Path::new("/"), relative)
            .map_err(|_| refusal("package_path_unsafe"))
    }
    pub(crate) fn open(dir: &File, entry: &CStr, directory: bool) -> Result<File, PackageRefusal> {
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if directory { libc::O_DIRECTORY } else { 0 };
        // SAFETY: the directory and NUL-terminated entry are live.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), entry.as_ptr(), flags) };
        if fd < 0 {
            return Err(refusal("package_path_unsafe"));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata().map_err(|_| refusal("package_unreadable"))?;
        if !(meta.is_file() || directory && meta.is_dir()) {
            return Err(refusal("package_path_unsafe"));
        }
        Ok(file)
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Identity {
        dev: libc::dev_t,
        ino: libc::ino_t,
    }
    impl Identity {
        fn of(file: &File) -> Result<Self, PackageRefusal> {
            let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
                return Err(refusal("package_unreadable"));
            }
            let info = unsafe { info.assume_init() };
            Ok(Self {
                dev: info.st_dev,
                ino: info.st_ino,
            })
        }
        fn matches(self, dir: &File, entry: &CStr) -> bool {
            let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    entry.as_ptr(),
                    info.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return false;
            }
            let info = unsafe { info.assume_init() };
            self.dev == info.st_dev && self.ino == info.st_ino
        }
        fn remove(self, dir: &File, entry: &CStr, flags: i32) {
            if self.matches(dir, entry) {
                unsafe {
                    libc::unlinkat(dir.as_raw_fd(), entry.as_ptr(), flags);
                }
            }
        }
    }
    fn trusted_parent(parent: &File) -> Result<(), PackageRefusal> {
        let meta = parent
            .metadata()
            .map_err(|_| refusal("package_unreadable"))?;
        if meta.uid() != unsafe { libc::geteuid() }
            || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0)
        {
            return Err(refusal("package_parent_unsafe"));
        }
        Ok(())
    }
    // Private defaults are filtered by umask. Never chmod to widen permissions.
    fn mkdir(dir: &File, entry: &CStr) -> Result<File, PackageRefusal> {
        if unsafe { libc::mkdirat(dir.as_raw_fd(), entry.as_ptr(), 0o700) } != 0 {
            return Err(refusal("package_output_exists_or_unwritable"));
        }
        // Without an opened fd we cannot safely identify an object for cleanup.
        open(dir, entry, true)
    }
    fn create(dir: &File, entry: &CStr, bytes: &[u8]) -> Result<Identity, PackageRefusal> {
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                entry.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(refusal("package_output_exists_or_unwritable"));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let identity = Identity::of(&file)?;
        if file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            identity.remove(dir, entry, 0);
            return Err(refusal("package_write_failed"));
        }
        Ok(identity)
    }
    fn rename(dir: &File, from: &CStr, parent: &File, to: &CStr) -> Result<(), PackageRefusal> {
        #[cfg(target_os = "macos")]
        let rc = unsafe {
            libc::renameatx_np(
                dir.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dir.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                1u32,
            ) as i32
        };
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let rc = -1;
        if rc != 0 {
            return Err(refusal("package_publish_refused"));
        }
        Ok(())
    }
    struct Stage {
        parent: File,
        name: CString,
        dirs: BTreeMap<String, File>,
        identity: Identity,
        files: Vec<(String, CString, Identity)>,
        created_dirs: Vec<(String, CString, Identity)>,
        published: bool,
    }
    impl Stage {
        fn check(&self) -> Result<(), PackageRefusal> {
            trusted_parent(&self.parent)?;
            if !self.identity.matches(&self.parent, &self.name) {
                return Err(refusal("package_staging_changed"));
            }
            Ok(())
        }
    }
    impl Drop for Stage {
        fn drop(&mut self) {
            if self.published {
                return;
            }
            for (parent, entry, identity) in self.files.iter().rev() {
                identity.remove(&self.dirs[parent], entry, 0);
            }
            for (parent, entry, identity) in self.created_dirs.iter().rev() {
                identity.remove(&self.dirs[parent], entry, libc::AT_REMOVEDIR);
            }
            self.identity
                .remove(&self.parent, &self.name, libc::AT_REMOVEDIR);
        }
    }
    pub fn publish(out: &Path, files: &Files, zip: Option<&[u8]>) -> Result<(), PackageRefusal> {
        let (parent, destination) = parent(out)?;
        trusted_parent(&parent)?;
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                destination.as_ptr(),
                info.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Err(refusal("package_output_exists"));
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            return Err(refusal("package_output_unwritable"));
        }
        let temp = name(&format!(
            ".vettalon-package-{}",
            uuid::Uuid::new_v4().simple()
        ))?;
        let root = mkdir(&parent, &temp)?;
        let identity = Identity::of(&root)?;
        let mut stage = Stage {
            parent,
            name: temp,
            identity,
            dirs: BTreeMap::from([(String::new(), root)]),
            files: vec![],
            created_dirs: vec![],
            published: false,
        };
        if let Some(bytes) = zip {
            let entry = name("package.zip")?;
            stage.check()?;
            let identity = create(&stage.dirs[""], &entry, bytes)?;
            stage.files.push((String::new(), entry.clone(), identity));
            // ZIP bytes are assembled in memory, never read through a staging path.
            // Publish relative to the opened staging fd, not "stage/package.zip".
            stage.check()?;
            if !identity.matches(&stage.dirs[""], &entry) {
                return Err(refusal("package_staging_changed"));
            }
            rename(&stage.dirs[""], &entry, &stage.parent, &destination)?;
        } else {
            let paths = files
                .keys()
                .filter(|p| p.as_str() != "manifest.json")
                .chain(files.keys().filter(|p| p.as_str() == "manifest.json"));
            for path in paths {
                safe_name(path)?;
                let mut parent_path = String::new();
                let parts: Vec<_> = path.split('/').collect();
                for part in &parts[..parts.len() - 1] {
                    let child = if parent_path.is_empty() {
                        (*part).to_owned()
                    } else {
                        format!("{parent_path}/{part}")
                    };
                    if !stage.dirs.contains_key(&child) {
                        let entry = name(part)?;
                        let dir = mkdir(&stage.dirs[&parent_path], &entry)?;
                        let identity = Identity::of(&dir)?;
                        stage
                            .created_dirs
                            .push((parent_path.clone(), entry, identity));
                        stage.dirs.insert(child.clone(), dir);
                    }
                    parent_path = child;
                }
                let entry = name(parts[parts.len() - 1])?;
                let identity = create(&stage.dirs[&parent_path], &entry, &files[path])?;
                stage.files.push((parent_path, entry, identity));
            }
            stage.check()?;
            rename(&stage.parent, &stage.name, &stage.parent, &destination)?;
            // Ownership transferred: cleanup must never touch published files.
            stage.published = true;
        }
        let _ = stage.parent.sync_all();
        Ok(())
    }
    pub(crate) fn read_file(mut file: File, remaining: u64) -> Result<Vec<u8>, PackageRefusal> {
        if file
            .metadata()
            .map_err(|_| refusal("package_unreadable"))?
            .len()
            > remaining
        {
            return Err(refusal("package_too_large"));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(remaining + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refusal("package_unreadable"))?;
        if bytes.len() as u64 > remaining {
            return Err(refusal("package_too_large"));
        }
        Ok(bytes)
    }
    pub(crate) fn read_dir(root: File) -> Result<Files, PackageRefusal> {
        fn walk(
            dir: &File,
            prefix: &str,
            files: &mut Files,
            count: &mut usize,
            remaining: &mut u64,
        ) -> Result<(), PackageRefusal> {
            // fdopendir owns the duplicate; closedir releases it on every path.
            let fd = unsafe { libc::dup(dir.as_raw_fd()) };
            if fd < 0 {
                return Err(refusal("package_unreadable"));
            }
            let stream = unsafe { libc::fdopendir(fd) };
            if stream.is_null() {
                unsafe {
                    libc::close(fd);
                }
                return Err(refusal("package_unreadable"));
            }
            struct Stream(*mut libc::DIR);
            impl Drop for Stream {
                fn drop(&mut self) {
                    unsafe {
                        libc::closedir(self.0);
                    }
                }
            }
            let stream = Stream(stream);
            loop {
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    break;
                }
                let entry = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                if entry.to_bytes() == b"." || entry.to_bytes() == b".." {
                    continue;
                }
                *count += 1;
                if *count > MAX_ENTRIES {
                    return Err(refusal("package_too_large"));
                }
                let leaf = entry.to_str().map_err(|_| refusal("package_path_unsafe"))?;
                let path = if prefix.is_empty() {
                    leaf.into()
                } else {
                    format!("{prefix}/{leaf}")
                };
                safe_name(&path)?;
                let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
                if unsafe {
                    libc::fstatat(
                        dir.as_raw_fd(),
                        entry.as_ptr(),
                        info.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(refusal("package_unreadable"));
                }
                let info = unsafe { info.assume_init() };
                match info.st_mode & libc::S_IFMT {
                    libc::S_IFDIR => {
                        // Empty or unexpected directories are extra package content too.
                        if !matches!(
                            path.as_str(),
                            "receipts"
                                | "receipts/retest"
                                | "receipts/reproduce"
                                | "receipts/fix-check"
                                | "receipts/plans"
                                | "report"
                                | "signatures"
                                | "signatures-pq"
                                | "keys"
                        ) {
                            return Err(refusal("package_extra_directory"));
                        }
                        let before = files.len();
                        walk(&open(dir, entry, true)?, &path, files, count, remaining)?;
                        if files.len() == before {
                            return Err(refusal("package_extra_directory"));
                        }
                    }
                    libc::S_IFREG => {
                        let bytes = read_file(open(dir, entry, false)?, *remaining)?;
                        *remaining -= bytes.len() as u64;
                        if files.insert(path, bytes).is_some() {
                            return Err(refusal("package_duplicate"));
                        }
                    }
                    _ => return Err(refusal("package_path_unsafe")),
                }
            }
            Ok(())
        }
        let mut files = Files::new();
        let mut count = 0;
        let mut remaining = PACKAGE_MAX_BYTES;
        walk(&root, "", &mut files, &mut count, &mut remaining)?;
        Ok(files)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn staging_replacement_is_refused_and_cleanup_preserves_replacements() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().canonicalize().unwrap();
            let parent = File::open(&path).unwrap();
            let entry = name("stage").unwrap();
            let root = mkdir(&parent, &entry).unwrap();
            let identity = Identity::of(&root).unwrap();
            let file_name = name("receipt").unwrap();
            let file_id = create(&root, &file_name, b"original").unwrap();
            let child_name = name("child").unwrap();
            let child = mkdir(&root, &child_name).unwrap();
            let child_id = Identity::of(&child).unwrap();
            let stage = Stage {
                parent,
                name: entry,
                identity,
                dirs: BTreeMap::from([(String::new(), root), ("child".into(), child)]),
                files: vec![(String::new(), file_name, file_id)],
                created_dirs: vec![(String::new(), child_name, child_id)],
                published: false,
            };
            assert!(stage.check().is_ok());
            std::fs::rename(path.join("stage"), path.join("moved")).unwrap();
            std::fs::create_dir(path.join("stage")).unwrap();
            std::fs::rename(path.join("moved/receipt"), path.join("moved/original")).unwrap();
            std::fs::write(path.join("moved/receipt"), b"replacement").unwrap();
            std::fs::rename(path.join("moved/child"), path.join("moved/original-child")).unwrap();
            std::fs::create_dir(path.join("moved/child")).unwrap();
            assert_eq!(stage.check().unwrap_err().token, "package_staging_changed");
            drop(stage);
            assert!(path.join("stage").is_dir());
            assert!(path.join("moved/child").is_dir());
            assert_eq!(
                std::fs::read(path.join("moved/receipt")).unwrap(),
                b"replacement"
            );
        }

        #[test]
        fn creation_respects_restrictive_umask() {
            const CHILD: &str = "VETTALON_TEST_PRIVATE_UMASK";
            if std::env::var_os(CHILD).is_none() {
                // umask is process-global; isolate it from concurrent tests.
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "audit::retest_package::write::io::tests::creation_respects_restrictive_umask"])
                    .env(CHILD, "1")
                    .output().unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stdout)
                );
                return;
            }
            let temp = tempfile::tempdir().unwrap();
            let parent = File::open(temp.path()).unwrap();
            unsafe {
                libc::umask(0o200);
            }
            create(&parent, &name("file").unwrap(), b"private").unwrap();
            let directory = mkdir(&parent, &name("dir").unwrap()).unwrap();
            assert_eq!(directory.metadata().unwrap().mode() & 0o777, 0o500);
            assert_eq!(
                std::fs::metadata(temp.path().join("file")).unwrap().mode() & 0o777,
                0o400
            );
        }

        #[test]
        fn unsafe_parent_is_refused_before_creating_staging() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().canonicalize().unwrap();
            for mode in [0o720, 0o702] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                let result = publish(&path.join("package"), &Files::new(), None);
                assert_eq!(result.unwrap_err().token, "package_parent_unsafe");
                assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o1700 | 0o022))
                .unwrap();
            assert!(trusted_parent(&File::open(&path).unwrap()).is_ok());
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) mod io {
    use super::*;
    pub fn publish(_: &Path, _: &Files, _: Option<&[u8]>) -> Result<(), PackageRefusal> {
        Err(refusal("package_atomic_output_unsupported"))
    }
}

#[cfg(windows)]
pub(crate) mod io {
    use super::*;
    use std::fs;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;

    fn ordinary(meta: &fs::Metadata) -> bool {
        // Reject junctions and every other reparse point as well as symlinks.
        meta.file_attributes() & 0x400 == 0
    }
    pub(crate) fn checked(path: &Path) -> Result<PathBuf, PackageRefusal> {
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|_| refusal("package_path_unsafe"))?
                .join(path)
        };
        let mut cursor = PathBuf::new();
        for component in path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(refusal("package_path_unsafe"));
            }
            cursor.push(component);
            let meta = fs::symlink_metadata(&cursor).map_err(|_| refusal("package_unreadable"))?;
            if !ordinary(&meta) {
                return Err(refusal("package_path_unsafe"));
            }
        }
        Ok(path)
    }
    fn rename(from: &Path, to: &Path) -> Result<(), PackageRefusal> {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        }
        let wide = |p: &Path| {
            p.as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
        };
        let (from, to) = (wide(from), wide(to));
        // Zero flags refuses replacement and cross-volume copy fallback.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } == 0 {
            return Err(refusal("package_publish_refused"));
        }
        Ok(())
    }
    pub fn publish(out: &Path, files: &Files, zip: Option<&[u8]>) -> Result<(), PackageRefusal> {
        let out = crate::remediation::preflight_new_output(out)
            .map_err(|_| refusal("package_output_exists_or_unwritable"))?;
        let out = out.path();
        let parent = out.parent().ok_or_else(|| refusal("package_path_unsafe"))?;
        // Windows retains the path-based fallback: reject reparse-point parents.
        // Unix fd identity guarantees are not provided by this fallback.
        checked(parent)?;
        let temp = parent.join(format!(
            ".vettalon-package-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&temp).map_err(|_| refusal("package_write_failed"))?;
        struct Cleanup {
            files: Vec<PathBuf>,
            dirs: Vec<PathBuf>,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for file in self.files.iter().rev() {
                    let _ = fs::remove_file(file);
                }
                for dir in self.dirs.iter().rev() {
                    let _ = fs::remove_dir(dir);
                }
            }
        }
        let mut cleanup = Cleanup {
            files: vec![],
            dirs: vec![temp.clone()],
        };
        let archive;
        let content = if let Some(bytes) = zip {
            archive = Files::from([("package.zip".into(), bytes.to_vec())]);
            &archive
        } else {
            files
        };
        for path in content
            .keys()
            .filter(|p| p.as_str() != "manifest.json")
            .chain(content.keys().filter(|p| p.as_str() == "manifest.json"))
        {
            safe_name(path)?;
            let mut cursor = temp.clone();
            let parts: Vec<_> = path.split('/').collect();
            for part in &parts[..parts.len() - 1] {
                cursor.push(part);
                if !cleanup.dirs.contains(&cursor) {
                    checked(
                        cursor
                            .parent()
                            .ok_or_else(|| refusal("package_path_unsafe"))?,
                    )?;
                    fs::create_dir(&cursor).map_err(|_| refusal("package_write_failed"))?;
                    cleanup.dirs.push(cursor.clone());
                }
            }
            checked(&cursor)?;
            let file = temp.join(path);
            let mut handle = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&file)
                .map_err(|_| refusal("package_write_failed"))?;
            cleanup.files.push(file);
            handle
                .write_all(&content[path])
                .and_then(|()| handle.sync_all())
                .map_err(|_| refusal("package_write_failed"))?;
        }
        checked(parent)?;
        if zip.is_some() {
            rename(&temp.join("package.zip"), &out)?;
        } else {
            rename(&temp, &out)?;
            cleanup.files.clear();
            cleanup.dirs.clear();
        }
        Ok(())
    }
    pub(crate) fn read_package(path: &Path) -> Result<Files, PackageRefusal> {
        use std::io::Read;
        fn read(path: &Path, cap: u64) -> Result<Vec<u8>, PackageRefusal> {
            checked(path)?;
            let file = fs::File::open(path).map_err(|_| refusal("package_unreadable"))?;
            let meta = file.metadata().map_err(|_| refusal("package_unreadable"))?;
            if !meta.is_file() || !ordinary(&meta) || meta.len() > cap {
                return Err(refusal("package_path_unsafe"));
            }
            let mut bytes = Vec::new();
            file.take(cap + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refusal("package_unreadable"))?;
            if bytes.len() as u64 > cap {
                return Err(refusal("package_too_large"));
            }
            Ok(bytes)
        }
        fn walk(
            root: &Path,
            dir: &Path,
            files: &mut Files,
            count: &mut usize,
            remaining: &mut u64,
        ) -> Result<(), PackageRefusal> {
            checked(dir)?;
            for entry in fs::read_dir(dir).map_err(|_| refusal("package_unreadable"))? {
                let entry = entry.map_err(|_| refusal("package_unreadable"))?;
                *count += 1;
                if *count > MAX_ENTRIES {
                    return Err(refusal("package_too_large"));
                }
                let path = checked(&entry.path())?;
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| refusal("package_path_unsafe"))?
                    .to_str()
                    .ok_or_else(|| refusal("package_path_unsafe"))?
                    .replace('\\', "/");
                safe_name(&relative)?;
                if path.is_dir() {
                    let before = files.len();
                    walk(root, &path, files, count, remaining)?;
                    if files.len() == before {
                        return Err(refusal("package_extra_directory"));
                    }
                } else {
                    let bytes = read(&path, *remaining)?;
                    *remaining -= bytes.len() as u64;
                    files.insert(relative, bytes);
                }
            }
            Ok(())
        }
        let path = checked(path)?;
        if path.is_dir() {
            let mut files = Files::new();
            let mut count = 0;
            let mut remaining = PACKAGE_MAX_BYTES;
            walk(&path, &path, &mut files, &mut count, &mut remaining)?;
            Ok(files)
        } else {
            super::super::verify::read_zip(&read(&path, PACKAGE_MAX_BYTES + 1024 * 1024)?)
        }
    }
}

pub(crate) fn read_pq_key(path: &Path) -> Result<Vec<u8>, PackageRefusal> {
    crate::remediation::read_regular_capped(
        path,
        crate::attest::pq::PUBLIC_KEY_MAX_BYTES,
        "ML-DSA public key",
    )
    .map(String::into_bytes)
    .map_err(|_| refusal("pq_key_unreadable"))
}

pub(crate) fn verify_pq_signatures(
    inputs: &PackageInputs,
    key: &[u8],
) -> Result<PqSignatures, PackageRefusal> {
    use super::SourceKind;
    use crate::attest::pq::{Openssl, Sidecar, parse_mldsa65_pub_pem, pq_verify};
    let bundles: Vec<_> = inputs
        .sources
        .iter()
        .filter(|s| s.kind == SourceKind::Signature)
        .collect();
    if bundles.is_empty()
        || bundles.iter().any(|bundle| {
            !inputs.sources.iter().any(|s| {
                s.kind == SourceKind::PqSignature && s.covers.as_ref() == Some(&bundle.path)
            })
        })
    {
        return Err(refusal("pq_signature_missing"));
    }
    let der = parse_mldsa65_pub_pem(key).map_err(|_| refusal("pq_key_invalid"))?;
    let excluded: Vec<&Path> = inputs
        .tool_exclusions
        .iter()
        .map(PathBuf::as_path)
        .collect();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let stage = tempfile::tempdir().map_err(|_| refusal("signature_staging_failed"))?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| refusal("signature_staging_failed"))?;
                runtime.block_on(async {
                    let tool = Openssl::locate(stage.path(), &excluded)
                        .await
                        .map_err(|_| refusal("pq_signature_invalid"))?;
                    let mut results = PqSignatures::new();
                    for source in inputs
                        .sources
                        .iter()
                        .filter(|s| s.kind == SourceKind::PqSignature)
                    {
                        let bundle = bundles
                            .iter()
                            .find(|b| Some(&b.path) == source.covers.as_ref())
                            .ok_or_else(|| refusal("pq_signature_unmatched"))?;
                        let receipt = inputs
                            .sources
                            .iter()
                            .find(|s| Some(&s.path) == bundle.covers.as_ref())
                            .ok_or_else(|| refusal("pq_signature_unmatched"))?;
                        let sidecar = Sidecar::parse(&source.bytes)
                            .map_err(|_| refusal("pq_signature_invalid"))?;
                        pq_verify(&tool, &der, &sidecar, &bundle.bytes, &receipt.bytes)
                            .await
                            .map_err(|_| refusal("pq_signature_invalid"))?;
                        results.insert(
                            source.path.clone(),
                            super::record::MldsaRecord {
                                verified: true,
                                key_sha256: sha256_hex(&der),
                            },
                        );
                    }
                    Ok(results)
                })
            })
            .join()
            .map_err(|_| refusal("signature_staging_failed"))?
    })
}
