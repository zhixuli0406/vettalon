//! A5: sign Vettalon receipts as in-toto Statements with the user's cosign
//! and verify them offline.
//!
//! A valid signature shows who vouched for a receipt and that its bytes did
//! not change after signing. It does not show that the receipt's conclusion
//! is right. Keys are local; nothing is uploaded to a transparency log.
//!
//! cosign always runs on a private copy of the exact bytes Vettalon parsed,
//! so the signed digest and the extracted predicate describe the same file.

pub mod cosign;
pub mod pq;
pub mod predicate;
pub mod statement;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

pub use predicate::{ExtractedReceipt, ReceiptKind, extract};

use crate::remediation::{
    preflight_new_output, read_regular_capped, write_preflighted_output_pair,
};

use cosign::{Cosign, CosignError};
use statement::{BUNDLE_MAX_BYTES, canonical_bytes, check_bundle, decode_bundle_statement};

/// Largest receipt read.
pub const RECEIPT_MAX_BYTES: u64 = 16 * 1024 * 1024;
const BUNDLE_MAX: u64 = BUNDLE_MAX_BYTES as u64;
const BUNDLE_FILE: &str = "bundle.sigstore.json";
const PREDICATE_FILE: &str = "predicate.json";
const SUBJECT_DIR: &str = "subject";
const PASSWORD_HINT: &str = "set COSIGN_PASSWORD for an encrypted key (cosign cannot prompt)";

/// Why `receipt verify` did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestError {
    /// Input refused or cosign could not run; nothing was checked.
    Refused(String),
    /// cosign or the Statement checks rejected the bundle.
    Failed(String),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(message) | Self::Failed(message) => f.write_str(message),
        }
    }
}

impl From<CosignError> for AttestError {
    fn from(error: CosignError) -> Self {
        match error {
            CosignError::Unavailable(message) => Self::Refused(message),
            CosignError::Rejected(message) => Self::Failed(message),
        }
    }
}

/// A receipt signed and its bundle written.
#[derive(Debug, Clone)]
pub struct Signed {
    pub kind: ReceiptKind,
    pub bundle: PathBuf,
    pub cosign_version: String,
    pub pq: Option<PqSigned>,
}

/// The self-verified optional ML-DSA sidecar.
#[derive(Debug, Clone)]
pub struct PqSigned {
    pub sidecar: PathBuf,
    pub openssl_version: String,
    pub public_key_sha256: String,
}

/// A receipt whose bundle cosign accepted and whose Statement matched.
#[derive(Debug, Clone)]
pub struct Verified {
    pub kind: ReceiptKind,
    pub cosign_version: String,
    pub pq_verified: bool,
}

struct LoadedReceipt {
    file_name: String,
    raw: String,
    extracted: ExtractedReceipt,
}

/// Private temporary directory (removed on drop) holding a copy of the
/// receipt bytes under the receipt's own file name, plus the UTF-8 paths
/// passed to cosign.
struct Staged {
    dir: tempfile::TempDir,
    blob: String,
    bundle: String,
    predicate: String,
}

/// `<receipt>.sigstore.json`.
pub fn default_bundle_path(receipt: &Path) -> PathBuf {
    let mut name = receipt.as_os_str().to_owned();
    name.push(".sigstore.json");
    PathBuf::from(name)
}

/// Sign `receipt` with the local cosign private key file `key`. Before the
/// bundle is written (0600, never over an existing file), its layout is
/// checked and the Statement cosign signed is decoded and compared with the
/// receipt. The signature itself is not checked here; `verify` does that.
pub async fn sign_receipt(
    receipt: &Path,
    key: &Path,
    out: Option<&Path>,
) -> Result<Signed, String> {
    sign_receipt_hybrid(receipt, key, out, None).await
}

/// Sign both layers when `pq` supplies a local private key and optional sidecar path.
pub async fn sign_receipt_hybrid(
    receipt: &Path,
    key: &Path,
    out: Option<&Path>,
    pq: Option<(&Path, Option<&Path>)>,
) -> Result<Signed, String> {
    sign_receipt_with_tools(receipt, key, out, pq, None).await
}

// Explicit binaries keep subprocess tests independent of the process environment.
async fn sign_receipt_with_tools(
    receipt: &Path,
    key: &Path,
    out: Option<&Path>,
    pq: Option<(&Path, Option<&Path>)>,
    programs: Option<(&str, &str)>,
) -> Result<Signed, String> {
    // Until native path and descriptor-bound cleanup acceptance is available,
    // do not create hybrid outputs on platforms with path-only rollback.
    #[cfg(not(unix))]
    if pq.is_some() {
        return Err("ML-DSA signing requires Unix; native Windows key paths and identity-checked cleanup are not yet supported".into());
    }
    let key = key_argument(key, "private key")?;
    let loaded = load_receipt(receipt)?;
    let pq_key = pq
        .map(|(key, _)| key_argument(key, "ML-DSA private key"))
        .transpose()?;
    let requested = match out {
        Some(path) => path.to_path_buf(),
        None => default_bundle_path(receipt),
    };
    let out = preflight_new_output(&requested)?;
    let pq_out = pq
        .map(|(_, path)| {
            preflight_new_output(
                &path
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| pq::default_sidecar_path(receipt)),
            )
        })
        .transpose()?;
    if pq_out
        .as_ref()
        .is_some_and(|pq_out| pq_out.path() == out.path())
    {
        return Err("bundle and ML-DSA sidecar must be different paths".into());
    }
    let staged = stage(&loaded)?;
    let work = staged.dir.path();
    let pq_signer = if let Some(key) = &pq_key {
        let tool = locate_openssl(programs, work, receipt, &[])
            .await
            .map_err(|e| e.to_string())?;
        let der = tool
            .derive_public_key(key, work)
            .await
            .map_err(|e| e.to_string())?;
        Some((tool, der))
    } else {
        None
    };
    let cosign = locate_cosign(programs, work, receipt, &[])
        .await
        .map_err(|e| e.to_string())?;
    let kind = loaded.extracted.kind;
    let predicate = &loaded.extracted.predicate;
    write_private(Path::new(&staged.predicate), &canonical_bytes(predicate)?)?;
    let args = cosign::sign_args(
        &key,
        &staged.predicate,
        kind.predicate_type(),
        &staged.bundle,
        &staged.blob,
    );
    cosign.run(&args, work).await.map_err(sign_failure)?;
    let bundle = read_regular_capped(Path::new(&staged.bundle), BUNDLE_MAX, "cosign bundle")?;
    let receipt_bytes = loaded.raw.as_bytes();
    // Content check only: the Statement cosign wrote must describe these
    // receipt bytes. No signature is verified at sign time.
    check_bundle(bundle.as_bytes(), receipt_bytes, kind, predicate).map_err(|e| {
        format!("the Statement in the bundle cosign wrote does not match the receipt: {e}")
    })?;
    let bundle_path = out.path().to_path_buf();
    let pq = match (pq_signer, pq_key, pq_out) {
        (Some((tool, der)), Some(key), Some(pq_out)) => {
            let sidecar = pq::pq_sign(&tool, &key, &der, bundle.as_bytes(), receipt_bytes)
                .await
                .map_err(|e| e.to_string())?;
            let signed = PqSigned {
                sidecar: pq_out.path().to_path_buf(),
                openssl_version: tool.version,
                public_key_sha256: sidecar.public_key_sha256.clone(),
            };
            write_preflighted_output_pair(
                out,
                bundle.as_bytes(),
                pq_out,
                &sidecar.canonical_bytes()?,
            )?;
            Some(signed)
        }
        _ => {
            out.write_text(&bundle)?;
            None
        }
    };
    Ok(Signed {
        kind,
        bundle: bundle_path,
        cosign_version: cosign.version,
        pq,
    })
}

/// cosign's own message; the `COSIGN_PASSWORD` hint only when cosign's
/// stderr points at a key decryption or password problem.
fn sign_failure(error: CosignError) -> String {
    match error {
        CosignError::Rejected(message) if mentions_password_problem(&message) => {
            format!("{message}\nhint: {PASSWORD_HINT}")
        }
        CosignError::Rejected(message) | CosignError::Unavailable(message) => message,
    }
}

fn mentions_password_problem(message: &str) -> bool {
    // cosign's own wording for a key it cannot decrypt or a password it cannot
    // read; a bare "password" is not enough (a path such as ~/passwords/
    // contains it).
    const MARKERS: [&str; 6] = [
        "decrypt:",
        "decryption failed",
        "error reading password",
        "reading password",
        "incorrect passphrase",
        "incorrect password",
    ];
    let lower = message.to_ascii_lowercase();
    MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Verify `receipt` against `bundle` with the local cosign public key file
/// `key`, offline, then check the signed Statement against the receipt.
pub async fn verify_receipt(
    receipt: &Path,
    key: &Path,
    bundle: &Path,
) -> Result<Verified, AttestError> {
    verify_receipt_hybrid(receipt, key, bundle, None).await
}

/// Require both cosign and ML-DSA when the caller supplies a public key and sidecar.
/// There is deliberately no sidecar auto-discovery.
pub async fn verify_receipt_hybrid(
    receipt: &Path,
    key: &Path,
    bundle: &Path,
    pq: Option<(&Path, &Path)>,
) -> Result<Verified, AttestError> {
    verify_receipt_with_tools(receipt, key, bundle, pq, None).await
}

async fn verify_receipt_with_tools(
    receipt: &Path,
    key: &Path,
    bundle: &Path,
    pq: Option<(&Path, &Path)>,
    programs: Option<(&str, &str)>,
) -> Result<Verified, AttestError> {
    verify_receipt_with_context(receipt, key, bundle, pq, programs, &[]).await
}

/// Package callers retain the original input directories after staging bytes.
pub(crate) async fn verify_receipt_excluding(
    receipt: &Path,
    key: &Path,
    bundle: &Path,
    excluded: &[&Path],
) -> Result<Verified, AttestError> {
    verify_receipt_with_context(receipt, key, bundle, None, None, excluded).await
}

async fn verify_receipt_with_context(
    receipt: &Path,
    key: &Path,
    bundle: &Path,
    pq: Option<(&Path, &Path)>,
    programs: Option<(&str, &str)>,
    excluded: &[&Path],
) -> Result<Verified, AttestError> {
    let loaded = load_receipt(receipt).map_err(AttestError::Refused)?;
    let bundle = read_regular_capped(bundle, BUNDLE_MAX, "bundle").map_err(AttestError::Refused)?;
    let key = key_argument(key, "public key").map_err(AttestError::Refused)?;
    // A malformed bundle is refused (exit 2) before cosign runs, not reported
    // as a failed verification.
    decode_bundle_statement(bundle.as_bytes())
        .map_err(|e| AttestError::Refused(format!("bundle refused: {e}")))?;
    let pq_inputs = pq
        .map(|(public, sidecar)| {
            let raw = read_regular_capped(sidecar, pq::SIDECAR_MAX_BYTES as u64, "ML-DSA sidecar")?;
            let sidecar = pq::Sidecar::parse(raw.as_bytes())?;
            let pem = read_regular_capped(public, pq::PUBLIC_KEY_MAX_BYTES, "ML-DSA public key")?;
            let der = pq::parse_mldsa65_pub_pem(pem.as_bytes())?;
            Ok::<_, String>((der, sidecar))
        })
        .transpose()
        .map_err(AttestError::Refused)?;
    let staged = stage(&loaded).map_err(AttestError::Refused)?;
    let work = staged.dir.path();
    let cosign = locate_cosign(programs, work, receipt, excluded).await?;
    let openssl = if pq_inputs.is_some() {
        Some(locate_openssl(programs, work, receipt, excluded).await?)
    } else {
        None
    };
    write_private(Path::new(&staged.bundle), bundle.as_bytes()).map_err(AttestError::Refused)?;
    let kind = loaded.extracted.kind;
    let args = cosign::verify_args(&key, &staged.bundle, kind.predicate_type(), &staged.blob);
    cosign.run(&args, work).await?;
    let receipt_bytes = loaded.raw.as_bytes();
    let predicate = &loaded.extracted.predicate;
    check_bundle(bundle.as_bytes(), receipt_bytes, kind, predicate).map_err(AttestError::Failed)?;
    if let (Some(tool), Some((der, sidecar))) = (openssl, pq_inputs) {
        pq::pq_verify(&tool, &der, &sidecar, bundle.as_bytes(), receipt_bytes).await?;
    }
    Ok(Verified {
        kind,
        cosign_version: cosign.version,
        pq_verified: pq.is_some(),
    })
}

async fn locate_cosign(
    programs: Option<(&str, &str)>,
    work: &Path,
    receipt: &Path,
    additional: &[&Path],
) -> Result<Cosign, CosignError> {
    let dirs = receipt_tool_exclusions(receipt).map_err(CosignError::Unavailable)?;
    let excluded: Vec<&Path> = dirs
        .iter()
        .map(PathBuf::as_path)
        .chain(additional.iter().copied())
        .collect();
    match programs {
        Some((cosign, _)) => Cosign::probe(cosign, work, &excluded).await,
        None => Cosign::locate(work, &excluded).await,
    }
}

async fn locate_openssl(
    programs: Option<(&str, &str)>,
    work: &Path,
    receipt: &Path,
    additional: &[&Path],
) -> Result<pq::Openssl, AttestError> {
    let dirs = receipt_tool_exclusions(receipt).map_err(AttestError::Refused)?;
    let excluded: Vec<&Path> = dirs
        .iter()
        .map(PathBuf::as_path)
        .chain(additional.iter().copied())
        .collect();
    match programs {
        Some((_, openssl)) => pq::Openssl::probe(openssl, work, &excluded).await,
        None => pq::Openssl::locate(work, &excluded).await,
    }
}

// Exclude both the named directory and the target directory of a symlinked receipt.
pub(crate) fn receipt_tool_exclusions(receipt: &Path) -> Result<Vec<PathBuf>, String> {
    let absolute = std::path::absolute(receipt).map_err(|e| e.to_string())?;
    let canonical = receipt.canonicalize().map_err(|e| e.to_string())?;
    [absolute, canonical]
        .iter()
        .map(|path| {
            path.parent()
                .ok_or_else(|| "receipt has no parent directory".to_owned())?
                .canonicalize()
                .map_err(|e| e.to_string())
        })
        .collect()
}

fn load_receipt(path: &Path) -> Result<LoadedReceipt, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("the receipt path must end in a UTF-8 file name")?
        .to_string();
    let raw = read_regular_capped(path, RECEIPT_MAX_BYTES, "receipt")?;
    let extracted = extract(&raw).map_err(|e| format!("receipt refused: {e}"))?;
    Ok(LoadedReceipt {
        file_name,
        raw,
        extracted,
    })
}

fn stage(loaded: &LoadedReceipt) -> Result<Staged, String> {
    let dir = tempfile::Builder::new()
        .prefix("vettalon-attest-")
        .tempdir()
        .map_err(|e| format!("cannot create a private temporary directory: {e}"))?;
    let subject = dir.path().join(SUBJECT_DIR);
    std::fs::create_dir(&subject)
        .map_err(|e| format!("cannot create {}: {e}", subject.display()))?;
    let blob = subject.join(&loaded.file_name);
    write_private(&blob, loaded.raw.as_bytes())?;
    let blob = utf8(&blob, "receipt copy")?.to_string();
    let bundle = utf8(&dir.path().join(BUNDLE_FILE), "bundle")?.to_string();
    let predicate = utf8(&dir.path().join(PREDICATE_FILE), "predicate")?.to_string();
    Ok(Staged {
        dir,
        blob,
        bundle,
        predicate,
    })
}

/// Create a new 0600 file; never follows or replaces an existing path.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn utf8<'a>(path: &'a Path, label: &str) -> Result<&'a str, String> {
    path.to_str()
        .ok_or_else(|| format!("{label} path must be valid UTF-8"))
}

/// cosign key reference schemes that make it fetch a key, ask a KMS or
/// hardware token, or run a `sigstore-kms-*` plugin from PATH.
const KEY_SCHEMES: [&str; 7] = [
    "pkcs11:",
    "env:",
    "k8s:",
    "hashivault:",
    "awskms:",
    "gcpkms:",
    "azurekms:",
];

/// The key argument handed to cosign: the absolute, symlink-free path of an
/// existing regular local file. Keys are local only, so remote, KMS,
/// hardware-token and plugin references (anything with `://`, a cosign
/// scheme prefix, or another `scheme:` prefix that is not an existing path)
/// are refused before cosign runs. The key is opened (non-blocking, never
/// following a symlink) only to `fstat` it; its contents are never read.
fn key_argument(key: &Path, label: &str) -> Result<String, String> {
    let text = utf8(key, label)?;
    if text.is_empty() {
        return Err(format!("--key ({label}) is empty"));
    }
    let lower = text.to_ascii_lowercase();
    let known_scheme = KEY_SCHEMES.iter().any(|scheme| lower.starts_with(scheme));
    if text.contains("://") || known_scheme || (has_scheme_prefix(text) && !path_exists(key)) {
        return Err(format!(
            "--key ({label}) must be a local key file; remote, KMS, token and plugin key \
             references are refused"
        ));
    }
    let resolved = std::fs::canonicalize(key)
        .map_err(|e| format!("--key ({label}) {text} cannot be resolved: {e}"))?;
    require_regular_file(&resolved)
        .map_err(|e| format!("--key ({label}) {text} must be a regular file: {e}"))?;
    utf8(&resolved, label).map(str::to_string)
}

/// `scheme:` at the start, RFC 3986 style. A one-letter prefix is a Windows
/// drive (`C:`), not a scheme.
fn has_scheme_prefix(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut bytes = scheme.bytes();
    scheme.len() > 1
        && bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn path_exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// `path` (already canonical) is a regular file, both by `lstat` and by
/// `fstat` on a handle opened without following a link and without blocking
/// on a FIFO.
fn require_regular_file(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("not a regular file".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() {
        return Err("not a regular file".into());
    }
    Ok(())
}
