//! Optional ML-DSA-65 layer over the exact DSSE PAE signed by cosign.
//! Cryptography belongs to the user's OpenSSL; private keys are never read here.
//!
//! OpenSSL and cosign must resolve to canonical absolute executables outside
//! cwd, the receipt directory and their repositories. On Unix, each executable
//! and ancestor must be owned by root or the current uid. Group/world write
//! access is refused except on root-owned sticky ancestor directories
//! (never regular files). Device/inode and permissions
//! are rechecked immediately before every spawn; unsupported platforms refuse.
//! OpenSSL gets a cleared environment, fixed PATH/locales and OPENSSL_CONF=""
//! to disable system configuration and provider injection. HOME is unnecessary;
//! only derive/sign receive VETTALON_PQ_KEY_PASSWORD. The default provider supplies
//! ML-DSA-65 on OpenSSL 3.5+. Trusted installations and their libraries remain
//! part of the trust boundary; this is not descriptor-bound execution.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::cosign::printable;
use super::statement::{decode_base64_strict, decode_bundle_payload, dsse_pae, encode_base64_std};
use super::{AttestError, utf8, write_private};
use crate::audit::schema::sha256_hex;
use crate::audit::{
    AttestationEnv, SubprocessLimits, TrustedExecutable, run_attestation_subprocess,
};
use serde::{Deserialize, Serialize};

pub const OPENSSL_TIMEOUT: Duration = Duration::from_secs(60);
pub const SIDECAR_MAX_BYTES: usize = 16 * 1024;
pub const PUBLIC_KEY_MAX_BYTES: u64 = 8 * 1024;
pub const SIGNATURE_BYTES: usize = 3309;
const OUTPUT_MAX_BYTES: usize = 256 * 1024;
const SPKI_BYTES: usize = 1974;
const SPKI_PREFIX: &[u8] = &[
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];
const MISSING: &str = "install OpenSSL 3.5+ or set VETTALON_OPENSSL (Homebrew: /opt/homebrew/opt/openssl@3/bin/openssl)";

pub fn default_sidecar_path(receipt: &Path) -> PathBuf {
    let mut name = receipt.as_os_str().to_owned();
    name.push(".mldsa.json");
    PathBuf::from(name)
}

pub fn require_supported_version(output: &str) -> Result<String, String> {
    let mut tokens = output.lines().next().unwrap_or("").split_whitespace();
    if tokens.next() != Some("OpenSSL") {
        return Err("OpenSSL 3.5 <= version < 5 is required; LibreSSL is not supported".into());
    }
    let token = tokens.next().ok_or("cannot read the OpenSSL version")?;
    let mut parts = token.split('.');
    let number = |s: &str| -> Option<u32> {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let major = parts.next().and_then(number);
    let minor = parts.next().and_then(number);
    let patch = parts.next().unwrap_or("");
    let digits = patch.bytes().take_while(u8::is_ascii_digit).count();
    let valid_patch = digits > 0 && patch[digits..].bytes().all(|b| b.is_ascii_alphabetic());
    let supported = matches!((major, minor), (Some(3), Some(5..)) | (Some(4), Some(_)));
    let version = format!("OpenSSL {token}");
    if !supported || !valid_patch || parts.next().is_some() || !valid_version_label(&version) {
        return Err(format!(
            "OpenSSL 3.5 <= version < 5 is required; found {}",
            printable(token, 64)
        ));
    }
    Ok(version)
}

fn valid_version_label(text: &str) -> bool {
    !text.is_empty() && text.len() <= 64 && text.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn has_mldsa65(output: &str) -> bool {
    output
        .split(|c: char| c.is_ascii_whitespace() || matches!(c, '{' | '}' | ','))
        .any(|token| token == "ML-DSA-65")
}

fn resolve_program(override_path: Option<&std::ffi::OsStr>) -> Result<String, String> {
    let name = match override_path {
        Some(path) => {
            if !Path::new(path).is_absolute() {
                return Err("VETTALON_OPENSSL must be an absolute executable path".into());
            }
            path.to_str()
                .ok_or("VETTALON_OPENSSL must be valid UTF-8")?
        }
        None => return resolve_on_path(std::env::var_os("PATH").as_deref()),
    };
    crate::util::which_cli(name).ok_or_else(|| MISSING.into())
}

fn resolve_on_path(path: Option<&std::ffi::OsStr>) -> Result<String, String> {
    // which_cli's bare-name branch also guesses common installation locations.
    // Use only absolute PATH entries, passing each candidate to its absolute branch.
    let program = if cfg!(windows) {
        "openssl.exe"
    } else {
        "openssl"
    };
    path.and_then(|path| {
        std::env::split_paths(path)
            .filter(|dir| dir.is_absolute())
            .find_map(|dir| dir.join(program).to_str().and_then(crate::util::which_cli))
    })
    .ok_or_else(|| MISSING.into())
}

/// Probed once per operation, inside the private staging directory.
#[derive(Debug, Clone)]
pub struct Openssl {
    program: TrustedExecutable,
    pub version: String,
}

impl Openssl {
    pub async fn locate(workdir: &Path, excluded: &[&Path]) -> Result<Self, AttestError> {
        let program = resolve_program(std::env::var_os("VETTALON_OPENSSL").as_deref())
            .map_err(AttestError::Refused)?;
        Self::probe(&program, workdir, excluded).await
    }

    pub async fn probe(
        program: &str,
        workdir: &Path,
        excluded: &[&Path],
    ) -> Result<Self, AttestError> {
        let mut tool = Self {
            program: TrustedExecutable::resolve(program, excluded).map_err(AttestError::Refused)?,
            version: String::new(),
        };
        let version = tool
            .run(&["version"], workdir, OUTPUT_MAX_BYTES, false)
            .await?;
        tool.version = require_supported_version(&String::from_utf8_lossy(&version))
            .map_err(AttestError::Refused)?;
        let caps = tool
            .run(
                &["list", "-signature-algorithms"],
                workdir,
                OUTPUT_MAX_BYTES,
                false,
            )
            .await?;
        if !has_mldsa65(&String::from_utf8_lossy(&caps)) {
            return Err(AttestError::Refused(
                "OpenSSL does not provide ML-DSA-65".into(),
            ));
        }
        Ok(tool)
    }

    async fn run(
        &self,
        args: &[&str],
        work: &Path,
        cap: usize,
        verify: bool,
    ) -> Result<Vec<u8>, AttestError> {
        let limits = SubprocessLimits {
            timeout: OPENSSL_TIMEOUT,
            max_output_bytes: cap,
        };
        let private_key = args.first() == Some(&"pkey")
            || (args.first() == Some(&"pkeyutl") && args.get(1) == Some(&"-sign"));
        let out = run_attestation_subprocess(
            &self.program,
            args,
            work,
            &limits,
            AttestationEnv::Openssl { private_key },
        )
        .await;
        // Do not print argv or stdout: derive returns key material as binary.
        let problem = if out.spawn_error.is_some() {
            Some("could not start")
        } else if out.timed_out {
            Some("did not finish within 60 s")
        } else if out.cleanup_error.is_some() {
            Some("process cleanup failed")
        } else if out.stdout_truncated {
            Some("printed too much output")
        } else {
            None
        };
        if let Some(problem) = problem {
            return Err(AttestError::Refused(format!(
                "OpenSSL {} {problem}",
                args[0]
            )));
        }
        if verify {
            let text = String::from_utf8_lossy(&out.stdout);
            if out.exit_code == Some(0) && text.trim() == "Signature Verified Successfully" {
                return Ok(out.stdout);
            }
            if out.exit_code == Some(1) && text.contains("Signature Verification Failure") {
                return Err(AttestError::Failed(
                    "ML-DSA-65 signature verification failed".into(),
                ));
            }
        } else if out.exit_code == Some(0) {
            return Ok(out.stdout);
        }
        Err(AttestError::Refused(format!(
            "OpenSSL {} failed or returned unexpected output (exit {:?}): {}",
            args[0],
            out.exit_code,
            printable(out.stderr_tail.trim(), 2000)
        )))
    }

    /// Derive a public SPKI from a local PKCS#8 PEM private key. This check
    /// must finish before cosign is invoked, since rawin also accepts Ed25519.
    pub async fn derive_public_key(&self, key: &str, work: &Path) -> Result<Vec<u8>, AttestError> {
        let der = self
            .run(&derive_args(key, passin()), work, 4096, false)
            .await?;
        check_public_der(&der).map_err(AttestError::Refused)?;
        Ok(der)
    }
}

fn passin_for(present: bool) -> &'static str {
    if present {
        "env:VETTALON_PQ_KEY_PASSWORD"
    } else {
        "pass:"
    }
}

fn passin() -> &'static str {
    passin_for(std::env::var_os("VETTALON_PQ_KEY_PASSWORD").is_some())
}

pub fn derive_args<'a>(key: &'a str, password_source: &'a str) -> [&'a str; 10] {
    [
        "pkey",
        "-inform",
        "PEM",
        "-in",
        key,
        "-passin",
        password_source,
        "-pubout",
        "-outform",
        "DER",
    ]
}

pub fn sign_args<'a>(
    key: &'a str,
    password_source: &'a str,
    pae: &'a str,
    sig: &'a str,
) -> [&'a str; 13] {
    [
        "pkeyutl",
        "-sign",
        "-inkey",
        key,
        "-keyform",
        "PEM",
        "-passin",
        password_source,
        "-rawin",
        "-in",
        pae,
        "-out",
        sig,
    ]
}

pub fn verify_args<'a>(pub_der: &'a str, pae: &'a str, sig: &'a str) -> [&'a str; 12] {
    [
        "pkeyutl", "-verify", "-pubin", "-inkey", pub_der, "-keyform", "DER", "-rawin", "-in", pae,
        "-sigfile", sig,
    ]
}

pub fn check_public_der(der: &[u8]) -> Result<(), String> {
    if der.len() != SPKI_BYTES || !der.starts_with(SPKI_PREFIX) {
        return Err(
            "public key must be an ML-DSA-65 SPKI (1974-byte DER with the ML-DSA-65 OID)".into(),
        );
    }
    Ok(())
}

/// Strict PEM: LF or CRLF throughout, one block, no extra text or blank lines.
pub fn parse_mldsa65_pub_pem(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() > PUBLIC_KEY_MAX_BYTES as usize || !bytes.is_ascii() {
        return Err("ML-DSA public PEM must be ASCII and at most 8 KiB".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid public PEM")?;
    let normalized;
    let text = if text.contains('\r') {
        normalized = text.replace("\r\n", "\n");
        if normalized.contains('\r') || text.replace("\r\n", "").contains('\n') {
            return Err("public PEM has mixed or invalid line endings".into());
        }
        normalized.as_str()
    } else {
        text
    };
    let body = text
        .strip_suffix('\n')
        .unwrap_or(text)
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|s| s.strip_suffix("\n-----END PUBLIC KEY-----"))
        .ok_or("expected exactly one PUBLIC KEY PEM block")?;
    if body.lines().any(str::is_empty) || body.is_empty() {
        return Err("empty public PEM body or line".into());
    }
    let joined = body.replace('\n', "");
    let der = decode_base64_strict(&joined).ok_or("public PEM is not strict standard base64")?;
    check_public_der(&der)?;
    Ok(der)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sidecar {
    pub algorithm: String,
    pub message: String,
    pub openssl_version: String,
    pub public_key_sha256: String,
    pub receipt_sha256: String,
    pub schema: String,
    pub signature: String,
    pub statement_sha256: String,
}

impl Sidecar {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "sidecar must be UTF-8")?;
        let value: Self =
            vettalon_contract::strict_json::parse_strict_with_limit(text, SIDECAR_MAX_BYTES)
                .map_err(|e| format!("ML-DSA sidecar refused: {e}"))?;
        value.validate()?;
        if value.canonical_bytes()? != bytes {
            return Err(
                "ML-DSA sidecar must be canonical JSON (sorted keys, pretty, trailing newline)"
                    .into(),
            );
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        if self.algorithm != "ML-DSA-65"
            || self.message != "dsse-pae-v1"
            || self.schema != "vettalon.receipt-mldsa/1"
        {
            return Err("unsupported ML-DSA sidecar schema, algorithm or message".into());
        }
        for hash in [
            &self.public_key_sha256,
            &self.receipt_sha256,
            &self.statement_sha256,
        ] {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("ML-DSA sidecar hashes must be 64 lowercase hex characters".into());
            }
        }
        if !valid_version_label(&self.openssl_version) {
            return Err("invalid sidecar openssl_version".into());
        }
        self.signature_bytes()?;
        Ok(())
    }

    pub fn signature_bytes(&self) -> Result<Vec<u8>, String> {
        decode_base64_strict(&self.signature)
            .filter(|sig| sig.len() == SIGNATURE_BYTES)
            .ok_or_else(|| {
                "ML-DSA-65 signature must be strict base64 encoding exactly 3309 bytes".into()
            })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        // Sorting through canonical_json also works when serde_json preserves insertion order.
        let sorted: serde_json::Value =
            serde_json::from_slice(&super::statement::canonical_bytes(&value)?)
                .map_err(|e| e.to_string())?;
        let mut bytes = serde_json::to_vec_pretty(&sorted).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if bytes.len() > SIDECAR_MAX_BYTES {
            return Err("ML-DSA sidecar exceeds 16 KiB".into());
        }
        Ok(bytes)
    }

    pub fn check_binding(
        &self,
        der: &[u8],
        payload: &[u8],
        receipt: &[u8],
    ) -> Result<(), AttestError> {
        if self.public_key_sha256 != sha256_hex(der) {
            return Err(AttestError::Failed(
                "ML-DSA sidecar public key sha256 mismatch".into(),
            ));
        }
        self.check_content_binding(payload, receipt)
    }

    /// Match content without making a cryptographic verification claim.
    pub fn check_content_binding(&self, payload: &[u8], receipt: &[u8]) -> Result<(), AttestError> {
        for (label, expected, actual) in [
            ("receipt", &self.receipt_sha256, sha256_hex(receipt)),
            ("statement", &self.statement_sha256, sha256_hex(payload)),
        ] {
            if expected != &actual {
                return Err(AttestError::Failed(format!(
                    "ML-DSA sidecar {label} sha256 mismatch"
                )));
            }
        }
        Ok(())
    }
}

fn private_workdir() -> Result<tempfile::TempDir, AttestError> {
    tempfile::Builder::new()
        .prefix("vettalon-pq-")
        .tempdir()
        .map_err(|e| AttestError::Refused(format!("cannot create private ML-DSA directory: {e}")))
}

fn read_signature(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("cannot read ML-DSA signature: {e}"))?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() != SIGNATURE_BYTES as u64 {
        return Err("ML-DSA-65 signature must be a regular file of exactly 3309 bytes".into());
    }
    let mut bytes = Vec::new();
    file.take(SIGNATURE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() != SIGNATURE_BYTES {
        return Err("ML-DSA signature length changed".into());
    }
    Ok(bytes)
}

/// Sign and self-verify using a public key already derived before cosign ran.
pub async fn pq_sign(
    tool: &Openssl,
    key: &str,
    der: &[u8],
    bundle: &[u8],
    receipt: &[u8],
) -> Result<Sidecar, AttestError> {
    check_public_der(der).map_err(AttestError::Refused)?;
    let payload = decode_bundle_payload(bundle).map_err(AttestError::Refused)?;
    let dir = private_workdir()?;
    let pae = dir.path().join("pae.bin");
    let sig = dir.path().join("signature.bin");
    write_private(&pae, &dsse_pae(&payload)).map_err(AttestError::Refused)?;
    let args = sign_args(
        key,
        passin(),
        utf8(&pae, "PAE").map_err(AttestError::Refused)?,
        utf8(&sig, "signature").map_err(AttestError::Refused)?,
    );
    tool.run(&args, dir.path(), OUTPUT_MAX_BYTES, false).await?;
    let signature = read_signature(&sig).map_err(AttestError::Refused)?;
    let sidecar = Sidecar {
        algorithm: "ML-DSA-65".into(),
        message: "dsse-pae-v1".into(),
        schema: "vettalon.receipt-mldsa/1".into(),
        openssl_version: tool.version.clone(),
        public_key_sha256: sha256_hex(der),
        receipt_sha256: sha256_hex(receipt),
        statement_sha256: sha256_hex(&payload),
        signature: encode_base64_std(&signature),
    };
    pq_verify(tool, der, &sidecar, bundle, receipt)
        .await
        .map_err(|e| AttestError::Refused(format!("ML-DSA self-verification failed: {e}")))?;
    Ok(sidecar)
}

/// Verify only validated DER, signature and original PAE in a private directory.
/// Callers must also verify cosign; this function checks only the ML-DSA layer.
pub async fn pq_verify(
    tool: &Openssl,
    der: &[u8],
    sidecar: &Sidecar,
    bundle: &[u8],
    receipt: &[u8],
) -> Result<(), AttestError> {
    check_public_der(der).map_err(AttestError::Refused)?;
    sidecar.validate().map_err(AttestError::Refused)?;
    let payload = decode_bundle_payload(bundle).map_err(AttestError::Refused)?;
    sidecar.check_binding(der, &payload, receipt)?;
    let dir = private_workdir()?;
    let public = dir.path().join("public.der");
    let pae = dir.path().join("pae.bin");
    let sig = dir.path().join("signature.bin");
    for (path, bytes) in [
        (&public, der.to_vec()),
        (&pae, dsse_pae(&payload)),
        (
            &sig,
            sidecar.signature_bytes().map_err(AttestError::Refused)?,
        ),
    ] {
        write_private(path, &bytes).map_err(AttestError::Refused)?;
    }
    let args = verify_args(
        utf8(&public, "public key").map_err(AttestError::Refused)?,
        utf8(&pae, "PAE").map_err(AttestError::Refused)?,
        utf8(&sig, "signature").map_err(AttestError::Refused)?,
    );
    tool.run(&args, dir.path(), OUTPUT_MAX_BYTES, true).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
