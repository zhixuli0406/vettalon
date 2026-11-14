//! Experimental CycloneDX 1.6/1.7 CBOM reader for `vettalon cbom-check`.
//!
//! A CBOM is untrusted input. Only the fields `cbom-check` needs are read;
//! unknown fields are ignored (real CBOMs carry many), but the document is
//! validated (`bomFormat`, `specVersion`) and bounded while it is parsed (file
//! size, component count, occurrences per component and in total, string
//! length; see `cbom_raw`). A malformed leaf (wrong JSON type) is dropped to
//! "missing" rather than failing the whole file, and a bad occurrence `line`
//! or `location` becomes an `Err(reason)` that the caller turns into an
//! `unknown` row; nothing here panics on hostile input.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::schema::sha256_hex;

#[path = "cbom_raw.rs"]
mod raw;
use raw::{Leaf, Lenient, RawBom, RawOccurrence};

/// Largest CBOM file read (bytes).
pub const MAX_CBOM_BYTES: u64 = 32 * 1024 * 1024;
/// Most components accepted.
pub const MAX_COMPONENTS: usize = 100_000;
/// Most occurrences accepted for one component.
pub const MAX_OCCURRENCES: usize = 10_000;
/// Most occurrences accepted across all components.
pub const MAX_TOTAL_OCCURRENCES: usize = 200_000;
/// CBOM strings are clipped to this many characters (plus `…`).
pub const MAX_STRING_CHARS: usize = 256;
/// Longest occurrence `location` mapped (bytes); longer is `location_too_long`.
pub const MAX_LOCATION_BYTES: usize = 4096;
/// Most path components in a mapped `location`.
pub const MAX_LOCATION_COMPONENTS: usize = 64;
/// Largest source file an occurrence may point at (bytes).
pub const MAX_SOURCE_FILE_BYTES: u64 = super::py_usage::MAX_FILE_BYTES;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CbomError {
    #[error("CBOM is larger than 32 MiB")]
    TooLarge,
    #[error("cannot read the CBOM: {0}")]
    Io(String),
    #[error("CBOM is not valid JSON of the expected shape: {0}")]
    Json(String),
    #[error("bomFormat must be \"CycloneDX\"")]
    BadFormat,
    #[error("unsupported specVersion {0:?}; only 1.6 and 1.7 are accepted")]
    UnsupportedVersion(String),
    #[error("CBOM has more than 100000 components")]
    TooManyComponents,
    #[error("a component has more than 10000 occurrences")]
    TooManyOccurrences,
    #[error("CBOM has more than 200000 occurrences in total")]
    TooManyTotalOccurrences,
}

/// One `evidence.occurrences[]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    /// `Err(reason)` when `location` is missing, not a string or too long.
    pub location: Result<String, &'static str>,
    /// `Err(reason)` when `line` is missing, negative or not an integer.
    pub line: Result<u32, &'static str>,
    pub offset: Option<u64>,
    pub additional_context: Option<String>,
    /// CBOM field names of this occurrence whose value was clipped.
    pub clipped: Vec<&'static str>,
}

/// One cryptographic-asset component (only the fields cbom-check uses).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Component {
    pub bom_ref: Option<String>,
    pub name: Option<String>,
    pub asset_type: Option<String>,
    pub primitive: Option<String>,
    pub parameter_set_identifier: Option<String>,
    pub curve: Option<String>,
    pub mode: Option<String>,
    pub crypto_functions: Vec<String>,
    pub material_type: Option<String>,
    pub material_size: Option<u64>,
    pub occurrences: Vec<Occurrence>,
    /// CBOM field names of this component whose value was clipped.
    pub clipped: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cbom {
    /// SHA-256 of the raw file bytes.
    pub sha256: String,
    pub spec_version: String,
    /// Producing tool from `metadata.tools`, if present.
    pub tool: Option<String>,
    /// Components that carry `cryptoProperties`.
    pub components: Vec<Component>,
    /// `dependencies[].ref` -> `dependsOn`.
    pub dependencies: HashMap<String, Vec<String>>,
    /// Some `dependencies` entries or `dependsOn` refs were dropped by a cap
    /// (an algorithm link may be missing).
    pub dependencies_truncated: bool,
    /// Per component: index of the algorithm component it names.
    algorithms: Vec<Option<usize>>,
}

/// Clip `s` to `max` characters, appending `…`; whether it was clipped.
pub fn clip_chars(s: &str, max: usize) -> (String, bool) {
    match s.char_indices().nth(max) {
        Some((i, _)) => {
            let mut out = String::with_capacity(i + 3);
            out.push_str(&s[..i]);
            out.push('…');
            (out, true)
        }
        None => (s.to_string(), false),
    }
}

/// A leaf as a string, recording `field` in `clipped` when it was clipped.
fn take(l: Leaf, field: &'static str, clipped: &mut Vec<&'static str>) -> Option<String> {
    if l.clipped() && !clipped.contains(&field) {
        clipped.push(field);
    }
    l.into_str()
}

fn decode_line(l: &Leaf) -> Result<u32, &'static str> {
    match l {
        Leaf::Missing | Leaf::Null => Err("line_missing"),
        Leaf::U64(u) => u32::try_from(*u).map_err(|_| "line_invalid"),
        Leaf::I64(i) if *i < 0 => Err("line_negative"),
        _ => Err("line_invalid"),
    }
}

fn occurrence(o: RawOccurrence) -> Occurrence {
    let mut clipped = Vec::new();
    Occurrence {
        location: match o.location.0 {
            Leaf::Str(s, _) => Ok(s),
            Leaf::TooLong => Err("location_too_long"),
            Leaf::Missing | Leaf::Null => Err("location_missing"),
            _ => Err("location_invalid"),
        },
        line: decode_line(&o.line),
        offset: o.offset.u64(),
        additional_context: take(o.additional_context, "additionalContext", &mut clipped),
        clipped,
    }
}

fn json_error(e: serde_json::Error) -> CbomError {
    let m = e.to_string();
    if m.starts_with(raw::ERR_COMPONENTS) {
        CbomError::TooManyComponents
    } else if m.starts_with(raw::ERR_OCCURRENCES) {
        CbomError::TooManyOccurrences
    } else if m.starts_with(raw::ERR_TOTAL) {
        CbomError::TooManyTotalOccurrences
    } else {
        CbomError::Json(m.chars().take(300).collect())
    }
}

/// For each component, the algorithm component a row should name: itself
/// when it is an algorithm, else the first `dependsOn` entry that is the
/// `bom-ref` of an algorithm (the first such component when refs repeat).
/// One pass over the components plus one over each distinct ref's
/// dependencies. A clipped `bom-ref` never links (it may collide).
fn link_algorithms(
    components: &[Component],
    dependencies: &HashMap<String, Vec<String>>,
) -> Vec<Option<usize>> {
    fn is_alg(c: &Component) -> bool {
        c.asset_type.as_deref() == Some("algorithm")
    }
    fn link_ref(c: &Component) -> Option<&str> {
        if c.clipped.contains(&"bom-ref") {
            None
        } else {
            c.bom_ref.as_deref()
        }
    }
    let mut by_ref: HashMap<&str, usize> = HashMap::new();
    for (i, c) in components.iter().enumerate() {
        if is_alg(c)
            && let Some(r) = link_ref(c)
        {
            by_ref.entry(r).or_insert(i);
        }
    }
    let mut memo: HashMap<&str, Option<usize>> = HashMap::new();
    components
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if is_alg(c) {
                return Some(i);
            }
            let r = link_ref(c)?;
            *memo.entry(r).or_insert_with(|| {
                dependencies
                    .get(r)?
                    .iter()
                    .find_map(|d| by_ref.get(d.as_str()).copied())
            })
        })
        .collect()
}

/// Parse and validate CBOM bytes. See the module docs for the policy.
pub fn parse_cbom(bytes: &[u8]) -> Result<Cbom, CbomError> {
    if bytes.len() as u64 > MAX_CBOM_BYTES {
        return Err(CbomError::TooLarge);
    }
    let Lenient(raw) = serde_json::from_slice::<Lenient<RawBom>>(bytes).map_err(json_error)?;
    let raw = raw.ok_or(CbomError::BadFormat)?;
    if raw.bom_format.as_str() != Some("CycloneDX") {
        return Err(CbomError::BadFormat);
    }
    let spec = raw.spec_version.into_str().unwrap_or_default();
    if spec != "1.6" && spec != "1.7" {
        return Err(CbomError::UnsupportedVersion(
            spec.chars().take(40).collect(),
        ));
    }
    let mut components = Vec::new();
    for rc in raw.components.0 {
        let Some(crypto) = rc.crypto.0 else { continue };
        let alg = crypto.algorithm.0.unwrap_or_default();
        let mat = crypto.material.0.unwrap_or_default();
        let mut clipped = Vec::new();
        let crypto_functions = alg
            .crypto_functions
            .0
            .into_iter()
            .filter_map(|l| take(l, "cryptoFunctions", &mut clipped))
            .collect();
        let occurrences = rc
            .evidence
            .0
            .map(|e| e.occurrences.0)
            .unwrap_or_default()
            .into_iter()
            .map(occurrence)
            .collect();
        components.push(Component {
            bom_ref: take(rc.bom_ref, "bom-ref", &mut clipped),
            name: take(rc.name, "name", &mut clipped),
            asset_type: take(crypto.asset_type, "assetType", &mut clipped),
            primitive: take(alg.primitive, "primitive", &mut clipped),
            parameter_set_identifier: take(
                alg.parameter_set_identifier,
                "parameterSetIdentifier",
                &mut clipped,
            ),
            curve: take(alg.curve, "curve", &mut clipped),
            mode: take(alg.mode, "mode", &mut clipped),
            crypto_functions,
            material_type: take(mat.material_type, "type", &mut clipped),
            material_size: mat.size.u64(),
            occurrences,
            clipped,
        });
    }
    let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();
    let dependencies_truncated = raw.dependencies.1;
    for d in raw.dependencies.0 {
        if d.reference.clipped() {
            continue;
        }
        let Some(r) = d.reference.into_str() else {
            continue;
        };
        let deps = d
            .depends_on
            .0
            .into_iter()
            .filter(|l| !l.clipped())
            .filter_map(Leaf::into_str);
        dependencies.entry(r).or_default().extend(deps);
    }
    let algorithms = link_algorithms(&components, &dependencies);
    Ok(Cbom {
        sha256: sha256_hex(bytes),
        spec_version: spec,
        tool: raw.metadata.0.and_then(|m| m.tools.0),
        components,
        dependencies,
        dependencies_truncated,
        algorithms,
    })
}

/// Read a CBOM file (bounded; a special file cannot exhaust memory or block).
pub fn read_cbom(path: &Path) -> Result<Cbom, CbomError> {
    let io = |e: std::io::Error| CbomError::Io(e.to_string());
    let not_file = || CbomError::Io("not a regular file".to_string());
    if !std::fs::metadata(path).map_err(io)?.is_file() {
        return Err(not_file());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let file = opts.open(path).map_err(io)?;
    if !file.metadata().map_err(io)?.is_file() {
        return Err(not_file());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CBOM_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    parse_cbom(&bytes)
}

impl Cbom {
    /// The algorithm component a row should name: the component itself when
    /// it is an algorithm, else the first `assetType: algorithm` it depends
    /// on. O(1): the links are computed once in [`parse_cbom`].
    pub fn algorithm_for(&self, idx: usize) -> Option<&Component> {
        let a = (*self.algorithms.get(idx)?)?;
        self.components.get(a)
    }
}

// ---- quantum classification --------------------------------------------------

/// Quantum vulnerability of an algorithm component, from NIST IR 8547 (final,
/// 2026-10-27), which deprecates and disallows RSA, ECDSA / elliptic-curve,
/// EdDSA, finite-field and elliptic-curve Diffie-Hellman, DSA and MQV.
///
/// The table is deliberately small:
/// * `Some(true)`: a name token is RSA*, EC, ECC, ECDSA*, ECDH*, ECDHE, ECMQV,
///   MQV, EdDSA, Ed25519, Ed448, X25519, X448, DSA, DH, DHE; or a `curve` is
///   given with a public-key primitive (`pke`, `signature`, `key-agree`) or no
///   primitive.
/// * `Some(false)`: primitive `hash`, or `ae` / `block-cipher` with a key size
///   of at least 128 bits (from `parameterSetIdentifier`, else a 128/192/256
///   name token).
/// * `None` (unknown): everything else, including post-quantum names
///   (ML-KEM, ML-DSA, SLH-DSA, ...), which are checked first so `ML-DSA` is
///   never mistaken for DSA.
pub fn classify_quantum(c: &Component) -> Option<bool> {
    let name = c.name.as_deref().unwrap_or("").to_ascii_uppercase();
    let toks: Vec<&str> = name
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    const PQC: &[&str] = &[
        "ML",
        "SLH",
        "FN",
        "KYBER",
        "DILITHIUM",
        "FALCON",
        "SPHINCS",
        "XMSS",
        "LMS",
        "HSS",
        "FRODOKEM",
        "BIKE",
        "HQC",
        "MCELIECE",
    ];
    if toks.iter().any(|t| PQC.contains(t)) {
        return None;
    }
    const EXACT: &[&str] = &[
        "EC", "ECC", "ECDHE", "ECMQV", "MQV", "EDDSA", "ED25519", "ED448", "X25519", "X448", "DSA",
        "DH", "DHE",
    ];
    let vulnerable_name = toks.iter().any(|t| {
        EXACT.contains(t)
            || t.starts_with("RSA")
            || t.starts_with("ECDSA")
            || t.starts_with("ECDH")
            || t.contains("WITHRSA")
            || t.contains("WITHECDSA")
    });
    let prim = c.primitive.as_deref();
    let public_key_prim = matches!(prim, None | Some("pke" | "signature" | "key-agree"));
    if vulnerable_name || (c.curve.is_some() && public_key_prim) {
        return Some(true);
    }
    if prim == Some("hash") {
        return Some(false);
    }
    if matches!(prim, Some("ae" | "block-cipher")) {
        let bits = c
            .parameter_set_identifier
            .as_deref()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .or_else(|| {
                toks.iter()
                    .filter_map(|t| t.parse::<u32>().ok())
                    .find(|b| [128, 192, 256].contains(b))
            });
        if bits.is_some_and(|b| b >= 128) {
            return Some(false);
        }
    }
    None
}

// ---- path mapping ------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    Invalid,
    Absolute,
    ParentComponent,
    OutsideRoot,
    Missing,
    TooLarge,
    TooLong,
}

impl PathError {
    /// Stable reason string for the receipt.
    pub fn reason(self) -> &'static str {
        match self {
            PathError::Invalid => "invalid_location",
            PathError::Absolute => "absolute_path",
            PathError::ParentComponent => "parent_component",
            PathError::OutsideRoot => "path_outside_root",
            PathError::Missing => "file_missing",
            PathError::TooLarge => "file_too_large",
            PathError::TooLong => "location_too_long",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapped {
    /// Path relative to the canonical root, `/`-separated (symlinks resolved).
    pub rel: String,
    pub abs: PathBuf,
    /// Leading location components dropped to find the file (CBOMkit's
    /// workspace prefix is 1).
    pub stripped: usize,
}

/// Map a CBOM `location` onto a file under `root`.
///
/// CBOMkit prefixes locations with the scanner's workspace directory name
/// (`ws/app/keys.py` for `<root>/app/keys.py`), so the full relative path is
/// tried first, then each suffix with the leading components stripped; the
/// first existing regular file wins and [`Mapped::stripped`] says how many
/// were dropped. `root` must already be canonical. Locations over
/// [`MAX_LOCATION_BYTES`] or [`MAX_LOCATION_COMPONENTS`] are refused (the
/// suffix search is quadratic in the component count). Absolute paths and
/// `..` components are rejected up front; a candidate whose canonical path
/// leaves `root` (a symlink out) is rejected, never followed.
pub fn map_location(root: &Path, location: &str) -> Result<Mapped, PathError> {
    if location.len() > MAX_LOCATION_BYTES {
        return Err(PathError::TooLong);
    }
    if location.is_empty() || location.contains('\0') {
        return Err(PathError::Invalid);
    }
    let loc = location.replace('\\', "/");
    let b = loc.as_bytes();
    if loc.starts_with('/') || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':') {
        return Err(PathError::Absolute);
    }
    let comps: Vec<&str> = loc
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if comps.is_empty() {
        return Err(PathError::Invalid);
    }
    if comps.len() > MAX_LOCATION_COMPONENTS {
        return Err(PathError::TooLong);
    }
    if comps.contains(&"..") {
        return Err(PathError::ParentComponent);
    }
    for k in 0..comps.len() {
        let candidate = root.join(comps[k..].join("/"));
        let Ok(canon) = candidate.canonicalize() else {
            continue;
        };
        if !canon.starts_with(root) {
            return Err(PathError::OutsideRoot);
        }
        let Ok(meta) = std::fs::metadata(&canon) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if meta.len() > MAX_SOURCE_FILE_BYTES {
            return Err(PathError::TooLarge);
        }
        let Ok(rel) = canon.strip_prefix(root) else {
            return Err(PathError::OutsideRoot);
        };
        let rel = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        return Ok(Mapped {
            rel,
            abs: canon,
            stripped: k,
        });
    }
    Err(PathError::Missing)
}

#[cfg(test)]
#[path = "cbom_tests.rs"]
mod tests;
