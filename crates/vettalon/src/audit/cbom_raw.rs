//! Bounded serde shapes for [`super::parse_cbom`] (a child module of `cbom`,
//! declared there with `#[path]`).
//!
//! Every cap is enforced *while* deserializing: the component, per-component
//! occurrence and total occurrence counters error out as soon as a cap is
//! passed, and nothing ever builds a `serde_json::Value` tree. A value of the
//! wrong JSON type becomes "missing" (`Leaf::Other`, `Lenient(None)`, an empty
//! list) and is skipped with [`IgnoredAny`]. Strings are clipped to
//! [`MAX_STRING_CHARS`] characters on arrival (`Leaf::Str(_, true)` records
//! it); an occurrence `location` is kept whole up to [`MAX_LOCATION_BYTES`]
//! and is `Leaf::TooLong` beyond.

use std::fmt;
use std::marker::PhantomData;

use serde::Deserialize;
use serde::de::value::MapAccessDeserializer;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use super::{
    MAX_COMPONENTS, MAX_LOCATION_BYTES, MAX_OCCURRENCES, MAX_STRING_CHARS, MAX_TOTAL_OCCURRENCES,
    clip_chars,
};

/// Error message prefixes `parse_cbom` maps back to `CbomError` variants.
pub(super) const ERR_COMPONENTS: &str = "vettalon-cap: components";
pub(super) const ERR_OCCURRENCES: &str = "vettalon-cap: occurrences";
pub(super) const ERR_TOTAL: &str = "vettalon-cap: total occurrences";

/// `metadata.tools` entries looked at.
const MAX_TOOLS: usize = 16;
const MAX_CRYPTO_FUNCTIONS: usize = 64;
const MAX_DEPENDS_ON: usize = 1024;

/// Visitor methods for every scalar JSON type, returning `$v`.
macro_rules! scalars_to {
    ($v:expr) => {
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok($v)
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok($v)
        }
    };
}

/// `visit_seq` that skips every element and returns `$v`.
macro_rules! skip_seq {
    ($de:lifetime, $v:expr) => {
        fn visit_seq<A: SeqAccess<$de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            while a.next_element::<IgnoredAny>()?.is_some() {}
            Ok($v)
        }
    };
}

/// `visit_map` that skips every entry and returns `$v`.
macro_rules! skip_map {
    ($de:lifetime, $v:expr) => {
        fn visit_map<A: MapAccess<$de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            while a.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok($v)
        }
    };
}

// ---- leaves ------------------------------------------------------------------

/// A scalar leaf field.
#[derive(Debug, Default)]
pub(super) enum Leaf {
    #[default]
    Missing,
    Null,
    /// The string and whether it was clipped.
    Str(String, bool),
    /// A `location` longer than [`MAX_LOCATION_BYTES`].
    TooLong,
    U64(u64),
    I64(i64),
    /// Any other type (float, bool, array, object).
    Other,
}

impl Leaf {
    pub(super) fn as_str(&self) -> Option<&str> {
        match self {
            Leaf::Str(s, _) => Some(s),
            _ => None,
        }
    }

    pub(super) fn into_str(self) -> Option<String> {
        match self {
            Leaf::Str(s, _) => Some(s),
            _ => None,
        }
    }

    pub(super) fn clipped(&self) -> bool {
        matches!(self, Leaf::Str(_, true))
    }

    pub(super) fn u64(&self) -> Option<u64> {
        match self {
            Leaf::U64(v) => Some(*v),
            _ => None,
        }
    }
}

struct LeafVisitor {
    location: bool,
}

impl<'de> Visitor<'de> for LeafVisitor {
    type Value = Leaf;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Leaf, E> {
        Ok(Leaf::Other)
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Leaf, E> {
        Ok(match u64::try_from(v) {
            Ok(u) => Leaf::U64(u),
            Err(_) => Leaf::I64(v),
        })
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Leaf, E> {
        Ok(Leaf::U64(v))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Leaf, E> {
        Ok(Leaf::Other)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Leaf, E> {
        if self.location {
            return Ok(if v.len() > MAX_LOCATION_BYTES {
                Leaf::TooLong
            } else {
                Leaf::Str(v.to_string(), false)
            });
        }
        let (s, clipped) = clip_chars(v, MAX_STRING_CHARS);
        Ok(Leaf::Str(s, clipped))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Leaf, E> {
        Ok(Leaf::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Leaf, E> {
        Ok(Leaf::Null)
    }

    skip_seq!('de, Leaf::Other);
    skip_map!('de, Leaf::Other);
}

impl<'de> Deserialize<'de> for Leaf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(LeafVisitor { location: false })
    }
}

/// An occurrence `location`: kept whole up to [`MAX_LOCATION_BYTES`].
#[derive(Debug, Default)]
pub(super) struct LocLeaf(pub(super) Leaf);

impl<'de> Deserialize<'de> for LocLeaf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(LeafVisitor { location: true })
            .map(LocLeaf)
    }
}

// ---- generic wrappers --------------------------------------------------------

/// An object deserialized as `T`; any other JSON type is `None`.
pub(super) struct Lenient<T>(pub(super) Option<T>);

impl<T> Default for Lenient<T> {
    fn default() -> Self {
        Lenient(None)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Lenient<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = Lenient<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(self, a: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(a)).map(|t| Lenient(Some(t)))
            }
            skip_seq!('de, Lenient(None));
            scalars_to!(Lenient(None));
        }
        d.deserialize_any(V::<T>(PhantomData))
    }
}

/// The first `N` elements of an array (the rest is skipped; the flag records
/// that something was dropped); any other JSON type is an empty list.
pub(super) struct Bounded<T, const N: usize>(pub(super) Vec<T>, pub(super) bool);

impl<T, const N: usize> Default for Bounded<T, N> {
    fn default() -> Self {
        Bounded(Vec::new(), false)
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for V<T, N> {
            type Value = Bounded<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while out.len() < N {
                    match a.next_element::<T>()? {
                        Some(t) => out.push(t),
                        None => return Ok(Bounded(out, false)),
                    }
                }
                let mut dropped = false;
                while a.next_element::<IgnoredAny>()?.is_some() {
                    dropped = true;
                }
                Ok(Bounded(out, dropped))
            }
            skip_map!('de, Bounded(Vec::new(), false));
            scalars_to!(Bounded(Vec::new(), false));
        }
        d.deserialize_any(V::<T, N>(PhantomData))
    }
}

// ---- document ----------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawBom {
    #[serde(rename = "bomFormat")]
    pub(super) bom_format: Leaf,
    #[serde(rename = "specVersion")]
    pub(super) spec_version: Leaf,
    pub(super) metadata: Lenient<RawMetadata>,
    pub(super) components: Components,
    pub(super) dependencies: Dependencies,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawMetadata {
    pub(super) tools: Tools,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawDependency {
    #[serde(rename = "ref")]
    pub(super) reference: Leaf,
    #[serde(rename = "dependsOn")]
    pub(super) depends_on: Bounded<Leaf, MAX_DEPENDS_ON>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawComponent {
    #[serde(rename = "bom-ref")]
    pub(super) bom_ref: Leaf,
    pub(super) name: Leaf,
    pub(super) evidence: Lenient<RawEvidence>,
    #[serde(rename = "cryptoProperties")]
    pub(super) crypto: Lenient<RawCrypto>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawEvidence {
    pub(super) occurrences: Occurrences,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawOccurrence {
    pub(super) location: LocLeaf,
    pub(super) line: Leaf,
    pub(super) offset: Leaf,
    #[serde(rename = "additionalContext")]
    pub(super) additional_context: Leaf,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawCrypto {
    #[serde(rename = "assetType")]
    pub(super) asset_type: Leaf,
    #[serde(rename = "algorithmProperties")]
    pub(super) algorithm: Lenient<RawAlgorithm>,
    #[serde(rename = "relatedCryptoMaterialProperties")]
    pub(super) material: Lenient<RawMaterial>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawAlgorithm {
    pub(super) primitive: Leaf,
    #[serde(rename = "parameterSetIdentifier")]
    pub(super) parameter_set_identifier: Leaf,
    pub(super) curve: Leaf,
    pub(super) mode: Leaf,
    #[serde(rename = "cryptoFunctions")]
    pub(super) crypto_functions: Bounded<Leaf, MAX_CRYPTO_FUNCTIONS>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RawMaterial {
    #[serde(rename = "type")]
    pub(super) material_type: Leaf,
    pub(super) size: Leaf,
}

// ---- capped arrays -----------------------------------------------------------

/// `components[]`: errors once more than [`MAX_COMPONENTS`] components or
/// more than [`MAX_TOTAL_OCCURRENCES`] occurrences in total are seen; keeps
/// only components with `cryptoProperties`.
#[derive(Default)]
pub(super) struct Components(pub(super) Vec<RawComponent>);

impl<'de> Deserialize<'de> for Components {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Components;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Components, A::Error> {
                let (mut out, mut count, mut total) = (Vec::new(), 0usize, 0usize);
                while let Some(Lenient(c)) = a.next_element::<Lenient<RawComponent>>()? {
                    count += 1;
                    if count > MAX_COMPONENTS {
                        return Err(de::Error::custom(ERR_COMPONENTS));
                    }
                    let Some(c) = c else { continue };
                    total += c.evidence.0.as_ref().map_or(0, |e| e.occurrences.0.len());
                    if total > MAX_TOTAL_OCCURRENCES {
                        return Err(de::Error::custom(ERR_TOTAL));
                    }
                    if c.crypto.0.is_some() {
                        out.push(c);
                    }
                }
                Ok(Components(out))
            }
            skip_map!('de, Components(Vec::new()));
            scalars_to!(Components(Vec::new()));
        }
        d.deserialize_any(V)
    }
}

/// `evidence.occurrences[]`: errors past [`MAX_OCCURRENCES`]. A non-object
/// entry is kept as an empty occurrence (it becomes an `unknown` row).
#[derive(Default)]
pub(super) struct Occurrences(pub(super) Vec<RawOccurrence>);

impl<'de> Deserialize<'de> for Occurrences {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Occurrences;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Occurrences, A::Error> {
                let mut out = Vec::new();
                while let Some(Lenient(o)) = a.next_element::<Lenient<RawOccurrence>>()? {
                    if out.len() >= MAX_OCCURRENCES {
                        return Err(de::Error::custom(ERR_OCCURRENCES));
                    }
                    out.push(o.unwrap_or_default());
                }
                Ok(Occurrences(out))
            }
            skip_map!('de, Occurrences(Vec::new()));
            scalars_to!(Occurrences(Vec::new()));
        }
        d.deserialize_any(V)
    }
}

/// `dependencies[]`: at most [`MAX_COMPONENTS`] entries and
/// [`MAX_TOTAL_OCCURRENCES`] `dependsOn` refs are kept; the rest is parsed
/// and dropped (a lost link only makes an algorithm unknown). The flag is set
/// when any entry or `dependsOn` ref was dropped by a cap.
#[derive(Default)]
pub(super) struct Dependencies(pub(super) Vec<RawDependency>, pub(super) bool);

impl<'de> Deserialize<'de> for Dependencies {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Dependencies;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Dependencies, A::Error> {
                let (mut out, mut refs, mut truncated) = (Vec::new(), 0usize, false);
                while let Some(Lenient(dep)) = a.next_element::<Lenient<RawDependency>>()? {
                    let Some(dep) = dep else { continue };
                    let n = dep.depends_on.0.len();
                    truncated |= dep.depends_on.1;
                    if out.len() < MAX_COMPONENTS && refs + n <= MAX_TOTAL_OCCURRENCES {
                        refs += n;
                        out.push(dep);
                    } else {
                        truncated = true;
                    }
                }
                Ok(Dependencies(out, truncated))
            }
            skip_map!('de, Dependencies(Vec::new(), false));
            scalars_to!(Dependencies(Vec::new(), false));
        }
        d.deserialize_any(V)
    }
}

// ---- metadata.tools ----------------------------------------------------------

/// The first named tool of `metadata.tools`: an object (`services` /
/// `components`, CycloneDX 1.5+) or a legacy array of `{vendor, name,
/// version}`. Only the first [`MAX_TOOLS`] entries of a list are read.
#[derive(Default)]
pub(super) struct Tools(pub(super) Option<String>);

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawToolsObject {
    services: ToolList,
    components: ToolList,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawTool {
    vendor: Leaf,
    name: Leaf,
    version: Leaf,
    provider: Lenient<RawProvider>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawProvider {
    name: Leaf,
}

impl RawTool {
    fn label(self) -> Option<String> {
        let non_empty = |l: Leaf| l.into_str().filter(|s| !s.is_empty());
        let vendor = non_empty(self.vendor).or_else(|| self.provider.0?.name.into_str());
        let name = non_empty(self.name)?;
        let mut parts: Vec<String> = Vec::new();
        parts.extend(vendor);
        parts.push(name);
        parts.extend(non_empty(self.version));
        Some(parts.join(" ").chars().take(200).collect())
    }
}

#[derive(Default)]
struct ToolList(Option<String>);

impl<'de> Deserialize<'de> for ToolList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ToolList;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<ToolList, A::Error> {
                let mut found = None;
                for _ in 0..MAX_TOOLS {
                    match a.next_element::<Lenient<RawTool>>()? {
                        Some(Lenient(t)) => {
                            if found.is_none() {
                                found = t.and_then(RawTool::label);
                            }
                        }
                        None => return Ok(ToolList(found)),
                    }
                }
                while a.next_element::<IgnoredAny>()?.is_some() {}
                Ok(ToolList(found))
            }
            skip_map!('de, ToolList(None));
            scalars_to!(ToolList(None));
        }
        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for Tools {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Tools;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, a: A) -> Result<Tools, A::Error> {
                let list = ToolList::deserialize(de::value::SeqAccessDeserializer::new(a))?;
                Ok(Tools(list.0))
            }
            fn visit_map<A: MapAccess<'de>>(self, a: A) -> Result<Tools, A::Error> {
                let o = RawToolsObject::deserialize(MapAccessDeserializer::new(a))?;
                Ok(Tools(o.services.0.or(o.components.0)))
            }
            scalars_to!(Tools(None));
        }
        d.deserialize_any(V)
    }
}
