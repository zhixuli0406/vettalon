//! vettalon: multi-model security audit for your own code.
//!
//! OSS scanners plus an AI audit where modules are split between finder
//! models and every candidate is challenged by a verifier of a different
//! model family. Every model reply is checked against a strict contract
//! (`vettalon-contract`); a reply that breaks it is discarded, never
//! repaired.

pub mod audit;
pub mod budget;
pub mod config;
pub mod disclose;
pub mod guard;
pub mod hunt;
pub mod joern;
pub mod kb;
pub mod lang;
pub mod llm;
pub mod sandbox;
pub mod util;
