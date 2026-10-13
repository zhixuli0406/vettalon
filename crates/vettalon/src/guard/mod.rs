//! Deterministic, zero-LLM prompt-injection signals, ported from DuDuClaw
//! `duduclaw-security` (`input_guard`, `unicode_normalizer`). vettalon uses
//! them to flag audited files that contain text aimed at the model.

pub mod input_guard;
pub mod unicode_normalizer;
