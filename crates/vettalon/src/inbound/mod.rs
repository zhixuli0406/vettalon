//! Turns one pasted vulnerability report into claims/1; report text never reaches a model.

// Parts of the module are only reached from the binary (`vettalon intake`).
#![allow(dead_code)]

pub mod extract;
pub(crate) mod parse;
pub mod run;
pub mod summary;

#[cfg(test)]
mod tests;
