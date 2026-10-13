//! Work assignment for the multi-model run.
//!
//! - Finders: ranked modules are dealt round-robin to the finder models, so
//!   each module is audited by exactly one model and the cost stays close to
//!   a single-model run.
//! - Verifiers: a finding is verified by a model of a different family from
//!   its finder when the roster has one (rotating over those to spread the
//!   load); otherwise by another model of the same family; otherwise by the
//!   finder itself. The vote records which case applied.

use crate::llm::ModelHandle;

/// Index of the finder for the `i`-th ranked module.
pub fn finder_for(module_index: usize, finder_count: usize) -> Option<usize> {
    (finder_count > 0).then(|| module_index % finder_count)
}

/// The chosen verifier and whether it is cross-family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierPick {
    pub index: usize,
    pub cross_family: bool,
}

/// Pick a verifier for a finding found by `finder`. `nth` is a run-wide
/// counter used to rotate among equally good candidates.
pub fn verifier_for(
    finder: &ModelHandle,
    verifiers: &[ModelHandle],
    nth: usize,
) -> Option<VerifierPick> {
    let cross: Vec<usize> = (0..verifiers.len())
        .filter(|&i| verifiers[i].family != finder.family)
        .collect();
    if !cross.is_empty() {
        return Some(VerifierPick {
            index: cross[nth % cross.len()],
            cross_family: true,
        });
    }
    let other_model: Vec<usize> = (0..verifiers.len())
        .filter(|&i| verifiers[i].id != finder.id)
        .collect();
    if !other_model.is_empty() {
        return Some(VerifierPick {
            index: other_model[nth % other_model.len()],
            cross_family: false,
        });
    }
    (!verifiers.is_empty()).then_some(VerifierPick {
        index: 0,
        cross_family: false,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::llm::{LlmCaller, Result};

    struct Nop;
    #[async_trait]
    impl LlmCaller for Nop {
        async fn complete(&self, _p: &str) -> Result<String> {
            Ok(String::new())
        }
    }

    fn m(id: &str, family: &str) -> ModelHandle {
        ModelHandle {
            id: id.into(),
            family: family.into(),
            caller: Arc::new(Nop),
        }
    }

    #[test]
    fn modules_are_dealt_round_robin() {
        let got: Vec<_> = (0..5).map(|i| finder_for(i, 3).unwrap()).collect();
        assert_eq!(got, vec![0, 1, 2, 0, 1]);
        assert_eq!(finder_for(0, 0), None);
    }

    #[test]
    fn verifier_prefers_other_family_and_rotates() {
        let vs = vec![
            m("claude", "anthropic"),
            m("codex", "openai"),
            m("grok", "xai"),
        ];
        let f = m("claude", "anthropic");
        let a = verifier_for(&f, &vs, 0).unwrap();
        let b = verifier_for(&f, &vs, 1).unwrap();
        assert!(a.cross_family && b.cross_family);
        assert_eq!((a.index, b.index), (1, 2));
    }

    #[test]
    fn same_family_other_model_then_self() {
        let vs = vec![m("opus", "anthropic"), m("sonnet", "anthropic")];
        let p = verifier_for(&m("opus", "anthropic"), &vs, 0).unwrap();
        assert_eq!(
            p,
            VerifierPick {
                index: 1,
                cross_family: false
            }
        );
        let only = vec![m("opus", "anthropic")];
        let p = verifier_for(&m("opus", "anthropic"), &only, 0).unwrap();
        assert_eq!(
            p,
            VerifierPick {
                index: 0,
                cross_family: false
            }
        );
        assert!(verifier_for(&m("x", "y"), &[], 0).is_none());
    }
}
