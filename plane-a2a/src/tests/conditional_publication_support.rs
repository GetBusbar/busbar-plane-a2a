// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The journal's test-only reach: a publication with no local obligations, and the questions the
//! callback tests ask of its steps.

use super::*;

impl Journal {
    /// Publish once at this replay position. Only a definitive conflict permits primitive retry.
    pub(crate) fn publish(
        &self,
        seq: u32,
        predicates: &[Predicate],
        lives: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.publish_with(seq, predicates, lives, writes, &Draft::default())
    }

    /// Whether this invocation's conditional event filing actually reached Applied.
    pub(crate) fn applied_since(&self, seq: u32, kind: &str, key: &str) -> bool {
        self.0.with(&(), |s| {
            s.is_some_and(|s| {
                s.steps.iter().any(|step| {
                    if step.seq < seq {
                        return false;
                    }
                    matches!(&step.action, Action::Publish {
                answer: Some(Ok(Decision::Applied)), writes, ..
            } if writes.iter().any(|w| w.kind == kind && w.key == key && !w.value.is_empty()))
                })
            })
        })
    }

    /// A submitted event whose definitive outcome is still unknown cannot be offered anew.
    pub(crate) fn owns_unresolved_event(&self, kind: &str, key: &str) -> bool {
        self.0.with(&(), |s| {
            s.is_some_and(|s| {
                s.steps.iter().any(|step| {
                    if !step.submitted {
                        return false;
                    }
                    match &step.action {
                        Action::Publish { answer, writes, .. } => {
                            let resolved = matches!(
                                answer,
                                Some(Ok(_)) | Some(Err(wire::ConditionalFailure::Refused(_)))
                            );
                            !resolved
                                && writes
                                    .iter()
                                    .any(|w| w.kind == kind && w.key == key && !w.value.is_empty())
                        }
                        _ => false,
                    }
                })
            })
        })
    }
}
