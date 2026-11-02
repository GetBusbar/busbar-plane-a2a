// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One callback's replay journal for read-bound observations and atomic publication. The host

use std::sync::{Arc, Weak};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::AbiOut;
use busbar_contract::abi::sdk::life::Leases;
use busbar_contract::abi::sdk::plane::conditional as wire;
use busbar_contract::abi::sdk::store::conditional::{Decision, Expected};
use busbar_contract::abi::sdk::{Keyed, Out};

use crate::proto::custody::{Guard, Wipe};
use crate::records::{HELD_KINDS, KIND_TASK_EVENT};
use crate::tasks::{ChainLife, Halt, Predicate, Write};

/// Shared only by one pass and its ephemeral record adapter. All guards protect local data;
/// encoding an intent makes no host call while the guard is held.
#[derive(Debug, Clone, Default)]
pub(crate) struct Journal(Arc<Keyed<(), State>>);

#[derive(Debug, Default)]
struct State {
    capability: Option<wire::Capability>,
    next: u64,
    steps: Vec<Step>,
    cancelled: bool,
    broken: bool,
    completed: bool,
    ack_offered: Option<wire::Settlement>,
    quarantined: bool,
    wake: OwnerWake,
    applying: Option<Arc<()>>,
}

#[derive(Default)]
struct OwnerWake(Weak<crate::push::Wakeup>);
impl std::fmt::Debug for OwnerWake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnerWake")
    }
}

/// Local obligations attached before submitting a candidate; never reconstructed from post-state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Draft {
    pub(crate) notify: bool,
    pub(crate) config: Option<Result<Option<crate::local::PushConfig>, ()>>,
    pub(crate) backend: Option<String>,
    pub(crate) owed: Option<crate::push::OwedReceipt>,
}

#[derive(Debug)]
struct After {
    draft: Draft,
    row: Option<crate::TaskRow>,
    config_withdrawn: bool,
    notify_done: bool,
    backend_done: bool,
    owed_done: bool,
}

/// Acknowledged effects to apply after releasing the journal's guard.
#[derive(Default)]
pub(crate) struct Applied {
    pub(crate) owner: Option<Arc<()>>,
    pub(crate) deletes: Vec<Write>,
    pub(crate) notify: Vec<(
        crate::TaskRow,
        Option<Result<Option<crate::local::PushConfig>, ()>>,
    )>,
    pub(crate) backends: Vec<(crate::TaskRow, String)>,
    pub(crate) owed: Vec<crate::push::OwedReceipt>,
    pub(crate) release_owed: Vec<crate::push::OwedReceipt>,
}

#[derive(Debug)]
struct Step {
    seq: u32,
    submitted: bool,
    action: Action,
}

enum Action {
    Observe {
        request: wire::Observation,
        answer: Option<Result<Expected, wire::ConditionalFailure>>,
    },
    Publish {
        request: wire::Request,
        writes: Vec<Write>,
        answer: Option<Result<Decision, wire::ConditionalFailure>>,
        metadata_taken: bool,
        after: After,
    },
}

impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Action([REDACTED])")
    }
}

impl Drop for Action {
    fn drop(&mut self) {
        match self {
            Self::Publish { request, .. } => request.wipe(),
            Self::Observe { request, answer } => {
                crate::record_custody::bytes(&mut request.scope);
                if let Some(Ok(expected)) = answer {
                    expected.wipe();
                }
            }
        }
    }
}

fn failed() -> Halt {
    Halt::Failed("conditional task publication unavailable or inconsistent".into())
}

fn kind(kind: &str) -> Result<u32, Halt> {
    HELD_KINDS
        .iter()
        .position(|k| *k == kind)
        .and_then(|i| u32::try_from(i).ok())
        .ok_or_else(failed)
}

fn expected(value: &Option<Vec<u8>>) -> Expected {
    value.clone().map_or(Expected::Absent, Expected::Bytes)
}

impl Step {
    fn pending(&self) -> bool {
        match &self.action {
            Action::Observe { answer, .. } => answer.is_none(),
            Action::Publish { answer, .. } => answer.is_none(),
        }
    }
}

impl State {
    fn effects_complete(&self) -> bool {
        self.applying.is_none()
            && self.steps.iter().all(|step| {
                let Action::Publish {
                    answer,
                    metadata_taken,
                    after,
                    ..
                } = &step.action
                else {
                    return true;
                };
                if matches!(answer, Some(Ok(Decision::Applied))) {
                    *metadata_taken
                        && (!after.draft.notify || after.notify_done)
                        && (after.draft.backend.is_none() || after.backend_done)
                        && (after.draft.owed.is_none() || after.owed_done)
                } else if self.cancelled
                    && after
                        .draft
                        .owed
                        .as_ref()
                        .is_some_and(|receipt| self.owed_decision(receipt) == Some(false))
                {
                    after.owed_done
                } else {
                    true
                }
            })
    }

    fn owed_decision(&self, receipt: &crate::push::OwedReceipt) -> Option<bool> {
        let mut unresolved = false;
        for step in &self.steps {
            if let Action::Publish { answer, after, .. } = &step.action {
                if after.draft.owed.as_ref() != Some(receipt) {
                    continue;
                }
                if matches!(answer, Some(Ok(Decision::Applied))) {
                    return Some(true);
                }
                unresolved |= step.submitted
                    && !matches!(
                        answer,
                        Some(Ok(Decision::ConditionConflict))
                            | Some(Err(wire::ConditionalFailure::Refused(_)))
                    );
            }
        }
        if unresolved {
            None
        } else {
            Some(false)
        }
    }
}

impl Journal {
    /// Re-enter the same callback epoch. Only its exact receipt can settle its outstanding step.
    pub(crate) fn enter(&self, ticket: Ticket, extensions: &[u8]) -> Result<(), Halt> {
        self.0.with_all(|all| {
            let s = all.entry(()).or_default();
            if s.cancelled || s.broken {
                return Err(failed());
            }
            let capability = wire::read_capability(extensions).map_err(|_| failed())?;
            if capability.is_some_and(|c| c.ticket != ticket) {
                s.broken = true;
                return Err(failed());
            }
            if !s.steps.is_empty() && s.capability != capability {
                s.broken = true;
                return Err(failed());
            }
            s.capability = capability;
            s.completed = false;
            if let Some(step) = s.steps.iter_mut().find(|step| step.pending()) {
                let result_key = match &step.action {
                    Action::Observe { .. } => wire::OBSERVED,
                    Action::Publish { .. } => wire::RESULT,
                };
                if !step.submitted && busbar_contract::abi::mechanism::extensions::get(extensions, result_key).is_some() {
                    s.broken = true;
                    return Err(failed());
                }
                let read = match &mut step.action {
                    Action::Observe { request, answer } => wire::read_observed(extensions, request)
                        .map(|result| {
                            if let Some(result) = result {
                                *answer = Some(result.result);
                            }
                        }),
                    Action::Publish {
                        request, answer, ..
                    } => wire::read_result(extensions, request).map(|result| {
                        if let Some(result) = result {
                            *answer = Some(result.decision);
                        }
                    }),
                };
                if read.is_err() {
                    s.broken = true;
                    return Err(failed());
                }
                let refused = match &step.action {
                    Action::Observe { answer, .. } => matches!(answer, Some(Err(error)) if !matches!(error, wire::ConditionalFailure::Refused(_))),
                    Action::Publish { answer, .. } => matches!(answer, Some(Err(error)) if !matches!(error, wire::ConditionalFailure::Refused(_))),
                };
                if refused {


                    s.broken = true;
                    return Err(failed());
                }
            }
            Ok(())
        })
    }

    /// Read the original life before the caller issues its next, genuinely fresh GET handle.
    pub(crate) fn observe(
        &self,
        seq: u32,
        name: &str,
        scope: &str,
    ) -> Result<Option<Vec<u8>>, Halt> {
        let kind = kind(name)?;
        self.0.with_all(|all| {
            let s = all.entry(()).or_default();
            if s.cancelled || s.broken {
                return Err(failed());
            }
            let capability = s.capability.ok_or_else(failed)?;
            let at = s
                .steps
                .iter()
                .position(|step| step.seq == seq)
                .unwrap_or(s.steps.len());
            if at == s.steps.len() {
                if s.steps.last().is_some_and(|step| seq <= step.seq) {
                    s.broken = true;
                    return Err(failed());
                }
                s.next = s.next.checked_add(1).ok_or_else(failed)?;
                s.steps.push(Step {
                    seq,
                    submitted: false,
                    action: Action::Observe {
                        request: wire::Observation {
                            capability,
                            correlation: s.next,
                            kind,
                            scope: scope.as_bytes().to_vec(),
                        },
                        answer: None,
                    },
                });
            }
            let Some(step) = s.steps.get(at) else {
                return Err(failed());
            };
            let Action::Observe { request, answer } = &step.action else {
                return Err(failed());
            };
            if step.seq != seq || request.kind != kind || request.scope != scope.as_bytes() {
                s.broken = true;
                return Err(failed());
            }
            match answer {
                None => Err(Halt::Pending),
                Some(Ok(Expected::Absent)) => Ok(None),
                Some(Ok(Expected::Bytes(bytes))) if bytes.len() == 8 => Ok(Some(bytes.clone())),
                _ => {
                    s.broken = true;
                    Err(failed())
                }
            }
        })
    }

    /// Publish once at this replay position. Only a definitive conflict permits primitive retry.
    #[cfg(test)]
    pub(crate) fn publish(
        &self,
        seq: u32,
        predicates: &[Predicate],
        lives: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.publish_with(seq, predicates, lives, writes, &Draft::default())
    }

    pub(crate) fn publish_with(
        &self,
        seq: u32,
        predicates: &[Predicate],
        lives: &[ChainLife],
        writes: &[Write],
        draft: &Draft,
    ) -> Result<bool, Halt> {
        self.0.with_all(|all| {
            let s = all.entry(()).or_default();
            if s.cancelled || s.broken {
                return Err(failed());
            }
            let capability = s.capability.ok_or_else(failed)?;
            let at = s
                .steps
                .iter()
                .position(|step| step.seq == seq)
                .unwrap_or(s.steps.len());
            for life in lives {
                let observed_kind = kind(life.kind)?;
                let original = s.steps.iter().rev().find_map(|step| {
                    if step.seq >= seq {
                        return None;
                    }
                    match &step.action {
                        Action::Observe { request, answer }
                            if request.kind == observed_kind
                                && request.scope == life.scope.as_bytes() =>
                        {
                            Some(answer)
                        }
                        _ => None,
                    }
                });
                if original != Some(&Some(Ok(expected(&life.expected)))) {
                    s.broken = true;
                    return Err(failed());
                }
            }
            let correlation = match s.steps.get(at) {
                Some(Step {
                    action: Action::Publish { request, .. },
                    ..
                }) => request.candidate.correlation,
                Some(_) => {
                    s.broken = true;
                    return Err(failed());
                }
                None => {
                    if s.steps.last().is_some_and(|step| seq <= step.seq) {
                        s.broken = true;
                        return Err(failed());
                    }
                    s.next = s.next.checked_add(1).ok_or_else(failed)?;
                    s.next
                }
            };
            let request = candidate(capability, correlation, predicates, lives, writes)?;
            if at == s.steps.len() {
                if draft.notify && draft.config.is_none() {
                    return Err(failed());
                }
                let row = if draft.notify || draft.backend.is_some() {
                    Some(
                        writes
                            .iter()
                            .find(|w| w.kind == crate::records::KIND_TASK && !w.value.is_empty())
                            .and_then(|w| serde_json::from_slice::<crate::TaskRow>(&w.value).ok())
                            .ok_or_else(failed)?,
                    )
                } else {
                    None
                };
                s.steps.push(Step {
                    seq,
                    submitted: false,
                    action: Action::Publish {
                        request: (*request).clone(),
                        writes: writes.to_vec(),
                        answer: None,
                        metadata_taken: false,
                        after: After {
                            draft: draft.clone(),
                            row,
                            config_withdrawn: false,
                            notify_done: false,
                            backend_done: false,
                            owed_done: false,
                        },
                    },
                });
            }
            let Some(step) = s.steps.get(at) else {
                return Err(failed());
            };
            let Action::Publish {
                request: original,
                answer,
                after,
                ..
            } = &step.action
            else {
                return Err(failed());
            };
            if step.seq != seq || original != &*request || after.draft != *draft {
                s.broken = true;
                return Err(failed());
            }
            match answer {
                None => Err(Halt::Pending),
                Some(Ok(Decision::Applied)) => Ok(true),
                Some(Ok(Decision::ConditionConflict)) => Ok(false),
                Some(Err(_)) => Err(failed()),
            }
        })
    }

    /// Emit only an outstanding immutable intent. Call this before any ordinary output writer.
    pub(crate) fn pending<T: AbiOut>(
        &self,
        leases: &Leases,
        out: &mut Out<'_, T>,
    ) -> Option<Outcome> {
        self.0.with_all(|all| {
            let s = all.entry(()).or_default();
            if s.cancelled || s.broken {
                return Some(Outcome::Failed);
            }
            let step = s.steps.iter_mut().find(|step| step.pending())?;
            let result = match &step.action {
                Action::Observe { request, .. } => out.conditional_observation(leases, request),
                Action::Publish { request, .. } => out.conditional_request(leases, request),
            };
            if result.is_err() {
                s.broken = true;
                return Some(Outcome::Failed);
            }
            step.submitted = true;
            Some(Outcome::Pending)
        })
    }

    /// Config deletion metadata becomes visible only after the transaction acknowledges Applied.
    pub(crate) fn committed_writes(&self) -> Vec<Write> {
        self.0.with_all(|all| {
            let mut writes = Vec::new();
            let s = all.entry(()).or_default();
            for step in &mut s.steps {
                if let Action::Publish {
                    answer: Some(Ok(Decision::Applied)),
                    writes: committed,
                    metadata_taken,
                    ..
                } = &mut step.action
                {
                    if !*metadata_taken {
                        writes.extend(committed.clone());
                        *metadata_taken = true;
                    }
                }
            }
            writes
        })
    }

    /// Whether this invocation's conditional event filing actually reached Applied.
    #[cfg(test)]
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
    #[cfg(test)]
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

    /// A completed callback advances its service base; a SHORT or pending entry retains all steps.
    pub(crate) fn finished(&self) {
        self.0.with_all(|all| {
            let s = all.entry(()).or_default();
            if !s.broken
                && !s.cancelled
                && s.effects_complete()
                && !s.steps.iter().any(Step::pending)
            {
                s.steps.clear();
                s.completed = true;
            }
        });
    }

    /// Cancel starts no transaction. An emitted attempt stays owned by the host unchanged.
    pub(crate) fn cancelled(&self) {
        self.0.with_all(|all| {
            let s = all.entry(()).or_default();
            s.cancelled = true;
            if !s
                .steps
                .iter()
                .any(|step| step.submitted && matches!(step.action, Action::Publish { .. }))
            {
                s.steps.clear();
            }
        });
    }

    /// Parked callbacks may be dropped by generic cancellation before a settlement arrives.
    pub(crate) fn owner_dropped(&self) {
        if self.completed() {
            return;
        }
        self.cancelled();
        let wake = self.0.with(&(), |s| s.and_then(|s| s.wake.0.upgrade()));
        if let Some(wake) = wake {
            let call = wake.with(&(), |call| call.cloned());
            if let Some(call) = call {
                call();
            }
        }
    }

    pub(crate) fn owner_wake(&self, wake: Weak<crate::push::Wakeup>) {
        self.0
            .with_all(|all| all.entry(()).or_default().wake = OwnerWake(wake));
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.with(&(), |s| s.is_some_and(|s| s.cancelled))
    }

    /// An emitted later observation replaced the prior definitive commit at the host. Its

    pub(crate) fn cancelled_without_receipt(&self) -> bool {
        self.0.with(&(), |state| {
            state.is_some_and(|state| {
                state.cancelled
                    && state.effects_complete()
                    && !state
                        .steps
                        .iter()
                        .rev()
                        .find(|step| step.submitted)
                        .is_some_and(|step| matches!(step.action, Action::Publish { .. }))
                    && state.steps.iter().all(|step| match &step.action {
                        Action::Publish { answer, .. } if step.submitted => matches!(
                            answer,
                            Some(Ok(_)) | Some(Err(wire::ConditionalFailure::Refused(_)))
                        ),
                        _ => true,
                    })
            })
        })
    }

    pub(crate) fn completed(&self) -> bool {
        self.0.with(&(), |s| s.is_none_or(|s| s.completed))
    }

    pub(crate) fn released(&self) {
        self.0
            .with_all(|all| all.entry(()).or_default().completed = true);
    }

    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// A Commit is retained before its intent is emitted, including when it has no local effects.
    pub(crate) fn has_commit(&self) -> bool {
        self.0.with(&(), |s| {
            s.is_some_and(|s| {
                s.steps
                    .iter()
                    .any(|step| matches!(step.action, Action::Publish { .. }))
            })
        })
    }

    pub(crate) fn owed_done(&self, receipt: &crate::push::OwedReceipt) {
        self.0.with_all(|all| {
            for step in &mut all.entry(()).or_default().steps {
                if let Action::Publish { after, .. } = &mut step.action {
                    if after.draft.owed.as_ref() == Some(receipt) {
                        after.owed_done = true;
                    }
                }
            }
        });
    }

    /// Called under the existing delivery Book lock, serialized with notification enqueue.
    pub(crate) fn withdraw_config(&self, key: &str) {
        self.0.with_all(|all| {
            for step in &mut all.entry(()).or_default().steps {
                if let Action::Publish { after, .. } = &mut step.action {
                    if after.row.as_ref().is_some_and(|row| {
                        crate::tasks::task_key(&row.principal, &row.task_id) == key
                    }) {
                        after.config_withdrawn = true;
                    }
                }
            }
        });
    }

    /// Classify only this exact owed entry, never another event on the same task chain.
    pub(crate) fn owed_decision(&self, receipt: &crate::push::OwedReceipt) -> Option<bool> {
        self.0.with(&(), |state| {
            state.map_or(Some(false), |state| state.owed_decision(receipt))
        })
    }

    /// Exact host settlement only; this never calls enter or re-enables canceled publication.
    pub(crate) fn settle(&self, settlement: &wire::Settlement) -> Result<bool, Halt> {
        self.0.with_all(|all| {
            let s = all.entry(()).or_default();
            for step in &mut s.steps {
                if !step.submitted {
                    continue;
                }
                if let Action::Publish {
                    request, answer, ..
                } = &mut step.action
                {
                    if settlement.matches(request).map_err(|_| failed())? {
                        if answer
                            .as_ref()
                            .is_some_and(|known| known != &settlement.result.decision)
                        {
                            return Err(failed());
                        }
                        *answer = Some(settlement.result.decision.clone());
                        s.cancelled = true;
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
    }

    /// Sticky host selection confirms offered ACK consumption on the next different driver input.
    pub(crate) fn ack_confirmed(&self, incoming: Option<&wire::Settlement>) -> bool {
        self.0.with_all(|all| {
            let s = all.entry(()).or_default();
            if !s.effects_complete() {
                return false;
            }
            if !s
                .ack_offered
                .as_ref()
                .is_some_and(|ack| incoming != Some(ack))
            {
                return false;
            }
            s.ack_offered = None;

            s.quarantined = s.steps.iter().any(|step| {
                step.submitted
                    && matches!(
                        &step.action,
                        Action::Publish {
                            answer: None
                                | Some(Err(wire::ConditionalFailure::Indeterminate
                                    | wire::ConditionalFailure::OpIdConflict)),
                            ..
                        }
                    )
            });
            !s.quarantined
        })
    }

    pub(crate) fn offer_ack(&self, settlement: &wire::Settlement) {
        self.0
            .with_all(|all| all.entry(()).or_default().ack_offered = Some(settlement.clone()));
    }

    pub(crate) fn effects_complete(&self) -> bool {
        self.0.with(&(), |state| {
            state.is_none_or(|state| state.effects_complete())
        })
    }

    /// Complete only the batch this caller owns, after every outside-Book obligation returns.

    pub(crate) fn effects_finished(&self, owner: Option<Arc<()>>) {
        let Some(owner) = owner else {
            return;
        };
        let wake = self.0.with_all(|all| {
            let state = all.entry(()).or_default();
            if !state
                .applying
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, &owner))
            {
                return None;
            }
            state.applying = None;
            state.cancelled.then(|| state.wake.0.upgrade()).flatten()
        });
        if let Some(wake) = wake {
            let call = wake.with(&(), |call| call.cloned());
            if let Some(call) = call {
                call();
            }
        }
    }

    pub(crate) fn applied_effects(&self) -> Applied {
        self.0.with_all(|all| {
            let mut effects = Applied::default();
            let s = all.entry(()).or_default();
            if s.applying.is_some() {
                return effects;
            }
            let releasable: Vec<_> = s
                .steps
                .iter()
                .filter_map(|step| match &step.action {
                    Action::Publish { after, .. } => after.draft.owed.as_ref(),
                    _ => None,
                })
                .filter(|receipt| s.cancelled && s.owed_decision(receipt) == Some(false))
                .cloned()
                .collect();
            for step in &mut s.steps {
                let Action::Publish {
                    answer,
                    writes,
                    metadata_taken,
                    after,
                    ..
                } = &mut step.action
                else {
                    continue;
                };
                if matches!(answer, Some(Ok(Decision::Applied))) {
                    if !*metadata_taken {
                        effects.deletes.extend(writes.clone());
                        *metadata_taken = true;
                    }
                    if after.draft.notify && !after.notify_done {
                        if let Some(row) = &after.row {
                            let config = if after.config_withdrawn {
                                Some(Ok(None))
                            } else {
                                after.draft.config.clone()
                            };
                            effects.notify.push((row.clone(), config));
                        }
                        after.notify_done = true;
                    }
                    if !after.backend_done {
                        if let (Some(row), Some(id)) = (&after.row, &after.draft.backend) {
                            effects.backends.push((row.clone(), id.clone()));
                        }
                        after.backend_done = true;
                    }
                    if !after.owed_done {
                        if let Some(receipt) = &after.draft.owed {
                            effects.owed.push(receipt.clone());
                        }
                        after.owed_done = true;
                    }
                } else if !after.owed_done
                    && after
                        .draft
                        .owed
                        .as_ref()
                        .is_some_and(|receipt| releasable.contains(receipt))
                {
                    if let Some(receipt) = &after.draft.owed {
                        effects.release_owed.push(receipt.clone());
                    }
                    after.owed_done = true;
                }
            }
            if !effects.deletes.is_empty()
                || !effects.notify.is_empty()
                || !effects.backends.is_empty()
                || !effects.owed.is_empty()
                || !effects.release_owed.is_empty()
            {
                let owner = Arc::new(());
                s.applying = Some(owner.clone());
                effects.owner = Some(owner);
            }
            effects
        })
    }
}

fn candidate(
    capability: wire::Capability,
    correlation: u64,
    predicates: &[Predicate],
    lives: &[ChainLife],
    writes: &[Write],
) -> Result<Guard<wire::Request>, Halt> {
    let mut guarded_predicates = Guard::new(Vec::new());
    for p in predicates {
        guarded_predicates.push(wire::RecordPredicate {
            kind: kind(p.kind)?,
            key: p.key.as_bytes().to_vec(),
            expected: expected(&p.expected),
        });
    }
    let mut mutations = Guard::new(Vec::new());
    let mut chains = Guard::new(Vec::new());
    for life in lives {
        if life.expected.as_ref().is_some_and(|b| b.len() != 8) {
            return Err(failed());
        }
        if !writes
            .iter()
            .any(|w| w.kind == life.kind && w.key == life.scope)
        {
            chains.push(wire::ChainMutation::Check {
                kind: kind(life.kind)?,
                scope: life.scope.as_bytes().to_vec(),
                life: expected(&life.expected),
            });
        }
    }
    for w in writes {
        let kind = kind(w.kind)?;
        let key = w.key.as_bytes().to_vec();
        if w.kind == KIND_TASK_EVENT {
            let life = lives
                .iter()
                .find(|l| l.kind == w.kind && l.scope == w.key)
                .ok_or_else(failed)?;
            chains.push(if w.value.is_empty() {
                wire::ChainMutation::Drop {
                    kind,
                    scope: key,
                    life: expected(&life.expected),
                }
            } else {
                wire::ChainMutation::Append {
                    kind,
                    scope: key,
                    life: expected(&life.expected),
                    content: w.value.clone(),
                }
            });
        } else {
            mutations.push(if w.value.is_empty() {
                wire::RecordMutation::Delete { kind, key }
            } else {
                wire::RecordMutation::Put {
                    kind,
                    key,
                    value: w.value.clone(),
                }
            });
        }
    }
    Ok(Guard::new(wire::Request {
        capability,
        candidate: wire::ConditionalCandidate {
            correlation,
            predicates: guarded_predicates.take(),
            mutations: mutations.take(),
            chains: chains.take(),
        },
    }))
}

#[cfg(test)]
#[path = "tests/conditional_callback_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/conditional_raw_custody.rs"]
mod raw_custody_tests;

#[cfg(test)]
#[path = "tests/conditional_fixture.rs"]
pub(crate) mod fixture;
