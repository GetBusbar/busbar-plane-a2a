// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `POST /a2a/push`: an agent reporting a task it moved, to the callback busbar registered with it
//! (a public route of the plane, served by its `serve` op, authorised by busbar's own per-task
//! capability, bounded by the push-volume limit).
//!
//! Every step is a refusal that costs nothing further:
//!
//! 1. the presented token names a task this instance minted it for, and the host's signature of
//!    that task is the one presented, or `401`;
//! 2. that task's push-volume budget has room ([`crate::push::PushLimiter`]), or `429` with
//!    `retry-after`;
//! 3. the body is at most [`MAX_PUSH_BODY`], or `413`;
//! 4. the task is held for its caller and still live, or `401` (the same sentence as every other
//!    refusal: whether a task exists or has ended is not told here);
//! 5. the body is JSON, or `400`;
//! 6. the state it reports is recorded on the task's own chain through the one transition table
//!    (a push reporting no state this build can read, or the state already held, is `202` and moves
//!    nothing, queuing no notification; storage or signing failure answers retryable `503`);
//! 7. the caller's own delivery is queued from busbar's own row, never from the pushed body.

use std::task::Poll;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{ServeIn, ServeOut, AUDIT_NONE};
use busbar_contract::abi::sdk::{Instance, Lent, Out, ServiceError};
use serde_json::{json, Value};

use crate::a2a::task::{Task, TaskState};
use crate::plane_door::A2aDoor;
use crate::tasks::{self, Halt, Stamp, Write};

/// The ceiling on a pushed body: one task document.
pub const MAX_PUSH_BODY: usize = 64 * 1024;

/// The one sentence every authorisation refusal answers with.
pub const UNAUTHORISED: &str =
    "this endpoint is addressed by the push token busbar registered with the agent";

/// The sentence a spent push-volume budget answers with.
pub const RATE_LIMITED: &str = "this task's push volume has exceeded its window budget";

const JSON_FIELDS: &[(&str, &str)] = &[("content-type", crate::agent_arrival::JSON_MEDIA_TYPE)];

/// A refusal in the one shape this endpoint speaks: `{"error":{"message":...}}`, not a JSON-RPC
fn refused(
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    status: u32,
    message: &str,
    extra: &[(&str, &str)],
) -> Outcome {
    let body = serde_json::to_vec(&json!({ "error": { "message": message } })).unwrap_or_default();
    let mut fields = JSON_FIELDS.to_vec();
    fields.extend_from_slice(extra);
    out.answer(input, status, &fields, &body, AUDIT_NONE)
}

/// `202`, with no document: the report was taken, the move it recorded written to the task's
fn accepted(input: &Lent<'_, ServeIn>, out: &mut Out<'_, ServeOut>, writes: &[Write]) -> Outcome {
    crate::plane_door::verb_answer(input, out, (202, &[], b""), AUDIT_NONE, writes)
}

/// What a push keeps across its op's PENDING entries: it has already spent its push-volume budget,
/// so a re-entry does not spend it twice.
#[derive(Default)]
struct Admitted {
    observed_at: Option<u64>,
    charge: Option<crate::push::PushCharge>,
    publication: crate::conditional_publication::Journal,
    prepared: Option<Prepared>,
    refusal: Option<(u32, &'static str)>,
}
impl Drop for Admitted {
    fn drop(&mut self) {
        self.publication.owner_dropped();
    }
}
struct Prepared {
    writes: Vec<Write>,
}
const UNAVAILABLE: &str = "the push report could not be checked or recorded; retry this request";

fn cached_refusal(
    instance: &Instance<'_, A2aDoor>,
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    mut state: Admitted,
    status: u32,
    message: &'static str,
) -> Outcome {
    state.refusal = Some((status, message));
    let outcome = refused(input, out, status, message, &[]);
    let short = outcome == Outcome::Failed
        && (out.get().reply_needed > input.reply_buf().cap() as u64
            || out.get().fields_needed as usize > input.fields_buf().cap()
            || out.get().arena_needed > input.arena_buf().cap() as u64);
    if short {
        if let Some(charge) = state.charge.take() {
            charge.refund();
        }
    } else if outcome == Outcome::Ready {
        if let Some(plane) = instance.get() {
            crate::push_door::apply_publication(plane, &state.publication);
            state.publication.finished();
            if state.publication.completed() {
                plane.deliveries.release_publication(&state.publication);
            }
        }
    }
    outcome
}

fn unavailable(
    instance: &Instance<'_, A2aDoor>,
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    state: Admitted,
    stage: &'static str,
) -> Outcome {
    let outcome = cached_refusal(instance, input, out, state, 503, UNAVAILABLE);
    if outcome == Outcome::Ready {
        busbar_contract::diag_warn!(
            crate::diagnostics::A2A_PUSH_CHECK_UNAVAILABLE,
            "a2a: push {stage} unavailable; answered 503 for retry"
        );
    }
    outcome
}

/// The synchronous signer retains the service's Short/failure distinction. A failed signer is
fn signature(
    plane: &A2aDoor,
    ticket: busbar_contract::abi::mechanism::ticket::Ticket,
    task_id: &str,
) -> Result<Vec<u8>, ServiceError> {
    let services = plane.services.as_ref().ok_or(ServiceError::Unserved)?;
    let handle = crate::task_door::handle(ticket, 0);
    let data = crate::push::token_input(task_id);
    let mut bytes = vec![0u8; 1024];
    let mut spans = vec![crate::task_door::ABSENT_SPAN; 2];
    match services.sign(handle, &data, &mut bytes, &mut spans) {
        Ok(signature) => return Ok(signature.signature.to_vec()),
        Err(ServiceError::Short {
            bytes: needed,
            items,
        }) => {
            let size = |n| usize::try_from(n).unwrap_or(usize::MAX);
            bytes.resize(size(needed), 0);
            spans.resize(size(items), crate::task_door::ABSENT_SPAN);
        }
        Err(error) => return Err(error),
    }
    services
        .sign(handle, &data, &mut bytes, &mut spans)
        .map(|s| s.signature.to_vec())
}

fn finish_prepared(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    mut state: Admitted,
) -> Outcome {
    let prepared = state.prepared.take().expect("prepared push answer");
    let outcome = accepted(input, out, &prepared.writes);
    if outcome != Outcome::Ready {
        state.prepared = Some(prepared);
        instance.park(state);
        return outcome;
    }
    crate::push_door::apply_publication(plane, &state.publication);
    state.publication.finished();
    if state.publication.completed() {
        plane.deliveries.release_publication(&state.publication);
    }
    outcome
}

/// THE MOVE A PUSHED `document` ASKS OF A TASK IN `held`: the state it reports, when it reports one
pub(crate) fn push_move(held: TaskState, document: &Value) -> Option<TaskState> {
    crate::task_identity::reported_task_state(document).filter(|reported| *reported != held)
}

/// `serve` of the push route.
pub(crate) fn serve(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: Lent<'_, ServeIn>,
    mut out: Out<'_, ServeOut>,
) -> Outcome {
    let ticket = instance.ticket();
    let mut state = match instance.resume::<Admitted>() {
        Some(state) => *state,
        None if instance.resuming() => return Outcome::Failed,
        None => Admitted::default(),
    };
    let entered = state
        .publication
        .enter(ticket, input.head().extensions().bytes());
    if entered.is_err() {
        crate::push_door::apply_publication(plane, &state.publication);
        instance.park(state);
        return Outcome::Failed;
    }
    plane.deliveries.apply_deletions(&state.publication);
    if let Some(outcome) = state
        .publication
        .pending(&plane.publication_leases, &mut out)
    {
        if outcome != Outcome::Pending {
            crate::push_door::apply_publication(plane, &state.publication);
        }
        instance.park(state);
        return outcome;
    }
    if let Some((status, message)) = state.refusal {
        return cached_refusal(instance, &input, &mut out, state, status, message);
    }
    if state.prepared.is_some() {
        return finish_prepared(plane, instance, &input, &mut out, state);
    }
    let fields = input.fields();
    let authorization = fields
        .iter()
        .find(|f| {
            f.name()
                .as_str()
                .is_ok_and(|n| n.eq_ignore_ascii_case("authorization"))
        })
        .and_then(|f| f.value().as_str().ok())
        .unwrap_or_default();

    let Some((task_id, caller, presented)) = plane.tokens.claim_of_authorization(authorization)
    else {
        return cached_refusal(instance, &input, &mut out, state, 401, UNAUTHORISED);
    };
    let signed = match signature(plane, ticket, &task_id) {
        Ok(signature) => signature,
        Err(_) => return unavailable(instance, &input, &mut out, state, "capability-signature"),
    };
    if !crate::push::verified(&signed, presented) {
        return cached_refusal(instance, &input, &mut out, state, 401, UNAUTHORISED);
    }
    let Some(host) = plane.host.as_ref() else {
        return unavailable(instance, &input, &mut out, state, "host-binding");
    };
    let now = match state.observed_at {
        Some(now) => now,
        None => {
            let reading = match host.connector_from(ticket, 1).clock_now() {
                Poll::Pending => {
                    instance.park(state);
                    return Outcome::Pending;
                }
                Poll::Ready(Err(_)) => {
                    return unavailable(instance, &input, &mut out, state, "clock");
                }
                Poll::Ready(Ok(reading)) => reading,
            };
            let now = reading.wall_ns / 1_000_000_000;
            state.observed_at = Some(now);
            now
        }
    };

    if state.charge.is_none() {
        let Some(charge) = plane.pushes.charge(&task_id, now) else {
            let window = crate::push::PUSH_RATE_WINDOW_SECS.to_string();
            return refused(
                &input,
                &mut out,
                429,
                RATE_LIMITED,
                &[("retry-after", window.as_str())],
            );
        };
        state.charge = Some(charge);
    }

    let body = input.body().bytes();
    if body.len() > MAX_PUSH_BODY {
        return cached_refusal(
            instance,
            &input,
            &mut out,
            state,
            413,
            "a push notification is one task document",
        );
    }
    let mut via = crate::task_door::Via::new(host, plane.services, ticket, 2, &plane.grown)
        .publishing(&state.publication);

    let pend = |state: Admitted, out: &mut Out<'_, ServeOut>| {
        plane.deliveries.retain_publication(&state.publication);
        let outcome = state
            .publication
            .pending(&plane.publication_leases, out)
            .unwrap_or(Outcome::Pending);
        if outcome != Outcome::Pending {
            crate::push_door::apply_publication(plane, &state.publication);
        }
        instance.park(state);
        outcome
    };
    let held = match tasks::get(&mut via, &caller, &task_id, now) {
        Err(Halt::Pending) => return pend(state, &mut out),
        Err(Halt::Failed(_)) => {
            return unavailable(instance, &input, &mut out, state, "task-lookup")
        }
        Ok(None) => return cached_refusal(instance, &input, &mut out, state, 401, UNAUTHORISED),
        Ok(Some(held)) => held,
    };
    let Ok(task) = Task::from_row(&held.row) else {
        return cached_refusal(instance, &input, &mut out, state, 401, UNAUTHORISED);
    };
    if task.state.is_terminal() {
        return cached_refusal(instance, &input, &mut out, state, 401, UNAUTHORISED);
    }

    let Ok(document) = serde_json::from_slice::<crate::request_json::RequestJson>(body) else {
        return cached_refusal(
            instance,
            &input,
            &mut out,
            state,
            400,
            "a push notification is a JSON task document",
        );
    };

    let Some(reported) = push_move(task.state, &document) else {
        let outcome = accepted(&input, &mut out, &[]);
        if outcome == Outcome::Ready {
            state.publication.finished();
        } else {
            instance.park(state);
        }
        return outcome;
    };
    if !task.state.can_transition_to(reported) {
        let outcome = accepted(&input, &mut out, &[]);
        if outcome == Outcome::Ready {
            state.publication.finished();
        } else {
            instance.park(state);
        }
        return outcome;
    }
    let mut writes = Vec::new();
    let at = Stamp {
        caller: &caller,
        request_id: "",
        now,
    };
    let mut plan = |row: &crate::TaskRow| -> tasks::Planned {
        let held = TaskState::parse(&row.state).map_err(|error| error.to_string())?;
        if held == reported || !held.can_transition_to(reported) {
            return Ok(None);
        }
        crate::a2a::task::plan_transition(reported, now)(row).map(Some)
    };
    via.effects(crate::conditional_publication::Draft {
        notify: true,
        ..Default::default()
    });
    match tasks::change(&mut via, &at, &task_id, &mut plan, &mut writes) {
        Err(Halt::Pending) => return pend(state, &mut out),

        Err(Halt::Failed(_)) => {
            return unavailable(instance, &input, &mut out, state, "task-transition");
        }
        Ok(None) => {
            let outcome = accepted(&input, &mut out, &[]);
            if outcome == Outcome::Ready {
                state.publication.finished();
                if state.publication.completed() {
                    plane.deliveries.release_publication(&state.publication);
                }
            } else {
                instance.park(state);
            }
            return outcome;
        }
        Ok(Some(_)) => {}
    };
    state.prepared = Some(Prepared { writes });
    finish_prepared(plane, instance, &input, &mut out, state)
}
