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
//!    nothing, queuing no notification; a move that cannot be recorded is still `202`);
//! 7. the caller's own delivery is queued from busbar's own row, never from the pushed body.

use std::task::Poll;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{ServeIn, ServeOut, AUDIT_NONE};
use busbar_contract::abi::sdk::{Instance, Lent, Out};
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
/// envelope (the caller is an HTTP webhook client).
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
/// chain with the answer.
fn accepted(input: &Lent<'_, ServeIn>, out: &mut Out<'_, ServeOut>, writes: &[Write]) -> Outcome {
    crate::plane_door::verb_answer(input, out, (202, &[], b""), AUDIT_NONE, writes)
}

/// What a push keeps across its op's PENDING entries: it has already spent its push-volume budget,
/// so a re-entry does not spend it twice.
struct Admitted;

/// The host's signature of `task_id`'s token input, on handle `seq` of the op's ticket.
fn signature(
    plane: &A2aDoor,
    ticket: busbar_contract::abi::mechanism::ticket::Ticket,
    seq: u32,
    task_id: &str,
) -> Option<Vec<u8>> {
    let mut signer = crate::task_door::HostSigner {
        services: plane.services.as_ref(),
        ticket,
        seq,
    };
    signer
        .signed(&crate::push::token_input(task_id))
        .map(|(_, sig)| sig)
}

/// THE MOVE A PUSHED `document` ASKS OF A TASK IN `held`: the state it reports, when it reports one
/// this build can read and the task is not already in it. `None` is no move: an artifact update or
/// a message reports no state, and a retried push re-reports the one already recorded.
pub(crate) fn push_move(held: TaskState, document: &Value) -> Option<TaskState> {
    crate::task_identity::reported_task_state(document).filter(|reported| *reported != held)
}

/// Where the route stops short of recording a move: PENDING, a refusal, or `202` with nothing
/// recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// A records call pends: the op runs again.
    Pending,
    /// Refused with this status and sentence.
    Refused(u32, &'static str),
    /// Taken, nothing recorded.
    Accepted,
}

/// Step 1, the capability's signature: the host's `signature` of the claimed task is the one
/// `presented`, or the route stops.
pub(crate) fn verified_or_stop(signature: Option<&[u8]>, presented: &str) -> Result<(), Stop> {
    match signature {
        Some(sig) if crate::push::verified(sig, presented) => Ok(()),
        Some(_) | None => Err(Stop::Refused(401, UNAUTHORISED)),
    }
}

/// Step 4, the task read: the task held for its caller, or the route stops.
pub(crate) fn held_or_stop<T>(read: Result<Option<T>, Halt>) -> Result<T, Stop> {
    match read {
        Err(Halt::Pending) => Err(Stop::Pending),
        Err(Halt::Failed(_)) | Ok(None) => Err(Stop::Refused(401, UNAUTHORISED)),
        Ok(Some(held)) => Ok(held),
    }
}

/// Step 6, the move through the transition table (an illegal move already answered `202` before
/// it): the moved row, or the route stops.
pub(crate) fn moved_or_stop<T>(moved: Result<Option<T>, Halt>) -> Result<T, Stop> {
    match moved {
        Err(Halt::Pending) => Err(Stop::Pending),
        Err(Halt::Failed(_)) | Ok(None) => Err(Stop::Accepted),
        Ok(Some(row)) => Ok(row),
    }
}

/// Step 7, the caller's own delivery queued: on, or the route stops.
pub(crate) fn queued_or_stop(queued: Result<bool, Halt>) -> Result<(), Stop> {
    match queued {
        Err(Halt::Pending) => Err(Stop::Pending),
        Err(Halt::Failed(_)) | Ok(_) => Ok(()),
    }
}

/// `serve` of the push route.
pub(crate) fn serve(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: Lent<'_, ServeIn>,
    mut out: Out<'_, ServeOut>,
) -> Outcome {
    let ticket = instance.ticket();
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
    // 1. THE CAPABILITY: a token this instance minted, signed again by the host and compared in
    //    constant time.
    let Some((task_id, caller, presented)) = plane.tokens.claim_of_authorization(authorization)
    else {
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    };
    let stop = |input: &Lent<'_, ServeIn>, out: &mut Out<'_, ServeOut>, stop: Stop| match stop {
        Stop::Pending => {
            instance.park(Admitted);
            Outcome::Pending
        }
        Stop::Refused(status, sentence) => refused(input, out, status, sentence, &[]),
        Stop::Accepted => accepted(input, out, &[]),
    };
    let signed = signature(plane, ticket, 0, &task_id);
    if let Err(s) = verified_or_stop(signed.as_deref(), presented) {
        return stop(&input, &mut out, s);
    }
    let Some(host) = plane.host.as_ref() else {
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    };
    let Poll::Ready(Ok(reading)) = host.connector_from(ticket, 1).clock_now() else {
        return Outcome::Failed;
    };
    let now = reading.wall_ns / 1_000_000_000;
    // 2. THE VOLUME BOUND, before any of the cost it bounds; spent once across re-entries.
    let resumed = instance.resume::<Admitted>().is_some();
    if !resumed && !plane.pushes.admit(&task_id, now) {
        let window = crate::push::PUSH_RATE_WINDOW_SECS.to_string();
        return refused(
            &input,
            &mut out,
            429,
            RATE_LIMITED,
            &[("retry-after", window.as_str())],
        );
    }
    // 3. THE BODY'S CEILING.
    let body = input.body().bytes();
    if body.len() > MAX_PUSH_BODY {
        return refused(
            &input,
            &mut out,
            413,
            "a push notification is one task document",
            &[],
        );
    }
    let mut via = crate::task_door::Via::new(host, plane.services, ticket, 2, &plane.grown);
    // 4. THE TASK, held and live.
    let held = match held_or_stop(tasks::get(&mut via, &caller, &task_id, now)) {
        Err(s) => return stop(&input, &mut out, s),
        Ok(held) => held,
    };
    let Ok(task) = Task::from_row(&held.row) else {
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    };
    if task.state.is_terminal() {
        plane.tokens.forget(&task_id);
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    }
    // 5. A JSON DOCUMENT.
    let Ok(document) = serde_json::from_slice::<Value>(body) else {
        return refused(
            &input,
            &mut out,
            400,
            "a push notification is a JSON task document",
            &[],
        );
    };
    // 6. THE MOVE, through the one transition table, read by the one reader of a task's state. A
    //    push that reports no state, or the state the task holds, moves nothing: `202`, nothing
    //    recorded and no notification queued.
    let Some(reported) = push_move(task.state, &document) else {
        return accepted(&input, &mut out, &[]);
    };
    // A move the table forbids (a push about a state the task cannot reach from where it is) is
    // the agent being redundant: `202` stops its retry loop, nothing recorded.
    if crate::a2a::task::plan_transition(reported, now)(&held.row).is_err() {
        return accepted(&input, &mut out, &[]);
    }
    let mut writes = Vec::new();
    let at = Stamp {
        caller: &caller,
        request_id: "",
        now,
    };
    let moved = match moved_or_stop(tasks::transition(
        &mut via,
        &at,
        &task_id,
        reported,
        &mut writes,
    )) {
        Err(s) => return stop(&input, &mut out, s),
        Ok(row) => row,
    };
    // 7. THE CALLER'S OWN DELIVERY, from busbar's row.
    if let Err(s) = queued_or_stop(crate::push_door::queue_moved(
        &plane.deliveries,
        &mut via,
        &caller,
        &moved,
    )) {
        return stop(&input, &mut out, s);
    }
    // The ending spends the token, once the answer is final: forgotten before a PENDING entry,
    // the re-entry would find no token and refuse the very report that ended the task.
    if reported.is_terminal() {
        plane.tokens.forget(&task_id);
    }
    accepted(&input, &mut out, &writes)
}
