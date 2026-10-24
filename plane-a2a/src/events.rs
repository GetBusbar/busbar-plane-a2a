// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE EVENT OFF A RELAYED EVENT STREAM, as busbar reads it (the served engine's `read_event`,
//! `frame_sse`, its HTTP+JSON frame reader and its HTTP+JSON line's event re-framer, in their words
//! and their bytes). Pure: the relay feeds it frames ([`crate::sse::SseReader`]) and the door writes
//! what it answers.
//!
//! * A frame that is not JSON, or that carries neither `result` nor a non-null `error`, passes
//!   through UNCHANGED: an event stream carries comments and keep-alives, and busbar is
//!   content-blind.
//! * A frame that IS a JSON-RPC response is CORRELATED to the caller's request id and answered
//!   under it; one that names a different request is an error, and the hop is refused, as it is
//!   for a `result` that is no object (no event about a task is a string or a number).
//! * An `error` frame is relayed as it stands under the caller's id: mid-stream, the status is
//!   already spent and the far end's error is content the caller is owed.
//! * A `result` frame leaves as the far end's own bytes under busbar's task identity
//!   ([`crate::answer_bytes::rewrite_identity`]); the state it reports, whether it carried an
//!   artifact and the far end's own task id are read off it first, through the v1.0 wrappers as
//!   well as the v0.3 bare shape (its `kind` naming the member that names the task).

use busbar_contract::jsonrpc::{read_response, Reply};
use serde_json::Value;

use crate::a2a::task::TaskState;
use crate::relay::HopRefusal;
use crate::sse::sse_data;
use crate::task_identity;

/// The media type of an event stream: what a relayed stream's answer is.
pub const EVENTS_MEDIA_TYPE: &str = "text/event-stream";

/// What a hop that may answer with events accepts: an event stream, or one document.
pub const ACCEPT_EVENTS: &str = "text/event-stream, application/json";

/// ONE EVENT, read: its bytes for the caller (identity substituted), and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The event, framed for the caller.
    pub sse: Vec<u8>,
    /// The task state it reported, if it reported one this build can read.
    pub state: Option<TaskState>,
    /// It carried an artifact chunk: the resume cursor advances.
    pub artifact: bool,
    /// The far end's own task id, before the substitution.
    pub backend_task_id: Option<String>,
    /// It was a message naming no task ([`task_identity::names_no_task`]).
    pub names_no_task: bool,
}

/// One JSON value as a complete event.
fn json_event(value: &Value) -> Vec<u8> {
    format!("data: {value}\n\n").into_bytes()
}

/// `payload` as one complete event: each of its lines a `data:` line of its own, as the
/// event-stream format joins them back (a far end's JSON may break its lines between tokens).
fn data_event(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    for line in payload.split(|b| *b == b'\n') {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}

/// READ ONE FAR-END EVENT `frame_text` and frame it for the caller of request `rpc_id`, under
/// busbar's `task_id`, `context_id` and the matched `skill`; a task the event refers to by one of
/// the far end's ids in `references` (each the far end's id, then busbar's) is named by busbar's.
///
/// # Errors
/// The hop's refusal: the frame answers a different request ([`HopRefusal::Uncorrelated`]), or
/// its `result` is no object the plane can read as an event about a task
/// ([`HopRefusal::NotJson`]).
pub fn read_event(
    frame_text: &str,
    rpc_id: &Value,
    task_id: &str,
    context_id: &str,
    skill: Option<&str>,
    references: &[(String, String)],
) -> Result<Event, HopRefusal> {
    let verbatim = || {
        Ok(Event {
            sse: frame_text.as_bytes().to_vec(),
            state: None,
            artifact: false,
            backend_task_id: None,
            names_no_task: false,
        })
    };
    let Some(data) = sse_data(frame_text) else {
        return verbatim();
    };
    let Ok(mut envelope) =
        serde_json::from_slice::<Value>(&crate::answer_bytes::readable(data.as_bytes()))
    else {
        return verbatim();
    };
    let is_response = envelope.get("result").is_some()
        || envelope.get("error").filter(|e| !e.is_null()).is_some();
    if !is_response {
        return verbatim();
    }
    let reply = read_response(&envelope, rpc_id).map_err(|_| HopRefusal::Uncorrelated)?;
    if let Some(obj) = envelope.as_object_mut() {
        obj.insert("id".to_string(), rpc_id.clone());
    }
    let Reply::Result(_) = reply else {
        return Ok(Event {
            sse: json_event(&envelope),
            state: None,
            artifact: false,
            backend_task_id: None,
            names_no_task: false,
        });
    };
    let Some(result) = envelope.get_mut("result") else {
        return verbatim();
    };
    if !result.is_object() {
        return Err(HopRefusal::NotJson);
    }
    let payload = task_identity::payload_of(result);
    let artifact = payload.get("artifact").is_some()
        || payload.get("artifacts").is_some()
        || result.get("artifactUpdate").is_some();
    let state = task_identity::reported_task_state(result);
    let backend_task_id = task_identity::backend_task_id(result);
    let names_no_task = task_identity::names_no_task(result);
    // The far end's own `result` bytes with busbar's identity spliced in (Law 5; Q128 a2a M8).
    let spliced = crate::answer_bytes::result_span(data.as_bytes()).and_then(|r| {
        crate::answer_bytes::rewrite_identity(
            &data.as_bytes()[r],
            (&task_identity::WRAPPERS, &task_identity::KINDS),
            task_id,
            context_id,
            skill.map(|s| (task_identity::SKILL_METADATA_KEY, s)),
            references,
        )
    });
    let sse = match spliced {
        Some(bytes) => data_event(&crate::answer_bytes::result_reply(rpc_id, &bytes)),
        None => {
            if !task_identity::rewrite_identity(result, task_id, context_id, skill, references) {
                return Err(HopRefusal::NotJson);
            }
            json_event(&envelope)
        }
    };
    Ok(Event {
        sse,
        state,
        artifact,
        backend_task_id,
        names_no_task,
    })
}

/// AN HTTP+JSON FAR END'S FRAME, wrapped back into the one dialect: its `data:` payload is the
/// bare event, so it becomes `result` under `rpc_id`, the far end's own bytes
/// ([`crate::answer_bytes::rewrap`]); a frame with no JSON payload passes as it is.
#[must_use]
pub fn rewrap(frame_text: String, rpc_id: &Value) -> String {
    let wrapped = sse_data(&frame_text)
        .filter(|d| !d.trim().is_empty())
        .and_then(|d| crate::answer_bytes::rewrap(d.as_bytes(), rpc_id).ok());
    match wrapped {
        Some(envelope) => String::from_utf8(data_event(&envelope)).unwrap_or(frame_text),
        None => frame_text,
    }
}

/// THE HTTP+JSON LINE'S EVENTS: every event of `buf` whose data is a JSON-RPC `result` becomes the
/// bare result, the result's own bytes ([`crate::answer_bytes::result_span`]); everything else (an
/// `error` frame, a keep-alive, a comment) passes byte for byte, each line's own terminator kept.
#[must_use]
pub fn reframe_events(buf: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(buf) else {
        return buf.to_vec();
    };
    let mut out = Vec::with_capacity(buf.len());
    let mut event: Vec<&str> = Vec::new();
    for line in text.split_inclusive('\n') {
        event.push(line);
        if line.trim_end_matches(['\r', '\n']).is_empty() {
            reframe_event(&event, &mut out);
            event.clear();
        }
    }
    reframe_event(&event, &mut out);
    out
}

/// The value of a `data` field line, or `None` for another line.
fn data_field(line: &str) -> Option<&str> {
    let field = line.trim_end_matches(['\r', '\n']);
    match field.strip_prefix("data:") {
        Some(value) => Some(value.strip_prefix(' ').unwrap_or(value)),
        None => (field == "data").then_some(""),
    }
}

/// One event's `lines` (each with its terminator) onto `out`: its data lines replaced, where they
/// join to a JSON-RPC `result`, by that result's own bytes, one `data:` line per line of it.
fn reframe_event(lines: &[&str], out: &mut Vec<u8>) {
    let data: Vec<&str> = lines.iter().copied().filter_map(data_field).collect();
    let joined = data.join("\n");
    let result = if data.is_empty() {
        None
    } else {
        crate::answer_bytes::result_span(joined.as_bytes()).map(|span| &joined[span])
    };
    let Some(result) = result else {
        for line in lines {
            out.extend_from_slice(line.as_bytes());
        }
        return;
    };
    let mut written = false;
    for &line in lines {
        if data_field(line).is_none() {
            out.extend_from_slice(line.as_bytes());
            continue;
        }
        if written {
            continue;
        }
        written = true;
        let field = line.trim_end_matches(['\r', '\n']);
        let end = &line[field.len()..];
        let between = if end.is_empty() { "\n" } else { end };
        let mut pieces = result.split('\n').peekable();
        while let Some(piece) = pieces.next() {
            out.extend_from_slice(b"data: ");
            out.extend_from_slice(piece.as_bytes());
            let tail = if pieces.peek().is_some() {
                between
            } else {
                end
            };
            out.extend_from_slice(tail.as_bytes());
        }
    }
}

#[cfg(test)]
#[path = "tests/events_tests.rs"]
mod tests;
