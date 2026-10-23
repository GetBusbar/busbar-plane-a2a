// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR'S TASK IDENTITY ON A RELAYED HOP (ARCHITECT ruling B1, 2026-10-02: the far end's task id
//! rewritten to busbar's routable id is GOVERNED routing identity, the class of the mapped model).
//! Ported from the served engine (`busbar-a2a` `receive` and `relay::rewrite_identity`, `idmap`),
//! byte for byte; pure, so every rule is tested without a door.
//!
//! * A fresh task's id is `a2a-<agent>-<16 hex>` ([`mint`]), its eight bytes from the kernel's
//!   `random.fill`; its `contextId` is the caller's, or the id when the caller named none.
//! * A request naming a task the caller holds, in its `params` or its message, reuses that task's
//!   identity ([`translatable`]).
//! * The far end's answer leaves under busbar's identity ([`rewrite_identity`]); the far end's own
//!   id is read first ([`backend_task_id`]) so a following request naming busbar's id (or referring
//!   to it) is sent on under the far end's ([`translate_request`], a splice of the caller's bytes).
//! * A refused hop that opened or names a task answers with that task as a `ResourceInfo`
//!   ([`about_task`]).

use serde_json::{json, Map, Value};

use crate::a2a::task::TaskState;
use crate::agent_arrival::AgentRefusal;

/// What every task id busbar mints starts with.
pub const TASK_ID_PREFIX: &str = "a2a";

/// How many random bytes a minted id carries.
pub const MINT_BYTES: usize = 8;

/// A FRESH TASK ID for a task relayed to `agent`: `a2a-<agent>-<16 hex>` over `random`.
#[must_use]
pub fn mint(agent: &str, random: [u8; MINT_BYTES]) -> String {
    format!(
        "{TASK_ID_PREFIX}-{agent}-{:016x}",
        u64::from_be_bytes(random)
    )
}

/// The members of a request's `params` that name a task: `id` is `GetTask`/`CancelTask`'s
/// spelling, `taskId` every verb about a task, `task_id` A2A v1.0's.
pub const TASK_ID_MEMBERS: [&str; 3] = ["id", "taskId", "task_id"];

/// The members of `envelope`'s `params` that name a task: [`TASK_ID_MEMBERS`], less `id` on a
/// v1.0 push-config verb, whose `id` is the CONFIG (a2a.proto:716-733: `task_id = 2`, `id = 3`).
fn task_members(envelope: &Value) -> &'static [&'static str] {
    use crate::local::{verb_of, Dialect, LocalVerb};
    match envelope
        .get("method")
        .and_then(Value::as_str)
        .and_then(verb_of)
    {
        Some(
            LocalVerb::CreatePushConfig(Dialect::V10)
            | LocalVerb::GetPushConfig(Dialect::V10)
            | LocalVerb::ListPushConfigs(Dialect::V10)
            | LocalVerb::DeletePushConfig(Dialect::V10),
        ) => &TASK_ID_MEMBERS[1..],
        _ => &TASK_ID_MEMBERS[..],
    }
}

/// The task ids a request names at the top of its `params`, in [`TASK_ID_MEMBERS`] order: the
/// candidates for the task the request addresses.
#[must_use]
pub fn named_tasks(envelope: &Value) -> Vec<&str> {
    let Some(params) = envelope.get("params").and_then(Value::as_object) else {
        return Vec::new();
    };
    task_members(envelope)
        .iter()
        .filter_map(|m| params.get(*m).and_then(Value::as_str))
        .collect()
}

/// The `contextId` the caller's message names; empty when none.
#[must_use]
pub fn context_of(envelope: &Value) -> &str {
    envelope
        .pointer("/params/message/contextId")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The task ids the caller's MESSAGE names (`params.message.taskId`, or `task_id`): how A2A v1.0
/// continues a task (`Message.task_id`, a2a.proto:265-266). A message's own `id` is not a task id.
#[must_use]
pub fn message_tasks(envelope: &Value) -> Vec<&str> {
    let Some(message) = envelope
        .pointer("/params/message")
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    TASK_ID_MEMBERS
        .iter()
        .filter(|m| **m != "id")
        .filter_map(|m| message.get(*m).and_then(Value::as_str))
        .collect()
}

/// Every task id a request ADDRESSES, and so every one [`translate_request`] may translate: the
/// top-level members ([`named_tasks`]), then the message's ([`message_tasks`]).
#[must_use]
pub fn translatable(envelope: &Value) -> Vec<&str> {
    let mut ids = named_tasks(envelope);
    ids.extend(message_tasks(envelope));
    ids
}

/// Every task a request's message REFERS to (`referenceTaskIds`, either spelling): translated with
/// the task ids, never read as the task the request addresses.
#[must_use]
pub fn referenced_tasks(envelope: &Value) -> Vec<&str> {
    let Some(message) = envelope
        .pointer("/params/message")
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    crate::answer_bytes::REFERENCE_MEMBERS
        .iter()
        .filter_map(|m| message.get(*m).and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// TRANSLATE every busbar task id in a request's `params` (and its message's, the tasks its message
/// refers to included) to the far end's, through `backend_of`, which answers only for a task the
/// caller holds. `envelope` is the request's own bytes: only each translated id's string is
/// spliced, every other byte goes on as the caller wrote it (Law 5). `None` when nothing was
/// translated: the caller's bytes then go on UNCHANGED.
#[must_use]
pub fn translate_request(
    envelope: &[u8],
    backend_of: &dyn Fn(&str) -> Option<String>,
) -> Option<Vec<u8>> {
    let reading: Value = serde_json::from_slice(&crate::answer_bytes::readable(envelope)).ok()?;
    crate::answer_bytes::translate_ids(
        envelope,
        task_members(&reading),
        &TASK_ID_MEMBERS[1..],
        backend_of,
    )
}

/// The wrapper members an A2A v1.0 `result` puts its payload under, each with the member that
/// identifies the task inside it.
pub(crate) const WRAPPERS: [(&str, &str); 4] = [
    ("task", "id"),
    ("message", "taskId"),
    ("statusUpdate", "taskId"),
    ("artifactUpdate", "taskId"),
];

/// The `kind` an A2A v0.3 `result` names itself by when it is not wrapped, each with the member
/// that identifies the task in it: a task is its own `id`; a message, a status update and an
/// artifact update name theirs `taskId` (a message's `messageId` is its own).
pub(crate) const KINDS: [(&str, &str); 4] = [
    ("task", "id"),
    ("message", "taskId"),
    ("status-update", "taskId"),
    ("artifact-update", "taskId"),
];

fn wrapper_of(result: &Value) -> Option<(&'static str, &'static str)> {
    WRAPPERS
        .into_iter()
        .find(|(member, _)| result.get(member).is_some_and(Value::is_object))
}

/// The wrapper a `result` puts its payload under (`None`: unwrapped) and the member naming the
/// task in that payload: the wrapper's, else the one its `kind` names, else `id`.
fn identity_of(result: &Value) -> (Option<&'static str>, &'static str) {
    if let Some((wrapper, member)) = wrapper_of(result) {
        return (Some(wrapper), member);
    }
    let kind = result.get("kind").and_then(Value::as_str);
    let member = KINDS
        .into_iter()
        .find(|(k, _)| Some(*k) == kind)
        .map_or("id", |(_, member)| member);
    (None, member)
}

pub(crate) fn payload_of(result: &Value) -> &Value {
    wrapper_of(result)
        .and_then(|(member, _)| result.get(member))
        .unwrap_or(result)
}

/// THE FAR END'S OWN TASK ID, read off a `result` before [`rewrite_identity`] replaces it.
#[must_use]
pub fn backend_task_id(result: &Value) -> Option<String> {
    let (_, id_member) = identity_of(result);
    payload_of(result)
        .get(id_member)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// ONE READING OF A FAR END'S STATE TOKEN, in either A2A vocabulary (`input-required` or
/// `TASK_STATE_INPUT_REQUIRED`); `None` for a token this build does not know.
#[must_use]
pub fn wire_state(token: &str) -> Option<TaskState> {
    if let Ok(state) = TaskState::parse(token) {
        return Some(state);
    }
    TaskState::parse(
        &token
            .strip_prefix("TASK_STATE_")?
            .to_ascii_lowercase()
            .replace('_', "-"),
    )
    .ok()
}

/// The task state a `result` reports; `None` when it reports none this build can read (an artifact
/// update, a message, an unknown token): a reader that guessed a state from nothing would move a
/// task no one moved.
#[must_use]
pub fn reported_task_state(result: &Value) -> Option<TaskState> {
    payload_of(result)
        .pointer("/status/state")
        .and_then(Value::as_str)
        .and_then(wire_state)
}

/// Whether a `result` is a MESSAGE THAT NAMES NO TASK (A2A v1.0 `SendMessageResponse.message`, or
/// v0.3's `kind: "message"`, with no `taskId`): a server message names a task only if one was
/// created (a2a.proto:254-259), so such an answer is the whole interaction.
#[must_use]
pub fn names_no_task(result: &Value) -> bool {
    let message = match wrapper_of(result) {
        Some(("message", _)) => &result["message"],
        Some(_) => return false,
        None if result.get("kind").and_then(Value::as_str) == Some("message") => result,
        None => return false,
    };
    !matches!(message.get("taskId").and_then(Value::as_str), Some(id) if !id.is_empty())
}

/// The metadata key the matched skill rides under: busbar's own, namespaced annotation.
pub const SKILL_METADATA_KEY: &str = "busbar/skill";

/// SUBSTITUTE BUSBAR'S TASK IDENTITY onto a far end's `result`, leaving everything else alone: the
/// payload's own identity member (inside its wrapper, or the one its `kind` names), its
/// `contextId`, the ids a status message and every `history` message nest, the tasks a message
/// refers to that busbar knows (this task's own far-end id, or one of `references`, each the far
/// end's id then busbar's), and the matched skill as `metadata["busbar/skill"]`. `false` when
/// `result` is not an object: no task identity can be laid on it, and the plane cannot read it as
/// an answer about a task.
#[must_use]
pub fn rewrite_identity(
    result: &mut Value,
    task_id: &str,
    context_id: &str,
    matched_skill: Option<&str>,
    references: &[(String, String)],
) -> bool {
    if !result.is_object() {
        return false;
    }
    let (wrapper, id_member) = identity_of(result);
    let message = match wrapper {
        Some(member) => member == "message",
        None => result.get("kind").and_then(Value::as_str) == Some("message"),
    };
    let own = backend_task_id(result);
    let refer = |far: &str| {
        if own.as_deref() == Some(far) {
            return Some(task_id.to_string());
        }
        references
            .iter()
            .find(|(theirs, _)| theirs == far)
            .map(|(_, ours)| ours.clone())
    };
    let payload = match wrapper {
        Some(member) => match result.get_mut(member) {
            Some(inner) => inner,
            None => return true,
        },
        None => result,
    };
    let Some(obj) = payload.as_object_mut() else {
        return true;
    };
    // A standalone message names no task: `taskId` is added only to one that belongs to a task.
    if !message || obj.contains_key("taskId") {
        obj.insert(id_member.to_string(), Value::String(task_id.to_string()));
    }
    obj.insert(
        "contextId".to_string(),
        Value::String(context_id.to_string()),
    );
    refer_to_busbar(obj, &refer);
    if let Some(msg) = obj
        .get_mut("status")
        .and_then(Value::as_object_mut)
        .and_then(|s| s.get_mut("message"))
        .and_then(Value::as_object_mut)
    {
        rewrite_message_identity(msg, task_id, context_id, &refer);
    }
    // A task's history is its messages (a2a.proto:179-180): each that names the far end's task or
    // context names busbar's.
    if let Some(history) = obj.get_mut("history").and_then(Value::as_array_mut) {
        for msg in history.iter_mut().filter_map(Value::as_object_mut) {
            rewrite_message_identity(msg, task_id, context_id, &refer);
        }
    }
    if let Some(skill) = matched_skill {
        let metadata = obj
            .entry("metadata")
            .or_insert_with(|| Value::Object(Map::new()));
        if !metadata.is_object() {
            *metadata = Value::Object(Map::new());
        }
        if let Some(metadata) = metadata.as_object_mut() {
            metadata.insert(
                SKILL_METADATA_KEY.to_string(),
                Value::String(skill.to_string()),
            );
        }
    }
    true
}

/// Every task a message refers to (`referenceTaskIds`, either spelling) that `refer` knows, named
/// by busbar's id.
fn refer_to_busbar(msg: &mut Map<String, Value>, refer: &dyn Fn(&str) -> Option<String>) {
    for member in crate::answer_bytes::REFERENCE_MEMBERS {
        let Some(ids) = msg.get_mut(member).and_then(Value::as_array_mut) else {
            continue;
        };
        for id in ids.iter_mut() {
            if let Some(ours) = id.as_str().and_then(refer) {
                *id = Value::String(ours);
            }
        }
    }
}

/// The task and context ids a message nested in a result names, replaced by busbar's, and the tasks
/// it refers to that `refer` knows; a member the message does not carry is not added.
fn rewrite_message_identity(
    msg: &mut Map<String, Value>,
    task_id: &str,
    context_id: &str,
    refer: &dyn Fn(&str) -> Option<String>,
) {
    if msg.contains_key("taskId") {
        msg.insert("taskId".to_string(), Value::String(task_id.to_string()));
    }
    if msg.contains_key("contextId") {
        msg.insert(
            "contextId".to_string(),
            Value::String(context_id.to_string()),
        );
    }
    refer_to_busbar(msg, refer);
}

/// The ProtoJSON type URL of `google.rpc.ResourceInfo`, which is how the task a refusal is about
/// travels.
pub const RESOURCE_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ResourceInfo";

/// The resource type a task's `ResourceInfo` names.
pub const TASK_RESOURCE_TYPE: &str = "a2a.busbar/task";

/// THE REFUSAL'S ENVELOPE, NAMING THE TASK: its error carries a `ResourceInfo` for `task_id` after
/// its `ErrorInfo` (the engine's `rpcerror::about_task`).
#[must_use]
pub fn about_task(refusal: &AgentRefusal, task_id: &str) -> Value {
    let mut doc = refusal.envelope();
    let entry = json!({
        "@type": RESOURCE_INFO_TYPE,
        "resourceType": TASK_RESOURCE_TYPE,
        "resourceName": task_id,
    });
    match doc["error"]["data"].as_array_mut() {
        Some(data) => data.push(entry),
        None => doc["error"]["data"] = json!([entry]),
    }
    doc
}

/// The HTTP status A2A section 5.4 binds an error `code` to, for the codes the engine re-emits from
/// a far end's error; `None` for a code A2A does not define.
#[must_use]
pub const fn status_of_code(code: i64) -> Option<u32> {
    Some(match code {
        -32001 | -32601 => 404,
        -32002 => 409,
        -32003 | -32004 | -32007 | -32008 | -32009 | -32600 | -32602 | -32700 => 400,
        -32005 => 415,
        -32006 => 502,
        -32603 => 500,
        _ => return None,
    })
}

#[cfg(test)]
#[path = "tests/task_identity_tests.rs"]
mod tests;
