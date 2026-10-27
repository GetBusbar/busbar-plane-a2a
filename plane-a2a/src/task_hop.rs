// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TASK A RELAYED HOP IS FOR (ARCHITECT ruling B1): opened at the unit's first ATTEMPT over the
//! task store's host records, and settled on the far end's answer. Ported from the served engine's
//! unary hop (`busbar-a2a` `receive`: `addressed_task`, `resumable_task`, the mint, the submit and
//! `record_dispatch`, `record_state`, `end_task`), in its order and with its answers.
//!
//! * ADDRESSED: the request's `params`, or its message's `taskId` (a second turn), name a task the
//!   caller holds ([`task_identity::translatable`]): the hop reuses its identity and opens nothing.
//! * UNNAMED: a task verb (`GetTask`, `CancelTask` or `SubscribeToTask`, either spelling) is always
//!   ADDRESSED to a task, and one whose `params` name none as a string is refused `400`, invalid
//!   params (`-32602`, the gRPC line's `INVALID_ARGUMENT`) before anything is read or opened: a task
//!   verb never opens a task.
//! * NOT HELD: a request ADDRESSED to a task (a task verb, or a message whose `taskId` names one)
//!   that the caller does not hold is refused `404`,
//!   A2A's `TaskNotFoundError` (`-32001`) in the local verbs' words ([`local::NO_SUCH_TASK`]):
//!   nothing is opened and nothing is relayed. Another caller's task, a retired one and one that
//!   never was read alike, so the refusal is no existence oracle.
//! * HELD AS TERMINAL: a `CancelTask` of a task the caller holds as terminal is refused `409`, A2A's
//!   `TaskNotCancelableError` (`-32002`, [`TASK_NOT_CANCELABLE`]): busbar's own row answers it, as
//!   a subscribe to a terminal task is answered, and nothing is relayed.
//! * RESUMED: the caller's message names a `contextId` under which one of its tasks on this agent
//!   is interrupted: the newest moves back to `working` (refused `409` when it cannot).
//! * FRESH: busbar mints the id from eight random bytes ([`task_identity::mint`]), the `contextId` is the
//!   caller's or the id, and the task is submitted and dispatched to the agent before the hop
//!   (refused `503` when it cannot be recorded). The submit carries the task store's RETENTION
//!   SWEEP ([`tasks::retention_sweep`], at most [`tasks::SWEEP_BUDGET`] settled tasks retired in
//!   its own writes): the sweep runs from a submit, never from a read or a timer, and one that
//!   fails retires nothing and fails no submit.
//!
//! Task ids the caller holds and whose far-end id busbar learnt are sent on as the far end's
//! ([`task_identity::translate_request`]). On the answer, the reported state is recorded (nothing for
//! `submitted`), and a failed hop ends a task it opened as `failed`.
//!
//! A push callback the request carries INLINE (its `configuration`, in any of the three spellings
//! [`CALLBACK_CONFIG_POINTERS`] names) is judged before anything is opened, by the same floor the
//! push-config verbs use ([`local::judge_callback`]), and a callback or a credential busbar cannot
//! honour refuses the request `400` in the engine's words. One that passes is the task's
//! `push_callback`, on the row it opens or resumes (in that change's own claimed write); on a task
//! it addresses it is the task's push config, put as the push-config verbs put one, the later set
//! winning. Its credential rides back to the door ([`Callback`]), which holds it in plane memory as
//! the engine's delivery does.

use std::collections::BTreeMap;

use busbar_contract::abi::sdk::publish::Keyed;
use serde_json::Value;

use crate::a2a::task::{plan_transition, Direction, Task, TaskState};
use crate::agent_arrival::{AgentRefusal, JSON_MEDIA_TYPE};
use crate::local::{self, Reach};
use crate::push::DeliveryAuth;
use crate::records::KIND_PUSH_CONFIG;
use crate::relay::{RelayReply, TaskHop, TaskSettled};
use crate::skill::CALLBACK_CONFIG_POINTERS;
use crate::task_identity::{self, MINT_BYTES};
use crate::tasks::{self, Halt, Planned, Records, Stamp, Write};
use crate::TaskRow;

use crate::agent_arrival::{
    CODE_INTERNAL, CODE_INVALID_PARAMS, CODE_TASK_NOT_CANCELABLE, CODE_TASK_NOT_FOUND,
};
/// The status a callback busbar cannot honour, or a task verb naming no task, answers with: the
/// caller's fault.
const STATUS_BAD_REQUEST: u32 = 400;
/// The plane's words for a task verb whose `params` name no task id as a string.
pub const TASK_UNNAMED: &str = "a task verb must name its task: `params.id` is required, a string";
/// The status a task that cannot be recorded answers with.
const STATUS_UNAVAILABLE: u32 = 503;
/// The status a task the caller does not hold answers with (A2A section 5.4, `TaskNotFoundError`).
const STATUS_NOT_FOUND: u32 = 404;
/// The status an interrupted task that cannot resume answers with.
const STATUS_CONFLICT: u32 = 409;
/// The engine's words for a task it could not record (`busbar-a2a` `receive.rs:2032-2049`).
pub const TASK_UNRECORDED: &str = "the task could not be recorded";
/// The plane's words for a cancel of a task it holds as terminal (in the style of the subscribe
/// refusal, `local::subscribe_refusal`).
pub const TASK_NOT_CANCELABLE: &str =
    "this task has reached a terminal state, so it cannot be canceled";
/// The engine's words for an interrupted task it could not move back to `working`
/// (`busbar-a2a` `receive.rs:1985-2001`).
pub const TASK_UNRESUMED: &str = "this task cannot be resumed";

/// The host's reach opening a task needs beyond the records and the destination judge: the
/// kernel's random bytes.
pub trait Mint: Reach {
    /// `random.fill` into `buf`.
    ///
    /// # Errors
    /// [`Halt`].
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt>;
}

/// One relayed request, as its first ATTEMPT sees it.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The caller's JSON-RPC envelope.
    pub envelope: &'a Value,
    /// The envelope a request-stage rewrite left, when one did: the request relayed (its task ids
    /// translated over it). The task is opened from [`Request::envelope`].
    pub relayed: Option<&'a Value>,
    /// The bytes the hop relays, when the hop kept them (a request naming a task, or one a
    /// request-stage rewrite or a minted message id rewrote): its task ids are translated in place
    /// in these (Law 5), every other byte as the caller wrote it.
    pub relayed_bytes: Option<&'a [u8]>,
    /// The caller's reference: the task store's key prefix.
    pub caller: &'a str,
    /// The agent the kernel picked.
    pub member: &'a str,
    /// The agent the caller ADDRESSED, a fresh task's id is minted for (predev `receive.rs`:
    /// `a2a-{admitted agent}-…`, the agent admitted, not the pool member the walk placed it on);
    /// `None` = the member.
    pub addressed: Option<&'a str>,
    /// Now, in seconds.
    pub now: u64,
}

/// THE PUSH CALLBACK a request carried inline, as it passed the floor: the URL now on the task's
/// row, and the credential the caller asked busbar to present there (none clears one held).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    /// The URL, as registered.
    pub url: String,
    /// The credential, if the config named one.
    pub auth: Option<DeliveryAuth>,
}

/// What opening answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// The hop goes ahead for this task, sending `instead` in place of the caller's bytes when a
    /// task id was translated.
    Hop {
        /// The task, boxed: the hop's answer is the larger arm by far.
        task: Box<TaskHop>,
        /// The translated request, if any id was.
        instead: Option<Vec<u8>>,
        /// The push callback the request carried inline, registered on the task.
        callback: Option<Callback>,
        /// THE CALLER'S ANSWER IF THE STORE REFUSES THE OPENING'S RECORD WRITES (the kernel ends the
        /// unit `durability_unavailable` and the door's `refusal` renders it): the engine's answer
        /// for the write it made before the hop. A fresh task: `503`, `-32603`
        /// ([`TASK_UNRECORDED`]); a resumed one: `409`, `-32002` ([`TASK_UNRESUMED`]). `None` for an
        /// addressed task, whose hop the engine sent whether or not its callback was recorded
        /// (`busbar-a2a` `receive.rs:2080-2096`).
        unrecorded: Option<AgentRefusal>,
    },
    /// The hop does not go ahead: the caller's whole answer.
    Refused(RelayReply),
}

/// The refusal an opening gives, echoing `rpc_id`.
fn refusal(status: u32, rpc_id: &Value, code: i64, message: &str) -> AgentRefusal {
    AgentRefusal {
        status,
        id: Some(rpc_id.clone()),
        code,
        message: message.to_string(),
    }
}

/// The answer a refused opening gives, in the engine's `rpcerror::body` words.
fn refused(status: u32, rpc_id: &Value, code: i64, message: &str) -> Opened {
    let answer = refusal(status, rpc_id, code, message);
    Opened::Refused(RelayReply {
        status,
        content_type: JSON_MEDIA_TYPE,
        body: serde_json::to_vec(&answer.envelope()).unwrap_or_default(),
    })
}

/// A read that failed reads as nothing (the engine's scoped reads collapse an error to absent); a
/// pending one pends.
fn or_absent<T>(read: Result<T, Halt>, absent: T) -> Result<T, Halt> {
    match read {
        Err(Halt::Pending) => Err(Halt::Pending),
        Err(Halt::Failed(_)) => Ok(absent),
        Ok(v) => Ok(v),
    }
}

/// The newest of the caller's tasks under `context_id` on `member` that is interrupted.
fn resumable(rows: Vec<TaskRow>, context_id: &str, member: &str) -> Option<TaskRow> {
    let mut candidates: Vec<TaskRow> = rows
        .into_iter()
        .filter(|r| {
            r.context_id == context_id
                && r.agent_id == member
                && TaskState::parse(&r.state).is_ok_and(TaskState::is_interrupted)
        })
        .collect();
    candidates.sort_by_key(|r| r.updated_at);
    candidates.pop()
}

/// THE MEMBER HOLDING THE TASK a request to a failover pool is about (predev `receive.rs:1858-1868`
/// and `route.rs` `select_member`), read off the caller's task records: the `agent_id` of the task
/// the request names (in its `params` or its message) and the caller holds, else of the newest of the caller's interrupted tasks
/// under the `contextId` it names held by ANY of the pool's `members` (it resumes AT that member).
/// `None` = the request is a fresh submission, which the pool's walk places. A read that failed
/// reads as nothing, as [`open`]'s lookups read it.
///
/// # Errors
/// [`Halt::Pending`] when a host call pends: the piece runs again from the top.
pub fn holder(
    reach: &mut dyn Records,
    envelope: &Value,
    caller: &str,
    now: u64,
    members: &[String],
) -> Result<Option<String>, Halt> {
    for named in task_identity::translatable(envelope) {
        if let Some(held) = or_absent(tasks::get(reach, caller, named, now), None)? {
            return Ok(Some(held.row.agent_id));
        }
    }
    let context = task_identity::context_of(envelope);
    if context.is_empty() {
        return Ok(None);
    }
    let mut candidates: Vec<TaskRow> = or_absent(tasks::list(reach, caller, now), Vec::new())?
        .into_iter()
        .filter(|r| {
            r.context_id == context
                && members.contains(&r.agent_id)
                && TaskState::parse(&r.state).is_ok_and(TaskState::is_interrupted)
        })
        .collect();
    candidates.sort_by_key(|r| r.updated_at);
    Ok(candidates.pop().map(|r| r.agent_id))
}

/// OPEN the task request `req` is for; its record writes go to `out`. `backends` answers the far
/// end's id busbar learnt for one of the caller's task ids.
///
/// # Errors
/// [`Halt::Pending`] when a host call pends: the piece runs again from the top.
pub fn open(
    reach: &mut dyn Mint,
    req: &Request<'_>,
    rpc_id: &Value,
    backends: &dyn Fn(&str) -> Option<String>,
    out: &mut Vec<Write>,
) -> Result<Opened, Halt> {
    if is_task_verb(req.envelope) && task_identity::named_tasks(req.envelope).is_empty() {
        return Ok(refused(
            STATUS_BAD_REQUEST,
            rpc_id,
            CODE_INVALID_PARAMS,
            TASK_UNNAMED,
        ));
    }
    let callback = match inline_callback(reach, req.envelope)? {
        Ok(callback) => callback,
        Err(message) => {
            return Ok(refused(
                STATUS_BAD_REQUEST,
                rpc_id,
                CODE_INVALID_PARAMS,
                &message,
            ))
        }
    };
    let url = callback.as_ref().map(|c| c.url.as_str());
    // The version the callback is registered under: the one the request's method is spelled in.
    let version = local::Dialect::of_method(
        req.envelope
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .version();
    let mut addressed = None;
    for named in task_identity::translatable(req.envelope) {
        if let Some(held) = or_absent(tasks::get(reach, req.caller, named, req.now), None)? {
            addressed = Some(held.row);
            break;
        }
    }
    if addressed.is_none() && addresses_a_task(req.envelope) {
        return Ok(refused(
            STATUS_NOT_FOUND,
            rpc_id,
            CODE_TASK_NOT_FOUND,
            local::NO_SUCH_TASK,
        ));
    }
    let context = task_identity::context_of(req.envelope);
    let resumed = match (&addressed, context.is_empty()) {
        (None, false) => resumable(
            or_absent(tasks::list(reach, req.caller, req.now), Vec::new())?,
            context,
            req.member,
        ),
        _ => None,
    };
    let (task, unrecorded) = match (addressed, resumed) {
        (Some(row), _)
            if is_cancel(req.envelope)
                && TaskState::parse(&row.state).is_ok_and(TaskState::is_terminal) =>
        {
            return Ok(refused(
                STATUS_CONFLICT,
                rpc_id,
                CODE_TASK_NOT_CANCELABLE,
                TASK_NOT_CANCELABLE,
            ));
        }
        (Some(row), _) => {
            // An addressed task's callback is a PUSH-CONFIG SET, replace semantics, last writer
            // wins: a put of the task's push_config record, never a write of its row, so no other
            // writer's move of the task is undone.
            if let Some(callback) = callback.as_ref() {
                let stored = local::PushConfig {
                    id: inline_config(req.envelope)
                        .and_then(|c| c.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    url: callback.url.clone(),
                    authentication: callback.auth.clone(),
                    version: version.to_string(),
                };
                // A callback that cannot be registered leaves the task as it was: the hop goes on.
                if let Ok(value) = serde_json::to_vec(&stored) {
                    out.push(Write {
                        kind: KIND_PUSH_CONFIG,
                        key: tasks::task_key(req.caller, &row.task_id),
                        value,
                    });
                }
            }
            let task = TaskHop {
                task_id: row.task_id,
                context_id: row.context_id,
                addressed: true,
                skill: None,
                references: Vec::new(),
            };
            (task, None)
        }
        (None, Some(row)) => {
            let at = Stamp {
                caller: req.caller,
                request_id: &row.task_id,
                now: req.now,
            };
            let mut plan = |held: &TaskRow| -> Planned {
                plan_transition(TaskState::Working, at.now)(held).map(|(mut next, kind)| {
                    if let Some(url) = url {
                        next.push_callback = url.to_string();
                        next.push_version = version.to_string();
                    }
                    Some((next, kind))
                })
            };
            match tasks::change(reach, &at, &row.task_id, &mut plan, out) {
                Err(Halt::Pending) => return Err(Halt::Pending),
                Err(Halt::Failed(_)) => {
                    return Ok(refused(
                        STATUS_CONFLICT,
                        rpc_id,
                        CODE_TASK_NOT_CANCELABLE,
                        TASK_UNRESUMED,
                    ))
                }
                Ok(_) => {}
            }
            let task = TaskHop {
                task_id: row.task_id,
                context_id: row.context_id,
                addressed: false,
                skill: None,
                references: Vec::new(),
            };
            let unresumed = refusal(
                STATUS_CONFLICT,
                rpc_id,
                CODE_TASK_NOT_CANCELABLE,
                TASK_UNRESUMED,
            );
            (task, Some(unresumed))
        }
        (None, None) => {
            let mut random = [0u8; MINT_BYTES];
            reach.random(&mut random)?;
            let task_id = task_identity::mint(req.addressed.unwrap_or(req.member), random);
            let context_id = if context.is_empty() {
                task_id.clone()
            } else {
                context.to_string()
            };
            let at = Stamp {
                caller: req.caller,
                request_id: &task_id,
                now: req.now,
            };
            let opened = Task::submitted(
                task_id.as_str(),
                context_id.as_str(),
                req.caller,
                Direction::Inbound,
                req.now,
            )
            .map_err(|e| Halt::Failed(e.to_string()))
            .and_then(|mut t| {
                t.push_callback = url.map(str::to_string);
                if url.is_some() {
                    t.push_version = version.to_string();
                }
                tasks::open(reach, &at, t.to_row(), req.member, out)
            });
            match opened {
                Err(Halt::Pending) => return Err(Halt::Pending),
                Err(Halt::Failed(_)) => {
                    return Ok(refused(
                        STATUS_UNAVAILABLE,
                        rpc_id,
                        CODE_INTERNAL,
                        TASK_UNRECORDED,
                    ))
                }
                Ok(_) => {}
            }
            // THE SUBMIT'S RETENTION SWEEP, in the submit's own writes: a sweep that fails leaves
            // nothing behind (it writes only once its read is whole) and fails no submit.
            if let Err(Halt::Pending) =
                tasks::retention_sweep(reach, req.now, tasks::SWEEP_BUDGET, out)
            {
                return Err(Halt::Pending);
            }
            let task = TaskHop {
                task_id,
                context_id,
                addressed: false,
                skill: None,
                references: Vec::new(),
            };
            let unrecorded = refusal(STATUS_UNAVAILABLE, rpc_id, CODE_INTERNAL, TASK_UNRECORDED);
            (task, Some(unrecorded))
        }
    };
    let (instead, references) = translated(reach, req, backends)?;
    Ok(Opened::Hop {
        task: Box::new(TaskHop { references, ..task }),
        instead,
        callback,
        unrecorded,
    })
}

/// Whether `envelope` is ADDRESSED to a task, so that a task the caller does not hold refuses it:
/// every task verb ([`is_task_verb`]), or a message naming one in its `taskId`.
fn addresses_a_task(envelope: &Value) -> bool {
    is_task_verb(envelope) || !task_identity::message_tasks(envelope).is_empty()
}

/// Whether `envelope` is a task verb (`GetTask`, `CancelTask`, `SubscribeToTask`, either
/// spelling): a request about one task, which it must name.
fn is_task_verb(envelope: &Value) -> bool {
    use crate::ops::{row_for, OP_TASK_CANCEL, OP_TASK_GET, OP_TASK_SUBSCRIBE};
    envelope
        .get("method")
        .and_then(Value::as_str)
        .and_then(row_for)
        .is_some_and(|row| [OP_TASK_GET, OP_TASK_CANCEL, OP_TASK_SUBSCRIBE].contains(&row.op))
}

/// Whether `envelope` is a `CancelTask`, in either spelling.
fn is_cancel(envelope: &Value) -> bool {
    envelope
        .get("method")
        .and_then(Value::as_str)
        .and_then(crate::ops::row_for)
        .is_some_and(|row| row.op == crate::ops::OP_TASK_CANCEL)
}

/// THE INLINE CONFIG OBJECT whose `url` is the callback: the first of the three spellings that
/// carries a non-empty one, so the credential is read out of the same object as the URL.
fn inline_config(envelope: &Value) -> Option<&Value> {
    CALLBACK_CONFIG_POINTERS.into_iter().find_map(|p| {
        envelope.pointer(p).filter(|cfg| {
            cfg.get("url")
                .and_then(Value::as_str)
                .is_some_and(|u| !u.is_empty())
        })
    })
}

/// THE PUSH CALLBACK `envelope` carries inline, judged: `Ok(None)` for none, the callback as it
/// passed, or the refusal's words (a credential busbar cannot present, or a URL the floor refuses).
///
/// # Errors
/// [`Halt`] from the destination judge.
fn inline_callback(
    reach: &mut dyn Reach,
    envelope: &Value,
) -> Result<Result<Option<Callback>, String>, Halt> {
    let Some(cfg) = inline_config(envelope) else {
        return Ok(Ok(None));
    };
    let auth = match local::delivery_auth(cfg) {
        Ok(auth) => auth,
        Err(message) => return Ok(Err(message)),
    };
    let url = cfg
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(local::judge_callback(reach, &url)?.map(|()| Some(Callback { url, auth })))
}

/// The request with every task id the caller holds, and whose far-end id busbar learnt, sent on as
/// the far end's; `None` when none is.
fn translated(
    reach: &mut dyn Mint,
    req: &Request<'_>,
    backends: &dyn Fn(&str) -> Option<String>,
) -> Result<Translated, Halt> {
    let mut owned = BTreeMap::new();
    let relayed = req.relayed.unwrap_or(req.envelope);
    let mut ids = task_identity::translatable(relayed);
    ids.extend(task_identity::referenced_tasks(relayed));
    for id in ids {
        if owned.contains_key(id) {
            continue;
        }
        let Some(backend) = backends(id).filter(|b| b != id) else {
            continue;
        };
        if or_absent(tasks::get(reach, req.caller, id, req.now), None)?.is_some() {
            owned.insert(id.to_string(), backend);
        }
    }
    if owned.is_empty() {
        return Ok((None, Vec::new()));
    }
    let printed;
    let bytes = match req.relayed_bytes {
        Some(bytes) => bytes,
        None => {
            printed = serde_json::to_vec(relayed).map_err(|e| Halt::Failed(e.to_string()))?;
            printed.as_slice()
        }
    };
    let instead = task_identity::translate_request(bytes, &|id| owned.get(id).cloned());
    let references = owned
        .into_iter()
        .map(|(ours, theirs)| (theirs, ours))
        .collect();
    Ok((instead, references))
}

/// What [`translated`] answers: the request to send in place of the caller's bytes, when an id was
/// translated, and each translated task as the far end's id then busbar's, for the answer.
type Translated = (Option<Vec<u8>>, Vec<(String, String)>);

/// The error-once latches of the refused record writes, one per condition as predev held them
/// (`receive.rs` `RELAYED_OUTCOME_UNRECORDED_WARNED`, `STREAM_OUTCOME_UNRECORDED_WARNED`,
/// `RESUME_CURSOR_UNRECORDED_WARNED`, `FAILURE_UNRECORDED_WARNED`): a store outage persists across
/// every relayed outcome, so the first refusal of a kind is an error and the rest hold at debug.
/// Plane memory of the door instance (a restart forgets it), never a process global.
#[derive(Debug, Default)]
pub struct Latches {
    tripped: Keyed<u8, ()>,
}

impl Latches {
    /// No latch tripped.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trip latch `kind`; `true` when this is the first trip.
    fn first(&self, kind: u8) -> bool {
        self.tripped.with_all(|m| m.insert(kind, ()).is_none())
    }
}

/// Emit the diagnostic at error the first time `latch` is tripped and at debug after that.
macro_rules! latched {
    ($latches:expr, $kind:expr, $diag:expr, $($rest:tt)*) => {
        if $latches.first($kind) {
            busbar_contract::diag_error!($diag, $($rest)*)
        } else {
            busbar_contract::diag_debug!($diag, $($rest)*)
        }
    };
}

/// A record write the store refused, reported and never fatal: the hop SUCCEEDED, the caller is
/// owed its answer, and the stream keeps flowing. The words are predev's, line for line.
pub(crate) enum WriteRefused {
    /// The unary hop's reported state (predev `receive.rs` `record_state`, l.3239).
    Relayed,
    /// A streamed event's state (predev l.2965).
    Streamed(TaskState),
    /// The hop's task ended `failed` (predev `end_task`, l.3508).
    Failure,
    /// The artifact resume cursor (predev `advance_resume_cursor`, l.3198).
    Cursor,
}

impl WriteRefused {
    pub(crate) fn report(&self, latches: &Latches, task: &str, error: &str) {
        use crate::diagnostics::{A2A_FAILURE_UNRECORDED, A2A_RELAYED_OUTCOME_UNRECORDED};
        match self {
            Self::Relayed => latched!(
                latches, 0,
                A2A_RELAYED_OUTCOME_UNRECORDED,
                task = %task,
                error = %error,
                "a2a: the relayed task's outcome could not be recorded"
            ),
            Self::Streamed(state) => latched!(
                latches, 1,
                A2A_RELAYED_OUTCOME_UNRECORDED,
                task = %task,
                state = %state.as_str(),
                error = %error,
                "a2a: a streamed task transition could not be recorded"
            ),
            Self::Failure => latched!(
                latches, 2,
                A2A_FAILURE_UNRECORDED,
                task = %task,
                error = %error,
                "a2a: a failed task could not be recorded as failed"
            ),
            Self::Cursor => latched!(
                latches, 3,
                A2A_RELAYED_OUTCOME_UNRECORDED,
                task = %task,
                error = %error,
                "a2a: a streamed task's artifact resume cursor could not be recorded"
            ),
        }
    }
}

/// SETTLE `task` on what its answer said; the record writes go to `out`. A write the store refuses
/// is not the caller's failure: the answer stands. A relayed event settles as it passes: the state
/// it reported, then the artifact it carried (the resume cursor, one chunk on), each chained over
/// the writes `out` already holds. Answers the row as it moved (what a push notification about the
/// move carries), or `None` when nothing moved.
///
/// A write the store refuses is journaled through `latches` (error once per kind, debug after).
///
/// # Errors
/// [`Halt::Pending`] when a records call pends.
pub fn settle_on_answer(
    rec: &mut dyn Records,
    task: &TaskHop,
    settled: &TaskSettled,
    caller: &str,
    now: u64,
    out: &mut Vec<Write>,
    latches: &Latches,
) -> Result<Option<TaskRow>, Halt> {
    let (to, artifact) = match settled {
        TaskSettled::Reported { state, .. } if *state == TaskState::Submitted => return Ok(None),
        TaskSettled::Reported { state, .. } => (Some(*state), false),
        TaskSettled::Failed => (Some(TaskState::Failed), false),
        TaskSettled::Event {
            state, artifact, ..
        } => (*state, *artifact),
    };
    let at = Stamp {
        caller,
        request_id: &task.task_id,
        now,
    };
    let mut moved = None;
    if let Some(to) = to {
        let mut step = Vec::new();
        let transitioned = {
            let mut staged = tasks::Staged::new(&mut *rec, out);
            tasks::transition(&mut staged, &at, &task.task_id, to, &mut step)
        };
        match transitioned {
            Err(Halt::Pending) => return Err(Halt::Pending),
            Err(Halt::Failed(words)) => {
                let refused = match settled {
                    TaskSettled::Failed => WriteRefused::Failure,
                    TaskSettled::Reported { .. } => WriteRefused::Relayed,
                    TaskSettled::Event { .. } => WriteRefused::Streamed(to),
                };
                refused.report(latches, &task.task_id, &words);
            }
            Ok(row) => {
                out.extend(step);
                moved = row;
            }
        }
    }
    if artifact {
        let mut step = Vec::new();
        let bumped = {
            let mut staged = tasks::Staged::new(&mut *rec, out);
            tasks::bump_cursor(&mut staged, &at, &task.task_id, &mut step)
        };
        match bumped {
            Err(Halt::Pending) => return Err(Halt::Pending),
            Err(Halt::Failed(words)) => WriteRefused::Cursor.report(latches, &task.task_id, &words),
            Ok(_) => out.extend(step),
        }
    }
    Ok(moved)
}

#[cfg(test)]
#[path = "tests/task_hop_tests.rs"]
mod tests;
