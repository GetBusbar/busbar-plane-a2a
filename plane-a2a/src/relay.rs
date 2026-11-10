// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unary relay, as the kernel's route pump drives it: one JSON-RPC hop to the agent the
//! kernel's walk picked, in the order the pump pushes its pieces, and what the plane answers each
//! with.

use busbar_contract::jsonrpc::{read_response, NotAnAnswerKind, Reply as RpcReply};
use serde_json::Value;

use crate::a2a::task::TaskState;
use crate::agent_arrival::{AgentRefusal, CODE_INTERNAL, JSON_MEDIA_TYPE};
use crate::binding::{self, Binding};
use crate::events::{self, ACCEPT_EVENTS};
use crate::sse::SseReader;
use crate::task_identity;
use zeroize::Zeroize;

/// The verb every JSON-RPC hop is sent with.
pub const VERB: &str = "POST";

/// The `accept` a unary hop declares: the one document it reads.
pub const ACCEPT_UNARY: &str = JSON_MEDIA_TYPE;

/// The head field specifying response caching policy.
pub const H_CACHE_CONTROL: &str = "cache-control";
/// The head field naming a body's media type.
pub const H_CONTENT_TYPE: &str = "content-type";
/// The head field naming the media types the hop reads.
pub const H_ACCEPT: &str = "accept";

/// The most reply bytes a hop reads, since an unbounded read is an allocation the backend chooses
/// the size of.
pub const MAX_REPLY_BYTES: usize = 512 * 1024;

/// The status a refused hop answers with when the agent answered but its response is invalid;
/// a not-serving agent uses [`STATUS_NOT_SERVING`] instead.
pub const STATUS_BAD_GATEWAY: u32 = 502;

/// The status a hop to an agent that is not currently serving is refused with.
pub const STATUS_NOT_SERVING: u32 = 503;

/// The sentence a hop to an agent that is not currently serving is refused with.
pub const NOT_SERVING: &str = "this agent is not currently serving";

/// The status a relayed answer is given.
pub const STATUS_OK: u32 = 200;

/// `InvalidAgentResponse`, the code every refused hop carries.
pub const CODE_INVALID_AGENT_RESPONSE: i64 = -32006;

/// The words a task hop that did not complete is refused with.
pub const TASK_UNCOMPLETED: &str = "the backend agent did not complete this task";

/// The words an extended-card read through the relay that could not be made is refused with.
pub const CARD_UNFETCHED: &str = "the extended agent card could not be fetched";

/// Who pushed a piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum From<'a> {
    /// The caller: the request body.
    Caller,
    /// The far end: its answer.
    FarEnd,
    /// The kernel: an ATTEMPT, with the URL the operator wrote for the agent it picked (`None`
    /// when the plane's section names no such agent).
    Kernel(Option<&'a str>),
}

/// One piece, as the door read it off the crossing.
#[derive(Debug, Clone, Copy)]
pub struct Piece<'a> {
    /// Who pushed it.
    pub from: From<'a>,
    /// Its bytes.
    pub bytes: &'a [u8],
    /// On the far end's first piece: the status it answered.
    pub status: Option<u32>,
    /// No piece of this `from` follows.
    pub last: bool,
}

/// The request one attempt sends the far end: the verb, the target under the agent's origin, and
/// the head fields in order. The kernel leads them with the member's auth
/// fields and sends the body that follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The verb.
    pub verb: &'static str,
    /// The target: the agent URL's path and query.
    pub target: String,
    /// The head fields, in order. A field this plane spells is borrowed from its constant, so an
    /// attempt's head allocates its field list and nothing per field (the allocation pin,
    /// `src/tests/alloc_gate.rs`).
    pub fields: Vec<(&'static str, std::borrow::Cow<'static, str>)>,
}

/// What the caller is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayReply {
    /// The status.
    pub status: u32,
    /// The body's media type.
    pub content_type: &'static str,
    /// The body.
    pub body: Vec<u8>,
}

impl RelayReply {
    /// A refusal as the caller's whole answer, at the refusal's status: its envelope, naming the
    /// task `about` when there is one ([`task_identity::about_task`]).
    #[must_use]
    pub fn refused(refusal: &AgentRefusal, about: Option<&str>) -> Self {
        let body = match about {
            Some(task) => task_identity::about_task(refusal, task),
            None => refusal.envelope(),
        };
        RelayReply {
            status: refusal.status,
            content_type: JSON_MEDIA_TYPE,
            body: crate::relay::json_bytes(&body).unwrap_or_default(),
        }
    }
}

impl Drop for RelayReply {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// PART OF AN ANSWER IN EVENTS: whether it starts the caller's answer (its head: `200`, an event
/// stream), the whole events it carries, and whether it ends the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// It starts the caller's answer.
    pub head: bool,
    /// Whole events.
    pub body: Vec<u8>,
    /// No part follows: the unit is done.
    pub last: bool,
}

impl Drop for Part {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// The plane's answer to one piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceAnswer {
    /// Nothing to emit yet.
    Nothing,
    /// The request this attempt sends the far end; its body follows as [`PieceAnswer::ToFarEnd`].
    Attempt(Attempt),
    /// The request's body, bound for the far end: bytes the relay made (a translated or framed
    /// request).
    ToFarEnd(RawBytes),
    /// The request's body, bound for the far end: the caller's piece itself, unchanged. The door
    /// writes it from the piece the host lent, so relaying an envelope it changes nothing about
    /// copies nothing (the allocation pin, `src/tests/alloc_gate.rs`).
    ToFarEndLent,
    /// The caller's whole answer: the unit is done.
    ToCaller(RelayReply),
    /// Part of the caller's answer in events.
    Part(Part),
    /// The piece is one this relay never takes.
    Refused,
}

/// Why a hop has no answer to relay, in the arms the plane can see (the guard, the trust gate, the lease and the breaker are the kernel's now).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopRefusal {
    /// The backend answered outside 2xx.
    Status,
    /// The reply was over [`MAX_REPLY_BYTES`].
    BodyTooLarge,
    /// The reply is not a JSON-RPC answer.
    NotJson,
    /// The backend answered with a JSON-RPC `error`.
    BackendError,
    /// The reply names a different request.
    Uncorrelated,
    /// The agent is not currently serving: its re-verification demoted it.
    NotServing,
    /// The egress guard refused the agent's registered endpoint.
    EndpointRefused,
    /// The hop left for the agent and no answer came back: the connection could not be made, or
    /// it closed before the agent answered.
    Transport,
}

impl HopRefusal {
    /// The stable token a caller may quote.
    #[must_use]
    pub const fn client_code(self) -> &'static str {
        match self {
            HopRefusal::Status => "a2a.hop.backend_status",
            HopRefusal::BodyTooLarge => "a2a.hop.reply_too_large",
            HopRefusal::NotJson => "a2a.hop.reply_not_json",
            HopRefusal::BackendError => "a2a.hop.backend_refused",
            HopRefusal::Uncorrelated => "a2a.hop.reply_uncorrelated",
            HopRefusal::NotServing => "a2a.hop.agent_not_serving",
            HopRefusal::EndpointRefused => "a2a.hop.endpoint_refused",
            HopRefusal::Transport => "a2a.hop.transport_failed",
        }
    }

    /// The caller's sentence: fixed per arm, interpolating nothing a backend, its address or its
    /// bytes could choose.
    #[must_use]
    pub fn client_text(self) -> String {
        let sentence = match self {
            HopRefusal::Status => "this agent's backend refused busbar's request",
            HopRefusal::BodyTooLarge => {
                "this agent's backend replied with more than the fixed reply limit"
            }
            HopRefusal::NotJson => {
                "this agent's backend replied with something that is not a JSON-RPC answer"
            }
            HopRefusal::BackendError => "this agent's backend refused the request",
            HopRefusal::Uncorrelated => {
                "this agent's backend answered something busbar cannot correlate to the request it \
                 sent, so it is refused rather than relayed"
            }
            HopRefusal::NotServing => NOT_SERVING,
            HopRefusal::EndpointRefused => {
                "busbar's egress guard refused the registered endpoint for this agent"
            }
            HopRefusal::Transport => "busbar could not reach this agent's backend",
        };
        format!("{}: {sentence}", self.client_code())
    }

    /// The operator's sentence: it names the backend's `url` on purpose, because a journal line is
    /// for diagnosing the backend.
    #[must_use]
    pub fn operator(self, url: &str, status: Option<u32>) -> String {
        match self {
            HopRefusal::Status => match status {
                Some(status) => format!("the backend agent at `{url}` answered HTTP {status}"),
                None => format!("the backend agent at `{url}` answered outside 2xx"),
            },
            HopRefusal::BodyTooLarge => {
                format!("the backend agent at `{url}` replied over the fixed reply limit")
            }
            HopRefusal::NotJson => {
                format!("the backend agent at `{url}` replied with something that is not JSON")
            }
            HopRefusal::BackendError => format!("the backend agent at `{url}` refused the task"),
            HopRefusal::Uncorrelated => format!(
                "the backend agent at `{url}` answered something busbar cannot correlate to the \
                 request it sent, so it is refused rather than relayed"
            ),
            HopRefusal::NotServing => self.client_text(),
            HopRefusal::EndpointRefused => format!("the relay target `{url}` was refused"),
            HopRefusal::Transport => {
                format!("the relayed hop to `{url}` ended before its answer completed")
            }
        }
    }

    /// The caller's answer: the one error envelope, `-32006` with its `ErrorInfo`, at `502`.
    #[must_use]
    pub fn reply(self, id: &Value) -> RelayReply {
        let refusal = AgentRefusal::new(
            STATUS_BAD_GATEWAY,
            Some(id.clone()),
            CODE_INVALID_AGENT_RESPONSE,
            self.client_text(),
        );
        RelayReply::refused(&refusal, None)
    }
}

/// The far end's whole answer, read as the answer to `id`: the span of its `result` in `body`, or
/// why it is refused, read off its bytes and never into a value.
pub fn read_answer(
    status: u32,
    body: &[u8],
    id: &Value,
) -> Result<std::ops::Range<usize>, HopRefusal> {
    if !(200..300).contains(&status) {
        return Err(HopRefusal::Status);
    }
    if body.len() > MAX_REPLY_BYTES {
        return Err(HopRefusal::BodyTooLarge);
    }
    read_answer_document(body, id)
}

/// Read an already size-checked document, including a locally added JSON-RPC envelope.
fn read_answer_document(body: &[u8], id: &Value) -> Result<std::ops::Range<usize>, HopRefusal> {
    if !crate::answer_bytes::with_readable(body, crate::answer_bytes::is_json) {
        return Err(HopRefusal::NotJson);
    }
    let (judged, result) =
        crate::answer_bytes::envelope_reading(body).ok_or(HopRefusal::NotJson)?;
    let judged = crate::request_json::RequestJson::new(judged);
    match read_response(&judged, id) {
        Ok(RpcReply::Result(_)) => result.ok_or(HopRefusal::NotJson),
        Ok(RpcReply::Error { .. }) => Err(HopRefusal::BackendError),
        Err(e) => Err(match e.kind {
            NotAnAnswerKind::Uncorrelated => HopRefusal::Uncorrelated,
            NotAnAnswerKind::NotAResponse => HopRefusal::NotJson,
        }),
    }
}

/// The caller's answer to a relayed `result` given as the far end's own bytes (spliced, never
/// re-serialised; Law 5), under the caller's own `id`.
#[must_use]
pub fn relayed_bytes(id: &Value, result: &[u8]) -> RelayReply {
    RelayReply {
        status: STATUS_OK,
        content_type: JSON_MEDIA_TYPE,
        body: crate::answer_bytes::result_reply(id, result),
    }
}

/// The target an attempt is sent at: the agent URL's path and query, which the kernel joins onto
/// the agent's origin, or `None` for a URL that does not parse.
#[must_use]
pub fn target_of(url: &str) -> Option<String> {
    if let Some(target) = verbatim_target(url) {
        return Some(target);
    }
    let parsed = url::Url::parse(url).ok()?;
    let mut target = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }
    Some(target)
}

/// [`target_of`] for the common url, read off its own bytes with no parse: an `http`/`https` url
/// whose host is a plain name or address and whose path and query hold only characters the URL
/// standard serializes as they are, and `None` for any other url.
fn verbatim_target(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (host, tail) = rest.split_at(split);

    let plain_host = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()))
        && !host.starts_with(['.', '-'])
        && !host.contains("..");
    let plain_tail = tail
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&()*+,;=:@/?%".contains(&b));
    let (path, _) = tail.split_once('?').unwrap_or((tail, ""));
    let dot_segment = path.split('/').any(|seg| {
        seg == "."
            || seg == ".."
            || seg
                .as_bytes()
                .windows(3)
                .any(|w| w.eq_ignore_ascii_case(b"%2e"))
    });
    if !plain_host || !plain_tail || dot_segment {
        return None;
    }
    Some(if path.is_empty() {
        let mut target = String::with_capacity(1 + tail.len());
        target.push('/');
        target.push_str(tail);
        target
    } else {
        tail.to_owned()
    })
}

/// What the far end's answer says about the far end (the breaker's reading, read where the
/// answer's structure still exists, status first). Any
/// status outside `2xx` is the status table's alone, whatever its body says ([`status_reading`]);
/// only on a `2xx` is the body read: a result, or an error the protocol defines, is the destination
/// answering, the WORK failing and not the wire, and a body that is no usable
/// answer is transient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    /// The destination answered.
    Healthy,
    /// The caller's request was refused.
    Caller,
    /// A failure the destination may recover from.
    Transient,
    /// The destination refuses busbar itself.
    Hard,
}

/// A retained wire buffer. Growth copies into a new allocation before wiping the old one;
/// retry and prefix removal wipe bytes before the allocation can be reused.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RawBytes(Vec<u8>);

impl RawBytes {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
    fn clear(&mut self) {
        #[cfg(test)]
        crate::tests::raw_custody_probe::before_wipe(&self.0);
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        crate::tests::raw_custody_probe::after_wipe(&self.0);
        self.0.zeroize();
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        let needed = self.0.len().saturating_add(bytes.len());
        self.reserve_for(needed);
        self.0.extend_from_slice(bytes);
    }

    fn reserve_for(&mut self, needed: usize) {
        if needed > self.0.capacity() {
            let mut next =
                Vec::with_capacity(needed.max(256).max(self.0.capacity().saturating_mul(2)));
            next.extend_from_slice(&self.0);
            self.clear();
            self.0 = next;
        }
    }

    /// Grow initialized scratch without freeing an unwiped old allocation.
    pub(crate) fn grow_zeroed(&mut self, len: usize) {
        if len > self.0.len() {
            self.reserve_for(len);
            self.0.resize(len, 0);
        }
    }

    fn discard_prefix(&mut self, count: usize) {
        self.0.copy_within(count.., 0);
        let remaining = self.0.len() - count;
        #[cfg(test)]
        crate::tests::raw_custody_probe::before_wipe(&self.0[remaining..]);
        self.0[remaining..].fill(0);
        #[cfg(test)]
        crate::tests::raw_custody_probe::after_wipe(&self.0[remaining..]);
        self.0.truncate(remaining);
    }
}

impl std::io::Write for RawBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialized_json(value: &Value) -> RawBytes {
    let mut bytes = RawBytes::default();
    if serde_json::to_writer(&mut bytes, value).is_ok() {
        bytes
    } else {
        RawBytes::default()
    }
}

/// Serialize through a wiping growth owner, transferring only the completed output.
pub(crate) fn json_bytes<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = RawBytes::default();
    serde_json::to_writer(&mut bytes, value)?;
    Ok(bytes.into_vec())
}

impl std::convert::From<Vec<u8>> for RawBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::ops::Deref for RawBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for RawBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Drop for RawBytes {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
#[path = "tests/raw_buffer_custody.rs"]
mod raw_buffer_custody;

/// The status table: the reading of an answer at a status outside `2xx`, its body unread.
#[must_use]
pub fn status_reading(status: u32) -> Reading {
    match status {
        401 | 403 => Reading::Hard,
        408 | 429 | 500..=599 => Reading::Transient,
        _ => Reading::Caller,
    }
}

fn grpc_status_reading(ended: &crate::framed::Ended) -> Reading {
    use crate::framed::Code;

    const DEADLINE_EXCEEDED: u32 = 4;
    if [Code::PermissionDenied as u32, Code::Unauthenticated as u32].contains(&ended.code) {
        Reading::Hard
    } else if ended.code == DEADLINE_EXCEEDED
        || [
            Code::Unknown as u32,
            Code::ResourceExhausted as u32,
            Code::Internal as u32,
            Code::Unavailable as u32,
        ]
        .contains(&ended.code)
    {
        Reading::Transient
    } else {
        Reading::Healthy
    }
}

/// ONE UNARY HOP: the caller's request id and negotiated version, and what the current attempt's
/// far end has said so far.
#[derive(Clone, Default)]
pub struct HopRelay {
    id: Value,
    version: &'static str,
    sent: u64,
    status: Option<u32>,
    far: RawBytes,
    received: u64,
    answered: bool,
    task: Option<TaskHop>,
    instead: Option<RawBytes>,
    /// The body the current attempt's binding composed (HTTP+JSON, gRPC), sent in place of
    /// [`Self::instead`] and the caller's bytes; cleared by every attempt, so a JSON-RPC attempt
    /// after a failover never sends another binding's body.
    composed: Option<RawBytes>,
    instead_sent: bool,
    settled: Vec<TaskSettled>,
    binding: Binding,
    method: String,
    params: crate::request_json::RequestJson,
    events: Option<Events>,
    /// The reading of the far end's answer, once the answer says enough to read ([`Reading`]).
    reading: Option<Reading>,
    /// On the gRPC binding: what the far end's messages and trailers have said so far.
    grpc: GrpcRead,
    /// The registered agent identifier, used by operator diagnostics without its endpoint.
    agent: String,
}

impl std::fmt::Debug for HopRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopRelay")
            .field("binding", &self.binding)
            .field("status", &self.status)
            .field("answered", &self.answered)
            .finish_non_exhaustive()
    }
}

/// HOW FAR A gRPC FAR END'S ANSWER HAS BEEN READ: the length-prefixed bytes of an answer in events
/// not yet a whole message, and how the call ended, once its trailers said.
#[derive(Debug, Clone, Default)]
struct GrpcRead {
    pending: RawBytes,
    ended: Option<crate::framed::Ended>,
}

/// How far a hop that expects events has read its far end's answer.
#[derive(Debug, Clone, Default)]
struct Events {
    reader: SseReader,
    /// A frame was read: the answer is a stream, not one document.
    framed: bool,
    /// The far end answered one document: it is read whole, as a unary hop's is.
    document: bool,
    /// The caller's answer has started: no refusal is expressible any more.
    committed: bool,
}

/// Whether a frame is an event: its first line is an event-stream field or a comment, never the
/// first line of a document.
fn is_event(frame: &str) -> bool {
    let first = frame.trim_start_matches(['\r', '\n']);
    [":", "data", "event", "id", "retry"]
        .iter()
        .any(|field| first.starts_with(field))
}

/// The task a relayed hop is for: busbar's identity for it, whether the
/// request addressed a task the caller already holds, and the skill the arrival matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHop {
    /// busbar's task id.
    pub task_id: String,
    /// busbar's `contextId`.
    pub context_id: String,
    /// The request named a task the caller holds: a failed hop says nothing about that task.
    pub addressed: bool,
    /// The skill the arrival matched, annotated on the answer.
    pub skill: Option<String>,
    /// The tasks the request referred to that busbar translated, each as the far end's id then
    /// busbar's: an answer referring to one names busbar's.
    pub references: Vec<(String, String)>,
}

/// What reading a 2xx far-end piece's events answers: `None` while no event is framed; else the
/// events for the caller, or the refusal they earn with the events read before it.
type EventsRead = Option<Result<RawBytes, (HopRefusal, RawBytes)>>;

/// WHAT A TASK HOP'S ANSWER SAYS ABOUT ITS TASK, for the door to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskSettled {
    /// The far end answered: the state it reported, and its own id for the task.
    Reported {
        /// The reported state (`Working` when none could be read).
        state: TaskState,
        /// The far end's own task id, before the rewrite.
        backend_id: Option<String>,
    },
    /// The hop failed a task it opened: the task ends `failed`.
    Failed,
    /// One relayed event: the state it reported, whether it carried an artifact, and the far
    /// end's own id for the task.
    Event {
        /// The state it reported, if one this build can read.
        state: Option<TaskState>,
        /// It carried an artifact chunk.
        artifact: bool,
        /// The far end's own task id, before the rewrite.
        backend_id: Option<String>,
    },
}

impl HopRelay {
    /// Whether the far end has begun its answer: a status or a byte of it has arrived.
    pub(crate) const fn far_answered(&self) -> bool {
        self.status.is_some() || self.received != 0
    }

    /// A hop answering the request `id`, declaring the `version` busbar's edge negotiated.
    #[must_use]
    pub fn new(id: Value, version: &'static str) -> Self {
        HopRelay {
            id,
            version,
            ..HopRelay::default()
        }
    }

    /// Name the registered agent for diagnostics; its endpoint is never retained for logging.
    pub fn name_backend(&mut self, agent: &str, _url: &str) {
        self.agent = agent.to_string();
    }

    /// Report a refused hop with a fixed reason and no backend endpoint.
    fn journal(&self, refusal: HopRefusal, stream: bool) {
        let error = refusal.operator("[redacted]", self.status);
        self.journal_reason(refusal.client_code(), &error, stream);
    }

    /// Operator-only reasons are fixed at the failure stage, so framing libraries' free-form error
    /// strings, which can include request values, never enter the journal.
    fn journal_reason(&self, code: &str, error: &str, stream: bool) {
        let agent = self.agent.as_str();
        match (&self.task, stream || self.events.is_some()) {
            (Some(task), true) => busbar_contract::diag_debug!(
                crate::diagnostics::A2A_RELAYED_STREAM_REFUSED,
                agent = %agent,
                task = %task.task_id,
                error = %error,
                "a2a: the relayed stream ended in a refusal"
            ),
            (Some(task), false) => busbar_contract::diag_debug!(
                crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED,
                agent = %agent,
                task = %task.task_id,
                error = %error,
                "a2a: the relayed request failed"
            ),
            (None, true) => busbar_contract::diag_debug!(
                crate::diagnostics::A2A_RELAYED_STREAM_REFUSED,
                agent = %agent,
                code = %code,
                error = %error,
                "a2a: the relayed stream was refused before a task context existed"
            ),
            (None, false) => busbar_contract::diag_debug!(
                crate::diagnostics::A2A_RELAYED_SUBMISSION_FAILED,
                agent = %agent,
                code = %code,
                error = %error,
                "a2a: a hop was refused before a task context existed"
            ),
        }
    }

    /// The binding the hop's attempts speak.
    #[must_use]
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    /// The reading of the far end's answer, once: on the piece that holds the whole answer, or on
    /// the first event of a stream ([`Reading`]), else `None`.
    pub fn take_reading(&mut self) -> Option<Reading> {
        self.reading.take()
    }

    fn answer_reading(&self, fallback: Reading) -> Reading {
        self.status
            .filter(|status| *status != 0 && !(200..300).contains(status))
            .map(status_reading)
            .or_else(|| {
                self.grpc
                    .ended
                    .as_ref()
                    .filter(|ended| !ended.ok())
                    .map(grpc_status_reading)
            })
            .unwrap_or(fallback)
    }

    /// The hop's answer may be a stream of events (the engine's event-stream hop): its attempts
    /// accept one, and its far end's events are answered as they come.
    pub fn expect_events(&mut self) {
        self.events = Some(Events::default());
    }

    /// Whether the hop's answer may be a stream of events ([`Self::expect_events`]).
    #[must_use]
    pub const fn expects_events(&self) -> bool {
        self.events.is_some()
    }

    /// The `accept` an attempt declares.
    fn accept(&self) -> &'static str {
        if self.events.is_some() {
            ACCEPT_EVENTS
        } else {
            ACCEPT_UNARY
        }
    }

    /// The binding the next attempt speaks, for the request `envelope` (the translated one, when a
    /// task id was translated).
    pub fn bind(&mut self, binding: Binding, envelope: &Value) {
        let first = self.method.is_empty() && self.params.is_null();
        self.binding = binding;
        if !first {
            return;
        }
        let translated = self
            .instead
            .as_deref()
            .and_then(|b| crate::request_json::parse(b).ok());
        let envelope = translated.as_deref().unwrap_or(envelope);
        self.method = envelope
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.params = crate::request_json::RequestJson::new(
            envelope
                .get("params")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        );
    }

    /// REFUSED BY NAME before the hop: the agent's card declares only `word`, a binding the plane
    /// does not frame.
    pub fn refuse_unspeakable(&mut self, word: &str) -> PieceAnswer {
        self.answered = true;
        self.journal_reason(
            "a2a.hop.unframable",
            "the agent card declares no binding busbar can frame",
            false,
        );
        if self.task.as_ref().is_some_and(|task| !task.addressed) {
            self.settled.push(TaskSettled::Failed);
        }
        PieceAnswer::ToCaller(self.unframable_reply(word))
    }

    /// REFUSED AT THE HOP'S TRUST GATE: the agent was serving at admission and its re-verification
    /// demoted it.
    pub fn refuse_demoted(&mut self) -> PieceAnswer {
        self.answered = true;
        self.journal(HopRefusal::NotServing, false);
        if self.task.as_ref().is_some_and(|task| !task.addressed) {
            self.settled.push(TaskSettled::Failed);
        }
        let reply = match &self.task {
            Some(task) if task.addressed => task_refusal(None, task, &self.id).0,
            Some(task) => {
                let refusal = AgentRefusal::new(
                    STATUS_NOT_SERVING,
                    Some(self.id.clone()),
                    crate::agent_arrival::CODE_UNSUPPORTED_OPERATION,
                    NOT_SERVING,
                );
                RelayReply::refused(&refusal, Some(&task.task_id))
            }
            None => {
                let refusal = AgentRefusal::new(
                    STATUS_NOT_SERVING,
                    Some(self.id.clone()),
                    CODE_INVALID_AGENT_RESPONSE,
                    HopRefusal::NotServing.client_text(),
                );
                RelayReply::refused(&refusal, None)
            }
        };
        PieceAnswer::ToCaller(reply)
    }

    /// REFUSED AT THE RELAY'S GUARD: the agent's registered endpoint was refused before the hop,
    /// and the caller never reads the endpoint.
    pub fn refuse_endpoint(&mut self) -> PieceAnswer {
        self.answered = true;
        self.journal(HopRefusal::EndpointRefused, false);
        let reply = self.task_refused(None);
        PieceAnswer::ToCaller(reply.unwrap_or_else(|| HopRefusal::EndpointRefused.reply(&self.id)))
    }

    /// The caller's answer to this refused task hop ([`task_refusal`]), its task ended `failed`
    fn task_refused(&mut self, code: Option<i64>) -> Option<RelayReply> {
        let (reply, failed) = task_refusal(code, self.task.as_ref()?, &self.id);
        if failed {
            self.settled.push(TaskSettled::Failed);
        }
        Some(reply)
    }

    /// THE HOP LEFT AND NOTHING CAME BACK: the attempt went to the agent and the connection could
    /// not be made, or closed before any answer.
    #[must_use]
    pub fn refuse_transport(&mut self) -> (RelayReply, bool) {
        self.answered = true;
        self.journal(HopRefusal::Transport, false);
        match &self.task {
            None => (HopRefusal::Transport.reply(&self.id), false),
            Some(task) => task_refusal(None, task, &self.id),
        }
    }

    /// REFUSED FOR BUSBAR'S OWN CREDENTIAL: the agent's `upstream_credential`, re-resolved for this
    /// hop, was unavailable, so the kernel refused the unit before anything was dialled.
    #[must_use]
    pub fn refuse_credential(&mut self) -> (RelayReply, bool) {
        self.answered = true;
        self.journal_reason(
            "a2a.hop.credential_unavailable",
            "the upstream credential could not be leased for this agent",
            false,
        );
        let task = self.task.as_ref().map(|t| t.task_id.as_str());
        let message = if task.is_some() {
            TASK_UNCOMPLETED
        } else {
            CARD_UNFETCHED
        };
        let refusal = AgentRefusal::new(
            STATUS_BAD_GATEWAY,
            Some(self.id.clone()),
            CODE_INVALID_AGENT_RESPONSE,
            message,
        );
        (RelayReply::refused(&refusal, task), task.is_some())
    }

    /// The early refusal of a request that cannot be carried over `word`.
    fn unframable_reply(&self, word: &str) -> RelayReply {
        let refusal = AgentRefusal::new(
            STATUS_BAD_GATEWAY,
            Some(self.id.clone()),
            CODE_INVALID_AGENT_RESPONSE,
            binding::unframable_text(&self.method, word),
        );
        RelayReply::refused(
            &refusal,
            self.task.as_ref().map(|task| task.task_id.as_str()),
        )
    }

    /// The hop could not be framed on its binding: a task-less hop is refused by name; a task hop
    /// answers as any failed hop does.
    fn unframable(&mut self, cause: &str) -> PieceAnswer {
        self.answered = true;
        self.journal_reason("a2a.hop.unframable", cause, false);
        let reply = self.task_refused(None);
        PieceAnswer::ToCaller(reply.unwrap_or_else(|| self.unframable_reply(self.binding.word())))
    }

    /// The request one attempt sends on the hop's binding, to the agent at `url`.
    fn attempt(&mut self, url: &str) -> PieceAnswer {
        let version = (
            crate::agent_arrival::H_VERSION,
            std::borrow::Cow::Borrowed(self.version),
        );
        match self.binding {
            Binding::JsonRpc => match target_of(url) {
                Some(target) => PieceAnswer::Attempt(Attempt {
                    verb: VERB,
                    target,
                    fields: vec![
                        (H_CONTENT_TYPE, JSON_MEDIA_TYPE.into()),
                        (H_ACCEPT, self.accept().into()),
                        version,
                    ],
                }),
                None => {
                    self.journal_reason(
                        HopRefusal::EndpointRefused.client_code(),
                        "the registered agent url has no path and query busbar can send to",
                        false,
                    );
                    PieceAnswer::Refused
                }
            },
            Binding::HttpJson => match binding::compose(url, &self.method, &self.params) {
                Ok(mut framed) => {
                    let mut fields = Vec::new();
                    if framed.has_body {
                        fields.push((H_CONTENT_TYPE, JSON_MEDIA_TYPE.into()));
                    }
                    fields.push((H_ACCEPT, self.accept().into()));
                    fields.push(version);
                    self.composed = Some(std::mem::take(&mut framed.body).into());
                    PieceAnswer::Attempt(Attempt {
                        verb: framed.verb,
                        target: std::mem::take(&mut framed.target),
                        fields,
                    })
                }
                Err(_) => self.unframable(
                    "the HTTP+JSON request could not be composed from the operation's path, query and body params",
                ),
            },
            Binding::Grpc => {
                let framed = crate::framed::Rpc::of_method(&self.method)
                    .ok_or("the requested operation has no gRPC binding")
                    .and_then(|rpc| {
                        crate::framed::request_message(rpc, &self.params)
                            .map(|body| (rpc, body))
                            .map_err(|_| "the request params could not be encoded for the gRPC operation")
                    });
                match framed {
                    Ok((rpc, body)) => {
                        self.composed = Some(body.into());
                        let media = crate::framed::DIAL_CONTENT_TYPE;
                        PieceAnswer::Attempt(Attempt {
                            verb: VERB,
                            target: rpc.target(),
                            fields: vec![
                                (H_CONTENT_TYPE, media.into()),
                                (H_ACCEPT, media.into()),
                                version,
                            ],
                        })
                    }
                    Err(cause) => self.unframable(cause),
                }
            }
        }
    }

    /// The hop is for `task`: its answer leaves under busbar's identity and its refusals name the
    /// task.
    pub fn for_task(&mut self, task: TaskHop) {
        self.task = Some(task);
    }

    /// The request id the hop answers.
    #[must_use]
    pub const fn id(&self) -> &Value {
        &self.id
    }

    /// The task this hop is for, once one is open.
    #[must_use]
    pub const fn task(&self) -> Option<&TaskHop> {
        self.task.as_ref()
    }

    /// Every attempt sends `body` in place of the caller's bytes, for a request whose task ids were
    /// translated to the far end's.
    pub fn send_instead(&mut self, body: Vec<u8>) {
        self.instead = Some(body.into());
    }

    #[cfg(test)]
    pub(crate) fn send_shared_instead(&mut self, body: RawBytes) {
        self.instead = Some(body);
    }

    pub(crate) fn replacement_bytes(&self) -> Option<&[u8]> {
        self.instead.as_deref()
    }

    /// Release payload custody after the unit ends, retaining its refusal and billing facts.
    pub(crate) fn release_payloads(&mut self) {
        self.far = RawBytes::default();
        self.instead = None;
        self.composed = None;
        self.params = crate::request_json::RequestJson::default();
        self.grpc.pending = RawBytes::default();
        if let Some(events) = self.events.as_mut() {
            events.reader = SseReader::default();
        }
    }

    /// What the answer has said about the task since this was last asked, in order; empty before
    /// the answer or for a task-less hop.
    pub fn take_settled(&mut self) -> Vec<TaskSettled> {
        std::mem::take(&mut self.settled)
    }

    /// The payload bytes the hop has moved both ways, the request's and the reply's, once the far
    /// end has answered.
    #[must_use]
    pub fn moved(&self) -> u64 {
        if self.status.is_some() {
            self.sent.saturating_add(self.received)
        } else {
            0
        }
    }

    /// The plane's answer to `piece`.
    pub fn on_piece(&mut self, piece: Piece<'_>) -> PieceAnswer {
        if self.answered {
            return PieceAnswer::Nothing;
        }
        match piece.from {
            From::Kernel(url) => {
                if self.events.as_ref().is_some_and(|e| e.committed) {
                    return PieceAnswer::Refused;
                }
                if let Some(events) = self.events.as_mut() {
                    *events = Events::default();
                }
                self.sent = 0;
                self.status = None;
                self.far.clear();
                self.received = 0;
                self.instead_sent = false;
                self.composed = None;
                self.reading = None;
                self.grpc = GrpcRead::default();
                match url {
                    Some(url) => self.attempt(url),
                    None => PieceAnswer::Refused,
                }
            }
            From::Caller => {
                let replacement = self.composed.as_ref().or(self.instead.as_ref());
                let (bytes, message) = match replacement {
                    Some(_) if self.instead_sent => (None, false),
                    Some(instead) => (Some(instead.clone()), true),
                    None => (None, false),
                };
                if message {
                    self.instead_sent = true;
                }
                let len = bytes.as_ref().map_or(
                    if replacement.is_some() {
                        0
                    } else {
                        piece.bytes.len()
                    },
                    |bytes| bytes.len(),
                );

                let prefix = if message && self.binding == Binding::Grpc {
                    crate::framed::MESSAGE_PREFIX
                } else {
                    0
                };
                self.sent = self.sent.saturating_add(len.saturating_add(prefix) as u64);
                match bytes {
                    _ if len == 0 => PieceAnswer::Nothing,
                    Some(bytes) => PieceAnswer::ToFarEnd(bytes),
                    None => PieceAnswer::ToFarEndLent,
                }
            }
            From::FarEnd => self.far_end_piece(piece),
        }
    }

    fn far_end_piece(&mut self, piece: Piece<'_>) -> PieceAnswer {
        if self.binding == Binding::Grpc {
            return self.grpc_piece(&piece);
        }
        if let Some(status) = piece.status {
            self.status = Some(status);
        }
        self.received = self.received.saturating_add(piece.bytes.len() as u64);
        let in_events = self.events.as_ref().is_some_and(|e| !e.document)
            && self.status.is_some_and(|s| (200..300).contains(&s));
        if in_events {
            if let Some(answer) = self.events_piece(&piece) {
                return answer;
            }
        } else {
            self.keep(piece.bytes);
        }
        if !piece.last {
            return PieceAnswer::Nothing;
        }
        let Some(status) = self.status else {
            return PieceAnswer::Refused;
        };
        self.whole(status)
    }

    /// The kernel ended the answer with `PIECE_CUT`: complete events already received remain
    /// visible, followed by the transport error.
    pub fn on_far_cut(&mut self, bytes: &[u8], status: Option<u32>) -> PieceAnswer {
        if self.answered {
            return PieceAnswer::Nothing;
        }
        if let Some(status) = status {
            self.status = Some(status);
        }
        self.received = self.received.saturating_add(bytes.len() as u64);
        let in_events = self.events.as_ref().is_some_and(|e| !e.document)
            && self.status.is_some_and(|status| {
                (200..300).contains(&status) || (self.binding == Binding::Grpc && status == 0)
            });
        let mut body = if in_events {
            let framed;
            let bytes = if self.binding == Binding::Grpc {
                framed = self.grpc_events(bytes).0;
                &framed[..]
            } else {
                bytes
            };
            match self.events_read(bytes) {
                Some(Ok(body) | Err((_, body))) => body,
                None => RawBytes::default(),
            }
        } else {
            RawBytes::default()
        };
        if !body.is_empty() || self.events.as_ref().is_some_and(|e| e.committed) {
            body.extend_from_slice(b"data: ");
            body.extend_from_slice(&HopRefusal::Transport.reply(&self.id).body);
            body.extend_from_slice(b"\n\n");
        }
        self.events_refused(HopRefusal::Transport, body)
    }

    /// Keep `bytes` of a far end's answer read whole, only up to one byte past the ceiling: past it
    /// the reply is refused whole.
    fn keep(&mut self, bytes: &[u8]) {
        let room = (MAX_REPLY_BYTES + 1).saturating_sub(self.far.len());
        self.far.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    /// One 2xx far-end piece of a hop expecting events: `None` while the far end has framed no
    /// event (its bytes kept, as one document's are), else what the events it finished answer.
    fn events_piece(&mut self, piece: &Piece<'_>) -> Option<PieceAnswer> {
        Some(match self.events_read(piece.bytes)? {
            Ok(body) => {
                if piece.last {
                    self.answered = true;
                }
                self.part(body, piece.last)
            }
            Err((refusal, body)) => self.events_refused(refusal, body),
        })
    }

    /// The events a 2xx far-end piece's `bytes` finish, read ([`EventsRead`]): `None` while the far
    /// end has framed no event.
    fn events_read(&mut self, bytes: &[u8]) -> EventsRead {
        let mut reader = std::mem::take(&mut self.events.as_mut()?.reader);
        reader.feed_from(&self.agent, bytes);
        let read = self.frames_read(&reader, bytes);
        if let Some(events) = self.events.as_mut() {
            events.reader = reader;
        }
        read
    }

    /// The events `reader`'s last feed (`bytes`) finished, read ([`Self::events_read`]).
    fn frames_read(&mut self, reader: &SseReader, bytes: &[u8]) -> EventsRead {
        let (mut frames, pending) = (reader.frames().peekable(), reader.pending());
        let framed = self.events.as_ref()?.framed;
        if !framed {
            let first = frames.peek();
            let document = first.is_some_and(|f| !is_event(f));
            if first.is_none() || document {
                self.keep(bytes);
                if let Some(events) = self.events.as_mut() {
                    events.document = document || pending > MAX_REPLY_BYTES;
                }
                return None;
            }
        }
        if let Some(events) = self.events.as_mut() {
            if !events.framed {
                self.reading = Some(Reading::Healthy);
            }
            events.framed = true;
        }
        let (task_id, context_id, skill, references) = match &self.task {
            Some(t) => (
                t.task_id.as_str(),
                t.context_id.as_str(),
                t.skill.as_deref(),
                t.references.as_slice(),
            ),
            None => ("", "", None, &[][..]),
        };
        let opened = self.task.as_ref().is_some_and(|t| !t.addressed);
        let rest = self.binding == Binding::HttpJson;
        let id = &self.id;
        let mut body = RawBytes::default();
        for frame in frames {
            let wrapped =
                rest.then(|| zeroize::Zeroizing::new(events::rewrap(frame, id).into_owned()));
            let frame = wrapped.as_deref().map(String::as_str).unwrap_or(frame);
            let read = events::read_event(frame, id, task_id, context_id, skill, references);
            match read {
                Ok(mut event) => {
                    let sse = zeroize::Zeroizing::new(std::mem::take(&mut event.sse));
                    body.extend_from_slice(&sse);

                    let state = if opened && event.names_no_task {
                        Some(TaskState::Completed)
                    } else {
                        event.state
                    };
                    let said = state.is_some() || event.artifact || event.backend_task_id.is_some();
                    if self.task.is_some() && said {
                        self.settled.push(TaskSettled::Event {
                            state,
                            artifact: event.artifact,
                            backend_id: event.backend_task_id.take(),
                        });
                    }
                }
                Err(refusal) => return Some(Err((refusal, body))),
            }
        }

        if pending > MAX_REPLY_BYTES {
            return Some(Err((HopRefusal::BodyTooLarge, body)));
        }
        Some(Ok(body))
    }

    /// Part of the caller's answer in events: the first one starts it.
    fn part(&mut self, body: RawBytes, last: bool) -> PieceAnswer {
        let Some(events) = self.events.as_mut() else {
            return PieceAnswer::Refused;
        };
        if body.is_empty() && !last {
            return PieceAnswer::Nothing;
        }
        let head = !events.committed;
        events.committed = true;
        PieceAnswer::Part(Part {
            head,
            body: body.into_vec(),
            last,
        })
    }

    /// A hop expecting events is refused for `refusal`: before its answer started the caller is
    /// answered as a refused hop is, and after it the events already read go out and the answer
    /// ends there, its task `failed`.
    fn events_refused(&mut self, refusal: HopRefusal, body: RawBytes) -> PieceAnswer {
        self.answered = true;
        self.reading = Some(self.answer_reading(if refusal == HopRefusal::BackendError {
            Reading::Healthy
        } else {
            Reading::Transient
        }));
        let started = self.events.as_ref().is_some_and(|e| e.committed);
        self.journal(refusal, started || !body.is_empty());
        if !started && body.is_empty() {
            let reply = self.task_refused(None);
            return PieceAnswer::ToCaller(reply.unwrap_or_else(|| refusal.reply(&self.id)));
        }
        if self.task.is_some() {
            self.settled.push(TaskSettled::Failed);
        }
        self.part(body, true)
    }

    /// THE TRAILERS of the far end's answer (a field block after its body, `PIECE_FIELDS`), with
    /// the `status` the host reports beside them: on the gRPC binding they say how the call ended
    /// ([`crate::framed::ended`]), and any other binding ignores them.
    pub fn on_far_fields(&mut self, bytes: &[u8], status: Option<u32>, last: bool) -> PieceAnswer {
        if self.answered {
            return PieceAnswer::Nothing;
        }

        if self.binding == Binding::Grpc {
            if let Some(ended) = crate::framed::ended(bytes, status) {
                self.grpc.ended = Some(ended);
            }
        }
        if !last {
            return PieceAnswer::Nothing;
        }
        self.far_end_piece(Piece {
            from: From::FarEnd,
            bytes: &[],
            status: None,
            last: true,
        })
    }

    /// ONE PIECE OF A gRPC FAR END'S ANSWER (the grpc transport's: its head, with no status of its
    /// own; each message length-prefixed; then the trailers, [`Self::on_far_fields`]).
    fn grpc_piece(&mut self, piece: &Piece<'_>) -> PieceAnswer {
        if let Some(status) = piece.status {
            self.status = Some(status);
        }
        self.received = self.received.saturating_add(piece.bytes.len() as u64);
        if let Some(status) = self
            .status
            .filter(|status| *status != 0 && !(200..300).contains(status))
        {
            self.keep(piece.bytes);
            return if piece.last {
                self.whole(status)
            } else {
                PieceAnswer::Nothing
            };
        }
        if self.events.is_some() {
            let (framed, unread) = self.grpc_events(piece.bytes);
            if self.grpc.pending.len() > MAX_REPLY_BYTES {
                return self.events_refused(HopRefusal::BodyTooLarge, RawBytes::default());
            }
            match self.events_read(&framed) {
                None if unread => {
                    return self.events_refused(HopRefusal::NotJson, RawBytes::default())
                }
                None => {}
                Some(Err((refusal, body))) => return self.events_refused(refusal, body),
                Some(Ok(body)) if unread => return self.events_refused(HopRefusal::NotJson, body),
                Some(Ok(mut body)) => {
                    if piece.last {
                        if !self.grpc.pending.is_empty() || self.grpc.ended.is_none() {
                            return self.events_refused(HopRefusal::NotJson, body);
                        }

                        if let Some(error) = self.grpc_error() {
                            body.extend_from_slice(b"data: ");
                            body.extend_from_slice(&error);
                            body.extend_from_slice(b"\n\n");
                            return self.events_refused(HopRefusal::BackendError, body);
                        }
                        self.answered = true;
                    }
                    return self.part(body, piece.last);
                }
            }
        } else {
            self.keep(piece.bytes);
        }
        if !piece.last {
            return PieceAnswer::Nothing;
        }
        let Some(status) = self.status else {
            return PieceAnswer::Refused;
        };
        self.whole(status)
    }

    /// The whole messages `bytes` completes, each as one event-stream frame carrying the JSON-RPC
    /// response its `StreamResponse` is, and whether the reading stopped at a message it cannot
    /// read.
    fn grpc_events(&mut self, bytes: &[u8]) -> (RawBytes, bool) {
        self.grpc.pending.extend_from_slice(bytes);
        let Some(rpc) = crate::framed::Rpc::of_method(&self.method) else {
            return (RawBytes::default(), false);
        };
        let mut out = RawBytes::default();
        let mut cursor = 0;
        let unread = loop {
            let (len, took) = match crate::framed::take_message(&self.grpc.pending[cursor..]) {
                Ok(Some(message)) => message,
                Ok(None) => break false,
                Err(_) => break true,
            };
            let start = cursor + crate::framed::MESSAGE_PREFIX;
            let Ok(result) =
                crate::framed::response_result(rpc, &self.grpc.pending[start..start + len])
            else {
                break true;
            };
            let result = crate::request_json::RequestJson::new(result);
            cursor += took;
            out.extend_from_slice(b"data: ");
            let id = serialized_json(&self.id);
            let result = serialized_json(&result);
            let answer =
                zeroize::Zeroizing::new(busbar_contract::jsonrpc::result_bytes(&id, &result));
            out.extend_from_slice(&answer);
            out.extend_from_slice(b"\n\n");
        };
        self.grpc.pending.discard_prefix(cursor);
        (out, unread)
    }

    /// The JSON-RPC error a gRPC call that ended with an error status answers: its A2A code, where
    /// its reason or its status names one, else JSON-RPC's own internal error.
    fn grpc_error(&self) -> Option<RawBytes> {
        let ended = self.grpc.ended.as_ref().filter(|e| !e.ok())?;
        let code = ended.a2a_code().unwrap_or(CODE_INTERNAL);
        let id = serialized_json(&self.id);
        Some(
            busbar_contract::jsonrpc::error_bytes(
                &id,
                code,
                &format!("grpc-status {}", ended.code),
                None,
            )
            .into(),
        )
    }

    /// A gRPC far end's whole answer, as the JSON-RPC envelope the one reader reads: a call that
    /// ended with an error status is that error, else its one message is the rpc's `result`.
    fn grpc_envelope(&self) -> Option<RawBytes> {
        self.grpc.ended.as_ref()?;
        if let Some(envelope) = self.grpc_error() {
            return Some(envelope);
        }
        let rpc = crate::framed::Rpc::of_method(&self.method)?;
        let (len, took) = crate::framed::take_message(&self.far).ok()??;
        if took != self.far.len() {
            return None;
        }
        let message = &self.far[crate::framed::MESSAGE_PREFIX..crate::framed::MESSAGE_PREFIX + len];
        let result = crate::request_json::RequestJson::new(
            crate::framed::response_result(rpc, message).ok()?,
        );
        let id = serialized_json(&self.id);
        let result = serialized_json(&result);
        Some(busbar_contract::jsonrpc::result_bytes(&id, &result).into())
    }

    /// The caller's answer to a far end's whole answer at `status`, read as one document.
    fn whole(&mut self, status: u32) -> PieceAnswer {
        let head = status != 0 && !(200..300).contains(&status);
        let mut unreadable_grpc = false;
        let status = if self.binding == Binding::Grpc {
            if self.far.len() <= MAX_REPLY_BYTES {
                match self.grpc_envelope() {
                    Some(envelope) => self.far = envelope,
                    None => unreadable_grpc = true,
                }
            }
            if head {
                status
            } else {
                STATUS_OK
            }
        } else {
            status
        };

        let rewrapped = match self.binding {
            Binding::HttpJson
                if (200..300).contains(&status) && self.far.len() <= MAX_REPLY_BYTES =>
            {
                crate::answer_bytes::rewrap(&self.far, &self.id)
                    .ok()
                    .map(zeroize::Zeroizing::new)
            }
            _ => None,
        };
        let answer = match self.binding {
            Binding::Grpc if unreadable_grpc && !head => Err(HopRefusal::NotJson),
            Binding::JsonRpc | Binding::Grpc => read_answer(status, &self.far, &self.id),
            Binding::HttpJson => match &rewrapped {
                Some(envelope) => read_answer_document(envelope, &self.id),
                None if !(200..300).contains(&status) => Err(HopRefusal::Status),
                None if self.far.len() > MAX_REPLY_BYTES => Err(HopRefusal::BodyTooLarge),
                None => Err(HopRefusal::NotJson),
            },
        };
        self.reading = Some(self.answer_reading(match &answer {
            Ok(_) | Err(HopRefusal::BackendError) => Reading::Healthy,
            Err(_) => Reading::Transient,
        }));
        self.answered = true;
        if let Err(refusal) = &answer {
            self.journal(*refusal, false);
        }
        let envelope: &[u8] = rewrapped
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .unwrap_or(&self.far);
        let answer = answer.map(|result| &envelope[result]);
        let code = answer
            .as_ref()
            .err()
            .and_then(|refusal| match (self.binding, *refusal) {
                (_, HopRefusal::BackendError) => backend_error_code(&self.far),
                (Binding::HttpJson, HopRefusal::Status) => http_json_error_code(&self.far),
                (Binding::JsonRpc, HopRefusal::Status)
                    if status == 400
                        && self.far.len() <= MAX_REPLY_BYTES
                        && read_answer_document(&self.far, &self.id)
                            == Err(HopRefusal::BackendError) =>
                {
                    backend_error_code(&self.far)
                        .filter(|code| task_identity::status_of_code(*code) == Some(status))
                }
                _ => None,
            });
        let Some(task) = &self.task else {
            return PieceAnswer::ToCaller(match answer {
                Ok(result) => relayed_bytes(&self.id, result),
                Err(refusal) => match code.and_then(|code| {
                    task_identity::status_of_code(code).map(|status| (code, status))
                }) {
                    Some((code, status)) => RelayReply::refused(
                        &AgentRefusal::new(
                            status,
                            Some(self.id.clone()),
                            code,
                            "this agent's backend refused the request",
                        ),
                        None,
                    ),
                    None => refusal.reply(&self.id),
                },
            });
        };

        let spliced = answer.map(|result| {
            let skill = task.skill.as_deref();
            let spliced = crate::answer_bytes::rewrite_identity(
                result,
                (&task_identity::WRAPPERS, &task_identity::KINDS),
                &task.task_id,
                &task.context_id,
                skill.map(|s| (task_identity::SKILL_METADATA_KEY, s)),
                &task.references,
            );
            (result, spliced)
        });
        PieceAnswer::ToCaller(match spliced {
            Ok((_, None)) => {
                self.reading = Some(self.answer_reading(Reading::Transient));
                self.journal(HopRefusal::NotJson, false);
                let (reply, failed) = task_refusal(None, task, &self.id);
                if failed {
                    self.settled.push(TaskSettled::Failed);
                }
                reply
            }
            Ok((result, Some(spliced))) => {
                let spliced = RawBytes::from(spliced);

                let result = crate::answer_bytes::read_json(result).unwrap_or_default();

                let state = if !task.addressed && task_identity::names_no_task(&result) {
                    TaskState::Completed
                } else {
                    task_identity::reported_task_state(&result).unwrap_or(TaskState::Working)
                };
                self.settled.push(TaskSettled::Reported {
                    state,
                    backend_id: task_identity::backend_task_id(&result),
                });
                relayed_bytes(&self.id, &spliced)
            }
            Err(_) => {
                let (reply, failed) = task_refusal(code, task, &self.id);
                if failed {
                    self.settled.push(TaskSettled::Failed);
                }
                reply
            }
        })
    }
}

/// An HTTP+JSON AIP-193 error's A2A identity, since a carrier status alone is not an A2A code and a
/// foreign detail's reason belongs to its own domain.
fn http_json_error_code(body: &[u8]) -> Option<i64> {
    if body.len() > MAX_REPLY_BYTES {
        return None;
    }
    let document = crate::request_json::parse(body).ok()?;
    let details = document.get("error")?.get("details")?.as_array()?;
    details.iter().find_map(|info| {
        if info.get("@type")?.as_str()? != crate::ERROR_INFO_TYPE
            || info.get("domain")?.as_str()? != crate::ERROR_INFO_DOMAIN
        {
            return None;
        }
        let reason = info.get("reason")?.as_str()?;
        crate::ERRORS
            .iter()
            .find(|(_, name)| *name == reason)
            .map(|(code, _)| *code)
    })
}

/// The far end's JSON-RPC error `code`, when it answered one A2A defines, read off the bytes of an
/// answer [`read_answer`] read.
fn backend_error_code(body: &[u8]) -> Option<i64> {
    match crate::answer_bytes::readable(body) {
        std::borrow::Cow::Borrowed(_) => {}
        std::borrow::Cow::Owned(bytes) => {
            drop(RawBytes::from(bytes));
            return None;
        }
    }
    let error = &body[crate::answer_bytes::member_span(body, "error")?];
    crate::request_json::parse(&error[crate::answer_bytes::member_span(error, "code")?])
        .ok()?
        .as_i64()
        .filter(|c| task_identity::status_of_code(*c).is_some())
}

/// The caller's answer to a refused task hop, and whether the task ends `failed`: the far end's own
/// A2A error code travels, its prose never does, and the refusal names the task.
fn task_refusal(code: Option<i64>, task: &TaskHop, id: &Value) -> (RelayReply, bool) {
    let status = code
        .and_then(task_identity::status_of_code)
        .unwrap_or(STATUS_BAD_GATEWAY);
    let (code, message, failed) = match (task.addressed, code) {
        (true, code) => (
            code.unwrap_or(CODE_INVALID_AGENT_RESPONSE),
            "the backend agent refused this request",
            false,
        ),
        (false, Some(code)) => (code, "the backend agent refused this task", true),
        (false, None) => (CODE_INVALID_AGENT_RESPONSE, TASK_UNCOMPLETED, true),
    };
    let refusal = AgentRefusal::new(status, Some(id.clone()), code, message);
    (RelayReply::refused(&refusal, Some(&task.task_id)), failed)
}

#[cfg(test)]
#[path = "tests/relay_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/relay_grpc_tests.rs"]
mod grpc_tests;
