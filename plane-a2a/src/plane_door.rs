// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, SERVED: the slots the kernel calls over the plane ABI, on the SDK's safe
//! surface.

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{GenIn, ReadyIn, RefreshIn, TickIn, TickOut};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneSnapshot, ProjectIn, ProjectOut, RecordWrite,
    RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PIECE_REFUSED, PRINCIPAL_NONE,
    PRINCIPAL_REQUIRED, RECORD_PUT, REFUSAL_ARRIVE, REFUSAL_KERNEL, ROUTE_DIRECT, ROUTE_POOL,
    ROUTE_SCOPE, ROUTE_SCOPE_LOCAL, UNITS_REPORTED, VERDICT_RETRY,
};
use busbar_contract::abi::sdk::conn::{Host, StaticHost};

use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::plane::{cancel_disposition, Ending, UnitCancel};
use busbar_contract::abi::sdk::plane_life::{self, PlaneLife, Published};
use busbar_contract::abi::sdk::publish::{class_index, Generations, Keyed};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot, Services, StaticServices};
use busbar_contract::abi::transport::{
    FAULT_CALLER, FAULT_HARD, FAULT_HEALTHY, FAULT_NONE, FAULT_TRANSIENT,
};

use std::sync::Arc;
use std::task::Poll;

use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};

use crate::a2a::config::AgentsCfg;
use crate::agent_arrival::{self, AgentDisposition, Dialect};
use crate::relay::{self, HopRelay, PieceAnswer, TaskSettled};
use crate::rest::STATUS_NOT_FOUND;
use crate::statement::{self, Line};
use crate::task_door::{kind_index, Via};
use crate::task_hop::{self, Opened};
use crate::tasks::{self, task_key, Halt, Write};

/// The most calls the kernel keeps in flight on one instance, as the transport doors state it.
const MAX_INFLIGHT: u32 = 64;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// The lifecycle section schema, independent of A2A request/card schemas.
const SETTINGS_SCHEMA: &[u8] = include_bytes!("settings.schema.json");

/// The Statement: the plane's name and version, the settings section it declares
/// ([`statement::SECTIONS`]), its three outbound needs ([`statement::NEEDS`]), the secret
/// references its section holds ([`statement::SECRET_REFS`]) and its tail ([`statement::TAIL`]).
pub const STATEMENT: Statement = {
    let mut s = statement(crate::PLANE_KEY, VERSION, MAX_INFLIGHT)
        .with_kind_tail(statement::TAIL)
        .with_sections(statement::SECTIONS)
        .with_needs(statement::NEEDS)
        .with_secret_refs(statement::SECRET_REFS)
        .with_families(statement::FAMILIES);
    s.settings_schema = busbar_contract::abi::mechanism::call::Blob::json(SETTINGS_SCHEMA);
    s.extensions = EXTENSIONS;
    s
};

busbar_contract::statement_extensions!(
    /// The Statement's extensions: this plugin's whole `declares` document.
    /// It states the plane's breaker fact: one transient failure below the trip
    /// threshold never benches an agent's cell — the cell refuses on a TRIP and nothing less, an
    /// upstream `Retry-After` still honoured (docs/a2a.md, "These cells refuse on a trip and nothing
    /// less"). Why no bench: an A2A call's errors are mostly the agent's own answer (an agent says
    /// no), not a sign the agent is unhealthy, so only a trip benches it.
    EXTENSIONS: [(
        busbar_contract::abi::mechanism::extensions::EXT_DECLARES,
        crate::DECLARES.as_bytes()
    ), (
        busbar_contract::abi::sdk::plane::conditional::CAPABILITY,
        b"1"
    ), (
        // Task, event, push configuration and durable quota share conditional publication.
        // Cards (indices 3 and 4) keep their existing ordinary writes.
        busbar_contract::abi::sdk::plane::conditional::REQUIRED_KINDS,
        &[4_u8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0]
    )]
);

/// The most units the instance keeps state for at once; at it, the units the door is done with make
/// room ([`AgentUnit::over`]), so an instance full of live units refuses the next arrival
/// ([`room_for`]).
pub const MAX_UNITS: usize = 4096;

/// One unit the instance keeps, from its arrival: what the arrival was, the agent the caller
/// addressed by name (if it did), the section of the generation it arrived under, and what its
/// pieces carry from one to the next ([`crate::task_door::Pass`]).
#[derive(Debug)]
pub struct AgentUnit {
    /// The arrival, decided.
    pub disposition: AgentDisposition,
    /// The agent a `/a2a/agents/{agent_id}` target names.
    pub agent: Option<String>,
    /// The section of the newest generation when it arrived.
    pub section: Option<Arc<AgentsCfg>>,
    /// The unit's unary hop and what it still owes the host; `None` for a unit `on_piece` does not
    /// serve yet.
    pub hop: Option<Hop>,
    /// The host services its pieces have made so far, and the piece in flight.
    pub pass: crate::task_door::Pass,
    /// The JSON-RPC envelope an HTTP+JSON arrival's request spells ([`crate::rest::compose`]):
    /// what its unit answers and relays in place of the caller's body, its answers re-framed for
    /// the line ([`crate::rest::reframe`]). `None` on the JSON-RPC line.
    pub envelope: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// The rpc a gRPC-line arrival called ([`crate::framed`]): its `envelope` is the JSON-RPC request
    /// the call's message composed, and its answers are transcoded back to the rpc's messages and
    /// status. `None` on every other line.
    pub framed: Option<crate::framed::Rpc>,
    /// The refresh generation it arrived under: the held cards it reads are that generation's.
    pub generation: u64,
    /// `project` refused a committed rewrite it could not read back: `refusal` answers the unit
    /// the internal error ([`unreadable_rewrite`]).
    pub unreadable_rewrite: bool,
    /// The failover pool the unit routes over (`ROUTE_POOL`): the pool its addressed agent is a
    /// member of. `None` for every other unit.
    pub pool: Option<String>,
    /// The unit's own ticket, as its pieces carry it: what the kernel's `cancel` names it by.
    pub ticket: Ticket,
    /// The door is done with it: its answer is written whole, or the kernel cancelled it. Only a
    /// `refusal` may still read it (the kernel judges the plane's last answer after it returns), and
    /// that refusal forgets it; until then it makes room when the instance is full ([`room_for`]).
    pub over: bool,
    /// Request metadata retained for catalogue refusals after payload release.
    ended_shape: Option<crate::skill::TaskShape>,
}

impl AgentUnit {
    /// A unit arriving as `disposition` under `generation`: no hop, envelope, framed call or pool
    /// yet, its pass fresh, its ticket unknown and the door not done with it.
    fn new(
        disposition: AgentDisposition,
        agent: Option<String>,
        section: Option<Arc<AgentsCfg>>,
        generation: u64,
    ) -> Self {
        Self {
            disposition,
            agent,
            section,
            hop: None,
            pass: crate::task_door::Pass::default(),
            envelope: None,
            framed: None,
            generation,
            unreadable_rewrite: false,
            pool: None,
            ticket: Ticket::NONE,
            over: false,
            ended_shape: None,
        }
    }

    /// The door is done with the unit ([`AgentUnit::over`]): what only its hop's pieces read (a
    /// card look in flight and its host stream, the answer bytes and the relayed copies of the
    /// caller's request) is released now, keeping what a `refusal` still reads.
    pub(crate) fn end(&mut self) {
        self.over = true;
        if let Some(envelope) = self.envelope.as_mut() {
            use zeroize::Zeroize;
            envelope.zeroize();
        }
        if let Some(hop) = self.hop.as_mut() {
            self.ended_shape.get_or_insert_with(|| {
                hop.request
                    .as_deref()
                    .map(crate::skill::TaskShape::of)
                    .unwrap_or_default()
            });
            hop.request = None;
            hop.verifying = None;
            hop.outbox = Outbox::default();
            hop.relay.release_payloads();
            hop.rewritten = None;
            hop.held_writes = Vec::new();
        }
    }
}

/// One unit's unary hop, and the answer it is part way through writing.
#[derive(Debug, Default)]
pub struct Hop {
    relay: HopRelay,
    outbox: Outbox,
    /// A task hop whose first ATTEMPT has not yet opened its task (from [`Hop::request`]).
    opening: bool,
    /// The caller's request envelope: what a binding other than JSON-RPC composes from.
    request: Option<crate::request_json::RequestJson>,
    /// What the far end's answer has said about the task, until its record writes are made.
    settle: Vec<TaskSettled>,
    /// The second the piece in flight entered, kept across its re-entries.
    now: Option<u64>,
    /// A subscribe: busbar's own refusal of a task it does not hold live comes before the hop.
    subscribe: bool,
    /// How many of the piece in flight's task moves have queued their push notifications: a
    /// re-entry never queues one twice.
    queued: usize,
    sweep: Option<bool>,
    /// What the piece in flight files for earlier deliveries, taken once across its re-entries.
    owed: Option<Vec<crate::push::OwedReceipt>>,
    /// The ATTEMPT passed the admission gate: its re-entries do not judge it again.
    admitted: bool,
    /// The skill the agent's held card matched at admission.
    skill: Option<String>,
    /// The flight epoch it waits on, while another unit's look at its agent is in flight.
    waits_on: Option<u64>,
    /// Verify-on-call's look, while one of its services is in flight.
    verifying: Option<LookParked>,
    /// The record writes the ATTEMPT made before verify-on-call paused it: they ride with its
    /// answer when it resumes.
    held_writes: Vec<Write>,
    /// The ATTEMPT's agent endpoint was judged by the relay's guard: its re-entries do not judge it
    /// again.
    endpoint_judged: Option<JudgedRelay>,
    /// The hop has LEFT the plane for its agent (its request answered at an ATTEMPT, every gate
    /// of the plane's passed): the unit is served and its fee unit is reported from then on.
    left: bool,
    /// A piece of the far end's answer has come: the agent was reached.
    heard: bool,
    /// The envelope a request-stage rewrite left (`project`'s `rewrite`): what the hop relays
    /// (its task ids translated over it, its binding composed from it). Everything else the hop
    /// reads (the task it opens, the callback it carries, the admission) reads the caller's own
    /// envelope, the params its gate had already screened.
    rewritten: Option<crate::request_json::RequestJson>,
    /// A gRPC send whose request carried no message: its first ATTEMPT mints the message's id
    /// ([`crate::framed::mints_message_id`]) before the task is opened.
    mint_message_id: bool,
    /// The agent the latest ATTEMPT reached (its route entry): the unit's ledger lane and the
    /// resource its audit row names.
    member: String,
    /// The caller's answer to a hop the kernel refused, made once on its refused piece (refused for
    /// busbar's own credential, or left with no answer back, [`hop_refused`]): `refusal` renders
    /// it, and a short `refusal` re-called renders the same again.
    refused: Option<relay::RelayReply>,
    /// A unit over a failover pool: the member holding the task it is about, once its first
    /// ATTEMPT read it off the caller's task records (`Some(None)`: a fresh submission).
    holder: Option<Option<String>>,
    /// A fresh submission the walk placed on a member whose approved card fingerprint is not the
    /// pool primary's: the refusal's words, answered once its task is open.
    mismatch: Option<String>,
    /// The ATTEMPT the pool's gate let go (its number; `0` = none yet): its re-entries do not
    /// judge it again, so the host calls after it keep their handles.
    gated: u32,
    /// The task a breaker refusal rejected (a fresh submission the open breaker refused before
    /// the socket is opened ends `rejected`, and the refusal names its id): kept here on the refused piece, because `refusal` is ticketless and reads no store.
    rejected: Option<String>,
}

impl Hop {
    /// Cancellation releases only a filing that never submitted a mutation: an applied outcome is
    /// acknowledged, and an unknown submitted attempt stays owned by its ticket.
    pub(crate) fn cancel_owed(
        &mut self,
        deliveries: &crate::push::Deliveries,
        journal: &crate::conditional_publication::Journal,
    ) {
        if let Some(owed) = &self.owed {
            for receipt in owed {
                match journal.owed_decision(receipt) {
                    Some(true) => deliveries.acknowledge_owed(receipt),
                    Some(false) => deliveries.release_owed(receipt),
                    None => {}
                }
            }
        }
    }

    /// A task-less hop answering the request `id`, declaring `version`.
    #[must_use]
    pub fn new(id: serde_json::Value, version: &'static str) -> Self {
        Hop {
            relay: HopRelay::new(id, version),
            ..Hop::default()
        }
    }

    /// A task-less hop for the request `envelope`.
    #[must_use]
    pub fn of(
        id: serde_json::Value,
        version: &'static str,
        envelope: Option<serde_json::Value>,
    ) -> Self {
        Hop {
            request: envelope.map(crate::request_json::RequestJson::new),
            ..Hop::new(id, version)
        }
    }

    /// A hop about a task: `envelope` opens it at the first ATTEMPT.
    #[must_use]
    pub fn task(id: serde_json::Value, version: &'static str, envelope: serde_json::Value) -> Self {
        Hop {
            opening: true,
            request: Some(crate::request_json::RequestJson::new(envelope)),
            ..Hop::new(id, version)
        }
    }

    /// Whether the hop's answer is a stream of events (a streaming hop).
    #[must_use]
    pub fn streams(&self) -> bool {
        self.relay.expects_events()
    }

    /// A task hop that receives event streams and optionally subscribes to an existing task.
    #[must_use]
    pub fn events(
        id: serde_json::Value,
        version: &'static str,
        envelope: serde_json::Value,
        subscribe: bool,
    ) -> Self {
        let mut hop = Hop::task(id, version, envelope);
        hop.relay.expect_events();
        hop.subscribe = subscribe;
        hop
    }
}

/// What a piece's answer still owes the host: its head, once, then its bytes, `reply_cap` at a
/// time. `live` while any of it is unwritten; `recall` after a short answer, whose re-call carries
/// the same piece and must not apply it twice.
#[derive(Debug, Default)]
struct Outbox {
    /// The bytes to write are the caller's piece itself, lent by the host for this call
    /// ([`PieceAnswer::ToFarEndLent`]): written straight from it, and only what the host's buffer could
    /// not take is kept in `bytes`.
    lent: bool,
    live: bool,
    recall: bool,
    to_far: bool,
    done: bool,
    head: Option<AnswerHead>,
    bytes: relay::RawBytes,
    at: usize,
    /// The record writes that ride with the head.
    writes: Vec<Write>,
    /// On the gRPC line: the messages after `bytes`, each emitted on an answer of its own.
    queue: std::collections::VecDeque<relay::RawBytes>,
    /// On the gRPC line: `bytes` (and each queued one) is a message, its last byte a message
    /// boundary (`EMIT_MESSAGE_END`); `false` for a status's message text.
    messages: bool,
    /// On the gRPC line: the status the call ends with when it is not a whole `OK` answer (a
    /// stream's last status, or a whole answer's error), stated on its closing answer
    /// (`EMIT_FINAL_STATUS`).
    final_status: Option<crate::framed::FramedReply>,
    /// The breaker's reading of the far end's answer this piece read (`FAULT_NONE` = none yet),
    /// stated on the answer that writes it ([`relay::Reading`]).
    fault: u8,
}

#[derive(Debug)]
struct JudgedRelay {
    attempt: u32,
    member: String,
    url: String,
    within: String,
}

/// The head an answer starts with.
#[derive(Debug)]
enum AnswerHead {
    /// The request bound for the far end: verb, target, fields.
    Attempt(relay::Attempt),
    /// The caller's reply: its status and media type.
    Reply(u32, &'static str),
    /// The caller's reply in events: `200`, an event stream nothing may cache.
    Events,
    /// The caller's reply on the gRPC line: the listener's `200` and the line's media type, no length. The
    /// call's status is its final status ([`Outbox::final_status`], `OK` when none is stated),
    /// which the stream's framer renders on its close (SEAM-4l).
    Framed,
}

/// The head field a whole answer states its length in.
pub(crate) const H_CONTENT_LENGTH: &str = "content-length";

/// The head fields an answer in events starts with.
const EVENTS_HEAD: [(&str, &str); 2] = [
    (relay::H_CONTENT_TYPE, crate::events::EVENTS_MEDIA_TYPE),
    ("cache-control", "no-store"),
];

impl Outbox {
    /// Write the remaining suffix and retain the cursor after a short host write.
    fn drain(&mut self, write: impl FnOnce(&[u8]) -> usize) -> usize {
        let n = write(&self.bytes[self.at..]);
        self.at += n;
        n
    }

    /// The outbox for `answer`; `None` for a piece the hop refuses.
    fn of(answer: PieceAnswer) -> Option<Self> {
        let lent = matches!(answer, PieceAnswer::ToFarEndLent);
        let (to_far, done, head, bytes) = match answer {
            PieceAnswer::Nothing => (false, false, None, relay::RawBytes::default()),
            PieceAnswer::Refused => return None,
            PieceAnswer::Attempt(a) => (
                true,
                false,
                Some(AnswerHead::Attempt(a)),
                relay::RawBytes::default(),
            ),
            PieceAnswer::ToFarEnd(bytes) => (true, false, None, bytes),
            PieceAnswer::ToFarEndLent => (true, false, None, relay::RawBytes::default()),
            PieceAnswer::ToCaller(mut r) => (
                false,
                true,
                Some(AnswerHead::Reply(r.status, r.content_type)),
                std::mem::take(&mut r.body).into(),
            ),
            PieceAnswer::Part(mut part) => (
                false,
                part.last,
                part.head.then_some(AnswerHead::Events),
                std::mem::take(&mut part.body).into(),
            ),
        };
        Some(Outbox {
            lent,
            live: true,
            to_far,
            done,
            head,
            bytes,
            ..Outbox::default()
        })
    }

    /// The outbox for `answer` on the gRPC line, the rpc `rpc`: a whole answer is the rpc's one
    /// message, or the status it ends with, and an answer in events is one message per event, each
    /// on an answer of its own, an `error` event ending the stream.
    fn framed(answer: PieceAnswer, rpc: crate::framed::Rpc) -> Option<Self> {
        match answer {
            PieceAnswer::ToCaller(mut r) => {
                let body = zeroize::Zeroizing::new(std::mem::take(&mut r.body));
                Some(Self::framed_whole(crate::framed::framed_reply(
                    rpc, r.status, &body,
                )))
            }
            PieceAnswer::Part(mut part) => {
                let body = zeroize::Zeroizing::new(std::mem::take(&mut part.body));
                let (messages, terminal) = crate::framed::event_messages(rpc, &body);
                if let Some(status) = terminal.clone() {
                    if part.head && messages.is_empty() {
                        return Some(Self::framed_whole(status.into()));
                    }
                }
                let emits = !messages.is_empty();
                let mut queue: std::collections::VecDeque<relay::RawBytes> =
                    messages.into_iter().map(Into::into).collect();
                let bytes = queue.pop_front().unwrap_or_default();
                Some(Outbox {
                    live: true,
                    done: part.last || terminal.is_some(),
                    head: part.head.then_some(AnswerHead::Framed),
                    bytes,
                    queue,
                    messages: emits,
                    final_status: terminal.map(Into::into),
                    ..Outbox::default()
                })
            }
            other => Self::of(other),
        }
    }

    /// A whole reply on the gRPC line: an `OK` answer is its one message, the stream closing as one
    /// that ended whole; any other status is no message, and the call ends with it as its final
    /// status (its message and details), rendered by the stream's framer (SEAM-4l).
    fn framed_whole(mut reply: crate::framed::FramedReply) -> Self {
        let ok = reply.code == crate::framed::Code::Ok as u32;
        let (bytes, final_status) = if ok {
            (std::mem::take(&mut reply.body).into(), None)
        } else {
            (relay::RawBytes::default(), Some(reply))
        };
        Outbox {
            live: true,
            done: true,
            messages: ok,
            head: Some(AnswerHead::Framed),
            bytes,
            final_status,
            ..Outbox::default()
        }
    }
}

/// ONE REQUEST BUSBAR ORIGINATES ([`crate::mirror::Originated`]): its agent's url judged as a
/// relayed hop's endpoint is, then `method` with `params` sent over the agent's need naming its
/// registration.
pub(crate) fn drive_originated(
    plane: &A2aDoor,
    ticket: Ticket,
    hop: &mut crate::mirror::Originated,
    method: &str,
    params: &serde_json::Value,
) -> Poll<crate::mirror::Landed> {
    use busbar_contract::abi::sdk::exchange::{exchange, Exchange};
    if hop.exchange.is_none() {
        let standing = plane.trust.get(&hop.agent).unwrap_or_default();
        if !kernel_serves(plane, &hop.agent, &standing) {
            return Poll::Ready(Ok(None));
        }
        let at = LookAt {
            plane,
            generation: plane.newest(),
            ticket,
            base: hop.seq,
        };
        let within = match judge_hop(&at, &hop.url, hop.allow_private, hop.seq) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Ok(None)),
            Poll::Ready(Ok((next, within))) => {
                hop.seq = next;
                within
            }
        };
        let request = crate::mirror::request(hop.binding, &hop.url, hop.version, method, params)
            .and_then(|r| Exchange::request(r).ok());
        let Some(ex) = request else {
            return Poll::Ready(Ok(None));
        };
        let ex = ex.landing_within(within).as_member(hop.agent.clone());
        hop.exchange = Some((hop.seq, Box::new(ex)));
    }
    let Some(host) = plane.host.as_ref() else {
        hop.exchange = None;
        return Poll::Ready(Ok(None));
    };
    let Some((start, ex)) = hop.exchange.as_mut() else {
        return Poll::Ready(Ok(None));
    };
    let mut conn = host.connector_from(ticket, *start);
    let need = match hop.binding {
        crate::binding::Binding::Grpc => statement::NEED_GRPC,
        crate::binding::Binding::JsonRpc | crate::binding::Binding::HttpJson => {
            statement::NEED_AGENT
        }
    };
    match exchange(&mut conn, ex, need, Some(&hop.url)) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(answer) => {
            hop.seq = conn.issued();
            hop.exchange = None;
            Poll::Ready(crate::mirror::landed(
                hop.binding,
                &hop.agent,
                method,
                answer,
            ))
        }
    }
}

/// The mirror ([`crate::mirror::Flight`]): each stage's request originated, until its last stage is
/// answered or one is refused for the agent's unavailable credential.
pub(crate) fn drive_mirror(
    plane: &A2aDoor,
    ticket: Ticket,
    flight: &mut crate::mirror::Flight,
) -> Poll<()> {
    while flight.stage != crate::mirror::Stage::Done {
        let (method, params) = (
            flight.issuing(),
            crate::request_json::RequestJson::new(flight.params()),
        );
        match drive_originated(plane, ticket, &mut flight.hop, method, &params) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(landed) => flight.land(match &landed {
                Ok(answered) => Ok(answered.as_ref().map(|(s, b)| (*s, b.as_slice()))),
                Err(unleased) => Err(*unleased),
            }),
        }
    }
    Poll::Ready(())
}

type CardWarmSnapshot = (u64, Option<Arc<AgentsCfg>>);

/// One instance: the public base URL `open` was given, the host tables, every live generation's
/// snapshot and section, the units in flight, whether (and when) the task records were restored,
/// and the far end's own id for each relayed task busbar learnt it for.
pub struct A2aDoor {
    /// Conditional intent bytes remain leased until the host releases their answer.
    pub(crate) publication_leases: busbar_contract::abi::sdk::life::Leases,
    pub(crate) public_url: Option<String>,
    pub(crate) host: Option<StaticHost>,
    pub(crate) services: Option<StaticServices>,
    generations: Generations<PlaneSnapshot, AgentsCfg>,
    pub(crate) units: Keyed<u64, AgentUnit>,
    arrival_gate: std::sync::Mutex<()>,
    card_publication: std::sync::Mutex<()>,
    cleanup_pending: std::sync::atomic::AtomicBool,
    pub(crate) restored: crate::task_door::Restore,
    /// `<caller>/<busbar task id>` to the far end's own id for the task: plane memory, so a
    /// restart forgets it (its bound included).
    backends: BackendIds,
    /// The agents' verified cards, held in plugin memory to their refresh generation.
    pub(crate) cards: crate::cards::Cards,
    pub(crate) card_cache: crate::served_card_cache::CardCache,
    /// The held cards were warmed from the `card` and `card_approval` host records after `open`,
    /// both listings landed ([`warm_cards`]).
    cards_warmed: Keyed<(), bool>,
    /// A warm's listing was refused and said so ([`warm_unlisted`]) since a warm last landed.
    warm_unlisted: Keyed<(), bool>,
    /// The registration snapshot captured before a warm issues its first listing.
    warming: Keyed<(u32, u32), CardWarmSnapshot>,
    /// The host refused the last tick's (or its drive's) warm: the next tick attempts the
    /// deliveries, and the one after warms again, so a store that keeps refusing the listing never
    /// holds the deliveries up.
    warm_refused: Keyed<(), bool>,
    /// The part records ([`crate::split_record`]) the store may hold under each `(kind, key)` of a
    /// card or an approval, as far as this instance knows ([`HeldParts`]).
    record_parts: Keyed<(&'static str, String), HeldParts>,
    /// A `tick`'s warm of the held cards pended on the driver ticket: the `drive` its wake runs
    /// carries it on, on the same handles, before anything else the drive does.
    warm_driving: Keyed<(), bool>,
    /// The push notifications waiting for delivery, and the webhook credentials they present.
    pub(crate) deliveries: crate::push::Deliveries,
    /// The delivery attempt in flight across a PENDING `tick`, which `drive` carries on.
    pub(crate) attempting: crate::push_door::Attempting,
    /// Busbar's own callback tokens, by the task each names ([`crate::push::Tokens`]).
    pub(crate) tokens: crate::push::Tokens,
    /// The push-volume bound on busbar's own callback ([`crate::push::PushLimiter`]).
    pub(crate) pushes: crate::push::PushLimiter,
    pub(crate) sweeps: tasks::SweepGate,
    /// The newest refresh generation published.
    newest: Keyed<(), u64>,
    /// The registrations a `refresh` keeps unchanged, whose current approvals publication keeps.
    kept_registrations: Keyed<(), std::collections::BTreeSet<String>>,
    /// The sizes short host-records answers named, per handle ([`crate::task_door::Grown`]).
    pub(crate) grown: crate::task_door::Grown,
    /// Each agent's verify-on-call flight: one look at a time.
    pub(crate) flights: Flights,
    /// Each registered agent's trust: the skills of the card an operator approved (`approve`), the
    /// last sighting of its card and verify-on-call's ledger. The approved skills are also its
    /// `card_approval` host record, warmed back after `open` ([`warm_cards`]); the sighting and the
    /// ledger are plane memory, so a restart looks again (a ledger that never looked is due).
    pub(crate) trust: Keyed<String, crate::card_trust::TrustStanding>,
    /// The error-once latches of the record writes the store refused ([`crate::task_hop::Latches`]).
    pub(crate) latches: crate::task_hop::Latches,
}

impl Default for A2aDoor {
    fn default() -> Self {
        Self {
            publication_leases: Default::default(),
            public_url: Default::default(),
            host: Default::default(),
            services: Default::default(),
            generations: Default::default(),
            units: Keyed::sharded(),
            arrival_gate: Default::default(),
            card_publication: Default::default(),
            cleanup_pending: Default::default(),
            restored: Default::default(),
            backends: Default::default(),
            cards: Default::default(),
            card_cache: Default::default(),
            cards_warmed: Default::default(),
            warm_unlisted: Default::default(),
            warming: Default::default(),
            warm_refused: Default::default(),
            record_parts: Default::default(),
            warm_driving: Default::default(),
            deliveries: Default::default(),
            attempting: Default::default(),
            tokens: Default::default(),
            pushes: Default::default(),
            sweeps: Default::default(),
            newest: Default::default(),
            kept_registrations: Default::default(),
            grown: Default::default(),
            flights: Default::default(),
            trust: Default::default(),
            latches: Default::default(),
        }
    }
}

impl A2aDoor {
    pub(crate) fn unit_ended(&self) {
        self.cleanup_pending
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Run `f` over unit `unit`, when the instance still keeps it.
    pub(crate) fn on_unit(&self, unit: u64, f: impl FnOnce(&mut AgentUnit)) {
        self.units.with(&unit, |u| u.map(f));
    }

    /// The agent's own id for `caller`'s task `task_id`, once the agent named it.
    pub(crate) fn backend_of(&self, caller: &str, task_id: &str) -> Option<String> {
        self.backends.get(&task_key(caller, task_id))
    }

    pub(crate) fn remember_backend(&self, row: &crate::TaskRow, backend: String) {
        if backend == row.task_id {
            return;
        }
        let bytes = backend.len();
        if !self.backends.record(
            MAX_BACKEND_IDS,
            task_key(&row.principal, &row.task_id),
            backend,
        ) {
            busbar_contract::diag_warn!(crate::diagnostics::A2A_BACKEND_TASK_ID_UNHELD,
                task = %row.task_id, bytes,
                "a2a: the agent's own task id ({bytes} bytes) is longer than the plane holds; the task keeps busbar's id");
        }
    }

    /// The newest refresh generation published; `0` before `open`.
    fn newest(&self) -> u64 {
        self.newest.get(&()).unwrap_or(0)
    }

    /// `refresh`: the new section judged, the applied `agent_push:` section (`owned`, the
    /// document's other owned sections) judged as `open` judges it, and the next generation's
    /// snapshot over the same public base URL.
    fn refreshed(
        &self,
        settings: &[u8],
        owned: &[u8],
        generation: u64,
    ) -> Result<Published<AgentsCfg>, Refusal> {
        let plane = self;
        let cfg = agents_section(settings)?;
        statement::read_push_section(owned).map_err(Refusal::refused)?;
        let names: Vec<&str> = cfg.agents.keys().map(String::as_str).collect();
        let spec = statement::agents_snapshot_spec(plane.public_url.as_deref(), &names);

        let held_at = plane.newest();
        let before = plane.generations.at(held_at);
        let mut kept_names = std::collections::BTreeSet::new();
        for (name, def) in &cfg.agents {
            let kept = before
                .as_ref()
                .and_then(|b| b.agents.get(name))
                .is_some_and(|was| was == def);
            if let Some(card) = plane.cards.at(name, held_at).filter(|_| kept) {
                plane.cards.hold_shared(name, generation, card);
            }

            if kept {
                kept_names.insert(name.clone());
            }
        }

        plane.kept_registrations.insert((), kept_names);
        Ok(Published { spec, held: cfg })
    }
}

/// The held cards, warmed from the `card` host records (the `connect` and `approve` answers write
/// them, keeping every write on an answer): every agent's recorded card held under the newest
/// generation, so an instance opened again serves the agents its operator approved before.
fn warm_cards(plane: &A2aDoor, ticket: Ticket, issued: u32) -> (Poll<bool>, u32) {
    use crate::tasks::Records;
    let Some(host) = plane.host.as_ref() else {
        return (Poll::Ready(true), issued);
    };
    let key = (ticket.slot, ticket.generation);
    let (generation, section) = plane.warming.with_all(|m| {
        m.entry(key)
            .or_insert_with(|| {
                let generation = plane.newest();
                (generation, plane.generations.at(generation))
            })
            .clone()
    });
    let mut via = Via::new(host, plane.services, ticket, issued, &plane.grown);
    let cards = match via.list(crate::records::KIND_CARD, "") {
        Err(Halt::Pending) => return (Poll::Pending, via.issued()),
        Err(Halt::Failed(why)) => {
            warm_unlisted(plane, crate::records::KIND_CARD, &why);
            plane.warming.remove(&key);
            return (Poll::Ready(false), via.issued());
        }
        Ok(rows) => rows,
    };
    let (approvals, landed) = match via.list(crate::records::KIND_CARD_APPROVAL, "") {
        Err(Halt::Pending) => return (Poll::Pending, via.issued()),
        Err(Halt::Failed(why)) => {
            warm_unlisted(plane, crate::records::KIND_CARD_APPROVAL, &why);
            (Vec::new(), false)
        }
        Ok(rows) => (rows, true),
    };
    let issued = via.issued();
    plane.warming.remove(&key);
    if landed {
        plane.warm_unlisted.remove(&());
    }

    let Some(section) = section.filter(|_| plane.generations.at(generation).is_some()) else {
        return (Poll::Ready(false), issued);
    };
    let current_generation = plane.newest();
    let current = plane.generations.at(current_generation);
    let cards = joined(plane, crate::records::KIND_CARD, cards);
    let approvals = joined(plane, crate::records::KIND_CARD_APPROVAL, approvals);
    for (agent, value) in cards {
        let Some(original) = section.agents.get(&agent) else {
            continue;
        };
        match crate::request_json::parse(&value) {
            Ok(card) => {
                if plane
                    .cards
                    .hold_if_none(&agent, generation, card.into_value())
                    && current_generation != generation
                    && current.as_ref().and_then(|s| s.agents.get(&agent)) == Some(original)
                {
                    if let Some(card) = plane.cards.at(&agent, generation) {
                        plane
                            .cards
                            .hold_shared_if_absent(&agent, current_generation, card);
                    }
                }
            }
            Err(e) => record_unread(crate::records::KIND_CARD, &agent, &e),
        }
    }
    for (agent, value) in approvals {
        let Some(original) = section.agents.get(&agent) else {
            continue;
        };
        if current.as_ref().and_then(|s| s.agents.get(&agent)) != Some(original) {
            continue;
        }
        let approved = match crate::request_json::from_slice::<
            std::collections::BTreeMap<String, String>,
        >(&value)
        {
            Ok(approved) => approved,
            Err(e) => {
                record_unread(crate::records::KIND_CARD_APPROVAL, &agent, &e);
                continue;
            }
        };
        plane.trust.with_all(|standings| {
            let standing = standings.entry(agent).or_default();
            if standing.approved.is_none() {
                standing.approved = Some(approved);
            }
        });
    }
    (Poll::Ready(landed), issued)
}

/// A listing of the held `kind` the host refused at a warm: said once until a warm lands, so a
/// store that keeps refusing it is named in the plugin's log without a line on every tick.
fn warm_unlisted(plane: &A2aDoor, kind: &str, _why: &str) {
    if plane.warm_unlisted.insert((), true).is_none() {
        tracing::warn!(
            kind,
            "a2a: the host refused the listing of the stored {kind} records; the agents' \
             cards stay unwarmed and the listing is retried on a later tick"
        );
    }
}

/// A record that could not be read leaves its agent without that restored card or approval.
fn record_unread(kind: &str, agent: &str, e: &serde_json::Error) {
    busbar_contract::diag_warn!(
        crate::diagnostics::A2A_CARD_RECORD_UNREAD,
        kind,
        agent = %agent,
        "a2a: agent `{agent}`'s stored {kind} record could not be read ({e}); the agent is looked \
         at afresh and the record is written again on its next connect or approve"
    );
}

/// How soon after a tick that left the held cards unwarmed (the host refused their listing) the
/// tick that warms them again is asked for, at the latest: a second.
const WARM_AGAIN_NS: u64 = 1_000_000_000;

/// One held kind's listed `rows` read back whole ([`crate::split_record::rejoin`]): a card or an
/// approval past the host's record ceiling is reassembled from its parts and verified.
fn joined(
    plane: &A2aDoor,
    kind: &'static str,
    rows: Vec<(String, Vec<u8>)>,
) -> Vec<(String, Vec<u8>)> {
    use crate::split_record::{is_part, owner};
    let listed: Vec<String> = rows
        .iter()
        .filter(|(key, _)| is_part(key))
        .map(|(key, _)| key.clone())
        .collect();
    let joined = crate::split_record::rejoin(rows);
    plane.record_parts.with_all(|known| {
        for part in listed {
            let held = known.entry((kind, owner(&part).to_string())).or_default();
            if !held.current.contains(&part) && !held.retired.contains(&part) {
                held.retired.push(part);
                held.carried = false;
            }
        }
    });
    for (agent, why) in &joined.refused {
        busbar_contract::diag_warn!(
            crate::diagnostics::A2A_SPLIT_RECORD_UNREAD,
            kind,
            agent = %agent,
            why,
            "an A2A {kind} record split across host records was not read back whole: {why}; the \
             agent is looked at afresh and the record is written again on its next connect or approve"
        );
    }
    if !joined.stray.is_empty() {
        busbar_contract::diag_warn!(
            crate::diagnostics::A2A_SPLIT_RECORD_STRAY_PARTS,
            kind,
            parts = joined.stray.len(),
            "A2A {kind} part records that no whole record names were found; each is tombstoned on \
             its agent's next connect or approve"
        );
    }
    joined.whole
}

/// The `card` host records of `agent`'s verified `card`: keyed by the agent's id under the
/// operator's scope (no caller prefix), split across records under the host's ceiling
/// ([`kept_records`]).
fn card_records(plane: &A2aDoor, agent: &str, card: &serde_json::Value) -> Vec<Write> {
    crate::relay::json_bytes(card)
        .map(|value| kept_records(plane, crate::records::KIND_CARD, agent, &value))
        .unwrap_or_default()
}

/// The `card_approval` host records of the skills (`id -> digest`) of the card the operator
/// approved for `agent`: keyed like its `card` records ([`kept_records`]).
fn approval_records(
    plane: &A2aDoor,
    agent: &str,
    approved: &std::collections::BTreeMap<String, String>,
) -> Vec<Write> {
    crate::relay::json_bytes(approved)
        .map(|value| kept_records(plane, crate::records::KIND_CARD_APPROVAL, agent, &value))
        .unwrap_or_default()
}

/// The part records a key may hold in the store: those its last written value names (`current`),
/// and every other one this instance knows of (`retired`: a value's it replaced, and what the warm
/// listed), which each write of the key tombstones. A write of the value `current` already names
/// (an unchanged card, or the kernel's re-call of a short answer) tombstones `retired` again, so an
/// answer that was never written still tombstones what it should.
///
/// BOUNDED: a change of value retires the parts of the value it replaces; the parts an earlier
/// change retired were tombstoned by that change's answer and are not carried on (a part an answer
/// that was never written left in the store is a stray the next warm lists and retires again).
/// The parts the warm listed are carried until one write has tombstoned them (`carried`).
#[derive(Debug, Clone, Default)]
struct HeldParts {
    current: Vec<String>,
    retired: Vec<String>,
    /// A write of the key has tombstoned `retired` since the warm listed them.
    carried: bool,
}

/// The host records that keep `value` under `agent` of `kind`, whatever its length: a record is at
/// most [`busbar_contract::bounded::MAX_RECORD_BYTES`] (busbar dev's store refuses a longer one,
/// and the kernel answers the whole verb `500` for a write it cannot make), so a longer value is
/// its parts, then its head ([`crate::split_record::split_value`]); then a tombstone of every part
/// the store may hold under the key that the new value does not name ([`HeldParts`]), written after
/// the head, so no head is ever left naming a part that is gone.
fn kept_records(plane: &A2aDoor, kind: &'static str, agent: &str, value: &[u8]) -> Vec<Write> {
    let mut writes = crate::split_record::split_value(kind, agent, value);
    let named: Vec<String> = writes
        .iter()
        .filter(|w| crate::split_record::is_part(&w.key))
        .map(|w| w.key.clone())
        .collect();
    let retired = plane.record_parts.with_all(|known| {
        let held = known.entry((kind, agent.to_string())).or_default();
        if held.current != named {
            let mut retired = std::mem::take(&mut held.current);
            if !held.carried {
                retired.append(&mut held.retired);
            }
            retired.retain(|part| !named.contains(part));
            retired.sort();
            retired.dedup();
            *held = HeldParts {
                current: named.clone(),
                retired,
                carried: false,
            };
        }
        held.carried = true;
        held.retired.clone()
    });
    writes.extend(retired.into_iter().map(|key| Write {
        kind,
        key,
        value: Vec::new(),
    }));
    writes
}

/// A whole serve answer (a trust verb's, a push callback's): `status`, the head `fields`, `body`,
/// the `AUDIT_*` row, and the record `writes` it carries, every span in the one arena; a short
/// buffer answers FAILED with what each needs.
pub(crate) fn verb_answer(
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    (status, head, body): (u32, &[(&str, &str)], &[u8]),
    audit: u32,
    writes: &[Write],
) -> Outcome {
    let (mut reply, mut fields, mut arena, mut records) = (
        input.reply_buf(),
        input.fields_buf(),
        input.arena_buf(),
        input.records_buf(),
    );
    reply.extend(body);
    for (name, value) in head {
        fields.push(OutField {
            name: arena.span(name.as_bytes()),
            value: arena.span(value.as_bytes()),
        });
    }
    for w in writes {
        records.push(RecordWrite {
            kind: kind_index(w.kind),
            op: RECORD_PUT,
            key: arena.span(w.key.as_bytes()),
            value: arena.span(&w.value),
        });
    }
    let short = !(reply.fits() && fields.fits() && arena.fits() && records.fits());
    let (rw, rnd) = reply.settle(short);
    let (fw, fnd) = fields.settle(short);
    let (cw, cnd) = records.settle(short);
    let (aw, and) = arena.settle(short);
    out.set(|o| &o.reply_written, rw as u64);
    out.set(|o| &o.reply_needed, rnd as u64);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.records_written, cw as u32);
    out.set(|o| &o.records_needed, cnd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    if short {
        return Outcome::Failed;
    }
    out.set(|o| &o.status, status);
    out.set(|o| &o.audit, audit);
    Outcome::Ready
}

/// The most far-end task ids the instance remembers.
pub const MAX_BACKEND_IDS: usize = 100_000;

/// The longest far-end task id the instance holds, in bytes: the far end's id is untrusted input,
/// so the map is bounded in bytes as well as in entries ([`MAX_BACKEND_IDS`]).
pub const MAX_BACKEND_ID_BYTES: usize = 1024;

/// Maximum retained task-key bytes per backend-id entry.
const MAX_BACKEND_KEY_BYTES: usize = 4096;

/// Combined string payload budget, counting both stored copies of each key.
const MAX_BACKEND_BYTES: usize = 8 * 1024 * 1024;

/// The far end's own task ids, by `<caller>/<busbar task id>`, bounded: past the bound the id
/// recorded longest ago is forgotten first, whichever caller it is for, so one caller's volume
/// never pushes out another caller's newer ids because of how their references sort.
#[derive(Debug, Default)]
pub(crate) struct BackendIds(Keyed<(), Recorded>);

/// The ids, each with when it was first recorded, and that order.
#[derive(Debug, Default)]
struct Recorded {
    ids: std::collections::BTreeMap<String, (u64, String)>,
    order: std::collections::BTreeMap<u64, String>,
    next: u64,
    bytes: usize,
}

impl BackendIds {
    /// The far end's id held under `key`.
    pub(crate) fn get(&self, key: &str) -> Option<String> {
        self.0.with(&(), |r| {
            r.and_then(|r| r.ids.get(key).map(|(_, id)| id.clone()))
        })
    }

    /// Hold `id` under `key`, past `cap` forgetting the id recorded longest ago (a key held already
    /// keeps its place), and answer `false` for an id longer than [`MAX_BACKEND_ID_BYTES`], which
    /// is not held.
    pub(crate) fn record(&self, cap: usize, key: String, id: String) -> bool {
        if cap == 0 || id.len() > MAX_BACKEND_ID_BYTES || key.len() > MAX_BACKEND_KEY_BYTES {
            return false;
        }
        self.0.with_all(|m| {
            let r = m.entry(()).or_default();
            let cost = key.len() * 2 + id.len();
            if let Some((_, held)) = r.ids.get_mut(&key) {
                let next_bytes = r.bytes - held.len() + id.len();
                if next_bytes <= MAX_BACKEND_BYTES {
                    r.bytes = next_bytes;
                    *held = id;
                    return;
                }
            }
            let previous = r.ids.remove(&key).map(|(at, held)| {
                r.order.remove(&at);
                r.bytes -= key.len() * 2 + held.len();
                at
            });
            while r.ids.len() >= cap || r.bytes + cost > MAX_BACKEND_BYTES {
                let Some((_, oldest)) = r.order.pop_first() else {
                    break;
                };
                if let Some((_, held)) = r.ids.remove(&oldest) {
                    r.bytes -= oldest.len() * 2 + held.len();
                }
            }
            let at = previous.unwrap_or_else(|| {
                let at = r.next;
                r.next += 1;
                at
            });
            r.bytes += cost;
            r.order.insert(at, key.clone());
            r.ids.insert(key, (at, id));
        });
        true
    }
}

/// The settings blob read as the `agents:` section, or the refusal in the grammar's words.
fn agents_section(bytes: &[u8]) -> Result<AgentsCfg, Refusal> {
    statement::read_agents_section(bytes).map_err(Refusal::refused)
}

/// Check capacity under the arrival gate, reclaiming ended units only after a new completion.
fn room_for(plane: &A2aDoor, key: u64) -> bool {
    if plane.units.len() < MAX_UNITS || plane.units.with(&key, |unit| unit.is_some()) {
        return true;
    }
    if !plane
        .cleanup_pending
        .swap(false, std::sync::atomic::Ordering::AcqRel)
    {
        return false;
    }
    plane.units.with_all(|units| {
        units.retain(|_, unit| !unit.over);
        units.len() < MAX_UNITS
    })
}

/// How many trailing-separator agent claims the current generation's snapshot states (R-16).
fn agent_claims(plane: &A2aDoor) -> usize {
    plane.generations.current().map_or(0, |s| {
        statement::agent_claim_count(s.agents.keys().map(String::as_str))
    })
}

/// The agent a JSON-RPC target names below the catalogue, if it names one.
fn agent_of(target: &str) -> Option<String> {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        ["a2a", "agents", id] | ["a2a", "agents", id, ".well-known", "agent-card.json"] => {
            Some((*id).to_string())
        }
        _ => None,
    }
}

/// [`ArriveOut::refusal`]: the arrival is refused in the plane's own words, at its own status (the
/// words ride in the head's error, and `refusal` renders them).
pub const REFUSED_IN_OWN_WORDS: u32 = 1;

/// [`ArriveOut::refusal`]: no line of this door serves the arrival (a 404).
pub const UNSERVED: u32 = 2;

/// REFUSED in the plane's own words, at its own status: `refusal` renders them in the line's
/// dialect.
fn refused(out: &mut Out<'_, ArriveOut>, refusal: &agent_arrival::AgentRefusal) -> Outcome {
    out.set(|o| &o.refusal, REFUSED_IN_OWN_WORDS);
    out.set(|o| &o.refusal_status, refusal.status);
    out.fail(Refusal::refused(refusal.words()))
}

/// The status a gRPC call is refused with at its arrival, as the refusal its line renders it from
/// (the JSON-RPC code [`crate::framed::grpc_code`] maps back to it, and its message).
fn framed_refusal(status: &crate::framed::CallStatus) -> agent_arrival::AgentRefusal {
    use crate::framed::Code;
    let code = match status.code() {
        Code::Unimplemented => -32601,
        Code::InvalidArgument => agent_arrival::CODE_INVALID_PARAMS,
        _ => -32603,
    };
    agent_arrival::AgentRefusal::new(
        agent_arrival::STATUS_BAD_REQUEST,
        None,
        code,
        status.message().to_string(),
    )
}

/// REFUSED as UNSERVED (a `404`): no line of this door serves the arrival, a route it does not
/// claim, a target its line does not read, or a request whose method names no operation class.
fn unserved(out: &mut Out<'_, ArriveOut>) -> Outcome {
    out.set(|o| &o.refusal, UNSERVED);
    out.set(|o| &o.refusal_status, STATUS_NOT_FOUND);
    out.fail(Refusal::bare())
}

/// A gRPC call's head field `name`, over the call's own fields (`field`): no media type and no
/// `Origin` to judge, and the version its `a2a-version` names, the line's own (`1.0`) when it names
/// none: absent, empty, or nothing but whitespace (the version is read trimmed, so a blank one
/// would otherwise read as the JSON-RPC line's default).
fn framed_field<'a>(field: impl Fn(&str) -> Option<&'a str>, name: &str) -> Option<&'a str> {
    if name.eq_ignore_ascii_case(agent_arrival::H_VERSION) {
        field(name)
            .filter(|v| !v.trim().is_empty())
            .or(Some(crate::framed::DEFAULT_VERSION))
    } else if name.eq_ignore_ascii_case(agent_arrival::H_CONTENT_TYPE)
        || name.eq_ignore_ascii_case(agent_arrival::H_ORIGIN)
    {
        None
    } else {
        field(name)
    }
}

/// One slot body on the SDK's safe surface, over this plane's [`A2aDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = A2aDoor;
            fn call($inst: Instance<'_, A2aDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `ready` (after `open`, before any unit arrives; boot awaits it): the held CARDS are warmed
    /// from the `card` host records ([`warm_cards`]), on the op's real ticket, so the agents the
    /// operator approved before are served from the first unit, their arrival admitted against the
    /// card they fit. PENDING while the listing is in flight; a listing the host refuses leaves the
    /// cards unwarmed, for the first tick to warm, and the instance serves.
    ReadyOp, ReadyIn, OutHead, |instance, _, _| {
        let Some(plane) = instance.get() else {
            return Outcome::Ready;
        };
        if plane.cards_warmed.get(&()).unwrap_or(false) {
            let ticket = instance.ticket();
            plane.warming.remove(&(ticket.slot, ticket.generation));
            return Outcome::Ready;
        }
        match warm_cards(plane, instance.ticket(), 0).0 {
            Poll::Ready(landed) => {
                if landed {
                    plane.cards_warmed.insert((), true);
                }
                Outcome::Ready
            }
            Poll::Pending => Outcome::Pending,
        }
    }
);

/// The SDK lifecycle validates settings, publishes generations, and drives timed work.
impl PlaneLife for A2aDoor {
    type Held = AgentsCfg;

    fn leases(&self) -> Option<&busbar_contract::abi::sdk::life::Leases> {
        Some(&self.publication_leases)
    }

    fn generations(&self) -> &Generations<PlaneSnapshot, AgentsCfg> {
        &self.generations
    }

    /// `validate`: the settings read as the section, or refused in the grammar's words.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        agents_section(&statement::dealt_section(settings)).map(|_| ())
    }

    /// `open`: the instance over the section and the public base URL, and the first generation's
    /// snapshot.
    fn open(input: &Lent<'_, PlaneOpenIn>) -> Result<plane_life::Opened<Self>, Refusal> {
        let cfg = agents_section(input.open().settings().bytes())?;

        statement::read_push_section(input.owned().bytes()).map_err(Refusal::refused)?;
        let plane = A2aDoor {
            public_url: input.public_url().stated(),
            host: input.open().host().map(Host::of),
            services: input.open().host().and_then(Services::of),
            ..A2aDoor::default()
        };
        let names: Vec<&str> = cfg.agents.keys().map(String::as_str).collect();
        let spec = statement::agents_snapshot_spec(plane.public_url.as_deref(), &names);
        Ok(plane_life::Opened {
            plane,
            first: Published { spec, held: cfg },
        })
    }

    /// `refresh` with no other owned section applied ([`A2aDoor::refreshed`]); the slot calls
    /// [`Self::refresh_in`], which reads the applied ones.
    fn refresh(&self, settings: &[u8], generation: u64) -> Result<Published<AgentsCfg>, Refusal> {
        self.refreshed(settings, &[], generation)
    }

    /// Refresh validates the applied agent and push sections before publishing their snapshot.
    fn refresh_in(&self, input: &Lent<'_, RefreshIn>) -> Result<Published<AgentsCfg>, Refusal> {
        let extensions = input.head().extensions().bytes();
        let owned = busbar_contract::abi::mechanism::extensions::get(
            extensions,
            busbar_contract::abi::plane::EXT_OWNED,
        )
        .unwrap_or_default();
        self.refreshed(input.settings().bytes(), owned, input.generation())
    }

    /// After `generation` was published, by `open` or `refresh`: the newest when it is newer, each
    /// kept registration carrying the card it is held at now and starting again at the fail-closed
    /// floor (nothing sighted) with the approval it stands at now.
    fn published(&self, generation: u64) {
        let _publication = self
            .card_publication
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = self.newest.with_all(|m| {
            let before = m.get(&()).copied();
            if before.is_none_or(|n| n < generation) {
                m.insert((), generation);
            }
            before
        });
        let Some(kept) = self.kept_registrations.remove(&()) else {
            return;
        };
        // A card a trust verb held after `refresh` copied the kept cards is carried on too.
        if let Some(before) = before.filter(|n| *n < generation) {
            for name in &kept {
                if let Some(card) = self.cards.at(name, before) {
                    self.cards.hold_shared(name, generation, card);
                }
            }
        }
        self.trust.with_all(|m| {
            let approvals: Vec<_> = kept
                .into_iter()
                .filter_map(|name| {
                    let approved = m.get(&name).and_then(|s| s.approved.clone())?;
                    Some((name, approved))
                })
                .collect();
            m.clear();
            for (name, approved) in approvals {
                let standing = crate::card_trust::TrustStanding {
                    approved: Some(approved),
                    ..Default::default()
                };
                m.insert(name, standing);
            }
        });
    }

    /// `retire`, after the generation's snapshot is dropped: the cards held to it go too.
    fn retire(&self, generation: u64) {
        self.cards.retire(generation);
        self.card_cache.retire(generation);
    }

    /// `tick`: one due push notification attempted ([`crate::push_door::tick_deliveries`]), and the
    /// next tick wanted when the earliest waiting one is due (`0`: none waits).
    fn tick(
        instance: Instance<'_, Self>,
        input: Lent<'_, TickIn>,
        mut out: Out<'_, TickOut>,
    ) -> Outcome {
        let Some(plane) = instance.get() else {
            out.set(|o| &o.next_tick_ns, 0);
            return Outcome::Ready;
        };

        crate::push_door::arm(plane, &instance);
        if let Some(outcome) = crate::push_door::settle_publications(
            plane,
            instance.ticket(),
            input.head().extensions().bytes(),
            &mut out,
        ) {
            return outcome;
        }

        let now = input.now_ns();
        let unwarmed = !plane.cards_warmed.get(&()).unwrap_or(false);
        if unwarmed && !plane.warm_refused.get(&()).unwrap_or(false) {
            let landed = match warm_cards(plane, instance.ticket(), 0).0 {
                Poll::Pending => {
                    plane.warm_driving.insert((), true);
                    out.set(|o| &o.next_tick_ns, 0);
                    return Outcome::Pending;
                }
                Poll::Ready(landed) => landed,
            };
            plane.cards_warmed.insert((), landed);
            plane.warm_refused.insert((), !landed);
            plane.warm_driving.insert((), false);
            out.set(|o| &o.next_tick_ns, now.max(1));
            return Outcome::Ready;
        }
        plane.warm_refused.insert((), false);
        let outcome = crate::push_door::tick_deliveries(plane, &instance, now);

        let (dropped, unfiled) = plane.deliveries.take_counted();
        for (family, count) in [
            (statement::FAMILY_PUSH_DROPPED, dropped),
            (statement::FAMILY_PUSH_UNFILED, unfiled),
        ] {
            if count > 0 {
                out.metric(
                    family,
                    busbar_contract::abi::mechanism::call::METRIC_ADD,
                    count as f64,
                );
            }
        }
        let due = crate::push_door::next_tick_ns(&plane.deliveries, &plane.attempting);
        let again = now.saturating_add(WARM_AGAIN_NS).max(1);
        let next = match (unwarmed, due) {
            (false, _) => due,
            (true, 0) => again,
            (true, _) => due.min(again),
        };
        out.set(|o| &o.next_tick_ns, next);
        outcome
    }

    /// `drive`: no session has unsolicited output; a push delivery the last `tick` left PENDING
    /// goes on ([`crate::push_door::drive`]).
    fn drive(
        instance: Instance<'_, Self>,
        input: Lent<'_, PlaneDriveIn>,
        mut out: Out<'_, PlaneDriveOut>,
    ) -> Outcome {
        let Some(plane) = instance.get() else {
            return Outcome::Ready;
        };
        if let Some(outcome) = crate::push_door::settle_publications(
            plane,
            instance.ticket(),
            input.drive().head().extensions().bytes(),
            &mut out,
        ) {
            return outcome;
        }

        if plane.warm_driving.get(&()).unwrap_or(false) {
            if !plane.cards_warmed.get(&()).unwrap_or(false) {
                let landed = match warm_cards(plane, instance.ticket(), 0).0 {
                    Poll::Pending => return Outcome::Pending,
                    Poll::Ready(landed) => landed,
                };
                plane.cards_warmed.insert((), landed);
                plane.warm_refused.insert((), !landed);
            }
            let ticket = instance.ticket();
            plane.warming.remove(&(ticket.slot, ticket.generation));
            plane.warm_driving.insert((), false);
            return Outcome::Ready;
        }
        crate::push_door::drive(plane, &instance)
    }

    /// `cancel`: nothing the far end moved is in flight, so nothing moved; a card look the
    /// cancelled unit held is abandoned, and every unit waiting on it is woken at once to look for
    /// itself (cancellation is a wake).
    fn cancel(
        instance: Instance<'_, Self>,
        input: Lent<'_, PlaneCancelIn>,
        mut out: Out<'_, PlaneCancelOut>,
    ) -> Outcome {
        let mut answered = false;
        if let Some(plane) = instance.get() {
            let cancelled = input.cancel().ticket();
            plane
                .warming
                .remove(&(cancelled.slot, cancelled.generation));

            answered = UnitCancel::of(&input).end(
                &plane.units,
                Ending::Keep,
                |u| Some(u.ticket),
                |u| {
                    u.end();
                    plane
                        .cleanup_pending
                        .store(true, std::sync::atomic::Ordering::Release);
                    u.hop.as_ref().is_some_and(|h| h.relay.far_answered())
                },
            );
            crate::task_door::cancelled(plane, UnitCancel::of(&input));
            plane.deliveries.wake();
            let woken = plane.flights.abandon(input.cancel().ticket());
            if let Some(host) = plane.host.as_ref() {
                for waiter in woken {
                    host.wake(waiter);
                }
            }
        }

        out.set(|o| &o.cancel.disposition, cancel_disposition(answered));
        Outcome::Ready
    }
}

slot!(
    /// `arrive`: an arrival on the JSON-RPC line, on the HTTP+JSON line as the envelope its request
    /// spells ([`crate::rest::compose`]), or on the gRPC line as the JSON-RPC request its call's
    /// message composes ([`crate::framed::compose`]), decided and kept with the generation it
    /// arrived under, keyed by its unit; a refused one refused in its own words. A message whose
    /// method the vocabulary does not list is classed as the hop it relays on, never
    /// refused. A card read on the open line is decided by [`arrive_card`]. An instance holding as
    /// many live units as it keeps refuses the arrival ([`room_for`]).
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input;
        let _arrival = plane.arrival_gate.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !room_for(plane, given.unit()) {
            return refused(&mut out, &agent_arrival::units_full());
        }
        let Some(route) = statement::route_of_claim(given.claim(), || agent_claims(plane)) else {
            return unserved(&mut out);
        };
        let target = input.target().as_str().unwrap_or_default();
        let body = input.body().bytes();
        let line = statement::line_of(route);
        // Admission is a length check before REST/protobuf composition, JSON decoding,
        // task creation, or any backend dispatch. Card/discovery reads have no request body.
        if line != Line::Open {
            if let Some(refusal) = agent_arrival::request_body_refusal(body) {
                return refused(&mut out, &refusal);
            }
        }
        let (dialect, envelope, framed) = match line {
            Line::Document => (statement::DIALECT_DOCUMENT, None, None),
            Line::Target => {
                // Judge the head before decoding a REST body, just as the document line does.
                let fields = input.fields();
                let raw = |name: &str| fields.iter().find(|field| {
                    field.name().as_str().is_ok_and(|key| key.eq_ignore_ascii_case(name))
                }).map(|field| field.value().bytes());
                let mut values = [None; 3];
                let names = [agent_arrival::H_ORIGIN, agent_arrival::H_CONTENT_TYPE, agent_arrival::H_VERSION];
                for (name, value) in names.iter().zip(&mut values) {
                    *value = match agent_arrival::read_head_field(name, raw(name)) {
                        Ok(value) => value,
                        Err(refusal) => return refused(&mut out, &refusal),
                    };
                }
                let field = |name: &str| names.iter().position(|key| *key == name).and_then(|at| values[at]);
                if let Err(refusal) = agent_arrival::origin_refusal(field).and_then(|()| agent_arrival::head_refusal(field)) {
                    return refused(&mut out, &refusal);
                }
                match crate::rest::compose(route, target, body) {
                    Ok(Some(envelope)) => (statement::DIALECT_TARGET, Some(envelope), None),
                    Ok(None) => return unserved(&mut out),
                    Err(refusal) => return refused(&mut out, &refusal),
                }
            },
            Line::Open => return arrive_card(plane, route, target, given.unit(), &mut out),
            // The gRPC line: the rpc the target names, its one request
            // message composed as the v1.0 JSON-RPC request it is, served from there as the
            // JSON-RPC line serves its own; a method the service does not have, or a message that
            // does not read, is refused in the status the service answered it with.
            Line::Framed => {
                let Some(rpc) = crate::framed::Rpc::of_target(target) else {
                    return refused(&mut out, &framed_refusal(&crate::framed::unimplemented()));
                };
                match crate::framed::compose(rpc, body) {
                    Ok(envelope) => (statement::DIALECT_FRAMED, Some(envelope), Some(rpc)),
                    Err(status) => return refused(&mut out, &framed_refusal(&status)),
                }
            }
        };
        // A composed request may contain callback credentials even when its head is refused.
        let envelope = envelope.map(zeroize::Zeroizing::new);
        let fields = input.fields();
        if dialect != statement::DIALECT_TARGET {
            for name in [
                agent_arrival::H_ORIGIN,
                agent_arrival::H_CONTENT_TYPE,
                agent_arrival::H_VERSION,
            ] {
                let value = fields
                    .iter()
                    .find(|f| {
                        f.name()
                            .as_str()
                            .is_ok_and(|n| n.eq_ignore_ascii_case(name))
                    })
                    .map(|f| f.value().bytes());
                if let Err(refusal) = agent_arrival::read_head_field(name, value) {
                    return refused(&mut out, &refusal);
                }
            }
        }
        let field = |name: &str| {
            fields
                .iter()
                .find(|f| {
                    f.name()
                        .as_str()
                        .is_ok_and(|n| n.eq_ignore_ascii_case(name))
                })
                .and_then(|f| f.value().as_str().ok())
        };
        // The arrival is decided over the body it read once, and that read is the unit's request.
        let read = envelope.as_deref().map(Vec::as_slice).unwrap_or(body);
        let (disposition, request) = match framed {
            Some(_) => agent_arrival::decide_and_read(read, |name| framed_field(field, name)),
            None => agent_arrival::decide_and_read(read, field),
        };
        let mut request = crate::request_json::OptionalRequest::new(request);
        if let AgentDisposition::Refused(refusal) = &disposition {
            return refused(&mut out, refusal);
        }
        let Some(op) = disposition
            .op_class()
            .and_then(|op| class_index(crate::ops::OP_CLASSES, op)) else {
            return unserved(&mut out);
        };
        out.set(|o| &o.op_class, op);
        out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
        out.set(|o| &o.dialect, dialect);
        let agent = agent_of(target);
        let generation = plane.newest();
        let section = plane.generations.at(generation);
        let mut hop = hop_of(&disposition, agent.is_some(), &mut request);
        if let (Some(hop), Some(rpc)) = (hop.as_mut(), framed) {
            hop.mint_message_id = crate::framed::mints_message_id(rpc, body);
        }
        // The HTTP+JSON line relays the envelope its request spelled, never the caller's body.
        if let (Some(hop), Some(composed)) = (hop.as_mut(), envelope.as_ref()) {
            hop.relay.send_instead(composed.to_vec());
        }
        // A request naming a task keeps the bytes it relays, for its ids to be translated in them.
        if let Some(hop) = hop.as_mut() {
            let names_a_task = hop.request.as_ref().is_some_and(|r| {
                !crate::task_identity::translatable(r).is_empty()
                    || !crate::task_identity::referenced_tasks(r).is_empty()
            });
            if names_a_task && hop.relay.replacement_bytes().is_none() {
                hop.relay.send_instead(read.to_vec());
            }
        }
        // The request the admission reads: the hop's, which took it, or the arrival's own.
        let request = hop.as_ref().map_or(request.as_ref(), |h| h.request.as_deref());
        let shape = request.map(crate::skill::TaskShape::of).unwrap_or_default();
        // The entry the unit routes over: the addressed agent, its name inside the `agents:`
        // section, routed directly; an unaddressed unit is routed by the
        // caller's scope, to the one agent its grant reaches.
        //
        // Admission and the catalogue at arrival: an addressed agent that is not serving, or whose
        // card the request does not fit, refuses the unit about that agent — the kernel judges the
        // caller's grant over it first and charges nothing; an unaddressed unit names the agents
        // that would serve it as its candidates, which the kernel intersects with the caller's
        // grant.
        // BUSBAR'S EXTENDED CARD and A NOTIFICATION, the plane's own to answer before any agent
        // is selected ([`answered_here`]).
        if answered_here(&disposition, agent.is_some()) {
            out.local();
            // Busbar's extended card is an ADMITTED CALL on the plane's pool (governance,
            // admission, the request meter, then the card): it counts its
            // request; a notification moves nothing.
            if matches!(disposition, AgentDisposition::Request { .. }) {
                out.counted();
            }
            let unit = AgentUnit {
                envelope,
                framed,
                ..AgentUnit::new(disposition, agent, section, generation)
            };
            plane.units.insert(given.unit(), unit);
            return Outcome::Ready;
        }
        let mut pool = None;
        let scope_local;
        match &agent {
            Some(agent) => {
                scope_local = hop.is_none()
                    && matches!(
                        &disposition,
                        AgentDisposition::Request { row, .. }
                            if row.op == crate::ops::OP_TASK_LIST
                    );
                out.route(
                    if scope_local {
                        ROUTE_SCOPE_LOCAL
                    } else {
                        ROUTE_DIRECT
                    },
                    agent,
                );
                // An agent this deployment does not front:
                // a refusal about the entry it names, so the kernel judges the caller's identity
                // and grant first and nothing is charged; `404`, never a `503`.
                let Some(def) = section.as_ref().and_then(|s| s.agents.get(agent)) else {
                    return refused(&mut out, &agent_arrival::no_such_agent(agent));
                };
                let pooled = section.as_ref().and_then(|s| s.pool_of(agent));
                // A CARD READ ADDRESSED TO A POOLED AGENT has no one answer across the pool's
                // members: refused about the agent it addressed, so
                // the kernel judges the caller's grant on it first; an agent the kernel's trust
                // book does not serve is refused for that first, its trust facts stated (a refusal
                // about an entry states none, abi/plane "A refused arrival").
                if let (Some(_), AgentDisposition::Request { row, id, .. }) = (&pooled, &disposition) {
                    if row.op == crate::ops::OP_AGENT_CARD
                        && verdict(plane, agent) == busbar_contract::abi::host::service::DISTRUST_NONE
                    {
                        return refused(&mut out, &agent_arrival::pooled_card(id.clone()));
                    }
                }
                if let Err(refusal) =
                    admit_addressed(plane, (agent, def), generation, request, &mut out)
                {
                    return refused(&mut out, &refusal);
                }
                // An agent in a failover pool: a relayed unit routes
                // over the POOL, so the kernel's one walk picks the member, primary first (each
                // member's declared tier); the caller's grant on the agent it addressed is judged
                // on the trust counterparty it states. A verb the plane answers itself stays the
                // addressed agent's, answered before the pool is read.
                if let Some((name, _)) = pooled {
                    if hop.is_some() {
                        out.route(ROUTE_POOL, name);
                        pool = Some(name.to_string());
                    }
                }
            }
            None => {
                let candidates: Vec<&str> = section
                    .as_ref()
                    .map(|s| {
                        s.agents
                            .iter()
                            .filter(|(name, _def)| {
                                admit_shape(plane, name, None, generation, &shape)
                                    .is_ok()
                            })
                            .map(|(name, _)| name.as_str())
                            .collect()
                    })
                    .unwrap_or_default();
                // A verb the plane answers itself, unaddressed (`ROUTE_SCOPE_LOCAL`): answered at
                // the one agent the caller's grant reaches, with no route walked, before the
                // egress gate and before any pool is read. An admitted call, counted.
                scope_local = hop.is_none();
                out.route(
                    if scope_local {
                        ROUTE_SCOPE_LOCAL
                    } else {
                        ROUTE_SCOPE
                    },
                    &candidates.join(busbar_contract::abi::plane::ROUTE_SCOPE_SEPARATOR),
                );
            }
        }
        // At most once: an agent that answered with a failure is not retried on
        // another; its failure is the unit's answer, surfaced per attempt, while the walk still
        // moves past a member whose breaker is open before anything was sent. Stated only on a
        // unit admitted here: a refusal about an entry states no route flags (abi/plane "A refused
        // arrival").
        out.once();
        if scope_local {
            out.counted();
        }
        // A STREAMED ANSWER (`message/stream`, `tasks/resubscribe`, their v1.0 names and an unlisted
        // method named as a stream): the kernel bounds it by
        // the tail's stream ceiling, from the moment its route is known.
        if hop.as_ref().is_some_and(Hop::streams) {
            out.stream();
        }
        let unit = AgentUnit {
            hop,
            envelope,
            framed,
            pool,
            ..AgentUnit::new(disposition, agent, section, generation)
        };
        plane.units.insert(given.unit(), unit);
        Outcome::Ready
    }
);

/// WHETHER THE PLANE ANSWERS AN ARRIVAL ITSELF, before any agent is selected: busbar's EXTENDED
/// card on the plane's own endpoint (the caller named no agent, so the verb asks busbar about
/// itself; busbar's extended card), and a notification wherever it arrived (received, never
/// answered and never relayed: answered `202` with no body, moving nothing).
pub(crate) fn answered_here(disposition: &AgentDisposition, addressed: bool) -> bool {
    match disposition {
        AgentDisposition::Request { row, .. } => !addressed && row.op == crate::ops::OP_AGENT_CARD,
        AgentDisposition::Notice { .. } => true,
        _ => false,
    }
}

/// AN ARRIVAL ON THE OPEN LINE: a read of a card busbar serves ([`crate::served_card`]), kept with
/// the generation it arrived under.
fn arrive_card(
    plane: &A2aDoor,
    route: &statement::Route,
    target: &str,
    unit: u64,
    out: &mut Out<'_, ArriveOut>,
) -> Outcome {
    let generation = plane.newest();
    let section = plane.generations.at(generation);
    let (ask, agent) = if route.verb == "GET" && route.target == crate::WELL_KNOWN_CARD_PATH {
        (agent_arrival::CardAsk::Own, None)
    } else if route.verb == "GET"
        && (route.target == crate::mounted_route(crate::ROUTE_AGENT)
            || route.target == crate::mounted_route(crate::ROUTE_AGENT_CARD))
    {
        let Some(agent) = agent_of(target) else {
            return unserved(out);
        };
        (agent_arrival::CardAsk::Agent, Some(agent))
    } else {
        return unserved(out);
    };
    let Some(op) = class_index(crate::ops::OP_CLASSES, crate::ops::OP_AGENT_CARD) else {
        return unserved(out);
    };
    out.set(|o| &o.op_class, op);
    out.set(|o| &o.dialect, statement::DIALECT_DOCUMENT);
    match &agent {
        None => {
            out.set(|o| &o.principal_need, PRINCIPAL_NONE);
            out.local();
        }
        Some(agent) => {
            out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
            out.route(ROUTE_DIRECT, agent);
            let Some(def) = section.as_ref().and_then(|s| s.agents.get(agent)) else {
                return refused(out, &agent_arrival::no_such_agent(agent));
            };

            if section.as_ref().and_then(|s| s.pool_of(agent)).is_some()
                && verdict(plane, agent) == busbar_contract::abi::host::service::DISTRUST_NONE
            {
                return refused(out, &agent_arrival::pooled_card(serde_json::Value::Null));
            }
            if let Err(refusal) = admit_addressed(plane, (agent, def), generation, None, out) {
                return refused(out, &refusal);
            }
        }
    }
    let card = AgentDisposition::Card(ask);
    let held = AgentUnit::new(card, agent, section, generation);
    plane.units.insert(unit, held);
    Outcome::Ready
}

/// The hop a unit's `on_piece` serves: the extended-card read addressed to one agent, task-less
/// (its `card_fetch` arm); a request whose answer is events (the vocabulary's multi-frame rows, and
/// an unlisted method named as a stream), about a task, a subscribe answering busbar's own refusal
/// first; and every other relayed one-reply request, about a task (`request` is its envelope: the
/// caller's on the JSON-RPC line, the one its request spelled on the HTTP+JSON line).
fn hop_of(
    disposition: &AgentDisposition,
    addressed: bool,
    request: &mut Option<serde_json::Value>,
) -> Option<Hop> {
    use crate::local::{verb_of, LocalVerb};
    use crate::ops::{relay_class, OP_AGENT_CARD, OP_MESSAGE_SEND, OP_MESSAGE_STREAM};
    match disposition {
        AgentDisposition::Request { row, id, version } if row.op == OP_AGENT_CARD => {
            addressed.then(|| Hop::of(id.clone(), version, request.take()))
        }
        AgentDisposition::Request { row, id, version } if row.multi_frame => {
            let subscribe = verb_of(row.method) == Some(LocalVerb::Subscribe);
            Some(Hop::events(id.clone(), version, request.take()?, subscribe))
        }
        AgentDisposition::Request { row, id, version } if verb_of(row.method).is_none() => {
            Some(Hop::task(id.clone(), version, request.take()?))
        }
        AgentDisposition::Unlisted {
            method,
            id,
            version,
        } => {
            let class = relay_class(method);
            if class == OP_MESSAGE_SEND {
                Some(Hop::task(id.clone(), version, request.take()?))
            } else if class == OP_MESSAGE_STREAM {
                Some(Hop::events(id.clone(), version, request.take()?, false))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The URL the operator wrote for agent `member` in the section the unit arrived under.
/// The host reach one piece's task work makes: the instance, and the piece's ticket.
struct Reach<'p> {
    plane: &'p A2aDoor,
    ticket: Ticket,
}

impl Reach<'_> {
    /// The piece's records and random bytes, counting on from the `issued` its unit's finished
    /// pieces made; `None` when the instance was opened without host tables.
    fn via(&self, issued: u32) -> Option<Via<'_>> {
        let host = self.plane.host.as_ref()?;
        Some(Via::new(
            host,
            self.plane.services,
            self.ticket,
            issued,
            &self.plane.grown,
        ))
    }

    /// Now, in seconds, from the host's clock.
    fn now(&self) -> Option<u64> {
        self.now_ms().map(|ms| ms / 1_000)
    }

    /// The host's wall clock, milliseconds.
    fn now_ms(&self) -> Option<u64> {
        match self.clock_ms() {
            Poll::Ready(Ok(now)) => Some(now),
            _ => None,
        }
    }

    fn clock_ms(&self) -> Poll<Result<u64, ()>> {
        let Some(host) = self.plane.host.as_ref() else {
            return Poll::Ready(Err(()));
        };
        host.connector(self.ticket).clock_now().map(|result| {
            result
                .map(|reading| reading.wall_ns / 1_000_000)
                .map_err(|_| ())
        })
    }
}

/// OPEN the task `hop` is about, at its first ATTEMPT ([`task_hop::open`]): its identity on the
/// relay and its record writes on `writes`, or the caller's whole answer when it does not go ahead.
fn open_task(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    request: (&str, &str, Option<&str>),
    skill: Option<String>,
    writes: &mut Vec<Write>,
) -> Result<Option<relay::RelayReply>, Outcome> {
    let (caller, member, addressed) = request;
    let Some(envelope) = hop.request.as_ref().filter(|_| hop.opening) else {
        return Ok(None);
    };
    let now = match hop.now {
        Some(now) => now,
        None => *hop.now.insert(reach.now().ok_or(Outcome::Failed)?),
    };
    let mut via = reach
        .via(pass.issued)
        .ok_or(Outcome::Failed)?
        .publishing(&pass.publication);

    if hop.mint_message_id {
        let mut random = [0_u8; 10];
        if via.random(&mut random).is_err() {
            return Err(Outcome::Failed);
        }
        let ms = reach.now_ms().ok_or(Outcome::Failed)?;
        let id = crate::framed::message_id_v7(ms, &random);
        let minted =
            crate::request_json::RequestJson::new(crate::framed::with_message_id(envelope, &id));
        if let Ok(bytes) = crate::relay::json_bytes(&minted) {
            hop.relay.send_instead(bytes);
        }
        hop.request = Some(minted);
        hop.mint_message_id = false;

        pass.issued = via.issued();
    }
    let Some(envelope) = hop.request.as_ref() else {
        return Ok(None);
    };

    if hop.subscribe {
        let mut none = Vec::new();
        let refused = match crate::local::answer_local(
            &mut via,
            crate::local::LocalVerb::Subscribe,
            envelope,
            caller,
            now,
            &mut none,
        ) {
            Err(Halt::Pending) => return Err(Outcome::Pending),
            Err(Halt::Failed(_)) => Some(crate::local::unreadable(hop.relay.id())),
            Ok(answer) => answer,
        };
        if let Some(mut answer) = refused {
            pass.issued = via.issued();
            hop.opening = false;
            hop.now = None;
            return Ok(Some(relay::RelayReply {
                status: answer.status,
                content_type: crate::agent_arrival::JSON_MEDIA_TYPE,
                body: std::mem::take(&mut answer.body),
            }));
        }
    }
    let backends = |id: &str| reach.plane.backends.get(&task_key(caller, id));
    let req = task_hop::Request {
        envelope,
        relayed: hop.rewritten.as_deref(),
        relayed_bytes: hop.relay.replacement_bytes(),
        caller,
        member,
        addressed,
        now,
        sweep: *hop.sweep.get_or_insert_with(|| reach.plane.sweeps.due(now)),
    };
    let opened = match task_hop::open(&mut via, &req, hop.relay.id(), &backends, writes) {
        Err(Halt::Pending) => return Err(Outcome::Pending),
        Err(Halt::Failed(_)) => return Err(Outcome::Failed),
        Ok(opened) => opened,
    };
    pass.issued = via.issued();
    hop.opening = false;
    hop.now = None;
    hop.sweep = None;
    match opened {
        Opened::Refused(reply) => {
            pass.unrecorded = None;
            Ok(Some(reply))
        }
        Opened::Hop {
            mut task,
            instead,
            callback,
            swept,
            unrecorded,
        } => {
            if let Some(touched) = swept {
                reach.plane.sweeps.swept(now, touched, tasks::SWEEP_BUDGET);
            }

            drop(unrecorded);
            pass.unrecorded = None;

            drop(callback);
            task.skill = skill;
            hop.relay.for_task(*task);
            if let Some(body) = instead {
                hop.relay.send_instead(body);
            }
            Ok(None)
        }
    }
}

/// SETTLE the task `hop` is about on what its answer has said ([`task_hop::settle_on_answer`]): the
/// record writes ride with the answer, each move of the task publishes its push notification, and
/// what earlier deliveries owe this caller's other tasks' chains is filed.
fn settle_task(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    caller: &str,
) -> Result<(), Outcome> {
    let settles = std::mem::take(&mut hop.settle);
    if settles.is_empty() {
        return Ok(());
    }
    let Some(task) = hop.relay.task().cloned() else {
        return Ok(());
    };
    let pend = |hop: &mut Hop, settles: Vec<TaskSettled>| {
        hop.settle = settles;
        Err(Outcome::Pending)
    };
    // A host without a clock or records fails the piece with its settles kept for the re-call.
    let now = match hop.now.or_else(|| reach.now()) {
        Some(now) => *hop.now.insert(now),
        None => {
            hop.settle = settles;
            return Err(Outcome::Failed);
        }
    };
    let Some(via) = reach.via(pass.issued) else {
        hop.settle = settles;
        return Err(Outcome::Failed);
    };
    let mut via = via.publishing(&pass.publication);

    let mut writes = hop.outbox.writes.clone();
    let seeded = writes.len();
    let mut moved = Vec::new();
    let mut halted = false;
    for settled in &settles {
        let backend = match settled {
            TaskSettled::Reported { backend_id, .. } | TaskSettled::Event { backend_id, .. } => {
                backend_id.clone()
            }
            TaskSettled::Failed => None,
        };
        if backend.is_some() {
            via.effects(crate::conditional_publication::Draft {
                backend,
                ..Default::default()
            });
            let at = tasks::Stamp {
                caller,
                request_id: &task.task_id,
                now,
            };
            match tasks::guard_backend(&mut via, &at, &task.task_id) {
                Err(Halt::Pending) => return pend(hop, settles),
                Err(Halt::Failed(_)) => {
                    hop.settle = settles;
                    return Err(Outcome::Failed);
                }
                Ok(()) => {}
            }
        }
        via.effects(crate::conditional_publication::Draft {
            notify: true,
            ..Default::default()
        });
        match task_hop::settle_on_answer(
            &mut via,
            &task,
            settled,
            caller,
            now,
            &mut writes,
            &reach.plane.latches,
        ) {
            Err(Halt::Pending) => {
                halted = true;
                break;
            }
            Err(Halt::Failed(_)) => {
                hop.settle = settles;
                return Err(Outcome::Failed);
            }
            Ok(row) => moved.extend(row),
        }
    }
    if halted {
        return pend(hop, settles);
    }

    // Each move's notification rides the journal's draft: published once per move, a re-entry
    // never publishing one twice.
    for _ in hop.queued..moved.len() {
        crate::push_door::apply_publication(reach.plane, &pass.publication);
    }
    hop.queued = hop.queued.max(moved.len());

    let owed = hop
        .owed
        .get_or_insert_with(|| {
            reach
                .plane
                .deliveries
                .peek_owed(reach.ticket, caller, Some(task.task_id.as_str()))
        })
        .clone();
    match crate::push_door::file_owed_committed(
        &mut via,
        &pass.publication,
        &reach.plane.deliveries,
        caller,
        &owed,
        now,
    ) {
        Err(Halt::Pending) => return pend(hop, settles),
        Err(Halt::Failed(_)) => {
            hop.settle = settles;
            return Err(Outcome::Failed);
        }
        Ok(()) => {}
    }
    hop.queued = 0;
    hop.owed = None;
    pass.issued = via.issued();
    crate::push_door::apply_publication(reach.plane, &pass.publication);
    hop.outbox.writes.extend(writes.split_off(seeded));
    hop.now = None;
    Ok(())
}

/// A HOP THE KERNEL REFUSED FOR BUSBAR'S OWN CREDENTIAL (`credential_unavailable`: the agent's
/// `upstream_credential`, re-resolved for this hop, no longer resolves, so nothing was dialled):
/// logged once as the engine logged a lease it could not mint (`A2A_OUTBOUND_CRED_UNLEASED`, naming
/// `agent`), its answer made in the engine's words ([`HopRelay::refuse_credential`]: the relay's
/// 502 naming the task, or the card fetch's) by [`hop_refused`].
fn credential_refused(hop: &mut Hop, agent: &str, target_line: bool) -> bool {
    if hop.refused.is_none() {
        busbar_contract::diag_warn!(
            crate::diagnostics::A2A_OUTBOUND_CRED_UNLEASED,
            agent = %agent,
            "a2a: the outbound credential could not be leased"
        );
    }
    hop_refused(hop, HopRelay::refuse_credential, target_line)
}

/// THE ANSWER A REFUSED HOP MAKES, once: `refuse`'s answer in the engine's words, re-framed on the
/// HTTP+JSON line, kept on the hop for `refusal` to render.
fn hop_refused(
    hop: &mut Hop,
    refuse: fn(&mut HopRelay) -> (relay::RelayReply, bool),
    target_line: bool,
) -> bool {
    if hop.refused.is_some() {
        return false;
    }
    let (mut reply, failed) = refuse(&mut hop.relay);
    if target_line {
        let original = zeroize::Zeroizing::new(std::mem::take(&mut reply.body));
        reply.body = crate::rest::reframe(reply.status, &original);
    }
    hop.refused = Some(reply);
    failed && hop.relay.task().is_some()
}

/// Render and retain a credential refusal in the unit's wire dialect.
fn credential_refusal(unit: &mut AgentUnit) -> Option<relay::RelayReply> {
    let target_line = unit.envelope.is_some() && unit.framed.is_none();
    let addressed = unit.agent.clone();
    let hop = unit.hop.as_mut()?;
    if hop.refused.is_none() {
        let agent = if hop.member.is_empty() {
            addressed.unwrap_or_default()
        } else {
            hop.member.clone()
        };
        credential_refused(hop, &agent, target_line);
    }
    hop.refused.clone()
}

/// A HOP THAT LEFT AND HEARD NOTHING BACK (the kernel's walk ended with no member left after the
/// unit's attempt went out: the connection to the agent could not be made, or closed unanswered):
/// the engine's `RelayRefusal::Transport` as `receive::refuse_hop` answered it, never the open
/// breaker's words — the attempt WAS dispatched ([`HopRelay::refuse_transport`]), as `refusal`
/// renders it: what the refused piece made, its task already ended there as [`credential_refusal`]
/// ends one.
fn transport_refusal(unit: &mut AgentUnit) -> Option<relay::RelayReply> {
    let target_line = unit.envelope.is_some() && unit.framed.is_none();
    let hop = unit.hop.as_mut()?;
    if !hop.left {
        return None;
    }
    hop_refused(hop, HopRelay::refuse_transport, target_line);
    hop.refused.clone()
}

/// What `f` reads off unit `unit`, when the instance and the unit are both there.
fn of_unit<T>(
    instance: &Instance<'_, A2aDoor>,
    unit: u64,
    f: impl FnOnce(&mut AgentUnit) -> Option<T>,
) -> Option<T> {
    instance.get()?.units.with(&unit, |u| u.and_then(f))
}

/// The kernel's verdict on `agent` (`trust.serves`: the kernel's Approve as a query; it never
/// pends, so it rides no ticket): [`svc::DISTRUST_NONE`] serves, any other `DISTRUST_*` refuses.
pub(crate) fn verdict(plane: &A2aDoor, agent: &str) -> u64 {
    use busbar_contract::abi::host::service as svc;
    let Some(services) = plane.services else {
        return svc::DISTRUST_UNKNOWN;
    };
    let handle = crate::task_door::handle(Ticket::NONE, 0);
    services
        .trust_serves(handle, agent, None, None)
        .unwrap_or(svc::DISTRUST_UNKNOWN)
}

/// An arrival addressed to `member` states its trust facts (the agent, as the counterparty): the
/// kernel's Approve judges them and refuses an agent its trust book does not serve (`untrusted`,
/// rendered by `refusal` in the admission's words).
fn admit_addressed(
    plane: &A2aDoor,
    (member, def): (&str, &crate::a2a::config::AgentDefCfg),
    generation: u64,
    envelope: Option<&serde_json::Value>,
    out: &mut Out<'_, ArriveOut>,
) -> Result<(), agent_arrival::AgentRefusal> {
    if verdict(plane, member) == busbar_contract::abi::host::service::DISTRUST_NONE {
        admit_unit(plane, (member, def), Some(member), generation, envelope)?;
    }
    out.trust(member, None, None);
    Ok(())
}

/// THE ADMISSION AND THE CATALOGUE (the engine's `receive::admit`, after the kernel's identity and
/// grant), for a unit routed to `member` (`def`): an agent the KERNEL'S TRUST BOOK does not serve
/// ([`verdict`]: never approved, or quarantined), is refused in the admission's words
/// ([`crate::card_trust::not_serving`]); one with no held card, or whose held card the request's
/// shape (`envelope`) does not fit, is excluded from the catalogue — addressed, the catalogue's
/// refusal naming the exclusion (`400`, [`crate::skill::refusal`]), routed by scope, the
/// none-refusal.
pub(crate) fn admit_unit(
    plane: &A2aDoor,
    (member, _def): (&str, &crate::a2a::config::AgentDefCfg),
    addressed: Option<&str>,
    generation: u64,
    envelope: Option<&serde_json::Value>,
) -> Result<Option<String>, agent_arrival::AgentRefusal> {
    let shape = envelope
        .map(crate::skill::TaskShape::of)
        .unwrap_or_default();
    admit_shape(plane, member, addressed, generation, &shape)
}

fn admit_shape(
    plane: &A2aDoor,
    member: &str,
    addressed: Option<&str>,
    generation: u64,
    shape: &crate::skill::TaskShape,
) -> Result<Option<String>, agent_arrival::AgentRefusal> {
    use crate::card_trust::{not_serving, verdict_state, UNTRUSTED_STATUS};
    let distrust = verdict(plane, member);
    if distrust != busbar_contract::abi::host::service::DISTRUST_NONE {
        return Err(not_serving(
            addressed,
            verdict_state(distrust),
            UNTRUSTED_STATUS,
        ));
    }
    let excluded = |unfit: crate::skill::Unfit| match (unfit, addressed) {
        (crate::skill::Unfit::NoCachedCard, _) => not_serving(
            addressed,
            crate::card_trust::State::Pending,
            UNTRUSTED_STATUS,
        ),
        (unfit, Some(_)) => crate::skill::refusal(&unfit),
        (_, None) => agent_arrival::scope_refusal(""),
    };
    plane.cards.fit(member, generation, shape).map_err(excluded)
}

/// The caller's identity, the ordered gate's first step (a key that is disabled, deleted or past
/// its row's `expires_at` is `KeyNotLive`, `401`, before anything else is judged), asked of the
/// kernel at the unit's attempt: `entitlement.check` of the unit's caller for `member`'s agent
/// scope, whose identity step refuses a principal that is not live (the kernel's own auth chain
/// admits a key row past its `expires_at`; this plane's admission never did).
fn caller_stands(
    reach: &Reach<'_>,
    pass: &mut crate::task_door::Pass,
    member: &str,
    addressed: Option<&str>,
) -> Option<agent_arrival::AgentRefusal> {
    if addressed.is_some_and(|a| a != member) {
        return None;
    }
    match (
        entitled(reach, pass, &statement::agent_resource(member)),
        addressed,
    ) {
        (Ok(true), _) => None,
        (Ok(false), Some(_)) => Some(agent_arrival::not_live()),
        (Ok(false), None) => Some(agent_arrival::scope_refusal("")),
        (Err(()), _) => Some(entitlement_unavailable(None)),
    }
}

/// ONE ATTEMPT OF A UNIT OVER A FAILOVER POOL, as [`pool_gate`] judges it: the pool, its members in
/// declared order (the first the primary), the member the kernel's walk picked, the agent the unit
/// addressed, and the caller's reference.
struct PoolGate<'a> {
    /// The pool, as its refusal names it (`agent:<pool>`, the walk key).
    pool: &'a str,
    members: &'a [String],
    member: &'a str,
    addressed: Option<&'a str>,
    caller: &'a str,
    /// The refresh generation the unit arrived under: the held cards it reads are that one's.
    generation: u64,
}

/// What [`pool_gate`] decided for one ATTEMPT.
enum Gate {
    /// The attempt goes on to the member.
    Go,
    /// The member is one this unit may not be sent to: declined, nothing sent, the walk moves on
    /// (an empty `VERDICT_RETRY`).
    Decline,
    /// The caller's whole answer, before anything is sent.
    Refuse(relay::RelayReply),
    /// A host call pends: the piece runs again from the top.
    Pending,
}

/// The pool's member for this attempt over the kernel's one walk, primary first: a hop that already
/// left is not sent to another, a request about a task is pinned to the member holding it, and a
/// fresh submission takes the member the walk placed it on unless the caller's grant, the trust
/// book or the primary's card fingerprint rules that member out.
fn pool_gate(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    gate: &PoolGate<'_>,
) -> Gate {
    if hop.left {
        return Gate::Decline;
    }
    let holder = match read_holder(reach, hop, pass, gate.caller, gate.members) {
        Poll::Pending => return Gate::Pending,
        Poll::Ready(Err(())) => return Gate::Refuse(holder_unavailable(hop)),
        Poll::Ready(Ok(holder)) => holder,
    };

    let elsewhere = gate.addressed != Some(gate.member);
    match holder {
        Some(holder) if holder != gate.member => Gate::Decline,
        Some(_) if elsewhere => {
            match entitled(reach, pass, &statement::agent_resource(gate.member)) {
                Ok(true) => Gate::Go,
                Err(()) => Gate::Refuse(relay::RelayReply::refused(
                    &entitlement_unavailable(Some(hop.relay.id().clone())),
                    None,
                )),
                Ok(false) => {
                    let standing = busbar_contract::abi::host::service::ENTITLEMENT_STANDING;
                    let live = match entitled(reach, pass, standing) {
                        Ok(live) => live,
                        Err(()) => {
                            return Gate::Refuse(relay::RelayReply::refused(
                                &entitlement_unavailable(Some(hop.relay.id().clone())),
                                None,
                            ))
                        }
                    };
                    Gate::Refuse(relay::RelayReply::refused(
                        &agent_arrival::pinned_ungranted(
                            hop.relay.id().clone(),
                            &statement::agent_resource(gate.member),
                            live,
                        ),
                        None,
                    ))
                }
            }
        }
        Some(_) => Gate::Go,
        None => {
            if elsewhere {
                let granted = match entitled(reach, pass, &statement::agent_resource(gate.member)) {
                    Ok(granted) => granted,
                    Err(()) => {
                        return Gate::Refuse(relay::RelayReply::refused(
                            &entitlement_unavailable(Some(hop.relay.id().clone())),
                            None,
                        ))
                    }
                };
                if !granted
                    || verdict(reach.plane, gate.member)
                        != busbar_contract::abi::host::service::DISTRUST_NONE
                {
                    return Gate::Decline;
                }
            }
            if let Some(primary) = gate.members.first().filter(|p| *p != gate.member) {
                let (a, b) = (
                    approved_fingerprint(reach.plane, primary, gate.generation),
                    approved_fingerprint(reach.plane, gate.member, gate.generation),
                );
                if a.is_none() || a != b {
                    hop.mismatch = Some(agent_arrival::not_interchangeable(
                        gate.pool,
                        (primary, a.as_deref()),
                        (gate.member, b.as_deref()),
                    ));
                }
            }
            Gate::Go
        }
    }
}

/// The member holding the task a pooled unit's request is about ([`task_hop::holder`]), read once
/// per unit and kept on its hop; `None` for a fresh submission, and where there is nothing to read
/// it with.
fn read_holder(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    caller: &str,
    members: &[String],
) -> Poll<Result<Option<String>, ()>> {
    if hop
        .request
        .as_deref()
        .is_some_and(task_hop::conflicting_tasks)
    {
        return Poll::Ready(Err(()));
    }
    if let Some(holder) = hop.holder.clone() {
        return Poll::Ready(Ok(holder));
    }
    let (Some(envelope), Some(now), Some(mut via)) =
        (hop.request.as_ref(), reach.now(), reach.via(pass.issued))
    else {
        return Poll::Ready(Err(()));
    };
    let holder = match task_hop::holder(&mut via, envelope, caller, now, members) {
        Err(Halt::Pending) => return Poll::Pending,
        Err(Halt::Failed(_)) => return Poll::Ready(Err(())),
        Ok(holder) => holder,
    };
    pass.issued = via.issued();
    hop.holder = Some(holder.clone());
    Poll::Ready(Ok(holder))
}

fn holder_unavailable(hop: &Hop) -> relay::RelayReply {
    if hop
        .request
        .as_ref()
        .is_some_and(|request| task_hop::conflicting_tasks(request))
    {
        return relay::RelayReply::refused(
            &agent_arrival::AgentRefusal::new(
                400,
                Some(hop.relay.id().clone()),
                -32602,
                task_hop::TASK_NAMED_TWICE.to_string(),
            ),
            None,
        );
    }
    relay::RelayReply::refused(
        &agent_arrival::AgentRefusal::new(
            503,
            Some(hop.relay.id().clone()),
            -32603,
            "the task store is unavailable; retry this request".to_string(),
        ),
        None,
    )
}

/// `entitlement.check` of the unit's caller for `target` (an agent's scope, or the principal's
/// standing), distinguishing host failure from an explicit denial.
fn entitled(
    reach: &Reach<'_>,
    pass: &mut crate::task_door::Pass,
    target: &str,
) -> Result<bool, ()> {
    let handle = crate::task_door::handle(reach.ticket, pass.issued);
    pass.issued += 1;
    match reach
        .plane
        .services
        .map(|services| services.entitled(handle, target))
    {
        Some(Ok(entitled)) => Ok(entitled),
        _ => {
            tracing::warn!("a2a: host entitlement check unavailable; refusing the hop");
            Err(())
        }
    }
}

fn entitlement_unavailable(id: Option<serde_json::Value>) -> agent_arrival::AgentRefusal {
    agent_arrival::AgentRefusal::new(
        503,
        id,
        -32603,
        "the entitlement service is unavailable; retry this request",
    )
}

/// The approved card fingerprint of `agent` (the approved canonical card fingerprint): its held
/// card's, when the kernel's trust book serves it; `None` (which never matches) when nothing is
/// approved or held.
fn approved_fingerprint(plane: &A2aDoor, agent: &str, generation: u64) -> Option<String> {
    if verdict(plane, agent) != busbar_contract::abi::host::service::DISTRUST_NONE {
        return None;
    }
    let card = plane.cards.at(agent, generation)?;
    crate::a2a::card::fingerprint(&card).ok()
}

/// The not-interchangeable refusal: `503`, `-32004`, the walk's own words, naming the task the hop
/// opened.
fn not_interchangeable(hop: &Hop, reason: String) -> relay::RelayReply {
    let refusal = agent_arrival::AgentRefusal::new(
        agent_arrival::STATUS_UNAVAILABLE,
        Some(hop.relay.id().clone()),
        agent_arrival::CODE_UNSUPPORTED_OPERATION,
        reason,
    );
    let task = hop.relay.task().map(|t| t.task_id.as_str());
    relay::RelayReply::refused(&refusal, task)
}

/// BIND the hop to the binding `member`'s card held under `generation` declares; the refusal's
/// answer when the plane frames none of them.
fn bind(
    reach: &Reach<'_>,
    hop: &mut Hop,
    member: &str,
    generation: u64,
    configured_url: &str,
) -> Option<PieceAnswer> {
    let card = reach.plane.cards.at(member, generation);
    let word = crate::binding::select(card.as_deref(), configured_url).word;
    match crate::binding::speakable(&word) {
        Some(binding) => {
            let null = serde_json::Value::Null;
            let envelope = hop
                .rewritten
                .as_deref()
                .or(hop.request.as_deref())
                .unwrap_or(&null);
            hop.relay.bind(binding, envelope);
            None
        }
        None => Some(hop.relay.refuse_unspeakable(&word)),
    }
}

/// The caller's answer as its line spells it: on the HTTP+JSON line (`target_line`) a whole answer
/// is re-framed ([`crate::rest::reframe`]) and each event to its bare result
/// ([`crate::events::reframe_events`]), as the engine re-frames what its shared sequence answered;
/// on the JSON-RPC line it leaves as the relay wrote it.
#[must_use]
pub fn for_line(answer: PieceAnswer, target_line: bool) -> PieceAnswer {
    match answer {
        PieceAnswer::ToCaller(mut reply) if target_line => {
            let original = zeroize::Zeroizing::new(std::mem::take(&mut reply.body));
            reply.body = crate::rest::reframe(reply.status, &original);
            PieceAnswer::ToCaller(reply)
        }
        PieceAnswer::Part(mut part) if target_line => {
            let original = zeroize::Zeroizing::new(std::mem::take(&mut part.body));
            part.body = crate::events::reframe_events(&original);
            PieceAnswer::Part(part)
        }
        other => other,
    }
}

/// One piece of `unit`'s hop, applied (unless it continues or re-calls the answer still owed) and
/// written into the host's buffers, answering the outcome and whether the unit is done.
fn hop_piece(
    reach: &Reach<'_>,
    unit: &mut AgentUnit,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> (Outcome, bool) {
    let given = input;
    let bytes = input.bytes().bytes();
    let given_member = input.member().as_str().unwrap_or_default();
    let caller = input.caller_ref().as_str().unwrap_or_default();

    if let Some(hop) = unit.hop.as_mut() {
        if given.from() == FROM_KERNEL && !given_member.is_empty() {
            hop.member = given_member.to_string();
        }
    }
    let member_owned = unit
        .hop
        .as_ref()
        .map(|h| h.member.clone())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| given_member.to_string());
    let member = member_owned.as_str();
    let section = unit.section.clone();
    let def = section.as_ref().and_then(|s| s.agents.get(member));
    let url = def.map(|def| def.url.as_str());

    if unit.agent.is_none() && unit.pool.is_none() {
        let given_pool = input.pool().as_str().unwrap_or_default();
        if unit
            .section
            .as_ref()
            .is_some_and(|s| s.pools.contains_key(given_pool))
        {
            unit.pool = Some(given_pool.to_string());
        }
    }
    let addressed = unit.agent.clone();
    let generation = unit.generation;
    let framed = unit.framed;
    let target_line = unit.envelope.is_some() && framed.is_none();

    let pooled = unit.pool.as_ref().and_then(|name| {
        let members = section.as_ref()?.pools.get(name)?;
        Some((name.as_str(), members))
    });
    let pass = &mut unit.pass;
    let Some(hop) = unit.hop.as_mut() else {
        return (Outcome::Refused, false);
    };
    if let Some(url) = &url {
        hop.relay.name_backend(member, url);
    }
    if given.from() == FROM_FAR_END {
        hop.heard = true;
    }

    let refused = given.from() == FROM_KERNEL && given.flags() & PIECE_REFUSED != 0;
    let breaker_refused =
        given.reason() == busbar_contract::abi::plane::RefusalCode::BreakerOpen.code();
    let attempt = given.from() == FROM_KERNEL && !refused;

    let continues = hop.outbox.live
        && (hop.outbox.recall
            || (bytes.is_empty() && given.flags() == 0 && given.attempt_no() == 0));

    let mut holder_refusal = None;
    if let (false, Some((_, members))) = (continues, pooled.as_ref()) {
        let memberless = given.from() == FROM_CALLER && given_member.is_empty();
        if memberless || (refused && breaker_refused) {
            match read_holder(reach, hop, pass, caller, members) {
                Poll::Pending => return (Outcome::Pending, false),
                Poll::Ready(Err(())) => holder_refusal = Some(holder_unavailable(hop)),
                Poll::Ready(Ok(_)) => {}
            }
        }
    }

    let wait_member = (refused && breaker_refused)
        .then(|| hop.holder.clone().flatten())
        .flatten()
        .filter(|h| pooled.as_ref().is_some_and(|(_, m)| m.contains(h)));
    if !continues {
        let mut pool_refusal = holder_refusal;
        let ungated = pool_refusal.is_none() && attempt && hop.gated != given.attempt_no();
        if let (true, Some((name, members))) = (ungated, pooled.as_ref()) {
            let pool = statement::agent_resource(name);
            let gate = PoolGate {
                pool: &pool,
                members,
                member,
                addressed: addressed.as_deref(),
                caller,
                generation,
            };
            match pool_gate(reach, hop, pass, &gate) {
                Gate::Pending => return (Outcome::Pending, false),
                Gate::Decline => {
                    out.set(|o| &o.verdict, VERDICT_RETRY);
                    return (Outcome::Ready, false);
                }
                Gate::Refuse(reply) => {
                    hop.gated = given.attempt_no();
                    hop.admitted = true;
                    pool_refusal = Some(reply);
                }
                Gate::Go => hop.gated = given.attempt_no(),
            }
        }

        if !attempt {
            pass.unrecorded = None;
        }
        let mut writes = std::mem::take(&mut hop.held_writes);

        let admission = match (&def, attempt && !hop.admitted) {
            (Some(def), true) => {
                let admitted = match caller_stands(reach, pass, member, addressed.as_deref()) {
                    Some(refusal) => Err(refusal),
                    None => admit_unit(
                        reach.plane,
                        (member, def),
                        addressed.as_deref(),
                        unit.generation,
                        hop.request.as_deref(),
                    ),
                };
                match admitted {
                    Ok(skill) => {
                        hop.admitted = true;
                        hop.skill = skill;
                        None
                    }
                    Err(refusal) => Some(relay::RelayReply::refused(&refusal, None)),
                }
            }
            (None, true) if !member.is_empty() => Some(relay::RelayReply::refused(
                &agent_arrival::no_such_agent(member),
                None,
            )),
            _ => None,
        };
        let opened = if let Some(reply) = pool_refusal.or(admission) {
            Some(reply)
        } else if attempt {
            let skill = hop.skill.clone();
            let request = (caller, member, addressed.as_deref());
            match open_task(reach, hop, pass, request, skill, &mut writes) {
                Err(outcome) => return (outcome, false),
                Ok(refused) => refused,
            }
        } else if refused && breaker_refused && !hop.left {
            let agent = match member {
                "" => addressed
                    .clone()
                    .or_else(|| pooled.as_ref().and_then(|(_, m)| m.first().cloned()))
                    .unwrap_or_default(),
                member => member.to_string(),
            };
            let request = (caller, agent.as_str(), addressed.as_deref());
            match open_task(reach, hop, pass, request, None, &mut writes) {
                Err(outcome) => return (outcome, false),
                Ok(_) => None,
            }
        } else {
            None
        };

        let opened = match (opened, hop.mismatch.take()) {
            (None, Some(reason)) if attempt => {
                busbar_contract::diag_debug!(
                    crate::diagnostics::A2A_POOL_NOT_INTERCHANGEABLE,
                    reason = %reason,
                    "a2a: the pool's members are not interchangeable; the submission is not accepted"
                );
                if hop.relay.task().is_some_and(|t| !t.addressed) {
                    hop.settle.push(TaskSettled::Reported {
                        state: crate::a2a::task::TaskState::Rejected,
                        backend_id: None,
                    });
                }
                Some(not_interchangeable(hop, reason))
            }
            (opened, _) => opened,
        };

        let demoted = match (&def, attempt && opened.is_none()) {
            (Some(def), true) => {
                match verify_agent_on_call(reach, hop, pass, member, def, unit.generation) {
                    Poll::Pending => {
                        hop.held_writes = writes;
                        return (Outcome::Pending, false);
                    }
                    Poll::Ready(Ok(true)) => None,
                    Poll::Ready(Ok(false)) => Some(hop.relay.refuse_demoted()),
                    Poll::Ready(Err(outcome)) => {
                        hop.held_writes = writes;
                        return (outcome, false);
                    }
                }
            }
            _ => None,
        };

        let unspeakable = if attempt && opened.is_none() && demoted.is_none() {
            def.as_ref()
                .and_then(|def| bind(reach, hop, member, unit.generation, &def.url))
        } else {
            None
        };

        let unguarded = match (&def, &url) {
            (Some(def), Some(url))
                if attempt && opened.is_none() && demoted.is_none() && unspeakable.is_none() =>
            {
                match guard_relay(reach, hop, pass, url, def, given.attempt_no()) {
                    Poll::Pending => {
                        hop.held_writes = writes;
                        return (Outcome::Pending, false);
                    }
                    Poll::Ready(refused) => refused,
                }
            }
            _ => None,
        };
        let mut answer = match (opened, demoted.or(unspeakable).or(unguarded)) {
            _ if refused => {
                use busbar_contract::abi::plane::RefusalCode as Code;
                let ends = if given.reason() == Code::CredentialUnavailable.code() {
                    let agent = if member.is_empty() {
                        addressed.clone().unwrap_or_default()
                    } else {
                        member.to_string()
                    };
                    credential_refused(hop, &agent, target_line)
                } else if given.reason() == Code::BreakerOpen.code() && hop.left {
                    hop_refused(hop, HopRelay::refuse_transport, target_line)
                } else if breaker_refused && hop.rejected.is_none() {
                    if let Some(task) = hop.relay.task().filter(|t| !t.addressed) {
                        hop.rejected = Some(task.task_id.clone());
                        hop.settle.push(TaskSettled::Reported {
                            state: crate::a2a::task::TaskState::Rejected,
                            backend_id: None,
                        });
                    }
                    false
                } else {
                    false
                };
                if ends {
                    hop.settle.push(TaskSettled::Failed);
                }
                PieceAnswer::Nothing
            }
            (Some(reply), _) => PieceAnswer::ToCaller(reply),
            (None, Some(answer)) => answer,
            (None, None) => {
                let from = match given.from() {
                    FROM_KERNEL => relay::From::Kernel(url),
                    FROM_CALLER => relay::From::Caller,
                    FROM_FAR_END => relay::From::FarEnd,
                    _ => return (Outcome::Refused, false),
                };
                let status = (given.flags() & PIECE_HAS_STATUS != 0).then_some(given.status_code());
                let last = given.flags() & PIECE_LAST != 0;

                if from == relay::From::FarEnd
                    && given.flags() & busbar_contract::abi::plane::PIECE_CUT != 0
                {
                    let payload = if given.flags() & busbar_contract::abi::plane::PIECE_FIELDS != 0
                    {
                        &[][..]
                    } else {
                        bytes
                    };
                    hop.relay.on_far_cut(payload, status)
                } else if from == relay::From::FarEnd
                    && given.flags() & busbar_contract::abi::plane::PIECE_FIELDS != 0
                {
                    hop.relay.on_far_fields(bytes, status, last)
                } else {
                    hop.relay.on_piece(relay::Piece {
                        from,
                        bytes,
                        status,
                        last,
                    })
                }
            }
        };
        if let (PieceAnswer::Attempt(attempt), Some(judged)) = (&mut answer, &hop.endpoint_judged) {
            if !judged.within.is_empty() {
                attempt.fields.push((
                    busbar_contract::abi::host::conn::connector::WITHIN_REQUEST_FIELD,
                    judged.within.clone().into(),
                ));
            }
        }
        let outbox = match framed {
            _ if refused => Outbox::of(answer),
            Some(rpc) => Outbox::framed(answer, rpc),
            None => Outbox::of(for_line(answer, target_line)),
        };
        let Some(outbox) = outbox else {
            return (Outcome::Refused, false);
        };
        hop.outbox = outbox;
        hop.outbox.writes = writes;

        hop.outbox.fault = hop.relay.take_reading().map_or(FAULT_NONE, fault_of);
        hop.settle.extend(hop.relay.take_settled());

        hop.outbox.recall = true;
    }
    if !hop.settle.is_empty() {
        if let Err(outcome) = settle_task(reach, hop, pass, caller) {
            if hop.outbox.lent {
                hop.outbox.lent = false;
                hop.outbox.bytes = bytes.to_vec().into();
                hop.outbox.at = 0;
            }
            return (outcome, false);
        }
    }

    pass.response_only |= pass.publication.response_only();
    let response_only = pass.response_only;
    if response_only
        && (hop.outbox.to_far
            || matches!(hop.outbox.head, Some(AnswerHead::Attempt(_)))
            || !hop.outbox.writes.is_empty())
    {
        return (
            out.fail(Refusal::failed(
                "a refused conditional publication may only answer its caller",
            )),
            false,
        );
    }

    if matches!(hop.outbox.head, Some(AnswerHead::Attempt(_))) {
        hop.left = true;
    }

    let undialled = refused
        && given.reason() == busbar_contract::abi::plane::RefusalCode::CredentialUnavailable.code()
        && !hop.heard;
    if undialled {
        hop.left = false;
    }
    let left = hop.left;
    let admitted = hop.admitted;
    let need = attempt_need(hop.relay.binding());

    let binding_word = match hop.relay.binding() {
        crate::binding::Binding::JsonRpc => crate::binding::BINDING_DOCUMENT,
        crate::binding::Binding::HttpJson => crate::binding::BINDING_TARGET,
        crate::binding::Binding::Grpc => crate::binding::BINDING_FRAMED,
    };
    let ob = &mut hop.outbox;
    let (mut reply, mut fields, mut records, mut arena, mut units) = (
        input.reply_buf(),
        input.fields_buf(),
        input.records_buf(),
        input.arena_buf(),
        input.units_buf(),
    );

    let moved = if refused || response_only {
        0
    } else {
        hop.relay.moved()
    };
    if moved != 0 {
        units.push(UnitCount {
            class: statement::CLASS_BYTES_INDEX,
            source: UNITS_REPORTED,
            amount: moved,
        });
    }
    if left && !refused && !response_only {
        units.push(UnitCount {
            class: statement::CLASS_FEE_INDEX,
            source: UNITS_REPORTED,
            amount: 1,
        });
    }
    if undialled && !response_only {
        for class in [statement::CLASS_BYTES_INDEX, statement::CLASS_FEE_INDEX] {
            units.push(UnitCount {
                class,
                source: UNITS_REPORTED,
                amount: 0,
            });
        }
    }
    let mut head_fields = |list: &[(&'static str, std::borrow::Cow<'static, str>)]| {
        for (name, value) in list {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
    };
    let (mut verb, mut target, mut status) = (None, None, 0);
    match &ob.head {
        Some(AnswerHead::Attempt(a)) => {
            head_fields(&a.fields);
            verb = Some(arena.span(a.verb.as_bytes()));
            target = Some(arena.span(a.target.as_bytes()));
        }
        Some(AnswerHead::Reply(s, content_type)) => {
            head_fields(&[
                (relay::H_CONTENT_TYPE, (*content_type).into()),
                (H_CONTENT_LENGTH, ob.bytes.len().to_string().into()),
            ]);
            status = *s;
        }
        Some(AnswerHead::Events) => {
            head_fields(&EVENTS_HEAD.map(|(name, value)| (name, value.into())));
            status = relay::STATUS_OK;
        }

        Some(AnswerHead::Framed) => {
            head_fields(&[(
                relay::H_CONTENT_TYPE,
                crate::framed::REPLY_CONTENT_TYPE.into(),
            )]);
            status = relay::STATUS_OK;
        }
        None => {}
    }
    for w in &ob.writes {
        records.push(RecordWrite {
            kind: kind_index(w.kind),
            op: RECORD_PUT,
            key: arena.span(w.key.as_bytes()),
            value: arena.span(&w.value),
        });
    }

    let caller_head = matches!(
        ob.head,
        Some(AnswerHead::Reply(..) | AnswerHead::Events | AnswerHead::Framed)
    );
    if caller_head && admitted && !member.is_empty() && !response_only {
        records.push(statement::audit_write(
            &mut arena,
            &statement::agent_resource(member),
            left,
        ));
    }

    let lane = (!member.is_empty() && !response_only)
        .then(|| arena.span(statement::agent_resource(member).as_bytes()));
    let wait_member = wait_member
        .filter(|_| !response_only)
        .map(|h| arena.span(h.as_bytes()));

    let metric =
        (matches!(ob.head, Some(AnswerHead::Attempt(_))) && !member.is_empty() && !response_only)
            .then(|| {
                (
                    arena.span(member.as_bytes()),
                    arena.span(binding_word.as_bytes()),
                )
            });

    let closing_final = ob
        .final_status
        .as_ref()
        .filter(|_| ob.done && ob.queue.is_empty())
        .map(|f| {
            (
                f.code,
                arena.span(&f.body),
                arena.span(f.details.as_deref().unwrap_or_default().as_bytes()),
            )
        });
    let short = busbar_contract::abi::sdk::plane::settle_piece(
        out,
        &fields,
        &units,
        &arena,
        Some(&records),
    );
    if short {
        if ob.lent {
            ob.lent = false;
            ob.bytes = bytes.to_vec().into();
            ob.at = 0;
        }
        ob.recall = true;
        return (Outcome::Failed, false);
    }
    let n = if ob.lent {
        ob.lent = false;
        let n = reply.stream(bytes);
        ob.bytes = bytes[n..].to_vec().into();
        ob.at = 0;
        n
    } else {
        ob.drain(|bytes| reply.stream(bytes))
    };

    let message_end = ob.messages && ob.at >= ob.bytes.len();

    if ob.at >= ob.bytes.len() {
        if let Some(next) = ob.queue.pop_front() {
            ob.bytes = next;
            ob.at = 0;
        }
    }
    ob.head = None;
    ob.writes.clear();
    ob.recall = false;
    let more = ob.at < ob.bytes.len();
    ob.live = more;
    let mut flags = 0;
    if ob.to_far {
        flags |= EMIT_TO_FAR_END;
    }
    let done = ob.done && !more;
    if done {
        flags |= EMIT_DONE;
    }
    if message_end {
        flags |= busbar_contract::abi::plane::EMIT_MESSAGE_END;
    }
    if let Some((code, message, details)) = closing_final.filter(|_| done) {
        flags |= busbar_contract::abi::plane::EMIT_FINAL_STATUS;
        out.set(|o| &o.final_status, code);
        out.set(|o| &o.final_message, message);
        out.set(|o| &o.final_details, details);
    }
    if let (Some(v), Some(t)) = (verb, target) {
        out.set(|o| &o.verb, v);
        out.set(|o| &o.target, t);

        out.set(|o| &o.need, need);
    }
    if let Some(lane) = lane {
        out.set(|o| &o.lane, lane);
    }
    if let Some(wait) = wait_member {
        out.set(|o| &o.wait_member, wait);
    }
    if let Some((pool, lane)) = metric {
        out.set(|o| &o.metric_pool, pool);
        out.set(|o| &o.metric_lane, lane);
    }
    out.set(|o| &o.emitted, n as u64);
    out.set(|o| &o.more, u32::from(more));
    out.set(|o| &o.flags, flags);
    out.set(|o| &o.reply_status, status);

    let fault = std::mem::replace(&mut ob.fault, FAULT_NONE);
    out.set(|o| &o.fault, if response_only { FAULT_NONE } else { fault });
    (Outcome::Ready, done)
}

/// Return the one-based outbound need index for the selected binding.
#[must_use]
pub fn attempt_need(binding: crate::binding::Binding) -> u32 {
    match binding {
        crate::binding::Binding::Grpc => statement::NEED_GRPC + 1,
        crate::binding::Binding::JsonRpc | crate::binding::Binding::HttpJson => 0,
    }
}

/// The shared fault reading a [`relay::Reading`] is.
fn fault_of(reading: relay::Reading) -> u8 {
    match reading {
        relay::Reading::Healthy => FAULT_HEALTHY,
        relay::Reading::Caller => FAULT_CALLER,
        relay::Reading::Transient => FAULT_TRANSIENT,
        relay::Reading::Hard => FAULT_HARD,
    }
}

slot!(
    /// `on_piece`: the unit's unary hop, one piece at a time ([`crate::relay`]); otherwise a verb
    /// the plane answers itself, over the task store ([`crate::task_door`]); a unit that is
    /// neither is REFUSED. A finished hop's unit is over ([`AgentUnit::over`]).
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let unit = input.unit();
        // THE HELD CARDS ARE WARM BEFORE ANY PIECE IS SERVED: a unit's admission reads the card it
        // fits, so a unit whose first piece came before the instance's first tick warms them here,
        // on its own ticket ([`warm_cards`]), rather than being refused for want of a card its
        // operator approved (`NoCachedCard`). The warm's handles are the unit's: they count on
        // from its pass, and its pass counts on from after them, so no piece of the unit issues a
        // handle the warm's listing was answered on (busbar keeps each handle's first answer). A
        // unit whose warm pended replays it on its next entry, on the same handles, even when
        // another unit's warm landed meanwhile. A warm the host refused leaves the cards unwarmed
        // and the unit served: each unit warms on its first piece only (its ticket not yet
        // recorded), so a store that keeps refusing the listing costs a unit one warm, not one per
        // piece.
        let warm = plane.units.with(&unit, |u| {
            u.map(|u| (u.pass.warming, u.pass.issued, u.ticket == Ticket::NONE))
        });
        if let Some((warming, issued, first)) = warm {
            if warming || (first && !plane.cards_warmed.get(&()).unwrap_or(false)) {
                let (warmed, counted) = warm_cards(plane, instance.ticket(), issued);
                let Poll::Ready(landed) = warmed else {
                    plane.on_unit(unit, |u| {
                        u.pass.warming = true;
                    });
                    return Outcome::Pending;
                };
                plane.on_unit(unit, |u| {
                    u.pass.warming = false;
                    u.pass.issued = counted;
                });
                if landed {
                    plane.cards_warmed.insert((), true);
                }
            }
        }
        // The unit's ticket, which the kernel's `cancel` names it by.
        let ticket = instance.ticket();
        plane.on_unit(unit, |u| {
            u.ticket = ticket;
        });
        // A REFUSED PIECE (`TAIL_REFUSED_PIECE`) ends only a relayed hop's task: a unit with no hop
        // has nothing to end, and `refusal` answers it.
        let refused = input.from() == FROM_KERNEL && input.flags() & PIECE_REFUSED != 0;
        if refused && plane.units.with(&unit, |u| u.is_none_or(|u| u.hop.is_none())) {
            return Outcome::Ready;
        }
        let card = plane.units.with(&unit, |u| match u {
            Some(u) => match &u.disposition {
                AgentDisposition::Card(ask) => Some(*ask),
                AgentDisposition::Request { row, .. }
                    if row.op == crate::ops::OP_AGENT_CARD && u.agent.is_none() =>
                {
                    Some(agent_arrival::CardAsk::Extended)
                }
                _ => None,
            },
            None => None,
        });
        if let Some(ask) = card {
            return crate::task_door::card_piece(plane, &instance, input, out, ask);
        }
        let journal = plane.units.with(&unit, |u| u.map(|u| u.pass.publication.clone()));
        let Some(journal) = journal else { return Outcome::Refused; };
        let entered = journal.enter(instance.ticket(), input.head().extensions().bytes());
        if entered.is_err() {
            crate::push_door::apply_publication(plane, &journal);
            return Outcome::Failed;
        }
        plane.deliveries.apply_deletions(&journal);
        if let Some(outcome) = journal.pending(&plane.publication_leases, &mut out) {
            if outcome != Outcome::Pending { crate::push_door::apply_publication(plane, &journal); }
            return outcome;
        }
        let relayed = plane.units.with(&unit, |u| u.is_some_and(|u| u.hop.is_some()));
        if !relayed {
            return crate::task_door::on_piece(plane, &instance, input, out)
                .unwrap_or(Outcome::Refused);
        }
        let reach = Reach {
            plane,
            ticket: instance.ticket(),
        };
        let (outcome, done) = plane.units.with(&unit, |u| match u {
            Some(u) => hop_piece(&reach, u, input, &mut out),
            None => (Outcome::Refused, false),
        });
        plane.deliveries.retain_publication(&journal);
        if let Some(pending) = journal.pending(&plane.publication_leases, &mut out) {
            if pending != Outcome::Pending { crate::push_door::apply_publication(plane, &journal); }
            return pending;
        }
        if outcome == Outcome::Ready {
            crate::push_door::apply_publication(plane, &journal);
            journal.finished();
            if journal.completed() { plane.deliveries.release_publication(&journal); }
        } else if outcome != Outcome::Pending {
            crate::push_door::apply_publication(plane, &journal);
        }
        // A FINISHED HOP'S UNIT IS OVER, never dropped here: a `refusal` of the answer it wrote
        // (the store refused its record writes, a response hook vetoed it) still reads it.
        if done {
            plane.on_unit(unit, AgentUnit::end);
            plane.unit_ended();
        }
        outcome
    }
);

/// THE AGENTS OF `reachable` (the kernel's list for a unit routed by scope) IN THE CALLER'S
/// CATALOGUE: the engine chose among those, and an agent the kernel's trust book does not serve,
/// holds no card, or whose card the unit's request does not fit, is in no catalogue
/// ([`admit_unit`]).
fn serving_of(plane: &A2aDoor, unit: u64, reachable: &str) -> String {
    use busbar_contract::abi::plane::ROUTE_SCOPE_SEPARATOR;
    let Some((generation, section, envelope)) = plane.units.with(&unit, |u| {
        u.map(|u| {
            (
                u.generation,
                u.section.clone(),
                u.ended_shape.clone().unwrap_or_else(|| {
                    u.hop
                        .as_ref()
                        .and_then(|h| h.request.as_deref())
                        .map(crate::skill::TaskShape::of)
                        .unwrap_or_default()
                }),
            )
        })
    }) else {
        return String::new();
    };
    let serving: Vec<&str> = reachable
        .split(ROUTE_SCOPE_SEPARATOR)
        .filter(|id| {
            section
                .as_ref()
                .and_then(|s| s.agents.get(*id))
                .is_some_and(|_def| admit_shape(plane, id, Some(id), generation, &envelope).is_ok())
        })
        .collect();
    if serving.len() == 1 {
        return reachable.to_string();
    }
    serving.join(ROUTE_SCOPE_SEPARATOR)
}

/// THE ONE AGENT AN UNADDRESSED UNIT WOULD BE SERVED BY: the agents of the unit's section that
/// would serve its request ([`admit_unit`], the candidates its arrival named), when exactly one
/// does; `None` when none or several do.
fn sole_serving(plane: &A2aDoor, unit: u64) -> Option<String> {
    let (generation, section, envelope) = plane.units.with(&unit, |u| {
        u.map(|u| {
            (
                u.generation,
                u.section.clone(),
                u.ended_shape.clone().unwrap_or_else(|| {
                    u.hop
                        .as_ref()
                        .and_then(|h| h.request.as_deref())
                        .map(crate::skill::TaskShape::of)
                        .unwrap_or_default()
                }),
            )
        })
    })?;
    let section = section?;
    let mut serving = section
        .agents
        .keys()
        .filter(|id| admit_shape(plane, id.as_str(), None, generation, &envelope).is_ok());
    let one = serving.next()?;
    serving.next().is_none().then(|| one.clone())
}

/// The agent an open breaker's refusal of an unaddressed unit names: its one serving agent
/// ([`sole_serving`]), or the pool that agent is a member of in the section the unit arrived
/// under, whose walk refused it.
fn breaker_subject(plane: &A2aDoor, unit: u64) -> Option<String> {
    let one = sole_serving(plane, unit)?;
    let section = plane
        .units
        .with(&unit, |u| u.and_then(|u| u.section.clone()));
    let pool = section.and_then(|s| s.pool_of(&one).map(|(name, _)| name.to_string()));
    Some(pool.unwrap_or(one))
}

slot!(
    /// `refusal`: a refused arrival rendered in its own words and status, and a kernel or gate
    /// refusal in the engine's admission words at the kernel's status, each in the line's dialect;
    /// on the gRPC line, the envelope at its neutral status, for the grpc transport to map. The
    /// gate-rejected marker is the kernel's: this rendering never sets it.
    RefusalSlot, RefusalIn, RefusalOut, |instance, input, mut out| {
        let given = input;
        // An unaddressed unit no one agent of the caller's grant reaches (the kernel's
        // `no_destination` for a unit routed by scope): the words naming the several agents it
        // reaches named from the kernel's text.
        let scoped = given.reason() == busbar_contract::abi::plane::RefusalCode::NoDestination.code()
            && of_unit(&instance, given.unit(), |u| u.agent.is_none().then_some(())).is_some();
        // A REFUSAL BEFORE `arrive` READ ITS LINE (the kernel decoded none, so it states the first
        // dialect): the plane chooses its envelope from the target by its own rule (abi/plane
        // `RefusalIn::target`), and a call on the gRPC service is refused on the gRPC line.
        let asked = input.target().as_str().unwrap_or_default();
        let dialect = match given.dialect() {
            statement::DIALECT_DOCUMENT if crate::framed::on_service(asked) => Dialect::Framed,
            statement::DIALECT_DOCUMENT if crate::rest::on_target(asked) => Dialect::RestJson,
            statement::DIALECT_DOCUMENT => Dialect::JsonRpc,
            statement::DIALECT_TARGET => Dialect::RestJson,
            statement::DIALECT_FRAMED => Dialect::Framed,
            _ => return Outcome::Refused,
        };
        let text = input.text().bytes();
        // A unit its agent's open breaker refused before it dialled: the words naming
        // the agent and the seconds until it may be dialled again, which `Retry-After` repeats.
        let retry_after = given.retry_after_s().max(1);
        let breaker =
            given.reason() == busbar_contract::abi::plane::RefusalCode::BreakerOpen.code();
        // The walk ended with no member left AFTER the unit's attempt went out (the connection to
        // the agent failed, or closed unanswered): the engine's transport failure, not the
        // breaker's words ([`transport_refusal`]).
        let transport = breaker
            .then(|| of_unit(&instance, given.unit(), transport_refusal))
            .flatten();
        let tripped = (breaker && transport.is_none())
            .then(|| {
                instance.get().and_then(|plane| {
                    let (id, agent) = plane.units.with(&given.unit(), |u| {
                        let u = u?;
                        let id = u.disposition.rpc_id();
                        // A unit over a failover pool names the member its task is pinned to
                        // (a pinned hop: the member's own breaker), else the pool, whose
                        // walk found nothing admissible.
                        let pinned = u.hop.as_ref().and_then(|h| h.holder.clone()).flatten();
                        let named = match (&u.pool, pinned) {
                            (Some(_), Some(holder)) => Some(holder),
                            (Some(pool), None) => Some(pool.clone()),
                            (None, _) => u.agent.clone(),
                        };
                        Some((id, named))
                    })?;
                    // An unaddressed unit names the agent the engine would have selected for it:
                    // the one serving agent of its catalogue (before the breaker).
                    // An unaddressed unit whose one agent is a pool member was walked over the pool
                    // (the kernel routes it as an addressed one): the walk's refusal names the pool.
                    let agent = agent.or_else(|| breaker_subject(plane, given.unit()))?;
                    Some(agent_arrival::breaker_refusal(&agent, id, retry_after))
                })
            })
            .flatten();
        // A unit whose agent the KERNEL'S TRUST BOOK does not serve (its Approve refused the trust
        // facts the arrival stated: never approved, or quarantined): the admission's words for an
        // agent that is not serving, at the kernel's status, its state the book's verdict.
        let untrusted = (given.reason()
            == busbar_contract::abi::plane::RefusalCode::Untrusted.code())
        .then(|| {
            of_unit(&instance, given.unit(), |u| {
                Some(crate::card_trust::not_serving(
                    Some(u.agent.as_deref()?),
                    crate::card_trust::verdict_state(u64::from(given.trust())),
                    given.status(),
                ))
            })
        })
        .flatten();
        // A unit `project` refused for a committed rewrite it could not read back: a
        // conformant internal error, echoing the request id.
        let unreadable = instance.get().and_then(|plane| {
            plane.units.with(&given.unit(), |u| {
                let u = u.filter(|u| u.unreadable_rewrite)?;
                let id = u.disposition.rpc_id();
                Some(unreadable_rewrite(id))
            })
        });
        // A hop the kernel refused for busbar's own credential: the engine's answer to a lease it
        // could not mint, made on the refused piece, which ended its task ([`credential_refusal`]).
        let credential = (given.reason()
            == busbar_contract::abi::plane::RefusalCode::CredentialUnavailable.code())
        .then(|| of_unit(&instance, given.unit(), credential_refusal))
        .flatten();
        // A unit whose record writes the store refused: the engine's answer for the write its verb
        // could not make durable, at its own status ([`crate::task_door::Pass`]'s `unrecorded`).
        let unrecorded = (given.reason()
            == busbar_contract::abi::plane::RefusalCode::DurabilityUnavailable.code())
        .then(|| of_unit(&instance, given.unit(), |u| u.pass.unrecorded.clone()))
        .flatten();
        // A KERNEL REFUSAL WITH NO UNIT (no credential, a body over the cap: refused before any
        // unit was made) answers the bytes the route answers, a JSON-RPC error with no
        // id, at the kernel's own status, on every line. The bytes live once, in the contract's
        // JSON-RPC module, beside the envelope they are an instance of.
        let unitless = (given.unit() == 0 && given.cause() == REFUSAL_KERNEL)
            .then(|| busbar_contract::jsonrpc::unitless_kernel_body(given.reason()))
            .flatten();
        let mut rendered = if let Some(body) = unitless {
            // `0`: the kernel's status stands.
            agent_arrival::Rendered {
                status: 0,
                body: body.to_vec(),
                content_type: "application/json",
            }
        } else if let Some(refusal) = &unreadable {
            agent_arrival::render(dialect, refusal, true)
        } else if let Some(refusal) = &unrecorded {
            agent_arrival::render(dialect, refusal, true)
        } else if let Some(reply) = credential.as_ref().or(transport.as_ref()) {
            agent_arrival::Rendered {
                status: reply.status,
                body: reply.body.clone(),
                content_type: reply.content_type,
            }
        } else if let Some(refusal) = &tripped {
            // A fresh submission's refusal names the task it rejected,
            // read off the unit's own memory: this slot is ticketless.
            let rejected = of_unit(&instance, given.unit(), |u| u.hop.as_ref()?.rejected.clone());
            match rejected {
                Some(task) => agent_arrival::render_about_task(dialect, refusal, &task),
                None => agent_arrival::render(dialect, refusal, true),
            }
        } else if let Some(refusal) = &untrusted {
            agent_arrival::render(dialect, refusal, true)
        } else if scoped {
            let reachable = std::str::from_utf8(text).unwrap_or_default();
            let serving = instance
                .get()
                .map_or_else(|| reachable.to_string(), |plane| {
                    serving_of(plane, given.unit(), reachable)
                });
            agent_arrival::render(dialect, &agent_arrival::scope_refusal(&serving), true)
        } else if given.cause() == REFUSAL_ARRIVE {
            let Some(refusal) = agent_arrival::AgentRefusal::from_words(text) else {
                return Outcome::Refused;
            };
            agent_arrival::render(dialect, &refusal, true)
        } else {
            let text = std::str::from_utf8(text).unwrap_or_default();
            // A refusal of the caller's governance (a spent budget, a request limit, a frozen
            // group, a reached overdraft ceiling) in the engine's own words for it.
            use busbar_contract::abi::plane::RefusalCode as Code;
            let governance = [
                Code::RateLimited,
                Code::OverBudget,
                Code::GroupFrozen,
                Code::OverdraftCeiling,
            ]
            .iter()
            .any(|c| c.code() == given.reason());
            let text = if governance { agent_arrival::BUDGET_SPENT } else { text };
            // A caller whose grant does not reach the agent it addressed: the engine's
            // `NotInScope` sentence, naming the agent's scope.
            let ungranted = (given.reason() == Code::ScopeDenied.code())
                .then(|| of_unit(&instance, given.unit(), |u| u.agent.clone()))
                .flatten()
                .map(|agent| agent_arrival::not_granted_sentence(&statement::agent_resource(&agent)));
            let text = ungranted.as_deref().unwrap_or(text);
            // The code is the reason's CLASS's (`class_code`): a node fault reads as the internal
            // error, every other class as the engine's admission refusal.
            let refusal = agent_arrival::kernel_refusal_of(given.reason(), given.status(), text);
            agent_arrival::render(dialect, &refusal, false)
        };
        // ON THE gRPC LINE the rendered envelope is the status the call ends with, as the engine's
        // bridge read its ingress's envelope: the status in the line's own numbering, its message
        // and its details, stated as the closing block the stream's framer sends as the whole
        // answer, at the refusal's neutral status (SEAM-4l: a block stating `grpc-status` is the
        // close; the neutral status is what a framer maps when the block states none).
        let rendered_body = relay::RawBytes::from(std::mem::take(&mut rendered.body));
        let (body, head, status) = if dialect == Dialect::Framed && unitless.is_none() {
            let neutral = if rendered.status == 0 {
                given.status()
            } else {
                rendered.status
            };
            let reply = crate::framed::refusal(&rendered_body, neutral);
            (relay::RawBytes::from(crate::framed::status_block(&reply)), Vec::new(), neutral)
        } else {
            let mut head = vec![("content-type", rendered.content_type.to_string())];
            // AN OPEN BREAKER'S WAIT rides every HTTP line's refusal as `Retry-After`, whatever words
            // it carries (the engine's `refuse_hop`: `503` + `Retry-After` from the cell's own
            // deadline); on the gRPC line it is the status message's own words alone.
            if breaker && transport.is_none() {
                head.push(("retry-after", retry_after.to_string()));
            }
            (rendered_body, head, rendered.status)
        };
        // THE UNIT'S AUDIT ROW, rejected, for a refusal the engine made after its admission (a
        // gate's veto, a spent budget, an open breaker), naming the unit's agent (or busbar's
        // extended card's plane pool); a refusal before it (no key, no grant) leaves none.
        use busbar_contract::abi::plane::RefusalCode;
        let after_admission = given.cause() == busbar_contract::abi::plane::REFUSAL_GATE
            || [
                RefusalCode::HookVeto,
                RefusalCode::OverBudget,
                RefusalCode::GroupFrozen,
                RefusalCode::OverdraftCeiling,
                RefusalCode::BreakerOpen,
                RefusalCode::CredentialUnavailable,
            ]
            .iter()
            .any(|c| c.code() == given.reason())
            // An unreadable rewrite's refusal is audited `rejected`, as a hook's own.
            || unreadable.is_some();
        let audited = after_admission
            .then(|| {
                of_unit(&instance, given.unit(), |u| match (&u.disposition, &u.agent) {
                    (AgentDisposition::Request { row, .. }, None)
                        if row.op == crate::ops::OP_AGENT_CARD =>
                    {
                        Some(statement::PLANE_POOL_RESOURCE.to_string())
                    }
                    (_, Some(agent)) => Some(statement::agent_resource(agent)),
                    _ => None,
                })
            })
            .flatten();
        let (mut reply, mut fields, mut arena, mut records) = (
            input.reply_buf(),
            input.fields_buf(),
            input.arena_buf(),
            input.records_buf(),
        );
        reply.extend(&body);
        for (name, value) in &head {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
        if let Some(resource) = &audited {
            records.push(statement::audit_write(&mut arena, resource, false));
        }
        let short = !(reply.fits() && fields.fits() && arena.fits() && records.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = fields.settle(short);
        let (cw, cnd) = records.settle(short);
        out.set(|o| &o.records_written, cw as u32);
        out.set(|o| &o.records_needed, cnd as u32);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.reply_written, rw as u64);
        out.set(|o| &o.reply_needed, rnd as u64);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            return Outcome::Failed;
        }
        out.set(|o| &o.status, status);
        // THE UNIT'S LAST CALL: its refusal is rendered, and the door forgets it.
        if let Some(plane) = instance.get() {
            plane.units.remove(&given.unit());
        }
        Outcome::Ready
    }
);

/// The agent a trust verb's target names: the segment its route's `{name}` stands at.
fn verb_agent(route: &str, target: &[u8]) -> Option<String> {
    let target = std::str::from_utf8(target).ok()?;
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let at = route.split('/').position(|seg| seg == "{name}")?;
    let name = path.split('/').nth(at)?;
    (!name.is_empty()).then(|| name.to_string())
}

/// What one look landed: the sighting, and the card document a verified sighting was taken from.
#[derive(Debug)]
struct CardLook {
    sighting: crate::card_trust::Sighting,
    card: Option<serde_json::Value>,
}

/// A look paused: its card fetch on the connection need (the legacy path's or the canonical's,
/// the handle it counts on from, the exchange), or its sighting on the kernel's trust book (what
/// it landed, and the handles it issued).
#[derive(Debug)]
enum LookParked {
    /// One hop of the card fetch is in flight: its destination's judgement (`exchange` absent), or
    /// its request (the exchange, and the handle it counts on from).
    Fetching {
        registration: crate::a2a::config::AgentDefCfg,
        generation: u64,
        hop: CardHop,
        exchange: Option<ParkedExchange>,
    },
    /// The verified card is retained while the original trust decision awaits custody.
    Deciding {
        registration: crate::a2a::config::AgentDefCfg,
        generation: u64,
        looked: CardLook,
        issued: u32,
    },
    /// `trust.sight` is in flight.
    Sighted {
        registration: crate::a2a::config::AgentDefCfg,
        generation: u64,
        looked: CardLook,
        issued: u32,
        unreachable: bool,
    },
}

impl LookParked {
    fn generation(&self) -> u64 {
        match self {
            Self::Fetching { generation, .. }
            | Self::Sighted { generation, .. }
            | Self::Deciding { generation, .. } => *generation,
        }
    }

    fn registration(&self) -> &crate::a2a::config::AgentDefCfg {
        match self {
            Self::Fetching { registration, .. }
            | Self::Sighted { registration, .. }
            | Self::Deciding { registration, .. } => registration,
        }
    }
}

/// Where a look runs: the instance, the op's ticket, and the completion handle its host services
/// count on from (every service the op made before it, so a handle is never issued twice on the op:
/// the replay rule).
struct LookAt<'a> {
    plane: &'a A2aDoor,
    generation: u64,
    ticket: Ticket,
    base: u32,
}

impl LookAt<'_> {
    fn handle(&self, seq: u32) -> CompletionHandle {
        crate::task_door::handle(self.ticket, seq)
    }
}

/// A card fetch's request in flight: the handle it counts on from, and the exchange.
type ParkedExchange = (u32, Box<busbar_contract::abi::sdk::exchange::Exchange>);

/// ONE HOP OF A CARD FETCH: which discovery path it is on, how many redirects its chain followed,
/// the URL it reaches, and the handle its services count on from.
#[derive(Debug, Clone)]
struct CardHop {
    legacy: bool,
    redirects: u8,
    url: String,
    issued: u32,
    /// The canonical path's refusal, retained while its legacy fallback is in flight.
    canonical: Option<CardRefusal>,
}

#[derive(Debug, Clone)]
struct CardRefusal {
    message: String,
    transport: Option<CardTransportRefusal>,
}

#[derive(Clone)]
struct CardTransportRefusal {
    url: String,
    redirects: u8,
    cause: u64,
    failure: busbar_contract::abi::sdk::conn::ConnFailure,
}

impl std::fmt::Debug for CardTransportRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardTransportRefusal")
            .field("url", &self.url)
            .field("redirects", &self.redirects)
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

fn card_refusals(canonical: CardRefusal, legacy: CardRefusal, urls: &[String; 2]) -> String {
    let equivalent = match (&canonical.transport, &legacy.transport) {
        (None, None) => canonical.message == legacy.message,
        (Some(first), Some(second)) => {
            first.redirects == 0
                && second.redirects == 0
                && first.url == urls[0]
                && second.url == urls[1]
                && url::Url::parse(&first.url)
                    .ok()
                    .zip(url::Url::parse(&second.url).ok())
                    .is_some_and(|(first, second)| first.origin() == second.origin())
                && first.cause == second.cause
                && first.failure == second.failure
        }
        _ => false,
    };
    if equivalent {
        legacy.message
    } else {
        format!("{}; the legacy path: {}", canonical.message, legacy.message)
    }
}

/// The most addresses one card host's judgement is read for.
const JUDGED_ADDRESSES: usize = 16;
/// Room for those addresses, or for the resolver's reason a refusal names.
const JUDGED_BYTES: usize = 4096;

/// THE GUARD, AS THE ENGINE APPLIED IT TO EVERY HOP (`fetch::guard_hop`, the card fetch's and the
/// relay's alike): the host's ONE destination judgement of `url` (the name, then every address it
/// resolves to), on handle `base`.
fn judge_hop(
    at: &LookAt<'_>,
    url: &str,
    allow_private: bool,
    base: u32,
) -> Poll<Result<(u32, String), String>> {
    use busbar_contract::abi::host::conn::connector::{
        EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    };
    use busbar_contract::abi::host::service::{DEST_ALLOWED, DEST_EXPLAIN, DEST_REFUSE_PRIVATE};

    let Some(services) = at.plane.services else {
        return Poll::Ready(Err(format!(
            "agent card fetch of `{url}` refused: no destination judgement is available (the \
             host lent no services)"
        )));
    };

    let (class, flags) = if allow_private {
        (EGRESS_OPERATOR_INFRASTRUCTURE, DEST_EXPLAIN)
    } else {
        (EGRESS_OPEN_WEB, DEST_EXPLAIN | DEST_REFUSE_PRIVATE)
    };
    let mut bytes = vec![0u8; JUDGED_BYTES];
    let mut spans = [crate::task_door::ABSENT_SPAN; JUDGED_ADDRESSES];
    let judged = services.dest_judge_as(
        at.handle(base),
        url,
        class,
        flags,
        Some((&mut bytes[..], &mut spans[..])),
    );
    Poll::Ready(match judged {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(e)) => Err(format!("agent card fetch of `{url}` failed: {e:?}")),
        Poll::Ready(Ok(judged)) if judged.verdict == DEST_ALLOWED => {
            Ok((base + 1, judged.within()))
        }
        Poll::Ready(Ok(judged)) => Err(crate::card_trust::refused_judgement(
            url,
            judged.verdict,
            judged.detail(),
        )),
    })
}

/// THE RELAY'S GUARD (the engine's `relay::prepare`, which guarded the registered endpoint through
/// the card fetch's own hop door before every relayed submission): the agent's `url` judged on the
/// registration's `allow_private`, once per attempt.
fn guard_relay(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    url: &str,
    def: &crate::a2a::config::AgentDefCfg,
    attempt: u32,
) -> Poll<Option<PieceAnswer>> {
    if hop.endpoint_judged.as_ref().is_some_and(|judged| {
        judged.attempt == attempt && judged.member == hop.member && judged.url == url
    }) {
        return Poll::Ready(None);
    }
    hop.endpoint_judged = None;

    let refused = match crate::card_trust::scheme_refusal(url, def.allow_private) {
        Some(why) => Some(why),
        None => {
            let at = LookAt {
                plane: reach.plane,
                generation: reach.plane.newest(),
                ticket: reach.ticket,
                base: pass.issued,
            };
            match judge_hop(&at, url, def.allow_private, pass.issued) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok((issued, within))) => {
                    pass.issued = issued;
                    hop.endpoint_judged = Some(JudgedRelay {
                        attempt,
                        member: hop.member.clone(),
                        url: url.to_string(),
                        within,
                    });
                    None
                }
                Poll::Ready(Err(why)) => {
                    pass.issued += 1;
                    Some(why)
                }
            }
        }
    };
    if let Some(why) = refused.as_deref() {
        busbar_contract::diag_warn!(
            crate::diagnostics::A2A_RELAY_ENDPOINT_REFUSED,
            url = %url,
            "a2a: the agent endpoint `{url}` was refused before the hop: {why}"
        );
    }
    Poll::Ready(refused.map(|_| hop.relay.refuse_endpoint()))
}

/// THE CARD at the agent origin's well-known paths, canonical first, over the agent's connection
/// need, as the engine fetched it (`fetch::fetch_card`): every hop guarded from scratch
/// ([`judge_hop`]), a redirect followed — resolved against the hop that sent it — up to
/// [`crate::card_trust::MAX_REDIRECTS`], and the legacy path only when the canonical one produced
/// no document.
fn fetch_card(
    at: &LookAt<'_>,
    name: &str,
    def: &crate::a2a::config::AgentDefCfg,
    resumed: Option<(CardHop, Option<ParkedExchange>)>,
) -> Result<
    (
        Result<serde_json::Value, String>,
        crate::card_trust::Handshake,
        u32,
    ),
    Box<LookParked>,
> {
    use busbar_contract::abi::sdk::exchange::{exchange, Exchange, Request};
    let urls = match crate::card_trust::discovery_urls(&def.url) {
        Ok(urls) => urls,
        Err(refusal) => {
            return Ok((
                Err(refusal),
                crate::card_trust::Handshake::default(),
                at.base,
            ))
        }
    };
    let (mut hop, mut parked) = resumed.unwrap_or_else(|| {
        let first = CardHop {
            legacy: false,
            redirects: 0,
            url: urls[0].clone(),
            issued: at.base,
            canonical: None,
        };
        (first, None)
    });
    loop {
        let url = hop.url.clone();
        let mut seen = crate::card_trust::Handshake::default();
        let mut transport_refusal = None;
        let got: Result<Option<serde_json::Value>, String> = 'hop: {
            let (start, state) = match parked.take() {
                Some((start, state)) => (start, Ok(*state)),
                None => {
                    if let Some(refusal) =
                        crate::card_trust::scheme_refusal(&url, def.allow_private)
                    {
                        break 'hop Err(refusal);
                    }
                    let (start, within) = match judge_hop(at, &url, def.allow_private, hop.issued) {
                        Poll::Pending => {
                            return Err(Box::new(LookParked::Fetching {
                                registration: def.clone(),
                                generation: at.generation,
                                hop,
                                exchange: None,
                            }))
                        }

                        Poll::Ready(Err(refusal)) => {
                            hop.issued += 1;
                            break 'hop Err(refusal);
                        }
                        Poll::Ready(Ok(judged)) => judged,
                    };
                    let target = url::Url::parse(&url)
                        .map(|u| match u.query() {
                            Some(q) => format!("{}?{q}", u.path()),
                            None => u.path().to_string(),
                        })
                        .unwrap_or_default();

                    let request = Exchange::request(Request {
                        method: b"GET".to_vec(),
                        target: target.into_bytes(),

                        fields: vec![(
                            busbar_contract::abi::auth::NO_MEMBER_AUTH_FIELD
                                .as_bytes()
                                .to_vec(),
                            b"1".to_vec(),
                        )],
                        body: Vec::new(),
                        timeout_ms: crate::card_trust::CARD_FETCH_TIMEOUT_MS,
                    })
                    .map(|request| request.landing_within(within).observing().as_member(name));
                    (start, request)
                }
            };
            let answer = match (state, at.plane.host.as_ref()) {
                (Err(e), _) => Err(e.to_string()),
                (Ok(_), None) => {
                    Err(busbar_contract::abi::sdk::conn::ConnFailure::Unarmed.to_string())
                }
                (Ok(mut state), Some(host)) => {
                    let mut conn = host.connector_from(at.ticket, start);
                    match exchange(&mut conn, &mut state, statement::NEED_AGENT, Some(&url)) {
                        Poll::Pending => {
                            return Err(Box::new(LookParked::Fetching {
                                registration: def.clone(),
                                generation: at.generation,
                                hop,
                                exchange: Some((start, Box::new(state))),
                            }));
                        }
                        Poll::Ready(answer) => {
                            hop.issued = conn.issued();
                            if let Some(observed) = state.observed() {
                                seen = crate::card_trust::Handshake {
                                    peer_key_pin: observed.peer_key_pin.clone(),
                                    client_identity_offered: observed.client_identity,
                                };
                            }
                            answer.map_err(|failure| {
                                let cause = conn.cause();
                                let message = crate::card_trust::transport_err(cause, &failure);
                                transport_refusal = Some(CardTransportRefusal {
                                    url: url.clone(),
                                    redirects: hop.redirects,
                                    cause,
                                    failure,
                                });
                                message
                            })
                        }
                    }
                }
            };
            let response = match answer {
                Ok(response) => response,
                Err(e) => break 'hop crate::card_trust::read_card(&url, Err(e)).map(Some),
            };
            let location = response
                .fields
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(b"location"))
                .and_then(|(_, value)| std::str::from_utf8(value).ok());
            match crate::card_trust::next_hop(&url, response.status, location, hop.redirects) {
                Err(refusal) => Err(refusal),
                Ok(Some(next)) => {
                    hop.redirects += 1;
                    hop.url = next;
                    Ok(None)
                }
                Ok(None) => {
                    crate::card_trust::read_card(&url, Ok((response.status, &response.body)))
                        .map(Some)
                }
            }
        };
        match got {
            Ok(None) => {}
            Ok(Some(card)) => return Ok((Ok(card), seen, hop.issued)),
            Err(refusal) if !hop.legacy => {
                hop = CardHop {
                    legacy: true,
                    redirects: 0,
                    url: urls[1].clone(),
                    issued: hop.issued,
                    canonical: Some(CardRefusal {
                        message: refusal,
                        transport: transport_refusal,
                    }),
                };
            }
            Err(refusal) => {
                let refusal = match hop.canonical.take() {
                    Some(canonical) => card_refusals(
                        canonical,
                        CardRefusal {
                            message: refusal,
                            transport: transport_refusal,
                        },
                        &urls,
                    ),
                    None => refusal,
                };
                return Ok((Err(refusal), seen, hop.issued));
            }
        }
    }
}

/// The room a `trust.verify` answer is first asked into, in bytes.
const VERIFY_FIRST_BYTES: usize = 256;

/// The most room a `trust.verify` answer is re-asked into after a short answer named more, in bytes.
const VERIFY_MAX_BYTES: usize = 1 << 16;

/// Ask the kernel to verify the card signatures against the agent's registered root key.
fn signed_by_root(
    at: &LookAt<'_>,
    seq: u32,
    name: &str,
    card: &serde_json::Value,
) -> Result<(), String> {
    let (payload, signatures) = crate::card_trust::signed_parts(card)?;
    let unjudged = |why: String| format!("the agent card's signatures were not judged: {why}");
    let Some(services) = at.plane.services else {
        return Err(unjudged(
            "the instance was handed no host services".to_string(),
        ));
    };
    let handle = at.handle(seq);
    let (mut buf, mut grown) = (vec![0u8; VERIFY_FIRST_BYTES], Vec::new());

    let answer = match services.trust_verify(handle, name, &payload, &signatures, &mut buf) {
        Err(busbar_contract::abi::sdk::ServiceError::Short { bytes, .. }) => {
            grown.resize(
                usize::try_from(bytes)
                    .unwrap_or(usize::MAX)
                    .min(VERIFY_MAX_BYTES),
                0,
            );
            services.trust_verify(handle, name, &payload, &signatures, &mut grown)
        }
        other => other,
    };
    match answer {
        Ok(signed) => {
            crate::card_trust::jws_refusal(signed.verdict, signed.named, card).map_or(Ok(()), Err)
        }
        Err(e) => Err(unjudged(format!("{e:?}"))),
    }
}

/// THE CATALOGUE HASH a card that failed its verification is sighted under: no fingerprint is ever
/// this, so a pinned (approved) agent sighted under it has drifted, and the kernel quarantines it.
const UNVERIFIED_CARD: &str = "unverified";

/// THE LOOK every trust read shares (`connect`, `approve` and verify-on-call), so no two of them
/// judge a card differently: fetch the card, verify it against the registration's pin, and record
/// the verified fingerprint on the kernel's trust book (`trust.sight`, which stamps the agent's
/// re-verification clock and judges it against a declared fingerprint).
fn look(
    at: &LookAt<'_>,
    name: &str,
    def: &crate::a2a::config::AgentDefCfg,
    parked: Option<LookParked>,
) -> Result<(CardLook, u32), Box<LookParked>> {
    use crate::card_trust::Sighting;
    let resumed = match parked {
        Some(LookParked::Deciding { looked, issued, .. }) => return Ok((looked, issued)),
        Some(LookParked::Sighted {
            looked,
            issued,
            unreachable,
            ..
        }) => {
            let sighted = sight(at, name, &looked, unreachable, issued - 1);
            return settle_look(at, name, def, looked, sighted, issued, unreachable);
        }
        Some(LookParked::Fetching { hop, exchange, .. }) => Some((hop, exchange)),
        None => None,
    };
    let (card, hop, issued) = fetch_card(at, name, def, resumed)?;
    let (verify_seq, sight_seq) = (issued, issued + 1);

    // A failed fetch is judged once: refused by the hop's own guard, or the agent unreachable.
    let guarded = card
        .is_err()
        .then(|| crate::card_trust::hop_refusal(&def.pin, &hop, &def.url));
    let unreachable = matches!(guarded, Some(None));
    let card = card.map_err(|e| guarded.flatten().unwrap_or(e));
    let looked = match card.and_then(|card| {
        crate::card_trust::verify_card(&def.pin, &card, &hop, || {
            signed_by_root(at, verify_seq, name, &card)
        })
        .map(|seen| (seen, card))
    }) {
        Ok((seen, card)) => CardLook {
            sighting: Sighting::Seen(seen),
            card: Some(card),
        },
        Err(reason) => CardLook {
            sighting: Sighting::Failed(reason),
            card: None,
        },
    };
    let issued = sight_seq + 1;
    let sighted = sight(at, name, &looked, unreachable, sight_seq);
    settle_look(at, name, def, looked, sighted, issued, unreachable)
}

/// Read the sighting on its original completion handle, including after a pending answer.
fn sight(
    at: &LookAt<'_>,
    name: &str,
    looked: &CardLook,
    unreachable: bool,
    sight_seq: u32,
) -> Option<busbar_contract::abi::sdk::Pend<u64>> {
    use crate::card_trust::Sighting;

    let services = at.plane.services?;
    match &looked.sighting {
        Sighting::Seen(seen) => seen
            .pin
            .fingerprint()
            .map(|fp| services.trust_sight(at.handle(sight_seq), name, fp)),
        Sighting::Failed(_) if unreachable => {
            Some(services.trust_unreachable(at.handle(sight_seq), name))
        }
        Sighting::Failed(_) => {
            Some(services.trust_sight(at.handle(sight_seq), name, UNVERIFIED_CARD))
        }
        Sighting::Never => None,
    }
}

/// A failed trust write cannot publish or serve a card under a verdict for an older sighting.
fn settle_look(
    at: &LookAt<'_>,
    name: &str,
    def: &crate::a2a::config::AgentDefCfg,
    looked: CardLook,
    sighted: Option<busbar_contract::abi::sdk::Pend<u64>>,
    issued: u32,
    unreachable: bool,
) -> Result<(CardLook, u32), Box<LookParked>> {
    match sighted {
        Some(Poll::Pending) => Err(Box::new(LookParked::Sighted {
            registration: def.clone(),
            generation: at.generation,
            looked,
            issued,
            unreachable,
        })),
        Some(Poll::Ready(Err(e))) => {
            busbar_contract::diag_warn!(
                crate::diagnostics::A2A_TRUST_SIGHTING_UNRECORDED,
                agent = %name,
                "a2a: the kernel's trust book did not record agent `{name}`'s card sighting ({e:?}); \
                 the look fails and the agent is not served on it"
            );
            Ok((
                CardLook {
                    sighting: crate::card_trust::Sighting::Failed(format!(
                        "the kernel's trust book did not record this card's sighting ({e:?})"
                    )),
                    card: None,
                },
                issued,
            ))
        }
        _ => Ok((looked, issued)),
    }
}

/// WHETHER `member` SERVES, on its `standing` (read here, never decided): SERVING is the kernel's
/// verdict on the agent's key.
fn kernel_serves(
    plane: &A2aDoor,
    member: &str,
    standing: &crate::card_trust::TrustStanding,
) -> bool {
    !matches!(standing.sighting, crate::card_trust::Sighting::Failed(_))
        && verdict(plane, member) == busbar_contract::abi::host::service::DISTRUST_NONE
}

/// Reverify a due registration through its single flight before allowing an outbound hop.
fn verify_agent_on_call(
    reach: &Reach<'_>,
    hop: &mut Hop,
    pass: &mut crate::task_door::Pass,
    member: &str,
    def: &crate::a2a::config::AgentDefCfg,
    generation: u64,
) -> Poll<Result<bool, Outcome>> {
    let plane = reach.plane;
    let key = member.to_string();
    let standing = plane.trust.get(&key).unwrap_or_default();
    let cadence = crate::card_trust::Cadence::of(def);
    let now_ms = match reach.clock_ms() {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(now)) => now,
        Poll::Ready(Err(())) => {
            tracing::warn!(
                agent = %member,
                "a2a: the host clock did not answer, so agent `{member}`'s trust could not be re-checked; \
                 the piece fails and may be retried"
            );
            hop.verifying = None;
            hop.waits_on = None;
            let waiters = plane.flights.abandon(reach.ticket);
            if let Some(host) = plane.host.as_ref() {
                for waiter in waiters {
                    host.wake(waiter);
                }
            }
            return Poll::Ready(Err(Outcome::Failed));
        }
    };
    let serves =
        |standing: &crate::card_trust::TrustStanding| kernel_serves(plane, member, standing);

    if let Some(seen) = hop.waits_on {
        match plane.flights.state(&key, seen, reach.ticket) {
            FlightState::InFlight => return Poll::Pending,
            FlightState::Landed => {
                hop.waits_on = None;
                let standing = plane.trust.get(&key).unwrap_or_default();
                return Poll::Ready(Ok(serves(&standing)));
            }
            FlightState::Released => hop.waits_on = None,
        }
    }
    if hop.verifying.is_none() {
        if !cadence.due(&standing.ledger, now_ms) {
            return Poll::Ready(Ok(serves(&standing)));
        }

        if let Some(seen) = plane.flights.join(&key, reach.ticket) {
            hop.waits_on = Some(seen);
            return Poll::Pending;
        }
        if let Some(standing) = reuse_fresh_look(plane, &key, cadence, now_ms) {
            return Poll::Ready(Ok(serves(&standing)));
        }
    }
    let at = LookAt {
        plane,
        generation,
        ticket: reach.ticket,
        base: pass.issued,
    };
    let parked = hop.verifying.take();
    let held = (&plane.flights, plane.host.as_ref(), reach.ticket);
    let (looked, issued) = match looking(held, || look(&at, member, def, parked)) {
        Ok(done) => done,
        Err(parked) => {
            hop.verifying = Some(*parked);
            return Poll::Pending;
        }
    };
    pass.issued = issued;

    let standing = plane.trust.with_all(|all| {
        let standing = all.entry(key.clone()).or_default();
        standing.sighting = cadence.settle(looked.sighting, &mut standing.ledger, now_ms);
        standing.clone()
    });
    if let Some(card) = looked.card {
        plane.cards.hold(member, generation, card);
    }
    let serving = serves(&standing);

    if let Some(host) = plane.host.as_ref() {
        for waiter in plane.flights.land(&key) {
            host.wake(waiter);
        }
    }
    Poll::Ready(Ok(serving))
}

/// Recheck the ledger after taking a flight, avoiding a look already completed by its prior owner.
fn reuse_fresh_look(
    plane: &A2aDoor,
    key: &str,
    cadence: crate::card_trust::Cadence,
    now_ms: u64,
) -> Option<crate::card_trust::TrustStanding> {
    let standing = plane.trust.get(&key.to_string()).unwrap_or_default();
    if cadence.due(&standing.ledger, now_ms) {
        return None;
    }
    let waiters = plane.flights.land(key);
    if let Some(host) = plane.host.as_ref() {
        for waiter in waiters {
            host.wake(waiter);
        }
    }
    Some(standing)
}

/// THE LOOK OF A UNIT HOLDING ITS AGENT'S FLIGHT (`held`: the flights, the host that wakes, the
/// unit's ticket), run as `look`; a look that unwinds releases the flight, landing nothing, and
/// wakes every unit that waited on it.
fn looking<T>(held: (&Flights, Option<&Host>, Ticket), look: impl FnOnce() -> T) -> T {
    /// Armed while the look runs, so only an unwinding look drops it armed and releases the flight;
    /// a look that returns disarms it and the caller lands the flight.
    struct Unwinding<'p> {
        flights: &'p Flights,

        wake: Option<&'p dyn Fn(Ticket)>,
        ticket: Ticket,
        armed: bool,
    }
    impl Drop for Unwinding<'_> {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            let woken = self.flights.abandon(self.ticket);
            if let Some(wake) = self.wake {
                for waiter in woken {
                    wake(waiter);
                }
            }
        }
    }
    let (flights, host, ticket) = held;
    let wake = host.map(|host| move |waiter: Ticket| host.wake(waiter));
    let mut unwinding = Unwinding {
        flights,
        wake: wake.as_ref().map(|w| w as &dyn Fn(Ticket)),
        ticket,
        armed: true,
    };
    let looked = look();
    unwinding.armed = false;
    looked
}

/// ONE AGENT'S LOOK IN FLIGHT (the engine's `VerifyGate` flight): how many looks have landed, the
/// unit looking now, and the units waiting on it.
#[derive(Debug, Clone, Default)]
pub struct Flight {
    epoch: u64,
    owner: Option<Ticket>,
    waiters: Vec<Ticket>,
}

/// Where a waiter's flight stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightState {
    /// The look it waits on is still in flight.
    InFlight,
    /// The look landed: its verdict is recorded.
    Landed,
    /// The look was abandoned before it landed: nothing was recorded, and the waiter looks again.
    Released,
}

/// Every agent's flight.
#[derive(Debug, Default)]
pub struct Flights(Keyed<String, Flight>);

impl Flights {
    /// `ticket` is due to look at `agent`: `None` = it holds the flight and looks; `Some(epoch)` =
    /// another unit's look is in flight, and `ticket` waits on it.
    fn join(&self, agent: &str, ticket: Ticket) -> Option<u64> {
        self.0.with_all(|m| {
            let f = m.entry(agent.to_string()).or_default();
            match f.owner {
                Some(owner) if owner != ticket => {
                    if !f.waiters.contains(&ticket) {
                        f.waiters.push(ticket);
                    }
                    Some(f.epoch)
                }
                _ => {
                    f.owner = Some(ticket);
                    None
                }
            }
        })
    }

    /// Where the flight `ticket` joined at `seen` stands; still in flight, `ticket` stays a waiter.
    fn state(&self, agent: &str, seen: u64, ticket: Ticket) -> FlightState {
        self.0.with_all(|m| {
            let Some(f) = m.get_mut(agent) else {
                return FlightState::Released;
            };
            if f.epoch != seen {
                return FlightState::Landed;
            }
            if f.owner.is_none() {
                return FlightState::Released;
            }
            if !f.waiters.contains(&ticket) {
                f.waiters.push(ticket);
            }
            FlightState::InFlight
        })
    }

    /// The flight on `agent` landed: the next epoch, no owner, and the units that waited on it.
    fn land(&self, agent: &str) -> Vec<Ticket> {
        self.0.with_all(|m| {
            let f = m.entry(agent.to_string()).or_default();
            f.epoch += 1;
            f.owner = None;
            std::mem::take(&mut f.waiters)
        })
    }

    /// THE UNIT ON `ticket` WAS ABANDONED (cancelled): every flight it held is released, landing
    /// nothing, and the units that waited on them are answered to be woken; it waits on none any
    /// more.
    fn abandon(&self, ticket: Ticket) -> Vec<Ticket> {
        self.0.with_all(|m| {
            let mut woken = Vec::new();
            for f in m.values_mut() {
                f.waiters.retain(|w| *w != ticket);
                if f.owner == Some(ticket) {
                    f.owner = None;
                    woken.append(&mut f.waiters);
                }
            }
            woken
        })
    }
}

/// The head fields a trust verb's view is answered with.
const VIEW_FIELDS: &[(&str, &str)] =
    &[(relay::H_CONTENT_TYPE, crate::agent_arrival::JSON_MEDIA_TYPE)];

/// A trust verb's refusal: `status`, the message alone (the kernel frames it in the admin
/// taxonomy), the condition it is when it names one, and its audit row.
fn verb_refused(
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    status: u32,
    message: &str,
    condition: Option<&str>,
    audit: u32,
) -> Outcome {
    use busbar_contract::plane::ADMIN_CONDITION_FIELD;
    let mut fields = vec![(relay::H_CONTENT_TYPE, "text/plain")];
    fields.extend(condition.map(|c| (ADMIN_CONDITION_FIELD, c)));
    out.answer(input, status, &fields, message.as_bytes(), audit)
}

slot!(
    /// `serve`: the trust verbs over the section's registrations, over the kernel's trust book
    /// (the plane holds no approval; the book pins, quarantines and keeps the operator's decision):
    ///
    /// * an unregistered name is `404` before anything else, audited rejected;
    /// * `approve` reads its body (`{"fingerprint": "…"}`) next, and a malformed one is `400`
    ///   (the malformed-body condition), audited rejected;
    /// * both then LOOK ([`look`]): the card fetched over the agent's own connection need,
    ///   verified against its pin and SIGHTED on the kernel's trust book;
    /// * `connect` answers its preview and decides nothing; the card it verified is held for the
    ///   relay and rides its answer as the agent's `card` host records ([`card_records`]);
    /// * `approve` compares what the endpoint serves now against the fingerprint the operator
    ///   names and refuses any disagreement `400` (the invalid-config condition), audited
    ///   rejected; otherwise it APPROVES the agent's trust key on the kernel's book
    ///   (`trust.decide`, the same decision `POST /admin/trust/approve` makes), holds the verified
    ///   card for the relay, and answers the registration as it now stands.
    Serve, ServeIn, ServeOut, |instance, input, mut out| {
        use busbar_contract::abi::plane::{AUDIT_APPLIED, AUDIT_NONE, AUDIT_REJECTED};
        use busbar_contract::plane::{
            ADMIN_CONDITION_INVALID_CONFIG as INVALID_CONFIG,
            ADMIN_CONDITION_MALFORMED_BODY as MALFORMED_BODY,
        };
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        if input.route() as usize == statement::PUSH_ROUTE {
            return crate::push_serve::serve(plane, &instance, input, out);
        }
        let Some((_, route)) = statement::ADMIN_VERBS.get(input.route() as usize) else {
            return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_NONE);
        };
        let approving = route.ends_with("/approve");
        let registered = |name: &str| {
            plane
                .generations
                .current()
                .and_then(|held| held.agents.get(name).cloned())
        };
        let parked = instance.resume::<LookParked>().map(|p| *p);
        let generation = parked.as_ref().map_or_else(|| plane.newest(), LookParked::generation);
        let found = verb_agent(route, input.target().bytes()).and_then(|name| {
            let def = parked.as_ref().map(|p| p.registration().clone())
                .or_else(|| plane.generations.at(generation).and_then(|s| s.agents.get(&name).cloned()))?;
            (registered(&name).as_ref() == Some(&def)).then_some((name, def))
        });
        let Some((name, def)) = found else {
            return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_REJECTED);
        };
        let claimed = if approving {
            let fields = input.fields();
            let content_type = fields
                .iter()
                .find(|f| {
                    f.name()
                        .as_str()
                        .is_ok_and(|n| n.eq_ignore_ascii_case(relay::H_CONTENT_TYPE))
                })
                .and_then(|f| f.value().as_str().ok());
            match crate::card_trust::approve_body(content_type, input.body().bytes()) {
                Ok(fingerprint) => Some(fingerprint),
                Err(refusal) => {
                    let condition = Some(MALFORMED_BODY);
                    return verb_refused(
                        &input,
                        &mut out,
                        400,
                        &refusal,
                        condition,
                        AUDIT_REJECTED,
                    );
                }
            }
        } else {
            None
        };
        let at = LookAt {
            plane,
            generation,
            ticket: instance.ticket(),
            base: 0,
        };
        let (looked,issued) = match look(&at, &name, &def, parked) {
            Ok(looked) => looked,
            Err(parked) => {
                instance.park(*parked);
                return Outcome::Pending;
            }
        };
        // Complete every host crossing before deciding which registration may receive the
        // local standing and answer records. A host call may overlap a configuration refresh.
        if let Some(claimed) = claimed.as_deref() {
            if let Err(refusal) = crate::card_trust::agrees(&looked.sighting, claimed.trim()) {
                return verb_refused(&input, &mut out, 400, &refusal, Some(INVALID_CONFIG), AUDIT_REJECTED);
            }
            if registered(&name).as_ref() != Some(&def) {
                return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_REJECTED);
            }
            match approve_key(plane, &at, &name, claimed.trim()) {
                Poll::Pending => {
                    instance.park(LookParked::Deciding {registration:def.clone(),generation,looked,issued});
                    return Outcome::Pending;
                }
                Poll::Ready(Err(refusal))=>return verb_refused(&input, &mut out, 400, &refusal, None, AUDIT_REJECTED),
                Poll::Ready(Ok(()))=>{},
            }
        }
        let state_now = verdict(plane, &name);
        // The original registration owns every pending stage of the look, including trust.sight.
        // Recheck both verbs before any card/approval record or local standing is changed.
        let held_at = plane.newest();
        if plane.generations.at(held_at).and_then(|s| s.agents.get(&name).cloned()).as_ref() != Some(&def) {
            return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_REJECTED);
        }
        let hold_card = |card: serde_json::Value| {
            let _publication = plane.card_publication.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let card = std::sync::Arc::new(card);
            if generation != held_at && plane.generations.at(generation).is_some() {
                plane.cards.hold_shared(&name, generation, card.clone());
            }
            plane.cards.hold_shared(&name, held_at, card.clone());
            // A refresh published meanwhile that kept the registration serves the card too.
            let newest = plane.newest();
            if newest != held_at
                && plane
                    .generations
                    .at(newest)
                    .is_some_and(|s| s.agents.get(&name) == Some(&def))
            {
                plane.cards.hold_shared(&name, newest, card);
            }
        };
        // The card record: a card this look verified rides the verb's
        // answer as the agent's `card` host records (split under the host's record ceiling),
        // which a later `open` warms the held cards from.
        let writes: Vec<Write> = looked
            .card
            .as_ref()
            .map(|card| card_records(plane, &name, card))
            .unwrap_or_default();
        let Some(_) = claimed else {
            // A PREVIEW DECIDES NOTHING: the key stands where the book has it.
            if let Some(card) = looked.card {
                hold_card(card);
            }
            let Some(approved) = kept_standing(plane, (&name, &def), &looked.sighting, None) else {
                return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_REJECTED);
            };
            let view = crate::card_trust::connect_view(
                &name,
                state_now,
                &looked.sighting,
                approved.as_ref(),
            );
            let answer = (200, VIEW_FIELDS, view.as_bytes());
            return verb_answer(&input, &mut out, answer, AUDIT_APPLIED, &writes);
        };
        // THE SERVED CARD, warmed from the document this approval just verified: the relay reads
        // the agent's binding and skills off it.
        if let Some(card) = looked.card {
            hold_card(card);
        }
        // The skills approved, held for the trust view's drift lists: the card this
        // approval adopted, which `agrees` matched to the fingerprint the operator named.
        let skills = looked.sighting.seen().map(|seen| seen.skills.clone());
        let Some(approved) = kept_standing(plane, (&name, &def), &looked.sighting, Some(skills))
        else {
            return verb_refused(&input, &mut out, STATUS_NOT_FOUND, "", None, AUDIT_REJECTED);
        };
        // ... and written as the agent's `card_approval` host record, so a restart keeps them.
        let mut writes = writes;
        writes.extend(
            approved
                .as_ref()
                .map(|approved| approval_records(plane, &name, approved))
                .unwrap_or_default(),
        );
        let view = crate::card_trust::registration_view(
            &name,
            state_now,
            &looked.sighting,
            approved.as_ref(),
        );
        let answer = (200, VIEW_FIELDS, view.as_bytes());
        verb_answer(&input, &mut out, answer, AUDIT_APPLIED, &writes)
    }
);

/// The skills (`id -> digest`) of the card an operator approved for an agent.
type ApprovedSkills = std::collections::BTreeMap<String, String>;

/// A trust verb's `sighting` (and an approval's skills, `approved`) recorded on `name`'s live
/// standing in place while the newest generation still registers it as `def`, answering the
/// approved skills it stands at; `None` when the registration was replaced, recording nothing.
fn kept_standing(
    plane: &A2aDoor,
    (name, def): (&str, &crate::a2a::config::AgentDefCfg),
    sighting: &crate::card_trust::Sighting,
    approved: Option<Option<ApprovedSkills>>,
) -> Option<Option<ApprovedSkills>> {
    plane.trust.with_all(|standings| {
        let registered = plane
            .generations
            .at(plane.newest())
            .is_some_and(|s| s.agents.get(name) == Some(def));
        if !registered {
            return None;
        }
        let standing = standings.entry(name.to_string()).or_default();
        standing.sighting = sighting.clone();
        if let Some(approved) = approved {
            standing.approved = approved;
        }
        Some(standing.approved.clone())
    })
}

/// APPROVE `agent`'s trust key on the KERNEL'S trust book at the fingerprint the operator named and
/// this look just sighted (`trust.decide`, the ONE decide path `POST /admin/trust/approve` takes
/// for `<instance>/<agent>`).
fn approve_key(
    plane: &A2aDoor,
    at: &LookAt<'_>,
    agent: &str,
    seen: &str,
) -> Poll<Result<(), String>> {
    use busbar_contract::abi::host::service as svc;
    let Some(services) = plane.services else {
        return Poll::Ready(Err("the instance was handed no host services".to_string()));
    };
    let Poll::Ready(answer) =
        services.trust_decide(at.handle(TRUST_DECIDE_SEQ), agent, None, Some(seen), true)
    else {
        return Poll::Pending;
    };
    Poll::Ready(match answer {
        Ok(svc::UNDECIDED_UNPINNED) => Err(
            "the agent's card could not be authenticated, so there is nothing to approve".to_string(),
        ),
        Ok(svc::UNDECIDED_STALE) => Err(format!(
            "the endpoint's card moved while it was being approved: `{seen}` is no longer what the \
             trust book last sighted; re-run `connect` and read the new fingerprint before approving."
        )),
        Ok(svc::UNDECIDED_ROOTLESS) => Err(
            "cannot approve: this registration has no authenticity root (unpinned). Supply an \
             issuer key out of band, or pin the endpoint at the transport layer."
                .to_string(),
        ),
        Ok(svc::UNDECIDED_UNKNOWN) => Err(format!("the trust book declares no agent `{agent}`")),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("the trust book did not decide: {e:?}")),
    })
}

/// The completion handle the approve's decision rides: past every handle its look issued.
const TRUST_DECIDE_SEQ: u32 = u32::MAX - 1;

slot!(
    /// `hydrate`: nothing to load. The door's durable state is host records (its tasks, their push
    /// configs and chains), read on demand through `records.get`/`records.list`, and the agents'
    /// cards and approved skills, warmed after `open` ([`warm_cards`]); what else it holds in
    /// memory (the far-end id map, owed push outcomes, the last sightings) is plane memory a
    /// restart forgets, as the engine's was.
    Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `start`: the door runs nothing of its own. Its timed work is the lifecycle `tick` (push
    /// delivery) and the retention sweep the first relayed piece of each second runs
    /// ([`crate::task_door`]).
    Start, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

/// Parse the request once for every part of its hook view: the projection, the invocation (which
/// takes ownership of `params`) and the session.
pub(crate) fn hook_view(
    envelope: &[u8],
) -> Option<(
    Vec<u8>,
    busbar_contract::ir::invoke::InvokeReq,
    Option<String>,
)> {
    let mut value = crate::request_json::parse(envelope).ok()?;
    value.as_object()?;
    let context = crate::task_identity::context_of(&value);
    let session = (!context.is_empty()).then(|| context.to_string());
    let object = value.as_object_mut()?;
    let tool = object
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let invocation = busbar_contract::ir::invoke::InvokeReq {
        tool,
        arguments: object.remove("params").unwrap_or(serde_json::Value::Null),
        extra: Default::default(),
    };
    #[derive(serde::Serialize)]
    struct Projection<'a> {
        arguments: &'a serde_json::Value,
        tool: &'a str,
    }
    let projection = crate::relay::json_bytes(&Projection {
        tool: &invocation.tool,
        arguments: &invocation.arguments,
    })
    .ok()?;
    Some((projection, invocation, session))
}

/// A request-stage hook's rewrite, read as a `prompt: rw` reply to an A2A submission (the invoke
/// rewrite contract): the hook stage hands the plane the reply as `{"messages": [...], "tools":
/// ...}`; an A2A request has one untrusted content member, its `params` object, and the rewrite
/// REPLACES it: a `messages` entry's `content` (an object verbatim, or a JSON string that parses to
/// an object) or, for an entry with no `role`, the entry itself; the LAST entry that yields an
/// object wins.
pub fn rewritten_params(rewrite: &[u8]) -> Result<Option<serde_json::Value>, String> {
    use serde_json::Value;
    let refused = |why: String| {
        busbar_contract::diag_warn!(
            crate::diagnostics::A2A_HOOK_REWRITE_UNREADABLE,
            stage = "request",
            "a2a: the request hook stage's committed rewrite could not be read back ({why}); the \
             submission is refused"
        );
        why
    };
    let reply = crate::request_json::parse(rewrite)
        .map_err(|e| refused(format!("the output is not JSON: {e}")))?;
    let messages = reply
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| refused("the output is JSON but names no `messages` list".to_string()))?;
    let mut params: Option<crate::request_json::RequestJson> = None;
    for message in messages {
        let candidate = match message.get("content") {
            Some(content) => content,
            None if message.get("role").is_none() => message,
            None => continue,
        };
        let resolved = match candidate {
            Value::Object(_) => Some(crate::request_json::RequestJson::new(candidate.clone())),
            Value::String(text) => crate::request_json::parse_str(text)
                .ok()
                .filter(|value| value.is_object()),
            _ => None,
        };
        if resolved.is_some() {
            params = resolved;
        }
    }
    if params.is_none() {
        busbar_contract::diag_warn!(
            crate::diagnostics::A2A_HOOK_REWRITE_NOT_APPLIED,
            stage = "request",
            "a2a: the request hook stage's rewrite was not applied: none of its {} messages \
             yields a params object; the submission is refused",
            messages.len()
        );
        return Err("the committed rewrite yields no params object".to_string());
    }
    Ok(params.map(crate::request_json::RequestJson::into_value))
}

/// The sentence a committed rewrite busbar cannot read back is refused with.
pub const UNREADABLE_REWRITE: &str = "a rewrite hook attached to this agent committed a rewrite \
     that busbar could not read back. The submission is refused rather than relayed with the \
     params the hook said it had replaced.";

/// The status a committed rewrite busbar cannot read back is refused with: A2A section 5.4's
/// `InternalError` row.
pub const UNREADABLE_REWRITE_STATUS: u32 = 500;

/// The refusal of a committed rewrite busbar cannot read back: a conformant A2A internal error
/// (`-32603` at `500`) echoing the request id `id`.
#[must_use]
pub fn unreadable_rewrite(id: Option<serde_json::Value>) -> agent_arrival::AgentRefusal {
    agent_arrival::AgentRefusal::new(
        UNREADABLE_REWRITE_STATUS,
        id,
        crate::agent_arrival::CODE_INTERNAL,
        UNREADABLE_REWRITE.to_string(),
    )
}

/// THE ENVELOPE `envelope` WITH ITS `params` REPLACED by `params`, re-serialized (the served engine
/// wrote a committed rewrite back into the envelope and relayed it re-serialized).
#[must_use]
pub fn with_params(
    envelope: &[u8],
    params: serde_json::Value,
) -> Option<(serde_json::Value, Vec<u8>)> {
    let params = crate::request_json::RequestJson::new(params);
    let mut value = crate::request_json::parse(envelope).ok()?;
    let replaced = value
        .as_object_mut()?
        .insert("params".to_string(), params.into_value());
    drop(replaced.map(crate::request_json::RequestJson::new));
    let bytes = crate::relay::json_bytes(&value).ok()?;
    Some((value.into_value(), bytes))
}

/// THE HTTP+JSON BODY THAT SPELLS `params` on `route`, where the line's body is the request's
/// params ([`crate::rest::compose`]: a message sent or streamed, a push config posted, whose task
/// the path names again); `None` on a route whose params the path and query spell.
fn target_body(route: &statement::Route, params: &serde_json::Value) -> Option<Vec<u8>> {
    let rel = route
        .target
        .strip_prefix(crate::MOUNT_PATH)
        .unwrap_or(route.target);
    let bodied = route.verb == "POST"
        && [
            crate::ROUTE_MESSAGE_SEND,
            crate::ROUTE_MESSAGE_STREAM,
            crate::ROUTE_PUSH_CONFIGS,
        ]
        .contains(&rel);
    bodied
        .then(|| crate::relay::json_bytes(params).ok())
        .flatten()
}

slot!(
    /// `project`: the hook view of an arrival on the JSON-RPC or the HTTP+JSON line: its
    /// projection from [`hook_view`] as the body (the envelope its request spelled, on the HTTP+JSON
    /// line), the plane's own key as the ingress dialect (the engine's gate label), the agent the target
    /// addresses by name as the pool (none when the kernel's walk picks one), the session from
    /// [`hook_view`], and the prompt view a content-granted hook reads (the one `user` turn of the
    /// params as JSON text, as the served engine projected an A2A submission). No signals.
    ///
    /// A request-stage hook's rewrite ([`rewritten_params`]) is applied first: the envelope with its
    /// params replaced is the request projected and the request the unit relays from then on (kept
    /// on the unit, [`Hop`]); the body the kernel keeps and re-pushes is answered in `rewritten`
    /// (the envelope on the JSON-RPC line, the params where the HTTP+JSON line's body is the params).
    /// Any other line, or a body that is no envelope, projects nothing (REFUSED).
    Project, ProjectIn, ProjectOut, |instance, input, mut out| {
        let plane = instance.get();
        let agents = || plane.map_or(0, agent_claims);
        let Some(route) = statement::route_of_claim(input.claim(), agents) else {
            return Outcome::Refused;
        };
        let target = input.target().as_str().unwrap_or_default();
        let body = input.body().bytes();
        // An acknowledged notification selects no agent and binds no agent's request hooks.
        // Its neutral view must agree with the ROUTE_LOCAL arrival, even on an agent's URL.
        let notice = plane.is_some_and(|plane| {
            plane.units.with(&input.unit(), |unit| {
                unit.is_some_and(|unit| matches!(&unit.disposition, AgentDisposition::Notice { .. }))
            })
        });
        let line = if notice { Line::Open } else { statement::line_of(route) };
        let envelope = match line {
            Line::Document => body.to_vec(),
            Line::Target => match crate::rest::compose(route, target, body) {
                Ok(Some(envelope)) => envelope,
                _ => return Outcome::Refused,
            },
            // The gRPC line projects the JSON-RPC request its call's message composed at arrival.
            Line::Framed => {
                let composed = of_unit(&instance, input.unit(), |u| u.envelope.clone());
                match composed {
                    Some(mut envelope) => std::mem::take(&mut *envelope),
                    None => return Outcome::Refused,
                }
            }
            // A card read or acknowledged notification carries no agent request to screen:
            // its view names no entry and no turn, so no agent's hooks bind.
            Line::Open => {
                let mut arena = input.arena_buf();
                let dialect = arena.span(crate::PLANE_KEY.as_bytes());
                let short = !arena.fits();
                let (aw, and) = arena.settle(short);
                out.set(|o| &o.arena_written, aw as u64);
                out.set(|o| &o.arena_needed, and as u64);
                if short {
                    return Outcome::Failed;
                }
                out.host_str(|o| &o.view.ingress_dialect, &arena, dialect);
                return Outcome::Ready;
            }
        };
        let envelope = zeroize::Zeroizing::new(envelope);
        let rewrite = input.rewrite().bytes();
        let read = if rewrite.is_empty() {
            Ok(None)
        } else {
            rewritten_params(rewrite)
        };
        // A committed rewrite busbar cannot read back, or write back, refuses the unit: it is
        // never relayed with the params the hook said it had replaced. The unit is marked, and
        // `refusal` answers it the internal error.
        let applied = match read.and_then(|params| {
            params
                .map(|params| {
                    let kept = match line {
                        Line::Target => target_body(route, &params),
                        _ => None,
                    };
                    with_params(&envelope, params)
                        .map(|(value, bytes)| (crate::request_json::RequestJson::new(value), bytes, kept))
                        .ok_or_else(|| {
                            busbar_contract::diag_warn!(
                                crate::diagnostics::A2A_HOOK_REWRITE_UNREADABLE,
                                stage = "request",
                                "a2a: the request hook stage's committed rewrite could not be \
                                 written back (the request is no envelope to write it into); \
                                 the submission is refused"
                            );
                            "the request is no envelope to write it into".to_string()
                        })
                })
                .transpose()
        }) {
            Ok(applied) => applied,
            Err(_) => {
                if let Some(plane) = instance.get() {
                    plane.on_unit(input.unit(), |u| {
                        u.unreadable_rewrite = true;
                    });
                }
                return Outcome::Refused;
            }
        };
        let (envelope, rewritten) = match applied {
            Some((value, bytes, kept)) => {
                if let Some(plane) = instance.get() {
                    plane.on_unit(input.unit(), |u| {
                        // A line that composed its request relays the composition, so the
                        // rewrite is what it relays (the HTTP+JSON and gRPC lines).
                        if let Some(hop) = u.hop.as_mut() {
                            hop.relay.send_instead(bytes.clone());
                            hop.rewritten = Some(value.clone());
                        }
                    });
                }
                let kept = match line {
                    Line::Document => Some(bytes.clone()),
                    _ => kept,
                };
                (zeroize::Zeroizing::new(bytes), kept)
            }
            None => (envelope, None),
        };
        let rewritten = rewritten.map(zeroize::Zeroizing::new);
        let Some((projected, invocation, session)) = hook_view(&envelope) else {
            return Outcome::Refused;
        };
        let projected = zeroize::Zeroizing::new(projected);
        let shape = busbar_contract::ir::facts::IrFacts::shape(&invocation);
        let turns: Vec<(&str, zeroize::Zeroizing<String>)> = busbar_contract::ir::facts::IrFacts::content(&invocation)
            .iter()
            .map(|item| (item.author(), zeroize::Zeroizing::new(item.screenable_text().into_owned())))
            .collect();
        let pool = agent_of(target).unwrap_or_default();
        let (signals, mut arena, mut messages) =
            (input.signals_buf(), input.arena_buf(), input.messages_buf());
        let pool = arena.span(pool.as_bytes());
        let dialect = arena.span(crate::PLANE_KEY.as_bytes());
        let projected = arena.span(&projected);
        let session = session.map(|s| arena.span(s.as_bytes()));
        let rewritten = rewritten.as_deref().map(|r| arena.span(r));
        let turns: Vec<_> = turns
            .iter()
            .map(|(role, text)| (arena.span(role.as_bytes()), arena.span(text.as_bytes())))
            .collect();
        for (role, text) in turns {
            messages.push_turn(&arena, role, text);
        }
        let short = !arena.fits() || !messages.fits();
        let (aw, and) = arena.settle(short);
        let (turns_written, turns_needed) = messages.settle(short);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        out.set(|o| &o.messages_needed, turns_needed as u32);
        if short {
            return Outcome::Failed;
        }
        out.host_str(|o| &o.view.pool, &arena, pool);
        out.host_str(|o| &o.view.ingress_dialect, &arena, dialect);
        if let Some(session) = session {
            out.host_octets(|o| &o.view.session, &arena, session);
        }
        out.host_list(|o| &o.view.signals, |o| &o.view.signals_len, &signals);
        out.set(|o| &o.view.message_count, shape.turn_count as u64);
        out.set(|o| &o.view.total_chars, shape.text_chars as u64);
        let mut flags = 0;
        if shape.has_tools {
            flags |= busbar_contract::abi::hook::REQUEST_HAS_TOOLS;
        }
        out.set(|o| &o.view.flags, flags);
        out.set(|o| &o.body, projected);
        out.host_rows(|o| &o.prompt.messages, &messages);
        out.set(|o| &o.prompt.messages_len, turns_written);
        out.set(|o| &o.prompt.message_count, turns_written as u64);
        if let Some(rewritten) = rewritten {
            out.set(|o| &o.rewritten, rewritten);
        }
        Outcome::Ready
    }
);

#[cfg(test)]
#[path = "tests/plane_door_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/card_precheck_tests.rs"]
mod card_precheck_tests;

#[cfg(test)]
#[path = "tests/card_refusal_equivalence_tests.rs"]
mod card_refusal_equivalence_tests;

#[cfg(test)]
#[path = "tests/originated_trust_tests.rs"]
mod originated_trust_tests;

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: STATEMENT,
    lifecycle: plane_life(A2aDoor),
    ready: Safe<ReadyOp>,
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<RefusalSlot>,
        serve: Safe<Serve>, hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}

#[cfg(test)]
#[path = "tests/request_ownership_cases.rs"]
mod request_ownership_cases;

#[cfg(test)]
#[path = "tests/plane_door_support.rs"]
mod plane_door_support;
