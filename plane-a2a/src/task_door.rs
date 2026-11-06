// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S HALF OF THE TASK VERBS: the host records the task store reads and the destination
//! judge, reached through [`Via`], and `on_piece` for a unit whose verb the plane answers itself
//! ([`crate::local`]).

use std::task::Poll;

use busbar_contract::abi::host::conn::connector::EGRESS_OPEN_WEB;
use busbar_contract::abi::host::service::{ItemSpan, DEST_REFUSE_PRIVATE};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    OnPieceIn, OnPieceOut, OutField, RecordWrite, UnitCount, EMIT_DONE, FROM_CALLER, RECORD_PUT,
    UNITS_REPORTED,
};
use busbar_contract::abi::sdk::conn::{Connector, StaticHost};
use busbar_contract::abi::sdk::{
    Instance, Keyed, Lent, Out, ServiceError, Services, StaticServices,
};
use serde_json::Value;

use crate::agent_arrival::{AgentDisposition, JSON_MEDIA_TYPE};
use crate::local::{self, LocalVerb, Reach};
use crate::plane_door::A2aDoor;
use crate::tasks::{self, Halt, Records, Write};

/// What a unit's pieces carry from one to the next.
#[derive(Debug, Default)]
pub struct Pass {
    /// Exact conditional attempts on this unit's current callback epoch.
    pub(crate) publication: crate::conditional_publication::Journal,
    /// A received definitive refusal allows a caller reply alone, across all its windows.
    pub(crate) response_only: bool,
    card_started: bool,
    /// The host services its finished pieces made: the next piece's handles count on from here.
    pub(crate) issued: u32,
    /// The held cards' warm runs on this unit's handles and has not landed: the next entry
    /// replays it from `issued`, on the same handles, before anything else the piece does.
    pub(crate) warming: bool,
    /// The piece in flight's stamp, kept across its re-entries.
    entry: Option<Entry>,
    /// The reply bytes the last window did not hold.
    rest: Remaining,
    /// The plane answered the verb itself (the admission passed): the unit is served, and every
    /// window reports its fee unit.
    served: bool,
    /// A card read's answer was written: a later piece answers nothing more.
    answered: bool,
    /// A local answer decided and held while busbar's own callback is mirrored onto the agent
    /// ([`crate::mirror`]): its status, its body, its record writes, and the mirror in flight.
    held: Option<HeldAnswer>,
    /// `ListTasks`'s refresh from the agent ([`refresh_listed`]): the listing in flight, then its
    /// answer and the handle the piece's calls count on from after it. Refreshed moves and configs
    /// stay staged until every read and output serialization succeeds.
    listing: Option<Box<crate::mirror::Originated>>,
    listed: Option<Listed>,
    refreshed: Vec<(crate::TaskRow, Option<local::PushConfig>)>,
    /// The reply the windows write is one message (the gRPC line's).
    message: bool,
    /// The audit row the unit's answer writes with its first window: its resource, and whether
    /// the unit was served ([`crate::statement::AUDIT_ACTION`]); its resource is also the unit's ledger
    /// lane.
    pub(crate) audit: Option<(String, bool)>,
    /// The agent the unit's ATTEMPT reached.
    member: String,
    /// The instance's restore this unit ran was reported: a re-entry re-reads it, and says nothing.
    restore_reported: bool,
    /// The caller's answer if the store refuses the record writes the unit's piece in hand carries
    /// (the kernel ends the unit `durability_unavailable`): the answer for the write its verb
    /// could not make durable, which the door's `refusal` renders in place of the kernel's
    /// words. Set by the piece that carries a verb's own write (a push config registered or
    /// removed, [`local::unrecorded`]; a task opened or resumed,
    /// [`crate::task_hop::Opened::Hop`]); `None` for a piece whose writes never fail
    /// a verb.
    pub(crate) unrecorded: Option<crate::agent_arrival::AgentRefusal>,
}

impl Drop for Pass {
    fn drop(&mut self) {
        self.publication.owner_dropped();
    }
}

/// A finished listing: the handle the piece's calls count on from after it, and its answer's status
/// and body (`None` = not answered).
type Listed = (
    u32,
    crate::binding::Binding,
    Option<(u16, crate::relay::RawBytes)>,
);

/// A local answer held across the mirror's PENDING entries.
#[derive(Debug)]
pub(crate) struct HeldAnswer {
    status: u32,
    body: crate::relay::RawBytes,
    writes: Vec<Write>,
    flight: Box<crate::mirror::Flight>,
    mirrored: bool,
}

/// A shared immutable answer allocation and the next byte to emit.
#[derive(Debug, Clone, Default)]
struct Remaining {
    bytes: std::sync::Arc<crate::relay::RawBytes>,
    offset: usize,
}

impl Remaining {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: std::sync::Arc::new(bytes.to_vec().into()),
            offset: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }
    fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
    fn advance(mut self, count: usize) -> Self {
        self.offset += count;
        self
    }
}

/// One piece's stamp: its clock, and whether it runs the instance's restore. A local verb never
/// runs the retention sweep: it runs from a submit ([`crate::task_hop::open`]), never from a read
/// or a timer.
#[derive(Debug, Clone, Copy)]
struct Entry {
    now: u64,
    restore: bool,
}

/// THE HOST RECORDS AND THE DESTINATION JUDGE, for one piece: its connector, and the host services
/// the door was opened with.
pub struct Via<'h> {
    host: &'h StaticHost,
    services: Option<StaticServices>,
    ticket: Ticket,
    conn: Connector<'h>,
    grown: &'h Grown,
    /// The bytes every records call of the piece is answered into, grown to the largest asked for
    /// and never cleared.
    scratch: crate::relay::RawBytes,
    /// The item spans every records call of the piece is answered into, grown as [`Via::scratch`].
    spans: Vec<ItemSpan>,
    publication: Option<crate::conditional_publication::Journal>,
    effects: crate::conditional_publication::Draft,
}

impl<'h> Via<'h> {
    /// The piece's calls, counting on from the `issued` its unit's finished pieces made; `grown` is
    /// the instance's book of the sizes short records answers named.
    pub fn new(
        host: &'h StaticHost,
        services: Option<StaticServices>,
        ticket: Ticket,
        issued: u32,
        grown: &'h Grown,
    ) -> Self {
        grown.with_all(|sizes| {
            sizes.retain(|(slot, generation, _), _| {
                *slot != ticket.slot || *generation == ticket.generation
            })
        });
        Self {
            host,
            services,
            ticket,
            conn: host.connector_from(ticket, issued),
            grown,
            scratch: crate::relay::RawBytes::default(),
            spans: Vec::new(),
            publication: None,
            effects: crate::conditional_publication::Draft::default(),
        }
    }

    /// Use this callback's replay owner for conditional observations and publication.
    pub(crate) fn publishing(mut self, journal: &crate::conditional_publication::Journal) -> Self {
        self.publication = Some(journal.clone());
        self
    }

    pub(crate) fn effects(&mut self, effects: crate::conditional_publication::Draft) {
        self.effects = effects;
    }

    /// The services the door was opened with.
    fn services(&self) -> Result<StaticServices, Halt> {
        self.services.ok_or_else(|| halted(ServiceError::Unserved))
    }

    /// The buffer sizes to issue `handle` at: what a short answer on it already named, else
    /// `(bytes, items)`.
    fn sized(&self, handle: CompletionHandle, bytes: usize, items: usize) -> (usize, usize) {
        match self.grown.get(&grown_key(handle)) {
            Some(size) => (
                usize::try_from(size.bytes).unwrap_or(usize::MAX).max(bytes),
                usize::try_from(size.items).unwrap_or(usize::MAX).max(items),
            ),
            None => (bytes, items),
        }
    }

    /// A short answer on `handle` named `bytes` and `items`: kept, so every entry of the piece
    /// issues the handle at that size from now on.
    fn grow(&self, handle: CompletionHandle, bytes: u64, items: u64) -> Result<(), Halt> {
        check_record_room(bytes, items)?;
        self.grown.with_all(|m| {
            let key = grown_key(handle);
            if m.len() >= GROWN_MAX && !m.contains_key(&key) {
                return Err(Halt::Failed("short-answer sizes book is full".into()));
            }
            m.insert(
                key,
                RecordSize {
                    bytes,
                    items,
                    short: true,
                },
            );
            Ok(())
        })
    }

    /// Reserve room atomically before issuing a new handle, so a later SHORT is recordable even
    /// when this call first pends and another ticket fills the book in the meantime.
    fn reserve(&self, handle: CompletionHandle, bytes: usize, items: usize) -> Result<(), Halt> {
        self.grown.with_all(|sizes| {
            let key = grown_key(handle);
            if sizes.contains_key(&key) {
                return Ok(());
            }
            if sizes.len() >= GROWN_MAX {
                return Err(Halt::Failed("short-answer sizes book is full".into()));
            }
            sizes.insert(
                key,
                RecordSize {
                    bytes: bytes as u64,
                    items: items as u64,
                    short: false,
                },
            );
            Ok(())
        })
    }

    /// A call that never answered SHORT and has finished needs no replay size, so only its
    /// reservation is released.
    fn unreserve(&self, handle: CompletionHandle) {
        self.grown.with_all(|sizes| {
            let key = grown_key(handle);
            if sizes.get(&key).is_some_and(|size| !size.short) {
                sizes.remove(&key);
            }
        });
    }

    /// The handles this piece has issued, counted from its unit's start.
    pub const fn issued(&self) -> u32 {
        self.conn.issued()
    }

    /// `random.fill` into `buf`, under this piece's next handle.
    pub fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt> {
        let Some(services) = self.services else {
            return Err(halted(ServiceError::Unserved));
        };
        let handle = self.next_handle();
        services
            .random_fill(handle, buf)
            .map_err(|e| Halt::Failed(format!("{e:?}")))
    }

    /// The next handle, for a host service the connector does not wrap.
    fn next_handle(&mut self) -> CompletionHandle {
        let seq = self.conn.issued();
        self.conn = self.host.connector_from(self.ticket, seq + 1);
        crate::task_door::handle(self.ticket, seq)
    }
}

/// The completion handle `seq` of `ticket`.
pub(crate) const fn handle(ticket: Ticket, seq: u32) -> CompletionHandle {
    CompletionHandle {
        ticket,
        seq,
        _reserved: 0,
    }
}

/// THE SIZES SHORT RECORDS ANSWERS NAMED, and pending calls' reservations, per handle (`ticket
/// slot, ticket generation, handle sequence`).
pub type Grown = Keyed<(u32, u32, u32), RecordSize>;

/// A reserved records call's initial room, or the room its SHORT answer named. Reservations
/// survive PENDING; completed calls release them unless a SHORT made the size part of replay.
#[derive(Debug, Clone, Copy)]
pub struct RecordSize {
    bytes: u64,
    items: u64,
    short: bool,
}

/// The most entries [`Grown`] holds; a full book never evicts a live handle.
const GROWN_MAX: usize = 4096;

/// Room for one record on its first read: a task row with its history and artifacts, where a longer
/// one is re-called once, on the same handle, at the size the host named.
const RECORD_BYTES: usize = 64 * 1024;

/// The records one page of a listing asks for; a page that comes back full asks for the next.
const PAGE_RECORDS: u32 = 64;

/// Room for one page of a listing on its first read.
const PAGE_BYTES: usize = 256 * 1024;

/// Bounds cover a page of maximum-sized task records plus keys.
const MAX_RECORD_ROOM: u64 = 8 * 1024 * 1024;
const MAX_RECORD_ITEMS: u64 = 4096;
const MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_SCAN_ROWS: usize = 65_536;

fn check_record_room(bytes: u64, items: u64) -> Result<(), Halt> {
    if bytes > MAX_RECORD_ROOM || items > MAX_RECORD_ITEMS {
        return Err(Halt::Failed(
            "record answer exceeds the bounded scratch capacity".into(),
        ));
    }
    Ok(())
}

fn check_scan_room(rows: usize, bytes: usize) -> Result<(), Halt> {
    if rows > MAX_SCAN_ROWS || bytes > MAX_SCAN_BYTES {
        return Err(Halt::Failed(
            "record listing exceeds the bounded scan capacity".into(),
        ));
    }
    Ok(())
}

/// The [`Grown`] key of `handle`.
const fn grown_key(handle: CompletionHandle) -> (u32, u32, u32) {
    (handle.ticket.slot, handle.ticket.generation, handle.seq)
}

/// An item span no answer wrote.
pub(crate) const ABSENT_SPAN: ItemSpan = ItemSpan {
    key: Span {
        offset: SPAN_ABSENT,
        len: 0,
    },
    value: Span {
        offset: SPAN_ABSENT,
        len: 0,
    },
};

/// A records answer that is not a value, as the task store reads it.
fn halted(e: ServiceError) -> Halt {
    Halt::Failed(format!("{e:?}"))
}

/// What one issue of a records call answered: its value, PENDING, or short at a size.
enum Issued<T> {
    Value(T),
    Pending,
    Short(u64, u64),
}

impl<T> Issued<T> {
    /// The wrapper's answer, read for the replay and short-buffer rules.
    fn of(answer: Poll<Result<T, ServiceError>>) -> Result<Self, Halt> {
        match answer {
            Poll::Pending => Ok(Issued::Pending),
            Poll::Ready(Ok(v)) => Ok(Issued::Value(v)),
            Poll::Ready(Err(ServiceError::Short { bytes, items })) => {
                Ok(Issued::Short(bytes, items))
            }
            Poll::Ready(Err(e)) => Err(halted(e)),
        }
    }
}

impl Via<'_> {
    /// The piece's buffers, `bytes` and `items` of them, grown when a call asks for more than they
    /// hold.
    fn buffers(&mut self, bytes: usize, items: usize) -> (&mut [u8], &mut [ItemSpan]) {
        if self.scratch.len() < bytes {
            self.scratch.grow_zeroed(bytes);
        }
        if self.spans.len() < items {
            self.spans.resize(items, ABSENT_SPAN);
        }
        (
            &mut self.scratch.as_mut_slice()[..bytes],
            &mut self.spans[..items],
        )
    }

    /// One records call under this piece's next handle, issued at `(bytes, items)` (or the size a
    /// short answer on the handle already named) and, answered short, re-issued ONCE on the same
    /// handle at the size it names.
    fn issue<T>(
        &mut self,
        (bytes, items): (usize, usize),
        mut call: impl FnMut(
            &Services,
            CompletionHandle,
            &mut [u8],
            &mut [ItemSpan],
        ) -> Poll<Result<T, ServiceError>>,
    ) -> Result<T, Halt> {
        let services = self.services()?;
        let handle = handle(self.ticket, self.conn.issued());
        self.reserve(handle, bytes, items)?;
        let handle = self.next_handle();
        let (b, i) = self.sized(handle, bytes, items);
        let (buf, spans) = self.buffers(b, i);
        let issued = match Issued::of(call(&services, handle, buf, spans)) {
            Ok(issued) => issued,
            Err(error) => {
                self.unreserve(handle);
                return Err(error);
            }
        };
        let (need_b, need_i) = match issued {
            Issued::Value(v) => {
                self.unreserve(handle);
                return Ok(v);
            }
            Issued::Pending => return Err(Halt::Pending),
            Issued::Short(need_b, need_i) => (need_b, need_i),
        };
        self.grow(handle, need_b, need_i)?;
        let (b, i) = self.sized(handle, bytes, items);
        let (buf, spans) = self.buffers(b, i);
        match Issued::of(call(&services, handle, buf, spans))? {
            Issued::Value(v) => Ok(v),
            Issued::Pending => Err(Halt::Pending),

            Issued::Short(..) => Err(halted(ServiceError::Broken)),
        }
    }
}

fn decode_notification_config(bytes: Option<&[u8]>) -> Result<Option<local::PushConfig>, ()> {
    bytes
        .map(crate::request_json::from_slice)
        .transpose()
        .map_err(|_| ())
}

impl Records for Via<'_> {
    fn retry_quota(&mut self) -> Result<bool, Halt> {
        let journal = self
            .publication
            .clone()
            .ok_or_else(|| Halt::Failed("conditional quota retry unavailable".into()))?;
        let Poll::Ready(Ok(reading)) = self.conn.clock_now() else {
            return Err(Halt::Failed("quota retry clock unavailable".into()));
        };
        let handle = self.next_handle();
        journal.retry_quota(handle.seq, reading.mono_ns)
    }

    fn quota_bootstrap_allowed(&mut self) -> Result<bool, Halt> {
        self.issue((0, 0), |services, handle, _, _| {
            Poll::Ready(services.entitled(handle, "record-quota-bootstrap:"))
        })
    }

    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        let journal = self
            .publication
            .clone()
            .ok_or_else(|| Halt::Failed("conditional observation unavailable".into()))?;
        let handle = self.next_handle();
        journal.observe(handle.seq, kind, scope)
    }

    fn publish(
        &mut self,
        predicates: &[tasks::Predicate],
        lives: &[tasks::ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        let journal = self
            .publication
            .clone()
            .ok_or_else(|| Halt::Failed("conditional publication unavailable".into()))?;
        // Quota bootstrap publishes its barrier and counters before the task transaction.
        // Those administrative writes have no task to notify or backend mapping to install.
        // Keep the caller's draft for the later task publication, including on replay.
        let quota_only = !writes.is_empty()
            && !predicates.is_empty()
            && lives.is_empty()
            && writes
                .iter()
                .all(|write| write.kind == crate::records::KIND_TASK_QUOTA)
            && predicates
                .iter()
                .all(|predicate| predicate.kind == crate::records::KIND_TASK_QUOTA);
        let mut effects = if quota_only {
            crate::conditional_publication::Draft::default()
        } else {
            self.effects.clone()
        };
        let mut predicates = predicates.to_vec();
        if effects.notify {
            let row = writes
                .iter()
                .find(|write| write.kind == crate::records::KIND_TASK && !write.value.is_empty())
                .and_then(|write| {
                    crate::request_json::from_slice::<crate::TaskRow>(&write.value).ok()
                })
                .ok_or_else(|| Halt::Failed("notification task unavailable".into()))?;

            let key = tasks::task_key(&row.principal, &row.task_id);
            match self.get(crate::records::KIND_PUSH_CONFIG, &key) {
                Err(Halt::Pending) => return Err(Halt::Pending),
                Err(Halt::Failed(_)) => effects.config = Some(Err(())),
                Ok(raw) => {
                    let raw = raw.map(crate::relay::RawBytes::from);
                    let config = match writes.iter().rev().find(|write| {
                        write.kind == crate::records::KIND_PUSH_CONFIG && write.key == key
                    }) {
                        Some(write) if write.value.is_empty() => None,
                        Some(write) => Some(write.value.as_slice()),
                        None => raw.as_deref(),
                    };
                    effects.config = Some(decode_notification_config(config));
                    if matches!(effects.config, Some(Err(()))) {
                        tracing::warn!(
                            phase = "notification-config",
                            "A2A stored push configuration is unreadable"
                        );
                    }
                    if let Some(existing) = predicates.iter().find(|predicate| {
                        predicate.kind == crate::records::KIND_PUSH_CONFIG && predicate.key == key
                    }) {
                        if existing.expected.as_deref() != raw.as_deref() {
                            return Err(Halt::Failed("notification configuration changed".into()));
                        }
                    } else {
                        predicates.push(tasks::Predicate {
                            kind: crate::records::KIND_PUSH_CONFIG,
                            key,
                            expected: raw.map(crate::relay::RawBytes::into_vec),
                        });
                    }
                }
            }
        }
        let handle = self.next_handle();
        journal.publish_with(handle.seq, &predicates, lives, writes, &effects)
    }

    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.issue((RECORD_BYTES, 1), |services, handle, buf, _| {
            services
                .records_get(handle, kind, key.as_bytes(), buf)
                .map(|r| r.map(|found| found.map(<[u8]>::to_vec)))
        })
    }

    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        let mut rows = crate::proto::custody::Guard::new(Vec::<(String, Vec<u8>)>::new());
        let mut scanned_bytes = 0usize;
        loop {
            let after = rows.last().map(|(k, _)| k.clone());
            let page = self.issue(
                (PAGE_BYTES, PAGE_RECORDS as usize),
                |services, handle, buf, spans| {
                    services
                        .records_list(
                            handle,
                            kind,
                            prefix.as_bytes(),
                            after.as_deref().map(str::as_bytes),
                            PAGE_RECORDS,
                            (buf, spans),
                        )
                        .map(|r| {
                            r.and_then(|page| {
                                let mut rows = crate::proto::custody::Guard::new(Vec::new());
                                for (k, v) in page.records() {
                                    let key =
                                        std::str::from_utf8(k).map_err(|_| ServiceError::Broken)?;
                                    rows.push((key.to_owned(), v.to_vec()));
                                }
                                Ok(rows.take())
                            })
                        })
                },
            )?;
            let mut page = crate::proto::custody::Guard::new(page);
            let full = page.len() >= PAGE_RECORDS as usize;
            for (key, value) in page.iter() {
                scanned_bytes = scanned_bytes
                    .saturating_add(key.len())
                    .saturating_add(value.len());
            }
            check_scan_room(rows.len().saturating_add(page.len()), scanned_bytes)?;
            if full
                && page
                    .last()
                    .is_some_and(|(key, _)| after.as_ref().is_some_and(|after| key <= after))
            {
                return Err(Halt::Failed("record listing cursor did not advance".into()));
            }
            rows.extend(page.take());
            if !full {
                return Ok(rows.take());
            }
        }
    }
}

impl crate::task_hop::Mint for Via<'_> {
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt> {
        Via::random(self, buf)
    }
}

/// Room for the judged addresses of one destination.
const JUDGED_BYTES: usize = 512;
/// One span per judged address.
const JUDGED_ADDRESSES: usize = 16;

/// The open-web judgement of a caller-named destination (a push callback) on `handle`: its `DEST_*`
/// verdict and the set a dial must land within.
pub(crate) fn judge_open_web(
    services: &StaticServices,
    handle: CompletionHandle,
    dest: &str,
) -> Poll<Result<(u64, String), ServiceError>> {
    judge_open_web_sized(services, handle, dest, JUDGED_BYTES, JUDGED_ADDRESSES)
}

/// [`judge_open_web`] with the sizes a short answer named, on the original handle.
pub(crate) fn judge_open_web_sized(
    services: &StaticServices,
    handle: CompletionHandle,
    dest: &str,
    bytes: usize,
    items: usize,
) -> Poll<Result<(u64, String), ServiceError>> {
    let mut bytes = vec![0u8; bytes];
    let mut spans = vec![ABSENT_SPAN; items];
    services
        .dest_judge_as(
            handle,
            dest,
            EGRESS_OPEN_WEB,
            DEST_REFUSE_PRIVATE,
            Some((&mut bytes[..], &mut spans[..])),
        )
        .map(|r| r.map(|judged| (judged.verdict, judged.within())))
}

impl Reach for Via<'_> {
    fn judge(&mut self, dest: &str) -> Result<u64, Halt> {
        let services = self.services()?;
        let handle = self.next_handle();
        match judge_open_web(&services, handle, dest) {
            Poll::Pending => Err(Halt::Pending),
            Poll::Ready(Ok((verdict, _))) => Ok(verdict),
            Poll::Ready(Err(e)) => Err(Halt::Failed(format!("{e:?}"))),
        }
    }
}

/// The instance's restore is either owned by one live unit or has finished reporting.
pub(crate) type Restore = Keyed<(), RestoreState>;

#[derive(Debug, Clone, Copy)]
pub(crate) enum RestoreState {
    InFlight { unit: u64, ticket: Ticket },
    Reported,
}

fn claim_restore(restored: &Restore, unit: u64, ticket: Ticket) -> bool {
    restored.with_all(|m| {
        if m.contains_key(&()) {
            return false;
        }
        m.insert((), RestoreState::InFlight { unit, ticket });
        true
    })
}

fn restored(plane: &A2aDoor, unit: u64, ticket: Ticket) {
    plane.restored.with_all(|m| {
        if matches!(m.get(&()), Some(RestoreState::InFlight { unit: owner, ticket: held })
            if *owner == unit && *held == ticket)
        {
            m.insert((), RestoreState::Reported);
        }
    });
}

fn forget_sizes(grown: &Grown, ticket: Ticket) {
    if ticket != Ticket::NONE {
        grown.with_all(|sizes| {
            sizes.retain(|(slot, generation, _), _| {
                *slot != ticket.slot || *generation != ticket.generation
            })
        });
    }
}

fn cancel_unit(
    plane: &A2aDoor,
    unit: &mut crate::plane_door::AgentUnit,
) -> crate::conditional_publication::Journal {
    unit.pass.refreshed.clear();
    if let Some(hop) = unit.hop.as_mut() {
        hop.cancel_owed(&plane.deliveries, &unit.pass.publication);
    }
    unit.pass.publication.cancelled();
    unit.pass.publication.clone()
}

/// Release only the cancelled unit's pending restore and replay sizes, after the plane marks that
/// unit over.
pub(crate) fn cancelled(plane: &A2aDoor, cancel: busbar_contract::abi::sdk::plane::UnitCancel) {
    let mut publications = Vec::new();
    let named = (cancel.unit != 0)
        .then(|| {
            plane.units.with(&cancel.unit, |u| {
                u.map(|u| {
                    publications.push(cancel_unit(plane, u));
                    u.ticket
                })
            })
        })
        .flatten();
    let ticket = named.unwrap_or(cancel.ticket);
    if named.is_none() && ticket != Ticket::NONE {
        plane.units.with_all(|units| {
            for u in units.values_mut().filter(|u| u.ticket == ticket) {
                publications.push(cancel_unit(plane, u));
            }
        });
    }

    for publication in publications {
        publication.owner_dropped();
    }
    plane.restored.with_all(|m| {
        let ours = match m.get(&()) {
            Some(RestoreState::InFlight { unit, ticket: held }) => match named {
                Some(_) => *unit == cancel.unit,
                None => ticket != Ticket::NONE && *held == ticket,
            },
            _ => false,
        };
        if ours {
            m.remove(&());
        }
    });
    forget_sizes(&plane.grown, ticket);
}

/// Say what the restore found, once per unit: the counts, a row this build cannot read at WARN,
/// each in-flight task's broken chain at ERROR as tamper evidence, and a restore that could not
/// read the records at WARN.
fn report_restore(plane: &A2aDoor, unit: u64, restored: Result<tasks::Restored, Halt>) {
    let first = plane.units.with(&unit, |u| {
        u.is_some_and(|u| !std::mem::replace(&mut u.pass.restore_reported, true))
    });
    if !first {
        return;
    }
    let restored = match restored {
        Ok(r) => r,
        Err(e) => {
            busbar_contract::diag_warn!(
                crate::diagnostics::A2A_TASK_STATE_UNREAD,
                error = ?e,
                "could not read durable A2A task state; in-flight tasks are read as they are asked for"
            );
            return;
        }
    };
    if restored != tasks::Restored::default() {
        tracing::info!(
            active = restored.active,
            terminal = restored.terminal,
            unreadable = restored.unreadable,
            "A2A in-flight tasks rehydrated from the durable task records"
        );
    }
    if restored.unreadable > 0 {
        busbar_contract::diag_warn!(
            crate::diagnostics::A2A_TASK_ROWS_UNREADABLE,
            rows = restored.unreadable,
            "persisted A2A task rows could not be read back and are NOT resumable; they were most \
             likely written by a different engine version"
        );
    }
    for (task, words) in &restored.chain_breaks {
        busbar_contract::diag_error!(
            crate::diagnostics::A2A_TASK_CHAIN_VERIFY_FAILED,
            task_id = %task,
            break_detail = %words,
            "A2A per-task provenance CHAIN VERIFICATION FAILED on restore"
        );
    }
}

/// The answer a NOTIFICATION gets: received, never answered (JSON-RPC 2.0 section 4.1: the server
/// MUST NOT reply), so `202` and no body at all.
pub(crate) const fn notice_answer() -> (u32, &'static [u8]) {
    (crate::agent_arrival::STATUS_ACCEPTED, b"")
}

/// The local verb a unit arrived as.
fn verb_of(disposition: &AgentDisposition) -> Option<LocalVerb> {
    match disposition {
        AgentDisposition::Request { row, .. } => local::verb_of(row.method),
        _ => None,
    }
}

/// `on_piece` for a unit whose verb the plane answers itself; `None` for any other unit.
pub fn on_piece(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: Lent<'_, OnPieceIn>,
    mut out: Out<'_, OnPieceOut>,
) -> Option<Outcome> {
    let journal = plane
        .units
        .with(&input.unit(), |u| u.map(|u| u.pass.publication.clone()))?;
    let outcome = local_piece(plane, instance, input, &mut out, &journal);
    plane.deliveries.retain_publication(&journal);
    if let Some(pending) = journal.pending(&plane.publication_leases, &mut out) {
        if pending != Outcome::Pending {
            crate::push_door::apply_publication(plane, &journal);
        }
        return Some(pending);
    }
    if outcome == Some(Outcome::Ready) {
        crate::push_door::apply_publication(plane, &journal);
        journal.finished();
        if journal.completed() {
            plane.deliveries.release_publication(&journal);
        }
    } else if outcome.is_some_and(|outcome| outcome != Outcome::Pending) {
        crate::push_door::apply_publication(plane, &journal);
    }
    outcome
}

fn local_piece(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    journal: &crate::conditional_publication::Journal,
) -> Option<Outcome> {
    let unit = input.unit();

    if plane.units.with(&unit, |u| {
        u.is_some_and(|u| matches!(u.disposition, AgentDisposition::Notice { .. }))
    }) {
        if input.from() != FROM_CALLER {
            return Some(Outcome::Ready);
        }
        let (status, body) = notice_answer();
        let head = WindowHead {
            fields: &[],
            length: true,
            message: false,
            close: None,
        };
        return Some(window_core(
            plane,
            unit,
            &input,
            out,
            (status, body),
            &[],
            Some(head),
        ));
    }
    let (verb, rest, composed, framed, addressed, section, generation, version, held) =
        plane.units.with(&unit, |u| {
            let u = u?;
            let version = match &u.disposition {
                AgentDisposition::Request { version, .. } => *version,
                _ => crate::agent_arrival::DEFAULT_VERSION,
            };
            Some((
                verb_of(&u.disposition)?,
                std::mem::take(&mut u.pass.rest),
                u.envelope.clone(),
                u.framed,
                u.agent.clone(),
                u.section.clone(),
                u.generation,
                version,
                u.pass.held.take(),
            ))
        })?;

    if !rest.is_empty() {
        return Some(tail_window(plane, unit, &input, out, rest));
    }

    if let Some(mut held) = held {
        if !held.mirrored
            && crate::plane_door::drive_mirror(plane, instance.ticket(), &mut held.flight)
                .is_pending()
        {
            plane.on_unit(unit, |u| {
                u.pass.held = Some(held);
            });
            return Some(Outcome::Pending);
        }
        held.mirrored = true;
        let issued = held.flight.hop.seq;
        let mut answer = local::LocalAnswer {
            status: held.status,
            body: std::mem::take(&mut held.body).into_vec(),
        };
        let outcome = answered_window(
            plane,
            unit,
            &input,
            out,
            (framed, composed.is_some()),
            &answer,
            &held.writes,
            issued,
        );
        if outcome != Outcome::Ready {
            held.body = std::mem::take(&mut answer.body).into();
            plane.on_unit(unit, |u| u.pass.held = Some(held));
        }
        return Some(outcome);
    }

    if input.from() != FROM_CALLER {
        let given = input.member().as_str().unwrap_or_default();
        if !given.is_empty() {
            plane.on_unit(unit, |u| {
                u.pass.member = given.to_string();
            });
        }
        return Some(Outcome::Ready);
    }
    let host = plane.host.as_ref()?;
    let Poll::Ready(Ok(reading)) = host.connector(instance.ticket()).clock_now() else {
        tracing::warn!(phase = "clock", "A2A local task clock is unavailable");
        return Some(Outcome::Failed);
    };
    let clock = reading.wall_ns / 1_000_000_000;
    let (base, entry) = plane.units.with(&unit, |u| {
        let u = u?;
        let entry = *u.pass.entry.get_or_insert_with(|| Entry {
            now: clock,
            restore: claim_restore(&plane.restored, unit, instance.ticket()),
        });
        Some((u.pass.issued, entry))
    })?;
    let mut via =
        Via::new(host, plane.services, instance.ticket(), base, &plane.grown).publishing(journal);

    let raw = composed
        .as_deref()
        .map(Vec::as_slice)
        .unwrap_or_else(|| input.bytes().bytes());
    let envelope = crate::request_json::parse(raw).unwrap_or_default();
    let caller = input.caller_ref().as_str().unwrap_or_default();
    let mut writes = Vec::new();
    if entry.restore {
        match tasks::restore(&mut via) {
            Err(Halt::Pending) => return Some(Outcome::Pending),
            answer => {
                report_restore(plane, unit, answer);
                restored(plane, unit, instance.ticket());
            }
        }
    }

    let handle = via.next_handle();
    let live = plane.services.is_some_and(|services| {
        services
            .entitled(
                handle,
                busbar_contract::abi::host::service::ENTITLEMENT_STANDING,
            )
            .unwrap_or(false)
    });

    let given_member = input.member().as_str().unwrap_or_default();
    let held_member = plane
        .units
        .with(&unit, |u| u.map(|u| u.pass.member.clone()))
        .unwrap_or_default();
    let member = if given_member.is_empty() {
        held_member.as_str()
    } else {
        given_member
    };
    let refused = if !live {
        Some(crate::agent_arrival::not_live())
    } else if member.is_empty() {
        Some(crate::agent_arrival::scope_refusal(""))
    } else {
        match section.as_ref().and_then(|s| s.agents.get(member)) {
            Some(def) => crate::plane_door::admit_unit(
                plane,
                (member, def),
                addressed.as_deref(),
                generation,
                Some(&envelope),
            )
            .err(),
            None => Some(crate::agent_arrival::no_such_agent(member)),
        }
    };
    let served = refused.is_none();
    let answered = match refused {
        Some(refusal) => Ok(Some(local::LocalAnswer {
            status: refusal.status,
            body: crate::relay::json_bytes(&refusal.envelope()).unwrap_or_default(),
        })),

        None if verb == local::LocalVerb::ListTasks => {
            match refresh_listed(
                plane,
                instance.ticket(),
                unit,
                &mut via,
                (caller, member),
                (section.as_deref(), generation, entry.now, version),
                &mut writes,
            ) {
                Err(Halt::Pending) => return Some(Outcome::Pending),
                Err(Halt::Failed(_)) => {
                    tracing::warn!(
                        phase = "list-refresh-store",
                        "A2A task listing refresh failed; retained state is served"
                    );
                    writes.clear();
                    plane.on_unit(unit, |u| u.pass.refreshed.clear());
                }
                Ok(()) => {}
            }
            let staged = writes.clone();
            local::list_answer(
                &mut tasks::Staged::new(&mut via, &staged),
                &envelope,
                caller,
                entry.now,
            )
            .map(Some)
        }
        None => local::answer_local(&mut via, verb, &envelope, caller, entry.now, &mut writes),
    };
    let mut answer = match answered {
        Err(Halt::Pending) => return Some(Outcome::Pending),
        Err(Halt::Failed(_)) => {
            tracing::warn!(
                phase = "local-task-store",
                "A2A local task operation could not read or publish records"
            );
            writes.clear();
            plane.on_unit(unit, |u| u.pass.refreshed.clear());
            let id = envelope.get("id").unwrap_or(&Value::Null);
            if journal.refused_commit() {
                local::unrecorded_answer(verb, id).unwrap_or_else(|| local::unreadable(id))
            } else {
                local::unreadable(id)
            }
        }

        Ok(None) => return Some(Outcome::Refused),
        Ok(Some(answer)) => answer,
    };

    plane.deliveries.apply_deletions(journal);

    let unrecorded = (!writes.is_empty())
        .then(|| local::unrecorded(verb, envelope.get("id").unwrap_or(&Value::Null)))
        .flatten();
    plane.on_unit(unit, |u| {
        u.pass.unrecorded = unrecorded;
        u.pass.response_only |= journal.response_only();
        u.pass.served = served && !u.pass.response_only;

        u.pass.audit = (served && !u.pass.response_only)
            .then(|| (crate::statement::agent_resource(member), true));
    });

    let mirrored = crate::mirror::mirrored_verb(verb).filter(|_| served && answer.status == 200);
    let flight = match mirrored {
        Some(method) => match mirror_flight(
            plane,
            instance.ticket(),
            &mut via,
            (method, version),
            &envelope,
            (caller, member),
            (section.as_deref(), generation, entry.now),
        ) {
            Err(Halt::Pending) => return Some(Outcome::Pending),
            Err(Halt::Failed(_)) => None,
            Ok(flight) => flight,
        },
        None => None,
    };
    if let Some(mut flight) = flight {
        if crate::plane_door::drive_mirror(plane, instance.ticket(), &mut flight).is_pending() {
            plane.on_unit(unit, |u| {
                u.pass.held = Some(HeldAnswer {
                    status: answer.status,
                    body: std::mem::take(&mut answer.body).into(),
                    writes,
                    flight,
                    mirrored: false,
                });
            });
            return Some(Outcome::Pending);
        }
        let issued = flight.hop.seq;
        let outcome = answered_window(
            plane,
            unit,
            &input,
            out,
            (framed, composed.is_some()),
            &answer,
            &writes,
            issued,
        );
        if outcome != Outcome::Ready {
            plane.on_unit(unit, |u| {
                u.pass.held = Some(HeldAnswer {
                    status: answer.status,
                    body: std::mem::take(&mut answer.body).into(),
                    writes,
                    flight,
                    mirrored: true,
                })
            });
        }
        return Some(outcome);
    }
    let issued = via.issued();
    Some(answered_window(
        plane,
        unit,
        &input,
        out,
        (framed, composed.is_some()),
        &answer,
        &writes,
        issued,
    ))
}

/// Refresh what busbar last saw from the agent doing the work: the caller's live rows on this agent
/// whose agent ids busbar learnt are the whitelist, and the agent is asked `ListTasks` (its default
/// page) only when there is one.
#[allow(clippy::too_many_arguments)]
fn refresh_listed<'h>(
    plane: &'h A2aDoor,
    ticket: Ticket,
    unit: u64,
    via: &mut Via<'h>,
    (caller, member): (&str, &str),
    (section, generation, now, version): (
        Option<&crate::a2a::config::AgentsCfg>,
        u64,
        u64,
        &'static str,
    ),
    writes: &mut Vec<Write>,
) -> Result<(), Halt> {
    let Some(def) = section.and_then(|s| s.agents.get(member)) else {
        return Ok(());
    };
    let ours = listed_backend_ids(&tasks::list(via, caller, now)?, member, |id| {
        plane.backend_of(caller, id)
    });
    if ours.is_empty() {
        return Ok(());
    }
    let Some(host) = plane.host.as_ref() else {
        return Ok(());
    };
    let held = plane.units.with(&unit, |u| {
        u.map(|u| (u.pass.listed.clone(), u.pass.listing.take()))
    });
    let Some((listed, listing)) = held else {
        return Ok(());
    };
    let (after, binding, answered) = match listed {
        Some(done) => done,
        None => {
            let card = plane.cards.at(member, generation);
            let selected = crate::binding::select(card.as_deref(), &def.url);
            let Some(binding) = crate::binding::speakable(&selected.word) else {
                return Ok(());
            };
            let mut hop = listing.unwrap_or_else(|| {
                Box::new(crate::mirror::Originated {
                    agent: member.to_string(),
                    url: selected.endpoint.to_string(),
                    allow_private: def.allow_private,
                    binding,
                    version,
                    seq: via.issued(),
                    exchange: None,
                })
            });
            let params = serde_json::json!({});
            match crate::plane_door::drive_originated(
                plane,
                ticket,
                &mut hop,
                crate::mirror::LIST_TASKS,
                &params,
            ) {
                Poll::Pending => {
                    plane.on_unit(unit, |u| {
                        u.pass.listing = Some(hop);
                    });
                    return Err(Halt::Pending);
                }

                Poll::Ready(landed) => {
                    let answer = match landed {
                        Ok(answer) => answer.map(|(status, body)| (status, body.into())),
                        Err(_) => {
                            tracing::warn!(
                                phase = "list-refresh-hop",
                                "A2A task listing refresh failed; retained state is served"
                            );
                            None
                        }
                    };
                    let done = (hop.seq, hop.binding, answer);
                    plane.on_unit(unit, |u| {
                        u.pass.listed = Some(done.clone());
                    });
                    done
                }
            }
        }
    };
    let publication = via.publication.clone();
    *via = Via::new(host, plane.services, ticket, after, &plane.grown);
    via.publication = publication;
    let states = crate::mirror::listed_states(
        binding,
        answered.as_ref().map(|(s, b)| (*s, b.as_slice())),
        &ours,
    );
    let at = tasks::Stamp {
        caller,
        request_id: "",
        now,
    };
    let mut moved = Vec::new();
    for (busbar_id, state) in states {
        via.effects(crate::conditional_publication::Draft {
            notify: true,
            ..Default::default()
        });

        match tasks::transition(via, &at, &busbar_id, state, writes) {
            Err(Halt::Pending) => return Err(Halt::Pending),
            Err(Halt::Failed(_)) => {
                tracing::warn!(
                    phase = "list-refresh-transition",
                    "A2A task refresh transition failed; retained state is served"
                );
            }
            Ok(None) => {}
            Ok(Some(row)) => moved.push(row),
        }
    }

    let mut refreshed = Vec::new();
    for row in moved {
        let config =
            local::held_config(&mut tasks::Staged::new(via, writes), caller, &row.task_id)?;
        refreshed.push((row, config));
    }
    plane.on_unit(unit, |u| {
        u.pass.refreshed = refreshed;
    });
    Ok(())
}

/// Far-end ids that identify exactly one of this caller's live tasks on the listed agent.
pub(crate) fn listed_backend_ids(
    rows: &[crate::TaskRow],
    member: &str,
    backend: impl Fn(&str) -> Option<String>,
) -> std::collections::BTreeMap<String, String> {
    let mut ids = std::collections::BTreeMap::new();
    let mut ambiguous = std::collections::BTreeSet::new();
    for task in rows
        .iter()
        .filter_map(|row| crate::a2a::task::Task::from_row(row).ok())
        .filter(|t| t.agent_id == member && !t.state.is_terminal())
    {
        let Some(id) = backend(&task.task_id) else {
            continue;
        };
        if let Some(previous) = ids.insert(id.clone(), task.task_id.clone()) {
            if previous != task.task_id {
                ambiguous.insert(id);
            }
        }
    }
    for id in ambiguous {
        ids.remove(&id);
    }
    ids
}

/// THE MIRROR a successful push-config verb owes ([`crate::mirror`]), or `None` when it owes none.
fn mirror_flight(
    plane: &A2aDoor,
    ticket: Ticket,
    via: &mut Via<'_>,
    (method, version): (&'static str, &'static str),
    envelope: &Value,
    (caller, member): (&str, &str),
    (section, generation, now): (Option<&crate::a2a::config::AgentsCfg>, u64, u64),
) -> Result<Option<Box<crate::mirror::Flight>>, Halt> {
    let made = mirror_flight_inner(
        plane,
        ticket,
        via,
        (method, version),
        envelope,
        (caller, member),
        (section, generation, now),
    );
    if matches!(&made, Err(Halt::Failed(_))) {
        tracing::warn!(agent = %member, method, phase = "setup", failure_class = "records",
            "A2A push-config mirror could not be prepared; the local answer is unchanged");
    }
    made
}

fn mirror_owns_task(task: &crate::a2a::task::Task, member: &str) -> bool {
    task.agent_id == member && !task.state.is_terminal()
}

fn mirror_flight_inner(
    plane: &A2aDoor,
    ticket: Ticket,
    via: &mut Via<'_>,
    (method, version): (&'static str, &'static str),
    envelope: &Value,
    (caller, member): (&str, &str),
    (section, generation, now): (Option<&crate::a2a::config::AgentsCfg>, u64, u64),
) -> Result<Option<Box<crate::mirror::Flight>>, Halt> {
    let Some(our_url) = plane
        .public_url
        .as_deref()
        .and_then(crate::mirror::callback_url)
    else {
        return Ok(None);
    };
    let Some(def) = section.and_then(|s| s.agents.get(member)) else {
        return Ok(None);
    };
    let params = crate::request_json::RequestJson::new(
        envelope.get("params").cloned().unwrap_or(Value::Null),
    );
    let dialect = local::Dialect::of_method(
        envelope
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let Some(task) = local::addressed(via, dialect, &params, caller, now)? else {
        return Ok(None);
    };
    if !mirror_owns_task(&task, member) {
        return Ok(None);
    }
    let Some(backend_task) = plane.backend_of(caller, &task.task_id) else {
        return Ok(None);
    };
    let card = plane.cards.at(member, generation);
    let selected = crate::binding::select(card.as_deref(), &def.url);
    let Some(binding) = crate::binding::speakable(&selected.word) else {
        return Ok(None);
    };
    let mut signer = HostSigner {
        services: plane.services.as_ref(),
        ticket,
        seq: via.issued(),
        key_id: None,
    };
    let Some(token) = signer
        .signed(&crate::push::token_input(&task.task_id))
        .and_then(|(_, sig)| plane.tokens.mint(caller, &task.task_id, &sig))
    else {
        tracing::warn!(agent = %member, method, phase = "signing",
            "A2A push-config mirror could not obtain a callback capability; the local answer is unchanged");
        return Ok(None);
    };
    let token = zeroize::Zeroizing::new(token);
    let create = crate::mirror::create_params(&backend_task, &our_url, &token);
    Ok(Some(Box::new(crate::mirror::Flight {
        stage: crate::mirror::Stage::Mirror,
        method,
        backend_task,
        create,
        hop: crate::mirror::Originated {
            agent: member.to_string(),
            url: selected.endpoint.to_string(),
            allow_private: def.allow_private,
            binding,
            version,
            seq: signer.seq,
            exchange: None,
        },
    })))
}

/// The caller's local answer, written for its line: the gRPC line's message or status, the
/// HTTP+JSON line's re-framed document, the JSON-RPC line's envelope as answered.
#[allow(clippy::too_many_arguments)]
fn answered_window(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    (framed, composed): (Option<crate::framed::Rpc>, bool),
    answer: &local::LocalAnswer,
    writes: &[Write],
    issued: u32,
) -> Outcome {
    let done = match (framed, composed) {
        (Some(rpc), _) => framed_window(
            plane,
            unit,
            input,
            out,
            &crate::framed::framed_reply(rpc, answer.status, &answer.body),
            writes,
        ),
        (None, true) => window(
            plane,
            unit,
            input,
            out,
            (
                answer.status,
                &crate::relay::RawBytes::from(crate::rest::reframe(answer.status, &answer.body)),
            ),
            writes,
        ),
        (None, false) => window(
            plane,
            unit,
            input,
            out,
            (answer.status, &answer.body),
            writes,
        ),
    };
    if done == Outcome::Ready {
        let refreshed = plane
            .units
            .with(&unit, |u| {
                let u = u?;
                u.pass.issued = issued;
                u.pass.entry = None;
                u.pass.listing = None;
                u.pass.listed = None;
                Some(std::mem::take(&mut u.pass.refreshed))
            })
            .unwrap_or_default();
        if !refreshed.is_empty() {
            let publication = plane
                .units
                .with(&unit, |u| u.map(|u| u.pass.publication.clone()));
            if let Some(publication) = publication {
                crate::push_door::apply_publication(plane, &publication);
            }
        }
    }
    done
}

/// The kind index `kind` is in the tail's record kinds.
pub(crate) fn kind_index(kind: &str) -> u32 {
    crate::records::held_kind_index(kind)
}

/// Answer one window of a local reply: as many bytes as the reply buffer holds, and on the first
/// window (`status != 0`) its status, its `content-type` and the record writes.
fn window(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    answer: (u32, &[u8]),
    writes: &[Write],
) -> Outcome {
    window_with(plane, unit, input, out, answer, writes, &[JSON_HEAD])
}

/// The head a JSON answer starts with.
const JSON_HEAD: (&str, &str) = (crate::relay::H_CONTENT_TYPE, JSON_MEDIA_TYPE);

/// [`window`], the first window's head fields `head` (each written before its stated length).
fn window_with(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    (status, body): (u32, &[u8]),
    writes: &[Write],
    head: &[(&str, &str)],
) -> Outcome {
    let first = (status != 0).then_some(WindowHead {
        close: None,
        fields: head,
        length: true,
        message: false,
    });
    window_core(plane, unit, input, out, (status, body), writes, first)
}

/// A WHOLE REPLY ON THE gRPC LINE ([`crate::framed::FramedReply`]): its status in the line's own
/// numbering (`0` = `OK`), its details field when it has one, and no media type and no length (the
/// grpc transport frames).
fn framed_window(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    reply: &crate::framed::FramedReply,
    writes: &[Write],
) -> Outcome {
    let ok = reply.code == crate::framed::Code::Ok as u32;
    let body: &[u8] = if ok { &reply.body } else { &[] };
    window_core(
        plane,
        unit,
        input,
        out,
        (crate::relay::STATUS_OK, body),
        writes,
        Some(WindowHead {
            fields: &[(
                crate::relay::H_CONTENT_TYPE,
                crate::framed::REPLY_CONTENT_TYPE,
            )],
            length: false,
            message: ok,
            close: (!ok).then_some(reply),
        }),
    )
}

/// The first window's head: its fields, whether it states its length, and whether its body is one
/// message (the gRPC line's: its last byte is a message boundary).
struct WindowHead<'h> {
    fields: &'h [(&'h str, &'h str)],
    length: bool,
    message: bool,
    /// The gRPC line's final status the answer closes with (no message went out).
    close: Option<&'h crate::framed::FramedReply>,
}

/// A response-only refusal cannot stage record effects beside its error answer.
fn check_response_effects(response_only: bool, writes: &[Write]) -> Result<(), Outcome> {
    if response_only && !writes.is_empty() {
        return Err(Outcome::Failed);
    }
    Ok(())
}

/// One window: on the first (`first`), its head; then as many bytes as the reply buffer holds.
fn window_core(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    (status, body): (u32, &[u8]),
    writes: &[Write],
    first: Option<WindowHead<'_>>,
) -> Outcome {
    window_core_inner(plane, unit, input, out, (status, body), writes, first, None)
}

fn tail_window(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    rest: Remaining,
) -> Outcome {
    let outcome = window_core_inner(
        plane,
        unit,
        input,
        out,
        (0, rest.as_slice()),
        &[],
        None,
        Some(&rest),
    );
    if outcome != Outcome::Ready {
        plane.on_unit(unit, |u| u.pass.rest = rest);
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn window_core_inner(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    (status, body): (u32, &[u8]),
    writes: &[Write],
    first: Option<WindowHead<'_>>,
    retained: Option<&Remaining>,
) -> Outcome {
    let response_only = plane
        .units
        .with(&unit, |u| u.is_some_and(|u| u.pass.response_only));
    if let Err(outcome) = check_response_effects(response_only, writes) {
        return outcome;
    }
    let (mut reply, mut fields, mut records, mut arena, mut units) = (
        input.reply_buf(),
        input.fields_buf(),
        input.records_buf(),
        input.arena_buf(),
        input.units_buf(),
    );
    if !response_only
        && plane
            .units
            .with(&unit, |u| u.is_some_and(|u| u.pass.served))
    {
        units.push(UnitCount {
            class: crate::statement::CLASS_FEE_INDEX,
            source: UNITS_REPORTED,
            amount: 1,
        });
    }
    if let Some(head) = &first {
        for (name, value) in head.fields {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }

        if head.length {
            fields.push(OutField {
                name: arena.span(crate::plane_door::H_CONTENT_LENGTH.as_bytes()),
                value: arena.span(body.len().to_string().as_bytes()),
            });
        }
    }
    for w in writes {
        records.push(RecordWrite {
            kind: kind_index(w.kind),
            op: RECORD_PUT,
            key: arena.span(w.key.as_bytes()),
            value: arena.span(&w.value),
        });
    }

    let audit = if response_only {
        None
    } else {
        first.as_ref().and(
            plane
                .units
                .with(&unit, |u| u.and_then(|u| u.pass.audit.clone())),
        )
    };
    if let Some((resource, applied)) = &audit {
        records.push(crate::statement::audit_write(
            &mut arena, resource, *applied,
        ));
    }

    let lane = audit
        .as_ref()
        .map(|(resource, _)| arena.span(resource.as_bytes()));

    let close = first.as_ref().and_then(|h| h.close).map(|r| {
        (
            r.code,
            arena.span(&r.body),
            arena.span(r.details.as_deref().unwrap_or_default().as_bytes()),
        )
    });
    let short = !(fields.fits() && records.fits() && arena.fits() && units.fits());
    let (fw, fnd) = fields.settle(short);
    let (rw, rnd) = records.settle(short);
    let (aw, and) = arena.settle(short);
    let (uw, und) = units.settle(short);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, und as u32);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.records_written, rw as u32);
    out.set(|o| &o.records_needed, rnd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    if short {
        return Outcome::Failed;
    }
    if audit.is_some() {
        plane.on_unit(unit, |u| {
            u.pass.audit = None;
        });
    }
    if let Some(lane) = lane {
        out.set(|o| &o.lane, lane);
    }
    let n = reply.stream(body);
    let rest = &body[n..];
    out.set(|o| &o.emitted, n as u64);
    out.set(|o| &o.reply_status, status);

    let message = match &first {
        Some(head) => head.message,
        None => plane
            .units
            .with(&unit, |u| u.is_some_and(|u| u.pass.message)),
    };
    if rest.is_empty() {
        let ticket = plane.units.with(&unit, |u| {
            let u = u?;
            u.end();
            plane.unit_ended();
            Some(u.ticket)
        });
        if let Some(ticket) = ticket {
            forget_sizes(&plane.grown, ticket);
        }
        let mut flags = EMIT_DONE;
        if message {
            flags |= busbar_contract::abi::plane::EMIT_MESSAGE_END;
        }
        if let Some((code, message, details)) = close {
            flags |= busbar_contract::abi::plane::EMIT_FINAL_STATUS;
            out.set(|o| &o.final_status, code);
            out.set(|o| &o.final_message, message);
            out.set(|o| &o.final_details, details);
        }
        out.set(|o| &o.flags, flags);
    } else {
        out.set(|o| &o.more, 1);
        plane.on_unit(unit, |u| {
            u.pass.rest =
                retained.map_or_else(|| Remaining::new(rest), |tail| tail.clone().advance(n));
            u.pass.message = message;
        });
    }
    Outcome::Ready
}

/// THE HOST'S SIGNING SERVICE as a card's [`crate::served_card::Signer`]: the key id read with a
/// first signature (the host names it beside every signature), then the signature, each on its own
/// handle of the piece's ticket.
pub(crate) struct HostSigner<'a> {
    pub(crate) services: Option<&'a StaticServices>,
    pub(crate) ticket: Ticket,
    pub(crate) seq: u32,
    key_id: Option<String>,
}

impl HostSigner<'_> {
    pub(crate) fn signed(&mut self, data: &[u8]) -> Option<(String, Vec<u8>)> {
        let services = self.services?;
        let handle = crate::task_door::handle(self.ticket, self.seq);
        self.seq += 1;
        let mut buf = vec![0u8; 1024];
        let mut spans = [ABSENT_SPAN; 2];
        let sig = services.sign(handle, data, &mut buf, &mut spans).ok()?;
        Some((sig.key_id.to_string(), sig.signature.to_vec()))
    }
}

impl HostSigner<'_> {
    /// `entitlement.check` of the unit's caller for `target` (`<scope kind>:<name>`), on the next
    /// handle; a check the host cannot answer is no entitlement.
    fn entitled(&mut self, target: &str) -> bool {
        let Some(services) = self.services else {
            return false;
        };
        let handle = crate::task_door::handle(self.ticket, self.seq);
        self.seq += 1;
        services.entitled(handle, target).unwrap_or(false)
    }
}

impl crate::served_card::Signer for HostSigner<'_> {
    fn kid(&mut self) -> Option<String> {
        self.key_id = self.signed(b"").map(|(kid, _)| kid);
        self.key_id.clone()
    }

    fn sign(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        let (kid, signature) = self.signed(input)?;
        (self.key_id.as_deref() == Some(kid.as_str())).then_some(signature)
    }
}

/// Busbar's extended card for the unit's caller: one skill per fronted agent the caller's own
/// catalogue holds, signed, in a JSON-RPC answer.
fn extended_card(
    plane: &A2aDoor,
    signer: &mut HostSigner<'_>,
    section: Option<&crate::a2a::config::AgentsCfg>,
    generation: u64,
    public_url: &str,
    rpc: Value,
) -> (u32, Vec<u8>) {
    use crate::served_card as served;
    let refusal = |status: u32, code: i64, message: &str| {
        let refusal = crate::agent_arrival::AgentRefusal::new(
            status,
            Some(rpc.clone()),
            code,
            message.to_string(),
        );
        (
            status,
            crate::relay::json_bytes(&refusal.envelope()).unwrap_or_default(),
        )
    };
    let agents = section.map(|s| &s.agents).filter(|a| !a.is_empty());
    let Some(agents) = agents else {
        return refusal(
            400,
            -32007,
            "this deployment fronts no agents, so there is no extended agent card to serve",
        );
    };
    let mut held = Vec::new();
    for (name, def) in agents {
        if !signer.entitled(&format!("{}:{name}", crate::statement::SCOPE)) {
            continue;
        }
        if crate::plane_door::admit_unit(plane, (name, def), None, generation, None).is_err() {
            continue;
        }
        held.push((
            name.as_str(),
            def.url.as_str(),
            plane.cards.at(name, generation),
        ));
    }
    let entitled: Vec<served::EntitledAgent<'_>> = held
        .iter()
        .map(|(agent_id, backend_url, card)| served::EntitledAgent {
            agent_id,
            backend_url,
            card: card.as_deref(),
        })
        .collect();
    match served::extended_card_document(public_url, &entitled)
        .ok_or("extended-card-document")
        .and_then(|card| served::sign_card(&card, signer).map_err(|_| "extended-card-sign"))
    {
        Ok(doc) => {
            let rpc =
                crate::relay::RawBytes::from(crate::relay::json_bytes(&rpc).unwrap_or_default());
            let doc =
                crate::relay::RawBytes::from(crate::relay::json_bytes(&doc).unwrap_or_default());
            (200, busbar_contract::jsonrpc::result_bytes(&rpc, &doc))
        }
        Err(phase) => {
            tracing::warn!(phase, "A2A extended card could not be built or signed");
            refusal(500, -32603, "the extended agent card could not be built")
        }
    }
}

/// An error document of the card routes: `{"error": {"code", "message"}}`.
fn card_error(code: &str, message: &str) -> Vec<u8> {
    crate::relay::json_bytes(&serde_json::json!({ "error": { "code": code, "message": message } }))
        .unwrap_or_default()
}

/// `on_piece` for a card read ([`crate::agent_arrival::CardAsk`]): its first piece is answered
/// whole, the card signed with busbar's key through the host's `sign`.
pub fn card_piece(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: Lent<'_, OnPieceIn>,
    mut out: Out<'_, OnPieceOut>,
    ask: crate::agent_arrival::CardAsk,
) -> Outcome {
    use crate::served_card::{self as served, OWN_CARD_CACHE_CONTROL, OWN_CARD_MEDIA_TYPE};
    let unit = input.unit();
    let Some((rest, answered, agent, section, generation, issued, rpc, composed, framed)) =
        plane.units.with(&unit, |u| {
            u.map(|u| {
                let rpc = match &u.disposition {
                    AgentDisposition::Request { id, .. } => id.clone(),
                    _ => Value::Null,
                };
                (
                    std::mem::take(&mut u.pass.rest),
                    u.pass.answered,
                    u.agent.clone(),
                    u.section.clone(),
                    u.generation,
                    u.pass.issued,
                    rpc,
                    u.envelope.is_some(),
                    u.framed,
                )
            })
        })
    else {
        return Outcome::Refused;
    };
    if !rest.is_empty() {
        return tail_window(plane, unit, &input, &mut out, rest);
    }
    if answered {
        return Outcome::Ready;
    }
    let retry = plane.units.with(&unit, |unit| {
        unit.map(|unit| std::mem::replace(&mut unit.pass.card_started, true))
            .unwrap_or(false)
    });
    let mut signer = HostSigner {
        services: plane.services.as_ref(),
        ticket: instance.ticket(),
        seq: issued,
        key_id: None,
    };
    let public_url = plane.public_url.clone().unwrap_or_default();
    let own_head = [
        (crate::relay::H_CACHE_CONTROL, OWN_CARD_CACHE_CONTROL),
        (crate::relay::H_CONTENT_TYPE, OWN_CARD_MEDIA_TYPE),
    ];
    let (status, body, own) = match ask {
        crate::agent_arrival::CardAsk::Own => {
            match plane
                .card_cache
                .serve(generation, !retry, None, None, &mut signer, || {
                    served::self_card_document(&public_url, Vec::new())
                        .ok_or_else(|| "own-card-public-url".to_string())
                }) {
                Ok(body) => (200, body, true),
                Err(phase) => {
                    tracing::warn!(phase = %phase, "A2A own card could not be built or signed");
                    (
                        500,
                        card_error("internal", "the agent card could not be built"),
                        false,
                    )
                }
            }
        }
        crate::agent_arrival::CardAsk::Extended => {
            let (status, body) = extended_card(
                plane,
                &mut signer,
                section.as_deref(),
                generation,
                &public_url,
                rpc,
            );
            let body = crate::relay::RawBytes::from(body);
            plane.on_unit(unit, |u| {
                u.pass.audit = Some((
                    crate::statement::PLANE_POOL_RESOURCE.to_string(),
                    status == 200,
                ));
            });

            if let Some(rpc) = framed {
                let seq = signer.seq;
                let reply = crate::framed::framed_reply(rpc, status, &body);
                let done = framed_window(plane, unit, &input, &mut out, &reply, &[]);
                if done == Outcome::Ready {
                    plane.on_unit(unit, |u| {
                        u.pass.answered = true;
                        u.pass.issued = seq;
                    });
                }
                return done;
            }
            let body = if composed {
                crate::rest::reframe(status, &body)
            } else {
                body.into_vec()
            };
            (status, body, false)
        }
        crate::agent_arrival::CardAsk::Agent => {
            let agent = agent.unwrap_or_default();
            let def = section.as_ref().and_then(|s| s.agents.get(&agent));
            match (def, plane.cards.at(&agent, generation)) {
                (Some(def), Some(held)) => {
                    match plane.card_cache.serve(
                        generation,
                        !retry,
                        Some(&agent),
                        Some(&held),
                        &mut signer,
                        || {
                            served::rewrite_card(&held, &def.url, &public_url, &agent)
                                .map_err(|_| "agent-card-rewrite".to_string())
                        },
                    ) {
                        Ok(body) => (200, body, false),
                        Err(phase) => {
                            tracing::warn!(
                                phase = %phase,
                                "A2A agent card could not be rewritten or signed"
                            );
                            (
                                502,
                                card_error("upstream_error", "the agent card could not be served"),
                                false,
                            )
                        }
                    }
                }
                _ => (
                    503,
                    card_error(
                        "unavailable",
                        "no agent card has been fetched for this registration yet",
                    ),
                    false,
                ),
            }
        }
    };
    if status >= 500 {
        tracing::warn!(
            phase = "card-build-sign",
            status,
            "A2A card could not be built, signed or served"
        );
    }
    let body = crate::relay::RawBytes::from(body);
    let seq = signer.seq;
    let done = if own {
        window_with(
            plane,
            unit,
            &input,
            &mut out,
            (status, &body),
            &[],
            &own_head,
        )
    } else {
        window(plane, unit, &input, &mut out, (status, &body), &[])
    };
    if done == Outcome::Ready {
        plane.on_unit(unit, |u| {
            u.pass.answered = true;
            u.pass.issued = seq;
        });
    }
    done
}

#[cfg(test)]
#[path = "tests/task_door.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/task_refusal_output_tests.rs"]
mod refusal_output_tests;

#[cfg(test)]
#[path = "tests/record_scratch_custody.rs"]
mod scratch_custody_tests;
