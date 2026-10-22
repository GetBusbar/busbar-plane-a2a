// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A UNIT'S STATE LIVES FOR, AND WHAT A HOP THAT NEVER LEFT REPORTS, driven through the door's
//! own table as the kernel's plane driver drives it (`arrive`, `on_piece`, `refusal`, `serve`,
//! `cancel`), over a host whose services and connector are this file's:
//!
//! * a unit the door has finished with (its answer's last window written, its refusal rendered) no
//!   longer holds a place among the [`MAX_UNITS`] the instance keeps, so it never pushes a live
//!   unit out; a cancelled unit is the first to go when the instance is full;
//! * a hop the kernel refused for the agent's credential before it dialled reports its fee unit at
//!   `0` and no bytes on its refused piece, so the kernel's checkpoint refunds it
//!   (`BUSBAR-1.6.0.md` l.1126: "a hop refused before the socket ledgers nothing");
//! * a READY arrival on a warmed instance allocates an exact, pinned count: the route name an
//!   arrival names is the instance's kept copy, never a fresh heap string (THE DESIGN, the plugin
//!   ABI: "no allocation and no blocking on the hot path"), so the dropped-in twin, built from this
//!   repo's pin, carries the SDK the linked build carries (compiled in or dropped in, "NOTHING
//!   CHANGES about the plugin itself").

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::host::conn::connector::{
    ConnectorSlots, ReplyIn, ReplyPiece, RequestIn, RequestPiece, StreamIn, REPLY_BODY, REPLY_END,
    REPLY_HEAD, SERVICES as CONN_SERVICES,
};
use busbar_contract::abi::host::service::{
    op as service_op, ClockNowIn, HostSlots, ItemSpan, RecordsListIn, ServiceHead, ServiceOut,
    DEST_ALLOWED, DISTRUST_NONE, ENTITLED, SERVICES as HOST_SERVICES, SIGNED_VERIFIED,
    TRUST_DECIDED_SERVING, TRUST_NEW,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, OutHead, Outcome, RawOutcome, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, DriveIn, OpenIn, OpenOut, OpsHead, TickIn, TickOut,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, Ops, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, RecordWrite, RefusalCode, RefusalIn,
    RefusalOut, ServeIn, ServeOut, UnitCount, EMIT_DONE, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    PIECE_HAS_STATUS, PIECE_LAST, PIECE_REFUSED, REFUSAL_KERNEL,
};
use busbar_plane_a2a::agent_door::{self, MAX_UNITS};
use busbar_plane_a2a::door_statement::{
    self, CLASS_BYTES_INDEX, CLASS_FEE_INDEX, DIALECT_DOCUMENT,
};

// ── the allocation count ────────────────────────────────────────────────────────────────────────

thread_local! {
    /// Allocations made by THIS thread since the counter was last read.
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting.
struct Counting;

// SAFETY: every call is forwarded verbatim to the system allocator; the counter is a thread-local
// `Cell` of a plain integer, touched only on the allocating thread, and never reads or writes the
// memory being handed out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// How many allocations `f` made on this thread, and what it returned.
fn allocations_of<R>(f: impl FnOnce() -> R) -> (u64, R) {
    let before = ALLOCS.with(Cell::get);
    let r = f();
    (ALLOCS.with(Cell::get) - before, r)
}

// ── the host's services ─────────────────────────────────────────────────────────────────────────

fn answer(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(outcome),
            value,
            len,
            _reserved: [0; 3],
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        });
    }
    RawOutcome::of(outcome)
}

/// The host's clock: it moves a second on every reading.
static MONO: AtomicU64 = AtomicU64::new(1_000_000_000);

extern "C" fn clock_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `ClockNowIn` whose reading slot it owns.
    let i = unsafe { input.cast::<ClockNowIn>().read() };
    let mono = MONO.fetch_add(1_000_000_000, Ordering::SeqCst);
    // SAFETY: as above.
    unsafe {
        (*i.reading).wall_ns = 1_800_000_000_000_000_000 + mono;
        (*i.reading).mono_ns = mono;
    }
    answer(out, Outcome::Ready, 0, 0)
}

/// EVERY HANDLE THE HOST WAS HANDED, `(ticket slot, ticket generation, seq)`, with the service it
/// was handed to. busbar's host keeps each handle's first answer and hands it back to any later
/// call on that handle, whatever service that call names; a handle handed to two services is one
/// whose second call reads the first's answer.
static HANDLES: Mutex<Vec<Handed>> = Mutex::new(Vec::new());

/// One handle the host was handed, `(ticket slot, ticket generation, seq)`, and its service.
type Handed = ((u32, u32, u32), u32);

fn handles() -> MutexGuard<'static, Vec<Handed>> {
    HANDLES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Note the handle a service's `in` leads with.
fn handed(input: *const c_void) {
    // SAFETY: every service's `in` leads with its head.
    let head = unsafe { input.cast::<ServiceHead>().read() };
    let h = head.handle;
    handles().push(((h.ticket.slot, h.ticket.generation, h.seq), head.op));
}

extern "C" fn entitled(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    handed(input);
    answer(out, Outcome::Ready, ENTITLED, 0)
}

extern "C" fn serves(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, DISTRUST_NONE, 0)
}

/// `trust.verify`: every card's signatures verify against the issuer key the kernel holds.
extern "C" fn verified(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, SIGNED_VERIFIED, 0)
}

/// `trust.sight`: the kernel records the sighting.
extern "C" fn sighted(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, TRUST_NEW, 0)
}

/// `trust.decide`: the operator's approval is the kernel's, and the key serves.
extern "C" fn decided(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, TRUST_DECIDED_SERVING, 0)
}

extern "C" fn judged(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, DEST_ALLOWED, 0)
}

/// THE STORE the host keeps for the plane, across instances: what the plane's answers wrote, as
/// `(kind, key, value)`, the last write of a key standing.
static STORE: Mutex<Vec<(String, String, Vec<u8>)>> = Mutex::new(Vec::new());

fn store() -> MutexGuard<'static, Vec<(String, String, Vec<u8>)>> {
    STORE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `records.list`: every stored record of the kind asked, in key order, one page.
/// While set, `records.list` answers PENDING the first time it is handed a handle and the rows
/// when that handle is issued again (a store read on the host's pool, completed before the replay).
static LIST_PENDS: AtomicBool = AtomicBool::new(false);

extern "C" fn records_list(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    handed(input);
    if LIST_PENDS.load(Ordering::SeqCst) {
        // SAFETY: every service's `in` leads with its head.
        let h = unsafe { input.cast::<ServiceHead>().read() }.handle;
        let at = (h.ticket.slot, h.ticket.generation, h.seq);
        let seen = handles()
            .iter()
            .filter(|(handle, op)| *handle == at && *op == service_op::RECORDS_LIST)
            .count();
        if seen < 2 {
            return answer(out, Outcome::Pending, 0, 0);
        }
    }
    // SAFETY: the SDK hands a `RecordsListIn` over its own text and buffers.
    let i = unsafe { input.cast::<RecordsListIn>().read() };
    // SAFETY: as above.
    let text = |s: AbiStr| unsafe {
        if s.ptr.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(s.ptr, s.len).to_vec()
        }
    };
    let (kind, after) = (text(i.kind), text(i.after));
    let mut rows: Vec<(String, Vec<u8>)> = store()
        .iter()
        .filter(|(k, _, _)| k.as_bytes() == kind.as_slice())
        .map(|(_, key, value)| (key.clone(), value.clone()))
        .collect();
    rows.sort();
    if !after.is_empty() {
        rows.clear();
    }
    // SAFETY: the SDK's buffers of the capacities it states.
    let (buf, spans) = unsafe {
        (
            std::slice::from_raw_parts_mut(i.into.buf, i.into.cap),
            std::slice::from_raw_parts_mut(i.into.spans, i.into.spans_cap),
        )
    };
    let mut at = 0_usize;
    for (n, (key, value)) in rows.iter().enumerate() {
        let span = |at: usize, len: usize| busbar_contract::abi::mechanism::call::Span {
            offset: u32::try_from(at).unwrap(),
            len: u32::try_from(len).unwrap(),
        };
        buf[at..at + key.len()].copy_from_slice(key.as_bytes());
        buf[at + key.len()..at + key.len() + value.len()].copy_from_slice(value);
        spans[n] = ItemSpan {
            key: span(at, key.len()),
            value: span(at + key.len(), value.len()),
        };
        at += key.len() + value.len();
    }
    // SAFETY: the SDK's `out`, live for the call.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(Outcome::Ready),
            len: at as u64,
            items: rows.len() as u64,
            _reserved: [0; 3],
            value: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        });
    }
    RawOutcome::of(Outcome::Ready)
}

static HOST_SLOTS: HostSlots = HostSlots {
    size: std::mem::size_of::<HostSlots>() as u32,
    slots: HOST_SERVICES,
    clock_now: Some(clock_now),
    records_get: None,
    records_list: Some(records_list),
    records_claim: None,
    dest_judge: Some(judged),
    sign: None,
    unit_nest: None,
    work_open: None,
    work_find: None,
    work_settle: None,
    work_resume: None,
    trust_sight: Some(sighted),
    trust_due: None,
    verify_lookup: None,
    verify_store: None,
    entitlement_check: Some(entitled),
    content_scan: None,
    hook_call: None,
    random_fill: None,
    need_admit: None,
    trust_verify: Some(verified),
    records_secret: None,
    disk_append: None,
    snapshot_read: None,
    trust_sight_item: None,
    trust_serves: Some(serves),
    trust_decide: Some(decided),
    trust_state: None,
    session_emit: None,
};

// ── the agent behind the connector: it serves its card to every exchange ───────────────────────

/// The agent's card: unsigned (its registration is `unpinned`), one skill.
const CARD: &[u8] = br#"{"protocolVersion":"0.3.0","name":"vendor","description":"a vendor agent","url":"https://vendor.example/agent","version":"1","capabilities":{},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[{"id":"quote","name":"quote","description":"quotes","tags":["quote"]}]}"#;

/// The agent serves [`long_card`] in place of [`CARD`] while set.
static LONG_CARD: AtomicBool = AtomicBool::new(false);

/// [`CARD`] with a description long enough that the card is past the host's record ceiling
/// ([`busbar_contract::bounded::MAX_RECORD_BYTES`]), as an ordinary card with a few interfaces, a
/// provider and signatures is, and a dozen skills, so the skills an operator approves of it
/// (`id -> digest`) are past the ceiling too.
fn long_card() -> Vec<u8> {
    let description = "a vendor agent ".repeat(48);
    let skills: Vec<String> = (0..12)
        .map(|n| {
            format!(
                r#"{{"id":"quote-{n}","name":"quote {n}","description":"quotes, way {n}","tags":["quote"]}}"#
            )
        })
        .collect();
    String::from_utf8_lossy(CARD)
        .replace("a vendor agent", description.trim_end())
        .replace(
            r#"{"id":"quote","name":"quote","description":"quotes","tags":["quote"]}"#,
            &skills.join(","),
        )
        .into_bytes()
}

/// The card the agent serves now.
fn served_card() -> Vec<u8> {
    if LONG_CARD.load(Ordering::SeqCst) {
        long_card()
    } else {
        CARD.to_vec()
    }
}

/// Each open exchange: how far its reply has been read.
static WIRES: Mutex<Option<HashMap<u64, u8>>> = Mutex::new(None);
static NEXT_WIRE: AtomicU64 = AtomicU64::new(1);

fn wires() -> MutexGuard<'static, Option<HashMap<u64, u8>>> {
    WIRES.lock().unwrap_or_else(PoisonError::into_inner)
}

extern "C" fn establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let id = NEXT_WIRE.fetch_add(1, Ordering::SeqCst);
    wires().get_or_insert_with(HashMap::new).insert(id, 0);
    answer(out, Outcome::Ready, id, 0)
}

extern "C" fn write_request(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `RequestIn` over its own bytes and descriptor.
    let i = unsafe { input.cast::<RequestIn>().read() };
    // SAFETY: as above.
    let _piece = unsafe { i.piece.cast::<RequestPiece>().read() };
    answer(out, Outcome::Ready, 0, i.len as u64)
}

extern "C" fn read_reply(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `ReplyIn` over its own buffer and descriptor slot.
    let i = unsafe { input.cast::<ReplyIn>().read() };
    // SAFETY: as above.
    let buf = unsafe { std::slice::from_raw_parts_mut(i.buf, i.len) };
    let mut held = wires();
    let Some(step) = held.get_or_insert_with(HashMap::new).get_mut(&i.stream) else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    let (piece, n) = match *step {
        0 => {
            let block = b"content-type: application/json\r\n";
            buf[..block.len()].copy_from_slice(block);
            (
                ReplyPiece {
                    kind: REPLY_HEAD,
                    code: 200,
                    fields: busbar_contract::abi::transport::FrameSpan {
                        offset: 0,
                        len: block.len() as u64,
                    },
                    ..ReplyPiece::default()
                },
                block.len(),
            )
        }
        1 => {
            let card = served_card();
            buf[..card.len()].copy_from_slice(&card);
            (
                ReplyPiece {
                    kind: REPLY_BODY,
                    ..ReplyPiece::default()
                },
                card.len(),
            )
        }
        _ => (
            ReplyPiece {
                kind: REPLY_END,
                ..ReplyPiece::default()
            },
            0,
        ),
    };
    *step += 1;
    // SAFETY: the SDK's descriptor slot.
    unsafe { i.piece.write(piece) };
    answer(out, Outcome::Ready, 0, n as u64)
}

extern "C" fn close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `StreamIn`.
    let i = unsafe { input.cast::<StreamIn>().read() };
    if let Some(open) = wires().as_mut() {
        open.remove(&i.stream);
    }
    answer(out, Outcome::Ready, 0, 0)
}

static CONN_SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: CONN_SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: None,
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(close),
    random: None,
    identity: None,
    read_reply: Some(read_reply),
    write_request: Some(write_request),
};

struct Tables(HostTables);
// SAFETY: the tables name only `'static` tables of `extern "C"` functions.
unsafe impl Sync for Tables {}

static TABLES: Tables = Tables(HostTables {
    size: std::mem::size_of::<HostTables>() as u32,
    _reserved: 0,
    ctx: HostCtx::NONE,
    wake: None,
    conns: &CONN_SLOTS,
    io: std::ptr::null(),
    services: &HOST_SLOTS,
});

/// One test at a time: the connector's wires are the process's.
static SERIAL: Mutex<()> = Mutex::new(());

// ── the door, op by op ──────────────────────────────────────────────────────────────────────────

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

fn str_of(s: &[u8]) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn head<T>(op: u32, ticket: Ticket) -> InHead {
    InHead {
        size: std::mem::size_of::<T>() as u32,
        op,
        ticket,
        ..z()
    }
}

fn out_head<T>() -> OutHead {
    OutHead {
        size: std::mem::size_of::<T>() as u32,
        ..z()
    }
}

fn ops() -> &'static Ops {
    // SAFETY: the door is a `'static` table whose ops are the plane kind's.
    unsafe { &*(*agent_door::door()).ops.cast::<Ops>() }
}

fn lifecycle() -> &'static OpsHead {
    &ops().head
}

/// The unit's own ticket, as the kernel hands every one of its pieces and its `cancel`.
fn ticket(unit: u64) -> Ticket {
    Ticket {
        slot: u32::try_from(unit).unwrap(),
        generation: 1,
    }
}

/// One fronted agent, `unpinned`.
const SECTION: &[u8] =
    br#"{"vendor": {"url": "https://vendor.example/agent", "pin": {"mechanism": "unpinned"}}}"#;

/// The same agent, its card verified against an out-of-band issuer key (the kernel's
/// `trust.verify` here verifies every card), so `connect` sights a fingerprint `approve` can name.
const SIGNED_SECTION: &[u8] =
    br#"{"vendor": {"url": "https://vendor.example/agent", "pin": {"mechanism": "jws_issuer_key", "key": "issuer"}}}"#;

/// The caller's opaque reference, as the kernel lends it.
const ALICE: &[u8] = b"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// The extended-card read addressed to the agent: a task-less relayed hop.
const CARD_READ: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"agent/getAuthenticatedExtendedCard"}"#;

/// One opened instance of the door.
struct Door {
    instance: *mut c_void,
}

/// What one `on_piece` answered.
#[derive(Debug, Default)]
struct Answered {
    outcome: Option<Outcome>,
    more: u32,
    flags: u32,
    verb: String,
    emitted: Vec<u8>,
    units: Vec<(u32, u64)>,
}

/// One piece as the kernel pushes it.
#[derive(Clone, Copy)]
struct Given<'a> {
    from: u32,
    flags: u32,
    attempt: u32,
    member: &'a [u8],
    reason: u32,
    status: u32,
    bytes: &'a [u8],
}

impl Given<'_> {
    /// The caller's whole body.
    fn caller(bytes: &[u8]) -> Given<'_> {
        Given {
            from: FROM_CALLER,
            flags: PIECE_LAST,
            attempt: 0,
            member: b"",
            reason: 0,
            status: 0,
            bytes,
        }
    }

    /// A re-call after `more = 1`: no bytes, no flags, no attempt.
    fn more() -> Given<'static> {
        Given {
            from: FROM_CALLER,
            flags: 0,
            attempt: 0,
            member: b"",
            reason: 0,
            status: 0,
            bytes: b"",
        }
    }

    /// The kernel's ATTEMPT naming `member`.
    fn attempt(member: &[u8]) -> Given<'_> {
        Given {
            from: FROM_KERNEL,
            flags: 0,
            attempt: 1,
            member,
            reason: 0,
            status: 0,
            bytes: b"",
        }
    }

    /// The refused piece for `reason`, before the unit is refused.
    fn refused(reason: RefusalCode) -> Given<'static> {
        Given {
            from: FROM_KERNEL,
            flags: PIECE_REFUSED | PIECE_LAST,
            attempt: 0,
            member: b"",
            reason: reason.code(),
            status: 0,
            bytes: b"",
        }
    }

    /// The far end's whole answer, `bytes` at HTTP `status`, in one last piece.
    fn far_end(status: u32, bytes: &[u8]) -> Given<'_> {
        Given {
            from: FROM_FAR_END,
            flags: PIECE_HAS_STATUS | PIECE_LAST,
            attempt: 0,
            member: b"",
            reason: 0,
            status,
            bytes,
        }
    }
}

/// The route index of `(verb, target)` in the door's table, the claim an arrival carries.
fn claim(verb: &str, target: &str) -> u32 {
    let i = door_statement::ROUTES
        .iter()
        .position(|r| r.verb == verb && r.target == target)
        .unwrap_or_else(|| panic!("the door routes {verb} {target}"));
    u32::try_from(i).unwrap()
}

fn open() -> Door {
    open_with(SECTION)
}

/// The door opened over `section`.
fn open_with(section: &'static [u8]) -> Door {
    let mut i: PlaneOpenIn = z();
    i.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: &TABLES.0,
        settings: octets(section),
        generation: 1,
        ..z()
    };
    i.public_url = str_of(b"https://gw.example");
    let mut o: PlaneOpenOut = z();
    o.open = OpenOut {
        head: out_head::<PlaneOpenOut>(),
        ..z()
    };
    let f = lifecycle().open.expect("the door opens");
    let ret = f(
        std::ptr::null_mut(),
        std::ptr::from_ref(&i).cast(),
        std::ptr::from_mut(&mut o).cast(),
    );
    assert_eq!(ret.outcome(), Outcome::Ready, "the door opens");
    Door {
        instance: o.open.instance,
    }
}

impl Door {
    /// `arrive` of `body` at `target` on the route `(verb, route)`: its outcome and refusal status.
    fn arrive(
        &self,
        unit: u64,
        (verb, route): (&str, &str),
        target: &str,
        body: &[u8],
    ) -> (Outcome, u32) {
        let mut i: ArriveIn = z();
        i.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
        i.unit = unit;
        i.claim = claim(verb, route);
        i.target = str_of(target.as_bytes());
        i.method = str_of(verb.as_bytes());
        i.body = octets(body);
        let mut units = [z::<UnitCount>(); 8];
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: ArriveOut = z();
        o.head = out_head::<ArriveOut>();
        let f = ops().arrive.expect("arrive");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        (ret.outcome(), o.refusal_status)
    }

    /// Busbar's own card read, on the open line.
    fn arrive_own_card(&self, unit: u64) {
        let route = ("GET", busbar_plane_a2a::WELL_KNOWN_CARD_PATH);
        let (outcome, _) = self.arrive(unit, route, busbar_plane_a2a::WELL_KNOWN_CARD_PATH, b"");
        assert_eq!(outcome, Outcome::Ready, "busbar's own card read arrives");
    }

    /// One `on_piece` of `unit`, its reply buffer `reply_cap` bytes.
    fn piece(&self, unit: u64, given: Given<'_>, reply_cap: usize) -> Answered {
        let mut reply = vec![0_u8; reply_cap];
        let mut fields = [z::<OutField>(); 16];
        let mut arena = vec![0_u8; 1 << 14];
        let mut records = [z::<RecordWrite>(); 16];
        let mut units = [z::<UnitCount>(); 8];
        let mut i: OnPieceIn = z();
        i.head = head::<OnPieceIn>(slot::ON_PIECE, ticket(unit));
        i.unit = unit;
        i.from = given.from;
        i.flags = given.flags;
        i.bytes = octets(given.bytes);
        i.attempt_no = given.attempt;
        i.member = str_of(given.member);
        i.caller_ref = str_of(ALICE);
        i.reason = given.reason;
        i.status_code = given.status;
        (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: OnPieceOut = z();
        o.head = out_head::<OnPieceOut>();
        let f = ops().on_piece.expect("on_piece");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        let at = |s: busbar_contract::abi::mechanism::call::Span| {
            let from = s.offset as usize;
            String::from_utf8_lossy(&arena[from..from + s.len as usize]).into_owned()
        };
        Answered {
            outcome: Some(ret.outcome()),
            more: o.more,
            flags: o.flags,
            verb: if o.verb.len == 0 {
                String::new()
            } else {
                at(o.verb)
            },
            emitted: reply[..usize::try_from(o.emitted).unwrap().min(reply_cap)].to_vec(),
            units: units[..(o.units_written as usize).min(units.len())]
                .iter()
                .map(|u| (u.class, u.amount))
                .collect(),
        }
    }

    /// `refusal` of `unit` for `reason` at `status`: its outcome, status and body.
    fn refusal(&self, unit: u64, reason: RefusalCode, status: u32) -> (Outcome, u32, String) {
        let text = b"refused";
        let mut reply = vec![0_u8; 4096];
        let mut fields = [z::<OutField>(); 8];
        let mut arena = vec![0_u8; 1024];
        let mut records = [z::<RecordWrite>(); 4];
        let mut i: RefusalIn = z();
        i.head = head::<RefusalIn>(slot::REFUSAL, Ticket::NONE);
        (i.cause, i.status, i.dialect) = (REFUSAL_KERNEL, status, DIALECT_DOCUMENT);
        i.reason = reason.code();
        i.unit = unit;
        i.text = str_of(text);
        (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
        let mut o: RefusalOut = z();
        o.head = out_head::<RefusalOut>();
        let f = ops().refusal.expect("refusal");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        let body = String::from_utf8_lossy(&reply[..o.reply_written as usize]).into_owned();
        (ret.outcome(), o.status, body)
    }

    /// `serve` of the trust verb `connect` for `agent`: its outcome, status and body.
    fn connect(&self, agent: &str) -> (Outcome, u32, String) {
        self.verb(0, &format!("/agents/{agent}/connect"), &[], b"")
    }

    /// `serve` of the trust verb `approve` for `agent`, naming `fingerprint`: its outcome, status
    /// and body.
    fn approve(&self, agent: &str, fingerprint: &str) -> (Outcome, u32, String) {
        let body = format!(r#"{{"fingerprint": "{fingerprint}"}}"#);
        let fields = [Field {
            name: str_of(b"content-type"),
            value: str_of(b"application/json"),
        }];
        self.verb(
            1,
            &format!("/agents/{agent}/approve"),
            &fields,
            body.as_bytes(),
        )
    }

    /// `serve` of the admin verb at `route` on `target`, with the head `fields` and `body`: its
    /// outcome, status and body; the answer's record writes are written to the store as busbar
    /// dev's kernel writes them (`plane_driver/serve.rs` `write_served_records`): in the plane's
    /// order, and a record past [`busbar_contract::bounded::MAX_RECORD_BYTES`] is a write the
    /// store refuses, so the verb answers `500` and no later write of the answer is made.
    fn verb(
        &self,
        route: u32,
        target: &str,
        fields: &[Field],
        body: &[u8],
    ) -> (Outcome, u32, String) {
        let mut reply = vec![0_u8; 1 << 14];
        let mut out_fields = [z::<OutField>(); 8];
        let mut arena = vec![0_u8; 1 << 14];
        let mut records = [z::<RecordWrite>(); 64];
        let mut i: ServeIn = z();
        i.head = head::<ServeIn>(slot::SERVE, ticket(1 << 30));
        i.route = route;
        i.target = str_of(target.as_bytes());
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
        i.body = octets(body);
        (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (i.fields_buf, i.fields_cap) = (out_fields.as_mut_ptr(), out_fields.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
        let mut o: ServeOut = z();
        o.head = out_head::<ServeOut>();
        let f = ops().serve.expect("serve");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        // The kernel writes the answer's record writes to the store, in order.
        let held = busbar_plane_a2a::records::HELD_KINDS;
        let mut status = o.status;
        for w in &records[..(o.records_written as usize).min(records.len())] {
            let at = |s: busbar_contract::abi::mechanism::call::Span| {
                arena[s.offset as usize..(s.offset + s.len) as usize].to_vec()
            };
            let value = at(w.value);
            if value.len() > busbar_contract::bounded::MAX_RECORD_BYTES {
                status = 500;
                break;
            }
            let kind = held[w.kind as usize].to_string();
            let key = String::from_utf8(at(w.key)).unwrap();
            let mut stored = store();
            stored.retain(|(k, id, _)| !(*k == kind && *id == key));
            if !value.is_empty() {
                stored.push((kind, key, value));
            }
        }
        let body = String::from_utf8_lossy(&reply[..o.reply_written as usize]).into_owned();
        (ret.outcome(), status, body)
    }

    /// The kernel's `tick` of the instance, on its driver ticket: when it wants the next.
    fn tick(&self) -> (Outcome, u64) {
        let i = TickIn {
            head: head::<TickIn>(life::TICK, ticket(1 << 29)),
            now_ns: 5_000_000_000,
        };
        let mut o: TickOut = z();
        o.head = out_head::<TickOut>();
        let f = lifecycle().tick.expect("tick");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        (ret.outcome(), o.next_tick_ns)
    }

    /// The `drive` a wake of the instance's driver ticket runs, on the ticket its `tick` ran on.
    fn drive(&self) -> Outcome {
        let mut sessions = [0_u64; 4];
        let i = PlaneDriveIn {
            drive: DriveIn {
                head: head::<PlaneDriveIn>(life::DRIVE, ticket(1 << 29)),
                driver: ticket(1 << 29),
            },
            sessions_buf: sessions.as_mut_ptr(),
            sessions_cap: sessions.len(),
        };
        let mut o: PlaneDriveOut = z();
        o.head = out_head::<PlaneDriveOut>();
        let f = lifecycle().drive.expect("drive");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        ret.outcome()
    }

    /// The kernel's `cancel` of `unit`'s ticket.
    fn cancel(&self, unit: u64) -> Outcome {
        let mut i: PlaneCancelIn = z();
        i.cancel = CancelIn {
            head: head::<PlaneCancelIn>(life::CANCEL, Ticket::NONE),
            ticket: ticket(unit),
        };
        let mut o: PlaneCancelOut = z();
        o.cancel.head = out_head::<PlaneCancelOut>();
        let f = lifecycle().cancel.expect("cancel");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        ret.outcome()
    }

    /// Busbar's own card read on `unit`, its first window written into a reply buffer too small
    /// for the card: the unit is LIVE, part way through its answer.
    fn begin_own_card(&self, unit: u64) {
        self.arrive_own_card(unit);
        let first = self.piece(unit, Given::caller(b""), 8);
        assert_eq!(
            first.outcome,
            Some(Outcome::Ready),
            "the card's first window"
        );
        assert_eq!(first.more, 1, "the card does not fit 8 bytes: more is owed");
    }

    /// Whether `unit`, begun by [`Self::begin_own_card`], is still held: its next window is
    /// answered from what it owes, never refused.
    fn still_answers(&self, unit: u64) -> bool {
        self.piece(unit, Given::more(), 8).outcome == Some(Outcome::Ready)
    }
}

// ── (A2) a finished unit holds no place ─────────────────────────────────────────────────────────

/// A UNIT WHOSE ANSWER IS WHOLLY WRITTEN IS FORGOTTEN: busbar's own card read, answered to its last
/// window, no longer holds one of the instance's [`MAX_UNITS`] places. RED before the fix: only a
/// finished relayed hop was ever removed, so [`MAX_UNITS`] finished card reads filled the instance
/// and the next arrival evicted the oldest LIVE unit, whose next window was then refused.
#[test]
fn units_whose_answer_is_written_never_push_a_live_unit_out() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    door.begin_own_card(1);
    for unit in 2..=(MAX_UNITS as u64 + 1) {
        door.arrive_own_card(unit);
        let whole = door.piece(unit, Given::caller(b""), 1 << 16);
        assert_eq!(whole.outcome, Some(Outcome::Ready), "unit {unit}");
        assert_ne!(whole.flags & EMIT_DONE, 0, "unit {unit}'s answer is whole");
    }
    assert!(
        door.still_answers(1),
        "a live unit was evicted by {MAX_UNITS} card reads the door had already finished"
    );
}

/// A UNIT WHOSE REFUSAL IS RENDERED IS FORGOTTEN: the kernel refused it after `arrive` (a spent
/// budget, a request limit, a hook's veto) and `refusal` rendered its answer, its last call. RED
/// before the fix: a refused unit was never removed.
#[test]
fn units_whose_refusal_is_rendered_never_push_a_live_unit_out() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    door.begin_own_card(1);
    for unit in 2..=(MAX_UNITS as u64 + 1) {
        door.arrive_own_card(unit);
        let (outcome, _, body) = door.refusal(unit, RefusalCode::RateLimited, 429);
        assert_eq!(outcome, Outcome::Ready, "unit {unit}: {body}");
    }
    assert!(
        door.still_answers(1),
        "a live unit was evicted by {MAX_UNITS} units whose refusal the door had already rendered"
    );
}

/// A CANCELLED UNIT GOES FIRST: when the instance is full, the oldest cancelled unit makes room,
/// never a live one. RED before the fix: `cancel` left the unit as it was and the instance evicted
/// the oldest unit whatever it was.
#[test]
fn cancelled_units_make_room_before_a_live_unit_does() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    door.begin_own_card(1);
    for unit in 2..=(MAX_UNITS as u64 + 1) {
        door.begin_own_card(unit);
        assert_eq!(door.cancel(unit), Outcome::Ready, "unit {unit}'s cancel");
    }
    assert!(
        door.still_answers(1),
        "a live unit was evicted while {MAX_UNITS} cancelled units were held"
    );
}

// ── (A1) a hop the kernel never dialled ─────────────────────────────────────────────────────────

/// A HOP REFUSED FOR THE AGENT'S CREDENTIAL BEFORE IT WAS DIALLED LEDGERS NOTHING
/// (`BUSBAR-1.6.0.md` l.1126: "a hop refused before the socket ledgers nothing"; the fee class's
/// own statement in `door_statement::BILLABLE_CLASSES`: "a unit refused before that has its
/// `per_request` refunded"). The ATTEMPT left the plane (its fee unit `1`) and the caller's body went
/// toward the agent, then the kernel's send found the agent's credential unavailable and dialled nothing: the
/// refused piece reports every class at `0`, which the kernel's checkpoint takes as the unit's last
/// counts, so its end refunds the fee and ledgers no bytes. RED before the fix: the refused piece
/// reported no units at all, the kernel kept the ATTEMPT's counts, and the fee stood.
#[test]
fn a_hop_refused_for_its_credential_before_the_dial_reports_its_fee_and_bytes_at_zero() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` holds the agent's card: {body}"
    );
    let unit = 7;
    let route = ("POST", "/a2a/agents/{agent_id}");
    let (arrived, refused) = door.arrive(unit, route, "/a2a/agents/vendor", CARD_READ);
    assert_eq!(
        (arrived, refused),
        (Outcome::Ready, 0),
        "the card read is admitted"
    );

    let attempt = door.piece(unit, Given::attempt(b"vendor"), 1 << 16);
    assert_eq!(attempt.outcome, Some(Outcome::Ready), "{attempt:?}");
    assert!(
        !attempt.verb.is_empty(),
        "the ATTEMPT names its request: {attempt:?}"
    );
    assert!(
        attempt.units.contains(&(CLASS_FEE_INDEX, 1)),
        "the hop left the plane: its fee unit is reported: {attempt:?}"
    );
    let body = door.piece(unit, Given::caller(CARD_READ), 1 << 16);
    assert_eq!(body.outcome, Some(Outcome::Ready), "{body:?}");
    assert_eq!(
        body.emitted, CARD_READ,
        "the caller's body goes to the agent: {body:?}"
    );
    assert!(
        body.units.contains(&(CLASS_FEE_INDEX, 1)),
        "the hop is still served: {body:?}"
    );

    let refused = door.piece(
        unit,
        Given::refused(RefusalCode::CredentialUnavailable),
        1 << 16,
    );
    assert_eq!(refused.outcome, Some(Outcome::Ready), "{refused:?}");
    assert!(
        refused.units.contains(&(CLASS_FEE_INDEX, 0)),
        "the refused piece reports the fee unit at 0, so the kernel refunds it: {refused:?}"
    );
    assert!(
        refused.units.iter().all(|&(_, amount)| amount == 0),
        "nothing went to the agent, so no class is counted: {refused:?}"
    );
    assert!(
        refused.emitted.is_empty(),
        "the refused piece answers nothing"
    );
}

/// AN EMPTY ENVELOPE FROM A REACHED AGENT IS CHARGED AS THE HOP THAT REACHED IT (coordinator
/// ruling, parity principle: "charge exactly what v1.5.5 charged for it"). v1.5.5 had no A2A path
/// to charge one: its tree holds no a2a crate or module (`git ls-tree -r --name-only v1.5.5`
/// names no path matching `a2a`), no JSON-RPC reader (`git grep -il jsonrpc v1.5.5` matches no
/// file), and names A2A only as work to come (v1.5.5 `qa/segments.toml:61` "a2a -> 1.5.6" and
/// `:169-172`, the `a2a` segment `status = "reserved"`; `crates/busbar/src/config/named_map.rs:16`,
/// "`agents:` (1.5.6 A2A)"). So the charge stands as this plane makes it, pinned here: the far
/// end answered a JSON-RPC envelope with neither `result` nor `error`, the caller is answered the
/// hop's refusal (`a2a.hop.reply_not_json`), and the unit reports the fee unit at `1` (the hop
/// left the plane for its agent) and the bytes the hop moved both ways (the caller's request and
/// the far end's envelope).
#[test]
fn an_empty_envelope_from_a_reached_agent_reports_the_hops_fee_and_bytes() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` holds the agent's card: {body}"
    );
    let unit = 9;
    let route = ("POST", "/a2a/agents/{agent_id}");
    let (arrived, refused) = door.arrive(unit, route, "/a2a/agents/vendor", CARD_READ);
    assert_eq!(
        (arrived, refused),
        (Outcome::Ready, 0),
        "the card read is admitted"
    );
    let attempt = door.piece(unit, Given::attempt(b"vendor"), 1 << 16);
    assert_eq!(attempt.outcome, Some(Outcome::Ready), "{attempt:?}");
    let sent = door.piece(unit, Given::caller(CARD_READ), 1 << 16);
    assert_eq!(
        sent.emitted, CARD_READ,
        "the caller's body goes to the agent: {sent:?}"
    );

    let empty: &[u8] = br#"{"jsonrpc":"2.0","id":1}"#;
    let answered = door.piece(unit, Given::far_end(200, empty), 1 << 16);
    assert_eq!(answered.outcome, Some(Outcome::Ready), "{answered:?}");
    assert!(
        String::from_utf8_lossy(&answered.emitted).contains("a2a.hop.reply_not_json"),
        "the caller is answered the hop's refusal, never the empty envelope: {answered:?}"
    );
    assert!(
        answered.units.contains(&(CLASS_FEE_INDEX, 1)),
        "the hop reached its agent: its fee unit stands: {answered:?}"
    );
    assert!(
        answered
            .units
            .contains(&(CLASS_BYTES_INDEX, (CARD_READ.len() + empty.len()) as u64)),
        "the bytes the hop moved both ways are counted: {answered:?}"
    );
}

// ── (B2) an approved agent's card outlives the instance ─────────────────────────────────────────

/// A CARD PAST THE HOST'S RECORD CEILING IS HELD, NEVER WRITTEN AS A RECORD THE HOST CANNOT KEEP
/// (`busbar_contract::bounded::MAX_RECORD_BYTES`, 512 bytes: busbar dev's store refuses a longer
/// record, and the kernel answers the whole `serve` `500` for a record write it cannot make). An
/// operator's `connect` to an agent whose card is longer answers its view, holds the card for the
/// relay, and carries no record past the ceiling (since the split records, its `card` records are
/// the card's parts and their head, each within the ceiling). RED before the fix: the answer carried the whole card as
/// its `card` record (the busbar root cells `root::serve::plane_a2a_door::*` over the gRPC agent,
/// whose signed card with its interface is past 512 bytes, at busbar-plane-a2a bcc9cff241 against
/// busbar dev: every `connect` answered `500` `internal error`).
#[test]
fn a_card_past_the_hosts_record_ceiling_is_held_and_never_written_as_a_record() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    assert!(
        long_card().len() > busbar_contract::bounded::MAX_RECORD_BYTES,
        "the long card is past the ceiling"
    );
    struct Plain;
    impl Drop for Plain {
        fn drop(&mut self) {
            LONG_CARD.store(false, Ordering::SeqCst);
        }
    }
    let _plain = Plain;
    LONG_CARD.store(true, Ordering::SeqCst);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` answers its view: {body}"
    );
    let too_long: Vec<(String, String, usize)> = store()
        .iter()
        .filter(|(_, _, value)| value.len() > busbar_contract::bounded::MAX_RECORD_BYTES)
        .map(|(kind, key, value)| (kind.clone(), key.clone(), value.len()))
        .collect();
    assert!(
        too_long.is_empty(),
        "the answer wrote records past the host's ceiling: {too_long:?}"
    );
    let route = ("POST", "/a2a/agents/{agent_id}");
    assert_eq!(
        door.arrive(12, route, "/a2a/agents/vendor", CARD_READ),
        (Outcome::Ready, 0),
        "the card the look verified is held for the relay"
    );
}

/// THE CARD WARM ON A UNIT'S TICKET NEVER SHARES A HANDLE WITH THE UNIT'S OWN CALLS
/// (`abi::mechanism::ticket`: a handle's `seq` counts the services one ticket issued). An instance
/// busbar never readied or ticked (busbar dev drives no plane `ready`) warms its held cards on the
/// first unit's first piece, on that unit's ticket; the unit's admission then asks
/// `entitlement.check` of its caller. busbar's host answers a handle once and hands that answer to
/// every later call on it, so the check on a handle the warm's `records.list` was answered on reads
/// a listing, never `ENTITLED`, and the caller is refused `401` `this key is not live`. RED before
/// the fix: the warm counted from `seq` 0 and the unit's pieces counted from 0 again, so the
/// listing of the `card` kind and the admission's check shared `seq` 0 (the busbar root cells
/// `root::serve::plane_a2a_door::*`, at busbar-plane-a2a 7eeb7d8220 against busbar dev: every
/// first served hop of an instance refused `401` `this key is not live`).
#[test]
fn the_card_warm_on_a_units_ticket_never_shares_a_handle_with_the_units_own_calls() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` holds the agent's card: {body}"
    );
    handles().clear();
    let unit = 11;
    let route = ("POST", "/a2a/agents/{agent_id}");
    assert_eq!(
        door.arrive(unit, route, "/a2a/agents/vendor", CARD_READ),
        (Outcome::Ready, 0),
        "the card read is admitted"
    );
    let attempt = door.piece(unit, Given::attempt(b"vendor"), 1 << 16);
    assert_eq!(attempt.outcome, Some(Outcome::Ready), "{attempt:?}");
    assert!(
        attempt.units.contains(&(CLASS_FEE_INDEX, 1)),
        "the caller stands and the hop left the plane: {attempt:?}"
    );

    let own = ticket(unit);
    let handed: Vec<Handed> = handles()
        .iter()
        .copied()
        .filter(|((slot, generation, _), _)| (*slot, *generation) == (own.slot, own.generation))
        .collect();
    assert!(
        handed.iter().any(|(_, op)| *op == service_op::RECORDS_LIST),
        "the unit's first piece warmed the held cards on its own ticket: {handed:?}"
    );
    assert!(
        handed
            .iter()
            .any(|(_, op)| *op == service_op::ENTITLEMENT_CHECK),
        "the unit's admission asked the caller's entitlement: {handed:?}"
    );
    for (handle, op) in &handed {
        assert!(
            handed.iter().all(|(h, o)| h != handle || o == op),
            "handle {handle:?} was handed to two services, so the second reads the first's \
             answer: {handed:?}"
        );
    }
}

/// A RESTART SERVES THE AGENTS APPROVED BEFORE IT (ARCHITECT ruling B2, as amended: the `connect`
/// and `approve` answers write the agent's `card` host record, `BUSBAR-1.6.0.md` l.290 "record
/// writes ride `on_piece`'s answer", and the first tick after `open` warms the held cards from
/// those records). An operator's `connect` held the agent's card; the instance is opened again over
/// the same store and ticked once, and a card read addressed to the agent is admitted, never refused
/// for a card the instance does not hold. RED before the fix: the cards lived only in the first
/// instance's memory, so the new one refused every agent until the operator looked again.
#[test]
fn a_restarted_instance_serves_an_agent_from_its_recorded_card() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    let before = open();
    let (outcome, status, body) = before.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` holds the agent's card: {body}"
    );
    let route = ("POST", "/a2a/agents/{agent_id}");
    assert_eq!(
        before.arrive(7, route, "/a2a/agents/vendor", CARD_READ),
        (Outcome::Ready, 0),
        "the instance that looked serves the agent"
    );

    let after = open();
    let (ticked, _) = after.tick();
    assert_eq!(ticked, Outcome::Ready, "the first tick after `open`");
    assert_eq!(
        after.arrive(8, route, "/a2a/agents/vendor", CARD_READ),
        (Outcome::Ready, 0),
        "the instance opened again serves the agent from its recorded card"
    );
}

/// A TICK WHOSE CARD WARM PENDS ENDS PENDING, AND THE `drive` ITS WAKE RUNS LANDS THE WARM
/// (`abi::mechanism::lifecycle`: a tick's PENDING answer ends it, what pended inside it goes on
/// through `drive`, and the next tick's start forgets the cycle's answers). An instance opened again
/// over a store whose `card` listing the host answers on its pool: the first tick's listing pends,
/// so the tick answers PENDING, and the drives its completions run replay the listing on the same
/// handles until the cards are held; an arrival addressed to the agent is then admitted. RED before
/// the fix: the tick answered READY with the listing still in flight and asked for another tick a
/// second later, whose start forgot the listing, so on busbar dev the warm landed through no tick,
/// each completion ran another tick, and the driver ticket's schedule served the warm in place of
/// the deliveries (the busbar root cells `root::serve::plane_a2a_door::*` that wait for a delivery,
/// at busbar-plane-a2a bcc9cff241 against busbar dev: no delivery within the window).
#[test]
fn a_tick_whose_card_warm_pends_ends_pending_and_its_drive_lands_the_warm() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    handles().clear();
    let before = open();
    let (outcome, status, body) = before.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` holds the agent's card: {body}"
    );
    struct Prompt;
    impl Drop for Prompt {
        fn drop(&mut self) {
            LIST_PENDS.store(false, Ordering::SeqCst);
        }
    }
    let _prompt = Prompt;
    LIST_PENDS.store(true, Ordering::SeqCst);
    let after = open();
    let (ticked, _) = after.tick();
    assert_eq!(
        ticked,
        Outcome::Pending,
        "the first tick's warm is in flight: the tick ends PENDING and goes on through `drive`"
    );
    let driven: Vec<Outcome> = (0..4).map(|_| after.drive()).collect();
    assert!(
        driven.contains(&Outcome::Ready),
        "the drives land the warm: {driven:?}"
    );
    let route = ("POST", "/a2a/agents/{agent_id}");
    assert_eq!(
        after.arrive(13, route, "/a2a/agents/vendor", CARD_READ),
        (Outcome::Ready, 0),
        "the instance opened again serves the agent from the card its drive warmed"
    );
}

/// A RESTART KEEPS THE SKILLS THE OPERATOR APPROVED (`BUSBAR-1.6.0.md` l.345-346: "what must
/// survive a restart goes to its records through the store kind", F15 l.4633). The approval is
/// the kernel's trust book's, which outlives the instance; the skills of the card it adopted are
/// the plane's, held for the trust view's drift lists (coordinator ruling Q2). An operator
/// connects, approves the fingerprint seen, and the view shows no drift; the instance is opened
/// again over the same store and ticked once, and a `connect` to the unchanged card still shows
/// none. RED before the fix: the approved skills lived only in the first instance's memory, so the
/// instance opened again reported every skill of the approved, unchanged card as `added`.
#[test]
fn a_restarted_instance_keeps_the_skills_its_operator_approved() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    let view = |answered: (Outcome, u32, String)| {
        let (outcome, status, body) = answered;
        assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
        serde_json::from_str::<serde_json::Value>(&body).expect("a trust view")
    };
    let before = open_with(SIGNED_SECTION);
    let preview = view(before.connect("vendor"));
    assert_eq!(
        preview["added"],
        serde_json::json!(["quote"]),
        "nothing approved yet, so the card's skill is added: {preview}"
    );
    let fingerprint = preview["fingerprint"]
        .as_str()
        .unwrap_or_else(|| panic!("connect reported no fingerprint: {preview}"))
        .to_string();
    let approved = view(before.approve("vendor", &fingerprint));
    assert_eq!(approved["state"], "approved", "{approved}");
    assert_eq!(
        approved["added"],
        serde_json::json!([]),
        "the approved card shows no drift: {approved}"
    );

    let after = open_with(SIGNED_SECTION);
    let (ticked, _) = after.tick();
    assert_eq!(ticked, Outcome::Ready, "the first tick after `open`");
    let again = view(after.connect("vendor"));
    assert_eq!(
        (&again["added"], &again["changed"], &again["removed"]),
        (
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([])
        ),
        "the instance opened again still holds the skills the operator approved, so the \
         unchanged card shows no drift: {again}"
    );
}

/// A RESTART SERVES A CARD PAST THE HOST'S RECORD CEILING AND KEEPS ITS APPROVED SKILLS
/// (ARCHITECT ruling B2, as amended; `BUSBAR-1.6.0.md` l.345-346: "what must survive a restart goes
/// to its records through the store kind"): a host record is at most
/// [`busbar_contract::bounded::MAX_RECORD_BYTES`] by design, and a card, or the skills approved of
/// it, of any size outlives the instance all the same. An operator connects to an agent whose card
/// is several records long and whose approved skills are past the ceiling too, and approves it;
/// the instance is opened again over the same store and ticked once: a card read addressed to the
/// agent is admitted from the recorded card, and a `connect` to the unchanged card shows no drift.
/// RED before the fix (busbar-plane-a2a 1bba8a8): a card or an approval past the ceiling was held
/// in plane memory only, so the instance opened again refused the agent for a card it does not
/// hold, and judged its approved card against nothing.
#[test]
fn a_restarted_instance_serves_a_card_past_the_record_ceiling_and_keeps_its_approved_skills() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    struct Plain;
    impl Drop for Plain {
        fn drop(&mut self) {
            LONG_CARD.store(false, Ordering::SeqCst);
        }
    }
    let _plain = Plain;
    LONG_CARD.store(true, Ordering::SeqCst);
    let ceiling = busbar_contract::bounded::MAX_RECORD_BYTES;
    assert!(
        long_card().len() > 2 * ceiling,
        "the card is several records long"
    );
    let view = |answered: (Outcome, u32, String)| {
        let (outcome, status, body) = answered;
        assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
        serde_json::from_str::<serde_json::Value>(&body).expect("a trust view")
    };
    let before = open_with(SIGNED_SECTION);
    let preview = view(before.connect("vendor"));
    let fingerprint = preview["fingerprint"]
        .as_str()
        .unwrap_or_else(|| panic!("connect reported no fingerprint: {preview}"))
        .to_string();
    let approved = view(before.approve("vendor", &fingerprint));
    assert_eq!(approved["state"], "approved", "{approved}");
    assert_eq!(
        approved["added"],
        serde_json::json!([]),
        "the approved card shows no drift: {approved}"
    );
    assert_eq!(
        preview["added"].as_array().map(Vec::len),
        Some(12),
        "every skill of the card was added before the approval: {preview}"
    );
    assert!(
        store().iter().all(|(_, _, value)| value.len() <= ceiling),
        "no record past the host's ceiling was written"
    );

    let after = open_with(SIGNED_SECTION);
    let (ticked, _) = after.tick();
    assert_eq!(ticked, Outcome::Ready, "the first tick after `open`");
    let route = ("POST", "/a2a/agents/{agent_id}");
    assert_eq!(
        after.arrive(14, route, "/a2a/agents/vendor", CARD_READ),
        (Outcome::Ready, 0),
        "the instance opened again serves the agent from its recorded card"
    );
    let again = view(after.connect("vendor"));
    assert_eq!(
        (&again["added"], &again["changed"], &again["removed"]),
        (
            &serde_json::json!([]),
            &serde_json::json!([]),
            &serde_json::json!([])
        ),
        "the instance opened again still holds the skills the operator approved, so the \
         unchanged card shows no drift: {again}"
    );
}

/// A KERNEL REFUSAL WITH NO UNIT ANSWERS THE BASELINE BYTES: the kernel refused the request before
/// any unit was made (no credential, a body over the cap), so the plane renders the bytes v1.5.5
/// answered on that route, a JSON-RPC error with no id, at the kernel's status. RED before the fix:
/// the door rendered its own words for the kernel's text.
#[test]
fn a_kernel_refusal_with_no_unit_answers_the_baseline_json_rpc_bytes() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    for (reason, status, body) in [
        (
            RefusalCode::Unauthenticated,
            401,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"authentication failed"}}"#,
        ),
        (
            RefusalCode::BodyTooLarge,
            413,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"request body exceeds the maximum allowed size"}}"#,
        ),
    ] {
        let (outcome, answered, rendered) = door.refusal(0, reason, status);
        assert_eq!(outcome, Outcome::Ready, "{reason:?}: {rendered}");
        assert_eq!(rendered, body, "{reason:?}: the v1.5.5 bytes");
        assert!(
            answered == 0 || answered == status,
            "{reason:?}: the kernel's status {status} stands, the door answered {answered}"
        );
    }
}

// ── the READY path the dropped-in twin carries ──────────────────────────────────────────────────

/// What one addressed READY arrival allocates on a warmed instance (the agent's card held, its
/// route entry already named by earlier arrivals). The bound is exact (the plane's own unit state,
/// task rows and relay set-up; the route name costs none): a change that moves it moves this
/// constant in the same commit, with the reason.
const READY_ARRIVAL_ALLOCATIONS: u64 = 64;

/// A WARMED READY ARRIVAL NAMES ITS ROUTE WITHOUT THE HEAP (THE DESIGN, the plugin ABI: "no
/// allocation and no blocking on the hot path"; compiled in or dropped in, "NOTHING CHANGES about
/// the plugin itself"). An arrival addressed to a held agent routes `ROUTE_DIRECT` to it through the SDK's
/// `Out::route`; once the instance has named that entry, naming it again is a load of the kept
/// copy. RED at a busbar-contract pin whose SDK kept a fresh `String` for every route name (under
/// the instance-wide mutex): every arrival paid that allocation, so the count sat above the pin,
/// and the dropped-in twin built from this repo's pin was a slower plane than the linked one.
#[test]
fn a_warmed_ready_arrival_allocates_its_pinned_count() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` holds the agent's card: {body}"
    );
    let route = ("POST", "/a2a/agents/{agent_id}");
    for unit in 20..24 {
        assert_eq!(
            door.arrive(unit, route, "/a2a/agents/vendor", CARD_READ),
            (Outcome::Ready, 0),
            "warming arrival {unit}"
        );
    }
    let (allocations, arrived) =
        allocations_of(|| door.arrive(24, route, "/a2a/agents/vendor", CARD_READ));
    assert_eq!(arrived, (Outcome::Ready, 0), "the measured arrival");
    assert_eq!(
        allocations, READY_ARRIVAL_ALLOCATIONS,
        "a warmed READY arrival allocated {allocations}, pinned {READY_ARRIVAL_ALLOCATIONS}"
    );
}
