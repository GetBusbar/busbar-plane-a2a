// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A UNIT'S STATE LIVES FOR, AND WHAT A HOP THAT NEVER LEFT REPORTS, driven through the door's

#[path = "support/door_facts.rs"]
#[allow(dead_code)]
mod door_facts;

#[path = "support/task_door_lifecycle_cases.rs"]
mod task_door_lifecycle_cases;

#[path = "support/unreadable_header_cases.rs"]
mod unreadable_header_cases;

#[path = "support/local_admission_cases.rs"]
mod local_admission_cases;

#[path = "support/raw_custody_cases.rs"]
mod raw_custody_cases;

use std::cell::RefCell;
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
    RefusalOut, ServeIn, ServeOut, UnitCount, CANCEL_ABORTED, CANCEL_OK_PARTIAL, EMIT_DONE,
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PIECE_REFUSED,
    REFUSAL_KERNEL,
};
use door_facts::{CLASS_BYTES_INDEX, CLASS_FEE_INDEX, DIALECT_DOCUMENT, MAX_UNITS};

use busbar_test_kit::alloc_counter::allocations_with as allocations_of;

#[global_allocator]
static A: busbar_test_kit::alloc_counter::Counting =
    busbar_test_kit::alloc_counter::Counting::new();

fn answer(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(outcome),
            value,
            len,
            exited: 0,
            _reserved: [0; 2],
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr::ABSENT,
        });
    }
    RawOutcome::of(outcome)
}

/// The host's clock: it moves a second on every reading.
static MONO: AtomicU64 = AtomicU64::new(1_000_000_000);

extern "C" fn clock_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `ClockNowIn` whose reading slot it owns.
    let i = unsafe { input.cast::<ClockNowIn>().read() };
    if verification_custody_cases::clock_refuses(i.head.handle.ticket) {
        return answer(out, Outcome::Failed, 0, 0);
    }
    let mono = MONO.fetch_add(1_000_000_000, Ordering::SeqCst);
    // SAFETY: as above.
    unsafe {
        (*i.reading).wall_ns = 1_800_000_000_000_000_000 + mono;
        (*i.reading).mono_ns = mono;
    }
    answer(out, Outcome::Ready, 0, 0)
}

/// EVERY HANDLE THE HOST WAS HANDED, `(ticket slot, ticket generation, seq)`, with the service it
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
    card_generation_custody_cases::refresh_during_admission();
    verification_custody_cases::during_verdict();
    answer(out, Outcome::Ready, DISTRUST_NONE, 0)
}

/// `trust.verify`: every card's signatures verify against the issuer key the kernel holds.
extern "C" fn verified(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, SIGNED_VERIFIED, 0)
}

/// `trust.sight`: the kernel records the sighting.
extern "C" fn sighted(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    handed(input);
    if verification_custody_cases::pend_sighting(input) {
        return answer(out, Outcome::Pending, 0, 0);
    }
    if card_generation_custody_cases::pend_sighting() {
        return answer(out, Outcome::Pending, 0, 0);
    }
    if card_generation_custody_cases::fail_sighting() {
        return answer(out, Outcome::Failed, 0, 0);
    }
    answer(out, Outcome::Ready, TRUST_NEW, 0)
}

/// `trust.decide`: the operator's approval is the kernel's, and the key serves.
extern "C" fn decided(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    card_generation_custody_cases::note_decision();
    answer(out, Outcome::Ready, TRUST_DECIDED_SERVING, 0)
}

extern "C" fn judged(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if card_generation_custody_cases::pend_judgement() {
        return answer(out, Outcome::Pending, 0, 0);
    }
    if let Some(result) = relay_within_cases::scripted_judgement(input, out) {
        return result;
    }
    answer(out, Outcome::Ready, DEST_ALLOWED, 0)
}

/// THE STORE the host keeps for the plane, across instances: what the plane's answers wrote, as
static STORE: Mutex<Vec<(String, String, Vec<u8>)>> = Mutex::new(Vec::new());

fn store() -> MutexGuard<'static, Vec<(String, String, Vec<u8>)>> {
    STORE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `records.list`: kind/prefix matching records in key order, strictly after the cursor.
static LIST_PENDS: AtomicBool = AtomicBool::new(false);

/// While set, `records.list` is refused (the store is unavailable): FAILED, nothing listed.
static LIST_REFUSES: AtomicBool = AtomicBool::new(false);

extern "C" fn records_list(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    handed(input);
    if LIST_REFUSES.load(Ordering::SeqCst) {
        return answer(out, Outcome::Failed, 0, 0);
    }
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
        if s.is_absent() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(s.ptr(), s.len()).to_vec()
        }
    };
    let (kind, prefix, after) = (text(i.kind), text(i.prefix), text(i.after));
    let mut rows: Vec<(String, Vec<u8>)> = store()
        .iter()
        .filter(|(k, key, _)| {
            k.as_bytes() == kind.as_slice()
                && key.as_bytes().starts_with(&prefix)
                && (after.is_empty() || key.as_bytes() > after.as_slice())
        })
        .map(|(_, key, value)| (key.clone(), value.clone()))
        .collect();
    rows.sort();
    let limit = if i.limit == 0 {
        busbar_contract::abi::host::service::MAX_SPANS as usize
    } else {
        i.limit as usize
    };
    rows.truncate(limit);
    let needed: usize = rows
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    if needed > i.into.cap || rows.len() > i.into.spans_cap {
        let result = answer(out, Outcome::Failed, 0, 0);
        // SAFETY: the caller owns this live output; no payload or spans were written.
        unsafe {
            (*out).needed_bytes = needed as u64;
            (*out).needed_items = rows.len() as u64;
        }
        return result;
    }
    // SAFETY: the SDK's buffers of the capacities it states.
    let (buf, spans) = unsafe {
        (
            if i.into.cap == 0 {
                &mut []
            } else {
                std::slice::from_raw_parts_mut(i.into.buf, i.into.cap)
            },
            if i.into.spans_cap == 0 {
                &mut []
            } else {
                std::slice::from_raw_parts_mut(i.into.spans, i.into.spans_cap)
            },
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
            exited: 0,
            _reserved: [0; 2],
            value: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr::ABSENT,
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
    auth_call: None,
    unit_hand_in: None,
    unit_refuse: None,
    ticket_mint: None,
    ticket_take: None,
};

/// The agent's card: unsigned (its registration is `unpinned`), one skill.
const CARD: &[u8] = br#"{"protocolVersion":"0.3.0","name":"vendor","description":"a vendor agent","url":"https://vendor.example/agent","version":"1","capabilities":{},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[{"id":"quote","name":"quote","description":"quotes","tags":["quote"]}]}"#;

/// The agent serves [`long_card`] in place of [`CARD`] while set.
static LONG_CARD: AtomicBool = AtomicBool::new(false);

/// [`CARD`] with a description long enough that the card is past the host's record ceiling
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
    wake: Some(verification_custody_cases::wake),
    conns: &CONN_SLOTS,
    io: std::ptr::null(),
    services: &HOST_SLOTS,
});

/// One test at a time: the connector's wires are the process's.
static SERIAL: Mutex<()> = Mutex::new(());

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

fn str_of(s: &[u8]) -> AbiStr {
    // SAFETY: `s` is a fixture or a buffer that outlives the call its `in` is lent to.
    unsafe { AbiStr::from_raw_parts(s.as_ptr(), s.len()) }
}

fn octets(b: &[u8]) -> Blob {
    // SAFETY: as `str_of`.
    unsafe { Blob::from_raw_parts(b.as_ptr(), b.len(), BLOB_OCTETS, 0) }
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
    unsafe { &*(*busbar_plane_a2a::door()).ops().cast::<Ops>() }
}

/// The host reads actual ABI diagnostics before another crossing retires their reply.
fn forward_diagnostics(head: &OutHead) {
    use busbar_contract::abi::mechanism::call::{
        DIAG_LOG, DIAG_LOG_DROPPED, SEVERITY_DEBUG, SEVERITY_ERROR, SEVERITY_INFO, SEVERITY_TRACE,
        SEVERITY_WARN,
    };
    if head.envelope.diags_len == 0 {
        return;
    }
    assert!(!head.envelope.diags.is_null());
    // SAFETY: the linked macro's Statement and id list are static; this call's diagnostic
    // array and strings remain live until the next crossing, which has not started.
    let statement = unsafe { &*(*busbar_plane_a2a::door()).statement() };
    let diags = unsafe { std::slice::from_raw_parts(head.envelope.diags, head.envelope.diags_len) };
    let copy = |text: AbiStr| {
        if text.is_absent() {
            String::new()
        } else {
            // SAFETY: the text belongs to the static Statement or this live diagnostic reply.
            String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(text.ptr(), text.len()) })
                .into_owned()
        }
    };
    for diag in diags {
        let id = if matches!(diag.id_idx, DIAG_LOG | DIAG_LOG_DROPPED) {
            String::from("log")
        } else {
            assert!((diag.id_idx as usize) < statement.diag_ids_len);
            assert!(!statement.diag_ids.is_null());
            // SAFETY: the index is within the linked Statement's live static id list.
            copy(unsafe { statement.diag_ids.add(diag.id_idx as usize).read() })
        };
        let text = copy(diag.text);
        match diag.severity {
            SEVERITY_ERROR => tracing::error!(diagnostic = %id, message = %text),
            SEVERITY_WARN => tracing::warn!(diagnostic = %id, message = %text),
            SEVERITY_INFO => tracing::info!(diagnostic = %id, message = %text),
            SEVERITY_DEBUG => tracing::debug!(diagnostic = %id, message = %text),
            SEVERITY_TRACE => tracing::trace!(diagnostic = %id, message = %text),
            _ => panic!("the linked door returned an unknown diagnostic severity"),
        }
    }
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
    owned: bool,
    pending: RefCell<HashMap<Ticket, Box<PieceFrame>>>,
}

/// One existing caller's continuation: every original frame and lent allocation stays put.
struct PieceFrame {
    input: Box<OnPieceIn>,
    output: Box<OnPieceOut>,
    member: zeroize::Zeroizing<Vec<u8>>,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    reply: zeroize::Zeroizing<Vec<u8>>,
    fields: Vec<OutField>,
    arena: zeroize::Zeroizing<Vec<u8>>,
    records: Vec<RecordWrite>,
    units: Vec<UnitCount>,
}

impl PieceFrame {
    fn new(unit: u64, given: Given<'_>, reply_cap: usize, fields_cap: usize) -> Box<Self> {
        let mut frame = Box::new(Self {
            input: Box::new(z()),
            output: Box::new(z()),
            member: zeroize::Zeroizing::new(given.member.to_vec()),
            bytes: zeroize::Zeroizing::new(given.bytes.to_vec()),
            reply: zeroize::Zeroizing::new(vec![0; reply_cap]),
            fields: vec![z(); fields_cap],
            arena: zeroize::Zeroizing::new(vec![0; 1 << 14]),
            records: vec![z(); 16],
            units: vec![z(); 8],
        });
        let i = &mut frame.input;
        i.head = head::<OnPieceIn>(slot::ON_PIECE, ticket(unit));
        i.unit = unit;
        (i.from, i.flags, i.attempt_no) = (given.from, given.flags, given.attempt);
        (i.reason, i.status_code) = (given.reason, given.status);
        i.member = str_of(&frame.member);
        i.bytes = octets(&frame.bytes);
        i.caller_ref = str_of(ALICE);
        (i.reply_buf, i.reply_cap) = (frame.reply.as_mut_ptr(), frame.reply.len());
        (i.fields_buf, i.fields_cap) = (frame.fields.as_mut_ptr(), frame.fields.len());
        (i.arena_buf, i.arena_cap) = (frame.arena.as_mut_ptr(), frame.arena.len());
        (i.records_buf, i.records_cap) = (frame.records.as_mut_ptr(), frame.records.len());
        (i.units_buf, i.units_cap) = (frame.units.as_mut_ptr(), frame.units.len());
        frame
    }

    fn check_resume(&self, unit: u64, given: Given<'_>, reply_cap: usize, fields_cap: usize) {
        let i = &self.input;
        assert!(
            i.head.ticket == ticket(unit)
                && i.unit == unit
                && i.from == given.from
                && i.flags == given.flags
                && i.attempt_no == given.attempt
                && i.reason == given.reason
                && i.status_code == given.status
                && self.member.as_slice() == given.member
                && self.bytes.as_slice() == given.bytes,
            "a pending piece must resume its exact logical input"
        );
        assert_eq!(
            (self.reply.len(), self.fields.len()),
            (reply_cap, fields_cap),
            "pending output loans cannot be replaced; only terminal SHORT permits fresh buffers"
        );
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        if !self.owned {
            assert!(
                self.pending.get_mut().is_empty(),
                "a borrowed door owns no continuations"
            );
            return;
        }
        let input = head::<InHead>(life::CLOSE, Ticket::NONE);
        let mut output = out_head::<OutHead>();
        let outcome = lifecycle().close.map_or(Outcome::Fault, |close| {
            // SAFETY: this owner closes exactly its OPEN's still-live instance, synchronously,
            // with every retained pending frame and allocation alive until CLOSE returns.
            unsafe {
                close(
                    self.instance,
                    std::ptr::from_ref(&input).cast(),
                    std::ptr::from_mut(&mut output).cast(),
                )
            }
            .outcome()
        });
        if outcome != Outcome::Ready {
            // A broken CLOSE is a test failure, but cannot authorize freeing unresolved loans.
            std::mem::forget(std::mem::take(self.pending.get_mut()));
        }
        assert_eq!(
            outcome,
            Outcome::Ready,
            "the owned door closes before its loans retire"
        );
    }
}

/// What one `on_piece` answered.
#[derive(Debug, Default)]
struct Answered {
    outcome: Option<Outcome>,
    more: u32,
    flags: u32,
    verb: String,
    target: String,
    fields: Vec<(String, String)>,
    fields_needed: u32,
    arena_needed: u64,
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
    door_facts::claim(verb, target)
}

fn open() -> Door {
    open_with(SECTION)
}

/// The door opened over `section`.
fn open_with(section: &[u8]) -> Door {
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
    // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
    // states and live for the call.
    #[allow(unused_unsafe)]
    let ret = unsafe {
        f(
            std::ptr::null_mut(),
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    assert_eq!(ret.outcome(), Outcome::Ready, "the door opens");
    Door::new(o.open.instance)
}

impl Door {
    fn new(instance: *mut c_void) -> Self {
        Self {
            instance,
            owned: true,
            pending: RefCell::new(HashMap::new()),
        }
    }

    fn borrowed(instance: *mut c_void) -> Self {
        Self {
            instance,
            owned: false,
            pending: RefCell::new(HashMap::new()),
        }
    }

    /// `arrive` of `body` at `target` on the route `(verb, route)`: its outcome and refusal status.
    fn arrive(
        &self,
        unit: u64,
        (verb, route): (&str, &str),
        target: &str,
        body: &[u8],
    ) -> (Outcome, u32) {
        assert!(
            !self.pending.borrow().contains_key(&ticket(unit)),
            "a fresh arrival cannot replace a pending piece on the same full ticket"
        );
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
        // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
        // states and live for the call.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        (ret.outcome(), o.refusal_status)
    }

    /// Busbar's own card read, on the open line.
    fn arrive_own_card(&self, unit: u64) {
        assert!(
            self.arrives_own_card(unit),
            "busbar's own card read arrives"
        );
    }

    /// Whether busbar's own card read under `unit` is admitted (`arrive` answers READY; a full
    fn arrives_own_card(&self, unit: u64) -> bool {
        let route = ("GET", door_facts::WELL_KNOWN_CARD_PATH);
        let (outcome, _) = self.arrive(unit, route, door_facts::WELL_KNOWN_CARD_PATH, b"");
        outcome == Outcome::Ready
    }

    /// One `on_piece` of `unit`, its reply buffer `reply_cap` bytes.
    fn piece(&self, unit: u64, given: Given<'_>, reply_cap: usize) -> Answered {
        self.piece_with_fields(unit, given, reply_cap, 16)
    }

    fn piece_with_fields(
        &self,
        unit: u64,
        given: Given<'_>,
        reply_cap: usize,
        fields_cap: usize,
    ) -> Answered {
        assert!(self.owned, "a borrowed door cannot own a pending piece");
        let mut frame = {
            let mut pending = self.pending.borrow_mut();
            if let Some(frame) = pending.get(&ticket(unit)) {
                // Validate while custody is still in the Door: a rejected re-entry keeps it.
                frame.check_resume(unit, given, reply_cap, fields_cap);
            }
            match pending.remove(&ticket(unit)) {
                Some(mut frame) => {
                    frame.input.head.flags |= busbar_contract::abi::mechanism::call::FLAG_RESUME;
                    frame
                }
                None => PieceFrame::new(unit, given, reply_cap, fields_cap),
            }
        };
        *frame.output = z();
        frame.output.head = out_head::<OnPieceOut>();
        let f = ops().on_piece.expect("on_piece");
        // SAFETY: the Door retains these exact boxed frames and every original lent allocation
        // through PENDING. A resume changes only FLAG_RESUME; terminal SHORT ends this loan.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&*frame.input).cast(),
                std::ptr::from_mut(&mut *frame.output).cast(),
            )
        };
        let outcome = ret.outcome();
        if outcome == Outcome::Pending {
            // Retain custody before reading or allocating any ordinary reply payload.
            self.pending.borrow_mut().insert(ticket(unit), frame);
            return Answered {
                outcome: Some(outcome),
                ..Answered::default()
            };
        }
        if outcome != Outcome::Ready {
            return Answered {
                outcome: Some(outcome),
                fields_needed: if outcome == Outcome::Failed {
                    frame.output.fields_needed
                } else {
                    0
                },
                arena_needed: if outcome == Outcome::Failed {
                    frame.output.arena_needed
                } else {
                    0
                },
                ..Answered::default()
            };
        }
        let (o, reply, fields, arena, units) = (
            &frame.output,
            &frame.reply,
            &frame.fields,
            &frame.arena,
            &frame.units,
        );
        let at = |s: busbar_contract::abi::mechanism::call::Span| {
            let from = s.offset as usize;
            String::from_utf8_lossy(&arena[from..from + s.len as usize]).into_owned()
        };
        Answered {
            outcome: Some(outcome),
            more: o.more,
            flags: o.flags,
            verb: if o.verb.len == 0 {
                String::new()
            } else {
                at(o.verb)
            },
            target: if o.target.len == 0 {
                String::new()
            } else {
                at(o.target)
            },
            fields: fields[..(o.fields_written as usize).min(fields.len())]
                .iter()
                .map(|field| (at(field.name), at(field.value)))
                .collect(),
            fields_needed: o.fields_needed,
            arena_needed: o.arena_needed,
            emitted: reply[..usize::try_from(o.emitted).unwrap().min(reply_cap)].to_vec(),
            units: units[..(o.units_written as usize).min(units.len())]
                .iter()
                .map(|u| (u.class, u.amount))
                .collect(),
        }
    }

    /// `refusal` of `unit` for `reason` at `status`: its outcome, status and body.
    fn refusal(&self, unit: u64, reason: RefusalCode, status: u32) -> (Outcome, u32, String) {
        let (outcome, answered, body, _) = self.refusal_writing(unit, reason, status);
        (outcome, answered, body)
    }

    /// [`Self::refusal`], and how many record writes (its audit row among them) it answered.
    fn refusal_writing(
        &self,
        unit: u64,
        reason: RefusalCode,
        status: u32,
    ) -> (Outcome, u32, String, u32) {
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
        // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
        // states and live for the call.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        let body = String::from_utf8_lossy(&reply[..o.reply_written as usize]).into_owned();
        (ret.outcome(), o.status, body, o.records_written)
    }

    /// `serve` of the trust verb `connect` for `agent`: its outcome, status and body.
    fn connect(&self, agent: &str) -> (Outcome, u32, String) {
        self.verb(0, &format!("/agents/{agent}/connect"), &[], b"")
    }

    /// `serve` of the trust verb `approve` for `agent`, naming `fingerprint`: its outcome, status
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
    fn verb(
        &self,
        route: u32,
        target: &str,
        fields: &[Field],
        body: &[u8],
    ) -> (Outcome, u32, String) {
        let (outcome, status, body, _) = self.verb_audited(route, target, fields, body);
        (outcome, status, body)
    }

    /// [`Self::verb`], and the `AUDIT_*` row the answer asks the kernel to audit it with.
    fn verb_audited(
        &self,
        route: u32,
        target: &str,
        fields: &[Field],
        body: &[u8],
    ) -> (Outcome, u32, String, u32) {
        self.verb_audited_flags(route, target, fields, body, 0)
    }

    fn verb_audited_flags(
        &self,
        route: u32,
        target: &str,
        fields: &[Field],
        body: &[u8],
        flags: u32,
    ) -> (Outcome, u32, String, u32) {
        let mut reply = vec![0_u8; 1 << 14];
        let mut out_fields = [z::<OutField>(); 8];
        let mut arena = vec![0_u8; 1 << 14];
        let mut records = [z::<RecordWrite>(); 64];
        let mut i: ServeIn = z();
        i.head = head::<ServeIn>(slot::SERVE, ticket(1 << 30));
        i.head.flags = flags;
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
        // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
        // states and live for the call.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };

        forward_diagnostics(&o.head);
        let held = door_facts::HELD_KINDS;
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
        (ret.outcome(), status, body, o.audit)
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
        // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
        // states and live for the call.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        forward_diagnostics(&o.head);
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
        // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
        // states and live for the call.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
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
        // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
        // states and live for the call.
        #[allow(unused_unsafe)]
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        let outcome = ret.outcome();
        if outcome == Outcome::Ready {
            self.pending.borrow_mut().remove(&ticket(unit));
        }
        outcome
    }

    /// The host's own cancel of `unit`, naming it by the key `arrive` kept it under as well as by
    fn cancel_unit(&self, unit: u64) -> Outcome {
        let mut i: PlaneCancelIn = z();
        i.cancel = CancelIn {
            head: head::<PlaneCancelIn>(life::CANCEL, Ticket::NONE),
            ticket: ticket(unit),
        };
        i.unit = unit;
        let mut o: PlaneCancelOut = z();
        o.cancel.head = out_head::<PlaneCancelOut>();
        let f = lifecycle().cancel.expect("cancel");
        // SAFETY: this live Door owns the instance of this lifecycle table. The complete
        // PlaneCancelIn/Out frames stay live for the synchronous call; no buffers are lent.
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        let outcome = ret.outcome();
        if outcome == Outcome::Ready {
            self.pending.borrow_mut().remove(&ticket(unit));
        }
        outcome
    }

    /// The host's own cancel of `unit` (by its key and its ticket): the disposition the door
    fn cancel_disposition(&self, unit: u64) -> u32 {
        let mut i: PlaneCancelIn = z();
        i.cancel = CancelIn {
            head: head::<PlaneCancelIn>(life::CANCEL, Ticket::NONE),
            ticket: ticket(unit),
        };
        i.unit = unit;
        let mut o: PlaneCancelOut = z();
        o.cancel.head = out_head::<PlaneCancelOut>();
        let f = lifecycle().cancel.expect("cancel");
        // SAFETY: this live Door owns the instance of this lifecycle table. The complete
        // PlaneCancelIn/Out frames stay live for the synchronous call; no buffers are lent.
        let ret = unsafe {
            f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        if ret.outcome() == Outcome::Ready {
            self.pending.borrow_mut().remove(&ticket(unit));
        }
        assert_eq!(ret.outcome(), Outcome::Ready);
        o.cancel.disposition
    }

    /// Busbar's own card read on `unit`, its first window written into a reply buffer too small
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
    fn still_answers(&self, unit: u64) -> bool {
        self.piece(unit, Given::more(), 8).outcome == Some(Outcome::Ready)
    }
}

#[path = "support/relay_within_cases.rs"]
mod relay_within_cases;

#[path = "support/card_generation_custody_cases.rs"]
mod card_generation_custody_cases;

#[path = "support/verification_custody_cases.rs"]
mod verification_custody_cases;

/// A UNIT WHOSE ANSWER IS WHOLLY WRITTEN IS FORGOTTEN: busbar's own card read, answered to its last
#[test]
fn units_whose_answer_is_written_never_push_a_live_unit_out() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    door.begin_own_card(1);
    for unit in 2..=(MAX_UNITS as u64 + 1) {
        assert!(
            door.arrives_own_card(unit),
            "unit {unit} was refused: the card reads the door had already finished still held \
             their places"
        );
        let whole = door.piece(unit, Given::caller(b""), 1 << 16);
        assert_eq!(whole.outcome, Some(Outcome::Ready), "unit {unit}");
        assert_ne!(whole.flags & EMIT_DONE, 0, "unit {unit}'s answer is whole");
    }
    assert!(
        door.still_answers(1),
        "the live unit 1 was dropped to make room for {MAX_UNITS} finished card reads"
    );
}

/// A UNIT WHOSE REFUSAL IS RENDERED IS FORGOTTEN: the kernel refused it after `arrive` (a spent
#[test]
fn units_whose_refusal_is_rendered_never_push_a_live_unit_out() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    door.begin_own_card(1);
    for unit in 2..=(MAX_UNITS as u64 + 1) {
        assert!(
            door.arrives_own_card(unit),
            "unit {unit} was refused: the units whose refusal the door had rendered were not \
             forgotten"
        );
        let (outcome, _, body) = door.refusal(unit, RefusalCode::RateLimited, 429);
        assert_eq!(outcome, Outcome::Ready, "unit {unit}: {body}");
    }
    assert!(
        door.still_answers(1),
        "the live unit 1 was dropped to make room for {MAX_UNITS} units whose refusal was rendered"
    );
}

/// A CANCELLED UNIT GOES FIRST: when the instance is full, the cancelled units make room, never a
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
        "the live unit 1 was dropped to make room while {MAX_UNITS} cancelled units were held"
    );
}

/// An instance at live-unit capacity refuses the next arrival without evicting active units.
#[test]
fn an_instance_full_of_live_units_refuses_the_next_arrival_and_evicts_none() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    door.begin_own_card(1);
    for unit in 2..=(MAX_UNITS as u64) {
        door.arrive_own_card(unit);
    }
    let route = ("GET", door_facts::WELL_KNOWN_CARD_PATH);
    let next = MAX_UNITS as u64 + 1;
    assert_eq!(
        door.arrive(next, route, door_facts::WELL_KNOWN_CARD_PATH, b""),
        (Outcome::Refused, 429),
        "the arrival past {MAX_UNITS} live units is refused"
    );
    assert!(
        door.still_answers(1),
        "the live unit 1 was dropped to make room for a refused arrival"
    );
}

/// A UNIT CANCELLED BEFORE ITS FIRST PIECE IS OVER: the host's cancel names it by the key `arrive`
#[test]
fn a_unit_cancelled_before_its_first_piece_makes_room() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    door.begin_own_card(1);
    for unit in 2..=(MAX_UNITS as u64) {
        door.arrive_own_card(unit);
        assert_eq!(
            door.cancel_unit(unit),
            Outcome::Ready,
            "unit {unit}'s cancel"
        );
    }
    assert!(
        door.arrives_own_card(MAX_UNITS as u64 + 1),
        "the arrival past {MAX_UNITS} units was refused: the units cancelled before their first \
         piece are still live"
    );
    assert!(
        door.still_answers(1),
        "the live unit 1 was dropped to make room while {MAX_UNITS} units cancelled before their \
         first piece were held"
    );
}

/// A FINISHED HOP'S UNIT IS STILL READ BY A REFUSAL OF ITS ANSWER: the hop's last piece wrote the
#[test]
fn a_refusal_after_a_finished_hop_still_reads_its_unit() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` holds the agent's card: {body}"
    );
    let unit = 10;
    let route = ("POST", "/a2a/agents/{agent_id}");
    assert_eq!(
        door.arrive(unit, route, "/a2a/agents/vendor", CARD_READ),
        (Outcome::Ready, 0),
        "the card read is admitted"
    );
    let attempt = door.piece(unit, Given::attempt(b"vendor"), 1 << 16);
    assert_eq!(attempt.outcome, Some(Outcome::Ready), "{attempt:?}");
    let sent = door.piece(unit, Given::caller(CARD_READ), 1 << 16);
    assert_eq!(sent.outcome, Some(Outcome::Ready), "{sent:?}");
    let reply = reported_fixture_cases::card_answer();
    let answered = door.piece(unit, Given::far_end(200, &reply), 1 << 16);
    assert_eq!(answered.outcome, Some(Outcome::Ready), "{answered:?}");
    assert_ne!(
        answered.flags & EMIT_DONE,
        0,
        "the hop's answer is written whole: {answered:?}"
    );

    let (refused, _, body, writes) = door.refusal_writing(unit, RefusalCode::HookVeto, 403);
    assert_eq!(refused, Outcome::Ready, "{body}");
    assert_eq!(
        writes, 1,
        "the refusal read the finished hop's unit and wrote its audit row: {body}"
    );
}

/// A CANCEL SAYS HOW FAR THE HOP GOT (owner billing rule R21: the ledger records what the dialect
#[test]
fn a_cancel_after_the_agent_answered_is_partial() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
    let route = ("POST", "/a2a/agents/{agent_id}");
    let dialled = |unit: u64| {
        assert_eq!(
            door.arrive(unit, route, "/a2a/agents/vendor", CARD_READ),
            (Outcome::Ready, 0)
        );
        let attempt = door.piece(unit, Given::attempt(b"vendor"), 1 << 16);
        assert_eq!(attempt.outcome, Some(Outcome::Ready), "{attempt:?}");
        let sent = door.piece(unit, Given::caller(CARD_READ), 1 << 16);
        assert_eq!(sent.outcome, Some(Outcome::Ready), "{sent:?}");
    };
    dialled(20);
    assert_eq!(
        door.cancel_disposition(20),
        CANCEL_ABORTED,
        "cut before the agent answered: aborted"
    );
    dialled(21);
    let reply = reported_fixture_cases::card_answer();
    let answered = door.piece(21, Given::far_end(200, &reply), 1 << 16);
    assert_eq!(answered.outcome, Some(Outcome::Ready), "{answered:?}");
    assert_eq!(
        door.cancel_disposition(21),
        CANCEL_OK_PARTIAL,
        "cut after the agent answered: partial"
    );
}

/// A HOP REFUSED FOR THE AGENT'S CREDENTIAL BEFORE IT WAS DIALLED LEDGERS NOTHING
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

/// A CARD PAST THE HOST'S RECORD CEILING IS HELD, NEVER WRITTEN AS A RECORD THE HOST CANNOT KEEP
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

/// A restarted instance serves agents from the approved cards it previously recorded.
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

/// A restart preserves the skills approved by the operator.
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

/// A CARD LISTING THE HOST REFUSED IS LISTED AGAIN: the cards are warmed only once both their
#[test]
fn a_card_listing_the_host_refused_is_listed_again() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    let before = open();
    let (outcome, status, body) = before.connect("vendor");
    assert_eq!(
        (outcome, status),
        (Outcome::Ready, 200),
        "`connect` holds the agent's card: {body}"
    );
    struct Available;
    impl Drop for Available {
        fn drop(&mut self) {
            LIST_REFUSES.store(false, Ordering::SeqCst);
        }
    }
    let _available = Available;
    LIST_REFUSES.store(true, Ordering::SeqCst);
    let after = open();
    let (ticked, _) = after.tick();
    assert_eq!(ticked, Outcome::Ready, "a refused listing ends the tick");
    LIST_REFUSES.store(false, Ordering::SeqCst);

    for n in 0..2 {
        let (ticked, _) = after.tick();
        assert_eq!(ticked, Outcome::Ready, "tick {n} after the refused one");
    }
    let route = ("POST", "/a2a/agents/{agent_id}");
    assert_eq!(
        after.arrive(14, route, "/a2a/agents/vendor", CARD_READ),
        (Outcome::Ready, 0),
        "the instance warmed the agent's card once the store listed it"
    );
}

/// What one addressed READY arrival allocates on a warmed instance (the agent's card held, its
const READY_ARRIVAL_ALLOCATIONS: u64 = 56;

/// A warmed ready arrival matches its pinned allocation count.
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

/// EVERY REFUSED TRUST VERB IS AUDITED AS REJECTED (docs/a2a.md: both verbs audited, refusals as
#[test]
fn a_malformed_or_unknown_approval_is_audited_rejected() {
    use busbar_contract::abi::plane::AUDIT_REJECTED;
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    store().clear();
    let door = open();
    let json = [Field {
        name: str_of(b"content-type"),
        value: str_of(b"application/json"),
    }];
    let fingerprint = br#"{"fingerprint": "sha256:aa"}"#;
    let cases: [(&str, u32, &str, &[u8], u32); 3] = [
        ("unknown connect", 0, "/agents/nope/connect", b"", 404),
        (
            "unknown approve",
            1,
            "/agents/nope/approve",
            fingerprint,
            404,
        ),
        (
            "malformed approve",
            1,
            "/agents/vendor/approve",
            br#"{"fingerprint": "sha256:aa", "and": "more"}"#,
            400,
        ),
    ];
    for (case, route, target, body, refused) in cases {
        let (outcome, status, answered, audit) = door.verb_audited(route, target, &json, body);
        assert_eq!(
            (outcome, status),
            (Outcome::Ready, refused),
            "{case}: {answered}"
        );
        assert_eq!(audit, AUDIT_REJECTED, "{case} is audited rejected");
    }
}

#[path = "support/push_lifecycle_cases.rs"]
mod push_lifecycle_cases;

#[path = "support/reported_fixture_cases.rs"]
mod reported_fixture_cases;

#[path = "support/card_admission_audit_cases.rs"]
mod card_admission_audit_cases;
