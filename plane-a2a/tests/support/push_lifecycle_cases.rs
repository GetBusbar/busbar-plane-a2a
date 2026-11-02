// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Actual public callback route: capabilities are minted by the real push-config mirror.
use super::*;
use busbar_contract::abi::host::service::{RecordsGetIn, SignIn, CLAIM_WON, FOUND};
use busbar_contract::abi::mechanism::call::Span;
use serde_json::{json, Value};
#[path = "conditional_callback_host.rs"]
mod conditional_host;

#[derive(Default)]
struct Script {
    conditional: conditional_host::Host,
    sign_failed: bool,
    read_failed: bool,
    publish_failed: bool,
    read_pending: bool,
    signs: usize,
    gets: usize,
    claims: usize,
    config_failed: bool,
    config_gets: usize,
    full_lists: usize,
    random: u8,
    notifications: usize,
}
static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
fn script<T>(f: impl FnOnce(&mut Script) -> T) -> T {
    f(SCRIPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
        .unwrap())
}
fn text(s: AbiStr) -> String {
    if s.len() == 0 {
        return String::new();
    }
    // SAFETY: every caller passes a live ABI string during its call or envelope lifetime.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr(), s.len()) }).into_owned()
}
struct Reset(Vec<(String, String, Vec<u8>)>);
impl Drop for Reset {
    fn drop(&mut self) {
        *store() = std::mem::take(&mut self.0);
        *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}
extern "C" fn fixed_clock(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: SDK lends ClockNowIn and its live reading slot.
    let i = unsafe { input.cast::<ClockNowIn>().read() };
    unsafe {
        (*i.reading).wall_ns = 1_800_000_000_000_000_000;
        (*i.reading).mono_ns = 5_000_000_000;
    }
    answer(out, Outcome::Ready, 0, 0)
}
extern "C" fn get(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: SDK lends RecordsGetIn and its stated output buffers.
    let i = unsafe { input.cast::<RecordsGetIn>().read() };
    let (failed, pending) = script(|s| {
        s.gets += 1;
        if text(i.kind) == "push_config" {
            s.config_gets += 1;
        }
        (
            s.read_failed || (s.config_failed && text(i.kind) == "push_config"),
            s.read_pending,
        )
    });
    if pending {
        return answer(out, Outcome::Pending, 0, 0);
    }
    if failed {
        return answer(out, Outcome::Failed, 0, 0);
    }
    let row = script(|s| s.conditional.get(i.head, &text(i.kind), &text(i.key)));
    let Some(row) = row else {
        return answer(out, Outcome::Ready, 0, 0);
    };
    if row.len() > i.into.cap || i.into.spans_cap < 1 {
        let result = answer(out, Outcome::Failed, 0, 0);
        // SAFETY: the live ServiceOut reports both complete loan requirements; neither payload
        // buffer has been written on this SHORT path.
        unsafe {
            (*out).needed_bytes = row.len() as u64;
            (*out).needed_items = 1;
        }
        return result;
    }
    // SAFETY: both output capacities were checked above; the SDK lends the byte/span regions
    // exclusively for this synchronous records.get callback.
    unsafe {
        std::ptr::copy_nonoverlapping(row.as_ptr(), i.into.buf, row.len());
        i.into.spans.write(ItemSpan {
            key: Span {
                offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
            value: Span {
                offset: 0,
                len: u32::try_from(row.len()).expect("the fixture record fits its span"),
            },
        });
    }
    let result = answer(out, Outcome::Ready, FOUND, row.len() as u64);
    // SAFETY: this is the callback's live output; its one initialized value span was just written.
    unsafe {
        (*out).items = 1;
    }
    result
}
extern "C" fn claimed(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let failed = script(|s| {
        s.claims += 1;
        s.publish_failed
    });
    answer(
        out,
        if failed {
            Outcome::Failed
        } else {
            Outcome::Ready
        },
        CLAIM_WON,
        0,
    )
}
extern "C" fn signed(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let failed = script(|s| {
        s.signs += 1;
        s.sign_failed
    });
    if failed {
        return answer(out, Outcome::Failed, 0, 0);
    }
    // SAFETY: SDK lends SignIn and its writable buffers.
    let i = unsafe { input.cast::<SignIn>().read() };
    let key = b"fixture";
    let signature = [7u8; 64];
    assert!(i.into.cap >= key.len() + signature.len() && i.into.spans_cap >= 1);
    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr(), i.into.buf, key.len());
        std::ptr::copy_nonoverlapping(
            signature.as_ptr(),
            i.into.buf.add(key.len()),
            signature.len(),
        );
        i.into.spans.write(ItemSpan {
            key: Span {
                offset: 0,
                len: key.len() as u32,
            },
            value: Span {
                offset: key.len() as u32,
                len: signature.len() as u32,
            },
        });
    }
    let result = answer(out, Outcome::Ready, 0, (key.len() + signature.len()) as u64);
    unsafe {
        (*out).items = 1;
    }
    result
}
extern "C" fn listed(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends RecordsListIn during the call.
    let i = unsafe { input.cast::<RecordsListIn>().read() };
    let _ = ctx;
    let (fresh, rows) = script(|s| {
        let rows = s.conditional.list(
            i.head,
            &text(i.kind),
            &text(i.prefix),
            &text(i.after),
            if i.limit == 0 {
                usize::MAX
            } else {
                i.limit as usize
            },
        );
        if rows.0 && text(i.kind) == "task" && i.prefix.len() == 0 {
            s.full_lists += 1;
        }
        rows
    });
    let _ = fresh;
    let needed: usize = rows.iter().map(|(k, v)| k.len() + v.len()).sum();
    if needed > i.into.cap || rows.len() > i.into.spans_cap {
        let result = answer(out, Outcome::Failed, 0, 0);
        unsafe {
            (*out).needed_bytes = needed as u64;
            (*out).needed_items = rows.len() as u64;
        }
        return result;
    }
    let mut at = 0;
    for (n, (key, value)) in rows.iter().enumerate() {
        // SAFETY: the SDK's live buffers fit the checked complete page.
        unsafe {
            std::ptr::copy_nonoverlapping(key.as_ptr(), i.into.buf.add(at), key.len());
            std::ptr::copy_nonoverlapping(
                value.as_ptr(),
                i.into.buf.add(at + key.len()),
                value.len(),
            );
            i.into.spans.add(n).write(ItemSpan {
                key: Span {
                    offset: at as u32,
                    len: key.len() as u32,
                },
                value: Span {
                    offset: (at + key.len()) as u32,
                    len: value.len() as u32,
                },
            });
        }
        at += key.len() + value.len();
    }
    let result = answer(out, Outcome::Ready, 0, at as u64);
    unsafe {
        (*out).items = rows.len() as u64;
    }
    result
}
extern "C" fn random_fill(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends RandomFillIn and its declared byte region.
    let i = unsafe {
        input
            .cast::<busbar_contract::abi::host::service::RandomFillIn>()
            .read()
    };
    let value = script(|s| {
        s.random = s.random.wrapping_add(1);
        s.conditional.random(i.head, s.random)
    });
    assert!(i.into.cap >= i.len as usize);
    unsafe {
        std::ptr::write_bytes(i.into.buf, value, i.len as usize);
    }
    answer(out, Outcome::Ready, 0, i.len)
}
fn apply(records: &[RecordWrite], arena: &[u8]) {
    let at = |s: Span| arena[s.offset as usize..(s.offset + s.len) as usize].to_vec();
    let mut stored = store();
    for w in records {
        let kind = door_facts::HELD_KINDS[w.kind as usize].to_string();
        let key = String::from_utf8(at(w.key)).unwrap();
        let value = at(w.value);
        stored.retain(|(k, id, _)| *k != kind || *id != key);
        if !value.is_empty() {
            stored.push((kind, key, value));
        }
    }
}
extern "C" fn notification_request(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: connector lends the request bytes and descriptor throughout this call.
    let i = unsafe { input.cast::<RequestIn>().read() };
    let piece = unsafe { i.piece.read() };
    if piece.kind == busbar_contract::abi::host::conn::connector::REQUEST_HEAD {
        let bytes = unsafe { std::slice::from_raw_parts(i.buf, i.len) };
        let target = piece.target;
        if &bytes[target.offset as usize..(target.offset + target.len) as usize] == b"/cb" {
            script(|s| s.notifications += 1);
        }
    }
    super::write_request(ctx, input, out)
}

extern "C" fn notification_judged(
    _: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the destination service lends its writable address and span regions.
    let i = unsafe {
        input
            .cast::<busbar_contract::abi::host::service::DestJudgeIn>()
            .read()
    };
    let address = b"93.184.216.34";
    if i.into.cap < address.len() || i.into.spans_cap < 1 {
        let result = answer(out, Outcome::Failed, 0, 0);
        unsafe {
            (*out).needed_bytes = address.len() as u64;
            (*out).needed_items = 1;
        }
        return result;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(address.as_ptr(), i.into.buf, address.len());
        i.into.spans.write(ItemSpan {
            key: Span {
                offset: 0,
                len: address.len() as u32,
            },
            value: Span {
                offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
        });
    }
    let result = answer(out, Outcome::Ready, DEST_ALLOWED, address.len() as u64);
    unsafe {
        (*out).items = 1;
    }
    result
}

fn open_scripted() -> (Reset, Door) {
    let reset = Reset(std::mem::take(&mut *store()));
    *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = Some(Script::default());
    (reset, open_scripted_instance())
}

fn open_scripted_instance() -> Door {
    let services = Box::leak(Box::new(HostSlots {
        records_list: Some(listed),
        random_fill: Some(random_fill),
        clock_now: Some(fixed_clock),
        records_get: Some(get),
        records_claim: Some(claimed),
        sign: Some(signed),
        dest_judge: Some(notification_judged),
        ..HOST_SLOTS
    }));
    let conns = Box::leak(Box::new(ConnectorSlots {
        write_request: Some(notification_request),
        ..CONN_SLOTS
    }));
    let tables = Box::leak(Box::new(HostTables {
        services,
        conns,
        ..TABLES.0
    }));
    let mut input: PlaneOpenIn = z();
    input.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: tables,
        settings: octets(SECTION),
        generation: 1,
        ..z()
    };
    input.public_url = str_of(b"https://gw.example");
    let mut output: PlaneOpenOut = z();
    output.open.head = out_head::<PlaneOpenOut>();
    // SAFETY: exact public OPEN ABI, live buffers and static host slots.
    let result = unsafe {
        lifecycle().open.unwrap()(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
    Door::new(output.open.instance)
}
fn seed() {
    seed_task("t1");
}
fn seed_task(task_id: &str) {
    let caller = std::str::from_utf8(ALICE).unwrap();
    let row = json!({"task_id":task_id,"context_id":"c1","principal":caller,"direction":"inbound","state":"working","agent_id":"vendor","artifact_cursor":0,"push_callback":"","created_at":1_800_000_000u64,"updated_at":1_800_000_000u64,"next_seq":1});
    store().push((
        "task".into(),
        format!("{caller}/{task_id}"),
        serde_json::to_vec(&row).unwrap(),
    ));
}
fn registered(door: &Door) -> String {
    assert_eq!(door.connect("vendor").1, 200);
    seed();
    let get = br#"{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t1"}}"#;
    assert_eq!(
        door.arrive(
            501,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            get
        ),
        (Outcome::Ready, 0)
    );
    let attempt = piece(door, 501, Given::attempt(b"vendor"), 65536);
    assert_eq!(
        attempt.outcome,
        Some(Outcome::Ready),
        "flags={}, emitted_bytes={}",
        attempt.flags,
        attempt.emitted.len()
    );
    assert_ne!(attempt.flags & busbar_contract::abi::plane::EMIT_TO_FAR_END, 0,
        "the setup must actually reach the agent (flags={}, emitted_bytes={}, publications={}, observations={})",
        attempt.flags, attempt.emitted.len(), script(|s| s.conditional.requests.len()), script(|s| s.conditional.observations.len()));
    assert_eq!(
        piece(door, 501, Given::caller(get), 65536).outcome,
        Some(Outcome::Ready)
    );
    let response=br#"{"jsonrpc":"2.0","id":1,"result":{"id":"backend-t1","contextId":"c1","status":{"state":"working"}}}"#;
    let far = piece(door, 501, Given::far_end(200, response), 65536);
    assert_eq!(far.outcome, Some(Outcome::Ready),
        "far reply did not settle (flags={}, emitted_bytes={}, publications={}, observations={}, applied={})",
        far.flags, far.emitted.len(), script(|s| s.conditional.requests.len()),
        script(|s| s.conditional.observations.len()), script(|s| s.conditional.applied));
    let create=br#"{"jsonrpc":"2.0","id":2,"method":"CreateTaskPushNotificationConfig","params":{"taskId":"t1","id":"cfg","url":"https://receiver.example/cb"}}"#;
    assert_eq!(
        door.arrive(
            502,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            create
        ),
        (Outcome::Ready, 0)
    );
    assert_eq!(
        piece(door, 502, Given::attempt(b"vendor"), 65536).outcome,
        Some(Outcome::Ready)
    );
    let reply = piece(door, 502, Given::caller(create), 65536);
    assert_eq!(reply.outcome, Some(Outcome::Ready), "{reply:?}");
    assert!(
        script(|s| s.signs) > 0,
        "real config mirror must mint a callback token: {reply:?}"
    );
    format!("Bearer t1.{}", "07".repeat(32))
}
#[derive(Debug)]
struct Served {
    outcome: Outcome,
    status: u32,
    needed: u64,
    diags: Vec<String>,
    writes: usize,
}

fn copied_extensions(door: &Door, answer_head: &OutHead) -> Vec<u8> {
    let ext = answer_head.extensions;
    if ext.len == 0 {
        return Vec::new();
    }
    // SAFETY: copied while the answer's lease is live, before invoking generic RELEASE.
    let bytes = unsafe { std::slice::from_raw_parts(ext.ptr, ext.len) }.to_vec();
    if answer_head.lease != 0 {
        let input = busbar_contract::abi::mechanism::lifecycle::ReleaseIn {
            head: head::<busbar_contract::abi::mechanism::lifecycle::ReleaseIn>(
                life::RELEASE,
                Ticket::NONE,
            ),
            lease: answer_head.lease,
        };
        let mut output = out_head::<OutHead>();
        // SAFETY: existing generic RELEASE over the exact live lease returned by this instance.
        let result = unsafe {
            lifecycle().release.unwrap()(
                door.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        };
        assert_eq!(
            result.outcome(),
            Outcome::Ready,
            "conditional intent lease is released by PlaneLife"
        );
    }
    bytes
}

fn begin_conditional(ticket: Ticket, resuming: bool) -> Vec<u8> {
    script(|s| {
        let refused = s.publish_failed;
        s.conditional.begin(ticket, resuming, refused)
    })
}

fn next_conditional(
    ticket: Ticket,
    outcome: Outcome,
    short: bool,
    extensions: &[u8],
) -> Option<Vec<u8>> {
    script(|s| {
        let refused = s.publish_failed;
        s.conditional
            .returned(ticket, outcome, short, extensions, refused)
    })
}

struct Driven {
    outcome: Outcome,
    extensions: Vec<u8>,
    short: bool,
}

/// Every normal driver crossing carries the host's sticky receipt until ACK consumption.
fn sticky_settlement_driver(door: &Door, tick: bool) -> Driven {
    let receipt = script(|s| s.conditional.retained_settlement()).unwrap_or_default();
    settlement_driver(door, &receipt, tick)
}

/// The real driver ABI, including copying and releasing its leased acknowledgement.
fn settlement_driver(door: &Door, receipt: &[u8], tick: bool) -> Driven {
    let driver = ticket(1 << 29);
    let mut extensions = begin_conditional(driver, false);
    extensions.extend_from_slice(receipt);
    if tick {
        let mut input = TickIn {
            head: head::<TickIn>(life::TICK, driver),
            now_ns: 5_000_000_000,
        };
        input.head.extensions = octets(&extensions);
        let mut output: TickOut = z();
        output.head = out_head::<TickOut>();
        // SAFETY: the active Door owns this table's instance. TickIn/Out and the input's
        // extension bytes remain live through the call and copying/releasing its answer.
        let result = unsafe {
            lifecycle().tick.unwrap()(
                door.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        };
        Driven {
            outcome: result.outcome(),
            extensions: copied_extensions(door, &output.head),
            short: false,
        }
    } else {
        let mut sessions = [0_u64; 4];
        let mut input = PlaneDriveIn {
            drive: DriveIn {
                head: head::<PlaneDriveIn>(life::DRIVE, driver),
                driver,
            },
            sessions_buf: sessions.as_mut_ptr(),
            sessions_cap: sessions.len(),
        };
        input.drive.head.extensions = octets(&extensions);
        let mut output: PlaneDriveOut = z();
        output.head = out_head::<PlaneDriveOut>();
        // SAFETY: the active Door owns this table's instance. The complete PlaneDriveIn/Out,
        // extension bytes and exclusive initialized sessions buffer stay live for the call.
        let result = unsafe {
            lifecycle().drive.unwrap()(
                door.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        };
        Driven {
            outcome: result.outcome(),
            extensions: copied_extensions(door, &output.head),
            short: output.sessions_needed as usize > sessions.len(),
        }
    }
}

fn consume_settlement(answer: &Driven) -> bool {
    script(|s| {
        s.conditional
            .acknowledge(&answer.extensions, answer.outcome, answer.short)
    })
}

fn serve(door: &Door, slot_id: u64, auth: &str, body: &[u8], cap: usize) -> Served {
    serve_flags(door, slot_id, auth, body, cap, 0)
}
fn recall(door: &Door, slot_id: u64, auth: &str, body: &[u8], cap: usize) -> Served {
    serve_flags(
        door,
        slot_id,
        auth,
        body,
        cap,
        busbar_contract::abi::mechanism::call::FLAG_RESUME,
    )
}
fn serve_flags(
    door: &Door,
    slot_id: u64,
    auth: &str,
    body: &[u8],
    cap: usize,
    flags: u32,
) -> Served {
    let fields = [Field {
        name: str_of(b"authorization"),
        value: str_of(auth.as_bytes()),
    }];
    let mut reply = vec![0u8; cap];
    let mut out_fields = [z::<OutField>(); 8];
    let mut arena = vec![0u8; 65536];
    let mut records = [z::<RecordWrite>(); 64];
    let mut input: ServeIn = z();
    input.head = head::<ServeIn>(slot::SERVE, ticket(slot_id));
    input.head.flags = flags;
    input.route = 2;
    input.target = str_of(b"/a2a/push");
    input.fields = fields.as_ptr();
    input.fields_len = fields.len();
    input.body = octets(body);
    (input.reply_buf, input.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (input.fields_buf, input.fields_cap) = (out_fields.as_mut_ptr(), out_fields.len());
    (input.arena_buf, input.arena_cap) = (arena.as_mut_ptr(), arena.len());
    (input.records_buf, input.records_cap) = (records.as_mut_ptr(), records.len());
    let mut output: ServeOut;
    let mut extensions = begin_conditional(
        ticket(slot_id),
        flags & busbar_contract::abi::mechanism::call::FLAG_RESUME != 0,
    );
    let mut crossings = 0;
    // SAFETY: exact SERVE structs and all declared buffers remain live throughout the call.
    let result = loop {
        crossings += 1;
        assert!(crossings < 256, "conditional callback failed to settle");
        input.head.extensions = octets(&extensions);
        output = z();
        output.head = out_head::<ServeOut>();
        let result = unsafe {
            ops().serve.unwrap()(
                door.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        };
        let ext = copied_extensions(door, &output.head);
        if busbar_contract::abi::sdk::plane::conditional::read_request(&ext)
            .unwrap()
            .is_some()
            || busbar_contract::abi::sdk::plane::conditional::read_observation(&ext)
                .unwrap()
                .is_some()
        {
            assert_eq!(
                (
                    output.status,
                    output.reply_written,
                    output.records_written,
                    output.fields_written
                ),
                (0, 0, 0, 0)
            );
        }
        if let Some(next) = next_conditional(
            ticket(slot_id),
            result.outcome(),
            output.reply_needed > cap as u64,
            &ext,
        ) {
            extensions = next;
            input.head.flags |= busbar_contract::abi::mechanism::call::FLAG_RESUME;
            continue;
        }
        break result;
    };
    let envelope = output.head.envelope;
    let diags = if envelope.diags_len == 0 {
        Vec::new()
    } else {
        // SAFETY: per-ticket envelope remains valid until the next operation on this ticket.
        unsafe { std::slice::from_raw_parts(envelope.diags, envelope.diags_len) }
            .iter()
            .map(|d| text(d.text))
            .collect()
    };
    if result.outcome() == Outcome::Ready {
        apply(&records[..output.records_written as usize], &arena);
    }
    Served {
        outcome: result.outcome(),
        status: output.status,
        needed: output.reply_needed,
        diags,
        writes: output.records_written as usize,
    }
}
fn piece(door: &Door, unit: u64, given: Given<'_>, reply_cap: usize) -> Answered {
    piece_sized(door, unit, given, reply_cap, 16, 1 << 14)
}
fn piece_sized(
    door: &Door,
    unit: u64,
    given: Given<'_>,
    reply_cap: usize,
    fields_cap: usize,
    arena_cap: usize,
) -> Answered {
    let mut reply = vec![0_u8; reply_cap];
    let mut fields = vec![z::<OutField>(); fields_cap];
    let mut arena = vec![0_u8; arena_cap];
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
    let mut o: OnPieceOut;
    let mut extensions = begin_conditional(ticket(unit), false);
    let mut crossings = 0;
    let f = ops().on_piece.expect("on_piece");
    // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
    // states and live for the call.
    #[allow(unused_unsafe)]
    let ret = loop {
        crossings += 1;
        assert!(crossings < 256, "conditional piece failed to settle");
        i.head.extensions = octets(&extensions);
        o = z();
        o.head = out_head::<OnPieceOut>();
        let ret = unsafe {
            f(
                door.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            )
        };
        assert!(
            o.emitted <= reply_cap as u64,
            "the reply window fits its buffer"
        );
        let ext = copied_extensions(door, &o.head);
        if busbar_contract::abi::sdk::plane::conditional::read_request(&ext)
            .unwrap()
            .is_some()
            || busbar_contract::abi::sdk::plane::conditional::read_observation(&ext)
                .unwrap()
                .is_some()
        {
            assert_eq!(
                (
                    o.emitted,
                    o.records_written,
                    o.units_written,
                    o.flags,
                    o.fields_written
                ),
                (0, 0, 0, 0, 0)
            );
        }
        if let Some(next) = next_conditional(
            ticket(unit),
            ret.outcome(),
            o.fields_needed as usize > fields.len()
                || o.arena_needed as usize > arena.len()
                || o.records_needed as usize > records.len()
                || o.units_needed as usize > units.len(),
            &ext,
        ) {
            extensions = next;
            i.head.flags |= busbar_contract::abi::mechanism::call::FLAG_RESUME;
            continue;
        }
        break ret;
    };
    if ret.outcome() == Outcome::Ready {
        apply(&records[..o.records_written as usize], &arena);
    }
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

const WORKING: &[u8] = br#"{"id":"t1","status":{"state":"working"}}"#;
const COMPLETED: &[u8] = br#"{"id":"t1","status":{"state":"completed"}}"#;
fn fault(reply: &Served) {
    assert_eq!(
        (reply.outcome, reply.status),
        (Outcome::Ready, 503),
        "{reply:?}"
    );
    assert!(
        reply.diags.iter().any(|d| d.contains("BUSBAR-7050")),
        "{reply:?}"
    );
    assert_eq!(reply.writes, 0);
}
#[test]
fn callback_signer_read_and_transition_faults_are_retryable_and_distinct_from_bad_tokens() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    assert_eq!(
        serve(&door, 600, "Bearer missing.00", WORKING, 4096).status,
        401
    );
    script(|s| s.sign_failed = true);
    fault(&serve(&door, 601, &auth, WORKING, 4096));
    script(|s| s.sign_failed = false);
    script(|s| s.read_failed = true);
    fault(&serve(&door, 602, &auth, WORKING, 4096));
    script(|s| s.read_failed = false);
    script(|s| s.publish_failed = true);
    fault(&serve(&door, 603, &auth, COMPLETED, 4096));
    script(|s| s.publish_failed = false);
    let unchanged = serve(&door, 604, &auth, WORKING, 4096);
    assert_eq!(unchanged.status, 202);
    assert_eq!(unchanged.writes, 0);
    let illegal = serve(
        &door,
        605,
        &auth,
        br#"{"status":{"state":"submitted"}}"#,
        4096,
    );
    assert_eq!(illegal.status, 202);
    assert_eq!(illegal.writes, 0);
    store().retain(|(kind, _, _)| kind != "task");
    assert_eq!(serve(&door, 606, &auth, WORKING, 4096).status, 401);
}
#[test]
fn callback_pending_and_short_refusals_preserve_one_budget_charge_and_one_warning() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    script(|s| s.read_pending = true);
    assert_eq!(
        serve(&door, 700, &auth, WORKING, 4096).outcome,
        Outcome::Pending
    );
    script(|s| s.read_pending = false);
    assert_eq!(recall(&door, 700, &auth, WORKING, 4096).status, 202);

    for ticket in 701..759 {
        assert_eq!(serve(&door, ticket, &auth, WORKING, 4096).status, 202);
    }
    script(|s| s.read_failed = true);
    let short = serve(&door, 759, &auth, WORKING, 0);
    assert_eq!(short.outcome, Outcome::Failed);
    assert!(short.needed > 0);
    assert_eq!(
        short
            .diags
            .iter()
            .filter(|d| d.contains("BUSBAR-7050"))
            .count(),
        1
    );
    let recalled = recall(&door, 759, &auth, WORKING, 4096);
    assert_eq!(
        (recalled.outcome, recalled.status),
        (Outcome::Ready, 503),
        "{recalled:?}"
    );
    assert!(!recalled.diags.iter().any(|d| d.contains("BUSBAR-7050")));
    script(|s| s.read_failed = false);
    assert_eq!(serve(&door, 760, &auth, WORKING, 4096).status, 429);
    let short_limit = serve(&door, 761, &auth, WORKING, 0);
    assert_eq!(short_limit.outcome, Outcome::Failed);
    assert!(short_limit.needed > 0);
    let recalled_limit = recall(&door, 761, &auth, WORKING, 4096);
    assert_eq!(
        (recalled_limit.outcome, recalled_limit.status),
        (Outcome::Ready, 429)
    );
}

#[test]
fn failed_config_read_keeps_the_accepted_move_and_retries_its_notification() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let before_applied = script(|s| s.conditional.applied);
    script(|s| s.config_failed = true);
    let accepted = serve(&door, 800, &auth, COMPLETED, 4096);
    assert_eq!(
        (accepted.outcome, accepted.status),
        (Outcome::Ready, 202),
        "{accepted:?}"
    );
    assert_eq!(
        accepted.writes, 0,
        "guarded mutations never ride ordinary output"
    );
    assert_eq!(script(|s| s.conditional.applied), before_applied + 1);
    let row = store()
        .iter()
        .find(|(kind, _, _)| kind == "task")
        .unwrap()
        .2
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&row).unwrap()["state"],
        "completed"
    );
    assert!(accepted.diags.iter().any(|d| d.contains("BUSBAR-7050")));
    let before = script(|s| s.config_gets);
    script(|s| s.config_failed = false);
    let (outcome, _) = door.tick();
    assert_eq!(outcome, Outcome::Ready);
    assert!(
        script(|s| s.config_gets) > before,
        "driver must retry the retained configuration read"
    );
}
#[test]
fn repeated_actual_submits_do_not_repeat_a_full_retention_read() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    let request=br#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"user","parts":[{"kind":"text","text":"hello"}]}}}"#;
    let mut first = 0;
    for unit in [901, 902] {
        assert_eq!(
            door.arrive(
                unit,
                ("POST", "/a2a/agents/{agent_id}"),
                "/a2a/agents/vendor",
                request
            ),
            (Outcome::Ready, 0)
        );
        assert_eq!(
            piece(&door, unit, Given::attempt(b"vendor"), 65536).outcome,
            Some(Outcome::Ready)
        );
        let sent = piece(&door, unit, Given::caller(request), 65536);
        assert_eq!(sent.outcome, Some(Outcome::Ready), "{sent:?}");
        assert!(
            !sent.emitted.is_empty(),
            "actual message must reach the relay"
        );
        if unit == 901 {
            first = script(|s| s.full_lists);
            assert!(first > 0);
        } else {
            assert_eq!(
                script(|s| s.full_lists),
                first,
                "second submit inside the gate must not list every task again"
            );
        }
    }
}

#[test]
fn malformed_callback_short_recall_keeps_its_refusal_and_single_charge() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    for id in 1000..1059 {
        assert_eq!(serve(&door, id, &auth, WORKING, 4096).status, 202);
    }
    let short = serve(&door, 1059, &auth, b"{", 0);
    assert_eq!(short.outcome, Outcome::Failed);
    assert!(short.needed > 0);
    let recalled = recall(&door, 1059, &auth, b"{", 4096);
    assert_eq!(
        (recalled.outcome, recalled.status),
        (Outcome::Ready, 400),
        "{recalled:?}"
    );
    assert_eq!(serve(&door, 1060, &auth, WORKING, 4096).status, 429);
}

fn task_state() -> Value {
    let rows = store();
    serde_json::from_slice(
        &rows
            .iter()
            .find(|(kind, key, _)| kind == "task" && key.ends_with("/t1"))
            .unwrap()
            .2,
    )
    .unwrap()
}

#[test]
fn conditional_callback_waits_for_applied_and_replays_the_identical_candidate() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let applied = script(|s| s.conditional.applied);
    let emitted = script(|s| s.conditional.emitted.len());
    script(|s| s.conditional.pause_commit = true);
    let waiting = serve(&door, 1100, &auth, COMPLETED, 4096);
    assert_eq!(
        (waiting.outcome, waiting.status, waiting.writes),
        (Outcome::Pending, 0, 0)
    );
    assert_eq!(task_state()["state"], "working");
    let reads = script(|s| s.gets);
    assert_eq!(
        recall(&door, 1100, &auth, COMPLETED, 4096).outcome,
        Outcome::Pending
    );
    assert_eq!(
        script(|s| s.gets),
        reads,
        "a wake without the receipt cannot reread or replan"
    );
    assert_eq!(script(|s| s.conditional.applied), applied);
    script(|s| {
        assert_eq!(
            s.conditional.emitted[emitted],
            s.conditional.emitted[emitted + 1]
        );
    });
    assert_eq!(
        serve(&door, 1101, &auth, WORKING, 4096).status,
        202,
        "pending terminal publication has not ended the callback token"
    );
    script(|s| s.conditional.pause_commit = false);
    let landed = recall(&door, 1100, &auth, COMPLETED, 4096);
    assert_eq!(
        (landed.outcome, landed.status, landed.writes),
        (Outcome::Ready, 202, 0)
    );
    assert_eq!(script(|s| s.conditional.applied), applied + 1);
    assert_eq!(task_state()["state"], "completed");
    assert_eq!(
        serve(&door, 1102, &auth, WORKING, 4096).status,
        401,
        "the acknowledged terminal move ends its token"
    );
    assert_eq!(
        script(|s| s.claims),
        0,
        "publication does not leave a TTL claim behind"
    );
}

#[test]
fn conditional_conflict_observes_again_and_reads_a_fresh_row() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let before = script(|s| s.conditional.requests.len());
    let observed = script(|s| s.conditional.observations.len());
    script(|s| s.conditional.conflict_once = true);
    assert_eq!(serve(&door, 1110, &auth, COMPLETED, 4096).status, 202);
    script(|s| {
        let attempts = &s.conditional.requests[before..];
        assert_eq!(attempts.len(), 2);
        assert_ne!(
            attempts[0].candidate.correlation,
            attempts[1].candidate.correlation
        );
        assert_ne!(
            attempts[0].candidate.predicates[0].expected,
            attempts[1].candidate.predicates[0].expected,
            "the real competing cursor change is reread"
        );
        assert_eq!(s.conditional.observations.len(), observed + 2);
        let epoch = attempts[0].capability.epoch;
        let reads: Vec<_> = s
            .conditional
            .reads
            .iter()
            .filter(|r| r.0 == epoch && r.2 == "task")
            .collect();
        assert!(
            reads.len() >= 3,
            "precheck plus two distinct post-observation GET handles: {reads:?}"
        );
        assert!(reads.windows(2).all(|r| r[0].1 < r[1].1));
    });
    assert_eq!(
        task_state()["artifact_cursor"],
        1,
        "the retry preserves the competitor's mutation"
    );
    assert_eq!(task_state()["state"], "completed");
}

#[test]
fn lost_applied_callback_receipt_never_reexecutes_the_transaction() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    let applied = script(|s| s.conditional.applied);
    let emitted = script(|s| s.conditional.emitted.len());
    script(|s| s.conditional.lose_applied_once = true);
    assert_eq!(serve(&door, 1120, &auth, COMPLETED, 4096).status, 202);
    script(|s| {
        assert_eq!(s.conditional.applied, applied + 1);
        assert_eq!(s.conditional.emitted.len(), emitted + 2);
        assert_eq!(
            s.conditional.emitted[emitted],
            s.conditional.emitted[emitted + 1]
        );
    });
}

const SUBMIT: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"user","parts":[{"kind":"text","text":"hello"}]}}}"#;
fn arrive_submit(door: &Door, unit: u64) {
    assert_eq!(
        door.arrive(
            unit,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            SUBMIT
        )
        .0,
        Outcome::Ready
    );
}

#[test]
fn an_applied_task_open_keeps_its_identity_through_output_short_recall() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    arrive_submit(&door, 1130);
    let attempt = piece(&door, 1130, Given::attempt(b"vendor"), 65536);
    assert_eq!(
        attempt.outcome,
        Some(Outcome::Ready),
        "flags={}, emitted_bytes={}",
        attempt.flags,
        attempt.emitted.len()
    );
    assert_ne!(attempt.flags & busbar_contract::abi::plane::EMIT_TO_FAR_END, 0,
        "the setup must actually open its task (flags={}, emitted_bytes={}, publications={}, observations={})",
        attempt.flags, attempt.emitted.len(), script(|s| s.conditional.requests.len()), script(|s| s.conditional.observations.len()));
    let applied = script(|s| s.conditional.applied);
    let rows = store().clone();
    let short = piece_sized(&door, 1130, Given::caller(SUBMIT), 65536, 16, 0);
    assert_eq!(short.outcome, Some(Outcome::Failed));
    assert!(
        short.arena_needed > 0,
        "the auxiliary arena causes an actual SHORT"
    );
    let recalled = piece(&door, 1130, Given::caller(SUBMIT), 65536);
    assert_eq!(recalled.outcome, Some(Outcome::Ready));
    assert!(!recalled.emitted.is_empty());
    assert_eq!(*store(), rows, "SHORT writes no second task or chain event");
    script(|s| {
        assert_eq!(s.conditional.applied, applied);
        assert_eq!(
            s.conditional.events.len(),
            2,
            "submitted and delegated are one atomic opening"
        );
        assert_eq!(s.claims, 0);
    });
}

#[test]
fn an_applied_task_open_streams_a_zero_room_body_without_reopening_the_task() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    arrive_submit(&door, 1131);
    let attempt = piece(&door, 1131, Given::attempt(b"vendor"), 65536);
    assert_eq!(attempt.outcome, Some(Outcome::Ready));
    assert_ne!(
        attempt.flags & busbar_contract::abi::plane::EMIT_TO_FAR_END,
        0
    );
    let applied = script(|s| s.conditional.applied);
    let rows = store().clone();
    let blocked = piece(&door, 1131, Given::caller(SUBMIT), 0);
    assert_eq!(blocked.outcome, Some(Outcome::Ready));
    assert_eq!(blocked.more, 1);
    assert!(blocked.emitted.is_empty());
    let drained = piece(&door, 1131, Given::more(), 65536);
    assert_eq!(drained.outcome, Some(Outcome::Ready));
    assert_eq!(drained.more, 0);
    assert!(!drained.emitted.is_empty());
    assert_eq!(*store(), rows);
    script(|s| {
        assert_eq!(s.conditional.applied, applied);
        assert_eq!(s.conditional.events.len(), 2);
        assert_eq!(s.claims, 0);
    });
}

#[test]
fn cancel_starts_no_publication_and_does_not_replace_a_submitted_attempt() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    assert_eq!(door.connect("vendor").1, 200);
    arrive_submit(&door, 1140);
    assert_eq!(door.cancel_unit(1140), Outcome::Ready);
    assert_eq!(script(|s| s.conditional.applied), 0);
    arrive_submit(&door, 1141);
    script(|s| s.conditional.pause_commit = true);
    let pending = piece(&door, 1141, Given::attempt(b"vendor"), 65536);
    assert_eq!(pending.outcome, Some(Outcome::Pending));
    assert!(pending.emitted.is_empty());
    assert_eq!(pending.flags, 0);
    assert_eq!(door.cancel_unit(1141), Outcome::Ready);
    let original = script(|s| s.conditional.emitted.last().unwrap().clone());
    script(|s| {
        s.conditional.pause_commit = false;

        s.conditional.begin(ticket(1141), true, false);
        assert_eq!(s.conditional.requests.last(), Some(&original));
        assert_eq!(s.conditional.applied, 1);
    });
    let cancelled = piece(&door, 1141, Given::attempt(b"vendor"), 65536);
    assert_eq!(cancelled.outcome, Some(Outcome::Failed));
    assert!(cancelled.emitted.is_empty());
    assert_eq!(script(|s| s.conditional.applied), 1);
    assert_eq!(script(|s| s.claims), 0);
}

#[test]
fn canceled_raw_callback_settles_late_applied_once_across_lost_driver_ack() {
    use busbar_contract::abi::sdk::plane::conditional as wire;
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);

    assert_eq!(door.tick().0, Outcome::Ready);
    assert_eq!(door.tick().0, Outcome::Ready);
    let notifications = script(|s| s.notifications);
    let applied = script(|s| s.conditional.applied);
    script(|s| s.conditional.pause_commit = true);
    assert_eq!(
        serve(&door, 1200, &auth, COMPLETED, 4096).outcome,
        Outcome::Pending
    );
    let original = script(|s| s.conditional.emitted.last().unwrap().clone());
    assert_eq!(door.cancel_unit(1200), Outcome::Ready);
    let reads = script(|s| s.gets);
    let emitted = script(|s| s.conditional.emitted.len());
    let receipt = script(|s| s.conditional.detach(ticket(1200)));
    assert_eq!(
        script(|s| s.conditional.requests.last().cloned()),
        Some(original.clone())
    );
    assert_eq!(script(|s| s.conditional.applied), applied + 1);
    assert_eq!(script(|s| s.notifications), notifications);

    assert_eq!(
        recall(&door, 1200, &auth, COMPLETED, 4096).outcome,
        Outcome::Failed
    );
    assert_eq!(
        script(|s| (s.gets, s.conditional.emitted.len())),
        (reads, emitted)
    );
    let first = sticky_settlement_driver(&door, false);
    assert_eq!(first.outcome, Outcome::Pending);
    assert!(wire::read_settlement_ack(&first.extensions)
        .unwrap()
        .unwrap()
        .matches(&original)
        .unwrap());

    assert_eq!(
        script(|s| s.conditional.retained_settlement()),
        Some(receipt.clone())
    );
    assert_eq!(serve(&door, 1201, &auth, WORKING, 4096).status, 401);
    let repeated = sticky_settlement_driver(&door, true);
    assert_eq!(repeated.outcome, Outcome::Pending);
    assert_eq!(first.extensions, repeated.extensions);
    let repeated_drive = sticky_settlement_driver(&door, false);
    assert_eq!(repeated_drive.outcome, Outcome::Pending);
    assert_eq!(first.extensions, repeated_drive.extensions);
    assert_eq!(
        script(|s| s.notifications),
        notifications,
        "sticky receipt retries are ACK-only; delivery waits for host ACK consumption"
    );
    assert!(consume_settlement(&repeated_drive));
    assert_eq!(script(|s| s.conditional.retained_settlement()), None);
    assert_eq!(
        sticky_settlement_driver(&door, false).outcome,
        Outcome::Ready
    );
    assert_eq!(
        sticky_settlement_driver(&door, true).outcome,
        Outcome::Ready
    );
    assert_eq!(script(|s| s.notifications), notifications + 1);
    assert_eq!(
        sticky_settlement_driver(&door, true).outcome,
        Outcome::Ready
    );
    assert_eq!(
        script(|s| s.notifications),
        notifications + 1,
        "repeated receipt consumption queues exactly one notification"
    );

    let stale = settlement_driver(&door, &receipt, false);
    assert_eq!(stale.outcome, Outcome::Failed);
    assert!(wire::read_settlement_ack(&stale.extensions)
        .unwrap()
        .is_none());
    assert_eq!(script(|s| s.notifications), notifications + 1);
    assert_eq!(
        script(|s| (s.conditional.applied, s.conditional.acknowledgements)),
        (applied + 1, 1)
    );
}

#[test]
fn detached_settlement_rejects_other_instance_changed_identity_and_reused_ticket() {
    use busbar_contract::abi::sdk::plane::conditional as wire;
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    script(|s| s.conditional.pause_commit = true);
    assert_eq!(
        serve(&door, 1210, &auth, COMPLETED, 4096).outcome,
        Outcome::Pending
    );
    assert_eq!(door.cancel_unit(1210), Outcome::Ready);
    let receipt = script(|s| s.conditional.detach(ticket(1210)));
    let original = script(|s| s.conditional.emitted.last().unwrap().clone());
    let other = open_scripted_instance();
    let foreign = settlement_driver(&other, &receipt, false);
    assert_eq!(foreign.outcome, Outcome::Failed);
    assert!(wire::read_settlement_ack(&foreign.extensions)
        .unwrap()
        .is_none());
    assert!(!consume_settlement(&foreign));
    for changed in 0..5 {
        let mut request = original.clone();
        match changed {
            0 => request.capability.ticket.generation += 1,
            1 => request.capability.epoch += 1,
            2 => request.candidate.correlation += 1,
            3 => request
                .candidate
                .mutations
                .push(wire::RecordMutation::Delete {
                    kind: 0,
                    key: b"wrong-digest".to_vec(),
                }),
            _ => request.capability.ticket.slot += 1,
        }
        let wrong = wire::encode_settlement(
            &request,
            &wire::ConditionalResult {
                correlation: request.candidate.correlation,
                decision: Ok(busbar_contract::abi::sdk::store::conditional::Decision::Applied),
            },
        )
        .unwrap();
        let answer = settlement_driver(&door, &wrong, changed % 2 == 0);
        assert_eq!(answer.outcome, Outcome::Failed);
        assert!(wire::read_settlement_ack(&answer.extensions)
            .unwrap()
            .is_none());
        assert!(!consume_settlement(&answer));
        assert_eq!(
            script(|s| s.conditional.retained_settlement()),
            Some(receipt.clone())
        );
    }
    let emitted = script(|s| s.conditional.emitted.len());
    assert_eq!(
        recall(&door, 1210, &auth, COMPLETED, 4096).outcome,
        Outcome::Failed
    );
    assert_eq!(script(|s| s.conditional.emitted.len()), emitted);
    let exact = settlement_driver(&door, &receipt, false);
    assert_eq!(exact.outcome, Outcome::Pending);
    assert!(consume_settlement(&exact));
}

#[test]
fn actual_short_callback_then_cancel_retains_original_receipt_until_driver_ack() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    registered(&door);
    let applied = script(|s| s.conditional.applied);
    let short = get_task_answer_sized(&door, 1220, 0, true);
    assert_eq!(short.outcome, Some(Outcome::Failed));
    assert!(short.emitted.is_empty());
    assert!(short.fields_needed > 0);
    assert_eq!(script(|s| s.conditional.applied), applied + 1);
    assert_eq!(script(|s| s.conditional.acknowledgements), 0);
    assert_eq!(door.cancel_unit(1220), Outcome::Ready);
    let receipt = script(|s| s.conditional.detach(ticket(1220)));
    let ack = settlement_driver(&door, &receipt, true);
    assert_eq!(ack.outcome, Outcome::Pending);
    assert_eq!(
        script(|s| s.conditional.retained_settlement()),
        Some(receipt)
    );
    assert!(consume_settlement(&ack));
    assert_eq!(
        script(|s| (s.conditional.applied, s.conditional.acknowledgements)),
        (applied + 1, 1)
    );
}

fn get_task_answer_sized(door: &Door, unit: u64, cap: usize, short: bool) -> Answered {
    get_named_task_answer(door, unit, "t1", "completed", cap, short)
}
fn get_named_task_answer(
    door: &Door,
    unit: u64,
    task_id: &str,
    state: &str,
    cap: usize,
    short: bool,
) -> Answered {
    let request = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":task_id}}),
    )
    .unwrap();
    assert_eq!(
        door.arrive(
            unit,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            &request
        ),
        (Outcome::Ready, 0)
    );
    assert_eq!(
        piece(door, unit, Given::attempt(b"vendor"), 65536).outcome,
        Some(Outcome::Ready)
    );
    assert_eq!(
        piece(door, unit, Given::caller(&request), 65536).outcome,
        Some(Outcome::Ready)
    );
    let response = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{"id":format!("backend-{task_id}"),"contextId":"c1","status":{"state":state}}})).unwrap();
    piece_sized(
        door,
        unit,
        Given::far_end(200, &response),
        cap,
        if short { 0 } else { 16 },
        if short { 0 } else { 1 << 14 },
    )
}

fn delivered_events() -> usize {
    script(|s| {
        s.conditional
            .events
            .iter()
            .filter(|(_, content)| {
                let event: Value = serde_json::from_slice(content).unwrap();
                event["kind"] == "task.push_delivered"
            })
            .count()
    })
}

#[test]
fn canceled_owed_append_is_acknowledged_only_after_its_exact_late_applied() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    seed_task("t2");
    assert_eq!(serve(&door, 1230, &auth, COMPLETED, 4096).status, 202);
    assert_eq!(door.tick().0, Outcome::Ready);
    assert_eq!(door.tick().0, Outcome::Ready);
    assert!(
        script(|s| s.notifications) > 0,
        "an actual receiver exchange creates the owed delivery outcome"
    );
    let before = delivered_events();
    script(|s| s.conditional.pause_owed_commit = true);
    let pending = get_named_task_answer(&door, 1231, "t2", "working", 65536, false);
    assert_eq!(pending.outcome, Some(Outcome::Pending));
    assert_eq!(delivered_events(), before);
    let original = script(|s| s.conditional.emitted.last().unwrap().clone());
    assert_eq!(original.capability.ticket, ticket(1231));
    assert!(
        original.candidate.chains.iter().any(|chain| matches!(chain,
        busbar_contract::abi::sdk::plane::conditional::ChainMutation::Append { scope, content, .. }
        if scope == format!("{}/t1", std::str::from_utf8(ALICE).unwrap()).as_bytes()
            && serde_json::from_slice::<Value>(content).unwrap()["kind"] == "task.push_delivered"))
    );
    assert!(
        script(|s| !s.conditional.requests.contains(&original)),
        "the actual owed append is copied but paused before the host decision"
    );
    assert_eq!(door.cancel_unit(1231), Outcome::Ready);
    let receipt = script(|s| s.conditional.detach(ticket(1231)));
    assert_eq!(
        script(|s| s.conditional.retained_settlement()),
        Some(receipt)
    );
    assert_eq!(delivered_events(), before + 1);
    let ack = sticky_settlement_driver(&door, false);
    assert_eq!(ack.outcome, Outcome::Pending);
    let repeated = sticky_settlement_driver(&door, true);
    assert_eq!(repeated.outcome, Outcome::Pending);
    assert_eq!(ack.extensions, repeated.extensions);
    assert!(consume_settlement(&repeated));
    assert_eq!(
        sticky_settlement_driver(&door, false).outcome,
        Outcome::Ready
    );
    assert_eq!(
        get_named_task_answer(&door, 1232, "t2", "working", 65536, false).outcome,
        Some(Outcome::Ready)
    );
    assert_eq!(
        delivered_events(),
        before + 1,
        "settlement consumes the exact owed receipt so a later real callback cannot file it again"
    );
    assert_eq!(
        script(|s| s
            .conditional
            .requests
            .iter()
            .filter(|request| **request == original)
            .count()),
        1
    );
}
