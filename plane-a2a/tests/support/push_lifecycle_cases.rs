// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Actual public callback route: capabilities are minted by the real push-config mirror.
use super::*;
use busbar_contract::abi::host::service::{RecordsGetIn, SignIn, CLAIM_WON, FOUND};
use busbar_contract::abi::mechanism::call::Span;
use serde_json::json;

#[derive(Default)]
struct Script {
    sign_failed: bool,
    read_failed: bool,
    claim_failed: bool,
    read_pending: bool,
    signs: usize,
    gets: usize,
    claims: usize,
    config_failed: bool,
    config_gets: usize,
    full_lists: usize,
    random: u8,
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
    let row = store()
        .iter()
        .find(|(kind, key, _)| *kind == text(i.kind) && *key == text(i.key))
        .map(|(_, _, v)| v.clone());
    let Some(row) = row else {
        return answer(out, Outcome::Ready, 0, 0);
    };
    if row.len() > i.into.cap {
        let result = answer(out, Outcome::Failed, 0, 0);
        unsafe {
            (*out).needed_bytes = row.len() as u64;
        }
        return result;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(row.as_ptr(), i.into.buf, row.len());
    }
    answer(out, Outcome::Ready, FOUND, row.len() as u64)
}
extern "C" fn claimed(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let failed = script(|s| {
        s.claims += 1;
        s.claim_failed
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
    if text(i.kind) == "task" && i.prefix.len() == 0 {
        script(|s| s.full_lists += 1);
    }
    records_list(ctx, input, out)
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
        s.random
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
fn open_scripted() -> (Reset, Door) {
    let reset = Reset(std::mem::take(&mut *store()));
    *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = Some(Script::default());
    let services = Box::leak(Box::new(HostSlots {
        records_list: Some(listed),
        random_fill: Some(random_fill),
        clock_now: Some(fixed_clock),
        records_get: Some(get),
        records_claim: Some(claimed),
        sign: Some(signed),
        ..HOST_SLOTS
    }));
    let tables = Box::leak(Box::new(HostTables {
        services,
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
    (
        reset,
        Door {
            instance: output.open.instance,
        },
    )
}
fn seed() {
    let caller = std::str::from_utf8(ALICE).unwrap();
    let row = json!({"task_id":"t1","context_id":"c1","principal":caller,"direction":"inbound","state":"working","agent_id":"vendor","artifact_cursor":0,"push_callback":"","created_at":1_800_000_000u64,"updated_at":1_800_000_000u64,"next_seq":1});
    store().push((
        "task".into(),
        format!("{caller}/t1"),
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
    assert_eq!(
        piece(door, 501, Given::attempt(b"vendor"), 65536).outcome,
        Some(Outcome::Ready)
    );
    assert_eq!(
        piece(door, 501, Given::caller(get), 65536).outcome,
        Some(Outcome::Ready)
    );
    let response=br#"{"jsonrpc":"2.0","id":1,"result":{"id":"backend-t1","contextId":"c1","status":{"state":"working"}}}"#;
    assert_eq!(
        piece(door, 501, Given::far_end(200, response), 65536).outcome,
        Some(Outcome::Ready)
    );
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
    let mut output: ServeOut = z();
    output.head = out_head::<ServeOut>();
    // SAFETY: exact SERVE structs and all declared buffers remain live throughout the call.
    let result = unsafe {
        ops().serve.unwrap()(
            door.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
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
    let mut reply = vec![0_u8; reply_cap];
    let mut fields = vec![z::<OutField>(); 16];
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
    // SAFETY: `f` is the door's own slot, called over an `in` and an `out` laid out as its ABI
    // states and live for the call.
    #[allow(unused_unsafe)]
    let ret = unsafe {
        f(
            door.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
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
    script(|s| s.claim_failed = true);
    fault(&serve(&door, 603, &auth, COMPLETED, 4096));
    script(|s| s.claim_failed = false);
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
    // 58 further operations leave exactly one of the existing 60-per-minute slots.
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
}

#[test]
fn failed_config_read_keeps_the_accepted_move_and_retries_its_notification() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_scripted();
    let auth = registered(&door);
    script(|s| s.config_failed = true);
    let accepted = serve(&door, 800, &auth, COMPLETED, 4096);
    assert_eq!(
        (accepted.outcome, accepted.status),
        (Outcome::Ready, 202),
        "{accepted:?}"
    );
    assert!(accepted.writes > 0);
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
