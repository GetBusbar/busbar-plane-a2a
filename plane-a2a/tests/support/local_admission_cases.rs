// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Local admission through the existing public arrival/piece ABI and real host service table.
use super::*;
use busbar_contract::abi::host::service::{EntitlementCheckIn, ENTITLEMENT_STANDING};
use serde_json::{json, Value};

#[derive(Default)]
struct Script {
    live: bool,
    unavailable: bool,
    checks: Vec<(Completion, String)>,
}
type Completion = (u32, u32, u32);
static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);

struct Reset(Vec<(String, String, Vec<u8>)>);
impl Drop for Reset {
    fn drop(&mut self) {
        *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = None;
        LIST_PENDS.store(false, Ordering::SeqCst);
        *store() = std::mem::take(&mut self.0);
    }
}

extern "C" fn standing(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    handed(input);
    // SAFETY: entitlement.check lends its complete input and UTF-8 target for this call.
    let input = unsafe { input.cast::<EntitlementCheckIn>().read() };
    let target = unsafe { std::slice::from_raw_parts(input.target.ptr(), input.target.len()) };
    let h = input.head.handle;
    let (live, unavailable) = {
        let mut script = SCRIPT.lock().unwrap_or_else(PoisonError::into_inner);
        let script = script.as_mut().unwrap();
        script.checks.push((
            (h.ticket.slot, h.ticket.generation, h.seq),
            String::from_utf8(target.to_vec()).unwrap(),
        ));
        (script.live, script.unavailable)
    };
    if unavailable {
        answer(out, Outcome::Failed, 0, 0)
    } else {
        answer(out, Outcome::Ready, if live { ENTITLED } else { 0 }, 0)
    }
}

extern "C" fn listed(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: records.list lends its complete input and text for this call.
    let i = unsafe { input.cast::<RecordsListIn>().read() };
    if i.prefix.is_empty() {
        return records_list(ctx, input, out);
    }
    handed(input);
    let text = |s: AbiStr| {
        if s.is_empty() {
            Vec::new()
        } else {
            // SAFETY: the nonempty service string is live for this callback.
            unsafe { std::slice::from_raw_parts(s.ptr(), s.len()).to_vec() }
        }
    };
    let (kind, prefix, after) = (text(i.kind), text(i.prefix), text(i.after));
    let mut rows: Vec<_> = store()
        .iter()
        .filter(|(k, key, _)| {
            k.as_bytes() == kind.as_slice()
                && key.as_bytes().starts_with(&prefix)
                && key.as_bytes() > after.as_slice()
        })
        .map(|(_, key, value)| (key.clone(), value.clone()))
        .collect();
    rows.sort();
    let needed: usize = rows
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    if needed > i.into.cap || rows.len() > i.into.spans_cap {
        let result = answer(out, Outcome::Failed, 0, 0);
        // SAFETY: answer initialized the live output, whose short sizes name these rows.
        unsafe {
            (*out).needed_bytes = needed as u64;
            (*out).needed_items = rows.len() as u64;
        }
        return result;
    }
    // SAFETY: the SDK lends these writable regions at the checked capacities.
    let (buf, spans) = unsafe {
        (
            std::slice::from_raw_parts_mut(i.into.buf, i.into.cap),
            std::slice::from_raw_parts_mut(i.into.spans, i.into.spans_cap),
        )
    };
    let mut offset = 0;
    for (n, (key, value)) in rows.iter().enumerate() {
        buf[offset..offset + key.len()].copy_from_slice(key.as_bytes());
        buf[offset + key.len()..offset + key.len() + value.len()].copy_from_slice(value);
        spans[n] = ItemSpan {
            key: busbar_contract::abi::mechanism::call::Span {
                offset: offset as u32,
                len: key.len() as u32,
            },
            value: busbar_contract::abi::mechanism::call::Span {
                offset: (offset + key.len()) as u32,
                len: value.len() as u32,
            },
        };
        offset += key.len() + value.len();
    }
    let result = answer(out, Outcome::Ready, 0, needed as u64);
    // SAFETY: answer initialized the live output; every span above lies within needed bytes.
    unsafe {
        (*out).items = rows.len() as u64;
    }
    result
}

fn open_local() -> (Reset, Door) {
    let reset = Reset(std::mem::take(&mut *store()));
    *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = Some(Script {
        live: true,
        ..Script::default()
    });
    let services = Box::leak(Box::new(HostSlots {
        entitlement_check: Some(standing),
        records_list: Some(listed),
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
    // SAFETY: the public OPEN receives complete live ABI structs and static host tables.
    let result = unsafe {
        lifecycle().open.unwrap()(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
    let door = Door {
        instance: output.open.instance,
    };
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, 200), "{body}");
    handles().clear();
    SCRIPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
        .unwrap()
        .checks
        .clear();
    (reset, door)
}

fn arrive_local(door: &Door, unit: u64, envelope: &[u8]) {
    assert_eq!(
        door.arrive(
            unit,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            envelope
        ),
        (Outcome::Ready, 0)
    );
}

#[derive(Debug)]
struct Reply {
    outcome: Outcome,
    output: OnPieceOut,
    body: Vec<u8>,
    lane: String,
    units: Vec<(u32, u64)>,
}

fn local_reply(door: &Door, unit: u64, member: &[u8], body: &[u8], fields_cap: usize) -> Reply {
    let mut reply = vec![0; 65536];
    let mut fields = vec![z::<OutField>(); fields_cap];
    let mut arena = vec![0; 16384];
    let mut records = [z::<RecordWrite>(); 16];
    let mut units = [z::<UnitCount>(); 8];
    let mut input: OnPieceIn = z();
    input.head = head::<OnPieceIn>(slot::ON_PIECE, ticket(unit));
    input.unit = unit;
    input.from = FROM_CALLER;
    input.flags = PIECE_LAST;
    input.bytes = octets(body);
    input.member = str_of(member);
    input.caller_ref = str_of(ALICE);
    (input.reply_buf, input.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (input.fields_buf, input.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (input.arena_buf, input.arena_cap) = (arena.as_mut_ptr(), arena.len());
    (input.records_buf, input.records_cap) = (records.as_mut_ptr(), records.len());
    (input.units_buf, input.units_cap) = (units.as_mut_ptr(), units.len());
    let mut output: OnPieceOut = z();
    output.head = out_head::<OnPieceOut>();
    // SAFETY: the existing ON_PIECE slot receives exact live structs and stated buffer regions.
    let result = unsafe {
        ops().on_piece.unwrap()(
            door.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    reply.truncate(output.emitted as usize);
    let lane = if output.lane.len == 0 {
        String::new()
    } else {
        let s = output.lane;
        String::from_utf8(arena[s.offset as usize..(s.offset + s.len) as usize].to_vec()).unwrap()
    };
    Reply {
        outcome: result.outcome(),
        output,
        body: reply,
        lane,
        units: units[..output.units_written as usize]
            .iter()
            .map(|u| (u.class, u.amount))
            .collect(),
    }
}

fn refused(reply: &Reply, status: u32, sentence: &str) {
    assert_eq!(reply.outcome, Outcome::Ready, "{reply:?}");
    assert_eq!(reply.output.reply_status, status, "{reply:?}");
    assert!(
        String::from_utf8_lossy(&reply.body).contains(sentence),
        "{reply:?}"
    );
    assert!(
        reply
            .units
            .iter()
            .all(|(class, amount)| *class != CLASS_FEE_INDEX || *amount == 0),
        "{reply:?}"
    );
    assert_eq!(
        reply.output.records_written, 0,
        "no served audit or writes: {reply:?}"
    );
    assert!(reply.lane.is_empty(), "no applied resource: {reply:?}");
}

const LIST: &[u8] = br#"{"jsonrpc":"2.0","id":17,"method":"ListTasks","params":{}}"#;

#[test]
fn addressed_lists_resolve_only_the_named_agent_without_an_egress_walk() {
    use busbar_contract::abi::plane::{ROUTE_COUNTED, ROUTE_DIRECT, ROUTE_SCOPE_LOCAL};
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for (body, route) in [
        (LIST, ROUTE_SCOPE_LOCAL),
        (
            &br#"{"jsonrpc":"2.0","id":18,"method":"tasks/list","params":{}}"#[..],
            ROUTE_SCOPE_LOCAL,
        ),
        (
            &br#"{"jsonrpc":"2.0","id":19,"method":"tasks/get","params":{"id":"task-one"}}"#[..],
            ROUTE_DIRECT,
        ),
        (
            &br#"{"jsonrpc":"2.0","id":20,"method":"message/send","params":{"message":{"role":"user","messageId":"m-one","parts":[{"kind":"text","text":"hello"}]}}}"#[..],
            ROUTE_DIRECT,
        ),
    ] {
        let (_reset, door) = open_local();
        let mut input: ArriveIn = z();
        input.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
        input.unit = 605;
        input.claim = claim("POST", "/a2a/agents/{agent_id}");
        input.target = str_of(b"/a2a/agents/vendor");
        input.method = str_of(b"POST");
        input.body = octets(body);
        let mut units = [z::<UnitCount>(); 8];
        (input.units_buf, input.units_cap) = (units.as_mut_ptr(), units.len());
        let mut output: ArriveOut = z();
        output.head = out_head::<ArriveOut>();
        // SAFETY: ARRIVE receives its complete live ABI input and output buffers.
        let result = unsafe {
            ops().arrive.unwrap()(
                door.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        };
        assert_eq!(result.outcome(), Outcome::Ready);
        assert_eq!(output.refusal_status, 0);
        assert_eq!(output.route, route);
        let text = |value: AbiStr| {
            if value.is_empty() {
                return String::new();
            }
            // SAFETY: the live door owns the output's nonempty UTF-8 strings.
            let bytes = unsafe { std::slice::from_raw_parts(value.ptr(), value.len()) };
            std::str::from_utf8(bytes).unwrap().to_string()
        };
        assert_eq!(text(output.pool), "vendor", "only the addressed candidate");
        assert_eq!(text(output.trust_counterparty), "vendor");
        assert_eq!(
            output.route_flags & ROUTE_COUNTED,
            if route == ROUTE_SCOPE_LOCAL { ROUTE_COUNTED } else { 0 },
        );
    }
}

#[test]
fn dead_or_unavailable_principals_are_refused_before_local_verbs() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for unavailable in [false, true] {
        for envelope in [
            LIST,
            &br#"{"jsonrpc":"2.0","id":18,"method":"DeleteTaskPushNotificationConfig","params":{"taskId":"task-one","id":"push-one"}}"#[..],
        ] {
            let (_reset, door) = open_local();
            arrive_local(&door, 601, envelope);
            let before = store().clone();
            {
                let mut script = SCRIPT.lock().unwrap_or_else(PoisonError::into_inner);
                let script = script.as_mut().unwrap();
                script.live = false;
                script.unavailable = unavailable;
            }
            let reply = local_reply(&door, 601, b"vendor", envelope, 16);
            refused(&reply, 401, "this key is not live");
            assert_eq!(*store(), before);
            let script = SCRIPT.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(!script.as_ref().unwrap().checks.is_empty());
            assert!(script.as_ref().unwrap().checks.iter().all(|(_, target)| target == ENTITLEMENT_STANDING));
        }
    }
}

#[test]
fn a_missing_selected_member_cannot_be_served_or_charged_and_a_held_member_still_works() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for (member, status, words) in [
        (&b""[..], 400, "no agent this key may reach"),
        (&b"missing-agent"[..], 404, "no fronted agent"),
    ] {
        let (_reset, door) = open_local();
        arrive_local(&door, 602, LIST);
        let reply = local_reply(&door, 602, member, LIST, 16);
        refused(&reply, status, words);
    }
    let (_reset, door) = open_local();
    arrive_local(&door, 603, LIST);
    assert_eq!(
        door.piece(603, Given::attempt(b"vendor"), 4096).outcome,
        Some(Outcome::Ready)
    );
    let reply = local_reply(&door, 603, b"", LIST, 16);
    assert_eq!(
        (reply.outcome, reply.output.reply_status),
        (Outcome::Ready, 200),
        "{reply:?}"
    );
    assert_eq!(reply.lane, "agent:vendor");
    assert!(reply.units.contains(&(CLASS_FEE_INDEX, 1)));
}

#[test]
fn a_live_call_keeps_principal_and_context_filtering_and_replay_handles_separate_from_restore() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let (_reset, door) = open_local();
    let alice = std::str::from_utf8(ALICE).unwrap();
    for (caller, id, context) in [
        (alice, "ours", "wanted"),
        (alice, "other-context", "other"),
        ("b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", "not-ours", "wanted"),
    ] {
        store().push(("task".into(), format!("{caller}/{id}"), serde_json::to_vec(&json!({"task_id":id,"context_id":context,"principal":caller,"direction":"inbound","state":"completed","agent_id":"vendor","artifact_cursor":0,"push_callback":"","created_at":1_800_000_000u64,"updated_at":1_800_000_100u64,"next_seq":1})).unwrap()));
    }
    let envelope =
        br#"{"jsonrpc":"2.0","id":19,"method":"ListTasks","params":{"contextId":"wanted"}}"#;
    arrive_local(&door, 604, envelope);
    LIST_PENDS.store(true, Ordering::SeqCst);
    let pending = local_reply(&door, 604, b"vendor", envelope, 16);
    assert_eq!(pending.outcome, Outcome::Pending, "{pending:?}");
    LIST_PENDS.store(false, Ordering::SeqCst);
    let short = local_reply(&door, 604, b"vendor", envelope, 0);
    assert_eq!(short.outcome, Outcome::Failed, "{short:?}");
    assert!(short.output.fields_needed > 0);
    let ready = local_reply(&door, 604, b"vendor", envelope, 16);
    assert_eq!(
        (ready.outcome, ready.output.reply_status),
        (Outcome::Ready, 200),
        "{ready:?}"
    );
    let body: Value = serde_json::from_slice(&ready.body).unwrap();
    assert_eq!(body["id"], 19);
    let ids: Vec<_> = body["result"]["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|task| task["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["ours"]);
    assert_eq!(ready.lane, "agent:vendor");
    let own = ticket(604);
    let calls: Vec<_> = handles()
        .iter()
        .copied()
        .filter(|((slot, generation, _), _)| (*slot, *generation) == (own.slot, own.generation))
        .collect();
    assert!(calls.iter().any(|(_, op)| *op == service_op::RECORDS_LIST));
    assert!(calls
        .iter()
        .any(|(_, op)| *op == service_op::ENTITLEMENT_CHECK));
    for (handle, op) in &calls {
        assert!(
            calls
                .iter()
                .all(|(other, other_op)| handle != other || op == other_op),
            "one handle cannot represent two services: {calls:?}"
        );
    }
    let checks = SCRIPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .unwrap()
        .checks
        .clone();
    assert!(
        checks.len() >= 2,
        "short recall really repeated the admission: {checks:?}"
    );
    assert!(checks
        .iter()
        .all(|(handle, target)| handle == &checks[0].0 && target == ENTITLEMENT_STANDING));
}
