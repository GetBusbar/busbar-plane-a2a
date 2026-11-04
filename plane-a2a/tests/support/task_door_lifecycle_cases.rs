// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real public door slots for serialization retries and cancelled restore ownership.
use super::*;
use busbar_contract::abi::host::service::SignIn;
use busbar_contract::abi::mechanism::call::Span;

#[derive(Default)]
struct Script {
    pend_restore: bool,
    restore_tickets: Vec<Ticket>,
    sign_handles: Vec<((u32, u32, u32), Vec<u8>)>,
}
static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);

struct Reset(Vec<(String, String, Vec<u8>)>);
impl Drop for Reset {
    fn drop(&mut self) {
        *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = None;
        *store() = std::mem::take(&mut self.0);
    }
}

extern "C" fn listed(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends the complete RecordsListIn and its text for this call.
    let i = unsafe { input.cast::<RecordsListIn>().read() };
    let kind = unsafe { std::slice::from_raw_parts(i.kind.ptr(), i.kind.len()) };
    let full = kind == b"task" && i.prefix.is_empty();
    let pending = {
        let mut script = SCRIPT.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(s) = script.as_mut() else {
            return answer(out, Outcome::Failed, 0, 0);
        };
        if full {
            s.restore_tickets.push(i.head.handle.ticket);
        }
        full && s.pend_restore
    };
    if pending {
        answer(out, Outcome::Pending, 0, 0)
    } else {
        answer(out, Outcome::Ready, 0, 0)
    }
}

extern "C" fn signed(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends SignIn, its input blob and writable result regions for this call.
    let i = unsafe { input.cast::<SignIn>().read() };
    let data = if i.data.is_empty() {
        &[]
    } else {
        // SAFETY: a nonempty SDK blob names exactly this many live input bytes.
        unsafe { std::slice::from_raw_parts(i.data.ptr(), i.data.len()) }
    };
    let h = i.head.handle;
    {
        let mut script = SCRIPT.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(script) = script.as_mut() else {
            return answer(out, Outcome::Failed, 0, 0);
        };
        script
            .sign_handles
            .push(((h.ticket.slot, h.ticket.generation, h.seq), data.to_vec()));
    }
    let key = b"busbar-card-test";
    let signature = [7u8; 64];
    if i.into.cap < key.len() + signature.len() || i.into.spans_cap < 1 {
        return answer(out, Outcome::Failed, 0, 0);
    }
    // SAFETY: the checked capacities cover both writes and the sole result span.
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
    // SAFETY: the SDK's output remains live and the result above initialized it.
    unsafe {
        (*out).items = 1;
    }
    result
}

fn open_scripted(pend_restore: bool) -> (Reset, Door) {
    *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = Some(Script {
        pend_restore,
        ..Script::default()
    });
    let services = Box::leak(Box::new(HostSlots {
        records_list: Some(listed),
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
    // SAFETY: the public door slot receives complete live ABI structs and static host tables.
    let result = unsafe {
        lifecycle().open.unwrap()(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
    (Reset(store().clone()), Door::new(output.open.instance))
}

fn piece(
    door: &Door,
    unit: u64,
    bytes: &[u8],
    fields_cap: usize,
    arena_cap: usize,
) -> (Outcome, OnPieceOut, Vec<u8>) {
    let given = Given {
        member: b"vendor",
        ..Given::caller(bytes)
    };
    let (mut frame, _) = door.piece_frame(unit, given, 65536, fields_cap, arena_cap);
    *frame.output = z();
    frame.output.head = out_head::<OnPieceOut>();
    // SAFETY: the per-Door boxed frames and original loans remain live through Pending,
    // cancellation or synchronous CLOSE, including the body and caller identity.
    let outcome = unsafe {
        ops().on_piece.unwrap()(
            door.instance,
            std::ptr::from_ref(&*frame.input).cast(),
            std::ptr::from_mut(&mut *frame.output).cast(),
        )
    }
    .outcome();
    if outcome == Outcome::Pending {
        door.pending.borrow_mut().insert(ticket(unit), frame);
        return (outcome, z(), Vec::new());
    }
    let body = if outcome == Outcome::Ready {
        frame.reply[..frame.output.emitted as usize].to_vec()
    } else {
        Vec::new()
    };
    (outcome, *frame.output, body)
}

#[test]
fn own_and_grpc_extended_cards_retry_after_short_fields_or_arena_without_consuming_the_answer() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for grpc in [false, true] {
        for (fields, arena) in [(0, 16384), (16, 0)] {
            let (_reset, door) = open_scripted(false);
            if grpc {
                let target = format!("{}/GetExtendedAgentCard", door_facts::SERVICE_PATH);
                assert_eq!(
                    door.arrive(1, ("POST", "/lf.a2a.v1.A2AService/{method}"), &target, b"")
                        .0,
                    Outcome::Ready
                );
            } else {
                door.arrive_own_card(1);
            }
            let (short, out, body) = piece(&door, 1, b"", fields, arena);
            assert_eq!(short, Outcome::Failed);
            assert!(body.is_empty());
            if fields == 0 {
                assert!(
                    out.fields_needed > 0,
                    "missing fields must report field capacity"
                );
            } else {
                assert!(
                    out.arena_needed > 0,
                    "missing arena must report byte capacity"
                );
            }
            let first = SCRIPT
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .unwrap()
                .sign_handles
                .clone();
            assert!(
                !first.is_empty(),
                "the signing phase really ran before serialization failed"
            );
            let (ready, out, body) = piece(&door, 1, b"", 16, 16384);
            assert_eq!(ready, Outcome::Ready);
            assert_eq!(out.reply_status, 200);
            assert!(!body.is_empty());
            assert_ne!(out.flags & EMIT_DONE, 0);
            let replay = SCRIPT
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .unwrap()
                .sign_handles
                .clone();
            assert_eq!(
                &replay[first.len()..],
                first.as_slice(),
                "same signing inputs and completion handles on retry"
            );
            let (ready, _, body) = piece(&door, 1, b"", 16, 16384);
            assert_eq!(ready, Outcome::Ready);
            assert!(body.is_empty());
        }
    }
}

#[test]
fn cancel_by_unit_or_ticket_releases_a_pending_restore_for_the_next_real_local_verb() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let body = br#"{"jsonrpc":"2.0","id":7,"method":"tasks/list","params":{}}"#;
    for named in [false, true] {
        let (_reset, door) = open_scripted(true);
        let (ready, status, _) = door.connect("vendor");
        assert_eq!((ready, status), (Outcome::Ready, 200));
        assert_eq!(
            door.arrive(1, ("POST", "/a2a"), "/a2a", body).0,
            Outcome::Ready
        );
        assert_eq!(piece(&door, 1, body, 16, 16384).0, Outcome::Pending);
        assert!(door.pending.borrow().contains_key(&ticket(1)));
        assert_eq!(
            if named {
                door.cancel_unit(1)
            } else {
                door.cancel(1)
            },
            Outcome::Ready
        );
        assert!(!door.pending.borrow().contains_key(&ticket(1)));
        SCRIPT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .unwrap()
            .pend_restore = false;
        for unit in [2, 3] {
            assert_eq!(
                door.arrive(unit, ("POST", "/a2a"), "/a2a", body).0,
                Outcome::Ready
            );
            assert_eq!(piece(&door, unit, body, 16, 16384).0, Outcome::Ready);
        }
        let observed = SCRIPT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .unwrap()
            .restore_tickets
            .clone();
        assert_eq!(
            observed,
            [ticket(1), ticket(2)],
            "cancelled restore is retried once, then remains reported"
        );
    }
}
