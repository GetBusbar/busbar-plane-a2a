// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Card-route admission and the actual extended-card answer's audit, through the public door.
use super::*;
use busbar_contract::abi::host::service::SignIn;
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::plane::{AUDIT_APPLIED, AUDIT_REJECTED, RECORD_AUDIT};

const POOLED: &[u8] = br#"{
    "vendor":{"url":"https://vendor.example/agent","pin":{"mechanism":"unpinned"}},
    "pools":{"workers":{"members":["vendor"]}}
}"#;

#[test]
fn both_open_card_aliases_refuse_an_unknown_agent_as_missing() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    for (index, suffix) in ["", "/.well-known/agent-card.json"].iter().enumerate() {
        let route = format!("/a2a/agents/{{agent_id}}{suffix}");
        let target = format!("/a2a/agents/ghost{suffix}");
        assert_eq!(
            door.arrive(index as u64 + 1, ("GET", &route), &target, b""),
            (Outcome::Refused, 404),
            "an unknown registration has no card awaiting discovery"
        );
    }
}

#[test]
fn both_open_card_aliases_refuse_a_serving_pool_as_the_document_line_does() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let saved = store().clone();
    let door = open_with(POOLED);
    let (outcome, status, _) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, 200));
    let request = br#"{"jsonrpc":"2.0","id":7,"method":"GetExtendedAgentCard","params":{}}"#;
    assert_eq!(
        door.arrive(
            1,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            request
        ),
        (Outcome::Refused, 400),
        "the existing document-line pooled-card refusal is the control"
    );
    for (index, suffix) in ["", "/.well-known/agent-card.json"].iter().enumerate() {
        let route = format!("/a2a/agents/{{agent_id}}{suffix}");
        let target = format!("/a2a/agents/vendor{suffix}");
        assert_eq!(
            door.arrive(index as u64 + 2, ("GET", &route), &target, b""),
            (Outcome::Refused, 400),
            "a serving pool cannot publish one member's card as its own"
        );
    }
    drop(door);
    *store() = saved;
}

static FAIL_SIGNATURE: AtomicBool = AtomicBool::new(false);
static SIGNATURE_CALLS: AtomicU64 = AtomicU64::new(0);

extern "C" fn signed_card(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the public door's SDK lends SignIn and its writable result regions for this call.
    let input = unsafe { input.cast::<SignIn>().read() };
    if input.data.len() != 0 {
        SIGNATURE_CALLS.fetch_add(1, Ordering::SeqCst);
        if FAIL_SIGNATURE.load(Ordering::SeqCst) {
            return answer(out, Outcome::Failed, 0, 0);
        }
    }

    let key = b"card-audit-test";
    let signature = [7u8; 64];
    assert!(input.into.cap >= key.len() + signature.len() && input.into.spans_cap >= 1);
    // SAFETY: the capacities above cover the key, signature and one result span.
    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr(), input.into.buf, key.len());
        std::ptr::copy_nonoverlapping(
            signature.as_ptr(),
            input.into.buf.add(key.len()),
            signature.len(),
        );
        input.into.spans.write(ItemSpan {
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
    // SAFETY: answer initialized this SDK output, which is still lent for the call.
    unsafe {
        (*out).items = 1;
    }
    result
}

fn open_signed_card(fail_signature: bool) -> Door {
    FAIL_SIGNATURE.store(fail_signature, Ordering::SeqCst);
    SIGNATURE_CALLS.store(0, Ordering::SeqCst);
    open_card_over(
        SECTION,
        HostSlots {
            sign: Some(signed_card),
            ..HOST_SLOTS
        },
    )
}

fn open_card_over(section: &'static [u8], services: HostSlots) -> Door {
    let services = Box::leak(Box::new(services));
    let tables = Box::leak(Box::new(HostTables {
        services,
        ..TABLES.0
    }));
    let mut input: PlaneOpenIn = z();
    input.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: tables,
        settings: octets(section),
        generation: 1,
        ..z()
    };
    input.public_url = str_of(b"https://gw.example");
    let mut output: PlaneOpenOut = z();
    output.open.head = out_head::<PlaneOpenOut>();
    // SAFETY: complete ABI structs and the static host tables live through this public slot call.
    let outcome = unsafe {
        lifecycle().open.unwrap()(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(outcome.outcome(), Outcome::Ready);
    Door::new(output.open.instance)
}

fn card_answer_with_audit(
    door: &Door,
    unit: u64,
    fields_cap: usize,
) -> (Outcome, OnPieceOut, Vec<u8>, Vec<(u32, String)>) {
    let mut body = vec![0u8; 65536];
    let mut fields = vec![z::<OutField>(); fields_cap];
    let mut arena = vec![0u8; 16384];
    let mut records = [z::<RecordWrite>(); 16];
    let mut units = [z::<UnitCount>(); 8];
    let mut input: OnPieceIn = z();
    input.head = head::<OnPieceIn>(slot::ON_PIECE, ticket(unit));
    input.unit = unit;
    input.from = FROM_CALLER;
    input.flags = PIECE_LAST;
    input.caller_ref = str_of(ALICE);
    (input.reply_buf, input.reply_cap) = (body.as_mut_ptr(), body.len());
    (input.fields_buf, input.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (input.arena_buf, input.arena_cap) = (arena.as_mut_ptr(), arena.len());
    (input.records_buf, input.records_cap) = (records.as_mut_ptr(), records.len());
    (input.units_buf, input.units_cap) = (units.as_mut_ptr(), units.len());
    let mut output: OnPieceOut = z();
    output.head = out_head::<OnPieceOut>();
    // SAFETY: every ABI buffer and struct is live and writable at its stated capacity for this call.
    let outcome = unsafe {
        ops().on_piece.unwrap()(
            door.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    body.truncate(output.emitted as usize);
    let audit = records[..output.records_written as usize]
        .iter()
        .filter(|record| record.op == RECORD_AUDIT)
        .map(|record| {
            let span = record.value;
            let value = &arena[span.offset as usize..span.offset as usize + span.len as usize];
            (record.kind, String::from_utf8(value.to_vec()).unwrap())
        })
        .collect();
    (outcome.outcome(), output, body, audit)
}

#[test]
fn extended_card_audits_signature_failure_as_rejected_and_the_success_control_as_applied() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for grpc in [false, true] {
        for fail_signature in [true, false] {
            let door = open_signed_card(fail_signature);
            let target = format!("{}/GetExtendedAgentCard", door_facts::SERVICE_PATH);
            let request =
                br#"{"jsonrpc":"2.0","id":7,"method":"GetExtendedAgentCard","params":{}}"#;
            let arrival = if grpc {
                door.arrive(1, ("POST", "/lf.a2a.v1.A2AService/{method}"), &target, b"")
            } else {
                door.arrive(1, ("POST", "/a2a"), "/a2a", request)
            };
            assert_eq!(arrival, (Outcome::Ready, 0));

            let (short, output, _, audit) = card_answer_with_audit(&door, 1, 0);
            assert_eq!(short, Outcome::Failed);
            assert!(output.fields_needed > 0);
            assert!(audit.is_empty(), "a SHORT answer applies no audit record");
            let (outcome, output, body, audit) = card_answer_with_audit(&door, 1, 16);
            assert_eq!(outcome, Outcome::Ready);
            assert!(
                SIGNATURE_CALLS.load(Ordering::SeqCst) >= 1,
                "the real signature service ran"
            );
            if grpc {
                assert_eq!(output.reply_status, 200);
                assert_eq!(output.final_status, if fail_signature { 13 } else { 0 });
            } else {
                assert_eq!(output.reply_status, if fail_signature { 500 } else { 200 });
                let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(document.get("error").is_some(), fail_signature);
            }
            assert_eq!(
                audit,
                [(
                    if fail_signature {
                        AUDIT_REJECTED
                    } else {
                        AUDIT_APPLIED
                    },
                    "agents".to_string()
                )]
            );
            let (_, _, _, repeated) = card_answer_with_audit(&door, 1, 16);
            assert!(repeated.is_empty(), "the audit is emitted once");
        }
    }
}

extern "C" fn quarantined_card_agent(
    _: HostCtx,
    _: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    answer(
        out,
        Outcome::Ready,
        busbar_contract::abi::host::service::DISTRUST_QUARANTINED,
        0,
    )
}

#[test]
fn an_untrusted_pool_keeps_kernel_trust_admission_ahead_of_the_card_refusal() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open_card_over(
        POOLED,
        HostSlots {
            trust_serves: Some(quarantined_card_agent),
            ..HOST_SLOTS
        },
    );
    for (index, suffix) in ["", "/.well-known/agent-card.json"].iter().enumerate() {
        let route = format!("/a2a/agents/{{agent_id}}{suffix}");
        let target = format!("/a2a/agents/vendor{suffix}");
        assert_eq!(
            door.arrive(index as u64 + 1, ("GET", &route), &target, b""),
            (Outcome::Ready, 0),
            "the caller's grant and the kernel's trust check precede a pool's card refusal"
        );
    }
}
