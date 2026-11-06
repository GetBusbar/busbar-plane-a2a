// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real settlement and journal re-entry over SDK record slots; no synthetic state transition.
use super::*;
use busbar_contract::abi::host::service::{HostSlots, ItemSpan, RecordsGetIn, ServiceOut};
use busbar_contract::abi::mechanism::call::{RawOutcome, Span};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::sdk::plane::conditional as wire;
use busbar_contract::abi::sdk::store::conditional::{Decision, Expected};
use busbar_contract::abi::sdk::test_support::zeroed;
use std::cell::RefCell;
use std::ffi::c_void;

const CALLER: &str = "a11ce";
const LOCAL: &str = "local-task";
const BACKEND: &str = "agent-task";
thread_local! { static ROW: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) }; }

#[allow(unsafe_code)]
extern "C" fn get(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only in records_get. SDK lends complete input and exclusive output;
    // both destination capacities are checked before copying the task and its item span.
    unsafe {
        let input = &*input.cast::<RecordsGetIn>();
        let kind = std::slice::from_raw_parts(input.kind.ptr, input.kind.len);
        let key = std::slice::from_raw_parts(input.key.ptr, input.key.len);
        assert_eq!(kind, crate::records::KIND_TASK.as_bytes());
        assert_eq!(key, task_key(CALLER, LOCAL).as_bytes());
        let raw = RawOutcome::of(Outcome::Ready);
        ROW.with(|row| {
            let row = row.borrow();
            assert!(input.into.cap >= row.len() && input.into.spans_cap >= 1);
            std::ptr::copy_nonoverlapping(row.as_ptr(), input.into.buf, row.len());
            input.into.spans.write(ItemSpan {
                key: Span {
                    offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
                    len: 0,
                },
                value: Span {
                    offset: 0,
                    len: row.len() as u32,
                },
            });
            out.write(ServiceOut {
                size: std::mem::size_of::<ServiceOut>() as u32,
                outcome: raw,
                value: busbar_contract::abi::host::service::FOUND,
                len: row.len() as u64,
                items: 1,
                ..ServiceOut::ZERO
            });
        });
        raw
    }
}

#[allow(unsafe_code)]
fn run(state: crate::a2a::task::TaskState, event: bool, refuse: bool) {
    let mut row = crate::tasks::tests::row(LOCAL, 100);
    row.principal = CALLER.into();
    row.state = state.as_str().into();
    let held = tasks::HeldTask { row, next_seq: 3 };
    let original = serde_json::to_vec(&held).unwrap();
    ROW.with(|row| *row.borrow_mut() = original.clone());
    let slots = HostSlots {
        size: std::mem::size_of::<HostSlots>() as u32,
        slots: busbar_contract::abi::host::service::SERVICES,
        records_get: Some(get),
        ..zeroed()
    };
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx { handle: 1 },
        wake: None,
        conns: std::ptr::null(),
        services: &slots,
        io: std::ptr::null(),
    };
    // SAFETY: complete readable table and service prefix; snapshots retain only static callbacks.
    let host = unsafe { Host::from_raw(&tables) };
    // SAFETY: the same complete readable service prefix and static callback.
    let services = unsafe { Services::from_raw(&tables) };
    let plane = A2aDoor {
        host: Some(host),
        services,
        ..A2aDoor::default()
    };
    let ticket = Ticket {
        slot: 21,
        generation: 1,
    };
    let reach = Reach {
        plane: &plane,
        ticket,
    };
    let mut hop = Hop::task(json!(7), "1.0", json!({"method":"SendMessage"}));
    hop.now = Some(100);
    hop.relay.for_task(relay::TaskHop {
        task_id: LOCAL.into(),
        context_id: "context".into(),
        addressed: false,
        skill: None,
        references: Vec::new(),
    });
    hop.settle.push(if event {
        TaskSettled::Event {
            state: Some(state),
            artifact: false,
            backend_id: Some(BACKEND.into()),
        }
    } else {
        TaskSettled::Reported {
            state,
            backend_id: Some(BACKEND.into()),
        }
    });
    let mut pass = crate::task_door::Pass::default();
    let capability = wire::encode_capability(wire::Capability { ticket, epoch: 1 });
    pass.publication.enter(ticket, &capability).unwrap();
    let mut publications = 0;
    for _ in 0..8 {
        let outcome = settle_task(&reach, &mut hop, &mut pass, CALLER);
        if outcome != Err(Outcome::Pending) {
            assert_eq!(
                publications, 1,
                "the first task ID requires an acknowledged mapping publication"
            );
            if refuse {
                assert_eq!(outcome, Err(Outcome::Failed));
                assert_eq!(plane.backend_of(CALLER, LOCAL), None);
                assert!(
                    !hop.settle.is_empty(),
                    "failed publication cannot release the pending answer"
                );
            } else {
                assert_eq!(outcome, Ok(()));
                assert_eq!(plane.backend_of(CALLER, LOCAL).as_deref(), Some(BACKEND));
                assert!(hop.settle.is_empty());
            }
            assert!(hop.outbox.writes.is_empty());
            ROW.with(|row| {
                assert_eq!(
                    *row.borrow(),
                    original,
                    "state, sequence and quotas do not advance"
                )
            });
            return;
        }
        assert_eq!(
            plane.backend_of(CALLER, LOCAL),
            None,
            "no mapping before acknowledgement"
        );
        let mut request = None;
        let receipt =
            crate::conditional_publication::fixture::receipt(&pass.publication, |candidate| {
                publications += 1;
                assert!(
                    candidate.candidate.mutations.is_empty(),
                    "mapping grants no records or quotas"
                );
                assert_eq!(candidate.candidate.predicates.len(), 1);
                let predicate = &candidate.candidate.predicates[0];
                assert_eq!(predicate.expected, Expected::Bytes(original.clone()));
                assert_eq!(predicate.key, task_key(CALLER, LOCAL).as_bytes());
                assert!(
                    matches!(
                        candidate.candidate.chains.as_slice(),
                        [wire::ChainMutation::Check { .. }]
                    ),
                    "mapping must retain the observed task incarnation"
                );
                request = Some(candidate.clone());
                Decision::Applied
            });
        let receipt = if let Some(request) = request.filter(|_| refuse) {
            wire::encode_result(
                &request,
                &wire::ConditionalResult {
                    correlation: request.candidate.correlation,
                    decision: Err(wire::ConditionalFailure::Refused("store unavailable")),
                },
            )
            .unwrap()
        } else {
            receipt
        };
        let mut input = capability.clone();
        input.extend(receipt);
        pass.publication.enter(ticket, &input).unwrap();
    }
    panic!("settlement did not complete in its bounded conditional sequence");
}

#[test]
fn submitted_backend_mapping_precedes_first_task_id() {
    run(crate::a2a::task::TaskState::Submitted, false, false);
}

#[test]
fn unchanged_event_backend_mapping_precedes_first_task_id() {
    for state in [
        crate::a2a::task::TaskState::Submitted,
        crate::a2a::task::TaskState::Working,
    ] {
        run(state, true, false);
    }
}

#[test]
fn refused_backend_mapping_cannot_release_first_task_id() {
    run(crate::a2a::task::TaskState::Submitted, false, true);
}
