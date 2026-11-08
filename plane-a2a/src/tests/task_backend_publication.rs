// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real settlement and journal re-entry over SDK record slots; no synthetic state transition.
use super::*;
use busbar_contract::abi::host::conn::connector::ConnectorSlots;
use busbar_contract::abi::host::service::{HostSlots, ItemSpan, RecordsGetIn, ServiceOut};
use busbar_contract::abi::mechanism::call::{RawOutcome, Span};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::sdk::plane::conditional as wire;
use busbar_contract::abi::sdk::test_support::zeroed;
use busbar_contract::host_records::conditional::{self as store, Decision, Expected};
use std::cell::{Cell, RefCell};
use std::ffi::c_void;

const CALLER: &str = "a11ce";
const LOCAL: &str = "local-task";
const BACKEND: &str = "agent-task";
thread_local! {
    static ROW: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static DIALS: Cell<usize> = const { Cell::new(0) };
    static GETS: RefCell<std::collections::BTreeMap<u32, Vec<u8>>> = const { RefCell::new(std::collections::BTreeMap::new()) };
}

#[allow(unsafe_code)]
extern "C" fn dial(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    DIALS.with(|calls| calls.set(calls.get() + 1));
    let raw = RawOutcome::of(Outcome::Failed);
    // SAFETY: installed only in establish; the SDK lends an exclusive complete output frame.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            ..ServiceOut::ZERO
        });
    }
    raw
}

/// Lower this fixture's row/check candidate to the actual Store request codec. Chain Check adds
/// only a life predicate, as the host does; it cannot supply a missing mutation. Validation is
/// the real SDK implementation, not a permissive imitation of its transaction rules.
fn store_request(candidate: &wire::Request) -> store::Request {
    let mut request = store::Request {
        version: store::VERSION,
        op_id: busbar_contract::abi::store::OpId::from_parts(1, candidate.candidate.correlation),
        predicates: candidate
            .candidate
            .predicates
            .iter()
            .map(|predicate| store::Predicate {
                schema: format!("record-{}", predicate.kind),
                key: predicate.key.clone(),
                expected: predicate.expected.clone(),
            })
            .collect(),
        mutations: candidate
            .candidate
            .mutations
            .iter()
            .map(|mutation| match mutation {
                wire::RecordMutation::Put { kind, key, value } => store::Mutation::Put {
                    schema: format!("record-{kind}"),
                    key: key.clone(),
                    value: value.clone(),
                },
                wire::RecordMutation::Delete { .. } => {
                    panic!("a backend mapping cannot delete a record")
                }
            })
            .collect(),
    };
    for chain in &candidate.candidate.chains {
        let wire::ChainMutation::Check { kind, scope, life } = chain else {
            panic!("a backend mapping cannot append or remove task events");
        };
        request.predicates.push(store::Predicate {
            schema: format!("life-{kind}"),
            key: scope.clone(),
            expected: life.clone(),
        });
    }
    let encoded = request
        .encode_held()
        .expect("mapping must pass the real Store transaction validator");
    store::Request::decode(&encoded).expect("actual Store request codec round trip")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    Applied,
    Refused,
    ConflictAndLostReply,
}

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
        GETS.with(|gets| {
            let mut gets = gets.borrow_mut();
            let row = gets
                .entry(input.head.handle.seq)
                .or_insert_with(|| ROW.with(|row| row.borrow().clone()));
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
fn run(state: crate::a2a::task::TaskState, event: bool, behavior: Behavior) {
    let mut row = crate::tasks::tests::row(LOCAL, 100);
    row.principal = CALLER.into();
    row.state = state.as_str().into();
    let held = tasks::HeldTask { row, next_seq: 3 };
    let original = serde_json::to_vec(&held).unwrap();
    ROW.with(|row| *row.borrow_mut() = original.clone());
    DIALS.with(|calls| calls.set(0));
    GETS.with(|gets| gets.borrow_mut().clear());
    let conns = ConnectorSlots {
        size: std::mem::size_of::<ConnectorSlots>() as u32,
        slots: busbar_contract::abi::host::conn::connector::SERVICES,
        establish: Some(dial),
        ..zeroed()
    };
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
        conns: &conns,
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
    let mut writes = 0;
    let mut conflicted = false;
    let mut lost_reply = false;
    let mut last_applied: Option<wire::Request> = None;
    let mut expected_row = original.clone();
    for _ in 0..16 {
        let outcome = settle_task(&reach, &mut hop, &mut pass, CALLER);
        if outcome != Err(Outcome::Pending) {
            assert_eq!(
                publications,
                if behavior == Behavior::ConflictAndLostReply {
                    3
                } else {
                    1
                },
                "only the acknowledged mapping publication releases the first task ID"
            );
            if behavior == Behavior::Refused {
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
            assert!(!matches!(hop.outbox.head, Some(AnswerHead::Attempt(_))));
            DIALS.with(|calls| {
                assert_eq!(
                    calls.get(),
                    0,
                    "settlement retries must not redial the backend"
                )
            });
            assert_eq!(writes, usize::from(behavior != Behavior::Refused));
            ROW.with(|row| {
                assert_eq!(
                    *row.borrow(),
                    expected_row,
                    "state, sequence and quotas do not advance; a concurrent row is not overwritten"
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
                // This call is what the original permissive fixture omitted. Empty mutation
                // sets fail here through the actual Store encode_held/validate implementation.
                let transaction = store_request(candidate);
                assert_eq!(candidate.candidate.predicates.len(), 1);
                let predicate = &candidate.candidate.predicates[0];
                assert_eq!(predicate.key, task_key(CALLER, LOCAL).as_bytes());
                let [store::Mutation::Put { key, value, .. }] = transaction.mutations.as_slice()
                else {
                    panic!("mapping must republish exactly one existing task row");
                };
                assert_eq!(key, &predicate.key);
                assert_eq!(
                    predicate.expected,
                    Expected::Bytes(value.clone()),
                    "retain raw bytes without reserialization"
                );
                assert_eq!(candidate.candidate.chains.len(), 1);
                request = Some(candidate.clone());
                if behavior == Behavior::ConflictAndLostReply && !conflicted {
                    // A concurrent byte-level change between observation and commit must win.
                    expected_row.push(b'\n');
                    ROW.with(|row| *row.borrow_mut() = expected_row.clone());
                    conflicted = true;
                }
                let matches =
                    ROW.with(|row| predicate.expected == Expected::Bytes(row.borrow().clone()));
                if !matches {
                    assert_eq!(writes, 0);
                    return Decision::ConditionConflict;
                }
                if behavior != Behavior::Refused {
                    if let Some(previous) = &last_applied {
                        assert_eq!(
                            candidate, previous,
                            "a lost receipt replays the immutable original candidate"
                        );
                    } else {
                        ROW.with(|row| *row.borrow_mut() = value.clone());
                        writes += 1;
                        last_applied = Some(candidate.clone());
                    }
                }
                Decision::Applied
            });
        if behavior == Behavior::ConflictAndLostReply && last_applied.is_some() && !lost_reply {
            // Lose the first Applied response; re-enter settlement with the original journal.
            lost_reply = true;
            continue;
        }
        let receipt = if let Some(request) = request.filter(|_| behavior == Behavior::Refused) {
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
    run(
        crate::a2a::task::TaskState::Submitted,
        false,
        Behavior::Applied,
    );
}

#[test]
fn unchanged_event_backend_mapping_precedes_first_task_id() {
    for state in [
        crate::a2a::task::TaskState::Submitted,
        crate::a2a::task::TaskState::Working,
    ] {
        run(state, true, Behavior::Applied);
    }
}

#[test]
fn refused_backend_mapping_cannot_release_first_task_id() {
    run(
        crate::a2a::task::TaskState::Submitted,
        false,
        Behavior::Refused,
    );
}

#[test]
fn backend_mapping_conflict_and_lost_reply_preserve_raw_row_without_redial() {
    run(
        crate::a2a::task::TaskState::Submitted,
        false,
        Behavior::ConflictAndLostReply,
    );
}

#[test]
#[allow(unsafe_code)]
fn staged_read_guard_uses_empty_effects_despite_notifying_via() {
    use crate::tasks::Records;
    let conns = ConnectorSlots {
        size: std::mem::size_of::<ConnectorSlots>() as u32,
        slots: busbar_contract::abi::host::conn::connector::SERVICES,
        establish: Some(dial),
        ..zeroed()
    };
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
        conns: &conns,
        services: &slots,
        io: std::ptr::null(),
    };
    // SAFETY: complete tables and static fixture callbacks live for this test.
    let plane = A2aDoor {
        host: Some(unsafe { Host::from_raw(&tables) }),
        services: unsafe { Services::from_raw(&tables) },
        ..Default::default()
    };
    let ticket = Ticket {
        slot: 31,
        generation: 1,
    };
    let reach = Reach {
        plane: &plane,
        ticket,
    };
    let journal = crate::conditional_publication::Journal::default();
    let capability = wire::encode_capability(wire::Capability { ticket, epoch: 1 });
    journal.enter(ticket, &capability).unwrap();
    let raw = serde_json::to_vec(&tasks::HeldTask {
        row: crate::tasks::tests::row(LOCAL, 100),
        next_seq: 3,
    })
    .unwrap();
    let mut applied = 0;
    for _ in 0..8 {
        let mut via = reach.via(0).unwrap().publishing(&journal);
        via.effects(crate::conditional_publication::Draft {
            notify: true,
            backend: Some(BACKEND.into()),
            ..Default::default()
        });
        let mut staged = tasks::Staged::new(&mut via, &[]);
        let key = task_key(CALLER, LOCAL);
        let guarded = (|| {
            let life = staged.observe_chain_life(crate::records::KIND_TASK_EVENT, &key)?;
            staged.publish_read_guard(
                &[tasks::Predicate {
                    kind: crate::records::KIND_TASK,
                    key: key.clone(),
                    expected: Some(raw.clone()),
                }],
                &[tasks::ChainLife {
                    kind: crate::records::KIND_TASK_EVENT,
                    scope: key.clone(),
                    expected: life,
                }],
                &[tasks::Write {
                    kind: crate::records::KIND_TASK,
                    key,
                    value: raw.clone(),
                }],
            )
        })();
        if guarded == Ok(true) {
            assert_eq!(applied, 1);
            let effects = journal.applied_effects();
            assert!(
                effects.notify.is_empty()
                    && effects.backends.is_empty()
                    && effects.owed.is_empty()
                    && effects.deletes.is_empty()
            );
            journal.effects_finished(effects.owner);
            return;
        }
        assert_eq!(guarded, Err(tasks::Halt::Pending));
        if let Some(draft) = crate::conditional_publication::fixture::pending_draft(&journal) {
            assert_eq!(draft, crate::conditional_publication::Draft::default());
        }
        let receipt = crate::conditional_publication::fixture::receipt(&journal, |candidate| {
            let request = store_request(candidate);
            assert_eq!(request.mutations.len(), 1);
            assert_eq!(candidate.candidate.mutations.len(), 1);
            applied += 1;
            Decision::Applied
        });
        let mut input = capability.clone();
        input.extend(receipt);
        journal.enter(ticket, &input).unwrap();
    }
    panic!("read guard did not settle within its fixed observation/publication callbacks");
}
