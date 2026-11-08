// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual READY slot over ticketed SDK record callbacks and conditional receipts.
use super::*;
use busbar_contract::abi::host::service::{
    EntitlementCheckIn, HostSlots, ItemSpan, RecordsGetIn, RecordsListIn, ServiceBufs, ServiceOut,
};
use busbar_contract::abi::mechanism::call::{InHead, RawOutcome, Span, FLAG_RESUME};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::sdk::door::{blank_in, blank_out, Entry};
use busbar_contract::abi::sdk::plane::conditional as wire;
use busbar_contract::host_records::conditional::Decision;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::c_void;

const TICKET: Ticket = Ticket {
    slot: 21,
    generation: 9,
};
type Rows = Vec<(Vec<u8>, Vec<u8>)>;
#[derive(Default)]
struct HostState {
    gate: Option<Vec<u8>>,
    answers: BTreeMap<u32, Rows>,
    card_handles: Vec<u32>,
    hold_cards: bool,
}
thread_local! {
    static HOST: RefCell<HostState> = RefCell::new(HostState::default());
    static OPENING: RefCell<Option<A2aDoor>> = const { RefCell::new(None) };
    static JOURNAL: RefCell<Option<crate::conditional_publication::Journal>> = const { RefCell::new(None) };
    static OWNER: RefCell<Option<std::sync::Weak<ReadyPublication>>> = const { RefCell::new(None) };
}

#[allow(unsafe_code)]
unsafe fn answer(rows: Rows, into: ServiceBufs, out: *mut ServiceOut, found: bool) -> RawOutcome {
    let mut bytes = Vec::new();
    let mut spans = Vec::new();
    for (key, value) in rows {
        let k = Span {
            offset: bytes.len() as u32,
            len: key.len() as u32,
        };
        bytes.extend(key);
        let v = Span {
            offset: bytes.len() as u32,
            len: value.len() as u32,
        };
        bytes.extend(value);
        spans.push(ItemSpan { key: k, value: v });
    }
    assert!(bytes.len() <= into.cap && spans.len() <= into.spans_cap);
    let raw = RawOutcome::of(Outcome::Ready);
    // SAFETY: SDK callbacks lend writable destinations of the checked capacities.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), into.buf, bytes.len());
        std::ptr::copy_nonoverlapping(spans.as_ptr(), into.spans, spans.len());
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value: u64::from(found),
            len: bytes.len() as u64,
            items: spans.len() as u64,
            ..ServiceOut::ZERO
        });
    }
    raw
}
#[allow(unsafe_code)]
extern "C" fn get(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only in records_get; the SDK lends its complete input and output.
    unsafe {
        let input = &*input.cast::<RecordsGetIn>();
        let kind = std::slice::from_raw_parts(input.kind.ptr, input.kind.len);
        assert_eq!(kind, crate::records::KIND_TASK_QUOTA.as_bytes());
        let rows = HOST.with(|host| {
            let mut host = host.borrow_mut();
            let current = host
                .gate
                .clone()
                .map(|value| vec![(Vec::new(), value)])
                .unwrap_or_default();
            host.answers
                .entry(input.head.handle.seq)
                .or_insert(current)
                .clone()
        });
        let found = !rows.is_empty();
        answer(rows, input.into, out, found)
    }
}
#[allow(unsafe_code)]
extern "C" fn list(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only in records_list; all nested loans live for this callback.
    unsafe {
        let input = &*input.cast::<RecordsListIn>();
        let kind = std::slice::from_raw_parts(input.kind.ptr, input.kind.len);
        let rows = HOST.with(|host| {
            let mut host = host.borrow_mut();
            if kind == crate::records::KIND_CARD.as_bytes() {
                host.card_handles.push(input.head.handle.seq);
                if host.hold_cards {
                    return None;
                }
            }
            let current = if kind == crate::records::KIND_TASK_QUOTA.as_bytes() {
                host.gate
                    .clone()
                    .map(|value| vec![(b"active/v1".to_vec(), value)])
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            Some(
                host.answers
                    .entry(input.head.handle.seq)
                    .or_insert(current)
                    .clone(),
            )
        });
        match rows {
            Some(rows) => answer(rows, input.into, out, false),
            None => {
                let raw = RawOutcome::of(Outcome::Pending);
                out.write(ServiceOut {
                    size: std::mem::size_of::<ServiceOut>() as u32,
                    outcome: raw,
                    ..ServiceOut::ZERO
                });
                raw
            }
        }
    }
}
#[allow(unsafe_code)]
extern "C" fn entitled(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only in entitlement_check with the SDK's complete immutable input.
    unsafe {
        let input = &*input.cast::<EntitlementCheckIn>();
        assert_eq!(input.head.handle.ticket, TICKET);
        assert_eq!(
            std::slice::from_raw_parts(input.target.ptr, input.target.len),
            b"record-quota-bootstrap:"
        );
    }
    let raw = RawOutcome::of(Outcome::Ready);
    // SAFETY: installed only in the entitlement slot, which lends a complete output.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value: busbar_contract::abi::host::service::ENTITLED,
            ..ServiceOut::ZERO
        });
    }
    raw
}
struct Open;
impl SafeSlot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    type State = A2aDoor;
    fn call(instance: Instance<'_, A2aDoor>, _: Lent<'_, OpenIn>, _: Out<'_, OpenOut>) -> Outcome {
        instance.open(OPENING.with(|plane| plane.borrow_mut().take().unwrap()));
        Outcome::Ready
    }
}
struct Inspect;
impl SafeSlot for Inspect {
    type In = InHead;
    type Out = OutHead;
    type State = A2aDoor;
    fn call(instance: Instance<'_, A2aDoor>, _: Lent<'_, InHead>, _: Out<'_, OutHead>) -> Outcome {
        let ready = instance
            .get()
            .unwrap()
            .ready_quota
            .get(&(TICKET.slot, TICKET.generation))
            .unwrap();
        JOURNAL.with(|journal| *journal.borrow_mut() = Some(ready.publication.0.clone()));
        OWNER.with(|owner| *owner.borrow_mut() = Some(Arc::downgrade(&ready.publication)));
        Outcome::Ready
    }
}

#[allow(unsafe_code)]
fn ready(
    instance: *mut c_void,
    tables: &HostTables,
    receipt: &[u8],
    resume: bool,
) -> (Outcome, Option<wire::Request>) {
    let mut extensions = wire::encode_capability(wire::Capability {
        ticket: TICKET,
        epoch: 1,
    });
    extensions.extend_from_slice(receipt);
    let mut input: ReadyIn = blank_in();
    input.head.ticket = TICKET;
    input.head.op = slot::READY;
    input.head.flags = if resume { FLAG_RESUME } else { 0 };
    input.head.extensions = busbar_contract::abi::mechanism::call::Blob::of(&extensions);
    input.host = tables;
    let mut out: OutHead = blank_out();
    // SAFETY: instance is the live SDK allocation; every READY input range lives through entry.
    let outcome =
        unsafe { <Safe<ReadyOp> as Entry>::enter(instance, slot::READY, &input, &mut out) };
    // SAFETY: the SDK keeps the output's leased extensions live through this synchronous read.
    let request = wire::read_request(unsafe { out.extensions.bytes() }).unwrap();
    (outcome, request)
}

#[test]
#[allow(unsafe_code)]
fn real_ready_waits_for_quota_receipts_and_replays_card_handles_then_cancels_exact_intent() {
    let slots = HostSlots {
        size: std::mem::size_of::<HostSlots>() as u32,
        slots: busbar_contract::abi::host::service::SERVICES,
        records_get: Some(get),
        records_list: Some(list),
        entitlement_check: Some(entitled),
        ..busbar_contract::abi::sdk::test_support::zeroed()
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
    for cancel in [false, true] {
        HOST.with(|host| {
            *host.borrow_mut() = HostState {
                hold_cards: true,
                ..Default::default()
            }
        });
        // SAFETY: readable complete tables; snapshots retain only static callbacks.
        let plane = A2aDoor {
            host: Some(unsafe { Host::from_raw(&tables) }),
            services: unsafe { Services::from_raw(&tables) },
            ..Default::default()
        };
        let cfg = AgentsCfg::default();
        let spec = statement::agents_snapshot_spec(None, &[]);
        plane.generations.publish_with(1, &spec, cfg);
        plane.newest.insert((), 1);
        OPENING.with(|opening| *opening.borrow_mut() = Some(plane));
        let input: OpenIn = blank_in();
        let mut opened: OpenOut = blank_out();
        // SAFETY: instance-less OPEN mints the SDK allocation retained until CLOSE below.
        assert_eq!(
            unsafe {
                <Safe<Open> as Entry>::enter(std::ptr::null_mut(), slot::OPEN, &input, &mut opened)
            },
            Outcome::Ready
        );
        let instance = opened.instance;
        let (outcome, request) = ready(instance, &tables, &[], false);
        assert_eq!(outcome, Outcome::Pending);
        let request = request.expect("READY offers the initializing gate publication");
        assert!(
            HOST.with(|host| host.borrow().gate.is_none()),
            "offering is not committing"
        );
        let (again, repeated) = ready(instance, &tables, &[], true);
        assert_eq!(again, Outcome::Pending);
        assert_eq!(
            repeated.as_ref(),
            Some(&request),
            "a wake retains exact submitted bytes"
        );
        let input: InHead = blank_in();
        let mut out: OutHead = blank_out();
        // SAFETY: inspection borrows the same live SDK state and exports only owned handles.
        unsafe {
            <Safe<Inspect> as Entry>::enter(instance, slot::TICK, &input, &mut out);
        }
        if cancel {
            let mut input: PlaneCancelIn = blank_in();
            input.cancel.ticket = TICKET;
            let mut out: PlaneCancelOut = blank_out();
            // SAFETY: cancellation names the exact pending READY ticket on this instance.
            assert_eq!(
                unsafe {
                    <Safe<plane_life::Cancel<A2aDoor>> as Entry>::enter(
                        instance,
                        slot::CANCEL,
                        &input,
                        &mut out,
                    )
                },
                Outcome::Ready
            );
            OWNER.with(|owner| assert!(owner.borrow().as_ref().unwrap().upgrade().is_none()));
            JOURNAL.with(|journal| {
                let journal = journal.borrow();
                let journal = journal.as_ref().unwrap();
                assert!(journal.is_cancelled());
                assert!(
                    journal.has_commit(),
                    "cancellation retains the submitted candidate"
                );
                assert_eq!(
                    crate::conditional_publication::fixture::retained_request(journal).as_ref(),
                    Some(&request),
                    "cancellation retains exact submitted intent bytes"
                );
            });
            assert!(HOST.with(|host| host.borrow().gate.is_none()));
        } else {
            let mut next = Some(request);
            let mut publications = 0;
            while let Some(request) = next.take() {
                publications += 1;
                assert!(publications <= 2, "bounded two-phase quota initialization");
                let wire::RecordMutation::Put { kind, value, .. } = &request.candidate.mutations[0]
                else {
                    panic!("quota Put");
                };
                assert_eq!(*kind, kind_index(crate::records::KIND_TASK_QUOTA));
                assert_eq!(request.candidate.mutations.len(), 1);
                assert_eq!(request.candidate.predicates.len(), 1);
                assert!(request.candidate.chains.is_empty());
                HOST.with(|host| {
                    let mut host = host.borrow_mut();
                    let expected = &request.candidate.predicates[0].expected;
                    assert_eq!(
                        expected,
                        &host.gate.clone().map_or(
                            busbar_contract::host_records::conditional::Expected::Absent,
                            busbar_contract::host_records::conditional::Expected::Bytes
                        ),
                        "the host commits only the exact observed gate"
                    );
                    host.gate = Some(value.clone());
                });
                let receipt = wire::encode_result(
                    &request,
                    &wire::ConditionalResult {
                        correlation: request.candidate.correlation,
                        decision: Ok(Decision::Applied),
                    },
                )
                .unwrap();
                let (outcome, request) = ready(instance, &tables, &receipt, true);
                assert_eq!(
                    outcome,
                    Outcome::Pending,
                    "card warming still owns READY after quota commit"
                );
                next = request;
            }
            assert_eq!(publications, 2);
            let before = HOST.with(|host| host.borrow().card_handles.clone());
            assert_eq!(before.len(), 1);
            let (outcome, request) = ready(instance, &tables, &[], true);
            assert_eq!(outcome, Outcome::Pending);
            assert!(request.is_none());
            HOST.with(|host| host.borrow_mut().hold_cards = false);
            assert_eq!(ready(instance, &tables, &[], true).0, Outcome::Ready);
            HOST.with(|host| {
                let host = host.borrow();
                assert_eq!(
                    host.card_handles,
                    vec![before[0]; 3],
                    "warming reuses its post-quota service base"
                );
                let gate: serde_json::Value =
                    serde_json::from_slice(host.gate.as_ref().unwrap()).unwrap();
                assert_eq!(gate["active"], 0);
            });
            OWNER.with(|owner| assert!(owner.borrow().as_ref().unwrap().upgrade().is_none()));
            JOURNAL.with(|journal| {
                let journal = journal.borrow();
                let journal = journal.as_ref().unwrap();
                assert!(
                    journal.completed(),
                    "warm-card replay must finish the journal before dropping its last owner"
                );
                assert!(
                    !journal.is_cancelled(),
                    "successful READY cannot be canceled by last-owner cleanup"
                );
            });
        }
        let input: InHead = blank_in();
        let mut out: OutHead = blank_out();
        // SAFETY: no crossing remains in flight; CLOSE consumes this one SDK allocation.
        assert_eq!(
            unsafe {
                <Safe<plane_life::Close<A2aDoor>> as Entry>::enter(
                    instance,
                    slot::CLOSE,
                    &input,
                    &mut out,
                )
            },
            Outcome::Ready
        );
        JOURNAL.with(|journal| journal.borrow_mut().take());
        OWNER.with(|owner| owner.borrow_mut().take());
    }
}
